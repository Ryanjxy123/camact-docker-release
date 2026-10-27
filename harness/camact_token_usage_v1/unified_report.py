"""Versioned request accounting; no execution, estimation or scoring.

Three separate sets: reliable Usage, formally selected scored Agent Runs, and
all physical attempts. Role wire journals are converted to the same schema
without copying bodies. Existing v2 reports and historical ledgers stay intact.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
from functools import lru_cache
from pathlib import Path

from .adapters import FIELDS, extract, normalize_details
from .normalization import normalize_request, enrich_terminal_usage
from .completeness import request_bound_summary, token_field_display

VERSION = "camact.token_accounting.v3"
ROLES = ("Agent", "Simulator", "Judge")
IDENTITY = ("run_id", "harness_id", "user_id", "task_id", "attempt_id")
PRIMARY = ("input_tokens", "output_tokens", "total_tokens")
PROJECT = Path(__file__).resolve().parents[2]


def read_json(path, default=None):
    path = Path(path)
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def read_lines(path):
    """A partial append is explicit evidence, never a silently dropped request."""
    rows, errors = [], []
    if not path.exists():
        return rows, errors
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append((number, json.loads(line)))
        except ValueError:
            errors.append({"code": "malformed_journal_line", "path": str(path), "line": number})
    return rows, errors


def _merge_evidence(row, *mirrors):
    aliases = []
    for source in (row, *mirrors):
        for evidence in [source.get("evidence"), *(source.get("evidence_aliases") or [])]:
            if evidence and evidence not in aliases:
                aliases.append(evidence)
    if len(aliases) > 1:
        row["evidence_aliases"] = aliases
    return row


def _retained_judge_row(path, pointer, identity, retained):
    ledger = path.parent / "token_usage/accounting_v3/requests.jsonl"
    if ledger not in retained:
        retained[ledger] = [r for _, r in read_lines(ledger)[0] if r.get("role") == "Judge"]
    matches = {}
    for row in retained[ledger]:
        if tuple(row.get(k) for k in IDENTITY) != tuple(identity.get(k) for k in IDENTITY):
            continue
        evidence = [row.get("evidence"), *(row.get("evidence_aliases") or [])]
        if any(e and e.get("path") == str(path) and e.get("json_pointer") == pointer for e in evidence):
            if row["model_request_id"] in matches and matches[row["model_request_id"]] != row:
                return None, True
            matches[row["model_request_id"]] = row
    return (dict(next(iter(matches.values()))), False) if len(matches) == 1 else (None, len(matches) > 1)


def load_ledgers(roots, filters=None):
    filters, found, errors = filters or {}, {}, []
    for root in roots:
        for path in sorted(Path(root).rglob("identity.json")):
            if path.parent.parent.name not in {"token_usage", "ledgers"}:
                continue
            identity = read_json(path, {})
            if any(str(identity.get(k)) not in values for k, values in filters.items() if k != "model_id"):
                continue
            key = tuple(identity.get(k) for k in IDENTITY)
            journal = path.parent / "request_events.jsonl"
            if not journal.exists():
                journal = path.parent / "requests.jsonl"
            lines, parse_errors = read_lines(journal)
            errors.extend(parse_errors)
            rows = {}
            for line, row in lines:
                request_id = row.get("model_request_id")
                if not request_id:
                    errors.append({"code": "request_without_identity", "path": str(journal), "line": line})
                    continue
                rows[request_id] = (row, line)
            summary = read_json(path.parent / "task_summary.json", {})
            candidate = {"identity": identity, "rows": rows, "summary": summary,
                         "journal": str(journal), "mirrors": [str(journal)]}
            if key in found:
                previous = found[key]
                if {k: r[0] for k, r in previous["rows"].items()} != {k: r[0] for k, r in rows.items()}:
                    errors.append({"code": "conflicting_attempt_mirrors", "identity": key})
                    continue
                previous["mirrors"].append(str(journal))
            else:
                found[key] = candidate
    return sorted(found.values(), key=lambda x: tuple(str(v or "") for v in (x["identity"].get("started_at"), *tuple(x["identity"].get(k) for k in IDENTITY)))), errors


def normalized_rows(ledgers, filters=None):
    filters, requests = filters or {}, {}
    for ledger in ledgers:
        summary = ledger["summary"]
        reconciliation = summary.get("request_count_reconciliation", [])
        covered = bool(summary.get("closed") and not summary.get("collector_errors") and
                       reconciliation and all(r.get("matched") for r in reconciliation) and
                       reconciliation[-1].get("recorded_model_requests") == len(ledger["rows"]))
        for physical_id, (source, line) in ledger["rows"].items():
            if filters.get("model_id") and source.get("model_id") not in filters["model_id"]:
                continue
            source = enrich_terminal_usage(source, PROJECT)
            row = {**source, **normalize_request(source), "role": "Agent",
                   "model_request_id": physical_id, "request_capture_complete": covered,
                   "evidence": {"path": ledger["journal"], "line": line},
                   "http_status": source.get("http_status"), "timestamp": source.get("timestamp"),
                   "request_sha256": source.get("request_sha256"), "response_sha256": source.get("response_sha256")}
            if row["request_kind"] == "model_generation":
                row["request_kind"] = "generation"
            key = tuple(source.get(k) for k in IDENTITY) + (physical_id,)
            requests[key] = row
    return list(requests.values())


def _enclosing_ledgers(path, ledgers):
    matches = []
    for ledger in ledgers:
        identity = ledger["identity"]
        run = Path(identity["run_id"])
        try:
            relative = path.resolve().relative_to(run.resolve())
        except ValueError:
            continue
        if identity.get("task_id") in relative.parts or sum(l["identity"]["run_id"] == identity["run_id"] for l in ledgers) == 1:
            matches.append(ledger)
    return matches


def _ledger_owners(ledger):
    # Original journals live below their physical execution's token_usage.
    # Export mirrors may have a broader owner; specificity must choose the
    # original attempt directory, never the opaque exported ledger UUID.
    for journal in {ledger.get("journal"), *ledger.get("mirrors", [])} - {None}:
        usage = next((p for p in Path(journal).resolve().parents if p.name == "token_usage"), None)
        if usage is not None:
            yield usage.parent


def _enclosing_identity(path, ledgers):
    matches = []
    for ledger in _enclosing_ledgers(path, ledgers):
        identity = ledger["identity"]
        run = Path(identity["run_id"]).resolve()
        roots = [p for p in _ledger_owners(ledger) if p.is_relative_to(run)]
        physical = [p for p in roots if identity.get("task_id") in p.parts]
        if physical:
            depth = max(len(p.parts) for p in physical)
            if not any(path.resolve().is_relative_to(p) for p in physical if len(p.parts) == depth):
                continue
        owners = [len(p.parts) for p in roots if path.resolve().is_relative_to(p)]
        matches.append(((len(run.parts), max(owners, default=0)), identity))
    if matches:
        best = max(score for score, _ in matches)
        identities = {tuple(r.get(k) for k in IDENTITY): r for score, r in matches if score == best}
        if len(identities) == 1:
            return next(iter(identities.values()))
    return None


def role_rows(roots, ledgers, filters=None):
    """Use physical provider wire records, not semantic judge calls or scores.

    visual_wire's started/completed rows describe one physical request.
    provider_wire retries are keyed by request_id AND attempt_index.
    A copied wire record has the same physical key and cannot double-charge.
    """
    filters, output, errors = filters or {}, {}, []
    for root in roots:
        for pattern, role in (("simulator_provider_wire.jsonl", "Simulator"), ("judge_provider_wire.jsonl", "Judge")):
            for path in sorted(Path(root).rglob(pattern)):
                identity = _enclosing_identity(path, ledgers)
                if identity is None:
                    # Never bind an unrelated user's wire to the sole user
                    # left after a filter. An enclosing identity is required.
                    code = "ambiguous_role_wire_identity" if len(_enclosing_ledgers(path, ledgers)) > 1 else "unattributed_role_wire"
                    errors.append({"code": code, "path": str(path)})
                    continue
                lines, parse_errors = read_lines(path); errors.extend(parse_errors)
                for line, raw in lines:
                    request_id = raw.get("request_id")
                    if not request_id:
                        errors.append({"code": "role_wire_without_request_id", "path": str(path), "line": line}); continue
                    key = (*tuple(identity.get(k) for k in IDENTITY), role, request_id, raw.get("attempt_index", 1))
                    if raw.get("capture_stage") == "started" and key in output:
                        continue
                    body = raw.get("response_body", "")
                    payload = body.encode("utf-8") if isinstance(body, str) else json.dumps(body).encode("utf-8")
                    parsed = extract(payload, "openai-chat")
                    tokens = parsed.pop("usage")
                    response_id = None
                    try: response_id = json.loads(body).get("id") if body else None
                    except (ValueError, AttributeError, TypeError): pass
                    row = {**identity, **tokens, **parsed, "model_request_id": "role:" + role + ":" + request_id + ":" + str(raw.get("attempt_index", 1)),
                           "operation_id": request_id,
                           "operation_attribution": "explicit_logical_call" if raw.get("schema_version") == "camact.provider_wire.v1" else "physical_request",
                           "protocol": "openai-chat", "request_status": raw.get("status", "succeeded" if raw.get("success") else "error"),
                           "http_status": raw.get("http_status"), "retry_attempt": raw.get("retry_index"),
                           "model_id": raw.get("requested_model", raw.get("model")), "timestamp": raw.get("started_at"),
                           "request_sha256": raw.get("request_sha256"), "response_sha256": raw.get("response_sha256"),
                           "provider_response_id": response_id,
                           "usage_source": "provider_wire_response", "role": role, "request_kind": "generation",
                           "request_capture_complete": True, "evidence": {"path": str(path), "line": line}}
                    if filters.get("model_id") and row["model_id"] not in filters["model_id"]:
                        continue
                    # Preserve explicit non-Agent role after normalization.
                    row.update(normalize_request(row)); row["role"] = role
                    previous = output.get(key)
                    if previous and previous.get("response_sha256") and row.get("response_sha256") and previous["response_sha256"] != row["response_sha256"]:
                        errors.append({"code": "conflicting_role_wire", "request_id": request_id})
                        continue
                    output[key] = row
    # Numeric role ledgers survive raw-artifact cleanup. They are mirrors,
    # deduplicated against retained raw wire by physical provider identity.
    for root in roots:
        for path in sorted(Path(root).rglob("requests.jsonl")):
            if path.parent.name != "accounting_v3":
                continue
            for _, row in read_lines(path)[0]:
                if row.get("role") not in {"Simulator", "Judge"}:
                    continue
                if any(str(row.get(k)) not in values for k, values in filters.items()):
                    continue
                key = (*tuple(row.get(k) for k in IDENTITY), row.get("model_request_id"))
                output[key] = row
    return list(output.values()), errors


def judge_rows(roots, ledgers, filters=None, evaluation_documents=None):
    """Semantic Judge keeps raw physical attempts in the saved evaluator audit.

    Criterion calls and retries are different boundaries; only actual response
    attempts enter this ledger. Result copies share provider response IDs.
    """
    output, errors, filters, retained = {}, [], filters or {}, {}
    documents = {p: None for root in roots for p in Path(root).rglob("result.json")}
    # Retention may strip response bodies from the public result before this
    # hook runs. Consume its original in-memory evaluator document once,
    # exporting only numeric accounting evidence before raw cleanup.
    documents.update({Path(p).resolve(): doc for p, doc in (evaluation_documents or {}).items()})
    for path, supplied in sorted(documents.items()):
        doc = supplied if supplied is not None else read_json(path, {})
        if not isinstance(doc, dict) or not doc.get("evaluations"):
            continue
        for ei, evaluation in enumerate(doc["evaluations"]):
            eval_task_id = Path(evaluation["grader"]).parent.name if evaluation.get("grader") else None
            if not eval_task_id:
                source_path = _resolve_source(path, doc.get("source", ""))
                if source_path and source_path.is_file():
                    artifact = next((a for a in _artifact_rows(source_path) if a.get("task_id") == evaluation.get("task_id")), {})
                    task_hint = artifact.get("task", {})
                    if isinstance(task_hint, dict):
                        eval_task_id = task_hint.get("task_name") or task_hint.get("task_dir")
                        if eval_task_id: eval_task_id = Path(eval_task_id).name
                    elif isinstance(task_hint, str):
                        eval_task_id = Path(task_hint).name
            source = _resolve_source(path, doc.get("source", ""))
            identity = _enclosing_identity(path, ledgers)
            if identity is None:
                identity = _enclosing_identity(source, ledgers) if source else None
            if eval_task_id:
                candidates = [l for l in ledgers if l["identity"].get("task_id") == eval_task_id
                              and (str(path).startswith(l["identity"]["run_id"].rstrip("/") + "/")
                                   or source and str(source).startswith(l["identity"]["run_id"].rstrip("/") + "/"))]
                candidates = _selected_attempt_candidates(path, doc, evaluation.get("task_id"), candidates)
                identity = candidates[0]["identity"] if len(candidates) == 1 else None
            if identity is None:
                if eval_task_id and len(candidates) > 1:
                    errors.append({"code": "ambiguous_judge_identity", "path": str(path), "task": eval_task_id})
                continue
            identity = dict(identity)
            if "judge-only" in path.parts:
                identity.update(run_id=str(path.parent), attempt_id="judge-only:" + str(path.parent))
            task_id = eval_task_id or identity.get("task_id")
            calls = evaluation.get("judge_summary", {}).get("calls", [])
            for ci, call in enumerate(calls):
                audit = call.get("audit") or {}
                # Equal request bytes can belong to separate semantic calls.
                # A call's enclosing identity and index survive result mirrors.
                logical_call = "judgecall:" + hashlib.sha256(json.dumps([
                    identity.get("run_id"), identity.get("harness_id"), identity.get("user_id"),
                    task_id, identity.get("attempt_id"), ci,
                ], separators=(",", ":")).encode()).hexdigest()
                for ai, raw in enumerate(audit.get("responses") or []):
                    if not isinstance(raw, dict):
                        continue
                    model = audit.get("model")
                    if filters.get("model_id") and model not in filters["model_id"]:
                        continue
                    body = raw.get("response_body")
                    pointer = f"/evaluations/{ei}/judge_summary/calls/{ci}/audit/responses/{ai}"
                    restored, ambiguous = _retained_judge_row(path, pointer, {**identity, "task_id": task_id}, retained) if not body else (None, False)
                    if ambiguous:
                        errors.append({"code": "retained_judge_identity_ambiguous", "path": str(path), "json_pointer": pointer})
                        continue
                    request_body = raw.get("request_body")
                    payload = body.encode("utf-8") if isinstance(body, str) else b""
                    parsed = extract(payload, "openai-chat")
                    tokens = parsed.pop("usage")
                    # Compact retention can retain actual provider Usage while
                    # omitting bodies. Keep it known, with coverage explicit.
                    if not body and isinstance(raw.get("usage"), dict):
                        parsed = normalize_details(raw["usage"], "openai-chat")
                        tokens = parsed.pop("usage")
                        parsed.update(raw_usage=raw["usage"], response_complete=bool(raw.get("finish_reason")))
                    reqsha = hashlib.sha256(request_body.encode()).hexdigest() if isinstance(request_body, str) else call.get("request_sha256")
                    ressha = hashlib.sha256(payload).hexdigest() if body else None
                    response_id = None
                    if body:
                        try: response_id = json.loads(body).get("id")
                        except (ValueError, AttributeError): pass
                    physical = "judge:" + str(response_id or f"{identity['run_id']}:{task_id}:{identity.get('attempt_id')}:{call.get('request_sha256')}:{ci}:{raw.get('attempt', ai+1)}")
                    row = {**identity, **tokens, **parsed, "task_id": task_id, "model_id": model,
                           "model_request_id": physical, "operation_id": logical_call,
                           "operation_attribution": "explicit_logical_call", "protocol": "openai-chat",
                           "request_status": "succeeded" if raw.get("http_status", 0) == 200 else "error",
                           "http_status": raw.get("http_status"), "role": "Judge", "request_kind": "generation",
                           "request_sha256": reqsha, "response_sha256": ressha, "provider_response_id": response_id,
                           "usage_source": "provider_response_in_evaluator_audit", "request_capture_complete": bool(audit.get("attempt_count") == len(audit.get("responses", []))),
                           "evidence": {"path": str(path), "json_pointer": pointer}}
                    row.update(normalize_request(row)); row["role"] = "Judge"
                    if restored is not None:
                        row = _merge_evidence(restored, row)
                    mirror_key = (identity["run_id"], identity.get("user_id"), identity.get("harness_id"), task_id, identity.get("attempt_id"), call.get("request_sha256"),
                                  call.get("criterion_id"), ci, raw.get("attempt", ai + 1))
                    previous = output.get(mirror_key)
                    if previous is None or ressha and not previous.get("response_sha256"):
                        output[mirror_key] = _merge_evidence(row, *([previous] if previous else []))
                    else:
                        _merge_evidence(previous, row)
    return list(output.values()), errors


def deduplicate_roles(rows):
    unique = {}
    for row in rows:
        # Same response can be present in provider wire and multiple evaluator
        # exports. Distinct real attempts have different response identity.
        scope = (row.get("harness_id"), row.get("user_id"), row.get("task_id"), row["role"])
        # Provider-issued response identity links a wire record to its
        # evaluator mirror. Equal byte bodies alone cannot identify retries.
        response_id = row.get("provider_response_id")
        # An Agent physical request is owned by its capture and Attempt. A
        # provider response ID may be repeated by a replaying upstream and
        # cannot collapse two separately observed HTTP requests or Attempts.
        key = ((*scope, "provider", response_id)
               if response_id and row["role"] != "Agent" else
               (*tuple(row.get(k) for k in IDENTITY), row["role"], row["model_request_id"]))
        previous = unique.get(key)
        if previous is None or row.get("usage_status") == "complete" and previous.get("usage_status") != "complete":
            unique[key] = _merge_evidence(dict(row), *([previous] if previous else []))
        else:
            _merge_evidence(previous, row)
    return list(unique.values())


def aggregate(rows):
    known, exact, coverage = {}, {}, {}
    for field in (*FIELDS, "provider_reported_total_tokens", "standardized_total_tokens"):
        values = [row.get(field) for row in rows]
        coverage[field] = sum(v is not None for v in values)
        known[field] = sum(v for v in values if v is not None) if coverage[field] or not rows else None
        if field in FIELDS:
            exact_values = [r.get("standardized_tokens", {}).get(field) for r in rows]
            exact[field] = sum(exact_values) if all(v is not None for v in exact_values) else None
        elif field == "standardized_total_tokens":
            exact[field] = known[field] if coverage[field] == len(rows) else None
        else:
            exact[field] = known[field] if coverage[field] == len(rows) and all(r.get("usage_status") == "complete" for r in rows) else None
    reliable = sum(r.get("comparable") is True and r.get("usage_status") == "complete" for r in rows)
    logical = {tuple(r.get(k) for k in IDENTITY) + (r.get("role"), r.get("logical_model_request_id")) for r in rows if r.get("logical_model_request_id")}
    opaque = sum(not r.get("logical_model_request_id") for r in rows)
    capture_fields_present = any("request_capture_complete" in r for r in rows)
    captured = bool(rows) and all(r.get("request_capture_complete") is True for r in rows)
    # Older role fixtures did not carry the capture marker.  They remain
    # usable for backwards-compatible unit reports, while every production
    # row emitted by the collector carries the marker explicitly.
    legacy_capture = bool(rows) and not capture_fields_present
    terminal = bool(rows) and all(r.get("request_status") not in {"in_flight", None}
                                  for r in rows if "request_status" in r)
    identity_complete = bool(rows) and opaque == 0 and all(
        r.get("logical_identity_source") or r.get("operation_attribution") == "explicit_logical_call"
        for r in rows)
    # Preserve compatibility with pre-v3 in-memory rows that predate the
    # provenance fields.  Persisted Collector rows always carry one of the
    # explicit markers above and therefore still require it.
    legacy_identity = bool(rows) and not opaque and not any(
        "logical_identity_source" in r or "operation_attribution" in r for r in rows)
    logical_exact = bool(rows) and not opaque and (identity_complete or legacy_identity) and (captured or legacy_capture) and terminal
    if not rows:
        logical_exact = False
    failed_statuses = {"error", "failed", "interrupted", "timeout"}
    def request_failed(row):
        return (row.get("request_status") in failed_statuses or
                isinstance(row.get("http_status"), int) and row["http_status"] >= 400)
    failed = sum(request_failed(r) for r in rows)
    successful = sum(not request_failed(r) and (
        r.get("request_status") in {"succeeded", "completed"} or
        isinstance(r.get("http_status"), int) and 200 <= r["http_status"] < 300)
        for r in rows)
    return {"http_attempt_count": len(rows), "observed_logical_request_count": len(logical),
            "opaque_physical_request_count": opaque,
            "request_count": len(rows) if captured else None,
            "request_count_status": "complete" if captured else "unknown_capture_incomplete",
            "successful_request_count": successful if captured else None,
            "failed_request_count": failed if captured else None,
            "logical_request_count": len(logical) if logical_exact else None,
            "logical_request_status": "complete" if logical_exact else
                "unknown_no_rows" if not rows else
                "unknown_opaque_identity" if opaque else
                "unknown_capture_incomplete" if not (captured or legacy_capture) else
                "unknown_nonterminal_attempt" if not terminal else "unknown_identity_evidence",
            "logical_identity_complete": identity_complete or legacy_identity,
            "reliable_usage_requests": reliable, "unknown_or_unreliable_usage_requests": len(rows) - reliable,
            "usage_coverage": reliable / len(rows) if rows else None,
            "known_tokens": known, "exact_tokens": exact, "field_coverage": coverage,
            "exact_run_tokens": exact.copy() if captured else dict.fromkeys(exact),
            "request_statuses": dict(sorted(Counter(str(r.get("http_status") or r.get("request_status")) for r in rows).items())),
            "usage_statuses": dict(sorted(Counter(r.get("usage_status", "unknown") for r in rows).items())),
            "request_kinds": dict(sorted(Counter(r.get("request_kind", "generation") for r in rows).items())),
            "capture_complete": captured,
            "physical_request_ids": [r["model_request_id"] for r in rows],
            **request_bound_summary(rows)}


def _resolve_source(result_path, source):
    candidates = [Path(source), PROJECT / str(source).removeprefix("camact/"), result_path.parent / source]
    return next((p for p in candidates if p.exists()), None)


@lru_cache(maxsize=256)
def _artifact_rows(path):
    if path.suffix == ".jsonl":
        return [row for _, row in read_lines(path)[0]]
    value = read_json(path, {})
    return [value] if isinstance(value, dict) else []


def _selected_attempt_candidates(path, doc, external_task, candidates):
    """Narrow only with saved physical execution or retained exact identity.

    Baseline retries share a top Run and task. Its frozen standard artifact's
    diagnostics.source_path and canonical task_results trajectory_path name
    the actual selected execution; request order and UUIDs cannot select it.
    """
    if not candidates:
        return candidates
    anchors = []
    source = _resolve_source(path, doc.get("source", ""))
    if source and source.is_file():
        artifact = next((a for a in _artifact_rows(source) if a.get("task_id") == external_task), {})
        selected = artifact.get("diagnostics", {}).get("source_path")
        if isinstance(selected, str) and selected:
            resolved = _resolve_source(source, selected)
            if resolved is not None:
                anchors.append(resolved)
        task_results = source.parent / "task_results.jsonl"
        for _, result in read_lines(task_results)[0]:
            if result.get("task_id") == external_task and result.get("trajectory_path"):
                resolved = _resolve_source(task_results, result["trajectory_path"])
                if resolved is not None:
                    anchors.append(resolved)
    def from_anchors(values):
        identified = {tuple(identity.get(k) for k in IDENTITY) for anchor in values
                      if (identity := _enclosing_identity(anchor, candidates)) is not None}
        if len(identified) > 1:
            return candidates
        return [l for l in candidates if tuple(l["identity"].get(k) for k in IDENTITY) in identified]
    if anchors:
        return from_anchors(anchors)
    # Before cleanup, the retention hook records the exact selected identity.
    # Re-use only that same result/task record after its raw anchors are gone.
    retained = read_json(path.parent / "token_usage/accounting_v3/summary.json", {})
    selected = {tuple(t.get(k) for k in ("agent_run_id", "harness_id", "user_id", "task_id", "agent_attempt_id"))
                for t in retained.get("tasks", []) if t.get("external_task_id") == external_task
                and t.get("result_path") == str(path)}
    if selected:
        if len(selected) > 1:
            return []
        matched = [l for l in candidates if tuple(l["identity"].get(k) for k in IDENTITY) in selected]
        return matched if len(matched) <= 1 else candidates
    matched = from_anchors([path, *([source] if source else [])])
    return matched if matched else candidates


def _task_steps(path, doc, external_task):
    source = _resolve_source(path, doc.get("source", ""))
    if source and source.is_file():
        for artifact in _artifact_rows(source):
            if artifact.get("task_id") == external_task:
                steps = artifact.get("runtime_metadata", {}).get("agent_turns")
                if isinstance(steps, int) and not isinstance(steps, bool):
                    return steps, str(source)
    # The retention hook has already exported numeric Step evidence before
    # deleting the frozen raw artifact. Re-use that same task's saved value.
    compact = read_json(path.parent / "token_usage/accounting_v3/summary.json", {})
    for task in compact.get("tasks", []):
        if task.get("external_task_id") == external_task and task.get("result_path") == str(path):
            steps = task.get("task_steps")
            if isinstance(steps, int) and not isinstance(steps, bool):
                return steps, task.get("task_steps_evidence")
    return None, None


def selection(roots, ledgers, snapshot_path=None, evaluation_documents=None, filters=None):
    """Read evaluator status; never call an evaluator or invent a terminal."""
    tasks, errors, filters = {}, [], filters or {}
    documents = {Path(p).resolve(): doc for p, doc in (evaluation_documents or {}).items()}
    if snapshot_path:
        snapshot = read_json(snapshot_path)
        entries = [(s["method"], key, t, PROJECT / t["result_path"]) for s in snapshot["summaries"] for key, t in s["latest_tasks"].items()]
    else:
        entries = []
        paths = {p for root in roots for p in Path(root).rglob("result.json") if "evaluation" not in p.parts}
        # Internal evaluation result is the fallback before retention finishes.
        if not paths:
            paths = {p for root in roots for p in Path(root).rglob("result.json")}
        for path in sorted(paths, key=lambda p: (p.stat().st_mtime_ns, str(p))):
            doc = documents.get(path, read_json(path, {}))
            identity = _enclosing_identity(path, ledgers)
            if identity is None:
                identity = next((l["identity"] for l in ledgers if str(path).startswith(l["identity"]["run_id"])), None)
            if identity is None:
                # A scoring-only recovery may live outside the frozen Agent
                # Run and need not use a particular directory name. Its saved
                # artifact source binds it to the existing physical ledger.
                source = _resolve_source(path, doc.get("source", ""))
                if source:
                    identity = _enclosing_identity(source, ledgers)
                    if identity is None:
                        identity = next((l["identity"] for l in ledgers
                                         if str(source).startswith(l["identity"]["run_id"].rstrip("/") + "/")), None)
            if identity:
                for evaluation in doc.get("evaluations", []):
                    entries.append((identity["harness_id"], evaluation["task_id"], evaluation, path))
    for harness, external_task, saved, path in entries:
        harness = "canonical-baseline" if harness == "baseline" else harness
        doc = documents.get(path, read_json(path, {}))
        evaluation = next((e for e in doc.get("evaluations", []) if e.get("task_id") == external_task), None)
        if not evaluation:
            errors.append({"code": "selected_evaluation_missing", "path": str(path), "task": external_task}); continue
        grader = evaluation.get("grader")
        task_id = Path(grader).parent.name if grader else None
        if not task_id or not task_id.startswith("task_"):
            task_id = next((p[:8] for p in path.parts if p.startswith("task_") and p[5:8].isdigit()), None)
        candidates = [l for l in ledgers if l["identity"].get("harness_id") == harness and l["identity"].get("task_id") == task_id
                      and (str(path).startswith(l["identity"]["run_id"].rstrip("/") + "/"))]
        frozen_source = False
        if "judge-only" in path.parts or not candidates:
            artifact = _resolve_source(path, doc.get("source", ""))
            candidates = [l for l in ledgers if l["identity"].get("harness_id") == harness and l["identity"].get("task_id") == task_id
                          and artifact and str(artifact).startswith(l["identity"]["run_id"].rstrip("/") + "/")]
            frozen_source = bool(candidates)
        candidates = _selected_attempt_candidates(path, doc, external_task, candidates)
        excluded = saved.get("excluded", evaluation.get("infrastructure_failure", False)) or evaluation.get("score") is None
        row = {"harness_id": harness, "task_id": task_id, "external_task_id": external_task,
               "result_path": str(path), "score": evaluation.get("score"), "strict_success": evaluation.get("strict_success"),
               "excluded": bool(excluded), "status": evaluation.get("status"), "failure_type": evaluation.get("failure_type"),
               "agent_attempt_id": None, "agent_run_id": None, "task_steps": None,
               "judge_only": "judge-only" in path.parts or frozen_source}
        row["task_steps"], row["task_steps_evidence"] = _task_steps(path, doc, external_task)
        if len(candidates) == 1:
            row.update(agent_attempt_id=candidates[0]["identity"]["attempt_id"], agent_run_id=candidates[0]["identity"]["run_id"])
        user_id = candidates[0]["identity"].get("user_id") if len(candidates) == 1 else external_task.rsplit("_", 2)[0]
        row["user_id"] = user_id
        scope = {**row, "run_id": row["agent_run_id"], "attempt_id": row["agent_attempt_id"]}
        if any(str(scope.get(k)) not in values for k, values in filters.items() if k != "model_id"):
            continue
        if filters.get("model_id") and not any(source.get("model_id") in filters["model_id"]
                                               for ledger in candidates for source, _ in ledger["rows"].values()):
            continue
        if len(candidates) != 1 and not excluded:
            errors.append({"code": "selected_agent_attempt_ambiguous", "path": str(path), "task": task_id, "candidate_count": len(candidates)})
        task_key = (user_id, harness, external_task)
        if snapshot_path or task_key not in tasks or not row["excluded"] or tasks[task_key]["excluded"]:
            tasks[task_key] = row
        else:
            tasks[task_key]["latest_unscored_attempt"] = {"result_path": str(path), "status": row["status"]}
    return sorted(tasks.values(), key=lambda t: (t["harness_id"], t["external_task_id"])), errors


def build(roots, *, filters=None, snapshot_path=None, evaluation_documents=None):
    roots = [Path(p).resolve() for p in roots]
    ledgers, errors = load_ledgers(roots, filters)
    agent = normalized_rows(ledgers, filters)
    roles, role_errors = role_rows(roots, ledgers, filters); errors.extend(role_errors)
    judges, judge_errors = judge_rows(roots, ledgers, filters, evaluation_documents); errors.extend(judge_errors)
    roles = deduplicate_roles(roles + judges)
    tasks, selection_errors = selection(roots, ledgers, snapshot_path, evaluation_documents, filters); errors.extend(selection_errors)
    selected_ids = {(t["agent_run_id"], t["harness_id"], t["user_id"], t["task_id"], t["agent_attempt_id"]) for t in tasks if not t["excluded"] and t["agent_attempt_id"]}
    selected = [r for r in agent if tuple(r.get(k) for k in IDENTITY) in selected_ids]
    requests = agent + roles
    effective = [r for r in agent if r["usage_status"] == "complete" and r["comparable"]]
    harnesses = sorted({r["harness_id"] for r in requests} | {t["harness_id"] for t in tasks})
    views = {name: {h: aggregate([r for r in rows if r["harness_id"] == h]) for h in harnesses}
             for name, rows in (("effective_usage", effective), ("selected_run", selected), ("all_attempts", agent))}
    for task in tasks:
        task_rows = [r for r in agent if tuple(r.get(k) for k in IDENTITY) == (task["agent_run_id"], task["harness_id"], task["user_id"], task["task_id"], task["agent_attempt_id"])]
        task["agent_tokens"] = aggregate(task_rows)
    formal = {}
    for h in harnesses:
        scoped = [t for t in tasks if t["harness_id"] == h]
        scored = [t for t in scoped if not t["excluded"]]
        totals = [t["agent_tokens"]["exact_run_tokens"]["total_tokens"] for t in scored]
        steps = [t["task_steps"] for t in scored]
        formal[h] = {"scored_tasks": len(scored), "excluded_tasks": len(scoped) - len(scored),
                     "strict_success_count": sum(bool(t["strict_success"]) for t in scored),
                     "mean_score_per_100": sum(t["score"] for t in scored) * 100 / len(scored) if scored else None,
                     "mean_exact_agent_tokens_per_scored_task": sum(totals) / len(totals) if totals and all(v is not None for v in totals) else None,
                     "task_steps": sum(steps) if steps and all(v is not None for v in steps) else None,
                     "task_step_coverage": sum(v is not None for v in steps)}
    scored_scopes = [{(t["user_id"], t["task_id"]) for t in tasks if t["harness_id"] == h and not t["excluded"]} for h in harnesses]
    paired_scope = set.intersection(*scored_scopes) if scored_scopes else set()
    paired = {}
    for h in harnesses:
        matched = [t for t in tasks if t["harness_id"] == h and not t["excluded"] and (t["user_id"], t["task_id"]) in paired_scope]
        values = [t["agent_tokens"]["exact_run_tokens"]["total_tokens"] for t in matched]
        paired[h] = {"task_count": len(matched), "mean_score_per_100": sum(t["score"] for t in matched) * 100 / len(matched) if matched else None,
                     "mean_agent_total_tokens": sum(values) / len(values) if values and all(v is not None for v in values) else None}
    result = {"schema_version": VERSION, "filters": filters or {}, "source_roots": [str(p) for p in roots],
              "historical_read_only": True, "views": views, "formal_results": formal, "tasks": tasks, "errors": errors,
              "role_views": {h: {role: aggregate([r for r in requests if r["harness_id"] == h and r["role"] == role]) for role in ROLES} for h in harnesses},
              "all_roles_all_attempts": aggregate(requests),
              "paired_scored_tasks": {"scope": sorted([list(s) for s in paired_scope]), "harnesses": paired,
                                      "note": "Intersection of valid scored tasks only; complete usage does not prove equal native tools, context, or reasoning observability. Full-scope means with different denominators are not a paired ranking."},
              "definitions": {"effective_usage": "Exact primary sum for observed Agent requests with trusted complete Usage; task/generation success is not a filter.",
                              "selected_run": "Agent requests from the immutable source Run of each latest valid saved evaluation; excludes infrastructure/unscored tasks, includes scored agent failures. Judge-only keeps frozen Agent Run once.",
                              "all_attempts": "Every observed Agent physical HTTP attempt, including retries, failures and auxiliary generations, deduplicated by full identity and physical id.",
                              "roles": "Role view contains every observed role HTTP attempt; Simulator/Judge from original provider wire, never from CLI estimates or evaluation criterion counts.",
                              "reasoning": "Subset of output when reported. Unknown stays null. No inference from thinking=enabled.",
                              "cache": "Included in standardized input using protocol contract; missing optional breakdowns remain null.",
                              "coverage": "Ledger reconciliation proves Agent boundary capture; role wire covers instrumented provider boundary. Opaque provider-internal retries/logical operations are unknown."},
              "evidence": [{"identity": l["identity"], "journal": l["journal"], "mirrors": l["mirrors"],
                            "request_count": len(l["rows"])} for l in ledgers]}
    return result, requests


def write(result, requests, output):
    output = Path(output); output.mkdir(parents=True, exist_ok=True)
    (output / "summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # Numeric-only usage evidence and source links; no raw prompts/responses.
    fields = ["schema_version", "normalizer_version", *IDENTITY, "model_request_id", "physical_http_attempt_id", "operation_id", "logical_model_request_id", "operation_attribution", "logical_identity_source", "logical_request_observability", "native_session_id", "native_turn_id", "native_step_id", "native_through_seq", "native_request_id", "native_request_id_source", "request_retry_identity", "agent_operation_type", "role", "request_kind", "protocol", "model_id", "request_status", "http_status", "timestamp", "retry_attempt",
              *FIELDS, "provider_reported_total_tokens", "standardized_total_tokens", "standardized_tokens", "field_status", "field_provenance", "usage_status", "missing_reason", "usage_source", "coverage_status", "generation_status", "comparable", "request_capture_complete", "request_sha256", "response_sha256", "provider_response_id", "evidence", "evidence_aliases"]
    with (output / "requests.jsonl").open("w", encoding="utf-8") as stream:
        for row in requests:
            stream.write(json.dumps({k: row.get(k) for k in fields}, ensure_ascii=False) + "\n")
    with (output / "tasks.csv").open("w", newline="", encoding="utf-8") as stream:
        task_fields = ["harness_id", "user_id", "task_id", "external_task_id", "excluded", "status", "score", "strict_success", "agent_run_id", "agent_attempt_id", "judge_only", "task_steps", "result_path", "task_steps_evidence"]
        writer = csv.DictWriter(stream, fieldnames=task_fields); writer.writeheader()
        writer.writerows({k: t.get(k) for k in task_fields} for t in result["tasks"])
    headers = ["view", "harness", "role", "http_attempts", "request_count", "request_count_status", "successful_request_count", "failed_request_count", "reliable_usage", "missing_or_unreliable_usage", "usage_coverage", *["known_" + f for f in FIELDS], *["exact_" + f for f in FIELDS]]
    with (output / "summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream); writer.writerow(headers)
        for view, harnesses in result["views"].items():
            for harness, data in harnesses.items():
                writer.writerow([view, harness, "Agent", data["http_attempt_count"], data["request_count"], data["request_count_status"], data["successful_request_count"], data["failed_request_count"], data["reliable_usage_requests"], data["unknown_or_unreliable_usage_requests"], data["usage_coverage"], *[data["known_tokens"][f] for f in FIELDS], *[data["exact_tokens"][f] for f in FIELDS]])
        for harness, roles in result["role_views"].items():
            for role, data in roles.items():
                writer.writerow(["all_roles_all_attempts", harness, role, data["http_attempt_count"], data["request_count"], data["request_count_status"], data["successful_request_count"], data["failed_request_count"], data["reliable_usage_requests"], data["unknown_or_unreliable_usage_requests"], data["usage_coverage"], *[data["known_tokens"][f] for f in FIELDS], *[data["exact_tokens"][f] for f in FIELDS]])
    lines = ["# Unified Token Accounting", "", f"Rules: `{VERSION}`. Main tables include Agent and native auxiliary generation only.", "A ≥ value is the confirmed lower bound, including reliable requests inside incomplete tasks. Exact totals remain separate in JSON.", "", "## Formal results and selected Runs", "", "| Harness | Scored / Excluded | Mean /100 | Strict | Physical requests | Input | Output | Total | Usage coverage | Mean exact Agent Total / scored Task | Task Steps |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    def value(v): return "N/A" if v is None else f"{v:,}" if isinstance(v, int) else str(round(v, 6)) if isinstance(v, float) else str(v)
    def table_row(values): return "| " + " | ".join(value(v) for v in values) + " |"
    def tokens(data):
        view = {**data, "exact_tokens": data["exact_run_tokens"]}
        return [token_field_display(view, field) for field in PRIMARY]
    for harness, data in result["views"]["selected_run"].items():
        tasks = [t for t in result["tasks"] if t["harness_id"] == harness]; scored = [t for t in tasks if not t["excluded"]]
        formal = result["formal_results"][harness]
        lines.append(table_row([harness, f"{len(scored)} / {len(tasks)-len(scored)}", formal["mean_score_per_100"], f"{sum(bool(t['strict_success']) for t in scored)} / {len(scored)}", data["request_count"], *tokens(data), data["usage_coverage"], formal["mean_exact_agent_tokens_per_scored_task"], formal["task_steps"]]))
    for view, title in (("effective_usage", "Reliable Usage subset — exact for included requests"), ("all_attempts", "All Attempts — known consumption")):
        lines += ["", "## " + title, "", "| Harness | Physical requests | Observed HTTP attempts | Reliable Usage | Unknown / Unreliable | Input | Output | Total | Cache read | Cache write | Reasoning | Coverage |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for harness, data in result["views"][view].items():
            lines.append(table_row([harness, data["request_count"], data["http_attempt_count"], data["reliable_usage_requests"], data["unknown_or_unreliable_usage_requests"], *tokens(data), *[data["known_tokens"][f] for f in ("cache_read_tokens", "cache_write_tokens", "reasoning_tokens")], data["usage_coverage"]]))
    lines += ["", "Physical requests is the complete captured model HTTP count when request capture is closed; observed HTTP attempts remains an audit count even when capture is incomplete.", "Breakdown columns are known sums; exactness and per-field coverage are in JSON. Missing breakdowns remain N/A, never invented zero.", "", "## Roles — all observed Attempts", "", "| Harness | Role | Physical requests | Observed HTTP attempts | Known Input | Known Output | Known Total | Unknown / Unreliable Usage |", "|---|---|---:|---:|---:|---:|---:|---:|"]
    for harness, roles in result["role_views"].items():
        for role, data in roles.items():
            lines.append(table_row([harness, role, data["request_count"], data["http_attempt_count"], *tokens(data), data["unknown_or_unreliable_usage_requests"]]))
    lines += ["", "## Matched scored task scope", "", f"Common task count: {len(result['paired_scored_tasks']['scope'])}. {result['paired_scored_tasks']['note']}", "", "| Harness | Tasks | Mean /100 | Mean exact Agent Token / Task |", "|---|---:|---:|---:|"]
    lines += [table_row([h, d["task_count"], d["mean_score_per_100"], d["mean_agent_total_tokens"]]) for h, d in result["paired_scored_tasks"]["harnesses"].items()]
    lines += ["", "## Accounting rules", ""] + [f"- **{k}**: {v}" for k, v in result["definitions"].items()]
    lines += ["", "Unscored tasks remain individually listed in summary.json and never enter scored-task averages. Every numeric aggregate lists physical request IDs, linked to requests.jsonl source path/line. No historical score is changed.", "", f"Accounting errors: {len(result['errors'])}. An error prevents an unrestricted completeness claim."]
    (output / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def report(roots, output, *, filters=None, snapshot_path=None, evaluation_documents=None):
    result, requests = build(roots, filters=filters, snapshot_path=snapshot_path, evaluation_documents=evaluation_documents)
    write(result, requests, output)
    return result


def safe_report(roots, output, **kwargs):
    """Accounting errors must not influence execution, evaluator or rewards."""
    try:
        return report(roots, output, **kwargs)
    except Exception as exc:
        output = Path(output); output.mkdir(parents=True, exist_ok=True)
        (output / "report_error.json").write_text(json.dumps({"schema_version": VERSION,
            "error": type(exc).__name__, "complete": False}) + "\n", encoding="utf-8")
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", nargs="+", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path)
    for flag in ("run-id", "user-id", "task-id", "harness-id", "model-id", "attempt-id"):
        parser.add_argument("--" + flag, action="append")
    args = parser.parse_args()
    filters = {k: v for k, v in vars(args).items() if k.endswith("_id") and v}
    result = report(args.input, args.output, filters=filters, snapshot_path=args.snapshot)
    print(json.dumps({"schema_version": VERSION, "tasks": len(result["tasks"]), "errors": result["errors"]}))


if __name__ == "__main__":
    main()
