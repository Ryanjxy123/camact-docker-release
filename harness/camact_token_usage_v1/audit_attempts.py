"""Offline, deterministic index of every Manifest Agent Attempt and its evidence.

Reads exact output paths and compact ledgers first. When an interrupted output
has no compact export, reads its defined Collector directories without walking
the benchmark tree. Does not execute an Agent, Simulator, evaluator or provider.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path

from .unified_report import IDENTITY, aggregate, normalized_rows

VERSION = "camact.manifest_attempt_usage_audit.v1"
FIELDS = ("input_tokens", "output_tokens", "total_tokens", "cache_read_tokens", "cache_write_tokens")


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _harness(value):
    return "baseline" if value == "canonical-baseline" else value


def _document(path):
    content = path.read_bytes()
    return json.loads(content), {"path": str(path), "sha256": hashlib.sha256(content).hexdigest(),
                                "size": len(content)}


def _lines(path):
    content = path.read_bytes()
    evidence = {"path": str(path), "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
    rows, errors = [], []
    for number, line in enumerate(content.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError("request must be an object")
            rows.append((number, row))
        except (ValueError, UnicodeError):
            errors.append({"code": "malformed_request_line", "path": str(path), "line": number})
    return rows, evidence, errors


def plan_attempts(manifests):
    plans, fingerprints = {}, []
    for path in manifests:
        path = Path(path).resolve()
        document, fingerprint = _document(path)
        fingerprints.append(fingerprint)
        for position, slot in enumerate(document["tasks"]):
            selected = slot.get("final_formal_run_id") or slot.get("agent_run_id")
            if not selected:
                provenance = document.get("slot_provenance", {}).get(
                    "/".join(slot[k] for k in ("user_id", "harness", "task")), {})
                number = provenance.get("selected_attempt")
                matches = [a for a in slot.get("attempts", [])
                           if number is not None and a.get("attempt", a.get("number")) == number]
                if len(matches) == 1:
                    attempt = matches[0]
                    selected = (attempt.get("output") or attempt.get("run_id")
                                or str(Path(attempt["directory"]) / "run"))
            attempts = list(enumerate(slot.get("attempts") or []))
            outputs = {str(a.get("output") or a.get("run_id") or (Path(a["directory"]) / "run"))
                       for _, a in attempts if a.get("output") or a.get("run_id") or a.get("directory")}
            if selected and selected not in outputs:
                attempts.append((None, {"output": selected, "status": slot.get("status"),
                                        "reference_kind": "imported_selected_agent"}))
            if not attempts:
                attempts.append((None, {"reference_kind": "missing_attempt_registration"}))
            for number, attempt in attempts:
                output = attempt.get("output") or attempt.get("run_id")
                if not output and attempt.get("directory"):
                    output = str(Path(attempt["directory"]) / "run")
                output = str(Path(output).resolve()) if output else None
                key = (slot["user_id"], _harness(slot["harness"]), slot["task"], output)
                registration = {
                    "manifest": str(path), "manifest_sha256": fingerprint["sha256"],
                    "task_pointer": f"/tasks/{position}",
                    "attempt_pointer": f"/tasks/{position}/attempts/{number}" if number is not None else None,
                    "attempt_number": attempt.get("attempt", attempt.get("number")),
                    "status": attempt.get("status"),
                    "mode": attempt.get("mode", attempt.get("recovery_mode")),
                    "reference_kind": attempt.get("reference_kind", "registered_attempt"),
                    "selected_agent": bool(output and selected and output == str(Path(selected).resolve())),
                    "slot_scored": bool(slot.get("scored", slot.get("has_valid_score"))),
                    "verdict": {k: (attempt.get("verdict") or {}).get(k)
                                for k in ("scored", "infrastructure_error", "failure_type")},
                }
                if key not in plans:
                    plans[key] = {"user_id": slot["user_id"], "harness": _harness(slot["harness"]),
                                  "task": slot["task"], "external_task_id": slot.get("task_id"),
                                  "output": output, "registrations": []}
                plans[key]["registrations"].append(registration)
    return sorted(plans.values(), key=lambda p: (p["user_id"], p["harness"], p["task"], p["output"] or "")), fingerprints


def _raw_capture(output, plan):
    """Inspect only the output's defined ledger locations; retain partial data."""
    bases = [output / "token_usage/ledgers", output / "runs/execution/token_usage",
             output / "runs/token_usage"]
    ledgers, evidence, errors = {}, [], []
    for base in bases:
        if not base.is_dir():
            continue
        for directory in sorted(base.iterdir()):
            identity_path = directory / "identity.json"
            if not identity_path.is_file():
                continue
            identity, ref = _document(identity_path)
            summary_path = directory / "task_summary.json"
            if summary_path.is_file():
                summary, summary_ref = _document(summary_path)
                evidence.append(summary_ref)
            else:
                summary = {}
            journal = directory / "request_events.jsonl"
            if not journal.is_file():
                journal = directory / "requests.jsonl"
            rows, journal_ref, parse_errors = _lines(journal)
            evidence.extend([ref, journal_ref])
            errors.extend(parse_errors)
            latest = {}
            for line, row in rows:
                request_id = row.get("model_request_id")
                if not request_id or any(row.get(k) != identity.get(k) for k in IDENTITY):
                    errors.append({"code": "raw_request_identity_mismatch", "path": str(journal), "line": line})
                else:
                    latest[request_id] = (row, line)
            key = tuple(identity.get(k) for k in IDENTITY)
            candidate = dict(identity=identity, summary=summary, rows=latest, journal=str(journal))
            if key in ledgers and {k: v[0] for k, v in ledgers[key]["rows"].items()} != {k: v[0] for k, v in latest.items()}:
                errors.append({"code": "conflicting_raw_attempt_mirrors", "identity": list(key)})
            else:
                ledgers[key] = candidate
    scoped = [ledger for ledger in ledgers.values()
              if _planned_identity_matches(ledger["identity"], plan)]
    zero = bool(scoped) and all(not ledger["rows"] and ledger["summary"].get("closed") is True
               and ledger["summary"].get("coverage") == "exclusive_agent_http_boundary"
               and ledger["summary"].get("collector_errors") == []
               and ledger["summary"].get("model_request_count") == 0
               and ledger["summary"].get("request_count_reconciliation")
               and all(c.get("matched") is True and c.get("expected_model_requests") == 0
                       and c.get("recorded_model_requests") == 0
                       for c in ledger["summary"]["request_count_reconciliation"])
               for ledger in scoped)
    return normalized_rows(list(ledgers.values())), evidence, errors, zero


def _matches(row, plan):
    return (row.get("role") == "Agent" and row.get("run_id") == plan["output"]
            and row.get("user_id") == plan["user_id"] and row.get("task_id") == plan["task"]
            and _harness(row.get("harness_id")) == plan["harness"])


def _planned_identity_matches(identity, plan):
    return (identity.get("run_id") == plan["output"]
            and identity.get("user_id") == plan["user_id"]
            and identity.get("task_id") == plan["task"]
            and _harness(identity.get("harness_id")) == plan["harness"])


def recover_plan(plan, historical):
    record = dict(plan, schema_version=VERSION)
    rows, evidence, errors, zero = [], [], [], False
    try:
        output = Path(plan["output"]) if plan["output"] else None
        compact = output / "token_usage/accounting_v3/requests.jsonl" if output else None
        if compact and compact.is_file():
            entries, ref, errors = _lines(compact)
            evidence.append(ref)
            rows = [dict(row, audit_source={**ref, "line": line}) for line, row in entries if _matches(row, plan)]
            record["recovery_method"] = "compact_request_ledger"
            if not rows:
                # A scoring retry may own the result wrapper while its
                # accounting task explicitly points to the earlier Agent Run.
                # Validate that relation with the same strict binder used by
                # score-only recovery, then read only that bound physical
                # ledger. This avoids treating a wrapper path mismatch as a
                # missing request count.
                try:
                    from deployment.full_benchmark import bound_task_usage
                    slot = {"user_id": plan["user_id"], "harness": plan["harness"],
                            "task": plan["task"], "task_id": plan.get("external_task_id")}
                    bound = bound_task_usage(output, slot)
                    binding = (bound or {}).get("usage_binding") or {}
                    bound_path = Path(binding.get("requests_path", ""))
                    identity = binding.get("identity") or {}
                    if bound and bound_path.is_file() and identity:
                        bound_entries, bound_ref, bound_errors = _lines(bound_path)
                        evidence.append(bound_ref)
                        errors.extend(bound_errors)
                        rows = [dict(row, audit_source={**bound_ref, "line": line})
                                for line, row in bound_entries
                                if row.get("role") == "Agent"
                                and all(row.get(key) == value for key, value in identity.items())]
                        record["recovery_method"] = "task_summary_agent_run_ledger"
                        record["bound_usage"] = bound
                except (OSError, ValueError, TypeError, KeyError, AttributeError):
                    pass
        else:
            key = (plan["user_id"], plan["harness"], plan["task"], plan["output"])
            rows = list(historical.get(key, []))
            if not rows and plan.get("historical_agent_binding"):
                binding = plan["historical_agent_binding"]
                original_key = (plan["user_id"], plan["harness"], plan["task"], binding["agent_run_id"])
                rows = list(historical.get(original_key, []))
                if rows:
                    record["historical_agent_binding"] = binding
            if rows:
                evidence = list({row["audit_source"]["path"]: {k: v for k, v in row["audit_source"].items() if k != "line"}
                                 for row in rows}.values())
                record["recovery_method"] = "retained_historical_request_ledger"
            elif output:
                raw, evidence, errors, zero = _raw_capture(output, plan)
                rows = [dict(row, audit_source=row.get("evidence")) for row in raw if _matches(row, plan)]
                record["recovery_method"] = "raw_collector_journal"
            else:
                record["recovery_method"] = "no_attempt_output"
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        errors.append({"code": "source_read_error", "type": type(exc).__name__})
    unique = {}
    for row in rows:
        identity = tuple(row.get(k) for k in IDENTITY)
        request_id = row.get("model_request_id")
        if not request_id or any(value is None for value in identity):
            errors.append({"code": "incomplete_physical_request_identity"})
            continue
        key = (*identity, request_id)
        if key in unique:
            previous = unique[key]
            if any(previous.get(k) != row.get(k) for k in (*FIELDS, "request_status", "standardized_tokens")):
                errors.append({"code": "conflicting_physical_request", "request_id": request_id})
        unique[key] = row
    rows = list(unique.values())
    if errors:
        rows = [dict(row, request_capture_complete=False) for row in rows]
        zero = False
    usage = aggregate(rows)
    if zero and not rows:
        usage.update(request_count=0, request_count_status="confirmed_zero", capture_complete=True,
                     successful_request_count=0, failed_request_count=0,
                     exact_run_tokens={field: 0 for field in usage["exact_run_tokens"]})
    record.update(usage=usage, evidence=evidence, errors=errors,
                  recovery_status="confirmed_zero" if zero and not rows else
                      "complete" if usage["capture_complete"] else "partial" if rows else "unrecoverable",
                  remaining_reason=None if usage["capture_complete"] else
                      "capture_not_closed_or_reconciled" if rows else "no_readable_bound_agent_capture")
    identities = defaultdict(list)
    for row in rows:
        identities[tuple(row.get(k) for k in IDENTITY)].append(row)
    record["agent_identities"] = [{"identity": dict(zip(IDENTITY, identity)),
                                   "native_session_ids": sorted({r.get("native_session_id") or r.get("session_id")
                                                                 for r in scoped if r.get("native_session_id") or r.get("session_id")}),
                                   "physical_request_ids": [r["model_request_id"] for r in scoped]}
                                  for identity, scoped in sorted(identities.items(), key=lambda item: str(item[0]))]
    return record, rows


def audit(manifests, archive_root, *, historical_requests=None, historical_manifest=None, workers=8):
    archive_root = Path(archive_root).resolve()
    plans, fingerprints = plan_attempts(manifests)
    if historical_manifest:
        document, fingerprint = _document(Path(historical_manifest).resolve())
        fingerprints.append(fingerprint)
        aliases = defaultdict(list)
        for index, task in enumerate(document.get("tasks", [])):
            if not task.get("agent_run_id") or not task.get("final_run_id"):
                continue
            key = (task.get("user_id"), _harness(task.get("harness")), task.get("task"),
                   str(Path(task["final_run_id"]).resolve()))
            aliases[key].append({"agent_run_id": str(Path(task["agent_run_id"]).resolve()),
                                 "external_task_id": task.get("task_id"),
                                 "manifest": fingerprint, "json_pointer": f"/tasks/{index}",
                                 "recovery_mode": task.get("recovery_mode")})
        for plan in plans:
            key = (plan["user_id"], plan["harness"], plan["task"], plan["output"])
            candidates = [a for a in aliases.get(key, []) if a["external_task_id"] == plan["external_task_id"]]
            if len(candidates) == 1:
                plan["historical_agent_binding"] = candidates[0]
    historical = defaultdict(list)
    if historical_requests:
        entries, ref, errors = _lines(Path(historical_requests).resolve())
        if errors:
            raise ValueError("Historical request sidecar is malformed")
        fingerprints.append(ref)
        for line, row in entries:
            if row.get("role") == "Agent":
                key = (row.get("user_id"), _harness(row.get("harness_id")), row.get("task_id"), row.get("run_id"))
                historical[key].append(dict(row, audit_source={**ref, "line": line}))
        planned = {(p["user_id"], p["harness"], p["task"], p["output"]) for p in plans}
        for key in sorted(set(historical) - planned, key=str):
            user, harness, task, output = key
            plans.append({"user_id": user, "harness": harness, "task": task,
                          "external_task_id": None, "output": output,
                          "registrations": [{"reference_kind": "retained_historical_attempt",
                                              "ledger": ref, "selected_agent": False}]})
        plans.sort(key=lambda p: (p["user_id"], p["harness"], p["task"], p["output"] or ""))
    records, requests = [], {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for record, rows in pool.map(lambda plan: recover_plan(plan, historical), plans):
            records.append(record)
            for row in rows:
                key = (*tuple(row.get(k) for k in IDENTITY), row["model_request_id"])
                requests[key] = row
    rows = [requests[key] for key in sorted(requests, key=str)]
    coverage = Counter(record["recovery_status"] for record in records)
    observed = aggregate(rows)
    complete = all(record["usage"]["capture_complete"] for record in records)
    summary = {
        "schema_version": VERSION, "sources": fingerprints,
        "scope": "Agent model HTTP attempts only; each Run/User/Task/Harness/Collector Attempt/physical request ID counted once; all registered statuses included",
        "manifest_registration_count": sum(sum(reg["reference_kind"] == "registered_attempt" for reg in record["registrations"]) for record in records),
        "attempt_output_task_count": len(records), "physical_request_identity_count": len(rows),
        "recovery_status_counts": dict(coverage), "all_manifest_attempts_complete": complete,
        "exact_all_manifest_request_count": len(rows) if complete else None,
        "observed_agent_usage": observed,
        "unresolved": [{k: record[k] for k in ("user_id", "harness", "task", "output", "recovery_status", "remaining_reason")}
                       for record in records if not record["usage"]["capture_complete"]],
        "by_harness": {}, "new_agent_requests": 0, "new_simulator_requests": 0, "new_judge_requests": 0,
    }
    for harness in sorted({record["harness"] for record in records}):
        scoped = [record for record in records if record["harness"] == harness]
        physical = [row for row in rows if _harness(row.get("harness_id")) == harness]
        is_complete = all(record["usage"]["capture_complete"] for record in scoped)
        summary["by_harness"][harness] = {
            "attempt_output_task_count": len(scoped),
            "recovery_status_counts": dict(Counter(record["recovery_status"] for record in scoped)),
            "known_http_attempts": len(physical),
            "exact_http_attempts": len(physical) if is_complete else None,
        }
    for name in ("evaluation", "manifest"):
        (archive_root / name).mkdir(parents=True, exist_ok=True)
    (archive_root / "evaluation/manifest-attempts.jsonl").write_text("".join(_json(record) + "\n" for record in records))
    # Normalized numeric/provider fields and exact source pointers only. No raw
    # request bodies, model content, headers or credentials are copied.
    allowed = (*IDENTITY, "model_request_id", "role", "provider_response_id", "native_session_id",
               "native_turn_id", "native_step_id", "request_kind", "request_status", "http_status",
               "request_capture_complete", "usage_status", "missing_reason", *FIELDS,
               "standardized_tokens", "field_status", "request_sha256", "response_sha256",
               "evidence", "audit_source")
    (archive_root / "evaluation/request-index.jsonl").write_text("".join(
        _json({key: row.get(key) for key in allowed}) + "\n" for row in rows))
    (archive_root / "manifest/attempt-audit-summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, nargs="+", action="extend", required=True)
    parser.add_argument("--archive-root", type=Path, required=True)
    parser.add_argument("--historical-requests", type=Path)
    parser.add_argument("--historical-manifest", type=Path)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()
    summary = audit(args.manifest, args.archive_root, historical_requests=args.historical_requests,
                    historical_manifest=args.historical_manifest, workers=args.workers)
    print(_json({key: summary[key] for key in ("manifest_registration_count", "attempt_output_task_count",
                                              "physical_request_identity_count", "recovery_status_counts")}))


if __name__ == "__main__":
    main()
