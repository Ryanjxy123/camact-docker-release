"""Bind an unscored, closed Agent capture without running an evaluator.

An interrupted scoring phase may leave no task row in the accounting report.
The immutable executor spec and the closed Collector journal can still prove
which Task and Attempt own the normalized physical requests.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .unified_report import IDENTITY, aggregate


def _read(path, evidence):
    content = path.read_bytes()
    evidence.append({"path": str(path), "sha256": hashlib.sha256(content).hexdigest()})
    return content


def bind_unscored_agent_usage(output, slot):
    """Return exact same-Attempt usage, or None when its proof is incomplete.

    Never use a Harness-wide all_attempts total. All five Collector identity
    fields, the external Task ID, the request ID set and capture reconciliation
    must agree. A missing or empty capture cannot establish zero requests here.
    """
    output, evidence = Path(output).resolve(), []
    try:
        spec_path = output.parent / "spec.json"
        spec = json.loads(_read(spec_path, evidence))
        if spec.get("mode") != "agent" or any(
                spec.get(key) != slot[key] for key in ("user_id", "harness", "task", "task_id")):
            return None
        requests_path = output / "token_usage/accounting_v3/requests.jsonl"
        rows = [json.loads(line) for line in _read(requests_path, evidence).splitlines() if line.strip()]
        physical = [row for row in rows if row.get("role") == "Agent"]
        identities = {tuple(row.get(key) for key in IDENTITY) for row in physical}
        if len(identities) != 1:
            return None
        identity = dict(zip(IDENTITY, next(iter(identities))))
        harnesses = {slot["harness"]}
        if slot["harness"] == "baseline":
            harnesses.add("canonical-baseline")
        if (identity["run_id"] != str(output) or identity["harness_id"] not in harnesses
                or identity["user_id"] != slot["user_id"] or identity["task_id"] != slot["task"]):
            return None
        attempt_id = identity["attempt_id"]
        if not isinstance(attempt_id, str) or not attempt_id or Path(attempt_id).name != attempt_id:
            return None
        ids = [row.get("model_request_id") for row in physical]
        if (not ids or not all(isinstance(value, str) and value for value in ids)
                or len(set(ids)) != len(ids)
                or not all(row.get("request_capture_complete") is True for row in physical)
                or any(row.get("request_status") in {None, "in_flight"} for row in physical)):
            return None

        ledger = output / "token_usage/ledgers" / attempt_id
        recorded_identity = json.loads(_read(ledger / "identity.json", evidence))
        summary = json.loads(_read(ledger / "task_summary.json", evidence))
        if any(document.get(key) != value for document in (recorded_identity, summary)
               for key, value in identity.items()):
            return None
        checks = summary.get("request_count_reconciliation")
        if (summary.get("closed") is not True or summary.get("collector_errors") != []
                or summary.get("coverage") != "exclusive_agent_http_boundary"
                or recorded_identity.get("coverage") != "exclusive_agent_http_boundary"
                or not isinstance(checks, list) or not checks
                or not all(check.get("matched") is True
                           and type(check.get("expected_model_requests")) is int
                           and check["expected_model_requests"] >= 0
                           and check["expected_model_requests"] == check.get("recorded_model_requests")
                           for check in checks)
                or checks[-1]["recorded_model_requests"] != len(ids)
                or summary.get("model_request_count") != len(ids)):
            return None
        journal = ledger / "request_events.jsonl"
        if not journal.is_file():
            journal = ledger / "requests.jsonl"
        latest = {}
        for line in _read(journal, evidence).splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            request_id = row.get("model_request_id")
            if (not isinstance(request_id, str) or not request_id
                    or any(row.get(key) != value for key, value in identity.items())):
                return None
            latest[request_id] = row
        if set(latest) != set(ids) or any(
                row.get("request_status") in {None, "in_flight"} for row in latest.values()):
            return None
        for row in physical:
            original = latest[row["model_request_id"]]
            if any(row.get(key) != original.get(key) for key in ("request_sha256", "response_sha256")):
                return None
        usage = aggregate(physical)
        usage["usage_binding"] = {
            "kind": "frozen_unscored_agent_ledger", "identity": identity,
            "external_task_id": slot["task_id"], "evidence": evidence,
            "collector_session_ids": sorted({row.get("session_id") for row in latest.values()
                                             if isinstance(row.get("session_id"), str) and row["session_id"]}),
            "requests_path": str(requests_path),
            "requests_sha256": next(item["sha256"] for item in evidence
                                    if item["path"] == str(requests_path)),
        }
        return usage
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return None
