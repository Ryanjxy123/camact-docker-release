"""One task-attempt ledger, isolated by ContextVar and explicit transport handles."""
from __future__ import annotations
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import json
import hashlib
import os
from pathlib import Path
import threading
import uuid
import warnings

from .adapters import FIELDS, extract
from .accounting import totals
from .normalization import normalize_request

_ACTIVE = ContextVar("camact_agent_token_collector", default=None)


def current():
    return _ACTIVE.get()


def enabled(config=None, override=None):
    if override is not None:
        return bool(override)
    value = (config or {}).get("token_tracking", {}).get("enabled", False)
    if not isinstance(value, bool):
        raise ValueError("token_tracking.enabled must be a JSON boolean")
    return value


def now():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


class Collector:
    def __init__(self, directory, *, run_id, user_id, task_id, harness_id, attempt_id=None,
                 provider=None, model_id=None, coverage="exclusive_agent_http_boundary", lazy=False, secrets=()):
        self.directory = Path(directory)
        self.identity = dict(run_id=str(run_id), user_id=str(user_id), task_id=str(task_id),
                             harness_id=harness_id, attempt_id=attempt_id or uuid.uuid4().hex,
                             provider=provider, model_id=model_id)
        self.identity["started_at"] = now()
        self.records = {}
        self.errors = []
        self.lock = threading.RLock()
        self.context = {"session_id": None, "agent_turn_id": None, "parent_agent_id": None,
                        "sub_agent_id": None}
        self.coverage = coverage
        self.secrets = tuple(str(s) for s in secrets if s)
        self.reconciliation = []
        self.closed = False
        self.task_status = "running"
        self.initialized = False
        if not lazy:
            self.safe(self._initialize)

    def safe(self, function, *args, **kwargs):
        try:
            return function(*args, **kwargs)
        except Exception as exc:
            # No exception text: provider/parser/IO errors may contain secrets.
            code = "collector_error:" + type(exc).__name__
            if code not in self.errors:
                self.errors.append(code)
                try:
                    warnings.warn(code + "; Agent execution continues, usage is not comparable", RuntimeWarning)
                except Exception:
                    pass  # A warnings-as-errors policy must not stop the Agent.
            try:
                write_json(self.directory / "collector_errors.json", {"errors": self.errors, "comparable": False})
            except Exception:
                pass
            return None

    def _initialize(self):
        if self.initialized:
            return
        self.directory.mkdir(parents=True, exist_ok=False)
        self.initialized = True
        write_json(self.directory / "identity.json", {**self.identity, "coverage": self.coverage})
        self._report()

    def update_context(self, **fields):
        with self.lock:
            self.context.update(fields)

    def reconcile(self, expected, *, source):
        """Independent runner/transport counter; mismatches never affect grades."""
        with self.lock:
            actual = len(self.records)
            self.reconciliation.append({"source": source, "expected_model_requests": expected,
                                        "recorded_model_requests": actual, "matched": expected == actual})
            if expected != actual:
                self.errors.append("model_request_count_mismatch")

    def bind_session(self, turn_id, session_id):
        if not session_id:
            return
        def bind():
            with self.lock:
                for row in self.records.values():
                    if row["agent_turn_id"] == turn_id and row["session_id"] is None:
                        row["session_id"] = session_id
                        self._append(row)
        self.safe(bind)

    def attach_native_events(self, events):
        """Enrich only on an exact provider response ID; never add CLI usage."""
        def attach():
            with self.lock:
                for event in events:
                    if not isinstance(event, dict):
                        continue
                    message = event.get("message", {})
                    if not isinstance(message, dict) or not message.get("id"):
                        continue
                    matches = [r for r in self.records.values() if r.get("provider_response_id") == message["id"]]
                    # Provider IDs reused across attempts are ambiguous.
                    if len(matches) != 1:
                        continue
                    row = matches[0]
                    for key, source in (("session_id", "session_id"), ("sub_agent_id", "agentId"),
                                        ("parent_tool_use_id", "parent_tool_use_id")):
                        if event.get(source) is not None:
                            row[key] = event[source]
                    self._append(row)
        self.safe(attach)

    def _clean(self, value):
        text = json.dumps(value, ensure_ascii=False)
        for secret in self.secrets:
            text = text.replace(secret, "[REDACTED]")
        return json.loads(text)

    def _append(self, row):
        self._initialize()
        with (self.directory / "request_events.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(self._clean(row), ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def observe_response_headers(self, request_id, headers, status):
        """Persist only correlation headers, including on HTTP error attempts.

        Credentials, cookies and arbitrary upstream headers are never retained.
        Header IDs are evidence, not a logical request or usage deduplication key.
        """
        if request_id is None:
            return
        allowed = {"request-id", "x-request-id", "trace-id", "x-trace-id",
                   "x-new-api-request-id", "x-oneapi-request-id", "cf-ray",
                   "traceparent", "date", "content-type", "content-encoding",
                   "retry-after"}
        def observe():
            with self.lock:
                row = self.records[request_id]
                row["response_headers"] = {str(k).lower(): str(v) for k, v in headers.items()
                                           if str(k).lower() in allowed}
                row.update(http_status=status, response_headers_observed_at=now())
                self._append(row)
        self.safe(observe)

    def begin(self, *, protocol, model_id=None, operation_id=None, **metadata):
        def record():
            with self.lock:
                ident = uuid.uuid4().hex
                row = {**self.identity, **self.context, **dict.fromkeys(FIELDS),
                       "model_request_id": ident, "operation_id": operation_id or "request:" + ident,
                       "operation_attribution": "explicit_logical_call" if operation_id else "physical_request",
                       "model_id": model_id or self.identity["model_id"], "protocol": protocol,
                       "timestamp": now(), "request_sequence": len(self.records) + 1,
                       "retry_attempt": None, "agent_operation_type": "model_request",
                       "associated_tool_calls": [], "usage_source": "provider_http_response",
                       "usage_completeness": "unknown", "request_status": "in_flight",
                       "raw_usage": {}, "issues": ["response_not_observed"], **metadata}
                if operation_id:
                    # Keep the normalized field explicit in the journal.  The
                    # normalizer still validates the attribution source; this
                    # field makes downstream recovery independent of legacy
                    # ``operation_id`` naming.
                    row["logical_model_request_id"] = str(operation_id)
                    row.setdefault("logical_identity_source", "collector_operation_id")
                self.records[ident] = row
                self._append(row)
                self._report()
                return ident
        return self.safe(record)

    def finish_request(self, request_id, payload=b"", *, status=None, encoding=None, interrupted=False):
        if request_id is None:
            return
        def finish():
            with self.lock:
                row = self.records[request_id]
                evidence = extract(payload, row["protocol"], encoding=encoding, profile=row.get("usage_profile_override"))
                row.update(evidence.pop("usage"))
                row.update(evidence)
                row["response_sha256"] = hashlib.sha256(payload).hexdigest()
                row.update(http_status=status, completed_at=now(),
                           request_status="interrupted" if interrupted else "succeeded" if status and status < 400 else "error")
                if not row["response_complete"]:
                    row["issues"].append("response_incomplete")
                if not row["response_complete"] or "malformed_stream" in row["issues"]:
                    row["comparable_tokens"] = dict.fromkeys(FIELDS)
                cap = row.get("requested_output_cap")
                if isinstance(cap, int) and row.get("output_tokens") is not None and row["output_tokens"] > cap:
                    row["diagnostics"].append("reported_output_exceeds_wire_cap")
                # Complete usage can survive a failed task or downstream socket.
                # A truncated response has only a known subtotal, not an exact total.
                row["usage_completeness"] = ("complete" if all(row["comparable_tokens"].get(k) is not None
                                                              for k in ("input_tokens", "output_tokens", "total_tokens"))
                                             else "partial" if row["raw_usage"] else "unknown")
                # Add a versioned flat view without changing legacy counters or
                # aggregation semantics.
                row["normalized_usage"] = normalize_request(row)
                self._append(row)
                self._report()
        self.safe(finish)

    def finish_task(self, status="unknown"):
        def finish():
            with self.lock:
                self.task_status, self.closed = status, True
                self._report()
        self.safe(finish)

    def _report(self):
        if not self.initialized:
            self._initialize()
            return
        requests = self._clean(list(self.records.values()))
        result_links = {}
        for row in requests:
            for tool_id in row.get("observed_tool_results", []):
                result_links.setdefault(tool_id, []).append(row["model_request_id"])
        operations = {}
        for row in requests:
            operation = operations.setdefault(row["operation_id"], {
                **self.identity, "operation_id": row["operation_id"], "agent_turn_id": row["agent_turn_id"],
                "agent_operation_type": row["agent_operation_type"], "model_request_ids": [], "rows": [],
                "associated_tool_calls": []})
            operation["model_request_ids"].append(row["model_request_id"])
            operation["rows"].append(row)
            operation["associated_tool_calls"].extend(row["associated_tool_calls"])
        operation_rows = []
        for operation in operations.values():
            rows = operation.pop("rows")
            operation.update(totals(rows))
            operation["model_request_count"] = len(rows)
            operation_rows.append(operation)
            # Execution edges reference the owning request. Zero here means the
            # tool execution itself is not a model call; no token redistribution.
            for row in rows:
                for tool in row["associated_tool_calls"]:
                    operation_rows.append({**self.identity, "operation_id": "tool:" + row["model_request_id"] + ":" + tool["tool_call_id"],
                        "agent_operation_type": "tool_call", **tool, "parent_operation_id": operation["operation_id"],
                        "origin_model_request_id": row["model_request_id"], "model_request_ids": [],
                        "execution_status": "result_observed_in_model_input" if tool["tool_call_id"] in result_links else "requested",
                        "result_consumed_by_request_ids": result_links.get(tool["tool_call_id"], []),
                        "linked_model_request_ids": [r["model_request_id"] for r in requests
                                                    if r.get("parent_tool_use_id") == tool["tool_call_id"]
                                                    and sum(t["tool_call_id"] == tool["tool_call_id"]
                                                            for owner in requests for t in owner["associated_tool_calls"]) == 1],
                        "tokens": dict.fromkeys(FIELDS, 0),
                        "usage_source": "tool_self_usage_only; linked_model_requests_counted_separately"})
        for filename, rows in (("requests.jsonl", requests), ("operations.jsonl", operation_rows)):
            target = self.directory / filename
            tmp = target.with_suffix(".tmp")
            tmp.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
            os.replace(tmp, target)
        coverage_valid = (not self.errors and not any(r["request_status"] == "in_flight" for r in requests)
                          and self.closed and self.coverage == "exclusive_agent_http_boundary"
                          and bool(self.reconciliation) and all(r["matched"] for r in self.reconciliation)
                          and self.reconciliation[-1]["recorded_model_requests"] == len(requests))
        summary = {**self.identity, **totals(requests, coverage_valid=coverage_valid),
            "task_status": self.task_status, "closed": self.closed, "coverage": self.coverage,
            "model_request_count": len(requests), "usage_record_count": sum(bool(r["raw_usage"]) for r in requests),
            "complete_request_count": sum(r["usage_completeness"] == "complete" for r in requests),
            "collector_errors": self.errors,
            "request_count_reconciliation": self.reconciliation,
            "attribution_limits": ["Native parent/sub-agent identity is unknown unless explicitly observed",
                                   "A model request owns its generated tools; tool execution tokens are not redistributed"],
            "operations": len(operations)}
        write_json(self.directory / "task_summary.json", summary)


@contextmanager
def scope(collector):
    token = _ACTIVE.set(collector)
    try:
        yield collector
    finally:
        _ACTIVE.reset(token)


def create(directory, **identity):
    """Construction failure must not prevent the tested Agent from starting."""
    try:
        return Collector(directory, **identity)
    except Exception as exc:
        try:
            warnings.warn("token collector unavailable: " + type(exc).__name__, RuntimeWarning)
        except Exception:
            pass
        return None
