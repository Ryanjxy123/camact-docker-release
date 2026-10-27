"""Classify execution facts before serializing a terminal Episode."""
from __future__ import annotations

import re

BUDGET_REASONS = {"agent_turn_limit_exceeded", "simulator_round_limit_exceeded", "max_model_requests",
                  "error_max_turns", "max_turns", "max_agent_turns", "native_output_token_limit",
                  # dsh's native event protocol spells the model output cap
                  # `max-tokens` (its Anthropic adapter uses `max_tokens`).
                  # Keep these wire values as aliases so the public terminal
                  # reason remains the harness-level canonical value above.
                  "max-tokens", "max_tokens"}
BUDGET_REASON_ALIASES = {"max-tokens": "native_output_token_limit",
                         "max_tokens": "native_output_token_limit"}


def canonical_budget_reason(value):
    """Return the stable terminal reason for a native budget signal.

    Native CLIs expose protocol-specific spellings.  They are only treated as
    a budget after an official event/terminal field explicitly reports them;
    this helper never infers a budget from an exit code or a partial response.
    """
    if not isinstance(value, str):
        return None
    if value in BUDGET_REASON_ALIASES:
        return BUDGET_REASON_ALIASES[value]
    return value if value in BUDGET_REASONS else None


def _forwarded(record):
    """Use the relay boundary flag, with a narrow legacy wire fallback."""
    if "upstream_dispatched" in record:
        return record["upstream_dispatched"] is True
    if (record.get("transport_phase") == "local"
            or record.get("failure_type") in {"agent_budget_limit", "simulator_stop"}):
        return False
    # Older captures predate upstream_dispatched. A local limit response must
    # never become an upstream attempt merely because it resembles HTTP.
    return bool(record.get("upstream_request_sha256") or record.get("http_status"))


def _auxiliary(record):
    route = str(record.get("route", ""))
    return ("count_tokens" in route or "countTokens" in route
            or str(record.get("step_exemption", "")).endswith("_title_generation"))


def _request_failed(record):
    status = record.get("http_status")
    return (record.get("status") in {"error", "http_error"}
            or isinstance(status, int) and status >= 400)


def last_provider_attempt_failed(records):
    """Inspect the last actual forwarded attempt, excluding local limits."""
    for record in reversed(records or []):
        if not isinstance(record, dict) or _auxiliary(record) or not _forwarded(record):
            continue
        return _request_failed(record)
    return False


def local_budget_terminal(capture, *, state=None, stop=None, runtime_reason=None,
                          event_reason=None, signal=None, terminal_event=None,
                          controlled_stop=False):
    """Identify a native error caused by the relay's own budget response.

    The relay may have made recoverable Files probes immediately before the
    local limit. Require the final request, matching Runtime/relay reasons and
    counters; an unrelated native failure still takes precedence.
    """
    records = (capture or {}).get("requests") or []
    relevant = [record for record in records if isinstance(record, dict) and not _auxiliary(record)]
    if not relevant:
        return None
    local = relevant[-1]
    if (local.get("failure_type") != "agent_budget_limit" or _forwarded(local)
            or local.get("transport_phase") not in {None, "local"}):
        return None
    message = str(local.get("error", ""))
    reason = next((value for value in ("agent_turn_limit_exceeded", "simulator_round_limit_exceeded")
                   if re.search(r"\b" + value + r"\b", message)), None)
    if (not reason or canonical_budget_reason(stop) != reason
            or canonical_budget_reason(runtime_reason) != reason):
        return None
    state = state or {}
    count_key, limit_key = (("agent_turns", "max_agent_turns") if reason == "agent_turn_limit_exceeded"
                            else ("simulator_rounds", "max_simulator_rounds"))
    count, limit = state.get(count_key), state.get(limit_key)
    if type(limit) is not int or limit <= 0 or type(count) is not int or count != limit:
        return None
    if reason == "agent_turn_limit_exceeded":
        completed = [record for record in relevant if record.get("step_counted") is True
                     and record.get("generation_completed") is True and _forwarded(record)
                     and not _request_failed(record)]
        if len(completed) != limit or local.get("counts_agent_step") is not True:
            return None
    if signal == "failed":
        if not controlled_stop:
            return None
        if _explicit_cancellation(terminal_event):
            return reason
        event = terminal_event or {}
        detail = event.get("error")
        text = event.get("message") if event.get("type") == "error" else None
        if isinstance(detail, dict):
            text = detail.get("message", text)
            if detail.get("type") == "agent_budget_limit" and reason in str(text):
                return reason
        # Codex reports the local synthetic HTTP429 as this official event.
        # The verified local request/counters above establish its cause.
        if not isinstance(text, str) or not re.fullmatch(
                r"exceeded retry limit, last status: 429 Too Many Requests", text.strip()):
            return None
    return reason


def terminal_provider_failure(records):
    """Check the latest provider generation; older recovered errors are history."""
    for record in reversed(records or []):
        if not isinstance(record, dict) or _auxiliary(record) or not _forwarded(record):
            continue
        route = str(record.get("route", ""))
        if record.get("component") == "file_api" or route.startswith("/v1/files"):
            if not _request_failed(record) or record.get("native_recovery_allowed"):
                continue
        return _request_failed(record)
    return False


def terminal_signal(events):
    """Read official event envelopes; never infer success from model prose."""
    return _terminal_signal(events)[:2]


def _terminal_signal(events):
    signal = None
    reason = None
    terminal_event = None
    assistant_output_limit = False
    for event in events or []:
        kind = event.get("type")
        if kind == "assistant":
            # Claude emits a typed synthetic assistant error followed by a
            # result with subtype=success, is_error=true, and process exit 1.
            # Only the native error code establishes the output-budget fact.
            assistant_output_limit = event.get("error") == "max_output_tokens"
            if assistant_output_limit:
                signal, reason, terminal_event = "agent_failure", "native_output_token_limit", event
        if kind in {"turn.failed", "error"}:
            assistant_output_limit = False
            detail = event.get("error")
            if isinstance(detail, dict) and detail.get("type") == "output-limit":
                signal, reason, terminal_event = "agent_failure", "native_output_token_limit", event
            else:
                signal, reason, terminal_event = "failed", None, event
        elif kind == "turn.completed":
            assistant_output_limit = False
            signal, reason, terminal_event = "finished", None, event
        elif kind == "result":
            subtype = event.get("subtype")
            budget_reason = canonical_budget_reason(subtype)
            if budget_reason:
                signal, reason, terminal_event = "agent_failure", budget_reason, event
            elif (assistant_output_limit and subtype == "success" and event.get("is_error") is True
                    and event.get("api_error_status") is None):
                signal, reason, terminal_event = "agent_failure", "native_output_token_limit", event
            elif event.get("is_error") or event.get("status") == "error":
                signal, reason, terminal_event = "failed", None, event
            elif subtype == "success" or event.get("status") == "success":
                signal, reason, terminal_event = "finished", None, event
        elif kind == "status" and event.get("phase") == "turn_end":
            assistant_output_limit = False
            value = event.get("reason", {})
            value = value.get("kind") if isinstance(value, dict) else value
            if value == "completed":
                signal, reason, terminal_event = "finished", None, event
            else:
                budget_reason = canonical_budget_reason(value)
                if budget_reason:
                    signal, reason, terminal_event = "agent_failure", budget_reason, event
                elif value in {"error", "aborted", "failed"}:
                    signal, reason, terminal_event = "failed", None, event
        elif kind == "step_finish" and event.get("part", {}).get("reason") == "stop":
            signal, reason, terminal_event = "finished", None, event
        elif "payloads" in event and isinstance(event.get("meta"), dict):
            # OpenClaw's top-level successful official local result.
            signal, reason, terminal_event = ("failed" if event.get("error") else "finished"), None, event
    return signal, reason, terminal_event


def _explicit_cancellation(event):
    """Recognize a native cancellation field, never infer it from a host kill."""
    if not isinstance(event, dict):
        return False
    if event.get("type") == "status" and event.get("phase") == "turn_end":
        reason = event.get("reason", {})
        reason = reason.get("kind") if isinstance(reason, dict) else reason
        return reason == "aborted"
    if event.get("type") in {"error", "turn.failed"}:
        detail = event.get("error")
        return isinstance(detail, dict) and detail.get("type") in {"aborted", "cancelled", "canceled", "interrupted"}
    return False


def classify_native(session, *, requested, error=None, capture=None, events=None, native_harness=None):
    state = session.environment.state["session"]
    capture = capture or {}
    process = capture.get("native_process", {})
    stop = capture.get("stop_reason")
    signal, event_reason, terminal_event = _terminal_signal(events)
    cancellation = _explicit_cancellation(terminal_event)
    opencode_reason = None
    if native_harness == "opencode":
        from camact_multi.opencode_runtime import terminal_signal as opencode_terminal_signal
        projection = capture.get("opencode_terminal")
        signal, opencode_reason = opencode_terminal_signal(projection)
        if ((isinstance(projection, dict) and projection.get("stdout_errors")) or
                any(e.get("type") in {"error", "turn.failed", "session.execution.failed",
                                     "session.execution.interrupted"} for e in events or [])):
            signal, opencode_reason = "failed", "opencode_native_execution_error"
        event_reason = opencode_reason if signal == "agent_failure" else None
        cancellation = opencode_reason == "opencode_execution_interrupted"
    runtime_reason = state.get("termination_reason") or state.get("failure_type")
    # True infrastructure faults take precedence over an incomplete/fabricated
    # budget snapshot. A later valid Episode check is still mandatory.
    if session.infrastructure_error:
        return "infrastructure_failure", session.infrastructure_error
    if process.get("timed_out"):
        return "infrastructure_failure", "task_timeout"
    # New captures distinguish an actual host signal from a condition merely
    # observed after the CLI exited. Old artifacts only had simulator_stop.
    controlled_stop = (process.get("controlled_stop") if "controlled_stop" in process
                       else process.get("simulator_stop"))
    if (isinstance(process.get("returncode"), int) and process["returncode"] < 0 and
            not (controlled_stop and
                 (stop == "simulator_stop" or canonical_budget_reason(stop)))):
        return "infrastructure_failure", error or f"Official process interrupted by signal {-process['returncode']}"
    if (capture.get("native_session_capture_errors") or
            capture.get("native_session_capture", {}).get("errors")):
        return "infrastructure_failure", "native_session_capture_error"
    if stop in {"upstream_error", "provider_auth_error", "provider_configuration_error",
                "model_policy_violation", "harness_transport_error", "task_timeout"}:
        return "infrastructure_failure", stop
    if stop == "agent_request_error":
        # The official SDK/CLI constructs the provider request. A provider 400
        # is not proof of a malformed Task business action chosen by the Agent.
        return "infrastructure_failure", "native_provider_request_error"
    local_budget = local_budget_terminal(capture, state=state, stop=stop, runtime_reason=runtime_reason,
                                         event_reason=event_reason, signal=signal,
                                         terminal_event=terminal_event, controlled_stop=controlled_stop)
    if local_budget and not terminal_provider_failure(capture.get("requests")):
        state.update(status="agent_failure", termination_reason=local_budget,
                     failure_type=local_budget, strict_success=False)
        return "agent_failure", local_budget
    if last_provider_attempt_failed(capture.get("requests")):
        last = next((r for r in reversed(capture["requests"])
                     if isinstance(r, dict) and _forwarded(r) and not _auxiliary(r)), {})
        return "infrastructure_failure", last.get("failure_type") or "unrecovered_provider_attempt"
    if (signal == "failed" and not (cancellation and controlled_stop and
            (stop == "simulator_stop" or canonical_budget_reason(stop)))):
        # The latest authoritative event supersedes an earlier budget/STOP
        # snapshot. Only an explicit cancellation can be explained by a
        # confirmed host stop; an independent native error remains a fault.
        return "infrastructure_failure", opencode_reason or error or "Official execution reported failure"
    if (native_harness == "opencode" and signal == "failed" and
            runtime_reason not in BUDGET_REASONS and stop not in BUDGET_REASONS):
        return "infrastructure_failure", opencode_reason
    if (native_harness == "opencode" and stop == "simulator_stop" and
            process.get("returncode") not in {None, 0} and not process.get("simulator_stop")):
        return "infrastructure_failure", error or "OpenCode exited before controlled Simulator STOP"
    if stop == "simulator_stop" and last_provider_attempt_failed(capture.get("requests")):
        return "infrastructure_failure", "Unrecovered provider failure at Simulator termination"
    if (stop == "simulator_stop" and getattr(session.environment, "simulator_stopped", False)
            and state.get("status") != "agent_failure" and not last_provider_attempt_failed(capture.get("requests"))):
        return "finished", None
    # A native max-tokens event is an Agent output-budget terminal.  It is
    # deliberately evaluated after provider/transport evidence above, so a
    # real upstream failure can never be hidden by a coincidentally truncated
    # generation.
    budget = (canonical_budget_reason(runtime_reason) or
              canonical_budget_reason(stop) or event_reason)
    if stop == "provider_request_failed" or (budget == "max_model_requests" and
                                            last_provider_attempt_failed(capture.get("requests"))):
        return "infrastructure_failure", "Provider attempts exhausted without recovery"
    if budget:
        state.update(status="agent_failure", termination_reason=budget, failure_type=budget, strict_success=False)
        return "agent_failure", budget
    # OpenCode 2.0.32 can exit 1 after its durable execution has succeeded.
    # Only its invocation-scoped, fully checked database projection can
    # establish that completion. All provider, native, capture, timeout and
    # host-signal failures above still take precedence. Other exit codes and
    # CLIs keep the ordinary process-failure rule; stdout prose is insufficient.
    opencode_completed_exit = (native_harness == "opencode" and signal == "finished"
                               and type(process.get("returncode")) is int
                               and process["returncode"] == 1)
    if process.get("returncode") not in {None, 0} and not opencode_completed_exit:
        return "infrastructure_failure", error or f"Official process exited {process['returncode']}"
    if state.get("status") == "agent_failure":
        return "agent_failure", runtime_reason or error
    if signal == "finished" and stop not in {"provider_request_failed", "model_policy_violation"}:
        # Earlier HTTP errors or a process cleanup exit do not invalidate a
        # subsequently completed official turn and a complete service snapshot.
        return "finished", None
    if requested in {"infrastructure_failure", "harness_failure"} or error or signal == "failed":
        return "infrastructure_failure", error or stop or "Official execution did not reach a valid terminal event"
    if native_harness == "opencode" and opencode_reason:
        return "infrastructure_failure", "incomplete_native_stream: " + opencode_reason
    return "infrastructure_failure", "incomplete_native_stream: no official terminal event"
