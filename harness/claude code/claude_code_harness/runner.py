"""Run Claude Code tasks and adapt their declarations to the standard artifact."""
from __future__ import annotations

import copy
import json
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .core import (
    MUTATING_TOOLS,
    READ_ONLY_TOOLS,
    ClaudeSettings,
    TaskHandle,
    build_prompt,
    build_task_workspace,
    benchmark_provenance,
    claude_command,
    extract_result_from_workspace,
    harness_commit,
    inspected_images,
    parse_stream,
    read_json,
    result_schema,
    redact_text,
    utc_now,
    write_json,
)
from .adapter import ClaudeCodeAdapter
from .provider_bridge import OpenAIProtocolBridge, requires_protocol_bridge
from evaluation.camact_eval.measurement import canonical_measurement, normalize_model_calls, normalize_usage


def _normalise_images(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        for match in re.findall(r"\b[0-9]+\.(?:jpg|jpeg|png)\b", item, flags=re.I):
            if match not in result:
                result.append(match)
    return result


def _canonical_image_lookup(handle: TaskHandle) -> dict[str, str]:
    """Build a public, task-local filename map without consulting GT."""
    image_root = handle.task_dir.parents[2] / "users" / handle.user_id / "base_memory" / "images"
    if not image_root.is_dir():
        return {}
    return {
        path.name.casefold(): path.name
        for path in image_root.iterdir()
        if path.is_file() and path.suffix.casefold() in {".jpg", ".jpeg", ".png"}
    }


def _canonical_image_id(value: Any, lookup: dict[str, str]) -> str | None:
    if not isinstance(value, str):
        return None
    matches = re.findall(r"\b[0-9]+\.(?:jpg|jpeg|png)\b", value, flags=re.I)
    if len(matches) != 1:
        return None
    return lookup.get(matches[0].casefold(), matches[0])


def _canonical_images(value: Any, lookup: dict[str, str]) -> list[str]:
    result: list[str] = []
    for image_id in _normalise_images(value):
        canonical = lookup.get(image_id.casefold(), image_id)
        if canonical not in result:
            result.append(canonical)
    return result


def _canonical_action_arguments(arguments: dict[str, Any], lookup: dict[str, str]) -> dict[str, Any]:
    """Normalize only declared image-bearing action fields."""
    result = copy.deepcopy(arguments)
    for field in ("attachments", "images", "image_ids"):
        if field in result:
            result[field] = _canonical_images(result[field], lookup)
    for field in ("image", "image_id"):
        if field in result:
            canonical = _canonical_image_id(result[field], lookup)
            if canonical:
                result[field] = canonical
    return result


def _usage(metadata: dict[str, Any]) -> dict[str, Any]:
    raw = metadata.get("usage") if isinstance(metadata.get("usage"), dict) else {}
    normalized = normalize_usage(raw, source="session_aggregate")
    result = {
        key: normalized[key]
        for key in ("input_tokens", "output_tokens", "cached_input_tokens", "total_tokens")
        if isinstance(normalized.get(key), int)
    }
    result.update({
        "usage_available": bool(normalized.get("usage_available")),
        "usage_source": normalized.get("usage_source"),
    })
    if metadata.get("total_cost_usd") is not None:
        result["cost_usd"] = metadata["total_cost_usd"]
    return result


def _model_calls(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return one record per Claude-visible assistant message.

    With ``--include-partial-messages`` Claude emits repeated top-level
    assistant snapshots for the same message.  Message IDs (and, when
    available, stream ``message_start`` events) are the stable boundary; event
    UUIDs are snapshot IDs and must not be counted as model calls.
    """
    calls: list[dict[str, Any]] = []
    seen: set[str] = set()
    positions: dict[str, int] = {}
    terminal_usage: dict[str, dict[str, Any]] = {}

    # With Claude's streaming protocol the initial assistant snapshot reports
    # ``output_tokens: 0``.  The terminal message_delta for the same message
    # carries the actual generated output count.  Collect those deltas first
    # so model-call records can retain real per-call usage without estimating.
    active_message_id: str | None = None
    for event in events:
        if event.get("type") != "stream_event":
            continue
        stream_event = event.get("event")
        if not isinstance(stream_event, dict):
            continue
        event_type = stream_event.get("type")
        if event_type == "message_start":
            message = stream_event.get("message")
            active_message_id = str(message.get("id") or "").strip() if isinstance(message, dict) else None
        elif event_type == "message_delta" and active_message_id:
            usage = stream_event.get("usage")
            if isinstance(usage, dict):
                terminal_usage[active_message_id] = {
                    **terminal_usage.get(active_message_id, {}),
                    **copy.deepcopy(usage),
                }

    def append(message: dict[str, Any], fallback_id: str | None = None) -> None:
        message_id = str(message.get("id") or fallback_id or "").strip()
        if not message_id:
            return
        if message_id in seen:
            existing = calls[positions[message_id]]
            if not existing.get("model") and message.get("model"):
                existing["model"] = message["model"]
            if isinstance(message.get("usage"), dict):
                existing["usage"] = {
                    **existing.get("usage", {}),
                    **copy.deepcopy(message["usage"]),
                }
            return
        seen.add(message_id)
        item: dict[str, Any] = {
            "call_id": message_id,
            "step": len(calls) + 1,
            "model": message.get("model"),
            "status": "succeeded",
            "source": "claude_assistant_message",
        }
        if isinstance(message.get("usage"), dict):
            item["usage"] = copy.deepcopy(message["usage"])
        positions[message_id] = len(calls)
        calls.append(item)

    for event in events:
        if event.get("type") != "stream_event":
            continue
        stream_event = event.get("event")
        if not isinstance(stream_event, dict) or stream_event.get("type") != "message_start":
            continue
        message = stream_event.get("message")
        if isinstance(message, dict):
            append(message)

    for event in events:
        if event.get("type") != "assistant":
            continue
        message = event.get("message", event)
        if not isinstance(message, dict):
            continue
        if not message.get("model") and event.get("model"):
            message = {**message, "model": event.get("model")}
        append(message, str(event.get("uuid") or ""))

    for message_id, usage in terminal_usage.items():
        position = positions.get(message_id)
        if position is None:
            continue
        calls[position]["usage"] = {
            **calls[position].get("usage", {}),
            **usage,
        }
    return calls


def _bridge_delta(before: dict[str, Any] | None, after: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(after, dict):
        return {"enabled": False, "request_count": 0, "success_count": 0}
    prior = before if isinstance(before, dict) else {}
    result = copy.deepcopy(after)
    result["request_count"] = max(0, int(after.get("request_count", 0) or 0) - int(prior.get("request_count", 0) or 0))
    result["success_count"] = max(0, int(after.get("success_count", 0) or 0) - int(prior.get("success_count", 0) or 0))
    for key in ("attempt_events", "stream_diagnostics"):
        current = after.get(key, [])
        previous = prior.get(key, [])
        if isinstance(current, list):
            result[key] = copy.deepcopy(current[len(previous):] if isinstance(previous, list) else current)
    return result


def _redacted_command(command: list[str], secret: str) -> list[str]:
    return [redact_text(item, [secret]) for item in command]


def _redact_value(value: Any, secret: str) -> Any:
    if isinstance(value, str):
        return redact_text(value, [secret])
    if isinstance(value, list):
        return [_redact_value(item, secret) for item in value]
    if isinstance(value, dict):
        return {str(key): _redact_value(item, secret) for key, item in value.items()}
    return value


def _archive_retry_workspace(task_root: Path, workspace: Path, attempt: int) -> None:
    """Archive a failed attempt before rebuilding the canonical workspace."""
    if not workspace.exists():
        return
    attempt_root = task_root / "attempts" / f"attempt_{attempt:02d}"
    attempt_root.mkdir(parents=True, exist_ok=True)
    destination = attempt_root / "workspace"
    if destination.exists():
        raise FileExistsError(f"retry workspace archive already exists: {destination}")
    workspace.replace(destination)


def _write_invocation_logs(
    task_root: Path,
    attempt: int,
    invocation: int,
    stdout: str,
    stderr: str,
    secret: str,
) -> tuple[str, str]:
    root = task_root / "attempts" / f"attempt_{attempt:02d}"
    root.mkdir(parents=True, exist_ok=True)
    stdout_path = root / f"invocation_{invocation:02d}.stdout.log"
    stderr_path = root / f"invocation_{invocation:02d}.stderr.log"
    stdout_path.write_text(redact_text(stdout, [secret]), encoding="utf-8")
    stderr_path.write_text(redact_text(stderr, [secret]), encoding="utf-8")
    return str(stdout_path), str(stderr_path)


def _terminate_process(process: subprocess.Popen[str]) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, check=False)
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        process.kill()


def _communicate(process: subprocess.Popen[str], timeout: float) -> tuple[str, str, bool]:
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return str(stdout or ""), str(stderr or ""), False
    except subprocess.TimeoutExpired as exc:
        _terminate_process(process)

        def as_text(value: Any) -> str:
            if isinstance(value, bytes):
                return value.decode(errors="replace")
            return str(value or "")

        try:
            tail_out, tail_err = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            tail_out, tail_err = "", ""
        return as_text(exc.stdout) + as_text(tail_out), as_text(exc.stderr) + as_text(tail_err), True


def _invoke_claude(
    *,
    command: list[str],
    workspace: Path,
    env: dict[str, str],
    timeout: float,
    bridge: OpenAIProtocolBridge | None,
) -> dict[str, Any]:
    bridge_before = bridge.snapshot() if bridge else None
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        cwd=str(workspace),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=(os.name != "nt"),
    )
    stdout, stderr, timed_out = _communicate(process, timeout)
    structured, events, metadata = parse_stream(stdout)
    return {
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": timed_out,
        "returncode": -9 if timed_out else int(process.returncode if process.returncode is not None else -127),
        "structured": structured,
        "events": events,
        "metadata": metadata,
        "duration_seconds": round(time.monotonic() - started, 3),
        "protocol_bridge": _bridge_delta(bridge_before, bridge.snapshot() if bridge else None),
    }


def _apply_actions(
    handle: TaskHandle,
    actions: list[Any],
    evidence: list[str],
    session_dir: Path,
    observed_images: list[str],
    environment: Any | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], list[str]]:
    """Materialize declared actions only after Claude has exited.

    The runtime is created outside the exposed workspace.  Read-only Claude
    file observations are represented as audit-only image_view records so the
    frozen evaluator can apply its existing evidence policy.
    """
    from benchmark.services.runtime_environment import RuntimeEnvironment

    session_dir.parent.mkdir(parents=True, exist_ok=True)
    environment = environment or RuntimeEnvironment(handle.task_dir, session_dir)
    allowed = read_json(handle.task_dir / "task_spec.json", {})
    allowed_tools = set(allowed.get("allowed_tools", [])) if isinstance(allowed, dict) else set()
    canonical_lookup = _canonical_image_lookup(handle)
    calls: list[dict[str, Any]] = []
    action_results: list[dict[str, Any]] = []
    errors: list[str] = []

    # A Read of an image is the Claude-native observation.  It is not executed
    # through CamAct's image_view runtime; this record only preserves the
    # evaluator's established observation vocabulary and its source.
    for image_id in _canonical_images(observed_images, canonical_lookup):
        # Preserve the evaluator's existing visual-observation vocabulary only
        # when this task publicly allows an image-view capability.
        if "image_view" not in allowed_tools and "inspect_image" not in allowed_tools:
            continue
        calls.append({
            "tool": "image_view" if "image_view" in allowed_tools else "inspect_image",
            "arguments": {"image_id": image_id},
            "status": "succeeded",
            "source": "claude_code_read",
        })

    for raw in actions:
        if not isinstance(raw, dict):
            errors.append("action entry is not an object")
            continue
        tool = str(raw.get("tool", "")).strip()
        arguments = raw.get("arguments", {})
        if not isinstance(arguments, dict):
            arguments = {}
        arguments = _canonical_action_arguments(arguments, canonical_lookup)
        call: dict[str, Any] = {"tool": tool, "arguments": copy.deepcopy(arguments), "status": "failed"}
        if tool not in allowed_tools:
            call["error"] = "tool is not in this task's public allowlist"
            action_results.append(call)
            calls.append(call)
            continue
        if tool in READ_ONLY_TOOLS:
            call["status"] = "external_observation"
            call["source"] = "claude_code_file_workspace"
            action_results.append(call)
            calls.append(call)
            continue
        if tool not in MUTATING_TOOLS:
            call["error"] = "unsupported action declaration"
            action_results.append(call)
            calls.append(call)
            continue
        response = environment.call_tool(tool, arguments)
        call["status"] = "succeeded" if response.get("ok") else "failed"
        if not response.get("ok"):
            call["error"] = response.get("error", "runtime rejected action")
            errors.append(f"{tool}: {call['error']}")
        action_results.append({**call, "response": copy.deepcopy(response)})
        calls.append(call)

    conversation_trace = copy.deepcopy(environment.conversation_trace)
    final_state = environment.close()
    return final_state, calls, {
        "action_results": action_results,
        "errors": errors,
        "runtime_conversation_trace": conversation_trace,
    }, _canonical_images(evidence, canonical_lookup)


def _standard_artifact(
    *,
    handle: TaskHandle,
    run_id: str,
    settings: ClaudeSettings,
    benchmark_root: Path,
    result: dict[str, Any],
    final_state: dict[str, Any],
    calls: list[dict[str, Any]],
    events: list[dict[str, Any]],
    metadata: dict[str, Any],
    workspace_manifest: dict[str, Any],
    timing: dict[str, Any],
    trajectory_class: str,
    errors: dict[str, Any],
    invocation: list[str],
    action_diagnostics: dict[str, Any],
    conversation_trace: list[Any] | None = None,
    invocation_records: list[dict[str, Any]] | None = None,
):
    from evaluation.camact_eval.schema import StandardRunArtifact

    evidence = _canonical_images(result.get("evidence", []), _canonical_image_lookup(handle))
    final_response = str(result.get("final_response", ""))
    assistant_messages = normalize_model_calls(_model_calls(events), session_usage=metadata.get("usage"))
    provenance = benchmark_provenance(benchmark_root)
    records = invocation_records or []
    provider_request_attempts = sum(
        int(item.get("protocol_bridge", {}).get("request_count", 0) or 0)
        for item in records
        if isinstance(item, dict)
    )
    provider_completed_requests = sum(
        int(item.get("protocol_bridge", {}).get("success_count", 0) or 0)
        for item in records
        if isinstance(item, dict)
    )
    artifact = StandardRunArtifact(
        user_id=handle.user_id,
        task_id=handle.task_id,
        task=f"{handle.user_id}/{handle.task_name}",
        run={
            "run_id": run_id,
            "trial": 1,
            "provider": settings.provider,
            "protocol_version": "claude-code-cli",
            "benchmark_release_id": provenance.get("benchmark_release_id") or provenance.get("release_id"),
            "benchmark_release_version": provenance.get("benchmark_release_version") or provenance.get("release_version"),
            "benchmark_manifest_sha256": provenance.get("benchmark_manifest_sha256") or provenance.get("manifest_sha256"),
        },
        method=str(result.get("_method", "claude_code")),
        model={"name": settings.model, "requested_model": settings.model, "configured_model": settings.model, "provider": settings.provider, "base_url": settings.public_dict()["base_url"], "version": settings.claude_version, "executable": settings.executable_path},
        model_policy=dict(action_diagnostics.get("model_policy", {})) if isinstance(action_diagnostics.get("model_policy", {}), dict) else {},
        final_response=final_response,
        evidence=evidence,
        tool_calls=calls,
        actions=[item for item in calls if item.get("source") not in {"claude_code_read", "claude_code_native_read"}
                 and item.get("tool_category") not in {"domain_tool", "business_read"}],
        final_state=final_state,
        simulator={
            "status": "available"
            if isinstance(final_state.get("user_simulator"), dict)
            and (final_state["user_simulator"].get("turns") or final_state["user_simulator"].get("delivered_batches"))
            else "not_recorded"
        },
        errors=errors,
        token_usage=_usage(metadata),
        model_calls=assistant_messages,
        timing=timing,
        diagnostics={
            "workspace_manifest": workspace_manifest,
            "external_file_inspections": [
                item.get("arguments", {}).get("image_id") or item.get("arguments", {}).get("file_path")
                for item in calls
                if str(item.get("source", "")).casefold() in {"claude_code_read", "claude_code_native_read"}
            ],
            "adapter": action_diagnostics,
            "conversation_trace": conversation_trace or [],
            "identity_claims": result.get("identity_claims", []),
            "invocation": _redacted_command(invocation, settings.api_key),
            "session_id": metadata.get("session_id"),
            "claude_subtype": metadata.get("subtype"),
            # Preserve provider-reported per-model aggregates so a Standard
            # Artifact can be re-normalized offline without the live trace.
            "provider_model_usage": metadata.get("modelUsage", metadata.get("model_usage", {})),
            "attempts": metadata.get("attempts", []),
            "statistics_definitions": {
                "model_calls": "one record per unique Claude-visible assistant message id",
                "provider_request_attempts": "outbound HTTP attempts, including provider retries",
                "provider_completed_requests": "outbound model responses completed successfully",
                "claude_reported_num_turns": "raw terminal invocation value; semantics may be CLI-version dependent",
            },
            "execution_statistics": {
                "infrastructure_attempts": len(metadata.get("attempts", [])),
                "claude_invocations": len(records) or 1,
                "assistant_messages": len(assistant_messages),
                "provider_request_attempts": provider_request_attempts,
                "provider_completed_requests": provider_completed_requests,
                "tool_calls": len(calls),
                "claude_reported_num_turns": metadata.get("num_turns"),
            },
            "invocations": records,
        },
        trajectory_class=trajectory_class,
    )
    artifact.measurement = canonical_measurement(
        model_calls=artifact.model_calls,
        token_usage=artifact.token_usage,
        tool_calls=artifact.tool_calls,
        actions=artifact.actions,
        evidence=artifact.evidence,
        timing=artifact.timing,
        diagnostics=artifact.diagnostics,
        final_state=artifact.final_state,
        native_events=events,
        provider_model_usage=metadata.get("modelUsage", metadata.get("model_usage")),
    )
    artifact.validate()
    return artifact


def run_task(
    handle: TaskHandle,
    *,
    benchmark_root: Path,
    run_root: Path,
    run_id: str,
    settings: ClaudeSettings,
) -> dict[str, Any]:
    task_root = run_root / "tasks" / handle.user_id / handle.task_name
    workspace = task_root / "workspace"
    trace_path = run_root / "traces" / handle.user_id / f"{handle.task_name}.json"
    stdout_path = run_root / "stdout" / handle.user_id / f"{handle.task_name}.log"
    stderr_path = run_root / "stderr" / handle.user_id / f"{handle.task_name}.log"
    submission_path = run_root / "submissions" / handle.user_id / f"{handle.task_name}.json"
    artifact_path = run_root / "artifacts" / handle.user_id / f"{handle.task_name}.json"
    session_dir = run_root / "sessions" / handle.user_id / handle.task_name
    started_at = utc_now()
    started_monotonic = time.monotonic()
    task_root.mkdir(parents=True, exist_ok=True)
    try:
        public = build_task_workspace(handle, workspace)
    except Exception as exc:
        return _failure_result(handle, run_root, started_at, started_monotonic, "infrastructure_failure", f"workspace: {type(exc).__name__}: {exc}")
    schema = result_schema(public["allowed_tools"])
    base_env = os.environ.copy()
    base_env["NO_COLOR"] = "1"
    base_env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    spec_doc = read_json(handle.task_dir / "task_spec.json", {})
    is_multi_turn = isinstance(spec_doc, dict) and spec_doc.get("interaction_type") == "simulated_multi_turn"
    use_protocol_bridge = requires_protocol_bridge(settings.model)
    attempts: list[dict[str, Any]] = []
    invocation_records: list[dict[str, Any]] = []
    all_events: list[dict[str, Any]] = []
    selected_events: list[dict[str, Any]] = []
    stdout_parts: list[str] = []
    stderr_parts: list[str] = []
    candidate: dict[str, Any] | None = None
    metadata: dict[str, Any] = {}
    stdout = ""
    stderr = ""
    returncode = -127
    command: list[str] = []
    selected_environment: Any | None = None
    selected_runtime_dir: Path | None = None
    selected_simulator_turns: list[dict[str, Any]] = []
    protocol_failure: str | None = None
    bridge_context = (
        OpenAIProtocolBridge(
            base_url=settings.base_url,
            api_key=settings.api_key,
            model=settings.model,
            timeout=settings.timeout,
            request_attempts=settings.request_attempts,
        )
        if use_protocol_bridge else None
    )
    if use_protocol_bridge and (not settings.base_url or not settings.api_key):
        return _failure_result(handle, run_root, started_at, started_monotonic, "infrastructure_failure", "OpenAI protocol bridge requires --base-url and --api-key")
    context = bridge_context or __import__("contextlib").nullcontext()
    with context as bridge:
        if bridge:
            base_env["ANTHROPIC_BASE_URL"] = bridge.local_base_url
            base_env["ANTHROPIC_API_KEY"] = "camact-local-protocol-bridge"
        else:
            if settings.api_key:
                base_env["ANTHROPIC_API_KEY"] = settings.api_key
            if settings.base_url:
                base_env["ANTHROPIC_BASE_URL"] = settings.base_url
        for model_env in (
            "ANTHROPIC_MODEL", "CLAUDE_CODE_MODEL",
            "ANTHROPIC_SMALL_FAST_MODEL", "CLAUDE_CODE_SMALL_FAST_MODEL",
            "CLAUDE_CODE_SUBAGENT_MODEL", "CLAUDE_CODE_FALLBACK_MODEL",
            "ANTHROPIC_FALLBACK_MODEL", "CLAUDE_CODE_UTILITY_MODEL",
            "ANTHROPIC_UTILITY_MODEL", "CLAUDE_CODE_PRIMARY_MODEL",
        ):
            base_env[model_env] = settings.model

        for attempt_index in range(settings.retries):
            attempt_number = attempt_index + 1
            if attempt_index:
                try:
                    _archive_retry_workspace(task_root, workspace, attempt_index)
                    public = build_task_workspace(handle, workspace)
                    schema = result_schema(public["allowed_tools"])
                except Exception as exc:
                    protocol_failure = f"retry workspace: {type(exc).__name__}: {exc}"
                    attempts.append({
                        "attempt": attempt_number,
                        "status": "workspace_failure",
                        "error": protocol_failure,
                        "invocations": [],
                    })
                    break

            attempt_env = base_env.copy()
            attempt_events: list[dict[str, Any]] = []
            attempt_invocations: list[int] = []
            attempt_status = "infrastructure_failure"
            clean_terminal = False
            current_environment: Any | None = None
            current_runtime_dir: Path | None = None
            simulator_turns: list[dict[str, Any]] = []
            conversation_session_id = str(uuid4()) if is_multi_turn else None
            if is_multi_turn:
                from benchmark.services.runtime_environment import RuntimeEnvironment

                try:
                    current_runtime_dir = run_root / "session_attempts" / handle.user_id / handle.task_name / f"attempt_{attempt_number:02d}"
                    current_environment = RuntimeEnvironment(handle.task_dir, current_runtime_dir)
                    config_dir = task_root / "claude_config" / f"attempt_{attempt_number:02d}"
                    config_dir.mkdir(parents=True, exist_ok=False)
                    attempt_env["CLAUDE_CONFIG_DIR"] = str(config_dir)
                    simulator_rules = (
                        current_environment.simulator.get("reveal_policy", {}).get("fields", [])
                        if isinstance(current_environment.simulator, dict)
                        else []
                    )
                    max_simulator_turns = len(simulator_rules) + 1
                except Exception as exc:
                    protocol_failure = f"simulator environment: {type(exc).__name__}: {exc}"
                    attempts.append({
                        "attempt": attempt_number,
                        "status": "infrastructure_failure",
                        "error": protocol_failure,
                        "invocations": [],
                    })
                    break
            else:
                max_simulator_turns = 0

            prompt = build_prompt(workspace)
            resume = False
            invocation_number = 0
            try:
                while True:
                    invocation_number += 1
                    command = claude_command(
                        settings,
                        prompt,
                        schema,
                        session_id=conversation_session_id if is_multi_turn and not resume else None,
                        resume_session_id=conversation_session_id if is_multi_turn and resume else None,
                    )
                    invocation = _invoke_claude(
                        command=command,
                        workspace=workspace,
                        env=attempt_env,
                        timeout=settings.task_timeout,
                        bridge=bridge,
                    )
                    stdout = str(invocation["stdout"])
                    stderr = str(invocation["stderr"])
                    returncode = int(invocation["returncode"])
                    invocation_metadata = invocation["metadata"]
                    invocation_events = invocation["events"]
                    metadata = invocation_metadata
                    attempt_events.extend(invocation_events)
                    all_events.extend(invocation_events)
                    stdout_parts.append(f"[attempt {attempt_number}, invocation {invocation_number}]\n{stdout}")
                    stderr_parts.append(f"[attempt {attempt_number}, invocation {invocation_number}]\n{stderr}")
                    stdout_log, stderr_log = _write_invocation_logs(
                        task_root,
                        attempt_number,
                        invocation_number,
                        stdout,
                        stderr,
                        settings.api_key,
                    )
                    record = {
                        "attempt": attempt_number,
                        "invocation": invocation_number,
                        "kind": "simulator_reply" if resume else "initial",
                        "returncode": returncode,
                        "timed_out": bool(invocation["timed_out"]),
                        "duration_seconds": invocation["duration_seconds"],
                        "event_count": len(invocation_events),
                        "metadata": _redact_value(invocation_metadata, settings.api_key),
                        "protocol_bridge": invocation["protocol_bridge"],
                        "command": _redacted_command(command, settings.api_key),
                        "stdout_path": stdout_log,
                        "stderr_path": stderr_log,
                    }
                    invocation_records.append(record)
                    attempt_invocations.append(len(invocation_records))
                    candidate = extract_result_from_workspace(
                        workspace,
                        invocation["structured"],
                        invocation_events,
                        invocation_metadata,
                    )
                    selected_events = list(attempt_events)

                    if invocation["timed_out"]:
                        candidate = None
                        attempt_status = "timeout"
                        break
                    execution_error = (
                        invocation_metadata.get("subtype") == "error_during_execution"
                        or bool(invocation_metadata.get("errors"))
                    )
                    if returncode != 0 or execution_error:
                        candidate = None
                        attempt_status = "infrastructure_failure"
                        break
                    if not isinstance(candidate, dict):
                        attempt_status = "agent_failure"
                        clean_terminal = True
                        break
                    if not isinstance(candidate.get("actions", []), list) or not isinstance(candidate.get("evidence", []), list):
                        attempt_status = "agent_failure"
                        clean_terminal = True
                        break

                    canonical_lookup = _canonical_image_lookup(handle)
                    candidate = copy.deepcopy(candidate)
                    candidate["evidence"] = _canonical_images(candidate.get("evidence", []), canonical_lookup)
                    candidate["actions"] = [
                        {
                            **raw,
                            "arguments": _canonical_action_arguments(raw.get("arguments", {}), canonical_lookup),
                        }
                        if isinstance(raw, dict) and isinstance(raw.get("arguments", {}), dict)
                        else raw
                        for raw in candidate["actions"]
                    ]

                    declared_messages = candidate.get("user_messages", [])
                    questions = [
                        str(item).strip()
                        for item in declared_messages
                        if isinstance(item, str) and str(item).strip()
                    ] if isinstance(declared_messages, list) else []
                    if not is_multi_turn or not questions:
                        attempt_status = "success"
                        clean_terminal = True
                        selected_environment = current_environment
                        selected_runtime_dir = current_runtime_dir
                        selected_simulator_turns = list(simulator_turns)
                        break
                    if len(simulator_turns) >= max_simulator_turns:
                        protocol_failure = "Claude exceeded the task simulator's finite clarification contract"
                        candidate = None
                        attempt_status = "agent_failure"
                        clean_terminal = True
                        break

                    question = questions[0]
                    response = current_environment.user_message(question)
                    simulator_turns.append({
                        "question": question,
                        "response": response.get("content"),
                        "matched": response.get("matched"),
                        "released_fields": response.get("released_fields", []),
                        "done": response.get("done", False),
                        "additional_declared_messages": questions[1:],
                    })
                    if not response.get("ok") or not str(response.get("content", "")).strip():
                        protocol_failure = str(response.get("error") or "user simulator returned an empty response")
                        candidate = None
                        attempt_status = "agent_failure"
                        clean_terminal = True
                        break

                    result_path = workspace / "output" / "result.json"
                    if result_path.exists():
                        result_path.unlink()
                    prompt = str(response["content"])
                    resume = True
            except OSError as exc:
                stderr = str(exc)
                candidate = None
                metadata = {}
                returncode = -127
                attempt_status = "infrastructure_failure"

            attempts.append({
                "attempt": attempt_number,
                "status": attempt_status,
                "returncode": returncode,
                "timeout_seconds": settings.task_timeout if attempt_status == "timeout" else None,
                "has_result": isinstance(candidate, dict),
                "invocations": attempt_invocations,
                "metadata": _redact_value(metadata, settings.api_key),
                "simulator_turns": simulator_turns,
            })
            if clean_terminal:
                if selected_environment is not current_environment and current_environment is not None:
                    current_environment.close()
                break
            if current_environment is not None:
                current_environment.close()
            if attempt_number < settings.retries:
                time.sleep(min(2.0, 0.25 * attempt_number))

        if bridge:
            metadata["protocol_bridge"] = bridge.snapshot()

    metadata["attempts"] = attempts
    events = all_events
    stdout = "\n\n".join(stdout_parts)
    stderr = "\n\n".join(stderr_parts)
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    stdout_path.write_text(redact_text(stdout, [settings.api_key]), encoding="utf-8")
    stderr_path.write_text(redact_text(stderr, [settings.api_key]), encoding="utf-8")
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    write_json(trace_path, _redact_value({
        "events": events,
        "attempts": attempts,
        "invocations": invocation_records,
        "metadata": metadata,
    }, settings.api_key))
    if isinstance(candidate, dict):
        candidate = _redact_value(candidate, settings.api_key)

    if protocol_failure:
        infrastructure_prefixes = ("retry workspace:", "simulator environment:")
        trajectory = "infrastructure_failure" if protocol_failure.startswith(infrastructure_prefixes) else "agent_failure"
        return _failure_result(
            handle,
            run_root,
            started_at,
            started_monotonic,
            trajectory,
            protocol_failure,
            extra={"status": trajectory, "attempts": attempts},
        )
    if returncode == -9 and not isinstance(candidate, dict):
        return _failure_result(handle, run_root, started_at, started_monotonic, "harness_failure", "Claude Code timed out", extra={"status": "timeout", "attempts": attempts})
    execution_error = metadata.get("subtype") == "error_during_execution" or bool(metadata.get("errors"))
    if (returncode != 0 or execution_error) and not isinstance(candidate, dict):
        message = metadata.get("result_text") or "; ".join(str(item) for item in metadata.get("errors", [])) or stderr.strip() or f"Claude exited with code {returncode}"
        return _failure_result(handle, run_root, started_at, started_monotonic, "infrastructure_failure", redact_text(message, [settings.api_key]), extra={"status": "infrastructure_failure", "attempts": attempts})
    if not isinstance(candidate, dict) or not isinstance(candidate.get("actions", []), list) or not isinstance(candidate.get("evidence", []), list):
        return _failure_result(handle, run_root, started_at, started_monotonic, "agent_failure", "Claude output did not satisfy result schema", extra={"status": "agent_failure", "attempts": attempts})

    observed = inspected_images(selected_events, workspace)
    try:
        final_state, calls, action_diagnostics, evidence = _apply_actions(
            handle,
            candidate.get("actions", []),
            _normalise_images(candidate.get("evidence", [])),
            session_dir,
            observed,
            environment=selected_environment,
        )
        if selected_runtime_dir is not None:
            session_dir.parent.mkdir(parents=True, exist_ok=True)
            if session_dir.exists():
                raise FileExistsError(f"final runtime session already exists: {session_dir}")
            shutil.move(str(selected_runtime_dir), str(session_dir))
        history_doc = read_json(handle.task_dir / "conversation" / "history.json", {})
        initial_doc = read_json(handle.task_dir / "conversation" / "initial_message.json", {})
        conversation_trace = []
        if isinstance(initial_doc, dict) and initial_doc:
            conversation_trace.append(initial_doc)
        runtime_trace = action_diagnostics.pop("runtime_conversation_trace", [])
        if isinstance(runtime_trace, list) and runtime_trace:
            conversation_trace.extend(runtime_trace)
        elif isinstance(history_doc, dict) and isinstance(history_doc.get("messages"), list):
            conversation_trace.extend(history_doc["messages"])
        if is_multi_turn:
            action_diagnostics["simulator_bridge"] = {
                "status": "completed" if selected_simulator_turns else "not_requested",
                "turns": selected_simulator_turns,
                "transport": "task-local Claude session resume",
            }
        artifact = ClaudeCodeAdapter.to_standard_artifact(
            handle=handle,
            run_id=run_id,
            settings=settings,
            benchmark_root=benchmark_root,
            result=candidate,
            final_state=final_state,
            calls=calls,
            events=events,
            metadata=metadata,
            workspace_manifest=public["workspace_manifest"],
            timing={"started_at": started_at, "ended_at": utc_now(), "duration_seconds": round(time.monotonic() - started_monotonic, 3)},
            trajectory_class="finished",
            errors={"adapter": [{"message": item} for item in action_diagnostics.get("errors", [])]} if action_diagnostics.get("errors") else {},
            invocation=command,
            action_diagnostics=action_diagnostics,
            conversation_trace=conversation_trace,
            invocation_records=invocation_records,
        )
        write_json(submission_path, candidate)
        artifact.write(artifact_path)
        result = {
            "user_id": handle.user_id,
            "task": handle.task_name,
            "task_id": handle.task_id,
            "status": "success",
            "trajectory_class": "finished",
            "artifact_path": str(artifact_path),
            "submission_path": str(submission_path),
            "session_id": metadata.get("session_id"),
            "duration_seconds": artifact.timing.get("duration_seconds"),
            "evidence_count": len(artifact.evidence),
            "action_count": len(artifact.actions),
            "errors": action_diagnostics.get("errors", []),
        }
        return result
    except Exception as exc:
        return _failure_result(handle, run_root, started_at, started_monotonic, "infrastructure_failure", f"adapter: {type(exc).__name__}: {exc}")


def _failure_result(handle: TaskHandle, run_root: Path, started_at: str, started_monotonic: float, trajectory_class: str, message: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    result = {
        "user_id": handle.user_id,
        "task": handle.task_name,
        "task_id": handle.task_id,
        "status": "timeout" if trajectory_class == "harness_failure" and "timed out" in message.casefold() else trajectory_class,
        "trajectory_class": trajectory_class,
        "error": message,
        "duration_seconds": round(time.monotonic() - started_monotonic, 3),
        **(extra or {}),
    }
    path = run_root / "task_failures" / handle.user_id / f"{handle.task_name}.json"
    write_json(path, result)
    # Preserve a valid terminal Standard Run Artifact even when Claude or the
    # adapter fails before a normal submission exists.  This keeps failure
    # accounting visible to the same evaluator and never includes GT data.
    try:
        from evaluation.camact_eval.schema import StandardRunArtifact
        artifact = StandardRunArtifact(
            user_id=handle.user_id,
            task_id=handle.task_id,
            task=f"{handle.user_id}/{handle.task_name}",
            run={"run_id": run_root.name, "trial": 1, "provider": "anthropic-compatible", "protocol_version": "claude-code-cli"},
            method="claude_code",
            model={},
            final_response="",
            evidence=[],
            tool_calls=[],
            actions=[],
            final_state={},
            simulator={"status": "not_recorded"},
            errors={"infrastructure" if trajectory_class == "infrastructure_failure" else "harness": [{"message": message}]},
            token_usage={},
            model_calls=[],
            timing={"started_at": started_at, "ended_at": utc_now(), "duration_seconds": result["duration_seconds"]},
            diagnostics={"failure": message, "source": "claude_code_harness"},
            trajectory_class=trajectory_class,
        )
        artifact_path = run_root / "artifacts" / handle.user_id / f"{handle.task_name}.json"
        artifact.write(artifact_path)
        result["artifact_path"] = str(artifact_path)
    except Exception:
        pass
    return result


def run_tasks(handles: list[TaskHandle], *, benchmark_root: Path, run_root: Path, run_id: str, settings: ClaudeSettings) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    lock = threading.Lock()
    results_path = run_root / "task_results.jsonl"
    def execute(handle: TaskHandle) -> dict[str, Any]:
        return run_task(handle, benchmark_root=benchmark_root, run_root=run_root, run_id=run_id, settings=settings)
    with ThreadPoolExecutor(max_workers=settings.parallel, thread_name_prefix="claude-code") as pool:
        futures = {pool.submit(execute, handle): handle for handle in handles}
        for future in as_completed(futures):
            handle = futures[future]
            try:
                item = future.result()
            except Exception as exc:
                item = _failure_result(handle, run_root, utc_now(), time.monotonic(), "infrastructure_failure", f"runner: {type(exc).__name__}: {exc}")
            with lock:
                results.append(item)
                results_path.parent.mkdir(parents=True, exist_ok=True)
                with results_path.open("a", encoding="utf-8") as output:
                    output.write(json.dumps(item, ensure_ascii=False) + "\n")
                write_json(run_root / "logs" / str(item.get("user_id", "unknown")) / f"{item.get('task', 'unknown')}.json", item)
            print(json.dumps({"type": "task_finished", **item}, ensure_ascii=False), flush=True)
    return sorted(results, key=lambda item: (str(item.get("user_id")), str(item.get("task"))))


def write_run_manifest(run_root: Path, benchmark_root: Path, settings: ClaudeSettings, handles: list[TaskHandle], cli_arguments: list[str] | None = None) -> None:
    provenance = benchmark_provenance(benchmark_root)
    runtime = {
        "executable": "claude.cmd" if os.name == "nt" else "claude",
        "version": settings.claude_version,
        "path": settings.executable_path,
    }
    public = {
        "schema_version": "camact.claude_code_run.v1",
        "run_id": run_root.name,
        "method": "claude_code",
        "started_at": utc_now(),
        "secret_persisted": False,
        "benchmark_provenance": provenance,
        "harness_commit": harness_commit(),
        "claude": {"model": settings.model, "provider": settings.provider, "base_url": settings.public_dict()["base_url"], "distro": settings.distro, **runtime},
        "task_count": len(handles),
        "tasks": [{"user_id": h.user_id, "task": h.task_name, "task_id": h.task_id} for h in handles],
        "cli_arguments": _redacted_command(cli_arguments or [], settings.api_key),
    }
    write_json(run_root / "run_manifest.json", public)
    config = {
        **settings.public_dict(),
        "benchmark": str(benchmark_root),
        "parallel": settings.parallel,
        "timeout": settings.timeout,
        "retries": settings.retries,
        "request_timeout": settings.timeout,
        "request_attempts": settings.request_attempts,
        "infrastructure_attempts": settings.retries,
        "task_timeout": settings.task_timeout,
        "timeout_semantics": {
            "request_timeout": "per outbound provider HTTP attempt",
            "task_timeout": "per Claude CLI invocation",
        },
        "attempt_semantics": {
            "request_attempts": "total attempts per Claude model request",
            "infrastructure_attempts": "total fresh Claude task attempts",
        },
        "task_count": len(handles),
        "cli_arguments": _redacted_command(cli_arguments or [], settings.api_key),
        "api_key": None,
        "api_key_transport": "task-private protocol bridge" if requires_protocol_bridge(settings.model) else "Claude child environment",
        "api_key_env": None if requires_protocol_bridge(settings.model) else ("ANTHROPIC_API_KEY" if settings.api_key else None),
    }
    write_json(run_root / "config.json", config)


def finalize_run(run_root: Path, results: list[dict[str, Any]]) -> dict[str, Any]:
    artifact_rows: list[dict[str, Any]] = []
    for path in sorted((run_root / "artifacts").glob("*/*.json")):
        value = read_json(path, None)
        if isinstance(value, dict):
            artifact_rows.append(value)
    (run_root / "standard_run_artifacts.jsonl").write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in artifact_rows),
        encoding="utf-8",
    )
    summary = {
        "schema_version": "camact.claude_code_summary.v1",
        "run_id": run_root.name,
        "method": "claude_code",
        "requested_tasks": len(results),
        "completed_tasks": sum(item.get("status") in {"success", "agent_failure", "infrastructure_failure", "timeout", "harness_failure"} for item in results),
        "successful_tasks": sum(item.get("status") == "success" for item in results),
        "agent_failures": sum(item.get("status") == "agent_failure" for item in results),
        "infrastructure_failures": sum(item.get("status") == "infrastructure_failure" for item in results),
        "timeouts": sum(item.get("status") == "timeout" for item in results),
        "standard_artifacts": len(artifact_rows),
        "results": results,
        "finished_at": utc_now(),
    }
    write_json(run_root / "summary.json", summary)
    return summary


def audit_run_isolation(run_root: Path) -> dict[str, Any]:
    """Audit materialized workspaces for forbidden benchmark/evaluator data."""
    forbidden_names = {"ground_truth", "evaluator_config.json", "task_spec.json", "tools.json", "benchmark", "evaluation"}
    violations: list[dict[str, Any]] = []
    workspace_count = 0
    workspaces = set((run_root / "tasks").glob("*/task_*/workspace"))
    workspaces.update((run_root / "tasks").glob("*/task_*/attempts/attempt_*/workspace"))
    for workspace in sorted(workspaces):
        workspace_count += 1
        root = workspace.resolve()
        # The raw album can contain thousands of images. Its copy routine
        # explicitly rejects symlinks, so audit the control-plane tree and the
        # data root without recursively walking every image file.
        for path in workspace.iterdir():
            relative = path.relative_to(workspace)
            if path.is_symlink():
                violations.append({"workspace": str(workspace), "path": str(relative), "reason": "symlink is not permitted"})
            if path.name in forbidden_names:
                violations.append({"workspace": str(workspace), "path": str(relative), "reason": "forbidden benchmark/evaluator path"})
            if path.name != "data" and path.is_dir():
                for child in path.rglob("*"):
                    child_relative = child.relative_to(workspace)
                    if child.is_symlink() or child.name in forbidden_names or any(part in forbidden_names for part in child_relative.parts):
                        violations.append({"workspace": str(workspace), "path": str(child_relative), "reason": "forbidden path or symlink"})
    document = {
        "schema_version": "camact.claude_code_isolation_audit.v1",
        "passed": not violations,
        "workspace_count": workspace_count,
        "violations": violations,
        "checked_at": utc_now(),
    }
    write_json(run_root / "isolation_audit.json", document)
    return document
