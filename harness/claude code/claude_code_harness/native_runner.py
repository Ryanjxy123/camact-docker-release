"""Claude Code-native CamAct runner.

Claude Code owns the complete agent loop.  This module creates the isolated
workspace, starts a task-local action service, invokes the stock Claude Code
CLI, and adapts the resulting trajectory/state to StandardRunArtifact.
"""
from __future__ import annotations

import copy
import gzip
import json
import os
import queue
import shutil
import threading
import time
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .core import (
    ClaudeSettings,
    TaskHandle,
    benchmark_provenance,
    harness_commit,
    parse_stream,
    redact_text,
    utc_now,
    write_json,
)
from .native_adapter import NativeAdapterRuntime, NativeAdapterServer, build_native_workspace
from .provider_bridge import AnthropicTelemetryProxy, OpenAIProtocolBridge
from .runner import (
    _archive_retry_workspace,
    _bridge_delta,
    _model_calls,
    _redact_value,
    _redacted_command,
    _standard_artifact,
    _terminate_process,
)
from evaluation.camact_eval.measurement import (
    model_policy,
    observed_models,
)


from .tool_profiles import NATIVE_TOOLS, DOMAIN_TOOLS, registered_tools, task_tools, validate_profile
from .sandbox_transport import SandboxTransport
from .execution_limits import ExecutionLimits
IMAGE_SUFFIXES = {".jpg", ".jpeg", ".png"}


def validate_native_model_settings(settings: ClaudeSettings) -> dict[str, Any]:
    """Validate the Native execution model policy before a task is started."""
    requested = str(settings.model).strip()
    entrypoints = {
        name: value
        for name, value in {
            **getattr(settings, "configured_entrypoints", {}),
            **{
                name: os.environ[name]
                for name in (
                    "ANTHROPIC_MODEL", "CLAUDE_CODE_MODEL",
                    "ANTHROPIC_SMALL_FAST_MODEL", "CLAUDE_CODE_SMALL_FAST_MODEL",
                    "CLAUDE_CODE_SUBAGENT_MODEL", "CLAUDE_CODE_FALLBACK_MODEL",
                    "ANTHROPIC_FALLBACK_MODEL", "CLAUDE_CODE_UTILITY_MODEL",
                    "ANTHROPIC_UTILITY_MODEL", "CLAUDE_CODE_PRIMARY_MODEL",
                )
                if not settings.provider_config_authoritative and os.environ.get(name)
            },
        }.items()
        if value
    }
    primary = next((entrypoints[name] for name in (
        "CLAUDE_CODE_PRIMARY_MODEL", "ANTHROPIC_MODEL", "CLAUDE_CODE_MODEL"
    ) if name in entrypoints), requested)
    small_fast = next((entrypoints[name] for name in (
        "ANTHROPIC_SMALL_FAST_MODEL", "CLAUDE_CODE_SMALL_FAST_MODEL"
    ) if name in entrypoints), requested)
    subagent = next((entrypoints[name] for name in (
        "CLAUDE_CODE_SUBAGENT_MODEL", "CLAUDE_CODE_FALLBACK_MODEL", "ANTHROPIC_FALLBACK_MODEL"
    ) if name in entrypoints), requested)
    fallback = next((entrypoints[name] for name in (
        "CLAUDE_CODE_FALLBACK_MODEL", "ANTHROPIC_FALLBACK_MODEL"
    ) if name in entrypoints), requested)
    utility = next((entrypoints[name] for name in (
        "CLAUDE_CODE_UTILITY_MODEL", "ANTHROPIC_UTILITY_MODEL"
    ) if name in entrypoints), requested)
    policy = model_policy(
        requested_model=requested,
        primary_model=primary,
        small_fast_model=small_fast,
        subagent_model=subagent,
        fallback_model=fallback,
        utility_model=utility,
        configured_model=primary,
        configured_entrypoints=entrypoints,
        aliases=getattr(settings, "model_aliases", {}),
        enforce=True,
    )
    if policy["violation"]:
        raise ValueError(
            "Claude Code Native requires one consistent requested model for primary, small-fast, and subagent models; "
            f"observed configuration={policy['primary_model']},{policy['small_fast_model']},{policy['subagent_model']}"
        )
    return policy


def build_native_prompt(tool_profile: str = "native") -> str:
    return (
        ("Task-declared CamAct MCP tools are also available. " if tool_profile == "camact" else "") +
        "Open TASK.md and complete the user's CamAct request. Use only the current task workspace. "
        "Use Glob/Grep/Read for album discovery and Read the original image files when visual evidence is needed. "
        "Use the task-local CLI documented in context/adapter_cli.json through native Bash for actions or ask-user. "
        "Do not write result.json and do not inspect any parent or external path. Finish with a concise natural-language answer."
    )


def native_claude_command(settings: ClaudeSettings, prompt: str, domain_tools: list[str] | None = None, *,
                          session_id: str | None = None, resume: bool = False,
                          max_turns: int | None = None) -> list[str]:
    validate_profile(settings.tool_profile)
    tools = ",".join(NATIVE_TOOLS)
    allowed = tools + "".join(f",mcp__camact__{name}" for name in (domain_tools or []) if settings.tool_profile == "camact")
    return [
        settings.executable_path or ("claude.cmd" if os.name == "nt" else "claude"),
        "--print",
        "--output-format",
        "stream-json",
        "--verbose",
        "--include-partial-messages",
        "--setting-sources",
        "local",
        "--strict-mcp-config",
        "--mcp-config",
        "/tmp/.camact/mcp.json",
        "--disable-slash-commands",
        "--model",
        settings.model,
        "--permission-mode",
        "dontAsk",
        "--tools",
        tools,
        "--allowedTools",
        allowed,
        *(["--resume" if resume else "--session-id", session_id] if session_id else []),
        "--max-turns",
        str(max_turns if max_turns is not None else settings.max_agent_turns),
        "--",
        prompt,
    ]


def _sandbox_command(command: list[str], workspace: Path, config_dir: Path, transport_dir: Path | None = None, *, runtime_roots=(), node_executable=None, sandbox_backend="bwrap") -> list[str]:
    """Expose only runtime libraries and this task; no host network or data."""
    if os.name == "nt":
        raise RuntimeError("Claude Code runs must use the WSL wrapper")
    if sandbox_backend == "gvisor":
        from harness.camact_multi_harness_v1.camact_multi.gvisor import command as gvisor_command
        return gvisor_command(command, workspace, config_dir,
            {"runtime_roots": runtime_roots, "node_executable": node_executable}, transport_dir,
            home_guest="/home", relay_script="/tmp/.camact/sandbox_launcher.py",
            environment={"HOME": "/home", "CLAUDE_CONFIG_DIR": "/home",
                         "PATH": "/opt:/usr/local/bin:/usr/bin:/bin"})
    if sandbox_backend != "bwrap":
        raise ValueError(f"Unsupported sandbox backend: {sandbox_backend}")
    bwrap, claude = shutil.which("bwrap"), shutil.which(command[0])
    if not bwrap or not claude:
        raise RuntimeError("bubblewrap and Claude Code are required")
    mounts = []
    for path in ("/usr", "/bin", "/sbin", "/lib", "/lib64"):
        if Path(path).exists():
            mounts += ["--ro-bind", path, path]
    # Do not expose managed Claude settings, machine secrets, or arbitrary /etc files.
    for path in ("/etc/ssl/certs", "/etc/fonts", "/etc/ld.so.cache", "/etc/localtime"):
        if Path(path).exists():
            mounts += ["--ro-bind", path, path]
    executable = claude
    if runtime_roots:
        roots = [Path(root).resolve(strict=True) for root in runtime_roots]
        executable = str(Path(claude).resolve(strict=True))
        if not any(Path(executable).is_relative_to(root) for root in roots):
            raise ValueError("Claude must be inside an explicit read-only runtime root")
        for root in roots:
            if (root in {Path("/"), Path("/home"), Path("/root"), Path("/mnt"), Path.home()}
                    or root.parent == Path("/home") or root.as_posix().startswith("/mnt/")):
                raise ValueError('Unsafe runtime root')
            mounts += ['--ro-bind', str(root), str(root)]
        if node_executable:
            node = Path(node_executable).resolve(strict=True)
            if not any(node.is_relative_to(root) for root in roots):
                raise ValueError('Node must be inside an explicit read-only runtime root')
            mounts += ['--ro-bind', str(node), '/opt/node']
    elif claude.startswith("/mnt/"):
        npm_root = Path(claude).parent
        executable = "/opt/claude"
        mounts += ["--ro-bind", claude, executable, "--ro-bind",
                   str(npm_root / "node_modules/@anthropic-ai/claude-code"),
                   "/opt/node_modules/@anthropic-ai/claude-code"]
    elif not claude.startswith(("/usr/", "/bin/")):
        executable = "/opt/claude"
        mounts += ["--ro-bind", str(Path(claude).resolve()), executable]
    if transport_dir is not None:
        mounts += ["--ro-bind", str(transport_dir), "/transport"]
    from harness.camact_prompt_parity_v1.sandbox import memory_alias_mounts
    return [bwrap, "--die-with-parent", "--new-session", "--unshare-pid", "--unshare-ipc",
            "--unshare-uts", "--unshare-net", "--cap-drop", "ALL", *mounts,
            "--tmpfs", "/mnt", "--tmpfs", "/root", "--tmpfs", "/run",
            "--bind", str(workspace), "/tmp", "--bind", str(config_dir), "/home",
            "--ro-bind", str(workspace / "album"), "/tmp/album",
            *memory_alias_mounts(workspace),
            "--ro-bind", str(workspace / "context"), "/tmp/context",
            "--ro-bind", str(workspace / ".camact"), "/tmp/.camact",
            "--proc", "/proc", "--dev", "/dev", "--chdir", "/tmp",
            "--setenv", "HOME", "/home", "--setenv", "CLAUDE_CONFIG_DIR", "/home",
            "--setenv", "PATH", "/opt:/usr/local/bin:/usr/bin:/bin",
            "--", "python3", "/tmp/.camact/sandbox_launcher.py", executable, *command[1:]]


def _task_environment(settings: ClaudeSettings, bridge: AnthropicTelemetryProxy | OpenAIProtocolBridge | None) -> dict[str, str]:
    attempts = settings.agent_request_attempts or settings.request_attempts
    delays = sum(settings.agent_retry_delay if settings.agent_retry_delay is not None else
                 (2, 4, 8, 16, 30, 60, 90)[min(n, 6)] for n in range(attempts - 1))
    # The stock SDK must wait for the outer HTTP retry policy. Its default
    # 600s deadline otherwise resends a still-running generation. The task
    # watchdog and each upstream request retain their separate original caps.
    client_timeout = max(settings.task_timeout, attempts * (settings.timeout + 5) + delays + 30)
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        "NO_COLOR": "1",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "ENABLE_TOOL_SEARCH": "false",
        "CLAUDE_CODE_MAX_OUTPUT_TOKENS": str(settings.max_output_tokens),
        "API_TIMEOUT_MS": str(int(client_timeout * 1000)),
        "ANTHROPIC_MODEL": settings.model,
        "ANTHROPIC_SMALL_FAST_MODEL": settings.model,
        "CLAUDE_CODE_SUBAGENT_MODEL": settings.model,
        "CLAUDE_CODE_MODEL": settings.model,
        "CLAUDE_CODE_SMALL_FAST_MODEL": settings.model,
        "CLAUDE_CODE_FALLBACK_MODEL": settings.model,
        "ANTHROPIC_FALLBACK_MODEL": settings.model,
        "CLAUDE_CODE_UTILITY_MODEL": settings.model,
        "ANTHROPIC_UTILITY_MODEL": settings.model,
        "CLAUDE_CODE_PRIMARY_MODEL": settings.model,
    }
    if bridge:
        env["ANTHROPIC_BASE_URL"] = bridge.local_base_url
        env["ANTHROPIC_API_KEY"] = "camact-local-protocol-bridge"
    else:
        if settings.base_url:
            env["ANTHROPIC_BASE_URL"] = settings.base_url
        if settings.api_key:
            env["ANTHROPIC_API_KEY"] = settings.api_key
    return env


def _invoke_native(
    command: list[str],
    workspace: Path,
    env: dict[str, str],
    timeout: float,
    bridge: AnthropicTelemetryProxy | OpenAIProtocolBridge | None,
    transport: SandboxTransport | None = None,
) -> dict[str, Any]:
    import subprocess

    bridge_before = bridge.snapshot() if bridge else None
    started = time.monotonic()
    started_at = utc_now()
    process = subprocess.Popen(
        command,
        cwd=str(workspace),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    stdout_parts, stderr_parts, reader_errors = [], [], []
    stdout_events = queue.Queue()
    read_requests = {}

    def consume_stdout():
        # The stock native binary exits without waiting for queued stdout
        # writes under pipe backpressure. Drain the pipe independently of disk
        # logging / JSON parsing / native image processing, which can be slow
        # on real multi-MB transcripts. Queue references to the captured lines.
        try:
            for line in process.stdout:
                stdout_parts.append(line)
                stdout_events.put(line)
        finally:
            stdout_events.put(None)

    event_output = None
    event_processing_complete = False
    try:
        if transport and transport.limits:
            event_output = (transport.limits.log_dir.parent / "claude.stream.jsonl").open("a", encoding="utf-8")
    except OSError as exc:
        reader_errors.append({"stream": "stdout_events", "error_type": type(exc).__name__})

    def consume_stdout_events(max_lines=None):
        # Event callbacks run on the coordinator thread. They can be slow but
        # cannot hold up the independent pipe reader, nor survive this call and
        # mutate a later attempt after a watchdog/processing timeout.
        nonlocal event_processing_complete
        count = 0
        while max_lines is None or count < max_lines:
            try:
                line = stdout_events.get_nowait()
            except queue.Empty:
                return
            if line is None:
                event_processing_complete = True
                return
            if event_output is not None:
                event_output.write(redact_text(line, [transport.limits.settings.api_key]))
            process_stdout_event(line)
            count += 1

    def process_stdout_event(line):
        try:
            event = json.loads(line)
        except ValueError:
            return
        if not isinstance(event, dict):
            return
        if transport and event.get("type") == "system" and event.get("subtype") == "init":
            transport.accept_init(event)
            if not transport.registration["passed"]:
                _terminate_process(process)
        if transport and transport.limits:
            content = event.get("message", {}).get("content", [])
            for block in content if isinstance(content, list) else []:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "tool_use" and block.get("name") == "Read":
                    read_requests[block.get("id")] = event
                if block.get("type") == "tool_result" and block.get("tool_use_id") in read_requests:
                    for image in inspected_native_images([read_requests[block["tool_use_id"]], event], workspace):
                        transport.limits.record_native_read(image)

    def consume_stderr():
        for line in process.stderr:
            stderr_parts.append(line)
            if transport and transport.limits:
                with (transport.limits.log_dir.parent / "claude.stderr.log").open("a", encoding="utf-8") as output:
                    output.write(redact_text(line, [transport.limits.settings.api_key]))

    def guarded_reader(name, consume):
        try:
            consume()
        except Exception as exc:
            # A reader thread exception must not masquerade as a drained pipe.
            reader_errors.append({"stream": name, "error_type": type(exc).__name__})

    readers = [threading.Thread(target=guarded_reader, args=(name, consume), daemon=True)
               for name, consume in (("stdout", consume_stdout), ("stderr", consume_stderr))]
    for reader in readers:
        reader.start()
    timed_out = False
    controlled_stop = False
    controlled_stop_reason = None
    deadline = started + timeout
    while process.poll() is None:
        guarded_reader("stdout_events", lambda: consume_stdout_events(128))
        if reader_errors:
            _terminate_process(process)
            break
        if transport and transport.limits and getattr(transport.runtime, "infrastructure_error", None):
            transport.limits.stop_reason = "business_or_simulator_infrastructure_failure"
        elif (transport and transport.limits and transport.runtime.environment.simulator_stopped
              and transport.limits.stop_reason in {None, "simulator_stop", "agent_turn_limit_exceeded"}):
            transport.limits.stop_reason = "simulator_stop"
        if transport and transport.limits and transport.limits.stop_reason:
            from harness.camact_compatibility_v2.terminal import canonical_budget_reason
            reason = transport.limits.stop_reason
            # Record the actual host kill while this process is alive. A
            # coincidentally present old budget/STOP field cannot authorize a
            # later unexpected signal exit as a controlled termination.
            if process.poll() is None and (reason == "simulator_stop" or canonical_budget_reason(reason)):
                controlled_stop, controlled_stop_reason = True, reason
            _terminate_process(process)
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            if transport and transport.limits:
                transport.limits.stop_reason = "task_timeout"
            _terminate_process(process)
            break
        try:
            process.wait(timeout=min(remaining, 0.5))
        except subprocess.TimeoutExpired:
            pass
    process.wait(timeout=5)
    if (transport and transport.limits and transport.runtime.environment.simulator_stopped
            and not transport.runtime.infrastructure_error
            and transport.limits.stop_reason in {None, "simulator_stop", "agent_turn_limit_exceeded"}):
        # The stock CLI can emit error_max_turns immediately after the final
        # allowed tool round. The real user STOP already completed the task.
        transport.limits.stop_reason = "simulator_stop"
    if transport and transport.limits and (timed_out or transport.limits.stop_reason):
        transport.limits.cancelled.set()
    for reader in readers:
        # Drain captured pipes inside the original task deadline. A fixed
        # five-second cutoff could itself abandon a large valid transcript.
        reader.join(timeout=min(30, max(0, deadline - time.monotonic())))
    if any(reader.is_alive() for reader in readers):
        # A descendant retaining a pipe after the immediate process exits is
        # still part of this invocation's process group. Close it before the
        # final short drain; never leave it attached to a later attempt.
        try:
            _terminate_process(process)
        except ProcessLookupError:
            pass
        for reader in readers:
            reader.join(timeout=2)
    while not event_processing_complete and not reader_errors and time.monotonic() < deadline:
        before = stdout_events.qsize()
        guarded_reader("stdout_events", lambda: consume_stdout_events(128))
        if stdout_events.qsize() == before and not event_processing_complete:
            break
    if event_output is not None:
        event_output.close()
    for pipe, reader in zip((process.stdout, process.stderr), readers):
        if not reader.is_alive():
            pipe.close()
    stdout, stderr = "".join(stdout_parts), "".join(stderr_parts)
    structured, events, metadata = parse_stream(stdout)
    return {
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": timed_out,
        "controlled_stop": controlled_stop,
        "controlled_stop_reason": controlled_stop_reason,
        "returncode": -9 if timed_out else int(process.returncode if process.returncode is not None else -127),
        "structured": structured,
        "events": events,
        "metadata": metadata,
        "native_stream_complete": not reader_errors and not any(reader.is_alive() for reader in readers)
            and event_processing_complete and any(event.get("type") == "result" for event in events),
        # A result event is a useful fast path, but the stock CLI can persist
        # a complete assistant turn to its native session JSONL without
        # emitting the wrapper result record. Keep drain state separately so
        # an equivalent persisted terminal can be checked fail-closed.
        "native_stdout_drained": not reader_errors and not any(reader.is_alive() for reader in readers),
        "native_event_processing_complete": event_processing_complete,
        "native_reader_errors": reader_errors,
        "started_at": started_at,
        "duration_seconds": round(time.monotonic() - started, 3),
        "protocol_bridge": _bridge_delta(bridge_before, bridge.snapshot() if bridge else None),
        "execution_limits": transport.limits.diagnostics() if transport and transport.limits else {},
    }


def _persisted_native_terminal(*, invocation: dict[str, Any], config_dir: Path | None,
                               transport: SandboxTransport | None) -> dict[str, Any]:
    """Prove the current print turn from its native journal and final HTTP wire.

    The wrapper result may be lost by the stock binary's stdout shutdown.
    Only the latest persisted conversation leaf, linked by message id and
    exact final text to this invocation's final complete provider response,
    can substitute for it. Previous --resume turns cannot satisfy this proof.
    """
    evidence: dict[str, Any] = {"valid": False, "reason": "missing_evidence"}
    if config_dir is None or not invocation.get("native_stdout_drained") or invocation.get("native_reader_errors"):
        evidence["reason"] = "stdout_not_drained_or_config_unavailable"
        return evidence
    session_id = invocation.get("metadata", {}).get("session_id")
    started_at = invocation.get("started_at")
    if not isinstance(session_id, str) or not session_id or not started_at:
        evidence["reason"] = "missing_stream_session_id_or_invocation_start"
        return evidence
    from datetime import datetime
    try:
        started = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        evidence["reason"] = "invalid_invocation_start"
        return evidence
    # The exact official journal is keyed by session UUID. Never scan subagent
    # journals or select any earlier end_turn in the conversation.
    journal_path = config_dir / "projects" / "-tmp" / (session_id + ".jsonl")
    try:
        rows = [json.loads(line) for line in journal_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        evidence["reason"] = "native_journal_missing_or_malformed"
        return evidence
    matching = [row for row in rows if isinstance(row, dict) and row.get("sessionId") == session_id]
    messages = [row for row in matching if row.get("type") in {"user", "assistant"} and not row.get("isSidechain")]
    leaf_rows = [row for row in matching if row.get("type") == "last-prompt"]
    if not messages or messages[-1].get("type") != "assistant" or not leaf_rows:
        evidence["reason"] = "no_final_assistant_or_leaf"
        return evidence
    final_assistant = messages[-1]
    message = final_assistant.get("message", {})
    final_uuid = final_assistant.get("uuid")
    if (not isinstance(message, dict) or not final_uuid or leaf_rows[-1].get("leafUuid") != final_uuid
            or message.get("stop_reason") != "end_turn" or final_assistant.get("isApiErrorMessage")):
        evidence["reason"] = "persisted_leaf_is_not_completed_assistant"
        return evidence
    try:
        if datetime.fromisoformat(final_assistant["timestamp"].replace("Z", "+00:00")) < started:
            evidence["reason"] = "persisted_assistant_precedes_invocation"
            return evidence
    except (KeyError, TypeError, ValueError):
        evidence["reason"] = "persisted_assistant_timestamp_missing"
        return evidence
    content = message.get("content", [])
    if (not isinstance(content, list) or any(not isinstance(block, dict) or block.get("type") != "text" for block in content)
            or not content or not all(isinstance(block.get("text"), str) for block in content)):
        evidence["reason"] = "final_assistant_is_not_complete_text"
        return evidence
    final_text = "".join(block["text"] for block in content)
    response_path = None
    if transport is not None and getattr(transport, "limits", None) is not None:
        response_path = transport.limits.log_dir / "provider_responses.jsonl.gz"
    try:
        if response_path is None:
            raise OSError("provider log unavailable")
        with gzip.open(response_path, "rt", encoding="utf-8") as source:
            responses = [json.loads(line) for line in source if line.strip()]
        response = responses[-1]
        if not isinstance(response, dict):
            raise ValueError("provider response record is not an object")
        response_started = datetime.fromisoformat(response["started_at"].replace("Z", "+00:00"))
        if (response_started < started or response.get("http_status") != 200
                or response.get("upstream_http_status", 200) != 200 or response.get("error")):
            evidence["reason"] = "final_provider_attempt_not_successful_current_invocation"
            return evidence
        body = response.get("response")
        if not isinstance(body, str):
            raise ValueError("SSE body missing")
        frames = [json.loads(line[5:].strip()) for line in body.splitlines() if line.startswith("data:")]
        if any(not isinstance(frame, dict) or not isinstance(frame.get("delta", {}), dict)
               or not isinstance(frame.get("message", {}), dict) for frame in frames):
            raise ValueError("provider SSE frame is not a valid event object")
    except (OSError, EOFError, gzip.BadGzipFile, UnicodeDecodeError, json.JSONDecodeError, IndexError, KeyError, TypeError, ValueError):
        evidence["reason"] = "final_provider_sse_missing_or_malformed"
        return evidence
    starts = [frame.get("message", {}) for frame in frames if frame.get("type") == "message_start"]
    stops = [frame for frame in frames if frame.get("type") == "message_stop"]
    deltas = [frame.get("delta", {}) for frame in frames if frame.get("type") == "message_delta"]
    wire_text = "".join(frame.get("delta", {}).get("text", "") for frame in frames
                        if frame.get("type") == "content_block_delta" and frame.get("delta", {}).get("type") == "text_delta")
    if (len(starts) != 1 or not stops or frames[-1].get("type") != "message_stop"
            or not deltas or deltas[-1].get("stop_reason") != "end_turn"
            or starts[0].get("id") != message.get("id") or wire_text != final_text):
        evidence["reason"] = "final_provider_message_does_not_match_native_end_turn"
        return evidence
    evidence.update(valid=True, reason="persisted_native_end_turn", session_id=session_id,
                    journal=str(journal_path), assistant_uuid=final_uuid, provider_message_id=message.get("id"),
                    provider_request_id=response.get("request_id"), provider_response=str(response_path),
                    final_response=final_text)
    return evidence


def _final_text(events: list[dict[str, Any]], metadata: dict[str, Any]) -> str:
    if isinstance(metadata.get("result_text"), str):
        return str(metadata["result_text"])
    texts: list[str] = []
    for event in events:
        if event.get("type") != "assistant":
            continue
        message = event.get("message", event)
        content = message.get("content", []) if isinstance(message, dict) else []
        if isinstance(content, str):
            texts.append(content)
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
                    texts.append(item["text"])
    return texts[-1] if texts else ""


def _native_termination(runtime, settings, invocation):
    from harness.camact_compatibility_v2.terminal import classify_native, BUDGET_REASONS
    if runtime.infrastructure_error:
        return "infrastructure_failure", runtime.infrastructure_error
    if invocation.get("native_reader_errors"):
        return "infrastructure_failure", "native_stdout_capture_error"
    if invocation.get("native_event_processing_complete") is False:
        return "infrastructure_failure", "incomplete_native_stream: native event processing did not drain"
    forced = invocation.get("host_trajectory_class")
    if forced:
        return forced, invocation.get("host_terminal_error")
    metadata = invocation.get("metadata", {})
    error = None
    if invocation.get("timed_out") or invocation.get("returncode") != 0 or metadata.get("is_error") or metadata.get("errors"):
        error = (f"Claude Code task timed out after {settings.task_timeout}s" if invocation.get("timed_out")
                 else str(metadata.get("result_text") or invocation.get("stderr") or "Official Claude execution failed"))
    capture = {"stop_reason": invocation.get("execution_limits", {}).get("stop_reason"),
               "native_process": {k: invocation.get(k) for k in ("returncode", "timed_out", "controlled_stop")}}
    if metadata.get("subtype") in BUDGET_REASONS and not capture["stop_reason"]:
        capture["stop_reason"] = metadata["subtype"]
    trajectory, error = classify_native(runtime, requested="infrastructure_failure" if error else "finished",
        error=error, capture=capture, events=invocation.get("events", []))
    persisted = invocation.get("persisted_native_terminal", {})
    if (trajectory == "infrastructure_failure"
            and str(error or "").startswith("incomplete_native_stream")
            and persisted.get("valid")
            and invocation.get("returncode") == 0
            and invocation.get("native_stdout_drained")):
        trajectory, error = "finished", None
    if (trajectory == "finished" and invocation.get("native_stream_complete") is False
            and not runtime.environment.simulator_stopped and not persisted.get("valid")):
        # Exit 0 alone does not prove a complete native turn. In particular,
        # partial stream deltas are not an empty answer chosen by the Agent.
        return "infrastructure_failure", "incomplete_native_stream: official result event or stdout drain is missing"
    if invocation.get("tool_registration", {}).get("passed") is False:
        return "infrastructure_failure", "Tool registration preflight failed"
    return trajectory, error


def _run_native_conversation(*, runtime, settings, workspace, config_dir, bridge, transport, deadline):
    generator = runtime.environment.simulator_generator
    if generator is not None and hasattr(generator, "__dict__"):
        generator.deadline = deadline
    """Deliver real user replies via --resume in one isolated official session."""
    from harness.camact_compatibility_v2.multiturn import advance_native_turn
    session_id = str(uuid4())
    if transport.limits is not None:
        transport.limits.deadline = deadline
    prompt = runtime.environment.task.initial_user_message()["content"]
    invocations, continuations, all_events, outputs, errors = [], [], [], [], []
    bridge_before = bridge.snapshot() if bridge else None
    last = {"metadata": {}, "events": [], "returncode": -127}
    command = []
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            last.update(timed_out=True, host_trajectory_class="infrastructure_failure",
                        host_terminal_error=f"Claude Code task timed out after {settings.task_timeout}s")
            break
        generation_budget = settings.max_agent_turns - runtime.environment.agent_turns
        if generation_budget <= 0:
            reason = "agent_turn_limit_exceeded"
            runtime.environment.state["session"].update(status="agent_failure", termination_reason=reason, failure_type=reason)
            last.update(host_trajectory_class="agent_failure", host_terminal_error=reason)
            break
        plain = native_claude_command(settings, prompt, runtime.domain_tools, session_id=session_id,
                                     resume=bool(invocations), max_turns=generation_budget)
        command = _sandbox_command(plain, workspace, config_dir, transport.path,
                                   runtime_roots=settings.runtime_roots, node_executable=settings.node_executable, sandbox_backend=settings.sandbox_backend)
        transport.ready.clear()
        transport.registration = {}
        if getattr(bridge, "token_collector", None):
            bridge.token_collector.update_context(session_id=session_id, native_invocation_id=len(invocations) + 1)
        last = _invoke_native(command, workspace, _task_environment(settings, bridge), remaining, bridge, transport)
        last["persisted_native_terminal"] = _persisted_native_terminal(
            invocation=last, config_dir=config_dir, transport=transport)
        if last["persisted_native_terminal"].get("valid"):
            last["metadata"]["native_terminal_source"] = "persisted_native_end_turn"
            last["metadata"]["result_text"] = last["persisted_native_terminal"]["final_response"]
        if getattr(bridge, "token_collector", None):
            bridge.token_collector.attach_native_events(last.get("events", []))
        passed = bool(transport.registration.get("passed")) and bool(transport.registrations) and all(row["passed"] for row in transport.registrations)
        last["tool_registration"] = {**transport.registration, "passed": passed, "provider_requests": copy.deepcopy(transport.registrations)}
        invocations.append({"index": len(invocations) + 1, "session_id": session_id, "resumed": len(invocations) > 0,
            "command": _redacted_command(command, settings.api_key), "returncode": last.get("returncode"),
            "timed_out": last.get("timed_out", False), "duration_seconds": last.get("duration_seconds"),
            "controlled_stop": last.get("controlled_stop", False),
            "controlled_stop_reason": last.get("controlled_stop_reason"),
            "started_at": last.get("started_at"), "native_stdout_drained": last.get("native_stdout_drained"),
            "native_stream_complete": last.get("native_stream_complete"),
            "native_event_processing_complete": last.get("native_event_processing_complete"),
            "native_reader_errors": last.get("native_reader_errors", []),
            "persisted_native_terminal": copy.deepcopy(last.get("persisted_native_terminal", {})),
            "metadata": copy.deepcopy(last.get("metadata", {})), "execution_limits": copy.deepcopy(last.get("execution_limits", {}))})
        all_events.extend(last.get("events", []))
        outputs.append(last.get("stdout", ""))
        errors.append(last.get("stderr", ""))
        trajectory, terminal_error = _native_termination(runtime, settings, last)
        if trajectory != "finished":
            last.update(host_trajectory_class=trajectory, host_terminal_error=terminal_error)
            break
        observed_id = last.get("metadata", {}).get("session_id")
        if observed_id and observed_id != session_id:
            last.update(host_trajectory_class="infrastructure_failure", host_terminal_error="Official Claude session identity changed")
            break
        answer = _final_text(last.get("events", []), last.get("metadata", {}))
        # User Simulator generation is part of this task's same deadline.
        if time.monotonic() >= deadline:
            last.update(timed_out=True, host_trajectory_class="infrastructure_failure",
                        host_terminal_error=f"Claude Code task timed out after {settings.task_timeout}s")
            break
        decision = advance_native_turn(runtime, answer, trajectory)
        continuations.append({"native_invocation": len(invocations), "assistant_answer": answer, **decision})
        if time.monotonic() >= deadline:
            last.update(timed_out=True, host_trajectory_class="infrastructure_failure",
                        host_terminal_error=f"Claude Code task timed out after {settings.task_timeout}s")
            break
        if decision["action"] == "finish":
            break
        if decision["action"] != "resume":
            kind = decision["action"]
            reason = decision.get("reason")
            if kind == "agent_failure":
                runtime.environment.state["session"].update(status="agent_failure", termination_reason=reason, failure_type=reason)
            last.update(host_trajectory_class=kind, host_terminal_error=reason)
            break
        prompt = decision["message"]
    metadata = copy.deepcopy(last.get("metadata", {}))
    # Claude result usage is scoped to each print invocation; keep all records
    # and sum those reported counters, never infer usage from prompt text.
    usage = {}
    for item in invocations:
        for key, value in item.get("metadata", {}).get("usage", {}).items():
            if isinstance(value, (int, float)):
                usage[key] = usage.get(key, 0) + value
    if usage:
        metadata["usage"] = usage
    costs = [row["metadata"].get("total_cost_usd") for row in invocations]
    if costs and all(isinstance(value, (int, float)) for value in costs):
        metadata["total_cost_usd"] = sum(costs)
    metadata["native_session_id"] = session_id
    metadata["native_invocations"] = invocations
    metadata["simulator_continuations"] = continuations
    result = {**last, "metadata": metadata, "events": all_events, "stdout": "".join(outputs), "stderr": "".join(errors),
              "duration_seconds": sum(float(row.get("duration_seconds") or 0) for row in invocations),
              "execution_limits": transport.limits.diagnostics(),
              "protocol_bridge": _bridge_delta(bridge_before, bridge.snapshot() if bridge else None)}
    path = transport.limits.log_dir.parent / "native_conversation.json"
    write_json(path, _redact_value({"session_id": session_id, "invocations": invocations,
        "simulator_continuations": continuations, "execution_limits": result["execution_limits"]}, settings.api_key))
    return result, command


def _tool_uses(events: list[dict[str, Any]]) -> list[tuple[str, dict[str, Any]]]:
    found: list[tuple[str, dict[str, Any]]] = []
    seen: set[str] = set()
    for event in events:
        candidates: list[dict[str, Any]] = []
        if event.get("type") == "assistant":
            message = event.get("message", event)
            content = message.get("content", []) if isinstance(message, dict) else []
            if isinstance(content, list):
                candidates.extend(item for item in content if isinstance(item, dict) and item.get("type") == "tool_use")
        elif event.get("type") == "tool_use":
            candidates.append(event)
        for item in candidates:
            call_id = str(item.get("id") or item.get("tool_use_id") or json.dumps(item, sort_keys=True))
            if call_id in seen:
                continue
            seen.add(call_id)
            payload = item.get("input", {})
            found.append((str(item.get("name", "")), payload if isinstance(payload, dict) else {}))
    return found


def inspected_native_images(events: list[dict[str, Any]], workspace: Path) -> list[str]:
    root = workspace.resolve()
    image_root = root / "album" / "images"
    from harness.camact_prompt_parity_v1.sandbox import memory_alias_mounts
    # The published source points to this isolated copy inside the sandbox.
    # Never resolve that source against the export host's private album tree.
    try:
        alias_mounts = memory_alias_mounts(root)
    except (OSError, ValueError):
        alias_mounts = []
    memory_alias = alias_mounts[-1] + "/" if alias_mounts else None
    result: list[str] = []
    successful_ids = set()
    for event in events:
        message = event.get("message", event)
        for item in message.get("content", []) if isinstance(message, dict) and isinstance(message.get("content", []), list) else []:
            if isinstance(item, dict) and item.get("type") == "tool_result" and not item.get("is_error"):
                blocks = item.get("content", [])
                if isinstance(blocks, list) and any(isinstance(b, dict) and b.get("type") == "image" for b in blocks):
                    successful_ids.add(item.get("tool_use_id"))
    successful_reads = []
    for event in events:
        message = event.get("message", event)
        for item in message.get("content", []) if isinstance(message, dict) and isinstance(message.get("content", []), list) else []:
            if isinstance(item, dict) and item.get("type") == "tool_use" and item.get("id") in successful_ids:
                successful_reads.append((item.get("name", ""), item.get("input", {})))
    for tool, payload in successful_reads:
        if tool.casefold() != "read":
            continue
        raw = payload.get("file_path") or payload.get("path")
        if not isinstance(raw, str):
            continue
        normalized = raw.replace("\\", "/")
        if memory_alias and normalized.startswith(memory_alias):
            candidate = root / "album" / normalized.removeprefix(memory_alias)
        elif normalized in {"/workspace", "/tmp"}:
            candidate = root
        elif normalized.startswith("/workspace/"):
            candidate = root / normalized.removeprefix("/workspace/")
        elif normalized.startswith("/tmp/"):
            candidate = root / normalized.removeprefix("/tmp/")
        else:
            candidate = Path(raw)
            if not candidate.is_absolute():
                candidate = root / candidate
        try:
            resolved = candidate.resolve()
            resolved.relative_to(image_root.resolve())
        except (OSError, ValueError):
            continue
        if resolved.is_file() and resolved.suffix.casefold() in IMAGE_SUFFIXES and resolved.name not in result:
            result.append(resolved.name)
    return result


def _file_observation_calls(handle: TaskHandle, images: list[str]) -> list[dict[str, Any]]:
    _, schemas = task_tools(handle)
    allowed = set(schemas)
    observation_tool = "image_view" if "image_view" in allowed else "inspect_image" if "inspect_image" in allowed else None
    if not observation_tool:
        return []
    return [
        {
            "tool": observation_tool,
            "arguments": {"image_id": image_id},
            "status": "succeeded",
            "source": "claude_code_native_read",
        }
        for image_id in images
    ]


def _persist_terminal(
    *,
    handle: TaskHandle,
    benchmark_root: Path,
    run_root: Path,
    run_id: str,
    settings: ClaudeSettings,
    task_root: Path,
    workspace: Path,
    runtime: NativeAdapterRuntime,
    runtime_dir: Path,
    public: dict[str, Any],
    invocation: dict[str, Any],
    attempts: list[dict[str, Any]],
    trajectory_class: str,
    terminal_error: str | None,
    started_at: str,
    started_monotonic: float,
    command: list[str],
) -> dict[str, Any]:
    events = invocation.get("events", [])
    metadata = copy.deepcopy(invocation.get("metadata", {}))
    metadata["attempts"] = copy.deepcopy(attempts)
    metadata["tool_profile"] = settings.tool_profile
    observed = inspected_native_images(events, workspace)
    observed_model_names = observed_models(events, metadata)
    bridge_model_names = sorted({
        str(model)
        for attempt in attempts
        if isinstance(attempt, dict)
        for model in (attempt.get("protocol_bridge", {}).get("observed_models", [])
                      if isinstance(attempt.get("protocol_bridge"), dict) else [])
        if str(model).strip()
    })
    all_observed_model_names = sorted(set(observed_model_names) | set(bridge_model_names))
    policy = model_policy(
        requested_model=settings.model,
        primary_model=str(metadata.get("model") or settings.model),
        small_fast_model=str(metadata.get("small_fast_model") or settings.model),
        subagent_model=str(metadata.get("subagent_model") or settings.model),
        fallback_model=str(metadata.get("fallback_model") or settings.model),
        utility_model=str(metadata.get("utility_model") or settings.model),
        configured_model=str(metadata.get("configured_model") or settings.model),
        aliases=getattr(settings, "model_aliases", {}),
        configured_entrypoints={
            name: str(metadata.get(metadata_key) or settings.configured_entrypoints.get(name) or settings.model)
            for name, metadata_key in {
                "ANTHROPIC_MODEL": "anthropic_model",
                "CLAUDE_CODE_MODEL": "claude_code_model",
                "ANTHROPIC_SMALL_FAST_MODEL": "small_fast_model",
                "CLAUDE_CODE_SMALL_FAST_MODEL": "claude_code_small_fast_model",
                "CLAUDE_CODE_SUBAGENT_MODEL": "subagent_model",
                "CLAUDE_CODE_FALLBACK_MODEL": "fallback_model",
                "ANTHROPIC_FALLBACK_MODEL": "anthropic_fallback_model",
                "CLAUDE_CODE_UTILITY_MODEL": "utility_model",
                "ANTHROPIC_UTILITY_MODEL": "anthropic_utility_model",
                "CLAUDE_CODE_PRIMARY_MODEL": "primary_model",
            }.items()
        },
        observed=all_observed_model_names,
        upstream_models=bridge_model_names,
        enforce=True,
    )
    if policy["violation"]:
        trajectory_class = "infrastructure_failure"
        terminal_error = "Claude Code model policy violation: non-requested model observed"
    final_text = _final_text(events, metadata)
    # Native image observations are recorded from actual successful Read results.
    # Fall back for direct/test callers that did not use the streaming callback.
    existing_reads = {c.get("arguments", {}).get("image_id") for c in runtime.tool_calls()
                      if c.get("source") == "claude_code_native_read"}
    for image in observed:
        if image not in existing_reads:
            runtime.record_native_read(image)
    episode = runtime.finish(final_text, observed, trajectory_class)
    final_state = runtime.close()
    diagnostics = runtime.diagnostics()
    runtime_calls = runtime.tool_calls()
    calls = runtime_calls
    for call in runtime_calls:
        if call.get("tool") in {"image_view", "inspect_image"} and call.get("status") == "succeeded":
            args = call.get("arguments", {})
            image = args.get("image_id") or args.get("image")
            if image and image not in observed:
                observed.append(image)
    diagnostics.update({
        "native_tools": list(NATIVE_TOOLS),
        "execution_limits": invocation.get("execution_limits", {}),
        "native_process": {key: invocation.get(key) for key in
                           ("returncode", "timed_out", "controlled_stop", "controlled_stop_reason")},
        "benchmark_tools_registered_with_claude": runtime.domain_tools,
        "tool_registration": invocation.get("tool_registration", {}),
        "native_tool_calls": [{"tool": name, "arguments": args, "tool_category": "native_tool" if name in NATIVE_TOOLS else "domain_tool"} for name, args in _tool_uses(events)],
        "result_json_required": False,
        "final_response_source": "claude_code_trajectory",
        "evidence_source": "successful native Read image results + live MCP image observations",
        "final_state_source": "live_runtime_environment",
        "sandbox": "bubblewrap",
        "simulator_turns": len(final_state.get("user_simulator", {}).get("turns", [])) if isinstance(final_state.get("user_simulator"), dict) else 0,
        "model_policy": policy,
        "observed_models": all_observed_model_names,
        "upstream_models": bridge_model_names,
        "native_session_id": metadata.get("native_session_id"),
        "native_invocations": copy.deepcopy(metadata.get("native_invocations", [])),
        "simulator_continuations": copy.deepcopy(metadata.get("simulator_continuations", [])),
    })
    conversation_trace = diagnostics.pop("runtime_conversation_trace", [])
    errors: dict[str, Any] = {}
    if terminal_error:
        key = "infrastructure" if trajectory_class == "infrastructure_failure" else "agent"
        errors[key] = [{"message": terminal_error}]
    result_payload = {
        "_method": "claude_code_native",
        "final_response": final_text,
        "evidence": observed,
        "actions": [item for item in runtime_calls if item.get("status") == "succeeded" and item.get("tool_category") == "business_action"],
        "source": "adapter_derived",
    }
    artifact = _standard_artifact(
        handle=handle,
        run_id=run_id,
        settings=settings,
        benchmark_root=benchmark_root,
        result=result_payload,
        final_state=final_state,
        calls=calls,
        events=events,
        metadata=metadata,
        workspace_manifest=public["workspace_manifest"],
        timing={"started_at": started_at, "ended_at": utc_now(), "duration_seconds": round(time.monotonic() - started_monotonic, 3)},
        trajectory_class=trajectory_class,
        errors=errors,
        invocation=command,
        action_diagnostics=diagnostics,
        conversation_trace=conversation_trace,
        invocation_records=attempts,
    )
    artifact.run["tool_profile"] = settings.tool_profile
    for field in ("execution_trace", "action_audit", "conversation", "final_service_state", "service_audit", "runtime_metadata"):
        setattr(artifact, field, copy.deepcopy(episode[field]))
    artifact.diagnostics["identity_claims"] = episode.get("identity_claims", [])
    final_session = run_root / "sessions" / handle.user_id / handle.task_name
    final_session.parent.mkdir(parents=True, exist_ok=True)
    if runtime_dir.exists() and runtime_dir != final_session:
        if final_session.exists():
            raise FileExistsError(f"final session already exists: {final_session}")
        shutil.move(str(runtime_dir), str(final_session))
    # Closing Runtime and the provider transport flushes all wire requests. Only
    # collect after moving the complete session so no evidence names a dead path.
    from evaluation.camact_eval.visual_capture import collect_visual_evidence
    artifact.visual_evidence = collect_visual_evidence(final_session, episode, workspace / "album/images")
    artifact.validate()
    submission_path = run_root / "submissions" / handle.user_id / f"{handle.task_name}.json"
    artifact_path = run_root / "artifacts" / handle.user_id / f"{handle.task_name}.json"
    write_json(submission_path, result_payload)
    artifact.write(artifact_path)
    status = "success" if trajectory_class == "finished" else trajectory_class
    return {
        "user_id": handle.user_id,
        "task": handle.task_name,
        "task_id": handle.task_id,
        "tool_profile": settings.tool_profile,
        "status": status,
        "trajectory_class": trajectory_class,
        "artifact_path": str(artifact_path),
        "submission_path": str(submission_path),
        "duration_seconds": artifact.timing.get("duration_seconds"),
        "evidence_count": len(observed),
        "action_count": runtime.successful_action_count,
        "final_response_empty": not bool(final_text.strip()),
        **({"error": terminal_error} if terminal_error else {}),
    }


from harness.camact_token_usage_v1.integration import track_claude


@track_claude
def run_task(
    handle: TaskHandle,
    *,
    benchmark_root: Path,
    run_root: Path,
    run_id: str,
    settings: ClaudeSettings,
    resume: bool = False,
) -> dict[str, Any]:
    # Fail closed before creating a task attempt when any configured auxiliary
    # model diverges from the requested control model.
    validate_native_model_settings(settings)
    task_root = run_root / "tasks" / handle.user_id / handle.task_name
    workspace = task_root / "workspace"
    started_at = utc_now()
    started_monotonic = time.monotonic()
    task_root.mkdir(parents=True, exist_ok=True)
    use_bridge = settings.protocol_bridge_required
    if use_bridge and (not settings.base_url or not settings.api_key):
        return _early_failure(handle, run_root, started_at, started_monotonic, "OpenAI protocol bridge requires --base-url and --api-key", benchmark_root=benchmark_root, settings=settings)

    if use_bridge:
        bridge_context: AnthropicTelemetryProxy | OpenAIProtocolBridge | None = OpenAIProtocolBridge(
            base_url=settings.base_url,
            api_key=settings.api_key,
            model=settings.model,
            timeout=settings.timeout,
            request_attempts=settings.request_attempts,
            task_key=f"{handle.user_id}/{handle.task_name}",
        )
    elif settings.base_url and settings.api_key:
        bridge_context = AnthropicTelemetryProxy(
            base_url=settings.base_url,
            api_key=settings.api_key,
            model=settings.model,
            timeout=settings.timeout,
            task_key=f"{handle.user_id}/{handle.task_name}",
        )
    else:
        bridge_context = None
    context = bridge_context or __import__("contextlib").nullcontext()
    from .resume import previous_attempts
    attempts: list[dict[str, Any]] = previous_attempts(run_root, handle) if resume else []
    spent_attempts = len(attempts)
    if spent_attempts >= settings.retries:
        return _early_failure(handle, run_root, started_at, started_monotonic,
            'Infrastructure attempt budget exhausted before coordinator resume; preserved raw sessions',
            benchmark_root=benchmark_root, settings=settings)
    selected: tuple[NativeAdapterRuntime, Path, dict[str, Any], dict[str, Any], str, list[str], str | None] | None = None

    with context as bridge:
        for attempt_index in range(spent_attempts, settings.retries):
            attempt_number = attempt_index + 1
            attempt_started = time.monotonic()
            if attempt_index:
                _archive_retry_workspace(task_root, workspace, attempt_index)
            runtime_dir = run_root / "session_attempts" / handle.user_id / handle.task_name / f"attempt_{attempt_number:02d}"
            if getattr(bridge, "token_collector", None):
                bridge.token_collector.update_context(infrastructure_attempt=attempt_number)
            runtime_dir.parent.mkdir(parents=True, exist_ok=True)
            try:
                runtime = NativeAdapterRuntime(handle, runtime_dir, settings, benchmark_root)
            except Exception as exc:
                message = redact_text(f"adapter runtime: {type(exc).__name__}: {exc}", [settings.api_key])
                record = {"attempt": attempt_number, "status": "infrastructure_failure", "error": message}
                attempts.append(record)
                write_json(task_root / "attempts" / f"attempt_{attempt_number:02d}" / "runtime-start-failure.json", record)
                if attempt_number < settings.retries:
                    continue
                return _early_failure(handle, run_root, started_at, started_monotonic, message, benchmark_root=benchmark_root, settings=settings)

            config_dir = task_root / "claude_config" / f"attempt_{attempt_number:02d}"
            config_dir.mkdir(parents=True, exist_ok=False)
            try:
                with NativeAdapterServer(runtime) as server:
                    public = build_native_workspace(handle, workspace, {
                        "transport": "unix", "timeout": min(settings.task_timeout,
                            settings.timeout * settings.request_attempts + 30)}, settings.tool_profile)
                    if bridge is None:
                        raise ValueError("Isolated execution requires provider --base-url and credentials")
                    expected = registered_tools(runtime.environment.tools, settings.tool_profile)
                    limits = ExecutionLimits(runtime, settings, runtime_dir / "execution_limits")
                    with SandboxTransport(runtime, bridge.local_base_url, expected, settings.task_timeout, limits=limits) as transport:
                        invocation, command = _run_native_conversation(runtime=runtime, settings=settings,
                            workspace=workspace, config_dir=config_dir, bridge=bridge, transport=transport,
                            deadline=started_monotonic + settings.task_timeout)
                        passed = bool(transport.registration.get("passed")) and bool(transport.registrations) and all(r["passed"] for r in transport.registrations)
                        invocation["tool_registration"] = {**transport.registration, "passed": passed,
                            "provider_requests": transport.registrations}
                        if not passed:
                            invocation["returncode"] = -126
                            invocation["stderr"] += "\nTool registration preflight failed (see tool_registration)"

            except Exception as exc:
                invocation = {
                    "stdout": "",
                    "stderr": str(exc),
                    "timed_out": False,
                    "returncode": -127,
                    "events": [],
                    "metadata": {},
                    "duration_seconds": 0.0,
                    "protocol_bridge": {},
                }
                public = {"workspace_manifest": {"schema_version": "workspace_failure", "files": []}, "allowed_actions": runtime.allowed_actions}
                command = []

            stdout = redact_text(invocation.get("stdout", ""), [settings.api_key])
            stderr = redact_text(invocation.get("stderr", ""), [settings.api_key])
            attempt_root = task_root / "attempts" / f"attempt_{attempt_number:02d}"
            attempt_root.mkdir(parents=True, exist_ok=True)
            (attempt_root / "stdout.log").write_text(stdout, encoding="utf-8")
            (attempt_root / "stderr.log").write_text(stderr, encoding="utf-8")
            trajectory, terminal_error = _native_termination(runtime, settings, invocation)
            record = {
                "tool_profile": settings.tool_profile,
                "tool_registration": invocation.get("tool_registration", {}),
                "attempt": attempt_number,
                "status": trajectory,
                "returncode": invocation.get("returncode"),
                "timed_out": bool(invocation.get("timed_out")),
                "controlled_stop": bool(invocation.get("controlled_stop")),
                "controlled_stop_reason": invocation.get("controlled_stop_reason"),
                "duration_seconds": invocation.get("duration_seconds"),
                "event_count": len(invocation.get("events", [])),
                "protocol_bridge": invocation.get("protocol_bridge", {}),
                "execution_limits": invocation.get("execution_limits", {}),
                "command": _redacted_command(command, settings.api_key),
                "successful_actions": runtime.successful_action_count,
            }
            attempts.append(record)
            selected = (runtime, runtime_dir, public, invocation, trajectory, command, terminal_error)
            if trajectory != "infrastructure_failure" or attempt_number >= settings.retries:
                break
            runtime.finish(_final_text(invocation.get("events", []), invocation.get("metadata", {})),
                           inspected_native_images(invocation.get("events", []), workspace), "infrastructure_failure")
            runtime.close()
            # Baseline infrastructure retries restart immediately from a fresh fixture.

    assert selected is not None
    runtime, runtime_dir, public, invocation, trajectory, command, terminal_error = selected
    trace_path = run_root / "traces" / handle.user_id / f"{handle.task_name}.json"
    write_json(trace_path, _redact_value({
        "events": invocation.get("events", []),
        "metadata": invocation.get("metadata", {}),
        "attempts": attempts,
        "adapter": runtime.diagnostics(),
    }, settings.api_key))
    try:
        return _persist_terminal(
            handle=handle,
            benchmark_root=benchmark_root,
            run_root=run_root,
            run_id=run_id,
            settings=settings,
            task_root=task_root,
            workspace=workspace,
            runtime=runtime,
            runtime_dir=runtime_dir,
            public=public,
            invocation=invocation,
            attempts=attempts,
            trajectory_class=trajectory,
            terminal_error=terminal_error,
            started_at=started_at,
            started_monotonic=started_monotonic,
            command=command,
        )
    except Exception as exc:
        return _early_failure(handle, run_root, started_at, started_monotonic, f"artifact adapter: {type(exc).__name__}: {exc}", benchmark_root=benchmark_root, settings=settings)


def _early_failure(
    handle: TaskHandle,
    run_root: Path,
    started_at: str,
    started_monotonic: float,
    message: str,
    *,
    benchmark_root: Path | None = None,
    settings: ClaudeSettings | None = None,
) -> dict[str, Any]:
    from evaluation.camact_eval.schema import StandardRunArtifact

    duration = round(time.monotonic() - started_monotonic, 3)
    provenance = benchmark_provenance(benchmark_root) if benchmark_root is not None else {}
    requested_model = str(settings.model).strip() if settings is not None else ""
    policy = model_policy(
        requested_model=requested_model,
        primary_model=requested_model,
        small_fast_model=requested_model,
        subagent_model=requested_model,
        fallback_model=requested_model,
        utility_model=requested_model,
        configured_model=requested_model,
        aliases=getattr(settings, "model_aliases", {}) if settings is not None else {},
        configured_entrypoints=getattr(settings, "configured_entrypoints", {}) if settings is not None else {},
        enforce=True,
    )
    artifact = StandardRunArtifact(
        user_id=handle.user_id,
        task_id=handle.task_id,
        task=f"{handle.user_id}/{handle.task_name}",
        run={
            "run_id": run_root.name,
            "trial": 1,
            "protocol_version": "claude-code-native",
            "tool_profile": settings.tool_profile if settings else "native",
            "benchmark_release_id": provenance.get("benchmark_release_id"),
            "benchmark_release_version": provenance.get("benchmark_release_version"),
            "benchmark_manifest_sha256": provenance.get("benchmark_manifest_sha256"),
        },
        method="claude_code_native",
        model=(
            {
                "name": requested_model,
                "requested_model": requested_model,
                "configured_model": requested_model,
                "provider": settings.provider,
                "base_url": settings.public_dict().get("base_url"),
            }
            if settings is not None
            else {}
        ),
        model_policy=policy,
        final_response="",
        evidence=[],
        tool_calls=[],
        actions=[],
        final_state={},
        simulator={"status": "not_recorded"},
        errors={"infrastructure": [{"message": message}]},
        token_usage={},
        model_calls=[],
        timing={"started_at": started_at, "ended_at": utc_now(), "duration_seconds": duration},
        diagnostics={
            "native_tools": list(NATIVE_TOOLS),
            "tool_profile": settings.tool_profile if settings else "native",
            "benchmark_tools_registered_with_claude": [],
            "model_policy": policy,
            "failure_source": "pre_terminal_native_runner",
        },
        trajectory_class="infrastructure_failure",
    )
    artifact_path = run_root / "artifacts" / handle.user_id / f"{handle.task_name}.json"
    artifact.write(artifact_path)
    return {
        "user_id": handle.user_id,
        "task": handle.task_name,
        "task_id": handle.task_id,
        "status": "infrastructure_failure",
        "tool_profile": settings.tool_profile if settings else "native",
        "trajectory_class": "infrastructure_failure",
        "artifact_path": str(artifact_path),
        "error": message,
        "duration_seconds": duration,
    }


def run_tasks(handles: list[TaskHandle], *, benchmark_root: Path, run_root: Path, run_id: str, settings: ClaudeSettings, resume: bool = False) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    lock = threading.Lock()
    results_path = run_root / "task_results.jsonl"
    with ThreadPoolExecutor(max_workers=settings.parallel, thread_name_prefix="claude-code-native") as pool:
        futures = {
            pool.submit(run_task, handle, benchmark_root=benchmark_root, run_root=run_root, run_id=run_id, settings=settings, resume=resume): handle
            for handle in handles
        }
        for future in as_completed(futures):
            handle = futures[future]
            try:
                item = future.result()
            except Exception as exc:
                item = _early_failure(
                    handle,
                    run_root,
                    utc_now(),
                    time.monotonic(),
                    f"runner: {type(exc).__name__}: {exc}",
                    benchmark_root=benchmark_root,
                    settings=settings,
                )
            with lock:
                results.append(item)
                with results_path.open("a", encoding="utf-8") as output:
                    output.write(json.dumps(item, ensure_ascii=False) + "\n")
                write_json(run_root / "logs" / handle.user_id / f"{handle.task_name}.json", item)
            print(json.dumps({"type": "task_finished", **item}, ensure_ascii=False), flush=True)
    return sorted(results, key=lambda item: (str(item.get("user_id")), str(item.get("task"))))


def write_run_manifest(run_root: Path, benchmark_root: Path, settings: ClaudeSettings, handles: list[TaskHandle], cli_arguments: list[str] | None = None) -> None:
    policy = validate_native_model_settings(settings)
    public_settings = settings.public_dict()
    public_settings["allow_bash"] = True
    public_settings["permission_mode"] = "dontAsk (inside bubblewrap)"
    manifest = {
        "schema_version": "camact.claude_code_native_run.v1",
        "run_id": run_root.name,
        "method": "claude_code_native",
        "started_at": utc_now(),
        "secret_persisted": False,
        "architecture": "Claude Code native harness -> Bash thin adapter -> CamAct RuntimeEnvironment -> StandardRunArtifact",
        "native_tools": list(NATIVE_TOOLS),
        "tool_profile": settings.tool_profile,
        "benchmark_tools_registered_with_claude": {f"{h.user_id}/{h.task_name}": registered_tools(task_tools(h)[1], settings.tool_profile)[4:] for h in handles},
        "benchmark_provenance": benchmark_provenance(benchmark_root),
        "model_policy": policy,
        "harness_commit": harness_commit(),
        "task_count": len(handles),
        "tasks": [{"user_id": item.user_id, "task": item.task_name, "task_id": item.task_id} for item in handles],
        "cli_arguments": _redacted_command(cli_arguments or [], settings.api_key),
    }
    write_json(run_root / "run_manifest.json", manifest)
    write_json(run_root / "config.json", {
        **public_settings,
        "benchmark": str(benchmark_root),
        "task_count": len(handles),
        "native_tools": list(NATIVE_TOOLS),
        "sandbox": "bubblewrap",
        "result_json_required": False,
        "api_key": None,
        "api_key_env": None,
        "model_policy": policy,
    })


def finalize_run(run_root: Path, results: list[dict[str, Any]]) -> dict[str, Any]:
    from evaluation.camact_eval.schema import StandardRunArtifact

    rows: list[dict[str, Any]] = []
    bundle_path = run_root / "standard_run_artifacts.jsonl"
    for path in sorted((run_root / "artifacts").glob("*/*.json")):
        artifact = StandardRunArtifact.read(path)
        rows.append(artifact.document_for_path(bundle_path))
    bundle_path.write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in rows),
        encoding="utf-8",
    )
    summary = {
        "schema_version": "camact.claude_code_native_summary.v1",
        "tool_profiles": sorted({row.get("run", {}).get("tool_profile", "native") for row in rows}),
        "run_id": run_root.name,
        "method": "claude_code_native",
        "requested_tasks": len(results),
        "completed_tasks": len(results),
        "successful_tasks": sum(item.get("status") == "success" for item in results),
        "agent_failures": sum(item.get("status") == "agent_failure" for item in results),
        "infrastructure_failures": sum(item.get("status") == "infrastructure_failure" for item in results),
        "standard_artifacts": len(rows),
        "results": results,
        "finished_at": utc_now(),
    }
    write_json(run_root / "summary.json", summary)
    return summary


def audit_run_isolation(run_root: Path) -> dict[str, Any]:
    forbidden = {"ground_truth", "evaluator_config.json", "task_spec.json", "tools.json", "evaluation", "benchmark"}
    violations: list[dict[str, str]] = []
    workspaces = sorted(set((run_root / "tasks").glob("*/task_*/workspace")) | set((run_root / "tasks").glob("*/task_*/attempts/attempt_*/workspace")))
    for workspace in workspaces:
        for path in workspace.rglob("*"):
            relative = path.relative_to(workspace)
            if path.is_symlink():
                violations.append({"workspace": str(workspace), "path": str(relative), "reason": "symlink"})
            if any(part in forbidden for part in relative.parts):
                violations.append({"workspace": str(workspace), "path": str(relative), "reason": "forbidden path"})
        if (workspace / "output" / "result.json").exists() or (workspace / "output" / "result.schema.json").exists():
            violations.append({"workspace": str(workspace), "path": "output/result.json", "reason": "legacy result contract"})
    document = {
        "schema_version": "camact.claude_code_native_isolation_audit.v1",
        "passed": not violations,
        "workspace_count": len(workspaces),
        "violations": violations,
        "checked_at": utc_now(),
    }
    write_json(run_root / "isolation_audit.json", document)
    return document
