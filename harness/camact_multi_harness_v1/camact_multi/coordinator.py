"""Single-task coordinator: shared runtime -> official CLI -> external artifact."""
from __future__ import annotations
import json
import os
from pathlib import Path
import signal
import subprocess
import time
from contextlib import nullcontext
from claude_code_harness.core import ClaudeSettings, task_handles, write_json, utc_now
from . import PROJECT
from .config import provider_ready
from .drivers import prepare, parse_events, final_text, terminal_error, native_session_id, resume_command
from .session import RuntimeSession, workspace, export_artifact
from .sandbox import command as sandbox_command
from .transport import Transport, redact
from harness.camact_token_usage_v1.integration import track_official

def invoke(command, env, timeout, *, umask=-1, stop_condition=None, stdin=None):
    started_at = utc_now()
    p = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         stdin=stdin, text=True, start_new_session=True, umask=umask)
    timed_out = False
    simulator_stop = False
    controlled_stop = False
    try:
        if stop_condition is None:
            stdout, stderr = p.communicate(timeout=timeout)
        else:
            deadline = time.monotonic() + timeout
            while True:
                if stop_condition():
                    simulator_stop = True
                    if p.poll() is None:
                        os.killpg(p.pid, signal.SIGTERM)
                        controlled_stop = True
                    try:
                        stdout, stderr = p.communicate(timeout=2)
                    except subprocess.TimeoutExpired:
                        os.killpg(p.pid, signal.SIGKILL)
                        stdout, stderr = p.communicate()
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                try:
                    stdout, stderr = p.communicate(timeout=min(.05, remaining))
                    break
                except subprocess.TimeoutExpired:
                    continue
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(p.pid, signal.SIGKILL)
        stdout, stderr = p.communicate()
    except BaseException:
        # Interrupting the coordinator must also reap its task's process group.
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGTERM)
            try:
                p.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.communicate()
        raise
    # The CLI may emit a terminal event and exit inside the same poll that
    # delivered ask_user. Preserve the Runtime fact even without a kill.
    if not timed_out and stop_condition is not None and stop_condition():
        simulator_stop = True
    return {"returncode": p.returncode, "timed_out": timed_out, "stdout": stdout, "stderr": stderr,
            "simulator_stop": simulator_stop, "controlled_stop": controlled_stop,
            "started_at": started_at, "ended_at": utc_now(),
            "pid": p.pid, "process_reaped": p.poll() is not None}


def invoke_turns(session, name, entry, argv, env, public_workspace, live_home, relay,
                 output, limits, started, *, storage=None, secrets=()):
    """Deliver Simulator replies to the same official Session until real STOP.

    Runtime, provider relay, HOME and all budgets live outside this loop. Each
    invocation is still the unmodified official agent/tool loop.
    """
    from harness.camact_compatibility_v2.multiturn import advance_native_turn
    from harness.camact_compatibility_v2.terminal import classify_native, last_provider_attempt_failed
    from benchmark.services.runtime_environment import AgentTurnLimit
    events, turns, stdout, stderr = [], [], [], []
    current = list(argv)
    identity = None
    answer, error, trajectory = "", None, "finished"
    last = {"returncode": -127, "timed_out": False}
    opencode_terminal = None
    deadline = started + limits.get("task_timeout_seconds", 1800)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                last.update(returncode=-124, timed_out=True)
                raise TimeoutError("Native task watchdog expired before continuation")
            if session.environment.agent_turns >= session.environment.max_agent_turns:
                session.environment._budget_limit(AgentTurnLimit)
            command = sandbox_command(current, public_workspace, live_home, entry, relay.path)
            native_offset = len(storage.events) if storage else 0
            if getattr(relay, "token_collector", None):
                relay.token_collector.update_context(agent_turn_id=len(turns) + 1, session_id=identity)
            if name == "opencode":
                from . import opencode_runtime
                before = opencode_runtime.checkpoint(live_home)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Native task watchdog expired during Session checkpoint")
            last = invoke(command, env, remaining, umask=0o077 if storage else -1,
                stop_condition=lambda: session.environment.simulator_stopped or bool(relay.stop_reason),
                stdin=subprocess.DEVNULL if name in {"opencode", "deepseek"} else None)
            clean_stdout = redact(last["stdout"], secrets)
            clean_stderr = redact(last["stderr"], secrets)
            stdout.append(clean_stdout); stderr.append(clean_stderr)
            turn_events = parse_events(name, clean_stdout)
            new_native = []
            if storage:
                storage.collect()
                new_native = storage.events[native_offset:]
                turn_events.extend(new_native)
            events.extend(turn_events)
            answer = final_text(name, turn_events)
            if name == "openclaw" and storage and not answer:
                from .openclaw_runtime import session_final_text
                answer = session_final_text(new_native)
            official_id = native_session_id(name, turn_events, current)
            if identity and official_id and identity != official_id:
                raise RuntimeError("Official continuation returned a different native session identity")
            identity = identity or official_id
            if name == "opencode":
                opencode_terminal = opencode_runtime.collect(live_home, session_id=identity,
                    before=before, prompt=current[-1], events=turn_events,
                    model=entry["provider"]["model"], version=entry.get("version"))
                answer = opencode_runtime.final_text(opencode_terminal) or answer
            if getattr(relay, "token_collector", None):
                relay.token_collector.bind_session(len(turns) + 1, identity)
                relay.token_collector.attach_native_events(turn_events)
            turn_error = (f"Official CLI exit={last['returncode']}; timeout={last['timed_out']}"
                          if last["returncode"] or last["timed_out"] else terminal_error(name, turn_events))
            if not turn_events:
                turn_error = turn_error or "No native events were emitted"
            if name == "deepseek" and storage and not storage.offsets:
                turn_error = turn_error or "No durable dsh Session log was emitted; native continuation is unavailable"
            if name == "deepseek" and storage and storage.errors:
                turn_error = turn_error or "dsh Session capture failed: " + "; ".join(storage.errors)
            native_capture = {**relay.summary(), "native_process": {
                "returncode": last["returncode"], "timed_out": last["timed_out"],
                "simulator_stop": last.get("simulator_stop", False),
                **({"controlled_stop": last["controlled_stop"]} if "controlled_stop" in last else {})}}
            if name == "deepseek" and storage:
                # Durable capture faults are infrastructure evidence in their
                # own right; do not let an official output-budget event hide
                # a corrupt or absent Session log behind exit code 1.
                native_capture["native_session_capture_errors"] = list(storage.errors)
                if not storage.offsets:
                    native_capture["native_session_capture_errors"].append("missing_durable_session")
            if name == "opencode":
                native_capture["opencode_terminal"] = opencode_terminal
            if (last.get("simulator_stop") and session.environment.simulator_stopped and
                    native_capture.get("stop_reason") is None):
                native_capture["stop_reason"] = "simulator_stop"
            trajectory, error = classify_native(session,
                requested="infrastructure_failure" if turn_error else "finished",
                error=turn_error, capture=native_capture, events=turn_events, native_harness=name)
            relay_state = relay.summary()
            if (session.environment.simulator_stopped and not session.infrastructure_error and
                    session.environment.state["session"].get("status") != "agent_failure" and
                    relay_state.get("stop_reason") in {None, "simulator_stop"} and
                    trajectory == "finished" and
                    not last_provider_attempt_failed(relay_state.get("requests")) and (
                    last.get("simulator_stop") or relay_state.get("stop_reason") == "simulator_stop")):
                relay.stop_reason = "simulator_stop"
                trajectory, error = "finished", None
                if not answer:
                    answer = next((row["content"] for row in reversed(session.environment.conversation_trace)
                                   if row.get("role") == "assistant"), "")
            if last["timed_out"]:
                relay.stop_reason = "task_timeout"
                trajectory, error = "infrastructure_failure", turn_error
            if time.monotonic() >= deadline:
                last["timed_out"] = True
                raise TimeoutError("Native task watchdog expired before Simulator delivery")
            decision = advance_native_turn(session, answer, trajectory)
            if time.monotonic() >= deadline:
                last["timed_out"] = True
                raise TimeoutError("Native task watchdog expired during Simulator delivery")
            turn_root = output / "native_turns" / f"turn_{len(turns) + 1:03d}"
            turn_root.mkdir(parents=True, exist_ok=False)
            (turn_root / "stdout.log").write_text(clean_stdout, encoding="utf-8")
            (turn_root / "stderr.log").write_text(clean_stderr, encoding="utf-8")
            write_json(turn_root / "events.json", turn_events)
            if name == "opencode":
                write_json(turn_root / "opencode-terminal.json", opencode_terminal)
            turn = {"turn": len(turns) + 1, "native_session_id": identity,
                    "argv": current, "returncode": last["returncode"], "timed_out": last["timed_out"],
                    "started_at": last["started_at"], "ended_at": last["ended_at"],
                    "agent_generations": session.environment.agent_turns,
                    "simulator_rounds": session.environment.simulator_rounds,
                    "simulator_stopped": session.environment.simulator_stopped, "decision": decision}
            turns.append(turn)
            write_json(turn_root / "turn.json", turn)
            if decision["action"] == "resume":
                current = resume_command(name, current, identity, decision["message"])
                continue
            if decision["action"] in {"agent_failure", "infrastructure_failure"}:
                trajectory, error = decision["action"], error or decision.get("reason")
            break
    except AgentTurnLimit as exc:
        trajectory, error = "agent_failure", str(exc)
    except Exception as exc:
        if isinstance(exc, TimeoutError):
            relay.stop_reason = "task_timeout"
        trajectory, error = "infrastructure_failure", redact(f"Native continuation: {type(exc).__name__}: {exc}", secrets)
    if trajectory == "infrastructure_failure":
        # Prior completed turns must not mask a failed continuation or Simulator.
        session.infrastructure_error = error or "Native continuation failed"
    elif trajectory == "agent_failure":
        session.environment.state["session"].update(status="agent_failure", failure_type=error,
            termination_reason=error, strict_success=False)
        session.environment._persist()
    return {**last, "stdout": "\n".join(stdout), "stderr": "\n".join(stderr), "events": events,
            "final_response": answer, "trajectory_class": trajectory, "stop_error": error,
            "native_turns": turns, "native_session_id": identity,
            **({"opencode_terminal": opencode_terminal} if name == "opencode" else {})}

def simulator(config, log_dir, *, deadline=None):
    if not config:
        return None
    from harness.camact_compatibility_v2.roles import role_provider, provider_config
    from benchmark.benchmark_runner.mllm_adapter import complete_text
    role = role_provider(config, role="simulator", protocol="openai-chat")
    from dataclasses import replace
    provider = replace(provider_config(role, telemetry_path=str(log_dir / "simulator_attempts.jsonl")), deadline=deadline)
    def generate(system_prompt, user_prompt, seed):
        return complete_text(provider, system_prompt=system_prompt, seed=seed,
                             **({"messages": user_prompt} if isinstance(user_prompt, list) else {"user_prompt": user_prompt}))
    return generate

def execution_limits(config, entry, name=None):
    """Bind supported role budgets to the existing native runtime/relay."""
    limits = dict(config["limits"])
    native_cli_retries = name in {"codex", "opencode", "openclaw", "deepseek"}
    if native_cli_retries and "retry_attempts" in entry["provider"]:
        raise ValueError(f"{name}: retry_attempts is controlled by the official CLI; a uniform outer retry override is unsupported")
    for source, target in (("timeout_seconds", "request_timeout_seconds"),
                           ("max_output_tokens", "max_output_tokens"),
                           ("retry_attempts", "request_attempts")):
        if source in entry["provider"] and not (native_cli_retries and source == "retry_attempts"):
            limits[target] = entry["provider"][source]
    for key, value in limits.items():
        if key.endswith(("seconds", "tokens", "attempts", "turns", "rounds", "requests")) and float(value) <= 0:
            raise ValueError(f"limits.{key} must be positive")
    if native_cli_retries:
        limits["requested_retry_attempts"] = limits.pop("request_attempts", None)
        limits["effective_retry_attempts"] = None
        limits["native_retry_policy"] = "official CLI defaults; outer relay does not retry"
        if name == "openclaw":
            limits["native_retry_policy"] = "official CLI plus bounded relay recovery for pre-response upstream errors"
    limits["requested_max_model_requests"] = limits.pop("max_model_requests", None)
    limits["effective_max_model_requests"] = None
    limits["model_request_limit_policy"] = "successful generation cap; HTTP requests are audit-only"
    return limits

def claude_settings(config, entry):
    """Keep the existing Claude runner, with all three roles bound explicitly."""
    from claude_code_harness.core import load_settings
    from types import SimpleNamespace
    limits = execution_limits(config, entry, name="claude")
    if entry["provider"].get("parameters"):
        raise ValueError("Claude telemetry adapter does not support arbitrary Agent parameters; use its supported budget settings")
    legacy = json.loads(Path(entry["legacy_config"]).read_text()) if entry.get("legacy_config") else {}
    p = entry["provider"]
    args = SimpleNamespace(model=p["model"], base_url=p["base_url"], api_key=None, api_key_env=p["api_key_env"],
        tool_profile="native", distro=config["distro"], allow_bash=False,
        timeout=limits.get("request_timeout_seconds", 600), task_timeout=limits.get("task_timeout_seconds", 1800),
        request_attempts=limits.get("request_attempts", 4), retries=limits.get("infrastructure_attempts", 1),
        agent_request_attempts=limits.get("request_attempts", 4), max_agent_turns=limits.get("max_agent_turns", 50),
        max_simulator_rounds=limits.get("max_simulator_rounds", 10), max_output_tokens=limits.get("max_output_tokens", 2048))
    settings = load_settings(args, {**legacy, "agent_provider": p,
                                   "simulator_provider": config.get("simulator"),
                                   "judge_provider": config.get("judge"),
                                   "token_tracking": config.get("token_tracking", {})})
    settings.executable_path = entry["executable"]
    settings.runtime_roots = entry.get("runtime_roots", [])
    settings.node_executable = entry.get("node_executable")
    settings.sandbox_backend = entry.get("sandbox_backend", "bwrap")
    settings.claude_version = entry["version"]
    return settings

@track_official
def run(config, name, user, task, output):
    entry = config["harnesses"][name]
    provider_ready(name, entry["provider"])
    limits = execution_limits(config, entry, name=name)
    handles = task_handles(Path(config["benchmark_root"]), users=[user], tasks=[task])
    if len(handles) != 1:
        raise ValueError("Exactly one existing task must be selected")
    output.mkdir(parents=True, exist_ok=False)
    handle = handles[0]
    started = time.monotonic()
    started_at = utc_now()
    if name == "claude":
        # Preserve the existing native runner and its provider/model policy.
        from claude_code_harness.native_runner import run_task, finalize_run, write_run_manifest
        settings = claude_settings(config, entry)
        write_run_manifest(output, Path(config["benchmark_root"]), settings, [handle])
        result = run_task(handle, benchmark_root=Path(config["benchmark_root"]), run_root=output,
                          run_id=output.name, settings=settings)
        finalize_run(output, [result])
        return result
    generator = simulator(config.get("simulator", {}), output,
                          deadline=started + limits.get("task_timeout_seconds", 1800))
    from benchmark.services.task_definition import load_task
    if load_task(handle.task_dir).user_agent_enabled and generator is None:
        raise ValueError("This multi_turn task requires a separately configured Simulator provider")
    try:
        session = RuntimeSession(handle, output / "session", Path(config["benchmark_root"]), limits, generator)
    except Exception as exc:
        from .session import export_setup_failure
        keys = [os.environ.get(entry["provider"]["api_key_env"], "")]
        keys.extend(os.environ.get(config.get(role, {}).get("api_key_env", ""), "") for role in ("simulator", "judge"))
        return export_setup_failure(handle, name=name, entry=entry, run_dir=output,
            error=redact(f"Runtime initialization: {type(exc).__name__}: {exc}", keys),
            timing={"started_at": started_at, "ended_at": utc_now(), "duration_seconds": time.monotonic() - started})
    invocation = {"stdout": "", "stderr": "", "returncode": -127, "timed_out": False}
    capture = {}
    error = None
    native_session_events = []
    keys = [os.environ.get(entry["provider"]["api_key_env"], "")]
    keys.extend(os.environ.get(config.get(role, {}).get("api_key_env", ""), "") for role in ("simulator", "judge"))
    try:
        public_workspace = output / "workspace"
        workspace(handle, public_workspace)
        from .openclaw_runtime import OpenClawHome, sandbox_preflight
        storage_context = OpenClawHome(output, [os.environ.get(entry['provider']['api_key_env'],'')],
            backend=entry.get('openclaw_home_backend', 'ext4')) if name == 'openclaw' else nullcontext(None)
        if name == "deepseek":
            from .deepseek_runtime import DeepSeekSessionCapture
            storage_context = DeepSeekSessionCapture(output, keys)
        with storage_context as storage:
            live_home = storage.home if storage else output / 'home'
            argv, env = prepare(name, entry, live_home, limits,
                                prompt=session.environment.task.initial_user_message()["content"])
            if name == "openclaw" and storage:
                (live_home/'.openclaw/openclaw.json').chmod(0o600)
                sandbox_preflight(sandbox_command, public_workspace, storage, entry, output)
            with Transport(session, entry["provider"], output / "capture", limits, harness_name=name) as relay:
                relay.deadline = started + limits.get("task_timeout_seconds", 1800)
                command = sandbox_command(argv, public_workspace, live_home, entry, relay.path)
                write_json(output / "launch.json", {"argv": command, "environment_keys": sorted(env),
                                                    "executable": entry["executable"], "version": entry["version"],
                                                    "effective_limits": limits})
                invocation = invoke_turns(session, name, entry, argv, env, public_workspace, live_home,
                    relay, output, limits, started, storage=storage, secrets=keys)
                capture = relay.summary()
                capture["native_turns"] = invocation["native_turns"]
                capture["native_process"] = {k: invocation.get(k) for k in
                    ("returncode", "timed_out", "simulator_stop", "controlled_stop")}
                if name == "opencode":
                    capture["opencode_terminal"] = invocation.get("opencode_terminal")
        if storage:
            native_session_events = storage.events
            capture['native_session_capture'] = {'events':len(storage.events),'errors':storage.errors,
                                               'source':'incremental official session JSONL'}
        write_json(output / 'invocation.json', {k:v for k,v in invocation.items() if k not in {'stdout','stderr'}})
        error = invocation.get("stop_error")
        if not error and (invocation["timed_out"] or invocation["returncode"]):
            error = f"Official CLI exit={invocation['returncode']}; timeout={invocation['timed_out']}"
        if session.infrastructure_error:
            error = session.infrastructure_error
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        # Setup/capture/cleanup exceptions are real infrastructure evidence,
        # even if an earlier official event recorded an Agent budget terminal.
        session.infrastructure_error = redact(error, keys)
    keys = [os.environ.get(entry["provider"]["api_key_env"], "")]
    keys.extend(os.environ.get(config.get(role, {}).get("api_key_env", ""), "") for role in ("simulator", "judge"))
    for key in ("stdout", "stderr"):
        invocation[key] = redact(invocation[key], keys)
        (output / (key + ".log")).write_text(invocation[key])
    if name in {'openclaw', 'deepseek'} and (output/'native-session-events.jsonl').exists():
        native_session_events = [json.loads(line) for line in (output/'native-session-events.jsonl').read_text().splitlines()]
    events = invocation.get("events", parse_events(name, invocation["stdout"]))
    if name in {'openclaw', 'deepseek'} and "events" not in invocation:
        events.extend(native_session_events)
    error = error or terminal_error(name, events)
    answer = invocation.get("final_response", final_text(name, events))
    if name == 'openclaw' and not answer:
        from .openclaw_runtime import session_final_text
        answer = session_final_text(native_session_events)
    # A process that never emitted events is a broken integration, not success.
    if not events:
        error = error or "No native events were emitted"
    write_json(output / "native-events.json", events)
    native_sessions = [str(p.relative_to(output)) for p in (output / "home").rglob("*")
                       if p.is_file() and ("session" in str(p) or p.suffix == ".jsonl")]
    capture["native_session_files"] = native_sessions
    capture["effective_limits"] = limits
    artifact = export_artifact(session, name=name, entry=entry, run_id=output.name,
        final_text=answer, events=events, run_dir=output,
        trajectory_class=invocation.get("trajectory_class", "infrastructure_failure" if error else "finished"), error=redact(error, keys) if error else None,
        timing={"started_at": started_at, "ended_at": utc_now(), "duration_seconds": time.monotonic() - started}, capture=capture)
    return {"artifact": str(output / "artifact.json"), "trajectory_class": artifact.trajectory_class,
            "note": "Execution completed does not imply task success; use the existing external evaluator"}
