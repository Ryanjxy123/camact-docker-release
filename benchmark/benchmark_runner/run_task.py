#!/usr/bin/env python3
"""Run one CamAct task in an isolated, stateful tool environment."""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from evaluator.evaluate import evaluate
from benchmark_runner.mllm_adapter import complete_text, resolve_provider_config
from services.simulator_common import SimulatorInfrastructureError
from services.runtime_environment import (RuntimeEnvironment, agent_task_view, AgentTurnLimit, SimulatorRoundLimit,
                                          DEFAULT_MAX_AGENT_TURNS, DEFAULT_MAX_SIMULATOR_ROUNDS)
from services.task_definition import load_task


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def dump(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def find_task(identifier: str, user_id: str | None = None) -> Path:
    candidates = []
    pattern = f"{user_id}/task_*/task_spec.json" if user_id else "*/task_*/task_spec.json"
    for task_spec in (ROOT / "tasks").glob(pattern):
        task_dir = task_spec.parent
        spec = load(task_spec)
        if task_dir.name == identifier or spec["task_id"] == identifier:
            candidates.append(task_dir)
    if len(candidates) != 1:
        raise SystemExit(f"unknown or ambiguous task: {identifier}")
    return candidates[0]


def public_context(task_dir: Path) -> dict:
    task = load_task(task_dir)
    initial = task.initial_user_message()
    return {
        "task": {"task_id": task.task_id, "task_type": task.task_type,
                 "interaction_type": task.task_type, "user_query": initial["content"]},
        "initial_message": initial,
        "conversation": {"mode": task.task_type, "messages": task.initial_messages()[:-1],
                         "user_simulator_available": task.user_agent_enabled},
        "tools": {tool.name: tool.model_dump(exclude={"name"}) for tool in task.tools},
    }


def make_trajectory(task_dir: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    return (
        Path(os.environ.get("CAMACT_RUN_ROOT", str(ROOT / "runtime" / "trajectories")))
        / task_dir.parent.name
        / task_dir.name
        / f"{stamp}_{uuid4().hex[:8]}"
    )


def attach_user_simulator(environment: RuntimeEnvironment) -> None:
    """Attach the user model lazily; credentials remain in the environment."""
    if not environment.instruction_simulator:
        return
    simulator_config = None

    def generator(system: str, user: str | list[dict[str, str]], seed: int) -> str:
        nonlocal simulator_config
        if simulator_config is None:
            model = os.environ.get("CAMACT_SIMULATOR_MODEL", "").strip()
            api_base = os.environ.get("CAMACT_SIMULATOR_API_BASE", "").strip()
            api_key_env = os.environ.get("CAMACT_SIMULATOR_API_KEY_ENV", "CAMACT_SIMULATOR_API_KEY").strip()
            if not model or not api_base or not api_key_env:
                raise ValueError(
                    "user simulator configuration is missing; set "
                    "CAMACT_SIMULATOR_MODEL, CAMACT_SIMULATOR_API_BASE, "
                    "and CAMACT_SIMULATOR_API_KEY_ENV"
                )
            simulator_config = resolve_provider_config(
                provider=os.environ.get("CAMACT_SIMULATOR_PROVIDER", "relay").strip().casefold(),
                model=model,
                api_base=api_base,
                api_key_env=api_key_env,
                timeout_seconds=60.0,
                max_output_tokens=8192,
            )
        return complete_text(
            simulator_config, system_prompt=system, seed=seed,
            **({"messages": user} if isinstance(user, list) else {"user_prompt": user}),
        )

    environment.simulator_generator = generator


# Historical integrations may import this name; dispatch uses the task policy.
attach_hybrid_simulator = attach_user_simulator


def finalize(
    task_dir: Path,
    environment: RuntimeEnvironment,
    final_response: str,
    evidence: list[str] | None,
) -> dict:
    try:
        submission = environment.build_submission(final_response, evidence)
        state = environment.snapshot(terminal=True)
        # Persist the evidence before grading; grading failures retain the episode.
        dump(environment.session_dir / "submission.json", submission)
        dump(environment.session_dir / "final_state.json", state)
        result = evaluate(task_dir, submission, state)
    finally:
        environment.close()
    trajectory = environment.session_dir
    messages = submission["conversation_trace"]
    dump(trajectory / "submission.json", submission)
    dump(trajectory / "messages.jsonl", messages)
    dump(trajectory / "tool_calls.jsonl", submission["tool_calls"])
    dump(trajectory / "final_state.json", state)
    dump(trajectory / "evaluation.json", result)
    return {
        "type": "finished",
        "trajectory": str(trajectory),
        "evaluation": result,
        "episode": submission,
        "final_state": {key: value for key, value in state.items() if key != "user_simulator"}
        if environment.instruction_simulator else state,
    }


def budget_failure(task_dir: Path, environment: RuntimeEnvironment, exc: RuntimeError, request_id) -> tuple[dict, bool]:
    submission = environment.build_submission("", [])
    dump(environment.session_dir / "submission.json", submission)
    dump(environment.session_dir / "final_state.json", environment.state)
    evaluation = evaluate(task_dir, submission, environment.state)
    dump(environment.session_dir / "evaluation.json", evaluation)
    response = {"type": "agent_failure", "status": "agent_failure", "ok": False,
                "termination_reason": exc.reason, "failure_type": exc.reason, "strict_success": False,
                "trajectory": str(environment.session_dir), "evaluation": evaluation}
    if request_id is not None:
        response["id"] = request_id
    return response, True


def handle_request(
    task_dir: Path, environment: RuntimeEnvironment, request: dict
) -> tuple[dict, bool]:
    operation = request.get("op")
    request_id = request.get("id")
    if operation == "context":
        response = {"type": "context", "context": environment.agent_context()}
    elif operation == "agent_turn":
        # External clients announce each logical generation once, before their
        # provider invocation. Protocol tool requests themselves cost zero turns.
        try:
            response = {"type": "agent_turn", "agent_turns": environment.begin_agent_turn()}
        except AgentTurnLimit as exc:
            return budget_failure(task_dir, environment, exc, request_id)
    elif operation == "tool":
        response = environment.call_tool(
            str(request.get("tool", "")), request.get("arguments", {})
        )
        response["type"] = "tool_result"
    elif operation == "user_message" or (operation == "finish" and environment.instruction_simulator):
        try:
            content = str(request.get("final_response" if operation == "finish" else "content", ""))
            if operation == "finish":
                environment.pending_finish_evidence = list(request.get("evidence", []))
            response = environment.user_message(content)
            if environment.simulator_stopped:
                response = finalize(task_dir, environment, content,
                                    getattr(environment, "pending_finish_evidence", []))
                if request_id is not None:
                    response["id"] = request_id
                return response, True
            response["type"] = "user_message"
        except SimulatorRoundLimit as exc:
            return budget_failure(task_dir, environment, exc, request_id)
        except SimulatorInfrastructureError as exc:
            environment.state["session"]["status"] = "infrastructure_error"
            environment.state["session"]["error"] = f"{type(exc).__name__}: {exc}"
            environment._persist()
            response = {
                "type": "infrastructure_error",
                "component": "user_simulator",
                "ok": False,
                "error": environment.state["session"]["error"],
            }
            return response, True
    elif operation == "finish":
        response = finalize(
            task_dir,
            environment,
            str(request.get("final_response", "")),
            request.get("evidence", []),
        )
        if request_id is not None:
            response["id"] = request_id
        return response, True
    else:
        response = {
            "type": "protocol_error",
            "ok": False,
            "error": f"unknown operation: {operation!r}",
        }
    if request_id is not None:
        response["id"] = request_id
    return response, False


def emit_jsonl(value: dict) -> None:
    print(json.dumps(value, ensure_ascii=False), flush=True)


def run_interactive(task_dir: Path, max_simulator_rounds: int | None = None,
                    max_agent_turns: int = DEFAULT_MAX_AGENT_TURNS) -> int:
    trajectory = make_trajectory(task_dir)
    with RuntimeEnvironment(task_dir, trajectory, max_simulator_rounds=max_simulator_rounds,
                            max_agent_turns=max_agent_turns) as environment:
        attach_user_simulator(environment)
        emit_jsonl(
            {
                "type": "session_started",
                "session_id": environment.session_id,
                "context": environment.agent_context(),
            }
        )
        for raw_line in sys.stdin:
            if not raw_line.strip():
                continue
            try:
                request = json.loads(raw_line)
                if not isinstance(request, dict):
                    raise ValueError("request must be a JSON object")
                response, finished = handle_request(task_dir, environment, request)
            except Exception as exc:
                response = {
                    "type": "protocol_error",
                    "ok": False,
                    "error": f"{type(exc).__name__}: {exc}",
                }
                # A finalization error must not reopen a conversation the user ended.
                finished = environment.simulator_stopped
                if finished:
                    environment.state["session"]["status"] = "error"
                    environment.state["session"]["error"] = response["error"]
                    environment._persist()
            emit_jsonl(response)
            if response.get("type") == "infrastructure_error":
                return 3
            if finished:
                return 2 if response.get("type") == "protocol_error" else 0
        environment.state["session"]["status"] = "abandoned"
        environment._persist()
        return 2


def load_script(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8")
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        value = [json.loads(line) for line in text.splitlines() if line.strip()]
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise SystemExit("script must be a JSON array or JSONL sequence of requests")
    return value


def run_script(task_dir: Path, script_path: Path, max_simulator_rounds: int | None = None,
               max_agent_turns: int = DEFAULT_MAX_AGENT_TURNS) -> int:
    with RuntimeEnvironment(task_dir, make_trajectory(task_dir), max_simulator_rounds=max_simulator_rounds,
                            max_agent_turns=max_agent_turns) as environment:
        attach_user_simulator(environment)
        responses = []
        finished = False
        for request in load_script(script_path):
            response, finished = handle_request(task_dir, environment, request)
            responses.append(response)
            if response.get("type") == "infrastructure_error":
                print(json.dumps({"responses": responses}, ensure_ascii=False, indent=2))
                return 3
            if finished:
                break
        if not finished:
            raise SystemExit("script must end with a finish operation")
        print(json.dumps({"responses": responses}, ensure_ascii=False, indent=2))
        return 0


def run_legacy_submission(task_dir: Path, submission_path: Path) -> int:
    """Execute old artifacts through the runtime instead of replaying state."""
    legacy = load(submission_path)
    with RuntimeEnvironment(task_dir, make_trajectory(task_dir)) as environment:
        attach_user_simulator(environment)
        seen_calls: set[str] = set()
        for call in legacy.get("tool_calls", []) + legacy.get("actions", []):
            if isinstance(call, dict):
                signature = json.dumps(call, ensure_ascii=False, sort_keys=True)
                if signature in seen_calls:
                    continue
                seen_calls.add(signature)
                environment.call_tool(call.get("tool", ""), call.get("arguments", {}))
        for message in legacy.get("conversation_trace", []):
            if isinstance(message, dict):
                environment.conversation_trace.append(message)
        response = finalize(
            task_dir,
            environment,
            str(legacy.get("final_response", "")),
            legacy.get("evidence", []),
        )
        response["compatibility_mode"] = "legacy_submission_executed_in_runtime"
        print(json.dumps(response, ensure_ascii=False, indent=2))
        return 0


def dry_run(task_dir: Path) -> int:
    with tempfile.TemporaryDirectory(prefix=f"camact-{task_dir.name}-") as temp:
        with RuntimeEnvironment(task_dir, Path(temp) / "trial") as environment:
            context = environment.agent_context()
            environment.close()
        print(
            json.dumps(
                {
                    "task": task_dir.name,
                    "materialized": True,
                    "declared_tools": sorted(context["tools"]),
                },
                ensure_ascii=False,
            )
        )
        return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", required=True, help="task_001 or canonical task id")
    parser.add_argument("--user-id", help="Required for short task names in a multi-user benchmark")
    parser.add_argument("--max-agent-turns", "--max-steps", dest="max_agent_turns", type=int, default=DEFAULT_MAX_AGENT_TURNS)
    parser.add_argument("--max-simulator-rounds", "--max-simulator-turns", dest="max_simulator_rounds", type=int, default=None)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--interactive", action="store_true", help="run JSONL agent/tool loop")
    mode.add_argument("--script", type=Path, help="execute a JSON/JSONL protocol script")
    mode.add_argument("--submission", type=Path, help="execute a legacy submission")
    mode.add_argument("--emit-context", action="store_true")
    mode.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    task_dir = find_task(args.task, args.user_id)
    if args.emit_context:
        print(json.dumps(public_context(task_dir), ensure_ascii=False, indent=2))
        return 0
    if args.interactive:
        return run_interactive(task_dir, args.max_simulator_rounds, args.max_agent_turns)
    if args.script:
        return run_script(task_dir, args.script, args.max_simulator_rounds, args.max_agent_turns)
    if args.submission:
        return run_legacy_submission(task_dir, args.submission)
    if args.dry_run:
        return dry_run(task_dir)
    raise SystemExit("choose --interactive, --script, --submission, --emit-context, or --dry-run")


if __name__ == "__main__":
    raise SystemExit(main())
