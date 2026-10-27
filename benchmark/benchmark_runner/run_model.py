#!/usr/bin/env python3
"""Run one CamAct task with a real multimodal model and runtime tool loop."""
from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from benchmark_runner.mllm_adapter import (  # noqa: E402
    ModelTurn,
    ProviderInfrastructureError,
    complete_text,
    create_adapter,
    resolve_provider_config,
)
from benchmark_runner.clarification_guard import (  # noqa: E402
    ClarificationGuardTermination,
    ClarificationLoopGuard,
)
from benchmark_runner.run_task import finalize, find_task, make_trajectory  # noqa: E402
from services.tool_schema import argument_schema as _argument_schema, input_schema
from services.task_definition import ToolSpec
from benchmark_runner.system_prompt import build_system_prompt, prompt_config_for_task, append_public_suffix
from services.runtime_environment import (RuntimeEnvironment, AgentTurnLimit, SimulatorRoundLimit,
                                         DEFAULT_MAX_AGENT_TURNS, DEFAULT_MAX_SIMULATOR_ROUNDS)  # noqa: E402
from services.simulator_common import SimulatorInfrastructureError
from services.service_manager import ServiceInfrastructureError  # noqa: E402


TOOL_DESCRIPTIONS = {
    "album_search": "Search the real album by natural metadata such as location or date text. Returns image IDs and basic metadata, never captions.",
    "album_get_metadata": "Get basic date/location metadata for one raw album image.",
    "inspect_image": "View the raw image as a multimodal observation. Compatibility alias for image_view.",
    "image_view": "View one raw album image. The observation contains the actual image, not a caption.",
    "people_search": "Search the user's known people memory by display name or relation-to-owner. Returns an opaque person_A-style reference ID and does not identify people inside album images.",
    "person_view_reference": "View the real reference portrait for a known person using the opaque ID returned by people_search so you can visually compare it with album images.",
    "relationship_lookup": "Read one explicit relation-to-owner fact using the opaque ID returned by people_search.",
    "owner_profile_view": "View the album owner's identity reference and real profile image. Does not identify the owner in album photos.",
    "contacts_search": "Search contacts available in the current task environment.",
    "message_send": "Send a real runtime message and persist it in final state.",
    "calendar_search": "Read runtime calendar events on a date.",
    "calendar_get_availability": "Check the runtime calendar for conflicts in an interval.",
    "calendar_create_event": "Create and persist a calendar event in runtime state.",
    "publish_post": "Create and persist a publishing draft with explicit visibility.",
    "workspace_write": "Write and persist a task artifact with explicit image references.",
}


def runtime_tool_definitions(declared: dict[str, dict[str, Any]], *, user_simulator_available: bool = True) -> list[dict[str, Any]]:
    # Retain the keyword for existing method hooks; interaction is implicit and
    # no longer changes the model-visible tool set.
    del user_simulator_available
    tools = []
    for name, definition in declared.items():
        parameters = input_schema(definition)
        tools.append(
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": definition.get("description")
                    or TOOL_DESCRIPTIONS.get(name, f"Call runtime tool {name}."),
                    "parameters": parameters,
                },
            }
        )
    tools.extend(
        [
            {
                "type": "function",
                "function": {
                    "name": "finish",
                    "description": "Finish only after required state mutations succeed. Evidence must list the raw album image IDs you intentionally selected.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "final_response": {"type": "string"},
                            "evidence": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                        },
                        "required": ["final_response", "evidence"],
                        "additionalProperties": False,
                    },
                },
            },
        ]
    )
    return tools


def system_prompt(plan: dict[str, Any] | None = None, *, task_dir: Path,
                  tools: list[dict[str, Any]], system_prompt_suffix: str = "") -> str:
    # Retain the method-hook argument without injecting planner/private context.
    # Render the exact same merged declarations passed to every provider.
    specs = [ToolSpec(name=item["function"]["name"],
                      description=item["function"].get("description", ""),
                      input_schema=item["function"]["parameters"]) for item in tools]
    prompt = build_system_prompt(specs, prompt_config_for_task(task_dir))
    # Claw-Eval loop.py: append only the explicit public suffix; no interpolation.
    return append_public_suffix(prompt, system_prompt_suffix)


def _text_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(_text_value(item) for item in value)
    if isinstance(value, dict):
        return _text_value(value.get("text", value.get("content", "")))
    return ""


def _aep_context(environment: RuntimeEnvironment) -> tuple[str, list[dict[str, Any]]]:
    """Project only ordinary user-visible text into AEP (never task/private fields)."""
    query = _text_value(environment.initial_message.get("content", "")).strip()
    conversation = []
    for message in environment.history.get("messages", []):
        if isinstance(message, dict):
            text = _text_value(message.get("content", "")).strip()
            if text:
                conversation.append({"role": str(message.get("role", "user")), "content": text})
    return query, conversation


def _aep_request_context(query: str, conversation: list[dict[str, Any]]) -> str:
    if not conversation:
        return query
    turns = "\n".join(
        f"{message.get('role', 'user')}: {message.get('content', '')}"
        for message in conversation
    )
    return f"{query}\nConversation context:\n{turns}"


def _aep_candidates(response: dict[str, Any]) -> list[dict[str, Any]]:
    result = response.get("result", {}) if isinstance(response, dict) else {}
    photos = result.get("photos", []) if isinstance(result, dict) else []
    return [photo for photo in photos if isinstance(photo, dict) and (photo.get("image") or photo.get("image_id"))]


def _image_argument_keys(tool_definition: dict[str, Any], arguments: dict[str, Any]) -> list[str]:
    """Find image-list arguments from the public tool schema, not tool-name rules."""
    declared = tool_definition.get("arguments", {}) if isinstance(tool_definition, dict) else {}
    if not declared and isinstance(tool_definition, dict):
        declared = {key: schema.get("description", "")
                    for key, schema in tool_definition.get("input_schema", {}).get("properties", {}).items()}
    return [
        key
        for key, description in declared.items()
        if isinstance(arguments.get(key), list)
        and "list[raw image filename]" in str(description).casefold()
    ]


def _bind_aep_selection(
    aep: AlbumEvidencePlanner,
    query: str,
    tool_name: str,
    tool_definition: dict[str, Any],
    arguments: dict[str, Any],
) -> tuple[dict[str, Any], list[str] | None, bool]:
    bound = copy.deepcopy(arguments)
    keys = _image_argument_keys(tool_definition, bound)
    if not keys:
        return bound, None, False
    baseline_images = list(dict.fromkeys(
        str(image)
        for key in keys
        for image in bound.get(key, [])
        if str(image).strip()
    ))
    if not baseline_images:
        return bound, None, False
    selection = aep.select_for_action(query, tool_name, baseline_images)
    selected = list(selection.image_ids)
    # Identity claims are image-bound structured arguments. AEP cannot safely
    # transfer a claim to a different image, so retain the complete Baseline call.
    if selected != baseline_images and arguments.get("identity_claims"):
        return copy.deepcopy(arguments), baseline_images, True
    for key in keys:
        bound[key] = selected
    return bound, selected, selection.used_fallback


def _replace_assistant_arguments(assistant: dict[str, Any], call_id: str, arguments: dict[str, Any]) -> None:
    for call in assistant.get("tool_calls", []):
        if call.get("id") == call_id:
            call["arguments"] = copy.deepcopy(arguments)
            return


def initial_history(environment: RuntimeEnvironment) -> list[dict[str, Any]]:
    return [
        {"role": message["role"], "content": [{"type": "text", "text": message["content"]}]}
        for message in environment.initial_messages()
    ]


def _assistant_item(turn: ModelTurn) -> dict[str, Any]:
    return {
        "role": "assistant",
        "text": turn.text,
        "tool_calls": [
            {"id": call.id, "name": call.name, "arguments": call.arguments}
            for call in turn.tool_calls
        ],
    }


def _safe_tool_result(response: dict[str, Any]) -> dict[str, Any]:
    return {key: copy.deepcopy(value) for key, value in response.items() if key != "content"}


def _visual_content_blocks(response: dict[str, Any]) -> list[dict[str, Any]]:
    content = response.get("content", [])
    if not isinstance(content, list):
        return []
    return [copy.deepcopy(block) for block in content if isinstance(block, dict)]


def _write_trace(path: Path, trace: list[dict[str, Any]]) -> None:
    path.write_text(
        json.dumps(trace, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def _agent_failure_result(
    environment: RuntimeEnvironment,
    guard: ClarificationLoopGuard,
    *,
    reason: str,
    provider: str,
    model: str,
    step: int,
    image_views: int,
) -> dict[str, Any]:
    session = environment.state["session"]
    session.update(
        {
            "status": "agent_failure",
            "termination_reason": reason,
            "strict_success": False,
            "clarification_guard": guard.snapshot(),
        }
    )
    environment._persist()
    submission = environment.build_submission("", [])
    (environment.session_dir / "submission.json").write_text(json.dumps(submission, ensure_ascii=False, indent=2), encoding="utf-8")
    (environment.session_dir / "final_state.json").write_text(json.dumps(environment.state, ensure_ascii=False, indent=2), encoding="utf-8")
    from evaluator.evaluate import evaluate
    evaluation = evaluate(environment.task_dir, submission, environment.state)
    (environment.session_dir / "evaluation.json").write_text(json.dumps(evaluation, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "type": "agent_failure",
        "status": "agent_failure",
        "trajectory": str(environment.session_dir),
        "termination_reason": reason,
        "failure_type": reason,
        "strict_success": False,
        "clarification_guard": guard.snapshot(),
        "episode": submission,
        "evaluation": evaluation,
        "model": {
            "provider": provider,
            "model": model,
            "steps": environment.agent_turns,
            "agent_turns": environment.agent_turns,
            "simulator_rounds": environment.simulator_rounds,
            "image_views": image_views,
        },
    }


def run_agent(args: argparse.Namespace) -> int:
    task_dir = find_task(args.task, args.user_id)
    session_dir = (
        Path(args.session_dir).resolve()
        if args.session_dir
        else make_trajectory(task_dir)
    )
    max_agent_turns = getattr(args, "max_agent_turns", None)
    if max_agent_turns is None:
        max_agent_turns = getattr(args, "max_steps", None)
    if max_agent_turns is None:
        max_agent_turns = DEFAULT_MAX_AGENT_TURNS
    max_simulator_rounds = getattr(args, "max_simulator_rounds", None)
    if max_simulator_rounds is None:
        max_simulator_rounds = getattr(args, "max_simulator_turns", None)
    from harness.camact_token_usage_v1.integration import baseline_scope
    with baseline_scope(args, session_dir) as token_collector:
        with RuntimeEnvironment(task_dir, session_dir, max_agent_turns=max_agent_turns,
                                max_simulator_rounds=max_simulator_rounds) as environment:
            result = _run_agent(args, task_dir, session_dir, environment)
            if token_collector:
                token_collector.task_status = environment.state.get("session", {}).get("status", str(result))
                from harness.camact_token_usage_v1.integration import reconcile_baseline
                reconcile_baseline(token_collector, session_dir)
            return result


def _run_agent(args: argparse.Namespace, task_dir: Path, session_dir: Path, environment: RuntimeEnvironment) -> int:
    runtime_timeline = session_dir / "runtime_timeline.jsonl"

    def timeline(component: str, operation: str, started_at: str, started: float, *, status: str, **fields: Any) -> None:
        event = {
            "schema_version": "camact.runtime_timeline.v1",
            "task": f"{args.user_id}/{args.task}",
            "component": component,
            "operation": operation,
            "started_at": started_at,
            "ended_at": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(time.monotonic() - started, 6),
            "status": status,
            **fields,
        }
        runtime_timeline.parent.mkdir(parents=True, exist_ok=True)
        with runtime_timeline.open("a", encoding="utf-8") as output:
            output.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")

    task_key = f"{args.user_id}/{args.task}"
    provider_telemetry = str(session_dir / "provider_attempts.jsonl")
    config = resolve_provider_config(
        provider=args.provider,
        model=args.model,
        api_base=args.api_base,
        api_key_env=args.api_key_env,
        timeout_seconds=args.timeout,
        max_output_tokens=args.max_output_tokens,
        retry_attempts=args.provider_retry_attempts,
        telemetry_path=provider_telemetry,
        task_key=task_key,
    )
    adapter = create_adapter(config)
    aep_mode = getattr(args, "aep_mode", "baseline")
    if aep_mode != "baseline":
        try:
            from methods.album_evidence_planner import AlbumEvidencePlanner, AEPConfig
            from methods.album_evidence_planner.prompts import verification_prompt
        except ModuleNotFoundError:
            raise RuntimeError("Optional Album Evidence Planner is not installed; use --aep-mode baseline") from None
    aep_log_arg = getattr(args, "aep_log", None)
    aep_log = aep_log_arg or (
        str(session_dir / "aep.jsonl") if aep_mode != "baseline" else None
    )
    planner_model = None
    if aep_mode in {"planning", "full"} and getattr(args, "aep_model_planning", False):
        def planner_model(prompt: str) -> str:
            environment.begin_agent_turn()
            turn = adapter.complete(
                system_prompt="You are the Album Evidence Planner. Return the requested JSON only.",
                history=[{"role": "user", "content": [{"type": "text", "text": prompt}]}],
                tools=[],
            )
            return turn.text
    verifier = None
    if aep_mode in {"selection", "full"} and getattr(args, "aep_model_verification", False):
        def verifier(query: str, plan: dict[str, Any], candidate: Any) -> str:
            prompt = verification_prompt(query, plan, candidate.as_dict())
            content: list[dict[str, Any]] = [{"type": "text", "text": prompt}]
            content.extend(copy.deepcopy(getattr(candidate, "visual_content", [])))
            environment.begin_agent_turn()
            turn = adapter.complete(
                system_prompt="You are the Album Evidence Planner visual verifier. Return JSON only.",
                history=[{"role": "user", "content": content}],
                tools=[],
            )
            return turn.text
    aep = AlbumEvidencePlanner(
        AEPConfig.from_mode(aep_mode, log_path=aep_log),
        planner_model=planner_model,
        verifier=verifier,
    ) if aep_mode != "baseline" else None
    aep_query, aep_conversation = _aep_context(environment)
    aep_plan = aep.start(aep_query, aep_conversation) if aep is not None else None
    if environment.instruction_simulator:
        if not args.simulator_model or not args.simulator_api_base or not args.simulator_api_key_env:
            raise SimulatorInfrastructureError(
                "multi_turn requires simulator model, API base and API key environment configuration"
            )
        try:
            simulator_config = resolve_provider_config(
                provider="relay",
                model=args.simulator_model,
                api_base=args.simulator_api_base,
                api_key_env=args.simulator_api_key_env,
                timeout_seconds=args.simulator_timeout,
                max_output_tokens=args.simulator_max_output_tokens,
                retry_attempts=args.simulator_retry_attempts,
                telemetry_path=provider_telemetry,
                task_key=task_key,
            )
        except ValueError:
            raise SimulatorInfrastructureError(
                "invalid or missing simulator model/API configuration; check --simulator-* or CAMACT_SIMULATOR_*"
            ) from None

        def simulator_generator(system: str, user: str | list[dict[str, str]], seed: int) -> str:
            started_at = datetime.now(timezone.utc).isoformat()
            started = time.monotonic()
            try:
                result = complete_text(
                    simulator_config,
                    system_prompt=system,
                    seed=seed,
                    **({"messages": user} if isinstance(user, list) else {"user_prompt": user}),
                )
            except Exception as exc:
                timeline("simulator", "model_call", started_at, started, status="error", exception_type=type(exc).__name__)
                raise
            timeline("simulator", "model_call", started_at, started, status="succeeded")
            return result

        environment.simulator_generator = simulator_generator
    tools = runtime_tool_definitions(environment.tools, user_simulator_available=environment.simulator is not None)
    agent_system_prompt = system_prompt(task_dir=task_dir, tools=tools,
                                        system_prompt_suffix=environment.task.system_prompt_suffix)
    history = initial_history(environment)
    trace: list[dict[str, Any]] = []
    image_views = 0
    stalled_turns = 0
    action_evidence: list[str] = []
    clarification_guard = ClarificationLoopGuard.from_environment(environment)
    current_step = 0
    pending_finish_evidence: list[str] = []

    def check_agent_budget_failure() -> None:
        # Optional AEP helpers can fall back after exceptions; a budget failure
        # must still end the episode before any further action or submission.
        if environment.state["session"].get("termination_reason") == AgentTurnLimit.reason:
            raise AgentTurnLimit(AgentTurnLimit.reason)

    def finish_episode(content: str, evidence: list[str], step: int) -> int:
        result = finalize(task_dir, environment, content, evidence)
        result["model"] = {"provider": config.provider, "model": config.model,
                           "steps": environment.agent_turns, "agent_turns": environment.agent_turns,
                           "simulator_rounds": environment.simulator_rounds, "image_views": image_views}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    def converse(content: str, step: int) -> dict[str, Any]:
        decision = clarification_guard.before_ask(step)
        if decision.action != "call_simulator":
            raise ClarificationGuardTermination(decision.termination_reason or "clarification_limit_exceeded")
        response = environment.user_message(content)
        if not environment.simulator_stopped:
            reason = clarification_guard.after_simulator_response(step, response)
            if reason:
                raise ClarificationGuardTermination(reason)
        return response

    try:
        step = 0
        while True:
            if environment.agent_turns >= environment.max_agent_turns:
                environment._budget_limit(AgentTurnLimit)
            step = environment.agent_turns + 1
            model_started_at = datetime.now(timezone.utc).isoformat()
            model_started = time.monotonic()
            try:
                turn = adapter.complete(
                    system_prompt=agent_system_prompt, history=history, tools=tools
                )
            except Exception as exc:
                timeline("agent_model", "model_call", model_started_at, model_started, status="error", model_turn=step, exception_type=type(exc).__name__)
                raise
            step = environment.begin_agent_turn()
            current_step = step
            timeline("agent_model", "model_call", model_started_at, model_started, status="succeeded", model_turn=step)
            assistant = _assistant_item(turn)
            history.append(assistant)
            trace.append(
                {
                    "step": step,
                    "model_text": turn.text,
                    "tool_calls": assistant["tool_calls"],
                    "usage": turn.usage,
                    "finish_reason": turn.raw_finish_reason,
                }
            )
            _write_trace(environment.session_dir / "model_trace.json", trace)

            if not turn.tool_calls:
                if environment.instruction_simulator and turn.text.strip():
                    response = converse(turn.text, step)
                    if environment.simulator_stopped:
                        return finish_episode(turn.text, action_evidence or pending_finish_evidence, step)
                    history.append({"role": "user", "content": [{"type": "text", "text": response["content"]}]})
                    continue
                if turn.text.strip():
                    return finish_episode(turn.text, action_evidence or pending_finish_evidence, step)
                stalled_turns += 1
                if stalled_turns >= 2:
                    result = _agent_failure_result(
                        environment, clarification_guard,
                        reason="model did not call a tool or finish after two turns",
                        provider=config.provider, model=config.model,
                        step=current_step, image_views=image_views,
                    )
                    print(json.dumps(result, ensure_ascii=False, indent=2))
                    return 0
                history.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": "Continue using the available tools, or call finish when the runtime task is complete.",
                            }
                        ],
                    }
                )
                continue
            stalled_turns = 0
            if turn.text.strip():
                environment.record_assistant_message(turn.text)

            finish_calls = [call for call in turn.tool_calls if call.name == "finish"]
            for call in (call for call in turn.tool_calls if call.name != "finish"):
                call_arguments = copy.deepcopy(call.arguments)
                if aep is not None and aep.config.enable_evidence_selection:
                    call_arguments, action_images, used_fallback = _bind_aep_selection(
                        aep,
                        _aep_request_context(aep_query, aep_conversation),
                        call.name,
                        environment.tools.get(call.name, {}),
                        call_arguments,
                    )
                    check_agent_budget_failure()
                    if action_images is not None:
                        action_evidence.extend(action_images)
                        _replace_assistant_arguments(assistant, call.id, call_arguments)
                        trace.append(
                            {
                                "step": step,
                                "aep_action_binding": call.name,
                                "tool_call_id": call.id,
                                "images": action_images,
                                "used_fallback": used_fallback,
                            }
                        )
                runtime_started_at = datetime.now(timezone.utc).isoformat()
                runtime_started = time.monotonic()
                if call.name in {
                    "image_view",
                    "inspect_image",
                    "person_view_reference",
                    "owner_profile_view",
                }:
                    response = environment.call_tool(call.name, call_arguments)
                    if response.get("ok"):
                        image_views += 1
                else:
                    response = environment.call_tool(call.name, call_arguments)
                timeline(
                    "action" if call.name in {"message_send", "calendar_create_event", "publish_post", "workspace_write"} else "tool",
                    call.name,
                    runtime_started_at,
                    runtime_started,
                    status="succeeded" if response.get("ok") else "error",
                    step=step,
                    tool_call_id=call.id,
                )
                clarification_guard.record_tool_result(step, response)
                if aep is not None and aep.config.enable_evidence_selection:
                    aep.observe_candidates(_aep_candidates(response))
                    if response.get("ok") and call.name in {"image_view", "inspect_image"}:
                        image_id = call_arguments.get("image_id", call_arguments.get("image"))
                        if image_id:
                            aep.observe_candidates([{"image": str(image_id), "visual_content": _visual_content_blocks(response)}])
                            aep.mark_verified(str(image_id))
                history.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.id,
                        "name": call.name,
                        "result": _safe_tool_result(response),
                        "content": _visual_content_blocks(response),
                    }
                )
                trace.append(
                    {
                        "step": step,
                        "tool_call_id": call.id,
                        "tool": call.name,
                        "result": _safe_tool_result(response),
                        "visual_content_blocks": len(_visual_content_blocks(response)),
                    }
                )
                _write_trace(environment.session_dir / "model_trace.json", trace)
            clarification_guard.end_step(step)
            if environment.instruction_simulator:
                # Resolve every finish call before inserting a natural user turn.
                for call in finish_calls:
                    history.append({"role": "tool", "tool_call_id": call.id,
                                    "name": "finish", "result": {}, "content": []})
            if finish_calls:
                finish_call = finish_calls[-1]
                baseline_evidence = list(finish_call.arguments.get("evidence", []))
                selected_evidence = baseline_evidence
                if action_evidence:
                    selected_evidence = list(dict.fromkeys(action_evidence))
                elif aep is not None and aep.config.enable_evidence_selection:
                    selection = aep.select(
                        _aep_request_context(aep_query, aep_conversation),
                        fallback=baseline_evidence,
                        minimum_relevance=aep.config.min_action_relevance,
                    )
                    check_agent_budget_failure()
                    if selection is not None:
                        selected_evidence = list(selection.image_ids)
                final_response = str(finish_call.arguments.get("final_response", turn.text))
                if environment.instruction_simulator:
                    pending_finish_evidence = selected_evidence
                    response = converse(final_response, step)
                    if not environment.simulator_stopped:
                        history.append({"role": "user", "content": [{"type": "text", "text": response["content"]}]})
                        continue
                return finish_episode(final_response, selected_evidence, step)
    except (ClarificationGuardTermination, AgentTurnLimit, SimulatorRoundLimit) as exc:
        result = _agent_failure_result(
            environment,
            clarification_guard,
            reason=exc.reason,
            provider=config.provider,
            model=config.model,
            step=current_step,
            image_views=image_views,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (SimulatorInfrastructureError, ServiceInfrastructureError) as exc:
        environment.state["session"]["status"] = "infrastructure_error"
        environment.state["session"]["error"] = f"{type(exc).__name__}: {exc}"
        environment._persist()
        print(
            json.dumps(
                {
                    "type": "infrastructure_error",
                    "component": "service" if isinstance(exc, ServiceInfrastructureError) else "user_simulator",
                    "trajectory": str(environment.session_dir),
                    "error": environment.state["session"]["error"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            file=sys.stderr,
        )
        return 3
    except ProviderInfrastructureError as exc:
        environment.state["session"]["status"] = "infrastructure_error"
        environment.state["session"]["error"] = f"{type(exc).__name__}: {exc}"
        environment._persist()
        print(
            json.dumps(
                {
                    "type": "infrastructure_error",
                    "component": "agent_model",
                    "trajectory": str(environment.session_dir),
                    "error": environment.state["session"]["error"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            file=sys.stderr,
        )
        return 3
    except Exception as exc:
        environment.state["session"]["status"] = "error"
        environment.state["session"]["error"] = f"{type(exc).__name__}: {exc}"
        environment._persist()
        print(
            json.dumps(
                {
                    "type": "model_run_error",
                    "trajectory": str(environment.session_dir),
                    "error": environment.state["session"]["error"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            file=sys.stderr,
        )
        return 2


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", required=True)
    parser.add_argument("--user-id", help="User fixture id for short task names")
    parser.add_argument(
        "--provider",
        required=True,
        choices=["relay", "openai", "anthropic", "gemini", "qwen"],
    )
    parser.add_argument("--model", required=True)
    parser.add_argument("--api-base")
    parser.add_argument("--api-key-env")
    parser.add_argument("--max-agent-turns", "--max-steps", dest="max_agent_turns", type=int, default=DEFAULT_MAX_AGENT_TURNS,
                        help="Total Agent generations (default 50); --max-steps is a deprecated alias.")
    parser.add_argument("--max-simulator-rounds", "--max-simulator-turns", dest="max_simulator_rounds", type=int, default=None,
                        help="Override Task max_rounds; otherwise use Task value or 10. STOP and retries do not count.")
    parser.add_argument("--max-image-views", type=int, default=None, help="Deprecated compatibility option; does not impose a tool budget.")
    parser.add_argument("--max-output-tokens", type=int, default=2048)
    parser.add_argument("--no-runtime-caps", action="store_true", help="Legacy output-token override; Agent and Simulator turn budgets remain active.")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--provider-retry-attempts", type=int, default=4)
    parser.add_argument(
        "--aep-mode",
        choices=["baseline", "planning", "selection", "full"],
        default="baseline",
        help="Optional Album Evidence Planner mode; baseline preserves the original loop.",
    )
    parser.add_argument("--aep-log", help="JSONL path for AEP intermediate runtime logs.")
    parser.add_argument(
        "--aep-model-planning",
        action="store_true",
        help="Use the configured agent model for dynamic AEP planning; fallback is local and deterministic.",
    )
    parser.add_argument(
        "--aep-model-verification",
        action="store_true",
        help="Use the configured multimodal model for task-conditioned candidate verification.",
    )
    parser.add_argument("--simulator-model", default=os.environ.get("CAMACT_SIMULATOR_MODEL", ""))
    parser.add_argument("--simulator-api-base", default=os.environ.get("CAMACT_SIMULATOR_API_BASE", ""))
    parser.add_argument("--simulator-api-key-env", default=os.environ.get("CAMACT_SIMULATOR_API_KEY_ENV", "CAMACT_SIMULATOR_API_KEY"))
    parser.add_argument("--simulator-timeout", type=float, default=60.0)
    parser.add_argument("--simulator-max-output-tokens", type=int, default=8192)
    parser.add_argument("--simulator-retry-attempts", type=int, default=6)
    parser.add_argument(
        "--session-dir",
        help="Optional exact trajectory directory, primarily for batch runs.",
    )
    parser.add_argument("--token-tracking", action=argparse.BooleanOptionalAction, default=False,
                        help="Collect real Agent provider usage; default off")
    args = parser.parse_args()
    if args.no_runtime_caps:
        args.max_output_tokens = None
        args.simulator_max_output_tokens = None
    return run_agent(args)


if __name__ == "__main__":
    raise SystemExit(main())
