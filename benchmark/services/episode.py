"""Shared terminal-episode evidence contract for runners and evaluators."""
from __future__ import annotations

import copy
import json
from datetime import datetime
from pathlib import Path

VERSION = "camact.episode.v1"
TERMINAL = {"finished", "agent_failure"}
INFRASTRUCTURE = {"running", "error", "timeout", "abandoned", "infrastructure_error", "infrastructure_failure", "harness_failure", "evaluator_failure"}


def episode_error(episode: dict, state: dict | None = None, *, task_id: str | None = None) -> str | None:
    """Fail closed: a status label alone is not proof of a terminal snapshot."""
    if not isinstance(episode, dict):
        return "missing episode object"
    if episode.get("trajectory_class") in INFRASTRUCTURE:
        return "declared execution failure cannot be replaced by a terminal snapshot"
    errors = episode.get("errors", {})
    if isinstance(errors, dict) and any(errors.get(key) for key in ("infrastructure", "harness")):
        return "recorded terminal infrastructure failure"
    if task_id is not None and episode.get("task_id") != task_id:
        return "episode task identity differs from grader task"
    metadata = episode.get("runtime_metadata", {})
    environment = episode.get("final_environment")
    if not isinstance(metadata, dict) or metadata.get("snapshot_complete") is not True:
        return "missing or incomplete terminal snapshot"
    if not isinstance(environment, dict) or not isinstance(environment.get("session"), dict):
        return "missing terminal environment"
    session = environment["session"]
    if not isinstance(metadata.get("status"), str) or metadata.get("status") not in TERMINAL or session.get("status") != metadata.get("status"):
        return "episode is not a valid terminal execution"
    if not session.get("finished_at") or not session.get("id") or metadata.get("session_id") != session["id"]:
        return "terminal snapshot identity/timestamp is missing or inconsistent"
    if not isinstance(session["id"], str):
        return "invalid session identity"
    try:
        datetime.fromisoformat(session["finished_at"])
    except (TypeError, ValueError):
        return "invalid terminal timestamp"
    if state is not None and not isinstance(state, dict):
        return "invalid grader state"
    if state is not None and {k: v for k, v in state.items() if k != "user_simulator"} != environment:
        return "grader state differs from episode final environment"
    for key in ("execution_trace", "action_audit", "conversation", "tool_calls"):
        if not isinstance(episode.get(key), list):
            return f"missing episode evidence: {key}"
    if not isinstance(episode.get("final_answer"), str):
        return "missing episode final answer"
    if episode["action_audit"] != episode["execution_trace"]:
        return "action audit differs from execution trace"
    trace = episode["execution_trace"]
    if any(not isinstance(e, dict) or type(e.get("sequence")) is not int for e in trace):
        return "invalid execution trace sequence"
    sequences = [e["sequence"] for e in trace]
    if sequences != list(range(1, len(trace) + 1)):
        return "incomplete or reordered execution trace"
    if any(not isinstance(call, dict) for call in episode["tool_calls"]):
        return "invalid tool call evidence"
    traced = [{"tool": e.get("name"), "arguments": e.get("request", {}), "status": e.get("status")}
              for e in trace if e.get("kind") == "tool_call"]
    calls = [{"tool": e.get("tool"), "arguments": e.get("arguments", {}), "status": e.get("status")}
             for e in episode["tool_calls"]]
    if traced != calls:
        return "tool calls differ from execution trace"
    services = metadata.get("services")
    snapshots, audits = episode.get("final_service_state"), episode.get("service_audit")
    if not isinstance(services, list) or not isinstance(snapshots, dict) or not isinstance(audits, dict):
        return "missing service evidence"
    if any(not isinstance(name, str) or not name for name in services) or len(services) != len(set(services)):
        return "invalid service declarations"
    if set(services) != set(snapshots) or set(services) != set(audits):
        return "incomplete service evidence"
    for name in services:
        if not isinstance(snapshots[name], dict) or not isinstance(audits[name], list):
            return "invalid service evidence"
        for key, value in snapshots[name].items():
            if key not in environment or environment[key] != value:
                return "service snapshot differs from final environment"
    return None


def trajectory_class(episode: dict, state: dict) -> str:
    if episode_error(episode, state):
        return "infrastructure_failure"
    return "agent_failure" if episode["runtime_metadata"]["status"] == "agent_failure" else "finished"


def _read(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return copy.deepcopy(default)


def recover_episode(session_dir: Path, *, status: str | None = None, error: str | None = None,
                    fallback_episode: dict | None = None) -> dict:
    """Preserve the runtime episode; salvage diagnostics without certifying a snapshot."""
    episode = _read(session_dir / "episode.json", None)
    if not isinstance(episode, dict):
        episode = _read(session_dir / "submission.json", fallback_episode or {})
    if not isinstance(episode, dict):
        episode = {}
    # Capture validity BEFORE filling diagnostic defaults. Recovery may salvage
    # evidence, but cannot certify a previously incomplete persisted episode.
    original_error = episode_error(episode)
    state = episode.get("final_environment")
    # A persisted Episode can predate a failed finish/continuation. Never let
    # that older successful snapshot conceal the runner's later failure. Keep
    # the actual business state for diagnosis without certifying it for scoring.
    current_state = _read(session_dir / "state.json", None)
    if isinstance(current_state, dict) and isinstance(current_state.get("session"), dict):
        current_session = current_state["session"]
        prior_session = state.get("session", {}) if isinstance(state, dict) else {}
        if (current_session.get("id") and current_session.get("id") == prior_session.get("id")
                and current_session.get("status") in INFRASTRUCTURE):
            state = current_state
            original_error = original_error or "persisted runtime state records a later nonterminal or failed execution"
            episode.setdefault("runtime_metadata", {})["status"] = current_session["status"]
            episode["runtime_metadata"]["recovery_state_source"] = "state.json"
    if not isinstance(state, dict):
        state = _read(session_dir / "final_state.json", None)
        if not isinstance(state, dict):
            state = _read(session_dir / "state.json", {})
    state = {k: copy.deepcopy(v) for k, v in (state or {}).items() if k != "user_simulator"} if isinstance(state, dict) else {}
    if not isinstance(state.get("session"), dict):
        state["session"] = {}
    session = state["session"]
    if not isinstance(episode.get("runtime_metadata"), dict):
        episode["runtime_metadata"] = {}
    metadata = episode["runtime_metadata"]
    if original_error:
        metadata["snapshot_complete"] = False
        metadata["recovery_validation_error"] = original_error
    metadata.setdefault("snapshot_complete", False)
    metadata.setdefault("session_id", session.get("id"))
    metadata.setdefault("status", session.get("status", "infrastructure_error"))
    if status is not None and status != "finished":
        session["status"] = metadata["status"] = status
    if error:
        metadata["recovery_error"] = error
    trace = episode.get("execution_trace")
    if not isinstance(trace, list):
        trace = []
        try:
            for line in (session_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue  # A hard kill may truncate the last audit record.
                if not isinstance(event, dict):
                    continue
                if event.get("kind") == "user_turn":
                    event["response"] = {"content": event.get("response", {}).get("content", "")}
                trace.append(event)
        except OSError:
            pass
    episode.setdefault("execution_trace", trace)
    episode.setdefault("action_audit", copy.deepcopy(trace))
    episode.setdefault("tool_calls", [{"tool": e["name"], "arguments": e["request"], "status": e["status"]}
                                      for e in trace if e.get("kind") == "tool_call"])
    episode.setdefault("conversation", episode.get("conversation_trace", _read(session_dir / "conversation.json", [])))
    episode.setdefault("conversation_trace", copy.deepcopy(episode["conversation"]))
    episode.setdefault("final_answer", episode.get("final_response", ""))
    episode.setdefault("final_response", episode["final_answer"])
    for key in ("final_service_state", "service_audit"):
        if not isinstance(episode.get(key), dict):
            episode[key] = {}
    for path in sorted((session_dir / "services").glob("*/snapshot.json")):
        doc = _read(path, {})
        if doc.get("session_id") == metadata.get("session_id") and doc.get("service") == path.parent.name:
            episode["final_service_state"].setdefault(doc["service"], doc.get("state", {}))
            episode["service_audit"].setdefault(doc["service"], doc.get("audit", []))
    metadata.setdefault("services", sorted(episode["final_service_state"]))
    episode["final_environment"] = state
    episode["status"] = metadata["status"]
    episode.setdefault("evidence", [])
    episode.setdefault("actions", [])
    return episode


def evaluation_state(session_dir: Path, episode: dict) -> dict:
    """Recover evaluator-only simulator state from the same terminal session.

    The public episode intentionally omits ``user_simulator`` from the Agent
    projection.  Scoring may still require that private state, but only when a
    session/task-bound snapshot proves it belongs to this exact episode.
    """
    environment = copy.deepcopy(episode.get("final_environment", {}))
    if not isinstance(environment, dict) or episode_error(episode):
        return environment
    metadata = episode.get("runtime_metadata", {})
    session_id = metadata.get("session_id")
    private = episode.get("evaluator_private_state")
    if private is not None:
        if (not isinstance(private, dict) or private.get("session_id") != session_id
                or private.get("task_id") != episode.get("task_id")
                or not isinstance(private.get("user_simulator"), dict)):
            raise ValueError("evaluator private state identity/schema mismatch")
        environment["user_simulator"] = copy.deepcopy(private["user_simulator"])
        return environment
    for filename in ("final_state.json", "state.json"):
        candidate = _read(session_dir / filename, None)
        if not isinstance(candidate, dict) or not isinstance(candidate.get("user_simulator"), dict):
            continue
        if ({k: v for k, v in candidate.items() if k != "user_simulator"} != environment
                or candidate.get("session", {}).get("id") != session_id):
            raise ValueError("private grading snapshot differs from terminal episode")
        environment["user_simulator"] = copy.deepcopy(candidate["user_simulator"])
        return environment
    if metadata.get("user_simulator_enabled"):
        raise ValueError("missing session-bound private simulator state for grading")
    return environment
