"""Host delivery of official assistant turns to the unchanged user Simulator.

The native CLI still owns every model/tool decision. These helpers implement
only the same user-message/STOP boundary used by canonical run_model.py.
"""
from __future__ import annotations


def native_turn_action(environment, *, answer, trajectory_class="finished"):
    state = environment.state.get("session", {})
    if trajectory_class in {"infrastructure_failure", "harness_failure"}:
        return {"action": "infrastructure_failure", "reason": "native_execution_failed"}
    if trajectory_class == "agent_failure" or state.get("status") == "agent_failure":
        return {"action": "agent_failure", "reason": state.get("failure_type") or state.get("termination_reason") or "native_agent_failure"}
    if environment.simulator is None:
        return {"action": "finish", "reason": "single_native_turn"}
    if environment.simulator_stopped:
        return {"action": "finish", "reason": "simulator_stop"}
    if not isinstance(answer, str) or not answer.strip():
        return {"action": "agent_failure", "reason": "empty_native_final_response"}
    return {"action": "send_to_simulator"}


def advance_native_turn(runtime, answer, trajectory_class="finished"):
    """Return a real Simulator reply or terminal fact; never invent a STOP."""
    environment = runtime.environment
    decision = native_turn_action(environment, answer=answer, trajectory_class=trajectory_class)
    if decision["action"] != "send_to_simulator":
        return decision
    try:
        response = runtime.command({"op": "ask_user", "message": answer})
    except Exception as exc:
        state = environment.state.get("session", {})
        if state.get("status") == "agent_failure":
            return {"action": "agent_failure", "reason": state.get("failure_type") or state.get("termination_reason") or type(exc).__name__}
        return {"action": "infrastructure_failure", "reason": f"Simulator delivery failed ({type(exc).__name__})"}
    state = environment.state.get("session", {})
    if state.get("status") == "agent_failure":
        return {"action": "agent_failure", "reason": state.get("failure_type") or state.get("termination_reason") or "simulator_budget_exhausted"}
    if not response.get("ok"):
        return {"action": "infrastructure_failure", "reason": runtime.infrastructure_error or "Simulator delivery returned an error"}
    if environment.simulator_stopped:
        return {"action": "finish", "reason": "simulator_stop"}
    reply = response.get("content")
    if not isinstance(reply, str) or not reply.strip():
        return {"action": "infrastructure_failure", "reason": "Simulator returned an empty reply without STOP"}
    return {"action": "resume", "message": reply}
