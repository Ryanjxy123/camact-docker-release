"""Field/state binding checks shared by fixed and simulated CamAct tasks."""
from __future__ import annotations

from typing import Any


def _path(value: Any, path: str) -> Any:
    current = value
    for part in str(path).split("."):
        if not part:
            continue
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _field(value: Any, field: str) -> Any:
    current = value
    for part in str(field).split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def binding_result(state: dict[str, Any], binding: dict[str, Any]) -> dict[str, Any]:
    collection = _path(state, str(binding.get("path", "")))
    expected = binding.get("value")
    operator = binding.get("operator", "equals")
    if str(binding.get("field", "")) == "count" and isinstance(collection, list):
        actual = len(collection)
        matched = actual == expected
        return {
            "passed": matched,
            "score": float(matched),
            "binding": binding,
            "actual_values": [actual],
        }
    records = collection if isinstance(collection, list) else [collection]
    matched = False
    actual_values: list[Any] = []
    for record in records:
        actual = _field(record, str(binding.get("field", ""))) if isinstance(record, dict) else None
        actual_values.append(actual)
        if operator == "contains" and isinstance(actual, (list, str)):
            matched = expected in actual
        else:
            matched = actual == expected
        if matched:
            break
    return {"passed": matched, "score": float(matched), "binding": binding, "actual_values": actual_values}


def history_constraint_check(params: dict[str, Any], state: dict[str, Any]) -> tuple[float, dict[str, Any]]:
    message_count = int(params.get("history_message_count", 0))
    bindings = [binding_result(state, item["state_binding"]) for item in params.get("history_constraints", [])]
    history_ok = 2 <= message_count <= 6
    binding_score = sum(item["score"] for item in bindings) / len(bindings) if bindings else 0.0
    score = 0.25 * float(history_ok) + 0.75 * binding_score
    return score, {"history_message_count": message_count, "history_count_valid": history_ok, "binding_results": bindings}


def user_constraint_check(params: dict[str, Any], submission: dict[str, Any], state: dict[str, Any]) -> tuple[float, dict[str, Any]]:
    fields = list(params.get("fields", []))
    reported = set(str(item) for item in submission.get("clarifications", []))
    observed = submission.get("observed_constraints", {})
    results = []
    for field in fields:
        name = str(field.get("field_name", ""))
        observed_ok = name in observed and observed[name] == field.get("hidden_value")
        clarified_ok = name in reported
        binding = binding_result(state, field.get("state_binding", {}))
        score = 0.25 * float(clarified_ok) + 0.25 * float(observed_ok) + 0.50 * binding["score"]
        results.append({"field_name": name, "clarified": clarified_ok, "observed": observed_ok, "binding": binding, "score": score})
    score = sum(item["score"] for item in results) / len(results) if results else 0.0
    return score, {"field_results": results}
