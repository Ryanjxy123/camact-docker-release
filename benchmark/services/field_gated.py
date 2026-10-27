"""Deterministic question-sensitive user simulator for CamAct."""
from __future__ import annotations

import re
from typing import Any


def _normalized(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value).casefold()).strip()


def _matches(question: str, field: dict[str, Any]) -> bool:
    normalized = _normalized(question)
    rule = field.get("question_matching_rule", {})
    any_terms = [_normalized(item) for item in rule.get("any_terms", []) + field.get("synonyms", [])]
    all_terms = [_normalized(item) for item in rule.get("all_terms", [])]
    any_ok = any(term and term in normalized for term in any_terms) if any_terms else True
    all_ok = all(term and term in normalized for term in all_terms)
    return any_ok and all_ok


def respond(simulator: dict[str, Any], simulator_state: dict[str, Any], question: str) -> dict[str, Any]:
    if simulator.get("policy") != "field_gated_v1":
        raise ValueError("unsupported simulator policy")
    fields = list(simulator.get("fields", []))
    released = simulator_state.setdefault("released_fields", [])
    observed = simulator_state.setdefault("observed_constraints", {})
    clarifications = simulator_state.setdefault("clarifications", [])
    released_now: list[dict[str, Any]] = []
    progress = True
    while progress:
        progress = False
        for field in fields:
            name = str(field.get("field_name", ""))
            if not name or name in released:
                continue
            if any(str(dependency) not in released for dependency in field.get("dependencies", [])):
                continue
            if not _matches(question, field):
                continue
            released.append(name)
            observed[name] = field.get("hidden_value")
            if name not in clarifications:
                clarifications.append(name)
            released_now.append(field)
            progress = True
    if released_now:
        content = " ".join(str(field.get("release_response", "")).strip() for field in released_now).strip()
        return {
            "content": content,
            "done": len(released) == len(fields),
            "released_fields": [field["field_name"] for field in released_now],
            "matched": True,
        }
    if len(released) == len(fields):
        return {"content": simulator.get("complete_response", "I have no additional constraints to add."), "done": True, "released_fields": [], "matched": False}
    return {
        "content": simulator.get("unmatched_response", "Please ask a more specific question about the missing action details."),
        "done": False,
        "released_fields": [],
        "matched": False,
    }
