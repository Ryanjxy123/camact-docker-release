"""Completion taxonomy and read-only projections of task-owned atomic scores.

Projection is read-only. For v3 its weights and means mirror the production
dimension aggregation; v2 retains its historical flat-weight projection.
Historical results without this metadata remain unknown.
"""
from __future__ import annotations

import math

DIMENSION_VERSION = "camact.completion-dimensions.v1"
DIMENSIONS = (
    "outcome_correctness", "context_grounding", "execution_state",
    "interaction_adaptation",
)
DIMENSION_LABELS = {
    "outcome_correctness": "Outcome Correctness",
    "context_grounding": "Context Grounding",
    "execution_state": "Execution & State",
    "interaction_adaptation": "Interaction & Adaptation",
}


def project_completion(components, results, *, scoring_contract="camact.atomic.v2", dimension_weights=None):
    """Project a validated atomic result once; absent/unscored groups are N/A.

    v2 group score = sum(w*s)/sum(w), using the original task denominator.
    v3 group score = mean(s), with declared dimension weight as its task mass.
    Passing no results declares applicability without inventing a zero score.
    """
    by_id = {item["id"]: item for item in results}
    total = math.fsum(c["weight"] for c in components)
    atomic_v3 = scoring_contract == "camact.atomic.v3"
    if atomic_v3 and components:
        from .contracts import validate_dimension_weights
        validate_dimension_weights(dimension_weights, components)
    projected = {}
    for dimension in DIMENSIONS:
        group = [c for c in components if c["dimension"] == dimension]
        weight = math.fsum(c["weight"] for c in group)
        scored = bool(group) and all(c["id"] in by_id and by_id[c["id"]].get("score") is not None for c in group)
        numerator = math.fsum(c["weight"] * by_id[c["id"]]["score"] for c in group) if scored else None
        normalized_weight = (dimension_weights.get(dimension, 0) if atomic_v3 and dimension_weights
                             else weight / total if total else None)
        score = (math.fsum(by_id[c["id"]]["score"] for c in group) / len(group)
                 if scored and atomic_v3 else numerator / weight if scored else None)
        projected[dimension] = {
            "applicable": bool(group), "criterion_ids": [c["id"] for c in group],
            "criterion_count": len(group), "weight_sum": weight,
            "normalized_weight": normalized_weight,
            "score": score,
            "contribution": (score * normalized_weight if atomic_v3 else numerator / total) if scored else None,
        }
    return projected


def summarize_completion(results):
    """Task mean per applicable, scored dimension; no second aggregation score."""
    results = list(results)
    summary = {}
    for dimension in DIMENSIONS:
        values = []
        not_applicable = 0
        for result in results:
            group = result.get("completion_dimensions", {}).get(dimension)
            if not group or result.get("infrastructure_failure"):
                continue
            if group.get("applicable") is False:
                not_applicable += 1
            elif group.get("applicable") is True and group.get("score") is not None:
                values.append(group["score"])
        summary[dimension] = {
            "score": math.fsum(values) / len(values) if values else None,
            "evaluated_tasks": len(values), "not_applicable_tasks": not_applicable,
            "unknown_tasks": len(results) - len(values) - not_applicable,
        }
    return summary
