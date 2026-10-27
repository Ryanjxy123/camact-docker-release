"""Task-level aggregation and paired comparison for unified evaluations."""
from __future__ import annotations

from statistics import fmean
import math
import re
from typing import Any, Iterable, Mapping

from .schema import StandardRunArtifact
from .measurement import canonical_measurement
from benchmark.evaluator.dimensions import summarize_completion


def _mean(values: Iterable[float]) -> float | None:
    values = list(values)
    return round(float(fmean(values)), 6) if values else None


def _infrastructure_failure(result: Mapping[str, Any], artifact=None) -> bool:
    return bool(result.get("infrastructure_failure") or result.get("evaluation_infrastructure_failure")
        or result.get("status") in {"infrastructure_error", "infrastructure_failure", "harness_failure", "timeout", "evaluator_failure"}
        or getattr(artifact, "trajectory_class", None) in {"infrastructure_failure", "harness_failure"})


def _exclusion_reason(result: Mapping[str, Any], artifact=None) -> str | None:
    if _infrastructure_failure(result, artifact):
        return "infrastructure_failure"
    if result.get("analysis_eligible") is False or result.get("comparable") is False:
        return str(result.get("analysis_exclusion_reason") or "explicitly_noncomparable")
    score = result.get("capability_score", result.get("score"))
    if type(score) not in (int, float) or not math.isfinite(score):
        return "missing_or_invalid_score"
    return None


def _completion_summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Report independent denominators; missing semantic judgments are unknown."""
    summary: dict[str, Any] = {}
    valid = [row for row in items if _exclusion_reason(row["result"], row.get("artifact")) is None]
    summary["completion_dimensions"] = summarize_completion(
        row["result"] if _exclusion_reason(row["result"], row.get("artifact")) is None else {} for row in items)
    for field, label in (
        ("safety_pass", "safety_pass"),
        ("final_state_success", "final_state_success"),
        ("semantic_completion", "semantic_completion"),
        ("overall_task_success", "overall_task_success"),
    ):
        values = [row["result"][field] for row in valid if isinstance(row["result"].get(field), bool)]
        summary[label + "_rate"] = _mean(float(value) for value in values)
        summary[label + "_evaluated_tasks"] = len(values)
        summary[label + "_unknown_tasks"] = len(items) - len(values)
    summary["completion_infrastructure_failure_count"] = sum(
        bool(row["result"].get("completion_evaluation_infrastructure_failure")) for row in items
    )
    summary["capability_breakdown"] = {
        name: _mean(float(row["result"]["capability_breakdown"][name]) for row in valid
                    if isinstance(row["result"].get("capability_breakdown", {}).get(name), (int, float)))
        for name in ("retrieval", "inspection", "evidence_grounding", "semantic_role", "output_communication", "final_state")
    }
    return summary


def _key(artifact: StandardRunArtifact, result: Mapping[str, Any]) -> tuple[str, str, int]:
    trial = artifact.run.get("trial")
    if trial is None:
        source = str(artifact.run.get("source_path", ""))
        match = re.search(r"(?:^|[\\/])trial[_-](\d+)(?:[\\/]|$)", source)
        trial = int(match.group(1)) if match else None
    try:
        trial = int(trial) if trial is not None else 1
    except (TypeError, ValueError):
        trial = 1
    return artifact.user_id, artifact.task_id, trial


def _snapshot_validation(
    baseline_artifacts: Iterable[StandardRunArtifact],
    candidate_artifacts: Iterable[StandardRunArtifact],
) -> dict[str, Any]:
    fields = ("benchmark_release_id", "benchmark_release_version", "benchmark_manifest_sha256", "protocol_version")
    baseline = list(baseline_artifacts)
    candidate = list(candidate_artifacts)
    values: dict[str, dict[str, set[str]]] = {side: {field: set() for field in fields} for side in ("baseline", "candidate")}
    for side, artifacts in (("baseline", baseline), ("candidate", candidate)):
        for artifact in artifacts:
            for field in fields:
                value = artifact.run.get(field)
                if value is not None and str(value).strip():
                    values[side][field].add(str(value))
    mismatches = []
    # Protocol versions describe the harness/adapter transport and may differ
    # between paired sides.  Only the benchmark release identity and manifest
    # hash establish that both sides ran against the same benchmark snapshot.
    snapshot_fields = ("benchmark_release_id", "benchmark_release_version", "benchmark_manifest_sha256")
    for field in snapshot_fields:
        left, right = values["baseline"][field], values["candidate"][field]
        if left and right and left != right:
            mismatches.append({"field": field, "baseline": sorted(left), "candidate": sorted(right)})
    if mismatches:
        raise ValueError(f"benchmark snapshot mismatch: {mismatches}")
    # Protocol versions may legitimately differ between harness adapters; the
    # benchmark snapshot is proven by release identity/version/hash.
    available = all(values[side][field] for side in values for field in snapshot_fields)
    observed_hashes = {
        side: sorted(values[side]["benchmark_manifest_sha256"])
        for side in ("baseline", "candidate")
    }
    expected_hashes = sorted(set(observed_hashes["baseline"]) | set(observed_hashes["candidate"]))
    return {
        "status": "matched" if available else "unavailable",
        "expected_manifest_sha256": expected_hashes[0] if len(expected_hashes) == 1 else None,
        "observed_manifest_sha256": observed_hashes,
        "fields": {
            field: {
                "baseline": sorted(values["baseline"][field]),
                "candidate": sorted(values["candidate"][field]),
            }
            for field in fields
        },
    }


def aggregate_results(
    artifacts: Iterable[StandardRunArtifact],
    results: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    artifacts = list(artifacts)
    results = list(results)
    if len(artifacts) != len(results):
        raise ValueError("artifacts and results must have equal length")
    rows = []
    for artifact, result in zip(artifacts, results):
        rows.append({"artifact": artifact, "result": dict(result)})
    infra = [row for row in rows if _infrastructure_failure(row["result"], row["artifact"])]
    scored = [row for row in rows if _exclusion_reason(row["result"], row["artifact"]) is None]
    strict = [row for row in scored if bool(row["result"].get("strict_success", row["result"].get("passed", False)))]
    safety_evaluated = [row for row in scored if row["result"].get("safety_score") is not None]
    safety_failures = [row for row in safety_evaluated if float(row["result"].get("safety_score", 1)) < 1]
    capabilities = [float(row["result"].get("capability_score", row["result"].get("score"))) for row in scored]
    costs = [
        float(row["artifact"].token_usage["cost_usd"])
        for row in scored
        if isinstance(row["artifact"].token_usage.get("cost_usd"), (int, float))
    ]
    by_user: dict[str, list[dict[str, Any]]] = {}
    by_category: dict[str, list[dict[str, Any]]] = {}
    by_interaction: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_user.setdefault(row["artifact"].user_id, []).append(row)
        by_category.setdefault(str(row["result"].get("taxonomy_code") or "unknown"), []).append(row)
        by_interaction.setdefault(str(row["result"].get("interaction_type") or "unknown"), []).append(row)

    def block(items: list[dict[str, Any]]) -> dict[str, Any]:
        valid = [row for row in items if _exclusion_reason(row["result"], row["artifact"]) is None]
        safety_rows = [row for row in valid if row["result"].get("safety_score") is not None]
        return {
            **_completion_summary(items),
            "total_tasks": len(items),
            "evaluated_tasks": len(valid),
            "infrastructure_failure_count": sum(_infrastructure_failure(row["result"], row["artifact"]) for row in items),
            "excluded_task_count": len(items) - len(valid),
            "agent_failure_count": sum(bool(row["result"].get("agent_failure")) for row in valid),
            "mean_capability": _mean(float(row["result"].get("capability_score", row["result"].get("score"))) for row in valid),
            "strict_success_count": sum(bool(row["result"].get("strict_success", row["result"].get("passed", False))) for row in valid),
            "strict_success_rate": _mean([float(bool(row["result"].get("strict_success", row["result"].get("passed", False)))) for row in valid]),
            "safety_failure_count": sum(float(row["result"].get("safety_score", 1)) < 1 for row in safety_rows),
            "safety_failure_rate": _mean([float(float(row["result"].get("safety_score", 1)) < 1) for row in safety_rows]),
        }

    return {
        **_completion_summary(rows),
        "schema_version": "camact.standard_evaluation_summary.v1",
        "total_tasks": len(rows),
        "evaluated_tasks": len(scored),
        "infrastructure_failure_count": len(infra),
        "excluded_task_count": len(rows) - len(scored),
        "eligible_task_keys": [{"user_id": row["artifact"].user_id, "task_id": row["artifact"].task_id,
                                "trial": _key(row["artifact"], row["result"])[2]} for row in scored],
        "excluded_tasks": [{"user_id": row["artifact"].user_id, "task_id": row["artifact"].task_id,
                            "reason": _exclusion_reason(row["result"], row["artifact"])} for row in rows
                           if _exclusion_reason(row["result"], row["artifact"]) is not None],
        "agent_failure_count": sum(bool(row["result"].get("agent_failure")) for row in scored),
        "mean_capability": _mean(capabilities),
        "strict_success_count": len(strict),
        "strict_success_rate": round(len(strict) / len(scored), 6) if scored else None,
        "safety_evaluated_tasks": len(safety_evaluated),
        "safety_failure_count": len(safety_failures),
        "safety_failure_rate": round(len(safety_failures) / len(safety_evaluated), 6) if safety_evaluated else None,
        "cost_available_tasks": len(costs),
        "cost_coverage": round(len(costs) / len(scored), 6) if scored else None,
        "total_cost": round(sum(costs), 6) if costs else None,
        "cost_per_strict_success": (
            round(sum(costs) / len(strict), 6)
            if costs and strict and len(costs) == len(scored)
            else None
        ),
        "by_user": {user: block(items) for user, items in sorted(by_user.items())},
        "by_category": {category: block(items) for category, items in sorted(by_category.items())},
        "by_interaction": {mode: block(items) for mode, items in sorted(by_interaction.items())},
    }


def _retrieved_ids(artifact: StandardRunArtifact) -> set[str]:
    ids: set[str] = set()
    records = artifact.diagnostics.get("retrieval_diagnostics", [])
    if isinstance(records, list):
        for record in records:
            if not isinstance(record, dict) or record.get("record_type", record.get("kind")) != "retrieval":
                continue
            for key in ("returned_candidates", "merged_candidates", "literal_candidates", "semantic_candidates", "raw_retrieved_candidates"):
                value = record.get(key)
                if isinstance(value, list):
                    ids.update(str(item) for item in value)
            exposed = record.get("exposed_response")
            if isinstance(exposed, Mapping):
                result = exposed.get("result")
                if isinstance(result, Mapping):
                    for item in result.get("photos", []):
                        if isinstance(item, Mapping):
                            value = item.get("image_id") or item.get("id") or item.get("filename")
                            if value:
                                ids.add(str(value))
    return ids


def mechanism_metrics(artifact: StandardRunArtifact) -> dict[str, Any]:
    measurement = artifact.measurement if isinstance(artifact.measurement, dict) and artifact.measurement.get("schema_version") else canonical_measurement(
        model_calls=artifact.model_calls, token_usage=artifact.token_usage,
        tool_calls=artifact.tool_calls, actions=artifact.actions,
        evidence=artifact.evidence, timing=artifact.timing,
        diagnostics=artifact.diagnostics, final_state=artifact.final_state,
    )
    selected = {str(item) for item in artifact.evidence if isinstance(item, str)}
    action_count = int(measurement.get("domain_action_succeeded", 0) or 0)
    usage = artifact.token_usage
    model_call_count = len(artifact.model_calls)
    return {
        "retrieved_count": len(_retrieved_ids(artifact)),
        "viewed_count": int(measurement.get("unique_image_views", 0) or 0),
        "selected_count": len(measurement.get("evidence_selected", selected)),
        "action_count": action_count,
        "retrieval_calls": int(artifact.diagnostics.get("retrieval_calls", 0) or 0),
        "candidates_exposed": int(artifact.diagnostics.get("candidates_exposed", 0) or 0),
        "image_views": int(measurement.get("image_views", 0) or 0),
        "simulator_turns": int(measurement.get("simulator_turns", 0) or 0),
        "model_calls": int(measurement.get("model_calls") and len(measurement.get("model_calls", [])) or model_call_count),
        "input_tokens": usage.get("input_tokens"),
        "output_tokens": usage.get("output_tokens"),
        "total_tokens": usage.get("total_tokens"),
        "cost_usd": usage.get("cost_usd"),
    }


def _mechanism_summary(
    artifacts: Iterable[StandardRunArtifact],
    results: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    artifacts = list(artifacts)
    values = [mechanism_metrics(item) for item in artifacts]
    numeric = ("retrieved_count", "viewed_count", "selected_count", "action_count", "retrieval_calls", "candidates_exposed", "image_views", "simulator_turns", "model_calls", "input_tokens", "output_tokens", "total_tokens", "cost_usd")
    summary = {name: _mean(float(item[name]) for item in values if isinstance(item.get(name), (int, float))) for name in numeric}
    summary["lifecycle"] = {
        "retrieved": sum(int(item["retrieved_count"]) for item in values),
        "viewed": sum(int(item["viewed_count"]) for item in values),
        "selected": sum(int(item["selected_count"]) for item in values),
        "action": sum(int(item["action_count"]) for item in values),
    }
    result_values = list(results or [])
    strict_count = sum(
        bool(item.get("strict_success", item.get("passed", False)))
        for item in result_values
        if _exclusion_reason(item) is None
    )
    costs = [float(item["cost_usd"]) for item in values if isinstance(item.get("cost_usd"), (int, float))]
    cost_available = len(costs)
    summary["cost_available_tasks"] = cost_available
    summary["scope"] = "all_attempts_including_infrastructure_failures"
    summary["token_coverage"] = {
        field: {"available_attempts": sum(type(item.get(field)) in (int, float) for item in values),
                "total_attempts": len(values)} for field in ("input_tokens", "output_tokens", "total_tokens")}
    summary["token_comparability"] = "Recorded usage only; missing is not zero; native cache inclusion and partial-response coverage may differ."
    summary["cost_coverage"] = round(cost_available / len(values), 6) if values else None
    summary["total_cost"] = round(sum(costs), 6) if costs else None
    summary["cost_per_strict_success"] = (
        round(sum(costs) / strict_count, 6)
        if costs and strict_count and cost_available == len(values)
        else None
    )
    return summary


def compare_results(
    baseline_artifacts: Iterable[StandardRunArtifact],
    baseline_results: Iterable[Mapping[str, Any]],
    candidate_artifacts: Iterable[StandardRunArtifact],
    candidate_results: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    baseline_artifacts, baseline_results = list(baseline_artifacts), list(baseline_results)
    candidate_artifacts, candidate_results = list(candidate_artifacts), list(candidate_results)
    if len(baseline_artifacts) != len(baseline_results) or len(candidate_artifacts) != len(candidate_results):
        raise ValueError("artifacts and results must have equal length")
    snapshot_validation = _snapshot_validation(baseline_artifacts, candidate_artifacts)

    def index(artifacts: list[StandardRunArtifact], results: list[Mapping[str, Any]], side: str):
        indexed: dict[tuple[str, str, int], tuple[StandardRunArtifact, dict[str, Any]]] = {}
        duplicates: list[dict[str, Any]] = []
        for artifact, result in zip(artifacts, results):
            key = _key(artifact, result)
            if key in indexed:
                duplicates.append({"user_id": key[0], "task_id": key[1], "trial": key[2], "side": side})
                continue
            indexed[key] = (artifact, dict(result))
        return indexed, duplicates

    baseline, baseline_duplicates = index(baseline_artifacts, baseline_results, "baseline")
    candidate, candidate_duplicates = index(candidate_artifacts, candidate_results, "candidate")
    duplicate_pairs = baseline_duplicates + candidate_duplicates
    if duplicate_pairs:
        raise ValueError(f"duplicate paired keys: {duplicate_pairs}")
    common = sorted(set(baseline) & set(candidate))
    unmatched_baseline = sorted(set(baseline) - set(candidate))
    unmatched_candidate = sorted(set(candidate) - set(baseline))
    deltas = []
    wins = ties = losses = 0
    pairs, excluded_pairs = [], []
    for key in common:
        ba, br = baseline[key]
        ca, cr = candidate[key]
        bscore = br.get("capability_score", br.get("score"))
        cscore = cr.get("capability_score", cr.get("score"))
        breason, creason = _exclusion_reason(br, ba), _exclusion_reason(cr, ca)
        if breason is not None or creason is not None:
            excluded_pairs.append({"user_id": key[0], "task_id": key[1], "trial": key[2],
                                   "baseline_reason": breason, "candidate_reason": creason})
            continue
        delta = float(cscore) - float(bscore)
        deltas.append(delta)
        if delta > 1e-12:
            wins += 1
        elif delta < -1e-12:
            losses += 1
        else:
            ties += 1
        pairs.append({"user_id": key[0], "task_id": key[1], "trial": key[2], "baseline": bscore, "candidate": cscore, "delta": round(delta, 6), "baseline_strict_success": bool(br.get("strict_success", br.get("passed", False))), "candidate_strict_success": bool(cr.get("strict_success", cr.get("passed", False)))})
    baseline_summary = aggregate_results(baseline_artifacts, baseline_results)
    candidate_summary = aggregate_results(candidate_artifacts, candidate_results)
    return {
        "schema_version": "camact.standard_paired_comparison.v1",
        "paired_tasks": len(pairs),
        "common_pairs": len(common),
        "unmatched_baseline": [
            {"user_id": key[0], "task_id": key[1], "trial": key[2]} for key in unmatched_baseline
        ],
        "unmatched_candidate": [
            {"user_id": key[0], "task_id": key[1], "trial": key[2]} for key in unmatched_candidate
        ],
        "duplicate_pairs": duplicate_pairs,
        "excluded_pairs": excluded_pairs,
        "snapshot_validation": snapshot_validation,
        "benchmark_provenance": {
            "snapshot_validation": snapshot_validation,
            "baseline": snapshot_validation["fields"],
            "candidate": snapshot_validation["fields"],
        },
        "mean_capability": {
            "baseline": baseline_summary["mean_capability"],
            "candidate": candidate_summary["mean_capability"],
        },
        "mean_capability_scope": "each_side_own_eligible_tasks; not a paired capability ranking",
        "paired_mean_capability": {"baseline": _mean(p["baseline"] for p in pairs),
                                   "candidate": _mean(p["candidate"] for p in pairs)},
        "strict_success": {
            "baseline": baseline_summary["strict_success_rate"],
            "candidate": candidate_summary["strict_success_rate"],
        },
        "baseline": baseline_summary,
        "candidate": candidate_summary,
        "mean_paired_delta": _mean(deltas),
        "win_tie_loss": {"win": wins, "tie": ties, "loss": losses},
        "pairs": pairs,
        "mechanism": {
            "baseline": _mechanism_summary(baseline_artifacts, baseline_results),
            "candidate": _mechanism_summary(candidate_artifacts, candidate_results),
        },
    }
