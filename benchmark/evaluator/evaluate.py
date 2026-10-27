"""Canonical shared evaluator: episode gate -> task grader -> Capability/Strict."""
from __future__ import annotations

import math
from pathlib import Path

from .atomic import aggregate
from .contracts import LEGACY_VERSION, VERSION, load_contract, load_grader, validate_results
from .dimensions import DIMENSION_VERSION, project_completion
from .judge import JudgeInfrastructureError, SemanticJudge, judge_from_environment
# Stable checker imports for existing callers. These do not execute a legacy score.
from .checks import (
    load, _check, _critical_failure_results, _structured_assertion_matches,
    _canonical_strict_success, _state_path, _field_value_matches,
    _field_component_name, _metadata, _runtime_root, _state_images, _images,
    _viewed_images, _successful_tool_calls,
)


class _EnvironmentJudge:
    """Resolve Judge configuration only when a task checker actually needs it."""
    def __init__(self):
        self.judge = None

    def evaluate(self, **kwargs):
        if self.judge is None:
            self.judge = judge_from_environment()
        if self.judge is None:
            raise JudgeInfrastructureError("Task requires a Judge but none is configured")
        return self.judge.evaluate(**kwargs)


def _failure(task_id, component, error, *, scoring_contract=LEGACY_VERSION, **details):
    return {
        "task_id": task_id, "scoring_contract": scoring_contract,
        "status": "infrastructure_error", "infrastructure_failure": True,
        "score": None, "capability": None, "capability_score": None, "rubric_score": None,
        "completion_score": None, "completion_dimension_schema": DIMENSION_VERSION,
        "completion_dimensions": project_completion([], []),
        "robustness_extension": {"scope": "cross_trial", "status": "not_computed"},
        "strict_success": False, "passed": False, "overall_task_success": False,
        "comparable": False,
        "failure_type": "evidence_unknown" if component == "visual_evidence" else "infrastructure_failure",
        "weighted_scoring_executed": False,
        "failure_reason": [{"type": "invalid_episode" if component == "episode" else "evaluator_infrastructure_failure", "message": error}],
        "evaluation_infrastructure_failure": {"component": component, "error": error, "retryable": component == "task_grader"},
        "safety_score": None,
        "final_state_score": None, "final_state_success": None,
        "final_state_components": {}, "criterion_results": {}, "action_checks": [],
        "agent_failure": False,
        "critical_failure_triggered": [], "atomic_criteria": [], **details,
    }


def evaluate(task_dir: Path, submission: dict, service_state: dict,
             judge: SemanticJudge | bool | None = None) -> dict:
    if __package__ == "evaluator":
        from services.episode import episode_error
    else:
        from ..services.episode import episode_error
    task_dir = Path(task_dir)
    spec = load(task_dir / "task_spec.json")
    task_id = spec["task_id"]
    scoring_contract = spec.get("scoring_contract", LEGACY_VERSION)
    invalid = episode_error(submission, service_state, task_id=task_id)
    if invalid:
        return _failure(task_id, "episode", invalid, scoring_contract=scoring_contract)
    try:
        task = load_contract(task_dir)
        scoring_contract = task["scoring_contract"]
        if task["task_id"] != task_id:
            raise ValueError("scoring contract task identity mismatch")
        from .visual_evidence import applicable_components, component_binding, judge_visual_evidence, apply_visual_checks
        if applicable_components(task):
            evidence = submission.get("visual_evidence")
            if evidence:
                # Recompute from trusted source bodies; normalized claims alone
                # cannot certify a visual input or survive source tampering.
                from evaluation.camact_eval.visual_capture import collect_visual_evidence
                if __package__ == "evaluator":
                    from services.api import raw_root
                else:
                    from ..services.api import raw_root
                capture_root = evidence.get("capture_root")
                if capture_root and "workspace" not in Path(capture_root).parts:
                    submission = {**submission, "visual_evidence": collect_visual_evidence(
                        Path(capture_root), submission, raw_root(task_dir) / "images")}
                else:
                    submission = {**submission, "visual_evidence": {}}
            for component in applicable_components(task):
                visual_audit = judge_visual_evidence(submission.get("visual_evidence"), submission, component_binding(task,component))
                if visual_audit["status"] == "evidence_unknown":
                    return _failure(task_id, "visual_evidence", visual_audit["reason"],
                                    scoring_contract=scoring_contract, visual_evidence_audit=visual_audit)
        grader = load_grader(task_dir, task)
        # Project only after the unmodified Episode and trusted visual-source
        # gates have passed. Raw inputs remain authoritative and unchanged.
        from .grader_projection import project_grader_inputs
        grader_submission, grader_state = project_grader_inputs(task_dir, submission, service_state)
        graded = grader.grade(task=task, submission=grader_submission, state=grader_state,
                              judge=_EnvironmentJudge() if judge is None or judge is True else judge)
        apply_visual_checks(task, submission, graded)
        judge_summary = {
            "status": "failed" if graded.infrastructure_failures else "succeeded" if graded.judge_calls else "not_needed",
            "call_count": len(graded.judge_calls), "calls": graded.judge_calls,
            "failed_count": sum(c.get("status") == "failed" for c in graded.judge_calls),
        }
        if graded.infrastructure_failures:
            return _failure(task_id, "task_grader", graded.infrastructure_failures[0]["error"],
                            scoring_contract=scoring_contract,
                            atomic_criteria=graded.criteria, judge_summary=judge_summary,
                            critical_failure_triggered=graded.critical_failures,
                            safety_score=int(not graded.critical_failures),
                            mandatory_critical_violations=graded.mandatory_violations,
                            infrastructure_failures=graded.infrastructure_failures)
        validate_results(task["scoring_components"], graded.criteria, scoring_contract=scoring_contract)
        authored = {c["id"]: c for c in task["scoring_components"]}
        for criterion in graded.criteria:
            criterion["dimension"] = authored[criterion["id"]]["dimension"]
        capability, strict = aggregate(graded.criteria, safety_pass=not (graded.critical_failures or graded.mandatory_violations),
                                       episode_valid=submission["runtime_metadata"]["status"] == "finished",
                                       scoring_contract=scoring_contract,
                                       dimension_weights=task.get("dimension_weights"))
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, ImportError, AttributeError) as exc:
        return _failure(task_id, "scoring_contract_or_grader", f"{type(exc).__name__}: {exc}",
                        scoring_contract=scoring_contract)
    criteria = graded.criteria
    # v3 reports the true configured dimensions. v2 preserves report_group fields.
    groups = {}
    authored = {c["id"]: c for c in task["scoring_components"]}
    for item in criteria:
        dimension = (authored[item["id"]]["dimension"] if scoring_contract == VERSION
                     else authored[item["id"]].get("report_group", "completion"))
        groups.setdefault(dimension, []).append(item)
    weights = {k: math.fsum(c["normalized_weight"] for c in v) for k, v in groups.items()}
    dimensions = {k: math.fsum(c["contribution"] for c in v) / weights[k] for k, v in groups.items()}
    state_criteria = [c for c in criteria if c.get("state_projection")]
    content = [c for c in criteria if authored[c["id"]]["evidence_requirements"]["source"] == "persisted_text"]
    failures = [{"type": "atomic_requirement_failure", "criterion_id": c["id"], "score": c["score"]} for c in criteria if (c["mandatory"] and c["score"] < 1) or c["score"] == 0]
    failures.extend({"type": "safety_failure", "gate": c["type"], "details": c.get("details", {})} for c in graded.critical_failures)
    failures.extend({**c, "type": "mandatory_constraint_failure"} for c in graded.mandatory_violations)
    if submission["runtime_metadata"]["status"] != "finished":
        failures.append({"type": "execution_failure", "message": "terminal agent failure"})
    state_values = [c.get("send_score", c["score"]) for c in state_criteria]
    state_score = math.fsum(state_values) / len(state_values) if state_values else 1.0
    state_success = all(value == 1 for value in state_values) and not any(v.get("type") == "sent_photo_policy" for v in graded.mandatory_violations)
    aliases = {}
    for c in state_criteria:
        for alias in c.get("report_aliases", []):
            aliases.setdefault(alias, []).append(c["score"])
    state_components = {k: math.fsum(v) / len(v) for k, v in aliases.items()}
    return {
        "task_id": task_id, "taxonomy_code": spec.get("taxonomy_code"), "interaction_type": spec.get("interaction_type"),
        "visual_evidence_audit": graded.diagnostics.get("visual_evidence"),
        "scoring_contract": scoring_contract, "grader": str(task_dir / task["grader"]),
        "scoring_aggregation": "dimension_mean" if scoring_contract == VERSION else "legacy_flat_weighted",
        "status": "passed" if strict else "failed", "infrastructure_failure": False,
        "comparable": True,
        "failure_type": "agent_failure" if submission["runtime_metadata"]["status"] == "agent_failure" else None,
        "capability": capability, "capability_score": capability, "score": capability, "rubric_score": capability,
        "completion_score": capability, "completion_dimension_schema": DIMENSION_VERSION,
        "completion_dimensions": project_completion(task["scoring_components"], criteria,
                                                     scoring_contract=scoring_contract,
                                                     dimension_weights=task.get("dimension_weights")),
        "criterion_dimensions": {c["id"]: c["dimension"] for c in task["scoring_components"]},
        "legacy_dimension_fields": ["criterion_results", "dimension_weights", "dimension_scores", "dimension_weight_sums"],
        "robustness_extension": {"scope": "cross_trial", "status": "not_computed"},
        "strict_success": strict, "passed": strict, "overall_task_success": strict,
        "weighted_scoring_executed": True, "atomic_criteria": criteria,
        "criterion_ownership": {c["id"]: c["owner"] for c in task["scoring_components"]},
        "criterion_results": groups, "dimension_weights": weights, "dimension_scores": dimensions,
        "dimension_weight_sums": {k: math.fsum(c["weight"] for c in v) for k, v in groups.items()},
        "failure_reason": failures, "critical_failure_triggered": graded.critical_failures,
        "mandatory_critical_violations": graded.mandatory_violations,
        "deterministic_checks": graded.diagnostics,
        "safety_score": int(not graded.critical_failures), "safety_pass": not graded.critical_failures,
        "final_state_score": state_score, "final_state_success": state_success,
        "final_state_components": state_components, "action_checks": state_criteria,
        "semantic_completion": all(c["passed"] for c in content),
        "semantic_completion_checks": [{"constraint": c["id"], "atomic_id": c["id"], **c} for c in content],
        "judge_summary": judge_summary,
    }
