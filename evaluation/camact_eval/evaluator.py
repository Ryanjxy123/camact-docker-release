"""Harness-independent evaluation bridge to the canonical CamAct evaluator."""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from benchmark.evaluator.evaluate import (  # noqa: E402
    evaluate as canonical_evaluate,
)
from benchmark.evaluator.judge import JudgeBatchResult  # noqa: E402
from benchmark.evaluator.dimensions import DIMENSION_VERSION, project_completion

from .adapters import _task_dir
from .schema import StandardRunArtifact


@dataclass
class ReplayJudge:
    """Replay a previously recorded semantic-judge response for compatibility.

    This is intentionally opt-in. New semantic/visual evaluations use ``env``;
    ``off`` is valid only when no required criterion needs a Judge call.
    """

    legacy_evaluation: dict[str, Any]

    def evaluate_batch(self, criterion_rubric: list[dict[str, Any]]) -> JudgeBatchResult:
        evaluation = self.legacy_evaluation
        raw = (
            evaluation.get("judge_summary", {})
            .get("audit", {})
            .get("raw_output", "")
        )
        parsed: dict[str, dict[str, Any]] = {}
        if isinstance(raw, str) and raw.strip():
            try:
                payload = json.loads(raw)
                parsed.update(
                    {
                        str(item["criterion_id"]): item
                        for item in payload.get("criterion_results", [])
                        if isinstance(item, dict) and item.get("criterion_id")
                    }
                )
            except (json.JSONDecodeError, AttributeError, TypeError):
                pass
        for results in evaluation.get("criterion_results", {}).values():
            if not isinstance(results, list):
                continue
            for item in results:
                if not isinstance(item, dict):
                    continue
                score = item.get("judge_score")
                base_id = str(item.get("id", ""))
                if score is not None and base_id:
                    parsed.setdefault(
                        base_id,
                        {
                            "criterion_id": base_id,
                            "score": float(score),
                            "evidence": item.get("judge_evidence") or ["replayed legacy judge decision"],
                            "reason": item.get("judge_reason") or "replayed legacy judge decision",
                        },
                    )
                for nested in item.get("judge_role_results", []):
                    if isinstance(nested, dict) and nested.get("criterion_id"):
                        parsed.setdefault(str(nested["criterion_id"]), nested)
        for item in evaluation.get("semantic_completion_checks", []):
            if isinstance(item, dict) and item.get("constraint", "").startswith("core_output_completion") and item.get("score") is not None:
                identity = item["constraint"]
                parsed[identity] = {"criterion_id": identity, "score": item["score"],
                                    "reason": item.get("reason", "replayed output content decision"),
                                    "evidence": item.get("evidence", [])}
        results: dict[str, dict[str, Any]] = {}
        for item in criterion_rubric:
            criterion_id = str(item["criterion_id"])
            value = parsed.get(criterion_id)
            if value is None:
                raise ValueError(f"legacy evaluation has no judge result for {criterion_id}")
            results[criterion_id] = {
                "criterion_id": criterion_id,
                "score": float(value["score"]),
                "evidence": list(value.get("evidence") or ["replayed legacy judge decision"]),
                "reason": str(value.get("reason") or "replayed legacy judge decision"),
            }
        return JudgeBatchResult(
            results=results,
            audit={"status": "replayed", "source": "legacy_evaluation"},
        )

    # SemanticJudge-compatible entry point.  The canonical evaluator passes
    # ``criterion_rubric`` as a keyword, so this delegates to evaluate_batch.
    def __call__(self, **kwargs: Any) -> JudgeBatchResult:
        return self.evaluate_batch(kwargs["criterion_rubric"])


class _ReplayJudgeProxy:
    def __init__(self, judge: ReplayJudge, *, scoring_contract: str) -> None:
        from benchmark.evaluator.contracts import SUPPORTED_VERSIONS
        if scoring_contract not in SUPPORTED_VERSIONS:
            raise ValueError("unsupported replay scoring protocol")
        if judge.legacy_evaluation.get("scoring_contract") != scoring_contract:
            raise ValueError("recorded Judge scoring protocol differs from the current task; cross-protocol replay is not permitted")
        self.judge = judge
        self.scoring_contract = scoring_contract

    def evaluate(self, **kwargs: Any) -> JudgeBatchResult:
        from benchmark.evaluator.grading import request_fingerprint
        recorded = self.judge.legacy_evaluation
        if recorded.get("scoring_contract") != self.scoring_contract:
            raise ValueError("recorded Judge scoring protocol changed after replay initialization")
        fingerprint = request_fingerprint(kwargs)
        calls = recorded.get("judge_summary", {}).get("calls", [])
        matches = [c for c in calls if c.get("request_sha256") == fingerprint and c.get("status") == "succeeded"]
        if len(matches) != 1:
            raise ValueError("recorded Judge decision is missing or ambiguous for this criterion/evidence")
        decision = matches[0]["result"]
        return JudgeBatchResult(results={decision["criterion_id"]: decision},
                                audit={"status": "replayed", "request_sha256": fingerprint})


def _submission(artifact: StandardRunArtifact) -> dict[str, Any]:
    # camact.episode.v1 snapshots are stateful Runtime executions. Preserve that
    # contract at the Task-grader boundary; some graders explicitly require the
    # mode in addition to the session identity. Never infer it for unbound state.
    execution_mode = artifact.runtime_metadata.get("execution_mode")
    session_id = artifact.runtime_metadata.get("session_id")
    if (execution_mode is None and session_id
            and artifact.runtime_metadata.get("episode_contract") == "camact.episode.v1"
            and artifact.runtime_metadata.get("snapshot_complete") is True
            and artifact.final_state.get("session", {}).get("id") == session_id):
        execution_mode = "stateful_runtime"
    return {
        "task_id": artifact.task_id,
        "status": artifact.runtime_metadata.get("status"),
        "final_response": artifact.final_response,
        "final_answer": artifact.final_response,
        "final_environment": {k: v for k, v in artifact.final_state.items() if k != "user_simulator"},
        "conversation": artifact.conversation,
        "evidence": artifact.evidence,
        "visual_evidence": artifact.visual_evidence,
        # Graders consume the canonical Runtime projection.  Adapter tracking
        # fields (call ids, raw payloads, timing, etc.) remain available on the
        # artifact but must not participate in the strict tool-call contract.
        "tool_calls": [
            {
                "tool": call.get("tool"),
                "arguments": call.get("arguments", {}) if isinstance(call.get("arguments", {}), dict) else {},
                "status": call.get("status"),
            }
            for call in artifact.tool_calls
            if isinstance(call, dict)
        ],
        "actions": artifact.actions,
        "conversation_trace": artifact.conversation or artifact.diagnostics.get("conversation_trace", []),
        "execution_trace": artifact.execution_trace or artifact.diagnostics.get("execution_trace", []),
        "action_audit": artifact.action_audit,
        "final_service_state": artifact.final_service_state,
        "service_audit": artifact.service_audit,
        "runtime_metadata": artifact.runtime_metadata,
        "trajectory_class": artifact.trajectory_class,
        "errors": artifact.errors,
        "session_id": artifact.runtime_metadata.get("session_id"),
        "execution_mode": execution_mode,
        "identity_claims": artifact.diagnostics.get("identity_claims", []),
        "clarifications": artifact.diagnostics.get("clarifications", []),
        "observed_constraints": artifact.diagnostics.get("observed_constraints", {}),
    }


def _failure_result(artifact: StandardRunArtifact, *, infrastructure: bool = False, error: str | None = None) -> dict[str, Any]:
    status = "infrastructure_error" if infrastructure else "failed"
    return {
        "task_id": artifact.task_id,
        "user_id": artifact.user_id,
        "method": artifact.method,
        "status": status,
        "score": None if infrastructure else 0.0,
        "passed": False,
        "capability_score": None if infrastructure else 0.0,
        "completion_score": None if infrastructure else 0.0,
        "completion_dimension_schema": DIMENSION_VERSION,
        "completion_dimensions": project_completion([], []),
        "robustness_extension": {"scope": "cross_trial", "status": "not_computed"},
        "strict_success": False,
        "comparable": not infrastructure,
        "failure_type": "infrastructure_failure" if infrastructure else "agent_failure",
        "safety_score": None if infrastructure else 1.0,
        "failure_reason": [{"type": "infrastructure_failure" if infrastructure else "agent_failure", "message": error or "artifact terminal failure"}],
        "critical_failure_triggered": [],
        "weighted_scoring_executed": False,
        "final_state_score": None if infrastructure else 0.0,
        "final_state_components": {},
        "criterion_results": {},
        "action_checks": [],
        "agent_failure": not infrastructure,
        "infrastructure_failure": infrastructure,
        "trajectory_class": "infrastructure_failure" if infrastructure else artifact.trajectory_class,
    }


class UnifiedEvaluator:
    """Score Standard Run Artifacts against immutable benchmark task files."""

    def __init__(self, benchmark_root: Path | None = None, judge: str = "off") -> None:
        self.benchmark_root = (benchmark_root or _REPO_ROOT).resolve()
        self.judge_mode = judge
        if judge not in {"off", "env", "replay"}:
            raise ValueError("judge must be one of: off, env, replay")

    def evaluate(self, artifact: StandardRunArtifact) -> dict[str, Any]:
        from benchmark.services.episode import episode_error
        invalid = episode_error(_submission(artifact), artifact.final_state)
        if invalid or artifact.trajectory_class in {"infrastructure_failure", "harness_failure"}:
            return _failure_result(artifact, infrastructure=True, error=invalid or "non-scorable execution")
        task_dir = _task_dir(
            self.benchmark_root,
            user_id=artifact.user_id,
            task=artifact.task.rsplit("/", 1)[-1] if artifact.task else None,
            task_id=artifact.task_id,
        )
        if task_dir is None:
            return _failure_result(artifact, infrastructure=True, error=f"benchmark task not found: {artifact.user_id}/{artifact.task_id}")
        judge: Any = False
        if self.judge_mode == "env":
            judge = None
        elif self.judge_mode == "replay":
            legacy = artifact.diagnostics.get("legacy_evaluation")
            if isinstance(legacy, dict):
                from benchmark.evaluator.contracts import load_contract
                try:
                    protocol = load_contract(task_dir)["scoring_contract"]
                    judge = _ReplayJudgeProxy(ReplayJudge(legacy), scoring_contract=protocol)
                except (OSError, ValueError, KeyError, TypeError) as exc:
                    return _failure_result(artifact, infrastructure=True, error=f"{type(exc).__name__}: {exc}")
            else:
                judge = False
        try:
            result = canonical_evaluate(task_dir, _submission(artifact), artifact.final_state, judge=judge)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            return _failure_result(artifact, infrastructure=True, error=f"{type(exc).__name__}: {exc}")
        # Replay only supplies historical criterion-level judge decisions via
        # ReplayJudge above. All aggregate, strict-success, safety, and final
        # state fields are recomputed by the current canonical evaluator.
        result = dict(result)
        result.update(
            {
                "user_id": artifact.user_id,
                "method": artifact.method,
                "artifact_schema_version": artifact.schema_version,
                "trajectory_class": artifact.trajectory_class,
                "agent_failure": artifact.trajectory_class == "agent_failure",
                "infrastructure_failure": bool(result.get("status") == "infrastructure_error" or result.get("evaluation_infrastructure_failure")),
            }
        )
        if result["infrastructure_failure"]:
            result["agent_failure"] = False
        return result

    def evaluate_many(self, artifacts: Iterable[StandardRunArtifact]) -> list[dict[str, Any]]:
        return [self.evaluate(artifact) for artifact in artifacts]


def compatibility_diff(artifact: StandardRunArtifact, result: Mapping[str, Any]) -> dict[str, Any]:
    """Compare stable task-level fields with a legacy canonical evaluation."""
    legacy = artifact.diagnostics.get("legacy_evaluation")
    if not isinstance(legacy, dict):
        return {"available": False, "matches": None, "differences": []}
    comparisons = {
        "capability_score": (legacy.get("capability_score", legacy.get("score")), result.get("capability_score", result.get("score"))),
        "rubric_score": (legacy.get("rubric_score", legacy.get("capability_score", legacy.get("score"))), result.get("rubric_score", result.get("capability_score", result.get("score")))),
        "strict_success": (legacy.get("strict_success", legacy.get("passed")), result.get("strict_success", result.get("passed"))),
        "safety_score": (legacy.get("safety_score"), result.get("safety_score")),
        "final_state_score": (legacy.get("final_state_score"), result.get("final_state_score")),
        "status": (legacy.get("status"), result.get("status")),
    }
    differences = []
    for field, (old, new) in comparisons.items():
        if isinstance(old, (int, float)) and isinstance(new, (int, float)):
            if abs(float(old) - float(new)) > 1e-4:
                differences.append({"field": field, "legacy": old, "unified": new})
        elif old != new:
            differences.append({"field": field, "legacy": old, "unified": new})
    return {"available": True, "matches": not differences, "differences": differences}
