"""Stable Standard Run Artifact contract for CamAct experiments.

The contract deliberately contains execution facts only.  Ground truth,
rubrics, and evaluator output are kept outside the artifact so every harness
enters the same scoring path.
"""
from __future__ import annotations

import json
import math
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping


SCHEMA_VERSION = "camact.standard_run_artifact.v1"


class ArtifactValidationError(ValueError):
    """Raised when an artifact does not satisfy the standard contract."""


def _json_safe(value: Any) -> Any:
    if isinstance(value, float) and not math.isfinite(value):
        raise ArtifactValidationError("artifact contains a non-finite number")
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


@dataclass
class StandardRunArtifact:
    """One terminal task execution in the harness-independent format."""

    schema_version: str = SCHEMA_VERSION
    user_id: str = ""
    task_id: str = ""
    task: str | None = None
    run: dict[str, Any] = field(default_factory=dict)
    method: str = ""
    model: dict[str, Any] = field(default_factory=dict)
    model_policy: dict[str, Any] = field(default_factory=dict)
    final_response: str = ""
    evidence: list[Any] = field(default_factory=list)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    actions: list[dict[str, Any]] = field(default_factory=list)
    final_state: dict[str, Any] = field(default_factory=dict)
    simulator: dict[str, Any] = field(default_factory=dict)
    errors: dict[str, Any] = field(default_factory=dict)
    token_usage: dict[str, Any] = field(default_factory=dict)
    model_calls: list[dict[str, Any]] = field(default_factory=list)
    timing: dict[str, Any] = field(default_factory=dict)
    diagnostics: dict[str, Any] = field(default_factory=dict)
    # Episode evidence is optional for historical artifacts, lossless for new runs.
    execution_trace: list[dict[str, Any]] = field(default_factory=list)
    action_audit: list[dict[str, Any]] = field(default_factory=list)
    conversation: list[dict[str, Any]] = field(default_factory=list)
    final_service_state: dict[str, Any] = field(default_factory=dict)
    service_audit: dict[str, Any] = field(default_factory=dict)
    runtime_metadata: dict[str, Any] = field(default_factory=dict)
    # Optional derived measurement layer; old artifacts remain readable.
    measurement: dict[str, Any] = field(default_factory=dict)
    # Trusted execution sidecar; never supplied as an agent tool result.
    visual_evidence: dict[str, Any] = field(default_factory=dict)
    trajectory_class: str = "finished"

    REQUIRED_FIELDS = (
        "schema_version",
        "user_id",
        "task_id",
        "run",
        "method",
        "model",
        "final_response",
        "evidence",
        "tool_calls",
        "actions",
        "final_state",
        "simulator",
        "errors",
        "token_usage",
        "model_calls",
        "timing",
        "diagnostics",
        "trajectory_class",
    )
    TRAJECTORY_CLASSES = {
        "finished",
        "agent_failure",
        "infrastructure_failure",
        "harness_failure",
    }

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ArtifactValidationError(
                f"unsupported schema_version: {self.schema_version!r}"
            )
        for name in ("user_id", "task_id", "method"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name).strip():
                raise ArtifactValidationError(f"{name} must be a non-empty string")
        if self.trajectory_class not in self.TRAJECTORY_CLASSES:
            raise ArtifactValidationError(
                f"trajectory_class must be one of {sorted(self.TRAJECTORY_CLASSES)}"
            )
        if self.task is not None and not isinstance(self.task, str):
            raise ArtifactValidationError("task must be a string or null")
        if not isinstance(self.final_response, str):
            raise ArtifactValidationError("final_response must be a string")
        if not isinstance(self.run, dict) or not isinstance(self.model, dict) or not isinstance(self.model_policy, dict):
            raise ArtifactValidationError("run, model, and model_policy must be objects")
        if not isinstance(self.measurement, dict):
            raise ArtifactValidationError("measurement must be an object")
        if not isinstance(self.visual_evidence, dict):
            raise ArtifactValidationError("visual_evidence must be an object")
        if self.visual_evidence:
            from benchmark.evaluator.visual_evidence import validate_document
            try:
                validate_document(self.visual_evidence)
            except ValueError as exc:
                raise ArtifactValidationError(str(exc)) from exc
        sequence_fields = ("evidence", "tool_calls", "actions", "model_calls", "execution_trace", "action_audit", "conversation")
        for name in sequence_fields:
            value = getattr(self, name)
            if not isinstance(value, list):
                raise ArtifactValidationError(f"{name} must be an array")
            if name != "evidence" and any(not isinstance(item, dict) for item in value):
                raise ArtifactValidationError(f"{name} entries must be objects")
        for name in ("tool_calls", "actions", "model_calls"):
            for item in getattr(self, name):
                if "arguments" in item and not isinstance(item["arguments"], dict):
                    raise ArtifactValidationError(f"{name}.arguments must be an object when present")
        object_fields = (
            "final_state",
            "final_service_state",
            "service_audit",
            "runtime_metadata",
            "simulator",
            "errors",
            "token_usage",
            "timing",
            "diagnostics",
        )
        for name in object_fields:
            if not isinstance(getattr(self, name), dict):
                raise ArtifactValidationError(f"{name} must be an object")
        usage = self.token_usage
        for name in ("input_tokens", "output_tokens", "total_tokens"):
            if name in usage:
                value = usage[name]
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise ArtifactValidationError(f"token_usage.{name} must be a non-negative integer")
        if "cost_usd" in usage:
            value = usage["cost_usd"]
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, (int, float))
                or not math.isfinite(float(value)) or value < 0
            ):
                raise ArtifactValidationError("token_usage.cost_usd must be a non-negative finite number or null")
        _json_safe(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return _json_safe(asdict(self))

    def document_for_path(self, path: Path) -> dict[str, Any]:
        """Serialize runner-owned visual sources relative to their artifact file.

        The in-memory contract uses resolved paths. A saved artifact must travel
        with its session, without retaining the old temporary directory. Wire
        bytes and hashes are untouched; the evaluator still rebuilds evidence.
        """
        value = self.to_dict()
        value["visual_evidence"] = visual_paths(value["visual_evidence"], Path(path), relative=True)
        return value

    def write(self, path: Path) -> None:
        self.validate()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.document_for_path(path), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any], *, strict: bool = True
    ) -> "StandardRunArtifact":
        if not isinstance(value, Mapping):
            raise ArtifactValidationError("artifact must be a JSON object")
        missing = [name for name in cls.REQUIRED_FIELDS if name not in value]
        if strict and missing:
            raise ArtifactValidationError(
                "artifact is missing required fields: " + ", ".join(missing)
            )
        data = dict(value)
        # Non-strict loading is used only by adapters, which fill defaults for
        # older or third-party output before it reaches the stable contract.
        defaults: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "task": None,
            "run": {},
            "method": "unknown",
            "model": {},
            "model_policy": {},
            "final_response": "",
            "evidence": [],
            "tool_calls": [],
            "actions": [],
            "final_state": {},
            "simulator": {},
            "errors": {},
            "token_usage": {},
            "model_calls": [],
            "timing": {},
            "diagnostics": {},
            "measurement": {},
            "trajectory_class": "finished",
        }
        for key, default in defaults.items():
            data.setdefault(key, default)
        allowed = {field.name for field in dataclass_fields(cls)}
        unknown = set(data) - allowed
        # Preserve forward-compatible fields under diagnostics rather than
        # silently dropping telemetry supplied by a newer harness.
        if unknown:
            diagnostics = dict(data.get("diagnostics") or {})
            diagnostics.setdefault("extra_fields", {}).update(
                {key: data.pop(key) for key in sorted(unknown)}
            )
            data["diagnostics"] = diagnostics
        return cls(**{key: data[key] for key in allowed if key in data})

    @classmethod
    def read(cls, path: Path, *, strict: bool = True) -> "StandardRunArtifact":
        value = json.loads(path.read_text(encoding="utf-8"))
        value["visual_evidence"] = visual_paths(value.get("visual_evidence", {}), path)
        return cls.from_dict(value, strict=strict)


def visual_paths(evidence: Mapping[str, Any], source: Path, *, relative: bool = False) -> dict[str, Any]:
    """Resolve portable sidecar references, accepting legacy absolute paths."""
    from .visual_capture import native_capture_path

    fields = {"capture_root", "originals_root", "source_request", "source_response"}
    base = Path(source).resolve().parent

    def visit(value: Any, *, snapshot: bool = False) -> Any:
        if isinstance(value, list):
            return [visit(item, snapshot=snapshot) for item in value]
        if not isinstance(value, Mapping):
            return value
        result = {}
        for key, item in value.items():
            if (key in fields or (key == "path" and snapshot)) and isinstance(item, str) and item:
                path = Path(native_capture_path(item))
                path = path if path.is_absolute() else base / path
                if relative:
                    try:
                        result[key] = Path(os.path.relpath(path.resolve(), base)).as_posix()
                    except ValueError:  # A legacy source on another drive.
                        result[key] = str(path.resolve())
                else:
                    result[key] = str(path.resolve())
            else:
                result[key] = visit(item, snapshot=key == "source_episode_snapshots")
        return result

    return visit(evidence)


def dataclass_fields(cls: type[StandardRunArtifact]):
    """Small indirection keeps ``from_dict`` readable and testable."""
    from dataclasses import fields

    return fields(cls)


def validate_artifact_document(value: Mapping[str, Any]) -> StandardRunArtifact:
    """Strict public validation helper used by adapters and CLI."""
    return StandardRunArtifact.from_dict(value, strict=True)


def validate_evaluation_result_document(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the stable result envelope while keeping diagnostics extensible."""
    if not isinstance(value, Mapping):
        raise ArtifactValidationError("evaluation result must be a JSON object")
    if value.get("schema_version") != "camact.standard_evaluation_result.v1":
        raise ArtifactValidationError("unsupported evaluation result schema_version")
    evaluations = value.get("evaluations")
    summary = value.get("summary")
    if not isinstance(evaluations, list) or not isinstance(summary, Mapping):
        raise ArtifactValidationError("evaluations must be an array and summary must be an object")
    required_item = (
        "task_id", "user_id", "status", "capability_score", "strict_success",
        "safety_score", "final_state_score", "agent_failure",
        "infrastructure_failure", "trajectory_class", "criterion_results",
    )
    for index, item in enumerate(evaluations):
        if not isinstance(item, Mapping):
            raise ArtifactValidationError(f"evaluations[{index}] must be an object")
        missing = [name for name in required_item if name not in item]
        if missing:
            raise ArtifactValidationError(f"evaluations[{index}] missing required fields: {', '.join(missing)}")
        if not isinstance(item["task_id"], str) or not isinstance(item["user_id"], str):
            raise ArtifactValidationError(f"evaluations[{index}] task_id/user_id must be strings")
        for name in ("strict_success", "agent_failure", "infrastructure_failure"):
            if not isinstance(item[name], bool):
                raise ArtifactValidationError(f"evaluations[{index}].{name} must be boolean")
        if not isinstance(item["criterion_results"], Mapping):
            raise ArtifactValidationError(f"evaluations[{index}].criterion_results must be an object")
    for name in (
        "total_tasks", "evaluated_tasks", "strict_success_count",
        "agent_failure_count", "infrastructure_failure_count",
    ):
        if name not in summary or isinstance(summary[name], bool) or not isinstance(summary[name], int) or summary[name] < 0:
            raise ArtifactValidationError(f"summary.{name} must be a non-negative integer")
    return dict(value)
