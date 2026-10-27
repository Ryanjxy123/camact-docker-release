"""Task-owned scoring declarations and Claw-Eval-style local grader loading.

No task requirements are inferred here. Migration/authoring writes them once to
task.yaml; evaluation validates and executes that frozen declaration.
"""
from __future__ import annotations

import importlib.util
import math
from pathlib import Path

import yaml

from .dimensions import DIMENSIONS

LEGACY_VERSION = "camact.atomic.v2"
VERSION = "camact.atomic.v3"
SUPPORTED_VERSIONS = {LEGACY_VERSION, VERSION}
CHECK_TYPES = {"deterministic", "semantic_judge", "visual_judge"}


def _two_ternary_checklist_judge(check):
    """Recognize only the task's explicit two-part checklist Judge protocol."""
    if check.get("type") != "semantic_judge" or check.get("checker") != "checklist_structure":
        return False
    params = check.get("params")
    if not isinstance(params, dict) or params.get("aggregation") != "mean_two_ternary":
        return False
    children = params.get("subcriteria")
    if not isinstance(children, list) or len(children) != 2:
        return False
    identities = []
    for child in children:
        if not isinstance(child, dict):
            return False
        identity, values = child.get("criterion_id"), child.get("score_values")
        if (not isinstance(identity, str) or not identity.strip()
                or not isinstance(values, list) or values != [0, 0.5, 1]
                or any(type(value) not in (int, float) for value in values)):
            return False
        identities.append(identity.strip())
    return len(set(identities)) == 2


def score_values(component, *, scoring_contract=LEGACY_VERSION):
    if not isinstance(component, dict) or not isinstance(component.get("check", {}), dict):
        raise ValueError("score declaration and check must be objects")
    values = component.get("score_values", [0, 1])
    check = component.get("check", {})
    check_type = check.get("type", component.get("check_type"))
    # A range is an explicit deterministic opt-in. Its score_values are bounds,
    # not a discrete enumeration; ordinary v2/v3 checks retain their old rules.
    if "score_range" in component:
        bounds = component["score_range"]
        if (check_type != "deterministic" or values != [0, 1]
                or any(type(value) not in (int, float) for value in values)
                or not isinstance(bounds, dict) or set(bounds) != {"minimum", "maximum"}
                or any(type(bounds[k]) not in (int, float) for k in bounds)
                or bounds != {"minimum": 0, "maximum": 1}
                or check.get("checker") == "photo_target"):
            raise ValueError("score_range requires an explicit deterministic 0..1 range; photo_target stays binary")
        return values
    # Count-based thirds and quarters are opt-in deterministic checks only.
    deterministic_fraction = check_type == "deterministic" and values in (
        [0, 1 / 3, 2 / 3, 1], [0, 0.25, 0.5, 0.75, 1],
    )
    composite_judge_fraction = (values == [0, 0.25, 0.5, 0.75, 1]
                               and _two_ternary_checklist_judge(check))
    if (not isinstance(values, list) or any(isinstance(v, bool) for v in values)
            or (values not in ([0, 1], [0, 0.5, 1]) and not deterministic_fraction and not composite_judge_fraction)):
        raise ValueError("score_values must declare binary/three-level scores, explicit deterministic thirds/quarters, "
                         "or the explicit two-ternary checklist Judge mean")
    if scoring_contract == VERSION and check_type == "deterministic" and values != [0, 1]:
        raise ValueError("v3 deterministic Atomic Checks must declare binary score_values")
    return values


def score_allowed(component, score, *, scoring_contract=LEGACY_VERSION):
    values = score_values(component, scoring_contract=scoring_contract)
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score):
        return False
    if "score_range" in component:
        return component["score_range"]["minimum"] <= score <= component["score_range"]["maximum"]
    return score in values


def validate_dimension_weights(dimension_weights, components):
    """Validate the explicit v3 outer weights; no implicit count-based fallback."""
    dimensions = {item.get("dimension") for item in components}
    if not isinstance(dimension_weights, dict) or set(dimension_weights) != dimensions:
        raise ValueError("dimension_weights must cover exactly the active criterion dimensions")
    for dimension, weight in dimension_weights.items():
        if (dimension not in DIMENSIONS or isinstance(weight, bool)
                or not isinstance(weight, (int, float)) or not math.isfinite(weight)
                or not 0 < weight <= 1
                or not math.isclose(weight * 20, round(weight * 20), rel_tol=0, abs_tol=1e-12)):
            raise ValueError("dimension weights must be positive 5% increments")
    if not math.isclose(math.fsum(dimension_weights.values()), 1.0, rel_tol=0, abs_tol=1e-12):
        raise ValueError("dimension weights must total 100%")
    outcome = dimension_weights.get("outcome_correctness", 0)
    if outcome < 0.65 or outcome < max(dimension_weights.values()):
        raise ValueError("Outcome Correctness must be the largest dimension and at least 65%")
    return dimension_weights


def validate_components(components: list[dict], *, scoring_contract=LEGACY_VERSION) -> None:
    if scoring_contract not in SUPPORTED_VERSIONS:
        raise ValueError("unsupported scoring_contract")
    if not isinstance(components, list) or not components:
        raise ValueError("scoring_components must be a non-empty list")
    ids, owners = set(), set()
    for item in components:
        if not isinstance(item, dict):
            raise ValueError("each scoring component must be an object")
        for field in ("id", "owner", "description"):
            if not isinstance(item.get(field), str) or not item[field].strip():
                raise ValueError(f"scoring component requires {field}")
        if item["id"] in ids or item["owner"] in owners:
            raise ValueError("duplicate criterion ID or canonical owner")
        ids.add(item["id"])
        owners.add(item["owner"])
        if not isinstance(item.get("dimension"), str) or item["dimension"] not in DIMENSIONS:
            raise ValueError("criterion requires exactly one supported Completion dimension")
        score_values(item, scoring_contract=scoring_contract)
        weight = item.get("weight")
        if isinstance(weight, bool) or not isinstance(weight, (int, float)) or not math.isfinite(weight) or weight <= 0:
            raise ValueError("criterion weight must be finite and positive")
        if scoring_contract == VERSION and (type(weight) is not float or weight != 1.0):
            raise ValueError("v3 independent Atomic Checks must have raw weight=1.0")
        if type(item.get("mandatory")) is not bool:
            raise ValueError("mandatory must be declared by the task author")
        check = item.get("check", {})
        if check.get("type") not in CHECK_TYPES or not check.get("checker") or not isinstance(check.get("params"), dict):
            raise ValueError("criterion requires a supported check type, checker and params")
        if not isinstance(item.get("evidence_requirements"), dict) or not item["evidence_requirements"].get("source"):
            raise ValueError("criterion requires an explicit evidence selector")
        if check["type"] != "deterministic":
            rubric = item.get("rubric", "")
            if not isinstance(rubric, str) or not all(part in rubric for part in ("Criterion:", "Evidence:", "PASS:", "FAIL:", "Output:")):
                raise ValueError("Judge criterion requires a scoped rubric")
    if scoring_contract == VERSION:
        validate_photo_targets(components)


def validate_photo_targets(components):
    """Each effective photo target has exactly one row sharing one matching graph.

    A matching helper is safe only if every criterion uses the same graph. This
    prevents a malformed author contract from rewarding one photo twice across
    individually valid calls. Separate future selection goals need an explicit
    grouped protocol rather than quietly bypassing this invariant.
    """
    photos = [item for item in components if item["check"]["checker"] == "photo_target"]
    if not photos:
        return
    from .photo_targets import maximum_target_matching
    graph, declared = None, set()
    for component in photos:
        if component["check"]["type"] != "deterministic" or score_values(component) != [0, 1]:
            raise ValueError("photo_target must be an independent deterministic binary Atomic Check")
        params = component["check"]["params"]
        targets = params.get("targets")
        # Validate target identities and pools without requiring a delivered image.
        probe = next(iter(targets[0].get("accepted_images", targets[0].get("accepted_photo_ids"))), "__probe__")
        maximum_target_matching([probe], targets)
        normalized = tuple(sorted((target.get("id", target.get("target_id")),
                                   tuple(sorted(set(target.get("accepted_images", target.get("accepted_photo_ids"))))))
                                  for target in targets))
        if graph is None:
            graph = normalized
        elif normalized != graph:
            raise ValueError("all photo_target rows must share the same target matching graph")
        identity = params.get("target_id")
        if identity not in {target[0] for target in graph} or identity in declared:
            raise ValueError("each photo_target row must own a unique declared target_id")
        declared.add(identity)
    if declared != {target[0] for target in graph}:
        raise ValueError("photo_target rows must cover every effective target exactly once")


def load_contract(task_dir: Path) -> dict:
    task = yaml.safe_load((task_dir / "task.yaml").read_text(encoding="utf-8"))
    if not isinstance(task, dict) or task.get("scoring_contract") not in SUPPORTED_VERSIONS:
        raise ValueError(f"task must explicitly declare {LEGACY_VERSION} or {VERSION}")
    validate_components(task.get("scoring_components"), scoring_contract=task["scoring_contract"])
    if task["scoring_contract"] == VERSION:
        validate_dimension_weights(task.get("dimension_weights"), task["scoring_components"])
    if task.get("grader") != "grader.py":
        raise ValueError("task must name its local grader.py")
    if not isinstance(task.get("reference_solution"), dict):
        raise ValueError("task must declare its reference_solution")
    if not isinstance(task.get("safety_checks"), list):
        raise ValueError("task must declare safety_checks")
    return task


def load_grader(task_dir: Path, task: dict):
    """Adapt Claw-Eval graders/base.py's explicit task-local module loading."""
    path = task_dir / task["grader"]
    spec = importlib.util.spec_from_file_location(f"camact_grader_{task['task_id']}", path)
    if spec is None or spec.loader is None:
        raise ValueError(f"Cannot load task grader: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from .datetime_compat import bind_grader_datetime
    bind_grader_datetime(module)
    if getattr(module, "TASK_ID", None) != task["task_id"]:
        raise ValueError("task grader identity does not match scoring contract")
    grader = module.TaskGrader()
    if not callable(getattr(grader, "grade", None)):
        raise ValueError("task grader must implement grade()")
    return grader


def validate_results(components: list[dict], results: list[dict], *, scoring_contract=LEGACY_VERSION) -> None:
    """A grader may report decisions, never add owners or change author weights."""
    validate_components(components, scoring_contract=scoring_contract)
    if not isinstance(results, list) or len(results) != len(components):
        raise ValueError("grader must return exactly one result for every component")
    expected = {item["id"]: item for item in components}
    seen = set()
    for result in results:
        identity = result.get("id")
        if identity not in expected or identity in seen:
            raise ValueError("unexpected, missing or duplicate criterion result")
        seen.add(identity)
        component = expected[identity]
        if "dimension" in result and result["dimension"] != component["dimension"]:
            raise ValueError("grader changed task-owned dimension")
        for field in ("owner", "weight", "mandatory"):
            if type(result.get(field)) is not type(component[field]) or result[field] != component[field]:
                raise ValueError(f"grader changed task-owned {field} for {identity}")
        score = result.get("score")
        values = score_values(component, scoring_contract=scoring_contract)
        if result.get("score_values", [0, 1]) != values:
            raise ValueError("grader changed task-owned score_values")
        if result.get("score_range") != component.get("score_range"):
            raise ValueError("grader changed task-owned score_range")
        if not score_allowed(component, score, scoring_contract=scoring_contract):
            raise ValueError("atomic criterion score must satisfy its task-owned score declaration")
        if type(result.get("passed")) is not bool or result["passed"] != (score == 1):
            raise ValueError("passed must mean full credit (score=1)")
        if not isinstance(result.get("reason"), str) or not result["reason"].strip():
            raise ValueError("criterion result needs an audit reason")
        if not isinstance(result.get("evidence"), list):
            raise ValueError("criterion result evidence must be a list")
