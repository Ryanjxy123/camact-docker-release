"""Shared scoring with explicit discrete/range contracts owned by task.yaml."""
from __future__ import annotations

import math

from .contracts import LEGACY_VERSION, VERSION, SUPPORTED_VERSIONS, score_allowed, validate_dimension_weights


def aggregate(criteria, *, safety_pass=True, episode_valid=True,
              scoring_contract=LEGACY_VERSION, dimension_weights=None):
    """Score the explicitly selected protocol; unversioned calls retain v2.

    v2 keeps historical flat weighting. v3 averages equal Atomic Checks inside
    each dimension before applying the declared outer dimension percentages.
    """
    if scoring_contract not in SUPPORTED_VERSIONS:
        raise ValueError("unsupported scoring_contract")
    if not criteria or len({item["id"] for item in criteria}) != len(criteria):
        raise ValueError("atomic criteria must have unique identities and cannot be empty")
    owners = [item.get("owner", item["id"]) for item in criteria]
    if len(set(owners)) != len(owners):
        raise ValueError("duplicate canonical owner")
    for item in criteria:
        score, weight = item["score"], item["weight"]
        if not score_allowed(item, score, scoring_contract=scoring_contract):
            raise ValueError("atomic score must satisfy its task-owned score declaration")
        if isinstance(weight, bool) or not isinstance(weight, (int, float)) or not math.isfinite(weight) or weight <= 0:
            raise ValueError("invalid atomic criterion weight")
        if scoring_contract == VERSION and (type(weight) is not float or weight != 1.0):
            raise ValueError("v3 independent Atomic Checks must have raw weight=1.0")
        if type(item.get("mandatory")) is not bool:
            raise ValueError("mandatory must be explicit")
        if type(item.get("passed")) is not bool or item["passed"] != (score == 1):
            raise ValueError("passed disagrees with score")
    if scoring_contract == VERSION:
        validate_dimension_weights(dimension_weights, criteria)
        counts = {dimension: sum(item["dimension"] == dimension for item in criteria)
                  for dimension in dimension_weights}
        normalized = [dimension_weights[item["dimension"]] / counts[item["dimension"]]
                      for item in criteria]
    else:
        total = math.fsum(item["weight"] for item in criteria)
        if not math.isfinite(total):
            raise ValueError("invalid total criterion weight")
        normalized = [item["weight"] / total for item in criteria]
    for item, weight in zip(criteria, normalized):
        item["normalized_weight"] = weight
        item["contribution"] = item["normalized_weight"] * item["score"]
    if scoring_contract == VERSION:
        capability = math.fsum(dimension_weights[dimension]
                              * (math.fsum(item["score"] for item in criteria if item["dimension"] == dimension)
                                 / counts[dimension]) for dimension in dimension_weights)
    else:
        capability = math.fsum(item["contribution"] for item in criteria)
    capability = min(1.0, capability)
    strict = bool(episode_valid and safety_pass and all(
        item["score"] == 1 for item in criteria if item["mandatory"]))
    return capability, strict
