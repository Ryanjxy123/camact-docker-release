"""Deterministic one-to-one image matching for independent binary GT targets.

Call only after the task grader has bound actual delivered images to consistent
tool receipts and persisted state. Count, order and state checks are separate.
"""
from __future__ import annotations


def maximum_target_matching(images, targets):
    """Return {target_id: image_id} for a canonical maximum-cardinality matching.

    Targets use {id, accepted_images}; target_id/accepted_photo_ids aliases are
    accepted for authoring clients. Each unique photo can earn at most one point,
    including when pools overlap. Sorting makes the result independent of input
    target, candidate and delivery traversal order. No count/all-correct gate.
    """
    if not isinstance(images, (list, tuple)) or any(not isinstance(i, str) or not i for i in images):
        raise ValueError("delivered images must be a sequence of non-empty string identities")
    if not isinstance(targets, (list, tuple)) or not targets:
        raise ValueError("photo targets must be a non-empty list")
    pools = {}
    for target in targets:
        if not isinstance(target, dict):
            raise ValueError("photo target must be an object")
        identity = target.get("id", target.get("target_id"))
        candidates = target.get("accepted_images", target.get("accepted_photo_ids"))
        if not isinstance(identity, str) or not identity or identity in pools:
            raise ValueError("photo target identities must be unique non-empty strings")
        if (not isinstance(candidates, (list, tuple)) or not candidates
                or any(not isinstance(image, str) or not image for image in candidates)):
            raise ValueError("photo target must declare accepted image identities")
        pools[identity] = set(candidates)
    delivered = sorted(set(images))
    assigned = {}

    def augment(identity, seen):
        for image in delivered:
            if image in seen or image not in pools[identity]:
                continue
            seen.add(image)
            if image not in assigned or augment(assigned[image], seen):
                assigned[image] = identity
                return True
        return False

    for identity in sorted(pools):
        augment(identity, set())
    return dict(sorted((identity, image) for image, identity in assigned.items()))


def photo_target_scores(images, targets):
    """Return one independent 0/1 score per declared effective target."""
    matched = maximum_target_matching(images, targets)
    return {target.get("id", target.get("target_id")): int(target.get("id", target.get("target_id")) in matched)
            for target in targets}
