"""Explicit special visual deadlines, sharing the trusted cross-Harness reader.

These policies are registered per criterion. They do not infer new requirements
from a checker name, or change already registered visual checks.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path


def _stamp(value):
    if type(value) in (int, float):
        return value
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.timestamp() if parsed.tzinfo is not None else None
        except ValueError:
            pass
    return None


def _unknown(reason):
    return {"status": "evidence_unknown", "score": None, "images": [], "reason": reason}


def _creation(submission, operation):
    return next((event for event in submission.get("execution_trace", [])
                 if (event.get("kind"), event.get("name"), event.get("status"))
                 == ("tool_call", operation, "succeeded")), None)


def _prior_requests(evidence, image, deadline, *, allow_any=False):
    """An actual Agent input precedes the original action, including stream links."""
    cutoff = _stamp(deadline.get("timestamp"))
    if cutoff is None:
        return None
    hits = []
    for request in evidence["requests"]:
        if request.get("success") is not True or request.get("component", "agent_with_tools") != "agent_with_tools":
            continue
        start, end = _stamp(request.get("started_at")), _stamp(request.get("completed_at"))
        if start is None or end is None or start > cutoff:
            continue
        pixels = [payload for payload in request.get("images", [])
                  if payload.get("identity_route") in {"byte_identical", "native_conversion_record", "verified_full_frame_transform", "verified_composite"}
                  and payload.get("image_ids") and (allow_any or image in payload["image_ids"])]
        # Retain the existing reader's verified utility -> Agent analysis route;
        # a utility request on its own never establishes an Agent observation.
        forwarded_analysis = any(
            (allow_any or row.get('image_id') == image)
            and any(route.get('route') in {'retained_visual_analysis', 'auxiliary_visual_response'}
                    and route.get('main_request_id') == request['id']
                    for route in row.get('routes', []))
            for row in evidence['attachments'] if row.get('status') == 'visual_verified')
        if not pixels and not forwarded_analysis:
            continue
        stream_link = any(row.get("business_sequence") == deadline["sequence"]
                          and row.get("decision_request_id") == request["id"]
                          and row.get("streamed_receipt_link") and row.get("status") == "visual_verified"
                          and (allow_any or row.get("image_id") == image)
                          for row in evidence["attachments"])
        if end <= cutoff or stream_link:
            hits.append(request["id"])
    return hits


def score_visual_policy(evidence, submission, binding, policy):
    """Evaluate a reviewed policy on a source-rebuilt VisualEvidence document."""
    from .visual_evidence import (validate_document, judge_visual_evidence, attachment_events,
                                  _receipt_resources, business_image_ids)
    trace = submission.get("execution_trace", [])
    mode = policy["mode"]
    scopes = binding if isinstance(binding, list) else [binding]
    actual = [event for event in attachment_events(submission) if event["binding"] in scopes]
    if mode == "any_before_creation":
        creation = _creation(submission, policy["before_operation"])
        if creation is None:
            return {"status": "visual_not_verified", "score": 0, "images": [], "reason": "no successful creation"}
    elif mode == "support_coverage":
        targets = submission.get("evidence", [])
        if not isinstance(targets, list) or any(not isinstance(image, str) for image in targets):
            return _unknown("malformed runtime-selected supporting images")
        creation = _creation(submission, policy["before_operation"])
        if not targets or creation is None:
            return {"status": "visual_not_verified", "score": 0, "images": [], "reason": "no bound supporting images or creation"}
    elif not actual:
        return {"status": "visual_not_verified", "score": 0, "images": [], "reason": "no successful bound image use"}
    if not evidence:
        return _unknown("trusted model input capture is missing")
    try:
        validate_document(evidence)
    except (TypeError, ValueError) as exc:
        return _unknown(str(exc))
    if (not evidence["complete"] or evidence.get("task_id") != submission.get("task_id")
            or evidence.get("session_id") != submission.get("runtime_metadata", {}).get("session_id")):
        return _unknown("incomplete or foreign trusted model input capture")
    if mode == "any_before_creation":
        hits = _prior_requests(evidence, None, creation, allow_any=True)
        if hits is None:
            return _unknown("missing creation timestamp")
        score = int(bool(hits))
        return {"status": "visual_verified" if score else "visual_not_verified", "score": score,
                "images": [], "reason": "trusted original input before first creation",
                "before_sequence": creation["sequence"], "request_ids": hits}
    if mode == "support_coverage":
        first = {image: creation for image in dict.fromkeys(targets)}
        removed = set()
    else:
        bound = judge_visual_evidence(evidence, submission, binding)
        if bound["score"] is None:
            return bound
        targets = {image for event in actual for image in event["images"]}
        # Retain the earliest use even when an image is removed and reattached.
        first = {}
        for event in trace:
            if event.get("kind") != "tool_call" or event.get("status") != "succeeded":
                continue
            request, response = event.get("request", {}), event.get("response", {})
            if not isinstance(request, dict) or not isinstance(response, dict):
                continue
            for scope, _, record in _receipt_resources(request, response):
                if scope not in scopes:
                    continue
                requested = business_image_ids(request, scope, task_id=submission.get("task_id"))
                present = business_image_ids(record, scope, task_id=submission.get("task_id"))
                for image in requested & present:
                    first.setdefault(image, event)
        for event in actual:
            for image in event["images"]:
                first.setdefault(image, event)
        removed = set(first) - targets if policy.get("preserve_removed_first_use") else set()
        first = {image: first[image] for image in targets | removed}
    extra = []
    for operation in policy.get("deadline_operations", []):
        event = _creation(submission, operation)
        if event is None:
            return {"status": "visual_not_verified", "score": 0, "images": [], "reason": "missing required earlier action"}
        extra.append(event)
    rows = []
    for image, first_use in sorted(first.items()):
        deadline = min([first_use, *extra], key=lambda event: event["sequence"])
        hits = _prior_requests(evidence, image, deadline)
        if hits is None:
            return _unknown("missing trusted action timestamp")
        rows.append({"image_id": image, "before_sequence": deadline["sequence"],
                     "request_ids": hits, "removed_from_final": image in removed})
    early = True
    if policy.get("requires_any_before_operation"):
        creation = _creation(submission, policy["requires_any_before_operation"])
        prior = _prior_requests(evidence, None, creation, allow_any=True) if creation else []
        if prior is None:
            return _unknown("missing trusted creation timestamp")
        early = bool(prior)
    retained = [row for row in rows if not row["removed_from_final"]]
    score = sum(bool(row["request_ids"]) for row in retained) / len(retained) if retained and early else 0.0
    removed_failure = any(not row["request_ids"] for row in rows if row["removed_from_final"])
    return {"status": "visual_verified" if score == 1 and not removed_failure else "visual_not_verified",
            "score": score, "images": rows, "reason": "timely original-input coverage of distinct actual images",
            "required_observation_before_creation": early,
            "historical_first_use_violation": removed_failure}


def append_visual_policy(task, submission, result, component, task_dir):
    """Direct Task graders and Unified Evaluator use the same source-backed rule."""
    from .visual_evidence import component_registration, judge_visual_component
    from .grading import _result
    try:
        from benchmark.services.api import raw_root
    except ModuleNotFoundError:
        from services.api import raw_root
    from evaluation.camact_eval.visual_capture import collect_visual_evidence
    from .grader_projection import raw_visual_submission
    registration = component_registration(task, component)
    # Task-owned graders may receive an equivalent alias/optional-field copy.
    # Prove and reverse only that exact transformation, then retain the reader's
    # original trace/snapshot, wire-body and causal checks on the raw submission.
    source_submission = raw_visual_submission(Path(task_dir), submission)
    evidence = source_submission.get("visual_evidence") or {}
    capture = evidence.get("capture_root")
    trusted = (collect_visual_evidence(capture, source_submission, raw_root(Path(task_dir)) / "images")
               if capture and "workspace" not in Path(capture).parts else None)
    decision = judge_visual_component(task, component, {**source_submission, "visual_evidence": trusted})
    if decision["score"] is None:
        result.infrastructure_failures.append({"component": component["id"], "status": "evidence_unknown",
                                               "error": decision["reason"]})
    if decision.get("historical_first_use_violation") and component["mandatory"]:
        result.mandatory_violations.append({"id": component["id"], "type": "unviewed_historical_first_use",
                                           "details": decision["images"]})
    score = decision["score"] if decision["score"] is not None else 0
    result.criteria.append(_result(component, score == 1, [{"visual_policy": decision}], decision["reason"],
        score=score, dimension=component["dimension"], score_values=component.get("score_values", [0, 1]),
        state_projection=registration.get('state_projection', False),
        **({"score_range": component["score_range"]} if "score_range" in component else {})))


def grade_with_visual_policy(task, submission, state, judge, task_dir, *, criterion_id,
                             delegate_task=None, delegate_submission=None):
    """Keep generic business grading while replacing only its legacy view rule."""
    import copy
    from .grading import grade_components
    common = copy.deepcopy(delegate_task if delegate_task is not None else task)
    common['scoring_components'] = [c for c in common['scoring_components'] if c['id'] != criterion_id]
    graded = grade_components(task_dir, common,
                              delegate_submission if delegate_submission is not None else submission,
                              state, judge)
    component = next(c for c in task['scoring_components'] if c['id'] == criterion_id)
    append_visual_policy(task, submission, graded, component, task_dir)
    order = {c['id']: i for i, c in enumerate(task['scoring_components'])}
    graded.criteria.sort(key=lambda row: order[row['id']])
    return graded
