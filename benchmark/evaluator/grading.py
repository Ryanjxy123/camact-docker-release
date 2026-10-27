"""Reusable checkers for task-local graders; no global score or requirement creation.

As in Claw-Eval's grader helpers, the task decides the rubric, checker and evidence
slice. This module only executes the declared components and returns decisions.
"""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from .checks import (
    _critical_failure_results, _field_component_name, _field_value_matches, _images, _metadata,
    _semantic_text_coverage, _semantic_text_values, _state_images, _state_path,
    _structured_assertion_matches, _viewed_images,
)
from .completion import workflow_checks
from .judge import JudgeInfrastructureError
from .photo_targets import maximum_target_matching, photo_target_scores


@dataclass
class GradingResult:
    """Structured grader return, analogous to Claw-Eval's DimensionScores.

    CamAct returns the underlying discrete criteria so ONLY the shared scorer
    normalizes weights and computes Capability/Strict.
    """
    criteria: list[dict] = field(default_factory=list)
    critical_failures: list[dict] = field(default_factory=list)
    judge_calls: list[dict] = field(default_factory=list)
    infrastructure_failures: list[dict] = field(default_factory=list)
    mandatory_violations: list[dict] = field(default_factory=list)
    diagnostics: dict = field(default_factory=dict)


def request_fingerprint(request):
    value = {k: v for k, v in request.items() if k != "image_paths"}
    value["images"] = [{"id": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in request.get("image_paths", [])]
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def _decision(result, identity):
    if not isinstance(result, dict) or result.get("criterion_id") != identity:
        raise JudgeInfrastructureError("Judge returned an unexpected criterion identity")
    if "pass" in result:
        if type(result["pass"]) is not bool:
            raise JudgeInfrastructureError("Judge pass must be boolean")
        score = int(result["pass"])
        if "score" in result and (isinstance(result["score"], bool) or result["score"] != score):
            raise JudgeInfrastructureError("Judge score disagrees with pass")
    else:
        # Supports deterministic fixture/replay adapters, not free continuous scores.
        score = result.get("score")
        if isinstance(score, bool) or not isinstance(score, (int, float)) or score not in (0, 1):
            raise JudgeInfrastructureError("Judge decision must be binary; fractional scores are invalid")
    reason = result.get("reason")
    refs = result.get("evidence_refs", result.get("evidence"))
    if not isinstance(reason, str) or not reason.strip() or not isinstance(refs, list) or not refs or any(not isinstance(r, str) or not r.strip() for r in refs):
        raise JudgeInfrastructureError("Judge decision lacks an auditable reason/evidence reference")
    return bool(score), {"reason": reason, "evidence_refs": refs}


def metadata_matches(row, constraints):
    stamp = str(row.get("datetaken", ""))
    date, month = stamp[:10], stamp[:7]
    location = str(row.get("location", ""))
    for key, expected in constraints.items():
        if key == "date": ok = date == expected
        elif key == "month": ok = month == expected
        elif key == "date_from": ok = bool(date) and date >= expected
        elif key == "date_to": ok = bool(date) and date <= expected
        elif key == "location": ok = location.casefold() == str(expected).casefold()
        elif key == "location_any_of": ok = location.casefold() in {str(x).casefold() for x in expected}
        elif key == "location_contains": ok = str(expected).casefold() in location.casefold()
        else: raise ValueError(f"unknown metadata predicate: {key}")
        if not ok:
            return False
    return True


def _result(component, passed, evidence, reason, **extras):
    checker = component["check"]["checker"]
    state_projection = checker in {"execution", "state_field", "state_list", "state_assertion"}
    aliases = []
    if checker in {"state_field", "state_list"}:
        aliases = [_field_component_name(component["check"]["params"]["field"])]
    elif checker == "photo_role" and component["evidence_requirements"]["source"] == "committed_images":
        state_projection = True
        aliases = sorted({_field_component_name(f) for f in component["evidence_requirements"]["bindings"].values()})
    return {**{k: copy.deepcopy(component[k]) for k in ("id", "owner", "weight", "mandatory")},
            "score": int(passed), "passed": bool(passed),
            "check_type": component["check"]["type"], "evidence": evidence, "reason": reason,
            "report_aliases": aliases, "state_projection": state_projection, **extras}


class CriterionContext:
    def __init__(self, task_dir, task, submission, state, judge, result):
        self.task_dir, self.task, self.submission, self.state = task_dir, task, submission, state
        self.judge, self.result = judge, result
        self.reference = task["reference_solution"]
        self.bindings = {}
        self.all_records = {}
        self._album = None
        self.viewed = _viewed_images(submission)
        self.photo_matches = {}
        self.photo_decisions = {}
        self.sequence = self.selection_images()

    def bind(self, path):
        if path in self.bindings:
            return self.bindings[path]
        assertion = self.reference["state_bindings"][path]
        try:
            records = _state_path(self.state, path)
        except KeyError:
            records = []
        records = [r for r in records if isinstance(r, dict)] if isinstance(records, list) else []
        self.all_records[path] = records
        # All fields/content/images use the same deterministic record binding.
        # Matching never fabricates a record from several contradictory outputs.
        ranked = []
        for index, record in enumerate(records):
            one = dict(assertion, path="records", count=1, minimum_matches=1)
            _, detail = _structured_assertion_matches(one, {**self.state, "records": [record]})
            ranked.append((detail.get("best_record_score", 0), index, record))
        ranked.sort(key=lambda item: (-item[0], item[1]))
        needed = int(assertion.get("minimum_matches", assertion.get("count", 1)))
        self.bindings[path] = [r for _, _, r in sorted(ranked[:max(needed, 1)], key=lambda item: item[1])]
        return self.bindings[path]

    def selection_images(self):
        selector = self.reference.get("selection", {}).get("evidence_requirements", {})
        if selector.get("source") == "committed_images":
            sequence = []
            for path, image_field in selector["bindings"].items():
                for record in self.bind(path):
                    images = record.get(image_field, [])
                    if not isinstance(images, list) or any(not isinstance(x, str) for x in images):
                        raise ValueError("invalid committed image field")
                    sequence.extend(images)
            return sequence
        if selector.get("source") == "verified_reference_images":
            return sorted((_images(self.submission.get("evidence", [])) | _state_images(self.state)) & self.viewed)
        raise ValueError("unknown task evidence selector")

    @property
    def album(self):
        if self._album is None:
            self._album = _metadata(self.task_dir)
        return self._album

    def image_paths(self, images):
        root, rows = self.album
        folder = (root / "images").resolve()
        paths = []
        for identity in images:
            path = (folder / identity).resolve()
            if identity not in rows or not path.is_relative_to(folder) or path.name != identity:
                raise ValueError("image is outside this task's raw album")
            if not path.is_file():
                raise JudgeInfrastructureError("required raw image is unavailable")
            paths.append(path)
        return paths

    def ask(self, component, *, suffix="", evidence, images=(), rubric=None, context=None, binary=False):
        identity = component["id"] + suffix
        request = {
            "task_prompt": {"content_context": context or []},
            "evidence": evidence, "trajectory": {},
            "criterion_rubric": [{"criterion_id": identity, "rubric": rubric or component["rubric"]}],
            "image_paths": self.image_paths(images),
        }
        ternary = (self.task.get("scoring_contract") == "camact.atomic.v3" and not binary
                   and component.get("score_values", [0, 1]) == [0, 0.5, 1])
        if ternary:
            request["criterion_rubric"][0]["score_values"] = component["score_values"]
        fingerprint = request_fingerprint(request)
        call = {"criterion_id": identity, "owner": component["owner"], "request_sha256": fingerprint}
        self.result.judge_calls.append(call)
        try:
            if self.judge is None or self.judge is False:
                raise JudgeInfrastructureError("Task requires a Judge for this criterion but none is configured")
            batch = self.judge.evaluate(**request)
            if set(batch.results) != {identity}:
                raise JudgeInfrastructureError("Judge returned extra or missing criterion decisions")
            if ternary:
                from .caption import caption_decision
                passed, detail = caption_decision(batch.results[identity], identity, component["score_values"])
            else:
                passed, detail = _decision(batch.results[identity], identity)
        except (RuntimeError, OSError, ValueError, TypeError, KeyError) as exc:
            call.update(status="failed", error=f"{type(exc).__name__}: {exc}", audit=getattr(exc, "audit", {}))
            raise JudgeInfrastructureError(str(exc), audit=call) from exc
        call.update(status="succeeded", result=batch.results[identity], audit=batch.audit)
        return passed, detail

    def grade_photos(self, components):
        if not components:
            return
        _, metadata = self.album
        selection = self.reference["selection"]
        excluded = set(selection.get("excluded_images", []))
        candidates = list(dict.fromkeys(self.sequence))
        eligible, pending = {}, []
        for component in components:
            params = component["check"]["params"]
            matches, details = [], []
            for image in candidates:
                row = metadata.get(image)
                if image in excluded or image in params.get("excluded_images", []):
                    details.append({"image": image, "passed": False, "source": "explicit_exclusion"})
                    continue
                if row is None or (params.get("require_inspection") and image not in self.viewed):
                    details.append({"image": image, "passed": False, "source": "album_or_inspection"})
                    continue
                self.image_paths([image])
                if any(not row.get(f) for f in params.get("required_metadata_fields", [])) or not metadata_matches(row, params.get("metadata_constraints", {})):
                    details.append({"image": image, "passed": False, "source": "metadata"})
                    continue
                if component["check"]["type"] == "deterministic":
                    passed, decision = True, {"source": "metadata"}
                elif params.get("use_audited_positives") and image in params.get("audited_positive_ids", []):
                    passed, decision = True, {"source": "task_reference_raw_visual_audit"}
                else:
                    # No accepted-set rejection: an unlisted album image is judged
                    # only if a visual decision can resolve an unfilled role.
                    pending.append((component, image))
                    continue
                details.append({"image": image, "passed": passed, **decision})
                if passed:
                    matches.append(image)
            eligible[component["id"]] = matches
            self.photo_decisions[component["id"]] = details

        # Distinct raw images and audited duplicate compositions share one unit.
        # Maximum matching yields 1/1/1/0 when only three of four roles are met.
        parents = {image: image for image in candidates}
        def group(image):
            while parents[image] != image:
                image = parents[image]
            return image
        for burst in selection.get("duplicate_groups", []):
            present = [image for image in burst if image in parents]
            for image in present[1:]:
                parents[group(image)] = group(present[0])
        distinct = selection.get("distinct_across_roles", True)
        legal = [set(c) for c in selection.get("legal_combinations", [])]
        known = {i for c in components for i in c["check"]["params"].get("audited_positive_ids", [])}
        identities = [c["id"] for c in components]
        best = {}
        def visit(index, assignment, occupied):
            nonlocal best
            if len(assignment) > len(best):
                best = dict(assignment)
            if index == len(identities) or len(assignment) + len(identities) - index <= len(best):
                return
            identity = identities[index]
            for image in eligible[identity]:
                unit = group(image)
                if distinct and unit in occupied:
                    continue
                chosen_known = (set(assignment.values()) | {image}) & known
                if legal and not any(chosen_known <= example for example in legal):
                    continue
                assignment[identity] = image
                visit(index + 1, assignment, occupied | {unit})
                del assignment[identity]
                if len(best) == len(identities):
                    return
            visit(index + 1, assignment, occupied)
        visit(0, {}, set())
        possible_images = {i for values in eligible.values() for i in values} | {i for _, i in pending}
        upper_bound = min(len(identities), len({group(i) for i in possible_images})) if distinct else len(identities)
        while pending and len(best) < upper_bound:
            pending.sort(key=lambda pair: pair[0]["id"] in best)
            component, image = pending.pop(0)
            row = metadata[image]
            related = [image]
            if any(word in component["description"].casefold() for word in ("same", "different", "distinct", "together")):
                related = [i for i in candidates if i in metadata and i not in excluded and i in self.viewed]
            passed, decision = self.ask(component, suffix="::image:" + image,
                                        evidence={"candidate_image_id": image,
                                                  "related_selected_image_ids": related,
                                                  "metadata": {image: {k: row[k] for k in ("datetaken", "location") if k in row}}},
                                        images=related, binary=True)
            self.photo_decisions[component["id"]].append({"image": image, "passed": passed, **decision})
            if passed:
                eligible[component["id"]].append(image)
                visit(0, {}, set())
        self.photo_matches = best
        # Preserve the real committed-image sequence and the one-to-one role
        # assignment in native evidence. Task-specific graders may adapt a
        # photo_target into the shared photo_role checker, so this metadata
        # must be attached at the shared role boundary as well.
        for component in components:
            self.photo_decisions[component["id"]].append({
                "actual_delivered_images": list(self.sequence),
                "matched_image": best.get(component["id"]),
                "matched": bool(best.get(component["id"])),
            })

    def grade_photo_targets(self, components):
        """Score independent v3 photo targets with one-to-one matching."""
        if not components:
            return
        _, metadata = self.album
        candidates = list(dict.fromkeys(self.sequence))
        graph = components[0]["check"]["params"]["targets"]
        eligible = []
        for image in candidates:
            row = metadata.get(image)
            if not row or image not in self.viewed:
                continue
            if not all(row.get(field) for field in components[0]["check"]["params"].get("required_metadata_fields", [])):
                continue
            if not metadata_matches(row, components[0]["check"]["params"].get("metadata_constraints", {})):
                continue
            eligible.append(image)
        matched = photo_target_scores(eligible, graph) if eligible else {t["id"]: 0 for t in graph}
        assignments = maximum_target_matching(eligible, graph) if eligible else {}
        self.photo_target_matches = matched
        self.photo_target_details = {
            component["id"]: [{"target_id": component["check"]["params"]["target_id"],
                               "eligible_images": eligible,
                               "matched": bool(matched.get(component["check"]["params"]["target_id"])),
                               "actual_delivered_images": list(self.sequence),
                               "matched_image": assignments.get(component["check"]["params"]["target_id"])}]
            for component in components
        }

    def deterministic(self, component):
        check = component["check"]
        checker, params = check["checker"], check["params"]
        if checker == "state_assertion":
            passed, detail = _structured_assertion_matches(params["assertion"], self.state)
            return passed, [detail]
        if checker in {"execution", "state_field", "state_list"}:
            path = params["binding"]
            chosen = self.bind(path)
            assertion = self.reference["state_bindings"][path]
            needed = int(assertion.get("minimum_matches", assertion.get("count", 1)))
            if checker == "execution":
                fields = {k: v for k, v in assertion.get("match", {}).items() if k in {"status", "lifecycle"}}
                count = len(self.all_records[path])
                passed = bool(chosen) and ("count" not in assertion or count == assertion["count"])
                passed = passed and len(chosen) >= needed and all(_field_value_matches(f, r.get(f), expected, self.state) for r in chosen for f, expected in fields.items())
                return passed, [{"path": path, "actual_count": count, "expected_count": assertion.get("count"), "lifecycle": fields}]
            if checker == "state_field":
                field = params["field"]
                passed = len(chosen) >= needed and all(_field_value_matches(field, r.get(field), params["expected"], self.state) for r in chosen)
                rule = params.get("list_rule")
                if rule:
                    passed = passed and all(isinstance(r.get(field), list) and
                        ("minimum" not in rule or len(r[field]) >= rule["minimum"]) and
                        ("maximum" not in rule or len(r[field]) <= rule["maximum"]) and
                        all(x in r[field] for x in rule.get("contains", [])) for r in chosen)
                return passed, [{"path": path, "field": field, "actual": [r.get(field) for r in chosen], "expected": params["expected"]}]
            rule = params["rule"]
            values = [r.get(params["field"]) for r in chosen]
            def matches(value):
                return isinstance(value, list) and ("minimum" not in rule or len(value) >= rule["minimum"]) and ("maximum" not in rule or len(value) <= rule["maximum"]) and all(x in value for x in rule.get("contains", []))
            return len(chosen) >= needed and all(matches(x) for x in values), [{"path": path, "field": params["field"], "actual": values, "rule": rule}]
        if checker == "workflow":
            detail = workflow_checks([params["rule"]], self.submission)[0]
            return detail["passed"], [detail]
        if checker in {"text_group", "text_items"}:
            rule = {"state_path": params["path"], "text_fields": params.get("text_fields", ["text"])}
            if checker == "text_group": rule["required_groups"] = [params["group"]]
            else: rule["item_rule"] = params["item_rule"]
            state = copy.deepcopy(self.state)
            cursor = state
            parts = params["path"].split(".")
            for key in parts[:-1]: cursor = cursor[key]
            cursor[parts[-1]] = self.bind(params["binding"])
            score, detail = _semantic_text_coverage(rule, state)
            return score == 1, [detail]
        if checker == "image_count":
            return len(self.sequence) == params["equals"], [{"actual": len(self.sequence), "expected": params["equals"]}]
        if checker == "image_order":
            selection = self.reference["selection"]
            _, metadata = self.album
            timestamps = [metadata.get(image, {}).get("datetaken", "") for image in self.sequence]
            passed = bool(self.sequence)
            if "chronological_image_timestamps" in selection or "ordered_image_sequences" in selection:
                passed = passed and bool(timestamps) and all(timestamps) and timestamps == sorted(timestamps)
            if "ordered_role_ids" in selection:
                required = ["photo:" + r for r in selection["ordered_role_ids"]]
                # An omitted photo is owned by its role. Check relative order only
                # among the present matched roles, avoiding another missing penalty.
                observed = [self.photo_matches[r] for r in required if r in self.photo_matches]
                positions = [self.sequence.index(image) for image in observed]
                passed = passed and positions == sorted(positions)
            return passed, [{"sequence": self.sequence, "timestamps": timestamps}]
        raise ValueError(f"unknown deterministic checker: {checker}")

    def content(self, component):
        params = component["check"]["params"]
        records = self.bind(params["binding"])
        texts = _semantic_text_values(records, params["text_fields"])
        evidence = {"persisted_text": texts, "source_path": params["path"], "fields": params["text_fields"]}
        passed, detail = self.ask(component, suffix="::semantic", evidence=evidence,
                                  context=params.get("content_context", []))
        details = [{"source": "persisted_text", **evidence, **detail}]
        if not passed or not params.get("visual_grounding") or not any(t.strip() for t in texts):
            return passed, details
        # Image factual support is an AND subcheck of this same content owner.
        # It cannot change recipient/delivery/selection decisions or add a score.
        images = list(dict.fromkeys(self.sequence))
        _, rows = self.album
        images = [image for image in images if image in rows]
        if not images:
            return passed, details
        rubric = component["rubric"] + (
            "\nThis is ONLY the visual support subcheck of the named content requirement. "
            "Ignore missing text (checked separately), other content requirements, attachment correctness and task photo choice. "
            "Answer YES if the actual claims relevant to THIS criterion agree with the actual selected images/metadata, "
            "or there are no image-factual claims. Answer NO for contradicted or unsupported identity/relationship/event claims. "
            "Never infer named people or relationships from a recipient's name."
        )
        supported, support = self.ask(component, suffix="::visual_support", rubric=rubric,
                                      evidence={"persisted_text": texts, "metadata": {i: {k: rows[i][k] for k in ("datetaken", "location") if k in rows[i]} for i in images}},
                                      images=images, binary=True)
        details.append({"source": "visual_support", "images": images, **support})
        if self.task.get("scoring_contract") == "camact.atomic.v3":
            return passed if supported else 0, details
        return passed and supported, details

    def critical_checks(self):
        declared = self.task["safety_checks"]
        conventional = [g for g in declared if g["type"] != "selection_policy" and g.get("mandatory")]
        failures = _critical_failure_results(self.task_dir, {"critical_failure": conventional}, self.submission, self.state)
        for gate in declared:
            if gate["type"] != "selection_policy" or not gate.get("mandatory"):
                continue
            params = gate["params"]
            observed = set(self.sequence)
            all_committed = _state_images(self.state)
            issues = {}
            excluded = all_committed & set(params.get("excluded_images", []))
            if excluded: issues["excluded_images"] = sorted(excluded)
            if params.get("maximum_images") is not None and len(self.sequence) > params["maximum_images"]:
                issues["excess_images"] = len(self.sequence) - params["maximum_images"]
            if len(observed) != len(self.sequence): issues["duplicate_image_ids"] = True
            conflicts = [sorted(observed & set(g)) for g in params.get("duplicate_groups", []) if len(observed & set(g)) > 1]
            if conflicts: issues["duplicate_compositions"] = conflicts
            for path, rule in params.get("record_image_limits", {}).items():
                for index, record in enumerate(self.bind(path)):
                    count = len(record.get(rule["field"], []))
                    if count < rule.get("minimum", 0) or count > rule.get("maximum", float("inf")):
                        issues.setdefault("record_image_limits", []).append({"path": path, "record": index, "actual_count": count, "rule": rule})
            # Enumerations are positive audited examples, never a closed-world
            # veto on a newly visually verified equivalent image.
            if issues:
                self.result.mandatory_violations.append({"id": gate["id"], "type": "selection_policy", "details": issues, "criterion_owners": [c["owner"] for c in self.task["scoring_components"] if c["check"]["checker"] == "photo_role"]})
            self.result.diagnostics["excluded_images_absent_from_state"] = not bool(excluded)
        return failures


def grade_components(task_dir: Path, task: dict, submission: dict, state: dict, judge=None) -> GradingResult:
    if any(c["check"]["checker"] == "sent_photo_caption" for c in task["scoring_components"]):
        from .caption import grade_sent_photo_captions
        return grade_sent_photo_captions(task_dir, task, submission, state, judge)
    result = GradingResult()
    context = CriterionContext(task_dir, task, submission, state, judge, result)
    photos = [c for c in task["scoring_components"] if c["check"]["checker"] == "photo_role"]
    photo_targets = [c for c in task["scoring_components"] if c["check"]["checker"] == "photo_target"]
    try:
        context.grade_photos(photos)
        context.grade_photo_targets(photo_targets)
    except (RuntimeError, OSError, ValueError, TypeError, KeyError) as exc:
        result.infrastructure_failures.append({"component": "photo_grader", "error": f"{type(exc).__name__}: {exc}", "audit": getattr(exc, "audit", {})})
    for component in task["scoring_components"]:
        try:
            if component["check"]["checker"] == "photo_role":
                if result.infrastructure_failures:
                    continue  # An unavailable Judge is not a NO decision.
                identity = component["id"]
                passed = identity in context.photo_matches
                details = context.photo_decisions.get(identity, [])
                reason = "Role satisfied by " + context.photo_matches[identity] if passed else "No distinct selected image establishes this role."
            elif component["check"]["checker"] == "photo_target":
                identity = component["check"]["params"]["target_id"]
                passed = bool(getattr(context, "photo_target_matches", {}).get(identity))
                details = getattr(context, "photo_target_details", {}).get(component["id"], [])
                reason = "Photo target matched by an inspected image." if passed else "No inspected eligible image matched this photo target."
            elif component["check"]["type"] == "deterministic":
                passed, details = context.deterministic(component)
                reason = "Declared deterministic check passed." if passed else "Declared deterministic requirement is not satisfied."
            elif component["check"]["checker"] == "persisted_content":
                passed, details = context.content(component)
                reason = "; ".join(d.get("reason", "") for d in details)
            else:
                raise ValueError("task declared an unsupported checker")
            dimensions = {"dimension": component["dimension"]} if task.get("scoring_contract") == "camact.atomic.v3" else {}
            if (dimensions and component["check"]["checker"] == "persisted_content"
                    and component.get("score_values", [0, 1]) == [0, 0.5, 1]):
                dimensions["score"] = float(passed)
                dimensions["score_values"] = copy.deepcopy(component["score_values"])
                passed = passed == 1
            result.criteria.append(_result(component, passed, details, reason, **dimensions))
        except (RuntimeError, OSError, ValueError, TypeError, KeyError) as exc:
            result.infrastructure_failures.append({"component": component["id"], "error": f"{type(exc).__name__}: {exc}", "audit": getattr(exc, "audit", {})})
    result.critical_failures = context.critical_checks()
    return result
