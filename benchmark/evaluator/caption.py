"""Task-declared, individually sent photo captions: send gate times discrete rubric."""
from __future__ import annotations

import copy
from pathlib import Path

from .checks import _critical_failure_results, _field_value_matches, _runtime_root
from .contracts import score_values
from .grading import GradingResult, request_fingerprint
from .judge import JudgeInfrastructureError


def _accepted_photo_messages(params, submission, state):
    """Locate service messages belonging to this photo and successful send receipts."""
    image = params["image_id"]
    records = state.get("messages", {}).get("sent", [])
    records = records if isinstance(records, list) else []
    matches = [(n, r) for n, r in enumerate(records)
               if isinstance(r, dict) and r.get("attachments") == [image]
               and _field_value_matches("to", r.get("to"), params["recipient"], state)]
    for index, record in matches:
        for event in submission.get("execution_trace", []):
            if event.get("kind") != "tool_call" or event.get("name") != "message_send" or event.get("status") != "succeeded":
                continue
            response = event.get("response", {})
            if response.get("status") == "sent" and record.get("message_id") and response.get("message", {}).get("message_id") == record["message_id"]:
                yield record, event, {"image_id": image, "source": "final_service_state", "binding_count": len(matches),
                                      "record_index": index, "message_id": record["message_id"],
                                      "trace_sequence": event.get("sequence"), "failure": None}


def sent_photo_gate(params, submission, state):
    """Image send check: message_send succeeded and the service accepted this photo."""
    for record, event, detail in _accepted_photo_messages(params, submission, state):
        return True, record, detail
    return False, None, {"image_id": params["image_id"], "source": "final_service_state",
                         "failure": "target_photo_not_successfully_sent_to_service"}


def sent_caption_gate(params, submission, state):
    """Caption send check: corresponding nonempty text was sent and persisted."""
    for record, event, detail in _accepted_photo_messages(params, submission, state):
        requested = event.get("request", {}).get("text")
        persisted = record.get("text")
        if isinstance(requested, str) and requested.strip() and isinstance(persisted, str) and persisted.strip():
            return True, record, detail
    return False, None, {"image_id": params["image_id"], "source": "final_service_state",
                         "failure": "corresponding_caption_not_successfully_sent_to_service"}


def caption_decision(result, identity, values):
    if not isinstance(result, dict) or result.get("criterion_id") != identity:
        raise JudgeInfrastructureError("unexpected caption criterion identity")
    score = result.get("score")
    if isinstance(score, bool) or not isinstance(score, (int, float)) or score not in values:
        raise JudgeInfrastructureError("caption Judge score must be exactly 0, 0.5 or 1")
    if "pass" in result and (type(result["pass"]) is not bool or result["pass"] != (score == 1)):
        raise JudgeInfrastructureError("caption pass must mean full credit")
    reason, refs = result.get("reason"), result.get("evidence_refs")
    if not isinstance(reason, str) or not reason.strip() or not isinstance(refs, list) or not refs or any(not isinstance(r, str) or not r.strip() for r in refs):
        raise JudgeInfrastructureError("caption Judge lacks auditable reason/evidence")
    return score, {"reason": reason.strip(), "evidence_refs": refs}


def grade_sent_photo_captions(task_dir: Path, task, submission, state, judge):
    result = GradingResult()
    components = task["scoring_components"]
    if any(c["check"]["checker"] != "sent_photo_caption" or score_values(c) != [0, 0.5, 1]
           or c["check"]["params"].get("send_checks") != ["photo_send", "caption_send"] for c in components):
        raise ValueError("sent caption contract requires declared three-level caption components only")
    album_root = _runtime_root(task_dir)
    for component in components:
        identity, params = component["id"], component["check"]["params"]
        try:
            photo_sent, _, photo_detail = sent_photo_gate(params, submission, state)
            caption_sent, record, send_caption_detail = sent_caption_gate(params, submission, state)
            sent = photo_sent and caption_sent
            detail = {"image_id": params["image_id"], "photo_send": photo_detail, "caption_send": send_caption_detail}
            caption_score, caption_detail = None, {"source": "caption_judge", "status": "skipped_send_gate_failed"}
            if sent:
                text = record.get("text", "")
                if not isinstance(text, str) or not text.strip():
                    caption_score, caption_detail = 0, {"source": "persisted_caption", "reason": "Caption missing."}
                else:
                    image_path = (album_root / "images" / params["image_id"]).resolve()
                    if not image_path.is_relative_to((album_root / "images").resolve()) or image_path.name != params["image_id"]:
                        raise ValueError("caption image path is outside album")
                    if not image_path.is_file():
                        raise JudgeInfrastructureError("required caption raw image is unavailable")
                    request = {
                        "task_prompt": {"content_context": params.get("content_context", [])},
                        "evidence": {"message_id": record["message_id"], "image_id": params["image_id"], "persisted_text": text},
                        "trajectory": {},
                        "criterion_rubric": [{"criterion_id": identity, "rubric": component["rubric"], "score_values": score_values(component)}],
                        "image_paths": [image_path],
                    }
                    call = {"criterion_id": identity, "owner": component["owner"], "request_sha256": request_fingerprint(request)}
                    result.judge_calls.append(call)
                    try:
                        if judge is None or judge is False:
                            raise JudgeInfrastructureError("caption requires a configured Judge")
                        batch = judge.evaluate(**request)
                        if set(batch.results) != {identity}:
                            raise JudgeInfrastructureError("caption Judge returned extra or missing criteria")
                        caption_score, caption_detail = caption_decision(batch.results[identity], identity, score_values(component))
                        call.update(status="succeeded", result=batch.results[identity], audit=batch.audit)
                    except (RuntimeError, OSError, ValueError, TypeError, KeyError) as exc:
                        call.update(status="failed", error=f"{type(exc).__name__}: {exc}", audit=getattr(exc, "audit", {}))
                        raise
            score = caption_score if sent else 0
            result.criteria.append({
                **{k: copy.deepcopy(component[k]) for k in ("id", "owner", "weight", "mandatory", "score_values")},
                "score": score, "passed": score == 1, "check_type": component["check"]["type"],
                "send_score": int(sent), "caption_score": caption_score,
                "photo_send_score": int(photo_sent), "caption_send_score": int(caption_sent),
                "evidence": [detail, caption_detail], "reason": f"photo_send={int(photo_sent)}; caption_send={int(caption_sent)}; caption={caption_score if sent else 'not evaluated'}; product={score}",
                "report_aliases": [], "state_projection": True,
            })
            result.diagnostics[identity] = {"photo_send_score": int(photo_sent), "caption_send_score": int(caption_sent),
                                            "send_score": int(sent), "caption_score": caption_score, "score": score, **detail}
        except (RuntimeError, OSError, ValueError, TypeError, KeyError) as exc:
            result.infrastructure_failures.append({"component": identity, "error": f"{type(exc).__name__}: {exc}", "audit": getattr(exc, "audit", {})})
    conventional = [g for g in task["safety_checks"] if g["type"] != "sent_photo_policy" and g.get("mandatory")]
    result.critical_failures = _critical_failure_results(task_dir, {"critical_failure": conventional}, submission, state)
    for gate in task["safety_checks"]:
        if gate["type"] != "sent_photo_policy" or not gate.get("mandatory"):
            continue
        records = state.get("messages", {}).get("sent", [])
        policy, issues = gate["params"], {}
        if not isinstance(records, list):
            records, issues["invalid_records"] = [], True
        if len(records) != policy["message_count"]:
            issues["message_count"] = {"actual": len(records), "expected": policy["message_count"]}
        images = []
        for index, record in enumerate(records):
            if not isinstance(record, dict) or not isinstance(record.get("attachments"), list) or len(record["attachments"]) != 1:
                issues.setdefault("attachments_per_message", []).append(index)
                continue
            images.extend(record["attachments"])
        if any(not isinstance(image, str) or image not in policy["required_images"] for image in images):
            issues["unexpected_images"] = True
        if sorted(image for image in images if isinstance(image, str)) != sorted(policy["required_images"]):
            issues["missing_or_duplicate_images"] = True
        if issues:
            result.mandatory_violations.append({"id": gate["id"], "type": "sent_photo_policy", "details": issues})
    return result
