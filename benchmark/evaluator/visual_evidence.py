"""Trusted visual-input facts and causal attachment checks, independent of harness.

This module consumes execution records written outside the agent's workspace.
Neither a tool name nor an agent assertion is a visual observation.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from functools import lru_cache
from .datetime_compat import CompatibleDateTime as datetime
from pathlib import Path

VERSION = "camact.visual_evidence.v1"
POLICY = "camact.visual_before_attachment.v1"
STATUSES = {"visual_verified", "visual_not_verified", "evidence_unknown"}
RECEIPT_BINDINGS = {"message":"messages.sent", "draft":"publishing.drafts.created",
    "post":"publishing.posts", "story":"photo_library.stories", "album":"photo_library.albums",
    "archive":"archives.records", "event":"calendar.created_events", "reservation":"reservations",
    "checklist":"checklists", "item":"checklists", "output":"workspace.output"}
FINAL_ID_FIELDS = {"messages.drafts": "draft_id", "publishing.drafts.created": "draft_id",
    "publishing.posts": "post_id", "photo_library.stories": "story_id",
    "photo_library.albums": "album_id", "archives.records": "archive_id",
    "calendar.created_events": "event_id", "reservations": "reservation_id",
    "workspace.output": "name", "messages.sent": "message_id",
    "email.sent": "message_id", "telegram.sent": "message_id"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def walk(value, path="$"):
    if isinstance(value, dict):
        yield path, value
        for key, item in value.items():
            yield from walk(item, path + "." + key)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from walk(item, f"{path}[{index}]")


def image_ids(value):
    """Extract references, including references cited inside saved checklist text."""
    return set(re.findall(r"(?<![\w.-])([\w-]+\.(?:jpg|jpeg|png|webp|gif))(?![\w.-])",
                          json.dumps(value, ensure_ascii=False), re.I))


def attached_image_ids(value):
    fields = {"images", "image_ids", "image", "image_id", "attachments", "reference_images",
              "reference_image_ids", "supporting_images", "supporting_image_ids", "photo_ids"}
    return set().union(*(image_ids(item) for _,node in walk(value)
                         for key,item in node.items() if key in fields))


@lru_cache(maxsize=1024)
def _authored_reservation_text_fields(task_id):
    """Resolve text attachments only from the immutable authored task binding.

    A filename in arbitrary reservation notes is not a photo attachment. Some
    existing tasks explicitly bind their selected references to those notes;
    their persisted notes and real receipt must participate in the same visual
    acquisition checks as image arrays. No Agent-supplied binding is trusted.
    """
    if not isinstance(task_id, str):
        return ()
    identity = re.fullmatch(r"(?P<user>[0-9]+_N[0-9]+)_[A-Za-z0-9_]+", task_id)
    if identity is None:
        return ()
    tasks = Path(__file__).resolve().parents[1] / "tasks" / identity["user"]
    for spec in sorted(tasks.glob("task_*/task_spec.json")):
        try:
            if json.loads(spec.read_text(encoding="utf-8")).get("task_id") != task_id:
                continue
            from .contracts import load_contract
            contract = load_contract(spec.parent)
            requirements = contract.get("reference_solution", {}).get("selection", {}).get("evidence_requirements", {})
            fields = requirements.get("fields") or [requirements.get("field")]
            if requirements.get("path") == "reservations" and "notes" in fields:
                return ("notes",)
            return ()
        except (OSError, ValueError, TypeError, AttributeError):
            return ()
    return ()


def business_image_ids(value, binding=None, *, task_id=None):
    """Legacy checklist tools persist photo references inside item text.

    Those references are business attachments under the authored checklist
    contract; mentions in arbitrary message/story prose remain ordinary text.
    """
    images = attached_image_ids(value)
    if binding == "reservations" and isinstance(value, dict):
        for field in _authored_reservation_text_fields(task_id):
            images |= image_ids(value.get(field, ""))
    if binding == "checklists" and isinstance(value, dict):
        if "images" not in value:
            images |= image_ids(value.get("text", ""))
        for item in value.get("items", []):
            if not isinstance(item, dict):
                images |= image_ids(item)
            elif "images" not in item:
                images |= image_ids(item.get("text", ""))
    return images


def _receipt_resources(request, receipt):
    """Resolve saved business records by their declared identity, never API names."""
    identity_fields = {"message": "message_id", "draft": "draft_id", "post": "post_id",
                       "story": "story_id", "album": "album_id", "archive": "archive_id",
                       "event": "event_id", "reservation": "reservation_id", "output": "name"}
    for kind, binding in RECEIPT_BINDINGS.items():
        record = receipt.get(kind)
        if not isinstance(record, dict):
            continue
        if kind in {"checklist", "item"}:
            parent = record.get("checklist_id") if kind == "checklist" else request.get("checklist_id")
            items = record.get("items", []) if kind == "checklist" else [record]
            for item in items:
                if isinstance(item, dict):
                    yield binding, (parent, item.get("item_id")), item
            continue
        if kind == "draft" and "attachments" in record:
            binding = "messages.drafts"
        if kind == "message" and record.get("channel") in {"email", "telegram"}:
            binding = record["channel"] + ".sent"
        yield binding, (record.get(identity_fields[kind]),), record


def _final_resource(environment, binding, identity):
    value = environment
    for key in binding.split("."):
        value = value.get(key) if isinstance(value, dict) else None
    if not isinstance(value, list):
        return None, "missing final business namespace: " + binding
    if binding == "checklists":
        parents = [record for record in value if isinstance(record, dict)
                   and record.get("checklist_id") == identity[0]]
        if len(parents) != 1 or not isinstance(parents[0].get("items"), list):
            return None, "final checklist identity is missing or ambiguous"
        matches = [item for item in parents[0]["items"] if isinstance(item, dict)
                   and item.get("item_id") == identity[1]]
    else:
        field = FINAL_ID_FIELDS[binding]
        matches = [record for record in value if isinstance(record, dict)
                   and record.get(field) == identity[0]]
    if None in identity or len(matches) != 1:
        return None, "final business record identity is missing or ambiguous"
    return matches[0], None


def final_attachment_integrity_issues(submission, binding=None):
    """Find demonstrably new saved attachments lacking any business receipt.

    Existing fixture content is not an Agent attachment. Without session
    ownership or a creation timestamp, final state alone cannot distinguish it
    from an incomplete execution log, so it must not introduce a new event.
    """
    environment = submission.get("final_environment")
    if not isinstance(environment, dict):
        return []
    scopes = set(binding if isinstance(binding, list) else [binding]) if binding else set(FINAL_ID_FIELDS) | {"checklists"}
    covered = {(scope, identity) for event in submission.get("execution_trace", [])
               if event.get("kind") == "tool_call" and event.get("status") == "succeeded"
               and isinstance(event.get("request"), dict) and isinstance(event.get("response"), dict)
               and event["response"].get("status") in {"created", "updated", "sent", "published", "added", "booked", "confirmed", "drafted", "written"}
               for scope, identity, _ in _receipt_resources(event["request"], event["response"])}
    session = environment.get("session", {})
    session_id = submission.get("runtime_metadata", {}).get("session_id")

    def owned(record):
        if session_id and record.get("session_id") == session_id:
            return True
        try:
            started = datetime.fromisoformat(session["created_at"].replace("Z", "+00:00"))
        except (KeyError, TypeError, ValueError, AttributeError):
            return False
        for key in ("created_at", "written_at", "sent_at", "published_at"):
            try:
                if datetime.fromisoformat(record[key].replace("Z", "+00:00")) >= started:
                    return True
            except (KeyError, TypeError, ValueError, AttributeError):
                continue
        return False

    issues = []
    for scope in scopes:
        values = environment
        for key in scope.split("."):
            values = values.get(key) if isinstance(values, dict) else None
        if not isinstance(values, list):
            continue
        for record in values:
            if not isinstance(record, dict) or not owned(record):
                continue
            parts = ([(scope, (record.get("checklist_id"), item.get("item_id")), item)
                      for item in record.get("items", []) if isinstance(item, dict)] if scope == "checklists"
                     else [(scope, (record.get(FINAL_ID_FIELDS[scope]),), record)])
            for _, identity, part in parts:
                images = business_image_ids(part, scope, task_id=submission.get("task_id"))
                if images and (scope, identity) not in covered:
                    issues.append("current-session saved images lack a successful business receipt: "
                                  + scope + " " + ", ".join(sorted(images)))
    return issues


def attachment_events(submission):
    """Actual final attachments and the decision that established their presence.

    A metadata update retains the original attachment decision. Removing and
    reattaching an image establishes a new decision. Receipt snapshots must
    agree with the final saved record; incomplete records remain audit gaps.
    """
    resources = {}
    created = {"created", "sent", "published", "drafted", "written"}
    for event in submission.get("execution_trace", []):
        request, receipt = event.get("request", {}), event.get("response", {})
        if (event.get("kind") != "tool_call" or event.get("status") != "succeeded"
                or not isinstance(request, dict) or not isinstance(receipt, dict)
                or receipt.get("status") not in created | {"updated", "added", "booked", "confirmed"}):
            continue
        for binding, identity, record in _receipt_resources(request, receipt):
            requested = business_image_ids(request, binding, task_id=submission.get("task_id"))
            key = (binding, identity)
            resource = resources.setdefault(key, {"active": {}, "last": {}, "history": {}})
            images = business_image_ids(record, binding, task_id=submission.get("task_id"))
            # A complete saved-record snapshot also proves removals, even when
            # the removal request or a metadata update attaches no new image.
            resource["active"] = {image: source for image, source in resource["active"].items()
                                  if image in images}
            added = images if receipt["status"] in created else requested & images
            for image in added - resource["active"].keys():
                source = {"sequence": event["sequence"], "operation": event["name"],
                          "request": request, "receipt": receipt, "timestamp": event.get("timestamp"),
                          "binding": binding}
                resource["active"][image] = source
                resource["history"][image] = source
            resource["last"] = record
            resource["last_source"] = {"sequence": event["sequence"], "operation": event["name"],
                                       "request": request, "receipt": receipt,
                                       "timestamp": event.get("timestamp"), "binding": binding}
    grouped = {}
    environment = submission.get("final_environment")
    for (binding, identity), resource in resources.items():
        final, issue = (_final_resource(environment, binding, identity) if isinstance(environment, dict)
                        else (None, "missing final environment for attachment verification"))
        latest_images = business_image_ids(resource["last"], binding, task_id=submission.get("task_id"))
        if final is not None and business_image_ids(final, binding, task_id=submission.get("task_id")) != latest_images:
            issue = "last successful business receipt differs from final saved images"
        sources = dict(resource["history"] if issue else resource["active"])
        if issue and final is not None:
            for image in business_image_ids(final, binding, task_id=submission.get("task_id")) - latest_images:
                sources[image] = resource["last_source"]
        for image, source in sources.items():
            key = (source["sequence"], binding)
            event = grouped.setdefault(key, {**source, "images": [], "final_state_records": []})
            if image not in event["images"]:
                event["images"].append(image)
            if final is not None and final not in event["final_state_records"]:
                event["final_state_records"].append(final)
            if issue:
                event["final_state_issue"] = issue
    return [{**event, "images": sorted(event["images"])}
            for _, event in sorted(grouped.items())]


def applicable_components(task):
    """Explicitly reviewed semantic registry, never substring-match checker names."""
    registry = json.loads(Path(__file__).with_name("visual_check_registry.json").read_text(encoding="utf-8"))
    entries = registry.get("tasks", {}).get(task["task_id"], {})
    components = [c for c in task["scoring_components"] if c["id"] in entries]
    for c in components:
        current = sha(json.dumps({key:c.get(key) for key in ('check','description','mandatory')},sort_keys=True).encode())
        if entries[c['id']]['contract_sha256'] != current:
            raise ValueError('visual check semantic registration is stale: '+c['id'])
        binding=entries[c['id']].get('binding')
        valid=set(RECEIPT_BINDINGS.values())|{'messages.drafts','email.sent','telegram.sent'}
        if binding is not None and any(v not in valid for v in (binding if isinstance(binding,list) else [binding])):
            raise ValueError('invalid visual check binding: '+c['id'])
    return components


def component_binding(task, component):
    registry = json.loads(Path(__file__).with_name("visual_check_registry.json").read_text(encoding="utf-8"))
    return registry['tasks'][task['task_id']][component['id']].get('binding')


def component_registration(task, component):
    registry = json.loads(Path(__file__).with_name("visual_check_registry.json").read_text(encoding="utf-8"))
    return registry['tasks'][task['task_id']][component['id']]


def judge_visual_component(task, component, submission):
    entry = component_registration(task, component)
    if entry.get('policy'):
        from .visual_policy import score_visual_policy
        return score_visual_policy(submission.get('visual_evidence'), submission, entry.get('binding'), entry['policy'])
    return judge_visual_evidence(submission.get('visual_evidence'), submission, entry.get('binding'))


def validate_document(value):
    if not isinstance(value, dict) or value.get("schema_version") != VERSION:
        raise ValueError("unsupported VisualEvidence schema")
    if not isinstance(value.get("requests"), list) or not isinstance(value.get("attachments"), list):
        raise ValueError("VisualEvidence requests/attachments must be arrays")
    if value.get("status") not in STATUSES:
        raise ValueError("invalid VisualEvidence status")
    if type(value.get("complete")) is not bool:
        raise ValueError("VisualEvidence completeness must be explicit")
    if any(not isinstance(row,dict) or row.get('status') not in STATUSES for row in value['attachments']):
        raise ValueError('invalid per-image visual status')
    return value


def judge_visual_evidence(evidence, submission, binding=None):
    """Revalidate binding to this Episode; unknown never becomes binary credit."""
    final_issues = final_attachment_integrity_issues(submission, binding)
    if final_issues:
        return {"status": "evidence_unknown", "score": None, "images": [],
                "reason": "; ".join(final_issues)}
    actual = attachment_events(submission)
    if binding:
        scopes = binding if isinstance(binding,list) else [binding]
        actual = [a for a in actual if a['binding'] in scopes]
    if not actual:
        return {"status": "visual_not_verified", "score": 0, "images": [],
                "reason": "no successful image attachment; empty sets do not pass"}
    state_issues = [event['final_state_issue'] for event in actual if event.get('final_state_issue')]
    if state_issues:
        return {"status": "evidence_unknown", "score": None, "images": [],
                "reason": "; ".join(dict.fromkeys(state_issues))}
    if not evidence:
        return {"status": "evidence_unknown", "score": None, "images": [],
                "reason": "trusted model input capture is missing"}
    try:
        validate_document(evidence)
    except (ValueError, TypeError):
        return {"status": "evidence_unknown", "score": None, "images": [],
                "reason": "malformed VisualEvidence document"}
    if evidence.get("task_id") != submission.get("task_id") or evidence.get("session_id") != submission.get("runtime_metadata", {}).get("session_id"):
        return {"status": "evidence_unknown", "score": None, "images": [], "reason": "visual evidence belongs to another Episode"}
    expected = {(a["sequence"], i) for a in actual for i in a["images"]}
    rows = evidence["attachments"]
    if binding:
        rows = [a for a in rows if a.get('binding') in scopes]
    observed = {(a.get("business_sequence"), a.get("image_id")) for a in rows}
    if observed != expected or len(rows) != len(expected):
        return {"status": "evidence_unknown", "score": None, "images": rows, "reason": "attachment coverage is incomplete or duplicated"}
    by_sequence = {a["sequence"]: a for a in actual}
    for row in rows:
        event = by_sequence[row["business_sequence"]]
        if row.get("business_request") != event["request"] or row.get("business_receipt") != event["receipt"]:
            return {"status": "evidence_unknown", "score": None, "images": rows, "reason": "business receipt binding mismatch"}
    statuses = {a.get("status") for a in rows}
    status = ("evidence_unknown" if "evidence_unknown" in statuses or not evidence.get("complete")
              else "visual_verified" if statuses == {"visual_verified"} else "visual_not_verified")
    return {"status": status, "score": None if status == "evidence_unknown" else int(status == "visual_verified"),
            "images": copy.deepcopy(rows), "reason": "per-image request/response/decision/business causal audit"}


def apply_visual_checks(task, submission, graded):
    components = applicable_components(task)
    if not components:
        return
    results = {c['id']:judge_visual_component(task,c,submission) for c in components}
    graded.diagnostics["visual_evidence"] = {"policy": POLICY, 'criteria':results}
    if any(r['status'] == 'evidence_unknown' for r in results.values()):
        graded.infrastructure_failures.append({"component": "visual_evidence", "error": 'incomplete visual evidence',
                                               "status": "evidence_unknown"})
        return
    for criterion in graded.criteria:
        if criterion["id"] in results:
            result = results[criterion['id']]
            criterion.update(score=result["score"], passed=result["score"] == 1,
                             evidence=[{"visual_evidence": result}], reason=result["reason"])
            if "score_range" in next(c for c in components if c['id'] == criterion['id']):
                criterion['score_range'] = {'minimum': 0, 'maximum': 1}
