"""Strict, non-mutating compatibility projection for task-owned graders.

Raw Episode and visual-source validation run before this module. It changes
only equivalent representations: a proven session-issued image_view alias,
and absent/null optional fields inside identity_claims. Dispatch, saved audit,
model inputs, semantic identity values and grading requirements are untouched.
"""
from __future__ import annotations

import copy
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re


VERSION = "camact.grader_projection.v2"
_IMAGE_REF = re.compile(r"p[1-9][0-9]*-[1-9][0-9]*")


def _services():
    if __package__ == "evaluator":
        from services.api import image_path, inspect_image, photo_search_page
        from services.episode import episode_error
    else:
        from ..services.api import image_path, inspect_image, photo_search_page
        from ..services.episode import episode_error
    return image_path, inspect_image, photo_search_page, episode_error


def _timestamp(event):
    value = event.get("timestamp")
    if not isinstance(value, str):
        raise ValueError("image reference evidence lacks a timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("image reference evidence has an unbound timestamp")
    return parsed


def _issued_page(task_dir, event, page_number, search):
    """Verify the public deterministic browse receipt before trusting its map."""
    request, response = event.get("request"), event.get("response")
    if not isinstance(request, dict) or not isinstance(response, dict):
        raise ValueError("invalid album reference issuance")
    expected = search(task_dir, query=str(request.get("query", "")),
                      location=request.get("location"), start_date=request.get("start_date"),
                      end_date=request.get("end_date"), offset=int(request.get("offset", 0)),
                      limit=min(int(request.get("limit", 60)), 80))
    page_ref = f"p{page_number}"
    refs = {}
    for index, photo in enumerate(expected["photos"], 1):
        ref = f"{page_ref}-{index}"
        photo["image_ref"] = ref
        refs[ref] = photo["image"]
    expected.update(page_ref=page_ref, image_refs=refs)
    if response != expected:
        raise ValueError("album reference issuance differs from the task's raw album")
    return refs


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                    separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _identity_optionals(value, path=(), additions=None):
    """Canonicalize only missing optional claim fields; preserve every value."""
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "identity_claims" and isinstance(item, list):
                for index, claim in enumerate(item):
                    if isinstance(claim, dict):
                        for field in ("image_id", "relation_to_owner"):
                            if field not in claim:
                                claim[field] = None
                                if additions is not None:
                                    additions.append([*path, key, index, field])
            _identity_optionals(item, (*path, key), additions)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _identity_optionals(item, (*path, index), additions)


def project_grader_inputs(task_dir: Path, submission: dict, state: dict) -> tuple[dict, dict]:
    """Return equivalent grader copies, failing closed on unproven aliases."""
    image_path, inspect, search, episode_error = _services()
    invalid = episode_error(submission, state)
    if invalid:
        raise ValueError(f"raw episode cannot be projected: {invalid}")
    if "grader_projection" in submission:
        raise ValueError("grader projection requires an unmodified raw submission")
    projected, projected_state = copy.deepcopy(submission), copy.deepcopy(state)
    trace = submission["execution_trace"]
    issued = {}
    page_number = 0
    rewrites = []
    # The tool-call ordinal is already bound to this exact raw trace by the
    # Episode gate. Never match a duplicate call by filename or dict equality.
    call_ordinal = -1
    for index, event in enumerate(trace):
        if event.get("kind") != "tool_call":
            continue
        call_ordinal += 1
        if event.get("status") != "succeeded":
            continue
        if event.get("name") == "album_browse":
            page_number += 1
            # Validate lazily only if this page is used by a short reference.
            response = event.get("response", {})
            page = response.get("page_ref") if isinstance(response, dict) else None
            if isinstance(page, str):
                issued[page] = (event, page_number)
            continue
        request = event.get("request", {})
        ref = request.get("image_id") if isinstance(request, dict) else None
        if event.get("name") != "image_view" or not isinstance(ref, str) or not _IMAGE_REF.fullmatch(ref):
            continue
        page = ref.split("-", 1)[0]
        if page not in issued:
            raise ValueError("image_view reference was not issued earlier in this session")
        browse, number = issued[page]
        refs = _issued_page(Path(task_dir), browse, number, search)
        image = refs.get(ref)
        if image is None:
            raise ValueError("image_view reference was not part of its issued album page")
        browse_turn, view_turn = browse.get("agent_turn"), event.get("agent_turn")
        if (browse["sequence"] >= event["sequence"] or _timestamp(browse) > _timestamp(event)
                or type(browse_turn) is not int or type(view_turn) is not int
                or browse_turn > view_turn):
            raise ValueError("image_view reference issuance order is inconsistent")
        expected = {**inspect(Path(task_dir), image), "image_ref": ref}
        raw = image_path(Path(task_dir), image).read_bytes()
        observation = {"image_id": image, "media_type": expected["media_type"],
                       "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        if event.get("response") != expected or event.get("image_observation") != observation:
            raise ValueError("image_view alias receipt/observation differs from its raw original")
        canonical_request = {**request, "image_id": image}
        projected["execution_trace"][index]["request"] = copy.deepcopy(canonical_request)
        projected["action_audit"][index]["request"] = copy.deepcopy(canonical_request)
        projected["tool_calls"][call_ordinal]["arguments"] = copy.deepcopy(canonical_request)
        rewrites.append({"sequence": event["sequence"], "issued_sequence": browse["sequence"],
                         "tool_call_ordinal": call_ordinal,
                         "image_ref": ref, "image_id": image, "sha256": observation["sha256"],
                         "raw_request": copy.deepcopy(request)})
    additions = []
    _identity_optionals(projected, additions=additions)
    _identity_optionals(projected_state)
    # This is a derived evaluator record, never supplied to an Agent or used
    # to replace the separately retained raw Episode/source-body evidence.
    projected["grader_projection"] = {"schema_version": VERSION, "image_aliases": rewrites,
                                      "raw_submission_sha256": _digest(submission),
                                      "identity_optional_additions": additions,
                                      "identity_optional_fields": ["image_id", "relation_to_owner"]}
    invalid = episode_error(projected, projected_state)
    if invalid:
        raise ValueError(f"grader projection broke episode consistency: {invalid}")
    return projected, projected_state


def raw_visual_submission(task_dir: Path, submission: dict) -> dict:
    """Reverse and re-prove the exact allowed projection before source recheck.

    This does not certify visual input. The caller must still rebuild it from
    the original wire bodies and exact raw Episode snapshot. A forged derived
    record cannot relax that existing source-binding check.
    """
    proof = submission.get("grader_projection")
    if proof is None:
        return submission
    if not isinstance(proof, dict) or proof.get("schema_version") != VERSION:
        raise ValueError("unsupported grader projection proof")
    raw = copy.deepcopy(submission)
    raw.pop("grader_projection")
    additions = proof.get("identity_optional_additions")
    rewrites = proof.get("image_aliases")
    if not isinstance(additions, list) or not isinstance(rewrites, list):
        raise ValueError("incomplete grader projection proof")
    seen = set()
    for path in additions:
        if (not isinstance(path, list) or len(path) < 3 or path[-3] != "identity_claims"
                or type(path[-2]) is not int or path[-1] not in {"image_id", "relation_to_owner"}
                or any(type(part) not in (str, int) for part in path) or tuple(path) in seen):
            raise ValueError("invalid optional-field projection proof")
        seen.add(tuple(path))
        parent = raw
        try:
            for part in path[:-1]:
                parent = parent[part]
        except (IndexError, KeyError, TypeError) as exc:
            raise ValueError("optional-field projection path is missing") from exc
        if not isinstance(parent, dict) or path[-1] not in parent or parent[path[-1]] is not None:
            raise ValueError("optional-field projection changed a semantic value")
        del parent[path[-1]]
    seen = set()
    for record in rewrites:
        if (not isinstance(record, dict) or type(record.get("sequence")) is not int
                or type(record.get("tool_call_ordinal")) is not int or record["sequence"] in seen):
            raise ValueError("invalid image-alias projection proof")
        seen.add(record["sequence"])
        index, ordinal = record["sequence"] - 1, record["tool_call_ordinal"]
        if index < 0 or ordinal < 0:
            raise ValueError("invalid image-alias projection position")
        try:
            request = record["raw_request"]
            raw["execution_trace"][index]["request"] = copy.deepcopy(request)
            raw["action_audit"][index]["request"] = copy.deepcopy(request)
            raw["tool_calls"][ordinal]["arguments"] = copy.deepcopy(request)
        except (IndexError, KeyError, TypeError) as exc:
            raise ValueError("image-alias projection position is missing") from exc
    if _digest(raw) != proof.get("raw_submission_sha256"):
        raise ValueError("grader projection differs from its raw submission digest")
    expected, _ = project_grader_inputs(Path(task_dir), raw, raw["final_environment"])
    if expected != submission:
        raise ValueError("grader projection is not exactly the allowed raw-source projection")
    return raw
