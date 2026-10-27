"""Canonical, harness-independent measurement helpers.

This module contains execution telemetry normalization only.  It deliberately
does not import benchmark ground truth or evaluator/rubric code.  Raw harness
records remain available in the artifact; the values returned here are a
derived comparison layer for Native, Baseline, CamAct, and CamRoll.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping


MEASUREMENT_SCHEMA_VERSION = "camact.canonical_measurement.v1"
NATIVE_TOOL_NAMES = frozenset({"read", "glob", "grep", "bash"})
EVIDENCE_TOOL_NAMES = frozenset({"image_view", "inspect_image", "person_view_reference", "owner_profile_view", "evidence_select"})
IMAGE_EVIDENCE_TOOL_NAMES = frozenset({"image_view", "inspect_image", "person_view_reference", "owner_profile_view"})
DOMAIN_ACTION_TOOL_NAMES = frozenset({
    "message_create_draft", "message_send",
    "calendar_event_create", "calendar_create_event", "calendar_update_event", "calendar_create_event",
    "publish_draft", "publish_post",
    "workspace_write", "workspace_update",
    "album_create", "album_update", "album_add_images", "album_remove_images",
    "story_create", "story_create_draft", "story_update_draft",
    "archive_create", "archive_update",
    "checklist_create", "checklist_add_item", "checklist_update_item",
    "reservation_create", "reservation_update", "reservation_cancel",
})
IMAGE_SUFFIXES = frozenset({".jpg", ".jpeg", ".png"})


def _integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        integer = int(value)
    except (TypeError, ValueError):
        return None
    return integer if integer >= 0 else None


def _raw_usage(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def normalize_usage(value: Any, *, source: str = "unknown") -> dict[str, Any]:
    """Normalize one provider usage object without turning unknown into zero.

    Claude assistant snapshots commonly expose ``output_tokens: 0`` while the
    session aggregate contains the real output.  For that source, a zero with
    no total/completion field is therefore recorded as unavailable rather than
    as a factual per-call zero.
    """
    raw = _raw_usage(value)
    # OpenAI-compatible relays may attach zero-valued generic aliases beside
    # the actual prompt/completion counts. Match the session accounting order.
    input_value = _integer(raw.get("prompt_tokens", raw.get("input_tokens", raw.get("inputTokens"))))
    output_key = next((key for key in ("completion_tokens", "output_tokens", "outputTokens") if key in raw), None)
    output_value = _integer(raw.get(output_key)) if output_key else None
    total_value = _integer(raw.get("total_tokens", raw.get("totalTokenCount", raw.get("totalTokens"))))
    cached_value = _integer(raw.get("cached_input_tokens", raw.get("cache_read_input_tokens", raw.get("cachedInputTokens"))))
    if source.startswith("claude_assistant_message") and output_key and output_value == 0 and total_value is None:
        output_value = None
    if total_value is None and input_value is not None and output_value is not None:
        total_value = input_value + output_value
    available = any(item is not None for item in (input_value, output_value, total_value, cached_value))
    if source.startswith("claude_assistant_message") and output_value is None and total_value is None:
        available = False
    return {
        "input_tokens": input_value,
        "output_tokens": output_value,
        "cached_input_tokens": cached_value,
        "total_tokens": total_value,
        "usage_available": available,
        "usage_source": source if available else f"{source}_missing_per_call_usage",
        "raw": raw,
    }


def normalize_model_calls(
    calls: Iterable[Mapping[str, Any]],
    *,
    session_usage: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Return stable model-call records suitable for future token attribution."""
    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(calls, 1):
        if not isinstance(raw, Mapping):
            continue
        model_call_id = str(raw.get("model_call_id") or raw.get("call_id") or raw.get("id") or f"mc_{index:04d}")
        source = str(raw.get("usage_source") or raw.get("source") or "unknown")
        usage = normalize_usage(raw.get("usage", raw), source=source)
        unavailable_assistant = source.startswith("claude_assistant_message") and not usage["usage_available"]
        item: dict[str, Any] = {
            "model_call_id": model_call_id,
            "model": raw.get("model"),
            "timestamp_start": raw.get("timestamp_start", raw.get("started_at")),
            "timestamp_end": raw.get("timestamp_end", raw.get("finished_at")),
            "input_tokens": None if unavailable_assistant else usage["input_tokens"],
            "output_tokens": None if unavailable_assistant else usage["output_tokens"],
            "cached_input_tokens": None if unavailable_assistant else usage["cached_input_tokens"],
            "total_tokens": None if unavailable_assistant else usage["total_tokens"],
            "usage_available": usage["usage_available"],
            "usage_source": usage["usage_source"],
            "triggered_tool_call_ids": list(raw.get("triggered_tool_call_ids", [])) if isinstance(raw.get("triggered_tool_call_ids", []), list) else [],
            "preceding_tool_call_id": raw.get("preceding_tool_call_id"),
            "following_tool_call_ids": list(raw.get("following_tool_call_ids", [])) if isinstance(raw.get("following_tool_call_ids", []), list) else [],
        }
        if "step" in raw:
            item["step"] = raw.get("step")
        if raw.get("status") is not None:
            item["status"] = raw.get("status")
        item["raw_usage"] = usage["raw"]
        normalized.append(item)
    return normalized


def _tool_name(item: Mapping[str, Any]) -> str:
    return str(item.get("tool") or item.get("name") or "").strip()


def _arguments(item: Mapping[str, Any]) -> dict[str, Any]:
    value = item.get("arguments", item.get("input", {}))
    return dict(value) if isinstance(value, Mapping) else {}


def _status(item: Mapping[str, Any]) -> str:
    status = str(item.get("status") or "succeeded").casefold()
    response = item.get("response")
    if isinstance(response, Mapping) and response.get("ok") is False:
        status = "rejected" if "allow" in str(response.get("error", "")).casefold() else "failed"
    if status in {"ok", "success", "completed"}:
        return "succeeded"
    if status in {"denied", "rejected", "not_allowed"}:
        return "rejected"
    if status in {"succeeded", "success"}:
        return "succeeded"
    return status or "failed"


def _fingerprint(item: Mapping[str, Any]) -> str:
    explicit = item.get("action_id") or item.get("tool_call_id") or item.get("call_id") or item.get("id")
    if explicit:
        return f"id:{explicit}"
    payload = {"tool": _tool_name(item), "arguments": _arguments(item), "status": _status(item)}
    return "hash:" + hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def _semantic_fingerprint(item: Mapping[str, Any]) -> str:
    payload = {"tool": _tool_name(item), "arguments": _arguments(item), "status": _status(item)}
    return "hash:" + hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def _dedupe(
    items: Iterable[Mapping[str, Any]],
    *,
    semantic_across_ids: bool = False,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(items, 1):
        if not isinstance(raw, Mapping):
            continue
        item = dict(raw)
        key = _fingerprint(item)
        semantic_key = _semantic_fingerprint(item)
        if key in seen or (semantic_across_ids and semantic_key in seen):
            continue
        seen.add(key)
        if semantic_across_ids:
            seen.add(semantic_key)
        item.setdefault("action_id", item.get("id") or item.get("call_id") or f"act_{index:04d}")
        result.append(item)
    return result


def extract_native_tool_calls(events: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Extract one record per actual Claude native tool-use id.

    Partial stream snapshots are deduplicated by the provider tool-use id.  If
    an event has no id, its deterministic content fingerprint is used.
    """
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    positions: dict[str, int] = {}
    for event in events:
        if not isinstance(event, Mapping):
            continue
        candidates: list[Mapping[str, Any]] = []
        if event.get("type") == "assistant":
            message = event.get("message", event)
            content = message.get("content", []) if isinstance(message, Mapping) else []
            if isinstance(content, list):
                candidates.extend(item for item in content if isinstance(item, Mapping) and item.get("type") == "tool_use")
        if event.get("type") == "tool_use":
            candidates.append(event)
        stream_event = event.get("event")
        if event.get("type") == "stream_event" and isinstance(stream_event, Mapping):
            if stream_event.get("type") == "content_block_start":
                block = stream_event.get("content_block")
                if isinstance(block, Mapping) and block.get("type") == "tool_use":
                    candidates.append(block)
        for raw in candidates:
            name = _tool_name(raw)
            if name.casefold() not in NATIVE_TOOL_NAMES:
                continue
            tool_call_id = str(raw.get("tool_call_id") or raw.get("id") or "")
            item = {
                "tool_call_id": tool_call_id or None,
                "tool": name,
                "tool_category": "native",
                "arguments": _arguments(raw),
                "status": "succeeded",
                "parent_model_call_id": raw.get("parent_model_call_id"),
                "correlation_available": bool(tool_call_id),
            }
            # Claude's verbose/partial stream may emit an empty tool-use
            # snapshot before the same id's populated input. Merge the later
            # arguments so Read(image) remains observable in canonical data.
            if tool_call_id and tool_call_id in positions:
                existing = result[positions[tool_call_id]]
                arguments = _arguments(raw)
                if arguments:
                    existing["arguments"] = {**existing.get("arguments", {}), **arguments}
                continue
            key = _fingerprint(item)
            if key in seen:
                continue
            seen.add(key)
            item["tool_call_id"] = tool_call_id or f"tc_native_{len(result) + 1:04d}"
            if tool_call_id:
                positions[tool_call_id] = len(result)
            result.append(item)
    return result


def _is_native(item: Mapping[str, Any]) -> bool:
    # Source provenance alone is insufficient: Native image evidence records
    # deliberately use ``claude_code_native_read`` but are not native tools.
    return _tool_name(item).casefold() in NATIVE_TOOL_NAMES


def _is_evidence(item: Mapping[str, Any]) -> bool:
    return _tool_name(item).casefold() in EVIDENCE_TOOL_NAMES


def _is_domain_action_tool(item: Mapping[str, Any]) -> bool:
    category = str(item.get("tool_category") or item.get("category") or "").casefold()
    return _tool_name(item).casefold() in DOMAIN_ACTION_TOOL_NAMES or category in {"domain_action", "state_changing_action"}


def extract_domain_actions(
    tool_calls: Iterable[Mapping[str, Any]],
    actions: Iterable[Mapping[str, Any]] = (),
) -> list[dict[str, Any]]:
    """Return canonical domain actions from explicit actions and real tool calls."""
    return _dedupe([
        *(dict(item) for item in tool_calls if _is_domain_action_tool(item)),
        *(dict(item) for item in actions if not _is_native(item) and not _is_evidence(item)),
    ], semantic_across_ids=True)


def _image_record(item: Mapping[str, Any]) -> dict[str, Any] | None:
    """Convert a legacy image-view record into canonical inspection evidence."""
    if _status(item) != "succeeded" or _tool_name(item).casefold() not in IMAGE_EVIDENCE_TOOL_NAMES:
        return None
    args = _arguments(item)
    raw_path = args.get("file_path") or args.get("path")
    raw_image = args.get("image_id") or args.get("image")
    path = str(raw_path) if isinstance(raw_path, str) else None
    image_id = None
    if isinstance(raw_image, str):
        image_id = Path(raw_image.replace("\\", "/")).name
    elif path:
        candidate = Path(path.replace("\\", "/")).name
        if Path(candidate).suffix.casefold() in IMAGE_SUFFIXES:
            image_id = candidate
    if not path and not image_id:
        return None
    return {
        "path": path,
        "image_id": image_id,
        "provenance": str(item.get("source") or "canonical_evidence_mapping"),
        **({"tool_call_id": item.get("tool_call_id") or item.get("call_id") or item.get("id")} if item.get("tool_call_id") or item.get("call_id") or item.get("id") else {}),
    }


def _simulator_turn_count(
    final_state: Mapping[str, Any] | None,
    diagnostics: Mapping[str, Any],
) -> int:
    """Use live final state when available, with legacy diagnostics as fallback."""
    if isinstance(final_state, Mapping):
        simulator_state = final_state.get("user_simulator")
        if isinstance(simulator_state, Mapping) and "turns" in simulator_state:
            turns = simulator_state.get("turns")
            if isinstance(turns, list):
                return len(turns)
            parsed = _integer(turns)
            if parsed is not None:
                return parsed
    value = diagnostics.get("simulator_turns")
    if isinstance(value, list):
        return len(value)
    parsed = _integer(value)
    return parsed if parsed is not None else 0


def canonical_measurement(
    *,
    model_calls: Iterable[Mapping[str, Any]] = (),
    token_usage: Mapping[str, Any] | None = None,
    tool_calls: Iterable[Mapping[str, Any]] = (),
    actions: Iterable[Mapping[str, Any]] = (),
    evidence: Iterable[Any] = (),
    timing: Mapping[str, Any] | None = None,
    diagnostics: Mapping[str, Any] | None = None,
    final_state: Mapping[str, Any] | None = None,
    native_events: Iterable[Mapping[str, Any]] = (),
    provider_model_usage: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    diagnostics = diagnostics if isinstance(diagnostics, Mapping) else {}
    tool_call_records = [dict(item) for item in tool_calls if isinstance(item, Mapping)]
    action_records = [dict(item) for item in actions if isinstance(item, Mapping)]
    native = extract_native_tool_calls(native_events)
    explicit_native = [item for item in tool_call_records if _is_native(item)]
    native = _dedupe([*native, *explicit_native])
    domain = extract_domain_actions(tool_call_records, action_records)
    for index, item in enumerate(native, 1):
        item.setdefault("tool_call_id", f"tc_native_{index:04d}")
        item.setdefault("parent_model_call_id", None)
        item.setdefault("correlation_available", False)
    for index, item in enumerate(domain, 1):
        item.setdefault("action_id", item.get("id") or item.get("call_id") or f"act_{index:04d}")
        item.setdefault("parent_tool_call_id", None)
        item.setdefault("originating_model_call_id", None)
        item.setdefault("action_type", _tool_name(item))
        item.setdefault("tool_category", "domain_action")

    normalized_calls = normalize_model_calls(model_calls, session_usage=token_usage)
    per_model: dict[str, dict[str, Any]] = {}
    for call in normalized_calls:
        model = str(call.get("model") or "unknown")
        bucket = per_model.setdefault(model, {"model_calls": 0, "input_tokens": 0, "output_tokens": 0, "cached_input_tokens": 0, "total_tokens": 0, "usage_available_calls": 0})
        bucket["model_calls"] += 1
        if call.get("usage_available"):
            bucket["usage_available_calls"] += 1
        for name in ("input_tokens", "output_tokens", "cached_input_tokens", "total_tokens"):
            value = call.get(name)
            if isinstance(value, int):
                bucket[name] += value

    # Claude's terminal ``modelUsage`` is often the only reliable source for
    # auxiliary model accounting. Merge it without fabricating per-call data.
    for model, raw_usage in (provider_model_usage or {}).items():
        if not isinstance(raw_usage, Mapping):
            continue
        name = str(model).strip()
        if not name:
            continue
        bucket = per_model.setdefault(name, {
            "model_calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "cached_input_tokens": 0,
            "total_tokens": 0,
            "usage_available_calls": 0,
        })
        values = {
            "input_tokens": raw_usage.get("input_tokens", raw_usage.get("inputTokens", raw_usage.get("prompt_tokens"))),
            "output_tokens": raw_usage.get("output_tokens", raw_usage.get("outputTokens", raw_usage.get("completion_tokens"))),
            "cached_input_tokens": raw_usage.get("cached_input_tokens", raw_usage.get("cacheReadInputTokens", raw_usage.get("cachedInputTokens"))),
            "total_tokens": raw_usage.get("total_tokens", raw_usage.get("totalTokens")),
        }
        for field, value in values.items():
            parsed = _integer(value)
            if parsed is not None:
                # modelUsage is an aggregate; replace the call-derived value
                # for that model rather than double-counting it.
                bucket[field] = parsed
        if bucket["total_tokens"] == 0 and (bucket["input_tokens"] or bucket["output_tokens"]):
            bucket["total_tokens"] = bucket["input_tokens"] + bucket["output_tokens"]
        cost = raw_usage.get("cost_usd", raw_usage.get("costUSD"))
        if isinstance(cost, (int, float)):
            bucket["cost_usd"] = float(cost)
        bucket["usage_available_calls"] = max(int(bucket.get("usage_available_calls", 0)), 1)

    status_counts = Counter(_status(item) for item in domain)
    native_by_type = Counter(_tool_name(item) for item in native)
    read_records: list[dict[str, Any]] = []
    for item in native:
        if _status(item) != "succeeded":
            continue
        args = _arguments(item)
        path = args.get("file_path") or args.get("path")
        image_arg = args.get("image_id") or args.get("image")
        if isinstance(path, str):
            image = Path(path.replace("\\", "/")).name
            is_image = Path(image).suffix.casefold() in IMAGE_SUFFIXES
            read_records.append({"path": path, "image_id": image if is_image else None, "provenance": "claude_code_native_read", "tool_call_id": item.get("tool_call_id")})
        elif isinstance(image_arg, str) and Path(image_arg).suffix.casefold() in IMAGE_SUFFIXES:
            read_records.append({"path": None, "image_id": Path(image_arg).name, "provenance": str(item.get("source") or "canonical_evidence_mapping"), "tool_call_id": item.get("tool_call_id")})
    # Historical Native artifacts may only retain the adapter's translated
    # image_view record. It is evidence provenance, not a second domain tool.
    if not any(record.get("image_id") for record in read_records):
        for item in [*tool_calls, *actions]:
            if isinstance(item, Mapping):
                record = _image_record(item)
                if record is not None:
                    read_records.append(record)
    raw_inspections = diagnostics.get("external_file_inspections")
    if isinstance(raw_inspections, list) and not read_records:
        for item in raw_inspections:
            if isinstance(item, Mapping):
                record = dict(item)
                if record.get("path") or record.get("image_id"):
                    read_records.append(record)
            elif isinstance(item, str):
                read_records.append({"path": item, "image_id": Path(item).name, "provenance": "legacy_diagnostic"})
    unique_paths = {str(item.get("path") or item.get("image_id")) for item in read_records if item.get("path") or item.get("image_id")}
    image_views = [item for item in read_records if item.get("image_id")]
    unique_images = {str(item.get("image_id")) for item in image_views if item.get("image_id")}
    runtime_calls = tool_call_records
    retrieval_calls = sum(
        _tool_name(item) == "album_search" and _status(item) == "succeeded"
        for item in runtime_calls
    )
    if not retrieval_calls:
        retrieval_calls = _integer(diagnostics.get("retrieval_calls")) or 0
    selected = [str(item) for item in evidence if isinstance(item, str)]
    usage = dict(token_usage) if isinstance(token_usage, Mapping) else {}
    timing = timing if isinstance(timing, Mapping) else {}
    duration = timing.get("duration_seconds")
    measurement = {
        "schema_version": MEASUREMENT_SCHEMA_VERSION,
        "accounting_definitions": {
            "model_calls": "one record per stable assistant message id; provider aggregate-only auxiliary models are not fabricated into call records",
            "session_token_usage": "terminal/session aggregate reported by the harness; missing fields remain unavailable",
            "per_model_usage": "provider-reported aggregate keyed by observed model name; do not add to session aggregate",
            "cost_usd": "terminal/session total cost as reported by the harness; scope is provider-reported total",
            "native_tool_calls": "unique Claude native Read/Glob/Grep/Bash tool-use ids",
            "tool_calls": "number of runtime tool calls, including failed calls; native tool calls are reported separately",
            "retrieval_calls": "successful album_search calls, with harness diagnostic fallback when no search calls are present",
            "domain_actions": "unique state-changing RuntimeEnvironment actions; stable id first, normalized fingerprint fallback",
            "image_views": "successful image-bearing native Read events, with unique_image_views deduplicated by image id",
            "simulator_turns": "number of turns recorded in live final_state.user_simulator, with legacy diagnostics fallback",
        },
        "model_calls": normalized_calls,
        "per_model_usage": per_model,
        "usage_reconciliation": reconcile_usage(normalized_calls, usage),
        "native_tool_calls": native,
        "native_tool_calls_by_type": dict(sorted(native_by_type.items())),
        "tool_calls": len(runtime_calls),
        "retrieval_calls": retrieval_calls,
        "domain_actions": domain,
        "domain_action_attempts": len(domain),
        "domain_action_succeeded": status_counts.get("succeeded", 0),
        "domain_action_rejected": status_counts.get("rejected", 0),
        "domain_action_failed": sum(value for key, value in status_counts.items() if key not in {"succeeded", "rejected"}),
        "external_file_inspections": len(read_records),
        "unique_external_files_inspected": len(unique_paths),
        "image_views": len(image_views),
        "unique_image_views": len(unique_images),
        "evidence_selected": selected,
        "simulator_turns": _simulator_turn_count(final_state, diagnostics),
        "duration_seconds": duration,
        "cost_usd": usage.get("cost_usd"),
        "cost": usage.get("cost_usd"),
        "raw_external_inspections": read_records,
    }
    return measurement


def reconcile_usage(model_calls: Iterable[Mapping[str, Any]], session_usage: Mapping[str, Any] | None) -> dict[str, Any]:
    session = normalize_usage(session_usage or {}, source="session_aggregate")
    known = [item for item in model_calls if isinstance(item, Mapping) and item.get("usage_available")]
    sums = {name: sum(int(item[name]) for item in known if isinstance(item.get(name), int)) for name in ("input_tokens", "output_tokens", "cached_input_tokens", "total_tokens")}
    # A provider may omit optional cached-token fields.  Omission is an
    # unavailable comparison, not a mismatch; fields that are present must
    # still reconcile exactly with the per-call sum.
    comparable = {
        name: (None if session.get(name) is None else sums[name] == session.get(name))
        for name in sums
    }
    return {
        "session_usage": {key: session.get(key) for key in ("input_tokens", "output_tokens", "cached_input_tokens", "total_tokens")},
        "known_per_call_usage": sums,
        "known_per_call_count": len(known),
        "status": "matched" if known and all(value is not False for value in comparable.values()) else "partial" if known else "session_aggregate_only",
        "comparable_fields": comparable,
    }


def observed_models(events: Iterable[Mapping[str, Any]], metadata: Mapping[str, Any] | None = None) -> list[str]:
    found: set[str] = set()
    # Stock Claude Code emits this exact sentinel for local error messages.
    # Filter native observations only; model_policy still checks configured
    # entrypoints and the independently collected upstream models strictly.
    def add(value):
        if value and str(value) != "<synthetic>":
            found.add(str(value))

    for event in events:
        if not isinstance(event, Mapping):
            continue
        for value in (event.get("model"), (event.get("message") or {}).get("model") if isinstance(event.get("message"), Mapping) else None):
            add(value)
        stream = event.get("event")
        if isinstance(stream, Mapping):
            message = stream.get("message")
            if isinstance(message, Mapping) and message.get("model"):
                add(message["model"])
    metadata = metadata if isinstance(metadata, Mapping) else {}
    model_usage = metadata.get("modelUsage", metadata.get("model_usage"))
    if isinstance(model_usage, Mapping):
        for key in model_usage:
            if str(key).strip():
                add(key)
    if metadata.get("model"):
        add(metadata["model"])
    return sorted(found)


def model_policy(
    *,
    requested_model: str,
    primary_model: str | None = None,
    small_fast_model: str | None = None,
    subagent_model: str | None = None,
    fallback_model: str | None = None,
    utility_model: str | None = None,
    observed: Iterable[str] = (),
    configured_model: str | None = None,
    upstream_models: Iterable[str] = (),
    aliases: Mapping[str, str] | None = None,
    configured_entrypoints: Mapping[str, str] | None = None,
    enforce: bool = True,
) -> dict[str, Any]:
    """Describe and validate the single-model policy for one run.

    ``requested_model`` is the experiment control variable.  Gateway aliases
    are accepted only when an explicit ``aliases`` mapping proves that they
    resolve to that requested model; otherwise the discrepancy is visible and
    fail-closed when enforcement is enabled.
    """
    requested = str(requested_model or "").strip()
    aliases = {str(key): str(value) for key, value in (aliases or {}).items()}
    primary = str(primary_model or requested)
    small_fast = str(small_fast_model or requested)
    subagent = str(subagent_model or requested)
    fallback = str(fallback_model or requested)
    utility = str(utility_model or requested)
    configured = str(configured_model or primary)
    observed_models_list = sorted({str(item) for item in observed if str(item).strip()})
    upstream_list = sorted({str(item) for item in upstream_models if str(item).strip()})
    entrypoints = {
        str(key): str(value)
        for key, value in (configured_entrypoints or {}).items()
        if str(value).strip()
    }

    def matches(value: str) -> bool:
        return value == requested or aliases.get(value) == requested

    allowed = [requested] if requested else []
    violation = bool(requested) and any(
        not matches(str(item)) for item in [primary, small_fast, subagent, fallback, utility, configured, *entrypoints.values(), *observed_models_list, *upstream_list]
    )
    return {
        "requested_model": requested,
        "configured_model": configured,
        "primary_model": primary,
        "small_fast_model": small_fast,
        "subagent_model": subagent,
        "fallback_model": fallback,
        "utility_model": utility,
        "allowed_models": allowed,
        "observed_models": observed_models_list,
        "upstream_models": upstream_list,
        "aliases": aliases,
        "configured_entrypoints": entrypoints,
        "violation": bool(enforce and violation),
        "enforced": bool(enforce),
    }


def benchmark_provenance(benchmark_root: Path) -> dict[str, Any]:
    manifest = benchmark_root / "benchmark_manifest.json"
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest() if manifest.is_file() else None
    document: dict[str, Any] = {}
    if manifest.is_file():
        try:
            value = json.loads(manifest.read_text(encoding="utf-8"))
            if isinstance(value, Mapping):
                document = dict(value)
        except (OSError, json.JSONDecodeError):
            document = {}
    derived = f"manifest-{digest[:12]}" if digest else None
    release_id = document.get("release_id") or derived
    release_version = document.get("release_version") or document.get("updated_at") or derived
    return {
        "benchmark_root": str(benchmark_root),
        "manifest_sha256": digest,
        "benchmark_manifest_sha256": digest,
        "release_id": release_id,
        "release_version": release_version,
        "benchmark_release_id": release_id,
        "benchmark_release_version": release_version,
        "task_count": document.get("task_count"),
    }


def normalize_artifact_dict(value: Mapping[str, Any], *, benchmark_root: Path | None = None) -> dict[str, Any]:
    """Offline-normalize an old artifact without changing its raw source file."""
    data = dict(value)
    run = dict(data.get("run") or {})
    if benchmark_root is not None:
        provenance = benchmark_provenance(benchmark_root)
        aliases = {
            "benchmark_release_id": provenance.get("benchmark_release_id"),
            "benchmark_release_version": provenance.get("benchmark_release_version"),
            "benchmark_manifest_sha256": provenance.get("benchmark_manifest_sha256"),
        }
        for key, fallback in aliases.items():
            if (not run.get(key) or str(run.get(key)).casefold() in {"unknown", "null", "none"}) and fallback:
                run[key] = fallback
    data["run"] = run
    if not isinstance(data.get("model_policy"), Mapping):
        diagnostics = data.get("diagnostics") if isinstance(data.get("diagnostics"), Mapping) else {}
        data["model_policy"] = dict(diagnostics.get("model_policy", {})) if isinstance(diagnostics.get("model_policy", {}), Mapping) else {}
    data["model_calls"] = normalize_model_calls(
        data.get("model_calls", []), session_usage=data.get("token_usage", {}) if isinstance(data.get("token_usage", {}), Mapping) else {}
    )
    # Recompute even when an artifact advertises the current measurement
    # schema: a copied/partially-written measurement must not override the
    # canonical values derived from the artifact's own raw channels.
    data["measurement"] = canonical_measurement(
        model_calls=data.get("model_calls", []),
        token_usage=data.get("token_usage", {}),
        tool_calls=data.get("tool_calls", []),
        actions=data.get("actions", []),
        evidence=data.get("evidence", []),
        timing=data.get("timing", {}),
        diagnostics=data.get("diagnostics", {}),
        final_state=data.get("final_state", {}) if isinstance(data.get("final_state"), Mapping) else None,
        provider_model_usage=(
            (data.get("diagnostics") or {}).get("provider_model_usage", (data.get("diagnostics") or {}).get("modelUsage", {}))
            if isinstance(data.get("diagnostics"), Mapping) else {}
        ),
    )
    return data
