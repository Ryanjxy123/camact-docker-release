"""Versioned, request-level token view used by cross-harness reports.

The collector's historical fields remain the source of record.  This module
adds a deliberately small flat view for consumers that need to distinguish a
provider-reported value, a derived value, and an unknown value.  It never
estimates missing usage and never infers logical requests or roles from names.
"""
from __future__ import annotations

from collections.abc import Mapping
import gzip
import hashlib
from pathlib import Path

from .adapters import FIELDS, NORMALIZER_VERSION, extract


SCHEMA_VERSION = "camact.normalized_request.v1"
PRIMARY_FIELDS = ("input_tokens", "output_tokens", "total_tokens")


def _mapping(value):
    return value if isinstance(value, Mapping) else {}


def _has_usage(row):
    raw = _mapping(row.get("raw_usage"))
    return bool(raw)


def _response_complete(row):
    """Return whether the wire response was an authoritative complete result.

    ``response_complete`` is emitted by the wire adapter.  A missing flag is
    intentionally treated as unknown; historical ledgers must not be upgraded
    to exact totals merely because they contain counters.
    """
    if row.get("officially_ended_incomplete_with_usage") is True:
        return True
    value = row.get("response_complete")
    if isinstance(value, bool):
        return value
    # A caller may provide the explicit terminal exception for a provider that
    # documents usage on an officially ended incomplete response.  No generic
    # ``request_status`` or HTTP success inference is accepted here.
    return False


def _field_state(row, key, value):
    states = _mapping(row.get("field_status"))
    state = states.get(key)
    if state in {"known", "missing", "inconsistent", "unverified"}:
        return state
    if value is not None:
        return "known"
    if _has_usage(row):
        return "missing"
    return "unverified"


def normalize_request(row: Mapping) -> dict:
    """Return a flat normalized view for one physical provider HTTP attempt.

    Values are nullable by design.  ``standardized_total_tokens`` is an exact
    inclusive-input total only when all primary counters have reliable
    semantics and the response reached an authoritative terminal boundary.
    ``provider_reported_total_tokens`` is retained independently and is never
    substituted for a missing standardized total.
    """
    if not isinstance(row, Mapping):
        raise TypeError("row must be a mapping")

    normalized = _mapping(row.get("normalized_tokens"))
    usage = _mapping(row.get("usage"))
    comparable = _mapping(row.get("comparable_tokens"))
    raw = _mapping(row.get("raw_usage"))
    # Collector rows currently expose normalized counters at top level.  The
    # fallback also makes this API useful on exported rows from older ledgers.
    values = {key: row.get(key, normalized.get(key, usage.get(key))) for key in FIELDS}
    statuses = {key: _field_state(row, key, values[key]) for key in FIELDS}
    issues = list(row.get("issues") or []) if isinstance(row.get("issues"), list) else []
    diagnostics = list(row.get("diagnostics") or []) if isinstance(row.get("diagnostics"), list) else []
    arithmetic = row.get("arithmetic_status")
    provenance = dict(_mapping(row.get("field_provenance")))
    # DeepSeek Chat explicitly reports cache misses.  This is a provider value,
    # unlike guessing an absent cache-write counter to be zero.  Preserve the
    # old collector field and add the reliable value only in this new view.
    miss = raw.get("prompt_cache_miss_tokens")
    hit = raw.get("prompt_cache_hit_tokens")
    if (row.get("normalized_protocol", row.get("protocol")) == "openai-chat"
            and isinstance(miss, int) and not isinstance(miss, bool) and miss >= 0
            and isinstance(hit, int) and not isinstance(hit, bool) and hit >= 0
            and values["input_tokens"] == miss + hit):
        values["uncached_input_tokens"] = miss
        statuses["uncached_input_tokens"] = "known"
        provenance["uncached_input_tokens"] = "raw_usage.prompt_cache_miss_tokens; checked with prompt_cache_hit_tokens"

    # A complete usage payload is necessary but insufficient for comparison:
    # the response itself must have a trustworthy terminal boundary and no
    # parser/arithmetic conflict.  Explicitly supplied comparable values are
    # still checked against those conditions rather than blindly copied.
    complete_wire = _response_complete(row)
    required_known = all(isinstance(values[key], int) and not isinstance(values[key], bool)
                         and values[key] >= 0 and statuses[key] == "known" for key in PRIMARY_FIELDS)
    inconsistent = arithmetic == "inconsistent" or any(
        statuses[key] == "inconsistent" for key in FIELDS
    ) or any(issue in {"malformed_stream", "invalid_terminal_response", "invalid_usage_container", "provider_total_mismatch",
                       "cache_exceeds_input", "reasoning_exceeds_output", "candidates_exceed_output"}
             for issue in issues)
    protocol_known = row.get("normalized_protocol", row.get("protocol")) in {
        "openai-chat", "openai-responses", "anthropic-messages", "deepseek-messages", "google-generative-language"}
    if required_known and values["total_tokens"] != values["input_tokens"] + values["output_tokens"]:
        inconsistent = True
    comparable_ok = bool(complete_wire and required_known and _has_usage(row) and protocol_known and not inconsistent)

    # Derive standardized counters only from normalized fields.  The existing
    # adapter's comparable_tokens is authoritative for field-level conflicts,
    # but a response that did not terminate cannot be made comparable here.
    standardized = {}
    for key in FIELDS:
        candidate = (values[key] if row.get("officially_ended_incomplete_with_usage") is True
                     or key == "uncached_input_tokens" and provenance.get(key, "").startswith("raw_usage.prompt_cache_miss_tokens")
                     else comparable.get(key, values[key]))
        standardized[key] = candidate if comparable_ok and candidate is not None else None
    if comparable_ok and all(standardized[key] is not None for key in ("input_tokens", "output_tokens")):
        standardized["total_tokens"] = standardized["input_tokens"] + standardized["output_tokens"]
    else:
        standardized["total_tokens"] = None

    # The legacy provider_reported_tokens.total_tokens may contain a calculated
    # Messages I+O value even when no total was sent.  This new explicitly named
    # field therefore reads only an actual provider field from raw usage.
    raw_total = raw.get("total_tokens", raw.get("totalTokenCount"))
    reported_total = raw_total if isinstance(raw_total, int) and not isinstance(raw_total, bool) and raw_total >= 0 else None

    parse_failed = any(issue in {"malformed_stream", "invalid_terminal_response", "invalid_usage_container"}
                       or issue.startswith("collector_error:") for issue in issues)
    if parse_failed:
        usage_status = "parse_error"
    elif inconsistent:
        usage_status = "inconsistent"
    elif not _has_usage(row):
        usage_status = "missing"
    elif not complete_wire:
        usage_status = "partial"
    elif not required_known:
        usage_status = "partial"
    else:
        usage_status = "complete"

    request_status = row.get("request_status")
    if row.get("officially_ended_incomplete_with_usage") is True:
        generation_status = "incomplete_generation"
    elif request_status in {"succeeded", "completed"} and complete_wire:
        generation_status = "successful_generation"
    elif request_status in {"error", "interrupted", "timeout", "failed"}:
        generation_status = "failed_http_attempt"
    elif request_status in {"in_flight", None}:
        generation_status = "unknown"
    else:
        generation_status = "unknown"

    # Role and logical request attribution are intentionally pass-through only.
    role = row.get("role", row.get("component"))
    logical_id = row.get("logical_model_request_id")
    if logical_id is None and row.get("operation_attribution") == "explicit_logical_call":
        logical_id = row.get("operation_id")
    operation_type = row.get("agent_operation_type")
    request_kind = ("native_auxiliary_generation" if operation_type in {"auxiliary_generation", "context_compaction"}
                    else "non_generation_api" if row.get("protocol") is None
                    else "model_generation")

    coverage_status = "complete" if complete_wire else (
        "partial_response" if _has_usage(row) else "usage_unobserved")
    missing_reason = ("collector_parse_error" if parse_failed else
                      "failed_http_no_provider_usage" if not _has_usage(row) and request_status in {"error", "failed", "interrupted", "timeout"} else
                      "successful_http_no_provider_usage" if not _has_usage(row) and request_status == "succeeded" else
                      "usage_not_observed" if not _has_usage(row) else
                      "response_capture_incomplete" if not complete_wire else None)
    return {
        "schema_version": SCHEMA_VERSION,
        "normalizer_version": row.get("normalizer_version", NORMALIZER_VERSION),
        "physical_http_attempt_id": row.get("physical_http_attempt_id", row.get("model_request_id")),
        "logical_model_request_id": logical_id,
        "operation_id": row.get("operation_id"),
        "attempt_id": row.get("attempt_id"),
        "run_id": row.get("run_id"),
        "harness_id": row.get("harness_id"),
        "task_id": row.get("task_id"),
        "role": role,
        "request_kind": request_kind,
        "logical_request_observability": "explicit" if logical_id is not None else "physical_attempt_only",
        "agent_operation_type": row.get("agent_operation_type"),
        "protocol": row.get("normalized_protocol", row.get("protocol")),
        "request_status": request_status,
        "generation_status": generation_status,
        "input_tokens": values["input_tokens"],
        "output_tokens": values["output_tokens"],
        "total_tokens": values["total_tokens"],
        "cache_read_tokens": values["cache_read_tokens"],
        "cache_write_tokens": values["cache_write_tokens"],
        "uncached_input_tokens": values["uncached_input_tokens"],
        "reasoning_tokens": values["reasoning_tokens"],
        "provider_reported_total_tokens": reported_total,
        "standardized_total_tokens": standardized["total_tokens"],
        "standardized_tokens": standardized,
        "field_status": statuses,
        "field_provenance": provenance,
        "missing_reason": missing_reason,
        "usage_status": usage_status,
        "usage_source": row.get("usage_source", "provider_http_response" if _has_usage(row) else "not_reported"),
        "coverage_status": coverage_status,
        "response_complete": complete_wire,
        "comparable": comparable_ok,
        "issues": issues,
        "diagnostics": diagnostics,
    }


def enrich_terminal_usage(row: Mapping, project_root=None) -> dict:
    """Read-only enrichment for archived Responses terminal Usage evidence.

    Only a byte-exact request/response pair below the row's explicit run path
    can add the official incomplete-usage marker. Missing files or mismatches
    leave the copied row unchanged. No historical file is ever written.
    """
    result = dict(row)
    if (row.get("protocol") != "openai-responses" or row.get("response_complete") is not False
            or row.get("officially_ended_incomplete_with_usage") is True
            or not row.get("run_id") or not row.get("response_sha256") or not row.get("request_sha256")):
        return result
    run = Path(str(row["run_id"]))
    if not run.is_absolute():
        if project_root is None:
            return result
        run = Path(project_root) / run
    if project_root is not None and not run.resolve().is_relative_to(Path(project_root).resolve()):
        return result
    for capture in (run / "runs/execution/capture", run / "capture"):
        if not capture.is_dir():
            continue
        for path in sorted(capture.glob("*.response.gz")):
            request = path.with_name(path.name.replace(".response.gz", ".request.gz"))
            if path.is_symlink() or request.is_symlink() or not request.is_file():
                continue
            try:
                payload = gzip.decompress(path.read_bytes())
                if hashlib.sha256(payload).hexdigest() != row["response_sha256"]:
                    continue
                if hashlib.sha256(gzip.decompress(request.read_bytes())).hexdigest() != row["request_sha256"]:
                    continue
                evidence = extract(payload, row["protocol"], profile=row.get("usage_profile_override"))
            except (OSError, EOFError, ValueError):
                continue
            if (not evidence["officially_ended_incomplete_with_usage"]
                    or evidence["raw_usage"] != row.get("raw_usage")):
                continue
            result["officially_ended_incomplete_with_usage"] = True
            result["provider_terminal_status"] = evidence["provider_terminal_status"]
            result["terminal_usage_evidence"] = str(path)
            return result
    return result


__all__ = ["SCHEMA_VERSION", "normalize_request", "enrich_terminal_usage"]
