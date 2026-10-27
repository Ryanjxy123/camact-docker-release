"""Evidence-backed token lower bounds, separate from exact usage totals.

Inputs are deduplicated physical requests or their aggregate summaries. Cache
and reasoning counters are already normalized; neither is added to I/O again.
Legacy exact/known fields are never rewritten by these reporting helpers.
"""
from __future__ import annotations

from functools import lru_cache
import hashlib
import json
from pathlib import Path

PRIMARY = ("input_tokens", "output_tokens", "total_tokens")
FIELDS = (*PRIMARY, "cache_read_tokens", "cache_write_tokens")
PROTOCOLS = {"openai-chat", "openai-responses", "anthropic-messages",
             "deepseek-messages", "google-generative-language"}


def counter(value):
    return type(value) is int and value >= 0


def request_bounds(row):
    """Use exact standardized values or an unambiguous provider snapshot.

    A snapshot zero is a lower bound only. Incomplete output remains unknown
    as a final value even when message_start reports output_tokens=0.
    """
    result = dict.fromkeys(FIELDS)
    if row.get("usage_status") in {"inconsistent", "parse_error", "missing"}:
        return result
    if row.get("arithmetic_status") == "inconsistent" or any(
            state == "inconsistent" for state in (row.get("field_status") or {}).values()):
        return result
    warnings = set(row.get("issues") or []) - {"response_incomplete", "missing_input_or_output"}
    if warnings or row.get("diagnostics"):
        # Partial snapshots with parser/arithmetic warnings need independent
        # review. Complete standardized values remain the normalizer's job.
        if row.get("comparable") is not True:
            return result
    exact = row.get("standardized_tokens") or {}
    complete = row.get("comparable") is True and row.get("usage_status") == "complete"
    if complete:
        for field in FIELDS:
            if counter(exact.get(field)):
                result[field] = exact[field]
        return result
    if (row.get("usage_status") != "partial" or
            row.get("coverage_status") != "partial_response" or
            row.get("protocol") not in PROTOCOLS):
        return result
    for field in FIELDS:
        value = row.get(field)
        if counter(value) and (row.get("field_status") or {}).get(field) == "known":
            result[field] = value
    inp, out, total = (result[f] for f in PRIMARY)
    if all(counter(v) for v in (inp, out, total)) and total != inp + out:
        return dict.fromkeys(FIELDS)
    if inp is not None or out is not None:
        # Sum only observed nonnegative components; this is a bound, not a
        # fabricated zero for the unknown component or an exact final total.
        result["total_tokens"] = sum(v for v in (inp, out) if v is not None)
    return result


def request_bound_summary(rows):
    bounds = [request_bounds(row) for row in rows]
    return {
        "known_token_lower_bounds": {
            f: sum(b[f] for b in bounds if b[f] is not None)
            if any(b[f] is not None for b in bounds) else None for f in FIELDS},
        "token_bound_coverage": {
            f: {"observed_requests": sum(b[f] is not None for b in bounds),
                "snapshot_requests": sum(b[f] is not None and row.get("comparable") is not True
                                         for b, row in zip(bounds, rows)),
                "total_requests": len(rows)} for f in FIELDS},
        "token_snapshot_requests": sum(any(b[f] is not None for f in FIELDS)
                                       and row.get('comparable') is not True
                                       for b, row in zip(bounds, rows)),
    }


@lru_cache(maxsize=32)
def _ledger_rows(path, size, mtime_ns):
    content = Path(path).read_bytes()
    return [json.loads(line) for line in content.splitlines() if line.strip()], hashlib.sha256(content).hexdigest()


def slot_usage_with_bounds(slot):
    """Add bounds to a legacy incomplete slot using its exact selected IDs.

    Historical manifests remain immutable. Only the three incomplete selected
    ledgers need this read-through when an old manifest is rendered directly.
    Missing/ambiguous evidence leaves the conservative legacy view unchanged.
    """
    usage = slot.get('selected_agent_usage')
    if (not isinstance(usage, dict) or usage.get('known_token_lower_bounds') is not None
            or all(counter((usage.get('exact_tokens') or {}).get(f)) for f in PRIMARY)):
        return usage
    expected = usage.get('physical_request_ids') or []
    binding = usage.get('usage_binding') or {}
    if not expected or len(set(expected)) != len(expected):
        return usage
    try:
        path = Path(binding.get('requests_path') or Path(slot['result']).parent/'token_usage/accounting_v3/requests.jsonl')
        stat = path.stat()
        entries, sha256 = _ledger_rows(str(path), stat.st_size, stat.st_mtime_ns)
        if binding.get('requests_sha256') and sha256 != binding['requests_sha256']:
            return usage
        wanted = set(expected)
        rows = [r for r in entries if r.get('role') == 'Agent' and r.get('model_request_id') in wanted
                and r.get('user_id') == slot['user_id'] and r.get('task_id') == slot['task']
                and r.get('harness_id') in {slot['harness'], 'canonical-baseline' if slot['harness'] == 'baseline' else slot['harness']}]
        from .unified_report import aggregate, IDENTITY
        identities = {tuple(r.get(k) for k in IDENTITY) for r in rows}
        if (len(rows) != len(expected) or len(identities) != 1
                or any(v is None for v in next(iter(identities)))
                or {r.get('model_request_id') for r in rows} != wanted):
            return usage
        bound_identity = binding.get('identity') or {}
        if bound_identity and any(rows[0].get(k) != v for k, v in bound_identity.items()):
            return usage
        if not bound_identity and Path(rows[0]['run_id']).resolve() != path.parents[2].resolve():
            return usage
        replay = aggregate(rows)
        if any(replay.get(k) != usage.get(k) for k in ('known_tokens', 'exact_tokens', 'capture_complete', 'http_attempt_count')):
            return usage
        return {**usage, **request_bound_summary(rows),
                'token_lower_bound_source': {'path': str(path), 'sha256': sha256,
                                             'physical_request_ids_verified': True}}
    except (OSError, ValueError, KeyError, TypeError):
        return usage


def _legacy_bound(usage, field):
    """Accept old exact summaries and complete+missing request partitions.

    Never blindly treat legacy known_tokens as reliable: it also contains
    provisional/inconsistent counters. Partial ledgers require request replay.
    """
    exact = (usage.get("exact_tokens") or {}).get(field)
    if counter(exact):
        return exact
    statuses = usage.get("usage_statuses") or {}
    n = usage.get("http_attempt_count")
    reliable = usage.get("reliable_usage_requests")
    known = usage.get("known_tokens") or {}
    coverage = usage.get("field_coverage") or {}
    if (statuses and set(statuses) <= {"complete", "missing"} and counter(n)
            and all(counter(v) for v in statuses.values()) and sum(statuses.values()) == n
            and counter(reliable) and reliable > 0 and statuses.get("complete", 0) == reliable
            and coverage.get(field) == reliable and counter(known.get(field))
            and all(counter(known.get(f)) for f in PRIMARY)
            and known["total_tokens"] == known["input_tokens"] + known["output_tokens"]):
        return known[field]
    return None


def summarize_bounds(usages):
    """Combine all confirmed requests, including those in incomplete slots."""
    usages = list(usages)
    present = [u for u in usages if isinstance(u, dict)]
    fields = {}
    for field in FIELDS:
        values = []
        for usage in present:
            value = (usage.get("known_token_lower_bounds") or {}).get(field)
            if not counter(value):
                value = _legacy_bound(usage, field)
            if counter(value):
                values.append(value)
        fields[field] = {"known_sum": sum(values) if values else None,
                         "bound_slots": len(values), "total_slots": len(usages)}
    complete_slots = sum(u.get("capture_complete") is True and
                         all(counter((u.get("exact_tokens") or {}).get(f)) for f in PRIMARY)
                         for u in present)
    counts_known = len(present) == len(usages) and all(
        counter(u.get("unknown_or_unreliable_usage_requests")) for u in present)
    missing = sum(u["unknown_or_unreliable_usage_requests"] for u in present) if counts_known else None
    return {"known_token_lower_bounds": {f: fields[f]["known_sum"] for f in FIELDS},
            "token_lower_bound_coverage": fields,
            "token_completeness": {
                "status": "complete" if usages and complete_slots == len(usages) else
                          "partial" if any(fields[f]["bound_slots"] for f in PRIMARY) else "unknown",
                "complete_slots": complete_slots, "total_slots": len(usages),
                "capture_complete_slots": sum(u.get('capture_complete') is True for u in present),
                "missing_usage_requests": missing,
                "usage_missing_slots": len(usages) - len(present),
                "snapshot_requests": sum(u.get('token_snapshot_requests', 0) for u in present)}}


def token_field_display(stats, field, *, comma=True):
    exact = (stats.get("exact_tokens") or {}).get(field)
    scope = stats.get('token_completeness') or {}
    captured = (stats.get('capture_complete') is not False and
                (not scope or scope.get('capture_complete_slots', scope.get('complete_slots')) == scope.get('total_slots')))
    if counter(exact) and captured:
        return f"{exact:,}" if comma else str(exact)
    # Optional cache breakdowns keep their established unknown presentation;
    # the formal I/O/Total columns expose the newly audited lower bounds.
    if field not in PRIMARY:
        return "N/A"
    bound = (stats.get("known_token_lower_bounds") or {}).get(field)
    if counter(bound):
        return f"≥{bound:,}" if comma else f"≥{bound}"
    return "N/A"


def token_completeness_text(stats):
    detail = stats.get("token_completeness") or {}
    complete, total = detail.get("complete_slots", 0), detail.get("total_slots", 0)
    label = "完整" if detail.get("status") == "complete" else "下限" if detail.get("status") == "partial" else "未知"
    missing = detail.get("missing_usage_requests")
    return f"{label}；槽位 {complete}/{total}；缺完整 Usage 请求 {missing if missing is not None else '未知'}"
