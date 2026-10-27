"""One aggregation contract for operations, tasks and every reporting level."""
from .adapters import FIELDS, METRIC_SCOPE, NORMALIZER_VERSION

PRIMARY = ("input_tokens", "output_tokens", "total_tokens")


def totals(rows, *, coverage_valid=True):
    rows = list(rows)
    exact, known, comparable, coverage, semantics, declared = {}, {}, {}, {}, {}, {}
    for key in FIELDS:
        values = [r.get(key) for r in rows]
        coverage[key] = sum(v is not None for v in values)
        exact[key] = sum(values) if all(v is not None for v in values) else None
        reported = [r.get("provider_reported_tokens", {}).get(key) for r in rows]
        declared[key] = sum(reported) if all(v is not None for v in reported) else None
        known[key] = sum(v for v in values if v is not None) if coverage[key] else (None if rows else 0)
        semantics[key] = {
            state: sum(r.get("field_status", {}).get(key, "unverified") == state for r in rows)
            for state in ("known", "missing", "inconsistent", "unverified")}
        eligible = coverage_valid and all(
            r.get("normalizer_version") == NORMALIZER_VERSION
            and r.get("metric_scope") == METRIC_SCOPE
            and r.get("comparable_tokens", {}).get(key) is not None for r in rows)
        comparable[key] = sum(r["comparable_tokens"][key] for r in rows) if eligible else None
    primary_valid = all(comparable[k] is not None for k in PRIMARY)
    extension_scopes = {}
    for row in rows:
        details = row.get("provider_extensions", {})
        if not details.get("scope"):
            continue
        group = extension_scopes.setdefault(details["scope"], {"request_count": 0, "known_counters": {}, "field_coverage": {}})
        group["request_count"] += 1
        for key, value in details.items():
            if isinstance(value, int) and not isinstance(value, bool):
                group["known_counters"][key] = group["known_counters"].get(key, 0) + value
                group["field_coverage"][key] = group["field_coverage"].get(key, 0) + 1
    return {
        "schema_version": "camact.token_usage.v2", "normalizer_version": NORMALIZER_VERSION,
        "metric_scope": METRIC_SCOPE, "tokens": exact, "normalized_tokens": exact.copy(),
        "provider_reported_tokens": declared, "provider_extension_scopes": extension_scopes,
        "known_tokens": known, "comparable_tokens": comparable, "field_coverage": coverage,
        "field_coverage_denominator": len(rows), "semantic_validity": semantics,
        "request_coverage": "complete" if coverage_valid else "unverified_or_incomplete",
        "arithmetic_validity": {state: sum(r.get("arithmetic_status", "unverified") == state for r in rows)
                               for state in ("consistent", "inconsistent", "unverified")},
        "operation_attribution": {
            "explicit_logical_requests": sum(r.get("operation_attribution") == "explicit_logical_call" for r in rows),
            "physical_request_only": sum(r.get("operation_attribution") != "explicit_logical_call" for r in rows),
            "explicit_parent_requests": sum(bool(r.get("parent_tool_use_id")) for r in rows)},
        "comparable": primary_valid,
        "usage_completeness": "complete" if primary_valid else "partial" if any(r.get("raw_usage") for r in rows) else "unknown",
    }
