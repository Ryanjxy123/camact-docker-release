"""Portable statistics/durable JSON helpers retained from formal preflight."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

from harness.camact_token_usage_v1.completeness import (summarize_bounds, token_field_display, token_completeness_text, slot_usage_with_bounds)

HISTORICAL_USER = ""
REQUEST_COUNT_METRIC = "agent_model_http_attempts"
TOKEN_FIELDS = ("input_tokens", "output_tokens", "total_tokens", "cache_read_tokens", "cache_write_tokens")

REQUEST_COUNT_DESCRIPTION = "Agent HTTP 请求统计所选有效执行的物理模型请求；缺失 Token 保持 N/A，Simulator/Judge 和全部 Attempt 单独统计。"

def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()

def read(path):
    return json.loads(Path(path).read_text())

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f'.{os.getpid()}.tmp')
    with temporary.open('x') as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

def request_totals(usages):
    """Keep physical requests, logical identities and capture coverage separate.

    Legacy v3 summaries already carry http_attempt_count/capture_complete, so
    publishing the HTTP metric never depends on native logical request IDs.
    http_attempts retains the observed-count view for existing JSON consumers.
    """
    def count(usage, field):
        value = usage.get(field) if isinstance(usage, dict) else None
        return value if type(value) is int and value >= 0 else None

    def complete_sum(values):
        return sum(values) if values and all(v is not None for v in values) else None

    physical = [count(u, 'http_attempt_count') for u in usages]
    logical = [count(u, 'logical_request_count') for u in usages]
    covered = sum(n is not None and isinstance(u, dict) and u.get('capture_complete') is True
                  for u, n in zip(usages, physical))
    complete = bool(usages) and covered == len(usages)
    return dict(request_count_metric=REQUEST_COUNT_METRIC,
                request_count=sum(physical) if complete else None,
                request_count_status='complete' if complete else
                    'unknown_capture_incomplete' if usages else 'unknown_no_scored_usage',
                request_task_coverage=covered, request_task_total=len(usages),
                http_attempts=complete_sum(physical), logical_requests=complete_sum(logical))

def token_field_coverage(usages):
    """Return per-field known sums without turning missing values into zero.

    A provider-reported zero is a known value and therefore contributes to
    coverage.  A missing/invalid value remains unknown even when the other
    fields in the same request are present.
    """
    result = {}
    total = len(usages)
    for field in TOKEN_FIELDS:
        values = []
        for usage in usages:
            value = usage.get('exact_tokens', {}).get(field) if isinstance(usage, dict) else None
            if type(value) is int and value >= 0:
                values.append(value)
        result[field] = {
            'known_slots': len(values),
            'unknown_slots': total - len(values),
            'total_slots': total,
            'known_sum': sum(values),
            'complete': bool(usages) and len(values) == total,
        }
    return result

def token_coverage_text(stats):
    coverage = stats.get('token_field_coverage', {})
    labels = {
        'input_tokens': 'input', 'output_tokens': 'output',
        'total_tokens': 'total', 'cache_read_tokens': 'cache_read',
        'cache_write_tokens': 'cache_write',
    }
    return '; '.join(
        f"{labels[field]} {coverage.get(field, {}).get('known_slots', 0)}/"
        f"{coverage.get(field, {}).get('total_slots', stats.get('request_task_total', 0))}"
        for field in TOKEN_FIELDS)
