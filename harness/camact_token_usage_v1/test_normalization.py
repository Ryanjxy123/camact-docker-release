"""Regression tests for the additive normalized request view."""
from __future__ import annotations

import unittest

from .normalization import SCHEMA_VERSION, normalize_request


def _row(**updates):
    row = {
        "run_id": "run-1",
        "harness_id": "baseline",
        "task_id": "task-001",
        "attempt_id": "attempt-1",
        "model_request_id": "physical-1",
        "operation_id": "logical-1",
        "operation_attribution": "explicit_logical_call",
        "protocol": "openai-chat",
        "request_status": "succeeded",
        "response_complete": True,
        "raw_usage": {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14},
        "input_tokens": 10,
        "output_tokens": 4,
        "total_tokens": 14,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
        "uncached_input_tokens": 10,
        "reasoning_tokens": None,
        "provider_reported_tokens": {"total_tokens": 14},
        "comparable_tokens": {"input_tokens": 10, "output_tokens": 4, "total_tokens": 14,
                              "cache_read_tokens": 0, "cache_write_tokens": 0,
                              "uncached_input_tokens": 10, "reasoning_tokens": None},
        "field_status": {"input_tokens": "known", "output_tokens": "known", "total_tokens": "known"},
        "arithmetic_status": "consistent",
        "issues": [],
        "diagnostics": [],
    }
    row.update(updates)
    return row


def test_complete_request_exposes_comparable_standardized_total_and_ids():
    normalized = normalize_request(_row(role="agent", component="agent_model"))
    assert normalized["schema_version"] == SCHEMA_VERSION
    assert normalized["physical_http_attempt_id"] == "physical-1"
    assert normalized["logical_model_request_id"] == "logical-1"
    assert normalized["role"] == "agent"
    assert normalized["standardized_total_tokens"] == 14
    assert normalized["provider_reported_total_tokens"] == 14
    assert normalized["usage_status"] == "complete"
    assert normalized["coverage_status"] == "complete"
    assert normalized["comparable"] is True


def test_http_402_without_usage_is_unknown_and_never_zero():
    row = _row(request_status="error", http_status=402, response_complete=False,
               raw_usage={}, input_tokens=None, output_tokens=None, total_tokens=None,
               cache_read_tokens=None, cache_write_tokens=None, uncached_input_tokens=None,
               provider_reported_tokens={}, comparable_tokens={}, field_status={})
    normalized = normalize_request(row)
    assert normalized["usage_status"] == "missing"
    assert normalized["coverage_status"] == "usage_unobserved"
    assert normalized["provider_reported_total_tokens"] is None
    assert normalized["standardized_total_tokens"] is None
    assert normalized["comparable"] is False
    assert normalized["input_tokens"] is None


def test_incomplete_wire_with_counters_is_partial_and_not_comparable():
    normalized = normalize_request(_row(response_complete=False, request_status="succeeded"))
    assert normalized["usage_status"] == "partial"
    assert normalized["coverage_status"] == "partial_response"
    assert normalized["standardized_total_tokens"] is None
    assert normalized["comparable"] is False


def test_provider_total_mismatch_keeps_reported_value_but_rejects_standardized_total():
    normalized = normalize_request(_row(raw_usage={"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 99},
                                         provider_reported_tokens={"total_tokens": 99},
                                         issues=["provider_total_mismatch"],
                                         arithmetic_status="inconsistent"))
    assert normalized["provider_reported_total_tokens"] == 99
    assert normalized["standardized_total_tokens"] is None
    assert normalized["usage_status"] == "inconsistent"
    assert normalized["comparable"] is False


class TestNormalizedRequest(unittest.TestCase):
    """stdlib runner keeps this regression usable in the minimal image."""

    def test_complete(self):
        test_complete_request_exposes_comparable_standardized_total_and_ids()

    def test_missing(self):
        test_http_402_without_usage_is_unknown_and_never_zero()

    def test_incomplete(self):
        test_incomplete_wire_with_counters_is_partial_and_not_comparable()

    def test_mismatch(self):
        test_provider_total_mismatch_keeps_reported_value_but_rejects_standardized_total()


if __name__ == "__main__":
    unittest.main()

