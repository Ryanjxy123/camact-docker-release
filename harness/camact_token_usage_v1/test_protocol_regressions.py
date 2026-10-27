"""Offline wire/HTTP regressions, including valid Usage on incomplete output."""
from __future__ import annotations

import gzip
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import urllib.error
import urllib.request

from .adapters import extract, normalize_details, protocol_for
from .collector import Collector
from .http import observe_open
from .normalization import normalize_request
from .unified_report import aggregate, judge_rows, role_rows


def sse(*events):
    return b"".join(b"data: " + json.dumps(event).encode() + b"\n\n" for event in events)


def view(payload, protocol="openai-responses"):
    evidence = extract(payload, protocol)
    return normalize_request({**evidence["usage"], **evidence, "protocol": protocol,
                              "request_status": "succeeded"})


def chat_body(response_id):
    return json.dumps({"id": response_id, "usage": {"prompt_tokens": 2,
        "completion_tokens": 3, "total_tokens": 5}, "choices": [{"finish_reason": "stop"}]})


def role_identity(run, task="task_001", attempt="attempt-1"):
    return {"run_id": str(run), "harness_id": "baseline", "user_id": "user",
            "task_id": task, "attempt_id": attempt}


class ProtocolRegressions(unittest.TestCase):
    def test_messages_cache_is_added_once_and_stream_snapshot_replaces(self):
        payload = sse(
            {"type": "message_start", "message": {"usage": {"input_tokens": 12, "output_tokens": 0,
                                                                    "cache_read_input_tokens": 30,
                                                                    "cache_creation_input_tokens": 7}}},
            {"type": "message_delta", "usage": {"output_tokens": 3}},
            {"type": "message_delta", "usage": {"output_tokens": 9}},
            {"type": "message_stop"})
        result = view(payload, "anthropic-messages")
        self.assertEqual((result["input_tokens"], result["output_tokens"], result["standardized_total_tokens"]), (49, 9, 58))
        self.assertIsNone(result["provider_reported_total_tokens"])
        self.assertEqual(result["uncached_input_tokens"], 12)
        self.assertIsNone(result["reasoning_tokens"])

    def test_responses_incomplete_final_usage_is_exact_without_claiming_generation_success(self):
        payload = sse(
            {"type": "response.created", "response": {"status": "in_progress", "usage": {"input_tokens": 1, "output_tokens": 1}}},
            {"type": "response.incomplete", "response": {"status": "incomplete", "error": None,
                "incomplete_details": {"reason": "max_output_tokens"},
                "usage": {"input_tokens": 10, "output_tokens": 4, "total_tokens": 14,
                          "input_tokens_details": {"cached_tokens": 6},
                          "output_tokens_details": {"reasoning_tokens": 3}}}})
        evidence = extract(payload, "openai-responses")
        self.assertFalse(evidence["response_complete"])
        self.assertTrue(evidence["officially_ended_incomplete_with_usage"])
        result = view(payload)
        self.assertEqual(result["standardized_total_tokens"], 14)
        self.assertEqual(result["generation_status"], "incomplete_generation")
        self.assertEqual(result["reasoning_tokens"], 3)

    def test_incomplete_terminal_without_final_usage_cannot_reuse_provisional_usage(self):
        payload = sse(
            {"type": "response.created", "response": {"usage": {"input_tokens": 10, "output_tokens": 4, "total_tokens": 14}}},
            {"type": "response.incomplete", "response": {"status": "incomplete",
                "incomplete_details": {"reason": "max_output_tokens"}, "usage": None}})
        evidence = extract(payload, "openai-responses")
        self.assertEqual(evidence["raw_usage"], {})
        self.assertFalse(evidence["officially_ended_incomplete_with_usage"])
        self.assertIsNone(view(payload)["standardized_total_tokens"])

    def test_error_after_incomplete_terminal_cannot_claim_exact_usage(self):
        payload = sse(
            {"type": "response.incomplete", "response": {"status": "incomplete", "error": None,
                "incomplete_details": {"reason": "max_output_tokens"},
                "usage": {"input_tokens": 10, "output_tokens": 4, "total_tokens": 14}}},
            {"type": "error", "error": {"code": "server_error"}})
        self.assertFalse(extract(payload, "openai-responses")["officially_ended_incomplete_with_usage"])
        self.assertIsNone(view(payload)["standardized_total_tokens"])

    def test_truncated_or_malformed_stream_stays_unreliable(self):
        for payload in (
            sse({"type": "message_start", "message": {"usage": {"input_tokens": 5, "output_tokens": 0}}}),
            sse({"type": "message_stop", "usage": {"input_tokens": 5, "output_tokens": 2}}) + b"data: {broken\n\n",
        ):
            result = view(payload, "anthropic-messages")
            self.assertIsNone(result["standardized_total_tokens"])
            self.assertFalse(result["comparable"])

    def test_gzip_matches_uncompressed_usage(self):
        payload = json.dumps({"usage": {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14},
                              "choices": [{"finish_reason": "stop"}]}).encode()
        self.assertEqual(extract(payload, "openai-chat")["usage"],
                         extract(gzip.compress(payload), "openai-chat")["usage"])

    def test_deepseek_chat_cache_miss_is_reliable_without_invented_write_count(self):
        raw = {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14,
               "prompt_cache_hit_tokens": 6, "prompt_cache_miss_tokens": 4}
        result = normalize_details(raw, "openai-chat")
        normalized = normalize_request({**result["usage"], **result, "raw_usage": raw,
            "protocol": "openai-chat", "response_complete": True, "request_status": "succeeded"})
        self.assertEqual(normalized["uncached_input_tokens"], 4)
        self.assertIsNone(normalized["cache_write_tokens"])
        self.assertEqual(normalized["standardized_total_tokens"], 14)

    def test_known_zero_and_missing_optional_field_remain_distinct(self):
        def parse(details):
            return view(json.dumps({"status": "completed", "usage": {"input_tokens": 10,
                "output_tokens": 4, "total_tokens": 14, "output_tokens_details": details}}).encode())
        self.assertEqual(parse({"reasoning_tokens": 0})["reasoning_tokens"], 0)
        self.assertIsNone(parse({})["reasoning_tokens"])

    def test_non_generation_routes_are_excluded(self):
        for route in ("/v1/messages/count_tokens", "/v1/files", "/v1/models", "/user/balance"):
            self.assertIsNone(protocol_for("https://provider.invalid" + route))
        self.assertEqual(protocol_for("https://provider.invalid/v1/responses/compact"), "openai-responses")

    def test_two_physical_attempts_with_one_logical_id_are_both_kept(self):
        with tempfile.TemporaryDirectory() as directory:
            collector = Collector(Path(directory) / "ledger", run_id="run", user_id="user",
                                  task_id="task", harness_id="baseline")
            for _ in range(2):
                ident = collector.begin(protocol="openai-chat", operation_id="logical-1")
                collector.finish_request(ident, json.dumps({"usage": {"prompt_tokens": 2,
                    "completion_tokens": 3, "total_tokens": 5}}).encode(), status=200)
            self.assertEqual(len(collector.records), 2)
            self.assertEqual(sum(row["total_tokens"] for row in collector.records.values()), 10)
            self.assertEqual({r["normalized_usage"]["logical_model_request_id"] for r in collector.records.values()}, {"logical-1"})

    def test_visual_wire_request_ids_are_physical_only(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            path = run / "task_001/simulator_provider_wire.jsonl"
            path.parent.mkdir()
            records = [{"schema_version": "camact.visual_wire.v1", "request_id": f"wire-{i}",
                "capture_stage": "completed", "success": True, "http_status": 200,
                "response_body": chat_body(f"response-{i}")} for i in range(2)]
            path.write_text("".join(json.dumps(row) + "\n" for row in records))
            rows, errors = role_rows([run], [{"identity": role_identity(run)}])
            self.assertFalse(errors)
            self.assertEqual(len(rows), 2)
            self.assertTrue(all(row["logical_model_request_id"] is None for row in rows))
            totals = aggregate(rows)
            self.assertEqual(totals["http_attempt_count"], 2)
            self.assertEqual(totals["opaque_physical_request_count"], 2)
            self.assertIsNone(totals["logical_request_count"])
            self.assertEqual(totals["known_tokens"]["total_tokens"], 10)

    def test_provider_wire_retries_share_one_explicit_logical_call(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            path = run / "task_001/simulator_provider_wire.jsonl"
            path.parent.mkdir()
            records = [{"schema_version": "camact.provider_wire.v1", "request_id": "logical-1",
                "attempt_index": i, "status": "succeeded", "http_status": 200,
                "response_body": chat_body(f"response-{i}")} for i in (1, 2)]
            path.write_text("".join(json.dumps(row) + "\n" for row in records))
            rows, errors = role_rows([run], [{"identity": role_identity(run)}])
            self.assertFalse(errors)
            self.assertEqual(len(rows), 2)
            self.assertEqual({row["logical_model_request_id"] for row in rows}, {"logical-1"})
            totals = aggregate(rows)
            self.assertEqual(totals["http_attempt_count"], 2)
            self.assertEqual(totals["logical_request_count"], 1)
            self.assertEqual(totals["known_tokens"]["total_tokens"], 10)

    def test_judge_call_indices_separate_identical_prompts_and_mirrors_deduplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            calls = []
            for response_ids in (("response-a", "response-b"), ("response-c",)):
                responses = [{"response_body": chat_body(response_id), "request_body": "{}",
                    "http_status": 200, "attempt": i + 1} for i, response_id in enumerate(response_ids)]
                calls.append({"request_sha256": "same-prompt", "criterion_id": "same-criterion",
                    "audit": {"model": "test", "attempt_count": len(responses), "responses": responses}})
            doc = {"evaluations": [{"task_id": "external-task", "grader": str(run / "task_001/grader.py"),
                "judge_summary": {"calls": calls}}]}
            for relative in ("task_001/evaluation/result.json", "task_001/copy/result.json"):
                path = run / relative
                path.parent.mkdir(parents=True)
                path.write_text(json.dumps(doc))
            rows, errors = judge_rows([run], [{"identity": role_identity(run)}])
            self.assertFalse(errors)
            by_response = {row["provider_response_id"]: row for row in rows}
            self.assertEqual(len(rows), 3)
            self.assertEqual(by_response["response-a"]["logical_model_request_id"],
                             by_response["response-b"]["logical_model_request_id"])
            self.assertNotEqual(by_response["response-a"]["logical_model_request_id"],
                                by_response["response-c"]["logical_model_request_id"])
            totals = aggregate(rows)
            self.assertEqual(totals["logical_request_count"], 2)
            self.assertEqual(totals["known_tokens"]["total_tokens"], 15)

    def test_judge_logical_call_ids_include_run_and_task(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            ledgers = []
            for i, (run_name, task) in enumerate((("run-1", "task_001"), ("run-1", "task_002"), ("run-2", "task_001"))):
                run = base / run_name
                ledgers.append({"identity": role_identity(run, task)})
                path = run / task / "result.json"
                path.parent.mkdir(parents=True)
                response = {"response_body": chat_body(f"response-{i}"), "request_body": "{}", "http_status": 200}
                path.write_text(json.dumps({"evaluations": [{"task_id": task, "grader": str(run / task / "grader.py"),
                    "judge_summary": {"calls": [{"request_sha256": "same-prompt",
                        "audit": {"model": "test", "attempt_count": 1, "responses": [response]}}]}}]}))
            rows, errors = judge_rows([base], ledgers)
            self.assertFalse(errors)
            self.assertEqual(len(rows), 3)
            self.assertEqual(len({row["logical_model_request_id"] for row in rows}), 3)

    def test_logical_aggregation_scopes_attempt_and_role_identity(self):
        base = {**role_identity("run"), "role": "Agent", "logical_model_request_id": "logical-1"}
        rows = [{**base, "model_request_id": "physical-1"},
                {**base, "model_request_id": "physical-2", "attempt_id": "attempt-2"},
                {**base, "model_request_id": "physical-3", "role": "Simulator"}]
        self.assertEqual(aggregate(rows)["logical_request_count"], 3)

    def test_http_error_body_with_usage_is_not_lost_and_without_usage_is_not_zero(self):
        for status in (400, 402, 429, 500, 503):
            for raw, expected in (({}, None), ({"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}, 5)):
                with self.subTest(status=status, has_usage=bool(raw)), tempfile.TemporaryDirectory() as directory:
                    collector = Collector(Path(directory) / "ledger", run_id="run", user_id="user",
                                          task_id="task", harness_id="baseline")
                    payload = json.dumps({"error": {"type": "provider_error"}, **({"usage": raw} if raw else {})}).encode()
                    original = urllib.error.HTTPError("https://provider.invalid/v1/chat/completions", status, "provider error", {}, io.BytesIO(payload))
                    def opener(request, **kwargs):
                        raise original
                    request = urllib.request.Request("https://provider.invalid/v1/chat/completions", data=b"{}")
                    with self.assertRaises(urllib.error.HTTPError) as captured:
                        observe_open(collector, opener, request)
                    self.assertIs(captured.exception, original)
                    self.assertEqual(captured.exception.read(), payload)
                    row = next(iter(collector.records.values()))
                    self.assertEqual(row["http_status"], status)
                    self.assertEqual(row["total_tokens"], expected)
                    self.assertEqual(row["request_status"], "error")
                    self.assertFalse(row["normalized_usage"]["comparable"])

    def test_baseline_raw_wire_preserves_original_http_error_body(self):
        module_path = Path(__file__).resolve().parents[1] / "baseline harness/baseline_harness/visual_wire.py"
        spec = importlib.util.spec_from_file_location("baseline_wire_regression", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        payload = b'{"error":{"type":"invalid_request_error","message":"rejected"}}'
        endpoint = "https://provider.invalid/v1/chat/completions"
        error = urllib.error.HTTPError(endpoint, 400, "bad", {}, io.BytesIO(payload))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wire.jsonl"
            with mock.patch("urllib.request.urlopen", side_effect=error):
                with module.capture_json_http(path, endpoint, "", component="agent_model"):
                    with self.assertRaises(urllib.error.HTTPError) as captured:
                        urllib.request.urlopen(urllib.request.Request(endpoint, data=b'{"model":"test"}'))
                    self.assertIs(captured.exception, error)
                    self.assertEqual(captured.exception.read(), payload)
            events = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(events[-1]["response_body"], payload.decode())
            self.assertEqual(events[-1]["http_status"], 400)
            self.assertFalse(events[-1]["success"])
            self.assertIsNone(events[-1]["capture_incomplete_reason"])


if __name__ == "__main__":
    unittest.main()
