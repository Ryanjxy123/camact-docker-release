from __future__ import annotations

import json
import io
from pathlib import Path
import tempfile
import unittest
from urllib.request import Request

from .native_identity import extract_identity
from .collector import Collector
from .http import observe_open
from . import unified_report


class NativeIdentityTests(unittest.TestCase):
    def test_forwarded_headers_survive_http_ledger_and_compact_export(self):
        payload = json.dumps({"id": "response-1", "choices": [{"finish_reason": "stop"}],
                              "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}}).encode()
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run"
            collector = Collector(run / "token_usage/attempt", run_id=str(run),
                                  user_id="user", task_id="task", harness_id="codex", attempt_id="attempt")
            body = json.dumps({"model": "fixture", "client_metadata": {"session_id": "session-1"}}).encode()
            request = Request("https://provider.invalid/v1/chat/completions", data=body)
            response = io.BytesIO(payload)
            response.status, response.headers = 200, {}
            with observe_open(collector, lambda *args, **kwargs: response, request,
                              request_headers={"X-CamAct-Logical-Request-Id": "logical-1",
                                               "X-Request-Id": "physical-1", "Authorization": "fixture-excluded"}) as observed:
                self.assertEqual(observed.read(), payload)
            collector.reconcile(1, source="fixture-boundary")
            collector.finish_task("finished")
            result, rows = unified_report.build([run])
            output = Path(directory) / "compact"
            unified_report.write(result, rows, output)
            saved = json.loads((output / "requests.jsonl").read_text())
            self.assertEqual(saved["logical_model_request_id"], "logical-1")
            self.assertEqual(saved["logical_identity_source"], "header:x-camact-logical-request-id")
            self.assertEqual(saved["native_request_id"], "physical-1")
            self.assertEqual(saved["native_session_id"], "session-1")
            self.assertNotIn("fixture-excluded", (output / "requests.jsonl").read_text())
            self.assertEqual(result["views"]["all_attempts"]["codex"]["request_count"], 1)

    def test_private_logical_header_is_explicit(self):
        result = extract_identity({}, {"X-CamAct-Logical-Request-Id": "call-7"})
        self.assertEqual(result["operation_id"], "call-7")
        self.assertEqual(result["logical_identity_source"], "header:x-camact-logical-request-id")

    def test_provider_request_id_is_physical_evidence_only(self):
        result = extract_identity({}, {"x-request-id": "provider-7"})
        self.assertNotIn("operation_id", result)
        self.assertEqual(result["native_request_id"], "provider-7")

    def test_codex_turn_is_not_a_logical_request(self):
        result = extract_identity({"client_metadata": {
            "session_id": "session-1", "thread_id": "thread-1", "turn_id": "turn-1"}})
        self.assertNotIn("operation_id", result)
        self.assertEqual(result["native_session_id"], "session-1")
        self.assertEqual(result["native_turn_id"], "turn-1")

    def test_dsh_watermark_is_not_a_guess(self):
        result = extract_identity({"dsh_session_log": {
            "session": {"id": "session-1"}, "throughSeq": 9}})
        self.assertNotIn("operation_id", result)
        self.assertEqual(result["native_session_id"], "session-1")
        self.assertEqual(result["native_through_seq"], 9)

    def test_dsh_step_boundary_and_retry_are_explicit(self):
        result = extract_identity({
            "dsh_session_log": {"session": {"id": "session-1"}, "throughSeq": 12},
            "dsh_native_call": {"session_id": "session-1", "turn": 2,
                                 "step": 4, "retryId": "retry-2"},
        })
        self.assertEqual(result["operation_id"], "dsh:step:session-1:2:4")
        self.assertEqual(result["logical_identity_source"], "dsh_session_turn_step")
        self.assertEqual(result["request_retry_identity"], "retry-2")

    def test_title_event_boundary_is_explicit(self):
        result = extract_identity({
            "dsh_native_call": {"sessionId": "session-1", "eventSeq": 18,
                                 "kind": "title"},
        })
        self.assertEqual(result["operation_id"], "dsh:title:session-1:18")


if __name__ == "__main__":
    unittest.main()

