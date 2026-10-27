"""Independent regression guards from the terminal/accounting source review."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest

from . import unified_report as report
from .collector import Collector


class IndependentAccountingGuards(unittest.TestCase):
    def test_reused_provider_id_cannot_collapse_physical_agent_requests_or_attempts(self):
        base = {"run_id": "run", "harness_id": "codex", "user_id": "u",
                "task_id": "task", "attempt_id": "attempt-1", "role": "Agent",
                "provider_response_id": "replayed-provider-id", "model_request_id": "physical-1",
                "request_status": "succeeded", "request_capture_complete": True}
        rows = [base, dict(base), dict(base, model_request_id="physical-retry"),
                dict(base, attempt_id="attempt-2"), dict(base, run_id="other-run")]
        deduplicated = report.deduplicate_roles(rows)
        self.assertEqual(len(deduplicated), 4)
        self.assertEqual(report.aggregate(deduplicated)["request_count"], 4)

    def test_physical_retries_and_interrupted_stream_are_separate_from_logical_calls(self):
        base = {"run_id": "run", "harness_id": "codex", "user_id": "user",
                "task_id": "task", "attempt_id": "attempt", "role": "Agent",
                "logical_model_request_id": "logical-1",
                "operation_attribution": "explicit_logical_call", "request_capture_complete": True}
        rows = [{**base, "model_request_id": "retry-1", "http_status": 429, "request_status": "error"},
                {**base, "model_request_id": "retry-2", "http_status": 200, "request_status": "interrupted"},
                {**base, "model_request_id": "retry-3", "http_status": 200, "request_status": "succeeded"}]
        totals = report.aggregate(rows)
        self.assertEqual(totals["request_count"], 3)
        self.assertEqual(totals["logical_request_count"], 1)
        self.assertEqual(totals["successful_request_count"], 1)
        self.assertEqual(totals["failed_request_count"], 2)
        rows[0]["request_capture_complete"] = False
        incomplete = report.aggregate(rows)
        self.assertEqual(incomplete["http_attempt_count"], 3)
        for field in ("request_count", "logical_request_count", "successful_request_count", "failed_request_count"):
            self.assertIsNone(incomplete[field])

    def test_identical_judge_error_bodies_preserve_two_actual_attempts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / "run"
            task = run / "task_001"
            task.mkdir(parents=True)
            identity = {"run_id": str(run), "harness_id": "claude", "user_id": "A",
                        "task_id": "task_001", "attempt_id": "attempt-A"}
            body = json.dumps({"error": {"type": "payment"}})
            call = {"request_sha256": "same-request", "audit": {"model": "model", "attempt_count": 2,
                "responses": [{"attempt": i, "http_status": 402, "response_body": body} for i in (1, 2)]}}
            result = {"evaluations": [{"task_id": "A_S1_01", "grader": "tasks/A/task_001/grader.py",
                                       "judge_summary": {"calls": [call]}}]}
            (task / "result.json").write_text(json.dumps(result))
            rows, errors = report.judge_rows([root], [{"identity": identity}])
            self.assertEqual(errors, [])
            self.assertEqual(len(rows), 2)
            self.assertEqual(len(report.deduplicate_roles(rows)), 2)

    def test_filtered_user_cannot_inherit_an_unrelated_role_wire(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = {"run_id": str(root / "run-A"), "harness_id": "claude", "user_id": "A",
                        "task_id": "task_001", "attempt_id": "attempt-A"}
            other = root / "user-B/claude/task_001"
            other.mkdir(parents=True)
            (other / "simulator_provider_wire.jsonl").write_text(json.dumps({
                "request_id": "physical-user-B", "attempt_index": 1, "status": "succeeded",
                "http_status": 200, "model": "model", "response_body": json.dumps({
                    "choices": [{"finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})}) + "\n")
            rows, errors = report.role_rows([root], [{"identity": identity}], filters={"user_id": ["A"]})
            self.assertEqual(rows, [])
            self.assertEqual(errors[0]["code"], "unattributed_role_wire")

    def test_partial_usage_is_never_published_as_exact_primary_totals(self):
        aggregate = report.aggregate([{"model_request_id": "partial", "usage_status": "partial",
            "comparable": False, "input_tokens": 10, "output_tokens": 4, "total_tokens": 14,
            "standardized_total_tokens": None, "request_capture_complete": False}])
        self.assertEqual(aggregate["reliable_usage_requests"], 0)
        for field in ("input_tokens", "output_tokens", "total_tokens", "standardized_total_tokens"):
            self.assertIsNone(aggregate["exact_tokens"][field])

    def test_compact_export_roundtrip_preserves_roles_with_raw_and_after_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / 'run'
            collector = Collector(run / 'token_usage/fixture-ledger', run_id=str(run),
                user_id='user-A', task_id='task_001', harness_id='claude',
                attempt_id='fixture-attempt', model_id='model-fixture')
            ident = collector.begin(protocol='openai-chat')
            collector.finish_request(ident, json.dumps({'id': 'agent-response',
                'choices': [{'finish_reason': 'stop'}], 'usage': {
                    'prompt_tokens': 3, 'completion_tokens': 2, 'total_tokens': 5}}).encode(), status=200)
            collector.reconcile(1, source='fixture-boundary')
            collector.finish_task('finished')
            wire_path = run / 'task_001/simulator_provider_wire.jsonl'
            wire_path.parent.mkdir(parents=True)
            success_body = json.dumps({'id': 'simulator-response', 'choices': [{'finish_reason': 'stop'}],
                'usage': {'prompt_tokens': 7, 'completion_tokens': 4, 'total_tokens': 11}})
            wire = {'request_id': 'simulator-logical', 'attempt_index': 1, 'status': 'succeeded',
                'http_status': 200, 'requested_model': 'model-fixture', 'response_body': success_body}
            wire_path.write_text(json.dumps(wire) + '\n')
            before, rows = report.build([root], filters={'model_id': ['model-fixture']})
            report.write(before, rows, run / 'accounting_v3')
            after, _ = report.build([root], filters={'model_id': ['model-fixture']})
            self.assertEqual(before['views'], after['views'])
            self.assertEqual(before['role_views'], after['role_views'])
            self.assertEqual(before['all_roles_all_attempts'], after['all_roles_all_attempts'])
            wire_path.unlink()
            retained, _ = report.build([root], filters={'model_id': ['model-fixture']})
            self.assertEqual(before['role_views'], retained['role_views'])
            self.assertEqual(before['all_roles_all_attempts'], retained['all_roles_all_attempts'])


if __name__ == "__main__":
    unittest.main(verbosity=2)
