from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from .attempt_recovery import bind_unscored_agent_usage
from deployment import full_benchmark as full


class UnscoredAttemptBindingTests(unittest.TestCase):
    def fixture(self, directory):
        output = Path(directory).resolve() / "attempt/run"
        slot = dict(user_id="u", harness="claude", task="task_001", task_id="u_S1_01")
        identity = dict(run_id=str(output), harness_id="claude", user_id="u",
                        task_id="task_001", attempt_id="agent-attempt")
        ledger = output / "token_usage/ledgers/agent-attempt"
        ledger.mkdir(parents=True)
        request = dict(identity, role="Agent", model_request_id="request-1",
                       request_capture_complete=True, request_status="succeeded",
                       request_sha256="request-digest", response_sha256="response-digest",
                       input_tokens=10, output_tokens=2, total_tokens=12,
                       standardized_tokens=dict(input_tokens=10, output_tokens=2, total_tokens=12),
                       usage_status="complete", comparable=True)
        summary = dict(identity, closed=True, collector_errors=[],
                       coverage="exclusive_agent_http_boundary", model_request_count=1,
                       request_count_reconciliation=[dict(matched=True,
                           expected_model_requests=1, recorded_model_requests=1)])
        files = {
            output.parent / "spec.json": dict(slot, mode="agent"),
            ledger / "identity.json": dict(identity, coverage="exclusive_agent_http_boundary"),
            ledger / "task_summary.json": summary,
        }
        for path, document in files.items():
            path.write_text(json.dumps(document))
        compact = output / "token_usage/accounting_v3/requests.jsonl"
        compact.parent.mkdir()
        compact.write_text(json.dumps(request) + "\n")
        (ledger / "request_events.jsonl").write_text(json.dumps(dict(request, request_status="in_flight"))
                                                      + "\n" + json.dumps(request) + "\n")
        return output, slot, ledger, compact, files, request

    def test_closed_unscored_capture_has_same_attempt_tokens_and_no_logical_guess(self):
        with tempfile.TemporaryDirectory() as directory:
            output, slot, ledger, compact, files, request = self.fixture(directory)
            before = compact.read_bytes()
            usage = bind_unscored_agent_usage(output, slot)
            self.assertEqual(usage["request_count"], 1)
            self.assertEqual(usage["exact_run_tokens"]["total_tokens"], 12)
            self.assertIsNone(usage["logical_request_count"])
            self.assertEqual(usage["usage_binding"]["identity"]["attempt_id"], "agent-attempt")
            self.assertEqual(usage["usage_binding"]["external_task_id"], "u_S1_01")
            self.assertEqual(compact.read_bytes(), before)

    def test_spec_cannot_bind_another_task_or_external_id(self):
        with tempfile.TemporaryDirectory() as directory:
            output, slot, ledger, compact, files, request = self.fixture(directory)
            spec = output.parent / "spec.json"
            for field in ("user_id", "harness", "task", "task_id", "mode"):
                with self.subTest(field=field):
                    spec.write_text(json.dumps(dict(files[spec], **{field: "foreign"})))
                    self.assertIsNone(bind_unscored_agent_usage(output, slot))

    def test_partial_or_unreconciled_capture_stays_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            output, slot, ledger, compact, files, request = self.fixture(directory)
            path = ledger / "task_summary.json"
            for change in ("open", "errors", "unmatched", "count", "coverage"):
                with self.subTest(change=change):
                    doc = copy.deepcopy(files[path])
                    if change == "open": doc["closed"] = False
                    if change == "errors": doc["collector_errors"] = ["lost_event"]
                    if change == "unmatched": doc["request_count_reconciliation"][0]["matched"] = False
                    if change == "count": doc["request_count_reconciliation"][0]["recorded_model_requests"] = 2
                    if change == "coverage": doc["coverage"] = "partial"
                    path.write_text(json.dumps(doc))
                    self.assertIsNone(bind_unscored_agent_usage(output, slot))

    def test_concurrent_identity_duplicates_and_truncated_logs_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            output, slot, ledger, compact, files, request = self.fixture(directory)
            original = compact.read_text()
            for change in ("duplicate", "foreign_attempt", "foreign_task", "partial", "in_flight", "digest", "malformed"):
                with self.subTest(change=change):
                    row = copy.deepcopy(request)
                    if change == "foreign_attempt": row["attempt_id"] = "other"
                    if change == "foreign_task": row["task_id"] = "task_002"
                    if change == "partial": row["request_capture_complete"] = False
                    if change == "in_flight": row["request_status"] = "in_flight"
                    if change == "digest": row["response_sha256"] = "different"
                    compact.write_text(original + ("{" if change == "malformed" else json.dumps(row) + "\n"))
                    self.assertIsNone(bind_unscored_agent_usage(output, slot))
            compact.write_text(original)
            journal = ledger / "request_events.jsonl"
            journal.write_text(journal.read_text() + "{partial")
            self.assertIsNone(bind_unscored_agent_usage(output, slot))

    def test_result_wrapper_can_bind_the_explicit_original_agent_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            output = root / "wrapper/run"
            agent_output = root / "agent/run"
            slot = dict(user_id="u", harness="claude", task="task_001", task_id="u_S1_01")
            identity = dict(run_id=str(agent_output), harness_id="claude", user_id="u",
                            task_id="task_001", attempt_id="agent-attempt")
            request = dict(identity, role="Agent", model_request_id="request-1",
                           request_capture_complete=True, request_status="succeeded",
                           request_sha256="request-digest", response_sha256="response-digest",
                           input_tokens=10, output_tokens=2, total_tokens=12,
                           standardized_tokens=dict(input_tokens=10, output_tokens=2, total_tokens=12),
                           usage_status="complete", comparable=True)
            usage = dict(http_attempt_count=1, capture_complete=True,
                         physical_request_ids=["request-1"],
                         exact_tokens=dict(input_tokens=10, output_tokens=2, total_tokens=12))
            summary = dict(tasks=[dict(harness_id="claude", user_id="u", task_id="task_001",
                                       external_task_id="u_S1_01", agent_run_id=str(agent_output),
                                       agent_attempt_id="agent-attempt", result_path=str(output / "result.json"),
                                       agent_tokens=usage)])
            target = output / "token_usage/accounting_v3"
            target.mkdir(parents=True)
            (target / "summary.json").write_text(json.dumps(summary))
            (target / "requests.jsonl").write_text(json.dumps(request) + "\n")
            bound = full.bound_task_usage(output, slot)
            self.assertEqual(bound["http_attempt_count"], 1)
            self.assertEqual(bound["usage_binding"]["agent_run_path"], str(agent_output))
            self.assertEqual(bound["usage_binding"]["identity"]["attempt_id"], "agent-attempt")


if __name__ == "__main__":
    unittest.main()
