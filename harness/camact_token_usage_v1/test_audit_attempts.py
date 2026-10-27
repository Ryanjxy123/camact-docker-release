from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from .audit_attempts import audit


class ManifestAttemptAuditTests(unittest.TestCase):
    def row(self, output, attempt):
        return dict(run_id=str(output), user_id="u", harness_id="codex", task_id="task_001",
                    attempt_id=attempt, role="Agent", model_request_id="reused-physical-id",
                    provider_response_id="reused-provider-id", request_status="succeeded",
                    request_capture_complete=True, input_tokens=10, output_tokens=2, total_tokens=12,
                    usage_status="complete", comparable=True,
                    standardized_tokens=dict(input_tokens=10, output_tokens=2, total_tokens=12))

    def test_all_statuses_and_distinct_attempts_survive_duplicate_manifests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            attempts = []
            for number, status in ((1, "infrastructure_error"), (2, "scored")):
                output = root / f"attempt-{number}/run"
                compact = output / "token_usage/accounting_v3/requests.jsonl"
                compact.parent.mkdir(parents=True)
                compact.write_text(json.dumps(self.row(output, f"collector-{number}")) + "\n")
                attempts.append(dict(attempt=number, output=str(output), status=status))
            document = dict(tasks=[dict(user_id="u", harness="codex", task="task_001", task_id="u_S1_01",
                                       scored=True, final_formal_run_id=attempts[1]["output"], attempts=attempts)])
            manifests = [root / "source.json", root / "projection.json"]
            for path in manifests:
                path.write_text(json.dumps(document))
            summary = audit(manifests, root / "archive", workers=2)
            self.assertEqual(summary["manifest_registration_count"], 4)
            self.assertEqual(summary["attempt_output_task_count"], 2)
            self.assertEqual(summary["physical_request_identity_count"], 2)
            self.assertEqual(summary["by_harness"]["codex"]["known_http_attempts"], 2)
            self.assertTrue(summary["all_manifest_attempts_complete"])

    def test_score_wrapper_uses_historical_agent_mapping_without_double_counting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wrapper, agent = root / "judge-wrapper", root / "original-agent"
            manifest, previous, requests = root / "manifest.json", root / "historical.json", root / "requests.jsonl"
            task = dict(user_id="u", harness="codex", task="task_001", task_id="u_S1_01",
                        scored=True, final_formal_run_id=str(wrapper), attempts=[])
            manifest.write_text(json.dumps(dict(tasks=[task])))
            previous.write_text(json.dumps(dict(tasks=[dict(task, agent_run_id=str(agent),
                                                            final_run_id=str(wrapper), recovery_mode="judge_only")])))
            requests.write_text(json.dumps(self.row(agent, "original-collector")) + "\n")
            summary = audit([manifest], root / "archive", historical_requests=requests,
                            historical_manifest=previous, workers=1)
            self.assertEqual(summary["attempt_output_task_count"], 2)
            self.assertEqual(summary["physical_request_identity_count"], 1)
            self.assertEqual(summary["by_harness"]["codex"]["known_http_attempts"], 1)
            self.assertTrue(summary["all_manifest_attempts_complete"])

    def test_empty_uncaptured_output_remains_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(dict(tasks=[dict(user_id="u", harness="codex", task="task_001",
                task_id="u_S1_01", scored=False, attempts=[dict(attempt=1, status="infrastructure_error",
                                                              output=str(root / "missing-run"))])])))
            summary = audit([manifest], root / "archive", workers=1)
            self.assertEqual(summary["physical_request_identity_count"], 0)
            self.assertIsNone(summary["exact_all_manifest_request_count"])
            self.assertEqual(summary["recovery_status_counts"], {"unrecoverable": 1})


if __name__ == "__main__":
    unittest.main()
