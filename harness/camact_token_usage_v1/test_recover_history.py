from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from .recover_history import recover


class HistoryRecoveryTests(unittest.TestCase):
    def test_projection_is_idempotent_and_keeps_unknown_native_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / "run"
            manifest = root / "run_manifest.json"
            dsh = root / "dsh.jsonl"
            usage = {
                "http_attempt_count": 2, "logical_request_count": 0,
                "exact_run_tokens": {"input_tokens": 10, "output_tokens": 4,
                                     "total_tokens": 14, "cache_read_tokens": 3,
                                     "cache_write_tokens": 0},
                "capture_complete": True, "physical_request_ids": ["a", "b"],
            }
            tasks = [
                {"user_id": "u", "task": "task_001", "task_id": "x", "harness": "codex",
                 "status": "scored", "scored": True, "reward": 1.0, "strict": True,
                 "final_formal_run_id": str(run), "selected_agent_usage": usage},
                {"user_id": "u", "task": "task_001", "task_id": "x", "harness": "deepseek",
                 "status": "scored", "scored": True, "reward": 1.0, "strict": True,
                 "final_formal_run_id": str(run), "selected_agent_usage": usage},
            ]
            manifest.write_text(json.dumps({"benchmark_run_id": "r", "updated_at": "t", "tasks": tasks}))
            dsh.write_text(json.dumps({"root": str(run), "task": "task_001",
                "logical_request_count": 2, "errors": [], "native_group_count": 2,
                "joined_physical_attempts": 2, "groups": [{"session_id": "s"}]}) + "\n")
            archive = root / "archive"
            recover(manifest, archive, dsh_source=dsh)
            result = json.loads((archive / "manifest/summary.json").read_text())
            rows = [json.loads(line) for line in (archive / "evaluation/task_results.jsonl").read_text().splitlines()]
            native = next(row for row in rows if row["harness"] == "deepseek")
            codex = next(row for row in rows if row["harness"] == "codex")
            self.assertEqual(native["logical_request_count"], 2)
            self.assertIsNone(codex["logical_request_count"])
            self.assertEqual(result["slot_count"], 2)
            target = archive / "evaluation/task_results.jsonl"
            before = hashlib.sha256(target.read_bytes()).hexdigest()
            recover(manifest, archive, dsh_source=dsh)
            self.assertEqual(before, hashlib.sha256(target.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()

