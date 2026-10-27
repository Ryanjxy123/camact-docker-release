"""Offline deployment contracts: independent roles and durable paid-work resume."""
import datetime as dt
from contextlib import nullcontext
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from release import config, runner


class ModelRoles(unittest.TestCase):
    def env(self):
        return {f"{role}_{field}": value for role, values in {
            "AGENT": {"MODEL": "agent-model", "BASE_URL": "https://agent.example.invalid", "API_KEY": "agent-fixture-key"},
            "JUDGE": {"MODEL": "judge-model", "BASE_URL": "https://judge.example.invalid", "API_KEY": "judge-fixture-key"},
            "SIMULATOR": {"MODEL": "sim-model", "BASE_URL": "https://sim.example.invalid", "API_KEY": "sim-fixture-key"},
        }.items() for field, value in values.items()}

    def test_roles_do_not_fallback_or_share_credentials(self):
        with patch.dict(os.environ, self.env(), clear=True):
            actual = config.build(Path("/dataset"))
            config.validate(actual, config.METHODS)
            self.assertEqual(actual["judge"]["model"], "judge-model")
            self.assertEqual(actual["simulator"]["api_key_env"], "SIMULATOR_API_KEY")
            self.assertEqual(actual["harnesses"]["baseline"]["provider"]["model"], "agent-model")
            self.assertEqual(actual["harnesses"]["codex"]["provider"]["protocol"], "openai-responses")
            self.assertEqual(actual["harnesses"]["claude"]["provider"]["protocol"], "anthropic-messages")
            self.assertNotIn("retry_attempts", actual["harnesses"]["codex"]["provider"])
            self.assertNotIn("agent-fixture-key", json.dumps(actual))
            self.assertNotIn("judge-fixture-key", json.dumps(actual))
            os.environ.pop("JUDGE_API_KEY")
            with self.assertRaisesRegex(ValueError, "missing credential"):
                config.validate(actual, ["baseline"])

    def test_overrides_and_incompatible_protocol_fail_before_execution(self):
        with patch.dict(os.environ, self.env() | {"AGENT_MODEL_CODEX": "codex-model", "AGENT_PROTOCOL_CODEX": "openai-chat"}, clear=True):
            actual = config.build(Path("/dataset"))
            self.assertEqual(actual["harnesses"]["codex"]["provider"]["model"], "codex-model")
            self.assertEqual(actual["harnesses"]["baseline"]["provider"]["model"], "agent-model")
            with self.assertRaisesRegex(ValueError, "not supported"):
                config.validate(actual, ["codex"])
        with patch.dict(os.environ, self.env() | {"SIMULATOR_PROTOCOL": "anthropic-messages"}, clear=True):
            with self.assertRaisesRegex(ValueError, "incompatible protocol"):
                config.validate(config.build(Path("/dataset")), ["baseline"])
        with patch.dict(os.environ, self.env() | {"AGENT_RETRY_ATTEMPTS_CODEX": "2"}, clear=True):
            with self.assertRaisesRegex(ValueError, "controlled by the official CLI"):
                config.validate(config.build(Path("/dataset")), ["codex"])

    def test_external_secret_is_not_in_public_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "agent.secret"
            path.write_text("fixture-secret-value\n")
            with patch.dict(os.environ, self.env() | {"AGENT_API_KEY_FILE": str(path)}, clear=True):
                config.load_secrets()
                actual = config.build(Path("/dataset"))
                self.assertEqual(os.environ["AGENT_API_KEY"], "fixture-secret-value")
                self.assertNotIn("fixture-secret-value", json.dumps(actual))
                self.assertEqual(config.redact("failed fixture-secret-value"), "failed [REDACTED]")


class DurableResume(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "audit").mkdir()
        self.engine = runner.scheduler()
        self.attempt = self.root / "users/u/runs/codex/task_001/attempt_001"
        self.attempt.mkdir(parents=True)
        self.output = self.attempt / "run"
        self.slot = {"user_id": "u", "harness": "codex", "task": "task_001", "task_id": "u-task-001",
            "status": "running", "scored": False, "attempts": [{"directory": str(self.attempt),
                "output": str(self.output), "attempt": 1, "reserved_at": "2020-01-01T00:00:00+00:00"}]}
        self.manifest = {"tasks": [self.slot], "max_infrastructure_attempts": 3}
        self.engine.write(self.attempt / "spec.json", {**self.slot, "attempt": 1})

    def tearDown(self):
        self.temp.cleanup()

    def test_confirmed_score_is_recovered_without_reexecuting_agent(self):
        self.engine.write(self.attempt / "terminal.json", {"returncode": 0})
        verdict = {"scored": True, "reward": .75, "strict": False, "infrastructure_error": False,
                   "result": str(self.output / "result.json")}
        with patch.object(self.engine, "inspect_result", return_value=verdict), patch.object(self.engine, "selected_usage", return_value={"captured": True}):
            self.engine.reconcile(self.root, self.manifest)
        self.assertEqual(self.slot["status"], "scored")
        self.assertEqual(self.slot["reward"], .75)
        self.assertEqual(len(self.slot["attempts"]), 1)
        self.assertEqual(self.slot["selected_agent_usage"], {"captured": True})

    def test_uncertain_child_identity_blocks_dispatch(self):
        self.engine.write(self.attempt / "worker.json", {"identity": None})
        with patch.object(self.engine, "paid_descendants", return_value=[]):
            self.engine.reconcile(self.root, self.manifest)
        self.assertEqual(self.manifest["dispatch_fault"]["reason"], "worker_child_identity_uncertain")
        self.assertEqual(len(self.slot["attempts"]), 1)

    def test_interrupted_unscored_attempt_is_not_automatically_repeated(self):
        self.engine.write(self.attempt / "worker.json", {"identity": None})
        self.engine.write(self.attempt / "child.json", {"identity": None})
        verdict = {"scored": False, "reward": None, "infrastructure_error": True, "failure_type": "missing_result"}
        with patch.object(self.engine, "paid_descendants", return_value=[]), patch.object(self.engine, "inspect_result", return_value=verdict):
            self.engine.reconcile(self.root, self.manifest)
        self.assertEqual(self.slot["status"], "infrastructure_error")
        self.assertEqual(len(self.slot["attempts"]), 1)

    def test_run_id_and_native_results_containment(self):
        from camact_multi.config import archive_path
        with patch.dict(os.environ, {"CAMACT_RESULTS_ROOT": str(self.root)}):
            self.assertEqual(archive_path(str(self.root / "named-run/runs/task")), self.root / "named-run/runs/task")
            with self.assertRaises(ValueError):
                archive_path(str(self.root.parent / "outside"))
            with self.assertRaises(ValueError):
                runner.archive_path("../escape", self.root)


class AutomationExitCode(unittest.TestCase):
    def test_run_reports_nonzero_when_scheduler_cannot_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for state, expected in (("complete", 0), ("finished_with_infrastructure_errors", 3), ("blocked", 3)):
                with self.subTest(state=state), patch.object(config, "load_secrets"), \
                        patch.object(runner, "results_root", return_value=root), \
                        patch.object(runner, "data_lease", return_value=nullcontext(root)), \
                        patch.object(runner, "prepare", return_value=root / "fixture-run"), \
                        patch.object(runner, "scheduler") as scheduler, \
                        patch.object(runner, "status", return_value={"status": state}), patch("builtins.print"):
                    self.assertEqual(runner.main(["run", "--run-id", "fixture-run", "--users", "fixture-user"]), expected)
                    scheduler.return_value.run.assert_called_once_with(root / "fixture-run")


class HostHomeIsolation(unittest.TestCase):
    def command(self, backend, root, directory):
        from camact_multi import sandbox
        from claude_code_harness import native_runner
        executable = root / "bin/fixture-cli"
        with patch.object(Path, "resolve", lambda path, **_: path), \
                patch.object(sandbox.shutil, "which", side_effect=lambda value: "/usr/bin/bwrap" if value == "bwrap" else str(executable)), \
                patch("harness.camact_prompt_parity_v1.sandbox.memory_alias_mounts", return_value=[]), \
                patch.object(sandbox, "memory_alias_mounts", return_value=[]):
            if backend == "shared":
                return sandbox.command([str(executable)], directory / "workspace", directory / "guest-home",
                                       {"sandbox_backend": "bwrap", "runtime_roots": [str(root)]}, relay=False)
            return native_runner._sandbox_command([str(executable)], directory / "workspace", directory / "guest-home",
                                                   runtime_roots=[str(root)], sandbox_backend="bwrap")

    def test_both_boundaries_reject_entire_host_homes_and_windows_mounts(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.dict(os.environ, {"HOME": str(directory)}):
                for backend in ("shared", "claude"):
                    for root in (Path("/"), Path("/home"), Path("/root"), Path("/home") / "fixture-user",
                                 directory, Path("/mnt"), Path("/mnt/fixture-package")):
                        with self.subTest(backend=backend, root=str(root)), self.assertRaisesRegex(ValueError, "Unsafe runtime root"):
                            self.command(backend, root, directory)

    def test_explicit_package_below_home_remains_read_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root = Path("/home") / "fixture-user/packages/cli"
            for backend in ("shared", "claude"):
                with self.subTest(backend=backend):
                    command = self.command(backend, root, directory)
                    index = command.index(str(root))
                    self.assertEqual(command[index - 1], "--ro-bind")
                    self.assertIn("--unshare-net", command)


if __name__ == "__main__":
    unittest.main()
