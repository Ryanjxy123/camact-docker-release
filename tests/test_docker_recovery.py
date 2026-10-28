"""Recovery acceptance contracts; synthetic cache and simulated Docker only."""
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("docker_recovery_validation", ROOT / "scripts/verify-docker-recovery.py")
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


def identity(number=12):
    return {"pid": number, "start_ticks": 1234 + number, "boot_id": "synthetic-boot-id"}


def observation(*, complete=False):
    tasks = {}
    for index, name in enumerate(recovery.TASKS):
        scored = index == 0 or (index == 2 and complete)
        running = index == 1 and not complete
        tasks[name] = {"status": "scored" if scored else "running" if running else "infrastructure_error" if index == 1 else "pending",
            "attempts": 1 if index < 2 or complete else 0, "scored": scored, "strict": True if scored else None,
            "reward": 1.0 if scored else None, "result_sha256": "a" * 64 if scored else None,
            "artifact_tree_sha256": "b" * 64 if scored else None, "requests": 5 if scored else 1 if index == 1 else 0,
            "script_stage": 4 if scored else 0, "prompt_rules": True, "tool_assertions": scored,
            "usage_requests": 5 if scored else None, "usage_complete": True if scored else None,
            "worker_identity": identity(12 + index), "child_identity": identity(22 + index),
            "worker_live": running, "child_live": running, "worker_locked": running,
            "terminal_present": scored, "runtime": {"plans": 2 if scored or running else 0,
                "recorded_lifecycles": 1 if scored else 0, "missing_lifecycles": 1 if scored else 2 if running else 0,
                "recorded_executions_clean": scored, "guest_credentials_absent": scored, "visual_verified": scored,
                "execution_plan_pairs_verified": scored}}
    return {"frozen": {"model_config_id": "c" * 64, "source_version_sha256": "d" * 64,
        "config_sha256": "e" * 64, "benchmark_sha256": "f" * 64, "image": {"digest": "sha256:" + "1" * 64},
        "harness_versions": {"codex": "0.147.0"}}, "tasks": tasks,
        "scheduler_status": "finished_with_infrastructure_errors" if complete else "running",
        "scheduler_locked": not complete, "unexpected_requests": 0, "state_directories": ["9" * 64]}


class SyntheticSnapshot(unittest.TestCase):
    def test_existing_fixture_generates_three_distinct_tasks_and_original_offline_marker(self):
        import yaml
        with tempfile.TemporaryDirectory() as directory, patch.object(recovery.benchmark, "_metadata", side_effect=AssertionError("no network")), \
                patch.object(recovery.benchmark, "_download", side_effect=AssertionError("no download")):
            snapshot = recovery.create_snapshot(Path(directory))
            self.assertEqual(sorted(path.name for path in (snapshot / "tasks/fixture_user").iterdir()), list(recovery.TASKS))
            identities = []
            for name in recovery.TASKS:
                task = snapshot / "tasks/fixture_user" / name
                document = yaml.safe_load((task / "task.yaml").read_text())
                identities.append(document["task_id"])
                self.assertEqual(document["task_type"], "single_turn")
                self.assertFalse(document["user_agent"]["enabled"])
                self.assertIn(document["task_id"], (task / "grader.py").read_text())
                memory = json.loads((task / "workspace/memory_snapshot/memory_manifest.json").read_text())
                self.assertEqual(Path(memory["runtime_root"]), snapshot / "users/fixture_user/base_memory")
            self.assertEqual(len(set(identities)), 3)
            marker = json.loads((snapshot.parent / "complete.json").read_text())
            self.assertEqual(marker["repo_id"], recovery.FIXTURE_REPO)
            self.assertEqual(marker["revision"], recovery.FIXTURE_REVISION)
            with recovery.benchmark.lease(directory, recovery.FIXTURE_REPO, recovery.FIXTURE_REVISION, offline=True) as leased:
                self.assertEqual(leased, snapshot)
            with self.assertRaises(recovery.hf.ValidationError):
                recovery.create_snapshot(Path(directory))

    def test_tree_hash_records_symlink_without_reading_its_external_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = root / "task"
            task.mkdir()
            outside = root / "outside"
            outside.write_text("synthetic first value")
            (task / "link").symlink_to(outside)
            first = recovery.tree_digest(task)
            outside.write_text("synthetic changed value")
            self.assertEqual(first, recovery.tree_digest(task))

    def test_runtime_requires_every_executed_plan_pair_but_accepts_exact_launch_preview(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            output = parent / "run"
            execution = output / "runs/execution"
            preview = execution / "sandbox-launches/preview/plan.json"
            actual = execution / "sandbox-launches/executed/plan.json"
            original = "/opt/camact/.tools/codex/node_modules/.bin/codex"
            resolved = "/opt/camact/.tools/codex/node_modules/@openai/codex/bin/codex.js"
            mapping = [{"host": "/opt/camact/.tools/codex", "guest": "/opt/camact/runtime/0"},
                       {"host": "/opt/camact/.tools/node", "guest": "/opt/camact/runtime/1"}]
            guest = ["/usr/bin/python3", "/tmp/.camact/multi_launcher.py",
                     "/opt/camact/runtime/0/node_modules/@openai/codex/bin/codex.js", "exec", "fixture"]
            for path in (preview, actual):
                recovery.engine().write(path, {"argv": guest, "runtime_mapping": mapping})
            recovery.engine().write(execution / "launch.json", {"executable": original, "argv": ["/usr/local/bin/python", "-B",
                "/opt/camact/harness/camact_multi_harness_v1/camact_multi/gvisor.py", str(preview)]})
            recovery.engine().write(execution / "native_turns/turn_001/turn.json", {"argv": [original, "exec", "fixture"]})
            lifecycle = actual.with_name("lifecycle.json")
            recovery.engine().write(lifecycle, {"backend": "gvisor", "platform": "systrap", "network": "none",
                "host_proc_bound": False, "cleanup_returncode": 0, "state_removed": True, "returncode": 0,
                "parent_disconnected": False, "guest_environment_keys": ["HOME", "PATH"]})
            (output / "runs/standard_run_artifacts.jsonl").write_text(json.dumps({"visual_evidence": {"status": "visual_verified"}}) + "\n")
            real_resolve = Path.resolve
            def resolve(path, *args, **kwargs):
                return Path(resolved) if str(path) == original else real_resolve(path, *args, **kwargs)
            with patch.object(Path, "resolve", resolve):
                value = recovery.runtime_evidence(output)
                self.assertTrue(value["execution_plan_pairs_verified"])
                self.assertTrue(value["recorded_executions_clean"])
                self.assertEqual(value["missing_lifecycles"], 1)
                lifecycle.unlink()
                self.assertFalse(recovery.runtime_evidence(output)["execution_plan_pairs_verified"])


class ResumeSemantics(unittest.TestCase):
    def test_original_infrastructure_failure_outcome_is_expected_and_idempotent(self):
        before = observation()
        after = observation(complete=True)
        self.assertTrue(recovery.ready_for_interrupt(before))
        recovery.validate_final(before, after, repeat=deepcopy(after))
        self.assertEqual(after["scheduler_status"], "finished_with_infrastructure_errors")
        self.assertEqual(after["tasks"][recovery.TASKS[1]]["status"], "infrastructure_error")

    def test_barrier_requires_real_worker_child_lock_requests_and_pending_c(self):
        mutations = [lambda value: value["tasks"][recovery.TASKS[1]].update(worker_locked=False),
            lambda value: value["tasks"][recovery.TASKS[1]].update(child_live=False),
            lambda value: value["tasks"][recovery.TASKS[1]].update(requests=0),
            lambda value: value["tasks"][recovery.TASKS[2]].update(attempts=1),
            lambda value: value["tasks"][recovery.TASKS[0]].update(scored=False),
            lambda value: value.update(unexpected_requests=1)]
        for mutate in mutations:
            value = observation()
            mutate(value)
            self.assertFalse(recovery.ready_for_interrupt(value))

    def test_replayed_or_changed_completed_attempt_and_false_complete_are_rejected(self):
        before = observation()
        mutations = [lambda value: value.update(scheduler_status="complete"),
            lambda value: value["tasks"][recovery.TASKS[0]].update(requests=6),
            lambda value: value["tasks"][recovery.TASKS[0]].update(result_sha256="8" * 64),
            lambda value: value["tasks"][recovery.TASKS[1]].update(attempts=2),
            lambda value: value["tasks"][recovery.TASKS[1]].update(requests=2),
            lambda value: value["tasks"][recovery.TASKS[2]].update(scored=False),
            lambda value: value["tasks"][recovery.TASKS[2]]["runtime"].update(execution_plan_pairs_verified=False),
            lambda value: value["frozen"].update(config_sha256="7" * 64)]
        for mutate in mutations:
            value = observation(complete=True)
            mutate(value)
            with self.assertRaises(recovery.hf.ValidationError):
                recovery.validate_final(before, value)

    def test_second_resume_cannot_change_artifacts_counts_or_attempts(self):
        before, after = observation(), observation(complete=True)
        repeated = deepcopy(after)
        repeated["tasks"][recovery.TASKS[2]]["artifact_tree_sha256"] = "6" * 64
        with self.assertRaisesRegex(recovery.hf.ValidationError, "second_resume"):
            recovery.validate_final(before, after, repeat=repeated)

    def test_missing_killed_lifecycle_and_residual_state_remain_visible(self):
        before, after = observation(), observation(complete=True)
        after["tasks"][recovery.TASKS[1]]["runtime"] = {"plans": 2, "recorded_lifecycles": 0,
            "missing_lifecycles": 2, "recorded_executions_clean": False, "guest_credentials_absent": False, "visual_verified": False,
            "execution_plan_pairs_verified": False}
        recovery.validate_final(before, after)
        self.assertEqual(after["tasks"][recovery.TASKS[1]]["runtime"]["missing_lifecycles"], 2)
        self.assertEqual(after["state_directories"], ["9" * 64])


class LocalProtocol(unittest.TestCase):
    def fixture(self, task):
        value = recovery.ProtocolFixture.__new__(recovery.ProtocolFixture)
        value.case = "stop"
        value.path = Path("/fixture/ledger.json")
        value.lock = threading.RLock()
        value.actions = recovery.fixture_actions()
        value.smoke = recovery.load_script("recovery_protocol_test", "scripts/native-loop-smoke.py")
        value.ledger = {"counts": dict.fromkeys(recovery.TASKS, 0), "stages": dict.fromkeys(recovery.TASKS, 0), "unexpected": 0,
            "prompt_rules": dict.fromkeys(recovery.TASKS, True), "tool_assertions": dict.fromkeys(recovery.TASKS, False),
            "resource_ok": dict.fromkeys(recovery.TASKS, False), "negative_ok": dict.fromkeys(recovery.TASKS, False)}
        fake = SimpleNamespace(read=Mock(return_value={"tasks": [{"task": task, "status": "running"}]}), write=Mock())
        return value, fake

    def test_existing_responses_helper_executes_native_tools_without_persisting_request_body(self):
        value, fake = self.fixture(recovery.TASKS[0])
        request = {"instructions": "<camact_public_task_rules>", "tools": [{"name": "exec_command"}]}
        with patch.object(recovery, "engine", return_value=fake):
            payload = value.respond(request)
        self.assertIn(b"response.function_call_arguments.delta", payload)
        self.assertEqual(value.ledger["counts"][recovery.TASKS[0]], 1)
        self.assertEqual(value.ledger["stages"][recovery.TASKS[0]], 1)
        self.assertNotIn("instructions", json.dumps(value.ledger))
        self.assertNotIn("request", value.ledger)

    def test_b_first_request_blocks_without_a_response_or_action(self):
        value, fake = self.fixture(recovery.TASKS[1])
        with patch.object(recovery, "engine", return_value=fake):
            self.assertIsNone(value.respond({"instructions": "<camact_public_task_rules>"}))
        self.assertEqual(value.ledger["counts"][recovery.TASKS[1]], 1)
        self.assertEqual(value.ledger["stages"][recovery.TASKS[1]], 0)


class DockerControl(unittest.TestCase):
    def controller(self, directory):
        return recovery.RecoveryController(SimpleNamespace(output=directory, repository="Fixture/release", image_run_id="123",
            expected_source_revision="a" * 40, version="0.1.0-rc.1"))

    def test_live_tmpfs_release_requires_both_inside_and_started_host_policy(self):
        for failure in (None, "inside", "started"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                controller = self.controller(directory)
                checks = dict.fromkeys(recovery.hf.INNER_CHECKS, True)
                if failure == "inside":
                    checks["seccomp"] = False
                ready = {"schema": recovery.SCHEMA, "result": "PASS", "security": checks}
                events = []
                def inspect(*_args, **_kwargs):
                    events.append("host")
                    if failure == "started":
                        raise recovery.hf.ValidationError("started_policy_failed")
                def command(argv, **_kwargs):
                    events.append("release" if argv[:2] == ["docker", "exec"] else "start")
                    return SimpleNamespace(returncode=0, stdout="")
                with patch.object(controller, "create"), patch.object(controller, "read_ready", return_value=ready), \
                        patch.object(controller, "inspect", side_effect=inspect), patch.object(controller, "call", side_effect=command) as call:
                    if failure:
                        with self.assertRaises(recovery.hf.ValidationError):
                            controller.start("stop", "observe")
                        self.assertNotIn("release", events)
                    else:
                        controller.start("stop", "observe")
                        self.assertEqual(events, ["start", "host", "release"])
                        self.assertEqual(call.call_args.args[0][-1], recovery.RELEASE)
                        self.assertEqual(call.call_args.kwargs["timeout"], 5)
                self.assertFalse(any(item.args[0][:2] == ["docker", "cp"] for item in call.call_args_list))

    def test_recovery_create_is_scan_gated_and_uses_network_none_without_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            controller = self.controller(directory)
            with patch.object(controller, "call") as call, self.assertRaises(recovery.hf.ValidationError):
                controller.create("fixture", stage="stop:run")
            call.assert_not_called()
            controller.scanned = True
            controller.manifest = {"image_id": "sha256:" + "b" * 64}
            controller.tmpfs = {"/tmp": "rw,nosuid,nodev,size=512m,uid=10001,gid=10001,mode=1777"}
            with patch.object(controller, "call") as call, patch.object(controller, "inspect"):
                controller.create("fixture", stage="stop:run")
            command = call.call_args.args[0]
            for required in ("--network=none", "--cap-drop=ALL", "--read-only", "--pids-limit=4096", "camact.validation-kind=recovery"):
                self.assertIn(required, command)
            self.assertFalse(any("API_KEY" in value or "HF_TOKEN" in value for value in command))
            self.assertEqual(sum(value == "--mount" for value in command), 1)

    def test_stop_and_kill_use_real_docker_commands_and_retain_pid_evidence(self):
        for case in recovery.CASES:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                controller = self.controller(directory)
                controller.private.mkdir()
                calls = []
                def call(argv, **_kwargs):
                    calls.append(argv)
                    stdout = ""
                    if argv[:2] == ["docker", "cp"]:
                        Path(argv[-1]).write_text(json.dumps(observation()))
                    elif argv[:2] == ["docker", "top"]:
                        stdout = "PID\n123\n124\n125\n"
                    elif argv[:2] == ["docker", "wait"]:
                        stdout = "137" if case == "kill" else "3"
                    return SimpleNamespace(returncode=0, stdout=stdout)
                fake = SimpleNamespace(proc_identity=lambda number: identity(number), live=lambda _value: False)
                with patch.object(controller, "start", return_value="fixture-container"), patch.object(controller, "call", side_effect=call), \
                        patch.object(recovery, "engine", return_value=fake):
                    before, evidence = controller.interrupt(case)
                self.assertTrue(recovery.ready_for_interrupt(before))
                self.assertEqual(len(evidence["host_processes"]), 3)
                expected = ["docker", "stop", "--time", "60", "fixture-container"] if case == "stop" else ["docker", "kill", "--signal", "KILL", "fixture-container"]
                self.assertIn(expected, calls)


if __name__ == "__main__":
    unittest.main()
