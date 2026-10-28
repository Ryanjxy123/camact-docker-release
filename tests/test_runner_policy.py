"""Fail-closed actual runner policy and command-release contracts, without Docker."""
import copy
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("runner_policy", ROOT / "scripts/verify-runner-policy.py")
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)
IMAGE = "sha256:" + "1" * 64
REQUIRED = {"identity", "capabilities", "no_new_privileges", "seccomp", "apparmor", "root_readonly", "pids_limit", "data_bind", "tmpfs_flags"}
CANARY = "synthetic-runner-private-credential-value"


def configuration(directory):
    return {"services": {"runner": {"image": IMAGE,
        "volumes": [{"type": "bind", "source": str(directory / "data"), "target": "/var/lib/camact"}],
        "secrets": [role + "_api_key" for role in ("agent", "judge", "simulator")]},
        "storage-init": {"image": IMAGE, "profiles": ["tools"]}},
        "secrets": {role + "_api_key": {"file": str(directory / (role + "_api_key"))} for role in ("agent", "judge", "simulator")}}


def inspected(config, started=False):
    mounts = policy.expected_mounts(config)
    return {"Image": IMAGE, "Config": {"User": "10001:10001"}, "AppArmorProfile": policy.PROFILE,
        "State": {"Running": started}, "HostConfig": {"CapDrop": ["ALL"], "CapAdd": [], "ReadonlyRootfs": True,
        "Privileged": False, "PidsLimit": 4096, "NetworkMode": "none",
        "SecurityOpt": ["no-new-privileges:true", "apparmor=" + policy.PROFILE,
                        "seccomp=" + (ROOT / "deploy/seccomp-gvisor.json").read_text()],
        "Tmpfs": {target: f"rw,nosuid,nodev,size={size},uid=10001,gid=10001,mode={mode}" for target, (size, mode) in policy.TMPFS.items()},
        "Mounts": [{"Type": "bind", "Source": source, "Target": target, "ReadOnly": not rw} for target, (source, rw) in mounts.items()]},
        "Mounts": [{"Type": "bind", "Source": source, "Destination": target, "RW": rw} for target, (source, rw) in mounts.items()]}


class RunnerPolicyTests(unittest.TestCase):
    def test_inside_observes_real_flags_without_requiring_nosuid_on_the_data_disk(self):
        text = "Uid:\t10001 10001 10001 10001\nGid:\t10001 10001 10001 10001\n" + "".join(key + ":\t0\n" for key in ("CapEff", "CapBnd", "CapPrm", "CapInh", "CapAmb")) + "NoNewPrivs:\t1\nSeccomp:\t2\n"
        def read(path, *args, **kwargs):
            return {"/proc/self/status": text, "/proc/self/attr/current": policy.PROFILE + " (enforce)\n",
                    "/sys/fs/cgroup/pids.max": "4096\n"}.get(str(path), "")
        def mount(path):
            return {"mount_flags": ["ro"] if path == "/" else ["rw", "nosuid", "nodev", "noexec"] if path in policy.TMPFS else ["rw", "relatime"],
                    "exec_allowed": path not in policy.TMPFS, "f_flag": 0}
        metadata = SimpleNamespace(st_uid=10001, st_gid=10001, st_mode=0o40700)
        with mock.patch.object(Path, "read_text", read), mock.patch.object(policy, "flags", side_effect=mount), \
                mock.patch.object(Path, "stat", return_value=metadata):
            evidence = policy.inside_evidence()
        self.assertEqual(evidence["result"], "PASS")
        self.assertEqual(set(evidence["checks"]), REQUIRED)
        self.assertEqual(evidence["source_mounts"]["/var/lib/camact"]["mount_flags"], ["rw", "relatime"])

    def test_failed_inside_observation_cannot_execute_the_requested_command(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(policy, "READY", str(Path(temporary) / "ready.json")), \
                mock.patch.object(policy, "inside_evidence", return_value={"result": "FAIL"}), \
                mock.patch.object(policy.subprocess, "run") as command, \
                mock.patch.object(policy.os, "replace", wraps=os.replace) as replace:
            self.assertEqual(policy.inside(["paid-command"]), 125)
            command.assert_not_called()
            replace.assert_called_once_with(Path(policy.READY + ".pending"), policy.READY)
            self.assertEqual(json.loads(Path(policy.READY).read_text()), {"result": "FAIL"})
            self.assertFalse(Path(policy.READY + ".pending").exists())

    def test_live_namespace_helpers_accept_only_a_container_and_one_fixed_tmpfs_file(self):
        for helper, code in ((policy.ready_command, policy.READ_READY_CODE), (policy.release_command, policy.WRITE_RELEASE_CODE)):
            argv = helper("camact-fixture-123", "/run/camact/runner-policy.json")
            self.assertEqual(argv, ["docker", "exec", "camact-fixture-123", "python", "-B", "-c", code,
                                    "/run/camact/runner-policy.json"])
            self.assertFalse(any(value.startswith(("--privileged", "--user", "--env")) for value in argv))
            for container, path in (("--privileged", "/run/camact/ready"), ("a b", "/run/camact/ready"),
                    ("fixture", "/tmp/ready"), ("fixture", "/run/camact/../ready"),
                    ("fixture", "/run/camact/sub/ready"), ("fixture", "/run/camact/./ready"),
                    ("fixture", "/run/camact/ready\0"), ("fixture", "/var/lib/camact/checkpoints/ready")):
                with self.subTest(helper=helper.__name__, container=container, path=path), self.assertRaises(ValueError):
                    helper(container, path)

    def execute_ready_code(self, path, *, owner=10001, size=None):
        output = io.BytesIO()
        real_fstat = os.fstat
        def metadata(descriptor):
            value = real_fstat(descriptor)
            return SimpleNamespace(st_mode=value.st_mode, st_uid=owner, st_size=value.st_size if size is None else size)
        with mock.patch.object(sys, "argv", ["ready", str(path)]), \
                mock.patch.object(sys, "stdout", SimpleNamespace(buffer=output)), \
                mock.patch.object(os, "fstat", side_effect=metadata):
            exec(policy.READ_READY_CODE, {})
        return output.getvalue()

    def test_ready_code_reads_original_bytes_and_only_missing_files_return_75(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ready"
            with self.assertRaises(SystemExit) as missing:
                self.execute_ready_code(path)
            self.assertEqual(missing.exception.code, 75)
            path.write_bytes(b'{"synthetic":true}\n')
            self.assertEqual(self.execute_ready_code(path), path.read_bytes())
            for options in ({"owner": 0}, {"size": 65537}):
                with self.subTest(options=options), self.assertRaises(SystemExit) as unsafe:
                    self.execute_ready_code(path, **options)
                self.assertNotEqual(unsafe.exception.code, 75)
            path.write_bytes(b"x" * 65537)
            with self.assertRaises(SystemExit):
                self.execute_ready_code(path, size=1)  # Reject growth after the metadata check, too.
            target = Path(temporary) / "symlink"
            target.symlink_to(path)
            with self.assertRaises(SystemExit) as symbolic:
                self.execute_ready_code(target)
            self.assertNotEqual(symbolic.exception.code, 75)
            path.unlink()
            os.mkfifo(path)
            with self.assertRaises(SystemExit) as fifo:
                self.execute_ready_code(path)
            self.assertNotEqual(fifo.exception.code, 75)

    def test_release_code_creates_only_the_fixed_marker_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release"
            with mock.patch.object(sys, "argv", ["release", str(path)]):
                exec(policy.WRITE_RELEASE_CODE, {})
                self.assertEqual(path.read_bytes(), b"verified\n")
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                with self.assertRaises(SystemExit):
                    exec(policy.WRITE_RELEASE_CODE, {})
                self.assertEqual(path.read_bytes(), b"verified\n")
                path.unlink()
                target = Path(temporary) / "target"
                target.write_bytes(b"unchanged")
                path.symlink_to(target)
                with self.assertRaises(SystemExit):
                    exec(policy.WRITE_RELEASE_CODE, {})
                self.assertEqual(target.read_bytes(), b"unchanged")

    def test_actual_host_policy_requires_exact_filter_identity_and_mounts(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = configuration(Path(temporary))
            rules = json.loads((ROOT / "deploy/seccomp-gvisor.json").read_text())
            for started in (False, True):
                self.assertEqual(policy.inspect_errors(inspected(config, started), config, IMAGE, rules, started=started), [])
                for field, bad in (("CapAdd", ["CAP_SYS_ADMIN"]), ("ReadonlyRootfs", False), ("PidsLimit", 0),
                                   ("NetworkMode", "bridge"), ("SecurityOpt", ["seccomp=unconfined"])):
                    actual = inspected(config, started)
                    actual["HostConfig"][field] = bad
                    self.assertTrue(policy.inspect_errors(actual, config, IMAGE, rules, started=started))
            actual = inspected(config, True)
            actual["Mounts"][1]["RW"] = True
            self.assertIn("mounts", policy.inspect_errors(actual, config, IMAGE, rules, started=True))

    def test_created_bind_protocol_and_tmpfs_numeric_normalization(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = configuration(Path(temporary))
            actual = inspected(config)
            actual["HostConfig"]["Binds"] = [m["Source"] + ":" + m["Target"] + (":ro" if m["ReadOnly"] else ":rw") for m in actual["HostConfig"].pop("Mounts")]
            self.assertEqual(policy.inspect_errors(actual, config, IMAGE, json.loads((ROOT / "deploy/seccomp-gvisor.json").read_text()), started=False), [])
            self.assertEqual(policy.options("size=256m,mode=700,uid=10001")["size"], 268435456)
            with self.assertRaises(ValueError):
                policy.options("rw,rw")

    def exercise(self, *, failure=None, code=0, cleanup=0, runner_update=None, failure_stderr=None, container_stderr="", ready_codes=None):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            config = configuration(directory)
            config["services"]["runner"].update(runner_update or {})
            source = directory / "compose.json"
            source.write_text(json.dumps(config))
            args = SimpleNamespace(stage="native-test", image=IMAGE, output=str(directory / "archive"),
                                   compose_config=str(source), project="fixture", timeout=30)
            calls = []
            count = 0
            ready_results = iter(ready_codes or [0])
            def call(argv, **kwargs):
                nonlocal count
                calls.append(argv)
                stdout, stderr, rc = "", "", 0
                if "create" in argv:
                    # Model the real create CLI; a permissive stub hid Run40773680176.
                    if "--no-deps" in argv:
                        return subprocess.CompletedProcess(argv, 16, "", "unknown flag: --no-deps")
                    self.assertEqual(argv[argv.index("create"):], ["create", "--no-build", "--pull", "never", "runner"])
                    stage_config = json.loads(Path(argv[argv.index("-f") + 1]).read_text())
                    self.assertEqual(set(stage_config["services"]), {"runner"})
                    self.assertIn("storage-init", json.loads(source.read_text())["services"])
                    if failure == "create":
                        rc, stderr = 16, failure_stderr or "unknown flag: --synthetic-cli-flag"
                    elif failure == "create_timeout":
                        raise subprocess.TimeoutExpired(argv, 120, output="private-inspect-output", stderr=CANARY)
                elif "ps" in argv:
                    stdout = "a" * 64
                elif argv[:2] == ["docker", "inspect"]:
                    actual = inspected(config, count > 0)
                    if failure == ("created" if count == 0 else "started"):
                        actual["HostConfig"]["ReadonlyRootfs"] = False
                    if failure == "inspect_cli":
                        actual["Config"]["Env"] = ["MODEL_CONFIGURATION=synthetic-private-model-config"]
                        rc, stderr = 29, "inspect failed: " + CANARY
                    count += 1
                    stdout = json.dumps(actual)
                elif argv[:2] == ["docker", "cp"]:
                    raise AssertionError("docker cp cannot access the running tmpfs namespace")
                elif argv[:2] == ["docker", "exec"] and argv[-1] == policy.READY:
                    self.assertEqual(argv, policy.ready_command("a" * 64, policy.READY))
                    self.assertGreater(kwargs["timeout"], 0)
                    self.assertLessEqual(kwargs["timeout"], 5)
                    rc = next(ready_results, 75)
                    evidence = {"schema": "camact.runner-policy.inside.v1", "result": "PASS", "checks": dict.fromkeys(REQUIRED, True)}
                    if failure == "inside":
                        evidence["checks"] = {}
                    if failure == "ready_timeout":
                        raise subprocess.TimeoutExpired(argv, kwargs["timeout"], output=CANARY, stderr=CANARY)
                    stdout = ("x" * 65537 if failure == "ready_oversize" else "malformed" if failure == "ready_malformed"
                              else json.dumps(evidence)) if rc == 0 else ""
                    stderr = CANARY if rc not in {0, 75} else ""
                elif argv[:2] == ["docker", "exec"] and argv[-1] == policy.RELEASE:
                    self.assertEqual(argv, policy.release_command("a" * 64, policy.RELEASE))
                    if failure == "release":
                        rc, stderr = 1, "release_write_failed"
                elif argv[:2] == ["docker", "wait"]:
                    if failure == "timeout":
                        raise subprocess.TimeoutExpired(argv, 30)
                    stdout = str(code)
                elif argv[:2] == ["docker", "rm"]:
                    rc = cleanup
                elif argv[:2] == ["docker", "logs"]:
                    if failure == "logs":
                        raise subprocess.TimeoutExpired(argv, 60)
                    kwargs["stdout"].write(b"synthetic normal output\n")
                    kwargs["stderr"].write(container_stderr.encode())
                return subprocess.CompletedProcess(argv, rc, stdout, stderr)
            clock = iter(range(0, 1000, 10))
            timer = mock.patch.object(policy.time, "monotonic", side_effect=lambda: next(clock)) if failure == "ready_missing" else contextlib.nullcontext()
            with mock.patch.object(policy.subprocess, "run", side_effect=call), \
                    mock.patch.dict(os.environ, {"AGENT_API_KEY": CANARY}), \
                    mock.patch.object(policy.time, "sleep"), timer, \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                result = policy.run(args, ["python", "-B", "scripts/check-runtimes.py", "--sandbox"])
            report = json.loads((directory / "archive/runner-policy/native-test.json").read_text())
            report["_public_logs"] = "".join(path.read_text() for path in (directory / "archive/runner-policy").glob("*.log"))
            return result, report, calls

    def test_command_is_released_only_after_both_host_checks_and_actual_inside_evidence(self):
        result, report, calls = self.exercise()
        self.assertEqual(result, 0)
        self.assertEqual(report["result"], "PASS")
        release = next(i for i, argv in enumerate(calls) if argv[:2] == ["docker", "exec"] and argv[-1] == policy.RELEASE)
        self.assertEqual(sum(argv[:2] == ["docker", "inspect"] for argv in calls[:release]), 2)
        self.assertTrue(any(argv[:2] == ["docker", "rm"] for argv in calls))

    def test_only_missing_ready_retries_and_all_read_errors_keep_business_command_blocked(self):
        result, report, calls = self.exercise(ready_codes=[75, 0])
        self.assertEqual(result, 0)
        self.assertEqual(report["operations"], [])
        self.assertEqual(sum(argv[:2] == ["docker", "exec"] and argv[-1] == policy.READY for argv in calls), 2)
        for options in ({"ready_codes": [1]}, {"failure": "ready_timeout"}, {"failure": "ready_malformed"},
                        {"failure": "ready_oversize"}, {"failure": "ready_missing", "ready_codes": [75]}):
            with self.subTest(options=options):
                result, report, calls = self.exercise(**options)
                self.assertEqual(result, 125)
                self.assertEqual(report["result"], "FAIL")
                self.assertNotIn("command_exit_code", report)
                self.assertNotIn(CANARY, json.dumps(report))
                self.assertFalse(any(argv[:2] == ["docker", "exec"] and argv[-1] == policy.RELEASE for argv in calls))
                self.assertFalse(any(argv[:2] == ["docker", "wait"] for argv in calls))
                self.assertTrue(any(argv[:2] == ["docker", "rm"] for argv in calls))

    def test_failed_exclusive_release_never_runs_the_business_command(self):
        result, report, calls = self.exercise(failure="release")
        self.assertEqual(result, 125)
        self.assertNotIn("command_exit_code", report)
        self.assertEqual(report["operations"][0]["operation"], "release_write")
        self.assertFalse(any(argv[:2] == ["docker", "wait"] for argv in calls))
        self.assertTrue(any(argv[:2] == ["docker", "rm"] for argv in calls))

    def test_create_failure_retains_sanitized_stderr_actual_code_and_cleanup_without_release(self):
        stderr = "unknown flag: --synthetic-cli-flag\nAuthorization: Bearer " + CANARY + "\nhf_synthetic_token_123456789\n"
        result, report, calls = self.exercise(failure="create", failure_stderr=stderr)
        self.assertEqual(result, 125)
        self.assertEqual(report["result"], "FAIL")
        self.assertNotIn("command_exit_code", report)
        self.assertEqual(report["checks"], [])
        self.assertEqual(report["cleanup_returncode"], 0)
        self.assertEqual(len(report["operations"]), 1)
        operation = report["operations"][0]
        self.assertEqual(operation["operation"], "compose_create")
        self.assertEqual(operation["returncode"], 16)
        self.assertFalse(operation["timeout"])
        self.assertIn("unknown flag", operation["stderr"])
        self.assertNotIn(CANARY, json.dumps(report))
        self.assertNotIn("hf_synthetic_token_123456789", json.dumps(report))
        self.assertNotIn("argv", operation)
        self.assertTrue(any("down" in argv for argv in calls))
        self.assertFalse(any(argv[:2] == ["docker", "start"] or "ps" in argv for argv in calls))

    def test_command_diagnostics_sanitize_before_bounding_and_omit_stdout(self):
        # A credential beginning before the bound and ending after it must vanish whole.
        stderr = "x" * (policy.LIMIT - 5) + "\n" + CANARY + "\n" + "tail" * 20
        result, report, _ = self.exercise(failure="create", failure_stderr=stderr)
        operation = report["operations"][0]
        self.assertNotEqual(result, 0)
        self.assertTrue(operation["truncated"])
        self.assertLessEqual(len(operation["stderr"].encode()), policy.LIMIT)
        self.assertNotIn(CANARY[:8], operation["stderr"][-30:])
        self.assertIn("<red", operation["stderr"][-30:])
        self.assertNotIn("stdout", operation)

    def test_create_timeout_is_distinct_and_never_exposes_inspect_stdout_or_releases(self):
        result, report, calls = self.exercise(failure="create_timeout")
        self.assertEqual(result, 125)
        self.assertNotIn("command_exit_code", report)
        self.assertTrue(report["operations"][0]["timeout"])
        self.assertIsNone(report["operations"][0]["returncode"])
        self.assertNotIn("private-inspect-output", json.dumps(report))
        self.assertNotIn(CANARY, json.dumps(report))
        self.assertTrue(any("down" in argv for argv in calls))

    def test_runner_dependencies_are_rejected_before_any_docker_operation(self):
        changes = [{"depends_on": {"storage-init": {"condition": "service_completed_successfully"}}},
                   {"links": ["storage-init"]}, {"volumes_from": ["storage-init"]}]
        changes += [{key: "service:storage-init"} for key in ("network_mode", "ipc", "pid", "uts", "cgroup")]
        for update in changes:
            with self.subTest(update=update):
                result, report, calls = self.exercise(runner_update=update)
                self.assertEqual(result, 125)
                self.assertEqual(report["failure"], "runner_configuration_rejected")
                self.assertNotIn("command_exit_code", report)
                self.assertEqual(calls, [])

    def test_failed_inspect_keeps_stdout_private_and_still_removes_created_container(self):
        result, report, calls = self.exercise(failure="inspect_cli")
        self.assertEqual(result, 125)
        self.assertNotIn("command_exit_code", report)
        self.assertEqual(report["operations"][0]["operation"], "created_inspect")
        self.assertEqual(report["operations"][0]["returncode"], 29)
        self.assertNotIn("synthetic-private-model-config", json.dumps(report))
        self.assertNotIn(CANARY, json.dumps(report))
        self.assertTrue(any(argv[:2] == ["docker", "rm"] for argv in calls))
        self.assertFalse(any(argv[:2] == ["docker", "exec"] and argv[-1] == policy.RELEASE for argv in calls))

    def test_uploaded_container_logs_redact_credentials(self):
        stderr = "Authorization: Bearer " + CANARY + "\nhf_synthetic_log_token_123456789\n"
        result, report, _ = self.exercise(container_stderr=stderr)
        self.assertEqual(result, 0)
        self.assertIn("<redacted>", report["_public_logs"])
        self.assertNotIn(CANARY, report["_public_logs"])
        self.assertNotIn("hf_synthetic_log_token_123456789", report["_public_logs"])

    def test_failed_created_started_or_missing_inside_checks_never_release_and_always_cleanup(self):
        for failure in ("created", "started", "inside"):
            with self.subTest(failure=failure):
                result, report, calls = self.exercise(failure=failure)
                self.assertNotEqual(result, 0)
                self.assertEqual(report["result"], "FAIL")
                self.assertFalse(any(argv[:2] == ["docker", "exec"] and argv[-1] == policy.RELEASE for argv in calls))
                self.assertTrue(any(argv[:2] == ["docker", "rm"] for argv in calls))

    def test_command_timeout_nonzero_and_cleanup_failure_keep_gate_closed(self):
        for options in ({"failure": "timeout"}, {"failure": "logs"}, {"code": 37}, {"cleanup": 19}):
            with self.subTest(options=options):
                result, report, calls = self.exercise(**options)
                self.assertNotEqual(result, 0)
                self.assertEqual(report["result"], "FAIL")
                self.assertTrue(any(argv[:2] == ["docker", "rm"] for argv in calls))


if __name__ == "__main__":
    unittest.main()
