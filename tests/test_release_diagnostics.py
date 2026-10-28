"""Regression coverage for public failure details and the real offline cache CLI."""
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from release import benchmark
from release.diagnostics import PREFIX, stderr_summary

ROOT = Path(__file__).resolve().parents[1]


def script(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SyntheticCacheRegression(unittest.TestCase):
    def test_actual_cli_creates_and_reuses_run_id_cache_twice_without_network_or_tokens(self):
        with tempfile.TemporaryDirectory(prefix="camact-cache-regression-") as temporary:
            root = Path(temporary)
            # Enforce the prohibition in each real CLI process, including any
            # accidental future imports, not just mocked return values.
            (root / "sitecustomize.py").write_text('''import os, sys
def guard(event, args):
    if event.startswith("socket."):
        raise AssertionError("network_forbidden")
    if event == "open" and isinstance(args[0], (str, bytes)):
        path = os.fsdecode(args[0])
        if os.path.basename(path) in {"token", "stored_tokens"} or path.startswith("/run/secrets/"):
            raise AssertionError("token_read_forbidden")
sys.addaudithook(guard)
''')
            env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(root), "PYTHONDONTWRITEBYTECODE": "1",
                   "HOME": str(root), "HF_HOME": str(root), "HF_TOKEN_FILE": str(root / "token"),
                   "HF_HUB_OFFLINE": "1", "HF_HUB_DISABLE_IMPLICIT_TOKEN": "1"}
            repo, revision = "Fixture/Container-Smoke-docker-gates-20261029-a", "0" * 40
            command = [sys.executable, "-B", str(ROOT / "scripts/verify-benchmark-cache.py"),
                       "--cache-root", str(root / "cache"), "--repo", repo, "--revision", revision]
            check = "import sys; sys.audit('socket.camact_guard_check')"
            active = subprocess.run([sys.executable, "-B", "-c", check], env=env, capture_output=True, text=True, timeout=15)
            self.assertNotEqual(active.returncode, 0)
            self.assertIn("network_forbidden", active.stderr)
            check = "import sys; sys.audit('open', 'token', 'r', 0)"
            active = subprocess.run([sys.executable, "-B", "-c", check], env=env, capture_output=True, text=True, timeout=15)
            self.assertNotEqual(active.returncode, 0)
            self.assertIn("token_read_forbidden", active.stderr)
            reports = []
            for extra in (["--create"], [], []):
                completed = subprocess.run(command + extra, env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                reports.append(json.loads(completed.stdout))
            self.assertEqual(reports[0], reports[1])
            self.assertEqual(reports[1], reports[2])
            directory, _ = benchmark._location(root / "cache", repo, revision)
            self.assertTrue((directory / "snapshot/fixture/task.yaml").is_file())
            marker = json.loads((directory / "complete.json").read_text())
            self.assertEqual(reports[0]["manifest_sha256"], marker["manifest_sha256"])
            with patch.object(benchmark, "_token", side_effect=AssertionError("token")), \
                    patch.object(benchmark, "_metadata", side_effect=AssertionError("network")):
                self.assertEqual(benchmark.ensure(root / "cache", repo, revision, offline=True), directory / "snapshot")
                with self.assertRaises(benchmark.BenchmarkError):
                    benchmark.ensure(root / "cache", repo + "b", revision, offline=True)
                with self.assertRaises(benchmark.BenchmarkError):
                    benchmark.ensure(root / "cache", repo, "1" * 40, offline=True)

    def test_fixture_reuse_rejects_missing_corrupt_and_unlisted_files_without_repair(self):
        cache = script("verify-benchmark-cache")
        for damage in ("missing", "same_size_corruption", "unlisted"):
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as temporary, \
                    patch.object(benchmark, "_token", side_effect=AssertionError("token")), \
                    patch.object(benchmark, "_metadata", side_effect=AssertionError("network")), \
                    patch.object(benchmark, "_download", side_effect=AssertionError("download")):
                repo, revision = "Fixture/Container-Smoke-regression-run-id", "0" * 40
                cache.verify(temporary, repo, revision, create=True)
                directory, _ = benchmark._location(temporary, repo, revision)
                data = directory / "snapshot/fixture/task.yaml"
                if damage == "missing":
                    data.unlink()
                elif damage == "same_size_corruption":
                    data.write_bytes(b"x" * data.stat().st_size)
                else:
                    (directory / "snapshot/unlisted").write_text("fixture")
                with self.assertRaises(benchmark.BenchmarkError):
                    cache.verify(temporary, repo, revision)


class OfflineFailureDiagnostics(unittest.TestCase):
    def test_assertions_errors_and_subtests_report_source_without_private_values(self):
        offline = script("run-offline-tests")
        canary = "private-diagnostic-value"

        class Failing(unittest.TestCase):
            def test_equality(self):
                self.assertEqual(2, 3, canary)

            def test_subtest(self):
                with self.subTest(secret=canary):
                    raise PermissionError(errno.EACCES, canary, "/private/" + canary)

        result = unittest.TextTestRunner(stream=io.StringIO(), resultclass=offline.DiagnosticResult).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(Failing))
        details = result.failure_details
        self.assertEqual(len(details), 2)
        encoded = json.dumps(details)
        self.assertNotIn(canary, encoded)
        self.assertNotIn(str(ROOT), encoded)
        self.assertEqual(details[0]["assertion_kind"], "assertEqual")
        self.assertIn("self.assertEqual(2, 3", details[0]["assertion_source"])
        self.assertEqual(details[0]["exception_type"], "AssertionError")
        self.assertTrue(details[0]["traceback"])
        self.assertEqual(details[1]["errno"], errno.EACCES)
        self.assertTrue(details[1]["subtest"])

    def test_output_setup_failure_emits_safe_diagnostic_and_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "private-path-canary"
            parent.write_text("file")
            process = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/run-offline-tests.py"),
                                      "--output", str(parent / "child")],
                                     capture_output=True, text=True, timeout=15)
            self.assertEqual(process.returncode, 1)
            public = json.loads(process.stdout.removeprefix(PREFIX))
            self.assertFalse(public["success"])
            self.assertEqual(public["failure_details"][0]["errno"], errno.ENOTDIR)
            self.assertNotIn(str(parent), process.stdout + process.stderr)


class SandboxDiagnostics(unittest.TestCase):
    def test_stderr_summary_uses_fixed_categories_and_errno_names(self):
        value = stderr_summary("private-value /private/path https://private.invalid?token=value "
                               "creating sandbox: mount: operation not permitted (errno=1)")
        self.assertIn("operation_not_permitted", value["categories"])
        self.assertEqual(value["errno_names"], ["EPERM"])
        self.assertNotIn("private", json.dumps(value))

    def test_namespace_denial_preserves_exact_syscall_and_errno(self):
        diagnostic = script("diagnose-gvisor")
        from contextlib import redirect_stdout
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary, redirect_stdout(output), \
                patch.object(diagnostic, "syscall", side_effect=PermissionError(errno.EPERM, "private-value")):
            diagnostic.probe("user", Path(temporary), "host")
        steps = json.loads(output.getvalue())
        self.assertEqual(steps[0]["stage"], "user.unshare")
        self.assertEqual(steps[0]["errno"], errno.EPERM)

    def test_minimal_lifecycle_failure_is_not_reported_as_success(self):
        diagnostic = script("gvisor-preflight")
        from harness.camact_multi_harness_v1.camact_multi import gvisor
        # Only filesystem preconditions are supplied; no real namespace/runsc
        # execution is represented by this diagnostic-format regression.
        with patch.object(Path, "is_file", return_value=True), \
                patch.object(Path, "is_dir", return_value=True), \
                patch.object(diagnostic.os, "access", return_value=True), \
                patch.object(gvisor, "RUNSC", ROOT / ".tools/gvisor/20261012.0/runsc"), \
                patch.object(diagnostic, "execute", side_effect=[
                    ({"exit_code": 0}, "20261012.0"),
                    ({"exit_code": 0}, "unknown flags")]):
            value = diagnostic.runsc_probe()
        self.assertEqual(value["result"], "FAIL")
        self.assertEqual(value["stage"], "flags")


class LightweightDiagnosticSafety(unittest.TestCase):
    def test_effective_policy_rejects_privilege_or_seccomp_drift(self):
        diagnostic = script("diagnose-gvisor")
        policy = json.loads((ROOT / "deploy/seccomp-gvisor.json").read_text())
        for drift in (None, "privileged", "cap_add", "seccomp"):
            with self.subTest(drift=drift):
                observed = {"user": "10001:10001", "cap_drop": ["ALL"], "cap_add": None,
                    "read_only": True, "privileged": False, "pids_limit": 4096,
                    "apparmor": "docker-default", "security_opt": ["no-new-privileges:true",
                        "seccomp=" + json.dumps(policy if drift != "seccomp" else {})]}
                if drift in ("privileged", "cap_add"):
                    observed[drift] = True if drift == "privileged" else ["SYS_ADMIN"]
                with patch.object(diagnostic, "command", return_value={"returncode": 0,
                        "stdout": json.dumps(observed), "stderr": "", "errno": None, "timed_out": False}):
                    row, _ = diagnostic.inspect_policy("fixture-container")
                self.assertEqual(row["status"], "PASS" if drift is None else "FAIL")

    def test_controller_scans_immutable_base_before_execution_and_always_cleans_up(self):
        from contextlib import redirect_stdout
        diagnostic = script("diagnose-gvisor")
        image_id = "sha256:" + "7" * 64
        service = {"platform": "linux/amd64", "user": "10001:10001", "pids_limit": 4096,
                   "tmpfs": ["/tmp:rw,nosuid,nodev,size=512m,uid=10001,gid=10001,mode=1777"]}
        for scan_failure in (True, False):
            calls = []

            def execute(argv, *args, **kwargs):
                argv = [str(value) for value in argv]
                calls.append(argv)
                code, output = 0, ""
                if argv[:2] == ["docker", "info"]:
                    output = "[]"
                elif argv[:3] == ["docker", "image", "inspect"]:
                    output = image_id
                elif any(value.endswith("scripts/scan-image.py") for value in argv):
                    code = int(scan_failure)
                    output = json.dumps({"result": "FAIL" if scan_failure else "PASS", "issue_count": int(scan_failure),
                                         "files_scanned": 1, "bytes_scanned": 1})
                elif argv[:2] == ["docker", "create"]:
                    self.assertFalse(scan_failure)
                    self.assertIn(image_id, argv)
                    self.assertIn("--cap-drop=ALL", argv)
                    self.assertIn("10001:10001", argv)
                    self.assertIn("--read-only", argv)
                    self.assertNotIn("--privileged", argv)
                    self.assertFalse(any("unconfined" in v or "--cap-add" in v for v in argv))
                elif argv[:2] == ["docker", "start"]:
                    output = json.dumps({"environment": {"apparmor_current": {"value": "docker-default (enforce)"}},
                        "runsc_debug": "", "tests": [diagnostic.row("docker", "user_mount.unshare", "PASS"),
                        diagnostic.row("gvisor", "run", "PASS"), diagnostic.row("gvisor", "delete", "PASS")]})
                elif argv[:2] not in (["docker", "pull"], ["docker", "rm"]):
                    raise AssertionError("Unexpected diagnostic command")
                return {"returncode": code, "stdout": output, "stderr": "", "errno": None, "timed_out": False}

            with self.subTest(scan_failure=scan_failure), tempfile.TemporaryDirectory() as temporary, \
                    redirect_stdout(io.StringIO()), \
                    patch.object(diagnostic, "environment", return_value={}), \
                    patch.object(diagnostic, "namespace_tests", return_value=[]), \
                    patch.object(diagnostic, "compose_policy", return_value=(service, diagnostic.row("docker", "compose_policy", "PASS"))), \
                    patch.object(diagnostic, "inspect_policy", return_value=(diagnostic.row("docker", "effective_policy", "PASS"), {"apparmor": "docker-default"})), \
                    patch.object(diagnostic, "download_gvisor"), \
                    patch.object(diagnostic, "audit_records", return_value=([], [])), \
                    patch.object(diagnostic, "command", side_effect=execute), \
                    patch.dict(os.environ, {}, clear=True):
                code = diagnostic.diagnose(Path(temporary))
                report = json.loads((Path(temporary) / "report.json").read_text())
                self.assertEqual(code, 1 if scan_failure else 0)
                self.assertEqual(report["outcome"], "FAIL" if scan_failure else "PASS")
                self.assertEqual(any(call[:2] == ["docker", "create"] for call in calls), not scan_failure)
                self.assertEqual(any(call[:2] == ["docker", "rm"] for call in calls), not scan_failure)


if __name__ == "__main__":
    unittest.main()
