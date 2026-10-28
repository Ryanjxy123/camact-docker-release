"""Fail-closed host orchestration without invoking Docker or a model."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("production_plan_controller", ROOT / "scripts/diagnostic/production-plan-controller.py")
controller = importlib.util.module_from_spec(SPEC)
# This suite mocks every process; the shared syscall library is never used.
with mock.patch("ctypes.CDLL"):
    SPEC.loader.exec_module(controller)
IMAGE = "sha256:" + "a" * 64
REVISION = "b" * 40


def result(code=0, stdout="", stderr=""):
    return {"returncode": code, "stdout": stdout, "stderr": stderr, "errno": None, "timed_out": False}


def lifecycle():
    return {"returncode": 0, "cleanup_returncode": 0, "state_removed": True}


def inner_report(check_runtimes=True):
    names = controller.INNER_REQUIRED | ({"check_runtimes"} if check_runtimes else set())
    report = {"schema": controller.INNER_SCHEMA, "outcome": "PASS",
              "tests": [{"test": name, "status": "PASS"} for name in sorted(names)],
              "lifecycles": [lifecycle() for _ in range(7 if check_runtimes else 1)]}
    if check_runtimes:
        report["runtime_checks"] = {name: {"returncode": 0, "lifecycle": lifecycle()}
                                    for name in controller.RUNTIME_REQUIRED - {"credential_boundary"}}
        report["runtime_checks"]["credential_boundary"] = {"synthetic_only": True,
            "trusted_credentials_absent": True, "plan_and_lifecycle_canary_values_absent": True,
            "lifecycle": lifecycle()}
    return report


def compose():
    return {"services": {
        "runner": {"user": "10001:10001", "cap_drop": ["ALL"], "read_only": True,
            "security_opt": ["no-new-privileges:true", "seccomp=./deploy/seccomp-gvisor.json"],
            "pids_limit": 4096, "platform": "linux/amd64", "tmpfs": [
                "/run/camact:rw,nosuid,nodev,size=256m,uid=10001,gid=10001,mode=0700",
                "/run/camact/openclaw:rw,nosuid,nodev,size=256m,uid=10001,gid=10001,mode=0700",
                "/tmp:rw,nosuid,nodev,size=512m,uid=10001,gid=10001,mode=1777"]},
        "storage-init": {"user": "0:0", "cap_drop": ["ALL"],
            "cap_add": ["CHOWN", "DAC_OVERRIDE", "FOWNER"], "read_only": True, "network_mode": "none",
            "entrypoint": ["python", "-B", "/opt/camact/scripts/init-storage.py"]}}}


class DockerFixture:
    def __init__(self, *, scan_pass=True, drift=None, helper_drift=None, report=None, omit=(),
                 empty_created_mounts=False, timeout_role=None):
        self.calls = []
        self.containers = {}
        self.scan_pass = scan_pass
        self.scan_seen = False
        self.drift = drift
        self.helper_drift = helper_drift
        self.empty_created_mounts = empty_created_mounts
        self.timeout_role = timeout_role
        self.report = inner_report() if report is None else report
        self.omit = set(omit)
        self.source = compose()

    def __call__(self, argv, timeout=20):
        argv = [str(value) for value in argv]
        self.calls.append(argv)
        if argv[0] == "git":
            return result(stdout=REVISION)
        if argv[0] == "sudo":
            return result(1, stderr="Audit unavailable in the unit fixture")
        if len(argv) > 2 and argv[2].endswith("scan-image.py"):
            self.scan_seen = True
            return result(stdout=json.dumps({"result": "PASS" if self.scan_pass else "FAIL",
                "issue_count": 0 if self.scan_pass else 1, "issues": [] if self.scan_pass else [{}],
                "candidate_values_printed": False}))
        if argv[:3] == ["docker", "image", "inspect"]:
            return result(stdout=json.dumps({"id": IMAGE, "version": controller.VERSION,
                "revision": REVISION, "os": "linux", "architecture": "amd64"}))
        if argv[:2] == ["docker", "compose"]:
            return result(stdout=json.dumps(self.source))
        if argv[:2] == ["docker", "create"]:
            if not self.scan_seen or not self.scan_pass:
                raise AssertionError("A container was created before the immutable image scan passed")
            name = argv[argv.index("--name") + 1]
            user = argv[argv.index("--user") + 1]
            security = [value.partition("=")[2] for value in argv if value.startswith("--security-opt=")]
            security = ["seccomp=" + (ROOT / "deploy/seccomp-gvisor.json").read_text()
                        if value.startswith("seccomp=") else value for value in security]
            mounts, tmpfs, caps = [], {}, []
            for index, value in enumerate(argv):
                if value == "--mount":
                    parts = dict(piece.split("=", 1) for piece in argv[index + 1].split(",") if "=" in piece)
                    mounts.append({"Type": parts["type"], "Source": parts["src"], "Destination": parts["dst"],
                                   "RW": "readonly" not in argv[index + 1].split(",")})
                elif value == "--tmpfs":
                    target, options = argv[index + 1].split(":", 1)
                    tmpfs[target] = options
                elif value == "--cap-add":
                    caps.append(argv[index + 1])
            self.containers[name] = {"image": IMAGE, "user": user, "cap_drop": ["ALL"], "cap_add": caps,
                "read_only": True, "privileged": False, "pids_limit": 4096 if user == "10001:10001" else None,
                "apparmor": "", "security_opt": security, "network": "none", "tmpfs": tmpfs,
                "mounts": mounts, "requested_mounts": [
                    {"Type": item["Type"], "Source": item["Source"], "Target": item["Destination"], "ReadOnly": not item["RW"]}
                    for item in mounts], "state": {"Status": "created", "ExitCode": 0}}
            role = "runner" if user == "10001:10001" else "helper"
            if self.timeout_role == role:
                timed_out = result(124, stderr="Synthetic create timeout")
                timed_out["timed_out"] = True
                return timed_out
            return result(stdout=name)
        if argv[:2] == ["docker", "inspect"]:
            actual = dict(self.containers[argv[-1]])
            if self.drift and actual["user"] == "10001:10001":
                actual[self.drift[0]] = self.drift[1]
            if self.helper_drift and actual["user"] == "0:0":
                actual[self.helper_drift[0]] = self.helper_drift[1]
            if self.empty_created_mounts and actual["state"]["Status"] == "created":
                actual["mounts"] = []
            return result(stdout=json.dumps(actual))
        if argv[:2] == ["docker", "start"]:
            actual = self.containers[argv[-1]]
            actual["apparmor"] = controller.PROFILE if actual["user"] == "10001:10001" else "docker-default"
            actual["state"] = {"Status": "exited", "ExitCode": 0, "OOMKilled": False, "Error": ""}
            return result(stdout="fixed synthetic output")
        if argv[:2] == ["docker", "cp"]:
            destination = Path(argv[-1])
            values = {"report.json": json.dumps(self.report), "summary.md": "Synthetic PASS\n",
                      "plan.json": "{}", "lifecycle.json": json.dumps(lifecycle())}
            for name, content in values.items():
                if name not in self.omit:
                    (destination / name).write_text(content, encoding="utf-8")
            return result()
        if argv[:3] == ["docker", "rm", "--force"]:
            self.containers.pop(argv[-1], None)
            return result()
        raise AssertionError("Unexpected command category: " + argv[0])


class ControllerTests(unittest.TestCase):
    def invoke(self, fixture):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "production-plan"
        with mock.patch.object(controller.diag, "command", side_effect=fixture):
            report = controller.Controller(output).run("camact:gvisor-diagnostic")
        return report, output

    def test_scan_passes_before_every_helper_and_runner(self):
        fixture = DockerFixture()
        report, output = self.invoke(fixture)
        self.assertEqual(report["outcome"], "PASS")
        scan_index = next(index for index, argv in enumerate(fixture.calls) if len(argv) > 2 and argv[2].endswith("scan-image.py"))
        for index, argv in enumerate(fixture.calls):
            if argv[:2] == ["docker", "create"]:
                self.assertGreater(index, scan_index)
                self.assertIn(IMAGE, argv)
                self.assertNotIn("--privileged", argv)
                self.assertFalse(any("unconfined" in value for value in argv))
        self.assertFalse(fixture.containers)
        self.assertFalse((output / "private-fixture-data").exists())
        runner = next(argv for argv in fixture.calls if argv[:2] == ["docker", "create"] and "10001:10001" in argv)
        self.assertIn("--check-runtimes", runner)
        self.assertNotIn("--env-file", runner)
        self.assertFalse(any(value.startswith("--env") for value in runner))
        mounts = [runner[index + 1] for index, value in enumerate(runner) if value == "--mount"]
        self.assertEqual(len(mounts), 2)
        self.assertTrue(any("dst=/run/secrets/production-plan-fixture,readonly" in value for value in mounts))
        self.assertTrue((output / "report.json").is_file())

    def test_scan_failure_prevents_all_containers(self):
        fixture = DockerFixture(scan_pass=False)
        report, _ = self.invoke(fixture)
        self.assertEqual(report["outcome"], "FAIL")
        self.assertFalse(any(argv[:2] == ["docker", "create"] for argv in fixture.calls))

    def test_create_timeout_still_removes_any_created_container(self):
        for role in ("helper", "runner"):
            with self.subTest(role=role):
                fixture = DockerFixture(timeout_role=role)
                report, _ = self.invoke(fixture)
                self.assertEqual(report["outcome"], "FAIL")
                self.assertFalse(fixture.containers)
                self.assertTrue(any(argv[:3] == ["docker", "rm", "--force"] for argv in fixture.calls))

    def test_prestart_requested_mounts_are_verified_when_actual_mounts_are_empty(self):
        fixture = DockerFixture(empty_created_mounts=True)
        report, _ = self.invoke(fixture)
        self.assertEqual(report["outcome"], "PASS")
        self.assertEqual(len(report["audit_access"]), 2)
        self.assertTrue(all(item["status"] == "SKIP" for item in report["audit_access"]))

    def test_helper_capability_drift_prevents_its_start(self):
        fixture = DockerFixture(helper_drift=("cap_add", ["SYS_ADMIN"]))
        report, _ = self.invoke(fixture)
        self.assertEqual(report["outcome"], "FAIL")
        self.assertFalse(any(argv[:2] == ["docker", "start"] for argv in fixture.calls))
        self.assertFalse(fixture.containers)

    def test_compose_privilege_drift_fails_before_storage(self):
        fixture = DockerFixture()
        fixture.source["services"]["runner"]["cap_add"] = ["SYS_ADMIN"]
        report, _ = self.invoke(fixture)
        self.assertEqual(report["outcome"], "FAIL")
        self.assertFalse(any(argv[:2] == ["docker", "create"] for argv in fixture.calls))

    def test_actual_runner_privilege_drift_prevents_start_and_cleans(self):
        for field, value in (("cap_add", ["SYS_ADMIN"]), ("read_only", False), ("network", "host"),
                             ("user", "0:0"), ("pids_limit", 0)):
            with self.subTest(field=field):
                fixture = DockerFixture(drift=(field, value))
                report, _ = self.invoke(fixture)
                self.assertEqual(report["outcome"], "FAIL")
                self.assertFalse(any(argv[:2] == ["docker", "start"] and "-storage" not in argv[-1] for argv in fixture.calls))
                self.assertFalse(fixture.containers)

    def test_exit_zero_with_inner_failure_is_not_success(self):
        inner = inner_report()
        inner["tests"][0]["status"] = "FAIL"
        report, _ = self.invoke(DockerFixture(report=inner))
        self.assertEqual(report["outcome"], "FAIL")
        self.assertIn("inner_check_not_pass", report["inner_validation_errors"])

    def test_missing_artifacts_do_not_pass(self):
        for missing in ("report.json", "summary.md", "plan.json", "lifecycle.json"):
            with self.subTest(missing=missing):
                report, _ = self.invoke(DockerFixture(omit={missing}))
                self.assertEqual(report["outcome"], "FAIL")

    def test_missing_checks_lifecycles_or_runtime_details_do_not_pass(self):
        files = ["report.json", "summary.md", "plan.json", "lifecycle.json"]
        for mutate in (lambda report: report.update(tests=[]),
                       lambda report: report["tests"].pop(),
                       lambda report: report["lifecycles"].pop(),
                       lambda report: report["lifecycles"][0].update(state_removed=False),
                       lambda report: report["runtime_checks"].pop("codex")):
            inner = inner_report()
            mutate(inner)
            self.assertTrue(controller.validate_inner(inner, files))

    def test_complete_logs_are_redacted_before_chunking(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = controller.Controller(Path(directory))
            raw = "EARLY\n" + "a" * 20000 + " API_KEY=canary-value " + "hf_" + "z" * 30 + "\nTAIL"
            instance.capture("fixture", result(stdout=raw))
            paths = instance.report["logs"][0]["files"]
            captured = "".join((Path(directory) / name).read_text() for name in paths)
            self.assertEqual(captured, controller.diag.redact(raw, limit=None))
            self.assertNotIn("canary-value", captured)
            self.assertNotIn("hf_" + "z" * 30, captured)
            self.assertTrue(captured.startswith("EARLY"))
            self.assertTrue(captured.endswith("TAIL"))
            self.assertTrue(all((Path(directory) / name).stat().st_size <= controller.CAPTURE_BYTES for name in paths))

    def test_preexisting_fixture_is_never_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            instance = controller.Controller(output)
            fixture = output / "private-fixture-data"
            fixture.mkdir()
            marker = fixture / "preserve"
            marker.write_text("owned by another invocation")
            instance.cleanup_fixture()
            self.assertTrue(marker.is_file())

    def test_mount_validation_rejects_unlisted_sources_and_destinations(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            expected = {"/var/lib/camact": (source, True)}
            actual = [{"Type": "bind", "Source": str(source), "Destination": "/var/lib/camact", "RW": True}]
            self.assertTrue(controller.mount_matches(actual, expected))
            actual.append({"Type": "bind", "Source": "/", "Destination": "/host", "RW": True})
            self.assertFalse(controller.mount_matches(actual, expected))


if __name__ == "__main__":
    unittest.main()
