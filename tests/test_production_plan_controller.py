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
SOURCE_REVISION = "c" * 40
BASE_TREE = {
    "harness/camact_multi_harness_v1/camact_multi/gvisor.py": ("100644", "blob", "1" * 40),
    "scripts/diagnostic/production-plan-probe.py": ("100644", "blob", "2" * 40),
    "locks/runtimes.json": ("100644", "blob", "3" * 40),
    "scripts/scan-image.py": ("100644", "blob", "4" * 40),
    "compose.yaml": ("100644", "blob", "5" * 40),
    **{path: ("100644", "blob", "6" * 40) for path in controller.REUSE_SAFE_FILES},
}


def tree_text(tree):
    return "".join(" ".join(tree[path]) + "\t" + path + "\n" for path in sorted(tree))


def reused_manifest(fixture):
    with mock.patch.object(controller.diag, "command", side_effect=fixture):
        digest = controller.critical_source_digest(SOURCE_REVISION)
    return {"schema": controller.IMAGE_MANIFEST_SCHEMA, "image_id": IMAGE,
            "source_revision": SOURCE_REVISION, "version": controller.VERSION,
            "critical_source_digest": digest, "image_archive_sha256": "e" * 64}


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
                 empty_created_mounts=False, timeout_role=None, image_revision=REVISION):
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
        self.image_revision = image_revision
        self.image_version = controller.VERSION
        self.image_id = IMAGE
        self.dirty_paths = set()
        self.trees = {REVISION: dict(BASE_TREE), SOURCE_REVISION: dict(BASE_TREE)}

    def __call__(self, argv, timeout=20):
        argv = [str(value) for value in argv]
        self.calls.append(argv)
        if argv[0] == "git":
            if "cat-file" in argv:
                return result(stdout="commit") if argv[-1] in self.trees else result(1)
            if "ls-tree" in argv:
                return result(stdout=tree_text(self.trees[argv[-1]])) if argv[-1] in self.trees else result(1)
            if "diff" in argv:
                expected = ["git", "-C", str(controller.ROOT), "diff", "--quiet", REVISION, "--", ".",
                            *(":(top,literal,exclude)" + path for path in sorted(controller.REUSE_SAFE_FILES))]
                if argv != expected:
                    raise AssertionError("Critical source cleanliness must include staged and unstaged changes with exact exclusions")
                return result(1 if self.dirty_paths - controller.REUSE_SAFE_FILES else 0)
            return result(stdout=REVISION)
        if argv[0] == "sudo":
            return result(1, stderr="Audit unavailable in the unit fixture")
        if len(argv) > 2 and argv[2].endswith("scan-image.py"):
            self.scan_seen = True
            return result(stdout=json.dumps({"result": "PASS" if self.scan_pass else "FAIL",
                "issue_count": 0 if self.scan_pass else 1, "issues": [] if self.scan_pass else [{}],
                "candidate_values_printed": False}))
        if argv[:3] == ["docker", "image", "inspect"]:
            return result(stdout=json.dumps({"id": self.image_id, "version": self.image_version,
                "revision": self.image_revision, "os": "linux", "architecture": "amd64"}))
        if argv[:2] == ["docker", "compose"]:
            if "--profile" not in argv or argv[argv.index("--profile") + 1] != "tools":
                return result(stdout=json.dumps({"services": {"runner": self.source["services"]["runner"]}}))
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


class SourceDigestTests(unittest.TestCase):
    def digest(self, fixture, revision=REVISION):
        with mock.patch.object(controller.diag, "command", side_effect=fixture):
            return controller.critical_source_digest(revision)

    def test_only_the_four_reviewed_host_files_are_excluded(self):
        self.assertEqual(controller.REUSE_SAFE_FILES, {
            ".github/workflows/diagnose-gvisor.yml",
            "scripts/diagnostic/camact-gvisor-diagnostic-v1.profile",
            "scripts/diagnostic/production-plan-controller.py",
            "tests/test_production_plan_controller.py",
        })
        fixture = DockerFixture()
        before = self.digest(fixture)
        for path in controller.REUSE_SAFE_FILES:
            fixture.trees[REVISION][path] = ("100755", "blob", "d" * 40)
        self.assertEqual(self.digest(fixture), before)

    def test_core_probe_lock_and_every_other_critical_blob_change_the_digest(self):
        for path in BASE_TREE.keys() - controller.REUSE_SAFE_FILES:
            with self.subTest(path=path):
                fixture = DockerFixture()
                before = self.digest(fixture)
                fixture.trees[REVISION][path] = ("100644", "blob", "d" * 40)
                self.assertNotEqual(self.digest(fixture), before)

    def test_mode_type_path_additions_and_deletions_are_critical(self):
        path = "scripts/diagnostic/production-plan-probe.py"
        changes = {
            "mode": lambda tree: tree.update({path: ("100755", "blob", "2" * 40)}),
            "type": lambda tree: tree.update({path: ("160000", "commit", "2" * 40)}),
            "rename": lambda tree: tree.update({path + ".renamed": tree.pop(path)}),
            "add": lambda tree: tree.update({"new-critical-file": ("100644", "blob", "2" * 40)}),
            "delete": lambda tree: tree.pop(path),
        }
        for name, change in changes.items():
            with self.subTest(change=name):
                fixture = DockerFixture()
                before = self.digest(fixture)
                change(fixture.trees[REVISION])
                self.assertNotEqual(self.digest(fixture), before)

    def test_unavailable_commits_and_non_commit_references_are_rejected(self):
        fixture = DockerFixture()
        for revision in ("HEAD", "b" * 7, "B" * 40, "d" * 40):
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                self.digest(fixture, revision)
        self.assertFalse(any("fetch" in argv for argv in fixture.calls))


class ControllerTests(unittest.TestCase):
    def invoke(self, fixture, manifest=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "production-plan"
        manifest_path = None
        if manifest is not None:
            manifest_path = Path(temporary.name) / "reuse-manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with mock.patch.object(controller.diag, "command", side_effect=fixture):
            report = controller.Controller(output).run("camact:gvisor-diagnostic", reused_image_manifest=manifest_path)
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
        exported = json.loads((output / "image-manifest.json").read_text())
        self.assertEqual(exported["source_revision"], REVISION)
        self.assertEqual(exported["image_id"], IMAGE)
        self.assertNotIn("image_archive_sha256", exported)
        self.assertIs(report["image_provenance"]["reused"], False)

    def test_scan_failure_prevents_all_containers(self):
        fixture = DockerFixture(scan_pass=False)
        report, output = self.invoke(fixture)
        self.assertEqual(report["outcome"], "FAIL")
        self.assertFalse(any(argv[:2] == ["docker", "create"] for argv in fixture.calls))
        self.assertFalse((output / "image-manifest.json").exists())

    def test_reuse_requires_the_original_identity_and_a_new_scan_before_containers(self):
        fixture = DockerFixture(image_revision=SOURCE_REVISION)
        report, output = self.invoke(fixture, reused_manifest(fixture))
        self.assertEqual(report["outcome"], "PASS")
        provenance = report["image_provenance"]
        self.assertIs(provenance["reused"], True)
        self.assertEqual(provenance["current_revision"], REVISION)
        self.assertEqual(provenance["source_revision"], SOURCE_REVISION)
        self.assertEqual(provenance["archive_checksum_scope"], "workflow_before_load")
        scan_index = next(index for index, argv in enumerate(fixture.calls)
                          if len(argv) > 2 and argv[2].endswith("scan-image.py"))
        creates = [index for index, argv in enumerate(fixture.calls) if argv[:2] == ["docker", "create"]]
        self.assertTrue(creates)
        self.assertTrue(all(index > scan_index for index in creates))
        exported = json.loads((output / "image-manifest.json").read_text())
        self.assertEqual(exported["source_revision"], SOURCE_REVISION)
        self.assertEqual(exported["critical_source_digest"], provenance["critical_source_digest"])
        self.assertNotIn("image_archive_sha256", exported)

    def test_reuse_allows_host_profile_changes(self):
        fixture = DockerFixture(image_revision=SOURCE_REVISION)
        manifest = reused_manifest(fixture)
        fixture.trees[REVISION]["scripts/diagnostic/camact-gvisor-diagnostic-v1.profile"] = (
            "100644", "blob", "f" * 40)
        report, _ = self.invoke(fixture, manifest)
        self.assertEqual(report["outcome"], "PASS")

    def test_dirty_critical_tracked_sources_fail_before_image_scan(self):
        for path in BASE_TREE.keys() - controller.REUSE_SAFE_FILES:
            for reused in (False, True):
                with self.subTest(path=path, reused=reused):
                    fixture = DockerFixture(image_revision=SOURCE_REVISION if reused else REVISION)
                    fixture.dirty_paths.add(path)
                    manifest = reused_manifest(fixture) if reused else None
                    report, _ = self.invoke(fixture, manifest)
                    self.assertEqual(report["outcome"], "FAIL")
                    self.assertFalse(fixture.scan_seen)
                    self.assertFalse(any(argv[:2] == ["docker", "create"] for argv in fixture.calls))

    def test_dirty_reviewed_host_files_are_allowed_by_exact_pathspec(self):
        fixture = DockerFixture()
        fixture.dirty_paths.update(controller.REUSE_SAFE_FILES)
        report, _ = self.invoke(fixture)
        self.assertEqual(report["outcome"], "PASS")
        checks = [argv for argv in fixture.calls if argv[0] == "git" and "diff" in argv]
        self.assertEqual(len(checks), 1)

    def test_reuse_rejects_each_changed_core_probe_and_lock_before_scan(self):
        for path in BASE_TREE.keys() - controller.REUSE_SAFE_FILES:
            with self.subTest(path=path):
                fixture = DockerFixture(image_revision=SOURCE_REVISION)
                manifest = reused_manifest(fixture)
                fixture.trees[REVISION][path] = ("100644", "blob", "d" * 40)
                report, output = self.invoke(fixture, manifest)
                self.assertEqual(report["outcome"], "FAIL")
                self.assertFalse(fixture.scan_seen)
                self.assertFalse(any(argv[:2] == ["docker", "create"] for argv in fixture.calls))
                self.assertFalse((output / "image-manifest.json").exists())

    def test_reuse_rejects_manifest_identity_version_digest_and_checksum_mismatches(self):
        changes = {
            "schema": "unexpected.schema",
            "image_id": "sha256:" + "d" * 64,
            "source_revision": "d" * 40,
            "version": "0.1.0-rc.2",
            "critical_source_digest": "d" * 64,
            "image_archive_sha256": "invalid",
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                fixture = DockerFixture(image_revision=SOURCE_REVISION)
                manifest = reused_manifest(fixture)
                manifest[field] = value
                report, _ = self.invoke(fixture, manifest)
                self.assertEqual(report["outcome"], "FAIL")
                self.assertFalse(fixture.scan_seen)
                self.assertFalse(any(argv[:2] == ["docker", "create"] for argv in fixture.calls))

    def test_reuse_rejects_missing_manifest_fields_and_invalid_image_identity(self):
        for field in ("schema", "image_id", "source_revision", "version", "critical_source_digest", "image_archive_sha256"):
            with self.subTest(missing=field):
                fixture = DockerFixture(image_revision=SOURCE_REVISION)
                manifest = reused_manifest(fixture)
                del manifest[field]
                report, _ = self.invoke(fixture, manifest)
                self.assertEqual(report["outcome"], "FAIL")
                self.assertFalse(fixture.scan_seen)
        for field, value in (("image_id", "sha256:invalid"), ("image_version", "0.1.0-rc.2"),
                             ("image_revision", "invalid")):
            with self.subTest(identity=field):
                fixture = DockerFixture(image_revision=SOURCE_REVISION)
                manifest = reused_manifest(fixture)
                setattr(fixture, field, value)
                report, _ = self.invoke(fixture, manifest)
                self.assertEqual(report["outcome"], "FAIL")
                self.assertFalse(fixture.scan_seen)
                self.assertFalse(any(argv[:2] == ["docker", "create"] for argv in fixture.calls))

    def test_reuse_requires_the_source_commit_to_be_available_locally(self):
        fixture = DockerFixture(image_revision=SOURCE_REVISION)
        manifest = reused_manifest(fixture)
        del fixture.trees[SOURCE_REVISION]
        report, _ = self.invoke(fixture, manifest)
        self.assertEqual(report["outcome"], "FAIL")
        self.assertFalse(fixture.scan_seen)
        self.assertFalse(any("fetch" in argv for argv in fixture.calls))
        self.assertFalse(any(argv[:2] == ["docker", "create"] for argv in fixture.calls))

    def test_explicit_null_manifest_cannot_fall_back_to_fresh_image_validation(self):
        fixture = DockerFixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "reuse-manifest.json"
            path.write_text("null", encoding="utf-8")
            with mock.patch.object(controller.diag, "command", side_effect=fixture):
                report = controller.Controller(Path(directory) / "production-plan").run(
                    "camact:gvisor-diagnostic", reused_image_manifest=path)
        self.assertEqual(report["outcome"], "FAIL")
        self.assertFalse(fixture.scan_seen)
        self.assertFalse(any(argv[:2] == ["docker", "create"] for argv in fixture.calls))

    def test_old_revision_without_a_reuse_manifest_is_rejected(self):
        fixture = DockerFixture(image_revision=SOURCE_REVISION)
        report, _ = self.invoke(fixture)
        self.assertEqual(report["outcome"], "FAIL")
        self.assertFalse(fixture.scan_seen)
        self.assertFalse(any(argv[:2] == ["docker", "create"] for argv in fixture.calls))

    def test_reuse_scan_failure_still_prevents_all_containers_and_manifest_export(self):
        fixture = DockerFixture(image_revision=SOURCE_REVISION, scan_pass=False)
        report, output = self.invoke(fixture, reused_manifest(fixture))
        self.assertEqual(report["outcome"], "FAIL")
        self.assertTrue(fixture.scan_seen)
        self.assertFalse(any(argv[:2] == ["docker", "create"] for argv in fixture.calls))
        self.assertFalse((output / "image-manifest.json").exists())

    def test_successful_scan_exports_manifest_even_if_runtime_or_compose_later_fails(self):
        inner = inner_report()
        inner["outcome"] = "FAIL"
        for failure in ("inner", "compose"):
            with self.subTest(failure=failure):
                fixture = DockerFixture(report=inner if failure == "inner" else None)
                if failure == "compose":
                    fixture.source["services"].pop("storage-init")
                report, output = self.invoke(fixture)
                self.assertEqual(report["outcome"], "FAIL")
                exported = json.loads((output / "image-manifest.json").read_text())
                self.assertEqual(exported["source_revision"], REVISION)
                self.assertEqual(report["scanned_image_manifest"], "image-manifest.json")

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
