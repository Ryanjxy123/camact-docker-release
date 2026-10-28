"""Fail-closed host orchestration without invoking Docker or a model."""
from __future__ import annotations

import importlib.util
import hashlib
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


def native_evidence(harness, mode, output):
    requests = 6
    simulator = 3 if mode == "multi_turn" else 0
    evaluation = {"user_id": "fixture_user", "task_id": "fixture_user_OFFLINE", "strict_success": True,
                  "agent_failure": False, "infrastructure_failure": False}
    result = {"schema_version": "camact.standard_evaluation_result.v1", "evaluations": [evaluation],
              "summary": {"total_tasks": 1, "evaluated_tasks": 1, "strict_success_count": 1,
                          "agent_failure_count": 0, "infrastructure_failure_count": 0}}
    ledger = "run/token_usage/requests.jsonl"
    row = {"fixture_only": True, "real_model_calls": 0, "canonical_tasks_run": 0, "harness": harness, "mode": mode,
           "passed": True, "listener_closed": True, "script_completed": True, "prompt_injected": True,
           "visual_status": "visual_verified", "agent_requests": requests, "simulator_requests": simulator,
           "token_request_ledgers": [ledger], "evaluation": evaluation,
           **{field: {key: True for key in keys} for field, keys in controller.NATIVE_ASSERTIONS.items()}}
    parent = output.rsplit("/", 1)[0] + "/gvisor-state"
    state = {**lifecycle(), "backend": "gvisor", "platform": "systrap", "network": "none", "host_proc_bound": False,
             "state": parent + "/run-fixture", "parent_disconnected": False, "guest_environment_keys": ["HOME", "PATH"]}
    summary = {"schema_version": "camact.token_accounting.v3", "views": {"all_attempts": {harness: {
        "http_attempt_count": requests, "capture_complete": True, "usage_coverage": 1.0,
        "unknown_or_unreliable_usage_requests": 0,
        "exact_tokens": {"input_tokens": 10 * requests, "output_tokens": 5 * requests, "total_tokens": 15 * requests}}}},
        "all_roles_all_attempts": {"http_attempt_count": requests + simulator, "capture_complete": True,
                                   "exact_tokens": {"total_tokens": 15 * (requests + simulator)}},
        "formal_results": {harness: {"scored_tasks": 1, "strict_success_count": 1}}}
    artifact = {"schema_version": "camact.standard_run_artifact.v1", "trajectory_class": "finished",
                "visual_evidence": {"status": "visual_verified"}}
    values = {"validation.json": row, "run/result.json": result,
            "run/runs/standard_run_artifacts.jsonl": [artifact],
            "run/token_usage/accounting_v3/summary.json": summary,
            ledger: [{"fixture_only": True, "run_id": output + "/run", "harness_id": harness}],
            "run/runs/execution/sandbox-launches/fixture/plan.json": {
                "schema": "camact.gvisor.launch.v1", "state_parent": parent,
                "metadata": output + "/run/runs/execution/sandbox-launches/fixture",
                "mounts": [{"type": "bind", "source": output + "/run/runs/execution/workspace", "destination": "/tmp"}],
                "environment": {"HOME": "/home/agent"}},
            "run/runs/execution/sandbox-launches/fixture/lifecycle.json": state,
            "run/runs/execution/native_turns/turn_001/turn.json": {"returncode": 0, "timed_out": False,
                "decision": {"action": "finish", "reason": "completed"}}}
    if harness == "claude":
        values.pop("run/runs/execution/native_turns/turn_001/turn.json")
        values["run/runs/execution/session_attempts/fixture_user/task_fixture/attempt_01/native_conversation.json"] = {
            "invocations": [{"returncode": 0, "timed_out": False, "controlled_stop": False}],
            "simulator_continuations": []}
    return values


def evidence_bytes(name, value):
    return (("".join(json.dumps(row) + "\n" for row in value) if name.endswith(".jsonl") else json.dumps(value))
            .encode("utf-8"))


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
        self.native_mutation = None
        self.native_drift = None
        self.native_payloads = {}
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
            self.containers[name] = {"image": IMAGE, "user": user, "cap_drop": ["ALL"],
                "cap_add": [cap if cap.startswith("CAP_") else "CAP_" + cap for cap in caps],
                "read_only": True, "privileged": False, "pids_limit": 4096 if user == "10001:10001" else None,
                "apparmor": "", "security_opt": security, "network": "none", "tmpfs": tmpfs,
                "mounts": mounts, "requested_mounts": [
                    {"Type": item["Type"], "Source": item["Source"], "Target": item["Destination"], "ReadOnly": not item["RW"]}
                    for item in mounts], "state": {"Status": "created", "ExitCode": 0}}
            if controller.NATIVE_WRAPPER in argv:
                harness, mode, output = argv[-3:]
                key = harness + "-" + mode
                self.containers[name].update(native_key=key, case_output=output)
                values = native_evidence(harness, mode, output)
                if self.native_mutation:
                    self.native_mutation(harness, mode, values)
                self.native_payloads[key] = values
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
            if self.native_drift and actual.get("native_key") == self.native_drift[0]:
                actual[self.native_drift[1]] = self.native_drift[2]
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
            container, _, path = argv[-2].partition(":")
            actual = self.containers[container]
            if actual.get("native_key"):
                values = self.native_payloads[actual["native_key"]]
                relative = path.removeprefix(actual["case_output"] + "/")
                if relative == "native-artifact-index.json":
                    index = {"schema": controller.NATIVE_INDEX_SCHEMA, "outer_policy": True, "script_returncode": 0,
                             "errors": [], "files": [{"path": name, "bytes": len(evidence_bytes(name, value)),
                                 "sha256": hashlib.sha256(evidence_bytes(name, value)).hexdigest()} for name, value in values.items()]}
                    destination.write_text(json.dumps(index), encoding="utf-8")
                elif relative in values:
                    destination.write_bytes(evidence_bytes(relative, values[relative]))
                else:
                    return result(1)
                return result()
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
    def invoke(self, fixture, manifest=None, *, native_matrix=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "production-plan"
        manifest_path = None
        if manifest is not None:
            manifest_path = Path(temporary.name) / "reuse-manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with mock.patch.object(controller.diag, "command", side_effect=fixture):
            report = controller.Controller(output, native_matrix=native_matrix).run(
                "camact:gvisor-diagnostic", reused_image_manifest=manifest_path)
        return report, output

    def test_native_matrix_collects_all_fifteen_independent_hardened_runners(self):
        fixture = DockerFixture()
        report, output = self.invoke(fixture, native_matrix=True)
        self.assertEqual(report["outcome"], "PASS")
        self.assertEqual({(item["harness"], item["mode"]) for item in report["native_matrix"]}, set(controller.NATIVE_CASES))
        self.assertTrue(all(item["outcome"] == "PASS" for item in report["native_matrix"]))
        creates = [argv for argv in fixture.calls if argv[:2] == ["docker", "create"] and controller.NATIVE_WRAPPER in argv]
        self.assertEqual(len(creates), 15)
        self.assertEqual(len({argv[argv.index("--name") + 1] for argv in creates}), 15)
        for argv in creates:
            self.assertIn(IMAGE, argv)
            self.assertIn("--network=none", argv)
            self.assertIn("--cap-drop=ALL", argv)
            self.assertIn("--read-only", argv)
            self.assertIn("--security-opt=no-new-privileges:true", argv)
            self.assertIn("--security-opt=apparmor=" + controller.PROFILE, argv)
            self.assertRegex(argv[-1], r"^/var/lib/camact/scratch/docker-gates-[0-9a-f]{32}/[a-z]+-(?:single_turn|multi_turn|users_history)$")
            if argv[-3] == "openclaw":
                self.assertIn("CAMACT_OPENCLAW_TMPDIR=/run/camact/openclaw", argv)
            else:
                self.assertNotIn("--env", argv)
        self.assertEqual(len(list((output / "native-artifacts").glob("*/validation.json"))), 15)
        self.assertFalse(fixture.containers)
        self.assertFalse((output / "private-fixture-data").exists())

    def test_native_case_failure_does_not_skip_remaining_cases_or_erase_lifecycle_values(self):
        fixture = DockerFixture()
        def mutate(harness, mode, values):
            if (harness, mode) == controller.NATIVE_CASES[0]:
                values["validation.json"]["passed"] = False
                for name, item in values.items():
                    if name.endswith("/lifecycle.json"):
                        item.update(returncode=27, cleanup_returncode=19, state_removed=False, parent_disconnected=True)
        fixture.native_mutation = mutate
        report, _ = self.invoke(fixture, native_matrix=True)
        self.assertEqual(report["outcome"], "FAIL")
        self.assertEqual(len(fixture.native_payloads), 15)
        self.assertEqual([item["outcome"] for item in report["native_matrix"]].count("PASS"), 14)
        observed = next(iter(report["native_matrix"][0]["lifecycles"].values()))
        self.assertEqual(observed["returncode"], 27)
        self.assertEqual(observed["cleanup_returncode"], 19)
        self.assertIs(observed["state_removed"], False)
        self.assertIs(observed["parent_disconnected"], True)
        self.assertFalse(fixture.containers)

    def test_native_missing_evidence_does_not_pass_even_with_successful_exit(self):
        fixture = DockerFixture()
        def mutate(harness, mode, values):
            if (harness, mode) == controller.NATIVE_CASES[0]:
                del values["run/token_usage/accounting_v3/summary.json"]
        fixture.native_mutation = mutate
        report, _ = self.invoke(fixture, native_matrix=True)
        self.assertEqual(report["outcome"], "FAIL")
        self.assertEqual(len(fixture.native_payloads), 15)
        self.assertIn("accounting_evidence", report["native_matrix"][0]["validation_errors"])

    def test_native_prerequisite_failure_records_fifteen_real_skips_without_starting_them(self):
        inner = inner_report()
        inner["tests"][0]["status"] = "FAIL"
        fixture = DockerFixture(report=inner)
        report, _ = self.invoke(fixture, native_matrix=True)
        self.assertEqual(report["outcome"], "FAIL")
        self.assertEqual(len(report["native_matrix"]), 15)
        self.assertTrue(all(item["outcome"] == "SKIP" for item in report["native_matrix"]))
        self.assertFalse(fixture.native_payloads)

    def test_native_permission_drift_prevents_start_cleans_and_continues(self):
        fixture = DockerFixture()
        key = "-".join(controller.NATIVE_CASES[0])
        fixture.native_drift = (key, "cap_add", ["SYS_ADMIN"])
        report, _ = self.invoke(fixture, native_matrix=True)
        self.assertEqual(report["outcome"], "FAIL")
        self.assertEqual(len(fixture.native_payloads), 15)
        bad = next(argv[argv.index("--name") + 1] for argv in fixture.calls
                   if argv[:2] == ["docker", "create"] and controller.NATIVE_WRAPPER in argv and argv[-3:-1] == list(controller.NATIVE_CASES[0]))
        self.assertFalse(any(argv[:2] == ["docker", "start"] and argv[-1] == bad for argv in fixture.calls))
        self.assertTrue(any(argv[:3] == ["docker", "rm", "--force"] and argv[-1] == bad for argv in fixture.calls))
        self.assertFalse(fixture.containers)

    def test_native_validation_rejects_report_contract_and_evidence_mismatches(self):
        output = "/var/lib/camact/scratch/docker-gates-fixture/codex-single_turn"
        mutations = (
            lambda values: values["validation.json"].update(real_model_calls=1),
            lambda values: values["validation.json"].update(listener_closed=False),
            lambda values: values["validation.json"]["native_tool_assertions"].clear(),
            lambda values: values["run/token_usage/accounting_v3/summary.json"]["all_roles_all_attempts"].update(http_attempt_count=999),
            lambda values: values["run/runs/standard_run_artifacts.jsonl"][0].update(trajectory_class="infrastructure_failure"),
            lambda values: values.pop("run/runs/execution/sandbox-launches/fixture/plan.json"),
            lambda values: values.pop("run/runs/execution/native_turns/turn_001/turn.json"),
            lambda values: values["run/runs/execution/sandbox-launches/fixture/lifecycle.json"].update(guest_environment_keys=["HF_TOKEN"]),
        )
        for number, mutate in enumerate(mutations):
            with self.subTest(mutation=number):
                values = native_evidence("codex", "single_turn", output)
                mutate(values)
                self.assertTrue(controller.validate_native(values, "codex", "single_turn", output))

    def test_native_controlled_stop_preserves_actual_nonzero_exit_without_reclassifying_core(self):
        output = "/var/lib/camact/scratch/docker-gates-fixture/opencode-multi_turn"
        values = native_evidence("opencode", "multi_turn", output)
        values["run/runs/execution/sandbox-launches/fixture/lifecycle.json"].update(returncode=-15, parent_disconnected=True)
        values["run/runs/execution/native_turns/turn_001/turn.json"].update(returncode=-15,
            simulator_stopped=True, decision={"action": "finish", "reason": "simulator_stop"})
        self.assertEqual(controller.validate_native(values, "opencode", "multi_turn", output), [])
        self.assertEqual(values["run/runs/execution/sandbox-launches/fixture/lifecycle.json"]["returncode"], -15)

    def test_native_formal_failure_flags_must_be_explicit_false(self):
        output = "/var/lib/camact/scratch/docker-gates-fixture/codex-single_turn"
        for field in ("agent_failure", "infrastructure_failure"):
            for missing in (False, True):
                with self.subTest(field=field, missing=missing):
                    values = native_evidence("codex", "single_turn", output)
                    evaluation = values["run/result.json"]["evaluations"][0]
                    if missing:
                        del evaluation[field]
                    else:
                        evaluation[field] = None
                    self.assertIn("formal_evaluation", controller.validate_native(values, "codex", "single_turn", output))

    def test_native_rejected_symbolic_link_index_is_removed_before_upload(self):
        fixture = DockerFixture()
        original = Path.is_symlink
        def linked(path):
            return (path.name == "native-artifact-index.json" and path.parent.name == "claude-single_turn") or original(path)
        with mock.patch.object(Path, "is_symlink", linked):
            report, output = self.invoke(fixture, native_matrix=True)
        self.assertEqual(report["outcome"], "FAIL")
        self.assertEqual(len(fixture.native_payloads), 15)
        self.assertFalse((output / "native-artifacts/claude-single_turn/native-artifact-index.json").exists())
        self.assertTrue((output / "native-artifacts/codex-single_turn/native-artifact-index.json").is_file())
        self.assertFalse(fixture.containers)

    def test_native_whitelist_rejects_data_payloads_and_path_traversal(self):
        for name in ("../validation.json", "/etc/passwd", "run/../validation.json", "fixture-upstream.json",
                     "synthetic-benchmark/tasks/fixture_user/task_fixture/task.yaml", "run/workspace/.env", "run/raw.json"):
            self.assertFalse(controller.native_artifact_allowed(name), name)

    def test_native_cross_case_evidence_is_rejected_despite_shared_state_parent(self):
        parent = "/var/lib/camact/scratch/docker-gates-fixture/"
        source = native_evidence("codex", "single_turn", parent + "codex-single_turn")
        target_output = parent + "codex-users_history"
        target = native_evidence("codex", "users_history", target_output)
        for name, value in source.items():
            if "/sandbox-launches/" in name or name.endswith("/turn.json") or name.endswith("standard_run_artifacts.jsonl"):
                target[name] = value
        errors = controller.validate_native(target, "codex", "users_history", target_output)
        self.assertTrue(any(error.startswith("launch_plan:") for error in errors))
        target = native_evidence("codex", "users_history", target_output)
        target["run/runs/execution/sandbox-launches/fixture/plan.json"]["mounts"][0]["source"] = parent + "codex-single_turn/run/runs/execution/workspace"
        self.assertTrue(any(error.startswith("workspace_case_identity:") for error in controller.validate_native(
            target, "codex", "users_history", target_output)))
        target = native_evidence("codex", "users_history", target_output)
        target["run/token_usage/requests.jsonl"] = source["run/token_usage/requests.jsonl"]
        self.assertIn("token_ledger_case_identity", controller.validate_native(target, "codex", "users_history", target_output))

    def test_helper_capabilities_accept_only_prefix_equivalence(self):
        for caps in (["CHOWN", "DAC_OVERRIDE", "FOWNER"], ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER"]):
            with self.subTest(caps=caps):
                fixture = DockerFixture(helper_drift=("cap_add", caps))
                report, _ = self.invoke(fixture)
                self.assertEqual(report["outcome"], "PASS")
        for caps in (["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SYS_ADMIN"],
                     ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CHOWN"],
                     ["CAP_CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER"],
                     ["cap_chown", "CAP_DAC_OVERRIDE", "CAP_FOWNER"],
                     [" CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER"],
                     [None, "CAP_DAC_OVERRIDE", "CAP_FOWNER"]):
            with self.subTest(caps=caps):
                fixture = DockerFixture(helper_drift=("cap_add", caps))
                report, _ = self.invoke(fixture)
                self.assertEqual(report["outcome"], "FAIL")
                self.assertFalse(any(argv[:2] == ["docker", "start"] for argv in fixture.calls))
                self.assertFalse(fixture.containers)

    def test_native_wrapper_runs_only_original_script_and_inventories_whitelisted_bounded_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "case"
            original_read = Path.read_text
            def read(path, *args, **kwargs):
                if str(path).replace("\\", "/") == "/proc/self/status":
                    return "CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n"
                if str(path).replace("\\", "/") == "/proc/self/attr/current":
                    return controller.PROFILE + " (enforce)"
                return original_read(path, *args, **kwargs)
            def run(argv):
                self.assertEqual(argv[1:4], ["-B", "/opt/camact/scripts/native-loop-smoke.py", "--harness"])
                self.assertEqual(argv[-3:], ["single_turn", "--output", str(output)])
                output.mkdir()
                for name, value in native_evidence("codex", "single_turn", str(output)).items():
                    path = output.joinpath(*name.split("/"))
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(evidence_bytes(name, value))
                (output / "fixture-upstream.json").write_text("not collected")
                return mock.Mock(returncode=0)
            with mock.patch("os.getuid", return_value=10001, create=True), \
                    mock.patch("os.getgid", return_value=10001, create=True), \
                    mock.patch.object(Path, "read_text", read), mock.patch("subprocess.run", side_effect=run), \
                    mock.patch("sys.argv", ["-c", "codex", "single_turn", str(output)]):
                with self.assertRaises(SystemExit) as stopped:
                    exec(compile(controller.NATIVE_WRAPPER, "<native-wrapper>", "exec"), {})
            self.assertEqual(stopped.exception.code, 0)
            index = json.loads((output / "native-artifact-index.json").read_text())
            self.assertIs(index["outer_policy"], True)
            self.assertEqual(index["errors"], [])
            self.assertTrue(index["files"])
            self.assertTrue(all(controller.native_artifact_allowed(item["path"]) for item in index["files"]))
            self.assertNotIn("fixture-upstream.json", {item["path"] for item in index["files"]})

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
