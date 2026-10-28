"""Offline failure-closed contracts for the synthetic production-plan probe."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("production_plan_probe", ROOT / "scripts/diagnostic/production-plan-probe.py")
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class ProductionPlanProbeTests(unittest.TestCase):
    def report(self):
        return {"tests": [], "logs": {}}

    def test_missing_and_skipped_evidence_never_pass(self):
        report = self.report()
        self.assertEqual(probe.outcome(report), "INCOMPLETE")
        report["tests"] = [dict(test=name, status="PASS") for name in probe.REQUIRED]
        self.assertEqual(probe.outcome(report), "PASS")
        report["tests"].append(dict(test="extra_runtime_check", status="SKIP"))
        self.assertEqual(probe.outcome(report), "INCOMPLETE")
        report["tests"].append(dict(test="boundary_violation", status="FAIL"))
        self.assertEqual(probe.outcome(report), "FAIL")

    def test_outer_policy_rejects_uid_capability_filter_and_apparmor_drift(self):
        valid = dict(uid=10001, gid=10001, process_status=dict(NoNewPrivs="1", Seccomp="2", CapEff="0", CapBnd="0"),
                     apparmor_current=dict(value=probe.APPARMOR))
        with mock.patch.object(probe.platform, "system", return_value="Linux"), \
                mock.patch.object(probe.platform, "machine", return_value="x86_64"):
            self.assertTrue(probe.outer_policy(valid))
            changes = [dict(uid=0), dict(gid=0), dict(apparmor_current=dict(value="unconfined"))]
            for field in ("NoNewPrivs", "Seccomp", "CapEff", "CapBnd"):
                changed = copy.deepcopy(valid["process_status"])
                changed[field] = "1" if field.startswith("Cap") else "0"
                changes.append(dict(process_status=changed))
            for change in changes:
                with self.subTest(change=change):
                    self.assertFalse(probe.outer_policy({**valid, **change}))

    def test_outer_gate_stops_before_reading_secret_or_building_runtime(self):
        with mock.patch.object(probe.DIAG, "environment", return_value={}), \
                mock.patch.object(probe.DIAG, "mount_state", return_value={"status": "SKIP"}), \
                mock.patch.object(Path, "read_text", side_effect=AssertionError("No fixture reads before outer policy")):
            report = probe.run(Path("/var/lib/camact/scratch/production-plan-probe-report"), check_runtimes=True)
        self.assertEqual(report["schema"], "camact.gvisor.production-plan.v1")
        self.assertEqual(report["outcome"], "FAIL")
        self.assertEqual([item["test"] for item in report["tests"]], ["outer_policy"])

    def test_guest_evidence_requires_every_unique_boundary_check(self):
        rows = [dict(test=name, status="PASS") for name in probe.GUEST_CHECKS]
        for changed in (rows[:-1], rows + rows[:1], rows + [dict(test="invented", status="PASS")]):
            report = self.report()
            probe.guest_evidence(report, json.dumps(dict(schema="camact.production_plan.guest.v1", checks=changed)))
            self.assertEqual(report["tests"], [dict(test="guest_evidence", status="FAIL")])
        report = self.report()
        probe.guest_evidence(report, "not JSON")
        self.assertEqual(report["tests"][0]["status"], "FAIL")

    def test_lifecycle_requires_real_core_cleanup_and_credential_evidence(self):
        lifecycle = dict(backend="gvisor", network="none", state=str(probe.STATE / "run-synthetic-offline-proof"),
                         returncode=0, cleanup_returncode=0, state_removed=True, parent_disconnected=False,
                         host_proc_bound=False, guest_environment_keys=["PATH", "HOME"])
        self.assertTrue(probe.lifecycle_valid(lifecycle))
        for change in (dict(cleanup_returncode=1), dict(state_removed=False), dict(parent_disconnected=True),
                       dict(host_proc_bound=True), dict(state="/root/run-disallowed"), dict(network="host"),
                       dict(guest_environment_keys=["AGENT_API_KEY"])):
            with self.subTest(change=change):
                self.assertFalse(probe.lifecycle_valid({**lifecycle, **change}))
        missing = dict(lifecycle)
        missing.pop("guest_environment_keys")
        self.assertFalse(probe.lifecycle_valid(missing))
        cli = {**lifecycle, "state": str(probe.SCRATCH / "camact-sandbox-check-synthetic/gvisor-state/run-synthetic")}
        self.assertTrue(probe.lifecycle_valid(cli, cli=True))
        self.assertFalse(probe.lifecycle_valid(cli))
        self.assertFalse(probe.lifecycle_valid(lifecycle, cli=True))
        for path in (probe.SCRATCH / "arbitrary/gvisor-state/run-synthetic",
                     probe.SCRATCH / "nested/camact-sandbox-check-synthetic/gvisor-state/run-synthetic",
                     probe.SCRATCH / "camact-sandbox-check-synthetic/arbitrary/run-synthetic"):
            with self.subTest(path=path):
                self.assertFalse(probe.lifecycle_valid({**lifecycle, "state": str(path)}, cli=True))
                self.assertFalse(probe.lifecycle_valid({**lifecycle, "state": str(path)}))

    def test_plan_rejects_readwrite_album_wrong_alias_and_unlisted_bind(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace, home, transport, node = (root / name for name in ("workspace", "home", "transport", "node"))
            expected = {"/tmp": (workspace, False), "/home/agent": (home, False),
                        "/tmp/album": (workspace / "album", True), "/tmp/context": (workspace / "context", True),
                        "/tmp/.camact": (workspace / ".camact", True), probe.MEMORY: (workspace / "album", True),
                        "/transport": (transport, True), "/opt/node": (node, True),
                        "/opt/camact/runtime/0": (ROOT / ".tools/node", True)}
            plan = dict(schema="camact.gvisor.launch.v1", state_parent=str(probe.STATE), argv=[str(Path(sys.executable).resolve())],
                        mounts=[dict(type="bind", source=str(source.resolve()), destination=destination,
                                     options=["rbind", "nosuid", "nodev", "ro" if readonly else "rw"])
                                for destination, (source, readonly) in expected.items()])
            self.assertTrue(probe.plan_valid(plan, workspace, home, transport, node))
            changed = copy.deepcopy(plan)
            next(item for item in changed["mounts"] if item["destination"] == "/tmp/album")["options"][-1] = "rw"
            self.assertFalse(probe.plan_valid(changed, workspace, home, transport, node))
            changed = copy.deepcopy(plan)
            next(item for item in changed["mounts"] if item["destination"] == probe.MEMORY)["source"] = "/other-user/base_memory"
            self.assertFalse(probe.plan_valid(changed, workspace, home, transport, node))
            changed = copy.deepcopy(plan)
            changed["mounts"].append(dict(type="bind", source="/run/secrets", destination="/run/secrets", options=["ro"]))
            self.assertFalse(probe.plan_valid(changed, workspace, home, transport, node))

    def test_path_boundary_rejects_parent_escape_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "link").symlink_to(root, target_is_directory=True)
            probe.no_symlinks(root / "fresh-child", root)
            for path in (root, root.parent / "outside", root / "link/child", root / "../outside"):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    probe.no_symlinks(path, root)

    def test_capture_is_sanitized_before_chunking_and_combined_budget_is_bounded(self):
        token = "hf_" + "p" * 32
        report = self.report()
        with mock.patch.object(probe, "MAX_CAPTURE", 80):
            probe.capture(report, "stdout", "early-error " + token + " " + "a" * 50)
            probe.capture(report, "stderr", "b" * 100)
        self.assertNotIn(token, json.dumps(report))
        self.assertIn("early-error", report["logs"]["stdout"]["chunks"][0])
        self.assertLessEqual(sum(value["captured_bytes"] for value in report["logs"].values()), 80)
        self.assertTrue(report["logs"]["stderr"]["truncated"])


if __name__ == "__main__":
    unittest.main()
