"""Failure attribution, policy parity, cleanup and artifact privacy contracts."""
import contextlib
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("gvisor_diagnostics", PROJECT / "scripts/diagnose-gvisor.py")
diag = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diag)


def result(code=0, stdout="", stderr="", number=None, timeout=False):
    return dict(returncode=code, stdout=stdout, stderr=stderr, errno=number, timed_out=timeout)


class DiagnosticsTests(unittest.TestCase):
    def test_redacts_credentials_paths_urls_and_terminal_controls(self):
        canaries = ["hf_" + "a" * 32, "ghp_" + "b" * 32, "sk-" + "c" * 32,
                    "diagnostic-canary-a", "diagnostic-canary-b", "diagnostic-canary-c"]
        raw = (f'{canaries[0]} {canaries[1]} {canaries[2]} API_KEY="{canaries[3]}" '
               f'"HF_TOKEN": "{canaries[4]}" Authorization: Bearer {canaries[5]} '
               + 'https://' + 'user:pass@' + 'example.invalid/private?q=value '
               + '/home/fixture/work/private \x1b[31mpermission denied\x00')
        sanitized = diag.redact(raw)
        for value in canaries + ["user:pass", "example.invalid", "work/private", "\x1b", "\x00"]:
            self.assertNotIn(value, sanitized)
        self.assertIn("permission denied", sanitized)
        # A container-mounted script has no repository root; '/' must remain usable.
        with mock.patch.object(diag, "ROOT", Path("/")):
            self.assertEqual(diag.redact("mount /tmp failed"), "mount /tmp failed")

    def test_unshare_errno_and_dependent_skips(self):
        out = io.StringIO()
        with mock.patch.object(diag, "syscall", side_effect=PermissionError(errno.EPERM, "Operation not permitted")), contextlib.redirect_stdout(out):
            diag.probe("mount", Path("/unused"), "docker")
        rows = json.loads(out.getvalue())
        self.assertEqual((rows[0]["stage"], rows[0]["status"], rows[0]["errno"]),
                         ("mount.unshare", "FAIL", errno.EPERM))
        self.assertEqual(rows[0]["errno_source"], "syscall")
        self.assertTrue(all(r["status"] == "SKIP" and "mount.unshare" in r["detail"] for r in rows[1:]))

    def test_mount_failure_is_distinct_from_namespace_failure(self):
        def syscall(name, *args):
            if name == "mount":
                raise PermissionError(errno.EACCES, "Permission denied")
        out = io.StringIO()
        with mock.patch.object(diag, "syscall", side_effect=syscall), mock.patch.object(Path, "write_text"), contextlib.redirect_stdout(out):
            diag.probe("mount", Path("/unused"), "docker")
        rows = json.loads(out.getvalue())
        failed = [r for r in rows if r["status"] == "FAIL"]
        self.assertEqual([(r["stage"], r["errno_name"]) for r in failed], [("mount.private", "EACCES")])
        self.assertTrue(all(r["status"] == "PASS" for r in rows[:4]))

    def test_exit_code_does_not_become_errno(self):
        item = diag.command_row("gvisor", "run", result(1, stderr="sandbox setup failed"))
        self.assertEqual(item["status"], "FAIL")
        self.assertIsNone(item["errno"])
        item = diag.command_row("gvisor", "run", result(1, stderr="mount: operation not permitted"))
        self.assertEqual((item["errno"], item["errno_source"]), (errno.EPERM, "stderr_inferred"))

    def test_timeout_and_missing_command_are_failures(self):
        timed = diag.command([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.1)
        self.assertEqual((timed["returncode"], timed["timed_out"]), (124, True))
        self.assertIsNone(timed["errno"])
        missing = diag.command(["/nonexistent-camact-diagnostic-command"])
        self.assertEqual(missing["errno"], errno.ENOENT)
        self.assertEqual(diag.command_row("docker", "create", missing)["status"], "FAIL")

    def test_detached_pipe_holder_cannot_block_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            pidfile = Path(directory) / "child-pid"
            program = ("import os,time,pathlib; pid=os.fork(); "
                       "pathlib.Path(" + repr(str(pidfile)) + ").write_text(str(pid)) if pid else os.setsid(); "
                       "time.sleep(10)")
            started = time.monotonic()
            try:
                timed = diag.command([sys.executable, "-c", program], timeout=0.2)
                self.assertTrue(timed["timed_out"])
                self.assertLess(time.monotonic() - started, 4)
            finally:
                if pidfile.exists():
                    try:
                        os.kill(int(pidfile.read_text()), 9)
                    except ProcessLookupError:
                        pass

    def test_invalid_collector_output_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(diag, "command", return_value=result(stdout="not JSON")):
            rows = diag.namespace_tests("host", directory)
        self.assertTrue(rows)
        self.assertTrue(all(r["status"] == "FAIL" for r in rows if r["test"].endswith(".collector")))

    def test_download_digest_checked_before_extraction_and_sidecars_kept(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:bz2") as archive:
            for name in ("runsc", "runsc-gofer"):
                member = tarfile.TarInfo(name)
                member.size = 7
                archive.addfile(member, io.BytesIO(b"fixture"))
        content = stream.getvalue()
        entry = json.loads((PROJECT / "locks/runtimes.json").read_text())["gvisor"]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            with mock.patch.object(diag.urllib.request, "urlopen", return_value=io.BytesIO(content)):
                with self.assertRaisesRegex(ValueError, "SHA512"):
                    diag.download_gvisor(target, entry)
            self.assertFalse((target / "gvisor").exists())
            entry["sha512"] = hashlib.sha512(content).hexdigest()
            with mock.patch.object(diag.urllib.request, "urlopen", return_value=io.BytesIO(content)):
                diag.download_gvisor(target, entry)
            self.assertEqual({p.name for p in (target / "gvisor").iterdir()}, {"runsc", "runsc-gofer"})
            self.assertEqual((target / "gvisor/runsc").stat().st_mode & 0o777, 0o555)

    def test_effective_docker_policy_rejects_privilege_and_seccomp_drift(self):
        profile = json.loads((PROJECT / "deploy/seccomp-gvisor.json").read_text())
        actual = dict(user="10001:10001", cap_drop=["ALL"], cap_add=None, read_only=True,
                      privileged=False, pids_limit=4096, apparmor="docker-default",
                      security_opt=["no-new-privileges:true", "seccomp=" + json.dumps(profile)])
        for change, expected in (({}, "PASS"), ({"privileged": True}, "FAIL"),
                                 ({"user": "0:0"}, "FAIL"), ({"cap_add": ["SYS_ADMIN"]}, "FAIL"),
                                 ({"security_opt": ["no-new-privileges:true"]}, "FAIL")):
            with self.subTest(change=change), mock.patch.object(diag, "command", return_value=result(stdout=json.dumps({**actual, **change}))):
                item, _ = diag.inspect_policy("fixture")
                self.assertEqual(item["status"], expected)

    def test_apparmor_activation_is_checked_after_start_and_rejects_drift(self):
        seccomp = json.loads((PROJECT / "deploy/seccomp-gvisor.json").read_text())
        actual = dict(user="10001:10001", cap_drop=["ALL"], cap_add=None, read_only=True,
                      privileged=False, pids_limit=4096, apparmor="",
                      security_opt=["no-new-privileges:true", "seccomp=" + json.dumps(seccomp), "apparmor=docker-default"])
        for started, profile, expected in ((False, "", "PASS"), (True, "", "FAIL"),
                                            (True, "docker-default", "PASS"),
                                            (False, "unconfined", "FAIL"), (True, "other-profile", "FAIL")):
            with self.subTest(started=started, profile=profile), mock.patch.object(diag, "command", return_value=result(stdout=json.dumps({**actual, "apparmor": profile}))):
                item, observed = diag.inspect_policy("fixture", started=started)
                self.assertEqual(item["status"], expected)
                self.assertEqual(observed["apparmor"], profile)
        actual.update(apparmor="camact-gvisor-diagnostic-v1",
                      security_opt=["no-new-privileges:true", "seccomp=" + json.dumps(seccomp), "apparmor=camact-gvisor-diagnostic-v1"])
        with mock.patch.object(diag, "command", return_value=result(stdout=json.dumps(actual))):
            item, _ = diag.inspect_policy("fixture", "camact-gvisor-diagnostic-v1", started=True)
            self.assertEqual(item["status"], "PASS")
            item, _ = diag.inspect_policy("fixture", started=True)
            self.assertEqual(item["status"], "FAIL")
        service = dict(user="10001:10001", platform="linux/amd64", pids_limit=4096, tmpfs=[])
        for profile in diag.APPARMOR_PROFILES:
            args = diag.docker_arguments(service, Path("/fixture"), "fixture", "image", profile)
            self.assertIn("--security-opt=apparmor=" + profile, args)
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            diag.docker_arguments(service, Path("/fixture"), "fixture", "image", "unconfined")

    def test_process_policy_failure_does_not_relabel_observed_failures(self):
        observed = {"process_status": {"NoNewPrivs": "1", "Seccomp": "2", "CapEff": "0", "CapBnd": "0"}}
        with tempfile.TemporaryDirectory() as directory:
            assets = Path(directory)
            (assets / "metadata.json").write_text(json.dumps({"flags": [], "version": "fixture", "expected_apparmor": "docker-default"}))
            out = io.StringIO()
            with mock.patch.object(diag, "environment", return_value=observed), \
                    mock.patch.object(diag.os, "getuid", return_value=0), mock.patch.object(diag.os, "getgid", return_value=0), \
                    mock.patch.object(diag, "namespace_tests", return_value=[diag.row("docker", "user.unshare", "FAIL")]), \
                    mock.patch.object(Path, "mkdir"), \
                    mock.patch.object(diag, "gvisor_tests", return_value=([diag.row("gvisor", "run", "FAIL")], "fixture")), \
                    contextlib.redirect_stdout(out):
                diag.inside(assets)
        tests = json.loads(out.getvalue())["tests"]
        self.assertEqual([t["status"] for t in tests], ["FAIL", "FAIL", "FAIL"])
        self.assertFalse(any("observed_status" in t for t in tests))

    def test_audit_only_exports_security_fields_and_marks_missing_evidence(self):
        token = "hf_" + "z" * 32
        raw = ('audit: type=1400 audit(1234567890.123:456): apparmor="DENIED" '
               'operation="mount" profile="docker-default" comm="runsc" pid=123 '
               f'name="/private/{token}" secret={token}\n')
        with mock.patch.object(diag, "command", side_effect=[result(stdout=raw), result(1, stderr="Permission denied")]):
            rows, events = diag.audit_records("fixture-time")
        self.assertEqual([r["status"] for r in rows], ["PASS", "SKIP"])
        self.assertEqual(events[0]["operation"], "mount")
        self.assertEqual(events[0]["audit_id"], "1234567890.123:456")
        self.assertNotIn(token, json.dumps(events))
        self.assertEqual(events[0]["name"], "<path>")
        with mock.patch.object(diag, "command", return_value=result(stdout="No entries")):
            rows, events = diag.audit_records("fixture-time")
        self.assertEqual(events, [])
        self.assertTrue(all(r["status"] == "SKIP" for r in rows))

    def test_audit_keeps_safe_mount_evidence_and_deduplicates_sources(self):
        raw = ('audit: type=1400 audit(1234567890.123:457): apparmor="DENIED" '
               'operation="mount" profile="docker-default" comm="runsc" pid=123 '
               'name="/proc/self/fd/14" srcname="/var/lib/camact/scratch/gvisor/gvisor-fixture/rootfs/" '
               'flags="rw, rslave" info="failed flags match" fstype="tmpfs" capname="sys_admin" capability=21\n')
        with mock.patch.object(diag, "command", return_value=result(stdout=raw)):
            rows, events = diag.audit_records("fixture-time")
        self.assertEqual([r["status"] for r in rows], ["PASS", "PASS"])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["sources"], ["journal", "dmesg"])
        self.assertEqual(events[0]["flags"], "rw, rslave")
        self.assertEqual(events[0]["info"], "failed flags match")
        self.assertEqual(events[0]["name"], "/proc/self/fd/14")
        self.assertEqual(events[0]["capability"], "21")

    def test_minimal_success_never_claims_full_production_equivalence(self):
        report = {"tests": [diag.row("host", "user.unshare", "PASS"),
                            diag.row("docker", "production_equivalence", "SKIP"),
                            diag.row("audit", "journal", "SKIP")]}
        summary = diag.summarize(report)
        self.assertEqual(report["outcome"], "INCOMPLETE")
        self.assertEqual(report["nested_outcome"], "INCOMPLETE")
        self.assertIn("do not prove full CamAct acceptance", summary)
        report["tests"].append(diag.row("gvisor", "run", "SKIP"))
        diag.summarize(report)
        self.assertEqual(report["outcome"], "INCOMPLETE")

    def test_nested_success_requires_every_namespace_and_cleanup_check(self):
        docker = ("effective_policy", "started_policy", "collector", "process_policy", "apparmor_parity", "container_cleanup",
                  "user.unshare", "user.setgroups", "user.uid_map", "user.gid_map",
                  "user_mount.unshare", "user_mount.setgroups", "user_mount.uid_map", "user_mount.gid_map", "user_mount.exec_true",
                  "mount.unshare", "mount.setgroups", "mount.uid_map", "mount.gid_map", "mount.private", "mount.tmpfs",
                  "mount.tmpfs_write", "mount.tmpfs_unmount", "mount.bind", "mount.readonly", "mount.readonly_enforced", "mount.bind_unmount",
                  "net.unshare", "net.setgroups", "net.uid_map", "net.gid_map", "net.unshare_net", "original_unshare")
        runtime = ("version", "run", "delete", "state_absent", "child_reaping", "directory_cleanup")
        report = {"tests": [diag.row("docker", name, "PASS") for name in docker]
                  + [diag.row("gvisor", name, "PASS") for name in runtime]}
        diag.summarize(report)
        self.assertEqual((report["outcome"], report["nested_outcome"]), ("PASS", "PASS"))
        report["tests"].append(diag.row("host", "user.setgroups", "FAIL"))
        diag.summarize(report)
        self.assertEqual((report["outcome"], report["nested_outcome"]), ("FAIL", "PASS"))
        report["tests"] = [t for t in report["tests"] if t["test"] != "child_reaping"]
        diag.summarize(report)
        self.assertEqual(report["nested_outcome"], "INCOMPLETE")
        self.assertIn("gvisor.child_reaping", report["nested_missing_checks"])

    def test_missing_docker_produces_report_and_skips_runtime(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(diag, "namespace_tests", return_value=[]), \
                mock.patch.object(diag, "command", return_value=result(125, stderr="docker unavailable", number=errno.ENOENT)), \
                contextlib.redirect_stdout(io.StringIO()):
            output = Path(directory) / "report"
            self.assertEqual(diag.diagnose(output), 1)
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(report["outcome"], "FAIL")
            self.assertTrue((output / "summary.md").is_file())
            self.assertTrue(any(r["layer"] == "gvisor" and r["test"] == "run" and r["status"] == "SKIP" for r in report["tests"]))

    def test_nested_failure_report_and_cleanup_with_assets_still_present(self):
        # Exercise orchestration at command boundaries; real files/serialization,
        # policy gate and cleanup ordering remain active.
        calls, assets_path, inspected = [], [], []
        source = dict(user="10001:10001", platform="linux/amd64", pids_limit=4096,
                      tmpfs=["/tmp:rw,nosuid,nodev,size=512m,uid=10001,gid=10001,mode=1777"])
        nested = {"environment": {"apparmor_current": {"status": "PASS", "value": "docker-default (enforce)"}},
                  "tests": [diag.row("docker", "user_mount.unshare", "FAIL", error=OSError(errno.EPERM, "Operation not permitted")),
                            diag.row("gvisor", "run", "FAIL", stderr="namespace: operation not permitted"),
                            diag.row("gvisor", "delete", "PASS")], "runsc_debug": "diagnostic fixture"}

        def command(argv, *args, **kwargs):
            if str(argv[2]).endswith("scan-image.py"):
                return result(stdout=json.dumps({"result": "PASS", "issue_count": 0,
                    "files_scanned": 1, "bytes_scanned": 1}))
            self.assertEqual(argv[0], "docker")
            calls.append(argv[1])
            if argv[1] == "info":
                return result(stdout='["name=apparmor", "name=seccomp,profile=builtin"]')
            if argv[1] == "create":
                mount = next(v for v in argv if isinstance(v, str) and v.startswith("type=bind,src="))
                assets = Path(mount.split("src=", 1)[1].split(",", 1)[0])
                assets_path.append(assets)
                self.assertTrue(assets.stat().st_mode & 0o005 == 0o005, "UID 10001 needs directory read/search")
                self.assertNotIn("--privileged", argv)
                self.assertIn("--user", argv)
                self.assertEqual(argv[argv.index("--user") + 1], "10001:10001")
                self.assertIn("--security-opt=apparmor=docker-default", argv)
                self.assertEqual(json.loads((assets / "metadata.json").read_text())["expected_apparmor"], "docker-default")
                return result(stdout="container fixture")
            if argv[1] == "inspect":
                inspected.append(True)
                policy = dict(user="10001:10001", cap_drop=["ALL"], cap_add=None, read_only=True,
                              privileged=False, pids_limit=4096, apparmor="" if len(inspected) == 1 else "docker-default",
                              security_opt=["no-new-privileges:true", "apparmor=docker-default", "seccomp=" + (PROJECT / "deploy/seccomp-gvisor.json").read_text()])
                return result(stdout=json.dumps(policy))
            if argv[1:3] == ["image", "inspect"]:
                return result(stdout="sha256:" + "7" * 64)
            if argv[1] == "start":
                return result(stdout=json.dumps(nested))
            if argv[1] == "rm":
                self.assertTrue(assets_path[0].exists(), "remove container before bind source cleanup")
                return result()
            self.assertEqual(argv[1], "pull")
            return result()

        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(diag, "namespace_tests", return_value=[diag.row("host", "user_mount.unshare", "PASS")]), \
                mock.patch.object(diag, "compose_policy", return_value=(source, diag.row("docker", "compose_policy", "PASS"))), \
                mock.patch.object(diag, "download_gvisor"), \
                mock.patch.object(diag, "command", side_effect=command), \
                mock.patch.object(diag, "audit_records", return_value=([], [])), \
                contextlib.redirect_stdout(io.StringIO()):
            output = Path(directory) / "report"
            self.assertEqual(diag.diagnose(output), 1)
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(report["outcome"], "FAIL")
            failure = next(r for r in report["tests"] if r["layer"] == "docker" and r["test"] == "user_mount.unshare")
            self.assertEqual(failure["errno_name"], "EPERM")
            self.assertEqual(failure["status"], "FAIL")
            self.assertEqual(report["nested_outcome"], "FAIL")
            self.assertEqual(report["effective_docker_policy"]["apparmor"], "")
            self.assertEqual(report["started_docker_policy"]["apparmor"], "docker-default")
            self.assertEqual(next(t["status"] for t in report["tests"] if t["test"] == "apparmor_parity"), "PASS")
        self.assertEqual(calls, ["info", "pull", "image", "create", "inspect", "start", "inspect", "rm"])
        self.assertFalse(assets_path[0].exists())


if __name__ == "__main__":
    unittest.main()
