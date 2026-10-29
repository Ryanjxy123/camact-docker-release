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
from types import SimpleNamespace
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("gvisor_diagnostics", PROJECT / "scripts/diagnose-gvisor.py")
diag = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diag)


def result(code=0, stdout="", stderr="", number=None, timeout=False):
    return dict(returncode=code, stdout=stdout, stderr=stderr, errno=number, timed_out=timeout)


class DiagnosticsTests(unittest.TestCase):
    def test_compose_source_requires_the_production_named_apparmor_before_diagnostic_override(self):
        import yaml
        service = yaml.safe_load((PROJECT / 'compose.yaml').read_text())['services']['runner']
        for key in ('env_file', 'environment', 'secrets', 'volumes'):
            service.pop(key, None)
        expected = service['security_opt']
        for security, status in ((expected, 'PASS'), (expected[:-1], 'FAIL'),
                                 (expected + ['apparmor=unexpected'], 'FAIL'),
                                 ([*expected[:-1], 'apparmor=unconfined'], 'FAIL'),
                                 ([*expected[:-1], 'apparmor=camact-gvisor-diagnostic-v1'], 'FAIL')):
            with self.subTest(security=security), tempfile.TemporaryDirectory() as temporary:
                source = {'services': {'runner': dict(service, security_opt=security)}}
                with mock.patch.object(diag, 'command', return_value=result(stdout=json.dumps(source))):
                    _, observed = diag.compose_policy(Path(temporary))
                self.assertEqual(observed['status'], status)

    def test_redacts_credentials_paths_urls_and_terminal_controls(self):
        canaries = ["hf_" + "a" * 32, "ghp_" + "b" * 32, "sk-" + "c" * 32,
                    "diagnostic-canary-a", "diagnostic-canary-b", "diagnostic-canary-c"]
        raw = (f'{canaries[0]} {canaries[1]} {canaries[2]} API_KEY="{canaries[3]}" '
               f'"HF_TOKEN": "{canaries[4]}" Authorization: Bearer {canaries[5]} '
               + 'https://' + 'user:pass@' + 'example.invalid/private?q=value '
               + '/home/fixture/work/private /root/diagnostic-private \x1b[31mpermission denied\x00')
        sanitized = diag.redact(raw)
        for value in canaries + ["user:pass", "example.invalid", "work/private", "diagnostic-private", "\x1b", "\x00"]:
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

    def test_readonly_bind_preserves_source_locked_mount_flags(self):
        for stat_flags, expected in ((os.ST_NOEXEC | os.ST_RELATIME | os.ST_NODIRATIME,
                diag.MS_NOEXEC | diag.MS_RELATIME | diag.MS_NODIRATIME),
                (os.ST_NOATIME, diag.MS_NOATIME), (0, diag.MS_STRICTATIME)):
            with self.subTest(stat_flags=stat_flags), mock.patch.object(diag.os, "statvfs",
                    return_value=SimpleNamespace(f_flag=stat_flags)):
                flags = diag.readonly_bind_flags(Path("/fixture/source"))
            required = diag.MS_BIND | diag.MS_REMOUNT | diag.MS_RDONLY | diag.MS_NOSUID | diag.MS_NODEV
            self.assertEqual(flags, required | expected)

    def test_mount_state_distinguishes_exec_from_inherited_noexec(self):
        for extra, expected in ((0, True), (os.ST_NOEXEC, False)):
            with self.subTest(extra=extra), mock.patch.object(diag.os, "statvfs",
                    return_value=SimpleNamespace(f_flag=os.ST_NOSUID | os.ST_NODEV | extra)):
                observed = diag.mount_state(Path("/fixture"))
            self.assertEqual(observed["exec_allowed"], expected)
            self.assertEqual("noexec" in observed["mount_flags"], not expected)
            self.assertTrue({"rw", "nosuid", "nodev"}.issubset(observed["mount_flags"]))
        with mock.patch.object(diag.os, "statvfs", side_effect=OSError(errno.ENOENT, "Missing fixture")):
            self.assertEqual(diag.mount_state(Path("/fixture"))["status"], "SKIP")

    def test_fixture_storage_flags_are_required_and_recorded_inside(self):
        observed = {"process_status": {"NoNewPrivs": "1", "Seccomp": "2", "CapEff": "0", "CapBnd": "0"}}
        for flags, expected in ((os.ST_NOSUID | os.ST_NODEV, "PASS"),
                (os.ST_NOSUID | os.ST_NODEV | os.ST_NOEXEC, "FAIL"), (os.ST_NOSUID, "FAIL")):
            with self.subTest(flags=flags), tempfile.TemporaryDirectory() as directory:
                assets = Path(directory)
                (assets / "metadata.json").write_text(json.dumps({"flags": [], "version": "fixture"}))
                output = io.StringIO()
                with mock.patch.object(diag, "environment", return_value=dict(observed)), \
                        mock.patch.object(diag.os, "getuid", return_value=10001), mock.patch.object(diag.os, "getgid", return_value=10001), \
                        mock.patch.object(diag.os, "statvfs", return_value=SimpleNamespace(f_flag=flags)), \
                        mock.patch.object(diag, "namespace_tests", return_value=[]), mock.patch.object(Path, "mkdir"), \
                        mock.patch.object(diag, "gvisor_tests", return_value=([], "")), contextlib.redirect_stdout(output):
                    diag.inside(assets)
                report = json.loads(output.getvalue())
                storage = next(item for item in report["tests"] if item["test"] == "storage_mount_flags")
                self.assertEqual(storage["status"], expected)
                self.assertEqual(report["environment"]["fixture_storage"]["f_flag"], flags)

    def test_outside_mount_requires_eacces_after_legal_mounts_and_cleans_unexpected_success(self):
        original_write = Path.write_text
        for denied_errno, expected in ((errno.EACCES, "PASS"), (errno.EPERM, "FAIL"), (None, "FAIL")):
            with self.subTest(denied_errno=denied_errno), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                calls = []

                def write(path, value, *args, **kwargs):
                    if str(path).startswith("/proc/self/"):
                        return len(value)
                    if value == "must fail":
                        raise OSError(errno.EROFS, "Read-only file system")
                    return original_write(path, value, *args, **kwargs)

                def syscall(name, *args):
                    calls.append((name, args))
                    if name == "mount" and args[1] == os.fsencode(work / "outside") and denied_errno:
                        raise OSError(denied_errno, os.strerror(denied_errno))

                output = io.StringIO()
                with mock.patch.object(diag, "syscall", side_effect=syscall), \
                        mock.patch.object(Path, "write_text", autospec=True, side_effect=write), \
                        mock.patch.object(diag.os, "statvfs", return_value=SimpleNamespace(f_flag=os.ST_NOEXEC | os.ST_RELATIME)), \
                        contextlib.redirect_stdout(output):
                    diag.probe("mount", work, "docker")
                rows = json.loads(output.getvalue())
                self.assertTrue(all(item["status"] == "PASS" for item in rows[:-1]))
                self.assertEqual((rows[-1]["test"], rows[-1]["status"]), ("mount.outside_denied", expected))
                readonly = next(item for item in rows if item["test"] == "mount.readonly")
                self.assertIn("noexec", readonly["mount_flags"])
                self.assertIn("relatime", readonly["mount_flags"])
                self.assertEqual(any(name == "umount2" and args[0] == os.fsencode(work / "outside")
                                     for name, args in calls), denied_errno is None)
                if denied_errno == errno.EPERM:
                    self.assertEqual(rows[-1]["errno_name"], "EPERM")

    def test_debug_chunks_retain_early_errors_sanitize_before_split_and_bound_bytes(self):
        token = "hf_" + "z" * 40
        text = "EARLY_GOFER_FAILURE\n" + "a" * 15970 + " " + token + "\n" + "b" * 70000 + "\nTAIL_MARKER"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "debug.log"
            path.write_text(text)
            chunks = []
            tail, truncated = diag.capture_runsc_debug(path, chunks)
            self.assertFalse(truncated)
            self.assertTrue(all(len(part) <= 16000 for part in chunks))
            self.assertEqual("".join(chunks), diag.redact(text, limit=None))
            self.assertIn("EARLY_GOFER_FAILURE", chunks[0])
            self.assertNotIn(token, "".join(chunks))
            self.assertIn("TAIL_MARKER", tail)
            self.assertLessEqual(len(tail), 24000)
            path.write_text("EARLY_GOFER_FAILURE\n" + "界" * (diag.DEBUG_CAPTURE_BYTES // 3 + 100) + "TAIL_MARKER")
            chunks = []
            tail, truncated = diag.capture_runsc_debug(path, chunks)
            self.assertTrue(truncated)
            self.assertLessEqual(sum(len(part.encode("utf-8")) for part in chunks), 2 * 1024 * 1024)
            self.assertTrue(all(len(part) <= 16000 for part in chunks))
            self.assertIn("TAIL_MARKER", tail)

    def test_runtime_debug_capture_marks_truncation_explicitly(self):
        def command(argv, *args, **kwargs):
            if "--version" in argv:
                return result(stdout="runsc version fixture")
            if "run" in argv:
                debug_path = next(str(value).split("=", 1)[1] for value in argv if str(value).startswith("--debug-log="))
                Path(debug_path).write_text("EARLY_GOFER_FAILURE\n" + "a" * (diag.DEBUG_CAPTURE_BYTES + 1))
                return result(128, stderr="sandbox EOF")
            return result(stdout="[]")
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(diag, "command", side_effect=command), \
                mock.patch.object(diag, "syscall"), mock.patch.object(diag.os, "waitpid", side_effect=ChildProcessError):
            chunks = []
            rows, tail = diag.gvisor_tests(Path(directory), Path("/fixture/runsc"), [], "fixture", chunks)
        capture = next(item for item in rows if item["test"] == "debug_capture")
        self.assertEqual(capture["status"], "SKIP")
        self.assertTrue(capture["truncated"])
        self.assertIn("2 MiB", capture["detail"])
        self.assertIn("EARLY_GOFER_FAILURE", chunks[0])
        self.assertLessEqual(len(tail), 24000)

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
            storage = next(value for value in args if value.startswith("/var/lib/camact:"))
            self.assertIn("exec", storage.split(":", 1)[1].split(","))
            self.assertNotIn("noexec", storage.split(":", 1)[1].split(","))
            self.assertIn("nosuid,nodev", storage)
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
                    mock.patch.object(diag, "mount_state", return_value={"status": "SKIP"}), \
                    mock.patch.object(diag, "namespace_tests", return_value=[diag.row("docker", "user.unshare", "FAIL")]), \
                    mock.patch.object(Path, "mkdir"), \
                    mock.patch.object(diag, "gvisor_tests", return_value=([diag.row("gvisor", "run", "FAIL")], "fixture")), \
                    contextlib.redirect_stdout(out):
                diag.inside(assets)
        tests = json.loads(out.getvalue())["tests"]
        self.assertTrue(all(t["status"] == "FAIL" for t in tests))
        self.assertEqual({t["test"] for t in tests}, {"process_policy", "storage_mount_flags", "user.unshare", "run"})
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

    def test_audit_preserves_proc_fs_mount_targets(self):
        for path in ("/proc/fs", "/proc/fs/", "/proc/fs/proc/123/fd/", "/proc/fs/root/usr/"):
            with self.subTest(path=path), mock.patch.object(diag, "command", return_value=result(stdout=
                    'audit: type=1400 apparmor="DENIED" operation="mount" name="' + path + '"')):
                _, events = diag.audit_records("fixture-time")
            self.assertEqual(events[0]["name"], path)

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
        docker = ("effective_policy", "started_policy", "collector", "process_policy", "storage_mount_flags", "apparmor_parity", "container_cleanup",
                  "user.unshare", "user.setgroups", "user.uid_map", "user.gid_map",
                  "user_mount.unshare", "user_mount.setgroups", "user_mount.uid_map", "user_mount.gid_map", "user_mount.exec_true",
                  "mount.unshare", "mount.setgroups", "mount.uid_map", "mount.gid_map", "mount.private", "mount.tmpfs",
                  "mount.tmpfs_write", "mount.tmpfs_unmount", "mount.bind", "mount.readonly", "mount.readonly_enforced", "mount.bind_unmount", "mount.outside_denied",
                  "net.unshare", "net.setgroups", "net.uid_map", "net.gid_map", "net.unshare_net", "original_unshare")
        runtime = ("version", "rootfs_mount_flags", "run", "delete", "state_absent", "child_reaping", "directory_cleanup")
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
                            diag.row("gvisor", "delete", "PASS")], "runsc_debug": "diagnostic fixture",
                  "runsc_debug_chunks": ["EARLY_GOFER_FAILURE", "diagnostic fixture"]}

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
            self.assertEqual(report["runsc_debug_chunks"], nested["runsc_debug_chunks"])
            self.assertEqual(next(t["status"] for t in report["tests"] if t["test"] == "apparmor_parity"), "PASS")
        self.assertEqual(calls, ["info", "pull", "image", "create", "inspect", "start", "inspect", "rm"])
        self.assertFalse(assets_path[0].exists())


if __name__ == "__main__":
    unittest.main()
