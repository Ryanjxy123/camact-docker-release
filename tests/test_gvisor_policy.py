"""Offline policy scope and installer regressions; no kernel policy is loaded."""
import argparse
import hashlib
import itertools
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "deploy/camact-gvisor-v1.profile"
INSTALLER = ROOT / "scripts/install-gvisor-policy.sh"
SOURCE = PROFILE.read_text()
MODULE = {"__name__": "camact_policy_test"}
exec(compile(INSTALLER.read_text().split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0],
             str(INSTALLER), "exec"), MODULE)


def args(**overrides):
    values = dict(results_root=[], cache_root=[], scratch_root=[], state_root=[], repo_id=[], revision=[])
    values.update(overrides)
    return argparse.Namespace(**values)


def macros(text):
    return dict(re.findall(r"(?m)^@\{(CAMACT_[A-Z_]+)\}=(.*)$", text))


def expand(value, definitions):
    pending = [value]
    for _ in range(20):
        result = []
        changed = False
        for item in pending:
            match = re.search(r"@\{(CAMACT_[A-Z_]+)\}", item)
            if match:
                changed = True
                result.extend(item[:match.start()] + choice + item[match.end():]
                              for choice in definitions[match[1]].split())
            else:
                result.append(item)
        pending = result
        if not changed:
            break
    else:
        raise AssertionError("Recursive macro")
    for item in pending:
        match = re.search(r"\{([^{}]+)\}", item)
        if match:
            for choice in match[1].split(","):
                yield from expand(item[:match.start()] + choice + item[match.end():], definitions)
        else:
            yield item


def aa_match(pattern, path):
    """Only the path glob subset used by the fixed mount rules."""
    tokens = re.split(r"(\*\*|\*|\?|\[[^]]+\])", pattern)
    expression = "".join(".*" if token == "**" else "[^/]*" if token == "*" else
                         "[^/]" if token == "?" else token if token.startswith("[") else
                         re.escape(token) for token in tokens)
    return re.fullmatch(expression, path) is not None


def bind_allowed(source, destination, text=SOURCE):
    definitions = macros(text)
    for line in text.splitlines():
        match = re.fullmatch(r"\s*mount options=\(([^)]+)\) (\S+) -> (\S+),", line)
        if not match or "rbind" not in match[1].split(","):
            continue
        if any(aa_match(pattern, source) for pattern in expand(match[2], definitions)) and any(
                aa_match(pattern, destination) for pattern in expand(match[3], definitions)):
            return True
    return False


class PolicyScopeTests(unittest.TestCase):
    def test_named_enforce_profile_source(self):
        raw = PROFILE.read_bytes()
        self.assertNotIn(b"\r", raw)
        self.assertEqual(MODULE["read_source"](PROFILE), SOURCE)

    def test_formal_shared_and_claude_paths(self):
        base = "/var/lib/camact/results/release-v1/users/user_fixture/runs/"
        for harness in ("codex", "opencode", "deepseek", "openclaw", "claude"):
            execution = base + harness + "/task_fixture/attempt_001/run/runs/execution"
            workspace = execution + ("/tasks/user_fixture/task_fixture/workspace" if harness == "claude"
                                     else "/workspace")
            with self.subTest(harness=harness):
                self.assertTrue(bind_allowed(workspace + "/", "/proc/fs/root/tmp/"))
                for name in ("album", "context", ".camact"):
                    self.assertTrue(bind_allowed(workspace + "/" + name + "/",
                                                 "/proc/fs/root/tmp/" + name + "/"))
                if harness == "claude":
                    self.assertTrue(bind_allowed(execution + "/tasks/user_fixture/task_fixture/claude_config/attempt_01/",
                                                 "/proc/fs/root/home/"))
                elif harness != "openclaw":
                    self.assertTrue(bind_allowed(execution + "/home/", "/proc/fs/root/home/agent/"))
        self.assertTrue(bind_allowed("/run/camact/openclaw/camact-openclaw-123/home/",
                                     "/proc/fs/root/home/agent/"))

    def test_wrong_harness_depth_attempt_and_arbitrary_scratch_denied(self):
        prefix = "/var/lib/camact/results/release-v1/users/user_fixture/runs/"
        for invalid in (prefix + "baseline/task_fixture/attempt_001/run/runs/execution/workspace/",
                        prefix + "codex/task_fixture/attempt_01/run/runs/execution/workspace/",
                        prefix + "codex/task_fixture/attempt_0001/run/runs/execution/workspace/",
                        prefix + "codex/task_fixture/attempt_001/extra/run/runs/execution/workspace/",
                        "/var/lib/camact/results/release-v1/arbitrary/workspace/",
                        "/var/lib/camact/scratch/arbitrary/workspace/",
                        "/var/lib/camact/secrets/"):
            with self.subTest(source=invalid):
                self.assertFalse(bind_allowed(invalid, "/proc/fs/root/tmp/"))
        claude = prefix + "claude/task_fixture/attempt_001/run/runs/execution/tasks/user_fixture/task_fixture/claude_config/"
        self.assertFalse(bind_allowed(claude + "attempt_001/", "/proc/fs/root/home/"))

    def test_original_preflight_version_and_all_native_fixtures(self):
        scratch = "/var/lib/camact/scratch/"
        workspaces = [scratch + "camact-gvisor-diagnostic-fixture/workspace"]
        for harness in ("claude", "codex", "opencode", "deepseek", "openclaw", "credential-boundary"):
            workspaces.append(scratch + "camact-sandbox-check-fixture/" + harness + "/workspace")
        for harness, mode in itertools.product(("claude", "codex", "opencode", "deepseek", "openclaw"),
                                               ("single_turn", "multi_turn", "users_history")):
            execution = scratch + "docker-gates-fixture/" + harness + "-" + mode + "/run/runs/execution"
            workspaces.append(execution + ("/tasks/fixture_user/task_fixture/workspace" if harness == "claude"
                                           else "/workspace"))
        for workspace in workspaces:
            with self.subTest(workspace=workspace):
                self.assertTrue(bind_allowed(workspace + "/", "/proc/fs/root/tmp/"))
        states = (scratch + "gvisor/run-123", scratch + "camact-sandbox-check-fixture/gvisor-state/run-123",
                  scratch + "docker-gates-fixture/gvisor-state/run-123",
                  scratch + "camact-gvisor-diagnostic-fixture/runtime/run-123")
        for state in states:
            self.assertTrue(bind_allowed(state + "/rootfs/", "/proc/fs/root/"))
        self.assertFalse(bind_allowed(scratch + "arbitrary/run-123/rootfs/", "/proc/fs/root/"))

    def test_memory_source_is_workspace_album_and_pinned_target(self):
        source = "/var/lib/camact/results/run-fixture/users/user_fixture/runs/codex/task_fixture/attempt_001/run/runs/execution/workspace/album/"
        target = "/proc/fs/root/var/lib/camact/benchmark/" + MODULE["repository"](MODULE["DEFAULT_REPO"]) + "/" + MODULE["DEFAULT_REVISION"] + "/snapshot/users/user_fixture/base_memory/"
        self.assertTrue(bind_allowed(source, target))
        for invalid in (source.replace("/album/", "/context/"),
                        target.removeprefix("/proc/fs/root"), "/var/lib/camact/secrets/"):
            self.assertFalse(bind_allowed(invalid, target))
        self.assertFalse(bind_allowed(source, target.replace(MODULE["DEFAULT_REVISION"], "a" * 40)))

    def test_transport_and_preserved_moby_denies(self):
        for source in ("/tmp/camact-multi-fixture/", "/tmp/camact-transport-fixture/",
                       "/tmp/camact-native-relay-fixture/camact-multi-fixture/"):
            self.assertTrue(bind_allowed(source, "/proc/fs/root/transport/"))
        self.assertFalse(bind_allowed("/tmp/arbitrary/", "/proc/fs/root/transport/"))
        for rule in ("deny network raw,", "deny network vsock,", "deny @{PROC}/sysrq-trigger rwklx,",
                     "deny @{PROC}/kcore rwklx,", "deny /sys/kernel/security/** rwklx,"):
            self.assertIn(rule, SOURCE)
        self.assertNotIn("deny mount,", SOURCE)
        self.assertNotIn("/**/workspace", SOURCE)
        self.assertNotIn("camact-diag-*", SOURCE)
        self.assertNotIn("production-plan-fixture", SOURCE)
        self.assertIn("mount fstype=tmpfs options=(rw,nosuid,nodev) -> @{CAMACT_NAMESPACE_ROOT}/ns-*/target/", SOURCE)
        self.assertIn("@{CAMACT_NAMESPACE_ROOT}=/tmp/camact-namespace-diagnostics-*", SOURCE)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="camact-policy-unit-")
        self.addCleanup(self.temporary.cleanup)
        self.host = Path(self.temporary.name) / "data"

    def configuration(self, **overrides):
        return MODULE["configuration"](args(**overrides), self.host)

    def test_default_render_is_identical_and_custom_only_changes_six_lines(self):
        self.assertEqual(MODULE["render"](SOURCE, self.configuration()), SOURCE)
        configured = self.configuration(results_root=["/var/lib/camact/project/a/results"],
            cache_root=["/var/lib/camact/project/a/benchmark"], repo_id=["fixture_owner/fixture_dataset"],
            revision=["a" * 40])
        rendered = MODULE["render"](SOURCE, configured)
        key = lambda line: re.sub(r"^(@\{CAMACT_(?:RESULTS_ROOT|CACHE_ROOT|SCRATCH_ROOT|GVISOR_STATE_ROOT|CACHE_REPOSITORY|BENCHMARK_REVISION)\}=).*$", r"\1", line)
        self.assertEqual([key(line) for line in rendered.splitlines()], [key(line) for line in SOURCE.splitlines()])
        self.assertTrue(bind_allowed("/var/lib/camact/project/a/results/run-fixture/users/user_fixture/runs/codex/task_fixture/attempt_001/run/runs/execution/workspace/",
                                     "/proc/fs/root/tmp/", rendered))
        self.assertFalse(bind_allowed("/var/lib/camact/project/a/results/arbitrary/workspace/",
                                      "/proc/fs/root/tmp/", rendered))

    def test_unsafe_roots_and_config_injection_rejected(self):
        for value in ("/var/lib/camact", "/tmp/results", "/var/lib/camact/../results", "/var/lib/camact/a//b",
                      "/var/lib/camact/a/*", "/var/lib/camact/a/{b,c}", "/var/lib/camact/a\n/var/lib/camact/b",
                      "/var/lib/camact/secrets/data", "/var/lib/camact/proc/data", "/var/lib/camact/a/./b"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.configuration(results_root=[value])
        for value in ("../repo", "owner/repo extra", "owner/repo\nfile,"):
            with self.assertRaises(ValueError):
                self.configuration(repo_id=[value])
        for value in ("HEAD", "A" * 40, "a" * 39, "a" * 41):
            with self.assertRaises(ValueError):
                self.configuration(revision=[value])

    def test_limit_and_duplicates_are_finite(self):
        value = "/var/lib/camact/project/results"
        configured = self.configuration(results_root=[value] * 20)
        self.assertEqual(len(configured["CAMACT_RESULTS_ROOT"]), 2)
        with self.assertRaises(ValueError):
            self.configuration(results_root=["/var/lib/camact/fixture-" + str(index) for index in range(8)])

    def test_host_data_and_descendant_symlinks_rejected_without_reading(self):
        self.host.mkdir()
        (self.host / "results").symlink_to(self.host / "absent", target_is_directory=True)
        with self.assertRaises(ValueError):
            self.configuration()
        (self.host / "results").unlink()
        link = Path(self.temporary.name) / "linked-data"
        link.symlink_to(self.host, target_is_directory=True)
        with self.assertRaises(ValueError):
            MODULE["configuration"](args(), link)
        (self.host / "project").write_text("not a directory")
        with self.assertRaises(ValueError):
            self.configuration(results_root=["/var/lib/camact/project/results"])

    def test_exact_installed_policy_roots_and_enforce_are_required(self):
        defaults = self.configuration()
        custom = self.configuration(results_root=["/var/lib/camact/project/results"])
        installed = MODULE["render"](SOURCE, custom)
        self.assertEqual(MODULE["supported"](installed, SOURCE, defaults), custom)
        self.assertEqual(MODULE["supported"](installed, SOURCE, custom), custom)
        with self.assertRaises(ValueError):
            MODULE["supported"](SOURCE, SOURCE, custom)
        with self.assertRaises(ValueError):
            MODULE["supported"](installed.replace("deny network raw,", "network raw,"), SOURCE, custom)
        MODULE["enforce"]("other-profile (enforce)\ncamact-gvisor-v1 (enforce)\n")
        for text in ("camact-gvisor-v1 (complain)", "camact-gvisor-v1-extra (enforce)", "",
                     "camact-gvisor-v1 (enforce)\ncamact-gvisor-v1 (complain)"):
            with self.assertRaises(ValueError):
                MODULE["enforce"](text)

    def test_missing_altered_source_or_unsupported_mode_rejected(self):
        path = Path(self.temporary.name) / "profile"
        for content in (SOURCE.replace("abi <abi/4.0>", "abi <abi/3.0>"),
                        SOURCE.replace("attach_disconnected,mediate_deleted", "attach_disconnected,complain"),
                        SOURCE.replace("  userns,", ""), SOURCE.replace("\n", "\r\n")):
            path.write_bytes(content.encode())
            with self.assertRaises(ValueError):
                MODULE["read_source"](path)
        path.unlink()
        path.symlink_to(PROFILE)
        with self.assertRaises(ValueError):
            MODULE["read_source"](path)
        with self.assertRaises(ValueError):
            MODULE["render"](SOURCE.replace("@{CAMACT_RESULTS_ROOT}=/var/lib/camact/results", "@{CAMACT_RESULTS_ROOT}=/var/lib/camact/other"), self.configuration())

    def test_check_is_offline_and_never_calls_install_or_parser(self):
        with patch.dict(MODULE, install=lambda text: self.fail("check tried to load policy")), \
                patch("builtins.print") as output:
            self.assertEqual(MODULE["main"]([str(PROFILE), "check", "--data-dir", str(self.host)]), 0)
        import json
        report = json.loads(output.call_args.args[0])
        self.assertIs(report["enforce_verified"], False)
        self.assertIs(report["runtime_acceptance_required"], True)
        self.assertEqual(report["policy_sha256"], hashlib.sha256(SOURCE.encode()).hexdigest())

    def test_install_compiles_before_loading_only_fixed_enforce_path(self):
        target = Path(self.temporary.name) / "camact-gvisor-v1"
        profiles = Path(self.temporary.name) / "profiles"
        profiles.write_text("camact-gvisor-v1 (enforce)\n")
        read_text = Path.read_text
        calls = []

        def read(path, *arguments, **kwargs):
            if str(path) == "/sys/module/apparmor/parameters/enabled":
                return "Y\n"
            return read_text(path, *arguments, **kwargs)

        def execute(argv, **kwargs):
            calls.append(argv)
            if argv[-1] == "--version":
                return subprocess.CompletedProcess(argv, 0, stdout="AppArmor parser version 4.0.1\n")
            if "-Q" in argv:
                self.assertFalse(target.exists())
                self.assertEqual(Path(argv[-1]).read_text(), SOURCE)
            else:
                self.assertEqual(argv, ["/sbin/apparmor_parser", "-r", "-K", str(target)])
                self.assertEqual(target.read_text(), SOURCE)
            return subprocess.CompletedProcess(argv, 0)

        with patch.dict(MODULE, INSTALLED=target, PROFILES=profiles), \
                patch("os.geteuid", return_value=0), patch("shutil.which", return_value="/sbin/apparmor_parser"), \
                patch.object(Path, "read_text", read), patch("subprocess.run", side_effect=execute):
            MODULE["install"](SOURCE)
        self.assertEqual([argv[1] for argv in calls], ["--version", "-Q", "-r"])
        self.assertEqual(target.stat().st_mode & 0o777, 0o644)
        self.assertFalse(list(target.parent.glob(".camact-gvisor-v1-*")))

    def test_compile_failure_preserves_prior_file_and_never_loads(self):
        target = Path(self.temporary.name) / "camact-gvisor-v1"
        target.write_text("prior reviewed policy\n")
        read_text = Path.read_text

        def read(path, *arguments, **kwargs):
            return "Y\n" if str(path) == "/sys/module/apparmor/parameters/enabled" else read_text(path, *arguments, **kwargs)

        def execute(argv, **kwargs):
            if argv[-1] == "--version":
                return subprocess.CompletedProcess(argv, 0, stdout="AppArmor parser version 4.0.1\n")
            self.assertIn("-Q", argv)
            raise subprocess.CalledProcessError(1, argv)

        with patch.dict(MODULE, INSTALLED=target), patch("os.geteuid", return_value=0), \
                patch("shutil.which", return_value="/sbin/apparmor_parser"), patch.object(Path, "read_text", read), \
                patch("subprocess.run", side_effect=execute), self.assertRaises(subprocess.CalledProcessError):
            MODULE["install"](SOURCE)
        self.assertEqual(target.read_text(), "prior reviewed policy\n")
        self.assertFalse(list(target.parent.glob(".camact-gvisor-v1-*")))


if __name__ == "__main__":
    unittest.main()
