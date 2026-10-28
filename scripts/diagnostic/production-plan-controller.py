#!/usr/bin/env python3
"""Run the real production-plan probe with synthetic, bind-backed storage only."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("production_plan_diagnostics", ROOT / "scripts/diagnose-gvisor.py")
diag = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(diag)

PROFILE = "camact-gvisor-diagnostic-v1"
VERSION = "0.1.0-rc.1"
INNER_OUTPUT = "/var/lib/camact/scratch/production-plan-probe-report"
INNER_SCHEMA = "camact.gvisor.production-plan.v1"
CANARY = "camact-production-plan-synthetic-secret-only\n"
CAPTURE_BYTES = 2 * 1024 * 1024
ARTIFACT_BYTES = 4 * 1024 * 1024
INNER_REQUIRED = {
    "outer_policy", "secret_fixture", "runtime_version", "plan_layout", "guest_exit",
    "guest_evidence", "lifecycle", "credential_evidence", "fixture_cleanup",
    "album_readonly", "context_readonly", "policy_readonly", "memory_alias_readonly",
    "workspace_writable", "home_writable", "secrets_unreadable", "other_user_unreadable",
    "external_network_unreachable", "transport_allowed", "transport_sibling_denied", "credentials_absent",
}
RUNTIME_REQUIRED = {"claude", "codex", "opencode", "deepseek", "openclaw", "credential_boundary"}


class Stop(Exception):
    """A prerequisite failed; its sanitized check has already been recorded."""


def command(argv, timeout=20):
    return diag.command(argv, timeout=timeout)


def status(item):
    return item.get("status", item.get("result")) if isinstance(item, dict) else None


def lifecycle_ok(value):
    return (isinstance(value, dict) and value.get("returncode") == 0
            and value.get("cleanup_returncode") == 0 and value.get("state_removed") is True)


def validate_inner(report, artifacts, check_runtimes=True):
    """Do not turn a successful Docker exit or an arbitrary PASS row into success."""
    errors = []
    if not isinstance(report, dict) or report.get("schema") != INNER_SCHEMA:
        return ["inner_schema"]
    tests = report.get("tests")
    if not isinstance(tests, list) or not tests:
        errors.append("inner_tests_missing")
        tests = []
    names = [item.get("test") for item in tests if isinstance(item, dict)]
    required = INNER_REQUIRED | ({"check_runtimes"} if check_runtimes else set())
    if not required.issubset(names) or len(names) != len(set(names)):
        errors.append("inner_required_checks_missing_or_duplicate")
    if any(status(item) != "PASS" for item in tests):
        errors.append("inner_check_not_pass")
    if report.get("outcome") != "PASS":
        errors.append("inner_outcome_not_pass")
    lifecycles = report.get("lifecycles")
    expected_count = 7 if check_runtimes else 1
    if (not isinstance(lifecycles, list) or len(lifecycles) != expected_count
            or not all(lifecycle_ok(item) for item in lifecycles)):
        errors.append("inner_lifecycle_missing_or_failed")
    if check_runtimes:
        runtimes = report.get("runtime_checks")
        if not isinstance(runtimes, dict) or set(runtimes) != RUNTIME_REQUIRED:
            errors.append("runtime_checks_missing")
        else:
            for name in RUNTIME_REQUIRED - {"credential_boundary"}:
                item = runtimes[name]
                if (not isinstance(item, dict) or item.get("returncode") != 0
                        or not lifecycle_ok(item.get("lifecycle"))):
                    errors.append("runtime_check_failed:" + name)
            credential = runtimes["credential_boundary"]
            if (not isinstance(credential, dict) or credential.get("synthetic_only") is not True
                    or credential.get("trusted_credentials_absent") is not True
                    or credential.get("plan_and_lifecycle_canary_values_absent") is not True
                    or not lifecycle_ok(credential.get("lifecycle"))):
                errors.append("runtime_credential_boundary_failed")
    files = set(artifacts)
    if "report.json" not in files or "summary.md" not in files:
        errors.append("inner_report_or_summary_missing")
    if not any("plan" in Path(name).name and name.endswith(".json") and name != "report.json" for name in files):
        errors.append("plan_artifact_missing")
    if not any("lifecycle" in Path(name).name and name.endswith(".json") for name in files):
        errors.append("lifecycle_artifact_missing")
    return errors


def tmpfs_map(service):
    result = {}
    for value in service.get("tmpfs", []):
        if not isinstance(value, str) or ":" not in value:
            raise ValueError("Unexpected Compose tmpfs format")
        target, options = value.split(":", 1)
        if target in result:
            raise ValueError("Duplicate Compose tmpfs target")
        result[target] = options
    if set(result) != {"/run/camact", "/run/camact/openclaw", "/tmp"}:
        raise ValueError("Unexpected Compose tmpfs targets")
    for options in result.values():
        if not {"rw", "nosuid", "nodev", "uid=10001", "gid=10001"}.issubset(options.split(",")):
            raise ValueError("Compose tmpfs hardening drift")
    return result


def mount_matches(actual, expected, allowed_tmpfs=()):
    if not isinstance(actual, list):
        return False
    observed = {}
    for mount in actual:
        if not isinstance(mount, dict):
            return False
        target = mount.get("Destination")
        if mount.get("Type") == "tmpfs":
            if target not in allowed_tmpfs or mount.get("RW") is not True or mount.get("Source"):
                return False
            continue
        if mount.get("Type") != "bind":
            return False
        if target in observed:
            return False
        observed[target] = (str(Path(mount.get("Source", "")).resolve()), mount.get("RW"))
    return observed == {target: (str(source.resolve()), writable) for target, (source, writable) in expected.items()}


def requested_mounts_match(actual, expected):
    if not isinstance(actual, list) or len(actual) != len(expected):
        return False
    observed = {}
    for mount in actual:
        if not isinstance(mount, dict) or mount.get("Type") != "bind" or mount.get("Target") in observed:
            return False
        observed[mount.get("Target")] = (str(Path(mount.get("Source", "")).resolve()), not mount.get("ReadOnly", False))
    return observed == {target: (str(source.resolve()), writable) for target, (source, writable) in expected.items()}


class Controller:
    def __init__(self, output, check_runtimes=True):
        self.output = Path(output).absolute()
        self.check_runtimes = check_runtimes
        self.report = {"schema": "camact.gvisor.production-plan-controller.v1", "scope": "diagnostic_candidate_only",
                       "expected_apparmor": PROFILE, "tests": [], "logs": [], "check_runtimes": check_runtimes,
                       "synthetic_credentials_only": True, "model_requests": False}
        self.image_id = None
        self.scanned = False
        self.fixture = self.output / "private-fixture-data"
        self.runner = "camact-production-plan-" + uuid.uuid4().hex[:12]
        self.runner_created = False
        self.fixture_owned = False
        self.since = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    def check(self, name, passed, detail="", *, stop=True):
        self.report["tests"].append(diag.row("controller", name, "PASS" if passed else "FAIL", detail=detail))
        if not passed and stop:
            raise Stop(name)

    def capture(self, name, result):
        for stream in ("stdout", "stderr"):
            sanitized = diag.redact(result.get(stream, ""), limit=None).encode("utf-8")
            truncated = len(sanitized) > CAPTURE_BYTES
            value = sanitized[:CAPTURE_BYTES].decode("utf-8", errors="ignore")
            files = []
            for index, start in enumerate(range(0, len(value), 16000)):
                path = self.output / "logs" / f"{name}-{stream}-{index:04d}.txt"
                path.parent.mkdir(exist_ok=True)
                path.write_text(value[start:start + 16000], encoding="utf-8")
                files.append(str(path.relative_to(self.output)))
            self.report["logs"].append({"stage": name, "stream": stream, "files": files,
                                       "bytes": len(value.encode("utf-8")), "truncated": truncated})
            if truncated:
                self.check(name + "." + stream + "_complete", False, "Sanitized capture exceeded 2 MiB", stop=False)

    def execute(self, name, argv, timeout=30, *, stop=True):
        result = command(argv, timeout=timeout)
        self.capture(name, result)
        self.report["tests"].append(diag.command_row("controller", name, result))
        if result["returncode"] != 0 and stop:
            raise Stop(name)
        return result

    def compose(self):
        override = self.output / "credential-reset.yml"
        override.write_text("services:\n  runner:\n    env_file: !reset []\n    environment: !reset {}\n"
                            "    secrets: !reset []\n    volumes: !reset []\n"
                            "  storage-init:\n    volumes: !reset []\nsecrets: !reset {}\n", encoding="utf-8")
        result = self.execute("compose_read", ["docker", "compose", "--env-file", "/dev/null", "-f", ROOT / "compose.yaml",
                              "-f", override, "config", "--format", "json", "--no-env-resolution", "--no-consistency"])
        source = json.loads(result["stdout"])
        runner, storage = source["services"]["runner"], source["services"]["storage-init"]
        runner_ok = (runner.get("user") == "10001:10001" and runner.get("cap_drop") == ["ALL"]
                     and not runner.get("cap_add") and runner.get("read_only") is True
                     and runner.get("security_opt") == ["no-new-privileges:true", "seccomp=./deploy/seccomp-gvisor.json"]
                     and runner.get("pids_limit") == 4096 and runner.get("platform") == "linux/amd64"
                     and not any(runner.get(key) for key in ("privileged", "env_file", "environment", "secrets", "volumes")))
        storage_ok = (storage.get("user") == "0:0" and storage.get("cap_drop") == ["ALL"]
                      and set(storage.get("cap_add", [])) == {"CHOWN", "DAC_OVERRIDE", "FOWNER"}
                      and storage.get("read_only") is True and storage.get("network_mode") == "none"
                      and storage.get("entrypoint") == ["python", "-B", "/opt/camact/scripts/init-storage.py"]
                      and not any(storage.get(key) for key in ("privileged", "env_file", "environment", "secrets", "volumes", "security_opt")))
        self.check("compose_policy", runner_ok and storage_ok, "Credential fields reset before Compose resolution")
        tmpfs_map(runner)
        return runner, storage

    def inspect(self, name, stage, *, role, mounts, service=None, caps=(), started=False):
        fields = {"image": ".Image", "user": ".Config.User", "cap_drop": ".HostConfig.CapDrop", "cap_add": ".HostConfig.CapAdd",
                  "read_only": ".HostConfig.ReadonlyRootfs", "privileged": ".HostConfig.Privileged", "pids_limit": ".HostConfig.PidsLimit",
                  "apparmor": ".AppArmorProfile", "security_opt": ".HostConfig.SecurityOpt", "network": ".HostConfig.NetworkMode",
                  "tmpfs": ".HostConfig.Tmpfs", "mounts": ".Mounts", "requested_mounts": ".HostConfig.Mounts", "state": ".State"}
        template = "{" + ",".join('"' + key + '":{{json ' + field + "}}" for key, field in fields.items()) + "}"
        result = self.execute(stage + "_inspect", ["docker", "inspect", "--format", template, name])
        actual = json.loads(result["stdout"])
        security = actual.get("security_opt") or []
        valid = (actual.get("image") == self.image_id and actual.get("cap_drop") == ["ALL"]
                 and set(actual.get("cap_add") or []) == set(caps) and actual.get("read_only") is True
                 and not actual.get("privileged") and actual.get("network") == "none"
                 and (mount_matches(actual.get("mounts"), mounts, tmpfs_map(service) if role == "runner" else ())
                      if started else requested_mounts_match(actual.get("requested_mounts"), mounts))
                 and not any("unconfined" in value for value in security))
        if role == "runner":
            seccomp = [value.partition("=")[2] for value in security if value.startswith("seccomp=")]
            try:
                matches_seccomp = len(seccomp) == 1 and json.loads(seccomp[0]) == json.loads((ROOT / "deploy/seccomp-gvisor.json").read_text())
            except (ValueError, TypeError):
                matches_seccomp = False
            requested = [value.partition("=")[2] for value in security if value.startswith("apparmor=")]
            valid = (valid and actual.get("user") == "10001:10001" and actual.get("pids_limit") == service["pids_limit"]
                     and actual.get("tmpfs") == tmpfs_map(service) and matches_seccomp
                     and any(value in ("no-new-privileges", "no-new-privileges:true") for value in security)
                     and requested == [PROFILE] and actual.get("apparmor") in ((PROFILE,) if started else ("", PROFILE)))
        else:
            valid = (valid and actual.get("user") == "0:0" and not actual.get("tmpfs")
                     and not security and actual.get("apparmor") in (("docker-default",) if started else ("", "docker-default")))
        self.check(stage + "_policy", valid, "Only synthetic bind mounts and the expected immutable image are allowed")
        return actual

    def helper(self, name, mounts, caps, arguments, stage):
        self.check(stage + "_scan_prerequisite", self.scanned and bool(self.image_id))
        argv = ["docker", "create", "--name", name, "--user", "0:0", "--cap-drop=ALL", "--read-only", "--network=none"]
        for cap in caps:
            argv += ["--cap-add", cap]
        for target, (source, writable) in mounts.items():
            argv += ["--mount", f"type=bind,src={source},dst={target}" + ("" if writable else ",readonly")]
        argv += ["--entrypoint", "python", self.image_id, *arguments]
        created = False
        try:
            created = True  # A timed-out create may still have created its named container.
            self.execute(stage + "_create", argv)
            self.inspect(name, stage, role="helper", mounts=mounts, caps=caps)
            self.execute(stage + "_start", ["docker", "start", "--attach", name], timeout=120)
            actual = self.inspect(name, stage + "_started", role="helper", mounts=mounts, caps=caps, started=True)
            state = actual.get("state") or {}
            self.check(stage + "_exit", state.get("Status") == "exited" and state.get("ExitCode") == 0
                       and not state.get("OOMKilled") and not state.get("Error"))
        finally:
            if created:
                self.execute(stage + "_container_cleanup", ["docker", "rm", "--force", name], stop=False)

    def safe_fixture(self):
        return (not self.fixture.is_symlink() and self.fixture.resolve().parent == self.output.resolve()
                and self.fixture.name == "private-fixture-data")

    def cleanup_fixture(self):
        if not self.fixture_owned:
            self.check("fixture_cleanup", True, "No fixture was created by this invocation")
            return
        if not self.fixture.exists():
            self.check("fixture_cleanup", True)
            return
        if not self.safe_fixture():
            self.check("fixture_cleanup", False, "Unsafe fixture path; retained", stop=False)
            return
        try:
            shutil.rmtree(self.fixture)
        except OSError:
            # Root is confined to this one verified fixture mount. Never use host sudo.
            code = ("from pathlib import Path; import shutil\n"
                    "root=Path('/fixture')\n"
                    "assert not root.is_symlink() and root.resolve()==root\n"
                    "for child in root.iterdir():\n"
                    " if child.is_dir() and not child.is_symlink(): shutil.rmtree(child)\n"
                    " else: child.unlink()\n")
            try:
                self.helper(self.runner + "-cleanup", {"/fixture": (self.fixture, True)},
                            ("DAC_OVERRIDE", "FOWNER"), ["-B", "-c", code], "fixture_owner_cleanup")
                self.fixture.rmdir()
            except (Stop, OSError, ValueError, KeyError):
                self.check("fixture_cleanup", False, "Dedicated fixture retained for runner teardown", stop=False)
                self.report["fixture_retained"] = "private-fixture-data"
                return
        self.check("fixture_cleanup", not self.fixture.exists(), stop=False)

    def artifacts(self):
        target = self.output / "probe-artifacts"
        target.mkdir()
        self.execute("artifact_copy", ["docker", "cp", self.runner + ":" + INNER_OUTPUT + "/.", target])
        files = []
        valid = True
        for path in target.rglob("*"):
            if path.is_symlink() or not path.resolve().is_relative_to(target.resolve()):
                valid = False
                if path.is_symlink():
                    path.unlink()
                continue
            if path.is_dir():
                continue
            if path.suffix not in {".json", ".md", ".txt", ".log"} or path.stat().st_size > ARTIFACT_BYTES:
                valid = False
                path.unlink()
                continue
            value = path.read_text(encoding="utf-8", errors="replace")
            if path.suffix == ".json":
                try:
                    value = json.dumps(diag.clean(json.loads(value)), ensure_ascii=False, indent=2) + "\n"
                except ValueError:
                    valid = False
                    value = diag.redact(value, limit=None)
            else:
                value = diag.redact(value, limit=None)
            path.write_text(value, encoding="utf-8")
            files.append(path.relative_to(target).as_posix())
        self.check("artifact_format", valid, "Only bounded, sanitized text artifacts are accepted")
        inner_path = target / "report.json"
        inner = json.loads(inner_path.read_text()) if inner_path.is_file() else {}
        errors = validate_inner(inner, files, self.check_runtimes)
        self.report["inner_validation_errors"] = errors
        self.report["inner_outcome"] = inner.get("outcome")
        self.report["inner_lifecycle_count"] = len(inner.get("lifecycles", []))
        self.report["probe_artifacts"] = files
        self.check("inner_report", not errors, ", ".join(errors))

    def run(self, image):
        self.output.mkdir(parents=True, exist_ok=False)
        try:
            revision = self.execute("git_revision", ["git", "-C", ROOT, "rev-parse", "HEAD"])["stdout"].strip()
            self.check("git_revision_shape", bool(re.fullmatch(r"[0-9a-f]{40}", revision)))
            template = '{"id":{{json .Id}},"version":{{json (index .Config.Labels "org.opencontainers.image.version")}},"revision":{{json (index .Config.Labels "org.opencontainers.image.revision")}},"os":{{json .Os}},"architecture":{{json .Architecture}}}'
            value = json.loads(self.execute("image_inspect", ["docker", "image", "inspect", "--format", template, image])["stdout"])
            self.image_id = value.get("id")
            self.check("image_identity", bool(re.fullmatch(r"sha256:[0-9a-f]{64}", self.image_id or ""))
                       and value.get("revision") == revision and value.get("version") == VERSION
                       and value.get("os") == "linux" and value.get("architecture") == "amd64")
            self.report["image_identity"] = value
            scan = self.execute("image_scan_command", [sys.executable, "-B", ROOT / "scripts/scan-image.py", "--image", self.image_id], timeout=900)
            inventory = json.loads(scan["stdout"])
            self.check("image_scan", inventory.get("result") == "PASS" and inventory.get("issue_count") == 0
                       and inventory.get("issues") == [] and inventory.get("candidate_values_printed") is False)
            self.scanned = True
            self.report["image_scan"] = diag.clean(inventory)
            service, storage = self.compose()
            self.check("new_fixture", not self.fixture.exists() and self.safe_fixture())
            self.fixture.mkdir(mode=0o700)
            self.fixture_owned = True
            data, secrets = self.fixture / "data", self.fixture / "secrets"
            data.mkdir(mode=0o700)
            secrets.mkdir(mode=0o700)
            (secrets / "agent_api_key").write_text(CANARY, encoding="utf-8")
            self.helper(self.runner + "-storage", {"/var/lib/camact": (data, True), "/secrets": (secrets, True)},
                        tuple(storage["cap_add"]), ["-B", "/opt/camact/scripts/init-storage.py"], "storage")
            self.check("fixture_bind_path", self.safe_fixture() and not data.is_symlink() and not secrets.is_symlink())
            mounts = {"/var/lib/camact": (data, True), "/run/secrets/production-plan-fixture": (secrets / "agent_api_key", False)}
            argv = ["docker", "create", "--name", self.runner, "--platform", service["platform"], "--user", service["user"],
                    "--cap-drop=ALL", "--read-only", "--pids-limit", str(service["pids_limit"]), "--network=none",
                    "--security-opt=no-new-privileges:true", "--security-opt=seccomp=" + str(ROOT / "deploy/seccomp-gvisor.json"),
                    "--security-opt=apparmor=" + PROFILE]
            for target, options in tmpfs_map(service).items():
                argv += ["--tmpfs", target + ":" + options]
            for target, (source, writable) in mounts.items():
                argv += ["--mount", f"type=bind,src={source},dst={target}" + ("" if writable else ",readonly")]
            argv += ["--entrypoint", "python", self.image_id, "-B", "/opt/camact/scripts/diagnostic/production-plan-probe.py", "--output", INNER_OUTPUT]
            if self.check_runtimes:
                argv += ["--check-runtimes"]
            self.runner_created = True
            self.execute("runner_create", argv)
            self.inspect(self.runner, "runner", role="runner", mounts=mounts, service=service)
            self.execute("runner_start", ["docker", "start", "--attach", self.runner], timeout=1300, stop=False)
            actual = self.inspect(self.runner, "runner_started", role="runner", mounts=mounts, service=service, started=True)
            state = actual.get("state") or {}
            self.check("runner_exit", state.get("Status") == "exited" and state.get("ExitCode") == 0
                       and not state.get("OOMKilled") and not state.get("Error"), stop=False)
            self.artifacts()
        except Stop:
            pass
        except Exception as exc:
            self.check("controller_exception", False, type(exc).__name__, stop=False)
        finally:
            if self.runner_created:
                self.execute("runner_cleanup", ["docker", "rm", "--force", self.runner], stop=False)
            self.cleanup_fixture()
            try:
                audit_access, audit_events = diag.audit_records(self.since)
                self.report["audit_access"] = audit_access
                self.report["audit_events"] = audit_events
            except Exception as exc:
                self.report["audit_access"] = [diag.row("audit", "collector", "SKIP", detail=type(exc).__name__)]
                self.report["audit_events"] = []
            tests = self.report["tests"]
            self.report["outcome"] = "PASS" if tests and all(status(item) == "PASS" for item in tests) and any(
                item["test"] == "inner_report" and item["status"] == "PASS" for item in tests) else "FAIL"
            (self.output / "report.json").write_text(json.dumps(diag.clean(self.report), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            lines = ["# Production-plan diagnostic: " + self.report["outcome"], "",
                     "Synthetic fixture only. This does not approve publication or modify production policy.", "",
                     "| Check | Status |", "| --- | --- |"]
            lines += [f"| {item['test']} | {item['status']} |" for item in tests]
            (self.output / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        return self.report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="camact:gvisor-diagnostic")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--skip-check-runtimes", action="store_true")
    args = parser.parse_args(argv)
    os.umask(0o077)
    report = Controller(args.output, check_runtimes=not args.skip_check_runtimes).run(args.image)
    print(json.dumps({"schema": report["schema"], "outcome": report["outcome"], "model_requests": False}))
    return 0 if report["outcome"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
