#!/usr/bin/env python3
"""Synthetic, model-free acceptance probe for the unchanged production builder."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("production_probe_diagnostics", ROOT / "scripts/diagnose-gvisor.py")
DIAG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DIAG)
DATA = Path("/var/lib/camact")
SCRATCH = DATA / "scratch"
STATE = SCRATCH / "gvisor"
MEMORY = "/synthetic/users/fixture-user/base_memory"
CANARY_PATH = Path("/run/secrets/production-plan-fixture")
CANARY_CONTENT = "camact-production-plan-synthetic-secret-only\n"
APPARMOR = "camact-gvisor-diagnostic-v1 (enforce)"
MAX_CAPTURE = 2 * 1024 * 1024
CANARY_NAMES = ("AGENT_API_KEY", "AGENT_API_KEY_CODEX", "JUDGE_API_KEY", "SIMULATOR_API_KEY", "HF_TOKEN")
GUEST_CHECKS = {"album_readonly", "context_readonly", "policy_readonly", "memory_alias_readonly",
                "workspace_writable", "home_writable", "secrets_unreadable", "other_user_unreadable",
                "external_network_unreachable", "transport_allowed", "transport_sibling_denied", "credentials_absent"}
REQUIRED = {"outer_policy", "secret_fixture", "runtime_version", "plan_layout", "guest_exit",
            "guest_evidence", "lifecycle", "credential_evidence", "fixture_cleanup"} | GUEST_CHECKS

GUEST = r'''
import errno,json,os,socket,sys
from pathlib import Path
config=json.loads(Path('/tmp/guest-config.json').read_text())
checks=[]
def record(name,ok,**evidence):
    checks.append(dict(test=name,status='PASS' if ok else 'FAIL',**evidence))
for name,path in [('album_readonly','/tmp/album/fixture.txt'),('context_readonly','/tmp/context/fixture.txt'),
                  ('policy_readonly','/tmp/.camact/prompt_policy.json'),('memory_alias_readonly',config['memory']+'/fixture.txt')]:
    try:
        readable=Path(path).is_file() and bool(Path(path).read_text())
        try:
            Path(path).write_text('unexpected mutation')
            record(name,False,readable=readable,error='write unexpectedly allowed')
        except OSError as exc:
            record(name,readable and exc.errno==errno.EROFS,readable=readable,errno=exc.errno)
    except OSError as exc:
        record(name,False,errno=exc.errno)
for name,path in [('workspace_writable','/tmp/writable-proof'),('home_writable','/home/agent/writable-proof')]:
    try:
        Path(path).write_text('synthetic write proof')
        record(name,Path(path).read_text()=='synthetic write proof')
    except OSError as exc:
        record(name,False,errno=exc.errno)
for name,path in [('secrets_unreadable',config['secret']),('other_user_unreadable',config['other_user'])]:
    try:
        Path(path).read_bytes()
        record(name,False,error='unbound synthetic file was readable')
    except OSError as exc:
        record(name,exc.errno in (errno.ENOENT,errno.EACCES,errno.EPERM),errno=exc.errno)
try:
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as client:
        client.settimeout(1)
        result=client.connect_ex(('198.51.100.1',9))
    record('external_network_unreachable',result!=0,errno=result)
except OSError as exc:
    record('external_network_unreachable',True,errno=exc.errno)
try:
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect('/transport/allowed.sock')
        client.sendall(b'synthetic-ping')
        reply=client.recv(64)
    record('transport_allowed',reply==b'synthetic-pong')
except OSError as exc:
    record('transport_allowed',False,errno=exc.errno)
try:
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
        client.settimeout(1)
        client.connect(config['forbidden_socket'])
    record('transport_sibling_denied',False)
except OSError as exc:
    record('transport_sibling_denied',exc.errno in (errno.ENOENT,errno.EACCES,errno.EPERM),errno=exc.errno)
record('credentials_absent',not any(name in os.environ for name in config['credential_names']))
print(json.dumps(dict(schema='camact.production_plan.guest.v1',checks=checks)),flush=True)
sys.exit(0 if all(item['status']=='PASS' for item in checks) else 1)
'''


def add(report, name, passed, **evidence):
    report["tests"].append(dict(test=name, status="PASS" if passed else "FAIL", **evidence))


def outcome(report):
    checks = report["tests"]
    passed = {item["test"] for item in checks if item["status"] == "PASS"}
    report["missing_checks"] = sorted(REQUIRED - passed)
    report["outcome"] = "FAIL" if any(item["status"] == "FAIL" for item in checks) else (
        "INCOMPLETE" if report["missing_checks"] or any(item["status"] != "PASS" for item in checks) else "PASS")
    return report["outcome"]


def bounded(value, available=MAX_CAPTURE):
    text = DIAG.redact(value, limit=None)
    encoded = text.encode("utf-8")
    text = encoded[:available].decode("utf-8", errors="ignore")
    return dict(chunks=[text[index:index + 16000] for index in range(0, len(text), 16000)],
                truncated=len(encoded) > available, captured_bytes=len(text.encode("utf-8")))


def capture(report, name, text):
    used = sum(value["captured_bytes"] for value in report["logs"].values())
    report["logs"][name] = bounded(text, max(0, MAX_CAPTURE - used))


def no_symlinks(path, ancestor):
    if not path.is_absolute() or ".." in path.parts or not path.is_relative_to(ancestor) or path == ancestor:
        raise ValueError("Path is outside the disposable diagnostic data boundary")
    for member in (ancestor, *reversed(path.parents), path):
        if member.is_relative_to(ancestor) and member.is_symlink():
            raise ValueError("Diagnostic paths must not contain symlinks")


def outer_policy(observed):
    ps = observed.get("process_status", {})
    return (platform.system() == "Linux" and platform.machine() == "x86_64"
            and observed.get("uid") == observed.get("gid") == 10001
            and ps.get("NoNewPrivs") == "1" and ps.get("Seccomp") == "2"
            and int(ps.get("CapEff", "1"), 16) == int(ps.get("CapBnd", "1"), 16) == 0
            and observed.get("apparmor_current", {}).get("value", "").strip() == APPARMOR)


def plan_valid(plan, workspace, home, transport, node):
    mounts = plan.get("mounts", [])
    expected = {"/tmp": (workspace, False), "/home/agent": (home, False),
                "/tmp/album": (workspace / "album", True), "/tmp/context": (workspace / "context", True),
                "/tmp/.camact": (workspace / ".camact", True), MEMORY: (workspace / "album", True),
                "/transport": (transport, True), "/opt/node": (node, True),
                "/opt/camact/runtime/0": (ROOT / ".tools/node", True)}
    for target, (source, readonly) in expected.items():
        matches = [mount for mount in mounts if mount.get("destination") == target]
        if len(matches) != 1:
            return False
        actual = matches[0]
        options = set(actual.get("options", []))
        if (actual.get("type") != "bind" or actual.get("source") != str(source.resolve())
                or not {"rbind", "nosuid", "nodev", "ro" if readonly else "rw"}.issubset(options)
                or ("rw" if readonly else "ro") in options):
            return False
    allowed = set(expected) | set(str(path) for path in (
        "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc/ssl/certs", "/etc/fonts", "/etc/ld.so.cache", "/etc/localtime"))
    for mount in mounts:
        if mount.get("type") == "bind" and mount.get("destination") not in expected:
            options = set(mount.get("options", []))
            if (mount.get("source") != mount.get("destination") or "rw" in options
                    or not {"rbind", "nosuid", "nodev", "ro"}.issubset(options)):
                return False
    return (plan.get("schema") == "camact.gvisor.launch.v1" and plan.get("state_parent") == str(STATE)
            and all(mount.get("destination") in allowed for mount in mounts if mount.get("type") == "bind")
            and not any(mount.get("destination") in ("/run/secrets", "/var/lib/camact", "/synthetic/users") for mount in mounts)
            and plan.get("argv", [])[0:1] == [str(Path(sys.executable).resolve())])


def guest_evidence(report, stdout):
    try:
        evidence = json.loads(stdout)
        rows = evidence["checks"]
        names = [item["test"] for item in rows]
        valid = (evidence.get("schema") == "camact.production_plan.guest.v1" and len(names) == len(set(names))
                 and set(names) == GUEST_CHECKS and all(item.get("status") in ("PASS", "FAIL") for item in rows))
    except (ValueError, KeyError, TypeError):
        valid, rows = False, []
    add(report, "guest_evidence", valid)
    if valid:
        report["tests"].extend(rows)


def lifecycle_valid(value, *, cli=False):
    state = Path(value.get("state", ""))
    if cli:
        allowed = (state.parent.name == "gvisor-state" and state.parent.parent.parent == SCRATCH
                   and state.parent.parent.name.startswith("camact-sandbox-check-"))
    else:
        allowed = state.parent == STATE
    return (state.is_absolute() and allowed and state.name.startswith("run-")
            and not state.exists() and isinstance(value.get("guest_environment_keys"), list)
            and value.get("backend") == "gvisor" and value.get("network") == "none"
            and value.get("returncode") == 0 and value.get("cleanup_returncode") == 0
            and value.get("state_removed") is True and value.get("parent_disconnected") is False
            and value.get("host_proc_bound") is False
            and not any(name in value.get("guest_environment_keys", []) for name in CANARY_NAMES))


def clean_evidence(value):
    if isinstance(value, dict):
        return {str(key): clean_evidence(member) for key, member in value.items()}
    if isinstance(value, list):
        return [clean_evidence(member) for member in value]
    return DIAG.redact(value, limit=None) if isinstance(value, str) else value


def run(output, *, check_runtimes=False):
    report = dict(schema="camact.gvisor.production-plan.v1", scope="synthetic_production_builder_only",
                  tests=[], lifecycles=[], logs={}, notes=["No external model request; full benchmark acceptance is not established.",
                  "Seccomp=2 verifies an active filter; exact repository filter parity requires the outer Docker inspect evidence."])
    fixture = None
    listener = blocked = worker = None
    stop = threading.Event()
    stage = "outer_policy"
    try:
        no_symlinks(output, DATA)
        observed = DIAG.environment()
        report["outer_environment"] = observed
        storage = DIAG.mount_state(DATA)
        report["storage"] = storage
        policy_ok = (ROOT == Path("/opt/camact") and outer_policy(observed) and storage.get("exec_allowed") is True
                     and "rw" in storage.get("mount_flags", [])
                     and os.environ.get("CAMACT_GVISOR_STATE_ROOT") == str(STATE))
        add(report, "outer_policy", policy_ok)
        if not policy_ok:
            return report
        stage = "secret_fixture"
        secret_ok = CANARY_PATH.is_file() and not CANARY_PATH.is_symlink() and CANARY_PATH.read_text() == CANARY_CONTENT
        add(report, "secret_fixture", secret_ok, synthetic_only=True)
        if not secret_ok:
            return report
        lock = json.loads((ROOT / "locks/runtimes.json").read_text())
        sys.path.insert(0, str(ROOT))
        from harness.camact_multi_harness_v1.camact_multi import gvisor
        runsc = ROOT / ".tools/gvisor" / lock["gvisor"]["version"] / "runsc"
        version = DIAG.command([runsc, "--version"])
        report["runtime"] = dict(locked_version=lock["gvisor"]["version"], actual=DIAG.redact(version["stdout"]),
                                 builder_sha256=hashlib.sha256(Path(gvisor.__file__).read_bytes()).hexdigest(),
                                 seccomp_file_sha256=hashlib.sha256((ROOT / "deploy/seccomp-gvisor.json").read_bytes()).hexdigest(),
                                 image_version=os.environ.get("CAMACT_IMAGE_VERSION", "unavailable"),
                                 image_revision=os.environ.get("CAMACT_SOURCE_REVISION", "unavailable"))
        version_ok = version["returncode"] == 0 and lock["gvisor"]["version"] in version["stdout"] and gvisor.RUNSC.resolve() == runsc.resolve()
        add(report, "runtime_version", version_ok)
        if not version_ok:
            return report
        stage = "fixture_setup"
        SCRATCH.mkdir(parents=True, exist_ok=True)
        no_symlinks(SCRATCH, DATA)
        fixture = Path(tempfile.mkdtemp(prefix="production-plan-fixture-", dir=SCRATCH))
        workspace, home, transport = (fixture / name for name in ("workspace", "home", "transport"))
        for path in (workspace, home, transport, fixture / "forbidden", fixture / "users/other-user/base_memory"):
            path.mkdir(parents=True, mode=0o700)
        for name in ("album", "context", ".camact"):
            (workspace / name).mkdir(mode=0o700)
        for name in ("album", "context"):
            (workspace / name / "fixture.txt").write_text("Synthetic fixture only\n")
        (workspace / ".camact/prompt_policy.json").write_text(json.dumps(dict(schema_version="camact.system_prompt_policy.v1", memory_root=MEMORY)))
        other = fixture / "users/other-user/base_memory/fixture.txt"
        other.write_text("Synthetic other-user fixture only\n")
        forbidden = fixture / "forbidden/blocked.sock"
        listener, blocked = socket.socket(socket.AF_UNIX), socket.socket(socket.AF_UNIX)
        listener.bind(str(transport / "allowed.sock")); listener.listen(1); listener.settimeout(.2)
        blocked.bind(str(forbidden)); blocked.listen(1)
        def serve():
            while not stop.is_set():
                try:
                    client, _ = listener.accept()
                except socket.timeout:
                    continue
                with client:
                    client.settimeout(2)
                    if client.recv(64) == b"synthetic-ping":
                        client.sendall(b"synthetic-pong")
        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        (workspace / "guest-probe.py").write_text(GUEST)
        (workspace / "guest-config.json").write_text(json.dumps(dict(memory=MEMORY, secret=str(CANARY_PATH),
            other_user=str(other), forbidden_socket=str(forbidden), credential_names=list(CANARY_NAMES))))
        canaries = {name: "synthetic-production-plan-canary-" + name.lower() for name in CANARY_NAMES}
        node = ROOT / ".tools/node/bin/node"
        entry = dict(runtime_roots=[str(ROOT / ".tools/node")], node_executable=str(node))
        env = dict(PATH="/opt:/usr/local/bin:/usr/bin:/bin", HOME="/home/agent", LANG="C.UTF-8", LC_ALL="C.UTF-8",
                   PYTHONDONTWRITEBYTECODE="1", **canaries)
        stage = "build_plan"
        argv = gvisor.command([sys.executable, "/tmp/guest-probe.py"], workspace, home, entry, transport,
                              relay=False, environment=canaries)
        plan_path = Path(argv[-1])
        plan_text = plan_path.read_text()
        plan = json.loads(plan_text)
        report["plan"] = clean_evidence(plan)
        add(report, "plan_layout", plan_valid(plan, workspace, home, transport, node))
        if report["tests"][-1]["status"] != "PASS":
            report["plan"] = clean_evidence(plan)
            return report
        stage = "guest_execution"
        result = DIAG.command(argv, timeout=120, env=env)
        capture(report, "guest_stdout", result["stdout"])
        capture(report, "guest_stderr", result["stderr"])
        add(report, "guest_exit", result["returncode"] == 0 and not result["timed_out"], returncode=result["returncode"])
        guest_evidence(report, result["stdout"])
        lifecycle_path = plan_path.parent / "lifecycle.json"
        lifecycle = json.loads(lifecycle_path.read_text()) if lifecycle_path.is_file() else {}
        add(report, "lifecycle", lifecycle_valid(lifecycle))
        if lifecycle:
            report["lifecycles"].append(lifecycle)
        evidence = plan_text + json.dumps(lifecycle) + result["stdout"] + result["stderr"]
        add(report, "credential_evidence", not any(value in evidence for value in canaries.values()))
        report["plan"], report["lifecycle"] = clean_evidence(plan), clean_evidence(lifecycle)
        if check_runtimes:
            prerequisite = {name for name in REQUIRED if name != "fixture_cleanup"}
            passed = {item["test"] for item in report["tests"] if item["status"] == "PASS"}
            if not prerequisite.issubset(passed):
                report["tests"].append(dict(test="check_runtimes", status="SKIP", detail="Production-plan prerequisite failed"))
            else:
                stage = "check_runtimes"
                cli_env = {**DIAG.SAFE_ENV, "CAMACT_SCRATCH_ROOT": str(SCRATCH), "CAMACT_GVISOR_STATE_ROOT": str(STATE)}
                checked = DIAG.command([sys.executable, "-B", ROOT / "scripts/check-runtimes.py", "--sandbox"], timeout=1000, env=cli_env)
                capture(report, "runtimes_stdout", checked["stdout"])
                capture(report, "runtimes_stderr", checked["stderr"])
                try:
                    runtime_result = json.loads(checked["stdout"])
                    sandbox = runtime_result["sandbox"]
                    cli_ok = set(sandbox) == set(lock["cli"]) | {"credential_boundary"}
                    cli_ok = cli_ok and all(name in sandbox and lifecycle_valid(sandbox[name].get("lifecycle", {}), cli=True)
                        and sandbox[name].get("version") == lock["cli"][name]["version"]
                        and sandbox[name].get("returncode") == 0
                        and lock["cli"][name]["version"] in sandbox[name].get("actual", "") for name in lock["cli"])
                    boundary = sandbox["credential_boundary"]
                    cli_ok = cli_ok and (boundary.get("trusted_credentials_absent") is True
                        and boundary.get("plan_and_lifecycle_canary_values_absent") is True
                        and boundary.get("synthetic_only") is True and boundary.get("checked_names", 0) >= 10
                        and lifecycle_valid(boundary.get("lifecycle", {}), cli=True))
                    report["runtime_checks"] = clean_evidence(sandbox)
                    report["runtime_versions"] = clean_evidence({key: value for key, value in runtime_result.items() if key != "sandbox"})
                    report["lifecycles"].extend(sandbox[name]["lifecycle"] for name in lock["cli"] if name in sandbox)
                    if sandbox["credential_boundary"].get("lifecycle"):
                        report["lifecycles"].append(sandbox["credential_boundary"]["lifecycle"])
                except (ValueError, KeyError, TypeError):
                    cli_ok = False
                add(report, "check_runtimes", checked["returncode"] == 0 and cli_ok)
    except Exception as exc:
        add(report, stage, False, error=DIAG.redact(str(exc)), error_type=type(exc).__name__)
    finally:
        stop.set()
        if worker:
            worker.join(3)
        for connection in (listener, blocked):
            if connection:
                connection.close()
        if fixture is not None:
            try:
                no_symlinks(fixture, SCRATCH)
                if not fixture.name.startswith("production-plan-fixture-") or fixture.stat().st_uid != os.getuid():
                    raise ValueError("Unsafe fixture cleanup target")
                shutil.rmtree(fixture)
                add(report, "fixture_cleanup", not fixture.exists())
            except Exception as exc:
                add(report, "fixture_cleanup", False, error=DIAG.redact(str(exc)))
        if any(log["truncated"] for log in report["logs"].values()):
            report["tests"].append(dict(test="complete_log_capture", status="SKIP", detail="Sanitized combined stdout/stderr exceeded 2 MiB"))
        outcome(report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=SCRATCH / "production-plan-probe-report", type=Path)
    parser.add_argument("--check-runtimes", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    no_symlinks(args.output, DATA)
    report = run(args.output, check_runtimes=args.check_runtimes)
    args.output.mkdir(parents=True, exist_ok=False)
    sanitized = clean_evidence(report)
    (args.output / "report.json").write_text(json.dumps(sanitized, indent=2) + "\n")
    for name in ("plan", "lifecycle"):
        if name in sanitized:
            (args.output / (name + ".json")).write_text(json.dumps(sanitized[name], indent=2) + "\n")
    lines = ["# Synthetic production-plan probe: " + report["outcome"], "",
             "Actual production builder; synthetic fixtures and local UDS only. No model or benchmark run.", "",
             "| Check | Result |", "| --- | --- |"]
    lines.extend("| " + item["test"] + " | " + item["status"] + " |" for item in report["tests"])
    lines.extend(["", *report["notes"], ""])
    (args.output / "summary.md").write_text("\n".join(lines))
    print(json.dumps(dict(outcome=report["outcome"], output=str(args.output), missing_checks=report["missing_checks"])))
    return 0 if report["outcome"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
