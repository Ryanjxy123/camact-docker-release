#!/usr/bin/env python3
"""Verify the actual Compose runner before releasing a synthetic acceptance command."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "camact-gvisor-v1"
READY = "/run/camact/runner-policy.json"
RELEASE = "/run/camact/runner-policy.release"
LIMIT = 2 * 1024 * 1024
OPERATIONS = frozenset({"compose_create", "compose_ps", "created_inspect", "container_start",
    "inside_evidence_read", "started_inspect", "release_write", "container_wait", "container_remove", "compose_down"})
READ_READY_CODE = """import os,stat,sys
try:
    descriptor=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
except FileNotFoundError:
    sys.exit(75)
except OSError:
    sys.exit('ready_open_failed')
try:
    with os.fdopen(descriptor,'rb') as stream:
        metadata=os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=10001 or metadata.st_size>65536:
            sys.exit('unsafe_ready_file')
        content=stream.read(65537)
        if len(content)>65536:
            sys.exit('ready_file_too_large')
except OSError:
    sys.exit('ready_read_failed')
sys.stdout.buffer.write(content)
"""
WRITE_RELEASE_CODE = """import os,sys
try:
    descriptor=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'wb') as stream:
        stream.write(b'verified\\n')
        stream.flush()
        os.fsync(stream.fileno())
except OSError:
    sys.exit('release_write_failed')
"""
TMPFS = {"/run/camact": (256 * 1024**2, "0700"),
         "/run/camact/openclaw": (256 * 1024**2, "0700"), "/tmp": (512 * 1024**2, "1777")}


def sanitized(value):
    spec = importlib.util.spec_from_file_location("runner_policy_diagnostics", ROOT / "scripts/diagnose-gvisor.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    text = str(value)
    for key, content in os.environ.items():
        if content and (key.startswith(("AGENT_API_KEY", "JUDGE_API_KEY", "SIMULATOR_API_KEY"))
                        or key in {"HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HUGGINGFACE_HUB_TOKEN"}):
            text = text.replace(content, "<redacted>")
    return module.redact(text, limit=None)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def handshake_command(container, absolute_path, code):
    if (not isinstance(container, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}", container)
            or not isinstance(absolute_path, str)
            or not re.fullmatch(r"/run/camact/[a-z0-9][a-z0-9_.-]{0,90}", absolute_path)):
        raise ValueError("invalid_handshake_target")
    return ["docker", "exec", container, "python", "-B", "-c", code, absolute_path]


def ready_command(container, absolute_path):
    """Read only a bounded, owner-checked READY file in the live tmpfs namespace."""
    return handshake_command(container, absolute_path, READ_READY_CODE)


def release_command(container, absolute_path):
    """Publish the fixed release marker once, as the container's configured UID."""
    return handshake_command(container, absolute_path, WRITE_RELEASE_CODE)


def flags(path):
    observed = os.statvfs(path).f_flag
    names = [name for name, constant in (("ro", "ST_RDONLY"), ("nosuid", "ST_NOSUID"),
             ("nodev", "ST_NODEV"), ("noexec", "ST_NOEXEC"), ("noatime", "ST_NOATIME"),
             ("nodiratime", "ST_NODIRATIME"), ("relatime", "ST_RELATIME"))
             if observed & getattr(os, constant, 0)]
    if not observed & os.ST_RDONLY:
        names.insert(0, "rw")
    return {"f_flag": observed, "mount_flags": names, "exec_allowed": not bool(observed & os.ST_NOEXEC)}


def inside_evidence():
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    uid, gid = [int(v) for v in status["Uid"].split()], [int(v) for v in status["Gid"].split()]
    capabilities = {key: int(status[key].strip(), 16) for key in ("CapEff", "CapBnd", "CapPrm", "CapInh", "CapAmb")}
    aa = Path("/proc/self/attr/current").read_text().strip()
    mounts = {path: flags(path) for path in ("/", "/var/lib/camact", *TMPFS)}
    data = Path("/var/lib/camact")
    metadata = data.stat()
    pids = Path("/sys/fs/cgroup/pids.max").read_text().strip()
    checks = {"identity": uid == [10001] * 4 and gid == [10001] * 4,
        "capabilities": all(value == 0 for value in capabilities.values()),
        "no_new_privileges": status["NoNewPrivs"].strip() == "1",
        "seccomp": status["Seccomp"].strip() == "2", "apparmor": aa == PROFILE + " (enforce)",
        "root_readonly": "ro" in mounts["/"]["mount_flags"], "pids_limit": pids == "4096",
        "data_bind": not data.is_symlink() and metadata.st_uid == 10001 and metadata.st_gid == 10001
            and stat.S_IMODE(metadata.st_mode) == 0o700 and "rw" in mounts[str(data)]["mount_flags"]
            and mounts[str(data)]["exec_allowed"],
        "tmpfs_flags": all({"rw", "nosuid", "nodev"} <= set(mounts[path]["mount_flags"]) for path in TMPFS)}
    return {"schema": "camact.runner-policy.inside.v1", "result": "PASS" if all(checks.values()) else "FAIL",
            "checks": checks, "uid": uid, "gid": gid, "capabilities": capabilities,
            "no_new_privileges": int(status["NoNewPrivs"]), "seccomp": int(status["Seccomp"]),
            "apparmor": aa, "pids_max": pids, "source_mounts": mounts}


def inside(command):
    try:
        evidence = inside_evidence()
    except (OSError, ValueError, KeyError):
        evidence = {"schema": "camact.runner-policy.inside.v1", "result": "FAIL", "checks": {"collection": False}}
    pending = Path(READY + ".pending")
    write_json(pending, evidence)
    os.replace(pending, READY)
    if evidence["result"] != "PASS":
        return 125
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        gate = Path(RELEASE)
        if gate.is_file() and not gate.is_symlink() and gate.read_text() == "verified\n":
            return subprocess.run(command).returncode if command else 125
        time.sleep(.05)
    return 125


def options(value):
    result = {}
    for token in value.split(","):
        key, separator, content = token.partition("=")
        if key in result:
            raise ValueError("duplicate tmpfs option")
        if key == "size":
            match = re.fullmatch(r"([0-9]+)([kmg]?)", content.lower())
            if not match:
                raise ValueError("invalid tmpfs size")
            content = int(match[1]) * 1024 ** ("kmg".index(match[2]) + 1 if match[2] else 0)
        elif key in {"uid", "gid", "mode"}:
            content = int(content, 8 if key == "mode" else 10)
        result[key] = content if separator else True
    return result


def expected_mounts(config, *, allow_cache=False):
    runner = config["services"]["runner"]
    mounts = {}
    for item in runner.get("volumes", []):
        if item.get("type") != "bind" or item.get("target") in mounts:
            raise ValueError("unexpected runner volume")
        mounts[item["target"]] = (str(Path(item["source"]).resolve()), not item.get("read_only", False))
    for item in runner.get("secrets", []):
        source = item if isinstance(item, str) else item["source"]
        target = source if isinstance(item, str) else item.get("target", source)
        target = target if target.startswith("/") else "/run/secrets/" + target
        if target in mounts:
            raise ValueError("duplicate runner mount")
        mounts[target] = (str(Path(config["secrets"][source]["file"]).resolve()), False)
    required = {"/var/lib/camact", *("/run/secrets/" + role + "_api_key" for role in ("agent", "judge", "simulator"))}
    if ((set(mounts) != required and not (allow_cache and set(mounts) == required | {"/var/lib/camact/benchmark"}))
            or mounts["/var/lib/camact"][1] is not True):
        raise ValueError("runner mount allowlist changed")
    return mounts


def runner_configuration(config):
    """Create a single-service stage without starting any Compose dependency."""
    runner = config["services"]["runner"]
    if (any(runner.get(key) for key in ("depends_on", "links", "volumes_from"))
            or any(isinstance(runner.get(key), str) and runner[key].startswith("service:")
                   for key in ("network_mode", "ipc", "pid", "uts", "cgroup"))):
        raise ValueError("runner_service_dependency_forbidden")
    config["services"] = {"runner": runner}
    return runner


def inspect_errors(actual, config, image, policy, *, started, allow_cache=False):
    expected = expected_mounts(config, allow_cache=allow_cache)
    host = actual.get("HostConfig") or {}
    security = host.get("SecurityOpt") or []
    errors = []
    checks = {"image": actual.get("Image") == image, "user": (actual.get("Config") or {}).get("User") == "10001:10001",
        "cap_drop": host.get("CapDrop") == ["ALL"], "cap_add": not host.get("CapAdd"),
        "readonly": host.get("ReadonlyRootfs") is True, "privileged": host.get("Privileged") is False,
        "pids_limit": host.get("PidsLimit") == 4096, "network": host.get("NetworkMode") == "none",
        "security_options": len(security) == 3 and any(value in ("no-new-privileges", "no-new-privileges:true") for value in security)
            and "apparmor=" + PROFILE in security}
    try:
        filters = [json.loads(value.partition("=")[2]) for value in security if value.startswith("seccomp=")]
        checks["seccomp_filter"] = len(filters) == 1 and filters[0] == policy
    except (ValueError, TypeError):
        checks["seccomp_filter"] = False
    try:
        tmpfs = {target: options(value) for target, value in host.get("Tmpfs", {}).items()}
        wanted = {target: {"rw": True, "nosuid": True, "nodev": True, "size": size,
                  "uid": 10001, "gid": 10001, "mode": int(mode, 8)} for target, (size, mode) in TMPFS.items()}
        checks["tmpfs"] = tmpfs == wanted
    except (ValueError, TypeError):
        checks["tmpfs"] = False
    observed = {}
    if started:
        checks["apparmor_active"] = actual.get("AppArmorProfile") == PROFILE
        checks["running"] = (actual.get("State") or {}).get("Running") is True
        entries = actual.get("Mounts") or []
        for item in entries:
            if item.get("Type") == "tmpfs" and item.get("Destination") in TMPFS:
                continue
            target = item.get("Destination")
            if item.get("Type") != "bind" or target in observed:
                checks["mounts"] = False
                continue
            observed[target] = (str(Path(item.get("Source", "")).resolve()), item.get("RW"))
    else:
        for item in host.get("Mounts") or []:
            target = item.get("Target")
            if item.get("Type") != "bind" or target in observed:
                checks["mounts"] = False
                continue
            observed[target] = (str(Path(item.get("Source", "")).resolve()), not item.get("ReadOnly", False))
        for value in host.get("Binds") or []:
            parts = value.split(":")
            if len(parts) != 3 or parts[1] in observed:
                checks["mounts"] = False
                continue
            observed[parts[1]] = (str(Path(parts[0]).resolve()), "ro" not in parts[2].split(","))
    checks["mounts"] = checks.get("mounts", True) and observed == expected
    errors.extend(name for name, passed in checks.items() if not passed)
    return errors


def run(args, command):
    stage = args.stage
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,90}", stage) or not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image):
        return 125
    output = Path(args.output).resolve()
    private = output / "private"
    public = output / "runner-policy"
    private.mkdir(parents=True, exist_ok=True)
    public.mkdir(parents=True, exist_ok=True)
    report = {"schema": "camact.runner-policy.v1", "stage": stage, "result": "FAIL", "checks": [], "logs": [], "operations": []}
    try:
        config = json.loads(Path(args.compose_config).read_text())
        expected_mounts(config, allow_cache=stage == "full-benchmark-cache-offline-reuse")
        policy = json.loads((ROOT / "deploy/seccomp-gvisor.json").read_text())
        runner = runner_configuration(config)
    except (OSError, ValueError, KeyError, TypeError):
        report.update(failure="runner_configuration_rejected", cleanup_returncode=0)
        write_json(public / (stage + ".json"), report)
        return 125
    runner.setdefault("labels", {})["com.camact.verification"] = args.project
    runner["entrypoint"] = ["python", "-B", "/opt/camact/scripts/verify-runner-policy.py", "inside", "--"]
    runner["command"] = command
    path = private / (stage + "-compose.json")
    write_json(path, config)
    compose = ["docker", "compose", "--env-file", "/dev/null", "--project-directory", str(ROOT),
               "--project-name", args.project + "-" + stage, "-f", str(path)]
    container, result, cleanup = None, 125, None
    diagnostic_bytes = 0
    def failed_operation(operation, *, returncode=None, stderr="", timed_out=False, unavailable=False):
        nonlocal diagnostic_bytes
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        # No argv, environment, inspect stdout or model configuration is public.
        encoded = sanitized(stderr or "").encode("utf-8")
        remaining = max(0, LIMIT - diagnostic_bytes)
        bounded = encoded[:remaining].decode("utf-8", errors="ignore")
        diagnostic_bytes += len(bounded.encode("utf-8"))
        entry = {"operation": operation, "status": "FAIL", "returncode": returncode,
                 "timeout": timed_out, "stderr": bounded, "truncated": len(encoded) > remaining}
        if unavailable:
            entry["failure"] = "command_unavailable"
        report["operations"].append(entry)
    def call(operation, argv, *, check=True, timeout=60):
        if operation not in OPERATIONS:
            raise ValueError("unknown_docker_operation")
        try:
            value = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            failed_operation(operation, stderr=error.stderr, timed_out=True)
            raise
        except OSError:
            failed_operation(operation, unavailable=True)
            raise
        if value.returncode and not (operation == "inside_evidence_read" and value.returncode == 75):
            failed_operation(operation, returncode=value.returncode, stderr=value.stderr)
        if check and value.returncode:
            raise RuntimeError("docker_command_failed")
        return value
    def inspect(started):
        actual = json.loads(call("started_inspect" if started else "created_inspect",
                                 ["docker", "inspect", "--format", "{{json .}}", container]).stdout)
        errors = inspect_errors(actual, config, args.image, policy, started=started,
                                allow_cache=stage == "full-benchmark-cache-offline-reuse")
        report["checks"].append({"test": "started_hostconfig" if started else "created_hostconfig", "errors": errors,
                                 "status": "FAIL" if errors else "PASS"})
        if errors:
            raise RuntimeError("runner_host_policy_failed")
    try:
        call("compose_create", compose + ["create", "--no-build", "--pull", "never", "runner"], timeout=120)
        container = call("compose_ps", compose + ["ps", "--all", "--quiet", "runner"]).stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{12,64}", container):
            raise RuntimeError("runner_identity_missing")
        inspect(False)
        call("container_start", ["docker", "start", container])
        ready_content = None
        deadline = time.monotonic() + 20
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            observed = call("inside_evidence_read", ready_command(container, READY), check=False, timeout=min(5, remaining))
            if observed.returncode == 75:
                time.sleep(min(.1, max(0, deadline - time.monotonic())))
                continue
            if observed.returncode:
                raise RuntimeError("inside_evidence_read_failed")
            ready_content = observed.stdout
            break
        if ready_content is None or len(ready_content.encode("utf-8")) > 65536:
            raise RuntimeError("inside_evidence_missing")
        evidence = json.loads(ready_content)
        checks = evidence.get("checks")
        required = {"identity", "capabilities", "no_new_privileges", "seccomp", "apparmor", "root_readonly", "pids_limit", "data_bind", "tmpfs_flags"}
        if (evidence.get("schema") != "camact.runner-policy.inside.v1" or evidence.get("result") != "PASS"
                or not isinstance(checks, dict) or set(checks) != required or any(value is not True for value in checks.values())):
            raise RuntimeError("inside_policy_failed")
        report["inside"] = evidence
        inspect(True)
        call("release_write", release_command(container, RELEASE), timeout=5)
        wait = call("container_wait", ["docker", "wait", container], timeout=args.timeout)
        result = int(wait.stdout.strip())
        report["command_exit_code"] = result
        report["result"] = "PASS" if result == 0 else "FAIL"
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError):
        report["failure"] = "runner_policy_or_execution_failed"
    finally:
        if container:
            try:
                paths = {stream: private / (stage + "-container-" + stream + ".log") for stream in ("stdout", "stderr")}
                with paths["stdout"].open("wb") as out, paths["stderr"].open("wb") as err:
                    subprocess.run(["docker", "logs", container], stdout=out, stderr=err, timeout=60, check=True)
                for stream in ("stdout", "stderr"):
                    with paths[stream].open("rb") as source:
                        value = source.read(LIMIT + 65536).decode(errors="replace")
                    # The caller keeps raw logs private; uploaded logs are bounded and sanitized.
                    print(value[:LIMIT], end="", file=sys.stdout if stream == "stdout" else sys.stderr)
                    encoded = sanitized(value).encode("utf-8")
                    log = public / (stage + "-" + stream + ".log")
                    log.write_text(encoded[:LIMIT].decode("utf-8", errors="ignore"), encoding="utf-8")
                    report["logs"].append({"path": log.name, "truncated": paths[stream].stat().st_size > LIMIT or len(encoded) > LIMIT})
            except (OSError, subprocess.SubprocessError):
                result, report["result"] = 125, "FAIL"
                report["failure"] = "log_collection_failed"
            finally:
                try:
                    cleanup = call("container_remove", ["docker", "rm", "--force", container], check=False).returncode
                except (OSError, subprocess.SubprocessError):
                    cleanup = 125
        else:
            try:
                cleanup = call("compose_down", compose + ["down", "--remove-orphans"], check=False).returncode
            except (OSError, subprocess.SubprocessError):
                cleanup = 125
        report["cleanup_returncode"] = cleanup
        if cleanup:
            result, report["result"] = 125, "FAIL"
        write_json(public / (stage + ".json"), report)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inside", "run", "sanitize"))
    parser.add_argument("--compose-config")
    parser.add_argument("--project")
    parser.add_argument("--image")
    parser.add_argument("--output")
    parser.add_argument("--stage")
    parser.add_argument("--timeout", type=int, default=1800)
    args, command = parser.parse_known_args(argv)
    if command[:1] == ["--"]:
        command = command[1:]
    if args.action == "sanitize":
        content = sys.stdin.buffer.read(LIMIT + 65536)
        text = sanitized(content.decode(errors="replace"))
        sys.stdout.write(text.encode()[:LIMIT].decode(errors="ignore"))
        if len(content) > LIMIT:
            sys.stdout.write("\n[capture truncated at 2 MiB]\n")
        return 0
    if args.action == "inside":
        return inside(command)
    return run(args, command)


if __name__ == "__main__":
    raise SystemExit(main())
