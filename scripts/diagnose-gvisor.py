#!/usr/bin/env python3
"""Bounded, credential-free gVisor diagnostics; never change host/container policy."""
from __future__ import annotations

import argparse
import ast
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = Path(__file__).resolve()
PROBES = ("user", "user_mount", "mount", "net")
CLONE_NEWUSER, CLONE_NEWNS, CLONE_NEWNET = 0x10000000, 0x20000, 0x40000000
MS_RDONLY, MS_NOSUID, MS_NODEV = 1, 2, 4
MS_REMOUNT, MS_BIND, MS_REC, MS_PRIVATE = 32, 4096, 16384, 1 << 18
LIBC = ctypes.CDLL(None, use_errno=True)
SAFE_ENV = {"PATH": os.defpath + ":/usr/local/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1", "HOME": "/tmp"}


def redact(value):
    """Sanitize before saving OR displaying; raw command output is memory-only."""
    value = str(value)
    value = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value)
    value = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "?", value)
    value = re.sub(r"\b(?:sk-[\w-]{8,}|hf_[\w-]{8,}|gh[pousr]_[\w-]{8,}|github_pat_[\w-]+)", "<redacted>", value)
    value = re.sub(r"(?i)(authorization\s*[:=]\s*)(?:bearer\s+)?[^\s,;\"']+", r"\1<redacted>", value)
    value = re.sub(r'''(?i)(["']?[\w-]*(?:key|token|password|secret)["']?\s*[=:]\s*)["']?[^\s,;"']+["']?''', r"\1<redacted>", value)
    value = re.sub(r"https?://[^\s\"'<>]+", "<url>", value)
    value = re.sub(r"/(?:home|Users|root)/[^\s\"'<>:]+", "<home-path>", value)
    value = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<ip>", value)
    # Subprocess errors/debug logs have no reason to expose caller workspace paths.
    if ROOT != Path("/"):
        value = value.replace(str(ROOT), "<project>")
    return value[-24000:]


def clean(value):
    if isinstance(value, dict):
        return {str(k): clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [clean(v) for v in value]
    return redact(value) if isinstance(value, str) else value


def row(layer, test, status, *, stage=None, error=None, detail="", stderr="", **extra):
    number = error.errno if isinstance(error, OSError) else None
    return dict(layer=layer, test=test, status=status, stage=stage or test,
                errno=number, errno_name=errno.errorcode.get(number),
                errno_source="syscall" if number is not None else None,
                stderr=redact(stderr or (str(error) if error else "")), detail=redact(detail), **extra)


def command(argv, timeout=20, env=None):
    """Kill the command's process group on timeout, then allow normal cleanup."""
    try:
        with subprocess.Popen([str(v) for v in argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env=env or SAFE_ENV, start_new_session=True) as process:
            try:
                out, err = process.communicate(timeout=timeout)
                return dict(returncode=process.returncode, stdout=out.decode(errors="replace"),
                            stderr=err.decode(errors="replace"), errno=None, timed_out=False)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    out, err = process.communicate(timeout=2)
                except subprocess.TimeoutExpired as exc:
                    # Detached runtime children can retain the pipe descriptors.
                    # Return control to runsc delete / Docker cleanup regardless.
                    out, err = exc.output or b"", exc.stderr or b""
                    process.stdout.close()
                    process.stderr.close()
                    process.wait(timeout=2)
                return dict(returncode=124, stdout=out.decode(errors="replace"),
                            stderr=err.decode(errors="replace"), errno=None, timed_out=True)
    except OSError as exc:
        return dict(returncode=125, stdout="", stderr=str(exc), errno=exc.errno, timed_out=False)


def command_row(layer, test, result, *, detail=""):
    number, source = result["errno"], "exec" if result["errno"] else None
    if number is None:
        # Exit codes are NOT errno. Only classify an explicit, known stderr message.
        for message, candidate in (("operation not permitted", errno.EPERM),
                                   ("permission denied", errno.EACCES),
                                   ("function not implemented", errno.ENOSYS),
                                   ("invalid argument", errno.EINVAL)):
            if message in result["stderr"].lower():
                number, source = candidate, "stderr_inferred"
                break
    item = row(layer, test, "PASS" if result["returncode"] == 0 else "FAIL",
               stage=test + (".timeout" if result["timed_out"] else ""),
               detail=detail, stderr=result["stderr"], exit_code=result["returncode"])
    item.update(errno=number, errno_name=errno.errorcode.get(number), errno_source=source)
    return item


def environment():
    result = {"uid": os.getuid(), "gid": os.getgid(), "pid": os.getpid(), "machine": platform.machine(),
              "kernel": platform.release(), "python": platform.python_version()}
    for name, path in {
        "apparmor_current": "/proc/self/attr/current",
        "apparmor_enabled": "/sys/module/apparmor/parameters/enabled",
        "lsm": "/sys/kernel/security/lsm",
        "unprivileged_userns_clone": "/proc/sys/kernel/unprivileged_userns_clone",
        "apparmor_restrict_unprivileged_userns": "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
        "max_user_namespaces": "/proc/sys/user/max_user_namespaces",
        "max_mnt_namespaces": "/proc/sys/user/max_mnt_namespaces",
        "max_net_namespaces": "/proc/sys/user/max_net_namespaces",
        "uid_map": "/proc/self/uid_map", "gid_map": "/proc/self/gid_map",
    }.items():
        try:
            result[name] = {"status": "PASS", "value": Path(path).read_text().strip()}
        except OSError as exc:
            result[name] = {"status": "SKIP", "errno": exc.errno, "errno_name": errno.errorcode.get(exc.errno)}
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    result["process_status"] = {key: status[key].strip() for key in
                                ("CapEff", "CapBnd", "NoNewPrivs", "Seccomp", "Seccomp_filters") if key in status}
    return result


def syscall(name, *args):
    if getattr(LIBC, name)(*args) != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))


def probe(name, work, layer):
    """Each invocation is a disposable process. Never unshare the controller."""
    stages = [name + ".unshare", name + ".setgroups", name + ".uid_map", name + ".gid_map"]
    stages += {"user": [], "user_mount": ["user_mount.exec_true"],
               "net": ["net.unshare_net"], "mount": ["mount.private", "mount.tmpfs",
                   "mount.tmpfs_write", "mount.tmpfs_unmount", "mount.bind", "mount.readonly",
                   "mount.readonly_enforced", "mount.bind_unmount"]}[name]
    tests, stage = [], stages[0]

    def step(label, action):
        nonlocal stage
        stage = label
        action()
        tests.append(row(layer, label, "PASS"))

    uid, gid = os.getuid(), os.getgid()
    try:
        flags = CLONE_NEWUSER | (CLONE_NEWNS if name in ("user_mount", "mount") else 0)
        step(stages[0], lambda: syscall("unshare", flags))
        step(stages[1], lambda: Path("/proc/self/setgroups").write_text("deny"))
        step(stages[2], lambda: Path("/proc/self/uid_map").write_text(f"{uid} {uid} 1\n"))
        step(stages[3], lambda: Path("/proc/self/gid_map").write_text(f"{gid} {gid} 1\n"))
        if name == "user_mount":
            # Same user+mount flags, single current-ID mapping and exec as Run #5.
            stage = "user_mount.exec_true"
            tests.append(command_row(layer, stage, command(["/bin/true"])))
        elif name == "net":
            step("net.unshare_net", lambda: syscall("unshare", CLONE_NEWNET))
        elif name == "mount":
            step("mount.private", lambda: syscall("mount", None, b"/", None,
                                                   ctypes.c_ulong(MS_REC | MS_PRIVATE), None))
            target, source = work / "target", work / "source"
            target.mkdir(); source.mkdir()
            (source / "canary").write_text("fixture")
            step("mount.tmpfs", lambda: syscall("mount", b"tmpfs", os.fsencode(target), b"tmpfs",
                                                 ctypes.c_ulong(MS_NOSUID | MS_NODEV), b"size=1048576,mode=0700"))
            step("mount.tmpfs_write", lambda: (target / "canary").write_text("fixture"))
            step("mount.tmpfs_unmount", lambda: syscall("umount2", os.fsencode(target), 0))
            step("mount.bind", lambda: syscall("mount", os.fsencode(source), os.fsencode(target), None,
                                                ctypes.c_ulong(MS_BIND | MS_REC), None))
            step("mount.readonly", lambda: syscall("mount", None, os.fsencode(target), None,
                ctypes.c_ulong(MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV), None))

            def readonly():
                try:
                    (target / "canary").write_text("must fail")
                except OSError as exc:
                    if exc.errno == errno.EROFS:
                        return
                    raise
                raise OSError(errno.EIO, "read-only bind allowed a write")
            step("mount.readonly_enforced", readonly)
            step("mount.bind_unmount", lambda: syscall("umount2", os.fsencode(target), 0))
    except OSError as exc:
        tests.append(row(layer, stage, "FAIL", error=exc))
        for pending in stages[stages.index(stage) + 1:]:
            tests.append(row(layer, pending, "SKIP", detail="Blocked by " + stage))
    print(json.dumps(clean(tests)))
    return 0


def namespace_tests(layer, work):
    tests = []
    for name in PROBES:
        with tempfile.TemporaryDirectory(prefix="ns-", dir=work) as directory:
            result = command([sys.executable, "-B", SCRIPT, "--probe", name, "--layer", layer,
                              "--work", directory], timeout=12)
            try:
                rows = json.loads(result["stdout"])
                if result["returncode"] or not isinstance(rows, list) or not rows:
                    raise ValueError("probe did not return results")
                tests.extend(rows)
            except (ValueError, TypeError):
                tests.append(command_row(layer, name + ".collector", {**result,
                    "returncode": result["returncode"] or 125}, detail="Missing/invalid probe JSON"))
    baseline = command(["unshare", "--user", "--map-current-user", "--mount", "true"], 12)
    item = command_row(layer, "original_unshare", baseline,
                       detail="Exact Run #5 command, including util-linux mount propagation and possible executable AppArmor transitions")
    if baseline["errno"] == errno.ENOENT:
        item.update(status="SKIP", detail="unshare executable unavailable; direct syscall tests still ran")
    tests.append(item)
    return tests


def production_flags():
    """Read literal production prefix options without importing/executing a Harness."""
    source = ROOT / "harness/camact_multi_harness_v1/camact_multi/gvisor.py"
    tree = ast.parse(source.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "prefix" for t in node.targets):
            flags = [ast.literal_eval(v) for v in node.value.elts[2:]]
            if flags != ["--platform=systrap", "--network=none", "--gofer-network-namespace=new",
                         "--ignore-cgroups", "--host-uds=open"]:
                raise ValueError("Production runsc prefix changed; review diagnostic parity")
            return flags
    raise ValueError("Production runsc prefix missing")


def gvisor_tests(work, runsc, flags, version):
    tests = []
    result = command([runsc, "--version"])
    item = command_row("gvisor", "version", result)
    if item["status"] == "PASS" and not re.search(r"(?<![0-9])" + re.escape(version) + r"(?![0-9.])", result["stdout"]):
        item.update(status="FAIL", detail="runsc version does not match locks/runtimes.json")
    tests.append(item)
    if item["status"] != "PASS":
        return tests + [row("gvisor", name, "SKIP", detail="Blocked by version")
                        for name in ("run", "delete", "state_absent", "directory_cleanup")], ""
    # Reap detached gofer/sentry processes belonging to this diagnostic process.
    syscall("prctl", 36, 1, 0, 0, 0)  # PR_SET_CHILD_SUBREAPER
    state = Path(tempfile.mkdtemp(prefix="gvisor-", dir=work))
    for name in ("rootfs", "tmp", "home"):
        (state / name).mkdir(mode=0o700)
    uid, gid = os.getuid(), os.getgid()
    mounts = [{"type": "bind", "source": source, "destination": source,
               "options": ["rbind", "nosuid", "nodev", "ro"]}
              for source in ("/usr", "/bin", "/sbin", "/lib", "/lib64") if Path(source).exists()]
    mounts += [{"type": kind, "destination": target} for target, kind in
               (("/proc", "proc"), ("/sys", "sysfs"), ("/dev", "devtmpfs"), ("/dev/pts", "devpts"))]
    mounts += [{"type": "tmpfs", "destination": target,
                "options": ["nosuid", "nodev", "mode=1777", "size=16777216"]}
               for target in ("/tmp", "/run", "/mnt", "/root")]
    spec = {"ociVersion": "1.2.1", "root": {"path": str(state / "rootfs"), "readonly": True},
            "process": {"terminal": False, "user": {"uid": uid, "gid": gid}, "args": ["/bin/true"],
                "cwd": "/tmp", "env": ["PATH=/usr/bin:/bin", "LANG=C.UTF-8"], "noNewPrivileges": True,
                "capabilities": {key: [] for key in ("bounding", "effective", "permitted", "inheritable", "ambient")}},
            "mounts": mounts, "linux": {"namespaces": [{"type": "user"}],
                "uidMappings": [{"containerID": uid, "hostID": uid, "size": 1}],
                "gidMappings": [{"containerID": gid, "hostID": gid, "size": 1}]}}
    (state / "config.json").write_text(json.dumps(spec))
    cid = "camact-diag-" + uuid.uuid4().hex
    debug = state / "debug.log"
    prefix = [str(runsc), f"--root={state}/runtime", *flags]
    env = {**SAFE_ENV, "HOME": str(state / "home"), "TMPDIR": str(state / "tmp")}
    debug_text = ""
    try:
        tests.append(command_row("gvisor", "run", command(prefix + ["--debug", f"--debug-log={debug}",
                                 "run", "--bundle", state, cid], 45, env),
                                 detail="Minimal /bin/true startup and guest exit; production OCI user mapping and prefix"))
    finally:
        tests.append(command_row("gvisor", "delete", command(prefix + ["delete", "--force", cid], 15, env)))
        listing = command(prefix + ["list", "--format=json"], 10, env)
        item = command_row("gvisor", "state_absent", listing)
        try:
            if json.loads(listing["stdout"]) not in (None, []):
                raise ValueError("runtime state remains after delete")
        except ValueError:
            item.update(status="FAIL", detail="Runtime state absent could not be verified")
        tests.append(item)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
                if pid == 0:
                    time.sleep(0.05)
            except ChildProcessError:
                tests.append(row("gvisor", "child_reaping", "PASS"))
                break
        else:
            tests.append(row("gvisor", "child_reaping", "FAIL", detail="Detached child did not exit within 3s"))
        try:
            if debug.is_file():
                debug_text = redact(debug.read_text(errors="replace"))
            if any(t["status"] != "PASS" for t in tests if t["test"] in ("delete", "state_absent", "child_reaping")):
                tests.append(row("gvisor", "directory_cleanup", "SKIP", detail="Runtime cleanup not verified; Docker removal will contain remaining processes"))
            else:
                shutil.rmtree(state)
                tests.append(row("gvisor", "directory_cleanup", "PASS"))
        except OSError as exc:
            tests.append(row("gvisor", "directory_cleanup", "FAIL", error=exc))
    return tests, debug_text


def inside(assets):
    metadata = json.loads((assets / "metadata.json").read_text())
    observed = environment()
    ps = observed["process_status"]
    matches = (os.getuid() == os.getgid() == 10001 and ps.get("NoNewPrivs") == "1"
               and ps.get("Seccomp") == "2" and int(ps.get("CapEff", "1"), 16) == 0
               and int(ps.get("CapBnd", "1"), 16) == 0)
    tests = [row("docker", "process_policy", "PASS" if matches else "FAIL",
                 detail="UID/GID=10001, CapEff=CapBnd=0, NoNewPrivs=1, Seccomp=2")]
    debug = ""
    stage = "namespace_collector"
    try:
        with tempfile.TemporaryDirectory(prefix="camact-diag-") as directory:
            tests += namespace_tests("docker", directory)
        stage = "state_directory"
        state_parent = Path("/var/lib/camact/scratch/gvisor")
        state_parent.mkdir(parents=True, mode=0o700)
        stage = "runtime_collector"
        gvisor, debug = gvisor_tests(state_parent, assets / "gvisor/runsc", metadata["flags"], metadata["version"])
        tests += gvisor
    except Exception as exc:
        tests.append(row("gvisor", stage, "FAIL", error=exc, stderr=str(exc), detail=type(exc).__name__))
    if not matches:
        for item in tests[1:]:
            item.update(observed_status=item["status"], status="SKIP", detail="Process policy mismatch; observations are not comparable")
    print(json.dumps(clean({"environment": observed, "tests": tests, "runsc_debug": debug})))


def download_gvisor(assets, entry):
    url = entry["url"]
    if not re.fullmatch(r"https://storage\.googleapis\.com/gvisor/releases/release/[0-9.]+/x86_64/gvisor\.tar\.bz2", url):
        raise ValueError("Unexpected gVisor lock URL")
    archive = assets / "gvisor.tar.bz2"
    started = time.monotonic()
    with urllib.request.urlopen(url, timeout=30) as response, archive.open("wb") as output:
        while block := response.read(1024 * 1024):
            if output.tell() + len(block) > 150 * 1024 * 1024 or time.monotonic() - started > 120:
                raise ValueError("gVisor download exceeded diagnostic limits")
            output.write(block)
    if hashlib.sha512(archive.read_bytes()).hexdigest() != entry["sha512"]:
        raise ValueError("gVisor SHA512 differs from locks/runtimes.json")
    target = assets / "gvisor"
    target.mkdir()
    with tarfile.open(archive) as package:
        package.extractall(target, filter="data")
    for path in target.rglob("*"):
        if path.is_file():
            path.chmod(0o555)
        elif path.is_dir():
            path.chmod(0o755)
    target.chmod(0o755)
    archive.unlink()


def compose_policy(work):
    # Reset credential-bearing fields BEFORE Compose resolution. Never load .env,
    # models.env, secrets, real data, CLI packages or Benchmark files.
    override = work / "diagnostic-reset.yml"
    override.write_text("services:\n  runner:\n    env_file: !reset []\n    environment: !reset {}\n"
                        "    secrets: !reset []\n    volumes: !reset []\n"
                        "  storage-init:\n    volumes: !reset []\nsecrets: !reset {}\n")
    result = command(["docker", "compose", "--env-file", "/dev/null", "-f", ROOT / "compose.yaml",
                      "-f", override, "config", "--format", "json", "--no-env-resolution", "--no-consistency"])
    if result["returncode"]:
        return None, command_row("docker", "compose_policy", result)
    service = json.loads(result["stdout"])["services"]["runner"]
    valid = (service["user"] == "10001:10001" and service.get("cap_drop") == ["ALL"]
             and not service.get("cap_add") and service.get("read_only") is True
             and service.get("security_opt") == ["no-new-privileges:true", "seccomp=./deploy/seccomp-gvisor.json"]
             and service.get("platform") == "linux/amd64" and service.get("pids_limit") == 4096
             and not service.get("privileged") and not service.get("env_file")
             and not service.get("environment") and not service.get("secrets") and not service.get("volumes"))
    return service, row("docker", "compose_policy", "PASS" if valid else "FAIL",
                        detail="Read actual Compose security fields with credential fields reset; fail closed on policy drift")


def docker_arguments(service, assets, name, image):
    args = ["docker", "create", "--name", name, "--platform", service["platform"],
            "--user", service["user"], "--cap-drop=ALL", "--read-only", "--pids-limit", str(service["pids_limit"]),
            "--security-opt=no-new-privileges:true", "--security-opt=seccomp=" + str(ROOT / "deploy/seccomp-gvisor.json")]
    for mount in service["tmpfs"]:
        args += ["--tmpfs", mount]
    args += ["--tmpfs", "/var/lib/camact:rw,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=0700",
             "--mount", f"type=bind,src={assets},dst=/diagnostic,readonly",
             "--env", "HOME=/run/camact/home", "--env", "PYTHONDONTWRITEBYTECODE=1",
             "--entrypoint", "python3", image, "-B", "/diagnostic/diagnose-gvisor.py", "--inside", "/diagnostic"]
    return args


def inspect_policy(name):
    fields = {"user": ".Config.User", "cap_drop": ".HostConfig.CapDrop", "cap_add": ".HostConfig.CapAdd",
              "read_only": ".HostConfig.ReadonlyRootfs", "privileged": ".HostConfig.Privileged",
              "pids_limit": ".HostConfig.PidsLimit", "apparmor": ".AppArmorProfile", "security_opt": ".HostConfig.SecurityOpt"}
    template = "{" + ",".join('"' + key + '":{{json ' + value + "}}" for key, value in fields.items()) + "}"
    result = command(["docker", "inspect", "--format", template, name])
    if result["returncode"]:
        return command_row("docker", "effective_policy", result), {}
    actual = json.loads(result["stdout"])
    security = actual.pop("security_opt") or []
    profile = next((v.partition("=")[2] for v in security if v.startswith("seccomp=")), "")
    actual["seccomp_matches_repository"] = bool(profile) and json.loads(profile) == json.loads((ROOT / "deploy/seccomp-gvisor.json").read_text())
    actual["no_new_privileges"] = any(v in ("no-new-privileges", "no-new-privileges:true") for v in security)
    matches = (actual["user"] == "10001:10001" and actual["cap_drop"] == ["ALL"] and not actual["cap_add"]
               and actual["read_only"] and not actual["privileged"] and actual["pids_limit"] == 4096
               and actual["seccomp_matches_repository"] and actual["no_new_privileges"])
    return row("docker", "effective_policy", "PASS" if matches else "FAIL"), actual


def audit_records(since):
    """Only parsed security fields, never raw kernel/journal lines or paths."""
    tests, events = [], []
    allowed = {"apparmor", "operation", "profile", "comm", "requested_mask", "denied_mask", "error", "syscall", "arch", "code", "pid"}
    for name, argv in (("journal", ["sudo", "-n", "journalctl", "--kernel", "--since", since, "--no-pager", "--output=cat"]),
                       ("dmesg", ["sudo", "-n", "dmesg", "--since", since])):
        result = command(argv, 10)
        if result["returncode"]:
            item = command_row("audit", name, result,
                               detail="Read-only audit access unavailable; absence of evidence is not success")
            item["status"] = "SKIP"
            tests.append(item)
            continue
        count = 0
        for line in result["stdout"].splitlines():
            if not re.search(r'apparmor="DENIED"|type=(?:1400|1326|AVC|SECCOMP)\b|seccomp.*(?:denied|audit)', line, re.I):
                continue
            fields = {key: quoted or bare for key, quoted, bare in re.findall(r'(\w+)=(?:"([^"\n]*)"|(\S+))', line) if key in allowed}
            if fields:
                timestamp = re.search(r"audit\(([0-9.]+:[0-9]+)\)", line)
                if timestamp:
                    fields["audit_id"] = timestamp[1]
                events.append({"source": name, **fields})
                count += 1
        tests.append(row("audit", name, "PASS" if count else "SKIP",
                         detail=f"{count} security records; correlate comm/pid/time, records may include other runner activity" if count
                         else "No matching records visible; cannot exclude AppArmor/seccomp denials"))
    return tests, clean(events[-100:])


def summarize(report):
    tests = report["tests"]
    required = [t for t in tests if t["layer"] != "audit" and t["test"] != "production_equivalence"]
    outcome = "FAIL" if any(t["status"] == "FAIL" for t in required) else (
        "INCOMPLETE" if not required or any(t["status"] == "SKIP" for t in required) else "PASS")
    report["outcome"] = outcome
    lines = [f"# gVisor environment diagnostics: {outcome}", "",
             "Diagnostic only: a lightweight base image and tmpfs data fixture do not prove full CamAct acceptance.", "",
             "| Layer | Test / failure stage | Result | errno |", "| --- | --- | --- | --- |"]
    for item in tests:
        lines.append(f"| {item['layer']} | {item['stage']} | {item['status']} | {item['errno_name'] or '—'} |")
    lines += ["", "Interpretation:",
              "- Host user/mount failures: inspect runner kernel limits, AppArmor userns policy and audit first.",
              "- Host PASS, Docker namespace/mount FAIL: outer Docker/LSM policy is implicated; EPERM alone cannot distinguish AppArmor from seccomp.",
              "- An AppArmor denial for the relevant comm/pid/operation identifies an LSM block; a SECCOMP record identifies a filter block.",
              "- Namespace/mount/net PASS, runsc FAIL: inspect version, runsc stderr/debug, OCI mapping and flags; runtime-specific policy restrictions remain possible.",
              "- A failed prerequisite or missing audit is inconclusive. Never relax policy merely to obtain PASS.",
              "- All minimal probes PASS: investigate the full image, mounts and production launch plan in the next acceptance run.", ""]
    return "\n".join(lines)


def diagnose(output):
    output.mkdir(parents=True, exist_ok=True)
    report = {"schema": "camact.gvisor.diagnostics.v1", "tests": [], "environments": {},
              "runsc_debug": "", "audit_events": [], "scope": "diagnostic_only"}
    tests = report["tests"]
    since = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    name = "camact-gvisor-diag-" + uuid.uuid4().hex[:12]
    created = False
    temporary = tempfile.TemporaryDirectory(prefix="camact-gvisor-diag-")
    stage = "host.environment"
    try:
        report["environments"]["host"] = environment()
        if platform.system() != "Linux" or platform.machine() != "x86_64":
            tests.append(row("host", "platform", "FAIL", detail="Locked linux/amd64 Linux runtime required"))
            return 1
        work = Path(temporary.name)
        stage = "host.namespaces"
        tests += namespace_tests("host", work)
        tests.append(row("docker", "production_equivalence", "SKIP", detail=
            "Use the exact digest-pinned Python runner base, not the full CamAct image; /var/lib/camact is a UID-10001 tmpfs fixture, not the production bind. No model config/secrets/CLI/Benchmark. Docker default bridge replaces Compose bridge. This is not full image/storage acceptance."))
        stage = "docker.compose_policy"
        service, item = compose_policy(work)
        tests.append(item)
        if item["status"] != "PASS":
            return 1
        stage = "docker.daemon"
        daemon = command(["docker", "info", "--format", "{{json .SecurityOptions}}"])
        tests.append(command_row("docker", "daemon", daemon))
        if daemon["returncode"]:
            return 1
        report["docker_security_options"] = json.loads(daemon["stdout"])
        stage = "docker.base_image"
        image_match = re.search(r"^FROM (python:[^\s]+@sha256:[0-9a-f]{64}) AS runner$", (ROOT / "Dockerfile").read_text(), re.M)
        if not image_match:
            raise ValueError("Digest-pinned production Python base missing")
        image = image_match[1]
        result = command(["docker", "pull", "--platform=linux/amd64", image], 180)
        tests.append(command_row("docker", "base_image", result))
        if result["returncode"]:
            return 1
        assets = work / "assets"
        assets.mkdir(mode=0o755)
        assets.chmod(0o755)
        # Docker's bind target must be readable by UID 10001.
        shutil.copyfile(SCRIPT, assets / SCRIPT.name)
        (assets / SCRIPT.name).chmod(0o444)
        entry = json.loads((ROOT / "locks/runtimes.json").read_text())["gvisor"]
        stage = "gvisor.production_flags"
        flags = production_flags()
        stage = "gvisor.locked_download"
        download_gvisor(assets, entry)
        tests.append(row("gvisor", "locked_download", "PASS", detail="Official archive SHA512 verified; all sidecars retained"))
        (assets / "metadata.json").write_text(json.dumps({"version": entry["version"], "flags": flags}))
        (assets / "metadata.json").chmod(0o444)
        report["runtime"] = {"version": entry["version"], "sha512": entry["sha512"], "flags": flags,
                             "base_image": image}
        stage = "docker.create"
        created = True  # A timed-out create may have created the container.
        result = command(docker_arguments(service, assets, name, image))
        tests.append(command_row("docker", "create", result))
        if result["returncode"]:
            return 1
        stage = "docker.effective_policy"
        item, actual = inspect_policy(name)
        tests.append(item)
        report["effective_docker_policy"] = actual
        if item["status"] != "PASS":
            return 1
        stage = "docker.collector"
        result = command(["docker", "start", "--attach", name], 180)
        tests.append(command_row("docker", "collector", result))
        if result["returncode"]:
            return 1
        nested = json.loads(result["stdout"])
        report["environments"]["docker"] = nested["environment"]
        report["runsc_debug"] = nested["runsc_debug"]
        tests += nested["tests"]
        stage = "docker.apparmor_parity"
        current = nested["environment"]["apparmor_current"]
        if actual.get("apparmor") != "docker-default" or not current.get("value", "").startswith("docker-default"):
            tests.append(row("docker", "apparmor_parity", "SKIP", detail="Run #5 was AppArmor confined; Docker default confinement not verified here"))
            for item in tests:
                if item["layer"] in ("docker", "gvisor") and item["test"] not in ("production_equivalence", "apparmor_parity"):
                    item.update(observed_status=item["status"], status="SKIP", detail="AppArmor condition differs from Run #5; see observed_status")
        else:
            tests.append(row("docker", "apparmor_parity", "PASS", detail=current["value"]))
    except Exception as exc:
        tests.append(row("diagnostic", stage, "FAIL", error=exc,
                         detail=type(exc).__name__, stderr=str(exc)))
    finally:
        if created:
            tests.append(command_row("docker", "container_cleanup", command(["docker", "rm", "--force", name], 20)))
        temporary.cleanup()
        for layer, test in (("docker", "user_mount.unshare"), ("gvisor", "run"), ("gvisor", "delete")):
            if not any(t["layer"] == layer and t["test"] == test for t in tests):
                tests.append(row(layer, test, "SKIP", detail="Prerequisite failed; see first FAIL"))
        audit, events = audit_records(since)
        tests += audit
        report["audit_events"] = events
        summary = summarize(report)
        (output / "report.json").write_text(json.dumps(clean(report), indent=2) + "\n")
        (output / "summary.md").write_text(summary)
        print(summary)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
                stream.write(summary)
    return 0 if report["outcome"] == "PASS" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--probe", choices=PROBES)
    parser.add_argument("--work", type=Path)
    parser.add_argument("--layer", choices=("host", "docker"), default="host")
    parser.add_argument("--inside", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if args.probe:
        return probe(args.probe, args.work, args.layer)
    if args.inside:
        inside(args.inside)
        return 0
    if not args.output:
        parser.error("--output is required")
    return diagnose(args.output)


if __name__ == "__main__":
    raise SystemExit(main())
