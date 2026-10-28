#!/usr/bin/env python3
"""Host/container probes plus a minimal lifecycle using the production builder."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from release.diagnostics import PREFIX, exception_info, path_status, stderr_summary


def probe_tools():
    # Share syscall probes with the lightweight workflow; no Docker invocation,
    # download or controller entrypoint is executed by importing this module.
    spec = importlib.util.spec_from_file_location("camact_namespace_diagnostics", PROJECT / "scripts/diagnose-gvisor.py")
    diagnostic = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(diagnostic)
    return diagnostic


def namespace_diagnostics(context, parent):
    diagnostic = probe_tools()
    rows = diagnostic.namespace_tests("host" if context == "host" else "docker", parent)
    return [{"stage": row["stage"], "result": row["status"], "errno": row["errno"],
             "errno_name": row["errno_name"], "errno_source": row.get("errno_source"),
             "stderr_summary": stderr_summary(row.get("stderr", ""))} for row in rows]


def security_state():
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)

    def integer(path):
        try:
            return int(Path(path).read_text().strip())
        except (OSError, ValueError):
            return None

    try:
        profile = Path("/proc/self/attr/current").read_text().strip()
        apparmor = {"confined": profile != "unconfined",
                    "mode": "enforce" if profile.endswith("(enforce)") else
                            "complain" if profile.endswith("(complain)") else "unknown"}
    except OSError as exc:
        apparmor = {"confined": None, **exception_info(exc)}
    caps = status.get("CapEff", "").strip()
    return {"uid": os.getuid(), "gid": os.getgid(),
            "seccomp_mode": int(status.get("Seccomp", "-1")),
            "seccomp_filters": int(status.get("Seccomp_filters", "-1")),
            "no_new_privileges": int(status.get("NoNewPrivs", "-1")),
            "effective_capabilities": caps if re.fullmatch(r"[0-9a-f]{16}", caps) else None,
            "apparmor": apparmor,
            "unprivileged_userns_clone": integer("/proc/sys/kernel/unprivileged_userns_clone"),
            "max_user_namespaces": integer("/proc/sys/user/max_user_namespaces"),
            "apparmor_restrict_unprivileged_userns": integer("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
            "selinux_enforcing": integer("/sys/fs/selinux/enforce")}


def execute(argv, *, timeout=15, include_stderr=False):
    # Share bounded pipe handling with the lightweight controller. A detached
    # supervisor retaining stdout/stderr must not prevent failure reporting.
    process = probe_tools().command(argv, timeout=timeout,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
    return {"exit_code": process["returncode"], "errno": process["errno"],
            "timed_out": process["timed_out"], "stderr_summary": stderr_summary(process["stderr"])}, \
        process["stdout"] + (process["stderr"] if include_stderr else "")


def runsc_probe(state_parent=None):
    result = {"result": "FAIL", "stage": "configuration"}
    try:
        from harness.camact_multi_harness_v1.camact_multi import gvisor
        lock = json.loads((PROJECT / "locks/runtimes.json").read_text())["gvisor"]
        expected = PROJECT / ".tools/gvisor" / lock["version"] / "runsc"
        result["configuration"] = {"binary_present": expected.is_file(),
            "binary_executable": os.access(expected, os.X_OK),
            "configured_binary_matches_lock": gvisor.RUNSC == expected,
            "sidecars_present": (expected.parent / "gvisor-bin").is_dir()}
        if not all(result["configuration"].values()):
            return result
        result["stage"] = "version"
        version, output = execute([str(expected), "--version"])
        version["matches_lock"] = lock["version"] in output
        result["version"] = version
        if version["exit_code"] or not version["matches_lock"]:
            return result
        result["stage"] = "flags"
        flags, output = execute([str(expected), "flags"], include_stderr=True)
        flags["supported"] = {flag: bool(re.search(r"(?m)^\s*-" + re.escape(flag) + r"(?:[\s=]|$)", output))
                              for flag in ("root", "platform", "network", "gofer-network-namespace", "ignore-cgroups", "host-uds")}
        result["flags"] = flags
        if flags["exit_code"] or not all(flags["supported"].values()):
            return result
        result["stage"] = "state_directory"
        parent = state_parent or os.environ.get("CAMACT_SCRATCH_ROOT") or tempfile.gettempdir()
        result["state_parent"] = path_status(parent, probe=True)
        if result["state_parent"].get("write_probe") != "PASS":
            return result
        with tempfile.TemporaryDirectory(prefix="camact-gvisor-diagnostic-", dir=parent) as temporary:
            state = Path(temporary)
            workspace, home = state / "workspace", state / "home"
            workspace.mkdir(mode=0o700)
            home.mkdir(mode=0o700)
            result["stage"] = "production_plan"
            argv = gvisor.command(["/usr/bin/python3", "-c", "print('camact-gvisor-minimal-ok')"],
                                  workspace, home, {}, relay=False,
                                  environment={"HOME": "/home/agent", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
            plan_path = Path(argv[-1])
            plan = json.loads(plan_path.read_text())
            plan["state_parent"] = str(state / "runtime")
            plan_path.write_text(json.dumps(plan) + "\n")
            result["stage"] = "runsc_run"
            process, output = execute(argv, timeout=45)
            process["guest_marker_seen"] = output.strip() == "camact-gvisor-minimal-ok"
            result["run"] = process
            lifecycle_path = plan_path.parent / "lifecycle.json"
            if process["exit_code"] == 124:
                # Observe this invocation's cleanup; never start a second run.
                deadline = time.monotonic() + 20
                while not lifecycle_path.exists() and time.monotonic() < deadline:
                    time.sleep(.1)
            result["lifecycle_present"] = lifecycle_path.is_file()
            if lifecycle_path.is_file():
                lifecycle = json.loads(lifecycle_path.read_text())
                result["cleanup"] = {"exit_code": lifecycle.get("cleanup_returncode"),
                    "state_removed": lifecycle.get("state_removed"),
                    "stderr_summary": stderr_summary(lifecycle.get("cleanup_stderr", ""))}
            if process["exit_code"] == 0 and process["guest_marker_seen"]:
                result["stage"] = "runsc_cleanup"
                if result.get("cleanup", {}).get("exit_code") == 0 and result["cleanup"].get("state_removed") is True:
                    result.update(result="PASS", stage="complete")
            return result
    except Exception as exc:
        result.update(exception_info(exc))
        return result


def diagnose(context, *, namespace_only=False):
    report = {"schema": "camact.sandbox-diagnostics.v1", "diagnostic_only": True, "context": context}
    try:
        report["security"] = security_state()
        with tempfile.TemporaryDirectory(prefix="camact-namespace-diagnostics-") as parent:
            report["namespaces"] = namespace_diagnostics(context, parent)
        if not namespace_only:
            report["runsc"] = runsc_probe()
    except Exception as exc:
        report["collector_error"] = exception_info(exc)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", choices=("host", "container"), default="container")
    parser.add_argument("--namespace-only", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    report = diagnose(args.context, namespace_only=args.namespace_only)
    print(PREFIX + json.dumps(report, sort_keys=True), flush=True)
    # Namespace/runsc observations are diagnostic; the existing native runtime
    # gate remains mandatory, and this command cannot approve publication.
    return 1 if "collector_error" in report else 0


if __name__ == "__main__":
    raise SystemExit(main())
