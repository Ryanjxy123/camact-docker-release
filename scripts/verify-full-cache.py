#!/usr/bin/env python3
"""Opt-in full HF cache validation; no task selection, Guest or model execution."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from release import benchmark

SCHEMA = "camact.full-cache-validation.v1"
IMAGE_SCHEMA = "camact.verified-image.v1"
PROFILE = "camact-gvisor-v1"
CACHE = Path("/var/lib/camact/benchmark")
READY = "/run/camact/full-cache-ready.json"
RELEASE = "/run/camact/full-cache.release"
STAGES = ("download", "offline-1", "offline-2")
CALLS = ("metadata", "download", "token", "hf_api", "hf_file", "hf_snapshot",
         "httpx", "httpx_async", "requests", "socket", "socket_helper", "dns")
INNER_CHECKS = {"identity", "capabilities", "no_new_privileges", "seccomp", "apparmor",
                "root_readonly", "pids_limit", "data_bind", "tmpfs_flags", "credential_environment"}
HEX = re.compile(r"[0-9a-f]{64}")
SHA = re.compile(r"[0-9a-f]{40}")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
RUN_LABEL = re.compile(r"(?:[1-9][0-9]{0,19}-[1-9][0-9]{0,9}|local-[0-9a-f]{32})")


class ValidationError(RuntimeError):
    """Only fixed, non-sensitive reason codes belong in this exception."""


def require(condition, reason):
    if not condition:
        raise ValidationError(reason)


def validation_run_label():
    run, attempt = os.environ.get("GITHUB_RUN_ID"), os.environ.get("GITHUB_RUN_ATTEMPT")
    if run is not None or attempt is not None:
        value = str(run) + "-" + str(attempt)
        require(RUN_LABEL.fullmatch(value), "invalid_validation_run_label")
        return value
    return "local-" + uuid.uuid4().hex


def cleanup_scope(run, kind):
    """Recover only this job's containers; unexpected leftovers always fail."""
    report = {"schema": "camact.validation-cleanup.v1", "result": "FAIL", "validation_run": run,
              "validation_kind": kind, "unexpected_containers": 0, "remaining_containers": None}
    try:
        require(isinstance(run, str) and RUN_LABEL.fullmatch(run)
                and kind in {"full-cache", "recovery"}, "invalid_cleanup_scope")
        inventory = ["docker", "ps", "--all", "--quiet", "--filter", "label=camact.validation-run=" + run,
                     "--filter", "label=camact.validation-kind=" + kind]
        def containers():
            value = subprocess.run(inventory, capture_output=True, text=True, timeout=60)
            require(value.returncode == 0, "cleanup_inventory_failed")
            identifiers = value.stdout.split()
            require(len(identifiers) == len(set(identifiers))
                    and all(re.fullmatch(r"[0-9a-f]{12,64}", value) for value in identifiers), "cleanup_inventory_invalid")
            return identifiers
        found = containers()
        report["unexpected_containers"] = len(found)
        removals = []
        for identifier in found:
            try:
                removals.append(subprocess.run(["docker", "rm", "--force", identifier], capture_output=True,
                                               text=True, timeout=60).returncode)
            except (OSError, subprocess.SubprocessError):
                removals.append(125)
        remaining = containers()
        report["remaining_containers"] = len(remaining)
        if not found and not remaining and all(code == 0 for code in removals):
            report["result"] = "PASS"
    except (OSError, subprocess.SubprocessError, ValidationError):
        report["failure"] = "scoped_cleanup_failed"
    print(json.dumps(report, sort_keys=True))
    return 0 if report["result"] == "PASS" else 1


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def read_object(path, maximum=65536):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum, "summary_missing_or_unsafe")
    result = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(result, dict), "summary_shape")
    return result


def zero_calls(value):
    return (isinstance(value, dict) and set(value) == set(CALLS)
            and all(type(count) is int and count == 0 for count in value.values()))


def failure_reason(exc):
    if isinstance(exc, ValidationError):
        return str(exc)
    if isinstance(exc, benchmark.BenchmarkError):
        match = re.search(r"HTTP (401|403|404|429|500|502|503|504)\b", str(exc))
        if match:
            return "hf_http_" + match[1]
        if "offline" in str(exc).lower():
            return "offline_cache_incomplete_or_invalid"
        return "benchmark_integrity_or_download_failed"
    if isinstance(exc, subprocess.TimeoutExpired):
        return "operation_timeout"
    if isinstance(exc, OSError):
        return "filesystem_or_process_failure"
    return "invalid_validation_evidence"


class OfflineGuard:
    """Production offline paths must not request a client, credential or socket."""
    def __init__(self):
        self.calls = dict.fromkeys(CALLS, 0)
        self.stack = ExitStack()

    def blocked(self, name):
        def reject(*_args, **_kwargs):
            self.calls[name] += 1
            raise ValidationError("offline_external_entrypoint_called")
        return reject

    def __enter__(self):
        targets = {"metadata": "release.benchmark._metadata", "download": "release.benchmark._download",
            "token": "release.benchmark._token", "hf_api": "huggingface_hub.HfApi",
            "hf_file": "huggingface_hub.hf_hub_download", "hf_snapshot": "huggingface_hub.snapshot_download",
            "httpx": "httpx.Client.request", "httpx_async": "httpx.AsyncClient.request",
            "requests": "requests.sessions.Session.request", "socket": "socket.socket.connect",
            "socket_helper": "socket.create_connection", "dns": "socket.getaddrinfo"}
        try:
            for name, target in targets.items():
                self.stack.enter_context(patch(target, side_effect=self.blocked(name)))
        except BaseException:
            self.stack.close()
            raise
        return self

    def __exit__(self, *args):
        return self.stack.__exit__(*args)


def cache_summary(snapshot, repo, revision):
    """Read metadata privately; export only counts and whole-document hashes."""
    directory = Path(snapshot).parent
    manifest = benchmark._validate_manifest(read_object(directory / "manifest.json", 64 * 1024**2), repo, revision)
    marker = read_object(directory / "complete.json")
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    expected = {"schema": benchmark.SCHEMA, "repo_id": repo, "revision": revision,
        "file_count": len(manifest["files"]), "total_bytes": sum(value["size"] for value in manifest["files"].values()),
        "manifest_sha256": hashlib.sha256(encoded).hexdigest()}
    require(marker == expected, "completion_marker_mismatch")
    require(marker["file_count"] > 0 and marker["total_bytes"] > 0, "empty_complete_cache")
    return {**expected, "marker_sha256": digest(directory / "complete.json"),
        "git_sha1_files": sum(value["algorithm"] == "git-sha1" for value in manifest["files"].values()),
        "lfs_sha256_files": sum(value["algorithm"] == "sha256" for value in manifest["files"].values())}


def memory_layout(cache_root, repo, revision):
    """Check raw_root/alias layout under a shared lease, without loading Tasks."""
    try:
        with OfflineGuard() as guard, benchmark.lease(cache_root, repo, revision, offline=True) as snapshot:
            snapshot = Path(snapshot).resolve(strict=True)
            manifest = benchmark._validate_manifest(read_object(snapshot.parent / "manifest.json", 64 * 1024**2), repo, revision)
            files = set(manifest["files"])
            tasks = []
            for name in files:
                parts = PurePosixPath(name).parts
                if len(parts) == 4 and parts[0] == "tasks" and parts[2].startswith("task_") and parts[3] == "task.yaml":
                    tasks.append((parts[1], parts[2]))
            require(bool(tasks), "memory_layout_invalid")
            absolute = 0
            for user, task in tasks:
                relative = f"tasks/{user}/{task}/workspace/memory_snapshot/memory_manifest.json"
                require(relative in files, "memory_layout_invalid")
                path = benchmark._plain_path(snapshot, relative)
                document = read_object(path, 4 * 1024**2)
                raw = document.get("runtime_root")
                require(isinstance(raw, str) and bool(raw) and "\0" not in raw and "\\" not in raw, "memory_layout_invalid")
                root = Path(raw)
                expected = benchmark._plain_path(snapshot, f"users/{user}/base_memory")
                require(expected.is_dir() and not expected.is_symlink(), "memory_layout_invalid")
                canonical = expected.resolve(strict=True)
                if root.is_absolute():
                    absolute += 1
                    require(".." not in root.parts and not raw.startswith("//"), "memory_layout_invalid")
                    policy_root = root  # raw_root preserves the absolute Path string.
                else:
                    policy_root = (path.parent / root).resolve()
                require(policy_root.resolve() == canonical and str(policy_root) == str(canonical), "memory_layout_invalid")
            require(zero_calls(guard.calls), "memory_layout_invalid")
            return {"tasks": len(tasks), "users": len({user for user, _ in tasks}),
                "absolute_roots": absolute, "relative_roots": len(tasks) - absolute,
                "all_current_user_snapshot_roots_match": True, "alias_contract_valid": True}
    except (OSError, ValueError, KeyError, TypeError, ValidationError, benchmark.BenchmarkError):
        raise ValidationError("memory_layout_invalid") from None


def lock_child(cache_root, repo, revision, kind):
    with OfflineGuard() as guard:
        if kind == "shared":
            with benchmark.lease(cache_root, repo, revision, offline=True):
                return {"acquired": True, "calls": guard.calls}
        _, lock_path = benchmark._location(cache_root, repo, revision)
        descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except BlockingIOError:
                acquired = False
            return {"acquired": acquired, "calls": guard.calls}
        finally:
            os.close(descriptor)


def child_lock(cache_root, repo, revision, kind):
    completed = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "lock-child",
        "--cache-root", str(cache_root), "--repo-id", repo, "--revision", revision, "--kind", kind],
        capture_output=True, text=True, timeout=120)
    require(completed.returncode == 0, "lease_child_failed")
    value = json.loads(completed.stdout)
    require(set(value) == {"acquired", "calls"} and type(value["acquired"]) is bool
            and zero_calls(value["calls"]), "lease_child_evidence_invalid")
    return value["acquired"]


def validate_cache(cache_root, repo, revision, *, offline, workers=8):
    if not offline:
        # The production downloader explicitly supplies token=False; no personal
        # HOME/HF_TOKEN is used. No task package or Guest is ever imported here.
        require(not os.environ.get("HF_TOKEN_FILE"), "explicit_hf_token_not_enabled")
        snapshot = benchmark.ensure(cache_root, repo, revision, max_workers=workers)
        return {"cache": cache_summary(snapshot, repo, revision), "offline": None}
    with OfflineGuard() as guard:
        # Offline acceptance must not repair/recreate a missing marker even
        # though production ensure can reconstruct one from complete files.
        directory, _ = benchmark._location(cache_root, repo, revision)
        previous = cache_summary(directory / "snapshot", repo, revision)
        snapshot = benchmark.ensure(cache_root, repo, revision, offline=True)
        first = cache_summary(snapshot, repo, revision)
        require(first == previous, "offline_completion_marker_changed")
        require(snapshot == benchmark.ensure(cache_root, repo, revision, offline=True), "offline_snapshot_changed")
        with benchmark.lease(cache_root, repo, revision, offline=True) as leased:
            require(leased == snapshot and cache_summary(leased, repo, revision) == first, "leased_snapshot_changed")
            locks = {"exclusive_blocked_during_lease": not child_lock(cache_root, repo, revision, "exclusive"),
                     "shared_reader_during_lease": child_lock(cache_root, repo, revision, "shared")}
        locks["exclusive_acquired_after_lease"] = child_lock(cache_root, repo, revision, "exclusive")
        require(all(locks.values()), "lease_lock_contract_failed")
        require(guard.calls == dict.fromkeys(CALLS, 0), "offline_entrypoint_count_nonzero")
        return {"cache": first, "offline": {"calls": guard.calls, "locks": locks, "ensure_count": 2, "lease_count": 1}}


def runner_policy():
    spec = importlib.util.spec_from_file_location("full_cache_runner_policy", ROOT / "scripts/verify-runner-policy.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inside_checks():
    observed = runner_policy().inside_evidence()
    checks = dict(observed.get("checks", {}))
    forbidden = ("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HUGGINGFACE_HUB_TOKEN", "HF_TOKEN_FILE")
    checks["credential_environment"] = (not any(name in os.environ for name in forbidden)
        and not any(name.startswith(("AGENT_API_KEY", "JUDGE_API_KEY", "SIMULATOR_API_KEY")) for name in os.environ)
        and os.environ.get("HF_HUB_DISABLE_IMPLICIT_TOKEN") == "1"
        and os.environ.get("HF_HUB_DISABLE_TELEMETRY") == "1"
        and os.environ.get("HF_HUB_DISABLE_PROGRESS_BARS") == "1"
        and os.environ.get("HF_HOME") == "/var/lib/camact/cache/huggingface"
        and os.environ.get("HF_XET_CACHE") == "/var/lib/camact/cache/huggingface/xet")
    require(set(checks) == INNER_CHECKS and all(value is True for value in checks.values()), "inside_runner_policy_failed")
    return checks


def inside(args):
    result = {"schema": SCHEMA, "stage": args.stage, "status": "FAIL", "external_model_requests": 0,
              "canonical_tasks_run": 0, "errors": []}
    try:
        require(args.stage in STAGES, "invalid_stage")
        require(platform.system() == "Linux" and platform.machine() == "x86_64", "unsupported_platform")
        result["security"] = inside_checks()
        require(os.environ.get("CAMACT_SOURCE_REVISION") == args.expected_source_revision
                and os.environ.get("CAMACT_IMAGE_VERSION") == args.version
                and os.environ.get("CAMACT_IMAGE_DIGEST") == args.image_id, "inside_image_identity_mismatch")
        write(READY + ".pending", {"schema": SCHEMA, "status": "PASS", "security": result["security"]})
        os.replace(READY + ".pending", READY)
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            path = Path(RELEASE)
            if path.is_file() and not path.is_symlink() and path.read_text() == "verified\n":
                break
            time.sleep(.05)
        else:
            raise ValidationError("host_policy_release_missing")
        result.update(validate_cache(CACHE, benchmark.DEFAULT_REPO, benchmark.DEFAULT_REVISION,
                                     offline=args.stage != "download"))
        result["memory_layout"] = memory_layout(CACHE, benchmark.DEFAULT_REPO, benchmark.DEFAULT_REVISION)
        result["status"] = "PASS"
    except Exception as exc:
        result["errors"].append(failure_reason(exc))
    write(args.output, result)
    return 0 if result["status"] == "PASS" else 1


def verify_run(run, *, repository, source, current_source):
    require(SHA.fullmatch(source or "") and source == current_source, "checkout_source_mismatch")
    require(run.get("status") == "completed" and run.get("conclusion") == "success"
        and run.get("event") == "workflow_dispatch" and run.get("path") == ".github/workflows/publish.yml"
        and run.get("head_sha") == source and (run.get("head_repository") or {}).get("full_name") == repository,
        "verified_run_provenance_mismatch")


def verify_provenance(run, manifest, *, repository, source, version, current_source):
    verify_run(run, repository=repository, source=source, current_source=current_source)
    require(set(manifest) == {"schema", "image_id", "source_revision", "version", "image_archive_sha256"}
        and manifest.get("schema") == IMAGE_SCHEMA and IMAGE_ID.fullmatch(manifest.get("image_id", ""))
        and manifest.get("source_revision") == source and manifest.get("version") == version
        and HEX.fullmatch(manifest.get("image_archive_sha256", "")), "verified_image_manifest_mismatch")


def verify_archive(directory, manifest):
    directory = Path(directory)
    archive = directory / "image.tar.zst"
    require(not directory.is_symlink() and archive.is_file() and not archive.is_symlink()
        and 0 < archive.stat().st_size <= 4 * 1024**3
        and {path.name for path in directory.iterdir()} == {"image-manifest.json", "image.tar.zst"}
        and digest(archive) == manifest["image_archive_sha256"], "image_archive_mismatch")
    return archive


def image_identity(actual, manifest):
    config = actual.get("Config") or {}
    labels = config.get("Labels") or {}
    env = dict(item.split("=", 1) for item in config.get("Env", []) if isinstance(item, str) and "=" in item)
    require(actual.get("Id") == manifest["image_id"] and actual.get("Os") == "linux" and actual.get("Architecture") == "amd64"
        and labels.get("org.opencontainers.image.revision") == manifest["source_revision"]
        and labels.get("org.opencontainers.image.version") == manifest["version"]
        and env.get("CAMACT_SOURCE_REVISION") == manifest["source_revision"]
        and env.get("CAMACT_IMAGE_VERSION") == manifest["version"], "loaded_image_identity_mismatch")


def mounts_match(actual, source, *, started, helper=False):
    expected = {"/var/lib/camact": (str(Path(source).resolve()), True)}
    if helper:
        expected["/secrets"] = (str(Path(source).parent / "empty-secrets"), True)
    seen = {}
    for entry in actual:
        if started and entry.get("Type") == "tmpfs" and entry.get("Destination") in runner_policy().TMPFS:
            continue
        target = entry.get("Destination" if started else "Target")
        if entry.get("Type") != "bind" or target in seen:
            return False
        seen[target] = (str(Path(entry.get("Source", "")).resolve()), entry.get("RW") if started else not entry.get("ReadOnly", False))
    return seen == expected


def container_errors(actual, manifest, source, tmpfs, seccomp, *, started, stage=None):
    helper = stage is None
    host = actual.get("HostConfig") or {}
    security = host.get("SecurityOpt") or []
    caps = {value.removeprefix("CAP_") for value in host.get("CapAdd") or []}
    checks = {"image": actual.get("Image") == manifest["image_id"],
        "user": (actual.get("Config") or {}).get("User") == ("0:0" if helper else "10001:10001"),
        "cap_drop": host.get("CapDrop") == ["ALL"], "cap_add": caps == ({"CHOWN", "DAC_OVERRIDE", "FOWNER"} if helper else set()),
        "readonly": host.get("ReadonlyRootfs") is True, "privileged": host.get("Privileged") is False,
        "network": host.get("NetworkMode") == ("bridge" if stage == "download" else "none"),
        "tmpfs": (host.get("Tmpfs") or {}) == ({} if helper else tmpfs)}
    # Requested binds live under HostConfig; active binds come from .Mounts.
    checks["mounts"] = not host.get("Binds") and mounts_match(
        (actual.get("Mounts") or []) if started else (host.get("Mounts") or []), source, started=started, helper=helper)
    if helper:
        checks["security"] = not security
    else:
        filters = [value.partition("=")[2] for value in security if value.startswith("seccomp=")]
        try:
            filter_matches = len(filters) == 1 and json.loads(filters[0]) == seccomp
        except (ValueError, TypeError):
            filter_matches = False
        checks.update(pids=host.get("PidsLimit") == 4096, security=len(security) == 3
            and any(value in {"no-new-privileges", "no-new-privileges:true"} for value in security)
            and "apparmor=" + PROFILE in security and filter_matches)
    checks["apparmor"] = actual.get("AppArmorProfile") in (("docker-default" if helper else PROFILE,) if started else ("", "docker-default" if helper else PROFILE))
    if started and not helper:
        checks["running"] = (actual.get("State") or {}).get("Running") is True
    return sorted(key for key, passed in checks.items() if not passed)


def validate_inner(value, stage, *, expected_memory_layout=None):
    require(set(value) == {"schema", "stage", "status", "external_model_requests", "canonical_tasks_run", "errors", "security", "cache", "offline", "memory_layout"}
        and value["schema"] == SCHEMA and value["stage"] == stage and value["status"] == "PASS"
        and value["errors"] == [] and type(value["external_model_requests"]) is int and value["external_model_requests"] == 0
        and type(value["canonical_tasks_run"]) is int and value["canonical_tasks_run"] == 0
        and set(value["security"]) == INNER_CHECKS and all(item is True for item in value["security"].values()), "inner_summary_failed")
    layout = value["memory_layout"]
    require(isinstance(layout, dict) and set(layout) == {"tasks", "users", "absolute_roots", "relative_roots",
            "all_current_user_snapshot_roots_match", "alias_contract_valid"}
        and all(type(layout[name]) is int and layout[name] >= 0 for name in ("tasks", "users", "absolute_roots", "relative_roots"))
        and 0 < layout["users"] <= layout["tasks"] and layout["absolute_roots"] + layout["relative_roots"] == layout["tasks"]
        and layout["all_current_user_snapshot_roots_match"] is True and layout["alias_contract_valid"] is True,
        "memory_layout_summary_invalid")
    if expected_memory_layout is not None:
        require(layout == expected_memory_layout, "memory_layout_changed")
    cache = value["cache"]
    require(set(cache) == {"schema", "repo_id", "revision", "file_count", "total_bytes", "manifest_sha256", "marker_sha256", "git_sha1_files", "lfs_sha256_files"}
        and cache["schema"] == benchmark.SCHEMA and cache["repo_id"] == benchmark.DEFAULT_REPO
        and cache["revision"] == benchmark.DEFAULT_REVISION
        and all(type(cache[name]) is int and cache[name] >= 0 for name in ("file_count", "total_bytes", "git_sha1_files", "lfs_sha256_files"))
        and cache["file_count"] > 0 and cache["total_bytes"] > 0
        and cache["git_sha1_files"] + cache["lfs_sha256_files"] == cache["file_count"]
        and HEX.fullmatch(cache["manifest_sha256"]) and HEX.fullmatch(cache["marker_sha256"]), "cache_summary_invalid")
    if stage == "download":
        require(value["offline"] is None, "download_summary_invalid")
    else:
        offline = value["offline"]
        require(isinstance(offline, dict) and set(offline) == {"calls", "locks", "ensure_count", "lease_count"}
            and zero_calls(offline["calls"]) and type(offline["ensure_count"]) is int and offline["ensure_count"] == 2
            and type(offline["lease_count"]) is int and offline["lease_count"] == 1
            and offline["locks"] == {"exclusive_blocked_during_lease": True, "shared_reader_during_lease": True,
                                     "exclusive_acquired_after_lease": True}
            and all(item is True for item in offline["locks"].values()), "offline_summary_invalid")


class Controller:
    def __init__(self, args):
        self.args = args
        self.output = Path(args.output).absolute()
        self.private = self.output / "private"
        self.data = self.private / "data"
        self.scanned = False
        self.manifest = None
        self.containers = set()
        self.container_labels = {"camact.validation-run": validation_run_label(), "camact.validation-kind": "full-cache"}
        self.report = {"schema": SCHEMA, "result": "FAIL", "tests": [], "containers": [], "stages": [],
            "external_model_requests": 0, "canonical_tasks_run": 0, "private_data_uploaded": False}

    def check(self, name, condition):
        self.report["tests"].append({"test": name, "status": "PASS" if condition else "FAIL"})
        require(condition, name)

    def call(self, argv, *, timeout=60, check=True):
        result = subprocess.run([str(value) for value in argv], capture_output=True, text=True, timeout=timeout)
        if check:
            require(result.returncode == 0, "external_command_failed")
        return result

    def read_ready(self, name, path):
        # docker cp opens a separate filesystem view whose tmpfs is not the
        # live container tmpfs. Use the existing non-root process namespace.
        command = runner_policy().ready_command(name, path)
        deadline = time.monotonic() + 25
        while (remaining := deadline - time.monotonic()) > 0:
            observed = self.call(command, timeout=min(5, remaining), check=False)
            if observed.returncode == 75:
                time.sleep(min(.1, remaining))
                continue
            require(observed.returncode == 0 and len(observed.stdout.encode("utf-8")) <= 65536,
                    "inside_policy_handshake_failed")
            value = json.loads(observed.stdout)
            require(isinstance(value, dict), "inside_policy_handshake_failed")
            return value
        raise ValidationError("inside_policy_handshake_missing")

    def release(self, name, path):
        self.call(runner_policy().release_command(name, path), timeout=5)

    def inspect(self, name, *, helper=False, started=False, stage=None):
        actual = json.loads(self.call(["docker", "inspect", "--format", "{{json .}}", name]).stdout)
        errors = container_errors(actual, self.manifest, self.data, self.tmpfs, self.seccomp,
                                  started=started, stage=None if helper else stage)
        labels = (actual.get("Config") or {}).get("Labels") or {}
        if not isinstance(labels, dict) or any(labels.get(key) != value for key, value in self.container_labels.items()):
            errors.append("validation_labels")
        self.report["containers"].append({"stage": "storage-init" if helper else stage,
            "phase": "started" if started else "created", "image_id": actual.get("Image"),
            "errors": errors, "status": "FAIL" if errors else "PASS"})
        self.check(("storage-init" if helper else stage) + ("_started_policy" if started else "_created_policy"), not errors)

    def image(self):
        source = self.call(["git", "rev-parse", "HEAD"]).stdout.strip()
        self.check("checkout_source", source == self.args.expected_source_revision == os.environ.get("GITHUB_SHA", source))
        self.check("run_id", bool(re.fullmatch(r"[1-9][0-9]{0,19}", self.args.image_run_id)))
        repository = self.args.repository
        self.check("repository", bool(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)))
        self.check("workflow_repository", repository == os.environ.get("GITHUB_REPOSITORY", repository))
        self.check("explicit_version", bool(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9_.-]+)?", self.args.version)))
        run = json.loads(self.call(["gh", "api", "repos/" + repository + "/actions/runs/" + self.args.image_run_id]).stdout)
        verify_run(run, repository=repository, source=self.args.expected_source_revision, current_source=source)
        target = self.private / "verified-image"
        target.mkdir()
        self.call(["gh", "run", "download", self.args.image_run_id, "--repo", repository,
                   "--name", "camact-verified-image", "--dir", target], timeout=600)
        manifest = read_object(target / "image-manifest.json")
        verify_provenance(run, manifest, repository=repository, source=self.args.expected_source_revision,
                          version=self.args.version, current_source=source)
        archive = verify_archive(target, manifest)
        self.check("image_archive", True)
        with subprocess.Popen(["zstd", "--decompress", "--stdout", str(archive)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as unpacked:
            try:
                loaded = subprocess.run(["docker", "load"], stdin=unpacked.stdout, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, timeout=300)
                unpacked.stdout.close()
                self.check("image_load", loaded.returncode == 0 and unpacked.wait(timeout=30) == 0)
            finally:
                if unpacked.poll() is None:
                    unpacked.kill()
                    unpacked.wait()
        identity = json.loads(self.call(["docker", "image", "inspect", "--format", "{{json .}}", manifest["image_id"]]).stdout)
        image_identity(identity, manifest)
        scan = self.call([sys.executable, "scripts/scan-image.py", "--image", manifest["image_id"]], timeout=600, check=False)
        observed = json.loads(scan.stdout)
        self.check("complete_image_scan", scan.returncode == 0 and observed.get("result") == "PASS"
            and observed.get("issue_count") == 0 and observed.get("issues") == []
            and type(observed.get("files_scanned")) is int and observed["files_scanned"] > 0)
        self.report["image_scan"] = {key: observed[key] for key in ("result", "issue_count", "files_scanned", "bytes_scanned")}
        self.manifest = manifest
        self.scanned = True
        self.report["image"] = {**manifest, "image_run_id": self.args.image_run_id}

    def compose(self):
        override = self.private / "credential-reset.yml"
        override.write_text("services:\n  runner:\n    env_file: !reset []\n    environment: !reset {}\n"
            "    secrets: !reset []\n    volumes: !reset []\n  storage-init:\n    volumes: !reset []\nsecrets: !reset {}\n", encoding="utf-8")
        config = json.loads(self.call(["docker", "compose", "--profile", "tools", "--env-file", "/dev/null",
            "--project-directory", ROOT, "-f", ROOT / "compose.yaml", "-f", override, "config", "--format", "json",
            "--no-env-resolution", "--no-consistency"]).stdout)
        runner, storage = config["services"]["runner"], config["services"]["storage-init"]
        self.check("compose_policy", runner.get("user") == "10001:10001" and runner.get("read_only") is True
            and runner.get("cap_drop") == ["ALL"] and not runner.get("cap_add") and runner.get("pids_limit") == 4096
            and runner.get("platform") == "linux/amd64" and not runner.get("privileged")
            and runner.get("security_opt") == ["no-new-privileges:true", "seccomp=./deploy/seccomp-gvisor.json", "apparmor=" + PROFILE]
            and not any(runner.get(key) for key in ("env_file", "environment", "secrets", "volumes"))
            and storage.get("user") == "0:0" and storage.get("cap_drop") == ["ALL"]
            and set(storage.get("cap_add", [])) == {"CHOWN", "DAC_OVERRIDE", "FOWNER"}
            and storage.get("network_mode") == "none" and storage.get("read_only") is True
            and storage.get("entrypoint") == ["python", "-B", "/opt/camact/scripts/init-storage.py"]
            and not any(storage.get(key) for key in ("privileged", "security_opt", "environment", "env_file", "secrets", "volumes")))
        policy = runner_policy()
        self.tmpfs = dict(item.split(":", 1) for item in runner["tmpfs"])
        wanted = {target: {"rw": True, "nosuid": True, "nodev": True, "size": size,
            "uid": 10001, "gid": 10001, "mode": int(mode, 8)} for target, (size, mode) in policy.TMPFS.items()}
        self.check("compose_tmpfs", {target: policy.options(options) for target, options in self.tmpfs.items()} == wanted)
        self.seccomp = json.loads((ROOT / "deploy/seccomp-gvisor.json").read_text())

    def create(self, name, *, stage=None):
        self.check("scan_before_" + (stage or "storage-init"), self.scanned and self.manifest is not None)
        helper = stage is None
        args = ["docker", "create", "--name", name, "--platform=linux/amd64", "--user", "0:0" if helper else "10001:10001",
                "--cap-drop=ALL", "--read-only", "--network=" + ("bridge" if stage == "download" else "none"),
                "--mount", "type=bind,src=" + str(self.data) + ",dst=/var/lib/camact"]
        for key, value in self.container_labels.items():
            args += ["--label", key + "=" + value]
        if helper:
            for cap in ("CHOWN", "DAC_OVERRIDE", "FOWNER"):
                args += ["--cap-add", cap]
            args += ["--mount", "type=bind,src=" + str(self.private / "empty-secrets") + ",dst=/secrets"]
            command = ["-B", "/opt/camact/scripts/init-storage.py"]
        else:
            args += ["--pids-limit=4096", "--security-opt=no-new-privileges:true",
                "--security-opt=seccomp=" + str(ROOT / "deploy/seccomp-gvisor.json"), "--security-opt=apparmor=" + PROFILE]
            for target, value in self.tmpfs.items():
                args += ["--tmpfs", target + ":" + value]
            args += ["--env", "CAMACT_IMAGE_DIGEST=" + self.manifest["image_id"]]
            command = ["-B", "/opt/camact/scripts/verify-full-cache.py", "inside", "--stage", stage,
                "--expected-source-revision", self.args.expected_source_revision, "--version", self.args.version,
                "--image-id", self.manifest["image_id"], "--output", "/var/lib/camact/checkpoints/" + stage + ".json"]
        args += ["--entrypoint", "python", self.manifest["image_id"], *command]
        self.containers.add(name)  # A timed-out create can still create its name.
        self.call(args, timeout=120)
        self.inspect(name, helper=helper, stage=stage)

    def cleanup(self, name):
        removed = self.call(["docker", "rm", "--force", name], check=False)
        self.check("container_cleanup", removed.returncode == 0)
        self.containers.discard(name)

    def storage(self):
        self.data.mkdir()
        (self.private / "empty-secrets").mkdir()
        name = "camact-full-cache-init-" + str(os.getpid())
        try:
            self.create(name)
            self.call(["docker", "start", "--attach", name], timeout=120)
            self.inspect(name, helper=True, started=True)
        finally:
            if name in self.containers:
                self.cleanup(name)

    def stage(self, stage):
        name = "camact-full-cache-" + stage + "-" + str(os.getpid())
        try:
            self.create(name, stage=stage)
            self.call(["docker", "start", name])
            evidence = self.read_ready(name, READY)
            self.check(stage + "_inside_policy", set(evidence) == {"schema", "status", "security"}
                and evidence["schema"] == SCHEMA and evidence["status"] == "PASS"
                and set(evidence["security"]) == INNER_CHECKS and all(item is True for item in evidence["security"].values()))
            self.inspect(name, started=True, stage=stage)
            self.release(name, RELEASE)
            waited = self.call(["docker", "wait", name], timeout=12600 if stage == "download" else 600)
            local = self.private / (stage + "-summary.json")
            self.call(["docker", "cp", name + ":/var/lib/camact/checkpoints/" + stage + ".json", local])
            value = read_object(local)
            if value.get("status") != "PASS":
                # Never copy arbitrary error text or failed payloads to public files.
                reasons = value.get("errors", [])
                known = {"hf_http_" + str(code) for code in (401, 403, 404, 429, 500, 502, 503, 504)}
                reason = next((item for item in reasons if item in known), "cache_stage_failed")
                raise ValidationError(reason)
            self.check(stage + "_exit", waited.stdout.strip() == "0")
            validate_inner(value, stage, expected_memory_layout=self.report["stages"][0]["memory_layout"] if self.report["stages"] else None)
            if self.report["stages"]:
                self.check(stage + "_same_complete_snapshot", value["cache"] == self.report["stages"][0]["cache"])
            self.report["stages"].append(value)
        finally:
            if name in self.containers:
                self.cleanup(name)

    def run(self):
        os.umask(0o077)
        self.output.mkdir(parents=True, exist_ok=True)
        self.private.mkdir(exist_ok=False)
        try:
            memory = next(int(line.split()[1]) * 1024 for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemTotal:"))
            resources = {"cpus": os.cpu_count() or 0, "memory_bytes": memory, "disk_free_bytes": shutil.disk_usage(self.output).free}
            self.report["host_resources"] = resources
            self.check("host_resources", platform.system() == "Linux" and platform.machine() == "x86_64"
                and resources["cpus"] >= 2 and memory >= 4 * 1024**3 and resources["disk_free_bytes"] >= 16 * 1024**3)
            self.image()
            self.compose()
            self.storage()
            for stage in STAGES:
                self.stage(stage)
            self.check("three_recreated_containers", len(self.report["stages"]) == 3)
            self.report["result"] = "PASS"
        except Exception as exc:
            self.report["failure"] = failure_reason(exc)
        finally:
            for name in tuple(self.containers):
                try:
                    self.cleanup(name)
                except Exception:
                    self.report["failure"] = "container_cleanup_failed"
                    self.report["result"] = "FAIL"
            write(self.output / "report.json", self.report)
            public = {"schema": SCHEMA, "result": self.report["result"], "image": self.report.get("image"),
                "benchmark_revision": benchmark.DEFAULT_REVISION, "cache": self.report["stages"][0]["cache"] if self.report["stages"] else None,
                "memory_layout": self.report["stages"][0]["memory_layout"] if self.report["stages"] else None,
                "completed_stages": [value["stage"] for value in self.report["stages"]], "private_data_uploaded": False,
                "external_model_requests": 0, "canonical_tasks_run": 0, "failure": self.report.get("failure")}
            write(self.output / "summary.json", public)
            write(self.output / "manifest.json", {"schema": "camact.full-cache-artifacts.v1", "files": ["README.md", "manifest.json", "report.json", "summary.json", "cleanup.json"],
                "private_directory_excluded": True, "image_run_id": self.args.image_run_id,
                "cleanup_recorded_by_workflow": True,
                "source_revision": self.args.expected_source_revision, "version": self.args.version})
            (self.output / "README.md").write_text("# Full HF cache validation\n\nResult: " + self.report["result"]
                + "\n\nOpt-in final-image download and two network-disabled recreated-container validations. "
                "No Guest, model or canonical task was started. Public evidence is limited to the files in manifest.json. "
                "The independent workflow cleanup.json records recovery and can fail the job without rewriting this validation result. "
                "The private directory contains dataset/cache/image inputs and is never an artifact, Git change or registry publication. "
                "Cloud runner disposal removes its private storage. This validation does not prove Docker stop/resume.\n", encoding="utf-8")
        print(json.dumps({"schema": SCHEMA, "result": self.report["result"], "completed_stages": len(self.report["stages"]),
                          "failure": self.report.get("failure")}, sort_keys=True))
        return 0 if self.report["result"] == "PASS" else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "inside", "lock-child", "cleanup"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--image-run-id")
    parser.add_argument("--repository")
    parser.add_argument("--expected-source-revision")
    parser.add_argument("--version", default="0.1.0-rc.1")
    parser.add_argument("--image-id")
    parser.add_argument("--stage", choices=STAGES)
    parser.add_argument("--cache-root", type=Path)
    parser.add_argument("--repo-id")
    parser.add_argument("--revision")
    parser.add_argument("--kind", choices=("exclusive", "shared"))
    parser.add_argument("--validation-run")
    parser.add_argument("--validation-kind", choices=("full-cache", "recovery"))
    args = parser.parse_args(argv)
    if args.action == "cleanup":
        return cleanup_scope(args.validation_run, args.validation_kind)
    if args.action == "lock-child":
        try:
            print(json.dumps(lock_child(args.cache_root, args.repo_id, args.revision, args.kind)))
            return 0
        except Exception:
            return 1
    if args.action == "inside":
        return inside(args)
    if not all((args.output, args.image_run_id, args.repository, args.expected_source_revision)):
        parser.error("run requires explicit output, repository, image run ID and expected source revision")
    return Controller(args).run()


if __name__ == "__main__":
    raise SystemExit(main())
