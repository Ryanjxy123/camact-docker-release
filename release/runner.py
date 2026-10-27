"""Container entrypoint; retain the existing formal executor and durable scheduler."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from . import benchmark
from . import config as settings

PROJECT = settings.PROJECT
IMPORT_ROOTS = ("", "benchmark", "harness/camact_multi_harness_v1", "harness/claude code", "harness/baseline harness", "deployment")
for relative in IMPORT_ROOTS:
    sys.path.insert(0, str(PROJECT / relative))
os.environ["PYTHONPATH"] = os.pathsep.join(str(PROJECT / relative) for relative in IMPORT_ROOTS)
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
os.environ["PYTHONNOUSERSITE"] = "1"


def scheduler():
    import full_benchmark
    return full_benchmark


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_files():
    result = {}
    for directory in ("release", "deployment", "scripts", "camact_eval", "benchmark/benchmark_runner", "benchmark/evaluator", "benchmark/services", "evaluation", "harness"):
        for path in (PROJECT / directory).rglob("*"):
            if path.is_file() and not path.is_symlink() and path.suffix in {".py", ".json", ".cjs", ".rs", ".toml", ".lock"}:
                if "__pycache__" not in path.parts and "target" not in path.parts:
                    result[path.relative_to(PROJECT).as_posix()] = sha(path)
    return result


def verify_source(archive):
    record = json.loads((archive / "source-version.json").read_text())
    manifest = json.loads((archive / "run_manifest.json").read_text())
    if sha(archive / "source-version.json") != manifest["source_version_sha256"]:
        raise ValueError("Frozen source-version document changed")
    if source_files() != record["files"]:
        raise ValueError("Runtime source changed since preparation; resume with the original image")


def results_root(value=None):
    path = Path(value or os.environ.get("CAMACT_RESULTS_ROOT") or Path(os.environ.get("CAMACT_DATA_ROOT", "/var/lib/camact")) / "results").resolve()
    path.mkdir(parents=True, exist_ok=True)
    os.environ["CAMACT_RESULTS_ROOT"] = str(path)
    return path


def archive_path(run_id, root=None):
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,119}", run_id or "") or run_id in {".", ".."}:
        raise ValueError("Run ID must be a 1–120 character safe name")
    parent = results_root(root)
    path = parent / run_id
    if path.is_symlink():
        raise ValueError("Run directory must not be a symbolic link")
    return path


def bind_benchmark(snapshot):
    """One container has one immutable data root; benchmark Python stays in image."""
    link = Path(os.environ.get("CAMACT_BENCHMARK_LINK", "/run/camact/benchmark"))
    link.parent.mkdir(parents=True, exist_ok=True)
    if link.is_symlink():
        if link.resolve() == snapshot.resolve():
            return
        link.unlink()
    elif link.exists():
        raise ValueError("Runtime Benchmark link is occupied by a real directory")
    link.symlink_to(snapshot.resolve(), target_is_directory=True)
    # Baseline's existing entrypoint deliberately resolves PROJECT/benchmark.
    # Dockerfile supplies these links; a missing/mismatched mount must fail
    # before the scheduler can issue any model request.
    for name in ("tasks", "users", "benchmark_manifest.json"):
        member = PROJECT / "benchmark" / name
        if not member.exists() or member.resolve() != (snapshot / name).resolve():
            raise ValueError("Benchmark data mapping is missing; use the supplied image entrypoint")


@contextmanager
def data_lease(args, *, record=None):
    repo = record["repo_id"] if record else args.repo_id
    revision = record["revision"] if record else args.revision
    cache_root = Path(record["cache_root"]) if record else args.cache_root
    with benchmark.lease(cache_root, repo, revision, offline=args.offline) as snapshot:
        if args.snapshot and Path(args.snapshot).resolve() != snapshot.resolve():
            raise ValueError("Explicit snapshot must equal the fully verified pinned cache snapshot")
        if record and str(snapshot) != record["snapshot"]:
            raise ValueError("Frozen Benchmark path changed")
        bind_benchmark(snapshot)
        yield snapshot


def resource_check(root):
    free = shutil.disk_usage(root).free
    minimum_disk = int(os.environ.get("CAMACT_MIN_DISK_BYTES", str(2 * 1024**3)))
    if free < minimum_disk:
        raise ValueError("Insufficient free disk space in persistent results")
    memory = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        fields = line.split()
        memory[fields[0].rstrip(":")] = int(fields[1]) * 1024
    available = memory.get("MemAvailable", 0)
    try:
        limit = int(Path("/sys/fs/cgroup/memory.max").read_text())
        used = int(Path("/sys/fs/cgroup/memory.current").read_text())
        available = min(available, max(0, limit - used))
    except (OSError, ValueError):
        pass
    if available < int(os.environ.get("CAMACT_MIN_MEMORY_BYTES", str(1024**3))):
        raise ValueError("Insufficient available memory for evaluation startup")
    with tempfile.NamedTemporaryFile(dir=root) as probe:
        probe.write(b"camact persistence preflight\n")
        probe.flush()
        os.fsync(probe.fileno())
    return {"disk_free_bytes": free, "memory_available_bytes": available, "write_fsync": True}


def preflight(config, selected, root, *, runtimes=True):
    settings.validate(config, selected)
    from evaluation.camact_eval.environment import evaluation_environment
    environment = evaluation_environment(require_formal=True)
    resources = resource_check(root)
    if runtimes:
        check = subprocess.run([sys.executable, "-B", str(PROJECT / "scripts/check-runtimes.py"), "--sandbox"],
                               cwd=PROJECT, text=True, capture_output=True)
        if check.returncode:
            raise ValueError("Pinned CLI / codec / gVisor lifecycle verification failed; run scripts/check-runtimes.py --sandbox")
    return {"python": environment["python"], "formal_evaluator": environment["formal"], "resources": resources}


def selected_tasks(snapshot, args, chosen):
    users = sorted(p.name for p in (snapshot / "tasks").iterdir() if p.is_dir() and list(p.glob("task_*/task.yaml")))
    wanted = users if args.all_users else [x.strip() for x in (args.users or "").split(",") if x.strip()]
    if not wanted or len(set(wanted)) != len(wanted) or set(wanted) - set(users):
        raise ValueError("Select --all-users or existing, unique --users IDs")
    tasks = []
    import yaml
    for user in users:
        if user not in wanted:
            continue
        for path in sorted((snapshot / "tasks" / user).glob("task_*/task.yaml")):
            spec = yaml.safe_load(path.read_text())
            for method in chosen:
                tasks.append({"user_id": user, "task": path.parent.name, "task_id": spec["task_id"],
                    "task_type": spec.get("task_type", spec.get("interaction_type")), "harness": method,
                    "harness_label": scheduler().LABELS[method], "status": "pending", "scored": False,
                    "reward": None, "strict": None, "infrastructure_error": False, "attempts": []})
    return [u for u in users if u in wanted], tasks


def prepare(args, snapshot):
    engine = scheduler()
    path = archive_path(args.run_id, args.results_root)
    if path.exists():
        raise ValueError("Run directory already exists; choose another ID or use resume")
    chosen = settings.methods(args.harness)
    config = settings.build(snapshot)
    checks = preflight(config, chosen, path.parent)
    users, tasks = selected_tasks(snapshot, args, chosen)
    path.mkdir(mode=0o700, exist_ok=False)
    for directory in ("audit", "aggregate", "users"):
        (path / directory).mkdir()
    engine.write(path / "formal_config.json", config)
    files = source_files()
    source = {"schema_version": "camact.source.v1", "files": files,
              "digest": hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()}
    engine.write(path / "source-version.json", source)
    manifest = {"schema_version": "camact.docker_run.v1", "run_id": args.run_id,
        "created_at": engine.now(), "status": "prepared", "users": users, "requested_harnesses": chosen,
        "tasks": tasks, "parallel": args.parallel, "max_infrastructure_attempts": args.infrastructure_attempts,
        "config": str(path / "formal_config.json"), "config_sha256": engine.sha(path / "formal_config.json"),
        "source_version_sha256": engine.sha(path / "source-version.json"), "model_config_id": settings.identifier(config),
        "benchmark": {"repo_id": args.repo_id, "revision": args.revision,
                      "snapshot": str(snapshot), "cache_root": str(args.cache_root.resolve())},
        "image": {"version": os.environ.get("CAMACT_IMAGE_VERSION", "local"),
                  "digest": os.environ.get("CAMACT_IMAGE_DIGEST", "unavailable"),
                  "source_revision": os.environ.get("CAMACT_SOURCE_REVISION", "source-snapshot")},
        "harness_versions": {name: settings.VERSIONS.get(name, "canonical-python-source") for name in chosen},
        "preflight": checks, "resource_control": {"max_concurrent_tasks": args.parallel}, "service_ready_timeout_seconds": 60}
    engine.save(path, manifest)
    engine.report(path, manifest)
    return path


def status(path):
    engine = scheduler()
    manifest = engine.read(path / "run_manifest.json")
    return {name: manifest.get(name) for name in ("run_id", "status", "updated_at", "status_counts", "users",
        "requested_harnesses", "parallel", "new_attempts_started", "new_valid_scores", "active_tasks", "benchmark", "image")}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "run", "resume", "status", "logs"))
    parser.add_argument("--run-id")
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--harness", default="all")
    users = parser.add_mutually_exclusive_group()
    users.add_argument("--all-users", action="store_true")
    users.add_argument("--users", "--user", dest="users")
    parser.add_argument("--parallel", type=int, default=1)
    parser.add_argument("--infrastructure-attempts", type=int, choices=(1, 2, 3), default=1)
    parser.add_argument("--repo-id", default=os.environ.get("BENCHMARK_REPO", benchmark.DEFAULT_REPO))
    parser.add_argument("--revision", default=os.environ.get("BENCHMARK_COMMIT", benchmark.DEFAULT_REVISION))
    parser.add_argument("--cache-root", type=Path, default=Path(os.environ.get("CAMACT_DATA_ROOT", "/var/lib/camact")) / "benchmark")
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--lines", type=int, default=40)
    args = parser.parse_args(argv)
    if not 1 <= args.parallel <= 36:
        parser.error("parallel must be between 1 and 36")
    if args.action != "check" and not args.run_id:
        parser.error("--run-id is required")
    try:
        os.umask(0o077)
        settings.load_secrets()
        root = results_root(args.results_root)
        if args.action in {"status", "logs"}:
            path = archive_path(args.run_id, root)
            if args.action == "logs":
                if not 1 <= args.lines <= 10000:
                    raise ValueError("Log lines must be between 1 and 10000")
                file = path / "audit/scheduler_events.jsonl"
                print("\n".join(file.read_text().splitlines()[-args.lines:]) if file.exists() else "No scheduler events yet")
            else:
                print(json.dumps(status(path), ensure_ascii=False, indent=2))
            return 0
        path = archive_path(args.run_id, root) if args.run_id else None
        record = None
        if args.action == "resume":
            manifest = scheduler().read(path / "run_manifest.json")
            record = manifest["benchmark"]
        with data_lease(args, record=record) as snapshot:
            if args.action == "check":
                checks = preflight(settings.build(snapshot), settings.methods(args.harness), root)
                print(json.dumps({"ready": True, "benchmark": str(snapshot), **checks}, ensure_ascii=False))
                return 0
            if args.action == "run":
                path = prepare(args, snapshot)
            else:
                frozen = scheduler().read(path / "formal_config.json")
                if settings.identifier(settings.build(snapshot)) != manifest["model_config_id"]:
                    raise ValueError("Model configuration changed; resume requires the original settings")
                preflight(frozen, manifest["requested_harnesses"], root)
                verify_source(path)
            scheduler().run(path)
            final = status(path)
            print(json.dumps(final, ensure_ascii=False, indent=2))
            return 0 if final["status"] == "complete" else 3
    except (OSError, ValueError, RuntimeError, KeyError, benchmark.BenchmarkError) as exc:
        print(json.dumps({"ready": False, "error": settings.redact(exc), "type": type(exc).__name__}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
