"""Portable durable deployment of the existing six formal CamAct executors.

Original command/result/usage and reserve/worker/reconcile lifecycle are retained.
Deployment scope/config/reporting no longer depend on historical experiments.
"""
from __future__ import annotations
import argparse
from collections import Counter
import datetime as dt
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
from preflight_full_benchmark import (ROOT, HISTORICAL_USER, REQUEST_COUNT_DESCRIPTION,
    TOKEN_FIELDS, now, read, request_totals, sha, write, token_field_coverage,
    token_coverage_text, summarize_bounds, token_field_display,
    token_completeness_text, slot_usage_with_bounds)
METHODS = ("baseline", "claude", "codex", "opencode", "deepseek", "openclaw")
LABELS = dict(zip(METHODS, ("Canonical Baseline", "Claude Code", "Codex CLI", "OpenCode", "dsh", "OpenClaw")))
NATIVE_IDS = dict(zip(METHODS, ("canonical-baseline", "claude_code_native", "codex_native", "opencode_native", "deepseek_native", "openclaw_native")))
TERMINAL = {"scored", "infrastructure_error"}
SCRIPT = Path(__file__).resolve()


def redact(value):
    from release.config import redact as redact_roles
    return redact_roles(value)


def gate(archive):
    """Check the frozen public settings and currently injected role secrets."""
    from release.config import validate
    manifest = read(archive / "run_manifest.json")
    config = read(manifest["config"])
    if sha(manifest["config"]) != manifest["config_sha256"]:
        raise RuntimeError("Frozen model configuration changed; start a new run")
    validate(config, manifest["requested_harnesses"])
    from release.runner import verify_source
    verify_source(archive)


def save(archive, manifest):
    slots = manifest["tasks"]
    if not slots or len({slot_key(s) for s in slots}) != len(slots):
        raise ValueError("Task manifest is empty or contains duplicate slots")
    if set(s["harness"] for s in slots) != set(manifest["requested_harnesses"]):
        raise ValueError("Task manifest does not match selected Harnesses")
    active = [s for s in slots if s["status"] == "running"]
    counts = dict(Counter(s["harness"] for s in active))
    manifest.update(updated_at=now(), status_counts=dict(Counter(s["status"] for s in slots)),
        new_attempts_started=sum(len(s["attempts"]) for s in slots),
        new_valid_scores=sum(s["scored"] for s in slots), active_tasks=[slot_key(s) for s in active],
        active_counts_by_harness=counts, current_global_concurrency=len(active),
        current_per_harness_concurrency=max(counts.values(), default=0))
    write(archive / "run_manifest.json", manifest)


def report(archive, manifest):
    """Use the formal score/Strict/Token aggregates for exactly selected slots."""
    selected = manifest["requested_harnesses"]
    slots = manifest["tasks"]
    summaries = {name: statistics([s for s in slots if s["harness"] == name]) for name in selected}
    by_user = {user: {name: statistics([s for s in slots if s["harness"] == name and s["user_id"] == user])
                      for name in selected} for user in manifest["users"]}
    macro = {name: sum(by_user[user][name]["mean"] for user in manifest["users"]) / len(manifest["users"])
             if all(by_user[user][name]["mean"] is not None for user in manifest["users"]) else None for name in selected}
    lines = ["# CamAct 测评", "", f"状态：{manifest['status']}；有效评分 {sum(s['scored'] for s in slots)}/{len(slots)}。", "",
        f"Benchmark Commit：{manifest['benchmark']['revision']}。模型配置标识：{manifest['model_config_id']}。", "",
        REQUEST_COUNT_DESCRIPTION, "", "基础设施异常不计零分；有效 Agent Failure 按正式评分计入。", "",
        "| Harness | 计分/异常 | 均分/100 | Strict | Agent HTTP 请求 | 采集覆盖 | Agent 逻辑请求 | Input Token | Output Token | Total Token | Cache Read | Cache Write | Token 字段覆盖率 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    lines += [table_row(LABELS[name], summaries[name]) for name in selected]
    lines += ["", "明细：aggregate/task_details.json；全部角色/Attempt：aggregate/all_attempts_summary.json。", ""]
    atomic_text(archive / "final_report.md", "\n".join(lines))
    write(archive / "aggregate/summary.json", {"updated_at": now(), "complete": manifest.get("benchmark_complete", False),
        "harnesses": summaries, "users": by_user, "macro_average": macro})
    write(archive / "aggregate/task_details.json", slots)
    write(archive / "aggregate/pending_tasks.json", [s for s in slots if s["status"] not in TERMINAL])


def run(archive):
    """Preserve original durable attempt lifecycle with a global parallel cap."""
    with (archive / "scheduler.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        gate(archive)
        manifest = read(archive / "run_manifest.json")
        manifest.update(status="running", scheduler_identity=proc_identity(os.getpid()), dispatch_enabled=True)
        stopping = False
        def halt(*_):
            nonlocal stopping
            stopping = True
        signal.signal(signal.SIGTERM, halt)
        signal.signal(signal.SIGINT, halt)
        last_report = 0
        event(archive, "scheduler_started", identity=manifest["scheduler_identity"])
        while not stopping:
            reconcile(archive, manifest)
            if manifest.get("dispatch_fault"):
                manifest.update(status="blocked_dispatch", dispatch_enabled=False)
                save(archive, manifest)
                report(archive, manifest)
                raise RuntimeError("Owned execution identity is uncertain; inspect retained evidence before resuming")
            pending = [s for s in manifest["tasks"] if s["status"] not in TERMINAL]
            if not pending:
                manifest.update(status="complete" if all(s["scored"] for s in manifest["tasks"]) else "finished_with_infrastructure_errors",
                                benchmark_complete=True, dispatch_enabled=False)
                save(archive, manifest)
                aggregate_attempts(archive, manifest)
                report(archive, manifest)
                event(archive, "benchmark_finished", status=manifest["status"])
                return manifest
            user = next(u for u in manifest["users"] if any(s["user_id"] == u for s in pending))
            manifest["active_user"] = user
            active = sum(s["status"] == "running" for s in manifest["tasks"])
            free = max(0, manifest["parallel"] - active)
            eligible = [s for s in pending if s["user_id"] == user and s["status"] in {"pending", "retry_wait"}
                        and s.get("retry_after", 0) <= time.time()]
            # Round robin avoids filling the entire initial cap from one CLI.
            queues = {name: [s for s in eligible if s["harness"] == name] for name in manifest["requested_harnesses"]}
            while free and any(queues.values()):
                for name in manifest["requested_harnesses"]:
                    if queues[name] and free:
                        launch(archive, manifest, queues[name].pop(0))
                        free -= 1
            save(archive, manifest)
            if time.monotonic() - last_report >= 60:
                report(archive, manifest)
                last_report = time.monotonic()
            time.sleep(1)
        manifest.update(status="scheduler_stopped_workers_retained", dispatch_enabled=False)
        save(archive, manifest)
        report(archive, manifest)
        return manifest


def atomic_text(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    with temporary.open("x") as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)

def event(archive, kind, **data):
    with (archive / "audit/scheduler_events.jsonl").open("a") as stream:
        stream.write(json.dumps(dict(timestamp=now(), event=kind, **data), ensure_ascii=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())

def slot_key(slot):
    return f"{slot['user_id']}/{slot['harness']}/{slot['task']}"

def proc_identity(pid):
    try:
        value = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        if value[0] == "Z":
            return None
        return {"pid": int(pid), "start_ticks": int(value[19]),
                "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}
    except (OSError, ValueError, IndexError):
        return None

def live(identity):
    return bool(identity and proc_identity(identity["pid"]) == identity)

def paid_descendants(spec):
    marker = f"CAMACT_TASK_KEY={slot_key(spec)}/attempt_{spec['attempt']:03d}".encode()
    identities = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            if marker in (proc / 'environ').read_bytes().split(b'\0'):
                identity = proc_identity(int(proc.name))
                if identity:
                    identities.append(identity)
        except OSError:
            continue
    return identities

def locked(path):
    with Path(path).open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False

def command(config, slot, output, python=sys.executable):
    if slot["harness"] == "baseline":
        return [python, "-B", "-m", "camact_harness", "run", "--config", str(config),
                "--user-id", slot["user_id"], "--tasks", slot["task"], "--parallel", "1",
                "--judge", "env", "--task-retry-attempts", "1", "--run-dir", str(output),
                "--token-tracking", "--save-artifacts"]
    return [python, "-B", "-m", "camact_multi.cli", "--config", str(config), "run",
            "--harness", slot["harness"], "--user", slot["user_id"], "--task", slot["task"],
            "--evaluation-python", python, "--output", str(output),
            "--token-tracking", "--save-artifacts"]

def artifact_index(output):
    return next((p for p in (output / "runs/standard_run_artifacts.jsonl",
                             output / "runs/execution/standard_run_artifacts.jsonl")
                 if p.is_file()), None)

def frozen_eligible(output):
    index = artifact_index(output)
    if index is None:
        return False
    # The artifact's existing terminal classification determines whether the
    # Agent execution was usable. Do not convert infrastructure failure to score.
    from evaluation.camact_eval.adapters import adapt_source
    artifacts = adapt_source(index, adapter='external', benchmark_root=ROOT)
    return len(artifacts) == 1 and artifacts[0].trajectory_class in {'finished', 'agent_failure'}

def inspect_result(output, slot):
    path = output / "result.json"
    if not path.is_file():
        return dict(scored=False, reward=None, infrastructure_error=True,
                    failure_type="missing_result", result=None)
    document = read(path)
    grades = document.get("evaluations", [])
    if len(grades) != 1:
        raise ValueError("Expected exactly one evaluated Task")
    grade = grades[0]
    if (grade.get("user_id"), grade.get("task_id")) != (slot["user_id"], slot["task_id"]):
        raise ValueError("Evaluation identity mismatch")
    method = grade.get("method")
    if method and method not in {slot["harness"], NATIVE_IDS[slot['harness']]}:
        raise ValueError("Evaluation Harness mismatch")
    if not document.get("evaluation_environment", {}).get("formal"):
        raise ValueError("Evaluation did not use the formal environment")
    score = grade.get("score")
    valid = (not grade.get("infrastructure_failure") and
             not grade.get("evaluation_infrastructure_failure") and
             not grade.get("completion_infrastructure_failure") and
             type(score) in (int, float) and math.isfinite(score) and 0 <= score <= 1)
    return dict(scored=valid, reward=score if valid else None, strict=grade.get("strict_success"),
                infrastructure_error=not valid, agent_failure=grade.get("agent_failure"),
                failure_type=grade.get("failure_type"), result=str(path), result_sha256=sha(path))

def selected_usage(output, harness):
    summary = output / "token_usage/accounting_v3/summary.json"
    if not summary.is_file():
        return None
    data = read(summary)
    entries = data.get("views", {}).get("selected_run", {})
    usage = entries.get(harness) or (entries.get("canonical-baseline") if harness == "baseline" else None)
    if usage and usage.get('http_attempt_count') == 0 and not usage.get('capture_complete'):
        return None  # an unbound/uncaptured Run cannot establish zero billed usage
    return usage

def bound_task_usage(output, slot):
    """Recover the same frozen Agent usage when its original score was excluded.

    A separately accepted scoring repair does not update the original report's
    selected_run view. Bind its per-task usage to the physical ledger instead;
    never substitute all_attempts, another task, or another Agent attempt.
    """
    output = Path(output).resolve()
    summary_path = output / 'token_usage/accounting_v3/summary.json'
    try:
        summary_bytes = summary_path.read_bytes()
        data = json.loads(summary_bytes)
        harnesses = {slot['harness']}
        if slot['harness'] == 'baseline':
            harnesses.add('canonical-baseline')
        candidates = [(i, task) for i, task in enumerate(data.get('tasks', []))
                      if task.get('harness_id') in harnesses
                      and task.get('user_id') == slot['user_id']
                      and task.get('task_id') == slot['task']
                      and task.get('external_task_id') == slot['task_id']
                      and task.get('agent_run_id')
                      and task.get('agent_attempt_id')]
        # Some historical scoring retries wrote a new result wrapper while
        # deliberately reusing the original Agent execution. In that layout
        # `result_path` proves that this summary task belongs to `output`, and
        # `agent_run_id` identifies the physical ledger that must be bound.
        candidates = [(i, task) for i, task in candidates
                      if (Path(task['agent_run_id']).resolve() == output
                          or (task.get('result_path')
                              and (Path(task['result_path']).resolve() == output
                                   or Path(task['result_path']).resolve().parent == output)))]
        if not candidates and data.get('tasks') == []:
            # A killed scoring phase can leave a closed Agent capture but no
            # formal task row at all. Its exact executor spec and raw ledger
            # establish ownership independently of the score projection.
            from harness.camact_token_usage_v1.attempt_recovery import bind_unscored_agent_usage
            usage = bind_unscored_agent_usage(output, slot)
            if usage is not None:
                usage['usage_binding'].update(
                    summary_path=str(summary_path),
                    summary_sha256=hashlib.sha256(summary_bytes).hexdigest())
            return usage
        if len(candidates) != 1:
            return None
        index, task = candidates[0]
        # A result wrapper can point at an Agent run in a sibling attempt. Use
        # the wrapper ledger when it contains the physical rows; otherwise use
        # the exact Agent run named by the accounting task.
        requests_path = output / 'token_usage/accounting_v3/requests.jsonl'
        agent_output = Path(task['agent_run_id']).resolve()
        if not requests_path.is_file():
            requests_path = agent_output / 'token_usage/accounting_v3/requests.jsonl'
        request_bytes = requests_path.read_bytes()
        rows = [json.loads(line) for line in request_bytes.splitlines() if line.strip()]
        usage = task.get('agent_tokens')
        if not isinstance(usage, dict) or usage.get('capture_complete') is not True:
            return None
        count, ids = usage.get('http_attempt_count'), usage.get('physical_request_ids')
        if (type(count) is not int or count < 0 or not isinstance(ids, list)
                or not all(isinstance(v, str) and v for v in ids)
                or len(set(ids)) != len(ids) or len(ids) != count):
            return None
        identity = dict(run_id=task['agent_run_id'], harness_id=task['harness_id'],
                        user_id=slot['user_id'], task_id=slot['task'], attempt_id=task['agent_attempt_id'])
        physical = [r for r in rows if r.get('role') == 'Agent'
                    and all(r.get(k) == value for k, value in identity.items())]
        ledger_ids = [r.get('model_request_id') for r in physical]
        if (len(physical) != count or set(ledger_ids) != set(ids)
                or not all(r.get('request_capture_complete') is True for r in physical)):
            return None
        return dict(usage, usage_binding=dict(
            kind='frozen_task_agent_ledger', identity=identity,
            summary_path=str(summary_path), summary_sha256=hashlib.sha256(summary_bytes).hexdigest(),
            json_pointer=f'/tasks/{index}/agent_tokens',
            agent_run_path=str(agent_output),
            requests_path=str(requests_path), requests_sha256=hashlib.sha256(request_bytes).hexdigest()))
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return None

def score_frozen(config_path, source_run, output):
    from harness.camact_compatibility_v2.artifacts import RunArtifacts, evaluate_artifacts
    from harness.camact_compatibility_v2.roles import role_provider
    from harness.camact_token_usage_v1.unified_report import safe_report
    config = read(config_path)
    source = artifact_index(source_run)
    if source is None:
        raise RuntimeError("Frozen execution has no exported StandardRunArtifact index")
    judge = role_provider(config["judge"], role="judge", protocol="openai-chat")
    with RunArtifacts(output, save_artifacts=True, secrets=__import__("release.config", fromlist=["secret_values"]).secret_values()) as storage:
        document = evaluate_artifacts(source, Path(config["benchmark_root"]), judge_role=judge,
            judge_mode="env", output=storage.work_dir / "evaluation/result.json", evaluation_python=sys.executable)
        storage.finish(document, config=config)
    # Include frozen Agent source in selected usage, without executing it again.
    safe_report([source_run, output], output / "token_usage/accounting_v3")

def worker(archive, attempt_dir):
    """Uninterrupted worker survives scheduler exits; one lock prevents duplicates."""
    with (attempt_dir / "worker.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if (attempt_dir / "terminal.json").exists():
            return
        spec = read(attempt_dir / "spec.json")
        gate(archive)
        assert sha(archive / "formal_config.json") == spec["config_sha256"]
        if (attempt_dir / "worker.json").exists():
            raise RuntimeError("Previously started Attempt must be reconciled, never relaunched")
        write(attempt_dir / "worker.json", dict(identity=proc_identity(os.getpid()), started_at=now()))
        output = attempt_dir / "run"
        if spec["mode"] == "judge_only":
            cmd = [sys.executable, "-B", str(SCRIPT), "score", "--archive", str(archive),
                   "--source-run", spec["source_run"], "--output", str(output)]
        else:
            cmd = command(archive / "formal_config.json", spec, output)
        env = os.environ.copy()
        # The supervisor may have been started before a policy edit.  Resolve
        # the timeout again in this fresh worker so the next User receives the
        # new 60-second contract without restarting or replaying current work.
        if "service_ready_timeout_seconds" not in spec:
            live_manifest = read(archive / "run_manifest.json")
            live_policy = scheduling_policy(archive, spec["user_id"], live_manifest["users"])
            spec["service_ready_timeout_seconds"] = float(live_policy.get("service_ready_timeout_seconds", 10.0))
        if "scheduler_context" not in spec:
            live_manifest = read(archive / "run_manifest.json")
            spec["scheduler_context"] = {
                "active_user": live_manifest.get("active_user"),
                "active_tasks": live_manifest.get("active_tasks", []),
                "active_counts_by_harness": live_manifest.get("active_counts_by_harness", {}),
                "concurrency_policy": {
                    "max_parallel_harnesses": live_manifest.get("target_harness_concurrency"),
                    "max_tasks_per_harness": live_manifest.get("target_per_harness_concurrency"),
                    "resource_control": live_manifest.get("resource_control", {}),
                },
            }
        write(attempt_dir / "spec.json", spec)
        env.update(CAMACT_TASK_KEY=f"{slot_key(spec)}/attempt_{spec['attempt']:03d}", PYTHONUNBUFFERED="1",
                   CAMACT_SERVICE_READY_TIMEOUT=str(spec.get('service_ready_timeout_seconds', 10.0)),
                   CAMACT_SCHEDULER_CONTEXT=json.dumps(spec.get('scheduler_context', {}), ensure_ascii=False))
        start = time.monotonic()
        try:
            # One redacting stream avoids ever persisting raw child stderr with a key.
            process = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, errors="replace")
            write(attempt_dir / "child.json", dict(identity=proc_identity(process.pid), command=cmd))
            with (attempt_dir / "executor.log").open("x") as log:
                for line in process.stdout:
                    log.write(redact(line))
                    log.flush()
            code = process.wait()
            if output.is_dir() and not (output / 'token_usage/accounting_v3/summary.json').is_file():
                # Exceptions may bypass RunArtifacts.finish. Account preserved
                # journals with the same v3 exporter, without rerunning anything.
                from harness.camact_token_usage_v1.unified_report import safe_report
                safe_report([output], output / 'token_usage/accounting_v3')
            verdict = inspect_result(output, spec)
            write(attempt_dir / "terminal.json", dict(returncode=code, ended_at=now(),
                  elapsed_seconds=time.monotonic() - start, verdict=verdict))
        except Exception as exc:
            write(attempt_dir / "worker_error.json", dict(timestamp=now(),
                  error_type=type(exc).__name__, message=redact(str(exc))))
            raise

def launch(archive, manifest, slot):
    assert not slot["scored"]
    number = len(slot["attempts"]) + 1
    directory = archive / "users" / slot["user_id"] / "runs" / slot["harness"] / slot["task"] / f"attempt_{number:03d}"
    if directory.exists():
        # Only a reservation before manifest commit can be adopted. Once a
        # worker has started, its original Attempt is never relaunched.
        assert set(p.name for p in directory.iterdir()) <= {'spec.json'}, 'Untracked existing Attempt requires reconciliation'
    else:
        directory.mkdir(parents=True, exist_ok=False)
    previous = slot["attempts"][-1] if slot["attempts"] else None
    source = (previous.get("source_run") or previous["output"]) if previous else None
    mode = "judge_only" if source and frozen_eligible(Path(source)) else "agent"
    ready_timeout = manifest.get('service_ready_timeout_seconds',
                                manifest.get('scheduling_policy', {}).get('service_ready_timeout_seconds', 10.0))
    spec = dict(user_id=slot["user_id"], harness=slot["harness"], task=slot["task"], task_id=slot["task_id"],
                attempt=number, mode=mode, source_run=source if mode == "judge_only" else None,
                config_sha256=manifest["config_sha256"],
                service_ready_timeout_seconds=float(ready_timeout),
                scheduler_context={
                    "active_user": manifest.get("active_user"),
                    "active_tasks": manifest.get("active_tasks", []),
                    "active_counts_by_harness": manifest.get("active_counts_by_harness", {}),
                    "concurrency_policy": {
                        "max_parallel_harnesses": manifest.get("target_harness_concurrency"),
                        "max_tasks_per_harness": manifest.get("target_per_harness_concurrency"),
                        "resource_control": manifest.get("resource_control", {}),
                    },
                })
    write(directory / "spec.json", spec)
    record = dict(attempt=number, directory=str(directory), output=str(directory / "run"),
                  status="launching", mode=mode, source_run=spec["source_run"], reserved_at=now())
    slot["attempts"].append(record)
    slot.update(status="running", attempt_id=number)
    save(archive, manifest)  # reservation is durable before any worker can make a request
    log = (directory / "supervisor.log").open("x")
    try:
        process = subprocess.Popen([sys.executable, "-B", str(SCRIPT), "worker", "--archive", str(archive),
                                    "--attempt-dir", str(directory)], cwd=ROOT, stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        record.update(status="running", worker_identity=proc_identity(process.pid))
    finally:
        log.close()
    save(archive, manifest)
    event(archive, "task_started", key=slot_key(slot), attempt=number, mode=mode)

def reconcile(archive, manifest):
    changed = False
    for slot in manifest["tasks"]:
        if slot["status"] != "running":
            continue
        record = slot["attempts"][-1]
        directory = Path(record["directory"])
        terminal = directory / "terminal.json"
        if terminal.is_file():
            finished = read(terminal)
        else:
            worker_path, child_path = directory / "worker.json", directory / "child.json"
            worker_id = read(worker_path)["identity"] if worker_path.is_file() else record.get("worker_identity")
            child_id = read(child_path)["identity"] if child_path.is_file() else None
            if locked(directory / "worker.lock") or live(worker_id) or live(child_id):
                continue
            age = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(record["reserved_at"])).total_seconds()
            if age < 30:  # allow the reserved worker to publish its durable identity
                continue
            if paid_descendants(read(directory / "spec.json")):
                continue
            # A crash between spawn and child.json can leave an unknown paid process.
            # Never retry this uncertain Attempt automatically.
            if worker_path.is_file() and not child_path.is_file():
                manifest["dispatch_fault"] = dict(reason="worker_child_identity_uncertain", attempt=str(directory))
                continue
            try:
                verdict = inspect_result(Path(record["output"]), slot)
            except (ValueError, KeyError, TypeError) as exc:
                manifest["dispatch_fault"] = dict(reason="experiment_correctness", message=str(exc), attempt=str(directory))
                continue
            finished = dict(returncode=None, ended_at=now(), elapsed_seconds=None, verdict=verdict,
                            recovered_after_worker_exit=True)
            write(terminal, finished)
        verdict = inspect_result(Path(record["output"]), slot)
        record.update(status="scored" if verdict["scored"] else "infrastructure_error", **finished)
        slot.update(verdict)
        if verdict["scored"]:
            slot.update(status="scored", final_formal_run_id=record["output"],
                        selected_agent_usage=selected_usage(Path(record["output"]), slot["harness"]),
                        execution_seconds=finished.get("elapsed_seconds"))
        elif (not finished.get("recovered_after_worker_exit") and
              len(slot["attempts"]) < manifest["max_infrastructure_attempts"]):
            slot.update(status="retry_wait", retry_after=time.time() + 60 * len(slot["attempts"]))
        else:
            slot.update(status="infrastructure_error")
        event(archive, "task_finished", key=slot_key(slot), attempt=record["attempt"],
              status=slot["status"], reward=slot.get("reward"), failure_type=slot.get("failure_type"))
        changed = True
    return changed

def totals(usages):
    requests = request_totals(usages)
    coverage = token_field_coverage(usages)
    if not usages or any(u is None for u in usages):
        return dict(**requests, exact_tokens=dict.fromkeys(TOKEN_FIELDS),
                    token_field_coverage=coverage, **summarize_bounds(usages))
    def complete_sum(values):
        return sum(values) if all(type(v) is int and v >= 0 for v in values) else None
    return dict(**requests,
                exact_tokens={k: complete_sum([u.get("exact_tokens", {}).get(k) for u in usages]) for k in TOKEN_FIELDS},
                token_field_coverage=coverage, **summarize_bounds(usages))

def statistics(slots):
    valid = [s for s in slots if s["scored"]]
    usage = totals([slot_usage_with_bounds(s) for s in valid])
    return dict(valid=len(valid), errors=sum(s["status"] == "infrastructure_error" for s in slots),
                pending=sum(s["status"] not in TERMINAL for s in slots),
                mean=sum(s["reward"] * 100 for s in valid) / len(valid) if valid else None,
                strict=sum(bool(s["strict"]) for s in valid),
                attempts=sum(len(s["attempts"]) for s in slots), **usage)

def table_row(label, stats):
    def val(value):
        return "N/A" if value is None else str(value)
    mean = "N/A" if stats["mean"] is None else f"{stats['mean']:.2f}"
    return (f"| {label} | {stats['valid']} / {stats['errors']} | {mean} | "
            f"{stats['strict']}/{stats['valid']} | {val(stats['request_count'])} | "
            f"{stats['request_task_coverage']}/{stats['request_task_total']} | "
            f"{val(stats.get('logical_requests'))} | " +
            " | ".join(token_field_display(stats, k) for k in TOKEN_FIELDS) + " | "
            f"{token_coverage_text(stats)} |")

def aggregate_attempts(archive, manifest):
    from harness.camact_token_usage_v1.unified_report import aggregate, deduplicate_roles
    paths = []
    paths += [Path(a["output"]) / "token_usage/accounting_v3/requests.jsonl"
              for s in manifest["tasks"] for a in s["attempts"]]
    rows, unavailable = [], []
    for path in paths:
        if not path.is_file():
            unavailable.append(str(path))
            continue
        rows.extend(json.loads(line) for line in path.read_text().splitlines() if line.strip())
    rows = deduplicate_roles(rows)
    data = dict(updated_at=now(), sources=[str(p) for p in paths], unavailable=unavailable,
                scope='All observed deduplicated role requests, including failed Attempts; missing sources and uncaptured requests remain unknown. Known totals can be lower bounds; zero observed requests is not proof of zero billed usage.',
                observed_all_roles=aggregate(rows), harnesses={})
    for method in METHODS:
        selected = [r for r in rows if r.get("harness_id") in
                    {method, "canonical-baseline" if method == "baseline" else method}]
        data["harnesses"][method] = {role: aggregate([r for r in selected if r.get("role") == role])
                                     for role in ("Agent", "Simulator", "Judge")}
    write(archive / "aggregate/all_attempts_summary.json", data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("worker", "score", "report"))
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--attempt-dir", type=Path)
    parser.add_argument("--source-run", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    # Direct worker processes use the same external secret files and role
    # injection as the container entrypoint, with no implicit personal config.
    from release.config import load_secrets
    from release.runner import results_root
    load_secrets()
    archive = args.archive.resolve()
    root = results_root()
    if archive == root or not archive.is_relative_to(root):
        parser.error("archive must belong to CAMACT_RESULTS_ROOT")
    if args.action == "worker":
        if args.attempt_dir is None or not args.attempt_dir.resolve().is_relative_to(archive / "users"):
            parser.error("worker attempt must belong to this run")
        # The parent validated every file before launch. Keep an independent
        # shared lease for the worker lifetime so a surviving paid worker also
        # prevents cache repair after its scheduler exits. Do not hash the whole
        # 22k-file dataset once per task.
        from release.benchmark import _lock
        record = read(archive / "run_manifest.json")["benchmark"]
        with _lock(record["cache_root"], record["repo_id"], record["revision"], shared=True) as (directory, _):
            marker = read(directory / "complete.json")
            if marker.get("revision") != record["revision"] or not (directory / "snapshot").samefile(record["snapshot"]):
                raise RuntimeError("Frozen Benchmark cache changed")
            worker(archive, args.attempt_dir.resolve())
    elif args.action == "score":
        gate(archive)
        score_frozen(archive / "formal_config.json", args.source_run, args.output)
    else:
        manifest = read(archive / "run_manifest.json")
        report(archive, manifest)
        aggregate_attempts(archive, manifest)


if __name__ == "__main__":
    main()

