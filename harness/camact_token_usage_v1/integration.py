"""Small opt-in hooks around existing runners, never inside their Agent loops."""
from __future__ import annotations
from contextlib import contextmanager
from functools import wraps
import os
from pathlib import Path
import uuid
from .collector import create, current, enabled, scope


@contextmanager
def task_scope(directory, active, **identity):
    if not active or current() is not None:
        yield current()
        return
    collector = create(Path(directory) / "token_usage" / uuid.uuid4().hex, lazy=True, **identity)
    with scope(collector):
        try:
            yield collector
        except BaseException:
            if collector:
                collector.finish_task("exception_or_interruption")
            raise
        else:
            if collector:
                collector.finish_task(collector.task_status if collector.task_status != "running" else "returned")


def track_official(function):
    @wraps(function)
    def run(config, name, user, task, output):
        if not enabled(config):
            return function(config, name, user, task, output)
        p = config["harnesses"][name]["provider"]
        with task_scope(output, True, run_id=config.get("_token_run_id", Path(output).name + "-" + uuid.uuid4().hex),
                        harness_id=name, user_id=user, task_id=task, provider=p.get("provider"), model_id=p.get("model"),
                        secrets=[os.environ.get(p.get("api_key_env", ""), "")]) as collector:
            result = function(config, name, user, task, output)
            if collector:
                collector.task_status = result.get("trajectory_class", result.get("status", "unknown"))
        from .report import safe_report
        safe_report([Path(output) / "token_usage"], Path(output) / "token_usage")
        return result
    return run


def track_claude(function):
    @wraps(function)
    def run(handle, *, benchmark_root, run_root, run_id, settings, resume=False):
        kwargs = dict(benchmark_root=benchmark_root, run_root=run_root, run_id=run_id, settings=settings, resume=resume)
        if not getattr(settings, "token_tracking", False) or current() is not None:
            return function(handle, **kwargs)
        with task_scope(Path(run_root) / "tasks" / handle.user_id / handle.task_name, True,
                        run_id=str(Path(run_root).resolve()), harness_id="claude", user_id=handle.user_id,
                        task_id=handle.task_name, provider=settings.provider, model_id=settings.model,
                        secrets=[settings.api_key]) as collector:
            result = function(handle, **kwargs)
            if collector:
                collector.task_status = result.get("trajectory_class", result.get("status", "unknown"))
        return result
    return run


@contextmanager
def baseline_scope(args, session_dir):
    active = getattr(args, "token_tracking", False)
    try:
        with task_scope(session_dir, active,
                      run_id=os.environ.get("CAMACT_TOKEN_RUN_ID", str(Path(session_dir).resolve())),
                      harness_id="canonical-baseline", user_id=args.user_id, task_id=args.task,
                      provider=args.provider, model_id=args.model,
                      secrets=[os.environ.get(getattr(args, "api_key_env", "") or "", "")]) as collector:
            yield collector
    finally:
        if active:
            from .report import safe_report
            safe_report([Path(session_dir) / "token_usage"], Path(session_dir) / "token_usage")


def reconcile_baseline(collector, session_dir):
    def check():
        import json
        path = Path(session_dir) / "provider_attempts.jsonl"
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []
        collector.reconcile(sum(r.get("component") == "agent_model" for r in rows), source="canonical_provider_attempts")
    collector.safe(check)
