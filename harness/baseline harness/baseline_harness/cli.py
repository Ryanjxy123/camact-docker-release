"""CLI and batch orchestration for the canonical CamAct Baseline loop.

The agent itself always runs in ``benchmark/benchmark_runner/run_model.py``.
This module only owns process isolation, scheduling, retries, telemetry, and
artifact normalization.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import mimetypes
import os
import re
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4
from zoneinfo import ZoneInfo


HARNESS_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = HARNESS_ROOT.parents[1]
BENCHMARK_ROOT = PROJECT_ROOT / "benchmark"
CANONICAL_RUNNER = BENCHMARK_ROOT / "benchmark_runner" / "run_model.py"
OBSERVED_RUNNER = HARNESS_ROOT / "baseline_harness" / "observed_runner.py"
DEFAULT_CONFIG = PROJECT_ROOT / "harness" / "camact_multi_harness_v1" / "config.wsl.json"
EVALUATION_ROOT = PROJECT_ROOT / "evaluation"
PRIVATE_KEY_ENV = "CAMACT_CANONICAL_BASELINE_API_KEY"
SIMULATOR_KEY_ENV = "CAMACT_CANONICAL_BASELINE_SIMULATOR_API_KEY"
VIEW_TOOLS = {"image_view", "inspect_image", "person_view_reference", "owner_profile_view"}
INFRASTRUCTURE_RETURN_CODE = 3
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _configure_roles(args: argparse.Namespace) -> None:
    """Resolve independent role settings before creating a run or a process."""
    from harness.camact_compatibility_v2.roles import role_provider

    explicit_config = getattr(args, "config", None)
    config_path = Path(explicit_config) if explicit_config else DEFAULT_CONFIG
    config = _json(config_path, {})
    if not isinstance(config, dict) or (explicit_config and not config_path.is_file()):
        raise ValueError(f"invalid or missing role configuration: {config_path}")
    source = config.get("roles", config)
    agent = dict(source.get("agent") or config.get("harnesses", {}).get("baseline", {}).get("provider") or {})
    simulator = dict(source.get("simulator") or {})
    judge = dict(source.get("judge") or {})
    for role, raw in (("agent", agent), ("simulator", simulator), ("judge", judge)):
        prefix = "" if role == "agent" else role + "_"
        mappings = {"provider": "provider", "model": "model", "base_url": "base_url", "api_key": "api_key", "api_key_env": "api_key_env", "timeout": "timeout_seconds", "max_output_tokens": "max_output_tokens"}
        mappings["provider_retry_attempts" if role == "agent" else "retry_attempts"] = "retry_attempts"
        for attribute, key in mappings.items():
            value = getattr(args, prefix + attribute, None)
            if value is not None:
                raw[key] = value
                if key == "api_key_env":
                    raw.pop("api_key", None)
        if raw.get("api_key"):
            raw.pop("api_key_env", None)
        env_prefix = "CAMACT_AGENT_" if role == "agent" else f"CAMACT_{role.upper()}_"
        for key, suffix in (("provider", "PROVIDER"), ("model", "MODEL"), ("base_url", "BASE_URL"), ("api_key_env", "API_KEY_ENV")):
            value = os.environ.get(env_prefix + suffix)
            if not raw.get(key) and value:
                raw[key] = value
        if not raw.get("base_url") and os.environ.get(env_prefix + "API_BASE"):
            raw["base_url"] = os.environ[env_prefix + "API_BASE"]
        if not raw.get("api_key") and not raw.get("api_key_env") and os.environ.get(env_prefix + "API_KEY"):
            raw["api_key_env"] = env_prefix + "API_KEY"
    if args.provider is not None:
        agent["protocol"] = {"anthropic": "anthropic-messages", "gemini": "google-generative-language"}.get(args.provider, "openai-chat")
    need_simulator = any(_task_spec(args.user_id, task).get("interaction_type") == "multi_turn" for task in args.tasks)
    # Simulator and Judge use the existing OpenAI Chat implementation. Other
    # protocols cannot be enabled by changing a provider label.
    agent_protocol = agent.get("protocol") or {"anthropic": "anthropic-messages", "gemini": "google-generative-language"}.get(agent.get("provider"), "openai-chat")
    roles = {"agent": role_provider(agent, role="agent", protocol=agent_protocol)}
    roles["simulator"] = role_provider(simulator, role="simulator", protocol="openai-chat", require_key=need_simulator) if simulator or need_simulator else None
    roles["judge"] = role_provider(judge, role="judge", protocol="openai-chat", require_key=args.judge == "env") if judge or args.judge == "env" else None
    from harness.camact_compatibility_v2.roles import provider_config
    if need_simulator:
        provider_config(roles["simulator"])  # Validate supported protocol up front.
    transport_provider = {"openai-chat": "relay", "anthropic-messages": "anthropic", "google-generative-language": "gemini"}.get(agent_protocol)
    if transport_provider is None:
        raise ValueError(f"canonical Baseline does not support protocol: {agent_protocol}")
    supported_parameters = {"openai-chat": {"temperature", "top_p", "seed"}, "anthropic-messages": {"temperature", "top_p", "thinking"}, "google-generative-language": set()}
    unsupported = set(roles["agent"]["parameters"]) - supported_parameters[agent_protocol]
    if unsupported:
        raise ValueError(f"canonical Baseline {agent_protocol} does not support configured parameters: {sorted(unsupported)}")
    args._roles = roles
    args._config = config
    args._provider_label = roles["agent"]["provider"]
    args.provider = transport_provider
    for name, key in (("model", "model"), ("base_url", "base_url"), ("api_key", "api_key"), ("timeout", "timeout_seconds"), ("max_output_tokens", "max_output_tokens"), ("provider_retry_attempts", "retry_attempts")):
        setattr(args, name, roles["agent"][key])
    sim = roles["simulator"]
    for name, key, default in (("model", "model", "unused-simulator"), ("base_url", "base_url", "http://unused.invalid/v1"), ("timeout", "timeout_seconds", 120), ("max_output_tokens", "max_output_tokens", 256), ("retry_attempts", "retry_attempts", 4)):
        setattr(args, "simulator_" + name, sim[key] if sim else default)
    limits = config.get("limits", {})
    if args.max_steps is None:
        args.max_steps = int(limits.get("max_agent_turns", 50))
    if args.max_simulator_turns is None:
        args.max_simulator_turns = int(limits.get("max_simulator_rounds", 10))
    if args.task_timeout is None:
        args.task_timeout = float(limits.get("task_timeout_seconds", 1800))
    if args.task_retry_attempts is None:
        args.task_retry_attempts = 1
    for name in ("max_steps", "max_simulator_turns", "task_retry_attempts"):
        if getattr(args, name) < 1:
            raise ValueError(f"{name} must be positive")
    if not math.isfinite(args.task_timeout) or args.task_timeout <= 0:
        raise ValueError("task_timeout must be finite and positive")


def _redact_run(text: str, args: argparse.Namespace) -> str:
    for role in getattr(args, "_roles", {}).values():
        if role:
            text = _redact(text, role.get("api_key", ""))
    return _redact(text, getattr(args, "api_key", ""))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-._") or "model"


def _default_run_dir() -> Path:
    now = datetime.now(ZoneInfo("Asia/Shanghai"))
    return (PROJECT_ROOT / "harness" / "_log" / now.strftime("%Y-%m-%d") /
            f"camact-canonical-baseline-v1-{now:%H%M%S}-{uuid4().hex[:8]}")


def _register_default_archive(archive: Path, *, save_artifacts: bool) -> None:
    for name in ("report", "manifest", "evaluation"):
        (archive / name).mkdir(exist_ok=True)
    (archive / "README.md").write_text(
        f"# {archive.name}\n\nDate: {archive.parent.name} (Asia/Shanghai). Type: Canonical Baseline evaluation.\n"
        f"Original and archive location: {archive}. Method: unmodified run_model.py --aep-mode baseline with HTTP observation.\n"
        f"Full artifacts requested: {str(save_artifacts).lower()}; retained raw location: runs/execution/ when enabled.\n"
        "Result: result.json; summary: summary.json; role/config snapshot and benchmark source hashes: run_config.json; "
        "retention status: artifact_policy.json. Git commit: not determined by the runner.\n"
        "Canonical benchmark / Task / GT / Rubric / Simulator task logic / Atomic scoring / official Agent Loop: unchanged. "
        "The installed observation/configuration/evaluation compatibility layers are used. Credentials are environment-only.\n",
        encoding="utf-8",
    )
    for index, link in ((archive.parent / "README.md", f"{archive.name}/README.md"),
                        (archive.parents[1] / "EXPERIMENT_INDEX.md", f"{archive.parent.name}/{archive.name}/README.md")):
        with index.open("a", encoding="utf-8") as stream:
            stream.write(f"\n- [{archive.name}]({link}): Canonical Baseline evaluation; see result, summary and retention policy.\n")


def _sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json(path: Path, default: Any = None) -> Any:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def _redact(text: str, secret: str) -> str:
    return text.replace(secret, "[REDACTED]") if secret else text


def _benchmark_provenance() -> dict[str, Any]:
    manifest_path = BENCHMARK_ROOT / "benchmark_manifest.json"
    manifest = _json(manifest_path, {})
    return {
        "benchmark_root": str(BENCHMARK_ROOT),
        "manifest_sha256": _sha256(manifest_path),
        "release_id": manifest.get("release_id") if isinstance(manifest, dict) else None,
        "release_version": (
            manifest.get("release_version") or manifest.get("updated_at")
            if isinstance(manifest, dict)
            else None
        ),
        "code_hashes": {
            relative: _sha256(BENCHMARK_ROOT / relative)
            for relative in (
                "benchmark_runner/run_model.py",
                "benchmark_runner/mllm_adapter.py",
                "services/runtime_environment.py",
                "evaluator/evaluate.py",
            )
        },
    }


def _task_spec(user_id: str, task: str) -> dict[str, Any]:
    task_dir = BENCHMARK_ROOT / "tasks" / user_id / task
    spec = _json(task_dir / "task_spec.json")
    if not task_dir.is_dir() or not isinstance(spec, dict):
        raise ValueError(f"unknown benchmark task: {user_id}/{task}")
    return spec


def canonical_command(args: argparse.Namespace, task: str, session_dir: Path) -> list[str]:
    """Build the unmodified canonical Baseline CLI invocation."""
    command = [
        sys.executable,
        "-B",
        str(OBSERVED_RUNNER),
        "--task",
        task,
        "--user-id",
        args.user_id,
        "--provider",
        args.provider,
        "--model",
        args.model,
        "--api-base",
        args.base_url,
        "--api-key-env",
        PRIVATE_KEY_ENV,
        "--timeout",
        str(args.timeout),
        "--provider-retry-attempts",
        str(args.provider_retry_attempts),
        "--aep-mode",
        "baseline",
        "--simulator-model",
        args.simulator_model or args.model,
        "--simulator-api-base",
        args.simulator_base_url or args.base_url,
        "--simulator-api-key-env",
        SIMULATOR_KEY_ENV,
        "--simulator-timeout",
        str(args.simulator_timeout),
        "--simulator-retry-attempts",
        str(args.simulator_retry_attempts),
        "--session-dir",
        str(session_dir),
        "--max-simulator-turns",
        str(getattr(args, "max_simulator_turns", 15)),
    ]
    optional_runtime_args = (
        ("--max-steps", args.max_steps),
        ("--max-image-views", args.max_image_views),
        ("--max-output-tokens", args.max_output_tokens),
        ("--simulator-max-output-tokens", args.simulator_max_output_tokens),
    )
    for flag, value in optional_runtime_args:
        if value is not None:
            command.extend((flag, str(value)))
    if all(value is None for _flag, value in optional_runtime_args):
        command.append("--no-runtime-caps")
    if getattr(args, "token_tracking", False):
        command.append("--token-tracking")
    return command


def _classify_process_failure(return_code: int, timed_out: bool, text: str) -> str:
    """Keep canonical agent runtime guards out of infrastructure failures."""
    if timed_out or return_code == INFRASTRUCTURE_RETURN_CODE:
        return "infrastructure_failure"
    if (
        "model exceeded max_steps=" in text
        or "model did not call a tool or finish after two turns" in text
    ):
        return "agent_failure"
    return "harness_failure"


def _child_environment(api_key: str) -> dict[str, str]:
    environment = os.environ.copy()
    environment[PRIVATE_KEY_ENV] = api_key
    environment["PYTHONIOENCODING"] = "utf-8"
    return environment


def _terminate(process: subprocess.Popen[str]) -> None:
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    from benchmark.services.process_cleanup import terminate_process_tree
    terminate_process_tree(process, owned_process_group=os.name != "nt")


def _run_process(command: list[str], environment: dict[str, str], timeout: float) -> tuple[int, str, str, bool]:
    process = subprocess.Popen(
        command,
        cwd=str(PROJECT_ROOT),
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        start_new_session=os.name != "nt",
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return int(process.returncode or 0), stdout, stderr, False
    except subprocess.TimeoutExpired:
        _terminate(process)
        stdout, stderr = process.communicate()
        return 124, stdout, stderr, True
    except BaseException:
        _terminate(process)
        raise


def _unique_views(tool_calls: list[dict[str, Any]]) -> int:
    images: set[str] = set()
    for call in tool_calls:
        if call.get("status", "succeeded") != "succeeded" or call.get("tool") not in VIEW_TOOLS:
            continue
        arguments = call.get("arguments", {})
        if not isinstance(arguments, dict):
            continue
        image = arguments.get("image_id", arguments.get("image", arguments.get("person_id")))
        if image:
            images.add(str(image))
    return len(images)


def _provider_model_aliases(requested_model: str) -> dict[str, str]:
    """Return only aliases proven by the current relay's direct probe.

    The relay accepts ``gemini-3.7-flash`` but reports the upstream response
    model as ``gemini-3.7-flash-high``.  Keep this mapping explicit and narrow;
    it is a gateway identity mapping, not a fallback model selection rule.
    """
    if requested_model == "gemini-3.7-flash":
        return {"gemini-3.7-flash-high": "gemini-3.7-flash"}
    return {}


def _provider_model_policy(session_dir: Path, requested_model: str) -> dict[str, Any]:
    events = _jsonl(session_dir / "provider_attempts.jsonl")
    events = [event for event in events if event.get("component", "agent_model") == "agent_model"]
    configured = sorted({str(item.get("configured_model")) for item in events if item.get("configured_model")})
    upstream = sorted({str(item.get("upstream_model")) for item in events if item.get("upstream_model")})
    observed = sorted(set(configured) | set(upstream))
    aliases = _provider_model_aliases(requested_model)
    violation = any(model != requested_model and aliases.get(model) != requested_model for model in observed)
    return {
        "requested_model": requested_model,
        "primary_model": requested_model,
        "small_fast_model": requested_model,
        "subagent_model": requested_model,
        "allowed_models": [requested_model],
        "configured_models": configured,
        "upstream_models": upstream,
        "observed_models": observed,
        "aliases": aliases,
        "violation": violation,
    }


def _normalise_artifact(
    session_dir: Path,
    run_dir: Path,
    args: argparse.Namespace,
    task: str,
    attempt_count: int,
    started_at: str,
    ended_at: str,
    duration_seconds: float,
    fallback_class: str,
    error: str | None,
):
    sys.path.insert(0, str(EVALUATION_ROOT))
    from camact_eval.adapters import BaselineAdapter
    from camact_eval.measurement import canonical_measurement
    from camact_eval.schema import StandardRunArtifact

    artifacts = BaselineAdapter(PROJECT_ROOT).adapt(session_dir)
    if artifacts:
        artifact = artifacts[0]
    else:
        spec = _task_spec(args.user_id, task)
        artifact = StandardRunArtifact(
            user_id=args.user_id,
            task_id=str(spec.get("task_id", task)),
            task=f"{args.user_id}/{task}",
            run={},
            method="canonical-baseline",
            model={},
            final_response="",
            evidence=[],
            tool_calls=[],
            actions=[],
            final_state={},
            simulator={"status": "not_recorded", "audit_events": [], "state": {}},
            errors={},
            token_usage={"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
            model_calls=[],
            timing={},
            diagnostics={},
            trajectory_class=fallback_class,
        )
    provenance = _benchmark_provenance()
    artifact.run.update(
        {
            "run_id": getattr(args, "_run_id", run_dir.name),
            "trial": 1,
            "provider": getattr(args, "_provider_label", args.provider),
            "benchmark_release_id": provenance.get("release_id"),
            "benchmark_release_version": provenance.get("release_version"),
            "benchmark_manifest_sha256": provenance.get("manifest_sha256"),
            "source_path": str(run_dir),
        }
    )
    artifact.method = "canonical-baseline"
    artifact.model.update({"provider": getattr(args, "_provider_label", args.provider), "model": args.model, "agent_model": args.model})
    artifact.model_policy = _provider_model_policy(session_dir, args.model)
    artifact.timing = {
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_seconds": round(duration_seconds, 6),
    }
    artifact.diagnostics.update(
        {
            "canonical_entrypoint": str(CANONICAL_RUNNER),
            "canonical_entrypoint_sha256": _sha256(CANONICAL_RUNNER),
            "canonical_mode": "baseline",
            "observer_entrypoint": str(OBSERVED_RUNNER),
            "attempt_count": attempt_count,
            "unique_image_views": _unique_views(artifact.tool_calls),
            "provider_attempts": _jsonl(session_dir / "provider_attempts.jsonl"),
            "runtime_timeline": _jsonl(session_dir / "runtime_timeline.jsonl"),
        }
    )
    if not int(artifact.diagnostics.get("retrieval_calls", 0) or 0):
        artifact.diagnostics["retrieval_calls"] = sum(
            call.get("tool") == "album_search" and call.get("status", "succeeded") == "succeeded"
            for call in artifact.tool_calls
            if isinstance(call, dict)
        )
    from benchmark.services.episode import episode_error
    from camact_eval.evaluator import _submission
    invalid_episode = episode_error(_submission(artifact), artifact.final_state)
    if invalid_episode or fallback_class in {"infrastructure_failure", "harness_failure"}:
        artifact.trajectory_class = "infrastructure_failure"
    elif fallback_class == "agent_failure" and artifact.trajectory_class != "agent_failure":
        # A process label cannot turn a different or incomplete snapshot into a
        # valid agent-failure episode.
        artifact.trajectory_class = "infrastructure_failure"
    if error:
        if fallback_class == "infrastructure_failure":
            bucket = "infrastructure"
        elif fallback_class == "agent_failure":
            bucket = "agent"
        else:
            bucket = "harness"
        artifact.errors.setdefault(bucket, []).append(
            {"component": "canonical_baseline_process", "message": error, "retryable": bucket == "infrastructure"}
        )
    artifact.measurement = canonical_measurement(
        model_calls=artifact.model_calls, token_usage=artifact.token_usage,
        tool_calls=artifact.tool_calls, actions=artifact.actions,
        evidence=artifact.evidence, timing=artifact.timing,
        diagnostics=artifact.diagnostics, final_state=artifact.final_state,
    )
    target = run_dir / "standard_artifacts" / args.user_id / f"{task}.json"
    artifact.write(target)
    artifact.write(session_dir / "standard_run_artifact.json")
    return artifact, target


def _task_result(
    args: argparse.Namespace,
    run_dir: Path,
    task: str,
    environment: dict[str, str],
) -> dict[str, Any]:
    spec = _task_spec(args.user_id, task)
    task_started = time.monotonic()
    started_at = _utc_now()
    attempts: list[dict[str, Any]] = []
    selected_session: Path | None = None
    status = "harness_failure"
    final_error: str | None = None

    for attempt in range(1, args.task_retry_attempts + 1):
        session_dir = run_dir / "trials" / "trial_1" / "users" / args.user_id / task / f"attempt_{attempt}" / "baseline"
        session_dir.parent.mkdir(parents=True, exist_ok=True)
        command = canonical_command(args, task, session_dir)
        attempt_started = time.monotonic()
        return_code, stdout, stderr, timed_out = _run_process(command, environment, args.task_timeout)
        attempt_duration = time.monotonic() - attempt_started
        log_dir = run_dir / "logs" / args.user_id / task
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / f"attempt_{attempt}.stdout.log").write_text(_redact_run(stdout, args), encoding="utf-8")
        (log_dir / f"attempt_{attempt}.stderr.log").write_text(_redact_run(stderr, args), encoding="utf-8")
        finished = return_code == 0 and (session_dir / "submission.json").is_file() and (session_dir / "final_state.json").is_file()
        infrastructure = return_code == INFRASTRUCTURE_RETURN_CODE or timed_out
        policy = _provider_model_policy(session_dir, args.model)
        if policy["violation"]:
            finished = False
            infrastructure = True
            stderr = (stderr + "\nmodel policy violation: observed model differs from requested model").strip()
        attempts.append(
            {
                "attempt": attempt,
                "return_code": return_code,
                "timed_out": timed_out,
                "duration_seconds": round(attempt_duration, 6),
                "trajectory_path": str(session_dir),
                "retryable_infrastructure_failure": infrastructure,
            }
        )
        selected_session = session_dir
        if finished:
            status = "finished"
            final_error = None
            break
        final_error = _redact_run((stderr.strip() or stdout.strip() or f"canonical runner exited {return_code}")[-2000:], args)
        status = _classify_process_failure(return_code, timed_out, final_error)
        if not infrastructure:
            break

    assert selected_session is not None
    duration = time.monotonic() - task_started
    ended_at = _utc_now()
    artifact, artifact_path = _normalise_artifact(
        selected_session,
        run_dir,
        args,
        task,
        len(attempts),
        started_at,
        ended_at,
        duration,
        status,
        final_error,
    )
    legacy_evaluation = _json(selected_session / "evaluation.json", {})
    steps = max(
        (int(call.get("step") or 0) for call in artifact.model_calls if isinstance(call, dict)),
        default=0,
    )
    measurement = artifact.measurement
    session_usage = measurement["usage_reconciliation"]["session_usage"]
    metrics = {
        "input_tokens": int(session_usage.get("input_tokens") or 0),
        "output_tokens": int(session_usage.get("output_tokens") or 0),
        "total_tokens": int(session_usage.get("total_tokens") or 0),
        "model_calls": len(measurement["model_calls"]),
        "retrieval_calls": measurement["retrieval_calls"],
        "unique_image_views": int(artifact.diagnostics.get("unique_image_views", 0) or 0),
        "image_views": measurement["image_views"],
        "tool_calls": measurement["tool_calls"],
        "steps": steps,
    }
    if getattr(args, "token_tracking", False):
        from harness.camact_token_usage_v1.report import safe_report
        token_report = safe_report([selected_session.parents[1]], selected_session.parents[1] / "token_usage")
        metrics.update(dict.fromkeys(("input_tokens", "output_tokens", "total_tokens", "model_request_count")))
        if token_report:
            metrics.update({key: token_report["benchmark"]["tokens"][key]
                            for key in ("input_tokens", "output_tokens", "total_tokens")})
            metrics["model_request_count"] = token_report["benchmark"]["model_request_count"]
    return {
        "user_id": args.user_id,
        "task": task,
        "task_id": artifact.task_id or str(spec.get("task_id", task)),
        "trial": 1,
        "method": "canonical-baseline",
        "status": status,
        "trajectory_class": artifact.trajectory_class,
        "trajectory_path": str(selected_session),
        "standard_artifact_path": str(artifact_path),
        "attempt_count": len(attempts),
        "attempts": attempts,
        "duration_seconds": round(duration, 6),
        "score": legacy_evaluation.get("capability_score", legacy_evaluation.get("score")),
        "strict_success": legacy_evaluation.get("strict_success", legacy_evaluation.get("passed")),
        "metrics": metrics,
        "error": final_error,
    }


def _run_document(args: argparse.Namespace, run_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    provenance = _benchmark_provenance()
    config = {
        "parallel": args.parallel,
        "users": [args.user_id],
        "tasks": args.tasks,
        "trial_count": 1,
        "model": {
            "provider": args.provider,
            "base_url": args.base_url,
            "model": args.model,
            "timeout": args.timeout,
            "max_output_tokens": args.max_output_tokens,
            "retry_attempts": args.provider_retry_attempts,
            "secret_persisted": False,
        },
        "simulator_model": {
            "provider": args.provider,
            "base_url": args.simulator_base_url or args.base_url,
            "model": args.simulator_model or args.model,
            "timeout": args.simulator_timeout,
            "max_output_tokens": args.simulator_max_output_tokens,
            "retry_attempts": args.simulator_retry_attempts,
            "secret_persisted": False,
        },
        "budgets": {"max_steps": args.max_steps, "max_image_views": args.max_image_views,
                    "max_simulator_turns": getattr(args, "max_simulator_turns", 15)},
        "timeout": args.timeout,
        "task_timeout": args.task_timeout,
        "retry_policy": {
            "model_api": args.provider_retry_attempts,
            "task_infrastructure": args.task_retry_attempts,
            "simulator_api": args.simulator_retry_attempts,
        },
        "canonical_baseline": {
            "entrypoint": str(CANONICAL_RUNNER),
            "entrypoint_sha256": _sha256(CANONICAL_RUNNER),
            "aep_mode": "baseline",
            "prompt_history_tools_modified": False,
        },
        "benchmark_provenance": provenance,
        "api_key": None,
        "api_key_env": None,
    }
    manifest = {
        "schema_version": "camact_standard_run_v1",
        "run_id": getattr(args, "_run_id", run_dir.name),
        "experiment_type": "canonical_baseline_smoke",
        "method": "canonical-baseline",
        "started_at": _utc_now(),
        "secret_persisted": False,
        "benchmark_provenance": provenance,
        "canonical_entrypoint": config["canonical_baseline"],
        "reproducibility": {
            key: config[key]
            for key in ("parallel", "users", "tasks", "trial_count", "budgets", "timeout", "task_timeout", "retry_policy")
        },
    }
    if hasattr(args, "_roles"):
        from harness.camact_compatibility_v2.roles import public_role
        config["roles"] = {name: public_role(value) if value else None for name, value in args._roles.items()}
        config["model"] = config["roles"]["agent"]
        config["simulator_model"] = config["roles"]["simulator"]
        config["save_artifacts"] = bool(args.save_artifacts)
        config["canonical_baseline"]["observer_entrypoint"] = str(OBSERVED_RUNNER)
    return config, manifest


def _evaluate(run_dir: Path, judge: str) -> dict[str, Any]:
    sys.path.insert(0, str(EVALUATION_ROOT))
    from camact_eval.aggregation import aggregate_results
    from camact_eval.evaluator import UnifiedEvaluator
    from camact_eval.schema import StandardRunArtifact, validate_evaluation_result_document, visual_paths

    standard_index = run_dir / "standard_run_artifacts.jsonl"
    if standard_index.is_file():
        artifacts = [StandardRunArtifact.from_dict({**row, "visual_evidence": visual_paths(row.get("visual_evidence", {}), standard_index)}, strict=True) for row in _jsonl(standard_index)]
        adapter_name = "standard"
    else:
        from camact_eval.adapters import BaselineAdapter

        artifacts = BaselineAdapter(PROJECT_ROOT).adapt(run_dir)
        adapter_name = "baseline"
    evaluations = UnifiedEvaluator(PROJECT_ROOT, judge=judge).evaluate_many(artifacts)
    document = {
        "schema_version": "camact.standard_evaluation_result.v1",
        "source": str(run_dir),
        "adapter": adapter_name,
        "judge": judge,
        "evaluations": evaluations,
        "summary": aggregate_results(artifacts, evaluations),
    }
    validate_evaluation_result_document(document)
    _write_json(run_dir / "evaluation_summary.json", document)
    return document


def cmd_probe(args: argparse.Namespace) -> int:
    sys.path.insert(0, str(BENCHMARK_ROOT))
    from benchmark_runner.mllm_adapter import ProviderConfig, create_adapter

    config = ProviderConfig(
        provider=args.provider,
        model=args.model,
        api_base=args.base_url.rstrip("/"),
        api_key=args.api_key,
        timeout_seconds=args.timeout,
        max_output_tokens=256,
        retry_attempts=1,
    )
    adapter = create_adapter(config)
    results: list[dict[str, Any]] = []
    request = urllib.request.Request(
        f"{args.base_url.rstrip('/')}/models",
        headers={"Authorization": f"Bearer {args.api_key}", "Accept": "application/json"},
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        found = any(str(item.get("id")) == args.model for item in payload.get("data", []) if isinstance(item, dict))
        results.append({"probe": "models", "ok": found, "http_status": 200, "duration_seconds": round(time.monotonic() - started, 3)})
    except Exception as exc:
        results.append({"probe": "models", "ok": False, "error": _redact(str(exc), args.api_key), "duration_seconds": round(time.monotonic() - started, 3)})

    probes: list[tuple[str, list[dict[str, Any]], list[dict[str, Any]]]] = [
        (
            "text",
            [{"role": "user", "content": [{"type": "text", "text": "Reply exactly: OK"}]}],
            [],
        )
    ]
    ping_tool = [{
        "type": "function",
        "function": {
            "name": "ping",
            "description": "Return a connectivity acknowledgement.",
            "parameters": {
                "type": "object",
                "properties": {"message": {"type": "string"}},
                "required": ["message"],
                "additionalProperties": False,
            },
        },
    }]
    probes.append(("tool", [{"role": "user", "content": [{"type": "text", "text": "Call ping exactly once."}]}], ping_tool))
    image = next((BENCHMARK_ROOT / "users" / args.user_id / "base_memory" / "images").glob("*.jpg"), None)
    if image:
        media_type = mimetypes.guess_type(image.name)[0] or "image/jpeg"
        data = base64.b64encode(image.read_bytes()).decode("ascii")
        probes.append(
            (
                "visual_tool",
                [{"role": "user", "content": [
                    {"type": "text", "text": "Confirm the image is visible by calling ping exactly once."},
                    {"type": "image_url", "image_url": {"url": f"data:{media_type};base64,{data}"}},
                ]}],
                ping_tool,
            )
        )
    for name, history, tools in probes:
        started = time.monotonic()
        try:
            turn = adapter.complete(system_prompt="This is a non-mutating connectivity probe.", history=history, tools=tools)
            ok = bool(turn.tool_calls) if tools else bool(turn.text.strip())
            results.append(
                {
                    "probe": name,
                    "ok": ok,
                    "duration_seconds": round(time.monotonic() - started, 3),
                    "tool_calls": [call.name for call in turn.tool_calls],
                    "text": turn.text[:80],
                    "finish_reason": turn.raw_finish_reason,
                }
            )
        except Exception as exc:
            results.append({"probe": name, "ok": False, "error": _redact(str(exc), args.api_key), "duration_seconds": round(time.monotonic() - started, 3)})
    document = {"all_ok": all(item["ok"] for item in results), "model": args.model, "base_url": args.base_url, "results": results}
    print(json.dumps(document, ensure_ascii=False, indent=2))
    return 0 if document["all_ok"] else 2


def _execute_run(args: argparse.Namespace, run_dir: Path, environment: dict[str, str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not CANONICAL_RUNNER.is_file():
        raise SystemExit(f"canonical Baseline runner not found: {CANONICAL_RUNNER}")
    args.tasks = list(dict.fromkeys(args.tasks))
    for task in args.tasks:
        _task_spec(args.user_id, task)
    run_dir.mkdir(parents=True, exist_ok=False)
    config, manifest = _run_document(args, run_dir)
    _write_json(run_dir / "config.json", config)
    _write_json(run_dir / "run_manifest.json", manifest)
    _write_json(run_dir / "experiment_manifest.json", manifest)
    _write_json(
        run_dir / "run_config.json",
        {
            "run_id": getattr(args, "_run_id", run_dir.name),
            "trial": 1,
            "provider": args.provider,
            "model": args.model,
            "agent_model": args.model,
            "benchmark_release_id": config["benchmark_provenance"].get("release_id"),
            "benchmark_release_version": config["benchmark_provenance"].get("release_version"),
            "benchmark_manifest_sha256": config["benchmark_provenance"].get("manifest_sha256"),
        },
    )
    run_started = time.monotonic()
    results_by_task: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=args.parallel) as executor:
        futures = {executor.submit(_task_result, args, run_dir, task, environment): task for task in args.tasks}
        for future in as_completed(futures):
            task = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                failure_session = run_dir / "failed_sessions" / args.user_id / task
                failure_session.mkdir(parents=True, exist_ok=True)
                message = _redact_run(f"{type(exc).__name__}: {exc}", args)
                _artifact, failure_artifact_path = _normalise_artifact(
                    failure_session, run_dir, args, task, 0, _utc_now(), _utc_now(), 0.0,
                    "infrastructure_failure", message,
                )
                result = {
                    "user_id": args.user_id,
                    "task": task,
                    "task_id": str(_task_spec(args.user_id, task).get("task_id", task)),
                    "trial": 1,
                    "method": "canonical-baseline",
                    "status": "harness_failure",
                    "trajectory_class": "infrastructure_failure",
                    "trajectory_path": "",
                    "standard_artifact_path": str(failure_artifact_path),
                    "attempt_count": 0,
                    "attempts": [],
                    "duration_seconds": 0.0,
                    "score": None,
                    "strict_success": False,
                    "metrics": {},
                    "error": message,
                }
            results_by_task[task] = result
            print(json.dumps({"type": "task_finished", "task": task, "status": result["status"], "duration_seconds": result["duration_seconds"]}, ensure_ascii=False), flush=True)
    results = [results_by_task[task] for task in args.tasks]
    _write_jsonl(run_dir / "task_results.jsonl", results)
    sys.path.insert(0, str(EVALUATION_ROOT))
    from camact_eval.schema import StandardRunArtifact
    standard_index = run_dir / "standard_run_artifacts.jsonl"
    standard_rows = [
        StandardRunArtifact.read(Path(result["standard_artifact_path"])).document_for_path(standard_index)
        for result in results
        if result.get("standard_artifact_path")
    ]
    _write_jsonl(standard_index, standard_rows)
    metric_keys = ("input_tokens", "output_tokens", "total_tokens", "model_calls", "retrieval_calls", "unique_image_views", "image_views", "tool_calls", "steps")
    totals = {key: sum(int(item.get("metrics", {}).get(key, 0) or 0) for item in results) for key in metric_keys}
    if getattr(args, "token_tracking", False):
        for key in ("input_tokens", "output_tokens", "total_tokens"):
            if any(item.get("metrics", {}).get(key) is None for item in results):
                totals[key] = None
    finished = [item for item in results if item["status"] == "finished"]
    scores = [float(item["score"]) for item in finished if isinstance(item.get("score"), (int, float))]
    summary = {
        "schema_version": "camact_standard_summary_v1",
        "run_id": getattr(args, "_run_id", run_dir.name),
        "method": "canonical-baseline",
        "requested_tasks": len(results),
        "completed_tasks": len(results),
        "finished_tasks": len(finished),
        "strict_success_count": sum(bool(item.get("strict_success")) for item in finished),
        "strict_success_rate": round(sum(bool(item.get("strict_success")) for item in finished) / len(finished), 6) if finished else 0.0,
        "average_runtime_score": round(sum(scores) / len(scores), 6) if scores else None,
        "duration_seconds": round(time.monotonic() - run_started, 6),
        "usage": {key: totals[key] for key in ("input_tokens", "output_tokens", "total_tokens")},
        "aggregate_metrics": totals,
        "failure_classification": {
            "agent_failure": sum(item["trajectory_class"] == "agent_failure" for item in results),
            "infrastructure_failure": sum(item["trajectory_class"] == "infrastructure_failure" for item in results),
            "harness_failure": sum(item["trajectory_class"] == "harness_failure" for item in results),
            "retry": sum(max(0, int(item.get("attempt_count", 1)) - 1) for item in results),
        },
        "results": results,
        "finished_at": _utc_now(),
    }
    _write_json(run_dir / "summary.json", summary)
    return results, summary


def cmd_run(args: argparse.Namespace) -> int:
    from harness.camact_compatibility_v2.artifacts import RunArtifacts, evaluate_artifacts
    from harness.camact_compatibility_v2.roles import judge_environment

    _configure_roles(args)
    from harness.camact_token_usage_v1.collector import enabled
    from harness.camact_token_usage_v1.report import safe_report
    args.token_tracking = enabled(args._config, getattr(args, "token_tracking", None))
    output = Path(args.run_dir).resolve() if args.run_dir else _default_run_dir()
    secrets = tuple(role["api_key"] for role in args._roles.values() if role and role.get("api_key"))
    with RunArtifacts(output, save_artifacts=args.save_artifacts, secrets=secrets) as store:
        args._run_id = store.run_id
        if not args.run_dir:
            _register_default_archive(store.output, save_artifacts=args.save_artifacts)
        run_dir = store.work_dir / "execution"
        judge_role = args._roles["judge"] if args.judge == "env" else None
        with (judge_environment(judge_role) if judge_role else nullcontext({})) as judge_env:
            environment = _child_environment(args.api_key)
            if args.token_tracking:
                environment["CAMACT_TOKEN_RUN_ID"] = str(store.output)
            if judge_env:
                environment.update(judge_env)
            # Preserve the Agent Episode without an extra, discarded Judge call.
            # The formal evaluator below is the authoritative grading boundary.
            environment["CAMACT_JUDGE_API_KEY_ENV"] = "CAMACT_BASELINE_DISABLED_JUDGE_KEY"
            environment.pop("CAMACT_BASELINE_DISABLED_JUDGE_KEY", None)
            sim = args._roles["simulator"]
            environment[SIMULATOR_KEY_ENV] = sim["api_key"] if sim else "unused"
            environment["CAMACT_BASELINE_SIMULATOR_PROVIDER"] = "relay"
            environment["CAMACT_BASELINE_AGENT_PARAMETERS"] = json.dumps(args._roles["agent"]["parameters"])
            try:
                results, summary = _execute_run(args, run_dir, environment)
            finally:
                if args.token_tracking:
                    safe_report([run_dir], store.output / "token_usage")
            document = evaluate_artifacts(
                run_dir / "standard_run_artifacts.jsonl", PROJECT_ROOT,
                judge_role=judge_role, judge_mode=args.judge,
                output=run_dir / "evaluation_summary.json",
                evaluation_python=args._config.get("evaluation", {}).get("python_windows" if os.name == "nt" else "python",
                    args._config.get("evaluation", {}).get("python")),
            )
        config = _json(run_dir / "config.json", {})
        store.finish(document, config=config, summary={**summary, "unified_summary": document.get("summary", {})})
    finished = [result for result in results if result["status"] == "finished"]
    print(
        json.dumps(
            {
                "type": "run_finished",
                "run_dir": str(output),
                "completed": len(results),
                "finished": len(finished),
                "unified_evaluated": len(document["evaluations"]),
                "save_artifacts": args.save_artifacts,
                **({"token_usage_report": str(output / "token_usage/summary.json")} if args.token_tracking else {}),
            },
            ensure_ascii=False,
        ),
        flush=True,
    )
    return 0 if len(finished) == len(results) and len(document["evaluations"]) == len(results) else 2


def cmd_evaluate(args: argparse.Namespace) -> int:
    from harness.camact_compatibility_v2.artifacts import evaluate_artifacts
    from harness.camact_compatibility_v2.roles import role_provider
    run_dir = Path(args.run_dir).resolve()
    config = _json(Path(args.config) if args.config else DEFAULT_CONFIG, {})
    judge_role = None
    if args.judge == "env":
        source = config.get("roles", config)
        judge_role = role_provider(source.get("judge", {}), role="judge", protocol="openai-chat")
    candidates = (run_dir / "standard_run_artifacts.jsonl", run_dir / "runs" / "execution" / "standard_run_artifacts.jsonl")
    source = next((path for path in candidates if path.is_file()), run_dir)
    document = evaluate_artifacts(source, PROJECT_ROOT, judge_role=judge_role, judge_mode=args.judge,
                                  output=run_dir / "rescore" / "result.json", evaluation_python=config.get("evaluation", {}).get(
                                      "python_windows" if os.name == "nt" else "python", config.get("evaluation", {}).get("python")))
    print(json.dumps({"run_dir": str(run_dir), "evaluated": len(document["evaluations"]), "judge": args.judge}, ensure_ascii=False))
    return 0


def _connection_arguments(parser: argparse.ArgumentParser, *, required: bool = True) -> None:
    parser.add_argument("--provider", default="relay" if required else None, choices=["relay", "openai", "anthropic", "gemini", "qwen"])
    parser.add_argument("--base-url", required=required)
    parser.add_argument("--model", required=required)
    credentials = parser.add_mutually_exclusive_group(required=required)
    credentials.add_argument("--api-key")
    credentials.add_argument("--api-key-env", help="Read the API key from this environment variable.")
    parser.add_argument("--timeout", type=float, default=180.0 if required else None)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Thin harness for the canonical CamAct Baseline agent loop")
    sub = parser.add_subparsers(dest="command", required=True)
    probe = sub.add_parser("probe", help="run non-mutating model, tool, and visual connectivity probes")
    _connection_arguments(probe)
    probe.add_argument("--user-id", default="10129939_N08")
    probe.set_defaults(function=cmd_probe)

    run = sub.add_parser("run", help="run selected tasks through the canonical Baseline loop")
    _connection_arguments(run, required=False)
    run.add_argument("--config", help="Independent Agent/Simulator/Judge role configuration; defaults to shared config.wsl.json.")
    run.add_argument("--user-id", required=True)
    run.add_argument("--tasks", nargs="+", required=True)
    run.add_argument("--parallel", type=int, default=1)
    run.add_argument("--max-steps", type=int)
    run.add_argument("--max-simulator-turns", type=int)
    run.add_argument("--max-image-views", type=int)
    run.add_argument("--max-output-tokens", type=int)
    run.add_argument("--provider-retry-attempts", type=int)
    run.add_argument("--task-retry-attempts", type=int)
    run.add_argument("--task-timeout", type=float)
    run.add_argument("--simulator-provider")
    run.add_argument("--simulator-model")
    run.add_argument("--simulator-base-url")
    run.add_argument("--simulator-api-key-env")
    run.add_argument("--simulator-timeout", type=float)
    run.add_argument("--simulator-max-output-tokens", type=int)
    run.add_argument("--simulator-retry-attempts", type=int)
    run.add_argument("--judge-provider")
    run.add_argument("--judge-model")
    run.add_argument("--judge-base-url")
    run.add_argument("--judge-api-key-env")
    run.add_argument("--judge-timeout", type=float)
    run.add_argument("--judge-max-output-tokens", type=int)
    run.add_argument("--judge-retry-attempts", type=int)
    run.add_argument("--run-dir")
    run.add_argument("--evaluate", action="store_true", help="Compatibility flag; every run is now evaluated before cleanup.")
    run.add_argument("--save-artifacts", action="store_true", help="Keep full execution records and portable visual evidence after scoring.")
    run.add_argument("--token-tracking", action=argparse.BooleanOptionalAction, default=None,
                     help="Collect Agent model usage; overrides token_tracking.enabled (default off)")
    run.add_argument("--judge", choices=["off", "env", "replay"], default="env")
    run.set_defaults(function=cmd_run)

    evaluate = sub.add_parser("evaluate", help="re-evaluate a Baseline run with the existing Unified Evaluator")
    evaluate.add_argument("--run-dir", required=True)
    evaluate.add_argument("--config")
    evaluate.add_argument("--judge", choices=["off", "env", "replay"], default="env")
    evaluate.set_defaults(function=cmd_evaluate)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if hasattr(args, "api_key_env") and getattr(args, "api_key_env", None):
        args.api_key = os.environ.get(args.api_key_env, "")
        if not args.api_key:
            parser.error(f"environment variable {args.api_key_env} is not set")
    if hasattr(args, "parallel") and args.parallel < 1:
        raise SystemExit("--parallel must be at least 1")
    return int(args.function(args))
