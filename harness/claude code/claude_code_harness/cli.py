"""Command-line entry point for the Claude Code Harness."""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

from .core import (
    claude_runtime_info,
    benchmark_provenance,
    load_settings,
    parse_values,
    read_json,
    redact_text,
    safe_name,
    task_handles,
    write_json,
)
from .native_runner import audit_run_isolation, finalize_run, run_tasks, validate_native_model_settings, write_run_manifest
from .provider_bridge import AnthropicTelemetryProxy, OpenAIProtocolBridge, api_key_diagnostic, requires_protocol_bridge


def _load_config(path: Path | None) -> dict[str, Any]:
    if not path:
        local = Path(__file__).resolve().parents[1] / "config.local.json"
        if not local.is_file():
            return {}
        path = local
    if not path.is_file():
        raise SystemExit(f"config file does not exist: {path}")
    value = read_json(path, {})
    if not isinstance(value, dict):
        raise SystemExit("config file must contain a JSON object")
    return value


def _default_run_dir(benchmark: Path, model: str, tool_profile: str = "native") -> Path:
    from datetime import datetime
    from zoneinfo import ZoneInfo
    from uuid import uuid4
    now = datetime.now(ZoneInfo("Asia/Shanghai"))
    experiment = f"camact-claude-tools-v1-{tool_profile}-{now:%H%M%S}-{uuid4().hex[:8]}"
    return (benchmark.parent / "harness" / "_log" / now.strftime("%Y-%m-%d") /
            experiment / "runs" / f"{safe_name(model)}-{tool_profile}")


def _register_default_archive(run_root: Path, settings) -> None:
    archive = run_root.parents[1]
    for name in ("report", "manifest", "evaluation"):
        (archive / name).mkdir(exist_ok=True)
    text = (f"# {archive.name}\n\nDate: {archive.parent.name} (Asia/Shanghai). Type: Claude Code run.\n"
            f"Profile: {settings.tool_profile}. Method: claude-code native loop / dual profiles v1.\n"
            f"Original and archive location: {archive}. Raw run: runs/{run_root.name}/.\n"
            "Canonical benchmark / GT / rubric / simulator / baseline / evaluator / protocol: unchanged.\n"
            "Configuration and commit: raw run/run_manifest.json; result: raw run/summary.json; "
            "artifacts: raw run/standard_run_artifacts.jsonl. No credentials are persisted.\n")
    (archive / "README.md").write_text(text, encoding="utf-8")
    for index, link in ((archive.parent / "README.md", f"{archive.name}/README.md"),
                        (archive.parents[1] / "EXPERIMENT_INDEX.md", f"{archive.parent.name}/{archive.name}/README.md")):
        with index.open("a", encoding="utf-8") as stream:
            stream.write(f"\n- [{archive.name}]({link}): Claude Code {settings.tool_profile}; see run manifest and summary.\n")


def _make_run_root(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=False)
    for name in ("tasks", "traces", "stdout", "stderr", "logs", "submissions", "artifacts", "sessions", "evaluation"):
        (path / name).mkdir()


def _judge_mode(args, file_config):
    value = getattr(args, "judge", None)
    if value is None:
        configured = file_config.get("judge")
        if isinstance(configured, dict):
            value = configured.get("mode", "env")
        elif configured is not None:
            value = configured
        else:
            value = "env" if file_config.get("judge_provider") else "off"
    if value not in {"off", "env"}:
        raise ValueError("judge mode must be off or env; provider settings belong in judge_provider")
    return value


def env_check(args: argparse.Namespace) -> int:
    """Report the real CLI/runtime available to the current host/distro."""
    windows = platform.system() == "Windows"
    commands = {
        "claude_path": ["which", "claude"] if not windows else ["where", "claude"],
        "claude_version": ["claude.cmd", "--version"] if windows else ["claude", "--version"],
        "node_version": ["node.exe", "--version"] if windows else ["node", "--version"],
        "npm_version": ["npm.cmd", "--version"] if windows else ["npm", "--version"],
    }
    result: dict[str, Any] = {"platform": platform.platform(), "python": sys.version.split()[0], "distro": os.environ.get("WSL_DISTRO_NAME")}
    for key, command in commands.items():
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
            result[key] = {"command": command, "returncode": completed.returncode, "stdout": completed.stdout.strip(), "stderr": completed.stderr.strip()}
        except (OSError, subprocess.SubprocessError) as exc:
            result[key] = {"command": command, "error": f"{type(exc).__name__}: {exc}"}
    if platform.system() == "Windows":
        try:
            completed = subprocess.run(["wsl.exe", "--list", "--verbose"], capture_output=True, text=True, timeout=20, check=False)
            wsl_stdout = completed.stdout
            # `wsl.exe --list` may emit UTF-16LE even when text mode guesses a
            # legacy code page, leaving NULs in JSON output.
            if "\x00" in wsl_stdout:
                try:
                    wsl_stdout = wsl_stdout.encode("latin-1", errors="ignore").decode("utf-16le", errors="replace")
                except UnicodeError:
                    pass
            result["wsl_list"] = {"returncode": completed.returncode, "stdout": wsl_stdout, "stderr": completed.stderr}
        except OSError as exc:
            result["wsl_list"] = {"error": str(exc)}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def connectivity_check(args: argparse.Namespace) -> int:
    """Run one minimal non-interactive CLI probe using current credentials."""
    settings = load_settings(args, _load_config(args.config))
    validate_native_model_settings(settings)
    args.model, args.base_url, args.api_key = settings.model, settings.base_url, settings.api_key
    executable = "claude.cmd" if platform.system() == "Windows" else "claude"
    command = [executable, "-p", "Reply with exactly OK", "--output-format", "json", "--no-session-persistence", "--tools", "", "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}', "--disable-slash-commands", "--permission-mode", "bypassPermissions", "--model", args.model]
    bridge_context = (
        OpenAIProtocolBridge(
            base_url=args.base_url,
            api_key=args.api_key,
            model=args.model,
            timeout=args.timeout,
            request_attempts=args.request_attempts,
        )
        if requires_protocol_bridge(args.model) else
        AnthropicTelemetryProxy(base_url=args.base_url, api_key=args.api_key,
                                model=args.model, timeout=args.timeout)
        if args.base_url and args.api_key else None
    )
    context = bridge_context or contextlib.nullcontext()
    try:
        with context as bridge:
            env = os.environ.copy()
            env["ANTHROPIC_MODEL"] = args.model
            env["ANTHROPIC_SMALL_FAST_MODEL"] = args.model
            env["CLAUDE_CODE_SUBAGENT_MODEL"] = args.model
            env["CLAUDE_CODE_MODEL"] = args.model
            env["CLAUDE_CODE_SMALL_FAST_MODEL"] = args.model
            env["CLAUDE_CODE_FALLBACK_MODEL"] = args.model
            env["ANTHROPIC_FALLBACK_MODEL"] = args.model
            env["CLAUDE_CODE_UTILITY_MODEL"] = args.model
            env["ANTHROPIC_UTILITY_MODEL"] = args.model
            env["CLAUDE_CODE_PRIMARY_MODEL"] = args.model
            if bridge:
                env["ANTHROPIC_BASE_URL"] = bridge.local_base_url
                env["ANTHROPIC_API_KEY"] = "camact-local-protocol-bridge"
            else:
                if args.base_url:
                    env["ANTHROPIC_BASE_URL"] = args.base_url
                if args.api_key:
                    env["ANTHROPIC_API_KEY"] = args.api_key
            completed = subprocess.run(command, capture_output=True, text=True, timeout=args.task_timeout, check=False, cwd=args.cwd or None, env=env)
            output = completed.stdout.strip() or completed.stderr.strip()
            try:
                cli_result = json.loads(completed.stdout)
            except (json.JSONDecodeError, TypeError):
                cli_result = {}
            cli_success = (
                isinstance(cli_result, dict)
                and cli_result.get("subtype") == "success"
                and not cli_result.get("is_error")
                and not cli_result.get("errors")
                and str(cli_result.get("result") or "").strip() == "OK"
            )
            document = {
                "command": command,
                "returncode": completed.returncode,
                "ok": completed.returncode == 0 and cli_success and "Not logged in" not in output,
                "output": redact_text(output[:2000], [args.api_key]),
                "protocol_bridge": bridge.snapshot() if bridge else {"enabled": False},
            }
            if isinstance(bridge, OpenAIProtocolBridge):
                harness_input = api_key_diagnostic(args.api_key)
                authorization_header = bridge.authorization_diagnostic()
                document["api_key_diagnostics"] = {
                    "A_harness_input": harness_input,
                    "B_authorization_header": authorization_header,
                    "match": harness_input == authorization_header,
                }
        print(json.dumps(document, ensure_ascii=False, indent=2))
        return 0 if document["ok"] else 2
    except subprocess.TimeoutExpired:
        print(json.dumps({"command": command, "ok": False, "error": f"timeout after {args.task_timeout}s"}, ensure_ascii=False, indent=2))
        return 2
    except OSError as exc:
        print(json.dumps({"command": command, "ok": False, "error": redact_text(f"{type(exc).__name__}: {exc}", [args.api_key])}, ensure_ascii=False, indent=2))
        return 2


def _run(args: argparse.Namespace) -> int:
    """Keep complete temporary evidence until the formal evaluation finishes."""
    from harness.camact_compatibility_v2.artifacts import RunArtifacts
    file_config = _load_config(args.config)
    settings = load_settings(args, file_config)
    validate_native_model_settings(settings)
    if args.resume_run:
        if not args.save_artifacts:
            raise ValueError("--resume-run requires --save-artifacts; historical artifacts are never temporary")
        # Resume deliberately owns the supplied historical run, never a cleanup
        # context. Its files are retained regardless of subsequent failures.
        if args.run_dir and (args.run_dir.resolve() / "runs/execution").is_dir():
            from harness.camact_compatibility_v2.roles import public_config
            output = args.run_dir.resolve()
            local_args = argparse.Namespace(**vars(args))
            local_args.run_dir = output / "runs/execution"
            local_args.evaluate = True
            status = _run_existing(local_args)
            secrets = [settings.api_key]
            secrets.extend(role.get("api_key", "") for role in (settings.simulator_provider, settings.judge_provider) if role)
            document = read_json(local_args.run_dir / "evaluation/result.json", {})
            from evaluation.camact_eval.schema import validate_evaluation_result_document
            validate_evaluation_result_document(document)
            document["artifact_retention"] = {"saved": True, "raw_location": "runs/execution", "rescoring_supported": True}
            write_json(output / "result.json", public_config(document, secrets=secrets))
            write_json(output / "summary.json", public_config(read_json(local_args.run_dir / "summary.json", {}), secrets=secrets))
            if settings.token_tracking:
                from harness.camact_token_usage_v1.report import safe_report
                safe_report([local_args.run_dir], output / "token_usage")
            return status
        return _run_existing(args)
    output = args.run_dir.resolve() if args.run_dir else _default_run_dir(args.benchmark.resolve(), settings.model, settings.tool_profile)
    secrets = [settings.api_key]
    secrets.extend(role.get("api_key", "") for role in (settings.simulator_provider, settings.judge_provider) if role)
    with RunArtifacts(output, save_artifacts=args.save_artifacts, secrets=secrets) as storage:
        local_args = argparse.Namespace(**vars(args))
        local_args.run_dir = storage.work_dir / "execution"
        local_args.evaluate = True
        try:
            status = _run_existing(local_args)
        finally:
            if settings.token_tracking:
                from harness.camact_token_usage_v1.report import safe_report
                safe_report([local_args.run_dir], storage.output / "token_usage")
        result = read_json(local_args.run_dir / "evaluation" / "result.json", None)
        if not isinstance(result, dict):
            raise ValueError("Run did not produce a complete Unified Evaluator result; transient evidence was not marked finished")
        storage.finish(result, config=settings.public_dict(), summary=read_json(local_args.run_dir / "summary.json", {}))
    if args.run_dir is None:
        _register_default_archive(output, settings)
    print(json.dumps({"type": "artifacts_finalized", "result": str(output / "result.json"),
                      "save_artifacts": args.save_artifacts,
                      **({"token_usage_report": str(output / "token_usage/summary.json")} if settings.token_tracking else {})}, ensure_ascii=False), flush=True)
    return status


def _run_existing(args: argparse.Namespace) -> int:
    benchmark = args.benchmark.resolve()
    if not benchmark.is_dir():
        raise SystemExit(f"benchmark directory does not exist: {benchmark}")
    file_config = _load_config(args.config)
    args.judge = _judge_mode(args, file_config)
    settings = load_settings(args, file_config)
    # Reject divergent auxiliary model configuration before creating a run
    # directory or starting any benchmark task.
    validate_native_model_settings(settings)
    runtime_info = claude_runtime_info()
    settings.claude_version = runtime_info.get("version")
    settings.executable_path = runtime_info.get("path")
    users = parse_values((args.users or []) + (args.user or [])) or None
    tasks = parse_values((args.tasks or []) + (args.task or [])) or None
    handles = task_handles(benchmark, users=users, tasks=tasks)
    run_root = args.run_dir.resolve() if args.run_dir else _default_run_dir(benchmark, settings.model, settings.tool_profile)
    retained, deferred = [], []
    if args.resume_run:
        from .resume import prepare_resume
        retained, handles = prepare_resume(run_root, benchmark, settings, handles, args.resume_retry_policy_change)
        if args.resume_defer_exhausted:
            from .resume import defer_exhausted
            handles, deferred = defer_exhausted(run_root, handles, settings.retries)
    elif args.resume_defer_exhausted:
        raise ValueError('--resume-defer-exhausted requires --resume-run')
    else:
        _make_run_root(run_root)
    if args.run_dir is None:
        _register_default_archive(run_root, settings)
    if not args.resume_run:
        write_run_manifest(run_root, benchmark, settings, handles, sys.argv[1:])
    print(json.dumps({"type": "run_started", "tool_profile": settings.tool_profile, "run_dir": str(run_root), "tasks": len(handles), "parallel": settings.parallel, "model": settings.model, "distro": settings.distro}, ensure_ascii=False), flush=True)
    results = retained + run_tasks(handles, benchmark_root=benchmark, run_root=run_root, run_id=run_root.name, settings=settings, resume=args.resume_run)
    if settings.token_tracking:
        from harness.camact_token_usage_v1.report import safe_report
        safe_report([run_root / "tasks"], run_root / "token_usage")
    if deferred:
        checkpoint = {'type': 'run_checkpoint', 'terminal_count': len(results),
                      'deferred_tasks': [h.task_name for h in deferred],
                      'reason': 'Infrastructure budget choice pending; no terminal result created for deferred tasks',
                      'evaluated': False}
        index = len(list((run_root / 'logs').glob('deferred_*.json'))) + 1
        write_json(run_root / 'logs' / f'deferred_{index:02d}.json', checkpoint)
        print(json.dumps(checkpoint), flush=True)
        return 0
    summary = finalize_run(run_root, results)
    isolation = audit_run_isolation(run_root)
    summary["isolation_audit"] = {"passed": isolation["passed"], "violations": len(isolation["violations"])}
    evaluate_code = _evaluate_run(
        run_root,
        benchmark,
        judge=args.judge,
        judge_settings=settings if args.judge == "env" else None,
        evaluation_python=getattr(args, "evaluation_python", None) or file_config.get("evaluation", {}).get("python_windows" if os.name == "nt" else "python"),
    ) if args.evaluate else None
    if evaluate_code is not None:
        summary["evaluation"] = evaluate_code
    write_json(run_root / "summary.json", summary)
    print(json.dumps({"type": "run_finished", "run_dir": str(run_root), "completed": len(results), "successful": summary["successful_tasks"], "evaluation": evaluate_code}, ensure_ascii=False))
    if not isolation["passed"]:
        return 3
    return 0 if all(item.get("status") == "success" for item in results) else 2


def _evaluate_run(
    run_root: Path,
    benchmark: Path,
    *,
    judge: str = "off",
    judge_settings: Any | None = None,
    evaluation_python: str | None = None,
) -> dict[str, Any]:
    """Call only the existing Unified Evaluator; no scoring is implemented here."""
    from harness.camact_compatibility_v2.artifacts import evaluate_artifacts
    from evaluation.camact_eval.schema import StandardRunArtifact

    source = run_root / "standard_run_artifacts.jsonl"
    rows = []
    for path in sorted((run_root / "artifacts").glob("*/*.json")):
        value = StandardRunArtifact.read(path)
        rows.append(value.document_for_path(source))
    source.write_text("".join(json.dumps(item, ensure_ascii=False) + "\n" for item in rows), encoding="utf-8")
    role = judge_settings.judge_provider if judge == "env" and judge_settings is not None else None
    document = evaluate_artifacts(source, benchmark, judge_role=role, judge_mode=judge,
        output=run_root / "evaluation" / "result.json", evaluation_python=evaluation_python)
    return {"evaluated_tasks": len(document["evaluations"]), "summary": document["summary"],
            "result_path": str(run_root / "evaluation" / "result.json")}


def _evaluate(args: argparse.Namespace) -> int:
    run_root = args.run_dir.resolve()
    config = read_json(run_root / "config.json", {})
    benchmark = Path(args.benchmark or config.get("benchmark", "")).resolve()
    if not benchmark.is_dir():
        raise SystemExit(f"benchmark directory does not exist: {benchmark}")
    file_config = _load_config(args.config)
    args.judge = _judge_mode(args, file_config)
    judge_settings = None
    if args.judge == "env":
        judge_settings = load_settings(args, file_config)
    result = _evaluate_run(run_root, benchmark, judge=args.judge, judge_settings=judge_settings,
        evaluation_python=getattr(args, "evaluation_python", None) or file_config.get("evaluation", {}).get("python_windows" if os.name == "nt" else "python"))
    print(json.dumps({"run_dir": str(run_root), **result}, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="claude_code_harness")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("env-check", help="inspect Windows/WSL Claude Code runtime")
    check.set_defaults(func=env_check)
    probe = sub.add_parser("connectivity-check", help="run a minimal Claude Code non-interactive probe")
    probe.add_argument("--timeout", type=float, default=60.0)
    probe.add_argument("--request-attempts", type=int, default=4)
    probe.add_argument("--task-timeout", type=float, default=900.0)
    probe.add_argument("--cwd", type=Path)
    probe.add_argument("--config", type=Path)
    probe.add_argument("--base-url")
    probe.add_argument("--model")
    probe.add_argument("--api-key")
    probe.add_argument("--api-key-env")
    probe.set_defaults(func=connectivity_check)

    run = sub.add_parser("run", help="run benchmark tasks with Claude Code CLI")
    run.add_argument("--benchmark", type=Path, required=True)
    run.add_argument("--config", type=Path)
    run.add_argument("--base-url")
    run.add_argument("--model")
    run.add_argument("--tool-profile", choices=["native", "camact"], help="default: native; camact adds task-declared domain MCP tools")
    run.add_argument("--api-key")
    run.add_argument("--api-key-env")
    run.add_argument("--distro")
    run.add_argument("--user", action="append")
    run.add_argument("--users", nargs="*")
    run.add_argument("--task", action="append")
    run.add_argument("--tasks", nargs="*")
    run.add_argument("--parallel", type=int)
    run.add_argument("--timeout", type=float)
    run.add_argument("--retries", type=int)
    run.add_argument("--request-attempts", type=int)
    run.add_argument("--agent-request-attempts", type=int)
    run.add_argument("--agent-retry-delay", type=float)
    run.add_argument("--task-timeout", type=float)
    run.add_argument("--max-agent-turns", type=int)
    run.add_argument("--max-simulator-rounds", type=int)
    run.add_argument("--max-output-tokens", type=int)
    run.add_argument("--simulator-max-output-tokens", type=int)
    run.add_argument("--simulator-timeout", type=float)
    run.add_argument("--simulator-request-attempts", type=int)
    run.add_argument("--judge-timeout", type=float)
    run.add_argument("--judge-request-attempts", type=int)
    run.add_argument("--judge-max-output-tokens", type=int)
    run.add_argument("--permission-mode", choices=["default", "acceptEdits", "bypassPermissions", "dontAsk", "plan"])
    run.add_argument("--allow-bash", action="store_true", help=argparse.SUPPRESS)
    run.add_argument("--run-dir", type=Path)
    run.add_argument("--resume-run", action="store_true", help="retain terminal tasks and continue within original infrastructure budget")
    run.add_argument("--resume-retry-policy-change", action="store_true", help="record an explicitly authorized Agent provider retry policy change")
    run.add_argument("--resume-defer-exhausted", action="store_true", help="continue eligible tasks while leaving exhausted pending tasks without terminal results or evaluation")
    run.add_argument("--evaluate", action="store_true", help="Compatibility flag: run now always evaluates before cleanup")
    run.add_argument("--save-artifacts", action="store_true", help="Keep complete raw sessions and evidence after evaluation")
    run.add_argument("--evaluation-python", help="Explicit Python 3.13 evaluator executable")
    run.add_argument("--token-tracking", action=argparse.BooleanOptionalAction, default=None,
                     help="Collect Agent model usage; default off")
    run.add_argument("--judge", choices=["off", "env"])
    run.set_defaults(func=_run)

    evaluate = sub.add_parser("evaluate", help="re-run Unified Evaluator on Standard Run Artifacts")
    evaluate.add_argument("--run-dir", type=Path, required=True)
    evaluate.add_argument("--benchmark", type=Path)
    evaluate.add_argument("--config", type=Path)
    evaluate.add_argument("--base-url")
    evaluate.add_argument("--model")
    evaluate.add_argument("--api-key")
    evaluate.add_argument("--api-key-env")
    evaluate.add_argument("--timeout", type=float)
    evaluate.add_argument("--request-attempts", type=int)
    evaluate.add_argument("--task-timeout", type=float)
    evaluate.add_argument("--retries", type=int)
    evaluate.add_argument("--parallel", type=int)
    evaluate.add_argument("--distro")
    evaluate.add_argument("--permission-mode")
    evaluate.add_argument("--allow-bash", action="store_true", help=argparse.SUPPRESS)
    evaluate.add_argument("--judge", choices=["off", "env"])
    evaluate.add_argument("--evaluation-python", help="Explicit Python 3.13 evaluator executable")
    evaluate.set_defaults(func=_evaluate)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
