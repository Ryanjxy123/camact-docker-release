from __future__ import annotations
import argparse
import json
from pathlib import Path
from .config import load, archive_path, NAMES, METHODS

def main():
    p = argparse.ArgumentParser(description="CamAct official multi-harness outer adapter")
    p.add_argument("--config", type=Path, default=Path(__file__).resolve().parents[3] / "config/server.linux-local.json")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("check-config")
    offline = sub.add_parser("offline")
    offline.add_argument("--archive", required=True)
    run = sub.add_parser("run", help="Execute one real task only after providers are configured")
    for option in ("harness", "user", "task", "output"):
        run.add_argument("--" + option, required=True, **({"choices": NAMES} if option == "harness" else {}))
    run.add_argument("--save-artifacts", action="store_true", help="Retain complete raw evidence after Unified Evaluator finishes")
    run.add_argument("--evaluation-python", help="Explicit Python 3.13 evaluator executable")
    run.add_argument("--token-tracking", action=argparse.BooleanOptionalAction, default=None,
                     help="Collect Agent model usage; default off")
    args = p.parse_args()
    config = load(args.config)
    if args.command == "run" and args.token_tracking is not None:
        config = {**config, "token_tracking": {"enabled": args.token_tracking}}
    if args.command == "check-config":
        from .config import provider_ready
        from .coordinator import execution_limits
        from harness.camact_compatibility_v2.roles import role_provider
        ready = {}
        for name in METHODS:
            try:
                provider_ready(name, config["harnesses"][name]["provider"])
                ready[name] = {"ready": True,
                    "effective_limits": execution_limits(config, config["harnesses"][name], name=name)}
            except ValueError as exc:
                ready[name] = {"ready": False, "reason": str(exc)}
        roles = {}
        for role in ("simulator", "judge"):
            try:
                role_provider(config.get(role, {}), role=role, protocol="openai-chat")
                roles[role] = {"ready": True}
            except ValueError as exc:
                roles[role] = {"ready": False, "reason": str(exc)}
        result = {"schema": "valid", "harnesses": list(METHODS), "providers": ready, "roles": roles,
                  "evaluation": config.get("evaluation", {})}
    elif args.command == "offline":
        from .offline import validate
        result = validate(config, archive_path(args.archive))
    else:
        if args.harness == "openclaw" and config["harnesses"]["openclaw"].get("openclaw_home_backend") == "tmpfs":
            import sys
            from .private_tmpfs import launch_if_needed
            code = launch_if_needed(archive_path(args.output), sys.argv[1:])
            if code is not None:
                raise SystemExit(code)
        result = run_evaluated(config, args.harness, args.user, args.task, archive_path(args.output),
                               save_artifacts=args.save_artifacts, evaluation_python=args.evaluation_python)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.command == "offline" and not result["passed"]:
        raise SystemExit(1)

def run_evaluated(config, name, user, task, output, *, save_artifacts=False, evaluation_python=None):
    """Retention is applied after the same execution and formal scoring path."""
    import os
    from .coordinator import run, execution_limits
    from harness.camact_compatibility_v2.roles import role_provider
    from harness.camact_compatibility_v2.artifacts import RunArtifacts, evaluate_artifacts
    from evaluation.camact_eval.schema import StandardRunArtifact
    judge = role_provider(config.get("judge", {}), role="judge", protocol="openai-chat")
    secrets = [os.environ.get(entry.get("provider", {}).get("api_key_env") or "", "")
               for entry in config.get("harnesses", {}).values()]
    secrets.extend(os.environ.get(config.get(role, {}).get("api_key_env") or "", "") for role in ("simulator", "judge"))
    with RunArtifacts(output, save_artifacts=save_artifacts, secrets=secrets) as storage:
        from harness.camact_token_usage_v1.collector import enabled
        from harness.camact_token_usage_v1.report import safe_report
        tracking = enabled(config)
        execution_config = {**config, "_token_run_id": str(storage.output)} if tracking else config
        try:
            execution = run(execution_config, name, user, task, storage.work_dir / "execution")
        finally:
            if tracking:
                safe_report([storage.work_dir / "execution"], storage.output / "token_usage")
        artifact_path = execution.get("artifact") or execution.get("artifact_path")
        if not artifact_path:
            raise ValueError("Native execution did not export a StandardRunArtifact")
        source = storage.work_dir / "standard_run_artifacts.jsonl"
        artifact = StandardRunArtifact.read(Path(artifact_path))
        source.write_text(json.dumps(artifact.document_for_path(source), ensure_ascii=False) + "\n", encoding="utf-8")
        document = evaluate_artifacts(source, Path(config["benchmark_root"]), judge_role=judge,
            judge_mode="env", output=storage.work_dir / "evaluation" / "result.json",
            evaluation_python=evaluation_python or config.get("evaluation", {}).get("python_windows" if os.name == "nt" else "python"))
        snapshot = {**config, "selected_harness": name,
                    "effective_execution_limits": execution_limits(config, config["harnesses"][name], name=name)}
        storage.finish(document, config=snapshot, summary=document.get("summary", {}))
    return {"result": str(output / "result.json"), "summary": document.get("summary", {}),
            "save_artifacts": save_artifacts,
            **({"token_usage_report": str(output / "token_usage/summary.json")} if tracking else {})}

if __name__ == "__main__":
    main()
