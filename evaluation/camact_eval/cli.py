"""Command line interface for the unified CamAct evaluator."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .adapters import adapt_source
from .aggregation import aggregate_results, compare_results
from .evaluator import UnifiedEvaluator, compatibility_diff
from .schema import StandardRunArtifact, validate_evaluation_result_document
from .report import render_evaluation
from .environment import evaluation_environment


def _path(value: str) -> Path:
    return Path(value).expanduser().resolve()


def _source(args: argparse.Namespace) -> Path:
    value = args.input or args.source
    if not value:
        raise SystemExit("an input path is required (positional source or --input)")
    path = _path(value)
    if not path.exists():
        raise SystemExit(f"input does not exist: {path}")
    return path


def _filters(args: argparse.Namespace, artifacts: list[StandardRunArtifact]) -> list[StandardRunArtifact]:
    users = {str(value) for value in (args.user_id or [])}
    task_values = list(args.task or [])
    if getattr(args, "task_subset", None):
        task_values.extend(item.strip() for item in str(args.task_subset).split(",") if item.strip())
    tasks = set(task_values)
    filtered = []
    for artifact in artifacts:
        if users and artifact.user_id not in users:
            continue
        if tasks:
            short = artifact.task.rsplit("/", 1)[-1] if artifact.task else ""
            if artifact.task_id not in tasks and short not in tasks and (f"{artifact.user_id}/{short}" not in tasks):
                continue
        filtered.append(artifact)
    return filtered


def _write_or_print(value: Any, output: str | None) -> None:
    # Strip only a configured Judge credential from the serialized copy.
    # Provider-auth values must not survive in free-text criterion reasons,
    # including when the formal CLI is invoked directly for re-scoring.
    from harness.camact_compatibility_v2.roles import public_config
    key_env = os.environ.get("CAMACT_JUDGE_API_KEY_ENV", "CAMACT_JUDGE_API_KEY").strip()
    key = os.environ.get(key_env, "").strip()
    value = public_config(value, secrets=(key,) if key else ())
    text = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    if output:
        path = _path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        count = None
        if isinstance(value, dict):
            for key in ("evaluations", "pairs", "rows"):
                if isinstance(value.get(key), list):
                    count = len(value[key])
                    break
        print(json.dumps({"output": str(path), "count": count}, ensure_ascii=False))
    else:
        sys.stdout.write(text)


def _load(args: argparse.Namespace, source: Path, adapter: str) -> list[StandardRunArtifact]:
    benchmark_root = _path(args.benchmark_root) if args.benchmark_root else Path(__file__).resolve().parents[2]
    artifacts = adapt_source(
        source,
        adapter=adapter,
        benchmark_root=benchmark_root,
    )
    return _filters(args, artifacts)


def cmd_evaluate(args: argparse.Namespace) -> int:
    environment = evaluation_environment(require_formal=True)
    source = _source(args)
    artifacts = _load(args, source, args.adapter)
    benchmark_root = _path(args.benchmark_root) if args.benchmark_root else Path(__file__).resolve().parents[2]
    evaluator = UnifiedEvaluator(benchmark_root, judge=args.judge)
    evaluations = evaluator.evaluate_many(artifacts)
    document: dict[str, Any] = {
        "schema_version": "camact.standard_evaluation_result.v1",
        "source": str(source),
        "adapter": args.adapter,
        "judge": args.judge,
        "evaluation_environment": environment,
        "evaluations": evaluations,
        "summary": aggregate_results(artifacts, evaluations),
    }
    if args.include_artifacts:
        document["artifacts"] = [artifact.to_dict() for artifact in artifacts]
    if args.write_artifacts:
        target = _path(args.write_artifacts)
        target.mkdir(parents=True, exist_ok=True)
        paths = []
        for index, artifact in enumerate(artifacts, 1):
            path = target / f"{artifact.user_id}_{artifact.task_id}_{index:04d}.json"
            artifact.write(path)
            paths.append(str(path))
        document["standard_artifacts"] = paths
    validate_evaluation_result_document(document)
    if getattr(args, "report_markdown", None):
        report_path = _path(args.report_markdown)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(render_evaluation(document), encoding="utf-8")
    _write_or_print(document, args.output)
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    environment = evaluation_environment(require_formal=True)
    baseline_source = _path(args.baseline)
    candidate_source = _path(args.candidate)
    if not baseline_source.exists() or not candidate_source.exists():
        raise SystemExit("both --baseline and --candidate inputs must exist")
    baseline = _load(args, baseline_source, args.baseline_adapter)
    candidate = _load(args, candidate_source, args.candidate_adapter)
    benchmark_root = _path(args.benchmark_root) if args.benchmark_root else Path(__file__).resolve().parents[2]
    evaluator = UnifiedEvaluator(benchmark_root, judge=args.judge)
    baseline_results = evaluator.evaluate_many(baseline)
    candidate_results = evaluator.evaluate_many(candidate)
    try:
        document = compare_results(baseline, baseline_results, candidate, candidate_results)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    document.update({"baseline_source": str(baseline_source), "candidate_source": str(candidate_source), "judge": args.judge})
    document["evaluation_environment"] = environment
    _write_or_print(document, args.output)
    return 0


def cmd_compatibility(args: argparse.Namespace) -> int:
    source = _source(args)
    artifacts = _load(args, source, "baseline")
    evaluator = UnifiedEvaluator(_path(args.benchmark_root) if args.benchmark_root else None, judge="replay")
    evaluations = evaluator.evaluate_many(artifacts)
    rows = []
    for artifact, result in zip(artifacts, evaluations):
        diff = compatibility_diff(artifact, result)
        rows.append({"user_id": artifact.user_id, "task_id": artifact.task_id, **diff})
    available = [row for row in rows if row["available"]]
    mismatches = [row for row in available if not row["matches"]]
    document = {
        "schema_version": "camact.compatibility_report.v1",
        "mode": "replay_legacy_semantic_judge_plus_current_deterministic_checks",
        "source": str(source),
        "checked": len(rows),
        "legacy_available": len(available),
        "matches": len(available) - len(mismatches),
        "mismatch_count": len(mismatches),
        "all_match": bool(available) and not mismatches,
        "note": "Replay mode preserves each historical evaluation.json semantic-judge decision; future runs should use judge=off or judge=env.",
        "rows": rows,
    }
    _write_or_print(document, args.output)
    return 0 if not mismatches else 2


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("source", nargs="?", help="trajectory, run directory, or artifact JSON")
    parser.add_argument("--input", help="same as positional source")
    parser.add_argument("--adapter", choices=["auto", "baseline", "external", "retriever", "retriever-to-action"], default="auto")
    parser.add_argument("--benchmark-root", help="repository root (default: current CamAct repository)")
    parser.add_argument("--user-id", "--user", action="append", default=[])
    parser.add_argument("--task", action="append", default=[])
    parser.add_argument("--task-subset", help="comma-separated task names or canonical task ids")
    parser.add_argument("--judge", choices=["off", "env", "replay"], default="off")
    parser.add_argument("--output", help="write JSON result to this path")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="camact_eval", description="Harness-independent CamAct evaluator")
    sub = parser.add_subparsers(dest="command", required=True)
    evaluate = sub.add_parser("evaluate", help="evaluate one artifact, task, user, or run directory")
    _common(evaluate)
    evaluate.add_argument("--include-artifacts", action="store_true")
    evaluate.add_argument("--write-artifacts", help="also persist normalized Standard Run Artifacts")
    evaluate.add_argument("--report-markdown", help="write the four completion metrics, capability breakdown and per-task constraint details")
    evaluate.set_defaults(func=cmd_evaluate)

    compare = sub.add_parser("compare", help="paired baseline/candidate comparison")
    compare.add_argument("--baseline", required=True)
    compare.add_argument("--candidate", required=True)
    compare.add_argument("--baseline-adapter", choices=["auto", "baseline", "external", "retriever", "retriever-to-action"], default="auto")
    compare.add_argument("--candidate-adapter", choices=["auto", "baseline", "external", "retriever", "retriever-to-action"], default="auto")
    compare.add_argument("--benchmark-root")
    compare.add_argument("--user-id", "--user", action="append", default=[])
    compare.add_argument("--task", action="append", default=[])
    compare.add_argument("--task-subset")
    compare.add_argument("--judge", choices=["off", "env", "replay"], default="off")
    compare.add_argument("--output")
    compare.set_defaults(func=cmd_compare)

    compatibility = sub.add_parser("compatibility", help="re-score canonical Baseline artifacts and compare legacy fields")
    _common(compatibility)
    compatibility.set_defaults(func=cmd_compatibility)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))
