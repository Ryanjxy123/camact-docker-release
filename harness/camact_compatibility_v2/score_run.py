"""Formal subprocess boundary. No execution of an evaluated Agent."""
from pathlib import Path
import argparse
import json
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--benchmark-root", type=Path, required=True)
    parser.add_argument("--judge", choices=["env", "off", "replay"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 13):
        raise RuntimeError("Formal CamAct evaluation requires Python 3.13")
    from evaluation.camact_eval.environment import evaluation_environment
    environment = evaluation_environment(require_formal=True)
    from evaluation.camact_eval.adapters import adapt_source
    from evaluation.camact_eval.evaluator import UnifiedEvaluator
    from evaluation.camact_eval.aggregation import aggregate_results
    from evaluation.camact_eval.schema import validate_evaluation_result_document
    artifacts = adapt_source(args.input, adapter="external", benchmark_root=args.benchmark_root)
    results = UnifiedEvaluator(args.benchmark_root, judge=args.judge).evaluate_many(artifacts)
    document = {"schema_version": "camact.standard_evaluation_result.v1", "adapter": "external",
                "source": str(args.input), "judge": args.judge, "evaluations": results,
                "summary": aggregate_results(artifacts, results),
                "evaluation_environment": environment}
    # A provider may echo its key in a free-text decision reason. Keep the
    # original decisions for grading, but never write that value to even the
    # temporary score artifact.
    from harness.camact_compatibility_v2.roles import public_config
    from benchmark.evaluator.judge import JudgeSettings
    settings = JudgeSettings.from_environment() if args.judge == "env" else None
    document = public_config(document, secrets=(settings.api_key,) if settings else ())
    validate_evaluation_result_document(document)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
