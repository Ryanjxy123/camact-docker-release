"""Deduplicated Request -> Operation -> Task -> User/Harness -> Benchmark reports."""
from __future__ import annotations
import argparse
from collections import defaultdict
import json
from pathlib import Path
import shutil
import warnings
from .adapters import FIELDS
from .collector import write_json, totals
from .adapters import NORMALIZER_VERSION, METRIC_SCOPE


def read_rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def report(sources, output, *, filters=None):
    output = Path(output)
    filters = filters or {}
    ledgers, errors = {}, []
    for source in sources:
        for path in sorted(Path(source).rglob("identity.json")):
            if path.parent.parent.name != "token_usage" and path.parent.parent.name != "ledgers":
                continue
            try:
                identity = json.loads(path.read_text(encoding="utf-8"))
                if any(str(identity.get(key)) not in values for key, values in filters.items() if key != "model_id"):
                    continue
                key = tuple(identity.get(k) for k in ("run_id", "harness_id", "user_id", "task_id", "attempt_id"))
                events = path.parent / "request_events.jsonl"
                rows = {}
                if events.exists():
                    # A killed process can leave one incomplete trailing line.
                    for line in events.read_text(encoding="utf-8").splitlines():
                        try:
                            row = json.loads(line)
                            rows[row["model_request_id"]] = row
                        except (ValueError, KeyError):
                            errors.append("truncated_request_journal:" + str(identity.get("attempt_id")))
                summary_path = path.parent / "task_summary.json"
                summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else {}
                if key in ledgers:
                    existing_path = ledgers[key][0].resolve()
                    export_root = (output / "ledgers").resolve()
                    old_is_export = existing_path.is_relative_to(export_root)
                    new_is_export = path.parent.resolve().is_relative_to(export_root)
                    # Our previous export is a snapshot, not a competing source.
                    # Prefer its live ledger when refreshing this same report.
                    if old_is_export != new_is_export:
                        if old_is_export:
                            ledgers[key] = (path.parent, summary, rows, identity)
                        continue
                    # Copies may not silently override a divergent historical ledger.
                    if rows != ledgers[key][2]:
                        raise ValueError("conflicting copies of one task attempt")
                    continue
                ledgers[key] = (path.parent, summary, rows, identity)
            except Exception as exc:
                errors.append("ledger_read_error:" + type(exc).__name__)
    if not ledgers:
        errors.append("no_usage_ledgers_found")
    output.mkdir(parents=True, exist_ok=True)
    requests, attempts = [], []
    for key, (directory, summary, rows, identity) in sorted(ledgers.items(), key=lambda item: item[1][3].get("started_at", "")):
        selected = [r for r in rows.values() if not filters.get("model_id") or r.get("model_id") in filters["model_id"]]
        if filters.get("model_id") and not selected:
            continue
        requests.extend(selected)
        reconciliation = summary.get("request_count_reconciliation", [])
        coverage_valid = (summary.get("request_coverage") == "complete" and summary.get("closed")
                          and summary.get("coverage") == "exclusive_agent_http_boundary"
                          and not summary.get("collector_errors") and len(rows) == summary.get("model_request_count")
                          and bool(reconciliation) and all(r.get("matched") for r in reconciliation)
                          and reconciliation[-1].get("recorded_model_requests") == len(rows))
        attempts.append({**identity, "task_status": summary.get("task_status", "interrupted_or_unknown"),
                         "model_request_count": len(selected),
                         "collector_errors": summary.get("collector_errors", []),
                         **totals(selected, coverage_valid=coverage_valid and not errors)})
        # Token evidence survives RunArtifacts cleanup, without raw prompt bodies.
        destination = output / "ledgers" / identity["attempt_id"]
        if directory.resolve() != destination.resolve():
            if destination.exists():
                # A resumed report may refresh snapshots of the same live ledger.
                existing = json.loads((destination / "identity.json").read_text(encoding="utf-8"))
                if existing != identity:
                    raise ValueError("attempt_id collision")
            destination.mkdir(parents=True, exist_ok=True)
            for filename in ("identity.json", "request_events.jsonl", "requests.jsonl", "operations.jsonl", "task_summary.json", "collector_errors.json"):
                source_file = directory / filename
                if source_file.exists():
                    shutil.copyfile(source_file, destination / filename)
    grouped = defaultdict(list)
    for attempt in attempts:
        grouped[tuple(attempt[k] for k in ("run_id", "harness_id", "user_id", "task_id"))].append(attempt)
    tasks = []
    for key, task_attempts in grouped.items():
        identity = dict(zip(("run_id", "harness_id", "user_id", "task_id"), key))
        rows = [r for r in requests if all(r[k] == v for k, v in identity.items())]
        coverage_valid = all(a["request_coverage"] == "complete" for a in task_attempts) and not errors
        summary = {**identity, **totals(rows, coverage_valid=coverage_valid), "attempt_ids": [a["attempt_id"] for a in task_attempts],
                   "attempt_count": len(task_attempts), "task_status": task_attempts[-1]["task_status"],
                   "attempt_statuses": [a["task_status"] for a in task_attempts],
                   "model_request_count": len(rows), "usage_record_count": sum(bool(r["raw_usage"]) for r in rows)}
        tasks.append(summary)
    def aggregate(selected_tasks, selected_requests):
        coverage_valid = bool(selected_tasks) and all(t["request_coverage"] == "complete" for t in selected_tasks) and not errors
        values = totals(selected_requests, coverage_valid=coverage_valid)
        complete = sum(t["comparable"] for t in selected_tasks)
        exact = values["comparable"]
        return {**values, "task_count": len(selected_tasks), "complete_task_count": complete,
                "completeness_ratio": complete / len(selected_tasks) if selected_tasks else None,
                "model_request_count": len(selected_requests), "comparable": exact,
                "mean_tokens_per_task": values["comparable_tokens"]["total_tokens"] / len(selected_tasks) if exact else None,
                "task_scope": sorted({t["user_id"] + "/" + t["task_id"] for t in selected_tasks}),
                "models": sorted({r["model_id"] for r in selected_requests if r.get("model_id")}),
                "served_models": sorted({r["served_model_id"] for r in selected_requests if r.get("served_model_id")}),
                "run_ids": sorted({t["run_id"] for t in selected_tasks}),
                "comparison_note": "Compare only identical task scopes and model selections; complete usage is necessary, not sufficient"}
    result = {"schema_version": "camact.token_usage_report.v2", "normalizer_version": NORMALIZER_VERSION,
              "metric_scope": METRIC_SCOPE, "filters": filters,
              "errors": errors, "attempts": attempts, "tasks": tasks,
              "benchmark": aggregate(tasks, requests)}
    for level, field in (("users", "user_id"), ("harnesses", "harness_id"), ("models", "model_id")):
        values = sorted({r[field] for r in requests if r.get(field)} | ({t[field] for t in tasks} if field != "model_id" else set()))
        result[level] = {}
        for value in values:
            selected = [r for r in requests if r[field] == value]
            ids = {(r["run_id"], r["harness_id"], r["user_id"], r["task_id"]) for r in selected}
            selected_tasks = [t for t in tasks if (t.get(field) == value if field != "model_id" else
                              (t["run_id"], t["harness_id"], t["user_id"], t["task_id"]) in ids)]
            result[level][value] = aggregate(selected_tasks, selected)
    harness_rows = list(result["harnesses"].values())
    reasons = []
    if len(harness_rows) < 2:
        reasons.append("fewer_than_two_harnesses")
    if any(not row["comparable"] for row in harness_rows):
        reasons.append("incomplete_usage")
    if len({tuple(row["models"]) for row in harness_rows}) > 1:
        reasons.append("different_model_selections")
    if len({(tuple(row["task_scope"]), row["task_count"]) for row in harness_rows}) > 1:
        reasons.append("different_task_scopes_or_repeat_counts")
    result["cross_harness_comparison"] = {"eligible_by_usage_scope": not reasons, "reasons": reasons,
        "note": "Execution budgets and benchmark versions must also match; token collection does not change them"}
    write_json(output / "summary.json", result)
    (output / "requests.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in requests), encoding="utf-8")
    lines = ["# Agent Token Usage", "",
             "Metric: API-returned standardized Agent usage. Input includes cache; Output includes reasoning.",
             "Values below are normalized counters; consult Comparable before using totals for comparison.",
             "Missing breakdowns remain null. A semantic conflict does not erase other known counters.", "",
             "| Harness | Tasks | Complete | Requests | Input | Output | Total | Cache read | Cache write | Reasoning | Mean/task | Comparable |",
             "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|"]
    for name, row in result["harnesses"].items():
        tokens = row["tokens"]
        lines.append("| " + " | ".join(str(v) if v is not None else "unknown" for v in
            [name, row["task_count"], row["complete_task_count"], row["model_request_count"],
             *[tokens[f] for f in ("input_tokens", "output_tokens", "total_tokens", "cache_read_tokens", "cache_write_tokens", "reasoning_tokens")],
             row["mean_tokens_per_task"], row["comparable"]]) + " |")
    lines += ["", "## Field-level comparison", "",
              "An unavailable whole-run Total does not discard independently comparable fields.",
              "Provider-reported Total is reference-only; it is not the comparable inclusive-input Total.",
              "Compare each field only across identical task/model scopes with full request coverage.", "",
              "| Harness | Provider-reported Total | Comparable Input | Comparable Output | Comparable Total | Comparable Cache read | Comparable Cache write | Comparable Reasoning |",
              "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for name, row in result["harnesses"].items():
        comparable = row["comparable_tokens"]
        values = [name, row["provider_reported_tokens"]["total_tokens"],
                  *[comparable[f] for f in ("input_tokens", "output_tokens", "total_tokens",
                                            "cache_read_tokens", "cache_write_tokens", "reasoning_tokens")]]
        lines.append("| " + " | ".join(str(v) if v is not None else "not comparable" for v in values) + " |")
    lines += ["", "## Known breakdown coverage", "",
              "Known subtotals are not exact totals when any request is missing the field.", "",
              "| Harness | Field | Known subtotal | Known requests / All requests |",
              "|---|---|---:|---:|"]
    for name, row in result["harnesses"].items():
        for field in ("cache_read_tokens", "cache_write_tokens", "reasoning_tokens", "uncached_input_tokens"):
            value = row["known_tokens"][field]
            lines.append(f"| {name} | {field} | {value if value is not None else 'unknown'} | "
                         f"{row['field_coverage'][field]} / {row['field_coverage_denominator']} |")
    lines += ["", "See summary.json for task/user/model scopes, errors, field coverage and known subtotals.",
              "ledgers/<attempt_id>/operations.jsonl contains request/tool relationships. Tool calls are not charged twice.",
              "Native parent/sub-agent identities and unexposed provider-internal retries remain unknown."]
    (output / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    # Keep legacy v2 semantics intact and publish independent versioned sets.
    # Physical requests survive retention; score-based selection may remain
    # pending until the common RunArtifacts.finish hook runs after evaluation.
    from .unified_report import safe_report as unified_report
    unified_report(sources, output / "accounting_v3", filters=filters)
    return result


def safe_report(sources, output, **kwargs):
    try:
        return report(sources, output, **kwargs)
    except Exception as exc:
        code = "token_report_error:" + type(exc).__name__
        try:
            warnings.warn(code, RuntimeWarning)
        except Exception:
            pass
        try:
            write_json(Path(output) / "report_error.json", {"error": code, "comparable": False})
        except Exception:
            pass
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, nargs="+", required=True)
    parser.add_argument("--output", type=Path, required=True)
    for flag in ("run-id", "user-id", "task-id", "harness-id", "model-id"):
        parser.add_argument("--" + flag, action="append")
    args = parser.parse_args()
    filters = {k: v for k, v in vars(args).items() if k.endswith("_id") and v}
    result = report(args.input, args.output, filters=filters)
    print(json.dumps(result["benchmark"], indent=2))


if __name__ == "__main__":
    main()
