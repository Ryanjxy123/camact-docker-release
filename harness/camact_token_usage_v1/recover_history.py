"""Read-only recovery projection for completed CamAct benchmark attempts.

The recovery sidecar never edits a benchmark manifest, ledger, score, or raw
session.  It combines the immutable benchmark manifest with the previously
audited dsh native-boundary sidecar and publishes only numeric accounting and
evidence links.  A Native logical count is emitted only when the source proves
the complete logical boundary; physical HTTP counts and provider Usage remain
independent fields.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path


HARNESS_LABELS = {
    "baseline": "Canonical Baseline",
    "claude": "Claude Code",
    "codex": "Codex CLI",
    "opencode": "OpenCode",
    "deepseek": "dsh",
    "openclaw": "OpenClaw",
}
TOKEN_FIELDS = (
    "input_tokens", "output_tokens", "total_tokens", "cache_read_tokens", "cache_write_tokens",
)


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return default


def read_jsonl(path):
    rows, errors = [], []
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return rows, [f"read_error:{type(exc).__name__}"]
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except ValueError:
            errors.append(f"invalid_jsonl_line:{number}")
    return rows, errors


def sha256(path):
    digest = hashlib.sha256()
    try:
        with Path(path).open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _dsh_index(path):
    index = {}
    rows, errors = read_jsonl(path)
    for row in rows:
        root = row.get("root")
        task = row.get("task")
        if not root or not task:
            continue
        key = (str(Path(root)), str(task))
        # A duplicate key is ambiguous and must not be silently selected.
        if key in index and _json(index[key]) != _json(row):
            index[key] = {"ambiguous": True, "rows": [index[key], row]}
        elif key not in index:
            index[key] = row
    return index, errors


def _safe_value(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _usage_projection(task):
    usage = task.get("selected_agent_usage")
    if not isinstance(usage, dict):
        return {
            "http_attempt_count": None, "reported_logical_request_count": None,
            "reliable_usage_requests": None, "usage_coverage": None,
            "tokens": {field: None for field in TOKEN_FIELDS},
            "field_coverage": {}, "capture_complete": None,
            "physical_request_ids": [],
        }
    exact = usage.get("exact_run_tokens") or usage.get("exact_tokens") or {}
    return {
        "http_attempt_count": usage.get("http_attempt_count"),
        "reported_logical_request_count": usage.get("logical_request_count"),
        "reliable_usage_requests": usage.get("reliable_usage_requests"),
        "usage_coverage": usage.get("usage_coverage"),
        "tokens": {field: _safe_value(exact.get(field)) for field in TOKEN_FIELDS},
        "field_coverage": usage.get("field_coverage") or {},
        "capture_complete": usage.get("capture_complete"),
        "physical_request_ids": list(usage.get("physical_request_ids") or []),
    }


def _recover_task(task, dsh_index, dsh_source):
    harness = task.get("harness")
    run = task.get("final_formal_run_id")
    usage = _usage_projection(task)
    row = {
        "user_id": task.get("user_id"),
        "task": task.get("task"),
        "task_id": task.get("task_id"),
        "harness": harness,
        "harness_label": task.get("harness_label") or HARNESS_LABELS.get(harness, harness),
        "status": task.get("status"),
        "scored": bool(task.get("scored")),
        "reward": task.get("reward"),
        "strict": task.get("strict"),
        "infrastructure_error": bool(task.get("infrastructure_error")),
        "attempt_identity": run,
        "source_result": task.get("result"),
        "source_manifest": "run_manifest.json",
        "http_attempt_count": usage["http_attempt_count"],
        # Public request_count is the confirmed physical model HTTP boundary;
        # it includes provider retries and captured failed requests.  The
        # logical_request_count field below is a separate optional view.
        "request_count": usage["http_attempt_count"] if usage["capture_complete"] is True else None,
        "request_count_status": "complete" if usage["capture_complete"] is True else "unknown_capture",
        "reported_logical_request_count": usage["reported_logical_request_count"],
        "logical_request_count": None,
        "logical_request_status": "unknown_no_attempt_usage" if usage["http_attempt_count"] is None else "unknown_native_identity",
        "recovery_source": None,
        "evidence": [],
        "tokens": usage["tokens"],
        "field_coverage": usage["field_coverage"],
        "reliable_usage_requests": usage["reliable_usage_requests"],
        "usage_coverage": usage["usage_coverage"],
        "capture_complete": usage["capture_complete"],
        "physical_request_ids": usage["physical_request_ids"],
    }
    if run:
        row["evidence"].append({"kind": "selected_agent_usage", "path": str(Path(run) / "token_usage")})

    # Baseline already has explicit logical operation IDs in its Collector
    # ledger.  The manifest value is accepted only for that harness.
    if harness == "baseline" and isinstance(usage["reported_logical_request_count"], int):
        row.update(logical_request_count=usage["reported_logical_request_count"],
                   logical_request_status="runtime_recorded_complete",
                   recovery_source="collector_operation_id")
    elif harness == "deepseek" and run:
        key = (str(Path(run)), str(task.get("task")))
        candidate = dsh_index.get(key)
        if isinstance(candidate, dict) and not candidate.get("ambiguous"):
            row["evidence"].append({"kind": "dsh_native_boundary", "path": str(dsh_source),
                                     "source_root": candidate.get("root"),
                                     "native_session_ids": sorted({g.get("session_id") for g in candidate.get("groups", []) if g.get("session_id")}),
                                     "joined_physical_attempts": candidate.get("joined_physical_attempts"),
                                     "native_group_count": candidate.get("native_group_count"),
                                     "errors": candidate.get("errors", [])})
            if candidate.get("logical_request_count") is not None and not candidate.get("errors"):
                row.update(logical_request_count=candidate["logical_request_count"],
                           logical_request_status="offline_native_boundary_complete",
                           recovery_source="dsh_session_turn_step_or_title_event")
            else:
                row["logical_request_status"] = "unknown_native_boundary_incomplete"
        elif candidate and candidate.get("ambiguous"):
            row["logical_request_status"] = "unknown_ambiguous_native_evidence"
    return row


def _sum_exact(rows, field):
    values = [r["tokens"].get(field) for r in rows if r.get("scored")]
    return sum(values) if values and all(isinstance(v, (int, float)) for v in values) else None


def _known_sum(rows, field):
    values = [r["tokens"].get(field) for r in rows if r.get("scored") and r["tokens"].get(field) is not None]
    return sum(values) if values else None


def _harness_summary(rows):
    by_harness = defaultdict(list)
    for row in rows:
        by_harness[row["harness"]].append(row)
    output = {}
    for harness, scoped in sorted(by_harness.items()):
        scored = [r for r in scoped if r.get("scored")]
        logical = [r.get("logical_request_count") for r in scored]
        exact_logical = sum(logical) if logical and all(isinstance(v, int) for v in logical) else None
        recovered_tasks = sum(v is not None for v in logical)
        request_counts = [r.get("request_count") for r in scored]
        exact_requests = sum(request_counts) if request_counts and all(isinstance(v, int) for v in request_counts) else None
        original_na = sum(not isinstance(r.get("reported_logical_request_count"), int) or
                          r.get("reported_logical_request_count") == 0 for r in scored)
        partial_recovery = sum(r.get("logical_request_count") is None and
                               isinstance(r.get("http_attempt_count"), int) for r in scored)
        remaining_na = sum(r.get("logical_request_count") is None and
                           not isinstance(r.get("http_attempt_count"), int) for r in scored)
        score_values = [r.get("reward") for r in scored if isinstance(r.get("reward"), (int, float))]
        output[harness] = {
            "label": HARNESS_LABELS.get(harness, harness),
            "valid": len(scored), "abnormal": len(scoped) - len(scored),
            "mean_score_per_100": sum(score_values) * 100 / len(score_values) if score_values and len(score_values) == len(scored) else None,
            "strict_success": sum(bool(r.get("strict")) for r in scored),
            "logical_request_count": exact_logical,
            "request_count": exact_requests,
            "request_task_coverage": sum(v is not None for v in request_counts),
            "request_task_total": len(scored),
            "logical_request_task_coverage": recovered_tasks,
            "logical_request_task_total": len(scored),
            "original_logical_na_slots": original_na,
            "complete_logical_recovery_slots": recovered_tasks,
            "partial_recovery_slots": partial_recovery,
            "remaining_logical_na_slots": remaining_na,
            "still_na_slots": len(scored) - recovered_tasks,
            "known_logical_request_count": sum(v for v in logical if isinstance(v, int)) if any(isinstance(v, int) for v in logical) else None,
            "physical_http_attempts": sum(r["http_attempt_count"] for r in scored if isinstance(r.get("http_attempt_count"), int)) or None,
            "tokens": {field: _sum_exact(scored, field) for field in TOKEN_FIELDS},
            "known_tokens": {field: _known_sum(scored, field) for field in TOKEN_FIELDS},
            "token_task_coverage": {field: sum(r["tokens"].get(field) is not None for r in scored) for field in TOKEN_FIELDS},
            "usage_task_coverage": sum(r.get("capture_complete") is True for r in scored),
        }
    return output


def recover(manifest_path, archive_root, *, dsh_source=None):
    manifest_path = Path(manifest_path).resolve()
    archive_root = Path(archive_root).resolve()
    manifest = read_json(manifest_path, {})
    if not isinstance(manifest, dict) or not isinstance(manifest.get("tasks"), list):
        raise ValueError("benchmark manifest must contain a tasks list")
    if dsh_source is None:
        dsh_source = manifest_path.parent / "analysis/native_request_count_audit_20261025/dsh_offline_recovery.jsonl"
    dsh_source = Path(dsh_source).resolve()
    dsh_index, dsh_errors = _dsh_index(dsh_source)
    rows = [_recover_task(task, dsh_index, dsh_source) for task in manifest["tasks"]]
    rows.sort(key=lambda r: (str(r.get("user_id")), str(r.get("harness")), str(r.get("task"))))
    summary = {
        "schema_version": "camact.native_usage_recovery.v1",
        "source_manifest": str(manifest_path),
        "source_manifest_sha256": sha256(manifest_path),
        "source_run_id": manifest.get("benchmark_run_id"),
        "source_updated_at": manifest.get("updated_at"),
        "generated_at": manifest.get("updated_at") or datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "slot_count": len(rows),
        "harness_summary": _harness_summary(rows),
        "logical_status_counts": dict(sorted(Counter(r["logical_request_status"] for r in rows).items())),
        "dsh_source": str(dsh_source),
        "dsh_source_sha256": sha256(dsh_source),
        "dsh_index_errors": dsh_errors,
        "definitions": {
            "request_count": "Confirmed physical Agent model HTTP attempts from the immutable manifest; provider retries remain included.",
            "logical_request_count": "Only explicit Collector operation IDs or a dsh session turn/step/title boundary with closed one-to-one evidence.",
            "physical_http_attempts": "Alias retained for source comparison; request_count is the public metric.",
            "tokens": "Selected Agent exact_run_tokens; unknown fields stay null and are never filled with zero.",
            "scope": "All 3,240 manifest slots are listed; scored rows enter aggregate valid-task statistics.",
        },
    }
    archive_root.mkdir(parents=True, exist_ok=True)
    for directory in (archive_root / "report", archive_root / "manifest", archive_root / "evaluation"):
        directory.mkdir(parents=True, exist_ok=True)
    (archive_root / "manifest/source_fingerprint.json").write_text(_json({
        "manifest": {"path": str(manifest_path), "sha256": sha256(manifest_path), "size": manifest_path.stat().st_size},
        "dsh_sidecar": {"path": str(dsh_source), "sha256": sha256(dsh_source), "size": dsh_source.stat().st_size if dsh_source.exists() else None},
    }) + "\n", encoding="utf-8")
    (archive_root / "manifest/summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    with (archive_root / "evaluation/task_results.jsonl").open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(_json(row) + "\n")
    # Attempt detail is deliberately numeric/evidence-only: raw requests and
    # native transcripts remain at their original paths.
    with (archive_root / "evaluation/attempts.jsonl").open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(_json({k: row.get(k) for k in (
                "user_id", "task", "harness", "status", "scored", "attempt_identity",
                "http_attempt_count", "request_count", "request_count_status",
                "logical_request_count", "logical_request_status",
                "recovery_source", "evidence", "tokens", "capture_complete")}) + "\n")
    lines = [
        "# CamAct Native Usage Recovery",
        "",
        f"- Schema: `camact.native_usage_recovery.v1`",
        f"- Source manifest: `{manifest_path}`",
        f"- Source SHA-256: `{summary['source_manifest_sha256']}`",
        f"- Slots: **{len(rows)}** (20 Users × 27 Tasks × 6 Harnesses)",
        "- Mode: read-only projection; no Agent, Simulator, Judge, score, or raw session was changed.",
        "",
        "## Model request and logical identity recovery",
        "",
        "The public Model requests column is the confirmed physical Agent model HTTP count and includes captured provider retries/failures. Logical request counts are a secondary deduplicated view: only explicit Collector operation IDs and dsh boundaries with closed one-to-one evidence receive one. Codex turn IDs, OpenCode steps, OpenClaw response IDs, Claude message IDs, and request hashes do not create logical IDs.",
        "",
        "| Harness | Valid / abnormal | Mean | Strict | Model requests | Request coverage | Input | Output | Total | Cache read | Cache write |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    def fmt(value):
        if value is None:
            return "N/A"
        return f"{value:,}" if isinstance(value, int) else f"{value:.2f}" if isinstance(value, float) else str(value)
    for harness, data in summary["harness_summary"].items():
        token_values = [data["tokens"].get(field) for field in TOKEN_FIELDS]
        lines.append("| " + " | ".join(map(fmt, [data["label"], f"{data['valid']} / {data['abnormal']}",
            data["mean_score_per_100"], f"{data['strict_success']} / {data['valid']}",
            data["request_count"], f"{data['request_task_coverage']} / {data['request_task_total']}",
            *token_values])) + " |")
    lines += [
        "",
        "Model requests are confirmed physical Agent model HTTP attempts, including captured retry attempts and failures. They exclude tools, Simulator, Judge, CLI launches and turns.",
        "",
        "| Harness | Logical request total | Logical recovery coverage | Original logical N/A | Complete logical recovery | Partial physical evidence | Still logical N/A |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for harness, data in summary["harness_summary"].items():
        lines.append("| " + " | ".join(map(fmt, [data["label"], data["logical_request_count"],
            f"{data['logical_request_task_coverage']} / {data['logical_request_task_total']}",
            data["original_logical_na_slots"], data["complete_logical_recovery_slots"],
            data["partial_recovery_slots"], data["still_na_slots"]])) + " |")
    lines += [
        "",
        "`known_tokens` and per-field coverage are retained in `manifest/summary.json`; a field-level total is `null` when any scored task lacks that field. `known_logical_request_count` is a partial lower bound and is never presented as a complete total.",
        "",
        "## Evidence files",
        "",
        "- `evaluation/task_results.jsonl`: one row per User/Task/Harness slot with Attempt identity, values, evidence and status.",
        "- `evaluation/attempts.jsonl`: compact attempt projection without request/response bodies.",
        "- `manifest/source_fingerprint.json`: source hashes and sizes.",
        "- `manifest/summary.json`: deterministic aggregate and definitions.",
    ]
    (archive_root / "report/recovery_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    readme = "\n".join([
        "# camact-usage-recovery-v1-full-audit",
        "",
        "- Date: 2026-10-26 (Asia/Shanghai)",
        "- Type: read-only historical usage recovery and collector validation",
        f"- ARCHIVE_ROOT: `{archive_root}`",
        f"- Original benchmark: `{manifest_path.parent}`",
        "- Harness/method: `harness/camact_token_usage_v1`, native identity evidence v1",
        "- Raw run: retained in the original benchmark directory; not copied",
        "- Canonical Benchmark / GT/rubric / Simulator / Baseline / Unified Evaluator: unchanged",
        "- Git commit: unavailable; this project has no visible `.git` metadata",
        "",
        "## Entry points",
        "",
        "- [Recovery report](report/recovery_report.md)",
        "- [Aggregate JSON](manifest/summary.json)",
        "- [Source fingerprint](manifest/source_fingerprint.json)",
        "- [Per-slot results](evaluation/task_results.jsonl)",
        "- [Attempt projection](evaluation/attempts.jsonl)",
        "",
        "The projection is idempotent for a fixed source Manifest and dsh sidecar. It stores evidence paths and identifiers only; raw requests, transcripts and credentials remain at their source locations.",
    ]) + "\n"
    (archive_root / "README.md").write_text(readme, encoding="utf-8")
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--archive-root", type=Path, required=True)
    parser.add_argument("--dsh-sidecar", type=Path)
    args = parser.parse_args(argv)
    summary = recover(args.manifest, args.archive_root, dsh_source=args.dsh_sidecar)
    print(json.dumps({"archive_root": str(args.archive_root.resolve()), "slot_count": summary["slot_count"],
                      "harness_summary": summary["harness_summary"]}, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()

