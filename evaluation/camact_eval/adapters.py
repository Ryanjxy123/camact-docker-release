"""Adapters from existing CamAct runs and third-party harness output.

Adapters only translate execution telemetry.  They never inspect ground truth
to repair a submission and never implement scoring rules.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from benchmark.evaluator.datetime_compat import CompatibleDateTime as datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol

from .schema import SCHEMA_VERSION, ArtifactValidationError, StandardRunArtifact, visual_paths
from .measurement import benchmark_provenance, canonical_measurement, extract_domain_actions, normalize_artifact_dict, normalize_model_calls, normalize_usage


def _read_json(path: Path, default: Any = None) -> Any:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
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


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _path_task_parts(path: Path) -> tuple[str | None, str | None]:
    text = str(path).replace("\\", "/")
    user = re.search(r"/(?:users|tasks)/([A-Za-z0-9_-]+)(?:/|$)", text)
    task = re.search(r"/(task_\d+)(?:/|$)", text)
    return (user.group(1) if user else None, task.group(1) if task else None)


def _task_dir(
    benchmark_root: Path,
    *,
    user_id: str | None,
    task: str | None,
    task_id: str | None,
) -> Path | None:
    tasks_root = benchmark_root / "benchmark" / "tasks"
    if not tasks_root.is_dir():
        tasks_root = benchmark_root / "tasks"
    if user_id and task:
        candidate = tasks_root / user_id / task
        if candidate.is_dir():
            return candidate
    candidates = list(tasks_root.glob("*/task_*/task_spec.json"))
    for spec in candidates:
        parent = spec.parent
        if user_id and parent.parent.name != user_id:
            continue
        if task and parent.name == task:
            return parent
        data = _read_json(spec, {})
        if task_id and isinstance(data, dict) and str(data.get("task_id", "")) == task_id:
            return parent
    return None


def _run_root(path: Path) -> Path | None:
    parts = list(path.parts)
    for marker in ("runs", "experiments"):
        if marker in parts:
            index = parts.index(marker)
            if index + 1 < len(parts):
                return Path(*parts[: index + 2])
    return None


def _metadata_for_run(path: Path) -> dict[str, Any]:
    """Load run metadata without treating a missing file as an empty hit.

    A task may have a per-user ``run_config.json`` while the experiment-level
    ``experiment_manifest.json`` lives at the run root.  Merge both, with the
    more local config taking precedence, and expose provenance fields from the
    nested benchmark manifest as top-level convenience fields.
    """
    metadata: dict[str, Any] = {}
    ancestors = [path] + list(path.parents)
    for ancestor in ancestors:
        config = ancestor / "run_config.json"
        data = _read_json(config, None)
        if isinstance(data, dict):
            merged = dict(data)
            merged.update(metadata)
            metadata = merged
            break
    root = _run_root(path)
    manifest = _read_json((root / "experiment_manifest.json") if root else Path(""), None)
    if isinstance(manifest, dict):
        merged = dict(manifest)
        merged.update(metadata)
        metadata = merged
    provenance = metadata.get("benchmark_provenance")
    if isinstance(provenance, dict):
        for source, target in (
            ("release_id", "benchmark_release_id"),
            ("release_version", "benchmark_release_version"),
            ("manifest_sha256", "benchmark_manifest_sha256"),
        ):
            if target not in metadata and source in provenance:
                metadata[target] = provenance[source]
    return metadata


def _normalise_run_provenance(run: dict[str, Any], benchmark_root: Path) -> dict[str, Any]:
    """Fill missing/legacy placeholder snapshot fields from the benchmark."""
    provenance = benchmark_provenance(benchmark_root)
    aliases = {
        "benchmark_release_id": provenance.get("benchmark_release_id") or provenance.get("release_id"),
        "benchmark_release_version": provenance.get("benchmark_release_version") or provenance.get("release_version"),
        "benchmark_manifest_sha256": provenance.get("benchmark_manifest_sha256") or provenance.get("manifest_sha256"),
    }
    for key, fallback in aliases.items():
        if (not run.get(key) or str(run.get(key)).casefold() in {"unknown", "null", "none"}) and fallback:
            run[key] = fallback
    return run


def _infer_trial(path: Path, metadata: Mapping[str, Any] | None = None) -> int | None:
    match = re.search(r"(?:^|[\\/])trial[_-](\\d+)(?:[\\/]|$)", str(path))
    if match:
        return int(match.group(1))
    value = (metadata or {}).get("trial")
    if isinstance(value, bool):
        return None
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _usage(trace: list[dict[str, Any]]) -> dict[str, Any]:
    input_tokens = output_tokens = total_tokens = 0
    cost_usd = 0.0
    cost_seen = False
    usage_seen = False
    for item in trace:
        usage = item.get("usage")
        if not isinstance(usage, dict):
            continue
        usage_seen = True
        input_tokens += int(
            usage.get("prompt_tokens", usage.get("input_tokens", usage.get("promptTokenCount", 0)))
            or 0
        )
        output_tokens += int(
            usage.get(
                "completion_tokens",
                usage.get("output_tokens", usage.get("candidatesTokenCount", 0)),
            )
            or 0
        )
        total_tokens += int(usage.get("total_tokens", usage.get("totalTokenCount", 0)) or 0)
        raw_cost = usage.get("cost_usd", usage.get("cost"))
        if isinstance(raw_cost, (int, float)) and not isinstance(raw_cost, bool):
            cost_usd += float(raw_cost)
            cost_seen = True
    if usage_seen and not total_tokens:
        total_tokens = input_tokens + output_tokens
    result: dict[str, Any] = {"usage_available": usage_seen, "usage_source": "trace_aggregate" if usage_seen else "trace_missing"}
    if usage_seen:
        result.update({"input_tokens": input_tokens, "output_tokens": output_tokens, "total_tokens": total_tokens})
    if cost_seen:
        result["cost_usd"] = round(cost_usd, 8)
    return result


def _model_calls(trace: list[dict[str, Any]]) -> list[dict[str, Any]]:
    calls = []
    for index, item in enumerate(trace, 1):
        if not isinstance(item, dict):
            continue
        # Canonical model_trace also contains one record per tool result. A
        # model call is represented by usage/model response metadata, not by
        # those subsequent tool-result records.
        if not isinstance(item.get("usage"), dict) and "model_text" not in item and not item.get("model"):
            continue
        call = {
            "call_id": str(item.get("call_id") or item.get("id") or f"call_{index:04d}"),
            "step": item.get("step"),
            "model": item.get("model"),
            "tool": item.get("tool"),
            "status": item.get("status", "succeeded"),
        }
        if isinstance(item.get("usage"), dict):
            call["usage"] = dict(item["usage"])
        for key in ("started_at", "finished_at", "duration_seconds", "visual_content_blocks"):
            if key in item:
                call[key] = item[key]
        calls.append(call)
    return calls


def _duration(timing: dict[str, Any]) -> float | None:
    value = timing.get("duration_seconds")
    if isinstance(value, (int, float)):
        return float(value)
    started = timing.get("started_at")
    ended = timing.get("ended_at") or timing.get("finished_at")
    if isinstance(started, str) and isinstance(ended, str):
        try:
            return max(0.0, (datetime.fromisoformat(ended.replace("Z", "+00:00")) - datetime.fromisoformat(started.replace("Z", "+00:00"))).total_seconds())
        except ValueError:
            return None
    return None


def _normalise_errors(session: Mapping[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    errors: dict[str, Any] = {}
    declared = payload.get("errors")
    if isinstance(declared, dict):
        errors.update(declared)
    error = session.get("error") or payload.get("error")
    status = str(session.get("status") or payload.get("trajectory_class") or "").casefold()
    if error:
        bucket = "agent" if "agent" in status else "infrastructure" if "infrastructure" in status or "harness" in status else "other"
        existing = errors.get(bucket)
        if not isinstance(existing, list):
            existing = []
        existing.append({"component": bucket, "message": str(error), "retryable": bucket == "infrastructure"})
        errors[bucket] = existing
    return errors


def _trajectory_class(state: Mapping[str, Any], payload: Mapping[str, Any]) -> str:
    from benchmark.services.episode import trajectory_class
    return trajectory_class(dict(payload), dict(state))



class RunArtifactAdapter(Protocol):
    def adapt(self, source: Path, **kwargs: Any) -> list[StandardRunArtifact]: ...


@dataclass
class BaselineAdapter:
    """Translate canonical Baseline trajectory directories and run folders."""

    benchmark_root: Path
    method: str = "baseline"

    def _trajectory_paths(self, source: Path) -> list[Path]:
        source = source.resolve()
        if source.is_file():
            if source.name in {"episode.json", "submission.json", "evaluation.json", "state.json", "final_state.json"}:
                return [source.parent]
            if source.name == "canonical_records.jsonl":
                return [source.parent]
            return []
        if (source / "episode.json").is_file() or (source / "submission.json").is_file() or (source / "state.json").is_file() and (source / "task_results.jsonl").is_file() is False and (source / "tasks").is_dir() is False:
            return [source]
        paths: list[Path] = []
        for index_name in ("trajectory_index.jsonl", "task_results.jsonl"):
            for row in _read_jsonl(source / index_name):
                candidate = Path(str(row.get("trajectory_path", "")))
                if candidate.is_dir():
                    paths.append(candidate)
        if not paths and (source / "tasks").is_dir():
            for candidate in sorted(source.glob("tasks/**/submission.json")):
                paths.append(candidate.parent)
            for candidate in sorted(source.glob("tasks/**/state.json")):
                if candidate.parent not in paths:
                    paths.append(candidate.parent)
        if not paths:
            for candidate in sorted(source.rglob("submission.json")):
                paths.append(candidate.parent)
        if not paths and (source / "canonical_records.jsonl").is_file():
            # Summary-only canonical records are still accepted as diagnostics;
            # the evaluator will report missing final state rather than crash.
            return [source]
        unique: list[Path] = []
        for path in paths:
            if path not in unique:
                unique.append(path)
        return unique

    def adapt(self, source: Path, **kwargs: Any) -> list[StandardRunArtifact]:
        if source.is_file() and source.name == "canonical_records.jsonl":
            # The summary file is a pointer into the same run directory. Use
            # its trajectory index/task results when present so direct file
            # input has identical semantics to passing the directory.
            source = source.parent
        if source.is_dir() and (source / "canonical_records.jsonl").is_file() and not (source / "trajectory_index.jsonl").is_file() and not (source / "task_results.jsonl").is_file():
            return ExternalArtifactAdapter(self.benchmark_root, self.method)._adapt_record_only(source / "canonical_records.jsonl")
        return [self._adapt_trajectory(path, **kwargs) for path in self._trajectory_paths(source)]

    def _adapt_trajectory(
        self,
        path: Path,
        *,
        user_id: str | None = None,
        task: str | None = None,
        task_id: str | None = None,
    ) -> StandardRunArtifact:
        from benchmark.services.episode import recover_episode, evaluation_state
        payload = recover_episode(path)
        state = evaluation_state(path, payload)
        inferred_user, inferred_task = _path_task_parts(path)
        user_id = user_id or inferred_user or str(payload.get("user_id", ""))
        task = task or inferred_task or (str(payload.get("task", "")) or None)
        spec_dir = _task_dir(self.benchmark_root, user_id=user_id, task=task, task_id=task_id or str(payload.get("task_id", "")))
        spec = _read_json(spec_dir / "task_spec.json", {}) if spec_dir else {}
        canonical_task_id = task_id or str(payload.get("task_id", "")) or str(spec.get("task_id", ""))
        if not canonical_task_id and spec_dir:
            canonical_task_id = str(_read_json(spec_dir / "task_spec.json", {}).get("task_id", ""))
        visual_evidence = {}
        if (path / "visual_wire.jsonl").is_file() and spec_dir:
            from benchmark.services.api import raw_root
            from .visual_capture import collect_visual_evidence
            visual_evidence = collect_visual_evidence(path, payload, raw_root(spec_dir) / "images")
        trace = _read_json(path / "model_trace.json", [])
        trace = trace if isinstance(trace, list) else []
        tool_calls = _as_list(payload.get("tool_calls"))
        actions = _as_list(payload.get("actions"))
        if not tool_calls and payload.get("runtime_metadata", {}).get("snapshot_complete") is not True:
            tool_calls = _read_jsonl(path / "tool_calls.jsonl")
        pending: dict[str, dict[str, Any]] = {}
        traced_calls: list[dict[str, Any]] = []
        for item in trace:
            if not isinstance(item, dict):
                continue
            for call in _as_list(item.get("tool_calls")):
                if isinstance(call, dict) and call.get("id"):
                    pending[str(call["id"])] = call
            call_id = str(item.get("tool_call_id") or "")
            if not call_id or not item.get("tool") or item.get("tool") in {"ask_user", "finish"}:
                continue
            call = pending.get(call_id, {})
            result = item.get("result") if isinstance(item.get("result"), dict) else {}
            traced_calls.append({
                "call_id": call_id,
                "tool": str(item["tool"]),
                "arguments": call.get("arguments", {}) if isinstance(call.get("arguments", {}), dict) else {},
                "status": "succeeded" if result.get("ok") else "failed",
            })
        if payload.get("runtime_metadata", {}).get("snapshot_complete") is not True and len(traced_calls) > len(tool_calls):
            tool_calls = traced_calls
        actions = extract_domain_actions(
            (item for item in tool_calls if isinstance(item, dict)),
            (item for item in actions if isinstance(item, dict)),
        )
        retrieval = _read_jsonl(path / "retrieval_diagnostics.jsonl")
        simulator_audit = _read_jsonl(path / "simulator_audit.jsonl")
        session = state.get("session", {}) if isinstance(state.get("session"), dict) else {}
        run_config = _metadata_for_run(path)
        timing = {
            "started_at": session.get("created_at"),
            "ended_at": session.get("finished_at"),
            "duration_seconds": _duration({"started_at": session.get("created_at"), "ended_at": session.get("finished_at")}),
        }
        image_view_tools = {"image_view", "inspect_image", "person_view_reference", "owner_profile_view"}
        successful = [item for item in tool_calls if isinstance(item, dict) and item.get("status", "succeeded") == "succeeded"]
        viewed = [item for item in successful if item.get("tool") in image_view_tools]
        retrieval_records = [item for item in retrieval if item.get("record_type") == "retrieval"]
        candidates = sum(int(item.get("returned_candidate_total", item.get("merged_result_count", 0)) or 0) for item in retrieval_records)
        legacy_evaluation = _read_json(path / "evaluation.json", None)
        diagnostics = {
            "source_path": str(path),
            "retrieval_diagnostics": retrieval,
            "simulator_audit": simulator_audit,
            "simulator_turns": sum(e.get("kind") == "user_turn" and e.get("status") == "succeeded"
                                   for e in payload.get("execution_trace", []) if isinstance(e, dict)),
            "retrieval_calls": len(retrieval_records),
            "candidates_exposed": candidates,
            "image_views": len(viewed),
            "selected_evidence": list(payload.get("evidence", [])) if isinstance(payload.get("evidence", []), list) else [],
            "conversation_trace": payload.get("conversation_trace", []),
            "identity_claims": payload.get("identity_claims", []),
            "clarifications": payload.get("clarifications", []),
            "observed_constraints": payload.get("observed_constraints", {}),
        }
        if legacy_evaluation is not None:
            diagnostics["legacy_evaluation"] = legacy_evaluation
            diagnostics["legacy_evaluation_path"] = str(path / "evaluation.json")
        errors = _normalise_errors(session, payload)
        run_id = str(run_config.get("run_id") or (_run_root(path).name if _run_root(path) else ""))
        trial = _infer_trial(path, run_config)
        run = {"run_id": run_id, "trial": trial, "source_path": str(_run_root(path) or path)}
        for key in ("provider", "protocol_version", "benchmark_release_id", "benchmark_release_version", "benchmark_manifest_sha256"):
            if key in run_config:
                run[key] = run_config[key]
        run = _normalise_run_provenance(run, self.benchmark_root)
        model: dict[str, Any] = {}
        for key in ("model", "provider", "agent_model"):
            if key in run_config:
                model[key] = run_config[key]
        artifact = StandardRunArtifact(
            user_id=user_id or "unknown",
            task_id=canonical_task_id or task or "unknown",
            task=f"{user_id}/{task}" if user_id and task else task,
            run=run,
            method=str(payload.get("method") or self.method),
            model=model,
            final_response=str(payload.get("final_response", "")),
            evidence=list(payload.get("evidence", [])) if isinstance(payload.get("evidence", []), list) else [],
            tool_calls=[item for item in tool_calls if isinstance(item, dict)],
            actions=[item for item in actions if isinstance(item, dict)],
            final_state=state,
            execution_trace=payload.get("execution_trace", []),
            action_audit=payload.get("action_audit", []),
            conversation=payload.get("conversation", payload.get("conversation_trace", [])),
            final_service_state=payload.get("final_service_state", {}),
            service_audit=payload.get("service_audit", {}),
            runtime_metadata=payload.get("runtime_metadata", {}),
            visual_evidence=visual_evidence,
            simulator={"status": "available" if simulator_audit else "not_recorded", "audit_events": simulator_audit, "state": state.get("user_simulator", {})},
            errors=errors,
            token_usage=_usage(trace),
            model_calls=normalize_model_calls(_model_calls(trace), session_usage=_usage(trace)),
            timing=timing,
            diagnostics=diagnostics,
            trajectory_class=_trajectory_class(state, payload),
        )
        artifact.measurement = canonical_measurement(
            model_calls=artifact.model_calls, token_usage=artifact.token_usage,
            tool_calls=artifact.tool_calls, actions=artifact.actions,
            evidence=artifact.evidence, timing=artifact.timing,
            diagnostics=artifact.diagnostics, final_state=artifact.final_state,
        )
        artifact.validate()
        return artifact


class ExternalArtifactAdapter:
    """Generic adapter for a third-party harness with no internal assumptions."""

    def __init__(self, benchmark_root: Path, default_method: str = "external") -> None:
        self.benchmark_root = benchmark_root
        self.default_method = default_method

    def adapt(self, source: Path, **kwargs: Any) -> list[StandardRunArtifact]:
        if source.is_file() and source.name == "canonical_records.jsonl":
            return self._adapt_record_only(source)
        if source.is_dir():
            candidates = [source / name for name in ("standard_run_artifact.json", "artifact.json", "run_artifact.json") if (source / name).is_file()]
            if candidates:
                source = candidates[0]
            elif (source / "canonical_records.jsonl").is_file() and not (source / "trajectory_index.jsonl").is_file():
                return self._adapt_record_only(source / "canonical_records.jsonl")
        if source.suffix.lower() == ".jsonl":
            return [self._from_payload(item, source, **kwargs) for item in _read_jsonl(source)]
        value = _read_json(source, None)
        if isinstance(value, list):
            return [self._from_payload(item, source, **kwargs) for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            return [self._from_payload(value, source, **kwargs)]
        raise ArtifactValidationError(f"external artifact is not valid JSON: {source}")

    def _adapt_record_only(self, path: Path) -> list[StandardRunArtifact]:
        artifacts: list[StandardRunArtifact] = []
        for row in _read_jsonl(path):
            task = str(row.get("task", ""))
            user_id = str(row.get("user_id") or task.split("/", 1)[0] or "unknown")
            task_name = task.split("/", 1)[-1] if "/" in task else None
            trajectory = str(row.get("trajectory_class", "finished"))
            if trajectory not in StandardRunArtifact.TRAJECTORY_CLASSES:
                trajectory = "harness_failure" if trajectory in {"timeout", "error"} else "finished"
            artifacts.append(StandardRunArtifact(
                user_id=user_id,
                task_id=str(row.get("task_id") or "unknown"),
                task=task or task_name,
                run={
                    "run_id": path.parent.name,
                    "trial": row.get("trial") if row.get("trial") is not None else _infer_trial(path, row) or 1,
                    "source_path": str(path),
                    **{key: row[key] for key in ("protocol_version", "benchmark_release_id", "benchmark_release_version") if row.get(key) is not None},
                },
                method=str(row.get("method") or self.default_method),
                model={"name": row.get("model")},
                final_response="",
                evidence=[],
                tool_calls=[],
                actions=[],
                final_state={},
                simulator={"status": "not_recorded"},
                errors={"agent": [{"message": "summary-only canonical record"}]} if trajectory == "agent_failure" else {},
                token_usage={},
                model_calls=[],
                timing={},
                diagnostics={"source_path": str(path), "legacy_record": row},
                trajectory_class="infrastructure_failure",
            ))
        return artifacts

    def _from_payload(self, value: Mapping[str, Any], source: Path, **kwargs: Any) -> StandardRunArtifact:
        if value.get("schema_version") == SCHEMA_VERSION:
            normalized = normalize_artifact_dict(value, benchmark_root=self.benchmark_root)
            normalized["visual_evidence"] = visual_paths(normalized.get("visual_evidence", {}), source)
            normalized["trajectory_class"] = _trajectory_class(normalized.get("final_state", {}), {
                **normalized, "final_environment": {k: v for k, v in normalized.get("final_state", {}).items() if k != "user_simulator"},
                "final_answer": normalized.get("final_response", "")})
            return StandardRunArtifact.from_dict(normalized, strict=True)
        user_id = str(kwargs.get("user_id") or value.get("user_id") or "unknown")
        task = kwargs.get("task") or value.get("task")
        task_id = str(kwargs.get("task_id") or value.get("task_id") or task or "unknown")
        final_state = value.get("final_environment", value.get("final_state", value.get("state", {})))
        if not isinstance(final_state, dict):
            final_state = {}
        raw_tool_calls = value.get("tool_calls")
        raw_actions = value.get("actions")
        tool_calls = raw_tool_calls if isinstance(raw_tool_calls, list) else []
        actions = raw_actions if isinstance(raw_actions, list) else []
        # ``actions`` is a valid third-party alias for tool calls.  Preserve it
        # in one channel only when no explicit tool_calls channel exists.
        if raw_tool_calls is None and isinstance(raw_actions, list):
            tool_calls, actions = list(raw_actions), []
        errors = value.get("errors", {})
        if not isinstance(errors, dict):
            errors = {"other": [{"message": str(errors)}]}
        payload = {
            "schema_version": SCHEMA_VERSION,
            "user_id": user_id,
            "task_id": task_id,
            "task": task,
            "run": value.get("run", {"run_id": value.get("run_id"), "source_path": str(source)}),
            "method": value.get("method", self.default_method),
            "model": value.get("model", {}),
            "final_response": value.get("final_answer", value.get("final_response", value.get("response", ""))),
            "evidence": value.get("evidence", []),
            "tool_calls": tool_calls if isinstance(tool_calls, list) else [],
            "actions": actions if isinstance(actions, list) else [],
            "final_state": final_state,
            "execution_trace": value.get("execution_trace", []),
            "action_audit": value.get("action_audit", []),
            "conversation": value.get("conversation", value.get("conversation_trace", [])),
            "final_service_state": value.get("final_service_state", {}),
            "service_audit": value.get("service_audit", {}),
            "runtime_metadata": value.get("runtime_metadata", {}),
            "simulator": value.get("simulator", value.get("simulator_result", {})),
            "errors": errors,
            "token_usage": value.get("token_usage", value.get("usage", {})),
            "model_calls": value.get("model_calls", []),
            "timing": value.get("timing", {}),
            "diagnostics": {**(value.get("diagnostics", {}) if isinstance(value.get("diagnostics", {}), dict) else {}), "source_path": str(source)},
            "trajectory_class": value.get("trajectory_class", value.get("status", value.get("runtime_metadata", {}).get("status", "finished"))),
        }
        payload["trajectory_class"] = _trajectory_class(final_state, dict(value))
        return StandardRunArtifact.from_dict(normalize_artifact_dict(payload, benchmark_root=self.benchmark_root), strict=True)


class RetrieverToActionAdapter(ExternalArtifactAdapter):
    """Adapter for the portable Retriever-to-Action run layout.

    The harness stores task summaries in ``task_results.jsonl`` and keeps the
    scoring inputs in separate submission, trace, and session files.  This
    adapter joins those execution files into one Standard Run Artifact without
    importing the harness or its evaluator output.
    """

    def __init__(self, benchmark_root: Path) -> None:
        super().__init__(benchmark_root, default_method="camact_retriever_to_action")

    def adapt(self, source: Path, **kwargs: Any) -> list[StandardRunArtifact]:
        source = source.resolve()
        if source.is_dir() and (source / "task_results.jsonl").is_file():
            return [self._from_harness_result(row, source) for row in _read_jsonl(source / "task_results.jsonl")]
        return super().adapt(source, **kwargs)

    def _from_harness_result(self, row: Mapping[str, Any], root: Path) -> StandardRunArtifact:
        user_id = str(row.get("user_id") or "unknown")
        task = str(row.get("task") or "unknown")
        task_name = task.rsplit("/", 1)[-1]
        task_id = str(row.get("task_id") or task)
        submission = _read_json(root / "submissions" / user_id / f"{task_name}.json", {})
        trace_doc = _read_json(root / "traces" / user_id / f"{task_name}.json", {})
        trace = trace_doc.get("trace", []) if isinstance(trace_doc, dict) else []
        trace = trace if isinstance(trace, list) else []
        state = _read_json(root / "sessions" / user_id / task_name / "final_state.json", None)
        if not isinstance(state, dict):
            state = _read_json(root / "sessions" / user_id / task_name / "state.json", {})
        if not isinstance(submission, dict):
            submission = {}
        from benchmark.services.episode import recover_episode
        session_dir = root / "sessions" / user_id / task_name
        if session_dir.is_dir():
            submission = recover_episode(session_dir, fallback_episode=submission)
            state = submission["final_environment"]
            if (session_dir / "visual_wire.jsonl").is_file():
                from .visual_capture import collect_visual_evidence
                from benchmark.services.api import raw_root
                task_directory = _task_dir(self.benchmark_root, user_id=user_id, task=task_name, task_id=task_id)
                if task_directory is not None:
                    submission["visual_evidence"] = collect_visual_evidence(
                        session_dir, submission, raw_root(task_directory) / "images")
        elif isinstance(submission.get("final_environment"), dict):
            state = submission["final_environment"]
        internal_events: list[dict[str, Any]] = []
        traced_tool_calls: list[dict[str, Any]] = []
        for item in trace:
            if not isinstance(item, dict) or item.get("kind") != "tool_call":
                continue
            result = item.get("result") if isinstance(item.get("result"), dict) else {}
            normalised = {
                "call_id": item.get("tool_call_id"),
                "tool": item.get("tool"),
                "arguments": item.get("arguments", {}) if isinstance(item.get("arguments", {}), dict) else {},
                "status": "succeeded" if result.get("ok") else "failed",
                "result": result,
            }
            if item.get("tool") == "evidence_select" or item.get("internal") is True:
                internal_events.append(normalised)
            else:
                traced_tool_calls.append(normalised)
        canonical_calls = submission.get("tool_calls")
        if isinstance(canonical_calls, list):
            tool_calls = [dict(item) for item in canonical_calls if isinstance(item, dict)]
        else:
            tool_calls = traced_tool_calls
        model_calls = []
        usage = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
        for index, item in enumerate(trace, 1):
            if not isinstance(item, dict) or item.get("kind") != "model_call":
                continue
            raw_usage = item.get("usage_normalized") if isinstance(item.get("usage_normalized"), dict) else item.get("usage", {})
            raw_usage = raw_usage if isinstance(raw_usage, dict) else {}
            usage["input_tokens"] += int(raw_usage.get("input_tokens", raw_usage.get("prompt_tokens", 0)) or 0)
            usage["output_tokens"] += int(raw_usage.get("output_tokens", raw_usage.get("completion_tokens", 0)) or 0)
            usage["total_tokens"] += int(raw_usage.get("total_tokens", 0) or 0)
            model_calls.append({
                "call_id": f"model_call_{index:04d}",
                "step": item.get("step"),
                "model": item.get("model"),
                "usage": dict(raw_usage),
                "status": "succeeded",
            })
        if not usage["total_tokens"]:
            usage["total_tokens"] = usage["input_tokens"] + usage["output_tokens"]
        manifest = _read_json(root / "run_manifest.json", {})
        config = _read_json(root / "config.json", {})
        metadata = dict(manifest) if isinstance(manifest, dict) else {}
        if isinstance(config, dict):
            metadata.update({key: value for key, value in config.items() if key not in metadata})
        provenance = metadata.get("benchmark_provenance", {})
        if not isinstance(provenance, dict):
            provenance = {}
        run = {
            "run_id": str(metadata.get("run_id") or root.name),
            "trial": _infer_trial(root, metadata) or 1,
            "source_path": str(root),
            "protocol_version": metadata.get("protocol_version"),
            "benchmark_release_id": provenance.get("release_id") or metadata.get("benchmark_release_id"),
            "benchmark_release_version": provenance.get("release_version") or metadata.get("benchmark_release_version"),
        }
        run = {key: value for key, value in run.items() if value is not None}
        run = _normalise_run_provenance(run, self.benchmark_root)
        diagnostics = {
            "source_path": str(root),
            "harness_result": {key: value for key, value in row.items() if key not in {"evaluation", "submission", "final_state"}},
            "retrieval_diagnostics": trace_doc.get("audit_trace", []) if isinstance(trace_doc, dict) else [],
            "retrieval": trace_doc.get("retrieval", {}) if isinstance(trace_doc, dict) else {},
            "evidence_state": trace_doc.get("evidence_state", {}) if isinstance(trace_doc, dict) else {},
            "metrics": row.get("metrics", {}),
            "conversation_trace": submission.get("conversation_trace", []),
            "identity_claims": submission.get("identity_claims", []),
            "clarifications": submission.get("clarifications", []),
            "observed_constraints": submission.get("observed_constraints", {}),
            "simulator_turns": sum(e.get("kind") == "user_turn" and e.get("status") == "succeeded"
                                   for e in submission.get("execution_trace", []) if isinstance(e, dict)),
            "internal_events": internal_events,
            "traced_benchmark_tool_calls": traced_tool_calls,
        }
        if isinstance(row.get("evaluation"), dict):
            # Replay consumes only fingerprinted criterion decisions. The
            # canonical evaluator still recomputes all scores from this episode.
            diagnostics["legacy_evaluation"] = row["evaluation"]
        errors = {}
        if row.get("error"):
            bucket = "infrastructure" if str(row.get("status", "")).casefold() in {"infrastructure_error", "timeout", "evaluator_failure"} else "agent"
            errors[bucket] = [{"message": str(row["error"])}]
        trajectory_class = _trajectory_class(state, submission)
        if str(row.get("status", "")).casefold() in {"timeout", "infrastructure_error", "evaluator_failure", "error"}:
            trajectory_class = "infrastructure_failure"
        model = config.get("model", {}) if isinstance(config, dict) else {}
        artifact = StandardRunArtifact(
            user_id=user_id,
            task_id=task_id,
            task=f"{user_id}/{task_name}",
            run=run,
            method=str(metadata.get("method") or self.default_method),
            model=dict(model) if isinstance(model, dict) else {},
            final_response=str(submission.get("final_response", "")),
            evidence=submission.get("evidence", []) if isinstance(submission.get("evidence", []), list) else [],
            tool_calls=tool_calls,
            actions=[],
            final_state=state,
            execution_trace=submission.get("execution_trace", []),
            action_audit=submission.get("action_audit", []),
            conversation=submission.get("conversation", submission.get("conversation_trace", [])),
            final_service_state=submission.get("final_service_state", {}),
            service_audit=submission.get("service_audit", {}),
            runtime_metadata=submission.get("runtime_metadata", {}),
            visual_evidence=submission.get("visual_evidence", {}),
            simulator={"status": "available" if state else "not_recorded", "state": state.get("user_simulator", {}) if isinstance(state, dict) else {}},
            errors=errors,
            token_usage=usage,
            model_calls=normalize_model_calls(model_calls, session_usage=usage),
            timing={"duration_seconds": row.get("duration_seconds")},
            diagnostics=diagnostics,
            trajectory_class=trajectory_class,
        )
        artifact.measurement = canonical_measurement(
            model_calls=artifact.model_calls, token_usage=artifact.token_usage,
            tool_calls=artifact.tool_calls, actions=artifact.actions,
            evidence=artifact.evidence, timing=artifact.timing,
            diagnostics=artifact.diagnostics, final_state=artifact.final_state,
        )
        artifact.validate()
        return artifact


def adapt_source(
    source: Path,
    *,
    adapter: str = "auto",
    benchmark_root: Path,
    user_id: str | None = None,
    task: str | None = None,
    task_id: str | None = None,
) -> list[StandardRunArtifact]:
    if adapter == "baseline":
        impl: RunArtifactAdapter = BaselineAdapter(benchmark_root)
    elif adapter in {"retriever", "external"}:
        impl = ExternalArtifactAdapter(benchmark_root)
    elif adapter == "retriever-to-action":
        impl = RetrieverToActionAdapter(benchmark_root)
    elif adapter == "auto":
        if source.is_file() and source.suffix.lower() in {".json", ".jsonl"}:
            value = _read_json(source, None)
            if isinstance(value, dict) and value.get("schema_version") == SCHEMA_VERSION:
                impl = ExternalArtifactAdapter(benchmark_root)
            elif isinstance(value, list) and value and isinstance(value[0], dict) and value[0].get("schema_version") == SCHEMA_VERSION:
                impl = ExternalArtifactAdapter(benchmark_root)
            else:
                impl = BaselineAdapter(benchmark_root) if source.name in {"submission.json", "evaluation.json", "canonical_records.jsonl"} else ExternalArtifactAdapter(benchmark_root)
        else:
            impl = BaselineAdapter(benchmark_root)
    else:
        raise ValueError(f"unknown adapter: {adapter}")
    return impl.adapt(source, user_id=user_id, task=task, task_id=task_id)
