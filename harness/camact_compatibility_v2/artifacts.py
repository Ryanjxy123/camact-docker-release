"""One retention policy around existing runners and the formal evaluator.

The owned workspace is a child of a newly-created output directory.  Cleanup
never accepts a path supplied by a task, CLI process or historical manifest.
"""
from __future__ import annotations

from contextlib import nullcontext
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

from .roles import judge_environment, public_config

PROJECT = Path(__file__).resolve().parents[2]


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _without_raw_diagnostics(value):
    """Final grades stay; redundant Judge wire/requests do not become raw retention."""
    if isinstance(value, dict):
        return {key: _without_raw_diagnostics(item) for key, item in value.items()
                if key not in {"request_body", "response_body", "native_events", "execution_trace", "action_audit",
                               "final_service_state", "service_audit", "provider_requests", "provider_responses"}}
    if isinstance(value, list):
        return [_without_raw_diagnostics(item) for item in value]
    return value


class RunArtifacts:
    def __init__(self, output, save_artifacts=False, secrets=()):
        self.output = Path(output).absolute()
        self.save_artifacts = bool(save_artifacts)
        self.secrets = tuple(str(s) for s in secrets if s)
        self.run_id = self.output.name
        self.token = uuid.uuid4().hex
        self.completed = False
        self.evaluation_pending = False
        self._entered = False

    def __enter__(self):
        # Never reinterpret a historical directory as a disposable workspace.
        self.output.mkdir(parents=True, exist_ok=False)
        if self.output.is_symlink():
            raise ValueError("Run output cannot be a symlink")
        self.output = self.output.resolve(strict=True)
        if os.name == "nt" and not str(self.output).startswith("\\\\?\\"):
            # Benchmark sessions contain several nested service/attempt paths.
            # Use Win32 extended-length I/O without changing archive layout.
            self.output = Path("\\\\?\\" + str(self.output))
        self.work_dir = self.output / ("runs" if self.save_artifacts else ".camact-transient-" + self.token)
        self.work_dir.mkdir(exist_ok=False)
        self._owner = self.work_dir / ".camact-owned-run.json"
        _write(self._owner, {"token": self.token, "run_id": self.run_id, "output": str(self.output)})
        self._entered = True
        self._policy("running", cleanup=False)
        return self

    def _policy(self, status, *, cleanup):
        _write(self.output / "artifact_policy.json", {
            "schema_version": "camact.artifact_retention.v1", "save_artifacts": self.save_artifacts,
            "status": status, "raw_retained": (self.save_artifacts or self.evaluation_pending) and self.completed,
            "temporary_evidence_pending_evaluation": not self.completed or self.evaluation_pending,
            "owned_temporary_cleanup_completed": cleanup,
            "raw_location": "runs" if self.save_artifacts else self.work_dir.name if not self.completed or self.evaluation_pending else None,
            "rescoring_supported": (self.save_artifacts or self.evaluation_pending) and self.completed,
            "evaluation_before_cleanup": self.completed,
        })

    def finish(self, document, *, config=None, summary=None):
        if not self._entered or self.completed:
            raise RuntimeError("RunArtifacts.finish requires one active, unfinished run")
        # Refuse to discard raw evidence before a valid, complete score envelope
        # has actually been returned.  Infra and unknown envelopes are valid.
        from evaluation.camact_eval.schema import validate_evaluation_result_document
        validate_evaluation_result_document(document)
        # A valid null score envelope does not mean Judge work completed. Keep
        # frozen Agent evidence for independent scoring even without raw opt-in.
        self.evaluation_pending = any(
            row.get("evaluation_infrastructure_failure") or row.get("completion_infrastructure_failure")
            for row in document["evaluations"])
        clean = public_config(document, secrets=self.secrets)
        if not self.save_artifacts and not self.evaluation_pending:
            clean = _without_raw_diagnostics(clean)
            if "source" in clean:
                clean["source"] = "temporary execution artifacts (not retained)"
        clean = self._present_paths(clean)
        clean["artifact_retention"] = {"saved": self.save_artifacts or self.evaluation_pending,
                                       "raw_location": "runs" if self.save_artifacts else self.work_dir.name if self.evaluation_pending else None,
                                       "rescoring_supported": self.save_artifacts or self.evaluation_pending,
                                       "evaluation_pending": self.evaluation_pending}
        _write(self.output / "result.json", clean)
        final_summary = dict(clean["summary"])
        if summary is not None and summary != document["summary"]:
            execution_summary = public_config(summary, secrets=self.secrets)
            if not self.save_artifacts and not self.evaluation_pending:
                execution_summary = _without_raw_diagnostics(execution_summary)
            final_summary["execution_summary"] = self._present_paths(execution_summary)
        # All six final summaries use the formal denominator, including valid
        # Agent failures. Legacy runner success counters remain diagnostics.
        _write(self.output / "summary.json", final_summary)
        if config is not None:
            _write(self.output / "run_config.json", public_config(config, secrets=self.secrets))
        # All six runners finish through this boundary. Export accounting only
        # when Agent tracking was enabled, after Judge responses exist and
        # before transient raw evidence is removed. This does not re-evaluate
        # a task or change its score; compact numeric evidence survives cleanup.
        if (self.output / "token_usage").is_dir():
            from harness.camact_token_usage_v1.unified_report import safe_report
            safe_report([self.output], self.output / "token_usage" / "accounting_v3",
                        evaluation_documents={self.output / "result.json": public_config(document, secrets=self.secrets)})
        self.completed = True
        self._policy("evaluated", cleanup=False)
        return clean

    def _present_paths(self, value):
        """Result indexes travel with saved runs and never promise removed raw."""
        if isinstance(value, dict):
            return {key: self._present_paths(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._present_paths(item) for item in value]
        if isinstance(value, str):
            normalized = value.replace("\\", "/").removeprefix("//?/")
            prefix = str(self.work_dir).replace("\\", "/").removeprefix("//?/")
            if normalized == prefix or normalized.startswith(prefix + "/"):
                suffix = normalized[len(prefix):].lstrip("/")
                if self.save_artifacts or self.evaluation_pending:
                    return ("runs" if self.save_artifacts else self.work_dir.name) + "/" + suffix
                return "result.json" if suffix.endswith("result.json") else "temporary evidence (not retained)"
        return value

    def _cleanup(self):
        # A path might have been replaced by untrusted native shell code. Check
        # resolved ancestry, links/reparse points and the unpredictable owner.
        if self.work_dir.is_symlink() or self.work_dir.resolve() != self.work_dir:
            raise RuntimeError("Refusing cleanup of a replaced workspace")
        if self.work_dir.parent != self.output or not self.work_dir.name.startswith(".camact-transient-"):
            raise RuntimeError("Refusing cleanup outside this run's owned temporary directory")
        if not self._owner.is_file() or self._owner.is_symlink():
            raise RuntimeError("Missing owned-workspace marker; refusing cleanup")
        owner = json.loads(self._owner.read_text(encoding="utf-8"))
        if owner.get("token") != self.token or owner.get("output") != str(self.output):
            raise RuntimeError("Workspace ownership changed; refusing cleanup")
        # Refuse nested links/junctions before any recursive deletion on Windows.
        for path in self.work_dir.rglob("*"):
            if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
                raise RuntimeError("Workspace has a link/junction; refusing recursive cleanup")
        shutil.rmtree(self.work_dir)

    def __exit__(self, exc_type, exc, traceback):
        if not self._entered:
            return False
        if not self.completed:
            # Keep an explicit orchestration failure summary, not a fabricated
            # task grade.  Do not lose diagnostics if evaluation failed to run.
            _write(self.output / "summary.json", {
                "status": "evaluation_or_orchestration_failure", "comparable": False,
                "error": public_config(f"{exc_type.__name__}: {exc}" if exc_type else "Run did not finish evaluation",
                                       secrets=self.secrets),
                "formal_result_available": False,
            })
        if not self.save_artifacts and self.completed and not self.evaluation_pending:
            self._cleanup()
        # A failed evaluator has produced no trustworthy final result. Preserve
        # its owned temporary evidence for diagnosis/retry rather than deleting
        # the only execution record before scoring has completed.
        self._policy("evaluated" if self.completed and not self.evaluation_pending else "pending_evaluation",
                     cleanup=not self.save_artifacts and self.completed and not self.evaluation_pending)
        return False


def _child_path(value, windows):
    text = str(value).replace("\\", "/")
    if text.startswith("//?/"):
        if windows:
            return str(value)
        text = text[4:]
    mounted = re.fullmatch(r"/mnt/([a-zA-Z])/(.*)", text)
    drive = re.fullmatch(r"([a-zA-Z]):/(.*)", text)
    if windows and mounted:
        return mounted[1].upper() + ":/" + mounted[2]
    if not windows and drive:
        return "/mnt/" + drive[1].lower() + "/" + drive[2]
    return text


def evaluation_executable(configured=None):
    configured = configured or os.environ.get("CAMACT_EVALUATOR_PYTHON")
    if not configured and sys.version_info[:2] == (3, 13):
        return sys.executable
    if not configured:
        defaults = PROJECT / "harness/camact_multi_harness_v1/config.wsl.json"
        if defaults.is_file():
            settings = json.loads(defaults.read_text(encoding="utf-8")).get("evaluation", {})
            configured = settings.get("python_windows" if os.name == "nt" else "python", settings.get("python"))
    if not configured:
        raise ValueError("Formal evaluation needs Python 3.13; configure evaluation.python or CAMACT_EVALUATOR_PYTHON")
    return _child_path(configured, os.name == "nt")


def evaluate_artifacts(source, benchmark_root, *, judge_role=None, judge_mode="env", output=None, evaluation_python=None):
    """Evaluate in a verified 3.13 child, including WSL -> Windows interop."""
    if judge_mode not in {"env", "off", "replay"}:
        raise ValueError("judge_mode must be env, off or replay")
    if judge_mode == "env" and judge_role is None:
        raise ValueError("Formal Judge configuration must be explicit")
    source = Path(source).resolve()
    output = Path(output).resolve() if output else source.parent / "evaluation/result.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    executable = evaluation_executable(evaluation_python)
    windows = executable.lower().endswith(".exe")
    script = Path(__file__).with_name("score_run.py")
    command = [executable, "-B", _child_path(script, windows), "--input", _child_path(source, windows),
               "--benchmark-root", _child_path(Path(benchmark_root).resolve(), windows),
               "--judge", judge_mode, "--output", _child_path(output, windows)]
    context = judge_environment(judge_role) if judge_role is not None and judge_mode == "env" else nullcontext({})
    secrets = [judge_role.get("api_key", "")] if judge_role else []
    with context as additions:
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        # WSL only exports selected values to Windows programs. Names go in
        # WSLENV; actual credentials remain environment-only, never argv/files.
        if os.name != "nt" and windows:
            entries = set(filter(None, env.get("WSLENV", "").split(":")))
            entries.update(additions)
            entries.add("PYTHONIOENCODING")
            env["WSLENV"] = ":".join(sorted(entries))
        completed = subprocess.run(command, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
    _write(output.parent / "evaluator_invocation.json", {
        "argv": command, "returncode": completed.returncode, "required_python": "3.13",
        "stderr": public_config(completed.stderr, secrets=secrets),
    })
    if completed.returncode:
        raise RuntimeError("Python 3.13 evaluator failed: " + public_config(completed.stderr[-2000:], secrets=secrets))
    document = json.loads(output.read_text(encoding="utf-8"))
    from evaluation.camact_eval.schema import validate_evaluation_result_document
    validate_evaluation_result_document(document)
    return document
