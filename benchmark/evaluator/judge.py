"""Criterion-scoped multimodal judge for CamAct's semantic rubric items."""
from __future__ import annotations

import base64
import hashlib
import json
import http.client
import mimetypes
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


JUDGE_PROMPT_NAME = "camact_semantic_criterion_judge"
DEFAULT_BASE_URL = ""
DEFAULT_MODEL = ""
RETRYABLE_HTTP_CODES = {408, 409, 429, 500, 502, 503, 504, 524}


class JudgeInfrastructureError(RuntimeError):
    """The judge did not produce a valid, scoreable response."""

    def __init__(self, message: str, audit: dict[str, Any] | None = None):
        super().__init__(message)
        self.audit = audit or {}


@dataclass(frozen=True)
class JudgeSettings:
    api_base: str
    api_key: str
    model: str
    timeout_seconds: float = 120.0
    max_output_tokens: int = 8192
    attempts: int = 3

    @classmethod
    def from_environment(cls) -> "JudgeSettings | None":
        key_env = os.environ.get("CAMACT_JUDGE_API_KEY_ENV", "CAMACT_JUDGE_API_KEY").strip()
        key = os.environ.get(key_env, "").strip()
        if not key:
            return None
        base = os.environ.get("CAMACT_JUDGE_BASE_URL", DEFAULT_BASE_URL).strip().rstrip("/")
        if not base:
            raise ValueError("CAMACT_JUDGE_BASE_URL is empty")
        if not base.endswith("/v1"):
            base += "/v1"
        attempts = int(os.environ.get("CAMACT_JUDGE_RETRY_ATTEMPTS", "3"))
        if attempts < 1:
            raise ValueError("CAMACT_JUDGE_RETRY_ATTEMPTS must be at least 1")
        model = os.environ.get("CAMACT_JUDGE_MODEL", DEFAULT_MODEL).strip()
        if not model:
            raise ValueError("CAMACT_JUDGE_MODEL is required when judge credentials are configured")
        return cls(
            api_base=base,
            api_key=key,
            model=model,
            timeout_seconds=float(os.environ.get("CAMACT_JUDGE_TIMEOUT", "120")),
            max_output_tokens=int(os.environ.get("CAMACT_JUDGE_MAX_OUTPUT_TOKENS", "8192")),
            attempts=attempts,
        )


@dataclass(frozen=True)
class JudgeBatchResult:
    results: dict[str, dict[str, Any]]
    audit: dict[str, Any]


def judge_from_environment() -> "SemanticJudge | None":
    settings = JudgeSettings.from_environment()
    return SemanticJudge(settings) if settings else None


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _image_block(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    raw = path.read_bytes()
    media_type = mimetypes.guess_type(path.name)[0] or "image/jpeg"
    encoded = base64.b64encode(raw).decode("ascii")
    return (
        {
            "type": "image_url",
            "image_url": {
                "url": f"data:{media_type};base64,{encoded}",
                "detail": "auto",
            },
        },
        {"image_id": path.name, "sha256": _sha256(raw), "bytes": len(raw)},
    )


def _validate_response(raw_output: str, expected_ids: list[str], score_modes=None) -> dict[str, dict[str, Any]]:
    candidate = raw_output.strip()
    if candidate.startswith("```") and candidate.endswith("```"):
        first_newline = candidate.find("\n")
        if first_newline != -1 and candidate[:first_newline].strip().casefold() in {"```", "```json"}:
            candidate = candidate[first_newline + 1:-3].strip()
    try:
        payload = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise ValueError(f"judge output is not JSON: {exc}") from exc
    if not isinstance(payload, dict) or set(payload) != {"criterion_results"}:
        raise ValueError("judge output must contain only criterion_results")
    items = payload["criterion_results"]
    if not isinstance(items, list):
        raise ValueError("criterion_results must be a list")

    parsed: dict[str, dict[str, Any]] = {}
    required_keys = {"criterion_id", "pass", "evidence_refs", "reason"}
    for item in items:
        identity = item.get("criterion_id") if isinstance(item, dict) else None
        ternary = (score_modes or {}).get(identity) == [0, 0.5, 1]
        if ternary:
            if set(item) != {"criterion_id", "score", "evidence_refs", "reason"}:
                raise ValueError("three-level result requires criterion_id, score, evidence_refs, reason")
            value = item["score"]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value not in (0, 0.5, 1):
                raise ValueError("three-level Judge score must be exactly 0, 0.5 or 1")
            item = {**item, "pass": value == 1}
            item.pop("score")
        # Existing transport/replay adapters may return the former field names.
        # Keep only its EXACT binary subset; 0.5 and every other continuous score
        # are invalid. New prompts always request pass/evidence_refs.
        if isinstance(item, dict) and set(item) == {"criterion_id", "score", "evidence", "reason"}:
            score = item["score"]
            if isinstance(score, bool) or not isinstance(score, (int, float)) or score not in (0, 1):
                raise ValueError("compatibility Judge score must be exactly 0 or 1")
            item = {"criterion_id": item["criterion_id"], "pass": bool(score),
                    "evidence_refs": item["evidence"], "reason": item["reason"]}
        if not isinstance(item, dict) or set(item) != required_keys:
            raise ValueError("each criterion result must contain exactly criterion_id, pass, evidence_refs, reason")
        criterion_id = item["criterion_id"]
        decision = item["pass"]
        evidence = item["evidence_refs"]
        reason = item["reason"]
        if not isinstance(criterion_id, str) or criterion_id not in expected_ids:
            raise ValueError(f"unexpected criterion_id: {criterion_id!r}")
        if criterion_id in parsed:
            raise ValueError(f"duplicate criterion_id: {criterion_id}")
        if type(decision) is not bool:
            raise ValueError(f"pass for {criterion_id} must be a YES/NO boolean")
        if (
            not isinstance(evidence, list)
            or not evidence
            or any(not isinstance(value, str) or not value.strip() for value in evidence)
        ):
            raise ValueError(f"evidence for {criterion_id} must be a non-empty string list")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError(f"reason for {criterion_id} must be non-empty")
        parsed[criterion_id] = {
            "criterion_id": criterion_id,
            "pass": decision,
            "score": value if ternary else int(decision),
            "evidence_refs": evidence,
            "evidence": evidence,
            "reason": reason.strip(),
        }
    if set(parsed) != set(expected_ids):
        missing = sorted(set(expected_ids) - set(parsed))
        raise ValueError(f"judge output omitted criteria: {missing}")
    return parsed


class SemanticJudge:
    """OpenAI-compatible multimodal judge with strict response validation."""

    SYSTEM_PROMPT = """You are a criterion-scoped evaluator for a personal-photo agent benchmark.
Use only the supplied evaluator reference, agent evidence, trajectory, final state, metadata, and raw images.
Do not use external knowledge. Do not guess people, places, events, relationships, or facts that are not visible or provided.
Treat evaluator_reference as a rubric, never as proof that the agent's chosen image satisfies it.
Treat only agent_evidence and attached raw images as evidence of what the agent selected and did.
Evaluate each criterion independently; do not let another criterion, filename, or hidden reference membership determine the score.
For semantic checks, use only the actual persisted text and the necessary supplied context.
For visual checks, use only the actual target images, necessary metadata and the current criterion rubric.
Dates and recorded locations are checked deterministically. Never guess them from pixels.
When evidence for the current requirement is insufficient or materially ambiguous, answer NO.
Treat every explicitly required subject, action, interaction, and role-defining setting as material.
Do not re-evaluate deterministic safety, excluded-image, recipient, visibility, tool-allowlist, count, or final-state assertions.
Answer YES or NO for each criterion, encoded as pass: true or pass: false. Do not return a numerical score.
Return only one JSON object matching the requested schema. Do not include markdown or additional keys."""

    def __init__(self, settings: JudgeSettings):
        self.settings = settings

    def evaluate(
        self,
        *,
        task_prompt: dict[str, Any],
        evidence: dict[str, Any],
        trajectory: dict[str, Any],
        criterion_rubric: list[dict[str, Any]],
        image_paths: list[Path],
    ) -> JudgeBatchResult:
        expected_ids = [str(item["criterion_id"]) for item in criterion_rubric]
        if not expected_ids or len(expected_ids) != len(set(expected_ids)):
            raise ValueError("criterion_rubric requires unique criterion_id values")
        score_modes = {item["criterion_id"]: item.get("score_values", [0, 1]) for item in criterion_rubric}
        if any(values not in ([0, 1], [0, 0.5, 1]) or any(isinstance(v, bool) for v in values) for values in score_modes.values()):
            raise ValueError("unsupported Judge score_values")
        ternary = any(values == [0, 0.5, 1] for values in score_modes.values())

        prompt_document = {
            "task_prompt": task_prompt,
            "evaluator_reference": {"criteria": criterion_rubric},
            "agent_evidence": evidence,
            "relevant_trajectory": trajectory,
            "response_schema": {
                "criterion_results": [
                    {
                        "criterion_id": "one requested criterion_id",
                        "pass": "boolean: true for YES, false for NO",
                        "evidence_refs": ["specific supplied evidence supporting the decision"],
                        "reason": "concise criterion-specific explanation",
                    }
                ]
            },
        }
        prompt = json.dumps(prompt_document, ensure_ascii=False, sort_keys=True)
        if ternary:
            prompt_document["response_schema"]["criterion_results"] = [
                {"criterion_id": identity,
                 **({"score": "number: exactly 0, 0.5 or 1"} if values == [0, 0.5, 1] else {"pass": "boolean"}),
                 "evidence_refs": ["specific supplied evidence"], "reason": "concise explanation"}
                for identity, values in score_modes.items()]
            prompt = json.dumps(prompt_document, ensure_ascii=False, sort_keys=True)
        content: list[dict[str, Any]] = [
            {"type": "text", "text": "Return json only using the supplied response_schema.\n" + prompt}
        ]
        image_summaries = []
        for path in image_paths:
            content.append({"type": "text", "text": f"Attached raw agent-selected image: {path.name}"})
            block, summary = _image_block(path)
            content.append(block)
            image_summaries.append(summary)

        body = {
            "model": self.settings.model,
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT if not ternary else self.SYSTEM_PROMPT.replace(
                    "When evidence for the current requirement is insufficient or materially ambiguous, answer NO.",
                    "When evidence is insufficient, follow the declared discrete rubric; never invent support.").replace(
                    "Answer YES or NO for each criterion, encoded as pass: true or pass: false. Do not return a numerical score.",
                    "Follow each criterion's score_values and response_schema. For [0, 0.5, 1] output that numerical score; for binary checks output pass. Full credit requires all declared full-credit conditions; 0.5 requires the criterion's declared partial-credit conditions. Apply the declared zero-credit conditions for 0.")},
                {"role": "user", "content": content},
            ],
            "temperature": 0,
            "max_tokens": max(256, self.settings.max_output_tokens)
            if self.settings.model.casefold().startswith("gemini") else self.settings.max_output_tokens,
            "response_format": {"type": "json_object"},
        }
        complete_prompt = self.SYSTEM_PROMPT + "\n" + prompt
        input_summary = {
            "criterion_ids": expected_ids,
            "prompt_sha256": _sha256(complete_prompt.encode("utf-8")),
            "prompt_characters": len(complete_prompt),
            "images": image_summaries,
            "request_parameters": {key: body[key] for key in ("model", "temperature", "max_tokens", "response_format")},
        }
        raw_output = ""
        errors: list[str] = []
        responses: list[dict[str, Any]] = []
        for attempt in range(1, self.settings.attempts + 1):
            self._response_metadata = {}
            raw_output = ""
            try:
                raw_output = self._request(body)
                responses.append(self._safe_audit({"attempt": attempt, "max_output_tokens": body["max_tokens"], **self._response_metadata, "raw_output": raw_output}))
                parsed = _validate_response(raw_output, expected_ids, score_modes)
                return JudgeBatchResult(
                    results=parsed,
                    audit=self._safe_audit({
                        "status": "succeeded",
                        "model": self.settings.model,
                        "prompt": JUDGE_PROMPT_NAME,
                        "input_summary": input_summary,
                        "raw_output": raw_output,
                        "attempt_count": attempt,
                        "responses": responses,
                    }),
                )
            except (JudgeInfrastructureError, ValueError, KeyError, TypeError) as exc:
                if not responses or responses[-1]["attempt"] != attempt:
                    responses.append(self._safe_audit({"attempt": attempt, "max_output_tokens": body["max_tokens"], **getattr(exc, "audit", self._response_metadata)}))
                errors.append(self._safe_audit(f"attempt {attempt}: {type(exc).__name__}: {exc}"))
                if attempt < self.settings.attempts:
                    if self._response_metadata.get("finish_reason") == "length":
                        body["max_tokens"] = max(body["max_tokens"], min(32768, max(8192, body["max_tokens"] * 2)))
                    time.sleep(min(2 ** (attempt - 1), 4))
        raise JudgeInfrastructureError(
            "; ".join(errors),
            audit=self._safe_audit({
                "status": "failed",
                "model": self.settings.model,
                "prompt": JUDGE_PROMPT_NAME,
                "input_summary": input_summary,
                "raw_output": raw_output,
                "attempt_count": self.settings.attempts,
                "attempt_errors": errors,
                "responses": responses,
            }),
        )

    def _safe_audit(self, value):
        """Redact saved copies only; parse the original Judge content above."""
        if isinstance(value, str):
            return value.replace(self.settings.api_key, "[REDACTED]") if self.settings.api_key else value
        if isinstance(value, dict):
            return {self._safe_audit(key): self._safe_audit(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._safe_audit(item) for item in value]
        return value

    def _wire_body(self, raw: bytes) -> str | dict[str, str]:
        safe = raw.replace(self.settings.api_key.encode("utf-8"), b"[REDACTED]") if self.settings.api_key else raw
        try:
            return safe.decode("utf-8")
        except UnicodeDecodeError:
            return {"encoding": "base64", "data": base64.b64encode(safe).decode("ascii")}

    def _request(self, body: dict[str, Any]) -> str:
        serialized = json.dumps(body, ensure_ascii=False)
        safe_request = serialized.replace(self.settings.api_key, "[REDACTED]") if self.settings.api_key else serialized
        self._response_metadata = {"request_body": safe_request, "response_body": "", "http_status": None}
        request = urllib.request.Request(
            f"{self.settings.api_base}/chat/completions",
            data=serialized.encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.settings.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "CamAct-Benchmark/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.settings.timeout_seconds) as response:
                raw_bytes = response.read()
                self._response_metadata.update(response_body=self._wire_body(raw_bytes), http_status=int(getattr(response, "status", 200) or 200))
                raw = raw_bytes.decode("utf-8")
                payload = json.loads(raw)
        except urllib.error.HTTPError as exc:
            raw_bytes = exc.read()
            detail = raw_bytes.decode("utf-8", errors="replace")
            if self.settings.api_key:
                detail = detail.replace(self.settings.api_key, "[REDACTED]")
            self._response_metadata.update(response_body=self._wire_body(raw_bytes), http_status=exc.code)
            detail = detail[:1000]
            message = f"HTTP {exc.code}: {detail}"
            if exc.code in RETRYABLE_HTTP_CODES:
                raise JudgeInfrastructureError(message, audit=dict(self._response_metadata)) from None
            raise JudgeInfrastructureError(message, audit=dict(self._response_metadata)) from None
        except (
            TimeoutError,
            urllib.error.URLError,
            OSError,
            http.client.HTTPException,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            message = str(exc)
            if self.settings.api_key:
                message = message.replace(self.settings.api_key, "[REDACTED]")
            raise JudgeInfrastructureError(message, audit=dict(self._response_metadata)) from None
        try:
            choice = payload["choices"][0]
            content = choice["message"]["content"]
        except (KeyError, IndexError, TypeError, AttributeError) as exc:
            raise JudgeInfrastructureError("judge response omitted message content", audit=dict(self._response_metadata)) from exc
        self._response_metadata.update(finish_reason=choice.get("finish_reason"), usage=payload.get("usage", {}))
        response_audit = self._safe_audit({**self._response_metadata, "raw_output": content})
        if choice.get("finish_reason") != "stop":
            raise JudgeInfrastructureError("judge response did not finish with stop", audit=response_audit)
        if not isinstance(content, str) or not content.strip():
            raise JudgeInfrastructureError("judge returned empty message content", audit=response_audit)
        return content.strip()
