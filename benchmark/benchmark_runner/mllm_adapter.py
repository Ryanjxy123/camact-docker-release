"""Small provider adapters for running CamAct against multimodal LLM APIs.

The runtime uses one canonical transcript.  Each provider adapter is
responsible for preserving visual tool observations as native image blocks;
image data must never be flattened into a JSON string before the model call.
"""
from __future__ import annotations

import json
import base64
import hashlib
import http.client
import os
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class ModelTurn:
    text: str
    tool_calls: list[ToolCall]
    usage: dict[str, Any]
    raw_finish_reason: str | None = None


@dataclass(frozen=True)
class ProviderConfig:
    provider: str
    model: str
    api_base: str
    api_key: str
    timeout_seconds: float = 120.0
    max_output_tokens: int | None = 2048
    retry_attempts: int = 4
    telemetry_path: str | None = None
    task_key: str | None = None
    wire_path: str | None = None
    deadline: float | None = None


class ProviderInfrastructureError(RuntimeError):
    """A provider/relay request failed before a model turn was available."""


PROVIDER_ENV = {
    "relay": ("CAMACT_RELAY_BASE_URL", "CAMACT_RELAY_API_KEY"),
    "openai": ("OPENAI_BASE_URL", "OPENAI_API_KEY"),
    "anthropic": ("ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY"),
    "gemini": ("GEMINI_BASE_URL", "GEMINI_API_KEY"),
    "qwen": ("DASHSCOPE_BASE_URL", "DASHSCOPE_API_KEY"),
}

PROVIDER_BASES = {
    "relay": "",
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com",
    "gemini": "https://generativelanguage.googleapis.com/v1beta",
    "qwen": "https://dashscope.aliyuncs.com/compatible-mode/v1",
}

RETRY_BACKOFF_SECONDS = (2, 4, 8, 16, 30, 60, 90)
_TELEMETRY_LOCK = threading.Lock()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _telemetry_path(config: ProviderConfig) -> Path | None:
    value = config.telemetry_path or os.environ.get("CAMACT_PROVIDER_TELEMETRY_PATH", "")
    return Path(value) if str(value).strip() else None


def _credential_safe_text(config: ProviderConfig, value: str) -> str:
    """Provider errors may echo this role's key; never persist or rethrow it."""
    return value.replace(config.api_key, "[REDACTED]") if config.api_key else value


def _write_attempt_telemetry(config: ProviderConfig, event: dict[str, Any]) -> None:
    path = _telemetry_path(config)
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    line = _credential_safe_text(config, json.dumps(event, ensure_ascii=False, separators=(",", ":"))) + "\n"
    with _TELEMETRY_LOCK:
        with path.open("a", encoding="utf-8") as output:
            output.write(line)


def _record_provider_attempt(config: ProviderConfig, event: dict[str, Any], request_body: bytes, response_body: bytes) -> None:
    """Optional per-session wire capture, with the original request untouched."""
    _write_attempt_telemetry(config, event)
    if not config.wire_path:
        return
    key = config.api_key.encode("utf-8") if config.api_key else b""
    raw = {"request": request_body, "response": response_body}
    record = {**event, "schema_version": "camact.provider_wire.v1"}
    for name, value in raw.items():
        safe = value.replace(key, b"[REDACTED]") if key else value
        record[name + "_sha256"] = hashlib.sha256(safe).hexdigest()
        record[name + "_credential_redacted"] = safe != value
        try:
            record[name + "_body"] = safe.decode("utf-8")
        except UnicodeDecodeError:
            record[name + "_body"] = safe.decode("utf-8", errors="replace")
            # Preserve invalid/non-text HTTP bodies without losing their bytes.
            record[name + "_body_base64"] = base64.b64encode(safe).decode("ascii")
    path = Path(config.wire_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = _credential_safe_text(config, json.dumps(record, ensure_ascii=False, separators=(",", ":"))) + "\n"
    with _TELEMETRY_LOCK:
        with path.open("a", encoding="utf-8") as output:
            output.write(line)


def _upstream_model(response: Any) -> str | None:
    if not isinstance(response, dict):
        return None
    value = response.get("model") or response.get("modelVersion")
    return str(value) if value else None


def _env_value(name: str) -> str:
    return os.environ.get(name, "").strip()


def resolve_provider_config(
    *,
    provider: str,
    model: str,
    api_base: str | None = None,
    api_key_env: str | None = None,
    timeout_seconds: float = 120.0,
    max_output_tokens: int | None = 2048,
    retry_attempts: int = 4,
    telemetry_path: str | None = None,
    task_key: str | None = None,
) -> ProviderConfig:
    provider = provider.casefold()
    if provider not in PROVIDER_ENV:
        raise ValueError(f"unsupported provider: {provider}")
    base_env, key_env = PROVIDER_ENV[provider]
    resolved_base = (api_base or _env_value(base_env) or PROVIDER_BASES[provider]).rstrip("/")
    resolved_key_env = api_key_env or key_env
    resolved_key = _env_value(resolved_key_env)
    if not resolved_base:
        raise ValueError(f"{provider} API base is missing; set {base_env} or --api-base")
    if not resolved_key:
        raise ValueError(f"API key is missing; set {resolved_key_env}")
    if retry_attempts < 1:
        raise ValueError("retry_attempts must be at least 1")
    if provider in {"relay", "openai", "qwen"} and not resolved_base.endswith("/v1"):
        resolved_base += "/v1"
    return ProviderConfig(
        provider=provider,
        model=model,
        api_base=resolved_base,
        api_key=resolved_key,
        timeout_seconds=timeout_seconds,
        max_output_tokens=max_output_tokens,
        retry_attempts=retry_attempts,
        telemetry_path=telemetry_path,
        task_key=task_key,
    )


def _json_request(
    url: str,
    body: dict[str, Any],
    headers: dict[str, str],
    config: ProviderConfig,
    *,
    component: str = "agent_model",
    model_turn: int | None = None,
    validate_response=None,
) -> dict[str, Any]:
    from harness.camact_token_usage_v1.collector import current
    from harness.camact_token_usage_v1.http import observe_open
    from benchmark.services.http_compression import compress_request
    token_collector = current() if component == "agent_model" else None
    image_transport = None
    if component == "agent_model":
        from benchmark.services.image_transport import prepare_request, ImageTransportLimitError
        try:
            body, image_transport = prepare_request(body)
        except ImageTransportLimitError as exc:
            raise ProviderInfrastructureError(str(exc)) from None
    payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
    last_error: Exception | None = None
    request_id = f"req_{uuid.uuid4().hex}"
    for attempt in range(config.retry_attempts):
        remaining = config.deadline - time.monotonic() if config.deadline is not None else config.timeout_seconds
        if remaining <= 0:
            raise ProviderInfrastructureError("Task deadline expired before provider request")
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        if image_transport is not None and len(payload) > image_transport["max_request_bytes"]:
            raise ProviderInfrastructureError("Complete image request exceeds its preflight byte limit")
        truncated = False
        started_at = _utc_now()
        started = time.monotonic()
        status = "error"
        http_status: int | None = None
        exception_type: str | None = None
        exception_message: str | None = None
        timeout = False
        upstream_model: str | None = None
        response_body = b""
        wire_payload, wire_headers, wire_metadata = compress_request(payload, {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "CamAct-Benchmark/1.0",
            **headers,
        })
        if image_transport is not None:
            wire_metadata["image_transport"] = image_transport
        request = urllib.request.Request(
            url, data=wire_payload, headers=wire_headers, method="POST",
        )
        try:
            with observe_open(token_collector, urllib.request.urlopen, request, timeout=min(config.timeout_seconds, remaining),
                              metadata={"operation_id": request_id, "retry_attempt": attempt,
                                        "agent_turn_id": model_turn}) as response:
                http_status = int(getattr(response, "status", 200) or 200)
                try:
                    response_body = response.read()
                    result = json.loads(response_body.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    last_error = RuntimeError(f"provider returned invalid JSON response: {exc}")
                    exception_type = type(last_error).__name__
                    exception_message = _credential_safe_text(config, str(last_error))
                else:
                    if isinstance(result, dict):
                        if config.deadline is not None and time.monotonic() >= config.deadline:
                            raise ProviderInfrastructureError("Task deadline expired during provider response")
                        if validate_response is not None:
                            validate_response(result)
                        status = "succeeded"
                        upstream_model = _upstream_model(result)
                        _record_provider_attempt(config, {
                            **wire_metadata,
                            "schema_version": "camact.provider_attempt.v1",
                            "request_id": request_id,
                            "task": config.task_key or os.environ.get("CAMACT_TASK_KEY"),
                            "component": component,
                            "model_turn": model_turn,
                            "attempt_index": attempt + 1,
                            "retry_index": attempt,
                            "started_at": started_at,
                            "ended_at": _utc_now(),
                            "latency_seconds": round(time.monotonic() - started, 6),
                            "status": status,
                            "http_status": http_status,
                            "exception_type": None,
                            "exception": None,
                            "timeout": False,
                            "requested_model": config.model,
                            "configured_model": str(body.get("model") or config.model),
                            "upstream_model": upstream_model,
                        }, payload, response_body)
                        return result
                    last_error = RuntimeError("provider returned a non-object JSON response")
                    exception_type = type(last_error).__name__
                    exception_message = _credential_safe_text(config, str(last_error))
        except urllib.error.HTTPError as exc:
            response_body = exc.read()
            detail = _credential_safe_text(config, response_body.decode("utf-8", errors="replace"))
            http_status = exc.code
            last_error = RuntimeError(_credential_safe_text(config, f"HTTP {exc.code} from {url}: {detail[:1000]}"))
            exception_type = type(last_error).__name__
            exception_message = str(last_error)
            retryable = exc.code in {408, 409, 429, 500, 502, 503, 504, 524}
            if exc.code == 400:
                try:
                    provider_error = json.loads(detail).get("error", {})
                    retryable = isinstance(provider_error, dict) and (
                        provider_error.get("code") == "upstream_error"
                        or provider_error.get("type") == "upstream_error"
                    )
                except (ValueError, AttributeError):
                    pass
            if not retryable:
                _record_provider_attempt(config, {
                    **wire_metadata,
                    "schema_version": "camact.provider_attempt.v1", "request_id": request_id,
                    "task": config.task_key or os.environ.get("CAMACT_TASK_KEY"), "component": component,
                    "model_turn": model_turn, "attempt_index": attempt + 1, "retry_index": attempt,
                    "started_at": started_at, "ended_at": _utc_now(),
                    "latency_seconds": round(time.monotonic() - started, 6), "status": "error",
                    "http_status": http_status, "exception_type": exception_type,
                    "exception": exception_message, "timeout": False,
                    "requested_model": config.model, "configured_model": str(body.get("model") or config.model),
                    "upstream_model": None,
                }, payload, response_body)
                # HTTP reason strings can also echo a key. Suppress the raw
                # provider exception chain in CLI tracebacks and saved logs.
                raise ProviderInfrastructureError(str(last_error)) from None
        except ProviderInfrastructureError as exc:
            last_error = exc
            truncated = getattr(exc, "finish_reason", None) == "length"
            exception_type = type(exc).__name__
            exception_message = _credential_safe_text(config, str(exc))
        except (TimeoutError, urllib.error.URLError, OSError, http.client.HTTPException) as exc:
            last_error = RuntimeError(_credential_safe_text(config, str(exc)))
            exception_type = type(exc).__name__
            exception_message = str(last_error)
            timeout = isinstance(exc, (TimeoutError, socket.timeout)) or "timed out" in str(exc).casefold()
            status = "timeout" if timeout else "error"
        _record_provider_attempt(config, {
            **wire_metadata,
            "schema_version": "camact.provider_attempt.v1",
            "request_id": request_id,
            "task": config.task_key or os.environ.get("CAMACT_TASK_KEY"),
            "component": component,
            "model_turn": model_turn,
            "attempt_index": attempt + 1,
            "retry_index": attempt,
            "started_at": started_at,
            "ended_at": _utc_now(),
            "latency_seconds": round(time.monotonic() - started, 6),
            "status": status,
            "http_status": http_status,
            "exception_type": exception_type,
            "exception": exception_message,
            "timeout": timeout,
            "requested_model": config.model,
            "configured_model": str(body.get("model") or config.model),
            "upstream_model": upstream_model,
        }, payload, response_body)
        if attempt + 1 < config.retry_attempts:
            if truncated and component == "simulator_model" and isinstance(body.get("max_tokens"), int):
                body = {**body, "max_tokens": max(body["max_tokens"], min(32768, max(4096, body["max_tokens"] * 2)))}
            delay = RETRY_BACKOFF_SECONDS[min(attempt, len(RETRY_BACKOFF_SECONDS) - 1)]
            if config.deadline is not None:
                delay = min(delay, max(0, config.deadline - time.monotonic()))
            time.sleep(delay)
    raise ProviderInfrastructureError(
        _credential_safe_text(config, f"provider request failed after {config.retry_attempts} attempts: {last_error}")
    )


def _data_url(block: dict[str, Any]) -> tuple[str, str]:
    url = str(block["image_url"]["url"])
    if not url.startswith("data:") or ";base64," not in url:
        raise ValueError("multimodal observations must use a base64 data URL")
    header, data = url.split(",", 1)
    media_type = header[5:].split(";", 1)[0]
    return media_type, data


def _text_block(text: str) -> dict[str, str]:
    return {"type": "text", "text": text}


def _openai_content(blocks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [dict(block) for block in blocks]


def _openai_message_content(
    blocks: list[dict[str, Any]],
) -> str | list[dict[str, Any]]:
    """Use a plain string for text-only turns for broad relay compatibility."""
    if all(block.get("type") == "text" for block in blocks):
        return "\n".join(str(block.get("text", "")) for block in blocks)
    return _openai_content(blocks)


def _anthropic_content(blocks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for block in blocks:
        if block.get("type") == "text":
            result.append({"type": "text", "text": str(block.get("text", ""))})
        elif block.get("type") == "image_url":
            media_type, data = _data_url(block)
            result.append(
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": media_type,
                        "data": data,
                    },
                }
            )
    return result


def _gemini_parts(blocks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for block in blocks:
        if block.get("type") == "text":
            result.append({"text": str(block.get("text", ""))})
        elif block.get("type") == "image_url":
            media_type, data = _data_url(block)
            result.append({"inlineData": {"mimeType": media_type, "data": data}})
    return result


def _history_assistant_text(item: dict[str, Any]) -> str:
    """Accept restored conversation messages as well as live ModelTurn items."""
    if "text" in item:
        return str(item.get("text") or "")
    content = item.get("content", "")
    if isinstance(content, str):
        return content
    return "\n".join(block.get("text", "") for block in content if isinstance(block, dict) and block.get("type") == "text")


class BaseAdapter:
    def __init__(self, config: ProviderConfig):
        self.config = config

    def complete(
        self,
        *,
        system_prompt: str,
        history: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> ModelTurn:
        raise NotImplementedError


class OpenAICompatibleAdapter(BaseAdapter):
    """OpenAI Chat Completions format, also used by the relay and Qwen."""

    def build_payload(
        self,
        system_prompt: str,
        history: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        messages: list[dict[str, Any]] = [{"role": "system", "content": system_prompt}]
        index = 0
        while index < len(history):
            item = history[index]
            role = item["role"]
            if role == "user":
                messages.append(
                    {
                        "role": "user",
                        "content": _openai_message_content(item["content"]),
                    }
                )
            elif role == "assistant":
                message: dict[str, Any] = {
                    "role": "assistant",
                    "content": _history_assistant_text(item) or None,
                }
                calls = item.get("tool_calls", [])
                if calls:
                    message["tool_calls"] = [
                        {
                            "id": call["id"],
                            "type": "function",
                            "function": {
                                "name": call["name"],
                                "arguments": json.dumps(call["arguments"], ensure_ascii=False),
                            },
                        }
                        for call in calls
                    ]
                # Empty completed turns remain in the audit/Step count, but
                # DeepSeek rejects an assistant with neither text nor calls.
                if message["content"] or calls:
                    messages.append(message)
            elif role == "tool":
                visuals: list[list[dict[str, Any]]] = []
                while index < len(history) and history[index]["role"] == "tool":
                    tool_item = history[index]
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tool_item["tool_call_id"],
                            "content": json.dumps(tool_item["result"], ensure_ascii=False),
                        }
                    )
                    if tool_item.get("content"):
                        visuals.append(tool_item["content"])
                    index += 1
                for visual in visuals:
                    messages.append({"role": "user", "content": _openai_content(visual)})
                continue
            index += 1
        payload = {
            "model": self.config.model,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
        }
        if self.config.max_output_tokens is not None:
            payload["max_tokens"] = self.config.max_output_tokens
        return payload

    def complete(self, *, system_prompt: str, history: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ModelTurn:
        body = self.build_payload(system_prompt, history, tools)
        response = _json_request(
            f"{self.config.api_base}/chat/completions",
            body,
            {"Authorization": f"Bearer {self.config.api_key}"},
            self.config,
            component="agent_model",
            model_turn=1 + sum(item.get("role") == "assistant" for item in history),
            validate_response=_validate_chat_response,
        )
        choice = response["choices"][0]
        message = choice["message"]
        calls = []
        for index, item in enumerate(message.get("tool_calls") or []):
            function = item.get("function", {})
            raw_arguments = function.get("arguments") or "{}"
            if isinstance(raw_arguments, dict):
                arguments = raw_arguments
            else:
                try:
                    arguments = json.loads(raw_arguments)
                except (TypeError, json.JSONDecodeError):
                    arguments = {}
            calls.append(
                ToolCall(
                    id=str(item.get("id") or f"call_{index}"),
                    name=str(function.get("name", "")),
                    arguments=arguments if isinstance(arguments, dict) else {},
                )
            )
        return ModelTurn(
            text=str(message.get("content") or ""),
            tool_calls=calls,
            usage=response.get("usage", {}),
            raw_finish_reason=choice.get("finish_reason"),
        )


class AnthropicAdapter(BaseAdapter):
    def build_payload(self, system_prompt: str, history: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
        messages: list[dict[str, Any]] = []
        index = 0
        while index < len(history):
            item = history[index]
            if item["role"] == "user":
                messages.append({"role": "user", "content": _anthropic_content(item["content"])})
            elif item["role"] == "assistant":
                content: list[dict[str, Any]] = []
                if _history_assistant_text(item):
                    content.append(_text_block(_history_assistant_text(item)))
                content.extend(
                    {
                        "type": "tool_use",
                        "id": call["id"],
                        "name": call["name"],
                        "input": call["arguments"],
                    }
                    for call in item.get("tool_calls", [])
                )
                if content:
                    messages.append({"role": "assistant", "content": content})
            elif item["role"] == "tool":
                results = []
                while index < len(history) and history[index]["role"] == "tool":
                    tool_item = history[index]
                    content = [_text_block(json.dumps(tool_item["result"], ensure_ascii=False))]
                    content.extend(_anthropic_content(tool_item.get("content", [])))
                    results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": tool_item["tool_call_id"],
                            "content": content,
                            "is_error": not bool(tool_item["result"].get("ok", True)),
                        }
                    )
                    index += 1
                messages.append({"role": "user", "content": results})
                continue
            index += 1
        anthropic_tools = [
            {
                "name": item["function"]["name"],
                "description": item["function"].get("description", ""),
                "input_schema": item["function"]["parameters"],
            }
            for item in tools
        ]
        payload = {
            "model": self.config.model,
            "system": system_prompt,
            "messages": messages,
            "tools": anthropic_tools,
        }
        if self.config.max_output_tokens is not None:
            payload["max_tokens"] = self.config.max_output_tokens
        return payload

    def complete(self, *, system_prompt: str, history: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ModelTurn:
        response = _json_request(
            f"{self.config.api_base}/v1/messages",
            self.build_payload(system_prompt, history, tools),
            {
                "x-api-key": self.config.api_key,
                "anthropic-version": "2023-06-01",
            },
            self.config,
            component="agent_model",
            model_turn=1 + sum(item.get("role") == "assistant" for item in history),
        )
        text = "\n".join(
            str(block.get("text", "")) for block in response.get("content", []) if block.get("type") == "text"
        )
        calls = [
            ToolCall(
                id=str(block["id"]),
                name=str(block["name"]),
                arguments=block.get("input", {}) if isinstance(block.get("input", {}), dict) else {},
            )
            for block in response.get("content", [])
            if block.get("type") == "tool_use"
        ]
        return ModelTurn(text=text, tool_calls=calls, usage=response.get("usage", {}), raw_finish_reason=response.get("stop_reason"))


class GeminiAdapter(BaseAdapter):
    def build_payload(self, system_prompt: str, history: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
        contents: list[dict[str, Any]] = []
        index = 0
        while index < len(history):
            item = history[index]
            if item["role"] == "user":
                contents.append({"role": "user", "parts": _gemini_parts(item["content"])})
            elif item["role"] == "assistant":
                parts: list[dict[str, Any]] = []
                if _history_assistant_text(item):
                    parts.append({"text": _history_assistant_text(item)})
                parts.extend(
                    {
                        "functionCall": {
                            "name": call["name"],
                            "args": call["arguments"],
                        }
                    }
                    for call in item.get("tool_calls", [])
                )
                contents.append({"role": "model", "parts": parts})
            elif item["role"] == "tool":
                parts: list[dict[str, Any]] = []
                while index < len(history) and history[index]["role"] == "tool":
                    tool_item = history[index]
                    parts.append(
                        {
                            "functionResponse": {
                                "name": tool_item["name"],
                                "response": tool_item["result"],
                            }
                        }
                    )
                    parts.extend(_gemini_parts(tool_item.get("content", [])))
                    index += 1
                contents.append({"role": "user", "parts": parts})
                continue
            index += 1
        declarations = [
            {
                "name": item["function"]["name"],
                "description": item["function"].get("description", ""),
                "parameters": item["function"]["parameters"],
            }
            for item in tools
        ]
        payload = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": contents,
            "tools": [{"functionDeclarations": declarations}],
        }
        if self.config.max_output_tokens is not None:
            payload["generationConfig"] = {"maxOutputTokens": self.config.max_output_tokens}
        return payload

    def complete(self, *, system_prompt: str, history: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ModelTurn:
        url = f"{self.config.api_base}/models/{quote(self.config.model, safe='')}:generateContent"
        response = _json_request(
            url,
            self.build_payload(system_prompt, history, tools),
            {"x-goog-api-key": self.config.api_key},
            self.config,
            component="agent_model",
            model_turn=1 + sum(item.get("role") == "assistant" for item in history),
        )
        candidate = response["candidates"][0]
        parts = candidate.get("content", {}).get("parts", [])
        text = "\n".join(str(part.get("text", "")) for part in parts if "text" in part)
        calls = []
        for index, part in enumerate(parts):
            function = part.get("functionCall")
            if function:
                calls.append(
                    ToolCall(
                        id=f"gemini_call_{index}",
                        name=str(function.get("name", "")),
                        arguments=function.get("args", {}) if isinstance(function.get("args", {}), dict) else {},
                    )
                )
        return ModelTurn(
            text=text,
            tool_calls=calls,
            usage=response.get("usageMetadata", {}),
            raw_finish_reason=candidate.get("finishReason"),
        )


def create_adapter(config: ProviderConfig) -> BaseAdapter:
    if config.provider in {"relay", "openai", "qwen"}:
        return OpenAICompatibleAdapter(config)
    if config.provider == "anthropic":
        return AnthropicAdapter(config)
    if config.provider == "gemini":
        return GeminiAdapter(config)
    raise ValueError(f"unsupported provider: {config.provider}")


def _validate_chat_response(response):
    try:
        choice = response["choices"][0]
        message = choice["message"]
        if not isinstance(choice, dict) or not isinstance(message, dict):
            raise TypeError()
        if message.get("content") is not None and not isinstance(message["content"], str):
            raise TypeError()
        calls = message.get("tool_calls") or []
        if not isinstance(calls, list) or choice.get("finish_reason") is None:
            raise TypeError()
        for call in calls:
            function = call["function"]
            if not isinstance(call.get("id"), str) or not call["id"] or not isinstance(function.get("name"), str) or not function["name"]:
                raise TypeError()
            raw = function.get("arguments", "{}")
            arguments = raw if isinstance(raw, dict) else json.loads(raw)
            if not isinstance(arguments, dict):
                raise TypeError()
    except (KeyError, IndexError, TypeError, ValueError, AttributeError):
        raise ProviderInfrastructureError("provider returned a malformed Chat completion or tool call") from None


def _validate_simulator_response(response):
    _validate_chat_response(response)
    choice = response["choices"][0]
    message = choice["message"]
    if choice["finish_reason"] != "stop":
        error = ProviderInfrastructureError("simulator response did not finish with stop")
        error.finish_reason = choice["finish_reason"]
        raise error
    if message.get("tool_calls") or not isinstance(message.get("content"), str) or not message["content"].strip():
        raise ProviderInfrastructureError("simulator provider returned empty or non-text output")


def complete_text(
    config: ProviderConfig,
    *,
    system_prompt: str,
    user_prompt: str | None = None,
    seed: int,
    messages: list[dict[str, str]] | None = None,
) -> str:
    """Generate one deterministic text-only response with an OpenAI-compatible API."""
    if config.provider not in {"relay", "openai", "qwen"}:
        raise ValueError("User simulator requires an OpenAI-compatible provider")
    payload = {
        "model": config.model,
        "messages": [{"role": "system", "content": system_prompt}] + (
            messages if messages is not None else [{"role": "user", "content": user_prompt}]
        ),
        "temperature": 0,
        "seed": int(seed),
    }
    if config.max_output_tokens is not None:
        payload["max_tokens"] = config.max_output_tokens
    response = _json_request(
        f"{config.api_base}/chat/completions",
        payload,
        {"Authorization": f"Bearer {config.api_key}"},
        config,
        component="simulator_model",
        model_turn=None,
        validate_response=_validate_simulator_response,
    )
    content = response["choices"][0]["message"].get("content")
    if not isinstance(content, str) or not content.strip():
        raise RuntimeError("simulator provider returned empty text")
    return content.strip()
