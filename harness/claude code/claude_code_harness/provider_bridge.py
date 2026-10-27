"""Local protocol bridge for running OpenAI-protocol models through Claude Code."""
from __future__ import annotations

import copy
import hashlib
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import AbstractContextManager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from harness.camact_token_usage_v1.collector import current as token_collector
from harness.camact_token_usage_v1.http import observe_open
from benchmark.services.http_compression import compress_request


def requires_protocol_bridge(model: str) -> bool:
    """Return whether Claude Code needs an OpenAI-protocol bridge for a model."""
    value = str(model or "").strip().casefold()
    return bool(value) and not value.startswith(("claude-", "sonnet", "opus", "haiku"))


def api_key_diagnostic(api_key: str) -> dict[str, Any]:
    """Return a non-secret credential identity for transient connectivity output."""
    encoded = str(api_key).encode("utf-8")
    return {
        "utf8_byte_length": len(encoded),
        "sha256_prefix_12": hashlib.sha256(encoded).hexdigest()[:12],
    }


def chat_completions_url(base_url: str) -> str:
    """Resolve an OpenAI-compatible base URL to its chat completions endpoint."""
    root = base_url.rstrip("/")
    path = urllib.parse.urlsplit(root).path.rstrip("/")
    if path.endswith("/chat/completions"):
        return root
    if not path:
        return f"{root}/v1/chat/completions"
    return f"{root}/chat/completions"


def uses_responses_api(base_url: str) -> bool:
    """Treat a host-only Codex endpoint as a native Responses API base."""
    return not urllib.parse.urlsplit(base_url.rstrip("/")).path.rstrip("/")


def responses_url(base_url: str) -> str:
    root = base_url.rstrip("/")
    path = urllib.parse.urlsplit(root).path.rstrip("/")
    if path.endswith("/responses"):
        return root
    return f"{root}/responses"


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(
            str(item.get("text", ""))
            for item in value
            if isinstance(item, dict) and item.get("type") == "text"
        )
    return str(value or "")


def _openai_blocks(content: Any) -> str | list[dict[str, Any]]:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return str(content or "")
    blocks: list[dict[str, Any]] = []
    for item in content:
        if not isinstance(item, dict):
            continue
        kind = item.get("type")
        if kind == "text":
            blocks.append({"type": "text", "text": str(item.get("text", ""))})
        elif kind == "image":
            source = item.get("source", {})
            if isinstance(source, dict) and source.get("type") == "base64":
                media_type = str(source.get("media_type") or "image/jpeg")
                data = str(source.get("data") or "")
                blocks.append({
                    "type": "image_url",
                    "image_url": {"url": f"data:{media_type};base64,{data}"},
                })
    if all(item.get("type") == "text" for item in blocks):
        return "\n".join(str(item.get("text", "")) for item in blocks)
    return blocks


def _reasoning_text(value: Any) -> str:
    """Extract provider reasoning without treating it as answer text."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("text", "content", "reasoning", "thought", "thinking"):
            if key in value:
                text = _reasoning_text(value[key])
                if text:
                    return text
        return ""
    if isinstance(value, list):
        parts = [_reasoning_text(item) for item in value]
        return "".join(part for part in parts if part)
    return ""


def _reasoning_effort(value: dict[str, Any]) -> str | None:
    """Map an explicit Anthropic thinking budget to OpenAI reasoning effort."""
    thinking = value.get("thinking")
    if not isinstance(thinking, dict):
        return None
    kind = str(thinking.get("type") or "").casefold()
    if kind == "disabled":
        return "none"
    if kind != "enabled":
        return None
    try:
        budget = int(thinking.get("budget_tokens") or 0)
    except (TypeError, ValueError):
        budget = 0
    if budget >= 16_384:
        return "high"
    if budget >= 4_096:
        return "medium"
    return "low"


def _tool_choice(value: dict[str, Any]) -> Any:
    """Preserve explicit Anthropic tool-choice semantics in OpenAI form."""
    choice = value.get("tool_choice")
    if isinstance(choice, str):
        return choice
    if not isinstance(choice, dict):
        return "auto"
    kind = str(choice.get("type") or "auto").casefold()
    if kind == "none":
        return "none"
    if kind in {"any", "required"}:
        return "required"
    if kind == "tool" and choice.get("name"):
        return {"type": "function", "function": {"name": str(choice["name"])}}
    return "auto"


def _parallel_tool_calls(value: dict[str, Any]) -> bool | None:
    """Preserve explicit Anthropic parallel-tool semantics when present."""
    explicit = value.get("parallel_tool_calls")
    if isinstance(explicit, bool):
        return explicit
    tool_choice = value.get("tool_choice")
    if isinstance(tool_choice, dict):
        disabled = tool_choice.get("disable_parallel_tool_use")
        if isinstance(disabled, bool):
            return not disabled
    return None


def anthropic_to_openai(value: dict[str, Any], model: str) -> dict[str, Any]:
    """Translate one Anthropic Messages request to OpenAI Chat Completions."""
    messages: list[dict[str, Any]] = []
    system = _text(value.get("system"))
    if system:
        messages.append({"role": "system", "content": system})
    for message in value.get("messages", []):
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "user")
        content = message.get("content", "")
        if role == "assistant" and isinstance(content, list):
            text_blocks = [item for item in content if isinstance(item, dict) and item.get("type") == "text"]
            thinking_blocks = [item for item in content if isinstance(item, dict) and item.get("type") == "thinking"]
            tool_blocks = [item for item in content if isinstance(item, dict) and item.get("type") == "tool_use"]
            translated: dict[str, Any] = {"role": "assistant", "content": _openai_blocks(text_blocks) or None}
            thinking = _reasoning_text(thinking_blocks)
            if thinking:
                translated["reasoning_content"] = thinking
            if tool_blocks:
                translated["tool_calls"] = [
                    {
                        "id": str(item.get("id") or f"call_{index}"),
                        "type": "function",
                        "function": {
                            "name": str(item.get("name") or ""),
                            "arguments": json.dumps(item.get("input", {}), ensure_ascii=False),
                        },
                    }
                    for index, item in enumerate(tool_blocks)
                ]
            messages.append(translated)
            continue
        if role == "user" and isinstance(content, list) and any(
            isinstance(item, dict) and item.get("type") == "tool_result" for item in content
        ):
            followup: list[dict[str, Any]] = []
            for item in content:
                if not isinstance(item, dict):
                    continue
                if item.get("type") == "tool_result":
                    result_content = item.get("content", "")
                    messages.append({
                        "role": "tool",
                        "tool_call_id": str(item.get("tool_use_id") or ""),
                        "content": _text(result_content),
                    })
                    if isinstance(result_content, list):
                        followup.extend(
                            block for block in result_content
                            if isinstance(block, dict) and block.get("type") == "image"
                        )
                elif item.get("type") in {"text", "image"}:
                    followup.append(item)
            if followup:
                messages.append({"role": "user", "content": _openai_blocks(followup)})
            continue
        messages.append({"role": role, "content": _openai_blocks(content)})

    tools = []
    for item in value.get("tools", []):
        if not isinstance(item, dict) or not item.get("name"):
            continue
        tools.append({
            "type": "function",
            "function": {
                "name": str(item["name"]),
                "description": str(item.get("description") or ""),
                "parameters": copy.deepcopy(item.get("input_schema") or {"type": "object", "properties": {}}),
            },
        })
    result: dict[str, Any] = {
        "model": model,
        "messages": messages,
        # The bridge buffers the complete provider response before emitting
        # Anthropic SSE events. Requesting a complete JSON response avoids a
        # zcloud streaming edge case where text_tokens are reported but no
        # consumable delta.content is sent.
        "stream": False,
        "max_tokens": int(value.get("max_tokens") or 8192),
    }
    if tools:
        result.update({"tools": tools, "tool_choice": _tool_choice(value)})
        parallel_tool_calls = _parallel_tool_calls(value)
        if parallel_tool_calls is not None:
            result["parallel_tool_calls"] = parallel_tool_calls
    for key in ("temperature", "top_p"):
        if value.get(key) is not None:
            result[key] = value[key]
    stop = value.get("stop_sequences")
    if isinstance(stop, list) and stop:
        result["stop"] = stop
    reasoning_effort = _reasoning_effort(value)
    if reasoning_effort is not None:
        result["reasoning_effort"] = reasoning_effort
    return result


def _responses_blocks(content: Any, *, output: bool = False) -> list[dict[str, Any]]:
    if isinstance(content, str):
        return [{"type": "output_text" if output else "input_text", "text": content}]
    if not isinstance(content, list):
        return [{"type": "output_text" if output else "input_text", "text": str(content or "")}]
    blocks: list[dict[str, Any]] = []
    for item in content:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "text":
            blocks.append({"type": "output_text" if output else "input_text", "text": str(item.get("text", ""))})
        elif item.get("type") == "image" and not output:
            source = item.get("source", {})
            if isinstance(source, dict) and source.get("type") == "base64":
                media_type = str(source.get("media_type") or "image/jpeg")
                data = str(source.get("data") or "")
                blocks.append({"type": "input_image", "image_url": f"data:{media_type};base64,{data}"})
    return blocks


def anthropic_to_responses(value: dict[str, Any], model: str) -> dict[str, Any]:
    """Translate one Anthropic Messages request to OpenAI Responses."""
    input_items: list[dict[str, Any]] = []
    for message in value.get("messages", []):
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "user")
        content = message.get("content", "")
        if role == "assistant" and isinstance(content, list):
            text_blocks = [item for item in content if isinstance(item, dict) and item.get("type") == "text"]
            if text_blocks:
                input_items.append({"role": "assistant", "content": _responses_blocks(text_blocks, output=True)})
            for item in content:
                if isinstance(item, dict) and item.get("type") == "tool_use":
                    call_id = str(item.get("id") or f"call_{len(input_items)}")
                    input_items.append({
                        "type": "function_call",
                        "call_id": call_id,
                        "name": str(item.get("name") or ""),
                        "arguments": json.dumps(item.get("input", {}), ensure_ascii=False),
                    })
            continue
        if role == "user" and isinstance(content, list) and any(
            isinstance(item, dict) and item.get("type") == "tool_result" for item in content
        ):
            followup: list[dict[str, Any]] = []
            for item in content:
                if not isinstance(item, dict):
                    continue
                if item.get("type") == "tool_result":
                    result_content = item.get("content", "")
                    input_items.append({
                        "type": "function_call_output",
                        "call_id": str(item.get("tool_use_id") or ""),
                        "output": _text(result_content),
                    })
                    if isinstance(result_content, list):
                        followup.extend(
                            block for block in result_content
                            if isinstance(block, dict) and block.get("type") == "image"
                        )
                elif item.get("type") in {"text", "image"}:
                    followup.append(item)
            if followup:
                input_items.append({"role": "user", "content": _responses_blocks(followup)})
            continue
        input_items.append({"role": role, "content": _responses_blocks(content, output=role == "assistant")})

    tools = []
    for item in value.get("tools", []):
        if not isinstance(item, dict) or not item.get("name"):
            continue
        tools.append({
            "type": "function",
            "name": str(item["name"]),
            "description": str(item.get("description") or ""),
            "parameters": copy.deepcopy(item.get("input_schema") or {"type": "object", "properties": {}}),
            "strict": False,
        })
    result: dict[str, Any] = {
        "model": model,
        "input": input_items,
        "stream": True,
        "store": False,
        "max_output_tokens": int(value.get("max_tokens") or 8192),
    }
    system = _text(value.get("system"))
    if system:
        result["instructions"] = system
    if tools:
        result.update({"tools": tools, "tool_choice": "auto"})
        parallel_tool_calls = _parallel_tool_calls(value)
        if parallel_tool_calls is not None:
            result["parallel_tool_calls"] = parallel_tool_calls
    for key in ("temperature", "top_p"):
        if value.get(key) is not None:
            result[key] = value[key]
    return result


def _usage(value: Any) -> dict[str, int]:
    usage = value if isinstance(value, dict) else {}
    return {
        "input_tokens": int(usage.get("prompt_tokens", usage.get("input_tokens", 0)) or 0),
        "output_tokens": int(usage.get("completion_tokens", usage.get("output_tokens", 0)) or 0),
    }


def _completed_stream(lines: list[bytes], *, responses_mode: bool) -> tuple[bool, str | None]:
    finished = False
    saw_done = False
    saw_terminal_choice = False
    for raw in lines:
        line = raw.decode("utf-8", errors="replace").strip()
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]" and not responses_mode:
            saw_done = True
            continue
        if not data:
            continue
        try:
            value = json.loads(data)
        except json.JSONDecodeError:
            continue
        if responses_mode:
            event_type = str(value.get("type") or "")
            if event_type == "response.completed":
                finished = True
            elif event_type in {"error", "response.failed", "response.incomplete"}:
                response = value.get("response") if isinstance(value.get("response"), dict) else {}
                error = value.get("error") or response.get("error") or response.get("incomplete_details") or event_type
                return False, error.get("message") if isinstance(error, dict) else str(error)
        else:
            if isinstance(value.get("error"), dict):
                return False, str(value["error"].get("message") or "upstream error")
            choices = value.get("choices")
            if isinstance(choices, list) and any(
                isinstance(choice, dict) and choice.get("finish_reason") is not None for choice in choices
            ):
                saw_terminal_choice = True
                finished = True
    protocol = "Responses" if responses_mode else "Chat Completions"
    if not responses_mode and saw_done and not saw_terminal_choice:
        return False, f"upstream {protocol} stream ended without a terminal finish_reason"
    return finished, None if finished else f"upstream {protocol} stream ended before completion"


def chat_stream_diagnostic(lines: list[bytes]) -> dict[str, Any]:
    """Summarize a Chat Completions stream without retaining response data."""
    summary: dict[str, Any] = {
        "chunks": 0,
        "delta_fields": {},
        "content_value_types": {},
        "content_chunks": 0,
        "content_characters": 0,
        "reasoning_chunks": 0,
        "reasoning_characters": 0,
        "tool_call_chunks": 0,
        "finish_reasons": [],
        "usage": {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "text_tokens": 0,
            "reasoning_tokens": 0,
        },
    }
    delta_fields: dict[str, int] = summary["delta_fields"]
    content_value_types: dict[str, int] = summary["content_value_types"]
    finish_reasons: list[str] = summary["finish_reasons"]
    usage_summary: dict[str, int] = summary["usage"]
    for raw in lines:
        line = raw.decode("utf-8", errors="replace").strip()
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if not data or data == "[DONE]":
            continue
        try:
            chunk = json.loads(data)
        except json.JSONDecodeError:
            continue
        summary["chunks"] += 1
        usage = chunk.get("usage")
        if isinstance(usage, dict):
            usage_summary["prompt_tokens"] = int(usage.get("prompt_tokens", 0) or 0)
            usage_summary["completion_tokens"] = int(usage.get("completion_tokens", 0) or 0)
            details = usage.get("completion_tokens_details")
            if isinstance(details, dict):
                usage_summary["text_tokens"] = int(details.get("text_tokens", 0) or 0)
                usage_summary["reasoning_tokens"] = int(details.get("reasoning_tokens", 0) or 0)
        choices = chunk.get("choices")
        if not isinstance(choices, list):
            continue
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            finish_reason = choice.get("finish_reason")
            if finish_reason is not None and str(finish_reason) not in finish_reasons:
                finish_reasons.append(str(finish_reason))
            delta = choice.get("delta")
            if not isinstance(delta, dict):
                continue
            for field in delta:
                delta_fields[str(field)] = delta_fields.get(str(field), 0) + 1
            content = delta.get("content")
            if "content" in delta:
                content_type = "null" if content is None else type(content).__name__
                content_value_types[content_type] = content_value_types.get(content_type, 0) + 1
            if isinstance(content, str) and content:
                summary["content_chunks"] += 1
                summary["content_characters"] += len(content)
            for field in ("reasoning_content", "reasoning", "thought"):
                reasoning = delta.get(field)
                if isinstance(reasoning, str) and reasoning:
                    summary["reasoning_chunks"] += 1
                    summary["reasoning_characters"] += len(reasoning)
            tool_calls = delta.get("tool_calls")
            if isinstance(tool_calls, list):
                summary["tool_call_chunks"] += sum(isinstance(call, dict) for call in tool_calls)
    return summary


def chat_completion_diagnostic(value: dict[str, Any]) -> dict[str, Any]:
    """Summarize a buffered Chat Completions response without retaining text."""
    choices = value.get("choices") if isinstance(value.get("choices"), list) else []
    choice = choices[0] if choices and isinstance(choices[0], dict) else {}
    message = choice.get("message") if isinstance(choice.get("message"), dict) else {}
    content = _text(message.get("content", ""))
    reasoning = _reasoning_text(
        next((message[field] for field in ("reasoning_content", "reasoning", "thought") if field in message), "")
    )
    usage = _usage(value.get("usage"))
    return {
        "response_mode": "json",
        "content_value_type": type(message.get("content")).__name__ if "content" in message else "missing",
        "message_fields": sorted(str(key) for key in message.keys()),
        "content_characters": len(content),
        "reasoning_characters": len(reasoning),
        "tool_calls": len(message.get("tool_calls") or []) if isinstance(message.get("tool_calls"), list) else 0,
        "finish_reasons": [str(choice.get("finish_reason"))] if choice.get("finish_reason") is not None else [],
        "usage": usage,
    }


class _BridgeServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, bridge: "OpenAIProtocolBridge"):
        super().__init__(("127.0.0.1", 0), _BridgeHandler)
        self.bridge = bridge


class _BridgeHandler(BaseHTTPRequestHandler):
    server: _BridgeServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _json(self, status: int, value: dict[str, Any]) -> None:
        payload = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        self._json(200, {"ok": True, "bridge": "camact-openai-protocol"})

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            value = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._json(400, {"type": "error", "error": {"type": "invalid_request_error", "message": str(exc)}})
            return
        if self.path.rstrip("/").endswith("count_tokens"):
            estimate = max(1, len(json.dumps(value, ensure_ascii=False)) // 4)
            self._json(200, {"input_tokens": estimate})
            return
        if "messages" not in self.path:
            self._json(404, {"type": "error", "error": {"type": "not_found_error", "message": "unknown endpoint"}})
            return
        self.server.bridge.handle_messages(self, value)


def _response_models(raw: bytes, content_type: str) -> set[str]:
    """Extract only model identifiers explicitly returned by the upstream."""
    values: list[Any] = []
    if "text/event-stream" in content_type.casefold():
        for line in raw.splitlines():
            if not line.startswith(b"data:"):
                continue
            try:
                values.append(json.loads(line[5:].strip().decode("utf-8")))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
    else:
        try:
            values.append(json.loads(raw.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass

    models: set[str] = set()
    for value in values:
        if not isinstance(value, dict):
            continue
        candidates = [value.get("model")]
        message = value.get("message")
        if isinstance(message, dict):
            candidates.append(message.get("model"))
        for candidate in candidates:
            if candidate:
                models.add(str(candidate))
    return models


class _TransparentProxyHandler(BaseHTTPRequestHandler):
    server: "_TransparentProxyServer"  # type: ignore[assignment]

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        self.server.proxy.forward(self)


class _TransparentProxyServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, proxy: "AnthropicTelemetryProxy"):
        self.proxy = proxy
        super().__init__(("127.0.0.1", 0), _TransparentProxyHandler)


class ProviderReadTimeout(TimeoutError):
    def __init__(self, body: bytes):
        super().__init__("upstream request exceeded its total response deadline")
        self.body = body


def _read_anthropic_response(response, deadline: float) -> bytes:
    """Keep upstream bytes, stopping at SSE completion or the absolute cap.

    A socket idle timeout alone permits an endless stream of heartbeat pings.
    read1 avoids waiting for EOF after Anthropic's terminal event.
    """
    body = bytearray()
    pending = b""
    is_sse = "text/event-stream" in response.headers.get("Content-Type", "")
    stream = getattr(response, "fp", response)
    stream = getattr(stream, "fp", stream)
    socket = getattr(getattr(stream, "raw", stream), "_sock", None)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProviderReadTimeout(bytes(body))
        # HTTPResponse may close this socket after consuming Content-Length.
        if socket is not None and socket.fileno() >= 0:
            socket.settimeout(remaining)
        try:
            chunk = response.read1(65536)
        except (TimeoutError, OSError) as exc:
            if isinstance(exc, TimeoutError) or "timed out" in str(exc).casefold():
                raise ProviderReadTimeout(bytes(body)) from exc
            raise
        if not chunk:
            return bytes(body)
        body.extend(chunk)
        if is_sse:
            pending += chunk
            normalized = pending.replace(b"\r\n", b"\n")
            while b"\n\n" in normalized:
                event, normalized = normalized.split(b"\n\n", 1)
                for line in event.splitlines():
                    if line.startswith(b"data:"):
                        try:
                            value = json.loads(line[5:].strip())
                        except ValueError:
                            continue
                        if isinstance(value, dict) and value.get("type") in {"message_stop", "error"}:
                            return bytes(body)
            pending = normalized


class AnthropicTelemetryProxy(AbstractContextManager["AnthropicTelemetryProxy"]):
    """Byte-preserving Anthropic proxy that adds timing only and never retries."""

    def __init__(self, *, base_url: str, api_key: str, model: str, timeout: float, task_key: str | None = None):
        self.token_collector = token_collector()
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.task_key = task_key
        self.server: _TransparentProxyServer | None = None
        self.thread: threading.Thread | None = None
        self.lock = threading.Lock()
        self.request_count = 0
        self.success_count = 0
        self.last_error: str | None = None
        self._observed_models: set[str] = set()
        self._attempt_events: list[dict[str, Any]] = []
        self._fingerprints: dict[str, dict[str, Any]] = {}
        self._model_turn = 0

    @property
    def local_base_url(self) -> str:
        if not self.server:
            raise RuntimeError("telemetry proxy is not running")
        return f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self) -> "AnthropicTelemetryProxy":
        self.server = _TransparentProxyServer(self)
        self.thread = threading.Thread(target=self.server.serve_forever, name="camact-anthropic-telemetry", daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *_args: Any) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=2)
        self.server = None
        self.thread = None
        if self.token_collector:
            self.token_collector.reconcile(sum(e.get("component") == "agent_model" for e in self._attempt_events),
                                           source="claude_anthropic_attempt_events")

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "enabled": True,
                "measurement_only": True,
                "source_protocol": "anthropic-messages",
                "target_protocol": "anthropic-messages",
                "target_base_url": self.base_url,
                "target_model": self.model,
                "request_count": self.request_count,
                "success_count": self.success_count,
                "request_attempts": 1,
                "last_error": self.last_error,
                "api_key_persisted": False,
                "observed_models": sorted(self._observed_models),
                "attempt_events": copy.deepcopy(self._attempt_events),
            }

    def _target_url(self, path: str) -> str:
        incoming = urllib.parse.urlsplit(path)
        suffix = incoming.path
        base_path = urllib.parse.urlsplit(self.base_url).path.rstrip("/")
        if base_path.endswith("/v1") and suffix.startswith("/v1/"):
            suffix = suffix[3:]
        query = f"?{incoming.query}" if incoming.query else ""
        return f"{self.base_url}{suffix}{query}"

    def forward(self, handler: _TransparentProxyHandler) -> None:
        size = int(handler.headers.get("Content-Length", "0") or 0)
        body = handler.rfile.read(size)
        fingerprint = hashlib.sha256(handler.path.encode("utf-8") + b"\0" + body).hexdigest()
        is_model_request = "messages" in handler.path and "count_tokens" not in handler.path
        with self.lock:
            previous = self._fingerprints.get(fingerprint)
            if is_model_request and previous and previous.get("failed"):
                model_turn = previous["model_turn"]
                retry_index = int(previous.get("retry_index", 0)) + 1
            elif is_model_request:
                self._model_turn += 1
                model_turn = self._model_turn
                retry_index = 0
            else:
                model_turn = None
                retry_index = 0
            self.request_count += 1
            request_id = f"req_{uuid.uuid4().hex}"

        configured_model = self.model
        try:
            request_json = json.loads(body.decode("utf-8"))
            if isinstance(request_json, dict) and request_json.get("model"):
                configured_model = str(request_json["model"])
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass

        headers = {
            key: value for key, value in handler.headers.items()
            if key.casefold() not in {"host", "content-length", "connection", "authorization", "x-api-key"}
        }
        headers["x-api-key"] = self.api_key
        headers["Authorization"] = f"Bearer {self.api_key}"
        started_at = datetime.now(timezone.utc).isoformat()
        started = time.monotonic()
        status_code = 502
        response_body = b""
        response_headers: list[tuple[str, str]] = []
        error: str | None = None
        timeout = False
        wire_body, wire_headers, wire_metadata = compress_request(body, headers)
        try:
            request = urllib.request.Request(self._target_url(handler.path), data=wire_body, headers=wire_headers, method="POST")
            try:
                response = observe_open(self.token_collector, urllib.request.urlopen, request, timeout=self.timeout,
                    metadata={"retry_attempt": retry_index, "agent_turn_id": model_turn})
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                status_code = int(getattr(response, "status", None) or getattr(response, "code", 502))
                response_headers = list(response.headers.items())
                response_body = _read_anthropic_response(response, started + self.timeout)
            if status_code >= 400:
                error = f"HTTP {status_code}"
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            timeout = isinstance(exc, TimeoutError) or "timed out" in str(exc).casefold()
            status_code = 504 if timeout else 502
            error_body = json.dumps({"type": "error", "error": {"type": "api_error", "message": error}}).encode("utf-8")
            partial = getattr(exc, "body", b"")
            prior_type = next((v for k, v in response_headers if k.casefold() == "content-type"), "")
            if partial and "text/event-stream" in prior_type:
                response_body = partial + b"\n\nevent: error\ndata: " + error_body + b"\n\n"
                response_headers = [("Content-Type", "text/event-stream")]
            else:
                response_body = error_body
                response_headers = [("Content-Type", "application/json")]

        content_type = next((value for key, value in response_headers if key.casefold() == "content-type"), "")
        upstream_models = _response_models(response_body, content_type)
        succeeded = 200 <= status_code < 300 and error is None
        event = {
            **wire_metadata,
            "schema_version": "camact.provider_attempt.v1",
            "request_id": request_id,
            "task": self.task_key,
            "component": "agent_model" if is_model_request else "provider_utility",
            "model_turn": model_turn,
            "attempt_index": retry_index + 1,
            "retry_index": retry_index,
            "started_at": started_at,
            "ended_at": datetime.now(timezone.utc).isoformat(),
            "latency_seconds": round(time.monotonic() - started, 6),
            "status": "succeeded" if succeeded else ("timeout" if timeout else "error"),
            "http_status": status_code,
            "exception_type": error.split(":", 1)[0] if error and not error.startswith("HTTP ") else None,
            "exception": error,
            "timeout": timeout,
            "requested_model": self.model,
            "configured_model": configured_model,
            "upstream_model": sorted(upstream_models)[0] if len(upstream_models) == 1 else None,
        }
        with self.lock:
            self._attempt_events.append(event)
            self._observed_models.update(upstream_models)
            self._fingerprints[fingerprint] = {"failed": not succeeded, "model_turn": model_turn, "retry_index": retry_index}
            if succeeded:
                self.success_count += 1
                self.last_error = None
            else:
                self.last_error = error

        handler.send_response(status_code)
        for key, value in response_headers:
            if key.casefold() not in {"content-length", "transfer-encoding", "connection"}:
                handler.send_header(key, value)
        handler.send_header("Content-Length", str(len(response_body)))
        handler.end_headers()
        try:
            handler.wfile.write(response_body)
        except (BrokenPipeError, ConnectionResetError):
            pass


class OpenAIProtocolBridge(AbstractContextManager["OpenAIProtocolBridge"]):
    """Expose Anthropic Messages locally and forward as OpenAI streaming chat."""

    def __init__(self, *, base_url: str, api_key: str, model: str, timeout: float, request_attempts: int = 4, task_key: str | None = None):
        self.token_collector = token_collector()
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.request_attempts = max(1, int(request_attempts))
        self.task_key = task_key
        self.server: _BridgeServer | None = None
        self.thread: threading.Thread | None = None
        self.lock = threading.Lock()
        self.request_count = 0
        self.success_count = 0
        self.last_error: str | None = None
        self._authorization_diagnostic: dict[str, Any] | None = None
        self._stream_diagnostics: list[dict[str, Any]] = []
        self._observed_models: set[str] = set()
        self._attempt_events: list[dict[str, Any]] = []

    @property
    def local_base_url(self) -> str:
        if not self.server:
            raise RuntimeError("protocol bridge is not running")
        return f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self) -> "OpenAIProtocolBridge":
        self.server = _BridgeServer(self)
        self.thread = threading.Thread(target=self.server.serve_forever, name="camact-provider-bridge", daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=2)
        self.server = None
        self.thread = None
        if self.token_collector:
            self.token_collector.reconcile(self.request_count, source="claude_bridge_physical_request_count")

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "enabled": True,
                "source_protocol": "anthropic-messages",
                "target_protocol": "openai-responses-stream" if uses_responses_api(self.base_url) else "openai-chat-completions-buffered",
                "target_base_url": self.base_url,
                "target_endpoint": responses_url(self.base_url) if uses_responses_api(self.base_url) else chat_completions_url(self.base_url),
                "target_model": self.model,
                "request_count": self.request_count,
                "success_count": self.success_count,
                "request_attempts": self.request_attempts,
                "last_error": self.last_error,
                "api_key_persisted": False,
                "observed_models": sorted(self._observed_models),
                "stream_diagnostics": copy.deepcopy(self._stream_diagnostics),
                "attempt_events": copy.deepcopy(self._attempt_events),
            }

    def _record_attempt(
        self, *, request_id: str, model_turn: int, attempt: int, started_at: str,
        started: float, status: str, http_status: int | None, error: str | None,
        upstream_model: str | None = None,
        wire_metadata: dict[str, Any] | None = None,
    ) -> None:
        timeout = bool(error and "timed out" in error.casefold())
        with self.lock:
            self._attempt_events.append({
                **(wire_metadata or {}),
                "schema_version": "camact.provider_attempt.v1",
                "request_id": request_id,
                "task": self.task_key,
                "component": "agent_model",
                "model_turn": model_turn,
                "attempt_index": attempt,
                "retry_index": attempt - 1,
                "started_at": started_at,
                "ended_at": datetime.now(timezone.utc).isoformat(),
                "latency_seconds": round(time.monotonic() - started, 6),
                "status": "timeout" if timeout else status,
                "http_status": http_status,
                "exception_type": error.split(":", 1)[0] if error and not error.startswith("HTTP ") else None,
                "exception": error,
                "timeout": timeout,
                "requested_model": self.model,
                "configured_model": self.model,
                "upstream_model": upstream_model,
            })

    def authorization_diagnostic(self) -> dict[str, Any] | None:
        with self.lock:
            return copy.deepcopy(self._authorization_diagnostic)

    def _event(self, handler: _BridgeHandler, name: str, value: dict[str, Any]) -> None:
        payload = f"event: {name}\ndata: {json.dumps(value, ensure_ascii=False)}\n\n".encode("utf-8")
        handler.wfile.write(payload)
        handler.wfile.flush()

    def _error_event(self, handler: _BridgeHandler, message: str) -> None:
        self._event(handler, "error", {"type": "error", "error": {"type": "api_error", "message": message}})

    def handle_messages(self, handler: _BridgeHandler, value: dict[str, Any]) -> None:
        responses_mode = uses_responses_api(self.base_url)
        body = anthropic_to_responses(value, self.model) if responses_mode else anthropic_to_openai(value, self.model)
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        wire_payload, wire_headers, wire_metadata = compress_request(payload, {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream" if responses_mode else "application/json",
            "User-Agent": "CamAct-Claude-Code-Bridge/1.0",
        })
        endpoint = responses_url(self.base_url) if responses_mode else chat_completions_url(self.base_url)
        lines: list[bytes] | None = None
        completion: dict[str, Any] | None = None
        last_error = "upstream request failed"
        last_status = 502
        request_id = f"req_{uuid.uuid4().hex}"
        with self.lock:
            model_turn = 1 + sum(1 for item in self._attempt_events if item.get("status") == "succeeded")
        for attempt in range(1, self.request_attempts + 1):
            attempt_started_at = datetime.now(timezone.utc).isoformat()
            attempt_started = time.monotonic()
            attempt_status: int | None = None
            authorization_diagnostic = api_key_diagnostic(self.api_key)
            with self.lock:
                self._authorization_diagnostic = authorization_diagnostic
            request = urllib.request.Request(
                endpoint,
                data=wire_payload,
                headers=wire_headers,
                method="POST",
            )
            with self.lock:
                self.request_count += 1
            retryable = True
            try:
                with observe_open(self.token_collector, urllib.request.urlopen, request, timeout=self.timeout,
                                  metadata={"operation_id": request_id, "retry_attempt": attempt - 1,
                                            "agent_turn_id": model_turn}) as response:
                    attempt_status = int(getattr(response, "status", 200) or 200)
                    content_type = str(response.headers.get("Content-Type") or "").casefold()
                    if responses_mode or "text/event-stream" in content_type:
                        candidate_lines = list(response)
                        complete, stream_error = _completed_stream(candidate_lines, responses_mode=responses_mode)
                        if complete:
                            lines = candidate_lines
                            if not responses_mode:
                                diagnostic = chat_stream_diagnostic(candidate_lines)
                                with self.lock:
                                    self._stream_diagnostics.append(diagnostic)
                            self._record_attempt(request_id=request_id, model_turn=model_turn, attempt=attempt, started_at=attempt_started_at, started=attempt_started, status="succeeded", http_status=attempt_status, error=None, wire_metadata=wire_metadata)
                            break
                        last_error = stream_error or "upstream stream did not complete"
                    else:
                        raw = response.read()
                        try:
                            candidate = json.loads(raw.decode("utf-8", errors="replace"))
                        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                            last_error = f"invalid upstream JSON response: {exc}"
                            retryable = False
                        else:
                            if isinstance(candidate, dict) and isinstance(candidate.get("error"), dict):
                                last_error = str(candidate["error"].get("message") or "upstream error")
                                retryable = False
                            elif not isinstance(candidate, dict) or not isinstance(candidate.get("choices"), list):
                                last_error = "unexpected upstream Chat Completions JSON response"
                                retryable = False
                            else:
                                completion = candidate
                                if candidate.get("model"):
                                    with self.lock:
                                        self._observed_models.add(str(candidate["model"]))
                                diagnostic = chat_completion_diagnostic(candidate)
                                with self.lock:
                                    self._stream_diagnostics.append(diagnostic)
                                self._record_attempt(request_id=request_id, model_turn=model_turn, attempt=attempt, started_at=attempt_started_at, started=attempt_started, status="succeeded", http_status=attempt_status, error=None, upstream_model=str(candidate.get("model")) if candidate.get("model") else None, wire_metadata=wire_metadata)
                                break
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace")[:2000]
                last_status = exc.code
                attempt_status = exc.code
                last_error = f"HTTP {exc.code}: {detail}"
                retryable = exc.code in {408, 409, 429} or exc.code >= 500
            except (OSError, TimeoutError, urllib.error.URLError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
            with self.lock:
                self.last_error = last_error
            self._record_attempt(request_id=request_id, model_turn=model_turn, attempt=attempt, started_at=attempt_started_at, started=attempt_started, status="error", http_status=attempt_status, error=last_error, wire_metadata=wire_metadata)
            if not retryable or attempt >= self.request_attempts:
                break
            time.sleep(min(2.0, 0.25 * attempt))

        if lines is None and completion is None:
            self._json_error(handler, last_status, last_error)
            return

        handler.send_response(200)
        handler.send_header("Content-Type", "text/event-stream")
        handler.send_header("Cache-Control", "no-cache")
        handler.send_header("Connection", "close")
        handler.end_headers()

        if responses_mode:
            self._relay_responses(handler, lines)
            return

        if completion is not None:
            self._relay_chat_completion(handler, completion)
            return

        message_id = f"msg_{uuid.uuid4().hex}"
        started = False
        stopped = False
        blocks: dict[tuple[str, int], int] = {}
        block_count = 0
        finish_reason: str | None = None
        usage: dict[str, int] = {"input_tokens": 0, "output_tokens": 0}

        def start_message(remote_model: str | None = None) -> None:
            nonlocal started
            if started:
                return
            started = True
            self._event(handler, "message_start", {
                "type": "message_start",
                "message": {
                    "id": message_id,
                    "type": "message",
                    "role": "assistant",
                    "content": [],
                    "model": remote_model or self.model,
                    "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {"input_tokens": 0, "output_tokens": 0},
                },
            })

        try:
            for raw in lines:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if not data or data == "[DONE]":
                        continue
                    try:
                        chunk = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(chunk.get("error"), dict):
                        start_message()
                        self._error_event(handler, str(chunk["error"].get("message") or "upstream error"))
                        stopped = True
                        with self.lock:
                            self.last_error = str(chunk["error"].get("message") or "upstream error")
                        break
                    start_message(str(chunk.get("model") or self.model))
                    if chunk.get("model"):
                        with self.lock:
                            self._observed_models.add(str(chunk["model"]))
                    if isinstance(chunk.get("usage"), dict):
                        usage = _usage(chunk["usage"])
                    choices = chunk.get("choices")
                    if not isinstance(choices, list) or not choices:
                        continue
                    choice = choices[0] if isinstance(choices[0], dict) else {}
                    finish_reason = choice.get("finish_reason") or finish_reason
                    delta = choice.get("delta") if isinstance(choice.get("delta"), dict) else {}
                    reasoning = next(
                        (
                            delta[field]
                            for field in ("reasoning_content", "reasoning", "thought")
                            if isinstance(delta.get(field), str) and delta[field]
                        ),
                        None,
                    )
                    if reasoning is not None:
                        key = ("thinking", 0)
                        if key not in blocks:
                            blocks[key] = block_count
                            block_count += 1
                            self._event(handler, "content_block_start", {
                                "type": "content_block_start", "index": blocks[key],
                                "content_block": {"type": "thinking", "thinking": ""},
                            })
                        self._event(handler, "content_block_delta", {
                            "type": "content_block_delta", "index": blocks[key],
                            "delta": {"type": "thinking_delta", "thinking": reasoning},
                        })
                    content = delta.get("content")
                    if isinstance(content, str) and content:
                        key = ("text", 0)
                        if key not in blocks:
                            blocks[key] = block_count
                            block_count += 1
                            self._event(handler, "content_block_start", {
                                "type": "content_block_start", "index": blocks[key],
                                "content_block": {"type": "text", "text": ""},
                            })
                        self._event(handler, "content_block_delta", {
                            "type": "content_block_delta", "index": blocks[key],
                            "delta": {"type": "text_delta", "text": content},
                        })
                    for call in delta.get("tool_calls") or []:
                        if not isinstance(call, dict):
                            continue
                        remote_index = int(call.get("index", 0) or 0)
                        key = ("tool", remote_index)
                        function = call.get("function") if isinstance(call.get("function"), dict) else {}
                        if key not in blocks:
                            blocks[key] = block_count
                            block_count += 1
                            self._event(handler, "content_block_start", {
                                "type": "content_block_start", "index": blocks[key],
                                "content_block": {
                                    "type": "tool_use",
                                    "id": str(call.get("id") or f"toolu_{uuid.uuid4().hex}"),
                                    "name": str(function.get("name") or ""),
                                    "input": {},
                                },
                            })
                        arguments = function.get("arguments")
                        if isinstance(arguments, str) and arguments:
                            self._event(handler, "content_block_delta", {
                                "type": "content_block_delta", "index": blocks[key],
                                "delta": {"type": "input_json_delta", "partial_json": arguments},
                            })
            if not started:
                start_message()
            if not stopped:
                if not blocks:
                    blocks[("text", 0)] = 0
                    self._event(handler, "content_block_start", {
                        "type": "content_block_start", "index": 0,
                        "content_block": {"type": "text", "text": ""},
                    })
                for index in sorted(blocks.values()):
                    self._event(handler, "content_block_stop", {"type": "content_block_stop", "index": index})
                stop_reason = {
                    "tool_calls": "tool_use", "stop": "end_turn", "length": "max_tokens",
                    "content_filter": "end_turn",
                }.get(str(finish_reason), "end_turn")
                self._event(handler, "message_delta", {
                    "type": "message_delta",
                    "delta": {"stop_reason": stop_reason, "stop_sequence": None},
                    "usage": {"output_tokens": usage["output_tokens"]},
                })
                self._event(handler, "message_stop", {"type": "message_stop"})
                with self.lock:
                    self.success_count += 1
                    self.last_error = None
        except (BrokenPipeError, ConnectionResetError):
            return
        except (OSError, TimeoutError) as exc:
            with self.lock:
                self.last_error = f"{type(exc).__name__}: {exc}"
            if not stopped:
                try:
                    self._error_event(handler, self.last_error)
                except (BrokenPipeError, ConnectionResetError):
                    pass

    def _relay_chat_completion(self, handler: _BridgeHandler, response: dict[str, Any]) -> None:
        """Emit Anthropic SSE events from one complete Chat Completions response."""
        message_id = f"msg_{uuid.uuid4().hex}"
        choices = response.get("choices") if isinstance(response.get("choices"), list) else []
        choice = choices[0] if choices and isinstance(choices[0], dict) else {}
        message = choice.get("message") if isinstance(choice.get("message"), dict) else {}
        finish_reason = str(choice.get("finish_reason") or "stop")
        usage = _usage(response.get("usage"))
        if response.get("model"):
            with self.lock:
                self._observed_models.add(str(response["model"]))
        self._event(handler, "message_start", {
            "type": "message_start",
            "message": {
                "id": message_id,
                "type": "message",
                "role": "assistant",
                "content": [],
                "model": str(response.get("model") or self.model),
                "stop_reason": None,
                "stop_sequence": None,
                "usage": {"input_tokens": usage["input_tokens"], "output_tokens": 0},
            },
        })
        block_index = 0
        reasoning = _reasoning_text(
            next((message[field] for field in ("reasoning_content", "reasoning", "thought") if field in message), "")
        )
        if reasoning:
            self._event(handler, "content_block_start", {
                "type": "content_block_start", "index": block_index,
                "content_block": {"type": "thinking", "thinking": ""},
            })
            self._event(handler, "content_block_delta", {
                "type": "content_block_delta", "index": block_index,
                "delta": {"type": "thinking_delta", "thinking": reasoning},
            })
            self._event(handler, "content_block_stop", {"type": "content_block_stop", "index": block_index})
            block_index += 1

        content = _text(message.get("content", ""))
        if content:
            self._event(handler, "content_block_start", {
                "type": "content_block_start", "index": block_index,
                "content_block": {"type": "text", "text": ""},
            })
            self._event(handler, "content_block_delta", {
                "type": "content_block_delta", "index": block_index,
                "delta": {"type": "text_delta", "text": content},
            })
            self._event(handler, "content_block_stop", {"type": "content_block_stop", "index": block_index})
            block_index += 1

        tool_calls = message.get("tool_calls") if isinstance(message.get("tool_calls"), list) else []
        for index, call in enumerate(tool_calls):
            if not isinstance(call, dict):
                continue
            function = call.get("function") if isinstance(call.get("function"), dict) else {}
            arguments = function.get("arguments", {})
            if isinstance(arguments, (dict, list)):
                arguments = json.dumps(arguments, ensure_ascii=False)
            elif not isinstance(arguments, str):
                arguments = str(arguments or "")
            self._event(handler, "content_block_start", {
                "type": "content_block_start", "index": block_index,
                "content_block": {
                    "type": "tool_use",
                    "id": str(call.get("id") or f"toolu_{uuid.uuid4().hex}"),
                    "name": str(function.get("name") or ""),
                    "input": {},
                },
            })
            if arguments:
                self._event(handler, "content_block_delta", {
                    "type": "content_block_delta", "index": block_index,
                    "delta": {"type": "input_json_delta", "partial_json": arguments},
                })
            self._event(handler, "content_block_stop", {"type": "content_block_stop", "index": block_index})
            block_index += 1

        if block_index == 0:
            self._event(handler, "content_block_start", {
                "type": "content_block_start", "index": 0,
                "content_block": {"type": "text", "text": ""},
            })
            self._event(handler, "content_block_stop", {"type": "content_block_stop", "index": 0})
        stop_reason = {
            "tool_calls": "tool_use", "function_call": "tool_use",
            "length": "max_tokens", "content_filter": "end_turn",
        }.get(finish_reason, "end_turn")
        self._event(handler, "message_delta", {
            "type": "message_delta",
            "delta": {"stop_reason": stop_reason, "stop_sequence": None},
            "usage": {"output_tokens": usage["output_tokens"]},
        })
        self._event(handler, "message_stop", {"type": "message_stop"})
        with self.lock:
            self.success_count += 1
            self.last_error = None

    def _relay_responses(self, handler: _BridgeHandler, lines: list[bytes]) -> None:
        message_id = f"msg_{uuid.uuid4().hex}"
        started = False
        completed = False
        blocks: dict[tuple[str, int], int] = {}
        block_count = 0
        tool_seen = False
        model = self.model

        def start_message() -> None:
            nonlocal started
            if started:
                return
            started = True
            self._event(handler, "message_start", {
                "type": "message_start",
                "message": {
                    "id": message_id, "type": "message", "role": "assistant", "content": [],
                    "model": model, "stop_reason": None, "stop_sequence": None,
                    "usage": {"input_tokens": 0, "output_tokens": 0},
                },
            })

        def start_text(output_index: int) -> int:
            nonlocal block_count
            key = ("text", output_index)
            if key not in blocks:
                blocks[key] = block_count
                block_count += 1
                self._event(handler, "content_block_start", {
                    "type": "content_block_start", "index": blocks[key],
                    "content_block": {"type": "text", "text": ""},
                })
            return blocks[key]

        def start_tool(output_index: int, item: dict[str, Any]) -> int:
            nonlocal block_count, tool_seen
            tool_seen = True
            key = ("tool", output_index)
            if key not in blocks:
                blocks[key] = block_count
                block_count += 1
                self._event(handler, "content_block_start", {
                    "type": "content_block_start", "index": blocks[key],
                    "content_block": {
                        "type": "tool_use",
                        "id": str(item.get("call_id") or item.get("id") or f"toolu_{uuid.uuid4().hex}"),
                        "name": str(item.get("name") or ""),
                        "input": {},
                    },
                })
            return blocks[key]

        try:
            for raw in lines:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if not data or data == "[DONE]":
                        continue
                    try:
                        event = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    event_type = str(event.get("type") or "")
                    response_value = event.get("response") if isinstance(event.get("response"), dict) else {}
                    if response_value.get("model"):
                        model = str(response_value["model"])
                        with self.lock:
                            self._observed_models.add(model)
                    if event_type in {"error", "response.failed", "response.incomplete"}:
                        error = event.get("error") or response_value.get("error") or response_value.get("incomplete_details") or event_type
                        message = error.get("message") if isinstance(error, dict) else str(error)
                        start_message()
                        self._error_event(handler, message or event_type)
                        with self.lock:
                            self.last_error = message or event_type
                        return
                    if event_type == "response.created":
                        start_message()
                    elif event_type == "response.output_item.added":
                        start_message()
                        item = event.get("item") if isinstance(event.get("item"), dict) else {}
                        if item.get("type") == "function_call":
                            start_tool(int(event.get("output_index", 0) or 0), item)
                    elif event_type == "response.output_text.delta":
                        start_message()
                        index = start_text(int(event.get("output_index", 0) or 0))
                        delta = str(event.get("delta") or "")
                        if delta:
                            self._event(handler, "content_block_delta", {
                                "type": "content_block_delta", "index": index,
                                "delta": {"type": "text_delta", "text": delta},
                            })
                    elif event_type == "response.function_call_arguments.delta":
                        start_message()
                        output_index = int(event.get("output_index", 0) or 0)
                        item = event.get("item") if isinstance(event.get("item"), dict) else {}
                        index = start_tool(output_index, item)
                        delta = str(event.get("delta") or "")
                        if delta:
                            self._event(handler, "content_block_delta", {
                                "type": "content_block_delta", "index": index,
                                "delta": {"type": "input_json_delta", "partial_json": delta},
                            })
                    elif event_type == "response.completed":
                        start_message()
                        usage = _usage(response_value.get("usage"))
                        if not blocks:
                            start_text(0)
                        for index in sorted(blocks.values()):
                            self._event(handler, "content_block_stop", {"type": "content_block_stop", "index": index})
                        self._event(handler, "message_delta", {
                            "type": "message_delta",
                            "delta": {"stop_reason": "tool_use" if tool_seen else "end_turn", "stop_sequence": None},
                            "usage": {"output_tokens": usage["output_tokens"]},
                        })
                        self._event(handler, "message_stop", {"type": "message_stop"})
                        completed = True
                        with self.lock:
                            self.success_count += 1
                            self.last_error = None
                        return
            if not completed:
                start_message()
                message = "upstream Responses stream ended before response.completed"
                with self.lock:
                    self.last_error = message
                self._error_event(handler, message)
        except (BrokenPipeError, ConnectionResetError):
            return
        except (OSError, TimeoutError) as exc:
            with self.lock:
                self.last_error = f"{type(exc).__name__}: {exc}"
            try:
                self._error_event(handler, self.last_error)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _json_error(self, handler: _BridgeHandler, status: int, message: str) -> None:
        safe_status = status if 400 <= status <= 599 else 502
        handler._json(safe_status, {"type": "error", "error": {"type": "api_error", "message": message}})
