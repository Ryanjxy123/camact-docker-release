"""Bounded multi-protocol relay, official CLI retains requests and retries.

Shares the existing SandboxTransport's Unix server/adapter protocol. Credentials
are injected host-side. Wire bodies are saved without authorization headers.
"""
from __future__ import annotations
import gzip
import hashlib
import http.client
import http.server
import io
import json
import os
from pathlib import Path
import re
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from claude_code_harness.sandbox_transport import UnixServer
from claude_code_harness.execution_limits import completed_generation, provider_failure, GenerationBudget
from harness.camact_token_usage_v1.collector import current as token_collector
from harness.camact_token_usage_v1.http import observe_open
from harness.camact_token_usage_v1.native_identity import LOGICAL_HEADER_NAMES, PHYSICAL_HEADER_NAMES
from harness.camact_token_usage_v1.adapters import protocol_for, extract as extract_response
from benchmark.services.http_compression import compress_request, decoded_body

def files_unavailable(status, payload):
    """Cache only explicit endpoint/routing incompatibility, never arbitrary 400s."""
    try:
        error = json.loads(payload).get("error", {})
    except (ValueError, AttributeError):
        return None
    if not isinstance(error, dict):
        return None
    message = str(error.get("message", "")).casefold()
    if status == 405 or status == 404 and any(word in message for word in ("route", "endpoint", "url")):
        return "files_endpoint_unsupported"
    if (status == 400 and error.get("type") == "new_api_error"
            and any(word in message for word in ("模型名称不能为空", "model name is required", "model name cannot be empty"))):
        return "gateway_files_requires_model_routing"
    return None


def response_diagnostics(payload):
    """Non-scoring helper diagnostics; exact original wire remains in response.gz."""
    documents = []
    try:
        documents = [json.loads(payload)]
    except ValueError:
        for line in payload.decode(errors="replace").splitlines():
            if line.startswith("data:"):
                try:
                    documents.append(json.loads(line[5:]))
                except ValueError:
                    pass
    result = {"text_characters": 0, "thinking_characters": 0, "finish_reasons": [], "tool_ids": []}
    def visit(value):
        if isinstance(value, dict):
            for key in ("stop_reason", "finish_reason"):
                if value.get(key) is not None and value[key] not in result["finish_reasons"]:
                    result["finish_reasons"].append(value[key])
            if isinstance(value.get("text"), str):
                result["text_characters"] += len(value["text"])
            if isinstance(value.get("content"), str):
                result["text_characters"] += len(value["content"])
            if (value.get("type") == "response.output_text.delta" and
                    isinstance(value.get("delta"), str)):
                result["text_characters"] += len(value["delta"])
            for key in ("thinking", "reasoning_content"):
                if isinstance(value.get(key), str):
                    result["thinking_characters"] += len(value[key])
            # Tool schemas may themselves contain a property named "type"
            # whose value is an object. Diagnostics inspect arbitrary provider
            # JSON and must never interrupt otherwise successful wire capture.
            if value.get("type") in ("tool_use", "tool_result"):
                identifier = value.get("id") or value.get("tool_use_id")
                if identifier and identifier not in result["tool_ids"]:
                    result["tool_ids"].append(identifier)
            for child in value.values():
                if isinstance(child, (dict, list)):
                    visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    visit(documents)
    result["empty_text"] = result["text_characters"] == 0
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


class NativeConversationStopped(RuntimeError):
    """A real Simulator STOP already ended the current task."""


class DeferredErrorResponse:
    """Stream successful responses unchanged; hold errors for bounded recovery."""
    def __init__(self, handler):
        self.handler = handler
        self.headers_out = []
        self.wfile = handler.wfile
        self.status = None

    def __getattr__(self, name):
        return getattr(self.handler, name)

    def send_response(self, status):
        self.status = status
        if status >= 400:
            self.wfile = io.BytesIO()
        else:
            self.handler.send_response(status)

    def send_header(self, name, value):
        if self.status >= 400:
            self.headers_out.append((name, value))
        else:
            self.handler.send_header(name, value)

    def end_headers(self):
        if self.status < 400:
            self.handler.end_headers()

    def deliver_error(self):
        if self.status is not None and self.status >= 400:
            self.handler.send_response(self.status)
            for name, value in self.headers_out:
                self.handler.send_header(name, value)
            self.handler.end_headers()
            self.handler.wfile.write(self.wfile.getvalue())

def redact(text, secrets=()):
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    text = re.sub(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/-]+=*", r"\1[REDACTED]", text)
    return text

def response_usage(payload):
    """Retain provider-reported usage; do not invent cross-provider token totals."""
    documents = []
    try:
        documents.append(json.loads(payload))
    except (ValueError, UnicodeDecodeError):
        for line in payload.decode("utf-8", errors="replace").splitlines():
            if line.startswith("data:"):
                try:
                    documents.append(json.loads(line[5:]))
                except ValueError:
                    pass
    usage = {}
    for doc in documents:
        if not isinstance(doc, dict):
            continue
        for container in (doc, doc.get("message"), doc.get("response")):
            if isinstance(container, dict):
                found = container.get("usage", container.get("usageMetadata"))
                if isinstance(found, dict):
                    usage.update(found)
    return usage

def allowed(protocol, method, path):
    route = urllib.parse.urlsplit(path).path
    if protocol == "openai-responses":
        return method == "POST" and route in {"/v1/responses", "/v1/responses/compact"}
    if protocol == "openai-chat":
        return method == "POST" and route == "/v1/chat/completions"
    if protocol in {"anthropic-messages", "deepseek-messages"}:
        if method == "POST" and route in {"/v1/messages", "/v1/messages/count_tokens"}:
            return True
        return protocol == "deepseek-messages" and method in {"GET", "POST", "DELETE"} and bool(re.fullmatch(r"/v1/files(?:/[A-Za-z0-9_-]+)?", route))
    return False

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def process(self):
        owner = self.server.owner
        data = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.server.kind == "adapter":
            try:
                if self.path != "/command" or self.command != "POST":
                    raise ValueError("route denied")
                response = owner.runtime.command(json.loads(data))
                status = 200 if response.get("ok") else 400
            except Exception as exc:
                response, status = {"ok": False, "error": str(exc)}, 400
            body = json.dumps(response).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            owner.forward(self, data)

    do_POST = do_GET = do_DELETE = process

class Transport:
    def __init__(self, runtime, provider, log_dir: Path, limits, *, offline=False, harness_name=None):
        self.runtime, self.provider, self.log_dir, self.limits = runtime, provider, log_dir, limits
        self.offline = offline
        self.harness_name = harness_name
        self.servers = []
        self.records = []
        self.lock = threading.RLock()
        self.forward_condition = threading.Condition(self.lock)
        self.active_forwards = 0
        self.generations = set()
        self.stop_reason = None
        self.token_collector = token_collector()
        self.budget = GenerationBudget(runtime)
        self.deadline = time.monotonic() + limits.get("task_timeout_seconds", 1800)
        self.consecutive_upstream_errors = 0
        self.upstream_errors = 0
        self.retry_count = 0
        self.failure_limit = limits.get("request_attempts") or limits.get("requested_retry_attempts") or 4
        self.incoming_http_requests = 0
        self.file_api_unavailable = None  # This Attempt/provider only; never cross-Session.

    def __enter__(self):
        # A local deployment may confine sockets to its authorized filesystem.
        self.temp = tempfile.TemporaryDirectory(prefix="camact-multi-", dir=os.environ.get("CAMACT_TRANSPORT_TMPDIR", "/tmp"))
        self.path = Path(self.temp.name)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        for kind in ("adapter", "provider"):
            server = UnixServer(str(self.path / (kind + ".sock")), Handler)
            server.kind, server.owner = kind, self
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.servers.append((server, thread))
        return self

    def __exit__(self, *_):
        for server, thread in self.servers:
            server.shutdown()
            server.server_close()
            thread.join(5)
        # UnixServer uses daemon request threads. A CLI may finish while an
        # abandoned auxiliary response still carries real provider usage.
        # Keep capture/Collector alive within the original task deadline.
        with self.forward_condition:
            while self.active_forwards:
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.forward_condition.wait(min(remaining, .1))
        self.temp.cleanup()
        if self.token_collector:
            self.token_collector.reconcile(sum(bool(r.get("token_model_dispatched")) for r in self.records),
                                           source="native_relay_dispatched_requests")

    def forward(self, handler, body):
        with self.forward_condition:
            self.active_forwards += 1
        try:
            return self._forward_with_retries(handler, body)
        finally:
            with self.forward_condition:
                self.active_forwards -= 1
                self.forward_condition.notify_all()

    def _forward_with_retries(self, handler, body):
        with self.lock:
            self.incoming_http_requests += 1
        # OpenClaw's installed local runner surfaces 503 without a native retry.
        # Recover only transport errors before any response reaches the CLI.
        # Other official CLIs keep ownership of their existing retry policy.
        if self.harness_name != "openclaw":
            return self._forward(handler, body)
        for attempt in range(self.failure_limit):
            downstream = DeferredErrorResponse(handler)
            record = self._forward(downstream, body, relay_retry_index=attempt)
            if (record.get("retryable") and not self.stop_reason and
                    attempt + 1 < self.failure_limit and not record.get("step_counted") and
                    downstream.status is not None and downstream.status >= 400):
                delay = min((2, 4, 8, 16)[min(attempt, 3)], max(0, self.deadline - time.monotonic()))
                if delay:
                    time.sleep(delay)
                continue
            downstream.deliver_error()
            break
        handler.close_connection = True
        return record

    def _forward(self, handler, body, *, relay_retry_index=0):
        record = {"sequence": None, "method": handler.command, "protocol": self.provider.get("protocol"),
                  "status": "error", "started_at": time.time(), "capture": "wire_http", "component": "unclassified",
                  "relay_retry_index": relay_retry_index}
        started = time.monotonic()
        responded = False
        key = os.environ.get(self.provider.get("api_key_env") or "", "")
        response_bytes = bytearray()
        is_generation = False
        stage = "local"
        with self.lock:
            record["sequence"] = len(self.records) + 1
            self.records.append(record)
        prefix = self.log_dir / f"request-{record['sequence']:05d}"
        try:
            if self.offline:
                raise ValueError("provider access disabled for offline validation")
            if not allowed(self.provider["protocol"], handler.command, handler.path):
                raise ValueError("provider route denied; WebSocket and unrelated endpoints are not forwarded")
            with self.runtime._lock:
                if getattr(self.runtime.environment, "simulator_stopped", False):
                    if self.stop_reason in {None, "simulator_stop", "agent_turn_limit_exceeded"}:
                        self.stop_reason = "simulator_stop"
                    raise NativeConversationStopped("Simulator ended the conversation")
                if self.stop_reason:
                    record["failure_type"] = self.stop_reason
                    if self.stop_reason == "agent_turn_limit_exceeded":
                        from benchmark.services.runtime_environment import AgentTurnLimit
                        raise AgentTurnLimit(self.stop_reason)
                    raise RuntimeError("Task transport is terminal: " + self.stop_reason)
                if time.monotonic() >= self.deadline:
                    self.stop_reason = record["failure_type"] = "task_timeout"
                    raise TimeoutError("Native task deadline expired")
            parts = urllib.parse.urlsplit(handler.path)
            query = [(k, v) for k, v in urllib.parse.parse_qsl(parts.query) if k.lower() not in {"key", "api_key", "token"}]
            record["route"] = parts.path + ("?" + urllib.parse.urlencode(query) if query else "")
            base = self.provider["base_url"].rstrip("/")
            route = parts.path
            if base.endswith("/v1") and route.startswith("/v1/"):
                route = route[3:]
            target = base + route + ("?" + urllib.parse.urlencode(query) if query else "")
            record["upstream_url"] = target
            headers = {k: v for k, v in handler.headers.items() if k.lower() in
                       {"content-type", "anthropic-version", "anthropic-beta", "accept", "content-encoding"}}
            protocol = self.provider["protocol"]
            if protocol in {"anthropic-messages", "deepseek-messages"}:
                headers["x-api-key"] = key
            else:
                headers["Authorization"] = "Bearer " + key
            if parts.path.startswith("/v1/files"):
                # Messages-compatible relays may authenticate Files through
                # the OpenAI bearer scheme. Keep x-api-key as well.
                headers["Authorization"] = "Bearer " + key
                record.update(component="file_api", counts_agent_step=False,
                              step_exemption="non_generation_route", token_model_dispatched=False,
                              file_api_backend="official_provider")
                record["request_content_type"] = handler.headers.get("Content-Type", "")
            decoded = decoded_body(body, headers)
            try:
                document = json.loads(decoded)
            except (ValueError, UnicodeDecodeError):
                document = None
            if not isinstance(document, dict) and not parts.path.startswith("/v1/files"):
                raise ValueError("Model and token-count requests require a JSON object")
            if isinstance(document, dict):
                # Verified in installed OpenCode 2.0.32 / DeepSeek 0.2.1-rc.2:
                # the title agent never
                # executes the user's task. No-tools alone is NOT an exemption.
                native_system = document.get("system", document.get("instructions", ""))
                if not native_system:
                    native_system = "\n".join(m["content"] for m in document.get("messages", [])
                        if isinstance(m, dict) and m.get("role") in {"system", "developer"} and isinstance(m.get("content"), str))
                if isinstance(native_system, list):
                    native_system = "\n".join(p.get("text", "") for p in native_system if isinstance(p, dict))
                title_prefix = {
                    "opencode": "You are a title generator. You output ONLY a thread title. Nothing else.",
                    "deepseek": "Create a concise title for an AI coding-assistant session from the supplied human messages.",
                }.get(self.harness_name)
                title_request = (bool(title_prefix) and not document.get("tools")
                    and isinstance(native_system, str) and native_system.startswith(title_prefix))
                record["counts_agent_step"] = not title_request
                if title_request:
                    record["step_exemption"] = f"verified_{self.harness_name}_title_generation"
                policy = getattr(self.runtime, "prompt_policy", None)
                if policy is not None and parts.path.endswith(("/messages", "/messages/count_tokens", "/responses", "/responses/compact", "/completions")):
                    document, metadata = policy.apply(document, protocol)
                    record["system_prompt_policy"] = metadata
                    body = json.dumps(document, ensure_ascii=False).encode()
                    headers.pop("Content-Encoding", None)
                    headers.pop("content-encoding", None)
                options = self.provider.get("parameters", {})
                permitted = {"temperature", "top_p", "seed", "thinking", "reasoning"}
                if not isinstance(options, dict) or set(options) - permitted:
                    record["failure_type"] = "provider_configuration_error"
                    raise ValueError("Unsupported native model parameters")
                record["model"] = document.get("model")
                if self.provider.get("model") and record["model"] and record["model"] != self.provider["model"]:
                    record["failure_type"] = "model_policy_violation"
                    raise ValueError("Unexpected model; model fallback is forbidden")
                record["has_tools"] = bool(document.get("tools"))
                is_generation = "count" not in parts.path and parts.path.endswith(("/messages", "/responses", "/completions"))
                if not is_generation:
                    record.update(counts_agent_step=False, step_exemption="non_generation_route")
                if is_generation:
                    if options:
                        document.update(options)
                        body = json.dumps(document, ensure_ascii=False).encode()
                        headers.pop("Content-Encoding", None)
                        headers.pop("content-encoding", None)
                    digest = hashlib.sha256(body).hexdigest()
                    with self.runtime._lock:
                        if getattr(self.runtime.environment, "simulator_stopped", False):
                            self.stop_reason = "simulator_stop"
                            raise NativeConversationStopped("Simulator ended the conversation")
                        if record["counts_agent_step"]:
                            self.budget.reserve(record, self.deadline)
                        record["generation_key"] = digest  # audit only; never a deduplication key
                        record["step_counted"] = False
                        record["component"] = "agent_with_tools" if document.get("tools") else "utility_generation"
                cap = self.limits.get("max_output_tokens")
                if cap and is_generation:
                    with gzip.open(str(prefix) + ".native-request.gz", "wb") as out:
                        out.write(decoded.replace(key.encode(), b"[REDACTED]") if key else decoded)
                    field = "max_output_tokens" if protocol == "openai-responses" else "max_tokens"
                    record["native_output_limit"] = document.get(field)
                    document[field] = cap
                    if field == "max_tokens":
                        document.pop("max_completion_tokens", None)
                    record["enforced_output_limit"] = cap
                    body = json.dumps(document, ensure_ascii=False).encode()
                    headers.pop("Content-Encoding", None)
                    headers.pop("content-encoding", None)
                if is_generation and protocol in {"anthropic-messages", "deepseek-messages"}:
                    thinking = document.get("thinking", {})
                    if cap and thinking.get("type") == "enabled" and thinking.get("budget_tokens", 0) >= cap:
                        thinking["budget_tokens"] = cap - 1
                        body = json.dumps(document, ensure_ascii=False).encode()
                record["request_parameters"] = {k: document[k] for k in (
                    "model", "stream", "max_tokens", "max_output_tokens", "temperature", "top_p", "seed",
                    "thinking", "reasoning", "output_config", "tool_choice", "parallel_tool_calls") if k in document}
            capture_body = decoded_body(body, headers)
            record["upstream_request_sha256"] = hashlib.sha256(capture_body).hexdigest()
            # Preserve exact image/body bytes, redacting only actual credential values.
            safe_body = capture_body.replace(key.encode(), b"[REDACTED]") if key else capture_body
            with gzip.open(str(prefix) + ".request.gz", "wb") as out:
                out.write(safe_body)
            if (record.get("component") == "file_api" and handler.command == "POST"
                    and parts.path == "/v1/files" and self.file_api_unavailable):
                cached = self.file_api_unavailable
                response_bytes.extend(cached["body"])
                record.update(http_status=cached["status"], status="http_error", failure_type="file_api_error",
                              native_recovery_allowed=True, upstream_dispatched=False,
                              capability_cache_hit=True, capability_reason=cached["reason"],
                              capability_source_sequence=cached["sequence"])
                handler.send_response(cached["status"])
                handler.send_header("Content-Type", "application/json")
                handler.send_header("Content-Length", str(len(response_bytes)))
                handler.end_headers()
                responded = True
                handler.wfile.write(response_bytes)
                return record
            wire_body, wire_headers, wire_metadata = compress_request(
                body if handler.command == "POST" else None, headers)
            record.update(wire_metadata)
            req = urllib.request.Request(target, data=wire_body,
                                         headers=wire_headers, method=handler.command)
            # Count-token and retry routes need the same terminal boundary.
            # Never hold the Runtime lock over an upstream network operation.
            with self.runtime._lock:
                if getattr(self.runtime.environment, "simulator_stopped", False):
                    self.stop_reason = "simulator_stop"
                    raise NativeConversationStopped("Simulator ended the conversation")
            try:
                stage = "upstream"
                record["upstream_dispatched"] = True
                with self.lock:
                    record["retry_index"] = self.consecutive_upstream_errors
                    self.retry_count += int(self.consecutive_upstream_errors > 0)
                if self.token_collector:
                    record["token_model_dispatched"] = protocol_for(req.full_url) is not None
                response = observe_open(self.token_collector, urllib.request.build_opener(NoRedirect()).open, req,
                    metadata={"agent_operation_type": "auxiliary_generation" if record.get("component") == "utility_generation" else "model_request",
                              "operation_type_source": "transport.component",
                              "relay_sequence": record["sequence"], "relay_retry_index": relay_retry_index},
                    request_headers={k: v for k, v in handler.headers.items()
                                     if k.lower() in LOGICAL_HEADER_NAMES | PHYSICAL_HEADER_NAMES},
                    timeout=max(.001, min(self.limits.get("request_timeout_seconds", 600),
                                           self.deadline - time.monotonic())))
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                record["http_status"] = response.status
                record["response_headers"] = {k: v for k, v in response.headers.items() if k.lower() in
                    {"request-id", "x-request-id", "trace-id", "x-trace-id", "content-type", "content-encoding", "date",
                     "x-new-api-request-id", "x-oneapi-request-id", "cf-ray", "traceparent", "retry-after"}}
                def disconnected(exc):
                    record.update(native_client_disconnect=True, transport_phase="downstream",
                                  status="error", failure_type="harness_transport_error", retryable=False,
                                  error=redact(f"{type(exc).__name__}: {exc}", [key]),
                                  response_bytes_at_disconnect=len(response_bytes))
                    # Preserve the existing budget behavior: an abandoned
                    # generation releases its reservation and earns no later
                    # effective Step just because its usage tail was drained.
                    self.budget.release(record)
                stage = "downstream"
                responded = True
                try:
                    handler.send_response(response.status)
                    for header in ("Content-Type", "Content-Encoding"):
                        value = response.headers.get(header)
                        if value:
                            handler.send_header(header, value)
                    handler.send_header("Connection", "close")
                    handler.end_headers()
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError) as exc:
                    disconnected(exc)
                while True:
                    if time.monotonic() >= self.deadline:
                        self.stop_reason = record["failure_type"] = "task_timeout"
                        raise TimeoutError("Native task deadline expired during provider stream")
                    stage = "upstream"
                    chunk = response.read1(65536)
                    if not chunk:
                        break
                    response_bytes.extend(chunk)
                    if (not record.get("native_client_disconnect") and is_generation
                            and 200 <= response.status < 300 and not record.get("generation_completed")
                            and completed_generation(bytes(response_bytes), protocol)):
                        record["generation_completed"] = True
                        if record["counts_agent_step"]:
                            with self.runtime._lock:
                                self.budget.commit(record)
                                # Retained for consumers; contains successful request IDs,
                                # not body hashes, so repeated successful bodies count.
                                self.generations.add(record["sequence"])
                    stage = "downstream"
                    if not record.get("native_client_disconnect"):
                        try:
                            handler.wfile.write(chunk)
                            handler.wfile.flush()
                        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError) as exc:
                            disconnected(exc)
                if not record.get("native_client_disconnect"):
                    record["status"] = "succeeded" if response.status < 400 else "http_error"
                if response.status >= 400:
                    record["failure_type"], record["retryable"] = provider_failure(response.status, bytes(response_bytes))
                    if record.get("component") == "file_api" and response.status not in {401, 402, 403}:
                        # The official dsh adapter handles failed uploads by
                        # sending its own bounded inline image request. Return
                        # the actual error without terminating that recovery.
                        record["provider_failure_type"] = record["failure_type"]
                        record.update(failure_type="file_api_error", native_recovery_allowed=True)
                        reason = files_unavailable(response.status, bytes(response_bytes))
                        if handler.command == "POST" and parts.path == "/v1/files" and reason:
                            with self.lock:
                                self.file_api_unavailable = {"status": response.status, "body": bytes(response_bytes),
                                                             "sequence": record["sequence"], "reason": reason}
                            record["capability_reason"] = reason
                elif (is_generation and not record.get("generation_completed")
                      and not record.get("native_client_disconnect")):
                    record.update(status="error", failure_type="upstream_error", retryable=True,
                                  error="upstream response contained no complete generation")
        except Exception as exc:
            record["error"] = redact(f"{type(exc).__name__}: {exc}", [key])
            record["transport_phase"] = stage
            if stage == "downstream" and isinstance(exc, (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)):
                # Native tools can abandon an auxiliary request and continue.
                # Preserve this failed delivery; let the unchanged CLI recover
                # within the existing deadline instead of killing its next call.
                record["native_client_disconnect"] = True
            from benchmark.services.runtime_environment import AgentTurnLimit, SimulatorRoundLimit
            budget_error = isinstance(exc, (AgentTurnLimit, SimulatorRoundLimit))
            conversation_stopped = isinstance(exc, NativeConversationStopped)
            if budget_error:
                self.stop_reason = str(exc)
                record["failure_type"] = "agent_budget_limit"
            if conversation_stopped:
                record.update(status="runtime_stop", failure_type="simulator_stop")
            if not budget_error and not conversation_stopped and not record.get("failure_type"):
                if time.monotonic() >= self.deadline:
                    self.stop_reason = record["failure_type"] = "task_timeout"
                elif stage == "upstream" and isinstance(exc, (OSError, TimeoutError, urllib.error.URLError, http.client.HTTPException)):
                    record.update(failure_type="upstream_error", retryable=True)
                elif stage == "downstream":
                    record.update(failure_type="harness_transport_error", retryable=False)
                else:
                    record.update(failure_type="agent_request_error", retryable=False)
            if not responded:
                payload = json.dumps({"error": {"type": "simulator_stop" if conversation_stopped else "agent_budget_limit" if budget_error else record["failure_type"],
                                                "message": record["error"]}}).encode()
                handler.send_response(409 if conversation_stopped else 429 if budget_error else
                                      400 if record["failure_type"] == "agent_request_error" else
                                      408 if record["failure_type"] == "task_timeout" else 502)
                handler.send_header("Content-Type", "application/json")
                handler.send_header("Content-Length", str(len(payload)))
                handler.end_headers()
                handler.wfile.write(payload)
        finally:
            self.budget.release(record)
            with self.lock:
                failure = record.get("failure_type")
                if failure == "upstream_error" and record.get("upstream_dispatched"):
                    self.upstream_errors += 1
                    self.consecutive_upstream_errors += 1
                    if self.consecutive_upstream_errors >= self.failure_limit:
                        self.stop_reason = "upstream_error"
                elif failure in {"agent_request_error", "provider_auth_error", "provider_configuration_error",
                                 "model_policy_violation", "harness_transport_error"}:
                    if not (failure == "harness_transport_error" and record.get("native_client_disconnect")):
                        self.stop_reason = failure
                elif record.get("step_counted"):
                    self.consecutive_upstream_errors = 0
                record["consecutive_upstream_errors"] = self.consecutive_upstream_errors
            handler.close_connection = True
            safe_response = bytes(response_bytes).replace(key.encode(), b"[REDACTED]") if key else bytes(response_bytes)
            with gzip.open(str(prefix) + ".response.gz", "wb") as out:
                out.write(safe_response)
            record["duration_seconds"] = round(time.monotonic() - started, 6)
            record["completed_at"] = time.time()
            record["response_sha256"] = hashlib.sha256(bytes(response_bytes)).hexdigest()
            record["provider_usage_raw"] = response_usage(bytes(response_bytes))
            if is_generation:
                record["response_diagnostics"] = response_diagnostics(bytes(response_bytes))
                details = extract_response(bytes(response_bytes), self.provider["protocol"])
                record["response_model"] = details.get("served_model_id")
                record["response_id"] = details.get("provider_response_id")
                if record.get("native_client_disconnect"):
                    record["usage_drain_complete"] = bool(details.get("response_complete"))
            with self.lock:
                (self.log_dir / "requests.json").write_text(json.dumps(self.records, indent=2))
        return record

    def summary(self):
        return {"requests": self.records, "stop_reason": self.stop_reason,
                "http_requests": sum(bool(r.get("upstream_dispatched")) for r in self.records),
                "incoming_http_requests": self.incoming_http_requests,
                "relay_requests": len(self.records), "agent_steps": len(self.generations),
                "retry_count": self.retry_count, "upstream_errors": self.upstream_errors,
                "consecutive_upstream_errors": self.consecutive_upstream_errors,
                "max_consecutive_upstream_errors": self.failure_limit,
                "token_usage": {"source": "camact.token_usage.v1", "report": "token_usage/summary.json"}
                               if self.token_collector else "native/wire normalization reserved",
                "effective_limits": self.limits,
                "retry_policy": ("bounded relay retries for OpenClaw pre-response upstream errors; "
                                 if self.harness_name == "openclaw" else "official CLI retries; ") +
                                "consecutive upstream failure circuit breaker; HTTP totals are audit-only",
                "image_capture": "HTTP bodies and Files uploads retained; no visual credit inferred", "websocket": "unsupported_fail_closed"}

