"""Thin stateful adapter between Claude Code Bash and CamAct services.

Claude never imports benchmark code. Domain schemas are exposed only in camact mode.
The task-local CLI below only forwards an action or clarification request to a
loopback service owned by the harness process.  That service is the sole owner
of the task's RuntimeEnvironment.
"""
from __future__ import annotations

import copy
import hashlib
import http.server
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .core import MUTATING_TOOLS, ClaudeSettings, TaskHandle, write_json
from .tool_profiles import DOMAIN_TOOLS, domain_names, task_tools, validate_profile


IMAGE_FIELDS = ("attachments", "images", "image_ids", "reference_images")
SINGLE_IMAGE_FIELDS = ("image", "image_id")
IMAGE_RE = re.compile(r"\b[0-9]+\.(?:jpg|jpeg|png)\b", re.I)


CLIENT_SOURCE = r'''#!/usr/bin/env python3
import argparse
import json


def main():
    parser = argparse.ArgumentParser(prog="cc_benchmark_adapter")
    sub = parser.add_subparsers(dest="command", required=True)
    action = sub.add_parser("action", help="execute one allowed state-changing benchmark action")
    action.add_argument("tool")
    action.add_argument("--json", required=True, dest="arguments")
    ask = sub.add_parser("ask-user", help="ask the existing task user simulator")
    ask.add_argument("--message", required=True)
    sub.add_parser("status", help="show the task-local adapter capability status")
    args = parser.parse_args()

    if args.command == "action":
        try:
            arguments = json.loads(args.arguments)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"--json must be a JSON object: {exc}")
        if not isinstance(arguments, dict):
            raise SystemExit("--json must be a JSON object")
        payload = {"op": "action", "tool": args.tool, "arguments": arguments}
    elif args.command == "ask-user":
        payload = {"op": "ask_user", "message": args.message}
    else:
        payload = {"op": "status"}

    from mcp_server import command
    try:
        document = command(payload)
    except Exception as exc:
        document = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    print(json.dumps(document, ensure_ascii=False))
    return 0 if document.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _canonical_lookup(handle: TaskHandle) -> dict[str, str]:
    root = handle.task_dir.parents[2] / "users" / handle.user_id / "base_memory" / "images"
    if not root.is_dir():
        return {}
    return {
        path.name.casefold(): path.name
        for path in root.iterdir()
        if path.is_file() and path.suffix.casefold() in {".jpg", ".jpeg", ".png"}
    }


def _canonical_image(value: Any, lookup: dict[str, str]) -> str | None:
    if not isinstance(value, str):
        return None
    name = value.replace('\\', '/').rsplit('/', 1)[-1]
    if not IMAGE_RE.fullmatch(name):
        return None
    return lookup.get(name.casefold(), name)


def canonical_action_arguments(arguments: dict[str, Any], lookup: dict[str, str]) -> dict[str, Any]:
    result = copy.deepcopy(arguments)
    for field in IMAGE_FIELDS:
        if field not in result:
            continue
        if not isinstance(result[field], list):
            raise ValueError(f"{field} must be an array; adapter does not repair input types")
        values = result[field]
        normalized: list[str] = []
        for value in values:
            image_id = _canonical_image(value, lookup)
            if not image_id:
                raise ValueError(f"Unsupported image reference in {field}; use the original album filename, not a renamed copy")
            normalized.append(image_id)
        result[field] = normalized
    for field in SINGLE_IMAGE_FIELDS:
        if field in result:
            image_id = _canonical_image(result[field], lookup)
            if image_id:
                result[field] = image_id
    return result


def _simulator_generator(settings: ClaudeSettings, benchmark_root: Path, session_dir: Path | None = None, task_key: str | None = None):
    if settings.simulator_provider is None and (not settings.api_key or not settings.base_url):
        return None
    from benchmark.benchmark_runner.mllm_adapter import complete_text
    from harness.camact_compatibility_v2.roles import provider_config, role_provider
    role = settings.simulator_provider
    if role is None:
        base = settings.base_url.rstrip("/")
        if not base.endswith("/v1"):
            base += "/v1"
        role = role_provider({"provider": "relay", "model": settings.model, "base_url": base,
            "api_key": settings.api_key, "protocol": "openai-chat", "timeout_seconds": settings.simulator_timeout,
            "max_output_tokens": settings.simulator_max_output_tokens, "retry_attempts": settings.simulator_request_attempts},
            role="simulator", protocol="openai-chat")
    config = provider_config(role, telemetry_path=str(session_dir / "provider_attempts.jsonl") if session_dir else None,
                             task_key=task_key)

    def generate(system_prompt: str, user_prompt: str, seed: int) -> str:
        from dataclasses import replace
        bounded = replace(config, deadline=getattr(generate, "deadline", None))
        return complete_text(bounded, system_prompt=system_prompt, seed=seed,
                             **({"messages": user_prompt} if isinstance(user_prompt, list) else {"user_prompt": user_prompt}))

    return generate


class NativeAdapterRuntime:
    """Own one live benchmark environment and expose only bounded commands."""

    def __init__(self, handle: TaskHandle, session_dir: Path, settings: ClaudeSettings, benchmark_root: Path):
        from benchmark.services.runtime_environment import RuntimeEnvironment

        validate_profile(settings.tool_profile)
        task_tools(handle)  # fail before starting services if a declared tool has no backend
        from benchmark.services.service_manager import ServiceInfrastructureError
        from benchmark.services.simulator_common import SimulatorInfrastructureError
        self._infrastructure_types = (ServiceInfrastructureError, SimulatorInfrastructureError)
        self.infrastructure_error = None
        self._simulator_provider_error = None
        self._nonrecoverable_infrastructure_error = None
        self.handle = handle
        from harness.camact_prompt_parity_v1.policy import NativePromptPolicy
        self.prompt_policy = NativePromptPolicy(handle.task_dir, settings.tool_profile)
        self.lookup = _canonical_lookup(handle)
        self.environment = RuntimeEnvironment(
            handle.task_dir,
            session_dir,
            simulator_generator=_simulator_generator(settings, benchmark_root, session_dir, f"{handle.user_id}/{handle.task_name}"),
            max_agent_turns=settings.max_agent_turns,
            max_simulator_rounds=settings.max_simulator_rounds,
        )
        self.tool_profile = validate_profile(settings.tool_profile)
        self.allowed_actions = sorted(set(self.environment.tools) - DOMAIN_TOOLS)
        self.mutating_tools = MUTATING_TOOLS | {"email_send", "telegram_send"}
        self.domain_tools = domain_names(self.environment.tools, self.tool_profile)
        self._lock = threading.RLock()
        self._closed = False
        self._final_state: dict[str, Any] | None = None
        self.action_events: list[dict[str, Any]] = []
        self.ask_events: list[dict[str, Any]] = []
        self._successful_actions = 0
        self._requests: dict[str, tuple[str, dict[str, Any]]] = {}
        self.request_events: list[dict[str, Any]] = []
        self.idempotent_request_replays = 0
        self.request_id_conflicts = 0
        self.duplicate_actions_suppressed = 0

    @property
    def successful_action_count(self) -> int:
        return self._successful_actions

    def _record_infrastructure_error(self, exc: Exception) -> None:
        """Only a failed Simulator provider call can recover on that channel."""
        from benchmark.services.simulator_common import SimulatorInfrastructureError
        from benchmark.benchmark_runner.mllm_adapter import ProviderInfrastructureError

        message = f"{type(exc).__name__}: {exc}"
        cause, provider_failure, seen = exc, False, set()
        while cause is not None and id(cause) not in seen:
            seen.add(id(cause))
            provider_failure = provider_failure or isinstance(cause, ProviderInfrastructureError)
            cause = cause.__cause__ or cause.__context__
        # Preserve errors explicitly recorded by another runtime channel too.
        if self.infrastructure_error and self.infrastructure_error != self._simulator_provider_error:
            self._nonrecoverable_infrastructure_error = self.infrastructure_error
        if isinstance(exc, SimulatorInfrastructureError) and provider_failure:
            self._simulator_provider_error = message
            self.infrastructure_error = self._nonrecoverable_infrastructure_error or message
        else:
            self._nonrecoverable_infrastructure_error = self.infrastructure_error = message

    def _record_simulator_recovery(self) -> None:
        if self._simulator_provider_error:
            self._simulator_provider_error = None
            self.infrastructure_error = self._nonrecoverable_infrastructure_error

    def command(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Replay one transport request, never suppress a separate Agent action.

        This lock covers cache lookup, the actual Runtime call and receipt
        storage. Concurrent retries of one request therefore cannot both write.
        Legacy callers without an ID retain normal Runtime execution semantics.
        """
        with self._lock:
            if not isinstance(payload, dict):
                return {"ok": False, "error": "request must be a JSON object"}
            identity = payload.get("request_id")
            if identity is not None and (not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", identity)):
                return {"ok": False, "error": "request_id must be a nonempty bounded identifier", "error_code": "invalid_request_id"}
            try:
                fingerprint = hashlib.sha256(json.dumps(
                    {key: value for key, value in payload.items() if key != "request_id"},
                    ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
                ).encode("utf-8")).hexdigest() if identity is not None else None
            except (TypeError, ValueError):
                return {"ok": False, "error": "request must contain valid JSON values"}
            if identity in self._requests:
                previous_fingerprint, response = self._requests[identity]
                if previous_fingerprint != fingerprint:
                    self.request_id_conflicts += 1
                    self.request_events.append({"request_id": identity, "op": payload.get("op"), "status": "conflict"})
                    return {"ok": False, "error": "request_id was already used for a different request", "error_code": "request_id_conflict"}
                self.idempotent_request_replays += 1
                # Retain the old diagnostic name only for transport replays of
                # mutations. It no longer represents content-based suppression.
                if payload.get("op") == "action" and payload.get("tool") in self.mutating_tools:
                    self.duplicate_actions_suppressed += 1
                self.request_events.append({"request_id": identity, "op": payload.get("op"), "status": "replayed"})
                return copy.deepcopy(response)
            try:
                if (getattr(self.environment, "simulator_stopped", False)
                        and payload.get("op") in {"action", "ask_user", "domain"}):
                    # The same lock serializes STOP delivery and queued gateway
                    # calls. An official CLI may still be shutting down; no new
                    # business operation may cross the completed task boundary.
                    response = {"ok": False, "error": "the user Simulator has ended this task",
                                "error_code": "simulator_stopped"}
                else:
                    response = self._execute_command(payload)
            except Exception as exc:
                if isinstance(exc, self._infrastructure_types):
                    self._record_infrastructure_error(exc)
                response = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            if identity is not None:
                # Also retain errors: a transport retry must not repeat an
                # ambiguous operation after a service wrote but lost its reply.
                self._requests[identity] = (fingerprint, copy.deepcopy(response))
                self.request_events.append({"request_id": identity, "op": payload.get("op"), "status": "executed"})
            return response

    def _execute_command(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if self._closed:
                return {"ok": False, "error": "adapter session is closed"}
            op = str(payload.get("op", ""))
            if op == "status":
                return {
                    "ok": True,
                    "allowed_actions": self.allowed_actions,
                    "successful_actions": self.successful_action_count,
                    "duplicate_actions_suppressed": self.duplicate_actions_suppressed,
                    "idempotent_request_replays": self.idempotent_request_replays,
                    "request_id_conflicts": self.request_id_conflicts,
                    "session": "task-local",
                }
            if op == "domain_tools":
                return {"ok": True, "tools": [
                    {"name": name, "description": self.environment.tools[name]["description"],
                     "inputSchema": self.environment.tools[name]["input_schema"]}
                    for name in self.domain_tools]}
            if op == "domain":
                name = str(payload.get("tool", ""))
                if name not in self.domain_tools:
                    return {"ok": False, "error": "domain tool is not allowed by this profile/task"}
                return self.environment.call_tool(name, payload.get("arguments", {}))
            if op == "ask_user":
                message = str(payload.get("message", "")).strip()
                if not message:
                    return {"ok": False, "error": "message is required"}
                started_at = datetime.now(timezone.utc).isoformat()
                started = time.monotonic()
                before_turns = len(self.environment.state.get("user_simulator", {}).get("turns", []))
                try:
                    response = self.environment.user_message(message)
                except Exception as exc:
                    if isinstance(exc, self._infrastructure_types):
                        self._record_infrastructure_error(exc)
                    response = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
                else:
                    after_turns = len(self.environment.state.get("user_simulator", {}).get("turns", []))
                    if response.get("ok") and after_turns > before_turns:
                        self._record_simulator_recovery()
                self.ask_events.append({
                    "component": "simulator", "operation": "ask_user", "started_at": started_at,
                    "ended_at": datetime.now(timezone.utc).isoformat(),
                    "duration_seconds": round(time.monotonic() - started, 6),
                    "status": "succeeded" if response.get("ok") else "error",
                    "message": message, "response": copy.deepcopy(response),
                })
                return response
            if op != "action":
                return {"ok": False, "error": "unsupported adapter operation"}

            tool = str(payload.get("tool", "")).strip()
            arguments = payload.get("arguments", {})
            if not isinstance(arguments, dict):
                return {"ok": False, "error": "action arguments must be a JSON object"}
            if tool not in self.allowed_actions:
                response = {"ok": False, "tool": tool, "error": "action is not allowed for this task"}
                now = datetime.now(timezone.utc).isoformat()
                self.action_events.append({
                    "tool": tool, "arguments": copy.deepcopy(arguments), "response": response,
                    "component": "action", "started_at": now, "ended_at": now,
                    "duration_seconds": 0.0, "status": "error",
                })
                return response

            started_at = datetime.now(timezone.utc).isoformat()
            started = time.monotonic()
            normalized = copy.deepcopy(arguments)
            try:
                normalized = canonical_action_arguments(arguments, self.lookup)
                response = self.environment.call_tool(tool, normalized)
            except Exception as exc:
                if isinstance(exc, self._infrastructure_types):
                    self._record_infrastructure_error(exc)
                response = {"ok": False, "tool": tool, "error": f"{type(exc).__name__}: {exc}"}
            if response.get("ok") and tool in self.mutating_tools:
                self._successful_actions += 1
            self.action_events.append({
                "tool": tool,
                "input_arguments": copy.deepcopy(arguments),
                "arguments": copy.deepcopy(normalized),
                "response": copy.deepcopy(response),
                "duplicate_suppressed": False,
                "request_id": payload.get("request_id"),
                "component": "action",
                "started_at": started_at,
                "ended_at": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": round(time.monotonic() - started, 6),
                "status": "succeeded" if response.get("ok") else "error",
            })
            return response

    def record_native_read(self, image_id: str) -> None:
        with self._lock:
            name = "image_view" if "image_view" in self.environment.tools else "inspect_image" if "inspect_image" in self.environment.tools else None
            if name:
                args = {"image_id" if name == "image_view" else "image": image_id}
                self.environment._record(kind="tool_call", name=name, request=args,
                    response={"image_id": image_id, "source": "claude_code_native_read"}, status="succeeded")

    def finish(self, final_response: str, evidence: list[str], trajectory_class: str) -> dict[str, Any]:
        with self._lock:
            if trajectory_class != "finished":
                self.environment.state["session"]["status"] = "agent_failure" if trajectory_class == "agent_failure" else "infrastructure_error"
            return self.environment.build_submission(final_response, evidence)

    def close(self) -> dict[str, Any]:
        with self._lock:
            if not self._closed:
                self._final_state = self.environment.close()
                self._closed = True
            return copy.deepcopy(self._final_state or {})

    def tool_calls(self) -> list[dict[str, Any]]:
        with self._lock:
            calls = copy.deepcopy(self.environment.tool_calls_for_evaluation())
            audit_tools = [e for e in self.environment.audit if e.get("kind") == "tool_call"]
            for index, call in enumerate(calls, 1):
                call.setdefault("action_id", f"act_{index:04d}")
                call.setdefault("action_type", call.get("tool"))
                call["tool_category"] = "domain_tool" if call.get("tool") in DOMAIN_TOOLS else "business_action" if call.get("tool") in self.mutating_tools else "business_read"
                call["source"] = "camact_mcp" if call.get("tool") in DOMAIN_TOOLS else "camact_bash_adapter"
                if audit_tools[index - 1].get("response", {}).get("source") == "claude_code_native_read":
                    call["source"], call["tool_category"] = "claude_code_native_read", "file_observation"
                call.setdefault("parent_tool_call_id", None)
                call.setdefault("originating_model_call_id", None)
            return calls

    def diagnostics(self) -> dict[str, Any]:
        with self._lock:
            return {
                "transport": "task-local loopback CLI service",
                "allowed_actions": list(self.allowed_actions),
                "tool_profile": self.tool_profile,
                "domain_tools": self.domain_tools,
                "action_events": copy.deepcopy(self.action_events),
                "ask_user_events": copy.deepcopy(self.ask_events),
                "successful_actions": self.successful_action_count,
                "duplicate_actions_suppressed": self.duplicate_actions_suppressed,
                "idempotent_request_replays": self.idempotent_request_replays,
                "request_id_conflicts": self.request_id_conflicts,
                "request_events": copy.deepcopy(self.request_events),
                "runtime_conversation_trace": copy.deepcopy(self.environment.conversation_trace),
            }


class _AdapterHandler(http.server.BaseHTTPRequestHandler):
    server: "NativeAdapterServer"  # type: ignore[assignment]

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/command" or self.headers.get("X-CamAct-Token") != self.server.token:
            self._send(403, {"ok": False, "error": "forbidden"})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 1 or size > 1024 * 1024:
                raise ValueError("invalid request size")
            payload = json.loads(self.rfile.read(size).decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("request must be a JSON object")
            response = self.server.runtime.command(payload)
            self._send(200 if response.get("ok") else 400, response)
        except Exception as exc:
            self._send(400, {"ok": False, "error": f"{type(exc).__name__}: {exc}"})

    def _send(self, status: int, value: dict[str, Any]) -> None:
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class NativeAdapterServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, runtime: NativeAdapterRuntime):
        self.runtime = runtime
        self.token = secrets.token_urlsafe(32)
        super().__init__(("127.0.0.1", 0), _AdapterHandler)
        self._thread = threading.Thread(target=self.serve_forever, name=f"adapter-{runtime.handle.task_id}", daemon=True)

    @property
    def endpoint(self) -> dict[str, str]:
        return {"url": f"http://127.0.0.1:{self.server_address[1]}/command", "token": self.token}

    def __enter__(self) -> "NativeAdapterServer":
        self._thread.start()
        return self

    def __exit__(self, *_args: Any) -> None:
        self.shutdown()
        self.server_close()
        self._thread.join(timeout=5)


def _copy_tree_readonly(source: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for item in source.iterdir():
        destination = target / item.name
        if item.is_symlink():
            raise ValueError(f"workspace source symlink is not allowed: {item}")
        if item.is_dir():
            _copy_tree_readonly(item, destination)
        elif item.is_file():
            import shutil
            shutil.copy2(item, destination)



def _public_action_contract(tools: dict[str, Any]) -> dict[str, Any]:
    return {
        "interface": "Claude Code Bash -> task-local Adapter -> existing RuntimeEnvironment",
        "allowed_actions": {
            name: {"description": schema["description"], "input_schema": schema["input_schema"],
                   "command": f"python3 .camact/adapter.py action {name} --json '<JSON object>'"}
            for name, schema in tools.items() if name not in DOMAIN_TOOLS
        },
        "ask_user": "python3 .camact/adapter.py ask-user --message '<question>'",
    }


def build_native_workspace(handle: TaskHandle, workspace: Path, endpoint: dict[str, str], tool_profile: str = "native") -> dict[str, Any]:
    """Create an isolated workspace containing only runtime-visible data."""
    if workspace.exists():
        raise FileExistsError(f"task workspace already exists: {workspace}")
    workspace.mkdir(parents=True)
    user_memory = handle.task_dir.parents[2] / "users" / handle.user_id / "base_memory"
    if not user_memory.is_dir():
        raise FileNotFoundError(f"raw user memory is missing: {user_memory}")
    from benchmark.services.api import raw_root
    if raw_root(handle.task_dir).resolve() != user_memory.resolve():
        raise ValueError("file and domain-tool album roots must match")
    _copy_tree_readonly(user_memory, workspace / "album")

    validate_profile(tool_profile)
    task, tools = task_tools(handle)
    initial = task.initial_user_message()
    history = {"mode": task.task_type, "messages": task.initial_messages()[:-1]}
    public_spec = {"task_id": task.task_id, "interaction_type": task.task_type,
                   "user_query": initial["content"]}
    allowed_tools = list(tools)
    # Public fixtures only; simulator internals and delivery private state stay host-side.
    public_fixtures = {key: value for key, value in task.load_fixtures(handle.task_dir).items()
                       if key in {"contacts", "messaging", "calendar", "publishing", "photo_library",
                                  "archives", "workspace", "checklists", "service_catalog", "reservations"}}
    from benchmark.services.tool_support import _enforce_runtime_boundary
    _enforce_runtime_boundary(public_fixtures, "Claude public fixtures")

    write_json(workspace / "context" / "task.json", public_spec)
    write_json(workspace / "context" / "initial_message.json", initial if isinstance(initial, dict) else {})
    write_json(workspace / "context" / "history.json", history if isinstance(history, dict) else {})
    write_json(workspace / "context" / "public_state.json", public_fixtures)
    action_contract = _public_action_contract(tools)
    write_json(workspace / "context" / "adapter_cli.json", action_contract)
    (workspace / ".camact").mkdir()
    from harness.camact_prompt_parity_v1.policy import write_workspace_policy
    write_workspace_policy(handle.task_dir, workspace, tool_profile)
    (workspace / ".camact" / "adapter.py").write_text(CLIENT_SOURCE, encoding="utf-8")
    write_json(workspace / ".camact" / "endpoint.json", endpoint)
    import shutil
    for filename in ("mcp_server.py", "sandbox_launcher.py"):
        shutil.copy2(Path(__file__).with_name(filename), workspace / ".camact" / filename)
    servers = {"camact": {"command": "python3", "args": ["/tmp/.camact/mcp_server.py"]}} if tool_profile == "camact" else {}
    write_json(workspace / ".camact" / "mcp.json", {"mcpServers": servers})

    task_lines = [
        "# CamAct Task",
        "",
        "Work only inside this task workspace. Use Claude Code's native Read, Glob, Grep, and Bash tools.",
        "Inspect album/metadata.csv and other public files to find candidates, then use Read on the original image files in album/images/ for visual decisions.",
        "Additional task-declared photo/person tools are available through camact MCP." if tool_profile == "camact" else "No domain MCP tools are registered in this session.",
        "",
        "For a real state-changing action, use the Bash commands documented in context/adapter_cli.json. The command immediately calls the existing task simulator/service and prints the real result.",
        "For missing user information, call python3 .camact/adapter.py ask-user --message '<question>'; the reply comes from this same task session.",
        "Do not write a result.json. Your final natural-language answer is captured directly from the Claude Code trajectory; a completed action remains recorded even if the final answer is empty.",
        "Do not inspect parent paths or search for benchmark, ground truth, rubric, evaluator, or another task.",
        "",
        f"Task id: {handle.task_id}",
        f"Interaction type: {public_spec['interaction_type']}",
        f"User request: {public_spec['user_query']}",
        "",
        "Adapter CLI:",
        json.dumps(action_contract, ensure_ascii=False, indent=2),
    ]
    (workspace / "TASK.md").write_text("\n".join(task_lines) + "\n", encoding="utf-8")
    manifest = {
        "schema_version": "camact.claude_code_native_workspace.v1",
        "user_id": handle.user_id,
        "task_name": handle.task_name,
        "task_id": handle.task_id,
        "native_tools": ["Read", "Glob", "Grep", "Bash"],
        "tool_profile": tool_profile,
        "domain_tools": domain_names(tools, tool_profile),
        "files": ["TASK.md", "context/", "album/", ".camact/adapter.py", ".camact/endpoint.json"],
        "excluded": [
            "ground_truth/", "evaluator_config.json", "task_spec.json", "tools.json",
            "benchmark/", "evaluation/", "rubric", "user_simulator.hidden_state", "other_tasks/",
        ],
        "result_source": "claude trajectory + native Read events + live adapter RuntimeEnvironment",
    }
    write_json(workspace / "workspace_manifest.json", manifest)
    return {
        "public_spec": public_spec,
        "allowed_tools": allowed_tools,
        "allowed_actions": sorted(action_contract["allowed_actions"]),
        "workspace_manifest": manifest,
    }


def invoke_workspace_client(workspace: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    """Test helper that exercises the exact CLI Claude invokes."""
    return subprocess.run(
        [sys.executable, str(workspace / ".camact" / "adapter.py"), *arguments],
        cwd=workspace,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
