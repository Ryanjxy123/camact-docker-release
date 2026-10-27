"""Lightweight local mock API with Claw-Eval-style health/reset/audit routes.

Uses the standard-library HTTP server so optional services need no web server
installation. All mutations are serialized and validated before commit.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .business import PlatformTools
from .moments import MomentsTools
from .delivery import DeliveryTools
from ..platform_registry import PLATFORM_STATE_KEYS, PLATFORM_TOOLS
from ..process_cleanup import bind_service_to_parent
from ..tool_support import _dump, _load, _utc_now


class MockService:
    def __init__(self, name: str, task_dir: Path, workspace: Path, fixture_path: Path):
        self.name = name
        self.task_dir = task_dir
        self.workspace = workspace
        self.fixture_path = fixture_path
        self.lock = threading.RLock()
        self.state: dict = {}
        self.audit: list[dict] = []
        self.tools: dict = {}
        self.initialized = False
        self.session_id = os.environ.get("CAMACT_SESSION_ID", "")
        # Stateful receipt services recover the same session after a process
        # restart. A new trial still explicitly resets from its own fixture.
        persisted = self.workspace / "snapshot.json"
        if name in {"moments", "email", "telegram"} and persisted.is_file():
            document = _load(persisted)
            fixture = _load(self.fixture_path)
            if (document["service"] != name or document["session_id"] != self.session_id
                    or fixture["service"] != name or fixture["session_id"] != self.session_id):
                raise ValueError("persisted platform service/session mismatch")
            self.state = {**copy.deepcopy(fixture["state"]), **document["state"]}
            self.audit = document["audit"]
            self.tools = fixture["tools"]
            self.initialized = True

    def snapshot(self) -> dict:
        return {
            "service": self.name, "session_id": self.session_id,
            "state": {key: copy.deepcopy(self.state[key]) for key in PLATFORM_STATE_KEYS[self.name] if key in self.state},
            "audit": copy.deepcopy(self.audit),
        }

    def reset(self) -> dict:
        fixture = _load(self.fixture_path)
        if fixture["service"] != self.name or fixture["session_id"] != self.session_id:
            raise ValueError("fixture service/session mismatch")
        state, tools = copy.deepcopy(fixture["state"]), copy.deepcopy(fixture["tools"])
        if not set(tools) <= PLATFORM_TOOLS[self.name]:
            raise ValueError("fixture declares a tool for another service")
        # Persist before swapping live references. Reset errors fail setup.
        _dump(self.workspace / "snapshot.json", {
            "service": self.name, "session_id": self.session_id,
            "state": {key: state[key] for key in PLATFORM_STATE_KEYS[self.name]}, "audit": [],
        })
        self.state, self.tools, self.audit = state, tools, []
        self.initialized = True
        return {"status": "reset", "service": self.name, "session_id": self.session_id}

    def execute(self, tool: str, arguments) -> tuple[int, dict]:
        if not self.initialized:
            return 503, {"error": "service has not been initialized"}
        candidate = copy.deepcopy(self.state)
        try:
            if tool not in self.tools:
                raise ValueError("tool is not declared for this session/service")
            if self.name == "moments":
                executor = MomentsTools(self.task_dir, self.workspace, candidate, session_id=self.session_id)
            elif self.name in {"email", "telegram"}:
                executor = DeliveryTools(self.task_dir, self.workspace, candidate,
                                         channel=self.name, session_id=self.session_id)
            else:
                executor = PlatformTools(self.task_dir, self.workspace, candidate)
            result = executor.prepare(tool, arguments, self.tools[tool])
            status, code = "succeeded", 200
        except (ValueError, KeyError, TypeError) as exc:
            candidate = self.state
            result, status, code = {"error": str(exc)}, "rejected", 400
        event = {"sequence": len(self.audit) + 1, "timestamp": _utc_now(),
                 "kind": "tool_call", "name": tool, "request": copy.deepcopy(arguments),
                 "response": copy.deepcopy(result), "status": status}
        audit = self.audit + [event]
        document = {"service": self.name, "session_id": self.session_id,
                    "state": {key: candidate[key] for key in PLATFORM_STATE_KEYS[self.name]}, "audit": audit}
        # JSON/file validation precedes commit. No failed action changes state.
        _dump(self.workspace / "snapshot.json", document)
        self.state, self.audit = candidate, audit
        return code, result


def make_handler(service: MockService):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # Tool payloads belong in the structured audit, not stdout.

        def _reply(self, code, value):
            data = json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _route(self):
            route = urlparse(self.path).path
            prefix = f"/{service.name}"
            with service.lock:
                if route == prefix + "/health":
                    self._reply(200, {"status": "ok", "service": service.name, "session_id": service.session_id})
                elif route == prefix + "/audit" and self.command == "GET":
                    self._reply(200, service.snapshot())
                elif route == prefix + "/reset" and self.command == "POST":
                    self._reply(200, service.reset())
                elif route.startswith(prefix + "/") and self.command in {"POST", "GET"}:
                    tool = route[len(prefix) + 1:]
                    try:
                        size = int(self.headers.get("Content-Length", "0"))
                        if size < 0 or size > 4 * 1024 * 1024:
                            raise ValueError("request body exceeds limit")
                        arguments = json.loads(self.rfile.read(size) or b"{}", parse_constant=lambda value: (_ for _ in ()).throw(ValueError("invalid JSON number")))
                    except (ValueError, UnicodeError):
                        self._reply(400, {"error": "invalid JSON request"})
                        return
                    code, result = service.execute(tool, arguments)
                    self._reply(code, result)
                else:
                    self._reply(404, {"error": "unknown endpoint"})

        def do_GET(self):
            self._route()

        def do_POST(self):
            self._route()

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", required=True, choices=list(PLATFORM_TOOLS))
    args = parser.parse_args()
    bind_service_to_parent(int(os.environ["CAMACT_PARENT_PID"]))
    workspace = Path(os.environ["CAMACT_SERVICE_WORKSPACE"])
    service = MockService(args.service, Path(os.environ["CAMACT_TASK_DIR"]), workspace, Path(os.environ["CAMACT_SERVICE_FIXTURE"]))
    server = ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("PORT", "0"))), make_handler(service))
    # Bind port 0 in the child, then publish the allocated address. There is no
    # choose-free-port/rebind race between concurrent sessions.
    _dump(Path(os.environ["CAMACT_SERVICE_READY_FILE"]), {
        "port": server.server_port, "pid": os.getpid(), "session_id": service.session_id,
    })
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
