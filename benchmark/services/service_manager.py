"""Optional service lifecycle and HTTP dispatch, adapted from Claw-Eval.

Reference: runner/services.py and runner/dispatcher.py, 5680b8b11ff2ee5d.
Each session starts its own processes; declared ports are remapped to ports
allocated by the OS. We never reset or reuse another session's service.
"""
from __future__ import annotations

import atexit
import copy
import json
import math
import os
import shlex
import subprocess
import sys
import time
import re
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import httpx

from .platform_registry import PLATFORM_STATE_KEYS
from .task_definition import TaskDefinition
from .tool_support import _dump, _load, _utc_now


class ServiceInfrastructureError(RuntimeError):
    """Service setup, transport or snapshot failed; this is not an agent error."""

    def __init__(self, message: str, *, dispatch: dict | None = None):
        super().__init__(message)
        self.dispatch = dispatch or {}


class ServiceManager:
    def __init__(self, task: TaskDefinition, task_dir: Path, session_dir: Path, session_id: str, initial_state: dict):
        self.task = task
        self.task_dir = task_dir
        self.session_dir = session_dir
        self.session_id = session_id
        self.initial_state = initial_state
        self.client = httpx.Client(trust_env=False, timeout=10.0)
        self.spawned: list[tuple[object, subprocess.Popen, object]] = []
        self.ports: dict[int, int] = {}
        self.lifecycle: list[dict] = []
        self.closed = False
        try:
            value = float(os.environ.get("CAMACT_SERVICE_READY_TIMEOUT", ""))
            self.ready_timeout_override = value if math.isfinite(value) and value > 0 else None
        except ValueError:
            self.ready_timeout_override = None
        try:
            self.scheduler_context = json.loads(os.environ.get("CAMACT_SCHEDULER_CONTEXT", "{}"))
        except (TypeError, ValueError):
            self.scheduler_context = {}
        if not isinstance(self.scheduler_context, dict):
            self.scheduler_context = {}
        self._cleanup = self.close
        atexit.register(self._cleanup)

    def _event(self, service: str, phase: str, **details):
        self.lifecycle.append({"service": service, "phase": phase, "timestamp": _utc_now(), **details})
        _dump(self.session_dir / "service_lifecycle.json", self.lifecycle)

    def resolve_url(self, url: str) -> str:
        parsed = urlparse(url)
        return urlunparse(parsed._replace(netloc=f"127.0.0.1:{self.ports[parsed.port]}"))

    def _effective_ready_timeout(self, service) -> float:
        declared = float(service.ready_timeout)
        if not math.isfinite(declared) or declared <= 0:
            raise ServiceInfrastructureError("service readiness timeout must be finite and positive")
        return max(60.0, declared, self.ready_timeout_override or 0.0)

    @staticmethod
    def _resource_snapshot() -> dict:
        """Small dependency-free snapshot safe to persist with failure data."""
        data = {"pid": os.getpid(), "load_average": list(os.getloadavg())}
        try:
            meminfo = {}
            with open("/proc/meminfo", encoding="utf-8") as stream:
                for line in stream:
                    key, value = line.split(":", 1)
                    parts = value.strip().split()
                    meminfo[key] = int(parts[0]) * (1024 if len(parts) > 1 and parts[1] == "kB" else 1)
            data["meminfo_bytes"] = {k: meminfo[k] for k in ("MemAvailable", "MemFree", "SwapFree", "SwapTotal") if k in meminfo}
        except (OSError, ValueError, IndexError):
            data["meminfo_bytes"] = {}
        try:
            stat = os.statvfs("/")
            data["disk_free_bytes"] = stat.f_bavail * stat.f_frsize
        except OSError:
            data["disk_free_bytes"] = None
        try:
            data["pressure"] = {
                kind: open(f"/proc/pressure/{kind}", encoding="utf-8").read()
                for kind in ("cpu", "memory", "io")
                if os.path.isfile(f"/proc/pressure/{kind}")
            }
        except OSError:
            data["pressure"] = {}
        try:
            limit = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
            used = "/sys/fs/cgroup/memory/memory.usage_in_bytes"
            if os.path.isfile(limit) and os.path.isfile(used):
                data["cgroup_memory_headroom"] = int(open(limit).read()) - int(open(used).read())
        except (OSError, ValueError):
            data["cgroup_memory_headroom"] = None
        try:
            with open(f"/proc/{os.getpid()}/status", encoding="utf-8") as stream:
                data["process_rss_bytes"] = next((int(x.split()[1]) * 1024 for x in stream if x.startswith("VmRSS:")), None)
        except (OSError, ValueError, IndexError):
            data["process_rss_bytes"] = None
        return data

    def _failure(self, service, phase, *, started_at, ready_path, health_status=None,
                 health_error=None, failure_cause=None, elapsed=None):
        proc = next((p for s, p, _ in self.spawned if s is service), None)
        resource = self._resource_snapshot()
        log_tail = ""
        log_path = self.session_dir / "services" / service.name / "process.log"
        try:
            log_tail = "".join(log_path.read_text(errors="replace").splitlines(True)[-40:])
            log_tail = re.sub(r"(?i)(authorization\s*[:=]\s*(?:bearer\s+)?)[^\s,}]+", r"\1[REDACTED]", log_tail)
        except OSError:
            pass
        active_counts = self.scheduler_context.get("active_counts_by_harness") or {}
        available = (resource.get("meminfo_bytes") or {}).get("MemAvailable")
        iowait = resource.get("iowait_percent")
        if failure_cause == "ready_timeout":
            pressure = []
            if available is not None and available < 32 * 1024 ** 3:
                pressure.append("memory_available_below_32GiB")
            if resource.get("disk_free_bytes") is not None and resource["disk_free_bytes"] < 80 * 1024 ** 3:
                pressure.append("disk_free_below_80GiB")
            if iowait is not None and iowait >= 10:
                pressure.append("iowait_at_or_above_10_percent")
            if sum(active_counts.values()) >= 15:
                pressure.append("15_or_more_active_tasks")
            cause_category = "resource_pressure_or_high_parallelism" if pressure else "startup_or_health_check_slow"
        else:
            pressure = []
            cause_category = failure_cause or "service_setup_failure"
        details = {
            "ready_timeout": self._effective_ready_timeout(service),
            "elapsed_seconds": elapsed if elapsed is not None else time.monotonic() - started_at,
            "pid": proc.pid if proc else None,
            "returncode": proc.poll() if proc else None,
            "ready_file_exists": ready_path.exists(),
            "health_status": health_status,
            "health_error": health_error,
            "active_counts": active_counts,
            "active_tasks": self.scheduler_context.get("active_tasks"),
            "concurrency_policy": self.scheduler_context.get("concurrency_policy"),
            "resource_snapshot": resource,
            "process_log_tail": log_tail,
            "failure_cause": failure_cause or "service_ready_timeout",
            "cause_category": cause_category,
            "cause_evidence": pressure,
            "attribution": "observed_resource_correlation; process-level root cause requires process.log",
        }
        self._event(service.name, "failure", **details)
        path = self.session_dir / "service_failure_diagnostics.json"
        try:
            existing = _load(path) if path.is_file() else []
        except (OSError, ValueError, TypeError):
            existing = []
        existing.append({"service": service.name, "phase": phase, "timestamp": _utc_now(), **details})
        _dump(path, existing)
        return details

    def __enter__(self):
        try:
            for service in self.task.services:
                self._spawn(service)
            self.reset_all()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _spawn(self, service):
        timeout = self._effective_ready_timeout(service)
        workspace = self.session_dir / "services" / service.name
        workspace.mkdir(parents=True, exist_ok=False)
        if service.name not in PLATFORM_STATE_KEYS:
            raise ServiceInfrastructureError(f"unknown mock service: {service.name}")
        endpoint_names = {endpoint.tool_name for endpoint in self.task.tool_endpoints if self.task.service_for_endpoint(endpoint).name == service.name}
        fixture = {"service": service.name, "session_id": self.session_id,
                   "state": {key: copy.deepcopy(self.initial_state[key]) for key in (*PLATFORM_STATE_KEYS[service.name], "contacts")},
                   "tools": {tool.name: tool.model_dump(exclude={"name"}) for tool in self.task.tools if tool.name in endpoint_names}}
        fixture_path = workspace / "fixture.json"
        _dump(fixture_path, fixture)
        self._event(service.name, "fixture", path=str(fixture_path))
        ready_path = workspace / "ready.json"
        command = shlex.split(service.command)
        if command and command[0] in {"python", "python3"}:
            command[0] = sys.executable
        base_env = dict(os.environ)
        for key in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            base_env.pop(key, None)
        env = {**base_env, **service.env, "PORT": "0", "CAMACT_TASK_DIR": str(self.task_dir),
               "CAMACT_PARENT_PID": str(os.getpid()), "CAMACT_SESSION_ID": self.session_id, "CAMACT_SERVICE_WORKSPACE": str(workspace),
               "CAMACT_SERVICE_FIXTURE": str(fixture_path), "CAMACT_SERVICE_READY_FILE": str(ready_path)}
        log = (workspace / "process.log").open("wb")
        try:
            proc = subprocess.Popen(command, cwd=Path(__file__).resolve().parents[1], stdout=log, stderr=log,
                                    env=env, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except BaseException:
            log.close()
            raise
        # Register before health polling so failure always terminates this child.
        self.spawned.append((service, proc, log))
        started_at = time.monotonic()
        # Readiness is infrastructure policy.  A task-local legacy 10-second
        # value must not recreate the known startup race; keep the task's
        # requested value when it is already longer, otherwise use 60 seconds.
        self._event(service.name, "start", pid=proc.pid, ready_timeout=timeout,
                    scheduler_context=self.scheduler_context)
        deadline = started_at + timeout
        health_status = None
        health_error = None
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                self._failure(service, "start", started_at=started_at, ready_path=ready_path,
                              health_status=health_status, health_error=health_error,
                              failure_cause="service_process_exited", elapsed=time.monotonic() - started_at)
                raise ServiceInfrastructureError(f"service '{service.name}' exited during setup (rc={proc.returncode})")
            if ready_path.exists():
                try:
                    ready = _load(ready_path)
                except (OSError, ValueError, TypeError, KeyError) as exc:
                    health_error = f"ready_file_invalid:{type(exc).__name__}"
                    time.sleep(0.05)
                    continue
                if (not isinstance(ready, dict) or not {"session_id", "pid", "port"} <= ready.keys()
                        or type(ready.get("pid")) is not int or type(ready.get("port")) is not int
                        or not 1 <= ready.get("port", 0) <= 65535):
                    health_error = "ready_file_invalid_schema"
                    time.sleep(0.05)
                    continue
                if ready["session_id"] != self.session_id or ready["pid"] != proc.pid:
                    self._failure(service, "identity", started_at=started_at, ready_path=ready_path,
                                  health_status=health_status, health_error=health_error,
                                  failure_cause="ready_identity_mismatch")
                    raise ServiceInfrastructureError("service readiness identity mismatch")
                self.ports[service.port] = ready["port"]
                try:
                    response = self.client.request(service.health_check_method, self.resolve_url(service.health_check), timeout=0.5)
                    health_status = response.status_code
                    body = response.json()
                    if isinstance(body, dict) and response.status_code == 200 and body.get("session_id") == self.session_id and body.get("service") == service.name:
                        self._event(service.name, "health", port=ready["port"], elapsed_seconds=time.monotonic() - started_at,
                                    ready_timeout=timeout)
                        return
                    health_error = "health_contract_not_ready"
                except (httpx.HTTPError, ValueError, TypeError) as exc:
                    health_error = type(exc).__name__
            time.sleep(0.05)
        self._failure(service, "ready", started_at=started_at, ready_path=ready_path,
                      health_status=health_status, health_error=health_error,
                      failure_cause="ready_timeout", elapsed=time.monotonic() - started_at)
        raise ServiceInfrastructureError(f"service '{service.name}' did not become ready within {timeout}s")

    def reset_all(self):
        for service in self.task.services:
            try:
                response = self.client.post(self.resolve_url(service.reset_endpoint), json={})
                response.raise_for_status()
                body = response.json()
                if body.get("session_id") != self.session_id or body.get("status") != "reset":
                    raise ValueError("invalid reset response")
            except (httpx.HTTPError, ValueError) as exc:
                raise ServiceInfrastructureError(f"service '{service.name}' reset failed ({type(exc).__name__})") from None
            self._event(service.name, "reset")

    def dispatch(self, name: str, arguments) -> tuple[dict, dict]:
        endpoint = self.task.get_endpoint_map()[name]
        url = self.resolve_url(endpoint.url)
        start = time.monotonic()
        dispatch = {"endpoint_url": url, "method": endpoint.method, "response_status": None}
        try:
            response = self.client.request(endpoint.method, url, json=arguments)
            dispatch["response_status"] = response.status_code
            body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            dispatch["latency_ms"] = round((time.monotonic() - start) * 1000, 3)
            raise ServiceInfrastructureError(f"tool '{name}' transport failed ({type(exc).__name__}); outcome requires service snapshot", dispatch=dispatch) from None
        dispatch["latency_ms"] = round((time.monotonic() - start) * 1000, 3)
        if response.status_code >= 500:
            raise ServiceInfrastructureError(f"tool '{name}' service returned HTTP {response.status_code}", dispatch=dispatch)
        return body, dispatch

    def snapshot(self) -> dict:
        snapshots = {}
        for service in self.task.services:
            try:
                response = self.client.get(self.resolve_url(service.audit_endpoint))
                response.raise_for_status()
                document = response.json()
                if document.get("session_id") != self.session_id or document.get("service") != service.name:
                    raise ValueError("snapshot identity mismatch")
                if set(document["state"]) != set(PLATFORM_STATE_KEYS[service.name]) or not isinstance(document["audit"], list):
                    raise ValueError("incomplete service snapshot")
                snapshots[service.name] = document
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
                raise ServiceInfrastructureError(f"service '{service.name}' snapshot failed ({type(exc).__name__})") from None
        return snapshots

    def record_snapshot(self, snapshots):
        _dump(self.session_dir / "service_snapshots.json", snapshots)
        for name in snapshots:
            self._event(name, "snapshot")

    def close(self):
        if self.closed:
            return
        self.closed = True
        errors = []
        try:
            for service, proc, log in reversed(self.spawned):
                try:
                    if proc.poll() is None:
                        proc.terminate()
                        try:
                            proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait(timeout=5)
                except Exception as exc:
                    errors.append(type(exc).__name__)
                finally:
                    log.close()
                    try:
                        self._event(service.name, "cleanup", pid=proc.pid, returncode=proc.poll())
                    except OSError as exc:
                        errors.append(type(exc).__name__)
        finally:
            self.spawned.clear()
            self.client.close()
            atexit.unregister(self._cleanup)
        if errors:
            raise ServiceInfrastructureError("service cleanup failed: " + ", ".join(errors))
