"""Core task adapter and Claude Code process helpers.

This module is deliberately benchmark-light: the Claude process receives only
public task context and copied raw user data.  Ground truth and evaluator
files are never copied into the task workspace and are only read later by the
Unified Evaluator.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .provider_bridge import requires_protocol_bridge


REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
EVALUATION_ROOT = REPO_ROOT / "evaluation"
if str(EVALUATION_ROOT) not in sys.path:
    sys.path.insert(0, str(EVALUATION_ROOT))


READ_ONLY_TOOLS = {
    "album_search",
    "album_browse",
    "album_get_metadata",
    "image_view",
    "inspect_image",
    "people_search",
    "person_view_reference",
    "relationship_lookup",
    "owner_profile_view",
    "contacts_search",
    "threads_list",
    "thread_get",
    "albums_list",
    "album_get",
    "stories_list",
    "story_get",
    "archives_list",
    "archive_get",
    "checklists_list",
    "checklist_get",
    "calendar_search",
    "calendar_get_event",
    "calendar_get_availability",
    "reservations_list",
    "service_search",
    "service_get_details",
    "service_get_availability",
    "workspace_list",
    "workspace_read",
}

MUTATING_TOOLS = {
    "message_create_draft",
    "message_send",
    "calendar_create_event",
    "calendar_update_event",
    "publish_post",
    "workspace_write",
    "workspace_update",
    "album_create",
    "album_update",
    "album_add_images",
    "album_remove_images",
    "story_create_draft",
    "story_update_draft",
    "archive_create",
    "archive_update",
    "checklist_create",
    "checklist_add_item",
    "checklist_update_item",
    "reservation_create",
    "reservation_update",
    "reservation_cancel",
}

# This is an output mapping contract, not a tool implementation.  The Claude
# process never receives a callable/native CamAct tool.  Only the post-run
# adapter uses these field names to materialize the declared final state.
ACTION_ARGUMENTS: dict[str, list[str]] = {
    "message_create_draft": ["to", "text", "attachments", "identity_claims"],
    "message_send": ["to", "text", "attachments", "identity_claims"],
    "calendar_create_event": ["title", "start", "end", "location", "status", "participants"],
    "calendar_update_event": ["event_id", "title", "start", "end", "location", "status", "participants"],
    "publish_post": ["text", "images", "visibility"],
    "workspace_write": ["name", "content", "images", "identity_claims"],
    "workspace_update": ["name", "content", "images", "identity_claims"],
    "album_create": ["title", "description"],
    "album_update": ["album_id", "title", "description"],
    "album_add_images": ["album_id", "images"],
    "album_remove_images": ["album_id", "images"],
    "story_create_draft": ["title", "text", "images"],
    "story_update_draft": ["story_id", "title", "text", "images"],
    "archive_create": ["title", "summary", "images"],
    "archive_update": ["archive_id", "title", "summary", "images"],
    "checklist_create": ["title", "items"],
    "checklist_add_item": ["checklist_id", "text"],
    "checklist_update_item": ["checklist_id", "item_id", "text", "completed"],
    "reservation_create": ["service_id", "slot", "party_size", "notes"],
    "reservation_update": ["reservation_id", "slot", "party_size", "notes"],
    "reservation_cancel": ["reservation_id"],
}

IMAGE_RE = re.compile(r"\b[0-9]+\.(?:jpg|jpeg|png)\b", re.I)
SECRET_RE = re.compile(r"(?i)(?:sk-ant-[A-Za-z0-9_-]+|x-api-key[=: ]+[A-Za-z0-9._-]+)")


@dataclass(frozen=True)
class TaskHandle:
    user_id: str
    task_name: str
    task_dir: Path
    task_id: str


@dataclass
class ClaudeSettings:
    tool_profile: str = "native"
    model: str = ""
    provider_config_authoritative: bool = False
    base_url: str = ""
    api_key: str = ""
    distro: str = "Ubuntu-22.04"
    timeout: float = 600.0
    retries: int = 1
    parallel: int = 5
    permission_mode: str = "acceptEdits"
    allow_bash: bool = False
    request_attempts: int = 4
    agent_request_attempts: int | None = None
    agent_retry_delay: float | None = None
    task_timeout: float = 1800.0
    max_agent_turns: int = 50
    max_simulator_rounds: int = 10
    max_output_tokens: int = 2048
    simulator_max_output_tokens: int = 8192
    judge_timeout: float = 120.0
    judge_request_attempts: int = 3
    judge_max_output_tokens: int = 8192
    simulator_timeout: float = 600.0
    simulator_request_attempts: int = 4
    # Private runtime role dictionaries may contain a resolved key in memory.
    # public_dict always serializes these through the shared credential filter.
    simulator_provider: dict[str, Any] | None = None
    judge_provider: dict[str, Any] | None = None
    agent_provider: dict[str, Any] | None = None
    role_config_source: str = "legacy-flat-explicit-migration"
    claude_version: str | None = None
    executable_path: str | None = None
    runtime_roots: list[str] = field(default_factory=list)
    node_executable: str | None = None
    sandbox_backend: str = "bwrap"
    # Explicit gateway/provider aliases are allowed only when they resolve to
    # the requested control model.  Unknown aliases remain fail-closed.
    model_aliases: dict[str, str] = field(default_factory=dict)
    # Values explicitly supplied for Claude Code's model entrypoints are
    # retained so Native preflight can reject a divergent auxiliary model
    # before the task-local environment is normalized.
    configured_entrypoints: dict[str, str] = field(default_factory=dict)
    token_tracking: bool = False

    @property
    def protocol_bridge_required(self) -> bool:
        if self.agent_provider is not None:
            protocol = self.agent_provider["protocol"]
            if protocol not in {"anthropic-messages", "openai-chat"}:
                raise ValueError(f"Unsupported Claude provider protocol: {protocol}")
            return protocol == "openai-chat"
        return requires_protocol_bridge(self.model)

    @property
    def provider(self) -> str:
        return "openai-compatible-via-claude-code-bridge" if self.protocol_bridge_required else "anthropic-compatible"

    def public_dict(self) -> dict[str, Any]:
        from harness.camact_compatibility_v2.roles import public_role
        return {
            **({"token_tracking": {"enabled": True}} if self.token_tracking else {}),
            "tool_profile": self.tool_profile,
            "provider_config_authoritative": self.provider_config_authoritative,
            "model": self.model,
            "base_url": redact_url(self.base_url),
            "provider": self.provider,
            "distro": self.distro,
            "timeout": self.timeout,
            "retries": self.retries,
            "request_timeout": self.timeout,
            "request_attempts": self.request_attempts,
            "agent_request_attempts": self.agent_request_attempts or self.request_attempts,
            "agent_retry_delay": self.agent_retry_delay,
            "infrastructure_attempts": self.retries,
            "task_timeout": self.task_timeout,
            "max_agent_turns": self.max_agent_turns,
            "max_simulator_rounds": self.max_simulator_rounds,
            "max_output_tokens": self.max_output_tokens,
            "simulator_max_output_tokens": self.simulator_max_output_tokens,
            "simulator_timeout": self.simulator_timeout,
            "simulator_request_attempts": self.simulator_request_attempts,
            "simulator_provider": public_role(self.simulator_provider) if self.simulator_provider else None,
            "judge_provider": public_role(self.judge_provider) if self.judge_provider else None,
            "agent_provider": public_role(self.agent_provider) if self.agent_provider else None,
            "role_config_source": self.role_config_source,
            "judge_timeout": self.judge_timeout,
            "judge_request_attempts": self.judge_request_attempts,
            "judge_max_output_tokens": self.judge_max_output_tokens,
            "parallel": self.parallel,
            "permission_mode": self.permission_mode,
            "allow_bash": self.allow_bash,
            "claude_version": self.claude_version,
            "executable_path": self.executable_path,
            "runtime_roots": list(self.runtime_roots),
            "node_executable": self.node_executable,
            "sandbox_backend": self.sandbox_backend,
            "configured_entrypoints": dict(self.configured_entrypoints),
            "model_aliases": dict(self.model_aliases),
            "api_key": None,
            "api_key_env": "ANTHROPIC_API_KEY" if self.api_key else None,
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_name(value: Any) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", str(value)).strip("-._") or "value"


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)


def sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def redact_url(value: str) -> str:
    if not value:
        return ""
    try:
        parsed = urlsplit(value)
        query = parsed.query
        if query:
            query = urlencode([
                (key, "[REDACTED]" if any(token in key.casefold() for token in ("key", "token", "secret", "password")) else item)
                for key, item in parse_qsl(query, keep_blank_values=True)
            ])
        if parsed.username or parsed.password:
            host = parsed.hostname or ""
            if parsed.port:
                host += f":{parsed.port}"
            return urlunsplit((parsed.scheme, host, parsed.path, query, parsed.fragment))
        if query != parsed.query:
            return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))
    except ValueError:
        pass
    return SECRET_RE.sub("[REDACTED]", value)


def redact_text(value: Any, secrets: Iterable[str] = ()) -> str:
    text = str(value)
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return SECRET_RE.sub("[REDACTED]", text)


def parse_values(values: Iterable[str] | None) -> list[str]:
    result: list[str] = []
    for value in values or []:
        result.extend(item.strip() for item in str(value).split(",") if item.strip())
    return result


def benchmark_provenance(benchmark_root: Path) -> dict[str, Any]:
    manifest = benchmark_root / "benchmark_manifest.json"
    result: dict[str, Any] = {
        "benchmark_root": str(benchmark_root),
        "manifest_sha256": sha256_file(manifest),
    }
    document = read_json(manifest, {})
    if isinstance(document, dict):
        result.update({
            "release_id": document.get("release_id"),
            "release_version": document.get("release_version") or document.get("updated_at"),
            "task_count": document.get("task_count"),
        })
    # A deterministic public snapshot hash covers task identity/contracts
    # without hashing or exposing ground-truth/evaluator files.
    task_digest = hashlib.sha256()
    for path in sorted((benchmark_root / "tasks").glob("*/task_*/task_spec.json")):
        task_digest.update(str(path.relative_to(benchmark_root)).replace("\\", "/").encode("utf-8"))
        task_digest.update(path.read_bytes())
    result["task_specs_sha256"] = task_digest.hexdigest()
    manifest_hash = result.get("manifest_sha256")
    if manifest_hash:
        # The current benchmark manifest predates explicit release labels.
        # Derive a stable public release identity from its immutable hash.
        release_id = result.get("release_id") or f"manifest-{str(manifest_hash)[:12]}"
        release_version = result.get("release_version") or release_id
        result["release_id"] = release_id
        result["release_version"] = release_version
        result["benchmark_release_id"] = release_id
        result["benchmark_release_version"] = release_version
        result["benchmark_manifest_sha256"] = manifest_hash
    return result


def harness_commit() -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(REPO_ROOT / "harness"), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        value = completed.stdout.strip()
        return value or None
    except (OSError, subprocess.SubprocessError):
        return None


def claude_runtime_info() -> dict[str, Any]:
    """Return version and executable path from the runtime actually used."""
    executable = "claude.cmd" if os.name == "nt" else "claude"
    info: dict[str, Any] = {"executable": executable}
    try:
        path_cmd = ["where", executable] if os.name == "nt" else ["which", executable]
        path_result = subprocess.run(path_cmd, capture_output=True, text=True, timeout=10, check=False)
        info["path"] = path_result.stdout.strip().splitlines()[0] if path_result.stdout.strip() else None
    except (OSError, subprocess.SubprocessError):
        info["path"] = None
    try:
        version_result = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=20, check=False)
        info["version"] = version_result.stdout.strip() or version_result.stderr.strip()
        info["returncode"] = version_result.returncode
    except (OSError, subprocess.SubprocessError) as exc:
        info["version"] = None
        info["error"] = f"{type(exc).__name__}: {exc}"
    return info


def load_settings(args: Any, file_config: dict[str, Any]) -> ClaudeSettings:
    """Resolve settings; an explicit authoritative provider overrides ambient env."""
    from harness.camact_compatibility_v2.roles import role_provider
    file_config = dict(file_config)
    for role in ("agent", "simulator", "judge"):
        if isinstance(file_config.get(role), dict) and role + "_provider" not in file_config:
            file_config[role + "_provider"] = file_config[role]
    agent_role = None
    if "agent_provider" in file_config:
        raw = file_config["agent_provider"]
        if not isinstance(raw, dict) or not raw:
            raise ValueError("agent_provider must be a complete independent provider configuration")
        raw = dict(raw)
        for field in ("model", "base_url", "api_key", "api_key_env"):
            override = getattr(args, field, None)
            if override not in (None, ""):
                raw[field] = override
                if field == "api_key_env":
                    raw.pop("api_key", None)
        for cli_field, role_field in (("timeout", "timeout_seconds"), ("request_attempts", "retry_attempts"),
                                      ("max_output_tokens", "max_output_tokens")):
            if getattr(args, cli_field, None) is not None:
                raw[role_field] = getattr(args, cli_field)
        agent_role = role_provider(raw, role="agent", protocol="anthropic-messages")
        if agent_role["max_output_tokens"] is None:
            raise ValueError("Claude Agent requires an explicit positive max_output_tokens")
        if agent_role.get("parameters"):
            raise ValueError("Claude telemetry adapter does not support arbitrary Agent parameters")
        file_config = {**file_config, "provider_config_authoritative": True,
            "model": agent_role["model"], "base_url": agent_role["base_url"], "api_key": agent_role["api_key"],
            "timeout": agent_role["timeout_seconds"], "request_attempts": agent_role["retry_attempts"],
            "max_output_tokens": agent_role["max_output_tokens"]}
    authoritative = bool(file_config.get("provider_config_authoritative", False))
    def pick(cli: Any, env_names: tuple[str, ...], key: str, default: Any = "") -> Any:
        if cli not in (None, ""):
            return cli
        if authoritative and key in {"model", "base_url", "api_key"} and file_config.get(key):
            return file_config[key]
        for name in env_names:
            if os.environ.get(name):
                return os.environ[name]
        return file_config.get(key, default)

    api_key_env = str(getattr(args, "api_key_env", None) or "").strip()
    if api_key_env:
        api_key = os.environ.get(api_key_env, "")
        if not api_key:
            raise ValueError(f"environment variable {api_key_env} is not set")
    else:
        api_key = str(pick(getattr(args, "api_key", None), ("ANTHROPIC_API_KEY",), "api_key", "") or "")
    base_url = str(pick(getattr(args, "base_url", None), ("ANTHROPIC_BASE_URL",), "base_url", "") or "")
    model = str(pick(getattr(args, "model", None), ("CLAUDE_CODE_MODEL", "ANTHROPIC_MODEL"), "model", "") or "")
    policy_config = file_config.get("model_policy", {})
    policy_config = policy_config if isinstance(policy_config, dict) else {}
    raw_aliases = file_config.get("model_aliases", policy_config.get("aliases", {}))
    model_aliases = (
        {str(key): str(value) for key, value in raw_aliases.items() if str(key).strip() and str(value).strip()}
        if isinstance(raw_aliases, dict) else {}
    )
    model_entrypoint_config_keys: dict[str, tuple[str, ...]] = {
        "ANTHROPIC_MODEL": ("anthropic_model",),
        "CLAUDE_CODE_MODEL": ("claude_code_model",),
        "ANTHROPIC_SMALL_FAST_MODEL": ("anthropic_small_fast_model", "small_fast_model"),
        "CLAUDE_CODE_SMALL_FAST_MODEL": ("claude_code_small_fast_model", "small_fast_model"),
        "CLAUDE_CODE_SUBAGENT_MODEL": ("claude_code_subagent_model", "subagent_model"),
        "CLAUDE_CODE_FALLBACK_MODEL": ("claude_code_fallback_model", "fallback_model"),
        "ANTHROPIC_FALLBACK_MODEL": ("anthropic_fallback_model", "fallback_model"),
        "CLAUDE_CODE_UTILITY_MODEL": ("claude_code_utility_model", "utility_model"),
        "ANTHROPIC_UTILITY_MODEL": ("anthropic_utility_model", "utility_model"),
        "CLAUDE_CODE_PRIMARY_MODEL": ("claude_code_primary_model", "primary_model"),
    }
    configured_entrypoints: dict[str, str] = {}
    for entrypoint, keys in model_entrypoint_config_keys.items():
        environment_value = None if authoritative else os.environ.get(entrypoint)
        if environment_value:
            configured_entrypoints[entrypoint] = str(environment_value)
        for key in (*keys, entrypoint):
            candidate = file_config.get(key)
            if candidate in (None, ""):
                candidate = policy_config.get(key)
            if candidate in (None, ""):
                continue
            config_name = entrypoint if not environment_value else f"config.{entrypoint}"
            configured_entrypoints[config_name] = str(candidate)
            break
        nested_entrypoints = policy_config.get("configured_entrypoints", {})
        if isinstance(nested_entrypoints, dict):
            nested_value = nested_entrypoints.get(entrypoint)
            if nested_value not in (None, ""):
                configured_entrypoints[f"config.{entrypoint}"] = str(nested_value)
    distro = str(pick(getattr(args, "distro", None), ("CAMACT_CLAUDE_WSL_DISTRO",), "distro", "Ubuntu-22.04") or "Ubuntu-22.04")
    timeout_value = pick(getattr(args, "timeout", None), ("CAMACT_CLAUDE_TIMEOUT",), "timeout", 600.0)
    retries_value = pick(getattr(args, "retries", None), ("CAMACT_CLAUDE_RETRIES",), "retries", 1)
    parallel_value = pick(getattr(args, "parallel", None), ("CAMACT_CLAUDE_PARALLEL",), "parallel", 5)
    request_attempts_value = pick(getattr(args, "request_attempts", None), (), "request_attempts", 4)
    task_timeout_value = pick(getattr(args, "task_timeout", None), (), "task_timeout", 1800.0)
    timeout = float(600.0 if timeout_value in (None, "") else timeout_value)
    retries = int(1 if retries_value in (None, "") else retries_value)
    parallel = int(5 if parallel_value in (None, "") else parallel_value)
    request_attempts = int(4 if request_attempts_value in (None, "") else request_attempts_value)
    task_timeout = float(1800.0 if task_timeout_value in (None, "") else task_timeout_value)
    agent_attempts_value = pick(getattr(args, "agent_request_attempts", None), (), "agent_request_attempts", None)
    agent_delay_value = pick(getattr(args, "agent_retry_delay", None), (), "agent_retry_delay", None)
    agent_request_attempts = int(agent_attempts_value) if agent_attempts_value is not None else None
    agent_retry_delay = float(agent_delay_value) if agent_delay_value is not None else None
    if agent_request_attempts is not None and agent_request_attempts < 1:
        raise ValueError("agent request attempts must be >= 1")
    if agent_retry_delay is not None and agent_retry_delay < 0:
        raise ValueError("agent retry delay must be >= 0")
    permission_mode = str(pick(getattr(args, "permission_mode", None), (), "permission_mode", "acceptEdits") or "acceptEdits")
    allow_bash = bool(getattr(args, "allow_bash", False) or file_config.get("allow_bash", False))
    if timeout <= 0 or retries < 1 or parallel < 1 or request_attempts < 1 or task_timeout <= 0:
        raise ValueError("timeouts must be > 0 and attempt/parallel counts must be >= 1")
    from .tool_profiles import validate_profile
    tool_profile = validate_profile(str(pick(getattr(args, "tool_profile", None), ("CAMACT_CLAUDE_TOOL_PROFILE",), "tool_profile", "native")))
    limits = {key: cast(pick(getattr(args, key, None), (), key, default))
              for key, cast, default in (
                  ("max_agent_turns", int, 50), ("max_simulator_rounds", int, 10),
                  ("max_output_tokens", int, 2048), ("simulator_max_output_tokens", int, 8192),
                  ("judge_timeout", float, 120.0), ("judge_request_attempts", int, 3),
                  ("judge_max_output_tokens", int, 8192),
                  ("simulator_timeout", float, timeout),
                  ("simulator_request_attempts", int, request_attempts))}
    if any(value <= 0 for value in limits.values()):
        raise ValueError("generation, output, simulator and judge limits must be positive")
    settings = ClaudeSettings(
        **limits,
        tool_profile=tool_profile,
        provider_config_authoritative=authoritative,
        model=model,
        base_url=base_url,
        api_key=api_key,
        distro=distro,
        timeout=timeout,
        retries=retries,
        parallel=parallel,
        permission_mode=permission_mode,
        allow_bash=allow_bash,
        request_attempts=request_attempts,
        agent_request_attempts=agent_request_attempts,
        agent_retry_delay=agent_retry_delay,
        task_timeout=task_timeout,
        configured_entrypoints=configured_entrypoints,
        model_aliases=model_aliases,
        agent_provider=agent_role,
    )
    from harness.camact_token_usage_v1.collector import enabled
    settings.token_tracking = enabled(file_config, getattr(args, "token_tracking", None))
    explicit_roles = False
    for name in ("simulator", "judge"):
        key = name + "_provider"
        if key in file_config:
            explicit_roles = True
            role = file_config[key]
            if not isinstance(role, dict) or not role:
                raise ValueError(f"{key} must be a complete independent provider configuration")
            role = dict(role)
            for suffix, role_field in (("timeout", "timeout_seconds"), ("request_attempts", "retry_attempts"),
                                       ("max_output_tokens", "max_output_tokens")):
                cli_field = f"{name}_{suffix}"
                if getattr(args, cli_field, None) is not None:
                    role[role_field] = getattr(args, cli_field)
            normalized = role_provider(role, role=name, protocol="openai-chat")
            setattr(settings, key, normalized)
            if name == "simulator":
                settings.simulator_timeout = normalized["timeout_seconds"]
                settings.simulator_max_output_tokens = normalized["max_output_tokens"]
                settings.simulator_request_attempts = normalized["retry_attempts"]
            else:
                settings.judge_timeout = normalized["timeout_seconds"]
                settings.judge_max_output_tokens = normalized["max_output_tokens"]
                settings.judge_request_attempts = normalized["retry_attempts"]
        elif settings.base_url and settings.api_key:
            # Explicit compatibility contract for the old flat configuration;
            # new role dictionaries are never filled from another role.
            base = settings.base_url.rstrip("/")
            if not base.endswith("/v1"):
                base += "/v1"
            raw = {"provider": "relay", "model": settings.model, "base_url": base,
                   "api_key": settings.api_key, "protocol": "openai-chat",
                   "timeout_seconds": settings.simulator_timeout if name == "simulator" else settings.judge_timeout,
                   "max_output_tokens": settings.simulator_max_output_tokens if name == "simulator" else settings.judge_max_output_tokens,
                   "retry_attempts": settings.simulator_request_attempts if name == "simulator" else settings.judge_request_attempts}
            setattr(settings, key, role_provider(raw, role=name, protocol="openai-chat"))
    settings.role_config_source = "independent-role-config" if explicit_roles else "legacy-flat-explicit-migration"
    return settings


def task_handles(benchmark_root: Path, users: list[str] | None = None, tasks: list[str] | None = None) -> list[TaskHandle]:
    tasks_root = benchmark_root / "tasks"
    if not tasks_root.is_dir():
        raise ValueError(f"tasks directory does not exist: {tasks_root}")
    selected_users = users or sorted(path.name for path in tasks_root.iterdir() if path.is_dir())
    requested = set(tasks or [])
    handles: list[TaskHandle] = []
    for user_id in selected_users:
        user_root = tasks_root / user_id
        if not user_root.is_dir():
            raise ValueError(f"unknown CamAct user: {user_id}")
        for task_dir in sorted(path for path in user_root.glob("task_*") if path.is_dir()):
            spec = read_json(task_dir / "task_spec.json", {})
            if not isinstance(spec, dict):
                continue
            task_id = str(spec.get("task_id") or task_dir.name)
            if requested and task_dir.name not in requested and task_id not in requested:
                continue
            handles.append(TaskHandle(user_id, task_dir.name, task_dir, task_id))
    if requested and not handles:
        raise ValueError(f"no tasks matched: {sorted(requested)}")
    return handles


def _copy_tree_readonly(source: Path, target: Path) -> None:
    """Copy raw data without symlinks; hardlinks keep large albums affordable."""
    target.mkdir(parents=True, exist_ok=True)
    for item in source.iterdir():
        destination = target / item.name
        if item.is_dir() and not item.is_symlink():
            _copy_tree_readonly(item, destination)
            try:
                destination.chmod(0o555)
            except OSError:
                pass
        elif item.is_file():
            destination.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(item, destination)
            except OSError:
                shutil.copy2(item, destination)
            try:
                destination.chmod(0o444)
            except OSError:
                pass


def _public_action_contract(allowed_tools: list[str]) -> dict[str, Any]:
    actions = {}
    for name in allowed_tools:
        if name in MUTATING_TOOLS:
            actions[name] = {
                "arguments": ACTION_ARGUMENTS.get(name, []),
                "description": "Declare the final state-changing action; it is applied after Claude exits.",
            }
    return {"allowed_actions": actions, "read_only_capabilities": [name for name in allowed_tools if name not in MUTATING_TOOLS]}


def result_schema(allowed_tools: list[str]) -> dict[str, Any]:
    action_names = [name for name in allowed_tools if name in MUTATING_TOOLS]
    action_properties: dict[str, Any] = {
        "tool": {"type": "string", "enum": action_names} if action_names else {"type": "string"},
        "arguments": {"type": "object"},
        "status": {"type": "string"},
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "final_response": {"type": "string"},
            "evidence": {"type": "array", "items": {"type": "string"}},
            "actions": {"type": "array", "items": {"type": "object", "properties": action_properties, "required": ["tool", "arguments"], "additionalProperties": True}},
            "artifacts": {"type": "array", "items": {"type": "object"}},
            "user_messages": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["final_response", "evidence", "actions"],
    }


def build_task_workspace(handle: TaskHandle, workspace: Path) -> dict[str, Any]:
    """Materialize only user-visible inputs into a fresh per-task directory."""
    if workspace.exists():
        raise FileExistsError(f"task workspace already exists: {workspace}")
    workspace.mkdir(parents=True)
    data_dir = workspace / "data"
    user_memory = handle.task_dir.parents[2] / "users" / handle.user_id / "base_memory"
    # ``parents[2]`` is benchmark/tasks/<user>/task; benchmark root is parents[2].
    if not user_memory.is_dir():
        raise FileNotFoundError(f"raw user memory is missing: {user_memory}")
    _copy_tree_readonly(user_memory, data_dir)

    spec = read_json(handle.task_dir / "task_spec.json", {})
    initial = read_json(handle.task_dir / "conversation" / "initial_message.json", {})
    history = read_json(handle.task_dir / "conversation" / "history.json", {})
    state = read_json(handle.task_dir / "workspace" / "state.json", {})
    public_spec = {
        "task_id": handle.task_id,
        "interaction_type": spec.get("interaction_type", "single_turn_agentic"),
        "user_query": spec.get("user_query", initial.get("content", "") if isinstance(initial, dict) else ""),
    }
    allowed_tools = [str(name) for name in spec.get("allowed_tools", []) if isinstance(name, str)]
    context_dir = workspace / "context"
    context_dir.mkdir()
    write_json(context_dir / "task.json", public_spec)
    write_json(context_dir / "initial_message.json", initial if isinstance(initial, dict) else {})
    write_json(context_dir / "history.json", history if isinstance(history, dict) else {})
    fixtures = state.get("fixtures", {}) if isinstance(state, dict) else {}
    # Runtime fixtures can contain hybrid-simulator hidden_state and reveal
    # policy. Those fields are evaluator/runtime internals, never user data,
    # so omit the complete simulator object from Claude's exposed workspace.
    public_fixtures = {
        key: value
        for key, value in (fixtures.items() if isinstance(fixtures, dict) else [])
        if key != "user_simulator"
    }
    write_json(workspace / "workspace" / "initial_state.json", public_fixtures)
    write_json(workspace / "workspace" / "allowed_actions.json", _public_action_contract(allowed_tools))
    schema = result_schema(allowed_tools)
    write_json(workspace / "output" / "result.schema.json", schema)
    task_md = "\n".join([
        "# CamAct Task",
        "",
        "Use only the files in this workspace. The `data/` directory contains copied raw user memory; `context/` contains the user request and any visible conversation; `workspace/initial_state.json` contains public fixture state.",
        "",
        "Read metadata before opening candidate images. Use Claude Code's file tools to inspect raw images directly. No CamAct album/search/message tool is available in this session.",
        "",
        "When finished, write `output/result.json` using `output/result.schema.json`. Evidence must contain only image filenames you actually inspected. Actions are declarations only and will be materialized by the harness after this process exits.",
        "Do not inspect, create, or reference paths outside this workspace. Do not look for benchmark, ground-truth, rubric, evaluator, or other task data.",
        "",
        f"Task id: {handle.task_id}",
        f"Interaction type: {public_spec['interaction_type']}",
        f"User request: {public_spec['user_query']}",
        "",
        *(
            [
                "If required information is missing, ask exactly one clarification by writing it to the optional `user_messages` array in `output/result.json`. The harness will return only the authorized simulator reply and resume this same session. After receiving the reply, replace the provisional result with the completed result and leave `user_messages` empty or omit it.",
                "",
            ]
            if public_spec["interaction_type"] == "simulated_multi_turn"
            else []
        ),
        "Allowed action declarations:",
        json.dumps(_public_action_contract(allowed_tools), ensure_ascii=False, indent=2),
    ])
    (workspace / "TASK.md").write_text(task_md + "\n", encoding="utf-8")
    manifest = {
        "schema_version": "camact.claude_task_workspace.v1",
        "user_id": handle.user_id,
        "task_name": handle.task_name,
        "task_id": handle.task_id,
        "files": [
            "TASK.md",
            "context/task.json",
            "context/initial_message.json",
            "context/history.json",
            "data/",
            "workspace/initial_state.json",
            "workspace/allowed_actions.json",
            "output/result.schema.json",
            "output/result.json (agent-created)",
        ],
        "excluded": ["ground_truth/", "evaluator_config.json", "task_spec.json", "tools.json", "benchmark/", "evaluation/", "user_simulator.hidden_state"],
    }
    write_json(workspace / "workspace_manifest.json", manifest)
    return {"public_spec": public_spec, "allowed_tools": allowed_tools, "workspace_manifest": manifest}


def build_prompt(workspace: Path) -> str:
    return (
        "Complete the CamAct user request in the current task-scoped workspace. "
        "Use only Read, Write, Edit, Glob, and Grep file capabilities available in this session; "
        "do not access a parent directory or any path outside the workspace. "
        "Inspect raw images yourself when the request depends on visual evidence. "
        "Do not invent image IDs or facts from filenames alone. "
        "Do not search for benchmark, ground truth, rubric, evaluator, or other task data. "
        "Declare intended state-changing actions in output/result.json; the harness will apply them only after you exit. "
        "The final response must be concise and the JSON file must conform to output/result.schema.json."
    )


def claude_command(
    settings: ClaudeSettings,
    prompt: str,
    schema: dict[str, Any],
    *,
    session_id: str | None = None,
    resume_session_id: str | None = None,
) -> list[str]:
    if session_id and resume_session_id:
        raise ValueError("session_id and resume_session_id are mutually exclusive")
    command = [
        "claude.cmd" if os.name == "nt" else "claude",
        "--print",
        "--output-format",
        "stream-json",
        "--verbose",
        "--include-partial-messages",
        "--setting-sources",
        "local",
        "--strict-mcp-config",
        "--disable-slash-commands",
        "--model",
        settings.model,
        "--permission-mode",
        settings.permission_mode,
        "--tools",
        "Read,Write,Edit,Glob,Grep" + (",Bash" if settings.allow_bash else ""),
    ]
    if resume_session_id:
        command.extend(["--resume", resume_session_id])
    elif session_id:
        command.extend(["--session-id", session_id])
    else:
        command.append("--no-session-persistence")
    command.extend(["--", prompt])
    return command


def parse_stream(stdout: str) -> tuple[dict[str, Any] | None, list[dict[str, Any]], dict[str, Any]]:
    """Parse Claude stream-json without depending on a particular minor version."""
    events: list[dict[str, Any]] = []
    structured: dict[str, Any] | None = None
    metadata: dict[str, Any] = {}
    for line in stdout.splitlines():
        raw = line.strip()
        if not raw or not raw.startswith("{"):
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        events.append(event)
        if event.get("session_id"):
            metadata["session_id"] = event["session_id"]
        if event.get("type") == "result":
            metadata.update({key: event.get(key) for key in ("usage", "duration_ms", "num_turns", "total_cost_usd", "modelUsage", "is_error", "subtype", "errors") if key in event})
            candidate = event.get("structured_output")
            if isinstance(candidate, dict):
                structured = candidate
            elif isinstance(event.get("result"), dict):
                structured = event["result"]
            elif isinstance(event.get("result"), str):
                metadata["result_text"] = event["result"]
        if isinstance(event.get("structured_output"), dict):
            structured = event["structured_output"]
    return structured, events, metadata


def inspected_images(events: list[dict[str, Any]], workspace: Path) -> list[str]:
    found: list[str] = []
    root = workspace.resolve()
    for event in events:
        candidates: list[tuple[str, Any]] = []
        if event.get("type") == "assistant":
            message = event.get("message", event)
            content = message.get("content", []) if isinstance(message, dict) else []
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "tool_use":
                        candidates.append((str(item.get("name", "")), item.get("input", {})))
        if event.get("type") == "tool_use":
            candidates.append((str(event.get("name", "")), event.get("input", {})))
        for name, payload in candidates:
            if name.casefold() != "read" or not isinstance(payload, dict):
                continue
            path_value = payload.get("file_path") or payload.get("path")
            if not isinstance(path_value, str):
                continue
            candidate = Path(path_value)
            if not candidate.is_absolute():
                candidate = root / candidate
            try:
                resolved = candidate.resolve()
                resolved.relative_to(root)
            except (OSError, ValueError):
                continue
            if resolved.suffix.casefold() not in {".jpg", ".jpeg", ".png"}:
                continue
            if resolved.parent.name != "images":
                continue
            name_value = resolved.name
            if name_value not in found:
                found.append(name_value)
    return found


def extract_result_from_workspace(workspace: Path, structured: dict[str, Any] | None, events: list[dict[str, Any]], metadata: dict[str, Any]) -> dict[str, Any] | None:
    result_path = workspace / "output" / "result.json"
    value = read_json(result_path, None)
    if isinstance(value, dict):
        return value
    if isinstance(structured, dict):
        return structured
    text = metadata.get("result_text")
    if isinstance(text, str):
        # A model occasionally wraps the JSON in a markdown fence despite the
        # schema flag.  Only accept a complete JSON object, never heuristics.
        match = re.search(r"\{.*\}", text, flags=re.S)
        if match:
            candidate = read_json_from_text(match.group(0))
            if isinstance(candidate, dict):
                return candidate
    return None


def read_json_from_text(value: str) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None
