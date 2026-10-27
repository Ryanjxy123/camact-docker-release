"""Deployment settings for three independent model roles; keys stay in memory."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

METHODS = ("baseline", "claude", "codex", "opencode", "deepseek", "openclaw")
ALIASES = {"canonical-baseline": "baseline", "claude-code": "claude", "codex-cli": "codex", "dsh": "deepseek"}
VERSIONS = {"claude": "2.1.160", "codex": "0.147.0", "opencode": "2.0.32", "deepseek": "0.2.1-rc.2", "openclaw": "2026.6.11"}
DEFAULT_PROTOCOL = {"baseline": "openai-chat", "claude": "anthropic-messages", "codex": "openai-responses", "opencode": "anthropic-messages", "deepseek": "deepseek-messages", "openclaw": "anthropic-messages"}
PROJECT = Path(__file__).resolve().parents[1]


def methods(value: str) -> list[str]:
    requested = list(METHODS) if value == "all" else [ALIASES.get(x.strip(), x.strip()) for x in value.split(",")]
    if not requested or any(x not in METHODS for x in requested) or len(set(requested)) != len(requested):
        raise ValueError("Harness must be all or a unique comma-separated subset of " + ",".join(METHODS))
    return [x for x in METHODS if x in requested]


def _value(prefix: str, field: str, harness: str | None = None, default=None):
    override = os.environ.get(f"{prefix}_{field}_{harness.upper()}") if harness else None
    return override if override not in (None, "") else os.environ.get(f"{prefix}_{field}") or default


def _number(prefix, field, harness, default, *, integral=False):
    value = _value(prefix, field, harness, default)
    return int(value) if integral else float(value)


def _object(prefix, field, harness=None):
    value = json.loads(_value(prefix, field, harness, "{}"))
    if not isinstance(value, dict):
        raise ValueError(f"{prefix}_{field} must be a JSON object")
    return value


def load_secrets():
    """Accept external secret files or explicit environment injection, never HOME."""
    for prefix in ("AGENT", "JUDGE", "SIMULATOR"):
        for suffix in ("", *("_" + name.upper() for name in METHODS)) if prefix == "AGENT" else ("",):
            destination = prefix + "_API_KEY" + suffix
            filename = os.environ.get(prefix + "_API_KEY_FILE" + suffix)
            if filename:
                path = Path(filename)
                if not path.is_file() or path.is_symlink():
                    raise ValueError(f"{prefix} secret file must be an existing regular file")
                value = path.read_text(encoding="utf-8").strip()
                if not value or "\n" in value or "\r" in value:
                    raise ValueError(f"{prefix} secret file must contain one nonempty key")
                os.environ[destination] = value


def secret_values():
    return [v for k, v in os.environ.items() if v and k.startswith(("AGENT_API_KEY", "JUDGE_API_KEY", "SIMULATOR_API_KEY")) and "FILE" not in k]


def redact(value):
    value = str(value)
    for secret in secret_values():
        value = value.replace(secret, "[REDACTED]")
    return value


def _role(role: str, harness: str | None = None):
    prefix = role.upper()
    default_protocol = DEFAULT_PROTOCOL[harness] if harness else "openai-chat"
    key_env = prefix + "_API_KEY"
    if harness and (os.environ.get(key_env + "_" + harness.upper()) or os.environ.get(prefix + "_API_KEY_FILE_" + harness.upper())):
        key_env += "_" + harness.upper()
    value = {"provider": _value(prefix, "PROVIDER", harness, "configured"),
             "model": _value(prefix, "MODEL", harness, ""),
             "base_url": _value(prefix, "BASE_URL", harness, ""),
             "api_key_env": key_env, "protocol": _value(prefix, "PROTOCOL", harness, default_protocol),
             "timeout_seconds": _number(prefix, "TIMEOUT_SECONDS", harness, 120 if role == "judge" else 600),
             "max_output_tokens": _number(prefix, "MAX_OUTPUT_TOKENS", harness, 2048 if role == "agent" else 8192, integral=True),
             "parameters": _object(prefix, "PARAMETERS", harness)}
    # These native CLIs own retry policy. The validated adapter rejects an
    # override instead of silently changing official model-request behavior.
    if (not harness or harness in {"baseline", "claude"}
            or os.environ.get(f"{prefix}_RETRY_ATTEMPTS_{harness.upper()}")):
        value["retry_attempts"] = _number(prefix, "RETRY_ATTEMPTS", harness, 3 if role == "judge" else 4, integral=True)
    options = _object(prefix, "MODEL_OPTIONS", harness)
    if options:
        value["model_options"] = options
    return value


def build(snapshot: Path):
    root = PROJECT / ".tools"
    harnesses = {}
    for name in METHODS:
        item = {"provider": _role("agent", name)}
        if name != "baseline":
            command = "dsh" if name == "deepseek" else name
            item.update(executable=str(root / name / "node_modules/.bin" / command), version=VERSIONS[name],
                        runtime_roots=[str(root / name), str(root / "node")],
                        node_executable=str(root / "node/bin/node"), sandbox_backend="gvisor", legacy_config=None)
        if name == "openclaw":
            item["openclaw_home_backend"] = "tmpfs"
        harnesses[name] = item
    return {"schema_version": "camact.multi_harness_config.v1", "benchmark_root": str(snapshot),
            "tool_profile": "native", "album_extensions": {"enabled": False},
            "limits": {"task_timeout_seconds": _number("CAMACT", "TASK_TIMEOUT_SECONDS", None, 1800),
                       "request_timeout_seconds": 600, "max_model_requests": 100, "max_agent_turns": 50,
                       "max_simulator_rounds": 10, "max_output_tokens": 2048, "request_attempts": 4, "infrastructure_attempts": 1},
            "simulator": _role("simulator"), "judge": _role("judge"), "harnesses": harnesses,
            "evaluation": {"python": os.environ.get("CAMACT_EVALUATOR_PYTHON", os.sys.executable), "required_version": "3.13"},
            "token_tracking": {"enabled": True}, "distro": "Linux"}


def validate(config, selected, *, require_keys=True):
    from harness.camact_compatibility_v2.roles import role_provider, provider_config
    from camact_multi.config import provider_ready
    from camact_multi.coordinator import execution_limits
    for name in selected:
        provider = config["harnesses"][name]["provider"]
        provider_ready(name, provider, require_key=require_keys)
        execution_limits(config, config["harnesses"][name], name=name)
        if name == "claude" and provider.get("parameters"):
            raise ValueError("Claude's existing adapter does not support arbitrary Agent parameters")
        if name == "baseline":
            supported = {"openai-chat": {"temperature", "top_p", "seed"}, "anthropic-messages": {"temperature", "top_p", "thinking"}}
            if set(provider.get("parameters", {})) - supported[provider["protocol"]]:
                raise ValueError("Unsupported Baseline model parameters for the selected protocol")
    for name in ("simulator", "judge"):
        role_provider(config[name], role=name, protocol="openai-chat", require_key=require_keys)
        if config[name].get("parameters") not in ({}, {"temperature": 0}):
            raise ValueError(f"{name} supports its existing temperature=0 policy only")
    if require_keys:
        provider_config(config["simulator"])


def identifier(config):
    return hashlib.sha256(json.dumps(config, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
