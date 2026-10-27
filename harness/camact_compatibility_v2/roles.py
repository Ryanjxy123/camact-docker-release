"""Explicit independent model roles and secret-safe provider configuration."""
from __future__ import annotations

from contextlib import contextmanager
import math
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

_DEFAULTS = {
    "agent": (600.0, 2048, 4),
    "simulator": (600.0, 8192, 4),
    "judge": (120.0, 8192, 3),
}
PROTOCOLS = {"openai-chat", "openai-responses", "anthropic-messages", "deepseek-messages", "google-generative-language"}
_PARAMETERS = {"temperature", "top_p", "seed", "thinking", "reasoning"}
_SECRET_KEYS = {"api_key", "apikey", "authorization", "password", "secret", "access_token", "cookie"}


def role_provider(config: dict, *, role="agent", protocol=None, require_key=True) -> dict:
    """Validate one role; never choose another role or substitute a model."""
    if role not in _DEFAULTS or not isinstance(config, dict):
        raise ValueError(f"Invalid {role} model configuration")
    if isinstance(config.get("roles"), dict):
        config = config["roles"].get(role, {})
    elif isinstance(config.get(role), dict):
        config = config[role]
    raw = dict(config)
    for name in ("provider", "model", "base_url"):
        if not isinstance(raw.get(name), str) or not raw[name].strip():
            raise ValueError(f"{role}.{name} is required")
    actual_protocol = raw.get("protocol") or protocol
    if actual_protocol not in PROTOCOLS or (protocol and actual_protocol != protocol):
        raise ValueError(f"{role}: unsupported/incompatible protocol {actual_protocol!r}; expected {protocol!r}")
    base = raw["base_url"].rstrip("/")
    parsed = urlsplit(base)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(f"{role}.base_url must be HTTP(S), without credentials/query/fragment")
    key_env = raw.get("api_key_env")
    if key_env and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(key_env)):
        raise ValueError(f"{role}.api_key_env is invalid")
    key = raw.get("api_key") or (os.environ.get(key_env, "") if key_env else "")
    if require_key and not key:
        raise ValueError(f"{role}: missing credential; set {key_env or 'api_key_env'}")
    timeout_default, tokens_default, retry_default = _DEFAULTS[role]
    timeout = raw.get("timeout_seconds", raw.get("timeout", timeout_default))
    tokens = raw.get("max_output_tokens", tokens_default)
    attempts = raw.get("retry_attempts", raw.get("request_attempts", raw.get("attempts", retry_default)))
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError(f"{role}.timeout_seconds must be finite and positive")
    if tokens is not None and (type(tokens) is not int or tokens < 1):
        raise ValueError(f"{role}.max_output_tokens must be positive or explicitly null")
    if type(attempts) is not int or attempts < 1:
        raise ValueError(f"{role}.retry_attempts must be positive")
    parameters = raw.get("parameters", {})
    if not isinstance(parameters, dict) or set(parameters) - _PARAMETERS:
        raise ValueError(f"{role}: unsupported model parameters: {sorted(set(parameters or {}) - _PARAMETERS)}")
    return {**raw, "provider": raw["provider"].strip(), "model": raw["model"].strip(), "protocol": actual_protocol,
            "base_url": base, "api_key_env": key_env, "api_key": key, "timeout_seconds": float(timeout),
            "max_output_tokens": tokens, "retry_attempts": attempts, "parameters": dict(parameters)}


def public_role(config):
    """Remove inline values and accidental copies of this role's secret."""
    secrets = tuple(str(config[k]) for k in _SECRET_KEYS if config.get(k)) if isinstance(config, dict) else ()
    return public_config(config, secrets=secrets)


def public_config(value, *, secrets=()):
    if isinstance(value, dict):
        return {k: public_config(v, secrets=secrets) for k, v in value.items()
                if not isinstance(k, str) or k.lower() not in _SECRET_KEYS}
    if isinstance(value, (tuple, list)):
        return [public_config(v, secrets=secrets) for v in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, "[REDACTED]")
        return value
    return value


def provider_config(role: dict, *, telemetry_path=None, task_key=None):
    """Use the existing benchmark Chat adapter; reject unsupported promises."""
    from benchmark.benchmark_runner.mllm_adapter import ProviderConfig
    role = role_provider(role, role="simulator", protocol="openai-chat")
    # complete_text has a fixed, audited temperature/seed policy. Changing it
    # requires a protocol implementation, not silently ignoring settings.
    parameters = role.get("parameters", {})
    if parameters and parameters != {"temperature": 0}:
        raise ValueError("Simulator complete_text supports only its existing temperature=0 and supplied seed")
    base = role["base_url"]
    if not base.endswith("/v1"):
        base += "/v1"
    return ProviderConfig(provider="relay", model=role["model"], api_base=base, api_key=role["api_key"],
                          timeout_seconds=role["timeout_seconds"], max_output_tokens=role["max_output_tokens"],
                          retry_attempts=role["retry_attempts"], telemetry_path=str(telemetry_path) if telemetry_path else None,
                          wire_path=str(Path(telemetry_path).parent / "simulator_provider_wire.jsonl") if telemetry_path else None,
                          task_key=task_key)


@contextmanager
def judge_environment(role):
    role = role_provider(role, role="judge", protocol="openai-chat")
    if role.get("parameters") and role["parameters"] != {"temperature": 0}:
        raise ValueError("The existing Judge supports fixed temperature=0; other parameters are unsupported")
    if role["max_output_tokens"] is None:
        raise ValueError("Judge requires an explicit max_output_tokens")
    values = {"CAMACT_JUDGE_BASE_URL": role["base_url"], "CAMACT_JUDGE_MODEL": role["model"],
              "CAMACT_JUDGE_API_KEY_ENV": "CAMACT_JUDGE_API_KEY", "CAMACT_JUDGE_API_KEY": role["api_key"],
              "CAMACT_JUDGE_TIMEOUT": str(role["timeout_seconds"]),
              "CAMACT_JUDGE_MAX_OUTPUT_TOKENS": str(role["max_output_tokens"]),
              "CAMACT_JUDGE_RETRY_ATTEMPTS": str(role["retry_attempts"])}
    before = {k: os.environ.get(k) for k in values}
    os.environ.update(values)
    try:
        yield values
    finally:
        for key, value in before.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
