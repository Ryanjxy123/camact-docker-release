from __future__ import annotations
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

NAMES = ("claude", "codex", "opencode", "deepseek", "openclaw")
METHODS = ("baseline", *NAMES)
PROTOCOLS = {
    "claude": {"anthropic-messages"},
    "codex": {"openai-responses"},
    "baseline": {"openai-chat", "anthropic-messages"},
    "opencode": {"openai-responses", "openai-chat", "anthropic-messages"},
    "openclaw": {"openai-responses", "openai-chat", "anthropic-messages"},
    "deepseek": {"deepseek-messages"},
}

def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema_version") != "camact.multi_harness_config.v1":
        raise ValueError("Unsupported configuration schema")
    if value.get("tool_profile") != "native" or value.get("album_extensions", {}).get("enabled"):
        raise ValueError("Only native profile is implemented; album extension slot is reserved")
    if set(value.get("harnesses", {})) != set(METHODS):
        raise ValueError(f"Formal harnesses must be exactly {METHODS}")
    for name in NAMES:
        entry = value["harnesses"][name]
        if entry.get("sandbox_backend", "bwrap") not in {"bwrap", "gvisor"}:
            raise ValueError(f"{name}: unsupported sandbox backend")
        exe = entry["executable"]
        if not exe.startswith("/") or exe.startswith("/mnt/"):
            raise ValueError(f"{name}: Linux absolute executable required")
        if "api_key" in entry.get("provider", {}):
            raise ValueError("Use api_key_env; inline API keys are forbidden")
    for role in ("simulator", "judge"):
        if "api_key" in value.get(role, {}):
            raise ValueError(f"{role}: use api_key_env; inline API keys are forbidden")
    return value

def provider_ready(name: str, provider: dict, *, require_key: bool = True):
    for key in ("provider", "model", "base_url", "api_key_env", "protocol"):
        if not provider.get(key):
            raise ValueError(f"{name}: provider.{key} is not configured")
    if provider["protocol"] not in PROTOCOLS[name]:
        raise ValueError(f"{name}: protocol is not supported by this adapter: {provider['protocol']}")
    parsed = urlsplit(provider["base_url"])
    if parsed.scheme not in {"https", "http"} or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("base_url must be an HTTP(S) URL without credentials, query or fragment")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", provider["api_key_env"]):
        raise ValueError("Invalid API key environment variable name")
    if require_key and not os.environ.get(provider["api_key_env"]):
        raise ValueError(f"Missing environment variable: {provider['api_key_env']}")
    from harness.camact_compatibility_v2.roles import role_provider
    role_provider(provider, role="agent", protocol=provider["protocol"], require_key=require_key)

def archive_path(value: str) -> Path:
    path = Path(value).resolve()
    explicit_root = os.environ.get("CAMACT_RESULTS_ROOT")
    if explicit_root:
        root = Path(explicit_root).resolve()
        if path != root and path.is_relative_to(root):
            return path
        raise ValueError("Output must be a child of CAMACT_RESULTS_ROOT")
    test_log = Path(__file__).resolve().parents[3] / "test_log"
    if path.is_relative_to(test_log):
        relative = path.relative_to(test_log)
        if len(relative.parts) >= 2 and re.fullmatch(r"\d{4}-\d\d-\d\d_\d\d-\d\d-\d\d", relative.parts[0]):
            return path
    if "harness/_log/" not in path.as_posix() or not re.search(r"/\d{4}-\d\d-\d\d/[a-z0-9]+(?:-[a-z0-9]+)+", path.as_posix()):
        raise ValueError("Output must be an explicit dated experiment under harness/_log or project test_log")
    return path

