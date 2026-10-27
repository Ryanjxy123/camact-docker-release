"""Native argv/config differences only. No planning, tool choice or agent loop."""
from __future__ import annotations
import json
from pathlib import Path
import uuid
from claude_code_harness.core import write_json

ENDPOINT = "http://127.0.0.1:18780"
LOCAL_KEY = "camact-local-relay-credential"
PROMPT = ("Open TASK.md and carry out the user's request inside this workspace. "
          "Use your native file/search/shell/image tools. "
          "Use context/adapter_cli.json for CamAct business operations and ask-user. "
          "Finish with your natural-language response.")

def prepare(name: str, entry: dict, config_root: Path, limits: dict, *, model=None, protocol=None, prompt=None):
    p = entry.get("provider", {})
    model = model or p.get("model")
    protocol = protocol or p.get("protocol")
    if not model or not protocol:
        raise ValueError("Model and protocol must be supplied before command preparation")
    config_root.mkdir(parents=True, exist_ok=True)
    env = {"HOME": "/home/agent", "PATH": "/usr/local/bin:/usr/bin:/bin",
           "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "NO_COLOR": "1", "CI": "1", "TMPDIR": "/run/camact",
           "XDG_CONFIG_HOME": "/home/agent/.config", "XDG_DATA_HOME": "/home/agent/.local/share",
           "XDG_CACHE_HOME": "/home/agent/.cache", "XDG_STATE_HOME": "/home/agent/.local/state"}
    if entry.get("node_executable"):
        env["PATH"] = "/opt:" + env["PATH"]
    exe = entry["executable"]
    if name == "codex":
        env.update(CODEX_HOME="/home/agent/.codex", CAMACT_LOCAL_API_KEY=LOCAL_KEY)
        root = config_root / ".codex"
        root.mkdir(exist_ok=True)
        (root / "config.toml").write_text(
            f'model = {json.dumps(model)}\nmodel_provider = "camact"\napproval_policy = "never"\n'
            'sandbox_mode = "danger-full-access"\n[model_providers.camact]\nname = "CamAct configured provider"\n'
            f'base_url = "{ENDPOINT}/v1"\nwire_api = "responses"\nenv_key = "CAMACT_LOCAL_API_KEY"\n')
        argv = [exe, "exec", "--json", "--skip-git-repo-check", "--dangerously-bypass-approvals-and-sandbox",
                "--color", "never", "--model", model, "--cd", "/tmp", PROMPT]
    elif name == "opencode":
        packages = {"openai-responses": "openai-compatible/responses", "openai-chat": "openai-compatible",
                    "anthropic-messages": "anthropic-compatible"}
        # OpenCode 2.0.32 reads this in its private server's ModelsDev config.
        # Keep the pinned bundled catalog and explicit provider/model settings;
        # avoid the unrelated background models.opencode.ai network refresh.
        env.update(OPENCODE_DISABLE_AUTOUPDATE="1", OPENCODE_DISABLE_MODELS_FETCH="1")
        data = {"model": "camact/" + model, "update": "disable", "providers": {
            "camact": {"name": "CamAct configured provider", "env": ["CAMACT_LOCAL_API_KEY"],
                       "package": "@opencode/ai/providers/" + packages[protocol],
                       "settings": {"baseURL": ENDPOINT + "/v1"},
                       "models": {model: p.get("model_options", {})}}}}
        write_json(config_root / ".config/opencode/opencode.json", data)
        env["CAMACT_LOCAL_API_KEY"] = LOCAL_KEY
        argv = [exe, "run", "--standalone", "--format", "json", "--auto", "--model", "camact/" + model, PROMPT]
    elif name == "openclaw":
        apis = {"openai-responses": "openai-responses", "openai-chat": "openai-completions",
                "anthropic-messages": "anthropic-messages"}
        env.update(OPENCLAW_STATE_DIR="/home/agent/.openclaw", OPENCLAW_CONFIG_PATH="/home/agent/.openclaw/openclaw.json")
        data = {"models": {"mode": "replace", "providers": {"camact": {
            "baseUrl": ENDPOINT + "/v1",
            "apiKey": LOCAL_KEY, "api": apis[protocol], "models": [{"id": model, "name": model, **p.get("model_options", {})}]}}},
            "agents": {"defaults": {"workspace": "/tmp", "model": {"primary": "camact/" + model}, "skipBootstrap": True}},
            "tools": {"profile": "full", "exec": {"security": "full", "ask": "off"}},
            # Preserve official generic file/browser/memory capabilities. Bundled
            # external business/model plugins are not Task business backends.
            "plugins": {"allow": ["memory-core", "browser", "canvas", "file-transfer"]}}
        write_json(config_root / ".openclaw/openclaw.json", data)
        argv = [exe, "agent", "--local", "--json", "--agent", "main", "--session-id", str(uuid.uuid4()),
                "--model", "camact/" + model, "--timeout", str(int(limits.get("task_timeout_seconds", 1800))), "--message", PROMPT]
    elif name == "deepseek":
        env.update(DSH_HOME="/home/agent/.dsh", DEEPSEEK_API_KEY=LOCAL_KEY, DEEPSEEK_BASE_URL=ENDPOINT,
                   DSH_PERMISSION_MODE="danger-full-access", DSH_TELEMETRY_MODE="DISABLED")
        # Official headless profile retains dsh-base's agent, tools and context.
        # Only the durable log's physical encoding changes for passive capture.
        rows = [{"id": "agent-default-model", "config": {"provider": "deepseek-official", "model": model}},
                {"id": "llm-deepseek", "config": {"baseURL": ENDPOINT, "apiKeyEnv": "DEEPSEEK_API_KEY",
                  **({"models": [{"id": model, **p["model_options"]}]} if p.get("model_options") else {})}},
                {"id": "session-persistence-jsonl", "config": {
                    "root": "/home/agent/.dsh/sessions", "compression": "none"}}]
        import yaml
        (config_root / "provider.patch.yml").write_text(yaml.safe_dump(rows, sort_keys=False))
        argv = [exe, "--profile", "headless", "--patch", "/home/agent/provider.patch.yml", "--json", PROMPT]
    elif name == "claude":
        # Main coordinator delegates Claude to its existing runner. This command
        # is used only for offline executable checks of the shared sandbox.
        env.update(CLAUDE_CONFIG_DIR="/home/agent/.claude", ANTHROPIC_BASE_URL=ENDPOINT,
                   ANTHROPIC_API_KEY=LOCAL_KEY, CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1")
        argv = [exe, "--print", "--verbose", "--output-format", "stream-json", "--model", model,
                "--permission-mode", "bypassPermissions", "--max-turns", str(limits.get("max_agent_turns", 50)), PROMPT]
    else:
        raise ValueError(name)
    if prompt is not None:
        argv = [prompt if arg == PROMPT else arg for arg in argv]
    return argv, env

def parse_events(name: str, text: str):
    # OpenClaw emits one pretty-printed JSON result; other CLIs emit JSONL.
    if name == "openclaw":
        try:
            return [json.loads(text)]
        except ValueError:
            return []
    events = []
    for line in text.splitlines():
        try:
            event = json.loads(line)
            if isinstance(event, dict):
                events.append(event)
        except ValueError:
            continue
    return events


def native_session_id(name: str, events: list[dict], argv: list[str]):
    """Read the official session identity; never choose a host-wide --last."""
    if name == "openclaw":
        return argv[argv.index("--session-id") + 1]
    for event in events:
        if name == "codex" and event.get("type") == "thread.started":
            return event.get("thread_id")
        if name == "opencode" and event.get("sessionID"):
            return event["sessionID"]
        if name == "deepseek" and event.get("type") == "session":
            return event.get("sessionId")
    return None


def resume_command(name: str, argv: list[str], session_id: str, message: str):
    """Continue one task's official persisted Session using native CLI flags."""
    if not session_id or not isinstance(message, str) or not message.strip():
        raise ValueError("Native continuation requires the current session id and a real user reply")
    if name == "codex":
        return [argv[0], "exec", "resume", "--json", "--skip-git-repo-check",
                "--dangerously-bypass-approvals-and-sandbox", "--model", argv[argv.index("--model") + 1],
                session_id, message]
    if name == "opencode":
        base = list(argv[:-1])
        if "--session" in base:
            index = base.index("--session"); del base[index:index + 2]
        return [*base, "--session", session_id, message]
    if name == "deepseek":
        base = list(argv[:-1])
        if "--session-id" in base:
            index = base.index("--session-id"); del base[index:index + 2]
        return [*base, "--session-id", session_id, message]
    if name == "openclaw":
        result = list(argv)
        if result[result.index("--session-id") + 1] != session_id:
            raise ValueError("OpenClaw session identity changed during one task")
        result[result.index("--message") + 1] = message
        return result
    raise ValueError(f"No verified continuation command for {name}")

def final_text(name: str, events: list[dict]):
    if name == "claude":
        from claude_code_harness.native_runner import _final_text
        return _final_text(events, {})
    if name == "codex":
        return next((e["item"].get("text", "") for e in reversed(events)
                     if e.get("type") == "item.completed" and e.get("item", {}).get("type") == "agent_message"), "")
    if name == "deepseek":
        return next((e.get("text", e.get("content", "")) for e in reversed(events) if e.get("type") == "final"), "")
    if name == "opencode":
        parts, message = [], None
        for e in events:
            if e.get("type") == "text":
                current = e.get("part", {}).get("messageID")
                if current != message:
                    parts, message = [], current
                parts.append(e.get("part", {}).get("text", ""))
        return "".join(parts)
    if name == "openclaw":
        return "\n".join(p.get("text", "") for e in events for p in e.get("payloads", e.get("result", {}).get("payloads", [])))
    return ""

def terminal_error(name, events):
    for event in events:
        if event.get("type") in {"error", "turn.failed"}:
            return json.dumps(event, ensure_ascii=False)
        if name == "deepseek" and event.get("type") == "status":
            reason = event.get("reason")
            kind = reason.get("kind") if isinstance(reason, dict) else reason
            if kind in {"error", "aborted", "failed"}:
                return json.dumps(event, ensure_ascii=False)
    return None
