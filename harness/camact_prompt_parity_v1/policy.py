"""Apply the Baseline composer at the trusted native model-request boundary.

Append shared task constraints while preserving official system/developer
instructions. The CLI supplies identity and execution mechanics; behavior,
memory and public suffix still use the canonical Baseline composer.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys

BENCHMARK = Path(__file__).resolve().parents[2] / "benchmark"
CLAUDE_ROOT = BENCHMARK.parent / "harness" / "claude code"
for package_root in (BENCHMARK, CLAUDE_ROOT):
    if str(package_root) not in sys.path:
        sys.path.insert(0, str(package_root))

from benchmark_runner.system_prompt import (
    append_public_suffix, build_system_prompt, prompt_config_for_task,
)
from services.task_definition import ToolSpec, load_task

SCHEMA = "camact.system_prompt_policy.v1"
NATIVE_FINISH = "Finish with your final natural-language response when the task is complete."
BASELINE_FINISH = "Call finish when the task is complete."
_SHELL_TOOLS = {"Bash", "bash", "exec_command", "exec", "shell", "run_shell_command", "execute"}
POLICY_START = "<camact_public_task_rules>"
POLICY_END = "</camact_public_task_rules>"


def _without_policy(text):
    """Remove only our own delimited block when a request is reapplied."""
    if not isinstance(text, str):
        return text
    start = text.find(POLICY_START)
    end = text.find(POLICY_END, start)
    if start >= 0 and end >= 0:
        return text[:start].removesuffix("\n\n") + text[end + len(POLICY_END):]
    return text


def _append_policy(original, prompt):
    if isinstance(original, list):
        blocks = [item for item in original if not (
            isinstance(item, dict) and isinstance(item.get("text"), str)
            and item["text"].startswith(POLICY_START))]
        return [*blocks, {"type": "text", "text": prompt}]
    original = _without_policy(original or "")
    return original + "\n\n" + prompt if original else prompt


def non_tool_prompt(prompt: str) -> str:
    """Extract the invariant composed core; public suffix is handled separately."""
    # Native tool descriptions can contain arbitrary Markdown headings. The
    # composer always emits the complete behavior/memory tail after all tools;
    # anchor there instead of interpreting headings inside tool documentation.
    prefix, marker, tail = prompt.rpartition("\n\n## Tool Call Style\n")
    if not marker:
        raise ValueError("Canonical behavior block is missing")
    invariant = marker + tail
    lines = [line for line in invariant.splitlines()
             if line not in {BASELINE_FINISH, NATIVE_FINISH}]
    return "\n\n".join(block.strip() for block in "\n".join(lines).split("\n\n") if block.strip())


def _tools(document: dict) -> list[ToolSpec]:
    result = []

    def add(tool, prefix=""):
        if not isinstance(tool, dict):
            raise ValueError("Native tool declaration must be an object")
        if tool.get("type") == "namespace":
            name = str(tool.get("name") or "")
            for child in tool.get("tools", tool.get("functions", [])):
                add(child, prefix + name + ".")
            return
        if "functionDeclarations" in tool or "function_declarations" in tool:
            for child in tool.get("functionDeclarations", tool.get("function_declarations", [])):
                add(child, prefix)
            return
        function = tool.get("function", tool)
        name = function.get("name") or tool.get("type")
        if not name:
            raise ValueError("Native tool declaration has no name or type")
        schema = function.get("input_schema", function.get("parameters", function.get("parametersJsonSchema")))
        if not isinstance(schema, dict):
            schema = {"type": "object", "properties": {}}
        description = function.get("description") or "Use this registered native tool through its native API."
        result.append(ToolSpec(name=prefix + str(name), description=description, input_schema=schema))

    for tool in document.get("tools", []):
        add(tool)
    return result


class NativePromptPolicy:
    def __init__(self, task_dir: Path, tool_profile: str = "native"):
        self.task_dir = Path(task_dir)
        self.task = load_task(self.task_dir)
        self.config = prompt_config_for_task(self.task_dir)
        self.tool_profile = tool_profile
        self.public_suffix = self.task.system_prompt_suffix
        # Import only the public tool partition; no persona, GT or rubric input.
        from claude_code_harness.tool_profiles import DOMAIN_TOOLS
        self.business_tools = [tool for tool in self.task.tools if tool.name not in DOMAIN_TOOLS]

    @property
    def memory_root(self) -> str:
        return self.config.personal_memory.root

    @property
    def canonical_non_tool_prompt(self) -> str:
        core = build_system_prompt([], self.config)
        return append_public_suffix(non_tool_prompt(core), self.public_suffix)

    def _tool_access(self, native_tools: list[ToolSpec]) -> str:
        if not any(tool.name.rsplit(".", 1)[-1] in _SHELL_TOOLS for tool in native_tools):
            return ""
        lines = ["## Task Tool Access",
                 "The following Task operations are available through the registered native shell tool, not as additional API functions.",
                 "Read context/adapter_cli.json for the task-local CLI contract."]
        for tool in self.business_tools:
            lines.extend([f"- {tool.name}: {tool.description}",
                          f"  Command: python3 .camact/adapter.py action {tool.name} --json '<JSON object>'",
                          "  Arguments: " + json.dumps(tool.input_schema, ensure_ascii=False, sort_keys=True)])
        if self.task.user_agent_enabled:
            lines.append("Ask the task's user: python3 .camact/adapter.py ask-user --message '<question>'")
        lines.append("The published Personal Memory source is a read-only alias of this workspace's album/ directory; both paths contain the same current-user data.")
        return "\n".join(lines)

    def apply(self, document: dict, protocol: str) -> tuple[dict, dict]:
        if protocol not in {"anthropic-messages", "deepseek-messages", "openai-chat", "openai-responses", "google-generative-language"}:
            raise ValueError(f"Unsupported system prompt protocol: {protocol}")
        value = copy.deepcopy(document)
        tools = _tools(value)
        finish = BASELINE_FINISH if any(tool.name == "finish" for tool in tools) else NATIVE_FINISH
        core = build_system_prompt(tools, self.config, tool_access=self._tool_access(tools), finish_instruction=finish)
        if non_tool_prompt(core) != non_tool_prompt(build_system_prompt([], self.config)):
            raise ValueError("Native non-tool system policy differs from canonical Baseline")
        core = build_system_prompt(tools, self.config, tool_access=self._tool_access(tools),
                                   finish_instruction=finish, include_identity=False)
        prompt = POLICY_START + "\n" + append_public_suffix(core, self.public_suffix) + "\n" + POLICY_END
        removed = 0
        if protocol in {"anthropic-messages", "deepseek-messages"}:
            value["system"] = _append_policy(value.get("system"), prompt)
        elif protocol == "openai-chat":
            original = value.get("messages", [])
            messages = [m for m in original if not (isinstance(m, dict)
                        and m.get("role") == "system" and isinstance(m.get("content"), str)
                        and m["content"].startswith(POLICY_START))]
            # Keep original high-priority messages and their order intact.
            index = next((i for i, m in enumerate(messages)
                          if not isinstance(m, dict) or m.get("role") not in {"system", "developer"}), len(messages))
            messages.insert(index, {"role": "system", "content": prompt})
            value["messages"] = messages
        elif protocol == "openai-responses":
            value["instructions"] = _append_policy(value.get("instructions"), prompt)
        else:
            key = "systemInstruction" if "systemInstruction" in value else "system_instruction" if "system_instruction" in value else "systemInstruction"
            instruction = value.setdefault(key, {})
            instruction["parts"] = [p for p in instruction.get("parts", [])
                                    if not (isinstance(p.get("text"), str) and p["text"].startswith(POLICY_START))]
            instruction["parts"].append({"text": prompt})
        metadata = {"schema_version": SCHEMA, "source": "canonical_baseline_composer",
                    "system_prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
                    "non_tool_prompt_sha256": hashlib.sha256(self.canonical_non_tool_prompt.encode()).hexdigest(),
                    "native_tool_names": [t.name for t in tools],
                    "task_business_tools": [t.name for t in self.business_tools],
                    "removed_high_priority_messages": removed, "native_instructions_preserved": True,
                    "public_suffix_applied": bool(self.public_suffix)}
        return value, metadata


def write_workspace_policy(task_dir: Path, workspace: Path, tool_profile: str = "native") -> None:
    policy = NativePromptPolicy(task_dir, tool_profile)
    target = workspace / ".camact" / "prompt_policy.json"
    target.write_text(json.dumps({"schema_version": SCHEMA, "memory_root": policy.memory_root,
                                  "non_tool_prompt_sha256": hashlib.sha256(policy.canonical_non_tool_prompt.encode()).hexdigest()}, indent=2), encoding="utf-8")
