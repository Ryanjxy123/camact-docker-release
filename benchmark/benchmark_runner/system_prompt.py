"""Claw-Eval's dynamic composer, adapted for CamAct's tool-backed memory.

Source: src/claw_eval/{config.py,runner/system_prompt.py} at
5680b8b11ff2ee5dd2b07b89086a29a5c5c984d7. See THIRD_PARTY_NOTICES.md.
Only public tool declarations and the runtime memory path enter this module.
"""
from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

from services.api import raw_root
from services.task_definition import ToolSpec


class BehaviorRulesConfig(BaseModel):
    """Upstream behavior-policy fields relevant to CamAct."""

    safety: str = "No independent objective; do not pursue self-preservation, replication, or resource acquisition."
    tool_call_style: str = "For low-risk actions, call tools directly without narration; narrate only for complex tasks."


class PersonalMemoryConfig(BaseModel):
    """Replace upstream workspace markdown with a runtime-resolved resource root."""

    root: str


class PromptConfig(BaseModel):
    """The retained subset of Claw-Eval prompt composition configuration."""

    strict_file_check: bool = False
    include_tool_schema: bool = True
    personal_memory: PersonalMemoryConfig
    behavior_rules: BehaviorRulesConfig = Field(default_factory=BehaviorRulesConfig)


def _resolve_prompt_path(path_str: str) -> Path:
    p = Path(path_str)
    if p.is_absolute():
        return p
    return (Path(__file__).resolve().parents[1] / p).resolve()


def prompt_config_for_task(task_dir: Path) -> PromptConfig:
    # This is the same resolver used by the actual album/identity tools. In the
    # canonical benchmark each manifest resolves users/{user_id}/base_memory;
    # portable copies and tool-only fixtures may use their own runtime mount.
    return PromptConfig(personal_memory=PersonalMemoryConfig(root=str(raw_root(task_dir))))


def _render_tool_definitions(tools: list[ToolSpec]) -> str:
    if not tools:
        return "\n".join([
            "## Tooling",
            "Tool availability (filtered by policy):",
            "Tool names are case-sensitive. Call tools exactly as listed.",
            "- None",
        ])
    lines = [
        "## Tooling",
        "Tool availability (filtered by policy):",
        "Tool names are case-sensitive. Call tools exactly as listed.",
    ]
    for tool in tools:
        lines.append(f"- {tool.name}: {tool.description}")
    lines.append("When a first-class tool exists for an action, use the tool directly.")
    return "\n".join(lines)


def _render_tool_schemas(tools: list[ToolSpec]) -> str:
    if not tools:
        return ""
    lines = ["## Tool Schemas", "Complete JSON Schema for available tools:"]
    for tool in tools:
        schema_json = json.dumps(tool.input_schema, ensure_ascii=False, indent=2)
        lines.append(f"- {tool.name}")
        lines.append("```json")
        lines.append(schema_json)
        lines.append("```")
    return "\n".join(lines)


def _render_behavior_rules(cfg: PromptConfig, finish_instruction: str = "Call finish when the task is complete.") -> str:
    r = cfg.behavior_rules
    return "\n".join([
        "## Tool Call Style",
        "Default: do not narrate routine, low-risk tool calls (just call the tool).",
        "Narrate only when it helps: multi-step work, complex tasks, or sensitive actions.",
        "Keep narration brief and value-dense.",
        "Tool-call protocol is strict: use native API tool/function calls only.",
        "Never emit tool calls as plain text markup (for example: <tool_call>, <function=...>, <parameter=...>).",
        "If a tool is needed, issue a real tool call block instead of describing or simulating it in text.",
        finish_instruction,
        "",
        "## Safety",
        f"- Safety: {r.safety}",
        "- Personal memory is read-only.",
        f"- Tool Call Style: {r.tool_call_style}",
    ])


def _render_personal_memory(cfg: PromptConfig) -> str:
    p = _resolve_prompt_path(cfg.personal_memory.root)
    if cfg.strict_file_check and not p.is_dir():
        raise FileNotFoundError(f"Personal memory directory not found: {p}")
    # Preserve upstream Source/path/content rendering, but describe resources
    # rather than eagerly loading private album and identity contents.
    sections = ["## Personal Memory", f"Source: {p}"]
    if not p.is_dir():
        sections.append("[MISSING] Expected memory directory not found.")
    sections.append("\n".join([
        "Each user's read-only personal memory is located at the source path above.",
        "Key resources (relative to that path):",
        "- relation_graph/relation_graph.json: Album owner, known people or pets, and their relationships.",
        "- relation_graph/images/: Reference portraits of people and pets.",
        "- profile.jpg: Album owner's reference portrait.",
        "- images/: Original album photographs.",
        "- metadata.csv: Photo IDs, timestamps, and locations.",
        "Consult relevant memory as needed through the available memory tools, using their declared arguments; the tools read this source path.",
        "Relationship records provide identity context but do not automatically identify people in album photos. Verify identities using visual evidence when necessary.",
    ]))
    return "\n\n".join(sections)


def append_public_suffix(prompt: str, suffix: str = "") -> str:
    """One verbatim public suffix rule for Baseline and every native entrypoint."""
    return prompt + "\n\n" + suffix if suffix else prompt


def build_system_prompt(tools: list[ToolSpec], prompt_cfg: PromptConfig, *,
                        tool_access: str = "",
                        finish_instruction: str = "Call finish when the task is complete.",
                        include_identity: bool = True) -> str:
    """Compose one prompt for all task types from the actual public tool set.

    CamAct already merges the runtime finish tool into native tools.
    Accept that merged set instead of adding a second extras configuration.
    """
    blocks = ["You are a personal assistant running inside CamAct."] if include_identity else []
    blocks.append(_render_tool_definitions(tools))
    if prompt_cfg.include_tool_schema:
        blocks.append(_render_tool_schemas(tools))
    if tool_access:
        blocks.append(tool_access)
    blocks.append(_render_behavior_rules(prompt_cfg, finish_instruction))
    blocks.append(_render_personal_memory(prompt_cfg))
    return "\n\n".join(blocks).strip()
