"""Public task.yaml tool partition; no expected actions or evaluator inputs."""
from __future__ import annotations

NATIVE_TOOLS = ("Read", "Glob", "Grep", "Bash")
DOMAIN_TOOLS = frozenset({
    "album_search", "album_browse", "album_get_metadata", "image_view", "inspect_image",
    "people_search", "person_view_reference", "relationship_lookup", "owner_profile_view",
    "evidence_select",
})


def validate_profile(profile: str) -> str:
    if profile not in {"native", "camact"}:
        raise ValueError(f"unknown tool_profile: {profile}")
    return profile


def task_tools(handle):
    from benchmark.services.task_definition import load_task
    from benchmark.services.local_tools import LocalToolExecutor
    from benchmark.services.platform_registry import TOOL_SERVICE
    task = load_task(handle.task_dir)
    tools = {tool.name: tool.model_dump(exclude={"name"}) for tool in task.tools}
    unsupported = [name for name in tools if name not in TOOL_SERVICE
                   and not hasattr(LocalToolExecutor, f"_tool_{name}")]
    unsupported += [name for name in tools if name in TOOL_SERVICE
                    and name not in task.get_endpoint_map()]
    if unsupported:
        raise ValueError(f"declared tools have no supported backend: {unsupported}")
    return task, tools


def domain_names(tools, profile):
    validate_profile(profile)
    return sorted(set(tools) & DOMAIN_TOOLS) if profile == "camact" else []


def registered_tools(tools, profile):
    return list(NATIVE_TOOLS) + [f"mcp__camact__{name}" for name in domain_names(tools, profile)]


def check_registration(init, expected, profile):
    # Stock 2.1.59 lists this user-only built-in despite disabling slash commands.
    # Its shipped schema has disableModelInvocation=true. Skill is never enabled.
    inert = {"debug"} if init.get("claude_code_version") == "2.1.59" else set()
    extensions_ok = (set(init.get("skills", [])) <= inert
                     and not init.get("plugins") and not init.get("slash_commands"))
    mcp = init.get("mcp_servers", [])
    mcp_ok = mcp == [] if profile == "native" else (
        len(mcp) == 1 and mcp[0].get("name") == "camact" and mcp[0].get("status") == "connected")
    return {"passed": sorted(init.get("tools", [])) == sorted(expected) and extensions_ok and mcp_ok,
            "expected": expected, "actual": init.get("tools", []), "mcp_servers": mcp,
            "skills": init.get("skills", []), "plugins": init.get("plugins", []),
            "inert_builtin_skills": sorted(set(init.get("skills", [])) & inert)}
