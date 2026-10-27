"""Public tool defaults and private storage for saved conversation history."""
from __future__ import annotations

import copy

HISTORY_THREAD_ID = "thread_saved_history"
HISTORY_GUIDANCE = (
    "Conversation history is available through `threads_list` and `thread_get`. "
    "Use these tools when relevant to the task."
)
HISTORY_TOOLS = [
    {
        "name": "threads_list",
        "description": "List message threads and saved conversation history. Optional query filters the records.",
        "input_schema": {
            "type": "object", "properties": {"query": {"type": "string"}},
            "required": [], "additionalProperties": False,
        },
    },
    {
        "name": "thread_get",
        "description": "Read one message thread or saved conversation, preserving its original speakers and message order.",
        "input_schema": {
            "type": "object", "properties": {"thread_id": {"type": "string"}},
            "required": ["thread_id"], "additionalProperties": False,
        },
    },
]


def history_tool_defaults(data: dict) -> dict:
    """Complete users_history declarations without touching other task types."""
    from .platform_registry import service_contract

    if data.get("task_type") != "users_history":
        return data
    data = copy.deepcopy(data)
    context = data.get("context")
    if isinstance(context, dict) and context.get("kind") == "agent_history" and context.get("messages"):
        # Older authors may still supply inline records. They stay private and
        # are materialized as a fixture, never added to the model conversation.
        if context.get("source") is None and context.get("thread_id") is None:
            context.update(source="messages", thread_id=HISTORY_THREAD_ID)
    tools = data.setdefault("tools", [])
    names = {tool["name"] for tool in tools}
    for tool in HISTORY_TOOLS:
        if tool["name"] not in names:
            tools.append(copy.deepcopy(tool))
    services = data.setdefault("services", [])
    endpoints = data.setdefault("tool_endpoints", [])
    defaults, default_endpoints = service_contract({tool["name"] for tool in HISTORY_TOOLS})
    messages = next((service for service in services if service["name"] == "messages"), None)
    if messages is None:
        messages = defaults[0]
        services.append(messages)
    base = messages["reset_endpoint"].rsplit("/", 1)[0]
    names = {endpoint["tool_name"] for endpoint in endpoints}
    for endpoint in default_endpoints:
        if endpoint["tool_name"] not in names:
            endpoints.append({**endpoint, "url": base + "/" + endpoint["tool_name"]})
    return data


def saved_history_thread(messages: list[dict[str, str]], thread_id: str = HISTORY_THREAD_ID) -> dict:
    """Store the original records without relabeling them as external speakers."""
    return {
        "thread_id": thread_id,
        "title": "Saved conversation with the album assistant",
        "context_kind": "agent_history",
        "source_type": "saved_conversation_history",
        "participants": list(dict.fromkeys(message["role"] for message in messages)),
        "messages": copy.deepcopy(messages),
    }
