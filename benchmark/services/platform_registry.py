"""The existing external-platform tools and their optional mock backends."""
from __future__ import annotations

PLATFORM_TOOLS = {
    "messages": {"threads_list", "thread_get", "message_create_draft", "message_send"},
    "calendar": {"calendar_search", "calendar_get_event", "calendar_get_availability", "calendar_create_event", "calendar_update_event"},
    "booking": {"service_search", "service_get_details", "service_get_availability", "reservations_list", "reservation_create", "reservation_update", "reservation_cancel"},
    "social": {"publish_post"},
    "moments": {"publish_post", "post_get"},
    "email": {"email_send", "email_get_delivery"},
    "telegram": {"telegram_send", "telegram_get_delivery"},
}
PLATFORM_STATE_KEYS = {
    "messages": ("messages",), "calendar": ("calendar",),
    "booking": ("service_catalog", "reservations", "reservation_create_requests"), "social": ("publishing",),
    "moments": ("publishing",),
    "email": ("email",), "telegram": ("telegram",),
}
TOOL_SERVICE = {}
TOOL_SERVICES = {}
for service, names in PLATFORM_TOOLS.items():
    for tool in names:
        TOOL_SERVICE.setdefault(tool, service)  # Preserve the existing draft backend.
        TOOL_SERVICES.setdefault(tool, set()).add(service)
LOGICAL_PORTS = {"messages": 9100, "calendar": 9101, "booking": 9102, "social": 9103, "moments": 9104,
                 "email": 9105, "telegram": 9106}


def service_contract(tools):
    """Port numbers are logical; ServiceManager remaps them per session."""
    services, endpoints = [], []
    routing = dict(TOOL_SERVICE)
    if "post_get" in tools:
        routing["publish_post"] = "moments"
    for name, names in PLATFORM_TOOLS.items():
        required = sorted(tool for tool in set(tools) & names if routing[tool] == name)
        if not required:
            continue
        port = LOGICAL_PORTS[name]
        base = f"http://127.0.0.1:{port}/{name}"
        services.append({
            "name": name, "command": f"python -m services.mock_services.server --service {name}",
            "port": port, "health_check": base + "/health", "health_check_method": "GET",
            "ready_timeout": 10.0, "reset_endpoint": base + "/reset",
        })
        endpoints.extend({"tool_name": tool, "url": base + "/" + tool, "method": "POST"} for tool in required)
    return services, endpoints
