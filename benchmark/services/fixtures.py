"""Materialize existing CamAct fixture namespaces without changing their meaning."""
from __future__ import annotations
import copy
from typing import Any
from .tool_support import _utc_now


def initial_state(fixtures: dict, session_id: str, task_name: str) -> dict:
    calendar_fixture = fixtures.get("calendar", {})
    messaging_fixture = fixtures.get("messaging", {})
    publishing_fixture = fixtures.get("publishing", {})
    photo_library_fixture = fixtures.get("photo_library", {})
    archives_fixture = fixtures.get("archives", {})
    workspace_fixture = fixtures.get("workspace", {})
    state: dict[str, Any] = {
        "session": {
            "id": session_id,
            "task": task_name,
            "created_at": _utc_now(),
            "status": "running",
        },
        "contacts": copy.deepcopy(fixtures.get("contacts", [])),
        "messages": {
            "threads": copy.deepcopy(messaging_fixture.get("threads", [])),
            "drafts": copy.deepcopy(messaging_fixture.get("drafts", [])),
            "sent": [],
        },
        "calendar": {
            "fixture_events": copy.deepcopy(calendar_fixture.get("events", [])),
            "events": copy.deepcopy(calendar_fixture.get("events", [])),
            "created_events": [],
        },
        "publishing": {
            "drafts": {
                "created": copy.deepcopy(
                    publishing_fixture.get("drafts", {}).get("created", [])
                )
            },
            "posts": copy.deepcopy(publishing_fixture.get("posts", [])),
        },
        "photo_library": {
            "albums": copy.deepcopy(photo_library_fixture.get("albums", [])),
            "stories": copy.deepcopy(photo_library_fixture.get("stories", [])),
        },
        "archives": {
            "records": copy.deepcopy(archives_fixture.get("records", [])),
        },
        "checklists": copy.deepcopy(fixtures.get("checklists", [])),
        "service_catalog": copy.deepcopy(fixtures.get("service_catalog", [])),
        "reservations": copy.deepcopy(fixtures.get("reservations", [])),
        "reservation_create_requests": {},
        "workspace": {
            "output": copy.deepcopy(workspace_fixture.get("output", []))
        },
        "user_simulator": {},
    }
    # These platforms are opt-in; existing tasks retain their state namespaces.
    for channel in ("email", "telegram"):
        if channel in fixtures:
            state[channel] = {"sent": [], "received": []}
    return state
