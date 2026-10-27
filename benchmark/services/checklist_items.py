"""Ordered checklist photo attachments, with opt-in schemas and legacy text items."""
from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

from .api import image_path
from .tool_support import ToolExecutionError


def checklist_tool_schema(name: str) -> dict[str, Any]:
    """Return the explicit extended contract; existing task schemas stay unchanged."""
    images = {"type": "array", "items": {"type": "string", "minLength": 1},
              "uniqueItems": True,
              "description": "Raw album image filenames, in display order. An empty array removes attachments."}
    position = {"type": "integer", "minimum": 0,
                "description": "Optional zero-based item position; omit to append a new item or keep an existing item's position."}
    properties = {"checklist_id": {"type": "string"}}
    required = ["checklist_id"]
    if name == "checklist_create":
        properties = {
            "title": {"type": "string"},
            "items": {"type": "array", "minItems": 1, "items": {"oneOf": [
                {"type": "string"},
                {"type": "object", "properties": {
                    "text": {"type": "string", "minLength": 1, "pattern": "\\S"},
                    "images": copy.deepcopy(images),
                }, "required": ["text"], "additionalProperties": False},
            ]}, "description": "Items in display order: legacy text strings or objects containing text and optional ordered images."},
        }
        required = ["title", "items"]
    elif name == "checklist_add_item":
        properties.update(text={"type": "string"}, images=images, position=position)
        required.append("text")
    elif name == "checklist_update_item":
        properties.update(item_id={"type": "string"}, text={"type": "string"},
                          completed={"type": "boolean"}, images=images, position=position)
        required.append("item_id")
    else:
        raise KeyError(name)
    return {"type": "object", "properties": properties, "required": required,
            "additionalProperties": False}


def checklist_tool_definition(name: str) -> dict[str, Any]:
    descriptions = {
        "checklist_create": "Create and save a checklist. Items are stored in the supplied order; each item can contain text and ordered photo attachments. Text strings remain supported.",
        "checklist_add_item": "Add a checklist item with optional ordered photo attachments. Append by default, or insert at a zero-based position.",
        "checklist_update_item": "Update a checklist item's text, completion state, ordered photo attachments or zero-based position. Omitted fields stay unchanged; images replaces all attachments, and an empty array clears them.",
    }
    return {"name": name, "description": descriptions[name], "input_schema": checklist_tool_schema(name)}


def validate_images(task_dir: Path, value: Any) -> list[str]:
    """Validate the whole attachment array before a mutation; preserve its order."""
    if not isinstance(value, list):
        raise ToolExecutionError("images must be a list of raw image filenames")
    paths: list[Path] = []
    for image in value:
        if (not isinstance(image, str) or not image or image != image.strip()
                or "/" in image or "\\" in image or ":" in image or Path(image).name != image):
            raise ToolExecutionError("each image must be a raw album image filename")
        try:
            path = image_path(task_dir, image)
            if any(path.samefile(other) for other in paths):
                raise ToolExecutionError("duplicate images in one checklist item are not allowed")
        except (KeyError, OSError, ValueError) as exc:
            if isinstance(exc, ToolExecutionError):
                raise
            raise ToolExecutionError("image is not available in this user's raw album") from exc
        paths.append(path)
    return copy.deepcopy(value)


def create_items(task_dir: Path, value: Any) -> list[dict[str, Any]]:
    """Normalize initial items without altering the shape of legacy string items."""
    if not isinstance(value, list):
        raise ToolExecutionError("items must be a list")
    items = []
    for index, entry in enumerate(value, start=1):
        if isinstance(entry, str):
            if not entry.strip():
                continue
            item = {"item_id": f"item_{index:03d}", "text": entry, "completed": False}
        elif isinstance(entry, dict):
            if (set(entry) - {"text", "images"} or not isinstance(entry.get("text"), str)
                    or not entry["text"].strip()):
                raise ToolExecutionError("each structured item needs non-empty text and optional images")
            item = {"item_id": f"item_{index:03d}", "text": entry["text"], "completed": False,
                    "images": validate_images(task_dir, entry.get("images", []))}
        else:
            raise ToolExecutionError("each item must be a text string or an item object")
        items.append(item)
    if not items:
        raise ToolExecutionError("items must not be empty")
    return items


def item_position(args: dict[str, Any], count: int, *, inserting: bool = False) -> int | None:
    """Validate a zero-based insertion/final position; None preserves old behavior."""
    if "position" not in args:
        return None
    position = args["position"]
    maximum = count if inserting else count - 1
    if type(position) is not int or not 0 <= position <= maximum:
        raise ToolExecutionError("position is outside the checklist item range")
    return position


def next_item_id(items: list[dict[str, Any]]) -> str:
    """Keep stable IDs when gaps, imported IDs or item moves exist."""
    return next_record_id(items, "item_id", "item")


def next_record_id(records: list[dict[str, Any]], key: str, prefix: str) -> str:
    """Avoid collisions with existing fixture IDs while preserving ordinary IDs."""
    occupied = {str(record.get(key, "")).casefold() for record in records}
    numbers = [int(match.group(1)) for item_id in occupied
               if (match := re.fullmatch(re.escape(prefix) + r"_(\d+)", item_id))]
    number = max([len(records), *numbers]) + 1
    while f"{prefix}_{number:03d}" in occupied:
        number += 1
    return f"{prefix}_{number:03d}"
