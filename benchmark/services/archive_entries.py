"""Validate optional per-photo Archive records without inventing photo facts."""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from .api import image_path
from .tool_support import ToolExecutionError


ENTRY_FIELDS = frozenset({"image", "datetaken", "location", "description"})


def _path(task_dir: Path, image: Any) -> Path:
    if not isinstance(image, str) or not image.strip() or Path(image).name != image:
        raise ToolExecutionError("entry image must be a raw image filename")
    try:
        return image_path(task_dir, image)
    except (KeyError, OSError, ValueError) as exc:
        raise ToolExecutionError("entry image is not an available raw album image") from exc


def _same_image(left: Path, right: Path) -> bool:
    try:
        return left.samefile(right)
    except OSError as exc:
        raise ToolExecutionError("archive image identity is unavailable") from exc


def validate_entries(task_dir: Path, value: Any, images: list[str]) -> list[dict[str, str]]:
    """Check shape and attachment identity; preserve supplied strings verbatim."""
    if not isinstance(value, list):
        raise ToolExecutionError("entries must be a list of photo entry objects")
    attached = [_path(task_dir, image) for image in images]
    seen: list[Path] = []
    for entry in value:
        if (not isinstance(entry, dict) or set(entry) - ENTRY_FIELDS
                or "image" not in entry
                or any(not isinstance(text, str) for text in entry.values())):
            raise ToolExecutionError("each entry needs an image and optional string datetaken, location and description")
        path = _path(task_dir, entry["image"])
        if not any(_same_image(path, other) for other in attached):
            raise ToolExecutionError("entry image must refer to an attached raw image")
        if any(_same_image(path, other) for other in seen):
            raise ToolExecutionError("an attached raw image may have at most one entry")
        seen.append(path)
    return copy.deepcopy(value)


def retained_entries(task_dir: Path, value: Any, old_images: list[str],
                     new_images: list[str]) -> list[dict[str, str]]:
    """Keep existing entries only while their original image remains attached."""
    entries = validate_entries(task_dir, value, old_images)
    attached = [_path(task_dir, image) for image in new_images]
    return [entry for entry in entries
            if any(_same_image(_path(task_dir, entry["image"]), other) for other in attached)]
