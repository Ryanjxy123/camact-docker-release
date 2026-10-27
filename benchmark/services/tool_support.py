"""Shared pure tool checks and detached mutation preparation."""
from __future__ import annotations
import copy
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from .api import inspect_image, person_record, relationship_lookup
from .tool_schema import validate_arguments
if __package__ == "services":
    from evaluator.datetime_compat import normalize_iso_datetime
else:
    from ..evaluator.datetime_compat import normalize_iso_datetime

PRIVATE_SEMANTIC_FIELDS = frozenset(
    {
        "caption",
        "captions",
        "event_summary",
        "event_description",
        "grounded_description",
        "hidden_annotation",
        "hidden_visual_annotation",
        "image_memory",
        "image_memory_summary",
        "semantic_index",
        "semantic_summary",
        "timeline_index",
    }
)


class ToolExecutionError(ValueError):
    """A declared tool call could not be executed in the current environment."""


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _dump(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _private_semantic_paths(value: Any, prefix: str = "") -> list[str]:
    paths: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = re.sub(r"[^a-z0-9]+", "_", str(key).casefold()).strip("_")
            path = f"{prefix}.{key}" if prefix else str(key)
            if normalized in PRIVATE_SEMANTIC_FIELDS:
                paths.append(path)
            paths.extend(_private_semantic_paths(item, path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            paths.extend(_private_semantic_paths(item, f"{prefix}[{index}]"))
    return paths


def _enforce_runtime_boundary(value: Any, boundary: str) -> None:
    leaked = _private_semantic_paths(value)
    if leaked:
        raise ToolExecutionError(
            f"{boundary} contains private semantic fields and was blocked"
        )


def _parse_datetime(value: str, field: str) -> datetime:
    try:
        return datetime.fromisoformat(normalize_iso_datetime(value.replace("Z", "+00:00")))
    except (AttributeError, ValueError) as exc:
        raise ToolExecutionError(f"{field} must be an ISO date-time") from exc


class ToolBackend:
    """A handler works on a detached candidate; its caller commits after validation."""
    def __init__(self, task_dir: Path, session_dir: Path, state: dict):
        self.task_dir = task_dir
        self.session_dir = session_dir
        self.state = state
        self.pending_writes: dict[Path, str] = {}

    def prepare(self, name: str, arguments: dict, definition: dict) -> dict:
        validate_arguments(name, definition, arguments)
        handler = getattr(self, f"_tool_{name}", None)
        if handler is None:
            raise ToolExecutionError(f"tool '{name}' has no runtime implementation")
        response = handler(arguments)
        _enforce_runtime_boundary(response, f"tool '{name}' observation")
        return response

    def commit_files(self) -> None:
        # Workspace tools update a single file per action. Atomic replacement
        # happens only after handler, schema and observation checks all pass.
        if len(self.pending_writes) > 1:
            raise RuntimeError("workspace tool attempted a multi-file mutation")
        for target, content in self.pending_writes.items():
            temporary = target.with_name(target.name + ".camact-tmp")
            try:
                temporary.write_text(content, encoding="utf-8")
                temporary.replace(target)
            finally:
                temporary.unlink(missing_ok=True)
        self.pending_writes.clear()

    def _require_images(self, values: Any) -> None:
        if not isinstance(values, list):
            raise ToolExecutionError("images must be a list of raw image filenames")
        for image in values:
            if not isinstance(image, str) or not image.strip():
                raise ToolExecutionError("each image must be a raw image filename")
            inspect_image(self.task_dir, image)


    def _contact(self, name: str) -> dict[str, Any] | None:
        folded = str(name).casefold()
        for contact in self.state["contacts"]:
            if folded in {
                str(contact.get("name", "")).casefold(),
                str(contact.get("contact_id", "")).casefold(),
            }:
                return contact
        return None


    @staticmethod
    def _record_by_id(
        records: list[dict[str, Any]], value: str, *keys: str
    ) -> dict[str, Any] | None:
        folded = str(value).casefold()
        for record in records:
            if any(str(record.get(key, "")).casefold() == folded for key in keys):
                return record
        return None


    @staticmethod
    def _required_text(args: dict[str, Any], key: str) -> str:
        value = str(args.get(key, "")).strip()
        if not value:
            raise ToolExecutionError(f"{key} is required")
        return value


    def _identity_claims(self, args: dict[str, Any]) -> list[dict[str, Any]]:
        value = args.get("identity_claims", [])
        if value is None:
            return []
        if not isinstance(value, list):
            raise ToolExecutionError("identity_claims must be a list")
        result = []
        for claim in value:
            if not isinstance(claim, dict):
                raise ToolExecutionError("each identity claim must be an object")
            person_id = str(claim.get("person_id", ""))
            if not person_id:
                raise ToolExecutionError("identity claim person_id is required")
            person_id = str(person_record(self.task_dir, person_id)["person_id"])
            basis = str(claim.get("basis", ""))
            if basis not in {"visual_match_to_reference", "relation_graph"}:
                raise ToolExecutionError("identity claim basis is invalid")
            image_id = str(claim.get("image_id", ""))
            if image_id:
                inspect_image(self.task_dir, image_id)
            relation = str(claim.get("relation_to_owner", ""))
            if relation:
                expected = relationship_lookup(self.task_dir, person_id).get("relation")
                if relation.casefold() != str(expected or "").casefold():
                    raise ToolExecutionError(
                        f"relation_to_owner is inconsistent with the user relation graph for {person_id}"
                    )
            result.append(
                {
                    "image_id": image_id or None,
                    "person_id": person_id,
                    "relation_to_owner": relation or None,
                    "basis": basis,
                }
            )
        return result


