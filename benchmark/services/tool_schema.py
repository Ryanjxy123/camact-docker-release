"""One JSON Schema contract for model tools, local execution and HTTP services."""
from __future__ import annotations

import copy
import json
import re
from functools import lru_cache
from typing import Any

from jsonschema import Draft202012Validator, validators


# JSON booleans must never pass integer validation (bool is an int in Python).
# Keep Python entry points as strict as the JSON HTTP entry point.
StrictValidator = validators.extend(
    Draft202012Validator,
    type_checker=Draft202012Validator.TYPE_CHECKER.redefine(
        "integer", lambda checker, value: type(value) is int
    ),
)


def argument_schema(name: str, description: str) -> dict[str, Any]:
    folded = description.casefold()
    if "identity claim" in folded:
        return {
            "type": "array", "items": {
                "type": "object", "properties": {
                    "image_id": {"type": "string"},
                    "person_id": {"type": "string", "pattern": "^person_[A-Z]+$"},
                    "relation_to_owner": {"type": "string"},
                    "basis": {"type": "string", "enum": ["visual_match_to_reference", "relation_graph"]},
                },
                "required": ["person_id", "basis"], "additionalProperties": False,
            },
        }
    if "list[" in folded:
        return {"type": "array", "items": {"type": "string"}}
    if "boolean" in folded:
        return {"type": "boolean"}
    if "integer" in folded:
        result: dict[str, Any] = {"type": "integer"}
        if "non-negative" in folded:
            result["minimum"] = 0
        bounds = re.search(r"integer, (\d+)-(\d+)", folded)
        if bounds:
            result.update(minimum=int(bounds[1]), maximum=int(bounds[2]))
        return result
    if name == "person_id":
        # Lookup has always accepted case-insensitive opaque IDs and returns
        # the canonical spelling from the relation graph.
        return {"type": "string", "pattern": "^person_[A-Za-z]+$"}
    enum_source = folded.removeprefix("optional ")
    if "|" in enum_source and " " not in enum_source:
        return {"type": "string", "enum": enum_source.split("|")}
    if enum_source == "draft":
        return {"type": "string", "enum": ["draft"]}
    return {"type": "string"}


def input_schema(definition: dict[str, Any]) -> dict[str, Any]:
    if "input_schema" in definition:
        return copy.deepcopy(definition["input_schema"])
    descriptions = definition.get("arguments", {})
    return {
        "type": "object",
        "properties": {name: {**argument_schema(name, str(text)), "description": str(text)} for name, text in descriptions.items()},
        "required": [name for name, text in descriptions.items() if not str(text).casefold().startswith("optional")],
        "additionalProperties": False,
    }


@lru_cache(maxsize=256)
def _compile_schema(serialized: str):
    schema = json.loads(serialized)
    StrictValidator.check_schema(schema)
    return StrictValidator(schema)


def schema_validator(schema: dict[str, Any]):
    return _compile_schema(json.dumps(schema, sort_keys=True, allow_nan=False))


def validate_arguments(name: str, definition: dict[str, Any], arguments: Any) -> None:
    error = next(schema_validator(input_schema(definition)).iter_errors(arguments), None)
    if error is not None:
        location = ".".join(str(part) for part in error.absolute_path) or "arguments"
        # Do not echo arbitrary payloads in exception messages.
        raise ValueError(f"{name}.{location}: schema validation failed ({error.validator})")
