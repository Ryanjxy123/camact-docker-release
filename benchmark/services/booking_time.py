"""Compare booking slots by ISO date-time value without inventing a timezone."""
from __future__ import annotations

from datetime import datetime
import re


_SLOT = re.compile(
    r"\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}"
    r"(?::\d{2}(?:[.,]\d{1,6})?)?"
    r"(?:[Zz]|[+-](?:[01]\d|2[0-3]):?[0-5]\d)?"
)


def _slot_datetime(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not _SLOT.fullmatch(text):
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def booking_slots_equal(left: object, right: object) -> bool:
    """Accept equivalent precision/offset forms, but never a different time.

    An unqualified value is a service-local wall time. It can only match another
    unqualified value; explicit offsets can be compared as instants. Dates alone,
    malformed inputs and mixed qualified/unqualified values do not match.
    """
    first, second = _slot_datetime(left), _slot_datetime(right)
    return (first is not None and second is not None
            and (first.tzinfo is None) == (second.tzinfo is None)
            and first == second)
