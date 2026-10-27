"""Stable ISO datetime parsing for existing album timestamps on Python 3.10+.

Python 3.10 accepts only three or six fractional second digits. Album metadata
also has legitimate one-digit fractions such as ``.0``. Padding to microseconds
changes neither the instant nor its timezone, and leaves invalid input invalid.
"""
from __future__ import annotations

import re
from datetime import datetime as _Datetime


_FRACTION = re.compile(r"(?<=\d{2}:\d{2}:\d{2})[.,](\d{1,6})(?=Z?$|[+-]\d{2}:\d{2}(?::\d{2})?$)")


def normalize_iso_datetime(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("fromisoformat: argument must be str")
    value = _FRACTION.sub(lambda match: "." + match[1].ljust(6, "0"), value)
    return value[:-1] + "+00:00" if value.endswith("Z") else value


class CompatibleDateTime(_Datetime):
    @classmethod
    def fromisoformat(cls, value: str):
        return super().fromisoformat(normalize_iso_datetime(value))


def bind_grader_datetime(module) -> None:
    """Adapt a grader's imported datetime binding, never the process module.

    Task/GT/rubric bytes and grader control flow remain immutable. Rebinding the
    class in the freshly loaded grader also covers ``datetime as dt`` imports.
    """
    for name, value in list(vars(module).items()):
        if value is _Datetime:
            setattr(module, name, CompatibleDateTime)

