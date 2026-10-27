"""Verifiable environment gate for formal evaluation; APIs remain portable."""
from __future__ import annotations

import importlib.metadata
import platform
import sys
from pathlib import Path


def evaluation_environment(*, require_formal: bool = False) -> dict:
    lock = Path(__file__).with_name("requirements-evaluator.lock")
    expected = dict(line.split("==", 1) for line in lock.read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.startswith("#"))
    actual = {}
    for name in expected:
        try:
            actual[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            actual[name] = None
    mismatches = {name: {"expected": version, "actual": actual[name]}
                  for name, version in expected.items() if actual[name] != version}
    formal = sys.version_info[:2] == (3, 13) and not mismatches
    record = {"python": platform.python_version(), "executable": sys.executable,
              "required_python": "3.13", "dependencies": actual,
              "dependency_mismatches": mismatches, "formal": formal}
    if require_formal and not formal:
        raise RuntimeError("Formal Unified Evaluator requires Python 3.13 and "
                           f"{lock.name}; actual Python {record['python']}, mismatches={mismatches}")
    return record
