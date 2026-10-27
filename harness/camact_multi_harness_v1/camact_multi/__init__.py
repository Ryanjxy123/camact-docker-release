"""Shared outer orchestration; all agent loops belong to the official CLIs."""
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[3]
for path in (PROJECT, PROJECT / "harness" / "claude code"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

