"""Claude execution -> Standard Run Artifact adapter boundary.

This layer only normalizes execution telemetry. It never reads ground truth or
performs scoring; the Unified Evaluator remains the scoring owner.
"""
from __future__ import annotations

from typing import Any


class ClaudeCodeAdapter:
    """Serialize one completed Claude execution into the shared artifact."""

    @staticmethod
    def to_standard_artifact(**execution: Any):
        from .runner import _standard_artifact

        return _standard_artifact(**execution)

