"""Passive, opt-in Agent usage accounting. No model or evaluator dependencies."""
from .collector import Collector, current, scope, enabled

__all__ = ["Collector", "current", "scope", "enabled"]
