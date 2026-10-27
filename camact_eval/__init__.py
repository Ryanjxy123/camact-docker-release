"""Compatibility import path for ``python -m camact_eval``."""
from evaluation import camact_eval as _implementation
from evaluation.camact_eval import *  # noqa: F401,F403

# Keep submodule imports available even when this deployment shim was imported
# before the canonical evaluation directory was added to ``sys.path``.
__path__ = _implementation.__path__
