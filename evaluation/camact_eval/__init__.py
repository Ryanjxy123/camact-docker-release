"""CamAct Unified Evaluator public API."""
import sys
from pathlib import Path

# Both `evaluation.camact_eval` and the supported standalone `camact_eval`
# entry point share the canonical Completion taxonomy.
_ROOT = str(Path(__file__).resolve().parents[2])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from .aggregation import aggregate_results, compare_results, mechanism_metrics
from .adapters import BaselineAdapter, ExternalArtifactAdapter, RetrieverToActionAdapter, adapt_source
from .evaluator import UnifiedEvaluator, compatibility_diff
from .schema import SCHEMA_VERSION, ArtifactValidationError, StandardRunArtifact, validate_artifact_document, validate_evaluation_result_document
from .measurement import MEASUREMENT_SCHEMA_VERSION, canonical_measurement, normalize_artifact_dict

__all__ = [
    "SCHEMA_VERSION",
    "ArtifactValidationError",
    "StandardRunArtifact",
    "validate_artifact_document",
    "validate_evaluation_result_document",
    "MEASUREMENT_SCHEMA_VERSION",
    "canonical_measurement",
    "normalize_artifact_dict",
    "BaselineAdapter",
    "ExternalArtifactAdapter",
    "RetrieverToActionAdapter",
    "adapt_source",
    "UnifiedEvaluator",
    "compatibility_diff",
    "aggregate_results",
    "compare_results",
    "mechanism_metrics",
]
