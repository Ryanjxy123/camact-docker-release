#!/usr/bin/env python3
"""Run release contracts and original Usage regressions without model requests."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

USAGE_MODULES = (
    "test_normalization", "test_protocol_regressions", "test_native_identity",
    "test_unified_independent", "test_completeness", "test_attempt_recovery",
    "test_audit_attempts", "test_recover_history",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Evidence directory; defaults to CAMACT_TEST_OUTPUT or a private temporary directory.")
    args = parser.parse_args()
    destination = args.output or (Path(os.environ["CAMACT_TEST_OUTPUT"]) if os.environ.get("CAMACT_TEST_OUTPUT")
                                  else Path(tempfile.mkdtemp(prefix="camact-offline-tests-")))
    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    os.environ["CAMACT_TEST_OUTPUT"] = str(destination)
    from release import runner  # Configure the same import roots as production.

    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(
        "harness.camact_token_usage_v1." + name) for name in USAGE_MODULES)
    suite.addTests(unittest.defaultTestLoader.discover(str(PROJECT / "tests"), pattern="test_*.py"))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {"python": sys.version, "executable": sys.executable, "prefix": sys.prefix,
              "testsRun": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
              "skipped": len(result.skipped), "success": result.wasSuccessful(), "evidence": str(destination),
              "external_model_requests": 0, "canonical_benchmark_tasks": 0}
    (destination / "offline-tests.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
