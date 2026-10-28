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
from release.diagnostics import PREFIX, failure_detail, path_status

USAGE_MODULES = (
    "test_normalization", "test_protocol_regressions", "test_native_identity",
    "test_unified_independent", "test_completeness", "test_attempt_recovery",
    "test_audit_attempts", "test_recover_history",
)


class DiagnosticResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.failure_details = []

    def addFailure(self, test, err):
        self.failure_details.append(failure_detail(test, err, PROJECT))
        super().addFailure(test, err)

    def addError(self, test, err):
        self.failure_details.append(failure_detail(test, err, PROJECT))
        super().addError(test, err)

    def addSubTest(self, test, subtest, err):
        if err is not None:
            self.failure_details.append(failure_detail(test, err, PROJECT, subtest=True))
        super().addSubTest(test, subtest, err)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Evidence directory; defaults to CAMACT_TEST_OUTPUT or a private temporary directory.")
    args = parser.parse_args()
    public = {"schema": "camact.offline-diagnostics.v1", "success": False,
              "uid": os.getuid(), "gid": os.getgid(), "failure_details": []}
    try:
        destination = args.output or (Path(os.environ["CAMACT_TEST_OUTPUT"]) if os.environ.get("CAMACT_TEST_OUTPUT")
                                      else Path(tempfile.mkdtemp(prefix="camact-offline-tests-")))
        destination = destination.resolve()
        destination.mkdir(parents=True, exist_ok=True)
        os.environ["CAMACT_TEST_OUTPUT"] = str(destination)
        os.environ.setdefault("CAMACT_TEST_ARCHIVE", str(destination))
        public["paths"] = {"output": path_status(destination, probe=True),
                           "archive": path_status(os.environ["CAMACT_TEST_ARCHIVE"], probe=True),
                           "temporary": path_status(tempfile.gettempdir(), probe=True),
                           "project": path_status(PROJECT)}
        for key in ("CAMACT_DATA_ROOT", "CAMACT_SCRATCH_ROOT", "CAMACT_OPENCLAW_TMPDIR"):
            if os.environ.get(key):
                public["paths"][key] = path_status(os.environ[key])
        from release import runner  # Configure the same import roots as production.

        suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(
            "harness.camact_token_usage_v1." + name) for name in USAGE_MODULES)
        suite.addTests(unittest.defaultTestLoader.discover(str(PROJECT / "tests"), pattern="test_*.py"))
        result = unittest.TextTestRunner(verbosity=2, resultclass=DiagnosticResult).run(suite)
        public.update(success=result.wasSuccessful(), testsRun=result.testsRun,
                      failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped),
                      failure_details=result.failure_details)
    except Exception:
        class Setup:
            def id(self):
                return "run_offline_tests.setup"
        public["failure_details"].append(failure_detail(Setup(), sys.exc_info(), PROJECT))
        print(PREFIX + json.dumps(public, sort_keys=True), flush=True)
        return 1
    report = {"python": sys.version, "executable": sys.executable, "prefix": sys.prefix,
              "testsRun": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
              "skipped": len(result.skipped), "success": result.wasSuccessful(), "evidence": str(destination),
              "external_model_requests": 0, "canonical_benchmark_tasks": 0,
              "diagnostics": public}
    try:
        (destination / "offline-tests.json").write_text(json.dumps(report, indent=2) + "\n")
    except OSError:
        class EvidenceWrite:
            def id(self):
                return "run_offline_tests.evidence_write"
        public["success"] = False
        public["failure_details"].append(failure_detail(EvidenceWrite(), sys.exc_info(), PROJECT))
        print(PREFIX + json.dumps(public, sort_keys=True), flush=True)
        return 1
    print(PREFIX + json.dumps(public, sort_keys=True), flush=True)
    print(json.dumps(report, indent=2))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
