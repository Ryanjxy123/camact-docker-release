"""Actual child tempfile/exec behavior with a tiny synthetic offline runner."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("compose_offline_bootstrap", ROOT / "scripts/run-compose-offline-tests.py")
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class ComposeOfflineBootstrap(unittest.TestCase):
    def setUp(self):
        archive = os.environ.get("CAMACT_TEST_OUTPUT")
        self.temporary = tempfile.TemporaryDirectory(prefix="compose-offline-bootstrap-", dir=archive)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()
        self.output = self.scratch / "docker-gates-fixture123/offline-tests"
        self.runner = self.root / "synthetic-offline-runner.py"
        self.runner.write_text('''import argparse,json,os,pathlib,subprocess,tempfile
p=argparse.ArgumentParser();p.add_argument('--output');a=p.parse_args()
output=pathlib.Path(a.output)
assert os.environ['CAMACT_TEST_OUTPUT']==str(output)==os.environ['CAMACT_TEST_ARCHIVE']
expected=output.parent/'tmp'
assert pathlib.Path(tempfile.gettempdir())==expected
with tempfile.TemporaryDirectory() as directory:
    child=pathlib.Path(directory)/'synthetic-exec-stub'
    child.write_text('#!/bin/sh\\nexit 0\\n');child.chmod(0o700)
    assert subprocess.run([str(child)]).returncode==0
(output/'synthetic-behavior.json').write_text(json.dumps({'tempfile_and_exec':True,'tmp':str(expected)}))
raise SystemExit(17)
''')

    def test_fresh_child_uses_scoped_tmpdir_exec_and_propagates_exit17(self):
        old_environment = dict(os.environ)
        with patch.object(bootstrap, "SCRATCH", self.scratch), patch.object(bootstrap, "RUNNER", self.runner):
            self.assertEqual(bootstrap.run(str(self.output)), 17)
        self.assertEqual(dict(os.environ), old_environment)
        evidence = json.loads((self.output / "evidence/synthetic-behavior.json").read_text())
        self.assertTrue(evidence["tempfile_and_exec"])
        for path in (self.output, self.output / "tmp", self.output / "evidence"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)

    def test_noexec_scratch_is_rejected_before_any_child(self):
        with patch.object(bootstrap, "SCRATCH", self.scratch), patch.object(bootstrap.os, "statvfs", return_value=SimpleNamespace(f_flag=os.ST_NOEXEC)), \
                patch.object(bootstrap.subprocess, "run") as child:
            with self.assertRaisesRegex(ValueError, "noexec"):
                bootstrap.run(str(self.output))
            child.assert_not_called()

    def test_existing_output_cannot_be_reused(self):
        self.output.mkdir(parents=True)
        with patch.object(bootstrap, "SCRATCH", self.scratch), self.assertRaisesRegex(ValueError, "already_exists"):
            bootstrap.run(str(self.output))

    def test_symlink_ancestor_and_non_directory_are_rejected(self):
        outside = self.root / "outside"
        outside.mkdir()
        self.output.parent.symlink_to(outside, target_is_directory=True)
        with patch.object(bootstrap, "SCRATCH", self.scratch), self.assertRaisesRegex(ValueError, "ancestor"):
            bootstrap.run(str(self.output))
        self.output.parent.unlink()
        self.output.parent.write_text("synthetic file")
        with patch.object(bootstrap, "SCRATCH", self.scratch), self.assertRaisesRegex(ValueError, "ancestor"):
            bootstrap.run(str(self.output))

    def test_unscoped_noncanonical_and_other_stage_paths_are_rejected(self):
        with patch.object(bootstrap, "SCRATCH", self.scratch):
            for value in (str(self.root / "outside/offline-tests"), str(self.scratch / "other/offline-tests"),
                          str(self.output.parent / "other-stage"), str(self.output) + "/../offline-tests"):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    bootstrap.run(value)


if __name__ == "__main__":
    unittest.main()
