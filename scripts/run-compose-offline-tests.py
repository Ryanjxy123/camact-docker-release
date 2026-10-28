#!/usr/bin/env python3
"""Keep executable test fixtures on this verification run's private data bind."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

SCRATCH = Path("/var/lib/camact/scratch")
RUNNER = Path(__file__).resolve().with_name("run-offline-tests.py")


def safe_output(value):
    path = Path(value)
    if not path.is_absolute() or path.as_posix() != os.fspath(value):
        raise ValueError("noncanonical_output")
    try:
        relative = path.relative_to(SCRATCH)
    except ValueError:
        raise ValueError("output_outside_verification_scratch") from None
    if (len(relative.parts) != 2 or relative.parts[1] != "offline-tests"
            or not re.fullmatch(r"docker-gates-[a-z0-9][a-z0-9-]{0,100}", relative.parts[0])):
        raise ValueError("output_not_scoped_to_verification_run")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("unsafe_output_ancestor")
    if not SCRATCH.is_dir() or SCRATCH.is_symlink():
        raise ValueError("scratch_root_unavailable")
    if path.exists():
        raise ValueError("output_already_exists")
    return path


def run(value):
    output = safe_output(value)
    output.parent.mkdir(mode=0o700, exist_ok=True)
    output.mkdir(mode=0o700, exist_ok=False)
    temporary, evidence = output / "tmp", output / "evidence"
    temporary.mkdir(mode=0o700)
    evidence.mkdir(mode=0o700)
    for directory in (output, temporary, evidence):
        directory.chmod(0o700)
    if os.statvfs(temporary).f_flag & os.ST_NOEXEC:
        raise ValueError("verification_scratch_is_noexec")
    probe = temporary / "trusted-exec-probe"
    with probe.open("x", encoding="utf-8") as stream:
        stream.write("#!/bin/sh\nexit 0\n")
    probe.chmod(0o700)
    try:
        checked = subprocess.run([str(probe)], timeout=10)
        if checked.returncode:
            raise ValueError("verification_scratch_exec_probe_failed")
    finally:
        probe.unlink()
    environment = os.environ.copy()
    environment.update(TMPDIR=str(temporary), CAMACT_TEST_OUTPUT=str(evidence), CAMACT_TEST_ARCHIVE=str(evidence))
    # The fresh interpreter imports tempfile after this child-only environment
    # is installed. Production /tmp and other verification stages are untouched.
    return subprocess.run([sys.executable, "-B", str(RUNNER), "--output", str(evidence)], env=environment).returncode


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        return run(args.output)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        reason = str(exc) if type(exc) is ValueError else "filesystem_or_execution_failure"
        print(json.dumps({"schema": "camact.compose-offline-bootstrap.v1", "result": "FAIL", "failure": reason}), file=sys.stderr)
        return 125


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main())
