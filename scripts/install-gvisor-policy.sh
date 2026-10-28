#!/usr/bin/env bash
# Load only the repository's bounded Runner profile; never change host policy defaults.
set -euo pipefail
camact_policy_script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
camact_policy_source_root=$(cd -- "$camact_policy_script_dir/.." && pwd -P)
exec python3 - "$camact_policy_source_root/deploy/camact-gvisor-v1.profile" "$@" <<'PY'
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile

NAME = "camact-gvisor-v1"
DATA = PurePosixPath("/var/lib/camact")
INSTALLED = Path("/etc/apparmor.d") / NAME
PROFILES = Path("/sys/kernel/security/apparmor/profiles")
DEFAULT_REPO = "Ryanjxy/CamAct-Benchmark"
DEFAULT_REVISION = "53e2f450042485dfc4a3b566de6f46988c3a5661"
ROOTS = {"results_root": ("CAMACT_RESULTS_ROOT", "/var/lib/camact/results"),
         "cache_root": ("CAMACT_CACHE_ROOT", "/var/lib/camact/benchmark"),
         "scratch_root": ("CAMACT_SCRATCH_ROOT", "/var/lib/camact/scratch"),
         "state_root": ("CAMACT_GVISOR_STATE_ROOT", "/var/lib/camact/scratch/gvisor")}
LIMIT = 8


def repository(value):
    if (len(value) > 200 or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", value)):
        raise ValueError("Repository must be a literal owner/name identifier")
    return value.replace("/", "--") + "-" + hashlib.sha256(value.encode()).hexdigest()[:12]


def revision(value):
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValueError("Revision must be an immutable lowercase SHA40")
    return value


def literal_root(value):
    path = PurePosixPath(value)
    if (len(value) > 512 or not re.fullmatch(r"/[A-Za-z0-9_./-]+", value)
            or value != path.as_posix() or not path.is_relative_to(DATA)
            or path == DATA or any(part in {".", ".."} for part in value.split("/"))
            or any("secret" in part.lower() or part.lower() in {"proc", "sys", "dev"}
                   for part in path.relative_to(DATA).parts)):
        raise ValueError("Roots must be safe literal directories strictly below /var/lib/camact")
    return value


def plain_path(path):
    """Check existing components without following any symbolic link."""
    path = Path(path)
    if not path.is_absolute() or path != Path(os.path.abspath(path)):
        raise ValueError("Host data directory must be an absolute canonical path")
    for component in [*reversed(path.parents), path]:
        if component.is_symlink():
            raise ValueError("Policy and data paths must not contain symbolic links")
        if component.exists() and not component.is_dir():
            raise ValueError("Data path components must be directories")
    return path


def bounded(values, default, validator):
    checked = sorted({validator(default), *(validator(value) for value in values)})
    if len(checked) > LIMIT:
        raise ValueError("At most eight explicit values including the default are supported per macro")
    return checked


def configuration(args, data_dir):
    host = plain_path(data_dir)
    macros = {}
    for field, (macro, default) in ROOTS.items():
        values = bounded(getattr(args, field), default, literal_root)
        for value in values:
            plain_path(host.joinpath(*PurePosixPath(value).relative_to(DATA).parts))
        macros[macro] = values
    macros["CAMACT_CACHE_REPOSITORY"] = bounded(args.repo_id, DEFAULT_REPO, repository)
    macros["CAMACT_BENCHMARK_REVISION"] = bounded(args.revision, DEFAULT_REVISION, revision)
    return macros


def read_source(path):
    path = Path(path)
    # Resolve parents only after checking every component, including the file.
    plain_path(path.parent)
    if path.is_symlink() or not path.is_file():
        raise ValueError("The fixed policy source must be a regular non-symlink file")
    source = path.read_bytes()
    if b"\r" in source or b"\0" in source:
        raise ValueError("Policy source must be LF UTF-8 text")
    text = source.decode("utf-8")
    if (re.findall(r"(?m)^profile\s+(\S+)", text) != [NAME]
            or "flags=(attach_disconnected,mediate_deleted)" not in text
            or "abi <abi/4.0>," not in text or "  userns," not in text
            or re.search(r"flags=\([^)]*\b(?:complain|unconfined)\b", text)):
        raise ValueError("The fixed named enforce ABI4 profile is required")
    return text


def macro_values(text):
    keys = {entry[0] for entry in ROOTS.values()} | {
        "CAMACT_CACHE_REPOSITORY", "CAMACT_BENCHMARK_REVISION"}
    result = {}
    for key in keys:
        matches = re.findall(r"(?m)^@\{" + key + r"\}=(.*)$", text)
        if len(matches) != 1:
            raise ValueError("Each configurable macro must occur exactly once")
        values = matches[0].split()
        if not values or len(values) > LIMIT or len(set(values)) != len(values):
            raise ValueError("Installed macro values must be finite and unique")
        if key in {entry[0] for entry in ROOTS.values()}:
            if any(literal_root(value) != value for value in values):
                raise ValueError("Unsafe installed root")
        elif key == "CAMACT_CACHE_REPOSITORY":
            if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*--[A-Za-z0-9][A-Za-z0-9_.-]*-[0-9a-f]{12}", value)
                   for value in values):
                raise ValueError("Unsafe installed repository directory")
        elif any(revision(value) != value for value in values):
            raise ValueError("Unsafe installed revision")
        result[key] = values
    return result


def render(source, macros):
    defaults = {entry[0]: [entry[1]] for entry in ROOTS.values()}
    defaults.update(CAMACT_CACHE_REPOSITORY=[repository(DEFAULT_REPO)],
                    CAMACT_BENCHMARK_REVISION=[DEFAULT_REVISION])
    if macro_values(source) != defaults:
        raise ValueError("Repository policy must retain the reviewed default macro values")
    rendered = source
    for key, values in macros.items():
        rendered, count = re.subn(r"(?m)^@\{" + key + r"\}=.*$",
                                  "@{" + key + "}=" + " ".join(values), rendered)
        if count != 1:
            raise ValueError("Only the six fixed macro lines may be rendered")
    return rendered


def enforce(profiles):
    matches = [line for line in profiles.splitlines() if line.split(" ", 1)[0] == NAME]
    if matches != [NAME + " (enforce)"]:
        raise ValueError("The exact named profile must be loaded in enforce mode")


def supported(installed, source, requested):
    actual = macro_values(installed)
    # Reconstructing from the trusted source rejects edits outside the six macros.
    if render(source, actual) != installed:
        raise ValueError("Installed policy differs outside the six configurable macro lines")
    if any(not set(values).issubset(actual[key]) for key, values in requested.items()):
        raise ValueError("Requested root/repository/revision is absent; reinstall explicitly before use")
    return actual


def install(text):
    if os.geteuid() != 0 or sys.platform != "linux":
        raise ValueError("Install requires root on the dedicated Linux deployment host")
    parser = shutil.which("apparmor_parser")
    if not parser or Path("/sys/module/apparmor/parameters/enabled").read_text().strip() != "Y":
        raise ValueError("AppArmor must already be enabled; install its ABI4 parser without disabling the LSM")
    version = subprocess.run([parser, "--version"], check=True, capture_output=True, text=True).stdout
    match = re.search(r"version\s+(\d+)\.", version)
    if not match or int(match.group(1)) < 4:
        raise ValueError("An AppArmor 4 or newer parser with ABI4/userns support is required")
    plain_path(INSTALLED.parent)
    if INSTALLED.is_symlink() or (INSTALLED.exists() and not INSTALLED.is_file()):
        raise ValueError("Fixed installed policy must be a regular non-symlink file")
    descriptor, temporary = tempfile.mkstemp(prefix=".camact-gvisor-v1-", dir=INSTALLED.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        # Compile only first. Never relax ABI4 or force complain mode on failure.
        subprocess.run([parser, "-Q", "-K", temporary], check=True)
        os.chmod(temporary, 0o644)
        os.replace(temporary, INSTALLED)
        # This is the only kernel policy mutation and its path is fixed.
        subprocess.run([parser, "-r", "-K", str(INSTALLED)], check=True)
        enforce(PROFILES.read_text())
    finally:
        Path(temporary).unlink(missing_ok=True)


def main(argv):
    source_path = Path(argv[0]).absolute()
    parser = argparse.ArgumentParser(description="Install/check the fixed bounded camact-gvisor-v1 profile")
    parser.add_argument("action", choices=("install", "check", "check-roots"))
    parser.add_argument("--data-dir", type=Path, help="Host CAMACT_DATA_DIR; defaults to repository .data")
    for field in ROOTS:
        parser.add_argument("--" + field.replace("_", "-"), action="append", default=[])
    parser.add_argument("--repo-id", action="append", default=[])
    parser.add_argument("--revision", action="append", default=[])
    arguments = ["check-roots" if value == "--check-roots" else value for value in argv[1:]]
    args = parser.parse_args(arguments)
    source = read_source(source_path)
    data_dir = args.data_dir or source_path.parent.parent / ".data"
    macros = configuration(args, data_dir)
    text = render(source, macros)
    verified = False
    if args.action == "install":
        install(text)
        verified = True
    elif args.action == "check-roots":
        macros = supported(read_source(INSTALLED), source, macros)
        enforce(PROFILES.read_text())
        text = render(source, macros)
        verified = True
    print(json.dumps({"schema": "camact.gvisor.policy-install.v1", "action": args.action,
                      "profile": NAME, "enforce_verified": verified,
                      "policy_sha256": hashlib.sha256(text.encode()).hexdigest(), "macros": macros,
                      "runtime_acceptance_required": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("Policy installation/check failed: " + str(error), file=sys.stderr)
        sys.exit(1)
PY
