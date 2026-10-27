#!/usr/bin/env python3
"""Scan a Docker save archive without extracting it or printing candidate values.

``--image`` spools the ``docker save`` tar stream to temporary storage (up to
64 MiB in memory, then the host temporary directory) before validating every
declared config and layer.
"""
from __future__ import annotations

import argparse
import importlib.util
import io
import ipaddress
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

CHUNK_SIZE = 1024 * 1024
TAIL_SIZE = 1024
PERSONAL_NAMES = {".ssh", ".aws", ".npmrc", ".netrc", ".pypirc", "id_rsa"}
TEMPLATES = {".env.example", "config/models.env.example"}
ASSIGNMENT_RE = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:API[_-]?KEY|ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN|"
    r"CLIENT[_-]?SECRET|PRIVATE[_-]?KEY|PASSWORD|PASSWD|SECRET|TOKEN)[A-Z0-9_]*)\b"
    r"\s*[:=]\s*[\"']?([^\s\"'\x60;,}]*)"
)
DIRECT_ASSIGNMENT_RE = re.compile(
    r"(?m)^\s*(?:export\s+|ENV\s+)?([A-Z0-9_]*(?:API[_-]?KEY|ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN|"
    r"CLIENT[_-]?SECRET|PRIVATE[_-]?KEY|PASSWORD|PASSWD|SECRET|TOKEN)[A-Z0-9_]*)\b"
    r"\s*[:=]\s*[\"']?([^\s\"'\x60;,}]*)"
)
NUMERIC_GATEWAY_RE = re.compile(r"https?://(\d+\.\d+\.\d+\.\d+)(?::\d+)?")

_spec = importlib.util.spec_from_file_location("release_scanner", Path(__file__).with_name("scan-release.py"))
_release_scanner = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(_release_scanner)


class ScanFailure(Exception):
    pass


def add_issue(issues, location, kind):
    issues.append({"file": location, "kind": kind})


def safe_name(name):
    if not isinstance(name, str):
        raise ScanFailure("archive path is not text")
    path = PurePosixPath(name)
    if name.startswith("/") or ".." in path.parts or not path.parts:
        raise ScanFailure("unsafe archive path")
    return "/".join(path.parts)


def scan_text(text, location, issues, metadata=False):
    for kind, pattern in _release_scanner.SECRET_PATTERNS.items():
        if pattern.search(text):
            add_issue(issues, location, kind)
    for match in NUMERIC_GATEWAY_RE.finditer(text):
        address = ipaddress.ip_address(match.group(1))
        if not (address.is_loopback or address.is_unspecified):
            add_issue(issues, location, "numeric_gateway")
            break
    assignments = ASSIGNMENT_RE if metadata else DIRECT_ASSIGNMENT_RE
    for match in assignments.finditer(text):
        value = match.group(2)
        placeholders = {"placeholder", "changeme", "test", "<redacted>", "$" + "{VAR}", "$" + "{KEY}",
                       "0", "1", "true", "false", "none", "null", "unset",
                       "camact-local-protocol-bridge", "camact-local-relay-credential"}
        if re.fullmatch(r"[A-Z][A-Z0-9_]*", value):
            continue
        # Python modules often define uppercase token constants, regexes, or
        # collections.  Those expressions are source code, not assigned
        # secret values; shell/ENV assignments still contain a literal value.
        if (value in {"(", "[", "{"} or value.startswith(("re.compile(", "regex.compile("))
                or (value.endswith("(") and "." in value)):
            continue
        if value and value not in placeholders:
            add_issue(issues, location, "nonempty_secret_metadata" if metadata else "nonempty_secret_assignment")
            break


def scan_stream(source, location, issues, metadata=False):
    tail = ""
    while True:
        chunk = source.read(CHUNK_SIZE)
        if not chunk:
            return
        text = tail + chunk.decode("utf-8", errors="replace")
        scan_text(text, location, issues, metadata)
        tail = text[-TAIL_SIZE:]


def path_issue(path, size, regular=True):
    parts = PurePosixPath(path).parts
    base = parts[-1] if parts else ""
    if path in TEMPLATES or base == ".env.example" or path.endswith("config/models.env.example"):
        return None
    if any(part in PERSONAL_NAMES for part in parts):
        return "personal_config_or_credential_path"
    if any(part.startswith(".env") for part in parts):
        return "personal_config_or_credential_path"
    if base.endswith((".pem", ".key")) or base == "id_rsa":
        return "personal_config_or_credential_path"
    if regular and size and any(part in {".secrets", "runsecrets", "secrets"} for part in parts):
        return "nonempty_runtime_secret_path"
    project = path.startswith("opt/camact/")
    data_dir = any(path.startswith("opt/camact/" + part + "/")
                   for part in ("benchmark/tasks", "benchmark/users", "results", "logs", "cache", "scratch", "checkpoints"))
    artifact = base in {"result.json", "run_manifest.json", "formal_config.json", "auth.json"} or base.endswith((".jsonl", ".log"))
    if regular and project and (data_dir or artifact):
        return "project_data_or_runtime_artifact"
    return None


def scan_layer(source, label, issues):
    try:
        nested = tarfile.open(fileobj=source, mode="r|*")
        count = 0
        seen = set()
        for member in nested:
            name = safe_name(member.name)
            if name in seen:
                raise ScanFailure("duplicate layer member")
            seen.add(name)
            if member.isdir():
                continue
            if member.issym() or member.islnk():
                kind = path_issue(name, 0, regular=False)
                if kind:
                    add_issue(issues, label + ":" + name, kind)
                continue
            if not member.isfile():
                raise ScanFailure("unsupported layer member")
            count += 1
            kind = path_issue(name, member.size)
            if kind:
                add_issue(issues, label + ":" + name, kind)
                continue
            fileobj = nested.extractfile(member)
            if fileobj is None:
                raise ScanFailure("missing layer member content")
            scan_stream(fileobj, label + ":" + name, issues)
        nested.close()
        if count == 0:
            raise ScanFailure("empty layer")
    except (tarfile.TarError, OSError, EOFError):
        raise ScanFailure("malformed layer archive")


def require_end_blocks(raw):
    if len(raw) < 1024 or raw[-1024:] != b"\0" * 1024:
        raise ScanFailure("missing tar end blocks")


def scan_archive_bytes(source):
    issues = []
    raw_archive = source.read()
    require_end_blocks(raw_archive)
    try:
        with tarfile.open(fileobj=io.BytesIO(raw_archive), mode="r:*") as outer:
            members = {}
            payloads = {}
            for member in outer:
                name = safe_name(member.name)
                if name in members:
                    raise ScanFailure("duplicate docker archive member")
                members[name] = member
                if member.isfile():
                    fileobj = outer.extractfile(member)
                    if fileobj is None:
                        raise ScanFailure("missing archive member content")
                    payloads[name] = fileobj.read()
    except (tarfile.TarError, OSError, EOFError):
        raise ScanFailure("malformed docker archive")
    try:
        manifest = json.loads(payloads["manifest.json"])
        if not isinstance(manifest, list) or not manifest:
            raise ValueError
    except (KeyError, ValueError, TypeError, json.JSONDecodeError):
        raise ScanFailure("invalid or missing manifest")
    declared = set()
    for index, image in enumerate(manifest):
        if not isinstance(image, dict) or not isinstance(image.get("Config"), str) or not isinstance(image.get("Layers"), list):
            raise ScanFailure("invalid manifest entry")
        config_name = safe_name(image["Config"])
        config_raw = payloads.get(config_name)
        if config_raw is None:
            raise ScanFailure("missing image config")
        try:
            config = json.loads(config_raw)
            if not isinstance(config, dict):
                raise ValueError
        except (ValueError, TypeError, json.JSONDecodeError):
            raise ScanFailure("invalid image config")
        location = "config[" + str(index) + "]"
        scan_text(config_raw.decode("utf-8", errors="replace"), location, issues, metadata=True)
        if not isinstance(config.get("config"), dict):
            raise ScanFailure("image config section is missing")
        if not isinstance(config.get("history"), list):
            raise ScanFailure("image history is missing")
        cfg = config["config"]
        for field in ("Env", "Cmd", "Entrypoint"):
            value = cfg.get(field)
            if value is not None and not isinstance(value, list):
                raise ScanFailure("image config list field is malformed")
            for number, item in enumerate(value or []):
                if not isinstance(item, str):
                    raise ScanFailure("image config list item is malformed")
                scan_text(item, location + "." + field + "[" + str(number) + "]", issues, metadata=True)
        for number, item in enumerate(config["history"]):
            if not isinstance(item, dict):
                raise ScanFailure("image history item is malformed")
            scan_text(json.dumps(item, ensure_ascii=False), location + ".history[" + str(number) + "]", issues, metadata=True)
        labels = cfg.get("Labels")
        if labels is not None and not isinstance(labels, dict):
            raise ScanFailure("image labels are malformed")
        for number, (key, value) in enumerate((labels or {}).items()):
            if not isinstance(key, str) or not isinstance(value, str):
                raise ScanFailure("image label is malformed")
            scan_text(key + "=" + value, location + ".labels[" + str(number) + "]", issues, metadata=True)
        for number, layer_name in enumerate(image["Layers"]):
            if not isinstance(layer_name, str):
                raise ScanFailure("image layer name is malformed")
            layer_path = safe_name(layer_name)
            if layer_path in declared:
                raise ScanFailure("duplicate declared layer")
            declared.add(layer_path)
            raw = payloads.get(layer_path)
            if raw is None:
                raise ScanFailure("missing image layer")
            require_end_blocks(raw)
            scan_layer(io.BytesIO(raw), "layer[" + str(number) + "]", issues)
    actual = {name for name in payloads if name.endswith("/layer.tar")}
    if actual != declared:
        raise ScanFailure("undeclared image layer")
    return issues


def run_archive(archive, image):
    if archive is not None:
        try:
            with archive.open("rb") as source:
                return scan_archive_bytes(source)
        except OSError:
            raise ScanFailure("unreadable archive")
    process = subprocess.Popen([os.environ.get("CAMACT_DOCKER", "docker"), "save", image],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    assert process.stdout is not None
    try:
        # docker save is a tar stream. Spool one archive to temporary storage so
        # all declared config and layer members can be validated before scanning.
        with tempfile.SpooledTemporaryFile(max_size=64 * 1024 * 1024) as spool:
            while True:
                chunk = process.stdout.read(CHUNK_SIZE)
                if not chunk:
                    break
                spool.write(chunk)
            if process.wait() != 0:
                raise ScanFailure("docker save failed")
            spool.seek(0)
            result = scan_archive_bytes(spool)
    except Exception:
        if process.poll() is None:
            process.kill()
            process.wait()
        raise ScanFailure("docker archive scan failed")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--image")
    group.add_argument("--archive", type=Path)
    args = parser.parse_args(argv)
    try:
        issues = run_archive(args.archive, args.image)
        result = {"scope": "docker-image", "issues": issues, "issue_count": len(issues),
                  "result": "PASS" if not issues else "FAIL", "candidate_values_printed": False}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1 if issues else 0
    except (ScanFailure, OSError, ValueError, tarfile.TarError):
        print(json.dumps({"scope": "docker-image", "issues": [{"file": "<archive>", "kind": "scan_failed"}],
                          "issue_count": 1, "result": "FAIL", "candidate_values_printed": False},
                         ensure_ascii=False, indent=2))
        return 1


if __name__ == "__main__":
    sys.exit(main())
