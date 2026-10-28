#!/usr/bin/env python3
"""Scan a Docker save archive without extracting it or printing candidate values.

``--image`` spools the ``docker save`` tar stream to temporary storage (up to
64 MiB in memory, then the host temporary directory) before validating every
declared config and layer.
"""
from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import importlib.util
import io
import ipaddress
import json
import lzma
import os
import posixpath
import re
import ssl
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
    """Only fixed diagnostic codes and archive locations may be reported."""

    def __init__(self, reason, location="<archive>", exit_code=None):
        super().__init__(reason)
        self.reason = reason.replace(" ", "_")
        self.location = location
        self.exit_code = exit_code


def add_issue(issues, location, kind, candidate=None):
    issue = {"file": location, "kind": kind}
    if candidate is not None:
        issue["match_sha256"] = hashlib.sha256(candidate.encode()).hexdigest()
    if issue not in issues:
        issues.append(issue)


def safe_location(location):
    for pattern in _release_scanner.SECRET_PATTERNS.values():
        location = pattern.sub("<redacted>", location)
    return ASSIGNMENT_RE.sub(lambda match: match.group(1) + "=<redacted>", location)


def load_exceptions():
    """Reviewed upstream findings, bound to one exact path and file digest.

    This policy contains hashes, public package provenance and review notes,
    never candidate values. It cannot exempt a directory or a whole rule.
    """
    path = Path(__file__).resolve().parents[1] / "locks/image-scan-exceptions.json"
    try:
        policy = json.loads(path.read_text())
        if policy["schema"] != "camact.image-scan-exceptions.v1":
            raise ValueError
        sources = policy["sources"]
        root = path.parents[1]
        locks = {}
        for source in sources.values():
            lock_file = source["lock_file"]
            if lock_file == "locks/runtimes.json":
                if source["lock_entry"] not in {"node", "gvisor"}:
                    raise ValueError
                locks.setdefault(lock_file, json.loads((root / lock_file).read_text()))
                pinned = locks[lock_file][source["lock_entry"]]
                algorithm = "sha256" if "sha256" in pinned else "sha512"
                if source["url"] != pinned["url"] or source["integrity"] != algorithm + ":" + pinned[algorithm]:
                    raise ValueError
            elif re.fullmatch(r"locks/cli/(claude|codex|opencode|deepseek|openclaw)/package-lock.json", lock_file):
                if lock_file not in locks:
                    locks[lock_file] = json.loads((root / lock_file).read_text())
                pinned = locks[lock_file]["packages"][source["lock_entry"]]
                if source["url"] != pinned["resolved"] or source["integrity"] != pinned["integrity"]:
                    raise ValueError
            elif lock_file in {"locks/requirements-runtime.lock", "locks/requirements-bootstrap.lock"}:
                if not re.fullmatch(r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.+-]+", source["lock_entry"]):
                    raise ValueError
                expected = source["lock_entry"] + " --hash=" + source["integrity"]
                if expected not in (root / lock_file).read_text().splitlines():
                    raise ValueError
                if not source["url"].startswith("https://files.pythonhosted.org/"):
                    raise ValueError
            elif lock_file == "Dockerfile":
                image = source["lock_entry"]
                if not re.fullmatch(r"python:[A-Za-z0-9_.-]+@sha256:[a-f0-9]{64}", image):
                    raise ValueError
                if not re.search(r"^FROM " + re.escape(image) + r"(?: AS [a-z-]+)?$",
                                 (root / "Dockerfile").read_text(), re.MULTILINE):
                    raise ValueError
                if not re.fullmatch(r"sha256:[a-f0-9]{64}", source["integrity"]):
                    raise ValueError
                if source["url"] != "https://registry-1.docker.io/v2/library/python/blobs/" + source["integrity"]:
                    raise ValueError
            else:
                raise ValueError
        entries = {}
        for entry in policy["files"]:
            name = safe_name(entry["path"])
            if not name.startswith(("opt/camact/.tools/", "usr/", "etc/")):
                raise ValueError
            if not re.fullmatch(r"[a-f0-9]{64}", entry["sha256"]):
                raise ValueError
            source = sources[entry["source"]]
            if not source["url"].startswith(("https://nodejs.org/dist/", "https://registry.npmjs.org/",
                                             "https://storage.googleapis.com/gvisor/releases/",
                                             "https://registry-1.docker.io/v2/library/python/blobs/",
                                             "https://files.pythonhosted.org/")):
                raise ValueError
            if not source["integrity"] or not entry["source_member"] or not entry["review"]:
                raise ValueError
            for finding in entry["findings"]:
                if not re.fullmatch(r"[a-f0-9]{64}", finding["match_sha256"]):
                    raise ValueError
                if finding["kind"] not in {*_release_scanner.SECRET_PATTERNS, "numeric_gateway",
                                            "nonempty_secret_assignment", "personal_config_or_credential_path"}:
                    raise ValueError
            versions = entries.setdefault(name, {})
            if entry["sha256"] in versions:
                raise ValueError
            versions[entry["sha256"]] = entry
        return entries
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise ScanFailure("invalid upstream exception policy", "<exception-policy>") from None


def safe_name(name):
    if not isinstance(name, str):
        raise ScanFailure("archive path is not text")
    path = PurePosixPath(name)
    if name.startswith("/") or ".." in path.parts or not path.parts:
        raise ScanFailure("unsafe archive path")
    return "/".join(path.parts)


def scan_text(text, location, issues, metadata=False):
    for kind, pattern in _release_scanner.SECRET_PATTERNS.items():
        for match in pattern.finditer(text):
            add_issue(issues, location, kind, match.group())
    for match in NUMERIC_GATEWAY_RE.finditer(text):
        try:
            address = ipaddress.ip_address(match.group(1))
        except ValueError:
            continue  # An invalid IP literal cannot identify a gateway.
        if not (address.is_loopback or address.is_unspecified):
            add_issue(issues, location, "numeric_gateway", match.group())
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
            add_issue(issues, location, "nonempty_secret_metadata" if metadata else "nonempty_secret_assignment", match.group())


def scan_stream(source, location, issues, metadata=False):
    tail = ""
    digest = hashlib.sha256()
    while True:
        chunk = source.read(CHUNK_SIZE)
        if not chunk:
            return digest.hexdigest()
        digest.update(chunk)
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


def public_certificate(data):
    """Accept only complete, parseable public X.509 PEM certificates."""
    if not re.fullmatch(rb"(?:\s*-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*)+", data):
        return False
    try:
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=data.decode("ascii"))
        return True
    except (ssl.SSLError, UnicodeError):
        return False


def check_certificate_links(context, issues, stats):
    for location, target in context["certificate_links"]:
        if target in context["public_certificates"]:
            stats["public_certificate_paths_verified"] = stats.get("public_certificate_paths_verified", 0) + 1
        else:
            add_issue(issues, location, "personal_config_or_credential_path")


def scan_layer(source, label, issues, exceptions, stats, context=None):
    own_context = context is None
    context = context if context is not None else {"public_certificates": set(), "certificate_links": []}
    try:
        nested = tarfile.open(fileobj=source, mode="r|*")
        seen = set()
        for member in nested:
            if member.isdir() and member.name in {".", "./"}:
                continue  # Debian's official rootfs tar includes this entry.
            name = safe_name(member.name)
            if name in seen:
                raise ScanFailure("duplicate layer member")
            seen.add(name)
            if member.isdir():
                continue
            if member.issym() or member.islnk():
                kind = path_issue(name, 0, regular=False)
                if (member.issym() and PurePosixPath(name).parent == PurePosixPath("etc/ssl/certs")
                        and name.endswith(".pem") and path_issue(name[:-4] + ".crt", 0, regular=False) is None):
                    target = posixpath.normpath(posixpath.join("/", posixpath.dirname(name), member.linkname)).lstrip("/")
                    if target.startswith("usr/share/ca-certificates/") and target.endswith(".crt"):
                        context["certificate_links"].append((label + ":" + name, target))
                        continue
                if (member.issym() and name == "usr/lib/ssl/cert.pem"
                        and member.linkname == "/etc/ssl/certs/ca-certificates.crt"):
                    context["certificate_links"].append((label + ":" + name, "etc/ssl/certs/ca-certificates.crt"))
                    continue
                if kind:
                    add_issue(issues, label + ":" + name, kind)
                continue
            if not member.isfile():
                raise ScanFailure("unsupported layer member", label + ":" + name)
            location = label + ":" + name
            findings = []
            kind = path_issue(name, member.size)
            fileobj = nested.extractfile(member)
            if fileobj is None:
                raise ScanFailure("missing layer member content")
            # CA bundles have a .pem suffix too. Validate the complete content;
            # appended private keys, assignments or comments cannot qualify.
            certificate = False
            if name.endswith((".pem", ".crt")) and member.size <= 2 * CHUNK_SIZE:
                content = fileobj.read()
                certificate = public_certificate(content)
                fileobj = io.BytesIO(content)
            if certificate:
                context["public_certificates"].add(name)
                if (kind == "personal_config_or_credential_path" and name.endswith(".pem")
                        and path_issue(name[:-4] + ".crt", member.size) is None):
                    kind = None
                    stats["public_certificate_paths_verified"] = stats.get("public_certificate_paths_verified", 0) + 1
            else:
                context["public_certificates"].discard(name)
            if kind:
                add_issue(findings, location, kind, name)
            digest = scan_stream(fileobj, location, findings)
            stats["files_scanned"] += 1
            stats["bytes_scanned"] += member.size
            versions = exceptions.get(name, {})
            approved = versions.get(digest)
            if versions and approved is None:
                add_issue(findings, location, "upstream_file_digest_mismatch")
            allowed = {(item["kind"], item["match_sha256"]) for item in approved["findings"]} if approved else set()
            for finding in findings:
                if (finding["kind"], finding.get("match_sha256")) in allowed:
                    stats["reviewed_upstream_findings"] += 1
                else:
                    issues.append(finding)
        nested.close()
        if own_context:
            check_certificate_links(context, issues, stats)
    except (tarfile.TarError, OSError, EOFError):
        raise ScanFailure("malformed layer archive", label) from None


def require_end_blocks(source):
    source.seek(0, os.SEEK_END)
    if source.tell() < 1024:
        raise ScanFailure("missing tar end blocks")
    source.seek(-1024, os.SEEK_END)
    if source.read(1024) != b"\0" * 1024:
        raise ScanFailure("missing tar end blocks")
    source.seek(0)


def scan_layer_archive(source, label, issues, exceptions, stats, context):
    """Docker's containerd exporter can retain compressed OCI layer blobs."""
    magic = source.read(6)
    source.seek(0)
    if magic.startswith(b"\x1f\x8b"):
        unpacked = gzip.GzipFile(fileobj=source)
    elif magic.startswith(b"BZh"):
        unpacked = bz2.BZ2File(source)
    elif magic.startswith(b"\xfd7zXZ\x00"):
        unpacked = lzma.LZMAFile(source)
    else:
        unpacked = None
    try:
        if unpacked is None:
            require_end_blocks(source)
            scan_layer(source, label, issues, exceptions, stats, context)
        else:
            with unpacked, tempfile.TemporaryFile() as spool:
                while chunk := unpacked.read(CHUNK_SIZE):
                    spool.write(chunk)
                require_end_blocks(spool)
                scan_layer(spool, label, issues, exceptions, stats, context)
    except ScanFailure as exc:
        if exc.location == "<archive>":
            exc.location = label
        raise
    except (OSError, EOFError, lzma.LZMAError):
        raise ScanFailure("layer decompression failed", label) from None


def validate_layer_inventory(outer, members, declared, configs, issues):
    """Cover classic Docker layers and OCI blobs, including OCI metadata.

    Only descriptors reachable from index.json can account for extra JSON
    blobs. An unreferenced layer/blob still fails closed.
    """
    blobs = {name for name, member in members.items()
             if member.isfile() and name.startswith("blobs/")}
    metadata = set()

    def read_metadata(name):
        member = members.get(name)
        if member is None or not member.isfile() or member.size > 4 * CHUNK_SIZE:
            raise ScanFailure("invalid OCI metadata member", name)
        raw = outer.extractfile(member).read()
        if name.startswith("blobs/") and name != "blobs/sha256/" + hashlib.sha256(raw).hexdigest():
            raise ScanFailure("OCI metadata digest mismatch", name)
        scan_text(raw.decode("utf-8", errors="replace"), name, issues, metadata=True)
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ScanFailure("invalid OCI metadata", name)
        return value

    def visit(descriptor):
        if not isinstance(descriptor, dict) or not re.fullmatch(r"sha256:[a-f0-9]{64}", descriptor.get("digest", "")):
            raise ScanFailure("invalid OCI descriptor")
        name = "blobs/sha256/" + descriptor["digest"].split(":", 1)[1]
        if name in metadata or name in declared or name in configs:
            raise ScanFailure("duplicate or inconsistent OCI descriptor", name)
        metadata.add(name)
        value = read_metadata(name)
        if isinstance(value.get("manifests"), list):
            for child in value["manifests"]:
                visit(child)
        elif isinstance(value.get("config"), dict) and isinstance(value.get("layers"), list):
            config_digest = value["config"].get("digest", "")
            config_name = "blobs/sha256/" + config_digest.removeprefix("sha256:")
            if config_name not in configs:
                raise ScanFailure("OCI config is absent from Docker manifest", name)
            for layer in value["layers"]:
                if not isinstance(layer, dict) or "blobs/sha256/" + layer.get("digest", "").removeprefix("sha256:") not in declared:
                    raise ScanFailure("OCI layer is absent from Docker manifest", name)
        else:
            raise ScanFailure("invalid OCI manifest", name)

    if "index.json" in members:
        index = read_metadata("index.json")
        if not isinstance(index.get("manifests"), list) or not index["manifests"]:
            raise ScanFailure("invalid OCI index")
        for descriptor in index["manifests"]:
            visit(descriptor)
    actual = {name for name, member in members.items() if member.isfile() and name.endswith(".tar")}
    actual |= blobs - configs - metadata
    if actual != declared:
        raise ScanFailure("undeclared image layer")


def scan_archive_bytes(source, exceptions=None, stats=None):
    issues = []
    exceptions = load_exceptions() if exceptions is None else exceptions
    stats = stats if stats is not None else {"files_scanned": 0, "bytes_scanned": 0, "reviewed_upstream_findings": 0}
    require_end_blocks(source)
    context = {"public_certificates": set(), "certificate_links": []}
    try:
        outer = tarfile.open(fileobj=source, mode="r:*")
        members = {}
        for member in outer:
            if member.isdir() and member.name in {".", "./"}:
                continue
            name = safe_name(member.name)
            if name in members:
                raise ScanFailure("duplicate docker archive member")
            members[name] = member
    except (tarfile.TarError, OSError, EOFError):
        raise ScanFailure("malformed docker archive")
    try:
        manifest_member = members["manifest.json"]
        if not manifest_member.isfile():
            raise ScanFailure("invalid or missing manifest")
        manifest = json.load(outer.extractfile(manifest_member))
        if not isinstance(manifest, list) or not manifest:
            raise ValueError
    except (KeyError, ValueError, TypeError, json.JSONDecodeError):
        raise ScanFailure("invalid or missing manifest")
    declared = set()
    configs = set()
    for index, image in enumerate(manifest):
        if not isinstance(image, dict) or not isinstance(image.get("Config"), str) or not isinstance(image.get("Layers"), list):
            raise ScanFailure("invalid manifest entry")
        config_name = safe_name(image["Config"])
        configs.add(config_name)
        config_member = members.get(config_name)
        if config_member is None or not config_member.isfile():
            raise ScanFailure("missing image config")
        config_raw = outer.extractfile(config_member).read()
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
            layer_member = members.get(layer_path)
            if layer_member is None or not layer_member.isfile():
                raise ScanFailure("missing image layer", "manifest[" + str(index) + "].Layers[" + str(number) + "]")
            layer = outer.extractfile(layer_member)
            scan_layer_archive(layer, "layer[" + str(number) + "]", issues, exceptions, stats, context)
    validate_layer_inventory(outer, members, declared, configs, issues)
    check_certificate_links(context, issues, stats)
    outer.close()
    return issues


def run_archive(archive, image, stats):
    if archive is not None:
        try:
            with archive.open("rb") as source:
                return scan_archive_bytes(source, stats=stats)
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
            status = process.wait()
            if status != 0:
                raise ScanFailure("docker save failed", "<docker-save>", exit_code=status)
            spool.seek(0)
            result = scan_archive_bytes(spool, stats=stats)
    except BaseException:
        if process.poll() is None:
            process.kill()
            process.wait()
        raise
    finally:
        process.stdout.close()
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--image")
    group.add_argument("--archive", type=Path)
    args = parser.parse_args(argv)
    stats = {"files_scanned": 0, "bytes_scanned": 0, "reviewed_upstream_findings": 0}
    try:
        issues = run_archive(args.archive, args.image, stats)
        # Archive member names are untrusted too; never print a key embedded
        # in a filename or let a filename inject a GitHub logging command.
        for issue in issues:
            issue["file"] = safe_location(issue["file"])
        result = {"scope": "docker-image", "issues": issues, "issue_count": len(issues),
                  "result": "PASS" if not issues else "FAIL", "candidate_values_printed": False, **stats}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1 if issues else 0
    except Exception as exc:
        failure = {"file": safe_location(exc.location) if isinstance(exc, ScanFailure) else "<archive>",
                   "kind": "scan_failed", "error_type": type(exc).__name__,
                   "reason": exc.reason if isinstance(exc, ScanFailure) else "archive_read_or_parse_failed"}
        if isinstance(exc, ScanFailure) and exc.exit_code is not None:
            failure["exit_code"] = exc.exit_code
        print(json.dumps({"scope": "docker-image", "issues": [failure],
                          "issue_count": 1, "result": "FAIL", "candidate_values_printed": False, **stats},
                         ensure_ascii=False, indent=2))
        return 1


if __name__ == "__main__":
    sys.exit(main())
