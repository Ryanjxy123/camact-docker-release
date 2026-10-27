"""Exact native codec fallback for unresolved, source-bound captured images."""
from __future__ import annotations

import hashlib
import json
import copy
import os
from collections import OrderedDict
from pathlib import Path
import subprocess

VERSION = "camact.native_image_exact.v1"
_FILE_HASHES = OrderedDict()
_CODEC_REPLAYS = OrderedDict()
_CAPTURE_IDENTITIES = OrderedDict()
_FILE_HASH_LIMIT = 8192
_REPLAY_LIMIT = 32768
_BATCH_SIZE = 32


def _remember(cache, key, value, limit):
    cache[key] = value
    cache.move_to_end(key)
    if len(cache) > limit:
        cache.popitem(last=False)


def _content_identity(path):
    """A path and full file identity reuse only an already measured SHA."""
    path = Path(path).resolve(strict=True)
    def identity():
        info = path.stat()
        return (str(path), info.st_dev, info.st_ino, info.st_mode, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns)
    before = identity()
    if before in _FILE_HASHES:
        _FILE_HASHES.move_to_end(before)
        return before, _FILE_HASHES[before]
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if identity() != before:
        raise ValueError("codec input changed while hashing")
    _remember(_FILE_HASHES, before, digest, _FILE_HASH_LIMIT)
    return before, digest


def _codec_identity(project, family, version):
    """Recheck the current registry and all pins before any codec-cache hit."""
    registry_path = Path(__file__).with_name("native_codecs.json")
    registry_identity, registry_digest = _content_identity(registry_path)
    registry_bytes = registry_path.read_bytes()
    if (hashlib.sha256(registry_bytes).hexdigest() != registry_digest
            or _content_identity(registry_path) != (registry_identity, registry_digest)):
        raise ValueError("codec registry changed while reading")
    registry = json.loads(registry_bytes)
    codec = registry["codecs"][family]
    if codec["version"] != version:
        raise ValueError("recorded codec version differs")
    pins = []
    def visit(value):
        if isinstance(value, dict):
            if "path" in value and "sha256" in value:
                # Match the fixed Node dispatcher's lexical root boundary;
                # frozen runtimes intentionally share their pinned .tools link.
                path = Path(os.path.abspath(project / value["path"]))
                if not path.is_relative_to(project.resolve()):
                    raise ValueError("codec dependency outside project")
                identity, digest = _content_identity(path)
                if digest != value["sha256"]:
                    raise ValueError("codec dependency digest mismatch")
                pins.append((identity, digest))
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    visit(registry["node"])
    visit(codec)
    # These fixed dispatchers are implementation inputs outside the registry.
    for path in (Path(__file__).with_name("visual_replay.cjs"),
                 Path(__file__).with_name("visual_native_exact.cjs")):
        pins.append(_content_identity(path))
    return registry_identity, registry_digest, tuple(pins)


def _reference(path):
    identity, digest = _content_identity(path)
    return {"path": identity[0], "sha256": digest}


def _capture_identity(path):
    """Keep only identity fields from an unchanged hash-checked JSON source."""
    identity = _content_identity(path)
    if identity not in _CAPTURE_IDENTITIES:
        document = json.loads(Path(identity[0][0]).read_text())
        if _content_identity(path) != identity:
            raise ValueError("capture identity changed while parsing")
        fields = {"task_id": document.get("task_id"),
                  "session_id": document.get("runtime_metadata", {}).get("session_id"),
                  "version": document.get("version"), "claude_version": document.get("claude_version")}
        _remember(_CAPTURE_IDENTITIES, identity, fields, _FILE_HASH_LIMIT)
    _CAPTURE_IDENTITIES.move_to_end(identity)
    return identity[1], _CAPTURE_IDENTITIES[identity]


def native_capture_context(root, submission):
    """Bind recorded CLI version and the exact original Episode, never infer it."""
    root = Path(root).resolve()
    snapshots = []
    for path in (root / "episode.json", root / "session/episode.json", *root.glob("sessions/*/*/episode.json")):
        if not path.is_file():
            continue
        try:
            episode = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if (all(episode.get(field) == submission.get(field) for field in
                ("task_id", "execution_trace", "final_environment"))
                and episode.get("runtime_metadata", {}).get("session_id") ==
                    submission.get("runtime_metadata", {}).get("session_id")):
            snapshots.append(_reference(path))
    if len(snapshots) != 1:
        return None
    candidates = []
    for parent in (root, *list(root.parents)[:3]):
        for name, family, version_field in (("launch.json", "codex", "version"),
                                             ("launch.json", "opencode", "version"),
                                             ("config.json", "claude", "claude_version")):
            path = parent / name
            if not path.is_file():
                continue
            try:
                metadata = json.loads(path.read_text())
            except (OSError, ValueError):
                continue
            version = metadata.get(version_field)
            executable = metadata.get("executable_path" if family == "claude" else "executable", "")
            if not isinstance(version, str) or Path(executable).name != family:
                continue
            candidates.append({"family": family, "version": version,
                               "recorded_executable": executable, "metadata": _reference(path)})
        if candidates:
            break
    if len(candidates) != 1:
        return None
    return {"schema_version": VERSION, "capture_root": str(root),
            "task_id": submission.get("task_id"),
            "session_id": submission.get("runtime_metadata", {}).get("session_id"),
            "episode": snapshots[0], "producer": candidates[0]}


def _checked_context(context):
    if not isinstance(context, dict) or context.get("schema_version") != VERSION:
        return False
    try:
        root = Path(context["capture_root"]).resolve()
        if not Path(context["episode"]["path"]).resolve().is_relative_to(root):
            return False
        episode_digest, episode = _capture_identity(context["episode"]["path"])
        if episode_digest != context["episode"]["sha256"]:
            return False
        producer = context["producer"]
        metadata_digest, metadata = _capture_identity(producer["metadata"]["path"])
        if metadata_digest != producer["metadata"]["sha256"]:
            return False
        version_field = "claude_version" if producer["family"] == "claude" else "version"
        if (metadata.get(version_field) != producer["version"]
                or episode.get("task_id") != context["task_id"]
                or episode.get("session_id") != context["session_id"]):
            return False
        expected_tools = {"codex": {"view_image"}, "claude": {"Read"},
                          "opencode": {"read"}}.get(producer["family"], set())
        origins = context.get("native_tool_results", [])
        return (bool(context.get("request_id")) and isinstance(context.get("request_sequence"), int)
                and any(origin.get("producer_request_id") and origin.get("tool_result_id")
                        and origin.get("producer_success") is True
                        and isinstance(origin.get("producer_sequence"), int)
                        and origin["producer_sequence"] < context["request_sequence"]
                        and origin.get("native_tool", {}).get("name") in expected_tools for origin in origins))
    except (OSError, ValueError, KeyError, TypeError):
        return False


def replay_source(source, size, payload_sha256, context):
    """Only fixed local argv is executed; the helper verifies every implementation SHA."""
    if not _checked_context(context):
        return None
    project = Path(__file__).resolve().parents[2]
    try:
        family, version = context["producer"]["family"], context["producer"]["version"]
        source_identity, source_digest = _content_identity(source)
        implementation = _codec_identity(project, family, version)
        key = (family, version, tuple(size), payload_sha256,
               source_identity, source_digest, implementation)
        if key in _CODEC_REPLAYS:
            _CODEC_REPLAYS.move_to_end(key)
            proof = copy.deepcopy(_CODEC_REPLAYS[key])
            if proof is not None:
                proof["capture_binding"] = context
            return proof
        value = {"native": family, "native_version": version,
                 "source": source_identity[0], "source_sha256": source_digest,
                 "size": list(size), "target_sha256": payload_sha256}
        result = subprocess.run([str(project / ".tools/node/bin/node"),
                                 str(Path(__file__).with_name("visual_replay.cjs"))],
                                input=json.dumps(value), text=True, capture_output=True,
                                timeout=45, check=True)
        proof = json.loads(result.stdout)
        # Recheck after execution too. A concurrent source/dependency mutation
        # cannot populate a reusable result under a stale file identity.
        if (_content_identity(source) != (source_identity, source_digest)
                or _codec_identity(project, family, version) != implementation):
            return None
        if proof is None:
            _remember(_CODEC_REPLAYS, key, None, _REPLAY_LIMIT)
            return None
        if (not isinstance(proof, dict) or proof.get("verification") != "encoded_sha256_exact"
                or proof.get("replayed_sha256") != payload_sha256):
            return None
        proof.pop("capture_binding", None)
        _remember(_CODEC_REPLAYS, key, copy.deepcopy(proof), _REPLAY_LIMIT)
        proof["capture_binding"] = context
        return proof
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return None


def replay_sources(sources, size, payload_sha256, context):
    """Replay every unbound album source, sharing only pure codec preparation."""
    sources = list(sources)
    proofs = [None] * len(sources)
    if not _checked_context(context):
        return proofs
    project = Path(__file__).resolve().parents[2]
    try:
        family, version = context["producer"]["family"], context["producer"]["version"]
        implementation = _codec_identity(project, family, version)
        pending = []
        for index, source in enumerate(sources):
            try:
                source_identity, source_digest = _content_identity(source)
            except (OSError, ValueError, TypeError):
                # One unreadable source is an uncached miss, as on the
                # single-source path; the rest of the album is still tested.
                continue
            key = (family, version, tuple(size), payload_sha256,
                   source_identity, source_digest, implementation)
            if key in _CODEC_REPLAYS:
                _CODEC_REPLAYS.move_to_end(key)
                proofs[index] = copy.deepcopy(_CODEC_REPLAYS[key])
            else:
                pending.append((index, source_identity, source_digest, key))
        def run_batch(batch):
            try:
                value = {"native": family, "native_version": version,
                         "sources": [{"source": identity[0], "source_sha256": digest}
                                     for _, identity, digest, _ in batch],
                         "size": list(size), "target_sha256": payload_sha256}
                result = subprocess.run([str(project / ".tools/node/bin/node"),
                                         str(Path(__file__).with_name("visual_replay.cjs"))],
                                        input=json.dumps(value), text=True, capture_output=True,
                                        timeout=45, check=True)
                values = json.loads(result.stdout)
                if not isinstance(values, list) or len(values) != len(batch):
                    raise ValueError("invalid native codec batch output")
                # Validate the complete batch before committing even one result.
                for (_, identity, digest, _), proof in zip(batch, values):
                    if (_content_identity(identity[0]) != (identity, digest)
                            or (proof is not None and (not isinstance(proof, dict)
                                or proof.get("verification") != "encoded_sha256_exact"
                                or proof.get("replayed_sha256") != payload_sha256
                                or proof.get("source_sha256") != digest))):
                        raise ValueError("native codec batch input or output changed")
                if _codec_identity(project, family, version) != implementation:
                    raise ValueError("native codec batch implementation changed")
                for (index, _, _, key), proof in zip(batch, values):
                    if proof is not None:
                        proof.pop("capture_binding", None)
                    _remember(_CODEC_REPLAYS, key, copy.deepcopy(proof), _REPLAY_LIMIT)
                    proofs[index] = proof
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
                # A failed/partial batch never creates negative cache entries.
                # The original single-source path independently rechecks pins.
                if len(batch) > 1:
                    middle = len(batch) // 2
                    run_batch(batch[:middle])
                    run_batch(batch[middle:])
                else:
                    index = batch[0][0]
                    proof = replay_source(sources[index], size, payload_sha256, context)
                    if proof is not None:
                        proof.pop("capture_binding", None)
                    proofs[index] = proof
        for offset in range(0, len(pending), _BATCH_SIZE):
            run_batch(pending[offset:offset + _BATCH_SIZE])
        for proof in proofs:
            if proof is not None:
                proof["capture_binding"] = context
        return proofs
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return [None] * len(sources)
