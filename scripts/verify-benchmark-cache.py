#!/usr/bin/env python3
"""Create/reuse a tiny cache through the production offline integrity checks."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from release import benchmark


def verify(cache_root, repo, revision, *, create=False):
    if create:
        # Reuse both production path calculation and locking. In particular,
        # repo includes the verification run ID; never rebuild its path here.
        with benchmark._lock(cache_root, repo, revision) as (directory, _):
            snapshot = directory / "snapshot"
            snapshot.mkdir(exist_ok=False)
            data = b"camact-container-benchmark-smoke\n"
            relative = "fixture/task.yaml"
            path = snapshot / relative
            path.parent.mkdir()
            path.write_bytes(data)
            digest = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            benchmark._atomic(directory / "manifest.json", {
                "schema": benchmark.SCHEMA, "repo_id": repo, "revision": revision,
                "files": {relative: {"size": len(data), "algorithm": "git-sha1", "digest": digest}}})
        # Only production ensure may publish the completion marker.
    snapshot = benchmark.ensure(cache_root, repo, revision, offline=True)
    directory, _ = benchmark._location(cache_root, repo, revision)
    assert snapshot == directory / "snapshot", "production_cache_path_mismatch"
    marker = json.loads((directory / "complete.json").read_text())
    assert marker["repo_id"] == repo and marker["revision"] == revision, "cache_identity_mismatch"
    assert marker["file_count"] == 1, "fixture_file_count_mismatch"
    return {"repo_id": repo, "revision": revision, "file_count": marker["file_count"],
            "manifest_sha256": marker["manifest_sha256"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-root", type=Path, required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--create", action="store_true")
    args = parser.parse_args()
    print(json.dumps(verify(args.cache_root, args.repo, args.revision, create=args.create), sort_keys=True))
