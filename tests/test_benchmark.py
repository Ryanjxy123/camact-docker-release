"""Cache gates use tiny synthetic files; no formal benchmark is modified."""
from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import queue
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from release import benchmark as b

REPO = "example/synthetic-camact"
REVISION = "1" * 40
FILES = {"benchmark_manifest.json": b'{"user_count":1}',
         "tasks/synthetic/task_001/task_spec.json": b'{"task_id":"synthetic"}',
         "users/synthetic/base_memory/images/image.bin": b"synthetic bitmap bytes"}


def synthetic_metadata(repo=REPO, revision=REVISION, **kwargs):
    entries = {}
    for name, content in FILES.items():
        lfs = name.endswith(".bin")
        digest = (hashlib.sha256(content) if lfs else
                  hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content)).hexdigest()
        entries[name] = {"size": len(content), "algorithm": "sha256" if lfs else "git-sha1", "digest": digest}
    return {"schema": b.SCHEMA, "repo_id": repo, "revision": revision, "files": entries}


def exclusive_process(root, events):
    events.put("started")
    with b._lock(root, REPO, REVISION):
        events.put("acquired")


def reader_process(root, events):
    try:
        with b.lease(root, REPO, REVISION, offline=True) as path:
            events.put(str(path))
    except Exception as exc:
        events.put(type(exc).__name__)


class BenchmarkCacheTests(unittest.TestCase):
    def setUp(self):
        output = os.environ.get("CAMACT_TEST_OUTPUT")
        if output:
            Path(output).mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="synthetic-benchmark-", dir=output)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def downloader(self, repo_id, **kwargs):
        destination = Path(kwargs["local_dir"])
        for name, content in FILES.items():
            path = destination / name
            path.parent.mkdir(parents=True, exist_ok=True)
            # Faithfully reproduce HF local_dir's possible same-size stale reuse.
            if not path.exists():
                path.write_bytes(content)
        return str(destination)

    def file_downloader(self, repo_id, name, **kwargs):
        path = Path(kwargs["local_dir"]) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(FILES[name])
        return str(path)

    def download(self, revision=REVISION):
        with patch.object(b, "_metadata", side_effect=synthetic_metadata), \
             patch("huggingface_hub.snapshot_download", side_effect=self.downloader), \
             patch("huggingface_hub.hf_hub_download", side_effect=self.file_downloader):
            return b.ensure(self.root, REPO, revision)

    def test_complete_download_and_offline_reuse_make_no_network_calls(self):
        snapshot = self.download()
        state = json.loads((snapshot.parent / "complete.json").read_text())
        self.assertEqual(state["file_count"], len(FILES))
        self.assertEqual(state["revision"], REVISION)
        with patch.object(b, "_metadata", side_effect=AssertionError("network call")), \
             patch("huggingface_hub.snapshot_download", side_effect=AssertionError("download")):
            self.assertEqual(snapshot, b.ensure(self.root, REPO, REVISION, offline=True))

    def test_missing_file_fails_offline_then_repairs(self):
        snapshot = self.download()
        (snapshot / next(iter(FILES))).unlink()
        with self.assertRaises(b.BenchmarkError):
            b.ensure(self.root, REPO, REVISION, offline=True)
        self.assertFalse((snapshot.parent / "complete.json").exists())
        self.assertEqual(snapshot, self.download())
        self.assertTrue((snapshot.parent / "complete.json").exists())

    def test_same_size_corruption_is_forced_from_hf(self):
        snapshot = self.download()
        name = next(iter(FILES))
        (snapshot / name).write_bytes(b"x" * len(FILES[name]))
        with patch.object(b, "_metadata", side_effect=AssertionError("unnecessary metadata fetch")), \
             patch("huggingface_hub.snapshot_download", side_effect=self.downloader), \
             patch("huggingface_hub.hf_hub_download", side_effect=self.file_downloader) as repair:
            self.assertEqual(snapshot, b.ensure(self.root, REPO, REVISION))
            repair.assert_called_once()
            self.assertTrue(repair.call_args.kwargs["force_download"])
        self.assertEqual((snapshot / name).read_bytes(), FILES[name])

    def test_failed_download_never_publishes_completion(self):
        def fail(repo_id, name, **kwargs):
            p = Path(kwargs["local_dir"]) / next(iter(FILES))
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(FILES[next(iter(FILES))])
            raise PermissionError("synthetic permanent interruption")
        with patch.object(b, "_metadata", side_effect=synthetic_metadata), \
             patch("huggingface_hub.hf_hub_download", side_effect=fail):
            with self.assertRaisesRegex(b.BenchmarkError, "start prohibited"):
                b.ensure(self.root, REPO, REVISION)
        directory, _ = b._location(self.root, REPO, REVISION)
        self.assertFalse((directory / "complete.json").exists())
        with self.assertRaises(b.BenchmarkError):
            b.ensure(self.root, REPO, REVISION, offline=True)
        self.assertTrue(self.download().is_dir())

    def test_different_revision_has_separate_cache_and_never_reuses_old(self):
        first = self.download()
        other = "2" * 40
        with self.assertRaises(b.BenchmarkError):
            b.ensure(self.root, REPO, other, offline=True)
        second = self.download(other)
        self.assertNotEqual(first, second)
        self.assertTrue(first.is_dir())
        self.assertEqual(json.loads((second.parent / "complete.json").read_text())["revision"], other)

    def test_mutable_revision_and_unsafe_manifest_paths_are_rejected(self):
        with self.assertRaises(b.BenchmarkError):
            b.ensure(self.root, REPO, "main")
        for name in ["", ".", "../escape", "/absolute", "tasks/../../escape", "tasks\\escape", ".cache/injected", "tasks//injected"]:
            metadata = synthetic_metadata()
            metadata["files"][name] = next(iter(metadata["files"].values()))
            with self.subTest(name=name), self.assertRaises(b.BenchmarkError):
                b._validate_manifest(metadata, REPO, REVISION)

    def test_symbolic_file_and_directory_cannot_escape_snapshot(self):
        snapshot = self.download()
        name = next(iter(FILES))
        target = self.root / "outside"
        target.write_bytes(FILES[name])
        (snapshot / name).unlink()
        (snapshot / name).symlink_to(target)
        with self.assertRaises(b.BenchmarkError):
            b.ensure(self.root, REPO, REVISION)
        self.assertEqual(target.read_bytes(), FILES[name])

    def test_unlisted_files_cannot_silently_enter_a_run(self):
        snapshot = self.download()
        (snapshot / "unlisted-grader.py").write_text("raise AssertionError")
        with self.assertRaisesRegex(b.BenchmarkError, "unlisted"):
            b.ensure(self.root, REPO, REVISION, offline=True)

    def test_metadata_uses_hf_hashes_and_verifies_resolved_revision(self):
        metadata = synthetic_metadata()
        siblings = [SimpleNamespace(rfilename=name, size=value["size"],
                                    blob_id=value["digest"] if value["algorithm"] == "git-sha1" else "f" * 40,
                                    lfs={"sha256": value["digest"]} if value["algorithm"] == "sha256" else None)
                    for name, value in metadata["files"].items()]
        client = SimpleNamespace(dataset_info=lambda *args, **kwargs: SimpleNamespace(sha=REVISION, siblings=siblings))
        with patch("huggingface_hub.HfApi", return_value=client):
            self.assertEqual(b._metadata(REPO, REVISION), metadata)
        client.dataset_info = lambda *args, **kwargs: SimpleNamespace(sha="3" * 40, siblings=siblings)
        with patch("huggingface_hub.HfApi", return_value=client), self.assertRaisesRegex(b.BenchmarkError, "different commit"):
            b._metadata(REPO, REVISION)

    def test_public_rate_limit_is_retried_before_complete_gate(self):
        from requests import HTTPError, Response
        response = Response()
        response.status_code = 429
        response.headers["Retry-After"] = "0"
        calls = []
        def limited(repo_id, name, **kwargs):
            calls.append(name)
            if len(calls) == 1:
                raise HTTPError(response=response)
            return self.file_downloader(repo_id, name, **kwargs)
        name = next(iter(FILES))
        with patch("huggingface_hub.hf_hub_download", side_effect=limited):
            b._download(self.root / "retry-snapshot", [name], REPO, REVISION, 1)
        self.assertEqual(calls, [name, name])
        self.assertEqual((self.root / "retry-snapshot" / name).read_bytes(), FILES[name])

    def test_wrapped_network_failures_are_retryable_but_auth_failures_are_not(self):
        from requests import HTTPError, Response
        from huggingface_hub.errors import LocalEntryNotFoundError
        wrapped = LocalEntryNotFoundError("synthetic metadata unavailable")
        wrapped.__cause__ = ConnectionError("synthetic connection interruption")
        self.assertTrue(b._retryable(wrapped))
        response = Response()
        response.status_code = 401
        wrapped.__cause__ = HTTPError(response=response)
        self.assertFalse(b._retryable(wrapped))
        self.assertEqual(b._error_type(wrapped), "LocalEntryNotFoundError, HTTP 401")

    def test_lease_blocks_repair_until_run_exits(self):
        self.download()
        context = multiprocessing.get_context("spawn")
        events = context.Queue()
        with b.lease(self.root, REPO, REVISION, offline=True):
            worker = context.Process(target=exclusive_process, args=(str(self.root), events))
            worker.start()
            self.assertEqual(events.get(timeout=10), "started")
            with self.assertRaises(queue.Empty):
                events.get(timeout=0.2)
        self.assertEqual(events.get(timeout=10), "acquired")
        worker.join(timeout=10)
        self.assertEqual(worker.exitcode, 0)

    def test_multiple_evaluations_can_share_a_complete_snapshot(self):
        snapshot = self.download()
        context = multiprocessing.get_context("spawn")
        events = context.Queue()
        with b.lease(self.root, REPO, REVISION, offline=True):
            worker = context.Process(target=reader_process, args=(str(self.root), events))
            worker.start()
            self.assertEqual(events.get(timeout=10), str(snapshot))
            worker.join(timeout=10)
            self.assertEqual(worker.exitcode, 0)

    def test_run_exception_is_propagated_without_a_second_yield(self):
        self.download()
        for exception in [ValueError("synthetic caller failure"), b.BenchmarkError("synthetic caller failure")]:
            with self.subTest(exception=type(exception).__name__), self.assertRaisesRegex(type(exception), "caller failure"):
                with b.lease(self.root, REPO, REVISION, offline=True):
                    raise exception

    def test_hf_authentication_requires_explicit_external_secret_file(self):
        token = "hf_" + "synthetic" * 4
        with patch.dict(os.environ, {"HF_TOKEN": token, "HF_TOKEN_FILE": ""}):
            self.assertIs(b._token(None), False)
        secret = self.root / "external-secret"
        secret.write_text(token + "\n")
        self.assertEqual(b._token(secret), token)
        alias = self.root / "secret-alias"
        alias.symlink_to(secret)
        with self.assertRaises(b.BenchmarkError):
            b._token(alias)
        secret.write_text("not a token")
        with self.assertRaises(b.BenchmarkError):
            b._token(secret)

    def test_complete_cache_needs_no_hf_secret_after_initial_download(self):
        snapshot = self.download()
        missing = self.root / "removed-external-hf-token"
        self.assertEqual(b.ensure(self.root, REPO, REVISION, token_file=missing), snapshot)
        self.assertEqual(b.ensure(self.root, REPO, REVISION, offline=True, token_file=missing), snapshot)


if __name__ == "__main__":
    unittest.main()
