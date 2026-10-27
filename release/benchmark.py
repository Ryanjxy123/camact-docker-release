"""Complete, commit-pinned Hugging Face dataset cache (never bundled in the image).

``ensure`` returns only a fully hashed snapshot. Evaluations must use ``lease``
for their whole lifetime: its shared advisory lock blocks download/repair of the
same snapshot while a run is using it. Different commits always have new paths.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import threading
import time
from typing import Iterator

DEFAULT_REPO = "Ryanjxy/CamAct-Benchmark"
DEFAULT_REVISION = "53e2f450042485dfc4a3b566de6f46988c3a5661"
HF_ENDPOINT = "https://huggingface.co"
SCHEMA = "camact.benchmark-cache.v1"


class BenchmarkError(RuntimeError):
    """The snapshot cannot be established as complete; do not start evaluation."""


def _exception_chain(exc: Exception) -> Iterator[Exception]:
    seen = set()
    current = exc
    while current is not None and id(current) not in seen and len(seen) < 12:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def _http_failure(exc: Exception) -> tuple[int | None, dict]:
    for current in _exception_chain(exc):
        response = getattr(current, "response", None)
        status = getattr(response, "status_code", None)
        if type(status) is int:
            return status, getattr(response, "headers", {})
    return None, {}


def _error_type(exc: Exception) -> str:
    # Exception text can contain signed download URLs or credential-bearing
    # proxy details. Only expose the class and optional HTTP status.
    status, _ = _http_failure(exc)
    return type(exc).__name__ + (f", HTTP {status}" if type(status) is int else "")


def _retryable(exc: Exception) -> bool:
    status, _ = _http_failure(exc)
    if status is not None:
        return status in {429, 500, 502, 503, 504}
    # HF wraps failed metadata HEAD requests as LocalEntryNotFoundError; both
    # requests (hub 0.x) and httpx (hub 1.x) use these exception class names.
    transient = {"Timeout", "ConnectTimeout", "ReadTimeout", "WriteTimeout", "PoolTimeout",
                 "ConnectionError", "ConnectError", "RemoteProtocolError", "ReadError",
                 "NetworkError", "SSLError", "ProxyError", "LocalEntryNotFoundError"}
    return any(type(current).__name__ in transient for current in _exception_chain(exc))


def _token(token_file: Path | str | None) -> str | bool:
    """Only explicitly supplied secret files enable authenticated HF access."""
    token_file = token_file or os.environ.get("HF_TOKEN_FILE")
    if not token_file:
        return False
    try:
        descriptor = os.open(token_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("not regular")
            value = stream.read(513).decode("ascii").strip()
        if not re.fullmatch(r"hf_[A-Za-z0-9]{20,256}", value):
            raise ValueError("invalid token")
        return value
    except (OSError, ValueError, UnicodeError):
        raise BenchmarkError("Explicit HF token secret must be a regular file containing one valid token") from None


def _quiet_hf() -> None:
    # HF lazily initializes its own logger on first API import. Configure it
    # afterwards so retries cannot print signed URLs; our errors are sanitized.
    from huggingface_hub.utils import logging as hub_logging
    hub_logging.set_verbosity(50)
    hub_logging.disable_propagation()


def _identity(repo_id: str, revision: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repo_id):
        raise BenchmarkError("HF repository must be an owner/name dataset identifier")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise BenchmarkError("Benchmark revision must be an immutable 40-character commit SHA")


def _relative(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise BenchmarkError("Unsafe path in benchmark file manifest")
    p = PurePosixPath(value)
    if (not p.parts or "\\" in value or p.is_absolute()
            or value != p.as_posix() or any(x in {".", ".."} for x in p.parts)
            or p.parts[0] == ".cache"):
        raise BenchmarkError("Unsafe path in benchmark file manifest")
    return value


def _plain_path(root: Path, relative: str) -> Path:
    path = root
    if root.is_symlink():
        raise BenchmarkError("Benchmark cache paths must not be symbolic links")
    for part in PurePosixPath(_relative(relative)).parts:
        path = path / part
        if path.is_symlink():
            raise BenchmarkError("Benchmark cache paths must not be symbolic links")
    return path


def _atomic(path: Path, value: dict) -> None:
    if path.is_symlink():
        raise BenchmarkError("Benchmark state paths must not be symbolic links")
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _location(cache_root: Path | str, repo_id: str, revision: str) -> tuple[Path, Path]:
    _identity(repo_id, revision)
    root = Path(cache_root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    repository = root / (repo_id.replace("/", "--") + "-" + hashlib.sha256(repo_id.encode()).hexdigest()[:12])
    if repository.is_symlink():
        raise BenchmarkError("Benchmark repository cache must not be a symbolic link")
    repository.mkdir(exist_ok=True)
    directory = repository / revision
    if directory.is_symlink():
        raise BenchmarkError("Benchmark revision cache must not be a symbolic link")
    directory.mkdir(exist_ok=True)
    return directory, repository / (revision + ".lock")


@contextmanager
def _lock(cache_root: Path | str, repo_id: str, revision: str, *, shared: bool = False) -> Iterator[tuple[Path, int]]:
    directory, lock_path = _location(cache_root, repo_id, revision)
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise BenchmarkError("Benchmark lock is not a regular file")
        fcntl.flock(descriptor, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
        yield directory, descriptor
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _validate_manifest(value: dict, repo_id: str, revision: str) -> dict:
    if (value.get("schema") != SCHEMA or value.get("repo_id") != repo_id
            or value.get("revision") != revision or not isinstance(value.get("files"), dict)
            or not value["files"]):
        raise BenchmarkError("Benchmark manifest does not match the requested repository and commit")
    for name, entry in value["files"].items():
        _relative(name)
        if not isinstance(entry, dict):
            raise BenchmarkError("Malformed benchmark file metadata")
        algorithm = entry.get("algorithm")
        length = 64 if algorithm == "sha256" else 40 if algorithm == "git-sha1" else 0
        if (not length or type(entry.get("size")) is not int or entry["size"] < 0
                or not re.fullmatch(r"[0-9a-f]{" + str(length) + r"}", entry.get("digest", ""))):
            raise BenchmarkError("Malformed benchmark file integrity metadata")
    return value


def _metadata(repo_id: str, revision: str, *, token: str | bool = False) -> dict:
    from huggingface_hub import HfApi
    _quiet_hf()
    try:
        info = HfApi(endpoint=HF_ENDPOINT, token=token).dataset_info(
            repo_id, revision=revision, files_metadata=True, token=token)
    except Exception as exc:
        raise BenchmarkError("Cannot fetch pinned HF dataset metadata (" + _error_type(exc) + ")") from None
    if info.sha != revision:
        raise BenchmarkError("HF resolved a different commit; evaluation is prohibited")
    files = {}
    for sibling in info.siblings or []:
        name = _relative(sibling.rfilename)
        if name in files:
            raise BenchmarkError("Duplicate path in HF dataset metadata")
        lfs = sibling.lfs
        lfs_hash = (lfs.get("sha256") if isinstance(lfs, dict) else getattr(lfs, "sha256", None)) if lfs else None
        files[name] = {"size": sibling.size, "algorithm": "sha256" if lfs_hash else "git-sha1",
                       "digest": lfs_hash or sibling.blob_id}
    return _validate_manifest({"schema": SCHEMA, "repo_id": repo_id,
                               "revision": revision, "files": files}, repo_id, revision)


def _manifest(directory: Path, repo_id: str, revision: str, offline: bool, *, token: str | bool = False) -> dict:
    path = directory / "manifest.json"
    if path.is_symlink():
        raise BenchmarkError("Benchmark manifest must not be a symbolic link")
    if path.is_file():
        try:
            return _validate_manifest(json.loads(path.read_text(encoding="utf-8")), repo_id, revision)
        except (ValueError, TypeError, AttributeError, BenchmarkError):
            if offline:
                raise BenchmarkError("Cached benchmark manifest is invalid in offline mode") from None
    if offline:
        raise BenchmarkError("No complete pinned benchmark manifest is available offline")
    value = _metadata(repo_id, revision, token=token)
    _atomic(path, value)
    return value


def _digest(path: Path, entry: dict) -> str | None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError:
        raise BenchmarkError("Cannot safely read a benchmark file") from None
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise BenchmarkError("Benchmark files must be regular files")
        if metadata.st_size != entry["size"]:
            return None
        digest = hashlib.sha256() if entry["algorithm"] == "sha256" else hashlib.sha1()
        if entry["algorithm"] == "git-sha1":
            digest.update(b"blob " + str(metadata.st_size).encode("ascii") + b"\0")
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
        return digest.hexdigest()


def _verify(snapshot: Path, manifest: dict) -> list[str]:
    if snapshot.is_symlink():
        raise BenchmarkError("Benchmark snapshot must not be a symbolic link")
    if not snapshot.exists():
        return list(manifest["files"])
    if not snapshot.is_dir():
        raise BenchmarkError("Benchmark snapshot must be a directory")
    expected = set(manifest["files"])
    for directory, dirs, files in os.walk(snapshot, followlinks=False):
        relative = Path(directory).relative_to(snapshot)
        for name in dirs + files:
            if (Path(directory) / name).is_symlink():
                raise BenchmarkError("Benchmark snapshot contains a symbolic link")
        # Check bookkeeping for symlinks too, but it is not dataset data.
        for name in files:
            if relative.parts and relative.parts[0] == ".cache":
                continue
            if (relative / name).as_posix() not in expected:
                raise BenchmarkError("Benchmark snapshot contains an unlisted file")
    damaged = []
    for name, entry in manifest["files"].items():
        path = _plain_path(snapshot, name)
        if _digest(path, entry) != entry["digest"]:
            damaged.append(name)
    return damaged


def _download(snapshot: Path, damaged: list[str], repo_id: str, revision: str, max_workers: int,
              *, token: str | bool = False) -> None:
    """Fetch only missing/damaged files, with bounded retries and public-HF pacing.

    A small Git file may need three resolver requests including redirects.
    Start at most 2.5 files/second anonymously or 5 with an explicit token.
    Shared quota exhaustion still receives Retry-After backoff.
    """
    from huggingface_hub import hf_hub_download
    _quiet_hf()
    guard = threading.Lock()
    stopped = threading.Event()
    files = iter(damaged)
    next_request = 0.0

    def pace(delay: float = 0.0) -> None:
        nonlocal next_request
        with guard:
            current = time.monotonic()
            scheduled = max(current + delay, next_request)
            next_request = scheduled + (0.2 if token else 0.4)
        if stopped.wait(max(0.0, scheduled - current)):
            raise BenchmarkError("Pinned benchmark download stopped before completion")

    def worker() -> None:
        try:
            while not stopped.is_set():
                with guard:
                    name = next(files, None)
                if name is None:
                    return
                path = _plain_path(snapshot, name)
                force = path.exists()
                for attempt in range(9):
                    pace()
                    try:
                        hf_hub_download(repo_id, name, repo_type="dataset", revision=revision,
                                        local_dir=snapshot, force_download=force,
                                        token=token, endpoint=HF_ENDPOINT)
                        break
                    except Exception as exc:
                        _, headers = _http_failure(exc)
                        if not _retryable(exc) or attempt == 8:
                            raise
                        retry_after = headers.get("Retry-After", "")
                        delay = min(300.0, max(1.0, float(retry_after))) if str(retry_after).isdigit() else min(60.0, 2.0 ** (attempt + 1))
                        # A common gate prevents all workers retrying together.
                        pace(delay)
        except Exception:
            stopped.set()
            raise

    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="camact-hf") as pool:
        futures = [pool.submit(worker) for _ in range(min(max_workers, len(damaged)))]
        try:
            failures = []
            for future in futures:
                try:
                    future.result()
                except Exception as exc:
                    failures.append(exc)
            if failures:
                raise next((exc for exc in failures if not isinstance(exc, BenchmarkError)), failures[0])
        except BaseException:
            # Ctrl-C must stop assigning new files rather than drain a whole
            # dataset queue while the executor waits for its worker threads.
            stopped.set()
            for future in futures:
                future.cancel()
            raise


def _ensure_locked(directory: Path, repo_id: str, revision: str, offline: bool, max_workers: int,
                   *, token: str | bool = False) -> Path:
    if not 1 <= max_workers <= 64:
        raise BenchmarkError("HF download worker count must be between 1 and 64")
    snapshot = directory / "snapshot"
    marker = directory / "complete.json"
    if marker.is_symlink():
        raise BenchmarkError("Benchmark completion marker must not be a symbolic link")
    marker.unlink(missing_ok=True)
    manifest = _manifest(directory, repo_id, revision, offline, token=token)
    damaged = _verify(snapshot, manifest)
    if damaged:
        marker.unlink(missing_ok=True)
        if offline:
            raise BenchmarkError(f"Pinned benchmark is incomplete or damaged ({len(damaged)} files); offline start prohibited")
        try:
            _download(snapshot, damaged, repo_id, revision, max_workers, token=token)
        except BenchmarkError:
            raise
        except Exception as exc:
            raise BenchmarkError("Pinned benchmark download failed (" + _error_type(exc) + "); start prohibited") from None
        damaged = _verify(snapshot, manifest)
        if damaged:
            raise BenchmarkError(f"Pinned benchmark integrity check failed ({len(damaged)} files); start prohibited")
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    completion = {"schema": SCHEMA, "repo_id": repo_id, "revision": revision,
                  "file_count": len(manifest["files"]),
                  "total_bytes": sum(item["size"] for item in manifest["files"].values()),
                  "manifest_sha256": hashlib.sha256(encoded).hexdigest()}
    # No credentials, download URLs or per-user configuration enter state files.
    _atomic(marker, completion)
    return snapshot


def ensure(cache_root: Path | str, repo_id: str = DEFAULT_REPO, revision: str = DEFAULT_REVISION,
           *, offline: bool = False, max_workers: int = 8, token_file: Path | str | None = None) -> Path:
    """Download/repair as needed and return a fully locally verified snapshot."""
    with lease(cache_root, repo_id, revision, offline=offline, max_workers=max_workers, token_file=token_file) as snapshot:
        return snapshot


@contextmanager
def lease(cache_root: Path | str, repo_id: str = DEFAULT_REPO, revision: str = DEFAULT_REVISION,
          *, offline: bool = False, max_workers: int = 8, token_file: Path | str | None = None) -> Iterator[Path]:
    """Verify a fixed commit, then retain its shared lock for the whole run."""
    if not 1 <= max_workers <= 64:
        raise BenchmarkError("HF download worker count must be between 1 and 64")
    with _lock(cache_root, repo_id, revision, shared=True) as (directory, descriptor):
        marker = directory / "complete.json"
        ready = False
        if marker.is_file() and not marker.is_symlink():
            try:
                cached = _manifest(directory, repo_id, revision, offline=True)
                state = json.loads(marker.read_text(encoding="utf-8"))
                encoded = json.dumps(cached, sort_keys=True, separators=(",", ":")).encode()
                current = (state.get("schema") == SCHEMA and state.get("repo_id") == repo_id
                           and state.get("revision") == revision
                           and state.get("manifest_sha256") == hashlib.sha256(encoded).hexdigest())
                ready = current and not _verify(directory / "snapshot", cached)
            except (ValueError, TypeError, AttributeError):
                pass
            except BenchmarkError:
                # Re-enter under the exclusive lock: incomplete state must not
                # be repaired while another evaluation holds a shared lease.
                pass
        if ready:
            yield directory / "snapshot"
            return
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        token = False if offline else _token(token_file)
        snapshot = _ensure_locked(directory, repo_id, revision, offline, max_workers, token=token)
        fcntl.flock(descriptor, fcntl.LOCK_SH)
        yield snapshot


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-root", type=Path, required=True)
    parser.add_argument("--repo-id", default=DEFAULT_REPO)
    parser.add_argument("--revision", default=DEFAULT_REVISION)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--max-workers", type=int, default=8)
    parser.add_argument("--token-file", type=Path, help="Optional external HF token secret; otherwise anonymous")
    args = parser.parse_args()
    try:
        print(ensure(args.cache_root, args.repo_id, args.revision,
                     offline=args.offline, max_workers=args.max_workers, token_file=args.token_file))
    except BenchmarkError as exc:
        parser.exit(2, str(exc) + "\n")


if __name__ == "__main__":
    main()
