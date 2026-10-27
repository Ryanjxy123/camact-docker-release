"""Lossless, uniform compression at the final outgoing HTTP boundary."""
from __future__ import annotations

import gzip
import hashlib
from collections.abc import Mapping


COMPRESSION_THRESHOLD_BYTES = 1024 * 1024


def content_encoding(headers: Mapping[str, str]) -> str:
    return next((str(value).strip() for key, value in headers.items()
                 if key.casefold() == "content-encoding"), "")


def decoded_body(body: bytes, headers: Mapping[str, str]) -> bytes:
    """Decode gzip for passive accounting without changing the supplied request."""
    encoding = content_encoding(headers).casefold()
    if encoding == "gzip":
        return gzip.decompress(body)
    if encoding in {"", "identity"}:
        return body
    raise ValueError(f"Unsupported request content encoding: {encoding}")


def compress_request(
    body: bytes | None, headers: Mapping[str, str],
) -> tuple[bytes | None, dict[str, str], dict[str, str | int | None]]:
    """Gzip unencoded bodies of at least 1 MiB only when it saves bytes.

    Existing content encodings remain supplied by the caller. No response,
    retry, endpoint, role or protocol policy is involved here.
    """
    wire_headers = dict(headers)
    wire_body = body
    encoding = content_encoding(headers)
    if body is not None and not encoding and len(body) >= COMPRESSION_THRESHOLD_BYTES:
        candidate = gzip.compress(body, compresslevel=6, mtime=0)
        if len(candidate) < len(body):
            if gzip.decompress(candidate) != body:
                raise RuntimeError("HTTP gzip request round trip changed bytes")
            wire_body = candidate
            wire_headers = {key: value for key, value in wire_headers.items()
                            if key.casefold() != "content-encoding"}
            wire_headers["Content-Encoding"] = encoding = "gzip"
    if body is not None:
        wire_headers = {key: value for key, value in wire_headers.items()
                        if key.casefold() != "content-length"}
        wire_headers["Content-Length"] = str(len(wire_body))
    return wire_body, wire_headers, request_diagnostics(wire_body, wire_headers)


def request_diagnostics(body: bytes | None, headers: Mapping[str, str]) -> dict[str, str | int | None]:
    """Describe physical bytes separately from decoded capture/accounting bytes."""
    physical = body or b""
    try:
        decoded = decoded_body(physical, headers)
    except (ValueError, OSError, EOFError):
        decoded = None
    metadata = {
        "wire_encoding": content_encoding(headers) or "identity",
        "wire_request_bytes": len(physical),
        "wire_request_sha256": hashlib.sha256(physical).hexdigest(),
        "decoded_request_bytes": len(decoded) if decoded is not None else None,
        "decoded_request_sha256": hashlib.sha256(decoded).hexdigest() if decoded is not None else None,
    }
    return metadata
