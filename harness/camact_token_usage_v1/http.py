"""Transparent response observer; no headers, payloads or retry policy changed."""
from __future__ import annotations
import json
import hashlib
import urllib.error
from urllib.parse import urlsplit
from .adapters import protocol_for, tool_results
from .native_identity import extract_identity
from benchmark.services.http_compression import content_encoding, decoded_body


def request_metadata(body, headers=None):
    """Allowlisted passive attribution; no ordering or text-content inference."""
    if isinstance(body, bytes):
        try:
            body = json.loads(decoded_body(body, headers or {}))
        except (ValueError, OSError, EOFError):
            return {}
    if not isinstance(body, dict):
        return {}
    fields = {"observed_tool_results": tool_results(body)}
    fields.update(extract_identity(body, headers))
    for key in ("max_output_tokens", "max_completion_tokens", "max_tokens"):
        if isinstance(body.get(key), int) and not isinstance(body[key], bool):
            fields["requested_output_cap"] = body[key]
            break
    metadata = body.get("client_metadata")
    value = metadata.get("x-codex-turn-metadata") if isinstance(metadata, dict) else None
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            value = None
    if isinstance(value, dict) and value.get("request_kind") == "compaction":
        fields["agent_operation_type"] = "context_compaction"
        fields["operation_type_source"] = "client_metadata.x-codex-turn-metadata.request_kind"
    return fields


def observe_open(collector, opener, request, *, protocol=None, metadata=None,
                 request_headers=None, **kwargs):
    if collector is None:
        return opener(request, **kwargs)
    protocol = protocol or protocol_for(request.full_url)
    if protocol is None:
        return opener(request, **kwargs)
    model = None
    body = {}
    physical_body = request.data or b""
    decoded = None
    try:
        # Encoding comes from the actual outgoing request; attribution headers
        # may deliberately contain only a small allowlist of native identities.
        decoded = decoded_body(physical_body, request.headers)
        body = json.loads(decoded or b"{}")
        model = body.get("model")
    except (ValueError, AttributeError, OSError, EOFError):
        pass
    route = urlsplit(request.full_url).path
    fields = dict(metadata or {})
    fields["request_sha256"] = hashlib.sha256(physical_body).hexdigest()
    fields["wire_encoding"] = content_encoding(request.headers) or "identity"
    fields["wire_request_bytes"] = len(physical_body)
    if decoded is not None:
        fields["decoded_request_sha256"] = hashlib.sha256(decoded).hexdigest()
        fields["decoded_request_bytes"] = len(decoded)
    observed = collector.safe(request_metadata, body, request_headers or request.headers)
    if observed:
        fields.update(observed)
    if route.endswith("/compact"):
        fields["agent_operation_type"] = "context_compaction"
    # ``operation_id`` is reserved for an explicit logical identity.  A
    # provider response/request id remains metadata and therefore cannot make
    # a physical HTTP attempt look like a logical model call.
    operation_id = fields.pop("operation_id", None)
    ident = collector.begin(protocol=protocol, model_id=model, operation_id=operation_id, **fields)
    try:
        response = opener(request, **kwargs)
    except urllib.error.HTTPError as exc:
        # Preserve the exception type, identity, headers and caller's read path.
        status_code = exc.code
        error_encoding = exc.headers.get("Content-Encoding")
        collector.observe_response_headers(ident, exc.headers, status_code)
        error_chunks = []
        def wrap_read(original):
            def read(*args, **read_kwargs):
                data = original(*args, **read_kwargs)
                error_chunks.append(data)
                collector.finish_request(ident, b"".join(error_chunks), status=status_code,
                                         encoding=error_encoding)
                return data
            return read
        for method in ("read", "read1", "readline"):
            if hasattr(exc, method):
                setattr(exc, method, wrap_read(getattr(exc, method)))
        collector.finish_request(ident, status=exc.code, interrupted=True)
        raise
    except BaseException:
        collector.finish_request(ident, interrupted=True)
        raise
    collector.observe_response_headers(ident, response.headers,
                                      getattr(response, "status", getattr(response, "code", None)))
    return ObservedResponse(response, collector, ident)


class ObservedResponse:
    def __init__(self, response, collector, ident):
        self.response, self.collector, self.ident = response, collector, ident
        self.chunks = []
        self.finished = False

    def __getattr__(self, name):
        return getattr(self.response, name)

    def __enter__(self):
        self.response.__enter__()
        return self

    def _finish(self, interrupted=False):
        if not self.finished:
            self.finished = True
            self.collector.finish_request(self.ident, b"".join(self.chunks),
                status=getattr(self.response, "status", getattr(self.response, "code", None)),
                encoding=self.response.headers.get("Content-Encoding"), interrupted=interrupted)

    def __exit__(self, exc_type, exc, tb):
        try:
            return self.response.__exit__(exc_type, exc, tb)
        finally:
            self._finish(interrupted=exc_type is not None)

    def _read(self, method, *args, **kwargs):
        try:
            data = getattr(self.response, method)(*args, **kwargs)
            self.chunks.append(data)
            return data
        except BaseException:
            self._finish(interrupted=True)
            raise

    def read(self, *args, **kwargs):
        return self._read("read", *args, **kwargs)

    def read1(self, *args, **kwargs):
        return self._read("read1", *args, **kwargs)

    def readline(self, *args, **kwargs):
        return self._read("readline", *args, **kwargs)

    def __iter__(self):
        # Iteration must keep the underlying object's exact line segmentation.
        try:
            for line in self.response:
                self.chunks.append(line)
                yield line
        except BaseException:
            self._finish(interrupted=True)
            raise
