"""Conservative extraction of native model-call identities.

This module deliberately refuses to turn a CLI turn, step, response id, or
request hash into a logical request id.  A logical id is accepted only when a
caller explicitly supplied one, or when the dsh adapter supplied the complete
``session + turn + step`` (or title event) boundary.  Session/turn/step fields
are still retained as evidence when they are useful but incomplete.
"""
from __future__ import annotations

import json
from collections.abc import Mapping


# The CamAct headers are private attribution headers.  ``x-request-id`` is
# retained as evidence, but is not promoted to a logical id because providers
# commonly assign it to one physical HTTP response.
LOGICAL_HEADER_NAMES = {
    "x-camact-logical-request-id",
    "x-camact-operation-id",
    "x-logical-request-id",
    "x-native-logical-request-id",
}
PHYSICAL_HEADER_NAMES = {
    "x-request-id",
    "request-id",
    "trace-id",
    "x-trace-id",
}

LOGICAL_BODY_KEYS = (
    "logical_model_request_id",
    "logical_request_id",
    "operation_id",
    "model_call_id",
    "llm_call_id",
    "invocation_id",
)
SESSION_KEYS = ("session_id", "sessionId", "native_session_id", "nativeSessionId")
TURN_KEYS = ("turn_id", "turnId", "native_turn_id", "nativeTurnId", "turn")
STEP_KEYS = ("step_id", "stepId", "native_step_id", "nativeStepId", "step")
RETRY_KEYS = ("retry_id", "retryId", "request_retry_id", "requestRetryId")


def _scalar(value):
    if isinstance(value, (str, int)) and not isinstance(value, bool):
        value = str(value).strip()
        return value or None
    return None


def _mapping(value):
    return value if isinstance(value, Mapping) else {}


def _first(mapping, keys):
    mapping = _mapping(mapping)
    for key in keys:
        value = _scalar(mapping.get(key))
        if value is not None:
            return value
    return None


def _decode_json(value):
    if isinstance(value, Mapping):
        return value
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except (TypeError, ValueError):
            return None
        return decoded if isinstance(decoded, Mapping) else None
    return None


def _dsh_identity(body):
    """Extract only an explicitly exported dsh call boundary.

    The ordinary ``dsh_session_log`` extension contains a session watermark,
    which is an attribution anchor but not itself a call identity.  Newer
    adapters may include ``active_call``/``native_call`` alongside it.  We
    accept those fields only when the full boundary is present.  A watermark
    is retained below as evidence and never used as an operation id.
    """
    upload = _decode_json(_mapping(body).get("dsh_session_log")) or {}
    session = _mapping(upload.get("session"))
    session_id = _first(session, ("id",)) or _first(upload, SESSION_KEYS)
    call = (_mapping(body).get("dsh_native_call") or _mapping(body).get("dsh_call")
            or _mapping(body).get("native_call") or _mapping(body).get("active_call"))
    call = _decode_json(call) or {}
    native_session = _first(call, SESSION_KEYS) or session_id
    turn = _first(call, TURN_KEYS)
    step = _first(call, STEP_KEYS)
    retry = _first(call, RETRY_KEYS)
    event_seq = _first(call, ("event_seq", "eventSeq", "title_event_seq", "titleEventSeq"))
    kind = _first(call, ("kind", "call_kind", "callKind", "type"))
    out = {}
    if session_id:
        out["native_session_id"] = session_id
    if turn:
        out["native_turn_id"] = turn
    if step:
        out["native_step_id"] = step
    if retry:
        out["request_retry_identity"] = retry
    if upload.get("throughSeq") is not None:
        out["native_through_seq"] = upload.get("throughSeq")
    # Title requests have no turn/step.  The event sequence is their stable
    # identity, but only if the caller explicitly labels it as a title call.
    if native_session and event_seq and kind in {"title", "session-title", "title_generation"}:
        out.update(operation_id=f"dsh:title:{native_session}:{event_seq}",
                   logical_identity_source="dsh_session_title_event")
    elif native_session and turn and step:
        out.update(operation_id=f"dsh:step:{native_session}:{turn}:{step}",
                   logical_identity_source="dsh_session_turn_step")
    return out


def extract_identity(body=None, headers=None):
    """Return allowlisted attribution fields for a single outgoing request."""
    body = _mapping(body)
    headers = {str(k).lower(): v for k, v in _mapping(headers).items()}
    result = {}

    for name in LOGICAL_HEADER_NAMES:
        value = _scalar(headers.get(name))
        if value:
            result.update(operation_id=value, logical_identity_source=f"header:{name}")
            break
    for name in PHYSICAL_HEADER_NAMES:
        value = _scalar(headers.get(name))
        if value:
            result.setdefault("native_request_id", value)
            result.setdefault("native_request_id_source", f"header:{name}")

    if "operation_id" not in result:
        for key in LOGICAL_BODY_KEYS:
            value = _scalar(body.get(key))
            if value:
                result.update(operation_id=value, logical_identity_source=f"body:{key}")
                break

    # Common native identity fields are copied as evidence even when they do
    # not prove a logical request boundary by themselves.  Codex nests these
    # under client_metadata; the nesting is retained as provenance only.
    metadata = _decode_json(body.get("client_metadata")) or {}
    result.setdefault("native_session_id", _first(body, SESSION_KEYS) or _first(metadata, SESSION_KEYS))
    result.setdefault("native_turn_id", _first(body, TURN_KEYS) or _first(metadata, TURN_KEYS))
    result.setdefault("native_step_id", _first(body, STEP_KEYS) or _first(metadata, STEP_KEYS))
    result.setdefault("request_retry_identity", _first(body, RETRY_KEYS) or _first(metadata, RETRY_KEYS))
    dsh = _dsh_identity(body)
    for key, value in dsh.items():
        if value is not None:
            result[key] = value
    return {key: value for key, value in result.items() if value is not None}


def identity_from_request(body=None, headers=None):
    """Compatibility alias used by transports and offline tests."""
    return extract_identity(body, headers)

