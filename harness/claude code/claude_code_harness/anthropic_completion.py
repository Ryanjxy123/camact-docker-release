"""Validate Anthropic message framing without rewriting provider content."""
import gzip
import json


def completion_error(data):
    """Return None for a complete message, otherwise a protocol diagnostic.

    Called at Claude's buffered response boundary, before delivery to the CLI.
    Tool arguments and new delta types are deliberately not interpreted:
    generation completion is independent of subsequent tool success.
    """
    try:
        if data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)
        text = data.decode("utf-8")
    except (OSError, EOFError, UnicodeDecodeError):
        return "invalid response encoding"
    try:
        doc = json.loads(text)
    except ValueError:
        doc = None
    if isinstance(doc, dict):
        if (doc.get("type") == "message" and isinstance(doc.get("content"), list)
                and doc.get("stop_reason") and not doc.get("error")):
            return None
        return "incomplete Anthropic message"
    # SSE dispatches an event only at a blank line. Never accept an unfinished
    # terminal frame or silently discard malformed JSON.
    frames = text.replace("\r\n", "\n").replace("\r", "\n").split("\n\n")
    if frames[-1].strip():
        return "incomplete SSE frame"
    started = stopped = False
    stop_reason = None
    active, closed = set(), set()
    for frame in frames[:-1]:
        fields = [line[5:].lstrip(" ") for line in frame.splitlines() if line.startswith("data:")]
        if not fields:
            continue
        try:
            event = json.loads("\n".join(fields))
        except ValueError:
            return "invalid SSE JSON"
        if not isinstance(event, dict):
            return "invalid SSE event object"
        kind = event.get("type")
        names = [line[6:].strip() for line in frame.splitlines() if line.startswith("event:")]
        if names and names[-1] != kind:
            return "SSE event name/type mismatch"
        if kind == "error" or event.get("error"):
            return "upstream SSE error event"
        if kind == "ping":
            continue
        if stopped:
            return "event after message_stop"
        if kind == "message_start":
            if started or not isinstance(event.get("message"), dict):
                return "invalid or duplicate message_start"
            started = True
        elif kind in {"content_block_start", "content_block_delta", "content_block_stop"}:
            index = event.get("index")
            if not started or stop_reason:
                return "content block outside message body"
            if type(index) is not int or index < 0:
                return "invalid content block index"
            if kind == "content_block_start":
                if index in active or index in closed or not isinstance(event.get("content_block"), dict):
                    return f"invalid or duplicate content_block_start(index={index})"
                active.add(index)
            elif index not in active:
                return f"{kind}(index={index}) without active content_block_start"
            elif kind == "content_block_stop":
                active.remove(index)
                closed.add(index)
            elif not isinstance(event.get("delta"), dict):
                return f"invalid content_block_delta(index={index})"
        elif kind == "message_delta":
            if not started or active or not isinstance(event.get("delta"), dict):
                return "message_delta before content blocks completed"
            stop_reason = event["delta"].get("stop_reason") or stop_reason
        elif kind == "message_stop":
            if not started or active or not stop_reason:
                return "message_stop before message completed"
            if closed != set(range(len(closed))):
                return "noncontiguous content block indexes"
            stopped = True
        # Unknown event types are allowed by Anthropic's versioning policy.
    return None if stopped else "missing message_stop"
