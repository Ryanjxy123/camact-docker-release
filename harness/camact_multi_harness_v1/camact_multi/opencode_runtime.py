"""Read the pinned OpenCode V2 execution projection after its standalone CLI exits.

2.0.32 does not print execution.succeeded. Its wait/reconciliation path can also
omit the final step_finish. The official projector maps execution lifecycle
events to an idle message (outcome, durable sequence) and session idle_outcome.
Read those together with this invocation's newly admitted user and completed
assistant messages. Never infer a terminal from idle, prose or exit status alone.
Only session tables are read; credential tables are deliberately inaccessible
to this adapter's queries. This is not a second token-usage source.
"""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3

VERSION = "2.0.32"
DATABASE = Path(".local/share/opencode/opencode.db")
SOURCE = "opencode_v2_persisted_execution_projection"


def _connect(home):
    home = Path(home).resolve(strict=True)
    path = home / DATABASE
    if not path.exists():
        return None
    if path.is_symlink() or not path.resolve(strict=True).is_relative_to(home):
        raise ValueError("OpenCode Session database escaped the task HOME")
    db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA query_only=ON")
    db.execute("BEGIN")  # One consistent snapshot, including a live WAL if present.
    return db


def checkpoint(home):
    """Freeze durable sequence boundaries before admitting this CLI invocation."""
    try:
        db = _connect(home)
        if db is None:
            return {"sequences": {}}
        try:
            return {"sequences": {r["aggregate_id"]: r["seq"] for r in
                    db.execute("SELECT aggregate_id, seq FROM event_sequence")}}
        finally:
            db.close()
    except (OSError, sqlite3.Error, ValueError) as exc:
        return {"sequences": {}, "error": f"{type(exc).__name__}: {exc}"}


def _cli_message(message):
    # packages/cli/src/run/run.ts quotes a positional
    # message containing spaces before merging stdin. stdin is closed by our
    # OpenCode invocation so no unrelated host input can enter the Session.
    return '"' + message.replace('"', '\\"') + '"' if " " in message else message


def collect(home, *, session_id, before, prompt, events, model, version):
    """Collect current native facts; retain rejected evidence for audit as well."""
    evidence = {"source": SOURCE, "version": version, "session_id": session_id,
                "before": before, "expected_prompt": _cli_message(prompt),
                "expected_model": model, "database": str(DATABASE),
                "stdout_session_ids": sorted({e["sessionID"] for e in events if e.get("sessionID")}),
                "stdout_errors": [e for e in events if e.get("type") in
                                  {"error", "turn.failed", "session.execution.failed", "session.execution.interrupted"}],
                "stdout_message_ids": sorted({e.get("part", {}).get("messageID") for e in events
                                               if e.get("part", {}).get("messageID")})}
    try:
        if not session_id:
            raise ValueError("No invocation-scoped native Session ID")
        db = _connect(home)
        if db is None:
            raise ValueError("Official Session database is missing")
        try:
            row = db.execute("SELECT id, version, time_created, time_updated, time_idle, idle_outcome "
                             "FROM session_v2 WHERE id=?", (session_id,)).fetchone()
            sequence = db.execute("SELECT aggregate_id, seq, owner_id FROM event_sequence WHERE aggregate_id=?",
                                  (session_id,)).fetchone()
            boundary = before.get("sequences", {}).get(session_id, 0)
            messages = []
            for row_message in db.execute("SELECT id, session_id, type, seq, time_created, time_updated, data "
                    "FROM session_message WHERE session_id=? AND seq>? ORDER BY seq", (session_id, boundary)):
                message = dict(row_message)
                message["data"] = json.loads(message["data"])
                messages.append(message)
            evidence.update(session=dict(row) if row else None,
                            sequence=dict(sequence) if sequence else None, messages=messages,
                            pending=db.execute("SELECT count(*) FROM session_pending WHERE session_id=?",
                                               (session_id,)).fetchone()[0],
                            inbox=db.execute("SELECT count(*) FROM session_inbox WHERE session_id=?",
                                             (session_id,)).fetchone()[0])
        finally:
            db.close()
        signal, reason = terminal_signal(evidence)
        evidence.update(signal=signal, reason=reason)
    except (OSError, sqlite3.Error, ValueError, TypeError, KeyError) as exc:
        evidence.update(signal=None, reason=f"OpenCode terminal snapshot: {type(exc).__name__}: {exc}")
    return evidence


def terminal_signal(evidence):
    """Validate the official projection, never a caller-supplied 'validated' bit."""
    try:
        return _terminal_signal(evidence)
    except ValueError as exc:
        return None, "opencode_terminal_rejected: " + str(exc)
    except (KeyError, TypeError, IndexError, AttributeError):
        return None, "opencode_invalid_terminal_projection"


def _terminal_signal(e):
    def require(ok, reason):
        if not ok:
            raise ValueError(reason)

    if not isinstance(e, dict) or e.get("source") != SOURCE or e.get("version") != VERSION:
        return None, "opencode_missing_supported_terminal_projection"
    if e.get("before", {}).get("error"):
        return None, "opencode_invalid_execution_checkpoint"
    sid, session, sequence = e["session_id"], e["session"], e["sequence"]
    require(sid and session["id"] == sid and sequence["aggregate_id"] == sid, "Session identity")
    require(session["version"] == VERSION, "Session version")
    require(e["stdout_session_ids"] == [sid], "stdout Session identity")
    require(not e.get("stdout_errors"), "Native stdout execution error")
    require(sequence["owner_id"] is None, "Execution still owned")
    require(e["pending"] == 0 and e["inbox"] == 0, "Unsettled Session input")
    boundary = e["before"]["sequences"].get(sid, 0)
    rows = e["messages"]
    require(rows and all(r["session_id"] == sid for r in rows), "Message Session identity")
    seqs = [r["seq"] for r in rows]
    require(seqs == sorted(set(seqs)) and seqs[0] > boundary and sequence["seq"] >= seqs[-1],
            "Invocation sequence boundary")
    require(len({r["id"] for r in rows}) == len(rows), "Duplicate message identity")
    users = [r for r in rows if r["type"] == "user"]
    idles = [r for r in rows if r["type"] == "idle"]
    require(len(users) == 1 and len(idles) == 1 and rows[-1] == idles[0], "Execution turn boundary")
    user, idle = users[0], idles[0]
    require(user["data"]["text"] == e["expected_prompt"], "Prompt admission")
    require(user["seq"] < idle["seq"], "Execution causal order")
    require(idle["data"]["time"]["created"] == idle["time_created"], "Terminal timestamp")
    require(session["time_idle"] >= idle["time_created"] >= user["time_created"], "Session terminal timestamp")
    outcome = idle["data"]["outcome"]
    require(outcome == session["idle_outcome"], "Execution outcome agreement")
    if outcome in {"failed", "interrupted"}:
        return "failed", "opencode_execution_" + outcome
    require(outcome == "succeeded" and not idle["data"].get("error"), "Successful execution lifecycle")
    assistants = [r for r in rows if r["type"] == "assistant"]
    require(assistants and user["seq"] < assistants[0]["seq"] < idle["seq"], "Assistant admission")
    require(set(e["stdout_message_ids"]).issubset({r["id"] for r in assistants}), "stdout Message identity")
    for r in rows:
        if r["type"] == "compaction":
            require(r["data"].get("status") == "completed", "Unsettled compaction")
    for r in assistants:
        data = r["data"]
        require(data["model"]["id"] == e["expected_model"] and data["model"]["providerID"] == "camact",
                "Configured model identity")
        require(not data.get("error") and not data.get("retry"), "Unresolved native execution error")
        require(user["time_created"] <= data["time"]["created"] <= data["time"]["completed"]
                <= idle["time_created"], "Assistant completion timestamp")
        for part in data["content"]:
            if part["type"] != "tool":
                continue
            require(part["state"]["status"] in {"completed", "error"}, "Pending native tool")
            require(part["time"]["created"] <= part["time"]["completed"] <= data["time"]["completed"],
                    "Tool completion timestamp")
            if part["state"]["status"] == "error":
                error_type = part["state"].get("error", {}).get("type", "")
                require(error_type != "tool.execution.cancelled" and not error_type.startswith("provider."),
                        "Native tool infrastructure failure")
    final = assistants[-1]["data"]
    if final.get("finish") == "length":
        return "agent_failure", "native_output_token_limit"
    require(final.get("finish") == "stop" and final.get("rawFinish") not in
            {"tool_use", "tool_calls", "tool-calls", "max_tokens", "length", "content_filter"},
            "Final assistant finish reason")
    require(any(p["type"] == "text" and p.get("text", "").strip() for p in final["content"]),
            "Empty assistant completion")
    return "finished", None


def final_text(evidence):
    """Publish only a checked final message; never expose earlier tool-step prose."""
    if terminal_signal(evidence)[0] not in {"finished", "agent_failure"}:
        return ""
    final = next(r for r in reversed(evidence["messages"]) if r["type"] == "assistant")
    return "".join(p["text"] for p in final["data"]["content"] if p["type"] == "text")
