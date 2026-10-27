"""Passive capture of official dsh durable Session logs, including child work.

The public persistence option compression=none changes storage encoding only.
No request, tool result, context, or agent decision is synthesized here.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import threading
import time

from claude_code_harness.core import write_json
from .transport import redact


class DeepSeekSessionCapture:
    def __init__(self, output: Path, secrets=()):
        self.output = Path(output)
        self.home = self.output / "home"
        self.secrets = tuple(secret for secret in secrets if secret)
        self.events, self.errors, self.offsets = [], [], {}
        self.lock = threading.RLock()
        self.stop = threading.Event()

    def __enter__(self):
        self.home.mkdir(parents=True, mode=0o700, exist_ok=False)
        self.thread = threading.Thread(target=self._poll, daemon=True)
        self.thread.start()
        return self

    def _poll(self):
        while not self.stop.wait(.25):
            try:
                self.collect()
            except Exception as exc:
                self.errors.append(f"{type(exc).__name__}: {exc}")

    def collect(self):
        with self.lock:
            root = self.home / ".dsh/sessions"
            for path in sorted(root.glob("*/*/session*.jsonl")):
                if any(p.is_symlink() for p in (path, *path.parents) if p.is_relative_to(self.home)):
                    raise RuntimeError("dsh Session path contains a symlink")
                relative = str(path.relative_to(self.home))
                stat = path.stat()
                previous = self.offsets.get(relative, {"offset": 0, "inode": stat.st_ino})
                if previous["inode"] != stat.st_ino or stat.st_size < previous["offset"]:
                    raise RuntimeError("An append-only dsh Session log was replaced or truncated")
                with path.open("rb") as source:
                    source.seek(previous["offset"])
                    while True:
                        offset, line = source.tell(), source.readline()
                        if not line or not line.endswith(b"\n"):
                            break  # Uncommitted/torn tail is never a complete event.
                        native = json.loads(redact(line.decode("utf-8"), self.secrets))
                        row = {"type": "deepseek.native_session_event", "source_file": relative,
                               "source_offset_bytes": offset, "captured_at": time.time(),
                               "native_event": native}
                        with (self.output / "native-session-events.jsonl").open("a", encoding="utf-8") as target:
                            target.write(json.dumps(row, ensure_ascii=False) + "\n")
                        self.events.append(row)
                        previous["offset"] = source.tell()
                self.offsets[relative] = previous

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(5)
        self.collect()
        files = []
        for relative, position in self.offsets.items():
            data = (self.home / relative).read_bytes()
            files.append({"path": relative, "bytes": len(data),
                          "captured_bytes": position["offset"],
                          "incomplete_tail_bytes": len(data) - position["offset"],
                          "sha256": hashlib.sha256(data).hexdigest()})
        write_json(self.output / "native-session-capture.json", {
            "harness": "deepseek", "source": "official dsh append-only Session JSONL",
            "compression": "none", "events": len(self.events), "errors": self.errors,
            "files": files, "agent_loop_modified": False})
