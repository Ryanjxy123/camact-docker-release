"""Moments publishing backend; the service commits records before replying."""
from __future__ import annotations

import copy
import hashlib
import json
from uuid import uuid4

from ..tool_support import ToolBackend, ToolExecutionError, _utc_now


class MomentsTools(ToolBackend):
    def __init__(self, *args, session_id: str, **kwargs):
        super().__init__(*args, **kwargs)
        self.session_id = session_id

    def _tool_publish_post(self, args):
        text = self._required_text(args, "text")
        images = args["images"]
        self._require_images(images)
        if not images or len(set(images)) != len(images):
            raise ToolExecutionError("a post needs distinct raw album images")
        payload = {"text": text, "images": images, "visibility": args["visibility"],
                   "identity_claims": self._identity_claims(args)}
        fingerprint = hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        key = args.get("idempotency_key", "payload:" + fingerprint)
        posts = self.state["publishing"]["posts"]
        for post in posts:
            if post.get("idempotency_key") == key:
                if post.get("payload_sha256") != fingerprint:
                    raise ToolExecutionError("idempotency_key was already used for different content")
                return {"status": "published", "post": copy.deepcopy(post), "replayed": True}
        post = {"post_id": "post_" + uuid4().hex, "lifecycle": "published",
                "status": "published", **payload, "published_at": _utc_now(),
                "session_id": self.session_id, "idempotency_key": key,
                "payload_sha256": fingerprint}
        posts.append(post)
        return {"status": "published", "post": copy.deepcopy(post), "replayed": False}

    def _tool_post_get(self, args):
        post_id = self._required_text(args, "post_id")
        post = next((p for p in self.state["publishing"]["posts"] if p["post_id"] == post_id), None)
        if post is None:
            raise ToolExecutionError("post does not exist in this session")
        self._require_images(post["images"])
        return {"status": "found", "post": copy.deepcopy(post)}
