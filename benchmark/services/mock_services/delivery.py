"""Session-local email and Telegram transport with persisted receiver receipts.

No provider APIs are used. A successful send commits the sender and receiver
records together; a delivery read verifies those records rather than creating
an acknowledgement from the agent's claim.
"""
from __future__ import annotations

import copy
import hashlib
import json
from uuid import uuid4

from ..tool_support import ToolBackend, ToolExecutionError, _utc_now


class DeliveryTools(ToolBackend):
    def __init__(self, *args, channel: str, session_id: str, **kwargs):
        super().__init__(*args, **kwargs)
        if channel not in {"email", "telegram"} or not session_id:
            raise ToolExecutionError("delivery service needs a channel and session")
        self.channel = channel
        self.session_id = session_id

    @staticmethod
    def _fingerprint(payload):
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()

    def _recipient(self, value):
        field = "email" if self.channel == "email" else "telegram_chat_id"
        normalize = str.casefold if self.channel == "email" else lambda item: item
        matches = [contact for contact in self.state["contacts"]
                   if isinstance(contact.get(field), str)
                   and normalize(contact[field]) == normalize(value)]
        if len(matches) != 1 or not matches[0].get("contact_id"):
            raise ToolExecutionError("destination must identify one configured channel contact")
        return matches[0]

    def _payload(self, args):
        keys = ("to_email", "subject", "body") if self.channel == "email" else ("chat_id", "text")
        payload = {key: self._required_text(args, key) for key in keys}
        payload["attachments"] = list(args["attachments"])
        self._require_images(payload["attachments"])
        return payload

    def _send(self, args):
        payload = self._payload(args)
        destination = "to_email" if self.channel == "email" else "chat_id"
        contact = self._recipient(payload[destination])
        # Store the contact's canonical endpoint, including email spelling.
        payload[destination] = contact["email" if self.channel == "email" else "telegram_chat_id"]
        fingerprint = self._fingerprint(payload)
        key = args.get("idempotency_key", "payload:" + fingerprint)
        state = self.state[self.channel]
        for message in state["sent"]:
            if message.get("session_id") == self.session_id and message.get("idempotency_key") == key:
                if message.get("payload_sha256") != fingerprint:
                    raise ToolExecutionError("idempotency_key was already used for different content")
                self._delivery(message["message_id"])
                return {"status": "sent", "message": copy.deepcopy(message), "replayed": True}
        message = {
            "message_id": self.channel + "_" + uuid4().hex,
            "channel": self.channel, "session_id": self.session_id,
            "recipient_contact_id": contact["contact_id"], "status": "sent",
            "sent_at": _utc_now(), **payload,
            "idempotency_key": key, "payload_sha256": fingerprint,
        }
        receipt = {
            "receipt_id": "receipt_" + uuid4().hex,
            "message_id": message["message_id"], "channel": self.channel,
            "session_id": self.session_id, "recipient_contact_id": contact["contact_id"],
            destination: payload[destination], "status": "received",
            "received_at": _utc_now(), "payload_sha256": fingerprint,
        }
        state["sent"].append(message)
        state["received"].append(receipt)
        return {"status": "sent", "message": copy.deepcopy(message), "replayed": False}

    def _delivery(self, message_id):
        state = self.state[self.channel]
        messages = [item for item in state["sent"] if item.get("message_id") == message_id]
        receipts = [item for item in state["received"] if item.get("message_id") == message_id]
        if len(messages) != 1 or len(receipts) != 1:
            raise ToolExecutionError("message has no unique sender and receiver record in this session")
        message, receipt = messages[0], receipts[0]
        keys = ("to_email", "subject", "body", "attachments") if self.channel == "email" else ("chat_id", "text", "attachments")
        payload = {key: message[key] for key in keys}
        fingerprint = self._fingerprint(payload)
        destination = "to_email" if self.channel == "email" else "chat_id"
        contact = self._recipient(message[destination])
        expected = {"message_id": message_id, "channel": self.channel,
                    "session_id": self.session_id, "recipient_contact_id": contact["contact_id"],
                    destination: message[destination], "payload_sha256": fingerprint}
        if (any(message.get(key) != value or receipt.get(key) != value for key, value in expected.items())
                or message.get("status") != "sent" or receipt.get("status") != "received"
                or not message.get("sent_at") or not receipt.get("received_at") or not receipt.get("receipt_id")):
            raise ToolExecutionError("sender and receiver records do not match this session's delivery")
        self._require_images(message["attachments"])
        return {"status": "received", "message": copy.deepcopy(message), "receipt": copy.deepcopy(receipt)}

    def _tool_email_send(self, args):
        return self._send(args)

    def _tool_telegram_send(self, args):
        return self._send(args)

    def _tool_email_get_delivery(self, args):
        return self._delivery(self._required_text(args, "message_id"))

    def _tool_telegram_get_delivery(self, args):
        return self._delivery(self._required_text(args, "message_id"))
