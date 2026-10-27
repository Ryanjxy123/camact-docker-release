"""Existing CamAct platform business rules, executed only in a mock service.

The service owns the authoritative state. Handlers receive a private candidate
and commit only after all parameter and observation checks pass.
"""
from __future__ import annotations
import copy
import json
import os
import re
from datetime import date as iso_date, datetime, timedelta
from typing import Any
from ..booking_time import booking_slots_equal
from ..tool_support import ToolBackend, ToolExecutionError, _utc_now, _parse_datetime


class PlatformTools(ToolBackend):
    def _tool_threads_list(self, args: dict[str, Any]) -> dict[str, Any]:
        query = str(args.get("query", "")).casefold().strip()
        threads = [
            copy.deepcopy(thread)
            for thread in self.state["messages"]["threads"]
            if not query or query in json.dumps(thread, ensure_ascii=False).casefold()
        ]
        if os.environ.get('CAMACT_THREAD_LIST_SUMMARY_ONLY') == '1':
            # Opt-in authoring policy; existing consumers keep their response.
            threads = [{key: value for key, value in thread.items() if key != 'messages'}
                       for thread in threads]
        return {"threads": threads, "total": len(threads)}


    def _tool_thread_get(self, args: dict[str, Any]) -> dict[str, Any]:
        thread_id = self._required_text(args, "thread_id")
        thread = self._record_by_id(
            self.state["messages"]["threads"], thread_id, "thread_id"
        )
        if thread is None:
            raise ToolExecutionError(f"thread '{thread_id}' does not exist")
        return copy.deepcopy(thread)


    def _tool_calendar_get_event(self, args: dict[str, Any]) -> dict[str, Any]:
        event_id = self._required_text(args, "event_id")
        event = self._record_by_id(self._calendar_events(), event_id, "event_id")
        if event is None:
            raise ToolExecutionError(f"calendar event '{event_id}' does not exist")
        return copy.deepcopy(event)


    def _tool_service_search(self, args: dict[str, Any]) -> dict[str, Any]:
        terms = set(re.findall(r"\w+", self._required_text(args, "query").casefold()))
        location = str(args.get("location", "")).casefold().strip()
        matches = []
        for service in self.state["service_catalog"]:
            fields = ("service_id", "name", "category", "description", "facilities", "location",
                      "venue_name", "service_type", "tags")
            searchable = set(re.findall(r"\w+", " ".join(
                json.dumps(service.get(field, ""), ensure_ascii=False) for field in fields).casefold()))
            if not terms or not terms <= searchable:
                continue
            if location and location not in str(service.get("location", "")).casefold():
                continue
            matches.append(copy.deepcopy(service))
        if os.environ.get("CAMACT_SERVICE_CATALOG_SEPARATE_READS") == "1":
            matches = [{key: value for key, value in service.items()
                        if key in {"service_id", "name", "category", "location"}}
                       for service in matches]
        return {"services": matches, "total": len(matches)}


    def _tool_service_get_details(self, args: dict[str, Any]) -> dict[str, Any]:
        service_id = self._required_text(args, "service_id")
        service = self._record_by_id(
            self.state["service_catalog"], service_id, "service_id"
        )
        if service is None:
            raise ToolExecutionError(f"service '{service_id}' does not exist")
        if os.environ.get("CAMACT_SERVICE_CATALOG_SEPARATE_READS") == "1":
            return copy.deepcopy({key: value for key, value in service.items() if key != "availability"})
        return copy.deepcopy(service)


    def _tool_service_get_availability(self, args: dict[str, Any]) -> dict[str, Any]:
        service_id = self._required_text(args, "service_id")
        service = copy.deepcopy(self._record_by_id(self.state["service_catalog"], service_id, "service_id"))
        if service is None:
            raise ToolExecutionError(f"service '{service_id}' does not exist")
        slot = str(args.get("slot", "")).strip()
        slots = list(service.get("availability", []))
        available = bool(slots)
        if slot:
            if os.environ.get("CAMACT_BOOKING_SLOT_SEMANTICS") == "iso_datetime":
                available = any(booking_slots_equal(slot, candidate) for candidate in slots)
            else:
                available = slot in slots
        return {
            "service_id": service["service_id"],
            "available_slots": slots,
            "requested_slot": slot or None,
            "available": available,
        }


    def _tool_reservations_list(self, args: dict[str, Any]) -> dict[str, Any]:
        status = str(args.get("status", "")).casefold().strip()
        records = [
            copy.deepcopy(record)
            for record in self.state["reservations"]
            if not status or str(record.get("status", "")).casefold() == status
        ]
        return {"reservations": records, "total": len(records)}


    def _tool_message_create_draft(self, args: dict[str, Any]) -> dict[str, Any]:
        recipient = self._required_text(args, "to")
        contact = self._contact(recipient)
        if contact is None:
            raise ToolExecutionError(f"recipient '{recipient}' is not in task contacts")
        attachments = list(args.get("attachments", []))
        self._require_images(attachments)
        record = {
            "draft_id": f"message_draft_{len(self.state['messages']['drafts']) + 1:03d}",
            "to": contact["name"],
            "text": str(args.get("text", "")),
            "attachments": attachments,
            "identity_claims": self._identity_claims(args),
            "created_at": _utc_now(),
        }
        self.state["messages"]["drafts"].append(record)
        return {"status": "drafted", "draft": copy.deepcopy(record)}


    def _tool_message_send(self, args: dict[str, Any]) -> dict[str, Any]:
        recipient = str(args.get("to", "")).strip()
        if not recipient:
            raise ToolExecutionError("to is required")
        text = str(args.get("text", "")).strip()
        if not text:
            raise ToolExecutionError("text is required")
        contact = self._contact(recipient)
        if contact is None:
            raise ToolExecutionError(f"recipient '{recipient}' is not in task contacts")
        attachments = list(args.get("attachments", []))
        self._require_images(attachments)
        record = {
            "message_id": f"msg_{len(self.state['messages']['sent']) + 1:03d}",
            "to": contact["name"],
            "text": text,
            "attachments": attachments,
            "identity_claims": self._identity_claims(args),
            "sent_at": _utc_now(),
        }
        self.state["messages"]["sent"].append(record)
        return {"status": "sent", "message": copy.deepcopy(record)}


    def _calendar_events(self) -> list[dict[str, Any]]:
        return self.state["calendar"]["events"]


    @staticmethod
    def _calendar_interval(start: str, end: str) -> tuple[datetime, datetime]:
        # Calendar endpoints require times, not date-only midnight coercions.
        for value, field in ((start, "start"), (end, "end")):
            if len(value) <= 10 or value[10] not in {"T", "t", " "}:
                raise ToolExecutionError(f"{field} must be an ISO date-time")
        start_dt = _parse_datetime(start, "start")
        end_dt = _parse_datetime(end, "end")
        if (start_dt.tzinfo is None) != (end_dt.tzinfo is None):
            raise ToolExecutionError("calendar interval must use consistent time-zone offsets")
        if end_dt <= start_dt:
            raise ToolExecutionError("end must be after start")
        return start_dt, end_dt


    def _tool_calendar_search(self, args: dict[str, Any]) -> dict[str, Any]:
        date = str(args.get("date", ""))
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
            raise ToolExecutionError("date must use YYYY-MM-DD")
        try:
            requested_date = iso_date.fromisoformat(date)
        except ValueError as exc:
            raise ToolExecutionError("date must be a valid YYYY-MM-DD date") from exc
        events = []
        for event in self._calendar_events():
            event_start, event_end = self._calendar_interval(
                str(event.get("start", event.get("start_time", ""))),
                str(event.get("end", event.get("end_time", ""))),
            )
            # A date-only search is interpreted in each event's declared offset;
            # offset-free events keep their existing local wall-clock meaning.
            day_start = datetime.combine(requested_date, datetime.min.time(), event_start.tzinfo)
            day_end = day_start + timedelta(days=1)
            if day_start < event_end and day_end > event_start:
                events.append(copy.deepcopy(event))
        return {"events": events, "total": len(events)}


    def _tool_calendar_get_availability(self, args: dict[str, Any]) -> dict[str, Any]:
        start = str(args.get("start", ""))
        end = str(args.get("end", ""))
        start_dt, end_dt = self._calendar_interval(start, end)
        conflicts = []
        for event in self._calendar_events():
            event_start, event_end = self._calendar_interval(
                str(event.get("start", event.get("start_time", ""))),
                str(event.get("end", event.get("end_time", ""))),
            )
            if (start_dt.tzinfo is None) != (event_start.tzinfo is None):
                raise ToolExecutionError("query and calendar event must use consistent time-zone offsets")
            if start_dt < event_end and end_dt > event_start:
                conflicts.append(copy.deepcopy(event))
        return {
            "start": start,
            "end": end,
            "available": not conflicts,
            "conflicts": conflicts,
        }


    def _tool_calendar_create_event(self, args: dict[str, Any]) -> dict[str, Any]:
        # Optional album references are enabled by the declaring Task schema.
        # Consumers that omit these fields retain the original event shape.
        if "images" in args:
            self._require_images(args["images"])
        retry_key = args.get("idempotency_key")
        if retry_key is not None:
            if not isinstance(retry_key, str) or not retry_key.strip():
                raise ToolExecutionError("idempotency_key must be a non-empty string")
            request = {key: copy.deepcopy(value) for key, value in args.items()
                       if key != "idempotency_key"}
            previous = self.state["calendar"].get("create_requests", {}).get(retry_key)
            if previous is not None:
                if previous["request"] != request:
                    raise ToolExecutionError("idempotency_key was already used for a different event")
                return copy.deepcopy(previous["response"])
        start = str(args.get("start", ""))
        end = str(args.get("end", ""))
        self._calendar_interval(start, end)
        status = str(args.get("status", ""))
        if status not in {"tentative", "confirmed"}:
            raise ToolExecutionError("status must be tentative or confirmed")
        participants = list(args.get("participants", []))
        for participant in participants:
            if self.state["contacts"] and self._contact(str(participant)) is None:
                raise ToolExecutionError(
                    f"participant '{participant}' is not in task contacts"
                )
        availability = self._tool_calendar_get_availability({"start": start, "end": end})
        if not availability["available"]:
            raise ToolExecutionError("requested calendar interval conflicts with an event")
        event_number = len(self._calendar_events()) + 1
        existing_ids = {item.get("event_id") for item in self._calendar_events()}
        while f"evt_{event_number:03d}" in existing_ids:
            event_number += 1
        event = {
            "event_id": f"evt_{event_number:03d}",
            "title": str(args.get("title", args.get("location", "Plan"))),
            "location": str(args.get("location", "")),
            "start": start,
            "end": end,
            "status": status,
            "participants": participants,
            "created_at": _utc_now(),
        }
        if "images" in args:
            event["images"] = copy.deepcopy(args["images"])
        self.state["calendar"]["events"].append(event)
        self.state["calendar"]["created_events"].append(copy.deepcopy(event))
        response = {"status": "created", "event": copy.deepcopy(event)}
        if retry_key is not None:
            self.state["calendar"].setdefault("create_requests", {})[retry_key] = {
                "request": request, "response": copy.deepcopy(response),
            }
        return response


    def _tool_calendar_update_event(self, args: dict[str, Any]) -> dict[str, Any]:
        event_id = self._required_text(args, "event_id")
        event = self._record_by_id(self._calendar_events(), event_id, "event_id")
        if event is None:
            raise ToolExecutionError(f"calendar event '{event_id}' does not exist")
        for key in ("title", "location", "status"):
            if key in args:
                event[key] = str(args[key])
        if "participants" in args:
            event["participants"] = list(args["participants"])
        if "start" in args or "end" in args:
            start = str(args.get("start", event["start"]))
            end = str(args.get("end", event["end"]))
            if _parse_datetime(end, "end") <= _parse_datetime(start, "start"):
                raise ToolExecutionError("end must be after start")
            event["start"], event["end"] = start, end
        event["updated_at"] = _utc_now()
        return {"status": "updated", "event": copy.deepcopy(event)}


    def _reservation_party_size(self, service_id: str, party_size: Any) -> int:
        if type(party_size) is not int or party_size <= 0:
            raise ToolExecutionError("party_size must be a positive integer")
        service = self._tool_service_get_details({"service_id": service_id})
        # Catalogs that omit this optional limit retain the legacy contract.
        # A rental party limit is separate from its sleeping accommodation.
        if "party_capacity" in service:
            capacity = service["party_capacity"]
            if type(capacity) is not int or capacity <= 0:
                raise ToolExecutionError("service party_capacity must be a positive integer")
            if party_size > capacity:
                raise ToolExecutionError("party_size exceeds the service party_capacity")
        return party_size


    def _tool_reservation_create(self, args: dict[str, Any]) -> dict[str, Any]:
        # Optional raw-album references and retry keys preserve legacy receipts
        # when omitted, following calendar_create_event's retry contract.
        if "images" in args:
            self._require_images(args["images"])
        if "reference_images" in args:
            self._require_images(args["reference_images"])
        party_size = args.get("party_size", 1)
        retry_key = args.get("idempotency_key")
        if retry_key is not None:
            if not isinstance(retry_key, str) or not retry_key.strip():
                raise ToolExecutionError("idempotency_key must be a non-empty string")
            request = {key: copy.deepcopy(value) for key, value in args.items()
                       if key != "idempotency_key"}
            previous = self.state.get("reservation_create_requests", {}).get(retry_key)
            if previous is not None:
                if previous["request"] != request:
                    raise ToolExecutionError("idempotency_key was already used for a different reservation")
                return copy.deepcopy(previous["response"])
        service_id = self._required_text(args, "service_id")
        slot = self._required_text(args, "slot")
        party_size = self._reservation_party_size(service_id, party_size)
        availability = self._tool_service_get_availability(
            {"service_id": service_id, "slot": slot}
        )
        if not availability["available"]:
            raise ToolExecutionError("requested service slot is unavailable")
        reservation = {
            "reservation_id": f"reservation_{len(self.state['reservations']) + 1:03d}",
            "service_id": service_id,
            "slot": slot,
            "party_size": party_size,
            "notes": str(args.get("notes", "")),
            "status": "confirmed",
            "created_at": _utc_now(),
        }
        if "images" in args:
            reservation["images"] = copy.deepcopy(args["images"])
        if "reference_images" in args:
            reservation["reference_images"] = copy.deepcopy(args["reference_images"])
        self.state["reservations"].append(reservation)
        response = {"status": "created", "reservation": copy.deepcopy(reservation)}
        if retry_key is not None:
            self.state.setdefault("reservation_create_requests", {})[retry_key] = {
                "request": request, "response": copy.deepcopy(response),
            }
        return response


    def _tool_reservation_update(self, args: dict[str, Any]) -> dict[str, Any]:
        reservation_id = self._required_text(args, "reservation_id")
        record = self._record_by_id(
            self.state["reservations"], reservation_id, "reservation_id"
        )
        if record is None:
            raise ToolExecutionError(f"reservation '{reservation_id}' does not exist")
        if "party_size" in args:
            self._reservation_party_size(record["service_id"], args["party_size"])
        if "slot" in args:
            slot = str(args["slot"])
            availability = self._tool_service_get_availability(
                {"service_id": record["service_id"], "slot": slot}
            )
            if not availability["available"]:
                raise ToolExecutionError("requested service slot is unavailable")
            record["slot"] = slot
        for key in ("notes", "party_size"):
            if key in args:
                record[key] = int(args[key]) if key == "party_size" else str(args[key])
        record["updated_at"] = _utc_now()
        return {"status": "updated", "reservation": copy.deepcopy(record)}


    def _tool_reservation_cancel(self, args: dict[str, Any]) -> dict[str, Any]:
        reservation_id = self._required_text(args, "reservation_id")
        record = self._record_by_id(
            self.state["reservations"], reservation_id, "reservation_id"
        )
        if record is None:
            raise ToolExecutionError(f"reservation '{reservation_id}' does not exist")
        record["status"] = "cancelled"
        record["cancelled_at"] = _utc_now()
        return {"status": "cancelled", "reservation": copy.deepcopy(record)}


    def _tool_publish_post(self, args: dict[str, Any]) -> dict[str, Any]:
        lifecycle = str(args.get("lifecycle", "draft")).casefold()
        if lifecycle != "draft":
            raise ToolExecutionError("publishing tasks only create draft lifecycle records")
        visibility = str(args.get("visibility", "private")).casefold()
        if visibility not in {"private", "public"}:
            raise ToolExecutionError("visibility must be private or public")
        images = list(args.get("images", []))
        self._require_images(images)
        draft = {
            "draft_id": f"draft_{len(self.state['publishing']['drafts']['created']) + 1:03d}",
            "lifecycle": lifecycle,
            "visibility": visibility,
            "text": str(args.get("text", "")),
            "images": images,
            "identity_claims": self._identity_claims(args),
            "created_at": _utc_now(),
        }
        self.state["publishing"]["drafts"]["created"].append(draft)
        return {"status": "created", "draft": copy.deepcopy(draft)}


