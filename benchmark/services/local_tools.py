"""Local Python photo, metadata and workspace tools (no service process)."""
from __future__ import annotations
import copy
from datetime import date
from pathlib import Path
from typing import Any
from .tool_support import ToolBackend, ToolExecutionError, _utc_now
from .api import (photo_search_page, metadata_lookup, inspect_image, people_search,
                  person_reference, relationship_lookup, owner_profile)
from .archive_entries import retained_entries, validate_entries
from .checklist_items import create_items, item_position, next_item_id, next_record_id, validate_images


class LocalToolExecutor(ToolBackend):
    def _tool_album_search(self, args: dict[str, Any]) -> dict[str, Any]:
        return photo_search_page(
            self.task_dir,
            query=str(args.get("query", "")),
            location=args.get("location"),
            start_date=args.get("start_date"),
            end_date=args.get("end_date"),
            offset=int(args.get("offset", 0)),
            limit=int(args.get("limit", 50)),
        )


    def _tool_album_browse(self, args: dict[str, Any]) -> dict[str, Any]:
        return photo_search_page(
            self.task_dir,
            query=str(args.get("query", "")),
            location=args.get("location"),
            start_date=args.get("start_date"),
            end_date=args.get("end_date"),
            offset=int(args.get("offset", 0)),
            limit=min(int(args.get("limit", 60)), 80),
        )


    def _tool_album_get_metadata(self, args: dict[str, Any]) -> dict[str, Any]:
        image = str(args.get("image", ""))
        if not image:
            raise ToolExecutionError("image is required")
        return metadata_lookup(self.task_dir, image)


    def _tool_inspect_image(self, args: dict[str, Any]) -> dict[str, Any]:
        image = str(args.get("image", ""))
        if not image:
            raise ToolExecutionError("image is required")
        return inspect_image(self.task_dir, image)


    def _tool_image_view(self, args: dict[str, Any]) -> dict[str, Any]:
        image_id = str(args.get("image_id", ""))
        if not image_id:
            raise ToolExecutionError("image_id is required")
        return inspect_image(self.task_dir, image_id)


    def _tool_people_search(self, args: dict[str, Any]) -> dict[str, Any]:
        matches = people_search(
            self.task_dir,
            query=str(args.get("query", "")),
            relation=args.get("relation"),
            limit=int(args.get("limit", 20)),
        )
        return {"people": matches, "total": len(matches)}


    def _tool_person_view_reference(self, args: dict[str, Any]) -> dict[str, Any]:
        person_id = str(args.get("person_id", ""))
        if not person_id:
            raise ToolExecutionError("person_id is required")
        return person_reference(self.task_dir, person_id)


    def _tool_relationship_lookup(self, args: dict[str, Any]) -> dict[str, Any]:
        person_id = str(args.get("person_id", ""))
        if not person_id:
            raise ToolExecutionError("person_id is required")
        return relationship_lookup(self.task_dir, person_id)


    def _tool_owner_profile_view(self, args: dict[str, Any]) -> dict[str, Any]:
        if args:
            raise ToolExecutionError("owner_profile_view takes no arguments")
        return owner_profile(self.task_dir)


    def _tool_albums_list(self, args: dict[str, Any]) -> dict[str, Any]:
        query = str(args.get("query", "")).casefold().strip()
        albums = [
            copy.deepcopy(album)
            for album in self.state["photo_library"]["albums"]
            if not query
            or query
            in f"{album.get('title', '')} {album.get('description', '')}".casefold()
        ]
        return {"albums": albums, "total": len(albums)}


    def _tool_album_get(self, args: dict[str, Any]) -> dict[str, Any]:
        album_id = self._required_text(args, "album_id")
        album = self._record_by_id(
            self.state["photo_library"]["albums"], album_id, "album_id"
        )
        if album is None:
            raise ToolExecutionError(f"album '{album_id}' does not exist")
        return copy.deepcopy(album)


    def _tool_stories_list(self, args: dict[str, Any]) -> dict[str, Any]:
        query = str(args.get("query", "")).casefold().strip()
        stories = [
            copy.deepcopy(story)
            for story in self.state["photo_library"]["stories"]
            if not query
            or query in f"{story.get('title', '')} {story.get('text', '')}".casefold()
        ]
        return {"stories": stories, "total": len(stories)}


    def _tool_story_get(self, args: dict[str, Any]) -> dict[str, Any]:
        story_id = self._required_text(args, "story_id")
        story = self._record_by_id(
            self.state["photo_library"]["stories"], story_id, "story_id"
        )
        if story is None:
            raise ToolExecutionError(f"story '{story_id}' does not exist")
        return copy.deepcopy(story)


    def _tool_archives_list(self, args: dict[str, Any]) -> dict[str, Any]:
        query = str(args.get("query", "")).casefold().strip()
        records = [
            copy.deepcopy(record)
            for record in self.state["archives"]["records"]
            if not query
            or query in f"{record.get('title', '')} {record.get('summary', '')}".casefold()
        ]
        return {"archives": records, "total": len(records)}


    def _tool_archive_get(self, args: dict[str, Any]) -> dict[str, Any]:
        archive_id = self._required_text(args, "archive_id")
        record = self._record_by_id(
            self.state["archives"]["records"], archive_id, "archive_id"
        )
        if record is None:
            raise ToolExecutionError(f"archive '{archive_id}' does not exist")
        return copy.deepcopy(record)


    def _tool_checklists_list(self, args: dict[str, Any]) -> dict[str, Any]:
        query = str(args.get("query", "")).casefold().strip()
        records = [
            copy.deepcopy(record)
            for record in self.state["checklists"]
            if not query or query in str(record.get("title", "")).casefold()
        ]
        return {"checklists": records, "total": len(records)}


    def _tool_checklist_get(self, args: dict[str, Any]) -> dict[str, Any]:
        checklist_id = self._required_text(args, "checklist_id")
        record = self._record_by_id(
            self.state["checklists"], checklist_id, "checklist_id"
        )
        if record is None:
            raise ToolExecutionError(f"checklist '{checklist_id}' does not exist")
        return copy.deepcopy(record)


    def _tool_contacts_search(self, args: dict[str, Any]) -> dict[str, Any]:
        query = str(args.get("query", "")).casefold().strip()
        if not query:
            raise ToolExecutionError("query is required")
        contacts = [
            copy.deepcopy(contact)
            for contact in self.state["contacts"]
            if query in " ".join(str(value) for value in contact.values()).casefold()
        ]
        return {"contacts": contacts, "total": len(contacts)}


    def _tool_album_create(self, args: dict[str, Any]) -> dict[str, Any]:
        title = self._required_text(args, "title")
        album = {
            "album_id": f"album_{len(self.state['photo_library']['albums']) + 1:03d}",
            "title": title,
            "description": str(args.get("description", "")),
            "images": [],
            "created_at": _utc_now(),
        }
        self.state["photo_library"]["albums"].append(album)
        return {"status": "created", "album": copy.deepcopy(album)}


    def _tool_album_update(self, args: dict[str, Any]) -> dict[str, Any]:
        album_id = self._required_text(args, "album_id")
        album = self._record_by_id(
            self.state["photo_library"]["albums"], album_id, "album_id"
        )
        if album is None:
            raise ToolExecutionError(f"album '{album_id}' does not exist")
        for key in ("title", "description"):
            if key in args:
                album[key] = str(args[key])
        album["updated_at"] = _utc_now()
        return {"status": "updated", "album": copy.deepcopy(album)}


    def _tool_album_add_images(self, args: dict[str, Any]) -> dict[str, Any]:
        album_id = self._required_text(args, "album_id")
        album = self._record_by_id(
            self.state["photo_library"]["albums"], album_id, "album_id"
        )
        if album is None:
            raise ToolExecutionError(f"album '{album_id}' does not exist")
        images = list(args.get("images", []))
        if not images:
            raise ToolExecutionError("images must not be empty")
        self._require_images(images)
        for image in images:
            if image not in album["images"]:
                album["images"].append(image)
        album["updated_at"] = _utc_now()
        return {"status": "updated", "album": copy.deepcopy(album)}


    def _tool_album_remove_images(self, args: dict[str, Any]) -> dict[str, Any]:
        album_id = self._required_text(args, "album_id")
        album = self._record_by_id(
            self.state["photo_library"]["albums"], album_id, "album_id"
        )
        if album is None:
            raise ToolExecutionError(f"album '{album_id}' does not exist")
        remove = set(args.get("images", []))
        album["images"] = [image for image in album["images"] if image not in remove]
        album["updated_at"] = _utc_now()
        return {"status": "updated", "album": copy.deepcopy(album)}


    def _tool_story_create_draft(self, args: dict[str, Any]) -> dict[str, Any]:
        title = self._required_text(args, "title")
        images = list(args.get("images", []))
        if not images:
            raise ToolExecutionError("images must not be empty")
        self._require_images(images)
        story = {
            "story_id": f"story_{len(self.state['photo_library']['stories']) + 1:03d}",
            "title": title,
            "text": str(args.get("text", "")),
            "images": images,
            "status": "draft",
            "created_at": _utc_now(),
        }
        self.state["photo_library"]["stories"].append(story)
        return {"status": "created", "story": copy.deepcopy(story)}


    def _tool_story_update_draft(self, args: dict[str, Any]) -> dict[str, Any]:
        story_id = self._required_text(args, "story_id")
        story = self._record_by_id(
            self.state["photo_library"]["stories"], story_id, "story_id"
        )
        if story is None:
            raise ToolExecutionError(f"story '{story_id}' does not exist")
        if story.get("status") != "draft":
            raise ToolExecutionError("only draft stories can be updated")
        for key in ("title", "text"):
            if key in args:
                story[key] = str(args[key])
        if "images" in args:
            images = list(args["images"])
            self._require_images(images)
            story["images"] = images
        story["updated_at"] = _utc_now()
        return {"status": "updated", "story": copy.deepcopy(story)}


    def _tool_archive_create(self, args: dict[str, Any]) -> dict[str, Any]:
        title = self._required_text(args, "title")
        images = list(args.get("images", []))
        if not images:
            raise ToolExecutionError("images must not be empty")
        self._require_images(images)
        if "taken_at" in args:
            taken_at = args["taken_at"]
            try:
                if not isinstance(taken_at, str) or date.fromisoformat(taken_at).isoformat() != taken_at:
                    raise ValueError
            except ValueError as exc:
                raise ToolExecutionError("taken_at must be a valid date in YYYY-MM-DD format") from exc
        record = {
            "archive_id": f"archive_{len(self.state['archives']['records']) + 1:03d}",
            "title": title,
            "summary": str(args.get("summary", "")),
            "images": images,
            "created_at": _utc_now(),
        }
        if "taken_at" in args:
            record["taken_at"] = taken_at
        if "entries" in args:
            record["entries"] = validate_entries(self.task_dir, args["entries"], images)
        self.state["archives"]["records"].append(record)
        return {"status": "created", "archive": copy.deepcopy(record)}


    def _tool_archive_update(self, args: dict[str, Any]) -> dict[str, Any]:
        archive_id = self._required_text(args, "archive_id")
        record = self._record_by_id(
            self.state["archives"]["records"], archive_id, "archive_id"
        )
        if record is None:
            raise ToolExecutionError(f"archive '{archive_id}' does not exist")
        candidate = copy.deepcopy(record)
        for key in ("title", "summary"):
            if key in args:
                candidate[key] = str(args[key])
        if "images" in args:
            images = list(args["images"])
            self._require_images(images)
            candidate["images"] = images
        if "entries" in args:
            candidate["entries"] = validate_entries(self.task_dir, args["entries"], candidate["images"])
        elif "entries" in record and "images" in args:
            candidate["entries"] = retained_entries(self.task_dir, record["entries"],
                                                     record["images"], candidate["images"])
        candidate["updated_at"] = _utc_now()
        record.clear()
        record.update(candidate)
        return {"status": "updated", "archive": copy.deepcopy(record)}


    def _tool_checklist_create(self, args: dict[str, Any]) -> dict[str, Any]:
        title = self._required_text(args, "title")
        items = create_items(self.task_dir, args.get("items", []))
        record = {
            "checklist_id": next_record_id(self.state["checklists"], "checklist_id", "checklist"),
            "title": title,
            "items": items,
            "created_at": _utc_now(),
        }
        self.state["checklists"].append(record)
        return {"status": "created", "checklist": copy.deepcopy(record)}


    def _tool_checklist_add_item(self, args: dict[str, Any]) -> dict[str, Any]:
        checklist_id = self._required_text(args, "checklist_id")
        record = self._record_by_id(self.state["checklists"], checklist_id, "checklist_id")
        if record is None:
            raise ToolExecutionError(f"checklist '{checklist_id}' does not exist")
        text = self._required_text(args, "text")
        item = {
            "item_id": next_item_id(record["items"]),
            "text": text,
            "completed": False,
        }
        if "images" in args:
            item["images"] = validate_images(self.task_dir, args["images"])
        position = item_position(args, len(record["items"]), inserting=True)
        record["items"].insert(len(record["items"]) if position is None else position, item)
        return {"status": "created", "item": copy.deepcopy(item)}


    def _tool_checklist_update_item(self, args: dict[str, Any]) -> dict[str, Any]:
        checklist_id = self._required_text(args, "checklist_id")
        item_id = self._required_text(args, "item_id")
        record = self._record_by_id(self.state["checklists"], checklist_id, "checklist_id")
        if record is None:
            raise ToolExecutionError(f"checklist '{checklist_id}' does not exist")
        item = self._record_by_id(record["items"], item_id, "item_id")
        if item is None:
            raise ToolExecutionError(f"checklist item '{item_id}' does not exist")
        candidate = copy.deepcopy(item)
        if "text" in args:
            candidate["text"] = str(args["text"])
        if "completed" in args:
            candidate["completed"] = bool(args["completed"])
        if "images" in args:
            candidate["images"] = validate_images(self.task_dir, args["images"])
        position = item_position(args, len(record["items"]))
        item.clear()
        item.update(candidate)
        if position is not None:
            record["items"].remove(item)
            record["items"].insert(position, item)
        return {"status": "updated", "item": copy.deepcopy(item)}


    def _tool_workspace_write(self, args: dict[str, Any]) -> dict[str, Any]:
        name = str(args.get("name", "")).strip()
        if not name:
            raise ToolExecutionError("name is required")
        if Path(name).name != name or name in {".", ".."}:
            raise ToolExecutionError("name must be a plain filename")
        images = list(args.get("images", []))
        self._require_images(images)
        content = str(args.get("content", ""))
        target = self.session_dir / "workspace" / "output" / name
        identity_claims = self._identity_claims(args)
        record = {
            "name": name,
            "path": str(target),
            "content": content,
            "images": images,
            "identity_claims": identity_claims,
            "written_at": _utc_now(),
        }
        self.pending_writes[target] = content
        self.state["workspace"]["output"].append(record)
        return {"status": "written", "output": copy.deepcopy(record)}


    def _tool_workspace_list(self, args: dict[str, Any]) -> dict[str, Any]:
        if args:
            raise ToolExecutionError("workspace_list takes no arguments")
        outputs = [
            {key: copy.deepcopy(value) for key, value in record.items() if key != "content"}
            for record in self.state["workspace"]["output"]
        ]
        return {"outputs": outputs, "total": len(outputs)}


    def _tool_workspace_read(self, args: dict[str, Any]) -> dict[str, Any]:
        name = self._required_text(args, "name")
        record = self._record_by_id(self.state["workspace"]["output"], name, "name")
        if record is None:
            raise ToolExecutionError(f"workspace output '{name}' does not exist")
        return copy.deepcopy(record)


    def _tool_workspace_update(self, args: dict[str, Any]) -> dict[str, Any]:
        name = self._required_text(args, "name")
        record = self._record_by_id(self.state["workspace"]["output"], name, "name")
        if record is None:
            raise ToolExecutionError(f"workspace output '{name}' does not exist")
        if "content" in args:
            record["content"] = str(args["content"])
        if "images" in args:
            images = list(args["images"])
            self._require_images(images)
            record["images"] = images
        target = Path(record["path"])
        self.pending_writes[target] = str(record.get("content", ""))
        record["updated_at"] = _utc_now()
        return {"status": "updated", "output": copy.deepcopy(record)}


