"""Deterministic, raw-memory-only services exposed to benchmark agents."""
from __future__ import annotations
import base64
import csv
import json
import mimetypes
import re
from io import BytesIO
from functools import lru_cache
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont, ImageOps

def load_manifest(task_dir: Path):
    return json.loads((task_dir / "workspace" / "memory_snapshot" / "memory_manifest.json").read_text(encoding="utf-8"))

def raw_root(task_dir: Path) -> Path:
    root = Path(str(load_manifest(task_dir)["runtime_root"]))
    if root.is_absolute():
        return root
    return (task_dir / "workspace" / "memory_snapshot" / root).resolve()

def _rows(task_dir: Path):
    with (raw_root(task_dir) / "metadata.csv").open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))

def photo_search_page(
    task_dir: Path,
    query: str = "",
    location: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    offset: int = 0,
    limit: int = 50,
):
    """Search raw metadata with composable filters and deterministic paging."""
    query_needle = str(query or "").casefold().strip()
    location_needle = str(location or "").casefold().strip()
    start = str(start_date or "").strip()
    end = str(end_date or "").strip()
    bounded_offset = max(0, int(offset))
    bounded_limit = max(1, min(int(limit), 200))
    matches = []
    for row in _rows(task_dir):
        corpus = " ".join(row.values()).casefold()
        taken = str(row.get("datetaken", ""))[:10]
        if query_needle and query_needle not in corpus:
            continue
        if location_needle and location_needle not in str(row.get("location", "")).casefold():
            continue
        if start and taken < start:
            continue
        if end and taken > end:
            continue
        matches.append(row)
    matches.sort(key=lambda row: (str(row.get("datetaken", "")), str(row.get("image", ""))))
    page = matches[bounded_offset : bounded_offset + bounded_limit]
    next_offset = bounded_offset + len(page)
    if next_offset >= len(matches):
        next_offset = None
    return {
        "photos": [
            {
                "image": row["image"],
                "datetaken": row["datetaken"],
                "location": row["location"],
            }
            for row in page
        ],
        "total": len(matches),
        "offset": bounded_offset,
        "next_offset": next_offset,
    }


def photo_search(
    task_dir: Path,
    query: str = "",
    location: str | None = None,
    limit: int = 50,
):
    """Backward-compatible list-only photo search API."""
    return photo_search_page(
        task_dir,
        query=query,
        location=location,
        limit=limit,
    )["photos"]

def metadata_lookup(task_dir: Path, image: str):
    for row in _rows(task_dir):
        if row["image"] == image:
            return row
    raise KeyError(f"unknown raw image: {image}")


def image_path(task_dir: Path, image: str) -> Path:
    """Resolve a raw image without permitting traversal outside the album."""
    if not image or Path(image).name != image:
        raise KeyError(f"unknown raw image: {image}")
    image_root = (raw_root(task_dir) / "images").resolve()
    path = (image_root / image).resolve()
    if path.parent != image_root:
        raise KeyError(f"unknown raw image: {image}")
    if not path.is_file():
        raise KeyError(f"unknown raw image: {image}")
    return path


def inspect_image(task_dir: Path, image: str):
    """Return a safe reference; semantic understanding is never synthesized."""
    path = image_path(task_dir, image)
    media_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    return {
        "image_id": image,
        "image_source": f"runtime://images/{image}",
        "media_type": media_type,
        "bytes": path.stat().st_size,
    }


def image_data_url(task_dir: Path, image: str) -> str:
    """Materialize a validated raw image for an MLLM image_url content block."""
    path = image_path(task_dir, image)
    media_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:{media_type};base64,{encoded}"


@lru_cache(maxsize=32)
def _album_contact_sheet_data_url(
    raw_album_root: str, image_ids: tuple[str, ...], image_refs: tuple[str, ...] = (),
) -> str:
    """Cache recent immutable album pages shared by tasks for the same user."""
    if not image_ids:
        raise ValueError("cannot render an empty album page")
    if image_refs and len(image_refs) != len(image_ids):
        raise ValueError("each thumbnail must have exactly one image reference")
    columns = 8
    thumb_width, thumb_height = 150, 104
    cell_width, cell_height = 164, 132
    rows = (len(image_ids) + columns - 1) // columns
    sheet = Image.new("RGB", (columns * cell_width, rows * cell_height), "white")
    draw = ImageDraw.Draw(sheet)
    ref_font = ImageFont.load_default(size=16) if image_refs else None
    image_root = (Path(raw_album_root) / "images").resolve()
    for index, image_id in enumerate(image_ids):
        if not image_id or Path(image_id).name != image_id:
            raise KeyError(f"unknown raw image: {image_id}")
        path = (image_root / image_id).resolve()
        if path.parent != image_root or not path.is_file():
            raise KeyError(f"unknown raw image: {image_id}")
        column, row = index % columns, index // columns
        left = column * cell_width + 7
        top = row * cell_height + 7
        with Image.open(path) as source:
            thumbnail = ImageOps.contain(
                ImageOps.exif_transpose(source).convert("RGB"),
                (thumb_width, thumb_height),
            )
        image_left = left + (thumb_width - thumbnail.width) // 2
        image_top = top + (thumb_height - thumbnail.height) // 2
        sheet.paste(thumbnail, (image_left, image_top))
        draw.rectangle(
            (left - 1, top - 1, left + thumb_width, top + thumb_height),
            outline="#b8b8b8",
        )
        label = image_refs[index] if image_refs else image_id
        draw.text((left, top + thumb_height + 5), label, fill="black", font=ref_font)
    buffer = BytesIO()
    sheet.save(buffer, format="JPEG", quality=82, optimize=True)
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/jpeg;base64,{encoded}"


def album_contact_sheet_data_url(task_dir: Path, photos: list[dict]) -> str:
    """Render raw album thumbnails as a generic, task-independent contact sheet."""
    return _album_contact_sheet_data_url(
        str(raw_root(task_dir).resolve()),
        tuple(str(photo["image"]) for photo in photos),
        tuple(str(photo["image_ref"]) for photo in photos) if photos and "image_ref" in photos[0] else (),
    )


PERSON_ID_PATTERN = re.compile(r"^person_[A-Z]+$")


def _explicit_person_id(record: dict) -> str:
    """Read a stable opaque ID; never derive identity references from names."""
    person_id = str(record.get("person_id", "")).strip()
    if not PERSON_ID_PATTERN.fullmatch(person_id):
        raise ValueError("relation graph person_id must match person_[A-Z]+")
    return person_id


def _relation_graph(task_dir: Path) -> dict:
    path = raw_root(task_dir) / "relation_graph" / "relation_graph.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _people(task_dir: Path) -> list[dict]:
    graph = _relation_graph(task_dir)
    records: list[dict] = []
    owner = graph.get("owner")
    if isinstance(owner, dict):
        records.append({**owner, "relation": "owner"})
    records.extend(item for item in graph.get("entities", []) if isinstance(item, dict))
    records.extend(item for item in graph.get("relations", []) if isinstance(item, dict))
    unique: dict[str, dict] = {}
    for item in records:
        name = str(item.get("name", "")).strip()
        if not name:
            continue
        person_id = _explicit_person_id(item)
        key = person_id.casefold()
        existing = unique.get(key, {})
        if existing and str(existing.get("name", "")).casefold() != name.casefold():
            raise ValueError(f"duplicate relation graph person_id: {person_id}")
        unique[key] = {**existing, **item, "person_id": person_id}
    return list(unique.values())


def people_search(
    task_dir: Path,
    query: str = "",
    relation: str | None = None,
    limit: int = 20,
) -> list[dict]:
    query_folded = query.casefold().strip()
    relation_folded = str(relation or "").casefold().strip()
    if not query_folded and not relation_folded:
        raise ValueError("query or relation is required")
    bounded_limit = max(1, min(int(limit), 20))
    matches = []
    for item in _people(task_dir):
        name = str(item.get("name", ""))
        known_relation = str(item.get("relation", ""))
        if query_folded and query_folded not in name.casefold():
            continue
        if relation_folded and relation_folded != known_relation.casefold():
            continue
        matches.append(
            {
                "person_id": item["person_id"],
                "display_name": name,
                "entity_type": str(item.get("type", "person")),
                "has_reference_image": bool(item.get("image")),
            }
        )
    return matches[:bounded_limit]


def person_record(task_dir: Path, person_id: str) -> dict:
    requested = person_id.casefold()
    for item in _people(task_dir):
        if item["person_id"].casefold() == requested:
            return item
    raise KeyError(f"unknown person: {person_id}")


def relationship_lookup(task_dir: Path, person_id: str) -> dict:
    graph = _relation_graph(task_dir)
    person = person_record(task_dir, person_id)
    owner = graph.get("owner", {})
    relation = person.get("relation")
    return {
        "person_id": person["person_id"],
        "subject": person.get("name"),
        "relative_to": owner.get("name"),
        "relation": relation,
        "source": "user_relation_graph",
    }


def person_reference_path(task_dir: Path, person_id: str) -> Path:
    person = person_record(task_dir, person_id)
    relative = Path(str(person.get("image", "")))
    graph_root = (raw_root(task_dir) / "relation_graph").resolve()
    path = (graph_root / relative).resolve()
    if not relative.parts or graph_root not in path.parents or not path.is_file():
        raise KeyError(f"reference image is unavailable for {person_id}")
    return path


def person_reference(task_dir: Path, person_id: str) -> dict:
    person = person_record(task_dir, person_id)
    path = person_reference_path(task_dir, person_id)
    media_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    return {
        "person_id": person["person_id"],
        "display_name": person.get("name"),
        "image_source": f"runtime://relation-graph/people/{person['person_id']}",
        "media_type": media_type,
        "bytes": path.stat().st_size,
    }


def person_reference_data_url(task_dir: Path, person_id: str) -> str:
    path = person_reference_path(task_dir, person_id)
    media_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:{media_type};base64,{encoded}"


def owner_profile_path(task_dir: Path) -> Path:
    """Resolve the owner's dedicated profile reference without album injection."""
    root = raw_root(task_dir).resolve()
    path = (root / "profile.jpg").resolve()
    if path.parent != root or not path.is_file():
        raise KeyError("owner profile image is unavailable")
    return path


def owner_profile(task_dir: Path) -> dict:
    graph = _relation_graph(task_dir)
    owner = graph.get("owner", {})
    name = str(owner.get("name", "")).strip()
    if not name:
        raise KeyError("owner identity is unavailable")
    path = owner_profile_path(task_dir)
    media_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    return {
        "person_id": _explicit_person_id(owner),
        "display_name": name,
        "entity_type": str(owner.get("type", "person")),
        "relation_to_owner": "owner",
        "image_source": "runtime://owner-profile",
        "media_type": media_type,
        "bytes": path.stat().st_size,
    }


def owner_profile_data_url(task_dir: Path) -> str:
    path = owner_profile_path(task_dir)
    media_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:{media_type};base64,{encoded}"

def album_query(task_dir: Path, **filters):
    return photo_search(task_dir, filters.get("query", ""), filters.get("location"), filters.get("limit", 50))

