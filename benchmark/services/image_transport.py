"""Deterministic, full-frame image copies for Baseline model requests only.

History and business attachments retain their original bytes. The request is
copied, measured with the sender's exact JSON encoding, and reduced only by
re-encoding native inline image blocks. No text or image block is removed.
"""
from __future__ import annotations

import base64
from collections import OrderedDict
import copy
import hashlib
import io
import json

from PIL import Image, ImageOps, __version__ as PILLOW_VERSION

VERSION = "camact.baseline_image_transport.v1"
MAX_REQUEST_BYTES = 35 * 1024 * 1024
MAX_IMAGE_SIDE = 8000
# Ordered from the most detailed candidate to smaller emergency wire copies.
TIERS = ((4096, 90), (3072, 90), (2048, 85), (1536, 80),
         (1024, 75), (768, 65), (512, 50), (256, 40))
_CACHE = OrderedDict()
_CACHE_BYTES = 0
_CACHE_LIMIT = 48 * 1024 * 1024


class ImageTransportLimitError(ValueError):
    """No image-only transform can meet the complete request budget."""


def serialize(body):
    return json.dumps(body, ensure_ascii=False).encode("utf-8")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _slots(value, path="$", tokens=()):
    """Yield only native protocol image values; never inspect text strings."""
    if isinstance(value, dict):
        kind = value.get("type")
        if kind in ("image_url", "input_image"):
            entry = value.get("image_url")
            if isinstance(entry, dict) and isinstance(entry.get("url"), str):
                url = entry["url"]
                if url.startswith("data:image/") and ";base64," in url:
                    yield tokens + ("image_url", "url"), path + ".image_url.url", url, "url"
            elif isinstance(entry, str) and entry.startswith("data:image/") and ";base64," in entry:
                yield tokens + ("image_url",), path + ".image_url", entry, "url"
        if kind == "image" and isinstance(value.get("source"), dict):
            source = value["source"]
            if source.get("type") == "base64" and str(source.get("media_type", "")).startswith("image/"):
                yield tokens + ("source",), path + ".source.data", source, "source"
        for name in ("inlineData", "inline_data"):
            entry = value.get(name)
            if isinstance(entry, dict) and str(entry.get("mimeType", entry.get("mime_type", ""))).startswith("image/"):
                yield tokens + (name,), path + "." + name + ".data", entry, "inline"
        for key, member in value.items():
            yield from _slots(member, path + "." + key, tokens + (key,))
    elif isinstance(value, list):
        for index, member in enumerate(value):
            yield from _slots(member, f"{path}[{index}]", tokens + (index,))


def transform_image(data, media_type, tier=0):
    """Return a wire copy and a replayable proof, with no filesystem writes."""
    global _CACHE_BYTES
    source_hash = _sha(data)
    cache_key = (source_hash, media_type, tier)
    if cache_key in _CACHE:
        _CACHE.move_to_end(cache_key)
        output, proof = _CACHE[cache_key]
        return output, copy.deepcopy(proof)
    longest, quality = TIERS[tier]
    with Image.open(io.BytesIO(data)) as source:
        source.load()
        if getattr(source, "n_frames", 1) != 1:
            raise ImageTransportLimitError("Animated model images require an explicit transport policy")
        stored_size = list(source.size)
        oriented = ImageOps.exif_transpose(source)
        width, height = oriented.size
        scale = min(1.0, longest / max(width, height), MAX_IMAGE_SIDE / max(width, height))
        size = (max(1, round(width * scale)), max(1, round(height * scale)))
        # Small originals, including browse contact sheets, need no conversion
        # until their dimensions exceed the tier. This is property based.
        preserve = (scale == 1 and len(data) <= 256 * 1024
                    and source.format in {"JPEG", "PNG", "WEBP"})
        output = data
        converted_type = media_type
        if not preserve:
            raster = oriented.convert("RGB")
            if raster.size != size:
                raster = raster.resize(size, Image.Resampling.LANCZOS)
            stream = io.BytesIO()
            options = dict(quality=quality, subsampling=2, optimize=True, progressive=False)
            if source.info.get("icc_profile"):
                options["icc_profile"] = source.info["icc_profile"]
            raster.save(stream, "JPEG", **options)
            candidate = stream.getvalue()
            if len(candidate) < len(data) or scale < 1:
                output, converted_type = candidate, "image/jpeg"
        with Image.open(io.BytesIO(output)) as encoded:
            payload_size = list(encoded.size)
        proof = {"version": VERSION, "pillow_version": PILLOW_VERSION, "tier": tier,
                 "original_sha256": source_hash, "payload_sha256": _sha(output),
                 "original_bytes": len(data), "payload_bytes": len(output),
                 "original_dimensions": stored_size, "oriented_dimensions": [width, height],
                 "payload_dimensions": payload_size, "media_type": converted_type,
                 "changed": output != data, "visible_source_fraction": 1.0,
                 "recipe": {"engine": "pillow", "orientation": "exif_transpose",
                            "resample": "LANCZOS", "longest_side": longest,
                            "quality": quality, "subsampling": 2, "optimize": True,
                            "progressive": False, "preserve_icc": True}}
    _CACHE[cache_key] = (output, proof)
    _CACHE_BYTES += len(output)
    while _CACHE_BYTES > _CACHE_LIMIT and _CACHE:
        _, (old, _) = _CACHE.popitem(last=False)
        _CACHE_BYTES -= len(old)
    return output, copy.deepcopy(proof)


def prepare_request(body, *, max_bytes=MAX_REQUEST_BYTES):
    """Measure complete JSON and progressively replace image copies only."""
    slots = list(_slots(body))
    original_payload = serialize(body)
    original_bytes = len(original_payload)
    trials = []
    for tier in range(len(TIERS)):
        result = copy.deepcopy(body)
        proofs = []
        for tokens, path, entry, kind in slots:
            if kind == "url":
                header, content = entry.split(",", 1)
                media_type = header[5:].split(";", 1)[0]
            else:
                content = entry["data"]
                media_type = entry.get("media_type", entry.get("mimeType", entry.get("mime_type")))
            data = base64.b64decode(content, validate=True)
            output, proof = transform_image(data, media_type, tier)
            parent = result
            for token in tokens[:-1]:
                parent = parent[token]
            encoded = base64.b64encode(output).decode("ascii")
            if kind == "url":
                parent[tokens[-1]] = f"data:{proof['media_type']};base64,{encoded}"
            else:
                replacement = {**entry, "data": encoded}
                mime_key = "media_type" if kind == "source" else "mimeType" if "mimeType" in entry else "mime_type"
                replacement[mime_key] = proof["media_type"]
                parent[tokens[-1]] = replacement
            proofs.append({"json_path": path, **proof})
        payload = serialize(result)
        trials.append({"tier": tier, "request_bytes": len(payload)})
        if len(payload) <= max_bytes:
            return result, {"version": VERSION, "original_request_bytes": original_bytes,
                            "original_request_sha256": _sha(original_payload),
                            "request_bytes": len(payload), "request_sha256": _sha(payload),
                            "max_request_bytes": max_bytes, "max_image_side": MAX_IMAGE_SIDE,
                            "tier": tier, "trials": trials, "images": proofs}
        if not slots:
            break
    raise ImageTransportLimitError(
        f"Complete JSON still exceeds {max_bytes} bytes after image-only optimization; "
        "text History is preserved and no HTTP request was sent")
