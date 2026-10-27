"""Offline image identity proofs. Never execute a captured Agent command.

Candidate discovery is not evidence: credit requires a full-frame deterministic
replay, or a source-bound, unique full-raster verification. Every proof records
the original and transmitted byte hashes and the exact visible rectangle.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import subprocess
from functools import lru_cache
from collections import OrderedDict
from pathlib import Path

from PIL import Image, ImageChops, ImageCms, ImageOps, ImageStat, JpegImagePlugin

VERSION = "camact.image_provenance.v1"
RESAMPLERS = (Image.Resampling.LANCZOS, Image.Resampling.BICUBIC,
              Image.Resampling.BILINEAR, Image.Resampling.BOX,
              Image.Resampling.NEAREST, Image.Resampling.HAMMING)
_PROOFS = OrderedDict()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def _key(path):
    stat = path.stat()
    return str(path.resolve()), stat.st_size, stat.st_mtime_ns


@lru_cache(maxsize=10000)
def source_hash(key):
    return digest(Path(key[0]).read_bytes())


@lru_cache(maxsize=10000)
def signature(key):
    with Image.open(key[0]) as image:
        if getattr(image, "n_frames", 1) != 1:
            return None
        image = ImageOps.exif_transpose(image).convert("RGB")
        return image.size, image.resize((24, 24), Image.Resampling.BOX).tobytes()


@lru_cache(maxsize=10000)
def candidate_signatures(key):
    """Discover native stored/oriented and ICC-normalized candidates only.

    Native readers may retain the stored orientation or normalize a camera
    profile into sRGB. These thumbnails propose sources; newly discovered
    sources still require an exact encoded-payload replay below.
    """
    with Image.open(key[0]) as image:
        if getattr(image, "n_frames", 1) != 1:
            return ()
        profile = image.info.get("icc_profile")
        rows = []
        for oriented in (image, ImageOps.exif_transpose(image)):
            thumbnail = oriented.convert("RGB").resize((24, 24), Image.Resampling.BOX)
            rows.append((oriented.size, thumbnail.tobytes()))
            if profile:
                try:
                    normalized = ImageCms.profileToProfile(thumbnail,
                        ImageCms.ImageCmsProfile(io.BytesIO(profile)),
                        ImageCms.createProfile("sRGB"), outputMode="RGB")
                    rows.append((oriented.size, normalized.tobytes()))
                except (OSError, ValueError, ImageCms.PyCMSError):
                    pass
        return tuple(dict.fromkeys(rows))


def _difference(left, right):
    return ImageStat.Stat(ImageChops.difference(left, right))


def _same_aspect(source, target):
    # Only integer-rounding error, never a crop or an arbitrary stretch.
    return abs(source[0] * target[1] - target[0] * source[1]) <= max(source)


def _jpeg_options(image):
    if image.format != "JPEG":
        return None
    return {"qtables": image.quantization,
            "subsampling": JpegImagePlugin.get_sampling(image)}


def _pillow_replay(source, target, data, jpeg):
    for orientation, image in (("stored", source), ("exif_transpose", ImageOps.exif_transpose(source))):
        if not _same_aspect(image.size, target.size):
            continue
        for sampler in RESAMPLERS:
            for gap in (None, 2.0, 3.0):
                resized = image.convert("RGB").resize(target.size, sampler, reducing_gap=gap)
                if resized.tobytes() == target.tobytes():
                    return {"engine": "pillow", "orientation": orientation,
                            "resample": sampler.name, "reducing_gap": gap,
                            "verification": "decoded_pixels_exact"}
                if jpeg:
                    out = io.BytesIO()
                    resized.save(out, "JPEG", **jpeg)
                    encoded = out.getvalue()
                    with Image.open(io.BytesIO(encoded)) as restored:
                        exact = restored.convert("RGB").tobytes() == target.tobytes()
                    if exact:
                        return {"engine": "pillow", "orientation": orientation,
                                "resample": sampler.name, "reducing_gap": gap,
                                "jpeg": jpeg, "replayed_sha256": digest(encoded),
                                "verification": "encoded_sha256_exact" if encoded == data else "decoded_pixels_exact"}
    return None


def _sharp_replay(path, target, data):
    """Replay pinned native Sharp pipelines in a fixed helper, with no shell."""
    project = Path(os.environ.get("CAMACT_PROVENANCE_PROJECT_ROOT") or
                   Path(__file__).resolve().parents[2])
    node = project / ".tools/node/bin/node"
    sharp = project / ".tools/deepseek/node_modules/sharp"
    if not node.is_file() or not sharp.is_dir():
        return None
    helper = Path(__file__).with_name("visual_replay.cjs")
    value = {"source": str(path), "sharp": str(sharp), "size": list(target.size),
             "target_sha256": digest(data)}
    rastermill = project / '.tools/openclaw/node_modules/openclaw/node_modules/rastermill/dist/index.js'
    if rastermill.is_file():
        value['rastermill'] = str(rastermill)
    try:
        result = subprocess.run([str(node), str(helper)], input=json.dumps(value),
                                text=True, capture_output=True, timeout=45, check=True)
        return json.loads(result.stdout)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _full_raster_bound(source, target):
    """Strict fallback for native encoders unavailable as a replay library.

    Requires independent trusted tool-source binding, unique album identity,
    full aspect ratio, every spatial block, low codec residual, and texture.
    A perceptual hash or a nearest-neighbour match never earns credit.
    """
    image = ImageOps.exif_transpose(source).convert("RGB")
    if not _same_aspect(image.size, target.size) or min(target.size) < 128:
        return None
    if max(ImageStat.Stat(image.resize((64, 64))).stddev) < 12:
        return None
    best = None
    for sampler in RESAMPLERS[:3]:
        expected = image.resize(target.size, sampler)
        stat = _difference(expected, target)
        mean = sum(stat.mean) / 3
        if mean > 3 or max(stat.rms) > 8:
            continue
        # All 64 blocks must agree, including all four edges and corners.
        worst = 0
        for y in range(8):
            for x in range(8):
                box = (x * target.width // 8, y * target.height // 8,
                       (x + 1) * target.width // 8, (y + 1) * target.height // 8)
                worst = max(worst, max(_difference(expected.crop(box), target.crop(box)).mean))
        if worst > 5:
            continue
        # A second independent low-frequency comparison rejects overlays,
        # missing regions and wrong images with similar global appearance.
        small = _difference(expected.resize((32, 32), Image.Resampling.BOX),
                            target.resize((32, 32), Image.Resampling.BOX))
        if max(small.mean) > 1.5 or max(small.extrema[c][1] for c in range(3)) > 12:
            continue
        row = {"engine": "source_bound_full_raster", "orientation": "exif_transpose",
               "resample": sampler.name, "mean_absolute_error": mean,
               "channel_rms": stat.rms, "worst_block_channel_mae": worst,
               "low_frequency_channel_mae": small.mean,
               "verification": "unique_source_bound_full_frame_codec_residual"}
        if best is None or mean < best["mean_absolute_error"]:
            best = row
    return best


def _reencoded_full_raster(source, target, jpeg):
    if not jpeg or not _same_aspect(ImageOps.exif_transpose(source).size, target.size):
        return None
    for sampler in RESAMPLERS[:3]:
        expected = ImageOps.exif_transpose(source).convert('RGB').resize(target.size, sampler)
        stream = io.BytesIO()
        expected.save(stream, 'JPEG', **jpeg)
        with Image.open(io.BytesIO(stream.getvalue())) as reconstructed:
            proof = _full_raster_bound(reconstructed, target)
        if proof:
            proof.update(engine='source_bound_reencoded_full_raster',
                         source_resample=sampler.name, jpeg=jpeg,
                         replayed_sha256=digest(stream.getvalue()))
            return proof
    return None


@lru_cache(maxsize=2048)
def _dct_tile(key, thumb):
    """Reimplement the captured libjpeg grid recipe; never compile Agent C."""
    with Image.open(key[0]) as image:
        width, height = image.size
        denom = 1
        while max(width, height) // (denom * 2) >= thumb and denom < 8:
            denom *= 2
        image.draft("RGB", (max(1, width // denom), max(1, height // denom)))
        image = image.convert("RGB")
        width, height = image.size
        tw, th = thumb, thumb * height // width
        if th > thumb:
            th, tw = thumb, thumb * width // height
        pixels = image.load()
        # The historical C loop overwrote a target row until its last scanline.
        data = [pixels[x * width // tw, min(height - 1, ((y + 1) * height + th - 1) // th - 1)]
                for y in range(th) for x in range(tw)]
        tile = Image.new("RGB", (tw, th))
        tile.putdata(data)
        return tile


def collage_recipes(requests):
    recipes = []
    for request in requests:
        if not request.get("success"):
            continue
        for tool in request["response"]["tools"]:
            args = tool.get("input")
            command = args.get("command", args.get("cmd", "")) if isinstance(args, dict) else ""
            if all(token in command for token in ("cinfo.scale_denom=scale_denom", "cellw=thumb+6",
                                                   "memset(canvas,30", "jpeg_set_quality(&c,80")):
                recipes.append({"kind": "libjpeg_dct_grid_v1", "command_sha256": digest(command.encode()),
                                "producer_request_id": request["id"], "native_tool_id": tool.get("id")})
    return recipes


class ImageProvenance:
    def __init__(self, originals, recipes=(), required=None):
        self.originals = originals
        self.keys = {name: _key(path) for name, path in originals.items()}
        self.hashes = {}
        for name, key in self.keys.items():
            self.hashes.setdefault(source_hash(key), []).append(name)
        self.cache = {}
        self.recipes = recipes
        self.album_key = tuple(sorted(self.keys.items()))
        self.required = required

    def _legacy_candidates(self, target):
        thumb = target.resize((24, 24), Image.Resampling.BOX)
        found = []
        for name, key in self.keys.items():
            facts = signature(key)
            if facts is None or not _same_aspect(facts[0], target.size):
                continue
            other = Image.frombytes("RGB", (24, 24), facts[1])
            error = max(_difference(thumb, other).mean)
            if error <= 5:
                found.append((error, name))
        return [name for _, name in sorted(found)]

    def candidates(self, target):
        thumb = target.resize((24, 24), Image.Resampling.BOX)
        found = []
        for name, key in self.keys.items():
            errors = [max(_difference(thumb, Image.frombytes("RGB", (24, 24), pixels)).mean)
                      for size, pixels in candidate_signatures(key)
                      if _same_aspect(size, target.size)]
            if errors and min(errors) <= 5:
                found.append((min(errors), name))
        return [name for _, name in sorted(found)]

    def resolve(self, data, *, bound_sources=(), native_context=None):
        payload_hash = digest(data)
        key = payload_hash, tuple(sorted(bound_sources)), json.dumps(native_context, sort_keys=True)
        if key in self.cache:
            return copy.deepcopy(self.cache[key])
        shared = (self.album_key, key, json.dumps(self.recipes, sort_keys=True),
                  tuple(sorted(self.required)) if self.required is not None else None)
        if shared in _PROOFS:
            _PROOFS.move_to_end(shared)
            self.cache[key] = _PROOFS[shared]
            return copy.deepcopy(self.cache[key])
        if native_context:
            result = self._native_primary_result(data, bound_sources=set(bound_sources))
        else:
            result = self._resolve(data, bound_sources=set(bound_sources))
        if not result.get("image_ids") and native_context:
            result = self._native_exact(data, native_context, set(bound_sources)) or result
        self.cache[key] = result
        _PROOFS[shared] = result
        if len(_PROOFS) > 2048:
            _PROOFS.popitem(last=False)
        return copy.deepcopy(result)

    def _native_primary_result(self, data, *, bound_sources):
        """Memoize only the context-free legacy result for native requests."""
        key = (digest(data), tuple(sorted(bound_sources)), self.album_key,
               json.dumps(self.recipes, sort_keys=True),
               tuple(sorted(self.required)) if self.required is not None else None)
        cache = self.__dict__.setdefault('_native_primary_cache', OrderedDict())
        if key not in cache:
            cache[key] = self._resolve(data, bound_sources=bound_sources)
            if len(cache) > 2048:
                cache.popitem(last=False)
        cache.move_to_end(key)
        return copy.deepcopy(cache[key])

    def _native_exact(self, data, context, bound_sources):
        from .visual_native_exact import replay_source, replay_sources
        payload_hash = digest(data)
        with Image.open(io.BytesIO(data)) as encoded:
            target = encoded.convert("RGB")
        # A runner-verified exact tool path identifies the actual input, without
        # a thumbnail inference. Otherwise every album source must be tested.
        candidates = sorted(bound_sources if bound_sources else self.originals)
        if len(bound_sources) > 1:
            return {"image_ids": [], "identity_route": "unresolved",
                    "provenance_reason": "image_provenance_ambiguous"}
        if self.required is not None and not set(candidates) & self.required:
            return None
        proofs = []
        if bound_sources:
            replays = [replay_source(self.originals[name], target.size, payload_hash, context)
                       for name in candidates]
        else:
            replays = replay_sources([self.originals[name] for name in candidates],
                                     target.size, payload_hash, context)
        for name, proof in zip(candidates, replays):
            if proof:
                proofs.append((name, proof))
        if len(proofs) != 1:
            return {"image_ids": [], "identity_route": "unresolved",
                    "provenance_reason": "image_provenance_ambiguous" if proofs else "image_provenance_unresolved",
                    "candidate_image_ids": [name for name, _ in proofs]}
        name, proof = proofs[0]
        return {"image_ids": [name], "identity_route": "verified_full_frame_transform",
                "transformation": {"schema_version": VERSION,
                    "original_sha256": source_hash(self.keys[name]), "payload_sha256": payload_hash,
                    "source_image_id": name, "payload_dimensions": list(target.size),
                    "visible_source_fraction": 1.0, "payload_rectangle": [0, 0, *target.size],
                    "source_binding": ("native_tool_result_current_album_exact" if bound_sources else
                                       "unique_current_album_native_encoded_replay"), **proof}}

    def _resolve(self, data, *, bound_sources):
        payload_hash = digest(data)
        direct = self.hashes.get(payload_hash, [])
        if direct:
            return {"image_ids": direct if len(direct) == 1 else [],
                    "identity_route": "byte_identical" if len(direct) == 1 else "unresolved",
                    "provenance_reason": None if len(direct) == 1 else "image_provenance_ambiguous",
                    "candidate_image_ids": direct}
        with Image.open(io.BytesIO(data)) as encoded:
            jpeg = _jpeg_options(encoded)
            target = encoded.convert("RGB")
        if self.required is not None and bound_sources and not bound_sources & self.required:
            return {"image_ids": [], "identity_route": "unresolved",
                    "provenance_reason": "outside_current_check_scope"}
        legacy_candidates = set(self._legacy_candidates(target))
        candidates = self.candidates(target)
        if self.required is not None and not set(candidates) & self.required:
            composite = self._composite(data, target)
            return composite or {"image_ids": [], "identity_route": "unresolved",
                                  "provenance_reason": "outside_current_check_scope_or_unresolved"}
        proofs = []
        for name in candidates:
            path = self.originals[name]
            exact_only = name not in legacy_candidates
            with Image.open(path) as source:
                # A bound native conversion can be replayed directly. Avoid
                # dozens of full-size generic encoder attempts before it.
                proof = _sharp_replay(path, target, data) if name in bound_sources else None
                if proof is None:
                    proof = _pillow_replay(source, target, data, jpeg)
                if proof is None and name not in bound_sources:
                    # Native tools may read an Agent-created copy under /tmp.
                    # The pinned fixed pipeline needs no filename claim when
                    # it reproduces every transmitted encoded byte exactly.
                    exact = _sharp_replay(path, target, data)
                    if (exact and exact.get('verification') == 'encoded_sha256_exact'
                            and exact.get('replayed_sha256') == payload_hash):
                        proof = exact
                if proof is None and name in bound_sources and not exact_only:
                    proof = _full_raster_bound(source, target)
                if proof is None and name in bound_sources and jpeg and not exact_only:
                    # Verify against the transmitted JPEG's exact quantization
                    # and chroma layout as a reproducible native encoding stage.
                    # Use the same strict residual criteria after that stage.
                    proof = _reencoded_full_raster(source, target, jpeg)
                if exact_only and (not proof or
                        proof.get('verification') != 'encoded_sha256_exact' or
                        proof.get('replayed_sha256') != payload_hash):
                    proof = None
                if proof:
                    proofs.append((name, proof))
        # A second source compatible with the full raster is ambiguity even
        # when the tool's filename names only one of them.
        if len(proofs) == 1:
            name, proof = proofs[0]
            for other in candidates:
                if other == name:
                    continue
                with Image.open(self.originals[other]) as source:
                    if (_full_raster_bound(source, target) or
                            _reencoded_full_raster(source, target, jpeg)):
                        proofs.append((other, {"verification": "ambiguous_full_raster"}))
        if len(proofs) != 1:
            if not proofs:
                composite = self._composite(data, target)
                if composite:
                    return composite
            return {"image_ids": [], "identity_route": "unresolved",
                    "provenance_reason": "image_provenance_ambiguous" if len(proofs) > 1 else "image_provenance_unresolved",
                    "candidate_image_ids": [name for name, _ in proofs]}
        name, proof = proofs[0]
        return {"image_ids": [name], "identity_route": "verified_full_frame_transform",
                "transformation": {"schema_version": VERSION,
                    "original_sha256": source_hash(self.keys[name]), "payload_sha256": payload_hash,
                    "source_image_id": name, "payload_dimensions": list(target.size),
                    "visible_source_fraction": 1.0, "payload_rectangle": [0, 0, *target.size],
                    "source_binding": "native_tool_result" if name in bound_sources else "deterministic_pixel_replay",
                    **proof}}

    def _composite(self, data, target):
        if not self.recipes:
            return None
        # Only a captured supported recipe enables this search. Geometry alone
        # or visually similar tiles can never certify a composite.
        for thumb in (240, 256, 200, 320, 300, 180):
            cell = thumb + 6
            if target.width % cell or target.height % cell:
                continue
            cols, rows = target.width // cell, target.height // cell
            if not (1 <= cols <= 12 and 1 <= rows <= 20):
                continue
            backgrounds = Image.new("RGB", (cell, cell), (30, 30, 30))
            catalog = []
            for name, key in self.keys.items():
                try:
                    tile = _dct_tile(key, thumb)
                except (ValueError, OSError):
                    continue
                placed = backgrounds.copy()
                placed.paste(tile, (3, 3))
                catalog.append((name, tile, placed.resize((24, 24), Image.Resampling.BOX)))
            canvas = Image.new("RGB", target.size, (30, 30, 30))
            members = []
            alternatives = []
            for y in range(rows):
                for x in range(cols):
                    crop = target.crop((x * cell, y * cell, (x + 1) * cell, (y + 1) * cell))
                    small = crop.resize((24, 24), Image.Resampling.BOX)
                    if max(_difference(small, backgrounds.resize((24, 24))).mean) < .1:
                        continue
                    found = [(max(_difference(small, sig).mean), name, tile)
                             for name, tile, sig in catalog]
                    found.sort(key=lambda row: row[0])
                    if not found or found[0][0] > 5:
                        return None
                    _, name, tile = found[0]
                    if len(self.hashes.get(source_hash(self.keys[name]), [])) != 1:
                        return None
                    canvas.paste(tile, (x * cell + 3, y * cell + 3))
                    alternatives.append(((x * cell + 3, y * cell + 3), name,
                                         [(other, other_tile) for error, other, other_tile in found[1:]
                                          if error <= 5]))
                    members.append({"image_id": name, "original_sha256": source_hash(self.keys[name]),
                                    "payload_rectangle": [x * cell + 3, y * cell + 3,
                                                          x * cell + 3 + tile.width, y * cell + 3 + tile.height],
                                    "visible_source_fraction": 1.0})
            encoded = io.BytesIO()
            canvas.save(encoded, "JPEG", quality=80, subsampling=2)
            if encoded.getvalue() != data:
                continue
            # Distinct originals can become identical after downsampling or
            # JPEG quantization. A matching full canvas must also be unique.
            for position, name, others in alternatives:
                for other, tile in others:
                    alternate = canvas.copy()
                    alternate.paste((30, 30, 30), (*position, position[0] + thumb, position[1] + thumb))
                    alternate.paste(tile, position)
                    stream = io.BytesIO()
                    alternate.save(stream, 'JPEG', quality=80, subsampling=2)
                    if stream.getvalue() == data:
                        return {'image_ids': [], 'identity_route': 'unresolved',
                                'provenance_reason': 'image_provenance_ambiguous',
                                'candidate_image_ids': [name, other]}
            return {"image_ids": sorted({row["image_id"] for row in members}),
                    "identity_route": "verified_composite",
                    "transformation": {"schema_version": VERSION, "recipe": self.recipes[0],
                        "verification": "encoded_sha256_exact", "payload_sha256": digest(data),
                        "replayed_sha256": digest(encoded.getvalue()), "columns": cols,
                        "thumb": thumb, "members": members}}
        return None
