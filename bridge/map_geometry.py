"""Load the static EU4 province image and its map metadata.

The province image is an identity layer.  Every pixel stores a province
colour, and ``definition.csv`` maps that colour to a numeric province ID.
This module keeps that identity layer separate from ownership and discovery
read from a save or a running game.  It is therefore safe to reuse one
``MapGeometry`` instance while rendering several political snapshots.
"""

from __future__ import annotations

from dataclasses import dataclass
import csv
import hashlib
import io
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Sequence

import numpy as np
from PIL import Image

from tools.build_diplomacy_catalog import parse_script

from .information import static_data as _static
from .information.strait_definitions import StraitDefinitionIndex


MAX_BITMAP_BYTES = 256 * 1024 * 1024
MAX_BITMAP_PIXELS = 100_000_000
MAX_DEFINITION_BYTES = 16 * 1024 * 1024
MAX_DEFINITION_ROWS = 65_536
_INTEGER = re.compile(r"[0-9]+\Z", re.ASCII)


class MapGeometryError(ValueError):
    """Raised when the effective map cannot provide a usable identity layer."""


@dataclass(frozen=True)
class ProvinceDefinition:
    """Static fields from one row of ``definition.csv``."""

    province_id: int
    rgb: tuple[int, int, int]
    name: str | None = None


@dataclass
class MapGeometry:
    """Province identity raster and static province classes.

    ``province_ids[y, x]`` is zero for a pixel that has no valid definition.
    Coordinates use image order, with ``x`` increasing eastward and ``y``
    increasing downward.  The raster is read-only after construction so that
    concurrent renderers cannot accidentally alter the shared identity layer.
    """

    province_ids: np.ndarray
    definitions: Mapping[int, ProvinceDefinition]
    sea_province_ids: frozenset[int]
    lake_province_ids: frozenset[int]
    wasteland_province_ids: frozenset[int]
    source_files: Mapping[str, dict[str, Any]]
    map_width: int
    map_height: int

    def __post_init__(self) -> None:
        if self.province_ids.dtype != np.uint16 or self.province_ids.ndim != 2:
            raise TypeError("province_ids must be a two-dimensional uint16 array")
        if self.province_ids.shape != (self.map_height, self.map_width):
            raise ValueError("map dimensions do not match province_ids")
        self.province_ids.setflags(write=False)

    @property
    def shape(self) -> tuple[int, int]:
        return self.province_ids.shape

    @property
    def province_count(self) -> int:
        return len(self.definitions)

    def province_at(self, x: int, y: int) -> int | None:
        """Return the province ID at an image coordinate, or ``None`` outside."""

        if type(x) is not int or type(y) is not int:
            raise TypeError("x and y must be integers")
        if x < 0 or y < 0 or x >= self.map_width or y >= self.map_height:
            return None
        province_id = int(self.province_ids[y, x])
        return province_id or None

    def kind_for_province(self, province_id: int) -> str:
        """Classify a province using static map lists."""

        if province_id in self.lake_province_ids:
            return "lake"
        if province_id in self.sea_province_ids:
            return "sea"
        if province_id in self.wasteland_province_ids:
            return "wasteland"
        return "land" if province_id in self.definitions else "unknown"

    def metadata_for_province(self, province_id: int) -> dict[str, Any]:
        """Return a compact static record suitable for a renderer or picker."""

        definition = self.definitions.get(province_id)
        return {
            "province_id": province_id,
            "name": definition.name if definition else None,
            "rgb": list(definition.rgb) if definition else None,
            "kind": self.kind_for_province(province_id),
        }

    def context(self) -> dict[str, Any]:
        """Describe the loaded identity layer without serializing the raster."""

        used = self.province_ids != 0
        return {
            "status": "ready",
            "width": self.map_width,
            "height": self.map_height,
            "province_count": len(self.definitions),
            "mapped_pixel_count": int(np.count_nonzero(used)),
            "unmapped_pixel_count": int(used.size - np.count_nonzero(used)),
            "sea_province_count": len(self.sea_province_ids),
            "lake_province_count": len(self.lake_province_ids),
            "wasteland_province_count": len(self.wasteland_province_ids),
            "source_files": {key: dict(value) for key, value in self.source_files.items()},
        }


def _read_bounded(path: Path, limit: int) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise MapGeometryError(f"map input unavailable: {path}") from exc
    if size < 1 or size > limit:
        raise MapGeometryError(f"map input size out of range: {path} ({size} bytes)")
    try:
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
    except OSError as exc:
        raise MapGeometryError(f"map input unavailable: {path}") from exc
    if len(raw) != size or len(raw) > limit:
        raise MapGeometryError(f"map input changed while reading: {path}")
    return raw


def _fingerprint(path: Path, raw: bytes) -> dict[str, Any]:
    return {"path": str(path), "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _relative_map_path(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MapGeometryError("map path is missing")
    text = value.strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    if text.startswith("/") or re.match(r"^[A-Za-z]:", text):
        raise MapGeometryError(f"absolute map path is not allowed: {value!r}")
    if any(part in {"", ".", ".."} for part in text.split("/")):
        raise MapGeometryError(f"invalid map path: {value!r}")
    return text if text.casefold().startswith("map/") else f"map/{text}"


def _node_values(nodes: Iterable[Any], key: str) -> list[Any]:
    values: list[Any] = []
    for node in nodes:
        if getattr(node, "key", None) == key:
            values.append(node)
    return values


def _scalar_map_values(nodes: Iterable[Any], key: str) -> str | None:
    matches = _node_values(nodes, key)
    if not matches:
        return None
    node = matches[-1]
    if getattr(node, "children", None) or getattr(node, "value", None) is None:
        raise MapGeometryError(f"map key {key!r} is not a scalar")
    return str(node.value)


def _integer_list(nodes: Iterable[Any], key: str) -> set[int]:
    result: set[int] = set()
    for node in _node_values(nodes, key):
        children = getattr(node, "children", None) or []
        if not children:
            value = getattr(node, "value", None)
            children = [node] if value is not None else []
        for child in children:
            value = getattr(child, "value", None)
            if value is None:
                value = getattr(child, "key", None)
            if value is None:
                continue
            text = str(value).strip()
            if _INTEGER.fullmatch(text):
                number = int(text, 10)
                if number > 0:
                    result.add(number)
    return result


def _decode_definition(raw: bytes) -> str:
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            return raw.decode("cp1252")
        except UnicodeDecodeError as exc:
            raise MapGeometryError("definition.csv encoding is unsupported") from exc


def _parse_definitions(raw: bytes) -> dict[int, ProvinceDefinition]:
    text = _decode_definition(raw)
    rows = list(csv.reader(text.splitlines(), delimiter=";", strict=True))
    if not rows or not rows[0] or rows[0][0].strip().casefold() != "province":
        raise MapGeometryError("definition.csv has no province header")
    if len(rows) > MAX_DEFINITION_ROWS:
        raise MapGeometryError("definition.csv has too many rows")
    result: dict[int, ProvinceDefinition] = {}
    for row in rows[1:]:
        if not row or not row[0].strip():
            continue
        if len(row) < 4:
            raise MapGeometryError("definition.csv row has fewer than four columns")
        try:
            province_id = int(row[0].strip(), 10)
            rgb = tuple(int(row[index].strip(), 10) for index in (1, 2, 3))
        except (TypeError, ValueError) as exc:
            raise MapGeometryError("definition.csv has an invalid numeric row") from exc
        if province_id < 0 or province_id > 0xFFFF or any(value < 0 or value > 255 for value in rgb):
            raise MapGeometryError(f"definition.csv row is out of range: {province_id}")
        if province_id == 0:
            continue
        if province_id in result:
            raise MapGeometryError(f"duplicate province ID in definition.csv: {province_id}")
        name = row[4].strip() if len(row) > 4 and row[4].strip() else None
        result[province_id] = ProvinceDefinition(province_id, rgb, name)
    if not result:
        raise MapGeometryError("definition.csv has no positive province IDs")
    return result


def _parse_wasteland_ids(raw: bytes) -> set[int]:
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("cp1252", errors="replace")
    return _integer_list(parse_script(text), "impassable")


def _resolve(index: StraitDefinitionIndex, default_nodes: list[Any], key: str) -> Path:
    value = _scalar_map_values(default_nodes, key)
    if value is None:
        raise MapGeometryError(f"default.map does not define {key}")
    relative = _relative_map_path(value)
    path = index._resolve_file(relative)
    if path is None:
        raise MapGeometryError(f"effective map file is missing: {relative}")
    return path


def load_map_geometry(
    game_root: str | Path | None = None,
    user_data: str | Path | None = None,
    enabled_mods: Sequence[str | Path | Mapping[str, Any]] | None = None,
    *,
    max_bitmap_bytes: int = MAX_BITMAP_BYTES,
) -> MapGeometry:
    """Load the effective province bitmap and static province classifications."""

    if type(max_bitmap_bytes) is not int or max_bitmap_bytes <= 0 or max_bitmap_bytes > MAX_BITMAP_BYTES:
        raise ValueError("max_bitmap_bytes must be in 1..256 MiB")
    index = StraitDefinitionIndex(game_root=game_root, user_data=user_data, enabled_mods=enabled_mods)
    context = index.context()
    if context.get("status") != "ready":
        reasons = context.get("reasons") or []
        detail = reasons[0].get("message") if reasons else "static map source is unavailable"
        raise MapGeometryError(detail)
    default_path = index._resolve_file("map/default.map")
    if default_path is None:
        raise MapGeometryError("effective map/default.map is missing")
    default_raw = _read_bounded(default_path, 4 * 1024 * 1024)
    try:
        nodes = parse_script(default_raw.decode("utf-8-sig"))
    except Exception as exc:
        raise MapGeometryError("default.map could not be parsed") from exc

    bitmap_path = _resolve(index, nodes, "provinces")
    definition_path = _resolve(index, nodes, "definitions")
    definitions_raw = _read_bounded(definition_path, MAX_DEFINITION_BYTES)
    definitions = _parse_definitions(definitions_raw)

    bitmap_raw = _read_bounded(bitmap_path, max_bitmap_bytes)
    try:
        with Image.open(io.BytesIO(bitmap_raw)) as image:
            if image.width * image.height > MAX_BITMAP_PIXELS:
                raise MapGeometryError("province bitmap has too many pixels")
            rgb = np.asarray(image.convert("RGB"), dtype=np.uint8)
    except MapGeometryError:
        raise
    except Exception as exc:
        raise MapGeometryError(f"province bitmap could not be decoded: {bitmap_path}") from exc
    if rgb.ndim != 3 or rgb.shape[2] != 3:
        raise MapGeometryError("province bitmap is not RGB")

    packed = (
        (rgb[:, :, 0].astype(np.uint32) << 16)
        | (rgb[:, :, 1].astype(np.uint32) << 8)
        | rgb[:, :, 2].astype(np.uint32)
    )
    lut = np.zeros(1 << 24, dtype=np.uint16)
    for definition in definitions.values():
        red, green, blue = definition.rgb
        lut[(red << 16) | (green << 8) | blue] = definition.province_id
    province_ids = lut[packed]
    province_ids.setflags(write=False)

    sea_ids = _integer_list(nodes, "sea_starts")
    lake_ids = _integer_list(nodes, "lakes")
    climate_path = None
    wasteland_ids: set[int] = set()
    climate_value = _scalar_map_values(nodes, "climate")
    if climate_value:
        climate_path = _resolve(index, nodes, "climate")
        try:
            wasteland_ids = _parse_wasteland_ids(_read_bounded(climate_path, MAX_DEFINITION_BYTES))
        except MapGeometryError:
            raise
        except OSError as exc:
            raise MapGeometryError(f"climate file could not be read: {climate_path}") from exc

    files = {
        "default.map": _fingerprint(default_path, default_raw),
        "provinces.bmp": _fingerprint(bitmap_path, bitmap_raw),
        "definition.csv": _fingerprint(definition_path, definitions_raw),
    }
    if climate_path is not None:
        climate_raw = _read_bounded(climate_path, MAX_DEFINITION_BYTES)
        files["climate.txt"] = _fingerprint(climate_path, climate_raw)
    height, width = province_ids.shape
    return MapGeometry(
        province_ids=province_ids,
        definitions=definitions,
        sea_province_ids=frozenset(sea_ids),
        lake_province_ids=frozenset(lake_ids),
        wasteland_province_ids=frozenset(wasteland_ids),
        source_files=files,
        map_width=width,
        map_height=height,
    )


__all__ = [
    "MAX_BITMAP_BYTES",
    "MAX_BITMAP_PIXELS",
    "MapGeometry",
    "MapGeometryError",
    "ProvinceDefinition",
    "load_map_geometry",
]
