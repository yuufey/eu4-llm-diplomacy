"""Load effective EU4 country colours for political map rendering.

EU4 assigns a country's normal map colour in its ``common/countries``
definition.  ``common/country_tags`` supplies the tag-to-definition mapping.
This module resolves both through the same base-game and enabled-mod layers as
the static map reader.  A saved ``map_color`` value may be supplied explicitly
and takes precedence when a caller has parsed one from an EU4 save.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath
import re
from typing import Any, Iterable, Mapping, Sequence

from tools.build_diplomacy_catalog import parse_script

from .information.strait_definitions import StraitDefinitionIndex


MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_TAG_FILES = 4096
MAX_COUNTRY_DEFINITIONS = 4096
TAG_RE = re.compile(r"[A-Z0-9-]{3}\Z")
INTEGER_RE = re.compile(r"[0-9]+\Z", re.ASCII)
COLOR_RE = re.compile(
    r"(?m)^\s*(?:color|map_color)\s*=\s*\{\s*"
    r"([0-9]+)\s+([0-9]+)\s+([0-9]+)\s*\}"
)


class MapColorError(ValueError):
    """Raised when effective country colour definitions are unusable."""


@dataclass(frozen=True)
class CountryColor:
    """One country tag's RGB map colour and its static source files."""

    tag: str
    rgb: tuple[int, int, int]
    source: str
    country_definition: str | None = None
    tag_definition: str | None = None


@dataclass
class CountryColorIndex:
    """Resolved country colours and provenance for one map configuration."""

    entries: Mapping[str, CountryColor]
    source_files: Mapping[str, dict[str, Any]]
    diagnostics: tuple[dict[str, str], ...] = ()

    @property
    def colors(self) -> dict[str, tuple[int, int, int]]:
        return {tag: entry.rgb for tag, entry in self.entries.items()}

    def lookup(self, tag: str) -> CountryColor | None:
        return self.entries.get(tag)

    def context(self) -> dict[str, Any]:
        return {
            "status": "ready" if not self.diagnostics else "ready_with_diagnostics",
            "country_count": len(self.entries),
            "source_files": {key: dict(value) for key, value in self.source_files.items()},
            "diagnostics": [dict(item) for item in self.diagnostics],
        }


def _read_bounded(path: Path, limit: int = MAX_FILE_BYTES) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise MapColorError(f"country colour input unavailable: {path}") from exc
    if size < 1 or size > limit:
        raise MapColorError(f"country colour input size out of range: {path}")
    try:
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
    except OSError as exc:
        raise MapColorError(f"country colour input unavailable: {path}") from exc
    if len(raw) != size or len(raw) > limit:
        raise MapColorError(f"country colour input changed while reading: {path}")
    return raw


def _record(path: Path, raw: bytes, *, relative: str) -> dict[str, Any]:
    return {
        "relative": relative,
        "path": str(path),
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _decode(raw: bytes) -> str:
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            return raw.decode("cp1252", errors="replace")
        except UnicodeDecodeError as exc:
            raise MapColorError("country definition encoding is unsupported") from exc


def _safe_relative(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MapColorError("country tag path is missing")
    text = value.strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    if text.startswith("/") or re.match(r"^[A-Za-z]:", text):
        raise MapColorError(f"absolute country path is not allowed: {value!r}")
    parts = text.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise MapColorError(f"invalid country path: {value!r}")
    if text.casefold().startswith("common/"):
        return PurePosixPath(text).as_posix()
    if text.casefold().startswith("countries/"):
        return PurePosixPath("common", text).as_posix()
    return PurePosixPath("common", "countries", text).as_posix()


def _tag_file_candidates(index: StraitDefinitionIndex) -> list[str]:
    """Return all effective country-tag file paths in deterministic order."""

    candidates: set[str] = set()
    for layer in index._state.layers:
        directory = Path(layer.root) / "common" / "country_tags"
        if not directory.is_dir():
            continue
        for path in directory.rglob("*.txt"):
            if not path.is_file():
                continue
            try:
                relative = PurePosixPath(
                    "common", "country_tags", path.relative_to(directory).as_posix()
                ).as_posix()
            except ValueError as exc:
                raise MapColorError(f"country tag path escapes layer: {path}") from exc
            candidates.add(relative)
            if len(candidates) > MAX_TAG_FILES:
                raise MapColorError("country tag file count exceeds bound")
    return sorted(candidates, key=str.casefold)


def _literal_values(node: Any) -> list[str]:
    children = getattr(node, "children", None) or []
    if not children:
        value = getattr(node, "value", None)
        return [str(value)] if value is not None else []
    values: list[str] = []
    for child in children:
        value = getattr(child, "value", None)
        if value is None:
            value = getattr(child, "key", None)
        if value is not None:
            values.append(str(value))
    return values


def _parse_tag_file(raw: bytes, source_relative: str) -> dict[str, str]:
    try:
        nodes = parse_script(_decode(raw))
    except Exception as exc:
        raise MapColorError(f"country tag file cannot be parsed: {source_relative}") from exc
    result: dict[str, str] = {}
    for node in nodes:
        tag = getattr(node, "key", None)
        value = getattr(node, "value", None)
        if not isinstance(tag, str) or TAG_RE.fullmatch(tag) is None or not isinstance(value, str):
            continue
        result[tag] = _safe_relative(value)
    return result


def _parse_color(raw: bytes, source_relative: str) -> tuple[int, int, int] | None:
    text = _decode(raw)
    match = COLOR_RE.search(text)
    if match is None:
        return None
    rgb = tuple(int(match.group(index), 10) for index in (1, 2, 3))
    if any(value < 0 or value > 255 for value in rgb):
        raise MapColorError(f"country colour channel out of range: {source_relative}")
    return rgb


def _normalize_override(overrides: Mapping[str, Iterable[int]] | None) -> dict[str, tuple[int, int, int]]:
    if overrides is None:
        return {}
    if not isinstance(overrides, Mapping):
        raise MapColorError("save_colors must be a mapping")
    result: dict[str, tuple[int, int, int]] = {}
    for tag, value in overrides.items():
        if not isinstance(tag, str) or TAG_RE.fullmatch(tag) is None:
            raise MapColorError(f"invalid country tag in save_colors: {tag!r}")
        try:
            channels = tuple(value)
        except TypeError as exc:
            raise MapColorError(f"invalid save colour for {tag}") from exc
        if len(channels) != 3 or any(type(channel) is not int or not 0 <= channel <= 255 for channel in channels):
            raise MapColorError(f"invalid save colour for {tag}")
        result[tag] = channels
    return result


def _normalize_tags(only_tags: Iterable[str] | None) -> set[str] | None:
    if only_tags is None:
        return None
    if isinstance(only_tags, (str, bytes)):
        raise MapColorError("only_tags must be an iterable of country tags")
    try:
        values = set(only_tags)
    except TypeError as exc:
        raise MapColorError("only_tags must be an iterable of country tags") from exc
    if len(values) > MAX_COUNTRY_DEFINITIONS:
        raise MapColorError("only_tags count exceeds bound")
    if any(not isinstance(tag, str) or TAG_RE.fullmatch(tag) is None for tag in values):
        raise MapColorError("only_tags contains an invalid country tag")
    return values


def load_country_colors(
    game_root: str | Path | None = None,
    user_data: str | Path | None = None,
    enabled_mods: Sequence[str | Path | Mapping[str, Any]] | None = None,
    *,
    save_colors: Mapping[str, Iterable[int]] | None = None,
    only_tags: Iterable[str] | None = None,
) -> CountryColorIndex:
    """Resolve normal country colours, optionally overlaying save ``map_color``.

    ``only_tags`` limits country-definition reads after the effective tag map
    is resolved.  It is useful for a regional renderer that only needs colours
    for countries present in its current viewport.
    """

    requested_tags = _normalize_tags(only_tags)
    index = StraitDefinitionIndex(game_root=game_root, user_data=user_data, enabled_mods=enabled_mods)
    context = index.context()
    if context.get("status") != "ready":
        reasons = context.get("reasons") or []
        detail = reasons[0].get("message") if reasons else "static map source is unavailable"
        raise MapColorError(detail)

    records: dict[str, dict[str, Any]] = {}
    tag_to_path: dict[str, tuple[str, str]] = {}
    total_bytes = 0
    for relative in _tag_file_candidates(index):
        path = index._resolve_file(relative)
        if path is None:
            continue
        raw = _read_bounded(path)
        total_bytes += len(raw)
        if total_bytes > MAX_TOTAL_BYTES:
            raise MapColorError("country colour inputs exceed total size bound")
        tag_file_record = _record(path, raw, relative=relative)
        records[relative.casefold()] = tag_file_record
        for tag, country_relative in _parse_tag_file(raw, relative).items():
            tag_to_path[tag] = (country_relative, relative)

    if len(tag_to_path) > MAX_COUNTRY_DEFINITIONS:
        raise MapColorError("country tag count exceeds bound")

    entries: dict[str, CountryColor] = {}
    diagnostics: list[dict[str, str]] = []
    selected_tags = sorted(
        tag for tag in tag_to_path if requested_tags is None or tag in requested_tags
    )
    for tag in selected_tags:
        country_relative, tag_relative = tag_to_path[tag]
        path = index._resolve_file(country_relative)
        if path is None:
            diagnostics.append({"code": "COUNTRY_DEFINITION_MISSING", "message": f"{tag}:{country_relative}"})
            continue
        raw = _read_bounded(path)
        total_bytes += len(raw)
        if total_bytes > MAX_TOTAL_BYTES:
            raise MapColorError("country colour inputs exceed total size bound")
        country_record = _record(path, raw, relative=country_relative)
        records[country_relative.casefold()] = country_record
        rgb = _parse_color(raw, country_relative)
        if rgb is None:
            diagnostics.append({"code": "COUNTRY_COLOR_MISSING", "message": f"{tag}:{country_relative}"})
            continue
        entries[tag] = CountryColor(tag, rgb, "country_definition", country_relative, tag_relative)

    overrides = _normalize_override(save_colors)
    for tag, rgb in overrides.items():
        if requested_tags is not None and tag not in requested_tags:
            continue
        previous = entries.get(tag)
        entries[tag] = CountryColor(
            tag,
            rgb,
            "save_map_color",
            previous.country_definition if previous else None,
            previous.tag_definition if previous else None,
        )
    return CountryColorIndex(entries=entries, source_files=records, diagnostics=tuple(diagnostics))


__all__ = [
    "CountryColor",
    "CountryColorIndex",
    "MapColorError",
    "load_country_colors",
]
