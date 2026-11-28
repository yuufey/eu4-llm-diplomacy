"""Read a bounded, read-only political map snapshot from an EU4 save.

The save supplies the calendar date, country tags, and per-province owner,
controller and discovery records.  It does not normally contain map colours.
Callers can therefore pass a separately loaded ``country_colors`` map when
rendering.  Missing ``discovered_by`` is retained as ``None`` and is not
interpreted as an empty discovery list.

This module deliberately works on the serialized save.  It never starts the
game and it does not claim that a saved discovery list is the current UI view.
Text saves and ZIP saves containing a ``gamestate`` member are supported by
the bounded tokenizer already used by the information inspectors.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
from typing import Any, Iterable, Mapping
import zipfile

from work.inspect_diplomacy_save import (
    BoundedReader,
    MAX_STREAM,
    SaveError,
    _zip_directory_guard,
    events,
    open_gamestate,
)


TAG_RE = re.compile(r"[A-Z0-9-]{3}\Z")
DATE_RE = re.compile(r"\d{1,4}\.\d{1,2}\.\d{1,2}\Z")
MAX_PROVINCES = 65535
MAX_COUNTRIES = 4096


class MapSnapshotError(ValueError):
    """Raised when a save cannot yield an unambiguous map snapshot."""


def _token_text(token: tuple[Any, ...]) -> str:
    raw = token[1].decode("latin-1")
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        return raw[1:-1]
    return raw


def _province_id(key: str) -> int | None:
    try:
        value = int(key, 10)
    except (TypeError, ValueError):
        return None
    value = abs(value)
    return value if 1 <= value <= MAX_PROVINCES else None


def _tag(value: str) -> str | None:
    if TAG_RE.fullmatch(value) is None or value == "---":
        return None
    return value


def _normalise_colors(colors: Mapping[str, Iterable[int]] | None) -> dict[str, list[int]]:
    if colors is None:
        return {}
    if not isinstance(colors, Mapping) or len(colors) > MAX_COUNTRIES:
        raise MapSnapshotError("country_colors must be a bounded mapping")
    result: dict[str, list[int]] = {}
    for country, value in colors.items():
        if not isinstance(country, str) or TAG_RE.fullmatch(country) is None or country == "---":
            raise MapSnapshotError("country_colors contains an invalid country tag")
        try:
            rgb = list(value)
        except TypeError as exc:
            raise MapSnapshotError("country_colors values must contain three channels") from exc
        if (len(rgb) != 3 or any(type(channel) is not int or not 0 <= channel <= 255 for channel in rgb)):
            raise MapSnapshotError("country_colors channels must be integers from 0 through 255")
        result[country] = rgb
    return result


def _source_hash(path: Path) -> tuple[dict[str, Any], tuple[int, int, int]]:
    before = path.stat()
    if not path.is_file() or before.st_size > MAX_STREAM:
        raise MapSnapshotError("save is not a regular file or exceeds input size budget")
    identity = (before.st_size, before.st_mtime_ns, before.st_ino)
    return ({"path": str(path), "size_bytes": before.st_size,
             "mtime_ns": before.st_mtime_ns, "sha256": None,
             "format": "unknown"}, identity)


def _physical_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        total = 0
        while chunk := source.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_STREAM:
                raise MapSnapshotError("save exceeds input size budget while hashing")
            digest.update(chunk)
    return digest.hexdigest()


def _zip_meta(path: Path) -> tuple[str | None, str | None]:
    """Read the small ZIP ``meta`` member for fields omitted from gamestate."""

    with path.open("rb") as source:
        _zip_directory_guard(source, path.stat().st_size)
        with zipfile.ZipFile(source, "r") as archive:
            members = [info for info in archive.infolist() if info.filename == "meta"]
            if len(members) != 1:
                raise MapSnapshotError("ZIP must contain exactly one meta member")
            member = members[0]
            if member.flag_bits & 1 or member.file_size > 4 * 1024 * 1024:
                raise MapSnapshotError("encrypted or oversized save meta is unsupported")
            with archive.open(member, "r") as stream:
                reader = BoundedReader(stream)
                date = None
                player = None
                stack: list[str | None] = []
                for event, key, token in events(reader):
                    if event == "scalar" and not stack:
                        value = _token_text(token)
                        if key == "date":
                            date = value
                        elif key == "player":
                            player = _tag(value)
                    if event == "start":
                        stack.append(str(key) if key is not None else None)
                    elif event == "end" and stack:
                        stack.pop()
                return date, player


def parse_map_snapshot(
    path: str | Path,
    observer: str,
    *,
    country_colors: Mapping[str, Iterable[int]] | None = None,
) -> dict[str, Any]:
    """Parse one save and return a dated province ownership and control snapshot.

    ``observer`` controls only the convenience ``visible_provinces`` list.
    Every row still retains its full serialized ``discovered_by`` value, so a
    caller can choose another observer without reparsing the saved data.
    """

    if not isinstance(observer, str) or TAG_RE.fullmatch(observer) is None or observer == "---":
        raise MapSnapshotError("observer must be a three-character country tag")
    path = Path(path).expanduser().resolve(strict=True)
    source, identity = _source_hash(path)
    colors = _normalise_colors(country_colors)

    date: str | None = None
    player: str | None = None
    country_tags: set[str] = set()
    provinces: dict[int, dict[str, Any]] = {}
    path_stack: list[str | None] = []
    current: dict[str, Any] | None = None
    discovery: list[str] | None = None
    discovery_present = False

    try:
        with open_gamestate(path) as (reader, encoding):
            for event, key, token in events(reader):
                text = _token_text(token) if token is not None else ""
                if event == "start":
                    if not path_stack and key == "countries":
                        path_stack.append(key)
                        continue
                    if path_stack == ["countries"] and key is not None:
                        tag = _tag(str(key))
                        if tag is not None:
                            country_tags.add(tag)
                            if len(country_tags) > MAX_COUNTRIES:
                                raise MapSnapshotError("country tag count exceeds bound")
                        path_stack.append(str(key))
                        continue
                    if path_stack == ["provinces"] and key is not None:
                        pid = _province_id(str(key))
                        if pid is None:
                            # EU4 uses a few non-province entries only outside
                            # this map.  A malformed numeric key is safer to
                            # reject than to silently draw at the wrong place.
                            if str(key).lstrip("-").isdigit():
                                raise MapSnapshotError(f"invalid province key: {key}")
                        elif pid in provinces:
                            raise MapSnapshotError(f"duplicate province id: {pid}")
                        current = {"province_id": pid, "owner": None, "controller": None,
                                   "discovered_by": None, "owner_present": False,
                                   "controller_present": False}
                        path_stack.append(str(key))
                        continue
                    if current is not None and len(path_stack) == 2 and key == "discovered_by":
                        discovery = []
                        discovery_present = True
                    path_stack.append(str(key) if key is not None else None)
                    continue

                if event == "scalar":
                    if not path_stack:
                        if key == "date":
                            if date is not None:
                                raise MapSnapshotError("duplicate root date field")
                            date = text
                        elif key == "player":
                            if player is not None:
                                raise MapSnapshotError("duplicate root player field")
                            player = _tag(text)
                    elif current is not None and len(path_stack) == 2 and path_stack[0] == "provinces":
                        if key in ("owner", "controller"):
                            value = _tag(text)
                            current[key] = value
                            current[f"{key}_present"] = True
                    continue

                if event == "bare":
                    if (current is not None and discovery_present and path_stack[-1:] == ["discovered_by"]):
                        tag = _tag(text)
                        if tag is not None:
                            if tag not in discovery:
                                discovery.append(tag)
                    continue

                if event != "end":
                    continue
                if path_stack and path_stack[-1] == "discovered_by":
                    if current is not None and discovery_present:
                        current["discovered_by"] = sorted(discovery or [])
                    discovery = None
                    discovery_present = False
                if (current is not None and len(path_stack) == 2 and path_stack[0] == "provinces"):
                    pid = current["province_id"]
                    if pid is not None:
                        provinces[pid] = current
                    current = None
                if path_stack:
                    path_stack.pop()
            gamestate_sha = reader.sha256.hexdigest()
            gamestate_size = reader.count
    except (SaveError, OSError, ValueError) as exc:
        if isinstance(exc, MapSnapshotError):
            raise
        raise MapSnapshotError(f"map snapshot parse failed: {exc}") from exc

    after = path.stat()
    if (after.st_size, after.st_mtime_ns, after.st_ino) != identity:
        raise MapSnapshotError("save changed during map snapshot parse")
    source["format"] = encoding
    source["gamestate_bytes"] = gamestate_size
    source["gamestate_sha256"] = gamestate_sha
    if encoding == "plain_text":
        # The streaming reader covered the complete source, so this is also
        # the physical file hash and avoids a second pass in the common case.
        source["sha256"] = gamestate_sha
    else:
        source["sha256"] = _physical_hash(path)

    if encoding == "zip_gamestate" and (date is None or player is None):
        meta_date, meta_player = _zip_meta(path)
        if date is None:
            date = meta_date
        if player is None:
            player = meta_player

    if date is None or DATE_RE.fullmatch(date) is None:
        raise MapSnapshotError("save date is absent or malformed")
    if player is None:
        raise MapSnapshotError("save player is absent or malformed")
    if observer not in country_tags:
        # Observer saves sometimes use O00 as a physical observer while the
        # logical player is another country.  Keep the rows usable and make
        # this condition visible in the result rather than rejecting them.
        observer_in_country_list = False
    else:
        observer_in_country_list = True

    rows = [provinces[pid] for pid in sorted(provinces)]
    visible = [row["province_id"] for row in rows
               if row["discovered_by"] is not None and observer in row["discovered_by"]]
    return {
        "schema": "eu4.map_snapshot.v1",
        "schema_version": 1,
        "mode": "recorded",
        "observer": observer,
        "observer_in_country_list": observer_in_country_list,
        "date": date,
        "player": player,
        "country_tags": sorted(country_tags),
        "country_colors": colors,
        "provinces": rows,
        "visible_provinces": visible,
        "source": source,
        "limitations": [
            "owner, controller and discovered_by are serialized save fields",
            "discovered_by does not prove current UI visibility",
            "country_colors are supplied static data and are absent unless the caller provides them",
        ],
    }


class SavedMapSnapshot:
    """Pin a save and expose the parsed map snapshot with file revalidation."""

    def __init__(self, path: str | Path, observer: str, *, country_colors: Mapping[str, Iterable[int]] | None = None):
        self.path = Path(path).expanduser().resolve(strict=True)
        self.observer = observer
        self.country_colors = _normalise_colors(country_colors)
        self._data = parse_map_snapshot(self.path, observer, country_colors=self.country_colors)
        self._identity = (self._data["source"]["size_bytes"],
                          self._data["source"]["mtime_ns"], self.path.stat().st_ino)

    def _assert_unchanged(self) -> None:
        stat = self.path.stat()
        if (stat.st_size, stat.st_mtime_ns, stat.st_ino) != self._identity:
            raise MapSnapshotError("save changed after map snapshot construction")

    def as_dict(self) -> dict[str, Any]:
        self._assert_unchanged()
        return deepcopy(self._data)

    snapshot = as_dict

    def context(self) -> dict[str, Any]:
        self._assert_unchanged()
        source = self._data["source"]
        return {
            "mode": "recorded", "status": "recorded", "complete": True,
            "source": "SavedMapSnapshot", "observer": self.observer,
            "game_date": self._data["date"], "game_date_kind": "saved_calendar_date",
            "game_day": None, "world_id": None, "session_id": None,
            "live": False, "path": source["path"], "sha256": source["sha256"],
            "size_bytes": source["size_bytes"], "reasons": [],
        }

    @property
    def date(self) -> str:
        self._assert_unchanged()
        return self._data["date"]

    @property
    def provinces(self) -> list[dict[str, Any]]:
        self._assert_unchanged()
        return deepcopy(self._data["provinces"])


__all__ = ["MapSnapshotError", "SavedMapSnapshot", "parse_map_snapshot"]
