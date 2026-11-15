"""从 EU4 纯文本存档读取目标国家的已保存任务树字段。

``SavedMissionSnapshot`` 面向已经存在的存档文件。它只读取存档中明确写出
的值：``country_missions`` 的 ``mission_slot`` 顺序和根标识、
``completed_missions`` 是否存在及其列表，以及国家块直接包含的 flags。
它不会根据国家标签推算任务树，也不会把缺少 ``completed_missions`` 当成
空列表。返回结果的 ``mode`` 始终是 ``recorded``，不能当作当前游戏会话的
实时状态。

存档按二进制行流式扫描。解析和每次 ``as_dict``/``context`` 调用都会重新
核对文件大小、mtime 和 SHA-256；文件在扫描前后或调用期间改变时，读取
失败关闭。压缩存档、非 ``EU4txt`` 文件、超长行、过深嵌套和超大目标块均
拒绝读取。
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
from typing import Any


COUNTRY_RE = re.compile(r"[A-Z0-9]{3}\Z")
HEX64_RE = re.compile(r"[0-9a-fA-F]{64}\Z")

DEFAULT_MAX_FILE_BYTES = 128 * 1024 * 1024
DEFAULT_MAX_LINE_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_NESTING = 4096
DEFAULT_MAX_TARGET_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_TOKENS = 16_000_000
MAX_LIST_ITEMS = 100_000
MAX_ASSIGNMENTS = 100_000

_TOKEN_RE = re.compile(rb'"(?:\\.|[^"\\])*"|[{}=]|[^\s{}=]+')
_ASSIGNMENT_RE = re.compile(
    rb"^[ \t]*([A-Za-z0-9_.:-]+)[ \t]*=[ \t]*(.*?)[ \t]*$"
)


class SavedMissionSnapshotError(ValueError):
    """Raised when a save cannot be read as an unambiguous snapshot."""


@dataclass
class _LexState:
    in_quote: bool = False
    escaped: bool = False


@dataclass
class _RawBlock:
    key: str
    start_line: int
    depth: int
    max_bytes: int
    lines: list[bytes] = field(default_factory=list)
    byte_count: int = 0
    tokens: list[str] = field(default_factory=list)
    assignments: list[dict[str, Any]] = field(default_factory=list)

    def append(self, line: bytes) -> None:
        self.byte_count += len(line)
        if self.byte_count > self.max_bytes:
            raise SavedMissionSnapshotError(
                f"{self.key} block exceeds max_target_bytes ({self.byte_count}>{self.max_bytes})"
            )
        self.lines.append(line)

    def raw(self) -> dict[str, Any]:
        data = b"".join(self.lines)
        return {
            "line_start": self.start_line,
            "line_end": self.start_line + len(self.lines) - 1,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "lines": [_decode(line) for line in self.lines],
            "text": _decode(data),
        }


@dataclass
class _MissionSlot:
    index: int
    block: _RawBlock
    values: list[str] = field(default_factory=list)


def _decode(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")


def _strip_eol(value: bytes) -> bytes:
    if value.endswith(b"\r\n"):
        return value[:-2]
    if value.endswith(b"\n") or value.endswith(b"\r"):
        return value[:-1]
    return value


def _lex_line(line: bytes, state: _LexState) -> tuple[bytes, int, _LexState]:
    """Remove comments and count structural braces outside quoted strings."""

    output = bytearray()
    delta = 0
    in_quote = state.in_quote
    escaped = state.escaped
    in_comment = False
    for byte in _strip_eol(line):
        if in_comment:
            continue
        if in_quote:
            output.append(byte)
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_quote = False
            continue
        if byte == 0x23:  # Clausewitz line comment.
            in_comment = True
        elif byte == 0x22:
            output.append(byte)
            in_quote = True
            escaped = False
        elif byte == 0x7B:
            output.append(byte)
            delta += 1
        elif byte == 0x7D:
            output.append(byte)
            delta -= 1
        else:
            output.append(byte)
    return bytes(output), delta, _LexState(in_quote, escaped)


def _tokens(value: bytes) -> list[bytes]:
    return [match.group(0) for match in _TOKEN_RE.finditer(value)]


def _unquote(value: bytes) -> str:
    value = value.strip()
    if len(value) >= 2 and value[:1] == b'"' and value[-1:] == b'"':
        value = value[1:-1]
    return _decode(value)


def _direct_tokens(value: bytes) -> list[str]:
    """Return list leaves at the current block depth, ignoring nested blocks."""

    result: list[str] = []
    relative_depth = 0
    for token in _tokens(value):
        if token == b"{":
            relative_depth += 1
        elif token == b"}":
            relative_depth -= 1
            if relative_depth < 0:
                relative_depth = 0
        elif token == b"=" or relative_depth != 0:
            continue
        else:
            result.append(_unquote(token))
            if len(result) > MAX_LIST_ITEMS:
                raise SavedMissionSnapshotError("list exceeds MAX_LIST_ITEMS")
    return result


def _assignment(value: bytes) -> tuple[str, str] | None:
    match = _ASSIGNMENT_RE.match(value)
    if match is None:
        return None
    return match.group(1).decode("ascii"), _unquote(match.group(2))


def _block_open(value: bytes, key: str) -> bool:
    tokens = _tokens(value)
    return len(tokens) >= 3 and tokens[0] == key.encode("ascii") and tokens[1] == b"=" and tokens[2] == b"{"


def _after_open(value: bytes) -> bytes:
    marker = value.find(b"{")
    return value[marker + 1:] if marker >= 0 else b""


def _version_string(version_parts: dict[str, str], versions: list[str]) -> str | None:
    ordered = [version_parts.get(key) for key in ("first", "second", "third", "forth")]
    if all(isinstance(value, str) and re.fullmatch(r"\d+", value) for value in ordered):
        return ".".join(ordered)  # type: ignore[arg-type]
    return versions[0] if versions else None


def _mtime_text(mtime_ns: int) -> str:
    return datetime.fromtimestamp(mtime_ns / 1_000_000_000, timezone.utc).isoformat()


class SavedMissionSnapshot:
    """Read a bounded, recorded mission snapshot for one country.

    ``path`` is read immediately. The constructor verifies the optional
    ``expected_sha256`` and stores the actual hash. Later calls to
    :meth:`as_dict` or :meth:`context` re-hash the same path and fail if the
    file changed. The source never starts a game and has no live-session API.
    """

    def __init__(
        self,
        path: str | Path,
        country: str,
        expected_sha256: str | None = None,
        *,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
        max_nesting: int = DEFAULT_MAX_NESTING,
        max_target_bytes: int = DEFAULT_MAX_TARGET_BYTES,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> None:
        if not isinstance(country, str) or COUNTRY_RE.fullmatch(country) is None:
            raise SavedMissionSnapshotError("country must be a three-character EU4 country tag")
        if expected_sha256 is not None:
            if not isinstance(expected_sha256, str) or HEX64_RE.fullmatch(expected_sha256) is None:
                raise SavedMissionSnapshotError("expected_sha256 must be a SHA-256 hex string")
            expected_sha256 = expected_sha256.lower()
        for name, value in (
            ("max_file_bytes", max_file_bytes),
            ("max_line_bytes", max_line_bytes),
            ("max_nesting", max_nesting),
            ("max_target_bytes", max_target_bytes),
            ("max_tokens", max_tokens),
        ):
            if type(value) is not int or value <= 0:
                raise SavedMissionSnapshotError(f"{name} must be a positive integer")

        self.path = Path(path).expanduser().resolve(strict=True)
        if not self.path.is_file():
            raise SavedMissionSnapshotError(f"save path is not a file: {self.path}")
        self.country = country
        self.expected_sha256 = expected_sha256
        self.max_file_bytes = max_file_bytes
        self.max_line_bytes = max_line_bytes
        self.max_nesting = max_nesting
        self.max_target_bytes = max_target_bytes
        self.max_tokens = max_tokens
        self._data = self._parse()

    def _parse(self) -> dict[str, Any]:
        before_stat = self.path.stat()
        if before_stat.st_size > self.max_file_bytes:
            raise SavedMissionSnapshotError(
                f"save exceeds max_file_bytes ({before_stat.st_size}>{self.max_file_bytes})"
            )

        digest = hashlib.sha256()
        line_count = 0
        bytes_read = 0
        token_count = 0
        depth = 0
        lex_state = _LexState()
        first_line = True
        countries_depth: int | None = None
        countries_closed = False
        target_seen = False
        target_active = False
        target_depth: int | None = None
        target_start_line: int | None = None
        target_end_line: int | None = None
        target_bytes = 0
        root_block: _RawBlock | None = None
        child_block: _RawBlock | None = None
        child_kind: str | None = None
        mission_slot: _MissionSlot | None = None
        mission_slots: list[_MissionSlot] = []
        country_missions: _RawBlock | None = None
        completed_missions: _RawBlock | None = None
        flags_block: _RawBlock | None = None
        hidden_flags_block: _RawBlock | None = None
        root_version: dict[str, str] = {}
        root_versions: list[str] = []
        dlc_enabled: list[str] = []
        date: str | None = None
        player: str | None = None
        target_block_seen = False
        countries_seen = False

        def start_child(key: str, line_number: int, current_depth: int, raw: bytes) -> _RawBlock:
            block = _RawBlock(key, line_number, current_depth + 1, self.max_target_bytes)
            block.append(raw)
            return block

        def finish_slot() -> None:
            nonlocal mission_slot
            if mission_slot is None:
                return
            mission_slot.block.tokens = list(mission_slot.values)
            mission_slots.append(mission_slot)
            mission_slot = None

        def finish_child() -> None:
            nonlocal child_block, child_kind, country_missions, completed_missions
            nonlocal flags_block, hidden_flags_block
            if child_block is None:
                return
            if child_kind == "country_missions":
                country_missions = child_block
                child_block.tokens = []
            elif child_kind == "completed_missions":
                completed_missions = child_block
            elif child_kind == "flags":
                flags_block = child_block
            elif child_kind == "hidden_flags":
                hidden_flags_block = child_block
            child_block = None
            child_kind = None

        def finish_root_block() -> None:
            nonlocal root_block
            root_block = None

        with self.path.open("rb", buffering=1024 * 1024) as stream:
            while True:
                line = stream.readline(self.max_line_bytes + 1)
                if not line:
                    break
                line_count += 1
                if len(line) > self.max_line_bytes:
                    raise SavedMissionSnapshotError(
                        f"line {line_count} exceeds max_line_bytes ({len(line)}>{self.max_line_bytes})"
                    )
                digest.update(line)
                bytes_read += len(line)
                clean, delta, lex_state = _lex_line(line, lex_state)
                token_count += sum(1 for _ in _TOKEN_RE.finditer(clean))
                if token_count > self.max_tokens:
                    raise SavedMissionSnapshotError(
                        f"token count exceeds max_tokens ({token_count}>{self.max_tokens})"
                    )
                before_depth = depth
                depth += delta
                if depth < 0:
                    raise SavedMissionSnapshotError(f"negative brace depth at line {line_count}")
                if depth > self.max_nesting:
                    raise SavedMissionSnapshotError(
                        f"brace nesting exceeds max_nesting at line {line_count}"
                    )

                if first_line:
                    first_line = False
                    header = _strip_eol(line)
                    if header.startswith(b"\xef\xbb\xbf"):
                        header = header[3:]
                    if header.strip() != b"EU4txt":
                        raise SavedMissionSnapshotError("save is not an EU4txt text save")
                    continue

                # Root metadata blocks are disjoint from the countries block.
                if root_block is not None:
                    root_block.append(line)
                    if before_depth == root_block.depth:
                        if root_block.key == "savegame_version":
                            item = _assignment(clean)
                            if item is not None:
                                root_version[item[0]] = item[1]
                        elif root_block.key == "savegame_versions":
                            root_versions.extend(_direct_tokens(clean))
                        elif root_block.key == "dlc_enabled":
                            dlc_enabled.extend(_direct_tokens(clean))
                    if depth < root_block.depth:
                        finish_root_block()
                    continue

                if countries_depth is None and before_depth == 0:
                    if _block_open(clean, "countries"):
                        countries_seen = True
                        countries_depth = 1
                    else:
                        item = _assignment(clean)
                        if item is not None:
                            key, value = item
                            if key == "date":
                                if date is not None:
                                    raise SavedMissionSnapshotError("duplicate root date field")
                                date = value
                            elif key == "player":
                                if player is not None:
                                    raise SavedMissionSnapshotError("duplicate root player field")
                                player = value
                        for key in ("savegame_version", "savegame_versions", "dlc_enabled"):
                            if _block_open(clean, key):
                                root_block = start_child(key, line_count, before_depth, line)
                                tail = _after_open(clean)
                                if key == "savegame_versions" and tail:
                                    root_versions.extend(_direct_tokens(tail))
                                elif key == "dlc_enabled" and tail:
                                    dlc_enabled.extend(_direct_tokens(tail))
                                if delta <= 0:
                                    finish_root_block()
                                break
                    depth = before_depth + delta
                    continue

                if countries_depth is not None and not target_active and before_depth == countries_depth:
                    country_open = _tokens(clean)
                    if (
                        len(country_open) >= 3
                        and country_open[0].decode("ascii", errors="ignore") == self.country
                        and country_open[1] == b"="
                        and country_open[2] == b"{"
                    ):
                        if target_seen:
                            raise SavedMissionSnapshotError(
                                f"duplicate target country block: {self.country}"
                            )
                        target_seen = True
                        target_active = True
                        target_depth = countries_depth + 1
                        target_start_line = line_count
                        target_bytes = len(line)
                        if target_bytes > self.max_target_bytes:
                            raise SavedMissionSnapshotError("target country block exceeds max_target_bytes")
                        # FRA={} is a valid empty block; close it immediately.
                        if delta <= 0:
                            target_active = False
                            target_end_line = line_count
                    if depth < countries_depth:
                        countries_closed = True
                        countries_depth = None
                    continue

                if target_active:
                    target_bytes += len(line)
                    if target_bytes > self.max_target_bytes:
                        raise SavedMissionSnapshotError("target country block exceeds max_target_bytes")

                    if child_block is not None:
                        child_block.append(line)
                        if child_kind == "country_missions":
                            if mission_slot is not None:
                                # ``child_block`` preserves the complete
                                # country_missions block; keep an equivalent
                                # bounded raw capture for the active slot so
                                # its audit record includes every root line
                                # and the closing brace.
                                mission_slot.block.append(line)
                                if before_depth == mission_slot.block.depth:
                                    mission_slot.values.extend(_direct_tokens(clean))
                                if depth < mission_slot.block.depth:
                                    finish_slot()
                            elif before_depth == child_block.depth and _block_open(clean, "mission_slot"):
                                slot_block = start_child("mission_slot", line_count, before_depth, line)
                                mission_slot = _MissionSlot(len(mission_slots) + 1, slot_block)
                                tail = _after_open(clean)
                                if tail:
                                    mission_slot.values.extend(_direct_tokens(tail))
                                if delta <= 0:
                                    finish_slot()
                        elif child_kind == "completed_missions":
                            if before_depth == child_block.depth:
                                child_block.tokens.extend(_direct_tokens(clean))
                        elif child_kind in {"flags", "hidden_flags"}:
                            if before_depth == child_block.depth:
                                item = _assignment(clean)
                                if item is not None:
                                    if len(child_block.assignments) >= MAX_ASSIGNMENTS:
                                        raise SavedMissionSnapshotError("flags exceed MAX_ASSIGNMENTS")
                                    child_block.assignments.append(
                                        {"name": item[0], "value": item[1], "raw": _decode(_strip_eol(line))}
                                    )
                        if depth < child_block.depth:
                            if mission_slot is not None:
                                finish_slot()
                            finish_child()
                        if target_depth is not None and depth < target_depth:
                            target_active = False
                            target_end_line = line_count
                            target_depth = None
                    elif target_depth is not None and before_depth == target_depth:
                        for key in ("country_missions", "completed_missions", "flags", "hidden_flags"):
                            if _block_open(clean, key):
                                if key == "country_missions" and country_missions is not None:
                                    raise SavedMissionSnapshotError("duplicate country_missions field")
                                if key == "completed_missions" and completed_missions is not None:
                                    raise SavedMissionSnapshotError("duplicate completed_missions field")
                                if key == "flags" and flags_block is not None:
                                    raise SavedMissionSnapshotError("duplicate flags field")
                                if key == "hidden_flags" and hidden_flags_block is not None:
                                    raise SavedMissionSnapshotError("duplicate hidden_flags field")
                                child_kind = key
                                child_block = start_child(key, line_count, before_depth, line)
                                tail = _after_open(clean)
                                if key == "completed_missions" and tail:
                                    child_block.tokens.extend(_direct_tokens(tail))
                                if delta <= 0:
                                    finish_child()
                                break
                        else:
                            item = _assignment(clean)
                            if item is not None and item[0] in {
                                "country_missions", "completed_missions", "flags", "hidden_flags"
                            }:
                                raise SavedMissionSnapshotError(
                                    f"unsupported scalar {item[0]} field in target country"
                                )

                    if target_depth is not None and depth < target_depth:
                        target_active = False
                        target_end_line = line_count
                        target_depth = None
                    continue

                if countries_depth is not None and depth < countries_depth:
                    countries_closed = True
                    countries_depth = None

        if first_line:
            raise SavedMissionSnapshotError("empty save file")
        if lex_state.in_quote:
            raise SavedMissionSnapshotError("unterminated quoted string")
        if depth != 0:
            raise SavedMissionSnapshotError(f"final brace depth is {depth}, expected 0")
        if root_block is not None or child_block is not None or target_active:
            raise SavedMissionSnapshotError("save ended inside an open target or metadata block")
        if not countries_seen or not countries_closed:
            raise SavedMissionSnapshotError("countries block is absent or did not close")
        if not target_seen or target_start_line is None or target_end_line is None:
            raise SavedMissionSnapshotError(f"target country block not found: {self.country}")
        if mission_slot is not None:
            finish_slot()
        if child_block is not None:
            finish_child()

        after_stat = self.path.stat()
        actual_sha256 = digest.hexdigest()
        self._check_file_identity(before_stat, after_stat, bytes_read, actual_sha256)
        if self.expected_sha256 is not None and actual_sha256 != self.expected_sha256:
            raise SavedMissionSnapshotError(
                f"save SHA-256 mismatch: expected {self.expected_sha256}, got {actual_sha256}"
            )

        slot_dicts = []
        for slot in mission_slots:
            raw = slot.block.raw()
            slot_dicts.append({
                "index": slot.index,
                "root_ids": list(slot.values),
                "raw": raw,
            })

        def block_dict(block: _RawBlock | None, *, values: list[str] | None = None) -> dict[str, Any]:
            if block is None:
                return {"present": False, "values": [], "list": [], "raw": None}
            value_list = list(values or [])
            result: dict[str, Any] = {
                "present": True,
                "values": value_list,
                "list": list(value_list),
                "raw": block.raw(),
            }
            if block.assignments:
                result["entries"] = deepcopy(block.assignments)
            return result

        country_missions_result = {
            "present": country_missions is not None,
            "mission_slots": slot_dicts,
            "raw": country_missions.raw() if country_missions is not None else None,
        }
        completed_result = block_dict(
            completed_missions,
            values=completed_missions.tokens if completed_missions is not None else [],
        )
        flags_result = block_dict(flags_block)
        hidden_flags_result = block_dict(hidden_flags_block)
        save_version = _version_string(root_version, root_versions)
        file_info = {
            "path": str(self.path),
            "size_bytes": bytes_read,
            "mtime_ns": before_stat.st_mtime_ns,
            "mtime": before_stat.st_mtime,
            "mtime_utc": _mtime_text(before_stat.st_mtime_ns),
            "sha256": actual_sha256,
            "line_count": line_count,
            "token_count": token_count,
            "max_file_bytes": self.max_file_bytes,
            "max_line_bytes": self.max_line_bytes,
            "max_nesting": self.max_nesting,
            "max_target_bytes": self.max_target_bytes,
            "max_tokens": self.max_tokens,
        }
        return {
            "schema": "saved_mission_snapshot_v1",
            "schema_version": 1,
            "mode": "recorded",
            "country": self.country,
            "source": {
                "name": "SavedMissionSnapshot",
                "mode": "recorded",
                "read_only": True,
                "live": False,
            },
            "file": file_info,
            "input": deepcopy(file_info),
            "save": {
                "date": date,
                "version": save_version,
                "savegame_version": deepcopy(root_version),
                "savegame_versions": list(root_versions),
                "player": player,
                "dlc_enabled": list(dlc_enabled),
            },
            # These top-level aliases make the small snapshot convenient to
            # inspect while ``save`` remains the grouped audit record.
            "date": date,
            "version": save_version,
            "player": player,
            "dlc_enabled": list(dlc_enabled),
            "target_block": {
                "line_start": target_start_line,
                "line_end": target_end_line,
                "bytes": target_bytes,
            },
            "country_missions": country_missions_result,
            "completed_missions": completed_result,
            "country_flags": {
                "flags": flags_result,
                "hidden_flags": hidden_flags_result,
            },
            "flags": flags_result,
            "hidden_flags": hidden_flags_result,
        }

    def _check_file_identity(
        self,
        before_stat: Any,
        after_stat: Any,
        bytes_read: int,
        actual_sha256: str,
    ) -> None:
        if bytes_read != after_stat.st_size:
            raise SavedMissionSnapshotError(
                f"save size changed during read ({bytes_read}!={after_stat.st_size})"
            )
        if before_stat.st_size != after_stat.st_size or before_stat.st_mtime_ns != after_stat.st_mtime_ns:
            raise SavedMissionSnapshotError("save changed during streaming parse")
        if self.expected_sha256 is not None and actual_sha256 != self.expected_sha256:
            raise SavedMissionSnapshotError(
                f"save SHA-256 mismatch: expected {self.expected_sha256}, got {actual_sha256}"
            )

    def _assert_unchanged(self) -> None:
        recorded = self._data["file"]
        try:
            before = self.path.stat()
        except OSError as exc:
            raise SavedMissionSnapshotError(f"save is unavailable: {self.path}") from exc
        if before.st_size != recorded["size_bytes"] or before.st_mtime_ns != recorded["mtime_ns"]:
            raise SavedMissionSnapshotError("save changed after snapshot construction")
        digest = hashlib.sha256()
        bytes_read = 0
        with self.path.open("rb", buffering=1024 * 1024) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
                bytes_read += len(chunk)
        after = self.path.stat()
        if (
            bytes_read != recorded["size_bytes"]
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_size != after.st_size
            or digest.hexdigest() != recorded["sha256"]
        ):
            raise SavedMissionSnapshotError("save changed during snapshot validation")

    def as_dict(self) -> dict[str, Any]:
        """Return the immutable recorded snapshot after revalidating its file."""

        self._assert_unchanged()
        return deepcopy(self._data)

    def snapshot(self) -> dict[str, Any]:
        """Alias for :meth:`as_dict` used by callers that request a snapshot."""

        return self.as_dict()

    def context(self) -> dict[str, Any]:
        """Return recorded provenance without inventing a live game identity."""

        self._assert_unchanged()
        save = self._data["save"]
        file_info = self._data["file"]
        return {
            "mode": "recorded",
            "status": "recorded",
            "complete": True,
            "source": "SavedMissionSnapshot",
            "path": file_info["path"],
            "sha256": file_info["sha256"],
            "size_bytes": file_info["size_bytes"],
            "mtime_ns": file_info["mtime_ns"],
            "country": self.country,
            "save_date": save["date"],
            "version": save["version"],
            "player": save["player"],
            "dlc_enabled": list(save["dlc_enabled"]),
            # A saved calendar date is not a live session clock. Keep the
            # explicit kind and leave the monotonic/live identity fields null.
            "game_date": save["date"],
            "game_day": None,
            "game_date_kind": "saved_calendar_date",
            "world_id": None,
            "session_id": None,
            "live": False,
            "reasons": [],
        }

    @property
    def sha256(self) -> str:
        self._assert_unchanged()
        return self._data["file"]["sha256"]

    @property
    def size_bytes(self) -> int:
        self._assert_unchanged()
        return self._data["file"]["size_bytes"]

    @property
    def mtime_ns(self) -> int:
        self._assert_unchanged()
        return self._data["file"]["mtime_ns"]

    @property
    def date(self) -> str | None:
        self._assert_unchanged()
        return self._data["save"]["date"]

    @property
    def version(self) -> str | None:
        self._assert_unchanged()
        return self._data["save"]["version"]

    @property
    def player(self) -> str | None:
        self._assert_unchanged()
        return self._data["save"]["player"]

    @property
    def dlc_enabled(self) -> list[str]:
        self._assert_unchanged()
        return list(self._data["save"]["dlc_enabled"])

    @property
    def country_missions(self) -> dict[str, Any]:
        self._assert_unchanged()
        return deepcopy(self._data["country_missions"])

    @property
    def completed_missions(self) -> dict[str, Any]:
        self._assert_unchanged()
        return deepcopy(self._data["completed_missions"])

    @property
    def country_flags(self) -> dict[str, Any]:
        self._assert_unchanged()
        return deepcopy(self._data["country_flags"])
