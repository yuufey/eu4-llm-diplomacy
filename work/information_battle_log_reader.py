"""Bounded reader for the checked owned-battle JSONL log.

The checked native sink writes one ASCII binding line followed by the opaque
wire frames accepted by :mod:`work.information_battle_transport`.  This module
owns only tailing and a durable file cursor.  It never interprets payload
bytes, invents battle fields, or claims that the log is complete.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ctypes
from contextlib import contextmanager
import os
from pathlib import Path
import re
import sqlite3
import threading
from typing import Any

from work.information_battle_transport import (
    MAX_WIRE_BYTES,
    BattleTransportStore,
    FrameValidationError,
    parse_wire_frame,
)


HEADER_PREFIX = b"EU4_OWNED_BATTLE_WIRE_V1 "
MAX_HEADER_BYTES = 128
MAX_FRAMES_PER_POLL = 256
_HEADER_RE = re.compile(
    rb"EU4_OWNED_BATTLE_WIRE_V1 ([0-9a-f]{16}) ([0-9a-f]{16})\n\Z"
)


class BattleLogError(RuntimeError):
    """Base class for checked-log or cursor failures."""


class LogBindingError(BattleLogError):
    """The path, file identity, header, or frame binding changed."""


class CursorConflict(BattleLogError):
    """Another reader advanced the same cursor first."""


class FileLockBusy(BattleLogError):
    """The checked log is currently held by the native writer."""


if os.name == "nt":
    import msvcrt
    from ctypes import wintypes

    _LOCKFILE_FAIL_IMMEDIATELY = 0x00000001
    _LOCKFILE_EXCLUSIVE_LOCK = 0x00000002
    _ERROR_LOCK_VIOLATION = 33
    _ERROR_SHARING_VIOLATION = 32
    _DWORD_MAX = 0xFFFFFFFF

    class _Overlapped(ctypes.Structure):
        _fields_ = [
            ("Internal", wintypes.LPVOID),
            ("InternalHigh", wintypes.LPVOID),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        ]

    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _LOCK_FILE_EX = _KERNEL32.LockFileEx
    _LOCK_FILE_EX.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_Overlapped),
    ]
    _LOCK_FILE_EX.restype = wintypes.BOOL
    _UNLOCK_FILE_EX = _KERNEL32.UnlockFileEx
    _UNLOCK_FILE_EX.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_Overlapped),
    ]
    _UNLOCK_FILE_EX.restype = wintypes.BOOL
else:
    msvcrt = None
    _LOCKFILE_EXCLUSIVE_LOCK = 0


class _FileLockLease:
    """A whole-file advisory/mandatory lock kept until explicit release."""

    def __init__(self, stream: Any, *, exclusive: bool) -> None:
        self._stream = stream
        self._exclusive = bool(exclusive)
        self._released = False
        self._overlapped: Any = None
        self._acquire()

    def _acquire(self) -> None:
        if os.name == "nt":
            assert msvcrt is not None
            handle_value = int(msvcrt.get_osfhandle(self._stream.fileno()))
            if handle_value == -1:
                raise BattleLogError("invalid_file_handle")
            flags = _LOCKFILE_FAIL_IMMEDIATELY
            if self._exclusive:
                flags |= _LOCKFILE_EXCLUSIVE_LOCK
            overlapped = _Overlapped()
            if not _LOCK_FILE_EX(
                    ctypes.c_void_p(handle_value), flags, 0,
                    _DWORD_MAX, _DWORD_MAX, ctypes.byref(overlapped),
            ):
                error = int(ctypes.get_last_error())
                if error in (_ERROR_LOCK_VIOLATION, _ERROR_SHARING_VIOLATION):
                    raise FileLockBusy("file_lock_busy")
                raise OSError(error, "LockFileEx failed")
            # The OVERLAPPED address is retained until UnlockFileEx.
            self._overlapped = overlapped
            return
        try:
            import fcntl
        except ImportError as exc:  # pragma: no cover - unsupported platform
            raise BattleLogError("file_lock_unsupported") from exc
        operation = fcntl.LOCK_EX if self._exclusive else fcntl.LOCK_SH
        operation |= fcntl.LOCK_NB
        try:
            fcntl.flock(self._stream.fileno(), operation)
        except (BlockingIOError, OSError) as exc:
            if getattr(exc, "errno", None) in (11, 13):
                raise FileLockBusy("file_lock_busy") from exc
            raise

    def release(self) -> None:
        if self._released:
            return
        try:
            if os.name == "nt":
                assert msvcrt is not None
                handle_value = int(msvcrt.get_osfhandle(self._stream.fileno()))
                if handle_value == -1 or self._overlapped is None:
                    raise BattleLogError("invalid_file_handle")
                if not _UNLOCK_FILE_EX(
                        ctypes.c_void_p(handle_value), 0,
                        _DWORD_MAX, _DWORD_MAX,
                        ctypes.byref(self._overlapped),
                ):
                    error = int(ctypes.get_last_error())
                    raise OSError(error, "UnlockFileEx failed")
            else:
                import fcntl
                fcntl.flock(self._stream.fileno(), fcntl.LOCK_UN)
        finally:
            self._released = True

    def __enter__(self) -> "_FileLockLease":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.release()


def acquire_file_lock(stream: Any, *, exclusive: bool = False) -> _FileLockLease:
    """Acquire a non-blocking whole-file lock.

    Windows uses ``LockFileEx`` over the complete 64-bit range.  POSIX uses
    ``flock`` so the same tests exercise an advisory lock on development
    platforms.  The returned lease must remain alive for the whole checked
    snapshot/read/ack transaction.
    """

    return _FileLockLease(stream, exclusive=exclusive)


@dataclass(frozen=True)
class LogHeader:
    installation: str
    world_generation: str
    raw: bytes


@dataclass(frozen=True)
class FileSnapshot:
    identity: str
    size: int


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_budget(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("max_frames_must_be_integer")
    if not 1 <= value <= MAX_FRAMES_PER_POLL:
        raise ValueError("max_frames_out_of_range")
    return value


def parse_log_header(raw: bytes) -> LogHeader:
    """Parse the exact ASCII binding line, including its LF terminator."""

    if not isinstance(raw, bytes):
        raise LogBindingError("header_must_be_bytes")
    if len(raw) > MAX_HEADER_BYTES:
        raise LogBindingError("header_too_large")
    match = _HEADER_RE.fullmatch(raw)
    if match is None:
        raise LogBindingError("header_mismatch")
    installation = match.group(1).decode("ascii")
    world_generation = match.group(2).decode("ascii")
    if installation == "0" * 16 or world_generation == "0" * 16:
        raise LogBindingError("header_identity_must_not_be_zero")
    return LogHeader(
        installation=installation,
        world_generation=world_generation,
        raw=bytes(raw),
    )


def _file_identity(stat_result: os.stat_result) -> str:
    """Return a stable path-file identity for the current platform.

    Windows exposes the volume/file-index pair through st_dev/st_ino.  The
    creation timestamp fallback is used only on platforms/filesystems that do
    not expose an inode, avoiding a ctime component that changes on ordinary
    appends.
    """

    inode = int(getattr(stat_result, "st_ino", 0))
    device = int(getattr(stat_result, "st_dev", 0))
    if inode:
        return f"{device}:{inode}"
    creation = int(getattr(stat_result, "st_birthtime_ns", 0))
    if not creation:
        creation = int(getattr(stat_result, "st_ctime_ns", 0))
    return f"{device}:creation:{creation}"


def _record_from_row(row: sqlite3.Row | tuple[Any, ...]) -> dict[str, Any]:
    return {
        "path": str(row[0]),
        "file_identity": str(row[1]),
        "header": bytes(row[2]),
        "installation": str(row[3]),
        "world_generation": str(row[4]),
        "offset": int(row[5]),
        "updated_at": str(row[6]),
    }


class BattleLogTailer:
    """Tail one checked log with durable ack-after-record cursoring."""

    def __init__(
            self,
            log_path: str | Path,
            cursor_database: str | Path,
            *,
            receiver: BattleTransportStore | None = None,
            receiver_database: str | Path | None = None,
            max_frames: int = MAX_FRAMES_PER_POLL,
    ) -> None:
        self.log_path = Path(log_path).resolve()
        self.cursor_database = str(cursor_database)
        self.max_frames = _validate_budget(max_frames)
        if receiver is None and receiver_database is None:
            raise ValueError("receiver_or_receiver_database_required")
        self._owns_receiver = receiver is None
        self.receiver = receiver or BattleTransportStore(receiver_database)  # type: ignore[arg-type]
        if self.cursor_database != ":memory:":
            Path(self.cursor_database).parent.mkdir(parents=True, exist_ok=True)
        self._cursor_connection = sqlite3.connect(
            self.cursor_database,
            isolation_level=None,
            check_same_thread=False,
            timeout=5.0,
        )
        self._cursor_connection.execute("PRAGMA synchronous = FULL")
        synchronous = self._cursor_connection.execute(
            "PRAGMA synchronous"
        ).fetchone()[0]
        if int(synchronous) != 2:
            self._cursor_connection.close()
            if self._owns_receiver:
                self.receiver.close()
            raise BattleLogError("cursor_synchronous_not_full")
        self._cursor_connection.execute("PRAGMA foreign_keys = ON")
        self._cursor_connection.execute(
            """
            CREATE TABLE IF NOT EXISTS checked_log_cursor (
                cursor_id INTEGER PRIMARY KEY CHECK (cursor_id = 1),
                path TEXT NOT NULL,
                file_identity TEXT NOT NULL,
                header BLOB NOT NULL,
                installation TEXT NOT NULL,
                world_generation TEXT NOT NULL,
                offset INTEGER NOT NULL CHECK (offset >= 0),
                updated_at TEXT NOT NULL
            )
            """
        )
        self._lock = threading.RLock()
        self._closed = False

    def _ensure_open(self) -> None:
        if self._closed:
            raise BattleLogError("tailer_closed")

    def _cursor_commit(self) -> None:
        """Commit seam used to verify record-before-cursor failure behavior."""

        self._cursor_connection.commit()

    def _cursor_rollback(self) -> None:
        try:
            self._cursor_connection.rollback()
        except sqlite3.Error:
            pass

    def _cursor_row(self) -> dict[str, Any] | None:
        row = self._cursor_connection.execute(
            "SELECT path, file_identity, header, installation, world_generation, "
            "offset, updated_at FROM checked_log_cursor WHERE cursor_id=1"
        ).fetchone()
        return None if row is None else _record_from_row(row)

    def _open_checked_file(
            self,
    ) -> tuple[Any, _FileLockLease, FileSnapshot, LogHeader]:
        try:
            stream = self.log_path.open("rb")
        except OSError as exc:
            raise LogBindingError(f"file_unavailable:{type(exc).__name__}") from exc
        lease: _FileLockLease | None = None
        try:
            # The native writer takes the matching exclusive range lock before
            # append/rollback.  Do not use path metadata or header bytes as an
            # authority until this shared lock has been acquired.
            lease = acquire_file_lock(stream, exclusive=False)
            before = os.stat(self.log_path)
            after = os.fstat(stream.fileno())
            before_identity = _file_identity(before)
            after_identity = _file_identity(after)
            if before_identity != after_identity:
                raise LogBindingError("file_identity_changed_during_open")
            header_raw = stream.readline(MAX_HEADER_BYTES + 1)
            header = parse_log_header(header_raw)
            return stream, lease, FileSnapshot(after_identity, int(after.st_size)), header
        except FileLockBusy:
            stream.close()
            raise
        except LogBindingError:
            try:
                if lease is not None:
                    lease.release()
            finally:
                stream.close()
            raise
        except OSError as exc:
            try:
                if lease is not None:
                    lease.release()
            finally:
                stream.close()
            raise LogBindingError(f"file_read_failed:{type(exc).__name__}") from exc
        except Exception:
            try:
                if lease is not None:
                    lease.release()
            finally:
                stream.close()
            raise

    def _ensure_cursor(
            self, snapshot: FileSnapshot, header: LogHeader,
    ) -> dict[str, Any]:
        path_text = str(self.log_path)
        self._cursor_connection.execute("BEGIN IMMEDIATE")
        try:
            row = self._cursor_row()
            if row is None:
                self._cursor_connection.execute(
                    "INSERT INTO checked_log_cursor "
                    "(cursor_id, path, file_identity, header, installation, "
                    "world_generation, offset, updated_at) VALUES (1, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        path_text,
                        snapshot.identity,
                        sqlite3.Binary(header.raw),
                        header.installation,
                        header.world_generation,
                        len(header.raw),
                        _utc_now(),
                    ),
                )
                self._cursor_commit()
                return {
                    "path": path_text,
                    "file_identity": snapshot.identity,
                    "header": header.raw,
                    "installation": header.installation,
                    "world_generation": header.world_generation,
                    "offset": len(header.raw),
                    "updated_at": _utc_now(),
                }
            # No cursor mutation was made for an existing row.  Roll back the
            # short write transaction to release its lock without consuming
            # the checkpoint-commit failure seam used by poll().
            self._cursor_rollback()
        except Exception:
            self._cursor_rollback()
            raise
        if row["path"] != path_text:
            raise LogBindingError("log_path_changed")
        if row["file_identity"] != snapshot.identity:
            raise LogBindingError("file_identity_changed")
        if row["header"] != header.raw:
            raise LogBindingError("header_changed")
        if (
                row["installation"] != header.installation
                or row["world_generation"] != header.world_generation
        ):
            raise LogBindingError("header_identity_changed")
        return row

    @staticmethod
    def _read_frame(stream: Any) -> tuple[str, bytes]:
        """Read at most one frame, one bounded byte at a time.

        Reading one byte at a time prevents a poll from consuming the next
        frame before its preceding record has been durably acknowledged.
        """

        buffer = bytearray()
        for _ in range(MAX_WIRE_BYTES):
            chunk = stream.read(1)
            if not chunk:
                return ("eof" if not buffer else "partial"), bytes(buffer)
            if len(chunk) != 1:
                return "invalid_read", bytes(buffer)
            buffer.extend(chunk)
            if chunk == b"\n":
                return "complete", bytes(buffer)
        # A line exactly at the bound without LF is still a partial tail.  A
        # subsequent byte proves that it is overlong, without reading an
        # unbounded buffer.
        extra = stream.read(1)
        if extra:
            return "oversize", bytes(buffer)
        return "partial", bytes(buffer)

    def _checkpoint(
            self,
            expected_offset: int,
            next_offset: int,
            snapshot: FileSnapshot,
            header: LogHeader,
    ) -> None:
        path_text = str(self.log_path)
        self._cursor_connection.execute("BEGIN IMMEDIATE")
        try:
            cursor = self._cursor_connection.execute(
                "UPDATE checked_log_cursor SET offset=?, updated_at=? "
                "WHERE cursor_id=1 AND path=? AND file_identity=? AND header=? "
                "AND offset=?",
                (
                    next_offset,
                    _utc_now(),
                    path_text,
                    snapshot.identity,
                    sqlite3.Binary(header.raw),
                    expected_offset,
                ),
            )
            if cursor.rowcount != 1:
                raise CursorConflict("cursor_compare_and_swap_failed")
            self._cursor_commit()
        except Exception:
            self._cursor_rollback()
            raise

    def _result(
            self, *, status: str, offset: int, acked: int, duplicates: int,
            reason: str | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": status,
            "offset": offset,
            "acked": acked,
            "duplicates": duplicates,
            "complete": False,
        }
        if reason is not None:
            result["reason"] = reason
        return result

    def poll(self) -> dict[str, Any]:
        """Consume up to ``max_frames`` frames without advancing past failure."""

        with self._lock:
            self._ensure_open()
            prior_cursor = self._cursor_row()
            try:
                stream, lease, snapshot, header = self._open_checked_file()
            except FileLockBusy:
                prior_offset = 0 if prior_cursor is None else int(prior_cursor["offset"])
                return self._result(
                    status="busy_no_progress", offset=prior_offset, acked=0,
                    duplicates=0, reason="file_lock_busy",
                )
            except LogBindingError as exc:
                return self._result(
                    status="rejected_binding", offset=0, acked=0, duplicates=0,
                    reason=str(exc),
                )
            try:
                try:
                    cursor = self._ensure_cursor(snapshot, header)
                except LogBindingError as exc:
                    return self._result(
                        status="rejected_binding", offset=0, acked=0,
                        duplicates=0, reason=str(exc),
                    )
                except Exception as exc:
                    return self._result(
                        status="cursor_init_failed", offset=0, acked=0,
                        duplicates=0,
                        reason=f"{type(exc).__name__}:{exc}",
                    )
                offset = int(cursor["offset"])
                if offset < len(header.raw):
                    return self._result(
                        status="rejected_cursor", offset=offset, acked=0,
                        duplicates=0, reason="cursor_before_header",
                    )
                if snapshot.size < offset:
                    return self._result(
                        status="rejected_truncation", offset=offset, acked=0,
                        duplicates=0, reason="file_shorter_than_cursor",
                    )
                try:
                    stream.seek(offset)
                except OSError as exc:
                    return self._result(
                        status="stopped_read_error", offset=offset, acked=0,
                        duplicates=0,
                        reason=f"seek_failed:{type(exc).__name__}:{exc}",
                    )
                acked = 0
                duplicates = 0
                for _ in range(self.max_frames):
                    frame_offset = offset
                    try:
                        kind, raw_frame = self._read_frame(stream)
                    except OSError as exc:
                        return self._result(
                            status="stopped_read_error", offset=offset,
                            acked=acked, duplicates=duplicates,
                            reason=f"read_failed:{type(exc).__name__}:{exc}",
                        )
                    if kind == "eof":
                        return self._result(
                            status="advanced" if acked else "idle",
                            offset=offset, acked=acked, duplicates=duplicates,
                        )
                    if kind == "partial":
                        return self._result(
                            status="partial", offset=offset, acked=acked,
                            duplicates=duplicates,
                        )
                    if kind == "oversize":
                        return self._result(
                            status="stopped_oversize", offset=offset,
                            acked=acked, duplicates=duplicates,
                            reason="frame_exceeds_max_wire_bytes",
                        )
                    if kind != "complete":
                        return self._result(
                            status="stopped_read_error", offset=offset,
                            acked=acked, duplicates=duplicates,
                            reason=kind,
                        )
                    try:
                        frame = parse_wire_frame(raw_frame)
                    except FrameValidationError as exc:
                        return self._result(
                            status="stopped_invalid_frame", offset=offset,
                            acked=acked, duplicates=duplicates, reason=str(exc),
                        )
                    if (
                            frame.installation != header.installation
                            or frame.world_generation != header.world_generation
                    ):
                        return self._result(
                            status="stopped_binding_mismatch", offset=offset,
                            acked=acked, duplicates=duplicates,
                            reason="frame_identity_differs_from_log_header",
                        )
                    try:
                        receipt = self.receiver.ingest_line(raw_frame)
                    except Exception as exc:
                        return self._result(
                            status="stopped_receiver_error", offset=offset,
                            acked=acked, duplicates=duplicates,
                            reason=f"{type(exc).__name__}:{exc}",
                        )
                    if not receipt.get("ack"):
                        return self._result(
                            status="stopped_receiver_rejection", offset=offset,
                            acked=acked, duplicates=duplicates,
                            reason=str(receipt.get("reason", receipt.get("status"))),
                        )
                    next_offset = frame_offset + len(raw_frame)
                    try:
                        current = os.fstat(stream.fileno())
                        if _file_identity(current) != snapshot.identity:
                            raise LogBindingError("file_identity_changed_during_poll")
                        if int(current.st_size) < next_offset:
                            raise LogBindingError("file_truncated_during_poll")
                        self._checkpoint(
                            frame_offset, next_offset, snapshot, header
                        )
                    except CursorConflict as exc:
                        return self._result(
                            status="cursor_conflict", offset=frame_offset,
                            acked=acked + 1,
                            duplicates=duplicates + int(bool(receipt.get("idempotent"))),
                            reason=str(exc),
                        )
                    except LogBindingError as exc:
                        return self._result(
                            status="rejected_binding", offset=frame_offset,
                            acked=acked, duplicates=duplicates, reason=str(exc),
                        )
                    except Exception as exc:
                        return self._result(
                            status="cursor_checkpoint_failed", offset=frame_offset,
                            acked=acked, duplicates=duplicates,
                            reason=f"{type(exc).__name__}:{exc}",
                        )
                    offset = next_offset
                    acked += 1
                    if receipt.get("idempotent"):
                        duplicates += 1
                return self._result(
                    status="budget_exhausted", offset=offset, acked=acked,
                    duplicates=duplicates,
                )
            finally:
                try:
                    lease.release()
                finally:
                    stream.close()

    def status(self) -> dict[str, Any]:
        """Return a bounded, lock-checked snapshot without consuming frames."""

        with self._lock:
            self._ensure_open()
            prior_cursor = self._cursor_row()
            try:
                stream, lease, snapshot, header = self._open_checked_file()
            except FileLockBusy:
                offset = 0 if prior_cursor is None else int(prior_cursor["offset"])
                return {
                    "status": "busy_no_progress",
                    "offset": offset,
                    "complete": False,
                    "consistent": False,
                    "reason": "file_lock_busy",
                }
            except LogBindingError as exc:
                return {
                    "status": "rejected_binding",
                    "offset": 0 if cursor is None else int(cursor["offset"]),
                    "complete": False,
                    "consistent": False,
                    "reason": str(exc),
                }
            try:
                # The cursor and file binding are both authoritative only
                # after the shared lease has covered the full snapshot.
                cursor = self._cursor_row()
                if cursor is None:
                    return {
                        "status": "uninitialized",
                        "offset": len(header.raw),
                        "size": snapshot.size,
                        "identity": snapshot.identity,
                        "header": header.raw,
                        "complete": False,
                        "consistent": True,
                    }
                if (
                        cursor["path"] != str(self.log_path)
                        or cursor["file_identity"] != snapshot.identity
                        or cursor["header"] != header.raw
                        or cursor["installation"] != header.installation
                        or cursor["world_generation"] != header.world_generation
                ):
                    return {
                        "status": "rejected_binding",
                        "offset": int(cursor["offset"]),
                        "size": snapshot.size,
                        "identity": snapshot.identity,
                        "header": header.raw,
                        "complete": False,
                        "consistent": False,
                        "reason": "cursor_binding_changed",
                    }
                offset = int(cursor["offset"])
                if snapshot.size < offset:
                    current = "rejected_truncation"
                elif snapshot.size == offset:
                    current = "idle"
                else:
                    current = "ready"
                return {
                    "status": current,
                    "offset": offset,
                    "size": snapshot.size,
                    "identity": snapshot.identity,
                    "header": header.raw,
                    "complete": False,
                    "consistent": True,
                }
            finally:
                try:
                    lease.release()
                finally:
                    stream.close()

    def cursor(self) -> dict[str, Any] | None:
        with self._lock:
            self._ensure_open()
            return self._cursor_row()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._cursor_connection.close()
            if self._owns_receiver:
                self.receiver.close()
            self._closed = True

    def __enter__(self) -> "BattleLogTailer":
        self._ensure_open()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()


CheckedBattleLogTailer = BattleLogTailer


__all__ = [
    "HEADER_PREFIX",
    "MAX_HEADER_BYTES",
    "MAX_FRAMES_PER_POLL",
    "BattleLogError",
    "FileLockBusy",
    "LogBindingError",
    "CursorConflict",
    "LogHeader",
    "FileSnapshot",
    "parse_log_header",
    "acquire_file_lock",
    "BattleLogTailer",
    "CheckedBattleLogTailer",
]
