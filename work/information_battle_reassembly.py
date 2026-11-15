"""Durable, opaque reassembly for owned-battle transport fragments.

The transport receiver persists native JSONL rows first.  This module consumes
only those committed rows and interprets the payload as a bounded fragment
container.  It deliberately does not decode battle fields and never reports a
battle-complete result: a successful group is only ``transport_complete``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import struct
import threading
from typing import Any
import zlib

from work.information_battle_transport import BattleTransportStore


FRAGMENT_MAGIC = b"EU4BFRG1"
FRAGMENT_HEADER_BYTES = 64
FRAGMENT_CAPACITY_BYTES = 4032
MAX_RECORD_BYTES = 4096
MAX_MESSAGE_BYTES = 1024 * 1024
MAX_PENDING_GROUPS = 64
MAX_PENDING_BYTES = 8 * 1024 * 1024
DEFAULT_PAGE_LIMIT = 256
MAX_PAGE_LIMIT = 256
MAX_POLL_ROWS = 256
UINT64_MAX = (1 << 64) - 1
_HEX16 = re.compile(r"[0-9a-f]{16}\Z")
_DECIMAL = re.compile(r"[0-9]+\Z")
_HEADER = struct.Struct("<8sHHQIIIIII20s")


class ReassemblyError(RuntimeError):
    """Base class for durable reassembly failures."""


class FragmentValidationError(ReassemblyError):
    """A native fragment payload violates the fixed binary contract."""


class SourceBindingError(ReassemblyError):
    """The committed transport database changed or is not bindable."""


class ReassemblyPersistenceError(ReassemblyError):
    """The reassembly SQLite transaction could not be committed."""


class ReassemblyCursorConflict(ReassemblyError):
    """Another reassembler advanced the persistent source cursor first."""


class _CapacityStop(ReassemblyError):
    pass


class _ConflictStop(ReassemblyError):
    pass


class _CrcStop(ReassemblyError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_page_limit(value: Any, field: str = "limit") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field}_must_be_integer")
    if not 1 <= value <= MAX_PAGE_LIMIT:
        raise ValueError(f"{field}_out_of_range")
    return value


def _validate_after_group(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("after_group_id_must_be_integer_or_none")
    if value < 0:
        raise ValueError("after_group_id_must_not_be_negative")
    return value


def _validate_identity(value: Any, field: str) -> str:
    if not isinstance(value, str) or _HEX16.fullmatch(value) is None:
        raise ValueError(f"{field}_must_be_lower_hex16")
    if value == "0" * 16:
        raise ValueError(f"{field}_must_not_be_zero")
    return value


def _validate_uint64_text(value: Any, field: str = "message_id") -> str:
    if not isinstance(value, str) or len(value) > 20:
        raise ValueError(f"{field}_must_be_canonical_decimal")
    if _DECIMAL.fullmatch(value) is None or value == "0":
        raise ValueError(f"{field}_must_be_canonical_decimal")
    if len(value) > 1 and value.startswith("0"):
        raise ValueError(f"{field}_must_be_canonical_decimal")
    number = int(value, 10)
    if not 1 <= number <= UINT64_MAX:
        raise ValueError(f"{field}_out_of_uint64_range")
    return value


def _stable_file_identity(path: Path) -> tuple[str, str]:
    try:
        stat_result = path.stat()
    except OSError as exc:
        raise SourceBindingError(f"source_unavailable:{type(exc).__name__}") from exc
    device = int(getattr(stat_result, "st_dev", 0))
    inode = int(getattr(stat_result, "st_ino", 0))
    if not inode:
        raise SourceBindingError("source_file_identity_unavailable")
    birth = int(getattr(stat_result, "st_birthtime_ns", 0))
    # Windows exposes creation time through st_birthtime_ns.  On POSIX
    # platforms without it, ctime changes on ordinary writes, so retain an
    # inode-only creation marker and still reject normal path replacement.
    creation = str(birth) if birth else f"inode:{device}:{inode}"
    return f"{device}:{inode}", creation


def _source_schema_hash(path: Path) -> str:
    # Schema inspection must never create a database if the source disappears
    # between the identity stat and this probe.  SQLite's default path mode is
    # read/write/create, so use an explicit read-only URI instead.
    source_uri = path.resolve().as_uri() + "?mode=ro"
    try:
        connection = sqlite3.connect(
            source_uri, uri=True, isolation_level=None, timeout=2.0,
        )
        try:
            rows = connection.execute(
                "SELECT type, name, COALESCE(sql, '') FROM sqlite_master "
                "WHERE name IN ('battle_records','battle_streams','observed_gaps',"
                "'open_gap_ranges') ORDER BY type, name"
            ).fetchall()
            user_version = connection.execute("PRAGMA user_version").fetchone()[0]
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise SourceBindingError(f"source_schema_unreadable:{type(exc).__name__}") from exc
    document = json.dumps(
        {"user_version": int(user_version), "objects": rows},
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(document).hexdigest()


@dataclass(frozen=True)
class SourceSnapshot:
    path: str
    identity: str
    creation: str
    schema_hash: str


@dataclass(frozen=True)
class BattleFragment:
    installation: str
    world_generation: str
    message_id: str
    total_bytes: int
    fragment_index: int
    fragment_count: int
    fragment_bytes: bytes
    whole_crc32: int

    @property
    def key(self) -> tuple[str, str, str]:
        return self.installation, self.world_generation, self.message_id


def parse_fragment_payload(payload: bytes | bytearray | memoryview) -> BattleFragment:
    """Validate and copy one bounded native fragment payload."""

    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise FragmentValidationError("fragment_must_be_bytes")
    try:
        size = payload.nbytes if isinstance(payload, memoryview) else len(payload)
    except (TypeError, ValueError) as exc:
        raise FragmentValidationError("fragment_buffer_invalid") from exc
    if size < FRAGMENT_HEADER_BYTES:
        raise FragmentValidationError("fragment_header_truncated")
    if size > MAX_RECORD_BYTES:
        raise FragmentValidationError("fragment_record_too_large")
    try:
        raw = bytes(payload)
    except (BufferError, TypeError, ValueError) as exc:
        raise FragmentValidationError("fragment_buffer_invalid") from exc
    if len(raw) != size:
        raise FragmentValidationError("fragment_size_changed")
    (
        magic, header_bytes, flags, message_id, total_bytes, fragment_index,
        fragment_count, fragment_bytes, capacity_bytes, whole_crc32, reserved,
    ) = _HEADER.unpack(raw[:FRAGMENT_HEADER_BYTES])
    if magic != FRAGMENT_MAGIC:
        raise FragmentValidationError("fragment_magic_mismatch")
    if header_bytes != FRAGMENT_HEADER_BYTES:
        raise FragmentValidationError("fragment_header_size_mismatch")
    if flags != 0:
        raise FragmentValidationError("fragment_flags_must_be_zero")
    if message_id == 0:
        raise FragmentValidationError("fragment_message_id_must_not_be_zero")
    if not 1 <= total_bytes <= MAX_MESSAGE_BYTES:
        raise FragmentValidationError("fragment_total_out_of_range")
    expected_count = (total_bytes + FRAGMENT_CAPACITY_BYTES - 1) // FRAGMENT_CAPACITY_BYTES
    if fragment_count != expected_count:
        raise FragmentValidationError("fragment_count_mismatch")
    if not 0 <= fragment_index < fragment_count:
        raise FragmentValidationError("fragment_index_out_of_range")
    expected_bytes = min(
        FRAGMENT_CAPACITY_BYTES,
        total_bytes - fragment_index * FRAGMENT_CAPACITY_BYTES,
    )
    if fragment_bytes != expected_bytes:
        raise FragmentValidationError("fragment_length_mismatch")
    if capacity_bytes != FRAGMENT_CAPACITY_BYTES:
        raise FragmentValidationError("fragment_capacity_mismatch")
    if reserved != b"\x00" * 20:
        raise FragmentValidationError("fragment_reserved_bytes_nonzero")
    if len(raw) != FRAGMENT_HEADER_BYTES + fragment_bytes:
        raise FragmentValidationError("fragment_record_length_mismatch")
    return BattleFragment(
        installation="",
        world_generation="",
        message_id=str(message_id),
        total_bytes=total_bytes,
        fragment_index=fragment_index,
        fragment_count=fragment_count,
        fragment_bytes=bytes(raw[FRAGMENT_HEADER_BYTES:]),
        whole_crc32=whole_crc32,
    )


def build_fragment_payload(
        *, installation: str, world_generation: str, message_id: int,
        total_bytes: int, fragment_index: int, data: bytes,
        whole_crc32: int,
) -> bytes:
    """Test helper for deterministic opaque fragments.

    This helper writes the fixed binary container only; it does not create a
    transport JSONL envelope or claim native production provenance.
    """

    _validate_identity(installation, "installation")
    _validate_identity(world_generation, "world_generation")
    if isinstance(message_id, bool) or not isinstance(message_id, int):
        raise ValueError("message_id_must_be_integer")
    if not 1 <= message_id <= UINT64_MAX:
        raise ValueError("message_id_out_of_uint64_range")
    if isinstance(total_bytes, bool) or not isinstance(total_bytes, int):
        raise ValueError("total_bytes_must_be_integer")
    if not 1 <= total_bytes <= MAX_MESSAGE_BYTES:
        raise ValueError("total_bytes_out_of_range")
    expected_count = (total_bytes + FRAGMENT_CAPACITY_BYTES - 1) // FRAGMENT_CAPACITY_BYTES
    if not 0 <= fragment_index < expected_count:
        raise ValueError("fragment_index_out_of_range")
    if not isinstance(data, bytes):
        raise ValueError("data_must_be_bytes")
    expected_bytes = min(
        FRAGMENT_CAPACITY_BYTES,
        total_bytes - fragment_index * FRAGMENT_CAPACITY_BYTES,
    )
    if len(data) != expected_bytes:
        raise ValueError("data_length_mismatch")
    if isinstance(whole_crc32, bool) or not isinstance(whole_crc32, int):
        raise ValueError("crc32_must_be_integer")
    if not 0 <= whole_crc32 <= 0xFFFFFFFF:
        raise ValueError("crc32_out_of_range")
    header = _HEADER.pack(
        FRAGMENT_MAGIC, FRAGMENT_HEADER_BYTES, 0, message_id, total_bytes,
        fragment_index, expected_count, len(data), FRAGMENT_CAPACITY_BYTES,
        whole_crc32, b"\x00" * 20,
    )
    return header + data


class BattleReassemblyStore:
    """Durable source-cursor and opaque-fragment reassembly store."""

    def __init__(self, database: str | Path):
        self.database = str(database)
        if self.database != ":memory:":
            Path(self.database).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(
            self.database,
            isolation_level=None,
            check_same_thread=False,
            timeout=5.0,
        )
        self._connection.execute("PRAGMA synchronous = FULL")
        synchronous = self._connection.execute("PRAGMA synchronous").fetchone()[0]
        if int(synchronous) != 2:
            self._connection.close()
            raise ReassemblyPersistenceError("sqlite_synchronous_not_full")
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._lock = threading.RLock()
        self._closed = False
        self._create_schema()

    def _ensure_open(self) -> None:
        if self._closed:
            raise ReassemblyPersistenceError("reassembly_store_closed")

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS reassembly_cursor (
                cursor_id INTEGER PRIMARY KEY CHECK (cursor_id = 1),
                source_path TEXT NOT NULL,
                source_identity TEXT NOT NULL,
                source_creation TEXT NOT NULL,
                source_schema_hash TEXT NOT NULL,
                received_order INTEGER NOT NULL CHECK (received_order >= 0)
            );
            CREATE TABLE IF NOT EXISTS fragment_groups (
                group_id INTEGER PRIMARY KEY AUTOINCREMENT,
                installation TEXT NOT NULL,
                world_generation TEXT NOT NULL,
                message_id TEXT NOT NULL,
                total_bytes INTEGER NOT NULL,
                fragment_count INTEGER NOT NULL,
                whole_crc32 INTEGER NOT NULL,
                received_count INTEGER NOT NULL,
                pending_bytes INTEGER NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('pending','complete','conflicted','crc_error')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (installation, world_generation, message_id)
            );
            CREATE TABLE IF NOT EXISTS fragment_parts (
                group_id INTEGER NOT NULL,
                fragment_index INTEGER NOT NULL,
                fragment_bytes BLOB NOT NULL,
                fragment_sha256 TEXT NOT NULL,
                transport_received_order INTEGER NOT NULL,
                transport_attempt_sequence TEXT NOT NULL,
                received_at TEXT NOT NULL,
                PRIMARY KEY (group_id, fragment_index),
                FOREIGN KEY (group_id) REFERENCES fragment_groups(group_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS fragment_attempts (
                source_received_order INTEGER PRIMARY KEY,
                group_id INTEGER NOT NULL,
                fragment_index INTEGER NOT NULL,
                transport_attempt_sequence TEXT NOT NULL,
                transport_payload_sha256 TEXT NOT NULL,
                fragment_sha256 TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                FOREIGN KEY (group_id) REFERENCES fragment_groups(group_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS fragment_conflicts (
                conflict_id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL,
                fragment_index INTEGER NOT NULL,
                source_received_order INTEGER NOT NULL,
                reason TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                UNIQUE (group_id, fragment_index, source_received_order, reason),
                FOREIGN KEY (group_id) REFERENCES fragment_groups(group_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS complete_messages (
                group_id INTEGER PRIMARY KEY,
                payload BLOB NOT NULL,
                payload_sha256 TEXT NOT NULL,
                total_bytes INTEGER NOT NULL,
                whole_crc32 INTEGER NOT NULL,
                completed_at TEXT NOT NULL,
                FOREIGN KEY (group_id) REFERENCES fragment_groups(group_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS fragment_groups_page
                ON fragment_groups (group_id);
            CREATE INDEX IF NOT EXISTS fragment_attempts_group
                ON fragment_attempts (group_id, source_received_order);
            """
        )

    def _begin(self) -> None:
        self._connection.execute("BEGIN IMMEDIATE")

    def _commit(self) -> None:
        try:
            self._connection.commit()
        except Exception as exc:
            raise ReassemblyPersistenceError(
                f"reassembly_commit_failed:{type(exc).__name__}"
            ) from exc

    def _commit_checked(self) -> None:
        try:
            self._commit()
        except ReassemblyPersistenceError:
            raise
        except Exception as exc:
            raise ReassemblyPersistenceError(
                f"reassembly_commit_failed:{type(exc).__name__}"
            ) from exc

    def _rollback(self) -> None:
        try:
            self._connection.rollback()
        except sqlite3.Error:
            pass

    @staticmethod
    def _source_snapshot(store: BattleTransportStore) -> SourceSnapshot:
        database = getattr(store, "database", None)
        if not isinstance(database, (str, Path)) or str(database) == ":memory:":
            raise SourceBindingError("source_database_requires_file")
        path = Path(database).resolve()
        identity, creation = _stable_file_identity(path)
        return SourceSnapshot(
            path=str(path),
            identity=identity,
            creation=creation,
            schema_hash=_source_schema_hash(path),
        )

    def _cursor_row(self) -> dict[str, Any] | None:
        row = self._connection.execute(
            "SELECT source_path, source_identity, source_creation, "
            "source_schema_hash, received_order FROM reassembly_cursor "
            "WHERE cursor_id=1"
        ).fetchone()
        if row is None:
            return None
        return {
            "source_path": row[0],
            "source_identity": row[1],
            "source_creation": row[2],
            "source_schema_hash": row[3],
            "received_order": int(row[4]),
        }

    def _ensure_source_binding(self, source: SourceSnapshot) -> dict[str, Any]:
        cursor = self._cursor_row()
        if cursor is None:
            self._connection.execute(
                "INSERT INTO reassembly_cursor "
                "(cursor_id, source_path, source_identity, source_creation, "
                "source_schema_hash, received_order) VALUES (1, ?, ?, ?, ?, 0)",
                (source.path, source.identity, source.creation, source.schema_hash),
            )
            return {
                "source_path": source.path,
                "source_identity": source.identity,
                "source_creation": source.creation,
                "source_schema_hash": source.schema_hash,
                "received_order": 0,
            }
        if (
                cursor["source_path"] != source.path
                or cursor["source_identity"] != source.identity
                or cursor["source_creation"] != source.creation
                or cursor["source_schema_hash"] != source.schema_hash
        ):
            raise SourceBindingError("source_binding_changed")
        return cursor

    @staticmethod
    def _validate_bound_source(cursor: dict[str, Any] | None) -> None:
        """Recheck the persisted source file before reporting its status."""

        if cursor is None:
            return
        path = Path(str(cursor["source_path"]))
        identity, creation = _stable_file_identity(path)
        schema_hash = _source_schema_hash(path)
        if (
                identity != cursor["source_identity"]
                or creation != cursor["source_creation"]
                or schema_hash != cursor["source_schema_hash"]
        ):
            raise SourceBindingError("source_binding_changed")

    @staticmethod
    def _source_row(row: Any) -> tuple[int, str, bytes, str]:
        if not isinstance(row, dict):
            raise SourceBindingError("source_record_must_be_mapping")
        received_order = row.get("received_order")
        if isinstance(received_order, bool) or not isinstance(received_order, int):
            raise SourceBindingError("source_received_order_must_be_integer")
        if not 1 <= received_order <= (1 << 63) - 1:
            raise SourceBindingError("source_received_order_out_of_range")
        attempt = row.get("attempt_sequence")
        if not isinstance(attempt, str) or len(attempt) > 20 or _DECIMAL.fullmatch(attempt) is None:
            raise SourceBindingError("source_attempt_sequence_invalid")
        payload = row.get("payload")
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise SourceBindingError("source_payload_must_be_bytes")
        try:
            payload_size = payload.nbytes if isinstance(payload, memoryview) else len(payload)
        except (TypeError, ValueError) as exc:
            raise SourceBindingError("source_payload_buffer_invalid") from exc
        if not 1 <= payload_size <= MAX_RECORD_BYTES:
            raise SourceBindingError("source_payload_size_out_of_range")
        payload_copy = bytes(payload)
        claimed_sha = row.get("payload_sha256")
        actual_sha = hashlib.sha256(payload_copy).hexdigest()
        if claimed_sha is not None and claimed_sha != actual_sha:
            raise SourceBindingError("source_payload_hash_mismatch")
        return received_order, attempt, payload_copy, actual_sha

    def _group_row(self, fragment: BattleFragment) -> tuple[Any, ...] | None:
        return self._connection.execute(
            "SELECT group_id, total_bytes, fragment_count, whole_crc32, "
            "received_count, pending_bytes, status FROM fragment_groups "
            "WHERE installation=? AND world_generation=? AND message_id=?",
            fragment.key,
        ).fetchone()

    def _pending_capacity(self, *, new_group: bool, added_bytes: int) -> None:
        unfinished_groups = int(self._connection.execute(
            "SELECT COUNT(*) FROM fragment_groups WHERE status <> 'complete'"
        ).fetchone()[0])
        pending_bytes = int(self._connection.execute(
            "SELECT COALESCE(SUM(pending_bytes), 0) FROM fragment_groups "
            "WHERE status <> 'complete'"
        ).fetchone()[0])
        if new_group and unfinished_groups >= MAX_PENDING_GROUPS:
            raise _CapacityStop("unfinished_group_capacity_exhausted")
        if pending_bytes + added_bytes > MAX_PENDING_BYTES:
            raise _CapacityStop("pending_chunk_capacity_exhausted")

    def _record_attempt(
            self, *, source_received_order: int, group_id: int,
            fragment: BattleFragment, transport_attempt: str,
            transport_payload_sha256: str,
    ) -> None:
        fragment_sha = hashlib.sha256(fragment.fragment_bytes).hexdigest()
        self._connection.execute(
            "INSERT INTO fragment_attempts "
            "(source_received_order, group_id, fragment_index, "
            "transport_attempt_sequence, transport_payload_sha256, "
            "fragment_sha256, observed_at) VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(source_received_order) DO NOTHING",
            (
                source_received_order, group_id, fragment.fragment_index,
                transport_attempt, transport_payload_sha256, fragment_sha,
                _utc_now(),
            ),
        )

    def _latch_conflict(
            self, group_id: int, fragment_index: int,
            source_received_order: int, reason: str,
    ) -> None:
        self._connection.execute(
            "UPDATE fragment_groups SET status='conflicted', updated_at=? "
            "WHERE group_id=?",
            (_utc_now(), group_id),
        )
        self._connection.execute(
            "INSERT INTO fragment_conflicts "
            "(group_id, fragment_index, source_received_order, reason, observed_at) "
            "VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
            (group_id, fragment_index, source_received_order, reason, _utc_now()),
        )

    def _assemble_complete(
            self, group_id: int, fragment: BattleFragment,
            source_received_order: int,
    ) -> None:
        rows = self._connection.execute(
            "SELECT fragment_index, fragment_bytes FROM fragment_parts "
            "WHERE group_id=? ORDER BY fragment_index",
            (group_id,),
        ).fetchall()
        if len(rows) != fragment.fragment_count:
            self._latch_conflict(
                group_id, fragment.fragment_index, source_received_order,
                "fragment_count_state_mismatch",
            )
            raise _ConflictStop("fragment_count_state_mismatch")
        payload = b"".join(bytes(row[1]) for row in rows)
        if len(payload) != fragment.total_bytes:
            self._latch_conflict(
                group_id, fragment.fragment_index, source_received_order,
                "fragment_total_state_mismatch",
            )
            raise _ConflictStop("fragment_total_state_mismatch")
        if (zlib.crc32(payload) & 0xFFFFFFFF) != fragment.whole_crc32:
            self._connection.execute(
                "UPDATE fragment_groups SET status='crc_error', updated_at=? "
                "WHERE group_id=? AND status='pending'",
                (_utc_now(), group_id),
            )
            raise _CrcStop("whole_payload_crc32_mismatch")
        payload_sha = hashlib.sha256(payload).hexdigest()
        self._connection.execute(
            "INSERT INTO complete_messages "
            "(group_id, payload, payload_sha256, total_bytes, whole_crc32, completed_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                group_id, sqlite3.Binary(payload), payload_sha,
                fragment.total_bytes, fragment.whole_crc32, _utc_now(),
            ),
        )
        self._connection.execute(
            "UPDATE fragment_groups SET status='complete', pending_bytes=0, "
            "updated_at=? WHERE group_id=?",
            (_utc_now(), group_id),
        )

    def _apply_fragment(
            self, *, source_received_order: int, transport_attempt: str,
            transport_payload_sha256: str, fragment: BattleFragment,
    ) -> dict[str, Any]:
        row = self._group_row(fragment)
        if row is None:
            self._pending_capacity(new_group=True, added_bytes=len(fragment.fragment_bytes))
            cursor = self._connection.execute(
                "INSERT INTO fragment_groups "
                "(installation, world_generation, message_id, total_bytes, "
                "fragment_count, whole_crc32, received_count, pending_bytes, "
                "status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 0, 0, 'pending', ?, ?)",
                (
                    fragment.installation, fragment.world_generation, fragment.message_id,
                    fragment.total_bytes, fragment.fragment_count, fragment.whole_crc32,
                    _utc_now(), _utc_now(),
                ),
            )
            group_id = int(cursor.lastrowid)
            group_meta = (
                group_id, fragment.total_bytes, fragment.fragment_count,
                fragment.whole_crc32, 0, 0, "pending",
            )
        else:
            group_meta = row
            group_id, total, count, crc, received_count, pending_bytes, status = row
            group_id = int(group_id)
            self._record_attempt(
                source_received_order=source_received_order, group_id=group_id,
                fragment=fragment, transport_attempt=transport_attempt,
                transport_payload_sha256=transport_payload_sha256,
            )
            if (
                    int(total) != fragment.total_bytes
                    or int(count) != fragment.fragment_count
                    or int(crc) != fragment.whole_crc32
            ):
                self._latch_conflict(
                    group_id, fragment.fragment_index, source_received_order,
                    "fragment_group_metadata_conflict",
                )
                raise _ConflictStop("fragment_group_metadata_conflict")
            if status == "conflicted":
                raise _ConflictStop("fragment_group_conflicted")
            if status == "crc_error":
                raise _CrcStop("fragment_group_crc_error_latched")
            group_meta = (
                group_id, int(total), int(count), int(crc),
                int(received_count), int(pending_bytes), str(status),
            )
        group_id, _total, _count, _crc, _received_count, _pending_bytes, _status = group_meta
        existing = self._connection.execute(
            "SELECT fragment_bytes, fragment_sha256 FROM fragment_parts "
            "WHERE group_id=? AND fragment_index=?",
            (group_id, fragment.fragment_index),
        ).fetchone()
        fragment_sha = hashlib.sha256(fragment.fragment_bytes).hexdigest()
        if existing is not None:
            self._record_attempt(
                source_received_order=source_received_order, group_id=int(group_id),
                fragment=fragment, transport_attempt=transport_attempt,
                transport_payload_sha256=transport_payload_sha256,
            )
            if bytes(existing[0]) != fragment.fragment_bytes or existing[1] != fragment_sha:
                self._latch_conflict(
                    int(group_id), fragment.fragment_index, source_received_order,
                    "fragment_bytes_conflict",
                )
                raise _ConflictStop("fragment_bytes_conflict")
            return {"status": "duplicate", "duplicate": True, "completed": False}
        self._pending_capacity(new_group=False, added_bytes=len(fragment.fragment_bytes))
        self._connection.execute(
            "INSERT INTO fragment_parts "
            "(group_id, fragment_index, fragment_bytes, fragment_sha256, "
            "transport_received_order, transport_attempt_sequence, received_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                int(group_id), fragment.fragment_index,
                sqlite3.Binary(fragment.fragment_bytes), fragment_sha,
                source_received_order, transport_attempt, _utc_now(),
            ),
        )
        self._record_attempt(
            source_received_order=source_received_order, group_id=int(group_id),
            fragment=fragment, transport_attempt=transport_attempt,
            transport_payload_sha256=transport_payload_sha256,
        )
        new_count = int(_received_count) + 1
        new_pending = int(_pending_bytes) + len(fragment.fragment_bytes)
        self._connection.execute(
            "UPDATE fragment_groups SET received_count=?, pending_bytes=?, updated_at=? "
            "WHERE group_id=?",
            (new_count, new_pending, _utc_now(), int(group_id)),
        )
        completed = False
        if new_count == fragment.fragment_count:
            self._assemble_complete(int(group_id), fragment, source_received_order)
            completed = True
        return {"status": "completed" if completed else "accepted", "duplicate": False, "completed": completed}

    def _advance_cursor(self, expected: int, next_order: int) -> None:
        cursor = self._connection.execute(
            "UPDATE reassembly_cursor SET received_order=? "
            "WHERE cursor_id=1 AND received_order=?",
            (next_order, expected),
        )
        if cursor.rowcount != 1:
            raise ReassemblyCursorConflict("reassembly_cursor_compare_and_swap_failed")

    def _process_row(
            self, source: SourceSnapshot, expected_cursor: int, row: Any,
    ) -> tuple[dict[str, Any] | None, str | None]:
        received_order, transport_attempt, payload, payload_sha = self._source_row(row)
        if received_order <= expected_cursor:
            raise ReassemblyCursorConflict("source_received_order_not_after_cursor")
        fragment = parse_fragment_payload(payload)
        fragment = BattleFragment(
            installation=str(row.get("installation", "")),
            world_generation=str(row.get("world_generation", "")),
            message_id=fragment.message_id,
            total_bytes=fragment.total_bytes,
            fragment_index=fragment.fragment_index,
            fragment_count=fragment.fragment_count,
            fragment_bytes=fragment.fragment_bytes,
            whole_crc32=fragment.whole_crc32,
        )
        _validate_identity(fragment.installation, "installation")
        _validate_identity(fragment.world_generation, "world_generation")
        self._begin()
        try:
            current = self._cursor_row()
            if current is None or int(current["received_order"]) != expected_cursor:
                raise ReassemblyCursorConflict("reassembly_cursor_changed")
            outcome: dict[str, Any]
            try:
                outcome = self._apply_fragment(
                    source_received_order=received_order,
                    transport_attempt=transport_attempt,
                    transport_payload_sha256=payload_sha,
                    fragment=fragment,
                )
            except _CapacityStop:
                self._rollback()
                return None, "stopped_capacity"
            except _ConflictStop as exc:
                self._commit_checked()
                return {"reason": str(exc)}, "stopped_conflict"
            except _CrcStop as exc:
                self._commit_checked()
                return {"reason": str(exc)}, "stopped_crc_error"
            self._advance_cursor(expected_cursor, received_order)
            self._commit_checked()
            return outcome, None
        except Exception:
            self._rollback()
            raise

    def poll_from_store(
            self, store: BattleTransportStore, *, limit: int = MAX_POLL_ROWS,
    ) -> dict[str, Any]:
        """Consume a bounded page of already committed transport rows."""

        limit = _validate_page_limit(limit, "limit")
        with self._lock:
            self._ensure_open()
            source = self._source_snapshot(store)
            self._begin()
            try:
                cursor = self._ensure_source_binding(source)
                self._commit_checked()
            except Exception:
                self._rollback()
                raise
            expected = int(cursor["received_order"])
        rows = store.list_records(after_order=expected, limit=limit)
        if not rows:
            return {
                "status": "idle", "processed": 0, "completed": 0,
                "duplicates": 0, "received_order": expected,
                "transport_complete": False, "battle_complete": False,
                "overall_complete": False,
            }
        processed = 0
        completed = 0
        duplicates = 0
        current = expected
        for row in rows:
            with self._lock:
                self._ensure_open()
                current_source = self._source_snapshot(store)
                if current_source != source:
                    return {
                        "status": "source_binding_rejected",
                        "processed": processed, "completed": completed,
                        "duplicates": duplicates, "received_order": current,
                        "transport_complete": False, "battle_complete": False,
                        "overall_complete": False, "reason": "source_binding_changed",
                    }
                try:
                    outcome, stopped = self._process_row(source, current, row)
                except (FragmentValidationError, SourceBindingError) as exc:
                    return {
                        "status": "stopped_invalid_fragment",
                        "processed": processed, "completed": completed,
                        "duplicates": duplicates, "received_order": current,
                        "transport_complete": False, "battle_complete": False,
                        "overall_complete": False, "reason": str(exc),
                    }
                except ReassemblyCursorConflict as exc:
                    return {
                        "status": "cursor_conflict",
                        "processed": processed, "completed": completed,
                        "duplicates": duplicates, "received_order": current,
                        "transport_complete": False, "battle_complete": False,
                        "overall_complete": False, "reason": str(exc),
                    }
                except ReassemblyPersistenceError as exc:
                    return {
                        "status": "persistence_failed",
                        "processed": processed, "completed": completed,
                        "duplicates": duplicates, "received_order": current,
                        "transport_complete": False, "battle_complete": False,
                        "overall_complete": False, "reason": str(exc),
                    }
                if stopped is not None:
                    return {
                        "status": stopped, "processed": processed,
                        "completed": completed, "duplicates": duplicates,
                        "received_order": current,
                        "transport_complete": False, "battle_complete": False,
                        "overall_complete": False,
                        **({} if outcome is None else outcome),
                    }
                assert outcome is not None
                processed += 1
                current = int(row["received_order"])
                if outcome.get("completed"):
                    completed += 1
                if outcome.get("duplicate"):
                    duplicates += 1
        status = "budget_exhausted" if len(rows) >= limit else "advanced"
        return {
            "status": status, "processed": processed, "completed": completed,
            "duplicates": duplicates, "received_order": current,
            "transport_complete": False, "battle_complete": False,
            "overall_complete": False,
        }

    def _group_summary(self, row: tuple[Any, ...]) -> dict[str, Any]:
        (
            group_id, installation, world_generation, message_id, total_bytes,
            fragment_count, whole_crc32, received_count, pending_bytes, status,
            created_at, updated_at,
        ) = row
        missing: list[int] = []
        if status != "complete":
            present = {
                int(item[0]) for item in self._connection.execute(
                    "SELECT fragment_index FROM fragment_parts WHERE group_id=?",
                    (group_id,),
                ).fetchall()
            }
            missing = [index for index in range(int(fragment_count)) if index not in present]
        return {
            "group_id": int(group_id),
            "installation": installation,
            "world_generation": world_generation,
            "message_id": message_id,
            "total_bytes": int(total_bytes),
            "fragment_count": int(fragment_count),
            "whole_crc32": int(whole_crc32),
            "received_count": int(received_count),
            "pending_bytes": int(pending_bytes),
            "status": status,
            "missing_indices": missing,
            "created_at": created_at,
            "updated_at": updated_at,
            "transport_complete": status == "complete",
            "battle_complete": False,
            "overall_complete": False,
        }

    def list_groups(
            self, *, after_group_id: int | None = None,
            limit: int = DEFAULT_PAGE_LIMIT,
    ) -> dict[str, Any]:
        after_group_id = _validate_after_group(after_group_id)
        limit = _validate_page_limit(limit)
        with self._lock:
            self._ensure_open()
            query = (
                "SELECT group_id, installation, world_generation, message_id, "
                "total_bytes, fragment_count, whole_crc32, received_count, "
                "pending_bytes, status, created_at, updated_at FROM fragment_groups"
            )
            args: list[Any] = []
            if after_group_id is not None:
                query += " WHERE group_id > ?"
                args.append(after_group_id)
            query += " ORDER BY group_id LIMIT ?"
            args.append(limit)
            rows = self._connection.execute(query, args).fetchall()
            groups = [self._group_summary(row) for row in rows]
            if after_group_id is None:
                count_query = "SELECT COUNT(*) FROM fragment_groups"
                count_args: tuple[Any, ...] = ()
            else:
                count_query = "SELECT COUNT(*) FROM fragment_groups WHERE group_id > ?"
                count_args = (after_group_id,)
            total = int(self._connection.execute(count_query, count_args).fetchone()[0])
        next_group_id = groups[-1]["group_id"] if groups else after_group_id
        return {
            "groups": groups,
            "limit": limit,
            "returned": len(groups),
            "total": total,
            "truncated": total > len(groups),
            "next_group_id": next_group_id,
            "complete": False,
        }

    def status(self, *, limit: int = DEFAULT_PAGE_LIMIT) -> dict[str, Any]:
        limit = _validate_page_limit(limit)
        with self._lock:
            self._ensure_open()
            self._connection.execute("BEGIN")
            try:
                cursor = self._cursor_row()
                self._validate_bound_source(cursor)
                pending_groups, pending_bytes, complete_groups = self._connection.execute(
                    "SELECT "
                    "COALESCE(SUM(CASE WHEN status <> 'complete' THEN 1 ELSE 0 END), 0), "
                    "COALESCE(SUM(CASE WHEN status <> 'complete' THEN pending_bytes ELSE 0 END), 0), "
                    "COALESCE(SUM(CASE WHEN status = 'complete' THEN 1 ELSE 0 END), 0) "
                    "FROM fragment_groups"
                ).fetchone()
                rows = self._connection.execute(
                    "SELECT group_id, installation, world_generation, message_id, "
                    "total_bytes, fragment_count, whole_crc32, received_count, "
                    "pending_bytes, status, created_at, updated_at "
                    "FROM fragment_groups ORDER BY group_id LIMIT ?",
                    (limit,),
                ).fetchall()
                groups = [self._group_summary(row) for row in rows]
                total = int(self._connection.execute(
                    "SELECT COUNT(*) FROM fragment_groups"
                ).fetchone()[0])
                self._connection.commit()
            except Exception:
                self._rollback()
                raise
        return {
            "source": cursor,
            "groups": groups,
            "groups_limit": limit,
            "groups_returned": len(groups),
            "groups_total": total,
            "groups_truncated": total > len(groups),
            "unfinished_groups": int(pending_groups),
            "pending_chunk_bytes": int(pending_bytes),
            "complete_groups": int(complete_groups),
            "transport_complete": False,
            "battle_complete": False,
            "overall_complete": False,
            "consistent": True,
        }

    def get_message(
            self, installation: str, world_generation: str, message_id: str,
    ) -> dict[str, Any] | None:
        installation = _validate_identity(installation, "installation")
        world_generation = _validate_identity(world_generation, "world_generation")
        message_id = _validate_uint64_text(message_id)
        with self._lock:
            self._ensure_open()
            row = self._connection.execute(
                "SELECT g.group_id, g.total_bytes, g.whole_crc32, g.status, "
                "c.payload, c.payload_sha256, c.completed_at "
                "FROM fragment_groups g JOIN complete_messages c ON c.group_id=g.group_id "
                "WHERE g.installation=? AND g.world_generation=? AND g.message_id=?",
                (installation, world_generation, message_id),
            ).fetchone()
        if row is None or row[3] != "complete":
            return None
        payload = bytes(row[4])
        if len(payload) > MAX_MESSAGE_BYTES:
            raise ReassemblyPersistenceError("stored_message_exceeds_budget")
        return {
            "group_id": int(row[0]),
            "installation": installation,
            "world_generation": world_generation,
            "message_id": message_id,
            "payload": payload,
            "payload_bytes": len(payload),
            "payload_sha256": row[5],
            "whole_crc32": int(row[2]),
            "completed_at": row[6],
            "transport_complete": True,
            "battle_complete": False,
            "overall_complete": False,
        }

    def cursor(self) -> dict[str, Any] | None:
        with self._lock:
            self._ensure_open()
            return self._cursor_row()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._connection.close()
            self._closed = True

    def __enter__(self) -> "BattleReassemblyStore":
        self._ensure_open()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()


OpaqueBattleReassemblyStore = BattleReassemblyStore


__all__ = [
    "FRAGMENT_MAGIC",
    "FRAGMENT_HEADER_BYTES",
    "FRAGMENT_CAPACITY_BYTES",
    "MAX_RECORD_BYTES",
    "MAX_MESSAGE_BYTES",
    "MAX_PENDING_GROUPS",
    "MAX_PENDING_BYTES",
    "DEFAULT_PAGE_LIMIT",
    "MAX_POLL_ROWS",
    "FragmentValidationError",
    "SourceBindingError",
    "ReassemblyPersistenceError",
    "ReassemblyCursorConflict",
    "BattleFragment",
    "SourceSnapshot",
    "parse_fragment_payload",
    "build_fragment_payload",
    "BattleReassemblyStore",
    "OpaqueBattleReassemblyStore",
]
