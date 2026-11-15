"""Offline receiver and durable store for owned battle-record wire frames.

The native producer owns the meaning of ``payload``.  This module validates
only the transport envelope, copies the opaque bytes into SQLite, and exposes
the identity/sequence bookkeeping needed by a later delivery adapter.  It is
deliberately independent of ``bridge`` and does not claim that a frame is a
complete or semantically decoded battle report.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import threading
from typing import Any, Iterable


EVENT = "information_owned_battle_record"
WIRE_VERSION = 1
PAYLOAD_ENCODING = "hex"
MAX_PAYLOAD_BYTES = 4096
MIN_PAYLOAD_BYTES = 1
UINT64_MAX = (1 << 64) - 1
MAX_WIRE_BYTES = 16 * 1024
DEFAULT_PAGE_LIMIT = 256
MAX_PAGE_LIMIT = 1024

_WIRE_KEYS = frozenset({
    "event",
    "wire_version",
    "installation",
    "world_generation",
    "attempt_sequence",
    "payload_encoding",
    "payload_bytes",
    "payload_hex",
})
_HEX16 = re.compile(r"[0-9a-f]{16}\Z")
_DECIMAL = re.compile(r"[0-9]+\Z")
_PAYLOAD_HEX = re.compile(r"(?:[0-9a-f]{2})+\Z")


def _validate_page_limit(value: Any, field: str = "limit") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field}_must_be_integer")
    if not 1 <= value <= MAX_PAGE_LIMIT:
        raise ValueError(f"{field}_out_of_range")
    return value


def _validate_after_order(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("after_order_must_be_integer_or_none")
    if value < 0:
        raise ValueError("after_order_must_not_be_negative")
    return value


class TransportError(ValueError):
    """Base class for malformed or unsupported transport input."""


class FrameValidationError(TransportError):
    """Raised when a JSONL frame violates the wire contract."""


class PersistenceError(RuntimeError):
    """Raised internally when a durable transaction cannot be committed."""


def _reject_constant(value: str) -> None:
    raise FrameValidationError(f"non_finite_json_number:{value}")


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FrameValidationError(f"duplicate_key:{key}")
        result[key] = value
    return result


def _required_string(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise FrameValidationError(f"{field}_must_be_string")
    return value


def _required_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise FrameValidationError(f"{field}_must_be_integer")
    return value


def _validate_hex_identity(value: Any, field: str) -> str:
    value = _required_string(value, field)
    if _HEX16.fullmatch(value) is None:
        raise FrameValidationError(f"{field}_must_be_lower_hex16")
    if value == "0" * 16:
        raise FrameValidationError(f"{field}_must_not_be_zero")
    return value


def _validate_sequence(value: Any) -> tuple[str, int]:
    value = _required_string(value, "attempt_sequence")
    # UINT64_MAX has 20 decimal digits.  Bound the text before int() so a
    # hostile frame cannot force an unbounded decimal conversion.
    if len(value) > 20:
        raise FrameValidationError("attempt_sequence_too_long")
    if _DECIMAL.fullmatch(value) is None or value == "0" or (
            len(value) > 1 and value[0] == "0"):
        raise FrameValidationError("attempt_sequence_must_be_canonical_decimal")
    number = int(value, 10)
    if not 1 <= number <= UINT64_MAX:
        raise FrameValidationError("attempt_sequence_out_of_uint64_range")
    return value, number


@dataclass(frozen=True)
class BattleFrame:
    """A validated frame with copied opaque payload and original wire bytes."""

    installation: str
    world_generation: str
    attempt_sequence: str
    payload: bytes
    wire: bytes
    payload_sha256: str

    @property
    def payload_bytes(self) -> int:
        return len(self.payload)

    def stream_key(self) -> tuple[str, str]:
        return self.installation, self.world_generation

    def identity_key(self) -> tuple[str, str, str]:
        return self.installation, self.world_generation, self.attempt_sequence


def parse_wire_frame(line: bytes | bytearray | memoryview) -> BattleFrame:
    """Validate one complete newline-delimited frame.

    Bytes are decoded strictly as UTF-8.  The returned payload and wire are
    copies, so callers may reuse or mutate their input buffer immediately.
    """

    if not isinstance(line, (bytes, bytearray, memoryview)):
        raise FrameValidationError("wire_must_be_bytes")
    try:
        input_size = line.nbytes if isinstance(line, memoryview) else len(line)
    except (TypeError, ValueError) as exc:
        raise FrameValidationError("wire_buffer_invalid") from exc
    if input_size > MAX_WIRE_BYTES:
        raise FrameValidationError("wire_too_large")
    try:
        wire = bytes(line)
    except (BufferError, TypeError, ValueError) as exc:
        raise FrameValidationError("wire_buffer_invalid") from exc
    if len(wire) > MAX_WIRE_BYTES:
        raise FrameValidationError("wire_too_large")
    if not wire.endswith(b"\n") or wire.count(b"\n") != 1:
        raise FrameValidationError("wire_must_contain_one_terminal_newline")
    body = wire[:-1]
    if body.endswith(b"\r"):
        body = body[:-1]
    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise FrameValidationError("wire_invalid_utf8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_constant,
        )
    except FrameValidationError:
        raise
    except RecursionError as exc:
        raise FrameValidationError("wire_json_too_deep") from exc
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise FrameValidationError("wire_invalid_json") from exc
    if not isinstance(value, dict):
        raise FrameValidationError("wire_root_must_be_object")
    unknown = sorted(set(value) - _WIRE_KEYS)
    missing = sorted(_WIRE_KEYS - set(value))
    if unknown:
        raise FrameValidationError(f"wire_unknown_keys:{unknown}")
    if missing:
        raise FrameValidationError(f"wire_missing_keys:{missing}")
    if _required_string(value["event"], "event") != EVENT:
        raise FrameValidationError("event_mismatch")
    if _required_int(value["wire_version"], "wire_version") != WIRE_VERSION:
        raise FrameValidationError("wire_version_mismatch")
    installation = _validate_hex_identity(value["installation"], "installation")
    world_generation = _validate_hex_identity(value["world_generation"], "world_generation")
    attempt_sequence, _sequence_number = _validate_sequence(value["attempt_sequence"])
    if _required_string(value["payload_encoding"], "payload_encoding") != PAYLOAD_ENCODING:
        raise FrameValidationError("payload_encoding_mismatch")
    payload_bytes = _required_int(value["payload_bytes"], "payload_bytes")
    if not MIN_PAYLOAD_BYTES <= payload_bytes <= MAX_PAYLOAD_BYTES:
        raise FrameValidationError("payload_bytes_out_of_range")
    payload_hex = _required_string(value["payload_hex"], "payload_hex")
    if _PAYLOAD_HEX.fullmatch(payload_hex) is None:
        raise FrameValidationError("payload_hex_must_be_lower_even_hex")
    if len(payload_hex) != payload_bytes * 2:
        raise FrameValidationError("payload_bytes_does_not_match_payload_hex")
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError as exc:  # guarded by the regex, retained as defense in depth
        raise FrameValidationError("payload_hex_invalid") from exc
    if len(payload) != payload_bytes:
        raise FrameValidationError("payload_decode_length_mismatch")
    return BattleFrame(
        installation=installation,
        world_generation=world_generation,
        attempt_sequence=attempt_sequence,
        payload=bytes(payload),
        wire=bytes(wire),
        payload_sha256=hashlib.sha256(payload).hexdigest(),
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class BattleTransportStore:
    """Durable opaque-frame receiver with stream-local sequence observations.

    ``installation`` and ``world_generation`` are part of every primary key.
    Sequence numbers remain decimal TEXT in SQLite so UINT64_MAX is represented
    exactly; Python integers are used only for bounded comparisons.  An
    observed gap is retained as history even when later frames fill it, so a
    stream never upgrades to a claim of complete/lossless delivery.
    """

    def __init__(self, database: str | Path):
        self.database = str(database)
        if self.database != ":memory:":
            Path(self.database).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(
            self.database,
            isolation_level=None,
            check_same_thread=False,
        )
        # FULL is part of the persistence contract: acknowledgement is only
        # returned after SQLite has committed with the strongest synchronous
        # setting available for this connection.
        self._connection.execute("PRAGMA synchronous = FULL")
        synchronous = self._connection.execute("PRAGMA synchronous").fetchone()[0]
        if int(synchronous) != 2:  # SQLITE_FULL
            self._connection.close()
            raise PersistenceError("sqlite_synchronous_not_full")
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._lock = threading.RLock()
        self._closed = False
        self._create_schema()

    def _ensure_open(self) -> None:
        if self._closed:
            raise PersistenceError("store_closed")

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS battle_records (
                installation TEXT NOT NULL,
                world_generation TEXT NOT NULL,
                attempt_sequence TEXT NOT NULL,
                payload BLOB NOT NULL,
                payload_sha256 TEXT NOT NULL,
                payload_bytes INTEGER NOT NULL,
                wire BLOB NOT NULL,
                received_order INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at TEXT NOT NULL,
                UNIQUE (installation, world_generation, attempt_sequence)
            );
            CREATE INDEX IF NOT EXISTS battle_records_stream_order
                ON battle_records (installation, world_generation, received_order);
            CREATE TABLE IF NOT EXISTS battle_streams (
                installation TEXT NOT NULL,
                world_generation TEXT NOT NULL,
                first_sequence TEXT NOT NULL,
                max_sequence TEXT NOT NULL,
                received_count INTEGER NOT NULL,
                observed_gap INTEGER NOT NULL,
                PRIMARY KEY (installation, world_generation)
            );
            CREATE TABLE IF NOT EXISTS observed_gaps (
                gap_id INTEGER PRIMARY KEY AUTOINCREMENT,
                installation TEXT NOT NULL,
                world_generation TEXT NOT NULL,
                start_sequence TEXT NOT NULL,
                end_sequence TEXT NOT NULL,
                observed_by_sequence TEXT NOT NULL,
                observed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS open_gap_ranges (
                gap_id INTEGER NOT NULL,
                start_sequence TEXT NOT NULL,
                end_sequence TEXT NOT NULL,
                PRIMARY KEY (gap_id, start_sequence, end_sequence),
                FOREIGN KEY (gap_id) REFERENCES observed_gaps(gap_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS open_gap_stream
                ON open_gap_ranges (gap_id);
            CREATE INDEX IF NOT EXISTS observed_gap_stream_order
                ON observed_gaps (installation, world_generation, gap_id);
            """
        )

    def _begin(self) -> None:
        self._connection.execute("BEGIN IMMEDIATE")

    def _commit(self) -> None:
        """Small seam used by tests to prove failed commits do not ack."""

        self._connection.commit()

    def _rollback(self) -> None:
        try:
            self._connection.rollback()
        except sqlite3.Error:
            pass

    @staticmethod
    def _stream_where(frame: BattleFrame) -> tuple[str, str]:
        return frame.installation, frame.world_generation

    def _insert_observed_gap(
            self, frame: BattleFrame, start: int, end: int
    ) -> int:
        if start > end:
            raise ValueError("empty_gap")
        cursor = self._connection.execute(
            "INSERT INTO observed_gaps "
            "(installation, world_generation, start_sequence, end_sequence, "
            "observed_by_sequence, observed_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                frame.installation,
                frame.world_generation,
                str(start),
                str(end),
                frame.attempt_sequence,
                _utc_now(),
            ),
        )
        gap_id = int(cursor.lastrowid)
        self._connection.execute(
            "INSERT INTO open_gap_ranges (gap_id, start_sequence, end_sequence) "
            "VALUES (?, ?, ?)", (gap_id, str(start), str(end))
        )
        return gap_id

    def _fill_open_gaps(self, frame: BattleFrame, sequence: int) -> None:
        sequence_text = frame.attempt_sequence
        sequence_length = len(sequence_text)
        rows = self._connection.execute(
            "SELECT open_gap_ranges.gap_id, open_gap_ranges.start_sequence, "
            "open_gap_ranges.end_sequence FROM open_gap_ranges "
            "JOIN observed_gaps USING (gap_id) "
            "WHERE observed_gaps.installation=? AND observed_gaps.world_generation=? "
            "AND (LENGTH(open_gap_ranges.start_sequence) < ? OR "
            "(LENGTH(open_gap_ranges.start_sequence) = ? "
            "AND open_gap_ranges.start_sequence <= ?)) "
            "AND (LENGTH(open_gap_ranges.end_sequence) > ? OR "
            "(LENGTH(open_gap_ranges.end_sequence) = ? "
            "AND open_gap_ranges.end_sequence >= ?)) "
            "ORDER BY LENGTH(open_gap_ranges.start_sequence), "
            "open_gap_ranges.start_sequence LIMIT 2",
            (*self._stream_where(frame), sequence_length, sequence_length,
             sequence_text, sequence_length, sequence_length, sequence_text),
        ).fetchall()
        if len(rows) > 1:
            raise PersistenceError("overlapping_gap_ranges")
        for gap_id, start_text, end_text in rows:
            start, end = int(start_text), int(end_text)
            self._connection.execute(
                "DELETE FROM open_gap_ranges WHERE gap_id=? AND start_sequence=? AND end_sequence=?",
                (gap_id, start_text, end_text),
            )
            if start <= sequence - 1:
                self._connection.execute(
                    "INSERT INTO open_gap_ranges (gap_id, start_sequence, end_sequence) VALUES (?, ?, ?)",
                    (gap_id, str(start), str(sequence - 1)),
                )
            if sequence + 1 <= end:
                self._connection.execute(
                    "INSERT INTO open_gap_ranges (gap_id, start_sequence, end_sequence) VALUES (?, ?, ?)",
                    (gap_id, str(sequence + 1), str(end)),
                )

    def _open_gap_ranges(
            self, frame: BattleFrame, limit: int,
    ) -> tuple[list[dict[str, str]], int]:
        total = int(self._connection.execute(
            "SELECT COUNT(*) FROM open_gap_ranges "
            "JOIN observed_gaps USING (gap_id) "
            "WHERE observed_gaps.installation=? AND observed_gaps.world_generation=?",
            self._stream_where(frame),
        ).fetchone()[0])
        cursor = self._connection.execute(
            "SELECT open_gap_ranges.gap_id, open_gap_ranges.start_sequence, "
            "open_gap_ranges.end_sequence "
            "FROM open_gap_ranges JOIN observed_gaps USING (gap_id) "
            "WHERE observed_gaps.installation=? AND observed_gaps.world_generation=? "
            "ORDER BY open_gap_ranges.gap_id, LENGTH(open_gap_ranges.start_sequence), "
            "open_gap_ranges.start_sequence LIMIT ?",
            (*self._stream_where(frame), limit),
        )
        rows = cursor.fetchmany(limit)
        return [
            {"gap_id": str(gap_id), "start_sequence": start, "end_sequence": end}
            for gap_id, start, end in rows
        ], total

    def _observed_gaps(
            self, frame: BattleFrame, limit: int,
    ) -> tuple[list[dict[str, str]], int]:
        total = int(self._connection.execute(
            "SELECT COUNT(*) FROM observed_gaps "
            "WHERE installation=? AND world_generation=?",
            self._stream_where(frame),
        ).fetchone()[0])
        cursor = self._connection.execute(
            "SELECT gap_id, start_sequence, end_sequence, observed_by_sequence, observed_at "
            "FROM observed_gaps WHERE installation=? AND world_generation=? "
            "ORDER BY gap_id LIMIT ?",
            (*self._stream_where(frame), limit),
        )
        rows = cursor.fetchmany(limit)
        return [
            {
                "gap_id": str(gap_id),
                "start_sequence": start,
                "end_sequence": end,
                "observed_by_sequence": observed_by,
                "observed_at": observed_at,
            }
            for gap_id, start, end, observed_by, observed_at in rows
        ], total

    def _result(
            self, frame: BattleFrame, *, status: str, ack: bool,
            inserted: bool = False, idempotent: bool = False,
            conflict: bool = False, reason: str | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ack": ack,
            "status": status,
            "inserted": inserted,
            "idempotent": idempotent,
            "conflict": conflict,
            "installation": frame.installation,
            "world_generation": frame.world_generation,
            "attempt_sequence": frame.attempt_sequence,
            "payload_sha256": frame.payload_sha256,
        }
        if reason is not None:
            result["reason"] = reason
        return result

    def ingest_line(self, line: bytes | bytearray | memoryview) -> dict[str, Any]:
        """Validate, persist, and return an acknowledgement decision.

        A successful insertion is acknowledged only after SQLite commit.  A
        parse rejection, conflict, or transaction failure never overwrites an
        existing record and never leaves a partial record behind.
        """

        try:
            frame = parse_wire_frame(line)
        except FrameValidationError as exc:
            return {
                "ack": False,
                "status": "rejected",
                "inserted": False,
                "idempotent": False,
                "conflict": False,
                "reason": str(exc),
            }
        with self._lock:
            self._ensure_open()
            try:
                self._begin()
                # Keep the identity lookup inside the write transaction.  A
                # second process waiting on BEGIN IMMEDIATE therefore observes
                # the committed first insert and can return an idempotent ack
                # instead of racing into a uniqueness error.
                existing = self._connection.execute(
                    "SELECT payload, payload_sha256 FROM battle_records "
                    "WHERE installation=? AND world_generation=? AND attempt_sequence=?",
                    frame.identity_key(),
                ).fetchone()
                if existing is not None:
                    self._rollback()
                    old_payload, old_sha = bytes(existing[0]), str(existing[1])
                    if old_payload == frame.payload and old_sha == frame.payload_sha256:
                        return self._result(
                            frame, status="duplicate", ack=True, idempotent=True
                        )
                    return self._result(
                        frame, status="conflict", ack=False, conflict=True,
                        reason="identity_sequence_payload_conflict",
                    )
                stream = self._connection.execute(
                    "SELECT first_sequence, max_sequence, received_count, observed_gap "
                    "FROM battle_streams WHERE installation=? AND world_generation=?",
                    self._stream_where(frame),
                ).fetchone()
                sequence = int(frame.attempt_sequence)
                if stream is None:
                    self._connection.execute(
                        "INSERT INTO battle_streams "
                        "(installation, world_generation, first_sequence, max_sequence, received_count, observed_gap) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            frame.installation,
                            frame.world_generation,
                            frame.attempt_sequence,
                            frame.attempt_sequence,
                            1,
                            int(sequence > 1),
                        ),
                    )
                    if sequence > 1:
                        self._insert_observed_gap(frame, 1, sequence - 1)
                else:
                    first, max_text, count, observed_gap = stream
                    maximum = int(max_text)
                    if sequence > maximum:
                        if sequence > maximum + 1:
                            self._insert_observed_gap(frame, maximum + 1, sequence - 1)
                        maximum = sequence
                    else:
                        self._fill_open_gaps(frame, sequence)
                    self._connection.execute(
                        "UPDATE battle_streams SET max_sequence=?, received_count=?, observed_gap=? "
                        "WHERE installation=? AND world_generation=?",
                        (
                            str(maximum),
                            int(count) + 1,
                            int(bool(observed_gap) or sequence > int(max_text) + 1),
                            *self._stream_where(frame),
                        ),
                    )
                self._connection.execute(
                    "INSERT INTO battle_records "
                    "(installation, world_generation, attempt_sequence, payload, payload_sha256, "
                    "payload_bytes, wire, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        frame.installation,
                        frame.world_generation,
                        frame.attempt_sequence,
                        sqlite3.Binary(frame.payload),
                        frame.payload_sha256,
                        frame.payload_bytes,
                        sqlite3.Binary(frame.wire),
                        _utc_now(),
                    ),
                )
                self._commit()
            except Exception as exc:
                self._rollback()
                return self._result(
                    frame, status="persistence_failed", ack=False,
                    reason=f"{type(exc).__name__}:{exc}",
                )
            return self._result(frame, status="inserted", ack=True, inserted=True)

    # Explicit alias for callers that use the transport vocabulary.
    receive = ingest_line

    def get_record(
            self, installation: str, world_generation: str, attempt_sequence: str
    ) -> dict[str, Any] | None:
        """Return a durable record; the payload and wire are fresh byte copies."""

        with self._lock:
            self._ensure_open()
            row = self._connection.execute(
                "SELECT installation, world_generation, attempt_sequence, payload, "
                "payload_sha256, payload_bytes, wire, received_order, received_at "
                "FROM battle_records WHERE installation=? AND world_generation=? AND attempt_sequence=?",
                (installation, world_generation, attempt_sequence),
            ).fetchone()
        if row is None:
            return None
        return {
            "installation": row[0],
            "world_generation": row[1],
            "attempt_sequence": row[2],
            "payload": bytes(row[3]),
            "payload_sha256": row[4],
            "payload_bytes": row[5],
            "wire": bytes(row[6]),
            "received_order": row[7],
            "received_at": row[8],
        }

    def list_records(
            self, installation: str | None = None,
            world_generation: str | None = None,
            *, after_order: int | None = None,
            limit: int = DEFAULT_PAGE_LIMIT,
    ) -> list[dict[str, Any]]:
        after_order = _validate_after_order(after_order)
        limit = _validate_page_limit(limit)
        with self._lock:
            self._ensure_open()
            query = (
                "SELECT installation, world_generation, attempt_sequence, payload, "
                "payload_sha256, payload_bytes, wire, received_order, received_at "
                "FROM battle_records"
            )
            args: list[Any] = []
            clauses: list[str] = []
            if installation is not None:
                clauses.append("installation=?"); args.append(installation)
            if world_generation is not None:
                clauses.append("world_generation=?"); args.append(world_generation)
            if after_order is not None:
                clauses.append("received_order > ?"); args.append(after_order)
            if clauses:
                query += " WHERE " + " AND ".join(clauses)
            query += " ORDER BY received_order LIMIT ?"
            args.append(limit)
            cursor = self._connection.execute(query, args)
            rows = cursor.fetchmany(limit)
        return [
            {
                "installation": row[0],
                "world_generation": row[1],
                "attempt_sequence": row[2],
                "payload": bytes(row[3]),
                "payload_sha256": row[4],
                "payload_bytes": row[5],
                "wire": bytes(row[6]),
                "received_order": row[7],
                "received_at": row[8],
            }
            for row in rows
        ]

    def stream_status(
            self, installation: str, world_generation: str, *,
            gap_limit: int = DEFAULT_PAGE_LIMIT,
    ) -> dict[str, Any]:
        gap_limit = _validate_page_limit(gap_limit, "gap_limit")
        with self._lock:
            self._ensure_open()
            # Establish one SQLite read snapshot before reading the stream,
            # gap counts, and bounded pages.  A second Store cannot make the
            # returned scalars and pages describe different database states.
            self._connection.execute("BEGIN")
            try:
                stream = self._connection.execute(
                    "SELECT first_sequence, max_sequence, received_count, observed_gap "
                    "FROM battle_streams WHERE installation=? AND world_generation=?",
                    (installation, world_generation),
                ).fetchone()
                probe = BattleFrame(
                    installation=installation,
                    world_generation=world_generation,
                    attempt_sequence="1",
                    payload=b"x",
                    wire=b"",
                    payload_sha256=hashlib.sha256(b"x").hexdigest(),
                )
                observed, observed_total = self._observed_gaps(probe, gap_limit)
                open_ranges, open_total = self._open_gap_ranges(probe, gap_limit)
                self._connection.commit()
            except Exception:
                self._rollback()
                raise
        observed_page = {
            "limit": gap_limit,
            "returned": len(observed),
            "total": observed_total,
            "truncated": observed_total > len(observed),
        }
        open_page = {
            "limit": gap_limit,
            "returned": len(open_ranges),
            "total": open_total,
            "truncated": open_total > len(open_ranges),
        }
        if stream is None:
            return {
                "installation": installation,
                "world_generation": world_generation,
                "received_count": 0,
                "first_sequence": None,
                "max_sequence": None,
                "observed_gap": False,
                "continuity": "no_records",
                "complete": False,
                "observed_gaps": observed,
                "open_gap_ranges": open_ranges,
                "observed_gaps_total": observed_total,
                "observed_gaps_truncated": observed_page["truncated"],
                "open_gap_ranges_total": open_total,
                "open_gap_ranges_truncated": open_page["truncated"],
                "gap_limit": gap_limit,
                "observed_gaps_page": observed_page,
                "open_gap_ranges_page": open_page,
                "consistent": True,
                "read_snapshot": {"consistent": True},
            }
        first, maximum, count, observed_gap = stream
        return {
            "installation": installation,
            "world_generation": world_generation,
            "received_count": int(count),
            "first_sequence": first,
            "max_sequence": maximum,
            "observed_gap": bool(observed_gap),
            "continuity": "observed_gap" if observed_gap else "contiguous_so_far",
            # Even after late filling, an observed gap remains historical and
            # therefore never turns into a proof of complete delivery.
            "complete": False,
            "observed_gaps": observed,
            "open_gap_ranges": open_ranges,
            "observed_gaps_total": observed_total,
            "observed_gaps_truncated": observed_page["truncated"],
            "open_gap_ranges_total": open_total,
            "open_gap_ranges_truncated": open_page["truncated"],
            "gap_limit": gap_limit,
            "observed_gaps_page": observed_page,
            "open_gap_ranges_page": open_page,
            "consistent": True,
            "read_snapshot": {"consistent": True},
        }

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def __enter__(self) -> "BattleTransportStore":
        self._ensure_open()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()


# Friendly aliases for the eventual transport adapter without coupling this
# module to a native hook or InformationService.
InformationBattleTransport = BattleTransportStore
BattleTransportReceiver = BattleTransportStore


__all__ = [
    "EVENT",
    "WIRE_VERSION",
    "PAYLOAD_ENCODING",
    "MAX_PAYLOAD_BYTES",
    "DEFAULT_PAGE_LIMIT",
    "MAX_PAGE_LIMIT",
    "UINT64_MAX",
    "BattleFrame",
    "TransportError",
    "FrameValidationError",
    "PersistenceError",
    "parse_wire_frame",
    "BattleTransportStore",
    "InformationBattleTransport",
    "BattleTransportReceiver",
]
