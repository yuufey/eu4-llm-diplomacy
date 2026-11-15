"""Bounded, restart-safe ingestion of the checked local battle log.

The observer DLL and its control files are deliberately outside this module's
scope.  ``LiveBattleIngestor`` only tails the already checked JSONL file and
advances the existing transport/reassembly cursors in the caller-provided
SQLite database.  It never opens the game, sends a control request, or
performs a native query.
"""
from __future__ import annotations

from copy import deepcopy
import time
from pathlib import Path
import threading
from typing import Any

from .model import InformationError

from work.ingest_information_battle_raw_live import (
    RawIngestError,
    _load_binding,
)
from work.information_battle_log_reader import BattleLogTailer
from work.information_battle_log_reader import (
    FileLockBusy,
    MAX_HEADER_BYTES,
    acquire_file_lock,
    parse_log_header,
)
from work.information_battle_reassembly import BattleReassemblyStore
from work.information_battle_transport import BattleTransportStore


# Keep a refresh bounded even when a natural window appended many records.
# The underlying components retain their durable cursors, so another refresh
# continues exactly where this one stopped.
MAX_FRAMES_PER_REFRESH = 256
MAX_REASSEMBLY_ROWS_PER_REFRESH = 256
MAX_GROUPS_IN_SUMMARY = 64
COALESCE_SECONDS = 0.05

_TAIL_FAILURES = {
    "rejected_binding",
    "rejected_cursor",
    "rejected_truncation",
    "stopped_oversize",
    "stopped_read_error",
    "stopped_invalid_frame",
    "stopped_binding_mismatch",
    "stopped_receiver_error",
    "stopped_receiver_rejection",
    "cursor_conflict",
    "cursor_checkpoint_failed",
    "cursor_init_failed",
}
_REASSEMBLY_FAILURES = {
    "source_binding_rejected",
    "cursor_conflict",
    "persistence_failed",
    "stopped_invalid_fragment",
    "stopped_capacity",
    "stopped_conflict",
    "stopped_crc_error",
}


def _display_path(path: Path) -> str:
    """Return a stable, bounded path representation for a local summary."""

    return str(path)


def _failure(code: str, exc: BaseException) -> InformationError:
    if isinstance(exc, InformationError):
        return exc
    message = str(exc) or type(exc).__name__
    return InformationError(code, f"{type(exc).__name__}: {message}")


def _compact_poll(value: Any) -> dict[str, Any]:
    """Keep only scalar progress fields; never return payloads or group pages."""

    if not isinstance(value, dict):
        return {"status": "invalid_result", "complete": False}
    allowed = (
        "status", "offset", "size", "acked", "duplicates", "processed",
        "completed", "received_order", "complete", "reason",
        "transport_complete", "battle_complete", "overall_complete",
    )
    return {key: value[key] for key in allowed if key in value}


def _compact_cursor(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    allowed = (
        "offset", "received_order", "installation", "world_generation",
        "updated_at",
    )
    return {key: value[key] for key in allowed if key in value}


def _compact_transport(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"status": "invalid_result", "consistent": False}
    allowed = (
        "installation", "world_generation", "received_count",
        "first_sequence", "max_sequence", "observed_gap", "continuity",
        "observed_gaps_total", "open_gap_ranges_total", "consistent",
        "complete",
    )
    return {key: value[key] for key in allowed if key in value}


def _compact_reassembly_status(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"status": "invalid_result", "consistent": False}
    allowed = (
        "unfinished_groups", "pending_chunk_bytes", "complete_groups",
        "groups_total", "groups_returned", "groups_truncated",
        "transport_complete", "battle_complete", "overall_complete",
        "consistent",
    )
    result = {key: value[key] for key in allowed if key in value}
    result["status"] = "observed"
    return result


def _binding_key(binding: dict[str, Any]) -> tuple[Any, ...]:
    return (
        binding.get("pid"),
        binding.get("creation_filetime"),
        binding.get("session_id"),
        binding.get("dll_sha256"),
        binding.get("installation", {}).get("wire_hex"),
        binding.get("generation", {}).get("wire_hex"),
        binding.get("physical_player_ref", {}).get("raw_hex"),
    )


class LiveBattleIngestor:
    """Incrementally tail one installed battle log into a local SQLite DB.

    The installation JSON and its sibling binding are checked on every real
    refresh.  The first call opens the existing durable tailer, transport and
    reassembly stores; subsequent calls reuse them.  ``close`` is safe to call
    more than once and a new instance can reopen the same database without
    replaying already acknowledged frames.
    """

    def __init__(
            self, installation: str | Path, database: str | Path,
            expected_binding: dict[str, Any] | None = None,
    ):
        self.installation = Path(installation).expanduser().resolve()
        self.database = Path(database).expanduser().resolve()
        self.log_path = self.installation.parent / "information-battle-raw.jsonl"
        if not self.installation.is_file():
            raise InformationError(
                "invalid_battle_installation",
                f"Installation JSON does not exist: {self.installation}",
            )
        if self.database == self.installation or self.database == self.log_path:
            raise InformationError(
                "invalid_battle_database",
                "Battle ingestion database must differ from installation and log",
            )
        if self.database.exists() and not self.database.is_file():
            raise InformationError(
                "invalid_battle_database",
                f"Battle ingestion database is not a file: {self.database}",
            )
        if expected_binding is not None:
            if not isinstance(expected_binding, dict):
                raise InformationError(
                    "invalid_battle_expected_binding",
                    "Expected battle binding must be an object",
                )
            missing = {"session_id", "installation", "generation"} - set(expected_binding)
            if missing or any(
                    not isinstance(expected_binding.get(field), str)
                    or not expected_binding[field]
                    for field in ("session_id", "installation", "generation")
            ):
                raise InformationError(
                    "invalid_battle_expected_binding",
                    "Expected battle binding requires session_id, installation and generation",
                )
            self._expected_binding = {
                field: expected_binding[field]
                for field in ("session_id", "installation", "generation")
            }
        else:
            self._expected_binding = None
        self._lock = threading.RLock()
        self._transport: BattleTransportStore | None = None
        self._tailer: BattleLogTailer | None = None
        self._reassembly: BattleReassemblyStore | None = None
        self._binding: dict[str, Any] | None = None
        self._last_summary: dict[str, Any] | None = None
        self._last_refresh_monotonic = 0.0
        self._closed = False

    def _ensure_open(self) -> None:
        if self._closed:
            raise InformationError("battle_ingest_closed", "Battle ingestor is closed")

    def _read_binding(self) -> dict[str, Any]:
        try:
            binding, _pins, _raw = _load_binding(self.installation)
        except (RawIngestError, OSError, ValueError, TypeError) as exc:
            raise _failure("battle_ingest_binding_invalid", exc) from exc
        if self._expected_binding is not None:
            actual = {
                "session_id": binding["session_id"],
                "installation": binding["installation"]["wire_hex"],
                "generation": binding["generation"]["wire_hex"],
            }
            mismatches = [
                field for field in ("session_id", "installation", "generation")
                if actual[field] != self._expected_binding[field]
            ]
            if mismatches:
                raise InformationError(
                    "battle_ingest_expected_binding_mismatch",
                    "Source battle binding differs from installed ingestion binding: "
                    + ",".join(mismatches),
                )
        if self._binding is not None and _binding_key(binding) != _binding_key(self._binding):
            raise InformationError(
                "battle_ingest_binding_changed",
                "Installation/source binding changed while ingestion was open",
            )
        self._binding = binding
        if not self.log_path.is_file():
            raise InformationError(
                "battle_ingest_log_missing",
                f"Checked battle log does not exist: {self.log_path}",
            )
        self._check_log_header(binding)
        return binding

    def _check_log_header(self, binding: dict[str, Any]) -> None:
        """Compare the checked file header before opening any SQLite writer."""

        stream = None
        lease = None
        try:
            stream = self.log_path.open("rb")
            try:
                lease = acquire_file_lock(stream, exclusive=False)
            except FileLockBusy:
                # The tailer will return its existing bounded busy_no_progress
                # result.  A busy writer is not a binding mismatch.
                return
            header = parse_log_header(stream.readline(MAX_HEADER_BYTES + 1))
        except FileLockBusy:
            return
        except Exception as exc:
            raise _failure("battle_ingest_header_invalid", exc) from exc
        finally:
            if lease is not None:
                try:
                    lease.release()
                except Exception:
                    pass
            if stream is not None:
                stream.close()
        expected = (
            binding["installation"]["wire_hex"],
            binding["generation"]["wire_hex"],
        )
        actual = (header.installation, header.world_generation)
        if actual != expected:
            raise InformationError(
                "battle_ingest_header_binding_mismatch",
                "Checked battle log header does not match installation binding",
            )

    def _open_components(self) -> None:
        if self._transport is not None:
            return
        transport: BattleTransportStore | None = None
        tailer: BattleLogTailer | None = None
        reassembly: BattleReassemblyStore | None = None
        try:
            transport = BattleTransportStore(self.database)
            tailer = BattleLogTailer(
                self.log_path,
                self.database,
                receiver=transport,
                max_frames=MAX_FRAMES_PER_REFRESH,
            )
            reassembly = BattleReassemblyStore(self.database)
        except Exception as exc:
            for component in (reassembly, tailer, transport):
                if component is not None:
                    try:
                        component.close()
                    except Exception:
                        pass
            raise _failure("battle_ingest_open_failed", exc) from exc
        self._transport = transport
        self._tailer = tailer
        self._reassembly = reassembly

    @staticmethod
    def _hard_status(status: Any, failures: set[str]) -> bool:
        return isinstance(status, str) and (
            status in failures
            or (status.startswith("stopped_") and status != "stopped_no_progress")
        )

    def _summary(
            self, binding: dict[str, Any], tail_poll: dict[str, Any],
            tail_status: dict[str, Any], reassembly_poll: dict[str, Any],
            reassembly_status: dict[str, Any], transport_status: dict[str, Any],
            *, coalesced: bool,
    ) -> dict[str, Any]:
        tail_status_name = tail_poll.get("status")
        reassembly_status_name = reassembly_poll.get("status")
        if self._hard_status(tail_status_name, _TAIL_FAILURES):
            overall = str(tail_status_name)
        elif self._hard_status(reassembly_status_name, _REASSEMBLY_FAILURES):
            overall = str(reassembly_status_name)
        elif tail_status_name in {"advanced", "budget_exhausted"} or reassembly_status_name in {
                "advanced", "budget_exhausted"}:
            overall = "advanced"
        elif tail_status_name == "partial":
            overall = "partial"
        elif tail_status_name == "busy_no_progress":
            overall = "busy_no_progress"
        else:
            overall = "idle"
        return {
            "status": overall,
            "coalesced": coalesced,
            "complete": False,
            "battle_complete": False,
            "overall_complete": False,
            "source": {
                "installation": _display_path(self.installation),
                "log": _display_path(self.log_path),
                "database": _display_path(self.database),
                "installation_wire": binding["installation"]["wire_hex"],
                "world_generation_wire": binding["generation"]["wire_hex"],
                "session_id": binding["session_id"],
            },
            "tailer": {
                "poll": _compact_poll(tail_poll),
                "status": _compact_poll(tail_status),
                "cursor": _compact_cursor(self._tailer.cursor() if self._tailer else None),
            },
            "transport": _compact_transport(transport_status),
            "reassembly": {
                "poll": _compact_poll(reassembly_poll),
                "status": _compact_reassembly_status(reassembly_status),
                "cursor": _compact_cursor(self._reassembly.cursor() if self._reassembly else None),
            },
        }

    def refresh(self) -> dict[str, Any]:
        """Advance the durable pipeline once and return a bounded summary."""

        with self._lock:
            self._ensure_open()
            now = time.monotonic()
            if (self._last_summary is not None
                    and now - self._last_refresh_monotonic < COALESCE_SECONDS):
                summary = deepcopy(self._last_summary)
                summary["coalesced"] = True
                return summary

            binding = self._read_binding()
            self._open_components()
            assert self._transport is not None
            assert self._tailer is not None
            assert self._reassembly is not None
            try:
                tail_poll = self._tailer.poll()
                reassembly_poll = self._reassembly.poll_from_store(
                    self._transport,
                    limit=MAX_REASSEMBLY_ROWS_PER_REFRESH,
                )
                tail_status = self._tailer.status()
                transport_status = self._transport.stream_status(
                    binding["installation"]["wire_hex"],
                    binding["generation"]["wire_hex"],
                )
                reassembly_status = self._reassembly.status(limit=MAX_GROUPS_IN_SUMMARY)
            except Exception as exc:
                raise _failure("battle_ingest_failed", exc) from exc

            summary = self._summary(
                binding, tail_poll, tail_status, reassembly_poll,
                reassembly_status, transport_status, coalesced=False,
            )
            tail_failure = tail_poll.get("status")
            reassembly_failure = reassembly_poll.get("status")
            if self._hard_status(tail_failure, _TAIL_FAILURES):
                raise InformationError(
                    "battle_ingest_failed",
                    f"Checked battle log rejected progress: {tail_failure}"
                    + (f": {tail_poll.get('reason')}" if tail_poll.get("reason") else ""),
                )
            if self._hard_status(reassembly_failure, _REASSEMBLY_FAILURES):
                raise InformationError(
                    "battle_ingest_failed",
                    f"Battle reassembly rejected progress: {reassembly_failure}"
                    + (f": {reassembly_poll.get('reason')}" if reassembly_poll.get("reason") else ""),
                )
            self._last_summary = deepcopy(summary)
            self._last_refresh_monotonic = now
            return summary

    def close(self) -> None:
        """Close all persistent handles; repeated calls are harmless."""

        with self._lock:
            if self._closed:
                return
            self._closed = True
            errors: list[BaseException] = []
            for component in (self._reassembly, self._tailer, self._transport):
                if component is None:
                    continue
                try:
                    component.close()
                except Exception as exc:  # pragma: no cover - defensive close path
                    errors.append(exc)
            self._reassembly = None
            self._tailer = None
            self._transport = None
            if errors:
                raise _failure("battle_ingest_close_failed", errors[0])

    def __enter__(self) -> "LiveBattleIngestor":
        self._ensure_open()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()


__all__ = [
    "COALESCE_SECONDS",
    "LiveBattleIngestor",
    "MAX_FRAMES_PER_REFRESH",
    "MAX_REASSEMBLY_ROWS_PER_REFRESH",
]
