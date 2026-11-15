"""Lifecycle manager for the native EU4 battle capture source.

The information service owns subscriptions, while this module owns the small
piece of state needed to lease an already bootstrapped native battle source.
It deliberately does not know how to inject, advance, or persist game state.
The only native operations it can issue are ``status``, ``enable`` and
``disable`` through the control bridge.
"""

from __future__ import annotations

import copy
import json
import math
import os
import re
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping


try:  # pragma: no cover - exercised on POSIX only
    import fcntl  # type: ignore
except ImportError:  # pragma: no cover - exercised on Windows only
    fcntl = None  # type: ignore


Controller = Callable[[str, str | None], Mapping[str, Any]]


_HEX = re.compile(r"^[0-9a-fA-F]+$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_ALLOWED_COMMANDS = {"status", "enable", "disable"}
_JOURNAL_SCHEMA = "eu4-information-battle-capture/1"
_DEFAULT_JOURNAL_NAME = "information-battle-capture-journal.json"
_DEFAULT_LOCK_NAME = "information-battle-capture.lock"
_COMPLETED_TRANSITION_STATES = {"completed-enabled", "completed-disabled"}
_STATUS_FRESH_WAIT_SECONDS = 3.0
_STATUS_FRESH_WAIT_INTERVAL_SECONDS = 0.05

# A file lock is the inter-process guard.  This small in-process guard is
# needed as well because msvcrt locks are process-scoped on Windows and two
# handles in one process can otherwise both appear to acquire the lock.
_LOCAL_LOCK_GUARD = threading.RLock()
_LOCAL_LOCK_PATHS: set[str] = set()


class _CaptureError(RuntimeError):
    """An expected capture-manager failure which must not trigger a retry."""


def _now() -> float:
    return time.time()


def _now_ns() -> int:
    return time.time_ns()


def _as_int(value: Any, *, base: int | None = None) -> int:
    if isinstance(value, bool):
        raise _CaptureError("boolean is not an integer identity")
    if isinstance(value, int):
        if value < 0:
            raise _CaptureError("negative integer identity")
        return value
    if not isinstance(value, str) or not value:
        raise _CaptureError("missing integer identity")
    try:
        if base is not None:
            result = int(value, base)
        elif value.isdigit():
            result = int(value, 10)
        elif _HEX.fullmatch(value):
            result = int(value, 16)
        else:
            raise ValueError(value)
    except (TypeError, ValueError) as exc:
        raise _CaptureError("invalid integer identity") from exc
    if result < 0:
        raise _CaptureError("negative integer identity")
    return result


def _binding_u64(value: Any) -> int:
    """Parse a wire binding id, whose string representation is hexadecimal."""

    if isinstance(value, str):
        # Battle stream bindings use fixed-width hex16.  Accept a short
        # decimal spelling too so injected controllers and older operator
        # records can be checked without changing the wire contract.
        if len(value) == 16:
            return _as_int(value, base=16)
        if value.isdigit():
            return _as_int(value, base=10)
        return _as_int(value, base=16)
    return _as_int(value)


def _sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise _CaptureError(f"invalid {name}")
    return value.lower()


def _same_hash(left: Any, right: Any) -> bool:
    return isinstance(left, str) and isinstance(right, str) and left.lower() == right.lower()


def _canonical_path(path: Path) -> str:
    # ``strict=False`` keeps construction and journal comparison usable before
    # the installation file has been created.  This is not called by the
    # constructor, so construction itself has no filesystem/game I/O.
    return str(path.resolve(strict=False))


class BattleCaptureManager:
    """Lease and, when owned, stop a bootstrapped native battle source.

    ``expected_binding`` is the binding already established by the battle
    stream bootstrap.  It is used only for identity checks; in particular its
    historical ``observer_ref`` is never sent to the native controller.
    """

    def __init__(
        self,
        installation_path: str | os.PathLike[str],
        expected_binding: Mapping[str, Any],
        *,
        controller: Controller | None = None,
        journal_path: str | os.PathLike[str] | None = None,
    ) -> None:
        self.installation_path = Path(installation_path).expanduser()
        try:
            self.expected_binding = copy.deepcopy(dict(expected_binding))
        except (TypeError, ValueError):
            # Keep construction side-effect free; reconcile reports the
            # malformed operator binding as unavailable.
            self.expected_binding = {}
        self.journal_path = Path(journal_path) if journal_path is not None else (
            self.installation_path.parent / _DEFAULT_JOURNAL_NAME
        )
        self.lock_path = self.installation_path.parent / _DEFAULT_LOCK_NAME
        self._controller: Controller = controller or self._default_controller

        self._lock_handle: Any = None
        self._lock_key: str | None = None
        self._closed = False
        self._consumers: set[str] = set()
        self._producer_state = "unknown"
        self._managed = False
        self._owned = False
        self._reason = "not_reconciled"
        self._complete = False
        self._latched_unavailable = False
        self._identity: dict[str, Any] | None = None
        self._journal: dict[str, Any] | None = None

    @property
    def is_closed(self) -> bool:
        return self._closed

    def _default_controller(self, command: str, player_ref: str | None = None) -> Mapping[str, Any]:
        # Lazy import is intentional: constructing a manager must not inspect
        # the game or call the native bridge.
        from tools.control_information_battle_observer import run_control

        return run_control(self.installation_path, command, player_ref)

    def snapshot(self) -> dict[str, Any]:
        """Return manager state without reading files or calling the controller."""

        status = "closed" if self._closed else (
            "unavailable" if self._latched_unavailable else (
                "active" if self._consumers else "idle"
            )
        )
        return {
            "status": status,
            # Presence of this manager is the operator's explicit choice to
            # manage capture.  Lease/ownership transitions are represented by
            # ``consumer_count`` and ``owned``; they must not make the source
            # look unmanaged after the final release or after close.
            "producer_state": "unavailable" if self._latched_unavailable else self._producer_state,
            "managed": True,
            "owned": bool(self._owned),
            "consumer_count": len(self._consumers),
            "consumers": sorted(self._consumers),
            "reason": self._reason,
            "complete": bool(self._complete),
        }

    def reconcile(self, consumers: set[str]) -> dict[str, Any]:
        """Reconcile the source lease with the current active consumer set."""

        if self._closed:
            return self._unavailable("manager_closed")

        try:
            requested = self._normalize_consumers(consumers)
        except _CaptureError as exc:
            return self._unavailable(str(exc))

        had_consumers = bool(self._consumers)
        if requested:
            # ``managed`` means that this operator opted into the lease.  It
            # remains true while reconciliation is unavailable so the caller
            # cannot mistake a failed manager for an unmanaged read-only
            # source.  ``owned`` separately controls whether disable is safe.
            self._managed = True

        if self._latched_unavailable:
            self._consumers = requested
            if not requested and not self._owned:
                # An unavailable borrowed/pending source has no ownership
                # claim to protect.  Release its lease as soon as the last
                # consumer disappears; an owned unknown source stays locked
                # until explicit close.
                self._managed = False
                self._release_lock()
            return self.snapshot()

        if not requested:
            if self._consumers:
                self._consumers = set()
                self._release_owned_source()
            else:
                self._consumers = set()
            return self.snapshot()

        if not self._ensure_lock():
            self._consumers = requested
            return self._unavailable("capture_lock_unavailable")

        self._consumers = requested
        if self._identity is None:
            try:
                self._identity = self._read_identity()
            except _CaptureError as exc:
                return self._unavailable(str(exc))

        if self._journal is None:
            try:
                self._journal = self._read_journal()
            except _CaptureError as exc:
                return self._unavailable(str(exc))

        if self._journal is not None:
            if not self._journal_identity_matches(self._journal):
                return self._unavailable("journal_identity_mismatch")
            journal_state = self._journal.get("state")
            if journal_state in {
                "pending-enable",
                "pending-disable",
                "unknown-enable",
                "unknown-disable",
                "unknown-status",
            }:
                return self._unavailable(f"journal_{journal_state}")
            if journal_state == "completed-enabled":
                if self._journal.get("owned") is not True:
                    return self._unavailable("journal_ownership_invalid")
                self._owned = True
                self._managed = True
            elif journal_state not in {None, "completed-disabled"}:
                return self._unavailable("journal_state_invalid")

        record = self._status_record()
        if record is None:
            return self.snapshot()
        state = record["state"]

        if state == "enabled":
            if self._owned:
                self._managed = True
                self._producer_state = "enabled"
                self._reason = "owned_source_recovered" if self._journal else "owned_source"
                return self.snapshot()
            # A source that was enabled outside this manager is borrowed.  It
            # is never stopped by this manager, even after the final consumer.
            # ``managed`` describes the active subscription lease; ``owned``
            # separately records whether this manager is allowed to stop the
            # native source.  An external source is therefore managed for the
            # lease while remaining unowned.
            self._managed = True
            self._owned = False
            self._producer_state = "enabled"
            self._reason = "external_source"
            return self.snapshot()

        if state == "disabled":
            # An existing manager must never silently restart a source which
            # disappeared while it had consumers.
            if had_consumers:
                return self._unavailable("source_disabled")
            if not record.get("player_ref"):
                return self._unavailable("source_unbound")
            return self._enable_once(record)

        if state == "ready":
            return self._unavailable("source_ready_unbound")
        return self._unavailable(f"source_{state}")

    def close(self) -> dict[str, Any]:
        """Stop an owned source once when safe, then release the process lock."""

        if self._closed:
            return self.snapshot()

        if self._consumers:
            self._consumers = set()
            if not self._latched_unavailable:
                self._release_owned_source()
        elif self._owned and not self._latched_unavailable:
            self._release_owned_source()

        self._release_lock()
        self._closed = True
        self._managed = False
        if not self._latched_unavailable and not self._owned:
            self._reason = self._reason if self._reason != "not_reconciled" else "closed"
        return self.snapshot()

    @staticmethod
    def _normalize_consumers(consumers: Iterable[str]) -> set[str]:
        if isinstance(consumers, (str, bytes)):
            raise _CaptureError("consumers must be a set of strings")
        try:
            normalized = set(consumers)
        except (TypeError, ValueError) as exc:
            raise _CaptureError("consumers must be a set of strings") from exc
        if any(not isinstance(item, str) or not item for item in normalized):
            raise _CaptureError("consumers must contain non-empty strings")
        return normalized

    def _unavailable(self, reason: str) -> dict[str, Any]:
        self._latched_unavailable = True
        self._producer_state = "unavailable" if self._producer_state == "unknown" else self._producer_state
        self._reason = reason
        return self.snapshot()

    def _ensure_lock(self) -> bool:
        if self._lock_handle is not None:
            return True
        lock_key = os.path.normcase(_canonical_path(self.lock_path))
        with _LOCAL_LOCK_GUARD:
            if lock_key in _LOCAL_LOCK_PATHS:
                return False
            handle = None
            try:
                self.lock_path.parent.mkdir(parents=True, exist_ok=True)
                handle = open(self.lock_path, "a+b")
                if os.name == "nt":
                    import msvcrt  # type: ignore

                    handle.seek(0)
                    if handle.tell() == 0 and os.path.getsize(self.lock_path) == 0:
                        handle.write(b"\0")
                        handle.flush()
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    if fcntl is None:  # pragma: no cover
                        handle.close()
                        return False
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (OSError, IOError):
                if handle is not None:
                    try:
                        handle.close()
                    except Exception:
                        pass
                return False
            _LOCAL_LOCK_PATHS.add(lock_key)
            self._lock_key = lock_key
            self._lock_handle = handle
            return True

    def _release_lock(self) -> None:
        handle = self._lock_handle
        if handle is None:
            return
        try:
            if os.name == "nt":
                import msvcrt  # type: ignore

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            elif fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except (OSError, IOError):
            pass
        try:
            handle.close()
        finally:
            with _LOCAL_LOCK_GUARD:
                if self._lock_key is not None:
                    _LOCAL_LOCK_PATHS.discard(self._lock_key)
            self._lock_handle = None
            self._lock_key = None

    def _read_identity(self) -> dict[str, Any]:
        try:
            raw = self.installation_path.read_bytes()
        except OSError as exc:
            raise _CaptureError("installation_unreadable") from exc
        if len(raw) > 1024 * 1024:
            raise _CaptureError("installation_too_large")
        try:
            installation = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _CaptureError("installation_invalid_json") from exc
        if not isinstance(installation, dict):
            raise _CaptureError("installation_invalid")

        try:
            pid = _as_int(installation.get("pid"))
            creation = _as_int(installation.get("creation_filetime"))
            game_sha = _sha(installation.get("game_sha256"), "game_sha256")
            dll_sha = _sha(installation.get("dll_sha256"), "dll_sha256")
            expected_installation = _binding_u64(self.expected_binding.get("installation"))
            expected_generation = _binding_u64(self.expected_binding.get("generation"))
            expected_game_sha = _sha(self.expected_binding.get("game_sha256"), "expected game_sha256")
        except _CaptureError:
            raise
        if creation != expected_generation:
            raise _CaptureError("binding_generation_mismatch")
        if pid == 0 or creation == 0 or expected_installation == 0 or expected_generation == 0:
            raise _CaptureError("binding_identity_zero")
        if game_sha != expected_game_sha:
            raise _CaptureError("binding_game_mismatch")
        expected_dll = self.expected_binding.get("dll_sha256")
        if expected_dll is not None and not _same_hash(dll_sha, expected_dll):
            raise _CaptureError("binding_dll_mismatch")
        return {
            "installation_path": _canonical_path(self.installation_path),
            "installation": expected_installation,
            "generation": expected_generation,
            "pid": pid,
            "creation_filetime": creation,
            "game_sha256": game_sha,
            "dll_sha256": dll_sha,
        }

    def _read_journal(self) -> dict[str, Any] | None:
        try:
            raw = self.journal_path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise _CaptureError("journal_unreadable") from exc
        if len(raw) > 1024 * 1024:
            raise _CaptureError("journal_too_large")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _CaptureError("journal_invalid_json") from exc
        if not isinstance(value, dict) or value.get("schema") != _JOURNAL_SCHEMA:
            raise _CaptureError("journal_invalid")
        if not isinstance(value.get("state"), str):
            raise _CaptureError("journal_invalid_state")
        if not isinstance(value.get("identity"), dict):
            raise _CaptureError("journal_identity_missing")
        return value

    def _journal_identity_matches(self, journal: Mapping[str, Any]) -> bool:
        identity = journal.get("identity")
        if not isinstance(identity, Mapping) or self._identity is None:
            return False
        # Identity values are written canonically by this class.  Comparing
        # the complete object prevents an old game process from being treated
        # as the current source.
        return dict(identity) == self._identity

    @staticmethod
    def _journal_updated_at_ns(journal: Mapping[str, Any]) -> int | None:
        value = journal.get("updated_at_ns")
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
        # Journals written before updated_at_ns used a JSON float in seconds.
        # Keep those completed transitions recoverable while using nanoseconds
        # for all new freshness comparisons.
        legacy = journal.get("updated_at")
        if isinstance(legacy, bool) or not isinstance(legacy, (int, float)):
            return None
        try:
            legacy_float = float(legacy)
        except (TypeError, ValueError, OverflowError):
            return None
        if not math.isfinite(legacy_float) or legacy_float < 0:
            return None
        return int(legacy_float * 1_000_000_000)

    def _completed_transition_time_ns(self) -> int | None:
        if self._journal is None or self._journal.get("state") not in _COMPLETED_TRANSITION_STATES:
            return None
        updated_at_ns = self._journal_updated_at_ns(self._journal)
        if updated_at_ns is None:
            raise _CaptureError("journal_transition_time_missing")
        return updated_at_ns

    def _write_journal(self, state: str, *, owned: bool, nonce: str | None = None) -> None:
        if self._identity is None:
            raise _CaptureError("identity_unavailable")
        updated_at_ns = _now_ns()
        record = {
            "schema": _JOURNAL_SCHEMA,
            "state": state,
            "owned": bool(owned),
            "identity": copy.deepcopy(self._identity),
            "nonce": nonce,
            "updated_at": updated_at_ns / 1_000_000_000,
            "updated_at_ns": updated_at_ns,
        }
        try:
            self.journal_path.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(
                prefix=f".{self.journal_path.name}.",
                suffix=".tmp",
                dir=str(self.journal_path.parent),
            )
        except OSError as exc:
            raise _CaptureError("journal_write_failed") from exc
        try:
            data = json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.journal_path)
            if os.name != "nt":
                try:
                    directory_fd = os.open(self.journal_path.parent, os.O_RDONLY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
                except OSError:
                    pass
        except Exception as exc:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            if isinstance(exc, _CaptureError):
                raise
            raise _CaptureError("journal_write_failed") from exc
        self._journal = record

    def _status_record(self) -> dict[str, Any] | None:
        try:
            transition_time_ns = self._completed_transition_time_ns()
            deadline = (
                time.monotonic() + _STATUS_FRESH_WAIT_SECONDS
                if transition_time_ns is not None
                else None
            )
            while True:
                result = self._call_controller("status")
                record = self._parse_status(result)
                if transition_time_ns is None:
                    break
                observed_at_ns = record.get("observed_at_ns")
                if not isinstance(observed_at_ns, int) or isinstance(observed_at_ns, bool):
                    raise _CaptureError("status_observed_at_missing")
                if observed_at_ns > transition_time_ns:
                    break
                remaining = (deadline or time.monotonic()) - time.monotonic()
                if remaining <= 0:
                    raise _CaptureError("status_stale_timeout")
                time.sleep(min(_STATUS_FRESH_WAIT_INTERVAL_SECONDS, remaining))
        except _CaptureError as exc:
            # A status exception leaves the native ownership relationship
            # unknown.  Persist that fact so a fresh host cannot guess and
            # issue an enable/disable after this manager exits.
            try:
                if self._identity is not None:
                    self._write_journal("unknown-status", owned=self._owned)
            except _CaptureError:
                pass
            self._producer_state = "unavailable"
            self._unavailable(str(exc))
            return None
        self._producer_state = record["state"]
        return record

    def _call_controller(self, command: str, player_ref: str | None = None) -> Mapping[str, Any]:
        if command not in _ALLOWED_COMMANDS:
            raise _CaptureError("unsupported_controller_command")
        try:
            result = self._controller(command, player_ref)
        except Exception as exc:
            native_reason = getattr(exc, "reason", None)
            suffix = str(native_reason) if isinstance(native_reason, str) and native_reason else "exception"
            raise _CaptureError(f"controller_{command}_{suffix}") from exc
        if not isinstance(result, Mapping):
            raise _CaptureError(f"controller_{command}_invalid_result")
        return result

    def _parse_status(self, result: Mapping[str, Any]) -> dict[str, Any]:
        native = result.get("native")
        if not isinstance(native, Mapping):
            # A small direct form keeps injected controllers easy to write,
            # while the real bridge always returns the nested native object.
            native = result
        state = native.get("state")
        if state not in {"cold", "ready", "enabled", "disabled", "source_changed", "fault", "restart_required"}:
            raise _CaptureError("status_state_invalid")
        if self._identity is None:
            raise _CaptureError("identity_unavailable")
        observed_at_value = result.get("observed_at_ns", native.get("observed_at_ns"))
        observed_at_ns: int | None = None
        if observed_at_value is not None:
            observed_at_ns = _as_int(observed_at_value)

        try:
            pid = _as_int(native.get("pid"))
            creation = _as_int(native.get("creation_filetime"))
            native_installation = _as_int(native.get("installation"))
            native_generation = _as_int(native.get("generation"))
            dll_sha = _sha(native.get("dll_sha256"), "status dll_sha256")
        except _CaptureError:
            raise _CaptureError("status_identity_invalid")
        if pid == 0 or creation == 0:
            raise _CaptureError("status_identity_zero")
        if pid != self._identity["pid"] or creation != self._identity["creation_filetime"]:
            raise _CaptureError("source_identity_changed")
        if not _same_hash(dll_sha, self._identity["dll_sha256"]):
            raise _CaptureError("source_dll_changed")
        exe_sha = native.get("exe_sha256", native.get("game_sha256"))
        if exe_sha is not None and not _same_hash(exe_sha, self._identity["game_sha256"]):
            raise _CaptureError("source_game_changed")

        bound_identity = native_installation == self._identity["installation"] and native_generation == self._identity["generation"]
        binding = result.get("binding")
        if binding is None:
            binding = native.get("binding")
        player_ref: str | None = None
        if binding is not None:
            if not isinstance(binding, Mapping):
                raise _CaptureError("status_binding_invalid")
            try:
                if _as_int(binding.get("installation")) != self._identity["installation"]:
                    raise _CaptureError("status_binding_installation_mismatch")
                if _as_int(binding.get("generation")) != self._identity["generation"]:
                    raise _CaptureError("status_binding_generation_mismatch")
                if _as_int(binding.get("pid")) != self._identity["pid"]:
                    raise _CaptureError("status_binding_pid_mismatch")
                if _as_int(binding.get("creation_filetime")) != self._identity["creation_filetime"]:
                    raise _CaptureError("status_binding_creation_mismatch")
                binding_game = binding.get("game_sha256")
                if binding_game is not None and not _same_hash(binding_game, self._identity["game_sha256"]):
                    raise _CaptureError("status_binding_game_mismatch")
                binding_dll = binding.get("dll_sha256")
                if binding_dll is not None and not _same_hash(binding_dll, self._identity["dll_sha256"]):
                    raise _CaptureError("status_binding_dll_mismatch")
            except _CaptureError:
                raise
            player_ref_value = binding.get("player_ref")
            if (
                not isinstance(player_ref_value, str)
                or not _HEX.fullmatch(player_ref_value)
                or len(player_ref_value) != 16
                or int(player_ref_value, 16) == 0
            ):
                raise _CaptureError("status_player_ref_invalid")
            player_ref = player_ref_value

        if state in {"enabled", "disabled"} and (not bound_identity or player_ref is None):
            if not bound_identity:
                raise _CaptureError("source_binding_identity_mismatch")
            raise _CaptureError("source_unbound")
        if state in {"ready", "cold"} and native_installation == 0 and native_generation == 0:
            bound_identity = False
        return {
            "state": state,
            "player_ref": player_ref,
            "bound_identity": bound_identity,
            "observed_at_ns": observed_at_ns,
            "native": dict(native),
        }

    def _enable_once(self, record: Mapping[str, Any]) -> dict[str, Any]:
        if self._journal is not None and self._journal.get("state") not in {None, "completed-disabled"}:
            return self._unavailable("journal_enable_already_attempted")
        try:
            self._write_journal("pending-enable", owned=False)
        except _CaptureError as exc:
            return self._unavailable(str(exc))
        player_ref = record.get("player_ref")
        if not isinstance(player_ref, str):
            return self._unavailable("source_unbound")
        try:
            result = self._call_controller("enable", player_ref)
            self._verify_transition(result, "enabled")
        except _CaptureError as exc:
            try:
                self._write_journal("unknown-enable", owned=False)
            except _CaptureError:
                pass
            return self._unavailable(str(exc))
        nonce = result.get("nonce")
        if nonce is None:
            response = result.get("response")
            nonce = response.get("request_id") if isinstance(response, Mapping) else None
        try:
            self._write_journal("completed-enabled", owned=True, nonce=str(nonce))
        except _CaptureError as exc:
            # The source is already enabled but ownership cannot be recovered
            # safely, so leave it borrowed and latch until a fresh manager.
            self._owned = False
            self._producer_state = "unavailable"
            return self._unavailable(str(exc))
        self._owned = True
        self._managed = True
        self._producer_state = "enabled"
        self._reason = "owned_source"
        return self.snapshot()

    def _verify_transition(self, result: Mapping[str, Any], expected_state: str) -> None:
        if result.get("status") != "accepted":
            raise _CaptureError("controller_transition_not_accepted")
        response = result.get("response")
        if not isinstance(response, Mapping):
            response = result
        if response.get("accepted") is not True:
            raise _CaptureError("controller_transition_not_accepted")
        nonce = result.get("nonce")
        request_id = response.get("request_id")
        if nonce is None:
            nonce = request_id
        if nonce is None or (request_id is not None and str(request_id) != str(nonce)):
            raise _CaptureError("controller_transition_nonce_invalid")
        state = response.get("state", result.get("state"))
        if state != expected_state:
            raise _CaptureError("controller_transition_state_invalid")
        if self._identity is None:
            raise _CaptureError("identity_unavailable")
        try:
            if _as_int(response.get("pid")) != self._identity["pid"]:
                raise _CaptureError("controller_transition_pid_invalid")
            if _as_int(response.get("creation_filetime")) != self._identity["creation_filetime"]:
                raise _CaptureError("controller_transition_creation_invalid")
            if _as_int(response.get("installation")) != self._identity["installation"]:
                raise _CaptureError("controller_transition_installation_invalid")
            generation = response.get("generation", self._identity["generation"])
            if _as_int(generation) != self._identity["generation"]:
                raise _CaptureError("controller_transition_generation_invalid")
            if not _same_hash(response.get("dll_sha256"), self._identity["dll_sha256"]):
                raise _CaptureError("controller_transition_dll_invalid")
            game_sha = response.get("exe_sha256", response.get("game_sha256", self._identity["game_sha256"]))
            if not _same_hash(game_sha, self._identity["game_sha256"]):
                raise _CaptureError("controller_transition_game_invalid")
        except _CaptureError:
            raise

    def _release_owned_source(self) -> None:
        if not self._owned:
            self._managed = False
            self._release_lock()
            return
        if self._latched_unavailable:
            return
        record = self._status_record()
        if record is None:
            return
        if record["state"] != "enabled" or not record.get("bound_identity"):
            self._unavailable("source_not_safely_enabled")
            return
        player_ref = record.get("player_ref")
        if not isinstance(player_ref, str):
            self._unavailable("source_unbound")
            return
        try:
            self._write_journal("pending-disable", owned=True)
            result = self._call_controller("disable", player_ref)
            self._verify_transition(result, "disabled")
            nonce = result.get("nonce")
            if nonce is None:
                response = result.get("response")
                nonce = response.get("request_id") if isinstance(response, Mapping) else None
            self._write_journal("completed-disabled", owned=False, nonce=str(nonce))
        except _CaptureError as exc:
            try:
                self._write_journal("unknown-disable", owned=True)
            except _CaptureError:
                pass
            self._producer_state = "unavailable"
            self._unavailable(str(exc))
            return
        self._owned = False
        self._managed = False
        self._producer_state = "disabled"
        self._reason = "capture_disabled"
        self._release_lock()


__all__ = ["BattleCaptureManager"]
