"""Offline receiver for the checked live information-battle raw log.

This module composes the existing checked-log tailer, transport store, and
fragment reassembler.  It does not open the game process, issue a control
command, interpret a native pointer, or call an InformationService API.  The
only persistent writes are to the caller-provided local SQLite database and
the exclusive JSON report.

The reassembler's ``transport_complete`` flag describes one complete raw
fragment group.  It is kept separate from stream continuity and from the
business/battle completeness flags, which remain false.  A decoded payload is
still the bounded observation callback snapshot, not a public battle report.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

# Keep the documented ``python work/<script>.py`` entry point usable as well
# as ``python -m work.<module>``.  The receiver itself remains offline; this
# only makes the repository package importable from a direct script launch.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from work.information_battle_log_reader import BattleLogTailer
from work.information_battle_context_wire import (
    MAX_WIRE_BYTES as MAX_CONTEXT_WIRE_BYTES,
    ContextWireError,
    decode as decode_context,
)
from work.information_battle_naval_wire import (
    MAX_WIRE_BYTES as MAX_NAVAL_WIRE_BYTES,
    NavalWireError,
    decode as decode_naval,
)
from work.information_battle_template_wire import (
    MAX_WIRE_BYTES as MAX_TEMPLATE_WIRE_BYTES,
    TemplateWireError,
    decode as decode_template,
)
try:
    from work.information_battle_war_identity_wire import (
        MAX_WIRE_BYTES as MAX_WAR_IDENTITY_WIRE_BYTES,
        WarIdentityWireError,
        decode as decode_war_identity,
    )
except ImportError:  # v5 decoder is added independently; old ingest remains importable
    MAX_WAR_IDENTITY_WIRE_BYTES = MAX_TEMPLATE_WIRE_BYTES
    WarIdentityWireError = ValueError
    decode_war_identity = None
from work.information_battle_observation_wire import (
    MAX_WIRE_BYTES as MAX_OBSERVATION_WIRE_BYTES,
    ObservationWireError,
    decode as decode_observation,
)
from work.information_battle_native_text_wire import (
    MAX_WIRE_BYTES as MAX_NATIVE_TEXT_WIRE_BYTES,
    NativeTextWireError,
    decode as decode_native_text,
)
from work.information_battle_display_context_wire import (
    MAX_WIRE_BYTES as MAX_DISPLAY_CONTEXT_WIRE_BYTES,
    DisplayContextWireError,
    decode as decode_display_context,
)
from work.information_battle_name_handoff_wire import (
    MAX_WIRE_BYTES as MAX_NAME_HANDOFF_WIRE_BYTES,
    NameHandoffWireError,
    decode as decode_name_handoff,
)
from work.information_battle_end_state_wire import (
    MAX_WIRE_BYTES as MAX_END_STATE_WIRE_BYTES,
    EndStateWireError,
    decode as decode_end_state,
)
from work.information_battle_retreat_wire import (
    MAX_WIRE_BYTES as MAX_RETREAT_WIRE_BYTES,
    RetreatWireError,
    decode as decode_retreat,
)
from work.information_battle_name_sources_wire import (
    MAX_WIRE_BYTES as MAX_NAME_SOURCES_WIRE_BYTES,
    NameSourcesWireError,
    decode as decode_name_sources,
)
from work.information_battle_outcome_text_wire import (
    MAX_WIRE_BYTES as MAX_OUTCOME_TEXT_WIRE_BYTES,
    OutcomeTextWireError,
    decode as decode_outcome_text,
)
from work.information_battle_outcome_tail_wire import (
    MAX_WIRE_BYTES as MAX_OUTCOME_TAIL_WIRE_BYTES,
    OutcomeTailWireError,
    decode as decode_outcome_tail,
)
from work.information_battle_independent_line_wire import (
    MAX_WIRE_BYTES as MAX_INDEPENDENT_LINE_WIRE_BYTES,
    IndependentLineWireError,
    decode as decode_independent_line,
)
from work.information_battle_flag_inputs_wire import (
    MAX_WIRE_BYTES as MAX_FLAG_INPUT_WIRE_BYTES,
    FlagInputsWireError,
    decode as decode_flag_inputs,
)
from work.information_battle_reassembly import (
    BattleReassemblyStore,
    ReassemblyError,
)
from work.information_battle_transport import (
    BattleTransportStore,
)


MAX_METADATA_BYTES = 64 * 1024
MAX_REPORT_BYTES = 4 * 1024 * 1024
MAX_GROUPS_IN_REPORT = 64
MAX_MESSAGES_IN_REPORT = 64
MAX_MESSAGE_REPORT_BYTES = MAX_REPORT_BYTES // 2
MAX_FRAMES_PER_POLL = 256
MAX_DECODER_WIRE_BYTES = max(MAX_OBSERVATION_WIRE_BYTES, MAX_CONTEXT_WIRE_BYTES,
                             MAX_NAVAL_WIRE_BYTES, MAX_TEMPLATE_WIRE_BYTES,
                             MAX_WAR_IDENTITY_WIRE_BYTES, MAX_NATIVE_TEXT_WIRE_BYTES,
                             MAX_DISPLAY_CONTEXT_WIRE_BYTES,
                             MAX_NAME_HANDOFF_WIRE_BYTES, MAX_END_STATE_WIRE_BYTES,
                             MAX_RETREAT_WIRE_BYTES)
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX16 = re.compile(r"[0-9a-f]{16}\Z")
DECIMAL = re.compile(r"[0-9]+\Z")


class RawIngestError(RuntimeError):
    """The installation/source binding or local receive pipeline is invalid."""


def _decode_payload(payload: bytes) -> tuple[int, dict[str, Any]]:
    """Strictly dispatch one complete v1 through v9 observation payload.

    The outer checked-log/transport frame remains version 1.  This helper
    selects the embedded observation schema by its own IBOW version and turns
    every malformed versioned payload into a typed ingest rejection.  Opaque
    non-IBOW payloads are left to the existing unknown-value path because the
    reassembler may still be holding a non-observation fixture.
    """

    if len(payload) < 4 or payload[:4] != b"IBOW":
        raise RawIngestError("payload_not_observation_wire")
    if len(payload) < 6:
        raise RawIngestError("payload_version_truncated")
    version = int.from_bytes(payload[4:6], "little")
    if version == 1:
        if len(payload) > MAX_OBSERVATION_WIRE_BYTES:
            raise RawIngestError("v1_payload_over_bound")
        try:
            return version, decode_observation(payload)
        except ObservationWireError as exc:
            raise RawIngestError(f"v1_payload_rejected:{exc}") from exc
    if version == 2:
        if len(payload) > MAX_CONTEXT_WIRE_BYTES:
            raise RawIngestError("v2_payload_over_bound")
        try:
            return version, decode_context(payload)
        except ContextWireError as exc:
            raise RawIngestError(f"v2_payload_rejected:{exc}") from exc
    if version == 3:
        if len(payload) > MAX_NAVAL_WIRE_BYTES:
            raise RawIngestError("v3_payload_over_bound")
        try:
            return version, decode_naval(payload)
        except NavalWireError as exc:
            raise RawIngestError(f"v3_payload_rejected:{exc}") from exc
    if version == 4:
        if len(payload) > MAX_TEMPLATE_WIRE_BYTES:
            raise RawIngestError("v4_payload_over_bound")
        try:
            return version, decode_template(payload)
        except TemplateWireError as exc:
            raise RawIngestError(f"v4_payload_rejected:{exc}") from exc
    if version == 5:
        if len(payload) > MAX_WAR_IDENTITY_WIRE_BYTES:
            raise RawIngestError("v5_payload_over_bound")
        if decode_war_identity is None:
            raise RawIngestError("v5_decoder_unavailable")
        try:
            return version, decode_war_identity(payload)
        except (WarIdentityWireError, ValueError) as exc:
            raise RawIngestError(f"v5_payload_rejected:{exc}") from exc
    if version == 6:
        if len(payload) > MAX_NATIVE_TEXT_WIRE_BYTES:
            raise RawIngestError("v6_payload_over_bound")
        try:
            return version, decode_native_text(payload)
        except (NativeTextWireError, ValueError) as exc:
            raise RawIngestError(f"v6_payload_rejected:{exc}") from exc
    if version == 7:
        if len(payload) > MAX_DISPLAY_CONTEXT_WIRE_BYTES:
            raise RawIngestError("v7_payload_over_bound")
        try:
            return version, decode_display_context(payload)
        except (DisplayContextWireError, ValueError) as exc:
            raise RawIngestError(f"v7_payload_rejected:{exc}") from exc
    if version == 15:
        if len(payload) > MAX_FLAG_INPUT_WIRE_BYTES:
            raise RawIngestError("v15_payload_over_bound")
        try:
            return version, decode_flag_inputs(payload)
        except FlagInputsWireError as error:
            raise RawIngestError(f"v15_decode_failed:{error}") from error
    if version == 14:
        if len(payload) > MAX_INDEPENDENT_LINE_WIRE_BYTES:
            raise RawIngestError("v14_payload_over_bound")
        try:
            return version, decode_independent_line(payload)
        except IndependentLineWireError as error:
            raise RawIngestError(f"v14_decode_failed:{error}") from error
    if version == 13:
        if len(payload) > MAX_OUTCOME_TAIL_WIRE_BYTES:
            raise RawIngestError("v13_payload_over_bound")
        try:
            return version, decode_outcome_tail(payload)
        except OutcomeTailWireError as error:
            raise RawIngestError(f"v13_decode_failed:{error}") from error
    if version == 12:
        if len(payload) > MAX_OUTCOME_TEXT_WIRE_BYTES:
            raise RawIngestError("v12_payload_over_bound")
        try:
            return version, decode_outcome_text(payload)
        except OutcomeTextWireError as error:
            raise RawIngestError(f"v12_decode_failed:{error}") from error
    if version == 11:
        if len(payload) > MAX_NAME_SOURCES_WIRE_BYTES:
            raise RawIngestError("v11_payload_over_bound")
        try:
            return version, decode_name_sources(payload)
        except NameSourcesWireError as error:
            raise RawIngestError(f"v11_decode_failed:{error}") from error
    if version == 10:
        if len(payload) > MAX_RETREAT_WIRE_BYTES:
            raise RawIngestError("v10_payload_over_bound")
        try:
            return version, decode_retreat(payload)
        except RetreatWireError as error:
            raise RawIngestError(f"v10_decode_failed:{error}") from error
    if version == 9:
        if len(payload) > MAX_END_STATE_WIRE_BYTES:
            raise RawIngestError("v9_payload_over_bound")
        try:
            return version, decode_end_state(payload)
        except EndStateWireError as error:
            raise RawIngestError(f"v9_decode_failed:{error}") from error
    if version == 8:
        if len(payload) > MAX_NAME_HANDOFF_WIRE_BYTES:
            raise RawIngestError("v8_payload_over_bound")
        try:
            return version, decode_name_handoff(payload)
        except (NameHandoffWireError, ValueError) as exc:
            raise RawIngestError(f"v8_payload_rejected:{exc}") from exc
    raise RawIngestError(f"unsupported_observation_wire_version:{version}")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(resolved)


def _file_pin(path: Path) -> dict[str, Any]:
    try:
        stat_result = path.stat()
    except OSError as exc:
        return {
            "path": _display_path(path),
            "status": "missing",
            "error": f"{type(exc).__name__}:{exc}",
        }
    return {
        "path": _display_path(path),
        "status": "observed",
        "size_bytes": int(stat_result.st_size),
        "mtime_ns": int(stat_result.st_mtime_ns),
        "file_identity": _file_identity(stat_result),
    }


def _file_identity(stat_result: os.stat_result) -> str:
    inode = int(getattr(stat_result, "st_ino", 0))
    device = int(getattr(stat_result, "st_dev", 0))
    if inode:
        return f"{device}:{inode}"
    birth = int(getattr(stat_result, "st_birthtime_ns", 0))
    if not birth:
        birth = int(getattr(stat_result, "st_ctime_ns", 0))
    return f"{device}:creation:{birth}"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _reject_constant(value: str) -> None:
    raise RawIngestError(f"non_finite_json_number:{value}")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RawIngestError(f"duplicate_json_key:{key}")
        result[key] = value
    return result


def _read_json(path: Path, *, label: str) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        size = int(path.stat().st_size)
    except OSError as exc:
        raise RawIngestError(f"{label}_unavailable:{type(exc).__name__}") from exc
    if size > MAX_METADATA_BYTES:
        raise RawIngestError(f"{label}_over_bound")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RawIngestError(f"{label}_read_failed:{type(exc).__name__}") from exc
    if len(raw) != size:
        raise RawIngestError(f"{label}_changed_during_read")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
    except RawIngestError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError) as exc:
        raise RawIngestError(f"{label}_invalid_json:{type(exc).__name__}") from exc
    if not isinstance(value, dict):
        raise RawIngestError(f"{label}_root_must_be_object")
    pin = _file_pin(path)
    pin["sha256"] = hashlib.sha256(raw).hexdigest()
    return value, pin


def _required_string(value: Any, field: str, *, max_length: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise RawIngestError(f"{field}_must_be_bounded_string")
    return value


def _decimal_text(value: Any, field: str, *, max_value: int = (1 << 64) - 1) -> str:
    if isinstance(value, bool):
        raise RawIngestError(f"{field}_must_be_decimal")
    if isinstance(value, int):
        if not 0 < value <= max_value:
            raise RawIngestError(f"{field}_out_of_range")
        text = str(value)
    elif isinstance(value, str) and len(value) <= 20 and DECIMAL.fullmatch(value):
        if value == "0" or (len(value) > 1 and value.startswith("0")):
            raise RawIngestError(f"{field}_must_be_canonical_decimal")
        if int(value, 10) > max_value:
            raise RawIngestError(f"{field}_out_of_range")
        text = value
    else:
        raise RawIngestError(f"{field}_must_be_decimal")
    return text


def _required_sha(value: Any, field: str) -> str:
    value = _required_string(value, field, max_length=64)
    if HEX64.fullmatch(value) is None:
        raise RawIngestError(f"{field}_must_be_lower_sha256")
    return value


def _wire_identity(decimal_text: str, field: str) -> str:
    number = int(decimal_text, 10)
    if not 0 < number <= (1 << 64) - 1:
        raise RawIngestError(f"{field}_out_of_uint64_range")
    return f"{number:016x}"


def _json_safe(value: Any) -> Any:
    """Convert auxiliary API bytes to explicit bounded JSON-safe values."""

    if isinstance(value, bytes):
        return {"bytes": len(value), "raw_hex": value.hex()}
    if isinstance(value, bytearray):
        raw = bytes(value)
        return {"bytes": len(raw), "raw_hex": raw.hex()}
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    return value


def _load_binding(installation_path: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    installation, installation_pin = _read_json(installation_path, label="installation")
    binding_path = installation_path.parent / "information-battle-binding.json"
    binding, binding_pin = _read_json(binding_path, label="source_binding")

    pid = installation.get("pid")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise RawIngestError("installation_pid_invalid")
    creation = _decimal_text(installation.get("creation_filetime"), "creation_filetime")
    session = _required_string(installation.get("session_id"), "session_id", max_length=128)
    dll_sha = _required_sha(installation.get("dll_sha256"), "installation_dll_sha256")

    binding_pid = binding.get("pid")
    if isinstance(binding_pid, bool) or not isinstance(binding_pid, int) or binding_pid <= 0:
        raise RawIngestError("binding_pid_invalid")
    binding_creation = _decimal_text(binding.get("creation_filetime"), "binding_creation_filetime")
    binding_session = _required_string(binding.get("session_id"), "binding_session_id", max_length=128)
    binding_dll = _required_sha(binding.get("dll_sha256"), "binding_dll_sha256")
    installation_id = _decimal_text(binding.get("installation"), "binding_installation")
    generation = _decimal_text(binding.get("generation"), "binding_generation")
    player_ref = _required_string(binding.get("player_ref"), "physical_player_ref", max_length=16)
    if HEX16.fullmatch(player_ref) is None:
        raise RawIngestError("physical_player_ref_must_be_lower_hex16")

    checks = {
        "pid_matches": binding_pid == pid,
        "creation_matches": binding_creation == creation,
        "session_matches": binding_session == session,
        "dll_sha256_matches": binding_dll == dll_sha,
        "player_ref_present": True,
    }
    if not all(checks.values()):
        raise RawIngestError("source_binding_does_not_match_installation")

    normalized = {
        "pid": pid,
        "creation_filetime": creation,
        "session_id": session,
        "dll_sha256": dll_sha,
        "installation": {
            "decimal": installation_id,
            "wire_hex": _wire_identity(installation_id, "binding_installation"),
        },
        "generation": {
            "decimal": generation,
            "wire_hex": _wire_identity(generation, "binding_generation"),
        },
        "physical_player_ref": {
            "raw_hex": player_ref,
            "value": int(player_ref, 16),
        },
        "checks": checks,
    }
    return normalized, {"installation": installation_pin, "binding": binding_pin}, binding


def _wire_status(
        *, installation_wire: str, generation_wire: str,
        transport: BattleTransportStore,
) -> dict[str, Any]:
    return transport.stream_status(installation_wire, generation_wire)


def _pending_public_identity(identity_status: str = "invalid", *, reason: str | None = None) -> dict[str, Any]:
    """Describe a v5 binding without claiming the public adapter accepted it.

    The raw ingester only copies the opaque WARI tuple.  Pair/session guards
    belong to ``BattleObservationAdapter``; a bound wire status therefore
    cannot be exposed as a public ``war_id`` at this layer.
    """
    result: dict[str, Any] = {
        "status": "pending_public_validation",
        "war_id": None,
        "battle_id": None,
        "war_identity_status": identity_status if identity_status in {"absent", "bound", "invalid"}
        else "invalid",
        "public_projection": "opaque_war_binding_copied_public_projection_not_verified",
    }
    if reason is not None:
        result["reason"] = reason
    return result


def _aggregate_public_identity(messages: list[dict[str, Any]]) -> dict[str, Any]:
    """Keep the legacy absent shape unless a v5 binding was observed."""
    v5_items = [item.get("public_identity", {}) for item in messages
                if item.get("public_identity", {}).get("status") == "pending_public_validation"]
    if not v5_items:
        return {"status": "absent", "war_id": None, "battle_id": None}
    statuses = [item.get("war_identity_status") for item in v5_items]
    return {
        "status": "pending_public_validation",
        "war_id": None,
        "battle_id": None,
        "public_projection": "opaque_war_binding_copied_public_projection_not_verified",
        "v5_war_identity_count": len(v5_items),
        "v5_bound_count": statuses.count("bound"),
        "v5_invalid_count": statuses.count("invalid"),
        "v5_absent_count": statuses.count("absent"),
    }


def _message_report(
        message: dict[str, Any], *, group: dict[str, Any], index: int,
) -> dict[str, Any]:
    payload = bytes(message["payload"])
    is_v5 = (len(payload) >= 6 and payload[:4] == b"IBOW"
             and int.from_bytes(payload[4:6], "little") in (5, 6, 7, 8))
    item: dict[str, Any] = {
        "index": index,
        "group_id": int(message["group_id"]),
        "message_id": str(message["message_id"]),
        "payload_bytes": len(payload),
        "payload_sha256": str(message["payload_sha256"]),
        "raw_payload_complete": bool(message.get("transport_complete")),
        "transport_complete": bool(message.get("transport_complete")),
        "business_complete": False,
        "battle_complete": False,
        "overall_complete": False,
        "visibility_verified": False,
        "public_identity": (_pending_public_identity() if is_v5 else
                            {"status": "absent", "war_id": None, "battle_id": None}),
        "group": {
            "received_count": int(group.get("received_count", 0)),
            "fragment_count": int(group.get("fragment_count", 0)),
            "status": group.get("status"),
        },
    }
    if payload[:4] != b"IBOW":
        item["raw_payload_hex"] = payload.hex() if len(payload) <= MAX_DECODER_WIRE_BYTES else None
        item["decode"] = {
            "status": "unknown",
            "reason": "payload_not_observation_wire",
            "complete": False,
            "business_complete": False,
            "visibility_verified": False,
        }
    elif len(payload) <= MAX_DECODER_WIRE_BYTES:
        item["raw_payload_hex"] = payload.hex()
        try:
            version, decoded = _decode_payload(payload)
        except RawIngestError as exc:
            item["decode"] = {
                "status": "rejected",
                "reason": str(exc),
                "complete": False,
                "business_complete": False,
                "visibility_verified": False,
            }
            if is_v5:
                item["public_identity"] = _pending_public_identity("invalid", reason=str(exc))
        else:
            item["decode"] = {
                "status": (
                    "decoded_raw_observation" if version == 1
                    else ("decoded_raw_flag_inputs" if version == 15 else
                          "decoded_raw_independent_line" if version == 14 else
                          "decoded_raw_outcome_tail" if version == 13 else
                          "decoded_raw_outcome_text" if version == 12 else
                          "decoded_raw_name_sources" if version == 11 else
                          "decoded_raw_name_handoff" if version == 8 else
                          "decoded_raw_display_context" if version == 7 else
                          "decoded_raw_native_text" if version == 6 else
                          "decoded_raw_war_identity" if version == 5 else "decoded_raw_context")
                ),
                "wire_version": version,
                "value": decoded,
                "complete": False,
                "business_complete": False,
                "visibility_verified": False,
            }
            if version in (5, 6, 7, 8):
                identity = decoded.get("war_identity", {})
                item["public_identity"] = _pending_public_identity(
                    identity.get("status", "invalid"),
                    reason="WAR_ID_PUBLIC_PROJECTION_DEFERRED",
                )
    else:
        item["raw_payload_hex"] = None
        item["decode"] = {
            "status": "rejected",
            "reason": "versioned_payload_over_decoder_bound",
            "complete": False,
            "business_complete": False,
            "visibility_verified": False,
        }
    return item


def _write_new_json(path: Path, value: dict[str, Any]) -> tuple[int, str]:
    raw = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(raw) > MAX_REPORT_BYTES:
        raise RawIngestError("report_over_bound")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(raw)
    except FileExistsError as exc:
        raise RawIngestError("refusing_to_overwrite_output") from exc
    return len(raw), hashlib.sha256(raw).hexdigest()


def ingest_live_raw(
        installation: str | Path,
        database: str | Path,
        output: str | Path,
) -> dict[str, Any]:
    """Tail, persist, reassemble, and decode one bounded local snapshot.

    The report is always created exclusively.  Reusing ``database`` with a
    later output path resumes the checked-log and reassembly cursors and
    makes duplicate frames idempotent.
    """

    installation_path = Path(installation).resolve()
    database_path = Path(database).resolve()
    output_path = Path(output).resolve()
    if output_path.exists():
        raise RawIngestError("refusing_to_overwrite_output")
    if output_path == database_path:
        raise RawIngestError("output_must_differ_from_database")

    started = _utc_now()
    report: dict[str, Any] = {
        "schema": "information_battle_raw_ingest_v1",
        "status": "failed",
        "started_at": started,
        "scope": {
            "game_access": False,
            "process_access": False,
            "control_command_sent": False,
            "native_game_function_invoked": False,
            "dll_installation": False,
            "database_is_local_research_store": True,
        },
        "request": {
            "installation": _display_path(installation_path),
            "database": _display_path(database_path),
            "output": _display_path(output_path),
            "max_frames_per_poll": MAX_FRAMES_PER_POLL,
        },
        "source": {},
        "binding": {},
        "tailer": {},
        "transport": {},
        "reassembly": {},
        "messages": [],
        "decode_rejected_count": 0,
        "completeness": {
            "raw_payload_complete_count": 0,
            "transport_stream_complete": False,
            "battle_complete": False,
            "business_complete": False,
            "overall_complete": False,
            "visibility_verified": False,
            "public_identity": {"status": "absent", "war_id": None, "battle_id": None},
        },
        "errors": [],
    }
    transport: BattleTransportStore | None = None
    tailer: BattleLogTailer | None = None
    reassembly: BattleReassemblyStore | None = None
    try:
        binding, pins, binding_raw = _load_binding(installation_path)
        log_path = installation_path.parent / "information-battle-raw.jsonl"
        if not log_path.is_file():
            raise RawIngestError("raw_log_missing")
        report["binding"] = binding
        report["source"] = {
            "log": _file_pin(log_path),
            "installation": pins["installation"],
            "binding": pins["binding"],
            "binding_schema": binding_raw.get("schema"),
            "payload_dispatch": {
                "supported_observation_versions": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                "strict_versioned_decode_after_reassembly": True,
                "business_decode_does_not_control_transport_ack": True,
                "transport_ack_semantics": "raw_fragment_persisted",
                "multi_fragment_validation": "after_reassembly",
            },
            "header_expected": {
                "installation": binding["installation"],
                "world_generation": binding["generation"],
                "raw_hex": (
                    f"EU4_OWNED_BATTLE_WIRE_V1 "
                    f"{binding['installation']['wire_hex']} "
                    f"{binding['generation']['wire_hex']}\n"
                ).encode("ascii").hex(),
            },
        }

        transport = BattleTransportStore(database_path)
        tailer = BattleLogTailer(
            log_path,
            database_path,
            receiver=transport,
            max_frames=MAX_FRAMES_PER_POLL,
        )
        reassembly = BattleReassemblyStore(database_path)

        tail_result = tailer.poll()
        report["tailer"] = _json_safe({
            "poll": tail_result,
            "status": tailer.status(),
            "cursor": tailer.cursor(),
        })
        observed_header = (
            report["tailer"].get("status", {}).get("header", {})
            if isinstance(report["tailer"].get("status"), dict) else {}
        )
        expected_header_hex = report["source"]["header_expected"]["raw_hex"]
        header_matches_binding = observed_header.get("raw_hex") == expected_header_hex
        report["source"]["header_observed"] = observed_header
        report["source"]["header_matches_binding"] = header_matches_binding
        transport_result = _wire_status(
            installation_wire=binding["installation"]["wire_hex"],
            generation_wire=binding["generation"]["wire_hex"],
            transport=transport,
        )
        report["transport"] = transport_result
        reassembly_poll = reassembly.poll_from_store(transport)
        reassembly_status = reassembly.status(limit=MAX_GROUPS_IN_REPORT)
        groups_page = reassembly.list_groups(limit=MAX_GROUPS_IN_REPORT)
        report["reassembly"] = _json_safe({
            "poll": reassembly_poll,
            "status": reassembly_status,
            "groups": groups_page,
        })

        groups = groups_page.get("groups", [])
        complete_groups = [group for group in groups if group.get("status") == "complete"]
        messages: list[dict[str, Any]] = []
        message_report_bytes = 0
        for index, group in enumerate(complete_groups[:MAX_MESSAGES_IN_REPORT]):
            message = reassembly.get_message(
                binding["installation"]["wire_hex"],
                binding["generation"]["wire_hex"],
                str(group["message_id"]),
            )
            if message is not None:
                item = _message_report(message, group=group, index=index)
                item_bytes = len(json.dumps(item, ensure_ascii=False, sort_keys=True,
                                           indent=2).encode("utf-8"))
                if message_report_bytes + item_bytes > MAX_MESSAGE_REPORT_BYTES:
                    break
                messages.append(item)
                message_report_bytes += item_bytes
        report["messages"] = messages
        report["message_report_scope"] = {
            "complete_groups_in_page": len(complete_groups),
            "messages_in_report": len(messages),
            "limited": len(messages) < len(complete_groups),
            "message_json_bytes": message_report_bytes,
            "message_json_budget_bytes": MAX_MESSAGE_REPORT_BYTES,
            "omitted_payloads_remain_in_database": True,
        }
        report["decode_rejected_count"] = sum(
            1 for message in messages
            if message.get("decode", {}).get("status") == "rejected"
        )
        report["message_page"] = {
            "returned": len(messages),
            "complete_groups": len(complete_groups),
            "truncated": bool(groups_page.get("truncated")) or len(complete_groups) > MAX_MESSAGES_IN_REPORT,
        }
        report["completeness"] = {
            "raw_payload_complete_count": len(messages),
            "transport_stream_complete": False,
            "battle_complete": False,
            "business_complete": False,
            "overall_complete": False,
            "visibility_verified": False,
            "public_identity": _aggregate_public_identity(messages),
        }
        tail_status = str(tail_result.get("status"))
        reassembly_status_name = str(reassembly_poll.get("status"))
        if (
                not header_matches_binding
                or tail_status in {
                    "rejected_binding", "stopped_invalid_frame",
                    "stopped_binding_mismatch", "stopped_receiver_rejection",
                    "stopped_receiver_error",
                }
        ):
            if not header_matches_binding:
                report["errors"].append("source_header_binding_mismatch")
            report["status"] = "failed"
        elif reassembly_status_name.startswith("stopped_") or reassembly_status_name in {"source_binding_rejected", "cursor_conflict", "persistence_failed"}:
            report["status"] = "partial"
        elif report["decode_rejected_count"]:
            report["status"] = "partial"
        else:
            report["status"] = "passed"
    except (RawIngestError, OSError, ReassemblyError, ValueError, TypeError) as exc:
        report["status"] = "failed"
        report["errors"].append(f"{type(exc).__name__}:{exc}")
    finally:
        for handle in (reassembly, tailer, transport):
            if handle is not None:
                try:
                    handle.close()
                except Exception as exc:
                    report["errors"].append(f"close_{type(handle).__name__}:{type(exc).__name__}:{exc}")
        report["closed"] = True
        report["finished_at"] = _utc_now()

    _write_new_json(output_path, report)
    return report


# Short aliases make the composition usable from focused offline tests without
# introducing a second receive protocol.
run = ingest_live_raw
ingest_raw = ingest_live_raw


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = ingest_live_raw(args.installation, args.database, args.output)
    except (RawIngestError, OSError, ValueError, TypeError) as exc:
        print(json.dumps({"status": "failed", "error": f"{type(exc).__name__}:{exc}"}, ensure_ascii=False))
        return 1
    print(json.dumps({
        "status": report["status"],
        "output": report["request"]["output"],
        "messages": len(report.get("messages", [])),
        "tailer": report.get("tailer", {}).get("poll", {}).get("status"),
        "transport_received": report.get("transport", {}).get("received_count", 0),
        "complete": False,
    }, ensure_ascii=False))
    return 0 if report["status"] in {"passed", "partial"} else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "MAX_FRAMES_PER_POLL",
    "MAX_METADATA_BYTES",
    "MAX_REPORT_BYTES",
    "RawIngestError",
    "ingest_live_raw",
    "ingest_raw",
    "run",
]
