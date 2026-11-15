"""Strict IBOW v15/FLAG codec for owned battle flag input pairs.

The complete IBOW v14 frame is embedded unchanged. Country references are
checked only for structural validity; participant membership is a projection
concern and is deliberately outside this wire codec.
"""
from __future__ import annotations

from collections.abc import Mapping
import struct
from typing import Any

from . import information_battle_independent_line_wire as _v14


MAGIC = b"IBOW"
VERSION = 15
BASE_VERSION = 14
EXTENSION_MAGIC = b"FLAG"
EXTENSION_VERSION = 1
SOURCE = "owned_flag_inputs"
MAX_WIRE_BYTES = _v14.MAX_WIRE_BYTES
OUTER_HEADER_BYTES = 10
EXTENSION_HEADER_BYTES = 10
FIXED_BODY_BYTES = 17
ENTRY_BYTES = 16
MAX_ENTRIES = 128

STATE_IDS = {"unknown": 0, "known": 1, "not_applicable": 2}
STATE_NAMES = {value: key for key, value in STATE_IDS.items()}
MODE_IDS = {"numeric": 1, "country": 2, "rebel": 3}
MODE_NAMES = {value: key for key, value in MODE_IDS.items()}
ENTRY_FIELDS = {"pair_index", "side", "mode", "country_ref", "rebel_raw"}


class FlagInputsWireError(ValueError):
    """The input is not one strict IBOW v15/FLAG frame or snapshot."""


# Preserve inherited error names used by earlier battle codecs.
IndependentLineWireError = _v14.IndependentLineWireError
OutcomeTailWireError = _v14.OutcomeTailWireError
OutcomeTextWireError = _v14.OutcomeTextWireError
NameSourcesWireError = _v14.NameSourcesWireError
RetreatWireError = _v14.RetreatWireError
EndStateWireError = _v14.EndStateWireError
NameHandoffWireError = _v14.NameHandoffWireError
DisplayContextWireError = _v14.DisplayContextWireError


def _as_bytes(value: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise FlagInputsWireError("input_must_be_bytes_like")
    try:
        size = value.nbytes if isinstance(value, memoryview) else len(value)
    except (TypeError, ValueError) as exc:
        raise FlagInputsWireError("input_length_unavailable") from exc
    if size > MAX_WIRE_BYTES:
        raise FlagInputsWireError("wire_size_over_bound")
    try:
        raw = bytes(value)
    except (TypeError, ValueError) as exc:
        raise FlagInputsWireError("input_bytes_conversion_failed") from exc
    if len(raw) > MAX_WIRE_BYTES:
        raise FlagInputsWireError("wire_size_over_bound")
    return raw


def _require_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    keys = set(value)
    if keys - expected:
        raise FlagInputsWireError(f"{label}_unknown_keys")
    if expected - keys:
        raise FlagInputsWireError(f"{label}_missing_keys")


def _int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise FlagInputsWireError(f"{label}_out_of_range")
    return value


def _base_identity(decoded: Mapping[str, Any]) -> tuple[int, int, int]:
    try:
        observation = decoded["observation"]
        result = observation["result"]
        context = decoded["context"]
        sequence = observation["sequence"]
        raw_date = result["raw_date"]
        kind = context["kind"]
    except (KeyError, TypeError) as exc:
        raise FlagInputsWireError("embedded_base_identity_missing") from exc
    if (type(sequence) is not int or not 0 < sequence <= (1 << 64) - 1
            or type(raw_date) is not int or not 0 <= raw_date < (1 << 31)
            or type(kind) is not int or kind not in (1, 2)):
        raise FlagInputsWireError("embedded_base_identity_invalid")
    return sequence, raw_date, kind


def _validate_base(base: bytes | bytearray | memoryview
                   ) -> tuple[bytes, dict[str, Any], tuple[int, int, int]]:
    raw = _as_bytes(base)
    if (len(raw) < OUTER_HEADER_BYTES + _v14.OUTER_HEADER_BYTES
            or raw[:4] != MAGIC
            or struct.unpack_from("<H", raw, 4)[0] != BASE_VERSION):
        raise FlagInputsWireError("embedded_base_is_not_v14")
    if not _v14.validate(raw):
        raise FlagInputsWireError("invalid_embedded_base_v14")
    try:
        decoded = _v14.decode(raw)
    except (ValueError, TypeError) as exc:
        raise FlagInputsWireError(f"invalid_embedded_base_v14:{exc}") from exc
    wire14 = decoded.get("wire14") if isinstance(decoded, dict) else None
    if (not isinstance(decoded, dict) or not isinstance(wire14, Mapping)
            or wire14.get("version") != BASE_VERSION
            or wire14.get("base_version") != _v14.BASE_VERSION
            or wire14.get("source") != _v14.SOURCE):
        raise FlagInputsWireError("embedded_base_v14_decode_shape_invalid")
    return raw, decoded, _base_identity(decoded)


def _country_ref_valid(value: int) -> bool:
    low = (value & 0xFFFFFF).to_bytes(3, "little")
    fourth = (value >> 24) & 0xFF
    high = (value >> 56) & 0xFF
    return (all(0x41 <= byte <= 0x5A or 0x30 <= byte <= 0x39 for byte in low)
            and fourth == 0 and high != 0)


def _normalize_entry(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise FlagInputsWireError("entry_must_be_object")
    _require_keys(value, ENTRY_FIELDS, "entry")
    pair_index = _int(value["pair_index"], "pair_index", 0, 127)
    side = _int(value["side"], "side", 0, 1)
    mode = _int(value["mode"], "mode", 1, 3)
    country_ref = _int(value["country_ref"], "country_ref", 0, (1 << 64) - 1)
    rebel_raw = _int(value["rebel_raw"], "rebel_raw", 0, (1 << 32) - 1)
    if mode == MODE_IDS["numeric"]:
        if country_ref != 0 or rebel_raw != 0:
            raise FlagInputsWireError("numeric_entry_noncanonical_zero")
    elif mode == MODE_IDS["country"]:
        if country_ref == 0 or not _country_ref_valid(country_ref):
            raise FlagInputsWireError("country_ref_structure_invalid")
        if rebel_raw != 0:
            raise FlagInputsWireError("country_entry_rebel_nonzero")
    elif country_ref != 0:
        raise FlagInputsWireError("rebel_entry_country_nonzero")
    return {
        "pair_index": pair_index,
        "side": side,
        "mode": mode,
        "country_ref": country_ref,
        "rebel_raw": rebel_raw,
    }


def _normalize_snapshot(snapshot: Any, identity: tuple[int, int, int]
                        ) -> tuple[dict[str, Any], list[dict[str, int]]]:
    if not isinstance(snapshot, Mapping):
        raise FlagInputsWireError("snapshot_must_be_object")
    expected = {"sequence", "raw_date", "kind", "state", "failure", "entries"}
    _require_keys(snapshot, expected, "snapshot")
    sequence = _int(snapshot["sequence"], "sequence", 1, (1 << 64) - 1)
    raw_date = _int(snapshot["raw_date"], "raw_date", 0, (1 << 31) - 1)
    kind = _int(snapshot["kind"], "kind", 1, 2)
    state = snapshot["state"]
    if not isinstance(state, str) or state not in STATE_IDS:
        raise FlagInputsWireError("flag_inputs_state_out_of_range")
    failure = _int(snapshot["failure"], "failure", 0, 8)
    if type(snapshot["entries"]) is not list:
        raise FlagInputsWireError("entries_must_be_array")
    if len(snapshot["entries"]) > MAX_ENTRIES:
        raise FlagInputsWireError("entry_count_over_bound")
    if (sequence, raw_date, kind) != identity:
        raise FlagInputsWireError("flag_inputs_identity_mismatch")

    entries: list[dict[str, int]] = []
    previous = -1
    for item in snapshot["entries"]:
        entry = _normalize_entry(item)
        if entry["pair_index"] <= previous:
            raise FlagInputsWireError("pair_index_order_invalid")
        previous = entry["pair_index"]
        entries.append(entry)

    if state == "unknown":
        if not 1 <= failure <= 8 or entries:
            raise FlagInputsWireError("unknown_flag_inputs_group_mismatch")
    elif state == "known":
        if kind != 1 or failure != 0:
            raise FlagInputsWireError("known_flag_inputs_group_mismatch")
    elif kind != 2 or failure != 0 or entries:
        raise FlagInputsWireError("not_applicable_flag_inputs_group_mismatch")

    normalized = {
        "sequence": sequence,
        "raw_date": raw_date,
        "kind": kind,
        "state": state,
        "failure": failure,
        "entries": entries,
    }
    return normalized, entries


def _validate_entry_order_and_values(entries: list[dict[str, int]]) -> None:
    previous = -1
    for entry in entries:
        pair_index = entry["pair_index"]
        if pair_index <= previous:
            raise FlagInputsWireError("pair_index_order_invalid")
        previous = pair_index
        mode = entry["mode"]
        country_ref = entry["country_ref"]
        rebel_raw = entry["rebel_raw"]
        if mode == MODE_IDS["numeric"]:
            if country_ref != 0 or rebel_raw != 0:
                raise FlagInputsWireError("numeric_entry_noncanonical_zero")
        elif mode == MODE_IDS["country"]:
            if country_ref == 0 or not _country_ref_valid(country_ref):
                raise FlagInputsWireError("country_ref_structure_invalid")
            if rebel_raw != 0:
                raise FlagInputsWireError("country_entry_rebel_nonzero")
        elif mode == MODE_IDS["rebel"]:
            if country_ref != 0:
                raise FlagInputsWireError("rebel_entry_country_nonzero")
        else:
            raise FlagInputsWireError("entry_mode_out_of_range")


def _decode_v15(raw: bytes) -> dict[str, Any]:
    if len(raw) < OUTER_HEADER_BYTES + EXTENSION_HEADER_BYTES + FIXED_BODY_BYTES:
        raise FlagInputsWireError("wire_too_short")
    if raw[:4] != MAGIC:
        raise FlagInputsWireError("magic_mismatch")
    if struct.unpack_from("<H", raw, 4)[0] != VERSION:
        raise FlagInputsWireError("version_mismatch")
    base_size = struct.unpack_from("<I", raw, 6)[0]
    if base_size == 0 or base_size > MAX_WIRE_BYTES:
        raise FlagInputsWireError("base_length_over_bound")
    base_start = OUTER_HEADER_BYTES
    base_end = base_start + base_size
    if base_end < base_start or base_end > len(raw):
        raise FlagInputsWireError("truncated_embedded_base")
    _base, base_decoded, identity = _validate_base(raw[base_start:base_end])

    extension = raw[base_end:]
    if len(extension) < EXTENSION_HEADER_BYTES:
        raise FlagInputsWireError("truncated:extension_header")
    if extension[:4] != EXTENSION_MAGIC:
        raise FlagInputsWireError("extension_magic_mismatch")
    if struct.unpack_from("<H", extension, 4)[0] != EXTENSION_VERSION:
        raise FlagInputsWireError("extension_version_mismatch")
    body_length = struct.unpack_from("<I", extension, 6)[0]
    if body_length != len(extension) - EXTENSION_HEADER_BYTES:
        raise FlagInputsWireError("extension_length_mismatch")
    body = extension[EXTENSION_HEADER_BYTES:]
    if len(body) < FIXED_BODY_BYTES:
        raise FlagInputsWireError("flag_inputs_body_too_short")

    sequence, raw_date, kind, state_id, failure, entry_count = struct.unpack_from(
        "<QiBBBH", body, 0,
    )
    if (sequence, raw_date, kind) != identity:
        raise FlagInputsWireError("flag_inputs_identity_mismatch")
    if sequence == 0 or raw_date < 0 or kind not in (1, 2):
        raise FlagInputsWireError("flag_inputs_identity_invalid")
    state = STATE_NAMES.get(state_id)
    if state is None:
        raise FlagInputsWireError("flag_inputs_state_out_of_range")
    if entry_count > MAX_ENTRIES:
        raise FlagInputsWireError("entry_count_over_bound")
    expected_body_length = FIXED_BODY_BYTES + entry_count * ENTRY_BYTES
    if len(body) < expected_body_length:
        raise FlagInputsWireError("truncated:flag_input_entries")
    if len(body) > expected_body_length:
        raise FlagInputsWireError("trailing_bytes_in_flag_inputs_body")

    entries: list[dict[str, int]] = []
    position = FIXED_BODY_BYTES
    for _ in range(entry_count):
        pair_index, side, mode, country_ref, rebel_raw = struct.unpack_from(
            "<HBBQI", body, position,
        )
        if pair_index > 127:
            raise FlagInputsWireError("pair_index_out_of_range")
        if side not in (0, 1):
            raise FlagInputsWireError("side_out_of_range")
        if mode not in MODE_NAMES:
            raise FlagInputsWireError("entry_mode_out_of_range")
        entries.append({
            "pair_index": pair_index,
            "side": side,
            "mode": mode,
            "country_ref": country_ref,
            "rebel_raw": rebel_raw,
        })
        position += ENTRY_BYTES
    _validate_entry_order_and_values(entries)

    if not 0 <= failure <= 8:
        raise FlagInputsWireError("failure_out_of_range")
    if state == "unknown":
        if not 1 <= failure <= 8 or entries:
            raise FlagInputsWireError("unknown_flag_inputs_group_mismatch")
    elif state == "known":
        if kind != 1 or failure != 0:
            raise FlagInputsWireError("known_flag_inputs_group_mismatch")
    elif kind != 2 or failure != 0 or entries:
        raise FlagInputsWireError("not_applicable_flag_inputs_group_mismatch")

    composed = dict(base_decoded)
    composed["wire15"] = {
        "version": VERSION,
        "base_version": BASE_VERSION,
        "source": SOURCE,
    }
    composed["flag_inputs"] = {
        "sequence": sequence,
        "raw_date": raw_date,
        "kind": kind,
        "state": state,
        "failure": failure,
        "entries": entries,
    }
    return composed


def decode(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode v15, delegating every earlier IBOW version to the v14 codec."""
    raw = _as_bytes(data)
    if (len(raw) < 6 or raw[:4] != MAGIC
            or struct.unpack_from("<H", raw, 4)[0] != VERSION):
        return _v14.decode(raw)
    return _decode_v15(raw)


def encode(base14: bytes | bytearray | memoryview,
           snapshot: Mapping[str, Any]) -> bytes:
    """Embed one complete IBOW14 frame and one strict FLAG input group."""
    base, _base_decoded, identity = _validate_base(base14)
    normalized, entries = _normalize_snapshot(snapshot, identity)
    state = normalized["state"]
    body = bytearray(struct.pack(
        "<QiBBBH", normalized["sequence"], normalized["raw_date"],
        normalized["kind"], STATE_IDS[state], normalized["failure"], len(entries),
    ))
    for entry in entries:
        body.extend(struct.pack(
            "<HBBQI", entry["pair_index"], entry["side"], entry["mode"],
            entry["country_ref"], entry["rebel_raw"],
        ))
    result = (
        MAGIC + struct.pack("<HI", VERSION, len(base)) + base
        + EXTENSION_MAGIC + struct.pack("<HI", EXTENSION_VERSION, len(body))
        + body
    )
    if len(result) > MAX_WIRE_BYTES:
        raise FlagInputsWireError("wire_size_over_bound")
    return result


def validate(data: bytes | bytearray | memoryview) -> bool:
    """Return whether data is a valid v1..v15 frame accepted by decode()."""
    try:
        decode(data)
    except (TypeError, ValueError):
        return False
    return True


__all__ = [
    "BASE_VERSION", "DisplayContextWireError", "ENTRY_BYTES", "ENTRY_FIELDS",
    "EXTENSION_HEADER_BYTES", "EXTENSION_MAGIC", "EXTENSION_VERSION",
    "FIXED_BODY_BYTES", "FlagInputsWireError", "IndependentLineWireError",
    "MAGIC", "MAX_ENTRIES", "MAX_WIRE_BYTES", "MODE_IDS", "MODE_NAMES",
    "NameHandoffWireError", "NameSourcesWireError", "OUTER_HEADER_BYTES",
    "OutcomeTailWireError", "OutcomeTextWireError", "RetreatWireError",
    "SOURCE", "STATE_IDS", "STATE_NAMES", "VERSION", "decode", "encode",
    "validate",
]
