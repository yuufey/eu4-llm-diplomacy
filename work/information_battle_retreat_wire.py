"""Strict IBOW v10/RETR codec for copied battle retreat evidence.

The v10 frame embeds one complete, unchanged IBOW v9 frame and appends a
bounded unit-observation snapshot.  The copied full owner reference and four
per-unit bytes are deliberately kept as raw values: this codec transports
evidence and does not assign game semantics or observer visibility to them.
"""
from __future__ import annotations

from collections.abc import Mapping
import struct
from typing import Any

from . import information_battle_end_state_wire as _v9


MAGIC = b"IBOW"
VERSION = 10
BASE_VERSION = 9
EXTENSION_MAGIC = b"RETR"
EXTENSION_VERSION = 1
UNIT_REMOVAL_EXTENSION_VERSION = 2
MAX_WIRE_BYTES = _v9.MAX_WIRE_BYTES
MAX_UNITS = 128
OUTER_HEADER_BYTES = 10
EXTENSION_HEADER_BYTES = 10
FIXED_BODY_BYTES = 20
BODY_BYTES = FIXED_BODY_BYTES
UNIT_BYTES = 14
STATE_IDS = {"unknown": 0, "known": 1}
STATE_NAMES = {value: key for key, value in STATE_IDS.items()}


class RetreatWireError(ValueError):
    """The input is not one strict IBOW v10/RETR frame or snapshot."""


# Compatibility exports for callers that used the inherited wire decoder.
EndStateWireError = _v9.EndStateWireError
NameHandoffWireError = _v9.NameHandoffWireError
DisplayContextWireError = _v9.DisplayContextWireError


def _as_bytes(value: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise RetreatWireError("input_must_be_bytes_like")
    try:
        size = value.nbytes if isinstance(value, memoryview) else len(value)
    except (TypeError, ValueError) as exc:
        raise RetreatWireError("input_length_unavailable") from exc
    if size > MAX_WIRE_BYTES:
        raise RetreatWireError("wire_size_over_bound")
    try:
        raw = bytes(value)
    except (TypeError, ValueError) as exc:
        raise RetreatWireError("input_bytes_conversion_failed") from exc
    if len(raw) > MAX_WIRE_BYTES:
        raise RetreatWireError("wire_size_over_bound")
    return raw


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.position = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.position

    def take(self, size: int, label: str) -> bytes:
        if size < 0 or size > self.remaining:
            raise RetreatWireError(f"truncated:{label}")
        start = self.position
        self.position += size
        return self.data[start:self.position]

    def u8(self, label: str) -> int:
        return self.take(1, label)[0]

    def u16(self, label: str) -> int:
        return struct.unpack("<H", self.take(2, label))[0]

    def u32(self, label: str) -> int:
        return struct.unpack("<I", self.take(4, label))[0]


def _int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise RetreatWireError(f"{label}_out_of_range")
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
        raise RetreatWireError("embedded_base_identity_missing") from exc
    if (type(sequence) is not int or not 0 < sequence <= (1 << 64) - 1
            or type(raw_date) is not int or not -(1 << 31) <= raw_date < (1 << 31)
            or type(kind) is not int or kind not in (1, 2)):
        raise RetreatWireError("embedded_base_identity_invalid")
    return sequence, raw_date, kind


def _validate_base(base: bytes | bytearray | memoryview) -> dict[str, Any]:
    raw = _as_bytes(base)
    if (len(raw) < 6 or raw[:4] != MAGIC
            or struct.unpack_from("<H", raw, 4)[0] != BASE_VERSION):
        raise RetreatWireError("embedded_base_is_not_v9")
    try:
        decoded = _v9.decode(raw)
    except (ValueError, TypeError) as exc:
        raise RetreatWireError(f"invalid_embedded_base_v9:{exc}") from exc
    wire9 = decoded.get("wire9") if isinstance(decoded, dict) else None
    if (not isinstance(decoded, dict)
            or not isinstance(wire9, Mapping)
            or wire9.get("version") != BASE_VERSION):
        raise RetreatWireError("embedded_base_v9_decode_shape_invalid")
    _base_identity(decoded)
    return decoded


def _retreat_unknown() -> dict[str, Any]:
    return {"status": "unknown", "reason": "RETREAT_NOT_CAPTURED"}


def _validate_units(units: list[dict[str, Any]], initial_unit_count: int) -> None:
    if len(units) > initial_unit_count:
        raise RetreatWireError("observed_count_exceeds_initial_unit_count")
    previous = -1
    seen: set[int] = set()
    for unit in units:
        ordinal = unit["ordinal"]
        if ordinal in seen:
            raise RetreatWireError("unit_ordinal_duplicate")
        if ordinal <= previous:
            raise RetreatWireError("unit_ordinals_not_sorted")
        if ordinal >= initial_unit_count:
            raise RetreatWireError("unit_ordinal_out_of_range")
        seen.add(ordinal)
        previous = ordinal


def _decode_body(body: bytes, base_decoded: Mapping[str, Any],
                 extension_version: int) -> dict[str, Any]:
    if len(body) < FIXED_BODY_BYTES:
        raise RetreatWireError("retreat_body_too_short")
    reader = _Reader(body)
    sequence = struct.unpack("<Q", reader.take(8, "sequence"))[0]
    raw_date = struct.unpack("<i", reader.take(4, "raw_date"))[0]
    kind = reader.u8("kind")
    state_id = reader.u8("state")
    losing_combat_side = reader.u8("losing_combat_side")
    reserved = reader.u8("reserved")
    initial_unit_count = reader.u16("initial_unit_count")
    observed_count = reader.u16("observed_count")

    if state_id not in STATE_NAMES:
        raise RetreatWireError("state_out_of_range")
    expected_length = FIXED_BODY_BYTES + observed_count * UNIT_BYTES
    if len(body) != expected_length:
        raise RetreatWireError("retreat_body_length_mismatch")
    if extension_version == EXTENSION_VERSION:
        if reserved != 0:
            raise RetreatWireError("reserved_nonzero")
    elif (extension_version != UNIT_REMOVAL_EXTENSION_VERSION
          or state_id != STATE_IDS["known"] or reserved != 1):
        raise RetreatWireError("extension_version_capture_source_mismatch")

    if state_id == STATE_IDS["unknown"]:
        if body != bytes(FIXED_BODY_BYTES):
            raise RetreatWireError("noncanonical_unknown_retreat")
        return _retreat_unknown()

    if sequence == 0 or losing_combat_side not in (0, 1):
        raise RetreatWireError("known_retreat_identity_or_side_invalid")
    if initial_unit_count > MAX_UNITS:
        raise RetreatWireError("initial_unit_count_over_bound")
    if observed_count > initial_unit_count:
        raise RetreatWireError("observed_count_exceeds_initial_unit_count")
    if (sequence, raw_date, kind) != _base_identity(base_decoded):
        raise RetreatWireError("retreat_identity_mismatch")

    units: list[dict[str, Any]] = []
    previous = -1
    seen: set[int] = set()
    for index in range(observed_count):
        ordinal = reader.u16(f"unit_{index}.ordinal")
        owner_full_ref = struct.unpack(
            "<Q", reader.take(8, f"unit_{index}.owner_full_ref")
        )[0]
        raw_flags = [reader.u8(f"unit_{index}.flag_{flag}")
                     for flag in (201, 203, 204, 205)]
        if ordinal in seen:
            raise RetreatWireError("unit_ordinal_duplicate")
        if ordinal <= previous:
            raise RetreatWireError("unit_ordinals_not_sorted")
        if ordinal >= initial_unit_count:
            raise RetreatWireError("unit_ordinal_out_of_range")
        seen.add(ordinal)
        previous = ordinal
        units.append({
            "ordinal": ordinal,
            "owner_full_ref": owner_full_ref,
            "raw_flags": raw_flags,
        })
    if reader.remaining:
        raise RetreatWireError("trailing_bytes_in_retreat_body")
    result = {
        "status": "known",
        "sequence": sequence,
        "raw_date": raw_date,
        "kind": kind,
        "combat_side_index": losing_combat_side,
        "initial_unit_count": initial_unit_count,
        "units": units,
    }
    if extension_version == UNIT_REMOVAL_EXTENSION_VERSION:
        result["capture_source"] = "unit_removal_state"
    return result


def decode_envelope(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode v10 framing and RETR while validating the complete v9 base."""
    raw = _as_bytes(data)
    if len(raw) < OUTER_HEADER_BYTES + EXTENSION_HEADER_BYTES + FIXED_BODY_BYTES:
        raise RetreatWireError("wire_too_short")
    if raw[:4] != MAGIC:
        raise RetreatWireError("magic_mismatch")
    if struct.unpack_from("<H", raw, 4)[0] != VERSION:
        raise RetreatWireError("version_mismatch")
    base_bytes = struct.unpack_from("<I", raw, 6)[0]
    if base_bytes == 0 or base_bytes > MAX_WIRE_BYTES:
        raise RetreatWireError("base_length_over_bound")
    base_start = OUTER_HEADER_BYTES
    base_end = base_start + base_bytes
    if base_end < base_start or base_end > len(raw):
        raise RetreatWireError("truncated_embedded_base")
    base = raw[base_start:base_end]
    base_decoded = _validate_base(base)

    reader = _Reader(raw[base_end:])
    if reader.take(4, "extension_magic") != EXTENSION_MAGIC:
        raise RetreatWireError("extension_magic_mismatch")
    extension_version = reader.u16("extension_version")
    if extension_version not in (EXTENSION_VERSION, UNIT_REMOVAL_EXTENSION_VERSION):
        raise RetreatWireError("extension_version_mismatch")
    body_length = reader.u32("extension_body_length")
    if body_length != reader.remaining:
        raise RetreatWireError("extension_length_mismatch")
    body = reader.take(body_length, "extension_body")
    retreat = _decode_body(body, base_decoded, extension_version)
    return {
        "schema": "information_battle_retreat_wire_envelope_v10",
        "wire10": {
            "version": VERSION,
            "bytes": len(raw),
            "base_version": BASE_VERSION,
            "base_bytes": base_bytes,
            "extension_magic": EXTENSION_MAGIC.decode("ascii"),
            "extension_version": extension_version,
            "extension_bytes": body_length,
            "trailing_bytes": 0,
        },
        "base_payload_hex": base.hex(),
        "retreat": retreat,
        "complete": False,
    }


def decode(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Delegate versions 1..9 unchanged and compose the strict v10 extension."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return _v9.decode(data)
    # A multidimensional memoryview can have a small first-dimension len while
    # its byte payload is much larger.  Check nbytes before slicing or flattening
    # it; otherwise ``bytes(data[:6])`` may materialize the whole first row.
    if isinstance(data, memoryview):
        try:
            size = data.nbytes
        except (TypeError, ValueError) as exc:
            raise RetreatWireError("input_length_unavailable") from exc
        if size > MAX_WIRE_BYTES:
            raise RetreatWireError("wire_size_over_bound")
        try:
            data = bytes(data)
        except (TypeError, ValueError) as exc:
            raise RetreatWireError("input_bytes_conversion_failed") from exc
    try:
        if len(data) < 6:
            return _v9.decode(data)
        prefix = bytes(data[:6])
    except (TypeError, ValueError) as exc:
        raise RetreatWireError("input_bytes_conversion_failed") from exc
    if prefix[:4] != MAGIC or struct.unpack_from("<H", prefix, 4)[0] != VERSION:
        return _v9.decode(data)
    raw = _as_bytes(data)
    envelope = decode_envelope(raw)
    base = bytes.fromhex(envelope["base_payload_hex"])
    base_decoded = _validate_base(base)
    composed = dict(base_decoded)
    composed["wire10"] = dict(envelope["wire10"])
    composed["retreat"] = envelope["retreat"]
    composed["complete"] = False
    return composed


def _normalize_units(value: Any, initial_unit_count: int) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        raise RetreatWireError("units_must_be_sequence")
    if len(value) > MAX_UNITS:
        raise RetreatWireError("observed_count_over_bound")
    units: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise RetreatWireError(f"unit_{index}_must_be_object")
        ordinal = _int(item.get("ordinal"), f"unit_{index}_ordinal", 0, 65535)
        raw_flags = item.get("raw_flags")
        if (not isinstance(raw_flags, (list, tuple))
                or len(raw_flags) != 4):
            raise RetreatWireError(f"unit_{index}_raw_flags_must_have_four_bytes")
        owner_full_ref = _int(
            item.get("owner_full_ref"),
            f"unit_{index}_owner_full_ref",
            0,
            (1 << 64) - 1,
        )
        flags = [_int(flag, f"unit_{index}_flag_{flag_index}", 0, 255)
                 for flag_index, flag in enumerate(raw_flags)]
        units.append({
            "ordinal": ordinal,
            "owner_full_ref": owner_full_ref,
            "raw_flags": flags,
        })
    _validate_units(units, initial_unit_count)
    return units


def _side_input(snapshot: Mapping[str, Any]) -> Any:
    has_losing = "losing_combat_side" in snapshot
    has_index = "combat_side_index" in snapshot
    if has_losing and has_index and snapshot["losing_combat_side"] != snapshot["combat_side_index"]:
        raise RetreatWireError("ambiguous_combat_side")
    if has_losing:
        return snapshot["losing_combat_side"]
    return snapshot.get("combat_side_index")


def encode(base: bytes | bytearray | memoryview,
           snapshot: Mapping[str, Any]) -> bytes:
    """Encode one complete v9 frame and a strict pointer-free RETR snapshot."""
    base_bytes = _as_bytes(base)
    base_decoded = _validate_base(base_bytes)
    if not isinstance(snapshot, Mapping):
        raise RetreatWireError("snapshot_must_be_object")
    state = snapshot.get("state")
    if state not in STATE_IDS:
        raise RetreatWireError("invalid_snapshot_state")
    extension_version = EXTENSION_VERSION
    if state == "unknown":
        body = bytes(FIXED_BODY_BYTES)
    else:
        capture_source = snapshot.get("capture_source", "regular")
        if capture_source == "regular":
            capture_source_marker = 0
        elif capture_source == "unit_removal_state":
            capture_source_marker = 1
            extension_version = UNIT_REMOVAL_EXTENSION_VERSION
        else:
            raise RetreatWireError("invalid_capture_source")
        sequence = _int(snapshot.get("sequence"), "sequence", 1, (1 << 64) - 1)
        raw_date = _int(snapshot.get("raw_date"), "raw_date", -(1 << 31), (1 << 31) - 1)
        kind = _int(snapshot.get("kind"), "kind", 1, 2)
        side = _int(_side_input(snapshot), "losing_combat_side", 0, 1)
        initial = _int(snapshot.get("initial_unit_count"), "initial_unit_count", 0, MAX_UNITS)
        units = _normalize_units(snapshot.get("units", []), initial)
        observed = len(units)
        if "observed_count" in snapshot and snapshot["observed_count"] != observed:
            raise RetreatWireError("observed_count_mismatch")
        if (sequence, raw_date, kind) != _base_identity(base_decoded):
            raise RetreatWireError("retreat_identity_mismatch")
        body = bytearray(struct.pack(
            "<QiBBBBHH", sequence, raw_date, kind, STATE_IDS[state], side,
            capture_source_marker, initial, observed,
        ))
        for unit in units:
            body.extend(struct.pack(
                "<HQBBBB",
                unit["ordinal"],
                unit["owner_full_ref"],
                *unit["raw_flags"],
            ))
        body = bytes(body)
    result = (MAGIC + struct.pack("<HI", VERSION, len(base_bytes)) + base_bytes
              + EXTENSION_MAGIC
              + struct.pack("<HI", extension_version, len(body)) + body)
    if len(result) > MAX_WIRE_BYTES:
        raise RetreatWireError("wire_size_over_bound")
    return result


def validate(data: bytes | bytearray | memoryview) -> bool:
    try:
        decode_envelope(data)
    except (RetreatWireError, TypeError, ValueError):
        return False
    return True


__all__ = [
    "BASE_VERSION", "BODY_BYTES", "DisplayContextWireError",
    "EndStateWireError", "EXTENSION_MAGIC", "EXTENSION_VERSION",
    "UNIT_REMOVAL_EXTENSION_VERSION",
    "FIXED_BODY_BYTES", "MAX_UNITS", "MAX_WIRE_BYTES", "NameHandoffWireError",
    "OUTER_HEADER_BYTES", "RetreatWireError", "STATE_IDS", "VERSION",
    "UNIT_BYTES", "decode", "decode_envelope", "encode", "validate",
]
