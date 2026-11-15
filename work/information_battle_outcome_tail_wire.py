"""Strict IBOW v13/SCTX codec for copied battle outcome tail values.

The complete IBOW v12 frame is embedded unchanged. Text is transported as raw
bytes; this module does not decode, format, select, or expose game strings.
"""
from __future__ import annotations

from collections.abc import Mapping
import re
import struct
from typing import Any

from . import information_battle_outcome_text_wire as _v12


MAGIC = b"IBOW"
VERSION = 13
BASE_VERSION = 12
EXTENSION_MAGIC = b"SCTX"
EXTENSION_VERSION = 1
SOURCE = "owned_outcome_tail"
MAX_WIRE_BYTES = _v12.MAX_WIRE_BYTES
OUTER_HEADER_BYTES = 10
EXTENSION_HEADER_BYTES = 10
FIXED_BODY_BYTES = 27
TEXT_HEADER_BYTES = 3
MAX_TEXT_BYTES = 8192
MAX_LANGUAGE_BYTES = 256
FIELD_ORDER = (
    "language", "COMBAT_FLEE", "COMBAT_TRIUMPH",
    "COMBAT_WINNERTYPE_OUR", "COMBAT_WINNERTYPE_THEIR",
)
STATE_IDS = {"unknown": 0, "known": 1, "absent": 2}
STATE_NAMES = {value: key for key, value in STATE_IDS.items()}


class OutcomeTailWireError(ValueError):
    """The input is not one strict IBOW v13/SCTX frame or snapshot."""


# Preserve the inherited error names used by callers of earlier codecs.
OutcomeTextWireError = _v12.OutcomeTextWireError
NameSourcesWireError = _v12.NameSourcesWireError
RetreatWireError = _v12.RetreatWireError
EndStateWireError = _v12.EndStateWireError
NameHandoffWireError = _v12.NameHandoffWireError
DisplayContextWireError = _v12.DisplayContextWireError


def _as_bytes(value: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise OutcomeTailWireError("input_must_be_bytes_like")
    try:
        size = value.nbytes if isinstance(value, memoryview) else len(value)
    except (TypeError, ValueError) as exc:
        raise OutcomeTailWireError("input_length_unavailable") from exc
    if size > MAX_WIRE_BYTES:
        raise OutcomeTailWireError("wire_size_over_bound")
    try:
        raw = bytes(value)
    except (TypeError, ValueError) as exc:
        raise OutcomeTailWireError("input_bytes_conversion_failed") from exc
    if len(raw) > MAX_WIRE_BYTES:
        raise OutcomeTailWireError("wire_size_over_bound")
    return raw


def _require_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    keys = set(value)
    if keys - expected:
        raise OutcomeTailWireError(f"{label}_unknown_keys")
    if expected - keys:
        raise OutcomeTailWireError(f"{label}_missing_keys")


def _int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise OutcomeTailWireError(f"{label}_out_of_range")
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
        raise OutcomeTailWireError("embedded_base_identity_missing") from exc
    if (type(sequence) is not int or not 0 < sequence <= (1 << 64) - 1
            or type(raw_date) is not int or not 0 <= raw_date < (1 << 31)
            or type(kind) is not int or kind not in (1, 2)):
        raise OutcomeTailWireError("embedded_base_identity_invalid")
    return sequence, raw_date, kind


def _validate_base(base: bytes | bytearray | memoryview
                   ) -> tuple[bytes, dict[str, Any], tuple[int, int, int]]:
    raw = _as_bytes(base)
    if (len(raw) < OUTER_HEADER_BYTES + EXTENSION_HEADER_BYTES
            + _v12.FIXED_BODY_BYTES + len(_v12.FIELD_ORDER) * _v12.TEXT_HEADER_BYTES
            or raw[:4] != MAGIC
            or struct.unpack_from("<H", raw, 4)[0] != BASE_VERSION):
        raise OutcomeTailWireError("embedded_base_is_not_v12")
    if not _v12.validate(raw):
        raise OutcomeTailWireError("invalid_embedded_base_v12")
    try:
        decoded = _v12.decode(raw)
    except (ValueError, TypeError) as exc:
        raise OutcomeTailWireError(f"invalid_embedded_base_v12:{exc}") from exc
    wire12 = decoded.get("wire12") if isinstance(decoded, dict) else None
    if (not isinstance(decoded, dict) or not isinstance(wire12, Mapping)
            or wire12.get("version") != BASE_VERSION
            or wire12.get("source") != _v12.SOURCE):
        raise OutcomeTailWireError("embedded_base_v12_decode_shape_invalid")
    return raw, decoded, _base_identity(decoded)


def _validate_field(state: Any, raw: bytes, label: str) -> None:
    if not isinstance(state, str) or state not in STATE_IDS:
        raise OutcomeTailWireError(f"{label}_state_out_of_range")
    if state in ("unknown", "absent"):
        if raw:
            raise OutcomeTailWireError(f"noncanonical_{label}_{state}")
        if state == "absent" and label == "language":
            raise OutcomeTailWireError("language_cannot_be_absent")
        return
    maximum = MAX_LANGUAGE_BYTES if label == "language" else MAX_TEXT_BYTES
    if len(raw) > maximum:
        raise OutcomeTailWireError(f"{label}_length_over_bound")
    if b"\x00" in raw:
        raise OutcomeTailWireError(f"{label}_contains_nul")
    if label == "language" and re.fullmatch(rb"l_[A-Za-z0-9_]+", raw) is None:
        raise OutcomeTailWireError("language_format_invalid")


def _validate_group(failure: int, fields: Mapping[str, Mapping[str, Any]],
                    reserved_slots: tuple[int, int, int] | list[int]) -> None:
    if not 0 <= failure <= 9:
        raise OutcomeTailWireError("failure_out_of_range")
    if len(reserved_slots) != 3:
        raise OutcomeTailWireError("reserved_slots_length_invalid")
    for index, slot in enumerate(reserved_slots):
        _int(slot, f"reserved_slots_{index}", -(1 << 31), (1 << 31) - 1)
    if failure == 0:
        if fields["language"]["state"] != "known":
            raise OutcomeTailWireError("outcome_tail_group_state_mismatch")
        for label in FIELD_ORDER[1:]:
            if fields[label]["state"] not in ("known", "absent"):
                raise OutcomeTailWireError("outcome_tail_group_state_mismatch")
    else:
        if any(fields[label]["state"] != "unknown" for label in FIELD_ORDER):
            raise OutcomeTailWireError("outcome_tail_group_state_mismatch")
        if any(reserved_slots):
            raise OutcomeTailWireError("failed_group_reserved_slots_nonzero")


def _normalize_fields(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, Mapping):
        raise OutcomeTailWireError("text_fields_must_be_object")
    _require_keys(value, set(FIELD_ORDER), "text_fields")
    fields: dict[str, dict[str, Any]] = {}
    for label in FIELD_ORDER:
        item = value[label]
        if not isinstance(item, Mapping):
            raise OutcomeTailWireError(f"{label}_must_be_object")
        _require_keys(item, {"state", "raw_hex", "length"}, label)
        state = item["state"]
        raw_hex = item["raw_hex"]
        maximum = MAX_LANGUAGE_BYTES if label == "language" else MAX_TEXT_BYTES
        if (not isinstance(raw_hex, str) or len(raw_hex) > 2 * maximum
                or re.fullmatch(r"(?:[0-9A-Fa-f]{2})*", raw_hex) is None):
            raise OutcomeTailWireError(f"{label}_raw_hex_invalid")
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise OutcomeTailWireError(f"{label}_raw_hex_invalid") from exc
        length = _int(item["length"], f"{label}_length", 0, 65535)
        if length != len(raw):
            raise OutcomeTailWireError(f"{label}_length_mismatch")
        _validate_field(state, raw, label)
        fields[label] = {"state": state, "raw": raw, "length": length}
    return fields


def _decode_v13(raw: bytes) -> dict[str, Any]:
    minimum = (OUTER_HEADER_BYTES + EXTENSION_HEADER_BYTES + FIXED_BODY_BYTES
               + len(FIELD_ORDER) * TEXT_HEADER_BYTES)
    if len(raw) < minimum:
        raise OutcomeTailWireError("wire_too_short")
    if raw[:4] != MAGIC:
        raise OutcomeTailWireError("magic_mismatch")
    if struct.unpack_from("<H", raw, 4)[0] != VERSION:
        raise OutcomeTailWireError("version_mismatch")
    base_size = struct.unpack_from("<I", raw, 6)[0]
    if base_size == 0 or base_size > MAX_WIRE_BYTES:
        raise OutcomeTailWireError("base_length_over_bound")
    base_start = OUTER_HEADER_BYTES
    base_end = base_start + base_size
    if base_end < base_start or base_end > len(raw):
        raise OutcomeTailWireError("truncated_embedded_base")
    base, base_decoded, identity = _validate_base(raw[base_start:base_end])

    extension = raw[base_end:]
    if len(extension) < EXTENSION_HEADER_BYTES:
        raise OutcomeTailWireError("truncated:extension_header")
    if extension[:4] != EXTENSION_MAGIC:
        raise OutcomeTailWireError("extension_magic_mismatch")
    extension_version = struct.unpack_from("<H", extension, 4)[0]
    if extension_version != EXTENSION_VERSION:
        raise OutcomeTailWireError("extension_version_mismatch")
    body_length = struct.unpack_from("<I", extension, 6)[0]
    if body_length != len(extension) - EXTENSION_HEADER_BYTES:
        raise OutcomeTailWireError("extension_length_mismatch")
    body = extension[EXTENSION_HEADER_BYTES:]
    if len(body) < FIXED_BODY_BYTES + len(FIELD_ORDER) * TEXT_HEADER_BYTES:
        raise OutcomeTailWireError("outcome_tail_body_too_short")
    (sequence, raw_date, kind, failure,
     slot0, slot1, slot2) = struct.unpack_from("<QiBHiii", body, 0)
    reserved_slots = [slot0, slot1, slot2]
    if (sequence, raw_date, kind) != identity:
        raise OutcomeTailWireError("outcome_tail_identity_mismatch")
    if sequence == 0 or raw_date < 0 or kind not in (1, 2):
        raise OutcomeTailWireError("outcome_tail_identity_invalid")

    position = FIXED_BODY_BYTES
    fields: dict[str, dict[str, Any]] = {}
    for label in FIELD_ORDER:
        if len(body) - position < TEXT_HEADER_BYTES:
            raise OutcomeTailWireError(f"truncated:{label}.header")
        state_id = body[position]
        length = struct.unpack_from("<H", body, position + 1)[0]
        position += TEXT_HEADER_BYTES
        state = STATE_NAMES.get(state_id)
        if state is None:
            raise OutcomeTailWireError(f"{label}_state_out_of_range")
        if length > len(body) - position:
            raise OutcomeTailWireError(f"truncated:{label}.bytes")
        raw_value = body[position:position + length]
        position += length
        _validate_field(state, raw_value, label)
        fields[label] = {
            "state": state,
            "raw_hex": raw_value.hex(),
            "length": length,
        }
    if position != len(body):
        raise OutcomeTailWireError("trailing_bytes_in_outcome_tail_body")
    _validate_group(failure, fields, reserved_slots)

    composed = dict(base_decoded)
    composed["wire13"] = {"version": VERSION, "source": SOURCE}
    composed["outcome_tail"] = {
        "sequence": sequence,
        "raw_date": raw_date,
        "kind": kind,
        "failure": failure,
        "reserved_slots": reserved_slots,
        "text_fields": fields,
    }
    return composed


def decode(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode v13; delegate every older wire version to the unchanged v12 codec."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return _v12.decode(data)
    raw = _as_bytes(data)
    if (len(raw) < 6 or raw[:4] != MAGIC
            or struct.unpack_from("<H", raw, 4)[0] != VERSION):
        return _v12.decode(raw)
    return _decode_v13(raw)


def encode(base12: bytes | bytearray | memoryview,
           snapshot: Mapping[str, Any]) -> bytes:
    """Embed one complete IBOW12 frame and a strict SCTX outcome tail value."""
    base, _base_decoded, identity = _validate_base(base12)
    if not isinstance(snapshot, Mapping):
        raise OutcomeTailWireError("snapshot_must_be_object")
    expected = {"sequence", "raw_date", "kind", "failure", "reserved_slots", "text_fields"}
    _require_keys(snapshot, expected, "snapshot")
    sequence = _int(snapshot["sequence"], "sequence", 1, (1 << 64) - 1)
    raw_date = _int(snapshot["raw_date"], "raw_date", 0, (1 << 31) - 1)
    kind = _int(snapshot["kind"], "kind", 1, 2)
    failure = _int(snapshot["failure"], "failure", 0, 9)
    raw_slots = snapshot["reserved_slots"]
    if not isinstance(raw_slots, (list, tuple)) or len(raw_slots) != 3:
        raise OutcomeTailWireError("reserved_slots_must_be_three_integers")
    reserved_slots = [
        _int(value, f"reserved_slots_{index}", -(1 << 31), (1 << 31) - 1)
        for index, value in enumerate(raw_slots)
    ]
    if (sequence, raw_date, kind) != identity:
        raise OutcomeTailWireError("outcome_tail_identity_mismatch")
    fields = _normalize_fields(snapshot["text_fields"])
    _validate_group(failure, fields, reserved_slots)

    body = bytearray(struct.pack(
        "<QiBHiii", sequence, raw_date, kind, failure, *reserved_slots,
    ))
    for label in FIELD_ORDER:
        field = fields[label]
        body.extend(struct.pack("<BH", STATE_IDS[field["state"]], field["length"]))
        body.extend(field["raw"])
    result = (
        MAGIC + struct.pack("<HI", VERSION, len(base)) + base
        + EXTENSION_MAGIC + struct.pack("<HI", EXTENSION_VERSION, len(body))
        + body
    )
    if len(result) > MAX_WIRE_BYTES:
        raise OutcomeTailWireError("wire_size_over_bound")
    return result


def validate(data: bytes | bytearray | memoryview) -> bool:
    """Return whether data is a valid v1..v13 frame accepted by decode()."""
    try:
        decode(data)
    except (TypeError, ValueError):
        return False
    return True


__all__ = [
    "BASE_VERSION", "DisplayContextWireError", "EndStateWireError",
    "EXTENSION_MAGIC", "EXTENSION_VERSION", "FIELD_ORDER",
    "FIXED_BODY_BYTES", "MAGIC", "MAX_LANGUAGE_BYTES", "MAX_TEXT_BYTES",
    "MAX_WIRE_BYTES", "NameHandoffWireError", "NameSourcesWireError",
    "OUTER_HEADER_BYTES", "OutcomeTailWireError", "OutcomeTextWireError",
    "RetreatWireError",
    "SOURCE", "STATE_IDS", "STATE_NAMES", "TEXT_HEADER_BYTES", "VERSION",
    "decode", "encode", "validate",
]
