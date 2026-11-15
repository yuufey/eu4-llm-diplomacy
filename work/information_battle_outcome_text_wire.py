"""Strict IBOW v12/OCTX codec for copied battle outcome text.

The complete IBOW v11 frame is embedded unchanged. Text is transported as raw
bytes; this module does not decode, format, select, or expose game strings.
"""
from __future__ import annotations

from collections.abc import Mapping
import re
import struct
from typing import Any

from . import information_battle_name_sources_wire as _v11


MAGIC = b"IBOW"
VERSION = 12
BASE_VERSION = 11
EXTENSION_MAGIC = b"OCTX"
EXTENSION_VERSION = 1
SOURCE = "owned_outcome_text"
MAX_WIRE_BYTES = _v11.MAX_WIRE_BYTES
OUTER_HEADER_BYTES = 10
EXTENSION_HEADER_BYTES = 10
FIXED_BODY_BYTES = 15
TEXT_HEADER_BYTES = 3
MAX_TEXT_BYTES = 8192
MAX_LANGUAGE_BYTES = 256
FIELD_ORDER = (
    "language", "ALLIES_WON", "ALLIES_LOST", "YOU_WON", "YOU_LOST",
    "RESULT_WON", "RESULT_LOSS", "OTHERRESULT", "WARSCORE_FROM_BATTLE",
    "MESSAGE_HEAD_MIL", "MESSENGER",
)
STATE_IDS = {"unknown": 0, "known": 1, "absent": 2}
STATE_NAMES = {value: key for key, value in STATE_IDS.items()}


class OutcomeTextWireError(ValueError):
    """The input is not one strict IBOW v12/OCTX frame or snapshot."""


# Preserve the inherited error names used by callers of earlier codecs.
NameSourcesWireError = _v11.NameSourcesWireError
RetreatWireError = _v11.RetreatWireError
EndStateWireError = _v11.EndStateWireError
NameHandoffWireError = _v11.NameHandoffWireError
DisplayContextWireError = _v11.DisplayContextWireError


def _as_bytes(value: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise OutcomeTextWireError("input_must_be_bytes_like")
    try:
        size = value.nbytes if isinstance(value, memoryview) else len(value)
    except (TypeError, ValueError) as exc:
        raise OutcomeTextWireError("input_length_unavailable") from exc
    if size > MAX_WIRE_BYTES:
        raise OutcomeTextWireError("wire_size_over_bound")
    try:
        raw = bytes(value)
    except (TypeError, ValueError) as exc:
        raise OutcomeTextWireError("input_bytes_conversion_failed") from exc
    if len(raw) > MAX_WIRE_BYTES:
        raise OutcomeTextWireError("wire_size_over_bound")
    return raw


def _require_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    keys = set(value)
    if keys - expected:
        raise OutcomeTextWireError(f"{label}_unknown_keys")
    if expected - keys:
        raise OutcomeTextWireError(f"{label}_missing_keys")


def _int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise OutcomeTextWireError(f"{label}_out_of_range")
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
        raise OutcomeTextWireError("embedded_base_identity_missing") from exc
    if (type(sequence) is not int or not 0 < sequence <= (1 << 64) - 1
            or type(raw_date) is not int or not 0 <= raw_date < (1 << 31)
            or type(kind) is not int or kind not in (1, 2)):
        raise OutcomeTextWireError("embedded_base_identity_invalid")
    return sequence, raw_date, kind


def _validate_base(base: bytes | bytearray | memoryview
                   ) -> tuple[bytes, dict[str, Any], tuple[int, int, int]]:
    raw = _as_bytes(base)
    if (len(raw) < OUTER_HEADER_BYTES + EXTENSION_HEADER_BYTES
            + _v11.FIXED_BODY_BYTES or raw[:4] != MAGIC
            or struct.unpack_from("<H", raw, 4)[0] != BASE_VERSION):
        raise OutcomeTextWireError("embedded_base_is_not_v11")
    try:
        decoded = _v11.decode(raw)
    except (ValueError, TypeError) as exc:
        raise OutcomeTextWireError(f"invalid_embedded_base_v11:{exc}") from exc
    wire11 = decoded.get("wire11") if isinstance(decoded, dict) else None
    if (not isinstance(decoded, dict) or not isinstance(wire11, Mapping)
            or wire11.get("version") != BASE_VERSION
            or wire11.get("source") != _v11.SOURCE):
        raise OutcomeTextWireError("embedded_base_v11_decode_shape_invalid")
    return raw, decoded, _base_identity(decoded)


def _validate_field(state: Any, raw: bytes, label: str) -> None:
    if not isinstance(state, str) or state not in STATE_IDS:
        raise OutcomeTextWireError(f"{label}_state_out_of_range")
    if state in ("unknown", "absent"):
        if raw:
            raise OutcomeTextWireError(f"noncanonical_{label}_{state}")
        if state == "absent" and label == "language":
            raise OutcomeTextWireError("language_cannot_be_absent")
        return
    maximum = MAX_LANGUAGE_BYTES if label == "language" else MAX_TEXT_BYTES
    if len(raw) > maximum:
        raise OutcomeTextWireError(f"{label}_length_over_bound")
    if b"\x00" in raw:
        raise OutcomeTextWireError(f"{label}_contains_nul")
    if label == "language" and re.fullmatch(rb"l_[A-Za-z0-9_]+", raw) is None:
        raise OutcomeTextWireError("language_format_invalid")


def _validate_group(failure: int, fields: Mapping[str, Mapping[str, Any]]) -> None:
    if not 0 <= failure <= 9:
        raise OutcomeTextWireError("failure_out_of_range")
    if failure == 0:
        if fields["language"]["state"] != "known":
            raise OutcomeTextWireError("outcome_text_group_state_mismatch")
        for label in FIELD_ORDER[1:]:
            if fields[label]["state"] not in ("known", "absent"):
                raise OutcomeTextWireError("outcome_text_group_state_mismatch")
    elif any(fields[label]["state"] != "unknown" for label in FIELD_ORDER):
        raise OutcomeTextWireError("outcome_text_group_state_mismatch")


def _normalize_fields(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, Mapping):
        raise OutcomeTextWireError("text_fields_must_be_object")
    _require_keys(value, set(FIELD_ORDER), "text_fields")
    fields: dict[str, dict[str, Any]] = {}
    for label in FIELD_ORDER:
        item = value[label]
        if not isinstance(item, Mapping):
            raise OutcomeTextWireError(f"{label}_must_be_object")
        _require_keys(item, {"state", "raw_hex", "length"}, label)
        state = item["state"]
        raw_hex = item["raw_hex"]
        maximum = MAX_LANGUAGE_BYTES if label == "language" else MAX_TEXT_BYTES
        if (not isinstance(raw_hex, str) or len(raw_hex) > 2 * maximum
                or re.fullmatch(r"(?:[0-9A-Fa-f]{2})*", raw_hex) is None):
            raise OutcomeTextWireError(f"{label}_raw_hex_invalid")
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise OutcomeTextWireError(f"{label}_raw_hex_invalid") from exc
        length = _int(item["length"], f"{label}_length", 0, 65535)
        if length != len(raw):
            raise OutcomeTextWireError(f"{label}_length_mismatch")
        _validate_field(state, raw, label)
        fields[label] = {"state": state, "raw": raw, "length": length}
    return fields


def _decode_v12(raw: bytes) -> dict[str, Any]:
    minimum = (OUTER_HEADER_BYTES + EXTENSION_HEADER_BYTES + FIXED_BODY_BYTES
               + len(FIELD_ORDER) * TEXT_HEADER_BYTES)
    if len(raw) < minimum:
        raise OutcomeTextWireError("wire_too_short")
    if raw[:4] != MAGIC:
        raise OutcomeTextWireError("magic_mismatch")
    if struct.unpack_from("<H", raw, 4)[0] != VERSION:
        raise OutcomeTextWireError("version_mismatch")
    base_size = struct.unpack_from("<I", raw, 6)[0]
    if base_size == 0 or base_size > MAX_WIRE_BYTES:
        raise OutcomeTextWireError("base_length_over_bound")
    base_start = OUTER_HEADER_BYTES
    base_end = base_start + base_size
    if base_end < base_start or base_end > len(raw):
        raise OutcomeTextWireError("truncated_embedded_base")
    base, base_decoded, identity = _validate_base(raw[base_start:base_end])

    extension = raw[base_end:]
    if len(extension) < EXTENSION_HEADER_BYTES:
        raise OutcomeTextWireError("truncated:extension_header")
    if extension[:4] != EXTENSION_MAGIC:
        raise OutcomeTextWireError("extension_magic_mismatch")
    extension_version = struct.unpack_from("<H", extension, 4)[0]
    if extension_version != EXTENSION_VERSION:
        raise OutcomeTextWireError("extension_version_mismatch")
    body_length = struct.unpack_from("<I", extension, 6)[0]
    if body_length != len(extension) - EXTENSION_HEADER_BYTES:
        raise OutcomeTextWireError("extension_length_mismatch")
    body = extension[EXTENSION_HEADER_BYTES:]
    if len(body) < FIXED_BODY_BYTES + len(FIELD_ORDER) * TEXT_HEADER_BYTES:
        raise OutcomeTextWireError("outcome_text_body_too_short")
    sequence, raw_date, kind, failure = struct.unpack_from("<QiBH", body, 0)
    if (sequence, raw_date, kind) != identity:
        raise OutcomeTextWireError("outcome_text_identity_mismatch")
    if sequence == 0 or raw_date < 0 or kind not in (1, 2):
        raise OutcomeTextWireError("outcome_text_identity_invalid")

    position = FIXED_BODY_BYTES
    fields: dict[str, dict[str, Any]] = {}
    for label in FIELD_ORDER:
        if len(body) - position < TEXT_HEADER_BYTES:
            raise OutcomeTextWireError(f"truncated:{label}.header")
        state_id = body[position]
        length = struct.unpack_from("<H", body, position + 1)[0]
        position += TEXT_HEADER_BYTES
        state = STATE_NAMES.get(state_id)
        if state is None:
            raise OutcomeTextWireError(f"{label}_state_out_of_range")
        if length > len(body) - position:
            raise OutcomeTextWireError(f"truncated:{label}.bytes")
        raw_value = body[position:position + length]
        position += length
        _validate_field(state, raw_value, label)
        fields[label] = {
            "state": state,
            "raw_hex": raw_value.hex(),
            "length": length,
        }
    if position != len(body):
        raise OutcomeTextWireError("trailing_bytes_in_outcome_text_body")
    _validate_group(failure, fields)

    composed = dict(base_decoded)
    composed["wire12"] = {"version": VERSION, "source": SOURCE}
    composed["outcome_text"] = {
        "sequence": sequence,
        "raw_date": raw_date,
        "kind": kind,
        "failure": failure,
        "text_fields": fields,
    }
    return composed


def decode(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode v12, delegating all older versions unchanged to the v11 codec."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return _v11.decode(data)
    raw = _as_bytes(data)
    if (len(raw) < 6 or raw[:4] != MAGIC
            or struct.unpack_from("<H", raw, 4)[0] != VERSION):
        return _v11.decode(raw)
    return _decode_v12(raw)


def encode(base11: bytes | bytearray | memoryview,
           snapshot: Mapping[str, Any]) -> bytes:
    """Embed one complete IBOW11 frame and a strict OCTX outcome text value."""
    base, _base_decoded, identity = _validate_base(base11)
    if not isinstance(snapshot, Mapping):
        raise OutcomeTextWireError("snapshot_must_be_object")
    expected = {"sequence", "raw_date", "kind", "failure", "text_fields"}
    _require_keys(snapshot, expected, "snapshot")
    sequence = _int(snapshot["sequence"], "sequence", 1, (1 << 64) - 1)
    raw_date = _int(snapshot["raw_date"], "raw_date", 0, (1 << 31) - 1)
    kind = _int(snapshot["kind"], "kind", 1, 2)
    failure = _int(snapshot["failure"], "failure", 0, 9)
    if (sequence, raw_date, kind) != identity:
        raise OutcomeTextWireError("outcome_text_identity_mismatch")
    fields = _normalize_fields(snapshot["text_fields"])
    _validate_group(failure, fields)

    body = bytearray(struct.pack("<QiBH", sequence, raw_date, kind, failure))
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
        raise OutcomeTextWireError("wire_size_over_bound")
    return result


def validate(data: bytes | bytearray | memoryview) -> bool:
    """Return whether data is a valid v1..v12 frame accepted by decode()."""
    try:
        decode(data)
    except (OutcomeTextWireError, NameSourcesWireError, TypeError, ValueError):
        return False
    return True


__all__ = [
    "BASE_VERSION", "DisplayContextWireError", "EndStateWireError",
    "EXTENSION_MAGIC", "EXTENSION_VERSION", "FIELD_ORDER",
    "FIXED_BODY_BYTES", "MAGIC", "MAX_LANGUAGE_BYTES", "MAX_TEXT_BYTES",
    "MAX_WIRE_BYTES", "NameHandoffWireError", "NameSourcesWireError",
    "OUTER_HEADER_BYTES", "OutcomeTextWireError", "RetreatWireError",
    "SOURCE", "STATE_IDS", "STATE_NAMES", "TEXT_HEADER_BYTES", "VERSION",
    "decode", "encode", "validate",
]
