"""Strict IBOW v14/IFMT codec for owned independent battle-line values.

The complete IBOW v13 frame is embedded unchanged. Text is transported as raw
bytes; this module does not decode or format game strings.
"""
from __future__ import annotations

from collections.abc import Mapping
import re
import struct
from typing import Any

from . import information_battle_outcome_tail_wire as _v13


MAGIC = b"IBOW"
VERSION = 14
BASE_VERSION = 13
EXTENSION_MAGIC = b"IFMT"
EXTENSION_VERSION = 1
SOURCE = "owned_independent_line"
MAX_WIRE_BYTES = _v13.MAX_WIRE_BYTES
OUTER_HEADER_BYTES = 10
EXTENSION_HEADER_BYTES = 10
FIXED_BODY_BYTES = 17
TEXT_HEADER_BYTES = 3
MAX_LANGUAGE_BYTES = 256
MAX_DEFINITION_KEY_BYTES = 64
MAX_TEXT_BYTES = 8192
FIELD_ORDER = (
    "language", "definition_key", "body_template", "name_input", "output",
)
STATE_IDS = {"unknown": 0, "known": 1}
STATE_NAMES = {value: key for key, value in STATE_IDS.items()}
TRANSFORM_MODES = {"unknown": 0, "original_helper_inputs": 1,
                   "pinned_plugin_preassignment_inputs": 2}


class IndependentLineWireError(ValueError):
    """The input is not one strict IBOW v14/IFMT frame or snapshot."""


# Preserve inherited error names used by callers of earlier battle codecs.
OutcomeTailWireError = _v13.OutcomeTailWireError
OutcomeTextWireError = _v13.OutcomeTextWireError
NameSourcesWireError = _v13.NameSourcesWireError
RetreatWireError = _v13.RetreatWireError
EndStateWireError = _v13.EndStateWireError
NameHandoffWireError = _v13.NameHandoffWireError
DisplayContextWireError = _v13.DisplayContextWireError


def _as_bytes(value: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise IndependentLineWireError("input_must_be_bytes_like")
    try:
        size = value.nbytes if isinstance(value, memoryview) else len(value)
    except (TypeError, ValueError) as exc:
        raise IndependentLineWireError("input_length_unavailable") from exc
    if size > MAX_WIRE_BYTES:
        raise IndependentLineWireError("wire_size_over_bound")
    try:
        raw = bytes(value)
    except (TypeError, ValueError) as exc:
        raise IndependentLineWireError("input_bytes_conversion_failed") from exc
    if len(raw) > MAX_WIRE_BYTES:
        raise IndependentLineWireError("wire_size_over_bound")
    return raw


def _require_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    keys = set(value)
    if keys - expected:
        raise IndependentLineWireError(f"{label}_unknown_keys")
    if expected - keys:
        raise IndependentLineWireError(f"{label}_missing_keys")


def _int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise IndependentLineWireError(f"{label}_out_of_range")
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
        raise IndependentLineWireError("embedded_base_identity_missing") from exc
    if (type(sequence) is not int or not 0 < sequence <= (1 << 64) - 1
            or type(raw_date) is not int or not 0 <= raw_date < (1 << 31)
            or type(kind) is not int or kind not in (1, 2)):
        raise IndependentLineWireError("embedded_base_identity_invalid")
    return sequence, raw_date, kind


def _validate_base(base: bytes | bytearray | memoryview
                   ) -> tuple[bytes, dict[str, Any], tuple[int, int, int]]:
    raw = _as_bytes(base)
    if (len(raw) < OUTER_HEADER_BYTES + EXTENSION_HEADER_BYTES
            + _v13.FIXED_BODY_BYTES
            + len(_v13.FIELD_ORDER) * _v13.TEXT_HEADER_BYTES
            or raw[:4] != MAGIC
            or struct.unpack_from("<H", raw, 4)[0] != BASE_VERSION):
        raise IndependentLineWireError("embedded_base_is_not_v13")
    if not _v13.validate(raw):
        raise IndependentLineWireError("invalid_embedded_base_v13")
    try:
        decoded = _v13.decode(raw)
    except (ValueError, TypeError) as exc:
        raise IndependentLineWireError(f"invalid_embedded_base_v13:{exc}") from exc
    wire13 = decoded.get("wire13") if isinstance(decoded, dict) else None
    if (not isinstance(decoded, dict) or not isinstance(wire13, Mapping)
            or wire13.get("version") != BASE_VERSION
            or wire13.get("source") != _v13.SOURCE):
        raise IndependentLineWireError("embedded_base_v13_decode_shape_invalid")
    return raw, decoded, _base_identity(decoded)


def _field_limit(label: str) -> int:
    if label == "language":
        return MAX_LANGUAGE_BYTES
    if label == "definition_key":
        return MAX_DEFINITION_KEY_BYTES
    return MAX_TEXT_BYTES


def _validate_field(state: Any, raw: bytes, label: str, kind: int) -> None:
    if not isinstance(state, str) or state not in STATE_IDS:
        raise IndependentLineWireError(f"{label}_state_out_of_range")
    if state == "unknown":
        if raw:
            raise IndependentLineWireError(f"noncanonical_{label}_unknown")
        return
    if len(raw) > _field_limit(label):
        raise IndependentLineWireError(f"{label}_length_over_bound")
    if b"\x00" in raw:
        raise IndependentLineWireError(f"{label}_contains_nul")
    if label == "language" and re.fullmatch(rb"l_[A-Za-z0-9_]+", raw) is None:
        raise IndependentLineWireError("language_format_invalid")
    if label == "definition_key":
        expected = b"LANDBATTLEOVER" if kind == 1 else b"NAVALBATTLEOVER"
        if raw != expected:
            raise IndependentLineWireError("definition_key_mismatch")
    if label == "body_template" and raw != b"$NAME$":
        raise IndependentLineWireError("body_template_mismatch")


def _normalize_fields(value: Any, kind: int) -> dict[str, dict[str, Any]]:
    if not isinstance(value, Mapping):
        raise IndependentLineWireError("text_fields_must_be_object")
    _require_keys(value, set(FIELD_ORDER), "text_fields")
    fields: dict[str, dict[str, Any]] = {}
    for label in FIELD_ORDER:
        item = value[label]
        if not isinstance(item, Mapping):
            raise IndependentLineWireError(f"{label}_must_be_object")
        _require_keys(item, {"state", "raw_hex", "length"}, label)
        state = item["state"]
        raw_hex = item["raw_hex"]
        maximum = _field_limit(label)
        if (not isinstance(raw_hex, str) or len(raw_hex) > 2 * maximum
                or re.fullmatch(r"(?:[0-9A-Fa-f]{2})*", raw_hex) is None):
            raise IndependentLineWireError(f"{label}_raw_hex_invalid")
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise IndependentLineWireError(f"{label}_raw_hex_invalid") from exc
        length = _int(item["length"], f"{label}_length", 0, 65535)
        if length != len(raw):
            raise IndependentLineWireError(f"{label}_length_mismatch")
        _validate_field(state, raw, label, kind)
        fields[label] = {"state": state, "raw": raw, "length": length}
    return fields


def _validate_group(state: str, failure: int, transform_mode: int, flags: int,
                    fields: Mapping[str, Mapping[str, Any]]) -> None:
    if not 0 <= failure <= 12:
        raise IndependentLineWireError("failure_out_of_range")
    if not 0 <= transform_mode <= 2:
        raise IndependentLineWireError("transform_mode_out_of_range")
    if not 0 <= flags <= 15:
        raise IndependentLineWireError("flags_out_of_range")
    if flags & 0x6 and not flags & 0x1:
        raise IndependentLineWireError("returned_or_destroyed_without_invocation")
    if state == "known":
        if failure != 0 or transform_mode not in (1, 2) or flags != 15:
            raise IndependentLineWireError("known_independent_line_group_mismatch")
        if any(fields[label]["state"] != "known" for label in FIELD_ORDER):
            raise IndependentLineWireError("known_independent_line_fields_incomplete")
    elif state == "unknown":
        if failure == 0 or transform_mode != 0:
            raise IndependentLineWireError("unknown_independent_line_group_mismatch")
        if any(fields[label]["state"] != "unknown" for label in FIELD_ORDER):
            raise IndependentLineWireError("unknown_independent_line_fields_mixed")
    else:
        raise IndependentLineWireError("independent_line_state_out_of_range")


def _decode_v14(raw: bytes) -> dict[str, Any]:
    minimum = (OUTER_HEADER_BYTES + EXTENSION_HEADER_BYTES + FIXED_BODY_BYTES
               + len(FIELD_ORDER) * TEXT_HEADER_BYTES)
    if len(raw) < minimum:
        raise IndependentLineWireError("wire_too_short")
    if raw[:4] != MAGIC:
        raise IndependentLineWireError("magic_mismatch")
    if struct.unpack_from("<H", raw, 4)[0] != VERSION:
        raise IndependentLineWireError("version_mismatch")
    base_size = struct.unpack_from("<I", raw, 6)[0]
    if base_size == 0 or base_size > MAX_WIRE_BYTES:
        raise IndependentLineWireError("base_length_over_bound")
    base_start = OUTER_HEADER_BYTES
    base_end = base_start + base_size
    if base_end < base_start or base_end > len(raw):
        raise IndependentLineWireError("truncated_embedded_base")
    base, base_decoded, identity = _validate_base(raw[base_start:base_end])

    extension = raw[base_end:]
    if len(extension) < EXTENSION_HEADER_BYTES:
        raise IndependentLineWireError("truncated:extension_header")
    if extension[:4] != EXTENSION_MAGIC:
        raise IndependentLineWireError("extension_magic_mismatch")
    if struct.unpack_from("<H", extension, 4)[0] != EXTENSION_VERSION:
        raise IndependentLineWireError("extension_version_mismatch")
    body_length = struct.unpack_from("<I", extension, 6)[0]
    if body_length != len(extension) - EXTENSION_HEADER_BYTES:
        raise IndependentLineWireError("extension_length_mismatch")
    body = extension[EXTENSION_HEADER_BYTES:]
    if len(body) < FIXED_BODY_BYTES + len(FIELD_ORDER) * TEXT_HEADER_BYTES:
        raise IndependentLineWireError("independent_line_body_too_short")
    sequence, raw_date, kind, state_id, failure, transform_mode, flags = (
        struct.unpack_from("<QiBBBBB", body, 0)
    )
    if (sequence, raw_date, kind) != identity:
        raise IndependentLineWireError("independent_line_identity_mismatch")
    if sequence == 0 or raw_date < 0 or kind not in (1, 2):
        raise IndependentLineWireError("independent_line_identity_invalid")
    state = STATE_NAMES.get(state_id)
    if state is None:
        raise IndependentLineWireError("independent_line_state_out_of_range")

    position = FIXED_BODY_BYTES
    fields: dict[str, dict[str, Any]] = {}
    for label in FIELD_ORDER:
        if len(body) - position < TEXT_HEADER_BYTES:
            raise IndependentLineWireError(f"truncated:{label}.header")
        field_state_id = body[position]
        length = struct.unpack_from("<H", body, position + 1)[0]
        position += TEXT_HEADER_BYTES
        field_state = STATE_NAMES.get(field_state_id)
        if field_state is None:
            raise IndependentLineWireError(f"{label}_state_out_of_range")
        if length > len(body) - position:
            raise IndependentLineWireError(f"truncated:{label}.bytes")
        raw_value = body[position:position + length]
        position += length
        _validate_field(field_state, raw_value, label, kind)
        fields[label] = {
            "state": field_state,
            "raw_hex": raw_value.hex(),
            "length": length,
        }
    if position != len(body):
        raise IndependentLineWireError("trailing_bytes_in_independent_line_body")
    _validate_group(state, failure, transform_mode, flags, fields)

    composed = dict(base_decoded)
    composed["wire14"] = {
        "version": VERSION, "base_version": BASE_VERSION, "source": SOURCE,
    }
    composed["independent_line"] = {
        "sequence": sequence,
        "raw_date": raw_date,
        "kind": kind,
        "state": state,
        "failure": failure,
        "transform_mode": transform_mode,
        "flags": flags,
        "text_fields": fields,
    }
    return composed


def decode(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode v14; delegate all older wire versions to the unchanged v13 codec."""
    raw = _as_bytes(data)
    if (len(raw) < 6 or raw[:4] != MAGIC
            or struct.unpack_from("<H", raw, 4)[0] != VERSION):
        return _v13.decode(raw)
    return _decode_v14(raw)


def encode(base13: bytes | bytearray | memoryview,
           snapshot: Mapping[str, Any]) -> bytes:
    """Embed one complete IBOW13 frame and one strict IFMT independent line."""
    base, _base_decoded, identity = _validate_base(base13)
    if not isinstance(snapshot, Mapping):
        raise IndependentLineWireError("snapshot_must_be_object")
    expected = {
        "sequence", "raw_date", "kind", "state", "failure",
        "transform_mode", "flags", "text_fields",
    }
    _require_keys(snapshot, expected, "snapshot")
    sequence = _int(snapshot["sequence"], "sequence", 1, (1 << 64) - 1)
    raw_date = _int(snapshot["raw_date"], "raw_date", 0, (1 << 31) - 1)
    kind = _int(snapshot["kind"], "kind", 1, 2)
    state = snapshot["state"]
    if not isinstance(state, str) or state not in STATE_IDS:
        raise IndependentLineWireError("independent_line_state_out_of_range")
    failure = _int(snapshot["failure"], "failure", 0, 12)
    transform_mode = _int(snapshot["transform_mode"], "transform_mode", 0, 2)
    flags = _int(snapshot["flags"], "flags", 0, 15)
    if (sequence, raw_date, kind) != identity:
        raise IndependentLineWireError("independent_line_identity_mismatch")
    fields = _normalize_fields(snapshot["text_fields"], kind)
    _validate_group(state, failure, transform_mode, flags, fields)

    body = bytearray(struct.pack(
        "<QiBBBBB", sequence, raw_date, kind, STATE_IDS[state], failure,
        transform_mode, flags,
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
        raise IndependentLineWireError("wire_size_over_bound")
    return result


def validate(data: bytes | bytearray | memoryview) -> bool:
    """Return whether data is a valid v1..v14 frame accepted by decode()."""
    try:
        decode(data)
    except (TypeError, ValueError):
        return False
    return True


__all__ = [
    "BASE_VERSION", "DisplayContextWireError", "EndStateWireError",
    "EXTENSION_MAGIC", "EXTENSION_VERSION", "FIELD_ORDER",
    "FIXED_BODY_BYTES", "IndependentLineWireError", "MAGIC",
    "MAX_DEFINITION_KEY_BYTES", "MAX_LANGUAGE_BYTES", "MAX_TEXT_BYTES",
    "MAX_WIRE_BYTES", "NameHandoffWireError", "NameSourcesWireError",
    "OUTER_HEADER_BYTES", "OutcomeTailWireError", "OutcomeTextWireError",
    "RetreatWireError", "SOURCE", "STATE_IDS", "STATE_NAMES",
    "TEXT_HEADER_BYTES", "TRANSFORM_MODES", "VERSION", "decode", "encode",
    "validate",
]
