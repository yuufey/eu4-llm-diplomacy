"""Strict IBOW v11/NSRC codec for copied battle name sources.

The complete v10 frame is embedded unchanged. Text is transported as raw
bytes; decoding the game's string codec is outside this wire layer.
"""
from __future__ import annotations

from collections.abc import Mapping
import re
import struct
from typing import Any

from . import information_battle_retreat_wire as _v10


MAGIC = b"IBOW"
VERSION = 11
BASE_VERSION = 10
EXTENSION_MAGIC = b"NSRC"
EXTENSION_VERSION = 1
SOURCE = "owned_name_sources"
MAX_WIRE_BYTES = _v10.MAX_WIRE_BYTES
OUTER_HEADER_BYTES = 10
EXTENSION_HEADER_BYTES = 10
FIXED_BODY_BYTES = 29
TEXT_HEADER_BYTES = 3
MAX_TEXT_BYTES = 8192
MAX_LANGUAGE_BYTES = 256
TEXT_FIELDS = (
    "owner_name", "global_name", "battle_of_template", "language",
)
STATE_IDS = {"unknown": 0, "known": 1, "absent": 2}
STATE_NAMES = {value: key for key, value in STATE_IDS.items()}


class NameSourcesWireError(ValueError):
    """The input is not one strict IBOW v11/NSRC frame or snapshot."""


# Compatibility exports for callers that imported an inherited wire error.
RetreatWireError = _v10.RetreatWireError
EndStateWireError = _v10.EndStateWireError
NameHandoffWireError = _v10.NameHandoffWireError
DisplayContextWireError = _v10.DisplayContextWireError


def _as_bytes(value: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise NameSourcesWireError("input_must_be_bytes_like")
    try:
        size = value.nbytes if isinstance(value, memoryview) else len(value)
    except (TypeError, ValueError) as exc:
        raise NameSourcesWireError("input_length_unavailable") from exc
    if size > MAX_WIRE_BYTES:
        raise NameSourcesWireError("wire_size_over_bound")
    try:
        raw = bytes(value)
    except (TypeError, ValueError) as exc:
        raise NameSourcesWireError("input_bytes_conversion_failed") from exc
    if len(raw) > MAX_WIRE_BYTES:
        raise NameSourcesWireError("wire_size_over_bound")
    return raw


def _require_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    keys = set(value)
    if keys - expected:
        raise NameSourcesWireError(f"{label}_unknown_keys")
    if expected - keys:
        raise NameSourcesWireError(f"{label}_missing_keys")


def _int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise NameSourcesWireError(f"{label}_out_of_range")
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
        raise NameSourcesWireError("embedded_base_identity_missing") from exc
    if (type(sequence) is not int or not 0 < sequence <= (1 << 64) - 1
            or type(raw_date) is not int or not 0 <= raw_date < (1 << 31)
            or type(kind) is not int or kind not in (1, 2)):
        raise NameSourcesWireError("embedded_base_identity_invalid")
    return sequence, raw_date, kind


def _validate_base(base: bytes | bytearray | memoryview) -> tuple[bytes, dict[str, Any], tuple[int, int, int]]:
    raw = _as_bytes(base)
    if (len(raw) < 6 or raw[:4] != MAGIC
            or struct.unpack_from("<H", raw, 4)[0] != BASE_VERSION):
        raise NameSourcesWireError("embedded_base_is_not_v10")
    try:
        decoded = _v10.decode(raw)
    except (ValueError, TypeError) as exc:
        raise NameSourcesWireError(f"invalid_embedded_base_v10:{exc}") from exc
    wire10 = decoded.get("wire10") if isinstance(decoded, dict) else None
    if (not isinstance(decoded, dict) or not isinstance(wire10, Mapping)
            or wire10.get("version") != BASE_VERSION):
        raise NameSourcesWireError("embedded_base_v10_decode_shape_invalid")
    identity = _base_identity(decoded)
    return raw, decoded, identity


def _validate_field(state: Any, raw: bytes, label: str) -> None:
    if state not in STATE_IDS:
        raise NameSourcesWireError(f"{label}_state_out_of_range")
    if state in ("unknown", "absent"):
        if raw:
            raise NameSourcesWireError(f"noncanonical_{label}_{state}")
        if state == "absent" and label != "battle_of_template":
            raise NameSourcesWireError(f"{label}_cannot_be_absent")
        return
    maximum = MAX_LANGUAGE_BYTES if label == "language" else MAX_TEXT_BYTES
    if len(raw) > maximum:
        raise NameSourcesWireError(f"{label}_length_over_bound")
    if b"\x00" in raw:
        raise NameSourcesWireError(f"{label}_contains_nul")
    if label == "language" and re.fullmatch(rb"l_[A-Za-z0-9_]+", raw) is None:
        raise NameSourcesWireError("language_format_invalid")


def _validate_groups(raw_failure: int, prefix_failure: int,
                     fields: Mapping[str, Mapping[str, Any]]) -> None:
    if not 0 <= raw_failure <= 12:
        raise NameSourcesWireError("raw_failure_out_of_range")
    if not 0 <= prefix_failure <= 9:
        raise NameSourcesWireError("prefix_failure_out_of_range")
    owner = fields["owner_name"]["state"]
    global_name = fields["global_name"]["state"]
    if raw_failure == 0:
        if owner != "known" or global_name != "known":
            raise NameSourcesWireError("raw_group_state_mismatch")
    elif owner != "unknown" or global_name != "unknown":
        raise NameSourcesWireError("raw_group_state_mismatch")
    template = fields["battle_of_template"]["state"]
    language = fields["language"]["state"]
    if prefix_failure == 0:
        if language != "known" or template not in ("known", "absent"):
            raise NameSourcesWireError("prefix_group_state_mismatch")
    elif language != "unknown" or template != "unknown":
        raise NameSourcesWireError("prefix_group_state_mismatch")


def _decode_body(body: bytes, identity: tuple[int, int, int]) -> dict[str, Any]:
    if len(body) < FIXED_BODY_BYTES:
        raise NameSourcesWireError("name_sources_body_too_short")
    sequence, raw_date, kind, raw_failure, prefix_failure, transform_mode = struct.unpack_from(
        "<QiBBHB", body, 0,
    )
    if (sequence, raw_date, kind) != identity:
        raise NameSourcesWireError("name_sources_identity_mismatch")
    if raw_date < 0 or sequence == 0 or kind not in (1, 2):
        raise NameSourcesWireError("name_sources_identity_invalid")
    if transform_mode not in (0, 1, 2):
        raise NameSourcesWireError("transform_mode_out_of_range")
    position = 17
    fields: dict[str, dict[str, Any]] = {}
    states: dict[str, str] = {}
    for label in TEXT_FIELDS:
        if len(body) - position < TEXT_HEADER_BYTES:
            raise NameSourcesWireError(f"truncated:{label}.header")
        state_id = body[position]
        length = struct.unpack_from("<H", body, position + 1)[0]
        position += TEXT_HEADER_BYTES
        state = STATE_NAMES.get(state_id)
        if state is None:
            raise NameSourcesWireError(f"{label}_state_out_of_range")
        if length > len(body) - position:
            raise NameSourcesWireError(f"truncated:{label}.bytes")
        raw = body[position:position + length]
        position += length
        _validate_field(state, raw, label)
        states[label] = state
        fields[label] = {"state": state, "raw_hex": raw.hex(), "length": length}
    if position != len(body):
        raise NameSourcesWireError("trailing_bytes_in_name_sources_body")
    _validate_groups(raw_failure, prefix_failure, fields)
    return {
        "sequence": sequence,
        "raw_date": raw_date,
        "kind": kind,
        "raw_failure": raw_failure,
        "prefix_failure": prefix_failure,
        "transform_mode": transform_mode,
        "text_fields": fields,
    }


def decode_envelope(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode v11 framing and NSRC while validating the complete v10 base."""
    raw = _as_bytes(data)
    if len(raw) < OUTER_HEADER_BYTES + EXTENSION_HEADER_BYTES + FIXED_BODY_BYTES:
        raise NameSourcesWireError("wire_too_short")
    if raw[:4] != MAGIC:
        raise NameSourcesWireError("magic_mismatch")
    if struct.unpack_from("<H", raw, 4)[0] != VERSION:
        raise NameSourcesWireError("version_mismatch")
    base_bytes = struct.unpack_from("<I", raw, 6)[0]
    if base_bytes == 0 or base_bytes > MAX_WIRE_BYTES:
        raise NameSourcesWireError("base_length_over_bound")
    base_start = OUTER_HEADER_BYTES
    base_end = base_start + base_bytes
    if base_end < base_start or base_end > len(raw):
        raise NameSourcesWireError("truncated_embedded_base")
    base, _base_decoded, identity = _validate_base(raw[base_start:base_end])

    extension = raw[base_end:]
    if len(extension) < EXTENSION_HEADER_BYTES:
        raise NameSourcesWireError("truncated:extension_header")
    if extension[:4] != EXTENSION_MAGIC:
        raise NameSourcesWireError("extension_magic_mismatch")
    extension_version = struct.unpack_from("<H", extension, 4)[0]
    if extension_version != EXTENSION_VERSION:
        raise NameSourcesWireError("extension_version_mismatch")
    body_length = struct.unpack_from("<I", extension, 6)[0]
    if body_length != len(extension) - EXTENSION_HEADER_BYTES:
        raise NameSourcesWireError("extension_length_mismatch")
    body = extension[EXTENSION_HEADER_BYTES:]
    name_sources = _decode_body(body, identity)
    return {
        "schema": "information_battle_name_sources_wire_envelope_v11",
        "wire11": {
            "version": VERSION,
            "source": SOURCE,
            "bytes": len(raw),
            "base_version": BASE_VERSION,
            "base_bytes": len(base),
            "extension_magic": EXTENSION_MAGIC.decode("ascii"),
            "extension_version": extension_version,
            "extension_bytes": body_length,
            "trailing_bytes": 0,
        },
        "base_payload_hex": base.hex(),
        "name_sources": name_sources,
        "complete": False,
    }


def decode(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Delegate versions 1..10 unchanged and compose strict v11 NSRC data."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return _v10.decode(data)
    if isinstance(data, memoryview):
        try:
            size = data.nbytes
        except (TypeError, ValueError) as exc:
            raise NameSourcesWireError("input_length_unavailable") from exc
        if size > MAX_WIRE_BYTES:
            raise NameSourcesWireError("wire_size_over_bound")
        try:
            data = bytes(data)
        except (TypeError, ValueError) as exc:
            raise NameSourcesWireError("input_bytes_conversion_failed") from exc
    try:
        if len(data) < 6:
            return _v10.decode(data)
        prefix = bytes(data[:6])
    except (TypeError, ValueError) as exc:
        raise NameSourcesWireError("input_bytes_conversion_failed") from exc
    if prefix[:4] != MAGIC or struct.unpack_from("<H", prefix, 4)[0] != VERSION:
        return _v10.decode(data)
    raw = _as_bytes(data)
    envelope = decode_envelope(raw)
    base = bytes.fromhex(envelope["base_payload_hex"])
    _base, base_decoded, _identity = _validate_base(base)
    composed = dict(base_decoded)
    composed["wire11"] = {
        "version": VERSION,
        "source": SOURCE,
    }
    composed["name_sources"] = envelope["name_sources"]
    composed["complete"] = False
    return composed


def _normalize_fields(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, Mapping):
        raise NameSourcesWireError("text_fields_must_be_object")
    _require_keys(value, set(TEXT_FIELDS), "text_fields")
    fields: dict[str, dict[str, Any]] = {}
    for label in TEXT_FIELDS:
        item = value[label]
        if not isinstance(item, Mapping):
            raise NameSourcesWireError(f"{label}_must_be_object")
        _require_keys(item, {"state", "raw_hex", "length"}, label)
        state = item["state"]
        if not isinstance(state, str) or state not in STATE_IDS:
            raise NameSourcesWireError(f"{label}_state_out_of_range")
        raw_hex = item["raw_hex"]
        maximum = MAX_LANGUAGE_BYTES if label == "language" else MAX_TEXT_BYTES
        if (not isinstance(raw_hex, str) or len(raw_hex) > 2 * maximum
                or re.fullmatch(r"(?:[0-9A-Fa-f]{2})*", raw_hex) is None):
            raise NameSourcesWireError(f"{label}_raw_hex_invalid")
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise NameSourcesWireError(f"{label}_raw_hex_invalid") from exc
        length = _int(item["length"], f"{label}_length", 0, 65535)
        if length != len(raw):
            raise NameSourcesWireError(f"{label}_length_mismatch")
        _validate_field(state, raw, label)
        fields[label] = {"state": state, "raw": raw, "length": length}
    return fields


def encode(base: bytes | bytearray | memoryview,
           snapshot: Mapping[str, Any]) -> bytes:
    """Encode one complete v10 base and a strict pointer-free NSRC snapshot."""
    base_bytes, _base_decoded, base_identity = _validate_base(base)
    if not isinstance(snapshot, Mapping):
        raise NameSourcesWireError("snapshot_must_be_object")
    required = {
        "sequence", "raw_date", "kind", "raw_failure", "prefix_failure",
        "text_fields",
    }
    expected = required | {"transform_mode"}
    keys = set(snapshot)
    if keys - expected:
        raise NameSourcesWireError("snapshot_unknown_keys")
    if required - keys:
        raise NameSourcesWireError("snapshot_missing_keys")
    sequence = _int(snapshot["sequence"], "sequence", 1, (1 << 64) - 1)
    raw_date = _int(snapshot["raw_date"], "raw_date", 0, (1 << 31) - 1)
    kind = _int(snapshot["kind"], "kind", 1, 2)
    raw_failure = _int(snapshot["raw_failure"], "raw_failure", 0, 12)
    prefix_failure = _int(snapshot["prefix_failure"], "prefix_failure", 0, 9)
    transform_mode = _int(snapshot.get("transform_mode", 0), "transform_mode", 0, 2)
    if (sequence, raw_date, kind) != base_identity:
        raise NameSourcesWireError("name_sources_identity_mismatch")
    fields = _normalize_fields(snapshot["text_fields"])
    _validate_groups(raw_failure, prefix_failure, fields)

    body = bytearray(struct.pack(
        "<QiBBHB", sequence, raw_date, kind, raw_failure, prefix_failure,
        transform_mode,
    ))
    for label in TEXT_FIELDS:
        field = fields[label]
        body.extend(struct.pack(
            "<BH", STATE_IDS[field["state"]], field["length"],
        ))
        body.extend(field["raw"])
    result = (
        MAGIC + struct.pack("<HI", VERSION, len(base_bytes)) + base_bytes
        + EXTENSION_MAGIC
        + struct.pack("<HI", EXTENSION_VERSION, len(body)) + body
    )
    if len(result) > MAX_WIRE_BYTES:
        raise NameSourcesWireError("wire_size_over_bound")
    return result


def validate(data: bytes | bytearray | memoryview) -> bool:
    try:
        decode_envelope(data)
    except (NameSourcesWireError, TypeError, ValueError):
        return False
    return True


__all__ = [
    "BASE_VERSION", "DisplayContextWireError", "EXTENSION_MAGIC",
    "EXTENSION_VERSION", "EndStateWireError", "FIXED_BODY_BYTES",
    "MAGIC", "MAX_LANGUAGE_BYTES", "MAX_TEXT_BYTES", "MAX_WIRE_BYTES",
    "NameHandoffWireError", "NameSourcesWireError", "OUTER_HEADER_BYTES",
    "RetreatWireError", "SOURCE", "STATE_IDS", "STATE_NAMES",
    "TEXT_FIELDS", "VERSION", "decode", "decode_envelope", "encode",
    "validate",
]
