"""Strict IBOW v9/EOST codec for copied battle end-state bytes.

The v9 frame preserves one complete v7 or v8 frame byte-for-byte and appends
two copied raw gate bytes.  The codec does not interpret those bytes as
booleans and does not infer effects from a missing snapshot.
"""
from __future__ import annotations

from collections.abc import Mapping
import struct
from typing import Any

from . import information_battle_display_context_wire as _v7
from . import information_battle_name_handoff_wire as _v8


MAGIC = b"IBOW"
VERSION = 9
EXTENSION_MAGIC = b"EOST"
EXTENSION_VERSION = 1
BASE_VERSIONS = frozenset((7, 8))
MAX_WIRE_BYTES = _v8.MAX_WIRE_BYTES
OUTER_HEADER_BYTES = 10
EXTENSION_HEADER_BYTES = 10
BODY_BYTES = 16
STATE_IDS = {"unknown": 0, "known": 1}
STATE_NAMES = {value: key for key, value in STATE_IDS.items()}

NameHandoffWireError = _v8.NameHandoffWireError
DisplayContextWireError = _v8.DisplayContextWireError


class EndStateWireError(ValueError):
    """The input is not a strict IBOW v9/EOST frame or snapshot."""


def _as_bytes(value: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise EndStateWireError("input_must_be_bytes_like")
    try:
        size = len(value)
    except (TypeError, ValueError) as exc:
        raise EndStateWireError("input_length_unavailable") from exc
    if size > MAX_WIRE_BYTES:
        raise EndStateWireError("wire_size_over_bound")
    try:
        raw = bytes(value)
    except (TypeError, ValueError) as exc:
        raise EndStateWireError("input_bytes_conversion_failed") from exc
    if len(raw) > MAX_WIRE_BYTES:
        raise EndStateWireError("wire_size_over_bound")
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
            raise EndStateWireError(f"truncated:{label}")
        start = self.position
        self.position += size
        return self.data[start:self.position]

    def u8(self, label: str) -> int:
        return self.take(1, label)[0]

    def u16(self, label: str) -> int:
        return struct.unpack("<H", self.take(2, label))[0]

    def u32(self, label: str) -> int:
        return struct.unpack("<I", self.take(4, label))[0]


def _base_version(base: bytes) -> int:
    if len(base) < 6 or base[:4] != MAGIC:
        raise EndStateWireError("embedded_base_magic_or_header_invalid")
    version = struct.unpack_from("<H", base, 4)[0]
    if version not in BASE_VERSIONS:
        raise EndStateWireError("embedded_base_version_unsupported")
    return version


def _decode_base(base: bytes) -> tuple[int, dict[str, Any]]:
    version = _base_version(base)
    try:
        decoded = _v7.decode(base) if version == 7 else _v8.decode(base)
    except (ValueError, TypeError) as exc:
        raise EndStateWireError(f"embedded_base_decode_failed:{exc}") from exc
    if not isinstance(decoded, dict):
        raise EndStateWireError("embedded_base_decode_shape_invalid")
    if version == 7:
        wire_version = decoded.get("wire7", {}).get("version")
    else:
        wire_version = decoded.get("wire8", {}).get("version")
    if wire_version != version:
        raise EndStateWireError("embedded_base_decoder_version_mismatch")
    return version, decoded


def _base_identity(decoded: Mapping[str, Any]) -> tuple[int, int, int]:
    try:
        observation = decoded["observation"]
        result = observation["result"]
        context = decoded["context"]
        sequence = observation["sequence"]
        raw_date = result["raw_date"]
        kind = context["kind"]
    except (KeyError, TypeError):
        raise EndStateWireError("embedded_base_identity_missing")
    if (type(sequence) is not int or not 0 < sequence <= (1 << 64) - 1
            or type(raw_date) is not int or not -(1 << 31) <= raw_date < (1 << 31)
            or type(kind) is not int or kind not in (1, 2)):
        raise EndStateWireError("embedded_base_identity_invalid")
    return sequence, raw_date, kind


def _decode_body(body: bytes, base_decoded: Mapping[str, Any]) -> dict[str, Any]:
    if len(body) != BODY_BYTES:
        raise EndStateWireError("end_state_body_length_invalid")
    reader = _Reader(body)
    sequence = struct.unpack("<Q", reader.take(8, "sequence"))[0]
    raw_date = struct.unpack("<i", reader.take(4, "raw_date"))[0]
    kind = reader.u8("kind")
    state_id = reader.u8("state")
    raw_gates = [reader.u8("raw_gate_0"), reader.u8("raw_gate_1")]
    if reader.remaining:
        raise EndStateWireError("trailing_bytes_in_end_state")
    if state_id not in STATE_NAMES:
        raise EndStateWireError("state_out_of_range")
    if state_id == STATE_IDS["unknown"]:
        if sequence != 0 or raw_date != 0 or kind != 0 or raw_gates != [0, 0]:
            raise EndStateWireError("noncanonical_unknown_end_state")
        return {"status": "unknown", "reason": "END_STATE_NOT_CAPTURED"}

    if sequence == 0 or kind not in (1, 2):
        raise EndStateWireError("known_end_state_identity_invalid")
    if (sequence, raw_date, kind) != _base_identity(base_decoded):
        raise EndStateWireError("end_state_identity_mismatch")
    return {"status": "known", "raw_gates": raw_gates}


def decode_envelope(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode the strict v9 outer frame and validate its complete nested base."""
    raw = _as_bytes(data)
    if len(raw) < OUTER_HEADER_BYTES + EXTENSION_HEADER_BYTES + BODY_BYTES:
        raise EndStateWireError("wire_too_short")
    if raw[:4] != MAGIC:
        raise EndStateWireError("magic_mismatch")
    if struct.unpack_from("<H", raw, 4)[0] != VERSION:
        raise EndStateWireError("version_mismatch")
    base_bytes = struct.unpack_from("<I", raw, 6)[0]
    if base_bytes == 0 or base_bytes > MAX_WIRE_BYTES:
        raise EndStateWireError("base_length_over_bound")
    base_start = OUTER_HEADER_BYTES
    base_end = base_start + base_bytes
    if base_end < base_start or base_end > len(raw):
        raise EndStateWireError("truncated_embedded_base")
    base = raw[base_start:base_end]
    base_version, base_decoded = _decode_base(base)

    reader = _Reader(raw[base_end:])
    if reader.take(4, "extension_magic") != EXTENSION_MAGIC:
        raise EndStateWireError("extension_magic_mismatch")
    extension_version = reader.u16("extension_version")
    if extension_version != EXTENSION_VERSION:
        raise EndStateWireError("extension_version_mismatch")
    body_length = reader.u32("extension_body_length")
    if body_length != BODY_BYTES or body_length != reader.remaining:
        raise EndStateWireError("extension_length_mismatch")
    end_state = _decode_body(reader.take(body_length, "extension_body"), base_decoded)
    return {
        "schema": "information_battle_end_state_envelope_v9",
        "wire9": {
            "version": VERSION,
            "bytes": len(raw),
            "base_version": base_version,
            "base_bytes": base_bytes,
            "extension_magic": EXTENSION_MAGIC.decode("ascii"),
            "extension_version": extension_version,
            "extension_bytes": body_length,
            "trailing_bytes": 0,
        },
        "base_payload_hex": base.hex(),
        "end_state": end_state,
        "complete": False,
    }


def decode(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Keep v1-v8 decode results unchanged; compose only the v9 extension."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return _v8.decode(data)
    try:
        if len(data) < 6:
            return _v8.decode(data)
        prefix = bytes(data[:6])
    except (TypeError, ValueError) as exc:
        raise EndStateWireError("input_bytes_conversion_failed") from exc
    if prefix[:4] != MAGIC or struct.unpack_from("<H", prefix, 4)[0] != VERSION:
        return _v8.decode(data)
    raw = _as_bytes(data)
    envelope = decode_envelope(raw)
    base = bytes.fromhex(envelope["base_payload_hex"])
    _base_version_value, base_decoded = _decode_base(base)
    composed = dict(base_decoded)
    composed["wire9"] = dict(envelope["wire9"])
    composed["end_state"] = dict(envelope["end_state"])
    composed["complete"] = False
    return composed


def _int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise EndStateWireError(f"{label}_out_of_range")
    return value


def encode(base: bytes | bytearray | memoryview,
           snapshot: Mapping[str, Any]) -> bytes:
    """Encode a complete v7/v8 frame and a strict EOST end-state snapshot."""
    base_bytes = _as_bytes(base)
    _base_ver, base_decoded = _decode_base(base_bytes)
    if not isinstance(snapshot, Mapping):
        raise EndStateWireError("snapshot_must_be_object")
    state = snapshot.get("state")
    if not isinstance(state, str) or state not in STATE_IDS:
        raise EndStateWireError("invalid_snapshot_state")
    if state == "unknown":
        sequence, raw_date, kind, gates = 0, 0, 0, (0, 0)
    else:
        sequence = _int(snapshot.get("sequence"), "sequence", 1, (1 << 64) - 1)
        raw_date = _int(snapshot.get("raw_date"), "raw_date", -(1 << 31), (1 << 31) - 1)
        kind = _int(snapshot.get("kind"), "kind", 1, 2)
        raw_gates = snapshot.get("raw_gates")
        if not isinstance(raw_gates, (list, tuple)) or len(raw_gates) != 2:
            raise EndStateWireError("raw_gates_must_have_two_bytes")
        gates = tuple(_int(item, f"raw_gate_{index}", 0, 255)
                      for index, item in enumerate(raw_gates))
        if (sequence, raw_date, kind) != _base_identity(base_decoded):
            raise EndStateWireError("end_state_identity_mismatch")
    body = struct.pack("<QiBB2B", sequence, raw_date, kind,
                       STATE_IDS[state], *gates)
    result = (MAGIC + struct.pack("<HI", VERSION, len(base_bytes)) + base_bytes
              + EXTENSION_MAGIC
              + struct.pack("<HI", EXTENSION_VERSION, len(body)) + body)
    if len(result) > MAX_WIRE_BYTES:
        raise EndStateWireError("wire_size_over_bound")
    return result


def validate(data: bytes | bytearray | memoryview) -> bool:
    try:
        decode_envelope(data)
    except (EndStateWireError, TypeError, ValueError):
        return False
    return True


__all__ = [
    "BASE_VERSIONS", "BODY_BYTES", "DisplayContextWireError", "EndStateWireError",
    "EXTENSION_MAGIC", "EXTENSION_VERSION", "MAX_WIRE_BYTES",
    "NameHandoffWireError", "OUTER_HEADER_BYTES", "STATE_IDS", "VERSION",
    "decode", "decode_envelope", "encode", "validate",
]
