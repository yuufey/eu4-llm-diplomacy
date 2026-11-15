"""Strict IBOW v8/NHND codec for the copied logical NAME constructor value.

The frame embeds one complete, unchanged IBOW v7 display-context frame and
appends a bounded value-only snapshot.  The snapshot is a logical constructor
input: it is not native Line1 text, raw_text, a popup node, or proof that a
window was rendered or visible.
"""
from __future__ import annotations

from collections.abc import Mapping
import struct
from typing import Any

from . import information_battle_display_context_wire as _v7


MAGIC = b"IBOW"
VERSION = 8
BASE_VERSION = 7
EXTENSION_MAGIC = b"NHND"
EXTENSION_VERSION = 1
MAX_WIRE_BYTES = _v7.MAX_WIRE_BYTES
MAX_BASE_V7_BYTES = MAX_WIRE_BYTES
MAX_VALUE_BYTES = 8192
OUTER_HEADER_BYTES = 10
EXTENSION_HEADER_BYTES = 10
FIXED_BODY_BYTES = 24
STATE_IDS = {"unknown": 0, "known": 1}
STATE_NAMES = {value: key for key, value in STATE_IDS.items()}
KNOWN_KINDS = frozenset((1, 2))
SOURCE_NAME = "owned_name_handoff"
# Compatibility export for the existing battle adapter's shared error gate.
DisplayContextWireError = _v7.DisplayContextWireError


class NameHandoffWireError(ValueError):
    """The input is not one strict IBOW v8/NHND frame or snapshot."""


def _as_bytes(value: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise NameHandoffWireError("input_must_be_bytes_like")
    try:
        raw = bytes(value)
    except (TypeError, ValueError) as exc:
        raise NameHandoffWireError("input_bytes_conversion_failed") from exc
    if len(raw) > MAX_WIRE_BYTES:
        raise NameHandoffWireError("wire_size_over_bound")
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
            raise NameHandoffWireError(f"truncated:{label}")
        start = self.position
        self.position += size
        return self.data[start:self.position]

    def u8(self, label: str) -> int:
        return self.take(1, label)[0]

    def u16(self, label: str) -> int:
        return struct.unpack("<H", self.take(2, label))[0]

    def u32(self, label: str) -> int:
        return struct.unpack("<I", self.take(4, label))[0]

    def u64(self, label: str) -> int:
        return struct.unpack("<Q", self.take(8, label))[0]

    def i64(self, label: str) -> int:
        return struct.unpack("<q", self.take(8, label))[0]


def _int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise NameHandoffWireError(f"{label}_out_of_range")
    return value


def _validate_v7_base(base: bytes) -> dict[str, Any]:
    if (len(base) < 6 or len(base) > MAX_BASE_V7_BYTES
            or base[:4] != MAGIC
            or struct.unpack_from("<H", base, 4)[0] != BASE_VERSION):
        raise NameHandoffWireError("embedded_base_is_not_v7")
    try:
        decoded = _v7.decode(base)
    except (ValueError, TypeError) as exc:
        raise NameHandoffWireError(f"invalid_embedded_base_v7:{exc}") from exc
    if (not isinstance(decoded, dict)
            or decoded.get("schema") != "information_battle_native_text_wire_v6"
            or decoded.get("wire7", {}).get("version") != BASE_VERSION):
        raise NameHandoffWireError("embedded_base_v7_decode_shape_invalid")
    _validate_display_context_identity(decoded)
    return decoded


def _base_identity(decoded: Mapping[str, Any]) -> tuple[int, int, int]:
    try:
        observation = decoded["observation"]
        result = observation["result"]
        context = decoded["context"]
        sequence = observation["sequence"]
        raw_date = result["raw_date"]
        kind = context["kind"]
    except (KeyError, TypeError):
        raise NameHandoffWireError("embedded_base_v7_identity_missing")
    if (type(sequence) is not int or type(raw_date) is not int
            or type(kind) is not int):
        raise NameHandoffWireError("embedded_base_v7_identity_invalid")
    return sequence, raw_date, kind


def _validate_display_context_identity(decoded: Mapping[str, Any]) -> None:
    """Require an observed DCTX identity to agree with its nested v6 base.

    An unknown DCTX is a permitted partial capture: it carries no identity and
    must not prevent a separately captured NAME value from being retained.
    """
    try:
        display_context = decoded["display_context"]
        state = display_context["state"]
    except (KeyError, TypeError):
        raise NameHandoffWireError("embedded_display_context_missing")
    if state == "unknown":
        return
    if state != "observed":
        raise NameHandoffWireError("embedded_display_context_state_invalid")
    try:
        actual = (
            display_context["sequence"],
            display_context["raw_date"],
            display_context["battle_kind"],
        )
    except (KeyError, TypeError):
        raise NameHandoffWireError("embedded_display_context_identity_missing")
    if actual != _base_identity(decoded):
        raise NameHandoffWireError("embedded_display_context_identity_mismatch")


def _check_known_identity(snapshot: Mapping[str, Any],
                          base_decoded: Mapping[str, Any]) -> None:
    if snapshot.get("state") != "known":
        return
    expected = _base_identity(base_decoded)
    actual = (snapshot.get("sequence"), snapshot.get("raw_date"),
              snapshot.get("kind"))
    if actual != expected:
        raise NameHandoffWireError("name_handoff_identity_mismatch")


def _snapshot_unknown() -> dict[str, Any]:
    return {
        "schema": "information_battle_name_handoff_v1",
        "state": "unknown",
        "state_id": 0,
        "sequence": 0,
        "raw_date": 0,
        "kind": 0,
        "length": 0,
        "raw_hex": None,
        "source": SOURCE_NAME,
        "source_name": SOURCE_NAME,
        "semantic_role": "logical_name_constructor_input",
        "not_raw_text": True,
        "not_line1": True,
        "complete": False,
        "full_display_complete": False,
        "runtime_popup_verified": False,
        "visibility_verified": False,
    }


def _decode_body(body: bytes) -> dict[str, Any]:
    if len(body) < FIXED_BODY_BYTES:
        raise NameHandoffWireError("name_handoff_body_too_short")
    reader = _Reader(body)
    state_id = reader.u8("state")
    kind = reader.u8("kind")
    reserved = reader.u16("reserved")
    sequence = reader.u64("sequence")
    raw_date = reader.i64("raw_date")
    length = reader.u32("length")
    if state_id not in STATE_NAMES:
        raise NameHandoffWireError("state_out_of_range")
    if reserved != 0:
        raise NameHandoffWireError("reserved_nonzero")
    if length > MAX_VALUE_BYTES:
        raise NameHandoffWireError("value_length_over_bound")
    payload = reader.take(length, "value")
    if reader.remaining:
        raise NameHandoffWireError("trailing_bytes_in_name_handoff")

    if state_id == STATE_IDS["unknown"]:
        if (kind != 0 or sequence != 0 or raw_date != 0 or length != 0
                or payload):
            raise NameHandoffWireError("noncanonical_unknown_name_handoff")
        return _snapshot_unknown()

    if sequence == 0:
        raise NameHandoffWireError("known_name_handoff_zero_sequence")
    if raw_date < 0:
        raise NameHandoffWireError("known_name_handoff_negative_date")
    if kind not in KNOWN_KINDS:
        raise NameHandoffWireError("known_name_handoff_kind_out_of_range")
    if b"\x00" in payload:
        raise NameHandoffWireError("embedded_nul_in_name_value")
    return {
        "schema": "information_battle_name_handoff_v1",
        "state": "known",
        "state_id": state_id,
        "sequence": sequence,
        "raw_date": raw_date,
        "kind": kind,
        "length": length,
        "raw_hex": payload.hex(),
        "source": SOURCE_NAME,
        "source_name": SOURCE_NAME,
        "semantic_role": "logical_name_constructor_input",
        "not_raw_text": True,
        "not_line1": True,
        "complete": False,
        "full_display_complete": False,
        "runtime_popup_verified": False,
        "visibility_verified": False,
    }


def decode_envelope(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode v8 framing and NHND; embedded v7 is validated separately."""
    raw = _as_bytes(data)
    if (len(raw) < OUTER_HEADER_BYTES + EXTENSION_HEADER_BYTES + FIXED_BODY_BYTES
            or raw[:4] != MAGIC):
        raise NameHandoffWireError("magic_or_prefix_mismatch")
    version = struct.unpack_from("<H", raw, 4)[0]
    if version != VERSION:
        raise NameHandoffWireError("version_mismatch")
    base_bytes = struct.unpack_from("<I", raw, 6)[0]
    if base_bytes == 0 or base_bytes > MAX_BASE_V7_BYTES:
        raise NameHandoffWireError("base_v7_length_over_bound")
    base_end = OUTER_HEADER_BYTES + base_bytes
    if base_end > len(raw):
        raise NameHandoffWireError("truncated_base_v7")
    base = raw[OUTER_HEADER_BYTES:base_end]
    base_decoded = _validate_v7_base(base)

    reader = _Reader(raw[base_end:])
    if reader.take(4, "extension_magic") != EXTENSION_MAGIC:
        raise NameHandoffWireError("extension_magic_mismatch")
    extension_version = reader.u16("extension_version")
    if extension_version != EXTENSION_VERSION:
        raise NameHandoffWireError("extension_version_mismatch")
    body_length = reader.u32("extension_body_length")
    if body_length != reader.remaining:
        raise NameHandoffWireError("extension_length_mismatch")
    body = reader.take(body_length, "extension_body")
    snapshot = _decode_body(body)
    _check_known_identity(snapshot, base_decoded)
    return {
        "schema": "information_battle_name_handoff_envelope_v8",
        "wire": {
            "version": VERSION,
            "bytes": len(raw),
            "base_v7_version": BASE_VERSION,
            "base_v7_bytes": base_bytes,
            "extension_magic": EXTENSION_MAGIC.decode("ascii"),
            "extension_version": extension_version,
            "extension_bytes": body_length,
            "trailing_bytes": 0,
        },
        "base_v7_payload_hex": base.hex(),
        "name_handoff": snapshot,
        "complete": False,
        "full_display_complete": False,
        "runtime_popup_verified": False,
        "visibility_verified": False,
    }


def decode(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Delegate v1-v7 unchanged and compose the strict v8 extension."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return _v7.decode(data)
    raw = bytes(data)
    if len(raw) < 6 or raw[:4] != MAGIC or struct.unpack_from("<H", raw, 4)[0] != VERSION:
        # Preserve the existing decoder's v1-v7 result and error behavior.
        return _v7.decode(data)
    envelope = decode_envelope(raw)
    base = bytes.fromhex(envelope["base_v7_payload_hex"])
    base_result = _validate_v7_base(base)
    composed = dict(base_result)
    composed["wire8"] = dict(envelope["wire"])
    composed["name_handoff"] = envelope["name_handoff"]
    composed["full_display_complete"] = False
    composed["runtime_popup_verified"] = False
    composed["visibility_verified"] = False
    return composed


def _raw_input(snapshot: Mapping[str, Any]) -> bytes:
    names = [name for name in ("raw_bytes", "raw_hex", "bytes") if name in snapshot]
    if len(names) > 1:
        raise NameHandoffWireError("ambiguous_raw_value")
    if not names or snapshot[names[0]] is None:
        return b""
    value = snapshot[names[0]]
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str) and names[0] == "raw_hex":
        if len(value) % 2:
            raise NameHandoffWireError("invalid_raw_hex")
        try:
            return bytes.fromhex(value)
        except ValueError as exc:
            raise NameHandoffWireError("invalid_raw_hex") from exc
    raise NameHandoffWireError("invalid_raw_value")


def _normalize_snapshot(snapshot: Mapping[str, Any]) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(snapshot, Mapping):
        raise NameHandoffWireError("snapshot_must_be_object")
    state = snapshot.get("state")
    if state not in STATE_IDS:
        raise NameHandoffWireError("invalid_snapshot_state")
    raw = _raw_input(snapshot)
    length = snapshot.get("length", len(raw))
    sequence = snapshot.get("sequence", 0)
    raw_date = snapshot.get("raw_date", 0)
    kind = snapshot.get("kind", 0)
    if type(length) is not int or not 0 <= length <= MAX_VALUE_BYTES:
        raise NameHandoffWireError("length_out_of_range")
    if length != len(raw):
        raise NameHandoffWireError("length_value_mismatch")

    if state == "unknown":
        if (type(sequence) is not int or sequence != 0
                or type(raw_date) is not int or raw_date != 0
                or type(kind) is not int or kind != 0
                or raw or length):
            raise NameHandoffWireError("noncanonical_unknown_snapshot")
        return struct.pack("<BBHQqI", 0, 0, 0, 0, 0, 0), _snapshot_unknown()

    sequence = _int(sequence, "sequence", 1, (1 << 64) - 1)
    raw_date = _int(raw_date, "raw_date", 0, (1 << 63) - 1)
    kind = _int(kind, "kind", 1, 2)
    if b"\x00" in raw:
        raise NameHandoffWireError("embedded_nul_in_name_value")
    body = struct.pack("<BBHQqI", 1, kind, 0, sequence, raw_date, length) + raw
    return body, {
        "schema": "information_battle_name_handoff_v1",
        "state": "known",
        "state_id": 1,
        "sequence": sequence,
        "raw_date": raw_date,
        "kind": kind,
        "length": length,
        "raw_hex": raw.hex(),
        "source": SOURCE_NAME,
        "source_name": SOURCE_NAME,
        "semantic_role": "logical_name_constructor_input",
        "not_raw_text": True,
        "not_line1": True,
        "complete": False,
        "full_display_complete": False,
        "runtime_popup_verified": False,
        "visibility_verified": False,
    }


def validate(data: bytes | bytearray | memoryview) -> bool:
    try:
        decode_envelope(data)
    except (NameHandoffWireError, TypeError, ValueError):
        return False
    return True


def encode(base_v7: bytes | bytearray | memoryview,
           snapshot: Mapping[str, Any]) -> bytes:
    """Encode one complete v7 frame and a strict pointer-free NHND value."""
    base = _as_bytes(base_v7)
    base_decoded = _validate_v7_base(base)
    body, normalized = _normalize_snapshot(snapshot)
    _check_known_identity(normalized, base_decoded)
    extension = EXTENSION_MAGIC + struct.pack(
        "<HI", EXTENSION_VERSION, len(body)) + body
    result = MAGIC + struct.pack("<HI", VERSION, len(base)) + base + extension
    if len(result) > MAX_WIRE_BYTES:
        raise NameHandoffWireError("wire_size_over_bound")
    return result


__all__ = [
    "BASE_VERSION", "EXTENSION_MAGIC", "EXTENSION_VERSION", "FIXED_BODY_BYTES",
    "DisplayContextWireError", "MAX_VALUE_BYTES", "MAX_WIRE_BYTES",
    "NameHandoffWireError", "SOURCE_NAME",
    "VERSION", "decode", "decode_envelope", "encode", "validate",
]
