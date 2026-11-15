"""Strict decoder/encoder for the value-only IBOW version-6 text envelope.

The frame embeds one complete version-5 payload unchanged and appends an NTXT
extension.  Native pointers are never serialized.  Text bytes are intentionally
kept as bytes; decoding or assigning B04 meaning is a separate projection step.
"""

from __future__ import annotations

from collections.abc import Mapping
import struct
from typing import Any

try:  # namespace-package import from the repository root
    from .information_battle_war_identity_wire import (
        WarIdentityWireError,
        decode as decode_legacy_wire,
    )
except ImportError:  # pragma: no cover - direct script compatibility
    from information_battle_war_identity_wire import (  # type: ignore
        WarIdentityWireError,
        decode as decode_legacy_wire,
    )


MAGIC = b"IBOW"
VERSION = 6
BASE_VERSION = 5
EXTENSION_MAGIC = b"NTXT"
EXTENSION_VERSION = 1
EXTENSION_FLAGS = 0
MAX_WIRE_BYTES = 512 * 1024
MAX_BASE_V5_BYTES = MAX_WIRE_BYTES
MAX_BASE_V4_BYTES = 256 * 1024
MAX_KEY_BYTES = 256
MAX_TEXT_BYTES = 8192
EXTENSION_FIXED_BODY_BYTES = 16
ENTRY_HEADER_BYTES = 8
ENTRY_COUNT = 4

FIELD_ORDER = (
    "definition_key",
    "auxiliary_text",
    "title_helper_candidate",
    "line1_text",
)
FIELD_IDS = {name: index + 1 for index, name in enumerate(FIELD_ORDER)}
FIELD_SOURCES = {
    "definition_key": "message_metadata",
    "auxiliary_text": "message_metadata",
    "title_helper_candidate": "title_helper_candidate",
    "line1_text": "native_line1",
}
SOURCE_NAMES = frozenset(FIELD_SOURCES.values())
SOURCE_IDS = {
    "message_metadata": 1,
    "title_helper_candidate": 2,
    "native_line1": 3,
}
SOURCE_BY_ID = {value: key for key, value in SOURCE_IDS.items()}
STATE_IDS = {"unknown": 0, "observed": 1, "absent": 2}
STATE_NAMES = {value: key for key, value in STATE_IDS.items()}


class NativeTextWireError(ValueError):
    """The input is not one strict version-6 native-text frame."""


def _as_bytes(value: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise NativeTextWireError("input_must_be_bytes_like")
    try:
        raw = bytes(value)
    except (TypeError, ValueError) as exc:
        raise NativeTextWireError("input_bytes_conversion_failed") from exc
    if len(raw) > MAX_WIRE_BYTES:
        raise NativeTextWireError("wire_size_over_bound")
    return raw


def _validate_v5_base(raw: bytes) -> None:
    if (len(raw) < 10 + 10 + 4 + 35
            or len(raw) > MAX_BASE_V5_BYTES
            or raw[:4] != MAGIC
            or struct.unpack_from("<H", raw, 4)[0] != BASE_VERSION):
        raise NativeTextWireError("invalid_base_v5_envelope")
    base_v4_bytes = struct.unpack_from("<I", raw, 6)[0]
    if not 10 <= base_v4_bytes <= MAX_BASE_V4_BYTES:
        raise NativeTextWireError("invalid_base_v4_length")
    base_v4_end = 10 + base_v4_bytes
    if (base_v4_bytes < 10
            or base_v4_end > len(raw)
            or raw[10:14] != MAGIC
            or struct.unpack_from("<H", raw, 14)[0] != 4):
        raise NativeTextWireError("base_is_not_v4")
    wari = 10 + base_v4_bytes
    if wari + 4 + 35 > len(raw) or raw[wari:wari + 4] != b"WARI":
        raise NativeTextWireError("wari_extension_missing")
    identity = wari + 4
    status = raw[identity]
    if status > 2:
        raise NativeTextWireError("wari_status_out_of_range")
    id_length = raw[identity + 34]
    if id_length > 29:
        raise NativeTextWireError("wari_id_length_over_bound")
    expected = identity + 35 + id_length
    if expected != len(raw):
        raise NativeTextWireError("base_v5_length_mismatch")


def _decode_complete_v5(raw: bytes) -> dict[str, Any]:
    """Delegate all v5 semantics to the existing war-identity decoder."""

    try:
        result = decode_legacy_wire(raw)
    except (WarIdentityWireError, ValueError) as exc:
        raise NativeTextWireError(f"invalid_base_v5:{exc}") from exc
    if not isinstance(result, dict):  # defensive against a changed delegate
        raise NativeTextWireError("invalid_base_v5_result")
    return result


def validate_base_v5(data: bytes | bytearray | memoryview) -> bool:
    """Return whether *data* is a complete v5 payload accepted by the v5 decoder."""

    try:
        raw = _as_bytes(data)
        _validate_v5_base(raw)
        _decode_complete_v5(raw)
    except NativeTextWireError:
        return False
    return True


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.position = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.position

    def take(self, size: int, label: str) -> bytes:
        if size < 0 or size > self.remaining:
            raise NativeTextWireError(f"truncated:{label}")
        begin = self.position
        self.position += size
        return self.data[begin:self.position]

    def u8(self, label: str) -> int:
        return self.take(1, label)[0]

    def u16(self, label: str) -> int:
        return struct.unpack("<H", self.take(2, label))[0]

    def u32(self, label: str) -> int:
        return struct.unpack("<I", self.take(4, label))[0]

    def i32(self, label: str) -> int:
        return struct.unpack("<i", self.take(4, label))[0]


def _state_name(value: int, label: str) -> str:
    try:
        return STATE_NAMES[value]
    except KeyError as exc:
        raise NativeTextWireError(f"invalid_state:{label}") from exc


def _source_name(value: int, label: str) -> str:
    try:
        return SOURCE_BY_ID[value]
    except KeyError as exc:
        raise NativeTextWireError(f"invalid_source:{label}") from exc


def _status_for_state(state: str) -> str:
    return {"observed": "known", "unknown": "unknown", "absent": "absent"}[state]


def _field_output(state: str, source: str, raw: bytes) -> dict[str, Any]:
    return {
        "status": _status_for_state(state),
        "state": state,
        "source": source,
        # An observed empty byte string is deliberately "" rather than None.
        "raw_hex": raw.hex() if state == "observed" else None,
    }


def _metadata_state(value: Mapping[str, Any] | None, label: str) -> tuple[int, int]:
    value = {} if value is None else value
    if not isinstance(value, Mapping):
        raise NativeTextWireError(f"{label}_must_be_object")
    state_name = value.get("state", "unknown")
    if state_name not in STATE_IDS:
        raise NativeTextWireError(f"invalid_state:{label}")
    state = STATE_IDS[state_name]
    raw_value = value.get("value", 0)
    if state != STATE_IDS["observed"]:
        if raw_value not in (0, None):
            raise NativeTextWireError(f"nonzero_unobserved:{label}")
        return state, 0
    if type(raw_value) is not int:
        raise NativeTextWireError(f"invalid_value:{label}")
    if label == "native_date" and not -(1 << 31) <= raw_value < (1 << 31):
        raise NativeTextWireError("native_date_out_of_range")
    if label == "raw_flags" and not 0 <= raw_value <= 0xFFFF:
        raise NativeTextWireError("raw_flags_out_of_range")
    return state, raw_value


def _normalize_snapshot(snapshot: Mapping[str, Any] | None) -> tuple[bytes, dict[str, Any]]:
    if snapshot is None:
        snapshot = {}
    if not isinstance(snapshot, Mapping):
        raise NativeTextWireError("snapshot_must_be_object")

    date_state, date_value = _metadata_state(snapshot.get("native_date"), "native_date")
    flags_value = snapshot.get("raw_flags")
    if flags_value is None:
        flags_value = {}
    if not isinstance(flags_value, Mapping):
        raise NativeTextWireError("raw_flags_must_be_object")
    flags_state_name = flags_value.get("state", "unknown")
    if flags_state_name not in STATE_IDS:
        raise NativeTextWireError("invalid_state:raw_flags")
    flags_state = STATE_IDS[flags_state_name]
    flag_8c = flags_value.get("raw_flag_8c", flags_value.get("raw_8c", 0))
    flag_8d = flags_value.get("raw_flag_8d", flags_value.get("raw_8d", 0))
    if flags_state != STATE_IDS["observed"]:
        if flag_8c not in (0, None) or flag_8d not in (0, None):
            raise NativeTextWireError("nonzero_unobserved:raw_flags")
        flag_8c = flag_8d = 0
    elif (type(flag_8c) is not int or type(flag_8d) is not int
          or not 0 <= flag_8c <= 0xFF or not 0 <= flag_8d <= 0xFF):
        raise NativeTextWireError("raw_flags_out_of_range")

    entries: list[tuple[int, int, int, bytes]] = []
    for field in FIELD_ORDER:
        value = snapshot.get(field)
        if value is None:
            value = {}
        if not isinstance(value, Mapping):
            raise NativeTextWireError(f"{field}_must_be_object")
        state_name = value.get("state", "unknown")
        source = value.get("source", FIELD_SOURCES[field])
        if state_name not in STATE_IDS:
            raise NativeTextWireError(f"invalid_state:{field}")
        if source != FIELD_SOURCES[field] or source not in SOURCE_NAMES:
            raise NativeTextWireError(f"source_mismatch:{field}")
        raw_hex = value.get("raw_hex", "")
        if not isinstance(raw_hex, str) or len(raw_hex) % 2:
            raise NativeTextWireError(f"invalid_raw_hex:{field}")
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise NativeTextWireError(f"invalid_raw_hex:{field}") from exc
        max_length = MAX_KEY_BYTES if field == "definition_key" else MAX_TEXT_BYTES
        if len(raw) > max_length:
            raise NativeTextWireError(f"text_over_bound:{field}")
        if state_name != "observed" and raw:
            raise NativeTextWireError(f"raw_for_unobserved:{field}")
        entries.append((FIELD_IDS[field], STATE_IDS[state_name],
                        SOURCE_IDS[source], raw))

    body = bytearray(struct.pack(
        "<HHBBBBiBBH", EXTENSION_FLAGS, 0, date_state, flags_state,
        ENTRY_COUNT, 0, date_value, flag_8c, flag_8d, 0,
    ))
    for field_id, state, source_id, raw in entries:
        body.extend(struct.pack("<BBBBI", field_id, state, source_id, 0,
                                len(raw)))
        body.extend(raw)
    if len(body) > 0xFFFFFFFF:
        raise NativeTextWireError("extension_over_bound")
    return bytes(body), {
        "native_date": {"state": STATE_NAMES[date_state], "value": date_value},
        "raw_flags": {"state": STATE_NAMES[flags_state],
                       "raw_flag_8c": flag_8c,
                       "raw_flag_8d": flag_8d},
        "entries": entries,
    }


def _encode_envelope(base_v5: bytes,
                     snapshot: Mapping[str, Any] | None = None) -> bytes:
    base = _as_bytes(base_v5)
    _validate_v5_base(base)
    body, _ = _normalize_snapshot(snapshot)
    result = (MAGIC + struct.pack("<HI", VERSION, len(base)) + base
              + EXTENSION_MAGIC
              + struct.pack("<HI", EXTENSION_VERSION, len(body)) + body)
    if len(result) > MAX_WIRE_BYTES:
        raise NativeTextWireError("wire_size_over_bound")
    return result


def encode_envelope(base_v5: bytes | bytearray | memoryview,
                    snapshot: Mapping[str, Any] | None = None) -> bytes:
    """Encode framing around a structurally shaped v5 payload.

    This deliberately performs only NTXT/base framing checks.  It exists for
    bounded wire-contract fixtures; callers producing public data must use
    :func:`encode`, which delegates v5 semantic validation.
    """

    return _encode_envelope(_as_bytes(base_v5), snapshot)


def encode(base_v5: bytes | bytearray | memoryview,
           snapshot: Mapping[str, Any] | None = None) -> bytes:
    """Encode one v6 frame around a complete, decoder-accepted v5 payload."""

    base = _as_bytes(base_v5)
    _validate_v5_base(base)
    _decode_complete_v5(base)
    return _encode_envelope(base, snapshot)


def _decode_body(body: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    if len(body) < EXTENSION_FIXED_BODY_BYTES:
        raise NativeTextWireError("extension_body_too_short")
    reader = _Reader(body)
    flags = reader.u16("flags")
    reserved = reader.u16("reserved")
    date_state = reader.u8("native_date_state")
    raw_flags_state = reader.u8("raw_flags_state")
    entry_count = reader.u8("entry_count")
    reserved_byte = reader.u8("reserved_byte")
    native_date = reader.i32("native_date")
    raw_8c = reader.u8("raw_flag_8c")
    raw_8d = reader.u8("raw_flag_8d")
    reserved_tail = reader.u16("reserved_tail")
    if (flags != EXTENSION_FLAGS or reserved != 0
            or reserved_byte != 0 or reserved_tail != 0
            or entry_count != ENTRY_COUNT):
        raise NativeTextWireError("noncanonical_extension_flags")
    date_name = _state_name(date_state, "native_date")
    flags_name = _state_name(raw_flags_state, "raw_flags")
    if date_name != "observed" and native_date != 0:
        raise NativeTextWireError("nonzero_unobserved:native_date")
    if flags_name != "observed" and (raw_8c != 0 or raw_8d != 0):
        raise NativeTextWireError("nonzero_unobserved:raw_flags")

    fields: dict[str, Any] = {}
    for expected_index, field in enumerate(FIELD_ORDER, start=1):
        field_id = reader.u8(f"{field}.id")
        state = reader.u8(f"{field}.state")
        source_id = reader.u8(f"{field}.source")
        reserved_entry = reader.u8(f"{field}.reserved")
        length = reader.u32(f"{field}.length")
        max_length = MAX_KEY_BYTES if field == "definition_key" else MAX_TEXT_BYTES
        if (field_id != expected_index or reserved_entry != 0
                or length > max_length):
            raise NativeTextWireError(f"noncanonical_entry:{field}")
        state_name = _state_name(state, field)
        source = _source_name(source_id, field)
        if source != FIELD_SOURCES[field]:
            raise NativeTextWireError(f"source_mismatch:{field}")
        raw = reader.take(length, f"{field}.raw")
        if state_name != "observed" and raw:
            raise NativeTextWireError(f"raw_for_unobserved:{field}")
        fields[field] = _field_output(state_name, source, raw)
    if reader.remaining:
        raise NativeTextWireError("trailing_bytes_in_text_extension")
    metadata = {
        "native_date": {
            "status": _status_for_state(date_name),
            "state": date_name,
            "value": native_date if date_name == "observed" else None,
        },
        "raw_flags": {
            "status": _status_for_state(flags_name),
            "state": flags_name,
            "raw_flag_8c": raw_8c if flags_name == "observed" else None,
            "raw_flag_8d": raw_8d if flags_name == "observed" else None,
        },
    }
    return metadata, fields


def decode_envelope(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode only the v6 NTXT framing and its value-only extension.

    The embedded payload is checked for bounded v5 framing, but its legacy
    observation/template/war semantics are intentionally not projected here.
    Use :func:`decode` for the composed public result.
    """

    raw = _as_bytes(data)
    if len(raw) < 10 + 10 or raw[:4] != MAGIC:
        raise NativeTextWireError("magic_or_prefix_mismatch")
    if struct.unpack_from("<H", raw, 4)[0] != VERSION:
        raise NativeTextWireError("version_mismatch")
    base_bytes = struct.unpack_from("<I", raw, 6)[0]
    if not base_bytes or base_bytes > MAX_BASE_V5_BYTES:
        raise NativeTextWireError("base_v5_bytes_over_bound")
    base_end = 10 + base_bytes
    if base_end > len(raw):
        raise NativeTextWireError("truncated_base_v5")
    base = raw[10:base_end]
    _validate_v5_base(base)
    if len(raw) - base_end < 10:
        raise NativeTextWireError("truncated_text_extension")
    reader = _Reader(raw[base_end:])
    if reader.take(4, "extension_magic") != EXTENSION_MAGIC:
        raise NativeTextWireError("extension_magic_mismatch")
    extension_version = reader.u16("extension_version")
    extension_bytes = reader.u32("extension_bytes")
    if extension_version != EXTENSION_VERSION:
        raise NativeTextWireError("extension_version_mismatch")
    if extension_bytes > MAX_WIRE_BYTES or extension_bytes != reader.remaining:
        raise NativeTextWireError("extension_length_mismatch")
    body = reader.take(extension_bytes, "extension_body")
    metadata, fields = _decode_body(body)
    if reader.remaining:
        raise NativeTextWireError("trailing_bytes_after_extension")
    return {
        "schema": "information_battle_native_text_envelope_v6",
        "wire": {
            "version": VERSION,
            "bytes": len(raw),
            "base_v5_version": BASE_VERSION,
            "base_v5_bytes": base_bytes,
            "extension_magic": EXTENSION_MAGIC.decode("ascii"),
            "extension_version": extension_version,
            "extension_bytes": extension_bytes,
            "flags": EXTENSION_FLAGS,
            "trailing_bytes": 0,
        },
        "base_v5_payload_hex": base.hex(),
        "message_metadata": metadata,
        "text_fields": fields,
        "complete": False,
        "full_display_complete": False,
    }


def decode(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode legacy v1-v5 directly, or compose a complete v6 result.

    For v6, the existing v5 decoder remains the semantic owner of the
    embedded payload.  Its observation/context/naval/template/war fields are
    retained unchanged; NTXT data is namespaced under ``native_text`` and
    ``wire6``.
    """

    raw = _as_bytes(data)
    if len(raw) < 6 or raw[:4] != MAGIC:
        raise NativeTextWireError("magic_or_prefix_mismatch")
    version = struct.unpack_from("<H", raw, 4)[0]
    if version in (1, 2, 3, 4, 5):
        # Keep legacy result shapes and error semantics delegated to the
        # established decoder; this is a compatibility boundary.
        return decode_legacy_wire(raw)
    if version != VERSION:
        raise NativeTextWireError("version_mismatch")

    envelope = decode_envelope(raw)
    base = bytes.fromhex(envelope["base_v5_payload_hex"])
    base_result = _decode_complete_v5(base)
    composed = dict(base_result)
    composed["schema"] = "information_battle_native_text_wire_v6"
    composed["wire6"] = dict(envelope["wire"])
    composed["base_v5_payload_hex"] = envelope["base_v5_payload_hex"]
    composed["native_text"] = {
        "message_metadata": envelope["message_metadata"],
        "text_fields": envelope["text_fields"],
        "complete": False,
        "full_display_complete": False,
    }
    # The extension never upgrades the legacy battle/display completeness.
    composed["complete"] = False
    return composed


decode_wire = decode

__all__ = [
    "BASE_VERSION",
    "ENTRY_COUNT",
    "ENTRY_HEADER_BYTES",
    "EXTENSION_FIXED_BODY_BYTES",
    "EXTENSION_FLAGS",
    "EXTENSION_MAGIC",
    "EXTENSION_VERSION",
    "FIELD_ORDER",
    "FIELD_SOURCES",
    "MAX_BASE_V5_BYTES",
    "MAX_KEY_BYTES",
    "MAX_TEXT_BYTES",
    "MAX_WIRE_BYTES",
    "NativeTextWireError",
    "VERSION",
    "decode",
    "decode_envelope",
    "decode_wire",
    "encode",
    "encode_envelope",
    "validate_base_v5",
]
