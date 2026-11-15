"""Strict IBOW v7 display-context extension codec and local projection.

Version 7 embeds an unchanged complete v6 text-wire frame and appends a
pointer-free DCTX snapshot. The snapshot contains copied shared definition
and localization-cache values for one event; it is not evidence that a popup
was rendered or visible to an observer.
"""
from __future__ import annotations

from collections.abc import Mapping
import re
import struct
from typing import Any

try:  # namespace-package import from the repository root
    from . import information_battle_native_text_wire as _v6
except ImportError:  # pragma: no cover - direct script compatibility
    import information_battle_native_text_wire as _v6  # type: ignore

MAGIC = b"IBOW"
VERSION = 7
BASE_VERSION = 6
EXTENSION_MAGIC = b"DCTX"
EXTENSION_VERSION = 1
MAX_WIRE_BYTES = 512 * 1024
MAX_ARENA_BYTES = 32768
FIXED_BODY_BYTES = 27
ENTRY_HEADER_BYTES = 8
ENTRY_COUNT = 7

FIELD_ORDER = (
    "definition_key",
    "language",
    "body_template",
    "button1",
    "button2",
    "button3",
    "compact_losses_template",
)
FIELD_IDS = {name: index + 1 for index, name in enumerate(FIELD_ORDER)}
FIELD_NAMES = {value: key for key, value in FIELD_IDS.items()}
FIELD_LIMITS = {
    "definition_key": 64,
    "language": 256,
    "body_template": 8192,
    "button1": 8192,
    "button2": 8192,
    "button3": 8192,
    "compact_losses_template": 8192,
}
FIELD_SOURCES = {
    "definition_key": "native_message_definition",
    "language": "native_localization_cache",
    "body_template": "native_localization_cache",
    "button1": "native_localization_cache",
    "button2": "native_localization_cache",
    "button3": "native_localization_cache",
    "compact_losses_template": "native_localization_cache",
}
STATE_IDS = {"unknown": 0, "observed": 1, "absent": 2}
STATE_NAMES = {value: key for key, value in STATE_IDS.items()}
FAILURE_NAMES = {
    0: "none",
    1: "not_captured",
    2: "invalid_input",
    3: "read_failed",
    4: "definition_missing",
    5: "cache_invalid",
    6: "budget",
    7: "source_changed",
    8: "guard",
    9: "ambiguous_scope",
}
FORMATTER_KEYS = {1: b"LANDBATTLEOVER", 2: b"NAVALBATTLEOVER"}
LANGUAGE_RE = re.compile(rb"l_[A-Za-z0-9_]+\Z")


class DisplayContextWireError(ValueError):
    """Input does not satisfy the strict IBOW v7 display-context contract."""


def _as_bytes(value: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise DisplayContextWireError("input_must_be_bytes_like")
    try:
        raw = bytes(value)
    except (TypeError, ValueError) as exc:
        raise DisplayContextWireError("input_bytes_conversion_failed") from exc
    if len(raw) > MAX_WIRE_BYTES:
        raise DisplayContextWireError("wire_size_over_bound")
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
            raise DisplayContextWireError(f"truncated:{label}")
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

    def i32(self, label: str) -> int:
        return struct.unpack("<i", self.take(4, label))[0]


def _int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise DisplayContextWireError(f"{label}_out_of_range")
    return value


def _field_state(value: int, label: str) -> str:
    try:
        return STATE_NAMES[value]
    except KeyError as exc:
        raise DisplayContextWireError(f"invalid_state:{label}") from exc


def _failure_name(value: int) -> str:
    try:
        return FAILURE_NAMES[value]
    except KeyError as exc:
        raise DisplayContextWireError("failure_out_of_range") from exc


def _decode_language(value: bytes) -> None:
    if not LANGUAGE_RE.fullmatch(value):
        raise DisplayContextWireError("invalid_language_identifier")


def _decode_body(body: bytes) -> dict[str, Any]:
    if len(body) < FIXED_BODY_BYTES:
        raise DisplayContextWireError("display_context_body_too_short")
    reader = _Reader(body)
    context_state = reader.u8("context_state")
    capture_stage = reader.u8("capture_stage")
    failure = reader.u16("failure")
    sequence = reader.u64("sequence")
    raw_date = reader.i32("raw_date")
    battle_kind = reader.u8("battle_kind")
    popup_kind_raw = reader.i32("popup_kind_raw")
    layout_raw = reader.i32("layout_raw")
    button_flag_raw = reader.u8("button_flag_raw")
    entry_count = reader.u8("entry_count")

    if context_state not in (0, 1):
        raise DisplayContextWireError("context_state_out_of_range")
    if entry_count != ENTRY_COUNT:
        raise DisplayContextWireError("entry_count_mismatch")

    entries: dict[str, dict[str, Any]] = {}
    arena_chunks: list[bytes] = []
    arena_used = 0
    for expected_id, name in enumerate(FIELD_ORDER, start=1):
        field_id = reader.u8(f"{name}.field_id")
        state_id = reader.u8(f"{name}.field_state")
        reserved = reader.u16(f"{name}.reserved")
        length = reader.u32(f"{name}.byte_length")
        if field_id != expected_id:
            raise DisplayContextWireError(f"field_id_or_order_mismatch:{name}")
        if reserved != 0:
            raise DisplayContextWireError(f"reserved_nonzero:{name}")
        state = _field_state(state_id, name)
        if length > FIELD_LIMITS[name]:
            raise DisplayContextWireError(f"field_length_over_bound:{name}")
        if state != "observed" and length != 0:
            raise DisplayContextWireError(f"unobserved_field_has_bytes:{name}")
        raw = reader.take(length, f"{name}.value")
        if b"\x00" in raw:
            raise DisplayContextWireError(f"embedded_nul:{name}")
        arena_used += length
        if arena_used > MAX_ARENA_BYTES:
            raise DisplayContextWireError("arena_over_bound")
        if state == "observed":
            arena_chunks.append(raw)
        entries[name] = {
            "field_id": field_id,
            "state": state,
            "status": {"observed": "known", "unknown": "unknown", "absent": "absent"}[state],
            "byte_length": length,
            "raw_hex": raw.hex() if state == "observed" else None,
            "source": FIELD_SOURCES[name],
        }
    if reader.remaining:
        raise DisplayContextWireError(f"trailing_bytes_in_body:{reader.remaining}")

    if context_state == 0:
        if (capture_stage != 0 or failure not in range(1, 10)
                or sequence != 0 or raw_date != 0 or battle_kind != 0
                or popup_kind_raw != 0 or layout_raw != 0 or button_flag_raw != 0
                or arena_used != 0
                or any(entry["state"] != "unknown" for entry in entries.values())):
            raise DisplayContextWireError("noncanonical_unknown_context")
        state_name = "unknown"
    else:
        if failure != 0:
            raise DisplayContextWireError("observed_context_has_failure")
        if sequence == 0:
            raise DisplayContextWireError("observed_context_zero_sequence")
        if capture_stage not in (1, 2, 3):
            raise DisplayContextWireError("observed_context_stage_out_of_range")
        if battle_kind not in (1, 2):
            raise DisplayContextWireError("observed_context_kind_out_of_range")
        if entries["definition_key"]["state"] != "observed":
            raise DisplayContextWireError("observed_context_definition_key_missing")
        if entries["language"]["state"] != "observed":
            raise DisplayContextWireError("observed_context_language_missing")
        definition_key = bytes.fromhex(entries["definition_key"]["raw_hex"])
        if definition_key != FORMATTER_KEYS[battle_kind]:
            raise DisplayContextWireError("definition_key_kind_mismatch")
        language = bytes.fromhex(entries["language"]["raw_hex"])
        _decode_language(language)
        state_name = "observed"

    return {
        "schema": "information_battle_display_context_v1",
        "state": state_name,
        "state_id": context_state,
        "capture_stage": capture_stage,
        "failure": failure,
        "failure_name": _failure_name(failure),
        "sequence": sequence,
        "raw_date": raw_date,
        "battle_kind": battle_kind,
        "popup_kind_raw": popup_kind_raw,
        "layout_raw": layout_raw,
        "button_flag_raw": button_flag_raw,
        "entry_count": entry_count,
        "arena_used": arena_used,
        "arena_raw_hex": b"".join(arena_chunks).hex(),
        "fields": entries,
        "full_display_complete": False,
        "runtime_popup_verified": False,
        "visibility_verified": False,
    }


def decode_envelope(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode v7 framing and DCTX fields; :func:`decode` validates the base v6."""
    raw = _as_bytes(data)
    if len(raw) < 10 + 10 + FIXED_BODY_BYTES or raw[:4] != MAGIC:
        raise DisplayContextWireError("magic_or_prefix_mismatch")
    version = struct.unpack_from("<H", raw, 4)[0]
    if version != VERSION:
        raise DisplayContextWireError("version_mismatch")
    base_bytes = struct.unpack_from("<I", raw, 6)[0]
    if base_bytes == 0 or base_bytes > MAX_WIRE_BYTES:
        raise DisplayContextWireError("base_v6_length_over_bound")
    base_end = 10 + base_bytes
    if base_end > len(raw):
        raise DisplayContextWireError("truncated_base_v6")
    base = raw[10:base_end]
    if len(base) < 6 or base[:4] != MAGIC or struct.unpack_from("<H", base, 4)[0] != BASE_VERSION:
        raise DisplayContextWireError("embedded_base_is_not_v6")
    reader = _Reader(raw[base_end:])
    if reader.take(4, "extension_magic") != EXTENSION_MAGIC:
        raise DisplayContextWireError("extension_magic_mismatch")
    extension_version = reader.u16("extension_version")
    if extension_version != EXTENSION_VERSION:
        raise DisplayContextWireError("extension_version_mismatch")
    body_length = reader.u32("extension_body_length")
    if body_length != reader.remaining:
        raise DisplayContextWireError("extension_length_mismatch")
    body = reader.take(body_length, "extension_body")
    display_context = _decode_body(body)
    if reader.remaining:
        raise DisplayContextWireError("trailing_bytes_after_extension")
    return {
        "schema": "information_battle_display_context_envelope_v7",
        "wire": {
            "version": VERSION,
            "bytes": len(raw),
            "base_v6_version": BASE_VERSION,
            "base_v6_bytes": base_bytes,
            "extension_magic": EXTENSION_MAGIC.decode("ascii"),
            "extension_version": extension_version,
            "extension_bytes": body_length,
            "trailing_bytes": 0,
        },
        "base_v6_payload_hex": base.hex(),
        "display_context": display_context,
        "complete": False,
        "full_display_complete": False,
        "runtime_popup_verified": False,
        "visibility_verified": False,
    }


def _decode_base_v6(base: bytes) -> dict[str, Any]:
    if len(base) < 6 or base[:4] != MAGIC or struct.unpack_from("<H", base, 4)[0] != BASE_VERSION:
        raise DisplayContextWireError("embedded_base_is_not_v6")
    try:
        decoded = _v6.decode(base)
    except (ValueError, TypeError) as exc:
        raise DisplayContextWireError(f"invalid_embedded_base_v6:{exc}") from exc
    wire6 = decoded.get("wire6") if isinstance(decoded, dict) else None
    if (not isinstance(decoded, dict)
            or decoded.get("schema") != "information_battle_native_text_wire_v6"
            or not isinstance(wire6, Mapping)
            or wire6.get("version") != BASE_VERSION):
        raise DisplayContextWireError("embedded_base_v6_decode_shape_invalid")
    return decoded


def decode(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Delegate versions 1..6 unchanged and compose the strict v7 extension."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return _v6.decode(data)
    raw = bytes(data)
    if len(raw) < 6 or raw[:4] != MAGIC or struct.unpack_from("<H", raw, 4)[0] != VERSION:
        # Compatibility boundary: preserve the existing v1-v6 decoder result
        # object and error semantics exactly.
        return _v6.decode(data)
    raw = _as_bytes(raw)
    envelope = decode_envelope(raw)
    base = bytes.fromhex(envelope["base_v6_payload_hex"])
    base_result = _decode_base_v6(base)
    composed = dict(base_result)
    composed["wire7"] = dict(envelope["wire"])
    composed["display_context"] = envelope["display_context"]
    # Keep the full v6 decoded payload intact; these additional guards are
    # explicit and remain false for this copied-value snapshot.
    composed["full_display_complete"] = False
    composed["runtime_popup_verified"] = False
    composed["visibility_verified"] = False
    return composed


def _field_input(value: Any, name: str) -> tuple[int, bytes]:
    if value is None:
        value = {"state": "unknown"}
    if not isinstance(value, Mapping):
        raise DisplayContextWireError(f"field_must_be_object:{name}")
    state = value.get("state", "unknown")
    if state not in STATE_IDS:
        raise DisplayContextWireError(f"invalid_state:{name}")
    state_id = STATE_IDS[state]
    if "raw_hex" in value and "raw_bytes" in value:
        raise DisplayContextWireError(f"ambiguous_raw_value:{name}")
    raw_value = value.get("raw_bytes", value.get("raw_hex", ""))
    if raw_value is None and state_id != STATE_IDS["observed"]:
        raw_value = b""
    if isinstance(raw_value, (bytes, bytearray, memoryview)):
        raw = bytes(raw_value)
    elif isinstance(raw_value, str):
        if len(raw_value) % 2:
            raise DisplayContextWireError(f"invalid_raw_hex:{name}")
        try:
            raw = bytes.fromhex(raw_value)
        except ValueError as exc:
            raise DisplayContextWireError(f"invalid_raw_hex:{name}") from exc
    else:
        raise DisplayContextWireError(f"invalid_raw_value:{name}")
    if len(raw) > FIELD_LIMITS[name]:
        raise DisplayContextWireError(f"field_length_over_bound:{name}")
    if state_id != STATE_IDS["observed"] and raw:
        raise DisplayContextWireError(f"raw_for_unobserved:{name}")
    if b"\x00" in raw:
        raise DisplayContextWireError(f"embedded_nul:{name}")
    return state_id, raw


def _normalize_snapshot(snapshot: Mapping[str, Any]) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(snapshot, Mapping):
        raise DisplayContextWireError("snapshot_must_be_object")
    state_name = snapshot.get("state")
    if state_name not in ("unknown", "observed"):
        raise DisplayContextWireError("invalid_context_state")
    fields_value = snapshot.get("fields", {})
    if not isinstance(fields_value, Mapping):
        raise DisplayContextWireError("fields_must_be_object")
    entries: list[tuple[str, int, bytes]] = []
    arena_used = 0
    for name in FIELD_ORDER:
        state_id, raw = _field_input(fields_value.get(name), name)
        entries.append((name, state_id, raw))
        arena_used += len(raw)
        if arena_used > MAX_ARENA_BYTES:
            raise DisplayContextWireError("arena_over_bound")

    if state_name == "unknown":
        failure = _int(snapshot.get("failure"), "failure", 1, 9)
        stage = _int(snapshot.get("capture_stage", 0), "capture_stage", 0, 255)
        sequence = _int(snapshot.get("sequence", 0), "sequence", 0, (1 << 64) - 1)
        raw_date = _int(snapshot.get("raw_date", 0), "raw_date", -(1 << 31), (1 << 31) - 1)
        kind = _int(snapshot.get("battle_kind", 0), "battle_kind", 0, 255)
        popup_kind = _int(snapshot.get("popup_kind_raw", 0), "popup_kind_raw", -(1 << 31), (1 << 31) - 1)
        layout = _int(snapshot.get("layout_raw", 0), "layout_raw", -(1 << 31), (1 << 31) - 1)
        button = _int(snapshot.get("button_flag_raw", 0), "button_flag_raw", 0, 255)
        if (stage or sequence or raw_date or kind or popup_kind or layout or button or arena_used
                or any(state_id != STATE_IDS["unknown"] for _name, state_id, _raw in entries)):
            raise DisplayContextWireError("noncanonical_unknown_snapshot")
        context_state = 0
    else:
        failure = _int(snapshot.get("failure", 0), "failure", 0, 0)
        stage = _int(snapshot.get("capture_stage"), "capture_stage", 1, 3)
        sequence = _int(snapshot.get("sequence"), "sequence", 1, (1 << 64) - 1)
        raw_date = _int(snapshot.get("raw_date"), "raw_date", -(1 << 31), (1 << 31) - 1)
        kind = _int(snapshot.get("battle_kind"), "battle_kind", 1, 2)
        popup_kind = _int(snapshot.get("popup_kind_raw"), "popup_kind_raw", -(1 << 31), (1 << 31) - 1)
        layout = _int(snapshot.get("layout_raw"), "layout_raw", -(1 << 31), (1 << 31) - 1)
        button = _int(snapshot.get("button_flag_raw"), "button_flag_raw", 0, 255)
        values = {name: (state_id, raw) for name, state_id, raw in entries}
        if values["definition_key"][0] != STATE_IDS["observed"]:
            raise DisplayContextWireError("observed_definition_key_required")
        if values["language"][0] != STATE_IDS["observed"]:
            raise DisplayContextWireError("observed_language_required")
        if values["definition_key"][1] != FORMATTER_KEYS[kind]:
            raise DisplayContextWireError("definition_key_kind_mismatch")
        _decode_language(values["language"][1])
        context_state = 1

    _failure_name(failure)
    body = bytearray(struct.pack(
        "<BBHQiBiiBB",
        context_state, stage, failure, sequence, raw_date, kind,
        popup_kind, layout, button, ENTRY_COUNT,
    ))
    for field_id, (name, state_id, raw) in enumerate(entries, start=1):
        body.extend(struct.pack("<BBHI", field_id, state_id, 0, len(raw)))
        body.extend(raw)
    if len(body) < FIXED_BODY_BYTES or len(body) > FIXED_BODY_BYTES + ENTRY_COUNT * ENTRY_HEADER_BYTES + MAX_ARENA_BYTES:
        raise DisplayContextWireError("body_length_over_bound")
    return bytes(body), {
        "state": state_name,
        "failure": failure,
        "sequence": sequence,
        "raw_date": raw_date,
        "battle_kind": kind,
        "popup_kind_raw": popup_kind,
        "layout_raw": layout,
        "button_flag_raw": button,
        "arena_used": arena_used,
    }


def encode(base_v6: bytes | bytearray | memoryview,
           snapshot: Mapping[str, Any]) -> bytes:
    """Encode one complete v6 frame and a strict pointer-free DCTX snapshot."""
    base = _as_bytes(base_v6)
    _decode_base_v6(base)
    body, _normalized = _normalize_snapshot(snapshot)
    extension = EXTENSION_MAGIC + struct.pack("<HI", EXTENSION_VERSION, len(body)) + body
    result = MAGIC + struct.pack("<HI", VERSION, len(base)) + base + extension
    if len(result) > MAX_WIRE_BYTES:
        raise DisplayContextWireError("wire_size_over_bound")
    return result


__all__ = [
    "DisplayContextWireError", "EXTENSION_MAGIC", "EXTENSION_VERSION",
    "FIELD_IDS", "FIELD_LIMITS", "FIELD_ORDER", "FIELD_SOURCES", "MAGIC",
    "MAX_ARENA_BYTES", "MAX_WIRE_BYTES", "VERSION", "decode",
    "decode_envelope", "encode",
]
