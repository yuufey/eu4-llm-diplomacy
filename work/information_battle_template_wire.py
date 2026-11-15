"""Strict decoder for the version-4 IBOW message/template envelope.

Version 4 embeds exactly one complete version-3 naval wire frame and appends
an optional BTXT block.  Extension 1 contains a copied message object;
extension 2 contains the formatter's standalone pre-cleanup container.  Both
contain bounded scalar fields and raw bytes only; pair order and duplicate
keys are retained and no text decoding or native pointer is performed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

try:  # namespace-package import from the repository root
    from .information_battle_naval_wire import (
        NavalWireError,
        decode as decode_v3,
    )
except ImportError:  # pragma: no cover - direct script compatibility
    from information_battle_naval_wire import (  # type: ignore
        NavalWireError,
        decode as decode_v3,
    )


MAGIC = b"IBOW"
VERSION = 4
BASE_VERSION = 3
EXTENSION_MAGIC = b"BTXT"
EXTENSION_VERSION = 1
CONTAINER_EXTENSION_VERSION = 2
MESSAGE_SOURCE = 1
FORMATTER_CONTAINER_SOURCE = 2
MAX_WIRE_BYTES = 256 * 1024
MAX_BASE_V3_BYTES = 65_536
MAX_PAIRS = 128
MAX_KEY_BYTES = 128
MAX_VALUE_BYTES = 8192
MAX_AUXILIARY_TEXT_BYTES = 8192
MAX_ARENA_BYTES = 64 * 1024
EXTENSION_HEADER_BYTES = 4 + 2 + 4
FIXED_BODY_BYTES = 4 + 1 + 1 + 4 + 1 + 4 + 4
CONTAINER_FIXED_BODY_BYTES = 1 + 4 + 1 + 4


class TemplateWireError(ValueError):
    """The input is not one strict version-4 template frame."""


@dataclass
class _Reader:
    data: bytes
    position: int = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.position

    def take(self, size: int, label: str) -> bytes:
        if size < 0 or size > self.remaining:
            raise TemplateWireError(f"truncated:{label}")
        begin = self.position
        self.position += size
        return self.data[begin:self.position]

    def u8(self, label: str) -> int:
        return self.take(1, label)[0]

    def u16(self, label: str) -> int:
        return int.from_bytes(self.take(2, label), "little", signed=False)

    def u32(self, label: str) -> int:
        return int.from_bytes(self.take(4, label), "little", signed=False)

    def i32(self, label: str) -> int:
        return int.from_bytes(self.take(4, label), "little", signed=True)


def _as_bytes(data: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TemplateWireError("input_must_be_bytes_like")
    try:
        raw = bytes(data)
    except (TypeError, ValueError) as exc:
        raise TemplateWireError("input_bytes_conversion_failed") from exc
    if len(raw) > MAX_WIRE_BYTES:
        raise TemplateWireError("wire_size_over_bound")
    if len(raw) < 4 + 2 + 4 + 1:
        raise TemplateWireError("wire_truncated_prefix")
    return raw


def _canonical_bool(value: int, label: str) -> bool:
    if value not in (0, 1):
        raise TemplateWireError(f"noncanonical_bool:{label}")
    return bool(value)


def _v4_result(base: dict[str, Any], raw: bytes, base_bytes: int,
               message: dict[str, Any] | None, present: bool,
               extension_bytes: int = 0,
               extension_version: int | None = None) -> dict[str, Any]:
    # Preserve every v3 root key and replace only schema/wire metadata plus
    # the new value-only message_template key.
    result = dict(base)
    base_wire = dict(base.get("wire", {}))
    base_wire.update({
        "version": VERSION,
        "bytes": len(raw),
        "base_v3_version": BASE_VERSION,
        "base_v3_bytes": base_bytes,
        "template_present": present,
        "extension_version": extension_version,
        "extension_bytes": extension_bytes,
        "trailing_bytes": 0,
    })
    result["schema"] = "information_battle_template_wire_v4"
    result["wire"] = base_wire
    result["message_template"] = message
    return result


def _decode_message(body: _Reader) -> dict[str, Any]:
    native_date = body.i32("native_date")
    raw_flag_8c = body.u8("raw_flag_8c")
    raw_flag_8d = body.u8("raw_flag_8d")
    raw_header_word_20 = body.u32("raw_header_word_20")
    raw_header_flag_24 = body.u8("raw_header_flag_24")
    pair_count = body.u32("pair_count")
    if pair_count > MAX_PAIRS:
        raise TemplateWireError("pair_count_over_bound")

    auxiliary_length = body.u32("auxiliary_text_length")
    if auxiliary_length > MAX_AUXILIARY_TEXT_BYTES:
        raise TemplateWireError("auxiliary_text_over_bound")
    auxiliary = body.take(auxiliary_length, "auxiliary_text")
    arena_bytes = auxiliary_length

    pairs: list[dict[str, str]] = []
    for index in range(pair_count):
        key_length = body.u32(f"pairs[{index}].key_length")
        if key_length > MAX_KEY_BYTES:
            raise TemplateWireError(f"key_over_bound:pairs[{index}]")
        key = body.take(key_length, f"pairs[{index}].key")
        value_length = body.u32(f"pairs[{index}].value_length")
        if value_length > MAX_VALUE_BYTES:
            raise TemplateWireError(f"value_over_bound:pairs[{index}]")
        if (key_length > MAX_ARENA_BYTES - arena_bytes
                or value_length > MAX_ARENA_BYTES - arena_bytes - key_length):
            raise TemplateWireError("template_arena_over_bound")
        value = body.take(value_length, f"pairs[{index}].value")
        arena_bytes += key_length + value_length
        pairs.append({
            "key_raw_hex": key.hex(),
            "value_raw_hex": value.hex(),
        })

    if body.remaining != 0:
        raise TemplateWireError("trailing_bytes_in_template_extension")
    return {
        "native_date": native_date,
        "raw_flag_8c": raw_flag_8c,
        "raw_flag_8d": raw_flag_8d,
        "raw_header_word_20": raw_header_word_20,
        "raw_header_flag_24": raw_header_flag_24,
        "pair_count": pair_count,
        "auxiliary_text_hex": auxiliary.hex(),
        "pairs": pairs,
    }


def _decode_formatter_container(body: _Reader) -> dict[str, Any]:
    source_kind = body.u8("source_kind")
    if source_kind != FORMATTER_CONTAINER_SOURCE:
        raise TemplateWireError("noncanonical_formatter_container_source_kind")
    raw_container_word_10 = body.u32("raw_container_word_10")
    raw_container_flag_14 = body.u8("raw_container_flag_14")
    pair_count = body.u32("pair_count")
    if pair_count > MAX_PAIRS:
        raise TemplateWireError("pair_count_over_bound")

    pairs: list[dict[str, str]] = []
    arena_bytes = 0
    for index in range(pair_count):
        key_length = body.u32(f"pairs[{index}].key_length")
        if key_length > MAX_KEY_BYTES:
            raise TemplateWireError(f"key_over_bound:pairs[{index}]")
        key = body.take(key_length, f"pairs[{index}].key")
        value_length = body.u32(f"pairs[{index}].value_length")
        if value_length > MAX_VALUE_BYTES:
            raise TemplateWireError(f"value_over_bound:pairs[{index}]")
        if (key_length > MAX_ARENA_BYTES - arena_bytes
                or value_length > MAX_ARENA_BYTES - arena_bytes - key_length):
            raise TemplateWireError("template_arena_over_bound")
        value = body.take(value_length, f"pairs[{index}].value")
        arena_bytes += key_length + value_length
        pairs.append({
            "key_raw_hex": key.hex(),
            "value_raw_hex": value.hex(),
        })

    if body.remaining != 0:
        raise TemplateWireError("trailing_bytes_in_formatter_container_extension")
    return {
        "source_kind": "formatter_container_before_cleanup",
        "message_metadata_present": False,
        "native_date": None,
        "raw_flag_8c": None,
        "raw_flag_8d": None,
        "auxiliary_text_hex": None,
        "raw_container_word_10": raw_container_word_10,
        "raw_container_flag_14": raw_container_flag_14,
        "pair_count": pair_count,
        "pairs": pairs,
    }


def decode(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode one complete version-4 template frame.

    The embedded base must decode as a direct v3 frame.  A v2 base, nested v4
    frame, truncated body, or any trailing byte is rejected.
    """

    raw = _as_bytes(data)
    if raw[:4] == MAGIC and len(raw) >= 6:
        top_version = int.from_bytes(raw[4:6], "little", signed=False)
        if top_version in (2, 3):
            try:
                # Compatibility is deliberately delegated so v2/v3 retain
                # their existing schema and every existing top-level key.
                return decode_v3(raw)
            except (NavalWireError, ValueError) as exc:
                raise TemplateWireError(f"invalid_legacy_wire:{exc}") from exc
    reader = _Reader(raw)
    if reader.take(4, "magic") != MAGIC:
        raise TemplateWireError("magic_mismatch")
    if reader.u16("version") != VERSION:
        raise TemplateWireError("version_mismatch")
    base_bytes = reader.u32("base_v3_bytes")
    if base_bytes == 0 or base_bytes > MAX_BASE_V3_BYTES:
        raise TemplateWireError("base_v3_bytes_over_bound")
    base_raw = reader.take(base_bytes, "base_v3")
    try:
        base = decode_v3(base_raw)
    except (NavalWireError, ValueError) as exc:
        raise TemplateWireError(f"invalid_v3:{exc}") from exc
    if base.get("wire", {}).get("version") != BASE_VERSION:
        raise TemplateWireError("base_is_not_v3")

    present = _canonical_bool(reader.u8("template_present"), "template_present")
    if not present:
        if reader.remaining != 0:
            raise TemplateWireError(
                f"trailing_bytes_without_template:{reader.remaining}"
            )
        return _v4_result(base, raw, base_bytes, None, False)

    if reader.remaining < EXTENSION_HEADER_BYTES:
        raise TemplateWireError("truncated_template_extension_header")
    if reader.take(4, "extension_magic") != EXTENSION_MAGIC:
        raise TemplateWireError("extension_magic_mismatch")
    extension_version = reader.u16("extension_version")
    if extension_version not in (EXTENSION_VERSION,
                                 CONTAINER_EXTENSION_VERSION):
        raise TemplateWireError(f"unsupported_extension_version:{extension_version}")
    extension_bytes = reader.u32("extension_bytes")
    if extension_bytes > MAX_WIRE_BYTES or extension_bytes != reader.remaining:
        raise TemplateWireError("extension_length_mismatch")
    minimum_body = (CONTAINER_FIXED_BODY_BYTES
                    if extension_version == CONTAINER_EXTENSION_VERSION
                    else FIXED_BODY_BYTES)
    if extension_bytes < minimum_body:
        raise TemplateWireError("template_extension_too_short")
    body = _Reader(reader.take(extension_bytes, "extension_body"))
    message = (_decode_formatter_container(body)
               if extension_version == CONTAINER_EXTENSION_VERSION
               else _decode_message(body))
    if reader.remaining != 0:
        raise TemplateWireError("trailing_bytes_after_template_extension")
    return _v4_result(
        base, raw, base_bytes, message, True,
        extension_bytes, extension_version,
    )


decode_wire = decode

__all__ = [
    "BASE_VERSION",
    "CONTAINER_EXTENSION_VERSION",
    "CONTAINER_FIXED_BODY_BYTES",
    "EXTENSION_MAGIC",
    "EXTENSION_VERSION",
    "FORMATTER_CONTAINER_SOURCE",
    "FIXED_BODY_BYTES",
    "MAX_ARENA_BYTES",
    "MAX_AUXILIARY_TEXT_BYTES",
    "MAX_BASE_V3_BYTES",
    "MAX_KEY_BYTES",
    "MAX_PAIRS",
    "MAX_VALUE_BYTES",
    "MAX_WIRE_BYTES",
    "MESSAGE_SOURCE",
    "TemplateWireError",
    "VERSION",
    "decode",
    "decode_wire",
]
