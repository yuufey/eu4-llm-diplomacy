"""Strict decoder for the version-3 IBOW naval extension.

Version 3 embeds one complete, unchanged version-2 context frame and appends
an optional ``NAVL`` block.  The extension contains only bounded raw naval
loss/gate values and summary row type values.  It carries no pointers, source
roles, repeated initial lanes, ship-class claims, visibility, or business
semantics.

Version-2 input is delegated directly to the existing context decoder.  A
version-3 decoder accepts only a version-2 base; it never recursively decodes
a naval frame as its own base.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

try:  # namespace-package import from the repository root
    from .information_battle_context_wire import (
        ContextWireError,
        decode as decode_v2,
    )
    from .information_battle_observation_wire import ObservationWireError
except ImportError:  # pragma: no cover - direct script compatibility
    from information_battle_context_wire import (  # type: ignore
        ContextWireError,
        decode as decode_v2,
    )
    from information_battle_observation_wire import (  # type: ignore
        ObservationWireError,
    )


MAGIC = b"IBOW"
VERSION = 3
BASE_VERSION = 2
EXTENSION_MAGIC = b"NAVL"
EXTENSION_VERSION = 1
MAX_WIRE_BYTES = 65_536
MAX_BASE_V2_BYTES = 32_768
MAX_ROWS = 256
SIDE_COUNT = 2
RAW_LOSS_COUNT = 4
EXTENSION_HEADER_BYTES = 4 + 2 + 4
EXTENSION_FIXED_BODY_BYTES = 4 + SIDE_COUNT * (RAW_LOSS_COUNT * 4 + 1)


class NavalWireError(ValueError):
    """The input is not one strict version-2 or version-3 naval frame."""


@dataclass
class _Reader:
    data: bytes
    position: int = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.position

    def take(self, size: int, label: str) -> bytes:
        if size < 0 or size > self.remaining:
            raise NavalWireError(f"truncated:{label}")
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
        raise NavalWireError("input_must_be_bytes_like")
    try:
        raw = bytes(data)
    except (TypeError, ValueError) as exc:
        raise NavalWireError("input_bytes_conversion_failed") from exc
    if len(raw) > MAX_WIRE_BYTES:
        raise NavalWireError("wire_size_over_bound")
    if len(raw) < 4 + 2 + 4 + 1:
        raise NavalWireError("wire_truncated_prefix")
    return raw


def _canonical_bool(value: int, label: str) -> bool:
    if value not in (0, 1):
        raise NavalWireError(f"noncanonical_bool:{label}")
    return bool(value)


def _base_is_complete_naval(base: dict[str, Any]) -> bool:
    if base.get("context_present") is not True:
        return False
    context = base.get("context")
    if not isinstance(context, dict) or context.get("kind") != 2:
        return False
    sides = context.get("sides")
    if not isinstance(sides, list) or len(sides) != SIDE_COUNT:
        return False
    for side in sides:
        if not isinstance(side, dict) or side.get("present") is not True:
            return False
        participants = side.get("participants")
        if not isinstance(participants, dict) \
                or participants.get("complete") is not True:
            return False
    return True


def _decode_v2_compat(raw: bytes) -> dict[str, Any]:
    try:
        decoded = decode_v2(raw)
    except (ContextWireError, ObservationWireError) as exc:
        raise NavalWireError(f"invalid_v2:{exc}") from exc
    if decoded.get("wire", {}).get("version") != BASE_VERSION:
        raise NavalWireError("base_is_not_v2")
    return decoded


def _v3_result(base: dict[str, Any], raw: bytes, base_bytes: int,
               naval: dict[str, Any] | None, present: bool,
               extension_bytes: int = 0,
               extension_version: int | None = None) -> dict[str, Any]:
    # Keep every v2 root field (observation/context/complete flags) and replace
    # only schema/wire metadata plus the new raw naval field.
    result = dict(base)
    base_wire = dict(base.get("wire", {}))
    base_wire.update({
        "version": VERSION,
        "bytes": len(raw),
        "base_v2_version": BASE_VERSION,
        "base_v2_bytes": base_bytes,
        "naval_present": present,
        "extension_version": extension_version,
        "extension_bytes": extension_bytes,
        "trailing_bytes": 0,
    })
    result["schema"] = "information_battle_naval_wire_v3"
    result["wire"] = base_wire
    result["naval"] = naval
    return result


def decode(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode one complete v2 frame or strict v3 frame.

    v2 is returned directly from the existing context decoder.  v3 embeds
    exactly one v2 frame and returns the same root fields with ``naval`` added.
    """

    raw = _as_bytes(data)
    if raw[:4] != MAGIC:
        raise NavalWireError("magic_mismatch")
    version = int.from_bytes(raw[4:6], "little", signed=False)
    if version == BASE_VERSION:
        return _decode_v2_compat(raw)
    if version != VERSION:
        raise NavalWireError(f"unsupported_version:{version}")

    reader = _Reader(raw)
    if reader.take(4, "magic") != MAGIC:
        raise NavalWireError("magic_mismatch")
    if reader.u16("version") != VERSION:
        raise NavalWireError("version_mismatch")
    base_bytes = reader.u32("base_v2_bytes")
    if base_bytes == 0 or base_bytes > MAX_BASE_V2_BYTES:
        raise NavalWireError("base_v2_bytes_over_bound")
    base_raw = reader.take(base_bytes, "base_v2")
    base = _decode_v2_compat(base_raw)
    present = _canonical_bool(reader.u8("naval_present"), "naval_present")

    if not present:
        if reader.remaining != 0:
            raise NavalWireError(f"trailing_bytes_without_naval:{reader.remaining}")
        return _v3_result(base, raw, base_bytes, None, False)

    if not _base_is_complete_naval(base):
        raise NavalWireError("naval_requires_complete_naval_base")
    if reader.remaining < EXTENSION_HEADER_BYTES:
        raise NavalWireError("truncated_naval_extension_header")
    if reader.take(4, "extension_magic") != EXTENSION_MAGIC:
        raise NavalWireError("extension_magic_mismatch")
    extension_version = reader.u16("extension_version")
    if extension_version != EXTENSION_VERSION:
        raise NavalWireError(f"unsupported_extension_version:{extension_version}")
    extension_bytes = reader.u32("extension_bytes")
    if extension_bytes > MAX_WIRE_BYTES \
            or extension_bytes != reader.remaining:
        raise NavalWireError("extension_length_mismatch")
    body = _Reader(reader.take(extension_bytes, "extension_body"))
    row_count = body.u32("row_count")
    if row_count > MAX_ROWS:
        raise NavalWireError("row_count_over_bound")
    expected_body = EXTENSION_FIXED_BODY_BYTES + row_count * 4
    if extension_bytes != expected_body:
        raise NavalWireError("extension_size_for_row_count_mismatch")
    row_types = [
        body.i32(f"row_types[{index}]") for index in range(row_count)
    ]
    sides: list[dict[str, Any]] = []
    for side_index in range(SIDE_COUNT):
        raw_loss_i32 = [
            body.i32(f"sides[{side_index}].raw_loss_i32[{index}]")
            for index in range(RAW_LOSS_COUNT)
        ]
        raw_gate = body.u8(f"sides[{side_index}].raw_gate")
        sides.append({"raw_loss_i32": raw_loss_i32, "raw_gate": raw_gate})
    if body.remaining != 0 or reader.remaining != 0:
        raise NavalWireError("trailing_bytes_in_naval_extension")
    return _v3_result(
        base,
        raw,
        base_bytes,
        {"row_types": row_types, "sides": sides},
        True,
        extension_bytes,
        extension_version,
    )


decode_wire = decode

__all__ = [
    "BASE_VERSION",
    "EXTENSION_MAGIC",
    "EXTENSION_VERSION",
    "MAGIC",
    "MAX_BASE_V2_BYTES",
    "MAX_ROWS",
    "MAX_WIRE_BYTES",
    "NavalWireError",
    "VERSION",
    "decode",
    "decode_wire",
]
