"""Strict decoder for the pointer-free battle observation wire.

The native encoder carries one already-owned result snapshot and one raw
summary snapshot.  This module deliberately keeps string payloads as hex
bytes: no UTF-8, locale, capacity, pointer, kind, winner, scale, visibility,
war identity, or battle identity is guessed here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


MAGIC = b"IBOW"
VERSION = 1
MAX_WIRE_BYTES = 16_384
MAX_STRING_BYTES = 4_096
HEADER_BYTES = 19
SUMMARY_RAW_COUNT = 11
SIDE_COUNT = 2


class ObservationWireError(ValueError):
    """The input is not one strict version-1 observation frame."""


@dataclass
class _Reader:
    data: bytes
    position: int = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.position

    def take(self, size: int, label: str) -> bytes:
        if size < 0 or size > self.remaining:
            raise ObservationWireError(f"truncated:{label}")
        begin = self.position
        self.position += size
        return self.data[begin:self.position]

    def u8(self, label: str) -> int:
        return self.take(1, label)[0]

    def u16(self, label: str) -> int:
        return int.from_bytes(self.take(2, label), "little", signed=False)

    def u32(self, label: str) -> int:
        return int.from_bytes(self.take(4, label), "little", signed=False)

    def u64(self, label: str) -> int:
        return int.from_bytes(self.take(8, label), "little", signed=False)

    def i32(self, label: str) -> int:
        return int.from_bytes(self.take(4, label), "little", signed=True)


def _as_bytes(data: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ObservationWireError("input_must_be_bytes_like")
    try:
        raw = bytes(data)
    except (TypeError, ValueError) as exc:
        raise ObservationWireError("input_bytes_conversion_failed") from exc
    if len(raw) > MAX_WIRE_BYTES:
        raise ObservationWireError("wire_size_over_bound")
    if len(raw) < HEADER_BYTES:
        raise ObservationWireError("wire_truncated_header")
    return raw


def _raw_string(reader: _Reader, label: str) -> dict[str, Any]:
    length = reader.u32(f"{label}.length")
    if length > MAX_STRING_BYTES:
        raise ObservationWireError(f"string_length_over_bound:{label}")
    raw = reader.take(length, f"{label}.bytes")
    # The value is deliberately represented as hex rather than decoded text.
    # This preserves arbitrary non-UTF8 bytes and makes the returned object
    # JSON-safe without inventing a codec.
    return {"length": length, "raw_hex": raw.hex()}


def decode(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode one complete observation frame, rejecting every mismatch.

    The result is a JSON-shaped raw-value object.  ``complete`` and
    ``visibility_verified`` remain false because this wire contains a bounded
    callback snapshot, not a complete public battle event.
    """

    raw = _as_bytes(data)
    reader = _Reader(raw)
    if reader.take(4, "magic") != MAGIC:
        raise ObservationWireError("magic_mismatch")
    version = reader.u16("version")
    if version != VERSION:
        raise ObservationWireError(f"unsupported_version:{version}")

    sequence = reader.u64("sequence")
    thread = reader.u32("thread")
    if sequence == 0:
        raise ObservationWireError("zero_sequence")
    if thread == 0:
        raise ObservationWireError("zero_thread")
    known_router_raw = reader.u8("known_router")
    if known_router_raw not in (0, 1):
        raise ObservationWireError("noncanonical_known_router")

    result: dict[str, Any] = {
        "raw_date": reader.i32("result.raw_date"),
        "flag108": reader.u8("result.flag108"),
        "aux100": reader.i32("result.aux100"),
        "aux104": reader.i32("result.aux104"),
        "province_id": reader.i32("result.province_id"),
        "name": _raw_string(reader, "result.name"),
        "sides": [],
    }
    for side_index in range(SIDE_COUNT):
        country = reader.u64(f"result.sides[{side_index}].country")
        raw_fields = [
            reader.i32(f"result.sides[{side_index}].raw_fields[{field_index}]")
            for field_index in range(9)
        ]
        commander = _raw_string(reader, f"result.sides[{side_index}].commander")
        result["sides"].append({
            "country": country,
            "country_raw_hex": f"{country:016x}",
            "raw_fields": raw_fields,
            "commander": commander,
        })

    summary = {
        "raw_i32": [
            reader.i32(f"summary.raw_i32[{index}]")
            for index in range(SUMMARY_RAW_COUNT)
        ],
        "control_byte": reader.u8("summary.control_byte"),
    }
    if reader.remaining != 0:
        raise ObservationWireError(f"trailing_bytes:{reader.remaining}")

    return {
        "schema": "information_battle_observation_wire_v1",
        "wire": {
            "magic": MAGIC.decode("ascii"),
            "version": version,
            "bytes": len(raw),
            "trailing_bytes": 0,
        },
        "observation": {
            "sequence": sequence,
            "thread": thread,
            "known_router": bool(known_router_raw),
            "result": result,
            "summary": summary,
        },
        "complete": False,
        "visibility_verified": False,
        "public_identity": {
            "status": "absent",
            "war_id": None,
            "battle_id": None,
        },
    }


decode_wire = decode


__all__ = [
    "HEADER_BYTES",
    "MAGIC",
    "MAX_STRING_BYTES",
    "MAX_WIRE_BYTES",
    "ObservationWireError",
    "VERSION",
    "decode",
    "decode_wire",
]
