"""Strict decoder for the version-2 IBOW battle-context envelope.

The inner result/summary frame is decoded by the unchanged version-1
``information_battle_observation_wire`` module.  The optional context is a
bounded copy of ``information-battle-owned-context.h``.  This decoder keeps
all values raw and deliberately publishes no battle identity, visibility,
kind semantics, or business completeness.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

try:  # namespace-package import when called from the repository root
    from .information_battle_observation_wire import (
        ObservationWireError,
        decode as decode_v1,
    )
except ImportError:  # pragma: no cover - direct script compatibility
    from information_battle_observation_wire import (  # type: ignore
        ObservationWireError,
        decode as decode_v1,
    )


MAGIC = b"IBOW"
VERSION = 2
MAX_WIRE_BYTES = 32_768
MAX_INNER_V1_BYTES = 16_384
MAX_PARTICIPANTS = 256
MAX_WAR_MEMBERS = 256
SIDE_RAW_FIELD_COUNT = 6
SELECTOR_CODE_LENGTH = 6


class ContextWireError(ValueError):
    """The input is not one strict version-2 context frame."""


@dataclass
class _Reader:
    data: bytes
    position: int = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.position

    def take(self, size: int, label: str) -> bytes:
        if size < 0 or size > self.remaining:
            raise ContextWireError(f"truncated:{label}")
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
        raise ContextWireError("input_must_be_bytes_like")
    try:
        raw = bytes(data)
    except (TypeError, ValueError) as exc:
        raise ContextWireError("input_bytes_conversion_failed") from exc
    if len(raw) > MAX_WIRE_BYTES:
        raise ContextWireError("wire_size_over_bound")
    if len(raw) < 4 + 2 + 4 + 1:
        raise ContextWireError("wire_truncated_prefix")
    return raw


def _bool(value: int, label: str) -> bool:
    if value not in (0, 1):
        raise ContextWireError(f"noncanonical_bool:{label}")
    return bool(value)


def _ascii_alnum(value: int) -> bool:
    return (48 <= value <= 57) or (65 <= value <= 90)


def _valid_full_ref(value: int, label: str) -> None:
    # The low three bytes carry the ASCII uppercase/digit country tag.  Byte 3
    # and all higher identity bytes remain opaque and are not interpreted.
    if value == 0:
        raise ContextWireError(f"invalid_full_ref:{label}")
    if not all(_ascii_alnum((value >> shift) & 0xFF) for shift in (0, 8, 16)):
        raise ContextWireError(f"invalid_full_ref:{label}")


def _selector_code(raw_selector: int) -> bytes:
    return b"\xb8" + raw_selector.to_bytes(4, "little") + b"\xc3"


def _read_side(reader: _Reader, side_index: int) -> dict[str, Any]:
    label = f"sides[{side_index}]"
    present = _bool(reader.u8(f"{label}.present"), f"{label}.present")
    complete = _bool(reader.u8(f"{label}.participants.complete"),
                     f"{label}.participants.complete")
    count = reader.u32(f"{label}.participants.count")
    if count > MAX_PARTICIPANTS:
        raise ContextWireError(f"participant_count_over_bound:{label}")
    full_refs = []
    for index in range(count):
        value = reader.u64(f"{label}.participants.full_refs[{index}]")
        _valid_full_ref(value, f"{label}.participants.full_refs[{index}]")
        full_refs.append(value)
    raw_fields = [
        reader.i32(f"{label}.raw_fields[{index}]")
        for index in range(SIDE_RAW_FIELD_COUNT)
    ]
    if not present:
        if complete or count != 0 or any(raw_fields):
            raise ContextWireError(f"absent_side_has_values:{label}")
    elif not complete:
        raise ContextWireError(f"present_side_is_incomplete:{label}")
    return {
        "present": present,
        "participants": {
            "complete": complete,
            "count": count,
            "full_refs": full_refs,
        },
        "raw_fields": raw_fields,
    }


def _duplicates_or_overlap(left: list[int], right: list[int]) -> bool:
    return len(set(left)) != len(left) or len(set(right)) != len(right) \
        or bool(set(left).intersection(right))


def _read_war(reader: _Reader, known_router: bool, physical_ref: int) -> tuple[int, dict[str, Any] | None]:
    status = reader.u8("war_context_status")
    if status not in (0, 1, 2):
        raise ContextWireError("invalid_war_context_status")
    if status != 1:
        return status, None
    if not known_router:
        raise ContextWireError("observed_war_requires_known_router")
    side_a_count = reader.u32("war_members.side_a_count")
    if side_a_count > MAX_WAR_MEMBERS:
        raise ContextWireError("war_side_a_count_over_bound")
    side_a = []
    for index in range(side_a_count):
        value = reader.u64(f"war_members.side_a_full_refs[{index}]")
        _valid_full_ref(value, f"war_members.side_a_full_refs[{index}]")
        side_a.append(value)
    side_b_count = reader.u32("war_members.side_b_count")
    if side_b_count > MAX_WAR_MEMBERS:
        raise ContextWireError("war_side_b_count_over_bound")
    side_b = []
    for index in range(side_b_count):
        value = reader.u64(f"war_members.side_b_full_refs[{index}]")
        _valid_full_ref(value, f"war_members.side_b_full_refs[{index}]")
        side_b.append(value)
    if _duplicates_or_overlap(side_a, side_b):
        raise ContextWireError("war_refs_duplicate_or_overlap")
    vectors_complete = _bool(reader.u8("war_members.vectors_complete"),
                             "war_members.vectors_complete")
    membership_known = _bool(
        reader.u8("war_members.physical_player_membership_known"),
        "war_members.physical_player_membership_known",
    )
    is_member = _bool(reader.u8("war_members.physical_player_is_war_member"),
                      "war_members.physical_player_is_war_member")
    if not vectors_complete or not membership_known:
        raise ContextWireError("observed_war_is_not_complete")
    expected_member = physical_ref in side_a or physical_ref in side_b
    if is_member != expected_member:
        raise ContextWireError("membership_flag_mismatch")
    return status, {
        "side_a_count": side_a_count,
        "side_a_full_refs": side_a,
        "side_b_count": side_b_count,
        "side_b_full_refs": side_b,
        "vectors_complete": vectors_complete,
        "physical_player_membership_known": membership_known,
        "physical_player_is_war_member": is_member,
    }


def decode(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode one complete version-2 frame with strict canonical checks."""

    raw = _as_bytes(data)
    reader = _Reader(raw)
    if reader.take(4, "magic") != MAGIC:
        raise ContextWireError("magic_mismatch")
    version = reader.u16("version")
    if version != VERSION:
        raise ContextWireError(f"unsupported_version:{version}")
    inner_length = reader.u32("inner_v1_length")
    if inner_length == 0 or inner_length > MAX_INNER_V1_BYTES:
        raise ContextWireError("inner_v1_length_over_bound")
    inner = reader.take(inner_length, "inner_v1")
    try:
        decoded_inner = decode_v1(inner)
    except ObservationWireError as exc:
        raise ContextWireError(f"invalid_inner_v1:{exc}") from exc
    context_present = _bool(reader.u8("context_present"), "context_present")
    if not context_present:
        if reader.remaining != 0:
            raise ContextWireError(f"trailing_bytes_without_context:{reader.remaining}")
        return {
            "schema": "information_battle_context_wire_v2",
            "wire": {
                "magic": MAGIC.decode("ascii"),
                "version": version,
                "bytes": len(raw),
                "inner_v1_length": inner_length,
                "trailing_bytes": 0,
            },
            "observation": decoded_inner["observation"],
            "context_present": False,
            "context": None,
            "complete": False,
            "business_complete": False,
            "visibility_verified": False,
            "overall_complete": False,
            "public_identity": {
                "status": "absent",
                "war_id": None,
                "battle_id": None,
            },
        }

    known_router = _bool(reader.u8("context.known_router"),
                         "context.known_router")
    inner_known_router = decoded_inner["observation"]["known_router"]
    if known_router != inner_known_router:
        raise ContextWireError("known_router_mismatch_inner")
    raw_selector = reader.u32("context.raw_selector")
    if raw_selector not in (1, 2):
        raise ContextWireError("raw_selector_not_land_or_naval")
    selector_code = reader.take(SELECTOR_CODE_LENGTH, "context.selector_code")
    if selector_code != _selector_code(raw_selector):
        raise ContextWireError("selector_code_mismatch")
    selector_verified = _bool(
        reader.u8("context.selector_code_verified"),
        "context.selector_code_verified",
    )
    if not selector_verified:
        raise ContextWireError("selector_code_not_verified")
    kind = reader.u8("context.kind")
    if kind not in (1, 2) or kind != raw_selector:
        raise ContextWireError("kind_mismatch_selector")
    physical_ref = reader.u64("context.physical_player_ref")
    _valid_full_ref(physical_ref, "context.physical_player_ref")
    sides = [_read_side(reader, index) for index in range(2)]
    war_status, war_members = _read_war(reader, known_router, physical_ref)
    if reader.remaining != 0:
        raise ContextWireError(f"trailing_bytes:{reader.remaining}")
    context = {
        "known_router": known_router,
        "raw_selector": raw_selector,
        "selector_code_hex": selector_code.hex(),
        "selector_code_verified": selector_verified,
        "kind": kind,
        "physical_player_full_ref": physical_ref,
        "sides": sides,
        "war_context_status": war_status,
        "war_members": war_members,
    }
    return {
        "schema": "information_battle_context_wire_v2",
        "wire": {
            "magic": MAGIC.decode("ascii"),
            "version": version,
            "bytes": len(raw),
            "inner_v1_length": inner_length,
            "trailing_bytes": 0,
        },
        "observation": decoded_inner["observation"],
        "context_present": True,
        "context": context,
        "complete": False,
        "business_complete": False,
        "visibility_verified": False,
        "overall_complete": False,
        "public_identity": {
            "status": "absent",
            "war_id": None,
            "battle_id": None,
        },
    }


decode_wire = decode


__all__ = [
    "ContextWireError",
    "MAGIC",
    "MAX_INNER_V1_BYTES",
    "MAX_PARTICIPANTS",
    "MAX_WAR_MEMBERS",
    "MAX_WIRE_BYTES",
    "VERSION",
    "decode",
    "decode_wire",
]
