"""Strict decoder for the version-5 IBOW war-identity extension.

Version 5 embeds one complete, unchanged version-4 template frame and appends
the value-only ``WARI`` extension.  The extension contains an observer-session
binding tuple; it never carries a native pointer and does not assign a stable
cross-save war identity.  Versions 1 through 4 are delegated to their
existing decoders so their result shapes remain byte/shape compatible.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

try:  # namespace-package import from the repository root
    from .information_battle_observation_wire import (
        ObservationWireError,
        decode as decode_v1,
    )
    from .information_battle_template_wire import (
        TemplateWireError,
        decode as decode_v4,
    )
except ImportError:  # pragma: no cover - direct script compatibility
    from information_battle_observation_wire import (  # type: ignore
        ObservationWireError,
        decode as decode_v1,
    )
    from information_battle_template_wire import (  # type: ignore
        TemplateWireError,
        decode as decode_v4,
    )


MAGIC = b"IBOW"
VERSION = 5
BASE_VERSION = 4
EXTENSION_MAGIC = b"WARI"
MAX_WIRE_BYTES = 512 * 1024
MAX_BASE_V4_BYTES = 256 * 1024
MAX_WAR_ID_BYTES = 29
WAR_ID_STORAGE_BYTES = 30
EXTENSION_HEADER_BYTES = len(EXTENSION_MAGIC)
IDENTITY_FIXED_BYTES = 1 + 1 + 4 + 8 + 4 + 8 + 8 + 1
MAX_IDENTITY_BYTES = IDENTITY_FIXED_BYTES + MAX_WAR_ID_BYTES
BINDING_FLAGS = 63
STATUS_ABSENT = 0
STATUS_BOUND = 1
STATUS_INVALID = 2


class WarIdentityWireError(ValueError):
    """The input is not one strict version-5 war-identity frame."""


@dataclass
class _Reader:
    data: bytes
    position: int = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.position

    def take(self, size: int, label: str) -> bytes:
        if size < 0 or size > self.remaining:
            raise WarIdentityWireError(f"truncated:{label}")
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
        raise WarIdentityWireError("input_must_be_bytes_like")
    try:
        raw = bytes(data)
    except (TypeError, ValueError) as exc:
        raise WarIdentityWireError("input_bytes_conversion_failed") from exc
    if len(raw) > MAX_WIRE_BYTES:
        raise WarIdentityWireError("wire_size_over_bound")
    if len(raw) < 6:
        raise WarIdentityWireError("wire_truncated_prefix")
    return raw


def _valid_full_ref(value: int) -> bool:
    if value == 0:
        return False
    for shift in (0, 8, 16):
        byte = (value >> shift) & 0xFF
        if not (0x30 <= byte <= 0x39 or 0x41 <= byte <= 0x5A):
            return False
    return True


def _inner_raw_date(base: dict[str, Any]) -> int:
    observation = base.get("observation")
    if not isinstance(observation, dict):
        raise WarIdentityWireError("base_observation_missing")
    result = observation.get("result")
    if not isinstance(result, dict) or not isinstance(result.get("raw_date"), int):
        raise WarIdentityWireError("base_raw_date_missing")
    return int(result["raw_date"])


def _ascii_id(raw: bytes) -> str:
    if len(raw) != MAX_WAR_ID_BYTES:
        raise WarIdentityWireError("bound_war_id_length_mismatch")
    if (raw[:4] != b"war_" or raw[20:21] != b"_"
            or any(byte not in b"0123456789abcdef"
                   for index, byte in enumerate(raw[4:20], start=4))
            or any(byte not in b"0123456789abcdef" for byte in raw[21:])):
        raise WarIdentityWireError("bound_war_id_shape_mismatch")
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:  # pragma: no cover - range check above
        raise WarIdentityWireError("bound_war_id_not_ascii") from exc


def _identity_result(
    *,
    status: int,
    reason: int,
    binding_flags: int,
    process_creation_filetime: int,
    raw_date: int,
    pair_full_refs: list[int],
    war_id_bytes: bytes,
    base_raw_date: int,
) -> dict[str, Any]:
    if status not in (STATUS_ABSENT, STATUS_BOUND, STATUS_INVALID):
        raise WarIdentityWireError(f"unsupported_identity_status:{status}")
    if len(pair_full_refs) != 2:
        raise WarIdentityWireError("pair_full_refs_count_mismatch")

    war_id: str | None = None
    if status == STATUS_ABSENT:
        if binding_flags != 0 or pair_full_refs != [0, 0] or war_id_bytes:
            raise WarIdentityWireError("noncanonical_absent_identity")
    elif status == STATUS_BOUND:
        if reason != 0 or binding_flags != BINDING_FLAGS:
            raise WarIdentityWireError("bound_guard_mismatch")
        if process_creation_filetime <= 0:
            raise WarIdentityWireError("bound_creation_filetime_missing")
        if raw_date != base_raw_date:
            raise WarIdentityWireError("bound_raw_date_mismatch")
        if (not _valid_full_ref(pair_full_refs[0])
                or not _valid_full_ref(pair_full_refs[1])
                or pair_full_refs[0] == pair_full_refs[1]):
            raise WarIdentityWireError("bound_pair_full_refs_invalid")
        if len(war_id_bytes) != MAX_WAR_ID_BYTES:
            raise WarIdentityWireError("bound_war_id_length_mismatch")
        war_id = _ascii_id(war_id_bytes)
    else:
        # Invalid captures deliberately do not publish an opaque ID.  The
        # numeric fields remain available for diagnostics, but an invalid
        # record cannot be mistaken for a bound session identity.
        if war_id_bytes:
            raise WarIdentityWireError("invalid_identity_id_must_be_empty")

    status_name = {
        STATUS_ABSENT: "absent",
        STATUS_BOUND: "bound",
        STATUS_INVALID: "invalid",
    }[status]
    return {
        "status": status_name,
        "reason": reason,
        "binding_flags": binding_flags,
        "process_creation_filetime": process_creation_filetime,
        "raw_date": raw_date,
        "pair_full_refs": pair_full_refs,
        "war_id": war_id,
        "identity_scope": "observer_session",
    }


def _legacy_decode(raw: bytes, version: int) -> dict[str, Any]:
    try:
        if version == 1:
            return decode_v1(raw)
        return decode_v4(raw)
    except (ObservationWireError, TemplateWireError, ValueError) as exc:
        raise WarIdentityWireError(f"invalid_legacy_wire:{exc}") from exc


def _v5_result(base: dict[str, Any], raw: bytes, base_bytes: int,
               identity: dict[str, Any], extension_bytes: int) -> dict[str, Any]:
    result = dict(base)
    base_wire = dict(base.get("wire", {}))
    base_wire.update({
        "version": VERSION,
        "bytes": len(raw),
        "base_v4_version": BASE_VERSION,
        "base_v4_bytes": base_bytes,
        "extension_magic": EXTENSION_MAGIC.decode("ascii"),
        "extension_bytes": extension_bytes,
        "trailing_bytes": 0,
    })
    result["schema"] = "information_battle_war_identity_wire_v5"
    result["wire"] = base_wire
    result["war_identity"] = identity
    return result


def decode(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode one legacy IBOW frame or a strict version-5 WARI frame."""

    raw = _as_bytes(data)
    if raw[:4] != MAGIC:
        raise WarIdentityWireError("magic_mismatch")
    version = int.from_bytes(raw[4:6], "little", signed=False)
    if version in (1, 2, 3, 4):
        return _legacy_decode(raw, version)
    if version != VERSION:
        raise WarIdentityWireError(f"unsupported_version:{version}")

    reader = _Reader(raw)
    if reader.take(4, "magic") != MAGIC:
        raise WarIdentityWireError("magic_mismatch")
    if reader.u16("version") != VERSION:
        raise WarIdentityWireError("version_mismatch")
    base_bytes = reader.u32("base_v4_bytes")
    if base_bytes == 0 or base_bytes > MAX_BASE_V4_BYTES:
        raise WarIdentityWireError("base_v4_bytes_over_bound")
    base_raw = reader.take(base_bytes, "base_v4")
    try:
        base = decode_v4(base_raw)
    except (TemplateWireError, ValueError) as exc:
        raise WarIdentityWireError(f"invalid_v4:{exc}") from exc
    if base.get("wire", {}).get("version") != BASE_VERSION:
        raise WarIdentityWireError("base_is_not_v4")
    if reader.remaining < EXTENSION_HEADER_BYTES + IDENTITY_FIXED_BYTES:
        raise WarIdentityWireError("truncated_wari_extension")
    if reader.take(EXTENSION_HEADER_BYTES, "extension_magic") != EXTENSION_MAGIC:
        raise WarIdentityWireError("extension_magic_mismatch")

    status = reader.u8("identity.status")
    reason = reader.u8("identity.reason")
    binding_flags = reader.u32("identity.binding_flags")
    process_creation_filetime = reader.u64(
        "identity.process_creation_filetime")
    raw_date = reader.i32("identity.raw_date")
    pair_full_refs = [
        reader.u64("identity.pair_full_refs[0]"),
        reader.u64("identity.pair_full_refs[1]"),
    ]
    id_length = reader.u8("identity.id_length")
    if id_length > MAX_WAR_ID_BYTES:
        raise WarIdentityWireError("war_id_length_over_bound")
    if id_length != reader.remaining:
        raise WarIdentityWireError("war_id_length_mismatch")
    war_id_bytes = reader.take(id_length, "identity.war_id")
    if reader.remaining != 0:  # defensive; the length check above is exact
        raise WarIdentityWireError("trailing_bytes_after_wari")

    identity = _identity_result(
        status=status,
        reason=reason,
        binding_flags=binding_flags,
        process_creation_filetime=process_creation_filetime,
        raw_date=raw_date,
        pair_full_refs=pair_full_refs,
        war_id_bytes=war_id_bytes,
        base_raw_date=_inner_raw_date(base),
    )
    return _v5_result(base, raw, base_bytes, identity,
                      IDENTITY_FIXED_BYTES + id_length)


decode_wire = decode

__all__ = [
    "BASE_VERSION",
    "BINDING_FLAGS",
    "EXTENSION_HEADER_BYTES",
    "EXTENSION_MAGIC",
    "IDENTITY_FIXED_BYTES",
    "MAGIC",
    "MAX_BASE_V4_BYTES",
    "MAX_IDENTITY_BYTES",
    "MAX_WAR_ID_BYTES",
    "MAX_WIRE_BYTES",
    "STATUS_ABSENT",
    "STATUS_BOUND",
    "STATUS_INVALID",
    "VERSION",
    "WarIdentityWireError",
    "decode",
    "decode_wire",
]
