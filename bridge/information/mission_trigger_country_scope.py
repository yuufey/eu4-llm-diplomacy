"""Bind a task-declared country fullref to its current country object.

This leaf reuses the existing one-slot country-reference resolver. It performs
no process management, native calls, visibility inference, or full-country scan.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from . import country_reference_memory
from . import mission_task_memory
from . import province_state_memory


SOURCE = "province_state_memory._resolve_country_reference"
_MAX_U64 = 0xFFFFFFFFFFFFFFFF
_MIN_USER_ADDRESS = province_state_memory.MIN_USER_ADDRESS
_MAX_USER_ADDRESS_EXCLUSIVE = province_state_memory.MAX_USER_ADDRESS_EXCLUSIVE
_COUNTRY_FULLREF_OFFSET = province_state_memory.COUNTRY_FULLREF_OFFSET


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _canonical_u64(value: Any) -> int | None:
    if type(value) is not str or not value.startswith("0x"):
        return None
    digits = value[2:]
    if not digits or any(char not in "0123456789abcdefABCDEF" for char in digits):
        return None
    try:
        result = int(digits, 16)
    except ValueError:
        return None
    if not 0 <= result <= _MAX_U64 or hex(result) != value:
        return None
    return result


class _ReaderAdapter:
    """Preserve the caller's tracked unaligned-read path for the resolver."""

    def __init__(self, reader: Any, module_base: int):
        self.source = reader
        self.module_base = module_base

    def read(self, address: int, size: int, label: str) -> bytes:
        return mission_task_memory._read_unaligned(
            self.source, address, size, label
        )

    def read_code(self, address: int, size: int, label: str) -> bytes:
        return mission_task_memory._read_unaligned(
            self.source, address, size, label
        )


def _validate_binding(result: Any, fullref: int) -> dict[str, Any]:
    if not isinstance(result, Mapping):
        return _unknown("COUNTRY_SCOPE_BINDING_RESULT_INVALID")
    if result.get("status") != "known":
        reason = result.get("reason")
        return _unknown(
            reason if type(reason) is str else "COUNTRY_SCOPE_BINDING_UNKNOWN"
        )

    raw = result.get("raw_inputs")
    if not isinstance(raw, Mapping):
        return _unknown("COUNTRY_SCOPE_BINDING_EVIDENCE_MISSING")
    tag = result.get("value")
    canonical_tag = country_reference_memory._tag_from_fullref(fullref)
    if (
        type(tag) is not str
        or tag != canonical_tag
        or raw.get("tag") != canonical_tag
    ):
        return _unknown("COUNTRY_SCOPE_TAG_ECHO_MISMATCH")

    slot = (fullref >> 32) & 0xFFFF
    raw_slot = raw.get("slot")
    count = raw.get("count")
    if (
        type(raw_slot) is not int
        or raw_slot != slot
        or type(count) is not int
        or not 1 <= count <= country_reference_memory.MAX_COUNTRY_SLOTS
        or slot >= count
    ):
        return _unknown("COUNTRY_SCOPE_SLOT_EVIDENCE_INVALID")

    fullref_raw_hex = fullref.to_bytes(8, "little").hex()
    if (
        _canonical_u64(raw.get("fullref")) != fullref
        or raw.get("fullref_raw_hex") != fullref_raw_hex
        or _canonical_u64(raw.get("canonical_fullref")) != fullref
        or raw.get("canonical_fullref_raw_hex") != fullref_raw_hex
    ):
        return _unknown("COUNTRY_SCOPE_FULLREF_ECHO_MISMATCH")

    pointer = _canonical_u64(raw.get("country_pointer"))
    if (
        pointer is None
        or not mission_task_memory._valid_pointer(pointer)
        or pointer > _MAX_USER_ADDRESS_EXCLUSIVE - (_COUNTRY_FULLREF_OFFSET + 8)
    ):
        return _unknown("COUNTRY_SCOPE_POINTER_INVALID")
    table = _canonical_u64(raw.get("table"))
    entry_address = _canonical_u64(raw.get("table_entry_address"))
    entry_raw_hex = raw.get("table_entry_raw_hex")
    try:
        entry_raw = bytes.fromhex(entry_raw_hex) if type(entry_raw_hex) is str else b""
    except ValueError:
        entry_raw = b""
    if (
        table is None
        or entry_address != table + slot * 8
        or len(entry_raw) != 8
        or int.from_bytes(entry_raw, "little") != pointer
    ):
        return _unknown("COUNTRY_SCOPE_POINTER_ECHO_MISMATCH")
    if _canonical_u64(raw.get("canonical_fullref_address")) != (
        pointer + _COUNTRY_FULLREF_OFFSET
    ):
        return _unknown("COUNTRY_SCOPE_CANONICAL_ADDRESS_MISMATCH")

    return {
        "status": "known",
        "tag": tag,
        "pointer": pointer,
        "fullref": fullref,
    }


def bind_country_scope(
    reader: Any, module_base: int, fullref_int: int
) -> dict[str, Any]:
    """Resolve one task-declared fullref through its encoded country slot."""
    if type(fullref_int) is not int or not 0 <= fullref_int <= _MAX_U64:
        return _unknown("COUNTRY_SCOPE_FULLREF_INVALID")
    if (
        type(module_base) is not int
        or not province_state_memory._is_user_address(module_base)
    ):
        return _unknown("COUNTRY_SCOPE_MODULE_BASE_INVALID")

    adapted = _ReaderAdapter(reader, module_base)
    limiter = province_state_memory._shared._BoundedReader(adapted)
    try:
        resolved = province_state_memory._resolve_country_reference(
            limiter,
            module_base,
            fullref_int.to_bytes(8, "little"),
            "mission_country_scope",
        )
    except Exception as exc:
        return _unknown(f"COUNTRY_SCOPE_RESOLVER_FAILED:{type(exc).__name__}")
    return _validate_binding(resolved, fullref_int)


__all__ = ["SOURCE", "bind_country_scope"]
