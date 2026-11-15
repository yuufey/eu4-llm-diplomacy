"""Bounded read of the current HRE passed-reform string table.

The emperor/elector record is still parsed by :mod:`empire_memory`.  This
module adds a separately-failable reforms field and deliberately does not read
the nearby influence/flag fields or invoke native code.  The String32 reader
uses the bounded NUL-terminated serialization path; it does not trust the
object's unverified length member.
"""
from __future__ import annotations

import re
from typing import Any

from . import empire_memory as _base


SCHEMA = "information.empire_reforms_memory.v2"
OBSERVER = _base.OBSERVER
REFORMS_TABLE_OFFSET = 0x28
REFORMS_COUNT_OFFSET = 0x34
STRING_DATA_OFFSET = 0x10
STRING_CAPACITY_OFFSET = 0x28
MAX_REFORMS = 4096
MAX_REFORM_ID_BYTES = 128
MAX_STRING_CAPACITY = 1 << 20
MAX_REFORM_READ_BYTES_PER_PASS = 128 * 1024
MAX_REFORM_READ_CALLS_PER_PASS = 8000
_IDENTIFIER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}\Z")


class EmpireReformsMemoryError(ValueError):
    """A reform table or String32 candidate could not be read safely."""


class _ReformBudget:
    """Field-local limits which leave room for the two established base reads."""

    def __init__(self, reader):
        self.reader = reader
        self.calls = 0
        self.bytes = 0
        self.max_single = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        if (type(address) is not int or type(size) is not int or size <= 0
                or size > _base.MAX_SINGLE_READ or address < 0x10000
                or address + size - 1 >= 0x800000000000):
            raise EmpireReformsMemoryError("EMPIRE_REFORMS_READ_RANGE_INVALID")
        if (self.calls + 1 > MAX_REFORM_READ_CALLS_PER_PASS
                or self.bytes + size > MAX_REFORM_READ_BYTES_PER_PASS):
            raise EmpireReformsMemoryError("EMPIRE_REFORMS_BUDGET_EXCEEDED")
        self.calls += 1
        self.bytes += size
        self.max_single = max(self.max_single, size)
        raw = self.reader.read(address, size, label)
        if not isinstance(raw, (bytes, bytearray, memoryview)) or len(raw) != size:
            raise EmpireReformsMemoryError("EMPIRE_REFORMS_SHORT_READ")
        return bytes(raw)


def _qword(reader, address: int, label: str) -> tuple[int, bytes]:
    raw = reader.read(address, 8, label)
    return int.from_bytes(raw, "little", signed=False), raw


def _pointer(value: Any, label: str) -> int:
    try:
        return _base._pointer(value, label)
    except _base.EmpireMemoryError as exc:
        raise EmpireReformsMemoryError(f"EMPIRE_REFORMS_POINTER_INVALID:{label}") from exc


def _read_string32(reader, object_pointer: int, phase: str, index: int) -> dict[str, Any]:
    _pointer(object_pointer, f"reform_string_object_{index}")
    capacity, capacity_raw = _qword(
        reader, object_pointer + STRING_CAPACITY_OFFSET,
        f"empire.{phase}.reforms[{index}].capacity")
    if capacity > MAX_STRING_CAPACITY:
        raise EmpireReformsMemoryError("EMPIRE_REFORMS_STRING_CAPACITY_OUT_OF_RANGE")

    if capacity < 16:
        storage = "inline"
        data_pointer = object_pointer + STRING_DATA_OFFSET
        data_pointer_raw = None
        requested = min(16, capacity + 1)
    else:
        storage = "heap"
        data_pointer, data_pointer_raw_bytes = _qword(
            reader, object_pointer + STRING_DATA_OFFSET,
            f"empire.{phase}.reforms[{index}].data_pointer")
        if (type(data_pointer) is not int or not 0x10000 <= data_pointer < 0x800000000000):
            raise EmpireReformsMemoryError("EMPIRE_REFORMS_STRING_DATA_POINTER_INVALID")
        data_pointer_raw = data_pointer_raw_bytes.hex()
        requested = min(capacity + 1, MAX_REFORM_ID_BYTES + 1)

    if requested <= 0 or data_pointer + requested - 1 >= 0x800000000000:
        raise EmpireReformsMemoryError("EMPIRE_REFORMS_STRING_RANGE_INVALID")

    # Probe in small, bounded pieces. Most identifiers terminate in the first
    # block; a long ID is read only as far as its first NUL or the 128-byte cap.
    collected = bytearray()
    chunk_size = 16
    while len(collected) < requested:
        width = min(chunk_size, requested - len(collected))
        chunk = reader.read(
            data_pointer + len(collected), width,
            f"empire.{phase}.reforms[{index}].string[{len(collected)}:{len(collected)+width}]",
        )
        collected.extend(chunk)
        terminator = collected.find(0)
        if terminator >= 0:
            raw_id = bytes(collected[:terminator])
            if not raw_id or terminator > MAX_REFORM_ID_BYTES or terminator > capacity:
                raise EmpireReformsMemoryError("EMPIRE_REFORMS_STRING_LENGTH_INVALID")
            try:
                value = raw_id.decode("ascii", errors="strict")
            except UnicodeDecodeError as exc:
                raise EmpireReformsMemoryError("EMPIRE_REFORMS_STRING_NOT_ASCII") from exc
            if _IDENTIFIER.fullmatch(value) is None:
                raise EmpireReformsMemoryError("EMPIRE_REFORMS_ID_INVALID")
            return {
                "value": value,
                "storage": storage,
                "object_pointer": hex(object_pointer),
                "capacity_raw_hex": capacity_raw.hex(),
                "data_pointer_raw_hex": data_pointer_raw,
                "data_pointer": hex(data_pointer),
                "string_bytes_raw_hex": bytes(collected).hex(),
                "nul_terminated": True,
            }
    raise EmpireReformsMemoryError("EMPIRE_REFORMS_STRING_NUL_NOT_FOUND")


def _safe_reason(exc: Exception) -> str:
    if isinstance(exc, EmpireReformsMemoryError):
        return str(exc)[:128]
    if isinstance(exc, _base.EmpireMemoryError):
        return "EMPIRE_REFORMS_BASE_READ_LIMIT"
    # Actual read errors remain in the caller's ordered raw trace. Do not
    # expose arbitrary exception text (which can include process addresses).
    return "EMPIRE_REFORMS_READ_FAILED"


def _read_reforms(reader, hre_address: int, phase: str) -> dict[str, Any]:
    bounded = _ReformBudget(reader)
    table_raw = None
    count_raw = None
    try:
        table_pointer, table_raw = _qword(
            bounded, hre_address + REFORMS_TABLE_OFFSET,
            f"empire.{phase}.reforms.table_pointer")
        count_raw = bounded.read(
            hre_address + REFORMS_COUNT_OFFSET, 4,
            f"empire.{phase}.reforms.count")
        count = int.from_bytes(count_raw, "little", signed=True)
        if count < 0 or count > MAX_REFORMS:
            raise EmpireReformsMemoryError("EMPIRE_REFORMS_COUNT_OUT_OF_RANGE")
        if table_pointer != 0:
            _pointer(table_pointer, "reforms_table")
        if count > 0 and table_pointer == 0:
            raise EmpireReformsMemoryError("EMPIRE_REFORMS_TABLE_COUNT_MISMATCH")

        entries: list[dict[str, Any]] = []
        values: list[str] = []
        seen: set[str] = set()
        for index in range(count):
            slot_address = table_pointer + index * 8
            if slot_address < table_pointer or slot_address + 7 >= 0x800000000000:
                raise EmpireReformsMemoryError("EMPIRE_REFORMS_TABLE_RANGE_INVALID")
            object_pointer, slot_raw = _qword(
                bounded, slot_address,
                f"empire.{phase}.reforms[{index}].object_pointer")
            _pointer(object_pointer, f"reform_object_{index}")
            parsed = _read_string32(bounded, object_pointer, phase, index)
            value = parsed["value"]
            if value in seen:
                raise EmpireReformsMemoryError("EMPIRE_REFORMS_DUPLICATE_ID")
            seen.add(value)
            values.append(value)
            entries.append({"index": index, "slot_raw_hex": slot_raw.hex(), **parsed})

        return {
            "status": "known",
            "value": values,
            "count": count,
            "table_pointer_raw_hex": table_raw.hex(),
            "count_raw_hex": count_raw.hex(),
            "entries": entries,
            "basis": "bounded_nul_terminated_hre_passed_reform_string_table",
            "length_member_read": False,
            "read_budget": {
                "calls": bounded.calls,
                "bytes_requested": bounded.bytes,
                "max_single_read": bounded.max_single,
                "limits": {
                    "max_calls": MAX_REFORM_READ_CALLS_PER_PASS,
                    "max_bytes": MAX_REFORM_READ_BYTES_PER_PASS,
                    "max_single_read": _base.MAX_SINGLE_READ,
                    "max_count": MAX_REFORMS,
                    "max_id_bytes": MAX_REFORM_ID_BYTES,
                },
            },
        }
    except Exception as exc:
        result: dict[str, Any] = {
            "status": "unknown",
            "reason": _safe_reason(exc),
            "basis": "bounded_nul_terminated_hre_passed_reform_string_table",
            "length_member_read": False,
            "read_budget": {
                "calls": bounded.calls,
                "bytes_requested": bounded.bytes,
                "max_single_read": bounded.max_single,
                "limits": {
                    "max_calls": MAX_REFORM_READ_CALLS_PER_PASS,
                    "max_bytes": MAX_REFORM_READ_BYTES_PER_PASS,
                    "max_single_read": _base.MAX_SINGLE_READ,
                    "max_count": MAX_REFORMS,
                    "max_id_bytes": MAX_REFORM_ID_BYTES,
                },
            },
        }
        if table_raw is not None:
            result["table_pointer_raw_hex"] = table_raw.hex()
        if count_raw is not None:
            result["count_raw_hex"] = count_raw.hex()
        return result


def _read_pass(reader, module_base: int, observer: str, phase: str) -> dict[str, Any]:
    state = _base._read_state(reader, module_base, observer, phase)
    reforms = _read_reforms(reader, int(state["hre_address"], 16), phase)
    return {**state, "schema": SCHEMA, "reforms": reforms}


def read_state(reader, module_base: int, observer: str = OBSERVER) -> dict[str, Any]:
    """Read legacy HRE fields plus the independently-failable reforms field."""
    bounded = _base._BudgetReader(reader)
    state = _read_pass(bounded, module_base, observer, "single")
    state["read_budget"] = {
        "calls": bounded.calls,
        "bytes_requested": bounded.bytes,
        "max_single_read": bounded.max_single,
        "limits": {"max_calls": _base.MAX_READ_CALLS,
                   "max_bytes": _base.MAX_READ_BYTES,
                   "max_single_read": _base.MAX_SINGLE_READ},
    }
    state["atomic_snapshot"] = False
    state["visibility_evaluated"] = False
    return state


__all__ = ["read_state", "EmpireReformsMemoryError", "SCHEMA"]
