"""Private bounded predicate for an ordinary country's knowledge of a target.

This leaf resolves exactly one target capital record. It does not enumerate
foreign provinces, read owner/controller fields, or make the result public.
The parent remains responsible for binding the observer and both country
references to its two-pass capture.
"""
from __future__ import annotations

import re
from typing import Any

from . import country_reference_memory as _country
from . import province_discovery_bitmap_memory as _bitmap
from . import province_reference_memory as _province


SCHEMA = "information.country_knowledge_memory.v1"
OBSERVER_TAG = "FRA"
TARGET_CAPITAL_OFFSET = 0x14B0
CAPITAL_RECORD_ID_OFFSET = 0x20
CAPITAL_KNOWLEDGE_FLAGS_OFFSET = 0x959
CAPITAL_KNOWLEDGE_BIT = 0x10
COUNTRY_REFERENCE_OFFSET = 0x20
MAX_COUNTRY_SLOTS = 4096
MAX_READ_CALLS = 8
MAX_TOTAL_READ_BYTES = 64
MAX_SINGLE_READ_BYTES = 24
_HEX = re.compile(r"^(?:0x)?[0-9a-fA-F]+$")
_HEX16 = re.compile(r"^[0-9a-fA-F]{16}$")


class _Unknown(ValueError):
    pass


class _BudgetReader:
    """Small leaf budget around the parent trace; every read remains visible."""

    def __init__(self, source: Any) -> None:
        self.source = source
        self.calls = 0
        self.bytes_requested = 0
        self.max_single_read = 0
        self.reads: list[dict[str, Any]] = []

    def read(self, address: int, size: int, label: str) -> bytes:
        if (type(address) is not int or not _province._is_user_address(address)
                or type(size) is not int or not 0 < size <= MAX_SINGLE_READ_BYTES
                or address > _province.MAX_USER_ADDRESS_EXCLUSIVE - size):
            raise _Unknown("READ_ADDRESS_OR_SIZE_INVALID")
        if self.calls >= MAX_READ_CALLS:
            raise _Unknown("READ_CALL_BUDGET_EXCEEDED")
        if self.bytes_requested + size > MAX_TOTAL_READ_BYTES:
            raise _Unknown("READ_BYTE_BUDGET_EXCEEDED")
        self.calls += 1
        self.bytes_requested += size
        self.max_single_read = max(self.max_single_read, size)
        method = getattr(self.source, "read", None)
        try:
            raw = method(address, size, label) if callable(method) else self.source(address, size, label)
        except Exception as exc:
            self.reads.append({"address": hex(address), "size": size, "label": label,
                               "status": "failed", "error_type": type(exc).__name__})
            raise _Unknown(f"READ_FAILED:{label}") from exc
        if not isinstance(raw, (bytes, bytearray, memoryview)) or len(raw) != size:
            self.reads.append({"address": hex(address), "size": size, "label": label,
                               "status": "failed", "error_type": "short_or_invalid_read"})
            raise _Unknown(f"READ_SHORT_OR_INVALID:{label}")
        result = bytes(raw)
        self.reads.append({"address": hex(address), "size": size, "label": label,
                           "status": "ok", "raw_hex": result.hex()})
        return result

    def summary(self) -> dict[str, Any]:
        return {"calls": self.calls, "bytes_requested": self.bytes_requested,
                "max_single_read": self.max_single_read,
                "limits": {"calls": MAX_READ_CALLS, "bytes": MAX_TOTAL_READ_BYTES,
                           "single_read_bytes": MAX_SINGLE_READ_BYTES}}


def _parse_hex(value: Any, reason: str) -> int:
    if type(value) is not str or not _HEX.fullmatch(value):
        raise _Unknown(reason)
    try:
        parsed = int(value, 16)
    except ValueError as exc:
        raise _Unknown(reason) from exc
    if not 0 <= parsed <= _province.MAX_U64:
        raise _Unknown(reason)
    return parsed


def _validated_binding(binding: Any, role: str, *, observer_tag=OBSERVER_TAG) -> dict[str, Any]:
    if not isinstance(binding, dict):
        raise _Unknown(f"{role.upper()}_BINDING_INVALID")
    tag = binding.get("tag")
    if (type(tag) is not str or len(tag) != 3
            or not all("A" <= char <= "Z" or "0" <= char <= "9" for char in tag)):
        raise _Unknown(f"{role.upper()}_TAG_INVALID")
    if role == "observer" and tag != observer_tag:
        raise _Unknown("OBSERVER_MUST_BE_FRA" if observer_tag == OBSERVER_TAG else "OBSERVER_BINDING_MISMATCH")
    slot = binding.get("slot")
    if type(slot) is not int or not 0 <= slot < MAX_COUNTRY_SLOTS:
        raise _Unknown(f"{role.upper()}_SLOT_INVALID")
    pointer = _parse_hex(binding.get("country_pointer"), f"{role.upper()}_POINTER_INVALID")
    if not _province._is_user_address(pointer) or pointer & 7:
        raise _Unknown(f"{role.upper()}_POINTER_INVALID")
    fullref = _parse_hex(binding.get("fullref"), f"{role.upper()}_FULLREF_INVALID")
    raw_hex = binding.get("fullref_raw_hex")
    if type(raw_hex) is not str or not _HEX16.fullmatch(raw_hex):
        raise _Unknown(f"{role.upper()}_FULLREF_RAW_INVALID")
    raw = bytes.fromhex(raw_hex)
    if int.from_bytes(raw, "little", signed=False) != fullref:
        raise _Unknown(f"{role.upper()}_FULLREF_RAW_MISMATCH")
    if (fullref >> 56) & 0xFF == 0:
        raise _Unknown(f"{role.upper()}_FULLREF_HIGH_BYTE_ZERO")
    if (fullref >> 48) & 0xFF == 7:
        raise _Unknown(f"{role.upper()}_FULLREF_KIND_UNSUPPORTED")
    fullref_slot = (fullref >> 32) & 0xFFFF
    if fullref_slot != slot:
        raise _Unknown(f"{role.upper()}_FULLREF_SLOT_MISMATCH")
    if _country._tag_from_fullref(fullref) != tag:
        raise _Unknown(f"{role.upper()}_FULLREF_TAG_MISMATCH")
    return {"tag": tag, "slot": slot, "country_pointer": pointer,
            "fullref": fullref, "fullref_raw_hex": raw_hex.lower()}


def _validated_province_header(header: Any) -> dict[str, Any]:
    if not isinstance(header, dict):
        raise _Unknown("PROVINCE_HEADER_INVALID")
    records = _parse_hex(header.get("records_pointer"), "PROVINCE_RECORDS_POINTER_INVALID")
    if not _province._is_user_address(records) or records & 7:
        raise _Unknown("PROVINCE_RECORDS_POINTER_INVALID")
    count = header.get("count")
    if type(count) is not int or not 1 <= count <= _province.MAX_PROVINCE_COUNT:
        raise _Unknown("PROVINCE_COUNT_INVALID")
    supplied_range = header.get("records_range")
    if (not isinstance(supplied_range, list) or len(supplied_range) != 2):
        raise _Unknown("PROVINCE_RECORDS_RANGE_INVALID")
    range_start = _parse_hex(supplied_range[0], "PROVINCE_RECORDS_RANGE_INVALID")
    range_end = _parse_hex(supplied_range[1], "PROVINCE_RECORDS_RANGE_INVALID")
    try:
        checked_start, checked_end = _province._checked_range(
            records, count * _province.RECORD_STRIDE, "country_knowledge_province_records")
    except Exception as exc:
        raise _Unknown("PROVINCE_RECORDS_RANGE_OVERFLOW") from exc
    if range_start != checked_start or range_end != checked_end:
        raise _Unknown("PROVINCE_RECORDS_RANGE_MISMATCH")
    return {"records_pointer": records, "count": count,
            "records_range": (checked_start, checked_end)}


def _unknown(reason: str, raw_inputs: dict[str, Any], budget: _BudgetReader) -> dict[str, Any]:
    raw_inputs["ordered_read_trace"] = list(budget.reads)
    return {"schema": SCHEMA, "status": "unknown", "reason": reason,
            "basis": "native_target_capital_knowledge_predicate",
            "raw_inputs": raw_inputs, "read_budget": budget.summary()}


def read_knowledge(reader: Any, module_base: int, observer_binding: Any,
                   target_binding: Any, province_header: Any, *, observer_tag=OBSERVER_TAG) -> dict[str, Any]:
    """Read the target capital's native knowledge predicate for the observer slot.

    The first native read is target country ``+0x14b0``. A pointer that does
    not identify an exact indexed province record is unknown. If the capital's
    local ``+0x959 & 0x10`` shortcut is clear the predicate is true; otherwise
    the existing length-bounded discovery bitmap reader supplies the result.
    """
    budget = _BudgetReader(reader)
    raw_inputs: dict[str, Any] = {}
    try:
        if (type(module_base) is not int or not _province._is_user_address(module_base)
                or module_base & 7):
            raise _Unknown("MODULE_BASE_INVALID")
        observer = _validated_binding(observer_binding, "observer", observer_tag=observer_tag)
        target = _validated_binding(target_binding, "target")
        if not callable(getattr(reader, "read", None)) and not callable(reader):
            raise _Unknown("READER_INVALID")
        header = _validated_province_header(province_header)
        raw_inputs.update({
            "module_base": hex(module_base),
            "observer_binding": {"tag": observer["tag"], "slot": observer["slot"],
                                 "country_pointer": hex(observer["country_pointer"]),
                                 "fullref": hex(observer["fullref"]),
                                 "fullref_raw_hex": observer["fullref_raw_hex"]},
            "target_binding": {"tag": target["tag"], "slot": target["slot"],
                                "country_pointer": hex(target["country_pointer"]),
                                "fullref": hex(target["fullref"]),
                                "fullref_raw_hex": target["fullref_raw_hex"]},
            "province_header": {"records_pointer": hex(header["records_pointer"]),
                                "count": header["count"],
                                "records_range": [hex(header["records_range"][0]),
                                                  hex(header["records_range"][1])]},
        })

        target_cell = _province._checked_add(
            target["country_pointer"], TARGET_CAPITAL_OFFSET, "target_capital_pointer")
        target_cell_range = _province._checked_range(target_cell, 8, "target_capital_pointer")
        if target_cell_range[0] == target["country_pointer"] + COUNTRY_REFERENCE_OFFSET:
            raise _Unknown("TARGET_CAPITAL_CELL_ALIASES_FULLREF")
        capital_raw = budget.read(target_cell, 8, "country_knowledge.target.capital_pointer")
        capital = int.from_bytes(capital_raw, "little", signed=False)
        raw_inputs.update({"target_capital_pointer_address": hex(target_cell),
                           "target_capital_pointer_raw_hex": capital_raw.hex(),
                           "target_capital_pointer": hex(capital)})
        if not _province._is_user_address(capital) or capital & 7:
            raise _Unknown("TARGET_CAPITAL_POINTER_INVALID")

        records_start, records_end = header["records_range"]
        delta = capital - records_start
        if delta < 0 or delta % _province.RECORD_STRIDE:
            raise _Unknown("TARGET_CAPITAL_NOT_INDEXED_RECORD_START")
        province_index = delta // _province.RECORD_STRIDE
        if not 0 <= province_index < header["count"]:
            raise _Unknown("TARGET_CAPITAL_OUTSIDE_PROVINCE_INDEX")
        record_start, record_end = _province._checked_range(
            capital, _province.RECORD_STRIDE, "target_capital_record")
        if record_start < records_start or record_end > records_end:
            raise _Unknown("TARGET_CAPITAL_RECORD_OUTSIDE_INDEX")

        id_address = _province._checked_add(capital, CAPITAL_RECORD_ID_OFFSET,
                                            "target_capital_record_id")
        id_raw = budget.read(id_address, 4, "country_knowledge.capital.record_id")
        record_id = int.from_bytes(id_raw, "little", signed=True)
        raw_inputs.update({"capital_record_index": province_index,
                           "capital_record_id_address": hex(id_address),
                           "capital_record_id_raw_hex": id_raw.hex(),
                           "capital_record_id_i32": record_id})
        if record_id != province_index:
            raise _Unknown("TARGET_CAPITAL_RECORD_ID_MISMATCH")

        flags_address = _province._checked_add(capital, CAPITAL_KNOWLEDGE_FLAGS_OFFSET,
                                               "target_capital_knowledge_flags")
        flags_raw = budget.read(flags_address, 1, "country_knowledge.capital.flags")
        flags = flags_raw[0]
        flag_set = bool(flags & CAPITAL_KNOWLEDGE_BIT)
        raw_inputs.update({"capital_flags_address": hex(flags_address),
                           "capital_flags_raw_hex": flags_raw.hex(),
                           "capital_flags_u8": flags,
                           "capital_knowledge_flag_set": flag_set})

        if not flag_set:
            value = True
            raw_inputs["bitmap"] = {"status": "not_read", "reason": "CAPITAL_SHORTCUT"}
        else:
            bitmap_result = _bitmap.read_discovery(
                budget, capital, observer["slot"], module_base)
            raw_inputs["bitmap"] = bitmap_result.get("raw_inputs", {})
            if bitmap_result.get("status") != "known" or type(bitmap_result.get("value")) is not bool:
                reason = bitmap_result.get("reason", "TARGET_CAPITAL_BITMAP_UNKNOWN")
                return _unknown(str(reason)[:160], raw_inputs, budget)
            value = bitmap_result["value"]

        raw_inputs["ordered_read_trace"] = list(budget.reads)
        return {"schema": SCHEMA, "status": "known", "value": value,
                "basis": "native_target_capital_knowledge_predicate",
                "raw_inputs": raw_inputs, "read_budget": budget.summary()}
    except _Unknown as exc:
        return _unknown(str(exc)[:160], raw_inputs, budget)
    except Exception as exc:
        return _unknown(f"READ_OR_LAYOUT_INVALID:{type(exc).__name__}", raw_inputs, budget)


__all__ = ["SCHEMA", "read_knowledge"]
