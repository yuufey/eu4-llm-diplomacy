"""Bounded reader for a selected country's primary religion-group display name.

This leaf copies one String32 from the already bound country's primary
religion and its group object. The text is a display name, not a religion or
group configuration key. Process identity, admission, and two-pass owner
stability remain with the caller.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..native_text import EU4_ESCAPE_CODEC, NativeTextError, decode_native_text_hex
from . import country_faith_memory as _faith
from . import country_reference_memory as _country_reference


FIELD_ID = "S02.religion_group"
COUNTRY_RELIGION_POINTER_OFFSET = 0xF30
RELIGION_GROUP_POINTER_OFFSET = 0xD8
GROUP_NAME_OFFSET = 0x38
STRING32_SIZE = 32
STRING32_LENGTH_OFFSET = 0x10
STRING32_CAPACITY_OFFSET = 0x18
MAX_NAME_BYTES = 128
MAX_STRING_CAPACITY = 8192
MAX_READ_BYTES = 4096
MAX_READ_CALLS = 32
MIN_USER_ADDRESS = 0x10000
MAX_USER_ADDRESS = 0x00007FFFFFFFFFFF

_BASIS = "bounded_primary_religion_group_display_name_string32"
_GAPS = [
    "RELIGION_GROUP_CONFIGURATION_KEY_NOT_READ",
    "TOOLTIP_NOT_READ",
    "CALLER_ADMISSION_IS_PARENT_OWNED",
]


def _unknown(reason: str, raw_inputs: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "status": "unknown",
        "complete": False,
        "reason": reason,
        "raw_inputs": raw_inputs if raw_inputs is not None else {},
        "basis": _BASIS,
        "gaps": list(_GAPS),
    }


def _budget_error(exc: BaseException) -> bool:
    message = str(exc)
    return ("read_budget_exceeded" in message
            or "read_call_budget_exceeded" in message)


def _checked_add(address: int, offset: int, size: int, label: str) -> int:
    if (type(address) is not int or type(offset) is not int or type(size) is not int
            or address < MIN_USER_ADDRESS or address > MAX_USER_ADDRESS
            or offset < 0 or size < 1 or offset > MAX_USER_ADDRESS - address):
        raise ValueError(f"address_range_invalid:{label}")
    result = address + offset
    if result < MIN_USER_ADDRESS or result > MAX_USER_ADDRESS - (size - 1):
        raise ValueError(f"address_range_invalid:{label}")
    return result


def _parse_bound_address(value: Any, label: str) -> int:
    parsed = _faith._parse_uint(value, label)
    return _faith._user_pointer(parsed, label, aligned=True)


class _LeafLimiter:
    """Add a small per-leaf byte/call cap and private read trace."""

    def __init__(self, reader: Any, raw_inputs: dict[str, Any]):
        self.reader = reader
        self.raw_inputs = raw_inputs
        self.calls = 0
        self.bytes_requested = 0

    def __call__(self, address: int, size: int, label: str) -> bytes:
        return self.read(address, size, label)

    def read(self, address: int, size: int, label: str) -> bytes:
        trace: dict[str, Any] = {
            "ordinal": self.calls + 1,
            "address": hex(address) if type(address) is int else None,
            "size": size,
            "label": label,
            "status": "requested",
        }
        self.raw_inputs["reads"].append(trace)
        if (type(address) is not int or type(size) is not int or size < 1
                or size > MAX_READ_BYTES or self.calls >= MAX_READ_CALLS
                or self.bytes_requested + size > MAX_READ_BYTES):
            trace.update({"status": "rejected", "reason": "leaf_read_budget_exceeded"})
            raise ValueError("religion_group_leaf_read_budget_exceeded")
        self.calls += 1
        self.bytes_requested += size
        try:
            method = getattr(self.reader, "read", None)
            if callable(method):
                result = method(address, size, label)
            elif callable(self.reader):
                result = self.reader(address, size, label)
            else:
                raise TypeError("reader_not_callable_or_readable")
        except Exception as exc:
            trace.update({"status": "failed", "error_type": type(exc).__name__,
                          "error": str(exc)[:160]})
            if _budget_error(exc):
                raise
            raise
        if not isinstance(result, (bytes, bytearray, memoryview)):
            trace.update({"status": "failed", "error_type": "invalid_read_result"})
            raise ValueError("reader_read_result_invalid")
        data = bytes(result)
        if len(data) != size:
            trace.update({"status": "failed", "error_type": "short_read",
                          "returned": len(data)})
            raise ValueError(f"short_read:{label}:{len(data)}:{size}")
        trace.update({"status": "ok", "raw_hex": data.hex()})
        self.raw_inputs["budget"] = {
            "calls": self.calls,
            "bytes_requested": self.bytes_requested,
            "max_calls": MAX_READ_CALLS,
            "max_bytes": MAX_READ_BYTES,
        }
        return data


def _read_at(reader: _LeafLimiter, address: int, size: int, label: str) -> bytes:
    return _faith._read_exact(reader, address, size, label)


def _read_group(reader: _LeafLimiter, base: int, target_binding: Any,
                raw_inputs: dict[str, Any]) -> dict[str, Any]:
    try:
        if type(base) is not int:
            raise ValueError("module_base_invalid")
        module_base = _faith._user_pointer(base, "module_base")
        country_pointer, retained = _faith._binding(target_binding)
        if type(country_pointer) is not int:
            raise ValueError("country_pointer_invalid")
        expected_table_raw = country_pointer.to_bytes(8, "little").hex()
        table_address = _parse_bound_address(
            retained.get("table_entry_address"), "table_entry_address")
        table_raw = retained.get("table_entry_raw_hex")
        if not isinstance(table_raw, str) or table_raw != expected_table_raw:
            raise ValueError("table_entry_raw_mismatch")

        fullref_address = _checked_add(
            country_pointer, _country_reference.COUNTRY_FULLREF_OFFSET, 8,
            "country_fullref")
        supplied_fullref_address = _parse_bound_address(
            retained.get("country_fullref_address"), "country_fullref_address")
        if supplied_fullref_address != fullref_address:
            raise ValueError("country_fullref_address_mismatch")

        fullref_value = int(retained["fullref"], 16)
        fullref_raw = bytes.fromhex(retained["fullref_raw_hex"])
        if len(fullref_raw) != 8 or fullref_raw != fullref_value.to_bytes(8, "little"):
            raise ValueError("country_fullref_raw_invalid")

        raw_inputs.update({
            "module_base": hex(module_base),
            "country_binding": retained,
            "country_pointer": hex(country_pointer),
            "country_fullref_address": hex(fullref_address),
            "table_entry_address": hex(table_address),
            "expected_country_fullref_raw_hex": fullref_raw.hex(),
            "expected_table_entry_raw_hex": expected_table_raw,
        })

        # Verify the bound row immediately before following any leaf pointer.
        table_before = _read_at(reader, table_address, 8,
                                "religion_group.country_table_entry_before")
        fullref_before = _read_at(reader, fullref_address, 8,
                                  "religion_group.country_fullref_before")
        raw_inputs["country_table_entry_before_raw_hex"] = table_before.hex()
        raw_inputs["country_fullref_before_raw_hex"] = fullref_before.hex()
        if table_before.hex() != expected_table_raw:
            return _unknown("country_table_entry_changed_before_read", raw_inputs)
        if fullref_before != fullref_raw:
            return _unknown("country_fullref_changed_before_read", raw_inputs)

        religion_pointer_address = _checked_add(
            country_pointer, COUNTRY_RELIGION_POINTER_OFFSET, 8,
            "primary_religion_pointer")
        religion_raw = _read_at(reader, religion_pointer_address, 8,
                                "religion_group.primary_religion_pointer_before")
        religion_pointer = int.from_bytes(religion_raw, "little")
        raw_inputs["primary_religion_pointer_address"] = hex(religion_pointer_address)
        raw_inputs["primary_religion_pointer_before_raw_hex"] = religion_raw.hex()
        raw_inputs["primary_religion_pointer"] = hex(religion_pointer) if religion_pointer else None
        if religion_pointer == 0:
            return _unknown("primary_religion_pointer_null", raw_inputs)
        _faith._user_pointer(religion_pointer, "primary_religion_pointer", aligned=True)

        group_pointer_address = _checked_add(
            religion_pointer, RELIGION_GROUP_POINTER_OFFSET, 8,
            "religion_group_pointer")
        group_raw = _read_at(reader, group_pointer_address, 8,
                              "religion_group.group_pointer_before")
        group_pointer = int.from_bytes(group_raw, "little")
        raw_inputs["religion_group_pointer_address"] = hex(group_pointer_address)
        raw_inputs["religion_group_pointer_before_raw_hex"] = group_raw.hex()
        raw_inputs["religion_group_pointer"] = hex(group_pointer) if group_pointer else None
        if group_pointer == 0:
            return _unknown("religion_group_pointer_null", raw_inputs)
        _faith._user_pointer(group_pointer, "religion_group_pointer", aligned=True)

        header_address = _checked_add(group_pointer, GROUP_NAME_OFFSET, STRING32_SIZE,
                                      "religion_group_string32_header")
        raw_inputs["string32_address"] = hex(header_address)
        header_before = _read_at(reader, header_address, STRING32_SIZE,
                                 "religion_group.String32_header_before")
        length = int.from_bytes(header_before[STRING32_LENGTH_OFFSET:0x18], "little")
        capacity = int.from_bytes(header_before[STRING32_CAPACITY_OFFSET:0x20], "little")
        storage = "inline" if capacity < 16 else "heap"
        raw_inputs.update({
            "string32_header_before_raw_hex": header_before.hex(),
            "string32_length_raw_hex": header_before[0x10:0x18].hex(),
            "string32_capacity_raw_hex": header_before[0x18:0x20].hex(),
            "string32_length": length,
            "string32_capacity": capacity,
            "string32_storage": storage,
        })
        if length == 0:
            return _unknown("religion_group_name_empty", raw_inputs)
        if length > MAX_NAME_BYTES:
            return _unknown("religion_group_name_length_out_of_bound", raw_inputs)
        if capacity < length:
            return _unknown("religion_group_string32_capacity_below_length", raw_inputs)
        if capacity > MAX_STRING_CAPACITY:
            return _unknown("religion_group_string32_capacity_out_of_bound", raw_inputs)
        if capacity < 16 and length > 15:
            return _unknown("religion_group_string32_inline_length_invalid", raw_inputs)

        heap_pointer: int | None = None
        if storage == "inline":
            payload_before = header_before[:length + 1]
            raw_inputs["string32_inline_bytes_raw_hex"] = payload_before.hex()
        else:
            heap_pointer_raw = header_before[:8]
            heap_pointer = int.from_bytes(heap_pointer_raw, "little")
            raw_inputs["string32_heap_pointer_raw_hex"] = heap_pointer_raw.hex()
            raw_inputs["string32_heap_pointer"] = hex(heap_pointer) if heap_pointer else None
            _faith._user_pointer(heap_pointer, "religion_group_name_heap_pointer")
            payload_address = _checked_add(heap_pointer, 0, length + 1,
                                           "religion_group_name_heap_payload")
            payload_before = _read_at(reader, payload_address, length + 1,
                                      "religion_group.String32_heap_payload_before")
            raw_inputs["string32_heap_payload_address"] = hex(payload_address)
            raw_inputs["string32_payload_before_raw_hex"] = payload_before.hex()

        if len(payload_before) != length + 1 or payload_before[length] != 0:
            return _unknown("religion_group_name_terminator_invalid", raw_inputs)
        if b"\x00" in payload_before[:length]:
            return _unknown("religion_group_name_embedded_nul", raw_inputs)
        encoded_hex = payload_before[:length].hex()
        raw_inputs["religion_group_name_raw_hex"] = encoded_hex
        try:
            text = decode_native_text_hex(encoded_hex, codec=EU4_ESCAPE_CODEC,
                                          max_bytes=MAX_NAME_BYTES)
        except NativeTextError as exc:
            raw_inputs["native_text_decoder"] = {
                "status": "invalid", "codec": EU4_ESCAPE_CODEC,
                "error_type": type(exc).__name__,
            }
            return _unknown("religion_group_name_decode_invalid", raw_inputs)
        raw_inputs["native_text_decoder"] = {
            "status": "decoded", "codec": EU4_ESCAPE_CODEC,
        }
        if not text:
            return _unknown("religion_group_name_empty", raw_inputs)

        # Recheck every binding hop and the String32 source. The outer owner
        # still performs its own two-pass full binding/admission comparison.
        header_after = _read_at(reader, header_address, STRING32_SIZE,
                                 "religion_group.String32_header_after")
        raw_inputs["string32_header_after_raw_hex"] = header_after.hex()
        if header_after != header_before:
            return _unknown("religion_group_string32_header_changed", raw_inputs)
        if storage == "heap":
            assert heap_pointer is not None
            payload_after = _read_at(reader, payload_address, length + 1,
                                     "religion_group.String32_heap_payload_after")
            raw_inputs["string32_payload_after_raw_hex"] = payload_after.hex()
            if payload_after != payload_before:
                return _unknown("religion_group_string32_heap_payload_changed", raw_inputs)

        group_after = _read_at(reader, group_pointer_address, 8,
                               "religion_group.group_pointer_after")
        raw_inputs["religion_group_pointer_after_raw_hex"] = group_after.hex()
        religion_after = _read_at(reader, religion_pointer_address, 8,
                                  "religion_group.primary_religion_pointer_after")
        raw_inputs["primary_religion_pointer_after_raw_hex"] = religion_after.hex()
        if group_after != group_raw:
            return _unknown("religion_group_pointer_changed", raw_inputs)
        if religion_after != religion_raw:
            return _unknown("primary_religion_pointer_changed", raw_inputs)

        table_after = _read_at(reader, table_address, 8,
                               "religion_group.country_table_entry_after")
        fullref_after = _read_at(reader, fullref_address, 8,
                                 "religion_group.country_fullref_after")
        raw_inputs["country_table_entry_after_raw_hex"] = table_after.hex()
        raw_inputs["country_fullref_after_raw_hex"] = fullref_after.hex()
        if table_after != table_before or table_after.hex() != expected_table_raw:
            return _unknown("country_table_entry_changed_during_read", raw_inputs)
        if fullref_after != fullref_before or fullref_after != fullref_raw:
            return _unknown("country_fullref_changed_during_read", raw_inputs)

        raw_inputs["budget"] = {
            "calls": reader.calls,
            "bytes_requested": reader.bytes_requested,
            "max_calls": MAX_READ_CALLS,
            "max_bytes": MAX_READ_BYTES,
        }
        return {
            "status": "known",
            "complete": False,
            "value": {
                "religion_group_name": {
                    "text": text,
                    "raw_hex": encoded_hex,
                    "encoding": EU4_ESCAPE_CODEC,
                },
            },
            "basis": _BASIS,
            "gaps": list(_GAPS),
            "raw_inputs": raw_inputs,
        }
    except Exception as exc:
        if _budget_error(exc):
            # The parent must see exhausted shared budget as a collector
            # failure; converting it to a leaf unknown could hide truncation.
            raise
        raw_inputs.setdefault("leaf_error", {
            "type": type(exc).__name__, "detail": str(exc)[:160],
        })
        raw_inputs["budget"] = {
            "calls": reader.calls,
            "bytes_requested": reader.bytes_requested,
            "max_calls": MAX_READ_CALLS,
            "max_bytes": MAX_READ_BYTES,
        }
        return _unknown(f"religion_group_read_failed:{type(exc).__name__}", raw_inputs)


def read_fields(limiter: Any, base: int, target_binding: Mapping[str, Any],
                fields: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    """Read requested fields from an already country-bound read-only limiter."""
    if not isinstance(fields, tuple) or any(not isinstance(field, str) for field in fields):
        return {FIELD_ID: _unknown("fields_shape_invalid")}
    if len(set(fields)) != len(fields):
        return {field: _unknown("duplicate_field_requested") for field in dict.fromkeys(fields)}
    result: dict[str, dict[str, Any]] = {}
    for field in fields:
        if field != FIELD_ID:
            result[field] = _unknown("unsupported_field")
            continue
        raw_inputs: dict[str, Any] = {"reads": [], "read_failures": []}
        leaf_reader = _LeafLimiter(limiter, raw_inputs)
        result[field] = _read_group(leaf_reader, base, target_binding, raw_inputs)
    return result


__all__ = [
    "FIELD_ID",
    "COUNTRY_RELIGION_POINTER_OFFSET",
    "RELIGION_GROUP_POINTER_OFFSET",
    "GROUP_NAME_OFFSET",
    "STRING32_SIZE",
    "STRING32_LENGTH_OFFSET",
    "STRING32_CAPACITY_OFFSET",
    "MAX_NAME_BYTES",
    "MAX_STRING_CAPACITY",
    "MAX_READ_BYTES",
    "MAX_READ_CALLS",
    "read_fields",
]
