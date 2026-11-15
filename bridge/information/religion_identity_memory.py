"""Read the selected country's native primary-religion configuration keys.

The copied ASCII identifiers are read from the native religion and group
objects. This bounded leaf does not resolve localization, invoke game code,
or establish admission or UI visibility; those remain caller-owned.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from . import country_faith_memory as _faith
from . import country_reference_memory as _country_reference
from . import religion_group_memory as _group


FIELD_ID = "S02.religion_identity"
COUNTRY_RELIGION_POINTER_OFFSET = 0xF30
RELIGION_KEY_STRING32_OFFSET = 0x90
RELIGION_GROUP_POINTER_OFFSET = 0xD8
GROUP_KEY_STRING32_OFFSET = 0x18
STRING32_SIZE = 32
STRING32_LENGTH_OFFSET = 0x10
STRING32_CAPACITY_OFFSET = 0x18
MIN_NAME_BYTES = 1
MAX_NAME_BYTES = 128
MAX_STRING_CAPACITY = 8192
MAX_READ_BYTES = 4096
MAX_READ_CALLS = 32

_BASIS = "bounded_native_religion_and_group_configuration_keys"
_GAPS = [
    "LOCALIZATION_TOOLTIP_AND_RELIGION_RULES_NOT_READ",
    "CALLER_ADMISSION_IS_PARENT_OWNED",
    "UI_RENDER_NOT_OBSERVED",
]
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)


class _InvalidLeaf(ValueError):
    pass


def _unknown(reason: str, raw_inputs: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "status": "unknown",
        "complete": False,
        "reason": reason,
        "raw_inputs": raw_inputs if raw_inputs is not None else {},
        "basis": _BASIS,
        "gaps": list(_GAPS),
    }


def _read_at(reader: Any, address: int, size: int, label: str) -> bytes:
    return _faith._read_exact(reader, address, size, label)


def _bound_address(value: Any, label: str) -> int:
    parsed = _faith._parse_uint(value, label)
    return _faith._user_pointer(parsed, label, aligned=True)


def _read_string32_before(reader: Any, object_pointer: int, offset: int,
                           key_name: str, raw_inputs: dict[str, Any]) -> dict[str, Any]:
    address = _group._checked_add(object_pointer, offset, STRING32_SIZE,
                                  f"{key_name}_String32_header")
    label_prefix = key_name
    record: dict[str, Any] = {"address": hex(address)}
    raw_inputs[f"{label_prefix}_String32_address"] = hex(address)
    header = _read_at(reader, address, STRING32_SIZE,
                      f"religion_identity.{label_prefix}.String32_header_before")
    length = int.from_bytes(header[STRING32_LENGTH_OFFSET:0x18], "little")
    capacity = int.from_bytes(header[STRING32_CAPACITY_OFFSET:0x20], "little")
    storage = "inline" if capacity < 16 else "heap"
    record.update({"address": address, "header": header, "length": length,
                   "capacity": capacity, "storage": storage})
    raw_inputs.update({
        f"{label_prefix}_String32_header_before_raw_hex": header.hex(),
        f"{label_prefix}_String32_length_raw_hex": header[0x10:0x18].hex(),
        f"{label_prefix}_String32_capacity_raw_hex": header[0x18:0x20].hex(),
        f"{label_prefix}_String32_length": length,
        f"{label_prefix}_String32_capacity": capacity,
        f"{label_prefix}_String32_storage": storage,
    })
    if not MIN_NAME_BYTES <= length <= MAX_NAME_BYTES:
        raise _InvalidLeaf(f"{label_prefix}_length_out_of_bound")
    if capacity < length:
        raise _InvalidLeaf(f"{label_prefix}_capacity_below_length")
    if capacity > MAX_STRING_CAPACITY:
        raise _InvalidLeaf(f"{label_prefix}_capacity_out_of_bound")
    if storage == "inline" and length > 15:
        raise _InvalidLeaf(f"{label_prefix}_inline_length_invalid")

    if storage == "inline":
        payload = header[:length + 1]
        raw_inputs[f"{label_prefix}_String32_inline_bytes_raw_hex"] = payload.hex()
    else:
        pointer_raw = header[:8]
        heap_pointer = int.from_bytes(pointer_raw, "little")
        raw_inputs[f"{label_prefix}_String32_heap_pointer_raw_hex"] = pointer_raw.hex()
        raw_inputs[f"{label_prefix}_String32_heap_pointer"] = (
            hex(heap_pointer) if heap_pointer else None)
        try:
            _faith._user_pointer(heap_pointer, f"{label_prefix}_heap_pointer")
        except ValueError as exc:
            raise _InvalidLeaf(f"{label_prefix}_heap_pointer_invalid") from exc
        payload_address = _group._checked_add(
            heap_pointer, 0, length + 1, f"{label_prefix}_heap_payload")
        record["heap_pointer"] = heap_pointer
        record["payload_address"] = payload_address
        raw_inputs[f"{label_prefix}_String32_heap_payload_address"] = hex(payload_address)
        payload = _read_at(reader, payload_address, length + 1,
                           f"religion_identity.{label_prefix}.String32_heap_payload_before")
        raw_inputs[f"{label_prefix}_String32_heap_payload_before_raw_hex"] = payload.hex()

    if len(payload) != length + 1 or payload[length] != 0:
        raise _InvalidLeaf(f"{label_prefix}_terminator_invalid")
    if b"\x00" in payload[:length]:
        raise _InvalidLeaf(f"{label_prefix}_embedded_nul")
    raw = payload[:length]
    raw_inputs[f"{label_prefix}_key_raw_hex"] = raw.hex()
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise _InvalidLeaf(f"{label_prefix}_non_ascii") from exc
    if _IDENTIFIER_RE.fullmatch(text) is None:
        raise _InvalidLeaf(f"{label_prefix}_identifier_invalid")
    record["payload"] = payload
    record["key"] = text
    return record


def _read_string32_after(reader: Any, record: dict[str, Any], key_name: str,
                         raw_inputs: dict[str, Any]) -> bool:
    address = record["address"]
    header_after = _read_at(
        reader, address, STRING32_SIZE,
        f"religion_identity.{key_name}.String32_header_after")
    raw_inputs[f"{key_name}_String32_header_after_raw_hex"] = header_after.hex()
    stable = header_after == record["header"]
    if record["storage"] == "heap":
        payload_after = _read_at(
            reader, record["payload_address"], len(record["payload"]),
            f"religion_identity.{key_name}.String32_heap_payload_after")
        raw_inputs[f"{key_name}_String32_heap_payload_after_raw_hex"] = payload_after.hex()
        stable = stable and payload_after == record["payload"]
    return stable


def _read_identity(limiter: Any, base: Any, target_binding: Any,
                   raw_inputs: dict[str, Any]) -> dict[str, Any]:
    leaf_reader = _group._LeafLimiter(limiter, raw_inputs)
    try:
        if type(base) is not int:
            raise ValueError("module_base_invalid")
        module_base = _faith._user_pointer(base, "module_base")
        country_pointer, binding = _faith._binding(target_binding)
        if type(country_pointer) is not int:
            raise ValueError("country_pointer_invalid")
        table_raw_expected = country_pointer.to_bytes(8, "little")
        table_entry_address = _bound_address(
            binding.get("table_entry_address"), "table_entry_address")
        table_entry_raw_hex = binding.get("table_entry_raw_hex")
        if (not isinstance(table_entry_raw_hex, str)
                or table_entry_raw_hex != table_raw_expected.hex()):
            raise ValueError("table_entry_raw_mismatch")

        fullref_address = _group._checked_add(
            country_pointer, _country_reference.COUNTRY_FULLREF_OFFSET, 8,
            "country_fullref")
        supplied_fullref_address = _bound_address(
            binding.get("country_fullref_address"), "country_fullref_address")
        if supplied_fullref_address != fullref_address:
            raise ValueError("country_fullref_address_mismatch")
        fullref_raw_expected = bytes.fromhex(binding["fullref_raw_hex"])
        fullref_value = int(binding["fullref"], 16)
        if (len(fullref_raw_expected) != 8
                or fullref_raw_expected != fullref_value.to_bytes(8, "little")):
            raise ValueError("country_fullref_raw_invalid")

        raw_inputs.update({
            "module_base": hex(module_base),
            "country_binding": binding,
            "country_pointer": hex(country_pointer),
            "country_fullref_address": hex(fullref_address),
            "table_entry_address": hex(table_entry_address),
            "expected_country_fullref_raw_hex": fullref_raw_expected.hex(),
            "expected_table_entry_raw_hex": table_raw_expected.hex(),
        })
        table_before = _read_at(
            leaf_reader, table_entry_address, 8,
            "religion_identity.country_table_entry_before")
        fullref_before = _read_at(
            leaf_reader, fullref_address, 8,
            "religion_identity.country_fullref_before")
        raw_inputs["country_table_entry_before_raw_hex"] = table_before.hex()
        raw_inputs["country_fullref_before_raw_hex"] = fullref_before.hex()
        if table_before != table_raw_expected:
            return _unknown("country_table_entry_changed_before_read", raw_inputs)
        if fullref_before != fullref_raw_expected:
            return _unknown("country_fullref_changed_before_read", raw_inputs)

        religion_pointer_address = _group._checked_add(
            country_pointer, COUNTRY_RELIGION_POINTER_OFFSET, 8,
            "primary_religion_pointer")
        religion_pointer_raw = _read_at(
            leaf_reader, religion_pointer_address, 8,
            "religion_identity.primary_religion_pointer_before")
        religion_pointer = int.from_bytes(religion_pointer_raw, "little")
        raw_inputs.update({
            "primary_religion_pointer_address": hex(religion_pointer_address),
            "primary_religion_pointer_before_raw_hex": religion_pointer_raw.hex(),
            "primary_religion_pointer": hex(religion_pointer) if religion_pointer else None,
        })
        if religion_pointer == 0:
            return _unknown("primary_religion_pointer_null", raw_inputs)
        _faith._user_pointer(religion_pointer, "primary_religion_pointer", aligned=True)

        group_pointer_address = _group._checked_add(
            religion_pointer, RELIGION_GROUP_POINTER_OFFSET, 8,
            "religion_group_pointer")
        group_pointer_raw = _read_at(
            leaf_reader, group_pointer_address, 8,
            "religion_identity.group_pointer_before")
        group_pointer = int.from_bytes(group_pointer_raw, "little")
        raw_inputs.update({
            "religion_group_pointer_address": hex(group_pointer_address),
            "religion_group_pointer_before_raw_hex": group_pointer_raw.hex(),
            "religion_group_pointer": hex(group_pointer) if group_pointer else None,
        })
        if group_pointer == 0:
            return _unknown("religion_group_pointer_null", raw_inputs)
        _faith._user_pointer(group_pointer, "religion_group_pointer", aligned=True)

        religion_key = _read_string32_before(
            leaf_reader, religion_pointer, RELIGION_KEY_STRING32_OFFSET,
            "religion_key", raw_inputs)
        group_key = _read_string32_before(
            leaf_reader, group_pointer, GROUP_KEY_STRING32_OFFSET,
            "religion_group_key", raw_inputs)

        religion_header_stable = _read_string32_after(
            leaf_reader, religion_key, "religion_key", raw_inputs)
        group_header_stable = _read_string32_after(
            leaf_reader, group_key, "religion_group_key", raw_inputs)
        if not religion_header_stable or not group_header_stable:
            return _unknown("religion_identity_string32_changed", raw_inputs)

        group_pointer_after = _read_at(
            leaf_reader, group_pointer_address, 8,
            "religion_identity.group_pointer_after")
        religion_pointer_after = _read_at(
            leaf_reader, religion_pointer_address, 8,
            "religion_identity.primary_religion_pointer_after")
        raw_inputs["religion_group_pointer_after_raw_hex"] = group_pointer_after.hex()
        raw_inputs["primary_religion_pointer_after_raw_hex"] = religion_pointer_after.hex()
        if group_pointer_after != group_pointer_raw:
            return _unknown("religion_group_pointer_changed", raw_inputs)
        if religion_pointer_after != religion_pointer_raw:
            return _unknown("primary_religion_pointer_changed", raw_inputs)

        table_after = _read_at(
            leaf_reader, table_entry_address, 8,
            "religion_identity.country_table_entry_after")
        fullref_after = _read_at(
            leaf_reader, fullref_address, 8,
            "religion_identity.country_fullref_after")
        raw_inputs["country_table_entry_after_raw_hex"] = table_after.hex()
        raw_inputs["country_fullref_after_raw_hex"] = fullref_after.hex()
        if table_after != table_before or table_after != table_raw_expected:
            return _unknown("country_table_entry_changed_during_read", raw_inputs)
        if fullref_after != fullref_before or fullref_after != fullref_raw_expected:
            return _unknown("country_fullref_changed_during_read", raw_inputs)

        raw_inputs["budget"] = {
            "calls": leaf_reader.calls,
            "bytes_requested": leaf_reader.bytes_requested,
            "max_calls": MAX_READ_CALLS,
            "max_bytes": MAX_READ_BYTES,
        }
        return {
            "status": "known",
            "complete": False,
            "value": {
                "religion_key": religion_key["key"],
                "religion_group_key": group_key["key"],
            },
            "basis": _BASIS,
            "gaps": list(_GAPS),
            "raw_inputs": raw_inputs,
        }
    except Exception as exc:
        if _group._budget_error(exc):
            raise
        raw_inputs.setdefault("leaf_error", {
            "type": type(exc).__name__, "detail": str(exc)[:160],
        })
        raw_inputs["budget"] = {
            "calls": leaf_reader.calls,
            "bytes_requested": leaf_reader.bytes_requested,
            "max_calls": MAX_READ_CALLS,
            "max_bytes": MAX_READ_BYTES,
        }
        reason = str(exc) if isinstance(exc, _InvalidLeaf) else (
            f"religion_identity_read_failed:{type(exc).__name__}")
        return _unknown(reason[:180], raw_inputs)


def read_fields(limiter: Any, base: int, target_binding: Mapping[str, Any],
                fields: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    """Return requested information fields from an existing bounded reader."""
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
        result[field] = _read_identity(limiter, base, target_binding, raw_inputs)
    return result


__all__ = [
    "FIELD_ID",
    "COUNTRY_RELIGION_POINTER_OFFSET",
    "RELIGION_KEY_STRING32_OFFSET",
    "RELIGION_GROUP_POINTER_OFFSET",
    "GROUP_KEY_STRING32_OFFSET",
    "STRING32_SIZE",
    "STRING32_LENGTH_OFFSET",
    "STRING32_CAPACITY_OFFSET",
    "MAX_NAME_BYTES",
    "MAX_STRING_CAPACITY",
    "MAX_READ_BYTES",
    "MAX_READ_CALLS",
    "read_fields",
]
