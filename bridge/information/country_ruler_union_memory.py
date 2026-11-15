"""Bounded private reader for the writer's PERSONAL_UNION_WITH gate.

This leaf follows already supplied country bindings and reads only the
selected-country relation data needed by the original ruler-information
branch. It does not open a process, call game code, or describe every subject
relationship or any UI/public visibility outcome.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any


DATABASE_GLOBAL_RVA = 0x233D8B0
DATABASE_TABLE_OFFSET = 0x118
DATABASE_TABLE_COUNT_OFFSET = 0x124
COUNTRY_FULLREF_OFFSET = 0x20

TARGET_PERSONAL_UNION_REF_OFFSET = 0x18F0
TARGET_PERSONAL_UNION_DISCRIMINATOR_OFFSET = 0x18F7
TARGET_RELATION_TABLE_OFFSET = 0x1510
RELATION_ROW_STRIDE = 0x48
RELATION_ROW_OWNER_OFFSET = 0x0
RELATION_ROW_FULLREF_OFFSET = 0x10
RELATION_ROW_READ_SIZE = 0x18

OWNER_ENTRIES_OFFSET = 0x128
OWNER_ENTRY_COUNT_OFFSET = 0x134
OWNER_ENTRY_STRIDE = 16
OWNER_ENTRY_MAX_COUNT = 4096
RELATION_OBJECT_OFFSET = 8
RELATION_OBJECT_TYPE_OFFSET = 0x40
RELATION_TYPE_FLAG_OFFSET = 0x118

MAX_COUNTRY_SLOTS = 4096
MAX_READ_CALLS = 64
MAX_TOTAL_READ_BYTES = 128 * 1024
MAX_SINGLE_READ_BYTES = 65536
MIN_USER_ADDRESS = 0x10000
MAX_USER_ADDRESS_EXCLUSIVE = 0x800000000000
MAX_U64 = 0xFFFFFFFFFFFFFFFF
_VALID_TAG_BYTES = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")


class RulerUnionReadError(ValueError):
    """A bounded read or input could not be validated."""


def _parse_uint(value: Any, label: str, *, maximum: int = MAX_U64) -> int:
    if isinstance(value, bool):
        raise RulerUnionReadError(f"{label}_invalid")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value, 0)
        except ValueError as exc:
            raise RulerUnionReadError(f"{label}_invalid") from exc
    else:
        raise RulerUnionReadError(f"{label}_invalid")
    if not 0 <= parsed <= maximum:
        raise RulerUnionReadError(f"{label}_out_of_range")
    return parsed


def _user_pointer(value: int, label: str, *, aligned: bool = False) -> int:
    if not MIN_USER_ADDRESS <= value < MAX_USER_ADDRESS_EXCLUSIVE:
        raise RulerUnionReadError(f"{label}_invalid")
    if aligned and value & 7:
        raise RulerUnionReadError(f"{label}_unaligned")
    return value


def _checked_add(base: int, offset: int, label: str) -> int:
    _user_pointer(base, f"{label}_base")
    if type(offset) is not int or offset < 0 or base > MAX_U64 - offset:
        raise RulerUnionReadError(f"{label}_arithmetic_invalid")
    return _user_pointer(base + offset, label)


def _checked_range(address: int, size: int, label: str) -> tuple[int, int]:
    if type(size) is not int or not 0 < size <= MAX_SINGLE_READ_BYTES:
        raise RulerUnionReadError(f"{label}_size_invalid")
    _user_pointer(address, f"{label}_address")
    end = address + size
    if end > MAX_USER_ADDRESS_EXCLUSIVE or end <= address:
        raise RulerUnionReadError(f"{label}_range_invalid")
    return address, end


def _overlaps(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def _read_exact(limiter: Any, address: int, size: int, label: str,
                state: dict[str, Any]) -> bytes:
    _checked_range(address, size, label)
    if state["calls"] >= MAX_READ_CALLS:
        raise RulerUnionReadError("read_call_budget_exceeded")
    if state["bytes_requested"] + size > MAX_TOTAL_READ_BYTES:
        raise RulerUnionReadError("read_byte_budget_exceeded")
    state["calls"] += 1
    state["bytes_requested"] += size
    try:
        if callable(limiter):
            result = limiter(address, size, label)
        else:
            reader = getattr(limiter, "read", None)
            if not callable(reader):
                raise RulerUnionReadError("limiter_read_unavailable")
            result = reader(address, size, label)
    except Exception as exc:
        state["reads"].append({
            "address": hex(address),
            "size": size,
            "label": label,
            "status": "failed",
            "error": f"{type(exc).__name__}:{str(exc)[:160]}",
        })
        raise RulerUnionReadError(f"read_failed:{label}:{type(exc).__name__}") from exc
    if not isinstance(result, (bytes, bytearray, memoryview)):
        state["reads"].append({
            "address": hex(address), "size": size, "label": label,
            "status": "failed", "error": "read_result_not_bytes",
        })
        raise RulerUnionReadError(f"read_result_not_bytes:{label}")
    raw = bytes(result)
    if len(raw) != size:
        state["reads"].append({
            "address": hex(address), "size": size, "label": label,
            "status": "failed", "error": f"short_read:{len(raw)}:{size}",
            "raw_hex": raw.hex(),
        })
        raise RulerUnionReadError(f"short_read:{label}:{len(raw)}:{size}")
    state["reads"].append({
        "address": hex(address), "size": size, "label": label,
        "status": "ok", "raw_hex": raw.hex(),
    })
    return raw


def _read_u64(limiter: Any, address: int, label: str,
              state: dict[str, Any]) -> tuple[int, bytes]:
    raw = _read_exact(limiter, address, 8, label, state)
    return int.from_bytes(raw, "little", signed=False), raw


def _read_i32(limiter: Any, address: int, label: str,
              state: dict[str, Any]) -> tuple[int, bytes]:
    raw = _read_exact(limiter, address, 4, label, state)
    return int.from_bytes(raw, "little", signed=True), raw


def _binding(target_binding: Any) -> tuple[int, dict[str, Any]]:
    if not isinstance(target_binding, Mapping):
        raise RulerUnionReadError("target_binding_invalid")
    tag = target_binding.get("tag")
    if (not isinstance(tag, str) or len(tag) != 3
            or not all(ord(char) < 128 and ord(char) in _VALID_TAG_BYTES for char in tag)):
        raise RulerUnionReadError("target_binding_tag_invalid")
    slot = target_binding.get("slot")
    if type(slot) is not int or not 0 <= slot < MAX_COUNTRY_SLOTS:
        raise RulerUnionReadError("target_binding_slot_invalid")
    pointer = _user_pointer(
        _parse_uint(target_binding.get("country_pointer"), "target_country_pointer"),
        "target_country_pointer",
        aligned=True,
    )
    fullref = _parse_uint(target_binding.get("fullref"), "target_country_fullref")
    fullref_slot = (fullref >> 32) & 0xFFFF
    if fullref_slot != slot:
        raise RulerUnionReadError("target_binding_fullref_slot_mismatch")
    tag_raw = (fullref & 0xFFFFFF).to_bytes(3, "little")
    if tag_raw.decode("ascii", errors="strict") != tag:
        raise RulerUnionReadError("target_binding_fullref_tag_mismatch")
    raw_hex = fullref.to_bytes(8, "little").hex()
    supplied_raw = target_binding.get("fullref_raw_hex")
    if supplied_raw is not None and supplied_raw != raw_hex:
        raise RulerUnionReadError("target_binding_fullref_raw_mismatch")
    return pointer, {
        "tag": tag,
        "slot": slot,
        "country_pointer": hex(pointer),
        "fullref": hex(fullref),
        "fullref_raw_hex": raw_hex,
        "country_fullref_address": target_binding.get("country_fullref_address"),
        "table_entry_address": target_binding.get("table_entry_address"),
        "table_entry_raw_hex": target_binding.get("table_entry_raw_hex"),
    }


def _tag_from_fullref(fullref: int) -> str:
    tag_raw = (fullref & 0xFFFFFF).to_bytes(3, "little")
    if not all(byte in _VALID_TAG_BYTES for byte in tag_raw):
        raise RulerUnionReadError("related_country_tag_invalid")
    return tag_raw.decode("ascii")


def _finalize(status: str, reason: str, raw_inputs: dict[str, Any],
              state: dict[str, Any], *, active: bool | None = None,
              related_country: dict[str, Any] | None = None) -> dict[str, Any]:
    raw_inputs["read_calls"] = state["calls"]
    raw_inputs["bytes_requested"] = state["bytes_requested"]
    raw_inputs["reads"] = state["reads"]
    result: dict[str, Any] = {
        "status": status,
        "reason": reason,
        "raw_inputs": raw_inputs,
        "basis": "B23_PERSONAL_UNION_WITH_GATE_INPUTS_ONLY",
        "scope": [
            "PROJECTS_ONE_SELECTED_WRITER_RELATION_BRANCH",
            "DOES_NOT_ENUMERATE_ALL_SUBJECT_OR_UNION_RELATIONSHIPS",
            "DOES_NOT_PROVE_UI_RENDER_OR_PUBLIC_VISIBILITY",
        ],
    }
    if status == "known":
        result["active"] = bool(active)
        if related_country is not None:
            result["related_country"] = related_country
    return result


def read_ruler_union_gate(limiter: Any, base: int,
                          target_binding: Mapping[str, Any]) -> dict[str, Any]:
    """Read the selected-country PERSONAL_UNION_WITH branch inputs.

    The supplied binding must already identify one country row. All reads are
    bounded and exact. A known false result applies only to this selected
    writer gate; malformed data, pointer failures, ambiguous duplicate rows,
    and short reads return unknown without an active field.
    """
    state: dict[str, Any] = {"calls": 0, "bytes_requested": 0, "reads": []}
    raw_inputs: dict[str, Any] = {}
    try:
        module_base = _user_pointer(_parse_uint(base, "module_base"), "module_base")
        raw_inputs["module_base"] = hex(module_base)
        country_pointer, binding = _binding(target_binding)
        raw_inputs["target_binding"] = binding

        selected_ref_address = _checked_add(
            country_pointer, COUNTRY_FULLREF_OFFSET, "target_country_fullref_address")
        selected_ref, selected_ref_raw = _read_u64(
            limiter, selected_ref_address, "ruler_union.target_fullref", state)
        raw_inputs["target_fullref_address"] = hex(selected_ref_address)
        raw_inputs["target_fullref_raw_hex"] = selected_ref_raw.hex()
        raw_inputs["target_fullref"] = hex(selected_ref)
        if selected_ref != int(binding["fullref"], 16):
            raise RulerUnionReadError("target_binding_fullref_memory_mismatch")

        union_ref_address = _checked_add(
            country_pointer, TARGET_PERSONAL_UNION_REF_OFFSET,
            "personal_union_fullref_address")
        union_ref, union_ref_raw = _read_u64(
            limiter, union_ref_address, "ruler_union.related_fullref", state)
        discriminator = union_ref_raw[
            TARGET_PERSONAL_UNION_DISCRIMINATOR_OFFSET - TARGET_PERSONAL_UNION_REF_OFFSET
        ]
        raw_inputs["related_fullref_address"] = hex(union_ref_address)
        raw_inputs["related_fullref_raw_hex"] = union_ref_raw.hex()
        raw_inputs["related_fullref"] = hex(union_ref)
        raw_inputs["related_discriminator_address"] = hex(
            country_pointer + TARGET_PERSONAL_UNION_DISCRIMINATOR_OFFSET)
        raw_inputs["related_discriminator_raw_hex"] = f"{discriminator:02x}"
        raw_inputs["related_discriminator"] = discriminator
        if discriminator == 0:
            return _finalize("known", "related_discriminator_zero", raw_inputs, state,
                             active=False)

        related_slot = (union_ref >> 32) & 0xFFFF
        if related_slot >= MAX_COUNTRY_SLOTS:
            raise RulerUnionReadError("related_country_slot_out_of_range")
        related_tag = _tag_from_fullref(union_ref)
        raw_inputs["related_country_slot"] = related_slot
        raw_inputs["related_country_tag"] = related_tag

        database_global_address = _checked_add(
            module_base, DATABASE_GLOBAL_RVA, "database_global_address")
        database_pointer, database_raw = _read_u64(
            limiter, database_global_address, "ruler_union.database_global", state)
        database_pointer = _user_pointer(database_pointer, "database_pointer", aligned=True)
        raw_inputs["database_global_address"] = hex(database_global_address)
        raw_inputs["database_global_raw_hex"] = database_raw.hex()
        raw_inputs["database_pointer"] = hex(database_pointer)

        database_table_address = _checked_add(
            database_pointer, DATABASE_TABLE_OFFSET, "database_table_address")
        database_count_address = _checked_add(
            database_pointer, DATABASE_TABLE_COUNT_OFFSET, "database_count_address")
        database_table, database_table_raw = _read_u64(
            limiter, database_table_address, "ruler_union.database_table", state)
        count_raw = _read_exact(
            limiter, database_count_address, 4, "ruler_union.database_count", state)
        database_count = int.from_bytes(count_raw, "little", signed=True)
        database_table = _user_pointer(database_table, "database_table", aligned=True)
        raw_inputs["database_table_address"] = hex(database_table_address)
        raw_inputs["database_table_raw_hex"] = database_table_raw.hex()
        raw_inputs["database_table"] = hex(database_table)
        raw_inputs["database_count_address"] = hex(database_count_address)
        raw_inputs["database_count_raw_hex"] = count_raw.hex()
        raw_inputs["database_count"] = database_count
        if not 0 < database_count <= MAX_COUNTRY_SLOTS:
            raise RulerUnionReadError("database_count_out_of_range")
        if related_slot >= database_count:
            raise RulerUnionReadError("related_country_slot_not_in_database")

        related_pointer_address = _checked_add(
            database_table, related_slot * 8, "related_country_slot_pointer_address")
        related_pointer, related_pointer_raw = _read_u64(
            limiter, related_pointer_address, "ruler_union.related_country_pointer", state)
        related_pointer = _user_pointer(
            related_pointer, "related_country_pointer", aligned=True)
        raw_inputs["related_country_table_entry_address"] = hex(related_pointer_address)
        raw_inputs["related_country_table_entry_raw_hex"] = related_pointer_raw.hex()
        raw_inputs["resolved_related_country_pointer"] = hex(related_pointer)

        resolved_ref_address = _checked_add(
            related_pointer, COUNTRY_FULLREF_OFFSET, "related_country_fullref_address")
        resolved_ref, resolved_ref_raw = _read_u64(
            limiter, resolved_ref_address, "ruler_union.related_country_fullref", state)
        raw_inputs["resolved_related_country_fullref_address"] = hex(resolved_ref_address)
        raw_inputs["resolved_related_country_fullref_raw_hex"] = resolved_ref_raw.hex()
        raw_inputs["resolved_related_country_fullref"] = hex(resolved_ref)
        if resolved_ref != union_ref:
            raise RulerUnionReadError("related_country_fullref_mismatch")

        relation_table_address = _checked_add(
            country_pointer, TARGET_RELATION_TABLE_OFFSET, "relation_table_pointer_address")
        relation_table, relation_table_raw = _read_u64(
            limiter, relation_table_address, "ruler_union.relation_table", state)
        relation_table = _user_pointer(relation_table, "relation_table", aligned=True)
        raw_inputs["relation_table_pointer_address"] = hex(relation_table_address)
        raw_inputs["relation_table_raw_hex"] = relation_table_raw.hex()
        raw_inputs["relation_table"] = hex(relation_table)

        relation_row_address = _checked_add(
            relation_table, related_slot * RELATION_ROW_STRIDE,
            "relation_row_address")
        relation_row_raw = _read_exact(
            limiter, relation_row_address, RELATION_ROW_READ_SIZE,
            "ruler_union.relation_row", state)
        owner_pointer = int.from_bytes(
            relation_row_raw[RELATION_ROW_OWNER_OFFSET:RELATION_ROW_OWNER_OFFSET + 8],
            "little",
        )
        relation_row_ref_raw = relation_row_raw[
            RELATION_ROW_FULLREF_OFFSET:RELATION_ROW_FULLREF_OFFSET + 8
        ]
        relation_row_ref = int.from_bytes(relation_row_ref_raw, "little")
        raw_inputs["relation_row_address"] = hex(relation_row_address)
        raw_inputs["relation_row_raw_hex"] = relation_row_raw.hex()
        raw_inputs["relation_row_owner_pointer_raw_hex"] = relation_row_raw[:8].hex()
        raw_inputs["relation_row_owner_pointer"] = (
            hex(owner_pointer) if owner_pointer else None)
        raw_inputs["relation_row_fullref_raw_hex"] = relation_row_ref_raw.hex()
        raw_inputs["relation_row_fullref"] = hex(relation_row_ref)
        if relation_row_ref != union_ref:
            raise RulerUnionReadError("relation_row_fullref_mismatch")
        owner_pointer = _user_pointer(owner_pointer, "relation_owner_pointer", aligned=True)

        entries_pointer_address = _checked_add(
            owner_pointer, OWNER_ENTRIES_OFFSET, "owner_entries_pointer_address")
        entries_pointer, entries_pointer_raw = _read_u64(
            limiter, entries_pointer_address, "ruler_union.owner_entries_pointer", state)
        owner_count_address = _checked_add(
            owner_pointer, OWNER_ENTRY_COUNT_OFFSET, "owner_entry_count_address")
        owner_count, owner_count_raw = _read_i32(
            limiter, owner_count_address, "ruler_union.owner_entry_count", state)
        raw_inputs["owner_entries_pointer_address"] = hex(entries_pointer_address)
        raw_inputs["owner_entries_pointer_raw_hex"] = entries_pointer_raw.hex()
        raw_inputs["owner_entries_pointer"] = hex(entries_pointer) if entries_pointer else None
        raw_inputs["owner_entry_count_address"] = hex(owner_count_address)
        raw_inputs["owner_entry_count_raw_hex"] = owner_count_raw.hex()
        raw_inputs["owner_entry_count"] = owner_count
        if owner_count < 0 or owner_count > OWNER_ENTRY_MAX_COUNT:
            raise RulerUnionReadError("owner_entry_count_out_of_range")
        if owner_count == 0:
            return _finalize("known", "owner_entry_count_zero", raw_inputs, state,
                             active=False)
        entries_pointer = _user_pointer(
            entries_pointer, "owner_entries_pointer", aligned=True)
        entries_size = owner_count * OWNER_ENTRY_STRIDE
        if entries_size > 65536:
            raise RulerUnionReadError("owner_entries_size_out_of_range")
        entries_address = _checked_add(
            entries_pointer, 0, "owner_entries_address")
        entries_raw = _read_exact(
            limiter, entries_address, entries_size, "ruler_union.owner_entries", state)
        raw_inputs["owner_entries_address"] = hex(entries_address)
        raw_inputs["owner_entries_size"] = entries_size
        raw_inputs["owner_entries_raw_hex"] = entries_raw.hex()

        matching_indices = [
            index for index in range(owner_count)
            if int.from_bytes(
                entries_raw[index * OWNER_ENTRY_STRIDE:
                            index * OWNER_ENTRY_STRIDE + 4],
                "little",
                signed=True,
            ) == related_slot
        ]
        raw_inputs["matching_owner_entry_indices"] = matching_indices
        if len(matching_indices) > 1:
            raise RulerUnionReadError("duplicate_matching_owner_entries")
        if not matching_indices:
            return _finalize("known", "matching_owner_entry_absent",
                             raw_inputs, state, active=False)
        entry_index = matching_indices[0]
        relation_object_raw = entries_raw[
            entry_index * OWNER_ENTRY_STRIDE + RELATION_OBJECT_OFFSET:
            entry_index * OWNER_ENTRY_STRIDE + RELATION_OBJECT_OFFSET + 8
        ]
        relation_object = int.from_bytes(relation_object_raw, "little")
        raw_inputs["matching_owner_entry_index"] = entry_index
        raw_inputs["relation_object_raw_hex"] = relation_object_raw.hex()
        raw_inputs["relation_object"] = hex(relation_object) if relation_object else None
        if relation_object == 0:
            return _finalize("known", "relation_object_null", raw_inputs, state,
                             active=False)
        relation_object = _user_pointer(
            relation_object, "relation_object", aligned=True)

        type_pointer_address = _checked_add(
            relation_object, RELATION_OBJECT_TYPE_OFFSET,
            "relation_type_pointer_address")
        type_pointer, type_pointer_raw = _read_u64(
            limiter, type_pointer_address, "ruler_union.relation_type_pointer", state)
        raw_inputs["relation_type_pointer_address"] = hex(type_pointer_address)
        raw_inputs["relation_type_pointer_raw_hex"] = type_pointer_raw.hex()
        raw_inputs["relation_type_pointer"] = hex(type_pointer) if type_pointer else None
        if type_pointer == 0:
            return _finalize("known", "relation_type_pointer_null", raw_inputs, state,
                             active=False)
        type_pointer = _user_pointer(type_pointer, "relation_type_pointer", aligned=True)

        type_flag_address = _checked_add(
            type_pointer, RELATION_TYPE_FLAG_OFFSET, "relation_type_flag_address")
        type_flag_raw = _read_exact(
            limiter, type_flag_address, 1, "ruler_union.relation_type_flag", state)
        type_flag = type_flag_raw[0]
        raw_inputs["relation_type_flag_address"] = hex(type_flag_address)
        raw_inputs["relation_type_flag_raw_hex"] = type_flag_raw.hex()
        raw_inputs["relation_type_flag"] = type_flag
        active = type_flag != 0
        related_country = None
        if active:
            related_country = {
                "tag": related_tag,
                "slot": related_slot,
                "fullref": hex(union_ref),
            }
        reason = "relation_type_flag_nonzero" if active else "relation_type_flag_zero"
        return _finalize("known", reason, raw_inputs, state,
                         active=active, related_country=related_country)
    except Exception as exc:
        reason = str(exc) or type(exc).__name__
        return _finalize("unknown", reason, raw_inputs, state)


__all__ = [
    "DATABASE_GLOBAL_RVA",
    "DATABASE_TABLE_OFFSET",
    "DATABASE_TABLE_COUNT_OFFSET",
    "COUNTRY_FULLREF_OFFSET",
    "TARGET_PERSONAL_UNION_REF_OFFSET",
    "TARGET_PERSONAL_UNION_DISCRIMINATOR_OFFSET",
    "TARGET_RELATION_TABLE_OFFSET",
    "RELATION_ROW_STRIDE",
    "OWNER_ENTRIES_OFFSET",
    "OWNER_ENTRY_COUNT_OFFSET",
    "OWNER_ENTRY_STRIDE",
    "OWNER_ENTRY_MAX_COUNT",
    "RELATION_OBJECT_OFFSET",
    "RELATION_OBJECT_TYPE_OFFSET",
    "RELATION_TYPE_FLAG_OFFSET",
    "MAX_COUNTRY_SLOTS",
    "read_ruler_union_gate",
]
