"""Read-only leaf for native diplomacy soldier and ship statistics.

The caller owns process/session identity, the full country scan, observer role,
and the source-pinned predicate profile.  This leaf revalidates the supplied
target binding and field-specific permission before reading its +0xd18 group
chain.  It never calls a native function and does not inspect vector elements
for the naval branch.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import country_scale_development_memory as _country_binding
from . import foreign_manpower_memory as _manpower


SCHEMA = "information.foreign_force_statistics_memory.v1"
PROFILE_SCHEMA = "information.foreign_force_statistics_predicate_profile.v1"
FIELD_ARMY = "F02.visible_army"
FIELD_NAVY = "F02.visible_navy"
FIELDS = (FIELD_ARMY, FIELD_NAVY)
ARMY_BASIS = "native_diplomacy_soldier_statistic"
NAVY_BASIS = "native_diplomacy_ship_statistic"
EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"

COUNTRY_GROUP_HEAD_OFFSET = 0xD18
NODE_GROUP_OFFSET = 0x00
NODE_NEXT_OFFSET = 0x10
GROUP_VTABLE_OFFSET = 0x00
GROUP_VECTOR_BEGIN_OFFSET = 0x30
GROUP_VECTOR_END_OFFSET = 0x38
VTABLE_SLOT_80_OFFSET = 0x80
VTABLE_SLOT_88_OFFSET = 0x88
RECORD_STRENGTH_OFFSET = 0x28
VECTOR_STRIDE = 8

MIN_USER_ADDRESS = 0x10000
MAX_USER_ADDRESS_EXCLUSIVE = 0x800000000000
MAX_U64 = 0xFFFFFFFFFFFFFFFF
MAX_READ_CALLS = 4096
MAX_TOTAL_READ_BYTES = 256 * 1024
MAX_SINGLE_READ_BYTES = 16_384
MAX_CHAIN_NODES = 128
MAX_RECORDS = 4096
MAX_VECTOR_ELEMENTS = 4096

_EXPECTED_VTABLES = {
    0x1C42540: {"slot_80": 0x8F440, "slot_88": 0x8F450},
    0x1CCA618: {"slot_80": 0x8F450, "slot_88": 0x8F440},
}
_EXPECTED_METHODS = {
    0x8F440: {"body_hex": "b001c3", "constant_boolean_return": True},
    0x8F450: {"body_hex": "32c0c3", "constant_boolean_return": False},
}


class _LeafFailure(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class _BudgetReader:
    """Enforce field-local limits on a callable or .read()-compatible source."""

    def __init__(self, source: Any):
        self.source = source
        self.calls = 0
        self.bytes_requested = 0
        self.max_single = 0
        self.read_log: list[dict[str, Any]] = []

    def read(self, address: int, size: int, label: str) -> bytes:
        valid = (type(address) is int and MIN_USER_ADDRESS <= address < MAX_USER_ADDRESS_EXCLUSIVE
                 and type(size) is int and 0 < size <= MAX_SINGLE_READ_BYTES
                 and address <= MAX_USER_ADDRESS_EXCLUSIVE - size
                 and isinstance(label, str) and bool(label))
        if not valid:
            self.read_log.append({"address": hex(address) if type(address) is int else None,
                                  "size": size if type(size) is int else None,
                                  "label": label if isinstance(label, str) else None,
                                  "status": "rejected", "reason": "READ_REQUEST_INVALID"})
            raise _LeafFailure("READ_REQUEST_INVALID")
        if self.calls >= MAX_READ_CALLS or self.bytes_requested + size > MAX_TOTAL_READ_BYTES:
            self.read_log.append({"address": hex(address), "size": size, "label": label,
                                  "status": "rejected", "reason": "READ_BUDGET_EXCEEDED"})
            raise _LeafFailure("READ_BUDGET_EXCEEDED")
        self.calls += 1
        self.bytes_requested += size
        self.max_single = max(self.max_single, size)
        try:
            method = getattr(self.source, "read", None)
            raw = method(address, size, label) if callable(method) else self.source(address, size, label)
        except Exception as exc:
            self.read_log.append({"address": hex(address), "size": size, "label": label,
                                  "status": "failed", "error_type": type(exc).__name__})
            raise _LeafFailure("READ_FAILED") from exc
        if not isinstance(raw, (bytes, bytearray, memoryview)) or len(raw) != size:
            actual = len(raw) if isinstance(raw, (bytes, bytearray, memoryview)) else None
            self.read_log.append({"address": hex(address), "size": size, "label": label,
                                  "status": "failed", "error_type": "short_or_invalid_read",
                                  "actual_size": actual})
            raise _LeafFailure("READ_FAILED")
        raw = bytes(raw)
        self.read_log.append({"address": hex(address), "size": size, "label": label,
                              "status": "ok", "raw_hex": raw.hex()})
        return raw

    def summary(self) -> dict[str, int]:
        return {"calls": self.calls, "bytes_requested": self.bytes_requested,
                "max_single_read": self.max_single, "max_calls": MAX_READ_CALLS,
                "max_total_bytes": MAX_TOTAL_READ_BYTES,
                "max_single_read_bytes": MAX_SINGLE_READ_BYTES}


def _is_user(address: Any, size: int = 1) -> bool:
    return (type(address) is int and type(size) is int and size > 0
            and MIN_USER_ADDRESS <= address < MAX_USER_ADDRESS_EXCLUSIVE
            and address <= MAX_USER_ADDRESS_EXCLUSIVE - size)


def _checked_add(base: int, offset: int, size: int, label: str) -> int:
    if (type(base) is not int or not _is_user(base) or type(offset) is not int
            or offset < 0 or type(size) is not int or size <= 0
            or base > MAX_U64 - offset):
        raise _LeafFailure("ADDRESS_INVALID:" + label)
    address = base + offset
    if not _is_user(address, size):
        raise _LeafFailure("ADDRESS_INVALID:" + label)
    return address


def _pointer(value: Any, label: str, *, allow_null: bool = False,
             aligned: bool = True) -> int:
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise _LeafFailure("POINTER_INVALID:" + label)
    if value == 0 and allow_null:
        return value
    if not _is_user(value) or (aligned and value & 7):
        raise _LeafFailure("POINTER_INVALID:" + label)
    return value


def _read_exact(reader: _BudgetReader, address: int, size: int, label: str) -> bytes:
    if not _is_user(address, size) or size > MAX_SINGLE_READ_BYTES:
        raise _LeafFailure("ADDRESS_INVALID:" + label)
    raw = reader.read(address, size, label)
    if len(raw) != size:
        raise _LeafFailure("READ_FAILED")
    return raw


def _read_u64(reader: _BudgetReader, address: int, label: str) -> tuple[int, bytes]:
    raw = _read_exact(reader, address, 8, label)
    return int.from_bytes(raw, "little", signed=False), raw


def _read_i32(reader: _BudgetReader, address: int, label: str) -> tuple[int, bytes]:
    raw = _read_exact(reader, address, 4, label)
    return int.from_bytes(raw, "little", signed=True), raw


def _wrap_i32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _parse_rva_key(value: Any) -> int:
    if not isinstance(value, str) or len(value) > 18:
        raise _LeafFailure("PREDICATE_PROFILE_INVALID")
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise _LeafFailure("PREDICATE_PROFILE_INVALID") from exc
    if not 0 <= parsed <= 0xFFFFFFFF:
        raise _LeafFailure("PREDICATE_PROFILE_INVALID")
    return parsed


def _normalize_predicate_profile(profile: Any) -> dict[str, Any]:
    if (not isinstance(profile, Mapping) or profile.get("schema") != PROFILE_SCHEMA
            or profile.get("executable_sha256") != EXE_SHA256):
        raise _LeafFailure("PREDICATE_PROFILE_INVALID")
    raw_vtables = profile.get("vtable_rvas")
    raw_methods = profile.get("method_guards")
    if not isinstance(raw_vtables, Mapping) or not isinstance(raw_methods, Mapping):
        raise _LeafFailure("PREDICATE_PROFILE_INVALID")
    vtables: dict[int, dict[str, int]] = {}
    for raw_rva, slot_map in raw_vtables.items():
        rva = _parse_rva_key(raw_rva)
        if rva in vtables or not isinstance(slot_map, Mapping):
            raise _LeafFailure("PREDICATE_PROFILE_INVALID")
        if set(slot_map) != {"slot_80", "slot_88"}:
            raise _LeafFailure("PREDICATE_PROFILE_INVALID")
        vtables[rva] = {slot: _parse_rva_key(slot_map[slot])
                        for slot in ("slot_80", "slot_88")}
    methods: dict[int, dict[str, Any]] = {}
    for raw_rva, item in raw_methods.items():
        rva = _parse_rva_key(raw_rva)
        if rva in methods or not isinstance(item, Mapping):
            raise _LeafFailure("PREDICATE_PROFILE_INVALID")
        body_hex = item.get("body_hex")
        boolean = item.get("constant_boolean_return")
        try:
            body = bytes.fromhex(body_hex) if isinstance(body_hex, str) else b""
        except ValueError as exc:
            raise _LeafFailure("PREDICATE_PROFILE_INVALID") from exc
        if len(body) != 3 or type(boolean) is not bool:
            raise _LeafFailure("PREDICATE_PROFILE_INVALID")
        methods[rva] = {"body_hex": body.hex(), "constant_boolean_return": boolean}

    expected_vtables = {
        rva: {slot: method for slot, method in slots.items()}
        for rva, slots in _EXPECTED_VTABLES.items()
    }
    expected_methods = {
        rva: {"body_hex": item["body_hex"],
              "constant_boolean_return": item["constant_boolean_return"]}
        for rva, item in _EXPECTED_METHODS.items()
    }
    if vtables != expected_vtables or methods != expected_methods:
        raise _LeafFailure("PREDICATE_PROFILE_NOT_SUPPORTED")
    return {
        "schema": PROFILE_SCHEMA, "executable_sha256": EXE_SHA256,
        "vtable_rvas": {hex(rva): {slot: hex(method) for slot, method in slots.items()}
                        for rva, slots in vtables.items()},
        "method_guards": {hex(rva): dict(item) for rva, item in methods.items()},
        "evidence_pins": deepcopy(profile.get("evidence_pins", [])),
    }


def _field_shell(field: str, status: str, reason: str | None = None,
                 raw_inputs: Mapping[str, Any] | None = None) -> dict[str, Any]:
    is_army = field == FIELD_ARMY
    result: dict[str, Any] = {
        "status": status, "complete": False, "partial": True,
        "basis": ARMY_BASIS if is_army else NAVY_BASIS,
        "unit": "soldiers" if is_army else "ships", "scale": 1,
    }
    if reason is not None:
        result["reason"] = reason
    if raw_inputs is not None:
        result["raw_inputs"] = deepcopy(dict(raw_inputs))
    return result


def _unknown_for(field: str, reason: str,
                 raw_inputs: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return _field_shell(field, "unknown", reason, raw_inputs)


def _invisible_for(field: str, reason: str,
                   raw_inputs: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return _field_shell(field, "invisible", reason, raw_inputs)


def _known_army(value: int, record_count: int,
                raw_inputs: Mapping[str, Any]) -> dict[str, Any]:
    result = _field_shell(FIELD_ARMY, "known", raw_inputs=raw_inputs)
    result.update({"value": value, "raw": value, "record_count": record_count})
    return result


def _known_navy(value: int, raw_inputs: Mapping[str, Any]) -> dict[str, Any]:
    result = _field_shell(FIELD_NAVY, "known", raw_inputs=raw_inputs)
    result.update({"value": value, "raw": value})
    return result


def _base_raw(target_binding: Mapping[str, Any], permission: Any,
              profile: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "target_binding": deepcopy(dict(target_binding)),
        "permission": deepcopy(permission),
        "predicate_profile": deepcopy(dict(profile)),
        "target_binding_revalidation": None,
        "chain_head": None,
        "common_chain": [],
        "field_groups": [],
        "errors": [],
        "arithmetic": None,
    }


def _method_return(reader: _BudgetReader, base: int, vtable: int,
                   slot_name: str, slot_offset: int,
                   expected_method_rva: Any,
                   profile: Mapping[str, Any], label: str) -> tuple[bool, dict[str, Any]]:
    try:
        expected_method_rva = _parse_rva_key(expected_method_rva)
    except _LeafFailure as exc:
        raise _LeafFailure("PREDICATE_PROFILE_INVALID") from exc
    method_address = _checked_add(vtable, slot_offset, 8, label + ".method_cell")
    method_va, pointer_raw = _read_u64(reader, method_address, label + ".method_pointer")
    method_va = _pointer(method_va, label + ".method", aligned=False)
    method_rva = method_va - base
    if method_rva != expected_method_rva:
        raise _LeafFailure("METHOD_POINTER_NOT_PROFILED_FOR_SLOT")
    normalized_guards = profile["method_guards"]
    expected = normalized_guards.get(hex(method_rva))
    if not isinstance(expected, Mapping):
        raise _LeafFailure("METHOD_RVA_NOT_PROFILED")
    expected_va = _checked_add(base, method_rva, 3, label + ".method_code")
    if method_va != expected_va:
        raise _LeafFailure("METHOD_POINTER_INVALID")
    code = _read_exact(reader, method_va, 3, label + ".method_guard3")
    if code.hex() != expected.get("body_hex"):
        raise _LeafFailure("METHOD_ROM_GUARD_MISMATCH")
    expected_return = expected.get("constant_boolean_return")
    if type(expected_return) is not bool:
        raise _LeafFailure("METHOD_RETURN_PROFILE_INVALID")
    return expected_return, {
        "slot": slot_name, "method_pointer_raw_hex": pointer_raw.hex(),
        "method_va": hex(method_va), "method_rva": hex(method_rva),
        "method_code_raw_hex": code.hex(), "method_guard_bytes": 3,
        "constant_boolean_return": expected_return,
        "profile_guard_match": True,
    }


def _vector_header(reader: _BudgetReader, group: int, index: int,
                   field: str) -> tuple[dict[str, Any], int, int]:
    begin_address = _checked_add(group, GROUP_VECTOR_BEGIN_OFFSET, 8,
                                 f"group[{index}].{field}.vector_begin")
    end_address = _checked_add(group, GROUP_VECTOR_END_OFFSET, 8,
                               f"group[{index}].{field}.vector_end")
    begin, begin_raw = _read_u64(reader, begin_address,
        f"force_statistics.group[{index}].{field}.vector_begin")
    end, end_raw = _read_u64(reader, end_address,
        f"force_statistics.group[{index}].{field}.vector_end")
    if (begin == 0) != (end == 0):
        raise _LeafFailure("VECTOR_ENDPOINT_NULL_MISMATCH")
    if begin == end == 0:
        count = 0
    else:
        begin = _pointer(begin, f"group[{index}].{field}.vector_begin")
        end = _pointer(end, f"group[{index}].{field}.vector_end")
        if end < begin or (end - begin) % VECTOR_STRIDE:
            raise _LeafFailure("VECTOR_RANGE_INVALID")
        count = (end - begin) // VECTOR_STRIDE
        if count > MAX_VECTOR_ELEMENTS:
            raise _LeafFailure("VECTOR_ELEMENT_LIMIT_EXCEEDED")
    return ({"begin_address": hex(begin_address), "begin_raw_hex": begin_raw.hex(),
             "end_address": hex(end_address), "end_raw_hex": end_raw.hex(),
             "begin": hex(begin) if begin else None, "end": hex(end) if end else None,
             "element_stride_bytes": VECTOR_STRIDE, "count": count}, begin, end)


def _overlap(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def _read_army_group(reader: _BudgetReader, group: int, index: int,
                     existing_records: set[int], existing_ranges: list[tuple[int, int]],
                     remaining_record_cap: int) -> tuple[dict[str, Any], int, int]:
    vector, begin, end = _vector_header(reader, group, index, "army")
    count = vector["count"]
    if count > remaining_record_cap:
        raise _LeafFailure("RECORD_LIMIT_EXCEEDED")
    vector_range = (begin, end) if count else None
    if vector_range and any(_overlap(vector_range, item) for item in existing_ranges):
        raise _LeafFailure("VECTOR_METADATA_ALIAS")
    records: list[dict[str, Any]] = []
    total = 0
    for row_index in range(count):
        pointer_cell = _checked_add(begin, row_index * VECTOR_STRIDE, 8,
                                    f"group[{index}].army.record[{row_index}].pointer_cell")
        pointer, pointer_raw = _read_u64(reader, pointer_cell,
            f"force_statistics.group[{index}].army.record[{row_index}].pointer")
        pointer = _pointer(pointer, f"group[{index}].army.record[{row_index}]")
        if pointer in existing_records:
            raise _LeafFailure("DUPLICATE_RECORD_POINTER")
        if vector_range and _overlap((pointer, pointer + RECORD_STRENGTH_OFFSET + 4), vector_range):
            raise _LeafFailure("RECORD_VECTOR_ALIAS")
        if any(_overlap((pointer, pointer + RECORD_STRENGTH_OFFSET + 4), item)
               for item in existing_ranges):
            raise _LeafFailure("RECORD_METADATA_ALIAS")
        existing_records.add(pointer)
        strength_address = _checked_add(pointer, RECORD_STRENGTH_OFFSET, 4,
                                        f"group[{index}].army.record[{row_index}].strength")
        strength, strength_raw = _read_i32(reader, strength_address,
            f"force_statistics.group[{index}].army.record[{row_index}].strength_i32")
        total = _wrap_i32(total + strength)
        records.append({
            "vector_index": row_index, "pointer_cell": hex(pointer_cell),
            "pointer_raw_hex": pointer_raw.hex(), "record_pointer": hex(pointer),
            "strength_address": hex(strength_address), "strength_raw_hex": strength_raw.hex(),
            "strength_i32": strength,
        })
    vector["records_read"] = count
    return {"vector": vector, "records": records, "signed_i32_low32_sum": total}, count, total


def _read_navy_group(reader: _BudgetReader, group: int, index: int,
                     existing_ranges: list[tuple[int, int]],
                     remaining_element_cap: int) -> tuple[dict[str, Any], int]:
    vector, _begin, _end = _vector_header(reader, group, index, "navy")
    count = vector["count"]
    if count > remaining_element_cap:
        raise _LeafFailure("VECTOR_ELEMENT_LIMIT_EXCEEDED")
    if count and any(_overlap((_begin, _end), item) for item in existing_ranges):
        raise _LeafFailure("VECTOR_METADATA_ALIAS")
    vector["elements_read"] = False
    vector["record_strength_read"] = False
    return {"vector": vector}, count


def _read_group_chain(reader: _BudgetReader, base: int, target_pointer: int,
                      target_binding: Mapping[str, Any], permission: Any,
                      predicate_profile: Mapping[str, Any],
                      requested: set[str], target_evidence: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    army_requested = FIELD_ARMY in requested
    navy_requested = FIELD_NAVY in requested
    common_chain: list[dict[str, Any]] = []
    army_groups: list[dict[str, Any]] = []
    navy_groups: list[dict[str, Any]] = []
    ignored_groups: list[dict[str, Any]] = []
    army_total = 0
    army_records_count = 0
    navy_total = 0
    navy_elements_count = 0
    army_error: str | None = None
    navy_error: str | None = None
    common_error: str | None = None
    base_raw = _base_raw(target_binding, permission, predicate_profile)
    base_raw["target_binding_revalidation"] = deepcopy(dict(target_evidence))

    try:
        head_address = _checked_add(target_pointer, COUNTRY_GROUP_HEAD_OFFSET, 8,
                                    "country.group_head")
        head, head_raw = _read_u64(reader, head_address, "force_statistics.country.group_head")
        base_raw["chain_head"] = {"address": hex(head_address), "raw_hex": head_raw.hex(),
                                   "pointer": hex(head)}
        if head == 0:
            return {
                field: (_known_army(0, 0, {**deepcopy(base_raw), "common_chain": [],
                                          "field_groups": [], "arithmetic": {
                                              "sum_rule": "signed_i32_low32_after_each_add",
                                              "sum_raw": 0, "display_input_raw": 0,
                                              "display_input_raw_i32_hex": "0x00000000"}})
                        if field == FIELD_ARMY else
                        _known_navy(0, {**deepcopy(base_raw), "common_chain": [],
                                        "field_groups": [], "arithmetic": {
                                            "count_rule": "vector_length_divided_by_8_low32_sum",
                                            "count_raw": 0}}))
                for field in requested
            }

        node = _pointer(head, "chain_head")
        seen_nodes: set[int] = set()
        seen_groups: set[int] = set()
        seen_vtables: set[int] = set()
        vtable_ranges: list[tuple[int, int]] = []
        seen_records: set[int] = set()
        object_ranges: list[tuple[int, int]] = [
            (target_pointer, target_pointer + COUNTRY_GROUP_HEAD_OFFSET + 8)]
        index = 0
        while node != 0:
            if index >= MAX_CHAIN_NODES:
                raise _LeafFailure("CHAIN_NODE_LIMIT_EXCEEDED")
            node = _pointer(node, f"node[{index}]")
            if node in seen_nodes:
                raise _LeafFailure("CHAIN_NODE_CYCLE_OR_DUPLICATE")
            node_range = (node, node + 0x18)
            if any(_overlap(node_range, item) for item in [*object_ranges, *vtable_ranges]):
                raise _LeafFailure("CHAIN_NODE_ALIAS")
            seen_nodes.add(node)
            group_pointer, group_raw = _read_u64(reader,
                _checked_add(node, NODE_GROUP_OFFSET, 8, f"node[{index}].group_cell"),
                f"force_statistics.node[{index}].group_pointer")
            next_node, next_raw = _read_u64(reader,
                _checked_add(node, NODE_NEXT_OFFSET, 8, f"node[{index}].next_cell"),
                f"force_statistics.node[{index}].next_pointer")
            group_pointer = _pointer(group_pointer, f"node[{index}].group")
            if group_pointer in seen_groups:
                raise _LeafFailure("DUPLICATE_GROUP_POINTER")
            if group_pointer in seen_nodes or group_pointer == node:
                raise _LeafFailure("GROUP_NODE_ALIAS")
            group_range = (group_pointer, group_pointer + 0x40)
            if _overlap(group_range, node_range) or any(
                    _overlap(group_range, item) for item in [*object_ranges, *vtable_ranges]):
                raise _LeafFailure("GROUP_RANGE_ALIAS")
            seen_groups.add(group_pointer)
            object_ranges.extend((node_range, group_range))
            vtable, vtable_raw = _read_u64(reader,
                _checked_add(group_pointer, GROUP_VTABLE_OFFSET, 8, f"group[{index}].vtable_cell"),
                f"force_statistics.group[{index}].vtable_pointer")
            vtable = _pointer(vtable, f"group[{index}].vtable")
            if vtable in seen_nodes or vtable in seen_groups:
                raise _LeafFailure("VTABLE_OBJECT_ALIAS")
            if vtable < base:
                raise _LeafFailure("VTABLE_RVA_INVALID")
            vtable_rva = vtable - base
            vtable_profile = predicate_profile["vtable_rvas"].get(hex(vtable_rva))
            if not isinstance(vtable_profile, Mapping):
                raise _LeafFailure("VTABLE_NOT_PROFILED")
            vtable_range = (vtable, vtable + 0x90)
            if any(_overlap(vtable_range, item) for item in object_ranges):
                raise _LeafFailure("VTABLE_RANGE_ALIAS")
            if any(_overlap(vtable_range, item) and vtable_range != item
                   for item in vtable_ranges):
                raise _LeafFailure("VTABLE_RANGE_OVERLAP")
            if vtable not in seen_vtables:
                seen_vtables.add(vtable)
                vtable_ranges.append(vtable_range)
            slot_80_method = vtable_profile.get("slot_80")
            slot_80, slot_80_evidence = _method_return(
                reader, base, vtable, "slot_80", VTABLE_SLOT_80_OFFSET, slot_80_method,
                predicate_profile, f"force_statistics.group[{index}].slot_80")
            common_row = {
                "index": index, "node_pointer": hex(node),
                "node_group_raw_hex": group_raw.hex(), "next_pointer_raw_hex": next_raw.hex(),
                "group_pointer": hex(group_pointer), "vtable_pointer_raw_hex": vtable_raw.hex(),
                "vtable_pointer": hex(vtable), "vtable_rva": hex(vtable_rva),
                "slot_80": slot_80_evidence,
            }
            army_common = deepcopy(common_row)
            navy_common = deepcopy(common_row)
            if slot_80:
                army_common["branch"] = "slot_80_true_native_soldier_branch"
                navy_common["branch"] = "excluded_by_slot_80_true_short_circuit"
                if army_requested and army_error is None:
                    try:
                        remaining = MAX_RECORDS - army_records_count
                        field_group, count, contribution = _read_army_group(
                            reader, group_pointer, index, seen_records,
                            [*object_ranges, *vtable_ranges], remaining)
                        army_records_count += count
                        army_total = _wrap_i32(army_total + contribution)
                        field_group["selection_path"] = "slot_80_true"
                        field_group["group_pointer"] = hex(group_pointer)
                        army_groups.append(field_group)
                    except _LeafFailure as exc:
                        army_error = exc.reason
                        army_groups.append({"group_pointer": hex(group_pointer),
                                            "failure": exc.reason,
                                            "failed_read": deepcopy(reader.read_log[-1])
                                                if reader.read_log else None})
            else:
                army_common["branch"] = "excluded_by_slot_80_false"
                if navy_requested:
                    try:
                        slot_88, slot_88_evidence = _method_return(
                            reader, base, vtable, "slot_88", VTABLE_SLOT_88_OFFSET,
                            vtable_profile.get("slot_88"),
                            predicate_profile, f"force_statistics.group[{index}].slot_88")
                        navy_common["slot_88"] = slot_88_evidence
                        if slot_88:
                            navy_common["branch"] = "slot_80_false_slot_88_true_native_ship_branch"
                            if navy_error is None:
                                try:
                                    remaining = MAX_VECTOR_ELEMENTS - navy_elements_count
                                    field_group, count = _read_navy_group(
                                        reader, group_pointer, index,
                                        [*object_ranges, *vtable_ranges], remaining)
                                    navy_elements_count += count
                                    navy_total = _wrap_i32(navy_total + count)
                                    field_group["selection_path"] = "slot_80_false_slot_88_true"
                                    field_group["group_pointer"] = hex(group_pointer)
                                    navy_groups.append(field_group)
                                except _LeafFailure as exc:
                                    navy_error = exc.reason
                                    navy_groups.append({"group_pointer": hex(group_pointer),
                                                        "failure": exc.reason,
                                                        "failed_read": deepcopy(reader.read_log[-1])
                                                            if reader.read_log else None})
                        else:
                            navy_common["branch"] = "slot_80_false_slot_88_false_native_ignored"
                            ignored_groups.append({"group_pointer": hex(group_pointer),
                                                   "index": index,
                                                   "selection_path": "slot_80_false_slot_88_false"})
                    except _LeafFailure as exc:
                        navy_error = navy_error or exc.reason
                        navy_common["slot_88_failure"] = exc.reason
                        navy_common["slot_88_failed_read"] = (
                            deepcopy(reader.read_log[-1]) if reader.read_log else None)
                else:
                    navy_common["branch"] = "slot_88_not_read_not_requested"

            common_chain.append({"army": army_common, "navy": navy_common})
            if next_node != 0:
                next_node = _pointer(next_node, f"node[{index}].next")
                if next_node in seen_nodes or next_node in seen_groups:
                    raise _LeafFailure("CHAIN_NEXT_CYCLE_OR_DUPLICATE")
            node = next_node
            index += 1
    except _LeafFailure as exc:
        common_error = exc.reason
    except Exception as exc:
        common_error = "STRUCTURE_READ_FAILED:" + type(exc).__name__

    output: dict[str, dict[str, Any]] = {}
    for field in requested:
        raw = deepcopy(base_raw)
        branch_key = "army" if field == FIELD_ARMY else "navy"
        raw["common_chain"] = [entry[branch_key] for entry in common_chain]
        if field == FIELD_ARMY:
            raw["field_groups"] = deepcopy(army_groups)
            display_input_raw = _wrap_i32(army_total * 1000)
            raw["arithmetic"] = {
                "sum_rule": "signed_i32_low32_after_each_add",
                "sum_raw": army_total, "record_count": army_records_count,
                "display_input_raw": display_input_raw,
                "display_input_raw_i32_hex": f"0x{display_input_raw & 0xFFFFFFFF:08x}",
                "display_multiplier": 1000,
            }
            if common_error:
                raw["errors"].append(common_error)
                raw["common_failure_read"] = deepcopy(reader.read_log[-1]) if reader.read_log else None
                output[field] = _unknown_for(field, common_error, raw)
            elif army_error:
                raw["errors"].append(army_error)
                output[field] = _unknown_for(field, army_error, raw)
            else:
                output[field] = _known_army(army_total, army_records_count, raw)
        elif field == FIELD_NAVY:
            raw["field_groups"] = deepcopy(navy_groups)
            raw["ignored_groups"] = deepcopy(ignored_groups)
            raw["arithmetic"] = {
                "count_rule": "vector_length_divided_by_8_low32_sum",
                "count_raw": navy_total, "derived_element_count": navy_elements_count,
                "record_elements_read": False,
            }
            if common_error:
                raw["errors"].append(common_error)
                raw["common_failure_read"] = deepcopy(reader.read_log[-1]) if reader.read_log else None
                output[field] = _unknown_for(field, common_error, raw)
            elif navy_error:
                raw["errors"].append(navy_error)
                output[field] = _unknown_for(field, navy_error, raw)
            else:
                output[field] = _known_navy(navy_total, raw)
    return output


def read_fields(reader: Any, base: int, target_binding: Mapping[str, Any],
                fields: tuple[str, ...] | list[str], *, permission: Any = None,
                predicate_profile: Any = None) -> dict[str, dict[str, Any]]:
    """Read the requested soldier/ship statistics after permission and binding checks.

    This pure leaf uses the real foreign military visibility receipt supplied by
    its parent.  It does not open a process, resolve a full country table, read
    native function bodies from disk, or call a native method.
    """
    if not isinstance(fields, (tuple, list)) or len(fields) > 16 or any(
            not isinstance(field, str) or not field for field in fields):
        return {field: _unknown_for(field, "FIELDS_SHAPE_INVALID")
                for field in FIELDS}
    if len(set(fields)) != len(fields):
        return {field: _unknown_for(field, "DUPLICATE_FIELD_REQUESTED")
                for field in fields if field in FIELDS}
    output = {field: _unknown_for(field, "UNSUPPORTED_FIELD")
              for field in fields if field not in FIELDS}
    requested = {field for field in fields if field in FIELDS}
    if not requested:
        return output
    if (type(base) is not int or not _is_user(base) or base & 7):
        return {field: _unknown_for(field, "MODULE_BASE_INVALID") for field in requested} | output
    try:
        profile = _normalize_predicate_profile(predicate_profile)
    except _LeafFailure as exc:
        return {field: _unknown_for(field, exc.reason) for field in requested} | output
    try:
        parsed_base, target_pointer, retained = _country_binding._parse_target(base, target_binding)
        if parsed_base != base:
            raise ValueError("module_base_mismatch")
    except Exception:
        return {field: _unknown_for(field, "TARGET_BINDING_INVALID") for field in requested} | output

    permission_state, permission_reason = _manpower._permission_result(
        permission, base, retained)
    initial_raw = {
        "target_binding": deepcopy(retained),
        "permission": deepcopy(permission),
        "predicate_profile": deepcopy(profile),
        "permission_validation": {"status": permission_state, "reason": permission_reason},
    }
    if permission_state != "admitted":
        if permission_state == "invisible":
            blocked = {field: _invisible_for(field, "MILITARY_STATS_PERMISSION_DENIED", initial_raw)
                       for field in requested}
        else:
            blocked = {field: _unknown_for(field, "MILITARY_STATS_PERMISSION_UNKNOWN", initial_raw)
                       for field in requested}
        return blocked | output

    limiter = _BudgetReader(reader)
    try:
        target_validation = _country_binding._validate_target_binding(
            limiter, base, target_pointer, retained)
    except Exception as exc:
        failed = dict(initial_raw)
        failed.update({"target_binding_revalidation": {
            "status": "failed", "error_type": type(exc).__name__},
            "field_local_read_log": deepcopy(limiter.read_log)})
        return {field: _unknown_for(field, "TARGET_BINDING_REVALIDATION_FAILED", failed)
                for field in requested} | output

    result = _read_group_chain(limiter, base, target_pointer, retained, permission,
                               profile, requested, target_validation)
    return {**output, **result}


__all__ = [
    "SCHEMA", "PROFILE_SCHEMA", "FIELD_ARMY", "FIELD_NAVY", "FIELDS",
    "read_fields", "MAX_READ_CALLS", "MAX_TOTAL_READ_BYTES",
    "MAX_SINGLE_READ_BYTES", "MAX_CHAIN_NODES", "MAX_RECORDS",
]
