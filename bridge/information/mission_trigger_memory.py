"""Bounded RPM capture and evaluation of loaded mission trigger trees.

Only already-observed task pointers are followed.  This module reads the
current process through the supplied reader; it never opens a process, invokes
native code, or consults on-disk mission definitions.
"""
from __future__ import annotations

from typing import Any, Mapping

from . import mission_condition_memory as _mission_condition_memory
from . import country_reference_memory as _country_reference_memory
from . import mission_prerequisite_memory as _mission_prerequisite_memory
from . import mission_task_memory as _mission_task_memory
from .dlc_short_circuit_bindings import DLC_BINDINGS as _DLC_BINDINGS
from .mission_trigger_selection import select_tasks


ROOT_GROUP_VTABLE_RVA = 0x1C38010
GROUP_PARSER_VTABLE_RVA = 0x1C37FD0
GROUP_PARSER_CALLBACK_RVA = 0xB8B550
GROUP_PARSER_CALLBACK_SLOT = 0x20

GROUP_DATA_OFFSET = 0x08
GROUP_CAPACITY_OFFSET = 0x10
GROUP_COUNT_OFFSET = 0x14
GROUP_INLINE_OFFSET = 0x18
GROUP_PARSER_OFFSET = 0x38
TASK_TRIGGER_OFFSET = 0x70
GROUP_EVALUATE_SLOT = 0x30
NODE_TOKEN_OFFSET = 0x50
NODE_LITERAL_FLAGS_OFFSET = 0x4F
NODE_DYNAMIC_FLAGS_OFFSET = 0x60
NODE_THRESHOLD_OFFSET = 0x68
NODE_HEAD_BYTES = 0x70
NODE_LITERAL_HEAD_OFFSET = 0x48
NODE_LITERAL_HEAD_BYTES = NODE_HEAD_BYTES - NODE_LITERAL_HEAD_OFFSET

AND_EVALUATE_RVA = 0xB98070
OR_EVALUATE_RVA = 0xB98420
NOR_EVALUATE_RVA = 0xB98780
SAILORS_EVALUATE_RVA = 0xCE12E0
EXPLORER_EVALUATE_RVA = 0xBFAB60
GALLEY_EVALUATE_RVA = 0xC154B0
ARMY_RATIO_EVALUATE_RVA = 0xC8F430
UNITY_EVALUATE_RVA = 0xC0CF10
COUNTRY_MODIFIER_EVALUATE_RVA = 0xC4E7D0
DLC_EVALUATE_RVA = 0xCC5FB0
COUNT_EVALUATE_RVA = 0xC2ED70
STORED_BOOLEAN_EVALUATE_RVA = 0x2C6A50
BOOLEAN_MATCH_EVALUATE_RVA = 0xB999A0
PROVINCE_ID_EVALUATE_RVA = 0xC9D610
MAX_COUNT_DOMAIN = 256
MAX_COUNT_SAMPLES = 4
MAX_COUNT_EVALUATION_OPS = 1024
DLC_TOKEN = 0x2E20
DOMINATION_DLC_MASK = 0x80000
PROVINCE_SCOPE_EVALUATE_RVA = 0xB98C60
GEOGRAPHIC_EVALUATE_RVA = 0xC1BCF0
PROVINCE_OWNED_EVALUATE_RVA = 0xC3C940
PROVINCE_CONTROLLED_EVALUATE_RVA = 0xC3D8B0
PROVINCE_HELD_EVALUATE_RVA = 0xBE9300
IF_EVALUATE_RVA = 0xDC7D80
PROVINCE_SCOPE_REFERENCE_OFFSET = 0x68
IF_LIMIT_OFFSET = 0x68
IF_ELSE_OFFSET = 0xE0
IF_ELSEIF_POINTER_OFFSET = 0x158
PROVINCE_REFERENCE_KIND = 0x0C
COUNTRY_REFERENCE_KIND = 0x0F
EMPEROR_REFERENCE_KIND = 0x2939
CAPITAL_REFERENCE_KIND = 0x2A01
PROVINCE_REFERENCE_ID_OFFSET = 0x208
PROVINCE_REFERENCE_COUNTRY_FLAG_OFFSET = 0x213
COUNTRY_REFERENCE_FULLREF_OFFSET = 0x20C
GEOGRAPHIC_QUANTIFIER_OFFSET = 0x88
GEOGRAPHIC_ALL_TYPE = 0x2CCB
ROOT_COUNTRY_FLAGS = 0x4002
MAX_PROVINCE_TARGETS = 128
MAX_GEOGRAPHIC_PROVINCE_IDS = 64

_PROVINCE_METHODS = {
    PROVINCE_OWNED_EVALUATE_RVA: ("owned_by", 0x29F9, "owner"),
    PROVINCE_CONTROLLED_EVALUATE_RVA: ("controlled_by", 0x2B6B, "controller"),
    PROVINCE_HELD_EVALUATE_RVA: ("country_or_non_sovereign_subject_holds", 0x3643, "owner"),
}

SAILORS_TOKEN = 0x33F0
EXPLORER_TOKEN = 0x2B60
GALLEY_TOKEN = 0x2B78
ARMY_RATIO_TOKEN = 0x2BB7
UNITY_TOKEN = 0x2BE7
COUNTRY_MODIFIER_TOKEN = 0x2A2D
SAILORS_CURRENT_OFFSET = 0xDC0
SAILORS_MAX_OFFSET = 0xDC4
EXPLORER_COUNTER_POINTER_OFFSET = 0x1F68
EXPLORER_COUNTER_OFFSET = 0x0C

INLINE_GROUP_CAPACITY = 4
MAX_GROUP_COUNT = 256
MAX_GROUP_CAPACITY = 4096
MAX_TOTAL_NODES = 2048
MAX_TREE_DEPTH = 32
MAX_MODULE_RVA = 0x2800000
MAX_METHOD_RVA = 0x1C00000
MAX_CAPTURED_TASKS = _mission_condition_memory.MAX_CAPTURED_TASKS
MAX_SINGLE_RPM = _mission_condition_memory.MAX_SINGLE_RPM
MAX_TOTAL_RPM = _mission_condition_memory.MAX_TOTAL_RPM

_LOGIC_METHODS = {
    AND_EVALUATE_RVA: "and",
    OR_EVALUATE_RVA: "or",
    NOR_EVALUATE_RVA: "nor",
}
_SCALAR_METHOD_TOKENS = {
    SAILORS_EVALUATE_RVA: ("sailors", SAILORS_TOKEN),
    EXPLORER_EVALUATE_RVA: ("explorer", EXPLORER_TOKEN),
    GALLEY_EVALUATE_RVA: ("galley", GALLEY_TOKEN),
    ARMY_RATIO_EVALUATE_RVA: ("army_ratio", ARMY_RATIO_TOKEN),
    UNITY_EVALUATE_RVA: ("unity", UNITY_TOKEN),
}


def _unknown(reason: str, *, code_guards: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "status": "unknown",
        "complete": False,
        "reason": reason,
        "unknown_conditions": [reason],
        "code_guards": code_guards or [],
        "tasks": [],
        "_compare": None,
    }


def _module_pointer(pointer: int, module_base: int, label: str,
                    *, require_alignment: bool = True) -> int:
    if (isinstance(pointer, bool) or not isinstance(pointer, int)
            or pointer < 0x10000 or pointer >= _mission_task_memory.MAX_USER_ADDRESS
            or (require_alignment and pointer & 7)
            or not module_base <= pointer < module_base + MAX_MODULE_RVA):
        raise ValueError(f"{label}_outside_module_range")
    return pointer


def _read_exact(reader: Any, address: int, size: int, label: str) -> bytes:
    raw = _mission_task_memory._read_unaligned(reader, address, size, label)
    if not isinstance(raw, bytes) or len(raw) != size:
        raise ValueError(f"{label}_short_read")
    return raw


def _read_u32(reader: Any, address: int, label: str) -> int:
    raw = _read_exact(reader, address, 4, label)
    return int.from_bytes(raw, "little", signed=False)


def _read_s32(reader: Any, address: int, label: str) -> int:
    raw = _read_exact(reader, address, 4, label)
    return int.from_bytes(raw, "little", signed=True)


def _read_qword(reader: Any, address: int, label: str) -> int:
    return reader.qword(address, label)[0]


def _wrap_s32(value: int) -> int:
    wrapped = value & 0xFFFFFFFF
    return wrapped - 0x100000000 if wrapped & 0x80000000 else wrapped


def _truncating_division(numerator: int, denominator: int) -> int:
    if denominator == 0:
        raise ZeroDivisionError
    magnitude = abs(numerator) // abs(denominator)
    return -magnitude if (numerator < 0) != (denominator < 0) else magnitude


def _evaluation(value: bool | None, reason: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "known" if value is not None else "unknown",
        "satisfied": value,
    }
    if reason is not None:
        result["reason"] = reason
    return result


def _count_result(lower: int, upper: int, threshold: int) -> bool | None:
    # The native loop increments a matching member before its comparison.
    # An empty domain (or zero matches) is false, even for threshold <= 0.
    if lower > 0 and lower >= threshold:
        return True
    if upper == 0 or upper < threshold:
        return False
    return None


class _NodeMetadataCache:
    """Share only explicitly routed node bytes within one outer snapshot.

    State, visibility and country inputs bypass this cache. A second outer
    pass creates its own instance; this sampling does not imply atomicity.
    """
    def __init__(self, tracked: Any, module_base: int):
        self._tracked = tracked
        self.module_base = module_base
        self._bytes: dict[tuple[int, int], bytes] = {}
        self.bytes_cached = 0
        self.hits = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        key = (address, size)
        if key in self._bytes:
            self.hits += 1
            return self._bytes[key]
        raw = _read_exact(self._tracked, address, size, label)
        if len(self._bytes) < 8192 and self.bytes_cached + size <= 256 * 1024:
            self._bytes[key] = raw
            self.bytes_cached += size
        return raw

    read_code = read

    def qword(self, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(address, 8, label)
        return int.from_bytes(raw, 'little'), raw


def _subject_holds(reader: Any, owner_pointer: int, root_reference: int,
                   label: str) -> tuple[bool | None, str | None]:
    """Reproduce only BE9300's bounded ordinary owner/subject criterion.

    3D7A20 selects a per-country relation pair and then the first matching
    16-byte record. It returns the pointer stored at record+8 -> +40.
    We add explicit pointer/count bounds; a failed bound is unknown.
    """
    if not _mission_task_memory._valid_pointer(owner_pointer):
        return None, "province_owner_pointer_unverified"
    parent = _read_qword(reader, owner_pointer + 0x18F0, f"{label}.owner_parent_reference")
    slot = (parent >> 32) & 0xFFFF
    if slot != (root_reference >> 32) & 0xFFFF:
        return False, None
    if parent >> 56 == 0:
        return False, None
    subject_type, reason = _subject_type_pointer(reader, owner_pointer, parent, label)
    if subject_type is None:
        return None, reason
    if subject_type == 0:
        return False, None
    flags = _read_exact(reader, subject_type + 0x151, 2, f"{label}.subject_type_native_flags")
    return any(flags), None


def _subject_type_pointer(reader: Any, owner_pointer: int, parent: int,
                          label: str) -> tuple[int | None, str | None]:
    """Reuse the retained3D7A20 relation lookup without choosing its flags."""
    slot = (parent >> 32) & 0xFFFF
    if slot >= 0x8000:
        return None, "subject_relation_index_out_of_bound"
    table = _read_qword(reader, owner_pointer + 0x1510, f"{label}.owner_relation_table")
    if not _mission_task_memory._valid_pointer(table):
        return None, "subject_relation_table_invalid"
    pair = table + slot * 72
    relation = _read_qword(reader, pair, f"{label}.owner_relation")
    reference = _read_qword(reader, pair + 0x10, f"{label}.relation_lookup_reference")
    if not _mission_task_memory._valid_pointer(relation):
        return None, "subject_relation_pointer_invalid"
    key = (reference >> 32) & 0xFFFF
    if key >= 0x8000:
        key -= 0x10000
    data = _read_qword(reader, relation + 0x128, f"{label}.relation_records")
    count = _read_s32(reader, relation + 0x134, f"{label}.relation_record_count")
    if not 0 <= count <= 256:
        return None, "subject_relation_record_count_out_of_bound"
    if count == 0:
        return 0, None
    if not _mission_task_memory._valid_pointer(data):
        return None, "subject_relation_records_invalid"
    rows = _read_exact(reader, data, count * 16, f"{label}.relation_record_entries")
    for index in range(count):
        row = rows[index * 16:(index + 1) * 16]
        if int.from_bytes(row[:4], "little", signed=True) != key:
            continue
        holder = int.from_bytes(row[8:16], "little")
        if holder == 0:
            return 0, None
        if not _mission_task_memory._valid_pointer(holder):
            return None, "subject_relation_holder_invalid"
        subject_type = _read_qword(reader, holder + 0x40, f"{label}.subject_type")
        if subject_type == 0:
            return 0, None
        if not _mission_task_memory._valid_pointer(subject_type):
            return None, "subject_type_pointer_invalid"
        return subject_type, None
    return 0, None


def _combine(kind: str, children: list[dict[str, Any]]) -> dict[str, Any]:
    values = [child["evaluation"]["satisfied"] for child in children]
    if kind == "and":
        if any(value is False for value in values):
            return _evaluation(False)
        if all(value is True for value in values):
            return _evaluation(True)
    elif kind == "or":
        if any(value is True for value in values):
            return _evaluation(True)
        if all(value is False for value in values):
            return _evaluation(False)
    elif kind == "nor":
        if any(value is True for value in values):
            return _evaluation(False)
        if all(value is False for value in values):
            return _evaluation(True)
    else:  # pragma: no cover - guarded by the method dispatch table
        return _evaluation(None, "unsupported_logic_kind")
    return _evaluation(None, "child_evaluation_unknown")


def _public_pointer(pointer: int, module_base: int) -> dict[str, Any]:
    return _mission_task_memory._address(pointer, module_base)


def _unknown_tree_conditions(tasks: list[dict[str, Any]]) -> list[str]:
    conditions: list[str] = []

    def walk(node: Mapping[str, Any], path: str) -> None:
        evaluation = node.get("evaluation")
        if isinstance(evaluation, Mapping) and evaluation.get("status") == "unknown":
            reason = evaluation.get("reason")
            conditions.append(f"{path}:{reason or 'unknown'}")
        children = node.get("children")
        if isinstance(children, list):
            for index, child in enumerate(children):
                if isinstance(child, Mapping):
                    walk(child, f"{path}.children[{index}]")
        if node.get("kind") == "if":
            for name in ("limit", "then", "else"):
                branch = node.get(name)
                if isinstance(branch, Mapping):
                    walk(branch, f"{path}.{name}")
        if node.get('kind') == 'count' and isinstance(node.get('filter'), Mapping):
            walk(node['filter'], f'{path}.filter')
        if node.get('kind') == 'boolean_match' and isinstance(node.get('body'), Mapping):
            walk(node['body'], f'{path}.body')
        members = node.get("members")
        if isinstance(members, list):
            for index, member in enumerate(members):
                if isinstance(member, Mapping) and isinstance(member.get("tree"), Mapping):
                    walk(member["tree"], f"{path}.members[{index}].tree")

    for task in tasks:
        walk(task["tree"], f"{task['root_id']}:{task['task_id']}")
    return conditions


def _read_eval_method(reader: Any, module_base: int, node_pointer: int,
                      *, expected_root: bool = False) -> tuple[int, int, int]:
    vtable = _read_qword(reader, node_pointer, "mission_trigger.node.vtable")
    if not _mission_task_memory._valid_pointer(vtable):
        raise ValueError("mission_trigger.node_vtable_pointer_invalid")
    _module_pointer(vtable, module_base, "mission_trigger.node_vtable")
    method_slot = vtable + GROUP_EVALUATE_SLOT
    if method_slot + 8 > module_base + MAX_MODULE_RVA:
        raise ValueError("mission_trigger.evaluate_slot_outside_module_range")
    method = _read_qword(reader, method_slot, "mission_trigger.node.evaluate_method")
    _module_pointer(
        method, module_base, "mission_trigger.evaluate_method", require_alignment=False
    )
    method_rva = method - module_base
    if method_rva >= MAX_METHOD_RVA:
        raise ValueError("mission_trigger.evaluate_method_outside_code_range")
    if expected_root and vtable != module_base + ROOT_GROUP_VTABLE_RVA:
        raise ValueError("mission_trigger.root_group_vtable_mismatch")
    return vtable, method, method_rva


def _read_group_contract(reader: Any, module_base: int, group_pointer: int,
                         label: str, *, verify_parser: bool) -> dict[str, Any]:
    raw = _read_exact(reader, group_pointer, 0x18, f"{label}.header")
    vtable = int.from_bytes(raw[:8], "little")
    data = int.from_bytes(raw[GROUP_DATA_OFFSET:GROUP_DATA_OFFSET + 8], "little")
    capacity = int.from_bytes(
        raw[GROUP_CAPACITY_OFFSET:GROUP_CAPACITY_OFFSET + 4], "little", signed=True
    )
    count = int.from_bytes(
        raw[GROUP_COUNT_OFFSET:GROUP_COUNT_OFFSET + 4], "little", signed=True
    )
    _module_pointer(vtable, module_base, f"{label}.vtable")
    if capacity < 0 or capacity > MAX_GROUP_CAPACITY:
        raise ValueError(f"{label}_capacity_out_of_bound")
    if count < 0 or count > MAX_GROUP_COUNT or count > capacity:
        raise ValueError(f"{label}_count_out_of_bound")

    inline_pointer = group_pointer + GROUP_INLINE_OFFSET
    if capacity <= INLINE_GROUP_CAPACITY:
        if data != inline_pointer and not (capacity == 0 and count == 0 and data == 0):
            raise ValueError(f"{label}_inline_data_pointer_mismatch")
    elif not _mission_task_memory._valid_pointer(data):
        raise ValueError(f"{label}_heap_data_pointer_invalid")

    parser_vtable = None
    callback = None
    if verify_parser:
        parser_vtable = _read_qword(
            reader, group_pointer + GROUP_PARSER_OFFSET, f"{label}.parser_vtable"
        )
        _module_pointer(parser_vtable, module_base, f"{label}.parser_vtable")
        if parser_vtable != module_base + GROUP_PARSER_VTABLE_RVA:
            raise ValueError(f"{label}_parser_vtable_mismatch")
        callback = _read_qword(
            reader,
            parser_vtable + GROUP_PARSER_CALLBACK_SLOT,
            f"{label}.parser_callback",
        )
        if callback != module_base + GROUP_PARSER_CALLBACK_RVA:
            raise ValueError(f"{label}_parser_callback_mismatch")

    entries_raw = b""
    children: list[int] = []
    if count:
        if data & 7:
            raise ValueError(f"{label}_data_alignment_invalid")
        entries_raw = _read_exact(
            reader, data, count * 8, f"{label}.child_pointers"
        )
        for index in range(count):
            pointer = int.from_bytes(entries_raw[index * 8:(index + 1) * 8], "little")
            if not _mission_task_memory._valid_pointer(pointer):
                raise ValueError(f"{label}_child_{index}_pointer_invalid")
            children.append(pointer)
    return {
        "vtable": vtable,
        "data": data,
        "capacity": capacity,
        "count": count,
        "header_raw_hex": raw.hex(),
        "entries_raw_hex": entries_raw.hex(),
        "children": children,
        "parser_vtable": parser_vtable,
        "parser_callback": callback,
    }


def _read_node_token(reader: Any, node_pointer: int, label: str) -> int:
    return _read_u32(reader, node_pointer + NODE_TOKEN_OFFSET, f"{label}.token")


def _unknown_node(kind: str, token: int | None, method_rva: int,
                  node_pointer: int, module_base: int, reason: str,
                  *, compare_extra: Mapping[str, Any] | None = None
                  ) -> tuple[dict[str, Any], dict[str, Any]]:
    public = {
        "kind": kind,
        "token": token,
        "method_rva": method_rva,
        "native_pointer": _public_pointer(node_pointer, module_base),
        "evaluation": _evaluation(None, reason),
    }
    compare = {
        "kind": kind,
        "token": token,
        "method_rva": method_rva,
        "native_pointer": node_pointer,
        "evaluation": dict(public["evaluation"]),
    }
    if compare_extra:
        compare.update(compare_extra)
    return public, compare


def _literal_flags(head: bytes) -> tuple[int, int, int]:
    literal_flag = head[NODE_LITERAL_FLAGS_OFFSET - NODE_LITERAL_HEAD_OFFSET]
    flags_start = NODE_DYNAMIC_FLAGS_OFFSET - NODE_LITERAL_HEAD_OFFSET
    dynamic_flags = int.from_bytes(head[flags_start:flags_start + 4], "little")
    threshold_start = NODE_THRESHOLD_OFFSET - NODE_LITERAL_HEAD_OFFSET
    threshold = int.from_bytes(head[threshold_start:threshold_start + 4], "little", signed=True)
    return literal_flag, dynamic_flags, threshold


def _read_sailors_metric(reader: Any, country_pointer: int, threshold: int,
                         label: str) -> tuple[bool, dict[str, Any]]:
    raw_current = _read_s32(
        reader, country_pointer + SAILORS_CURRENT_OFFSET, f"{label}.sailors_current"
    )
    raw_max = _read_s32(
        reader, country_pointer + SAILORS_MAX_OFFSET, f"{label}.sailors_max"
    )
    ratio: int | None
    if raw_max == 0:
        ratio = None
        satisfied = False
    else:
        ratio = _wrap_s32(_truncating_division(raw_current * 1000, raw_max))
        satisfied = ratio >= threshold
    return satisfied, {
        "rawcurrent": raw_current,
        "rawmax": raw_max,
        "threshold": threshold,
        "derived_ratio_milli": ratio,
        "unit": "ratio_milli",
    }


def _read_explorer_metric(reader: Any, country_pointer: int, threshold: int,
                          label: str) -> tuple[bool, dict[str, Any]]:
    counter_pointer = _read_qword(
        reader,
        country_pointer + EXPLORER_COUNTER_POINTER_OFFSET,
        f"{label}.explorer_counter_pointer",
    )
    if not _mission_task_memory._valid_pointer(counter_pointer):
        raise ValueError("mission_trigger.explorer_counter_pointer_invalid")
    actual = _read_s32(
        reader, counter_pointer + EXPLORER_COUNTER_OFFSET, f"{label}.explorer_count"
    )
    return actual >= threshold, {
        "actual": actual,
        "threshold": threshold,
        "unit": "explorer_count",
    }


def _read_galley_metric(reader: Any, module_base: int, country_pointer: int,
                        threshold: int, callback: Any,
                        label: str) -> tuple[bool | None, dict[str, Any], str | None]:
    if callback is None:
        return None, {"threshold": threshold, "unit": "ships_scale_1000"}, "GALLEY_COUNTER_UNAVAILABLE"
    if not callable(callback):
        return None, {"threshold": threshold, "unit": "ships_scale_1000"}, "GALLEY_COUNTER_INVALID"
    try:
        raw_value = callback(reader, module_base, country_pointer)
    except Exception as exc:
        return None, {"threshold": threshold, "unit": "ships_scale_1000"}, f"galley_counter_failed:{exc}"

    metric: dict[str, Any] = {"threshold": threshold, "unit": "ships_scale_1000"}
    if isinstance(raw_value, Mapping):
        actual_fixed = raw_value.get("raw_fixed_milli")
        source = raw_value.get("source")
        if (isinstance(actual_fixed, bool) or not isinstance(actual_fixed, int)
                or not -(1 << 31) <= actual_fixed < (1 << 31)):
            return None, metric, "GALLEY_COUNTER_INVALID"
        metric["raw_fixed_milli"] = actual_fixed
        if source is not None:
            if not isinstance(source, str):
                return None, metric, "GALLEY_COUNTER_INVALID"
            metric["source"] = source
    elif isinstance(raw_value, int) and not isinstance(raw_value, bool):
        actual_fixed = _wrap_s32(raw_value * 1000)
        metric["count"] = raw_value
        metric["raw_fixed_milli"] = actual_fixed
    else:
        return None, metric, "GALLEY_COUNTER_INVALID"

    required_fixed = _wrap_s32(threshold * 1000)
    metric["raw_fixed_milli"] = actual_fixed
    metric["required_fixed_milli"] = required_fixed
    return actual_fixed >= required_fixed, metric, None


def capture_triggers(reader: Any, module_base: int, country_pointer: int,
                     loaded_prerequisites: Any, *,
                     code_guards: list[dict[str, Any]],
                     galley_counter: Any = None, province_reader: Any = None,
                     country_state_reader: Any = None,
                     geographic_reader: Any = None,
                     country_scope_reader: Any = None, dlc_reader: Any = None,
                     dynamic_scope_reader: Any = None,
                     count_domain_reader: Any = None,
                     task_selector: dict[str, str] | None = None) -> dict[str, Any]:
    """Capture/evaluate task trigger trees from observed loaded task pointers."""
    if (isinstance(module_base, bool) or not isinstance(module_base, int)
            or not _mission_task_memory._valid_pointer(module_base)):
        return _unknown("module_base_invalid")
    if getattr(reader, "module_base", module_base) != module_base:
        return _unknown("reader_module_base_mismatch")

    tracked = _mission_condition_memory._TrackingReader(reader)
    metadata = _NodeMetadataCache(tracked, module_base)
    guard_reports: list[dict[str, Any]] = []
    try:
        guard_reports = _mission_prerequisite_memory._validate_code_guards(
            tracked, module_base, code_guards
        )
    except Exception as exc:
        return _unknown(f"runtime_code_guard_failed:{exc}", code_guards=guard_reports)

    if (isinstance(country_pointer, bool) or not isinstance(country_pointer, int)
            or not _mission_task_memory._valid_pointer(country_pointer)):
        return _unknown("country_pointer_invalid", code_guards=guard_reports)
    try:
        descriptors = select_tasks(
            _mission_condition_memory._parse_source(loaded_prerequisites), task_selector)
        task_selector = None if task_selector is None else dict(task_selector)
    except Exception as exc:
        return _unknown(f"loaded_prerequisites_validation_failed:{exc}", code_guards=guard_reports)

    task_outputs: list[dict[str, Any]] = []
    task_compares: list[dict[str, Any]] = []
    node_count = [0]
    evaluation_ops = [0]
    ephemeral_depth = [0]
    count_domains: dict[int, Any] = {}
    province_states: dict[int, Any] = {}
    subject_results: dict[tuple[int, int], tuple[bool | None, str | None]] = {}
    country_states: dict[tuple[str, int], Any] = {}
    secondary_modifier_definitions: dict[int, set[int]] = {}
    geographic_definitions: dict[str, Any] = {}
    country_scope_bindings: dict[int, Any] = {}
    dlc_inputs: dict[int, Any] = {}
    dynamic_scope_inputs: dict[tuple[str, int], Any] = {}

    def consume_node() -> None:
        if ephemeral_depth[0]:
            if evaluation_ops[0] >= MAX_COUNT_EVALUATION_OPS:
                raise ValueError('count_evaluation_operation_budget_exceeded')
            evaluation_ops[0] += 1
        else:
            node_count[0] += 1
            if node_count[0] > MAX_TOTAL_NODES:
                raise ValueError('mission_trigger_total_node_budget_exceeded')

    class CountryInputReader:
        """Keep reused legacy reads on the same tracked handle, including odd offsets."""
        def __init__(self):
            self.module_base = module_base

        def read(self, address, size, label):
            return _read_exact(tracked, address, size, label)

        read_code = read

        def qword(self, address, label):
            raw = self.read(address, 8, label)
            return int.from_bytes(raw, "little"), raw

    def country_state(kind: str, current_country_pointer: int | None = None) -> Any:
        target_pointer = country_pointer if current_country_pointer is None else current_country_pointer
        if target_pointer != country_pointer:
            return {"status": "unknown", "reason": "foreign_country_inputs_unsupported"}
        cache_key = (kind, target_pointer)
        if cache_key not in country_states:
            if not callable(country_state_reader):
                return {"status": "unknown", "reason": "country_condition_reader_not_configured"}
            country_states[cache_key] = country_state_reader(CountryInputReader(), module_base,
                                                             target_pointer, kind)
        return country_states[cache_key]

    def geographic_definition(name: str) -> Any:
        if name not in geographic_definitions:
            if not callable(geographic_reader):
                geographic_definitions[name] = {
                    "status": "unknown", "reason": "geographic_reader_not_configured",
                }
            else:
                try:
                    result = geographic_reader(CountryInputReader(), module_base, name)
                except Exception as exc:
                    result = {"status": "unknown",
                              "reason": f"geographic_reader_failed:{type(exc).__name__}:{exc}"}
                if not isinstance(result, Mapping) or result.get("status") != "known":
                    reason = (result.get("reason", "geographic_definition_unknown")
                              if isinstance(result, Mapping) else "geographic_definition_invalid")
                    geographic_definitions[name] = {"status": "unknown", "reason": str(reason)}
                else:
                    found = result.get("found")
                    province_ids = result.get("province_ids")
                    source = result.get("source")
                    if (type(found) is not bool or not isinstance(province_ids, list)
                            or len(province_ids) > MAX_GEOGRAPHIC_PROVINCE_IDS
                            or not isinstance(source, str) or not source):
                        geographic_definitions[name] = {
                            "status": "unknown", "reason": "geographic_definition_contract_invalid",
                        }
                    elif (any(type(province_id) is not int or not 1 <= province_id < 65536
                              for province_id in province_ids)
                          or len(set(province_ids)) != len(province_ids)
                          or (not found and province_ids)):
                        geographic_definitions[name] = {
                            "status": "unknown", "reason": "geographic_province_ids_invalid",
                        }
                    else:
                        geographic_definitions[name] = {
                            "status": "known", "found": found,
                            "province_ids": list(province_ids), "source": source,
                        }
        return geographic_definitions[name]

    def country_scope_binding(fullref: int) -> Any:
        if fullref not in country_scope_bindings:
            if not callable(country_scope_reader):
                country_scope_bindings[fullref] = {
                    "status": "unknown", "reason": "country_scope_reader_not_configured",
                }
            else:
                try:
                    result = country_scope_reader(CountryInputReader(), module_base, fullref)
                except Exception as exc:
                    result = {"status": "unknown",
                              "reason": f"country_scope_reader_failed:{type(exc).__name__}:{exc}"}
                if not isinstance(result, Mapping) or result.get("status") != "known":
                    reason = (result.get("reason", "country_scope_binding_unknown")
                              if isinstance(result, Mapping) else "country_scope_binding_invalid")
                    country_scope_bindings[fullref] = {"status": "unknown", "reason": str(reason)}
                else:
                    tag, pointer, observed_fullref = (
                        result.get("tag"), result.get("pointer"), result.get("fullref")
                    )
                    decoded_tag = _country_reference_memory._tag_from_fullref(fullref)
                    if (type(tag) is not str or tag != decoded_tag
                            or type(pointer) is not int
                            or not _mission_task_memory._valid_pointer(pointer)
                            or type(observed_fullref) is not int or observed_fullref != fullref
                            or ((tag == "FRA") != (pointer == country_pointer))):
                        country_scope_bindings[fullref] = {
                            "status": "unknown", "reason": "country_scope_binding_contract_invalid",
                        }
                    else:
                        country_scope_bindings[fullref] = {
                            "status": "known", "tag": tag, "pointer": pointer,
                            "fullref": fullref,
                        }
        return country_scope_bindings[fullref]

    def dlc_state(mask: int) -> Any:
        if mask not in dlc_inputs:
            try:
                if not callable(dlc_reader):
                    raise ValueError("dlc_reader_not_configured")
                value = dlc_reader(CountryInputReader(), module_base, mask)
                if not isinstance(value, Mapping):
                    raise ValueError("dlc_reader_result_invalid")
                if value.get("status") == "known":
                    binding = _DLC_BINDINGS.get(mask)
                    if (binding is None or value.get("satisfied") is not True
                            or value.get("dlc") != binding[0]):
                        raise ValueError("dlc_input_contract_invalid")
                    dlc_inputs[mask] = {"status": "known", "satisfied": True,
                                        "dlc": binding[0], "source": value.get("source")}
                else:
                    dlc_inputs[mask] = {"status": "unknown", "reason": str(value.get("reason", "dlc_input_unknown"))}
            except Exception as exc:
                dlc_inputs[mask] = {"status": "unknown", "reason": f"dlc_input_failed:{exc}"}
        return dlc_inputs[mask]

    def dynamic_scope_state(kind: str, current_country_pointer: int) -> Any:
        key = (kind, 0 if kind == "emperor" else current_country_pointer)
        if key not in dynamic_scope_inputs:
            try:
                if not callable(dynamic_scope_reader):
                    raise ValueError("dynamic_scope_reader_not_configured")
                value = dynamic_scope_reader(CountryInputReader(), module_base,
                                              kind, current_country_pointer)
                if not isinstance(value, Mapping):
                    raise ValueError("dynamic_scope_result_invalid")
                if value.get("status") == "known":
                    field = "fullref" if kind == "emperor" else "province_id"
                    selected = value.get(field)
                    limit = 0xFFFFFFFFFFFFFFFF if kind == "emperor" else 65535
                    if type(selected) is not int or not 1 <= selected <= limit:
                        raise ValueError("dynamic_scope_binding_invalid")
                    dynamic_scope_inputs[key] = {"status": "known", field: selected,
                                                  "source": value.get("source")}
                else:
                    dynamic_scope_inputs[key] = {"status": "unknown", "reason": str(value.get("reason", "dynamic_scope_unknown"))}
            except Exception as exc:
                dynamic_scope_inputs[key] = {"status": "unknown", "reason": f"dynamic_scope_input_failed:{exc}"}
        return dynamic_scope_inputs[key]

    def secondary_modifiers(current_country_pointer: int | None = None) -> set[int]:
        target_pointer = country_pointer if current_country_pointer is None else current_country_pointer
        if target_pointer != country_pointer:
            raise ValueError("foreign_country_modifier_secondary_list_unsupported")
        if target_pointer not in secondary_modifier_definitions:
            current = _read_qword(tracked, target_pointer + 0x220,
                                  'mission_trigger.modifier.secondary_head')
            seen, definitions = set(), set()
            while current:
                if (not _mission_task_memory._valid_pointer(current)
                        or current in seen or len(seen) >= 128):
                    raise ValueError('mission_trigger.secondary_modifier_list_invalid_or_over_bound')
                seen.add(current)
                definitions.add(_read_qword(tracked, current,
                                            'mission_trigger.modifier.secondary_definition'))
                current = _read_qword(tracked, current + 0x10,
                                      'mission_trigger.modifier.secondary_next')
            secondary_modifier_definitions[target_pointer] = definitions
        return secondary_modifier_definitions[target_pointer]

    def province_state(province_id: int) -> Any:
        if province_id not in province_states:
            if len(province_states) >= MAX_PROVINCE_TARGETS:
                return {"status": "unknown", "reason": "province_target_budget_exceeded"}
            # Reuse the admitted province reader with this owner's handle and
            # trace. Its nested reads may be unaligned; route them accordingly.
            province_states[province_id] = province_reader(
                lambda address, size, label: _read_exact(tracked, address, size, label),
                module_base, province_id,
            )
        return province_states[province_id]

    root_reference_cache: dict[str, int] = {}

    def root_country_reference(label: str) -> int:
        if "value" not in root_reference_cache:
            root_reference_cache["value"] = _read_qword(
                tracked, country_pointer + 0x20, f"{label}.root_country_reference"
            )
        return root_reference_cache["value"]

    def count_domain(mode: int) -> Any:
        if mode not in count_domains:
            if not callable(count_domain_reader):
                result = {'status': 'unknown', 'reason': 'count_domain_reader_not_configured'}
            else:
                try:
                    result = count_domain_reader(CountryInputReader(), module_base, country_pointer, mode)
                except Exception as exc:
                    result = {'status': 'unknown', 'reason': f'count_domain_read_failed:{type(exc).__name__}:{exc}'}
            if not isinstance(result, Mapping):
                result = {'status': 'unknown', 'reason': 'count_domain_invalid'}
            ids = result.get('province_ids')
            if result.get('status') == 'known' and (
                    result.get('country') != 'FRA' or result.get('country_pointer') != country_pointer
                    or result.get('root_reference') != root_country_reference('count_domain')
                    or not isinstance(ids, list) or len(ids) > MAX_COUNT_DOMAIN
                    or any(type(pid) is not int or not 1 <= pid < 65536 for pid in ids)):
                result = {'status': 'unknown', 'reason': 'count_domain_contract_invalid'}
            count_domains[mode] = result
        return count_domains[mode]

    def capture_explicit_and_group(group_pointer: int, *, depth: int,
                                   active: set[int], label: str,
                                   province_id: int | None,
                                   current_country_pointer: int | None = None,
                                   evaluated_method_rva: int = AND_EVALUATE_RVA,
                                   dispatch: str = "direct_call",
                                   allow_active_alias: bool = False
                                   ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Capture a group vector under a caller-established AND contract.

        IF limit/body groups use a direct static AND call; geographic bodies
        use an inline AND loop. Their vtable can describe another node type,
        so this helper validates only the bounded group layout and module-local
        vtable pointer rather than dispatching through it.
        """
        if depth > MAX_TREE_DEPTH:
            raise ValueError("mission_trigger_max_tree_depth_exceeded")
        if not _mission_task_memory._valid_pointer(group_pointer):
            raise ValueError(f"{label}_group_pointer_invalid")
        already_active = group_pointer in active
        if already_active and not allow_active_alias:
            raise ValueError("mission_trigger_tree_cycle")
        consume_node()

        added_to_active = not already_active
        if added_to_active:
            active.add(group_pointer)
        try:
            group = _read_group_contract(
                metadata, module_base, group_pointer, label, verify_parser=False
            )
            children: list[dict[str, Any]] = []
            compare_children: list[dict[str, Any]] = []
            for index, child_pointer in enumerate(group["children"]):
                child, child_compare = capture_node(
                    child_pointer,
                    depth=depth + 1,
                    active=active,
                    is_root=False,
                    label=f"{label}.child[{index}]",
                    province_id=province_id,
                    current_country_pointer=current_country_pointer,
                )
                children.append(child)
                compare_children.append(child_compare)
            evaluation = _combine("and", children)
            public = {
                "kind": "and",
                "token": None,
                "method_rva": evaluated_method_rva,
                "native_pointer": _public_pointer(group_pointer, module_base),
                "children": children,
                "evaluation": evaluation,
            }
            compare = {
                "kind": "and",
                "token": None,
                "method_rva": evaluated_method_rva,
                "native_pointer": group_pointer,
                "dispatch": dispatch,
                "vtable": group["vtable"],
                "group": {key: value for key, value in group.items()
                          if key != "children"},
                "children": compare_children,
                "evaluation": dict(evaluation),
            }
            return public, compare
        finally:
            if added_to_active:
                active.remove(group_pointer)

    def capture_node(node_pointer: int, *, depth: int, active: set[int],
                     is_root: bool, label: str, province_id: int | None = None,
                     current_country_pointer: int | None = None
                     ) -> tuple[dict[str, Any], dict[str, Any]]:
        if depth > MAX_TREE_DEPTH:
            raise ValueError("mission_trigger_max_tree_depth_exceeded")
        if node_pointer in active:
            raise ValueError("mission_trigger_tree_cycle")
        consume_node()
        if not _mission_task_memory._valid_pointer(node_pointer):
            raise ValueError("mission_trigger.node_pointer_invalid")
        if current_country_pointer is None:
            current_country_pointer = country_pointer
        active.add(node_pointer)
        try:
            vtable, method, method_rva = _read_eval_method(
                metadata, module_base, node_pointer, expected_root=is_root
            )
            if is_root:
                if method_rva != AND_EVALUATE_RVA:
                    raise ValueError("mission_trigger_root_not_and_group")
                group = _read_group_contract(
                    metadata, module_base, node_pointer, label, verify_parser=True
                )
                if group["vtable"] != vtable:
                    raise ValueError("mission_trigger_root_vtable_drift")
                children: list[dict[str, Any]] = []
                compare_children: list[dict[str, Any]] = []
                for index, child_pointer in enumerate(group["children"]):
                    child, child_compare = capture_node(
                        child_pointer,
                        depth=depth + 1,
                        active=active,
                        is_root=False,
                        label=f"{label}.child[{index}]",
                        province_id=province_id,
                        current_country_pointer=current_country_pointer,
                    )
                    children.append(child)
                    compare_children.append(child_compare)
                evaluation = _combine("and", children)
                public = {
                    "kind": "and",
                    "token": None,
                    "method_rva": method_rva,
                    "native_pointer": _public_pointer(node_pointer, module_base),
                    "children": children,
                    "evaluation": evaluation,
                }
                compare = {
                    "kind": "and",
                    "token": None,
                    "method_rva": method_rva,
                    "native_pointer": node_pointer,
                    "vtable": vtable,
                    "method": method,
                    "group": {key: value for key, value in group.items() if key != "children"},
                    "children": compare_children,
                    "evaluation": dict(evaluation),
                }
                return public, compare

            if method_rva in _LOGIC_METHODS:
                kind = _LOGIC_METHODS[method_rva]
                token = _read_node_token(metadata, node_pointer, label)
                group = _read_group_contract(
                    metadata, module_base, node_pointer, label, verify_parser=False
                )
                if group["vtable"] != vtable:
                    raise ValueError(f"{label}_vtable_drift")
                children = []
                compare_children = []
                for index, child_pointer in enumerate(group["children"]):
                    child, child_compare = capture_node(
                        child_pointer,
                        depth=depth + 1,
                        active=active,
                        is_root=False,
                        label=f"{label}.child[{index}]",
                        province_id=province_id,
                        current_country_pointer=current_country_pointer,
                    )
                    children.append(child)
                    compare_children.append(child_compare)
                evaluation = _combine(kind, children)
                public = {
                    "kind": kind,
                    "token": token,
                    "method_rva": method_rva,
                    "native_pointer": _public_pointer(node_pointer, module_base),
                    "children": children,
                    "evaluation": evaluation,
                }
                compare = {
                    "kind": kind,
                    "token": token,
                    "method_rva": method_rva,
                    "native_pointer": node_pointer,
                    "vtable": vtable,
                    "method": method,
                    "group": {key: value for key, value in group.items() if key != "children"},
                    "children": compare_children,
                    "evaluation": dict(evaluation),
                }
                return public, compare

            if method_rva == BOOLEAN_MATCH_EVALUATE_RVA:
                token = _read_node_token(metadata, node_pointer, label)
                expected_raw = _read_exact(metadata, node_pointer + 0xA0, 1,
                                           f'{label}.boolean_match_expected')
                if expected_raw[0] not in (0, 1):
                    return _unknown_node('unsupported', token, method_rva, node_pointer,
                        module_base, 'boolean_match_noncanonical_expected_byte',
                        compare_extra={'vtable': vtable, 'method': method,
                                       'expected_raw_hex': expected_raw.hex()})
                body, body_compare = capture_explicit_and_group(
                    node_pointer, depth=depth + 1, active=active,
                    label=f'{label}.boolean_match_body', province_id=province_id,
                    current_country_pointer=current_country_pointer, allow_active_alias=True)
                expected = bool(expected_raw[0])
                actual = body['evaluation']['satisfied']
                evaluation = _evaluation(actual == expected if actual is not None else None,
                                         'boolean_match_body_unknown' if actual is None else None)
                public = {'kind': 'boolean_match', 'token': token, 'method_rva': method_rva,
                    'native_pointer': _public_pointer(node_pointer, module_base),
                    'expected_satisfied': expected, 'body': body, 'evaluation': evaluation}
                return public, dict(public, native_pointer=node_pointer, vtable=vtable,
                    method=method, expected_raw_hex=expected_raw.hex(), body=body_compare)

            if method_rva == PROVINCE_ID_EVALUATE_RVA:
                token = _read_node_token(metadata, node_pointer, label)
                raw = _read_exact(metadata, node_pointer + 0x60, 12,
                                  f'{label}.province_id_parameters')
                flags = int.from_bytes(raw[:4], 'little')
                required_id = int.from_bytes(raw[8:], 'little', signed=True)
                dynamic = bool(flags & 0x4000)
                if province_id is None:
                    value, reason = False, None
                elif province_id == 0:
                    value, reason = None, 'count_member_context_unbound'
                elif dynamic:
                    value, reason = None, 'dynamic_province_id_selector_unsupported'
                else:
                    value, reason = province_id == required_id, None
                metric = {'province_id': province_id or None,
                          'required_province_id': required_id, 'dynamic_selector': dynamic}
                evaluation = _evaluation(value, reason)
                public = {'kind': 'leaf', 'token': token, 'method_rva': method_rva,
                    'native_pointer': _public_pointer(node_pointer, module_base),
                    'condition_name': 'province_id_matches', 'metric': metric,
                    'evaluation': evaluation}
                return public, dict(public, native_pointer=node_pointer, vtable=vtable,
                                    method=method, parameters_raw_hex=raw.hex())

            if method_rva == IF_EVALUATE_RVA:
                token = _read_node_token(metadata, node_pointer, label)
                limit_tree, limit_compare = capture_explicit_and_group(
                    node_pointer + IF_LIMIT_OFFSET,
                    depth=depth + 1,
                    active=active,
                    label=f"{label}.branch.limit",
                    province_id=province_id,
                    current_country_pointer=current_country_pointer,
                )
                # The native evaluator calls B98070(node, ctx) for the then
                # body.  That is the same address as this IF node, whose
                # vtable method remains DC7D80; represent the direct-call view
                # without treating this intentional alias as a tree cycle.
                then_tree, then_compare = capture_explicit_and_group(
                    node_pointer,
                    depth=depth + 1,
                    active=active,
                    label=f"{label}.branch.then",
                    province_id=province_id,
                    current_country_pointer=current_country_pointer,
                    allow_active_alias=True,
                )

                elseif_pointer = _read_qword(
                    metadata,
                    node_pointer + IF_ELSEIF_POINTER_OFFSET,
                    f"{label}.elseif_pointer",
                )
                if elseif_pointer:
                    if not _mission_task_memory._valid_pointer(elseif_pointer):
                        raise ValueError("mission_trigger.elseif_pointer_invalid")
                    _elseif_vtable, _elseif_method, elseif_method_rva = _read_eval_method(
                        metadata, module_base, elseif_pointer
                    )
                    if elseif_method_rva != IF_EVALUATE_RVA:
                        raise ValueError("mission_trigger.elseif_method_mismatch")
                    else_tree, else_compare = capture_node(
                        elseif_pointer,
                        depth=depth + 1,
                        active=active,
                        is_root=False,
                        label=f"{label}.branch.else_if",
                        province_id=province_id,
                        current_country_pointer=current_country_pointer,
                    )
                else:
                    else_tree, else_compare = capture_explicit_and_group(
                        node_pointer + IF_ELSE_OFFSET,
                        depth=depth + 1,
                        active=active,
                        label=f"{label}.branch.else",
                        province_id=province_id,
                        current_country_pointer=current_country_pointer,
                    )

                limit_value = limit_tree["evaluation"]["satisfied"]
                then_value = then_tree["evaluation"]["satisfied"]
                else_value = else_tree["evaluation"]["satisfied"]
                selected_branch = "unknown"
                if limit_value is True:
                    selected_branch = "then"
                    value = then_value
                    reason = (then_tree["evaluation"].get("reason")
                              if value is None else None)
                elif limit_value is False:
                    selected_branch = "else"
                    value = else_value
                    reason = (else_tree["evaluation"].get("reason")
                              if value is None else None)
                elif (type(then_value) is bool and type(else_value) is bool
                      and then_value is else_value):
                    value = then_value
                    reason = None
                else:
                    value = None
                    reason = "if_limit_unknown_or_branches_disagree"

                evaluation = _evaluation(value, reason)
                compare_branches = {
                    "limit": limit_compare,
                    "then": then_compare,
                    "else": else_compare,
                }
                public = {
                    "kind": "if",
                    "token": token,
                    "method_rva": method_rva,
                    "native_pointer": _public_pointer(node_pointer, module_base),
                    "limit": limit_tree,
                    "then": then_tree,
                    "else": else_tree,
                    "selected_branch": selected_branch,
                    "evaluation": evaluation,
                }
                compare = {
                    "kind": "if",
                    "token": token,
                    "method_rva": method_rva,
                    "native_pointer": node_pointer,
                    "vtable": vtable,
                    "method": method,
                    "elseif_pointer": elseif_pointer,
                    "branches": compare_branches,
                    "selected_branch": selected_branch,
                    "evaluation": dict(evaluation),
                }
                return public, compare

            if method_rva == GEOGRAPHIC_EVALUATE_RVA:
                if not callable(geographic_reader):
                    return _unknown_node("unsupported", None, method_rva,
                                         node_pointer, module_base,
                                         "unsupported_method",
                                         compare_extra={"vtable": vtable,
                                                        "method": method})
                token = _read_node_token(metadata, node_pointer, label)
                name_address = node_pointer + NODE_THRESHOLD_OFFSET
                name_header = _read_exact(metadata, name_address, 32,
                                          f"{label}.geographic_name")
                from .mission_memory import _decode_string32
                decoded_name = _decode_string32(CountryInputReader(), name_address,
                                                name_header, f"{label}.geographic_name")
                extra = {"vtable": vtable, "method": method,
                         "name_header_raw_hex": name_header.hex()}
                if decoded_name.get("status") != "observed" or not decoded_name.get("text"):
                    reason = decoded_name.get("unknown_reason") or "geographic_name_unknown"
                    return _unknown_node("unsupported", token, method_rva, node_pointer,
                                         module_base, f"geographic_name_unknown:{reason}",
                                         compare_extra=extra)
                name = decoded_name["text"]
                definition = geographic_definition(name)
                if not isinstance(definition, Mapping) or definition.get("status") != "known":
                    reason = (definition.get("reason", "geographic_definition_unknown")
                              if isinstance(definition, Mapping) else "geographic_definition_invalid")
                    return _unknown_node("unsupported", token, method_rva, node_pointer,
                                         module_base, str(reason),
                                         compare_extra=dict(extra, name=name))

                native_type = _read_u32(metadata, node_pointer + GEOGRAPHIC_QUANTIFIER_OFFSET,
                                        f"{label}.geographic_type")
                quantifier = "all" if native_type == GEOGRAPHIC_ALL_TYPE else "any"
                found = definition["found"]
                scope = {"kind": "province_set", "name": name,
                         "quantifier": quantifier, "definition_found": found,
                         "domain_complete": found}
                members: list[dict[str, Any]] = []
                compare_members: list[dict[str, Any]] = []

                def opaque_member(reason, compare_extra):
                    # An unread member is still a view node, and its depth
                    # must obey the same bounds as an evaluated member body.
                    if depth + 1 > MAX_TREE_DEPTH:
                        raise ValueError('mission_trigger_max_tree_depth_exceeded')
                    consume_node()
                    return _unknown_node('unsupported', None, method_rva, node_pointer,
                                         module_base, reason, compare_extra=compare_extra)

                if not found:
                    evaluation = _evaluation(False)
                else:
                    root_reference = None
                    for province_id in definition["province_ids"]:
                        member_label = f"{label}.geographic_member[{province_id}]"
                        if not callable(province_reader):
                            member_tree, member_compare = opaque_member(
                                "province_state_reader_not_configured",
                                {"province_id": province_id},
                            )
                            state = None
                        else:
                            state = province_state(province_id)
                            if not isinstance(state, Mapping) or state.get("status") != "known":
                                state_reason = (state.get("reason")
                                                if isinstance(state, Mapping)
                                                and isinstance(state.get("reason"), str)
                                                else "province_state_not_admitted")
                                member_tree, member_compare = opaque_member(
                                    state_reason,
                                    {"province_id": province_id, "state": state},
                                )
                            else:
                                if root_reference is None:
                                    root_reference = root_country_reference(label)
                                if (state.get("observer_pointer") != country_pointer
                                        or state.get("observer_reference") != root_reference):
                                    member_tree, member_compare = opaque_member(
                                        "province_observer_root_mismatch",
                                        {"province_id": province_id, "state": state,
                                         "root_reference": root_reference},
                                    )
                                else:
                                    member_tree, member_compare = capture_explicit_and_group(
                                        node_pointer, depth=depth + 1, active=active,
                                        label=member_label, province_id=province_id,
                                        current_country_pointer=current_country_pointer,
                                        evaluated_method_rva=GEOGRAPHIC_EVALUATE_RVA,
                                        dispatch="inlined_and_loop",
                                        allow_active_alias=True,
                                    )
                        members.append({"province_id": province_id, "tree": member_tree})
                        compare_members.append({"province_id": province_id,
                                                "state": state, "tree": member_compare})
                    evaluation = _combine("and" if quantifier == "all" else "or",
                                          [member["tree"] for member in members])

                public = {"kind": "geographic", "token": token,
                          "method_rva": method_rva,
                          "native_pointer": _public_pointer(node_pointer, module_base),
                          "scope": scope, "members": members,
                          "evaluation": evaluation}
                compare = dict(extra, kind="geographic", token=token,
                    method_rva=method_rva, native_pointer=node_pointer,
                    name=name, definition_source=definition["source"],
                    province_ids=list(definition["province_ids"]),
                    native_type=native_type, scope=scope, members=compare_members,
                    evaluation=dict(evaluation))
                return public, compare

            if method_rva == STORED_BOOLEAN_EVALUATE_RVA:
                # Complete local five-byte sequence: movzx eax,byte[rcx+68];ret.
                # No claim about a script keyword or an unwind function boundary.
                raw = _read_exact(metadata, node_pointer + 0x68, 1, f'{label}.stored_boolean')
                token = _read_node_token(metadata, node_pointer, label)
                evaluation = _evaluation(raw[0] != 0)
                public = {'kind': 'leaf', 'token': token, 'method_rva': method_rva,
                    'native_pointer': _public_pointer(node_pointer, module_base),
                    'condition_name': 'stored_boolean', 'evaluation': evaluation}
                return public, dict(public, native_pointer=node_pointer, vtable=vtable,
                                    method=method, stored_byte=raw.hex())

            if method_rva == COUNT_EVALUATE_RVA:
                token = _read_node_token(metadata, node_pointer, label)
                extra = {'vtable': vtable, 'method': method}
                if province_id is not None or current_country_pointer != country_pointer:
                    return _unknown_node('unsupported', token, method_rva, node_pointer, module_base,
                                         'count_country_context_unsupported', compare_extra=extra)
                raw = _read_exact(metadata, node_pointer + 0x68, 5, f'{label}.count_parameters')
                threshold = int.from_bytes(raw[:4], 'little', signed=True)
                mode = raw[4]
                extra['parameter_raw_hex'] = raw.hex()
                if (token, mode) not in {(0x2BF9, 0), (0x37FC, 1)}:
                    return _unknown_node('unsupported', token, method_rva, node_pointer, module_base,
                                         'count_token_mode_unsupported', compare_extra=extra)
                domain = count_domain(mode)
                if domain.get('status') != 'known':
                    return _unknown_node('unsupported', token, method_rva, node_pointer, module_base,
                                         domain.get('reason', 'count_domain_unknown'), compare_extra=extra)
                ids = domain['province_ids']
                # Unbound province zero is never passed to the state reader.
                # This single template describes the filter without duplicating
                # its full tree for every domain member.
                template, template_compare = capture_explicit_and_group(
                    node_pointer, depth=depth + 1, active=active, label=f'{label}.filter',
                    province_id=0, current_country_pointer=0,
                    evaluated_method_rva=COUNT_EVALUATE_RVA, dispatch='inlined_and_loop',
                    allow_active_alias=True)
                universal = template['evaluation']['satisfied']
                samples, sample_compares = [], []
                if universal is not None:
                    lower = upper = len(ids) if universal else 0
                    fully_evaluated = True
                else:
                    lower, upper = 0, len(ids)
                    for index, pid in enumerate(ids[:MAX_COUNT_SAMPLES]):
                        admitted = False
                        try:
                            state = province_state(pid) if callable(province_reader) else {}
                            admitted = (state.get('status') == 'known'
                                and state.get('province_id') == pid
                                and state.get('observer_pointer') == country_pointer
                                and state.get('observer_reference') == root_country_reference(label))
                            if not admitted:
                                result = _evaluation(None, 'count_member_not_admitted')
                            else:
                                ephemeral_depth[0] += 1
                                try:
                                    tree, _ = capture_explicit_and_group(
                                        node_pointer, depth=depth + 1, active=active,
                                        label=f'{label}.sample[{index}]', province_id=pid,
                                        current_country_pointer=0,
                                        evaluated_method_rva=COUNT_EVALUATE_RVA,
                                        dispatch='inlined_and_loop', allow_active_alias=True)
                                    result = dict(tree['evaluation'])
                                finally:
                                    ephemeral_depth[0] -= 1
                        except Exception as exc:
                            result = _evaluation(None, f'count_member_evaluation_failed:{type(exc).__name__}:{exc}')
                        samples.append({'province_id': pid if admitted else None, 'evaluation': result})
                        sample_compares.append({'province_id': pid, 'evaluation': result})
                        if result['satisfied'] is True:
                            lower += 1
                        elif result['satisfied'] is False:
                            upper -= 1
                    fully_evaluated = len(samples) == len(ids)
                value = _count_result(lower, upper, threshold)
                evaluation = _evaluation(value, 'count_filter_or_unsampled_members_unknown' if value is None else None)
                metric = {'threshold': threshold, 'domain_count': len(ids),
                    'lower_bound': lower, 'upper_bound': upper, 'sampled_count': len(samples),
                    'fully_evaluated': fully_evaluated}
                public = {'kind': 'count', 'token': token, 'method_rva': method_rva,
                    'native_pointer': _public_pointer(node_pointer, module_base),
                    'condition_name': ('num_of_owned_provinces_with' if mode == 0 else
                        'num_of_provinces_owned_or_owned_by_non_sovereign_subjects_with'),
                    'scope': {'kind': 'owned_provinces', 'country': 'FRA',
                              'mode': 'owned' if mode == 0 else 'non_sovereign_subjects'},
                    'metric': metric, 'filter': template, 'samples': samples,
                    'evaluation': evaluation}
                compare = dict(public, **extra, native_pointer=node_pointer,
                               domain=dict(domain), filter=template_compare, samples=sample_compares)
                return public, compare

            if method_rva == DLC_EVALUATE_RVA:
                token = _read_node_token(metadata, node_pointer, label)
                extra = {"vtable": vtable, "method": method}
                if token != DLC_TOKEN:
                    return _unknown_node("unsupported", token, method_rva, node_pointer,
                                         module_base, "dlc_method_token_mismatch", compare_extra=extra)
                raw = _read_exact(metadata, node_pointer + NODE_THRESHOLD_OFFSET, 4,
                                  f"{label}.dlc_mask")
                mask = int.from_bytes(raw, "little")
                value = dlc_state(mask)
                known = value["status"] == "known"
                binding = _DLC_BINDINGS.get(mask)
                metric = {"dlc": binding[0] if binding is not None else None}
                evaluation = _evaluation(True if known else None, value.get("reason"))
                public = {"kind": "leaf", "token": token, "method_rva": method_rva,
                    "native_pointer": _public_pointer(node_pointer, module_base),
                    "condition_name": "has_dlc", "metric": metric, "evaluation": evaluation}
                compare = dict(extra, kind="leaf", token=token, method_rva=method_rva,
                    native_pointer=node_pointer, mask=mask, mask_raw_hex=raw.hex(),
                    dlc_input=dict(value), metric=metric, evaluation=dict(evaluation))
                return public, compare

            if method_rva == PROVINCE_SCOPE_EVALUATE_RVA:
                token = _read_node_token(metadata, node_pointer, label)
                reference = _read_qword(metadata, node_pointer + PROVINCE_SCOPE_REFERENCE_OFFSET,
                                        f"{label}.scope_reference")
                if not _mission_task_memory._valid_pointer(reference):
                    raise ValueError("mission_trigger.scope_reference_pointer_invalid")
                reference_raw = _read_exact(metadata, reference, 0x218,
                                            f"{label}.scope_reference_object")
                reference_kind = int.from_bytes(reference_raw[:4], "little")
                explicit_country = reference_raw[PROVINCE_REFERENCE_COUNTRY_FLAG_OFFSET]
                extra = {"vtable": vtable, "method": method, "reference": reference,
                         "reference_raw_hex": reference_raw.hex()}

                fullref = None
                country_selection = "literal"
                if reference_kind == COUNTRY_REFERENCE_KIND and explicit_country != 0:
                    fullref = int.from_bytes(
                        reference_raw[COUNTRY_REFERENCE_FULLREF_OFFSET:
                                      COUNTRY_REFERENCE_FULLREF_OFFSET + 8], "little"
                    )
                elif reference_kind == EMPEROR_REFERENCE_KIND and explicit_country == 0:
                    selector = dynamic_scope_state("emperor", current_country_pointer)
                    extra["selector_input"] = dict(selector)
                    if selector.get("status") != "known":
                        return _unknown_node("unsupported", token, method_rva, node_pointer,
                                             module_base, selector["reason"], compare_extra=extra)
                    fullref = selector["fullref"]
                    country_selection = "emperor"
                if fullref is not None:
                    binding = country_scope_binding(fullref)
                    if not isinstance(binding, Mapping) or binding.get("status") != "known":
                        reason = (binding.get("reason", "country_scope_binding_unknown")
                                  if isinstance(binding, Mapping) else "country_scope_binding_invalid")
                        return _unknown_node("unsupported", token, method_rva, node_pointer,
                                             module_base, str(reason),
                                             compare_extra=dict(extra, fullref=fullref))
                    tag = binding["tag"]
                    bound_pointer = country_pointer if tag == "FRA" else binding["pointer"]
                    group = _read_group_contract(metadata, module_base, node_pointer,
                                                 label, verify_parser=False)
                    if group["vtable"] != vtable:
                        raise ValueError(f"{label}_vtable_drift")
                    children, compare_children = [], []
                    for index, pointer in enumerate(group["children"]):
                        child, comparison = capture_node(
                            pointer, depth=depth + 1, active=active, is_root=False,
                            label=f"{label}.child[{index}]", province_id=None,
                            current_country_pointer=bound_pointer,
                        )
                        children.append(child)
                        compare_children.append(comparison)
                    evaluation = _combine("and", children)
                    scope = {"kind": "country", "country": tag,
                             "selection": country_selection}
                    public = {"kind": "scope", "token": token,
                              "method_rva": method_rva,
                              "native_pointer": _public_pointer(node_pointer, module_base),
                              "scope": scope, "children": children,
                              "evaluation": evaluation}
                    compare = dict(extra, kind="scope", token=token,
                        method_rva=method_rva, native_pointer=node_pointer,
                        scope=scope, fullref=fullref, binding=dict(binding),
                        bound_country_pointer=bound_pointer,
                        group={key: value for key, value in group.items()
                               if key != "children"},
                        children=compare_children, evaluation=dict(evaluation))
                    return public, compare

                province_selection = "literal"
                if reference_kind == CAPITAL_REFERENCE_KIND and explicit_country == 0:
                    if province_id is not None:
                        return _unknown_node("unsupported", token, method_rva, node_pointer,
                            module_base, "capital_scope_country_context_required", compare_extra=extra)
                    selector = dynamic_scope_state("capital", current_country_pointer)
                    extra["selector_input"] = dict(selector)
                    if selector.get("status") != "known":
                        return _unknown_node("unsupported", token, method_rva, node_pointer,
                                             module_base, selector["reason"], compare_extra=extra)
                    selected = selector["province_id"]
                    province_selection = "capital"
                elif reference_kind == PROVINCE_REFERENCE_KIND and explicit_country == 0:
                    selected = int.from_bytes(
                        reference_raw[PROVINCE_REFERENCE_ID_OFFSET:
                                      PROVINCE_REFERENCE_ID_OFFSET + 4], "little", signed=True)
                else:
                    return _unknown_node("unsupported", token, method_rva, node_pointer,
                                         module_base, "dynamic_or_country_scope_unsupported",
                                         compare_extra=extra)
                if not callable(province_reader):
                    return _unknown_node("unsupported", token, method_rva, node_pointer,
                                         module_base, "province_state_reader_not_configured",
                                         compare_extra=extra)
                if not 1 <= selected < 65536:
                    return _unknown_node("unsupported", token, method_rva, node_pointer,
                                         module_base, "literal_province_id_invalid",
                                         compare_extra=extra)
                state = province_state(selected)
                if not isinstance(state, Mapping) or state.get("status") != "known":
                    state_reason = (state.get("reason")
                                    if isinstance(state, Mapping)
                                    and isinstance(state.get("reason"), str)
                                    else "province_state_not_admitted")
                    return _unknown_node("unsupported", token, method_rva, node_pointer,
                                         module_base, state_reason,
                                         compare_extra=extra)
                root_reference = root_country_reference(label)
                if (state.get("observer_pointer") != country_pointer
                        or state.get("observer_reference") != root_reference):
                    return _unknown_node("unsupported", token, method_rva, node_pointer,
                                         module_base, "province_observer_root_mismatch",
                                         compare_extra=extra)
                group = _read_group_contract(metadata, module_base, node_pointer,
                                             label, verify_parser=False)
                if group["vtable"] != vtable:
                    raise ValueError(f"{label}_vtable_drift")
                children, compare_children = [], []
                for index, pointer in enumerate(group["children"]):
                    child, comparison = capture_node(
                        pointer, depth=depth + 1, active=active, is_root=False,
                        label=f"{label}.child[{index}]", province_id=selected,
                        current_country_pointer=current_country_pointer,
                    )
                    children.append(child)
                    compare_children.append(comparison)
                evaluation = _combine("and", children)
                scope = {"kind": "province", "province_id": selected,
                         "selection": province_selection}
                public = {"kind": "scope", "token": token,
                          "method_rva": method_rva,
                          "native_pointer": _public_pointer(node_pointer, module_base),
                          "scope": scope, "children": children,
                          "evaluation": evaluation}
                compare = dict(extra, kind="scope", token=token,
                    method_rva=method_rva, native_pointer=node_pointer,
                    scope=scope, state=state, root_reference=root_reference,
                    group={key: value for key, value in group.items()
                           if key != "children"},
                    children=compare_children, evaluation=dict(evaluation))
                return public, compare

            if method_rva in _PROVINCE_METHODS and callable(province_reader):
                name, expected_token, field = _PROVINCE_METHODS[method_rva]
                head = _read_exact(metadata, node_pointer + NODE_LITERAL_HEAD_OFFSET,
                                   NODE_LITERAL_HEAD_BYTES, f"{label}.province_predicate_head")
                token = int.from_bytes(head[8:12], "little")
                flag, flags, _threshold = _literal_flags(head)
                extra = {"vtable": vtable, "method": method, "head_raw_hex": head.hex()}
                if token != expected_token:
                    return _unknown_node("unsupported", token, method_rva, node_pointer, module_base,
                                         "province_method_token_mismatch", compare_extra=extra)
                value, reason = None, None
                metric: dict[str, Any] = {"province_id": province_id or None, "comparison_country": None,
                                          "source": "province_state_memory.read_two_pass"}
                comparison_reference = None
                if province_id is None:
                    reason = "province_scope_required"
                elif province_id == 0:
                    reason = 'count_member_context_unbound'
                elif method_rva == PROVINCE_HELD_EVALUATE_RVA and flag != 0:
                    # BE9606..BE962A uses node+48 directly when its high byte
                    # is nonzero, before consulting any dynamic selector flags.
                    # Reuse the canonical one-slot binding and per-snapshot
                    # cache already used by literal country scope nodes.
                    literal_reference = int.from_bytes(head[:8], "little")
                    binding = country_scope_binding(literal_reference)
                    extra["comparison_binding"] = dict(binding)
                    if binding.get("status") == "known":
                        comparison_reference = binding["fullref"]
                        metric["comparison_country"] = binding["tag"]
                    else:
                        reason = binding.get("reason", "comparison_country_binding_unknown")
                elif flag != 0 or flags != ROOT_COUNTRY_FLAGS:
                    reason = "comparison_country_selector_unsupported"
                else:
                    comparison_reference = root_country_reference(label)
                    metric["comparison_country"] = "ROOT"
                if comparison_reference is not None:
                    state = province_state(province_id)
                    actual = state.get(field, {})
                    root_reference = root_country_reference(label)
                    if (state.get("observer_pointer") != country_pointer
                            or state.get("observer_reference") != root_reference):
                        reason = "province_observer_root_mismatch"
                    elif (not isinstance(actual, Mapping) or actual.get("status") != "known"
                          or type(actual.get("reference")) is not int):
                        reason = "province_field_unknown"
                    else:
                        metric["actual_country"] = actual.get("tag")
                        same_owner = ((actual["reference"] >> 32) & 0xFFFF) == ((comparison_reference >> 32) & 0xFFFF)
                        if method_rva == PROVINCE_HELD_EVALUATE_RVA and not same_owner:
                            owner_pointer = actual.get("country_pointer")
                            if type(owner_pointer) is not int:
                                reason = "province_owner_pointer_unverified"
                            else:
                                key = owner_pointer, comparison_reference
                                if key not in subject_results:
                                    subject_results[key] = _subject_holds(tracked, owner_pointer,
                                                                         comparison_reference, label)
                                value, reason = subject_results[key]
                        else:
                            value = same_owner
                evaluation = _evaluation(value, reason)
                public = {"kind": "leaf", "token": token, "method_rva": method_rva,
                          "native_pointer": _public_pointer(node_pointer, module_base),
                          "condition_name": name, "metric": metric, "evaluation": evaluation}
                compare = dict(extra, kind="leaf", token=token, method_rva=method_rva,
                    native_pointer=node_pointer, metric=metric, evaluation=dict(evaluation))
                return public, compare

            if method_rva == COUNTRY_MODIFIER_EVALUATE_RVA:
                token = _read_node_token(metadata, node_pointer, label)
                extra = {'vtable': vtable, 'method': method}
                if token != COUNTRY_MODIFIER_TOKEN:
                    return _unknown_node('unsupported', token, method_rva, node_pointer, module_base,
                                         'modifier_method_token_mismatch', compare_extra=extra)
                if province_id is not None:
                    return _unknown_node('leaf', token, method_rva, node_pointer, module_base,
                                         'country_modifier_in_province_scope_unsupported', compare_extra=extra)
                if current_country_pointer != country_pointer:
                    return _unknown_node('leaf', token, method_rva, node_pointer, module_base,
                                         'foreign_country_modifier_unsupported', compare_extra=extra)
                definition = _read_qword(metadata, node_pointer + 0x68, f'{label}.modifier_definition')
                if not _mission_task_memory._valid_pointer(definition):
                    return _unknown_node('leaf', token, method_rva, node_pointer, module_base,
                                         'modifier_definition_pointer_invalid', compare_extra=extra)
                definition_vtable = _read_qword(metadata, definition, f'{label}.modifier_definition_vtable')
                if definition_vtable != module_base + 0x1C42AE0:
                    return _unknown_node('leaf', token, method_rva, node_pointer, module_base,
                                         'modifier_definition_vtable_mismatch', compare_extra=extra)
                from .mission_memory import _decode_string32
                key_address = definition + 0x158
                header = _read_exact(metadata, key_address, 32, f'{label}.modifier_definition_key')
                key = _decode_string32(CountryInputReader(), key_address, header, f'{label}.modifier_key')
                if key.get('status') != 'observed' or not key.get('text'):
                    return _unknown_node('leaf', token, method_rva, node_pointer, module_base,
                                         'modifier_definition_key_unknown', compare_extra=extra)
                observed = country_state('modifiers', current_country_pointer)
                metric = {'modifier_id': key['text'],
                          'source': 'native_definition_pointer_membership_in_country_modifier_lists'}
                value, reason = None, 'country_modifier_instances_unknown'
                rows = observed.get('definitions') if isinstance(observed, Mapping) else None
                if (isinstance(observed, Mapping) and observed.get('status') == 'known'
                        and isinstance(rows, list) and len(rows) <= 128
                        and all(isinstance(row, Mapping) and type(row.get('pointer')) is int
                                and isinstance(row.get('key'), str) for row in rows)):
                    direct = [row for row in rows if row['pointer'] == definition]
                    if direct and any(row['key'] != key['text'] for row in direct):
                        reason = 'modifier_definition_key_conflict'
                    else:
                        value = bool(direct) or definition in secondary_modifiers(current_country_pointer)
                        reason = None
                        metric.update(direct_list_complete=True, secondary_list_checked=not bool(direct))
                evaluation = _evaluation(value, reason)
                public = {'kind': 'leaf', 'token': token, 'method_rva': method_rva,
                          'native_pointer': _public_pointer(node_pointer, module_base),
                          'condition_name': 'has_country_modifier', 'metric': metric, 'evaluation': evaluation}
                compare = dict(extra, kind='leaf', token=token, method_rva=method_rva,
                    native_pointer=node_pointer, definition_pointer=definition,
                    metric=metric, evaluation=dict(evaluation))
                return public, compare

            scalar = _SCALAR_METHOD_TOKENS.get(method_rva)
            if scalar is None:
                return _unknown_node(
                    "unsupported", None, method_rva, node_pointer, module_base,
                    "unsupported_method",
                    compare_extra={"vtable": vtable, "method": method},
                )

            kind, expected_token = scalar
            head = _read_exact(
                metadata,
                node_pointer + NODE_LITERAL_HEAD_OFFSET,
                NODE_LITERAL_HEAD_BYTES,
                f"{label}.scalar_head",
            )
            token_offset = NODE_TOKEN_OFFSET - NODE_LITERAL_HEAD_OFFSET
            token = int.from_bytes(head[token_offset:token_offset + 4], "little")
            compare_extra = {
                "vtable": vtable,
                "method": method,
                "head_address": node_pointer + NODE_LITERAL_HEAD_OFFSET,
                "head_raw_hex": head.hex(),
            }
            if token != expected_token:
                return _unknown_node(
                    "unsupported", token, method_rva, node_pointer, module_base,
                    "scalar_method_token_mismatch", compare_extra=compare_extra,
                )
            if province_id is not None:
                return _unknown_node("leaf", token, method_rva, node_pointer, module_base,
                                     "country_scalar_in_province_scope_unsupported",
                                     compare_extra=compare_extra)
            if current_country_pointer != country_pointer:
                return _unknown_node("leaf", token, method_rva, node_pointer, module_base,
                                     "foreign_country_scalar_unsupported",
                                     compare_extra=compare_extra)

            literal_flag, dynamic_flags, threshold = _literal_flags(head)
            metric: dict[str, Any] = {"threshold": threshold}
            value: bool | None
            reason: str | None = None
            if kind == "sailors":
                value, metric = _read_sailors_metric(
                    tracked, current_country_pointer, threshold, label
                )
            elif kind == "army_ratio":
                observed = country_state("army_ratio", current_country_pointer)
                if (not isinstance(observed, Mapping) or observed.get("status") != "known"
                        or type(observed.get("army_raw_fixed_milli")) is not int
                        or not -(1 << 31) <= observed['army_raw_fixed_milli'] < (1 << 31)
                        or type(observed.get("land_force_limit_raw")) is not int
                        or not 0 <= observed['land_force_limit_raw'] < (1 << 31)):
                    value, reason = None, "army_ratio_inputs_unknown"
                else:
                    numerator = observed['army_raw_fixed_milli']
                    denominator = observed['land_force_limit_raw']
                    ratio = (-1 if denominator == 0 else
                             _wrap_s32(_truncating_division(numerator * 1000, denominator)))
                    value = ratio >= threshold
                    metric.update(numerator_raw=numerator, denominator_raw=denominator,
                                  raw_ratio=ratio, unit="fraction_per_mille",
                                  source=observed.get('source'))
            elif kind == "unity":
                if literal_flag != 0 or dynamic_flags & 0x4000:
                    value, reason = None, 'dynamic_unity_threshold_unsupported'
                else:
                    observed = country_state('religious_unity', current_country_pointer)
                    if (not isinstance(observed, Mapping) or observed.get('status') != 'known'
                            or type(observed.get('raw_fixed_milli')) is not int
                            or not 0 <= observed['raw_fixed_milli'] < (1 << 31)):
                        value, reason = None, 'religious_unity_inputs_unknown'
                    else:
                        raw_unity = observed['raw_fixed_milli']
                        value = raw_unity >= threshold
                        metric.update(raw_value=raw_unity, unit='fraction_per_mille',
                                      upper_clamp=False, source=observed.get('source'))
            elif literal_flag != 0 or dynamic_flags & 0x4000:
                value = None
                metric.update({
                    "literal_flag": literal_flag,
                    "dynamic_flags": dynamic_flags,
                    "unit": "explorer_count" if kind == "explorer" else "ships_scale_1000",
                })
                reason = "dynamic_threshold_unsupported"
            elif kind == "explorer":
                value, metric = _read_explorer_metric(
                    tracked, current_country_pointer, threshold, label
                )
            else:
                value, metric, reason = _read_galley_metric(
                    tracked, module_base, current_country_pointer, threshold,
                    galley_counter, label,
                )

            evaluation = _evaluation(value, reason)
            public = {
                "kind": "leaf",
                "token": token,
                "method_rva": method_rva,
                "native_pointer": _public_pointer(node_pointer, module_base),
                "evaluation": evaluation,
                "metric": metric,
            }
            compare = {
                "kind": "leaf",
                "token": token,
                "method_rva": method_rva,
                "native_pointer": node_pointer,
                "vtable": vtable,
                "method": method,
                "head_address": node_pointer + NODE_LITERAL_HEAD_OFFSET,
                "head_raw_hex": head.hex(),
                "evaluation": dict(evaluation),
                "metric": dict(metric),
            }
            return public, compare
        finally:
            active.remove(node_pointer)

    try:
        for descriptor in descriptors:
            task_pointer = descriptor["task_pointer"]
            if not _mission_task_memory._valid_pointer(task_pointer):
                raise ValueError("mission_trigger.task_pointer_invalid")
            group_pointer = task_pointer + TASK_TRIGGER_OFFSET
            tree, tree_compare = capture_node(
                group_pointer,
                depth=0,
                active=set(),
                is_root=True,
                label=f"mission_trigger[{descriptor['root_id']}:{descriptor['task_id']}]",
            )
            task_outputs.append({
                "root_id": descriptor["root_id"],
                "task_id": descriptor["task_id"],
                "tree": tree,
            })
            task_compares.append({
                "root_id": descriptor["root_id"],
                "task_id": descriptor["task_id"],
                "task_pointer": task_pointer,
                "tree": tree_compare,
            })
    except Exception as exc:
        return _unknown(f"mission_trigger_capture_failed:{exc}", code_guards=guard_reports)

    compare = {
        "status": "observed",
        "module_base": module_base,
        "country_pointer": country_pointer,
        "task_selector": task_selector,
        "code_guards": [
            {"rva": row["rva"], "raw_hex": row["raw_hex"], "sha256": row["sha256"]}
            for row in guard_reports
        ],
        "tasks": task_compares,
        "rawreads": tracked.rawreads,
    }
    return {
        "status": "observed",
        "complete": True,
        "reason": None,
        "unknown_conditions": _unknown_tree_conditions(task_outputs),
        "code_guards": guard_reports,
        "tasks": task_outputs,
        "total_task_count": len(task_outputs),
        "task_selector": task_selector,
        "total_nodes": node_count[0],
        "count_evaluation_ops": evaluation_ops[0],
        "node_metadata_sampling": 'shared_per_outer_snapshot_not_atomic',
        "node_metadata_cache": {'entries': len(metadata._bytes),
                                'bytes': metadata.bytes_cached, 'hits': metadata.hits},
        "_compare": compare,
    }


__all__ = ["capture_triggers"]
