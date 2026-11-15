"""Bounded RPM evaluation of loaded mission prerequisite completion.

This module resolves the task IDs captured by ``mission_prerequisite_memory``
to their canonical definition pointers, then checks those pointers against the
country's completed-definition hash set.  It only uses the caller's existing
reader and explicit runtime code guards; it never opens a process or invokes
game code.
"""
from __future__ import annotations

import re
from typing import Any, Mapping

from . import mission_memory as _mission_memory
from . import mission_prerequisite_memory as _mission_prerequisite_memory
from . import mission_task_memory as _mission_task_memory


REGISTRY_SINGLETON_RVA = 0x242BCE0
REGISTRY_VTABLE_RVA = 0x1C38348
REGISTRY_MAP_OFFSET = 0x18
COMPLETED_MAP_OFFSET = 0x9998
MAP_HEADER_BYTES = 64
MAP_BUCKET_PAIR_BYTES = 16
MAX_MAP_BUCKETS = 65536
MAX_NAME_MAP_SIZE = 16384
MAX_COMPLETED_MAP_SIZE = 4096
MAX_BUCKET_NODES = 256
MAX_TOTAL_CHAIN_STEPS = 8192
MAX_CAPTURED_TASKS = 4096
MAX_REQUIRED_PER_TASK = 512
MAX_TOTAL_REQUIRED = 4096
MAX_SINGLE_RPM = _mission_task_memory.MAX_SINGLE_RPM
MAX_TOTAL_RPM = _mission_task_memory.MAX_TOTAL_RPM
MAX_USER_ADDRESS = _mission_memory.MAX_USER_ADDRESS

_IDENTIFIER = re.compile(r"^[A-Za-z0-9_]+$", re.ASCII)


def _unknown(reason: str, tasks: list[dict[str, Any]] | None = None,
             code_guards: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "status": "unknown",
        "complete": False,
        "reason": reason,
        "unknown_conditions": [reason],
        "code_guards": code_guards or [],
        "tasks": tasks or [],
        "_compare": None,
    }


class _TrackingReader:
    """Record every read while preserving the underlying reader's budget."""

    def __init__(self, reader: Any):
        self._reader = reader
        self.module_base = getattr(reader, "module_base", None)
        self.rawreads: list[dict[str, Any]] = []
        self.bytes_read = 0

    def _check_range(self, address: int, size: int, label: str) -> None:
        if isinstance(address, bool) or not isinstance(address, int) or address < 0x10000:
            raise ValueError(f"{label}_address_invalid")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0 or size > MAX_SINGLE_RPM:
            raise ValueError(f"{label}_size_out_of_bound")
        if size and (address + size > MAX_USER_ADDRESS or address + size < address):
            raise ValueError(f"{label}_range_out_of_bound")
        if self.bytes_read + size > MAX_TOTAL_RPM:
            raise ValueError("condition_total_rpm_budget_exceeded")

    def _record(self, address: int, size: int, label: str, raw: Any) -> Any:
        self.bytes_read += size
        self.rawreads.append({
            "address": hex(address),
            "size": size,
            "label": label,
            "raw_hex": raw.hex() if isinstance(raw, bytes) else None,
            "actual_size": len(raw) if isinstance(raw, bytes) else None,
        })
        return raw

    def read(self, address: int, size: int, label: str) -> bytes:
        self._check_range(address, size, label)
        raw = self._reader.read(address, size, label)
        return self._record(address, size, label, raw)

    def read_code(self, address: int, size: int, label: str) -> bytes:
        self._check_range(address, size, label)
        method = getattr(self._reader, "read_code", None)
        raw = method(address, size, label) if callable(method) else self._reader.read(address, size, label)
        return self._record(address, size, label, raw)

    def qword(self, address: int, label: str) -> tuple[int, bytes]:
        if address & 7:
            raise ValueError(f"{label}_alignment_invalid")
        raw = self.read(address, 8, label)
        if not isinstance(raw, bytes) or len(raw) != 8:
            raise ValueError(f"{label}_short_read")
        return int.from_bytes(raw, "little"), raw


def _valid_pointer(pointer: int, label: str) -> int:
    if (isinstance(pointer, bool) or not isinstance(pointer, int)
            or not _mission_task_memory._valid_pointer(pointer) or pointer & 7):
        raise ValueError(f"{label}_pointer_invalid")
    return pointer


def _read_qword(reader: _TrackingReader, address: int, label: str) -> int:
    return reader.qword(address, label)[0]


def _parse_source(source: Any) -> list[dict[str, Any]]:
    if (not isinstance(source, Mapping) or source.get("status") != "observed"
            or source.get("complete") is not True):
        raise ValueError("loaded_prerequisites_not_observed_complete")
    tasks = source.get("tasks")
    if not isinstance(tasks, list) or len(tasks) > MAX_CAPTURED_TASKS:
        raise ValueError("loaded_prerequisite_tasks_missing_or_over_bound")
    declared_task_count = source.get("total_task_count")
    if (isinstance(declared_task_count, bool) or not isinstance(declared_task_count, int)
            or declared_task_count != len(tasks)):
        raise ValueError("loaded_prerequisite_task_count_mismatch")

    descriptors: list[dict[str, Any]] = []
    seen_root_task: set[tuple[str, str]] = set()
    id_to_pointer: dict[str, int] = {}
    pointer_to_id: dict[int, str] = {}
    total_required = 0
    for index, row in enumerate(tasks):
        if not isinstance(row, Mapping):
            raise ValueError(f"loaded_prerequisite_task_{index}_not_object")
        root_id = row.get("root_id")
        task_id = row.get("task_id")
        if not isinstance(root_id, str) or not _IDENTIFIER.fullmatch(root_id):
            raise ValueError(f"loaded_prerequisite_task_{index}_root_id_invalid")
        if not isinstance(task_id, str) or not _IDENTIFIER.fullmatch(task_id):
            raise ValueError(f"loaded_prerequisite_task_{index}_task_id_invalid")
        pointer = _mission_prerequisite_memory._parse_address(
            row.get("task_pointer"), f"loaded_task_{root_id}_{task_id}"
        )
        required_ids = row.get("required_task_ids")
        if not isinstance(required_ids, list) or len(required_ids) > MAX_REQUIRED_PER_TASK:
            raise ValueError(f"loaded_prerequisite_task_{root_id}_{task_id}_required_ids_invalid")
        for required_index, required_id in enumerate(required_ids):
            if not isinstance(required_id, str) or not _IDENTIFIER.fullmatch(required_id):
                raise ValueError(
                    f"loaded_prerequisite_{root_id}_{task_id}_required_{required_index}_invalid"
                )
        total_required += len(required_ids)
        if total_required > MAX_TOTAL_REQUIRED:
            raise ValueError("loaded_prerequisite_total_required_over_bound")
        pair = (root_id, task_id)
        if pair in seen_root_task:
            raise ValueError(f"duplicate_loaded_root_task:{root_id}:{task_id}")
        seen_root_task.add(pair)
        previous_pointer = id_to_pointer.get(task_id)
        if previous_pointer is not None and previous_pointer != pointer:
            raise ValueError(f"conflicting_loaded_task_id:{task_id}")
        previous_id = pointer_to_id.get(pointer)
        if previous_id is not None and previous_id != task_id:
            raise ValueError(f"conflicting_loaded_task_pointer:{hex(pointer)}")
        id_to_pointer[task_id] = pointer
        pointer_to_id[pointer] = task_id
        descriptors.append({
            "root_id": root_id,
            "task_id": task_id,
            "task_pointer": pointer,
            "required_task_ids": list(required_ids),
        })

    declared_required_count = source.get("total_required_count")
    if (isinstance(declared_required_count, bool) or not isinstance(declared_required_count, int)
            or declared_required_count != total_required):
        raise ValueError("loaded_prerequisite_required_count_mismatch")
    return descriptors


def _read_map_header(reader: _TrackingReader, address: int, label: str,
                     max_size: int) -> dict[str, Any]:
    _valid_pointer(address, f"{label}_object")
    raw = reader.read(address, MAP_HEADER_BYTES, f"mission_condition.{label}.header")
    if not isinstance(raw, bytes) or len(raw) != MAP_HEADER_BYTES:
        raise ValueError(f"{label}_header_short")
    sentinel = int.from_bytes(raw[8:16], "little")
    size = int.from_bytes(raw[16:24], "little")
    begin = int.from_bytes(raw[24:32], "little")
    end = int.from_bytes(raw[32:40], "little")
    capacity_end = int.from_bytes(raw[40:48], "little")
    mask = int.from_bytes(raw[48:56], "little")
    bucket_count = int.from_bytes(raw[56:64], "little")

    _valid_pointer(sentinel, f"{label}_sentinel")
    if isinstance(size, bool) or size > max_size:
        raise ValueError(f"{label}_size_over_bound")
    if (bucket_count < 8 or bucket_count > MAX_MAP_BUCKETS
            or bucket_count & (bucket_count - 1) or mask + 1 != bucket_count):
        raise ValueError(f"{label}_bucket_mask_or_count_invalid")
    _valid_pointer(begin, f"{label}_buckets_begin")
    if begin & 0xF:
        raise ValueError(f"{label}_buckets_begin_alignment_invalid")
    expected_end = begin + bucket_count * MAP_BUCKET_PAIR_BYTES
    if expected_end > MAX_USER_ADDRESS or end != expected_end:
        raise ValueError(f"{label}_bucket_range_invalid")
    if (capacity_end < end or capacity_end > MAX_USER_ADDRESS
            or capacity_end - begin > MAX_MAP_BUCKETS * MAP_BUCKET_PAIR_BYTES
            or capacity_end & 0xF):
        raise ValueError(f"{label}_bucket_capacity_invalid")
    return {
        "address": address,
        "sentinel": sentinel,
        "size": size,
        "begin": begin,
        "end": end,
        "capacity_end": capacity_end,
        "mask": mask,
        "bucket_count": bucket_count,
        "raw_hex": raw.hex(),
    }


def _fnv1_name(value: str) -> int:
    result = 0x811C9DC5
    for byte in value.encode("ascii"):
        result = ((result * 0x01000193) & 0xFFFFFFFF) ^ byte
    return result


def _fnv1a64(raw: bytes) -> int:
    result = 0xCBF29CE484222325
    for byte in raw:
        result = ((result ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return result


class _MapWalk:
    def __init__(self, reader: _TrackingReader, header: Mapping[str, Any], label: str,
                 total_chain_steps: list[int] | None = None):
        self.reader = reader
        self.header = header
        self.label = label
        self.total_chain_steps = total_chain_steps if total_chain_steps is not None else [0]

    def _bucket(self, bucket_index: int, operation: str) -> tuple[int, int]:
        address = int(self.header["begin"]) + bucket_index * MAP_BUCKET_PAIR_BYTES
        raw = self.reader.read(address, MAP_BUCKET_PAIR_BYTES,
                              f"mission_condition.{self.label}.{operation}.bucket[{bucket_index}]")
        if not isinstance(raw, bytes) or len(raw) != MAP_BUCKET_PAIR_BYTES:
            raise ValueError(f"{self.label}_bucket_pair_short")
        first = int.from_bytes(raw[:8], "little")
        last = int.from_bytes(raw[8:], "little")
        sentinel = int(self.header["sentinel"])
        for name, pointer in (("first", first), ("last", last)):
            if pointer != sentinel:
                _valid_pointer(pointer, f"{self.label}_{name}_node")
        if (first == sentinel) != (last == sentinel):
            raise ValueError(f"{self.label}_bucket_endpoints_mismatch")
        return first, last

    def _node_links(self, node: int, first: int, operation: str) -> int:
        next_pointer = _read_qword(
            self.reader, node,
            f"mission_condition.{self.label}.{operation}.node[{hex(node)}].next",
        )
        previous = _read_qword(
            self.reader, node + 8,
            f"mission_condition.{self.label}.{operation}.node[{hex(node)}].prev",
        )
        sentinel = int(self.header["sentinel"])
        if next_pointer != sentinel:
            _valid_pointer(next_pointer, f"{self.label}_next")
        if previous != sentinel:
            _valid_pointer(previous, f"{self.label}_prev")
        if node != first:
            if previous == sentinel:
                raise ValueError(f"{self.label}_bucket_chain_ended_before_first")
            reverse_next = _read_qword(
                self.reader, previous,
                f"mission_condition.{self.label}.{operation}.node[{hex(previous)}].next_check",
            )
            if reverse_next != node:
                raise ValueError(f"{self.label}_bucket_chain_broken")
        return previous

    def _visit(self, count: int, visited: set[int], node: int) -> None:
        if node in visited:
            raise ValueError(f"{self.label}_bucket_node_cycle")
        if count >= MAX_BUCKET_NODES:
            raise ValueError(f"{self.label}_bucket_node_limit_exceeded")
        if self.total_chain_steps[0] >= MAX_TOTAL_CHAIN_STEPS:
            raise ValueError("max_total_chain_steps_exceeded")
        if count >= int(self.header["size"]):
            raise ValueError(f"{self.label}_bucket_nodes_exceed_map_size")
        visited.add(node)
        self.total_chain_steps[0] += 1

    def find_name(self, name: str) -> int:
        bucket_index = _fnv1_name(name) & int(self.header["mask"])
        first, last = self._bucket(bucket_index, f"name[{name}]")
        sentinel = int(self.header["sentinel"])
        if last == sentinel:
            raise ValueError(f"canonical_definition_missing:{name}")
        if int(self.header["size"]) == 0:
            raise ValueError("name_registry_empty_with_nonempty_bucket")

        matches: list[int] = []
        visited: set[int] = set()
        node = last
        count = 0
        while True:
            self._visit(count, visited, node)
            count += 1
            previous = self._node_links(node, first, f"name[{name}]")
            decoded = _mission_prerequisite_memory._read_string(
                self.reader,
                node + 0x10,
                f"mission_condition.name_registry.node[{hex(node)}].key",
            )
            key_text = decoded["text"]
            if (_fnv1_name(key_text) & int(self.header["mask"])) != bucket_index:
                raise ValueError("name_registry_key_in_wrong_bucket")
            if key_text == name:
                definition = _read_qword(
                    self.reader, node + 0x30,
                    f"mission_condition.name_registry.node[{hex(node)}].definition",
                )
                _valid_pointer(definition, "canonical_definition")
                matches.append(definition)
            if node == first:
                break
            if previous == sentinel:
                raise ValueError("name_registry_bucket_chain_broken")
            node = previous
        if not matches:
            raise ValueError(f"canonical_definition_missing:{name}")
        if len(matches) != 1:
            raise ValueError(f"canonical_definition_duplicate:{name}")
        return matches[0]

    def contains_definition(self, definition: int) -> bool:
        key = definition.to_bytes(8, "little")
        bucket_index = _fnv1a64(key) & int(self.header["mask"])
        first, last = self._bucket(bucket_index, f"completed[{hex(definition)}]")
        sentinel = int(self.header["sentinel"])
        if last == sentinel:
            return False
        if int(self.header["size"]) == 0:
            raise ValueError("completed_map_nonempty_bucket_with_zero_size")

        matches = 0
        visited: set[int] = set()
        node = last
        count = 0
        while True:
            self._visit(count, visited, node)
            count += 1
            previous = self._node_links(node, first, f"completed[{hex(definition)}]")
            node_key = _read_qword(
                self.reader, node + 0x10,
                f"mission_condition.completed.node[{hex(node)}].definition_key",
            )
            if _fnv1a64(node_key.to_bytes(8, "little")) & int(self.header["mask"]) != bucket_index:
                raise ValueError("completed_map_key_in_wrong_bucket")
            if node_key == definition:
                matches += 1
            if node == first:
                break
            if previous == sentinel:
                raise ValueError("completed_map_bucket_chain_broken")
            node = previous
        if matches > 1:
            raise ValueError("completed_map_duplicate_definition_key")
        return matches == 1


def _validate_definition(reader: _TrackingReader, module_base: int, definition: int,
                         expected_name: str) -> None:
    _mission_prerequisite_memory._read_contract(
        reader,
        module_base,
        definition,
        expected_vtable_rva=_mission_task_memory.TASK_VTABLE_RVA,
        expected_parser_rva=_mission_task_memory.TASK_PARSER_RVA,
        label=f"definition[{expected_name}]",
    )
    decoded = _mission_prerequisite_memory._read_string(
        reader,
        definition + _mission_task_memory.TASK_DEFINITION_NAME_OFFSET,
        f"mission_condition.definition[{expected_name}].id",
    )
    if decoded["text"] != expected_name:
        raise ValueError(f"canonical_definition_id_mismatch:{expected_name}")


def capture_conditions(reader: Any, module_base: int, country_pointer: int,
                       loaded_prerequisites: Any, *,
                       code_guards: list[dict[str, Any]]) -> dict[str, Any]:
    """Resolve and evaluate loaded task prerequisite completion via bounded RPM."""
    if (isinstance(module_base, bool) or not isinstance(module_base, int)
            or not _mission_task_memory._valid_pointer(module_base)):
        return _unknown("module_base_invalid")
    if (isinstance(country_pointer, bool) or not isinstance(country_pointer, int)
            or not _mission_task_memory._valid_pointer(country_pointer) or country_pointer & 7):
        return _unknown("country_pointer_invalid")
    reader_module = getattr(reader, "module_base", module_base)
    if reader_module != module_base:
        return _unknown("reader_module_base_mismatch")
    try:
        descriptors = _parse_source(loaded_prerequisites)
    except Exception as exc:
        return _unknown(f"loaded_prerequisite_validation_failed:{exc}")

    tracked = _TrackingReader(reader)
    guard_reports: list[dict[str, Any]] = []
    try:
        guard_reports = _mission_prerequisite_memory._validate_code_guards(
            tracked, module_base, code_guards
        )
    except Exception as exc:
        return _unknown(f"runtime_code_guard_failed:{exc}", code_guards=guard_reports)

    output_tasks: list[dict[str, Any]] = []
    compare_tasks: list[dict[str, Any]] = []
    try:
        registry_address = module_base + REGISTRY_SINGLETON_RVA
        registry = _read_qword(
            tracked, registry_address, "mission_condition.registry_singleton"
        )
        _valid_pointer(registry, "mission_name_registry")
        registry_vtable = _read_qword(
            tracked, registry, "mission_condition.registry.vtable"
        )
        if registry_vtable != module_base + REGISTRY_VTABLE_RVA:
            raise ValueError("mission_name_registry_vtable_mismatch")
        name_map = _read_map_header(
            tracked, registry + REGISTRY_MAP_OFFSET, "name_registry", MAX_NAME_MAP_SIZE
        )
        completed_map = _read_map_header(
            tracked, country_pointer + COMPLETED_MAP_OFFSET,
            "completed_map", MAX_COMPLETED_MAP_SIZE,
        )
        if name_map["size"] == 0:
            raise ValueError("mission_name_registry_empty")

        total_chain_steps = [0]
        names = _MapWalk(tracked, name_map, "name_registry", total_chain_steps)
        completed = _MapWalk(tracked, completed_map, "completed_map", total_chain_steps)
        definition_cache: dict[str, int] = {}
        completed_cache: dict[int, bool] = {}

        def resolve(name: str) -> int:
            pointer = definition_cache.get(name)
            if pointer is None:
                pointer = names.find_name(name)
                _validate_definition(tracked, module_base, pointer, name)
                definition_cache[name] = pointer
            return pointer

        def is_completed(definition: int) -> bool:
            if definition not in completed_cache:
                completed_cache[definition] = completed.contains_definition(definition)
            return completed_cache[definition]

        for row in descriptors:
            task_id = row["task_id"]
            canonical_task = resolve(task_id)
            if canonical_task != row["task_pointer"]:
                raise ValueError(f"loaded_task_pointer_not_canonical:{row['root_id']}:{task_id}")
            task_completed = is_completed(canonical_task)
            required_rows: list[dict[str, Any]] = []
            required_compare: list[dict[str, Any]] = []
            for required_id in row["required_task_ids"]:
                required_definition = resolve(required_id)
                required_completed = is_completed(required_definition)
                required_rows.append({
                    "task_id": required_id,
                    "definition_pointer": _mission_task_memory._address(required_definition, module_base),
                    "completed": required_completed,
                })
                required_compare.append({
                    "task_id": required_id,
                    "definition_pointer": required_definition,
                    "completed": required_completed,
                })
            prerequisites_satisfied = all(item["completed"] for item in required_rows)
            output_tasks.append({
                "root_id": row["root_id"],
                "task_id": task_id,
                "task_pointer": _mission_task_memory._address(canonical_task, module_base),
                "task_completed": task_completed,
                "required": required_rows,
                "prerequisites_satisfied": prerequisites_satisfied,
            })
            compare_tasks.append({
                "root_id": row["root_id"],
                "task_id": task_id,
                "task_pointer": canonical_task,
                "task_completed": task_completed,
                "required": required_compare,
                "prerequisites_satisfied": prerequisites_satisfied,
            })
    except Exception as exc:
        return _unknown(f"condition_capture_failed:{exc}", output_tasks, guard_reports)

    compare = {
        "status": "observed",
        "code_guards": [
            {"rva": row["rva"], "raw_hex": row["raw_hex"], "sha256": row["sha256"]}
            for row in guard_reports
        ],
        "module_base": module_base,
        "country_pointer": country_pointer,
        "registry_pointer": registry,
        "registry_map": {key: value for key, value in name_map.items() if key != "address"},
        "completed_map": {key: value for key, value in completed_map.items() if key != "address"},
        "tasks": compare_tasks,
        "rawreads": tracked.rawreads,
    }
    return {
        "status": "observed",
        "complete": True,
        "reason": None,
        "unknown_conditions": [],
        "code_guards": guard_reports,
        "tasks": output_tasks,
        "total_task_count": len(output_tasks),
        "total_required_count": sum(len(row["required"]) for row in output_tasks),
        "evaluation_scope": "loaded_task_completion_and_prerequisite_conjunction_only",
        "_compare": compare,
    }


__all__ = ["capture_conditions"]
