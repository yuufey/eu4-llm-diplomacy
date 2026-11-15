"""Bounded RPM capture of literal mission prerequisite vectors.

This module only follows root/task objects that were already captured as
observed and complete by :mod:`mission_task_memory`. It does not infer task
eligibility or call native code. Runtime code guards are supplied by the
caller so the profile loader and its provenance remain independently owned.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping

from . import mission_memory as _mission_memory
from . import mission_task_memory as _mission_task_memory


PREREQUISITE_VECTOR_POINTER_OFFSET = 0x128
PREREQUISITE_VECTOR_CAPACITY_OFFSET = 0x130
PREREQUISITE_VECTOR_COUNT_OFFSET = 0x134
PREREQUISITE_VECTOR_HEADER_BYTES = 16
STRING32_BYTES = 32
MAX_REQUIRED_PER_TASK = 512
MAX_TOTAL_REQUIRED = 4096
MAX_CAPTURED_TASKS = 4096
MAX_CODE_GUARD_BYTES = 512 * 1024

_IDENTIFIER = re.compile(r"^[A-Za-z0-9_]+$", re.ASCII)
_HEX = re.compile(r"^[0-9a-fA-F]+$", re.ASCII)
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$", re.ASCII)


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


def _parse_address(value: Any, label: str, *, allow_zero: bool = False) -> int:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label}_address_object_missing")
    raw = value.get("va")
    if not isinstance(raw, str):
        raise ValueError(f"{label}_address_va_missing")
    try:
        parsed = int(raw, 0)
    except ValueError as exc:
        raise ValueError(f"{label}_address_va_invalid") from exc
    if parsed == 0 and allow_zero:
        return parsed
    if not _mission_task_memory._valid_pointer(parsed):
        raise ValueError(f"{label}_pointer_invalid")
    return parsed


def _validate_source_status(source: Any) -> tuple[Mapping[str, Any], list[dict[str, Any]]]:
    if isinstance(source, Mapping) and isinstance(source.get("loaded_tasks"), Mapping):
        source = source["loaded_tasks"]
    if not isinstance(source, Mapping) or source.get("status") != "observed" or source.get("complete") is not True:
        raise ValueError("loaded_tasks_not_observed_complete")
    roots = source.get("roots")
    if not isinstance(roots, list):
        raise ValueError("loaded_task_roots_missing")
    total = source.get("total_task_count")
    if isinstance(total, bool) or not isinstance(total, int) or total < 0 or total > MAX_CAPTURED_TASKS:
        raise ValueError("loaded_task_total_count_invalid")

    root_ids: set[str] = set()
    task_ids_by_root: dict[str, set[str]] = {}
    task_pointers_by_root: dict[str, set[int]] = {}
    id_to_pointer: dict[str, int] = {}
    pointer_to_id: dict[int, str] = {}
    descriptors: list[dict[str, Any]] = []
    seen_count = 0
    for root_index, root in enumerate(roots):
        if not isinstance(root, Mapping) or root.get("status") != "observed" or root.get("complete") is not True:
            raise ValueError(f"loaded_root_{root_index}_not_observed_complete")
        root_id = root.get("root_id")
        if not isinstance(root_id, str) or not _IDENTIFIER.fullmatch(root_id):
            raise ValueError(f"loaded_root_{root_index}_identifier_invalid")
        if root_id in root_ids:
            raise ValueError(f"duplicate_loaded_root_id:{root_id}")
        root_ids.add(root_id)
        root_pointer = _parse_address(root.get("root_pointer"), f"root_{root_id}")

        tasks = root.get("tasks")
        task_names = root.get("task_ids")
        if not isinstance(tasks, list) or not isinstance(task_names, list):
            raise ValueError(f"loaded_root_{root_id}_task_coverage_missing")
        if len(tasks) > _mission_task_memory.MAX_TASKS_PER_ROOT:
            raise ValueError(f"loaded_root_{root_id}_task_count_exceeds_bound")
        if len(task_names) != len(tasks):
            raise ValueError(f"loaded_root_{root_id}_task_coverage_incomplete")
        current_names: list[str] = []
        current_pointers: list[int] = []
        task_ids_by_root[root_id] = set()
        task_pointers_by_root[root_id] = set()
        for task_index, task in enumerate(tasks):
            if not isinstance(task, Mapping) or task.get("status") != "observed" or task.get("complete") is not True:
                raise ValueError(f"loaded_task_{root_id}_{task_index}_not_observed_complete")
            task_id_row = task.get("task_id")
            if not isinstance(task_id_row, Mapping) or task_id_row.get("status") != "observed" or task_id_row.get("complete") is not True:
                raise ValueError(f"loaded_task_{root_id}_{task_index}_id_not_observed")
            task_id = task_id_row.get("text")
            if not isinstance(task_id, str) or not _IDENTIFIER.fullmatch(task_id):
                raise ValueError(f"loaded_task_{root_id}_{task_index}_identifier_invalid")
            pointer = _parse_address(task.get("pointer"), f"task_{root_id}_{task_index}")
            if task_id in task_ids_by_root[root_id]:
                raise ValueError(f"duplicate_loaded_task_id:{root_id}:{task_id}")
            if pointer in task_pointers_by_root[root_id]:
                raise ValueError(f"duplicate_loaded_task_pointer:{root_id}:{hex(pointer)}")
            old_pointer = id_to_pointer.get(task_id)
            if old_pointer is not None and old_pointer != pointer:
                raise ValueError(f"conflicting_loaded_task_id:{task_id}")
            old_id = pointer_to_id.get(pointer)
            if old_id is not None and old_id != task_id:
                raise ValueError(f"conflicting_loaded_task_pointer:{hex(pointer)}")
            id_to_pointer[task_id] = pointer
            pointer_to_id[pointer] = task_id
            task_ids_by_root[root_id].add(task_id)
            task_pointers_by_root[root_id].add(pointer)
            current_names.append(task_id)
            current_pointers.append(pointer)
            descriptors.append({
                "root_id": root_id,
                "root_pointer": root_pointer,
                "task_id": task_id,
                "task_pointer": pointer,
                "source_root": root,
                "source_task": task,
                "task_index": task_index,
            })
        if task_names != current_names:
            raise ValueError(f"loaded_root_{root_id}_task_id_coverage_mismatch")
        seen_count += len(tasks)
    if seen_count != total:
        raise ValueError("loaded_task_total_count_does_not_match_roots")
    if seen_count > MAX_CAPTURED_TASKS:
        raise ValueError("loaded_task_total_count_exceeds_bound")
    return source, descriptors


def _validate_code_guards(reader: Any, module_base: int,
                          code_guards: Any) -> list[dict[str, Any]]:
    if not isinstance(code_guards, list) or not code_guards:
        raise ValueError("code_guards_missing")
    if len(code_guards) > 128:
        raise ValueError("code_guards_count_exceeds_bound")
    reports: list[dict[str, Any]] = []
    total_bytes = 0
    seen_rvas: set[int] = set()
    for index, item in enumerate(code_guards):
        if not isinstance(item, Mapping):
            raise ValueError(f"code_guard_{index}_not_object")
        rva = item.get("rva")
        raw_hex = item.get("raw_hex")
        digest = item.get("sha256")
        if isinstance(rva, bool) or not isinstance(rva, int) or rva < 0:
            raise ValueError(f"code_guard_{index}_rva_invalid")
        if rva in seen_rvas:
            raise ValueError(f"code_guard_{index}_duplicate_rva")
        seen_rvas.add(rva)
        if not isinstance(raw_hex, str) or not raw_hex or len(raw_hex) % 2 or not _HEX.fullmatch(raw_hex):
            raise ValueError(f"code_guard_{index}_raw_hex_invalid")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ValueError(f"code_guard_{index}_sha256_invalid")
        expected = bytes.fromhex(raw_hex)
        if len(expected) > _mission_task_memory.MAX_SINGLE_RPM:
            raise ValueError(f"code_guard_{index}_too_large")
        total_bytes += len(expected)
        if total_bytes > MAX_CODE_GUARD_BYTES:
            raise ValueError("code_guard_total_size_exceeds_bound")
        calculated = hashlib.sha256(expected).hexdigest()
        if calculated.lower() != digest.lower():
            raise ValueError(f"code_guard_{index}_sha256_mismatch")
        address = module_base + rva
        if address < 0x10000 or address + len(expected) > _mission_memory.MAX_USER_ADDRESS:
            raise ValueError(f"code_guard_{index}_address_out_of_bound")
        actual = _mission_task_memory._read_unaligned(
            reader, address, len(expected), f"mission_prerequisite.code_guard[{index}]"
        )
        if not isinstance(actual, bytes) or len(actual) != len(expected):
            raise ValueError(f"code_guard_{index}_short_read")
        report = {
            "rva": hex(rva),
            "expected_sha256": calculated,
            "sha256": hashlib.sha256(actual).hexdigest(),
            "expected_raw_hex": expected.hex(),
            "raw_hex": actual.hex(),
            "matches": actual == expected,
        }
        reports.append(report)
        if actual != expected:
            from .mission_observer_guard import verify_entry
            proof = verify_entry(reader, module_base, rva, expected, actual)
            if proof is None:
                raise ValueError(f"code_guard_{index}_runtime_mismatch")
            report["observer_patch"] = proof
    return reports


def _read_contract(reader: Any, module_base: int, pointer: int, *,
                   expected_vtable_rva: int, expected_parser_rva: int,
                   label: str) -> dict[str, Any]:
    vtable, vtable_raw = reader.qword(pointer, f"mission_prerequisite.{label}.vtable")
    if vtable != module_base + expected_vtable_rva:
        raise ValueError(f"{label}_vtable_mismatch")
    parser_address = vtable + _mission_task_memory.PARSER_ENTRY_OFFSET
    parser, parser_raw = reader.qword(parser_address, f"mission_prerequisite.{label}.parser")
    if parser != module_base + expected_parser_rva:
        raise ValueError(f"{label}_parser_mismatch")
    return {
        "vtable": vtable,
        "vtable_raw_hex": vtable_raw.hex(),
        "parser_address": parser_address,
        "parser": parser,
        "parser_raw_hex": parser_raw.hex(),
    }


def _read_string(reader: Any, address: int, label: str) -> dict[str, Any]:
    header = reader.read(address, STRING32_BYTES, f"{label}.header")
    if not isinstance(header, bytes) or len(header) != STRING32_BYTES:
        raise ValueError(f"{label}_header_short")
    decoded = _mission_memory._decode_string32(reader, address, header, label)
    if decoded.get("status") != "observed" or decoded.get("complete") is not True:
        raise ValueError(f"{label}_decode_failed:{decoded.get('unknown_reason') or 'unknown'}")
    text = decoded.get("text")
    if not isinstance(text, str) or not _IDENTIFIER.fullmatch(text):
        raise ValueError(f"{label}_identifier_invalid")
    return decoded


def _read_root_task_coverage(reader: Any, module_base: int, root: Mapping[str, Any],
                             root_pointer: int, expected_task_pointers: list[int],
                             root_id: str) -> dict[str, Any]:
    vector_address = root_pointer + _mission_task_memory.TASK_POINTER_OFFSET
    raw = reader.read(vector_address, _mission_task_memory.TASK_HEADER_BYTES,
                      f"mission_prerequisite.root[{root_id}].task_vector")
    if not isinstance(raw, bytes) or len(raw) != _mission_task_memory.TASK_HEADER_BYTES:
        raise ValueError(f"root_{root_id}_task_vector_short")
    pointer = int.from_bytes(raw[:8], "little")
    cap_offset = _mission_task_memory.TASK_CAPACITY_OFFSET - _mission_task_memory.TASK_POINTER_OFFSET
    count_offset = _mission_task_memory.TASK_COUNT_OFFSET - _mission_task_memory.TASK_POINTER_OFFSET
    capacity = int.from_bytes(raw[cap_offset:cap_offset + 4], "little", signed=True)
    count = int.from_bytes(raw[count_offset:count_offset + 4], "little", signed=True)
    if (capacity < 0 or count < 0 or count > capacity
            or capacity > _mission_task_memory.MAX_TASKS_PER_ROOT
            or count > _mission_task_memory.MAX_TASKS_PER_ROOT):
        raise ValueError(f"root_{root_id}_task_vector_bounds_invalid")
    if count != len(expected_task_pointers):
        raise ValueError(f"root_{root_id}_task_coverage_drift")
    prior = root.get("vector")
    if not isinstance(prior, Mapping):
        raise ValueError(f"loaded_root_{root_id}_vector_missing")
    prior_pointer = _parse_address(
        prior.get("pointer"), f"loaded_root_{root_id}_vector", allow_zero=True
    )
    if count and not _mission_task_memory._valid_pointer(pointer):
        raise ValueError(f"root_{root_id}_task_vector_pointer_invalid")
    if count and pointer + count * 8 > _mission_memory.MAX_USER_ADDRESS:
        raise ValueError(f"root_{root_id}_task_vector_range_out_of_bound")
    if pointer != prior_pointer or capacity != prior.get("capacity") or count != prior.get("count"):
        raise ValueError(f"root_{root_id}_task_vector_drift")
    prior_raw = prior.get("raw_hex")
    if not isinstance(prior_raw, str) or prior_raw.lower() != raw.hex():
        raise ValueError(f"root_{root_id}_task_vector_header_drift")
    entries_raw = b""
    if count:
        entries_raw = reader.read(pointer, count * 8, f"mission_prerequisite.root[{root_id}].task_pointers")
        if not isinstance(entries_raw, bytes) or len(entries_raw) != count * 8:
            raise ValueError(f"root_{root_id}_task_pointer_array_short")
        actual_pointers = [int.from_bytes(entries_raw[i * 8:(i + 1) * 8], "little") for i in range(count)]
        if actual_pointers != expected_task_pointers:
            raise ValueError(f"root_{root_id}_task_coverage_drift")
    elif pointer not in (0,) and not _mission_task_memory._valid_pointer(pointer):
        raise ValueError(f"root_{root_id}_empty_task_vector_pointer_invalid")
    return {
        "address": _mission_task_memory._address(vector_address, module_base),
        "pointer": _mission_task_memory._address(pointer, module_base),
        "capacity": capacity,
        "count": count,
        "raw_hex": raw.hex(),
        "entries_raw_hex": entries_raw.hex(),
        "pointer_offset": hex(_mission_task_memory.TASK_POINTER_OFFSET),
        "capacity_offset": hex(_mission_task_memory.TASK_CAPACITY_OFFSET),
        "count_offset": hex(_mission_task_memory.TASK_COUNT_OFFSET),
    }


def _capture_one_root(reader: Any, module_base: int, root_id: str,
                      root_pointer: int, root: Mapping[str, Any],
                      task_descriptors: list[dict[str, Any]],
                      total_required: list[int],
                      output_tasks: list[dict[str, Any]]) -> dict[str, Any]:
    root_contract = _read_contract(
        reader, module_base, root_pointer,
        expected_vtable_rva=_mission_task_memory.ROOT_VTABLE_RVA,
        expected_parser_rva=_mission_task_memory.ROOT_PARSER_RVA,
        label=f"root[{root_id}]",
    )
    root_name = _read_string(
        reader, root_pointer + _mission_task_memory.TASK_DEFINITION_NAME_OFFSET,
        f"mission_prerequisite.root[{root_id}].id",
    )
    if root_name["text"] != root_id:
        raise ValueError(f"root_id_drift:{root_id}")
    task_pointers = [row["task_pointer"] for row in task_descriptors]
    current_root_vector = _read_root_task_coverage(
        reader, module_base, root, root_pointer, task_pointers, root_id
    )
    root_compare = {
        "root_id": root_id,
        "root_pointer": root_pointer,
        "root_id_string": {
            "header_hex": root_name["header_hex"],
            "payload_hex": root_name["payload_hex"],
            "text": root_name["text"],
        },
        "vtable": root_contract["vtable"],
        "vtable_raw_hex": root_contract["vtable_raw_hex"],
        "parser": root_contract["parser"],
        "parser_raw_hex": root_contract["parser_raw_hex"],
        "task_vector": {
            "raw_hex": current_root_vector["raw_hex"],
            "entries_raw_hex": current_root_vector["entries_raw_hex"],
            "pointer": int(current_root_vector["pointer"]["va"], 0),
            "capacity": current_root_vector["capacity"],
            "count": current_root_vector["count"],
        },
        "tasks": [],
    }
    for row in task_descriptors:
        task_id = row["task_id"]
        task_pointer = row["task_pointer"]
        descriptor = _capture_task(reader, module_base, row, total_required)
        output_tasks.append(descriptor["public"])
        root_compare["tasks"].append(descriptor["compare"])
    return root_compare


def _capture_task(reader: Any, module_base: int, row: Mapping[str, Any],
                  total_required: list[int]) -> dict[str, Any]:
    root_id = row["root_id"]
    task_id = row["task_id"]
    task_pointer = row["task_pointer"]
    task_contract = _read_contract(
        reader, module_base, task_pointer,
        expected_vtable_rva=_mission_task_memory.TASK_VTABLE_RVA,
        expected_parser_rva=_mission_task_memory.TASK_PARSER_RVA,
        label=f"task[{root_id}:{task_id}]",
    )
    current_task_id = _read_string(
        reader, task_pointer + _mission_task_memory.TASK_DEFINITION_NAME_OFFSET,
        f"mission_prerequisite.task[{root_id}:{task_id}].id",
    )
    if current_task_id["text"] != task_id:
        raise ValueError(f"task_id_drift:{root_id}:{task_id}")

    vector_address = task_pointer + PREREQUISITE_VECTOR_POINTER_OFFSET
    vector_raw = reader.read(vector_address, PREREQUISITE_VECTOR_HEADER_BYTES,
                             f"mission_prerequisite.task[{root_id}:{task_id}].vector")
    if not isinstance(vector_raw, bytes) or len(vector_raw) != PREREQUISITE_VECTOR_HEADER_BYTES:
        raise ValueError(f"prerequisite_vector_short:{root_id}:{task_id}")
    vector_pointer = int.from_bytes(vector_raw[:8], "little")
    capacity = int.from_bytes(vector_raw[8:12], "little", signed=True)
    count = int.from_bytes(vector_raw[12:16], "little", signed=True)
    if capacity < 0 or count < 0 or count > capacity or capacity > MAX_REQUIRED_PER_TASK or count > MAX_REQUIRED_PER_TASK:
        raise ValueError(f"prerequisite_vector_bounds_invalid:{root_id}:{task_id}")
    if total_required[0] + count > MAX_TOTAL_REQUIRED:
        raise ValueError("total_prerequisite_limit_exceeded")
    total_required[0] += count
    if count == 0:
        if vector_pointer not in (0,) and not _mission_task_memory._valid_pointer(vector_pointer):
            raise ValueError(f"empty_prerequisite_vector_pointer_invalid:{root_id}:{task_id}")
        entries_raw = b""
    else:
        if not _mission_task_memory._valid_pointer(vector_pointer):
            raise ValueError(f"prerequisite_vector_pointer_invalid:{root_id}:{task_id}")
        if vector_pointer + count * STRING32_BYTES > _mission_memory.MAX_USER_ADDRESS:
            raise ValueError(f"prerequisite_vector_range_out_of_bound:{root_id}:{task_id}")
        entries_raw = reader.read(vector_pointer, count * STRING32_BYTES,
                                  f"mission_prerequisite.task[{root_id}:{task_id}].String32_array")
        if not isinstance(entries_raw, bytes) or len(entries_raw) != count * STRING32_BYTES:
            raise ValueError(f"prerequisite_String32_array_short:{root_id}:{task_id}")

    strings: list[dict[str, Any]] = []
    required_ids: list[str] = []
    string_compares: list[dict[str, Any]] = []
    for index in range(count):
        header_address = vector_pointer + index * STRING32_BYTES
        header = entries_raw[index * STRING32_BYTES:(index + 1) * STRING32_BYTES]
        decoded = _mission_memory._decode_string32(
            reader, header_address, header, f"mission_prerequisite.task[{root_id}:{task_id}].required[{index}]"
        )
        if decoded.get("status") != "observed" or decoded.get("complete") is not True:
            raise ValueError(
                f"prerequisite_string_decode_failed:{root_id}:{task_id}:{index}:"
                f"{decoded.get('unknown_reason') or 'unknown'}"
            )
        value = decoded.get("text")
        if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
            raise ValueError(f"prerequisite_identifier_invalid:{root_id}:{task_id}:{index}")
        strings.append(decoded)
        required_ids.append(value)
        string_compares.append({
            "header_hex": decoded["header_hex"],
            "payload_hex": decoded["payload_hex"],
            "text": value,
        })

    vector = {
        "address": _mission_task_memory._address(vector_address, module_base),
        "pointer": _mission_task_memory._address(vector_pointer, module_base),
        "capacity": capacity,
        "count": count,
        "raw_hex": vector_raw.hex(),
        "entries_raw_hex": entries_raw.hex(),
        "pointer_offset": hex(PREREQUISITE_VECTOR_POINTER_OFFSET),
        "capacity_offset": hex(PREREQUISITE_VECTOR_CAPACITY_OFFSET),
        "count_offset": hex(PREREQUISITE_VECTOR_COUNT_OFFSET),
    }
    public = {
        "root_id": root_id,
        "task_id": task_id,
        "task_pointer": _mission_task_memory._address(task_pointer, module_base),
        "required_task_ids": required_ids,
        "vector": vector,
        "strings": {"task_id": current_task_id, "required_task_ids": strings},
    }
    compare = {
        "root_id": root_id,
        "task_id": task_id,
        "task_pointer": task_pointer,
        "task_id_string": {
            "header_hex": current_task_id["header_hex"],
            "payload_hex": current_task_id["payload_hex"],
            "text": current_task_id["text"],
        },
        "vtable": task_contract["vtable"],
        "vtable_raw_hex": task_contract["vtable_raw_hex"],
        "parser": task_contract["parser"],
        "parser_raw_hex": task_contract["parser_raw_hex"],
        "vector": {
            "raw_hex": vector_raw.hex(),
            "entries_raw_hex": entries_raw.hex(),
            "pointer": vector_pointer,
            "capacity": capacity,
            "count": count,
        },
        "required_task_ids": required_ids,
        "strings": string_compares,
    }
    return {"public": public, "compare": compare}


def capture_prerequisites(reader: Any, module_base: int, loaded_tasks: Any,
                          *, code_guards: list[dict[str, Any]]) -> dict[str, Any]:
    """Capture prerequisite IDs from a complete observed loaded-task snapshot.

    The caller supplies explicit runtime code guards that have been fixed and
    validated by its independent profile path. Guards are verified before any
    root or task object is dereferenced.
    """
    if isinstance(module_base, bool) or not isinstance(module_base, int) or not _mission_task_memory._valid_pointer(module_base):
        return _unknown("module_base_invalid")
    reader_module = getattr(reader, "module_base", module_base)
    if reader_module != module_base:
        return _unknown("reader_module_base_mismatch")
    guard_reports: list[dict[str, Any]] = []
    try:
        guard_reports = _validate_code_guards(reader, module_base, code_guards)
    except Exception as exc:
        return _unknown(f"runtime_code_guard_failed:{exc}", code_guards=guard_reports)
    try:
        _source, descriptors = _validate_source_status(loaded_tasks)
    except Exception as exc:
        return _unknown(f"loaded_task_validation_failed:{exc}", code_guards=guard_reports)

    roots: list[dict[str, Any]] = []
    roots_by_id: dict[str, dict[str, Any]] = {}
    for source_root in _source.get("roots", []):
        root_id = source_root["root_id"]
        root_pointer = _parse_address(source_root["root_pointer"], f"root_{root_id}")
        roots_by_id[root_id] = {
            "root_pointer": root_pointer,
            "source_root": source_root,
            "tasks": [],
        }
        roots.append(roots_by_id[root_id])
    for descriptor in descriptors:
        root_id = descriptor["root_id"]
        roots_by_id[root_id]["tasks"].append(descriptor)
    # A complete observed snapshot may legitimately contain no roots. It still
    # reaches an observed result only when its explicit total is zero.
    output_tasks: list[dict[str, Any]] = []
    root_compares: list[dict[str, Any]] = []
    total_required = [0]
    try:
        for root_id, root_data in roots_by_id.items():
            root_compares.append(_capture_one_root(
                reader,
                module_base,
                root_id,
                root_data["root_pointer"],
                root_data["source_root"],
                root_data["tasks"],
                total_required,
                output_tasks,
            ))
    except Exception as exc:
        return _unknown(f"prerequisite_capture_failed:{exc}", output_tasks, guard_reports)

    compare = {
        "status": "observed",
        "code_guards": guard_reports,
        "roots": root_compares,
        "total_task_count": len(output_tasks),
        "total_required_count": total_required[0],
    }
    return {
        "status": "observed",
        "complete": True,
        "reason": None,
        "unknown_conditions": [],
        "code_guards": guard_reports,
        "tasks": output_tasks,
        "total_task_count": len(output_tasks),
        "total_required_count": total_required[0],
        "_compare": compare,
    }


__all__ = ["capture_prerequisites"]
