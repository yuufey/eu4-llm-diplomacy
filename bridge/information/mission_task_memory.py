"""Bounded read-only access to the loaded mission task vectors.

The root mission reader already proves the country identity and the root
definition strings.  This module follows the separately audited vector on
each loaded root only when the caller explicitly asks for it.  The profile
contains ordinary static file guards and the two parser/vtable contracts;
runtime vtable entries are relocated and are therefore compared with
``module_base + expected_rva`` rather than with the file bytes.

This is an observation helper, not a native invocation path.  It performs no
function calls, writes, heap scan, injection, date advance, or save.  Any
failed read, malformed vector, vtable mismatch, or incomplete String32 leaves
the affected task result unknown.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from . import mission_memory as _mission_memory


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "mission-task-memory-1374.json"
PROFILE_MAX_BYTES = 64 * 1024
EXPECTED_PROFILE_SHA256 = "3f855893f34a2203c4f77f885e2d68ebcf4e4d76ca33d8eea3ba9a6e9c648fd6"


class ProfileError(RuntimeError):
    """The task profile is absent, oversized, malformed, or tampered."""


class ProbeError(RuntimeError):
    """A bounded task read cannot be completed safely."""


def _load_profile(
    path: Path = PROFILE_FILE,
    expected_sha256: str = EXPECTED_PROFILE_SHA256,
) -> dict[str, Any]:
    try:
        size = path.stat().st_size
        if size <= 0 or size > PROFILE_MAX_BYTES:
            raise ProfileError(f"profile_size_out_of_bound:{size}")
        raw = path.read_bytes()
    except (OSError, UnicodeError) as exc:
        raise ProfileError(f"profile_read_failed:{exc}") from exc
    if len(raw) != size or len(raw) > PROFILE_MAX_BYTES:
        raise ProfileError("profile_read_size_changed")
    actual = hashlib.sha256(raw).hexdigest()
    if actual.lower() != expected_sha256.lower():
        raise ProfileError("profile_sha256_mismatch")
    try:
        profile = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"profile_json_invalid:{exc}") from exc
    if not isinstance(profile, dict) or profile.get("profile_id") != "mission-task-memory-1374":
        raise ProfileError("profile_shape_invalid")
    return profile


PROFILE = _load_profile()


def _profile_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        parsed = None
    elif isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value, 0)
        except ValueError:
            parsed = None
    else:
        parsed = None
    if parsed is None or parsed < 0:
        raise ProfileError(f"profile_integer_invalid:{label}")
    return parsed


EXPECTED_EXE_SHA256 = str(PROFILE["executable"]["sha256"]).lower()
EXPECTED_VERSION = str(PROFILE["game_version"])
EXPECTED_COUNTRY = "FRA"

TASK_VECTOR = PROFILE["task_vector"]
ROOT_VTABLE_RVA = _profile_int(TASK_VECTOR["root_vtable_rva"], "root_vtable_rva")
TASK_VTABLE_RVA = _profile_int(TASK_VECTOR["task_vtable_rva"], "task_vtable_rva")
ROOT_PARSER_RVA = _profile_int(TASK_VECTOR["root_parser_rva"], "root_parser_rva")
TASK_PARSER_RVA = _profile_int(TASK_VECTOR["task_parser_rva"], "task_parser_rva")
PARSER_ENTRY_OFFSET = _profile_int(TASK_VECTOR["parser_entry_offset"], "parser_entry_offset")
TASK_POINTER_OFFSET = _profile_int(TASK_VECTOR["pointer_offset"], "pointer_offset")
TASK_CAPACITY_OFFSET = _profile_int(TASK_VECTOR["capacity_offset"], "capacity_offset")
TASK_COUNT_OFFSET = _profile_int(TASK_VECTOR["count_offset"], "count_offset")
TASK_HEADER_BYTES = _profile_int(TASK_VECTOR["header_bytes"], "header_bytes")
TASK_DEFINITION_NAME_OFFSET = _profile_int(
    TASK_VECTOR["task_object_definition_name_offset"], "task_object_definition_name_offset"
)
ROOT_VTABLE_ENTRIES = tuple(
    _profile_int(value, "root_vtable_expected_entry_rva")
    for value in TASK_VECTOR["root_vtable_expected_entry_rvas"]
)
TASK_VTABLE_ENTRIES = tuple(
    _profile_int(value, "task_vtable_expected_entry_rva")
    for value in TASK_VECTOR["task_vtable_expected_entry_rvas"]
)

MAX_TOTAL_RPM = _profile_int(PROFILE["limits"]["max_total_rpm"], "max_total_rpm")
MAX_SINGLE_RPM = _profile_int(PROFILE["limits"]["max_single_rpm"], "max_single_rpm")
MAX_TASKS_PER_ROOT = _profile_int(PROFILE["limits"]["max_tasks_per_root"], "max_tasks_per_root")
MAX_TOTAL_TASKS = _profile_int(PROFILE["limits"]["max_total_tasks"], "max_total_tasks")
MAX_ASCII_LENGTH = _profile_int(PROFILE["limits"]["max_ascii_length"], "max_ascii_length")
MAX_STRING_CAPACITY = _profile_int(PROFILE["limits"]["max_string_capacity"], "max_string_capacity")
MAX_USER_ADDRESS = _mission_memory.MAX_USER_ADDRESS


def _hex(value: int | None) -> str | None:
    return hex(value) if isinstance(value, int) else None


def _parse_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _valid_pointer(value: int) -> bool:
    return _mission_memory._valid_pointer(value)


def _address(value: int | None, module_base: int | None = None, *, known_rva: int | None = None) -> dict[str, Any]:
    return _mission_memory._address(value, module_base, known_rva=known_rva)


def _read_unaligned(reader: Any, address: int, size: int, label: str) -> bytes:
    """Use a reader's unaligned path for code/byte slices when available."""
    method = getattr(reader, "read_code", None)
    if callable(method):
        return method(address, size, label)
    method = getattr(reader, "_read", None)
    if callable(method):
        return method(address, size, label, aligned=False)
    return reader.read(address, size, label)


def _profile_code_guards(profile: Mapping[str, Any] | None = None) -> list[tuple[str, int, bytes]]:
    profile = PROFILE if profile is None else profile
    guards: list[tuple[str, int, bytes]] = []
    for item in profile["code_guards"]:
        if not isinstance(item, Mapping):
            raise ProfileError("profile_code_guard_not_object")
        name = str(item["name"])
        rva = _profile_int(item["rva"], f"code_guard.{name}.rva")
        raw_hex = item.get("bytes")
        if not isinstance(raw_hex, str) or not raw_hex or len(raw_hex) % 2:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}")
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}") from exc
        if len(raw) > MAX_SINGLE_RPM:
            raise ProfileError(f"profile_code_guard_too_large:{name}")
        guards.append((name, rva, raw))
    return guards


def _profile_vtable_guards(profile: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    profile = PROFILE if profile is None else profile
    vector = profile["task_vector"]
    result: list[dict[str, Any]] = []
    for name, expected in (("root_vtable_table", vector["root_vtable_file_guard"]), ("task_vtable_table", vector["task_vtable_file_guard"])):
        if not isinstance(expected, Mapping):
            raise ProfileError(f"profile_vtable_guard_not_object:{name}")
        rva = _profile_int(expected.get("rva"), f"vtable_guard.{name}.rva")
        size = _profile_int(expected.get("size"), f"vtable_guard.{name}.size")
        raw_hex = expected.get("bytes")
        if size <= 0 or size > MAX_SINGLE_RPM or not isinstance(raw_hex, str) or len(raw_hex) != size * 2:
            raise ProfileError(f"profile_vtable_guard_shape_invalid:{name}")
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise ProfileError(f"profile_vtable_guard_hex_invalid:{name}") from exc
        try:
            entries = tuple(_profile_int(value, f"vtable_guard.{name}.entry") for value in vector[
                "root_vtable_expected_entry_rvas" if name.startswith("root_") else "task_vtable_expected_entry_rvas"
            ])
        except (KeyError, TypeError) as exc:
            raise ProfileError(f"profile_vtable_guard_entries_invalid:{name}") from exc
        if size != len(entries) * 8:
            raise ProfileError(f"profile_vtable_guard_entry_size_invalid:{name}")
        result.append({
            "name": name,
            "rva": rva,
            "size": size,
            "bytes": raw,
            "sha256": str(expected.get("sha256", "")).lower(),
            "expected_entry_rvas": entries,
        })
    return result


def _unknown_task_result(reason: str) -> dict[str, Any]:
    return {
        "status": "unknown",
        "complete": False,
        "roots": [],
        "total_task_count": 0,
        "unknown_conditions": [reason],
    }


def unknown_loaded_tasks(reason: str) -> dict[str, Any]:
    """Return the public fail-closed value used after a task-only failure."""
    result = _unknown_task_result(reason)
    result["supported_scope"] = "FRA_loaded_root_task_vectors_only"
    return result


_unknown_loaded_tasks = unknown_loaded_tasks


def _static_contract_guard() -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "evidence_kind": "ordinary_static_file_bytes_with_REA_source_not_REA_Evidence",
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "checks": {},
        "unknown_conditions": [],
    }
    try:
        profile = _load_profile()
        vector = profile["task_vector"]
        code_guards = _profile_code_guards(profile)
        vtable_guards = _profile_vtable_guards(profile)
        result["checks"].update({
            "profile_sha256": True,
            "game_sha256": str(profile["executable"]["sha256"]).lower() == EXPECTED_EXE_SHA256,
            "evidence_kind": profile.get("source_evidence_kind") == "ordinary_static_file_bytes_with_REA_source_not_REA_Evidence",
            "root_vtable_rva": vector["root_vtable_rva"] == "0x1cc2048",
            "task_vtable_rva": vector["task_vtable_rva"] == "0x1cc2008",
            "root_parser_rva": vector["root_parser_rva"] == "0x8d7430",
            "task_parser_rva": vector["task_parser_rva"] == "0x8d5070",
            "parser_entry_offset": vector["parser_entry_offset"] == "0x20",
            "root_vector_offsets": (
                vector["pointer_offset"] == "0x128"
                and vector["capacity_offset"] == "0x130"
                and vector["count_offset"] == "0x134"
                and vector["header_bytes"] == 16
            ),
            "task_definition_name_offset": vector["task_object_definition_name_offset"] == "0x10",
            "root_vtable_entries": ROOT_VTABLE_ENTRIES == (0x8D7320, 0xD2F280, 0x955A0, 0x17067E0, 0x8D7430, 0x955A0),
            "task_vtable_entries": TASK_VTABLE_ENTRIES == (0x8D4B20, 0xD2F280, 0x955A0, 0x17067E0, 0x8D5070, 0x955A0),
            "vtable_guards_have_parser_entry": all(
                len(item["expected_entry_rvas"]) == 6
                and item["expected_entry_rvas"][4] == (ROOT_PARSER_RVA if item["name"].startswith("root_") else TASK_PARSER_RVA)
                for item in vtable_guards
            ),
            "code_guards": len(code_guards) == 2 and {item[0] for item in code_guards} == {"root_parser", "task_parser"},
            "limits": (
                MAX_TOTAL_RPM == 524288
                and MAX_SINGLE_RPM == 65536
                and MAX_TASKS_PER_ROOT == 4096
                and MAX_TOTAL_TASKS == 4096
                and MAX_ASCII_LENGTH == 256
                and MAX_STRING_CAPACITY == 4096
            ),
        })
        result["provenance"] = {
            "source_evidence": copy.deepcopy(profile.get("source_evidence", {})),
            "runtime_rule": copy.deepcopy(profile.get("runtime_guards", {})),
            "vtable_file_guard_sha256": {item["name"]: item["sha256"] for item in vtable_guards},
        }
        failed = [key for key, value in result["checks"].items() if value is not True]
        if failed:
            result["unknown_conditions"].append("profile_contract_check_failed:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (ProfileError, KeyError, TypeError, ValueError) as exc:
        result["unknown_conditions"].append(f"profile_contract_read_failed:{exc}")
    return result


def _file_code_guard(path: Path) -> dict[str, Any]:
    """Verify both parser code slices and relocated-vtable source bytes on disk."""
    result: dict[str, Any] = {
        "status": "unknown",
        "path": str(path),
        "checks": {},
        "records": {},
        "unknown_conditions": [],
    }
    try:
        for name, rva, expected in _profile_code_guards():
            actual = _mission_memory._read_pe_rva_bytes(path, rva, len(expected))
            result["records"][name] = {
                "rva": _hex(rva),
                "expected_hex": expected.hex(),
                "actual_hex": actual.hex(),
            }
            result["checks"][name] = actual == expected
        for item in _profile_vtable_guards():
            actual = _mission_memory._read_pe_rva_bytes(path, item["rva"], item["size"])
            digest = hashlib.sha256(actual).hexdigest()
            result["records"][item["name"]] = {
                "rva": _hex(item["rva"]),
                "expected_hex": item["bytes"].hex(),
                "actual_hex": actual.hex(),
                "expected_sha256": item["sha256"],
                "actual_sha256": digest,
                "runtime_relocation": True,
            }
            result["checks"][item["name"]] = actual == item["bytes"] and digest == item["sha256"]
        failed = [name for name, value in result["checks"].items() if value is not True]
        if failed:
            result["status"] = "mismatch"
            result["unknown_conditions"].append("file_task_guard_mismatch:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except Exception as exc:
        result["unknown_conditions"].append(str(exc))
    return result


def _runtime_code_guard(reader: Any, module_base: int) -> dict[str, Any]:
    """Verify parser bytes and every vtable entry at the relocated module base."""
    result: dict[str, Any] = {
        "status": "unknown",
        "module_base": _address(module_base),
        "checks": {},
        "records": {},
        "unknown_conditions": [],
    }
    try:
        for name, rva, expected in _profile_code_guards():
            actual = _read_unaligned(reader, module_base + rva, len(expected), f"task_code_guard.{name}")
            result["records"][name] = {
                "address": _address(module_base + rva, module_base, known_rva=rva),
                "expected_hex": expected.hex(),
                "actual_hex": actual.hex(),
            }
            result["checks"][name] = actual == expected
        for item in _profile_vtable_guards():
            table_address = module_base + item["rva"]
            raw = reader.read(table_address, item["size"], f"task_vtable_guard.{item['name']}")
            actual_entries = tuple(int.from_bytes(raw[index * 8:(index + 1) * 8], "little") for index in range(len(item["expected_entry_rvas"])))
            expected_addresses = tuple(module_base + value for value in item["expected_entry_rvas"])
            entry_checks = [actual == expected for actual, expected in zip(actual_entries, expected_addresses)]
            result["records"][item["name"]] = {
                "address": _address(table_address, module_base, known_rva=item["rva"]),
                "raw_hex": raw.hex(),
                "expected_entry_rvas": [_hex(value) for value in item["expected_entry_rvas"]],
                "expected_entry_addresses": [_address(value, module_base) for value in expected_addresses],
                "actual_entry_addresses": [_address(value, module_base) for value in actual_entries],
                "entry_checks": entry_checks,
                "parser_entry_offset": _hex(PARSER_ENTRY_OFFSET),
                "relocated_runtime_comparison": True,
            }
            result["checks"][item["name"]] = len(raw) == item["size"] and all(entry_checks)
        failed = [name for name, value in result["checks"].items() if value is not True]
        if failed:
            result["status"] = "mismatch"
            result["unknown_conditions"].append("runtime_task_guard_mismatch:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except Exception as exc:
        result["unknown_conditions"].append(str(exc))
    return result


def _string_compare(value: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    return {
        "status": value.get("status"),
        "complete": value.get("complete"),
        "header_hex": value.get("header_hex"),
        "payload_hex": value.get("payload_hex"),
        "length": value.get("length"),
        "capacity": value.get("capacity"),
        "nul_terminator_observed": value.get("nul_terminator_observed"),
        "text": value.get("text"),
        "unknown_reason": value.get("unknown_reason"),
    }


def _root_pointer(root: Mapping[str, Any]) -> int | None:
    definition = root.get("definition")
    if isinstance(definition, Mapping):
        return _parse_int(definition.get("va"))
    return _parse_int(root.get("pointer"))


def _root_name(root: Mapping[str, Any]) -> str | None:
    value = root.get("definition_name")
    if isinstance(value, Mapping) and value.get("status") == "observed" and isinstance(value.get("text"), str):
        return value["text"]
    if isinstance(value, str):
        return value
    return None


def _unknown_root(root: Mapping[str, Any], reason: str, *, pointer: int | None = None) -> dict[str, Any]:
    return {
        "slot_index": root.get("slot_index"),
        "root_index": root.get("root_index"),
        "root_id": _root_name(root),
        "root_pointer": _address(pointer),
        "status": "unknown",
        "complete": False,
        "vector": None,
        "root_vtable": None,
        "tasks": [],
        "task_ids": [],
        "unknown_conditions": [reason],
    }


def _read_task_root(reader: Any, module_base: int, root: Mapping[str, Any], task_budget: list[int]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    pointer = _root_pointer(root)
    base_record: dict[str, Any] = {
        "slot_index": root.get("slot_index"),
        "root_index": root.get("root_index"),
        "root_id": _root_name(root),
        "root_pointer": _address(pointer, module_base),
        "status": "unknown",
        "complete": False,
        "vector": None,
        "root_vtable": None,
        "tasks": [],
        "task_ids": [],
        "unknown_conditions": [],
    }
    if pointer is None or not _valid_pointer(pointer):
        base_record["unknown_conditions"].append("root_object_pointer_invalid")
        return base_record, None
    if base_record["root_id"] is None:
        base_record["unknown_conditions"].append("root_definition_name_not_observed")
        return base_record, None
    try:
        vtable, vtable_raw = reader.qword(pointer, "loaded_tasks.root.vtable")
        parser_address = vtable + PARSER_ENTRY_OFFSET if _valid_pointer(vtable) else None
        parser = None
        parser_raw = None
        if parser_address is not None:
            parser, parser_raw = reader.qword(parser_address, "loaded_tasks.root.vtable_plus_20")
        root_contract = {
            "address": _address(pointer, module_base),
            "raw_hex": vtable_raw.hex(),
            "value": _address(vtable, module_base),
            "observed_rva": _hex(vtable - module_base) if vtable >= module_base else None,
            "expected_rva": _hex(ROOT_VTABLE_RVA),
            "parser_entry": {
                "address": _address(parser_address, module_base),
                "raw_hex": parser_raw.hex() if parser_raw is not None else None,
                "value": _address(parser, module_base),
                "observed_rva": _hex(parser - module_base) if isinstance(parser, int) and parser >= module_base else None,
                "expected_rva": _hex(ROOT_PARSER_RVA),
            },
            "status": "observed" if vtable == module_base + ROOT_VTABLE_RVA and parser == module_base + ROOT_PARSER_RVA else "mismatch",
        }
        base_record["root_vtable"] = root_contract
        if root_contract["status"] != "observed":
            base_record["unknown_conditions"].append("root_object_vtable_or_parser_mismatch")
            return base_record, None

        vector_address = pointer + TASK_POINTER_OFFSET
        vector_raw = reader.read(vector_address, TASK_HEADER_BYTES, "loaded_tasks.root.vector")
        if len(vector_raw) != TASK_HEADER_BYTES:
            raise ProbeError("loaded_tasks.vector_short")
        vector_pointer = int.from_bytes(vector_raw[0:8], "little")
        capacity = int.from_bytes(vector_raw[TASK_CAPACITY_OFFSET - TASK_POINTER_OFFSET:TASK_CAPACITY_OFFSET - TASK_POINTER_OFFSET + 4], "little", signed=True)
        count = int.from_bytes(vector_raw[TASK_COUNT_OFFSET - TASK_POINTER_OFFSET:TASK_COUNT_OFFSET - TASK_POINTER_OFFSET + 4], "little", signed=True)
        vector = {
            "address": _address(vector_address, module_base),
            "raw_hex": vector_raw.hex(),
            "pointer": _address(vector_pointer, module_base),
            "capacity": capacity,
            "count": count,
            "pointer_offset": _hex(TASK_POINTER_OFFSET),
            "capacity_offset": _hex(TASK_CAPACITY_OFFSET),
            "count_offset": _hex(TASK_COUNT_OFFSET),
        }
        base_record["vector"] = vector
        if count < 0 or capacity < 0 or count > capacity or capacity > MAX_TASKS_PER_ROOT or count > MAX_TASKS_PER_ROOT:
            base_record["unknown_conditions"].append("task_vector_count_or_capacity_out_of_bound")
            return base_record, None
        if count == 0:
            if vector_pointer not in (0,) and not _valid_pointer(vector_pointer):
                base_record["unknown_conditions"].append("empty_task_vector_pointer_invalid")
                return base_record, None
            base_record["status"] = "observed"
            base_record["complete"] = True
            comparison = {
                "slot_index": root.get("slot_index"),
                "root_index": root.get("root_index"),
                "root_pointer": pointer,
                "root_vtable": vtable,
                "root_parser": parser,
                "vector": {"pointer": vector_pointer, "capacity": capacity, "count": count, "raw_hex": vector_raw.hex()},
                "tasks": [],
            }
            return base_record, comparison
        if not _valid_pointer(vector_pointer):
            base_record["unknown_conditions"].append("task_vector_pointer_invalid")
            return base_record, None
        if task_budget[0] + count > MAX_TOTAL_TASKS:
            base_record["unknown_conditions"].append("total_loaded_task_limit_exceeded")
            return base_record, None
        pointers_raw = reader.read(vector_pointer, count * 8, "loaded_tasks.root.task_pointers")
        task_budget[0] += count
        comparisons: list[dict[str, Any]] = []
        complete = True
        for task_index in range(count):
            raw = pointers_raw[task_index * 8:(task_index + 1) * 8]
            task_pointer = int.from_bytes(raw, "little")
            task_record: dict[str, Any] = {
                "index": task_index,
                "pointer": _address(task_pointer, module_base),
                "pointer_raw_hex": raw.hex(),
                "status": "unknown",
                "complete": False,
                "vtable": None,
                "task_id": None,
                "unknown_conditions": [],
            }
            if not _valid_pointer(task_pointer):
                task_record["unknown_conditions"].append("task_object_pointer_invalid")
                base_record["tasks"].append(task_record)
                complete = False
                continue
            try:
                task_vtable, task_vtable_raw = reader.qword(task_pointer, f"loaded_tasks.task[{task_index}].vtable")
                parser_address = task_vtable + PARSER_ENTRY_OFFSET if _valid_pointer(task_vtable) else None
                task_parser = None
                task_parser_raw = None
                if parser_address is not None:
                    task_parser, task_parser_raw = reader.qword(parser_address, f"loaded_tasks.task[{task_index}].vtable_plus_20")
                task_record["vtable"] = {
                    "address": _address(task_pointer, module_base),
                    "raw_hex": task_vtable_raw.hex(),
                    "value": _address(task_vtable, module_base),
                    "observed_rva": _hex(task_vtable - module_base) if task_vtable >= module_base else None,
                    "expected_rva": _hex(TASK_VTABLE_RVA),
                    "parser_entry": {
                        "address": _address(parser_address, module_base),
                        "raw_hex": task_parser_raw.hex() if task_parser_raw is not None else None,
                        "value": _address(task_parser, module_base),
                        "observed_rva": _hex(task_parser - module_base) if isinstance(task_parser, int) and task_parser >= module_base else None,
                        "expected_rva": _hex(TASK_PARSER_RVA),
                    },
                }
                if task_vtable != module_base + TASK_VTABLE_RVA or task_parser != module_base + TASK_PARSER_RVA:
                    task_record["unknown_conditions"].append("task_object_vtable_or_parser_mismatch")
                    base_record["tasks"].append(task_record)
                    complete = False
                    continue
                header_address = task_pointer + TASK_DEFINITION_NAME_OFFSET
                header = reader.read(header_address, 32, f"loaded_tasks.task[{task_index}].String32")
                decoded = _mission_memory._decode_string32(reader, header_address, header, f"loaded_tasks.task[{task_index}]")
                task_record["task_id"] = decoded
                task_record["status"] = decoded.get("status", "unknown")
                task_record["complete"] = task_record["status"] == "observed"
                if not task_record["complete"]:
                    task_record["unknown_conditions"].append(decoded.get("unknown_reason", "task_id_unknown"))
                    complete = False
                    base_record["tasks"].append(task_record)
                    continue
                base_record["task_ids"].append(decoded["text"])
                comparison_task = {
                    "index": task_index,
                    "pointer": task_pointer,
                    "pointer_raw_hex": raw.hex(),
                    "vtable": task_vtable,
                    "vtable_raw_hex": task_vtable_raw.hex(),
                    "parser": task_parser,
                    "parser_raw_hex": task_parser_raw.hex() if task_parser_raw is not None else None,
                    "task_id": _string_compare(decoded),
                }
                comparisons.append(comparison_task)
            except Exception as exc:
                task_record["unknown_conditions"].append(f"task_read_failed:{exc}")
                complete = False
            base_record["tasks"].append(task_record)
        if complete and len(comparisons) == count:
            base_record["status"] = "observed"
            base_record["complete"] = True
            comparison = {
                "slot_index": root.get("slot_index"),
                "root_index": root.get("root_index"),
                "root_pointer": pointer,
                "root_vtable": vtable,
                "root_parser": parser,
                "vector": {"pointer": vector_pointer, "capacity": capacity, "count": count, "raw_hex": vector_raw.hex()},
                "tasks": comparisons,
            }
            return base_record, comparison
        base_record["unknown_conditions"].append("one_or_more_loaded_tasks_unknown")
        return base_record, None
    except Exception as exc:
        base_record["unknown_conditions"].append(f"root_task_read_failed:{exc}")
        return base_record, None


def capture_loaded_tasks(reader: Any, module_base: int, missions: Mapping[str, Any]) -> dict[str, Any]:
    """Read all root task vectors described by an already observed mission snapshot.

    ``missions`` is the result of the existing bounded root reader.  It is
    deliberately supplied by the caller so this helper never performs a
    second country scan or invents root pointers from static definitions.
    """
    if isinstance(missions, Mapping) and "missions" in missions and "slots" not in missions:
        nested = missions.get("missions")
        if isinstance(nested, Mapping):
            missions = nested
    result: dict[str, Any] = {
        "status": "unknown",
        "complete": False,
        "supported_scope": "FRA_loaded_root_task_vectors_only",
        "roots": [],
        "total_task_count": 0,
        "unknown_conditions": [],
    }
    if not isinstance(missions, Mapping) or missions.get("status") != "observed":
        result["unknown_conditions"].append("root_missions_not_observed")
        return {"loaded_tasks": result, "_compare": None}
    slots = missions.get("slots")
    if not isinstance(slots, list):
        result["unknown_conditions"].append("root_mission_slots_missing")
        return {"loaded_tasks": result, "_compare": None}
    all_comparisons: list[dict[str, Any]] = []
    task_budget = [0]
    overall_complete = True
    for slot in slots:
        if not isinstance(slot, Mapping):
            result["unknown_conditions"].append("root_slot_not_object")
            overall_complete = False
            continue
        roots = slot.get("roots")
        if not isinstance(roots, list):
            result["unknown_conditions"].append("root_slot_roots_missing")
            overall_complete = False
            continue
        for root in roots:
            if not isinstance(root, Mapping):
                result["unknown_conditions"].append("root_entry_not_object")
                overall_complete = False
                continue
            record, comparison = _read_task_root(reader, module_base, root, task_budget)
            result["roots"].append(record)
            result["total_task_count"] += len(record.get("tasks", []))
            if comparison is None or record.get("status") != "observed":
                overall_complete = False
            else:
                all_comparisons.append(comparison)
    if overall_complete:
        result["status"] = "observed"
        result["complete"] = True
        result["_compare"] = {
            "status": "observed",
            "roots": all_comparisons,
            "total_task_count": result["total_task_count"],
        }
    else:
        result["status"] = "unknown"
        result["unknown_conditions"].append("one_or_more_root_task_vectors_unknown")
        result["_compare"] = None
    public = {key: value for key, value in result.items() if key != "_compare"}
    return {"loaded_tasks": public, "_compare": result.get("_compare")}


# Descriptive aliases keep the integration point easy to discover without
# making a second implementation or a second process-reading path.
capture_tasks = capture_loaded_tasks
snapshot = capture_loaded_tasks
capture = capture_loaded_tasks
_snapshot = capture_loaded_tasks


__all__ = [
    "PROFILE_FILE",
    "EXPECTED_PROFILE_SHA256",
    "PROFILE",
    "ProfileError",
    "ProbeError",
    "_load_profile",
    "_profile_code_guards",
    "_profile_vtable_guards",
    "_static_contract_guard",
    "_file_code_guard",
    "_runtime_code_guard",
    "capture_loaded_tasks",
    "capture_tasks",
    "snapshot",
    "capture",
    "_snapshot",
    "unknown_loaded_tasks",
    "_unknown_loaded_tasks",
]
