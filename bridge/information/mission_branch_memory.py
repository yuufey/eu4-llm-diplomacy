"""有界读取 1.37.4 FRA 任务分支所需的当前输入。

该读取器只返回四个已确定的 FRA 国家旗标和 ``map_setup`` 模式。国家旗标
容器、String32 名称解析和地图模式指针链均绑定到随模块发布的短 profile；
profile 的来源是固定 EXE 上的普通静态证据，运行结果仍属于独立的只读
RPM 观测。读取器不会调用游戏函数、写入目标内存、注入 DLL、推进日期或
保存游戏。

公共入口是 :func:`capture_inputs`。内部会在同一进程句柄上做两次快照，并
比较日期、国家身份/指针、完整旗标 ID 与名称序列以及地图模式。任一读取、
身份、代码守卫、稳定性或句柄关闭检查失败，目标输入保持 unknown。
"""
from __future__ import annotations

import argparse
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from . import mission_memory as _mission_memory


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "mission-branch-memory-1374.json"
PROFILE_MAX_BYTES = 64 * 1024
EXPECTED_PROFILE_SHA256 = "dcb89f5251914727914d19eb4df8641e45020e5f365728b7c0b46c46fdbb701c"


class ProfileError(RuntimeError):
    """随模块发布的分支 profile 缺失、超限或被修改。"""


class ProbeError(RuntimeError):
    """一次有界读取不能安全完成。"""


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
    if not isinstance(profile, dict) or profile.get("profile_id") != "mission-branch-memory-1374":
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
TARGET_FLAGS = tuple(str(value) for value in PROFILE["flags"]["target_names"])
if TARGET_FLAGS != (
    "fra_shed_the_blood_of_the_saxon_man_flag",
    "fra_fufujoni_flag",
    "fra_chose_to_piss_off_pope_flag",
    "fra_papal_lap_dop_flag",
):
    raise ProfileError("profile_target_flags_invalid")

DATABASE_RVA = _profile_int(PROFILE["globals"]["database_rva"], "database_rva")
GAME_RVA = _profile_int(PROFILE["globals"]["game_rva"], "game_rva")
GAME_DATE_OFFSET = _profile_int(PROFILE["globals"]["game_date_offset"], "game_date_offset")
COUNTRY_TABLE_OFFSET = _profile_int(PROFILE["country"]["table_offset"], "country.table_offset")
COUNTRY_HANDLE_OFFSET = _profile_int(PROFILE["country"]["handle_offset"], "country.handle_offset")
FLAGS_OFFSET = _profile_int(PROFILE["country"]["flags_offset"], "country.flags_offset")
FLAGS_BEGIN_OFFSET = _profile_int(PROFILE["country"]["flags_begin_offset"], "country.flags_begin_offset")
FLAGS_END_OFFSET = _profile_int(PROFILE["country"]["flags_end_offset"], "country.flags_end_offset")
FLAGS_VTABLE_RVA = _profile_int(PROFILE["country"]["flags_vtable_rva"], "flags_vtable_rva")
FLAGS_THUNK_RVA = _profile_int(PROFILE["country"]["flags_vtable_plus_8_rva"], "flags_vtable_plus_8_rva")
FLAGS_BODY_RVA = _profile_int(PROFILE["country"]["flags_vtable_plus_10_rva"], "flags_vtable_plus_10_rva")

FLAGS_TABLE_RVA = _profile_int(PROFILE["flags"]["table_pointer_cell_rva"], "flags.table_pointer_cell_rva")
FLAGS_ENTRY_STRIDE = _profile_int(PROFILE["flags"]["entry_stride"], "flags.entry_stride")
STRING_LENGTH_OFFSET = _profile_int(PROFILE["flags"]["length_offset"], "flags.length_offset")
STRING_CAPACITY_OFFSET = _profile_int(PROFILE["flags"]["capacity_offset"], "flags.capacity_offset")
INLINE_CAPACITY_LIMIT = _profile_int(PROFILE["flags"]["inline_capacity_limit"], "flags.inline_capacity_limit")
MAX_ASCII_LENGTH = _profile_int(PROFILE["flags"]["max_ascii_length"], "flags.max_ascii_length")
MAX_STRING_CAPACITY = _profile_int(PROFILE["flags"]["max_string_capacity"], "flags.max_string_capacity")

MAP_GLOBAL_RVA = _profile_int(PROFILE["map_setup"]["global_pointer_cell_rva"], "map_setup.global_pointer_cell_rva")
MAP_CONTEXT_OFFSET = _profile_int(PROFILE["map_setup"]["global_to_context_pointer_offset"], "map_setup.context_offset")
MAP_MODE_OFFSET = _profile_int(PROFILE["map_setup"]["context_to_mode_dword_offset"], "map_setup.mode_offset")
MAP_EVALUATOR_RVA = _profile_int(PROFILE["map_setup"]["evaluator_rva"], "map_setup.evaluator_rva")
MAP_MODES = {int(key, 0): value for key, value in PROFILE["map_setup"]["mode_values"].items()}

DOMINATION_GLOBAL_BOOL_RVA = _profile_int(
    PROFILE["domination"]["predicate_branch"]["global_bool_rva"],
    "domination.global_bool_rva",
)
DOMINATION_OVERRIDE_BYTE_RVA = _profile_int(
    PROFILE["domination"]["predicate_branch"]["override_byte_rva"],
    "domination.override_byte_rva",
)
DOMINATION_UNKNOWN_REASON = "THREAD_LOCAL_DLC_OVERRIDE_UNRESOLVED"

MAX_TOTAL_RPM = _profile_int(PROFILE["limits"]["max_total_rpm"], "limits.max_total_rpm")
MAX_SINGLE_RPM = _profile_int(PROFILE["limits"]["max_single_rpm"], "limits.max_single_rpm")
INITIAL_COUNTRY_TABLE_ENTRIES = _profile_int(
    PROFILE["limits"]["initial_country_table_entries"], "limits.initial_country_table_entries"
)
MAX_COUNTRY_TABLE_ENTRIES = _profile_int(
    PROFILE["limits"]["max_country_table_entries"], "limits.max_country_table_entries"
)
MAX_FLAG_IDS = _profile_int(PROFILE["limits"]["max_flag_ids"], "limits.max_flag_ids")
MAX_TABLE_INDEX = _profile_int(PROFILE["limits"]["max_table_index"], "limits.max_table_index")
PROCESS_ACCESS = 0x0400 | 0x0010  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
MAX_USER_ADDRESS = 0x0000800000000000


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


def _valid_pointer(value: int) -> bool:
    return isinstance(value, int) and 0x10000 <= value < MAX_USER_ADDRESS and value % 8 == 0


def _address(value: int | None, module_base: int | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"va": _hex(value), "rva": None, "rva_identity": "not_applicable"}
    if not isinstance(value, int):
        return result
    if module_base is not None and module_base <= value < module_base + 0x40000000:
        result["rva"] = _hex(value - module_base)
        result["rva_identity"] = "module_relative_candidate"
    else:
        result["rva_identity"] = "runtime_va_or_heap"
    return result


def _tag_and_slot(handle: int) -> tuple[str | None, int | None]:
    raw = (handle & 0xFFFFFF).to_bytes(3, "little")
    if not all(0x41 <= byte <= 0x5A or 0x30 <= byte <= 0x39 for byte in raw):
        return None, (handle >> 32) & 0xFFFF
    return raw.decode("ascii"), (handle >> 32) & 0xFFFF


def _filetime_value(value: W.FILETIME) -> int:
    return (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)


def _filetime_iso(value: int) -> str | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(value / 10_000_000 - 11644473600, timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_installation(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProbeError(f"installation_read_failed:{exc}") from exc
    if not isinstance(document, dict):
        raise ProbeError("installation_not_object")
    pid = _parse_int(document.get("pid"))
    creation = _parse_int(document.get("creation_filetime"))
    if pid is None or pid <= 0 or creation is None or creation <= 0:
        raise ProbeError("installation_pid_or_creation_invalid")
    if str(document.get("game_sha256", "")).lower() != EXPECTED_EXE_SHA256:
        raise ProbeError("installation_game_sha256_mismatch")
    return document


def _unknown_flags(reason: str) -> dict[str, dict[str, Any]]:
    return {
        name: {"known": False, "value": None, "status": "unknown", "unknown_reason": reason}
        for name in TARGET_FLAGS
    }


def _unknown_mode(reason: str) -> dict[str, Any]:
    return {"known": False, "value": None, "name": None, "status": "unknown", "unknown_reason": reason}


def _unknown_domination(reason: str) -> dict[str, Any]:
    return {
        "known": False,
        "value": None,
        "status": "unknown",
        "unknown_reason": reason,
    }


def _base_report(installation: Path, country: str) -> dict[str, Any]:
    return {
        "probe": "information-mission-branch-inputs-runtime",
        "probe_version": 1,
        "probe_script": str(Path(__file__).resolve()),
        "probe_script_sha256": None,
        "read_only": True,
        "evidence_kind": "pure_runtime_observation_not_static_evidence",
        "request": {"installation": str(installation), "country": country},
        "profile": {
            "path": str(PROFILE_FILE),
            "sha256": EXPECTED_PROFILE_SHA256,
            "max_bytes": PROFILE_MAX_BYTES,
            "profile_id": PROFILE.get("profile_id"),
        },
        "target_build": {
            "version": EXPECTED_VERSION,
            "expected_exe_sha256": EXPECTED_EXE_SHA256,
            "database_rva": _hex(DATABASE_RVA),
            "game_rva": _hex(GAME_RVA),
            "map_global_pointer_cell_rva": _hex(MAP_GLOBAL_RVA),
            "flags_vtable_rva": _hex(FLAGS_VTABLE_RVA),
            "flags_body_rva": _hex(FLAGS_BODY_RVA),
            "domination_global_bool_rva": _hex(DOMINATION_GLOBAL_BOOL_RVA),
            "domination_override_byte_rva": _hex(DOMINATION_OVERRIDE_BYTE_RVA),
        },
        "static_contract_reference": {
            "profile_sha256": EXPECTED_PROFILE_SHA256,
            "source_evidence": dict(PROFILE.get("source_evidence", {})),
            "static_results_are_not_runtime_observation": True,
            "flag_table_length_known": False,
            "flag_table_length_provenance": PROFILE["flags"]["table_length_provenance"],
        },
        "identity": {
            "installation_path": str(installation),
            "installation_pid": None,
            "installation_creation_filetime": None,
            "installation_session_id": None,
            "process_path": None,
            "process_path_sha256": None,
            "process_path_sha256_matches_expected": None,
            "process_creation_filetime": None,
            "process_creation_utc": None,
            "process_creation_matches_installation": None,
            "module_path": None,
            "module_path_matches_process": None,
            "binding_verified": False,
        },
        "module_base": None,
        "access": {
            "open_process_mask": "QUERY_INFORMATION|VM_READ",
            "open_process_mask_hex": hex(PROCESS_ACCESS),
            "rpm_total_limit": MAX_TOTAL_RPM,
            "rpm_single_read_limit": MAX_SINGLE_RPM,
            "rpm_bytes_requested": 0,
            "rpm_calls": 0,
            "native_game_calls": False,
            "target_memory_writes": False,
            "dll_injection": False,
            "date_advance": False,
            "save_or_reload": False,
        },
        "before": None,
        "after": None,
        "inputs": {
            "country_flags": _unknown_flags("not_read"),
            "map_setup": _unknown_mode("not_read"),
            "has_domination": _unknown_domination("not_read"),
        },
        "doublepass": {"performed": False, "consistent": None, "mismatches": []},
        "cleanup": {"handle_close": {"status": "unknown", "success": None, "closed": False}},
        "status": "starting",
        "errors": [],
        "completed": False,
    }


def _profile_code_guards(profile: Mapping[str, Any] | None = None) -> list[tuple[str, int, bytes]]:
    profile = PROFILE if profile is None else profile
    guards: list[tuple[str, int, bytes]] = []
    for item in profile["code_guards"]:
        if not isinstance(item, Mapping):
            raise ProfileError("profile_code_guard_not_object")
        name = str(item["name"])
        rva = _profile_int(item["rva"], f"code_guard.{name}.rva")
        raw_hex = item.get("bytes")
        if not isinstance(raw_hex, str) or len(raw_hex) == 0 or len(raw_hex) % 2:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}")
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}") from exc
        if len(raw) > MAX_SINGLE_RPM:
            raise ProfileError(f"profile_code_guard_too_large:{name}")
        guards.append((name, rva, raw))
    return guards


def _static_contract_guard() -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "evidence_kind": "ordinary_file_analysis_not_REA_Evidence",
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "checks": {},
        "unknown_conditions": [],
    }
    try:
        profile = _load_profile()
        flags = profile["flags"]
        country = profile["country"]
        map_setup = profile["map_setup"]
        domination = profile["domination"]
        domination_source = profile["source_evidence"]["domination_short_circuit_contract"]
        guard_names = {name for name, _rva, _raw in _profile_code_guards(profile)}
        result["checks"].update(
            {
                "profile_sha256": True,
                "game_sha256": profile["executable"]["sha256"].lower() == EXPECTED_EXE_SHA256,
                "evidence_kind": profile.get("source_evidence_kind") == "ordinary_static_file_analysis_not_REA_Evidence",
                "target_flags": tuple(flags["target_names"]) == TARGET_FLAGS,
                "embedded_flags_object": country["flags_storage"] == "embedded_object",
                "flags_offsets": (
                    country["flags_offset"] == "0x270"
                    and country["flags_begin_offset"] == "0x10"
                    and country["flags_end_offset"] == "0x18"
                ),
                "flags_vtable_chain": (
                    country["flags_vtable_rva"] == "0x1c57520"
                    and country["flags_vtable_plus_8_rva"] == "0xd2f280"
                    and country["flags_vtable_plus_10_rva"] == "0x737ce0"
                ),
                "flags_table_length_unresolved": flags["table_length_known"] is False,
                "map_input_chain": (
                    map_setup["global_pointer_cell_rva"] == "0x233fe58"
                    and map_setup["global_to_context_pointer_offset"] == "0x2150"
                    and map_setup["context_to_mode_dword_offset"] == "0x34"
                ),
                "map_evaluator_rva": map_setup["evaluator_rva"] == "0xd15590",
                "map_modes": map_setup["mode_values"] == {
                    "0": "normal",
                    "1": "historical",
                    "2": "random",
                    "3": "custom",
                },
                "domination_source_report": (
                    domination_source["schema"] == "information.domination.short-circuit-contract.v1"
                    and isinstance(domination_source["sha256"], str)
                    and len(domination_source["sha256"]) == 64
                ),
                "domination_short_circuit": (
                    domination["predicate_branch"]["global_bool_rva"] == "0x233ff6c"
                    and domination["predicate_branch"]["override_byte_rva"] == "0x233feb6"
                    and domination["predicate_branch"]["helper_rva"] == "0xcfc70"
                    and domination["domination_name_mapping"]["name"] == "Domination"
                    and domination["domination_name_mapping"]["object_mask"] == "0x80000"
                    and domination["safe_boolean_derivation"]
                    == "raw Domination byte != 0 and override byte == 0 implies has_dlc(Domination) true without reading TLS"
                    and domination["unknown_condition"]
                    == "Otherwise the helper consults the evaluating game thread TLS. Do not infer false or read/call another thread TLS."
                ),
                "domination_code_guards": (
                    tuple(domination["code_guard_names"])
                    == ("domination_helper", "domination_predicate", "domination_short_circuit_branch")
                    and {
                        "domination_helper",
                        "domination_predicate",
                        "domination_short_circuit_branch",
                    }.issubset(guard_names)
                ),
                "code_guards": bool(_profile_code_guards(profile)),
            }
        )
        result["provenance"] = {
            "source_evidence": dict(profile.get("source_evidence", {})),
            "flag_table_length_known": False,
            "flag_table_length_provenance": flags["table_length_provenance"],
        }
        failed = [key for key, value in result["checks"].items() if value is not True]
        if failed:
            result["unknown_conditions"].append("profile_contract_check_failed:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (ProfileError, KeyError, TypeError, ValueError) as exc:
        result["unknown_conditions"].append(f"profile_contract_read_failed:{exc}")
    return result


def _read_unaligned(reader: Any, address: int, size: int, label: str) -> bytes:
    """Use the bounded reader's unaligned read path for DWORD mode fields."""
    method = getattr(reader, "read_code", None)
    if callable(method):
        return method(address, size, label)
    method = getattr(reader, "_read", None)
    if callable(method):
        return method(address, size, label, aligned=False)
    return reader.read(address, size, label)


def _file_code_guard(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "path": str(path), "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        for name, rva, expected in _profile_code_guards():
            actual = _mission_memory._read_pe_rva_bytes(path, rva, len(expected))
            result["records"][name] = {
                "rva": hex(rva),
                "expected_hex": expected.hex(),
                "actual_hex": actual.hex(),
            }
            result["checks"][name] = actual == expected
        failed = [name for name, value in result["checks"].items() if value is not True]
        if failed:
            result["status"] = "mismatch"
            result["unknown_conditions"].append("file_code_guard_mismatch:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (OSError, ProbeError, ProfileError, KeyError, TypeError, ValueError) as exc:
        result["unknown_conditions"].append(str(exc))
    return result


def _runtime_code_guard(reader: Any, module_base: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "module_base": _address(module_base),
        "checks": {},
        "records": {},
        "unknown_conditions": [],
    }
    try:
        for name, rva, expected in _profile_code_guards():
            address = module_base + rva
            actual = _read_unaligned(reader, address, len(expected), f"code_guard.{name}")
            result["records"][name] = {
                "address": _address(address, module_base),
                "expected_hex": expected.hex(),
                "actual_hex": actual.hex(),
            }
            result["checks"][name] = actual == expected
        failed = [name for name, value in result["checks"].items() if value is not True]
        if failed:
            result["status"] = "mismatch"
            result["unknown_conditions"].append("runtime_code_guard_mismatch:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (ProbeError, ProfileError, KeyError, TypeError, ValueError, OSError) as exc:
        result["unknown_conditions"].append(str(exc))
    return result


def _country_identity(reader: Any, module_base: int, requested_country: str) -> dict[str, Any]:
    """Find exactly one tag/slot match in the bounded first table window."""
    database_field = module_base + DATABASE_RVA
    database, database_raw = reader.qword(database_field, "global.database_pointer")
    result: dict[str, Any] = {
        "status": "unknown",
        "requested_country": requested_country,
        "database_pointer": _address(database, module_base),
        "database_raw_hex": database_raw.hex(),
        "table_pointer": None,
        "scanned_entries": 0,
        "initial_scan_limit": INITIAL_COUNTRY_TABLE_ENTRIES,
        "tail_not_claimed": True,
        "country_pointer": None,
        "country_handle": None,
    }
    if not _valid_pointer(database):
        result["unknown_reason"] = "database_pointer_invalid"
        return result
    table_field = database + COUNTRY_TABLE_OFFSET
    table, table_raw = reader.qword(table_field, "database.country_table")
    result["table_pointer"] = {"address": _address(table_field, module_base), "raw_hex": table_raw.hex(), "value": _address(table, module_base)}
    if not _valid_pointer(table):
        result["unknown_reason"] = "country_table_pointer_invalid"
        return result
    pointer_bytes = reader.read(table, INITIAL_COUNTRY_TABLE_ENTRIES * 8, "country_table.first_256_pointers")
    matches: list[dict[str, Any]] = []
    for index in range(INITIAL_COUNTRY_TABLE_ENTRIES):
        pointer = int.from_bytes(pointer_bytes[index * 8:(index + 1) * 8], "little")
        if pointer == 0 or not _valid_pointer(pointer):
            continue
        handle, handle_raw = reader.qword(pointer + COUNTRY_HANDLE_OFFSET, f"country[{index}].handle")
        tag, slot = _tag_and_slot(handle)
        if tag == requested_country and slot == index:
            matches.append(
                {
                    "table_index": index,
                    "country_pointer": _address(pointer, module_base),
                    "country_handle": {
                        "address": _address(pointer + COUNTRY_HANDLE_OFFSET, module_base),
                        "field_offset": hex(COUNTRY_HANDLE_OFFSET),
                        "raw_hex": handle_raw.hex(),
                        "value": _hex(handle),
                        "tag": tag,
                        "slot": slot,
                    },
                }
            )
    result["scanned_entries"] = INITIAL_COUNTRY_TABLE_ENTRIES
    if len(matches) == 1:
        result.update({"status": "observed", **matches[0]})
    elif len(matches) > 1:
        result["unknown_reason"] = "duplicate_tag_and_slot_matches"
    else:
        result["unknown_reason"] = "country_not_found_within_fixed_256_entry_bound"
    return result


def _flag_result_unknown(reason: str, *, object_address: int | None = None, module_base: int | None = None) -> dict[str, Any]:
    return {
        "status": "unknown",
        "object": _address(object_address, module_base),
        "target_flags": _unknown_flags(reason),
        "provenance": {
            "table_length_known": False,
            "table_length_provenance": PROFILE["flags"]["table_length_provenance"],
        },
        "unknown_reason": reason,
    }


def _sequence_hash(values: list[Any]) -> str:
    raw = json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _read_flags(reader: Any, module_base: int, country_pointer: int) -> dict[str, Any]:
    object_address = country_pointer + FLAGS_OFFSET
    result_base = {"object": _address(object_address, module_base), "storage": "embedded_object"}
    try:
        if not _valid_pointer(object_address):
            return _flag_result_unknown("flags_object_address_invalid", object_address=object_address, module_base=module_base)
        vtable, vtable_raw = reader.qword(object_address, "country.flags.vtable")
        result_base["vtable"] = {"raw_hex": vtable_raw.hex(), "value": _address(vtable, module_base), "observed_rva": _hex(vtable - module_base) if vtable >= module_base else None}
        if vtable != module_base + FLAGS_VTABLE_RVA:
            return {**result_base, **_flag_result_unknown("flags_vtable_rva_mismatch", object_address=object_address, module_base=module_base)}
        thunk, thunk_raw = reader.qword(vtable + 8, "country.flags.vtable_plus_8")
        body, body_raw = reader.qword(vtable + 0x10, "country.flags.vtable_plus_10")
        result_base["vtable_plus_8"] = {"raw_hex": thunk_raw.hex(), "value": _address(thunk, module_base), "observed_rva": _hex(thunk - module_base) if thunk >= module_base else None}
        result_base["vtable_plus_10"] = {"raw_hex": body_raw.hex(), "value": _address(body, module_base), "observed_rva": _hex(body - module_base) if body >= module_base else None}
        if thunk != module_base + FLAGS_THUNK_RVA or body != module_base + FLAGS_BODY_RVA:
            return {**result_base, **_flag_result_unknown("flags_vtable_chain_mismatch", object_address=object_address, module_base=module_base)}

        begin, begin_raw = reader.qword(object_address + FLAGS_BEGIN_OFFSET, "country.flags.begin")
        end, end_raw = reader.qword(object_address + FLAGS_END_OFFSET, "country.flags.end")
        result_base["begin"] = {"address": _address(object_address + FLAGS_BEGIN_OFFSET, module_base), "raw_hex": begin_raw.hex(), "value": _address(begin, module_base)}
        result_base["end"] = {"address": _address(object_address + FLAGS_END_OFFSET, module_base), "raw_hex": end_raw.hex(), "value": _address(end, module_base)}
        if end < begin:
            return {**result_base, **_flag_result_unknown("flags_end_before_begin", object_address=object_address, module_base=module_base)}
        span = end - begin
        if span % 2:
            return {**result_base, **_flag_result_unknown("flags_byte_span_odd", object_address=object_address, module_base=module_base)}
        count = span // 2
        if count > MAX_FLAG_IDS:
            return {**result_base, **_flag_result_unknown("flags_id_count_out_of_bound", object_address=object_address, module_base=module_base)}

        ids: list[int] = []
        names: list[str] = []
        if count:
            if not _valid_pointer(begin):
                return {**result_base, **_flag_result_unknown("flags_begin_pointer_invalid", object_address=object_address, module_base=module_base)}
            raw_ids = reader.read(begin, span, "country.flags.ids")
            ids = [int.from_bytes(raw_ids[index:index + 2], "little", signed=True) for index in range(0, span, 2)]
            if any(value < 0 for value in ids):
                return {**result_base, **_flag_result_unknown("flags_negative_id", object_address=object_address, module_base=module_base)}

            table, table_raw = reader.qword(module_base + FLAGS_TABLE_RVA, "flags.name_table_pointer")
            result_base["name_table"] = {"address": _address(module_base + FLAGS_TABLE_RVA, module_base), "raw_hex": table_raw.hex(), "value": _address(table, module_base)}
            if not _valid_pointer(table):
                return {**result_base, **_flag_result_unknown("flags_name_table_pointer_invalid", object_address=object_address, module_base=module_base)}
            for index, flag_id in enumerate(ids):
                if flag_id > MAX_TABLE_INDEX:
                    return {**result_base, **_flag_result_unknown("flags_id_exceeds_bounded_table_index", object_address=object_address, module_base=module_base)}
                entry = table + flag_id * FLAGS_ENTRY_STRIDE
                if not _valid_pointer(entry):
                    return {**result_base, **_flag_result_unknown("flags_name_entry_address_invalid", object_address=object_address, module_base=module_base)}
                header = reader.read(entry, 32, f"flags.name[{index}].String32")
                decoded = _mission_memory._decode_string32(reader, entry, header, f"flags.name[{index}]")
                if decoded.get("status") != "observed" or not isinstance(decoded.get("text"), str):
                    return {**result_base, **_flag_result_unknown("flags_name_incomplete", object_address=object_address, module_base=module_base)}
                names.append(decoded["text"])

        target_flags = {
            name: {"known": True, "value": name in names, "status": "observed"}
            for name in TARGET_FLAGS
        }
        result = {
            **result_base,
            "status": "observed",
            "target_flags": target_flags,
            "provenance": {
                "id_count": count,
                "resolved_name_count": len(names),
                "empty": count == 0,
                "id_sequence_sha256": _sequence_hash(ids),
                "name_sequence_sha256": _sequence_hash(names),
                "table_length_known": False,
                "table_length_provenance": PROFILE["flags"]["table_length_provenance"],
            },
            "unknown_reason": None,
        }
        result["_compare"] = {
            "object": object_address,
            "vtable": vtable,
            "begin": begin,
            "end": end,
            "ids": ids,
            "names": names,
        }
        return result
    except Exception as exc:
        return {**result_base, **_flag_result_unknown(f"flags_read_failed:{exc}", object_address=object_address, module_base=module_base)}


def _read_map_setup(reader: Any, module_base: int) -> dict[str, Any]:
    try:
        global_address = module_base + MAP_GLOBAL_RVA
        root, root_raw = reader.qword(global_address, "map_setup.global_pointer")
        result: dict[str, Any] = {
            "global_pointer": {"address": _address(global_address, module_base), "raw_hex": root_raw.hex(), "value": _address(root, module_base)},
        }
        if not _valid_pointer(root):
            return {**result, **_unknown_mode("map_setup_global_pointer_invalid")}
        context_address = root + MAP_CONTEXT_OFFSET
        context, context_raw = reader.qword(context_address, "map_setup.context_pointer")
        result["context_pointer"] = {"address": _address(context_address, module_base), "raw_hex": context_raw.hex(), "value": _address(context, module_base)}
        if not _valid_pointer(context):
            return {**result, **_unknown_mode("map_setup_context_pointer_invalid")}
        mode_address = context + MAP_MODE_OFFSET
        mode_raw = _read_unaligned(reader, mode_address, 4, "map_setup.mode_dword")
        mode = int.from_bytes(mode_raw, "little", signed=False)
        result["mode_field"] = {"address": _address(mode_address, module_base), "field_offset": hex(MAP_MODE_OFFSET), "raw_hex": mode_raw.hex(), "raw": mode}
        if mode not in MAP_MODES:
            return {**result, **_unknown_mode("map_setup_mode_out_of_contract")}
        result.update({"status": "observed", "known": True, "value": mode, "name": MAP_MODES[mode], "unknown_reason": None})
        result["_compare"] = {"global_pointer": root, "context_pointer": context, "mode": mode}
        return result
    except Exception as exc:
        return {"status": "unknown", **_unknown_mode(f"map_setup_read_failed:{exc}")}


def _read_domination(reader: Any, module_base: int) -> dict[str, Any]:
    """Apply only the proven byte-level Domination short circuit.

    A nonzero Domination byte together with a zero override byte proves true.
    Every other successfully read combination remains unresolved because the
    helper then consults the evaluating game thread's TLS.
    """
    domination_address = module_base + DOMINATION_GLOBAL_BOOL_RVA
    override_address = module_base + DOMINATION_OVERRIDE_BYTE_RVA
    domination_value: int | None = None
    override_value: int | None = None
    result: dict[str, Any] = {
        "known": False,
        "value": None,
        "status": "unknown",
        "unknown_reason": DOMINATION_UNKNOWN_REASON,
        "raw_domination_byte": None,
        "raw_override_byte": None,
        "source": {
            "contract_schema": "information.domination.short-circuit-contract.v1",
            "global_bool": {
                "address": _address(domination_address, module_base),
                "rva": _hex(DOMINATION_GLOBAL_BOOL_RVA),
                "raw_hex": None,
            },
            "override_byte": {
                "address": _address(override_address, module_base),
                "rva": _hex(DOMINATION_OVERRIDE_BYTE_RVA),
                "raw_hex": None,
            },
            "tls_read": False,
            "game_function_called": False,
        },
    }
    try:
        domination_raw = _read_unaligned(reader, domination_address, 1, "domination.global_bool")
        override_raw = _read_unaligned(reader, override_address, 1, "domination.override_byte")
        if len(domination_raw) != 1 or len(override_raw) != 1:
            raise ProbeError("domination_byte_read_size_invalid")
        domination_value = domination_raw[0]
        override_value = override_raw[0]
        result["raw_domination_byte"] = domination_value
        result["raw_override_byte"] = override_value
        result["source"]["global_bool"]["raw_hex"] = domination_raw.hex()
        result["source"]["global_bool"]["value"] = domination_value
        result["source"]["override_byte"]["raw_hex"] = override_raw.hex()
        result["source"]["override_byte"]["value"] = override_value
        if domination_value != 0 and override_value == 0:
            result.update({"known": True, "value": True, "status": "observed", "unknown_reason": None})
        result["_compare"] = {"global_bool": domination_value, "override_byte": override_value}
        return result
    except Exception as exc:
        result["unknown_reason"] = f"domination_read_failed:{exc}"
        result["_compare"] = {"global_bool": domination_value, "override_byte": override_value}
        return result


def _snapshot(reader: Any, module_base: int, country: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "unknown_conditions": [],
        "game_pointer": None,
        "database_pointer": None,
        "game_date": None,
        "country_scan": None,
        "country_flags": {"status": "unknown", "target_flags": _unknown_flags("not_read")},
        "map_setup": _unknown_mode("not_read"),
        "has_domination": _unknown_domination("not_read"),
        "unresolved_conditions": [],
    }
    try:
        game_field = module_base + GAME_RVA
        game, game_raw = reader.qword(game_field, "global.game_pointer")
        database_field = module_base + DATABASE_RVA
        database, database_raw = reader.qword(database_field, "global.database_pointer")
        result["game_pointer"] = {"address": _address(game_field, module_base), "raw_hex": game_raw.hex(), "value": _address(game, module_base)}
        result["database_pointer"] = {"address": _address(database_field, module_base), "raw_hex": database_raw.hex(), "value": _address(database, module_base)}
        if not _valid_pointer(game) or not _valid_pointer(database):
            result["unknown_conditions"].append("game_or_database_pointer_invalid")
            return result
        date_address = game + GAME_DATE_OFFSET
        date_raw = reader.read(date_address, 4, "game.raw_date")
        date_value = int.from_bytes(date_raw, "little", signed=True)
        result["game_date"] = {"address": _address(date_address, module_base), "field_offset": hex(GAME_DATE_OFFSET), "raw_hex": date_raw.hex(), "raw": date_value}
        country_scan = _country_identity(reader, module_base, country)
        result["country_scan"] = country_scan
        if country_scan.get("status") != "observed":
            result["unknown_conditions"].append(country_scan.get("unknown_reason", "country_identity_unknown"))
            return result
        country_pointer = int(country_scan["country_pointer"]["va"], 0)
        flags = _read_flags(reader, module_base, country_pointer)
        mode = _read_map_setup(reader, module_base)
        domination = _read_domination(reader, module_base)
        result["country_flags"] = flags
        result["map_setup"] = mode
        result["has_domination"] = domination
        if flags.get("status") != "observed":
            result["unknown_conditions"].append(flags.get("unknown_reason", "country_flags_unknown"))
        if mode.get("status") != "observed":
            result["unknown_conditions"].append(mode.get("unknown_reason", "map_setup_unknown"))
        if domination.get("status") != "observed":
            result["unresolved_conditions"].append(domination.get("unknown_reason", DOMINATION_UNKNOWN_REASON))
        if not result["unknown_conditions"]:
            result["status"] = "observed"
        result["_compare"] = {
            "game_pointer": game,
            "database_pointer": database,
            "game_date": date_value,
            "country_pointer": country_pointer,
            "country_handle": country_scan.get("country_handle"),
            "flags": flags.get("_compare"),
            "map_setup": mode.get("_compare"),
            "has_domination": domination.get("_compare"),
        }
        return result
    except Exception as exc:
        result["unknown_conditions"].append(f"snapshot_read_failed:{exc}")
        return result


def _without_private(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _without_private(item) for key, item in value.items() if key != "_compare"}
    if isinstance(value, list):
        return [_without_private(item) for item in value]
    return value


def _comparison_view(snapshot: Mapping[str, Any]) -> Any:
    return snapshot.get("_compare")


def _diff_paths(left: Any, right: Any, path: str = "$") -> list[str]:
    if type(left) is not type(right):
        return [path]
    if isinstance(left, dict):
        paths: list[str] = []
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                paths.append(f"{path}.{key}")
            else:
                paths.extend(_diff_paths(left[key], right[key], f"{path}.{key}"))
        return paths
    if isinstance(left, list):
        paths: list[str] = []
        if len(left) != len(right):
            paths.append(f"{path}.length")
        for index, (a, b) in enumerate(zip(left, right)):
            paths.extend(_diff_paths(a, b, f"{path}[{index}]"))
        return paths
    return [] if left == right else [path]


def _configure_kernel() -> Any:
    return _mission_memory._configure_kernel()


def _apply_cleanup(report: dict[str, Any], kernel: Any, handle: Any) -> None:
    _mission_memory._apply_cleanup(report, kernel, handle)


def _invalidate_inputs_after_cleanup_failure(report: dict[str, Any]) -> None:
    """撤销未能安全关闭句柄时的公开输入结论。

    ``before``/``after`` 保留原始观测，供审计和定位清理问题；顶层
    ``inputs`` 是供调用者消费的交付结果，句柄关闭失败时必须全部未知。
    """
    report["inputs"] = {
        "country_flags": _unknown_flags("handle_close_failed"),
        "map_setup": _unknown_mode("handle_close_failed"),
        "has_domination": _unknown_domination("handle_close_failed"),
    }


def _capture_identity(report: dict[str, Any], document: Mapping[str, Any], kernel: Any, handle: Any) -> int:
    pid = _parse_int(document.get("pid"))
    expected_creation = _parse_int(document.get("creation_filetime"))
    if pid is None or expected_creation is None:
        raise ProbeError("installation_pid_or_creation_invalid")
    report["identity"].update(
        {
            "installation_pid": pid,
            "installation_creation_filetime": expected_creation,
            "installation_session_id": document.get("session_id"),
        }
    )
    process_path_buffer = C.create_unicode_buffer(32768)
    process_path_length = W.DWORD(len(process_path_buffer))
    if not kernel.QueryFullProcessImageNameW(handle, 0, process_path_buffer, C.byref(process_path_length)):
        raise C.WinError(C.get_last_error())
    process_path = Path(process_path_buffer.value).resolve()
    process_hash = _sha256_file(process_path)
    report["identity"].update(
        {
            "process_path": str(process_path),
            "process_path_sha256": process_hash,
            "process_path_sha256_matches_expected": process_hash.lower() == EXPECTED_EXE_SHA256,
        }
    )
    report["file_code_guard"] = _file_code_guard(process_path)

    creation = W.FILETIME()
    exit_time = W.FILETIME()
    kernel_time = W.FILETIME()
    user_time = W.FILETIME()
    if not kernel.GetProcessTimes(handle, C.byref(creation), C.byref(exit_time), C.byref(kernel_time), C.byref(user_time)):
        raise C.WinError(C.get_last_error())
    process_creation = _filetime_value(creation)
    report["identity"].update(
        {
            "process_creation_filetime": process_creation,
            "process_creation_utc": _filetime_iso(process_creation),
            "process_creation_matches_installation": process_creation == expected_creation,
        }
    )

    modules = (W.HMODULE * 1024)()
    needed = W.DWORD()
    if not kernel.K32EnumProcessModulesEx(handle, modules, C.sizeof(modules), C.byref(needed), 3):
        raise C.WinError(C.get_last_error())
    if not needed.value or needed.value > C.sizeof(modules) or needed.value % C.sizeof(W.HMODULE):
        raise ProbeError("module_list_invalid")
    module_handle = modules[0]
    module_base = int(getattr(module_handle, "value", module_handle) or 0)
    if module_base < 0x10000:
        raise ProbeError("module_base_invalid")
    module_name_buffer = C.create_unicode_buffer(32768)
    module_name_length = kernel._probe_get_module_name(handle, module_handle, module_name_buffer, len(module_name_buffer))
    module_path = Path(module_name_buffer.value).resolve() if module_name_length else None
    report["module_base"] = _address(module_base)
    report["identity"]["module_path"] = str(module_path) if module_path else None
    report["identity"]["module_path_matches_process"] = module_path == process_path if module_path else False
    identity_ok = (
        report["identity"]["process_path_sha256_matches_expected"] is True
        and report["identity"]["process_creation_matches_installation"] is True
        and report["identity"]["module_path_matches_process"] is True
        and str(document.get("game_sha256", "")).lower() == EXPECTED_EXE_SHA256
    )
    report["identity"]["binding_verified"] = identity_ok
    if not identity_ok:
        raise ProbeError("PID creation/path/SHA/module binding mismatch")
    if report["file_code_guard"].get("status") != "observed":
        raise ProbeError("bound executable code bytes did not match profile")
    return module_base


def capture_inputs(installation: Path, country: str) -> dict[str, Any]:
    """读取同一进程两遍的 FRA 旗标和地图模式输入。"""
    installation = Path(installation)
    report = _base_report(installation, country)
    try:
        report["probe_script_sha256"] = _sha256_file(Path(__file__).resolve())
    except OSError as exc:
        report["errors"].append({"stage": "probe_identity", "status": "unknown", "error": str(exc)})
    report["static_contract_guard"] = _static_contract_guard()
    if report["static_contract_guard"].get("status") != "observed":
        report["status"] = "static_contract_mismatch"
        report["errors"].append({"stage": "static_contract", "status": "unknown", "error": "分支 profile/code guard 不匹配"})
        _apply_cleanup(report, None, None)
        report["completed"] = False
        return report
    if country != EXPECTED_COUNTRY:
        report["status"] = "unsupported_country"
        report["errors"].append({"stage": "request", "status": "unknown", "error": "Only FRA is permitted"})
        _apply_cleanup(report, None, None)
        report["completed"] = True
        return report

    handle = None
    kernel = None
    reader = None
    try:
        document = _load_installation(installation)
        report["identity"]["installation_pid"] = _parse_int(document.get("pid"))
        report["identity"]["installation_creation_filetime"] = _parse_int(document.get("creation_filetime"))
        report["identity"]["installation_session_id"] = document.get("session_id")
        kernel = _configure_kernel()
        handle = kernel.OpenProcess(PROCESS_ACCESS, False, report["identity"]["installation_pid"])
        if not handle:
            raise C.WinError(C.get_last_error())
        module_base = _capture_identity(report, document, kernel, handle)
        report["runtime_code_guard"] = None
        reader = _mission_memory.BoundedRPM(kernel, handle, module_base)
        report["runtime_code_guard"] = _runtime_code_guard(reader, module_base)
        if report["runtime_code_guard"].get("status") != "observed":
            raise ProbeError("进程内 code guard 不匹配")
        before_internal = _snapshot(reader, module_base, country)
        report["before"] = _without_private(before_internal)
        if before_internal.get("status") == "observed":
            after_internal = _snapshot(reader, module_base, country)
            report["after"] = _without_private(after_internal)
            report["doublepass"]["performed"] = True
            if after_internal.get("status") == "observed":
                mismatches = _diff_paths(_comparison_view(before_internal), _comparison_view(after_internal))
                report["doublepass"]["mismatches"] = mismatches[:128]
                report["doublepass"]["consistent"] = not mismatches
                if mismatches:
                    report["status"] = "doublepass_mismatch"
                    report["errors"].append({"stage": "doublepass", "status": "unknown", "error": "日期、国家身份/指针、旗标 ID/名称或 map_setup 改变", "paths": mismatches[:128]})
                else:
                    report["status"] = "observed"
                    report["inputs"] = {
                        "country_flags": report["before"]["country_flags"]["target_flags"],
                        "map_setup": report["before"]["map_setup"],
                        "has_domination": report["before"]["has_domination"],
                    }
            else:
                report["doublepass"]["consistent"] = False
                report["doublepass"]["mismatches"] = ["$.after.status"]
                report["status"] = "doublepass_mismatch"
                report["errors"].append({"stage": "doublepass", "status": "unknown", "error": "第二遍读取未完成"})
        else:
            report["status"] = "unknown"
            report["errors"].append({"stage": "before", "status": "unknown", "error": "第一遍输入未完整观测"})
    except Exception as exc:
        report["status"] = "error"
        report["errors"].append({"stage": "probe", "status": "unknown", "error": str(exc)})
    finally:
        if reader is not None:
            report["access"]["rpm_bytes_requested"] = reader.bytes_requested
            report["access"]["rpm_calls"] = reader.calls
        _apply_cleanup(report, kernel, handle)
        if report.get("cleanup", {}).get("handle_close", {}).get("status") == "error":
            _invalidate_inputs_after_cleanup_failure(report)
    report["completed"] = report["status"] in {
        "observed",
        "doublepass_mismatch",
        "error",
        "cleanup_error",
        "unsupported_country",
        "static_contract_mismatch",
    }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", required=True, type=Path)
    parser.add_argument("--country", choices=(EXPECTED_COUNTRY,), default=EXPECTED_COUNTRY)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    report = capture_inputs(args.installation, args.country)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"probe": report["probe"], "status": report["status"], "country": args.country, "doublepass": report["doublepass"], "output": str(args.output)}, ensure_ascii=False))
    return 0 if report["status"] == "observed" else 2


__all__ = ["capture_inputs"]


if __name__ == "__main__":
    raise SystemExit(main())
