"""Bounded read-only reader for one country's linked force records.

The reader deliberately stops at the native record boundary.  It does not
call a game function and it does not name a record as a regiment, ship,
active force, or men.  The adapter may project the validated raw records
using a separately pinned join.  A repeated record pointer or record id is a
hard error: silently de-duplicating a damaged graph would make the result
look more authoritative than the memory evidence supports.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from . import country_resources_memory as _crm
from . import localization_memory as _loc
from . import mission_memory as _mm
from .observation_time import dates_match, without_clock


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "country-forces-memory-1374-sampling-r1.json"
PROFILE_MAX_BYTES = 64 * 1024
# Updated after the profile is written.  Keeping the pin in code prevents a
# runtime process from accepting an edited profile by accident.
EXPECTED_PROFILE_SHA256 = "f1572a1cfe828ab2f9ee7673818a2a0dc78d8666964c2301bfe05efa08781e92"
EXPECTED_PROFILE_ID = "country-forces-memory-1374"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_VERSION = "1.37.4"
EXPECTED_COUNTRY = "FRA"

TYPE_PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "country-force-types-memory-1374.json"
TYPE_PROFILE_MAX_BYTES = 64 * 1024
EXPECTED_TYPE_PROFILE_SHA256 = "5f908fd09e3bcde2b95572c6eba7e5a456f6b01cbedd4456f5b6ddb3a76ab24e"
EXPECTED_TYPE_PROFILE_ID = "country-force-types-memory-1374"
TYPE_KEY_SCHEMA = "eu4.country_force_type_keys.v1"
TYPE_KEY_MAX_BYTES = 128
TYPE_CAPACITY_MAX = 4096
TYPE_KEY_GRAMMAR = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")

FIELDS = ("country_forces_records",)
FIELD_KEY = "country_forces_records"
BASIS = "native_country_direct_linked_force_records"
VALUE_ORIGIN = "bounded_rpm_record_graph"
UNIT = "native_force_records"
SCALE = 1
PERIOD = "current"
PARTIAL = True

MAX_SINGLE_RPM = 65_536
MAX_TOTAL_RPM = 1 * 1024 * 1024
# One shared budget covers country lookup and both snapshots.  This is the
# hard per-capture limit, rather than a budget multiplied by pass count.
READ_BUDGET_BYTES = MAX_TOTAL_RPM
MAX_USER_ADDRESS = _mm.MAX_USER_ADDRESS
PROCESS_ACCESS = _mm.PROCESS_ACCESS

AddressBoundedRPM = _crm.AddressBoundedRPM
ProbeError = _crm.ProbeError
_load_installation = _loc._load_installation
_configure_kernel = _loc._configure_kernel
_capture_identity = _loc._capture_identity
_close_process_handle = _loc._close_process_handle
_read_pe_rva_bytes = _mm._read_pe_rva_bytes


class ProfileError(RuntimeError):
    """The pinned profile or one of its source pins is invalid."""


class ReadError(RuntimeError):
    """A bounded read or force-graph contract check failed."""


def _copy_json(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False))


def _hex(value: int | None) -> str | None:
    return hex(value) if type(value) is int else None


def _parse_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ProfileError(f"profile_integer_invalid:{label}")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        try:
            result = int(value, 0)
        except ValueError as exc:
            raise ProfileError(f"profile_integer_invalid:{label}") from exc
    else:
        raise ProfileError(f"profile_integer_invalid:{label}")
    if result < 0:
        raise ProfileError(f"profile_integer_negative:{label}")
    return result


def _workspace_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _bounded_file(path: Path, limit: int, label: str) -> bytes:
    try:
        size = path.stat().st_size
        if size <= 0 or size > limit:
            raise ProfileError(f"{label}_size_out_of_bound:{size}")
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
    except (OSError, UnicodeError) as exc:
        raise ProfileError(f"{label}_read_failed:{exc}") from exc
    if len(raw) != size or len(raw) > limit:
        raise ProfileError(f"{label}_read_size_changed:{label}")
    return raw


def _source_evidence(profile: Mapping[str, Any]) -> list[dict[str, Any]]:
    items = profile.get("source_evidence")
    if not isinstance(items, list) or not items or len(items) > 12:
        raise ProfileError("source_evidence_shape_invalid")
    root = _workspace_root().resolve()
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, Mapping):
            raise ProfileError("source_evidence_item_invalid")
        relative = item.get("path")
        digest = item.get("sha256")
        size = item.get("bytes")
        if (not isinstance(relative, str) or not relative or
                not isinstance(digest, str) or len(digest) != 64 or
                type(size) is not int or size <= 0 or size > 256 * 1024):
            raise ProfileError("source_evidence_item_invalid")
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ProfileError("source_evidence_outside_workspace") from exc
        key = path.as_posix().lower()
        if key in seen:
            raise ProfileError("source_evidence_duplicate")
        seen.add(key)
        # Python references record the analysis revision. The pinned profile
        # and native code guards validate the runtime memory contract.
        if path.suffix == ".py":
            continue
        raw = _bounded_file(path, 256 * 1024, "source_evidence")
        if len(raw) != size or hashlib.sha256(raw).hexdigest().lower() != digest.lower():
            raise ProfileError(f"source_evidence_sha256_mismatch:{relative}")
        result.append({
            "path": path.relative_to(root).as_posix(),
            "sha256": digest.lower(),
            "bytes": size,
            "role": item.get("role"),
        })
    return result


def _profile_layout(profile: Mapping[str, Any]) -> dict[str, int]:
    raw = profile.get("layout")
    if not isinstance(raw, Mapping):
        raise ProfileError("profile_layout_missing")
    expected = {
        "database_global_rva": 0x233D8B0,
        "database_table_offset": 0x118,
        "database_table_count_offset": 0x124,
        "database_max_slots": 4095,
        "game_global_rva": 0x233FE58,
        "game_date_offset": 0x1DD0,
        "country_fullref_offset": 0x20,
        "country_group_offset": 0xD18,
        "group_object_offset": 0x0,
        "group_next_offset": 0x10,
        "group_vector_begin_offset": 0x30,
        "group_vector_end_offset": 0x38,
        "vector_entry_stride": 8,
        "record_body_size": 0x30,
        "record_id_type_offset": 0x10,
        "record_id_offset": 0x14,
        "record_type_offset": 0x20,
        "record_strength_offset": 0x28,
        "type_kind_offset": 0x10,
        "pointer_min": 0x10000,
        "pointer_max": MAX_USER_ADDRESS,
    }
    result: dict[str, int] = {}
    for key, expected in expected.items():
        value = _parse_int(raw.get(key), f"layout.{key}")
        if value != expected:
            raise ProfileError(f"profile_layout_value_invalid:{key}")
        result[key] = value
    return result


def _profile_code_guards(profile: Mapping[str, Any]) -> list[tuple[str, int, int, bytes]]:
    raw_guards = profile.get("code_guards")
    if not isinstance(raw_guards, list) or not raw_guards:
        raise ProfileError("profile_code_guards_shape_invalid")
    result: list[tuple[str, int, int, bytes]] = []
    names: set[str] = set()
    total = 0
    for item in raw_guards:
        if not isinstance(item, Mapping):
            raise ProfileError("profile_code_guard_invalid")
        name = item.get("name")
        if not isinstance(name, str) or not name or name in names:
            raise ProfileError("profile_code_guard_name_invalid")
        begin = _parse_int(item.get("rva"), f"code_guard.{name}.rva")
        end = _parse_int(item.get("rva_end_exclusive"), f"code_guard.{name}.end")
        try:
            raw = bytes.fromhex(str(item.get("hex", "")))
        except ValueError as exc:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}") from exc
        if (not raw or end != begin + len(raw) or
                hashlib.sha256(raw).hexdigest().lower() != str(item.get("sha256", "")).lower() or
                item.get("aslr_invariant") is not True):
            raise ProfileError(f"profile_code_guard_range_or_sha_invalid:{name}")
        total += len(raw)
        if total > MAX_SINGLE_RPM:
            raise ProfileError("profile_code_guards_budget_invalid")
        names.add(name)
        result.append((name, begin, end, raw))
    return result


def _validate_profile_shape(profile: Mapping[str, Any]) -> None:
    if profile.get("profile_id") != EXPECTED_PROFILE_ID or profile.get("game_version") != EXPECTED_VERSION:
        raise ProfileError("profile_shape_invalid")
    executable = profile.get("executable")
    if (not isinstance(executable, Mapping) or
            str(executable.get("sha256", "")).lower() != EXPECTED_EXE_SHA256):
        raise ProfileError("profile_executable_mismatch")
    _source_evidence(profile)
    _profile_layout(profile)
    limits = profile.get("limits")
    if not isinstance(limits, Mapping):
        raise ProfileError("profile_limits_invalid")
    expected_limits = {
        "max_total_rpm": MAX_TOTAL_RPM,
        "max_single_rpm": MAX_SINGLE_RPM,
        "max_groups": 128,
        "max_records": 1024,
        "max_records_per_group": 1024,
    }
    for key, value in expected_limits.items():
        if _parse_int(limits.get(key), f"limits.{key}") != value:
            raise ProfileError(f"profile_limits_invalid:{key}")
    semantics = profile.get("semantics")
    if (not isinstance(semantics, Mapping) or semantics.get("field") != FIELD_KEY or
            semantics.get("basis") != BASIS or semantics.get("value_origin") != VALUE_ORIGIN or
            semantics.get("unit") != UNIT or semantics.get("scale") != SCALE or
            semantics.get("period") != PERIOD or semantics.get("complete") is not False or
            semantics.get("partial") is not True):
        raise ProfileError("profile_semantics_invalid")
    _profile_code_guards(profile)


def _load_profile(path: Path | None = None, expected_sha256: str | None = None) -> dict[str, Any]:
    path = PROFILE_FILE if path is None else Path(path)
    expected = EXPECTED_PROFILE_SHA256 if expected_sha256 is None else expected_sha256
    if not isinstance(expected, str) or len(expected) != 64 or expected.startswith("__"):
        raise ProfileError("profile_sha256_pin_invalid")
    raw = _bounded_file(path, PROFILE_MAX_BYTES, "profile")
    if hashlib.sha256(raw).hexdigest().lower() != expected.lower():
        raise ProfileError("profile_sha256_mismatch")
    try:
        profile = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"profile_json_invalid:{exc}") from exc
    if not isinstance(profile, dict):
        raise ProfileError("profile_json_shape_invalid")
    _validate_profile_shape(profile)
    profile["_validated_source_evidence"] = _source_evidence(profile)
    return profile


def _prepare_profile(profile: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(profile, Mapping):
        raise ProfileError("profile_argument_invalid")
    result = dict(profile)
    _validate_profile_shape(result)
    result["_validated_source_evidence"] = _source_evidence(result)
    return result


def _type_profile_layout(profile: Mapping[str, Any]) -> dict[str, int]:
    raw = profile.get("layout")
    if not isinstance(raw, Mapping):
        raise ProfileError("type_profile_layout_missing")
    expected = {
        "record_type_pointer_offset": 0x20,
        "type_vptr_offset": 0,
        "type_vtable_rva": 0x1CE3700,
        "vtable_member_offset": 0x40,
        "member_rva": 0xAD8C10,
        "string_object_offset": 0x60,
        "capacity_offset": 0x78,
        "inline_when_capacity_less_than": 16,
        "pointer_min": 0x10000,
        "pointer_max": MAX_USER_ADDRESS,
    }
    result: dict[str, int] = {}
    for key, value in expected.items():
        actual = _parse_int(raw.get(key), f"type_layout.{key}")
        if actual != value:
            raise ProfileError(f"type_profile_layout_invalid:{key}")
        result[key] = actual
    return result


def _validate_type_profile_shape(profile: Mapping[str, Any]) -> None:
    if (profile.get("profile_id") != EXPECTED_TYPE_PROFILE_ID
            or profile.get("profile_version") != 1
            or profile.get("game_version") != EXPECTED_VERSION):
        raise ProfileError("type_profile_shape_invalid")
    executable = profile.get("executable")
    if (not isinstance(executable, Mapping)
            or str(executable.get("sha256", "")).lower() != EXPECTED_EXE_SHA256
            or str(executable.get("image_base", "")).lower() != "0x140000000"):
        raise ProfileError("type_profile_executable_mismatch")
    _source_evidence(profile)
    _type_profile_layout(profile)
    semantics = profile.get("semantics")
    if (not isinstance(semantics, Mapping)
            or semantics.get("field") != "unit_type"
            or semantics.get("key_grammar") != "[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"
            or semantics.get("max_key_bytes") != TYPE_KEY_MAX_BYTES
            or semantics.get("native_function_invoked") is not False
            or semantics.get("complete") is not False
            or semantics.get("partial") is not True):
        raise ProfileError("type_profile_semantics_invalid")
    limits = profile.get("limits")
    expected_limits = {
        "max_total_rpm": READ_BUDGET_BYTES,
        "max_single_rpm": MAX_SINGLE_RPM,
        "max_key_bytes": TYPE_KEY_MAX_BYTES,
        "max_type_capacity": TYPE_CAPACITY_MAX,
        "max_read_bytes": TYPE_KEY_MAX_BYTES + 1,
    }
    if not isinstance(limits, Mapping):
        raise ProfileError("type_profile_limits_invalid")
    for key, value in expected_limits.items():
        if _parse_int(limits.get(key), f"type_limits.{key}") != value:
            raise ProfileError(f"type_profile_limits_invalid:{key}")
    guards = _profile_code_guards(profile)
    expected_guard = bytes.fromhex(
        "40534883ec40488bda488d516048837a18107203488b1248c7442420"
    )
    if (len(guards) != 1
            or guards[0][0] != "unit_type_key_member_sso_heap_and_nul_prefix"
            or guards[0][1] != 0xAD8C10
            or guards[0][2] != 0xAD8C10 + len(expected_guard)
            or guards[0][3] != expected_guard):
        raise ProfileError("type_profile_code_guard_contract_invalid")


def _load_type_profile(path: Path | None = None,
                       expected_sha256: str | None = None) -> dict[str, Any]:
    path = TYPE_PROFILE_FILE if path is None else Path(path)
    expected = EXPECTED_TYPE_PROFILE_SHA256 if expected_sha256 is None else expected_sha256
    if not isinstance(expected, str) or len(expected) != 64 or expected.startswith("__"):
        raise ProfileError("type_profile_sha256_pin_invalid")
    raw = _bounded_file(path, TYPE_PROFILE_MAX_BYTES, "type_profile")
    if hashlib.sha256(raw).hexdigest().lower() != expected.lower():
        raise ProfileError("type_profile_sha256_mismatch")
    try:
        profile = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"type_profile_json_invalid:{exc}") from exc
    if not isinstance(profile, dict):
        raise ProfileError("type_profile_json_shape_invalid")
    _validate_type_profile_shape(profile)
    profile["_validated_source_evidence"] = _source_evidence(profile)
    return profile


def _prepare_type_profile(profile: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(profile, Mapping):
        raise ProfileError("type_profile_argument_invalid")
    result = dict(profile)
    _validate_type_profile_shape(result)
    result["_validated_source_evidence"] = _source_evidence(result)
    return result


def _type_static_contract_guard(profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown", "profile_id": EXPECTED_TYPE_PROFILE_ID,
        "profile_sha256": EXPECTED_TYPE_PROFILE_SHA256, "source_evidence": [],
        "checks": {}, "unknown_conditions": [],
    }
    try:
        loaded = _load_type_profile() if profile is None else _prepare_type_profile(profile)
        layout = _type_profile_layout(loaded)
        guards = _profile_code_guards(loaded)
        sources = loaded.get("_validated_source_evidence", _source_evidence(loaded))
        result["source_evidence"] = _copy_json(sources)
        result["checks"] = {
            "profile_id": loaded.get("profile_id") == EXPECTED_TYPE_PROFILE_ID,
            "game_version": loaded.get("game_version") == EXPECTED_VERSION,
            "game_sha256": str(loaded.get("executable", {}).get("sha256", "")).lower() == EXPECTED_EXE_SHA256,
            "vtable_and_member_contract": layout["type_vtable_rva"] == 0x1CE3700 and layout["vtable_member_offset"] == 0x40 and layout["member_rva"] == 0xAD8C10,
            "string_storage_contract": layout["string_object_offset"] == 0x60 and layout["capacity_offset"] == 0x78 and layout["inline_when_capacity_less_than"] == 16,
            "code_guards": bool(guards), "source_evidence": bool(sources),
        }
        if all(value is True for value in result["checks"].values()):
            result["status"] = "observed"
        else:
            result["unknown_conditions"].append("type_profile_contract_failed")
    except Exception as exc:
        result["unknown_conditions"].append(
            f"type_profile_contract_failed:{type(exc).__name__}:{exc}"
        )
    return result


def _type_file_code_guard(path: Path, profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "path": str(path),
                              "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        loaded = _load_type_profile() if profile is None else _prepare_type_profile(profile)
        for name, rva, end, expected in _profile_code_guards(loaded):
            actual = _read_pe_rva_bytes(path, rva, len(expected))
            result["records"][name] = {
                "rva": hex(rva), "rva_end_exclusive": hex(end),
                "expected_hex": expected.hex(), "actual_hex": actual.hex(),
                "expected_sha256": hashlib.sha256(expected).hexdigest(),
                "actual_sha256": hashlib.sha256(actual).hexdigest(),
            }
            result["checks"][name] = actual == expected
        if result["checks"] and all(result["checks"].values()):
            result["status"] = "observed"
        else:
            result["unknown_conditions"].append("type_file_code_guard_mismatch")
    except Exception as exc:
        result["unknown_conditions"].append(
            f"type_file_code_guard_failed:{type(exc).__name__}:{exc}"
        )
    return result


def _static_contract_guard(profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown", "evidence_kind": "ordinary_bounded_layout_and_record_identity_evidence",
        "profile": str(PROFILE_FILE), "profile_id": EXPECTED_PROFILE_ID,
        "profile_sha256": EXPECTED_PROFILE_SHA256, "source_evidence": [],
        "checks": {}, "unknown_conditions": [],
    }
    try:
        loaded = _load_profile() if profile is None else _prepare_profile(profile)
        layout = _profile_layout(loaded)
        guards = _profile_code_guards(loaded)
        sources = loaded.get("_validated_source_evidence", _source_evidence(loaded))
        result["source_evidence"] = _copy_json(sources)
        result["checks"] = {
            "profile_id": loaded.get("profile_id") == EXPECTED_PROFILE_ID,
            "game_version": loaded.get("game_version") == EXPECTED_VERSION,
            "game_sha256": str(loaded.get("executable", {}).get("sha256", "")).lower() == EXPECTED_EXE_SHA256,
            "database_and_country_layout": layout["database_global_rva"] == 0x233D8B0 and layout["database_table_offset"] == 0x118 and layout["country_fullref_offset"] == 0x20,
            "force_chain_layout": layout["country_group_offset"] == 0xD18 and layout["group_next_offset"] == 0x10 and layout["group_vector_begin_offset"] == 0x30 and layout["group_vector_end_offset"] == 0x38,
            "record_identity_layout": layout["record_id_type_offset"] == 0x10 and layout["record_id_offset"] == 0x14 and layout["record_type_offset"] == 0x20 and layout["record_strength_offset"] == 0x28 and layout["type_kind_offset"] == 0x10,
            "code_guards": bool(guards), "source_evidence": bool(sources),
        }
        failed = [key for key, value in result["checks"].items() if value is not True]
        if failed:
            result["unknown_conditions"].append("profile_contract_failed:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except Exception as exc:
        result["unknown_conditions"].append(f"profile_contract_read_failed:{type(exc).__name__}:{exc}")
    return result


def _file_code_guard(path: Path, profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "path": str(path), "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        for name, rva, end, expected in _profile_code_guards(profile or _load_profile()):
            actual = _read_pe_rva_bytes(path, rva, len(expected))
            result["records"][name] = {"rva": hex(rva), "rva_end_exclusive": hex(end), "expected_hex": expected.hex(), "actual_hex": actual.hex(), "expected_sha256": hashlib.sha256(expected).hexdigest(), "actual_sha256": hashlib.sha256(actual).hexdigest()}
            result["checks"][name] = actual == expected
        if result["checks"] and all(result["checks"].values()):
            result["status"] = "observed"
        else:
            result["unknown_conditions"].append("file_code_guard_mismatch")
    except Exception as exc:
        result["unknown_conditions"].append(f"file_code_guard_failed:{type(exc).__name__}:{exc}")
    return result


class _ReadBudget:
    def __init__(self, limit: int = READ_BUDGET_BYTES):
        self.limit = limit
        self.used = 0
        self.reads: list[dict[str, Any]] = []

    def reserve(self, size: int) -> None:
        if type(size) is not int or size <= 0 or size > MAX_SINGLE_RPM or self.used + size > self.limit:
            raise ReadError("read_budget_exceeded")
        self.used += size

    def snapshot(self, start: int = 0) -> dict[str, Any]:
        return {"bytes_reserved": self.used - start, "limit": self.limit}


def _valid_address(value: Any, layout: Mapping[str, int]) -> bool:
    return type(value) is int and layout["pointer_min"] <= value < layout["pointer_max"]


def _add_address(base: int, offset: int, layout: Mapping[str, int]) -> int:
    if not _valid_address(base, layout) or type(offset) is not int or offset < 0:
        raise ReadError("pointer_arithmetic_invalid")
    result = base + offset
    if not _valid_address(result, layout):
        raise ReadError("pointer_arithmetic_invalid")
    return result


def _reader_read(reader: Any, address: int, size: int, label: str, budget: _ReadBudget, layout: Mapping[str, int]) -> bytes:
    if not _valid_address(address, layout):
        raise ReadError(f"address_invalid:{label}")
    budget.reserve(size)
    method = getattr(reader, "read", None)
    if not callable(method):
        raise ReadError("reader_read_method_missing")
    try:
        raw = method(address, size, label)
    except Exception as exc:
        budget.reads.append({"address": _hex(address), "size": size, "label": label, "status": "failed", "error": type(exc).__name__})
        raise ReadError(f"read_failed:{label}:{type(exc).__name__}:{exc}") from exc
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != size:
        budget.reads.append({"address": _hex(address), "size": size, "label": label, "status": "failed", "error": "short_or_invalid_read"})
        raise ReadError(f"short_or_invalid_read:{label}")
    raw = bytes(raw)
    budget.reads.append({"address": _hex(address), "size": size, "label": label, "status": "ok", "raw_hex": raw.hex(), "sha256": hashlib.sha256(raw).hexdigest()})
    return raw


def _read_u64(reader: Any, address: int, label: str, budget: _ReadBudget, layout: Mapping[str, int]) -> tuple[int, bytes]:
    raw = _reader_read(reader, address, 8, label, budget, layout)
    return int.from_bytes(raw, "little", signed=False), raw


def _read_i32(reader: Any, address: int, label: str, budget: _ReadBudget, layout: Mapping[str, int]) -> tuple[int, bytes]:
    raw = _reader_read(reader, address, 4, label, budget, layout)
    return int.from_bytes(raw, "little", signed=True), raw


def _runtime_code_guard(reader: Any, module_base: int, profile: Mapping[str, Any], budget: _ReadBudget) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "module_base": _hex(module_base), "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        layout = _profile_layout(profile)
        for name, rva, end, expected in _profile_code_guards(profile):
            address = _add_address(module_base, rva, layout)
            budget.reserve(len(expected))
            method = getattr(reader, "read_code", None) or getattr(reader, "read", None)
            if not callable(method):
                raise ReadError("reader_code_method_missing")
            raw = method(address, len(expected), f"country_forces.code.{name}")
            if not isinstance(raw, (bytes, bytearray)) or len(raw) != len(expected):
                raise ReadError(f"code_guard_short:{name}")
            raw = bytes(raw)
            budget.reads.append({"address": _hex(address), "size": len(expected), "label": f"country_forces.code.{name}", "status": "ok", "raw_hex": raw.hex(), "sha256": hashlib.sha256(raw).hexdigest()})
            result["records"][name] = {"rva": hex(rva), "rva_end_exclusive": hex(end), "address": _hex(address), "expected_hex": expected.hex(), "actual_hex": raw.hex(), "expected_sha256": hashlib.sha256(expected).hexdigest(), "actual_sha256": hashlib.sha256(raw).hexdigest()}
            result["checks"][name] = raw == expected
        if result["checks"] and all(result["checks"].values()):
            result["status"] = "observed"
        else:
            result["unknown_conditions"].append("runtime_code_guard_mismatch")
    except Exception as exc:
        result["unknown_conditions"].append(f"runtime_code_guard_failed:{type(exc).__name__}:{exc}")
    result["bytes_reserved"] = sum(len(bytes.fromhex(item.get("expected_hex", ""))) for item in result.get("records", {}).values() if isinstance(item, Mapping))
    return result


def _type_runtime_code_guard(reader: Any, module_base: int,
                             profile: Mapping[str, Any], budget: _ReadBudget) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "module_base": _hex(module_base),
                              "profile_id": EXPECTED_TYPE_PROFILE_ID,
                              "profile_sha256": EXPECTED_TYPE_PROFILE_SHA256,
                              "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        layout = _type_profile_layout(profile)
        for name, rva, end, expected in _profile_code_guards(profile):
            address = _add_address(module_base, rva, layout)
            raw = _reader_read(reader, address, len(expected),
                               f"country_forces.unit_type.code.{name}", budget,
                               layout)
            result["records"][name] = {
                "rva": hex(rva), "rva_end_exclusive": hex(end),
                "address": _hex(address), "expected_hex": expected.hex(),
                "actual_hex": raw.hex(),
                "expected_sha256": hashlib.sha256(expected).hexdigest(),
                "actual_sha256": hashlib.sha256(raw).hexdigest(),
            }
            result["checks"][name] = raw == expected
        if result["checks"] and all(result["checks"].values()):
            result["status"] = "observed"
        else:
            result["unknown_conditions"].append("type_runtime_code_guard_mismatch")
    except Exception as exc:
        result["unknown_conditions"].append(
            f"type_runtime_code_guard_failed:{type(exc).__name__}:{exc}"
        )
    result["bytes_reserved"] = sum(
        len(bytes.fromhex(item.get("expected_hex", "")))
        for item in result["records"].values() if isinstance(item, Mapping)
    )
    return result


def _tag_from_fullref(value: int) -> str | None:
    raw = (value & 0xFFFFFF).to_bytes(3, "little")
    if not all(0x30 <= b <= 0x39 or 0x41 <= b <= 0x5A for b in raw):
        return None
    return raw.decode("ascii")


def _find_country(reader: Any, module_base: int, country: str, profile: Mapping[str, Any], budget: _ReadBudget) -> tuple[int, dict[str, Any]]:
    layout = _profile_layout(profile)
    if not isinstance(country, str) or re.fullmatch(r"[A-Z0-9]{3}", country) is None:
        raise ReadError("unsupported_country")
    database, database_raw = _read_u64(reader, _add_address(module_base, layout["database_global_rva"], layout), "country_forces.database", budget, layout)
    if not _valid_address(database, layout):
        raise ReadError("country_database_invalid")
    table, table_raw = _read_u64(reader, _add_address(database, layout["database_table_offset"], layout), "country_forces.country_table", budget, layout)
    if not _valid_address(table, layout):
        raise ReadError("country_table_invalid")
    count, count_raw = _read_i32(reader, _add_address(database, layout["database_table_count_offset"], layout), "country_forces.country_count", budget, layout)
    if not 1 <= count <= layout["database_max_slots"] + 1:
        raise ReadError("country_count_invalid")
    matches: list[dict[str, Any]] = []
    for slot in range(count):
        ptr, ptr_raw = _read_u64(reader, _add_address(table, slot * 8, layout), f"country_forces.country_table[{slot}]", budget, layout)
        if not ptr:
            continue
        if not _valid_address(ptr, layout):
            raise ReadError("country_pointer_invalid")
        fullref, fullref_raw = _read_u64(reader, _add_address(ptr, layout["country_fullref_offset"], layout), f"country_forces.country_fullref[{slot}]", budget, layout)
        tag = _tag_from_fullref(fullref)
        if tag == country and ((fullref >> 32) & 0xFFFF) == slot:
            handle, handle_raw = _read_u64(reader, _add_address(ptr, layout["country_fullref_offset"], layout), f"country_forces.country_handle[{slot}]", budget, layout)
            matches.append({"slot": slot, "pointer": _hex(ptr), "fullref_raw_hex": fullref_raw.hex(), "tag": tag, "table_entry_raw_hex": ptr_raw.hex(), "country_handle": _hex(handle), "country_handle_raw_hex": handle_raw.hex()})
    if len(matches) != 1:
        raise ReadError("country_identity_match_count_invalid")
    return int(matches[0]["pointer"], 0), {"status": "observed", "database": _hex(database), "database_raw_hex": database_raw.hex(), "table_pointer": _hex(table), "table_raw_hex": table_raw.hex(), "country_count": count, "country_count_raw_hex": count_raw.hex(), "matches": matches, "country_pointer": matches[0]["pointer"], "country_handle": matches[0]["country_handle"], "country_handle_raw_hex": matches[0]["country_handle_raw_hex"]}


def _read_force_chain(reader: Any, country_pointer: int, country: str, profile: Mapping[str, Any], budget: _ReadBudget) -> dict[str, Any]:
    layout = _profile_layout(profile)
    limits = profile["limits"]
    group_head, group_head_raw = _read_u64(reader, _add_address(country_pointer, layout["country_group_offset"], layout), "country_forces.country.group_head", budget, layout)
    groups: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    seen_groups: set[int] = set()
    seen_record_ptrs: set[int] = set()
    seen_ids: set[tuple[int, int]] = set()
    current = group_head
    current_raw = group_head_raw
    while current:
        if len(groups) >= int(limits["max_groups"]):
            raise ReadError("group_count_out_of_bound")
        if not _valid_address(current, layout) or current in seen_groups:
            raise ReadError("group_pointer_invalid_or_repeated")
        seen_groups.add(current)
        group_object, group_object_raw = _read_u64(reader, _add_address(current, layout["group_object_offset"], layout), f"country_forces.group[{len(groups)}].object", budget, layout)
        if not _valid_address(group_object, layout):
            raise ReadError("group_object_invalid")
        begin, begin_raw = _read_u64(reader, _add_address(group_object, layout["group_vector_begin_offset"], layout), f"country_forces.group[{len(groups)}].begin", budget, layout)
        end, end_raw = _read_u64(reader, _add_address(group_object, layout["group_vector_end_offset"], layout), f"country_forces.group[{len(groups)}].end", budget, layout)
        if (begin == 0) != (end == 0):
            raise ReadError("force_vector_null_pair_invalid")
        if begin and (not _valid_address(begin, layout) or not _valid_address(end, layout) or end < begin or (end - begin) % layout["vector_entry_stride"] != 0):
            raise ReadError("force_vector_bounds_invalid")
        count = 0 if not begin else (end - begin) // layout["vector_entry_stride"]
        if count > int(limits["max_records_per_group"]):
            raise ReadError("force_vector_count_out_of_bound")
        group_records: list[str] = []
        for index in range(count):
            record_pointer, pointer_raw = _read_u64(reader, begin + index * layout["vector_entry_stride"], f"country_forces.group[{len(groups)}].record[{index}]", budget, layout)
            if not _valid_address(record_pointer, layout):
                raise ReadError("record_pointer_invalid")
            if record_pointer in seen_record_ptrs:
                raise ReadError("record_pointer_repeated_across_groups")
            if len(records) >= int(limits["max_records"]):
                raise ReadError("record_count_out_of_bound")
            seen_record_ptrs.add(record_pointer)
            body = _reader_read(reader, record_pointer, layout["record_body_size"], f"country_forces.record[{len(records)}].body", budget, layout)
            id_type = int.from_bytes(body[layout["record_id_type_offset"]:layout["record_id_type_offset"] + 4], "little", signed=False)
            record_id = int.from_bytes(body[layout["record_id_offset"]:layout["record_id_offset"] + 4], "little", signed=False)
            identity = (id_type, record_id)
            if id_type == 0 or record_id == 0 or identity in seen_ids:
                raise ReadError("record_identity_invalid_or_repeated")
            type_object = int.from_bytes(body[layout["record_type_offset"]:layout["record_type_offset"] + 8], "little", signed=False)
            if not _valid_address(type_object, layout):
                raise ReadError("record_type_pointer_invalid")
            type_kind, type_kind_raw = _read_i32(reader, _add_address(type_object, layout["type_kind_offset"], layout), f"country_forces.record[{len(records)}].type_kind", budget, layout)
            strength_raw = int.from_bytes(body[layout["record_strength_offset"]:layout["record_strength_offset"] + 4], "little", signed=True)
            if strength_raw < 0:
                raise ReadError("record_strength_negative")
            seen_ids.add(identity)
            item = {
                "record_pointer": _hex(record_pointer),
                "record_pointer_raw_hex": pointer_raw.hex(),
                "record_body_raw_hex": body.hex(),
                "id_type": id_type,
                "id": record_id,
                "id_type_raw_hex": body[layout["record_id_type_offset"]:layout["record_id_type_offset"] + 4].hex(),
                "id_raw_hex": body[layout["record_id_offset"]:layout["record_id_offset"] + 4].hex(),
                "type_object": _hex(type_object),
                "type_kind": type_kind,
                "type_kind_raw_hex": type_kind_raw.hex(),
                "strength_raw": strength_raw,
                "strength_raw_hex": body[layout["record_strength_offset"]:layout["record_strength_offset"] + 4].hex(),
                "group_index": len(groups),
                "vector_index": index,
            }
            records.append(item)
            group_records.append(item["record_pointer"])
        next_group, next_raw = _read_u64(reader, _add_address(current, layout["group_next_offset"], layout), f"country_forces.group[{len(groups)}].next", budget, layout)
        groups.append({"group_head": _hex(current), "group_head_raw_hex": current_raw.hex(), "group_object": _hex(group_object), "group_object_raw_hex": group_object_raw.hex(), "vector_begin": _hex(begin) if begin else None, "vector_end": _hex(end) if end else None, "vector_begin_raw_hex": begin_raw.hex(), "vector_end_raw_hex": end_raw.hex(), "vector_length": count, "record_pointers": group_records, "next_group_head": _hex(next_group) if next_group else None, "next_group_head_raw_hex": next_raw.hex()})
        if next_group and next_group in seen_groups:
            raise ReadError("group_link_repeated")
        current = next_group
        current_raw = next_raw
    return {"status": "observed", "country": country, "country_group_head": _hex(group_head) if group_head else None, "country_group_head_raw_hex": group_head_raw.hex(), "group_count": len(groups), "record_count": len(records), "groups": groups, "records": records, "seen_record_count": len(seen_record_ptrs), "seen_identity_count": len(seen_ids)}


def _read_unit_type_key(reader: Any, module_base: int, row: Mapping[str, Any],
                        profile: Mapping[str, Any], budget: _ReadBudget,
                        type_index: int) -> tuple[dict[str, Any], dict[str, Any]]:
    layout = _type_profile_layout(profile)
    limits = profile["limits"]
    type_object = int(str(row["type_object"]), 0)
    proof: dict[str, Any] = {
        "status": "unknown", "profile_id": EXPECTED_TYPE_PROFILE_ID,
        "profile_sha256": EXPECTED_TYPE_PROFILE_SHA256,
        "type_object": _hex(type_object), "read_log": [],
    }
    start_log = len(budget.reads)

    def read(address: int, size: int, label: str) -> bytes:
        if size <= 0:
            raise ReadError("unit_type_read_size_invalid")
        _add_address(address, size - 1, layout)
        return _reader_read(reader, address, size, label, budget, layout)

    def unknown(reason: str) -> tuple[dict[str, Any], dict[str, Any]]:
        proof["reason"] = reason
        proof["read_log"] = _copy_json(budget.reads[start_log:])
        return {"status": "unknown", "reason": reason}, proof

    try:
        if not _valid_address(type_object, layout):
            return unknown("UNIT_TYPE_POINTER_INVALID")
        vptr_address = _add_address(type_object, layout["type_vptr_offset"], layout)
        vptr_raw = read(vptr_address, 8, f"country_forces.unit_type.type[{type_index}].vptr")
        vptr = int.from_bytes(vptr_raw, "little", signed=False)
        proof["vptr_raw_hex"] = vptr_raw.hex()
        expected_vtable = _add_address(module_base, layout["type_vtable_rva"], layout)
        if not _valid_address(vptr, layout) or vptr != expected_vtable:
            return unknown("UNIT_TYPE_VPTR_MISMATCH")

        member_address = _add_address(vptr, layout["vtable_member_offset"], layout)
        member_raw = read(member_address, 8,
                          f"country_forces.unit_type.type[{type_index}].member")
        member = int.from_bytes(member_raw, "little", signed=False)
        proof["member_pointer_raw_hex"] = member_raw.hex()
        expected_member = _add_address(module_base, layout["member_rva"], layout)
        if not _valid_address(member, layout) or member != expected_member:
            return unknown("UNIT_TYPE_MEMBER_MISMATCH")

        string_address = _add_address(type_object, layout["string_object_offset"], layout)
        capacity_address = _add_address(type_object, layout["capacity_offset"], layout)
        capacity_raw = read(capacity_address, 8,
                            f"country_forces.unit_type.type[{type_index}].capacity")
        capacity = int.from_bytes(capacity_raw, "little", signed=False)
        proof["capacity_raw_hex"] = capacity_raw.hex()
        proof["capacity"] = capacity
        if capacity > int(limits["max_type_capacity"]):
            return unknown("UNIT_TYPE_CAPACITY_INVALID")

        if capacity < layout["inline_when_capacity_less_than"]:
            storage = "inline"
            string_pointer_raw = None
            string_data_address = string_address
        else:
            storage = "heap"
            string_pointer_raw = read(
                string_address, 8,
                f"country_forces.unit_type.type[{type_index}].string_pointer",
            )
            string_data_address = int.from_bytes(string_pointer_raw, "little", signed=False)
            if not _valid_address(string_data_address, layout):
                proof["storage"] = storage
                proof["string_pointer_raw_hex"] = string_pointer_raw.hex()
                return unknown("UNIT_TYPE_STRING_POINTER_INVALID")
            proof["string_pointer_raw_hex"] = string_pointer_raw.hex()

        read_size = min(capacity + 1, int(limits["max_read_bytes"]))
        if read_size <= 0:
            return unknown("UNIT_TYPE_CAPACITY_INVALID")
        string_raw = read(
            string_data_address, read_size,
            f"country_forces.unit_type.type[{type_index}].string_bytes",
        )
        nul_offset = string_raw.find(b"\x00")
        proof.update({
            "storage": storage,
            "string_read_raw_hex": string_raw.hex(),
            "nul_offset": nul_offset if nul_offset >= 0 else None,
        })
        if nul_offset < 0:
            return unknown("UNIT_TYPE_KEY_NUL_MISSING")
        if nul_offset == 0:
            return unknown("UNIT_TYPE_KEY_EMPTY")
        if nul_offset > TYPE_KEY_MAX_BYTES:
            return unknown("UNIT_TYPE_KEY_TOO_LONG")
        key_raw = string_raw[:nul_offset]
        try:
            key = key_raw.decode("ascii")
        except UnicodeDecodeError:
            return unknown("UNIT_TYPE_KEY_NOT_ASCII")
        if TYPE_KEY_GRAMMAR.fullmatch(key) is None:
            return unknown("UNIT_TYPE_KEY_INVALID")
        proof.update({
            "status": "observed", "key_raw_hex": key_raw.hex(),
            "read_log": _copy_json(budget.reads[start_log:]),
        })
        return {"status": "known", "key": key}, proof
    except Exception as exc:
        reason = ("UNIT_TYPE_READ_BUDGET_EXCEEDED"
                  if isinstance(exc, ReadError) and str(exc) == "read_budget_exceeded"
                  else "UNIT_TYPE_READ_FAILED")
        return unknown(reason)


def _decorate_unit_type_rows(records: list[dict[str, Any]], reader: Any, module_base: int,
                             profile: Mapping[str, Any] | None,
                             budget: _ReadBudget, reason: str | None) -> None:
    cache: dict[int, tuple[dict[str, Any], dict[str, Any]]] = {}
    cache_indexes: dict[int, int] = {}
    for row in records:
        type_object = int(str(row["type_object"]), 0)
        if reason is not None:
            unit_type = {"status": "unknown", "reason": reason}
            proof = {
                "status": "unknown", "reason": reason,
                "profile_id": EXPECTED_TYPE_PROFILE_ID,
                "profile_sha256": EXPECTED_TYPE_PROFILE_SHA256,
                "type_object": _hex(type_object), "read_log": [],
            }
        else:
            if type_object not in cache:
                if profile is None:
                    unit_type = {"status": "unknown", "reason": "UNIT_TYPE_PROFILE_INVALID"}
                    proof = {"status": "unknown", "reason": "UNIT_TYPE_PROFILE_INVALID",
                             "profile_id": EXPECTED_TYPE_PROFILE_ID,
                             "profile_sha256": EXPECTED_TYPE_PROFILE_SHA256,
                             "type_object": _hex(type_object), "read_log": []}
                else:
                    index = len(cache_indexes)
                    cache_indexes[type_object] = index
                    unit_type, proof = _read_unit_type_key(
                        reader=reader, module_base=module_base,
                        row=row, profile=profile, budget=budget, type_index=index,
                    )
                cache[type_object] = (unit_type, proof)
            unit_type, proof = cache[type_object]
        row["unit_type"] = _copy_json(unit_type)
        row["unit_type_proof"] = _copy_json(proof)


def _snapshot(reader: Any, module_base: int, country_pointer: int, country: str,
              profile: Mapping[str, Any], static_guard: Mapping[str, Any],
              budget: _ReadBudget, *, include_type_keys: bool = False,
              type_profile: Mapping[str, Any] | None = None,
              type_static_guard: Mapping[str, Any] | None = None,
              type_file_guard: Mapping[str, Any] | None = None,
              type_reason: str | None = None) -> dict[str, Any]:
    layout = _profile_layout(profile)
    start_used = budget.used
    start_log = len(budget.reads)
    runtime_guard = _runtime_code_guard(reader, module_base, profile, budget)
    if runtime_guard.get("status") != "observed":
        raise ReadError("runtime_code_guard_failed")
    game, game_raw = _read_u64(reader, _add_address(module_base, layout["game_global_rva"], layout), "country_forces.game", budget, layout)
    if not _valid_address(game, layout):
        raise ReadError("game_pointer_invalid")
    date_raw = _reader_read(reader, _add_address(game, layout["game_date_offset"], layout), 4, "country_forces.game_date", budget, layout)
    game_date = int.from_bytes(date_raw, "little", signed=True)
    handle, handle_raw = _read_u64(reader, _add_address(country_pointer, layout["country_fullref_offset"], layout), "country_forces.country_handle", budget, layout)
    if _tag_from_fullref(handle) != country:
        raise ReadError("country_handle_tag_mismatch")
    chain = _read_force_chain(reader, country_pointer, country, profile, budget)
    type_runtime_guard: dict[str, Any] | None = None
    type_guard: dict[str, Any] | None = None
    if include_type_keys:
        type_static_guard = dict(type_static_guard or {
            "status": "unknown", "profile_id": EXPECTED_TYPE_PROFILE_ID,
            "profile_sha256": EXPECTED_TYPE_PROFILE_SHA256,
            "checks": {}, "source_evidence": [], "unknown_conditions": ["type_profile_not_loaded"],
        })
        type_file_guard = dict(type_file_guard or {
            "status": "unknown", "checks": {}, "records": [],
            "unknown_conditions": ["type_file_guard_not_run"],
        })
        if type_reason is None and type_profile is not None:
            type_runtime_guard = _type_runtime_code_guard(
                reader, module_base, type_profile, budget,
            )
            if type_runtime_guard.get("status") != "observed":
                type_reason = "UNIT_TYPE_RUNTIME_CODE_GUARD_MISMATCH"
        else:
            type_runtime_guard = {
                "status": "unknown", "profile_id": EXPECTED_TYPE_PROFILE_ID,
                "profile_sha256": EXPECTED_TYPE_PROFILE_SHA256,
                "module_base": _hex(module_base),
                "checks": {}, "records": {},
                "unknown_conditions": [type_reason or "type_profile_unavailable"],
            }
        _decorate_unit_type_rows(
            chain["records"], reader, module_base, type_profile, budget,
            type_reason,
        )
        type_guard = {
            "schema": TYPE_KEY_SCHEMA,
            "version": 1,
            "profile_id": EXPECTED_TYPE_PROFILE_ID,
            "profile_sha256": EXPECTED_TYPE_PROFILE_SHA256,
            "profile_status": "observed" if type_profile is not None else "unknown",
            "static_contract_guard": _copy_json(type_static_guard),
            "file_code_guard": _copy_json(type_file_guard),
            "runtime_code_guard": _copy_json(type_runtime_guard),
            "status": "observed" if type_reason is None else "unknown",
            "reason": type_reason,
        }
    read_log = _copy_json(budget.reads[start_log:])
    record = {
        "status": "observed", "profile_id": EXPECTED_PROFILE_ID, "profile_sha256": EXPECTED_PROFILE_SHA256,
        "module_base": _hex(module_base), "country_pointer": _hex(country_pointer),
        "country_handle": _hex(handle), "country_handle_raw_hex": handle_raw.hex(),
        "game_pointer": _hex(game), "game_pointer_raw_hex": game_raw.hex(),
        "game_date": {"value": game_date, "raw_hex": date_raw.hex()},
        "groups": _copy_json(chain["groups"]), "records": _copy_json(chain["records"]),
        "group_count": chain["group_count"], "record_count": chain["record_count"],
        "country_group_head": chain["country_group_head"], "country_group_head_raw_hex": chain["country_group_head_raw_hex"],
        "static_contract_guard": _copy_json(static_guard), "runtime_code_guard": _copy_json(runtime_guard),
        "basis": BASIS, "unit": UNIT, "scale": SCALE, "period": PERIOD, "value_origin": VALUE_ORIGIN,
        "complete": False,
        "observation": {"profile_id": EXPECTED_PROFILE_ID, "profile_sha256": EXPECTED_PROFILE_SHA256, "module_base": _hex(module_base), "country_pointer": _hex(country_pointer), "country_handle": _hex(handle), "game_date": game_date, "read_budget": {"bytes_reserved": budget.used - start_used, "limit": READ_BUDGET_BYTES}, "read_log": read_log, "graph": {"group_count": chain["group_count"], "record_count": chain["record_count"]}},
    }
    if type_guard is not None:
        record["unit_type_guard"] = _copy_json(type_guard)
    records = _copy_json(chain["records"])
    public_records = [
        {key: value for key, value in row.items() if key != "unit_type_proof"}
        if include_type_keys and isinstance(row, Mapping) else row
        for row in records
    ]
    field = {"status": "known", "complete": False, "partial": True, "value": public_records, "unit": UNIT, "scale": SCALE, "period": PERIOD, "basis": BASIS, "value_origin": VALUE_ORIGIN}
    record["fields"] = {FIELD_KEY: field}
    result = {"status": "observed", "country": country, "country_pointer": _hex(country_pointer), "country_handle": _hex(handle), "game_date": {"value": game_date, "raw_hex": date_raw.hex()}, "records": records, "groups": _copy_json(chain["groups"]), "record": record, "fields": {FIELD_KEY: field}, "values": {FIELD_KEY: public_records}, "raw_hex": {FIELD_KEY: [{"record_body_raw_hex": row["record_body_raw_hex"], "type_kind_raw_hex": row["type_kind_raw_hex"], "strength_raw_hex": row["strength_raw_hex"]} for row in records]}, "complete": False, "read_budget": {"bytes_reserved": budget.used - start_used, "limit": READ_BUDGET_BYTES}, "read_log": read_log, "runtime_code_guard": runtime_guard}
    if type_guard is not None:
        result["unit_type_guard"] = _copy_json(type_guard)
    return result


def _unknown_record(reason: str, *, module_base: int | None = None, country_pointer: int | None = None) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason, "profile_id": EXPECTED_PROFILE_ID, "profile_sha256": EXPECTED_PROFILE_SHA256, "module_base": _hex(module_base), "country_pointer": _hex(country_pointer), "records": None, "groups": None, "group_count": None, "record_count": None, "complete": False, "basis": BASIS, "unit": UNIT, "scale": SCALE, "period": PERIOD, "value_origin": VALUE_ORIGIN}


def read_fields(reader: Any, module_base: int, country_pointer: int, country: str = EXPECTED_COUNTRY, profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Read one synthetic or live Reader without opening a process."""
    try:
        loaded = _load_profile() if profile is None else _prepare_profile(profile)
        layout = _profile_layout(loaded)
        if not _valid_address(module_base, layout) or not _valid_address(country_pointer, layout):
            raise ReadError("module_or_country_pointer_invalid")
        static_guard = _static_contract_guard(loaded)
        if static_guard.get("status") != "observed":
            raise ReadError("static_contract_guard_failed")
        return _snapshot(reader, module_base, country_pointer, country, loaded, static_guard, _ReadBudget())
    except Exception as exc:
        return _unknown_record(f"{type(exc).__name__}:{exc}", module_base=module_base if type(module_base) is int else None, country_pointer=country_pointer if type(country_pointer) is int else None)


def _stable_record(record: Mapping[str, Any]) -> dict[str, Any]:
    result = {key: record.get(key) for key in (
        "status", "profile_id", "profile_sha256", "module_base", "country_pointer",
        "country_handle", "game_pointer", "game_date", "groups", "group_count",
        "record_count", "country_group_head", "basis", "unit", "scale", "period",
        "value_origin", "complete",
    )}
    rows = record.get("records")
    if isinstance(rows, list):
        result["records"] = [
            {key: value for key, value in row.items()
             if key not in {"unit_type", "unit_type_proof"}}
            if isinstance(row, Mapping) else row
            for row in rows
        ]
    else:
        result["records"] = rows
    return result


def _stable_record_for_comparison(record: Mapping[str, Any]) -> dict[str, Any]:
    return without_clock(_stable_record(record), date_labels=("country_forces.game_date",))


def _type_proof_signature(proof: Any) -> Any:
    if not isinstance(proof, Mapping):
        return proof
    return {key: value for key, value in proof.items() if key != "read_log"}


def _set_snapshot_unit_type(snapshot: dict[str, Any], index: int,
                            value: Mapping[str, Any]) -> None:
    containers = [snapshot.get("records")]
    record = snapshot.get("record")
    if isinstance(record, Mapping):
        containers.append(record.get("records"))
    fields = snapshot.get("fields")
    if isinstance(fields, Mapping) and isinstance(fields.get(FIELD_KEY), Mapping):
        containers.append(fields[FIELD_KEY].get("value"))
    values = snapshot.get("values")
    if isinstance(values, Mapping):
        containers.append(values.get(FIELD_KEY))
    if isinstance(record, Mapping):
        record_fields = record.get("fields")
        if isinstance(record_fields, Mapping) and isinstance(record_fields.get(FIELD_KEY), Mapping):
            containers.append(record_fields[FIELD_KEY].get("value"))
    seen: set[int] = set()
    for rows in containers:
        if not isinstance(rows, list) or index >= len(rows) or id(rows) in seen:
            continue
        seen.add(id(rows))
        if isinstance(rows[index], dict):
            rows[index]["unit_type"] = _copy_json(value)


def _reconcile_type_key_passes(before: dict[str, Any], after: dict[str, Any]) -> bool:
    before_rows = before.get("record", {}).get("records", [])
    after_rows = after.get("record", {}).get("records", [])
    if not isinstance(before_rows, list) or not isinstance(after_rows, list) or len(before_rows) != len(after_rows):
        return False
    consistent = True
    for index, (left, right) in enumerate(zip(before_rows, after_rows)):
        if not isinstance(left, Mapping) or not isinstance(right, Mapping):
            consistent = False
            continue
        left_type = left.get("unit_type")
        right_type = right.get("unit_type")
        same = (left_type == right_type
                and _type_proof_signature(left.get("unit_type_proof"))
                == _type_proof_signature(right.get("unit_type_proof")))
        if same:
            continue
        consistent = False
        mismatch = {"status": "unknown", "reason": "UNIT_TYPE_CHANGED_BETWEEN_PASSES"}
        _set_snapshot_unit_type(before, index, mismatch)
        _set_snapshot_unit_type(after, index, mismatch)
    return consistent


def _diff_paths(left: Any, right: Any, path: str = "$") -> list[str]:
    if type(left) is not type(right):
        return [path]
    if isinstance(left, Mapping):
        result: list[str] = []
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                result.append(f"{path}.{key}")
            else:
                result.extend(_diff_paths(left[key], right[key], f"{path}.{key}"))
        return result
    if isinstance(left, list):
        result = [] if len(left) == len(right) else [f"{path}.length"]
        for index, (a, b) in enumerate(zip(left, right)):
            result.extend(_diff_paths(a, b, f"{path}[{index}]"))
        return result
    return [] if left == right else [path]


def capture(installation: Path, country: str = EXPECTED_COUNTRY, *,
           include_type_keys: bool = False) -> dict[str, Any]:
    """Capture a country's direct linked records using read-only bounded RPM."""
    if type(include_type_keys) is not bool:
        raise TypeError("include_type_keys must be bool")
    installation = Path(installation)
    report: dict[str, Any] = {"probe": "information-country-forces-runtime", "probe_version": 1, "probe_script": str(Path(__file__).resolve()), "probe_script_sha256": None, "profile": {"path": str(PROFILE_FILE), "sha256": EXPECTED_PROFILE_SHA256, "profile_id": EXPECTED_PROFILE_ID, "max_bytes": PROFILE_MAX_BYTES}, "read_only": True, "evidence_kind": "pure_runtime_observation_not_static_evidence", "captured_at": datetime.now(timezone.utc).isoformat(), "request": {"installation": str(installation), "country": country, "scope": "direct_country_plus_0xd18_linked_records"}, "country": country, "target_build": {"version": EXPECTED_VERSION, "expected_exe_sha256": EXPECTED_EXE_SHA256, "database_rva": hex(0x233D8B0), "game_rva": hex(0x233FE58)}, "static_contract_guard": None, "file_code_guard": None, "runtime_code_guard": None, "identity": {"installation_path": str(installation), "installation_pid": None, "installation_creation_filetime": None, "installation_session_id": None, "process_path": None, "process_path_sha256": None, "process_path_sha256_matches_expected": None, "process_creation_filetime": None, "process_creation_utc": None, "process_creation_matches_installation": None, "module_path": None, "module_path_matches_process": None, "binding_verified": False}, "module_base": None, "country_pointer": None, "country_scan": None, "before": None, "after": None, "fields": {FIELD_KEY: {"status": "unknown", "reason": "not_read"}}, "values": None, "raw_hex": None, "complete": False, "doublepass": {"performed": False, "consistent": None, "mismatches": [], "atomic": False}, "access": {"open_process_mask": "QUERY_INFORMATION|VM_READ", "open_process_mask_hex": _hex(PROCESS_ACCESS), "rpm_total_limit": MAX_TOTAL_RPM, "rpm_single_read_limit": MAX_SINGLE_RPM, "rpm_bytes_requested": 0, "rpm_calls": 0, "native_game_calls": False, "target_memory_writes": False, "mcp_query": False, "control_or_business_dispatch": False, "date_advance_save_restart": False}, "cleanup": {"handle_close": {"status": "unknown", "success": None, "closed": False}}, "status": "starting", "errors": [], "completed": False}
    type_profile: dict[str, Any] | None = None
    type_static_guard: dict[str, Any] | None = None
    type_file_guard: dict[str, Any] | None = None
    type_profile_reason: str | None = None
    type_file_reason: str | None = None
    if include_type_keys:
        type_profile = None
        type_static_guard = {"status": "unknown", "profile_id": EXPECTED_TYPE_PROFILE_ID,
                             "profile_sha256": EXPECTED_TYPE_PROFILE_SHA256,
                             "source_evidence": [], "checks": {},
                             "unknown_conditions": ["not_loaded"]}
        type_file_guard = {"status": "unknown", "checks": {}, "records": {},
                           "unknown_conditions": ["not_checked"]}
        type_profile_reason = "UNIT_TYPE_PROFILE_INVALID"
        report["type_key_enhancement"] = {
            "schema": TYPE_KEY_SCHEMA, "version": 1, "enabled": True,
            "status": "unknown", "profile_id": EXPECTED_TYPE_PROFILE_ID,
            "profile_sha256": EXPECTED_TYPE_PROFILE_SHA256,
            "profile_status": "unknown", "static_contract_guard": type_static_guard,
            "file_code_guard": type_file_guard,
            "runtime_code_guard": {"status": "unknown", "passes": []},
            "cross_pass_consistent": None,
            "unknown_conditions": ["type_profile_not_loaded"],
        }
    kernel = None
    handle = None
    reader = None
    budget = _ReadBudget()
    try:
        report["probe_script_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        if not isinstance(country, str) or re.fullmatch(r"[A-Z0-9]{3}", country) is None:
            report["status"] = "unsupported_country"
            report["errors"].append({"stage": "request", "status": "unknown", "error": "Invalid country tag"})
            return report
        profile = _load_profile()
        report["static_contract_guard"] = _static_contract_guard(profile)
        if report["static_contract_guard"].get("status") != "observed":
            report["status"] = "static_contract_mismatch"
            return report
        if include_type_keys:
            try:
                type_profile = _load_type_profile()
                type_static_guard = _type_static_contract_guard(type_profile)
                type_profile_reason = (None if type_static_guard.get("status") == "observed"
                                       else "UNIT_TYPE_PROFILE_INVALID")
            except Exception as exc:
                type_profile = None
                type_profile_reason = "UNIT_TYPE_PROFILE_INVALID"
                type_static_guard = {
                    "status": "unknown", "profile_id": EXPECTED_TYPE_PROFILE_ID,
                    "profile_sha256": EXPECTED_TYPE_PROFILE_SHA256,
                    "source_evidence": [], "checks": {},
                    "unknown_conditions": [f"type_profile_load_failed:{type(exc).__name__}"],
                }
            report["type_key_enhancement"].update({
                "profile_status": "observed" if type_profile is not None and type_profile_reason is None else "unknown",
                "static_contract_guard": _copy_json(type_static_guard),
                "unknown_conditions": _copy_json(type_static_guard.get("unknown_conditions", [])),
            })
        document = _load_installation(installation)
        kernel = _configure_kernel()
        handle = kernel.OpenProcess(PROCESS_ACCESS, False, int(document["pid"]))
        if not handle:
            raise OSError("OpenProcess failed")
        module_base = _capture_identity(report, document, kernel, handle)
        report["module_base"] = _hex(module_base)
        report["request"].update({
            "pid": int(document["pid"]),
            "creation_filetime": int(document["creation_filetime"]),
            "session_id": str(document["session_id"]),
            "game_sha256": str(document.get("game_sha256", "")).lower(),
        })
        process_path = Path(report["identity"]["process_path"])
        report["file_code_guard"] = _file_code_guard(process_path, profile)
        if report["file_code_guard"].get("status") != "observed":
            report["status"] = "file_code_mismatch"
            return report
        if include_type_keys:
            if type_profile is not None and type_profile_reason is None:
                type_file_guard = _type_file_code_guard(process_path, type_profile)
                if type_file_guard.get("status") != "observed":
                    type_file_reason = "UNIT_TYPE_FILE_CODE_GUARD_MISMATCH"
            else:
                type_file_reason = type_profile_reason or "UNIT_TYPE_PROFILE_INVALID"
                type_file_guard = {
                    "status": "unknown", "checks": {}, "records": {},
                    "unknown_conditions": [type_file_reason],
                }
            report["type_key_enhancement"].update({
                "file_code_guard": _copy_json(type_file_guard),
                "unknown_conditions": [
                    *report["type_key_enhancement"].get("unknown_conditions", []),
                    *type_file_guard.get("unknown_conditions", []),
                ],
            })
        reader = AddressBoundedRPM(kernel, handle, module_base)
        first_country_pointer, first_country_scan = _find_country(reader, module_base, country, profile, budget)
        report["country_pointer"] = _hex(first_country_pointer)
        initial_type_reason = type_profile_reason or type_file_reason
        first = _snapshot(
            reader, module_base, first_country_pointer, country, profile,
            report["static_contract_guard"], budget,
            include_type_keys=include_type_keys, type_profile=type_profile,
            type_static_guard=type_static_guard, type_file_guard=type_file_guard,
            type_reason=initial_type_reason,
        )
        first["country_scan"] = _copy_json(first_country_scan)
        report["before"] = first
        second_country_pointer, second_country_scan = _find_country(reader, module_base, country, profile, budget)
        second = _snapshot(
            reader, module_base, second_country_pointer, country, profile,
            report["static_contract_guard"], budget,
            include_type_keys=include_type_keys, type_profile=type_profile,
            type_static_guard=type_static_guard, type_file_guard=type_file_guard,
            type_reason=initial_type_reason,
        )
        second["country_scan"] = _copy_json(second_country_scan)
        report["after"] = second
        report["doublepass"]["performed"] = True
        report["doublepass"]["mismatches"] = _diff_paths(
            _stable_record_for_comparison(first["record"]),
            _stable_record_for_comparison(second["record"]))
        first_date = first.get("game_date")
        second_date = second.get("game_date")
        first_date_value = first_date.get("value") if isinstance(first_date, Mapping) else None
        second_date_value = second_date.get("value") if isinstance(second_date, Mapping) else None
        if (not dates_match(first_date_value, second_date_value)
                and "$.game_date" not in report["doublepass"]["mismatches"]):
            report["doublepass"]["mismatches"].append("$.game_date")
        report["doublepass"]["mismatches"].extend(_diff_paths(first_country_scan, second_country_scan, "$.country_scan"))
        if first_country_pointer != second_country_pointer:
            report["doublepass"]["mismatches"].append("$.country_pointer")
        report["doublepass"]["consistent"] = not report["doublepass"]["mismatches"]
        report["country_scan"] = {"before": _copy_json(first_country_scan), "after": _copy_json(second_country_scan)}
        report["runtime_code_guard"] = {"status": "observed", "passes": [first["runtime_code_guard"], second["runtime_code_guard"]]}
        if include_type_keys:
            type_pass_consistent = _reconcile_type_key_passes(first, second)
            first_guard = first.get("unit_type_guard", {})
            second_guard = second.get("unit_type_guard", {})
            type_runtime_passes = [first_guard.get("runtime_code_guard"),
                                   second_guard.get("runtime_code_guard")]
            runtime_status = ("observed" if all(
                isinstance(item, Mapping) and item.get("status") == "observed"
                for item in type_runtime_passes) else "unknown")
            unit_rows = first.get("record", {}).get("records", [])
            type_global_reason = first_guard.get("reason")
            has_unknown = any(
                not isinstance(row.get("unit_type"), Mapping)
                or row["unit_type"].get("status") != "known"
                for row in unit_rows if isinstance(row, Mapping)
            )
            extension = report["type_key_enhancement"]
            extension.update({
                "status": ("unknown" if type_global_reason is not None else
                           "partial" if has_unknown or not type_pass_consistent else "observed"),
                "profile_status": "observed" if type_profile is not None and type_profile_reason is None else "unknown",
                "static_contract_guard": _copy_json(type_static_guard),
                "file_code_guard": _copy_json(type_file_guard),
                "runtime_code_guard": {"status": runtime_status, "passes": type_runtime_passes},
                "cross_pass_consistent": type_pass_consistent,
                "unknown_conditions": list(dict.fromkeys([
                    *(type_static_guard or {}).get("unknown_conditions", []),
                    *(type_file_guard or {}).get("unknown_conditions", []),
                    *[condition for item in type_runtime_passes
                      if isinstance(item, Mapping)
                      for condition in item.get("unknown_conditions", [])],
                    *(["unit_type_changed_between_passes"] if not type_pass_consistent else []),
                    *(["one_or_more_unit_type_keys_unknown"] if has_unknown else []),
                ])),
            })
        report["access"]["rpm_bytes_requested"] = budget.used
        report["access"]["rpm_calls"] = len(budget.reads)
        if not report["doublepass"]["consistent"]:
            report["status"] = "doublepass_mismatch"
            report["errors"].append({"stage": "doublepass", "status": "unknown", "error": "Country force graph changed between passes", "paths": report["doublepass"]["mismatches"][:256]})
            return report
        report["fields"] = _copy_json(first["fields"])
        report["values"] = _copy_json(first["values"])
        report["raw_hex"] = _copy_json(first["raw_hex"])
        report["complete"] = False
        report["status"] = "observed"
        report["completed"] = True
        return report
    except Exception as exc:
        report["status"] = "unknown"
        report["errors"].append({"stage": "capture", "status": "unknown", "error": f"{type(exc).__name__}:{exc}"})
        report["access"]["rpm_bytes_requested"] = budget.used
        report["access"]["rpm_calls"] = len(budget.reads)
        return report
    finally:
        report["access"]["rpm_bytes_requested"] = budget.used
        report["access"]["rpm_calls"] = len(budget.reads)
        report["cleanup"]["handle_close"] = _close_process_handle(kernel, handle)
        if report.get("status") == "observed" and report["cleanup"]["handle_close"] != {"status": "closed", "success": True, "closed": True}:
            report["status"] = "unknown"
            report["errors"].append({"stage": "cleanup", "status": "unknown", "error": "process handle cleanup failed", "cleanup": _copy_json(report["cleanup"]["handle_close"])})
        report["completed"] = True


def _runtime_guard_valid(value: Any, profile: Mapping[str, Any], module_base: int) -> bool:
    if not isinstance(value, Mapping) or value.get("status") != "observed" or value.get("module_base") != _hex(module_base):
        return False
    checks = value.get("checks")
    records = value.get("records")
    if not isinstance(checks, Mapping) or not checks or not all(item is True for item in checks.values()) or not isinstance(records, Mapping):
        return False
    try:
        for name, _rva, _end, expected in _profile_code_guards(profile):
            item = records.get(name)
            if (not isinstance(item, Mapping) or item.get("expected_hex") != expected.hex() or
                    item.get("actual_hex") != expected.hex() or
                    item.get("expected_sha256") != hashlib.sha256(expected).hexdigest() or
                    item.get("actual_sha256") != hashlib.sha256(expected).hexdigest()):
                return False
    except Exception:
        return False
    return True


def _static_guard_valid(value: Any) -> bool:
    if not isinstance(value, Mapping) or value.get("status") != "observed" or value.get("profile_id") != EXPECTED_PROFILE_ID or value.get("profile_sha256") != EXPECTED_PROFILE_SHA256:
        return False
    checks = value.get("checks")
    return isinstance(checks, Mapping) and bool(checks) and all(item is True for item in checks.values())


_TYPE_KEY_LOCAL_UNKNOWN_REASONS = {
    "UNIT_TYPE_VPTR_MISMATCH", "UNIT_TYPE_MEMBER_MISMATCH",
    "UNIT_TYPE_CAPACITY_INVALID", "UNIT_TYPE_STRING_POINTER_INVALID",
    "UNIT_TYPE_KEY_NUL_MISSING", "UNIT_TYPE_KEY_EMPTY",
    "UNIT_TYPE_KEY_TOO_LONG", "UNIT_TYPE_KEY_NOT_ASCII",
    "UNIT_TYPE_KEY_INVALID", "UNIT_TYPE_READ_BUDGET_EXCEEDED",
    "UNIT_TYPE_READ_FAILED",
}
_TYPE_KEY_GLOBAL_UNKNOWN_REASONS = {
    "UNIT_TYPE_PROFILE_INVALID", "UNIT_TYPE_FILE_CODE_GUARD_MISMATCH",
    "UNIT_TYPE_RUNTIME_CODE_GUARD_MISMATCH",
}


def _type_static_guard_valid(value: Any, profile: Mapping[str, Any]) -> bool:
    if (not isinstance(value, Mapping) or value.get("status") != "observed"
            or value.get("profile_id") != EXPECTED_TYPE_PROFILE_ID
            or value.get("profile_sha256") != EXPECTED_TYPE_PROFILE_SHA256):
        return False
    checks = value.get("checks")
    sources = profile.get("_validated_source_evidence", [])
    expected_checks = {
        "profile_id": True,
        "game_version": True,
        "game_sha256": True,
        "vtable_and_member_contract": True,
        "string_storage_contract": True,
        "code_guards": True,
        "source_evidence": True,
    }
    return (isinstance(checks, Mapping) and dict(checks) == expected_checks
            and value.get("source_evidence") == sources
            and value.get("unknown_conditions") == [])


def _type_guard_code_state(value: Any, profile: Mapping[str, Any],
                           module_base: int | None = None) -> str:
    if not isinstance(value, Mapping):
        return "invalid"
    if module_base is not None and value.get("module_base") != _hex(module_base):
        return "invalid"
    records = value.get("records")
    checks = value.get("checks")
    if not isinstance(records, Mapping) or not isinstance(checks, Mapping):
        return "invalid"
    try:
        expected_guards = _profile_code_guards(profile)
        expected_names = {item[0] for item in expected_guards}
        if (not set(records) <= expected_names or set(checks) != set(records)
                or not isinstance(value.get("unknown_conditions"), list)):
            return "invalid"
        matched = True
        for name, rva, end, expected in expected_guards:
            item = records.get(name)
            if item is None:
                continue
            if (not isinstance(item, Mapping)
                    or item.get("rva") != hex(rva)
                    or item.get("rva_end_exclusive") != hex(end)
                    or item.get("expected_hex") != expected.hex()
                    or item.get("expected_sha256") != hashlib.sha256(expected).hexdigest()):
                return "invalid"
            try:
                actual = bytes.fromhex(item.get("actual_hex", ""))
            except (TypeError, ValueError):
                return "invalid"
            if (len(actual) != len(expected)
                    or item.get("actual_sha256") != hashlib.sha256(actual).hexdigest()
                    or checks.get(name) is not (actual == expected)):
                return "invalid"
            if module_base is not None:
                address = item.get("address")
                if address != _hex(module_base + rva):
                    return "invalid"
            matched = matched and actual == expected
        complete = set(records) == expected_names
        if matched and complete and value.get("status") == "observed" and value.get("unknown_conditions") == []:
            return "match"
        if value.get("status") == "unknown" and value.get("unknown_conditions"):
            if not matched:
                return "mismatch"
            if not complete:
                return "unavailable"
            # A guard can be present but report an operational read failure.
            return "unavailable"
        if not complete and value.get("status") == "unknown":
            return "unavailable"
        if not matched and value.get("status") == "unknown":
            return "mismatch"
        return "invalid"
    except Exception:
        return "invalid"


def _type_enhancement_header_valid(value: Any) -> tuple[bool, dict[str, Any] | None]:
    if (not isinstance(value, Mapping) or value.get("schema") != TYPE_KEY_SCHEMA
            or value.get("version") != 1 or value.get("enabled") is not True
            or value.get("profile_id") != EXPECTED_TYPE_PROFILE_ID
            or value.get("profile_sha256") != EXPECTED_TYPE_PROFILE_SHA256
            or value.get("status") not in ("observed", "partial", "unknown")
            or value.get("profile_status") not in ("observed", "unknown")
            or not isinstance(value.get("unknown_conditions"), list)
            or any(not isinstance(item, str) for item in value.get("unknown_conditions", []))):
        return False, None
    if value.get("profile_status") == "unknown":
        static_guard = value.get("static_contract_guard")
        if (value.get("status") != "unknown" or not isinstance(static_guard, Mapping)
                or static_guard.get("status") != "unknown"
                or value.get("cross_pass_consistent") is not True):
            return False, None
        file_state = value.get("file_code_guard")
        runtime = value.get("runtime_code_guard")
        passes = runtime.get("passes") if isinstance(runtime, Mapping) else None
        if (not isinstance(file_state, Mapping) or file_state.get("status") != "unknown"
                or file_state.get("records") != {} or file_state.get("checks") != {}
                or not isinstance(passes, list) or len(passes) != 2
                or runtime.get("status") != "unknown"
                or any(_type_guard_code_state(item, _minimal_type_profile_for_unknown()) != "unavailable"
                       for item in passes)):
            return False, None
        # This branch deliberately accepts unknown-only output even if the
        # profile becomes readable later.  It carries no key or raw component.
        return True, None
    try:
        profile = _load_type_profile()
    except Exception:
        return False, None
    if not _type_static_guard_valid(value.get("static_contract_guard"), profile):
        return False, None
    file_state = _type_guard_code_state(value.get("file_code_guard"), profile)
    if file_state == "invalid":
        return False, None
    runtime = value.get("runtime_code_guard")
    passes = runtime.get("passes") if isinstance(runtime, Mapping) else None
    if not isinstance(passes, list) or len(passes) != 2:
        return False, None
    module_base = None
    states = [_type_guard_code_state(item, profile, module_base) for item in passes]
    if any(state == "invalid" for state in states):
        return False, None
    expected_runtime_status = "observed" if all(state == "match" for state in states) else "unknown"
    if runtime.get("status") != expected_runtime_status:
        return False, None
    if file_state != "match" or expected_runtime_status != "observed":
        if value.get("status") not in ("partial", "unknown"):
            return False, None
    if type(value.get("cross_pass_consistent")) is not bool:
        return False, None
    return True, profile


def _minimal_type_profile_for_unknown() -> dict[str, Any]:
    """Expected guard contract used to validate deliberately unknown-only reports."""
    return {
        "code_guards": [{
            "name": "unit_type_key_member_sso_heap_and_nul_prefix",
            "rva": "0xad8c10", "rva_end_exclusive": "0xad8c2c",
            "hex": "40534883ec40488bda488d516048837a18107203488b1248c7442420",
            "sha256": "54836054ebcc706fb8ea7abc887237236a5e302209ba8e859eeab798c8dac2e3",
            "aslr_invariant": True,
        }],
    }


def _unit_type_read_log_valid(log: Any, layout: Mapping[str, int]) -> bool:
    if not isinstance(log, list):
        return False
    for item in log:
        if (not isinstance(item, Mapping)
                or not isinstance(item.get("label"), str)
                or not item["label"].startswith("country_forces.unit_type.type[")
                or type(item.get("address")) is not str
                or type(item.get("size")) is not int or item["size"] <= 0):
            return False
        try:
            address = int(item["address"], 0)
        except ValueError:
            return False
        if not _valid_address(address, layout):
            return False
        if item.get("status") == "ok":
            try:
                raw = bytes.fromhex(item.get("raw_hex", ""))
            except (TypeError, ValueError):
                return False
            if (len(raw) != item["size"]
                    or item.get("sha256") != hashlib.sha256(raw).hexdigest()):
                return False
        elif item.get("status") == "failed":
            if (item.get("error") not in ("AssertionError", "OSError", "MemoryError",
                                           "KeyError", "ValueError", "RuntimeError",
                                           "short_or_invalid_read")
                    or "raw_hex" in item):
                return False
        else:
            return False
    return True


def _unit_type_proof_valid(row: Mapping[str, Any], unit_type: Mapping[str, Any],
                           proof: Mapping[str, Any], profile: Mapping[str, Any],
                           module_base: int) -> bool:
    reason = proof.get("reason")
    changed_unknown = unit_type == {
        "status": "unknown", "reason": "UNIT_TYPE_CHANGED_BETWEEN_PASSES",
    }

    def unit_type_matches(expected: Mapping[str, Any]) -> bool:
        return changed_unknown or dict(unit_type) == dict(expected)

    if reason in _TYPE_KEY_GLOBAL_UNKNOWN_REASONS:
        return (proof.get("status") == "unknown"
                and proof.get("profile_id") == EXPECTED_TYPE_PROFILE_ID
                and proof.get("profile_sha256") == EXPECTED_TYPE_PROFILE_SHA256
                and proof.get("type_object") == row.get("type_object")
                and proof.get("read_log") == []
                and unit_type_matches({"status": "unknown", "reason": reason}))
    if reason == "UNIT_TYPE_READ_BUDGET_EXCEEDED":
        return (proof.get("status") == "unknown"
                and proof.get("profile_id") == EXPECTED_TYPE_PROFILE_ID
                and proof.get("profile_sha256") == EXPECTED_TYPE_PROFILE_SHA256
                and proof.get("type_object") == row.get("type_object")
                and proof.get("read_log") == []
                and unit_type_matches({"status": "unknown", "reason": reason}))
    layout = _type_profile_layout(profile)
    if (proof.get("profile_id") != EXPECTED_TYPE_PROFILE_ID
            or proof.get("profile_sha256") != EXPECTED_TYPE_PROFILE_SHA256
            or proof.get("type_object") != row.get("type_object")
            or not _unit_type_read_log_valid(proof.get("read_log"), layout)):
        return False
    type_object = int(str(row.get("type_object")), 0)
    if not _valid_address(type_object, layout):
        return False
    log = proof.get("read_log", [])
    type_index: str | None = None
    for item in log:
        label = item["label"]
        match = re.fullmatch(r"country_forces\.unit_type\.type\[(\d+)\]\.(vptr|member|capacity|string_pointer|string_bytes)", label)
        if match is None or (type_index is not None and type_index != match.group(1)):
            return False
        type_index = match.group(1)
    if not log or type_index is None:
        return False

    expected_vtable = _add_address(module_base, layout["type_vtable_rva"], layout)
    expected_member = _add_address(module_base, layout["member_rva"], layout)
    labels = [item["label"].rsplit(".", 1)[-1] for item in log]
    if not labels or labels[0] != "vptr":
        return False

    def fail_or_raw(position: int, suffix: str, address: int, size: int) -> bytes | None:
        if position >= len(log):
            if proof.get("reason") == "UNIT_TYPE_READ_BUDGET_EXCEEDED":
                return None
            raise ValueError("proof_read_missing")
        item = log[position]
        if (not item["label"].endswith("." + suffix)
                or int(item["address"], 0) != address or item["size"] != size):
            raise ValueError("proof_read_target_invalid")
        if item["status"] == "failed":
            if position != len(log) - 1:
                raise ValueError("proof_read_after_failure")
            return None
        return bytes.fromhex(item["raw_hex"])

    position = 0
    try:
        vptr_raw = fail_or_raw(position, "vptr", type_object, 8)
        position += 1
        if vptr_raw is None:
            return (proof.get("reason") == "UNIT_TYPE_READ_FAILED"
                    and proof.get("status") == "unknown"
                    and unit_type_matches({"status": "unknown", "reason": "UNIT_TYPE_READ_FAILED"})) or (
                        proof.get("reason") == "UNIT_TYPE_READ_BUDGET_EXCEEDED"
                        and proof.get("status") == "unknown"
                        and unit_type_matches({"status": "unknown", "reason": "UNIT_TYPE_READ_BUDGET_EXCEEDED"}))
        if proof.get("vptr_raw_hex") != vptr_raw.hex():
            return False
        vptr = int.from_bytes(vptr_raw, "little")
        if vptr != expected_vtable:
            return (labels == ["vptr"] and proof.get("reason") == "UNIT_TYPE_VPTR_MISMATCH"
                    and proof.get("status") == "unknown"
                    and unit_type_matches({"status": "unknown", "reason": "UNIT_TYPE_VPTR_MISMATCH"}))

        member_raw = fail_or_raw(position, "member", expected_vtable + layout["vtable_member_offset"], 8)
        position += 1
        if member_raw is None:
            return (proof.get("reason") == "UNIT_TYPE_READ_FAILED"
                    and unit_type_matches({"status": "unknown", "reason": "UNIT_TYPE_READ_FAILED"})) or (
                        proof.get("reason") == "UNIT_TYPE_READ_BUDGET_EXCEEDED"
                        and unit_type_matches({"status": "unknown", "reason": "UNIT_TYPE_READ_BUDGET_EXCEEDED"}))
        if proof.get("member_pointer_raw_hex") != member_raw.hex():
            return False
        member = int.from_bytes(member_raw, "little")
        if member != expected_member:
            return (labels == ["vptr", "member"]
                    and proof.get("reason") == "UNIT_TYPE_MEMBER_MISMATCH"
                    and proof.get("status") == "unknown"
                    and unit_type_matches({"status": "unknown", "reason": "UNIT_TYPE_MEMBER_MISMATCH"}))

        capacity_raw = fail_or_raw(position, "capacity",
                                   type_object + layout["capacity_offset"], 8)
        position += 1
        if capacity_raw is None:
            return (proof.get("reason") == "UNIT_TYPE_READ_FAILED"
                    and unit_type_matches({"status": "unknown", "reason": "UNIT_TYPE_READ_FAILED"})) or (
                        proof.get("reason") == "UNIT_TYPE_READ_BUDGET_EXCEEDED"
                        and unit_type_matches({"status": "unknown", "reason": "UNIT_TYPE_READ_BUDGET_EXCEEDED"}))
        capacity = int.from_bytes(capacity_raw, "little")
        if (proof.get("capacity_raw_hex") != capacity_raw.hex()
                or type(proof.get("capacity")) is not int
                or proof.get("capacity") != capacity):
            return False
        if capacity > int(profile["limits"]["max_type_capacity"]):
            return (labels == ["vptr", "member", "capacity"]
                    and proof.get("reason") == "UNIT_TYPE_CAPACITY_INVALID"
                    and proof.get("status") == "unknown"
                    and unit_type_matches({"status": "unknown", "reason": "UNIT_TYPE_CAPACITY_INVALID"}))

        expected_size = min(capacity + 1, int(profile["limits"]["max_read_bytes"]))
        string_address = type_object + layout["string_object_offset"]
        if capacity < layout["inline_when_capacity_less_than"]:
            if proof.get("storage") not in (None, "inline") or proof.get("string_pointer_raw_hex") is not None:
                return False
            data_address = string_address
        else:
            if proof.get("storage") not in (None, "heap"):
                return False
            pointer_raw = fail_or_raw(position, "string_pointer", string_address, 8)
            position += 1
            if pointer_raw is None:
                return (proof.get("reason") == "UNIT_TYPE_READ_FAILED"
                        and unit_type_matches({"status": "unknown", "reason": "UNIT_TYPE_READ_FAILED"})) or (
                            proof.get("reason") == "UNIT_TYPE_READ_BUDGET_EXCEEDED"
                            and unit_type_matches({"status": "unknown", "reason": "UNIT_TYPE_READ_BUDGET_EXCEEDED"}))
            if proof.get("string_pointer_raw_hex") != pointer_raw.hex():
                return False
            data_address = int.from_bytes(pointer_raw, "little")
            if not _valid_address(data_address, layout):
                return (labels == ["vptr", "member", "capacity", "string_pointer"]
                        and proof.get("reason") == "UNIT_TYPE_STRING_POINTER_INVALID"
                        and proof.get("status") == "unknown"
                        and unit_type_matches({"status": "unknown", "reason": "UNIT_TYPE_STRING_POINTER_INVALID"}))
        if not _valid_address(data_address, layout):
            return False
        try:
            _add_address(data_address, expected_size - 1, layout)
        except ReadError:
            return (proof.get("reason") == "UNIT_TYPE_READ_FAILED"
                    and proof.get("status") == "unknown"
                    and unit_type_matches({"status": "unknown", "reason": "UNIT_TYPE_READ_FAILED"})
                    and position == len(log))
        string_raw = fail_or_raw(position, "string_bytes", data_address, expected_size)
        position += 1
        if string_raw is None:
            return (proof.get("reason") == "UNIT_TYPE_READ_FAILED"
                    and unit_type_matches({"status": "unknown", "reason": "UNIT_TYPE_READ_FAILED"})) or (
                        proof.get("reason") == "UNIT_TYPE_READ_BUDGET_EXCEEDED"
                        and unit_type_matches({"status": "unknown", "reason": "UNIT_TYPE_READ_BUDGET_EXCEEDED"}))
        if (proof.get("string_read_raw_hex") != string_raw.hex()
                or proof.get("storage") != ("inline" if capacity < layout["inline_when_capacity_less_than"] else "heap")):
            return False
        nul_offset = string_raw.find(b"\x00")
        if proof.get("nul_offset") != (nul_offset if nul_offset >= 0 else None):
            return False
        reason: str | None = None
        key: str | None = None
        if nul_offset < 0:
            reason = "UNIT_TYPE_KEY_NUL_MISSING"
        elif nul_offset == 0:
            reason = "UNIT_TYPE_KEY_EMPTY"
        elif nul_offset > TYPE_KEY_MAX_BYTES:
            reason = "UNIT_TYPE_KEY_TOO_LONG"
        else:
            raw_key = string_raw[:nul_offset]
            try:
                key = raw_key.decode("ascii")
            except UnicodeDecodeError:
                reason = "UNIT_TYPE_KEY_NOT_ASCII"
            if reason is None and TYPE_KEY_GRAMMAR.fullmatch(key or "") is None:
                reason = "UNIT_TYPE_KEY_INVALID"
            if reason is None and proof.get("key_raw_hex") != raw_key.hex():
                return False
        if position != len(log):
            return False
        if reason is not None:
            return (proof.get("status") == "unknown" and proof.get("reason") == reason
                    and unit_type_matches({"status": "unknown", "reason": reason}))
        if proof.get("status") != "observed" or "reason" in proof:
            return False
        expected_unit_type = {"status": "known", "key": key}
        return unit_type_matches(expected_unit_type)
    except (ValueError, TypeError, KeyError, ReadError):
        return False


def validate_record(record: Any, *, country: str = EXPECTED_COUNTRY,
                    type_key_enhancement: Mapping[str, Any] | None = None,
                    pass_index: int | None = None) -> bool:
    """Validate raw record identity and graph shape without deriving public meanings."""
    if (not isinstance(record, Mapping) or record.get("status") != "observed"
            or not isinstance(country, str) or re.fullmatch(r"[A-Z0-9]{3}", country) is None):
        return False
    try:
        profile = _load_profile()
        layout = _profile_layout(profile)
        limits = profile["limits"]
        if any(record.get(key) != value for key, value in {"profile_id": EXPECTED_PROFILE_ID, "profile_sha256": EXPECTED_PROFILE_SHA256, "basis": BASIS, "unit": UNIT, "scale": SCALE, "period": PERIOD, "value_origin": VALUE_ORIGIN, "complete": False}.items()):
            return False
        module_base = int(str(record.get("module_base")), 0)
        country_pointer = int(str(record.get("country_pointer")), 0)
        if not _valid_address(module_base, layout) or not _valid_address(country_pointer, layout) or not _static_guard_valid(record.get("static_contract_guard")) or not _runtime_guard_valid(record.get("runtime_code_guard"), profile, module_base):
            return False
        handle = int(str(record.get("country_handle")), 0)
        handle_raw_hex = record.get("country_handle_raw_hex")
        if (_tag_from_fullref(handle) != country or not isinstance(handle_raw_hex, str) or len(handle_raw_hex) != 16 or
                int.from_bytes(bytes.fromhex(handle_raw_hex), "little", signed=False) != handle):
            return False
        game_pointer = int(str(record.get("game_pointer")), 0)
        game_pointer_raw_hex = record.get("game_pointer_raw_hex")
        if (not _valid_address(game_pointer, layout) or not isinstance(game_pointer_raw_hex, str) or len(game_pointer_raw_hex) != 16 or
                int.from_bytes(bytes.fromhex(game_pointer_raw_hex), "little", signed=False) != game_pointer):
            return False
        game_date = record.get("game_date")
        if (not isinstance(game_date, Mapping) or type(game_date.get("value")) is not int or
                not isinstance(game_date.get("raw_hex"), str) or len(game_date["raw_hex"]) != 8 or
                int.from_bytes(bytes.fromhex(game_date["raw_hex"]), "little", signed=True) != game_date["value"]):
            return False
        records = record.get("records")
        groups = record.get("groups")
        type_guard = record.get("unit_type_guard")
        row_has_type_extension = (isinstance(records, list) and any(
            isinstance(row, Mapping) and ("unit_type" in row or "unit_type_proof" in row)
            for row in records
        ))
        enhanced = type_guard is not None or row_has_type_extension
        enhancement_profile: dict[str, Any] | None = None
        if enhanced:
            if type_key_enhancement is None or type(pass_index) is not int or pass_index not in (0, 1):
                return False
            header_ok, enhancement_profile = _type_enhancement_header_valid(type_key_enhancement)
            if not header_ok or not isinstance(type_guard, Mapping):
                return False
            runtime = type_key_enhancement.get("runtime_code_guard")
            passes = runtime.get("passes") if isinstance(runtime, Mapping) else None
            if not isinstance(passes, list) or len(passes) != 2:
                return False
            if (type_guard.get("schema") != TYPE_KEY_SCHEMA
                    or type_guard.get("version") != 1
                    or type_guard.get("profile_id") != EXPECTED_TYPE_PROFILE_ID
                    or type_guard.get("profile_sha256") != EXPECTED_TYPE_PROFILE_SHA256
                    or type_guard.get("profile_status") != type_key_enhancement.get("profile_status")
                    or type_guard.get("static_contract_guard") != type_key_enhancement.get("static_contract_guard")
                    or type_guard.get("file_code_guard") != type_key_enhancement.get("file_code_guard")
                    or type_guard.get("runtime_code_guard") != passes[pass_index]):
                return False
            runtime_state = _type_guard_code_state(
                type_guard.get("runtime_code_guard"),
                enhancement_profile or _minimal_type_profile_for_unknown(),
                module_base,
            )
            file_state = (_type_guard_code_state(
                type_guard.get("file_code_guard"), enhancement_profile,
            ) if enhancement_profile is not None else "unavailable")
            if runtime_state == "invalid" or file_state == "invalid":
                return False
            if type_guard.get("status") not in ("observed", "unknown"):
                return False
            global_reason = type_guard.get("reason")
            if global_reason is not None and global_reason not in _TYPE_KEY_GLOBAL_UNKNOWN_REASONS:
                return False
            if type_guard.get("status") == "observed":
                if (global_reason is not None or enhancement_profile is None
                        or runtime_state != "match" or file_state != "match"):
                    return False
            else:
                if global_reason not in _TYPE_KEY_GLOBAL_UNKNOWN_REASONS:
                    return False
                if global_reason == "UNIT_TYPE_PROFILE_INVALID" and enhancement_profile is not None:
                    return False
                if global_reason == "UNIT_TYPE_FILE_CODE_GUARD_MISMATCH" and file_state not in ("mismatch", "unavailable"):
                    return False
                if global_reason == "UNIT_TYPE_RUNTIME_CODE_GUARD_MISMATCH" and runtime_state not in ("mismatch", "unavailable"):
                    return False
        elif type_key_enhancement is not None or pass_index is not None:
            return False
        max_records = int(limits["max_records"])
        max_groups = int(limits["max_groups"])
        max_records_per_group = int(limits["max_records_per_group"])
        if (not isinstance(records, list) or not isinstance(groups, list) or
                len(records) != record.get("record_count") or len(groups) != record.get("group_count") or
                len(records) > max_records or len(groups) > max_groups):
            return False
        expected_pointers: list[str] = []
        seen_group_heads: set[str] = set()
        for group_index, group in enumerate(groups):
            if (not isinstance(group, Mapping) or type(group.get("vector_length")) is not int or
                    group.get("vector_length") < 0 or group.get("vector_length") > max_records_per_group or
                    not isinstance(group.get("record_pointers"), list) or
                    len(group["record_pointers"]) != group["vector_length"]):
                return False
            group_head = group.get("group_head")
            group_object = group.get("group_object")
            vector_begin = group.get("vector_begin")
            vector_end = group.get("vector_end")
            if any(not isinstance(value, str) for value in (group_head, group_object)):
                return False
            group_head_int = int(group_head, 0)
            group_object_int = int(group_object, 0)
            if (vector_begin is None) != (vector_end is None):
                return False
            vector_begin_int = 0 if vector_begin is None else int(vector_begin, 0)
            vector_end_int = 0 if vector_end is None else int(vector_end, 0)
            if (not _valid_address(group_head_int, layout) or group_head in seen_group_heads or
                    not _valid_address(group_object_int, layout) or
                    (vector_begin_int == 0) != (vector_end_int == 0) or
                    (vector_begin_int and (not _valid_address(vector_begin_int, layout) or not _valid_address(vector_end_int, layout) or vector_end_int < vector_begin_int or (vector_end_int - vector_begin_int) % layout["vector_entry_stride"] != 0 or (vector_end_int - vector_begin_int) // layout["vector_entry_stride"] != group["vector_length"]))):
                return False
            for raw_key, expected in (("group_head_raw_hex", group_head_int), ("group_object_raw_hex", group_object_int), ("vector_begin_raw_hex", vector_begin_int), ("vector_end_raw_hex", vector_end_int)):
                raw = group.get(raw_key)
                if not isinstance(raw, str) or len(raw) != 16 or int.from_bytes(bytes.fromhex(raw), "little", signed=False) != expected:
                    return False
            next_group = group.get("next_group_head")
            next_raw = group.get("next_group_head_raw_hex")
            if next_group is not None:
                if not isinstance(next_group, str) or not _valid_address(int(next_group, 0), layout) or not isinstance(next_raw, str) or len(next_raw) != 16 or int.from_bytes(bytes.fromhex(next_raw), "little", signed=False) != int(next_group, 0):
                    return False
            elif next_raw != "0000000000000000":
                return False
            seen_group_heads.add(group_head)
            expected_pointers.extend(group["record_pointers"])
        for index, group in enumerate(groups):
            expected_next = groups[index + 1]["group_head"] if index + 1 < len(groups) else None
            if group.get("next_group_head") != expected_next:
                return False
        if groups:
            if record.get("country_group_head") != groups[0].get("group_head"):
                return False
        elif record.get("country_group_head") is not None:
            return False
        group_head_raw = record.get("country_group_head_raw_hex")
        if not isinstance(group_head_raw, str) or len(group_head_raw) != 16 or int.from_bytes(bytes.fromhex(group_head_raw), "little", signed=False) != (int(record["country_group_head"], 0) if record.get("country_group_head") else 0):
            return False
        seen_ptrs: set[str] = set()
        seen_ids: set[tuple[int, int]] = set()
        for row_index, row in enumerate(records):
            if not isinstance(row, Mapping):
                return False
            ptr = row.get("record_pointer")
            identity = (row.get("id_type"), row.get("id"))
            kind, strength = row.get("type_kind"), row.get("strength_raw")
            body = row.get("record_body_raw_hex")
            if (not isinstance(ptr, str) or ptr in seen_ptrs or not _valid_address(int(ptr, 0), layout) or
                    type(row.get("id_type")) is not int or not 0 < row["id_type"] <= 0xFFFFFFFF or
                    type(row.get("id")) is not int or not 0 < row["id"] <= 0xFFFFFFFF or identity in seen_ids or
                    type(kind) is not int or not 0 <= kind <= 0x7FFFFFFF or type(strength) is not int or not 0 <= strength < (1 << 31) or
                    not isinstance(body, str) or len(body) != layout["record_body_size"] * 2 or any(c not in "0123456789abcdefABCDEF" for c in body) or
                    not isinstance(row.get("type_kind_raw_hex"), str) or len(row["type_kind_raw_hex"]) != 8 or
                    not isinstance(row.get("strength_raw_hex"), str) or len(row["strength_raw_hex"]) != 8):
                return False
            body_bytes = bytes.fromhex(body)
            if (row.get("id_type_raw_hex") != body_bytes[layout["record_id_type_offset"]:layout["record_id_type_offset"] + 4].hex()
                    or row.get("id_raw_hex") != body_bytes[layout["record_id_offset"]:layout["record_id_offset"] + 4].hex()
                    or row.get("strength_raw_hex") != body_bytes[layout["record_strength_offset"]:layout["record_strength_offset"] + 4].hex()
                    or int.from_bytes(bytes.fromhex(row["record_pointer_raw_hex"]), "little", signed=False) != int(ptr, 0)
                    or int.from_bytes(body_bytes[layout["record_type_offset"]:layout["record_type_offset"] + 8], "little", signed=False) != int(str(row.get("type_object")), 0)
                    or int.from_bytes(bytes.fromhex(row["id_type_raw_hex"]), "little", signed=False) != row["id_type"]
                    or int.from_bytes(bytes.fromhex(row["id_raw_hex"]), "little", signed=False) != row["id"]
                    or int.from_bytes(bytes.fromhex(row["strength_raw_hex"]), "little", signed=True) != strength
                    or int.from_bytes(bytes.fromhex(row["type_kind_raw_hex"]), "little", signed=True) != kind):
                return False
            type_object = int(str(row.get("type_object")), 0)
            if not _valid_address(type_object, layout):
                return False
            if row.get("group_index") != next((index for index, group in enumerate(groups) if ptr in group.get("record_pointers", [])), None):
                return False
            group_index = row.get("group_index")
            vector_index = row.get("vector_index")
            if (type(group_index) is not int or type(vector_index) is not int or group_index < 0 or group_index >= len(groups) or vector_index < 0 or vector_index >= len(groups[group_index]["record_pointers"]) or groups[group_index]["record_pointers"][vector_index] != ptr):
                return False
            if row_index != sum(len(groups[index]["record_pointers"]) for index in range(group_index)) + vector_index:
                return False
            if enhanced:
                unit_type = row.get("unit_type")
                proof = row.get("unit_type_proof")
                if not isinstance(unit_type, Mapping) or not isinstance(proof, Mapping):
                    return False
                if enhancement_profile is None:
                    if (type_guard.get("reason") != "UNIT_TYPE_PROFILE_INVALID"
                            or proof.get("reason") != "UNIT_TYPE_PROFILE_INVALID"
                            or proof.get("status") != "unknown"
                            or proof.get("profile_id") != EXPECTED_TYPE_PROFILE_ID
                            or proof.get("profile_sha256") != EXPECTED_TYPE_PROFILE_SHA256
                            or proof.get("type_object") != row.get("type_object")
                            or proof.get("read_log") != []
                            or unit_type != {"status": "unknown", "reason": "UNIT_TYPE_PROFILE_INVALID"}):
                        return False
                else:
                    if not _unit_type_proof_valid(row, unit_type, proof,
                                                  enhancement_profile, module_base):
                        return False
                    global_reason = type_guard.get("reason")
                    if global_reason is not None and (
                        unit_type != {"status": "unknown", "reason": global_reason}
                        or proof.get("reason") != global_reason
                    ):
                        return False
                for existing in records[:row_index]:
                    if (isinstance(existing, Mapping)
                            and existing.get("type_object") == row.get("type_object")
                            and (existing.get("unit_type") != unit_type
                                 or _type_proof_signature(existing.get("unit_type_proof"))
                                 != _type_proof_signature(proof))):
                        return False
            seen_ptrs.add(ptr); seen_ids.add(identity)
        if expected_pointers != [row.get("record_pointer") for row in records]:
            return False
        fields = record.get("fields")
        public_records = [
            {key: value for key, value in row.items() if key != "unit_type_proof"}
            if enhanced and isinstance(row, Mapping) else row
            for row in records
        ]
        if (not isinstance(fields, Mapping) or set(fields) != {FIELD_KEY} or not isinstance(fields[FIELD_KEY], Mapping) or
                fields[FIELD_KEY].get("status") != "known" or fields[FIELD_KEY].get("complete") is not False or
                fields[FIELD_KEY].get("partial") is not True or fields[FIELD_KEY].get("value") != public_records or
                fields[FIELD_KEY].get("unit") != UNIT or fields[FIELD_KEY].get("scale") != SCALE or
                fields[FIELD_KEY].get("period") != PERIOD or fields[FIELD_KEY].get("basis") != BASIS):
            return False
        observation = record.get("observation")
        if (not isinstance(observation, Mapping) or observation.get("profile_id") != EXPECTED_PROFILE_ID or observation.get("module_base") != record.get("module_base") or observation.get("country_pointer") != record.get("country_pointer")):
            return False
        budget = observation.get("read_budget"); logs = observation.get("read_log")
        if (not isinstance(budget, Mapping) or budget.get("limit") != READ_BUDGET_BYTES or type(budget.get("bytes_reserved")) is not int or budget["bytes_reserved"] < 0 or not isinstance(logs, list) or sum(int(item.get("size", 0)) for item in logs if isinstance(item, Mapping)) != budget["bytes_reserved"] or any(not isinstance(item, Mapping) or type(item.get("size")) is not int or item.get("size") <= 0 or (item.get("status") != "ok" and not (enhanced and item.get("status") == "failed" and isinstance(item.get("label"), str) and item["label"].startswith("country_forces.unit_type.type["))) for item in logs)):
            return False
        if enhanced:
            type_log_entries = [item for item in logs if isinstance(item, Mapping)
                                and isinstance(item.get("label"), str)
                                and item["label"].startswith("country_forces.unit_type.type[")]
            for entry in type_log_entries:
                if not _unit_type_read_log_valid([entry], _type_profile_layout(
                        enhancement_profile or _minimal_type_profile_for_unknown())):
                    return False
            recorded_proofs: dict[str, Mapping[str, Any]] = {}
            for row in records:
                proof = row.get("unit_type_proof")
                if isinstance(proof, Mapping) and proof.get("read_log"):
                    key = str(row.get("type_object"))
                    recorded_proofs[key] = proof
            all_log_signatures = {json.dumps(item, sort_keys=True) for item in type_log_entries}
            for proof in recorded_proofs.values():
                if any(json.dumps(item, sort_keys=True) not in all_log_signatures
                       for item in proof.get("read_log", [])):
                    return False
        return True
    except Exception:
        return False


def validate_capture(report: Any, context: Mapping[str, Any] | None, creation_filetime: int, country: str = EXPECTED_COUNTRY) -> bool:
    """Validate identity, fixed date, cleanup, and raw two-pass equality."""
    if (not isinstance(report, Mapping) or report.get("status") != "observed" or report.get("completed") is not True
            or report.get("country") != country or not isinstance(country, str)
            or re.fullmatch(r"[A-Z0-9]{3}", country) is None or report.get("read_only") is not True):
        return False
    identity = report.get("identity")
    request = report.get("request")
    cleanup = report.get("cleanup", {}).get("handle_close") if isinstance(report.get("cleanup"), Mapping) else None
    access = report.get("access")
    double = report.get("doublepass")
    if (not isinstance(identity, Mapping) or not isinstance(request, Mapping) or identity.get("binding_verified") is not True or identity.get("process_creation_matches_installation") is not True or identity.get("process_path_sha256_matches_expected") is not True or str(identity.get("process_path_sha256", "")).lower() != EXPECTED_EXE_SHA256 or cleanup != {"status": "closed", "success": True, "closed": True} or not isinstance(access, Mapping) or access.get("native_game_calls") is not False or access.get("target_memory_writes") is not False or access.get("mcp_query") is not False or not isinstance(double, Mapping) or double.get("performed") is not True or double.get("consistent") is not True or type(access.get("rpm_bytes_requested")) is not int or access.get("rpm_bytes_requested") > MAX_TOTAL_RPM):
        return False
    if (request.get("country") != country or request.get("installation") != identity.get("installation_path") or
            request.get("pid") != identity.get("installation_pid") or
            request.get("creation_filetime") != identity.get("installation_creation_filetime") or
            request.get("session_id") != identity.get("installation_session_id") or
            str(request.get("game_sha256", "")).lower() != EXPECTED_EXE_SHA256):
        return False
    if type(creation_filetime) is not int or identity.get("installation_creation_filetime") != creation_filetime or identity.get("process_creation_filetime") != creation_filetime:
        return False
    if (not isinstance(context, Mapping) or type(context.get("game_date")) is not int
            or context.get("observer", country) != country):
        return False
    expected_session = context.get("session_id", context.get("installation_session_id"))
    if expected_session is not None and identity.get("installation_session_id") != expected_session:
        return False
    expected_sha = context.get("game_sha256", context.get("expected_exe_sha256"))
    if expected_sha is not None and str(expected_sha).lower() != EXPECTED_EXE_SHA256:
        return False
    before, after = report.get("before"), report.get("after")
    if (not isinstance(before, Mapping) or not isinstance(after, Mapping)
            or not isinstance(before.get("record"), Mapping)
            or not isinstance(after.get("record"), Mapping)):
        return False
    enhancement = report.get("type_key_enhancement")
    before_record, after_record = before["record"], after["record"]
    carries_type_data = False
    for record in (before_record, after_record):
        rows = record.get("records")
        carries_type_data = carries_type_data or isinstance(record.get("unit_type_guard"), Mapping)
        if isinstance(rows, list):
            carries_type_data = carries_type_data or any(
                isinstance(row, Mapping) and ("unit_type" in row or "unit_type_proof" in row)
                for row in rows
            )
    if enhancement is None:
        if (carries_type_data or not validate_record(before_record, country=country)
                or not validate_record(after_record, country=country)):
            return False
    else:
        header_ok, _profile = _type_enhancement_header_valid(enhancement)
        if (not header_ok
                or not validate_record(before_record, country=country, type_key_enhancement=enhancement, pass_index=0)
                or not validate_record(after_record, country=country, type_key_enhancement=enhancement, pass_index=1)):
            return False
        before_rows = before_record.get("records")
        after_rows = after_record.get("records")
        if not isinstance(before_rows, list) or not isinstance(after_rows, list) or len(before_rows) != len(after_rows):
            return False
        pass_consistent = True
        any_unknown = False
        for left, right in zip(before_rows, after_rows):
            if not isinstance(left, Mapping) or not isinstance(right, Mapping):
                return False
            left_proof, right_proof = left.get("unit_type_proof"), right.get("unit_type_proof")
            left_unit, right_unit = left.get("unit_type"), right.get("unit_type")
            if not isinstance(left_proof, Mapping) or not isinstance(right_proof, Mapping):
                return False
            proofs_equal = _type_proof_signature(left_proof) == _type_proof_signature(right_proof)
            if proofs_equal:
                if left_unit != right_unit:
                    return False
            else:
                pass_consistent = False
                changed = {"status": "unknown", "reason": "UNIT_TYPE_CHANGED_BETWEEN_PASSES"}
                if left_unit != changed or right_unit != changed:
                    return False
            any_unknown = any_unknown or not isinstance(left_unit, Mapping) or left_unit.get("status") != "known"
        if enhancement.get("cross_pass_consistent") is not pass_consistent:
            return False
        before_reason = before_record.get("unit_type_guard", {}).get("reason")
        after_reason = after_record.get("unit_type_guard", {}).get("reason")
        if before_reason != after_reason:
            return False
        expected_status = (
            "unknown" if before_reason is not None
            else "partial" if any_unknown or not pass_consistent
            else "observed"
        )
        if enhancement.get("status") != expected_status:
            return False
        for outer, record in ((before, before_record), (after, after_record)):
            if (outer.get("unit_type_guard") != record.get("unit_type_guard")
                    or outer.get("records") != record.get("records")):
                return False
    if _diff_paths(_stable_record_for_comparison(before["record"]),
                   _stable_record_for_comparison(after["record"])):
        return False
    before_date = before["record"].get("game_date")
    after_date = after["record"].get("game_date")
    before_date_value = before_date.get("value") if isinstance(before_date, Mapping) else None
    after_date_value = after_date.get("value") if isinstance(after_date, Mapping) else None
    if (before.get("status") != "observed" or after.get("status") != "observed" or
            before.get("country_pointer") != after.get("country_pointer") or
            before.get("country_handle") != after.get("country_handle") or
            not dates_match(before_date_value, after_date_value) or
            not dates_match(context.get("game_date"), before_date_value, after_date_value)):
        return False
    if (report.get("module_base") != before["record"].get("module_base") or report.get("module_base") != after["record"].get("module_base") or
            report.get("country_pointer") != before.get("country_pointer") or report.get("country_pointer") != after.get("country_pointer") or
            report.get("fields") != after.get("fields") or report.get("values") != after.get("values") or report.get("raw_hex") != after.get("raw_hex")):
        return False
    for outer in (before, after):
        record = outer["record"]
        if (outer.get("country_pointer") != record.get("country_pointer") or
                outer.get("country_handle") != record.get("country_handle") or
                outer.get("game_date") != record.get("game_date") or
                outer.get("records") != record.get("records") or
                outer.get("groups") != record.get("groups")):
            return False
    report_scan = report.get("country_scan")
    if (not isinstance(report_scan, Mapping) or report_scan.get("before") != before.get("country_scan") or
            report_scan.get("after") != after.get("country_scan") or
            report_scan.get("before", {}).get("country_pointer") != before.get("country_pointer") or
            report_scan.get("after", {}).get("country_pointer") != after.get("country_pointer")):
        return False
    return True


def retract_record(record: Any, reason: str = "observation_retracted") -> dict[str, Any]:
    result = _unknown_record(reason)
    if isinstance(record, Mapping):
        for key in ("profile_id", "profile_sha256", "module_base", "country_pointer", "basis", "unit", "scale", "period", "value_origin"):
            if key in record:
                result[key] = _copy_json(record[key])
    return result


__all__ = [
    "PROFILE_FILE", "PROFILE_MAX_BYTES", "EXPECTED_PROFILE_SHA256", "EXPECTED_PROFILE_ID", "EXPECTED_EXE_SHA256", "EXPECTED_VERSION", "EXPECTED_COUNTRY", "FIELDS", "FIELD_KEY", "BASIS", "VALUE_ORIGIN", "UNIT", "SCALE", "PERIOD", "PARTIAL", "MAX_SINGLE_RPM", "MAX_TOTAL_RPM", "READ_BUDGET_BYTES", "ProfileError", "ReadError", "ProbeError", "AddressBoundedRPM", "read_fields", "capture", "validate_record", "validate_capture", "retract_record", "_load_profile", "_prepare_profile", "_profile_layout", "_profile_code_guards", "_static_contract_guard", "_file_code_guard", "_runtime_code_guard", "_ReadBudget", "_find_country", "_snapshot",
]
