"""Bounded read-only country sailors and force-limit observation.

This reader only follows the pinned 1.37.4 country table and reads the raw
country fields used by the native text/force-limit helpers.  It never calls a
game function, sends an MCP query, or writes target memory.  Addresses and
the modifier/processor graph are retained under ``record.private`` for
validation; consumers should use ``record.fields`` only.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
from typing import Any, Mapping

from . import country_resources_memory as _crm
from . import localization_memory as _loc
from . import mission_memory as _mm
from .observation_time import dates_match, without_clock


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "military-resources-memory-1374-sampling-r1.json"
PROFILE_MAX_BYTES = 64 * 1024
EXPECTED_PROFILE_SHA256 = "500501502e995442ce5c6e0d6323f69318372cd9d9aef6ac5d8fcd9ee36e7a99"
EXPECTED_PROFILE_ID = "military-resources-memory-1374"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_VERSION = "1.37.4"
EXPECTED_COUNTRY = "FRA"

FIELDS = ("sailors", "force_limits")
SAILORS_FIELD = "sailors"
FORCE_FIELD = "force_limits"
MAX_SINGLE_RPM = 65_536
MAX_TOTAL_RPM = 1 * 1024 * 1024
READ_BUDGET_BYTES = MAX_TOTAL_RPM
MAX_USER_ADDRESS = _mm.MAX_USER_ADDRESS
PROCESS_ACCESS = _mm.PROCESS_ACCESS
I32_MIN = -(1 << 31)
I32_MAX = (1 << 31) - 1
FORCE_IDS = (54, 55, 56, 57)
FORCE_KINDS = {
    54: ("land", "base"),
    55: ("naval", "base"),
    56: ("land", "factor"),
    57: ("naval", "factor"),
}
FORCE_UNITS = {"land": "regiments", "naval": "ships"}

AddressBoundedRPM = _crm.AddressBoundedRPM
ProbeError = _crm.ProbeError
_load_installation = _loc._load_installation
_configure_kernel = _loc._configure_kernel
_capture_identity = _loc._capture_identity
_close_process_handle = _loc._close_process_handle
_read_pe_rva_bytes = _mm._read_pe_rva_bytes


class ProfileError(RuntimeError):
    """The pinned profile or source evidence is invalid."""


class ReadError(RuntimeError):
    """A bounded read or fail-closed contract check failed."""


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
        historical_python = path.suffix == ".py"
        if not historical_python:
            raw = _bounded_file(path, 256 * 1024, "source_evidence")
            actual = hashlib.sha256(raw).hexdigest()
            if len(raw) != size or actual.lower() != digest.lower():
                raise ProfileError(f"source_evidence_sha256_mismatch:{relative}")
        seen.add(key)
        result.append({
            "path": path.relative_to(root).as_posix(),
            "sha256": digest.lower(),
            "bytes": size,
            "role": item.get("role"),
            "verification": "historical_reference" if historical_python else "current_file_hash",
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
        "sailors_offset": 0xDC0,
        "force_cache_state_offset": 0x28C8,
        "force_modifier_offset": 0x28D0,
        "modifier_dense_flag_offset": 0x10,
        "modifier_values_pointer_offset": 0x58,
        "modifier_sparse_count_offset": 0x64,
        "modifier_sparse_stride": 8,
        "processor_manager_rva": 0x2358060,
        "processor_stride": 0x60,
        "processor_offset": 0x40,
        "pointer_min": 0x10000,
        "pointer_max": MAX_USER_ADDRESS,
    }
    result: dict[str, int] = {}
    for key, expected_value in expected.items():
        value = _parse_int(raw.get(key), f"layout.{key}")
        if value != expected_value:
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
        expected_sha = hashlib.sha256(raw).hexdigest()
        if (not raw or end != begin + len(raw) or expected_sha != str(item.get("sha256", "")).lower() or
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
    if not isinstance(executable, Mapping) or str(executable.get("sha256", "")).lower() != EXPECTED_EXE_SHA256:
        raise ProfileError("profile_executable_mismatch")
    _source_evidence(profile)
    _profile_layout(profile)
    limits = profile.get("limits")
    if not isinstance(limits, Mapping):
        raise ProfileError("profile_limits_invalid")
    for key, expected in {
        "max_total_rpm": MAX_TOTAL_RPM,
        "max_single_rpm": MAX_SINGLE_RPM,
        "max_country_slots": 4096,
        "max_sparse_entries": 4096,
    }.items():
        if _parse_int(limits.get(key), f"limits.{key}") != expected:
            raise ProfileError(f"profile_limits_invalid:{key}")
    semantics = profile.get("semantics")
    if (not isinstance(semantics, Mapping) or semantics.get("sailors_field") != SAILORS_FIELD or
            semantics.get("force_limits_field") != FORCE_FIELD or semantics.get("sailors_unit") != "sailors" or
            semantics.get("force_scale") != 1000 or semantics.get("force_sailors_period") != "current" or
            semantics.get("force_modifier_storage") != "inline"):
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


def _static_contract_guard(profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown", "evidence_kind": "ordinary_static_source_pins_plus_bounded_rpm",
        "profile": str(PROFILE_FILE), "profile_id": EXPECTED_PROFILE_ID,
        "profile_sha256": EXPECTED_PROFILE_SHA256, "source_evidence": [], "checks": {},
        "unknown_conditions": [],
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
            "country_layout": layout["database_global_rva"] == 0x233D8B0 and layout["country_fullref_offset"] == 0x20,
            "sailors_offset": layout["sailors_offset"] == 0xDC0,
            "force_cache_layout": layout["force_cache_state_offset"] == 0x28C8 and layout["force_modifier_offset"] == 0x28D0,
            "processor_layout": layout["processor_manager_rva"] == 0x2358060 and layout["processor_stride"] == 0x60 and layout["processor_offset"] == 0x40,
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


def _read_u8(reader: Any, address: int, label: str, budget: _ReadBudget, layout: Mapping[str, int]) -> tuple[int, bytes]:
    raw = _reader_read(reader, address, 1, label, budget, layout)
    return raw[0], raw


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
            raw = method(address, len(expected), f"military_resources.code.{name}")
            if not isinstance(raw, (bytes, bytearray)) or len(raw) != len(expected):
                raise ReadError(f"code_guard_short:{name}")
            raw = bytes(raw)
            budget.reads.append({"address": _hex(address), "size": len(expected), "label": f"military_resources.code.{name}", "status": "ok", "raw_hex": raw.hex(), "sha256": hashlib.sha256(raw).hexdigest()})
            result["records"][name] = {"rva": hex(rva), "rva_end_exclusive": hex(end), "address": _hex(address), "expected_hex": expected.hex(), "actual_hex": raw.hex(), "expected_sha256": hashlib.sha256(expected).hexdigest(), "actual_sha256": hashlib.sha256(raw).hexdigest()}
            result["checks"][name] = raw == expected
        if result["checks"] and all(result["checks"].values()):
            result["status"] = "observed"
        else:
            result["unknown_conditions"].append("runtime_code_guard_mismatch")
    except Exception as exc:
        result["unknown_conditions"].append(f"runtime_code_guard_failed:{type(exc).__name__}:{exc}")
    result["bytes_reserved"] = sum(int(item.get("size", 0)) for item in budget.reads if item.get("label", "").startswith("military_resources.code."))
    return result


def _tag_from_fullref(value: int) -> str | None:
    raw = (value & 0xFFFFFF).to_bytes(3, "little")
    if not all(0x41 <= byte <= 0x5A for byte in raw):
        return None
    return raw.decode("ascii")


def _find_country(reader: Any, module_base: int, country: str, profile: Mapping[str, Any], budget: _ReadBudget) -> tuple[int, dict[str, Any]]:
    if country != EXPECTED_COUNTRY:
        raise ReadError("unsupported_country")
    layout = _profile_layout(profile)
    database, database_raw = _read_u64(reader, _add_address(module_base, layout["database_global_rva"], layout), "military_resources.database", budget, layout)
    if not _valid_address(database, layout):
        raise ReadError("country_database_invalid")
    table, table_raw = _read_u64(reader, _add_address(database, layout["database_table_offset"], layout), "military_resources.country_table", budget, layout)
    if not _valid_address(table, layout):
        raise ReadError("country_table_invalid")
    count, count_raw = _read_i32(reader, _add_address(database, layout["database_table_count_offset"], layout), "military_resources.country_count", budget, layout)
    if not 1 <= count <= int(profile["limits"]["max_country_slots"]):
        raise ReadError("country_count_invalid")
    matches: list[dict[str, Any]] = []
    for slot in range(count):
        ptr, ptr_raw = _read_u64(reader, _add_address(table, slot * 8, layout), f"military_resources.country_table[{slot}]", budget, layout)
        if not ptr:
            continue
        if not _valid_address(ptr, layout):
            raise ReadError("country_pointer_invalid")
        fullref, fullref_raw = _read_u64(reader, _add_address(ptr, layout["country_fullref_offset"], layout), f"military_resources.country_fullref[{slot}]", budget, layout)
        tag = _tag_from_fullref(fullref)
        if tag == country and ((fullref >> 32) & 0xFFFF) == slot:
            matches.append({"slot": slot, "pointer": _hex(ptr), "table_entry_raw_hex": ptr_raw.hex(), "fullref_raw_hex": fullref_raw.hex(), "tag": tag, "country_handle": _hex(fullref), "country_handle_raw_hex": fullref_raw.hex()})
    if len(matches) != 1:
        raise ReadError("country_identity_match_count_invalid")
    match = matches[0]
    return int(match["pointer"], 0), {"status": "observed", "database": _hex(database), "database_raw_hex": database_raw.hex(), "table_pointer": _hex(table), "table_raw_hex": table_raw.hex(), "country_count": count, "country_count_raw_hex": count_raw.hex(), "matches": matches, "country_pointer": match["pointer"], "country_handle": match["country_handle"], "country_handle_raw_hex": match["country_handle_raw_hex"]}


def _trunc_div(value: int, divisor: int) -> int:
    if divisor <= 0:
        raise ValueError("divisor must be positive")
    sign = -1 if value < 0 else 1
    return sign * (abs(value) // divisor)


def _float32(value: float) -> float:
    """Round one scalar as the native ``divss``/``mulss`` path does."""
    return struct.unpack("<f", struct.pack("<f", value))[0]


def _native_display_value(raw: int) -> int:
    # The formatter first executes cvtdq2ps, then scalar-single divide by
    # 1000.0, multiplies by the presentation multiplier (1 for sailors), and
    # executes cvttss2si.  Keeping each operation at float32 matters near the
    # 24-bit mantissa boundary.
    scaled = _float32(_float32(float(raw)) / _float32(1000.0))
    scaled = _float32(scaled * _float32(1.0))
    return int(scaled)


def _i32(value: int, label: str) -> int:
    if type(value) is not int or value < I32_MIN or value > I32_MAX:
        raise ReadError(f"{label}_outside_i32")
    return value


def _read_modifier_values(reader: Any, country_pointer: int, profile: Mapping[str, Any], budget: _ReadBudget) -> tuple[dict[int, int], dict[str, Any]]:
    layout = _profile_layout(profile)
    # The country accessor returns an inline modifier-cache object at +0x28d0.
    # Its first qword is part of the header (and resembles a vtable pointer); it
    # is not an indirection to another modifier object.
    modifier_address = _add_address(country_pointer, layout["force_modifier_offset"], layout)
    header = _reader_read(reader, modifier_address, 0x68, "military_resources.modifier_header", budget, layout)
    dense_flag = header[layout["modifier_dense_flag_offset"]]
    if dense_flag not in (0, 1):
        raise ReadError("modifier_dense_flag_invalid")
    values_pointer = int.from_bytes(header[layout["modifier_values_pointer_offset"]:layout["modifier_values_pointer_offset"] + 8], "little", signed=False)
    sparse_count = int.from_bytes(header[layout["modifier_sparse_count_offset"]:layout["modifier_sparse_count_offset"] + 4], "little", signed=True)
    if sparse_count < 0 or sparse_count > int(profile["limits"]["max_sparse_entries"]):
        raise ReadError("modifier_sparse_count_invalid")
    if sparse_count and not _valid_address(values_pointer, layout):
        raise ReadError("modifier_values_pointer_invalid")
    raw_ids: dict[str, dict[str, Any]] = {}
    values: dict[int, int] = {}
    sparse_entries: list[dict[str, Any]] = []
    if dense_flag:
        if not _valid_address(values_pointer, layout):
            raise ReadError("modifier_dense_values_pointer_invalid")
        for ident in FORCE_IDS:
            address = _add_address(values_pointer, ident * 8 + 4, layout)
            value, raw = _read_i32(reader, address, f"military_resources.modifier.dense[{ident}]", budget, layout)
            values[ident] = value
            raw_ids[str(ident)] = {"id": ident, "storage": "dense", "address": _hex(address), "raw_hex": raw.hex(), "value_raw": value}
    else:
        entries_address = values_pointer
        for index in range(sparse_count):
            address = _add_address(entries_address, index * layout["modifier_sparse_stride"], layout)
            entry = _reader_read(reader, address, layout["modifier_sparse_stride"], f"military_resources.modifier.sparse[{index}]", budget, layout)
            key = int.from_bytes(entry[:4], "little", signed=False)
            value = int.from_bytes(entry[4:8], "little", signed=True)
            sparse_entries.append({"index": index, "address": _hex(address), "raw_hex": entry.hex(), "key": key, "value_raw": value})
            if key in FORCE_IDS and key not in values:
                values[key] = value
                raw_ids[str(key)] = {"id": key, "storage": "sparse", "address": _hex(address + 4), "raw_hex": entry[4:8].hex(), "value_raw": value, "first_match_index": index}
        for ident in FORCE_IDS:
            if ident not in values:
                values[ident] = 0
                raw_ids[str(ident)] = {"id": ident, "storage": "sparse", "address": None, "raw_hex": "00000000", "value_raw": 0, "first_match_index": None}
    private = {"storage": "inline", "object_address": _hex(modifier_address), "header_raw_hex": header.hex(), "header_bytes": len(header), "dense_flag": dense_flag, "dense_flag_raw_hex": header[layout["modifier_dense_flag_offset"]:layout["modifier_dense_flag_offset"] + 1].hex(), "values_pointer": _hex(values_pointer) if values_pointer else None, "values_pointer_raw_hex": header[layout["modifier_values_pointer_offset"]:layout["modifier_values_pointer_offset"] + 8].hex(), "sparse_count": sparse_count, "sparse_count_raw_hex": header[layout["modifier_sparse_count_offset"]:layout["modifier_sparse_count_offset"] + 4].hex(), "mode": "dense" if dense_flag else "sparse", "ids": raw_ids, "sparse_entries": sparse_entries}
    return values, private


def _read_processors(reader: Any, module_base: int, profile: Mapping[str, Any], budget: _ReadBudget) -> tuple[dict[int, int | None], dict[str, Any]]:
    layout = _profile_layout(profile)
    manager_cell = _add_address(module_base, layout["processor_manager_rva"], layout)
    manager, manager_raw = _read_u64(reader, manager_cell, "military_resources.processor_manager", budget, layout)
    if not _valid_address(manager, layout):
        raise ReadError("processor_manager_invalid")
    pointers: dict[int, int | None] = {}
    rows: dict[str, Any] = {}
    for ident in FORCE_IDS:
        slot_address = _add_address(manager, ident * layout["processor_stride"] + layout["processor_offset"], layout)
        pointer, pointer_raw = _read_u64(reader, slot_address, f"military_resources.processor[{ident}]", budget, layout)
        if pointer and not _valid_address(pointer, layout):
            raise ReadError("processor_pointer_invalid")
        pointers[ident] = pointer or None
        rows[str(ident)] = {"id": ident, "slot_address": _hex(slot_address), "slot_raw_hex": pointer_raw.hex(), "processor_pointer": _hex(pointer) if pointer else None, "processor_pointer_raw_hex": pointer_raw.hex(), "status": "absent" if not pointer else "unsupported_nonnull"}
    return pointers, {"manager_global_rva": hex(layout["processor_manager_rva"]), "manager_global_address": _hex(manager_cell), "manager_pointer": _hex(manager), "manager_pointer_raw_hex": manager_raw.hex(), "slots": rows}


def _unknown_force(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason, "value": None, "complete": False, "partial": False}


def _force_value(kind: str, base: int, percentage: int) -> dict[str, Any]:
    base = _i32(base, f"{kind}_base")
    percentage = _i32(percentage, f"{kind}_percentage")
    factor = _i32(1000 + percentage, f"{kind}_factor")
    product = base * factor
    rescaled = _trunc_div(product, 1000)
    rescaled = _i32(rescaled, f"{kind}_rescaled")
    rounded = _trunc_div(rescaled, 1000) * 1000
    if rounded < 1000:
        rounded = 1000
    rounded = _i32(rounded, f"{kind}_rounded")
    count = rounded // 1000
    return {"status": "known", "value": count, "raw": rounded, "raw_hex": int(rounded).to_bytes(4, "little", signed=True).hex(), "unit": FORCE_UNITS[kind], "scale": 1000, "period": "current", "complete": True, "partial": False, "basis": "native_force_limit_getter_numeric_path"}


def _force_field(values: Mapping[int, int], processors: Mapping[int, int | None]) -> tuple[dict[str, Any], dict[str, Any]]:
    value: dict[str, Any] = {}
    errors: dict[str, Any] = {}
    for kind in ("land", "naval"):
        ids = (54, 56) if kind == "land" else (55, 57)
        if any(processors.get(ident) is not None for ident in ids):
            item = _unknown_force("DYNAMIC_FORCE_LIMIT_PROCESSOR_UNSUPPORTED")
            errors[kind] = item["reason"]
        else:
            try:
                item = _force_value(kind, values.get(ids[0], 0), values.get(ids[1], 0))
            except ReadError as exc:
                item = _unknown_force(str(exc))
                errors[kind] = str(exc)
        value[kind] = item
    return {"status": "partial", "value": value, "unit": "mixed", "scale": 1000, "period": "current", "basis": "native_force_limit_getter_numeric_path", "complete": False, "partial": True, "unknown_conditions": errors}, {"field_errors": errors}


def _sailors_field(raw: int, raw_hex: str) -> dict[str, Any]:
    raw = _i32(raw, "sailors_raw")
    if raw < 0:
        raise ReadError("sailors_negative")
    return {"status": "known", "value": raw, "raw": raw, "raw_hex": raw_hex, "display_value": _native_display_value(raw), "unit": "sailors", "scale": 1000, "period": "current", "basis": "native_country_current_sailors_raw_field", "complete": True, "partial": False}


def _snapshot(reader: Any, module_base: int, country: str, profile: Mapping[str, Any], static_guard: Mapping[str, Any], budget: _ReadBudget, country_pointer: int | None = None, country_scan: Mapping[str, Any] | None = None) -> dict[str, Any]:
    layout = _profile_layout(profile)
    start_used = budget.used
    start_log = len(budget.reads)
    runtime_guard = _runtime_code_guard(reader, module_base, profile, budget)
    if runtime_guard.get("status") != "observed":
        raise ReadError("runtime_code_guard_failed")
    game, game_raw = _read_u64(reader, _add_address(module_base, layout["game_global_rva"], layout), "military_resources.game", budget, layout)
    if not _valid_address(game, layout):
        raise ReadError("game_pointer_invalid")
    date_raw = _reader_read(reader, _add_address(game, layout["game_date_offset"], layout), 4, "military_resources.game_date", budget, layout)
    game_date = int.from_bytes(date_raw, "little", signed=True)
    if country_pointer is None:
        country_pointer, country_scan = _find_country(reader, module_base, country, profile, budget)
    if not _valid_address(country_pointer, layout):
        raise ReadError("country_pointer_invalid")
    handle, handle_raw = _read_u64(reader, _add_address(country_pointer, layout["country_fullref_offset"], layout), "military_resources.country_handle", budget, layout)
    if _tag_from_fullref(handle) != country:
        raise ReadError("country_handle_tag_mismatch")
    sailors_raw, sailors_bytes = _read_i32(reader, _add_address(country_pointer, layout["sailors_offset"], layout), "military_resources.sailors", budget, layout)
    sailors = _sailors_field(sailors_raw, sailors_bytes.hex())
    cache_state, cache_state_raw = _read_i32(reader, _add_address(country_pointer, layout["force_cache_state_offset"], layout), "military_resources.force_cache_state", budget, layout)
    force_private: dict[str, Any] = {"cache_state": {"value": cache_state, "raw_hex": cache_state_raw.hex()}, "modifier": None, "processors": None}
    if cache_state == 1:
        force = {"status": "partial", "value": {"land": _unknown_force("FORCE_LIMIT_CACHE_CALCULATING"), "naval": _unknown_force("FORCE_LIMIT_CACHE_CALCULATING")}, "unit": "mixed", "scale": 1000, "period": "current", "basis": "native_force_limit_getter_numeric_path", "complete": False, "partial": True, "unknown_conditions": {"cache": "FORCE_LIMIT_CACHE_CALCULATING"}}
    else:
        try:
            values, modifier_private = _read_modifier_values(reader, country_pointer, profile, budget)
            processors, processor_private = _read_processors(reader, module_base, profile, budget)
            force, field_private = _force_field(values, processors)
            force_private.update({"modifier": modifier_private, "processors": processor_private, "values": {str(key): value for key, value in values.items()}, "field": field_private})
        except ReadError as exc:
            force = {"status": "partial", "value": {"land": _unknown_force(str(exc)), "naval": _unknown_force(str(exc))}, "unit": "mixed", "scale": 1000, "period": "current", "basis": "native_force_limit_getter_numeric_path", "complete": False, "partial": True, "unknown_conditions": {"read": str(exc)}}
            force_private["error"] = str(exc)
    fields = {SAILORS_FIELD: sailors, FORCE_FIELD: force}
    private = {
        "module_base": _hex(module_base), "game_pointer": _hex(game), "game_pointer_raw_hex": game_raw.hex(),
        "country_pointer": _hex(country_pointer), "country_handle": _hex(handle), "country_handle_raw_hex": handle_raw.hex(),
        "game_date": {"value": game_date, "raw_hex": date_raw.hex()}, "country_scan": _copy_json(country_scan) if country_scan is not None else {"status": "synthetic", "country_pointer": _hex(country_pointer), "country_handle": _hex(handle), "country_handle_raw_hex": handle_raw.hex()},
        "force": force_private, "static_contract_guard": _copy_json(static_guard), "runtime_code_guard": _copy_json(runtime_guard),
    }
    read_log = _copy_json(budget.reads[start_log:])
    record = {
        "status": "observed", "profile_id": EXPECTED_PROFILE_ID, "profile_sha256": EXPECTED_PROFILE_SHA256,
        "country": country, "fields": _copy_json(fields), "complete": False, "partial": True,
        "private": private,
        "observation": {"profile_id": EXPECTED_PROFILE_ID, "profile_sha256": EXPECTED_PROFILE_SHA256, "module_base": _hex(module_base), "country_pointer": _hex(country_pointer), "country_handle": _hex(handle), "game_date": game_date, "read_budget": {"bytes_reserved": budget.used - start_used, "limit": READ_BUDGET_BYTES}, "read_log": read_log},
    }
    return {"status": "observed", "country": country, "record": record, "private": _copy_json(private), "fields": _copy_json(fields), "values": {SAILORS_FIELD: sailors["value"], FORCE_FIELD: _copy_json(force["value"])}, "raw_hex": {SAILORS_FIELD: sailors["raw_hex"], FORCE_FIELD: {key: (item.get("raw_hex") if isinstance(item, Mapping) and item.get("status") == "known" else None) for key, item in force["value"].items()}}, "complete": False, "partial": True, "read_budget": {"bytes_reserved": budget.used - start_used, "limit": READ_BUDGET_BYTES}, "read_log": read_log}


def _unknown_record(reason: str, module_base: int | None = None, country_pointer: int | None = None, country: str = EXPECTED_COUNTRY) -> dict[str, Any]:
    fields = {name: {"status": "unknown", "reason": reason, "complete": False, "partial": True} for name in FIELDS}
    return {"status": "unknown", "country": country, "record": {"status": "unknown", "profile_id": EXPECTED_PROFILE_ID, "profile_sha256": EXPECTED_PROFILE_SHA256, "fields": fields, "complete": False, "partial": True, "private": {"module_base": _hex(module_base), "country_pointer": _hex(country_pointer), "reason": reason}}, "fields": fields, "values": None, "raw_hex": None, "complete": False, "partial": True, "error": reason}


def read_fields(reader: Any, module_base: int, country_pointer: int, country: str = EXPECTED_COUNTRY, profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Read a synthetic/live bounded reader at a previously resolved country pointer."""
    try:
        loaded = _load_profile() if profile is None else _prepare_profile(profile)
        layout = _profile_layout(loaded)
        if country != EXPECTED_COUNTRY or not _valid_address(module_base, layout) or not _valid_address(country_pointer, layout):
            raise ReadError("unsupported_country_or_pointer")
        static_guard = _static_contract_guard(loaded)
        if static_guard.get("status") != "observed":
            raise ReadError("static_contract_guard_failed")
        return _snapshot(reader, module_base, country, loaded, static_guard, _ReadBudget(), country_pointer=country_pointer)
    except Exception as exc:
        return _unknown_record(f"{type(exc).__name__}:{exc}", module_base if type(module_base) is int else None, country_pointer if type(country_pointer) is int else None, country)


def _stable_record(record: Mapping[str, Any]) -> dict[str, Any]:
    private = record.get("private") if isinstance(record.get("private"), Mapping) else {}
    return {"status": record.get("status"), "profile_id": record.get("profile_id"), "profile_sha256": record.get("profile_sha256"), "country": record.get("country"), "fields": record.get("fields"), "country_pointer": private.get("country_pointer"), "country_handle": private.get("country_handle"), "game_pointer": private.get("game_pointer"), "game_date": private.get("game_date"), "country_scan": private.get("country_scan"), "force": private.get("force"), "complete": record.get("complete"), "partial": record.get("partial")}


def _stable_record_for_comparison(record: Mapping[str, Any]) -> dict[str, Any]:
    return without_clock(_stable_record(record), date_labels=("military_resources.game_date",))


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


def capture(installation: Path, country: str = EXPECTED_COUNTRY) -> dict[str, Any]:
    """Capture FRA sailors and force limits with two independent country scans."""
    installation = Path(installation)
    report: dict[str, Any] = {
        "probe": "information-military-resources-runtime", "probe_version": 1,
        "probe_script": str(Path(__file__).resolve()), "probe_script_sha256": None,
        "profile": {"path": str(PROFILE_FILE), "sha256": EXPECTED_PROFILE_SHA256, "profile_id": EXPECTED_PROFILE_ID, "max_bytes": PROFILE_MAX_BYTES},
        "read_only": True, "evidence_kind": "pure_runtime_observation_not_static_evidence", "captured_at": datetime.now(timezone.utc).isoformat(),
        "request": {"installation": str(installation), "country": country, "scope": "country_sailors_and_force_limits"}, "country": country,
        "target_build": {"version": EXPECTED_VERSION, "expected_exe_sha256": EXPECTED_EXE_SHA256, "database_rva": hex(0x233D8B0), "game_rva": hex(0x233FE58), "processor_manager_rva": hex(0x2358060)},
        "static_contract_guard": None, "file_code_guard": None, "runtime_code_guard": None,
        "identity": {"installation_path": str(installation), "installation_pid": None, "installation_creation_filetime": None, "installation_session_id": None, "process_path": None, "process_path_sha256": None, "process_path_sha256_matches_expected": None, "process_creation_filetime": None, "process_creation_utc": None, "process_creation_matches_installation": None, "module_path": None, "module_path_matches_process": None, "binding_verified": False},
        "module_base": None, "country_pointer": None, "country_scan": None, "before": None, "after": None,
        "fields": {name: {"status": "unknown", "reason": "not_read", "complete": False, "partial": True} for name in FIELDS}, "values": None, "raw_hex": None,
        "complete": False, "partial": True, "doublepass": {"performed": False, "consistent": None, "mismatches": [], "atomic": False},
        "access": {"open_process_mask": "QUERY_INFORMATION|VM_READ", "open_process_mask_hex": _hex(PROCESS_ACCESS), "rpm_total_limit": MAX_TOTAL_RPM, "rpm_single_read_limit": MAX_SINGLE_RPM, "rpm_bytes_requested": 0, "rpm_calls": 0, "native_game_calls": False, "target_memory_writes": False, "mcp_query": False, "control_or_business_dispatch": False, "date_advance_save_restart": False},
        "cleanup": {"handle_close": {"status": "unknown", "success": None, "closed": False}}, "status": "starting", "errors": [], "completed": False,
    }
    kernel = None; handle = None; budget = _ReadBudget()
    try:
        report["probe_script_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        if country != EXPECTED_COUNTRY:
            report["status"] = "unsupported_country"; report["errors"].append({"stage": "request", "status": "unknown", "error": "Only FRA is permitted"}); return report
        profile = _load_profile()
        report["static_contract_guard"] = _static_contract_guard(profile)
        if report["static_contract_guard"].get("status") != "observed":
            report["status"] = "static_contract_mismatch"; return report
        document = _load_installation(installation)
        kernel = _configure_kernel()
        handle = kernel.OpenProcess(PROCESS_ACCESS, False, int(document["pid"]))
        if not handle:
            raise OSError("OpenProcess failed")
        module_base = _capture_identity(report, document, kernel, handle)
        report["module_base"] = _hex(module_base)
        report["request"].update({"pid": int(document["pid"]), "creation_filetime": int(document["creation_filetime"]), "session_id": str(document["session_id"]), "game_sha256": str(document.get("game_sha256", "")).lower()})
        process_path = Path(report["identity"]["process_path"])
        report["file_code_guard"] = _file_code_guard(process_path, profile)
        if report["file_code_guard"].get("status") != "observed":
            report["status"] = "file_code_mismatch"; return report
        reader = AddressBoundedRPM(kernel, handle, module_base)
        first = _snapshot(reader, module_base, country, profile, report["static_contract_guard"], budget)
        second = _snapshot(reader, module_base, country, profile, report["static_contract_guard"], budget)
        report["before"], report["after"] = first, second
        report["country_pointer"] = first["private"].get("country_pointer")
        report["country_scan"] = {"before": _copy_json(first["private"].get("country_scan")), "after": _copy_json(second["private"].get("country_scan"))}
        report["doublepass"]["performed"] = True
        report["doublepass"]["mismatches"] = _diff_paths(
            _stable_record_for_comparison(first["record"]),
            _stable_record_for_comparison(second["record"]))
        first_date = first.get("record", {}).get("private", {}).get("game_date")
        second_date = second.get("record", {}).get("private", {}).get("game_date")
        first_date_value = first_date.get("value") if isinstance(first_date, Mapping) else None
        second_date_value = second_date.get("value") if isinstance(second_date, Mapping) else None
        if (not dates_match(first_date_value, second_date_value)
                and "$.game_date" not in report["doublepass"]["mismatches"]):
            report["doublepass"]["mismatches"].append("$.game_date")
        report["doublepass"]["consistent"] = not report["doublepass"]["mismatches"]
        report["runtime_code_guard"] = {"status": "observed", "passes": [first["private"]["runtime_code_guard"], second["private"]["runtime_code_guard"]]}
        report["access"]["rpm_bytes_requested"] = budget.used; report["access"]["rpm_calls"] = len(budget.reads)
        if not report["doublepass"]["consistent"]:
            report["status"] = "doublepass_mismatch"; report["errors"].append({"stage": "doublepass", "status": "unknown", "error": "country/date/resource graph changed between passes", "paths": report["doublepass"]["mismatches"][:256]}); return report
        report["access"]["rpm_bytes_requested"] = sum(
            item["record"]["observation"]["read_budget"]["bytes_reserved"] for item in (first, second))
        report["access"]["rpm_calls"] = sum(
            len(item["record"]["observation"]["read_log"]) for item in (first, second))
        report["fields"] = _copy_json(first["fields"]); report["values"] = _copy_json(first["values"]); report["raw_hex"] = _copy_json(first["raw_hex"]); report["status"] = "observed"; report["completed"] = True
        return report
    except Exception as exc:
        report["status"] = "unknown"; report["errors"].append({"stage": "capture", "status": "unknown", "error": f"{type(exc).__name__}:{exc}"}); return report
    finally:
        report["access"]["rpm_bytes_requested"] = budget.used; report["access"]["rpm_calls"] = len(budget.reads)
        report["cleanup"]["handle_close"] = _close_process_handle(kernel, handle)
        if report.get("status") == "observed" and report["cleanup"]["handle_close"] != {"status": "closed", "success": True, "closed": True}:
            report["status"] = "unknown"; report["errors"].append({"stage": "cleanup", "status": "unknown", "error": "process handle cleanup failed", "cleanup": _copy_json(report["cleanup"]["handle_close"])})
        report["completed"] = True


def _parse_address(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = int(value, 0)
    except ValueError:
        return None
    return parsed if value == _hex(parsed) else None


def _trace_index(observation: Any, layout: Mapping[str, int]) -> dict[str, dict[str, Any]] | None:
    """Validate a pass read log and return its uniquely labelled RPM rows."""
    if not isinstance(observation, Mapping):
        return None
    budget, logs = observation.get("read_budget"), observation.get("read_log")
    if (not isinstance(budget, Mapping) or budget.get("limit") != READ_BUDGET_BYTES or
            type(budget.get("bytes_reserved")) is not int or not 0 < budget["bytes_reserved"] <= READ_BUDGET_BYTES or
            not isinstance(logs, list) or not logs):
        return None
    result: dict[str, dict[str, Any]] = {}
    total = 0
    for item in logs:
        if not isinstance(item, Mapping) or item.get("status") != "ok":
            return None
        label, size, raw_hex, digest = item.get("label"), item.get("size"), item.get("raw_hex"), item.get("sha256")
        address = _parse_address(item.get("address"))
        if (not isinstance(label, str) or not label.startswith("military_resources.") or label in result or
                type(size) is not int or size <= 0 or size > MAX_SINGLE_RPM or
                not isinstance(raw_hex, str) or len(raw_hex) != size * 2 or raw_hex != raw_hex.lower() or
                not isinstance(digest, str) or len(digest) != 64 or address is None or
                not _valid_address(address, layout) or not _valid_address(address + size - 1, layout)):
            return None
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError:
            return None
        if raw.hex() != raw_hex or hashlib.sha256(raw).hexdigest() != digest.lower():
            return None
        total += size
        if total > READ_BUDGET_BYTES:
            return None
        result[label] = dict(item)
    if total != budget.get("bytes_reserved"):
        return None
    return result


def _trace_raw(trace: Mapping[str, Mapping[str, Any]], label: str,
               address: int | None = None, size: int | None = None) -> bytes | None:
    item = trace.get(label)
    if not isinstance(item, Mapping):
        return None
    if address is not None and item.get("address") != _hex(address):
        return None
    if size is not None and item.get("size") != size:
        return None
    try:
        return bytes.fromhex(item["raw_hex"])
    except (ValueError, KeyError, TypeError):
        return None


def _static_guard_valid(value: Any, profile: Mapping[str, Any]) -> bool:
    """Bind the retained static check to the currently pinned source/profile."""
    try:
        expected = _static_contract_guard(profile)
        return (isinstance(value, Mapping) and value.get("status") == "observed" and
                value.get("evidence_kind") == expected.get("evidence_kind") and
                value.get("profile") == expected.get("profile") and
                value.get("profile_id") == EXPECTED_PROFILE_ID and
                value.get("profile_sha256") == EXPECTED_PROFILE_SHA256 and
                value.get("source_evidence") == expected.get("source_evidence") and
                value.get("checks") == expected.get("checks") and
                value.get("unknown_conditions") == [])
    except Exception:
        return False


def _runtime_guard_valid(value: Any, profile: Mapping[str, Any], module_base: int,
                         trace: Mapping[str, Mapping[str, Any]], layout: Mapping[str, int]) -> bool:
    if not isinstance(value, Mapping) or value.get("status") != "observed" or value.get("module_base") != _hex(module_base):
        return False
    checks, records = value.get("checks"), value.get("records")
    if not isinstance(checks, Mapping) or not isinstance(records, Mapping):
        return False
    try:
        guards = _profile_code_guards(profile)
        names = {name for name, _rva, _end, _expected in guards}
        if set(checks) != names or any(checks.get(name) is not True for name in names) or set(records) != names:
            return False
        for name, rva, end, expected in guards:
            row = records[name]
            if not isinstance(row, Mapping):
                return False
            address = _add_address(module_base, rva, layout)
            raw = _trace_raw(trace, f"military_resources.code.{name}", address, len(expected))
            digest = hashlib.sha256(expected).hexdigest()
            if (raw != expected or row.get("rva") != hex(rva) or row.get("rva_end_exclusive") != hex(end) or
                    row.get("address") != _hex(address) or row.get("expected_hex") != expected.hex() or
                    row.get("actual_hex") != expected.hex() or row.get("expected_sha256") != digest or
                    row.get("actual_sha256") != digest):
                return False
    except Exception:
        return False
    return True


def _raw_i32(raw_hex: Any) -> int | None:
    try:
        if not isinstance(raw_hex, str) or len(raw_hex) != 8:
            return None
        return int.from_bytes(bytes.fromhex(raw_hex), "little", signed=True)
    except (ValueError, TypeError):
        return None


def _raw_u64(raw_hex: Any) -> int | None:
    try:
        if not isinstance(raw_hex, str) or len(raw_hex) != 16:
            return None
        return int.from_bytes(bytes.fromhex(raw_hex), "little", signed=False)
    except (ValueError, TypeError):
        return None


def _validate_sailors(field: Any) -> bool:
    if not isinstance(field, Mapping) or field.get("status") != "known" or field.get("complete") is not True or field.get("partial") is not False or field.get("unit") != "sailors" or field.get("scale") != 1000 or field.get("period") != "current":
        return False
    raw = field.get("raw")
    if type(raw) is not int or raw < 0 or raw > I32_MAX or field.get("value") != raw or _raw_i32(field.get("raw_hex")) != raw or field.get("display_value") != _native_display_value(raw):
        return False
    return True


def _validate_force_subfield(kind: str, field: Any) -> bool:
    if not isinstance(field, Mapping):
        return False
    if field.get("status") == "unknown":
        return field.get("reason") == "DYNAMIC_FORCE_LIMIT_PROCESSOR_UNSUPPORTED" or str(field.get("reason", "")).startswith(("FORCE_LIMIT_CACHE_", "modifier_", "processor_", "land_", "naval_"))
    if field.get("status") != "known" or field.get("complete") is not True or field.get("partial") is not False or field.get("unit") != FORCE_UNITS[kind] or field.get("scale") != 1000:
        return False
    value, raw = field.get("value"), field.get("raw")
    return type(value) is int and value >= 1 and type(raw) is int and raw == value * 1000 and _raw_i32(field.get("raw_hex")) == raw


def _validate_country_scan(scan: Any, country_pointer: int, handle: int,
                           module_base: int, layout: Mapping[str, int],
                           profile: Mapping[str, Any],
                           trace: Mapping[str, Mapping[str, Any]]) -> set[str] | None:
    """Rebuild the selected FRA table match from its per-slot RPM bytes."""
    if not isinstance(scan, Mapping) or scan.get("country_pointer") != _hex(country_pointer) or scan.get("country_handle") != _hex(handle):
        return None
    if scan.get("status") == "synthetic":
        expected = {"status", "country_pointer", "country_handle", "country_handle_raw_hex"}
        if (set(scan) != expected or scan.get("country_handle_raw_hex") != handle.to_bytes(8, "little").hex() or
                any(label.startswith(("military_resources.database", "military_resources.country_table", "military_resources.country_count", "military_resources.country_fullref")) for label in trace)):
            return None
        return set()
    if scan.get("status") != "observed":
        return None
    database = _parse_address(scan.get("database")); table = _parse_address(scan.get("table_pointer"))
    count = scan.get("country_count")
    if (database is None or table is None or not _valid_address(database, layout) or not _valid_address(table, layout) or
            type(count) is not int or not 1 <= count <= int(profile["limits"]["max_country_slots"])):
        return None
    database_raw = _trace_raw(trace, "military_resources.database", module_base + layout["database_global_rva"], 8)
    table_raw = _trace_raw(trace, "military_resources.country_table", database + layout["database_table_offset"], 8)
    count_raw = _trace_raw(trace, "military_resources.country_count", database + layout["database_table_count_offset"], 4)
    if (database_raw is None or int.from_bytes(database_raw, "little") != database or
            scan.get("database_raw_hex") != database_raw.hex() or table_raw is None or
            int.from_bytes(table_raw, "little") != table or scan.get("table_raw_hex") != table_raw.hex() or
            count_raw is None or int.from_bytes(count_raw, "little", signed=True) != count or
            scan.get("country_count_raw_hex") != count_raw.hex() or
            not _valid_address(database, layout) or not _valid_address(table, layout)):
        return None
    slot_labels: set[str] = set()
    fullref_labels: set[str] = set()
    matches: list[dict[str, Any]] = []
    for slot in range(count):
        table_label = f"military_resources.country_table[{slot}]"
        slot_address = table + slot * 8
        pointer_raw = _trace_raw(trace, table_label, slot_address, 8)
        if pointer_raw is None:
            return None
        slot_labels.add(table_label)
        pointer = int.from_bytes(pointer_raw, "little", signed=False)
        if not pointer:
            continue
        if not _valid_address(pointer, layout):
            return None
        fullref_label = f"military_resources.country_fullref[{slot}]"
        fullref_raw = _trace_raw(trace, fullref_label, pointer + layout["country_fullref_offset"], 8)
        if fullref_raw is None:
            return None
        fullref_labels.add(fullref_label)
        fullref = int.from_bytes(fullref_raw, "little", signed=False)
        tag = _tag_from_fullref(fullref)
        if tag == EXPECTED_COUNTRY and ((fullref >> 32) & 0xFFFF) == slot:
            matches.append({"slot": slot, "pointer": _hex(pointer), "table_entry_raw_hex": pointer_raw.hex(),
                            "fullref_raw_hex": fullref_raw.hex(), "tag": tag,
                            "country_handle": _hex(fullref), "country_handle_raw_hex": fullref_raw.hex()})
    observed_slot_labels = {key for key in trace if key.startswith("military_resources.country_table[")}
    observed_fullref_labels = {key for key in trace if key.startswith("military_resources.country_fullref[")}
    if observed_slot_labels != slot_labels or observed_fullref_labels != fullref_labels:
        return None
    if len(matches) != 1 or scan.get("matches") != matches:
        return None
    match = matches[0]
    if (match["pointer"] != _hex(country_pointer) or match["country_handle"] != _hex(handle) or
            scan.get("country_pointer") != match["pointer"] or scan.get("country_handle_raw_hex") != match["country_handle_raw_hex"]):
        return None
    return {"military_resources.database", "military_resources.country_table", "military_resources.country_count"} | slot_labels | fullref_labels


def _validate_modifier(modifier: Any, country_pointer: int, layout: Mapping[str, int],
                       trace: Mapping[str, Mapping[str, Any]]) -> tuple[dict[int, int], set[str]] | None:
    if not isinstance(modifier, Mapping):
        return None
    object_address = country_pointer + layout["force_modifier_offset"]
    if not _valid_address(object_address, layout) or modifier.get("storage") != "inline" or modifier.get("object_address") != _hex(object_address):
        return None
    header_raw = _trace_raw(trace, "military_resources.modifier_header", object_address, 0x68)
    if header_raw is None or modifier.get("header_raw_hex") != header_raw.hex() or modifier.get("header_bytes") != 0x68:
        return None
    dense_flag = header_raw[layout["modifier_dense_flag_offset"]]
    values_pointer = int.from_bytes(header_raw[layout["modifier_values_pointer_offset"]:layout["modifier_values_pointer_offset"] + 8], "little")
    sparse_count = int.from_bytes(header_raw[layout["modifier_sparse_count_offset"]:layout["modifier_sparse_count_offset"] + 4], "little", signed=True)
    if (dense_flag not in (0, 1) or sparse_count < 0 or sparse_count > 4096 or
            modifier.get("dense_flag") != dense_flag or modifier.get("dense_flag_raw_hex") != header_raw[layout["modifier_dense_flag_offset"]:layout["modifier_dense_flag_offset"] + 1].hex() or
            modifier.get("sparse_count") != sparse_count or modifier.get("sparse_count_raw_hex") != header_raw[layout["modifier_sparse_count_offset"]:layout["modifier_sparse_count_offset"] + 4].hex() or
            modifier.get("values_pointer_raw_hex") != header_raw[layout["modifier_values_pointer_offset"]:layout["modifier_values_pointer_offset"] + 8].hex() or
            modifier.get("values_pointer") != (_hex(values_pointer) if values_pointer else None) or
            modifier.get("mode") != ("dense" if dense_flag else "sparse")):
        return None
    if sparse_count and not _valid_address(values_pointer, layout):
        return None
    ids = modifier.get("ids")
    sparse_entries = modifier.get("sparse_entries")
    if not isinstance(ids, Mapping) or set(ids) != {str(ident) for ident in FORCE_IDS} or not isinstance(sparse_entries, list):
        return None
    labels = {"military_resources.modifier_header"}
    values: dict[int, int] = {}
    if dense_flag:
        if not _valid_address(values_pointer, layout) or sparse_entries:
            return None
        for ident in FORCE_IDS:
            label = f"military_resources.modifier.dense[{ident}]"
            address = values_pointer + ident * 8 + 4
            raw = _trace_raw(trace, label, address, 4)
            row = ids[str(ident)]
            if (raw is None or not isinstance(row, Mapping) or row.get("storage") != "dense" or
                    row.get("id") != ident or row.get("address") != _hex(address) or row.get("raw_hex") != raw.hex() or
                    row.get("value_raw") != int.from_bytes(raw, "little", signed=True)):
                return None
            values[ident] = int.from_bytes(raw, "little", signed=True)
            labels.add(label)
    else:
        if len(sparse_entries) != sparse_count:
            return None
        found: dict[int, tuple[int, int, bytes]] = {}
        for index, entry in enumerate(sparse_entries):
            if not isinstance(entry, Mapping) or entry.get("index") != index or not _valid_address(values_pointer, layout):
                return None
            label = f"military_resources.modifier.sparse[{index}]"
            address = values_pointer + index * layout["modifier_sparse_stride"]
            raw = _trace_raw(trace, label, address, layout["modifier_sparse_stride"])
            if raw is None or entry.get("address") != _hex(address) or entry.get("raw_hex") != raw.hex():
                return None
            key = int.from_bytes(raw[:4], "little", signed=False)
            value = int.from_bytes(raw[4:], "little", signed=True)
            if entry.get("key") != key or entry.get("value_raw") != value:
                return None
            if key in FORCE_IDS and key not in found:
                found[key] = (index, address, raw[4:])
            labels.add(label)
        for ident in FORCE_IDS:
            if ident in found:
                index, address, value_raw = found[ident]
                value = int.from_bytes(value_raw, "little", signed=True)
                expected = {"id": ident, "storage": "sparse", "address": _hex(address + 4),
                            "raw_hex": value_raw.hex(), "value_raw": value, "first_match_index": index}
            else:
                value = 0
                expected = {"id": ident, "storage": "sparse", "address": None,
                            "raw_hex": "00000000", "value_raw": 0, "first_match_index": None}
            if ids[str(ident)] != expected:
                return None
            values[ident] = value
    if not dense_flag:
        # Dense rows must not be smuggled into a sparse representation, even
        # if their self-reported value happens to equal the first match.
        for ident in FORCE_IDS:
            if ids[str(ident)].get("storage") != "sparse":
                return None
    return values, labels


def _validate_processors(processors: Any, module_base: int, layout: Mapping[str, int],
                          trace: Mapping[str, Mapping[str, Any]]) -> tuple[dict[int, int | None], set[str]] | None:
    if not isinstance(processors, Mapping):
        return None
    manager_cell = module_base + layout["processor_manager_rva"]
    manager_raw = _trace_raw(trace, "military_resources.processor_manager", manager_cell, 8)
    if manager_raw is None:
        return None
    manager = int.from_bytes(manager_raw, "little", signed=False)
    rows = processors.get("slots")
    if (not _valid_address(manager, layout) or processors.get("manager_global_rva") != hex(layout["processor_manager_rva"]) or
            processors.get("manager_global_address") != _hex(manager_cell) or processors.get("manager_pointer") != _hex(manager) or
            processors.get("manager_pointer_raw_hex") != manager_raw.hex() or not isinstance(rows, Mapping) or
            set(rows) != {str(ident) for ident in FORCE_IDS}):
        return None
    pointers: dict[int, int | None] = {}
    labels = {"military_resources.processor_manager"}
    for ident in FORCE_IDS:
        address = manager + ident * layout["processor_stride"] + layout["processor_offset"]
        label = f"military_resources.processor[{ident}]"
        raw = _trace_raw(trace, label, address, 8)
        row = rows[str(ident)]
        if (raw is None or not isinstance(row, Mapping) or row.get("id") != ident or
                row.get("slot_address") != _hex(address) or row.get("slot_raw_hex") != raw.hex() or
                row.get("processor_pointer_raw_hex") != raw.hex()):
            return None
        pointer = int.from_bytes(raw, "little", signed=False)
        if pointer and not _valid_address(pointer, layout):
            return None
        if (row.get("processor_pointer") != (_hex(pointer) if pointer else None) or
                row.get("status") != ("unsupported_nonnull" if pointer else "absent")):
            return None
        pointers[ident] = pointer or None
        labels.add(label)
    return pointers, labels


def _validate_private_graph(record: Mapping[str, Any], profile: Mapping[str, Any], module_base: int,
                            trace: Mapping[str, Mapping[str, Any]]) -> bool:
    layout = _profile_layout(profile)
    private, fields = record.get("private"), record.get("fields")
    if not isinstance(private, Mapping) or not isinstance(fields, Mapping):
        return False
    country_pointer = _parse_address(private.get("country_pointer"))
    handle = _parse_address(private.get("country_handle"))
    game = _parse_address(private.get("game_pointer"))
    if (country_pointer is None or handle is None or game is None or not _valid_address(country_pointer, layout) or
            not _valid_address(game, layout) or _tag_from_fullref(handle) != EXPECTED_COUNTRY):
        return False
    expected_labels = {f"military_resources.code.{name}" for name, _rva, _end, _raw in _profile_code_guards(profile)}
    game_cell = module_base + layout["game_global_rva"]
    game_raw = _trace_raw(trace, "military_resources.game", game_cell, 8)
    date_raw = _trace_raw(trace, "military_resources.game_date", game + layout["game_date_offset"], 4)
    handle_raw = _trace_raw(trace, "military_resources.country_handle", country_pointer + layout["country_fullref_offset"], 8)
    sailors_raw = _trace_raw(trace, "military_resources.sailors", country_pointer + layout["sailors_offset"], 4)
    cache_raw = _trace_raw(trace, "military_resources.force_cache_state", country_pointer + layout["force_cache_state_offset"], 4)
    date = private.get("game_date")
    if (game_raw is None or int.from_bytes(game_raw, "little") != game or private.get("game_pointer_raw_hex") != game_raw.hex() or
            date_raw is None or not isinstance(date, Mapping) or date.get("raw_hex") != date_raw.hex() or
            date.get("value") != int.from_bytes(date_raw, "little", signed=True) or
            handle_raw is None or int.from_bytes(handle_raw, "little") != handle or private.get("country_handle_raw_hex") != handle_raw.hex() or
            sailors_raw is None or _raw_i32(sailors_raw.hex()) != fields.get(SAILORS_FIELD, {}).get("raw") or
            cache_raw is None):
        return False
    scan_labels = _validate_country_scan(private.get("country_scan"), country_pointer, handle, module_base, layout, profile, trace)
    if scan_labels is None:
        return False
    expected_labels |= {"military_resources.game", "military_resources.game_date", "military_resources.country_handle",
                        "military_resources.sailors", "military_resources.force_cache_state"} | scan_labels
    force_private = private.get("force")
    force_field = fields.get(FORCE_FIELD)
    if not isinstance(force_private, Mapping) or not isinstance(force_private.get("cache_state"), Mapping) or not isinstance(force_field, Mapping):
        return False
    cache = force_private["cache_state"]
    cache_value = int.from_bytes(cache_raw, "little", signed=True)
    if type(cache.get("value")) is not int or cache.get("value") != cache_value or cache.get("raw_hex") != cache_raw.hex():
        return False
    if cache_value == 1:
        expected_unknown = _unknown_force("FORCE_LIMIT_CACHE_CALCULATING")
        expected_force = {"status": "partial", "value": {"land": expected_unknown, "naval": expected_unknown},
                          "unit": "mixed", "scale": 1000, "period": "current",
                          "basis": "native_force_limit_getter_numeric_path", "complete": False,
                          "partial": True, "unknown_conditions": {"cache": "FORCE_LIMIT_CACHE_CALCULATING"}}
        if (force_private.get("modifier") is not None or force_private.get("processors") is not None or
                any(key in force_private for key in ("values", "field", "error")) or force_field != expected_force):
            return False
    else:
        modifier_result = _validate_modifier(force_private.get("modifier"), country_pointer, layout, trace)
        processor_result = _validate_processors(force_private.get("processors"), module_base, layout, trace)
        if modifier_result is None or processor_result is None:
            return False
        modifier_values, modifier_labels = modifier_result
        processor_values, processor_labels = processor_result
        private_values = force_private.get("values")
        if (not isinstance(private_values, Mapping) or set(private_values) != {str(ident) for ident in FORCE_IDS} or
                any(private_values[str(ident)] != modifier_values[ident] for ident in FORCE_IDS)):
            return False
        expected_field, expected_private_field = _force_field(modifier_values, processor_values)
        if force_field != expected_field or force_private.get("field") != expected_private_field or "error" in force_private:
            return False
        expected_labels |= modifier_labels | processor_labels
    if set(trace) != expected_labels:
        return False
    return True


def validate_record(record: Any) -> bool:
    """Validate public fields and their private raw bindings."""
    try:
        profile = _load_profile()
        layout = _profile_layout(profile)
        if not isinstance(record, Mapping) or record.get("status") != "observed" or record.get("profile_id") != EXPECTED_PROFILE_ID or record.get("profile_sha256") != EXPECTED_PROFILE_SHA256 or record.get("country") != EXPECTED_COUNTRY:
            return False
        private = record.get("private")
        module_base = int(str(private.get("module_base")), 0) if isinstance(private, Mapping) else 0
        observation = record.get("observation")
        trace = _trace_index(observation, layout)
        if (not _valid_address(module_base, layout) or trace is None or
                not _static_guard_valid(private.get("static_contract_guard") if isinstance(private, Mapping) else None, profile) or
                not _runtime_guard_valid(private.get("runtime_code_guard") if isinstance(private, Mapping) else None, profile, module_base, trace, layout)):
            return False
        fields = record.get("fields")
        if not isinstance(fields, Mapping) or set(fields) != set(FIELDS) or not _validate_sailors(fields.get(SAILORS_FIELD)):
            return False
        force = fields.get(FORCE_FIELD)
        if not isinstance(force, Mapping) or force.get("status") != "partial" or force.get("complete") is not False or force.get("partial") is not True or not isinstance(force.get("value"), Mapping) or set(force["value"]) != {"land", "naval"} or not _validate_force_subfield("land", force["value"]["land"]) or not _validate_force_subfield("naval", force["value"]["naval"]):
            return False
        if (not isinstance(observation, Mapping) or observation.get("profile_id") != EXPECTED_PROFILE_ID or
                observation.get("profile_sha256") != EXPECTED_PROFILE_SHA256 or
                observation.get("module_base") != private.get("module_base") or
                observation.get("country_pointer") != private.get("country_pointer") or
                observation.get("country_handle") != private.get("country_handle") or
                observation.get("game_date") != private.get("game_date", {}).get("value")):
            return False
        return _validate_private_graph(record, profile, module_base, trace)
    except Exception:
        return False


def validate_capture(report: Any, context: Mapping[str, Any] | None, creation_filetime: int, country: str = EXPECTED_COUNTRY) -> bool:
    """Validate installation identity, date, two-pass equality, and cleanup."""
    try:
        if not isinstance(report, Mapping) or report.get("status") != "observed" or report.get("completed") is not True or report.get("country") != country or country != EXPECTED_COUNTRY or report.get("read_only") is not True:
            return False
        identity, request = report.get("identity"), report.get("request")
        cleanup = report.get("cleanup", {}).get("handle_close") if isinstance(report.get("cleanup"), Mapping) else None
        access, double = report.get("access"), report.get("doublepass")
        if (not isinstance(identity, Mapping) or not isinstance(request, Mapping) or identity.get("binding_verified") is not True or identity.get("process_creation_matches_installation") is not True or identity.get("process_path_sha256_matches_expected") is not True or str(identity.get("process_path_sha256", "")).lower() != EXPECTED_EXE_SHA256 or cleanup != {"status": "closed", "success": True, "closed": True} or not isinstance(access, Mapping) or access.get("native_game_calls") is not False or access.get("target_memory_writes") is not False or access.get("mcp_query") is not False or not isinstance(double, Mapping) or double.get("performed") is not True or double.get("consistent") is not True or type(access.get("rpm_bytes_requested")) is not int or not 0 <= access.get("rpm_bytes_requested") <= MAX_TOTAL_RPM or type(access.get("rpm_calls")) is not int or access.get("rpm_calls") < 0):
            return False
        if (request.get("country") != country or request.get("installation") != identity.get("installation_path") or request.get("pid") != identity.get("installation_pid") or request.get("creation_filetime") != identity.get("installation_creation_filetime") or request.get("session_id") != identity.get("installation_session_id") or str(request.get("game_sha256", "")).lower() != EXPECTED_EXE_SHA256):
            return False
        if type(creation_filetime) is not int or identity.get("installation_creation_filetime") != creation_filetime or identity.get("process_creation_filetime") != creation_filetime:
            return False
        if not isinstance(context, Mapping) or type(context.get("game_date")) is not int:
            return False
        expected_session = context.get("session_id", context.get("installation_session_id"))
        if expected_session is not None and identity.get("installation_session_id") != expected_session:
            return False
        expected_sha = context.get("game_sha256", context.get("expected_exe_sha256"))
        if expected_sha is not None and str(expected_sha).lower() != EXPECTED_EXE_SHA256:
            return False
        before, after = report.get("before"), report.get("after")
        if not isinstance(before, Mapping) or not isinstance(after, Mapping) or not isinstance(before.get("record"), Mapping) or not isinstance(after.get("record"), Mapping) or not validate_record(before["record"]) or not validate_record(after["record"]):
            return False
        pass_records = (before["record"], after["record"])
        expected_bytes = sum(item["observation"]["read_budget"]["bytes_reserved"] for item in pass_records)
        expected_calls = sum(len(item["observation"]["read_log"]) for item in pass_records)
        if access.get("rpm_bytes_requested") != expected_bytes or access.get("rpm_calls") != expected_calls:
            return False
        if _diff_paths(_stable_record_for_comparison(before["record"]),
                       _stable_record_for_comparison(after["record"])):
            return False
        if before.get("fields") != before["record"].get("fields") or after.get("fields") != after["record"].get("fields") or before.get("private") != before["record"].get("private") or after.get("private") != after["record"].get("private"):
            return False
        before_date = before["record"]["private"].get("game_date")
        after_date = after["record"]["private"].get("game_date")
        before_date_value = before_date.get("value") if isinstance(before_date, Mapping) else None
        after_date_value = after_date.get("value") if isinstance(after_date, Mapping) else None
        if (not dates_match(before_date_value, after_date_value) or
                not dates_match(context.get("game_date"), before_date_value, after_date_value)):
            return False
        if report.get("module_base") != before["record"]["private"].get("module_base") or report.get("module_base") != after["record"]["private"].get("module_base") or report.get("country_pointer") != before["record"]["private"].get("country_pointer") or report.get("fields") != after["fields"] or report.get("values") != after.get("values") or report.get("raw_hex") != after.get("raw_hex"):
            return False
        scans = report.get("country_scan")
        if not isinstance(scans, Mapping) or scans.get("before") != before["private"].get("country_scan") or scans.get("after") != after["private"].get("country_scan"):
            return False
        return True
    except Exception:
        return False


def retract_record(record: Any, reason: str = "observation_retracted") -> dict[str, Any]:
    return _unknown_record(reason)


__all__ = [
    "PROFILE_FILE", "PROFILE_MAX_BYTES", "EXPECTED_PROFILE_SHA256", "EXPECTED_PROFILE_ID", "EXPECTED_EXE_SHA256", "EXPECTED_VERSION", "EXPECTED_COUNTRY", "FIELDS", "SAILORS_FIELD", "FORCE_FIELD", "MAX_SINGLE_RPM", "MAX_TOTAL_RPM", "READ_BUDGET_BYTES", "ProfileError", "ReadError", "ProbeError", "AddressBoundedRPM", "read_fields", "capture", "validate_record", "validate_capture", "retract_record", "_load_profile", "_prepare_profile", "_profile_layout", "_profile_code_guards", "_static_contract_guard", "_file_code_guard", "_runtime_code_guard", "_ReadBudget", "_find_country", "_snapshot", "_force_value", "_force_field", "_read_modifier_values", "_read_processors",
]
