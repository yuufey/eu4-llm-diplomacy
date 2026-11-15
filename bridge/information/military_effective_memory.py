"""Bounded native reader for the current country's effective discipline.

The parent country capture owns process identity, lifecycle and the two-pass
comparison.  This child only validates its pinned static contract and copies
the keyed modifier inputs needed by the fixed-build discipline processor.  It
never calls a game function and never opens a process itself.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "military-effective-memory-1374-v2.json"
PROFILE_MAX_BYTES = 64 * 1024
SOURCE_EVIDENCE_MAX_BYTES = 128 * 1024
EXPECTED_PROFILE_SHA256 = "018fa77f0774e53075dd3536bd9578880fbc903f8074709b46755f5a34045868"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_VERSION = "1.37.4"
EXPECTED_COUNTRY = "FRA"

FIELDS = ("discipline",)
RECORD_KEY = "military_effective"
FIELD_KEY = "discipline"
BASIS = "native_country_discipline_calculation"
VALUE_ORIGIN = "derived_from_copied_native_inputs"
PERIOD = "current"
UNIT = "ratio"
SCALE = 1000
COMPLETE = False

COUNTRY_CACHE_STATE_OFFSET = 0x28C8
COUNTRY_MODIFIER_OBJECT_OFFSET = 0x28D0
MODIFIER_DENSE_FLAG_OFFSET = 0x10
MODIFIER_VALUES_POINTER_OFFSET = 0x58
MODIFIER_SPARSE_COUNT_OFFSET = 0x64
MODIFIER_ID = 0x77
MODIFIER_DATABASE_GLOBAL_RVA = 0x2358060
MODIFIER_RECORD_INDEX = 0x77
MODIFIER_RECORD_STRIDE = 0x60
MODIFIER_PROCESSOR_OFFSET = 0x40
PROCESSOR_VTABLE_RVA = 0x1CC9400
PROCESSOR_METHOD_RVA = 0x8F71D0
GLOBAL_FLAG_RVAS = {
    "0x102": 0x233FF0C,
    "0x1bb": 0x233FF2C,
    "0x1d2": 0x233FF54,
    "0x1c2": 0x233FF54,
}
SPECIAL_FLAG_RVA = 0x233FEB6
DENSE_MODIFIER_VALUE_OFFSET = 0x3BC
PROCESSOR_DENSE_OFFSETS = {
    "0x102": 0x814,
    "0x1bb": 0xDDC,
    "0x1d2": 0xE94,
    "0x1c2": 0xE14,
}
PROCESSOR_DENOMINATORS = {
    "0x102": 5000,
    "0x1bb": 10000,
    "0x1d2": 10000,
    "0x1c2": 10000,
}
MAX_SPARSE_COUNT = 8192
READ_BUDGET_BYTES = 98304
MAX_USER_ADDRESS = 0x00007FFFFFFFFFFF


class ProfileError(RuntimeError):
    """The pinned profile or one of its bounded source reports is invalid."""


class ReadError(RuntimeError):
    """A bounded child read or native-layout guard failed."""

    def __init__(self, reason: str, detail: Mapping[str, Any] | None = None):
        super().__init__(reason)
        self.reason = reason
        self.detail = dict(detail or {})


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


def _bounded_bytes(path: Path, limit: int, label: str) -> bytes:
    try:
        size = path.stat().st_size
        if size <= 0 or size > limit:
            raise ProfileError(f"{label}_size_out_of_bound:{size}")
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
    except (OSError, UnicodeError) as exc:
        raise ProfileError(f"{label}_read_failed:{exc}") from exc
    if len(raw) != size or len(raw) > limit:
        raise ProfileError(f"{label}_read_size_changed")
    return raw


def _workspace_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _source_path(raw_path: Any) -> Path:
    if not isinstance(raw_path, str) or not raw_path:
        raise ProfileError("source_evidence_path_invalid")
    root = _workspace_root()
    path = Path(raw_path)
    resolved = path.resolve() if path.is_absolute() else (root / path).resolve()
    if resolved != root and root not in resolved.parents:
        raise ProfileError("source_evidence_outside_workspace")
    return resolved


def _validate_source_evidence(profile: Mapping[str, Any]) -> list[dict[str, Any]]:
    items = profile.get("source_evidence")
    if not isinstance(items, list) or len(items) != 6:
        raise ProfileError("source_evidence_shape_invalid")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, Mapping):
            raise ProfileError("source_evidence_item_invalid")
        expected = item.get("sha256")
        expected_bytes = item.get("bytes")
        if not isinstance(expected, str) or len(expected) != 64:
            raise ProfileError("source_evidence_sha256_invalid")
        path = _source_path(item.get("path"))
        normalized = str(path).lower()
        if normalized in seen:
            raise ProfileError("source_evidence_duplicate")
        seen.add(normalized)
        raw = _bounded_bytes(path, SOURCE_EVIDENCE_MAX_BYTES, "source_evidence")
        if isinstance(expected_bytes, bool) or not isinstance(expected_bytes, int) or expected_bytes != len(raw):
            raise ProfileError("source_evidence_bytes_mismatch")
        actual = hashlib.sha256(raw).hexdigest()
        if actual.lower() != expected.lower():
            raise ProfileError("source_evidence_sha256_mismatch")
        result.append({
            "path": str(path.relative_to(_workspace_root())).replace("\\", "/"),
            "sha256": actual,
            "bytes": len(raw),
            "role": item.get("role"),
        })
    return result


def _profile_layout(profile: Mapping[str, Any]) -> dict[str, Any]:
    raw = profile.get("layout")
    if not isinstance(raw, Mapping):
        raise ProfileError("profile_layout_missing")
    names = (
        "country_cache_state_offset", "country_modifier_object_offset",
        "modifier_dense_flag_offset", "modifier_values_pointer_offset",
        "modifier_sparse_count_offset", "modifier_id", "modifier_database_global_rva",
        "modifier_record_index", "modifier_record_stride", "modifier_processor_offset",
        "processor_vtable_rva", "processor_method_rva", "dense_modifier_value_offset",
    )
    parsed = {name: _parse_int(raw.get(name), f"layout.{name}") for name in names}
    if parsed != {
        "country_cache_state_offset": COUNTRY_CACHE_STATE_OFFSET,
        "country_modifier_object_offset": COUNTRY_MODIFIER_OBJECT_OFFSET,
        "modifier_dense_flag_offset": MODIFIER_DENSE_FLAG_OFFSET,
        "modifier_values_pointer_offset": MODIFIER_VALUES_POINTER_OFFSET,
        "modifier_sparse_count_offset": MODIFIER_SPARSE_COUNT_OFFSET,
        "modifier_id": MODIFIER_ID,
        "modifier_database_global_rva": MODIFIER_DATABASE_GLOBAL_RVA,
        "modifier_record_index": MODIFIER_RECORD_INDEX,
        "modifier_record_stride": MODIFIER_RECORD_STRIDE,
        "modifier_processor_offset": MODIFIER_PROCESSOR_OFFSET,
        "processor_vtable_rva": PROCESSOR_VTABLE_RVA,
        "processor_method_rva": PROCESSOR_METHOD_RVA,
        "dense_modifier_value_offset": DENSE_MODIFIER_VALUE_OFFSET,
    }:
        raise ProfileError("profile_layout_offsets_invalid")
    if raw.get("sparse_entry_stride") != 8 or raw.get("max_sparse_count") != MAX_SPARSE_COUNT:
        raise ProfileError("profile_sparse_layout_invalid")
    if raw.get("read_budget_bytes") != READ_BUDGET_BYTES:
        raise ProfileError("profile_read_budget_invalid")
    processor_offsets = raw.get("processor_dense_offsets")
    expected_offsets = {key: hex(value) for key, value in PROCESSOR_DENSE_OFFSETS.items()}
    if not isinstance(processor_offsets, Mapping) or {
        key: processor_offsets.get(key) for key in expected_offsets
    } != expected_offsets:
        raise ProfileError("profile_processor_offsets_invalid")
    global_flags = raw.get("global_flags")
    expected_flags = {
        "specific_102": hex(GLOBAL_FLAG_RVAS["0x102"]),
        "specific_1bb": hex(GLOBAL_FLAG_RVAS["0x1bb"]),
        "specific_1d2_and_1c2": hex(GLOBAL_FLAG_RVAS["0x1d2"]),
        "special": hex(SPECIAL_FLAG_RVA),
    }
    if not isinstance(global_flags, Mapping) or {
        key: global_flags.get(key) for key in expected_flags
    } != expected_flags:
        raise ProfileError("profile_global_flags_invalid")
    return {
        **parsed,
        "sparse_entry_stride": 8,
        "max_sparse_count": MAX_SPARSE_COUNT,
        "read_budget_bytes": READ_BUDGET_BYTES,
        "processor_dense_offsets": dict(PROCESSOR_DENSE_OFFSETS),
        "global_flag_rvas": dict(GLOBAL_FLAG_RVAS),
        "special_flag_rva": SPECIAL_FLAG_RVA,
    }


def _profile_code_guards(profile: Mapping[str, Any]) -> list[tuple[str, int, int, bytes]]:
    raw_guards = profile.get("code_guards")
    if not isinstance(raw_guards, list) or len(raw_guards) != 2:
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
        start = _parse_int(item.get("rva"), f"code_guard.{name}.rva")
        end = _parse_int(item.get("rva_end_exclusive"), f"code_guard.{name}.end")
        try:
            raw = bytes.fromhex(item.get("hex", ""))
        except (TypeError, ValueError) as exc:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}") from exc
        if not raw or end <= start or len(raw) != end - start:
            raise ProfileError(f"profile_code_guard_range_invalid:{name}")
        if item.get("sha256") != hashlib.sha256(raw).hexdigest():
            raise ProfileError(f"profile_code_guard_sha_invalid:{name}")
        total += len(raw)
        if total > READ_BUDGET_BYTES:
            raise ProfileError("profile_code_guards_budget_invalid")
        names.add(name)
        result.append((name, start, end, raw))
    expected_names = {"discipline_helper_341850", "discipline_processor_8f71d0_full"}
    if names != expected_names:
        raise ProfileError("profile_code_guard_names_invalid")
    return result


def _validate_profile_shape(profile: Mapping[str, Any]) -> None:
    if profile.get("profile_id") != "military-effective-memory-1374":
        raise ProfileError("profile_shape_invalid")
    if profile.get("profile_version") != 2:
        raise ProfileError("profile_version_invalid")
    if profile.get("game_version") != EXPECTED_VERSION:
        raise ProfileError("profile_version_mismatch")
    executable = profile.get("executable")
    if not isinstance(executable, Mapping) or str(executable.get("sha256", "")).lower() != EXPECTED_EXE_SHA256:
        raise ProfileError("profile_executable_mismatch")
    _validate_source_evidence(profile)
    _profile_layout(profile)
    semantics = profile.get("semantics")
    expected = {
        "field": FIELD_KEY,
        "basis": BASIS,
        "value_origin": VALUE_ORIGIN,
        "unit": UNIT,
        "scale": SCALE,
        "period": PERIOD,
        "complete": COMPLETE,
    }
    if not isinstance(semantics, Mapping) or {
        key: semantics.get(key) for key in expected
    } != expected:
        raise ProfileError("profile_semantics_invalid")
    _profile_code_guards(profile)


def _load_profile(path: Path | None = None, expected_sha256: str | None = None) -> dict[str, Any]:
    path = PROFILE_FILE if path is None else Path(path)
    expected = EXPECTED_PROFILE_SHA256 if expected_sha256 is None else expected_sha256
    if not isinstance(expected, str) or len(expected) != 64:
        raise ProfileError("profile_sha256_invalid")
    raw = _bounded_bytes(path, PROFILE_MAX_BYTES, "profile")
    if hashlib.sha256(raw).hexdigest().lower() != expected.lower():
        raise ProfileError("profile_sha256_mismatch")
    try:
        profile = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"profile_json_invalid:{exc}") from exc
    if not isinstance(profile, dict):
        raise ProfileError("profile_json_shape_invalid")
    _validate_profile_shape(profile)
    result = dict(profile)
    result["_validated_source_evidence"] = _validate_source_evidence(profile)
    return result


def _copy_json(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False))


def _hex(value: int | None) -> str | None:
    return hex(value) if isinstance(value, int) else None


def _valid_address(value: Any) -> bool:
    return type(value) is int and 0x10000 <= value <= MAX_USER_ADDRESS


def _add_address(base: int, offset: int) -> int:
    if not _valid_address(base) or type(offset) is not int or offset < 0:
        raise ReadError("pointer_invalid")
    address = base + offset
    if not _valid_address(address):
        raise ReadError("pointer_arithmetic_invalid")
    return address


class _ReadBudget:
    def __init__(self, limit: int = READ_BUDGET_BYTES):
        self.limit = limit
        self.used = 0

    def reserve(self, size: int) -> None:
        if type(size) is not int or size < 0 or self.used + size > self.limit:
            raise ReadError("read_budget_exceeded", {"used": self.used, "requested": size, "limit": self.limit})
        self.used += size


def _reader_read(reader: Any, address: int, size: int, label: str, budget: _ReadBudget) -> bytes:
    if not _valid_address(address):
        raise ReadError(f"address_invalid:{label}")
    budget.reserve(size)
    method = getattr(reader, "read", None)
    if not callable(method):
        raise ReadError("reader_read_method_missing")
    try:
        raw = method(address, size, label)
    except Exception as exc:
        raise ReadError(f"read_failed:{label}:{type(exc).__name__}:{exc}") from exc
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != size:
        raise ReadError(f"short_or_invalid_read:{label}")
    return bytes(raw)


def _read_u8(reader: Any, address: int, label: str, budget: _ReadBudget) -> int:
    return _reader_read(reader, address, 1, label, budget)[0]


def _read_u32(reader: Any, address: int, label: str, budget: _ReadBudget) -> int:
    return int.from_bytes(_reader_read(reader, address, 4, label, budget), "little", signed=False)


def _read_i32(reader: Any, address: int, label: str, budget: _ReadBudget) -> int:
    return int.from_bytes(_reader_read(reader, address, 4, label, budget), "little", signed=True)


def _read_u64(reader: Any, address: int, label: str, budget: _ReadBudget) -> int:
    return int.from_bytes(_reader_read(reader, address, 8, label, budget), "little", signed=False)


def _i32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value >= 0x80000000 else value


def _trunc_zero(numerator: int, denominator: int) -> int:
    if numerator < 0:
        return -((-numerator) // denominator)
    return numerator // denominator


def _static_contract_guard(profile: Mapping[str, Any] | None = None, reason: str | None = None) -> dict[str, Any]:
    if not isinstance(profile, Mapping):
        return {
            "status": "unknown",
            "profile_id": "military-effective-memory-1374",
            "profile_sha256": EXPECTED_PROFILE_SHA256,
            "checks": {},
            "source_evidence": [],
            "unknown_conditions": [reason or "profile_unavailable"],
        }
    try:
        source = profile.get("_validated_source_evidence")
        if not isinstance(source, list):
            source = _validate_source_evidence(profile)
        checks = {
            "profile_id": profile.get("profile_id") == "military-effective-memory-1374",
            "game_version": profile.get("game_version") == EXPECTED_VERSION,
            "executable_sha256": isinstance(profile.get("executable"), Mapping)
            and str(profile["executable"].get("sha256", "")).lower() == EXPECTED_EXE_SHA256,
            "source_evidence": len(source) == 6,
            "layout": bool(_profile_layout(profile)),
            "semantics": profile.get("semantics", {}).get("field") == FIELD_KEY
            and profile.get("semantics", {}).get("basis") == BASIS
            and profile.get("semantics", {}).get("value_origin") == VALUE_ORIGIN
            and profile.get("semantics", {}).get("unit") == UNIT
            and profile.get("semantics", {}).get("scale") == SCALE
            and profile.get("semantics", {}).get("period") == PERIOD
            and profile.get("semantics", {}).get("complete") is COMPLETE,
            "code_guards": len(_profile_code_guards(profile)) == 2,
        }
        failed = [name for name, ok in checks.items() if ok is not True]
        return {
            "status": "observed" if not failed else "unknown",
            "profile_id": profile.get("profile_id"),
            "profile_sha256": EXPECTED_PROFILE_SHA256,
            "checks": checks,
            "source_evidence": _copy_json(source),
            "unknown_conditions": ["profile_contract_failed:" + ",".join(failed)] if failed else [],
        }
    except Exception as exc:
        return {
            "status": "unknown",
            "profile_id": profile.get("profile_id"),
            "profile_sha256": EXPECTED_PROFILE_SHA256,
            "checks": {},
            "source_evidence": [],
            "unknown_conditions": [f"profile_contract_failed:{type(exc).__name__}:{exc}"],
        }


def _unknown_field(reason: str) -> dict[str, Any]:
    return {
        "status": "unknown",
        "reason": reason,
        "complete": COMPLETE,
        "basis": BASIS,
        "value_origin": VALUE_ORIGIN,
        "period": PERIOD,
        "unit": UNIT,
        "scale": SCALE,
    }


def _empty_record(
    reason: str,
    *,
    profile: Mapping[str, Any] | None = None,
    static_guard: Mapping[str, Any] | None = None,
    runtime_guard: Mapping[str, Any] | None = None,
    module_base: int | None = None,
    country_pointer: int | None = None,
    observation: Mapping[str, Any] | None = None,
    read_budget: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if static_guard is None:
        static_guard = _static_contract_guard(profile, reason if profile is None else None)
    obs = {
        "record_key": RECORD_KEY,
        "profile_id": profile.get("profile_id") if isinstance(profile, Mapping) else "military-effective-memory-1374",
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "module_base": _hex(module_base),
        "country_pointer": _hex(country_pointer),
        "basis": BASIS,
        "value_origin": VALUE_ORIGIN,
        "period": PERIOD,
        "unit": UNIT,
        "scale": SCALE,
        "complete": COMPLETE,
        "static_contract_guard": _copy_json(static_guard),
        "code_guard": _copy_json(runtime_guard) if isinstance(runtime_guard, Mapping) else None,
        "read_budget": _copy_json(read_budget) if isinstance(read_budget, Mapping) else {
            "bytes_reserved": 0,
            "limit": READ_BUDGET_BYTES,
            "post_guard_bytes": 0,
        },
    }
    if isinstance(observation, Mapping):
        obs.update(_copy_json(observation))
    return {
        "status": "unknown",
        "reason": reason,
        "record_key": RECORD_KEY,
        "profile_id": obs["profile_id"],
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "module_base": _hex(module_base),
        "country_pointer": _hex(country_pointer),
        "static_contract_guard": _copy_json(static_guard),
        "runtime_code_guard": _copy_json(runtime_guard) if isinstance(runtime_guard, Mapping) else None,
        "fields": {FIELD_KEY: _unknown_field(reason)},
        "values": None,
        "raw_hex": None,
        "raw_bytes_hex": None,
        "basis": BASIS,
        "value_origin": VALUE_ORIGIN,
        "period": PERIOD,
        "unit": UNIT,
        "scale": SCALE,
        "complete": COMPLETE,
        "observation": obs,
    }


def _runtime_code_guard(reader: Any, module_base: int, profile: Mapping[str, Any], budget: _ReadBudget) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "module_base": _hex(module_base),
        "checks": {},
        "records": {},
        "unknown_conditions": [],
    }
    try:
        for name, rva, end, expected in _profile_code_guards(profile):
            address = _add_address(module_base, rva)
            actual = _reader_read(reader, address, len(expected), f"military_effective.code.{name}", budget)
            result["records"][name] = {
                "rva": hex(rva),
                "rva_end_exclusive": hex(end),
                "address": _hex(address),
                "expected_hex": expected.hex(),
                "actual_hex": actual.hex(),
                "expected_sha256": hashlib.sha256(expected).hexdigest(),
                "actual_sha256": hashlib.sha256(actual).hexdigest(),
            }
            result["checks"][name] = actual == expected
        failed = [name for name, ok in result["checks"].items() if ok is not True]
        if failed:
            result["status"] = "mismatch"
            result["unknown_conditions"].append("runtime_code_guard_mismatch:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (ReadError, ProfileError, TypeError, ValueError) as exc:
        result["unknown_conditions"].append(f"runtime_code_guard_failed:{type(exc).__name__}:{exc}")
    result["bytes_reserved"] = budget.used
    result["limit"] = budget.limit
    return result


def _read_modifier(
    reader: Any,
    country_pointer: int,
    layout: Mapping[str, Any],
    budget: _ReadBudget,
) -> dict[str, Any]:
    state_address = _add_address(country_pointer, layout["country_cache_state_offset"])
    state = _read_i32(reader, state_address, "military_effective.country.cache_state", budget)
    if state == 1:
        raise ReadError("MILITARY_CACHE_CALCULATING", {"cache_state": state})
    # The modifier object is embedded at country+0x28d0.  Only its values
    # pointer (+0x58) points elsewhere; do not interpret the first object
    # bytes as a qword pointer.
    modifier_object = _add_address(country_pointer, layout["country_modifier_object_offset"])
    dense_flag_address = _add_address(modifier_object, layout["modifier_dense_flag_offset"])
    values_address = _add_address(modifier_object, layout["modifier_values_pointer_offset"])
    count_address = _add_address(modifier_object, layout["modifier_sparse_count_offset"])
    dense_flag = _read_u8(reader, dense_flag_address, "military_effective.modifier.dense_flag", budget)
    values_pointer = _read_u64(reader, values_address, "military_effective.modifier.values_pointer", budget)
    count = _read_u32(reader, count_address, "military_effective.modifier.sparse_count", budget)
    if count > MAX_SPARSE_COUNT:
        raise ReadError("MILITARY_SPARSE_COUNT_OUT_OF_BOUND", {"count": count})
    result: dict[str, Any] = {
        "cache_state": state,
        "cache_state_raw_hex": (state & 0xFFFFFFFF).to_bytes(4, "little").hex(),
        "cache_state_address": _hex(state_address),
        "modifier_object": _hex(modifier_object),
        "dense_flag_raw": dense_flag,
        "dense_flag_hex": bytes([dense_flag]).hex(),
        "dense_flag_address": _hex(dense_flag_address),
        "values_pointer": _hex(values_pointer) if _valid_address(values_pointer) else None,
        "values_pointer_address": _hex(values_address),
        "sparse_count": count,
        "sparse_count_address": _hex(count_address),
        "modifier_id": MODIFIER_ID,
        "mode": "dense" if dense_flag != 0 else "sparse",
    }
    if dense_flag != 0:
        if not _valid_address(values_pointer):
            raise ReadError("MILITARY_MODIFIER_VALUES_UNAVAILABLE")
        value_address = _add_address(values_pointer, DENSE_MODIFIER_VALUE_OFFSET)
        raw = _reader_read(reader, value_address, 4, "military_effective.modifier.dense_value", budget)
        value = int.from_bytes(raw, "little", signed=True)
        result.update({
            "storage_address": _hex(value_address),
            "storage_raw_hex": raw.hex(),
            "modifier_raw": value,
            "modifier_raw_hex": raw.hex(),
            "first_match_index": None,
            "entries": [],
        })
        return result
    if count == 0:
        result.update({
            "storage_address": _hex(values_pointer) if _valid_address(values_pointer) else None,
            "storage_raw_hex": "",
            "modifier_raw": 0,
            "modifier_raw_hex": "00000000",
            "first_match_index": None,
            "entries": [],
        })
        return result
    if not _valid_address(values_pointer):
        raise ReadError("MILITARY_MODIFIER_VALUES_UNAVAILABLE")
    raw_table = _reader_read(
        reader,
        values_pointer,
        count * 8,
        "military_effective.modifier.sparse_entries",
        budget,
    )
    entries: list[dict[str, Any]] = []
    first_index: int | None = None
    modifier_raw = 0
    modifier_raw_hex = "00000000"
    for index in range(count):
        start = index * 8
        key_raw = raw_table[start : start + 4]
        value_raw = raw_table[start + 4 : start + 8]
        key = int.from_bytes(key_raw, "little", signed=False)
        value = int.from_bytes(value_raw, "little", signed=True)
        entries.append({
            "index": index,
            "address": _hex(values_pointer + start),
            "key": key,
            "key_hex": key_raw.hex(),
            "value": value,
            "value_hex": value_raw.hex(),
        })
        if first_index is None and key == MODIFIER_ID:
            first_index = index
            modifier_raw = value
            modifier_raw_hex = value_raw.hex()
    result.update({
        "storage_address": _hex(values_pointer),
        "storage_raw_hex": raw_table.hex(),
        "modifier_raw": modifier_raw,
        "modifier_raw_hex": modifier_raw_hex,
        "first_match_index": first_index,
        "entries": entries,
    })
    return result


def _read_processor(
    reader: Any,
    module_base: int,
    layout: Mapping[str, Any],
    modifier: Mapping[str, Any],
    budget: _ReadBudget,
    observation: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], int]:
    manager_address = _add_address(module_base, layout["modifier_database_global_rva"])
    manager_pointer = _read_u64(reader, manager_address, "military_effective.processor.manager_global", budget)
    if not _valid_address(manager_pointer):
        raise ReadError("MILITARY_PROCESSOR_MANAGER_UNAVAILABLE", {"manager_pointer": _hex(manager_pointer)})
    slot_offset = layout["modifier_record_index"] * layout["modifier_record_stride"] + layout["modifier_processor_offset"]
    slot_address = _add_address(manager_pointer, slot_offset)
    processor_pointer = _read_u64(reader, slot_address, "military_effective.processor.slot", budget)
    processor: dict[str, Any] = {
        "manager_global_rva": hex(layout["modifier_database_global_rva"]),
        "manager_global_address": _hex(manager_address),
        "manager_pointer": _hex(manager_pointer),
        "slot_offset": hex(slot_offset),
        "slot_address": _hex(slot_address),
        "processor_pointer": _hex(processor_pointer) if _valid_address(processor_pointer) else None,
    }
    observation["processor"] = processor
    if processor_pointer == 0:
        processor["status"] = "absent"
        processor["thread_context_status"] = "not_required_no_processor"
        callback_raw = _i32(int(modifier["modifier_raw"]))
        return processor, {}, callback_raw
    if not _valid_address(processor_pointer):
        processor["status"] = "unsupported"
        raise ReadError("MILITARY_PROCESSOR_POINTER_INVALID", {"processor_pointer": _hex(processor_pointer)})
    vtable_address = _add_address(processor_pointer, 0)
    vtable_pointer = _read_u64(reader, vtable_address, "military_effective.processor.vtable", budget)
    processor["vtable_pointer"] = _hex(vtable_pointer) if _valid_address(vtable_pointer) else None
    expected_vtable = _add_address(module_base, PROCESSOR_VTABLE_RVA)
    if vtable_pointer != expected_vtable:
        processor["status"] = "unsupported"
        raise ReadError("MILITARY_PROCESSOR_VTABLE_UNSUPPORTED", {"vtable_pointer": _hex(vtable_pointer)})
    method_address = _add_address(vtable_pointer, 8)
    method_pointer = _read_u64(reader, method_address, "military_effective.processor.method", budget)
    processor["method_pointer"] = _hex(method_pointer) if _valid_address(method_pointer) else None
    expected_method = _add_address(module_base, PROCESSOR_METHOD_RVA)
    if method_pointer != expected_method:
        processor["status"] = "unsupported"
        raise ReadError("MILITARY_PROCESSOR_METHOD_UNSUPPORTED", {"method_pointer": _hex(method_pointer)})
    processor.update({
        "status": "recognized",
        "vtable_rva": hex(PROCESSOR_VTABLE_RVA),
        "method_rva": hex(PROCESSOR_METHOD_RVA),
    })
    flags: dict[str, Any] = {}
    special_address = _add_address(module_base, SPECIAL_FLAG_RVA)
    special = _read_u8(reader, special_address, "military_effective.processor.special_flag", budget)
    flags["special"] = {
        "rva": hex(SPECIAL_FLAG_RVA),
        "address": _hex(special_address),
        "raw": special,
        "raw_hex": bytes([special]).hex(),
    }
    for key, rva in GLOBAL_FLAG_RVAS.items():
        address = _add_address(module_base, rva)
        raw = _read_u8(reader, address, f"military_effective.processor.flag_{key}", budget)
        flags[key] = {
            "rva": hex(rva),
            "address": _hex(address),
            "raw": raw,
            "raw_hex": bytes([raw]).hex(),
            "enabled": raw == 0 or special != 0,
        }
    processor["global_flags"] = flags
    inputs: dict[str, Any] = {}
    contributions: dict[str, Any] = {}
    storage_mode = modifier["mode"]
    entries = modifier.get("entries") if storage_mode == "sparse" else None
    for key, offset in PROCESSOR_DENSE_OFFSETS.items():
        raw_value: int
        source: str
        source_index: int | None = None
        address: int | None = None
        raw_hex: str
        if storage_mode == "dense":
            values_pointer = int(str(modifier["values_pointer"]), 0)
            address = _add_address(values_pointer, offset)
            raw_bytes = _reader_read(reader, address, 4, f"military_effective.processor.input_{key}", budget)
            raw_value = int.from_bytes(raw_bytes, "little", signed=True)
            raw_hex = raw_bytes.hex()
            source = "dense_values"
        else:
            found = next((item for item in entries or [] if item.get("key") == int(key, 16)), None)
            if found is None:
                raw_value, raw_hex, source = 0, "00000000", "sparse_missing_defaults_zero"
            else:
                raw_value = int(found["value"])
                raw_hex = str(found["value_hex"])
                source_index = int(found["index"])
                address = int(str(found["address"]), 0) + 4
                source = "sparse_first_match"
        specific = int(flags[key]["raw"])
        enabled = specific == 0 or special != 0
        denominator = PROCESSOR_DENOMINATORS[key]
        scaled = _trunc_zero(raw_value * 1000, denominator) if enabled else 0
        inputs[key] = {
            "id": int(key, 16),
            "id_hex": key,
            "raw": raw_value,
            "raw_hex": raw_hex,
            "address": _hex(address),
            "source": source,
            "source_index": source_index,
            "denominator": denominator,
        }
        contributions[key] = {
            "enabled": enabled,
            "specific_flag_raw": specific,
            "special_flag_raw": special,
            "scaled": scaled,
            "raw": raw_value,
            "raw_hex": raw_hex,
            "denominator": denominator,
        }
    processor["inputs"] = inputs
    processor["contributions"] = contributions
    nonzero = [key for key, item in contributions.items() if item["enabled"] and item["scaled"] != 0]
    processor["thread_context_status"] = "unavailable_nonzero_contribution" if nonzero else "not_required_zero_contribution"
    processor["thread_context_unknown_for"] = nonzero
    callback_raw = _i32(int(modifier["modifier_raw"]) + sum(int(item["scaled"]) for item in contributions.values()))
    processor["callback_raw"] = callback_raw
    processor["callback_raw_hex"] = (callback_raw & 0xFFFFFFFF).to_bytes(4, "little").hex()
    return processor, contributions, callback_raw


def _record_from_known(
    profile: Mapping[str, Any],
    static_guard: Mapping[str, Any],
    runtime_guard: Mapping[str, Any],
    module_base: int,
    country_pointer: int,
    observation: dict[str, Any],
    budget: _ReadBudget,
    callback_raw: int,
) -> dict[str, Any]:
    effective_before_clamp = _i32(1000 + callback_raw)
    value = max(10, effective_before_clamp)
    raw_hex = (value & 0xFFFFFFFF).to_bytes(4, "little").hex()
    observation["callback_raw"] = callback_raw
    observation["callback_raw_hex"] = (callback_raw & 0xFFFFFFFF).to_bytes(4, "little").hex()
    observation["effective_before_clamp"] = effective_before_clamp
    observation["effective_before_clamp_hex"] = (effective_before_clamp & 0xFFFFFFFF).to_bytes(4, "little").hex()
    observation["effective_raw"] = value
    observation["effective_raw_hex"] = raw_hex
    observation["minimum_clamp"] = 10
    observation["read_budget"] = {
        "bytes_reserved": budget.used,
        "limit": budget.limit,
        "post_guard_bytes": budget.used - int(runtime_guard.get("bytes_reserved", 0)),
    }
    field = {
        "status": "known",
        "complete": COMPLETE,
        "value": value,
        "raw": value,
        "raw_hex": raw_hex,
        "unit": UNIT,
        "scale": SCALE,
        "period": PERIOD,
        "basis": BASIS,
        "value_origin": VALUE_ORIGIN,
    }
    return {
        "status": "observed",
        "record_key": RECORD_KEY,
        "profile_id": profile["profile_id"],
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "module_base": _hex(module_base),
        "country_pointer": _hex(country_pointer),
        "static_contract_guard": _copy_json(static_guard),
        "runtime_code_guard": _copy_json(runtime_guard),
        "fields": {FIELD_KEY: field},
        "values": {FIELD_KEY: value},
        "raw_hex": {FIELD_KEY: raw_hex},
        "raw_bytes_hex": {FIELD_KEY: raw_hex},
        "basis": BASIS,
        "value_origin": VALUE_ORIGIN,
        "period": PERIOD,
        "unit": UNIT,
        "scale": SCALE,
        "complete": COMPLETE,
        "observation": _copy_json(observation),
    }


def read_fields(
    reader: Any,
    module_base: int,
    country_pointer: int,
    profile: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Read one bounded current-country discipline result.

    ``profile`` is an optional already-loaded profile for parent test seams;
    the normal path always reloads and rechecks the pinned profile.
    """
    budget = _ReadBudget()
    try:
        active_profile = dict(profile) if isinstance(profile, Mapping) else _load_profile()
        if isinstance(profile, Mapping) and "_validated_source_evidence" not in active_profile:
            _validate_profile_shape(active_profile)
            active_profile["_validated_source_evidence"] = _validate_source_evidence(active_profile)
    except Exception as exc:
        return _empty_record(
            "static_contract_guard_failed",
            module_base=module_base if type(module_base) is int else None,
            country_pointer=country_pointer if type(country_pointer) is int else None,
            observation={"detail": f"{type(exc).__name__}:{exc}"},
        )
    static_guard = _static_contract_guard(active_profile)
    if static_guard.get("status") != "observed":
        return _empty_record(
            "static_contract_guard_failed",
            profile=active_profile,
            static_guard=static_guard,
            module_base=module_base,
            country_pointer=country_pointer,
            read_budget={"bytes_reserved": 0, "limit": budget.limit, "post_guard_bytes": 0},
        )
    if not _valid_address(module_base) or not _valid_address(country_pointer):
        return _empty_record(
            "pointer_invalid",
            profile=active_profile,
            static_guard=static_guard,
            module_base=module_base if type(module_base) is int else None,
            country_pointer=country_pointer if type(country_pointer) is int else None,
            read_budget={"bytes_reserved": 0, "limit": budget.limit, "post_guard_bytes": 0},
        )
    runtime_guard = _runtime_code_guard(reader, module_base, active_profile, budget)
    if runtime_guard.get("status") != "observed":
        return _empty_record(
            "runtime_code_guard_failed",
            profile=active_profile,
            static_guard=static_guard,
            runtime_guard=runtime_guard,
            module_base=module_base,
            country_pointer=country_pointer,
            read_budget={"bytes_reserved": budget.used, "limit": budget.limit, "post_guard_bytes": 0},
        )
    observation: dict[str, Any] = {
        "record_key": RECORD_KEY,
        "profile_id": active_profile["profile_id"],
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "module_base": _hex(module_base),
        "country_pointer": _hex(country_pointer),
        "basis": BASIS,
        "value_origin": VALUE_ORIGIN,
        "period": PERIOD,
        "unit": UNIT,
        "scale": SCALE,
        "complete": COMPLETE,
        "static_contract_guard": _copy_json(static_guard),
        "code_guard": _copy_json(runtime_guard),
    }
    try:
        layout = _profile_layout(active_profile)
        modifier = _read_modifier(reader, country_pointer, layout, budget)
        observation["modifier"] = modifier
        processor, _contributions, callback_raw = _read_processor(
            reader, module_base, layout, modifier, budget, observation
        )
        observation["processor"] = processor
        if processor.get("thread_context_status") == "unavailable_nonzero_contribution":
            return _empty_record(
                "MILITARY_PROCESSOR_THREAD_CONTEXT_UNAVAILABLE",
                profile=active_profile,
                static_guard=static_guard,
                runtime_guard=runtime_guard,
                module_base=module_base,
                country_pointer=country_pointer,
                observation=observation,
                read_budget={"bytes_reserved": budget.used, "limit": budget.limit, "post_guard_bytes": budget.used - runtime_guard["bytes_reserved"]},
            )
        return _record_from_known(
            active_profile, static_guard, runtime_guard, module_base, country_pointer,
            observation, budget, callback_raw,
        )
    except ReadError as exc:
        observation.update(exc.detail)
        return _empty_record(
            exc.reason,
            profile=active_profile,
            static_guard=static_guard,
            runtime_guard=runtime_guard,
            module_base=module_base,
            country_pointer=country_pointer,
            observation=observation,
            read_budget={"bytes_reserved": budget.used, "limit": budget.limit, "post_guard_bytes": budget.used - runtime_guard["bytes_reserved"]},
        )
    except (ProfileError, TypeError, ValueError, OverflowError) as exc:
        observation["detail"] = f"{type(exc).__name__}:{exc}"
        return _empty_record(
            "MILITARY_EFFECTIVE_READ_FAILED",
            profile=active_profile,
            static_guard=static_guard,
            runtime_guard=runtime_guard,
            module_base=module_base,
            country_pointer=country_pointer,
            observation=observation,
            read_budget={"bytes_reserved": budget.used, "limit": budget.limit, "post_guard_bytes": budget.used - runtime_guard["bytes_reserved"]},
        )


def _valid_hex_address(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return _valid_address(int(value, 0))
    except (TypeError, ValueError):
        return False


def _runtime_guard_valid(guard: Any, profile: Mapping[str, Any], module_base: int) -> bool:
    if not isinstance(guard, Mapping) or guard.get("status") != "observed" or guard.get("module_base") != _hex(module_base):
        return False
    if guard.get("unknown_conditions") not in ([], None):
        return False
    try:
        expected = {name: (rva, end, raw) for name, rva, end, raw in _profile_code_guards(profile)}
    except ProfileError:
        return False
    checks = guard.get("checks")
    records = guard.get("records")
    if not isinstance(checks, Mapping) or not isinstance(records, Mapping):
        return False
    if set(checks) != set(expected) or set(records) != set(expected):
        return False
    for name, (rva, end, raw) in expected.items():
        if checks.get(name) is not True:
            return False
        item = records.get(name)
        if not isinstance(item, Mapping):
            return False
        digest = hashlib.sha256(raw).hexdigest()
        if (
            item.get("rva") != hex(rva)
            or item.get("rva_end_exclusive") != hex(end)
            or item.get("address") != _hex(module_base + rva)
            or item.get("expected_hex") != raw.hex()
            or item.get("actual_hex") != raw.hex()
            or item.get("expected_sha256") != digest
            or item.get("actual_sha256") != digest
        ):
            return False
    return (
        type(guard.get("bytes_reserved")) is int
        and type(guard.get("limit")) is int
        and 0 < guard["bytes_reserved"] <= guard["limit"] <= READ_BUDGET_BYTES
    )


def _static_guard_valid(guard: Any, profile: Mapping[str, Any]) -> bool:
    return isinstance(guard, Mapping) and guard == _static_contract_guard(profile)


def _validate_modifier(observation: Mapping[str, Any], country_pointer: int) -> tuple[bool, int]:
    modifier = observation.get("modifier")
    if not isinstance(modifier, Mapping):
        return False, 0
    if modifier.get("modifier_id") != MODIFIER_ID:
        return False, 0
    try:
        object_ptr = int(str(modifier["modifier_object"]), 0)
        state_addr = _add_address(country_pointer, COUNTRY_CACHE_STATE_OFFSET)
        object_addr = _add_address(country_pointer, COUNTRY_MODIFIER_OBJECT_OFFSET)
        if (
            modifier.get("cache_state_address") != _hex(state_addr)
            or object_ptr != object_addr
            or modifier.get("modifier_object") != _hex(object_addr)
            or modifier.get("dense_flag_address") != _hex(object_ptr + MODIFIER_DENSE_FLAG_OFFSET)
            or modifier.get("values_pointer_address") != _hex(object_ptr + MODIFIER_VALUES_POINTER_OFFSET)
            or modifier.get("sparse_count_address") != _hex(object_ptr + MODIFIER_SPARSE_COUNT_OFFSET)
            or modifier.get("dense_flag_raw") not in (0, 1)
            or modifier.get("dense_flag_hex") != bytes([modifier.get("dense_flag_raw", 0)]).hex()
        ):
            return False, 0
        if modifier.get("cache_state") == 1:
            return False, 0
        values_pointer_raw = modifier.get("values_pointer")
        values_pointer = int(values_pointer_raw, 0) if isinstance(values_pointer_raw, str) else None
        count = modifier.get("sparse_count")
        if type(count) is not int or count < 0 or count > MAX_SPARSE_COUNT:
            return False, 0
        mode = modifier.get("mode")
        if mode == "dense":
            if modifier.get("dense_flag_raw") == 0:
                return False, 0
            if values_pointer is None or not _valid_address(values_pointer):
                return False, 0
            raw_hex = modifier.get("storage_raw_hex")
            if not isinstance(raw_hex, str) or len(raw_hex) != 8:
                return False, 0
            raw = bytes.fromhex(raw_hex)
            value = int.from_bytes(raw, "little", signed=True)
            if modifier.get("storage_address") != _hex(values_pointer + DENSE_MODIFIER_VALUE_OFFSET):
                return False, 0
            if modifier.get("modifier_raw") != value or modifier.get("modifier_raw_hex") != raw_hex:
                return False, 0
            if modifier.get("first_match_index") is not None or modifier.get("entries") != []:
                return False, 0
            return True, value
        if mode != "sparse" or modifier.get("dense_flag_raw") != 0:
            return False, 0
        raw_hex = modifier.get("storage_raw_hex")
        if not isinstance(raw_hex, str) or len(raw_hex) != count * 16:
            return False, 0
        raw_table = bytes.fromhex(raw_hex)
        entries = modifier.get("entries")
        if not isinstance(entries, list) or len(entries) != count:
            return False, 0
        first_index = None
        value = 0
        for index in range(count):
            start = index * 8
            key_raw = raw_table[start : start + 4]
            value_raw = raw_table[start + 4 : start + 8]
            key = int.from_bytes(key_raw, "little", signed=False)
            item = entries[index]
            item_value = int.from_bytes(value_raw, "little", signed=True)
            if not isinstance(item, Mapping) or {
                "index": item.get("index"),
                "address": item.get("address"),
                "key": item.get("key"),
                "key_hex": item.get("key_hex"),
                "value": item.get("value"),
                "value_hex": item.get("value_hex"),
            } != {
                "index": index,
                "address": _hex(values_pointer + start) if values_pointer is not None else None,
                "key": key,
                "key_hex": key_raw.hex(),
                "value": item_value,
                "value_hex": value_raw.hex(),
            }:
                return False, 0
            if first_index is None and key == MODIFIER_ID:
                first_index = index
                value = item_value
        if modifier.get("first_match_index") != first_index:
            return False, 0
        expected_value_hex = (value & 0xFFFFFFFF).to_bytes(4, "little").hex()
        if modifier.get("modifier_raw") != value or modifier.get("modifier_raw_hex") != expected_value_hex:
            return False, 0
        if count and (values_pointer is None or modifier.get("storage_address") != _hex(values_pointer)):
            return False, 0
        if not count and modifier.get("storage_address") not in (None, _hex(values_pointer) if values_pointer else None):
            return False, 0
        return True, value
    except (KeyError, TypeError, ValueError, OverflowError):
        return False, 0


def _validate_processor(observation: Mapping[str, Any], module_base: int, modifier_raw: int) -> tuple[bool, int]:
    processor = observation.get("processor")
    if not isinstance(processor, Mapping):
        return False, 0
    try:
        manager = int(str(processor["manager_pointer"]), 0)
        manager_addr = _add_address(module_base, MODIFIER_DATABASE_GLOBAL_RVA)
        slot_offset = MODIFIER_RECORD_INDEX * MODIFIER_RECORD_STRIDE + MODIFIER_PROCESSOR_OFFSET
        slot_addr = _add_address(manager, slot_offset)
        if processor.get("manager_global_address") != _hex(manager_addr) or processor.get("slot_address") != _hex(slot_addr):
            return False, 0
        pointer_raw = processor.get("processor_pointer")
        pointer = int(pointer_raw, 0) if isinstance(pointer_raw, str) else 0
        status = processor.get("status")
        if status == "absent":
            if pointer != 0 or processor.get("thread_context_status") != "not_required_no_processor":
                return False, 0
            return True, _i32(modifier_raw)
        if status != "recognized" or not _valid_address(pointer):
            return False, 0
        expected_vtable = _add_address(module_base, PROCESSOR_VTABLE_RVA)
        expected_method = _add_address(module_base, PROCESSOR_METHOD_RVA)
        if processor.get("vtable_pointer") != _hex(expected_vtable) or processor.get("method_pointer") != _hex(expected_method):
            return False, 0
        flags = processor.get("global_flags")
        if not isinstance(flags, Mapping):
            return False, 0
        special = flags.get("special")
        if not isinstance(special, Mapping) or type(special.get("raw")) is not int or special.get("rva") != hex(SPECIAL_FLAG_RVA) or special.get("address") != _hex(module_base + SPECIAL_FLAG_RVA) or special.get("raw_hex") != bytes([special["raw"]]).hex():
            return False, 0
        inputs = processor.get("inputs")
        contributions = processor.get("contributions")
        if not isinstance(inputs, Mapping) or not isinstance(contributions, Mapping) or set(inputs) != set(PROCESSOR_DENSE_OFFSETS) or set(contributions) != set(PROCESSOR_DENSE_OFFSETS):
            return False, 0
        modifier = observation.get("modifier")
        if not isinstance(modifier, Mapping):
            return False, 0
        storage_mode = modifier.get("mode")
        values_pointer_raw = modifier.get("values_pointer")
        values_pointer = int(values_pointer_raw, 0) if isinstance(values_pointer_raw, str) else None
        entries = modifier.get("entries") if storage_mode == "sparse" else None
        total = 0
        any_nonzero = False
        for key in PROCESSOR_DENSE_OFFSETS:
            flag = flags.get(key)
            item = inputs.get(key)
            contribution = contributions.get(key)
            if not all(isinstance(value, Mapping) for value in (flag, item, contribution)):
                return False, 0
            flag_raw = flag.get("raw")
            if type(flag_raw) is not int or flag.get("rva") != hex(GLOBAL_FLAG_RVAS[key]) or flag.get("address") != _hex(module_base + GLOBAL_FLAG_RVAS[key]) or flag.get("raw_hex") != bytes([flag_raw]).hex():
                return False, 0
            enabled = flag_raw == 0 or special["raw"] != 0
            if flag.get("enabled") is not enabled:
                return False, 0
            raw = item.get("raw")
            raw_hex = item.get("raw_hex")
            if type(raw) is not int or not isinstance(raw_hex, str) or raw_hex != (raw & 0xFFFFFFFF).to_bytes(4, "little").hex() or item.get("id") != int(key, 16) or item.get("id_hex") != key or item.get("denominator") != PROCESSOR_DENOMINATORS[key]:
                return False, 0
            if storage_mode == "dense" and item.get("source") == "dense_values":
                if values_pointer is None or item.get("address") != _hex(values_pointer + PROCESSOR_DENSE_OFFSETS[key]):
                    return False, 0
            elif storage_mode == "sparse" and item.get("source") == "sparse_first_match":
                source_index = item.get("source_index")
                if not isinstance(entries, list) or type(source_index) is not int or source_index < 0 or source_index >= len(entries):
                    return False, 0
                if item.get("address") != _hex(values_pointer + source_index * 8 + 4):
                    return False, 0
                source_entry = entries[source_index]
                if not isinstance(source_entry, Mapping) or source_entry.get("key") != int(key, 16) or source_entry.get("value") != raw or source_entry.get("value_hex") != raw_hex:
                    return False, 0
            elif storage_mode == "sparse" and item.get("source") == "sparse_missing_defaults_zero":
                if item.get("address") is not None or item.get("source_index") is not None or raw != 0:
                    return False, 0
            else:
                return False, 0
            expected_scaled = _trunc_zero(raw * 1000, PROCESSOR_DENOMINATORS[key]) if enabled else 0
            if contribution.get("enabled") is not enabled or contribution.get("specific_flag_raw") != flag_raw or contribution.get("special_flag_raw") != special["raw"] or contribution.get("raw") != raw or contribution.get("raw_hex") != raw_hex or contribution.get("denominator") != PROCESSOR_DENOMINATORS[key] or contribution.get("scaled") != expected_scaled:
                return False, 0
            total += expected_scaled
            any_nonzero = any_nonzero or (enabled and expected_scaled != 0)
        expected_status = "unavailable_nonzero_contribution" if any_nonzero else "not_required_zero_contribution"
        if processor.get("thread_context_status") != expected_status or processor.get("thread_context_unknown_for") != [key for key in PROCESSOR_DENSE_OFFSETS if contributions[key].get("enabled") and contributions[key].get("scaled") != 0]:
            return False, 0
        callback = _i32(modifier_raw + total)
        if processor.get("callback_raw") != callback or processor.get("callback_raw_hex") != (callback & 0xFFFFFFFF).to_bytes(4, "little").hex():
            return False, 0
        if any_nonzero:
            return False, 0
        return True, callback
    except (KeyError, TypeError, ValueError, OverflowError, ReadError):
        return False, 0


def validate_record(record: Any) -> bool:
    """Recompute the profile, guard, keyed storage and fixed arithmetic."""
    if not isinstance(record, Mapping) or record.get("status") != "observed":
        return False
    try:
        profile = _load_profile()
        if record.get("record_key") != RECORD_KEY or record.get("profile_id") != profile.get("profile_id") or record.get("profile_sha256") != EXPECTED_PROFILE_SHA256:
            return False
        module_base = int(record.get("module_base"), 0)
        country_pointer = int(record.get("country_pointer"), 0)
        if not _valid_address(module_base) or not _valid_address(country_pointer):
            return False
        if not _static_guard_valid(record.get("static_contract_guard"), profile):
            return False
        if not _runtime_guard_valid(record.get("runtime_code_guard"), profile, module_base):
            return False
        if any(record.get(key) != expected for key, expected in (("basis", BASIS), ("value_origin", VALUE_ORIGIN), ("period", PERIOD), ("unit", UNIT), ("scale", SCALE), ("complete", COMPLETE))):
            return False
        fields = record.get("fields")
        values = record.get("values")
        raw_hexes = record.get("raw_hex")
        raw_bytes_hexes = record.get("raw_bytes_hex")
        if not all(isinstance(item, Mapping) for item in (fields, values, raw_hexes, raw_bytes_hexes)):
            return False
        if set(fields) != set(FIELDS) or set(values) != set(FIELDS) or set(raw_hexes) != set(FIELDS) or set(raw_bytes_hexes) != set(FIELDS):
            return False
        value = values[FIELD_KEY]
        if type(value) is not int or value < 10:
            return False
        expected_hex = (value & 0xFFFFFFFF).to_bytes(4, "little").hex()
        item = fields[FIELD_KEY]
        if not isinstance(item, Mapping) or item.get("status") != "known" or item.get("complete") is not COMPLETE or item.get("value") != value or item.get("raw") != value or item.get("raw_hex") != expected_hex or item.get("unit") != UNIT or item.get("scale") != SCALE or item.get("period") != PERIOD or item.get("basis") != BASIS or item.get("value_origin") != VALUE_ORIGIN or raw_hexes[FIELD_KEY] != expected_hex or raw_bytes_hexes[FIELD_KEY] != expected_hex:
            return False
        observation = record.get("observation")
        if not isinstance(observation, Mapping):
            return False
        if any(observation.get(key) != record.get(key) for key in ("record_key", "profile_id", "profile_sha256", "module_base", "country_pointer", "basis", "value_origin", "period", "unit", "scale", "complete")):
            return False
        if observation.get("static_contract_guard") != record.get("static_contract_guard") or observation.get("code_guard") != record.get("runtime_code_guard"):
            return False
        valid_modifier, modifier_raw = _validate_modifier(observation, country_pointer)
        if not valid_modifier:
            return False
        valid_processor, callback_raw = _validate_processor(observation, module_base, modifier_raw)
        if not valid_processor:
            return False
        expected_before = _i32(1000 + callback_raw)
        expected_value = max(10, expected_before)
        if expected_value != value or observation.get("callback_raw") != callback_raw or observation.get("effective_before_clamp") != expected_before or observation.get("effective_raw") != value or observation.get("minimum_clamp") != 10:
            return False
        if observation.get("callback_raw_hex") != (callback_raw & 0xFFFFFFFF).to_bytes(4, "little").hex() or observation.get("effective_before_clamp_hex") != (expected_before & 0xFFFFFFFF).to_bytes(4, "little").hex() or observation.get("effective_raw_hex") != expected_hex:
            return False
        read_budget = observation.get("read_budget")
        runtime_budget = record["runtime_code_guard"].get("bytes_reserved")
        if not isinstance(read_budget, Mapping) or type(read_budget.get("bytes_reserved")) is not int or type(read_budget.get("limit")) is not int or type(read_budget.get("post_guard_bytes")) is not int or read_budget.get("limit") != READ_BUDGET_BYTES or read_budget.get("bytes_reserved") != runtime_budget + read_budget.get("post_guard_bytes") or not 0 < read_budget["bytes_reserved"] <= read_budget["limit"] <= READ_BUDGET_BYTES:
            return False
        return True
    except (KeyError, TypeError, ValueError, OverflowError, OSError, ProfileError, ReadError):
        return False


def retract_record(record: Any, reason: str = "observation_retracted") -> dict[str, Any]:
    """Retract consumable known data after a failed second pass or cleanup."""
    result = _empty_record(reason)
    if isinstance(record, Mapping):
        for key in ("record_key", "profile_id", "profile_sha256", "module_base", "country_pointer", "basis", "value_origin", "period", "unit", "scale", "complete"):
            if key in record:
                result[key] = _copy_json(record[key])
                result["observation"][key] = _copy_json(record[key])
    return result


__all__ = [
    "PROFILE_FILE", "PROFILE_MAX_BYTES", "SOURCE_EVIDENCE_MAX_BYTES", "EXPECTED_PROFILE_SHA256",
    "EXPECTED_EXE_SHA256", "EXPECTED_VERSION", "EXPECTED_COUNTRY", "FIELDS", "RECORD_KEY",
    "FIELD_KEY", "BASIS", "VALUE_ORIGIN", "PERIOD", "UNIT", "SCALE", "COMPLETE",
    "COUNTRY_CACHE_STATE_OFFSET", "COUNTRY_MODIFIER_OBJECT_OFFSET", "READ_BUDGET_BYTES",
    "ProfileError", "ReadError", "read_fields", "validate_record", "retract_record",
    "_load_profile", "_profile_layout", "_profile_code_guards", "_runtime_code_guard",
    "_static_contract_guard", "_ReadBudget", "_reader_read",
]
