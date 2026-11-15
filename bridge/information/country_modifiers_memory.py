"""Bounded reader for the fixed-build country modifier instance list.

The country resource parent owns process identity, lifecycle, and the two-pass
comparison.  This child only reads the intrusive list and the already observed
definition/effect storage.  It never calls a native function and never writes
target memory.  A modifier definition key is copied from its native stable
string; no display name or missing date/effect value is synthesized.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "country-modifiers-memory-1374-v2.json"
PROFILE_MAX_BYTES = 64 * 1024
SOURCE_EVIDENCE_MAX_BYTES = 128 * 1024
EXPECTED_PROFILE_SHA256 = "da533caf9d3c9bfb21f8fd56bd197ab5935f5aaa1b5e48a861f0fba6c54a4c76"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_VERSION = "1.37.4"
EXPECTED_COUNTRY = "FRA"

FIELDS = ("modifiers",)
FIELD_KEY = "modifiers"
BASIS = "native_country_modifier_instances"
VALUE_ORIGIN = "copied_native_country_modifier_instances"
PERIOD = "current"
UNIT = "native_modifier"
SCALE = 1
COMPLETE = True

# The only country-list field proven by the native writer is the head at
# country+0x1f0.  The enclosing owner/header bytes are deliberately not used
# as a count, tail, or previous-link contract.
COUNTRY_LIST_HEAD_OFFSET = 0x1F0
NODE_ITEM_OFFSET = 0x0
NODE_NEXT_OFFSET = 0x10
NODE_WIDTH = 0x18
ITEM_VTABLE_OFFSET = 0x0
ITEM_DEFINITION_OFFSET = 0x30
# Keep the profile's 0x80 width for validating historical snapshots.  The
# bounded live copy uses the 0x50-byte allocation prefix; every consumed
# instance field ends at +0x4b.  Do not read or synthesize the trailing bytes.
ITEM_WIDTH = 0x80
LIVE_ITEM_PREFIX_WIDTH = 0x50
ITEM_START_DATE_OFFSET = 0x40
ITEM_DATE_OFFSET = 0x44
ITEM_FLAG_OFFSETS = {
    "ruler_modifier": 0x48,
    "parliament_modifier": 0x49,
    "permanent": 0x4A,
    "hidden": 0x4B,
}
VTABLE_ENTRIES_WIDTH = 0x18
DEFINITION_VTABLE_RVA = 0x1C42AE0
DEFINITION_PREFIX_WIDTH = 0x178
DEFINITION_EFFECTS_POINTER_OFFSET = 0x58
DEFINITION_EFFECT_COUNT_OFFSET = 0x64
DEFINITION_KEY_OFFSET = 0x158
DEFINITION_KEY_LENGTH_OFFSET = 0x168
DEFINITION_KEY_CAPACITY_OFFSET = 0x170
EFFECT_PAIR_WIDTH = 8
EFFECT_INDEX_OFFSET = 0
EFFECT_RAW_OFFSET = 4
MODIFIER_DATABASE_GLOBAL_RVA = 0x2358060
MODIFIER_RECORD_STRIDE = 0x60
MODIFIER_SELECTOR_OFFSET = 0x50
EXPECTED_VTABLE_RVA = 0x1CE7F08
EXPECTED_VTABLE_METHODS = {0x0: 0xB355E0, 0x8: 0xD2F280, 0x10: 0xB359E0}
MAX_INSTANCES = 128
MAX_EFFECTS = 256
MAX_KEY_BYTES = 255
MAX_SELECTOR_INDEX = 0x1000000
READ_BUDGET_BYTES = 128 * 1024
MAX_USER_ADDRESS = 0x00007FFFFFFFFFFF

# Compatibility aliases for callers that used the initial internal names.
DEFINITION_START_DATE_OFFSET = ITEM_START_DATE_OFFSET
DEFINITION_DATE_OFFSET = ITEM_DATE_OFFSET
DEFINITION_FLAG_OFFSETS = ITEM_FLAG_OFFSETS
DEFINITION_START_OFFSET = ITEM_START_DATE_OFFSET
DEFINITION_END_OFFSET = ITEM_DATE_OFFSET


class ProfileError(RuntimeError):
    """The pinned profile or source evidence is invalid."""


class ReadError(RuntimeError):
    """A bounded child read, pointer, list, or definition check failed."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


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
    root = _workspace_root().resolve()
    path = (root / raw_path).resolve() if not Path(raw_path).is_absolute() else Path(raw_path).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ProfileError("source_evidence_outside_workspace") from exc
    return path


def _validate_source_evidence(profile: Mapping[str, Any]) -> list[dict[str, Any]]:
    items = profile.get("source_evidence")
    if not isinstance(items, list) or not items or len(items) > 8:
        raise ProfileError("source_evidence_shape_invalid")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, Mapping):
            raise ProfileError("source_evidence_item_invalid")
        path = _source_path(item.get("path"))
        digest = item.get("sha256")
        expected_bytes = item.get("bytes")
        if not isinstance(digest, str) or len(digest) != 64 or type(expected_bytes) is not int:
            raise ProfileError("source_evidence_item_invalid")
        key = path.as_posix().lower()
        if key in seen:
            raise ProfileError("source_evidence_duplicate")
        raw = _bounded_bytes(path, SOURCE_EVIDENCE_MAX_BYTES, "source_evidence")
        if len(raw) != expected_bytes or hashlib.sha256(raw).hexdigest().lower() != digest.lower():
            raise ProfileError("source_evidence_digest_mismatch")
        seen.add(key)
        result.append(
            {
                "path": path.relative_to(_workspace_root()).as_posix(),
                "sha256": digest.lower(),
                "bytes": len(raw),
                "role": item.get("role"),
            }
        )
    return result


def _profile_layout(profile: Mapping[str, Any]) -> dict[str, Any]:
    raw = profile.get("layout")
    if not isinstance(raw, Mapping):
        raise ProfileError("profile_layout_missing")
    expected = {
        "country_list_head_offset": COUNTRY_LIST_HEAD_OFFSET,
        "node_item_offset": NODE_ITEM_OFFSET,
        "node_next_offset": NODE_NEXT_OFFSET,
        "node_width": NODE_WIDTH,
        "item_vtable_offset": ITEM_VTABLE_OFFSET,
        "item_definition_offset": ITEM_DEFINITION_OFFSET,
        "item_width": ITEM_WIDTH,
        "item_start_date_offset": ITEM_START_DATE_OFFSET,
        "item_date_offset": ITEM_DATE_OFFSET,
        "vtable_entries_width": VTABLE_ENTRIES_WIDTH,
        "definition_vtable_rva": DEFINITION_VTABLE_RVA,
        "definition_prefix_width": DEFINITION_PREFIX_WIDTH,
        "definition_effects_pointer_offset": DEFINITION_EFFECTS_POINTER_OFFSET,
        "definition_effect_count_offset": DEFINITION_EFFECT_COUNT_OFFSET,
        "definition_key_offset": DEFINITION_KEY_OFFSET,
        "definition_key_length_offset": DEFINITION_KEY_LENGTH_OFFSET,
        "definition_key_capacity_offset": DEFINITION_KEY_CAPACITY_OFFSET,
        "effect_pair_width": EFFECT_PAIR_WIDTH,
        "effect_index_offset": EFFECT_INDEX_OFFSET,
        "effect_raw_offset": EFFECT_RAW_OFFSET,
        "modifier_database_global_rva": MODIFIER_DATABASE_GLOBAL_RVA,
        "modifier_record_stride": MODIFIER_RECORD_STRIDE,
        "modifier_selector_offset": MODIFIER_SELECTOR_OFFSET,
        "expected_vtable_rva": EXPECTED_VTABLE_RVA,
        "max_instances": MAX_INSTANCES,
        "max_effects": MAX_EFFECTS,
        "max_key_bytes": MAX_KEY_BYTES,
        "read_budget_bytes": READ_BUDGET_BYTES,
    }
    result: dict[str, Any] = {}
    for key, expected in expected.items():
        value = _parse_int(raw.get(key), f"layout.{key}")
        if value != expected:
            raise ProfileError(f"profile_layout_value_invalid:{key}")
        result[key] = value
    pointer_min = _parse_int(raw.get("pointer_min"), "layout.pointer_min")
    pointer_max = _parse_int(raw.get("pointer_max"), "layout.pointer_max")
    if pointer_min != 0x10000 or pointer_max != MAX_USER_ADDRESS or pointer_min >= pointer_max:
        raise ProfileError("profile_pointer_bounds_invalid")
    result.update(pointer_min=pointer_min, pointer_max=pointer_max)
    if raw.get("field_key") != FIELD_KEY:
        raise ProfileError("profile_field_key_invalid")
    methods = raw.get("expected_vtable_methods")
    if not isinstance(methods, Mapping) or {
        _parse_int(key, f"layout.expected_vtable_methods.{key}"): _parse_int(value, f"layout.expected_vtable_methods.{key}")
        for key, value in methods.items()
    } != EXPECTED_VTABLE_METHODS:
        raise ProfileError("profile_vtable_methods_invalid")
    result["expected_vtable_methods"] = dict(EXPECTED_VTABLE_METHODS)
    flag_offsets = raw.get("item_flag_offsets")
    if not isinstance(flag_offsets, Mapping) or {
        name: _parse_int(flag_offsets.get(name), f"layout.definition_flag_offsets.{name}")
        for name in ITEM_FLAG_OFFSETS
    } != ITEM_FLAG_OFFSETS:
        raise ProfileError("profile_item_flag_offsets_invalid")
    result["item_flag_offsets"] = dict(ITEM_FLAG_OFFSETS)
    return result


def _profile_code_guards(profile: Mapping[str, Any]) -> list[tuple[str, int, int, bytes]]:
    raw_guards = profile.get("code_guards")
    if not isinstance(raw_guards, list) or not raw_guards:
        raise ProfileError("profile_code_guards_shape_invalid")
    result: list[tuple[str, int, int, bytes]] = []
    seen: set[str] = set()
    total = 0
    for item in raw_guards:
        if not isinstance(item, Mapping):
            raise ProfileError("profile_code_guard_invalid")
        name = item.get("name")
        if not isinstance(name, str) or not name or name in seen:
            raise ProfileError("profile_code_guard_name_invalid")
        begin = _parse_int(item.get("rva"), f"code_guard.{name}.rva")
        end = _parse_int(item.get("rva_end_exclusive"), f"code_guard.{name}.end")
        try:
            raw = bytes.fromhex(str(item.get("hex", "")))
        except ValueError as exc:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}") from exc
        if not raw or end <= begin or len(raw) != end - begin:
            raise ProfileError(f"profile_code_guard_range_invalid:{name}")
        if item.get("sha256") != hashlib.sha256(raw).hexdigest() or item.get("aslr_invariant") is not True:
            raise ProfileError(f"profile_code_guard_metadata_invalid:{name}")
        total += len(raw)
        if total > READ_BUDGET_BYTES:
            raise ProfileError("profile_code_guards_budget_invalid")
        seen.add(name)
        result.append((name, begin, end, raw))
    return result


def _validate_profile_shape(profile: Mapping[str, Any]) -> None:
    if profile.get("profile_id") != "country-modifiers-memory-1374-v2":
        raise ProfileError("profile_shape_invalid")
    if profile.get("game_version") != EXPECTED_VERSION:
        raise ProfileError("profile_version_mismatch")
    executable = profile.get("executable")
    if not isinstance(executable, Mapping) or str(executable.get("sha256", "")).lower() != EXPECTED_EXE_SHA256:
        raise ProfileError("profile_executable_mismatch")
    _validate_source_evidence(profile)
    _profile_layout(profile)
    semantics = profile.get("semantics")
    if not isinstance(semantics, Mapping) or {
        key: semantics.get(key)
        for key in ("field", "basis", "value_origin", "period", "unit", "scale", "complete")
    } != {
        "field": FIELD_KEY,
        "basis": BASIS,
        "value_origin": VALUE_ORIGIN,
        "period": PERIOD,
        "unit": UNIT,
        "scale": SCALE,
        "complete": COMPLETE,
    }:
        raise ProfileError("profile_semantics_invalid")
    static = profile.get("static_property")
    if not isinstance(static, Mapping) or {
        static.get("field_key"),
        static.get("list_writer_rva"),
        static.get("content_writer_rva"),
        static.get("definition_vtable_rva"),
        static.get("vtable_rva"),
        static.get("selector_global_rva"),
    } != {
        FIELD_KEY,
        hex(0x2E0076),
        hex(0xB359E0),
        hex(DEFINITION_VTABLE_RVA),
        hex(EXPECTED_VTABLE_RVA),
        hex(MODIFIER_DATABASE_GLOBAL_RVA),
    }:
        raise ProfileError("profile_static_property_invalid")
    _profile_code_guards(profile)


def _load_profile(path: Path | None = None, expected_sha256: str | None = None) -> dict[str, Any]:
    path = PROFILE_FILE if path is None else Path(path)
    expected = EXPECTED_PROFILE_SHA256 if expected_sha256 is None else expected_sha256
    if not isinstance(expected, str) or len(expected) != 64 or "__" in expected:
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
    return hex(value) if type(value) is int else None


def _valid_address(value: Any, *, minimum: int = 0x10000, maximum: int = MAX_USER_ADDRESS) -> bool:
    return type(value) is int and minimum <= value <= maximum


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
        self.reads: list[dict[str, Any]] = []

    def reserve(self, size: int) -> None:
        if type(size) is not int or size <= 0 or self.used + size > self.limit:
            raise ReadError("read_budget_exceeded")
        self.used += size

    def snapshot(self) -> dict[str, Any]:
        return {"bytes_reserved": self.used, "limit": self.limit}


def _reader_read(reader: Any, address: int, size: int, label: str, budget: _ReadBudget) -> bytes:
    if not _valid_address(address):
        raise ReadError(f"address_invalid:{label}")
    budget.reserve(size)
    method = getattr(reader, "read", None)
    if not callable(method):
        budget.reads.append({"address": _hex(address), "size": size, "label": label, "status": "failed"})
        raise ReadError("reader_read_method_missing")
    try:
        raw = method(address, size, label)
    except Exception as exc:
        budget.reads.append({"address": _hex(address), "size": size, "label": label, "status": "failed", "error": type(exc).__name__})
        raise ReadError(f"read_failed:{label}:{type(exc).__name__}:{exc}") from exc
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != size:
        budget.reads.append({"address": _hex(address), "size": size, "label": label, "status": "failed", "error": "short_or_invalid_read"})
        raise ReadError(f"short_or_invalid_read:{label}")
    result = bytes(raw)
    budget.reads.append({
        "address": _hex(address), "size": size, "label": label, "status": "ok",
        "raw_hex": result.hex(), "sha256": hashlib.sha256(result).hexdigest(),
    })
    return result


def _read_u64(reader: Any, address: int, label: str, budget: _ReadBudget) -> tuple[int, bytes]:
    raw = _reader_read(reader, address, 8, label, budget)
    return int.from_bytes(raw, "little", signed=False), raw


def _read_u32(reader: Any, address: int, label: str, budget: _ReadBudget) -> tuple[int, bytes]:
    raw = _reader_read(reader, address, 4, label, budget)
    return int.from_bytes(raw, "little", signed=False), raw


def _read_i32(reader: Any, address: int, label: str, budget: _ReadBudget) -> tuple[int, bytes]:
    raw = _reader_read(reader, address, 4, label, budget)
    return int.from_bytes(raw, "little", signed=True), raw


def _static_contract_guard(profile: Mapping[str, Any] | None = None, reason: str | None = None) -> dict[str, Any]:
    if not isinstance(profile, Mapping):
        return {
            "status": "unknown", "profile_id": "country-modifiers-memory-1374-v2",
            "profile_sha256": EXPECTED_PROFILE_SHA256, "checks": {}, "source_evidence": [],
            "unknown_conditions": [reason or "profile_unavailable"],
        }
    try:
        source = profile.get("_validated_source_evidence", _validate_source_evidence(profile))
        checks = {
            "profile_id": profile.get("profile_id") == "country-modifiers-memory-1374-v2",
            "game_version": profile.get("game_version") == EXPECTED_VERSION,
            "executable_sha256": isinstance(profile.get("executable"), Mapping)
            and str(profile["executable"].get("sha256", "")).lower() == EXPECTED_EXE_SHA256,
            "source_evidence": isinstance(source, list) and bool(source),
            "layout": _profile_layout(profile),
            "semantics": isinstance(profile.get("semantics"), Mapping)
            and profile["semantics"].get("field") == FIELD_KEY
            and profile["semantics"].get("basis") == BASIS
            and profile["semantics"].get("value_origin") == VALUE_ORIGIN
            and profile["semantics"].get("period") == PERIOD
            and profile["semantics"].get("unit") == UNIT
            and profile["semantics"].get("scale") == SCALE
            and profile["semantics"].get("complete") is COMPLETE,
            "code_guards": bool(_profile_code_guards(profile)),
        }
        checks["layout"] = checks["layout"] == _profile_layout(profile)
        failed = [name for name, value in checks.items() if value is not True]
        return {
            "status": "observed" if not failed else "unknown",
            "profile_id": profile.get("profile_id"), "profile_sha256": EXPECTED_PROFILE_SHA256,
            "checks": checks, "source_evidence": _copy_json(source) if isinstance(source, list) else [],
            "unknown_conditions": ["profile_contract_failed:" + ",".join(failed)] if failed else [],
        }
    except Exception as exc:
        return {
            "status": "unknown", "profile_id": profile.get("profile_id"),
            "profile_sha256": EXPECTED_PROFILE_SHA256, "checks": {}, "source_evidence": [],
            "unknown_conditions": [f"profile_contract_failed:{type(exc).__name__}:{exc}"],
        }


def _unknown_field(reason: str) -> dict[str, Any]:
    return {
        "status": "unknown", "reason": reason, "complete": False, "value": None,
        "unit": UNIT, "scale": SCALE, "period": PERIOD,
        "basis": BASIS, "value_origin": VALUE_ORIGIN,
    }


def _empty_record(
    reason: str,
    *,
    static_guard: Mapping[str, Any] | None = None,
    runtime_guard: Mapping[str, Any] | None = None,
    module_base: int | None = None,
    country_pointer: int | None = None,
    read_budget: Mapping[str, Any] | None = None,
    read_log: list[Mapping[str, Any]] | None = None,
    profile_id: str = "country-modifiers-memory-1374-v2",
) -> dict[str, Any]:
    budget = _copy_json(read_budget) if isinstance(read_budget, Mapping) else {"bytes_reserved": 0, "limit": READ_BUDGET_BYTES}
    logs = _copy_json(read_log) if isinstance(read_log, list) else []
    observation = {
        "profile_id": profile_id, "profile_sha256": EXPECTED_PROFILE_SHA256,
        "module_base": _hex(module_base), "country_pointer": _hex(country_pointer),
        "basis": BASIS, "unit": UNIT, "scale": SCALE, "period": PERIOD, "value_origin": VALUE_ORIGIN,
        "static_contract_guard": _copy_json(static_guard) if isinstance(static_guard, Mapping) else None,
        "runtime_code_guard": _copy_json(runtime_guard) if isinstance(runtime_guard, Mapping) else None,
        "read_budget": budget, "read_log": logs,
    }
    return {
        "status": "unknown", "reason": reason, "profile_id": profile_id,
        "profile_sha256": EXPECTED_PROFILE_SHA256, "module_base": _hex(module_base),
        "country_pointer": _hex(country_pointer),
        "static_contract_guard": _copy_json(static_guard) if isinstance(static_guard, Mapping) else None,
        "runtime_code_guard": _copy_json(runtime_guard) if isinstance(runtime_guard, Mapping) else None,
        "fields": {FIELD_KEY: _unknown_field(reason)}, "values": None,
        "raw_hex": None, "raw_bytes_hex": None, "basis": BASIS, "unit": UNIT,
        "scale": SCALE, "period": PERIOD, "value_origin": VALUE_ORIGIN,
        "observation": observation,
    }


def _runtime_code_guard(reader: Any, module_base: int, profile: Mapping[str, Any], budget: _ReadBudget) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "module_base": _hex(module_base), "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        for name, rva, end, expected in _profile_code_guards(profile):
            actual = _reader_read(reader, _add_address(module_base, rva), len(expected), f"country_modifiers.code.{name}", budget)
            result["records"][name] = {
                "rva": hex(rva), "rva_end_exclusive": hex(end), "address": _hex(module_base + rva),
                "expected_hex": expected.hex(), "actual_hex": actual.hex(),
                "expected_sha256": hashlib.sha256(expected).hexdigest(), "actual_sha256": hashlib.sha256(actual).hexdigest(),
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
    result["read_log"] = _copy_json(budget.reads)
    return result


def _ascii_key(payload: bytes) -> str:
    if not payload or payload[-1:] != b"\0":
        raise ReadError("modifier_key_missing_nul")
    key_bytes = payload[:-1]
    if not key_bytes or len(key_bytes) > MAX_KEY_BYTES:
        raise ReadError("modifier_key_length_out_of_bound")
    allowed = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
    if any(byte not in allowed for byte in key_bytes):
        raise ReadError("modifier_key_not_stable_ascii")
    try:
        return key_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ReadError("modifier_key_not_ascii") from exc


def _read_definition(
    reader: Any,
    module_base: int,
    definition_address: int,
    manager_pointer: int,
    item_raw: bytes,
    layout: Mapping[str, Any],
    budget: _ReadBudget,
    ordinal: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    prefix_address = definition_address
    prefix = _reader_read(reader, prefix_address, layout["definition_prefix_width"], f"country_modifiers.definition_{ordinal}", budget)
    definition_vtable = int.from_bytes(prefix[:8], "little")
    expected_definition_vtable = _add_address(module_base, layout["definition_vtable_rva"])
    if definition_vtable != expected_definition_vtable:
        raise ReadError("modifier_definition_vtable_unsupported")
    length = int.from_bytes(prefix[layout["definition_key_length_offset"]:layout["definition_key_length_offset"] + 8], "little")
    capacity = int.from_bytes(prefix[layout["definition_key_capacity_offset"]:layout["definition_key_capacity_offset"] + 8], "little")
    if length <= 0 or length > layout["max_key_bytes"] or capacity < length:
        raise ReadError("modifier_key_metadata_invalid")
    key_field = prefix[layout["definition_key_offset"]:layout["definition_key_offset"] + 8]
    key_pointer = int.from_bytes(key_field, "little")
    if capacity < 0x10:
        key_address = definition_address + layout["definition_key_offset"]
        end = layout["definition_key_offset"] + length + 1
        if end > len(prefix):
            raise ReadError("modifier_inline_key_out_of_prefix")
        key_raw = prefix[layout["definition_key_offset"]:end]
        storage = "sso_inline"
    else:
        if not _valid_address(key_pointer):
            raise ReadError("modifier_heap_key_pointer_invalid")
        key_address = key_pointer
        key_raw = _reader_read(reader, key_pointer, length + 1, f"country_modifiers.key_{ordinal}", budget)
        storage = "heap"
    key = _ascii_key(key_raw)
    start_raw_bytes = item_raw[layout["item_start_date_offset"]:layout["item_start_date_offset"] + 4]
    date_raw_bytes = item_raw[layout["item_date_offset"]:layout["item_date_offset"] + 4]
    if len(start_raw_bytes) != 4 or len(date_raw_bytes) != 4:
        raise ReadError("modifier_date_fields_missing")
    start_date_raw = int.from_bytes(start_raw_bytes, "little", signed=True)
    date_raw = int.from_bytes(date_raw_bytes, "little", signed=True)
    flags: dict[str, int] = {}
    flags_raw_hex: dict[str, str] = {}
    for name, offset in layout["item_flag_offsets"].items():
        if offset >= len(item_raw):
            raise ReadError("modifier_flag_offset_out_of_prefix")
        flags[name] = item_raw[offset]
        flags_raw_hex[name] = item_raw[offset:offset + 1].hex()
    effects_pointer = int.from_bytes(prefix[layout["definition_effects_pointer_offset"]:layout["definition_effects_pointer_offset"] + 8], "little")
    effect_count = int.from_bytes(prefix[layout["definition_effect_count_offset"]:layout["definition_effect_count_offset"] + 4], "little")
    if effect_count > layout["max_effects"]:
        raise ReadError("modifier_effect_count_out_of_bound")
    pairs: list[dict[str, Any]] = []
    pairs_raw = b""
    if effect_count:
        if not _valid_address(effects_pointer):
            raise ReadError("modifier_effects_pointer_invalid")
        pairs_raw = _reader_read(reader, effects_pointer, effect_count * layout["effect_pair_width"], f"country_modifiers.effect_pairs_{ordinal}", budget)
        for index in range(effect_count):
            begin = index * layout["effect_pair_width"]
            pair = pairs_raw[begin:begin + layout["effect_pair_width"]]
            effect_index = int.from_bytes(pair[layout["effect_index_offset"]:layout["effect_index_offset"] + 4], "little")
            effect_raw = int.from_bytes(pair[layout["effect_raw_offset"]:layout["effect_raw_offset"] + 4], "little", signed=True)
            if effect_index > MAX_SELECTOR_INDEX:
                raise ReadError("modifier_effect_index_out_of_bound")
            selector_address = _add_address(
                manager_pointer,
                effect_index * layout["modifier_record_stride"] + layout["modifier_selector_offset"],
            )
            selector, selector_raw = _read_u32(reader, selector_address, f"country_modifiers.selector_{ordinal}_{index}", budget)
            pairs.append({
                "index": effect_index, "index_raw_hex": pair[0:4].hex(),
                "raw": effect_raw, "raw_hex": pair[4:8].hex(),
                "selector": selector, "selector_raw_hex": selector_raw.hex(),
                "selector_address": _hex(selector_address), "pair_address": _hex(effects_pointer + begin),
                "pair_raw_hex": pair.hex(),
            })
    detail = {
        "key": key, "key_raw_hex": key_raw.hex(), "key_address": _hex(key_address),
        "key_storage": storage, "key_length": length, "key_capacity": capacity,
        "key_pointer_raw_hex": key_field.hex(),
        "start_date_raw": start_date_raw, "start_date_raw_hex": start_raw_bytes.hex(),
        "date_raw": date_raw, "date_raw_hex": date_raw_bytes.hex(),
        "flags": flags, "flags_raw_hex": flags_raw_hex,
        "effects_pointer": _hex(effects_pointer) if effects_pointer else None,
        "effects_pointer_raw_hex": prefix[layout["definition_effects_pointer_offset"]:layout["definition_effects_pointer_offset"] + 8].hex(),
        "effect_count": effect_count, "effect_count_raw_hex": prefix[layout["definition_effect_count_offset"]:layout["definition_effect_count_offset"] + 4].hex(),
        "effect_pairs": pairs, "effects": pairs,
    }
    raw_detail = {
        "definition_address": _hex(definition_address), "definition_prefix_raw_hex": prefix.hex(),
        "definition_vtable": _hex(definition_vtable), "definition_vtable_raw_hex": prefix[:8].hex(),
        "item_start_date_raw_hex": start_raw_bytes.hex(), "item_date_raw_hex": date_raw_bytes.hex(),
        "item_flags_raw_hex": flags_raw_hex,
        "key_raw_hex": key_raw.hex(), "key_address": _hex(key_address), "key_storage": storage,
        "key_length": length, "key_capacity": capacity, "key_pointer_raw_hex": key_field.hex(),
        "effects_pointer_raw_hex": detail["effects_pointer_raw_hex"],
        "effect_count_raw_hex": detail["effect_count_raw_hex"], "effect_pairs_raw_hex": pairs_raw.hex(),
        "definition": detail,
    }
    return detail, raw_detail


def _compact_modifier(detail: Mapping[str, Any]) -> dict[str, Any]:
    pairs = []
    for item in detail.get("effects", detail.get("effect_pairs", [])):
        if not isinstance(item, Mapping):
            continue
        pairs.append({
            "index": item.get("index"),
            "selector": item.get("selector"),
            "raw": item.get("raw"),
            "raw_hex": item.get("raw_hex"),
        })
    return {
        "key": detail.get("key"),
        "start_date_raw": detail.get("start_date_raw"),
        "date_raw": detail.get("date_raw"),
        "flags": _copy_json(detail.get("flags", {})),
        "effects": pairs,
    }


def read_fields(
    reader: Any,
    module_base: int,
    country_pointer: int,
    profile: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Copy the bounded current-country modifier list."""
    try:
        loaded = _load_profile() if profile is None else dict(profile)
        if profile is not None:
            _validate_profile_shape(loaded)
            loaded["_validated_source_evidence"] = _validate_source_evidence(loaded)
    except Exception as exc:
        return _empty_record("static_contract_guard_failed", module_base=module_base if type(module_base) is int else None, country_pointer=country_pointer if type(country_pointer) is int else None) | {"detail": f"{type(exc).__name__}:{exc}"}
    static_guard = _static_contract_guard(loaded)
    try:
        layout = _profile_layout(loaded)
    except Exception as exc:
        return _empty_record(f"static_contract_guard_failed:{type(exc).__name__}", static_guard=static_guard, module_base=module_base, country_pointer=country_pointer)
    budget = _ReadBudget(layout["read_budget_bytes"])
    if static_guard.get("status") != "observed":
        return _empty_record("static_contract_guard_failed", static_guard=static_guard, module_base=module_base, country_pointer=country_pointer, read_budget=budget.snapshot(), read_log=budget.reads)
    if not _valid_address(module_base, minimum=layout["pointer_min"], maximum=layout["pointer_max"]) or not _valid_address(country_pointer, minimum=layout["pointer_min"], maximum=layout["pointer_max"]):
        return _empty_record("pointer_invalid", static_guard=static_guard, module_base=module_base if type(module_base) is int else None, country_pointer=country_pointer if type(country_pointer) is int else None, read_budget=budget.snapshot(), read_log=budget.reads)
    runtime_guard = _runtime_code_guard(reader, module_base, loaded, budget)
    if runtime_guard.get("status") != "observed":
        return _empty_record("runtime_code_guard_failed", static_guard=static_guard, runtime_guard=runtime_guard, module_base=module_base, country_pointer=country_pointer, read_budget=budget.snapshot(), read_log=budget.reads)
    try:
        head_address = _add_address(country_pointer, layout["country_list_head_offset"])
        head_raw = _reader_read(reader, head_address, 8, "country_modifiers.list_head", budget)
        head = int.from_bytes(head_raw, "little")
        if head and not _valid_address(head, minimum=layout["pointer_min"], maximum=layout["pointer_max"]):
            raise ReadError("modifier_node_pointer_invalid")
        manager_global_address = _add_address(module_base, layout["modifier_database_global_rva"])
        manager_pointer, manager_raw = _read_u64(reader, manager_global_address, "country_modifiers.definition_manager_global", budget)
        if not _valid_address(manager_pointer, minimum=layout["pointer_min"], maximum=layout["pointer_max"]):
            raise ReadError("modifier_definition_manager_invalid")
        nodes: list[dict[str, Any]] = []
        compact: list[dict[str, Any]] = []
        raw_projection: list[dict[str, Any]] = []
        current = head
        seen: set[int] = set()
        terminated = False
        for ordinal in range(layout["max_instances"]):
            if not current:
                terminated = True
                break
            if current in seen:
                raise ReadError("modifier_list_cycle_detected")
            if not _valid_address(current, minimum=layout["pointer_min"], maximum=layout["pointer_max"]):
                raise ReadError("modifier_node_pointer_invalid")
            seen.add(current)
            node_raw = _reader_read(reader, current, layout["node_width"], f"country_modifiers.node_{ordinal}", budget)
            item = int.from_bytes(node_raw[layout["node_item_offset"]:layout["node_item_offset"] + 8], "little")
            next_node = int.from_bytes(node_raw[layout["node_next_offset"]:layout["node_next_offset"] + 8], "little")
            if not _valid_address(item, minimum=layout["pointer_min"], maximum=layout["pointer_max"]):
                raise ReadError("modifier_node_item_pointer_invalid")
            if next_node and not _valid_address(next_node, minimum=layout["pointer_min"], maximum=layout["pointer_max"]):
                raise ReadError("modifier_node_next_invalid")
            item_raw = _reader_read(reader, item, LIVE_ITEM_PREFIX_WIDTH, f"country_modifiers.item_{ordinal}", budget)
            vtable = int.from_bytes(item_raw[layout["item_vtable_offset"]:layout["item_vtable_offset"] + 8], "little")
            definition = int.from_bytes(item_raw[layout["item_definition_offset"]:layout["item_definition_offset"] + 8], "little")
            expected_vtable = _add_address(module_base, layout["expected_vtable_rva"])
            if vtable != expected_vtable:
                raise ReadError("modifier_vtable_unsupported")
            if not _valid_address(definition, minimum=layout["pointer_min"], maximum=layout["pointer_max"]):
                raise ReadError("modifier_definition_pointer_invalid")
            vtable_raw = _reader_read(reader, vtable, layout["vtable_entries_width"], f"country_modifiers.vtable_{ordinal}", budget)
            methods = layout["expected_vtable_methods"]
            for method_offset, method_rva in methods.items():
                actual = int.from_bytes(vtable_raw[method_offset:method_offset + 8], "little")
                if actual != _add_address(module_base, method_rva):
                    raise ReadError("modifier_vtable_method_mismatch")
            detail, raw_detail = _read_definition(reader, module_base, definition, manager_pointer, item_raw, layout, budget, ordinal)
            node = {
                "node_address": _hex(current), "next_address": _hex(next_node) if next_node else None,
                "node_raw_hex": node_raw.hex(), "item_address": _hex(item), "item_raw_hex": item_raw.hex(),
                "vtable_address": _hex(vtable), "vtable_rva": hex(vtable - module_base), "vtable_raw_hex": vtable_raw.hex(),
                "definition_address": _hex(definition), "definition": detail, "raw": raw_detail,
            }
            nodes.append(node)
            compact_item = _compact_modifier(detail)
            compact.append(compact_item)
            raw_projection.append({
                "node_address": node["node_address"], "item_address": node["item_address"],
                "definition_address": node["definition_address"], "node_raw_hex": node["node_raw_hex"],
                "item_raw_hex": node["item_raw_hex"], "vtable_raw_hex": node["vtable_raw_hex"],
                "definition_prefix_raw_hex": raw_detail["definition_prefix_raw_hex"],
                "key_raw_hex": raw_detail["key_raw_hex"], "effect_pairs_raw_hex": raw_detail["effect_pairs_raw_hex"],
                "selector_raw_hex": [pair["selector_raw_hex"] for pair in detail["effect_pairs"]],
            })
            current = next_node
        if not terminated:
            raise ReadError("modifier_instance_count_out_of_bound")
    except (ReadError, ProfileError, TypeError, ValueError) as exc:
        return _empty_record(str(exc), static_guard=static_guard, runtime_guard=runtime_guard, module_base=module_base, country_pointer=country_pointer, read_budget=budget.snapshot(), read_log=budget.reads)
    field = {
        "status": "known", "complete": COMPLETE, "value": _copy_json(compact),
        "unit": UNIT, "scale": SCALE, "period": PERIOD, "basis": BASIS, "value_origin": VALUE_ORIGIN,
    }
    observation = {
        "profile_id": loaded["profile_id"], "profile_sha256": EXPECTED_PROFILE_SHA256,
        "module_base": _hex(module_base), "country_pointer": _hex(country_pointer),
        "list_head_address": _hex(head_address), "list_head_offset": hex(layout["country_list_head_offset"]),
        "list_head_raw_hex": head_raw.hex(), "head": _hex(head) if head else None,
        "terminated": terminated, "count_observed": len(nodes),
        "manager_global_address": _hex(manager_global_address), "manager_global_rva": hex(layout["modifier_database_global_rva"]),
        "manager_pointer": _hex(manager_pointer), "manager_pointer_raw_hex": manager_raw.hex(),
        "nodes": _copy_json(nodes), "raw_projection": _copy_json(raw_projection),
        "basis": BASIS, "unit": UNIT, "scale": SCALE, "period": PERIOD, "value_origin": VALUE_ORIGIN,
        "static_contract_guard": _copy_json(static_guard), "runtime_code_guard": _copy_json(runtime_guard),
        "read_budget": budget.snapshot(), "read_log": _copy_json(budget.reads),
    }
    return {
        "status": "observed", "profile_id": loaded["profile_id"], "profile_sha256": EXPECTED_PROFILE_SHA256,
        "module_base": _hex(module_base), "country_pointer": _hex(country_pointer),
        "static_contract_guard": static_guard, "runtime_code_guard": runtime_guard,
        "fields": {FIELD_KEY: field}, "values": {FIELD_KEY: _copy_json(compact)},
        "raw_hex": {FIELD_KEY: _copy_json(raw_projection)}, "raw_bytes_hex": {FIELD_KEY: _copy_json(raw_projection)},
        "basis": BASIS, "unit": UNIT, "scale": SCALE, "period": PERIOD, "value_origin": VALUE_ORIGIN,
        "observation": observation,
    }


def _runtime_guard_valid(guard: Any, profile: Mapping[str, Any], module_base: int) -> bool:
    if not isinstance(guard, Mapping) or guard.get("status") != "observed" or guard.get("module_base") != _hex(module_base) or guard.get("unknown_conditions") not in ([], None):
        return False
    try:
        expected = {name: (rva, end, raw) for name, rva, end, raw in _profile_code_guards(profile)}
    except ProfileError:
        return False
    checks, records = guard.get("checks"), guard.get("records")
    if not isinstance(checks, Mapping) or not isinstance(records, Mapping) or set(checks) != set(expected) or set(records) != set(expected):
        return False
    for name, (rva, end, raw) in expected.items():
        item = records.get(name)
        digest = hashlib.sha256(raw).hexdigest()
        if checks.get(name) is not True or not isinstance(item, Mapping) or item.get("rva") != hex(rva) or item.get("rva_end_exclusive") != hex(end) or item.get("address") != _hex(module_base + rva) or item.get("expected_hex") != raw.hex() or item.get("actual_hex") != raw.hex() or item.get("expected_sha256") != digest or item.get("actual_sha256") != digest:
            return False
    expected_bytes = sum(end - begin for _name, begin, end, _raw in _profile_code_guards(profile))
    return guard.get("bytes_reserved") == expected_bytes and guard.get("limit") == READ_BUDGET_BYTES


def _static_guard_valid(guard: Any, profile: Mapping[str, Any]) -> bool:
    return isinstance(guard, Mapping) and guard == _static_contract_guard(profile)


def _valid_read_log(observation: Mapping[str, Any]) -> bool:
    budget = observation.get("read_budget")
    logs = observation.get("read_log")
    if not isinstance(budget, Mapping) or not isinstance(logs, list) or budget.get("limit") != READ_BUDGET_BYTES or type(budget.get("bytes_reserved")) is not int or not 0 < budget["bytes_reserved"] <= READ_BUDGET_BYTES:
        return False
    total = 0
    for entry in logs:
        if not isinstance(entry, Mapping) or type(entry.get("size")) is not int or entry["size"] <= 0 or not isinstance(entry.get("label"), str):
            return False
        total += entry["size"]
        if entry.get("status") != "ok":
            return False
        try:
            raw = bytes.fromhex(str(entry.get("raw_hex")))
        except ValueError:
            return False
        if len(raw) != entry["size"] or entry.get("sha256") != hashlib.sha256(raw).hexdigest():
            return False
    return total == budget["bytes_reserved"]


def _validate_definition(
    node: Mapping[str, Any],
    layout: Mapping[str, Any],
    module_base: int,
    manager_pointer: int,
) -> tuple[bool, dict[str, Any] | None, dict[str, Any] | None]:
    """Recompute one definition, including its raw date/flag/effect fields."""
    detail = node.get("definition")
    raw_detail = node.get("raw")
    if not isinstance(detail, Mapping) or not isinstance(raw_detail, Mapping):
        return False, None, None
    try:
        definition_address = int(str(node.get("definition_address")), 0)
        prefix = bytes.fromhex(str(raw_detail.get("definition_prefix_raw_hex")))
        item_raw = bytes.fromhex(str(node.get("item_raw_hex")))
        key_raw = bytes.fromhex(str(raw_detail.get("key_raw_hex")))
    except (TypeError, ValueError):
        return False, None, None
    if not _valid_address(definition_address) or len(prefix) != layout["definition_prefix_width"] or len(item_raw) not in {LIVE_ITEM_PREFIX_WIDTH, layout["item_width"]} or not key_raw or key_raw[-1:] != b"\0":
        return False, None, None
    definition_vtable = int.from_bytes(prefix[:8], "little")
    expected_definition_vtable = _add_address(module_base, layout["definition_vtable_rva"])
    if definition_vtable != expected_definition_vtable:
        return False, None, None
    length = int.from_bytes(prefix[layout["definition_key_length_offset"]:layout["definition_key_length_offset"] + 8], "little")
    capacity = int.from_bytes(prefix[layout["definition_key_capacity_offset"]:layout["definition_key_capacity_offset"] + 8], "little")
    if length <= 0 or length > layout["max_key_bytes"] or capacity < length or len(key_raw) != length + 1:
        return False, None, None
    try:
        key = _ascii_key(key_raw)
    except ReadError:
        return False, None, None
    key_field = prefix[layout["definition_key_offset"]:layout["definition_key_offset"] + 8]
    key_pointer = int.from_bytes(key_field, "little")
    storage = "sso_inline" if capacity < 0x10 else "heap"
    key_address = definition_address + layout["definition_key_offset"] if storage == "sso_inline" else key_pointer
    if storage == "sso_inline":
        if key_raw != prefix[layout["definition_key_offset"]:layout["definition_key_offset"] + length + 1]:
            return False, None, None
    elif not _valid_address(key_pointer):
        return False, None, None
    if detail.get("key") != key or detail.get("key_raw_hex") != key_raw.hex() or detail.get("key_address") != _hex(key_address) or detail.get("key_storage") != storage or detail.get("key_length") != length or detail.get("key_capacity") != capacity or detail.get("key_pointer_raw_hex") != key_field.hex():
        return False, None, None
    start_bytes = item_raw[layout["item_start_date_offset"]:layout["item_start_date_offset"] + 4]
    date_bytes = item_raw[layout["item_date_offset"]:layout["item_date_offset"] + 4]
    start_date_raw = int.from_bytes(start_bytes, "little", signed=True)
    date_raw = int.from_bytes(date_bytes, "little", signed=True)
    if detail.get("start_date_raw") != start_date_raw or detail.get("start_date_raw_hex") != start_bytes.hex() or detail.get("date_raw") != date_raw or detail.get("date_raw_hex") != date_bytes.hex():
        return False, None, None
    flags: dict[str, int] = {}
    flags_raw_hex: dict[str, str] = {}
    for name, offset in layout["item_flag_offsets"].items():
        flags[name] = item_raw[offset]
        flags_raw_hex[name] = item_raw[offset:offset + 1].hex()
    if detail.get("flags") != flags or detail.get("flags_raw_hex") != flags_raw_hex:
        return False, None, None
    pointer_bytes = prefix[layout["definition_effects_pointer_offset"]:layout["definition_effects_pointer_offset"] + 8]
    effect_ptr = int.from_bytes(pointer_bytes, "little")
    count_bytes = prefix[layout["definition_effect_count_offset"]:layout["definition_effect_count_offset"] + 4]
    count = int.from_bytes(count_bytes, "little")
    if count > layout["max_effects"] or detail.get("effect_count") != count or detail.get("effect_count_raw_hex") != count_bytes.hex() or detail.get("effects_pointer_raw_hex") != pointer_bytes.hex():
        return False, None, None
    try:
        pairs_raw = bytes.fromhex(str(raw_detail.get("effect_pairs_raw_hex", "")))
    except ValueError:
        return False, None, None
    pairs = detail.get("effect_pairs")
    effects = detail.get("effects")
    if not isinstance(pairs, list) or not isinstance(effects, list) or effects != pairs or len(pairs) != count or len(pairs_raw) != count * layout["effect_pair_width"]:
        return False, None, None
    expected_pairs: list[dict[str, Any]] = []
    for index, pair in enumerate(pairs):
        if not isinstance(pair, Mapping):
            return False, None, None
        begin = index * layout["effect_pair_width"]
        raw_pair = pairs_raw[begin:begin + layout["effect_pair_width"]]
        effect_index = int.from_bytes(raw_pair[:4], "little")
        effect_raw = int.from_bytes(raw_pair[4:], "little", signed=True)
        if effect_index > MAX_SELECTOR_INDEX:
            return False, None, None
        selector_address = _add_address(manager_pointer, effect_index * layout["modifier_record_stride"] + layout["modifier_selector_offset"])
        selector = pair.get("selector")
        selector_raw_hex = pair.get("selector_raw_hex")
        expected_pair = {
            "index": effect_index,
            "index_raw_hex": raw_pair[:4].hex(),
            "raw": effect_raw,
            "raw_hex": raw_pair[4:].hex(),
            "selector": selector,
            "selector_raw_hex": selector_raw_hex,
            "selector_address": _hex(selector_address),
            "pair_address": _hex(effect_ptr + begin) if effect_ptr else None,
            "pair_raw_hex": raw_pair.hex(),
        }
        if not isinstance(selector, int) or not isinstance(selector_raw_hex, str) or selector_raw_hex != (selector & 0xFFFFFFFF).to_bytes(4, "little").hex() or dict(pair) != expected_pair:
            return False, None, None
        expected_pairs.append(expected_pair)
    expected_detail = {
        "key": key,
        "key_raw_hex": key_raw.hex(),
        "key_address": _hex(key_address),
        "key_storage": storage,
        "key_length": length,
        "key_capacity": capacity,
        "key_pointer_raw_hex": key_field.hex(),
        "start_date_raw": start_date_raw,
        "start_date_raw_hex": start_bytes.hex(),
        "date_raw": date_raw,
        "date_raw_hex": date_bytes.hex(),
        "flags": flags,
        "flags_raw_hex": flags_raw_hex,
        "effects_pointer": _hex(effect_ptr) if effect_ptr else None,
        "effects_pointer_raw_hex": pointer_bytes.hex(),
        "effect_count": count,
        "effect_count_raw_hex": count_bytes.hex(),
        "effect_pairs": expected_pairs,
        "effects": _copy_json(expected_pairs),
    }
    expected_raw = {
        "definition_address": node.get("definition_address"),
        "definition_prefix_raw_hex": prefix.hex(),
        "definition_vtable": _hex(definition_vtable),
        "definition_vtable_raw_hex": prefix[:8].hex(),
        "key_raw_hex": key_raw.hex(),
        "key_address": _hex(key_address),
        "key_storage": storage,
        "key_length": length,
        "key_capacity": capacity,
        "key_pointer_raw_hex": key_field.hex(),
        "item_start_date_raw_hex": start_bytes.hex(),
        "item_date_raw_hex": date_bytes.hex(),
        "item_flags_raw_hex": flags_raw_hex,
        "effects_pointer_raw_hex": pointer_bytes.hex(),
        "effect_count_raw_hex": count_bytes.hex(),
        "effect_pairs_raw_hex": pairs_raw.hex(),
        "definition": expected_detail,
    }
    if dict(detail) != expected_detail or dict(raw_detail) != expected_raw:
        return False, None, None
    compact = _compact_modifier(expected_detail)
    projection = {
        "node_address": node.get("node_address"),
        "item_address": node.get("item_address"),
        "definition_address": node.get("definition_address"),
        "node_raw_hex": node.get("node_raw_hex"),
        "item_raw_hex": node.get("item_raw_hex"),
        "vtable_raw_hex": node.get("vtable_raw_hex"),
        "definition_prefix_raw_hex": prefix.hex(),
        "key_raw_hex": key_raw.hex(),
        "effect_pairs_raw_hex": pairs_raw.hex(),
        "selector_raw_hex": [pair["selector_raw_hex"] for pair in expected_pairs],
    }
    return True, compact, projection

def validate_record(record: Any) -> bool:
    """Recompute list topology, SSO key, raw effects and selector provenance."""
    if not isinstance(record, Mapping) or record.get("status") != "observed":
        return False
    try:
        profile = _load_profile()
        if record.get("profile_id") != profile["profile_id"] or record.get("profile_sha256") != EXPECTED_PROFILE_SHA256:
            return False
        module_base = int(record.get("module_base"), 0)
        country_pointer = int(record.get("country_pointer"), 0)
        layout = _profile_layout(profile)
        if not _valid_address(module_base, minimum=layout["pointer_min"], maximum=layout["pointer_max"]) or not _valid_address(country_pointer, minimum=layout["pointer_min"], maximum=layout["pointer_max"]):
            return False
        if not _static_guard_valid(record.get("static_contract_guard"), profile) or not _runtime_guard_valid(record.get("runtime_code_guard"), profile, module_base):
            return False
        if any(record.get(key) != expected for key, expected in (("basis", BASIS), ("unit", UNIT), ("scale", SCALE), ("period", PERIOD), ("value_origin", VALUE_ORIGIN))):
            return False
        fields, values, raw_hexes, raw_bytes = record.get("fields"), record.get("values"), record.get("raw_hex"), record.get("raw_bytes_hex")
        if not all(isinstance(item, Mapping) for item in (fields, values, raw_hexes, raw_bytes)) or any(set(item) != set(FIELDS) for item in (fields, values, raw_hexes, raw_bytes)):
            return False
        nodes = values[FIELD_KEY]
        field = fields[FIELD_KEY]
        if not isinstance(nodes, list) or not isinstance(field, Mapping) or field.get("status") != "known" or field.get("complete") is not COMPLETE or field.get("value") != nodes or field.get("unit") != UNIT or field.get("scale") != SCALE or field.get("period") != PERIOD or field.get("basis") != BASIS or field.get("value_origin") != VALUE_ORIGIN:
            return False
        observation = record.get("observation")
        if not isinstance(observation, Mapping) or observation.get("profile_id") != profile["profile_id"] or observation.get("profile_sha256") != EXPECTED_PROFILE_SHA256 or observation.get("module_base") != record.get("module_base") or observation.get("country_pointer") != record.get("country_pointer"):
            return False
        head_raw = bytes.fromhex(str(observation.get("list_head_raw_hex")))
        if len(head_raw) != 8:
            return False
        head_address = _add_address(country_pointer, layout["country_list_head_offset"])
        head = int.from_bytes(head_raw, "little")
        if observation.get("list_head_address") != _hex(head_address) or observation.get("list_head_offset") != hex(layout["country_list_head_offset"]) or observation.get("head") != (_hex(head) if head else None) or observation.get("terminated") is not True or observation.get("count_observed") != len(nodes) or len(nodes) > layout["max_instances"]:
            return False
        manager_global_address = _add_address(module_base, layout["modifier_database_global_rva"])
        manager = int(str(observation.get("manager_pointer")), 0)
        manager_raw = bytes.fromhex(str(observation.get("manager_pointer_raw_hex")))
        if len(manager_raw) != 8 or int.from_bytes(manager_raw, "little") != manager or observation.get("manager_global_address") != _hex(manager_global_address) or observation.get("manager_global_rva") != hex(layout["modifier_database_global_rva"]) or not _valid_address(manager):
            return False
        if not _valid_read_log(observation):
            return False
        full_nodes = observation.get("nodes")
        projections = observation.get("raw_projection")
        if not isinstance(full_nodes, list) or not isinstance(projections, list) or len(full_nodes) != len(nodes) or len(projections) != len(nodes):
            return False
        current = head
        seen: set[int] = set()
        expected_compact: list[dict[str, Any]] = []
        expected_projection: list[dict[str, Any]] = []
        for ordinal, node in enumerate(full_nodes):
            if not isinstance(node, Mapping) or not current or current in seen or node.get("node_address") != _hex(current):
                return False
            seen.add(current)
            node_raw = bytes.fromhex(str(node.get("node_raw_hex")))
            item_raw = bytes.fromhex(str(node.get("item_raw_hex")))
            vtable_raw = bytes.fromhex(str(node.get("vtable_raw_hex")))
            if len(node_raw) != layout["node_width"] or len(item_raw) not in {LIVE_ITEM_PREFIX_WIDTH, layout["item_width"]} or len(vtable_raw) != layout["vtable_entries_width"]:
                return False
            item = int.from_bytes(node_raw[layout["node_item_offset"]:layout["node_item_offset"] + 8], "little")
            next_node = int.from_bytes(node_raw[layout["node_next_offset"]:layout["node_next_offset"] + 8], "little")
            vtable = int.from_bytes(item_raw[layout["item_vtable_offset"]:layout["item_vtable_offset"] + 8], "little")
            definition = int.from_bytes(item_raw[layout["item_definition_offset"]:layout["item_definition_offset"] + 8], "little")
            if node.get("next_address") != (_hex(next_node) if next_node else None) or node.get("item_address") != _hex(item) or node.get("vtable_address") != _hex(vtable) or node.get("definition_address") != _hex(definition) or node.get("vtable_rva") != hex(vtable - module_base) or not _valid_address(item) or vtable != _add_address(module_base, layout["expected_vtable_rva"]) or definition == 0 or not _valid_address(definition):
                return False
            methods = layout["expected_vtable_methods"]
            if any(int.from_bytes(vtable_raw[offset:offset + 8], "little") != _add_address(module_base, method_rva) for offset, method_rva in methods.items()):
                return False
            ok, compact_item, projection = _validate_definition(node, layout, module_base, manager)
            if not ok or compact_item is None or projection is None:
                return False
            expected_compact.append(compact_item)
            expected_projection.append(projection)
            current = next_node
        if current != 0 or len(full_nodes) > layout["max_instances"]:
            return False
        if observation.get("raw_projection") != expected_projection or nodes != expected_compact or raw_hexes[FIELD_KEY] != expected_projection or raw_bytes[FIELD_KEY] != expected_projection:
            return False
        if field.get("value") != expected_compact:
            return False
        return True
    except (KeyError, TypeError, ValueError, OSError, ProfileError, ReadError):
        return False


def retract_record(record: Any, reason: str = "observation_retracted") -> dict[str, Any]:
    """Remove modifier instances after a failed second pass or cleanup."""
    module_base = country_pointer = None
    if isinstance(record, Mapping):
        try:
            module_base = int(record.get("module_base"), 0)
        except (TypeError, ValueError):
            pass
        try:
            country_pointer = int(record.get("country_pointer"), 0)
        except (TypeError, ValueError):
            pass
    result = _empty_record(reason, module_base=module_base, country_pointer=country_pointer)
    if isinstance(record, Mapping):
        for key in ("profile_id", "profile_sha256", "module_base", "country_pointer", "basis", "unit", "scale", "period", "value_origin"):
            if key in record:
                result[key] = _copy_json(record[key])
                result["observation"][key] = _copy_json(record[key])
    return result


__all__ = [
    "PROFILE_FILE", "PROFILE_MAX_BYTES", "SOURCE_EVIDENCE_MAX_BYTES", "EXPECTED_PROFILE_SHA256",
    "EXPECTED_EXE_SHA256", "EXPECTED_VERSION", "EXPECTED_COUNTRY", "FIELDS", "FIELD_KEY", "BASIS",
    "VALUE_ORIGIN", "PERIOD", "UNIT", "SCALE", "COMPLETE", "COUNTRY_LIST_HEAD_OFFSET",
    "NODE_WIDTH", "ITEM_WIDTH", "LIVE_ITEM_PREFIX_WIDTH", "ITEM_START_DATE_OFFSET", "ITEM_DATE_OFFSET", "ITEM_FLAG_OFFSETS",
    "DEFINITION_PREFIX_WIDTH", "DEFINITION_VTABLE_RVA", "DEFINITION_EFFECTS_POINTER_OFFSET", "DEFINITION_EFFECT_COUNT_OFFSET",
    "DEFINITION_KEY_OFFSET", "DEFINITION_KEY_LENGTH_OFFSET", "DEFINITION_KEY_CAPACITY_OFFSET",
    "MODIFIER_DATABASE_GLOBAL_RVA", "MODIFIER_RECORD_STRIDE", "MODIFIER_SELECTOR_OFFSET",
    "MAX_INSTANCES", "MAX_EFFECTS", "MAX_KEY_BYTES", "READ_BUDGET_BYTES", "ProfileError", "ReadError",
    "read_fields", "validate_record", "retract_record", "_load_profile", "_profile_layout",
    "_profile_code_guards", "_runtime_code_guard", "_static_contract_guard", "_ReadBudget",
]
