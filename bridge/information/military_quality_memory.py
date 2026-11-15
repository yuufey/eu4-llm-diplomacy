"""Bounded native military-technology cache reader for EU4 1.37.4.

The parent country-resource capture owns process lifetime and the two-pass
observation.  This child only validates its pinned profile, copies the
``mil_tech`` definition lookup and reads one bounded int32 from the country's
technology vector.  It never opens a process or calls a native function.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "military-quality-memory-1374.json"
PROFILE_MAX_BYTES = 64 * 1024
SOURCE_EVIDENCE_MAX_BYTES = 128 * 1024
EXPECTED_PROFILE_SHA256 = "3f9113e7d5d87ae1ce19fc4b63e5034d1806f98c2a5630d847d06510fbcb6c32"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_VERSION = "1.37.4"
EXPECTED_COUNTRY = "FRA"

FIELDS = ("military_technology",)
BASIS = "native_country_technology_level_cache"
VALUE_ORIGIN = "copied_native_country_technology_cache"
PERIOD = "current"
UNIT = "technology_level"
SCALE = 1
TECHNOLOGY_KEY = "mil_tech"
TECHNOLOGY_KEY_BYTES = TECHNOLOGY_KEY.encode("ascii")
MAX_USER_ADDRESS = 0x00007FFFFFFFFFFF
MAX_BUCKET_COUNT = 65536
MAX_CHAIN_STEPS = 64
MAX_TECHNOLOGY_VECTOR_COUNT = 256
READ_BUDGET_BYTES = 64 * 1024


class ProfileError(RuntimeError):
    """The pinned profile or its small source reports are invalid."""


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
        raw = path.read_bytes()
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
    path = Path(raw_path)
    resolved = path.resolve() if path.is_absolute() else (_workspace_root() / path).resolve()
    root = _workspace_root()
    if resolved != root and root not in resolved.parents:
        raise ProfileError("source_evidence_outside_workspace")
    return resolved


def _validate_source_evidence(profile: Mapping[str, Any]) -> list[dict[str, Any]]:
    items = profile.get("source_evidence")
    if not isinstance(items, list) or len(items) != 3:
        raise ProfileError("source_evidence_shape_invalid")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, Mapping):
            raise ProfileError("source_evidence_item_invalid")
        raw_path = item.get("path")
        expected = item.get("sha256")
        expected_bytes = item.get("bytes")
        if not isinstance(expected, str) or len(expected) != 64:
            raise ProfileError("source_evidence_sha256_invalid")
        path = _source_path(raw_path)
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
    layout = profile.get("layout")
    if not isinstance(layout, Mapping):
        raise ProfileError("profile_layout_missing")
    names = (
        "singleton_global_rva", "manager_bucket_count_offset", "manager_buckets_offset",
        "chain_definition_offset", "chain_next_offset", "definition_key_string_offset",
        "definition_key_length_offset", "definition_key_capacity_offset", "definition_index_offset",
        "country_technology_pointer_offset", "technology_vector_begin_offset",
        "technology_vector_end_offset", "technology_vector_capacity_offset",
    )
    parsed = {name: _parse_int(layout.get(name), f"layout.{name}") for name in names}
    if parsed["singleton_global_rva"] > 0x40000000:
        raise ProfileError("profile_layout_offset_out_of_bound:singleton_global_rva")
    for name in names:
        if name != "singleton_global_rva" and parsed[name] > 0x100000:
            raise ProfileError(f"profile_layout_offset_out_of_bound:{name}")
    if layout.get("bucket_entry_stride") != 8 or layout.get("technology_component_width") != 4:
        raise ProfileError("profile_layout_stride_invalid")
    key = layout.get("technology_key")
    if key != TECHNOLOGY_KEY or layout.get("technology_key_length") != len(TECHNOLOGY_KEY_BYTES):
        raise ProfileError("profile_technology_key_invalid")
    if layout.get("max_bucket_count") != MAX_BUCKET_COUNT:
        raise ProfileError("profile_bucket_limit_invalid")
    if layout.get("max_chain_steps") != MAX_CHAIN_STEPS:
        raise ProfileError("profile_chain_limit_invalid")
    if layout.get("max_technology_vector_count") != MAX_TECHNOLOGY_VECTOR_COUNT:
        raise ProfileError("profile_vector_limit_invalid")
    if layout.get("read_budget_bytes") != READ_BUDGET_BYTES:
        raise ProfileError("profile_read_budget_invalid")
    parsed.update({
        "bucket_entry_stride": 8,
        "technology_component_width": 4,
        "technology_key": TECHNOLOGY_KEY,
        "technology_key_length": len(TECHNOLOGY_KEY_BYTES),
        "max_bucket_count": MAX_BUCKET_COUNT,
        "max_chain_steps": MAX_CHAIN_STEPS,
        "max_technology_vector_count": MAX_TECHNOLOGY_VECTOR_COUNT,
        "read_budget_bytes": READ_BUDGET_BYTES,
    })
    return parsed


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
        if total > 512 * 1024:
            raise ProfileError("profile_code_guards_budget_invalid")
        names.add(name)
        result.append((name, start, end, raw))
    return result


def _validate_profile_shape(profile: Mapping[str, Any]) -> None:
    if profile.get("profile_id") != "military-quality-memory-1374":
        raise ProfileError("profile_shape_invalid")
    if profile.get("game_version") != EXPECTED_VERSION:
        raise ProfileError("profile_version_mismatch")
    executable = profile.get("executable")
    if not isinstance(executable, Mapping) or str(executable.get("sha256", "")).lower() != EXPECTED_EXE_SHA256:
        raise ProfileError("profile_executable_mismatch")
    _validate_source_evidence(profile)
    layout = _profile_layout(profile)
    semantics = profile.get("semantics")
    if not isinstance(semantics, Mapping) or {
        "field": semantics.get("field"),
        "basis": semantics.get("basis"),
        "value_origin": semantics.get("value_origin"),
        "period": semantics.get("period"),
        "unit": semantics.get("unit"),
        "scale": semantics.get("scale"),
        "complete": semantics.get("complete"),
    } != {
        "field": FIELDS[0], "basis": BASIS, "value_origin": VALUE_ORIGIN,
        "period": PERIOD, "unit": UNIT, "scale": SCALE, "complete": True,
    }:
        raise ProfileError("profile_semantics_invalid")
    _profile_code_guards(profile)
    if layout["technology_key"].encode("ascii") != TECHNOLOGY_KEY_BYTES:
        raise ProfileError("profile_key_encoding_invalid")


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
    profile = dict(profile)
    profile["_validated_source_evidence"] = _validate_source_evidence(profile)
    return profile


try:
    PROFILE: dict[str, Any] | None = _load_profile()
except ProfileError:
    PROFILE = None


def _active_profile() -> dict[str, Any]:
    return _load_profile()


def _hex(value: int | None) -> str | None:
    return hex(value) if isinstance(value, int) else None


def _valid_address(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0x10000 <= value <= MAX_USER_ADDRESS


def _add_address(base: int, offset: int) -> int:
    if not _valid_address(base) or offset < 0:
        raise ReadError("pointer_invalid")
    value = base + offset
    if not _valid_address(value):
        raise ReadError("pointer_arithmetic_invalid")
    return value


def _copy_json(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False))


def _unknown_fields(reason: str) -> dict[str, dict[str, Any]]:
    return {
        field: {
            "status": "unknown",
            "reason": reason,
            "complete": False,
            "basis": BASIS,
            "period": PERIOD,
            "unit": UNIT,
            "scale": SCALE,
            "value_origin": VALUE_ORIGIN,
        }
        for field in FIELDS
    }


def _static_contract_guard(profile: Mapping[str, Any] | None = None, reason: str | None = None) -> dict[str, Any]:
    if not isinstance(profile, Mapping):
        return {"status": "unknown", "checks": {}, "unknown_conditions": [reason or "profile_unavailable"]}
    try:
        source = profile.get("_validated_source_evidence", _validate_source_evidence(profile))
        checks = {
            "profile_id": profile.get("profile_id") == "military-quality-memory-1374",
            "game_version": profile.get("game_version") == EXPECTED_VERSION,
            "executable_sha256": isinstance(profile.get("executable"), Mapping)
            and str(profile["executable"].get("sha256", "")).lower() == EXPECTED_EXE_SHA256,
            "source_evidence": isinstance(source, list) and len(source) == 3,
            "layout": True,
            "semantics": True,
            "code_guards": True,
        }
        failed = [name for name, ok in checks.items() if ok is not True]
        return {
            "status": "observed" if not failed else "unknown",
            "profile_id": profile.get("profile_id"),
            "profile_sha256": EXPECTED_PROFILE_SHA256,
            "checks": checks,
            "source_evidence": _copy_json(source) if isinstance(source, list) else [],
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


def _empty_record(
    reason: str,
    *,
    guard: Mapping[str, Any] | None = None,
    profile: Mapping[str, Any] | None = None,
    module_base: int | None = None,
    country_pointer: int | None = None,
    observation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    static_guard = _static_contract_guard(profile, reason)
    obs = {
        "basis": BASIS,
        "period": PERIOD,
        "unit": UNIT,
        "scale": SCALE,
        "value_origin": VALUE_ORIGIN,
        "profile_id": "military-quality-memory-1374",
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "static_contract_guard": static_guard,
        "code_guard": _copy_json(guard) if isinstance(guard, Mapping) else None,
        "module_base": _hex(module_base),
        "country_pointer": _hex(country_pointer),
    }
    if isinstance(observation, Mapping):
        obs.update(_copy_json(observation))
    return {
        "status": "unknown",
        "reason": reason,
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "static_contract_guard": static_guard,
        "runtime_code_guard": _copy_json(guard) if isinstance(guard, Mapping) else None,
        "module_base": _hex(module_base),
        "country_pointer": _hex(country_pointer),
        "fields": _unknown_fields(reason),
        "values": None,
        "raw_hex": None,
        "basis": BASIS,
        "period": PERIOD,
        "unit": UNIT,
        "scale": SCALE,
        "value_origin": VALUE_ORIGIN,
        "observation": obs,
    }


class _ReadBudget:
    def __init__(self, limit: int = READ_BUDGET_BYTES):
        self.limit = limit
        self.used = 0

    def reserve(self, size: int) -> None:
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ReadError("read_size_invalid")
        if self.used + size > self.limit:
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


def _read_u64(reader: Any, address: int, label: str, budget: _ReadBudget) -> int:
    return int.from_bytes(_reader_read(reader, address, 8, label, budget), "little", signed=False)


def _read_u32(reader: Any, address: int, label: str, budget: _ReadBudget) -> int:
    return int.from_bytes(_reader_read(reader, address, 4, label, budget), "little", signed=False)


def _read_i32(reader: Any, address: int, label: str, budget: _ReadBudget) -> int:
    return int.from_bytes(_reader_read(reader, address, 4, label, budget), "little", signed=True)


def _runtime_code_guard(reader: Any, module_base: int, profile: Mapping[str, Any], budget: _ReadBudget) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "module_base": _hex(module_base),
        "checks": {},
        "records": {},
        "unknown_conditions": [],
    }
    try:
        for name, rva, _end, expected in _profile_code_guards(profile):
            address = _add_address(module_base, rva)
            actual = _reader_read(reader, address, len(expected), f"military_quality.code.{name}", budget)
            result["records"][name] = {
                "rva": _hex(rva),
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
    except ReadError as exc:
        result["unknown_conditions"].append(exc.reason)
    except (ProfileError, TypeError, ValueError) as exc:
        result["unknown_conditions"].append(f"runtime_code_guard_failed:{type(exc).__name__}:{exc}")
    result["bytes_reserved"] = budget.used
    return result


def _hash_key(key: bytes) -> int:
    value = 0
    for byte in key:
        signed = byte - 256 if byte >= 0x80 else byte
        value = ((value + signed) * 0x3D) & 0xFFFFFFFF
    return value


def _read_definition_key(
    reader: Any,
    definition: int,
    layout: Mapping[str, Any],
    budget: _ReadBudget,
) -> dict[str, Any]:
    length_address = _add_address(definition, layout["definition_key_length_offset"])
    capacity_address = _add_address(definition, layout["definition_key_capacity_offset"])
    length = _read_u64(reader, length_address, "military_quality.definition.key_length", budget)
    capacity = _read_u64(reader, capacity_address, "military_quality.definition.key_capacity", budget)
    if length > 4096:
        raise ReadError("definition_key_length_out_of_bound")
    if capacity < length:
        raise ReadError("definition_key_capacity_invalid")
    data_address = _add_address(definition, layout["definition_key_string_offset"])
    if length == len(TECHNOLOGY_KEY_BYTES):
        if capacity < 0x10:
            data_pointer = data_address
        else:
            data_pointer = _read_u64(reader, data_address, "military_quality.definition.key_pointer", budget)
            if not _valid_address(data_pointer):
                raise ReadError("definition_key_pointer_invalid")
        data = _reader_read(reader, data_pointer, len(TECHNOLOGY_KEY_BYTES), "military_quality.definition.key", budget)
    else:
        data = None
    return {
        "length": length,
        "capacity": capacity,
        "data_hex": data.hex() if data is not None else None,
        "match": data == TECHNOLOGY_KEY_BYTES,
    }


def _lookup_definition(
    reader: Any,
    module_base: int,
    layout: Mapping[str, Any],
    budget: _ReadBudget,
) -> tuple[int, int, dict[str, Any]]:
    state: dict[str, Any] = {
        "key": TECHNOLOGY_KEY,
        "key_hex": TECHNOLOGY_KEY_BYTES.hex(),
        "key_hash_u32": _hash_key(TECHNOLOGY_KEY_BYTES),
        "chain": [],
    }
    try:
        global_address = _add_address(module_base, layout["singleton_global_rva"])
        manager = _read_u64(reader, global_address, "military_quality.singleton.manager", budget)
        if not _valid_address(manager):
            raise ReadError("manager_pointer_invalid")
        bucket_count = _read_u32(reader, _add_address(manager, layout["manager_bucket_count_offset"]), "military_quality.manager.bucket_count", budget)
        if not 1 <= bucket_count <= layout["max_bucket_count"]:
            raise ReadError("bucket_count_out_of_bound")
        buckets = _read_u64(reader, _add_address(manager, layout["manager_buckets_offset"]), "military_quality.manager.buckets", budget)
        if not _valid_address(buckets):
            raise ReadError("bucket_pointer_invalid")
        bucket_index = state["key_hash_u32"] % bucket_count
        bucket_address = _add_address(buckets, bucket_index * layout["bucket_entry_stride"])
        item = _read_u64(reader, bucket_address, "military_quality.bucket.head", budget)
        state.update({
            "global_address": _hex(global_address),
            "manager_pointer": _hex(manager),
            "bucket_count": bucket_count,
            "buckets_pointer": _hex(buckets),
            "bucket_index": bucket_index,
            "bucket_address": _hex(bucket_address),
        })
        seen: set[int] = set()
        for attempt in range(layout["max_chain_steps"]):
            if not item:
                raise ReadError("definition_key_not_found")
            if not _valid_address(item):
                raise ReadError("bucket_item_pointer_invalid")
            if item in seen:
                raise ReadError("bucket_chain_cycle")
            seen.add(item)
            definition = _read_u64(reader, _add_address(item, layout["chain_definition_offset"]), "military_quality.bucket.definition", budget)
            if not _valid_address(definition):
                raise ReadError("definition_pointer_invalid")
            key = _read_definition_key(reader, definition, layout, budget)
            entry = {
                "attempt": attempt,
                "item_pointer": _hex(item),
                "definition_pointer": _hex(definition),
                "key_length": key["length"],
                "key_capacity": key["capacity"],
                "key_raw_hex": key["data_hex"],
                "match": key["match"],
            }
            state["chain"].append(entry)
            if key["match"]:
                index_address = _add_address(definition, layout["definition_index_offset"])
                definition_index = _read_i32(reader, index_address, "military_quality.definition.index", budget)
                state.update({
                    "definition_pointer": _hex(definition),
                    "definition_index": definition_index,
                    "definition_index_address": _hex(index_address),
                    "chain_steps": attempt + 1,
                })
                return definition, definition_index, state
            item = _read_u64(reader, _add_address(item, layout["chain_next_offset"]), "military_quality.bucket.next", budget)
        raise ReadError("bucket_chain_limit")
    except ReadError as exc:
        detail = dict(state)
        detail["failure"] = exc.reason
        detail["bytes_reserved"] = budget.used
        raise ReadError(exc.reason, detail) from exc


def _read_technology(
    reader: Any,
    module_base: int,
    country_pointer: int,
    profile: Mapping[str, Any],
    budget: _ReadBudget,
) -> tuple[int, dict[str, Any]]:
    layout = _profile_layout(profile)
    definition, definition_index, lookup = _lookup_definition(reader, module_base, layout, budget)
    tech_pointer_address = _add_address(country_pointer, layout["country_technology_pointer_offset"])
    technology_pointer = _read_u64(reader, tech_pointer_address, "military_quality.country.technology_pointer", budget)
    if not _valid_address(technology_pointer):
        raise ReadError("technology_pointer_invalid", {"lookup": lookup})
    begin = _read_u64(reader, _add_address(technology_pointer, layout["technology_vector_begin_offset"]), "military_quality.technology.vector_begin", budget)
    end = _read_u64(reader, _add_address(technology_pointer, layout["technology_vector_end_offset"]), "military_quality.technology.vector_end", budget)
    state = {
        "lookup": lookup,
        "definition_pointer": _hex(definition),
        "technology_pointer": _hex(technology_pointer),
        "technology_pointer_address": _hex(tech_pointer_address),
        "vector_begin": _hex(begin),
        "vector_end": _hex(end),
        "vector_capacity": None,
        "vector_capacity_read": False,
        "definition_index": definition_index,
    }
    if end < begin or (end - begin) % layout["technology_component_width"]:
        raise ReadError("technology_vector_span_invalid", state)
    count = (end - begin) // layout["technology_component_width"]
    state["vector_count"] = count
    if count > layout["max_technology_vector_count"]:
        raise ReadError("technology_vector_count_out_of_bound", state)
    if definition_index < 0 or definition_index >= count:
        raise ReadError("technology_definition_index_out_of_bound", state)
    value_address = _add_address(begin, definition_index * layout["technology_component_width"])
    value = _read_i32(reader, value_address, "military_quality.technology.level", budget)
    state.update({"value_address": _hex(value_address), "value": value, "raw_hex": (value & 0xFFFFFFFF).to_bytes(4, "little").hex()})
    return value, state


def _record_from_value(
    value: int,
    state: Mapping[str, Any],
    profile: Mapping[str, Any],
    module_base: int,
    country_pointer: int,
    guard: Mapping[str, Any],
    budget: _ReadBudget,
) -> dict[str, Any]:
    raw_hex = (value & 0xFFFFFFFF).to_bytes(4, "little", signed=False).hex()
    static_guard = _static_contract_guard(profile)
    field = {
        "status": "known",
        "complete": True,
        "value": value,
        "raw": value,
        "raw_hex": raw_hex,
        "unit": UNIT,
        "scale": SCALE,
        "basis": BASIS,
        "period": PERIOD,
        "value_origin": VALUE_ORIGIN,
    }
    observation = {
        "basis": BASIS,
        "period": PERIOD,
        "unit": UNIT,
        "scale": SCALE,
        "value_origin": VALUE_ORIGIN,
        "profile_id": profile.get("profile_id"),
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "static_contract_guard": static_guard,
        "code_guard": _copy_json(guard),
        "module_base": _hex(module_base),
        "country_pointer": _hex(country_pointer),
        "lookup": _copy_json(state),
        "read_budget": {"bytes_reserved": budget.used, "limit": budget.limit},
    }
    return {
        "status": "observed",
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "static_contract_guard": static_guard,
        "runtime_code_guard": _copy_json(guard),
        "module_base": _hex(module_base),
        "country_pointer": _hex(country_pointer),
        "fields": {FIELDS[0]: field},
        "values": {FIELDS[0]: value},
        "raw_hex": {FIELDS[0]: raw_hex},
        "basis": BASIS,
        "period": PERIOD,
        "unit": UNIT,
        "scale": SCALE,
        "value_origin": VALUE_ORIGIN,
        "observation": observation,
    }


def read_fields(reader: Any, module_base: int, country_pointer: int) -> dict[str, Any]:
    """Read one bounded native technology level through an injected reader."""
    try:
        profile = _active_profile()
        _validate_profile_shape(profile)
    except Exception as exc:
        return _empty_record(f"profile_rejected:{type(exc).__name__}:{exc}", module_base=module_base, country_pointer=country_pointer)
    if not _valid_address(module_base) or not _valid_address(country_pointer):
        return _empty_record("pointer_rejected", profile=profile, module_base=module_base, country_pointer=country_pointer)
    budget = _ReadBudget(READ_BUDGET_BYTES)
    guard = _runtime_code_guard(reader, module_base, profile, budget)
    if guard.get("status") != "observed":
        return _empty_record(
            "runtime_code_guard_failed",
            guard=guard,
            profile=profile,
            module_base=module_base,
            country_pointer=country_pointer,
            observation={"read_budget": {"bytes_reserved": budget.used, "limit": budget.limit}},
        )
    try:
        value, state = _read_technology(reader, module_base, country_pointer, profile, budget)
        guard = _copy_json(guard)
        guard["bytes_reserved"] = budget.used
        return _record_from_value(value, state, profile, module_base, country_pointer, guard, budget)
    except ReadError as exc:
        detail = dict(exc.detail)
        detail.setdefault("read_budget", {"bytes_reserved": budget.used, "limit": budget.limit})
        return _empty_record(
            exc.reason,
            guard=guard,
            profile=profile,
            module_base=module_base,
            country_pointer=country_pointer,
            observation=detail,
        )
    except Exception as exc:
        return _empty_record(
            f"read_failed:{type(exc).__name__}:{exc}",
            guard=guard,
            profile=profile,
            module_base=module_base,
            country_pointer=country_pointer,
            observation={"read_budget": {"bytes_reserved": budget.used, "limit": budget.limit}},
        )


def _static_guard_valid(record_guard: Any, profile: Mapping[str, Any]) -> bool:
    expected = _static_contract_guard(profile)
    return isinstance(record_guard, Mapping) and record_guard == expected and record_guard.get("status") == "observed"


def _runtime_guard_valid(record_guard: Any, profile: Mapping[str, Any], module_base: int) -> bool:
    if not isinstance(record_guard, Mapping) or record_guard.get("status") != "observed":
        return False
    if record_guard.get("module_base") != hex(module_base) or record_guard.get("unknown_conditions") != []:
        return False
    expected_guards = _profile_code_guards(profile)
    expected_names = {name for name, _start, _end, _raw in expected_guards}
    if record_guard.get("checks") != {name: True for name in expected_names}:
        return False
    records = record_guard.get("records")
    if not isinstance(records, Mapping) or set(records) != expected_names:
        return False
    for name, start, _end, expected in expected_guards:
        item = records.get(name)
        if not isinstance(item, Mapping):
            return False
        if item.get("rva") != hex(start) or item.get("address") != hex(module_base + start):
            return False
        if item.get("expected_hex") != expected.hex() or item.get("actual_hex") != expected.hex():
            return False
        expected_sha = hashlib.sha256(expected).hexdigest()
        if item.get("expected_sha256") != expected_sha or item.get("actual_sha256") != expected_sha:
            return False
    return True


def _valid_hex_address(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return _valid_address(int(value, 0))
    except (TypeError, ValueError):
        return False


def _validate_lookup(state: Any, value: int) -> bool:
    if not isinstance(state, Mapping):
        return False
    lookup = state.get("lookup")
    if not isinstance(lookup, Mapping):
        return False
    if lookup.get("key") != TECHNOLOGY_KEY or lookup.get("key_hex") != TECHNOLOGY_KEY_BYTES.hex():
        return False
    if not isinstance(lookup.get("key_hash_u32"), int) or not 0 <= lookup["key_hash_u32"] <= 0xFFFFFFFF:
        return False
    for key in ("global_address", "manager_pointer", "buckets_pointer", "bucket_address", "definition_pointer", "definition_index_address"):
        if not _valid_hex_address(lookup.get(key)):
            return False
    for key in ("definition_pointer", "technology_pointer", "technology_pointer_address", "vector_begin", "vector_end", "value_address"):
        if not _valid_hex_address(state.get(key)):
            return False
    if state.get("vector_capacity") is not None or state.get("vector_capacity_read") is not False:
        return False
    for key in ("bucket_count", "bucket_index", "definition_index", "chain_steps"):
        if not isinstance(lookup.get(key), int):
            return False
    for key in ("definition_index", "vector_count", "value"):
        if not isinstance(state.get(key), int):
            return False
    if lookup.get("definition_index") != state.get("definition_index"):
        return False
    if state.get("definition_index") < 0 or state.get("vector_count") <= state.get("definition_index"):
        return False
    if state.get("value") != value:
        return False
    if state.get("raw_hex") != (value & 0xFFFFFFFF).to_bytes(4, "little").hex():
        return False
    if not 1 <= lookup["bucket_count"] <= MAX_BUCKET_COUNT or not 0 <= lookup["chain_steps"] <= MAX_CHAIN_STEPS:
        return False
    chain = lookup.get("chain")
    if not isinstance(chain, list) or not chain or len(chain) != lookup["chain_steps"]:
        return False
    last = chain[-1]
    if not isinstance(last, Mapping) or last.get("match") is not True or last.get("key_length") != len(TECHNOLOGY_KEY_BYTES) or last.get("key_raw_hex") != TECHNOLOGY_KEY_BYTES.hex():
        return False
    if state.get("vector_count") > MAX_TECHNOLOGY_VECTOR_COUNT:
        return False
    return True


def validate_record(record: Any) -> bool:
    """Validate profile/source pins, guards, lookup provenance and int32 value."""
    if not isinstance(record, Mapping) or record.get("status") != "observed":
        return False
    try:
        profile = _active_profile()
        if record.get("profile_sha256") != EXPECTED_PROFILE_SHA256:
            return False
        if not _static_guard_valid(record.get("static_contract_guard"), profile):
            return False
        module_base = int(record.get("module_base"), 0)
        country_pointer = int(record.get("country_pointer"), 0)
        if not _valid_address(module_base) or not _valid_address(country_pointer):
            return False
        guard = record.get("runtime_code_guard")
        if not _runtime_guard_valid(guard, profile, module_base):
            return False
        if record.get("basis") != BASIS or record.get("period") != PERIOD or record.get("unit") != UNIT or record.get("scale") != SCALE or record.get("value_origin") != VALUE_ORIGIN:
            return False
        values = record.get("values")
        raw_hex = record.get("raw_hex")
        fields = record.get("fields")
        if not isinstance(values, Mapping) or set(values) != set(FIELDS) or not isinstance(raw_hex, Mapping) or set(raw_hex) != set(FIELDS) or not isinstance(fields, Mapping) or set(fields) != set(FIELDS):
            return False
        value = values[FIELDS[0]]
        if isinstance(value, bool) or not isinstance(value, int):
            return False
        expected_hex = (value & 0xFFFFFFFF).to_bytes(4, "little").hex()
        if raw_hex[FIELDS[0]] != expected_hex:
            return False
        item = fields[FIELDS[0]]
        if not isinstance(item, Mapping):
            return False
        if (
            item.get("status") != "known"
            or item.get("complete") is not True
            or item.get("value") != value
            or item.get("raw") != value
            or item.get("raw_hex") != expected_hex
            or item.get("unit") != UNIT
            or item.get("scale") != SCALE
            or item.get("basis") != BASIS
            or item.get("period") != PERIOD
            or item.get("value_origin") != VALUE_ORIGIN
        ):
            return False
        observation = record.get("observation")
        if not isinstance(observation, Mapping):
            return False
        if (
            observation.get("basis") != BASIS
            or observation.get("period") != PERIOD
            or observation.get("unit") != UNIT
            or observation.get("scale") != SCALE
            or observation.get("value_origin") != VALUE_ORIGIN
            or observation.get("profile_id") != profile.get("profile_id")
            or observation.get("profile_sha256") != EXPECTED_PROFILE_SHA256
            or observation.get("static_contract_guard") != record.get("static_contract_guard")
            or observation.get("code_guard") != guard
            or observation.get("module_base") != record.get("module_base")
            or observation.get("country_pointer") != record.get("country_pointer")
        ):
            return False
        read_budget = observation.get("read_budget")
        if not isinstance(read_budget, Mapping) or not isinstance(read_budget.get("bytes_reserved"), int) or not isinstance(read_budget.get("limit"), int) or not 0 < read_budget["bytes_reserved"] <= read_budget["limit"] <= READ_BUDGET_BYTES:
            return False
        if not _validate_lookup(observation.get("lookup"), value):
            return False
        lookup = observation["lookup"]
        if lookup.get("vector_count") <= lookup.get("definition_index"):
            return False
        return True
    except (KeyError, TypeError, ValueError, OSError, ProfileError):
        return False


def retract_record(record: Any, reason: str = "observation_retracted") -> dict[str, Any]:
    """Retract consumable child data after a failed pass or cleanup."""
    result = _empty_record(reason)
    if isinstance(record, Mapping):
        observation = record.get("observation")
        if isinstance(observation, Mapping):
            result["observation"].update({
                key: _copy_json(value) if isinstance(value, Mapping) else value
                for key, value in observation.items()
                if key in {"basis", "period", "unit", "scale", "value_origin", "profile_id", "profile_sha256"}
            })
    return result


__all__ = [
    "PROFILE_FILE", "PROFILE_MAX_BYTES", "SOURCE_EVIDENCE_MAX_BYTES", "EXPECTED_PROFILE_SHA256",
    "EXPECTED_EXE_SHA256", "EXPECTED_VERSION", "EXPECTED_COUNTRY", "FIELDS", "BASIS",
    "VALUE_ORIGIN", "PERIOD", "UNIT", "SCALE", "TECHNOLOGY_KEY", "READ_BUDGET_BYTES",
    "ProfileError", "ReadError", "read_fields", "validate_record", "retract_record",
    "_load_profile", "_profile_layout", "_profile_code_guards", "_runtime_code_guard",
    "_static_contract_guard",
    "_hash_key",
]
