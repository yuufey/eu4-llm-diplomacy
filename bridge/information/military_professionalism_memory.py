"""Bounded reader for the fixed-build army-professionalism country cache.

The parent country-resource reader owns process identity, lifecycle, the
two-pass comparison, and the global RPM budget.  This child only verifies its
small static profile/code guards and copies the signed 64-bit inline value at
``country + 0x50``.  The eight bytes are the cache itself; they are not a
pointer to another object.  It never calls a game function or writes target
memory.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


PROFILE_FILE = (
    Path(__file__).resolve().parent / "profiles" / "military-professionalism-memory-1374.json"
)
PROFILE_MAX_BYTES = 64 * 1024
SOURCE_EVIDENCE_MAX_BYTES = 128 * 1024
# Filled by the exclusive profile generator after the batch-51 source report
# is pinned.  Keeping the digest in code makes a copied/tampered profile fail
# closed instead of silently changing the reader contract.
EXPECTED_PROFILE_SHA256 = "6ba4de58e640483d39fa928758549eee0d81cf2f61fb079df57d84e30cc93d00"
EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
EXPECTED_VERSION = "1.37.4"
EXPECTED_COUNTRY = "FRA"

FIELDS = ("professionalism",)
BASIS = "native_country_army_professionalism_cache"
VALUE_ORIGIN = "copied_native_country_army_professionalism_cache"
PERIOD = "current"
UNIT = "ratio"
SCALE = 32768
FIELD_KEY = "professionalism"
COUNTRY_OFFSET = 0x50
VALUE_WIDTH = 8
READ_BUDGET_BYTES = 8 * 1024
MAX_USER_ADDRESS = 0x00007FFFFFFFFFFF


class ProfileError(RuntimeError):
    """The pinned profile or its source evidence is invalid."""


class ReadError(RuntimeError):
    """A bounded child read or address/guard check failed."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _parse_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ProfileError(f"profile_integer_invalid:{label}")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value, 0)
        except ValueError as exc:
            raise ProfileError(f"profile_integer_invalid:{label}") from exc
    else:
        raise ProfileError(f"profile_integer_invalid:{label}")
    if parsed < 0:
        raise ProfileError(f"profile_integer_negative:{label}")
    return parsed


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
    raw_items = profile.get("source_evidence")
    if not isinstance(raw_items, list) or not raw_items or len(raw_items) > 8:
        raise ProfileError("source_evidence_shape_invalid")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw_items:
        if not isinstance(item, Mapping):
            raise ProfileError("source_evidence_item_invalid")
        expected_sha = item.get("sha256")
        expected_bytes = item.get("bytes")
        if not isinstance(expected_sha, str) or len(expected_sha) != 64:
            raise ProfileError("source_evidence_sha256_invalid")
        path = _source_path(item.get("path"))
        normalized = str(path).lower()
        if normalized in seen:
            raise ProfileError("source_evidence_duplicate")
        seen.add(normalized)
        raw = _bounded_bytes(path, SOURCE_EVIDENCE_MAX_BYTES, "source_evidence")
        if type(expected_bytes) is not int or expected_bytes != len(raw):
            raise ProfileError("source_evidence_bytes_mismatch")
        actual_sha = hashlib.sha256(raw).hexdigest()
        if actual_sha.lower() != expected_sha.lower():
            raise ProfileError("source_evidence_sha256_mismatch")
        result.append(
            {
                "path": str(path.relative_to(_workspace_root())).replace("\\", "/"),
                "sha256": actual_sha,
                "bytes": len(raw),
                "role": item.get("role"),
            }
        )
    return result


def _profile_layout(profile: Mapping[str, Any]) -> dict[str, Any]:
    layout = profile.get("layout")
    if not isinstance(layout, Mapping):
        raise ProfileError("profile_layout_missing")
    offset = _parse_int(
        layout.get("country_army_professionalism_offset"),
        "layout.country_army_professionalism_offset",
    )
    width = _parse_int(layout.get("value_width"), "layout.value_width")
    budget = _parse_int(layout.get("read_budget_bytes"), "layout.read_budget_bytes")
    if offset != COUNTRY_OFFSET or width != VALUE_WIDTH:
        raise ProfileError("profile_layout_offset_or_width_invalid")
    if layout.get("value_signed") is not True:
        raise ProfileError("profile_layout_signed_invalid")
    if budget != READ_BUDGET_BYTES:
        raise ProfileError("profile_read_budget_invalid")
    if layout.get("field_key") != FIELD_KEY:
        raise ProfileError("profile_field_key_invalid")
    return {
        "country_army_professionalism_offset": offset,
        "value_width": width,
        "value_signed": True,
        "read_budget_bytes": budget,
        "field_key": FIELD_KEY,
    }


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
            raw = bytes.fromhex(item.get("hex", ""))
        except (TypeError, ValueError) as exc:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}") from exc
        if not raw or end <= begin or len(raw) != end - begin:
            raise ProfileError(f"profile_code_guard_range_invalid:{name}")
        if item.get("sha256") != hashlib.sha256(raw).hexdigest():
            raise ProfileError(f"profile_code_guard_sha_invalid:{name}")
        if item.get("aslr_invariant") is not True:
            raise ProfileError(f"profile_code_guard_aslr_invalid:{name}")
        total += len(raw)
        if total > READ_BUDGET_BYTES:
            raise ProfileError("profile_code_guards_budget_invalid")
        names.add(name)
        result.append((name, begin, end, raw))
    return result


def _validate_profile_shape(profile: Mapping[str, Any]) -> None:
    if profile.get("profile_id") != "military-professionalism-memory-1374":
        raise ProfileError("profile_shape_invalid")
    if profile.get("game_version") != EXPECTED_VERSION:
        raise ProfileError("profile_version_mismatch")
    executable = profile.get("executable")
    if not isinstance(executable, Mapping) or str(executable.get("sha256", "")).lower() != EXPECTED_EXE_SHA256:
        raise ProfileError("profile_executable_mismatch")
    _validate_source_evidence(profile)
    _profile_layout(profile)
    semantics = profile.get("semantics")
    expected_semantics = {
        "field": FIELD_KEY,
        "basis": BASIS,
        "value_origin": VALUE_ORIGIN,
        "period": PERIOD,
        "unit": UNIT,
        "scale": SCALE,
        "complete": True,
    }
    if not isinstance(semantics, Mapping) or {
        key: semantics.get(key) for key in expected_semantics
    } != expected_semantics:
        raise ProfileError("profile_semantics_invalid")
    static_property = profile.get("static_property")
    if not isinstance(static_property, Mapping):
        raise ProfileError("profile_static_property_missing")
    if (
        static_property.get("field_key") != FIELD_KEY
        or static_property.get("key") != "army_professionalism"
        or static_property.get("getter_rva") != "0x9a530"
        or static_property.get("formatter_scale") != SCALE
    ):
        raise ProfileError("profile_static_property_invalid")
    if _parse_int(static_property.get("country_offset"), "static_property.country_offset") != COUNTRY_OFFSET:
        raise ProfileError("profile_static_property_offset_invalid")
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
            raise ReadError("read_budget_exceeded")
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


def _static_contract_guard(
    profile: Mapping[str, Any] | None = None, reason: str | None = None
) -> dict[str, Any]:
    if not isinstance(profile, Mapping):
        return {
            "status": "unknown",
            "profile_id": "military-professionalism-memory-1374",
            "profile_sha256": EXPECTED_PROFILE_SHA256,
            "checks": {},
            "source_evidence": [],
            "unknown_conditions": [reason or "profile_unavailable"],
        }
    try:
        source = profile.get("_validated_source_evidence", _validate_source_evidence(profile))
        checks = {
            "profile_id": profile.get("profile_id") == "military-professionalism-memory-1374",
            "game_version": profile.get("game_version") == EXPECTED_VERSION,
            "executable_sha256": isinstance(profile.get("executable"), Mapping)
            and str(profile["executable"].get("sha256", "")).lower() == EXPECTED_EXE_SHA256,
            "source_evidence": isinstance(source, list) and 0 < len(source) <= 8,
            "layout": _profile_layout(profile) == {
                "country_army_professionalism_offset": COUNTRY_OFFSET,
                "value_width": VALUE_WIDTH,
                "value_signed": True,
                "read_budget_bytes": READ_BUDGET_BYTES,
                "field_key": FIELD_KEY,
            },
            "semantics": profile.get("semantics", {}).get("field") == FIELD_KEY
            and profile.get("semantics", {}).get("basis") == BASIS
            and profile.get("semantics", {}).get("value_origin") == VALUE_ORIGIN
            and profile.get("semantics", {}).get("period") == PERIOD
            and profile.get("semantics", {}).get("unit") == UNIT
            and profile.get("semantics", {}).get("scale") == SCALE
            and profile.get("semantics", {}).get("complete") is True,
            "code_guards": bool(_profile_code_guards(profile)),
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


def _unknown_field(reason: str) -> dict[str, Any]:
    return {
        "status": "unknown",
        "reason": reason,
        "complete": False,
        "unit": UNIT,
        "scale": SCALE,
        "period": PERIOD,
        "basis": BASIS,
        "value_origin": VALUE_ORIGIN,
    }


def _empty_record(
    reason: str,
    *,
    static_guard: Mapping[str, Any] | None = None,
    runtime_guard: Mapping[str, Any] | None = None,
    module_base: int | None = None,
    country_pointer: int | None = None,
    profile_id: str = "military-professionalism-memory-1374",
    read_budget: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "status": "unknown",
        "reason": reason,
        "profile_id": profile_id,
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "module_base": _hex(module_base),
        "country_pointer": _hex(country_pointer),
        "static_contract_guard": _copy_json(static_guard) if isinstance(static_guard, Mapping) else None,
        "runtime_code_guard": _copy_json(runtime_guard) if isinstance(runtime_guard, Mapping) else None,
        "fields": {FIELD_KEY: _unknown_field(reason)},
        "values": None,
        "raw_hex": None,
        "raw_bytes_hex": None,
        "basis": BASIS,
        "unit": UNIT,
        "scale": SCALE,
        "period": PERIOD,
        "value_origin": VALUE_ORIGIN,
        "observation": {
            "profile_id": profile_id,
            "profile_sha256": EXPECTED_PROFILE_SHA256,
            "module_base": _hex(module_base),
            "country_pointer": _hex(country_pointer),
            "basis": BASIS,
            "unit": UNIT,
            "scale": SCALE,
            "period": PERIOD,
            "value_origin": VALUE_ORIGIN,
            "static_contract_guard": _copy_json(static_guard) if isinstance(static_guard, Mapping) else None,
            "code_guard": _copy_json(runtime_guard) if isinstance(runtime_guard, Mapping) else None,
            "read_budget": _copy_json(read_budget) if isinstance(read_budget, Mapping) else {"bytes_reserved": 0, "limit": READ_BUDGET_BYTES},
        },
    }


def _runtime_code_guard(
    reader: Any, module_base: int, profile: Mapping[str, Any], budget: _ReadBudget
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "module_base": _hex(module_base),
        "checks": {},
        "records": {},
        "unknown_conditions": [],
    }
    try:
        for name, rva, end, expected in _profile_code_guards(profile):
            actual = _reader_read(
                reader,
                _add_address(module_base, rva),
                len(expected),
                f"military_professionalism.code.{name}",
                budget,
            )
            result["records"][name] = {
                "rva": hex(rva),
                "rva_end_exclusive": hex(end),
                "address": _hex(module_base + rva),
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


def read_fields(reader: Any, module_base: int, country_pointer: int) -> dict[str, Any]:
    """Read and validate one bounded current-country professionalism value."""
    budget = _ReadBudget()
    try:
        profile = _load_profile()
    except Exception as exc:
        return _empty_record(
            "static_contract_guard_failed",
            module_base=module_base if type(module_base) is int else None,
            country_pointer=country_pointer if type(country_pointer) is int else None,
        ) | {"detail": f"{type(exc).__name__}:{exc}"}
    static_guard = _static_contract_guard(profile)
    if static_guard.get("status") != "observed":
        return _empty_record(
            "static_contract_guard_failed",
            static_guard=static_guard,
            module_base=module_base,
            country_pointer=country_pointer,
            read_budget={"bytes_reserved": budget.used, "limit": budget.limit},
        )
    if not _valid_address(module_base) or not _valid_address(country_pointer):
        return _empty_record(
            "pointer_invalid",
            static_guard=static_guard,
            module_base=module_base if type(module_base) is int else None,
            country_pointer=country_pointer if type(country_pointer) is int else None,
            read_budget={"bytes_reserved": budget.used, "limit": budget.limit},
        )
    runtime_guard = _runtime_code_guard(reader, module_base, profile, budget)
    if runtime_guard.get("status") != "observed":
        return _empty_record(
            "runtime_code_guard_failed",
            static_guard=static_guard,
            runtime_guard=runtime_guard,
            module_base=module_base,
            country_pointer=country_pointer,
            read_budget={"bytes_reserved": budget.used, "limit": budget.limit},
        )
    try:
        layout = _profile_layout(profile)
        cache_address = _add_address(country_pointer, layout["country_army_professionalism_offset"])
        raw = _reader_read(reader, cache_address, VALUE_WIDTH, "military_professionalism.current_cache", budget)
    except (ReadError, ProfileError) as exc:
        return _empty_record(
            str(exc),
            static_guard=static_guard,
            runtime_guard=runtime_guard,
            module_base=module_base,
            country_pointer=country_pointer,
            read_budget={"bytes_reserved": budget.used, "limit": budget.limit},
        )
    value = int.from_bytes(raw, "little", signed=True)
    raw_hex = raw.hex()
    field = {
        "status": "known",
        "complete": True,
        "value": value,
        "raw": value,
        "raw_hex": raw_hex,
        "unit": UNIT,
        "scale": SCALE,
        "period": PERIOD,
        "basis": BASIS,
        "value_origin": VALUE_ORIGIN,
    }
    read_budget = {"bytes_reserved": budget.used, "limit": budget.limit}
    observation = {
        "profile_id": profile["profile_id"],
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "module_base": _hex(module_base),
        "country_pointer": _hex(country_pointer),
        "cache_address": _hex(cache_address),
        "cache_offset": hex(layout["country_army_professionalism_offset"]),
        "raw": value,
        "raw_hex": raw_hex,
        "raw_bytes_hex": raw_hex,
        "basis": BASIS,
        "unit": UNIT,
        "scale": SCALE,
        "period": PERIOD,
        "value_origin": VALUE_ORIGIN,
        "static_contract_guard": _copy_json(static_guard),
        "code_guard": _copy_json(runtime_guard),
        "read_budget": read_budget,
    }
    return {
        "status": "observed",
        "profile_id": profile["profile_id"],
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "module_base": _hex(module_base),
        "country_pointer": _hex(country_pointer),
        "static_contract_guard": static_guard,
        "runtime_code_guard": runtime_guard,
        "fields": {FIELD_KEY: field},
        "values": {FIELD_KEY: value},
        "raw_hex": {FIELD_KEY: raw_hex},
        "raw_bytes_hex": {FIELD_KEY: raw_hex},
        "basis": BASIS,
        "unit": UNIT,
        "scale": SCALE,
        "period": PERIOD,
        "value_origin": VALUE_ORIGIN,
        "observation": observation,
    }


def _valid_hex_address(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return _valid_address(int(value, 0))
    except (TypeError, ValueError):
        return False


def _runtime_guard_valid(guard: Any, profile: Mapping[str, Any], module_base: int) -> bool:
    if (
        not isinstance(guard, Mapping)
        or guard.get("status") != "observed"
        or guard.get("module_base") != _hex(module_base)
        or guard.get("unknown_conditions") not in ([], None)
    ):
        return False
    try:
        expected = {name: (rva, end, raw) for name, rva, end, raw in _profile_code_guards(profile)}
    except ProfileError:
        return False
    checks = guard.get("checks")
    records = guard.get("records")
    if not isinstance(checks, Mapping) or not isinstance(records, Mapping) or set(checks) != set(expected) or set(records) != set(expected):
        return False
    for name, (rva, end, raw) in expected.items():
        if checks.get(name) is not True:
            return False
        item = records.get(name)
        if not isinstance(item, Mapping):
            return False
        if item.get("rva") != hex(rva) or item.get("rva_end_exclusive") != hex(end):
            return False
        if item.get("address") != _hex(module_base + rva):
            return False
        if item.get("expected_hex") != raw.hex() or item.get("actual_hex") != raw.hex():
            return False
        digest = hashlib.sha256(raw).hexdigest()
        if item.get("expected_sha256") != digest or item.get("actual_sha256") != digest:
            return False
    return type(guard.get("bytes_reserved")) is int and 0 < guard["bytes_reserved"] <= guard.get("limit", 0) <= READ_BUDGET_BYTES


def _static_guard_valid(guard: Any, profile: Mapping[str, Any]) -> bool:
    return isinstance(guard, Mapping) and guard == _static_contract_guard(profile)


def validate_record(record: Any) -> bool:
    """Recompute profile provenance, guard digests, raw encoding and field shape."""
    if not isinstance(record, Mapping) or record.get("status") != "observed":
        return False
    try:
        profile = _load_profile()
        if record.get("profile_id") != profile.get("profile_id") or record.get("profile_sha256") != EXPECTED_PROFILE_SHA256:
            return False
        module_base = int(record.get("module_base"), 0)
        country_pointer = int(record.get("country_pointer"), 0)
        if not _valid_address(module_base) or not _valid_address(country_pointer):
            return False
        if not _static_guard_valid(record.get("static_contract_guard"), profile):
            return False
        if not _runtime_guard_valid(record.get("runtime_code_guard"), profile, module_base):
            return False
        for key, expected in (("basis", BASIS), ("unit", UNIT), ("scale", SCALE), ("period", PERIOD), ("value_origin", VALUE_ORIGIN)):
            if record.get(key) != expected:
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
        if type(value) is not int:
            return False
        if value < -(1 << 63) or value > (1 << 63) - 1:
            return False
        expected_raw_hex = value.to_bytes(VALUE_WIDTH, "little", signed=True).hex()
        if raw_hexes[FIELD_KEY] != expected_raw_hex or raw_bytes_hexes[FIELD_KEY] != expected_raw_hex:
            return False
        item = fields[FIELD_KEY]
        if not isinstance(item, Mapping) or {
            "status": item.get("status"),
            "complete": item.get("complete"),
            "value": item.get("value"),
            "raw": item.get("raw"),
            "raw_hex": item.get("raw_hex"),
            "unit": item.get("unit"),
            "scale": item.get("scale"),
            "period": item.get("period"),
            "basis": item.get("basis"),
            "value_origin": item.get("value_origin"),
        } != {
            "status": "known", "complete": True, "value": value, "raw": value,
            "raw_hex": expected_raw_hex, "unit": UNIT, "scale": SCALE,
            "period": PERIOD, "basis": BASIS, "value_origin": VALUE_ORIGIN,
        }:
            return False
        observation = record.get("observation")
        if not isinstance(observation, Mapping):
            return False
        expected_address = _add_address(country_pointer, COUNTRY_OFFSET)
        if (
            observation.get("profile_id") != profile.get("profile_id")
            or observation.get("profile_sha256") != EXPECTED_PROFILE_SHA256
            or observation.get("module_base") != record.get("module_base")
            or observation.get("country_pointer") != record.get("country_pointer")
            or observation.get("cache_address") != _hex(expected_address)
            or observation.get("cache_offset") != hex(COUNTRY_OFFSET)
            or observation.get("raw") != value
            or observation.get("raw_hex") != expected_raw_hex
            or observation.get("raw_bytes_hex") != expected_raw_hex
            or observation.get("basis") != BASIS
            or observation.get("unit") != UNIT
            or observation.get("scale") != SCALE
            or observation.get("period") != PERIOD
            or observation.get("value_origin") != VALUE_ORIGIN
            or observation.get("static_contract_guard") != record.get("static_contract_guard")
            or observation.get("code_guard") != record.get("runtime_code_guard")
        ):
            return False
        read_budget = observation.get("read_budget")
        if (
            not isinstance(read_budget, Mapping)
            or type(read_budget.get("bytes_reserved")) is not int
            or type(read_budget.get("limit")) is not int
            or read_budget.get("limit") != READ_BUDGET_BYTES
            or read_budget.get("bytes_reserved") != record["runtime_code_guard"].get("bytes_reserved", -1) + VALUE_WIDTH
            or not 0 < read_budget["bytes_reserved"] <= read_budget["limit"] <= READ_BUDGET_BYTES
        ):
            return False
        return True
    except (KeyError, TypeError, ValueError, OSError, ProfileError, ReadError):
        return False


def retract_record(record: Any, reason: str = "observation_retracted") -> dict[str, Any]:
    """Remove consumable known data after a failed second pass or cleanup."""
    result = _empty_record(reason)
    if isinstance(record, Mapping):
        for key in ("profile_id", "profile_sha256", "module_base", "country_pointer", "basis", "unit", "scale", "period", "value_origin"):
            if key in record:
                result[key] = _copy_json(record[key])
                result["observation"][key] = _copy_json(record[key])
    return result


__all__ = [
    "PROFILE_FILE", "PROFILE_MAX_BYTES", "SOURCE_EVIDENCE_MAX_BYTES", "EXPECTED_PROFILE_SHA256",
    "EXPECTED_EXE_SHA256", "EXPECTED_VERSION", "EXPECTED_COUNTRY", "FIELDS", "BASIS",
    "VALUE_ORIGIN", "PERIOD", "UNIT", "SCALE", "FIELD_KEY", "COUNTRY_OFFSET", "VALUE_WIDTH",
    "READ_BUDGET_BYTES",
    "ProfileError", "ReadError", "read_fields", "validate_record", "retract_record",
    "_load_profile", "_profile_layout", "_profile_code_guards", "_runtime_code_guard",
    "_static_contract_guard",
]
