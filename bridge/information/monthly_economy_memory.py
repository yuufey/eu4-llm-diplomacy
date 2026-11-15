"""Bounded previous-month recurring ledger reader for EU4 1.37.4.

The source arrays are ``lastmonthincometable`` and
``lastmonthexpensetable``: a previous-month recurring ledger in ducats at
scale 1000.  This module copies one bounded 228-byte range and derives the
three requested signed-int32 values from the audited slot sets.  It does not
call a game function or recalculate a UI estimate.  Until the pinned profile
and source index exist, every read fails closed before touching the supplied
reader.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "monthly-economy-memory-1374.json"
PROFILE_MAX_BYTES = 64 * 1024
SOURCE_INDEX_MAX_BYTES = 128 * 1024
EXPECTED_PROFILE_SHA256 = "bd5e3ee39b02e4b5f183790d4550f394c6248eaa4dc4c68e9c17d9ec3254d831"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_VERSION = "1.37.4"
EXPECTED_COUNTRY = "FRA"

FIELDS = ("monthly_income", "monthly_expenses", "monthly_balance")
BASIS = "native_recurring_monthly_ledger"
REFERENCE_PERIOD = "previous_month"
PERIOD = "month"
VALUE_SEMANTICS = "previous_month_recurring_ledger"
VALUE_ORIGIN = "derived_from_copied_native_ledger"
UNIT = "ducats"
SCALE = 1000
INCOME_OFFSET = 0x770
EXPENSE_OFFSET = 0x7BC
INCOME_COUNT = 19
EXPENSE_COUNT = 38
COMPONENT_WIDTH = 4
LEDGER_SIZE = 228
INCOME_INDICES = (0, 1, 2, 3, 4, 5, 6, 7, 8, 15, 16)
EXPENSE_INDICES = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 21, 22, 23, 24, 25, 26, 27, 30, 31, 33, 34)
INT32_MODULUS = 1 << 32
INT32_SIGN = 1 << 31
MAX_USER_ADDRESS = 0x00007FFFFFFFFFFF


class ProfileError(RuntimeError):
    """The monthly profile or pinned source index is absent or invalid."""


class ReadError(RuntimeError):
    """A bounded ledger or guard read failed."""


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


def _source_index_path(raw_path: Any) -> Path:
    if not isinstance(raw_path, str) or not raw_path:
        raise ProfileError("source_index_path_invalid")
    path = Path(raw_path)
    if path.is_absolute():
        resolved = path.resolve()
    else:
        resolved = (_workspace_root() / path).resolve()
    root = _workspace_root()
    if resolved != root and root not in resolved.parents:
        raise ProfileError("source_index_outside_workspace")
    return resolved


def _validate_source_index(profile: Mapping[str, Any]) -> dict[str, Any]:
    source = profile.get("source_index")
    if not isinstance(source, Mapping):
        raise ProfileError("source_index_missing")
    source_id = source.get("source_index_id")
    if not isinstance(source_id, str) or not source_id:
        raise ProfileError("source_index_id_invalid")
    expected = source.get("sha256")
    if not isinstance(expected, str) or len(expected) != 64:
        raise ProfileError("source_index_sha256_invalid")
    path = _source_index_path(source.get("path"))
    raw = _bounded_bytes(path, SOURCE_INDEX_MAX_BYTES, "source_index")
    actual = hashlib.sha256(raw).hexdigest()
    if actual.lower() != expected.lower():
        raise ProfileError("source_index_sha256_mismatch")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"source_index_json_invalid:{exc}") from exc
    if not isinstance(document, dict):
        raise ProfileError("source_index_shape_invalid")
    if document.get("source_index_id") != source_id:
        raise ProfileError("source_index_id_mismatch")
    if document.get("profile_id") != profile.get("profile_id"):
        raise ProfileError("source_index_profile_id_mismatch")
    return {
        "path": str(path),
        "source_index_id": source_id,
        "sha256": expected.lower(),
        "bytes": len(raw),
        "document": document,
    }


def _profile_layout(profile: Mapping[str, Any]) -> dict[str, Any]:
    layout = profile.get("layout")
    if not isinstance(layout, Mapping):
        raise ProfileError("profile_layout_missing")
    try:
        result = {
            "income_offset": _parse_int(layout["income_offset"], "layout.income_offset"),
            "income_count": _parse_int(layout["income_count"], "layout.income_count"),
            "expense_offset": _parse_int(layout["expense_offset"], "layout.expense_offset"),
            "expense_count": _parse_int(layout["expense_count"], "layout.expense_count"),
            "payload_size": _parse_int(layout["payload_size"], "layout.payload_size"),
            "component_width": _parse_int(layout["component_width"], "layout.component_width"),
            "signed": layout["signed"],
            "wrap_bits": _parse_int(layout["wrap_bits"], "layout.wrap_bits"),
            "income_indices": tuple(layout["income_indices"]),
            "expense_indices": tuple(layout["expense_indices"]),
        }
    except (KeyError, TypeError) as exc:
        raise ProfileError(f"profile_layout_invalid:{exc}") from exc
    if result["income_offset"] != INCOME_OFFSET or result["income_count"] != INCOME_COUNT:
        raise ProfileError("profile_income_layout_mismatch")
    if result["expense_offset"] != EXPENSE_OFFSET or result["expense_count"] != EXPENSE_COUNT:
        raise ProfileError("profile_expense_layout_mismatch")
    if result["payload_size"] != LEDGER_SIZE or result["component_width"] != COMPONENT_WIDTH:
        raise ProfileError("profile_payload_layout_mismatch")
    if result["signed"] is not True or result["wrap_bits"] != 32:
        raise ProfileError("profile_int32_contract_mismatch")
    if result["income_indices"] != INCOME_INDICES or result["expense_indices"] != EXPENSE_INDICES:
        raise ProfileError("profile_inclusion_set_mismatch")
    return result


def _profile_code_guards(profile: Mapping[str, Any]) -> list[tuple[str, int, bytes]]:
    raw_guards = profile.get("code_guards")
    if not isinstance(raw_guards, list) or not raw_guards:
        raise ProfileError("profile_code_guards_missing")
    guards: list[tuple[str, int, bytes]] = []
    names: set[str] = set()
    total = 0
    for item in raw_guards:
        if not isinstance(item, Mapping):
            raise ProfileError("profile_code_guard_not_object")
        name = item.get("name")
        raw_hex = item.get("hex", item.get("bytes"))
        if not isinstance(name, str) or not name or name in names:
            raise ProfileError("profile_code_guard_name_invalid")
        if not isinstance(raw_hex, str) or not raw_hex or len(raw_hex) % 2:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}")
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}") from exc
        rva = _parse_int(item.get("rva"), f"code_guard.{name}.rva")
        if not raw or len(raw) > 65_536:
            raise ProfileError(f"profile_code_guard_size_invalid:{name}")
        total += len(raw)
        if total > 512 * 1024:
            raise ProfileError("profile_code_guards_budget_invalid")
        names.add(name)
        guards.append((name, rva, raw))
    return guards


def _validate_profile_shape(profile: Mapping[str, Any]) -> None:
    if profile.get("profile_id") != "monthly-economy-memory-1374":
        raise ProfileError("profile_shape_invalid")
    if profile.get("game_version") != EXPECTED_VERSION:
        raise ProfileError("profile_version_mismatch")
    executable = profile.get("executable")
    if not isinstance(executable, Mapping) or str(executable.get("sha256", "")).lower() != EXPECTED_EXE_SHA256:
        raise ProfileError("profile_executable_mismatch")
    _profile_layout(profile)
    _profile_code_guards(profile)


def _load_profile(
    path: Path | None = None,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    path = PROFILE_FILE if path is None else Path(path)
    expected = EXPECTED_PROFILE_SHA256 if expected_sha256 is None else expected_sha256
    if not isinstance(expected, str) or len(expected) != 64 or expected == "pending-profile":
        raise ProfileError("profile_sha256_pending_or_invalid")
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
    source = _validate_source_index(profile)
    profile = dict(profile)
    profile["_validated_source_index"] = source
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


def _wrap_i32(value: int) -> int:
    value &= INT32_MODULUS - 1
    return value - INT32_MODULUS if value & INT32_SIGN else value


def _derived_hex(value: int) -> str:
    return (value & (INT32_MODULUS - 1)).to_bytes(4, "little", signed=False).hex()


def _sum_indices(values: list[int], indices: tuple[int, ...]) -> int:
    total = 0
    for index in indices:
        total = _wrap_i32(total + values[index])
    return total


def _unknown_fields(reason: str) -> dict[str, dict[str, Any]]:
    return {
        field: {
            "status": "unknown",
            "reason": reason,
            "complete": False,
            "reference_period": REFERENCE_PERIOD,
            "period": PERIOD,
            "value_semantics": VALUE_SEMANTICS,
            "value_origin": VALUE_ORIGIN,
        }
        for field in FIELDS
    }


def _static_contract_guard(profile: Mapping[str, Any] | None = None, reason: str | None = None) -> dict[str, Any]:
    if not isinstance(profile, Mapping):
        return {
            "status": "unknown",
            "checks": {},
            "unknown_conditions": [reason or "profile_unavailable"],
        }
    source = profile.get("_validated_source_index", profile.get("source_index", {}))
    source_ok = isinstance(source, Mapping) and all(
        isinstance(source.get(key), str) and bool(source.get(key))
        for key in ("source_index_id", "path", "sha256")
    )
    checks = {
        "profile_id": profile.get("profile_id") == "monthly-economy-memory-1374",
        "game_version": profile.get("game_version") == EXPECTED_VERSION,
        "executable_sha256": isinstance(profile.get("executable"), Mapping)
        and str(profile["executable"].get("sha256", "")).lower() == EXPECTED_EXE_SHA256,
        "source_index": source_ok,
        "layout": True,
        "code_guards": True,
    }
    failed = [key for key, value in checks.items() if value is not True]
    return {
        "status": "observed" if not failed else "unknown",
        "profile_id": profile.get("profile_id"),
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "checks": checks,
        "source_index": {
            key: source.get(key)
            for key in ("source_index_id", "path", "sha256", "bytes")
            if isinstance(source, Mapping) and key in source
        },
        "unknown_conditions": ["profile_contract_failed:" + ",".join(failed)] if failed else [],
    }


def _empty_record(
    reason: str,
    *,
    guard: Mapping[str, Any] | None = None,
    profile: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    static_guard = _static_contract_guard(profile, reason)
    return {
        "status": "unknown",
        "reason": reason,
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "static_contract_guard": static_guard,
        "runtime_code_guard": deepcopy_dict(guard) if isinstance(guard, Mapping) else None,
        "raw_ledger_hex": None,
        "income_slots": None,
        "expense_slots": None,
        "fields": _unknown_fields(reason),
        "values": None,
        "raw_hex": None,
        "raw_payload_hex": None,
        "raw_payload_size": None,
        "basis": BASIS,
        "reference_period": REFERENCE_PERIOD,
        "period": PERIOD,
        "value_semantics": VALUE_SEMANTICS,
        "unit": UNIT,
        "scale": SCALE,
        "value_origin": VALUE_ORIGIN,
        "observation": {
            "basis": BASIS,
            "reference_period": REFERENCE_PERIOD,
            "period": PERIOD,
            "value_semantics": VALUE_SEMANTICS,
            "unit": UNIT,
            "scale": SCALE,
            "profile_id": "monthly-economy-memory-1374",
            "profile_sha256": EXPECTED_PROFILE_SHA256,
            "static_contract_guard": static_guard,
            "code_guard": deepcopy_dict(guard) if isinstance(guard, Mapping) else None,
        },
    }


def deepcopy_dict(value: Mapping[str, Any]) -> dict[str, Any]:
    """Copy JSON-shaped guard data without importing the parent reader."""
    return json.loads(json.dumps(value))


def _reader_read(reader: Any, address: int, size: int, label: str) -> bytes:
    method = getattr(reader, "read", None)
    if not callable(method):
        raise ReadError("reader_read_method_missing")
    raw = method(address, size, label)
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != size:
        raise ReadError(f"short_or_invalid_read:{label}")
    return bytes(raw)


def _runtime_code_guard(reader: Any, module_base: int, profile: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "module_base": _hex(module_base),
        "checks": {},
        "records": {},
        "unknown_conditions": [],
    }
    try:
        for name, rva, expected in _profile_code_guards(profile):
            address = module_base + rva
            if not _valid_address(address):
                raise ReadError(f"guard_address_invalid:{name}")
            actual = _reader_read(reader, address, len(expected), f"monthly_economy.code.{name}")
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
    except (ProfileError, ReadError, OSError, TypeError, ValueError) as exc:
        result["unknown_conditions"].append(f"runtime_code_guard_failed:{type(exc).__name__}:{exc}")
    return result


def _record_from_payload(
    payload: bytes,
    profile: Mapping[str, Any],
    module_base: int,
    country_pointer: int,
    guard: Mapping[str, Any],
) -> dict[str, Any]:
    layout = _profile_layout(profile)
    income_raw = [
        int.from_bytes(payload[index * COMPONENT_WIDTH:(index + 1) * COMPONENT_WIDTH], "little", signed=True)
        for index in range(INCOME_COUNT)
    ]
    expense_start = EXPENSE_OFFSET - INCOME_OFFSET
    expense_raw = [
        int.from_bytes(
            payload[expense_start + index * COMPONENT_WIDTH:expense_start + (index + 1) * COMPONENT_WIDTH],
            "little",
            signed=True,
        )
        for index in range(EXPENSE_COUNT)
    ]
    income = _sum_indices(income_raw, INCOME_INDICES)
    expenses = _sum_indices(expense_raw, EXPENSE_INDICES)
    balance = _wrap_i32(income - expenses)
    values = {
        "monthly_income": income,
        "monthly_expenses": expenses,
        "monthly_balance": balance,
    }
    derived_hex = {field: _derived_hex(value) for field, value in values.items()}
    fields = {
        field: {
            "status": "known",
            "complete": False,
            "value": value,
            "raw": value,
            "raw_hex": derived_hex[field],
            "value_origin": VALUE_ORIGIN,
            "value_semantics": VALUE_SEMANTICS,
            "reference_period": REFERENCE_PERIOD,
            "period": PERIOD,
        }
        for field, value in values.items()
    }
    return {
        "status": "observed",
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "static_contract_guard": _static_contract_guard(profile),
        "runtime_code_guard": deepcopy_dict(guard),
        "raw_ledger_hex": payload.hex(),
        "income_slots": income_raw,
        "expense_slots": expense_raw,
        "fields": fields,
        "values": values,
        "raw_hex": derived_hex,
        "raw_payload_hex": payload.hex(),
        "raw_payload_size": len(payload),
        "input_arrays": {
            "income": {
                "offset": hex(layout["income_offset"]),
                "count": layout["income_count"],
                "raw_values": income_raw,
                "included_indices": list(INCOME_INDICES),
            },
            "expense": {
                "offset": hex(layout["expense_offset"]),
                "count": layout["expense_count"],
                "raw_values": expense_raw,
                "included_indices": list(EXPENSE_INDICES),
            },
        },
        "observation": {
            "basis": BASIS,
            "reference_period": REFERENCE_PERIOD,
            "period": PERIOD,
            "value_semantics": VALUE_SEMANTICS,
            "unit": UNIT,
            "scale": SCALE,
            "value_origin": VALUE_ORIGIN,
            "profile_id": profile.get("profile_id"),
            "profile_sha256": EXPECTED_PROFILE_SHA256,
            "static_contract_guard": _static_contract_guard(profile),
            "module_base": _hex(module_base),
            "country_pointer": _hex(country_pointer),
            "code_guard": deepcopy_dict(guard),
            "ledger": {
                "offset": hex(INCOME_OFFSET),
                "size": LEDGER_SIZE,
                "raw_payload_hex": payload.hex(),
            },
            "arithmetic": {
                "signed": True,
                "wrap_bits": 32,
                "income_indices": list(INCOME_INDICES),
                "expense_indices": list(EXPENSE_INDICES),
            },
        },
        "basis": BASIS,
        "reference_period": REFERENCE_PERIOD,
        "period": PERIOD,
        "value_semantics": VALUE_SEMANTICS,
        "unit": UNIT,
        "scale": SCALE,
        "value_origin": VALUE_ORIGIN,
    }


def read_fields(reader: Any, module_base: int, country_pointer: int) -> dict[str, Any]:
    """Read and derive the three monthly fields through one bounded reader."""
    try:
        profile = _active_profile()
        _validate_profile_shape(profile)
    except Exception as exc:
        return _empty_record(f"profile_rejected:{type(exc).__name__}:{exc}")
    if not _valid_address(module_base) or not _valid_address(country_pointer):
        return _empty_record("pointer_rejected")
    guard = _runtime_code_guard(reader, module_base, profile)
    if guard.get("status") != "observed":
        return _empty_record("runtime_code_guard_failed", guard=guard, profile=profile)
    try:
        payload = _reader_read(reader, country_pointer + INCOME_OFFSET, LEDGER_SIZE, "monthly_economy.ledger")
        if len(payload) != LEDGER_SIZE:
            raise ReadError("ledger_size_mismatch")
        return _record_from_payload(payload, profile, module_base, country_pointer, guard)
    except Exception as exc:
        return _empty_record(
            f"ledger_read_failed:{type(exc).__name__}:{exc}", guard=guard, profile=profile
        )


def _guard_valid(record_guard: Mapping[str, Any], profile: Mapping[str, Any]) -> bool:
    expected_guards = _profile_code_guards(profile)
    expected_names = {name for name, _rva, _raw in expected_guards}
    if record_guard.get("status") != "observed":
        return False
    checks = record_guard.get("checks")
    records = record_guard.get("records")
    if checks != {name: True for name in expected_names} or not isinstance(records, Mapping):
        return False
    for name, rva, expected in expected_guards:
        item = records.get(name)
        if not isinstance(item, Mapping):
            return False
        if item.get("rva") != hex(rva) or item.get("expected_hex") != expected.hex():
            return False
        if item.get("actual_hex") != expected.hex():
            return False
        if item.get("expected_sha256") != hashlib.sha256(expected).hexdigest():
            return False
        if item.get("actual_sha256") != hashlib.sha256(expected).hexdigest():
            return False
    return set(records) == expected_names


def validate_record(record: Any) -> bool:
    """Validate profile pin, all guards, payload bytes, arrays and arithmetic."""
    if not isinstance(record, Mapping) or record.get("status") != "observed":
        return False
    try:
        profile = _active_profile()
        layout = _profile_layout(profile)
        if record.get("profile_sha256") != EXPECTED_PROFILE_SHA256:
            return False
        static_guard = record.get("static_contract_guard")
        if not isinstance(static_guard, Mapping) or static_guard.get("status") != "observed":
            return False
        if static_guard.get("profile_id") != profile.get("profile_id"):
            return False
        if static_guard.get("profile_sha256") != EXPECTED_PROFILE_SHA256:
            return False
        if static_guard.get("checks") != {
            "profile_id": True,
            "game_version": True,
            "executable_sha256": True,
            "source_index": True,
            "layout": True,
            "code_guards": True,
        }:
            return False
        top_guard = record.get("runtime_code_guard")
        if not isinstance(top_guard, Mapping) or not _guard_valid(top_guard, profile):
            return False
        if (
            record.get("basis") != BASIS
            or record.get("reference_period") != REFERENCE_PERIOD
            or record.get("period") != PERIOD
            or record.get("value_semantics") != VALUE_SEMANTICS
            or record.get("unit") != UNIT
            or record.get("scale") != SCALE
        ):
            return False
        if record.get("value_origin") != VALUE_ORIGIN:
            return False
        observation = record["observation"]
        if not isinstance(observation, Mapping):
            return False
        if (
            observation.get("basis") != BASIS
            or observation.get("reference_period") != REFERENCE_PERIOD
            or observation.get("period") != PERIOD
            or observation.get("value_semantics") != VALUE_SEMANTICS
            or observation.get("unit") != UNIT
            or observation.get("scale") != SCALE
            or observation.get("profile_id") != profile.get("profile_id")
        ):
            return False
        if observation.get("profile_sha256") != EXPECTED_PROFILE_SHA256:
            return False
        if observation.get("static_contract_guard") != static_guard:
            return False
        guard = observation.get("code_guard")
        if not isinstance(guard, Mapping) or guard != top_guard or not _guard_valid(guard, profile):
            return False
        ledger = observation.get("ledger")
        if not isinstance(ledger, Mapping) or ledger.get("offset") != hex(INCOME_OFFSET) or ledger.get("size") != LEDGER_SIZE:
            return False
        raw_payload_hex = record.get("raw_ledger_hex")
        if (
            not isinstance(raw_payload_hex, str)
            or record.get("raw_payload_hex") != raw_payload_hex
            or ledger.get("raw_payload_hex") != raw_payload_hex
        ):
            return False
        payload = bytes.fromhex(raw_payload_hex)
        if len(payload) != LEDGER_SIZE or record.get("raw_payload_size") != LEDGER_SIZE:
            return False
        income_item = record.get("income_slots")
        expense_item = record.get("expense_slots")
        if not isinstance(income_item, list) or not isinstance(expense_item, list):
            return False
        income_raw = [
            int.from_bytes(payload[index * COMPONENT_WIDTH:(index + 1) * COMPONENT_WIDTH], "little", signed=True)
            for index in range(INCOME_COUNT)
        ]
        expense_start = EXPENSE_OFFSET - INCOME_OFFSET
        expense_raw = [
            int.from_bytes(payload[expense_start + index * COMPONENT_WIDTH:expense_start + (index + 1) * COMPONENT_WIDTH], "little", signed=True)
            for index in range(EXPENSE_COUNT)
        ]
        if income_item != income_raw or expense_item != expense_raw:
            return False
        arrays = record.get("input_arrays")
        if not isinstance(arrays, Mapping):
            return False
        income_array = arrays.get("income")
        expense_array = arrays.get("expense")
        if not isinstance(income_array, Mapping) or not isinstance(expense_array, Mapping):
            return False
        if (
            income_array.get("offset") != hex(INCOME_OFFSET)
            or income_array.get("count") != INCOME_COUNT
            or income_array.get("raw_values") != income_raw
            or income_array.get("included_indices") != list(INCOME_INDICES)
            or expense_array.get("offset") != hex(EXPENSE_OFFSET)
            or expense_array.get("count") != EXPENSE_COUNT
            or expense_array.get("raw_values") != expense_raw
            or expense_array.get("included_indices") != list(EXPENSE_INDICES)
        ):
            return False
        values = {
            "monthly_income": _sum_indices(income_raw, INCOME_INDICES),
            "monthly_expenses": _sum_indices(expense_raw, EXPENSE_INDICES),
        }
        values["monthly_balance"] = _wrap_i32(values["monthly_income"] - values["monthly_expenses"])
        if record.get("values") != values:
            return False
        expected_hex = {field: _derived_hex(value) for field, value in values.items()}
        if record.get("raw_hex") != expected_hex:
            return False
        fields = record.get("fields")
        if not isinstance(fields, Mapping):
            return False
        for field, value in values.items():
            item = fields.get(field)
            if not isinstance(item, Mapping) or item.get("status") != "known":
                return False
            if (
                item.get("complete") is not False
                or item.get("value") != value
                or item.get("raw") != value
                or item.get("raw_hex") != expected_hex[field]
                or item.get("value_origin") != VALUE_ORIGIN
                or item.get("value_semantics") != VALUE_SEMANTICS
                or item.get("reference_period") != REFERENCE_PERIOD
                or item.get("period") != PERIOD
            ):
                return False
        return set(fields) == set(FIELDS)
    except (KeyError, TypeError, ValueError, OSError, ProfileError):
        return False


def retract_record(record: Any, reason: str = "observation_retracted") -> dict[str, Any]:
    """Remove consumable economy data after a failed double pass or cleanup."""
    result = _empty_record(reason)
    if isinstance(record, Mapping):
        observation = record.get("observation")
        if isinstance(observation, Mapping):
            result["observation"].update({
                key: deepcopy_dict(value) if isinstance(value, Mapping) else value
                for key, value in observation.items()
                if key in {"basis", "profile_id", "profile_sha256"}
            })
    return result


__all__ = [
    "PROFILE_FILE", "PROFILE_MAX_BYTES", "SOURCE_INDEX_MAX_BYTES", "EXPECTED_PROFILE_SHA256",
    "EXPECTED_EXE_SHA256", "EXPECTED_VERSION", "EXPECTED_COUNTRY", "FIELDS", "BASIS",
    "REFERENCE_PERIOD", "PERIOD", "VALUE_SEMANTICS", "VALUE_ORIGIN", "UNIT", "SCALE",
    "INCOME_OFFSET", "EXPENSE_OFFSET", "INCOME_COUNT", "EXPENSE_COUNT", "LEDGER_SIZE",
    "INCOME_INDICES", "EXPENSE_INDICES", "ProfileError", "ReadError", "read_fields",
    "validate_record", "retract_record", "_load_profile", "_profile_layout",
    "_profile_code_guards", "_runtime_code_guard", "_wrap_i32", "_derived_hex",
]
