"""Bounded current-country loan-record reader for EU4 1.37.4.

The native country writer walks an intrusive list at ``country + 0xde8``.
This child copies that list through a bounded reader; it never calls a game
function and never writes target memory.  The v2 source contract adds the
special lender discriminator and the bounded foreign-fullref lookup while
retaining raw values when either lookup is unavailable.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .engine_dates import project_engine_date


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "country-loans-memory-1374-v2.json"
PROFILE_MAX_BYTES = 64 * 1024
SOURCE_EVIDENCE_MAX_BYTES = 128 * 1024
EXPECTED_PROFILE_ID = "country-loans-memory-1374-v2"
# Updated after the profile is written and its bytes are independently hashed.
EXPECTED_PROFILE_SHA256 = "686d88ef6b2dd02e12067d3fc2e7a942c39b131cf504bbe7bcf4f130d706cf69"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_VERSION = "1.37.4"
EXPECTED_COUNTRY = "FRA"

FIELDS = ("loans",)
FIELD_KEY = "loans"
BASIS = "native_country_loan_records"
VALUE_ORIGIN = "copied_native_country_loan_records"
PERIOD = "current"
UNIT = "loan_records"
SCALE = 1
PARTIAL = True

COUNTRY_OFFSET = 0xDE8
NODE_PAYLOAD_OFFSET = 0x0
NODE_NEXT_OFFSET = 0x10
RECORD_VTABLE_OFFSET = 0x0
VTABLE_ENTRY_OFFSET = 0x0
LENDER_OFFSET = 0x20
INTEREST_OFFSET = 0x28
PRINCIPAL_OFFSET = 0x2C
DUE_OFFSET = 0x30
RECORD_FIELDS_SIZE = 0x14
SPECIAL_PRESENCE_OFFSET = 0x27
SPECIAL_FLAG_OFFSET = 0x36
SPECIAL_FLAG_SIZE = 1
DATABASE_GLOBAL_RVA = 0x233D8B0
DATABASE_TABLE_OFFSET = 0x118
DATABASE_ENTRY_GATE_OFFSET = 0x2680
DATABASE_ENTRY_FULLREF_OFFSET = 0x20
DATABASE_MAX_SLOTS = 4095
DATE_REFERENCE_RAW = 43_800_000
DATE_TICKS_PER_DAY = 24
DATE_DAYS_PER_YEAR = 365
MAX_NODES = 64
READ_BUDGET_BYTES = 16 * 1024
MAX_USER_ADDRESS = 0x00007FFFFFFFFFFF
IMAGE_RVA_END = 0x25DF8B4
TEXT_RVA_BEGIN = 0x1000
TEXT_RVA_END = 0x1B65E00
RDATA_RVA_BEGIN = 0x1B66000
RDATA_RVA_END = 0x1FAFA00


class ProfileError(RuntimeError):
    """The pinned profile or its source evidence is invalid."""


class ReadError(RuntimeError):
    """A bounded child read, pointer, list, or guard check failed."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _workspace_root() -> Path:
    return Path(__file__).resolve().parents[2]


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


def _validate_source_evidence(profile: Mapping[str, Any]) -> list[dict[str, Any]]:
    items = profile.get("source_evidence")
    if not isinstance(items, list) or not items or len(items) > 8:
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
        if (
            not isinstance(relative, str)
            or not isinstance(digest, str)
            or len(digest) != 64
            or type(size) is not int
            or size <= 0
            or size > SOURCE_EVIDENCE_MAX_BYTES
        ):
            raise ProfileError("source_evidence_item_invalid")
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ProfileError("source_evidence_outside_workspace") from exc
        key = path.as_posix().lower()
        if key in seen:
            raise ProfileError("source_evidence_duplicate")
        raw = _bounded_bytes(path, SOURCE_EVIDENCE_MAX_BYTES, "source_evidence")
        if len(raw) != size:
            raise ProfileError("source_evidence_bytes_mismatch")
        if hashlib.sha256(raw).hexdigest().lower() != digest.lower():
            raise ProfileError("source_evidence_sha256_mismatch")
        seen.add(key)
        result.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": digest.lower(),
                "bytes": size,
                "role": item.get("role"),
            }
        )
    return result


def _profile_layout(profile: Mapping[str, Any]) -> dict[str, int]:
    layout = profile.get("layout")
    if not isinstance(layout, Mapping):
        raise ProfileError("profile_layout_missing")
    expected = {
        "country_loans_offset": COUNTRY_OFFSET,
        "node_payload_offset": NODE_PAYLOAD_OFFSET,
        "node_next_offset": NODE_NEXT_OFFSET,
        "loan_record_vtable_offset": RECORD_VTABLE_OFFSET,
        "vtable_guard_entry_offset": VTABLE_ENTRY_OFFSET,
        "lender_fullref_offset": LENDER_OFFSET,
        "interest_offset": INTEREST_OFFSET,
        "principal_offset": PRINCIPAL_OFFSET,
        "due_offset": DUE_OFFSET,
        "special_presence_offset": SPECIAL_PRESENCE_OFFSET,
        "special_flag_offset": SPECIAL_FLAG_OFFSET,
        "special_flag_width": SPECIAL_FLAG_SIZE,
        "database_global_rva": DATABASE_GLOBAL_RVA,
        "database_table_offset": DATABASE_TABLE_OFFSET,
        "database_entry_gate_offset": DATABASE_ENTRY_GATE_OFFSET,
        "database_entry_fullref_offset": DATABASE_ENTRY_FULLREF_OFFSET,
        "database_max_slots": DATABASE_MAX_SLOTS,
        "date_reference_raw": DATE_REFERENCE_RAW,
        "date_ticks_per_day": DATE_TICKS_PER_DAY,
        "date_days_per_year": DATE_DAYS_PER_YEAR,
        "max_nodes": MAX_NODES,
        "read_budget_bytes": READ_BUDGET_BYTES,
        "image_rva_end": IMAGE_RVA_END,
        "vtable_rva_begin": RDATA_RVA_BEGIN,
        "vtable_rva_end": RDATA_RVA_END,
        "code_rva_begin": TEXT_RVA_BEGIN,
        "code_rva_end": TEXT_RVA_END,
    }
    parsed: dict[str, int] = {}
    for key, expected_value in expected.items():
        value = _parse_int(layout.get(key), f"layout.{key}")
        if value != expected_value:
            raise ProfileError(f"profile_layout_value_invalid:{key}")
        parsed[key] = value
    pointer_min = _parse_int(layout.get("pointer_min"), "layout.pointer_min")
    pointer_max = _parse_int(layout.get("pointer_max"), "layout.pointer_max")
    if pointer_min != 0x10000 or pointer_max != MAX_USER_ADDRESS or pointer_min >= pointer_max:
        raise ProfileError("profile_pointer_bounds_invalid")
    parsed["pointer_min"] = pointer_min
    parsed["pointer_max"] = pointer_max
    if not (
        parsed["image_rva_end"] > parsed["vtable_rva_end"] > parsed["vtable_rva_begin"]
        and parsed["code_rva_begin"] < parsed["code_rva_end"] <= parsed["image_rva_end"]
        and parsed["vtable_rva_begin"] < parsed["vtable_rva_end"] <= parsed["image_rva_end"]
    ):
        raise ProfileError("profile_image_ranges_invalid")
    if layout.get("field_key") != FIELD_KEY:
        raise ProfileError("profile_field_key_invalid")
    return parsed


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
    if profile.get("profile_id") != EXPECTED_PROFILE_ID:
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
        "unit": UNIT,
        "scale": SCALE,
        "period": PERIOD,
        "complete": False,
        "partial": True,
        "principal_unit": "ducats",
        "principal_scale": 1,
        "interest_unit": "percent",
        "interest_scale": 1000,
        "due_unit": "engine_date_raw",
        "due_scale": 1,
        "due_raw_unit": "eu4_hour_tick",
        "due_calendar_algorithm": "floor_24_tick_365_day",
        "lender_mapping": "special_flag_and_strict_foreign_fullref",
    }
    if not isinstance(semantics, Mapping) or any(semantics.get(key) != value for key, value in expected_semantics.items()):
        raise ProfileError("profile_semantics_invalid")
    static_property = profile.get("static_property")
    if not isinstance(static_property, Mapping) or static_property.get("field_key") != FIELD_KEY:
        raise ProfileError("profile_static_property_invalid")
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
    profile["_validated_source_evidence"] = _validate_source_evidence(profile)
    return profile


def _prepare_profile(profile: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(profile, Mapping):
        raise ProfileError("profile_argument_invalid")
    result = dict(profile)
    _validate_profile_shape(result)
    result["_validated_source_evidence"] = _validate_source_evidence(result)
    return result


def _copy_json(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False))


def _hex(value: int | None) -> str | None:
    return hex(value) if type(value) is int else None


def _valid_address(value: Any, *, minimum: int = 0x10000, maximum: int = MAX_USER_ADDRESS) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _valid_module_pointer(value: Any, module_base: int, rva_begin: int, rva_end: int) -> bool:
    if not _valid_address(value) or not _valid_address(module_base):
        return False
    rva = value - module_base
    return type(rva) is int and rva_begin <= rva < rva_end


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
        budget.reads.append(
            {"address": _hex(address), "size": size, "label": label, "status": "failed", "error": type(exc).__name__}
        )
        raise ReadError(f"read_failed:{label}:{type(exc).__name__}:{exc}") from exc
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != size:
        budget.reads.append(
            {"address": _hex(address), "size": size, "label": label, "status": "failed", "error": "short_or_invalid_read"}
        )
        raise ReadError(f"short_or_invalid_read:{label}")
    result = bytes(raw)
    budget.reads.append(
        {
            "address": _hex(address),
            "size": size,
            "label": label,
            "status": "ok",
            "raw_hex": result.hex(),
            "sha256": hashlib.sha256(result).hexdigest(),
        }
    )
    return result


def _static_contract_guard(profile: Mapping[str, Any] | None = None, reason: str | None = None) -> dict[str, Any]:
    if not isinstance(profile, Mapping):
        return {
            "status": "unknown",
            "profile_id": EXPECTED_PROFILE_ID,
            "profile_sha256": EXPECTED_PROFILE_SHA256,
            "checks": {},
            "source_evidence": [],
            "unknown_conditions": [reason or "profile_unavailable"],
        }
    try:
        source = profile.get("_validated_source_evidence", _validate_source_evidence(profile))
        checks = {
            "profile_id": profile.get("profile_id") == EXPECTED_PROFILE_ID,
            "game_version": profile.get("game_version") == EXPECTED_VERSION,
            "executable_sha256": isinstance(profile.get("executable"), Mapping)
            and str(profile["executable"].get("sha256", "")).lower() == EXPECTED_EXE_SHA256,
            "source_evidence": isinstance(source, list) and bool(source),
            "layout": _profile_layout(profile),
            "semantics": isinstance(profile.get("semantics"), Mapping)
            and profile["semantics"].get("field") == FIELD_KEY
            and profile["semantics"].get("basis") == BASIS
            and profile["semantics"].get("value_origin") == VALUE_ORIGIN
            and profile["semantics"].get("unit") == UNIT
            and profile["semantics"].get("scale") == SCALE
            and profile["semantics"].get("period") == PERIOD
            and profile["semantics"].get("complete") is False
            and profile["semantics"].get("partial") is True
            and profile["semantics"].get("due_calendar_algorithm") == "floor_24_tick_365_day"
            and profile["semantics"].get("lender_mapping") == "special_flag_and_strict_foreign_fullref",
            "code_guards": bool(_profile_code_guards(profile)),
        }
        checks["layout"] = checks["layout"] == _profile_layout(profile)
        failed = [name for name, value in checks.items() if value is not True]
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
        "partial": PARTIAL,
        "value": None,
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
    read_budget: Mapping[str, Any] | None = None,
    read_log: list[Mapping[str, Any]] | None = None,
    profile_id: str = EXPECTED_PROFILE_ID,
) -> dict[str, Any]:
    budget = _copy_json(read_budget) if isinstance(read_budget, Mapping) else {"bytes_reserved": 0, "limit": READ_BUDGET_BYTES}
    logs = _copy_json(read_log) if isinstance(read_log, list) else []
    observation = {
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
        "runtime_code_guard": _copy_json(runtime_guard) if isinstance(runtime_guard, Mapping) else None,
        "read_budget": budget,
        "read_log": logs,
    }
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
        "observation": observation,
    }


def _runtime_code_guard(reader: Any, module_base: int, profile: Mapping[str, Any], budget: _ReadBudget) -> dict[str, Any]:
    start = len(budget.reads)
    result: dict[str, Any] = {
        "status": "unknown",
        "module_base": _hex(module_base),
        "checks": {},
        "records": {},
        "unknown_conditions": [],
    }
    try:
        for name, rva, end, expected in _profile_code_guards(profile):
            actual = _reader_read(reader, _add_address(module_base, rva), len(expected), f"country_loans.code.{name}", budget)
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
    result["read_log"] = _copy_json(budget.reads[start:])
    return result


def _read_u64(reader: Any, address: int, label: str, budget: _ReadBudget) -> tuple[int, bytes]:
    raw = _reader_read(reader, address, 8, label, budget)
    return int.from_bytes(raw, "little", signed=False), raw


def _read_optional_u8(reader: Any, address: int, label: str, budget: _ReadBudget) -> tuple[int | None, bytes | None]:
    """Read a newly closed byte without invalidating old raw loan samples."""

    try:
        raw = _reader_read(reader, address, SPECIAL_FLAG_SIZE, label, budget)
    except ReadError:
        return None, None
    return raw[0], raw


def _foreign_lender_lookup(
    reader: Any,
    *,
    module_base: int,
    lender_fullref: int,
    profile: Mapping[str, Any],
    layout: Mapping[str, int],
    budget: _ReadBudget,
) -> dict[str, Any]:
    """Resolve a foreign lender only after the native table/fullref match.

    The helper's ``+0x2690`` SSO object is deliberately not exposed as a
    country tag.  The packed fullref is exposed as a TAG only when the
    bounded country table entry at the calculated signed slot contains the
    exact same fullref.
    """

    packed = lender_fullref.to_bytes(8, "little", signed=False)
    slot = int.from_bytes(packed[4:6], "little", signed=True)
    result: dict[str, Any] = {
        "status": "unknown",
        "slot": slot,
        "slot_raw_hex": packed[4:6].hex(),
        "database_global_rva": hex(layout["database_global_rva"]),
        "database_global_address": _hex(module_base + layout["database_global_rva"]),
        "database_global_raw_hex": None,
        "database_root_pointer": None,
        "database_table_address": None,
        "database_table_pointer": None,
        "database_table_raw_hex": None,
        "country_slot_address": None,
        "country_entry_pointer": None,
        "country_entry_raw_hex": None,
        "country_entry_gate_raw_hex": None,
        "country_fullref_address": None,
        "country_fullref_raw_hex": None,
        "country_fullref_matched": None,
        "country_tag": None,
        "country_tag_status": "unknown",
        "reason": None,
    }
    if slot < 0 or slot > layout["database_max_slots"]:
        result["reason"] = "foreign_slot_out_of_range"
        return result
    try:
        global_address = _add_address(module_base, layout["database_global_rva"])
        database_root, database_root_raw = _read_u64(reader, global_address, "country_loans.lender_foreign.database_global", budget)
        result["database_global_address"] = _hex(global_address)
        result["database_global_raw_hex"] = database_root_raw.hex()
        result["database_root_pointer"] = _hex(database_root)
        if not _valid_address(database_root):
            result["reason"] = "foreign_database_root_invalid"
            return result
        table_address = _add_address(database_root, layout["database_table_offset"])
        table, table_raw = _read_u64(reader, table_address, "country_loans.lender_foreign.table", budget)
        result["database_table_address"] = _hex(table_address)
        result["database_table_pointer"] = _hex(table)
        result["database_table_raw_hex"] = table_raw.hex()
        if not _valid_address(table):
            result["reason"] = "foreign_database_table_invalid"
            return result
        slot_address = _add_address(table, slot * 8)
        entry, entry_raw = _read_u64(reader, slot_address, "country_loans.lender_foreign.entry", budget)
        result["country_slot_address"] = _hex(slot_address)
        result["country_entry_pointer"] = _hex(entry) if entry else None
        result["country_entry_raw_hex"] = entry_raw.hex()
        if not _valid_address(entry):
            result["reason"] = "foreign_country_entry_invalid"
            return result
        gate_address = _add_address(entry, layout["database_entry_gate_offset"])
        gate, gate_raw = _read_u64(reader, gate_address, "country_loans.lender_foreign.entry_gate", budget)
        result["country_entry_gate_raw_hex"] = gate_raw.hex()
        if gate == 0:
            result["reason"] = "foreign_country_entry_gate_closed"
            return result
        fullref_address = _add_address(entry, layout["database_entry_fullref_offset"])
        fullref_raw = _reader_read(reader, fullref_address, 8, "country_loans.lender_foreign.entry_fullref", budget)
        matched = fullref_raw == packed
        result["country_fullref_address"] = _hex(fullref_address)
        result["country_fullref_raw_hex"] = fullref_raw.hex()
        result["country_fullref_matched"] = matched
        if not matched:
            result["reason"] = "foreign_fullref_mismatch"
            result["country_tag_status"] = "fullref_mismatch"
            return result
        if fullref_raw[3] == 0 and all(0x30 <= value <= 0x39 or 0x41 <= value <= 0x5A for value in fullref_raw[:3]):
            result["status"] = "known"
            result["country_tag"] = fullref_raw[:3].decode("ascii")
            result["country_tag_status"] = "matched_fullref"
            result["reason"] = None
        else:
            result["status"] = "unknown"
            result["country_tag_status"] = "matched_fullref_prefix_invalid"
            result["reason"] = "foreign_fullref_tag_prefix_invalid"
        return result
    except (ReadError, TypeError, ValueError) as exc:
        result["reason"] = f"foreign_lookup_unavailable:{type(exc).__name__}"
        return result


def _record_node(
    *,
    node_address: int,
    node_payload: int,
    node_payload_raw: bytes,
    next_address: int,
    next_raw: bytes,
    record_vtable: int,
    record_vtable_raw: bytes,
    vtable_entry: int,
    vtable_entry_raw: bytes,
    record_fields_raw: bytes,
    special_flag_raw: bytes | None,
    foreign_resolution: Mapping[str, Any] | None,
    profile: Mapping[str, Any],
    layout: Mapping[str, int],
) -> dict[str, Any]:
    lender_raw = record_fields_raw[0:8]
    interest_raw = int.from_bytes(record_fields_raw[8:12], "little", signed=True)
    principal_raw = int.from_bytes(record_fields_raw[12:16], "little", signed=True)
    due_raw = int.from_bytes(record_fields_raw[16:20], "little", signed=True)
    due_raw_unsigned = int.from_bytes(record_fields_raw[16:20], "little", signed=False)
    lender_fullref = int.from_bytes(lender_raw, "little", signed=False)
    presence_raw = record_fields_raw[SPECIAL_PRESENCE_OFFSET - LENDER_OFFSET]
    special_flag_value = special_flag_raw[0] if special_flag_raw is not None else None
    if presence_raw != 0:
        lender = {
            "status": "known" if isinstance(foreign_resolution, Mapping) and foreign_resolution.get("status") == "known" else "unknown",
            "raw_fullref": lender_fullref,
            "raw_fullref_hex": lender_raw.hex(),
            "mapping": foreign_resolution.get("country_tag") if isinstance(foreign_resolution, Mapping) else None,
            "branch": "foreign",
            "special_presence_raw": presence_raw,
            "special_presence_raw_hex": bytes([presence_raw]).hex(),
            "special_flag_raw": None,
            "special_flag_raw_hex": None,
            "foreign": _copy_json(foreign_resolution) if isinstance(foreign_resolution, Mapping) else None,
            "reason": None if isinstance(foreign_resolution, Mapping) and foreign_resolution.get("status") == "known" else (foreign_resolution.get("reason") if isinstance(foreign_resolution, Mapping) else "foreign_lookup_unavailable"),
        }
    else:
        mapping = None if special_flag_value is None else ("ESTATE" if special_flag_value != 0 else "BANK")
        lender = {
            "status": "known" if mapping is not None else "unknown",
            "raw_fullref": lender_fullref,
            "raw_fullref_hex": lender_raw.hex(),
            "mapping": mapping,
            "branch": "special",
            "special_presence_raw": presence_raw,
            "special_presence_raw_hex": bytes([presence_raw]).hex(),
            "special_flag_raw": special_flag_value,
            "special_flag_raw_hex": special_flag_raw.hex() if special_flag_raw is not None else None,
            "special_status": mapping.lower() if mapping is not None else "unknown",
            "display_input": mapping,
            "foreign": None,
            "reason": None if mapping is not None else "special_lender_flag_unobserved",
        }
    calendar = project_engine_date(
        due_raw_unsigned,
        reference_raw=layout["date_reference_raw"],
        ticks_per_day=layout["date_ticks_per_day"],
        days_per_year=layout["date_days_per_year"],
    )
    return {
        "node_address": _hex(node_address),
        "record_address": _hex(node_payload),
        "node_payload_raw_hex": node_payload_raw.hex(),
        "record_vtable_pointer": _hex(record_vtable),
        "record_vtable_pointer_raw_hex": record_vtable_raw.hex(),
        "vtable_first_entry": _hex(vtable_entry),
        "vtable_first_entry_raw_hex": vtable_entry_raw.hex(),
        "next_address": _hex(next_address) if next_address else None,
        "next_raw_hex": next_raw.hex(),
        "record_fields_raw_hex": record_fields_raw.hex(),
        "lender_fullref_raw": lender_fullref,
        "lender_fullref_raw_hex": lender_raw.hex(),
        "interest_raw": interest_raw,
        "interest_raw_hex": record_fields_raw[8:12].hex(),
        "interest_percent": interest_raw / 1000.0,
        "principal_raw": principal_raw,
        "principal_raw_hex": record_fields_raw[12:16].hex(),
        "principal_ducats": principal_raw,
        # The native source names this slot "amount"; the public contract
        # calls it principal and keeps the alias explicit for consumers that
        # follow the serializer terminology.
        "amount_raw": principal_raw,
        "amount_raw_hex": record_fields_raw[12:16].hex(),
        "due_raw": due_raw,
        "due_raw_hex": record_fields_raw[16:20].hex(),
        "special_presence_raw": presence_raw,
        "special_presence_raw_hex": bytes([presence_raw]).hex(),
        "special_flag_raw": special_flag_value,
        "special_flag_raw_hex": special_flag_raw.hex() if special_flag_raw is not None else None,
        "lender": lender,
        "foreign_resolution": _copy_json(foreign_resolution) if isinstance(foreign_resolution, Mapping) else None,
        "principal": {
            "status": "known",
            "complete": True,
            "value": principal_raw,
            "raw": principal_raw,
            "raw_hex": record_fields_raw[12:16].hex(),
            "unit": "ducats",
            "scale": 1,
            "period": PERIOD,
            "basis": BASIS,
            "value_origin": VALUE_ORIGIN,
        },
        "interest": {
            "status": "known",
            "complete": True,
            "value": interest_raw / 1000.0,
            "raw": interest_raw,
            "raw_hex": record_fields_raw[8:12].hex(),
            "unit": "percent",
            "scale": 1000,
            "period": PERIOD,
            "basis": BASIS,
            "value_origin": VALUE_ORIGIN,
        },
        "due": {
            "status": "known",
            "complete": True,
            "value": due_raw,
            "raw": due_raw,
            "raw_hex": record_fields_raw[16:20].hex(),
            "unit": "engine_date_raw",
            "scale": 1,
            "period": PERIOD,
            "basis": BASIS,
            "value_origin": VALUE_ORIGIN,
            "date_semantics": "native_24_tick_365_day_projection",
            "raw_unsigned": due_raw_unsigned,
            "raw_unsigned_hex": record_fields_raw[16:20].hex(),
            "calendar": calendar,
        },
    }


def _raw_projection(node: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "node_address": node.get("node_address"),
        "record_address": node.get("record_address"),
        "node_payload_raw_hex": node.get("node_payload_raw_hex"),
        "record_vtable_pointer_raw_hex": node.get("record_vtable_pointer_raw_hex"),
        "vtable_first_entry_raw_hex": node.get("vtable_first_entry_raw_hex"),
        "lender_fullref_raw_hex": node.get("lender", {}).get("raw_fullref_hex") if isinstance(node.get("lender"), Mapping) else None,
        "special_presence_raw_hex": node.get("special_presence_raw_hex"),
        "special_flag_raw_hex": node.get("special_flag_raw_hex"),
        "interest_raw_hex": node.get("interest", {}).get("raw_hex") if isinstance(node.get("interest"), Mapping) else None,
        "principal_raw_hex": node.get("principal", {}).get("raw_hex") if isinstance(node.get("principal"), Mapping) else None,
        "due_raw_hex": node.get("due", {}).get("raw_hex") if isinstance(node.get("due"), Mapping) else None,
        "foreign_country_fullref_raw_hex": (
            node.get("foreign_resolution", {}).get("country_fullref_raw_hex")
            if isinstance(node.get("foreign_resolution"), Mapping)
            else None
        ),
        "foreign_country_tag": (
            node.get("foreign_resolution", {}).get("country_tag")
            if isinstance(node.get("foreign_resolution"), Mapping)
            else None
        ),
        "next_raw_hex": node.get("next_raw_hex"),
        "record_fields_raw_hex": node.get("record_fields_raw_hex"),
    }


def read_fields(reader: Any, module_base: int, country_pointer: int, profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Copy the bounded current loan list and its closed raw record fields."""
    budget = _ReadBudget()
    try:
        loaded = _load_profile() if profile is None else _prepare_profile(profile)
    except Exception as exc:
        return _empty_record(
            "static_contract_guard_failed",
            module_base=module_base if type(module_base) is int else None,
            country_pointer=country_pointer if type(country_pointer) is int else None,
        ) | {"detail": f"{type(exc).__name__}:{exc}"}
    static_guard = _static_contract_guard(loaded)
    if static_guard.get("status") != "observed":
        return _empty_record(
            "static_contract_guard_failed",
            static_guard=static_guard,
            module_base=module_base if type(module_base) is int else None,
            country_pointer=country_pointer if type(country_pointer) is int else None,
            read_budget=budget.snapshot(),
            read_log=budget.reads,
        )
    try:
        layout = _profile_layout(loaded)
        budget = _ReadBudget(layout["read_budget_bytes"])
    except ProfileError as exc:
        return _empty_record(str(exc), static_guard=static_guard, module_base=module_base, country_pointer=country_pointer)
    if not _valid_address(module_base, minimum=layout["pointer_min"], maximum=layout["pointer_max"]) or not _valid_address(
        country_pointer, minimum=layout["pointer_min"], maximum=layout["pointer_max"]
    ):
        return _empty_record(
            "pointer_invalid",
            static_guard=static_guard,
            module_base=module_base if type(module_base) is int else None,
            country_pointer=country_pointer if type(country_pointer) is int else None,
            read_budget=budget.snapshot(),
            read_log=budget.reads,
        )
    runtime_guard = _runtime_code_guard(reader, module_base, loaded, budget)
    if runtime_guard.get("status") != "observed":
        return _empty_record(
            "runtime_code_guard_failed",
            static_guard=static_guard,
            runtime_guard=runtime_guard,
            module_base=module_base,
            country_pointer=country_pointer,
            read_budget=budget.snapshot(),
            read_log=budget.reads,
        )
    try:
        container_address = _add_address(country_pointer, layout["country_loans_offset"])
        head, head_raw = _read_u64(reader, container_address, "country_loans.container_head", budget)
        if head and not _valid_address(head, minimum=layout["pointer_min"], maximum=layout["pointer_max"]):
            raise ReadError("loan_container_head_invalid")
        nodes: list[dict[str, Any]] = []
        compact: list[dict[str, Any]] = []
        seen_nodes: set[int] = set()
        seen_records: set[int] = set()
        current = head
        while current:
            if len(nodes) >= layout["max_nodes"]:
                raise ReadError("loan_node_limit_exceeded")
            if current in seen_nodes:
                raise ReadError("loan_node_cycle_detected")
            if not _valid_address(current, minimum=layout["pointer_min"], maximum=layout["pointer_max"]):
                raise ReadError("loan_node_pointer_invalid")
            seen_nodes.add(current)
            node_payload, node_payload_raw = _read_u64(
                reader, _add_address(current, layout["node_payload_offset"]), "country_loans.node_payload", budget
            )
            if not _valid_address(node_payload, minimum=layout["pointer_min"], maximum=layout["pointer_max"]):
                raise ReadError("loan_record_pointer_invalid")
            if node_payload in seen_records:
                raise ReadError("loan_record_cycle_detected")
            seen_records.add(node_payload)
            record_vtable, record_vtable_raw = _read_u64(
                reader, _add_address(node_payload, layout["loan_record_vtable_offset"]), "country_loans.record_vtable", budget
            )
            if not _valid_module_pointer(record_vtable, module_base, layout["vtable_rva_begin"], layout["vtable_rva_end"]):
                raise ReadError("loan_record_vtable_invalid")
            vtable_entry, vtable_entry_raw = _read_u64(
                reader, _add_address(record_vtable, layout["vtable_guard_entry_offset"]), "country_loans.vtable_entry", budget
            )
            if not _valid_module_pointer(vtable_entry, module_base, layout["code_rva_begin"], layout["code_rva_end"]):
                raise ReadError("loan_vtable_entry_invalid")
            fields_address = _add_address(node_payload, layout["lender_fullref_offset"])
            fields_raw = _reader_read(reader, fields_address, RECORD_FIELDS_SIZE, "country_loans.record_fields", budget)
            special_flag_address = _add_address(node_payload, layout["special_flag_offset"])
            special_flag_value, special_flag_raw = _read_optional_u8(
                reader, special_flag_address, "country_loans.special_flag", budget
            )
            lender_fullref = int.from_bytes(fields_raw[0:8], "little", signed=False)
            foreign_resolution = None
            if fields_raw[layout["special_presence_offset"] - layout["lender_fullref_offset"]] != 0:
                foreign_resolution = _foreign_lender_lookup(
                    reader,
                    module_base=module_base,
                    lender_fullref=lender_fullref,
                    profile=loaded,
                    layout=layout,
                    budget=budget,
                )
            next_address, next_raw = _read_u64(
                reader, _add_address(current, layout["node_next_offset"]), "country_loans.node_next", budget
            )
            if next_address and not _valid_address(next_address, minimum=layout["pointer_min"], maximum=layout["pointer_max"]):
                raise ReadError("loan_node_next_invalid")
            node = _record_node(
                node_address=current,
                node_payload=node_payload,
                node_payload_raw=node_payload_raw,
                next_address=next_address,
                next_raw=next_raw,
                record_vtable=record_vtable,
                record_vtable_raw=record_vtable_raw,
                vtable_entry=vtable_entry,
                vtable_entry_raw=vtable_entry_raw,
                record_fields_raw=fields_raw,
                special_flag_raw=special_flag_raw,
                foreign_resolution=foreign_resolution,
                profile=loaded,
                layout=layout,
            )
            nodes.append(node)
            compact.append(
                {
                    "node_address": node["node_address"],
                    "record_address": node["record_address"],
                    "next_address": node["next_address"],
                    "record_fields_raw_hex": node["record_fields_raw_hex"],
                    "special_presence_raw_hex": node["special_presence_raw_hex"],
                    "special_flag_raw_hex": node["special_flag_raw_hex"],
                    "foreign_resolution": _copy_json(node.get("foreign_resolution")),
                }
            )
            current = next_address
    except (ReadError, ProfileError, TypeError, ValueError) as exc:
        return _empty_record(
            str(exc),
            static_guard=static_guard,
            runtime_guard=runtime_guard,
            module_base=module_base,
            country_pointer=country_pointer,
            read_budget=budget.snapshot(),
            read_log=budget.reads,
        )

    value = _copy_json(nodes)
    field = {
        "status": "known",
        "complete": False,
        "partial": PARTIAL,
        "value": value,
        "unit": UNIT,
        "scale": SCALE,
        "period": PERIOD,
        "basis": BASIS,
        "value_origin": VALUE_ORIGIN,
        "unknown_conditions": [
            "special lender +0x36 may be absent from historical raw samples",
            "foreign lender country tag requires strict table/fullref match",
            "nested loan serializer and amount-with-interest helper unresolved",
        ],
    }
    read_budget = budget.snapshot()
    observation = {
        "profile_id": loaded["profile_id"],
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "module_base": _hex(module_base),
        "country_pointer": _hex(country_pointer),
        "container_address": _hex(container_address),
        "container_offset": hex(layout["country_loans_offset"]),
        "container_head": _hex(head) if head else None,
        "container_head_raw_hex": head_raw.hex(),
        "node_count": len(nodes),
        "nodes": compact,
        "basis": BASIS,
        "unit": UNIT,
        "scale": SCALE,
        "period": PERIOD,
        "value_origin": VALUE_ORIGIN,
        "static_contract_guard": _copy_json(static_guard),
        "runtime_code_guard": _copy_json(runtime_guard),
        "read_budget": read_budget,
        "read_log": _copy_json(budget.reads),
    }
    return {
        "status": "observed",
        "profile_id": loaded["profile_id"],
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "module_base": _hex(module_base),
        "country_pointer": _hex(country_pointer),
        "static_contract_guard": static_guard,
        "runtime_code_guard": runtime_guard,
        "fields": {FIELD_KEY: field},
        "values": {FIELD_KEY: value},
        "raw_hex": {FIELD_KEY: [_raw_projection(node) for node in nodes]},
        "raw_bytes_hex": {FIELD_KEY: [_raw_projection(node) for node in nodes]},
        "basis": BASIS,
        "unit": UNIT,
        "scale": SCALE,
        "period": PERIOD,
        "value_origin": VALUE_ORIGIN,
        "observation": observation,
    }


def _valid_hex_address(value: Any, *, allow_none: bool = False) -> bool:
    if allow_none and value is None:
        return True
    if not isinstance(value, str):
        return False
    try:
        return _valid_address(int(value, 0))
    except (TypeError, ValueError):
        return False


def _runtime_guard_valid(guard: Any, profile: Mapping[str, Any], module_base: int) -> bool:
    if not isinstance(guard, Mapping) or guard.get("status") != "observed" or guard.get("module_base") != _hex(module_base):
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
        expected_sha = hashlib.sha256(raw).hexdigest()
        if (
            item.get("rva") != hex(rva)
            or item.get("rva_end_exclusive") != hex(end)
            or item.get("address") != _hex(module_base + rva)
            or item.get("expected_hex") != raw.hex()
            or item.get("actual_hex") != raw.hex()
            or item.get("expected_sha256") != expected_sha
            or item.get("actual_sha256") != expected_sha
        ):
            return False
    records_bytes = sum(end - begin for _name, begin, end, _raw in _profile_code_guards(profile))
    return (
        type(guard.get("bytes_reserved")) is int
        and guard.get("bytes_reserved") == records_bytes
        and guard.get("limit") == READ_BUDGET_BYTES
        and isinstance(guard.get("read_log"), list)
        and len(guard["read_log"]) == len(expected)
        and all(isinstance(item, Mapping) and item.get("status") == "ok" for item in guard["read_log"])
    )


def _static_guard_valid(guard: Any, profile: Mapping[str, Any]) -> bool:
    return isinstance(guard, Mapping) and guard == _static_contract_guard(profile)


def _field_value_valid(node: Mapping[str, Any], key: str, raw: bytes, *, unit: str, scale: int, complete: bool) -> bool:
    item = node.get(key)
    if not isinstance(item, Mapping):
        return False
    raw_value = int.from_bytes(raw, "little", signed=True)
    expected_value: Any = raw_value if key != "interest" else raw_value / 1000.0
    return {
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
    } == {
        "status": "known",
        "complete": complete,
        "value": expected_value,
        "raw": raw_value,
        "raw_hex": raw.hex(),
        "unit": unit,
        "scale": scale,
        "period": PERIOD,
        "basis": BASIS,
        "value_origin": VALUE_ORIGIN,
    }


def _validate_node(
    node: Any,
    expected_node: int,
    expected_next: int | None,
    layout: Mapping[str, int],
    module_base: int,
) -> tuple[bool, int | None, dict[str, Any] | None]:
    if not isinstance(node, Mapping) or node.get("node_address") != _hex(expected_node):
        return False, None, None
    try:
        record = int(node.get("record_address"), 0)
        payload_raw = bytes.fromhex(str(node.get("node_payload_raw_hex")))
        vtable = int(node.get("record_vtable_pointer"), 0)
        vtable_raw = bytes.fromhex(str(node.get("record_vtable_pointer_raw_hex")))
        entry = int(node.get("vtable_first_entry"), 0)
        entry_raw = bytes.fromhex(str(node.get("vtable_first_entry_raw_hex")))
        fields_raw = bytes.fromhex(str(node.get("record_fields_raw_hex")))
        next_raw = bytes.fromhex(str(node.get("next_raw_hex")))
    except (TypeError, ValueError):
        return False, None, None
    if (
        len(payload_raw) != 8
        or len(vtable_raw) != 8
        or len(entry_raw) != 8
        or len(fields_raw) != RECORD_FIELDS_SIZE
        or len(next_raw) != 8
        or int.from_bytes(payload_raw, "little") != record
        or int.from_bytes(vtable_raw, "little") != vtable
        or int.from_bytes(entry_raw, "little") != entry
    ):
        return False, None, None
    next_value = int.from_bytes(next_raw, "little")
    if expected_next is not None:
        expected_next_hex = _hex(expected_next)
        if next_value != expected_next or node.get("next_address") != expected_next_hex:
            return False, None, None
    elif node.get("next_address") != (_hex(next_value) if next_value else None):
        return False, None, None
    if not (
        _valid_address(record)
        and _valid_module_pointer(vtable, module_base, layout["vtable_rva_begin"], layout["vtable_rva_end"])
        and _valid_module_pointer(entry, module_base, layout["code_rva_begin"], layout["code_rva_end"])
    ):
        return False, None, None
    lender_raw = fields_raw[0:8]
    interest_raw = fields_raw[8:12]
    principal_raw = fields_raw[12:16]
    due_raw = fields_raw[16:20]
    due_unsigned = int.from_bytes(due_raw, "little", signed=False)
    lender = node.get("lender")
    if not isinstance(lender, Mapping):
        return False, None, None
    lender_value = int.from_bytes(lender_raw, "little")
    presence_value = fields_raw[SPECIAL_PRESENCE_OFFSET - LENDER_OFFSET]
    if (
        lender.get("raw_fullref") != lender_value
        or lender.get("raw_fullref_hex") != lender_raw.hex()
        or lender.get("special_presence_raw") != presence_value
        or lender.get("special_presence_raw_hex") != bytes([presence_value]).hex()
        or node.get("special_presence_raw") != presence_value
        or node.get("special_presence_raw_hex") != bytes([presence_value]).hex()
        or lender.get("special_flag_raw") != node.get("special_flag_raw")
        or lender.get("special_flag_raw_hex") != node.get("special_flag_raw_hex")
    ):
        return False, None, None
    try:
        special_flag_hex = node.get("special_flag_raw_hex")
        special_flag = None if special_flag_hex is None else bytes.fromhex(str(special_flag_hex))
    except ValueError:
        return False, None, None
    if special_flag is not None and len(special_flag) != SPECIAL_FLAG_SIZE:
        return False, None, None
    if node.get("special_flag_raw") != (special_flag[0] if special_flag is not None else None):
        return False, None, None
    if presence_value == 0:
        if lender.get("branch") != "special" or lender.get("foreign") is not None:
            return False, None, None
        if special_flag is None:
            if lender.get("status") != "unknown" or lender.get("mapping") is not None or lender.get("special_status") != "unknown" or lender.get("reason") != "special_lender_flag_unobserved":
                return False, None, None
        else:
            expected_mapping = "ESTATE" if special_flag[0] != 0 else "BANK"
            if (
                lender.get("status") != "known"
                or lender.get("mapping") != expected_mapping
                or lender.get("special_status") != expected_mapping.lower()
                or lender.get("display_input") != expected_mapping
                or lender.get("reason") is not None
            ):
                return False, None, None
    else:
        if lender.get("branch") != "foreign" or special_flag is not None:
            return False, None, None
        foreign = lender.get("foreign")
        if not isinstance(foreign, Mapping) or node.get("foreign_resolution") != foreign:
            return False, None, None
        packed = lender_raw
        expected_slot = int.from_bytes(packed[4:6], "little", signed=True)
        if (
            foreign.get("slot") != expected_slot
            or foreign.get("slot_raw_hex") != packed[4:6].hex()
            or foreign.get("database_global_rva") != hex(DATABASE_GLOBAL_RVA)
            or foreign.get("database_global_address") != _hex(module_base + DATABASE_GLOBAL_RVA)
        ):
            return False, None, None
        for pointer_key, raw_key in (
            ("database_root_pointer", "database_global_raw_hex"),
            ("database_table_pointer", "database_table_raw_hex"),
            ("country_entry_pointer", "country_entry_raw_hex"),
        ):
            pointer = foreign.get(pointer_key)
            raw_hex = foreign.get(raw_key)
            if pointer is None and raw_hex is None:
                continue
            if not _valid_hex_address(pointer) or not isinstance(raw_hex, str) or len(raw_hex) != 16:
                return False
            try:
                raw_value = int.from_bytes(bytes.fromhex(raw_hex), "little")
            except ValueError:
                return False
            if raw_value != int(pointer, 0):
                return False
        if foreign.get("database_root_pointer") is not None:
            if foreign.get("database_table_address") != _hex(int(foreign["database_root_pointer"], 0) + DATABASE_TABLE_OFFSET):
                return False
        if foreign.get("database_table_pointer") is not None:
            table = int(foreign["database_table_pointer"], 0)
            if foreign.get("country_slot_address") != _hex(table + expected_slot * 8):
                return False
        if foreign.get("country_entry_pointer") is not None and foreign.get("country_fullref_address") is not None:
            if foreign.get("country_fullref_address") != _hex(int(foreign["country_entry_pointer"], 0) + DATABASE_ENTRY_FULLREF_OFFSET):
                return False
        if foreign.get("status") == "known":
            fullref_hex = foreign.get("country_fullref_raw_hex")
            tag = foreign.get("country_tag")
            if (
                foreign.get("country_fullref_matched") is not True
                or not isinstance(fullref_hex, str)
                or fullref_hex != packed.hex()
                or foreign.get("country_tag_status") != "matched_fullref"
                or not isinstance(tag, str)
                or len(tag) != 3
                or any(not ("0" <= char <= "9" or "A" <= char <= "Z") for char in tag)
                or tag != packed[:3].decode("ascii", errors="ignore")
                or lender.get("mapping") != tag
                or lender.get("status") != "known"
            ):
                return False, None, None
        else:
            if lender.get("status") != "unknown" or lender.get("mapping") is not None or foreign.get("country_tag") is not None:
                return False, None, None
    if (
        node.get("lender_fullref_raw") != lender_value
        or node.get("lender_fullref_raw_hex") != lender_raw.hex()
        or node.get("interest_raw") != int.from_bytes(interest_raw, "little", signed=True)
        or node.get("interest_raw_hex") != interest_raw.hex()
        or node.get("interest_percent") != int.from_bytes(interest_raw, "little", signed=True) / 1000.0
        or node.get("principal_raw") != int.from_bytes(principal_raw, "little", signed=True)
        or node.get("principal_raw_hex") != principal_raw.hex()
        or node.get("principal_ducats") != int.from_bytes(principal_raw, "little", signed=True)
        or node.get("amount_raw") != int.from_bytes(principal_raw, "little", signed=True)
        or node.get("amount_raw_hex") != principal_raw.hex()
        or node.get("due_raw") != int.from_bytes(due_raw, "little", signed=True)
        or node.get("due_raw_hex") != due_raw.hex()
    ):
        return False, None, None
    if not _field_value_valid(node, "principal", principal_raw, unit="ducats", scale=1, complete=True):
        return False, None, None
    if not _field_value_valid(node, "interest", interest_raw, unit="percent", scale=1000, complete=True):
        return False, None, None
    if not _field_value_valid(node, "due", due_raw, unit="engine_date_raw", scale=1, complete=True):
        return False, None, None
    due = node.get("due")
    if not isinstance(due, Mapping) or due.get("date_semantics") != "native_24_tick_365_day_projection":
        return False, None, None
    expected_calendar = project_engine_date(
        due_unsigned,
        reference_raw=DATE_REFERENCE_RAW,
        ticks_per_day=DATE_TICKS_PER_DAY,
        days_per_year=DATE_DAYS_PER_YEAR,
    )
    if (
        due.get("raw_unsigned") != due_unsigned
        or due.get("raw_unsigned_hex") != due_raw.hex()
        or due.get("calendar") != expected_calendar
    ):
        return False, None, None
    projection = _raw_projection(node)
    if projection["lender_fullref_raw_hex"] != lender_raw.hex() or projection["interest_raw_hex"] != interest_raw.hex() or projection["principal_raw_hex"] != principal_raw.hex() or projection["due_raw_hex"] != due_raw.hex():
        return False, None, None
    return True, next_value or None, projection


def _read_log_valid(observation: Mapping[str, Any], runtime_guard: Mapping[str, Any], node_count: int) -> bool:
    budget = observation.get("read_budget")
    logs = observation.get("read_log")
    if not isinstance(budget, Mapping) or not isinstance(logs, list):
        return False
    if budget.get("limit") != READ_BUDGET_BYTES or type(budget.get("bytes_reserved")) is not int:
        return False
    if not 0 < budget["bytes_reserved"] <= READ_BUDGET_BYTES:
        return False
    total = 0
    for item in logs:
        if not isinstance(item, Mapping) or type(item.get("size")) is not int or item.get("size") <= 0 or not isinstance(item.get("label"), str):
            return False
        total += item["size"]
        if item.get("status") == "ok":
            try:
                raw = bytes.fromhex(str(item.get("raw_hex")))
            except ValueError:
                return False
            if len(raw) != item["size"] or item.get("sha256") != hashlib.sha256(raw).hexdigest():
                return False
        elif item.get("status") != "failed":
            return False
    dynamic = sum(
        item["size"]
        for item in logs
        if isinstance(item, Mapping) and str(item.get("label", "")).startswith("country_loans.lender_foreign.")
    )
    expected = int(runtime_guard.get("bytes_reserved", -1)) + 8 + node_count * (8 + 8 + 8 + RECORD_FIELDS_SIZE + SPECIAL_FLAG_SIZE + 8) + dynamic
    failed = [item for item in logs if item.get("status") == "failed"]
    optional_failed = all(
        str(item.get("label", "")).startswith(("country_loans.special_flag", "country_loans.lender_foreign."))
        for item in failed
    )
    return total == budget["bytes_reserved"] == expected and optional_failed


def validate_record(record: Any) -> bool:
    """Validate provenance, list topology, raw fields, and derived values."""
    if not isinstance(record, Mapping) or record.get("status") != "observed":
        return False
    try:
        profile = _load_profile()
        if record.get("profile_id") != profile.get("profile_id") or record.get("profile_sha256") != EXPECTED_PROFILE_SHA256:
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
        fields = record.get("fields")
        values = record.get("values")
        raw_hexes = record.get("raw_hex")
        raw_bytes_hexes = record.get("raw_bytes_hex")
        if not all(isinstance(item, Mapping) for item in (fields, values, raw_hexes, raw_bytes_hexes)):
            return False
        if set(fields) != set(FIELDS) or set(values) != set(FIELDS) or set(raw_hexes) != set(FIELDS) or set(raw_bytes_hexes) != set(FIELDS):
            return False
        nodes = values[FIELD_KEY]
        field = fields[FIELD_KEY]
        if not isinstance(nodes, list) or not isinstance(field, Mapping) or field.get("status") != "known" or field.get("complete") is not False or field.get("partial") is not True or field.get("value") != nodes:
            return False
        if field.get("unit") != UNIT or field.get("scale") != SCALE or field.get("period") != PERIOD or field.get("basis") != BASIS or field.get("value_origin") != VALUE_ORIGIN:
            return False
        observation = record.get("observation")
        if not isinstance(observation, Mapping):
            return False
        container_address = _add_address(country_pointer, layout["country_loans_offset"])
        head_raw = bytes.fromhex(str(observation.get("container_head_raw_hex")))
        if len(head_raw) != 8:
            return False
        head = int.from_bytes(head_raw, "little")
        if observation.get("profile_id") != profile.get("profile_id") or observation.get("profile_sha256") != EXPECTED_PROFILE_SHA256 or observation.get("module_base") != record.get("module_base") or observation.get("country_pointer") != record.get("country_pointer") or observation.get("container_address") != _hex(container_address) or observation.get("container_offset") != hex(COUNTRY_OFFSET) or observation.get("container_head") != (_hex(head) if head else None) or observation.get("container_head_raw_hex") != head_raw.hex() or observation.get("node_count") != len(nodes) or observation.get("nodes") != [{"node_address": node.get("node_address"), "record_address": node.get("record_address"), "next_address": node.get("next_address"), "record_fields_raw_hex": node.get("record_fields_raw_hex"), "special_presence_raw_hex": node.get("special_presence_raw_hex"), "special_flag_raw_hex": node.get("special_flag_raw_hex"), "foreign_resolution": _copy_json(node.get("foreign_resolution"))} for node in nodes] or observation.get("static_contract_guard") != record.get("static_contract_guard") or observation.get("runtime_code_guard") != record.get("runtime_code_guard"):
            return False
        if len(nodes) > layout["max_nodes"] or not _read_log_valid(observation, record["runtime_code_guard"], len(nodes)):
            return False
        expected_node = head
        seen: set[int] = set()
        projections: list[dict[str, Any]] = []
        for node in nodes:
            if not expected_node or expected_node in seen:
                return False
            seen.add(expected_node)
            ok, expected_node, projection = _validate_node(node, expected_node, None, layout, module_base)
            # _validate_node checks the node's own next pointer.  The expected
            # next is established by the returned value and is checked against
            # the next list element on the following iteration.
            if not ok or projection is None:
                return False
            projections.append(projection)
        if expected_node:
            return False
        if head == 0 and nodes:
            return False
        if raw_hexes[FIELD_KEY] != projections or raw_bytes_hexes[FIELD_KEY] != projections:
            return False
        if not nodes and head != 0:
            return False
        return True
    except (KeyError, TypeError, ValueError, OSError, ProfileError, ReadError):
        return False


def retract_record(record: Any, reason: str = "observation_retracted") -> dict[str, Any]:
    """Remove loan records after a failed second pass or cleanup."""
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
    "PROFILE_FILE",
    "PROFILE_MAX_BYTES",
    "SOURCE_EVIDENCE_MAX_BYTES",
    "EXPECTED_PROFILE_SHA256",
    "EXPECTED_PROFILE_ID",
    "EXPECTED_EXE_SHA256",
    "EXPECTED_VERSION",
    "EXPECTED_COUNTRY",
    "FIELDS",
    "BASIS",
    "VALUE_ORIGIN",
    "PERIOD",
    "UNIT",
    "SCALE",
    "COUNTRY_OFFSET",
    "SPECIAL_PRESENCE_OFFSET",
    "SPECIAL_FLAG_OFFSET",
    "DATABASE_GLOBAL_RVA",
    "DATABASE_TABLE_OFFSET",
    "DATABASE_ENTRY_GATE_OFFSET",
    "DATABASE_ENTRY_FULLREF_OFFSET",
    "DATE_REFERENCE_RAW",
    "MAX_NODES",
    "READ_BUDGET_BYTES",
    "ProfileError",
    "ReadError",
    "read_fields",
    "validate_record",
    "retract_record",
    "_load_profile",
    "_profile_layout",
    "_profile_code_guards",
    "_runtime_code_guard",
    "_static_contract_guard",
    "_ReadBudget",
]
