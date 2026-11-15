"""Bounded read-only reader for the native trade-league membership object.

The public relation adapter owns query shaping.  This module owns only the
country object, its predicate, the fullref vector, and the country-table
binding.  It never calls the virtual predicate and never treats an invalid
member as an empty known vector.
"""
from __future__ import annotations

from copy import deepcopy
import ctypes as C
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from . import country_resources_memory as _crm
from . import localization_memory as _loc
from . import mission_memory as _mm
from .observation_time import dates_match, without_clock


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "trade-league-memory-1374.json"
PROFILE_MAX_BYTES = 64 * 1024
SOURCE_MAX_BYTES = 8 * 1024 * 1024
EXPECTED_PROFILE_SHA256 = "e539d3651f23bd84fa13cfaa70649315cc166625386dfc94f0acdb3cb3cf980c"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_VERSION = "1.37.4"
EXPECTED_COUNTRY = "FRA"
FIELDS = ("trade_league",)

BASIS = "native_country_trade_league_membership"
UNIT = "relation_state"
SCALE = 1
PERIOD = "current"
VALUE_ORIGIN = "copied_native_country_trade_league_object_vector"

MAX_USER_ADDRESS = _mm.MAX_USER_ADDRESS
MAX_SINGLE_RPM = 64 * 1024
MAX_TOTAL_RPM = 512 * 1024
QWORD_WIDTH = 8
I32_WIDTH = 4
NULL_FULLREF_RAW_HEX = "2d2d2d0000000000"

PROCESS_ACCESS = _mm.PROCESS_ACCESS
AddressBoundedRPM = _crm.AddressBoundedRPM
_load_installation = _loc._load_installation
_configure_kernel = _loc._configure_kernel
_capture_identity = _loc._capture_identity
_close_process_handle = _loc._close_process_handle
_read_pe_rva_bytes = _loc._read_pe_rva_bytes


class ProfileError(RuntimeError):
    """The pinned trade-league profile or source evidence is invalid."""


class ProbeError(RuntimeError):
    """A bounded read or identity check failed."""


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
        raise ProfileError(f"{label}_read_size_changed")
    return raw


def _workspace_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _source_path(raw_path: Any) -> Path:
    if not isinstance(raw_path, str) or not raw_path:
        raise ProfileError("source_path_invalid")
    path = Path(raw_path)
    resolved = (path if path.is_absolute() else _workspace_root() / path).resolve()
    root = _workspace_root()
    if resolved != root and root not in resolved.parents:
        raise ProfileError("source_path_outside_workspace")
    return resolved


def _validate_source_evidence(profile: Mapping[str, Any]) -> dict[str, bool]:
    refs = profile.get("source_evidence")
    if not isinstance(refs, list) or not refs:
        raise ProfileError("source_evidence_missing")
    checks: dict[str, bool] = {}
    for item in refs:
        if not isinstance(item, Mapping):
            raise ProfileError("source_evidence_item_invalid")
        path = _source_path(item.get("path"))
        expected = item.get("sha256")
        if not isinstance(expected, str) or len(expected) != 64:
            raise ProfileError("source_evidence_sha256_invalid")
        raw = _bounded_file(path, SOURCE_MAX_BYTES, "source_evidence")
        actual = hashlib.sha256(raw).hexdigest()
        checks[str(item["path"])] = actual.lower() == expected.lower()
        if not checks[str(item["path"])]:
            raise ProfileError(f"source_evidence_sha256_mismatch:{item['path']}")
        if item.get("bytes") is not None and _parse_int(item["bytes"], "source_evidence.bytes") != len(raw):
            raise ProfileError(f"source_evidence_size_mismatch:{item['path']}")
    return checks


def _profile_guards(profile: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = profile.get("code_guards")
    if not isinstance(raw, list) or not raw:
        raise ProfileError("profile_code_guards_missing")
    result: list[dict[str, Any]] = []
    names: set[str] = set()
    for item in raw:
        if not isinstance(item, Mapping):
            raise ProfileError("profile_code_guard_invalid")
        name = item.get("name")
        if not isinstance(name, str) or not name or name in names:
            raise ProfileError("profile_code_guard_name_invalid")
        hex_value = item.get("hex", item.get("bytes"))
        if not isinstance(hex_value, str) or not hex_value or len(hex_value) % 2:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}")
        try:
            expected = bytes.fromhex(hex_value)
        except ValueError as exc:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}") from exc
        rva = _parse_int(item.get("rva"), f"profile_code_guard.{name}.rva")
        end = _parse_int(item.get("end_rva_exclusive"), f"profile_code_guard.{name}.end")
        if end != rva + len(expected) or len(expected) > MAX_SINGLE_RPM:
            raise ProfileError(f"profile_code_guard_range_invalid:{name}")
        if hashlib.sha256(expected).hexdigest() != str(item.get("sha256", "")).lower():
            raise ProfileError(f"profile_code_guard_sha_invalid:{name}")
        kind = item.get("kind", "bytes")
        if kind not in {"bytes", "pointer_slot"}:
            raise ProfileError(f"profile_code_guard_kind_invalid:{name}")
        target_rva = None
        if kind == "pointer_slot":
            target_rva = _parse_int(item.get("target_rva"), f"profile_code_guard.{name}.target_rva")
        names.add(name)
        result.append({
            "name": name, "kind": kind, "rva": rva, "end": end,
            "expected": expected, "target_rva": target_rva,
        })
    return result


def _profile_layout(profile: Mapping[str, Any]) -> dict[str, Any]:
    try:
        executable = profile["executable"]
        globals_ = profile["globals"]
        country = profile["country"]
        league = profile["trade_league"]
        limits = profile["limits"]
        if not all(isinstance(x, Mapping) for x in (executable, globals_, country, league, limits)):
            raise ProfileError("profile_layout_not_object")
        if profile.get("profile_id") != "trade-league-memory-1374":
            raise ProfileError("profile_id_invalid")
        if profile.get("game_version") != EXPECTED_VERSION:
            raise ProfileError("profile_version_invalid")
        if str(executable.get("sha256", "")).lower() != EXPECTED_EXE_SHA256:
            raise ProfileError("profile_executable_sha_invalid")
        if country.get("supported_actor") != EXPECTED_COUNTRY:
            raise ProfileError("profile_supported_actor_invalid")
        result = {
            "database_global_rva": _parse_int(globals_.get("database_global_rva"), "globals.database_global_rva"),
            "game_global_rva": _parse_int(globals_.get("game_global_rva"), "globals.game_global_rva"),
            "game_date_offset": _parse_int(globals_.get("game_date_offset"), "globals.game_date_offset"),
            "trade_league_offset": _parse_int(country.get("trade_league_offset"), "country.trade_league_offset"),
            "fullref_offset": _parse_int(country.get("fullref_offset"), "country.fullref_offset"),
            "table_offset": _parse_int(country.get("table_offset"), "country.table_offset"),
            "count_offset": _parse_int(country.get("count_offset"), "country.count_offset"),
            "max_country_entries": _parse_int(country.get("max_entries"), "country.max_entries"),
            "object_prefix_size": _parse_int(league.get("object_prefix_size"), "trade_league.object_prefix_size"),
            "vtable_method_slot": _parse_int(league.get("vtable_method_slot"), "trade_league.vtable_method_slot"),
            "vector_begin_offset": _parse_int(league.get("vector_begin_offset"), "trade_league.vector_begin_offset"),
            "vector_end_offset": _parse_int(league.get("vector_end_offset"), "trade_league.vector_end_offset"),
            "vector_stride": _parse_int(league.get("vector_stride"), "trade_league.vector_stride"),
            "null_vtable_rva": _parse_int(league.get("null_vtable_rva"), "trade_league.null_vtable_rva"),
            "active_vtable_rva": _parse_int(league.get("active_vtable_rva"), "trade_league.active_vtable_rva"),
            "null_predicate_rva": _parse_int(league.get("null_predicate_rva"), "trade_league.null_predicate_rva"),
            "active_predicate_rva": _parse_int(league.get("active_predicate_rva"), "trade_league.active_predicate_rva"),
            "null_vtable_slot_rva": _parse_int(league.get("null_vtable_slot_rva"), "trade_league.null_vtable_slot_rva"),
            "active_vtable_slot_rva": _parse_int(league.get("active_vtable_slot_rva"), "trade_league.active_vtable_slot_rva"),
            "max_vector_count": _parse_int(limits.get("max_vector_count"), "limits.max_vector_count"),
            "max_total_rpm": _parse_int(limits.get("max_total_rpm"), "limits.max_total_rpm"),
            "max_single_rpm": _parse_int(limits.get("max_single_rpm"), "limits.max_single_rpm"),
            "null_fullref_raw_hex": league.get("null_fullref_raw_hex"),
        }
    except (KeyError, TypeError) as exc:
        raise ProfileError(f"profile_layout_invalid:{exc}") from exc
    if result["object_prefix_size"] != 0x40 or result["vtable_method_slot"] != 0x40:
        raise ProfileError("profile_object_contract_invalid")
    if (result["vector_begin_offset"], result["vector_end_offset"], result["vector_stride"]) != (0x20, 0x28, 8):
        raise ProfileError("profile_vector_contract_invalid")
    if result["max_country_entries"] < 1 or result["max_country_entries"] > 4096:
        raise ProfileError("profile_country_bound_invalid")
    if result["max_vector_count"] < 1 or result["max_vector_count"] > 4096:
        raise ProfileError("profile_vector_bound_invalid")
    if result["max_total_rpm"] != MAX_TOTAL_RPM or result["max_single_rpm"] != MAX_SINGLE_RPM:
        raise ProfileError("profile_budget_invalid")
    if result["null_fullref_raw_hex"] != NULL_FULLREF_RAW_HEX:
        raise ProfileError("profile_null_sentinel_invalid")
    return result


def _load_profile(path: Path | None = None, expected_sha256: str | None = None) -> dict[str, Any]:
    path = PROFILE_FILE if path is None else Path(path)
    expected_sha256 = EXPECTED_PROFILE_SHA256 if expected_sha256 is None else expected_sha256
    raw = _bounded_file(path, PROFILE_MAX_BYTES, "profile")
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
        raise ProfileError("profile_sha256_pin_invalid")
    if hashlib.sha256(raw).hexdigest().lower() != expected_sha256.lower():
        raise ProfileError("profile_sha256_mismatch")
    try:
        profile = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"profile_json_invalid:{exc}") from exc
    if not isinstance(profile, dict):
        raise ProfileError("profile_json_shape_invalid")
    layout = _profile_layout(profile)
    source_checks = _validate_source_evidence(profile)
    guards = _profile_guards(profile)
    semantics = profile.get("semantics")
    if not isinstance(semantics, Mapping) or semantics.get("basis") != BASIS or semantics.get("unit") != UNIT or semantics.get("scale") != SCALE or semantics.get("period") != PERIOD:
        raise ProfileError("profile_semantics_invalid")
    profile = dict(profile)
    profile["_layout"] = layout
    profile["_guards"] = guards
    profile["_source_checks"] = source_checks
    return profile


try:
    PROFILE: dict[str, Any] | None = _load_profile()
except ProfileError:
    PROFILE = None


def _active_profile() -> dict[str, Any]:
    return _load_profile()


def _hex(value: int | None) -> str | None:
    return hex(value) if isinstance(value, int) else None


def _valid_pointer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0x10000 <= value <= MAX_USER_ADDRESS


def _safe_add(base: int, offset: int, label: str) -> int:
    if not _valid_pointer(base) or not isinstance(offset, int) or offset < 0:
        raise ProbeError(f"address_invalid:{label}")
    value = base + offset
    if not _valid_pointer(value):
        raise ProbeError(f"address_overflow:{label}")
    return value


def _tag_from_raw(raw: bytes) -> tuple[str, int] | None:
    if len(raw) != QWORD_WIDTH or raw[3] != 0:
        return None
    tag_bytes = raw[:3]
    if any(byte < ord("A") or byte > ord("Z") for byte in tag_bytes):
        return None
    return tag_bytes.decode("ascii"), int.from_bytes(raw[4:6], "little", signed=False)


def _pointer_raw(value: int) -> str:
    return int(value).to_bytes(QWORD_WIDTH, "little", signed=False).hex()


def _i32_hex(value: int) -> str:
    return (int(value) & 0xFFFFFFFF).to_bytes(I32_WIDTH, "little", signed=False).hex()


def _deepcopy(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False))


class _ReadBudget:
    """Precharge each read before dispatching it to the process reader."""

    def __init__(self, reader: Any, limit: int = MAX_TOTAL_RPM):
        self.reader = reader
        self.limit = limit
        self.bytes_reserved = 0
        self.calls_reserved = 0
        self.log: list[dict[str, Any]] = []

    def read(self, address: int, size: int, label: str) -> bytes:
        if not _valid_pointer(address):
            raise ProbeError(f"invalid_address:{label}")
        if not isinstance(size, int) or size <= 0 or size > MAX_SINGLE_RPM:
            raise ProbeError(f"invalid_size:{label}")
        if self.bytes_reserved + size > self.limit:
            self.log.append({"label": label, "address": _hex(address), "size": size, "status": "budget_rejected"})
            raise ProbeError(f"RPM_TOTAL_BUDGET_EXCEEDED:{label}")
        self.bytes_reserved += size
        self.calls_reserved += 1
        try:
            raw = self.reader.read(address, size, label)
        except Exception as exc:
            self.log.append({"label": label, "address": _hex(address), "size": size, "status": "error", "error": f"{type(exc).__name__}:{exc}"})
            raise
        if not isinstance(raw, (bytes, bytearray)) or len(raw) != size:
            raise ProbeError(f"short_read:{label}")
        data = bytes(raw)
        self.log.append({"label": label, "address": _hex(address), "size": size, "status": "observed", "raw_hex": data.hex()})
        return data

    def qword(self, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(address, QWORD_WIDTH, label)
        return int.from_bytes(raw, "little", signed=False), raw

    def i32(self, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(address, I32_WIDTH, label)
        return int.from_bytes(raw, "little", signed=True), raw

    def summary(self) -> dict[str, Any]:
        return {"bytes_requested": self.bytes_reserved, "calls": self.calls_reserved}


def _static_contract_guard(profile: Mapping[str, Any] | None = None, reason: str | None = None) -> dict[str, Any]:
    if not isinstance(profile, Mapping):
        return {"status": "unknown", "checks": {}, "unknown_conditions": [reason or "profile_unavailable"]}
    source_checks = profile.get("_source_checks", {})
    try:
        layout = profile.get("_layout") or _profile_layout(profile)
        guards = profile.get("_guards") or _profile_guards(profile)
        checks = {
            "profile_id": profile.get("profile_id") == "trade-league-memory-1374",
            "game_version": profile.get("game_version") == EXPECTED_VERSION,
            "executable_sha256": str(profile.get("executable", {}).get("sha256", "")).lower() == EXPECTED_EXE_SHA256,
            "layout": layout["trade_league_offset"] == 0x1948 and layout["vector_stride"] == 8,
            "code_guards": bool(guards),
            "source_pins": isinstance(source_checks, Mapping) and bool(source_checks) and all(value is True for value in source_checks.values()),
        }
    except Exception:
        checks = {"profile_contract": False}
    failed = [name for name, value in checks.items() if value is not True]
    unknown = ["profile_contract_failed:" + ",".join(failed)] if failed else []
    if reason:
        unknown.append(reason)
    return {
        "status": "observed" if not failed else "unknown",
        "profile_id": profile.get("profile_id"),
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "checks": checks,
        "source_checks": dict(source_checks) if isinstance(source_checks, Mapping) else {},
        "unknown_conditions": unknown,
    }


def _runtime_code_guard(ctx: _ReadBudget, module_base: int, profile: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "module_base": _hex(module_base), "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        for item in profile.get("_guards") or _profile_guards(profile):
            address = _safe_add(module_base, item["rva"], "code_guard." + item["name"])
            actual = ctx.read(address, len(item["expected"]), "trade_league.code." + item["name"])
            entry: dict[str, Any] = {
                "rva": _hex(item["rva"]), "address": _hex(address),
                "kind": item["kind"], "expected_hex": item["expected"].hex(),
                "actual_hex": actual.hex(),
                "expected_sha256": hashlib.sha256(item["expected"]).hexdigest(),
                "actual_sha256": hashlib.sha256(actual).hexdigest(),
            }
            if item["kind"] == "pointer_slot":
                pointer = int.from_bytes(actual, "little", signed=False)
                target_rva = pointer - module_base if pointer >= module_base else None
                entry.update({"actual_pointer": _hex(pointer), "actual_target_rva": _hex(target_rva), "target_rva": _hex(item["target_rva"])})
                ok = target_rva == item["target_rva"]
            else:
                ok = actual == item["expected"]
            result["records"][item["name"]] = entry
            result["checks"][item["name"]] = ok
        failed = [name for name, ok in result["checks"].items() if ok is not True]
        if failed:
            result["unknown_conditions"].append("runtime_code_guard_mismatch:" + ",".join(failed))
            result["status"] = "mismatch"
        else:
            result["status"] = "observed"
    except Exception as exc:
        result["unknown_conditions"].append(f"runtime_code_guard_failed:{type(exc).__name__}:{exc}")
    return result


def _file_code_guard(path: Path, profile: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "path": str(path), "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        for item in profile.get("_guards") or _profile_guards(profile):
            actual = _read_pe_rva_bytes(path, item["rva"], len(item["expected"]))
            result["records"][item["name"]] = {
                "rva": _hex(item["rva"]), "expected_hex": item["expected"].hex(), "actual_hex": actual.hex(),
            }
            result["checks"][item["name"]] = actual == item["expected"]
        failed = [name for name, ok in result["checks"].items() if ok is not True]
        if failed:
            result["status"] = "mismatch"
            result["unknown_conditions"].append("file_code_guard_mismatch:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except Exception as exc:
        result["unknown_conditions"].append(f"file_code_guard_failed:{type(exc).__name__}:{exc}")
    return result


def _empty_field(reason: str, *, network: bool = True) -> dict[str, Any]:
    return {
        "status": "unknown", "value": [] if network else None, "reason": reason,
        "unit": UNIT, "scale": SCALE, "period": PERIOD, "complete": False, "partial": True,
        "basis": BASIS, "value_origin": VALUE_ORIGIN,
    }


def _empty_record(reason: str, *, profile: Mapping[str, Any] | None = None, guard: Mapping[str, Any] | None = None, module_base: int | None = None, network: bool = True) -> dict[str, Any]:
    return {
        "status": "unknown", "reason": reason, "profile_sha256": EXPECTED_PROFILE_SHA256,
        "static_contract_guard": _static_contract_guard(profile, reason if profile is None else None),
        "runtime_code_guard": _deepcopy(guard) if isinstance(guard, Mapping) else None,
        "module_base": _hex(module_base), "country_pointer": None, "country": None,
        "country_fullref_raw_hex": None, "country_slot": None, "object": None,
        "predicate": None, "members": None, "first_leader": None, "league_leader": None,
        "country_table": None, "fields": {"trade_league": _empty_field(reason, network=network)},
        "basis": BASIS, "unit": UNIT, "scale": SCALE, "period": PERIOD,
        "value_origin": VALUE_ORIGIN, "read_budget": {"bytes_requested": 0, "calls": 0},
    }


def _scan_country_table(ctx: _ReadBudget, module_base: int, profile: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    layout = profile["_layout"]
    database_address = _safe_add(module_base, layout["database_global_rva"], "globals.database")
    database, database_raw = ctx.qword(database_address, "globals.database")
    if not _valid_pointer(database):
        raise ProbeError("database_pointer_invalid")
    table_address = _safe_add(database, layout["table_offset"], "database.country_table")
    table, table_raw = ctx.qword(table_address, "database.country_table")
    count_address = _safe_add(database, layout["count_offset"], "database.country_count")
    count, count_raw = ctx.i32(count_address, "database.country_count")
    if not _valid_pointer(table) or count < 1 or count > layout["max_country_entries"]:
        raise ProbeError("country_table_contract_invalid")
    pointer_raw = ctx.read(table, count * QWORD_WIDTH, "country_table.pointer_array")
    entries: list[dict[str, Any]] = []
    lookup: dict[str, list[dict[str, Any]]] = {}
    pointer_matches: dict[int, list[dict[str, Any]]] = {}
    for index in range(count):
        entry_address = table + index * QWORD_WIDTH
        p_raw = pointer_raw[index * QWORD_WIDTH:(index + 1) * QWORD_WIDTH]
        pointer = int.from_bytes(p_raw, "little", signed=False)
        entry: dict[str, Any] = {
            "index": index, "entry_address": _hex(entry_address), "pointer_raw_hex": p_raw.hex(),
            "pointer": _hex(pointer), "status": "unknown", "fullref_raw_hex": None,
            "tag": None, "slot": None,
        }
        if pointer == 0:
            entry["status"] = "null_pointer"
            entries.append(entry)
            continue
        if not _valid_pointer(pointer):
            entry["status"] = "invalid_pointer"
            entries.append(entry)
            continue
        pointer_matches.setdefault(pointer, []).append(entry)
        try:
            fullref_address = _safe_add(pointer, layout["fullref_offset"], f"country[{index}].fullref")
            fullref_raw = ctx.read(fullref_address, QWORD_WIDTH, f"country[{index}].fullref")
        except Exception as exc:
            entry["status"] = "fullref_read_failed"
            entry["reason"] = f"{type(exc).__name__}:{exc}"
            entries.append(entry)
            continue
        entry["fullref_raw_hex"] = fullref_raw.hex()
        parsed = _tag_from_raw(fullref_raw)
        if fullref_raw.hex() == NULL_FULLREF_RAW_HEX:
            entry["status"] = "known_null_country_sentinel"
        elif parsed is None:
            entry["status"] = "invalid_fullref"
        else:
            tag, slot = parsed
            entry.update({"status": "observed", "tag": tag, "slot": slot, "fullref_address": _hex(fullref_address)})
            if slot != index:
                entry["status"] = "stale_slot"
            else:
                lookup.setdefault(fullref_raw.hex(), []).append(entry)
        entries.append(entry)
    table_record = {
        "database_address": _hex(database_address), "database_pointer": _hex(database), "database_raw_hex": database_raw.hex(),
        "table_address": _hex(table_address), "table_pointer": _hex(table), "table_raw_hex": table_raw.hex(),
        "count_address": _hex(count_address), "count_raw_hex": count_raw.hex(), "count": count,
        "pointer_array_raw_hex": pointer_raw.hex(), "entries": entries,
        "duplicate_pointer_values": [_hex(pointer) for pointer, items in pointer_matches.items() if len(items) > 1],
    }
    return table_record, lookup


def _find_country_pointer_from_table(table: Mapping[str, Any], tag: str) -> int | None:
    matches = []
    for entry in table.get("entries", []):
        if isinstance(entry, Mapping) and entry.get("tag") == tag and entry.get("status") == "observed":
            value = entry.get("pointer")
            if isinstance(value, str):
                try:
                    matches.append(int(value, 0))
                except ValueError:
                    pass
    if len(matches) != 1:
        return None
    return matches[0]


def _member_projection(raw_hex: str, entry: Mapping[str, Any], leader: str | None, active: bool) -> dict[str, Any]:
    return {
        "country": entry.get("tag"), "fullref_hex": raw_hex, "fullref_raw_hex": raw_hex,
        "slot": entry.get("slot"), "active": bool(active), "league_leader": leader,
        "index": entry.get("index"),
    }


def _read_object(ctx: _ReadBudget, module_base: int, country_pointer: int, table: Mapping[str, Any], lookup: Mapping[str, list[dict[str, Any]]], profile: Mapping[str, Any]) -> dict[str, Any]:
    layout = profile["_layout"]
    country_entry = [item for item in table.get("entries", []) if item.get("pointer") == _hex(country_pointer)]
    if len(country_entry) != 1:
        raise ProbeError("country_pointer_not_unique_in_database")
    entry = country_entry[0]
    if entry.get("status") != "observed" or not isinstance(entry.get("fullref_raw_hex"), str):
        raise ProbeError("country_identity_unavailable")
    country_tag = entry.get("tag")
    country_slot = entry.get("slot")
    country_fullref_hex = entry["fullref_raw_hex"]
    if len(lookup.get(country_fullref_hex, [])) != 1:
        raise ProbeError("country_fullref_duplicate_or_unmapped")
    league_address = _safe_add(country_pointer, layout["trade_league_offset"], "country.trade_league")
    league_object, league_raw = ctx.qword(league_address, "country.trade_league_object")
    if not _valid_pointer(league_object):
        raise ProbeError("trade_league_object_invalid")
    object_raw = ctx.read(league_object, layout["object_prefix_size"], "trade_league.object_prefix")
    vtable = int.from_bytes(object_raw[:8], "little", signed=False)
    begin = int.from_bytes(object_raw[layout["vector_begin_offset"]:layout["vector_begin_offset"] + 8], "little", signed=False)
    end = int.from_bytes(object_raw[layout["vector_end_offset"]:layout["vector_end_offset"] + 8], "little", signed=False)
    vtable_rva = vtable - module_base if vtable >= module_base else None
    if vtable_rva == layout["null_vtable_rva"]:
        active = False
        expected_method_rva = layout["null_predicate_rva"]
    elif vtable_rva == layout["active_vtable_rva"]:
        active = True
        expected_method_rva = layout["active_predicate_rva"]
    else:
        raise ProbeError("trade_league_vtable_unknown")
    method_address = _safe_add(vtable, layout["vtable_method_slot"], "trade_league.vtable_method")
    method, method_raw = ctx.qword(method_address, "trade_league.vtable_method")
    method_rva = method - module_base if method >= module_base else None
    if method_rva != expected_method_rva:
        raise ProbeError("trade_league_predicate_pointer_mismatch")
    if (begin, end) == (0, 0):
        vector_raw = b""
        count = 0
    else:
        if not _valid_pointer(begin) or not _valid_pointer(end) or end < begin or (end - begin) % layout["vector_stride"]:
            raise ProbeError("trade_league_vector_range_invalid")
        count = (end - begin) // layout["vector_stride"]
        if count < 1 or count > layout["max_vector_count"]:
            raise ProbeError("trade_league_vector_count_invalid")
        vector_raw = ctx.read(begin, count * layout["vector_stride"], "trade_league.member_vector")
    if not active and count:
        raise ProbeError("inactive_trade_league_has_members")
    if active and not count:
        raise ProbeError("active_trade_league_vector_empty")
    raw_members: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index in range(count):
        raw = vector_raw[index * 8:(index + 1) * 8]
        raw_hex = raw.hex()
        candidates = lookup.get(raw_hex, [])
        if len(candidates) != 1:
            raise ProbeError("member_fullref_unmapped_or_duplicate")
        member_entry = candidates[0]
        if member_entry.get("status") != "observed" or raw_hex in seen:
            raise ProbeError("member_fullref_stale_or_duplicate")
        seen.add(raw_hex)
        raw_members.append({"raw_hex": raw_hex, "entry": member_entry, "index": index})
    leader = raw_members[0]["entry"]["tag"] if raw_members else None
    members = [_member_projection(item["raw_hex"], item["entry"], leader, True) for item in raw_members]
    object_record = {
        "country_trade_league_address": _hex(league_address), "country_trade_league_raw_hex": league_raw.hex(),
        "object_address": _hex(league_object), "object_pointer_raw_hex": _pointer_raw(league_object),
        "object_prefix_raw_hex": object_raw.hex(), "vtable_pointer": _hex(vtable),
        "vtable_pointer_raw_hex": object_raw[:8].hex(), "vtable_rva": _hex(vtable_rva),
        "vtable_method_address": _hex(method_address), "method_pointer": _hex(method),
        "method_pointer_raw_hex": method_raw.hex(), "method_rva": _hex(method_rva),
        "vector_begin": _hex(begin), "vector_begin_raw_hex": object_raw[0x20:0x28].hex(),
        "vector_end": _hex(end), "vector_end_raw_hex": object_raw[0x28:0x30].hex(),
        "vector_count": count, "vector_raw_hex": vector_raw.hex(),
    }
    return {
        "country": country_tag, "country_slot": country_slot, "country_fullref_raw_hex": country_fullref_hex,
        "country_pointer": _hex(country_pointer), "active": active, "predicate": active,
        "league_object_pointer": _hex(league_object), "object": object_record,
        "members": members, "first_leader": deepcopy(members[0]) if members else None,
        "league_leader": leader,
    }


def _field_from_object(obj: Mapping[str, Any], *, network: bool) -> dict[str, Any]:
    value = [deepcopy(item) for item in obj["members"]] if network else bool(obj["active"])
    return {
        "status": "known", "value": value, "unit": UNIT, "scale": SCALE, "period": PERIOD,
        "complete": False, "partial": True, "basis": BASIS, "value_origin": VALUE_ORIGIN,
        "league_leader": obj.get("league_leader"),
    }


def read_fields(reader: Any, module_base: int, country_pointer: int, *, recipient: str | None = None) -> dict[str, Any]:
    """Read one country object with a fresh bounded budget."""
    network = recipient is None
    try:
        profile = _active_profile()
        static = _static_contract_guard(profile)
    except Exception as exc:
        return _empty_record(f"profile_unavailable:{type(exc).__name__}:{exc}", network=network)
    if static.get("status") != "observed":
        return _empty_record("static_contract_guard_failed", profile=profile, network=network)
    if not _valid_pointer(module_base) or not _valid_pointer(country_pointer):
        return _empty_record("module_or_country_pointer_invalid", profile=profile, module_base=module_base, network=network)
    ctx = _ReadBudget(reader)
    guard = _runtime_code_guard(ctx, module_base, profile)
    if guard.get("status") != "observed":
        result = _empty_record("runtime_code_guard_failed", profile=profile, guard=guard, module_base=module_base, network=network)
        result["read_budget"] = ctx.summary()
        return result
    try:
        table, lookup = _scan_country_table(ctx, module_base, profile)
        obj = _read_object(ctx, module_base, country_pointer, table, lookup, profile)
        field = _field_from_object(obj, network=network)
        return {
            "status": "observed", "profile_sha256": EXPECTED_PROFILE_SHA256,
            "static_contract_guard": static, "runtime_code_guard": guard,
            "module_base": _hex(module_base), "country_pointer": _hex(country_pointer),
            "country": obj["country"], "country_fullref_raw_hex": obj["country_fullref_raw_hex"],
            "country_slot": obj["country_slot"], "object": obj["object"],
            "league_object_pointer": obj["league_object_pointer"], "predicate": obj["predicate"],
            "members": obj["members"], "first_leader": obj["first_leader"], "league_leader": obj["league_leader"],
            "country_table": table, "fields": {"trade_league": field},
            "basis": BASIS, "unit": UNIT, "scale": SCALE, "period": PERIOD,
            "value_origin": VALUE_ORIGIN, "read_budget": ctx.summary(),
            "observation": {"status": "observed", "recipient": recipient},
        }
    except Exception as exc:
        result = _empty_record(f"read_failed:{type(exc).__name__}:{exc}", profile=profile, guard=guard, module_base=module_base, network=network)
        result["read_budget"] = ctx.summary()
        return result


def _valid_hex(raw: Any, width: int) -> bool:
    if not isinstance(raw, str) or len(raw) != width * 2:
        return False
    try:
        bytes.fromhex(raw)
    except ValueError:
        return False
    return True


def _guard_valid(record: Mapping[str, Any], profile: Mapping[str, Any]) -> bool:
    static = record.get("static_contract_guard")
    runtime = record.get("runtime_code_guard")
    if not isinstance(static, Mapping) or static.get("status") != "observed":
        return False
    if static.get("profile_id") != "trade-league-memory-1374" or static.get("profile_sha256") != EXPECTED_PROFILE_SHA256:
        return False
    if not isinstance(runtime, Mapping) or runtime.get("status") != "observed":
        return False
    guards = profile.get("_guards") or _profile_guards(profile)
    checks = runtime.get("checks")
    records = runtime.get("records")
    if not isinstance(checks, Mapping) or set(checks) != {item["name"] for item in guards} or any(value is not True for value in checks.values()):
        return False
    if not isinstance(records, Mapping) or set(records) != {item["name"] for item in guards}:
        return False
    module_base = record.get("module_base")
    try:
        base = int(module_base, 0)
    except (TypeError, ValueError):
        return False
    if not _valid_pointer(base):
        return False
    for item in guards:
        got = records.get(item["name"])
        if not isinstance(got, Mapping) or got.get("rva") != _hex(item["rva"]) or got.get("address") != _hex(base + item["rva"]):
            return False
        if got.get("expected_hex") != item["expected"].hex():
            return False
        if item["kind"] == "pointer_slot":
            if got.get("target_rva") != _hex(item["target_rva"]) or got.get("actual_target_rva") != _hex(item["target_rva"]):
                return False
        else:
            if got.get("actual_hex") != item["expected"].hex() or got.get("actual_sha256") != hashlib.sha256(item["expected"]).hexdigest():
                return False
        if got.get("expected_sha256") != hashlib.sha256(item["expected"]).hexdigest():
            return False
    return True


def _table_for_validation(record: Mapping[str, Any], layout: Mapping[str, Any]) -> tuple[dict[str, list[dict[str, Any]]], dict[int, list[dict[str, Any]]]] | None:
    table = record.get("country_table")
    if not isinstance(table, Mapping):
        return None
    count = table.get("count")
    entries = table.get("entries")
    pointer_hex = table.get("pointer_array_raw_hex")
    if not isinstance(count, int) or count < 1 or count > layout["max_country_entries"] or not isinstance(entries, list) or len(entries) != count:
        return None
    if not _valid_hex(pointer_hex, count * QWORD_WIDTH):
        return None
    pointer_raw = bytes.fromhex(pointer_hex)
    lookup: dict[str, list[dict[str, Any]]] = {}
    pointer_map: dict[int, list[dict[str, Any]]] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping) or entry.get("index") != index:
            return None
        chunk = pointer_raw[index * 8:(index + 1) * 8]
        if entry.get("pointer_raw_hex") != chunk.hex():
            return None
        pointer = int.from_bytes(chunk, "little")
        if entry.get("pointer") != _hex(pointer):
            return None
        if pointer == 0:
            if entry.get("status") != "null_pointer":
                return None
            continue
        if not _valid_pointer(pointer):
            if entry.get("status") != "invalid_pointer":
                return None
            continue
        pointer_map.setdefault(pointer, []).append(dict(entry))
        raw_hex = entry.get("fullref_raw_hex")
        if entry.get("status") == "observed":
            if not _valid_hex(raw_hex, QWORD_WIDTH) or not isinstance(entry.get("tag"), str) or not isinstance(entry.get("slot"), int):
                return None
            lookup.setdefault(raw_hex, []).append(dict(entry))
        elif entry.get("status") not in {"known_null_country_sentinel", "invalid_fullref", "stale_slot", "fullref_read_failed"}:
            return None
    return lookup, pointer_map


def validate_record(record: Any) -> bool:
    """Validate static/runtime guards and recompute the predicate/vector."""
    if not isinstance(record, Mapping) or record.get("status") != "observed":
        return False
    try:
        profile = _active_profile()
        layout = profile["_layout"]
        if record.get("profile_sha256") != EXPECTED_PROFILE_SHA256 or not _guard_valid(record, profile):
            return False
        if (record.get("basis") != BASIS or record.get("unit") != UNIT
                or record.get("scale") != SCALE or record.get("period") != PERIOD
                or record.get("value_origin") != VALUE_ORIGIN):
            return False
        base = int(record["module_base"], 0)
        country_pointer = int(record["country_pointer"], 0)
        if not _valid_pointer(base) or not _valid_pointer(country_pointer):
            return False
        table_result = _table_for_validation(record, layout)
        if table_result is None:
            return False
        table = record["country_table"]
        database_address = _safe_add(base, layout["database_global_rva"], "globals.database")
        database_pointer = int(table.get("database_pointer"), 0) if isinstance(table.get("database_pointer"), str) else None
        if (table.get("database_address") != _hex(database_address) or database_pointer is None
                or not _valid_pointer(database_pointer)
                or table.get("database_raw_hex") != _pointer_raw(database_pointer)):
            return False
        table_address = _safe_add(database_pointer, layout["table_offset"], "database.country_table")
        table_pointer = int(table.get("table_pointer"), 0) if isinstance(table.get("table_pointer"), str) else None
        if (table.get("table_address") != _hex(table_address) or table_pointer is None
                or not _valid_pointer(table_pointer)
                or table.get("table_raw_hex") != _pointer_raw(table_pointer)):
            return False
        count_address = _safe_add(database_pointer, layout["count_offset"], "database.country_count")
        if (table.get("count_address") != _hex(count_address)
                or table.get("count_raw_hex") != _i32_hex(table["count"])):
            return False
        pointer_map = table_result[1]
        expected_duplicate_pointers = {_hex(pointer) for pointer, values in pointer_map.items() if len(values) > 1}
        actual_duplicate_pointers = table.get("duplicate_pointer_values")
        if not isinstance(actual_duplicate_pointers, list) or set(actual_duplicate_pointers) != expected_duplicate_pointers:
            return False
        for index, entry in enumerate(table["entries"]):
            if entry.get("entry_address") != _hex(table_pointer + index * QWORD_WIDTH):
                return False
            pointer = int(entry["pointer"], 0) if isinstance(entry.get("pointer"), str) else None
            if pointer is None:
                return False
            if pointer == 0:
                if (entry.get("status") != "null_pointer" or entry.get("fullref_raw_hex") is not None
                        or entry.get("tag") is not None or entry.get("slot") is not None):
                    return False
                continue
            if not _valid_pointer(pointer):
                if (entry.get("status") != "invalid_pointer" or entry.get("fullref_raw_hex") is not None
                        or entry.get("tag") is not None or entry.get("slot") is not None):
                    return False
                continue
            raw_hex = entry.get("fullref_raw_hex")
            if entry.get("status") == "fullref_read_failed":
                return False
            if not _valid_hex(raw_hex, QWORD_WIDTH):
                return False
            parsed = _tag_from_raw(bytes.fromhex(raw_hex))
            expected_status = "known_null_country_sentinel" if raw_hex == NULL_FULLREF_RAW_HEX else None
            if expected_status:
                if (entry.get("status") != expected_status or entry.get("tag") is not None
                        or entry.get("slot") is not None or entry.get("fullref_address") is not None):
                    return False
                continue
            if parsed is None:
                if (entry.get("status") != "invalid_fullref" or entry.get("tag") is not None
                        or entry.get("slot") is not None or entry.get("fullref_address") is not None):
                    return False
                continue
            tag, slot = parsed
            if entry.get("fullref_address") != _hex(pointer + layout["fullref_offset"]):
                return False
            if entry.get("tag") != tag or entry.get("slot") != slot:
                return False
            if slot == index:
                if entry.get("status") != "observed":
                    return False
            elif entry.get("status") != "stale_slot":
                return False
        lookup, _pointer_map = table_result
        matching = [item for item in table["entries"] if item.get("pointer") == _hex(country_pointer)]
        if len(matching) != 1 or matching[0].get("status") != "observed":
            return False
        current = matching[0]
        if record.get("country") != current.get("tag") or record.get("country_slot") != current.get("slot") or record.get("country_fullref_raw_hex") != current.get("fullref_raw_hex"):
            return False
        if len(lookup.get(current.get("fullref_raw_hex"), [])) != 1:
            return False
        obj = record.get("object")
        if not isinstance(obj, Mapping):
            return False
        league_address = _safe_add(country_pointer, layout["trade_league_offset"], "country.trade_league")
        league_object = int(record.get("league_object_pointer"), 0) if isinstance(record.get("league_object_pointer"), str) else None
        if (obj.get("country_trade_league_address") != _hex(league_address)
                or not isinstance(obj.get("country_trade_league_raw_hex"), str)
                or not _valid_hex(obj.get("country_trade_league_raw_hex"), QWORD_WIDTH)
                or league_object is None or not _valid_pointer(league_object)
                or int.from_bytes(bytes.fromhex(obj["country_trade_league_raw_hex"]), "little") != league_object
                or obj.get("object_address") != _hex(league_object)
                or obj.get("object_pointer_raw_hex") != _pointer_raw(league_object)):
            return False
        prefix_hex = obj.get("object_prefix_raw_hex")
        if not _valid_hex(prefix_hex, layout["object_prefix_size"]):
            return False
        prefix = bytes.fromhex(prefix_hex)
        vtable = int.from_bytes(prefix[:8], "little")
        begin = int.from_bytes(prefix[0x20:0x28], "little")
        end = int.from_bytes(prefix[0x28:0x30], "little")
        vtable_rva = vtable - base
        if (obj.get("vtable_pointer") != _hex(vtable)
                or obj.get("vtable_pointer_raw_hex") != prefix[:QWORD_WIDTH].hex()
                or obj.get("vtable_rva") != _hex(vtable_rva)):
            return False
        if vtable_rva == layout["null_vtable_rva"]:
            active, expected_method_rva = False, layout["null_predicate_rva"]
        elif vtable_rva == layout["active_vtable_rva"]:
            active, expected_method_rva = True, layout["active_predicate_rva"]
        else:
            return False
        if obj.get("vtable_method_address") != _hex(vtable + layout["vtable_method_slot"]):
            return False
        method = obj.get("method_pointer")
        method_int = int(method, 0) if isinstance(method, str) else None
        if (method_int is None or not _valid_pointer(method_int)
                or obj.get("method_pointer_raw_hex") != _pointer_raw(method_int)
                or obj.get("method_rva") != _hex(expected_method_rva)
                or method_int - base != expected_method_rva):
            return False
        if (obj.get("vector_begin") != _hex(begin) or obj.get("vector_end") != _hex(end)
                or obj.get("vector_begin_raw_hex") != prefix[0x20:0x28].hex()
                or obj.get("vector_end_raw_hex") != prefix[0x28:0x30].hex()):
            return False
        vector_hex = obj.get("vector_raw_hex")
        if (begin, end) == (0, 0):
            if vector_hex != "" or obj.get("vector_count") != 0:
                return False
            count = 0
        else:
            if not _valid_pointer(begin) or not _valid_pointer(end) or end < begin or (end - begin) % 8:
                return False
            count = (end - begin) // 8
            if count < 1 or count > layout["max_vector_count"] or not _valid_hex(vector_hex, count * 8):
                return False
        if obj.get("vector_count") != count:
            return False
        if (not active and count) or (active and not count):
            return False
        member_items = []
        seen: set[str] = set()
        raw_vector = bytes.fromhex(vector_hex) if vector_hex else b""
        for index in range(count):
            raw_hex = raw_vector[index * 8:(index + 1) * 8].hex()
            if raw_hex in seen or len(lookup.get(raw_hex, [])) != 1:
                return False
            seen.add(raw_hex)
            member_items.append(lookup[raw_hex][0])
        leader = member_items[0].get("tag") if member_items else None
        expected_members = [_member_projection(raw_vector[index * 8:(index + 1) * 8].hex(), member_items[index], leader, True) for index in range(count)]
        if record.get("members") != expected_members or record.get("predicate") is not active or record.get("league_leader") != leader:
            return False
        first = record.get("first_leader")
        if first != (expected_members[0] if expected_members else None):
            return False
        field = record.get("fields", {}).get("trade_league") if isinstance(record.get("fields"), Mapping) else None
        observation = record.get("observation")
        observation_recipient = observation.get("recipient") if isinstance(observation, Mapping) else None
        if not isinstance(field, Mapping) or field.get("status") != "known" or field.get("basis") != BASIS:
            return False
        if observation_recipient is None:
            if field.get("value") != expected_members:
                return False
        elif not _valid_tag(observation_recipient):
            return False
        elif type(field.get("value")) is not bool or field.get("value") is not active:
            return False
        if field.get("league_leader") != leader or field.get("unit") != UNIT or field.get("scale") != SCALE or field.get("period") != PERIOD or field.get("complete") is not False or field.get("partial") is not True:
            return False
        return True
    except (ProfileError, KeyError, TypeError, ValueError, AttributeError):
        return False


def _valid_tag(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 3 and all("A" <= char <= "Z" for char in value)


def _base_report(installation: Path, actor: str, recipient: str | None) -> dict[str, Any]:
    return {
        "schema": "information_trade_league_runtime.v1",
        "probe": "information-trade-league-runtime", "probe_version": 1,
        "probe_script": str(Path(__file__).resolve()), "probe_script_sha256": None,
        "profile": {"path": str(PROFILE_FILE), "sha256": EXPECTED_PROFILE_SHA256, "profile_id": "trade-league-memory-1374", "max_bytes": PROFILE_MAX_BYTES},
        "read_only": True, "request": {"installation": str(installation), "actor": actor, "recipient": recipient},
        "target_build": {"version": EXPECTED_VERSION, "expected_exe_sha256": EXPECTED_EXE_SHA256},
        "static_contract_guard": None, "file_code_guard": None, "runtime_code_guard": None,
        "identity": {"binding_verified": False, "installation_pid": None, "installation_creation_filetime": None, "installation_session_id": None,
                     "process_path": None, "process_path_sha256": None, "process_path_sha256_matches_expected": None,
                     "process_creation_filetime": None, "process_creation_matches_installation": None,
                     "module_path": None, "module_path_matches_process": None},
        "module_base": None, "before": None, "after": None, "context_before": None, "context_after": None,
        "fields": {"trade_league": _empty_field("not_read", network=recipient is None)},
        "doublepass": {"performed": False, "consistent": None, "mismatches": []},
        "access": {"open_process_mask": "QUERY_INFORMATION|VM_READ", "open_process_mask_hex": hex(PROCESS_ACCESS),
                   "rpm_total_limit": MAX_TOTAL_RPM, "rpm_single_read_limit": MAX_SINGLE_RPM,
                   "rpm_bytes_requested": 0, "rpm_calls": 0, "native_game_calls": False, "target_memory_writes": False,
                   "dll_injection": False, "private_heap_scan": False, "ui_control": False, "date_advance": False,
                   "save_or_reload": False},
        "cleanup": {"handle_close": {"status": "unknown", "success": None, "closed": False}},
        "status": "starting", "errors": [], "completed": False,
    }


def _read_game_date(reader: Any, module_base: int, profile: Mapping[str, Any], label: str) -> dict[str, Any]:
    ctx = _ReadBudget(reader, limit=MAX_TOTAL_RPM)
    layout = profile["_layout"]
    game_address = _safe_add(module_base, layout["game_global_rva"], label + ".game_global")
    game, game_raw = ctx.qword(game_address, label + ".game_global")
    if not _valid_pointer(game):
        raise ProbeError("game_pointer_invalid")
    date_address = _safe_add(game, layout["game_date_offset"], label + ".game_date")
    value, raw = ctx.i32(date_address, label + ".game_date")
    return {"game_address": _hex(game_address), "game_pointer": _hex(game), "game_raw_hex": game_raw.hex(),
            "game_date_address": _hex(date_address), "game_date_raw_hex": raw.hex(), "game_date": value}


def _stable(value: Any) -> Any:
    def strip_volatile(item: Any) -> Any:
        if isinstance(item, Mapping):
            return {key: strip_volatile(child) for key, child in item.items() if key not in {"read_budget", "read_log", "probe_script_sha256"}}
        if isinstance(item, list):
            return [strip_volatile(child) for child in item]
        return item

    return without_clock(strip_volatile(value), date_labels=("pass.game_date",))


def _observation_dates_match(before_context: Any, after_context: Any, anchor_date: Any = None, *, anchor_present: bool = False) -> bool:
    if not isinstance(before_context, Mapping) or not isinstance(after_context, Mapping):
        return False
    before_date = before_context.get("game_date")
    after_date = after_context.get("game_date")
    before_binding = {key: value for key, value in before_context.items() if key not in {"game_date", "game_date_raw_hex"}}
    after_binding = {key: value for key, value in after_context.items() if key not in {"game_date", "game_date_raw_hex"}}
    if before_binding != after_binding or not dates_match(before_date, after_date):
        return False
    return not anchor_present or dates_match(anchor_date, before_date, after_date)


def _find_country_pointer(reader: Any, module_base: int, profile: Mapping[str, Any], tag: str) -> int:
    ctx = _ReadBudget(reader)
    table, _lookup = _scan_country_table(ctx, module_base, profile)
    pointer = _find_country_pointer_from_table(table, tag)
    if pointer is None:
        raise ProbeError(f"country_not_found_or_duplicate:{tag}")
    return pointer


def _capture_pass(reader: Any, module_base: int, profile: Mapping[str, Any], actor: str, recipient: str | None) -> dict[str, Any]:
    context = _read_game_date(reader, module_base, profile, "pass")
    actor_pointer = _find_country_pointer(reader, module_base, profile, actor)
    actor_record = read_fields(reader, module_base, actor_pointer, recipient=recipient)
    if actor_record.get("status") != "observed" or not validate_record(actor_record):
        return {"status": "unknown", "context": context, "actor_record": actor_record, "fields": {"trade_league": _empty_field("ACTOR_RECORD_INVALID", network=recipient is None)}}
    if recipient is None:
        field = deepcopy(actor_record["fields"]["trade_league"])
        field["value"] = [item for item in field["value"] if item.get("country") != actor]
        return {"status": "observed", "context": context, "actor_record": actor_record, "recipient_record": None, "fields": {"trade_league": field}}
    recipient_pointer = _find_country_pointer(reader, module_base, profile, recipient)
    recipient_record = read_fields(reader, module_base, recipient_pointer, recipient=recipient)
    if recipient_record.get("status") != "observed" or not validate_record(recipient_record):
        return {"status": "unknown", "context": context, "actor_record": actor_record, "recipient_record": recipient_record, "fields": {"trade_league": _empty_field("RECIPIENT_RECORD_INVALID", network=False)}}
    actor_object = actor_record["object"]
    recipient_object = recipient_record["object"]
    same_object = actor_record.get("league_object_pointer") == recipient_record.get("league_object_pointer")
    same_vector = (
        actor_object.get("vector_begin") == recipient_object.get("vector_begin")
        and actor_object.get("vector_end") == recipient_object.get("vector_end")
        and actor_object.get("vector_raw_hex") == recipient_object.get("vector_raw_hex")
    )
    if same_object and not same_vector:
        return {
            "status": "unknown", "context": context, "actor_record": actor_record,
            "recipient_record": recipient_record,
            "fields": {"trade_league": _empty_field("TRADE_LEAGUE_VECTOR_IDENTITY_MISMATCH", network=False)},
        }
    actor_member = any(item.get("country") == recipient for item in actor_record.get("members", []))
    active = actor_record.get("predicate") is True and recipient_record.get("predicate") is True
    value = bool(active and same_object and same_vector and actor_member)
    leader = actor_record.get("league_leader") if value else None
    field = {
        "status": "known", "value": value, "league_leader": leader,
        "unit": UNIT, "scale": SCALE, "period": PERIOD, "complete": False, "partial": True,
        "basis": BASIS, "value_origin": VALUE_ORIGIN,
        "raw": {"actor_object_pointer": actor_record.get("league_object_pointer"), "recipient_object_pointer": recipient_record.get("league_object_pointer"),
                "same_object": same_object, "same_vector": same_vector, "actor_member": actor_member},
    }
    return {"status": "observed", "context": context, "actor_record": actor_record, "recipient_record": recipient_record, "fields": {"trade_league": field}}


def capture(installation: Path, actor: str = EXPECTED_COUNTRY, recipient: str | None = None) -> dict[str, Any]:
    """Capture one read-only two-pass trade-league observation."""
    installation = Path(installation)
    report = _base_report(installation, actor, recipient)
    kernel = None
    handle = None
    reader = None
    try:
        report["probe_script_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        if not _valid_tag(actor) or (recipient is not None and (not _valid_tag(recipient) or recipient == actor)):
            report["status"] = "invalid_request"
            report["errors"].append({"stage": "request", "status": "unknown", "error": "actor/recipient must be distinct uppercase tags"})
            return report
        profile = _active_profile()
        report["static_contract_guard"] = _static_contract_guard(profile)
        if report["static_contract_guard"].get("status") != "observed":
            report["status"] = "static_contract_mismatch"
            return report
        document = _load_installation(installation)
        pid = int(document.get("pid"))
        kernel = _configure_kernel()
        handle = kernel.OpenProcess(PROCESS_ACCESS, False, pid)
        if not handle:
            raise C.WinError(C.get_last_error())
        module_base = _capture_identity(report, document, kernel, handle)
        if report["identity"].get("binding_verified") is not True or not _valid_pointer(module_base):
            raise ProbeError("identity_binding_not_verified")
        report["module_base"] = _hex(module_base)
        process_path = Path(report["identity"]["process_path"])
        report["file_code_guard"] = _file_code_guard(process_path, profile)
        if report["file_code_guard"].get("status") != "observed":
            report["status"] = "file_code_mismatch"
            return report
        reader = AddressBoundedRPM(kernel, handle, module_base)
        before = _capture_pass(reader, module_base, profile, actor, recipient)
        report["before"] = before
        if before.get("status") != "observed":
            report["status"] = "unknown"
            report["errors"].append({"stage": "before", "status": "unknown", "error": "trade_league_before_unknown"})
        else:
            after = _capture_pass(reader, module_base, profile, actor, recipient)
            report["after"] = after
            report["doublepass"]["performed"] = True
            report["doublepass"]["mismatches"] = [] if (_stable(before) == _stable(after) and _observation_dates_match(before.get("context"), after.get("context"))) else ["$.before_after"]
            report["doublepass"]["consistent"] = not report["doublepass"]["mismatches"]
            if report["doublepass"]["consistent"]:
                report["status"] = "observed" if after.get("status") == "observed" else "doublepass_mismatch"
                report["fields"] = deepcopy(after.get("fields", report["fields"]))
            else:
                report["status"] = "doublepass_mismatch"
                report["errors"].append({"stage": "doublepass", "status": "unknown", "error": "trade_league_context_or_vector_changed"})
        report["context_before"] = (before or {}).get("context")
        report["context_after"] = (report.get("after") or {}).get("context")
        passes = [before, report.get("after")]
        guards = [item.get("actor_record", {}).get("runtime_code_guard") for item in passes if isinstance(item, Mapping)]
        report["runtime_code_guard"] = {"status": "observed" if guards and all(isinstance(g, Mapping) and g.get("status") == "observed" for g in guards) else "unknown", "passes": guards}
        report["access"]["rpm_bytes_requested"] = reader.bytes_requested
        report["access"]["rpm_calls"] = reader.calls
    except Exception as exc:
        report["status"] = "error"
        report["errors"].append({"stage": "capture", "status": "unknown", "error": f"{type(exc).__name__}:{exc}"})
    finally:
        if reader is not None:
            report["access"]["rpm_bytes_requested"] = reader.bytes_requested
            report["access"]["rpm_calls"] = reader.calls
        report["cleanup"]["handle_close"] = _close_process_handle(kernel, handle)
    if report["status"] == "observed" and report["cleanup"]["handle_close"].get("closed") is True and report.get("doublepass", {}).get("consistent") is True:
        report["completed"] = True
    else:
        report["completed"] = False
        report["fields"] = {"trade_league": _empty_field("observation_not_completed", network=recipient is None)}
    return report


def _context_value(context: Mapping[str, Any], key: str) -> Any:
    value = context.get(key)
    if isinstance(value, Mapping) and "value" in value:
        return value.get("value")
    return value


def validate_capture(report: Any, context: Mapping[str, Any] | None = None, creation_filetime: int | None = None, actor: str | None = None, recipient: str | None = None) -> bool:
    """Validate identity, both raw passes, predicate and pair/network projection."""
    if not isinstance(report, Mapping):
        return False
    try:
        request = report.get("request")
        if report.get("schema") != "information_trade_league_runtime.v1" or report.get("status") != "observed" or report.get("completed") is not True:
            return False
        if report.get("profile", {}).get("profile_id") != "trade-league-memory-1374" or report.get("profile", {}).get("sha256") != EXPECTED_PROFILE_SHA256:
            return False
        if report.get("target_build", {}).get("expected_exe_sha256", "").lower() != EXPECTED_EXE_SHA256:
            return False
        if report.get("access", {}).get("native_game_calls") is not False or report.get("access", {}).get("target_memory_writes") is not False:
            return False
        if report.get("cleanup", {}).get("handle_close", {}).get("closed") is not True:
            return False
        if not isinstance(request, Mapping):
            return False
        if actor is not None and request.get("actor") != actor:
            return False
        if recipient is not None and request.get("recipient") != recipient:
            return False
        actual_actor = request.get("actor")
        actual_recipient = request.get("recipient")
        if not _valid_tag(actual_actor) or (actual_recipient is not None and (not _valid_tag(actual_recipient) or actual_recipient == actual_actor)):
            return False
        identity = report.get("identity")
        if not isinstance(identity, Mapping) or identity.get("binding_verified") is not True or identity.get("process_path_sha256_matches_expected") is not True or identity.get("process_creation_matches_installation") is not True:
            return False
        if creation_filetime is not None and identity.get("process_creation_filetime") != creation_filetime:
            return False
        if report.get("static_contract_guard", {}).get("status") != "observed" or report.get("file_code_guard", {}).get("status") != "observed" or report.get("runtime_code_guard", {}).get("status") != "observed":
            return False
        if report.get("doublepass", {}).get("performed") is not True or report.get("doublepass", {}).get("consistent") is not True:
            return False
        before, after = report.get("before"), report.get("after")
        if (not isinstance(before, Mapping) or not isinstance(after, Mapping)
                or _stable(before) != _stable(after)
                or not _observation_dates_match(before.get("context"), after.get("context"))):
            return False
        if before.get("status") != "observed" or after.get("status") != "observed" or report.get("fields") != after.get("fields"):
            return False
        if report.get("context_before") != before.get("context") or report.get("context_after") != after.get("context"):
            return False
        if context is not None:
            if not isinstance(context, Mapping):
                return False
            expected_session = _context_value(context, "session_id")
            if expected_session is not None and identity.get("installation_session_id") != expected_session:
                return False
            expected_creation = _context_value(context, "process_creation_filetime")
            if expected_creation is not None and identity.get("process_creation_filetime") != expected_creation:
                return False
            expected_date = _context_value(context, "game_date")
            if expected_date is not None and not _observation_dates_match(
                    (report.get("context_before") or {}), (report.get("context_after") or {}),
                    expected_date, anchor_present=True):
                return False
        actor_record = before.get("actor_record")
        recipient_record = before.get("recipient_record")
        if not validate_record(actor_record):
            return False
        if actor_record.get("country") != actual_actor:
            return False
        if actual_recipient is None:
            field = report["fields"].get("trade_league")
            if not isinstance(field, Mapping) or field.get("status") != "known" or not isinstance(field.get("value"), list):
                return False
            expected = [item for item in actor_record["members"] if item.get("country") != actual_actor]
            if field.get("value") != expected or field.get("league_leader") != actor_record.get("league_leader"):
                return False
        else:
            if not validate_record(recipient_record):
                return False
            if recipient_record.get("country") != actual_recipient:
                return False
            field = report["fields"].get("trade_league")
            if not isinstance(field, Mapping) or field.get("status") != "known" or type(field.get("value")) is not bool:
                return False
            same_object = actor_record.get("league_object_pointer") == recipient_record.get("league_object_pointer")
            same_vector = actor_record["object"].get("vector_begin") == recipient_record["object"].get("vector_begin") and actor_record["object"].get("vector_end") == recipient_record["object"].get("vector_end") and actor_record["object"].get("vector_raw_hex") == recipient_record["object"].get("vector_raw_hex")
            # A shared object with divergent double-pass vectors is an
            # inconsistent observation.  It must retract to unknown rather
            # than being interpreted as a legitimate known-false pair.
            if same_object and not same_vector:
                return False
            actor_member = any(item.get("country") == actual_recipient for item in actor_record.get("members", []))
            expected_value = bool(actor_record.get("predicate") is True and recipient_record.get("predicate") is True and same_object and same_vector and actor_member)
            expected_leader = actor_record.get("league_leader") if expected_value else None
            expected_raw = {"actor_object_pointer": actor_record.get("league_object_pointer"),
                            "recipient_object_pointer": recipient_record.get("league_object_pointer"),
                            "same_object": same_object, "same_vector": same_vector, "actor_member": actor_member}
            if (field.get("value") is not expected_value
                    or field.get("league_leader") != expected_leader
                    or field.get("raw") != expected_raw):
                return False
        return True
    except (ProfileError, KeyError, TypeError, ValueError, AttributeError):
        return False


def retract_record(record: Mapping[str, Any] | None, reason: str = "observation_retracted") -> dict[str, Any]:
    result = deepcopy(dict(record)) if isinstance(record, Mapping) else _empty_record(reason)
    result["status"] = "unknown"
    result["completed"] = False
    result["reason"] = reason
    fields = result.get("fields")
    if isinstance(fields, Mapping):
        network = result.get("request", {}).get("recipient") is None if isinstance(result.get("request"), Mapping) else True
        result["fields"] = {"trade_league": _empty_field(reason, network=network)}
    return result


__all__ = [
    "AddressBoundedRPM", "BASIS", "EXPECTED_COUNTRY", "EXPECTED_EXE_SHA256",
    "EXPECTED_PROFILE_SHA256", "EXPECTED_VERSION", "FIELDS", "MAX_SINGLE_RPM",
    "MAX_TOTAL_RPM", "PERIOD", "PROFILE", "PROFILE_FILE", "ProfileError",
    "ProbeError", "SCALE", "UNIT", "capture", "read_fields", "retract_record",
    "validate_capture", "validate_record", "_load_profile", "_profile_layout",
    "_profile_guards", "_static_contract_guard", "_runtime_code_guard",
]
