"""Bounded read-only capture of one country's outgoing rival membership.

This reader preserves the native linked-list order and private bytes for
validation.  Its public projection contains only sorted three-letter tags;
it does not expose addresses, database slots, or rival priorities.
"""
from __future__ import annotations

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


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "country-rivals-memory-1374.json"
PROFILE_MAX_BYTES = 64 * 1024
EXPECTED_PROFILE_SHA256 = "a40515fd3e19d59dd73bde7bde442f155c04fd91ef6c3cd786ddaa481690708c"
EXPECTED_PROFILE_ID = "country-rivals-memory-1374"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_VERSION = "1.37.4"
EXPECTED_COUNTRY = "FRA"

FIELD_KEY = "rivals"
FIELDS = (FIELD_KEY,)
BASIS = "native_outgoing_rival_membership"
UNIT = "country_tags"
SCALE = 1
PERIOD = "current"
COMPLETE = True
DIRECTION = "outgoing_declared_by_country"
VALUE_ORIGIN = "copied_native_cache"

MAX_SINGLE_RPM = 65_536
MAX_TOTAL_RPM = 1 * 1024 * 1024
READ_BUDGET_BYTES = MAX_TOTAL_RPM
MAX_RIVALS = 64
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
    """The pinned profile or one of its evidence files is invalid."""


class ReadError(RuntimeError):
    """A bounded read or outgoing-rival membership contract check failed."""


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
        relative, digest, size = item.get("path"), item.get("sha256"), item.get("bytes")
        if (not isinstance(relative, str) or not relative or not isinstance(digest, str) or
                len(digest) != 64 or type(size) is not int or size <= 0 or size > 256 * 1024):
            raise ProfileError("source_evidence_item_invalid")
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ProfileError("source_evidence_outside_workspace") from exc
        key = path.as_posix().lower()
        if key in seen:
            raise ProfileError("source_evidence_duplicate")
        raw = _bounded_file(path, 256 * 1024, "source_evidence")
        if len(raw) != size or hashlib.sha256(raw).hexdigest().lower() != digest.lower():
            raise ProfileError(f"source_evidence_sha256_mismatch:{relative}")
        seen.add(key)
        result.append({"path": path.relative_to(root).as_posix(), "sha256": digest.lower(),
                       "bytes": size, "role": item.get("role")})
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
        "country_rivals_head_offset": 0x2248,
        "country_rivals_count_offset": 0x2258,
        "rival_node_fullref_offset": 0x10,
        "rival_node_since_date_offset": 0x18,
        "rival_node_next_offset": 0x28,
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
    items = profile.get("code_guards")
    if not isinstance(items, list) or not items:
        raise ProfileError("profile_code_guards_shape_invalid")
    result: list[tuple[str, int, int, bytes]] = []
    names: set[str] = set()
    total = 0
    for item in items:
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
    if not isinstance(executable, Mapping) or str(executable.get("sha256", "")).lower() != EXPECTED_EXE_SHA256:
        raise ProfileError("profile_executable_mismatch")
    _source_evidence(profile)
    _profile_layout(profile)
    limits = profile.get("limits")
    expected_limits = {"max_total_rpm": MAX_TOTAL_RPM, "max_single_rpm": MAX_SINGLE_RPM,
                       "max_rivals": MAX_RIVALS, "max_country_slots": 4096}
    if not isinstance(limits, Mapping):
        raise ProfileError("profile_limits_invalid")
    for key, expected in expected_limits.items():
        if _parse_int(limits.get(key), f"limits.{key}") != expected:
            raise ProfileError(f"profile_limits_invalid:{key}")
    semantics = profile.get("semantics")
    if (not isinstance(semantics, Mapping) or semantics.get("field") != FIELD_KEY or
            semantics.get("basis") != BASIS or semantics.get("unit") != UNIT or
            semantics.get("scale") != SCALE or semantics.get("period") != PERIOD or
            semantics.get("complete") is not True or semantics.get("partial") is not False or
            semantics.get("scope") != "outgoing_active_rivals_only"):
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
    result: dict[str, Any] = {"status": "unknown", "evidence_kind": "ordinary_bounded_layout_and_fullref_membership_evidence",
                              "profile": str(PROFILE_FILE), "profile_id": EXPECTED_PROFILE_ID,
                              "profile_sha256": EXPECTED_PROFILE_SHA256, "source_evidence": [],
                              "checks": {}, "unknown_conditions": []}
    try:
        loaded = _load_profile() if profile is None else _prepare_profile(profile)
        layout = _profile_layout(loaded)
        sources = loaded.get("_validated_source_evidence", _source_evidence(loaded))
        guards = _profile_code_guards(loaded)
        result["source_evidence"] = _copy_json(sources)
        result["checks"] = {
            "profile_id": loaded.get("profile_id") == EXPECTED_PROFILE_ID,
            "game_version": loaded.get("game_version") == EXPECTED_VERSION,
            "game_sha256": str(loaded.get("executable", {}).get("sha256", "")).lower() == EXPECTED_EXE_SHA256,
            "database_country_fullref_layout": layout["database_global_rva"] == 0x233D8B0 and layout["database_table_offset"] == 0x118 and layout["country_fullref_offset"] == 0x20,
            "outgoing_rival_list_layout": layout["country_rivals_head_offset"] == 0x2248 and layout["country_rivals_count_offset"] == 0x2258 and layout["rival_node_fullref_offset"] == 0x10 and layout["rival_node_since_date_offset"] == 0x18 and layout["rival_node_next_offset"] == 0x28,
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
            result["records"][name] = {"rva": hex(rva), "rva_end_exclusive": hex(end),
                                       "expected_hex": expected.hex(), "actual_hex": actual.hex(),
                                       "expected_sha256": hashlib.sha256(expected).hexdigest(),
                                       "actual_sha256": hashlib.sha256(actual).hexdigest()}
            result["checks"][name] = actual == expected
        if result["checks"] and all(result["checks"].values()):
            result["status"] = "observed"
        else:
            result["unknown_conditions"].append("file_code_guard_mismatch")
    except Exception as exc:
        result["unknown_conditions"].append(f"file_code_guard_failed:{type(exc).__name__}:{exc}")
    return result


class _ReadBudget:
    def __init__(self, limit: int = READ_BUDGET_BYTES) -> None:
        self.limit = limit
        self.used = 0
        self.reads: list[dict[str, Any]] = []

    def reserve(self, size: int) -> None:
        if type(size) is not int or size <= 0 or size > MAX_SINGLE_RPM:
            raise ReadError("read_size_out_of_bound")
        if self.used + size > self.limit:
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


def _reader_read(reader: Any, address: int, size: int, label: str, budget: _ReadBudget,
                 layout: Mapping[str, int]) -> bytes:
    if not _valid_address(address, layout) or not _valid_address(address + size - 1, layout):
        raise ReadError(f"address_invalid:{label}")
    budget.reserve(size)
    method = getattr(reader, "read", None)
    if not callable(method):
        raise ReadError("reader_read_method_missing")
    try:
        raw = method(address, size, label)
    except Exception as exc:
        budget.reads.append({"address": _hex(address), "size": size, "label": label,
                             "status": "failed", "error": type(exc).__name__})
        raise ReadError(f"read_failed:{label}:{type(exc).__name__}:{exc}") from exc
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != size:
        budget.reads.append({"address": _hex(address), "size": size, "label": label,
                             "status": "failed", "error": "short_or_invalid_read"})
        raise ReadError(f"short_or_invalid_read:{label}")
    raw = bytes(raw)
    budget.reads.append({"address": _hex(address), "size": size, "label": label,
                         "status": "ok", "raw_hex": raw.hex(),
                         "sha256": hashlib.sha256(raw).hexdigest()})
    return raw


def _read_u64(reader: Any, address: int, label: str, budget: _ReadBudget,
              layout: Mapping[str, int]) -> tuple[int, bytes]:
    raw = _reader_read(reader, address, 8, label, budget, layout)
    return int.from_bytes(raw, "little", signed=False), raw


def _read_i32(reader: Any, address: int, label: str, budget: _ReadBudget,
              layout: Mapping[str, int]) -> tuple[int, bytes]:
    raw = _reader_read(reader, address, 4, label, budget, layout)
    return int.from_bytes(raw, "little", signed=True), raw


def _runtime_code_guard(reader: Any, module_base: int, profile: Mapping[str, Any],
                        budget: _ReadBudget) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "module_base": _hex(module_base),
                              "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        layout = _profile_layout(profile)
        for name, rva, end, expected in _profile_code_guards(profile):
            address = _add_address(module_base, rva, layout)
            raw = _reader_read(reader, address, len(expected), f"country_rivals.code.{name}", budget, layout)
            result["records"][name] = {"rva": hex(rva), "rva_end_exclusive": hex(end),
                                       "address": _hex(address), "expected_hex": expected.hex(),
                                       "actual_hex": raw.hex(),
                                       "expected_sha256": hashlib.sha256(expected).hexdigest(),
                                       "actual_sha256": hashlib.sha256(raw).hexdigest()}
            result["checks"][name] = raw == expected
        if result["checks"] and all(result["checks"].values()):
            result["status"] = "observed"
        else:
            result["unknown_conditions"].append("runtime_code_guard_mismatch")
    except Exception as exc:
        result["unknown_conditions"].append(f"runtime_code_guard_failed:{type(exc).__name__}:{exc}")
    return result


def _tag_from_fullref(value: int) -> str | None:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        return None
    raw = (value & 0xFFFFFF).to_bytes(3, "little")
    if not all(0x30 <= byte <= 0x39 or 0x41 <= byte <= 0x5A for byte in raw):
        return None
    return raw.decode("ascii")


def _slot_from_fullref(value: int) -> int | None:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        return None
    return (value >> 32) & 0xFFFF


def _parse_address(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = int(value, 0)
    except ValueError:
        return None
    return parsed if value == _hex(parsed) else None


def _find_country(reader: Any, module_base: int, country: str, profile: Mapping[str, Any],
                  budget: _ReadBudget) -> tuple[int, dict[str, Any]]:
    layout = _profile_layout(profile)
    if not isinstance(country, str) or re.fullmatch(r"[A-Z0-9]{3}", country) is None:
        raise ReadError("unsupported_country")
    database, database_raw = _read_u64(reader, _add_address(module_base, layout["database_global_rva"], layout),
                                       "country_rivals.database_global", budget, layout)
    if not _valid_address(database, layout):
        raise ReadError("country_database_invalid")
    table, table_raw = _read_u64(reader, _add_address(database, layout["database_table_offset"], layout),
                                 "country_rivals.database_table", budget, layout)
    if not _valid_address(table, layout):
        raise ReadError("country_table_invalid")
    count, count_raw = _read_i32(reader, _add_address(database, layout["database_table_count_offset"], layout),
                                 "country_rivals.database_count", budget, layout)
    if not 1 <= count <= int(profile["limits"]["max_country_slots"]):
        raise ReadError("country_count_invalid")
    slots: list[dict[str, Any]] = []
    matches: list[dict[str, Any]] = []
    seen_pointers: set[int] = set()
    for slot in range(count):
        entry_address = _add_address(table, slot * 8, layout)
        pointer, pointer_raw = _read_u64(reader, entry_address,
                                         f"country_rivals.database_slot[{slot}].pointer", budget, layout)
        row: dict[str, Any] = {"slot": slot, "table_entry_address": _hex(entry_address),
                               "table_entry_raw_hex": pointer_raw.hex(),
                               "country_pointer": _hex(pointer) if pointer else None,
                               "fullref": None, "fullref_raw_hex": None, "tag": None,
                               "fullref_slot": None}
        if pointer:
            if not _valid_address(pointer, layout) or pointer in seen_pointers:
                raise ReadError("country_pointer_invalid_or_repeated")
            seen_pointers.add(pointer)
            fullref, fullref_raw = _read_u64(reader, _add_address(pointer, layout["country_fullref_offset"], layout),
                                             f"country_rivals.database_slot[{slot}].fullref", budget, layout)
            tag = _tag_from_fullref(fullref)
            ref_slot = _slot_from_fullref(fullref)
            row.update({"fullref": _hex(fullref), "fullref_raw_hex": fullref_raw.hex(),
                        "tag": tag, "fullref_slot": ref_slot})
            if tag == country and ref_slot == slot:
                matches.append({"slot": slot, "country_pointer": _hex(pointer),
                                "fullref": _hex(fullref), "fullref_raw_hex": fullref_raw.hex(),
                                "tag": tag, "table_entry_raw_hex": pointer_raw.hex()})
        slots.append(row)
    if len(matches) != 1:
        raise ReadError("country_identity_match_count_invalid")
    scan = {"status": "observed", "database": _hex(database), "database_raw_hex": database_raw.hex(),
            "table_pointer": _hex(table), "table_raw_hex": table_raw.hex(), "country_count": count,
            "country_count_raw_hex": count_raw.hex(), "slots": slots, "matches": matches,
            "country_pointer": matches[0]["country_pointer"], "country_handle": matches[0]["fullref"],
            "country_slot": matches[0]["slot"]}
    return int(matches[0]["country_pointer"], 0), scan


def _resolve_fullref(fullref: int, country_scan: Mapping[str, Any], country: str,
                     layout: Mapping[str, int]) -> dict[str, Any]:
    tag, slot = _tag_from_fullref(fullref), _slot_from_fullref(fullref)
    if tag is None or slot is None:
        raise ReadError("rival_fullref_invalid")
    slots = country_scan.get("slots")
    if not isinstance(slots, list) or slot >= len(slots):
        raise ReadError("rival_fullref_slot_out_of_range")
    row = slots[slot]
    if (not isinstance(row, Mapping) or row.get("slot") != slot or row.get("tag") != tag or
            row.get("fullref") != _hex(fullref) or row.get("fullref_raw_hex") != fullref.to_bytes(8, "little").hex() or
            row.get("fullref_slot") != slot or row.get("country_pointer") is None or
            not _valid_address(_parse_address(row.get("country_pointer")), layout)):
        raise ReadError("rival_fullref_database_binding_mismatch")
    if tag == country:
        raise ReadError("rival_self_membership")
    return {"tag": tag, "slot": slot, "country_pointer": row["country_pointer"],
            "database_fullref_raw_hex": row["fullref_raw_hex"]}


def _read_rivals(reader: Any, country_pointer: int, country: str, country_scan: Mapping[str, Any],
                 profile: Mapping[str, Any], budget: _ReadBudget) -> dict[str, Any]:
    layout, limits = _profile_layout(profile), profile["limits"]
    head, head_raw = _read_u64(reader, _add_address(country_pointer, layout["country_rivals_head_offset"], layout),
                               "country_rivals.list_head", budget, layout)
    count, count_raw = _read_i32(reader, _add_address(country_pointer, layout["country_rivals_count_offset"], layout),
                                 "country_rivals.list_count", budget, layout)
    if count < 0 or count > int(limits["max_rivals"]):
        raise ReadError("rival_count_out_of_bound")
    if count == 0:
        if head != 0:
            raise ReadError("empty_rival_list_head_nonnull")
        return {"head": None, "head_raw_hex": head_raw.hex(), "count": 0,
                "count_raw_hex": count_raw.hex(), "entries": [], "members": []}
    if not _valid_address(head, layout):
        raise ReadError("rival_list_head_invalid")
    entries: list[dict[str, Any]] = []
    seen_nodes: set[int] = set()
    seen_tags: set[str] = set()
    seen_slots: set[int] = set()
    seen_fullrefs: set[int] = set()
    current = head
    for index in range(count):
        if not _valid_address(current, layout) or current in seen_nodes:
            raise ReadError("rival_node_invalid_or_cycle")
        seen_nodes.add(current)
        fullref, fullref_raw = _read_u64(reader, _add_address(current, layout["rival_node_fullref_offset"], layout),
                                        f"country_rivals.node[{index}].fullref", budget, layout)
        resolved = _resolve_fullref(fullref, country_scan, country, layout)
        tag, slot = resolved["tag"], resolved["slot"]
        if tag in seen_tags or slot in seen_slots or fullref in seen_fullrefs:
            raise ReadError("rival_duplicate_country")
        seen_tags.add(tag); seen_slots.add(slot); seen_fullrefs.add(fullref)
        since_date, since_raw = _read_i32(reader, _add_address(current, layout["rival_node_since_date_offset"], layout),
                                          f"country_rivals.node[{index}].since_date", budget, layout)
        next_node, next_raw = _read_u64(reader, _add_address(current, layout["rival_node_next_offset"], layout),
                                        f"country_rivals.node[{index}].next", budget, layout)
        if next_node and not _valid_address(next_node, layout):
            raise ReadError("rival_next_pointer_invalid")
        if next_node in seen_nodes:
            raise ReadError("rival_node_cycle")
        entries.append({"native_index": index, "node_address": _hex(current),
                        "fullref": _hex(fullref), "fullref_raw_hex": fullref_raw.hex(),
                        "tag": tag, "slot": slot, "target_country_pointer": resolved["country_pointer"],
                        "database_fullref_raw_hex": resolved["database_fullref_raw_hex"],
                        "since_date_raw": since_date, "since_date_raw_hex": since_raw.hex(),
                        "next_node": _hex(next_node) if next_node else None,
                        "next_raw_hex": next_raw.hex()})
        if index + 1 < count and next_node == 0:
            raise ReadError("rival_count_chain_short")
        if index + 1 == count and next_node != 0:
            raise ReadError("rival_count_chain_detached_tail")
        current = next_node
    return {"head": _hex(head), "head_raw_hex": head_raw.hex(), "count": count,
            "count_raw_hex": count_raw.hex(), "entries": entries,
            "members": sorted(seen_tags)}


def _snapshot(reader: Any, module_base: int, country_pointer: int, country: str,
              profile: Mapping[str, Any], static_guard: Mapping[str, Any], budget: _ReadBudget,
              country_scan: Mapping[str, Any] | None = None) -> dict[str, Any]:
    layout = _profile_layout(profile)
    start_used, start_log = budget.used, len(budget.reads)
    if country_scan is None:
        found_pointer, country_scan = _find_country(reader, module_base, country, profile, budget)
        if country_pointer is not None and found_pointer != country_pointer:
            raise ReadError("country_pointer_database_mismatch")
        country_pointer = found_pointer
    elif country_pointer is None:
        country_pointer = _parse_address(country_scan.get("country_pointer"))
    if country_pointer is None or not _valid_address(country_pointer, layout):
        raise ReadError("country_pointer_invalid")
    runtime_guard = _runtime_code_guard(reader, module_base, profile, budget)
    if runtime_guard.get("status") != "observed":
        raise ReadError("runtime_code_guard_failed")
    game, game_raw = _read_u64(reader, _add_address(module_base, layout["game_global_rva"], layout),
                               "country_rivals.game", budget, layout)
    if not _valid_address(game, layout):
        raise ReadError("game_pointer_invalid")
    date_raw = _reader_read(reader, _add_address(game, layout["game_date_offset"], layout), 4,
                            "country_rivals.game_date", budget, layout)
    game_date = int.from_bytes(date_raw, "little", signed=True)
    handle, handle_raw = _read_u64(reader, _add_address(country_pointer, layout["country_fullref_offset"], layout),
                                   "country_rivals.country_fullref", budget, layout)
    if (_tag_from_fullref(handle) != country or _slot_from_fullref(handle) != country_scan.get("country_slot") or
            handle != int(str(country_scan.get("country_handle")), 0)):
        raise ReadError("country_fullref_database_mismatch")
    list_data = _read_rivals(reader, country_pointer, country, country_scan, profile, budget)
    read_log = _copy_json(budget.reads[start_log:])
    field = {"status": "known", "value": list_data["members"], "unit": UNIT, "scale": SCALE,
             "period": PERIOD, "direction": DIRECTION, "basis": BASIS,
             "value_origin": VALUE_ORIGIN, "complete": True, "partial": False}
    private = {"module_base": _hex(module_base), "country_pointer": _hex(country_pointer),
               "country_handle": _hex(handle), "country_handle_raw_hex": handle_raw.hex(),
               "country_slot": country_scan["country_slot"], "country_scan": _copy_json(country_scan),
               "game_pointer": _hex(game), "game_pointer_raw_hex": game_raw.hex(),
               "game_date": {"value": game_date, "raw_hex": date_raw.hex()},
               "rival_list_head": list_data["head"], "rival_list_head_raw_hex": list_data["head_raw_hex"],
               "rival_count": list_data["count"], "rival_count_raw_hex": list_data["count_raw_hex"],
               "native_entries": _copy_json(list_data["entries"]),
               "static_contract_guard": _copy_json(static_guard),
               "runtime_code_guard": _copy_json(runtime_guard)}
    record = {"status": "observed", "profile_id": EXPECTED_PROFILE_ID,
              "profile_sha256": EXPECTED_PROFILE_SHA256, "country": country,
              "fields": {FIELD_KEY: field}, "private": private,
              "observation": {"profile_id": EXPECTED_PROFILE_ID,
                              "profile_sha256": EXPECTED_PROFILE_SHA256,
                              "module_base": _hex(module_base),
                              "country_pointer": _hex(country_pointer),
                              "country_handle": _hex(handle), "game_date": game_date,
                              "read_budget": {"bytes_reserved": budget.used - start_used,
                                              "limit": READ_BUDGET_BYTES},
                              "read_log": read_log}}
    return {"status": "observed", "country": country, "country_pointer": _hex(country_pointer),
            "country_handle": _hex(handle), "game_date": {"value": game_date, "raw_hex": date_raw.hex()},
            "fields": {FIELD_KEY: field}, "values": {FIELD_KEY: list_data["members"]},
            "raw_hex": {FIELD_KEY: _copy_json(list_data["entries"])},
            "private": _copy_json(private), "record": record,
            "country_scan": _copy_json(country_scan),
            "read_budget": {"bytes_reserved": budget.used - start_used, "limit": READ_BUDGET_BYTES},
            "read_log": read_log, "runtime_code_guard": runtime_guard}


def _unknown_record(reason: str, *, country: str = EXPECTED_COUNTRY,
                    module_base: int | None = None, country_pointer: int | None = None) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason, "country": country,
            "profile_id": EXPECTED_PROFILE_ID, "profile_sha256": EXPECTED_PROFILE_SHA256,
            "fields": {FIELD_KEY: {"status": "unknown", "reason": reason}},
            "private": {"module_base": _hex(module_base), "country_pointer": _hex(country_pointer)}}


def read_fields(reader: Any, module_base: int, country_pointer: int,
                country: str = EXPECTED_COUNTRY,
                profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Read one bounded Reader without opening a target process."""
    try:
        loaded = _load_profile() if profile is None else _prepare_profile(profile)
        layout = _profile_layout(loaded)
        if not isinstance(country, str) or re.fullmatch(r"[A-Z0-9]{3}", country) is None:
            raise ReadError("unsupported_country")
        if not _valid_address(module_base, layout) or not _valid_address(country_pointer, layout):
            raise ReadError("module_or_country_pointer_invalid")
        static_guard = _static_contract_guard(loaded)
        if static_guard.get("status") != "observed":
            raise ReadError("static_contract_guard_failed")
        budget = _ReadBudget()
        return _snapshot(reader, module_base, country_pointer, country, loaded,
                         static_guard, _ReadBudget())
    except Exception as exc:
        return _unknown_record(f"{type(exc).__name__}:{exc}", country=country,
                               module_base=module_base if type(module_base) is int else None,
                               country_pointer=country_pointer if type(country_pointer) is int else None)


def _stable_record(record: Mapping[str, Any]) -> dict[str, Any]:
    return _copy_json(record)


def _stable_record_for_comparison(record: Mapping[str, Any]) -> dict[str, Any]:
    return without_clock(_stable_record(record), date_labels=("country_rivals.game_date",))


def _diff_paths(left: Any, right: Any, path: str = "$") -> list[str]:
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        result: list[str] = []
        for key in sorted(set(left) | set(right), key=str):
            child = f"{path}.{key}"
            if key not in left or key not in right:
                result.append(child)
            else:
                result.extend(_diff_paths(left[key], right[key], child))
        return result
    if isinstance(left, list) and isinstance(right, list):
        result = []
        for index in range(max(len(left), len(right))):
            child = f"{path}[{index}]"
            if index >= len(left) or index >= len(right):
                result.append(child)
            else:
                result.extend(_diff_paths(left[index], right[index], child))
        return result
    return [] if left == right else [path]


def capture(installation: Path, country: str = EXPECTED_COUNTRY) -> dict[str, Any]:
    """Capture current outgoing rival tags with bounded read-only RPM."""
    installation = Path(installation)
    report: dict[str, Any] = {
        "probe": "information-country-rivals-runtime", "probe_version": 1,
        "probe_script": str(Path(__file__).resolve()), "probe_script_sha256": None,
        "profile": {"path": str(PROFILE_FILE), "sha256": EXPECTED_PROFILE_SHA256,
                    "profile_id": EXPECTED_PROFILE_ID, "max_bytes": PROFILE_MAX_BYTES},
        "read_only": True, "evidence_kind": "pure_runtime_observation_not_static_evidence",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "request": {"installation": str(installation), "country": country,
                    "scope": "direct_outgoing_active_rival_membership"},
        "country": country,
        "target_build": {"version": EXPECTED_VERSION, "expected_exe_sha256": EXPECTED_EXE_SHA256},
        "static_contract_guard": None, "file_code_guard": None, "runtime_code_guard": None,
        "identity": {"installation_path": str(installation), "installation_pid": None,
                     "installation_creation_filetime": None, "installation_session_id": None,
                     "process_path": None, "process_path_sha256": None,
                     "process_path_sha256_matches_expected": None,
                     "process_creation_filetime": None, "process_creation_utc": None,
                     "process_creation_matches_installation": None,
                     "module_path": None, "module_path_matches_process": None,
                     "binding_verified": False},
        "module_base": None, "country_pointer": None, "country_scan": None,
        "before": None, "after": None,
        "fields": {FIELD_KEY: {"status": "unknown", "reason": "not_read"}},
        "values": None, "raw_hex": None, "complete": False,
        "doublepass": {"performed": False, "consistent": None, "mismatches": [], "atomic": False},
        "access": {"open_process_mask": "QUERY_INFORMATION|VM_READ",
                   "open_process_mask_hex": _hex(PROCESS_ACCESS), "rpm_total_limit": MAX_TOTAL_RPM,
                   "rpm_single_read_limit": MAX_SINGLE_RPM, "rpm_bytes_requested": 0, "rpm_calls": 0,
                   "native_game_calls": False, "target_memory_writes": False,
                   "mcp_query": False, "control_or_business_dispatch": False,
                   "date_advance_save_restart": False},
        "cleanup": {"handle_close": {"status": "unknown", "success": None, "closed": False}},
        "status": "starting", "errors": [], "completed": False,
    }
    kernel = handle = reader = None
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
        document = _load_installation(installation)
        kernel = _configure_kernel()
        handle = kernel.OpenProcess(PROCESS_ACCESS, False, int(document["pid"]))
        if not handle:
            raise OSError("OpenProcess failed")
        module_base = _capture_identity(report, document, kernel, handle)
        report["module_base"] = _hex(module_base)
        report["request"].update({"pid": int(document["pid"]),
                                  "creation_filetime": int(document["creation_filetime"]),
                                  "session_id": str(document["session_id"]),
                                  "game_sha256": str(document.get("game_sha256", "")).lower()})
        process_path = Path(report["identity"]["process_path"])
        report["file_code_guard"] = _file_code_guard(process_path, profile)
        if report["file_code_guard"].get("status") != "observed":
            report["status"] = "file_code_mismatch"
            return report
        reader = AddressBoundedRPM(kernel, handle, module_base)
        first = _snapshot(reader, module_base, None, country, profile,
                          report["static_contract_guard"], budget)
        first_pointer, first_scan = int(first["country_pointer"], 0), first["country_scan"]
        report["country_pointer"] = _hex(first_pointer)
        report["before"] = first
        second = _snapshot(reader, module_base, None, country, profile,
                           report["static_contract_guard"], budget)
        second_pointer, second_scan = int(second["country_pointer"], 0), second["country_scan"]
        report["after"] = second
        report["doublepass"]["performed"] = True
        report["doublepass"]["mismatches"] = _diff_paths(
            _stable_record_for_comparison(first["record"]),
            _stable_record_for_comparison(second["record"]))
        first_date = first["record"].get("private", {}).get("game_date")
        second_date = second["record"].get("private", {}).get("game_date")
        first_date_value = first_date.get("value") if isinstance(first_date, Mapping) else None
        second_date_value = second_date.get("value") if isinstance(second_date, Mapping) else None
        if (not dates_match(first_date_value, second_date_value)
                and not any("game_date" in path for path in report["doublepass"]["mismatches"])):
            report["doublepass"]["mismatches"].append("$.game_date")
        report["doublepass"]["mismatches"].extend(_diff_paths(first_scan, second_scan, "$.country_scan"))
        if first_pointer != second_pointer:
            report["doublepass"]["mismatches"].append("$.country_pointer")
        report["doublepass"]["consistent"] = not report["doublepass"]["mismatches"]
        report["country_scan"] = {"before": _copy_json(first_scan), "after": _copy_json(second_scan)}
        report["runtime_code_guard"] = {"status": "observed", "passes": [first["runtime_code_guard"], second["runtime_code_guard"]]}
        report["access"]["rpm_bytes_requested"] = budget.used
        report["access"]["rpm_calls"] = len(budget.reads)
        if not report["doublepass"]["consistent"]:
            report["status"] = "doublepass_mismatch"
            report["errors"].append({"stage": "doublepass", "status": "unknown",
                                     "error": "Rival membership changed between passes",
                                     "paths": report["doublepass"]["mismatches"][:256]})
            return report
        report["fields"] = _copy_json(first["fields"])
        report["values"] = _copy_json(first["values"])
        report["raw_hex"] = _copy_json(first["raw_hex"])
        report["complete"] = True
        report["status"] = "observed"
        report["completed"] = True
        return report
    except Exception as exc:
        report["status"] = "unknown"
        report["errors"].append({"stage": "capture", "status": "unknown",
                                 "error": f"{type(exc).__name__}:{exc}"})
        report["access"]["rpm_bytes_requested"] = budget.used
        report["access"]["rpm_calls"] = len(budget.reads)
        return report
    finally:
        report["access"]["rpm_bytes_requested"] = budget.used
        report["access"]["rpm_calls"] = len(budget.reads)
        report["cleanup"]["handle_close"] = _close_process_handle(kernel, handle)
        if report.get("status") == "observed" and report["cleanup"]["handle_close"] != {"status": "closed", "success": True, "closed": True}:
            report["status"] = "unknown"
            report["fields"] = {FIELD_KEY: {"status": "unknown", "reason": "cleanup_failed"}}
            report["values"] = None
            report["raw_hex"] = None
            report["complete"] = False
            report["errors"].append({"stage": "cleanup", "status": "unknown",
                                     "error": "process handle cleanup failed",
                                     "cleanup": _copy_json(report["cleanup"]["handle_close"])})
        report["completed"] = report.get("status") == "observed" and report["cleanup"]["handle_close"] == {"status": "closed", "success": True, "closed": True}


def _trace_index(observation: Any, layout: Mapping[str, int]) -> dict[str, dict[str, Any]] | None:
    if not isinstance(observation, Mapping):
        return None
    budget, logs = observation.get("read_budget"), observation.get("read_log")
    if (not isinstance(budget, Mapping) or budget.get("limit") != READ_BUDGET_BYTES or
            type(budget.get("bytes_reserved")) is not int or
            not 0 < budget["bytes_reserved"] <= READ_BUDGET_BYTES or
            not isinstance(logs, list) or not logs):
        return None
    result: dict[str, dict[str, Any]] = {}
    total = 0
    for item in logs:
        if not isinstance(item, Mapping) or item.get("status") != "ok":
            return None
        label, size, raw_hex, digest = item.get("label"), item.get("size"), item.get("raw_hex"), item.get("sha256")
        address = _parse_address(item.get("address"))
        if (not isinstance(label, str) or not label.startswith("country_rivals.") or label in result or
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
    try:
        expected = _static_contract_guard(profile)
        return (isinstance(value, Mapping) and value.get("status") == "observed" and
                value.get("evidence_kind") == expected.get("evidence_kind") and
                value.get("profile") == expected.get("profile") and
                value.get("profile_id") == EXPECTED_PROFILE_ID and
                value.get("profile_sha256") == EXPECTED_PROFILE_SHA256 and
                value.get("source_evidence") == expected.get("source_evidence") and
                value.get("checks") == expected.get("checks") and value.get("unknown_conditions") == [])
    except Exception:
        return False


def _file_guard_valid(value: Any, profile: Mapping[str, Any], process_path: str) -> bool:
    if (not isinstance(value, Mapping) or value.get("status") != "observed" or
            value.get("path") != process_path):
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
            digest = hashlib.sha256(expected).hexdigest()
            if (not isinstance(row, Mapping) or row.get("rva") != hex(rva) or
                    row.get("rva_end_exclusive") != hex(end) or
                    row.get("expected_hex") != expected.hex() or row.get("actual_hex") != expected.hex() or
                    row.get("expected_sha256") != digest or row.get("actual_sha256") != digest):
                return False
    except Exception:
        return False
    return True


def _runtime_guard_valid(value: Any, profile: Mapping[str, Any], module_base: int,
                         trace: Mapping[str, Mapping[str, Any]],
                         layout: Mapping[str, int]) -> bool:
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
            raw = _trace_raw(trace, f"country_rivals.code.{name}", address, len(expected))
            digest = hashlib.sha256(expected).hexdigest()
            if (raw != expected or row.get("rva") != hex(rva) or row.get("rva_end_exclusive") != hex(end) or
                    row.get("address") != _hex(address) or row.get("expected_hex") != expected.hex() or
                    row.get("actual_hex") != expected.hex() or row.get("expected_sha256") != digest or
                    row.get("actual_sha256") != digest):
                return False
    except Exception:
        return False
    return True


def _raw_u64(raw_hex: Any) -> int | None:
    try:
        if not isinstance(raw_hex, str) or len(raw_hex) != 16 or raw_hex != raw_hex.lower():
            return None
        return int.from_bytes(bytes.fromhex(raw_hex), "little", signed=False)
    except (ValueError, TypeError):
        return None


def _raw_i32(raw_hex: Any) -> int | None:
    try:
        if not isinstance(raw_hex, str) or len(raw_hex) != 8 or raw_hex != raw_hex.lower():
            return None
        return int.from_bytes(bytes.fromhex(raw_hex), "little", signed=True)
    except (ValueError, TypeError):
        return None


def _validate_country_scan(scan: Any, module_base: int, profile: Mapping[str, Any],
                           trace: Mapping[str, Mapping[str, Any]], country: str) -> tuple[int, dict[int, dict[str, Any]], set[str]] | None:
    if not isinstance(scan, Mapping) or scan.get("status") != "observed":
        return None
    layout = _profile_layout(profile)
    database, table, count = (_parse_address(scan.get("database")),
                              _parse_address(scan.get("table_pointer")), scan.get("country_count"))
    if (database is None or table is None or not _valid_address(database, layout) or
            not _valid_address(table, layout) or type(count) is not int or
            not 1 <= count <= int(profile["limits"]["max_country_slots"])):
        return None
    db_raw = _trace_raw(trace, "country_rivals.database_global", module_base + layout["database_global_rva"], 8)
    table_raw = _trace_raw(trace, "country_rivals.database_table", database + layout["database_table_offset"], 8)
    count_raw = _trace_raw(trace, "country_rivals.database_count", database + layout["database_table_count_offset"], 4)
    if (db_raw is None or _raw_u64(db_raw.hex()) != database or scan.get("database_raw_hex") != db_raw.hex() or
            table_raw is None or _raw_u64(table_raw.hex()) != table or scan.get("table_raw_hex") != table_raw.hex() or
            count_raw is None or _raw_i32(count_raw.hex()) != count or scan.get("country_count_raw_hex") != count_raw.hex()):
        return None
    rows = scan.get("slots")
    if not isinstance(rows, list) or len(rows) != count:
        return None
    by_slot: dict[int, dict[str, Any]] = {}
    labels = {"country_rivals.database_global", "country_rivals.database_table", "country_rivals.database_count"}
    seen_pointers: set[int] = set()
    for slot, row in enumerate(rows):
        if not isinstance(row, Mapping) or row.get("slot") != slot:
            return None
        entry_address = table + slot * 8
        ptr_raw = _trace_raw(trace, f"country_rivals.database_slot[{slot}].pointer", entry_address, 8)
        pointer = _raw_u64(ptr_raw.hex()) if ptr_raw is not None else None
        if (ptr_raw is None or row.get("table_entry_address") != _hex(entry_address) or
                row.get("table_entry_raw_hex") != ptr_raw.hex() or
                _parse_address(row.get("country_pointer")) != (pointer or None)):
            return None
        labels.add(f"country_rivals.database_slot[{slot}].pointer")
        if pointer:
            if not _valid_address(pointer, layout) or pointer in seen_pointers:
                return None
            seen_pointers.add(pointer)
            fullref_raw = _trace_raw(trace, f"country_rivals.database_slot[{slot}].fullref",
                                     pointer + layout["country_fullref_offset"], 8)
            fullref = _raw_u64(fullref_raw.hex()) if fullref_raw is not None else None
            if (fullref_raw is None or row.get("fullref_raw_hex") != fullref_raw.hex() or
                    row.get("fullref") != _hex(fullref) or row.get("tag") != _tag_from_fullref(fullref) or
                    row.get("fullref_slot") != _slot_from_fullref(fullref)):
                return None
            labels.add(f"country_rivals.database_slot[{slot}].fullref")
            by_slot[slot] = dict(row)
        elif any(row.get(key) is not None for key in ("fullref", "fullref_raw_hex", "tag", "fullref_slot")):
            return None
    matches = scan.get("matches")
    exact_matches = []
    for slot, row in by_slot.items():
        fullref = _raw_u64(row.get("fullref_raw_hex"))
        if row.get("tag") == country and row.get("fullref_slot") == slot:
            exact_matches.append({"slot": slot, "country_pointer": row["country_pointer"],
                                  "fullref": row["fullref"], "fullref_raw_hex": row["fullref_raw_hex"],
                                  "tag": country, "table_entry_raw_hex": row["table_entry_raw_hex"]})
        # A parsed tag whose embedded slot disagrees is not a country-table match.
        if fullref is None:
            return None
    if (not isinstance(matches, list) or len(exact_matches) != 1 or matches != exact_matches or
            scan.get("country_pointer") != exact_matches[0]["country_pointer"] or
            scan.get("country_handle") != exact_matches[0]["fullref"] or
            scan.get("country_slot") != exact_matches[0]["slot"]):
        return None
    return exact_matches[0]["slot"], by_slot, labels


def _validate_private_graph(record: Mapping[str, Any], profile: Mapping[str, Any],
                            module_base: int, trace: Mapping[str, Mapping[str, Any]]) -> bool:
    layout = _profile_layout(profile)
    private, fields = record.get("private"), record.get("fields")
    if not isinstance(private, Mapping) or not isinstance(fields, Mapping):
        return False
    country_pointer = _parse_address(private.get("country_pointer"))
    game = _parse_address(private.get("game_pointer"))
    country_handle = _parse_address(private.get("country_handle"))
    country = record.get("country")
    if (country_pointer is None or game is None or country_handle is None or
            not _valid_address(country_pointer, layout) or not _valid_address(game, layout) or
            _tag_from_fullref(country_handle) != country):
        return False
    if not _static_guard_valid(private.get("static_contract_guard"), profile):
        return False
    if not _runtime_guard_valid(private.get("runtime_code_guard"), profile, module_base, trace, layout):
        return False
    game_raw = _trace_raw(trace, "country_rivals.game", module_base + layout["game_global_rva"], 8)
    date_raw = _trace_raw(trace, "country_rivals.game_date", game + layout["game_date_offset"], 4)
    handle_raw = _trace_raw(trace, "country_rivals.country_fullref", country_pointer + layout["country_fullref_offset"], 8)
    date = private.get("game_date")
    if (game_raw is None or _raw_u64(game_raw.hex()) != game or private.get("game_pointer_raw_hex") != game_raw.hex() or
            date_raw is None or not isinstance(date, Mapping) or date.get("raw_hex") != date_raw.hex() or
            date.get("value") != _raw_i32(date_raw.hex()) or handle_raw is None or
            _raw_u64(handle_raw.hex()) != country_handle or private.get("country_handle_raw_hex") != handle_raw.hex()):
        return False
    scan = _validate_country_scan(private.get("country_scan"), module_base, profile, trace, country)
    if scan is None:
        return False
    country_slot, database_rows, labels = scan
    if (private.get("country_pointer") != database_rows[country_slot].get("country_pointer") or
            private.get("country_handle") != database_rows[country_slot].get("fullref") or
            private.get("country_slot") != country_slot):
        return False
    head_raw = _trace_raw(trace, "country_rivals.list_head", country_pointer + layout["country_rivals_head_offset"], 8)
    count_raw = _trace_raw(trace, "country_rivals.list_count", country_pointer + layout["country_rivals_count_offset"], 4)
    head = _raw_u64(head_raw.hex()) if head_raw is not None else None
    count = _raw_i32(count_raw.hex()) if count_raw is not None else None
    if (head_raw is None or count_raw is None or private.get("rival_list_head_raw_hex") != head_raw.hex() or
            private.get("rival_count_raw_hex") != count_raw.hex() or private.get("rival_count") != count or
            private.get("rival_list_head") != (_hex(head) if head else None) or
            type(count) is not int or not 0 <= count <= MAX_RIVALS or
            (count == 0 and head != 0) or (count > 0 and (head is None or not _valid_address(head, layout)))):
        return False
    labels.update({f"country_rivals.code.{name}" for name, _rva, _end, _raw in _profile_code_guards(profile)})
    labels.update({"country_rivals.game", "country_rivals.game_date", "country_rivals.country_fullref",
                   "country_rivals.list_head", "country_rivals.list_count"})
    entries = private.get("native_entries")
    field = fields.get(FIELD_KEY)
    if not isinstance(entries, list) or len(entries) != count or not isinstance(field, Mapping):
        return False
    tags: list[str] = []
    seen_nodes: set[int] = set()
    seen_tags: set[str] = set()
    seen_slots: set[int] = set()
    seen_refs: set[int] = set()
    expected_node = head or 0
    for index, row in enumerate(entries):
        if not isinstance(row, Mapping):
            return False
        node = _parse_address(row.get("node_address"))
        if node is None or node != expected_node or not _valid_address(node, layout) or node in seen_nodes:
            return False
        seen_nodes.add(node)
        fullref_raw = _trace_raw(trace, f"country_rivals.node[{index}].fullref", node + layout["rival_node_fullref_offset"], 8)
        date_node_raw = _trace_raw(trace, f"country_rivals.node[{index}].since_date", node + layout["rival_node_since_date_offset"], 4)
        next_raw = _trace_raw(trace, f"country_rivals.node[{index}].next", node + layout["rival_node_next_offset"], 8)
        fullref = _raw_u64(fullref_raw.hex()) if fullref_raw is not None else None
        since = _raw_i32(date_node_raw.hex()) if date_node_raw is not None else None
        next_node = _raw_u64(next_raw.hex()) if next_raw is not None else None
        if (fullref_raw is None or date_node_raw is None or next_raw is None or
                row.get("fullref_raw_hex") != fullref_raw.hex() or row.get("fullref") != _hex(fullref) or
                row.get("since_date_raw_hex") != date_node_raw.hex() or row.get("since_date_raw") != since or
                row.get("next_raw_hex") != next_raw.hex() or row.get("next_node") != (_hex(next_node) if next_node else None) or
                row.get("native_index") != index):
            return False
        tag, slot = _tag_from_fullref(fullref), _slot_from_fullref(fullref)
        dbrow = database_rows.get(slot)
        if (tag is None or slot is None or tag == country or dbrow is None or
                dbrow.get("tag") != tag or dbrow.get("fullref") != _hex(fullref) or
                dbrow.get("fullref_raw_hex") != fullref_raw.hex() or
                dbrow.get("fullref_slot") != slot or row.get("tag") != tag or row.get("slot") != slot or
                row.get("target_country_pointer") != dbrow.get("country_pointer") or
                row.get("database_fullref_raw_hex") != dbrow.get("fullref_raw_hex") or
                tag in seen_tags or slot in seen_slots or fullref in seen_refs):
            return False
        tags.append(tag); seen_tags.add(tag); seen_slots.add(slot); seen_refs.add(fullref)
        labels.update({f"country_rivals.node[{index}].fullref",
                       f"country_rivals.node[{index}].since_date",
                       f"country_rivals.node[{index}].next"})
        if next_node and (not _valid_address(next_node, layout) or next_node in seen_nodes):
            return False
        expected_next = _parse_address(entries[index + 1].get("node_address")) if index + 1 < count else 0
        if next_node != expected_next:
            return False
        expected_node = next_node or 0
    if expected_node != 0 or set(trace) != labels:
        return False
    expected_members = sorted(tags)
    if (set(field) != {"status", "value", "unit", "scale", "period", "direction", "basis",
                       "value_origin", "complete", "partial"} or
            field.get("status") != "known" or field.get("value") != expected_members or
            field.get("unit") != UNIT or field.get("scale") != SCALE or
            field.get("period") != PERIOD or field.get("direction") != DIRECTION or
            field.get("value_origin") != VALUE_ORIGIN or field.get("complete") is not True or
            field.get("partial") is not False or field.get("basis") != BASIS):
        return False
    return True


def validate_record(record: Any) -> bool:
    """Validate public tags by rebuilding the linked membership from RPM trace bytes."""
    try:
        profile = _load_profile()
        layout = _profile_layout(profile)
        country = record.get("country") if isinstance(record, Mapping) else None
        if (not isinstance(country, str) or re.fullmatch(r"[A-Z0-9]{3}", country) is None
                or record.get("status") != "observed" or record.get("profile_id") != EXPECTED_PROFILE_ID
                or record.get("profile_sha256") != EXPECTED_PROFILE_SHA256):
            return False
        private = record.get("private")
        module_base = _parse_address(private.get("module_base")) if isinstance(private, Mapping) else None
        observation = record.get("observation")
        trace = _trace_index(observation, layout)
        if (module_base is None or not _valid_address(module_base, layout) or trace is None or
                not isinstance(observation, Mapping) or observation.get("profile_id") != EXPECTED_PROFILE_ID or
                observation.get("profile_sha256") != EXPECTED_PROFILE_SHA256 or
                observation.get("module_base") != private.get("module_base") or
                observation.get("country_pointer") != private.get("country_pointer") or
                observation.get("country_handle") != private.get("country_handle") or
                observation.get("game_date") != private.get("game_date", {}).get("value")):
            return False
        fields = record.get("fields")
        if not isinstance(fields, Mapping) or set(fields) != {FIELD_KEY}:
            return False
        budget = observation.get("read_budget")
        logs = observation.get("read_log")
        if (not isinstance(budget, Mapping) or budget.get("limit") != READ_BUDGET_BYTES or
                type(budget.get("bytes_reserved")) is not int or
                sum(int(item.get("size", 0)) for item in logs if isinstance(item, Mapping)) != budget.get("bytes_reserved")):
            return False
        return _validate_private_graph(record, profile, module_base, trace)
    except Exception:
        return False


def validate_capture(report: Any, context: Mapping[str, Any] | None,
                     creation_filetime: int, country: str = EXPECTED_COUNTRY) -> bool:
    """Validate installation identity, fixed session/date, both passes, and cleanup."""
    try:
        if (not isinstance(report, Mapping) or report.get("status") != "observed" or
                report.get("completed") is not True or report.get("complete") is not True or
                report.get("country") != country or
                report.get("read_only") is not True):
            return False
        identity, request = report.get("identity"), report.get("request")
        access, double = report.get("access"), report.get("doublepass")
        cleanup = report.get("cleanup", {}).get("handle_close") if isinstance(report.get("cleanup"), Mapping) else None
        profile = _load_profile()
        if (not isinstance(identity, Mapping) or not isinstance(request, Mapping) or
                identity.get("binding_verified") is not True or
                identity.get("process_creation_matches_installation") is not True or
                identity.get("process_path_sha256_matches_expected") is not True or
                str(identity.get("process_path_sha256", "")).lower() != EXPECTED_EXE_SHA256 or
                identity.get("module_path_matches_process") is not True or
                identity.get("installation_creation_filetime") != creation_filetime or
                identity.get("process_creation_filetime") != creation_filetime or
                cleanup != {"status": "closed", "success": True, "closed": True} or
                not isinstance(access, Mapping) or access.get("native_game_calls") is not False or
                access.get("target_memory_writes") is not False or access.get("mcp_query") is not False or
                access.get("control_or_business_dispatch") is not False or
                access.get("date_advance_save_restart") is not False or
                access.get("open_process_mask") != "QUERY_INFORMATION|VM_READ" or
                access.get("open_process_mask_hex") != _hex(PROCESS_ACCESS) or
                access.get("rpm_total_limit") != MAX_TOTAL_RPM or
                access.get("rpm_single_read_limit") != MAX_SINGLE_RPM or
                not isinstance(double, Mapping) or double.get("performed") is not True or
                double.get("consistent") is not True or double.get("mismatches") != [] or
                type(access.get("rpm_bytes_requested")) is not int or
                not 0 <= access["rpm_bytes_requested"] <= MAX_TOTAL_RPM or
                type(access.get("rpm_calls")) is not int or access["rpm_calls"] < 0):
            return False
        if (request.get("country") != country or request.get("installation") != identity.get("installation_path") or
                request.get("pid") != identity.get("installation_pid") or
                request.get("creation_filetime") != identity.get("installation_creation_filetime") or
                request.get("session_id") != identity.get("installation_session_id") or
                str(request.get("game_sha256", "")).lower() != EXPECTED_EXE_SHA256):
            return False
        if (type(creation_filetime) is not int or
                identity.get("installation_creation_filetime") != creation_filetime or
                identity.get("process_creation_filetime") != creation_filetime):
            return False
        if (not isinstance(context, Mapping) or context.get("status") != "ready" or
                context.get("mode") != "live" or
                context.get("observer") != country or context.get("game_version") != EXPECTED_VERSION or
                str(context.get("game_sha256", "")).lower() != EXPECTED_EXE_SHA256 or
                type(context.get("game_date")) is not int):
            return False
        if (report.get("profile") != {"path": str(PROFILE_FILE), "sha256": EXPECTED_PROFILE_SHA256,
                                      "profile_id": EXPECTED_PROFILE_ID, "max_bytes": PROFILE_MAX_BYTES} or
                report.get("target_build") != {"version": EXPECTED_VERSION,
                                                "expected_exe_sha256": EXPECTED_EXE_SHA256} or
                not _static_guard_valid(report.get("static_contract_guard"), profile) or
                not _file_guard_valid(report.get("file_code_guard"), profile, str(identity.get("process_path")))):
            return False
        if (identity.get("installation_session_id") != context.get("session_id") or
                identity.get("installation_session_id") != request.get("session_id")):
            return False
        before, after = report.get("before"), report.get("after")
        if (not isinstance(before, Mapping) or not isinstance(after, Mapping) or
                not isinstance(before.get("record"), Mapping) or not isinstance(after.get("record"), Mapping) or
                not validate_record(before["record"]) or not validate_record(after["record"])):
            return False
        pass_records = (before["record"], after["record"])
        if any(record.get("country") != country for record in pass_records):
            return False
        expected_bytes = sum(item["observation"]["read_budget"]["bytes_reserved"] for item in pass_records)
        expected_calls = sum(len(item["observation"]["read_log"]) for item in pass_records)
        if access.get("rpm_bytes_requested") != expected_bytes or access.get("rpm_calls") != expected_calls:
            return False
        if _diff_paths(_stable_record_for_comparison(before["record"]),
                       _stable_record_for_comparison(after["record"])):
            return False
        for outer in (before, after):
            record = outer["record"]
            private = record["private"]
            observation = record["observation"]
            public_value = record["fields"][FIELD_KEY]["value"]
            if (outer.get("fields") != record.get("fields") or outer.get("private") != record.get("private") or
                    outer.get("country_pointer") != private.get("country_pointer") or
                    outer.get("country_handle") != private.get("country_handle") or
                    outer.get("game_date") != private.get("game_date") or
                    outer.get("country_scan") != private.get("country_scan") or
                    outer.get("raw_hex") != {FIELD_KEY: private.get("native_entries")} or
                    outer.get("values") != {FIELD_KEY: public_value} or
                    outer.get("read_budget") != observation.get("read_budget") or
                    outer.get("read_log") != observation.get("read_log") or
                    outer.get("runtime_code_guard") != private.get("runtime_code_guard")):
                return False
        before_date = before["record"]["private"].get("game_date")
        after_date = after["record"]["private"].get("game_date")
        before_date_value = before_date.get("value") if isinstance(before_date, Mapping) else None
        after_date_value = after_date.get("value") if isinstance(after_date, Mapping) else None
        if (not dates_match(before_date_value, after_date_value) or
                not dates_match(context.get("game_date"), before_date_value, after_date_value)):
            return False
        if (report.get("module_base") != before["record"]["private"].get("module_base") or
                report.get("module_base") != after["record"]["private"].get("module_base") or
                report.get("country_pointer") != before["record"]["private"].get("country_pointer") or
                report.get("country_pointer") != after["record"]["private"].get("country_pointer") or
                report.get("fields") != after.get("fields") or report.get("values") != after.get("values") or
                report.get("raw_hex") != after.get("raw_hex")):
            return False
        expected_runtime = {"status": "observed", "passes": [
            before["record"]["private"].get("runtime_code_guard"),
            after["record"]["private"].get("runtime_code_guard"),
        ]}
        if report.get("runtime_code_guard") != expected_runtime:
            return False
        scans = report.get("country_scan")
        if (not isinstance(scans, Mapping) or scans.get("before") != before.get("country_scan") or
                scans.get("after") != after.get("country_scan")):
            return False
        return True
    except Exception:
        return False


def retract_record(record: Any, reason: str = "observation_retracted") -> dict[str, Any]:
    result = _unknown_record(reason)
    if isinstance(record, Mapping):
        for key in ("profile_id", "profile_sha256", "country"):
            if key in record:
                result[key] = _copy_json(record[key])
    return result


__all__ = ["PROFILE_FILE", "PROFILE_MAX_BYTES", "EXPECTED_PROFILE_SHA256", "EXPECTED_PROFILE_ID",
           "EXPECTED_EXE_SHA256", "EXPECTED_VERSION", "EXPECTED_COUNTRY", "FIELDS", "FIELD_KEY",
           "BASIS", "UNIT", "SCALE", "PERIOD", "COMPLETE", "MAX_SINGLE_RPM", "MAX_TOTAL_RPM",
           "DIRECTION", "VALUE_ORIGIN",
           "READ_BUDGET_BYTES", "MAX_RIVALS", "ProfileError", "ReadError", "ProbeError",
           "AddressBoundedRPM", "read_fields", "capture", "validate_record", "validate_capture",
           "retract_record", "_load_profile", "_prepare_profile", "_profile_layout",
           "_profile_code_guards", "_static_contract_guard", "_file_code_guard", "_runtime_code_guard",
           "_ReadBudget", "_find_country", "_snapshot", "_read_rivals", "_trace_index",
           "_trace_raw", "_validate_country_scan"]
