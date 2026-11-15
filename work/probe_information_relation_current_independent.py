"""Independent raw probe for the current relation pair/network.

This file deliberately does not import ``relation_memory`` or its profile.
Only the already audited process-installation/identity seams from
``localization_memory`` are reused.  All relation layout constants and code
guards are pinned here to source-002/contract-003, and every RPM request is
precharged before dispatch.
"""
from __future__ import annotations

import argparse
import ctypes as C
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence

from bridge.information import localization_memory as _base
from bridge.information import mission_memory as _mission


VERSION = "1.37.4"
EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = 0x140000000
SOURCE002_SHA256 = "31b786d242753f8849e0f2efee483d429a4a801eae0b6ef25d17245d5a5d3d41"
CONTRACT003_SHA256 = "3f95459d1be842cd8ed2c8e200c9ca2d1de4605a2c093484737c976290cccb73"
ACTOR = "FRA"
FAMILIES = ("alliance", "royal_marriage")
MAX_USER_ADDRESS = _mission.MAX_USER_ADDRESS
MAX_SINGLE_RPM = 65_536
PAIR_TOTAL_RPM = 512 * 1024
NETWORK_TOTAL_RPM = 2 * 1024 * 1024
MAX_COUNTRIES = 4096
MAX_VECTOR_COUNT = 4096

DATABASE_RVA = 0x233D8B0
GAME_RVA = 0x233FE58
GAME_DATE_OFFSET = 0x1DD0
COUNTRY_TABLE_OFFSET = 0x118
COUNTRY_COUNT_OFFSET = 0x124
COUNTRY_FULLREF_OFFSET = 0x20
RELATION_TABLE_OFFSET = 0x1510
RELATION_ROW_STRIDE = 0x48
RELATION_ROW_OWNER_OFFSET = 0x0
RELATION_ROW_RECIPIENT_OFFSET = 0x10
ELEMENT_STRIDE = 0x10
NULL_COUNTRY_FULLREF_RAW_HEX = "2d2d2d0000000000"

FAMILY_LAYOUT = {
    "alliance": {"selector": 0x293D, "selector_case_rva": 0x35A9E3, "call_rva": 0x35A9E6, "leaf_rva": 0xA68BC0, "begin_offset": 0x80, "count_offset": 0x8C},
    "royal_marriage": {"selector": 0x28DF, "selector_case_rva": 0x35AC11, "call_rva": 0x35AC14, "leaf_rva": 0xA68A10, "begin_offset": 0x68, "count_offset": 0x74},
}
CODE_GUARDS = (
    ("alliance_selector_case", 0x35A9E3, bytes.fromhex("488bcee8d5e170000fb6f84032fde96d140000")),
    ("royal_marriage_selector_case", 0x35AC11, bytes.fromhex("488bcee8f7dd70000fb6f84032fde93f120000")),
    ("alliance_membership_leaf", 0xA68BC0, bytes.fromhex("488b01488b511048c1ea20488b88800000004c63808c00000049c1e0044c03c10fbfc2493bc87410390174094883c110493bc875f3493bc80f95c0c3")),
    ("royal_marriage_membership_leaf", 0xA68A10, bytes.fromhex("488b01488b511048c1ea20488b48684c63407449c1e0044c03c10fbfc2493bc87410390174094883c110493bc875f3493bc80f95c0c3")),
)


class IndependentProbeError(RuntimeError):
    pass


class PrechargedRPM:
    """Minimal read-only Win32 RPM seam with a persistent local budget."""

    def __init__(self, kernel: Any, handle: Any, module_base: int, limit: int):
        self.kernel = kernel
        self.handle = handle
        self.module_base = module_base
        self.limit = limit
        self.reserved = 0
        self.calls = 0
        self.read_log: list[dict[str, Any]] = []

    def read(self, address: int, size: int, label: str) -> bytes:
        if not isinstance(address, int) or address < 0x10000 or address + size > MAX_USER_ADDRESS:
            raise IndependentProbeError(f"invalid_address:{label}")
        if not isinstance(size, int) or size <= 0 or size > MAX_SINGLE_RPM:
            raise IndependentProbeError(f"invalid_size:{label}")
        if self.reserved + size > self.limit:
            self.read_log.append({"label": label, "address": hex(address), "size": size, "status": "budget_rejected"})
            raise IndependentProbeError(f"RPM_TOTAL_BUDGET_EXCEEDED:{label}")
        self.reserved += size
        self.calls += 1
        entry = {"label": label, "address": hex(address), "size": size, "status": "requested"}
        self.read_log.append(entry)
        buffer = C.create_string_buffer(size)
        actual = C.c_size_t()
        try:
            ok = self.kernel.ReadProcessMemory(self.handle, C.c_void_p(address), buffer, size, C.byref(actual))
        except Exception as exc:
            entry.update(status="error", error=f"{type(exc).__name__}:{exc}")
            raise
        if not ok:
            entry.update(status="error", error="ReadProcessMemory_failed")
            raise C.WinError(C.get_last_error())
        if actual.value != size:
            entry.update(status="error", error=f"short_read:{actual.value}/{size}")
            raise IndependentProbeError(f"short_read:{label}")
        raw = buffer.raw
        entry.update(status="observed", raw_hex=raw.hex())
        return raw

    def qword(self, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(address, 8, label)
        return int.from_bytes(raw, "little"), raw

    def i32(self, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(address, 4, label)
        return int.from_bytes(raw, "little", signed=True), raw


def _addr(value: int | None, module_base: int | None = None) -> dict[str, Any] | None:
    if not isinstance(value, int):
        return None
    result = {"va": hex(value)}
    if isinstance(module_base, int) and value >= module_base:
        result["rva"] = hex(value - module_base)
    return result


def _safe_add(base: int, offset: int, label: str) -> int:
    value = base + offset
    if not isinstance(base, int) or not isinstance(offset, int) or value < 0x10000 or value >= MAX_USER_ADDRESS:
        raise IndependentProbeError(f"address_range_overflow:{label}")
    return value


def _valid_pointer(value: Any) -> bool:
    return isinstance(value, int) and 0x10000 <= value < MAX_USER_ADDRESS and value % 8 == 0


def _tag_slot(handle: int) -> tuple[str | None, int | None]:
    raw = (handle & 0xFFFFFF).to_bytes(3, "little")
    tag = raw.decode("ascii") if all(0x41 <= byte <= 0x5A or 0x30 <= byte <= 0x39 for byte in raw) else None
    return tag, (handle >> 32) & 0xFFFF


def _signed_i16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_guard(path: Path) -> dict[str, Any]:
    result = {"status": "unknown", "checks": {}, "records": [], "unknown_conditions": []}
    try:
        for name, rva, expected in CODE_GUARDS:
            actual = _base._read_pe_rva_bytes(path, rva, len(expected))
            result["records"].append({"name": name, "rva": hex(rva), "expected_hex": expected.hex(), "actual_hex": actual.hex()})
            result["checks"][name] = actual == expected
        result["status"] = "observed" if all(result["checks"].values()) else "mismatch"
    except Exception as exc:
        result["unknown_conditions"].append(f"{type(exc).__name__}:{exc}")
    return result


def _runtime_guard(reader: PrechargedRPM, module_base: int) -> dict[str, Any]:
    result = {"status": "unknown", "checks": {}, "records": [], "module_base": _addr(module_base)}
    try:
        for name, rva, expected in CODE_GUARDS:
            actual = reader.read(_safe_add(module_base, rva, f"code_guard.{name}"), len(expected), f"code_guard.{name}")
            result["records"].append({"name": name, "rva": hex(rva), "address": _addr(module_base + rva, module_base), "expected_hex": expected.hex(), "actual_hex": actual.hex()})
            result["checks"][name] = actual == expected
        result["status"] = "observed" if all(result["checks"].values()) else "mismatch"
    except Exception as exc:
        result.setdefault("unknown_conditions", []).append(f"{type(exc).__name__}:{exc}")
    return result


def _country_context(reader: PrechargedRPM, module_base: int, recipient: str | None = None) -> dict[str, Any]:
    db_address = _safe_add(module_base, DATABASE_RVA, "global.database")
    database, db_raw = reader.qword(db_address, "global.database")
    game_address = _safe_add(module_base, GAME_RVA, "global.game")
    game, game_raw = reader.qword(game_address, "global.game")
    result = {"status": "unknown", "database": {"address": _addr(db_address, module_base), "raw_hex": db_raw.hex(), "value": database}, "game": {"address": _addr(game_address, module_base), "raw_hex": game_raw.hex(), "value": game}, "game_date": None, "entries": [], "matches": {}, "candidate_failures": [], "unknown_conditions": []}
    if not _valid_pointer(database) or not _valid_pointer(game):
        result["unknown_conditions"].append("game_or_database_pointer_invalid")
        return result
    date_address = _safe_add(game, GAME_DATE_OFFSET, "game.date")
    date, date_raw = reader.i32(date_address, "game.raw_date")
    result["game_date"] = {"address": _addr(date_address, module_base), "raw_hex": date_raw.hex(), "value": date}
    table_address = _safe_add(database, COUNTRY_TABLE_OFFSET, "database.country_table")
    table, table_raw = reader.qword(table_address, "database.country_table")
    count_address = _safe_add(database, COUNTRY_COUNT_OFFSET, "database.country_count")
    count, count_raw = reader.i32(count_address, "database.country_count")
    result["country_table"] = {"address": _addr(table_address, module_base), "raw_hex": table_raw.hex(), "value": table}
    result["country_count"] = {"address": _addr(count_address, module_base), "raw_hex": count_raw.hex(), "value": count}
    if not _valid_pointer(table) or count <= 0 or count > MAX_COUNTRIES:
        result["unknown_conditions"].append("country_table_or_count_invalid")
        return result
    table_raw_bytes = reader.read(table, count * 8, "country_table.entries")
    requested = [ACTOR] + ([recipient] if recipient and recipient != ACTOR else [])
    matches: dict[str, list[dict[str, Any]]] = {item: [] for item in requested}
    for index in range(count):
        pointer_raw = table_raw_bytes[index * 8:(index + 1) * 8]
        pointer = int.from_bytes(pointer_raw, "little")
        entry: dict[str, Any] = {"index": index, "pointer_raw_hex": pointer_raw.hex(), "pointer": _addr(pointer, module_base)}
        if pointer == 0:
            entry["status"] = "empty"
            result["entries"].append(entry)
            continue
        if not _valid_pointer(pointer):
            entry.update(status="unknown", reason="nonzero_country_pointer_invalid")
            result["candidate_failures"].append({"index": index, "reason": entry["reason"], "pointer_raw_hex": pointer_raw.hex()})
            result["entries"].append(entry)
            continue
        full_address = _safe_add(pointer, COUNTRY_FULLREF_OFFSET, f"country[{index}].fullref")
        fullref, full_raw = reader.qword(full_address, f"country[{index}].fullref")
        tag, slot = _tag_slot(fullref)
        entry["fullref"] = {"address": _addr(full_address, module_base), "raw_hex": full_raw.hex(), "value": fullref}
        entry.update({"tag": tag, "slot": slot})
        if full_raw.hex() == NULL_COUNTRY_FULLREF_RAW_HEX:
            entry.update(status="null_sentinel", reason="known_null_country_sentinel")
            result["entries"].append(entry)
            continue
        if tag is None or slot is None or slot != index:
            entry.update(status="unknown", reason="country_fullref_tag_or_slot_invalid")
            result["candidate_failures"].append({"index": index, "reason": entry["reason"], "fullref_raw_hex": full_raw.hex(), "tag": tag, "slot": slot})
        else:
            entry["status"] = "valid"
            if tag in matches:
                matches[tag].append(entry)
        result["entries"].append(entry)
    result["matches"] = {tag: value for tag, value in matches.items() if len(value) == 1}
    for tag in requested:
        if len(matches[tag]) != 1:
            result["unknown_conditions"].append(f"country_identity_match_count_invalid:{tag}")
    result["status"] = "observed" if not any(item.startswith("country_identity_match_count_invalid") for item in result["unknown_conditions"]) else "unknown"
    return result


def _relation_row(reader: PrechargedRPM, actor_entry: Mapping[str, Any], recipient_entry: Mapping[str, Any], module_base: int) -> dict[str, Any]:
    actor_pointer = int(actor_entry["pointer"]["va"], 0)
    recipient_fullref = int(recipient_entry["fullref"]["value"])
    slot = (recipient_fullref >> 32) & 0xFFFF
    if slot >= MAX_COUNTRIES:
        raise IndependentProbeError("recipient_slot_out_of_bound")
    table_address = _safe_add(actor_pointer, RELATION_TABLE_OFFSET, "actor.relation_table")
    table_pointer, table_raw = reader.qword(table_address, "actor.relation_table.pointer")
    if not _valid_pointer(table_pointer):
        raise IndependentProbeError("relation_table_pointer_invalid")
    row_address = _safe_add(table_pointer, slot * RELATION_ROW_STRIDE, "relation.row")
    raw = reader.read(row_address, 0x20, "relation.row.prefix")
    owner = int.from_bytes(raw[0:8], "little")
    row_fullref = int.from_bytes(raw[RELATION_ROW_RECIPIENT_OFFSET:RELATION_ROW_RECIPIENT_OFFSET + 8], "little")
    if not _valid_pointer(owner):
        raise IndependentProbeError("relation_row_owner_invalid")
    if row_fullref != recipient_fullref:
        raise IndependentProbeError("relation_row_recipient_fullref_mismatch")
    return {"address": _addr(row_address, module_base), "relation_table": {"address": _addr(table_address, module_base), "raw_hex": table_raw.hex(), "value": table_pointer}, "prefix_raw_hex": raw.hex(), "owner": _addr(owner, module_base), "owner_raw_hex": raw[:8].hex(), "recipient_fullref": {"address": _addr(row_address + RELATION_ROW_RECIPIENT_OFFSET, module_base), "raw_hex": raw[RELATION_ROW_RECIPIENT_OFFSET:RELATION_ROW_RECIPIENT_OFFSET + 8].hex(), "value": row_fullref}, "recipient_slot": slot}


def _vector(reader: PrechargedRPM, family: str, row: Mapping[str, Any], recipient_fullref: int, module_base: int) -> dict[str, Any]:
    spec = FAMILY_LAYOUT[family]
    owner = int(row["owner"]["va"], 0)
    begin_address = _safe_add(owner, spec["begin_offset"], f"{family}.vector_begin")
    count_address = _safe_add(owner, spec["count_offset"], f"{family}.vector_count")
    begin, begin_raw = reader.qword(begin_address, f"{family}.vector_begin")
    count, count_raw = reader.i32(count_address, f"{family}.vector_count")
    if count < 0 or count > MAX_VECTOR_COUNT:
        raise IndependentProbeError(f"{family}.vector_count_out_of_bound")
    if count and not _valid_pointer(begin):
        raise IndependentProbeError(f"{family}.vector_begin_invalid")
    raw_elements = reader.read(begin, count * ELEMENT_STRIDE, f"{family}.vector.elements") if count else b""
    slot = _signed_i16((recipient_fullref >> 32) & 0xFFFF)
    elements = []
    matches = []
    for index in range(count):
        chunk = raw_elements[index * 16:(index + 1) * 16]
        first = int.from_bytes(chunk[:4], "little")
        elements.append({"index": index, "address": _addr(begin + index * 16, module_base), "raw_hex": chunk.hex(), "first_dword_raw_hex": chunk[:4].hex(), "first_dword": first, "unread_tail_raw_hex": chunk[4:].hex()})
        if first == (slot & 0xFFFFFFFF):
            matches.append(index)
    return {"status": "known", "value": bool(matches), "raw": {"owner_pointer": deepcopy(row["owner"]), "owner_pointer_raw_hex": row["owner_raw_hex"], "recipient_fullref": deepcopy(row["recipient_fullref"]), "recipient_slot_signed_i16": slot, "vector_begin": {"address": _addr(begin_address, module_base), "raw_hex": begin_raw.hex(), "value": begin}, "vector_count": {"address": _addr(count_address, module_base), "raw_hex": count_raw.hex(), "value": count}, "elements": elements}, "proof": {"family": family, "selector": hex(spec["selector"]), "call_rva": hex(spec["call_rva"]), "leaf_rva": hex(spec["leaf_rva"]), "offer": False, "matching_element_indices": matches}}


def _unknown(family: str, reason: str) -> dict[str, Any]:
    return {"status": "unknown", "family": family, "value": None, "reason": reason, "raw": None, "proof": None, "partial": True, "complete": False}


def _pair_pass(reader: PrechargedRPM, module_base: int, actor: str, recipient: str, families: Sequence[str]) -> dict[str, Any]:
    guard = _runtime_guard(reader, module_base)
    result = {"status": "unknown", "runtime_code_guard": guard, "context": None, "relation_row": None, "fields": {family: _unknown(family, "not_read") for family in families}, "unknown_conditions": [], "read_budget": None, "read_log": None, "complete": False}
    if guard.get("status") != "observed":
        result["unknown_conditions"].append("runtime_code_guard_not_observed")
        return result
    context = _country_context(reader, module_base, recipient)
    result["context"] = context
    if context.get("status") != "observed":
        result["unknown_conditions"].extend(context.get("unknown_conditions", []))
        return result
    actor_matches = context.get("matches", {}).get(actor, [])
    recipient_matches = context.get("matches", {}).get(recipient, [])
    if len(actor_matches) != 1 or len(recipient_matches) != 1:
        result["unknown_conditions"].append("actor_or_recipient_identity_invalid")
        return result
    row = _relation_row(reader, actor_matches[0], recipient_matches[0], module_base)
    result["relation_row"] = row
    for family in families:
        try:
            result["fields"][family] = _vector(reader, family, row, int(recipient_matches[0]["fullref"]["value"]), module_base)
        except Exception as exc:
            result["fields"][family] = _unknown(family, f"{type(exc).__name__}:{exc}")
    result["status"] = "observed"
    result["complete"] = all(field.get("status") == "known" for field in result["fields"].values())
    return result


def _network_pass(reader: PrechargedRPM, module_base: int, actor: str, families: Sequence[str]) -> dict[str, Any]:
    guard = _runtime_guard(reader, module_base)
    result = {"status": "unknown", "runtime_code_guard": guard, "context": None, "targets": [], "owner_cache": {}, "fields": {}, "candidate_failures": [], "unknown_conditions": [], "read_budget": None, "read_log": None, "complete": False}
    if guard.get("status") != "observed":
        result["unknown_conditions"].append("runtime_code_guard_not_observed")
        return result
    context = _country_context(reader, module_base)
    result["context"] = context
    if context.get("status") != "observed":
        result["unknown_conditions"].extend(context.get("unknown_conditions", []))
        return result
    result["candidate_failures"] = deepcopy(context.get("candidate_failures", []))
    actor_matches = context.get("matches", {}).get(actor, [])
    if len(actor_matches) != 1:
        result["unknown_conditions"].append("actor_identity_invalid")
        return result
    actor_index = actor_matches[0]["index"]
    valid_targets = []
    for entry in context.get("entries", []):
        if entry.get("status") != "valid":
            if entry.get("status") in {"unknown", "null_sentinel"}:
                continue
            continue
        if entry["index"] == actor_index:
            continue
        valid_targets.append({"index": entry["index"], "country": entry["tag"], "country_pointer": deepcopy(entry["pointer"]), "fullref": entry["fullref"]["value"], "fullref_hex": entry["fullref"]["raw_hex"], "slot": entry["slot"]})
    result["targets"] = valid_targets
    cache: dict[str, dict[str, Any]] = {}
    for target in valid_targets:
        target_entry = {"pointer": target["country_pointer"], "fullref": {"value": target["fullref"], "raw_hex": target["fullref_hex"]}}
        try:
            target["relation_row"] = _relation_row(reader, actor_matches[0], target_entry, module_base)
            target["row_status"] = "observed"
        except Exception as exc:
            target["row_status"] = "unknown"
            target["row_reason"] = f"{type(exc).__name__}:{exc}"
            result["candidate_failures"].append({"index": target["index"], "country": target["country"], "reason": target["row_reason"]})
    for family in families:
        rows = []
        active = []
        unknown = []
        for target in valid_targets:
            row_out = {"country": target["country"], "fullref_hex": target["fullref_hex"], "slot": target["slot"], "relation_row": deepcopy(target.get("relation_row")), "status": "unknown", "active": None, "predicate_cache_key": None}
            try:
                if target.get("row_status") != "observed":
                    raise IndependentProbeError(target.get("row_reason", "relation_row_unknown"))
                row = target["relation_row"]
                owner = int(row["owner"]["va"], 0)
                key = f"{owner:#x}:{family}"
                if key not in cache:
                    copied = _vector(reader, family, row, target["fullref"], module_base)
                    copied["raw"].pop("recipient_fullref", None)
                    copied["raw"].pop("recipient_slot_signed_i16", None)
                    copied["value"] = None
                    copied["proof"]["matching_element_indices"] = []
                    cache[key] = copied
                expected = _signed_i16((target["fullref"] >> 32) & 0xFFFF)
                elements = cache[key]["raw"]["elements"]
                matches = [item["index"] for item in elements if item["first_dword"] == (expected & 0xFFFFFFFF)]
                row_out.update(status="known", active=bool(matches), predicate_cache_key=key, predicate={"matching_element_indices": matches, "value": bool(matches)})
                if row_out["active"]:
                    active.append({"country": target["country"], "fullref_hex": target["fullref_hex"], "slot": target["slot"], "active": True})
            except Exception as exc:
                row_out.update(status="unknown", reason=f"{type(exc).__name__}:{exc}")
                unknown.append({"country": target["country"], "fullref_hex": target["fullref_hex"], "slot": target["slot"], "reason": row_out["reason"]})
            rows.append(row_out)
        status = "known" if not unknown and not result["candidate_failures"] else "partial"
        result["fields"][family] = {"status": status, "family": family, "value": active, "rows": rows, "unknown_rows": unknown, "candidate_failures": deepcopy(result["candidate_failures"]), "candidate_count": len(valid_targets), "partial": True, "complete": False, "unit": "relation_state", "scale": 1, "period": "current"}
    result["owner_cache"] = cache
    result["status"] = "observed"
    result["complete"] = all(field.get("status") == "known" for field in result["fields"].values())
    return result


def _strip_volatile(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _strip_volatile(item) for key, item in value.items() if key not in {"read_budget", "read_log"}}
    if isinstance(value, list):
        return [_strip_volatile(item) for item in value]
    return value


def _base_report(installation: Path, actor: str, recipient: str | None, families: Sequence[str], mode: str) -> dict[str, Any]:
    return {"schema": "information_relation_independent_raw.v1", "probe": "information-relation-current-independent", "probe_version": 1, "independent": True, "production_reader_imported": False, "profile_imported": False, "read_only": True, "evidence_kind": "independent_raw_runtime_observation", "source_pins": {"source002_sha256": SOURCE002_SHA256, "contract003_sha256": CONTRACT003_SHA256, "executable_sha256": EXE_SHA256}, "request": {"installation": str(installation), "actor": actor, "recipient": recipient, "families": list(families), "mode": mode}, "target_build": {"version": VERSION, "expected_exe_sha256": EXE_SHA256, "image_base": hex(IMAGE_BASE)}, "identity": {"installation_path": str(installation), "installation_pid": None, "installation_creation_filetime": None, "installation_session_id": None, "process_path": None, "process_path_sha256": None, "process_path_sha256_matches_expected": None, "process_creation_filetime": None, "process_creation_utc": None, "process_creation_matches_installation": None, "module_path": None, "module_path_matches_process": None, "binding_verified": False}, "module_base": None, "static_contract_guard": {"status": "observed", "source_pins": {"source002_sha256": SOURCE002_SHA256, "contract003_sha256": CONTRACT003_SHA256}}, "file_code_guard": None, "runtime_code_guard": None, "before": None, "after": None, "fields": {family: {"status": "unknown", "value": None} for family in families}, "context_before": None, "context_after": None, "doublepass": {"performed": False, "consistent": None, "mismatches": []}, "access": {"native_game_calls": False, "target_memory_writes": False, "open_process_mask": "QUERY_INFORMATION|VM_READ", "rpm_total_limit": NETWORK_TOTAL_RPM if mode == "network" else PAIR_TOTAL_RPM, "rpm_single_read_limit": MAX_SINGLE_RPM, "rpm_bytes_requested": 0, "rpm_calls": 0}, "cleanup": {"handle_close": {"status": "unknown", "success": None, "closed": False}}, "status": "starting", "completed": False, "errors": []}


def capture_raw(installation: Path, actor: str, recipient: str | None, families: Sequence[str], mode: str) -> dict[str, Any]:
    installation = Path(installation)
    report = _base_report(installation, actor, recipient, families, mode)
    if actor != ACTOR or any(family not in FAMILIES for family in families) or len(set(families)) != len(families) or not families:
        report.update(status="unsupported_request", completed=True)
        report["errors"].append({"stage": "request", "error": "actor/family request invalid"})
        report["cleanup"]["handle_close"] = {"status": "not_opened", "success": None, "closed": False}
        return report
    if mode == "pair" and (not isinstance(recipient, str) or not re.fullmatch(r"[A-Z0-9]{3}", recipient) or recipient == actor):
        report.update(status="unsupported_request", completed=True)
        report["errors"].append({"stage": "request", "error": "pair recipient invalid"})
        report["cleanup"]["handle_close"] = {"status": "not_opened", "success": None, "closed": False}
        return report
    kernel = handle = reader = None
    try:
        report["probe_script_sha256"] = _sha256_file(Path(__file__).resolve())
        document = _base._load_installation(installation)
        kernel = _base._configure_kernel()
        handle = kernel.OpenProcess(_base.PROCESS_ACCESS, False, int(document["pid"]))
        if not handle:
            raise IndependentProbeError("OpenProcess_failed")
        module_base = _base._capture_identity(report, document, kernel, handle)
        if report["identity"].get("binding_verified") is not True or not _valid_pointer(module_base):
            raise IndependentProbeError("identity_binding_not_verified")
        report["module_base"] = _addr(module_base)
        report["file_code_guard"] = _file_guard(Path(report["identity"]["process_path"]))
        if report["file_code_guard"].get("status") != "observed":
            raise IndependentProbeError("file_code_guard_mismatch")
        limit = NETWORK_TOTAL_RPM if mode == "network" else PAIR_TOTAL_RPM
        reader = PrechargedRPM(kernel, handle, module_base, limit)
        budget_before = len(reader.read_log)
        first = _network_pass(reader, module_base, actor, families) if mode == "network" else _pair_pass(reader, module_base, actor, recipient or "", families)
        first["read_budget"] = {"bytes_reserved": reader.reserved, "calls_reserved": reader.calls, "limit": limit}
        first["read_log"] = deepcopy(reader.read_log[budget_before:])
        report["before"] = first
        report["context_before"] = deepcopy(first.get("context"))
        if first.get("status") == "observed":
            start = len(reader.read_log)
            second = _network_pass(reader, module_base, actor, families) if mode == "network" else _pair_pass(reader, module_base, actor, recipient or "", families)
            second["read_budget"] = {"bytes_reserved": reader.reserved, "calls_reserved": reader.calls, "limit": limit}
            second["read_log"] = deepcopy(reader.read_log[start:])
            report["after"] = second
            report["context_after"] = deepcopy(second.get("context"))
            report["doublepass"]["performed"] = True
            left = _strip_volatile(first)
            right = _strip_volatile(second)
            report["doublepass"]["mismatches"] = _diff_paths(left, right)[:256]
            report["doublepass"]["consistent"] = not report["doublepass"]["mismatches"]
            if report["doublepass"]["consistent"]:
                report["status"] = "observed"
                report["fields"] = deepcopy(second.get("fields", {}))
                if mode == "network":
                    report["owner_cache"] = deepcopy(second.get("owner_cache", {}))
            else:
                report["status"] = "doublepass_mismatch"
        else:
            report["status"] = "unknown"
        before_guard = (report.get("before") or {}).get("runtime_code_guard", {})
        after_guard = (report.get("after") or {}).get("runtime_code_guard", {})
        report["runtime_code_guard"] = {"status": "observed" if before_guard.get("status") == "observed" and after_guard.get("status") == "observed" else "unknown", "passes": [before_guard, after_guard]}
        report["access"]["rpm_bytes_requested"] = reader.reserved
        report["access"]["rpm_calls"] = reader.calls
    except Exception as exc:
        report["status"] = "error"
        report["errors"].append({"stage": "capture", "error": f"{type(exc).__name__}:{exc}"})
    finally:
        if reader is not None:
            report["access"]["rpm_bytes_requested"] = reader.reserved
            report["access"]["rpm_calls"] = reader.calls
    report["cleanup"]["handle_close"] = _base._close_process_handle(kernel, handle)
    report["completed"] = report["status"] == "observed" and report["cleanup"]["handle_close"].get("closed") is True
    return report


def _diff_paths(left: Any, right: Any, prefix: str = "$") -> list[str]:
    if type(left) is not type(right):
        return [prefix]
    if isinstance(left, Mapping):
        result = []
        for key in sorted(set(left) | set(right), key=str):
            if key not in left or key not in right:
                result.append(f"{prefix}.{key}")
            else:
                result.extend(_diff_paths(left[key], right[key], f"{prefix}.{key}"))
        return result
    if isinstance(left, list):
        result = []
        for index in range(max(len(left), len(right))):
            if index >= len(left) or index >= len(right):
                result.append(f"{prefix}[{index}]")
            else:
                result.extend(_diff_paths(left[index], right[index], f"{prefix}[{index}]"))
        return result
    return [] if left == right else [prefix]


def probe(installation: Path, actor: str = "FRA", recipient: str | None = None, families: Sequence[str] | None = None, network: bool = False) -> dict[str, Any]:
    selected = list(FAMILIES if families is None else families)
    return capture_raw(installation, actor, None if network else recipient, selected, "network" if network else "pair")


def _write_once(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"output_exists:{path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Independent raw bounded probe for current relation pair/network")
    parser.add_argument("--installation", required=True, type=Path)
    parser.add_argument("--actor", default="FRA")
    parser.add_argument("--recipient")
    parser.add_argument("--network", action="store_true")
    parser.add_argument("--families", default="alliance,royal_marriage")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    if not args.network and not args.recipient:
        parser.error("--recipient is required unless --network is selected")
    try:
        payload = probe(args.installation, args.actor, args.recipient, [item.strip() for item in args.families.split(",") if item.strip()], args.network)
        _write_once(args.output, payload)
    except (OSError, ValueError, IndependentProbeError) as exc:
        print(f"independent_relation_probe_error:{exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": payload.get("status"), "completed": payload.get("completed"), "doublepass": payload.get("doublepass"), "output": str(args.output)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
