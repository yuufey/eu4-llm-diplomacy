"""Independent bounded raw probe for current fleet-basing predicates.

The probe deliberately does not import a production reader or profile. It
reuses only the audited installation, identity, handle, and Win32 RPM seams
from ``localization_memory`` plus the user-address bound from
``mission_memory``. It copies the country table, relation rows, and the two
owner vectors, then applies the bounded native comparisons described by
fleet-basing-current-source-002. It does not infer grantor/recipient roles,
expiry, or a complete current fleet-basing container.

No process is opened unless the CLI receives the explicit ``--run`` switch.
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

# Direct ``python work/<script>.py`` execution sets sys.path[0] to ``work``;
# make the repository-local audited seams importable without requiring an
# environment-wide PYTHONPATH.
_WORKSPACE = Path(__file__).resolve().parents[1]
if str(_WORKSPACE) not in sys.path:
    sys.path.insert(0, str(_WORKSPACE))

from bridge.information import localization_memory as _base
from bridge.information import mission_memory as _mission


VERSION = "1.37.4"
EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = 0x140000000
FLEET_SOURCE002_SHA256 = "90dc23321e41458e13875d5a74ba85f0845214897da77ce546aed96ab1a7ce04"
RELATION_CONTRACT003_SHA256 = "3f95459d1be842cd8ed2c8e200c9ca2d1de4605a2c093484737c976290cccb73"
DEFAULT_ACTOR = "FRA"
FAMILIES = ("received", "granted")

MAX_USER_ADDRESS = _mission.MAX_USER_ADDRESS
MAX_SINGLE_RPM = 65_536
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
NULL_COUNTRY_FULLREF_RAW_HEX = "2d2d2d0000000000"

FAMILY_LAYOUT: dict[str, dict[str, Any]] = {
    "received": {
        "begin_offset": 0xE0,
        "count_offset": 0xEC,
        "element_stride": 0x10,
        "predicate_rva": 0x52FC20,
        "agreement_pointer_offset": 0x08,
        "agreement_ref_offset": 0x18,
    },
    "granted": {
        "begin_offset": 0xF8,
        "count_offset": 0x104,
        "element_stride": 0x10,
        "predicate_rva": 0x533FD0,
    },
}

# These two audited token leaves provide a small file/runtime guard without
# pretending that the unresolved predicate callees are closed.
CODE_GUARDS = (
    ("fleet_access_token_leaf", 0x5302B0, bytes.fromhex("b8d62d0000c3")),
    ("offer_fleet_access_token_leaf", 0x534690, bytes.fromhex("b8d72d0000c3")),
)


class IndependentProbeError(RuntimeError):
    """A bounded read or identity contract could not be satisfied."""


class PrechargedRPM:
    """Win32 read-only RPM seam with pre-dispatch accounting."""

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
    result: dict[str, Any] = {"va": hex(value)}
    if isinstance(module_base, int) and value >= module_base:
        result["rva"] = hex(value - module_base)
    return result


def _valid_pointer(value: Any) -> bool:
    return isinstance(value, int) and 0x10000 <= value < MAX_USER_ADDRESS and value % 8 == 0


def _safe_add(base: int, offset: int, label: str) -> int:
    value = base + offset
    if not isinstance(base, int) or not isinstance(offset, int) or value < 0x10000 or value >= MAX_USER_ADDRESS:
        raise IndependentProbeError(f"address_range_overflow:{label}")
    return value


def _tag_slot(fullref: int) -> tuple[str | None, int | None]:
    raw = (fullref & 0xFFFFFF).to_bytes(3, "little")
    tag = raw.decode("ascii") if all(0x41 <= byte <= 0x5A or 0x30 <= byte <= 0x39 for byte in raw) else None
    return tag, (fullref >> 32) & 0xFFFF


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


def _country_context(reader: PrechargedRPM, module_base: int) -> dict[str, Any]:
    db_address = _safe_add(module_base, DATABASE_RVA, "global.database")
    database, db_raw = reader.qword(db_address, "global.database")
    game_address = _safe_add(module_base, GAME_RVA, "global.game")
    game, game_raw = reader.qword(game_address, "global.game")
    result: dict[str, Any] = {"status": "unknown", "database": {"address": _addr(db_address, module_base), "raw_hex": db_raw.hex(), "value": database}, "game": {"address": _addr(game_address, module_base), "raw_hex": game_raw.hex(), "value": game}, "game_date": None, "country_table": None, "country_count": None, "entries": [], "matches": {}, "candidate_failures": [], "unknown_conditions": []}
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
    valid_by_tag: dict[str, list[dict[str, Any]]] = {}
    entries: list[dict[str, Any]] = []
    for index in range(count):
        pointer_raw = table_raw_bytes[index * 8:(index + 1) * 8]
        pointer = int.from_bytes(pointer_raw, "little")
        entry: dict[str, Any] = {"index": index, "pointer_raw_hex": pointer_raw.hex(), "pointer": _addr(pointer, module_base)}
        if pointer == 0:
            entry["status"] = "empty"
            entries.append(entry)
            continue
        if not _valid_pointer(pointer):
            entry.update(status="unknown", reason="nonzero_country_pointer_invalid")
            result["candidate_failures"].append({"index": index, "reason": entry["reason"], "pointer_raw_hex": pointer_raw.hex()})
            entries.append(entry)
            continue
        full_address = _safe_add(pointer, COUNTRY_FULLREF_OFFSET, f"country[{index}].fullref")
        fullref, full_raw = reader.qword(full_address, f"country[{index}].fullref")
        tag, slot = _tag_slot(fullref)
        entry["fullref"] = {"address": _addr(full_address, module_base), "raw_hex": full_raw.hex(), "value": fullref}
        entry.update({"tag": tag, "slot": slot})
        if full_raw.hex() == NULL_COUNTRY_FULLREF_RAW_HEX:
            entry.update(status="null_sentinel", reason="known_null_country_sentinel")
            entries.append(entry)
            continue
        if tag is None or slot is None or slot != index:
            entry.update(status="unknown", reason="country_fullref_tag_or_slot_invalid")
            result["candidate_failures"].append({"index": index, "reason": entry["reason"], "fullref_raw_hex": full_raw.hex(), "tag": tag, "slot": slot})
        else:
            entry["status"] = "valid"
            valid_by_tag.setdefault(tag, []).append(entry)
        entries.append(entry)
    result["entries"] = entries
    result["matches"] = {tag: value for tag, value in valid_by_tag.items() if len(value) == 1}
    result["scanned_entries"] = count
    result["status"] = "observed"
    return result


def _relation_row(reader: PrechargedRPM, actor_entry: Mapping[str, Any], target_entry: Mapping[str, Any], module_base: int) -> dict[str, Any]:
    actor_pointer = int(actor_entry["pointer"]["va"], 0)
    recipient_fullref = int(target_entry["fullref"]["value"])
    slot = (recipient_fullref >> 32) & 0xFFFF
    if slot >= MAX_COUNTRIES:
        raise IndependentProbeError("recipient_slot_out_of_bound")
    table_address = _safe_add(actor_pointer, RELATION_TABLE_OFFSET, "actor.relation_table")
    table_pointer, table_raw = reader.qword(table_address, "actor.relation_table.pointer")
    if not _valid_pointer(table_pointer):
        raise IndependentProbeError("relation_table_pointer_invalid")
    row_address = _safe_add(table_pointer, slot * RELATION_ROW_STRIDE, "relation.row")
    raw = reader.read(row_address, 0x20, "relation.row.prefix")
    owner = int.from_bytes(raw[RELATION_ROW_OWNER_OFFSET:RELATION_ROW_OWNER_OFFSET + 8], "little")
    row_fullref = int.from_bytes(raw[RELATION_ROW_RECIPIENT_OFFSET:RELATION_ROW_RECIPIENT_OFFSET + 8], "little")
    if not _valid_pointer(owner):
        raise IndependentProbeError("relation_row_owner_invalid")
    if row_fullref != recipient_fullref:
        raise IndependentProbeError("relation_row_recipient_fullref_mismatch")
    return {"address": _addr(row_address, module_base), "relation_table": {"address": _addr(table_address, module_base), "raw_hex": table_raw.hex(), "value": table_pointer}, "prefix_raw_hex": raw.hex(), "owner": _addr(owner, module_base), "owner_raw_hex": raw[:8].hex(), "recipient_fullref": {"address": _addr(row_address + RELATION_ROW_RECIPIENT_OFFSET, module_base), "raw_hex": raw[RELATION_ROW_RECIPIENT_OFFSET:RELATION_ROW_RECIPIENT_OFFSET + 8].hex(), "value": row_fullref}, "recipient_slot": slot, "row_stride": RELATION_ROW_STRIDE}


def _vector_snapshot(reader: PrechargedRPM, family: str, row: Mapping[str, Any], module_base: int) -> dict[str, Any]:
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
    size = count * 0x10
    raw_elements = reader.read(begin, size, f"{family}.vector.elements") if count else b""
    elements: list[dict[str, Any]] = []
    for index in range(count):
        chunk = raw_elements[index * 16:(index + 1) * 16]
        elements.append({"index": index, "address": _addr(begin + index * 16, module_base), "raw_hex": chunk.hex(), "first_dword_raw_hex": chunk[:4].hex(), "first_dword": int.from_bytes(chunk[:4], "little"), "unread_tail_raw_hex": chunk[4:].hex()})
    return {"status": "known", "raw": {"owner_pointer": deepcopy(row["owner"]), "owner_pointer_raw_hex": row["owner_raw_hex"], "vector_begin": {"address": _addr(begin_address, module_base), "raw_hex": begin_raw.hex(), "value": begin}, "vector_count": {"address": _addr(count_address, module_base), "raw_hex": count_raw.hex(), "value": count}, "element_stride": 0x10, "elements": elements}, "proof": {"family": family, "predicate_rva": hex(spec["predicate_rva"]), "unread_element_bytes": "+0x4..+0xf_unread_by_direct_leaf"}}


def _project_granted(cached: Mapping[str, Any], recipient_fullref: int) -> dict[str, Any]:
    raw = cached.get("raw")
    if not isinstance(raw, Mapping) or not isinstance(raw.get("elements"), list):
        raise IndependentProbeError("granted_vector_cache_shape_invalid")
    expected = _signed_i16((recipient_fullref >> 32) & 0xFFFF)
    matches = [item["index"] for item in raw["elements"] if isinstance(item, Mapping) and item.get("first_dword") == (expected & 0xFFFFFFFF)]
    return {"value": bool(matches), "proof": {"matching_element_indices": matches, "comparison_slot_signed_i16": expected, "native_leaf_al": bool(matches)}}


def _project_received(reader: PrechargedRPM, cached: Mapping[str, Any], recipient_fullref: int, module_base: int) -> dict[str, Any]:
    raw = cached.get("raw")
    if not isinstance(raw, Mapping) or not isinstance(raw.get("elements"), list):
        raise IndependentProbeError("received_vector_cache_shape_invalid")
    expected = _signed_i16((recipient_fullref >> 32) & 0xFFFF)
    first_index = next((item["index"] for item in raw["elements"] if isinstance(item, Mapping) and item.get("first_dword") == (expected & 0xFFFFFFFF)), None)
    proof: dict[str, Any] = {"comparison_slot_signed_i16": expected, "first_matching_element_index": first_index, "native_leaf_al": False}
    if first_index is None:
        return {"value": False, "proof": proof}
    element = raw["elements"][first_index]
    pointer_raw = bytes.fromhex(element["raw_hex"])[8:16]
    agreement_pointer = int.from_bytes(pointer_raw, "little")
    proof["agreement_pointer"] = _addr(agreement_pointer, module_base)
    proof["agreement_pointer_raw_hex"] = pointer_raw.hex()
    if agreement_pointer == 0:
        proof["agreement_status"] = "null"
        return {"value": False, "proof": proof}
    if not _valid_pointer(agreement_pointer):
        raise IndependentProbeError("received_agreement_pointer_invalid")
    agreement_address = _safe_add(agreement_pointer, 0x18, "received.agreement_ref")
    agreement_ref, agreement_raw = reader.qword(agreement_address, "received.agreement_ref")
    agreement_slot = _signed_i16((agreement_ref >> 32) & 0xFFFF)
    proof.update({"agreement_ref": {"address": _addr(agreement_address, module_base), "raw_hex": agreement_raw.hex(), "value": agreement_ref}, "agreement_slot_signed_i16": agreement_slot, "agreement_status": "observed", "native_leaf_al": agreement_slot == expected})
    return {"value": agreement_slot == expected, "proof": proof}


def _unknown(family: str, reason: str) -> dict[str, Any]:
    return {"status": "unknown", "family": family, "value": None, "reason": reason, "partial": True, "complete": False, "unit": "relation_state", "scale": 1, "period": "current"}


def _network_pass(reader: PrechargedRPM, module_base: int, actor: str, families: Sequence[str]) -> dict[str, Any]:
    guard = _runtime_guard(reader, module_base)
    result: dict[str, Any] = {"status": "unknown", "runtime_code_guard": guard, "context": None, "targets": [], "owner_cache": {}, "fields": {family: _unknown(family, "not_read") for family in families}, "candidate_failures": [], "unknown_conditions": [], "complete": False}
    if guard.get("status") != "observed":
        result["unknown_conditions"].append("runtime_code_guard_not_observed")
        return result
    context = _country_context(reader, module_base)
    result["context"] = context
    if context.get("status") != "observed":
        result["unknown_conditions"].extend(context.get("unknown_conditions", []))
        return result
    actor_matches = context.get("matches", {}).get(actor, [])
    if len(actor_matches) != 1:
        result["unknown_conditions"].append("actor_identity_invalid")
        return result
    result["candidate_failures"] = deepcopy(context.get("candidate_failures", []))
    actor_entry = actor_matches[0]
    actor_index = actor_entry["index"]
    targets: list[dict[str, Any]] = []
    for entry in context.get("entries", []):
        if not isinstance(entry, Mapping) or entry.get("status") in {"empty", "null_sentinel", "unknown"} or entry.get("index") == actor_index:
            continue
        targets.append({"index": entry["index"], "country": entry["tag"], "country_pointer": deepcopy(entry["pointer"]), "fullref": entry["fullref"]["value"], "fullref_hex": entry["fullref"]["raw_hex"], "slot": entry["slot"]})
    result["targets"] = targets
    for target in targets:
        try:
            target["relation_row"] = _relation_row(reader, actor_entry, {"pointer": target["country_pointer"], "fullref": {"value": target["fullref"], "raw_hex": target["fullref_hex"]}}, module_base)
            target["row_status"] = "observed"
        except Exception as exc:
            target["row_status"] = "unknown"
            target["row_reason"] = f"{type(exc).__name__}:{exc}"
            result["candidate_failures"].append({"index": target["index"], "country": target["country"], "reason": target["row_reason"]})
    cache: dict[str, dict[str, Any]] = {}
    for family in families:
        rows: list[dict[str, Any]] = []
        active: list[dict[str, Any]] = []
        unknown: list[dict[str, Any]] = []
        for target in targets:
            row_out: dict[str, Any] = {"index": target["index"], "country": target["country"], "fullref_hex": target["fullref_hex"], "slot": target["slot"], "relation_row": deepcopy(target.get("relation_row")), "status": "unknown", "active": None, "predicate_cache_key": None}
            try:
                if target.get("row_status") != "observed":
                    raise IndependentProbeError(target.get("row_reason", "relation_row_unknown"))
                row = target["relation_row"]
                owner = int(row["owner"]["va"], 0)
                cache_key = f"{owner:#x}:{family}"
                row_out["predicate_cache_key"] = cache_key
                cached = cache.get(cache_key)
                if cached is None:
                    try:
                        cached = _vector_snapshot(reader, family, row, module_base)
                    except Exception as exc:
                        cached = {"status": "unknown", "reason": f"{type(exc).__name__}:{exc}"}
                    cache[cache_key] = cached
                if cached.get("status") != "known":
                    raise IndependentProbeError(str(cached.get("reason", "owner_vector_unknown")))
                projected = _project_received(reader, cached, target["fullref"], module_base) if family == "received" else _project_granted(cached, target["fullref"])
                row_out.update(status="known", active=bool(projected["value"]), predicate=projected["proof"])
                if row_out["active"]:
                    active.append({"country": target["country"], "fullref_hex": target["fullref_hex"], "slot": target["slot"], "active": True})
            except Exception as exc:
                row_out.update(status="unknown", active=None, reason=f"{type(exc).__name__}:{exc}")
                unknown.append({"index": target["index"], "country": target["country"], "fullref_hex": target["fullref_hex"], "slot": target["slot"], "reason": row_out["reason"]})
            rows.append(row_out)
        result["fields"][family] = {"status": "known" if not unknown and not result["candidate_failures"] else "partial", "family": family, "value": active, "rows": rows, "unknown_rows": unknown, "candidate_failures": deepcopy(result["candidate_failures"]), "candidate_count": len(targets), "partial": True, "complete": False, "unit": "relation_state", "scale": 1, "period": "current", "basis": "native_fleet_basing_owner_vector_predicate", "value_origin": "derived_from_copied_native_vectors"}
    result["owner_cache"] = cache
    result["status"] = "observed"
    return result


def _strip_volatile(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _strip_volatile(item) for key, item in value.items() if key not in {"read_budget", "read_log"}}
    if isinstance(value, list):
        return [_strip_volatile(item) for item in value]
    return value


def _diff_paths(left: Any, right: Any, prefix: str = "$") -> list[str]:
    if type(left) is not type(right):
        return [prefix]
    if isinstance(left, Mapping):
        result: list[str] = []
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


def _base_report(installation: Path, actors: Sequence[str], families: Sequence[str]) -> dict[str, Any]:
    return {"schema": "information_fleet_basing_independent_raw.v1", "probe": "information-fleet-basing-current-independent", "probe_version": 1, "independent": True, "production_reader_imported": False, "profile_imported": False, "read_only": True, "evidence_kind": "independent_raw_runtime_observation", "source_pins": {"fleet_source002_sha256": FLEET_SOURCE002_SHA256, "relation_contract003_sha256": RELATION_CONTRACT003_SHA256, "executable_sha256": EXE_SHA256}, "request": {"installation": str(installation), "actors": list(actors), "families": list(families), "mode": "network"}, "target_build": {"version": VERSION, "expected_exe_sha256": EXE_SHA256, "image_base": hex(IMAGE_BASE)}, "identity": {"installation_path": str(installation), "installation_pid": None, "installation_creation_filetime": None, "installation_session_id": None, "process_path": None, "process_path_sha256": None, "process_path_sha256_matches_expected": None, "process_creation_filetime": None, "process_creation_utc": None, "process_creation_matches_installation": None, "module_path": None, "module_path_matches_process": None, "binding_verified": False}, "module_base": None, "static_contract_guard": {"status": "observed", "source_pins": {"fleet_source002_sha256": FLEET_SOURCE002_SHA256, "relation_contract003_sha256": RELATION_CONTRACT003_SHA256}}, "file_code_guard": None, "runtime_code_guard": None, "actors": {}, "fields": {family: {"status": "unknown", "value": None} for family in families}, "doublepass": {"performed": False, "consistent": None, "mismatches": []}, "access": {"native_game_calls": False, "target_memory_writes": False, "open_process_mask": "QUERY_INFORMATION|VM_READ", "rpm_total_limit": NETWORK_TOTAL_RPM, "rpm_single_read_limit": MAX_SINGLE_RPM, "rpm_bytes_requested": 0, "rpm_calls": 0}, "cleanup": {"handle_close": {"status": "unknown", "success": None, "closed": False}}, "status": "starting", "completed": False, "complete": False, "unknown_conditions": ["fleet-basing direction/roles and expiry are not inferred by this raw probe"], "errors": []}


def capture_raw(installation: Path, actors: Sequence[str], families: Sequence[str]) -> dict[str, Any]:
    installation = Path(installation)
    report = _base_report(installation, actors, families)
    if not actors or len(set(actors)) != len(actors) or any(not isinstance(actor, str) or not re.fullmatch(r"[A-Z0-9]{3}", actor) for actor in actors) or any(family not in FAMILIES for family in families) or len(set(families)) != len(families) or not families:
        report.update(status="unsupported_request", completed=True)
        report["errors"].append({"stage": "request", "error": "actors/family request invalid"})
        report["cleanup"]["handle_close"] = {"status": "not_opened", "success": None, "closed": False}
        return report
    kernel = handle = None
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
        for actor in actors:
            reader = PrechargedRPM(kernel, handle, module_base, NETWORK_TOTAL_RPM)
            first = _network_pass(reader, module_base, actor, families)
            first["read_budget"] = {"bytes_reserved": reader.reserved, "calls_reserved": reader.calls, "limit": NETWORK_TOTAL_RPM}
            first["read_log"] = deepcopy(reader.read_log)
            second = None
            if first.get("status") == "observed":
                start = len(reader.read_log)
                second = _network_pass(reader, module_base, actor, families)
                second["read_budget"] = {"bytes_reserved": reader.reserved, "calls_reserved": reader.calls, "limit": NETWORK_TOTAL_RPM}
                second["read_log"] = deepcopy(reader.read_log[start:])
            actor_record: dict[str, Any] = {"actor": actor, "before": first, "after": second, "context_before": deepcopy(first.get("context")), "context_after": deepcopy(second.get("context")) if isinstance(second, Mapping) else None, "doublepass": {"performed": second is not None, "consistent": False, "mismatches": []}, "access": {"rpm_bytes_requested": reader.reserved, "rpm_calls": reader.calls}}
            if isinstance(second, Mapping):
                actor_record["doublepass"]["mismatches"] = _diff_paths(_strip_volatile(first), _strip_volatile(second))[:256]
                actor_record["doublepass"]["consistent"] = not actor_record["doublepass"]["mismatches"]
            report["actors"][actor] = actor_record
            report["access"]["rpm_bytes_requested"] += reader.reserved
            report["access"]["rpm_calls"] += reader.calls
        if len(actors) == 1:
            one = report["actors"][actors[0]]
            report["before"] = one["before"]
            report["after"] = one["after"]
            report["context_before"] = one["context_before"]
            report["context_after"] = one["context_after"]
            report["doublepass"] = one["doublepass"]
            if isinstance(one.get("after"), Mapping) and one["doublepass"].get("consistent"):
                report["fields"] = deepcopy(one["after"].get("fields", {}))
        report["runtime_code_guard"] = {"status": "observed" if all((item.get("before") or {}).get("runtime_code_guard", {}).get("status") == "observed" and (item.get("after") or {}).get("runtime_code_guard", {}).get("status") == "observed" for item in report["actors"].values()) else "unknown", "passes": [{"actor": actor, "before": report["actors"][actor]["before"].get("runtime_code_guard"), "after": report["actors"][actor]["after"].get("runtime_code_guard") if isinstance(report["actors"][actor].get("after"), Mapping) else None} for actor in actors]}
        report["status"] = "observed" if all(item["doublepass"].get("consistent") is True for item in report["actors"].values()) else "doublepass_mismatch"
    except Exception as exc:
        report["status"] = "error"
        report["errors"].append({"stage": "capture", "error": f"{type(exc).__name__}:{exc}"})
    finally:
        report["cleanup"]["handle_close"] = _base._close_process_handle(kernel, handle)
    report["completed"] = report["status"] == "observed" and report["cleanup"]["handle_close"].get("closed") is True
    return report


def probe(installation: Path, actors: Sequence[str] | None = None, families: Sequence[str] | None = None) -> dict[str, Any]:
    return capture_raw(installation, list(actors or (DEFAULT_ACTOR,)), list(families or FAMILIES))


def _write_once(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"output_exists:{path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Independent bounded raw probe for current fleet-basing predicates")
    parser.add_argument("--run", action="store_true", help="explicitly permit installation/VM_READ capture")
    parser.add_argument("--installation", type=Path)
    parser.add_argument("--actors", default=DEFAULT_ACTOR, help="comma-separated country tags; default FRA")
    parser.add_argument("--families", default="received,granted")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if not args.run:
        print(json.dumps({"status": "inert", "run_required": True, "native_game_calls": False, "target_memory_writes": False}, ensure_ascii=False))
        return 0
    if args.installation is None or args.output is None:
        parser.error("--run requires --installation and --output")
    actors = [item.strip() for item in args.actors.split(",") if item.strip()]
    families = [item.strip() for item in args.families.split(",") if item.strip()]
    try:
        payload = probe(args.installation, actors, families)
        _write_once(args.output, payload)
    except (OSError, ValueError, IndependentProbeError) as exc:
        print(f"independent_fleet_basing_probe_error:{exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": payload.get("status"), "completed": payload.get("completed"), "doublepass": payload.get("doublepass"), "actors": actors, "output": str(args.output)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
