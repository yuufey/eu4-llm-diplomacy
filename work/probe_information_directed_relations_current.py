"""Lazy, independent bounded probe for directed current relations.

This is a batch-56 raw probe, deliberately separate from the production
readers.  It supports the two current row predicates whose operands are
closed for this build: ``military_access`` and ``guarantee``.  Every result
keeps the native ``forward`` (actor row -> target) and ``reverse`` (target
row -> actor) labels.  It does not infer grantor/recipient roles, dates,
expiry, or action legality.

No process is opened unless the explicit ``--run`` switch is supplied.  The
probe uses only QUERY_INFORMATION|VM_READ, precharges every RPM read before
dispatch, and retains unknown rows instead of converting failed reads to
False.  It imports only the existing low-level installation/Win32 seams; it
does not import a production information reader or profile.
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

_WORKSPACE = Path(__file__).resolve().parents[1]
if str(_WORKSPACE) not in sys.path:
    sys.path.insert(0, str(_WORKSPACE))

from bridge.information import localization_memory as _base
from bridge.information import mission_memory as _mission


VERSION = "1.37.4"
EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = 0x140000000
ACTOR = "FRA"
FAMILIES = ("military_access", "guarantee")

MAX_USER_ADDRESS = _mission.MAX_USER_ADDRESS
MAX_SINGLE_RPM = 64 * 1024
PAIR_TOTAL_RPM = 512 * 1024
NETWORK_TOTAL_RPM = 2 * 1024 * 1024
MAX_COUNTRIES = 4096
MAX_VECTOR_COUNT = 4096
NULL_COUNTRY_FULLREF_RAW_HEX = "2d2d2d0000000000"

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

FAMILY_LAYOUT: dict[str, dict[str, Any]] = {
    "military_access": {
        "begin_offset": 0xB0,
        "count_offset": 0xBC,
        "element_stride": 0x10,
        "leaf_rva": 0xA68E60,
        "leaf_range": [0xA68E60, 0xA68E9C],
        "record_identity": False,
    },
    "guarantee": {
        "begin_offset": 0x1A0,
        "count_offset": 0x1AC,
        "element_stride": 0x10,
        "leaf_rva": 0xA69E00,
        "leaf_range": [0xA69E00, 0xA69E5A],
        "record_identity": True,
    },
}

# These file pins are static source guards, not a new REA query.  The
# batch-56 contract-003 report combines both accepted current-build leaves;
# source-001/source-002 remain pinned as their family-specific antecedents.
SOURCE_FILE_PINS = (
    (
        "work/runtime/information-relation-network-remaining-20261027-001/source-001.json",
        "fab84043a0ef928b4e26a5e57226dcd0d1881a555edf1a3898a5ff16f2b368a0",
        "military_access row/vector contract and common country+0x1510 layout",
    ),
    (
        "work/runtime/information-relation-network-remaining-20261027-001/source-002.json",
        "259767cc399fcd79145182aee7c9afc1bf3c83c5544859adab7c53582cb4bbc3",
        "guarantee current predicate and SHA audit",
    ),
    (
        "work/runtime/information-relation-network-remaining-20261027-001/relation-network-contract-003.json",
        "26ce4537760fdf97bb5be7c660797e564f8bfc7a1205ad80ff04884e9ef6786c",
        "batch-56 two-family directed relation contract and static role map",
    ),
    (
        "work/native/alliance-query.inc",
        "ed245857d184a0221eca60c0e7b238d4179f4fc3e17f78a4ce2d7137b94458d4",
        "bounded country+0x1510 source descriptor",
    ),
    (
        "work/runtime/military-access-integration-20261015-001/rea-a68e60/evidence.json",
        "8f9f40e23e933f5f96a9f8c8a1688581f65259644cb676a267b2ffb9e914348a",
        "accepted current military-access leaf evidence",
    ),
    (
        "work/runtime/guarantee-support-identification-20261015-001/guarantee-integration-20261015-001/rea-a69e00/evidence.json",
        "8b1b7272985651d83bc9508a1cb9611fa72924fae472e490d2a63d6e16e23b93",
        "accepted current guarantee leaf evidence",
    ),
)

EVIDENCE_IDS = {
    "military_access": "ev_0dd1460e4ae8b6b19678e5a7ef9f40aef6e2cd68ad253487bf5157f8f871e7a2",
    "guarantee": "ev_b602b9bcefcd85043989b7e8da1e08e8e79f2c446c710a6f0510e0b18b63ee48",
}


class IndependentProbeError(RuntimeError):
    """A bounded read or identity contract could not be satisfied."""


class PrechargedRPM:
    """Read-only Win32 RPM with failure-consuming pre-dispatch accounting."""

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
        entry = {"label": label, "address": hex(address), "size": size, "status": "reserved"}
        # Reserve before calling ReadProcessMemory.  Failed requests consume
        # the reservation and are never retried by this reader.
        if self.reserved + size > self.limit:
            entry["status"] = "budget_rejected"
            self.read_log.append(entry)
            raise IndependentProbeError(f"RPM_TOTAL_BUDGET_EXCEEDED:{label}")
        self.reserved += size
        self.calls += 1
        self.read_log.append(entry)
        buffer = C.create_string_buffer(size)
        actual = C.c_size_t()
        try:
            ok = self.kernel.ReadProcessMemory(
                self.handle, C.c_void_p(address), buffer, size, C.byref(actual)
            )
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
        return int.from_bytes(raw, "little", signed=False), raw

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


def _safe_add(base: int, offset: int, label: str) -> int:
    value = base + offset
    if not isinstance(base, int) or not isinstance(offset, int) or value < 0x10000 or value >= MAX_USER_ADDRESS:
        raise IndependentProbeError(f"address_range_overflow:{label}")
    return value


def _valid_pointer(value: Any) -> bool:
    return isinstance(value, int) and 0x10000 <= value < MAX_USER_ADDRESS and value % 8 == 0


def _signed_i16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def _tag_slot(raw: bytes) -> tuple[str | None, int | None]:
    if len(raw) != 8:
        return None, None
    if raw == bytes.fromhex(NULL_COUNTRY_FULLREF_RAW_HEX):
        return None, None
    if raw[3] != 0 or not all(0x41 <= byte <= 0x5A or 0x30 <= byte <= 0x39 for byte in raw[:3]):
        return None, None
    return raw[:3].decode("ascii"), int.from_bytes(raw[4:6], "little", signed=False)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_guard() -> dict[str, Any]:
    checks: dict[str, bool] = {}
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    for relative, expected, role in SOURCE_FILE_PINS:
        path = _WORKSPACE / relative
        try:
            actual = _sha256_file(path)
            checks[relative] = actual == expected
            records.append({"path": relative, "expected_sha256": expected, "actual_sha256": actual, "role": role})
        except Exception as exc:
            checks[relative] = False
            errors.append(f"{relative}:{type(exc).__name__}:{exc}")
    return {
        "status": "observed" if checks and all(checks.values()) and not errors else "unknown",
        "checks": checks,
        "records": records,
        "unknown_conditions": errors,
        "evidence_ids": deepcopy(EVIDENCE_IDS),
    }


def _file_code_guard(process_path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "process_path": str(process_path),
        "process_sha256": None,
        "process_sha256_matches_expected": False,
        "windows": [],
        "unknown_conditions": [],
    }
    try:
        process_sha = _sha256_file(process_path)
        result["process_sha256"] = process_sha
        result["process_sha256_matches_expected"] = process_sha == EXE_SHA256
        for family, spec in FAMILY_LAYOUT.items():
            start, end = spec["leaf_range"]
            raw = _base._read_pe_rva_bytes(process_path, start, end - start)
            result["windows"].append(
                {
                    "family": family,
                    "rva": [hex(start), hex(end)],
                    "va": [hex(IMAGE_BASE + start), hex(IMAGE_BASE + end)],
                    "size": len(raw),
                    "raw_hex": raw.hex(),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        result["status"] = "observed" if result["process_sha256_matches_expected"] else "mismatch"
    except Exception as exc:
        result["unknown_conditions"].append(f"{type(exc).__name__}:{exc}")
    return result


def _runtime_code_guard(reader: PrechargedRPM, module_base: int, file_guard: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "records": [], "module_base": _addr(module_base), "unknown_conditions": []}
    windows = file_guard.get("windows") if isinstance(file_guard, Mapping) else None
    if not isinstance(windows, list) or len(windows) != len(FAMILY_LAYOUT):
        result["unknown_conditions"].append("file_code_guard_windows_missing")
        return result
    try:
        for expected in windows:
            family = expected["family"]
            start, end = FAMILY_LAYOUT[family]["leaf_range"]
            expected_raw = bytes.fromhex(expected["raw_hex"])
            actual = reader.read(_safe_add(module_base, start, f"code_guard.{family}"), len(expected_raw), f"code_guard.{family}")
            result["records"].append(
                {
                    "family": family,
                    "rva": [hex(start), hex(end)],
                    "address": _addr(module_base + start, module_base),
                    "expected_sha256": expected["sha256"],
                    "actual_sha256": hashlib.sha256(actual).hexdigest(),
                    "expected_hex": expected_raw.hex(),
                    "actual_hex": actual.hex(),
                    "matches": actual == expected_raw,
                }
            )
        result["status"] = "observed" if all(item["matches"] for item in result["records"]) else "mismatch"
    except Exception as exc:
        result["unknown_conditions"].append(f"{type(exc).__name__}:{exc}")
    return result


def _country_context(reader: PrechargedRPM, module_base: int, requested: Sequence[str]) -> dict[str, Any]:
    db_address = _safe_add(module_base, DATABASE_RVA, "global.database")
    database, db_raw = reader.qword(db_address, "global.database")
    game_address = _safe_add(module_base, GAME_RVA, "global.game")
    game, game_raw = reader.qword(game_address, "global.game")
    result: dict[str, Any] = {
        "status": "unknown",
        "database": {"address": _addr(db_address, module_base), "raw_hex": db_raw.hex(), "value": database},
        "game": {"address": _addr(game_address, module_base), "raw_hex": game_raw.hex(), "value": game},
        "game_date": None,
        "country_table": None,
        "country_count": None,
        "entries": [],
        "matches": {tag: [] for tag in requested},
        "candidate_failures": [],
        "unknown_conditions": [],
    }
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
    matches: dict[str, list[dict[str, Any]]] = {tag: [] for tag in requested}
    for index in range(count):
        pointer_raw = table_raw_bytes[index * 8 : (index + 1) * 8]
        pointer = int.from_bytes(pointer_raw, "little", signed=False)
        entry: dict[str, Any] = {
            "index": index,
            "pointer_raw_hex": pointer_raw.hex(),
            "pointer": _addr(pointer, module_base),
            "pointer_value": pointer,
        }
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
        tag, slot = _tag_slot(full_raw)
        entry["fullref"] = {"address": _addr(full_address, module_base), "raw_hex": full_raw.hex(), "value": fullref}
        entry.update({"tag": tag, "slot": slot})
        if full_raw.hex() == NULL_COUNTRY_FULLREF_RAW_HEX:
            entry.update(status="null_sentinel", reason="known_null_country_sentinel")
            result["entries"].append(entry)
            continue
        if tag is None or slot is None or slot != index:
            entry.update(status="unknown", reason="country_fullref_tag_or_slot_invalid")
            result["candidate_failures"].append(
                {"index": index, "reason": entry["reason"], "fullref_raw_hex": full_raw.hex(), "tag": tag, "slot": slot}
            )
        else:
            entry["status"] = "valid"
            if tag in matches:
                matches[tag].append(entry)
        result["entries"].append(entry)
    result["matches"] = matches
    for tag in requested:
        if len(matches[tag]) != 1:
            result["unknown_conditions"].append(f"country_identity_match_count_invalid:{tag}")
    result["status"] = "observed"
    return result


def _entry_pointer(entry: Mapping[str, Any]) -> int:
    value = entry.get("pointer_value")
    if not isinstance(value, int) or not _valid_pointer(value):
        raise IndependentProbeError("country_pointer_invalid")
    return value


def _entry_fullref(entry: Mapping[str, Any]) -> int:
    fullref = entry.get("fullref")
    if not isinstance(fullref, Mapping) or not isinstance(fullref.get("value"), int):
        raise IndependentProbeError("country_fullref_missing")
    raw = fullref.get("raw_hex")
    if not isinstance(raw, str) or bytes.fromhex(raw) != int(fullref["value"]).to_bytes(8, "little"):
        raise IndependentProbeError("country_fullref_raw_mismatch")
    return int(fullref["value"])


def _relation_row(reader: PrechargedRPM, source_entry: Mapping[str, Any], target_entry: Mapping[str, Any], module_base: int) -> dict[str, Any]:
    source_pointer = _entry_pointer(source_entry)
    target_fullref = _entry_fullref(target_entry)
    target_slot = (target_fullref >> 32) & 0xFFFF
    if target_slot >= MAX_COUNTRIES:
        raise IndependentProbeError("target_slot_out_of_bound")
    table_address = _safe_add(source_pointer, RELATION_TABLE_OFFSET, "source.relation_table")
    table_pointer, table_raw = reader.qword(table_address, "source.relation_table.pointer")
    if not _valid_pointer(table_pointer):
        raise IndependentProbeError("relation_table_pointer_invalid")
    row_address = _safe_add(table_pointer, target_slot * RELATION_ROW_STRIDE, "relation.row")
    raw = reader.read(row_address, 0x20, "relation.row.prefix")
    owner = int.from_bytes(raw[RELATION_ROW_OWNER_OFFSET : RELATION_ROW_OWNER_OFFSET + 8], "little")
    row_fullref = int.from_bytes(raw[RELATION_ROW_RECIPIENT_OFFSET : RELATION_ROW_RECIPIENT_OFFSET + 8], "little")
    if not _valid_pointer(owner):
        raise IndependentProbeError("relation_row_owner_invalid")
    if row_fullref != target_fullref:
        raise IndependentProbeError("relation_row_recipient_fullref_mismatch")
    return {
        "address": _addr(row_address, module_base),
        "relation_table": {"address": _addr(table_address, module_base), "raw_hex": table_raw.hex(), "value": table_pointer},
        "prefix_raw_hex": raw.hex(),
        "source_country_pointer": _addr(source_pointer, module_base),
        "source_country_pointer_value": source_pointer,
        "target_fullref": {"address": _addr(row_address + RELATION_ROW_RECIPIENT_OFFSET, module_base), "raw_hex": raw[0x10:0x18].hex(), "value": row_fullref},
        "owner": _addr(owner, module_base),
        "owner_value": owner,
        "owner_raw_hex": raw[0:8].hex(),
        "target_slot_signed_i16": _signed_i16((target_fullref >> 32) & 0xFFFF),
    }


def _read_vector(reader: PrechargedRPM, family: str, row: Mapping[str, Any], module_base: int) -> dict[str, Any]:
    spec = FAMILY_LAYOUT[family]
    owner = row.get("owner_value")
    if not isinstance(owner, int) or not _valid_pointer(owner):
        raise IndependentProbeError(f"{family}.owner_invalid")
    begin_address = _safe_add(owner, spec["begin_offset"], f"{family}.vector_begin")
    count_address = _safe_add(owner, spec["count_offset"], f"{family}.vector_count")
    begin, begin_raw = reader.qword(begin_address, f"{family}.vector_begin")
    count, count_raw = reader.i32(count_address, f"{family}.vector_count")
    if count < 0 or count > MAX_VECTOR_COUNT:
        raise IndependentProbeError(f"{family}.vector_count_out_of_bound")
    if count and not _valid_pointer(begin):
        raise IndependentProbeError(f"{family}.vector_begin_invalid")
    raw_elements = reader.read(begin, count * 16, f"{family}.vector.elements") if count else b""
    elements: list[dict[str, Any]] = []
    for index in range(count):
        chunk = raw_elements[index * 16 : (index + 1) * 16]
        entry_pointer_raw = chunk[8:16]
        elements.append(
            {
                "index": index,
                "address": _addr(begin + index * 16, module_base),
                "raw_hex": chunk.hex(),
                "first_dword_raw_hex": chunk[:4].hex(),
                "first_dword": int.from_bytes(chunk[:4], "little", signed=False),
                "entry_pointer_raw_hex": entry_pointer_raw.hex(),
                "entry_pointer_value": int.from_bytes(entry_pointer_raw, "little", signed=False),
                "unread_tail_raw_hex": chunk[4:8].hex(),
            }
        )
    return {
        "status": "known",
        "raw": {
            "owner_pointer": _addr(owner, module_base),
            "owner_pointer_value": owner,
            "owner_pointer_raw_hex": row.get("owner_raw_hex"),
            "vector_begin": {"address": _addr(begin_address, module_base), "raw_hex": begin_raw.hex(), "value": begin},
            "vector_count": {"address": _addr(count_address, module_base), "raw_hex": count_raw.hex(), "value": count},
            "elements": elements,
        },
    }


def _evaluate_vector(reader: PrechargedRPM, family: str, cache: Mapping[str, Any], target_fullref: int, module_base: int, label: str) -> dict[str, Any]:
    raw = cache.get("raw") if isinstance(cache, Mapping) else None
    if not isinstance(raw, Mapping) or not isinstance(raw.get("elements"), list):
        raise IndependentProbeError(f"{family}.cached_vector_missing")
    target_slot = _signed_i16((target_fullref >> 32) & 0xFFFF)
    matching: dict[str, Any] | None = None
    for element in raw["elements"]:
        if not isinstance(element, Mapping):
            raise IndependentProbeError(f"{family}.element_shape_invalid")
        if int(element.get("first_dword", -1)) == (target_slot & 0xFFFFFFFF):
            matching = element
            break  # native first-match semantics
    proof: dict[str, Any] = {
        "family": family,
        "leaf_rva": hex(FAMILY_LAYOUT[family]["leaf_rva"]),
        "evidence_id": EVIDENCE_IDS[family],
        "target_slot_signed_i16": target_slot,
        "matching_element_index": matching.get("index") if matching is not None else None,
        "native_first_match_only": True,
    }
    if matching is None:
        proof["value"] = False
        return {"status": "known", "value": False, "proof": proof}
    if not FAMILY_LAYOUT[family]["record_identity"]:
        proof["value"] = True
        return {"status": "known", "value": True, "proof": proof}
    pointer = matching.get("entry_pointer_value")
    if pointer == 0:
        proof.update(value=False, record_pointer_status="null_native_false")
        return {"status": "known", "value": False, "proof": proof}
    if not _valid_pointer(pointer):
        raise IndependentProbeError(f"{family}.record_pointer_invalid")
    record_address = _safe_add(pointer, 0x18, f"{family}.record.fullref")
    record_fullref, record_raw = reader.qword(record_address, f"{family}.record.fullref:{label}")
    record_slot = _signed_i16((record_fullref >> 32) & 0xFFFF)
    proof["record_pointer"] = {"address": deepcopy(matching.get("address")), "raw_hex": matching.get("entry_pointer_raw_hex"), "value": pointer}
    proof["record_fullref"] = {"address": _addr(record_address, module_base), "raw_hex": record_raw.hex(), "value": record_fullref}
    proof["record_slot_signed_i16"] = record_slot
    proof["value"] = record_slot == target_slot
    return {"status": "known", "value": record_slot == target_slot, "proof": proof}


def _unknown(family: str, reason: str, direction: str, relation_row: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "family": family, "direction": direction, "value": None, "reason": reason, "relation_row": deepcopy(relation_row), "partial": True, "complete": False}
    return result


def _direction(reader: PrechargedRPM, family: str, direction: str, source_entry: Mapping[str, Any], target_entry: Mapping[str, Any], row: Mapping[str, Any] | None, cache: dict[str, dict[str, Any]], module_base: int) -> dict[str, Any]:
    target_fullref = _entry_fullref(target_entry)
    if not isinstance(row, Mapping):
        return _unknown(family, "relation_row_unknown", direction)
    owner = row.get("owner_value")
    key = f"{owner:#x}:{family}" if isinstance(owner, int) else None
    result: dict[str, Any] = {
        "status": "unknown",
        "family": family,
        "direction": direction,
        "value": None,
        "relation_row": deepcopy(row),
        "predicate_cache_key": key,
        "partial": True,
        "complete": False,
    }
    if key is None:
        result["reason"] = "relation_owner_missing"
        return result
    if key not in cache:
        try:
            cache[key] = _read_vector(reader, family, row, module_base)
        except Exception as exc:
            cache[key] = {"status": "unknown", "reason": f"{type(exc).__name__}:{exc}", "raw": None}
    vector = cache[key]
    if vector.get("status") != "known":
        result["reason"] = vector.get("reason", "owner_vector_unknown")
        return result
    try:
        evaluated = _evaluate_vector(reader, family, vector, target_fullref, module_base, f"{direction}:{target_entry.get('tag', '?')}")
    except Exception as exc:
        result["reason"] = f"{type(exc).__name__}:{exc}"
        return result
    result.update(status="known", value=evaluated["value"], proof=evaluated["proof"], complete=False)
    return result


def _target_record(entry: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "index": entry.get("index"),
        "country": entry.get("tag"),
        "country_pointer": deepcopy(entry.get("pointer")),
        "fullref_hex": (entry.get("fullref") or {}).get("raw_hex"),
        "fullref_value": (entry.get("fullref") or {}).get("value"),
        "slot": entry.get("slot"),
    }


def _pair_pass(reader: PrechargedRPM, module_base: int, actor: str, recipient: str, families: Sequence[str], file_guard: Mapping[str, Any]) -> dict[str, Any]:
    guard = _runtime_code_guard(reader, module_base, file_guard)
    result: dict[str, Any] = {
        "status": "unknown",
        "runtime_code_guard": guard,
        "context": None,
        "targets": [],
        "fields": {},
        "owner_cache": {},
        "candidate_failures": [],
        "unknown_conditions": [],
        "read_budget": None,
        "read_log": None,
        "complete": False,
    }
    if guard.get("status") != "observed":
        result["unknown_conditions"].append("runtime_code_guard_not_observed")
        return result
    context = _country_context(reader, module_base, (actor, recipient))
    result["context"] = context
    result["candidate_failures"] = deepcopy(context.get("candidate_failures", []))
    actor_matches = context.get("matches", {}).get(actor, [])
    recipient_matches = context.get("matches", {}).get(recipient, [])
    if len(actor_matches) != 1 or len(recipient_matches) != 1:
        result["unknown_conditions"].append("actor_or_recipient_identity_invalid")
        return result
    cache: dict[str, dict[str, Any]] = {}
    forward_row: Mapping[str, Any] | None = None
    reverse_row: Mapping[str, Any] | None = None
    try:
        forward_row = _relation_row(reader, actor_matches[0], recipient_matches[0], module_base)
    except Exception as exc:
        result["unknown_conditions"].append(f"forward_row:{type(exc).__name__}:{exc}")
    try:
        reverse_row = _relation_row(reader, recipient_matches[0], actor_matches[0], module_base)
    except Exception as exc:
        result["unknown_conditions"].append(f"reverse_row:{type(exc).__name__}:{exc}")
    target_info = _target_record(recipient_matches[0])
    target_info.update(
        {
            "forward": {"source": actor, "target": recipient},
            "reverse": {"source": recipient, "target": actor},
        }
    )
    for family in families:
        forward = _direction(reader, family, "forward", actor_matches[0], recipient_matches[0], forward_row, cache, module_base)
        reverse = _direction(reader, family, "reverse", recipient_matches[0], actor_matches[0], reverse_row, cache, module_base)
        row = {"country": recipient, "fullref_hex": target_info["fullref_hex"], "slot": target_info["slot"], "forward": forward, "reverse": reverse}
        known = [direction for direction in (forward, reverse) if direction.get("status") == "known"]
        unknown = [direction for direction in (forward, reverse) if direction.get("status") != "known"]
        values = [{"country": recipient, "fullref_hex": target_info["fullref_hex"], "slot": target_info["slot"], "direction": direction["direction"], "active": True} for direction in known if direction.get("value") is True]
        result["fields"][family] = {
            "status": "known" if not unknown and not result["candidate_failures"] else "partial",
            "family": family,
            "value": values,
            "rows": [row],
            "unknown_rows": [{"country": recipient, "direction": direction["direction"], "reason": direction.get("reason", "unknown")} for direction in unknown],
            "candidate_failures": deepcopy(result["candidate_failures"]),
            "partial": True,
            "complete": False,
            "unit": "relation_state",
            "scale": 1,
            "period": "current",
            "direction_labels": {"forward": "actor_row_to_target", "reverse": "target_row_to_actor"},
        }
    result["owner_cache"] = cache
    result["targets"] = [target_info]
    result["status"] = "observed"
    result["complete"] = all(field.get("status") == "known" for field in result["fields"].values())
    return result


def _network_pass(reader: PrechargedRPM, module_base: int, actor: str, families: Sequence[str], file_guard: Mapping[str, Any]) -> dict[str, Any]:
    guard = _runtime_code_guard(reader, module_base, file_guard)
    result: dict[str, Any] = {
        "status": "unknown",
        "runtime_code_guard": guard,
        "context": None,
        "targets": [],
        "owner_cache": {},
        "fields": {},
        "candidate_failures": [],
        "unknown_conditions": [],
        "read_budget": None,
        "read_log": None,
        "complete": False,
        "witnesses": {"status": "NO_ACTIVE_SAMPLE", "rows": [], "reason": "optional_foreign_owner_witness_scan_not_enabled"},
    }
    if guard.get("status") != "observed":
        result["unknown_conditions"].append("runtime_code_guard_not_observed")
        return result
    context = _country_context(reader, module_base, (actor,))
    result["context"] = context
    result["candidate_failures"] = deepcopy(context.get("candidate_failures", []))
    actor_matches = context.get("matches", {}).get(actor, [])
    if len(actor_matches) != 1:
        result["unknown_conditions"].append("actor_identity_invalid")
        return result
    actor_entry = actor_matches[0]
    actor_index = actor_entry["index"]
    targets = [
        entry
        for entry in context.get("entries", [])
        if entry.get("status") == "valid" and entry.get("index") != actor_index
    ]
    result["targets"] = [_target_record(entry) for entry in targets]
    cache: dict[str, dict[str, Any]] = {}
    rows_by_family: dict[str, list[dict[str, Any]]] = {family: [] for family in families}
    active_by_family: dict[str, list[dict[str, Any]]] = {family: [] for family in families}
    unknown_by_family: dict[str, list[dict[str, Any]]] = {family: [] for family in families}
    for target in targets:
        forward_row: Mapping[str, Any] | None = None
        reverse_row: Mapping[str, Any] | None = None
        try:
            forward_row = _relation_row(reader, actor_entry, target, module_base)
        except Exception as exc:
            result["candidate_failures"].append({"country": target.get("tag"), "direction": "forward", "reason": f"{type(exc).__name__}:{exc}"})
        try:
            reverse_row = _relation_row(reader, target, actor_entry, module_base)
        except Exception as exc:
            result["candidate_failures"].append({"country": target.get("tag"), "direction": "reverse", "reason": f"{type(exc).__name__}:{exc}"})
        for family in families:
            forward = _direction(reader, family, "forward", actor_entry, target, forward_row, cache, module_base)
            reverse = _direction(reader, family, "reverse", target, actor_entry, reverse_row, cache, module_base)
            row = {"country": target.get("tag"), "fullref_hex": (target.get("fullref") or {}).get("raw_hex"), "slot": target.get("slot"), "forward": forward, "reverse": reverse}
            rows_by_family[family].append(row)
            for direction in (forward, reverse):
                if direction.get("status") != "known":
                    unknown_by_family[family].append({"country": target.get("tag"), "direction": direction.get("direction"), "reason": direction.get("reason", "unknown")})
                elif direction.get("value") is True:
                    active_by_family[family].append({"country": target.get("tag"), "fullref_hex": row["fullref_hex"], "slot": row["slot"], "direction": direction["direction"], "active": True})
    for family in families:
        unknown = unknown_by_family[family]
        result["fields"][family] = {
            "status": "known" if not unknown and not result["candidate_failures"] else "partial",
            "family": family,
            "value": active_by_family[family],
            "rows": rows_by_family[family],
            "unknown_rows": unknown,
            "candidate_failures": deepcopy(result["candidate_failures"]),
            "candidate_count": len(targets),
            "partial": True,
            "complete": False,
            "unit": "relation_state",
            "scale": 1,
            "period": "current",
            "direction_labels": {"forward": "actor_row_to_target", "reverse": "target_row_to_actor"},
        }
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


def _base_report(installation: Path, actor: str, recipient: str | None, families: Sequence[str], mode: str) -> dict[str, Any]:
    return {
        "schema": "information_directed_relations_independent_raw.v1",
        "probe": "information-directed-relations-current",
        "probe_version": 1,
        "independent": True,
        "production_reader_imported": False,
        "profile_imported": False,
        "read_only": True,
        "evidence_kind": "independent_raw_runtime_observation",
        "source_pins": {"files": [path for path, _, _ in SOURCE_FILE_PINS], "evidence_ids": deepcopy(EVIDENCE_IDS), "executable_sha256": EXE_SHA256},
        "request": {"installation": str(installation), "actor": actor, "recipient": recipient, "families": list(families), "mode": mode},
        "target_build": {"version": VERSION, "expected_exe_sha256": EXE_SHA256, "image_base": hex(IMAGE_BASE), "rva_va_rule": "VA = image_base + RVA; retain both"},
        "static_contract_guard": _source_guard(),
        "identity": {"installation_path": str(installation), "installation_pid": None, "installation_creation_filetime": None, "installation_session_id": None, "process_path": None, "process_path_sha256": None, "process_path_sha256_matches_expected": None, "process_creation_filetime": None, "process_creation_utc": None, "process_creation_matches_installation": None, "module_path": None, "module_path_matches_process": None, "binding_verified": False},
        "module_base": None,
        "file_code_guard": None,
        "runtime_code_guard": None,
        "before": None,
        "after": None,
        "fields": {family: {"status": "unknown", "value": None} for family in families},
        "context_before": None,
        "context_after": None,
        "doublepass": {"performed": False, "consistent": None, "mismatches": []},
        "access": {"native_game_calls": False, "target_memory_writes": False, "open_process_mask": "QUERY_INFORMATION|VM_READ", "rpm_total_limit": NETWORK_TOTAL_RPM if mode == "network" else PAIR_TOTAL_RPM, "rpm_single_read_limit": MAX_SINGLE_RPM, "rpm_bytes_requested": 0, "rpm_calls": 0},
        "cleanup": {"handle_close": {"status": "unknown", "success": None, "closed": False}},
        "direction_semantics": {"forward": "actor_country_row_to_target_country", "reverse": "target_country_row_to_actor_country", "public_role_projection": "deferred; raw probe does not name grantor/recipient"},
        "static_role_map": {"status": "static_only", "military_access": {"forward": "received", "reverse": "granted"}, "guarantee": {"forward": "granted", "reverse": "received"}, "runtime_role_projection": False},
        "status": "starting",
        "completed": False,
        "errors": [],
    }


def capture_raw(installation: Path, actor: str, recipient: str | None, families: Sequence[str], mode: str) -> dict[str, Any]:
    installation = Path(installation)
    report = _base_report(installation, actor, recipient, families, mode)
    valid_actor = isinstance(actor, str) and re.fullmatch(r"[A-Z0-9]{3}", actor) is not None
    public_network_actor_ok = mode != "network" or actor == ACTOR
    if not valid_actor or not public_network_actor_ok or not families or len(set(families)) != len(families) or any(family not in FAMILIES for family in families):
        report.update(status="unsupported_request", completed=True)
        report["errors"].append({"stage": "request", "error": "actor/family request invalid; network scope is public FRA, pair scope permits a private valid three-character actor"})
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
        report["file_code_guard"] = _file_code_guard(Path(report["identity"]["process_path"]))
        if report["static_contract_guard"].get("status") != "observed":
            raise IndependentProbeError("source_contract_pin_mismatch")
        if report["file_code_guard"].get("status") != "observed":
            raise IndependentProbeError("file_code_guard_mismatch")
        limit = NETWORK_TOTAL_RPM if mode == "network" else PAIR_TOTAL_RPM
        reader = PrechargedRPM(kernel, handle, module_base, limit)
        before_start = len(reader.read_log)
        first = _network_pass(reader, module_base, actor, families, report["file_code_guard"]) if mode == "network" else _pair_pass(reader, module_base, actor, recipient or "", families, report["file_code_guard"])
        first["read_budget"] = {"bytes_reserved": reader.reserved, "calls_reserved": reader.calls, "limit": limit}
        first["read_log"] = deepcopy(reader.read_log[before_start:])
        report["before"] = first
        report["context_before"] = deepcopy(first.get("context"))
        if first.get("status") == "observed":
            after_start = len(reader.read_log)
            second = _network_pass(reader, module_base, actor, families, report["file_code_guard"]) if mode == "network" else _pair_pass(reader, module_base, actor, recipient or "", families, report["file_code_guard"])
            second["read_budget"] = {"bytes_reserved": reader.reserved, "calls_reserved": reader.calls, "limit": limit}
            second["read_log"] = deepcopy(reader.read_log[after_start:])
            report["after"] = second
            report["context_after"] = deepcopy(second.get("context"))
            report["doublepass"]["performed"] = True
            report["doublepass"]["mismatches"] = _diff_paths(_strip_volatile(first), _strip_volatile(second))[:256]
            report["doublepass"]["consistent"] = not report["doublepass"]["mismatches"]
            if report["doublepass"]["consistent"]:
                report["status"] = "observed"
                report["fields"] = deepcopy(second.get("fields", {}))
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


def probe(installation: Path, actor: str = ACTOR, recipient: str | None = None, families: Sequence[str] | None = None, network: bool = False) -> dict[str, Any]:
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
    parser = argparse.ArgumentParser(description="Lazy independent raw probe for current directed relation predicates")
    parser.add_argument("--run", action="store_true", help="explicitly permit process open and read-only RPM")
    parser.add_argument("--installation", required=True, type=Path)
    parser.add_argument("--actor", default=ACTOR)
    parser.add_argument("--recipient")
    parser.add_argument("--network", action="store_true", help="scan all valid country targets; otherwise use --recipient")
    parser.add_argument("--families", default=",".join(FAMILIES))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    selected = [item.strip() for item in args.families.split(",") if item.strip()]
    if not args.run:
        print(json.dumps({"status": "ready", "run_required": True, "would_open_process": False, "families": selected, "output": str(args.output)}, ensure_ascii=False))
        return 0
    if not args.network and not args.recipient:
        parser.error("--recipient is required unless --network is selected")
    try:
        payload = probe(args.installation, args.actor, args.recipient, selected, args.network)
        _write_once(args.output, payload)
    except (OSError, ValueError, IndependentProbeError) as exc:
        print(f"directed_relation_probe_error:{exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": payload.get("status"), "completed": payload.get("completed"), "doublepass": payload.get("doublepass"), "output": str(args.output)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
