"""Independent offline replay for the batch-56 directed-relation raw probe.

The reference never imports a production information reader or profile and
never opens a process.  It recomputes the military-access and guarantee
predicates from the probe's preserved relation rows, vector bytes, and (for
guarantee) the first matching record ``+0x18`` bytes.  ``forward`` and
``reverse`` remain native row directions; no grantor/recipient role is
invented.  Large probe reports are read one top-level value at a time with a
bounded buffer rather than ``json.load`` on the complete file.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Callable, Mapping

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-relation-network-remaining-20261027-001"
DEFAULT_INPUT = STAGE / "directed-relations-current-inputs-001.json"
DEFAULT_OUTPUT = STAGE / "expected-directed-relations-projection-001.json"
DEFAULT_RECEIPT = STAGE / "directed-relations-reference-receipt-001.json"

VERSION = "1.37.4"
EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = 0x140000000
FAMILIES = ("military_access", "guarantee")
MAX_USER_ADDRESS = 0x0000800000000000
MAX_COUNTRIES = 4096
MAX_VECTOR_COUNT = 4096
RELATION_TABLE_OFFSET = 0x1510
RELATION_ROW_STRIDE = 0x48
NULL_COUNTRY_FULLREF_RAW_HEX = "2d2d2d0000000000"

SOURCE_PINS = {
    "source_001": {
        "path": "work/runtime/information-relation-network-remaining-20261027-001/source-001.json",
        "sha256": "fab84043a0ef928b4e26a5e57226dcd0d1881a555edf1a3898a5ff16f2b368a0",
        "role": "military-access row/vector contract",
    },
    "source_002": {
        "path": "work/runtime/information-relation-network-remaining-20261027-001/source-002.json",
        "sha256": "259767cc399fcd79145182aee7c9afc1bf3c83c5544859adab7c53582cb4bbc3",
        "role": "guarantee current predicate and SHA audit",
    },
    "contract_003": {
        "path": "work/runtime/information-relation-network-remaining-20261027-001/relation-network-contract-003.json",
        "sha256": "26ce4537760fdf97bb5be7c660797e564f8bfc7a1205ad80ff04884e9ef6786c",
        "role": "batch-56 two-family directed relation contract and static role map",
    },
    "alliance_query": {
        "path": "work/native/alliance-query.inc",
        "sha256": "ed245857d184a0221eca60c0e7b238d4179f4fc3e17f78a4ce2d7137b94458d4",
        "role": "bounded country+0x1510 source descriptor",
    },
}
EVIDENCE_IDS = {
    "military_access": "ev_0dd1460e4ae8b6b19678e5a7ef9f40aef6e2cd68ad253487bf5157f8f871e7a2",
    "guarantee": "ev_b602b9bcefcd85043989b7e8da1e08e8e79f2c446c710a6f0510e0b18b63ee48",
}
FAMILY_LAYOUT = {
    "military_access": {"record_identity": False, "leaf_rva": 0xA68E60},
    "guarantee": {"record_identity": True, "leaf_rva": 0xA69E00},
}


class ReferenceError(ValueError):
    """The retained raw report violates a binding contract."""


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _hex_bytes(value: Any, label: str, width: int | None = None) -> bytes:
    if not isinstance(value, str) or len(value) % 2:
        raise ReferenceError(f"raw_hex_invalid:{label}")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ReferenceError(f"raw_hex_invalid:{label}") from exc
    if width is not None and len(raw) != width:
        raise ReferenceError(f"raw_hex_width_invalid:{label}:{len(raw)}")
    return raw


def _valid_pointer(value: Any) -> bool:
    return isinstance(value, int) and 0x10000 <= value < MAX_USER_ADDRESS and value % 8 == 0


def _signed_i16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def _slot(fullref: int) -> int:
    return _signed_i16((fullref >> 32) & 0xFFFF)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _unknown(family: str, reason: str, direction: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "family": family, "value": None, "reason": reason, "partial": True, "complete": False}
    if direction is not None:
        result["direction"] = direction
    return result


def _value_va(value: Any) -> int | None:
    if not isinstance(value, Mapping):
        return None
    return _as_int(value.get("va"))


def _fullref_value(entry: Any) -> int | None:
    if not isinstance(entry, Mapping):
        return None
    fullref = entry.get("fullref")
    if not isinstance(fullref, Mapping):
        return None
    value = _as_int(fullref.get("value"))
    raw = _hex_bytes(fullref.get("raw_hex"), "country.fullref", 8)
    if value is None or int.from_bytes(raw, "little") != value:
        return None
    return value


def _context_entry(context: Mapping[str, Any], tag: str) -> Mapping[str, Any] | None:
    matches = context.get("matches")
    if isinstance(matches, Mapping) and isinstance(matches.get(tag), list) and len(matches[tag]) == 1:
        item = matches[tag][0]
        if isinstance(item, Mapping):
            return item
    for item in context.get("entries", []) if isinstance(context.get("entries"), list) else []:
        if isinstance(item, Mapping) and item.get("tag") == tag and item.get("status") == "valid":
            return item
    return None


def _relation_row_binding_valid(relation_row: Mapping[str, Any], source_pointer: int | None, target_fullref: int) -> bool:
    if source_pointer is None or not _valid_pointer(source_pointer):
        return False
    table = relation_row.get("relation_table")
    if not isinstance(table, Mapping):
        return False
    table_address = _value_va(table.get("address"))
    table_pointer = _as_int(table.get("value"))
    table_raw = _hex_bytes(table.get("raw_hex"), "relation.table", 8)
    if table_address != source_pointer + RELATION_TABLE_OFFSET or table_pointer is None or not _valid_pointer(table_pointer) or int.from_bytes(table_raw, "little") != table_pointer:
        return False
    row_address = _value_va(relation_row.get("address"))
    target_slot = _slot(target_fullref)
    expected_row = table_pointer + target_slot * RELATION_ROW_STRIDE
    if row_address != expected_row:
        return False
    target = relation_row.get("target_fullref")
    if not isinstance(target, Mapping):
        return False
    row_fullref = _as_int(target.get("value"))
    row_raw = _hex_bytes(target.get("raw_hex"), "relation.target_fullref", 8)
    if row_fullref != target_fullref or int.from_bytes(row_raw, "little") != target_fullref:
        return False
    owner = _as_int(relation_row.get("owner_value"))
    owner_raw = _hex_bytes(relation_row.get("owner_raw_hex"), "relation.owner", 8)
    return owner is not None and _valid_pointer(owner) and int.from_bytes(owner_raw, "little") == owner


def _vector_raw_valid(raw: Mapping[str, Any], family: str, row: Mapping[str, Any], target_fullref: int) -> tuple[list[Mapping[str, Any]], int]:
    owner = _as_int(row.get("owner_value"))
    if owner is None or not _valid_pointer(owner):
        raise ReferenceError("raw_owner_invalid")
    cached_owner = _as_int(raw.get("owner_pointer_value"))
    owner_raw = _hex_bytes(raw.get("owner_pointer_raw_hex"), "vector.owner", 8)
    if cached_owner != owner or int.from_bytes(owner_raw, "little") != owner:
        raise ReferenceError("raw_owner_cache_binding_invalid")
    begin_field = raw.get("vector_begin")
    count_field = raw.get("vector_count")
    if not isinstance(begin_field, Mapping) or not isinstance(count_field, Mapping):
        raise ReferenceError("raw_vector_header_missing")
    begin = _as_int(begin_field.get("value"))
    begin_raw = _hex_bytes(begin_field.get("raw_hex"), "vector.begin", 8)
    count = _as_int(count_field.get("value"))
    count_raw = _hex_bytes(count_field.get("raw_hex"), "vector.count", 4)
    if begin is None or count is None or int.from_bytes(begin_raw, "little") != begin or int.from_bytes(count_raw, "little", signed=True) != count:
        raise ReferenceError("raw_vector_header_decode_invalid")
    if count < 0 or count > MAX_VECTOR_COUNT:
        raise ReferenceError("raw_vector_count_invalid")
    if count and not _valid_pointer(begin):
        raise ReferenceError("raw_vector_begin_invalid")
    elements = raw.get("elements")
    if not isinstance(elements, list) or len(elements) != count:
        raise ReferenceError("raw_vector_elements_count_invalid")
    target_slot = _slot(target_fullref)
    valid_elements: list[Mapping[str, Any]] = []
    for index, element in enumerate(elements):
        if not isinstance(element, Mapping) or _as_int(element.get("index")) != index:
            raise ReferenceError("raw_vector_element_index_invalid")
        chunk = _hex_bytes(element.get("raw_hex"), "vector.element", 16)
        address = _value_va(element.get("address"))
        first = int.from_bytes(chunk[:4], "little")
        pointer = int.from_bytes(chunk[8:16], "little")
        if address != begin + index * 16 or _as_int(element.get("first_dword")) != first or element.get("first_dword_raw_hex") != chunk[:4].hex() or element.get("entry_pointer_raw_hex") != chunk[8:16].hex() or _as_int(element.get("entry_pointer_value")) != pointer or element.get("unread_tail_raw_hex") != chunk[4:8].hex():
            raise ReferenceError("raw_vector_element_decode_invalid")
        valid_elements.append(element)
    return valid_elements, target_slot


def _replay_direction(direction: Mapping[str, Any], family: str, direction_name: str, source_pointer: int | None, target_fullref: int, owner_cache: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(direction, Mapping):
        return _unknown(family, "raw_direction_missing", direction_name)
    row = direction.get("relation_row")
    if not isinstance(row, Mapping) or not _relation_row_binding_valid(row, source_pointer, target_fullref):
        return _unknown(family, "raw_relation_row_binding_invalid", direction_name)
    key = direction.get("predicate_cache_key")
    if not isinstance(key, str) or not isinstance(owner_cache.get(key), Mapping):
        return _unknown(family, "raw_owner_cache_missing", direction_name)
    cache = owner_cache[key]
    if cache.get("status") != "known" or not isinstance(cache.get("raw"), Mapping):
        return _unknown(family, "raw_owner_vector_unknown", direction_name)
    try:
        elements, target_slot = _vector_raw_valid(cache["raw"], family, row, target_fullref)
    except ReferenceError as exc:
        return _unknown(family, str(exc), direction_name)
    first_match = None
    for element in elements:
        if int.from_bytes(_hex_bytes(element["raw_hex"], "vector.element", 16)[:4], "little") == (target_slot & 0xFFFFFFFF):
            first_match = element
            break
    proof: dict[str, Any] = {
        "family": family,
        "direction": direction_name,
        "leaf_rva": hex(FAMILY_LAYOUT[family]["leaf_rva"]),
        "evidence_id": EVIDENCE_IDS[family],
        "target_slot_signed_i16": target_slot,
        "matching_element_index": first_match.get("index") if first_match is not None else None,
        "native_first_match_only": True,
    }
    if first_match is None:
        return {"status": "known", "family": family, "direction": direction_name, "value": False, "proof": proof, "partial": True, "complete": False, "unit": "relation_state", "scale": 1, "period": "current"}
    if not FAMILY_LAYOUT[family]["record_identity"]:
        proof["value"] = True
        return {"status": "known", "family": family, "direction": direction_name, "value": True, "proof": proof, "partial": True, "complete": False, "unit": "relation_state", "scale": 1, "period": "current"}
    chunk = _hex_bytes(first_match.get("raw_hex"), "guarantee.element", 16)
    pointer = int.from_bytes(chunk[8:16], "little")
    proof["record_pointer"] = {"raw_hex": chunk[8:16].hex(), "value": pointer, "address": deepcopy(first_match.get("address"))}
    if pointer == 0:
        proof.update(value=False, record_pointer_status="null_native_false")
        return {"status": "known", "family": family, "direction": direction_name, "value": False, "proof": proof, "partial": True, "complete": False, "unit": "relation_state", "scale": 1, "period": "current"}
    if not _valid_pointer(pointer):
        return _unknown(family, "raw_record_pointer_invalid", direction_name)
    source_proof = direction.get("proof") if isinstance(direction.get("proof"), Mapping) else {}
    record = source_proof.get("record_fullref") if isinstance(source_proof, Mapping) else None
    if not isinstance(record, Mapping):
        return _unknown(family, "raw_record_fullref_missing", direction_name)
    record_address = _value_va(record.get("address"))
    record_raw = _hex_bytes(record.get("raw_hex"), "guarantee.record_fullref", 8)
    record_value = _as_int(record.get("value"))
    if record_address != pointer + 0x18 or record_value is None or int.from_bytes(record_raw, "little") != record_value:
        return _unknown(family, "raw_record_fullref_binding_invalid", direction_name)
    record_slot = _slot(record_value)
    proof["record_fullref"] = {"address": {"va": hex(record_address)}, "raw_hex": record_raw.hex(), "value": record_value}
    proof["record_slot_signed_i16"] = record_slot
    proof["value"] = record_slot == target_slot
    return {"status": "known", "family": family, "direction": direction_name, "value": record_slot == target_slot, "proof": proof, "partial": True, "complete": False, "unit": "relation_state", "scale": 1, "period": "current"}


def _context_raw(context: Any) -> dict[str, Any]:
    if not isinstance(context, Mapping):
        return {}
    entries = []
    for entry in context.get("entries", []) if isinstance(context.get("entries"), list) else []:
        if isinstance(entry, Mapping):
            fullref = entry.get("fullref") if isinstance(entry.get("fullref"), Mapping) else {}
            entries.append({"index": entry.get("index"), "pointer_raw_hex": entry.get("pointer_raw_hex"), "fullref_raw_hex": fullref.get("raw_hex"), "tag": entry.get("tag"), "slot": entry.get("slot")})
    return {"database": deepcopy(context.get("database")), "game": deepcopy(context.get("game")), "game_date": deepcopy(context.get("game_date")), "country_table": deepcopy(context.get("country_table")), "country_count": deepcopy(context.get("country_count")), "entries": entries, "candidate_failures": deepcopy(context.get("candidate_failures", []))}


def _direction_raw(direction: Any) -> dict[str, Any] | None:
    if not isinstance(direction, Mapping):
        return None
    proof = direction.get("proof") if isinstance(direction.get("proof"), Mapping) else {}
    raw: dict[str, Any] = {"relation_row": deepcopy(direction.get("relation_row")), "predicate_cache_key": direction.get("predicate_cache_key")}
    if isinstance(proof, Mapping) and isinstance(proof.get("record_fullref"), Mapping):
        raw["record_fullref"] = deepcopy(proof["record_fullref"])
    return raw


def _raw_projection(pass_record: Mapping[str, Any], network: bool, families: list[str]) -> dict[str, Any]:
    projection: dict[str, Any] = {"context": _context_raw(pass_record.get("context")), "runtime_code_guard": deepcopy((pass_record.get("runtime_code_guard") or {}).get("records", [])), "owner_cache": {key: deepcopy(value.get("raw")) if isinstance(value, Mapping) else None for key, value in (pass_record.get("owner_cache") or {}).items()}, "candidate_failures": deepcopy(pass_record.get("candidate_failures", []))}
    if network:
        projection["targets"] = deepcopy(pass_record.get("targets", []))
        projection["fields"] = {}
        for family in families:
            field = (pass_record.get("fields") or {}).get(family)
            if isinstance(field, Mapping):
                projection["fields"][family] = [{"country": row.get("country"), "fullref_hex": row.get("fullref_hex"), "slot": row.get("slot"), "forward": _direction_raw(row.get("forward")), "reverse": _direction_raw(row.get("reverse"))} for row in field.get("rows", []) if isinstance(row, Mapping)]
            else:
                projection["fields"][family] = None
    else:
        projection["targets"] = deepcopy(pass_record.get("targets", []))
        projection["fields"] = {}
        for family in families:
            field = (pass_record.get("fields") or {}).get(family)
            projection["fields"][family] = [{"country": row.get("country"), "fullref_hex": row.get("fullref_hex"), "slot": row.get("slot"), "forward": _direction_raw(row.get("forward")), "reverse": _direction_raw(row.get("reverse"))} for row in field.get("rows", [])] if isinstance(field, Mapping) and isinstance(field.get("rows"), list) else None
    return projection


def _replay_pass(pass_record: Mapping[str, Any], request: Mapping[str, Any], families: list[str], network: bool) -> dict[str, Any]:
    context = pass_record.get("context") if isinstance(pass_record.get("context"), Mapping) else {}
    actor = request.get("actor", "FRA")
    owner_cache = pass_record.get("owner_cache") if isinstance(pass_record.get("owner_cache"), Mapping) else {}
    fields: dict[str, Any] = {}
    actor_entry = _context_entry(context, actor)
    actor_pointer = _value_va(actor_entry.get("pointer")) if isinstance(actor_entry, Mapping) else None
    if actor_entry is None or actor_pointer is None:
        return {family: _unknown(family, "independent_actor_entry_missing") for family in families}
    rows_by_family: dict[str, list[dict[str, Any]]] = {family: [] for family in families}
    active_by_family: dict[str, list[dict[str, Any]]] = {family: [] for family in families}
    unknown_by_family: dict[str, list[dict[str, Any]]] = {family: [] for family in families}
    source_rows: dict[str, dict[str, Mapping[str, Any]]] = {family: {} for family in families}
    if network:
        for family in families:
            field = (pass_record.get("fields") or {}).get(family)
            if isinstance(field, Mapping) and isinstance(field.get("rows"), list):
                for row in field["rows"]:
                    if isinstance(row, Mapping) and isinstance(row.get("country"), str):
                        source_rows[family][row["country"]] = row
        target_tags = sorted(set(tag for mapping in source_rows.values() for tag in mapping))
    else:
        recipient = request.get("recipient")
        target_tags = [recipient] if isinstance(recipient, str) else []
        for family in families:
            field = (pass_record.get("fields") or {}).get(family)
            if isinstance(field, Mapping) and isinstance(field.get("rows"), list) and field["rows"]:
                row = field["rows"][0]
                if isinstance(row, Mapping) and isinstance(row.get("country"), str):
                    source_rows[family][row["country"]] = row
    for tag in target_tags:
        if tag == actor:
            continue
        target_entry = _context_entry(context, tag)
        target_pointer = _value_va(target_entry.get("pointer")) if isinstance(target_entry, Mapping) else None
        target_fullref = _fullref_value(target_entry) if isinstance(target_entry, Mapping) else None
        actor_fullref = _fullref_value(actor_entry)
        for family in families:
            source_row = source_rows[family].get(tag)
            if target_entry is None or target_pointer is None or target_fullref is None or actor_fullref is None or not isinstance(source_row, Mapping):
                unknown = {"country": tag, "fullref_hex": None, "slot": None, "reason": "independent_target_binding_missing"}
                unknown_by_family[family].append(unknown)
                rows_by_family[family].append({"country": tag, "fullref_hex": None, "slot": None, "forward": _unknown(family, unknown["reason"], "forward"), "reverse": _unknown(family, unknown["reason"], "reverse")})
                continue
            fullref_hex = (target_entry.get("fullref") or {}).get("raw_hex")
            slot = _slot(target_fullref)
            forward = _replay_direction(source_row.get("forward"), family, "forward", actor_pointer, target_fullref, owner_cache)
            reverse = _replay_direction(source_row.get("reverse"), family, "reverse", target_pointer, actor_fullref, owner_cache)
            row_out = {"country": tag, "fullref_hex": fullref_hex, "slot": slot, "forward": forward, "reverse": reverse}
            rows_by_family[family].append(row_out)
            for direction in (forward, reverse):
                if direction.get("status") != "known":
                    unknown_by_family[family].append({"country": tag, "direction": direction.get("direction"), "reason": direction.get("reason", "unknown")})
                elif direction.get("value") is True:
                    active_by_family[family].append({"country": tag, "fullref_hex": fullref_hex, "slot": slot, "direction": direction.get("direction"), "active": True})
    candidate_failures = pass_record.get("candidate_failures", []) if isinstance(pass_record.get("candidate_failures"), list) else [{"reason": "candidate_failure_shape_invalid"}]
    for family in families:
        unknown = unknown_by_family[family]
        fields[family] = {"status": "known" if not unknown and not candidate_failures else "partial", "family": family, "value": active_by_family[family], "rows": rows_by_family[family], "unknown_rows": unknown, "candidate_failures": deepcopy(candidate_failures), "partial": True, "complete": False, "unit": "relation_state", "scale": 1, "period": "current", "direction_labels": {"forward": "actor_row_to_target", "reverse": "target_row_to_actor"}, "basis": "independent_replay_of_current_directed_row_predicate", "value_origin": "copied_native_row_and_owner_vector_raw"}
    return fields


def reference(report: Mapping[str, Any]) -> dict[str, Any]:
    request = report.get("request", {}) if isinstance(report, Mapping) else {}
    families = [family for family in request.get("families", FAMILIES) if family in FAMILIES] if isinstance(request, Mapping) else list(FAMILIES)
    if not families:
        families = list(FAMILIES)
    network = isinstance(request, Mapping) and request.get("mode") == "network"
    before = report.get("before") if isinstance(report, Mapping) else None
    after = report.get("after") if isinstance(report, Mapping) else None
    raw_ok = isinstance(before, Mapping) and isinstance(after, Mapping) and _raw_projection(before, network, families) == _raw_projection(after, network, families)
    if raw_ok and isinstance(after, Mapping):
        fields = _replay_pass(after, request, families, network)
    else:
        fields = {family: _unknown(family, "independent_two_pass_raw_mismatch") for family in families}
    identity = deepcopy(report.get("identity")) if isinstance(report, Mapping) and isinstance(report.get("identity"), Mapping) else None
    identity_ok = isinstance(identity, Mapping) and identity.get("binding_verified") is True and identity.get("process_path_sha256_matches_expected") is True
    cleanup_ok = isinstance(report, Mapping) and isinstance(report.get("cleanup"), Mapping) and report["cleanup"].get("handle_close", {}).get("closed") is True
    context_after = after.get("context") if isinstance(after, Mapping) and isinstance(after.get("context"), Mapping) else {}
    game_date = context_after.get("game_date", {}).get("value") if isinstance(context_after.get("game_date"), Mapping) else None
    binding_context = {"session_id": identity.get("installation_session_id") if isinstance(identity, Mapping) else None, "process_creation_filetime": identity.get("process_creation_filetime") if isinstance(identity, Mapping) else None, "game_date": game_date, "observer": request.get("actor") if isinstance(request, Mapping) else None}
    unknown_conditions = ["direction remains forward/reverse; public grantor/recipient projection is intentionally deferred", "relation dates/expiry are not read by either leaf"]
    if network:
        unknown_conditions.append("offline owner-vector scan is separate from pair runtime witnesses and does not prove an active relationship")
    else:
        unknown_conditions.append("pair replay preserves native first-match and guarantee record-slot semantics; no public role is inferred from the boolean alone")
    return {
        "schema": "information_directed_relations_independent_reference.v1",
        "independent": True,
        "production_reader_imported": False,
        "profile_imported": False,
        "source_pins": {"files": deepcopy(SOURCE_PINS), "evidence_ids": deepcopy(EVIDENCE_IDS), "executable_sha256": EXE_SHA256},
        "request": deepcopy(request),
        "identity": identity,
        "context": binding_context,
        "raw_two_pass_consistent": raw_ok,
        "identity_binding_verified": identity_ok,
        "handle_closed": cleanup_ok,
        "fields": fields,
        "static_role_map": {"status": "static_only", "military_access": {"forward": "received", "reverse": "granted"}, "guarantee": {"forward": "granted", "reverse": "received"}, "runtime_role_projection": False},
        "status": "observed" if raw_ok and identity_ok and cleanup_ok else "unknown",
        "complete": False,
        "read_only": True,
        "native_game_calls": False,
        "target_memory_writes": False,
        "unknown_conditions": unknown_conditions,
    }


def _compact_field(field: Any) -> dict[str, Any]:
    """Project a replayed field without copying its raw rows or vectors."""
    if not isinstance(field, Mapping):
        return {"status": "unknown", "value": [], "row_count": 0, "unknown_row_count": 1}
    active = field.get("value") if isinstance(field.get("value"), list) else []
    values: list[dict[str, Any]] = []
    for item in active:
        if not isinstance(item, Mapping):
            continue
        values.append({"country": item.get("country"), "slot": item.get("slot"), "fullref_hex": item.get("fullref_hex"), "direction": item.get("direction"), "active": True})
    unknown = field.get("unknown_rows") if isinstance(field.get("unknown_rows"), list) else []
    rows = field.get("rows") if isinstance(field.get("rows"), list) else []
    row_count = field.get("candidate_count") if isinstance(field.get("candidate_count"), int) else len(rows)
    return {
        "status": field.get("status", "unknown"),
        "value": values,
        "row_count": row_count,
        "unknown_row_count": len(unknown),
    }


def compact_reference(result: Mapping[str, Any], source_raw: Mapping[str, Any]) -> dict[str, Any]:
    """Return the consumer-sized expected projection; raw rows stay in the input pin."""
    fields = result.get("fields") if isinstance(result.get("fields"), Mapping) else {}
    context = result.get("context") if isinstance(result.get("context"), Mapping) else {}
    game_date = context.get("game_date")
    compact_fields = {family: _compact_field(fields.get(family)) for family in FAMILIES if family in fields}
    return {
        "schema": "information_directed_relations_independent_reference.compact.v1",
        "independent": True,
        "production_reader_imported": False,
        "profile_imported": False,
        "read_only": True,
        "native_game_calls": False,
        "target_build": {"version": VERSION, "executable_sha256": EXE_SHA256, "image_base": hex(IMAGE_BASE)},
        "request": deepcopy(result.get("request")),
        "status": result.get("status", "unknown"),
        "complete": bool(result.get("complete", False)),
        "partial": True,
        "raw_two_pass_consistent": bool(result.get("raw_two_pass_consistent", False)),
        "identity_binding_verified": bool(result.get("identity_binding_verified", False)),
        "handle_closed": bool(result.get("handle_closed", False)),
        "fields": compact_fields,
        "identity": deepcopy(result.get("identity")),
        "context": deepcopy(result.get("context")),
        "date": deepcopy(game_date),
        "source_raw": deepcopy(source_raw),
        "source_pins": deepcopy(result.get("source_pins")),
        "static_role_map": deepcopy(result.get("static_role_map")),
        "unknown_conditions": deepcopy(result.get("unknown_conditions", [])),
    }


def _scan_json_bytes(data: bytes, state: tuple[bool, bool, int]) -> tuple[bool, bool, int]:
    in_string, escaped, depth = state
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
        else:
            if byte == 0x22:
                in_string = True
            elif byte in (0x7B, 0x5B):
                depth += 1
            elif byte in (0x7D, 0x5D):
                depth -= 1
    return in_string, escaped, depth


def _json_key(line: bytes, indent: int) -> str:
    colon = line.find(b":")
    if colon < 0:
        raise ReferenceError("json_key_missing_colon")
    value = json.loads(line[indent:colon].strip().decode("utf-8"))
    if not isinstance(value, str):
        raise ReferenceError("json_key_not_string")
    return value


def _read_value_after_colon(stream: Any, line: bytes, cap: int) -> Any:
    colon = line.find(b":")
    if colon < 0:
        raise ReferenceError("json_value_missing_colon")
    initial = line[colon + 1 :].lstrip()
    if not initial:
        raise ReferenceError("json_value_empty")
    if initial[:1] not in (b"{", b"["):
        return json.loads(initial.rstrip().rstrip(b",").rstrip().decode("utf-8"))
    buffer = bytearray(initial)
    state = _scan_json_bytes(initial, (False, False, 0))
    while state[2] > 0:
        chunk = stream.readline()
        if not chunk:
            raise ReferenceError("json_value_truncated")
        buffer.extend(chunk)
        if len(buffer) > cap:
            raise ReferenceError(f"json_value_over_cap:{len(buffer)}>{cap}")
        state = _scan_json_bytes(chunk, state)
    return json.loads(bytes(buffer).rstrip().rstrip(b",").rstrip().decode("utf-8"))


def _stream_report(path: Path) -> dict[str, Any]:
    """Read a large report one top-level value at a time."""
    cap = 48 * 1024 * 1024
    result: dict[str, Any] = {}
    with path.open("rb") as stream:
        if stream.readline().strip() != b"{":
            raise ReferenceError("json_root_not_object")
        while True:
            line = stream.readline()
            if not line:
                raise ReferenceError("json_root_truncated")
            if line.strip() == b"}":
                break
            if not line.strip() or line.strip() == b",":
                continue
            if not line.startswith(b"  ") or line.startswith(b"    "):
                raise ReferenceError("json_top_level_indent_invalid")
            key = _json_key(line, 2)
            result[key] = _read_value_after_colon(stream, line, cap)
    return result


def _write_once(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"output_exists:{path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Independently replay directed relation raw bytes")
    parser.add_argument("--run", action="store_true", help="explicitly permit offline raw replay and output generation")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    if not args.run:
        print(json.dumps({"status": "ready", "run_required": True, "would_read_input": False, "output": str(args.output)}, ensure_ascii=False))
        return 0
    try:
        raw = _stream_report(args.input)
        result = reference(raw)
        source_raw = {"path": str(args.input), "size_bytes": args.input.stat().st_size, "sha256": _sha256_file(args.input), "streamed_top_level": True}
        compact = compact_reference(result, source_raw)
        _write_once(args.output, compact)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"directed_relation_reference_error:{exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": compact.get("status"), "raw_two_pass_consistent": compact.get("raw_two_pass_consistent"), "output": str(args.output), "source_bytes": source_raw["size_bytes"], "source_sha256": source_raw["sha256"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
