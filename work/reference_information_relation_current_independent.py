"""Independent raw replay for ``probe_information_relation_current_independent``.

The replay never imports the production relation reader/profile and never
copies a computed ``status`` or ``value``.  It derives membership from the
recipient fullref bytes and the captured first DWORD of each 16-byte vector
element.  Network rows that were not resolvable remain unknown.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Mapping


EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
SOURCE002_SHA256 = "31b786d242753f8849e0f2efee483d429a4a801eae0b6ef25d17245d5a5d3d41"
CONTRACT003_SHA256 = "3f95459d1be842cd8ed2c8e200c9ca2d1de4605a2c093484737c976290cccb73"
FAMILIES = ("alliance", "royal_marriage")
RELATION_TABLE_OFFSET = 0x1510
RELATION_ROW_STRIDE = 0x48
MAX_USER_ADDRESS = 0x0000800000000000


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


def _hex_bytes(raw: Any, size: int | None = None) -> bytes | None:
    if not isinstance(raw, str) or len(raw) % 2:
        return None
    try:
        value = bytes.fromhex(raw)
    except ValueError:
        return None
    if size is not None and len(value) != size:
        return None
    return value


def _unknown(family: str, reason: str) -> dict[str, Any]:
    return {"status": "unknown", "family": family, "value": None, "reason": reason, "partial": True, "complete": False, "unit": "relation_state", "scale": 1, "period": "current"}


def _fullref_from_entry(entry: Mapping[str, Any]) -> int | None:
    return _as_int((entry.get("fullref") or {}).get("value"))


def _match_entry(matches: Any, tag: str) -> Mapping[str, Any] | None:
    if not isinstance(matches, Mapping):
        return None
    value = matches.get(tag)
    if isinstance(value, Mapping):
        return value
    if isinstance(value, list) and len(value) == 1 and isinstance(value[0], Mapping):
        return value[0]
    return None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _slot(fullref: int) -> int:
    value = (fullref >> 32) & 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def _valid_pointer(value: Any) -> bool:
    return isinstance(value, int) and 0x10000 <= value < MAX_USER_ADDRESS and value % 8 == 0


def _relation_row_binding_valid(relation_row: Mapping[str, Any], actor_pointer: int | None, recipient_fullref: int) -> bool:
    if actor_pointer is None or not _valid_pointer(actor_pointer):
        return False
    table = relation_row.get("relation_table")
    if not isinstance(table, Mapping):
        return False
    table_address = _as_int((table.get("address") or {}).get("va"))
    table_pointer = _as_int(table.get("value"))
    table_raw = _hex_bytes(table.get("raw_hex"), 8)
    if table_address != actor_pointer + RELATION_TABLE_OFFSET or not _valid_pointer(table_pointer) or table_raw is None or int.from_bytes(table_raw, "little") != table_pointer:
        return False
    row_address = _as_int((relation_row.get("address") or {}).get("va"))
    row_fullref = _as_int((relation_row.get("recipient_fullref") or {}).get("value"))
    row_fullref_raw = _hex_bytes((relation_row.get("recipient_fullref") or {}).get("raw_hex"), 8)
    expected_row = table_pointer + _slot(recipient_fullref) * RELATION_ROW_STRIDE
    return row_address == expected_row and row_fullref == recipient_fullref and row_fullref_raw is not None and int.from_bytes(row_fullref_raw, "little") == recipient_fullref


def _replay_pair_field(field: Mapping[str, Any], family: str, recipient_fullref: int, relation_row: Mapping[str, Any], actor_pointer: int | None) -> dict[str, Any]:
    if not _relation_row_binding_valid(relation_row, actor_pointer, recipient_fullref):
        return _unknown(family, "raw_relation_row_binding_invalid")
    raw = field.get("raw")
    if not isinstance(raw, Mapping):
        return _unknown(family, "raw_field_missing")
    raw_fullref = _as_int((raw.get("recipient_fullref") or {}).get("value"))
    if raw_fullref is None or raw_fullref != recipient_fullref:
        return _unknown(family, "raw_recipient_fullref_mismatch")
    expected_slot = _slot(recipient_fullref)
    if raw.get("recipient_slot_signed_i16") != expected_slot:
        return _unknown(family, "raw_recipient_slot_mismatch")
    count_raw = _hex_bytes((raw.get("vector_count") or {}).get("raw_hex"), 4)
    begin_raw = _hex_bytes((raw.get("vector_begin") or {}).get("raw_hex"), 8)
    elements = raw.get("elements")
    if count_raw is None or begin_raw is None or not isinstance(elements, list):
        return _unknown(family, "raw_vector_shape_invalid")
    count = int.from_bytes(count_raw, "little", signed=True)
    begin = int.from_bytes(begin_raw, "little")
    if count < 0 or count > 4096 or len(elements) != count:
        return _unknown(family, "raw_vector_count_invalid")
    matches = []
    for index, element in enumerate(elements):
        if not isinstance(element, Mapping) or element.get("index") != index:
            return _unknown(family, "raw_element_index_invalid")
        chunk = _hex_bytes(element.get("raw_hex"), 16)
        address = _as_int((element.get("address") or {}).get("va"))
        if chunk is None or address is None or address != begin + index * 16:
            return _unknown(family, "raw_element_binding_invalid")
        first = int.from_bytes(chunk[:4], "little")
        if first != _as_int(element.get("first_dword")) or element.get("first_dword_raw_hex") != chunk[:4].hex() or element.get("unread_tail_raw_hex") != chunk[4:].hex():
            return _unknown(family, "raw_element_decode_mismatch")
        if first == (expected_slot & 0xFFFFFFFF):
            matches.append(index)
    return {"status": "known", "family": family, "value": bool(matches), "unit": "relation_state", "scale": 1, "period": "current", "partial": True, "complete": False, "basis": "native_current_selected_pair_relation_predicate", "value_origin": "independent_replay_of_copied_relation_row_and_owner_vector", "raw": deepcopy(raw), "proof": {"matching_element_indices": matches, "offer": False}}


def _raw_projection(pass_record: Mapping[str, Any], network: bool) -> dict[str, Any]:
    """Keep only evidence bytes/addresses; exclude computed values and statuses."""
    context = pass_record.get("context") if isinstance(pass_record.get("context"), Mapping) else {}
    context_raw = {
        "database": deepcopy(context.get("database")),
        "game": deepcopy(context.get("game")),
        "game_date": deepcopy(context.get("game_date")),
        "country_table": deepcopy(context.get("country_table")),
        "country_count": deepcopy(context.get("country_count")),
        "entries": [
            {
                "index": entry.get("index"),
                "pointer_raw_hex": entry.get("pointer_raw_hex"),
                "fullref_raw_hex": (entry.get("fullref") or {}).get("raw_hex") if isinstance(entry, Mapping) else None,
            }
            for entry in context.get("entries", [])
            if isinstance(entry, Mapping)
        ],
    }
    guard = pass_record.get("runtime_code_guard") if isinstance(pass_record.get("runtime_code_guard"), Mapping) else {}
    projection: dict[str, Any] = {
        "context": context_raw,
        "runtime_code_guard": deepcopy(guard.get("records", [])),
    }
    if network:
        projection["targets"] = [{"index": target.get("index"), "country": target.get("country"), "fullref_hex": target.get("fullref_hex"), "slot": target.get("slot"), "country_pointer": deepcopy(target.get("country_pointer"))} for target in pass_record.get("targets", []) if isinstance(target, Mapping)]
        projection["owner_cache"] = {key: deepcopy(value.get("raw")) if isinstance(value, Mapping) else None for key, value in (pass_record.get("owner_cache", {}) or {}).items()}
        projection["rows"] = {}
        for family, field in (pass_record.get("fields") or {}).items():
            projection["rows"][family] = [{"country": row.get("country"), "fullref_hex": row.get("fullref_hex"), "slot": row.get("slot"), "relation_row": deepcopy(row.get("relation_row")), "predicate_cache_key": row.get("predicate_cache_key")} for row in field.get("rows", [])] if isinstance(field, Mapping) else None
    else:
        projection["relation_row"] = deepcopy(pass_record.get("relation_row"))
        projection["fields"] = {family: deepcopy(field.get("raw")) if isinstance(field, Mapping) else None for family, field in (pass_record.get("fields") or {}).items()}
    return projection


def _replay_network(report: Mapping[str, Any], pass_record: Mapping[str, Any], families: list[str]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    candidate_failures = pass_record.get("candidate_failures", [])
    if not isinstance(candidate_failures, list):
        candidate_failures = [{"reason": "candidate_failure_shape_invalid"}]
    cache = pass_record.get("owner_cache", {})
    if not isinstance(cache, Mapping):
        cache = {}
        candidate_failures = list(candidate_failures) + [{"reason": "owner_cache_shape_invalid"}]
    for family in families:
        source_field = (pass_record.get("fields") or {}).get(family)
        if not isinstance(source_field, Mapping) or not isinstance(source_field.get("rows"), list):
            fields[family] = _unknown(family, "raw_network_rows_missing")
            continue
        rows = []
        active = []
        unknown_rows = []
        for source_row in source_field["rows"]:
            if not isinstance(source_row, Mapping):
                unknown_rows.append({"reason": "raw_network_row_invalid"})
                continue
            out = {"country": source_row.get("country"), "fullref_hex": source_row.get("fullref_hex"), "slot": source_row.get("slot"), "relation_row": deepcopy(source_row.get("relation_row")), "status": "unknown", "active": None, "predicate_cache_key": source_row.get("predicate_cache_key")}
            fullref_raw = _hex_bytes(source_row.get("fullref_hex"), 8)
            fullref = int.from_bytes(fullref_raw, "little") if fullref_raw is not None else None
            slot = _as_int(source_row.get("slot"))
            relation_row = source_row.get("relation_row")
            key = source_row.get("predicate_cache_key")
            cached = cache.get(key) if isinstance(key, str) else None
            if fullref is None or slot is None or slot != ((fullref >> 32) & 0xFFFF) or not isinstance(relation_row, Mapping) or cached is None:
                out["reason"] = "raw_network_row_binding_invalid"
                unknown_rows.append({"country": out["country"], "fullref_hex": out["fullref_hex"], "slot": out["slot"], "reason": out["reason"]})
                rows.append(out)
                continue
            row_fullref = _as_int((relation_row.get("recipient_fullref") or {}).get("value"))
            row_address = _as_int((relation_row.get("address") or {}).get("va"))
            context = pass_record.get("context") or {}
            actor = context.get("actor") if isinstance(context, Mapping) else None
            if not isinstance(actor, Mapping):
                request = report.get("request") if isinstance(report, Mapping) else None
                actor_tag = request.get("actor", "FRA") if isinstance(request, Mapping) else "FRA"
                actor = _match_entry(context.get("matches"), actor_tag) if isinstance(context, Mapping) else None
            actor_ptr = _as_int((actor.get("pointer") or {}).get("va")) if isinstance(actor, Mapping) else None
            elements = (cached.get("raw") or {}).get("elements") if isinstance(cached, Mapping) else None
            if not _relation_row_binding_valid(relation_row, actor_ptr, fullref) or row_fullref != fullref or row_address is None or not isinstance(elements, list):
                out["reason"] = "raw_network_relation_binding_invalid"
                unknown_rows.append({"country": out["country"], "fullref_hex": out["fullref_hex"], "slot": out["slot"], "reason": out["reason"]})
                rows.append(out)
                continue
            expected_slot = _slot(fullref)
            matches = []
            valid = True
            for element in elements:
                if not isinstance(element, Mapping):
                    valid = False
                    break
                chunk = _hex_bytes(element.get("raw_hex"), 16)
                if chunk is None:
                    valid = False
                    break
                if int.from_bytes(chunk[:4], "little") == (expected_slot & 0xFFFFFFFF):
                    matches.append(element.get("index"))
            if not valid:
                out["reason"] = "raw_network_cache_element_invalid"
                unknown_rows.append({"country": out["country"], "fullref_hex": out["fullref_hex"], "slot": out["slot"], "reason": out["reason"]})
                rows.append(out)
                continue
            out.update(status="known", active=bool(matches), predicate={"matching_element_indices": matches, "value": bool(matches)})
            if out["active"]:
                active.append({"country": out["country"], "fullref_hex": out["fullref_hex"], "slot": out["slot"], "active": True})
            rows.append(out)
        fields[family] = {"status": "known" if not unknown_rows and not candidate_failures else "partial", "family": family, "value": active, "rows": rows, "unknown_rows": unknown_rows, "candidate_failures": deepcopy(candidate_failures), "partial": True, "complete": False, "unit": "relation_state", "scale": 1, "period": "current"}
    return fields


def reference(report: Mapping[str, Any]) -> dict[str, Any]:
    request = report.get("request", {}) if isinstance(report, Mapping) else {}
    families = [family for family in request.get("families", FAMILIES) if family in FAMILIES] if isinstance(request, Mapping) else list(FAMILIES)
    mode = request.get("mode") if isinstance(request, Mapping) else "pair"
    network = mode == "network"
    before = report.get("before") if isinstance(report, Mapping) else None
    after = report.get("after") if isinstance(report, Mapping) else None
    raw_ok = isinstance(before, Mapping) and isinstance(after, Mapping) and _raw_projection(before, network) == _raw_projection(after, network)
    fields: dict[str, Any] = {}
    if not raw_ok:
        fields = {family: _unknown(family, "independent_two_pass_raw_mismatch") for family in families}
    elif network:
        fields = _replay_network(report, after, families)
    else:
        context = after.get("context") or {}
        recipient_entry = _match_entry(context.get("matches"), request.get("recipient")) if isinstance(context, Mapping) and isinstance(request.get("recipient"), str) else None
        actor_entry = _match_entry(context.get("matches"), request.get("actor")) if isinstance(context, Mapping) and isinstance(request.get("actor"), str) else None
        recipient_fullref = _fullref_from_entry(recipient_entry) if isinstance(recipient_entry, Mapping) else None
        actor_pointer = _as_int((actor_entry.get("pointer") or {}).get("va")) if isinstance(actor_entry, Mapping) else None
        relation_row = after.get("relation_row") if isinstance(after, Mapping) else None
        if recipient_fullref is None:
            fields = {family: _unknown(family, "independent_recipient_fullref_missing") for family in families}
        else:
            for family in families:
                source = (after.get("fields") or {}).get(family)
                fields[family] = _replay_pair_field(source, family, recipient_fullref, relation_row, actor_pointer) if isinstance(source, Mapping) and isinstance(relation_row, Mapping) else _unknown(family, "independent_raw_relation_row_missing")
    identity_ok = isinstance(report, Mapping) and isinstance(report.get("identity"), Mapping) and report["identity"].get("binding_verified") is True
    cleanup_ok = isinstance(report, Mapping) and report.get("cleanup", {}).get("handle_close", {}).get("closed") is True
    identity = deepcopy(report.get("identity")) if isinstance(report, Mapping) and isinstance(report.get("identity"), Mapping) else None
    context_after = after.get("context") if isinstance(after, Mapping) and isinstance(after.get("context"), Mapping) else {}
    game_date = context_after.get("game_date", {}).get("value") if isinstance(context_after.get("game_date"), Mapping) else None
    binding_context = {
        "session_id": identity.get("installation_session_id") if isinstance(identity, Mapping) else None,
        "process_creation_filetime": identity.get("process_creation_filetime") if isinstance(identity, Mapping) else None,
        "game_date": game_date,
        "observer": request.get("actor") if isinstance(request, Mapping) else None,
    }
    return {"schema": "information_relation_independent_reference.v1", "independent": True, "production_reader_imported": False, "source_pins": {"source002_sha256": SOURCE002_SHA256, "contract003_sha256": CONTRACT003_SHA256, "executable_sha256": EXE_SHA256}, "request": deepcopy(request), "identity": identity, "context": binding_context, "raw_two_pass_consistent": raw_ok, "identity_binding_verified": identity_ok, "handle_closed": cleanup_ok, "fields": fields, "status": "observed" if raw_ok and identity_ok and cleanup_ok else "unknown", "complete": False, "read_only": True, "native_game_calls": False, "unknown_conditions": ["relation expiry/start dates remain outside direct leaf bytes", "remaining element bytes are preserved but not interpreted"]}


def _write_once(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"output_exists:{path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Independently replay relation bytes from a raw probe report")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.input.stat().st_size > 16 * 1024 * 1024:
            raise OSError("input_too_large")
        with args.input.open("r", encoding="utf-8") as stream:
            raw = json.load(stream)
        result = reference(raw)
        result["source_raw"] = {"path": str(args.input), "size_bytes": args.input.stat().st_size, "sha256": _sha256_file(args.input)}
        _write_once(args.output, result)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"independent_relation_reference_error:{exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": "observed", "output": str(args.output)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
