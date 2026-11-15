"""Bounded offline replay for the retained fleet-basing raw capture.

The input is intentionally larger than ten MiB.  This module never calls
json.load on it: the top-level actor map is walked from a buffered binary
stream and each actor value is decoded separately, with a 24 MiB cap.  The
probe's computed status and active values are not used as evidence.  Country
and fullref bindings, relation rows, vector bytes, and received-agreement
bytes are checked and the two predicates are replayed from those raw fields.

This is an offline reference.  It does not import a production reader, open a
process, call a native function, or infer a direction, expiry, or business
role.  The current capture has no positive sample; an empty active list
remains a raw replay result, while any unresolvable row remains unknown rather
than being converted to False.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-relation-remaining-20261027-001"
DEFAULT_INPUT = STAGE / "fleet-basing-current-inputs-001.json"
DEFAULT_OUTPUT = STAGE / "expected-fleet-basing-current-001.json"
DEFAULT_RECEIPT = STAGE / "fleet-basing-reference-receipt-001.json"

VERSION = "1.37.4"
EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
FLEET_SOURCE002_SHA256 = "90dc23321e41458e13875d5a74ba85f0845214897da77ce546aed96ab1a7ce04"
RELATION_CONTRACT003_SHA256 = "3f95459d1be842cd8ed2c8e200c9ca2d1de4605a2c093484737c976290cccb73"
IMAGE_BASE = 0x140000000

MAX_ACTOR_BYTES = 24 * 1024 * 1024
MAX_TOP_VALUE_BYTES = 32 * 1024 * 1024
MAX_COUNTRIES = 4096
MAX_VECTOR_COUNT = 4096
MAX_USER_ADDRESS = 0x0000800000000000
NULL_COUNTRY_FULLREF_RAW_HEX = "2d2d2d0000000000"
RELATION_TABLE_OFFSET = 0x1510
RELATION_ROW_STRIDE = 0x48
FAMILIES = ("received", "granted")


class ReferenceError(ValueError):
    """The retained raw record does not satisfy its binding contract."""


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


def _field_raw(field: Any, label: str, width: int, *, signed: bool = False) -> tuple[int, bytes]:
    if not isinstance(field, Mapping):
        raise ReferenceError(f"field_missing:{label}")
    raw = _hex_bytes(field.get("raw_hex"), label, width)
    value = int.from_bytes(raw, "little", signed=signed)
    reported = _as_int(field.get("value"))
    if reported is not None and reported != value:
        raise ReferenceError(f"field_value_mismatch:{label}")
    return value, raw


def _valid_pointer(value: Any) -> bool:
    return isinstance(value, int) and 0x10000 <= value < MAX_USER_ADDRESS and value % 8 == 0


def _signed_i16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def _tag_slot(raw: bytes) -> tuple[str | None, int | None]:
    if len(raw) != 8 or raw[3] != 0:
        return None, None
    if not all(0x41 <= byte <= 0x5A or 0x30 <= byte <= 0x39 for byte in raw[:3]):
        return None, None
    return raw[:3].decode("ascii"), int.from_bytes(raw[4:6], "little")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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
        raw = initial.rstrip().rstrip(b",").rstrip()
        return json.loads(raw.decode("utf-8"))
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
    raw = bytes(buffer).rstrip().rstrip(b",").rstrip()
    return json.loads(raw.decode("utf-8"))


def _stream_source(path: Path, on_actor: Callable[[str, Mapping[str, Any]], None]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Stream the top-level record and callback once per bounded actor object."""
    metadata: dict[str, Any] = {}
    actor_metadata: dict[str, Any] = {}
    with path.open("rb") as stream:
        if stream.readline().strip() != b"{":
            raise ReferenceError("json_root_not_object")
        while True:
            line = stream.readline()
            if not line:
                raise ReferenceError("json_top_level_truncated")
            if line.strip() == b"}":
                break
            if not line.strip() or line.strip() == b",":
                continue
            if not line.startswith(b"  ") or line.startswith(b"    "):
                raise ReferenceError("json_top_level_indent_invalid")
            key = _json_key(line, 2)
            if key != "actors":
                metadata[key] = _read_value_after_colon(stream, line, MAX_TOP_VALUE_BYTES)
                continue
            colon = line.find(b":")
            if line[colon + 1 :].strip() != b"{":
                raise ReferenceError("actors_value_not_object")
            while True:
                actor_line = stream.readline()
                if not actor_line:
                    raise ReferenceError("actors_map_truncated")
                if actor_line.startswith(b"  ") and not actor_line.startswith(b"    ") and actor_line.strip() in (b"},", b"}"):
                    break
                if not actor_line.strip() or actor_line.strip() == b",":
                    continue
                if not actor_line.startswith(b"    "):
                    raise ReferenceError("actor_key_indent_invalid")
                actor_key = _json_key(actor_line, 4)
                actor_value = _read_value_after_colon(stream, actor_line, MAX_ACTOR_BYTES)
                if not isinstance(actor_value, Mapping):
                    raise ReferenceError(f"actor_value_not_object:{actor_key}")
                if "before" in actor_value and "after" in actor_value:
                    on_actor(actor_key, actor_value)
                else:
                    actor_metadata[actor_key] = actor_value
            metadata["actors_metadata"] = actor_metadata
    return metadata, actor_metadata


def _context(pass_record: Mapping[str, Any], actor: str) -> dict[str, Any]:
    context = pass_record.get("context")
    if not isinstance(context, Mapping):
        raise ReferenceError("context_missing")
    entries = context.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ReferenceError("context_entries_missing")
    count, count_raw = _field_raw(context.get("country_count"), "country_count", 4, signed=True)
    if count <= 0 or count > MAX_COUNTRIES or len(entries) != count:
        raise ReferenceError("context_country_count_invalid")
    table_value, table_raw = _field_raw(context.get("country_table"), "country_table", 8)
    database_value, database_raw = _field_raw(context.get("database"), "database", 8)
    game_value, game_raw = _field_raw(context.get("game"), "game", 8)
    date_value, date_raw = _field_raw(context.get("game_date"), "game_date", 4, signed=True)
    if not _valid_pointer(table_value):
        raise ReferenceError("context_country_table_invalid")
    if not _valid_pointer(database_value):
        raise ReferenceError("context_database_invalid")
    if not _valid_pointer(game_value):
        raise ReferenceError("context_game_invalid")
    normalized_entries: list[dict[str, Any]] = []
    by_tag: dict[str, dict[str, Any]] = {}
    by_fullref: dict[str, dict[str, Any]] = {}
    failures: list[dict[str, Any]] = []
    for expected_index, entry in enumerate(entries):
        if not isinstance(entry, Mapping) or _as_int(entry.get("index")) != expected_index:
            failures.append({"index": expected_index, "reason": "country_entry_index_invalid"})
            continue
        pointer_raw = _hex_bytes(entry.get("pointer_raw_hex"), f"entry[{expected_index}].pointer", 8)
        pointer = int.from_bytes(pointer_raw, "little")
        reported_pointer = _as_int((entry.get("pointer") or {}).get("va")) if isinstance(entry.get("pointer"), Mapping) else None
        if reported_pointer is not None and reported_pointer != pointer:
            failures.append({"index": expected_index, "reason": "country_pointer_value_mismatch"})
        full_field = entry.get("fullref")
        if not isinstance(full_field, Mapping):
            failures.append({"index": expected_index, "reason": "country_fullref_missing"})
            continue
        full_raw = _hex_bytes(full_field.get("raw_hex"), f"entry[{expected_index}].fullref", 8)
        fullref = int.from_bytes(full_raw, "little")
        reported_fullref = _as_int(full_field.get("value"))
        if reported_fullref is not None and reported_fullref != fullref:
            failures.append({"index": expected_index, "reason": "country_fullref_value_mismatch"})
        row: dict[str, Any] = {"index": expected_index, "pointer_raw_hex": pointer_raw.hex(), "pointer": hex(pointer), "fullref_raw_hex": full_raw.hex(), "fullref": fullref}
        if full_raw.hex() == NULL_COUNTRY_FULLREF_RAW_HEX:
            row.update({"status": "null_sentinel", "country": None, "slot": 0})
            normalized_entries.append(row)
            continue
        tag, slot = _tag_slot(full_raw)
        if not _valid_pointer(pointer) or tag is None or slot is None or slot != expected_index:
            row.update({"status": "unknown", "country": tag, "slot": slot})
            failures.append({"index": expected_index, "reason": "country_identity_invalid", "fullref_raw_hex": full_raw.hex()})
            normalized_entries.append(row)
            continue
        row.update({"status": "valid", "country": tag, "slot": slot})
        if tag in by_tag or full_raw.hex() in by_fullref:
            failures.append({"index": expected_index, "reason": "country_identity_duplicate", "country": tag})
        else:
            by_tag[tag] = row
            by_fullref[full_raw.hex()] = row
        normalized_entries.append(row)
    actor_entry = by_tag.get(actor)
    if actor_entry is None:
        failures.append({"reason": "actor_identity_missing", "actor": actor})
    return {
        "database": {"value": database_value, "raw_hex": database_raw.hex()},
        "game": {"value": game_value, "raw_hex": game_raw.hex()},
        "game_date": {"value": date_value, "raw_hex": date_raw.hex()},
        "country_table": {"value": table_value, "raw_hex": table_raw.hex()},
        "country_count": {"value": count, "raw_hex": count_raw.hex()},
        "entries": normalized_entries,
        "by_tag": by_tag,
        "by_fullref": by_fullref,
        "actor_entry": actor_entry,
        "failures": failures,
    }


def _row_binding(row: Any, actor_entry: Mapping[str, Any], target: Mapping[str, Any], actor_fullref_raw: bytes) -> tuple[bool, str | None]:
    if not isinstance(row, Mapping):
        return False, "relation_row_missing"
    actor_ptr = int(str(actor_entry["pointer"]), 0)
    full_raw = _hex_bytes(target.get("fullref_hex"), "target.fullref", 8)
    fullref = int.from_bytes(full_raw, "little")
    tag, slot = _tag_slot(full_raw)
    if tag is None or slot is None:
        return False, "target_fullref_invalid"
    if _as_int(target.get("slot")) != slot:
        return False, "target_slot_mismatch"
    row_address = _as_int((row.get("address") or {}).get("va")) if isinstance(row.get("address"), Mapping) else None
    table = row.get("relation_table")
    if not isinstance(table, Mapping):
        return False, "relation_table_missing"
    table_address = _as_int((table.get("address") or {}).get("va")) if isinstance(table.get("address"), Mapping) else None
    table_raw = _hex_bytes(table.get("raw_hex"), "relation_table.raw", 8)
    table_value = int.from_bytes(table_raw, "little")
    if _as_int(table.get("value")) not in (None, table_value):
        return False, "relation_table_value_mismatch"
    if not _valid_pointer(table_value) or table_address != actor_ptr + RELATION_TABLE_OFFSET:
        return False, "relation_table_binding_invalid"
    if row_address != table_value + slot * RELATION_ROW_STRIDE:
        return False, "relation_row_address_invalid"
    owner_raw = _hex_bytes(row.get("owner_raw_hex"), "relation_row.owner", 8)
    owner_value = _as_int((row.get("owner") or {}).get("va")) if isinstance(row.get("owner"), Mapping) else None
    if owner_value is None or not _valid_pointer(owner_value) or int.from_bytes(owner_raw, "little") != owner_value:
        return False, "relation_row_owner_invalid"
    recipient = row.get("recipient_fullref")
    if not isinstance(recipient, Mapping):
        return False, "relation_row_recipient_missing"
    recipient_raw = _hex_bytes(recipient.get("raw_hex"), "relation_row.recipient", 8)
    if recipient_raw != full_raw or _as_int(recipient.get("value")) not in (None, fullref):
        return False, "relation_row_recipient_mismatch"
    if _as_int(row.get("recipient_slot")) != _signed_i16(slot):
        return False, "relation_row_slot_mismatch"
    if _as_int(row.get("row_stride")) not in (None, RELATION_ROW_STRIDE):
        return False, "relation_row_stride_invalid"
    prefix = row.get("prefix_raw_hex")
    if prefix is not None:
        prefix_raw = _hex_bytes(prefix, "relation_row.prefix", 0x20)
        if prefix_raw[:8] != owner_raw or prefix_raw[8:16] != actor_fullref_raw or prefix_raw[16:24] != full_raw:
            return False, "relation_row_prefix_binding_invalid"
    return True, None


def _target_rows(pass_record: Mapping[str, Any], context: Mapping[str, Any], actor: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    actor_entry = context.get("actor_entry")
    if not isinstance(actor_entry, Mapping):
        return [], [{"reason": "actor_identity_missing"}]
    actor_index = _as_int(actor_entry.get("index"))
    actor_fullref_raw = _hex_bytes(actor_entry.get("fullref_raw_hex"), "actor.fullref", 8)
    source_targets = pass_record.get("targets")
    if not isinstance(source_targets, list):
        return [], [{"reason": "targets_missing"}]
    rows: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = list(context.get("failures", []))
    expected = [entry for entry in context.get("entries", []) if isinstance(entry, Mapping) and entry.get("status") == "valid" and entry.get("index") != actor_index]
    expected_by_full = {entry["fullref_raw_hex"]: entry for entry in expected}
    seen: set[str] = set()
    for source in source_targets:
        if not isinstance(source, Mapping):
            failures.append({"reason": "target_not_object"})
            continue
        try:
            full_raw = _hex_bytes(source.get("fullref_hex"), "target.fullref", 8)
        except ReferenceError as exc:
            failures.append({"reason": str(exc)})
            continue
        full_hex = full_raw.hex()
        entry = expected_by_full.get(full_hex)
        row_out: dict[str, Any] = {"index": _as_int(source.get("index")), "country": None, "fullref_hex": full_hex, "slot": None, "country_pointer": source.get("country_pointer"), "relation_row": deepcopy(source.get("relation_row")), "status": "unknown", "reason": None}
        if full_hex in seen:
            row_out["reason"] = "duplicate_target_fullref"
            failures.append({"fullref_hex": full_hex, "reason": row_out["reason"]})
            rows.append(row_out)
            continue
        seen.add(full_hex)
        if entry is None:
            row_out["reason"] = "target_fullref_not_in_country_table"
            failures.append({"fullref_hex": full_hex, "reason": row_out["reason"]})
            rows.append(row_out)
            continue
        tag, slot = _tag_slot(full_raw)
        row_out.update(country=tag, slot=slot, country_pointer=entry["pointer"])
        if source.get("country") not in (None, tag) or _as_int(source.get("slot")) not in (None, slot):
            row_out["reason"] = "target_projection_mismatch"
        else:
            valid, reason = _row_binding(source.get("relation_row"), actor_entry, {"fullref_hex": full_hex, "slot": slot}, actor_fullref_raw)
            if valid:
                row_out["status"] = "known"
            else:
                row_out["reason"] = reason
        if row_out["reason"]:
            failures.append({"country": tag, "fullref_hex": full_hex, "reason": row_out["reason"]})
        rows.append(row_out)
    missing = sorted(set(expected_by_full) - seen)
    for full_hex in missing:
        failures.append({"fullref_hex": full_hex, "reason": "target_missing"})
    rows.sort(key=lambda item: (item.get("slot") is None, item.get("slot") if item.get("slot") is not None else 0))
    return rows, failures


def _cache_raw(cache: Any, owner_ptr: int, family: str) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(cache, Mapping):
        return None, "owner_cache_missing"
    key = f"{owner_ptr:#x}:{family}"
    item = cache.get(key)
    if not isinstance(item, Mapping):
        return None, "owner_cache_entry_missing"
    raw = item.get("raw")
    if not isinstance(raw, Mapping):
        return None, "owner_cache_raw_missing"
    owner_field = raw.get("owner_pointer")
    owner_value = _as_int((owner_field or {}).get("va")) if isinstance(owner_field, Mapping) else None
    owner_raw = _hex_bytes(raw.get("owner_pointer_raw_hex"), f"{family}.owner", 8)
    if owner_value != owner_ptr or int.from_bytes(owner_raw, "little") != owner_ptr:
        return None, "owner_cache_owner_mismatch"
    begin, begin_raw = _field_raw(raw.get("vector_begin"), f"{family}.vector_begin", 8)
    count, count_raw = _field_raw(raw.get("vector_count"), f"{family}.vector_count", 4, signed=True)
    if count < 0 or count > MAX_VECTOR_COUNT:
        return None, "owner_vector_count_invalid"
    if count and not _valid_pointer(begin):
        return None, "owner_vector_begin_invalid"
    elements = raw.get("elements")
    if not isinstance(elements, list) or len(elements) != count:
        return None, "owner_vector_elements_count_invalid"
    normalized_elements: list[dict[str, Any]] = []
    for index, element in enumerate(elements):
        if not isinstance(element, Mapping) or _as_int(element.get("index")) != index:
            return None, "owner_vector_element_index_invalid"
        element_raw = _hex_bytes(element.get("raw_hex"), f"{family}.element[{index}]", 16)
        address = _as_int((element.get("address") or {}).get("va")) if isinstance(element.get("address"), Mapping) else None
        if address != begin + index * 16:
            return None, "owner_vector_element_address_invalid"
        first_raw = element_raw[:4]
        first = int.from_bytes(first_raw, "little")
        if element.get("first_dword_raw_hex") not in (None, first_raw.hex()) or _as_int(element.get("first_dword")) not in (None, first):
            return None, "owner_vector_first_dword_mismatch"
        if element.get("unread_tail_raw_hex") not in (None, element_raw[4:].hex()):
            return None, "owner_vector_tail_mismatch"
        normalized_elements.append({"index": index, "address": hex(address), "raw_hex": element_raw.hex(), "first_dword": first, "first_dword_raw_hex": first_raw.hex(), "unread_tail_raw_hex": element_raw[4:].hex()})
    return {"owner_pointer_raw_hex": owner_raw.hex(), "vector_begin_raw_hex": begin_raw.hex(), "vector_count_raw_hex": count_raw.hex(), "vector_begin": begin, "vector_count": count, "element_stride": _as_int(raw.get("element_stride")) or 16, "elements": normalized_elements}, None


def _agreement_evidence(source_row: Mapping[str, Any], pointer_raw: bytes, agreement_pointer: int, expected: int) -> tuple[bool | None, dict[str, Any], str | None]:
    predicate = source_row.get("predicate")
    if not isinstance(predicate, Mapping):
        return None, {}, "received_agreement_evidence_missing"
    recorded_pointer_raw = predicate.get("agreement_pointer_raw_hex")
    if recorded_pointer_raw not in (None, pointer_raw.hex()):
        return None, {}, "received_agreement_pointer_mismatch"
    pointer_field = predicate.get("agreement_pointer")
    if isinstance(pointer_field, Mapping) and _as_int(pointer_field.get("va")) not in (None, agreement_pointer):
        return None, {}, "received_agreement_pointer_value_mismatch"
    agreement_ref = predicate.get("agreement_ref")
    if not isinstance(agreement_ref, Mapping):
        return None, {}, "received_agreement_ref_missing"
    ref_raw = _hex_bytes(agreement_ref.get("raw_hex"), "received.agreement_ref", 8)
    ref_value = int.from_bytes(ref_raw, "little")
    if _as_int(agreement_ref.get("value")) not in (None, ref_value):
        return None, {}, "received_agreement_ref_value_mismatch"
    address = _as_int((agreement_ref.get("address") or {}).get("va")) if isinstance(agreement_ref.get("address"), Mapping) else None
    if address != agreement_pointer + 0x18:
        return None, {}, "received_agreement_ref_address_mismatch"
    slot = _signed_i16((ref_value >> 32) & 0xFFFF)
    return slot == expected, {"agreement_pointer_raw_hex": pointer_raw.hex(), "agreement_ref": {"address": hex(address), "raw_hex": ref_raw.hex(), "slot_signed_i16": slot}}, None


def _replay_row(family: str, cache: Mapping[str, Any], source_row: Mapping[str, Any], expected_slot: int) -> tuple[bool | None, dict[str, Any], str | None]:
    elements = cache.get("elements")
    if not isinstance(elements, list):
        return None, {}, "owner_vector_elements_missing"
    expected_unsigned = expected_slot & 0xFFFFFFFF
    first_match = next((element for element in elements if element.get("first_dword") == expected_unsigned), None)
    proof: dict[str, Any] = {"comparison_slot_signed_i16": expected_slot, "first_matching_element_index": first_match.get("index") if first_match else None}
    if first_match is None:
        return False, proof, None
    if family == "granted":
        proof["native_leaf"] = "first_dword_only"
        return True, proof, None
    element_raw = _hex_bytes(first_match.get("raw_hex"), "received.element", 16)
    pointer_raw = element_raw[8:16]
    agreement_pointer = int.from_bytes(pointer_raw, "little")
    proof["agreement_pointer_raw_hex"] = pointer_raw.hex()
    if agreement_pointer == 0:
        proof["agreement_status"] = "null"
        return False, proof, None
    if not _valid_pointer(agreement_pointer):
        return None, proof, "received_agreement_pointer_invalid"
    value, evidence, reason = _agreement_evidence(source_row, pointer_raw, agreement_pointer, expected_slot)
    if reason:
        return None, proof, reason
    proof.update(evidence)
    proof["agreement_status"] = "observed"
    return value, proof, None


def _field_source_rows(pass_record: Mapping[str, Any], family: str) -> dict[int, Mapping[str, Any]]:
    field = (pass_record.get("fields") or {}).get(family)
    if not isinstance(field, Mapping) or not isinstance(field.get("rows"), list):
        return {}
    result: dict[int, Mapping[str, Any]] = {}
    for row in field["rows"]:
        if isinstance(row, Mapping):
            index = _as_int(row.get("index"))
            if index is not None:
                result[index] = row
    return result


def _replay_pass(pass_record: Mapping[str, Any], actor: str, families: list[str]) -> dict[str, Any]:
    context = _context(pass_record, actor)
    request_rows, failures = _target_rows(pass_record, context, actor)
    actor_entry = context.get("actor_entry")
    actor_ptr = int(str(actor_entry["pointer"]), 0) if isinstance(actor_entry, Mapping) else None
    fields: dict[str, Any] = {}
    cache_out: dict[str, Any] = {}
    for family in families:
        active: list[dict[str, Any]] = []
        unknown_rows: list[dict[str, Any]] = []
        field_rows: list[dict[str, Any]] = []
        source_rows = _field_source_rows(pass_record, family)
        cache_by_owner: dict[int, tuple[dict[str, Any] | None, str | None]] = {}
        for request_row in request_rows:
            index = request_row.get("index")
            out: dict[str, Any] = {"index": index, "country": request_row.get("country"), "fullref_hex": request_row.get("fullref_hex"), "slot": request_row.get("slot"), "status": "unknown", "active": None, "predicate": None}
            if request_row.get("status") != "known":
                out["reason"] = request_row.get("reason") or "request_row_unknown"
            else:
                relation_row = request_row.get("relation_row")
                owner_ptr = _as_int((relation_row.get("owner") or {}).get("va")) if isinstance(relation_row, Mapping) and isinstance(relation_row.get("owner"), Mapping) else None
                if owner_ptr is None:
                    out["reason"] = "relation_row_owner_unknown"
                    unknown_rows.append({"index": index, "country": out.get("country"), "fullref_hex": out.get("fullref_hex"), "reason": out["reason"]})
                    field_rows.append(out)
                    continue
                if owner_ptr not in cache_by_owner:
                    cache_by_owner[owner_ptr] = _cache_raw(pass_record.get("owner_cache"), owner_ptr, family)
                cache, cache_reason = cache_by_owner[owner_ptr]
                if cache is None:
                    out["reason"] = cache_reason or "owner_vector_unknown"
                else:
                    value, proof, reason = _replay_row(family, cache, source_rows.get(index, {}), _signed_i16(int(request_row["slot"])))
                    if reason:
                        out["reason"] = reason
                    else:
                        out.update(status="known", active=bool(value), predicate=proof)
                        if value:
                            active.append({"country": request_row.get("country"), "fullref_hex": request_row.get("fullref_hex"), "slot": request_row.get("slot"), "active": True})
            if out["status"] != "known":
                unknown_rows.append({"index": index, "country": out.get("country"), "fullref_hex": out.get("fullref_hex"), "reason": out.get("reason")})
            field_rows.append(out)
        for owner_ptr, (owner_cache, owner_reason) in cache_by_owner.items():
            if owner_cache is not None:
                cache_out[f"{owner_ptr:#x}:{family}"] = deepcopy(owner_cache)
        field_status = "known" if not unknown_rows and not failures else "partial"
        fields[family] = {"status": field_status, "family": family, "value": active, "rows": field_rows, "unknown_rows": unknown_rows, "candidate_failures": deepcopy(failures), "candidate_count": len(request_rows), "partial": True, "complete": False, "unit": "relation_state", "scale": 1, "period": "current", "basis": "native_fleet_basing_owner_vector_predicate", "value_origin": "independent_replay_of_copied_native_vectors"}
    compact_context = {key: deepcopy(context[key]) for key in ("database", "game", "game_date", "country_table", "country_count", "entries")}
    return {"status": "known" if not failures else "partial", "complete": False, "context": compact_context, "request_rows": request_rows, "owner_cache": cache_out, "fields": fields, "candidate_failures": failures}


def _raw_projection(pass_record: Mapping[str, Any], actor: str) -> dict[str, Any]:
    context = _context(pass_record, actor)
    rows, failures = _target_rows(pass_record, context, actor)
    cache: dict[str, Any] = {}
    owner_cache = pass_record.get("owner_cache")
    if isinstance(owner_cache, Mapping):
        for key, item in owner_cache.items():
            if isinstance(item, Mapping) and isinstance(item.get("raw"), Mapping):
                cache[str(key)] = deepcopy(item["raw"])
    field_projection: dict[str, Any] = {}
    for family in FAMILIES:
        source_rows = _field_source_rows(pass_record, family)
        values: list[Any] = []
        for row in rows:
            original = source_rows.get(row.get("index"))
            predicate = original.get("predicate") if isinstance(original, Mapping) else None
            evidence = None
            if isinstance(predicate, Mapping):
                evidence = {key: deepcopy(predicate.get(key)) for key in ("agreement_pointer", "agreement_pointer_raw_hex", "agreement_ref") if key in predicate}
            values.append({"index": row.get("index"), "fullref_hex": row.get("fullref_hex"), "relation_row": deepcopy(row.get("relation_row")), "predicate_evidence": evidence})
        field_projection[family] = values
    guard = pass_record.get("runtime_code_guard")
    guard_records = deepcopy(guard.get("records", [])) if isinstance(guard, Mapping) else None
    return {"context": {key: deepcopy(context[key]) for key in ("database", "game", "game_date", "country_table", "country_count", "entries")}, "request_rows": [{key: deepcopy(row.get(key)) for key in ("index", "country", "fullref_hex", "slot", "country_pointer", "relation_row")} for row in rows], "owner_cache": cache, "field_evidence": field_projection, "runtime_code_guard": guard_records, "failures": failures}


def _identity_ok(metadata: Mapping[str, Any]) -> bool:
    identity = metadata.get("identity")
    return bool(isinstance(identity, Mapping) and identity.get("binding_verified") is True and identity.get("process_path_sha256") == EXE_SHA256 and identity.get("process_path_sha256_matches_expected") is True and identity.get("process_creation_matches_installation") is True)


def _cleanup_ok(metadata: Mapping[str, Any]) -> bool:
    cleanup = metadata.get("cleanup")
    close = cleanup.get("handle_close") if isinstance(cleanup, Mapping) else None
    return bool(isinstance(close, Mapping) and close.get("closed") is True and close.get("success") is True)


def _write_once(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"output_exists:{path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def build_reference(input_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    source_size = input_path.stat().st_size
    if source_size <= 0:
        raise ReferenceError("source_empty")
    source_sha = _sha256_file(input_path)
    actors_out: dict[str, Any] = {}

    def consume_actor(actor: str, value: Mapping[str, Any]) -> None:
        if actor in actors_out:
            raise ReferenceError(f"duplicate_actor:{actor}")
        before = value.get("before")
        after = value.get("after")
        if not isinstance(before, Mapping) or not isinstance(after, Mapping):
            actors_out[actor] = {"status": "unknown", "reason": "actor_pass_missing"}
            return
        before_projection = _raw_projection(before, actor)
        after_projection = _raw_projection(after, actor)
        raw_consistent = before_projection == after_projection
        before_replay = _replay_pass(before, actor, list(FAMILIES))
        after_replay = _replay_pass(after, actor, list(FAMILIES))
        actors_out[actor] = {"actor": actor, "raw_two_pass_consistent": raw_consistent, "probe_doublepass": deepcopy(value.get("doublepass")), "before": before_replay, "after": after_replay, "fields": deepcopy(after_replay.get("fields")) if raw_consistent else {family: {"status": "unknown", "family": family, "value": None, "reason": "independent_two_pass_raw_mismatch", "partial": True, "complete": False} for family in FAMILIES}, "status": "observed" if raw_consistent else "unknown", "complete": False, "positive_sample_present": any(bool((after_replay.get("fields", {}).get(family, {}).get("value") or [])) for family in FAMILIES)}
        if not raw_consistent:
            actors_out[actor]["unknown_conditions"] = ["before_after_raw_projection_mismatch"]

    metadata, actor_metadata = _stream_source(input_path, consume_actor)
    requested = metadata.get("request") if isinstance(metadata.get("request"), Mapping) else {}
    requested_actors = requested.get("actors") if isinstance(requested, Mapping) else None
    actor_list = [str(x) for x in requested_actors] if isinstance(requested_actors, list) else sorted(actors_out)
    missing_actors = [actor for actor in actor_list if actor not in actors_out]
    per_actor_consistent = {actor: bool(actors_out.get(actor, {}).get("raw_two_pass_consistent") is True) for actor in actor_list}
    all_consistent = bool(actor_list) and not missing_actors and all(per_actor_consistent.values())
    source_pins = deepcopy(metadata.get("source_pins")) if isinstance(metadata.get("source_pins"), Mapping) else {"executable_sha256": EXE_SHA256, "fleet_source002_sha256": FLEET_SOURCE002_SHA256, "relation_contract003_sha256": RELATION_CONTRACT003_SHA256}
    checks = {"source_streamed": True, "actor_values_bounded": True, "actor_count": len(actors_out), "requested_actor_count": len(actor_list), "missing_actors": missing_actors, "identity_binding_verified": _identity_ok(metadata), "handle_closed": _cleanup_ok(metadata), "per_actor_raw_two_pass_consistent": per_actor_consistent, "probe_status_and_value_not_used_for_predicates": True, "positive_sample_present": any(bool(actors_out.get(actor, {}).get("positive_sample_present")) for actor in actor_list)}
    reference = {
        "schema": "information_fleet_basing_independent_reference.v1",
        "independent": True,
        "production_reader_imported": False,
        "profile_imported": False,
        "read_only": True,
        "native_game_calls": False,
        "source_raw": {"path": input_path.relative_to(ROOT).as_posix(), "bytes": source_size, "sha256": source_sha, "actor_cap_bytes": MAX_ACTOR_BYTES},
        "source_pins": source_pins,
        "request": deepcopy(requested),
        "identity": deepcopy(metadata.get("identity")),
        "cleanup": deepcopy(metadata.get("cleanup")),
        "target_build": deepcopy(metadata.get("target_build")),
        "module_base": deepcopy(metadata.get("module_base")),
        "file_code_guard": deepcopy(metadata.get("file_code_guard")),
        "runtime_code_guard": deepcopy(metadata.get("runtime_code_guard")),
        "actors_metadata": deepcopy(actor_metadata),
        "actors": actors_out,
        "top_header_doublepass": deepcopy(metadata.get("doublepass")),
        "top_level_doublepass_note": "false is retained from the multi-actor probe header; per-actor before/after raw projections are the independent two-pass evidence",
        "per_actor_doublepass": per_actor_consistent,
        "checks": checks,
        "status": "observed" if all_consistent and _identity_ok(metadata) and _cleanup_ok(metadata) else "unknown",
        "completed": True,
        "complete": False,
        "partial": True,
        "unknown_conditions": ["fleet-basing direction/roles and expiry are not inferred", "no positive active sample was present in the four requested actors"],
    }
    receipt = {
        "schema": "information_fleet_basing_reference_receipt.v1",
        "status": reference["status"],
        "source_raw": deepcopy(reference["source_raw"]),
        "source_pins": deepcopy(source_pins),
        "reference": {"path": DEFAULT_OUTPUT.relative_to(ROOT).as_posix(), "sha256": None},
        "reference_script": {"path": Path(__file__).resolve().relative_to(ROOT).as_posix(), "sha256": _sha256_file(Path(__file__))},
        "streaming": {"source_bytes": source_size, "actor_cap_bytes": MAX_ACTOR_BYTES, "actors_processed": len(actors_out), "full_source_json_loaded": False},
        "top_header": {"doublepass": deepcopy(metadata.get("doublepass")), "doublepass_interpretation": "multi_actor_header_false_is_expected_and_not_a_failure"},
        "per_actor": {actor: {"raw_two_pass_consistent": per_actor_consistent.get(actor, False), "positive_sample_present": bool(actors_out.get(actor, {}).get("positive_sample_present"))} for actor in actor_list},
        "checks": checks,
        "unknown_conditions": reference["unknown_conditions"],
    }
    return reference, receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--receipt", type=Path, default=DEFAULT_RECEIPT)
    args = parser.parse_args()
    input_path = args.input if args.input.is_absolute() else ROOT / args.input
    output_path = args.output if args.output.is_absolute() else ROOT / args.output
    receipt_path = args.receipt if args.receipt.is_absolute() else ROOT / args.receipt
    reference, receipt = build_reference(input_path)
    _write_once(output_path, reference)
    receipt["reference"]["sha256"] = _sha256_file(output_path)
    _write_once(receipt_path, receipt)
    print(json.dumps({"status": reference["status"], "actors": len(reference["actors"]), "source_bytes": reference["source_raw"]["bytes"], "source_sha256": reference["source_raw"]["sha256"], "output": output_path.as_posix(), "receipt": receipt_path.as_posix()}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
