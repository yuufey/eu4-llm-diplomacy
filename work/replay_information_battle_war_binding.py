"""Offline replay of one retained battle-war RPM report.

This tool deliberately consumes one already-recorded report.  It never opens a
process, calls a native function, or combines bytes from another capture.  The
default invocation and ``--help`` are inert; ``--run`` is required to emit a
fixture and a receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "work/runtime/information-battle-war-records-20261025-001/live-fra-bur-001/report.json"
DEFAULT_STAGE = ROOT / "work/runtime/information-battle-war-binding-20261027-001"
DEFAULT_FIXTURE = DEFAULT_STAGE / "war-binding-fixture-001.json"
DEFAULT_RECEIPT = DEFAULT_STAGE / "war-binding-replay-001.json"
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_FIXTURE_BYTES = 2 * 1024 * 1024

EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
DATABASE_GLOBAL_RVA = 0x233D8B0
COUNTRY_TABLE_OFFSET = 0x118
COUNTRY_HANDLE_OFFSET = 0x20
COUNTRY_RELATION_ROWS_OFFSET = 0x1548
COUNTRY_RELATION_COUNT_OFFSET = 0x1554
RELATION_ROW_STRIDE = 16
RELATION_ROW_COUNTERPART_OFFSET = 0
RELATION_ROW_REFERENCE_OFFSET = 8
HISTORY_ROOT_OFFSET = 0x108
HISTORY_ROOT_VTABLE_RVA = 0x1D20BE0
RESULT_VTABLE_RVA = 0x1C448D0
SIDE_VTABLE_RVA = 0x1C44910
RESULT_SIDE_A_OFFSET = 0x10
RESULT_SIDE_B_OFFSET = 0x88
SIDE_COUNTRY_OFFSET = 0x10
RESULT_SIZE = 0x138
SIDE_SIZE = 0x78


class ReplayError(RuntimeError):
    """A source report does not contain the bounded contract we replay."""


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _load_bounded_json(path: Path, limit: int = MAX_SOURCE_BYTES) -> tuple[dict[str, Any], bytes]:
    size = path.stat().st_size
    if size > limit:
        raise ReplayError(f"source exceeds bounded replay limit: {size} > {limit}")
    raw = path.read_bytes()
    if len(raw) != size:
        raise ReplayError("source changed while being read")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ReplayError("source root is not an object")
    return value, raw


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReplayError(message)


def _hex_bytes(value: Any, *, field: str, exact: int | None = None) -> bytes:
    _require(isinstance(value, str), f"{field} is not hex text")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ReplayError(f"{field} is not valid hex") from exc
    if exact is not None:
        _require(len(raw) == exact, f"{field} length {len(raw)} != {exact}")
    return raw


def _u64(value: Any, *, field: str) -> int:
    raw = _hex_bytes(value, field=field, exact=8)
    return int.from_bytes(raw, "little", signed=False)


def _i32(value: Any, *, field: str) -> int:
    raw = _hex_bytes(value, field=field, exact=4)
    return int.from_bytes(raw, "little", signed=True)


def _address_value(value: Any, *, field: str) -> int:
    _require(isinstance(value, dict), f"{field} missing address object")
    raw = value.get("va")
    _require(isinstance(raw, str), f"{field}.va missing")
    try:
        return int(raw, 16)
    except ValueError as exc:
        raise ReplayError(f"{field}.va is not hexadecimal") from exc


def _raw_pointer(value: Any, *, field: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{field} missing pointer record")
    raw_hex = value.get("raw_hex")
    parsed = _u64(raw_hex, field=f"{field}.raw_hex")
    nested = value.get("value")
    nested_va = _address_value(nested, field=f"{field}.value") if isinstance(nested, dict) else None
    if nested_va is not None:
        _require(parsed == nested_va, f"{field} raw/value mismatch")
    return {
        "address_va": _address_value(value.get("address"), field=f"{field}.address") if value.get("address") else None,
        "raw_hex": raw_hex,
        "value_va": nested_va if nested_va is not None else parsed,
    }


def _fullref(raw_hex: Any, *, field: str) -> dict[str, Any]:
    raw = _hex_bytes(raw_hex, field=field, exact=8)
    tag_bytes = raw[:3]
    tag = tag_bytes.decode("ascii", errors="replace") if all(32 <= b < 127 for b in tag_bytes) else None
    return {
        "raw_hex": raw.hex(),
        "tag": tag,
        "slot": int.from_bytes(raw[4:6], "little", signed=False),
        "generation_raw_hex": raw[6:8].hex(),
    }


def _country_snapshot(country: dict[str, Any], *, label: str) -> dict[str, Any]:
    handle = country.get("country_handle")
    _require(isinstance(handle, dict), f"{label}.country_handle missing")
    fullref = _fullref(handle.get("raw_hex"), field=f"{label}.country_handle.raw_hex")
    _require(handle.get("tag") == fullref["tag"], f"{label} handle tag mismatch")
    _require(handle.get("slot") == fullref["slot"], f"{label} handle slot mismatch")
    table_field = country.get("table_field")
    table = _raw_pointer(table_field, field=f"{label}.table_field")
    _require(table_field.get("field_offset") == hex(COUNTRY_TABLE_OFFSET), f"{label} country table offset mismatch")
    pointer = country.get("country_pointer")
    country_va = _address_value(pointer, field=f"{label}.country_pointer")
    matches = country.get("matches")
    _require(isinstance(matches, list) and len(matches) == 1, f"{label} must have one table match")
    match = matches[0]
    _require(match.get("table_index") == fullref["slot"], f"{label} table index mismatch")
    entries = country.get("entries")
    _require(isinstance(entries, list), f"{label}.entries missing")
    selected = [entry for entry in entries if entry.get("table_index") == fullref["slot"]]
    _require(len(selected) == 1, f"{label} selected table entry missing")
    entry = selected[0]
    entry_handle = entry.get("handle", {})
    _require(entry_handle.get("raw_hex") == fullref["raw_hex"], f"{label} table entry fullref mismatch")
    return {
        "label": label,
        "country_pointer_va": hex(country_va),
        "country_handle_offset": hex(COUNTRY_HANDLE_OFFSET),
        "country_fullref": fullref,
        "country_table": {
            "field_offset": hex(COUNTRY_TABLE_OFFSET),
            "field_address_va": hex(table["address_va"]) if table["address_va"] is not None else None,
            "field_raw_hex": table["raw_hex"],
            "table_value_va": hex(table["value_va"]),
            "selected_entry": {
                "table_index": entry["table_index"],
                "pointer_va": entry.get("pointer", {}).get("va") or entry.get("pointer", {}).get("value"),
                "pointer_raw_hex": entry.get("pointer_raw_hex"),
                "fullref_raw_hex": entry_handle.get("raw_hex"),
            },
            "scan_count": country.get("scanned_entries"),
            "scan_limit": country.get("initial_scan_limit"),
        },
    }


def _pair_snapshot(pair: dict[str, Any], *, label: str) -> dict[str, Any]:
    count = pair.get("count")
    _require(isinstance(count, dict), f"{label}.count missing")
    count_raw = _hex_bytes(count.get("raw_hex"), field=f"{label}.count.raw_hex", exact=4)
    count_value = int.from_bytes(count_raw, "little", signed=False)
    _require(count.get("value") == count_value, f"{label} count raw/value mismatch")
    rows = pair.get("rows")
    _require(isinstance(rows, dict), f"{label}.rows missing")
    rows_raw = _hex_bytes(rows.get("raw_hex"), field=f"{label}.rows.raw_hex", exact=8)
    rows_value = int.from_bytes(rows_raw, "little", signed=False)
    rows_nested = rows.get("value")
    _require(isinstance(rows_nested, dict), f"{label}.rows.value missing")
    _require(_address_value(rows_nested, field=f"{label}.rows.value") == rows_value, f"{label} rows raw/value mismatch")
    records = pair.get("row_records")
    _require(isinstance(records, list) and len(records) == count_value, f"{label} row count mismatch")
    retained = []
    for row in records:
        counterpart_raw = _hex_bytes(row.get("counterpart_raw_hex"), field=f"{label}.counterpart_raw_hex", exact=4)
        ref_raw = _hex_bytes(row.get("reference_raw_hex"), field=f"{label}.reference_raw_hex", exact=8)
        counterpart = int.from_bytes(counterpart_raw, "little", signed=True)
        reference = int.from_bytes(ref_raw, "little", signed=False)
        _require(row.get("counterpart") == counterpart, f"{label} counterpart raw/value mismatch")
        _require(int(row.get("reference", "0"), 16) == reference, f"{label} reference raw/value mismatch")
        retained.append({
            "index": row.get("index"),
            "counterpart_raw_hex": counterpart_raw.hex(),
            "counterpart": counterpart,
            "reference_raw_hex": ref_raw.hex(),
            "reference_va": hex(reference),
        })
    return {
        "label": label,
        "rows_field_offset": hex(COUNTRY_RELATION_ROWS_OFFSET),
        "count_field_offset": hex(COUNTRY_RELATION_COUNT_OFFSET),
        "row_stride": RELATION_ROW_STRIDE,
        "rows_pointer": {"address_va": hex(_address_value(rows.get("address"), field=f"{label}.rows.address")), "raw_hex": rows_raw.hex(), "value_va": hex(rows_value)},
        "count": {"raw_hex": count_raw.hex(), "value": count_value},
        "row_records": retained,
        "raw_retention": {
            "retained_fields": ["counterpart[0:4]", "reference[8:16]"],
            "unretained_stride_bytes": "[4:8]",
            "complete_16_byte_row_bytes": False,
        },
        "complete": pair.get("complete") is True,
        "status": pair.get("status"),
    }


def _side_snapshot(side: dict[str, Any], *, label: str) -> dict[str, Any]:
    header = _hex_bytes(side.get("raw_header_hex"), field=f"{label}.raw_header_hex", exact=24)
    begin = int.from_bytes(header[0:8], "little")
    end = int.from_bytes(header[8:16], "little")
    capacity = int.from_bytes(header[16:24], "little")
    count = side.get("count")
    members = side.get("members")
    _require(isinstance(count, int) and isinstance(members, list), f"{label} members missing")
    _require(end >= begin and (end - begin) % 8 == 0, f"{label} vector bounds invalid")
    _require((end - begin) // 8 == count == len(members), f"{label} vector count mismatch")
    member_bytes = []
    for index, member in enumerate(members):
        raw = _hex_bytes(member.get("raw_hex"), field=f"{label}.member[{index}].raw_hex", exact=8)
        fullref = _fullref(raw.hex(), field=f"{label}.member[{index}].raw_hex")
        member_bytes.append({
            "index": index,
            "raw_hex": raw.hex(),
            "tag": fullref["tag"],
            "slot": fullref["slot"],
        })
    return {
        "label": label,
        "raw_header_hex": header.hex(),
        "begin_raw_hex": header[0:8].hex(),
        "end_raw_hex": header[8:16].hex(),
        "capacity_raw_hex": header[16:24].hex(),
        "begin_va": hex(begin),
        "end_va": hex(end),
        "capacity_va": hex(capacity),
        "count": count,
        "members": member_bytes,
        "status": side.get("status"),
        "complete": side.get("complete") is True,
    }


def _result_snapshot(result: dict[str, Any]) -> dict[str, Any]:
    raw = _hex_bytes(result.get("raw_hex"), field="result.raw_hex", exact=RESULT_SIZE)
    vtable = _u64(raw[:8].hex(), field="result.vtable_raw")
    _require(vtable == _address_value(result.get("vtable", {}).get("value"), field="result.vtable.value"), "result vtable mismatch")
    side_snapshots: dict[str, Any] = {}
    for name, offset in (("side_a", RESULT_SIDE_A_OFFSET), ("side_b", RESULT_SIDE_B_OFFSET)):
        side = result.get(name)
        _require(isinstance(side, dict), f"result.{name} missing")
        side_raw = _hex_bytes(side.get("raw_hex"), field=f"result.{name}.raw_hex", exact=SIDE_SIZE)
        _require(raw[offset:offset + SIDE_SIZE] == side_raw, f"result.{name} raw slice mismatch")
        side_vtable = _u64(side_raw[:8].hex(), field=f"result.{name}.vtable_raw")
        side_country = side_raw[SIDE_COUNTRY_OFFSET:SIDE_COUNTRY_OFFSET + 8].hex()
        country = side.get("country", {})
        _require(country.get("identity_raw_hex") == side_country, f"result.{name} country fullref mismatch")
        side_snapshots[name] = {
            "raw_hex": side_raw.hex(),
            "vtable_raw_hex": side_raw[:8].hex(),
            "vtable_va": hex(side_vtable),
            "country_fullref": _fullref(side_country, field=f"result.{name}.country"),
            "source_country_pointer_va": country.get("country_pointer", {}).get("va"),
        }
    return {
        "address_va": result.get("address", {}).get("va"),
        "raw_hex": raw.hex(),
        "size": len(raw),
        "vtable_raw_hex": raw[:8].hex(),
        "vtable_va": hex(vtable),
        "expected_vtable_rva": hex(RESULT_VTABLE_RVA),
        "sides": side_snapshots,
        "complete": result.get("complete") is True,
        "status": result.get("status"),
    }


def _selected_signature(phase: dict[str, Any]) -> dict[str, Any]:
    """Only raw selected values; addresses are intentionally excluded."""
    wars = phase.get("wars")
    _require(isinstance(wars, list) and len(wars) == 1, "phase must contain one selected war")
    war = wars[0]
    return {
        "game_date_raw_hex": phase.get("game_date", {}).get("raw_hex"),
        "actor_handle_raw_hex": phase.get("actor_country", {}).get("country_handle", {}).get("raw_hex"),
        "recipient_handle_raw_hex": phase.get("recipient_country", {}).get("country_handle", {}).get("raw_hex"),
        "pair": {
            name: [
                (row.get("counterpart_raw_hex"), row.get("reference_raw_hex"))
                for row in phase.get("pair_references", {}).get(name, {}).get("row_records", [])
            ]
            for name in ("actor_to_recipient", "recipient_to_actor")
        },
        "war_reference": war.get("native_reference"),
        "side_a_header": war.get("side_a", {}).get("raw_header_hex"),
        "side_b_header": war.get("side_b", {}).get("raw_header_hex"),
        "side_a_members": [x.get("raw_hex") for x in war.get("side_a", {}).get("members", [])],
        "side_b_members": [x.get("raw_hex") for x in war.get("side_b", {}).get("members", [])],
        "history_header": war.get("history", {}).get("root_header_raw_hex"),
        "result": (war.get("results", {}).get("results") or [{}])[0].get("raw_hex"),
    }


def _build_fixture(report: dict[str, Any], source_path: Path, source_raw: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    _require(report.get("status") == "observed", "source report status is not observed")
    _require(report.get("completed") is True, "source report is not completed")
    _require(report.get("native_function_invoked") is False, "source report invoked a native function")
    _require(report.get("read_only") is True, "source report is not read-only")
    _require(report.get("access", {}).get("native_game_calls") is False, "source report has native game calls")
    _require(report.get("identity", {}).get("process_path_sha256") == EXE_SHA256, "source EXE SHA mismatch")
    _require(report.get("doublepass", {}).get("performed") is True, "source double-pass was not performed")
    _require(report.get("doublepass", {}).get("consistent") is True, "source double-pass is inconsistent")
    _require(report.get("doublepass", {}).get("all_read_bytes_compared") is True, "source selected bytes were not compared")
    before = report.get("before")
    after = report.get("after")
    _require(isinstance(before, dict) and isinstance(after, dict), "source lacks before/after passes")
    before_sig = _selected_signature(before)
    after_sig = _selected_signature(after)
    before_digest = _sha256_bytes(json.dumps(before_sig, sort_keys=True, separators=(",", ":")).encode())
    after_digest = _sha256_bytes(json.dumps(after_sig, sort_keys=True, separators=(",", ":")).encode())
    _require(before_sig == after_sig, "selected before/after raw values differ")

    actor = _country_snapshot(before["actor_country"], label="actor_country")
    recipient = _country_snapshot(before["recipient_country"], label="recipient_country")
    pair = {
        "actor_to_recipient": _pair_snapshot(before["pair_references"]["actor_to_recipient"], label="actor_to_recipient"),
        "recipient_to_actor": _pair_snapshot(before["pair_references"]["recipient_to_actor"], label="recipient_to_actor"),
    }
    _require(before["pair_references"].get("sets_equal") is True, "pair reference sets are not equal")
    war = before["wars"][0]
    war_va = _address_value(war.get("war"), field="war.war")
    native_reference = int(war.get("native_reference"), 16)
    _require(war_va == native_reference, "war pointer/native reference mismatch")
    _require(pair["actor_to_recipient"]["row_records"], "actor pair rows empty")
    _require(pair["recipient_to_actor"]["row_records"], "recipient pair rows empty")
    actor_slot = actor["country_fullref"]["slot"]
    recipient_slot = recipient["country_fullref"]["slot"]
    _require(any(r["counterpart"] == recipient_slot and r["reference_va"] == hex(native_reference) for r in pair["actor_to_recipient"]["row_records"]), "actor relation candidate missing")
    _require(any(r["counterpart"] == actor_slot and r["reference_va"] == hex(native_reference) for r in pair["recipient_to_actor"]["row_records"]), "recipient relation candidate missing")

    sides = {
        "actor_side": _side_snapshot(war["side_a"], label="war.side_a_at_0x48"),
        "recipient_side": _side_snapshot(war["side_b"], label="war.side_b_at_0x78"),
    }
    history_header = _hex_bytes(war["history"]["root_header_raw_hex"], field="history.root_header_raw_hex")
    history_root = _address_value(war["history_root"].get("value"), field="history_root.value")
    _require(history_root == war_va + HISTORY_ROOT_OFFSET, "history root is not war+0x108")
    root_vtable = _u64(history_header[:8].hex(), field="history.root_vtable_raw")
    result_list = war.get("results", {}).get("results")
    _require(isinstance(result_list, list) and len(result_list) == 1, "selected result missing")
    result = _result_snapshot(result_list[0])
    _require(result["sides"]["side_a"]["country_fullref"]["raw_hex"] == actor["country_fullref"]["raw_hex"], "result actor fullref mismatch")
    _require(result["sides"]["side_b"]["country_fullref"]["raw_hex"] == recipient["country_fullref"]["raw_hex"], "result recipient fullref mismatch")

    identity = report["identity"]
    module_base = _address_value(report["module_base"], field="module_base")
    guards = report.get("file_code_guard", {})
    pe_checks = guards.get("checks", {}) if isinstance(guards, dict) else {}
    pe_records = []
    guard_records = guards.get("records", {}) if isinstance(guards, dict) else {}
    if isinstance(guard_records, dict):
        for key in ("history_date_setter_7e7fb0", "result_retainer_d89a80", "retained_result_initializer_d8ff10"):
            value = guard_records.get(key)
            if isinstance(value, dict):
                pe_records.append({"name": key, "rva": value.get("rva"), "sha256": value.get("sha256"), "actual_hex": value.get("actual_hex"), "kind": "PE_supplement_not_runtime_fixture"})
    contract_path = ROOT / "work/runtime/information-battle-war-identity-20261027-001/war-binding-contract-001.json"
    source002_path = ROOT / "work/runtime/information-battle-war-identity-20261027-001/source-002.json"
    contract_pin = {"path": _relative(contract_path), "sha256": _sha256_path(contract_path)} if contract_path.exists() else None
    source002_pin = {"path": _relative(source002_path), "sha256": _sha256_path(source002_path)} if source002_path.exists() else None
    fixture = {
        "schema": "information_battle_war_binding_fixture.v1",
        "status": "offline_selected_bytes_replayable",
        "capture_scope": "one_same_rpm_report_only",
        "source": {
            "report_path": _relative(source_path),
            "report_sha256": _sha256_bytes(source_raw),
            "report_bytes": len(source_raw),
            "evidence_kind": report.get("evidence_kind"),
            "no_cross_capture_splice": True,
        },
        "identity": {
            "session_id": identity.get("installation_session_id"),
            "pid": identity.get("installation_pid"),
            "creation_filetime": identity.get("process_creation_filetime"),
            "game_date_raw": before.get("game_date", {}).get("raw"),
            "game_date_raw_hex": before.get("game_date", {}).get("raw_hex"),
            "observer": report.get("request", {}).get("actor") or report.get("probe", {}).get("actor"),
            "actor": actor["country_fullref"]["tag"],
            "recipient": recipient["country_fullref"]["tag"],
            "exe_sha256": identity.get("process_path_sha256"),
            "module_base_va": hex(module_base),
        },
        "country_table_and_fullrefs": {
            "database_pointer_rva": hex(DATABASE_GLOBAL_RVA),
            "database_pointer": _raw_pointer(before["database_pointer"], field="before.database_pointer"),
            "actor": actor,
            "recipient": recipient,
        },
        "pair_relations": {
            "country_relation_rows_offset": hex(COUNTRY_RELATION_ROWS_OFFSET),
            "country_relation_count_offset": hex(COUNTRY_RELATION_COUNT_OFFSET),
            "actor_to_recipient": pair["actor_to_recipient"],
            "recipient_to_actor": pair["recipient_to_actor"],
            "selected_candidate": {
                "native_reference_va": hex(native_reference),
                "actor_slot": actor_slot,
                "recipient_slot": recipient_slot,
                "actor_match": {"counterpart_slot": recipient_slot, "direction": "actor_to_recipient"},
                "recipient_match": {"counterpart_slot": actor_slot, "direction": "recipient_to_actor"},
            },
        },
        "selected_war": {
            "war_pointer_va": hex(war_va),
            "native_reference_va": hex(native_reference),
            "public_stable_war_id": {"available": False, "reason": "retained native pointer is session-scoped"},
            "history_root": {
                "offset_from_war": hex(HISTORY_ROOT_OFFSET),
                "address_va": hex(history_root),
                "root_header_raw_hex": history_header.hex(),
                "retained_prefix_bytes": len(history_header),
                "expected_header_bytes": 0x40,
                "root_vtable_raw_hex": history_header[:8].hex(),
                "root_vtable_va": hex(root_vtable),
                "expected_vtable_rva": hex(HISTORY_ROOT_VTABLE_RVA),
                "vtable_matches_module_rva": root_vtable == module_base + HISTORY_ROOT_VTABLE_RVA,
                "history_status": "unknown",
                "unknown_reason": "history_root_vtable_slots_unsupported (0x90 observed 0x8f440 vs expected 0x8f450)",
            },
            "side_vectors": sides,
            "result": result,
        },
        "doublepass": {
            "performed": report["doublepass"].get("performed"),
            "consistent": report["doublepass"].get("consistent"),
            "all_read_bytes_compared": report["doublepass"].get("all_read_bytes_compared"),
            "before_selected_sha256": before_digest,
            "after_selected_sha256": after_digest,
            "selected_raw_equal": True,
        },
        "guards": {
            "runtime_code_guard": {"status": report.get("runtime_code_guard", {}).get("status"), "checks": report.get("runtime_code_guard", {}).get("checks", {})},
            "static_pe_supplement": {"kind": "PE_supplement_not_runtime_fixture", "status": guards.get("status") if isinstance(guards, dict) else None, "checks": pe_checks, "records": pe_records},
        },
        "cleanup": {"handle_close": report.get("cleanup", {}).get("handle_close")},
        "replay_limits": {"source_max_bytes": MAX_SOURCE_BYTES, "source_bytes_read": len(source_raw), "fixture_max_bytes": MAX_FIXTURE_BYTES},
        "validation": {
            "country_table_and_current_fullrefs": True,
            "both_country_relation_rows": True,
            "selected_war_history_root_address_binding": True,
            "selected_war_side_vectors": True,
            "result_and_result_side_fullrefs": True,
            "history_decoded_as_complete": False,
            "overall_capture_complete": False,
        },
        "source_contract": {"war_binding_contract": contract_pin, "war_identity_source_002": source002_pin},
    }
    return fixture, {"before_selected_sha256": before_digest, "after_selected_sha256": after_digest}


def _decode_fixture(fixture: dict[str, Any]) -> dict[str, Any]:
    """Decode retained fields without importing the production reader."""
    country = fixture["country_table_and_fullrefs"]
    actor = country["actor"]["country_fullref"]
    recipient = country["recipient"]["country_fullref"]
    _require(actor["tag"] == "FRA" and recipient["tag"] in {"BUR", "ENG"}, "unexpected fixture pair tags")
    actor_slot = actor["slot"]
    recipient_slot = recipient["slot"]
    pair = fixture["pair_relations"]
    candidate = _u64(pair["selected_candidate"]["native_reference_va"], field="candidate pointer") if False else int(pair["selected_candidate"]["native_reference_va"], 16)
    matches = {}
    for name, target in (("actor_to_recipient", recipient_slot), ("recipient_to_actor", actor_slot)):
        rows = pair[name]["row_records"]
        _require(len(rows) == pair[name]["count"]["value"], f"fixture {name} count mismatch")
        hit = [r for r in rows if r["counterpart"] == target and int(r["reference_va"], 16) == candidate]
        _require(hit, f"fixture {name} candidate target missing")
        matches[name] = [r["index"] for r in hit]
    war = fixture["selected_war"]
    war_va = int(war["war_pointer_va"], 16)
    _require(candidate == war_va, "fixture candidate does not bind to war pointer")
    root = war["history_root"]
    _require(int(root["address_va"], 16) == war_va + HISTORY_ROOT_OFFSET, "fixture history root offset mismatch")
    _require(_u64(root["root_vtable_raw_hex"], field="fixture history root vtable") == int(root["root_vtable_va"], 16), "fixture history vtable mismatch")
    _require(root.get("vtable_matches_module_rva") is True, "fixture history vtable/module binding mismatch")
    side_checks = {}
    for name in ("actor_side", "recipient_side"):
        side = war["side_vectors"][name]
        begin = int(side["begin_va"], 16)
        end = int(side["end_va"], 16)
        _require(end >= begin and (end - begin) // 8 == side["count"] == len(side["members"]), f"fixture {name} vector mismatch")
        side_checks[name] = side["count"]
    result = war["result"]
    result_raw = _hex_bytes(result["raw_hex"], field="fixture result.raw_hex", exact=RESULT_SIZE)
    _require(_u64(result_raw[:8].hex(), field="fixture result vtable") == int(result["vtable_va"], 16), "fixture result vtable mismatch")
    result_fullrefs = {}
    for name, off, expected in (("side_a", RESULT_SIDE_A_OFFSET, actor["raw_hex"]), ("side_b", RESULT_SIDE_B_OFFSET, recipient["raw_hex"])):
        side = result["sides"][name]
        side_raw = _hex_bytes(side["raw_hex"], field=f"fixture {name}.raw_hex", exact=SIDE_SIZE)
        _require(result_raw[off:off + SIDE_SIZE] == side_raw, f"fixture {name} raw slice mismatch")
        observed = side_raw[SIDE_COUNTRY_OFFSET:SIDE_COUNTRY_OFFSET + 8].hex()
        _require(observed == expected, f"fixture {name} fullref mismatch")
        result_fullrefs[name] = observed
    return {"candidate_va": hex(candidate), "relation_matches": matches, "side_counts": side_checks, "result_side_fullrefs": result_fullrefs}


def run(source: Path, fixture_path: Path, receipt_path: Path) -> int:
    report, source_raw = _load_bounded_json(source)
    fixture, digests = _build_fixture(report, source, source_raw)
    fixture_path.parent.mkdir(parents=True, exist_ok=True)
    fixture_bytes = json.dumps(fixture, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    _require(len(fixture_bytes) <= MAX_FIXTURE_BYTES, "fixture exceeds bounded size")
    fixture_path.write_bytes(fixture_bytes)
    decoded = _decode_fixture(json.loads(fixture_bytes))
    receipt = {
        "schema": "information_battle_war_binding_replay_receipt.v1",
        "status": "passed_partial_history",
        "mode": "offline_same_capture_fixture_replay",
        "source_report": {"path": _relative(source), "sha256": _sha256_bytes(source_raw), "bytes": len(source_raw)},
        "fixture": {"path": _relative(fixture_path), "sha256": _sha256_bytes(fixture_bytes), "bytes": len(fixture_bytes)},
        "decoded": decoded,
        "proof": {
            "single_source_capture": True,
            "country_table_and_current_fullrefs": True,
            "both_country_1548_relation_rows": True,
            "selected_war_0x108_history_root_bytes": True,
            "selected_war_0x48_0x78_side_vectors": True,
            "result_side_fullrefs": True,
            "before_after_selected_sha256_equal": digests["before_selected_sha256"] == digests["after_selected_sha256"],
            "native_game_calls": False,
            "new_rpm": False,
            "cross_capture_splice": False,
        },
        "caveats": [
            "history root retained header is a prefix and its 0x90 vtable slot mismatches the supported 0x8f450 predicate; history remains unknown.",
            "relation rows retain the native counterpart and reference fields but not the four middle stride bytes [4:8].",
            "the retained native pointer is a session-scoped war candidate; no stable public war_id is claimed.",
            "three codeguards are PE supplements and are not runtime fixture bytes.",
        ],
    }
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": receipt["status"], "source_sha256": receipt["source_report"]["sha256"], "fixture": _relative(fixture_path), "receipt": _relative(receipt_path), "decoded": decoded}, ensure_ascii=False, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline replay of one retained battle-war RPM report; no process/native access.")
    parser.add_argument("--run", action="store_true", help="explicitly generate the bounded fixture and receipt")
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE, help="one retained report.json")
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE, help="output self-contained fixture")
    parser.add_argument("--receipt", type=Path, default=DEFAULT_RECEIPT, help="output replay receipt")
    args = parser.parse_args(argv)
    if not args.run:
        print("inert: pass --run to replay one retained report; no RPM/native/game access is performed")
        return 0
    try:
        return run(args.source.resolve(), args.fixture.resolve(), args.receipt.resolve())
    except (OSError, ReplayError, KeyError, TypeError, ValueError) as exc:
        print(f"replay failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
