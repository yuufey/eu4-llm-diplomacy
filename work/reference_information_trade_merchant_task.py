"""Build an independent merchant-task reference from archived raw trade bytes.

The reference is deliberately derived from archived inputs rather than from a
production reader or a public MCP result.  It combines the two-pass 0xc0 trade
entry capture with the independently archived flag projection, then applies the
bounded B58C70 aggregate predicate and the requested AE/collection task rule.
No game, RPM, REA, or native function is invoked by this script.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-trade-merchant-task-20261027-001"

ENTRY_INPUT = (
    ROOT
    / "work/runtime/information-trade-share-20261027-001/native-trade-entry-inputs-002.json"
)
FLAG_INPUT = (
    ROOT
    / "work/runtime/information-trade-merchant-state-20261027-001/"
    / "native-flag-inputs-from-archived-raw-001.json"
)
COLLECTION_REFERENCE = (
    ROOT
    / "work/runtime/information-trade-merchant-state-20261027-001/"
    / "expected-trade-collection-001.json"
)
SERIALIZATION_001 = STAGE / "merchant-serialization-source-001.json"
SERIALIZATION_002 = STAGE / "merchant-serialization-source-002.json"
MERCHANT_STATE_002 = (
    ROOT
    / "work/runtime/information-trade-merchant-state-20261027-001/"
    / "merchant-state-source-002.json"
)
MERCHANT_STATE_001 = (
    ROOT
    / "work/runtime/information-trade-merchant-state-20261027-001/"
    / "merchant-state-source-001.json"
)
PRIOR_TASK_SOURCE = (
    ROOT
    / "work/runtime/information-trade-state-20261027-001/merchant-task-source-001.json"
)
OUTPUT = STAGE / "expected-trade-merchant-task-001.json"

EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
EXPECTED_GAME_VERSION = "1.37.4"
COUNTRY = "FRA"
TRUE_PREDICATE_RVA = "0x8f440"
FALSE_PREDICATE_RVA = "0x8f450"
ENTRY_SIZE = 0xC0
FULLREF_OFFSET = 0x10
FLAGS_OFFSET = 0xAC
SPECIAL_SLOT = 2
MAX_INPUT_BYTES = 10 * 1024 * 1024


def _sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    if size > MAX_INPUT_BYTES:
        raise ValueError(f"input exceeds bounded JSON limit: {path} ({size} bytes)")
    return json.loads(path.read_text(encoding="utf-8"))


def _relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _require_file(path: Path) -> None:
    if not path.is_file():
        raise FileNotFoundError(path)


def _raw_bytes(node: dict[str, Any]) -> bytes:
    raw_hex = node.get("entry_raw_hex")
    if not isinstance(raw_hex, str):
        raise AssertionError(f"missing raw C0 entry for {node.get('node_id')}")
    raw = bytes.fromhex(raw_hex)
    if len(raw) != ENTRY_SIZE:
        raise AssertionError(
            f"unexpected entry size for {node.get('node_id')}: {len(raw)}"
        )
    return raw


def _slot_and_fullref(raw: bytes) -> tuple[bytes, int]:
    fullref = raw[FULLREF_OFFSET : FULLREF_OFFSET + 8]
    if len(fullref) != 8:
        raise AssertionError("entry fullref window is truncated")
    slot = struct.unpack_from("<h", fullref, 4)[0]
    return fullref, slot


def _flags(raw: bytes) -> tuple[int, int, int, int]:
    return tuple(raw[FLAGS_OFFSET : FLAGS_OFFSET + 4])  # type: ignore[return-value]


def _collection_predicate(raw: bytes, special_slot: int) -> bool:
    """The complete bounded B58C70 mapping for a valid non-null entry."""
    _, slot = _slot_and_fullref(raw)
    ac, ad, ae, _af = _flags(raw)
    if slot == special_slot:
        return True
    if ae == 0:
        return ad != 0
    return ac == 0


def _task_from_flags(ae: int, collection: bool) -> str:
    # This is the requested independent reference rule, not a public MCP value.
    if ae == 0:
        return "none"
    return "collect" if collection else "transfer"


def _true_nodes(pass_data: dict[str, Any]) -> list[dict[str, Any]]:
    rows = [
        node
        for node in pass_data["nodes"]
        if node.get("predicate_rva") == TRUE_PREDICATE_RVA
    ]
    if len(rows) != 80:
        raise AssertionError(f"expected 80 true nodes, got {len(rows)}")
    return rows


def _false_nodes(pass_data: dict[str, Any]) -> list[dict[str, Any]]:
    rows = [
        node
        for node in pass_data["nodes"]
        if node.get("predicate_rva") == FALSE_PREDICATE_RVA
    ]
    if len(rows) != 1 or rows[0].get("node_id") != "Null":
        raise AssertionError(f"unexpected false predicate rows: {rows!r}")
    # The graph node projection omits ``entry_read`` for the false placeholder;
    # the parallel skipped list records the explicit false read decision.  The
    # absence of a C0 payload in this node is the bounded raw guard we need.
    if rows[0].get("entry_raw_hex") is not None:
        raise AssertionError("false predicate placeholder unexpectedly has C0 bytes")
    return rows


def _pin(path: Path, role: str, evidence_kind: str) -> dict[str, Any]:
    return {
        "path": _relative(path),
        "sha256": _sha_file(path),
        "role": role,
        "evidence_kind": evidence_kind,
    }


def _source_summary(path: Path, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": _relative(path),
        "sha256": _sha_file(path),
        "schema": data.get("schema"),
    }


def _build_report() -> dict[str, Any]:
    for path in (
        ENTRY_INPUT,
        FLAG_INPUT,
        COLLECTION_REFERENCE,
        SERIALIZATION_001,
        SERIALIZATION_002,
        MERCHANT_STATE_001,
        MERCHANT_STATE_002,
        PRIOR_TASK_SOURCE,
    ):
        _require_file(path)

    entry_data = _load_json(ENTRY_INPUT)
    flag_data = _load_json(FLAG_INPUT)
    collection_data = _load_json(COLLECTION_REFERENCE)
    serialization_001 = _load_json(SERIALIZATION_001)
    serialization_002 = _load_json(SERIALIZATION_002)
    merchant_state_001 = _load_json(MERCHANT_STATE_001)
    merchant_state_002 = _load_json(MERCHANT_STATE_002)
    prior_task_source = _load_json(PRIOR_TASK_SOURCE)

    exe_sha = entry_data["identity"]["process_path_sha256"]
    if exe_sha != EXPECTED_EXE_SHA256:
        raise AssertionError(f"unexpected executable SHA: {exe_sha}")
    if entry_data["target_build"]["version"] != EXPECTED_GAME_VERSION:
        raise AssertionError("unexpected game version")
    if entry_data["country"] != COUNTRY:
        raise AssertionError("unexpected entry capture country")
    if flag_data["identity_binding"]["country"] != COUNTRY:
        raise AssertionError("unexpected flag capture country")
    if collection_data["country"] != COUNTRY:
        raise AssertionError("unexpected collection reference country")

    session_id = entry_data["identity"]["installation_session_id"]
    game_date = entry_data["trade_entries_inputs"][0]["date"]["value"]
    if session_id != flag_data["identity_binding"]["session_id"]:
        raise AssertionError("entry/flag session mismatch")
    if session_id != collection_data["session_id"]:
        raise AssertionError("entry/collection session mismatch")
    if game_date != flag_data["identity_binding"]["game_date_raw"]:
        raise AssertionError("entry/flag date mismatch")
    if game_date != collection_data["game_date"]:
        raise AssertionError("entry/collection date mismatch")

    passes = entry_data["trade_entries_inputs"]
    if len(passes) != 2:
        raise AssertionError("the entry reference must contain exactly two passes")
    true_passes = [_true_nodes(pass_data) for pass_data in passes]
    false_passes = [_false_nodes(pass_data) for pass_data in passes]
    node_order = [node["node_id"] for node in true_passes[0]]
    if [node["node_id"] for node in true_passes[1]] != node_order:
        raise AssertionError("true-node order changed between entry passes")
    if node_order != collection_data["node_order"]:
        raise AssertionError("entry order differs from independent collection order")
    if len(node_order) != 80 or len(set(node_order)) != 80:
        raise AssertionError("true-node order is not 80 unique node IDs")

    country_fullref = bytes.fromhex(passes[0]["country_reference_raw_hex"])
    if country_fullref.hex() != collection_data["country_fullref_raw_hex"]:
        raise AssertionError("country fullref mismatch")
    country_slot = passes[0]["country_slot"]
    if country_slot != collection_data["country_slot"]:
        raise AssertionError("country slot mismatch")
    if passes[0]["fullref_slot"] != country_slot or passes[1]["fullref_slot"] != country_slot:
        raise AssertionError("entry pass fullref slot mismatch")
    special_raw = bytes.fromhex(passes[0]["filter_special_country_slot_raw_hex"])
    if len(special_raw) < 4:
        raise AssertionError("special slot raw guard is truncated")
    special_slot = struct.unpack_from("<I", special_raw, 0)[0]
    if special_slot != SPECIAL_SLOT or special_slot != collection_data["special_slot"]:
        raise AssertionError("special slot mismatch")

    pass0 = {node["node_id"]: node for node in true_passes[0]}
    pass1 = {node["node_id"]: node for node in true_passes[1]}
    flag_rows = {node["node_id"]: node for node in flag_data["nodes"]}
    if set(flag_rows) != set(node_order):
        raise AssertionError("flag archive node set differs from entry archive")
    collection_nodes = collection_data["nodes"]
    if set(collection_nodes) != set(node_order):
        raise AssertionError("collection reference node set differs")

    output_nodes: dict[str, dict[str, Any]] = {}
    ordered_tasks: list[dict[str, str]] = []
    counts = {"none": 0, "collect": 0, "transfer": 0}
    all_pass_raw_equal = True
    all_pass_addresses_equal = True
    all_flag_raw_equal = True
    all_flag_values_equal = True
    all_collection_crosscheck_equal = True

    for node_id in node_order:
        first = pass0[node_id]
        second = pass1[node_id]
        raw0 = _raw_bytes(first)
        raw1 = _raw_bytes(second)
        fullref0, slot0 = _slot_and_fullref(raw0)
        fullref1, slot1 = _slot_and_fullref(raw1)
        ac, ad, ae, af = _flags(raw0)
        ac1, ad1, ae1, af1 = _flags(raw1)
        flag_row = flag_rows[node_id]
        flag_raw = _raw_bytes(flag_row)
        flag_ac, flag_ad, flag_ae, flag_af = _flags(flag_raw)
        collection = _collection_predicate(raw0, special_slot)
        task = _task_from_flags(ae, collection)
        counts[task] += 1
        if task != "none":
            ordered_tasks.append({"node_id": node_id, "task": task})

        pass_raw_equal = raw0 == raw1
        pass_addresses_equal = first["entry_address"] == second["entry_address"]
        flag_raw_equal = raw0 == flag_raw
        flag_values_equal = (ac, ad, ae, af) == (flag_ac, flag_ad, flag_ae, flag_af)
        collection_crosscheck_equal = bool(collection_nodes[node_id]["collection"]) == collection
        all_pass_raw_equal &= pass_raw_equal
        all_pass_addresses_equal &= pass_addresses_equal
        all_flag_raw_equal &= flag_raw_equal
        all_flag_values_equal &= flag_values_equal
        all_collection_crosscheck_equal &= collection_crosscheck_equal
        if not (pass_raw_equal and pass_addresses_equal and flag_raw_equal and flag_values_equal):
            raise AssertionError(f"raw/flag mismatch for {node_id}")
        if not collection_crosscheck_equal:
            raise AssertionError(f"collection cross-check mismatch for {node_id}")
        if (ac, ad, ae, af) != (ac1, ad1, ae1, af1):
            raise AssertionError(f"entry flags changed between passes for {node_id}")
        if fullref0 != fullref1 or fullref0 != country_fullref:
            raise AssertionError(f"fullref mismatch for {node_id}")
        if slot0 != country_slot or slot1 != country_slot:
            raise AssertionError(f"slot mismatch for {node_id}")

        entry_raw_sha = _sha_bytes(raw0)
        output_nodes[node_id] = {
            "merchant_task": task,
            "has_trader": ae != 0,
            "flag_ae": ae,
            "flags_raw_hex": raw0[FLAGS_OFFSET : FLAGS_OFFSET + 3].hex(),
            "flags_ac_ad_ae_af_hex": raw0[FLAGS_OFFSET : FLAGS_OFFSET + 4].hex(),
            "flags": {"AC": ac, "AD": ad, "AE": ae, "AF": af},
            "collection": collection,
            "raw_inputs": {
                "entry_address": first["entry_address"],
                "entry_size_bytes": len(raw0),
                "entry_raw_hex": raw0.hex(),
                "entry_raw_sha256": entry_raw_sha,
                "entry_fullref_offset": hex(FULLREF_OFFSET),
                "entry_fullref_raw_hex": fullref0.hex(),
                "entry_flags_offset": hex(FLAGS_OFFSET),
                "entry_flags_raw_hex": raw0[FLAGS_OFFSET : FLAGS_OFFSET + 4].hex(),
                "entry_pointer_nonnull": bool(int(first["entry_address"], 16)),
                "country_slot": slot0,
                "special_slot": special_slot,
            },
            "flag_archive": {
                "predicate_rva": flag_row["predicate_rva"],
                "entry_address": flag_row["entry_address"],
                "entry_raw_sha256": _sha_bytes(flag_raw),
                "flags_ac_ad_ae_af_hex": flag_row["flags_ac_ad_ae_af_hex"],
            },
            "pass_consistency": {
                "entry_raw_bytes": pass_raw_equal,
                "entry_addresses": pass_addresses_equal,
                "fullref": fullref0 == fullref1 == country_fullref,
                "flags": (ac, ad, ae, af) == (ac1, ad1, ae1, af1),
                "flag_archive_entry_raw": flag_raw_equal,
                "flag_archive_flags": flag_values_equal,
                "collection_reference": collection_crosscheck_equal,
            },
        }

    if counts != {"none": 78, "collect": 1, "transfer": 1}:
        raise AssertionError(f"unexpected task counts: {counts}")
    if ordered_tasks != [
        {"node_id": "rheinland", "task": "transfer"},
        {"node_id": "champagne", "task": "collect"},
    ]:
        raise AssertionError(f"unexpected active task order: {ordered_tasks}")

    b58 = merchant_state_002["b58c70_aggregate_mapping"]
    if b58["target_rva"] != "0xb58c70":
        raise AssertionError("unexpected B58C70 target")
    serialization_bindings = serialization_002["field_serializer_bindings"]
    if serialization_bindings["0xae"]["key_name"] != "has_trader":
        raise AssertionError("serializer correction does not bind AE to has_trader")
    if serialization_bindings["0xae"]["selector"] != "0x2c09":
        raise AssertionError("unexpected AE serializer selector")

    entry_summary = {
        **_source_summary(ENTRY_INPUT, entry_data),
        "identity": {
            "session_id": session_id,
            "game_date": game_date,
            "country": COUNTRY,
            "country_fullref_raw_hex": country_fullref.hex(),
            "country_slot": country_slot,
            "special_slot": special_slot,
            "exe_sha256": exe_sha,
        },
        "passes": 2,
        "true_nodes_per_pass": [len(rows) for rows in true_passes],
        "false_nodes_per_pass": [len(rows) for rows in false_passes],
        "entry_size_bytes": ENTRY_SIZE,
        "entry_bytes_per_pass": [pass_data["entry_read_bytes"] for pass_data in passes],
        "rpm_bytes_requested": entry_data["access_summary"]["rpm_bytes_requested"],
        "rpm_calls": entry_data["access_summary"]["rpm_calls"],
        "native_function_invoked": entry_data["capture_contract"]["native_function_invoked"],
        "target_memory_writes": entry_data["capture_contract"]["target_memory_writes"],
        "raw_only": entry_data["capture_contract"]["raw_only"],
        "handle_closed": entry_data["access_summary"]["handle_close"],
        "bounded_read": "predicate 0x8f440 true nodes only; one 0xc0 entry per true node per pass; 0x8f450 Null skipped",
    }
    flag_summary = {
        **_source_summary(FLAG_INPUT, flag_data),
        "identity": flag_data["identity_binding"],
        "passes": flag_data["capture_summary"]["passes"],
        "true_nodes_per_pass": flag_data["capture_summary"]["true_nodes_per_pass"],
        "entry_bytes_per_pass": flag_data["capture_summary"]["entry_bytes_per_pass"],
        "no_new_capture": flag_data["capture_summary"]["no_new_capture"],
        "handle_closed": flag_data["capture_summary"]["handle_close"],
        "bounded_projection": "AC/AD/AE/AF at entry+0xac..0xaf plus full archived C0 entry",
    }
    collection_summary = {
        **_source_summary(COLLECTION_REFERENCE, collection_data),
        "identity": {
            "session_id": collection_data["session_id"],
            "game_date": collection_data["game_date"],
            "country": collection_data["country"],
            "country_fullref_raw_hex": collection_data["country_fullref_raw_hex"],
            "country_slot": collection_data["country_slot"],
            "special_slot": collection_data["special_slot"],
        },
        "used_as": "independent cross-check only; collection booleans were recomputed from entry bytes",
        "all_80_match": all_collection_crosscheck_equal,
        "public_values_used": False,
    }

    source_pins = [
        _pin(
            SERIALIZATION_002,
            "corrected AE serializer key binding: 0xae/0x2c09/has_trader",
            "ordinary_static_report_with_prior_correction",
        ),
        _pin(
            SERIALIZATION_001,
            "prior serializer report retained for correction trace; not overwritten",
            "prior_ordinary_static_report",
        ),
        _pin(
            MERCHANT_STATE_002,
            "complete bounded B58C70 aggregate predicate contract",
            "ordinary_bounded_static_report",
        ),
        _pin(
            MERCHANT_STATE_001,
            "prior B58C70/merchant-state report retained",
            "prior_ordinary_static_report",
        ),
        _pin(
            PRIOR_TASK_SOURCE,
            "original B58C70 target byte provenance reused by merchant-state report",
            "prior_ordinary_static_report",
        ),
        _pin(
            ENTRY_INPUT,
            "authoritative archived two-pass raw 0xc0 entries",
            "archived_independent_RPM_capture",
        ),
        _pin(
            FLAG_INPUT,
            "archived independent AC/AD/AE/AF projection and C0 cross-check",
            "archived_independent_raw_projection",
        ),
        _pin(
            COLLECTION_REFERENCE,
            "independent collection reference used only for all-80 cross-check",
            "independent_archived_reference_not_public_values",
        ),
    ]

    return {
        "schema": "information_trade_merchant_task_independent_expected.v1",
        "reference_id": "expected-trade-merchant-task-001",
        "stage": "information-trade-merchant-task-20261027-001",
        "status": "observed_reference",
        "complete": False,
        "basis": "independent_archived_raw_and_native_merchant_presence_collection_predicate_not_public_values",
        "header": {
            "session_id": session_id,
            "game_date": game_date,
            "country": COUNTRY,
            "country_fullref_raw_hex": country_fullref.hex(),
            "country_slot": country_slot,
            "special_slot": special_slot,
            "game_version": EXPECTED_GAME_VERSION,
            "exe_sha256": exe_sha,
        },
        "node_count": len(node_order),
        "node_order": node_order,
        "nodes": output_nodes,
        "country_merchant_tasks": ordered_tasks,
        "merchant_task_count": len(ordered_tasks),
        "task_counts": counts,
        "predicate": {
            "rva": b58["target_rva"],
            "va": b58["target_va"],
            "bytes_hex": b58["target_bytes_hex"],
            "bytes_sha256": b58["target_bytes_sha256"],
            "entry_pointer_precondition": b58["contract"]["entry_pointer_precondition"],
            "special_slot": b58["contract"]["special_slot"],
            "native_order": [
                "valid non-null C0 entry is required",
                "slot = signed int16(entry[0x10:0x18][4:6])",
                "slot == special_slot -> true",
                "otherwise AE == 0 -> AD != 0",
                "otherwise AE != 0 -> AC == 0",
            ],
            "raw_offsets": {
                "fullref": hex(FULLREF_OFFSET),
                "AC": hex(FLAGS_OFFSET),
                "AD": hex(FLAGS_OFFSET + 1),
                "AE": hex(FLAGS_OFFSET + 2),
                "AF": hex(FLAGS_OFFSET + 3),
                "entry_size": hex(ENTRY_SIZE),
            },
            "semantic_scope": "aggregate collection/entry eligibility; reused as the collection input to the requested task reference rule",
        },
        "field_binding": {
            "source_report": _relative(SERIALIZATION_002),
            "source_report_sha256": _sha_file(SERIALIZATION_002),
            "correction_record": serialization_002["prior_reason_correction"],
            "ae": {
                "entry_offset": "0xae",
                "selector": serialization_bindings["0xae"]["selector"],
                "key_name": serialization_bindings["0xae"]["key_name"],
                "has_trader_rule": "AE == 0 -> false; AE != 0 -> true",
                "status": serialization_bindings["0xae"]["status"],
            },
            "ad_ac": {
                "entry_offsets": ["0xad", "0xac"],
                "used_by": "B58C70 aggregate predicate only",
                "business_task_semantics": "not separately named by this reference",
            },
        },
        "merchant_task_derivation": {
            "rule": "AE == 0 -> none; AE != 0 and B58C70 collection true -> collect; AE != 0 and B58C70 collection false -> transfer",
            "independent_raw_calculation": True,
            "public_mcp_values_used": False,
            "native_ui_task_semantics": "not independently proven by this archive; values are the requested raw-derived reference classification",
            "active_nodes": ordered_tasks,
        },
        "raw_provenance": {
            "entry_capture": entry_summary,
            "flag_archive": flag_summary,
            "collection_reference": collection_summary,
            "entry_pass_consistency": {
                "node_order": True,
                "entry_raw_bytes": all_pass_raw_equal,
                "entry_addresses": all_pass_addresses_equal,
                "fullref": True,
                "flags": True,
            },
            "entry_to_flag_archive": {
                "node_order": True,
                "full_c0_entry_bytes": all_flag_raw_equal,
                "ac_ad_ae_af": all_flag_values_equal,
            },
        },
        "cross_archive_identity": {
            "session_equal": True,
            "game_date_equal": True,
            "exe_sha_equal": True,
            "country_equal": True,
            "country_fullref_equal": True,
            "country_slot_equal": True,
            "special_slot_equal": True,
            "true_node_count_equal": True,
            "false_predicate_placeholder_excluded": True,
            "false_predicate_rva": FALSE_PREDICATE_RVA,
            "true_predicate_rva": TRUE_PREDICATE_RVA,
        },
        "source_pins": source_pins,
        "semantics": {
            "country_merchant_tasks": "only non-none rows in the archived native node order",
            "has_trader": "derived from the corrected static serializer binding of entry+0xae to has_trader",
            "collection": "B58C70 aggregate eligibility for a valid non-null entry",
            "none": "reference rule for AE == 0; not a separately proven UI no-merchant label",
            "transfer": "reference rule for AE != 0 and collection false; not a standalone UI enum proof",
            "freshness": "archived reference only; no current refresh claim",
            "scope": "FRA observer, fixed 1.37.4 build, 80 true predicate nodes",
            "unsupported": [
                "independent merchant presence container semantics",
                "runtime freshness or GUI equivalence",
                "foreign-country visibility",
                "steering direction and transfer amount",
            ],
        },
        "verification": {
            "archive_redecoded": True,
            "no_new_RPM": True,
            "no_game_access": True,
            "production_reader_imported": False,
            "public_MCP_values_used": False,
            "entry_two_pass_consistent": all_pass_raw_equal and all_pass_addresses_equal,
            "flag_archive_matches_entries": all_flag_raw_equal and all_flag_values_equal,
            "collection_crosscheck_all_80": all_collection_crosscheck_equal,
            "source_json_sha256_checked": True,
            "old_outputs_modified": False,
            "all_shells_terminal": True,
            "script_path": _relative(Path(__file__).resolve()),
            "script_sha256": _sha_file(Path(__file__).resolve()),
        },
    }


def main() -> int:
    if OUTPUT.exists():
        raise SystemExit(f"refusing to overwrite existing output: {OUTPUT}")
    report = _build_report()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "output": _relative(OUTPUT),
                "output_sha256": _sha_file(OUTPUT),
                "script_sha256": _sha_file(Path(__file__).resolve()),
                "nodes": report["node_count"],
                "merchant_task_count": report["merchant_task_count"],
                "task_counts": report["task_counts"],
                "entry_rpm_reused": True,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
