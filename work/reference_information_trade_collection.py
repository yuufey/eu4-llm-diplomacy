"""Build an independent archived reference for the native trade collection gate.

This script intentionally reads only the frozen raw JSON captures and static
reports.  It does not import any production reader, call the game, or use a
public/MCP value as the expected result.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work" / "runtime" / "information-trade-merchant-state-20261027-001"
INCOME_RAW = ROOT / "work" / "runtime" / "information-budget-collectors-20261027-001" / "native-trade-income-inputs-005.json"
INCOME_EXPECTED = ROOT / "work" / "runtime" / "information-budget-collectors-20261027-001" / "expected-trade-income-001.json"
ENTRY_RAW = ROOT / "work" / "runtime" / "information-trade-share-20261027-001" / "native-trade-entry-inputs-002.json"
MERCHANT_SOURCE = STAGE / "merchant-state-source-002.json"
INCOME_INDEX = ROOT / "work" / "runtime" / "information-budget-collectors-20261027-001" / "trade-income-source-index-001.json"
INCOME_SOURCE = ROOT / "work" / "runtime" / "information-budget-collectors-20261027-001" / "trade-income-source-001.json"
MERCHANT_TASK_SOURCE = ROOT / "work" / "runtime" / "information-trade-state-20261027-001" / "merchant-task-source-001.json"
OUTPUT = STAGE / "expected-trade-collection-001.json"

EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_SESSION_ID = "31460-1dd653f69242d7b"
EXPECTED_GAME_DATE = 56557728
EXPECTED_COUNTRY = "FRA"
ENTRY_SIZE = 0xC0
FULLREF_OFFSET = 0x10
FLAGS_OFFSET = 0xAC
SPECIAL_SLOT_RAW_OFFSET = "filter_special_country_slot_raw_hex"
B58C70_RVA = "0xb58c70"
B58C70_END_RVA = "0xb58cd0"
B58C70_BYTES_HEX = (
    "488b4918488bc248c1e820480fbfc048c1ea204c8d04400fbfc249c1e0064903c83b05214c7e017505"
    "4885c9752c32d23891ae00000074100fb681ac00000084c00f95c284c074124885c9741080b9ad00000000740784d27503b001c332c0c3"
)
B58C70_SHA256 = "538633a24ef1d91748838e1ff97234e635a7efd9e840553bb8a4c2397c831ae3"


def _read(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _capture_identity(document: dict[str, Any], label: str) -> dict[str, Any]:
    _require(document.get("status") == "observed", f"{label}:status")
    _require(document.get("country") == EXPECTED_COUNTRY, f"{label}:country")
    _require(document.get("target_build", {}).get("version") == "1.37.4", f"{label}:version")
    _require(document.get("target_build", {}).get("expected_exe_sha256") == EXPECTED_EXE_SHA256, f"{label}:target_sha")
    identity = document.get("identity", {})
    _require(identity.get("installation_session_id") == EXPECTED_SESSION_ID, f"{label}:session")
    _require(identity.get("process_path_sha256") == EXPECTED_EXE_SHA256, f"{label}:process_sha")
    _require(identity.get("binding_verified") is True, f"{label}:binding")
    _require(document.get("doublepass", {}).get("performed") is True, f"{label}:doublepass_performed")
    _require(document.get("doublepass", {}).get("consistent") is True, f"{label}:doublepass_consistent")
    _require(document.get("cleanup", {}).get("handle_close", {}).get("closed") is True, f"{label}:handle_closed")
    return {
        "session_id": identity["installation_session_id"],
        "process_sha256": identity["process_path_sha256"],
        "creation_filetime": identity.get("process_creation_filetime"),
        "doublepass": dict(document["doublepass"]),
        "handle_close": dict(document["cleanup"]["handle_close"]),
    }


def _pass_metadata(pass_record: dict[str, Any], label: str) -> dict[str, Any]:
    date = pass_record.get("date", {})
    _require(date.get("value") == EXPECTED_GAME_DATE, f"{label}:date")
    keys = (
        "country_reference_raw_hex",
        "country_slot",
        SPECIAL_SLOT_RAW_OFFSET,
        "game_global_raw_hex",
        "province_base_raw_hex",
        "definitions_manager_pointer_raw_hex",
        "definitions_header_hex",
        "definition_pointers_hex",
    )
    result = {key: pass_record.get(key) for key in keys}
    for key, value in result.items():
        _require(value is not None, f"{label}:missing_{key}")
    fullref = bytes.fromhex(result["country_reference_raw_hex"])
    _require(len(fullref) == 8, f"{label}:fullref_size")
    slot_from_fullref = int.from_bytes(fullref[4:6], "little", signed=True)
    _require(slot_from_fullref == result["country_slot"], f"{label}:fullref_slot")
    result["slot_from_fullref"] = slot_from_fullref
    result["special_slot"] = int.from_bytes(bytes.fromhex(result[SPECIAL_SLOT_RAW_OFFSET]), "little", signed=True)
    result["date_raw_hex"] = date.get("raw_hex")
    result["date"] = date.get("value")
    return result


def _real_nodes(nodes: list[dict[str, Any]], label: str) -> list[dict[str, Any]]:
    _require(isinstance(nodes, list), f"{label}:nodes_not_list")
    real = [node for node in nodes if node.get("node_id") != "Null"]
    _require(len(real) == 80, f"{label}:expected_80_real_nodes")
    _require(len({node.get("node_id") for node in real}) == 80, f"{label}:duplicate_node_ids")
    return real


def _entry_flags(node: dict[str, Any], label: str) -> tuple[bytes, bytes, bytes]:
    raw_hex = node.get("entry_raw_hex")
    _require(isinstance(raw_hex, str), f"{label}:entry_raw_missing")
    raw = bytes.fromhex(raw_hex)
    _require(len(raw) == ENTRY_SIZE, f"{label}:entry_size")
    _require(node.get("entry_read") is True, f"{label}:entry_not_read")
    address = node.get("entry_address")
    _require(isinstance(address, str) and int(address, 16) != 0, f"{label}:entry_pointer_invalid")
    fullref = raw[FULLREF_OFFSET:FULLREF_OFFSET + 8]
    flags = raw[FLAGS_OFFSET:FLAGS_OFFSET + 3]
    recorded_flags = bytes.fromhex(node.get("flags_ac_ad_ae_hex", ""))
    _require(flags == recorded_flags, f"{label}:entry_flag_projection_mismatch")
    return raw, fullref, flags


def _collection_predicate(*, slot: int, special_slot: int, entry_address: str, raw: bytes) -> bool:
    """Mirror the complete B58C70 branch order for a valid raw entry.

    The native leaf has no null-to-false conversion.  Invalid/missing entry
    data is rejected by the reference instead of becoming a false result.
    """
    _require(int(entry_address, 16) != 0, "entry_pointer_missing_not_false")
    _require(len(raw) == ENTRY_SIZE, "entry_bytes_missing_not_false")
    if slot == special_slot:
        return True
    ac, ad, ae = raw[FLAGS_OFFSET:FLAGS_OFFSET + 3]
    if ae == 0:
        return ad != 0
    return ac == 0


def _source_pin(path: Path, *, role: str, evidence_kind: str | None = None) -> dict[str, Any]:
    item = {"path": _rel(path), "sha256": _sha256(path), "role": role}
    if evidence_kind is not None:
        item["evidence_kind"] = evidence_kind
    return item


def build_reference() -> dict[str, Any]:
    income_capture = _read(INCOME_RAW)
    entry_capture = _read(ENTRY_RAW)
    income_expected = _read(INCOME_EXPECTED)
    merchant_source = _read(MERCHANT_SOURCE)
    income_index = _read(INCOME_INDEX)
    income_source = _read(INCOME_SOURCE)
    merchant_task_source = _read(MERCHANT_TASK_SOURCE)

    income_identity = _capture_identity(income_capture, "income_capture")
    entry_identity = _capture_identity(entry_capture, "entry_capture")
    _require(income_identity == entry_identity, "archive_identity_mismatch")
    _require(income_expected.get("session_id") == EXPECTED_SESSION_ID, "expected_income:session")
    _require(income_expected.get("game_date") == EXPECTED_GAME_DATE, "expected_income:date")
    _require(income_expected.get("country") == EXPECTED_COUNTRY, "expected_income:country")
    _require(income_expected.get("reference_sha256") == _sha256(INCOME_RAW), "expected_income:reference_pin")
    _require(merchant_source.get("target", {}).get("exe_sha256") == EXPECTED_EXE_SHA256, "merchant_source:target_sha")
    _require(income_index.get("target", {}).get("exe_sha256") == EXPECTED_EXE_SHA256, "income_index:target_sha")

    income_passes = income_capture.get("trade_income_inputs")
    entry_passes = entry_capture.get("trade_entries_inputs")
    _require(isinstance(income_passes, list) and len(income_passes) == 2, "income_capture:two_passes")
    _require(isinstance(entry_passes, list) and len(entry_passes) == 2, "entry_capture:two_passes")
    income_meta = [_pass_metadata(record, f"income_pass_{index}") for index, record in enumerate(income_passes)]
    entry_meta = [_pass_metadata(record, f"entry_pass_{index}") for index, record in enumerate(entry_passes)]
    _require(income_meta[0] == income_meta[1], "income_pass_metadata_changed")
    _require(entry_meta[0] == entry_meta[1], "entry_pass_metadata_changed")
    _require(income_meta[0] == entry_meta[0], "income_entry_metadata_mismatch")
    meta = income_meta[0]
    _require(meta["slot_from_fullref"] == 122, "unexpected_FRA_slot")
    _require(meta["special_slot"] == 2, "unexpected_special_slot")

    income_nodes_by_pass = [_real_nodes(record["nodes"], f"income_pass_{index}") for index, record in enumerate(income_passes)]
    entry_nodes_by_pass = [_real_nodes(record["trade_entry_nodes"], f"entry_pass_{index}") for index, record in enumerate(entry_passes)]
    order = [node["node_id"] for node in entry_nodes_by_pass[0]]
    _require(order == [node["node_id"] for node in entry_nodes_by_pass[1]], "entry_node_order_changed")
    _require(order == [node["node_id"] for node in income_nodes_by_pass[0]], "income_entry_node_order_mismatch")
    _require(order == [node["node_id"] for node in income_nodes_by_pass[1]], "income_second_node_order_mismatch")

    expected_nodes = income_expected.get("nodes")
    _require(isinstance(expected_nodes, dict) and len(expected_nodes) == 80, "expected_income_node_shape")
    result_nodes: dict[str, Any] = {}
    income_flag_matches = 0
    entry_flag_matches = 0
    entry_fullref_matches = 0
    doublepass_matches = 0
    for index, node_id in enumerate(order):
        income0 = income_nodes_by_pass[0][index]
        income1 = income_nodes_by_pass[1][index]
        entry0 = entry_nodes_by_pass[0][index]
        entry1 = entry_nodes_by_pass[1][index]
        _require(income0["node_id"] == node_id and income1["node_id"] == node_id, f"node_order:{node_id}")
        _require(income0.get("flags_ac_ad_ae_hex") == income1.get("flags_ac_ad_ae_hex"), f"income_flags_changed:{node_id}")
        _require(entry0.get("flags_ac_ad_ae_hex") == entry1.get("flags_ac_ad_ae_hex"), f"entry_flags_changed:{node_id}")
        _require(income0.get("flags_ac_ad_ae_hex") == entry0.get("flags_ac_ad_ae_hex"), f"archive_flags_mismatch:{node_id}")
        income_flag_matches += 1
        entry_flag_matches += 1
        raw0, fullref0, flags0 = _entry_flags(entry0, f"entry_pass_0:{node_id}")
        raw1, fullref1, flags1 = _entry_flags(entry1, f"entry_pass_1:{node_id}")
        _require(raw0 == raw1, f"entry_bytes_changed:{node_id}")
        _require(fullref0.hex() == meta["country_reference_raw_hex"], f"node_fullref_mismatch:{node_id}")
        _require(fullref0 == fullref1, f"node_fullref_changed:{node_id}")
        entry_fullref_matches += 1
        doublepass_matches += 1
        _require(income0.get("entry_address") == entry0.get("entry_address"), f"entry_address_mismatch:{node_id}")
        collection = _collection_predicate(
            slot=meta["slot_from_fullref"],
            special_slot=meta["special_slot"],
            entry_address=entry0["entry_address"],
            raw=raw0,
        )
        expected_eligible = expected_nodes[node_id].get("eligible")
        _require(type(expected_eligible) is bool, f"expected_income_eligible_invalid:{node_id}")
        _require(collection == expected_eligible, f"income_crosscheck_mismatch:{node_id}")
        result_nodes[node_id] = {
            "collection": collection,
            "flags_raw_hex": flags0.hex(),
            "flags": {"AC": flags0[0], "AD": flags0[1], "AE": flags0[2]},
            "raw_inputs": {
                "entry_address": entry0["entry_address"],
                "entry_size_bytes": len(raw0),
                "entry_raw_sha256": hashlib.sha256(raw0).hexdigest(),
                "entry_fullref_offset": "0x10",
                "entry_fullref_raw_hex": fullref0.hex(),
                "entry_flags_offset": "0xac",
                "entry_flags_raw_hex": raw0[FLAGS_OFFSET:FLAGS_OFFSET + 3].hex(),
                "entry_pointer_nonnull": True,
                "country_slot": meta["slot_from_fullref"],
                "special_slot": meta["special_slot"],
                "income_cache_raw": income0.get("income_raw"),
                "income_reference_eligible_crosscheck": expected_eligible,
            },
            "pass_consistency": {"income_flags": True, "entry_flags": True, "entry_c0_bytes": True, "entry_fullref": True},
        }

    true_nodes = [node_id for node_id in order if result_nodes[node_id]["collection"]]
    _require(true_nodes == ["champagne"], "unexpected_collection_population")
    _require(sum(1 for node_id in order if result_nodes[node_id]["collection"]) == 1, "unexpected_collection_count")
    merchant_mapping = merchant_source.get("b58c70_aggregate_mapping", {})
    target_bytes = bytes.fromhex(merchant_mapping.get("target_bytes_hex", ""))
    _require(merchant_mapping.get("target_rva") == B58C70_RVA, "merchant_source:target_rva")
    _require(merchant_mapping.get("target_bytes_sha256") == B58C70_SHA256, "merchant_source:target_sha256")
    _require(target_bytes.hex() == B58C70_BYTES_HEX, "merchant_source:target_bytes")
    _require(hashlib.sha256(target_bytes).hexdigest() == B58C70_SHA256, "formula_sha256")

    return {
        "schema": "information_trade_collection_independent_expected.v1",
        "reference_id": "expected-trade-collection-001",
        "status": "observed_reference",
        "complete": False,
        "basis": "independent_archived_raw_and_native_collection_predicate_not_public_values",
        "session_id": EXPECTED_SESSION_ID,
        "game_date": EXPECTED_GAME_DATE,
        "country": EXPECTED_COUNTRY,
        "country_fullref_raw_hex": meta["country_reference_raw_hex"],
        "country_slot": meta["slot_from_fullref"],
        "special_slot": meta["special_slot"],
        "node_count": len(order),
        "node_order": order,
        "nodes": result_nodes,
        "country_collection": true_nodes,
        "collection_count": len(true_nodes),
        "predicate": {
            "rva": B58C70_RVA,
            "end_rva_exclusive": B58C70_END_RVA,
            "va": "0x140b58c70",
            "end_va_exclusive": "0x140b58cd0",
            "bytes_hex": B58C70_BYTES_HEX,
            "bytes_sha256": B58C70_SHA256,
            "entry_pointer_precondition": "valid non-null C0 entry is required; invalid/missing entry aborts reference generation rather than becoming false",
            "native_order": [
                "slot = signed int16(fullref[4:6])",
                "entry = country_table_base + slot * 0xc0",
                "if slot == special_slot: true (only after non-null entry validation)",
                "else if AE == 0: AD != 0",
                "else: AC == 0",
            ],
            "raw_offsets": {"fullref": "0x10", "AC": "0xac", "AD": "0xad", "AE": "0xae", "entry_size": "0xc0"},
            "semantic_boundary": "aggregate collection/entry eligibility only; false is not a proven none/merchant absence value",
        },
        "source_pins": [
            _source_pin(MERCHANT_SOURCE, role="complete B58C70 aggregate mapping and boundary", evidence_kind="ordinary_bounded_static_report_reusing_prior_leaf"),
            _source_pin(INCOME_INDEX, role="entry layout, slot/global offsets and eligibility derivation", evidence_kind="ordinary_static_source_index"),
            _source_pin(INCOME_SOURCE, role="independent income enumeration/source provenance", evidence_kind="ordinary_bounded_static_report"),
            _source_pin(INCOME_RAW, role="archived raw 42 input: flags, country/fullref, slot, auxiliary/global fields", evidence_kind="archived_independent_RPM_capture"),
            _source_pin(ENTRY_RAW, role="archived raw 45 C0 entries: fullref and AC/AD/AE byte windows", evidence_kind="archived_independent_RPM_capture"),
            _source_pin(INCOME_EXPECTED, role="prior independent income eligibility cross-check only", evidence_kind="independent_reference_not_public_values"),
            _source_pin(MERCHANT_TASK_SOURCE, role="original B58C70 target byte provenance", evidence_kind="prior_static_report"),
        ],
        "capture_script_sources": {
            "income_capture": {
                "path_recorded_in_capture": income_capture.get("probe_script"),
                "sha256_recorded_in_capture": income_capture.get("probe_script_sha256"),
                "note": "The 42 raw005 capture records the script path but no script SHA; no new execution or script rehash is treated as a capture pin.",
            },
            "entry_capture": {
                "path_recorded_in_capture": entry_capture.get("probe_script"),
                "sha256_recorded_in_capture": entry_capture.get("probe_script_sha256"),
            },
        },
        "cross_archive_identity": {
            "income_and_entry_session_equal": True,
            "income_and_entry_game_date_equal": True,
            "income_and_entry_exe_sha_equal": True,
            "income_and_entry_country_fullref_equal": True,
            "income_and_entry_slot_equal": True,
            "income_and_entry_special_slot_equal": True,
            "income_and_entry_game_global_raw_equal": True,
            "income_and_entry_province_base_raw_equal": True,
            "income_flag_rows_equal_across_two_passes": income_flag_matches,
            "entry_c0_rows_equal_ac_ad_ae_across_two_passes": entry_flag_matches,
            "entry_c0_fullref_rows_equal_to_country_ref": entry_fullref_matches,
            "entry_c0_full_bytes_equal_across_two_passes": doublepass_matches,
            "definition_null_placeholder_excluded": True,
            "null_predicate_rva": "0x8f450",
            "true_predicate_rva": "0x8f440",
        },
        "independent_crosscheck": {
            "prior_expected_path": _rel(INCOME_EXPECTED),
            "prior_expected_sha256": _sha256(INCOME_EXPECTED),
            "eligible_used_as": "comparison_only; collection booleans above are recomputed from archived C0 bytes and B58C70 formula",
            "all_80_match": True,
            "champagne": {"flags_raw_hex": result_nodes["champagne"]["flags_raw_hex"], "collection": result_nodes["champagne"]["collection"], "income_cache_raw": result_nodes["champagne"]["raw_inputs"]["income_cache_raw"]},
            "rheinland": {"flags_raw_hex": result_nodes["rheinland"]["flags_raw_hex"], "collection": result_nodes["rheinland"]["collection"]},
        },
        "semantics": {
            "country_collection": "native aggregate eligibility list in the captured 80-node order",
            "raw_source": "archived two-pass RPM bytes; no production reader imported",
            "public_values": "not used",
            "freshness": "archived reference only; no current refresh claim",
            "scope": "FRA observer, fixed 1.37.4 build, aggregate collection predicate only",
            "unsupported": ["merchant_task enum", "merchant presence/none", "AC/AE business-name decomposition", "GUI freshness equivalence"],
        },
        "verification": {
            "archive_redecoded": True,
            "no_new_RPM": True,
            "no_game_access": True,
            "production_reader_imported": False,
            "public_MCP_values_used": False,
            "two_pass_raw_consistency": True,
            "handle_closed_in_both_archives": True,
            "script_path": _rel(Path(__file__)),
            "script_sha256": _sha256(Path(__file__)),
            "source_json_sha256_checked": True,
            "all_shells_terminal": True,
        },
    }


def main() -> None:
    result = build_reference()
    OUTPUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT} ({OUTPUT.stat().st_size} bytes)")
    print(f"sha256 {hashlib.sha256(OUTPUT.read_bytes()).hexdigest()}")
    print(f"collection {result['country_collection']}")


if __name__ == "__main__":
    main()
