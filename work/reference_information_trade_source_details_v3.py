"""Build the independent expected view for the v3 tail-only raw capture.

This script decodes only the saved JSON/bytes.  It does not import a
production reader or validator and does not calculate a public aggregate.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-trade-source-details-20261027-001"
RAW_PATH = STAGE / "native-trade-source-details-inputs-004.json"
PROFILE_PATH = ROOT / "bridge/information/profiles/trade-details-memory-1374-v3.json"
SOURCE_INDEX_PATH = STAGE / "trade-details-source-index-003.json"
OUTPUT_PATH = STAGE / "expected-trade-source-details-002.json"
SEED_PATH = STAGE / "native-trade-source-details-inputs-002.json"
EXPECTED_RAW_SHA256 = "2eb1e445a569d7400b82b4896615622c3d33673cf98e5d860d364cd208c09a08"
EXPECTED_PROFILE_SHA256 = "e5df6c617090d1df63eaf03d88a9d4716667548f36af9f1e1c24be2b71b06cb1"
EXPECTED_SOURCE_INDEX_SHA256 = "43f7f699c61ea08f7e298aeda210368c296df6d6addeb5db65ac7401f52e7674"
EXPECTED_SEED_SHA256 = "46d716e9302062382ce0af56d4f33977296d5bd35978f8d33666b18a04878a83"
TRUE_PREDICATE_RVA = 0x8F440
FALSE_PREDICATE_RVA = 0x8F450
ENTRY_SIZE = 0xC0


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def i32(raw: bytes) -> int:
    value = int.from_bytes(raw, "little", signed=False)
    return value - 0x100000000 if value & 0x80000000 else value


def source_inputs(entry_raw: bytes) -> dict[str, dict[str, Any]]:
    rows = (
        ("TP_PROVINCE_POWER", 0x28, lambda value: value != 0),
        ("TP_SHIP_POWER", 0x1C, lambda value: value != 0),
        ("MERCHANT_DOWNSTREAM_BONUS", 0x40, lambda value: value > 0),
    )
    result = {}
    for key, offset, include in rows:
        raw = entry_raw[offset:offset + 4]
        value = i32(raw)
        result[key] = {
            "raw": value,
            "raw_hex": raw.hex(),
            "included_by_static_condition": bool(include(value)),
        }
    return result


def _source_rows(node: dict[str, Any], scalar_raw: int, scalar_hex: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key, item in node["source_inputs"].items():
        rows.append({
            "native_key": key,
            "raw": item["raw"],
            "raw_hex": item["raw_hex"],
            "included": item["included_by_static_condition"],
            "unit": "trade_power",
            "scale": 1000,
            "origin": "copied_native_cache",
        })
    condition = node["capital_condition"]
    rows.append({
        "native_key": "TRADE_POWER_CAPITAL",
        "raw": scalar_raw,
        "raw_hex": scalar_hex,
        "included": bool(condition["matches"]),
        "unit": "trade_power",
        "scale": 1000,
        "origin": "copied_native_cache",
        "condition": condition,
    })
    return rows


def _verify_transfer(node: dict[str, Any], offset_hex: str, chain: dict[str, Any]) -> None:
    offset = int(offset_hex, 0)
    entry_raw = bytes.fromhex(node["entry_raw_hex"])
    expected_head = entry_raw[offset:offset + 8].hex()
    if chain.get("container_pointer_raw_hex") != expected_head:
        raise RuntimeError("tail_head_decode_mismatch")
    if chain.get("status") == "empty":
        if chain.get("items") != []:
            raise RuntimeError("empty_tail_has_items")
        return
    if chain.get("status") != "observed":
        if chain.get("items_retracted") is not True:
            raise RuntimeError("unknown_tail_not_retracted")
        return
    if not isinstance(chain.get("items"), list):
        raise RuntimeError("tail_items_missing")
    for item in chain["items"]:
        raw = bytes.fromhex(item["value_raw_hex"])
        if len(raw) != 4 or i32(raw) != item["value_raw"]:
            raise RuntimeError("tail_value_decode_mismatch")
        binding = item["country_binding"]
        if binding.get("element_fullref_raw_hex") != item["fullref_raw_hex"]:
            raise RuntimeError("tail_fullref_decode_mismatch")
        if binding.get("country_fullref_matches") is True:
            fullref = bytes.fromhex(item["fullref_raw_hex"])
            if binding.get("country_tag_raw_hex") != fullref[:4].hex():
                raise RuntimeError("tail_tag_raw_mismatch")


def main() -> None:
    if OUTPUT_PATH.exists():
        raise RuntimeError(f"refusing_to_overwrite:{OUTPUT_PATH}")
    raw_bytes = RAW_PATH.read_bytes()
    raw_sha = hashlib.sha256(raw_bytes).hexdigest()
    if raw_sha != EXPECTED_RAW_SHA256:
        raise RuntimeError(f"raw_sha256_mismatch:{raw_sha}")
    profile_sha = digest(PROFILE_PATH)
    source_sha = digest(SOURCE_INDEX_PATH)
    if profile_sha != EXPECTED_PROFILE_SHA256:
        raise RuntimeError(f"profile_sha256_mismatch:{profile_sha}")
    if source_sha != EXPECTED_SOURCE_INDEX_SHA256:
        raise RuntimeError(f"source_index_sha256_mismatch:{source_sha}")
    document = json.loads(raw_bytes.decode("utf-8"))
    if document.get("status") != "observed" or document.get("completed") is not True:
        raise RuntimeError("raw_reference_not_complete")
    if document.get("doublepass", {}).get("consistent") is not True:
        raise RuntimeError("raw_reference_passes_not_consistent")
    if document.get("cleanup", {}).get("handle_close", {}).get("closed") is not True:
        raise RuntimeError("raw_reference_handle_not_closed")
    passes = document.get("trade_source_details_inputs")
    if not isinstance(passes, list) or len(passes) != 2 or passes[0] != passes[1]:
        raise RuntimeError("raw_reference_passes_differ")
    first = passes[0]
    nodes = first.get("trade_source_nodes")
    graph = first.get("nodes")
    if not isinstance(nodes, list) or len(nodes) != 80:
        raise RuntimeError("true_node_count_mismatch")
    if not isinstance(graph, list) or len(graph) != 81:
        raise RuntimeError("definition_count_mismatch")
    graph_by_key = {item["node_id"]: item for item in graph}
    if len(graph_by_key) != 81:
        raise RuntimeError("definition_key_uniqueness_mismatch")
    if any(int(item["predicate_rva"], 0) not in (TRUE_PREDICATE_RVA, FALSE_PREDICATE_RVA) for item in graph):
        raise RuntimeError("predicate_identity_mismatch")
    false_nodes = first.get("skipped_false_nodes")
    if not isinstance(false_nodes, list) or len(false_nodes) != 1 or false_nodes[0].get("node_id") != "Null":
        raise RuntimeError("false_placeholder_mismatch")
    capital = first.get("capital_context")
    if not isinstance(capital, dict):
        # v3 is an extension-only capture.  The complete v2 capital context is
        # a pinned raw seed and is intentionally not re-read by the probe.
        if digest(SEED_PATH) != EXPECTED_SEED_SHA256:
            raise RuntimeError("v2_seed_sha256_mismatch")
        seed_document = json.loads(SEED_PATH.read_text(encoding="utf-8"))
        seed_passes = seed_document.get("trade_source_details_inputs")
        if not isinstance(seed_passes, list) or len(seed_passes) != 2:
            raise RuntimeError("v2_seed_capital_context_missing")
        capital = seed_passes[0].get("capital_context")
    if not isinstance(capital, dict):
        raise RuntimeError("capital_context_missing")
    scalar_raw = capital.get("scalar_raw")
    scalar_hex = capital.get("scalar_raw_hex")
    if not isinstance(scalar_raw, int) or not isinstance(scalar_hex, str) or len(scalar_hex) != 8:
        raise RuntimeError("capital_scalar_invalid")
    expected_nodes: dict[str, Any] = {}
    total_tail_items = 0
    for node in nodes:
        key = node.get("node_id")
        if not isinstance(key, str) or key in expected_nodes or key not in graph_by_key:
            raise RuntimeError("node_identity_invalid")
        if int(node["predicate_rva"], 0) != TRUE_PREDICATE_RVA:
            raise RuntimeError("false_node_in_true_payload")
        raw_hex = node.get("entry_raw_hex")
        if not isinstance(raw_hex, str) or len(raw_hex) != ENTRY_SIZE * 2:
            raise RuntimeError("entry_width_invalid")
        entry_raw = bytes.fromhex(raw_hex)
        if i32(entry_raw[0x2C:0x30]) != node.get("share_raw"):
            raise RuntimeError("share_decode_mismatch")
        decoded_inputs = source_inputs(entry_raw)
        if decoded_inputs != node.get("source_inputs"):
            raise RuntimeError("source_decode_mismatch")
        if node.get("dynamic_sources", {}).get("head_raw_hex") != entry_raw[0x90:0x98].hex():
            raise RuntimeError("dynamic_head_mismatch")
        _verify_transfer(node, "0x60", node["transfer_sources"]["to"])
        _verify_transfer(node, "0x78", node["transfer_sources"]["from"])
        total_tail_items += sum(len(node["transfer_sources"][direction].get("items", [])) for direction in ("to", "from"))
        expected_nodes[key] = {
            "node_id": key,
            "predicate_rva": node["predicate_rva"],
            "runtime_pointer": node["runtime_pointer"],
            "entry_address": node["entry_address"],
            "entry_raw_hex": raw_hex,
            "share_raw": node["share_raw"],
            "share_raw_hex": node["share_raw_hex"],
            "source_rows": _source_rows(node, scalar_raw, scalar_hex),
            "capital": {
                "raw": scalar_raw,
                "raw_hex": scalar_hex,
                "condition": node["capital_condition"],
            },
            "dynamic_sources": node["dynamic_sources"],
            "transfer_sources": node["transfer_sources"],
            "entry_chain_head_raw_hex": node["entry_chain_head_raw_hex"],
            "tail_items_retracted": node["tail_items_retracted"],
        }
    if total_tail_items != 5:
        raise RuntimeError(f"tail_item_count_mismatch:{total_tail_items}")
    fullref = bytes.fromhex(first["country_fullref_raw_hex"])
    if len(fullref) != 8 or fullref[:3] != b"FRA":
        raise RuntimeError("country_fullref_invalid")
    slot = int.from_bytes(fullref[4:6], "little", signed=True)
    if slot != first.get("country_slot"):
        raise RuntimeError("country_slot_mismatch")

    result = {
        "schema": "information_trade_source_details_independent_expected.v2",
        "basis": "independent_raw_RPM_and_static_extended_sources_not_public_values",
        "reference_path": RAW_PATH.relative_to(ROOT).as_posix(),
        "reference_sha256": raw_sha,
        "profile_path": PROFILE_PATH.relative_to(ROOT).as_posix(),
        "profile_sha256": profile_sha,
        "source_index_path": SOURCE_INDEX_PATH.relative_to(ROOT).as_posix(),
        "source_index_sha256": source_sha,
        "session_id": document["identity"]["installation_session_id"],
        "game_date": first["date"]["value"],
        "country": "FRA",
        "fullref_raw_hex": first["country_fullref_raw_hex"],
        "country_slot": slot,
        "definition_count": len(graph),
        "node_count": len(expected_nodes),
        "capital_context": capital,
        "country_table_context": first["country_table_context"],
        "nodes": expected_nodes,
        "semantics": {
            "raw_only": True,
            "share_unit": "ratio (source cache raw only)",
            "direct_source_rows": "four separate raw point rows: three v2 direct rows plus capital; no source sum",
            "transfer_unit": "trade_power",
            "transfer_scale": 1000,
            "transfer_direction": "container field/native key TO or FROM; raw sign preserved",
            "dynamic_unit": "unknown",
            "dynamic_names": "raw bytes; lookup-key candidate, no locale/display decoding",
            "country_tag_rule": "saved only after exact element-fullref == country_table[slot]+0x20 fullref",
            "max_country_slot_for_read": 4095,
            "max_country_slot_is_read_bound_not_total_country_count": True,
            "no_gui_equivalence": True,
        },
        "capture_contract": {
            "passes": 2,
            "true_nodes_per_pass": 80,
            "entry_size_bytes": ENTRY_SIZE,
            "full_entries_reread": False,
            "tail_items_per_pass": total_tail_items,
            "max_extension_read_bytes_per_pass": 131072,
            "max_items_per_node_across_three_chains": 64,
            "max_items_global_across_three_chains": 256,
            "native_function_invoked": False,
            "target_memory_writes": False,
            "handle_closed": True,
        },
        "v2_seed": document.get("v2_seed"),
        "repair_provenance": document.get("probe_repair"),
    }
    OUTPUT_PATH.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "path": OUTPUT_PATH.relative_to(ROOT).as_posix(),
        "sha256": digest(OUTPUT_PATH),
        "nodes": len(expected_nodes),
        "definition_count": len(graph),
        "tail_items": total_tail_items,
        "session_id": result["session_id"],
        "game_date": result["game_date"],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
