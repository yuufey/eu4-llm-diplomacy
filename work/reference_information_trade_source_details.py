"""Build an independent expected view from the Batch-46 raw capture.

This module only decodes bytes already saved by the bounded RPM probe.  It does
not import a production reader, validator, game module, or formula.  It keeps
the three old source inputs, capital raw/condition data, and dynamic raw list
items separate from any public normalized value.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-trade-source-details-20261027-001"
RAW_PATH = STAGE / "native-trade-source-details-inputs-002.json"
SOURCE_INDEX_PATH = STAGE / "trade-details-source-index-002.json"
EXPECTED_RAW_SHA256 = "46d716e9302062382ce0af56d4f33977296d5bd35978f8d33666b18a04878a83"
EXPECTED_SOURCE_INDEX_SHA256 = "50ad236e23c0479c60a04aa7741db99e1f2c33c87e615596e24f826f419ccb6a"
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


def main() -> None:
    raw_bytes = RAW_PATH.read_bytes()
    raw_sha = hashlib.sha256(raw_bytes).hexdigest()
    if raw_sha != EXPECTED_RAW_SHA256:
        raise RuntimeError(f"raw_sha256_mismatch:{raw_sha}")
    source_sha = digest(SOURCE_INDEX_PATH)
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
        raise RuntimeError("raw_reference_trade_source_passes_differ")
    first = passes[0]
    nodes = first.get("trade_source_nodes")
    graph = first.get("nodes")
    if not isinstance(nodes, list) or len(nodes) != 80:
        raise RuntimeError("raw_reference_true_node_count_mismatch")
    if not isinstance(graph, list) or len(graph) != 81:
        raise RuntimeError("raw_reference_definition_count_mismatch")
    false_nodes = first.get("skipped_false_nodes")
    if not isinstance(false_nodes, list) or len(false_nodes) != 1 or false_nodes[0].get("node_id") != "Null":
        raise RuntimeError("raw_reference_false_placeholder_mismatch")

    graph_by_key = {item["node_id"]: item for item in graph}
    if len(graph_by_key) != 81 or any(int(item["predicate_rva"], 0) not in (TRUE_PREDICATE_RVA, FALSE_PREDICATE_RVA) for item in graph):
        raise RuntimeError("raw_reference_graph_identity_invalid")
    capital_context = first.get("capital_context")
    if not isinstance(capital_context, dict):
        raise RuntimeError("raw_reference_capital_context_missing")
    scalar_raw = capital_context.get("scalar_raw")
    scalar_raw_hex = capital_context.get("scalar_raw_hex")
    if not isinstance(scalar_raw, int) or not isinstance(scalar_raw_hex, str) or len(scalar_raw_hex) != 8:
        raise RuntimeError("raw_reference_capital_scalar_invalid")

    expected_nodes: dict[str, Any] = {}
    for node in nodes:
        key = node.get("node_id")
        if not isinstance(key, str) or key in expected_nodes or key not in graph_by_key:
            raise RuntimeError("raw_reference_node_identity_invalid")
        if int(node["predicate_rva"], 0) != TRUE_PREDICATE_RVA:
            raise RuntimeError("raw_reference_false_node_in_true_payload")
        raw_hex = node.get("entry_raw_hex")
        if not isinstance(raw_hex, str) or len(raw_hex) != ENTRY_SIZE * 2:
            raise RuntimeError("raw_reference_entry_width_invalid")
        entry_raw = bytes.fromhex(raw_hex)
        if i32(entry_raw[0x2C:0x30]) != node.get("share_raw"):
            raise RuntimeError("raw_reference_share_decode_mismatch")
        inputs = node.get("source_inputs")
        if inputs != source_inputs(entry_raw):
            raise RuntimeError("raw_reference_source_decode_mismatch")
        capital_condition = node.get("capital_condition")
        if not isinstance(capital_condition, dict) or "matches" not in capital_condition:
            raise RuntimeError("raw_reference_capital_condition_missing")
        dynamic = node.get("dynamic_sources")
        if not isinstance(dynamic, dict) or dynamic.get("status") not in ("empty", "observed", "unknown"):
            raise RuntimeError("raw_reference_dynamic_shape_invalid")

        source_rows = []
        for native_key, item in inputs.items():
            source_rows.append({
                "native_key": native_key,
                "raw": item["raw"],
                "raw_hex": item["raw_hex"],
                "included": item["included_by_static_condition"],
            })
        source_rows.append({
            "native_key": "TRADE_POWER_CAPITAL",
            "raw": scalar_raw,
            "raw_hex": scalar_raw_hex,
            "included": bool(capital_condition["matches"]),
            "condition": capital_condition,
        })
        expected_nodes[key] = {
            "node_id": key,
            "predicate_rva": node["predicate_rva"],
            "runtime_pointer": node["runtime_pointer"],
            "entry_address": node["entry_address"],
            "entry_raw_hex": raw_hex,
            "share_raw": node["share_raw"],
            "share_raw_hex": node["share_raw_hex"],
            "source_inputs": inputs,
            "source_rows": source_rows,
            "capital": {
                "raw": scalar_raw,
                "raw_hex": scalar_raw_hex,
                "condition": capital_condition,
            },
            "dynamic_sources": {
                "status": dynamic["status"],
                "reason": dynamic.get("reason"),
                "head_raw_hex": dynamic.get("head_raw_hex"),
                "items": dynamic.get("items", []),
                "items_retracted": dynamic.get("items_retracted"),
                "raw_only": True,
                "unit": "unknown",
                "scale": 1000,
                "name_semantics": "lookup_key_candidate_not_display_text",
            },
        }

    fullref = bytes.fromhex(first["country_fullref_raw_hex"])
    if len(fullref) != 8 or fullref[:3] != b"FRA":
        raise RuntimeError("raw_reference_fullref_invalid")
    slot = int.from_bytes(fullref[4:6], "little", signed=True)
    if slot != first.get("country_slot"):
        raise RuntimeError("raw_reference_slot_mismatch")

    result = {
        "schema": "information_trade_source_details_independent_expected.v1",
        "basis": "independent_raw_RPM_and_static_extended_sources_not_public_values",
        "reference_path": RAW_PATH.relative_to(ROOT).as_posix(),
        "reference_sha256": raw_sha,
        "source_index_path": SOURCE_INDEX_PATH.relative_to(ROOT).as_posix(),
        "source_index_sha256": source_sha,
        "session_id": document["identity"]["installation_session_id"],
        "game_date": first["date"]["value"],
        "country": "FRA",
        "fullref_raw_hex": first["country_fullref_raw_hex"],
        "country_slot": slot,
        "definition_count": len(graph),
        "node_count": len(expected_nodes),
        "capital_context": capital_context,
        "nodes": expected_nodes,
        "semantics": {
            "raw_only": True,
            "share_unit": "ratio (source cache raw only)",
            "old_source_units": "source-row static labels are retained as raw inputs; no public row normalization is performed here",
            "capital_unit": "trade_power static source contract; raw only",
            "dynamic_unit": "unknown",
            "dynamic_scale_hint": 1000,
            "dynamic_names": "raw bytes; lookup-key candidate, no locale/display decoding",
            "no_source_sum": True,
            "no_gui_equivalence": True,
        },
        "capture_contract": {
            "passes": 2,
            "true_nodes_per_pass": 80,
            "entry_size_bytes": ENTRY_SIZE,
            "max_extension_read_bytes_per_pass": 131072,
            "dynamic_name_max_bytes": 1024,
            "dynamic_max_items_per_node": 64,
            "dynamic_max_items_global": 256,
            "native_function_invoked": False,
            "target_memory_writes": False,
            "handle_closed": True,
        },
        "repair_provenance": document.get("probe_repair"),
    }
    output = STAGE / "expected-trade-source-details-001.json"
    if output.exists():
        raise RuntimeError(f"refusing_to_overwrite:{output}")
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "path": output.relative_to(ROOT).as_posix(),
        "sha256": digest(output),
        "nodes": len(expected_nodes),
        "definition_count": len(graph),
        "session_id": result["session_id"],
        "game_date": result["game_date"],
        "dynamic_nonempty_nodes": sum(bool(item["dynamic_sources"]["items"]) for item in expected_nodes.values()),
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
