"""Build an independent raw-entry reference for trade shares and source rows.

The script intentionally reads only the saved two-pass RPM artifact.  It does
not import a production reader, a production formula, or a game module.  It
decodes signed DWORDs at the pinned entry offsets and preserves the native
inclusion predicates for the three source rows.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-trade-share-20261027-001"
RAW_PATH = STAGE / "native-trade-entry-inputs-002.json"
SOURCE_INDEX_PATH = STAGE / "trade-details-source-index-001.json"
PROFILE_PATH = ROOT / "bridge/information/profiles/trade-details-memory-1374.json"
TRUE_PREDICATE_RVA = 0x8F440
FALSE_PREDICATE_RVA = 0x8F450
ENTRY_SIZE = 192
SHARE_OFFSET = 0x2C
SOURCE_OFFSETS = {
    "TP_PROVINCE_POWER": 0x28,
    "TP_SHIP_POWER": 0x1C,
    "MERCHANT_DOWNSTREAM_BONUS": 0x40,
}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def signed32(raw: bytes) -> int:
    if len(raw) != 4:
        raise RuntimeError("signed32_width_invalid")
    return int.from_bytes(raw, "little", signed=True)


def raw_hex(raw: bytes) -> str:
    if len(raw) != 4:
        raise RuntimeError("raw_hex_width_invalid")
    return raw.hex()


def load_raw() -> tuple[dict, bytes]:
    raw = RAW_PATH.read_bytes()
    document = json.loads(raw.decode("utf-8"))
    if not isinstance(document, dict):
        raise RuntimeError("raw_reference_not_object")
    if document.get("schema") != "information_independent_trade_entry_inputs.v1":
        raise RuntimeError("raw_reference_schema_mismatch")
    if document.get("status") != "observed" or document.get("completed") is not True:
        raise RuntimeError("raw_reference_not_complete")
    if document.get("identity", {}).get("binding_verified") is not True:
        raise RuntimeError("raw_reference_identity_not_bound")
    if document.get("identity", {}).get("process_path_sha256") != "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77":
        raise RuntimeError("raw_reference_executable_mismatch")
    if document.get("doublepass", {}).get("performed") is not True or document.get("doublepass", {}).get("consistent") is not True:
        raise RuntimeError("raw_reference_doublepass_not_consistent")
    if document.get("cleanup", {}).get("handle_close", {}).get("closed") is not True:
        raise RuntimeError("raw_reference_handle_not_closed")
    if document.get("native_function_invoked") is not False or document.get("read_only") is not True:
        raise RuntimeError("raw_reference_not_raw_only")
    contract = document.get("capture_contract", {})
    if contract.get("entry_size_bytes") != ENTRY_SIZE or contract.get("raw_only") is not True:
        raise RuntimeError("raw_reference_capture_contract_mismatch")
    if contract.get("true_predicate_rva") != hex(TRUE_PREDICATE_RVA) or contract.get("false_predicate_rva") != hex(FALSE_PREDICATE_RVA):
        raise RuntimeError("raw_reference_predicate_contract_mismatch")
    passes = document.get("trade_entries_inputs")
    if not isinstance(passes, list) or len(passes) != 2 or passes[0] != passes[1]:
        raise RuntimeError("raw_reference_passes_differ")
    return document, raw


def parse_graph(first: dict) -> tuple[dict[str, dict], list[str]]:
    raw_nodes = first.get("nodes")
    if not isinstance(raw_nodes, list) or len(raw_nodes) != 81:
        raise RuntimeError("raw_reference_definition_count_mismatch")
    graph: dict[str, dict] = {}
    false_keys: list[str] = []
    for node in raw_nodes:
        if not isinstance(node, dict):
            raise RuntimeError("raw_graph_node_invalid")
        key_payload = bytes.fromhex(node.get("key_payload_hex", ""))
        if not key_payload.endswith(b"\0"):
            raise RuntimeError("raw_graph_key_not_terminated")
        try:
            key = key_payload[:-1].decode("ascii")
        except UnicodeDecodeError as exc:
            raise RuntimeError("raw_graph_key_not_ascii") from exc
        if key != node.get("node_id") or key in graph:
            raise RuntimeError("raw_graph_key_invalid_or_duplicate")
        predicate = int(node.get("predicate_rva"), 0)
        if predicate not in (TRUE_PREDICATE_RVA, FALSE_PREDICATE_RVA):
            raise RuntimeError("raw_graph_unexpected_predicate")
        graph[key] = node
        if predicate == FALSE_PREDICATE_RVA:
            false_keys.append(key)
    if false_keys != ["Null"]:
        raise RuntimeError("raw_false_placeholder_contract_mismatch")
    return graph, false_keys


def source_condition(key: str, value: int) -> bool:
    if key in ("TP_PROVINCE_POWER", "TP_SHIP_POWER"):
        return value != 0
    if key == "MERCHANT_DOWNSTREAM_BONUS":
        return value > 0
    raise RuntimeError(f"unknown_source_key:{key}")


def parse_nodes(first: dict, graph: dict[str, dict]) -> dict[str, dict]:
    nodes: dict[str, dict] = {}
    for graph_key, graph_node in graph.items():
        predicate = int(graph_node["predicate_rva"], 0)
        if predicate == FALSE_PREDICATE_RVA:
            continue
        entry_text = graph_node.get("entry_raw_hex")
        if not isinstance(entry_text, str) or len(entry_text) != ENTRY_SIZE * 2:
            raise RuntimeError("raw_entry_width_invalid")
        entry = bytes.fromhex(entry_text)
        share_bytes = entry[SHARE_OFFSET:SHARE_OFFSET + 4]
        share = signed32(share_bytes)
        source_inputs: dict[str, dict] = {}
        source_rows: list[dict] = []
        for key, offset in SOURCE_OFFSETS.items():
            field_bytes = entry[offset:offset + 4]
            value = signed32(field_bytes)
            included = source_condition(key, value)
            row = {"raw": value, "raw_hex": raw_hex(field_bytes), "included": included}
            source_inputs[key] = row
            if included:
                source_rows.append({
                    "native_key": key,
                    "raw": value,
                    "raw_hex": row["raw_hex"],
                })
        nodes[graph_key] = {
            "node_id": graph_key,
            "share_raw": share,
            "share_raw_hex": raw_hex(share_bytes),
            "source_inputs": source_inputs,
            "source_rows": source_rows,
        }
    if len(nodes) != 80:
        raise RuntimeError("raw_true_node_count_mismatch")
    return nodes


def main() -> None:
    document, raw_bytes = load_raw()
    if not SOURCE_INDEX_PATH.exists() or not PROFILE_PATH.exists():
        raise RuntimeError("trade_details_profile_or_source_missing")
    source_index = json.loads(SOURCE_INDEX_PATH.read_text(encoding="utf-8"))
    profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    if source_index.get("source_index_id") != "information-trade-details-source-index-001":
        raise RuntimeError("trade_details_source_index_id_mismatch")
    if profile.get("profile_id") != "trade-details-memory-1374":
        raise RuntimeError("trade_details_profile_id_mismatch")
    if profile.get("source_index", {}).get("sha256") != digest(SOURCE_INDEX_PATH):
        raise RuntimeError("trade_details_profile_source_pin_mismatch")

    first = document["trade_entries_inputs"][0]
    second = document["trade_entries_inputs"][1]
    if first.get("country", {}).get("requested_country") != "FRA" or first.get("country", {}).get("status") != "observed":
        raise RuntimeError("raw_country_contract_mismatch")
    if first.get("true_node_count") != 80 or first.get("false_node_count") != 1:
        raise RuntimeError("raw_node_count_contract_mismatch")
    if first.get("entry_capture_contract", {}).get("entry_size_bytes") != ENTRY_SIZE:
        raise RuntimeError("raw_entry_contract_mismatch")

    fullref = bytes.fromhex(first["country_reference_raw_hex"])
    if len(fullref) != 8 or fullref[:3] != b"FRA":
        raise RuntimeError("raw_fullref_identity_invalid")
    slot = int.from_bytes(fullref[4:6], "little", signed=True)
    if slot != first.get("country_slot") or first.get("fullref_slot") != slot:
        raise RuntimeError("raw_fullref_slot_mismatch")
    if first.get("country_reference_raw_hex") != second.get("country_reference_raw_hex"):
        raise RuntimeError("raw_fullref_changed_between_passes")
    if first.get("date", {}).get("value") != second.get("date", {}).get("value"):
        raise RuntimeError("raw_date_changed_between_passes")

    graph, false_keys = parse_graph(first)
    nodes = parse_nodes(first, graph)
    true_keys = list(nodes)
    summary = {key: sum(1 for node in nodes.values() if node["source_inputs"][key]["included"]) for key in SOURCE_OFFSETS}
    pass_summary = {
        "passes": 2,
        "true_nodes": len(nodes),
        "false_nodes": false_keys,
        "entry_size_bytes": ENTRY_SIZE,
        "raw_entry_bytes_per_pass": first.get("entry_read_bytes"),
        "rpm_calls": document.get("access_summary", {}).get("rpm_calls"),
        "rpm_bytes_requested": document.get("access_summary", {}).get("rpm_bytes_requested"),
        "doublepass_consistent": document["doublepass"]["consistent"],
        "handle_closed": document["cleanup"]["handle_close"]["closed"],
    }
    result = {
        "schema": "information_trade_details_independent_expected.v1",
        "basis": "independent_raw_RPM_and_static_share_sources_not_public_values",
        "reference_path": RAW_PATH.relative_to(ROOT).as_posix(),
        "reference_sha256": digest(RAW_PATH),
        "session_id": document["identity"]["installation_session_id"],
        "game_date": first["date"]["value"],
        "country": "FRA",
        "fullref_raw_hex": first["country_reference_raw_hex"],
        "country_slot": slot,
        "definition_count": len(graph),
        "node_count": len(nodes),
        "nodes": nodes,
        "source_inclusion_counts": summary,
        "capture_summary": pass_summary,
        "source_index_path": SOURCE_INDEX_PATH.relative_to(ROOT).as_posix(),
        "source_index_sha256": digest(SOURCE_INDEX_PATH),
        "profile_path": PROFILE_PATH.relative_to(ROOT).as_posix(),
        "profile_sha256": digest(PROFILE_PATH),
        "semantics": {
            "share": {"raw": "signed32 entry+0x2c", "unit": "ratio", "scale": 1000, "origin": "copied_native_cache"},
            "sources": {"raw": "signed32 entry+0x28/+0x1c/+0x40", "unit": "trade_power", "scale": 1000, "origin": "copied_native_cache"},
            "period": "current",
            "freshness": "partial; independent raw observation does not establish refresh timing or GUI equivalence",
        },
        "predicate_false_nodes_skipped": false_keys,
        "income_boundary": "The entry bytes are decoded only at the share/source offsets; the B58D00 return is not used as share.",
        "evidence_layers": "Raw bytes, identity, date and two-pass consistency are observations. Static share/source interpretation is pinned separately by the source index; no production reader or public value is imported.",
    }
    path = STAGE / "expected-trade-details-001.json"
    if path.exists():
        raise RuntimeError(f"refusing_to_overwrite:{path}")
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": digest(path),
        "nodes": len(nodes),
        "definitions": len(graph),
        "country_slot": slot,
        "session_id": result["session_id"],
        "game_date": result["game_date"],
        "source_inclusion_counts": summary,
    }))


if __name__ == "__main__":
    main()
