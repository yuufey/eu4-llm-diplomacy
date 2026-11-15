"""Build an independent expected trade-power reference from raw batch-43 bytes.

The script intentionally does not import the production trade reader or any
production formula.  It verifies the independent two-pass raw capture and
implements the bounded signed-width arithmetic described by the corrected
ordinary PE source report: TEST/CMOVG observes the signed low 32 bits of the
64-bit quotient.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-trade-power-20261027-001"
RAW_PATH = ROOT / "work/runtime/information-trade-state-20261027-001/native-trade-power-inputs-002.json"
SOURCE_INDEX_PATH = STAGE / "trade-power-source-index-002.json"
TRUE_PREDICATE_RVA = 0x8F440
FALSE_PREDICATE_RVA = 0x8F450
ENTRY_OFFSETS = (0x44, 0x48, 0x4C, 0x50, 0x54)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def i32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value >= 0x80000000 else value


def trunc0(numerator: int, denominator: int) -> int:
    quotient = abs(numerator) // denominator
    return -quotient if numerator < 0 else quotient


def compute_country_power(values: dict[int, int]) -> int:
    a = i32(values[0x44])
    cap_input = i32(values[0x48])
    c = i32(values[0x4C])
    before = i32(values[0x50])
    after = i32(values[0x54])
    q64 = trunc0(a * c, 1000)
    q32 = i32(q64)
    positive32 = q32 if q32 > 0 else 0
    capped = min(cap_input, positive32)
    delta = i32(after - before)
    return i32(capped + delta)


def formula_counterexample() -> dict:
    values = {0x44: 2_000_000_000, 0x4C: 2_000_000_000, 0x48: 2_147_483_647, 0x50: 0, 0x54: 0}
    q64 = trunc0(values[0x44] * values[0x4C], 1000)
    q32 = i32(q64)
    corrected_positive32 = q32 if q32 > 0 else 0
    corrected_final = i32(min(values[0x48], corrected_positive32) + i32(values[0x54] - values[0x50]))
    old_q64_test_wording = i32(q64) if q64 > 0 else 0
    return {
        "inputs": {hex(key): value for key, value in values.items()},
        "q64": q64,
        "q32": q32,
        "corrected_positive32": corrected_positive32,
        "corrected_final": corrected_final,
        "old_q64_test_wording_would_have_used": old_q64_test_wording,
        "meaning": "q64 is positive but its signed low 32 bits are negative; TEST EDX,EDX and CMOVG take the zero branch.",
    }


def signed_hex(value: int) -> str:
    return (value & 0xFFFFFFFF).to_bytes(4, "little").hex()


def load() -> tuple[dict, bytes]:
    raw = RAW_PATH.read_bytes()
    document = json.loads(raw.decode("utf-8"))
    if not isinstance(document, dict):
        raise RuntimeError("raw_reference_not_object")
    if document.get("status") != "observed" or document.get("completed") is not True:
        raise RuntimeError("raw_reference_not_complete")
    if document.get("doublepass", {}).get("consistent") is not True:
        raise RuntimeError("raw_reference_doublepass_not_consistent")
    if document.get("cleanup", {}).get("handle_close", {}).get("closed") is not True:
        raise RuntimeError("raw_reference_handle_not_closed")
    inputs = document.get("trade_power_inputs")
    if not isinstance(inputs, list) or len(inputs) != 2 or inputs[0] != inputs[1]:
        raise RuntimeError("raw_reference_passes_differ")
    return document, raw


def main() -> None:
    document, raw = load()
    if not SOURCE_INDEX_PATH.exists():
        raise RuntimeError("corrected_source_index_missing")
    source_index = json.loads(SOURCE_INDEX_PATH.read_text(encoding="utf-8"))
    if source_index.get("source_index_id") != "information-trade-power-source-index-002":
        raise RuntimeError("corrected_source_index_id_mismatch")
    first = document["trade_power_inputs"][0]
    graph = first.get("trade_income_reference")
    graph_nodes = graph.get("nodes") if isinstance(graph, dict) else None
    power_nodes = first.get("trade_power_nodes")
    if not isinstance(graph_nodes, list) or not isinstance(power_nodes, list):
        raise RuntimeError("raw_reference_graph_missing")
    if len(graph_nodes) != 81 or len(power_nodes) != 80:
        raise RuntimeError("raw_reference_node_count_mismatch")

    graph_by_key = {}
    for graph_node in graph_nodes:
        if not isinstance(graph_node, dict):
            raise RuntimeError("raw_graph_node_invalid")
        predicate = int(graph_node["predicate_rva"], 0)
        key_payload = bytes.fromhex(graph_node["key_payload_hex"])
        if not key_payload.endswith(b"\0"):
            raise RuntimeError("raw_graph_key_not_terminated")
        key = key_payload[:-1].decode("ascii")
        if key != graph_node["node_id"] or key in graph_by_key:
            raise RuntimeError("raw_graph_key_invalid_or_duplicate")
        if predicate not in (TRUE_PREDICATE_RVA, FALSE_PREDICATE_RVA):
            raise RuntimeError("raw_graph_unexpected_predicate")
        graph_by_key[key] = graph_node

    nodes = {}
    for power_node in power_nodes:
        if not isinstance(power_node, dict):
            raise RuntimeError("raw_power_node_invalid")
        key = power_node.get("node_id")
        if not isinstance(key, str) or key in nodes or key not in graph_by_key:
            raise RuntimeError("raw_power_node_identity_invalid")
        graph_node = graph_by_key[key]
        if int(graph_node["predicate_rva"], 0) != TRUE_PREDICATE_RVA:
            raise RuntimeError("false_predicate_power_node_present")
        raw_hex = power_node.get("entry_power_components_raw_hex")
        if not isinstance(raw_hex, str) or len(raw_hex) != 40:
            raise RuntimeError("entry_power_payload_width_invalid")
        payload = bytes.fromhex(raw_hex)
        values = {
            offset: int.from_bytes(payload[index * 4:(index + 1) * 4], "little", signed=True)
            for index, offset in enumerate(ENTRY_OFFSETS)
        }
        recorded = power_node.get("entry_power_components_raw")
        if not isinstance(recorded, dict) or any(recorded.get(hex(offset)) != value for offset, value in values.items()):
            raise RuntimeError("entry_power_signed_decode_mismatch")
        total_raw_hex = power_node.get("total_power_raw_hex")
        if not isinstance(total_raw_hex, str) or len(total_raw_hex) != 8:
            raise RuntimeError("total_power_payload_width_invalid")
        total_raw = int.from_bytes(bytes.fromhex(total_raw_hex), "little", signed=True)
        if total_raw != power_node.get("total_power_raw"):
            raise RuntimeError("total_power_signed_decode_mismatch")
        country_power = compute_country_power(values)
        node = {
            "node_id": key,
            "predicate_rva": hex(TRUE_PREDICATE_RVA),
            "definition_pointer": graph_node["definition_pointer"],
            "runtime_pointer": graph_node["runtime_pointer"],
            "entry_address": graph_node["entry_address"],
            "key_payload_hex": graph_node["key_payload_hex"],
            "center": graph_node["center"],
            "country_power_raw": country_power,
            "country_power_raw_hex": signed_hex(country_power),
            "total_power_raw": total_raw,
            "total_power_raw_hex": total_raw_hex,
            "inputs": {
                hex(offset): {"raw": values[offset], "raw_hex": signed_hex(values[offset])}
                for offset in ENTRY_OFFSETS
            },
            "total_input": {"raw": total_raw, "raw_hex": total_raw_hex},
        }
        nodes[key] = node

    false_keys = [key for key, value in graph_by_key.items() if int(value["predicate_rva"], 0) == FALSE_PREDICATE_RVA]
    if len(false_keys) != 1 or false_keys[0] != "Null":
        raise RuntimeError("false_placeholder_contract_mismatch")
    fullref = bytes.fromhex(first["country_fullref_raw_hex"])
    if fullref[:3] != b"FRA" or len(fullref) != 8:
        raise RuntimeError("fullref_identity_invalid")
    slot = int.from_bytes(fullref[4:6], "little", signed=True)
    if slot != first["country_slot"]:
        raise RuntimeError("fullref_slot_mismatch")

    result = {
        "schema": "information_trade_power_independent_expected.v1",
        "basis": "independent_raw_RPM_and_static_power_formula_not_public_values",
        "reference_path": RAW_PATH.relative_to(ROOT).as_posix(),
        "reference_sha256": digest(RAW_PATH),
        "session_id": document["identity"]["installation_session_id"],
        "game_date": first["date"]["value"],
        "country": "FRA",
        "fullref_raw_hex": first["country_fullref_raw_hex"],
        "country_fullref_raw_hex": first["country_fullref_raw_hex"],
        "country_slot": slot,
        "definition_count": len(graph_nodes),
        "node_count": len(nodes),
        "nodes": nodes,
        "formula": {
            "q64": "trunc0(i64(i32(0x44))*i64(i32(0x4c))/1000)",
            "q32": "i32(q64)",
            "positive32": "q32 if q32>0 else 0",
            "cap": "signed_min(i32(0x48),positive32)",
            "delta": "i32(0x54-0x50)",
            "country_power": "i32(cap+delta)",
            "total_power": "signed32(runtime_node+0xc8)",
            "aggregate": "not computed; no node sum is used as a denominator",
        },
        "formula_counterexample": formula_counterexample(),
        "source_index_path": SOURCE_INDEX_PATH.relative_to(ROOT).as_posix(),
        "source_index_sha256": digest(SOURCE_INDEX_PATH),
        "semantics": "Raw RPM bytes are independent of production readers; country_power_raw is derived only by the corrected bounded static formula with TEST/CMOVG on signed q32, and total_power_raw is the copied signed32 cache. No public values or GUI equality are used.",
        "predicate_false_nodes_skipped": false_keys,
    }
    path = STAGE / "expected-trade-power-002.json"
    if path.exists():
        raise RuntimeError(f"refusing_to_overwrite:{path}")
    STAGE.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": digest(path),
        "nodes": len(nodes),
        "country_slot": slot,
        "session_id": result["session_id"],
        "game_date": result["game_date"],
        "formula": "independent_raw_only",
    }))


if __name__ == "__main__":
    main()
