"""Capture bounded raw trade-power inputs for the fixed v27-002 process.

This probe composes the already-audited trade-income graph reader with two
additional raw reads per real node: the node ``+0xc8`` DWORD and the five
``entry+0x44..0x54`` signed DWORDs.  It deliberately keeps the values as
inputs.  No power formula, UI equivalence, or business result is derived.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.probe_information_current_overextension import probe
from work.probe_information_trade_income import read_trade


EXPECTED_INSTALLATION = (
    ROOT
    / "work/runtime/diplomacy-observer-20261026-information-battle-v27-002/installation.json"
).resolve()
EXPECTED_COUNTRY = "FRA"
TRUE_PREDICATE_RVA = 0x8F440
FALSE_PREDICATE_RVA = 0x8F450
NODE_TOTAL_OFFSET = 0xC8
ENTRY_COMPONENT_OFFSET = 0x44
ENTRY_COMPONENT_WIDTH = 4
ENTRY_COMPONENT_COUNT = 5
MAX_SINGLE_READ = 64 * 1024
MAX_TOTAL_READ = 512 * 1024


def _read(reader, address: int, size: int, label: str) -> bytes:
    """Apply the probe-local bounds before delegating to bounded RPM."""
    if not isinstance(address, int) or address < 0x10000:
        raise ValueError(f"trade_power_address_invalid:{label}")
    if not isinstance(size, int) or not 0 < size <= MAX_SINGLE_READ:
        raise ValueError(f"trade_power_read_size_invalid:{label}")
    return reader.read(address, size, "reference.trade_power." + label)


def _pointer(value: object, label: str) -> int:
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        try:
            result = int(value, 0)
        except ValueError as exc:
            raise ValueError(f"trade_power_pointer_invalid:{label}") from exc
    else:
        raise ValueError(f"trade_power_pointer_invalid:{label}")
    if not 0x10000 <= result < 0x7FFFFFFFFFFF:
        raise ValueError(f"trade_power_pointer_out_of_range:{label}")
    return result


def _identity(node: dict, index: int) -> dict:
    """Retain graph identity without copying the large definition payload."""
    return {
        "node_index": index,
        "node_id": node.get("node_id"),
        "definition_pointer": node.get("definition_pointer"),
        "definition_vtable_raw_hex": node.get("definition_vtable_raw_hex"),
        "native_definition_pointer_raw_hex": node.get("native_definition_pointer_raw_hex"),
        "key_header_hex": node.get("key_header_hex"),
        "key_payload_hex": node.get("key_payload_hex"),
        "predicate_rva": node.get("predicate_rva"),
        "predicate_prefix_hex": node.get("predicate_prefix_hex"),
        "runtime_pointer": node.get("runtime_pointer"),
        "runtime_pointer_raw_hex": node.get("runtime_pointer_raw_hex"),
        "entry_address": node.get("entry_address"),
        "country_table_pointer_raw_hex": node.get("country_table_pointer_raw_hex"),
    }


def read_trade_power(reader, base, country):
    """Read the mature raw graph, then only the new power input bytes."""
    # ``probe`` passes the already identity-checked country pointer to the
    # callback.  The mature graph reader performs the FRA fullref check at
    # country+0x20; do not reinterpret that pointer as a tag string here.
    if not isinstance(country, int) or country < 0x10000:
        raise ValueError("trade_power_country_pointer_invalid")

    graph = read_trade(reader, base, country)
    nodes = graph.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        raise ValueError("trade_power_graph_missing")

    power_nodes = []
    skipped_false = []
    predicate_counts = {}
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            raise ValueError(f"trade_power_node_invalid:{index}")
        raw_predicate = node.get("predicate_rva")
        try:
            predicate_rva = int(raw_predicate, 0) if isinstance(raw_predicate, str) else int(raw_predicate)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"trade_power_predicate_invalid:{index}") from exc
        predicate_counts[hex(predicate_rva)] = predicate_counts.get(hex(predicate_rva), 0) + 1
        identity = _identity(node, index)
        if predicate_rva == FALSE_PREDICATE_RVA:
            skipped_false.append(identity)
            continue
        if predicate_rva != TRUE_PREDICATE_RVA:
            raise ValueError(f"trade_power_predicate_unexpected:{hex(predicate_rva)}:{index}")

        runtime = _pointer(node.get("runtime_pointer"), f"runtime:{index}")
        entry = _pointer(node.get("entry_address"), f"entry:{index}")
        total_raw = _read(reader, runtime + NODE_TOTAL_OFFSET, 4, f"node_{index}_total_power")
        components_raw = _read(
            reader,
            entry + ENTRY_COMPONENT_OFFSET,
            ENTRY_COMPONENT_WIDTH * ENTRY_COMPONENT_COUNT,
            f"node_{index}_entry_power_components",
        )
        component_hex = {}
        component_signed = {}
        for component_index in range(ENTRY_COMPONENT_COUNT):
            offset = ENTRY_COMPONENT_OFFSET + component_index * ENTRY_COMPONENT_WIDTH
            part = components_raw[component_index * ENTRY_COMPONENT_WIDTH:(component_index + 1) * ENTRY_COMPONENT_WIDTH]
            component_hex[hex(offset)] = part.hex()
            component_signed[hex(offset)] = int.from_bytes(part, "little", signed=True)
        power_nodes.append({
            **identity,
            "total_power_raw_hex": total_raw.hex(),
            "total_power_raw": int.from_bytes(total_raw, "little", signed=True),
            "entry_power_components_raw_hex": components_raw.hex(),
            "entry_power_components_raw": component_signed,
            "entry_power_component_offsets": list(component_hex),
            "entry_power_component_hex_by_offset": component_hex,
            "derived_power": {
                "status": "not_computed",
                "reason": "raw_capture_only_no_formula_or_gui_equivalence",
            },
        })

    if reader.bytes_requested > MAX_TOTAL_READ:
        raise ValueError("trade_power_total_read_budget_exceeded")
    return {
        "trade_income_reference": graph,
        "trade_income_reference_semantics": (
            "The mature graph retains raw definition/key/country-fullref identity; "
            "the new power bytes below are independent raw inputs and are not a "
            "production-reader reference."
        ),
        "country_fullref_raw_hex": graph.get("country_reference_raw_hex"),
        "country_slot": graph.get("country_slot"),
        "predicate_contract": {
            "true_rva": hex(TRUE_PREDICATE_RVA),
            "false_placeholder_rva": hex(FALSE_PREDICATE_RVA),
            "false_action": "skipped_without_power_reads",
            "unexpected_action": "reject_capture",
            "counts": predicate_counts,
        },
        "skipped_false_nodes": skipped_false,
        "true_node_count": len(power_nodes),
        "trade_power_nodes": power_nodes,
        "raw_input_semantics": {
            "total_power_source": "runtime_pointer+0xc8",
            "total_power_width": 4,
            "entry_component_source": "entry_address+0x44",
            "entry_component_offsets": [hex(ENTRY_COMPONENT_OFFSET + i * ENTRY_COMPONENT_WIDTH) for i in range(ENTRY_COMPONENT_COUNT)],
            "entry_component_width": 4,
            "signed": True,
            "formula": "not computed",
            "gui_equivalence": "not established",
        },
    }


def _champagne_example(result: dict) -> dict | None:
    inputs = result.get("trade_power_inputs")
    if not isinstance(inputs, list) or not inputs:
        return None
    for snapshot in inputs:
        for node in snapshot.get("trade_power_nodes", []):
            if node.get("node_id") == "champagne":
                return {
                    "node_id": "champagne",
                    "total_power_raw": node.get("total_power_raw"),
                    "total_power_raw_hex": node.get("total_power_raw_hex"),
                    "entry_power_components_raw": node.get("entry_power_components_raw"),
                    "entry_power_components_raw_hex": node.get("entry_power_components_raw_hex"),
                    "derived_total": None,
                    "derived_total_semantics": "not computed; five raw inputs plus raw total cache only",
                }
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, default=EXPECTED_INSTALLATION)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "work/runtime/information-trade-state-20261027-001/native-trade-power-inputs-001.json",
    )
    args = parser.parse_args()
    installation = args.installation.resolve()
    if installation != EXPECTED_INSTALLATION:
        raise SystemExit("refusing_non_v27_002_installation")
    if args.output.exists():
        raise SystemExit("refusing_to_overwrite_output")

    result = probe(installation, field="trade_power", input_reader=read_trade_power)
    result["schema"] = "information_independent_trade_power_inputs.v1"
    result["field"] = "trade_power"
    result["capture_contract"] = {
        "installation": str(EXPECTED_INSTALLATION),
        "country": EXPECTED_COUNTRY,
        "read_only": True,
        "native_function_invoked": False,
        "game_function_or_write": False,
        "save_restart_date_ui": False,
        "raw_only": True,
        "formula_or_gui_equivalence": "not computed/not established",
    }
    result["champagne_example"] = _champagne_example(result)
    result["access_summary"] = {
        "status": result.get("status"),
        "completed": result.get("completed"),
        "rpm_bytes_requested": result.get("access", {}).get("rpm_bytes_requested"),
        "rpm_calls": result.get("access", {}).get("rpm_calls"),
        "true_node_count": [x.get("true_node_count") for x in result.get("trade_power_inputs", [])],
        "handle_close": result.get("cleanup", {}).get("handle_close"),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({
        "status": result.get("status"),
        "completed": result.get("completed"),
        "rpm_bytes_requested": result.get("access", {}).get("rpm_bytes_requested"),
        "rpm_calls": result.get("access", {}).get("rpm_calls"),
        "true_node_count": [x.get("true_node_count") for x in result.get("trade_power_inputs", [])],
        "champagne_example": result.get("champagne_example"),
        "handle_close": result.get("cleanup", {}).get("handle_close"),
    }))
    return 0 if result.get("completed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
