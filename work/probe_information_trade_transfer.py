"""Capture bounded raw transfer lists, or rebuild their reference offline.

The transfer bytes use the existing independent trade graph/RPM lifecycle.
No production trade adapter, transfer reader or validator supplies expected
values. Default/help are inert; --reference-from never opens the game.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.probe_information_current_overextension import probe
from work.probe_information_trade_income import read_trade
from work.probe_information_trade_source_details_v3 import (
    ExtensionReader, _capture_tail_chain, _read_country_table,
)

GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
STAGE = ROOT / "work/runtime/information-trade-transfer-20261027-001"


def pin(path: Path) -> dict:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return {"path": path.resolve().relative_to(ROOT).as_posix(),
            "bytes": path.stat().st_size, "sha256": value.hexdigest()}


def write(path: Path, value: dict) -> None:
    text = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


def read_transfer_inputs(reader, base: int, country: int) -> dict:
    graph = read_trade(reader, base, country)
    extension = ExtensionReader(reader)
    binding = _read_country_table(extension, base, graph["country_slot"],
                                  graph["country_reference_raw_hex"])
    table = int.from_bytes(bytes.fromhex(binding["country_table_raw_hex"]), "little")
    state = {"item_count": 0}
    nodes = []
    skipped = []
    for node in graph["nodes"]:
        predicate = int(node["predicate_rva"], 0)
        code = bytes.fromhex(node["predicate_prefix_hex"])
        if predicate == 0x8F450 and code.startswith(b"\x32\xc0\xc3"):
            skipped.append(node["node_id"])
            continue
        if predicate != 0x8F440 or not code.startswith(b"\xb0\x01\xc3"):
            raise ValueError("unverified_trade_node_predicate")
        address = int(node["entry_address"], 0)
        heads = {}
        item = {"node_id": node["node_id"], "entry_address": node["entry_address"]}
        for direction, offset, key in (("to", 0x60, "TRANSFER_TRADE_POWER_TO"),
                                       ("from", 0x78, "TRANSFER_TRADE_POWER_FROM")):
            head = extension.read(address + offset, 8, f"{node['node_id']}.{direction}.head_before")
            heads[direction] = head.hex()
            item[direction] = _capture_tail_chain(
                extension, address, offset, direction, key, table, state,
                head.hex(), node["node_id"])
            if extension.read(address + offset, 8, f"{node['node_id']}.{direction}.head_after") != head:
                raise ValueError("transfer_head_changed_during_copy")
        item["head_raw_hex"] = heads
        nodes.append(item)
    if len(nodes) != 80 or skipped != ["Null"]:
        raise ValueError("unexpected_trade_node_definition_scope")
    return {"country_fullref_raw_hex": graph["country_reference_raw_hex"],
            "country_slot": graph["country_slot"], "nodes": nodes,
            "country_table_context": binding, "skipped_false_nodes": skipped,
            "extension_bytes_requested": extension.bytes_requested,
            "extension_item_count": state["item_count"],
            "native_function_invoked": False}


def reference(raw: dict, raw_path: Path) -> dict:
    if raw.get("status") != "observed" or raw.get("completed") is not True:
        raise ValueError("raw_capture_not_completed")
    if raw.get("cleanup", {}).get("handle_close", {}).get("closed") is not True or raw.get("doublepass", {}).get("consistent") is not True:
        raise ValueError("raw_capture_not_closed_or_consistent")
    captures = raw["trade_transfer_inputs"]
    if len(captures) != 2 or captures[0] != captures[1]:
        raise ValueError("raw_transfer_passes_differ")
    selected = captures[0]
    nodes = []
    nonempty = []
    for node in selected["nodes"]:
        item = {"node_id": node["node_id"]}
        for direction, key in (("to", "TRANSFER_TRADE_POWER_TO"),
                               ("from", "TRANSFER_TRADE_POWER_FROM")):
            chain = node[direction]
            if chain["direction"] != direction or chain["native_key"] != key:
                raise ValueError("raw_transfer_direction_mismatch")
            if chain["status"] not in {"empty", "observed"}:
                raise ValueError("raw_transfer_chain_not_complete")
            rows = []
            for value in chain["items"]:
                fullref = bytes.fromhex(value["fullref_raw_hex"])
                raw_bytes = bytes.fromhex(value["value_raw_hex"])
                if len(fullref) != 8 or len(raw_bytes) != 4:
                    raise ValueError("raw_transfer_value_width")
                country_binding = value["country_binding"]
                matched = (country_binding.get("country_fullref_matches") is True
                           and country_binding.get("country_object_fullref_raw_hex") == fullref.hex())
                tag = None
                if matched and fullref[3] == 0:
                    text = fullref[:3].decode("ascii")
                    if len(text) == 3 and text.isalpha() and text.isupper():
                        tag = text
                rows.append({"country": tag, "fullref_raw_hex": fullref.hex(),
                             "slot": int.from_bytes(fullref[4:6], "little", signed=True),
                             "raw": int.from_bytes(raw_bytes, "little", signed=True),
                             "raw_hex": raw_bytes.hex(), "unit": "trade_power", "scale": 1000,
                             "native_key": key, "direction": direction})
            item[direction] = {"status": "known", "items": rows}
            if rows:
                nonempty.append({"node_id": node["node_id"], "direction": direction, "count": len(rows)})
        nodes.append(item)
    return {"schema": "information_trade_transfer_independent_reference.v1",
            "basis": "independent_raw_RPM_transfer_lists_not_public_projection",
            "session_id": raw["identity"]["installation_session_id"], "game_date": selected["date"]["value"],
            "country": "FRA", "nodes": nodes, "nonempty_containers": nonempty,
            "source": pin(raw_path), "reference_builder": pin(Path(__file__)),
            "native_function_invoked": False, "business_actions_submitted": 0,
            "complete": False, "limits": ["FRA_ONLY", "NATIVE_CACHE_FRESHNESS_NOT_PROVEN",
                                           "TRADE_POWER_RELATIONS_NOT_STEERING_OR_VALUE_FLOW"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--run", action="store_true")
    mode.add_argument("--reference-from", type=Path)
    parser.add_argument("--installation", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--reference-output", type=Path)
    args = parser.parse_args()
    if not args.run and args.reference_from is None:
        parser.print_help()
        return 0
    if args.reference_from is not None:
        if args.reference_output is None:
            parser.error("--reference-from requires --reference-output")
        raw_path = args.reference_from.resolve(strict=True)
    else:
        if args.installation is None or args.output is None:
            parser.error("--run requires --installation and --output")
        raw_path = args.output.resolve()
        if raw_path.exists() or (args.reference_output and args.reference_output.exists()):
            raise ValueError("output_already_exists_no_resample")
        report = probe(args.installation.resolve(strict=True), field="trade_transfer", input_reader=read_transfer_inputs)
        report["schema"] = "information_trade_transfer_independent_inputs.v1"
        report["probe_source"] = pin(Path(__file__))
        report["reused_helpers"] = [pin(ROOT / name) for name in (
            "work/probe_information_current_overextension.py", "work/probe_information_trade_income.py",
            "work/probe_information_trade_source_details_v3.py")]
        write(raw_path, report)
    raw = json.loads(raw_path.read_text(encoding="utf-8-sig"))
    if args.reference_output:
        expected = reference(raw, raw_path)
        write(args.reference_output.resolve(), expected)
        print(json.dumps({"status": "passed", "nodes": len(expected["nodes"]),
                          "nonempty_containers": expected["nonempty_containers"]}))
    else:
        print(json.dumps({"status": raw["status"], "completed": raw["completed"]}))
    return 0 if raw["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
