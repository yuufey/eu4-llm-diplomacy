"""Independent raw trade graph capture using the existing country RPM lifecycle."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.probe_information_current_overextension import probe


def read_trade(reader, base, country):
    def read(address, size, label):
        if not isinstance(address, int) or not 0x10000 <= address < 0x7FFFFFFFFFFF - size:
            raise ValueError("reference_pointer_invalid:" + label)
        return reader.read(address, size, "reference.trade." + label)

    def pointer(address, label):
        raw = read(address, 8, label)
        value = int.from_bytes(raw, "little")
        if not 0x10000 <= value < 0x7FFFFFFFFFFF:
            raise ValueError("reference_pointer_invalid:" + label)
        return value, raw.hex()

    manager, manager_hex = pointer(base + 0x242BE28, "definitions_manager_global")
    header = read(manager, 16, "definitions_header")
    begin, end = (int.from_bytes(header[n:n + 8], "little") for n in (0, 8))
    if end < begin or (end - begin) % 8 or not 1 <= (end - begin) // 8 <= 1024:
        raise ValueError("reference_node_vector_bounds")
    pointers = read(begin, end - begin, "definition_pointers")
    game, game_hex = pointer(base + 0x233FE58, "game_global")
    province_base, province_base_hex = pointer(game + 0x1CA8, "province_base")
    reference = read(country + 0x20, 8, "country_reference")
    slot = int.from_bytes(reference[4:6], "little", signed=True)
    if reference[:3] != b"FRA" or not 0 <= slot < 32768:
        raise ValueError("reference_country_binding")
    special = read(base + 0x233D8B8, 4, "filter_special_country_slot")
    nodes = []
    seen = set()
    for index in range((end - begin) // 8):
        definition = int.from_bytes(pointers[index * 8:index * 8 + 8], "little")
        data = read(definition, 0xE0, f"definition_{index}")
        vtable = int.from_bytes(data[:8], "little")
        method, method_hex = pointer(vtable + 0x40, f"predicate_{index}")
        if not base <= method < base + 0x4000000:
            raise ValueError("reference_predicate_not_in_module")
        center = int.from_bytes(data[0xDC:0xE0], "little", signed=True)
        if not 0 <= center < 32768:
            raise ValueError("reference_center_bound")
        runtime, runtime_hex = pointer(province_base + center * 0x2E10 + 0xE8, f"runtime_{index}")
        node = read(runtime, 0xB0, f"node_header_{index}")
        native_definition = int.from_bytes(node[0xA8:0xB0], "little")
        name_header = read(native_definition + 0x10, 32, f"key_header_{index}")
        length, capacity = (int.from_bytes(name_header[n:n + 8], "little") for n in (16, 24))
        if not 1 <= length <= 128 or capacity < length or capacity > 1048576:
            raise ValueError("reference_key_string_bound")
        payload = (name_header[:length + 1] if capacity < 16 else
                   read(int.from_bytes(name_header[:8], "little"), length + 1, f"key_{index}"))
        if len(payload) != length + 1 or payload[-1:] != b"\0":
            raise ValueError("reference_key_termination")
        key = payload[:-1].decode("ascii")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", key) or key in seen:
            raise ValueError(f"reference_key_invalid_or_duplicate:{index}")
        seen.add(key)
        table = int.from_bytes(node[0x18:0x20], "little")
        entry = table + slot * 0xC0
        income = read(entry + 0x34, 4, f"income_{index}")
        flags = read(entry + 0xAC, 3, f"flags_{index}")
        nodes.append({"definition_pointer": hex(definition), "definition_vtable_raw_hex": data[:8].hex(),
                      "definition_raw_hex": data.hex(),
                      "predicate_pointer_raw_hex": method_hex, "predicate_rva": hex(method - base),
                      "predicate_prefix_hex": read(method, 8, f"predicate_code_{index}").hex(),
                      "center_raw_hex": data[0xDC:0xE0].hex(), "center": center,
                      "runtime_pointer_raw_hex": runtime_hex, "runtime_pointer": hex(runtime),
                      "native_definition_pointer_raw_hex": node[0xA8:0xB0].hex(),
                      "key_header_hex": name_header.hex(), "key_payload_hex": payload.hex(), "node_id": key,
                      "country_table_pointer_raw_hex": node[0x18:0x20].hex(), "entry_address": hex(entry),
                      "income_raw_hex": income.hex(), "income_raw": int.from_bytes(income, "little", signed=True),
                      "flags_ac_ad_ae_hex": flags.hex()})
    return {"module_base": hex(base), "country_reference_raw_hex": reference.hex(), "country_slot": slot,
            "definitions_manager_pointer_raw_hex": manager_hex,
            "definitions_header_hex": header.hex(), "definition_pointers_hex": pointers.hex(),
            "game_global_raw_hex": game_hex, "province_base_raw_hex": province_base_hex,
            "filter_special_country_slot_raw_hex": special.hex(), "nodes": nodes,
            "selection_semantics": "Raw inputs only; outer virtual predicate and B58C70 filter evaluation are separate static derivations."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("refusing_to_overwrite_output")
    result = probe(args.installation, field="trade_income", input_reader=read_trade)
    result["schema"] = "information_independent_trade_income_inputs.v1"
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"status": result["status"], "completed": result["completed"], "errors": result["errors"],
                      "node_counts": [len(x.get("nodes", [])) for x in result["trade_income_inputs"]]}))
    raise SystemExit(0 if result["completed"] else 1)
