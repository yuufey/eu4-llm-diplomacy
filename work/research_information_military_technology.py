"""Targeted ordinary-PE military-technology survey and bounded decoding."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE, check_memory_budget, make_disassembler, rip_references
from work.local_config import game_exe
from work.research_information_branch_inputs import _decode_range

SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
STAGE = ROOT / "work/runtime/information-military-quality-20261027-001"
TARGETS = ("mil_tech", "military_technology", "military_tech", "MIL_TECH", "MILITARY_TECH")


def location(pe, rva):
    return {"rva": hex(rva), "va": hex(pe.base + rva)}


def survey(pe):
    matches, targets = [], set()
    for name in TARGETS:
        needle = name.encode() + b"\0"
        start = 0
        for _ in range(64):
            offset = pe.data.find(needle, start)
            if offset < 0:
                break
            start = offset + 1
            if offset and chr(pe.data[offset - 1]) in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_":
                continue
            rva = pe.to_rva(offset)
            if rva is None:
                continue
            item = {"name": name, **location(pe, rva), "bytes_hex": needle.hex()}
            targets.add(rva)
            record = rva - 4
            if (record - 0x1FD8660) % 0x208 == 0:
                token = struct.unpack("<I", pe.bytes_at(record, 4))[0]
                item["token_record"] = {**location(pe, record), "token": token, "token_hex": hex(token)}
                targets.add(record)
                pattern = b"\xb8" + struct.pack("<I", token) + b"\xc3"
                accessors = []
                cursor = 0
                for _ in range(32):
                    found = pe.data.find(pattern, cursor)
                    if found < 0:
                        break
                    cursor = found + 1
                    accessor = pe.to_rva(found)
                    if accessor is None or not pe.executable(accessor):
                        continue
                    pointers = []
                    ptr = struct.pack("<Q", pe.base + accessor)
                    pos = 0
                    for _ in range(64):
                        where = pe.data.find(ptr, pos)
                        if where < 0:
                            break
                        pos = where + 1
                        pointer_rva = pe.to_rva(where)
                        if pointer_rva is not None:
                            pointers.append(location(pe, pointer_rva))
                    accessors.append({**location(pe, accessor), "bytes_hex": pattern.hex(), "static_pointer_slots": pointers})
                item["token_accessors"] = accessors
            matches.append(item)
    refs = rip_references(pe, targets)
    for item in matches:
        item["rip_string_candidates"] = refs.get(int(item["rva"], 16), [])
        if "token_record" in item:
            item["rip_record_candidates"] = refs.get(int(item["token_record"]["rva"], 16), [])
    return {"matches": matches, "candidate_references_are_not_semantic_proof": True}


def run(output, ranges, contract=False):
    check_memory_budget()
    pe = PE(game_exe())
    assert hashlib.sha256(pe.data).hexdigest() == SHA and pe.base == 0x140000000
    report = {"schema": "information_military_technology_static.v1", "evidence_kind": "ordinary_bounded_PE_not_REA",
              "exe": {"path": str(pe.path), "sha256": SHA, "bytes": len(pe.data), "static_image_base": hex(pe.base)},
              "runtime_or_RPM": False, "game_calls": 0, "whole_image_disassembly": False}
    if contract:
        names = ["military-technology-code-003.json", "military-technology-code-004.json", "military-technology-code-005.json"]
        sources = [{"path": (STAGE / name).relative_to(ROOT).as_posix(),
                    "sha256": hashlib.sha256((STAGE / name).read_bytes()).hexdigest()} for name in names]
        report["source_pins"] = sources
        report["contract"] = {
            "field": "military_technology", "country_technology_pointer_offset": "0x2440",
            "technology_levels_vector_offsets": {"begin": "0x128", "end": "0x130"},
            "vector_element": {"bytes": 4, "signed": True, "unit": "technology_level", "scale": 1},
            "category": {"key": "mil_tech", "manager_pointer_global_rva": "0x242be30",
                         "bucket_count_offset": "0x34", "bucket_array_offset": "0x38",
                         "link_item_offset": "0x0", "link_next_offset": "0x8",
                         "definition_name_offset": "0x10", "name_length_offset": "0x20", "name_capacity_offset": "0x28",
                         "definition_index_offset": "0x50", "index_signed": True,
                         "hash": "h = ((h + signedASCIIbyte) * 61) modulo 2^32; unsigned h modulo bucket_count",
                         "selection": "first exact length-8 mil_tech key in selected bucket chain; capacity<16 inline, otherwise pointer",
                         "fixed_category_index_assumed": False},
            "getter": {"rva": "0x6df5a0", "va": "0x1406df5a0", "end_rva_exclusive": "0x6df692",
                       "key_literal_instruction_rva": "0x6df5cc", "level_load_rva": "0x6df67b",
                       "internal_result": "signed int32 level * 1000 in EAX; multiplication is internal fixed-point conversion",
                       "public_projection": "copy the original signed int32 level, with scale1; do not publish the internal product as an unscaled level"},
            "corroboration": {"UI_current_country_route_rva": ["0xfbad37", "0xfbad66"],
                              "observed_static_behavior": "database country table[fullref slot] -> country+2440 -> levels+128 -> definition_index*4; increment for next technology lookup"},
            "basis": "native_country_technology_level_cache", "value_origin": "copied_native_country_technology_cache"}
        report["limits"] = ["Ordinary bounded PE evidence, not a REA function result or a runtime observation.",
                            "A third pointer at technology+138 was only inferred from container shape in source001; it is not proved or needed by this contract, and is not consumed.",
                            "No game call, state write, date advance or save/reload was performed.",
                            "Read existing native level storage; this is not a technology cost or projected next-level field.",
                            "Runtime must resolve mil_tech by exact key, validate index against vector bounds, and bind the verified country/session/date.",
                            "No foreign-country visibility policy, event trigger, or GUI-widget identity is established by this source contract."]
        prior = STAGE / "military-technology-source-001.json"
        if prior.exists():
            report["correction"] = {"prior": {"path": prior.relative_to(ROOT).as_posix(),
                                              "sha256": hashlib.sha256(prior.read_bytes()).hexdigest()},
                                    "withdrawn": "technology+138 is a proved capacity slot",
                                    "retained": "The exact key/hash/index and country+2440/levels+128/end+130 paths remain valid."}
    elif not ranges:
        report["survey"] = survey(pe)
    else:
        parsed = [tuple(int(part, 16) for part in value.split(":")) for value in ranges]
        assert all(0 < end - start <= 0x4000 for start, end in parsed)
        assert sum(end - start for start, end in parsed) <= 0x8000
        md, decoder = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
        report["decoder"] = "Capstone " + decoder.__version__ if md is not None else "bounded objdump"
        decoded = []
        for start, end in parsed:
            raw = pe.bytes_at(start, end - start)
            assert len(raw) == end - start
            decoded.append({"start": location(pe, start), "end_exclusive": location(pe, end),
                            "byte_length": len(raw), "bytes_sha256": hashlib.sha256(raw).hexdigest(),
                            "pdata": pe.function(start), "instructions": _decode_range(pe, md, start, end)})
        report["ranges"] = decoded
    check_memory_budget()
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"output": str(output), "bytes": output.stat().st_size,
                      "sha256": hashlib.sha256(output.read_bytes()).hexdigest()}, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--range", action="append", default=[])
    parser.add_argument("--contract", action="store_true")
    args = parser.parse_args()
    assert not (args.contract and args.range)
    run(args.output, args.range, args.contract)
