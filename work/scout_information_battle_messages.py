"""Locate selected battle notification or GUI keys in the fixed 1.37.4 PE.

This is ordinary file evidence: one exact byte search and one RIP-byte-pattern
pass, followed only by bounded decoding of candidate unwind ranges. It neither
performs whole-image disassembly nor establishes a battle payload reader.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE, check_memory_budget, rip_references
from work.research_information_country_scalars import _objdump_rows

EXE = ROOT / "work/runtime/ghidra-full/b23fa0e1f698d31b-20261014T054913Z-6dda97/input/eu4.exe"
STAGE = ROOT / "work/runtime/information-battles-20261025-001"
SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
KEYS = ("LANDBATTLEOVER", "NAVALBATTLEOVER")
GUI_KEYS = ("EndOfLandCombatPopup", "EndOfLandCombatCompactPopup", "EndOfNavalCombatPopup",
            "GFX_combat_result_bg", "GFX_combat_result_compact_bg", "THE_FOLLOWING_SHIPS_WHERE_CAPTURED")
MAX_FUNCTION_BYTES = 0x10000
MAX_TOTAL_DECODE = 0x40000


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=STAGE / "message-key-xrefs-001.json")
    parser.add_argument("--targets", choices=("messages", "gui"), default="messages")
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(STAGE.resolve()) or output.exists():
        raise ValueError("a new battle-stage output file is required")
    if EXE.stat().st_size != 38463016:
        raise ValueError("fixed executable size mismatch")
    pe = PE(EXE)
    if hashlib.sha256(pe.data).hexdigest() != SHA or pe.base != 0x140000000:
        raise ValueError("fixed executable identity mismatch")
    locations = []
    keys = KEYS if args.targets == "messages" else GUI_KEYS
    for key in keys:
        for encoding in ("ascii", "utf-16-le"):
            needle = key.encode(encoding) + (b"\0" if encoding == "ascii" else b"\0\0")
            start = 0
            count = 0
            while True:
                offset = pe.data.find(needle, start)
                if offset < 0:
                    break
                count += 1
                if count > 32:
                    raise ValueError("selected key match budget exceeded")
                rva = pe.to_rva(offset)
                if rva is None:
                    raise ValueError("key is not uniquely mapped by PE sections")
                locations.append({"key": key, "encoding": encoding, "file_offset": offset,
                                  "rva": hex(rva), "static_va": hex(pe.base + rva),
                                  "bytes": len(needle), "raw_hex": needle.hex()})
                start = offset + len(needle)
    targets = {int(item["rva"], 16) for item in locations}
    references = rip_references(pe, targets)
    if sum(len(items) for items in references.values()) > 128:
        raise ValueError("selected key reference budget exceeded")
    decoded = {}
    total = 0
    for target, rows in references.items():
        for row in rows:
            rva = int(row["instruction_rva"], 16)
            bounds = pe.function(rva)
            if bounds is None:
                row["validation"] = "unknown_no_unwind_range"
                continue
            begin, end = bounds[:2]
            if begin not in decoded:
                if end - begin > MAX_FUNCTION_BYTES or total + end - begin > MAX_TOTAL_DECODE:
                    decoded[begin] = None
                else:
                    total += end - begin
                    decoded[begin] = {int(ins["rva"], 16): ins for ins in _objdump_rows(pe, begin, end)}
                check_memory_budget()
            instructions = decoded[begin]
            ins = instructions.get(rva) if instructions is not None else None
            if ins is None:
                row["validation"] = "unknown_decode_budget_or_not_instruction_boundary"
                continue
            raw = bytes.fromhex(ins["bytes"])
            exact = (ins["mnemonic"] in {"lea", "mov"} and "rip" in ins["operands"]
                     and len(raw) in {6, 7}
                     and rva + len(raw) + struct.unpack_from("<i", raw, len(raw) - 4)[0] == target)
            row.update(validation="instruction_verified" if exact else "rejected_target_mismatch",
                       static_va=hex(pe.base + rva), mnemonic=ins["mnemonic"], operands=ins["operands"],
                       raw_hex=raw.hex(),
                       unwind_range_sha256=hashlib.sha256(pe.bytes_at(begin, end - begin)).hexdigest())
    report = {
        "schema": "information_battle_message_key_xrefs_v1",
        "evidence_kind": "ordinary_PE_bytes_and_bounded_objdump_not_REA_or_runtime",
        "exe_sha256": SHA, "exe_bytes": len(pe.data), "image_base": hex(pe.base),
        "targets": list(keys), "locations": locations,
        "references": {hex(key): rows for key, rows in references.items()},
        "decoded_bytes": total, "max_total_decode_bytes": MAX_TOTAL_DECODE,
        "max_function_bytes": MAX_FUNCTION_BYTES,
        "resource_peak_commit_bytes": check_memory_budget(),
        "range_kind": "PE RUNTIME_FUNCTION half-open unwind range, not complete semantic C++ body",
        "whole_image_disassembly": False, "runtime_or_REA": False,
        "payload_layout_verified": False, "production_changed": False,
        "limitations": ["A notification key reference is only a candidate for further analysis.",
                        "No battle contents, lossless stream, event identity or visibility is established."]}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"output": output.relative_to(ROOT).as_posix(), "locations": len(locations),
                      "references": sum(len(rows) for rows in references.values()), "decoded_bytes": total,
                      "functions": sorted({row["function_range"][0] for rows in references.values()
                                           for row in rows if row.get("function_range")})}))


if __name__ == "__main__":
    main()
