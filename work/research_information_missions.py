"""Bounded ordinary file analysis for the exact 1.37.4 mission fields.

This is not REA Evidence. Literal byte searches use the PE file; disassembly is
limited to explicit ranges or the containing functions of three named fields.
No game process is opened and no whole-image disassembly is performed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE, rip_references, make_disassembler, check_memory_budget
from work.local_config import game_exe

EXPECTED = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
KEYS = ("country_missions", "mission_slot", "completed_missions")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--range", action="append", default=[])
    args = parser.parse_args()
    pe = PE(game_exe())
    digest = hashlib.sha256(pe.data).hexdigest()
    assert digest == EXPECTED, "Unsupported binary"
    md, cs = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    def decode(begin, end):
        if md is not None:
            return [{"rva": hex(i.address), "bytes": i.bytes.hex(), "mnemonic": i.mnemonic,
                     "operands": i.op_str} for i in md.disasm(pe.bytes_at(begin, end-begin), begin)]
        command = ["objdump", "-d", "-w", "-Mintel", f"--start-address={pe.base+begin:#x}",
                   f"--stop-address={pe.base+end:#x}", str(pe.path)]
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=30)
        assert len(result.stdout) <= 8*1024*1024
        rows = []
        for line in result.stdout.splitlines():
            match = re.match(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*([^\s]+)(?:\s+(.*))?$", line)
            if match:
                rows.append({"rva": hex(int(match[1],16)-pe.base), "bytes": match[2].replace(" ",""),
                             "mnemonic": match[3], "operands": match[4] or ""})
        return rows

    report = {"evidence_kind": "ordinary_file_analysis_not_REA_Evidence",
              "game_sha256": digest, "image_base": hex(pe.base),
              "decoder": "capstone " + cs.__version__ if cs else "bounded objdump -w -Mintel",
              "address_kind": "RVA", "limits": {"range_bytes": 65536, "total_decode_bytes": 262144},
              "decoded_bytes": 0, "ranges": [], "strings": [], "unresolved": []}
    for text in args.range:
        a, b = (int(value, 0) for value in text.split(":"))
        assert 0 <= a < b and b - a <= 65536
        assert pe.executable(a) and pe.executable(b - 1)
        assert report["decoded_bytes"] + b - a <= 262144
        raw = pe.bytes_at(a, b-a)
        report["decoded_bytes"] += len(raw)
        instructions = decode(a, b)
        report["ranges"].append({"start_rva": hex(a), "end_rva_exclusive": hex(b),
                                 "bytes_sha256": hashlib.sha256(raw).hexdigest(),
                                 "instructions": instructions})
    if not args.range:
        records = []
        for key in KEYS:
            needle = key.encode("ascii") + b"\0"
            offset = 0
            while True:
                found = pe.data.find(needle, offset)
                if found < 0:
                    break
                offset = found + len(needle)
                rva = pe.to_rva(found)
                if rva is not None:
                    records.append({"key": key, "string_rva": rva, "file_offset": found})
        targets = {r["string_rva"] + delta for r in records for delta in (0, -4)}
        refs = rip_references(pe, targets)
        for record in records:
            record["token_id"] = hex(pe.u32(record["file_offset"]-4))
            record["token_immediate_candidates"] = []
            token_bytes = struct.pack("<I", int(record["token_id"],16))
            for section in pe.sections:
                if not section["flags"] & 0x20000000:
                    continue
                position, stop = section["raw"], section["raw"]+section["size"]
                while True:
                    found = pe.data.find(token_bytes, position, stop)
                    if found < 0:
                        break
                    position = found + 4
                    rva = pe.to_rva(found)
                    function = pe.function(rva)
                    row = {"immediate_bytes_rva": hex(rva), "instruction_boundary_verified": False,
                           "function_range": [hex(i) for i in function[:2]] if function else None}
                    if function and function[1]-function[0] <= 65536 and report["decoded_bytes"]+function[1]-function[0] <= 262144:
                        report["decoded_bytes"] += function[1]-function[0]
                        instructions = decode(*function[:2])
                        row["context"] = [i for i in instructions if rva-65 <= int(i["rva"],16) <= rva+150]
                        row["instruction_boundary_verified"] = any(int(i["rva"],16) <= rva < int(i["rva"],16)+len(i["bytes"])//2 for i in instructions)
                    record["token_immediate_candidates"].append(row)
                    assert len(record["token_immediate_candidates"]) <= 128
            record["string_rva"] = hex(record["string_rva"])
            record["references"] = []
            for target in (int(record["string_rva"], 16), int(record["string_rva"], 16)-4):
                for ref in refs[target]:
                    rva = int(ref["instruction_rva"], 16)
                    function = pe.function(rva)
                    row = dict(ref, target_rva=hex(target), instruction_boundary_verified=False)
                    if function and function[1] - function[0] <= 65536:
                        begin, end = function[:2]
                        if report["decoded_bytes"] + end-begin <= 262144:
                            report["decoded_bytes"] += end-begin
                            instructions = decode(begin, end)
                            row["instruction_boundary_verified"] = any(int(i["rva"],16) == rva for i in instructions)
                            row["context"] = [i for i in instructions if rva-80 <= int(i["rva"],16) <= rva+160]
                    record["references"].append(row)
            report["strings"].append(record)
    report["peak_committed_bytes"] = check_memory_budget()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(report, output, ensure_ascii=False, indent=2)
        output.write("\n")
    print(json.dumps({"output": str(args.output), "decoded_bytes": report["decoded_bytes"],
                      "strings": len(report["strings"]), "peak_committed_bytes": report["peak_committed_bytes"]}))


if __name__ == "__main__":
    main()
