"""Retain small ordinary PE windows alongside separate cached REA evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE, check_memory_budget, make_disassembler
from work.local_config import game_exe
from work.research_information_branch_inputs import _decode_range

SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
STAGE = ROOT / "work/runtime/information-military-effective-20261027-001"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--range", action="append", required=True)
    args = parser.parse_args()
    ranges = [tuple(int(part, 16) for part in raw.split(":")) for raw in args.range]
    assert all(len(row) == 2 and 0 < row[1] - row[0] <= 16384 for row in ranges)
    assert sum(end - start for start, end in ranges) <= 32768
    check_memory_budget()
    pe = PE(game_exe())
    assert hashlib.sha256(pe.data).hexdigest() == SHA and pe.base == 0x140000000
    md, decoder = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    windows = []
    for start, end in ranges:
        raw = pe.bytes_at(start, end - start)
        assert len(raw) == end - start
        windows.append({"start_rva": hex(start), "end_rva_exclusive": hex(end),
                        "start_va": hex(pe.base + start), "end_va_exclusive": hex(pe.base + end),
                        "bytes_hex": raw.hex(), "bytes_sha256": hashlib.sha256(raw).hexdigest(),
                        "pdata": pe.function(start), "instructions": _decode_range(pe, md, start, end)})
    check_memory_budget()
    report = {"schema": "information_military_effective_bounded_code.v1",
              "evidence_kind": "ordinary_bounded_PE_not_REA", "binary_sha256": SHA,
              "static_image_base": hex(pe.base), "binary_bytes": len(pe.data),
              "decoder": "Capstone " + decoder.__version__ if md is not None else "bounded objdump",
              "decoded_bytes": sum(end - start for start, end in ranges), "windows": windows,
              "game_or_RPM": False, "whole_image_disassembly": False,
              "limitations": ["Static instructions do not prove runtime state or country semantics.",
                              "An arbitrary range start needs instruction-boundary justification before semantic use."]}
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"output": str(args.output), "decoded_bytes": report["decoded_bytes"],
                      "sha256": hashlib.sha256(args.output.read_bytes()).hexdigest()}, ensure_ascii=False))


if __name__ == "__main__":
    main()
