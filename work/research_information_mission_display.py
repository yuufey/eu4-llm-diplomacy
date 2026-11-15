"""Bounded ordinary-file exploration of mission selection/display candidates.

This produces neither REA Evidence nor runtime observations. It never opens
the game process. Candidate neighborhoods do not establish display semantics.
"""
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

EXPECTED = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
RANGES = (
    (0x8D5800, 0x8D7430, "mission_engine_neighborhood_before_known_root_parser"),
    (0x444A20, 0x444EE0, "country_mission_methods_before_known_save_parser"),
    (0xFC0E10, 0xFC3120, "mission_widget_neighborhood_after_known_tooltip"),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    pe = PE(game_exe())
    if hashlib.sha256(pe.data).hexdigest() != EXPECTED or pe.base != 0x140000000:
        raise ValueError("Unexpected EXE identity")
    md, _ = make_disassembler(None)
    assert all(0 < end-begin <= 65536 for begin, end, _ in RANGES)
    assert sum(end-begin for begin, end, _ in RANGES) <= 262144
    reports = []
    for begin, end, purpose in RANGES:
        raw = pe.bytes_at(begin, end-begin)
        rows = _decode_range(pe, md, begin, end)
        reports.append({"begin_rva": hex(begin), "end_rva_exclusive": hex(end),
            "purpose": purpose, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "instructions": rows,
            "unwind_ranges": [{"begin_rva":hex(a), "end_rva_exclusive":hex(b)}
                              for a,b,_ in pe.functions if begin <= a < end]})
        check_memory_budget()
    result = {"evidence_kind": "ordinary_bounded_file_analysis_not_REA_Evidence", "exe_sha256": EXPECTED,
        "image_base":hex(pe.base), "script_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "total_decode_bytes":sum(end-begin for begin,end,_ in RANGES), "ranges":reports,
        "limits": {"single_range_bytes":65536, "total_decode_bytes":262144},
        "unknowns":["Selected neighborhoods are candidates; no display or trigger conclusion follows from proximity.",
                    "No runtime execution or UI state was observed."]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"output":str(args.output), "ranges":len(reports), "decoded_bytes":result["total_decode_bytes"]}))


if __name__ == "__main__":
    main()
