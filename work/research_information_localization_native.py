"""Decode exact, bounded localization functions from the fixed EU4 1.37.4 PE.

Ordinary file evidence only; this tool does not open a game process or a REA
session. It refuses an existing output and requests exact unwind entries.
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

EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rva", action="append", type=lambda s:int(s,0), required=True)
    parser.add_argument("--purpose", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or not 1<=len(args.rva)<=16 or len(set(args.rva))!=len(args.rva):
        raise ValueError("Require new output and 1..16 distinct exact function entries")
    pe = PE(game_exe())
    if hashlib.sha256(pe.data).hexdigest()!=EXE_SHA256 or pe.base!=0x140000000:
        raise ValueError("Unsupported executable identity")
    ranges=[]
    for rva in args.rva:
        region=pe.function(rva)
        if region is None or region[0]!=rva or region[1]-rva>65536:
            raise ValueError(f"Missing/non-exact/unbounded unwind function {rva:#x}")
        ranges.append(region)
    if sum(end-begin for begin,end,_ in ranges)>262144:
        raise ValueError("Total decoding budget exceeded")
    md,_=make_disassembler(None)
    result={"evidence_kind":"ordinary_bounded_file_analysis_not_REA_Evidence", "exe_sha256":EXE_SHA256,
        "image_base":hex(pe.base), "script_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "purpose":args.purpose,"functions":[],"unknowns":["No runtime state or execution observed.",
        "PE unwind ranges do not prove all semantic chunks or a callable ABI."]}
    for begin,end,unwind in ranges:
        raw=pe.bytes_at(begin,end-begin)
        result["functions"].append({"begin_rva":hex(begin),"end_rva_exclusive":hex(end),"unwind_rva":hex(unwind),
            "bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"instructions":_decode_range(pe,md,begin,end)})
        check_memory_budget()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"output":str(args.output),"functions":len(ranges),"bytes":sum(e-b for b,e,_ in ranges)}))


if __name__=="__main__":
    main()
