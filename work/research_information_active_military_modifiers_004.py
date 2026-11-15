"""Bound the discovered country modifier list and its serialization helpers."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE, make_disassembler, check_memory_budget
from work.local_config import game_exe
from work.research_information_branch_inputs import _decode_range

RANGES = ((0x2E0020, 0x2E00D9), (0xC0170, 0xC0181), (0x9A010, 0x9A014),
          (0x114B00, 0x114B05), (0x43F2A0, 0x43F2A8), (0x1707920, 0x170794C))

def main(details=False):
    pe=PE(game_exe())
    digest=hashlib.sha256(pe.data).hexdigest()
    assert digest == "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
    md,_=make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    ranges=[]
    ranges_to_decode = ((0x2E0076,0x2E00D9),(0xB356D0,0xB359D4),
                        (0xB359E0,0xB35C1A),(0x8E67C0,0x8E6A0D)) if details else RANGES
    for start,end in ranges_to_decode:
        assert end-start <= 4096
        raw=pe.bytes_at(start,end-start)
        ranges.append(dict(start_rva=hex(start),end_rva_exclusive=hex(end),
                           start_static_va=hex(pe.base+start),bytes=len(raw),
                           sha256=hashlib.sha256(raw).hexdigest(),
                           instructions=_decode_range(pe,md,start,end)))
    d=dict(schema="information_active_military_modifiers_list_path.v1",
           evidence_kind="ordinary_bounded_PE_not_REA",exe_sha256=digest,
           image_base=hex(pe.base),ranges=ranges,RPM=False,native_calls=0,
           limitations=["Writer argument binding reuses source-003; no runtime list is observed.",
                        "List identity, source/date/definition semantics and completeness need separate closure."],
           peak_committed_bytes=check_memory_budget())
    d['limitations'].append('Source004 starts at an unaligned 2E0020: its prefix is not valid evidence. Source005 starts at the full-writer verified boundary 2E0076 and supersedes that prefix.')
    p=ROOT/('work/runtime/information-military-modifiers-20261027-001/active-military-modifiers-source-005.json' if details else 'work/runtime/information-military-modifiers-20261027-001/active-military-modifiers-source-004.json')
    with p.open('x',encoding='utf-8') as f:
        json.dump(d,f,ensure_ascii=False,indent=2); f.write('\n')
    for r in ranges:
        print(r['start_rva'],r['end_rva_exclusive'])
        for i in r['instructions']: print(i['rva'],i['mnemonic'],i['operands'])

if __name__=='__main__':
    assert sys.argv[1:] in ([],['--details'])
    main(sys.argv[1:]==['--details'])
