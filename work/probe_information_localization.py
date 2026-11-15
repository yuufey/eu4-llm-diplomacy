"""Pure-RPM localization research inside the existing identity-bound snapshot.

Only this Python process temporarily extends its snapshot function. No target
hook, invocation, write, thread manipulation, installation or game action occurs.
The extra observations are part of the ordinary mission double-pass comparison.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from bridge.information import mission_memory as mm

GLOBAL_RVA=0x2357B00


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():raise FileExistsError(args.output)
    original=mm._snapshot

    def extended(reader,module_base,country,include_completed,*rest):
        snapshot=original(reader,module_base,country,include_completed,*rest)
        if snapshot.get("status")!="observed":return snapshot
        observation={"status":"unknown","global_rva":hex(GLOBAL_RVA)}
        try:
            outer,raw=reader.qword(module_base+GLOBAL_RVA,"localization.global")
            observation.update(global_raw_hex=raw.hex(),outer_va=hex(outer))
            if not mm._valid_pointer(outer):raise ValueError("invalid_outer")
            header=reader.read(outer,64,"localization.outer_header")
            inner=int.from_bytes(header[:8],"little")
            observation.update(outer_header_hex=header.hex(),outer_qwords=[hex(int.from_bytes(header[i:i+8],"little")) for i in range(0,64,8)])
            if not mm._valid_pointer(inner):raise ValueError("invalid_inner")
            data=reader.read(inner,80,"localization.inner_header")
            observation.update(inner_va=hex(inner),inner_header_hex=data.hex(),inner_qwords=[hex(int.from_bytes(data[i:i+8],"little")) for i in range(0,80,8)],status="observed")
        except Exception as exc:observation["error"]=str(exc)
        snapshot["missions"]["localization_probe"]=observation
        return snapshot

    try:
        mm._snapshot=extended
        report=mm.capture(args.installation,"FRA",include_completed=False)
    finally:
        mm._snapshot=original
    report["research_extension"]={"script":str(Path(__file__).resolve()),"sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "kind":"process_local_Python_snapshot_extension_not_game_hook","extra_reads_per_pass":["module+0x2357b00:8","outer:64","inner:80"]}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"status":report["status"],"doublepass":report["doublepass"],"rpm_bytes":report["access"]["rpm_bytes_requested"],
        "localization":report.get("before",{}).get("missions",{}).get("localization_probe")}))


if __name__=="__main__":main()
