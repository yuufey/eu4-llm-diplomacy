"""Observe the existing common promotion table without invoking its getter."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from bridge.information import mission_memory as mm
from work.discover_diplomacy import PE,check_memory_budget
from work.local_config import game_exe

SHA="b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():raise FileExistsError(args.output)
    pe=PE(game_exe());assert hashlib.sha256(pe.data).hexdigest()==SHA
    guards=[(start,pe.bytes_at(start,end-start)) for start,end in [(0x6FC600,0x6FC692),(0x6FC6A0,0x6FC86B)]]
    original=mm._snapshot

    def extended(reader,module,country,include_completed,*rest):
        snapshot=original(reader,module,country,include_completed,*rest)
        if snapshot.get("status")!="observed":return snapshot
        value={"status":"unknown","guard_checks":[],"entries":[]}
        try:
            for rva,expected in guards:
                actual=reader.read(module+rva,len(expected),"promotions.code_guard")
                value["guard_checks"].append({"rva":hex(rva),"size":len(expected),"equal":actual==expected,"sha256":hashlib.sha256(actual).hexdigest()})
                if actual!=expected:raise ValueError("code_guard_mismatch")
            raw=reader.read(module+0x245AF80,8,"promotions.init_guard")
            epoch=int.from_bytes(raw[4:8],"little",signed=True)
            value.update(init_raw_hex=raw.hex(),init_epoch=epoch)
            if epoch in (0,-1):raise ValueError("promotion_table_uninitialized_or_initializing")
            table=reader.read(module+0x2327A20,6*40,"promotions.table")
            value.update(table_rva="0x2327a20",table_raw_hex=table.hex(),count=6)
            for index in range(6):
                address=module+0x2327A20+index*40;entry=table[index*40:(index+1)*40]
                name=mm._decode_string32(reader,address,entry[:32],"promotions.name")
                if name.get("status")!="observed" and name.get("unknown_reason")!="root_string_not_ascii":
                    raise ValueError("promotion_name_bytes_unverified")
                payload=bytes.fromhex(name["payload_hex"]);length=name["length"]
                if name.get("nul_terminator_observed") is not True or len(payload)<=length or 0 in payload[:length]:
                    raise ValueError("promotion_name_bytes_invalid")
                value["entries"].append({"index":index,"raw_hex":entry.hex(),"name":name,
                    "name_bytes_hex":payload[:length].hex(),"enum":int.from_bytes(entry[32:36],"little",signed=True)})
            matches=[entry for entry in value["entries"] if bytes.fromhex(entry["name_bytes_hex"])==b"Root"]
            value.update(status="observed",root_matches=matches)
        except Exception as exc:value["error"]=str(exc)
        snapshot["missions"]["common_promotions_probe"]=value
        return snapshot

    try:
        mm._snapshot=extended
        report=mm.capture(args.installation,"FRA",include_completed=False)
    finally:mm._snapshot=original
    report["research_extension"]={"script":str(Path(__file__).resolve()),"sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "kind":"process_local_Python_snapshot_extension_not_game_hook","exe_sha256":SHA,"getter_invoked":False,"TLS_read":False,
        "scope":"observed already initialized six-entry common promotion table"}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    check_memory_budget()
    x=report.get("before",{}).get("missions",{}).get("common_promotions_probe",{})
    print(json.dumps({"status":report["status"],"consistent":report["doublepass"]["consistent"],"probe_status":x.get("status"),"error":x.get("error"),
        "entries":[(e["name"].get("text"),e["enum"]) for e in x.get("entries",[])],"rpm_bytes":report["access"]["rpm_bytes_requested"]}))


if __name__=="__main__":main()
