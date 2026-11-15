"""Read the already initialized country text-name table without invoking TLS.

The callback is not called. Only its observed global pointer/count and exact
string entries are read in the existing identity-bound RPM double pass.
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
from work.discover_diplomacy import PE,check_memory_budget
from work.local_config import game_exe

SHA="b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
GLOBAL=0x245AC98
METHODS={"GetSelectableMissionTitle","GetSelectableMissionDescription"}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():raise FileExistsError(args.output)
    pe=PE(game_exe());assert hashlib.sha256(pe.data).hexdigest()==SHA
    guards=[(start,pe.bytes_at(start,end-start)) for start,end in [(0x27A100,0x27A16F),(0x1FCE70,0x1FCF90)]]
    original=mm._snapshot

    def extended(reader,module,country,include_completed,*rest):
        snapshot=original(reader,module,country,include_completed,*rest)
        if snapshot.get("status")!="observed":return snapshot
        value={"status":"unknown","guard_checks":[],"entries":[]}
        try:
            for rva,expected in guards:
                observed=reader.read(module+rva,len(expected),"builtin.code_guard")
                value["guard_checks"].append({"rva":hex(rva),"bytes":len(expected),"equal":observed==expected,"sha256":hashlib.sha256(observed).hexdigest()})
                if observed!=expected:raise ValueError("code_guard_mismatch")
            init=reader.read(module+0x245AC88,8,"builtin.init_guard")
            epoch=int.from_bytes(init[4:8],"little",signed=True)
            if epoch in (0,-1):raise ValueError("table_not_initialized_or_initializing")
            header=reader.read(module+GLOBAL,16,"builtin.table_header")
            pointer=int.from_bytes(header[:8],"little");count=int.from_bytes(header[12:16],"little",signed=True)
            if not 0<count<=2048 or not mm._valid_pointer(pointer):raise ValueError("invalid_table_header")
            value.update(init_guard_raw_hex=init.hex(),init_epoch=epoch,global_rva=hex(GLOBAL),header_hex=header.hex(),pointer_va=hex(pointer),count=count)
            for index in range(count):
                address=pointer+index*40
                raw=reader.read(address,40,"builtin.entry")
                name=mm._decode_string32(reader,address,raw[:32],"builtin.name")
                if name.get("status")!="observed":value.setdefault("unknown_names",[]).append({"index":index,"name":name})
                value["entries"].append({"index":index,"raw_hex":raw.hex(),"name":name})
            names=[entry["name"].get("text") for entry in value["entries"]]
            value.update(status="unknown" if value.get("unknown_names") else "observed",requested_method_matches={method:[i for i,name in enumerate(names) if name==method] for method in sorted(METHODS)})
        except Exception as exc:value["error"]=str(exc)
        snapshot["missions"]["country_builtin_text_probe"]=value
        return snapshot

    try:
        mm._snapshot=extended
        report=mm.capture(args.installation,"FRA",include_completed=False)
    finally:mm._snapshot=original
    report["research_extension"]={"script":str(Path(__file__).resolve()),"sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "kind":"process_local_Python_snapshot_extension_not_game_hook","exe_sha256":SHA,"callback_invoked":False,"TLS_read":False,
        "scope":"already initialized country builtin names and exact-match absence only"}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    check_memory_budget()
    x=report.get("before",{}).get("missions",{}).get("country_builtin_text_probe",{})
    print(json.dumps({"status":report["status"],"consistent":report["doublepass"]["consistent"],"probe_status":x.get("status"),"error":x.get("error"),
        "unknown_names":x.get("unknown_names"),"count":x.get("count"),"requested_matches":x.get("requested_method_matches"),"rpm_bytes":report["access"]["rpm_bytes_requested"]}))


if __name__=="__main__":main()
