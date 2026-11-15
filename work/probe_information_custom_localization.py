"""Inspect two loaded custom-localization records without evaluating them.

This extends only this Python process's existing bounded RPM snapshot. No
target hook, write, thread operation, function call, save or action occurs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from bridge.information import mission_memory as mm
from work.discover_diplomacy import PE,check_memory_budget
from work.local_config import game_exe

SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
GLOBAL = 0x233D900
METHODS = {"GetSelectableMissionTitle","GetSelectableMissionDescription"}
GUARDS = ((0x1FB320,0x1FBAE0),(0x46F770,0x46FAD0))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():raise FileExistsError(args.output)
    pe=PE(game_exe())
    if hashlib.sha256(pe.data).hexdigest()!=SHA:raise ValueError("EXE mismatch")
    guard_bytes=[(begin,pe.bytes_at(begin,end-begin)) for begin,end in GUARDS]
    original=mm._snapshot

    def extended(reader,module,country,include_completed,*rest):
        snapshot=original(reader,module,country,include_completed,*rest)
        if snapshot.get("status")!="observed":return snapshot
        observation={"status":"unknown","global_rva":hex(GLOBAL),"methods":{},"guard_checks":[],"unknown_names":[]}
        try:
            for rva,expected in guard_bytes:
                actual=reader.read(module+rva,len(expected),"customloc.code_guard")
                observation["guard_checks"].append({"rva":hex(rva),"size":len(expected),"sha256":hashlib.sha256(actual).hexdigest(),"equal":actual==expected})
                if actual!=expected:raise ValueError("code_guard_mismatch")
            database,raw=reader.qword(module+GLOBAL,"customloc.database")
            observation.update(global_raw_hex=raw.hex(),database_va=hex(database))
            if not mm._valid_pointer(database):raise ValueError("invalid_database")
            header=reader.read(database,16,"customloc.database_vector")
            begin,end=(int.from_bytes(header[i:i+8],"little") for i in (0,8))
            if end<begin or (end-begin)%8 or (end-begin)//8>2048:raise ValueError("invalid_database_span")
            count=(end-begin)//8
            if count and not mm._valid_pointer(begin):raise ValueError("invalid_database_entries")
            pointers=reader.read(begin,count*8,"customloc.database_pointers") if count else b""
            observation.update(database_header_hex=header.hex(),database_count=count,pointer_bytes_hex=pointers.hex())
            for index in range(count):
                pointer=int.from_bytes(pointers[index*8:index*8+8],"little")
                if not mm._valid_pointer(pointer):raise ValueError("invalid_definition_pointer")
                name_header=reader.read(pointer+0x18,32,"customloc.name_header")
                name=mm._decode_string32(reader,pointer+0x18,name_header,"customloc.name")
                if name.get("status")!="observed":
                    observation["unknown_names"].append({"index":index,"name":name})
                    continue
                text=name["text"]
                # Retain all name headers/payloads in the double-pass join;
                # omission of unrelated records must not mask name changes.
                observation.setdefault("names",[]).append({"index":index,"va":hex(pointer),"name":name})
                if text not in METHODS:continue
                if text in observation["methods"]:raise ValueError("duplicate_method_name")
                data=reader.read(pointer,0x48,"customloc.selected_definition")
                option_begin=int.from_bytes(data[0x38:0x40],"little")
                option_end=int.from_bytes(data[0x40:0x48],"little")
                if option_end<option_begin or (option_end-option_begin)%8 or (option_end-option_begin)//8>128:
                    raise ValueError("invalid_option_span")
                option_count=(option_end-option_begin)//8
                if option_count and not mm._valid_pointer(option_begin):raise ValueError("invalid_option_pointer")
                option_raw=reader.read(option_begin,option_count*8,"customloc.option_pointers") if option_count else b""
                record={"index":index,"name":name,"va":hex(pointer),"header_hex":data.hex(),
                        "random_byte":data[0x10],"option_count":option_count,"option_pointers_hex":option_raw.hex(),"options":[]}
                for option_index in range(option_count):
                    option=int.from_bytes(option_raw[option_index*8:option_index*8+8],"little")
                    if not mm._valid_pointer(option):raise ValueError("invalid_option_record")
                    entry=reader.read(option,0x48,"customloc.option_header")
                    key=mm._decode_string32(reader,option+0x10,entry[0x10:0x30],"customloc.text_key")
                    predicates=int.from_bytes(entry[0x38:0x40],"little")
                    predicate_count=int.from_bytes(entry[0x44:0x48],"little",signed=True)
                    if not 0<=predicate_count<=64:raise ValueError("invalid_predicate_count")
                    if predicate_count and not mm._valid_pointer(predicates):raise ValueError("invalid_predicate_pointer")
                    predicates_raw=reader.read(predicates,predicate_count*8,"customloc.predicate_pointers") if predicate_count else b""
                    record["options"].append({"index":option_index,"va":hex(option),"header_hex":entry.hex(),
                        "text_key":key,"predicate_count":predicate_count,"predicate_pointers_hex":predicates_raw.hex(),
                        "predicates_evaluated":False})
                observation["methods"][text]=record
            observation["status"]="observed"
            observation["requested_methods_found"]=set(observation["methods"])==METHODS
        except Exception as exc:observation["error"]=str(exc)
        snapshot["missions"]["custom_localization_probe"]=observation
        return snapshot

    try:
        mm._snapshot=extended
        report=mm.capture(args.installation,"FRA",include_completed=False)
    finally:mm._snapshot=original
    report["research_extension"]={"script":str(Path(__file__).resolve()),"sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "kind":"process_local_Python_snapshot_extension_not_game_hook","exe_sha256":SHA,
        "evidence_scope":"loaded custom text names/options only; no predicate evaluation or final text",
        "max_definitions":2048,"max_options_per_method":128,"max_predicates_per_option":64,
        "code_guard_ranges_rva":[[hex(a),hex(b)] for a,b in GUARDS]}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    check_memory_budget()
    probe=report.get("before",{}).get("missions",{}).get("custom_localization_probe",{})
    print(json.dumps({"status":report["status"],"doublepass":report["doublepass"],"rpm_bytes":report["access"]["rpm_bytes_requested"],
        "probe_status":probe.get("status"),"probe_error":probe.get("error"),"method_count":len(probe.get("methods",{})),
        "definition_count":probe.get("database_count"),"unknown_names":len(probe.get("unknown_names",[]))}))


if __name__=="__main__":main()
