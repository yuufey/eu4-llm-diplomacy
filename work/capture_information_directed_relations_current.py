"""Compare production relation captures with independent network/pair bytes.

Only --run opens the process. --replay reuses the original production JSON.
The private witnesses do not expand the public FRA observer scope.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
STAGE=ROOT/"work/runtime/information-relation-network-remaining-20261027-001"
INSTALLATION=ROOT/"work/runtime/diplomacy-observer-20261026-information-battle-v27-002/installation.json"


def load(path):
    if path.stat().st_size>10*1024*1024:
        from work.reference_information_directed_relations_current import _stream_report
        return _stream_report(path)
    with path.open(encoding="utf-8-sig") as stream:return json.load(stream)


def pin(path):
    with path.open("rb") as stream:digest=hashlib.file_digest(stream,"sha256").hexdigest()
    return {"path":path.relative_to(ROOT).as_posix(),"bytes":path.stat().st_size,"sha256":digest}


def write(path,value):
    with path.open("x",encoding="utf-8",newline="\n") as stream:
        json.dump(value,stream,ensure_ascii=False,indent=2,sort_keys=True);stream.write("\n")


def run(args):
    from bridge.information import directed_relation_memory as memory
    if args.receipt.exists():raise FileExistsError(args.receipt)
    args.output.mkdir(parents=True,exist_ok=args.replay)
    installation=load(args.installation)
    network_path=STAGE/"expected-directed-relations-projection-001.json"
    military_path=STAGE/"expected-directed-relations-witness-military-001.json"
    guarantee_path=STAGE/"expected-directed-relations-witness-guarantee-001.json"
    refs={"network":load(network_path),"military":load(military_path),"guarantee":load(guarantee_path)}
    contract=load(STAGE/"relation-network-contract-003.json")
    date=refs["network"]["context"]["game_date"]
    context={"session_id":installation["session_id"],"game_date":date,"observer":"FRA"}
    for ref in refs.values():
        assert ref["status"]=="observed" and ref["raw_two_pass_consistent"] is True and ref["handle_closed"] is True
        assert ref["context"]["session_id"]==installation["session_id"] and ref["context"]["game_date"]==date
    source_pins=[]
    if not args.replay:
        snapshot=args.output/"source";snapshot.mkdir()
        for path in (Path(memory.__file__),memory.PROFILE_FILE,Path(__file__).resolve()):
            target=snapshot/path.name
            with path.open("rb") as source,target.open("xb") as destination:shutil.copyfileobj(source,destination)
            source_pins.append(dict(pin(path),snapshot=pin(target)))
    cases=(("FRA-network","FRA",None,["guarantee","military_access"],"network",None),
           ("SWE-TEU-military","SWE","TEU",["military_access"],"military","forward"),
           ("CYP-MAM-guarantee","CYP","MAM",["guarantee"],"guarantee","forward"),
           ("MAM-CYP-guarantee","MAM","CYP",["guarantee"],"guarantee","reverse"))
    checks={};observations=[];network_fields={}
    for name,actor,recipient,families,reference,direction in cases:
        path=args.output/(name+".json")
        report=load(path) if args.replay else memory.capture(args.installation,actor,recipient,families=families)
        if not args.replay:write(path,report)
        checks[name+"_validator"]=memory.validate_capture(report,context,installation["creation_filetime"],actor,recipient) is True
        checks[name+"_completed"]=report.get("completed") is True
        checks[name+"_no_game_calls_or_writes"]=(report.get("access",{}).get("native_game_calls") is False
                                                 and report.get("access",{}).get("target_memory_writes") is False)
        actual={};expected={}
        for family in families:
            field=report.get("fields",{}).get(family,{})
            checks[name+"_"+family+"_known"]=field.get("status")=="known"
            if recipient is None:
                values=field.get("value")
                actual[family]=[{"country":row["country"],"direction":row["direction"],"operand_direction":row["operand_direction"]}
                                for row in values] if isinstance(values,list) else None
                expected[family]=[{"country":row["country"],
                                   "direction":contract["families"][family]["direction_map"][row["direction"]],
                                   "operand_direction":row["direction"]} for row in refs[reference]["fields"][family]["value"]]
                network_fields[family]={"status":field.get("status"),"value":actual[family]}
            else:
                actual[family]=field.get("value") if type(field.get("value")) is bool else None
                expected[family]=any(row["direction"]==direction and row.get("active") is True
                                     for row in refs[reference]["fields"][family]["value"])
            checks[name+"_"+family+"_independent_match"]=actual[family]==expected[family]
        observations.append({"case":name,"actor":actor,"recipient":recipient,"public_actor":actor=="FRA",
                             "actual":actual,"expected":expected,"raw":pin(path),"errors":report.get("errors",[])})
        del report
    receipt={"schema":"information_directed_relations_production_comparison.v1",
             "status":"passed" if all(checks.values()) else "failed","checks":checks,
             "fields":network_fields,"observations":observations,"source_snapshots":source_pins,
             "references":[pin(path) for path in (network_path,military_path,guarantee_path)],
             "session_id":installation["session_id"],"game_date":date,"observer":"FRA",
             "read_only":True,"native_game_calls":False,"target_memory_writes":False,
             "save_restart_or_date_advance":False,"offline_replay":args.replay,
             "private_positive_witnesses_do_not_expand_public_scope":True}
    write(args.receipt,receipt)
    print(json.dumps(receipt,ensure_ascii=False))
    return 0 if receipt["status"]=="passed" else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run",action="store_true")
    parser.add_argument("--replay",action="store_true")
    parser.add_argument("--installation",type=Path,default=INSTALLATION)
    parser.add_argument("--output",type=Path,default=STAGE/"production-capture-001")
    parser.add_argument("--receipt",type=Path,default=STAGE/"production-comparison-001.json")
    args=parser.parse_args()
    if not args.run:parser.print_help();return 0
    return run(args)


if __name__=="__main__":raise SystemExit(main())
