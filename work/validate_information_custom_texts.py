"""Verify bounded custom-text derivation through real read-only MCP queries.

Independent raw captures retain actual membership, compiled method records,
and selected cache bytes. Only information tools manage the local test
subscription; no game function, action, injection, save or date advance occurs.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from bridge.information import mission_memory as mm, localization_memory as lm
from bridge.information import custom_localization_memory as cm
from bridge.information.mission_texts import decode_template
from work.run_alliance_inbound_response import control_snapshot
from work.validate_information_live import Client

TEMPLATES={"[Root.GetSelectableMissionTitle]":"GetSelectableMissionTitle",
           "[Root.GetSelectableMissionDescription]":"GetSelectableMissionDescription"}


def write(path,value):
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_capture(report,installation,raw_date):
    assert report["status"]=="observed" and report["read_only"] is True
    assert report["identity"]["installation_session_id"]==installation["session_id"]
    assert report["identity"]["process_path_sha256"]==installation["game_sha256"]
    assert report["doublepass"]["consistent"] is True
    assert report["cleanup"]["handle_close"]["closed"] is True
    assert report["before"]["game_date"]["raw"]==report["after"]["game_date"]["raw"]==raw_date


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=False)
    installation=json.loads(args.installation.read_text(encoding="utf-8"))
    report={"status":"failed","checks":{},"read_only":True,"native_function_invoked":False,
            "root_binding":"explicit_query_observer_country","ui_root_scope_verified":False}
    client=None
    try:
        before=control_snapshot(installation["pid"],args.output/"before-control.json")
        assert (before["player_slot"],before["paused_flag"],before["date_raw"])==(189,1,56553384)
        tasks=mm.capture(args.installation,"FRA",include_completed=True,include_tasks=True)
        write(args.output/"loaded-tasks.json",tasks)
        verify_capture(tasks,installation,before["date_raw"])
        assert tasks["doublepass"]["task_consistent"] and tasks["loaded_tasks"]["status"]=="observed"
        members=[{"root_id":root["root_id"],"task_id":task,"branch_visibility":"unknown"}
                 for root in tasks["loaded_tasks"]["roots"] for task in root["task_ids"]]
        keys=list(dict.fromkeys(item["task_id"]+suffix for suffix in ("_title","_desc") for item in members))
        cache=lm.capture(args.installation,"FRA",keys)
        write(args.output/"native-cache.json",cache)
        verify_capture(cache,installation,before["date_raw"])
        methods=cm.capture(args.installation,"FRA",list(TEMPLATES.values()))
        write(args.output/"custom-methods.json",methods)
        verify_capture(methods,installation,before["date_raw"])
        selected_keys=[]
        method_keys={}
        for name in TEMPLATES.values():
            method=methods["methods"][name]; proof=method["selection"]
            assert method["status"]=="observed" and method["text_key"]["status"]=="observed"
            assert proof["option_count"]==1 and proof["predicate_count"]==0
            assert type(proof["weight"]) is int and 0<proof["weight"]<0x80000000
            assert proof["modifiers_empty"] is True and proof["builtin_name_absent"] is True
            assert proof["root_promotion_enum"]==3 and proof["ui_root_scope_verified"] is False
            method_keys[name]=method["text_key"]["text"]
            selected_keys.append(method_keys[name])
        selected=lm.capture(args.installation,"FRA",list(dict.fromkeys(selected_keys)))
        write(args.output/"selected-keys-cache.json",selected)
        verify_capture(selected,installation,before["date_raw"])
        assert selected["language"]["text"]==cache["language"]["text"]
        codec=installation["native_text_codec"]
        expected={}
        derived=0
        for key,entry in cache["entries"].items():
            assert entry["status"]=="observed"
            value=decode_template(entry["value_hex"],codec)
            template=value.get("template", "")
            token=next((token for token in TEMPLATES if template.count(token)==1
                        and not any(marker in template.replace(token,"",1) for marker in "[]$")),None)
            method_name=TEMPLATES.get(token)
            if method_name:
                text_key=method_keys[method_name]
                chosen=decode_template(selected["entries"][text_key]["value_hex"],codec)
                assert chosen["status"]=="known"
                value={"status":"known","text":template.replace(token,chosen["text"],1),"expected_custom_method":method_name}
                derived+=1
            expected[key]=value
        assert len(members)==61 and derived==14
        assert sum(entry["status"]=="known" for entry in expected.values())==116
        write(args.output/"expected-texts.json",expected)
        client=Client(args.installation,args.output,extra_args=["--mission-game-data"],tick=0.5)
        query={"topic":"M01","object":{"type":"country","country":"FRA"},"fields":["task_id","name","description"]}
        manual=client.call("information_query",request_id="custom-texts-manual",queries=[query])
        write(args.output/"manual-result.json",manual)
        assert manual["complete"] is False and manual["status"]=="partial"

        def check_item(item):
            assert item["fields"]["task_id"]["value"]==members
            for field,suffix in (("name","_title"),("description","_desc")):
                value=item["fields"][field]["value"]
                assert len(value["entries"])==61
                expected_known=sum(expected[member["task_id"]+suffix]["status"]=="known" for member in members)
                assert (value["resolved_count"],value["unresolved_count"])==(expected_known,len(members)-expected_known)
                assert item["fields"][field]["complete"] is (expected_known==len(members))
                for member,entry in zip(members,value["entries"]):
                    assert (entry["root_id"],entry["task_id"])==(member["root_id"],member["task_id"])
                    wanted=expected[member["task_id"]+suffix]
                    assert entry["status"]==wanted["status"]
                    if wanted["status"]=="known":
                        assert entry["text"]==wanted["text"]
                    else:
                        assert "text" not in entry and entry["template"]==wanted["template"]
                    if "expected_custom_method" in wanted:
                        derivation=entry["custom_text_derivation"]
                        assert derivation["method"]==wanted["expected_custom_method"]
                        assert derivation["ui_root_scope_verified"] is False
            custom=item["source"]["provenance"]["localization"]["custom_text_resolution"]
            assert custom["derived_count"]==14 and custom["native_function_invoked"] is False

        check_item(manual["items"][0])
        report["checks"]["active_matches_independent_compiled_methods_and_cache"] = True
        one=client.call("information_query",request_id="custom-texts-selected",queries=[dict(query,parameters={"task_id":"fra_branch_mission_1_5"})])
        write(args.output/"selected-result.json",one)
        assert one["complete"] is True
        assert one["items"][0]["fields"]["name"]["value"]["entries"][0]["text"]=="分支任务"
        assert one["items"][0]["fields"]["description"]["value"]["custom_derived_count"]==1
        report["checks"]["selected_placeholder_derived_without_engine_call"] = True
        saved=client.call("information_manage_report",request_id="custom-texts-report",operation="create",
                          config={"name":"custom-mission-texts","queries":[query],"detail":"raw"})["report"]
        subscription=client.call("information_manage_subscription",request_id="custom-texts-periodic",operation="create",
            config={"name":"custom-texts-two-seconds","kind":"periodic","report_id":saved["id"],"enabled":True,
                    "schedule":{"basis":"real","every":2,"unit":"seconds","missed":"coalesce"}})["subscription"]
        deadline=time.monotonic()+7
        while time.monotonic()<deadline:time.sleep(0.25)
        generated=[entry for entry in client.call("information_list_results",limit=50)["results"]
                   if entry.get("subscription_id")==subscription["id"]]
        write(args.output/"periodic-results.json",generated)
        assert len(generated)>=2
        for result in generated:
            assert result["complete"] is False and result["delivery"]["status"]=="delivered"
            check_item(result["items"][0])
        client.call("information_manage_subscription",request_id="custom-texts-cancel",operation="cancel",
                    subscription_id=subscription["id"],expected_version=subscription["version"])
        report["checks"]["periodic_derived_and_unknown_values_delivered"] = True
        client.close();client=None
        after=control_snapshot(installation["pid"],args.output/"after-control.json")
        assert (after["player_slot"],after["paused_flag"],after["date_raw"])==(189,1,before["date_raw"])
        report["checks"]["pause_player_date_preserved"] = True
        report.update(status="passed",task_count=len(members),key_count=len(keys),derived_count=derived,
            known_count=116,unresolved_count=6,periodic_results=len(generated),session_id=installation["session_id"],
            custom_capture_sha256=digest(args.output/"custom-methods.json"),
            native_cache_sha256=digest(args.output/"native-cache.json"))
    except Exception as exc:
        report["error"]={"type":type(exc).__name__,"message":str(exc)}
        raise
    finally:
        if client is not None:client.close()
        write(args.output/"report.json",report)
    print(json.dumps(report))


if __name__=="__main__":main()
