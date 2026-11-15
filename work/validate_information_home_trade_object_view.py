"""Verify only the default-object-view correction after initial acceptance."""
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.run_alliance_inbound_response import control_snapshot
from work.validate_information_live import Client


def write(path,value):
    with path.open("x",encoding="utf-8",newline="\n") as stream:
        json.dump(value,stream,ensure_ascii=False,indent=2)
        stream.write("\n")


def run(installation,reference,output):
    output.mkdir(parents=True,exist_ok=False)
    expected=json.loads(reference.read_bytes())
    binding=json.loads(installation.read_text(encoding="utf-8-sig"))
    assert binding["session_id"]==expected["session_id"]
    before=control_snapshot(int(binding["pid"]),output/"before-control.json")
    assert (before["date_raw"],before["paused_flag"],before["speed"],before["player_slot"])==(expected["game_date"],1,0,189)
    report={"schema":"information_home_trade_object_view_acceptance.v1","status":"running","session_id":binding["session_id"],
            "game_date":expected["game_date"],"checks":{},"original_query_report_periodic_and_rejection_repeated":False}
    client=None
    try:
        client=Client(installation.resolve(),output,extra_args=["--static-game-data"])
        value=client.call("information_query",request_id="home-default-object-view-001",queries=[
            {"topic":"T02","object":{"type":"trade_node","node_id":expected["home_node"]}},
            {"topic":"T02","object":{"type":"country","country":"FRA"},"fields":["home_node"]}])
        write(output/"default-object-view-query.json",value)
        first,second=value["items"]
        assert all(first["fields"][field]["status"]=="known" for field in ("upstream","routes"))
        assert first["fields"]["home_node"]["status"]=="not_applicable"
        assert first["fields"]["home_node"]["reason"]=="OBJECT_TYPE_NOT_SUPPORTED_BY_ADAPTER"
        assert second["fields"]["home_node"]["status"]=="known" and second["fields"]["home_node"]["value"]==expected["home_node"]
        assert value["context"]["session_id"]==expected["session_id"] and value["context"]["game_date"]==expected["game_date"]
        report["checks"]["default_static_node_view_preserved"]=True
        report["checks"]["country_home_view_remains_known"]=True
        report["status"]="passed"
    except Exception as exc:
        report.update(status="failed",error={"type":type(exc).__name__,"message":str(exc)})
    finally:
        if client is not None:
            try:
                client.close()
            except Exception as exc:
                report.update(status="failed",cleanup_error={"type":type(exc).__name__,"message":str(exc)})
            report["server_exit_code"]=client.process.returncode
        after=control_snapshot(int(binding["pid"]),output/"after-control.json")
        report["checks"]["date_pause_player_preserved"]=all(before[key]==after[key] for key in ("date_raw","paused_flag","speed","player_slot"))
        if not report["checks"]["date_pause_player_preserved"]:
            report["status"]="failed"
        write(output/"report.json",report)
    print(json.dumps(report,ensure_ascii=False))
    return 0 if report["status"]=="passed" else 1


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation",type=Path,required=True)
    parser.add_argument("--reference",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    raise SystemExit(run(args.installation,args.reference,args.output))
