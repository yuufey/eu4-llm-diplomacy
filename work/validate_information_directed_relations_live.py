"""Accept the six-family country network with one periodic delivery.

Explicit --run only.  References are independent raw-byte projections.  The
existing selected-pair nine-family contract is checked without changing its
ten-row shape.  --resume-query validates an original stored query offline.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
from typing import Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work import validate_information_relation_remaining_live as previous

STAGE = ROOT / "work/runtime/information-relation-network-remaining-20261027-001"
DIRECTED = ("guarantee", "military_access")
NETWORK = (*previous.NETWORK_FAMILIES, *DIRECTED)
FIELDS = previous.FIELDS
write = previous.write
load = previous._read_json
sha = previous._sha


def prepare(installation: Path):
    binding = load(installation, max_bytes=1024*1024)
    legacy = load(previous.DEFAULT_NETWORK_EXPECTED)
    trade = load(previous.DEFAULT_TRADE_EXPECTED)
    fleet = load(previous.DEFAULT_FLEET_EXPECTED)
    directed_path = STAGE / "expected-directed-relations-projection-001.json"
    directed = load(directed_path, max_bytes=4*1024*1024)
    contract = load(STAGE / "relation-network-contract-003.json")
    session, date, _, _ = previous._reference_identity(legacy)
    old, trade_members, fleet_members = previous._check_reference_set(legacy, trade, fleet, binding, date)
    assert directed.get("status") == "observed"
    previous._assert_reference_identity(directed, binding, "directed_network", date)
    assert directed.get("raw_two_pass_consistent") is True
    assert directed.get("handle_closed") is True
    raw_pin = directed["source_raw"]
    assert sha(Path(raw_pin["path"])) == raw_pin["sha256"]
    expected = {(family, None): members for family, members in old.items()}
    expected[("trade_league", None)] = trade_members
    expected.update({("fleet_basing", direction): members for direction, members in fleet_members.items()})
    for family in DIRECTED:
        field = directed["fields"][family]
        assert field["status"] == "known" and field.get("unknown_row_count", 0) == 0
        directions = contract["families"][family]["direction_map"]
        for direction in ("received", "granted"):
            expected[(family, direction)] = set()
        for row in field["value"]:
            assert row.get("active") is True and row["direction"] in directions
            direction = directions[row["direction"]]
            members = expected[(family, direction)]
            assert row["country"] not in members
            members.add(row["country"])
    return binding, session, date, expected, old, trade_members, fleet_members, directed_path


def check_network(item, expected):
    for name in FIELDS:
        field = item["fields"][name]
        assert field["status"] == "known"
        actual = {key: set() for key in expected}
        for row in field["value"]:
            family = row["relation_type"]
            direction = row.get("direction")
            key = (family, direction)
            assert key in expected, (name, key)
            partner = row["partner"]
            assert partner not in actual[key] and row.get("actor") == "FRA"
            actual[key].add(partner)
            if name in ("relation_type", "status"):
                assert row["status"] == "known"
                assert row["value"] == (family if name == "relation_type" else "active")
            elif direction is not None:
                assert row["status"] == "known"
                wanted = ((partner if direction == "received" else "FRA") if name == "grantor"
                          else ("FRA" if direction == "received" else partner))
                assert row["value"] == wanted
            else:
                assert row["status"] == "not_applicable"
        assert actual == expected, (name, actual, expected)
    calls = previous._network_container_calls(item)
    summaries = {}
    for call in calls:
        assert call.get("native_function_invoked") is False
        for family, summary in call["families"].items():
            assert family in NETWORK and family not in summaries
            summaries[family] = summary
    assert set(summaries) == set(NETWORK)
    for family, summary in summaries.items():
        assert summary["status"] == "known", (family, summary)
        assert summary["active_partner_count"] == sum(len(members) for (kind, _), members in expected.items() if kind == family)
    assert item["source"]["context_scope"] == "country_relation_network"


def check_result(result, prepared):
    binding, session, date, expected, legacy, trade, fleet, _ = prepared
    assert result["delivery"]["status"] == "delivered"
    assert (result["context"]["session_id"], result["context"]["game_date"]) == (session, date)
    items = result["items"]
    assert len(items) == 3 and result["complete"] is False
    check_network(items[0], expected)
    previous._check_pair_default_sav(items[1], trade, fleet, legacy)
    previous._check_orl_vassal(items[2])
    pair = previous._rows_for_field(items[1], "status")
    # The legacy guarantee validity accepts an association in either
    # direction. Its pair boolean does not identify a single guarantor.
    # Military access retains the requester's explicit received-access leaf.
    for family, directions in (("guarantee", ("granted", "received")),
                               ("military_access", ("received",))):
        wanted = "active" if any("SAV" in expected[(family, direction)] for direction in directions) else "inactive"
        assert pair[(family, None)]["value"] == wanted


def run(installation, output, resume_query=None):
    prepared = prepare(installation)
    binding, session, date, expected, *_ = prepared
    saved_query = load(resume_query) if resume_query is not None else None
    if saved_query is not None:
        check_result(saved_query, prepared)
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema":"information_directed_relations_live_acceptance.v1", "status":"running",
              "session_id":session,"game_date":date,"observer":"FRA","read_only":True,
              "checks":{},"periodic_results":0,"subscriptions_created":0,
              "business_actions_submitted":0,"new_relation_memory_native_functions_called":False,
              "game_functions_called":False,"game_function_scope":"existing read-only selected-pair inspections",
              "save_restart_or_date_advance":False,"outbox":"unverified","llm_read":"unknown",
              "original_query_reused_offline":resume_query is not None,
              "original_query":{"path":str(resume_query),"sha256":sha(resume_query)} if resume_query else None,
              "references":{str(path.relative_to(ROOT)):sha(path) for path in (
                  previous.DEFAULT_NETWORK_EXPECTED, previous.DEFAULT_TRADE_EXPECTED,
                  previous.DEFAULT_FLEET_EXPECTED, prepared[-1])}}
    queries = [{"topic":"R01","object":{"type":"country","country":"FRA"},
                "fields":list(FIELDS),"parameters":{}},
               previous.query_pair("SAV"), previous.query_pair("ORL",FIELDS,("vassalization",))]
    request_prefix = "directed-network-" + output.name
    before=client=subscription=None
    try:
        before=previous.control_snapshot(int(binding["pid"]),output/"before-control.json")
        assert (before["player_slot"],before["paused_flag"],before["speed"],before["date_raw"])==(189,1,0,date)
        client=previous.CheckedClient(installation,output,extra_args=["--static-game-data"])
        discovery=client.call("information_discover")
        write(output/"discovery.json",discovery)
        topic=next(item for item in discovery["topics"] if item["topic_id"]=="R01")
        assert topic["status"]=="available"
        assert topic["relation_types_by_object"]["country"]==list(NETWORK)
        assert len(topic["relation_types_by_object"]["country_pair"])==9
        assert all(topic["fields"][name]["coverage"]=="partial" for name in FIELDS)
        assert topic["fields"]["expires_at"]["coverage"]=="planned"
        report["checks"]["six_network_families_nine_pair_families_partial_expiry_planned"]=True
        query_result=saved_query if saved_query is not None else client.call(
            "information_query",request_id=request_prefix+"-query",queries=queries)
        write(output/"query.json",query_result)
        check_result(query_result,prepared)
        report["game_functions_called"] = resume_query is None
        report["checks"]["six_networks_pair_contract_and_roles_match_references"]=True
        saved=client.call("information_manage_report",request_id=request_prefix+"-report",operation="create",
                          config={"name":"FRA六类当前关系网","queries":queries,"detail":"raw"})
        write(output/"report-config.json",saved)
        report_id=saved["report"]["id"]
        result=client.call("information_query",request_id=request_prefix+"-report-query",report_id=report_id)
        write(output/"report-query.json",result)
        check_result(result,prepared)
        report["game_functions_called"] = True
        report["checks"]["saved_report_matches_same_references"]=True
        created=client.call("information_manage_subscription",request_id=request_prefix+"-subscribe",operation="create",
                            config={"name":"directed-network-one-period","kind":"periodic","report_id":report_id,
                                    "enabled":True,"schedule":{"basis":"real","every":5,"unit":"seconds","missed":"coalesce"}})
        subscription=created["subscription"]
        report["subscriptions_created"]=1
        write(output/"subscription-config.json",created)
        deadline=time.monotonic()+45
        periodic=[]
        while not periodic and time.monotonic()<deadline:
            listed=client.call("information_list_results",limit=50)
            periodic=[value for value in listed.get("results",[]) if value.get("subscription_id")==subscription["id"]]
            assert len(periodic)<=1
            if not periodic:time.sleep(0.2)
        assert len(periodic)==1
        write(output/"periodic-results.json",periodic)
        check_result(periodic[0],prepared)
        report["periodic_results"]=1
        cancelled=client.call("information_manage_subscription",request_id=request_prefix+"-cancel",operation="cancel",
                              subscription_id=subscription["id"],expected_version=subscription["version"])
        subscription=cancelled["subscription"]
        write(output/"cancelled-subscription.json",cancelled)
        listed=client.call("information_manage_subscription",request_id=request_prefix+"-list",operation="list")
        write(output/"subscriptions-after.json",listed)
        assert subscription["state"]=="cancelled" and all(value["state"]=="cancelled" for value in listed["subscriptions"])
        report["checks"]["one_five_second_periodic_cancelled_no_active"]=True
        report.update(status="passed",outbox="delivered")
    except Exception as exc:
        report.update(status="failed",error={"type":type(exc).__name__,"message":str(exc)})
    finally:
        if client is not None:
            try:
                if subscription is not None and subscription.get("state")!="cancelled":
                    client.call("information_manage_subscription",request_id=request_prefix+"-cleanup",operation="cancel",
                                subscription_id=subscription["id"],expected_version=subscription["version"])
                client.close()
            except Exception as exc:
                report.update(status="failed",cleanup_error={"type":type(exc).__name__,"message":str(exc)})
            report["server_exit_code"]=client.process.returncode
            report["checks"]["server_exit_zero"]=client.process.returncode==0
            if client.process.returncode!=0:report["status"]="failed"
        if before is not None:
            after=previous.control_snapshot(int(binding["pid"]),output/"after-control.json")
            same=all(before[key]==after[key] for key in ("date_raw","paused_flag","speed","player_slot"))
            report["checks"]["date_pause_player_preserved"]=same
            if not same:report["status"]="failed"
        write(output/"report.json",report)
    print(json.dumps(report,ensure_ascii=False))
    return 0 if report["status"]=="passed" else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run",action="store_true")
    parser.add_argument("--installation",type=Path,default=previous.DEFAULT_INSTALLATION)
    parser.add_argument("--output",type=Path,default=STAGE/"live-acceptance-001")
    parser.add_argument("--resume-query",type=Path)
    args=parser.parse_args()
    if not args.run:
        parser.print_help();return 0
    return run(args.installation,args.output,args.resume_query)


if __name__=="__main__":
    raise SystemExit(main())
