"""Archive batch43 after one complete regression and the preserved MCP recovery."""
from __future__ import annotations
import json
from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.archive_information_trade_income import sha, pin, tests

STAGE = ROOT/"work/runtime/information-trade-state-20261027-001"
BASELINE = ROOT/"work/runtime/information-budget-collectors-20261027-001"


def read(path):
    return json.loads(path.read_bytes())


def write(name,value):
    with (STAGE/name).open("x",encoding="utf-8",newline="\n") as stream:
        json.dump(value,stream,ensure_ascii=False,indent=2)
        stream.write("\n")


def main():
    before = read(STAGE/"runtime-source-pins-before-002.json")
    after = [dict(pin(ROOT/item["path"]),matches_before=sha(ROOT/item["path"])==item["sha256"]) for item in before["files"]]
    assert all(item["matches_before"] for item in after)
    write("runtime-source-pins-after-002.json",{"schema":before["schema"],"files":after,"all_match_before":True,
          "timing":"after all MCP servers exit and full suite","continuous_monitoring_claimed":False})
    cases,bad,occurrences = tests(STAGE/"regression-full-002.xml")
    old_cases,old_bad,old_occurrences = tests(BASELINE/"regression-full-001.xml")
    with (STAGE/"regression-full-002.log").open("rb") as stream:
        stream.seek(0,2)
        stream.seek(max(0,stream.tell()-8192))
        tail=stream.read().decode("utf-8",errors="replace")
    line=[line for line in tail.splitlines() if " passed" in line and " in " in line][-1]
    def count(label):
        match=re.search(r"(\d+) "+label+r"\b",line)
        return int(match.group(1)) if match else 0
    full={"command":"python -m pytest -q bridge/tests","exit_code":1 if bad else 0,
          "passed":count("passed"),"failed":count("failed"),"errors":count("errors"),"subtests_passed":count("subtests passed"),
          "summary_line":line,"whole_suite_green":not bad,"failure_error_occurrences":occurrences,"unique_failure_error_nodes":len(bad),
          "new_failure_nodes":sorted(bad-old_bad),"resolved_failure_nodes":sorted(old_bad-bad),"xml":pin(STAGE/"regression-full-002.xml")}
    key=lambda case:f"{case.get('classname')}::{case.get('name')}"
    old_keys={key(case) for case in old_cases}
    added=[case for case in cases if key(case) not in old_keys]
    new_tests={"execution":"derived_from_full_XML_not_another_run","cases":len(added),
               "failure_error_occurrences":sum(len(c.findall("failure"))+len(c.findall("error")) for c in added),"nodes":[key(c) for c in added]}
    write("regression-added-cases-from-full-001.json",new_tests)
    write("regression-comparison-001.json",{"schema":"information_home_trade_regression_comparison.v1","full":full,
          "baseline":pin(BASELINE/"regression-full-001.xml"),"baseline_occurrences":old_occurrences,"baseline_unique_nodes":len(old_bad)})
    relative_paths=[item["path"] for item in before["files"]]+[
        "bridge/tests/test_information_home_trade_node_memory.py","bridge/tests/test_information_trade_home.py","bridge/tests/test_information_composite.py",
        "work/create_information_home_trade_profile.py","work/reference_information_home_trade_node.py","work/validate_information_home_trade_live.py",
        "work/update_information_home_trade_coverage.py","work/document_information_home_trade_node.py","work/archive_information_home_trade_node.py",
        "work/validate_information_home_trade_object_view.py","work/probe_information_trade_power.py",
        "work/research_information_trade_state.py","work/research_information_home_node.py","work/research_information_trade_state_production_amount.py",
        "docs/本埠贸易节点接口.md","docs/信息服务合同.md","docs/信息字段覆盖.json","docs/信息导出与订阅开发计划.md",
        "docs/信息导出开发进展.md","docs/信息接口使用说明.md","HANDOFF.md","README(agent).md"]
    snapshots=[]
    for relative in dict.fromkeys(relative_paths):
        path=ROOT/relative
        original=pin(path)
        target=STAGE/"source-snapshot"/relative
        target.parent.mkdir(parents=True,exist_ok=True)
        assert not target.exists()
        shutil.copyfile(path,target)
        assert sha(target)==original["sha256"]==sha(path)
        snapshots.append(dict(original,snapshot=target.relative_to(ROOT).as_posix()))
    live=read(STAGE/"live-acceptance-001/report-004.json")
    assert live["status"]=="passed" and live["server_exit_code"]==0
    previous=read(BASELINE/"development-summary-001.json")
    power_inputs=read(STAGE/"native-trade-power-inputs-002.json")
    assert power_inputs["status"]=="observed" and power_inputs["completed"] is True
    assert power_inputs["doublepass"]["consistent"] is True
    assert power_inputs["access_summary"]["true_node_count"]==[80,80]
    assert power_inputs["cleanup"]["handle_close"]["status"]=="closed"
    summary={"schema":"information_development_summary.v1","batch":43,"status":"implemented_home_node_and_field_routing_live_verified",
             "objective":previous["objective"],"goal_complete":False,"scope":previous["scope"],"previous_goal_turn_classification":"progress",
             "delivered":{"topic":"T02","field":"home_node","value":live["home_node"],"country":"FRA","coverage":"partial","complete":False,
                          "basis":"native_trade_node_home_flag","value_origin":"derived_from_copied_native_flags","profile":pin(ROOT/"bridge/information/profiles/home-trade-node-memory-1374.json"),
                          "default_capture_and_existing_income_profile_preserved":True},
             "composition":{"disjoint_fields_same_topic":True,"overlapping_field_owners_rejected":True,
                            "field_owner_specific_validation_scope_versions_triggers":True,"per_field_sources_and_static_success_preserved":True,
                            "primary_event_polling_not_duplicated":True},
             "runtime_validation":live,"object_view_validation":read(STAGE/"live-object-view-001/report-002.json"),
             "source_revision":read(STAGE/"source-revision-001.json"),
             "coverage":read(STAGE/"coverage-update-001.json"),"tests":{"full":full,"new_cases":new_tests,"counts_not_additive":True,
                 "pre_object_view_fix_full":pin(STAGE/"regression-full-001.xml")},
             "runtime_identity":previous["runtime_identity"],
             "current_identity_witnesses":[pin(STAGE/"native-trade-state-inputs-001.json"),pin(STAGE/"live-object-view-001/after-control.json")],
             "validator_recovery":{"original_report":pin(STAGE/"live-acceptance-001/report.json"),
                                   "intermediate_reports":[pin(STAGE/f"live-acceptance-001/report-{n:03d}.json") for n in (2,3)],
                                   "final":pin(STAGE/"live-acceptance-001/report-004.json"),
                                   "cause":"Validator omitted required detail,enabled,missed keys; production home/static/income and three periodic deliveries had already passed.",
                                   "resolution":"Copy the original successful subscription config and locally validate the full MCP schema, then finish only the pending rejection check.",
                                   "original_queries_reports_periodic_rerun":False},
             "validation":{"new_REA_analysis":False,"REA_session_inventory_only":True,"business_actions_submitted":0,
                           "game_functions_called":False,"save_restart_DLL_date_changes":False,"source_pins_before_after_match":True,
                           "outbox":"delivered","llm_read":"unknown"},
             "ownership":{"commands":"terminal","workers":"terminal","subscriptions":"cancelled/no active subscription",
                          "MCP_servers":"all five exited0","native_entry_RX_unwind_DLL":"retained until process exit","battle_collection":"remains disabled"},
             "historical_integrity_incident":previous["historical_integrity_incident"],
             "next_work":{"trade_power":"trade-power-source-002 closes current_power formula and total_power copy. Independent raw002 now captures all80 nodes twice, including runtime+C8 and entry44/48/4C/50/54. Create the independent formula reference/profile and implement T04 without waiting for shares/sources.",
                          "trade_power_inputs":{"successful":pin(STAGE/"native-trade-power-inputs-002.json"),
                                                "failed_first_attempt":pin(STAGE/"native-trade-power-inputs-001.json"),
                                                "access":power_inputs["access_summary"],"example":power_inputs["champagne_example"],
                                                "inherited_metadata":"The reused probe retains domestic-pressure/stability header and profile metadata. Trade-power raw inputs are identified by schema, field, capture_contract and trade_power_inputs; that inherited header is not a trade-power source guard or public field result.",
                                                "interpretation":"raw only; formula and GUI equivalence not calculated by this probe"},
                          "merchant_tasks":"AC/AE assignment semantics remain unproved. Do not publish guessed tasks/collection/transfer from raw flags.",
                          "current_budget":"production-amount-contract-001 closes more ABI, not unit/TLS or an RPM cache. Continue true production/tax/expense sources.",
                          "full_scope":"All74topics397fields,phases2/3/4,LLM autonomous subscriptions and full B01-B04 remain active."},
             "source_snapshots":snapshots,
             "artifact_pins":[pin(p) for p in sorted(STAGE.rglob("*")) if p.is_file() and "source-snapshot" not in p.parts]}
    write("development-summary-001.json",summary)
    assert all(sha(ROOT/item["path"])==item["sha256"] for item in summary["artifact_pins"])
    print(json.dumps({"summary":pin(STAGE/"development-summary-001.json"),"full":full,"new_cases":len(added),
                      "artifacts":len(summary["artifact_pins"]),"snapshots":len(snapshots)},ensure_ascii=False))


if __name__=="__main__":
    main()
