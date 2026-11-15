"""Archive batch47 collection and conditional dynamic-name delivery."""
from __future__ import annotations
import json
from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.archive_information_trade_income import pin, sha, tests
from work.archive_information_trade_source_details import RUNTIME_PATHS as OLD_RUNTIME_PATHS

STAGE = ROOT / "work/runtime/information-trade-merchant-state-20261027-001"
BASELINE = ROOT / "work/runtime/information-trade-source-details-20261027-001"
RUNTIME_PATHS = OLD_RUNTIME_PATHS + [
    "bridge/information/native_localization.py", "bridge/information/localization_memory.py",
    "bridge/information/profiles/localization-memory-1374.json", "bridge/information/mission_texts.py",
    "bridge/native_text.py",
]


def read(path):
    return json.loads(path.read_bytes())


def write(name, value):
    with (STAGE / name).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def regression():
    cases, bad, occurrences = tests(STAGE / "regression-full-001.xml")
    old_cases, old_bad, old_occurrences = tests(BASELINE / "regression-full-001.xml")
    with (STAGE / "regression-full-001.log").open("rb") as stream:
        stream.seek(0, 2)
        stream.seek(max(0, stream.tell() - 8192))
        tail = stream.read().decode("utf-8", errors="replace")
    line = [line for line in tail.splitlines() if " passed" in line and " in " in line][-1]
    def count(label):
        match = re.search(r"(\d+) " + label + r"\b", line)
        return int(match.group(1)) if match else 0
    full = {"command": "python -m pytest -q bridge/tests", "exit_code": 1 if bad else 0,
            "passed": count("passed"), "failed": count("failed"), "errors": count("errors"),
            "subtests_passed": count("subtests passed"), "summary_line": line, "whole_suite_green": not bad,
            "failure_error_occurrences": occurrences, "unique_failure_error_nodes": len(bad),
            "new_failure_nodes": sorted(bad - old_bad), "resolved_failure_nodes": sorted(old_bad - bad),
            "xml": pin(STAGE / "regression-full-001.xml")}
    key = lambda case: f"{case.get('classname')}::{case.get('name')}"
    old_keys = {key(case) for case in old_cases}
    added = [case for case in cases if key(case) not in old_keys]
    new_tests = {"execution": "derived_from_full_XML_not_another_run", "cases": len(added),
                 "failure_error_occurrences": sum(len(c.findall("failure")) + len(c.findall("error")) for c in added),
                 "nodes": [key(c) for c in added]}
    return full, new_tests, old_occurrences, len(old_bad)


def pin_before():
    write("runtime-source-pins-before-001.json", {"schema": "information_runtime_source_pins.v1",
          "files": [pin(ROOT / relative) for relative in dict.fromkeys(RUNTIME_PATHS)],
          "timing": "after production freeze, before MCP and final full regression", "continuous_monitoring_claimed": False})


def main():
    before = read(STAGE / "runtime-source-pins-before-001.json")
    after = [dict(pin(ROOT / item["path"]), matches_before=sha(ROOT / item["path"]) == item["sha256"]) for item in before["files"]]
    assert all(item["matches_before"] for item in after)
    live = read(STAGE / "live-acceptance-001/report.json")
    assert live["status"] == "passed" and live["server_exit_code"] == 0 and all(live["checks"].values())
    full, added, old_occurrences, old_nodes = regression()
    assert not full["new_failure_nodes"] and added["failure_error_occurrences"] == 0
    write("runtime-source-pins-after-001.json", {"schema": before["schema"], "files": after,
          "all_match_before": True, "timing": "after MCP exit and full regression", "continuous_monitoring_claimed": False})
    write("regression-added-cases-from-full-001.json", added)
    write("regression-comparison-001.json", {"schema": "information_trade_collection_regression_comparison.v1",
          "full": full, "baseline": pin(BASELINE / "regression-full-001.xml"),
          "baseline_occurrences": old_occurrences, "baseline_unique_nodes": old_nodes})
    paths = RUNTIME_PATHS + [
        "bridge/tests/test_information_trade_details.py", "bridge/tests/test_information_trade_income.py",
        "bridge/tests/test_information_trade_collection.py", "work/research_information_trade_merchant_state.py",
        "work/research_information_trade_merchant_state_002.py", "work/research_information_trade_dynamic_lookup.py",
        "work/reference_information_trade_merchant_flags.py", "work/reference_information_trade_collection.py",
        "work/validate_information_trade_collection_live.py", "work/update_information_trade_collection_coverage.py",
        "work/run_information_trade_collection_regression.py", "work/document_information_trade_collection.py",
        "work/archive_information_trade_collection.py", "docs/贸易竞争力只读接口.md", "docs/贸易收入只读接口.md",
        "work/verify_information_trade_collection_documents.py",
        "docs/信息字段覆盖.json", "docs/信息导出与订阅开发计划.md", "docs/信息导出开发进展.md",
        "docs/信息接口使用说明.md", "HANDOFF.md", "README(agent).md",
    ]
    snapshots = []
    for relative in dict.fromkeys(paths):
        path = ROOT / relative
        original = pin(path)
        target = STAGE / "source-snapshot" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        assert not target.exists()
        shutil.copyfile(path, target)
        assert sha(target) == original["sha256"] == sha(path)
        snapshots.append(dict(original, snapshot=target.relative_to(ROOT).as_posix()))
    previous = read(BASELINE / "development-summary-001.json")
    summary = {"schema": "information_development_summary.v1", "batch": 47,
               "status": "implemented_collection_predicate_and_conditional_dynamic_name_lookup",
               "objective": previous["objective"], "goal_complete": False, "scope": previous["scope"],
               "previous_goal_turn_classification": "progress",
               "delivered": {"collection": {"topic": "T05", "field": "collection", "coverage": "partial", "complete": False,
                                             "observer": "FRA", "node_value": "boolean native aggregate collection predicate",
                                             "country_value": "native-order collecting node_id list", "basis": "native_trade_node_collection_predicate",
                                             "value_origin": "derived_from_copied_native_flags", "period": "current", "unit": "state",
                                             "does_not_prove": "merchant_task enum, independent merchant presence, transfer relation or steering direction"},
                             "dynamic_names": {"topic": "T04", "field": "sources", "coverage": "partial", "complete": False,
                                               "implementation": "strict printable ASCII/NUL keys, neutral NativeLocalizationReader, literal text only; templates/missing/errors stay unknown",
                                               "value_unit": "unknown", "live_dynamic_lists": "all empty in existing two-pass raw inputs",
                                               "positive_name_evidence": "bounded fake dynamic records with real child validators and real neutral localization reader capture seam; no live nonempty dynamic sample claimed",
                                               "atomic_with_source_quantities": False}},
               "runtime_validation": live, "coverage": read(STAGE / "coverage-update-001.json"),
               "tests": {"full": full, "new_cases": added, "counts_not_additive": True,
                         "unchanged_debt_classification": pin(ROOT / "work/runtime/information-trade-share-20261027-001/existing-regression-triage-001.json")},
               "runtime_identity": previous["runtime_identity"],
               "current_identity_witness": pin(STAGE / "live-acceptance-001/after-control.json"),
               "independent_reference": pin(STAGE / "expected-trade-collection-001.json"),
               "reference_method": "independent reanalysis of existing matching-session/date raw bytes; no fresh raw RPM sampling or production-reader import",
               "source_evidence": [pin(STAGE / name) for name in ("merchant-state-source-001.json", "merchant-state-source-002.json",
                                    "dynamic-lookup-source-001.json", "dynamic-lookup-reuse-001.json", "native-flag-inputs-from-archived-raw-001.json")],
               "validation": {"business_actions_submitted": 0, "game_functions_called": False, "save_restart_DLL_date_changes": False,
                              "source_pins_before_after_match": True, "outbox": "delivered", "llm_read": "unknown", "new_REA_analysis": False},
               "ownership": {"commands": "terminal", "workers": "terminal", "subscriptions": "cancelled/no active subscription",
                             "MCP_servers": "exited0", "native_entry_RX_unwind_DLL": "retained until process exit", "battle_collection": "remains disabled"},
               "historical_integrity_incident": previous["historical_integrity_incident"],
               "next_work": {"trade": "Merchant presence/task and steering/transfer relations require additional caller semantics; collection=false is not merchant absence or transfer. Dynamic numeric business unit, full multiplier and foreign visibility remain incomplete.",
                             "budget": "Complete native current production/tax/expense collectors remain incomplete.",
                             "battle": "Full B04 title/Line1/buttons/layout/raw_text and other B01-B04 gaps remain.",
                             "full_scope": "All74topics397fields,phases2/3/4,LLM autonomous subscriptions and full B01-B04 remain active."},
               "source_snapshots": snapshots,
               "artifact_pins": [pin(p) for p in sorted(STAGE.rglob("*")) if p.is_file() and "source-snapshot" not in p.parts]}
    write("development-summary-001.json", summary)
    assert all(sha(ROOT / item["path"]) == item["sha256"] for item in summary["artifact_pins"])
    print(json.dumps({"summary": pin(STAGE / "development-summary-001.json"), "full": full,
                      "new_cases": added["cases"], "artifacts": len(summary["artifact_pins"]), "snapshots": len(snapshots)}, ensure_ascii=False))


if __name__ == "__main__":
    if sys.argv[1:] == ["--pin-before"]:
        pin_before()
    else:
        assert not sys.argv[1:]
        main()
