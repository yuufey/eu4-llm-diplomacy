"""Freeze batch46 without modifying historical receipts or pins."""
from __future__ import annotations
import json
from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.archive_information_trade_income import sha, pin, tests
from work.archive_information_trade_details import RUNTIME_PATHS as PREVIOUS_RUNTIME_PATHS

STAGE = ROOT / "work/runtime/information-trade-source-details-20261027-001"
BASELINE = ROOT / "work/runtime/information-trade-share-20261027-001"
RUNTIME_PATHS = PREVIOUS_RUNTIME_PATHS + [
    "bridge/information/profiles/trade-details-memory-1374-v2.json",
    "bridge/information/profiles/trade-details-memory-1374-v3.json",
    "work/runtime/information-trade-source-details-20261027-001/trade-details-source-index-003.json",
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
          "files": [pin(ROOT / relative) for relative in RUNTIME_PATHS],
          "timing": "after final production freeze, before MCP acceptance and full regression",
          "continuous_monitoring_claimed": False})


def main():
    before = read(STAGE / "runtime-source-pins-before-001.json")
    after = [dict(pin(ROOT / item["path"]), matches_before=sha(ROOT / item["path"]) == item["sha256"]) for item in before["files"]]
    assert all(item["matches_before"] for item in after)
    live = read(STAGE / "live-acceptance-001/report.json")
    assert live["status"] == "passed" and live["server_exit_code"] == 0 and all(live["checks"].values())
    full, new_tests, old_occurrences, old_nodes = regression()
    assert not full["new_failure_nodes"] and new_tests["failure_error_occurrences"] == 0
    write("runtime-source-pins-after-001.json", {"schema": before["schema"], "files": after,
          "all_match_before": True, "timing": "after MCP exit and full regression", "continuous_monitoring_claimed": False})
    write("regression-added-cases-from-full-001.json", new_tests)
    write("regression-comparison-001.json", {"schema": "information_trade_source_details_regression_comparison.v1",
          "full": full, "baseline": pin(BASELINE / "regression-full-001.xml"),
          "baseline_occurrences": old_occurrences, "baseline_unique_nodes": old_nodes})
    paths = RUNTIME_PATHS + [
        "bridge/tests/test_information_trade_details_memory.py", "bridge/tests/test_information_trade_details.py",
        "bridge/tests/test_information_trade_source_details_memory.py",
        "work/create_information_trade_source_details_profile.py", "work/create_information_trade_source_details_profile_v3.py",
        "work/probe_information_trade_source_details.py", "work/probe_information_trade_source_details_v3.py",
        "work/reference_information_trade_source_details.py", "work/reference_information_trade_source_details_v3.py",
        "work/research_information_trade_capital_source.py", "work/research_information_trade_dynamic_sources.py",
        "work/research_information_trade_source_modifiers.py", "work/research_information_trade_source_modifiers_002.py",
        "work/validate_information_trade_source_details_live.py", "work/update_information_trade_source_details_coverage.py",
        "work/run_information_trade_source_details_regression.py",
        "work/verify_information_trade_source_details_artifacts.py",
        "work/document_information_trade_source_details.py", "work/archive_information_trade_source_details.py",
        "docs/贸易竞争力只读接口.md", "docs/信息字段覆盖.json", "docs/信息导出与订阅开发计划.md",
        "docs/信息导出开发进展.md", "docs/信息接口使用说明.md", "HANDOFF.md", "README(agent).md",
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
    profile = ROOT / "bridge/information/profiles/trade-details-memory-1374-v3.json"
    raw = read(STAGE / "native-trade-source-details-inputs-004.json")
    summary = {"schema": "information_development_summary.v1", "batch": 46,
               "status": "implemented_extended_trade_sources_live_verified", "objective": previous["objective"],
               "goal_complete": False, "scope": previous["scope"], "previous_goal_turn_classification": "progress",
               "delivered": {"topic": "T04", "field": "sources", "coverage": "partial", "complete": False,
                             "observer": "FRA", "object_type": "trade_node", "unit": "mixed",
                             "fixed_point_rows": ["TP_PROVINCE_POWER", "TP_SHIP_POWER", "TRADE_POWER_CAPITAL", "MERCHANT_DOWNSTREAM_BONUS"],
                             "dynamic": "bounded copied signed raw and name bytes; display lookup and value unit unknown; live chains empty",
                             "transfers": "own TO/FROM chains; signed32 fixed1000 trade_power; direction from container, raw sign preserved; country tag only after exact object fullref match",
                             "remaining": ["TRADE_MULTI_EXPLA", "dynamic name lookup and business unit", "competitor visibility", "cache refresh timing"],
                             "profile": pin(profile)},
               "runtime_validation": live, "coverage": read(STAGE / "coverage-update-001.json"),
               "tests": {"full": full, "new_cases": new_tests, "counts_not_additive": True,
                         "unchanged_debt_classification": pin(BASELINE / "existing-regression-triage-001.json")},
               "runtime_identity": previous["runtime_identity"],
               "current_identity_witnesses": [pin(STAGE / "native-trade-source-details-inputs-004.json"), pin(STAGE / "live-acceptance-001/after-control.json")],
               "independent_reference": pin(STAGE / "expected-trade-source-details-002.json"),
               "next_entry_evidence": pin(STAGE / "next-trade-entry-001.json"),
               "raw_capture": {"final_tail_capture": pin(STAGE / "native-trade-source-details-inputs-004.json"),
                               "access": raw.get("access"), "capital_dynamic_seed": pin(STAGE / "native-trade-source-details-inputs-002.json"),
                               "history": "001 null-head interpretation corrected into 002 by read-only reanalysis; tail 003 had wrong head indirection, 004 is a new bounded supplemental RPM capture, not a read-only repair; v2/expected001 preserved, v3/expected002 new filenames",
                               "inherited_metadata": "country-locator metadata is not a semantic guard for the new source fields"},
               "validation": {"business_actions_submitted": 0, "game_functions_called": False, "save_restart_DLL_date_changes": False,
                              "source_pins_before_after_match": True, "outbox": "delivered", "llm_read": "unknown", "new_REA_analysis": False},
               "ownership": {"commands": "terminal", "workers": "terminal", "subscriptions": "cancelled/no active subscription",
                             "MCP_servers": "exited0", "native_entry_RX_unwind_DLL": "retained until process exit", "battle_collection": "remains disabled"},
               "historical_integrity_incident": previous["historical_integrity_incident"],
               "next_work": {"trade": "T05 transfer and merchant-task semantics require separate native evidence; the T04 point containers do not prove T05 relation semantics. Competitor visibility and full multiplier chain remain incomplete. Do not sum partial rows into complete power.",
                             "budget": "Complete native current production/tax/expense collectors remain incomplete.",
                             "battle": "Full B04 title/Line1/buttons/layout/raw_text and other B01-B04 gaps remain.",
                             "full_scope": "All74topics397fields,phases2/3/4,LLM autonomous subscriptions and full B01-B04 remain active."},
               "source_snapshots": snapshots,
               "artifact_pins": [pin(p) for p in sorted(STAGE.rglob("*")) if p.is_file() and "source-snapshot" not in p.parts]}
    write("development-summary-001.json", summary)
    assert all(sha(ROOT / item["path"]) == item["sha256"] for item in summary["artifact_pins"])
    print(json.dumps({"summary": pin(STAGE / "development-summary-001.json"), "full": full,
                      "new_cases": new_tests["cases"], "artifacts": len(summary["artifact_pins"]), "snapshots": len(snapshots)}, ensure_ascii=False))


if __name__ == "__main__":
    if sys.argv[1:] == ["--pin-before"]:
        pin_before()
    else:
        assert not sys.argv[1:]
        main()
