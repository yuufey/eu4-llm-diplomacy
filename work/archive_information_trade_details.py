"""Freeze batch45 source, raw-reference, MCP and regression evidence."""
from __future__ import annotations
import json
from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.archive_information_trade_income import sha, pin, tests

STAGE = ROOT / "work/runtime/information-trade-share-20261027-001"
BASELINE = ROOT / "work/runtime/information-trade-power-20261027-001"
RUNTIME_PATHS = [
    "bridge/information/country_resources_memory.py", "bridge/information/trade_details_memory.py",
    "bridge/information/trade_details.py", "bridge/information/profiles/trade-details-memory-1374.json",
    "bridge/information/trade_income_memory.py", "bridge/information/profiles/trade-income-memory-1374.json",
    "bridge/information/trade_income.py", "bridge/information/trade_power.py", "bridge/information/trade_power_memory.py",
    "bridge/information/profiles/trade-power-memory-1374.json", "bridge/information/trade_home.py",
    "bridge/information/home_trade_node_memory.py", "bridge/information/composite.py", "bridge/information/service.py",
    "bridge/information/tools.py", "bridge/information/sources.py", "bridge/information/model.py", "tools/serve_information.py",
]


def read(path):
    return json.loads(path.read_bytes())


def write(name, value):
    with (STAGE / name).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def pin_before():
    write("runtime-source-pins-before-001.json", {"schema": "information_runtime_source_pins.v1",
          "files": [pin(ROOT / relative) for relative in RUNTIME_PATHS],
          "timing": "before MCP acceptance and final regression", "continuous_monitoring_claimed": False})


def main():
    before = read(STAGE / "runtime-source-pins-before-001.json")
    after = [dict(pin(ROOT / item["path"]), matches_before=sha(ROOT / item["path"]) == item["sha256"]) for item in before["files"]]
    assert all(item["matches_before"] for item in after)
    live = read(STAGE / "live-acceptance-001/report.json")
    assert live["status"] == "passed" and live["server_exit_code"] == 0 and all(live["checks"].values())
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
    write("runtime-source-pins-after-001.json", {"schema": before["schema"], "files": after, "all_match_before": True,
          "timing": "after MCP exit and final regression", "continuous_monitoring_claimed": False})
    write("regression-added-cases-from-full-001.json", new_tests)
    write("regression-comparison-001.json", {"schema": "information_trade_details_regression_comparison.v1", "full": full,
          "baseline": pin(BASELINE / "regression-full-001.xml"), "baseline_occurrences": old_occurrences,
          "baseline_unique_nodes": len(old_bad)})
    paths = RUNTIME_PATHS + [
        "bridge/tests/test_information_trade_details_memory.py", "bridge/tests/test_information_trade_details.py",
        "work/create_information_trade_details_profile.py", "work/reference_information_trade_details.py",
        "work/validate_information_trade_details_live.py", "work/update_information_trade_details_coverage.py",
        "work/document_information_trade_details.py", "work/archive_information_trade_details.py",
        "work/probe_information_trade_entries.py", "work/research_information_trade_share.py",
        "work/research_information_trade_power_sources.py", "work/research_information_trade_power_sources_002.py",
        "work/research_information_trade_country_scope.py", "docs/贸易竞争力只读接口.md", "docs/信息字段覆盖.json",
        "docs/信息导出与订阅开发计划.md", "docs/信息导出开发进展.md", "docs/信息接口使用说明.md", "HANDOFF.md", "README(agent).md",
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
    raw = read(STAGE / "native-trade-entry-inputs-002.json")
    summary = {"schema": "information_development_summary.v1", "batch": 45,
               "status": "implemented_native_trade_shares_and_three_source_rows_live_verified",
               "objective": previous["objective"], "goal_complete": False, "scope": previous["scope"],
               "previous_goal_turn_classification": "progress",
               "delivered": {"topic": "T04", "fields": ["shares", "sources"], "coverage": "partial", "complete": False,
                             "observer": "FRA", "object_type": "trade_node", "countries": ["FRA"],
                             "basis": "native_trade_node_share_and_source_caches", "value_origin": "copied_native_cache",
                             "share_source": "native entry+0x2c ratio cache, scale1000; not the B58D00 income return",
                             "source_rows": ["TP_PROVINCE_POWER", "TP_SHIP_POWER", "MERCHANT_DOWNSTREAM_BONUS"],
                             "profile": pin(ROOT / "bridge/information/profiles/trade-details-memory-1374.json")},
               "runtime_validation": live, "coverage": read(STAGE / "coverage-update-001.json"),
               "tests": {"full": full, "new_cases": new_tests, "counts_not_additive": True,
                         "existing_debt_triage": pin(STAGE / "existing-regression-triage-001.json")},
               "runtime_identity": previous["runtime_identity"],
               "current_identity_witnesses": [pin(STAGE / "native-trade-entry-inputs-002.json"), pin(STAGE / "live-acceptance-001/after-control.json")],
               "independent_reference": pin(STAGE / "expected-trade-details-001.json"),
               "reference_draft_revision": {"initial_draft": pin(STAGE / "expected-trade-details-draft-001.json"),
                                            "final": pin(STAGE / "expected-trade-details-001.json"),
                                            "timing": "reference schema corrected before runtime source pins and MCP acceptance",
                                            "history": "Initial same-name generated draft was removed during implementation. Reconstructed dict rows and offset annotations deterministically from the final list form; exact bytes match the independently observed initial SHA5c1968d89f9f93061b0099004e11f852d6d289b3fdc838f26085fab13cc9f3b4.",
                                            "new_RPM_observation": False},
               "raw_capture": {"failed_postcheck_first_attempt": pin(STAGE / "native-trade-entry-inputs-001.json"),
                               "second_capture": pin(STAGE / "native-trade-entry-inputs-002.json"),
                               "second_access": raw["access"],
                               "recovery_kind": "second raw RPM capture after a date-object postcheck error; not read-only reanalysis of the first capture",
                               "inherited_metadata": "domestic-pressure/stability profile and fields identify the reused country locator, not trade-share semantic guards"},
               "validation": {"business_actions_submitted": 0, "game_functions_called": False, "save_restart_DLL_date_changes": False,
                              "source_pins_before_after_match": True, "outbox": "delivered", "llm_read": "unknown", "new_REA_analysis": False},
               "ownership": {"commands": "terminal", "workers": "terminal", "subscriptions": "cancelled/no active subscription",
                             "MCP_servers": "exited0", "native_entry_RX_unwind_DLL": "retained until process exit", "battle_collection": "remains disabled"},
               "historical_integrity_incident": previous["historical_integrity_incident"],
               "next_work": {"trade": "Competitor visibility/country selection, capital/dynamic list/multiplier/native-tail rows and merchant tasks remain incomplete. Do not sum the three rows as complete country power or infer shares from current_power/total_power.",
                             "budget": "Complete native current production/tax/expense collectors remain incomplete.",
                             "battle": "Full B04 title/Line1/buttons/layout/raw_text and other B01-B04 gaps remain.",
                             "full_scope": "All74topics397fields,phases2/3/4,LLM autonomous subscriptions and full B01-B04 remain active."},
               "source_snapshots": snapshots,
               "artifact_pins": [pin(p) for p in sorted(STAGE.rglob("*")) if p.is_file() and "source-snapshot" not in p.parts]}
    write("development-summary-001.json", summary)
    assert all(sha(ROOT / item["path"]) == item["sha256"] for item in summary["artifact_pins"])
    print(json.dumps({"summary": pin(STAGE / "development-summary-001.json"), "full": full,
                      "new_cases": len(added), "artifacts": len(summary["artifact_pins"]), "snapshots": len(snapshots)}, ensure_ascii=False))


if __name__ == "__main__":
    if sys.argv[1:] == ["--pin-before"]:
        pin_before()
    else:
        assert not sys.argv[1:]
        main()
