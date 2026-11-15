"""Pin batch42 source and archive acceptance without changing earlier batches."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-budget-collectors-20261027-001"
BASELINE = ROOT / "work/runtime/information-economy-20261027-001"
RUNTIME_FILES = ["bridge/information/trade_income.py", "bridge/information/trade_income_memory.py",
                 "bridge/information/country_resources_memory.py", "bridge/information/country_state.py",
                 "bridge/information/composite.py", "bridge/information/catalog.py", "tools/serve_information.py",
                 "bridge/information/profiles/trade-income-memory-1374.json",
                 "bridge/information/profiles/country-resources-memory-1374.json",
                 "work/runtime/information-budget-collectors-20261027-001/trade-income-source-index-001.json"]


def sha(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def pin(path):
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size, "sha256": sha(path)}


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(name, value):
    with (STAGE / name).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def tests(path):
    cases = ET.parse(path).getroot().findall(".//testcase")
    bad = {f"{c.get('classname')}::{c.get('name')}" for c in cases if c.findall("failure") or c.findall("error")}
    occurrences = sum(len(c.findall("failure")) + len(c.findall("error")) for c in cases)
    return cases, bad, occurrences


def main(pin_before=False):
    if pin_before:
        write("runtime-source-pins-before-001.json", {"schema": "information_source_pins.v1",
              "timing": "after targeted tests, before live MCP acceptance", "files": [pin(ROOT/p) for p in RUNTIME_FILES]})
        print("source pins written")
        return
    before = read(STAGE / "runtime-source-pins-before-001.json")
    after = [dict(pin(ROOT/item["path"]), matches_before=sha(ROOT/item["path"]) == item["sha256"]) for item in before["files"]]
    assert all(item["matches_before"] for item in after)
    write("runtime-source-pins-after-001.json", {"schema": before["schema"], "files": after, "all_match_before": True,
          "timing": "after server exit and full suite", "continuous_monitoring_claimed": False})
    cases, bad, occurrences = tests(STAGE / "regression-full-001.xml")
    _, old_bad, old_occurrences = tests(BASELINE / "regression-full-001.xml")
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
            "subtests_passed": count("subtests passed"), "summary_line": line,
            "failure_error_occurrences": occurrences, "unique_failure_error_nodes": len(bad),
            "new_failure_nodes": sorted(bad-old_bad), "resolved_failure_nodes": sorted(old_bad-bad),
            "whole_suite_green": not bad, "xml": pin(STAGE / "regression-full-001.xml")}
    selected = [c for c in cases if "test_information_trade_income" in c.get("classname", "")]
    new_tests = {"execution": "derived_from_original_full_XML_not_new_execution", "cases": len(selected),
                 "failure_error_occurrences": sum(len(c.findall("failure"))+len(c.findall("error")) for c in selected),
                 "nodes": [f"{c.get('classname')}::{c.get('name')}" for c in selected]}
    write("regression-trade-income-from-full-001.json", new_tests)
    write("regression-comparison-001.json", {"schema": "information_trade_income_regression_comparison.v1", "full": full,
          "baseline": pin(BASELINE / "regression-full-001.xml"), "baseline_occurrences": old_occurrences, "baseline_nodes": len(old_bad)})
    paths = RUNTIME_FILES + ["bridge/tests/test_information_trade_income.py", "bridge/tests/test_information_trade_income_memory.py",
            "work/probe_information_current_overextension.py", "work/probe_information_trade_income.py",
            "work/reference_information_trade_income.py", "work/create_information_trade_income_profile.py",
            "work/validate_information_trade_income_live.py", "work/archive_information_trade_income.py",
            "work/update_information_trade_income_coverage.py", "work/document_information_trade_income.py",
            "docs/贸易收入只读接口.md", "docs/信息字段覆盖.json", "docs/信息导出与订阅开发计划.md",
            "docs/信息导出开发进展.md", "docs/信息接口使用说明.md", "HANDOFF.md", "README(agent).md"]
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
    live = read(STAGE / "live-acceptance-001/report.json")
    assert live["status"] == "passed" and live["server_exit_code"] == 0
    previous = read(BASELINE / "development-summary-001.json")
    summary = {"schema": "information_development_summary.v1", "batch": 42, "status": "implemented_trade_income_and_live_verified",
               "objective": previous["objective"], "goal_complete": False, "scope": previous["scope"],
               "delivered": {"topic": "T05", "field": "income", "coverage": live["income_coverage"],
                             "country": "FRA", "total_raw": live["total_raw"], "unit": "ducats", "scale": 1000, "period": "month",
                             "basis": "native_trade_node_country_income_cache", "node_count": 80,
                             "unsupported": ["collection", "transfer", "merchant_task", "steering_direction"],
                             "default_country_resources_capture_unchanged": True},
               "runtime_validation": live, "coverage": read(STAGE / "coverage-update-001.json"),
               "tests": {"full": full, "new_tests": new_tests, "counts_not_additive": True},
               "runtime_identity": previous["runtime_identity"],
               "current_identity_witnesses": [pin(STAGE / "native-trade-income-inputs-005.json"),
                                               pin(STAGE / "live-acceptance-001/before-control.json"),
                                               pin(STAGE / "live-acceptance-001/after-control.json")],
               "validation": {"business_actions_submitted": 0, "new_native_game_calls": False,
                              "save_restart_DLL_date_changes": False, "new_REA_analysis": False,
                              "source_pins_before_after_match": True, "outbox": "delivered", "llm_read": "unknown"},
               "historical_integrity_incident": read(STAGE / "historical-test-receipt-overwrite-001.json"),
               "ownership": {"root_commands": "terminal", "mcp_server_exit_code": 0, "subscription": "cancelled",
                             "workers": "terminal", "native_entry_RX_unwind_DLL": "retained until process exit",
                             "battle_collection": "remains disabled"},
               "next_work": {"current_budget": "Trade component closed. Continue true production A11920/A12C20, tax and other income/expense collectors; coefficient333310/333620 cannot supply amount totals.",
                             "scope": "Continue all74topics/397fields,phases2/3/4,LLM autonomous subscriptions and fullB01-B04.",
                             "B04": "projection9; fulltitle/Line1/buttons/layout/raw_text remain"},
               "source_snapshots": snapshots,
               "artifact_pins": [pin(p) for p in sorted(STAGE.rglob("*")) if p.is_file() and "source-snapshot" not in p.parts]}
    write("development-summary-001.json", summary)
    # Verify all archive pins from the just-created summary, using bounded streams.
    assert all(sha(ROOT/item["path"]) == item["sha256"] for item in summary["artifact_pins"])
    print(json.dumps({"summary": pin(STAGE / "development-summary-001.json"), "full": full, "new_cases": len(selected),
                      "artifacts": len(summary["artifact_pins"]), "snapshots": len(snapshots)}, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pin-before", action="store_true")
    main(parser.parse_args().pin_before)
