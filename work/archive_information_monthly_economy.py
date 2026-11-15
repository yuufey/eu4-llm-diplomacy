"""Finalize batch40 once, preserving raw tests, runtime receipts and source copies."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-economy-20261027-001"
BASELINE = ROOT / "work/runtime/information-trade-names-20261026-001"


def sha(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def pin(path):
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size,
            "sha256": sha(path)}


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(name, value):
    with (STAGE / name).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def tests(path):
    root = ET.parse(path).getroot()
    cases = root.findall(".//testcase")
    bad = {f"{case.get('classname')}::{case.get('name')}" for case in cases
           if case.findall("failure") or case.findall("error")}
    return root, cases, bad, sum(len(c.findall("failure")) + len(c.findall("error")) for c in cases)


def main():
    xml_path = STAGE / "regression-full-001.xml"
    xml, cases, bad, occurrences = tests(xml_path)
    _, _, old_bad, old_occurrences = tests(BASELINE / "regression-full-001.xml")
    # Read the bounded tail; do not load historical large logs into memory.
    with (STAGE / "regression-full-001.log").open("rb") as stream:
        stream.seek(0, 2)
        stream.seek(max(0, stream.tell() - 8192))
        tail = stream.read().decode("utf-8", errors="replace")
    lines = [line for line in tail.splitlines() if " passed" in line and " in " in line]
    final_line = lines[-1]
    def count(label):
        match = re.search(r"(\d+) " + label + r"\b", final_line)
        return int(match.group(1)) if match else 0
    full = {"command": "python -m pytest -q bridge/tests", "exit_code": 1 if bad else 0,
            "passed": count("passed"), "failed": count("failed"), "errors": count("errors"),
            "subtests_passed": count("subtests passed"), "summary_line": final_line,
            "xml": pin(xml_path), "failure_error_occurrences": occurrences,
            "unique_failure_error_nodes": len(bad), "whole_suite_green": not bad,
            "new_failure_nodes": sorted(bad - old_bad), "resolved_failure_nodes": sorted(old_bad - bad)}
    elapsed = re.search(r" in (\d+\.\d+)s", final_line)
    full["elapsed_seconds"] = float(elapsed.group(1)) if elapsed else None
    comparison = {"schema": "information_monthly_economy_regression_comparison.v1",
                  "execution": "derived_from_original_XML_not_a_new_test_run",
                  "baseline": pin(BASELINE / "regression-full-001.xml"), "full": full,
                  "baseline_failure_error_occurrences": old_occurrences,
                  "baseline_unique_failure_error_nodes": len(old_bad)}
    write("regression-comparison-001.json", comparison)
    new_modules = ["bridge.tests.test_information_monthly_economy_memory",
                   "bridge.tests.test_information_monthly_economy"]
    selected = [c for c in cases if c.get("classname") in new_modules]
    new_tests = {"schema": "information_new_test_nodes_from_full.v1",
                 "execution": "derived_node_view_not_new_test_run", "full_xml": pin(xml_path),
                 "modules": {module: sum(c.get("classname") == module for c in selected) for module in new_modules},
                 "cases": len(selected), "failure_error_occurrences": sum(len(c.findall("failure")) + len(c.findall("error")) for c in selected),
                 "skipped": sum(bool(c.findall("skipped")) for c in selected)}
    write("regression-monthly-from-full-001.json", new_tests)
    before = read(STAGE / "runtime-source-pins-before-001.json")
    after = []
    for original in before["files"]:
        current = pin(ROOT / original["path"])
        current["matches_before"] = current["sha256"] == original["sha256"]
        current["mtime_ns"] = (ROOT / original["path"]).stat().st_mtime_ns
        assert current["matches_before"]
        after.append(current)
    write("runtime-source-pins-after-001.json", {"schema": before["schema"],
          "timing": "after server exit and full suite completion", "files": after,
          "all_match_before": True, "continuous_monitoring_claimed": False})
    snapshots = []
    paths = [item["path"] for item in before["files"]] + [
        "bridge/tests/test_information_monthly_economy_memory.py",
        "bridge/tests/test_information_monthly_economy.py", "bridge/tests/test_information_country_state.py",
        "work/probe_information_current_overextension.py", "work/create_information_monthly_economy_profile.py",
        "work/archive_information_monthly_economy.py", "docs/月度经济台账只读接口.md",
        "docs/信息字段覆盖.json", "docs/信息导出与订阅开发计划.md", "docs/信息导出开发进展.md",
        "docs/信息接口使用说明.md", "HANDOFF.md", "README(agent).md"]
    for relative in dict.fromkeys(paths):
        path = ROOT / relative
        original = pin(path)
        target = STAGE / "source-snapshot" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        assert not target.exists()
        shutil.copyfile(path, target)
        assert sha(target) == original["sha256"] == sha(path)
        snapshots.append(dict(original, snapshot=target.relative_to(ROOT).as_posix(), snapshot_sha256=sha(target)))
    live = read(STAGE / "live-acceptance-001/report.json")
    assert live["status"] == "passed" and live["server_exit_code"] == 0
    prior = read(BASELINE / "development-summary-001.json")
    summary = {
        "schema": "information_development_summary.v1", "batch": 40,
        "status": "implemented_partial_scope_and_live_verified", "objective": prior["objective"],
        "goal_complete": False, "scope": prior["scope"],
        "delivered": {"topic": "N01", "fields": ["monthly_income", "monthly_expenses", "monthly_balance"],
            "coverage": "partial", "reference_period": "previous_month",
            "value_semantics": "previous_month_recurring_ledger", "basis": "native_recurring_monthly_ledger",
            "unit": "ducats", "scale": 1000, "value_origin": "derived_from_copied_native_ledger",
            "raw": live["expected_raw"], "complete": False,
            "reader": "new bounded ledger module, existing country-resource identity/lifecycle capture reused",
            "default_country_resources_capture_unchanged": True,
            "parameters": "Monthly-only accepts no reference recipient; treasury still requires one.",
            "correction": "Income index12 excluded; prior R71 prose retained unchanged."},
        "runtime_validation": live,
        "coverage": read(STAGE / "coverage-update-001.json"),
        "tests": {"full": full, "new_modules_from_full": new_tests,
            "targeted_receipts": ["monthly-economy-tests-003.xml", "adapter-tests-final.xml"],
            "targeted_and_new_cases_are_included_in_full_not_additive": True},
        "runtime_identity": prior["runtime_identity"],
        "ownership": {"root_shell": "live exit0; full exit1, both terminal",
            "workers": "all returned terminal; no owned analysis/runtime handle remains",
            "subscription": "cancelled", "mcp_server_exit_code": 0,
            "battle_collection": "remains disabled; no lifecycle changes",
            "native_entry_RX_unwind_DLL": "retained until process exit"},
        "validation": {"new_ledger_reader_native_calls": False,
            "mixed_treasury_existing_read_only_native_inspection": True,
            "business_actions_submitted": 0, "save_restart_DLL_date_changes": False,
            "new_REA_analysis": False, "REA_session_inventory_only": True,
            "outbox": "delivered", "llm_read": "unknown",
            "source_pins_before_and_after_match": True},
        "next_work": {"monthly_GUI_forecast": "Resolve dynamic UI components from bounded EB7B20/EB4910 producers; keep last-month semantics explicit until then.",
            "scope_remaining": "Continue all 74 topics/397 fields, phases 2/3/4, LLM autonomous subscriptions and full B01-B04; existing partial validation is not new implementation.",
            "B04": "projection9 only; full title/Line1/buttons/layout/raw_text remain"},
        "source_snapshots": snapshots,
        "artifact_pins": [pin(p) for p in sorted(STAGE.rglob("*")) if p.is_file() and "source-snapshot" not in p.parts],
    }
    write("development-summary-001.json", summary)
    print(json.dumps({"summary": pin(STAGE / "development-summary-001.json"), "full": full,
                      "new_tests": new_tests, "snapshots": len(snapshots)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
