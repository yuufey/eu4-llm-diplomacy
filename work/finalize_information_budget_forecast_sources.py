"""Archive bounded budget research separately from production capability claims."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-budget-forecast-20261027-001"
PRIOR = ROOT / "work/runtime/information-economy-20261027-001"


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            value.update(block)
    return value.hexdigest()


def pin(path):
    return {"path": path.relative_to(ROOT).as_posix(), "sha256": digest(path), "bytes": path.stat().st_size}


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(name, value):
    with (STAGE / name).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main():
    previous = read(PRIOR / "development-summary-001.json")
    raw = read(STAGE / "native-estimated-income-inputs-001.json")
    income = read(STAGE / "income-forecast-source-001.json")
    expense = read(STAGE / "expense-forecast-source-001.json")
    producer = read(STAGE / "estimated-income-producer-001.json")
    assert len(income["components"]) == 12 and len(expense["items"]) == 21
    assert raw["status"] == "observed" and raw["completed"] is True
    assert raw["identity"]["binding_verified"] is True and raw["doublepass"]["consistent"] is True
    assert raw["cleanup"]["handle_close"]["closed"] is True
    assert all(x["offset"] == "0xe38" and x["raw"] == 21104 and x["raw_hex"] == "70520000"
               and x["date"]["value"] == 56557728 for x in raw["estimated_income_inputs"])
    assert producer["producer"]["included_indices"] == [0,1,2,3,4,5,6,7,8,15,16]
    assert producer["decision"]["can_replace_gui_forecast"] is False
    assert expense["view_route_context"]["EB7B20_slot"] == "0x48"
    assert expense["view_route_context"]["EB40F0_slot"] == "0x50"
    assert expense["current_forecast_display"]["format_call_va"] == "0x140ebfc4b"
    # The matrix and production code/profile remain exactly the batch40 copies.
    preserved = ["bridge/information/monthly_economy_memory.py",
                 "bridge/information/country_resources_memory.py", "bridge/information/country_state.py",
                 "bridge/information/profiles/monthly-economy-memory-1374.json", "docs/信息字段覆盖.json"]
    preservation = [dict(pin(ROOT / path), matches_batch40=digest(ROOT / path) == digest(PRIOR / "source-snapshot" / path))
                    for path in preserved]
    assert all(item["matches_batch40"] for item in preservation)
    index = {"schema": "information_current_budget_source_index.v1", "batch": 41,
             "status": "source_progress_not_new_public_capability", "target": producer["target"],
             "evidence_layers": {"new_REA_analysis": False, "ordinary_bounded_PE": True,
                                 "static_object_domain_inferences_retained": True,
                                 "runtime": pin(STAGE / "native-estimated-income-inputs-001.json")},
             "budget_view": {"vtable_rva": "0x1d38c38", "income_method_slot": "0x48",
                 "expense_method_slot": "0x50", "income_components": 12, "expense_components": 21,
                 "income_total_offset": "0x578", "expense_total_offset": "0x5bc",
                 "balance": "signed32(view[0x578]-view[0x5bc])",
                 "arithmetic": "32-bit addition/subtraction; 956f0 copies a DWORD only",
                 "missing": ["Observer-country binding and freshness of a live view cache.",
                             "Complete explicit-country ABI and semantic contracts for the dynamic native collectors."]},
             "estimated_income_cache": {"country_offset": "0xe38", "unit": "ducats", "scale": 1000,
                 "raw_type": "signed int32", "observed_raw": 21104,
                 "located_write_path": "Roll current arrays into named last-month arrays, sum income indices 0..8/15/16 with int32 wrap, then signed minimum raw1.",
                 "producer_domain": "Country-domain inferred from ledger layout and use; C++ identity on every R12 reload path not proved.",
                 "update_schedule": "unknown", "all_writers_closed": False,
                 "GUI_forecast_equivalence": "not_established", "publish_as_current_forecast": False},
             "next_actions": ["Bind explicit country parameter and result contracts at native income collectors 0x333620 and 0x333310; inspect bounded entry/return paths before choosing a frame-thread collector.",
                              "Reuse engine maintenance/other component collectors identified in expense-forecast-source-001; avoid rewriting the entire game budget formula.",
                              "Require observer-country binding and current-result timing before publishing a GUI forecast or cache.",
                              "Continue other planned topics and full B01-B04; do not repeat E38/old partial acceptance as new implementation."],
             "production_and_matrix_preserved": preservation,
             "sources": [pin(path) for path in sorted(STAGE.glob("*.json"))]}
    write("current-budget-source-index-001.json", index)
    snapshots = []
    for relative in ["work/probe_information_current_overextension.py", "work/research_information_budget_view.py",
                     "work/finalize_information_budget_forecast_sources.py", "docs/当前预算预测来源.md",
                     "docs/信息导出与订阅开发计划.md", "HANDOFF.md", "README(agent).md"]:
        path = ROOT / relative
        target = STAGE / "source-snapshot" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        assert not target.exists()
        before = digest(path)
        shutil.copyfile(path, target)
        assert before == digest(path) == digest(target)
        snapshots.append(dict(pin(path), snapshot=target.relative_to(ROOT).as_posix(), snapshot_sha256=before))
    summary = {"schema": "information_development_summary.v1", "batch": 41,
               "status": "bounded_source_progress_and_independent_cache_observation",
               "objective": previous["objective"], "scope": previous["scope"], "goal_complete": False,
               "public_fields_added": 0, "coverage_changes": 0, "source_index": pin(STAGE / "current-budget-source-index-001.json"),
               "result": "Budget 12/21 component mappings and view aliases closed; lagged/clamped E38 cache ruled out as an unproven replacement for current GUI forecast.",
               "runtime_identity": raw["identity"], "raw_cache_observation": {"country": "FRA", "offset": "0xe38",
                   "raw": 21104, "raw_hex": "70520000", "game_date": 56557728,
                   "access": raw["access"], "doublepass": raw["doublepass"], "cleanup": raw["cleanup"]},
               "tests": {"new_full_suite_run": False, "reason": "No production behavior or profile changed; analysis scripts and the private RPM probe ran to completion.",
                         "prior_full_suite_only": previous["tests"]["full"]},
               "ownership": {"workers": "all terminal", "root_shells": "all terminal", "owned_live_handles": 0},
               "coverage_preserved": previous["coverage"]["aggregate_counts"],
               "production_and_matrix_preserved": preservation,
               "source_snapshots": snapshots,
               "artifact_pins": [pin(path) for path in sorted(STAGE.glob("*.json"))]}
    write("development-summary-001.json", summary)
    print(json.dumps({"summary": pin(STAGE / "development-summary-001.json"), "source_index": pin(STAGE / "current-budget-source-index-001.json"),
                      "snapshots": len(snapshots), "production_and_matrix_match_batch40": True}))


if __name__ == "__main__":
    main()
