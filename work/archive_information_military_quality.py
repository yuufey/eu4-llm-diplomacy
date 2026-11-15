"""Prepare the batch49 military-quality archive without running live work.

``--pin-before`` only writes exclusive source pins.  The default path is a
final-pass archive: it requires the root live receipt and the new full-suite
receipt, compares the full XML with batch48, and snapshots the frozen source
set.  It never rewrites a prior stage or starts a game/MCP process.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.archive_information_trade_income import pin, sha, tests
from work.archive_information_trade_merchant_task import RUNTIME_PATHS as BATCH48_RUNTIME_PATHS


STAGE = ROOT / "work/runtime/information-military-quality-20261027-001"
BASELINE = ROOT / "work/runtime/information-trade-merchant-task-20261027-001"
REGRESSION_BASENAME = "regression-full-001"

_ADDITIONAL_RUNTIME_PATHS = (
    "bridge/information/military_quality.py",
    "bridge/information/military_quality_memory.py",
    "bridge/information/military_tradition_memory.py",
    "bridge/information/profiles/military-quality-memory-1374.json",
    "bridge/information/profiles/military-tradition-memory-1374.json",
    "bridge/information/domestic_pressure_memory.py",
    "bridge/information/profiles/domestic-pressure-memory-1374-v2.json",
    "tools/serve_information.py",
)
RUNTIME_PATHS = tuple(dict.fromkeys(BATCH48_RUNTIME_PATHS + _ADDITIONAL_RUNTIME_PATHS))

_EXPLICIT_SOURCE_PATHS = (
    "bridge/tests/test_information_military_quality.py",
    "bridge/tests/test_information_military_quality_memory.py",
    "bridge/tests/test_information_military_tradition_memory.py",
    "bridge/tests/test_information_domestic_pressure_real.py",
    "work/create_information_military_quality_profile.py",
    "work/create_information_military_tradition_profile.py",
    "work/update_information_military_parent_dependency.py",
    "work/validate_information_military_quality_live.py",
    "work/reference_information_military_quality.py",
    "work/document_information_military_quality.py",
    "work/verify_information_military_quality_documents.py",
    "work/archive_information_military_quality.py",
    "work/update_information_military_quality_coverage.py",
    "work/run_information_military_quality_regression.py",
    "docs/信息字段覆盖.json",
    "docs/军事质量只读接口.md",
    "docs/信息导出与订阅开发计划.md",
    "docs/信息导出开发进展.md",
    "docs/信息接口使用说明.md",
    "HANDOFF.md",
    "README(agent).md",
)


def read(path: Path):
    return json.loads(path.read_bytes())


def write(name: str, value):
    target = STAGE / name
    with target.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def _case_key(case) -> str:
    return f"{case.get('classname')}::{case.get('name')}"


def _summary_line(path: Path) -> str:
    with path.open("rb") as stream:
        stream.seek(0, 2)
        stream.seek(max(0, stream.tell() - 8192))
        tail = stream.read().decode("utf-8", errors="replace")
    lines = [line for line in tail.splitlines() if " passed" in line and " in " in line]
    if not lines:
        raise AssertionError(f"pytest summary line missing: {path}")
    return lines[-1]


def _count(line: str, label: str) -> int:
    match = re.search(r"(\d+) " + re.escape(label) + r"\b", line)
    return int(match.group(1)) if match else 0


def regression():
    xml = STAGE / f"{REGRESSION_BASENAME}.xml"
    log = STAGE / f"{REGRESSION_BASENAME}.log"
    cases, bad, occurrences = tests(xml)
    old_cases, old_bad, old_occurrences = tests(BASELINE / f"{REGRESSION_BASENAME}.xml")
    line = _summary_line(log)
    old_keys = {_case_key(case) for case in old_cases}
    current_keys = {_case_key(case) for case in cases}
    current_bad = {_case_key(case) for case in cases if case.findall("failure") or case.findall("error")}
    added = [case for case in cases if _case_key(case) not in old_keys]
    full = {
        "command": "python -m pytest -q bridge/tests",
        "exit_code": 1 if bad else 0,
        "passed": _count(line, "passed"),
        "failed": _count(line, "failed"),
        "errors": _count(line, "errors"),
        "subtests_passed": _count(line, "subtests passed"),
        "summary_line": line,
        "whole_suite_green": not bad,
        "failure_error_occurrences": occurrences,
        "unique_failure_error_nodes": len(bad),
        "new_failure_nodes": sorted(current_bad - old_bad),
        "resolved_failure_nodes": sorted(old_bad - current_bad),
        "xml": pin(xml),
    }
    new_tests = {
        "execution": "derived_from_full_XML_not_another_run",
        "cases": len(added),
        "failure_error_occurrences": sum(
            len(case.findall("failure")) + len(case.findall("error")) for case in added
        ),
        "nodes": [_case_key(case) for case in added],
    }
    return {
        "full": full,
        "new_tests": new_tests,
        "updated_or_renamed_cases": [],
        "baseline_failure_error_occurrences": old_occurrences,
        "baseline_unique_failure_error_nodes": len(old_bad),
        "baseline_case_count": len(old_cases),
        "current_case_count": len(cases),
        "case_set_changed": old_keys != current_keys,
    }


def pin_before():
    if not STAGE.is_dir():
        raise AssertionError(f"stage missing: {STAGE}")
    target = STAGE / "runtime-source-pins-before-001.json"
    if target.exists():
        raise AssertionError("batch49 source pins already exist")
    write(
        target.name,
        {
            "schema": "information_runtime_source_pins.v1",
            "files": [pin(ROOT / relative) for relative in RUNTIME_PATHS],
            "timing": "after N03 production freeze, before live acceptance and final full regression",
            "continuous_monitoring_claimed": False,
            "batch": 49,
            "baseline_stage": BASELINE.relative_to(ROOT).as_posix(),
        },
    )


def _source_paths():
    paths = list(RUNTIME_PATHS) + list(_EXPLICIT_SOURCE_PATHS)
    # Include every bounded military research/probe/reference/helper companion
    # that exists at final archive time, while leaving unrelated research out.
    for pattern in (
        "work/research_information_military_*.py",
        "work/probe_information_military_*.py",
        "work/reference_information_military_*.py",
        "work/*information_military_quality*.py",
        "work/*information_military_tradition*.py",
    ):
        paths.extend(path.relative_to(ROOT).as_posix() for path in sorted(ROOT.glob(pattern)))
    return tuple(dict.fromkeys(paths))


_GENERATED_JSON = {
    "coverage-matrix-before-001.json",
    "coverage-update-001.json",
    "coverage-update-002.json",
    "development-summary-001.json",
    "regression-added-cases-from-full-001.json",
    "regression-comparison-001.json",
    "runtime-source-pins-before-001.json",
    "runtime-source-pins-after-001.json",
}


def _evidence_paths():
    evidence = [
        path
        for path in sorted(STAGE.glob("*.json"))
        if path.name not in _GENERATED_JSON
    ]
    evidence.extend(sorted((STAGE / "live-acceptance-001").glob("*.json")))
    return tuple(evidence)


def main():
    if not STAGE.is_dir() or not BASELINE.is_dir():
        raise AssertionError("batch49 stage or batch48 baseline is missing")
    before = read(STAGE / "runtime-source-pins-before-001.json")
    after = [
        dict(
            pin(ROOT / item["path"]),
            matches_before=sha(ROOT / item["path"]) == item["sha256"],
        )
        for item in before["files"]
    ]
    if not all(item["matches_before"] for item in after):
        raise AssertionError("a frozen runtime source changed after pin-before")

    live = read(STAGE / "live-acceptance-001/report.json")
    if live.get("status") != "passed" or live.get("server_exit_code") != 0:
        raise AssertionError("live acceptance did not pass")
    if not all(live.get("checks", {}).values()):
        raise AssertionError("live acceptance contains a failed check")

    comparison = regression()
    full = comparison["full"]
    if full["new_failure_nodes"]:
        raise AssertionError(full["new_failure_nodes"])
    if comparison["new_tests"]["failure_error_occurrences"]:
        raise AssertionError("a newly added test failed")

    write(
        "runtime-source-pins-after-001.json",
        {
            "schema": before["schema"],
            "files": after,
            "all_match_before": True,
            "timing": "after live acceptance and final full regression",
            "continuous_monitoring_claimed": False,
        },
    )
    write("regression-added-cases-from-full-001.json", comparison["new_tests"])
    write(
        "regression-comparison-001.json",
        {
            "schema": "information_military_quality_regression_comparison.v1",
            "full": full,
            "baseline": pin(BASELINE / f"{REGRESSION_BASENAME}.xml"),
            "baseline_failure_error_occurrences": comparison["baseline_failure_error_occurrences"],
            "baseline_unique_failure_error_nodes": comparison["baseline_unique_failure_error_nodes"],
            "baseline_case_count": comparison["baseline_case_count"],
            "current_case_count": comparison["current_case_count"],
            "updated_or_renamed_cases": [],
            "new_tests": comparison["new_tests"],
            "counts_not_additive": True,
        },
    )

    snapshots = []
    for relative in _source_paths():
        path = ROOT / relative
        original = pin(path)
        target = STAGE / "source-snapshot" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise AssertionError(f"source snapshot already exists: {target}")
        shutil.copyfile(path, target)
        if sha(target) != original["sha256"] or sha(path) != original["sha256"]:
            raise AssertionError(f"source snapshot changed during copy: {relative}")
        snapshots.append(dict(original, snapshot=target.relative_to(ROOT).as_posix()))

    previous = read(BASELINE / "development-summary-001.json")
    evidence = _evidence_paths()
    if not evidence:
        raise AssertionError("no batch49 evidence JSON found")
    if not (STAGE / "coverage-update-001.json").exists():
        raise AssertionError("coverage update receipt is missing")
    after_control = STAGE / "live-acceptance-001/after-control.json"
    current_witnesses = [pin(after_control)] if after_control.exists() else []
    reference = next(
        (path for path in evidence if path.name in ("native-military-quality-inputs-001.json", "expected-military-quality-001.json")),
        evidence[0],
    )
    artifact_paths = [
        path
        for path in sorted(STAGE.rglob("*"))
        if path.is_file() and "source-snapshot" not in path.parts
    ]
    summary = {
        "schema": "information_development_summary.v1",
        "batch": 49,
        "status": "implemented_military_quality_partial",
        "objective": previous.get("objective"),
        "goal_complete": False,
        "scope": previous.get("scope"),
        "previous_goal_turn_classification": "progress",
        "delivered": {
            "topic": "N03",
            "fields": ["military_technology", "army_tradition"],
            "coverage": "available",
            "complete": True,
            "observer": "FRA",
            "object_type": "country",
            "unit": {"military_technology": "technology_level", "army_tradition": "army_tradition"},
            "scale": {"military_technology": 1, "army_tradition": 1000},
            "basis": {
                "military_technology": "native_country_technology_level_cache",
                "army_tradition": "native_country_army_tradition_cache",
            },
            "value_origin": {
                "military_technology": "copied_native_country_technology_cache",
                "army_tradition": "copied_native_country_army_tradition_cache",
            },
            "remaining_fields": ["morale", "discipline", "professionalism", "military_modifiers"],
            "remaining_coverage": "planned",
            "gaps": [
                "NATIVE_CACHE_FRESHNESS_NOT_PROVEN",
                "MAIN_THREAD_ATOMICITY_NOT_PROVEN",
                "FOREIGN_COUNTRY_VISIBILITY_NOT_SUPPORTED",
                "MILITARY_COSTS_AND_MODIFIERS_NOT_CLOSED",
            ],
        },
        "runtime_validation": live,
        "coverage": read(STAGE / "coverage-update-001.json"),
        "tests": {
            "full": full,
            "new_tests": comparison["new_tests"],
            "updated_or_renamed_cases": [],
            "baseline_failure_error_occurrences": comparison["baseline_failure_error_occurrences"],
            "baseline_unique_failure_error_nodes": comparison["baseline_unique_failure_error_nodes"],
            "counts_not_additive": True,
        },
        "runtime_identity": previous.get("runtime_identity"),
        "current_identity_witnesses": current_witnesses,
        "independent_reference": pin(reference),
        "raw_reference_caveat": {
            "native_military_quality_inputs_001": "retained with its original sampling count misclassification",
            "expected_military_quality_001": "read-only reanalysis reference; it is not an original sampling report-pass receipt",
        },
        "source_evidence": [pin(path) for path in evidence],
        "validation": {
            "business_actions_submitted": 0,
            "game_functions_called": False,
            "save_restart_DLL_date_changes": False,
            "source_pins_before_after_match": True,
            "outbox": "delivered",
            "llm_read": "unknown",
            "new_REA_analysis": False,
            "historical_reference_reanalysis_is_not_original_capture": True,
        },
        "ownership": {
            "commands": "terminal",
            "workers": "terminal",
            "subscriptions": "cancelled/no active subscription",
            "MCP_servers": "exited0",
            "native_entry_RX_unwind_DLL": "retained until process exit",
        },
        "historical_integrity_incident": previous.get("historical_integrity_incident"),
        "next_work": {
            "military": "N03 morale, discipline, professionalism and military_modifiers remain planned; the copied technology/tradition caches do not imply those fields.",
            "domestic": "N04 coverage is unchanged; the v2 parent dependency is pinned as a corrected runtime source.",
            "full_scope": "All74topics397fields, phases2/3/4, LLM autonomous subscriptions and full B01-B04 remain active.",
        },
        "source_snapshots": snapshots,
        "artifact_pins": [pin(path) for path in artifact_paths],
    }
    write("development-summary-001.json", summary)
    if not all(sha(ROOT / item["path"]) == item["sha256"] for item in summary["artifact_pins"]):
        raise AssertionError("an archived stage artifact changed after pinning")
    print(
        json.dumps(
            {
                "summary": pin(STAGE / "development-summary-001.json"),
                "full": full,
                "new_cases": comparison["new_tests"]["cases"],
                "updated_or_renamed_cases": 0,
                "artifacts": len(summary["artifact_pins"]),
                "snapshots": len(snapshots),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    if sys.argv[1:] == ["--pin-before"]:
        pin_before()
    elif not sys.argv[1:]:
        main()
    else:
        raise SystemExit("usage: archive_information_military_quality.py [--pin-before]")
