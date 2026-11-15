"""Prepare the batch48 merchant-task archive without running live work.

The archive is deliberately a final-pass script: ``--pin-before`` only pins
the frozen runtime sources, while the default path requires the live receipt
and the new full-suite receipt.  It never rewrites the batch47 baseline.
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
from work.archive_information_trade_collection import RUNTIME_PATHS as BATCH47_RUNTIME_PATHS


STAGE = ROOT / "work/runtime/information-trade-merchant-task-20261027-001"
BASELINE = ROOT / "work/runtime/information-trade-merchant-state-20261027-001"
REGRESSION_BASENAME = "regression-full-001"

# Batch48 does not introduce a profile.  Keep the complete batch47 runtime
# pin set, including the already pinned income/details modules and profiles.
RUNTIME_PATHS = tuple(dict.fromkeys(BATCH47_RUNTIME_PATHS))

RENAMED_CASES = (
    {
        "old": (
            "bridge.tests.test_information_trade_collection::"
            "test_collection_catalog_is_distinct_and_merchant_task_stays_unsupported"
        ),
        "new": (
            "bridge.tests.test_information_trade_collection::"
            "test_collection_catalog_is_distinct_and_transfer_stays_unsupported"
        ),
        "reason": "collection negative case now names the unsupported transfer field",
    },
)

_RESEARCH_PATHS = (
    "work/research_information_trade_steering_direction.py",
    "work/research_information_trade_country_scope.py",
    "work/probe_information_trade_entries.py",
)
_ROOT_SOURCE_PATHS = (
    "bridge/tests/test_information_trade_merchant_task.py",
    "bridge/tests/test_information_trade_collection.py",
    "bridge/tests/test_information_trade_income.py",
    "bridge/tests/test_information_trade_details.py",
    "work/reference_information_trade_merchant_flags.py",
    "work/reference_information_trade_merchant_task.py",
    "work/validate_information_trade_merchant_task_live.py",
    "work/update_information_trade_merchant_task_coverage.py",
    "work/run_information_trade_merchant_task_regression.py",
    "work/document_information_trade_merchant_task.py",
    "work/verify_information_trade_merchant_task_documents.py",
    "work/archive_information_trade_merchant_task.py",
    "docs/贸易收入只读接口.md",
    "docs/贸易竞争力只读接口.md",
    "docs/信息字段覆盖.json",
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


_RENAME_TO_NEW = {item["old"]: item["new"] for item in RENAMED_CASES}


def _canonical_case_key(key: str) -> str:
    return _RENAME_TO_NEW.get(key, key)


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
    old_canonical = {_canonical_case_key(key) for key in old_keys}
    current_canonical = {_canonical_case_key(key) for key in current_keys}
    current_bad = {_canonical_case_key(key) for key in bad}
    old_bad_canonical = {_canonical_case_key(key) for key in old_bad}

    renamed = []
    for item in RENAMED_CASES:
        old_key, new_key = item["old"], item["new"]
        old_case = next((case for case in old_cases if _case_key(case) == old_key), None)
        new_case = next((case for case in cases if _case_key(case) == new_key), None)
        renamed.append({
            **item,
            "old_present": old_case is not None,
            "new_present": new_case is not None,
            "old_failure_or_error": bool(old_case is not None and (
                old_case.findall("failure") or old_case.findall("error")
            )),
            "new_failure_or_error": bool(new_case is not None and (
                new_case.findall("failure") or new_case.findall("error")
            )),
        })

    added = [
        case for case in cases
        if _canonical_case_key(_case_key(case)) not in old_canonical
    ]
    added_failure_occurrences = sum(
        len(case.findall("failure")) + len(case.findall("error")) for case in added
    )
    renamed_failure_occurrences = sum(
        len(case.findall("failure")) + len(case.findall("error"))
        for item in renamed
        for case in cases
        if item["new_present"] and _case_key(case) == item["new"]
    )
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
        "new_failure_nodes": sorted(current_bad - old_bad_canonical),
        "resolved_failure_nodes": sorted(old_bad_canonical - current_bad),
        "xml": pin(xml),
    }
    new_tests = {
        "execution": "derived_from_full_XML_not_another_run",
        "cases": len(added),
        "failure_error_occurrences": added_failure_occurrences,
        "nodes": [_case_key(case) for case in added],
    }
    return {
        "full": full,
        "new_tests": new_tests,
        "updated_or_renamed_cases": renamed,
        "renamed_failure_error_occurrences": renamed_failure_occurrences,
        "baseline_failure_error_occurrences": old_occurrences,
        "baseline_unique_failure_error_nodes": len(old_bad),
        "baseline_case_count": len(old_cases),
        "current_case_count": len(cases),
    }


def pin_before():
    assert STAGE.is_dir()
    write(
        "runtime-source-pins-before-001.json",
        {
            "schema": "information_runtime_source_pins.v1",
            "files": [pin(ROOT / relative) for relative in RUNTIME_PATHS],
            "timing": "after production freeze, before live acceptance and final full regression",
            "continuous_monitoring_claimed": False,
            "batch": 48,
        },
    )


def _source_paths():
    paths = list(RUNTIME_PATHS) + list(_ROOT_SOURCE_PATHS) + list(_RESEARCH_PATHS)
    # Keep every merchant-task research/reference script in the archive even
    # when a later bounded subtask adds a numbered companion.
    paths.extend(
        path.relative_to(ROOT).as_posix()
        for pattern in (
            "work/research_information_trade_merchant_*.py",
            "work/reference_information_trade_merchant_*.py",
        )
        for path in sorted(ROOT.glob(pattern))
    )
    return tuple(dict.fromkeys(paths))


def main():
    assert STAGE.is_dir() and BASELINE.is_dir()
    before = read(STAGE / "runtime-source-pins-before-001.json")
    after = [
        dict(
            pin(ROOT / item["path"]),
            matches_before=sha(ROOT / item["path"]) == item["sha256"],
        )
        for item in before["files"]
    ]
    assert all(item["matches_before"] for item in after)

    live = read(STAGE / "live-acceptance-001/report.json")
    assert live["status"] == "passed"
    assert live["server_exit_code"] == 0
    assert all(live.get("checks", {}).values())

    comparison = regression()
    full = comparison["full"]
    assert comparison["baseline_failure_error_occurrences"] == 141
    assert comparison["baseline_unique_failure_error_nodes"] == 128
    assert not full["new_failure_nodes"]
    assert comparison["new_tests"]["cases"] == 7
    assert comparison["new_tests"]["failure_error_occurrences"] == 0
    assert comparison["renamed_failure_error_occurrences"] == 0
    assert len(comparison["updated_or_renamed_cases"]) == 1
    assert all(item["old_present"] and item["new_present"] for item in comparison["updated_or_renamed_cases"])

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
            "schema": "information_trade_merchant_task_regression_comparison.v1",
            "full": full,
            "baseline": pin(BASELINE / f"{REGRESSION_BASENAME}.xml"),
            "baseline_failure_error_occurrences": comparison["baseline_failure_error_occurrences"],
            "baseline_unique_failure_error_nodes": comparison["baseline_unique_failure_error_nodes"],
            "baseline_case_count": comparison["baseline_case_count"],
            "current_case_count": comparison["current_case_count"],
            "updated_or_renamed_cases": comparison["updated_or_renamed_cases"],
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
        assert not target.exists()
        shutil.copyfile(path, target)
        assert sha(target) == original["sha256"] == sha(path)
        snapshots.append(dict(original, snapshot=target.relative_to(ROOT).as_posix()))

    previous = read(BASELINE / "development-summary-001.json")
    evidence_names = [
        "expected-trade-merchant-task-001.json",
        "merchant-presence-source-001.json",
        "merchant-serialization-source-001.json",
        "merchant-serialization-source-002.json",
        "merchant-task-source-001.json",
        "merchant-task-source-002.json",
        "merchant-task-source-003.json",
        "merchant-task-source-004.json",
        "steering-direction-source-001.json",
        "next-source-reuse-001.json",
    ]
    missing_evidence = [name for name in evidence_names if not (STAGE / name).exists()]
    assert not missing_evidence, missing_evidence
    source_evidence = [pin(STAGE / name) for name in evidence_names]
    summary = {
        "schema": "information_development_summary.v1",
        "batch": 48,
        "status": "implemented_merchant_task_partial",
        "objective": previous["objective"],
        "goal_complete": False,
        "scope": previous["scope"],
        "previous_goal_turn_classification": "progress",
        "delivered": {
            "topic": "T05",
            "field": "merchant_task",
            "coverage": "partial",
            "complete": False,
            "observer": "FRA",
            "object_types": ["country", "trade_node"],
            "node_value": "none/collect/transfer enum from copied flag_ae plus the existing collection predicate",
            "country_value": "ordered active rows only",
            "basis": "native_trade_node_merchant_presence_and_collection_predicate",
            "value_origin": "derived_from_copied_native_flags",
            "period": "current",
            "unit": "state",
            "scale": 1,
            "gaps": ["NATIVE_CACHE_FRESHNESS_NOT_PROVEN", "TRANSIT_IDLE_TASK_LIFECYCLE_NOT_PROVEN"],
            "collection_unchanged": {"coverage": "partial", "complete": False},
            "t04_metadata_unchanged": True,
        },
        "runtime_validation": live,
        "coverage": read(STAGE / "coverage-update-002.json"),
        "tests": {
            "full": full,
            "new_tests": comparison["new_tests"],
            "updated_or_renamed_cases": comparison["updated_or_renamed_cases"],
            "baseline_failure_error_occurrences": comparison["baseline_failure_error_occurrences"],
            "baseline_unique_failure_error_nodes": comparison["baseline_unique_failure_error_nodes"],
            "counts_not_additive": True,
        },
        "runtime_identity": previous["runtime_identity"],
        "current_identity_witnesses": [
            pin(STAGE / "expected-trade-merchant-task-001.json"),
            pin(STAGE / "live-acceptance-001/after-control.json"),
        ],
        "independent_reference": pin(STAGE / "expected-trade-merchant-task-001.json"),
        "source_evidence": source_evidence,
        "validation": {
            "business_actions_submitted": 0,
            "game_functions_called": False,
            "save_restart_DLL_date_changes": False,
            "source_pins_before_after_match": True,
            "outbox": "delivered",
            "llm_read": "unknown",
            "new_REA_analysis": False,
        },
        "ownership": {
            "commands": "terminal",
            "workers": "terminal",
            "subscriptions": "cancelled/no active subscription",
            "MCP_servers": "exited0",
            "native_entry_RX_unwind_DLL": "retained until process exit",
            "battle_collection": "remains disabled",
        },
        "historical_integrity_incident": previous["historical_integrity_incident"],
        "next_work": {
            "trade": "Node-cache merchant presence is bound by AE/has_trader; transit/idle lifecycle, transfer relationships and steering direction remain gaps. Collection=false alone is not a transfer or no-merchant proof.",
            "budget": "Complete native current production/tax/expense collectors remain incomplete.",
            "battle": "Full B04 title/Line1/buttons/layout/raw_text and other B01-B04 gaps remain.",
            "full_scope": "All74topics397fields, phases2/3/4, LLM autonomous subscriptions and full B01-B04 remain active.",
        },
        "source_snapshots": snapshots,
        "artifact_pins": [
            pin(path)
            for path in sorted(STAGE.rglob("*"))
            if path.is_file() and "source-snapshot" not in path.parts
        ],
    }
    write("development-summary-001.json", summary)
    assert all(sha(ROOT / item["path"]) == item["sha256"] for item in summary["artifact_pins"])
    print(json.dumps({
        "summary": pin(STAGE / "development-summary-001.json"),
        "full": full,
        "new_cases": comparison["new_tests"]["cases"],
        "updated_or_renamed_cases": len(comparison["updated_or_renamed_cases"]),
        "artifacts": len(summary["artifact_pins"]),
        "snapshots": len(snapshots),
    }, ensure_ascii=False))


if __name__ == "__main__":
    if sys.argv[1:] == ["--pin-before"]:
        pin_before()
    else:
        assert not sys.argv[1:]
        main()
