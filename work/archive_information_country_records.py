"""Archive the batch52 country-records delivery after its final checks.

The helper is inert on import.  The pin-before path records production and
runtime source pins.  The default path requires live and documentation
receipts, compares the single full bridge-suite XML with batch51, and
snapshots bounded country-record sources.  It never starts a game, MCP
server, RPM probe, or REA query.
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
from work.archive_information_military_professionalism import (
    RUNTIME_PATHS as BATCH51_RUNTIME_PATHS,
)


STAGE = ROOT / "work/runtime/information-country-records-20261027-001"
BASELINE = ROOT / "work/runtime/information-military-professionalism-20261027-001"
STATIC_STAGE = ROOT / "work/runtime/information-military-modifiers-20261027-001"
REGRESSION_BASENAME = "regression-full-001"

_ADDITIONAL_RUNTIME_PATHS = (
    "bridge/information/country_loans_memory.py",
    "bridge/information/profiles/country-loans-memory-1374.json",
    "bridge/information/country_modifiers_memory.py",
    "bridge/information/profiles/country-modifiers-memory-1374.json",
    "bridge/information/profiles/country-modifiers-memory-1374-v2.json",
    "bridge/information/country_records.py",
    "bridge/information/profiles/domestic-pressure-memory-1374-v6.json",
    "tools/serve_information.py",
)
RUNTIME_PATHS = tuple(dict.fromkeys(BATCH51_RUNTIME_PATHS + _ADDITIONAL_RUNTIME_PATHS))

_CORE_SOURCE_PATHS = (
    "bridge/tests/test_information_country_loans_memory.py",
    "bridge/tests/test_information_country_modifiers_memory.py",
    "bridge/tests/test_information_country_records.py",
    "work/create_information_country_loans_profile.py",
    "work/create_information_country_modifiers_profile.py",
    "work/probe_information_country_loans.py",
    "work/probe_information_active_military_modifiers.py",
    "work/reference_information_country_loans.py",
    "work/create_information_country_modifier_contract.py",
    "work/research_information_loans_001.py",
    "work/research_information_active_military_modifiers_001.py",
    "work/research_information_active_military_modifiers_002.py",
    "work/research_information_active_military_modifiers_004.py",
    "work/finalize_information_country_modifier_contract.py",
    "work/archive_information_country_records.py",
    "work/update_information_country_records_coverage.py",
    "work/run_information_country_records_regression.py",
    "docs/国家资源信息接口.md",
    "docs/国家贷款与当前修正只读接口.md",
    "docs/信息字段覆盖.json",
    "docs/信息导出与订阅开发计划.md",
    "docs/信息导出开发进展.md",
    "docs/信息接口使用说明.md",
    "HANDOFF.md",
    "README(agent).md",
)

_SOURCE_PATTERNS = (
    "bridge/tests/test_information_country_*.py",
    "work/*information_country_records*.py",
    "work/*information_country_loans*.py",
    "work/*information_country_modifiers*.py",
    "work/research_information_active_military_modifiers_*.py",
    "work/*information_modifier_effect*.py",
)

_STATIC_REFERENCE_NAMES = (
    "active-military-modifiers-source-001.json",
    "active-military-modifiers-source-002.json",
    "active-military-modifiers-source-003.json",
    "active-military-modifiers-source-004.json",
    "active-military-modifiers-source-005.json",
    "active-military-modifiers-source-006.json",
    "native-modifier-inputs-001.json",
    "native-modifier-inputs-002.json",
    "modifier-effect-date-source-001.json",
)

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
    old_cases, old_bad, old_occurrences = tests(
        BASELINE / f"{REGRESSION_BASENAME}.xml"
    )
    line = _summary_line(log)
    old_keys = {_case_key(case) for case in old_cases}
    current_keys = {_case_key(case) for case in cases}
    current_bad = {
        _case_key(case)
        for case in cases
        if case.findall("failure") or case.findall("error")
    }
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
            len(case.findall("failure")) + len(case.findall("error"))
            for case in added
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
        raise AssertionError("batch52 source pins already exist")
    write(
        target.name,
        {
            "schema": "information_runtime_source_pins.v1",
            "files": [pin(ROOT / relative) for relative in RUNTIME_PATHS],
            "timing": (
                "after country-records targeted checks, before live acceptance "
                "and final full regression"
            ),
            "continuous_monitoring_claimed": False,
            "batch": 52,
            "baseline_stage": BASELINE.relative_to(ROOT).as_posix(),
        },
    )


def _source_paths():
    paths = list(RUNTIME_PATHS) + list(_CORE_SOURCE_PATHS)
    for pattern in _SOURCE_PATTERNS:
        paths.extend(
            path.relative_to(ROOT).as_posix()
            for path in sorted(ROOT.glob(pattern))
            if path.is_file()
        )
    return tuple(
        dict.fromkeys(
            relative for relative in paths if (ROOT / relative).is_file()
        )
    )


def _evidence_paths():
    return tuple(
        path
        for path in sorted(STAGE.rglob("*.json"))
        if path.name not in _GENERATED_JSON
        and "source-snapshot" not in path.parts
    )


def _rea_run_paths():
    paths = tuple(sorted(STATIC_STAGE.rglob("run.json")))
    if not paths:
        raise AssertionError("batch52 static REA receipt set is missing")
    return paths


def _validate_rea_runs(paths):
    terminal_statuses = {"completed", "postread_guard_error"}
    for path in paths:
        run = read(path)
        if run.get("status") not in terminal_statuses:
            raise AssertionError(f"non-terminal REA receipt: {path}")
        if run.get("status") == "completed":
            if run.get("exit_code") != 0:
                raise AssertionError(f"completed REA receipt has nonzero exit: {path}")
        elif not (
            run.get("exit_code") == 1
            and run.get("provider_exit_code") == 0
            and run.get("postread", {}).get("status") == "guard_rejected"
        ):
            raise AssertionError(f"invalid guarded REA receipt: {path}")
        if run.get("database_unchanged") is not True:
            raise AssertionError(f"REA database changed: {path}")
        if run.get("query_reanalysis") is not False:
            raise AssertionError(f"REA query was reanalysed: {path}")
        if run.get("cleanup", {}).get("status") != "complete":
            raise AssertionError(f"REA cleanup is incomplete: {path}")


def _static_reference_paths():
    missing = [
        name for name in _STATIC_REFERENCE_NAMES
        if not (STATIC_STAGE / name).is_file()
    ]
    if missing:
        raise AssertionError(
            "required old-military static source pins are missing: "
            + ", ".join(missing)
        )
    return tuple(STATIC_STAGE / name for name in _STATIC_REFERENCE_NAMES)


def _verify_before():
    before = read(STAGE / "runtime-source-pins-before-001.json")
    after = []
    for item in before.get("files", []):
        path = ROOT / item["path"]
        after.append(
            dict(
                pin(path),
                matches_before=sha(path) == item.get("sha256"),
            )
        )
    if not after or not all(item["matches_before"] for item in after):
        raise AssertionError("a frozen country-record runtime source changed")
    return before, after


def main():
    if not STAGE.is_dir() or not BASELINE.is_dir():
        raise AssertionError("batch52 stage or batch51 baseline is missing")
    before, after = _verify_before()

    live = read(STAGE / "live-acceptance-001/report.json")
    if live.get("status") != "passed" or live.get("server_exit_code") != 0:
        raise AssertionError("live acceptance did not pass")
    if not all(live.get("checks", {}).values()):
        raise AssertionError("live acceptance contains a failed check")
    document_path = STAGE / "document-verification-001.json"
    if not document_path.exists():
        raise AssertionError("country-record document verification receipt is missing")
    document = read(document_path)
    if document.get("status") != "passed":
        raise AssertionError("country-record document verification did not pass")
    if document.get("new_game_queries_or_pytest_runs") != 0:
        raise AssertionError("document verification performed an unapproved run")

    comparison = regression()
    if comparison["full"]["new_failure_nodes"]:
        raise AssertionError(comparison["full"]["new_failure_nodes"])
    if comparison["new_tests"]["failure_error_occurrences"]:
        raise AssertionError("a newly added country-record test failed")

    coverage_path = STAGE / "coverage-update-001.json"
    if not coverage_path.exists():
        raise AssertionError("country-record coverage update receipt is missing")
    coverage = read(coverage_path)
    expected_fields = {
        ("N01", "loans"),
        ("N07", "modifier_id"),
        ("N07", "target"),
        ("N07", "effects"),
        ("N08", "modifier_start_date"),
        ("N08", "modifier_end_date"),
        ("N08", "remaining_days"),
        ("N08", "duration_type"),
    }
    actual_fields = {
        (item.get("topic"), item.get("field"))
        for item in coverage.get("coverage_changes", [])
    }
    if actual_fields != expected_fields:
        raise AssertionError(f"unexpected coverage changes: {sorted(actual_fields)}")

    rea_paths = _rea_run_paths()
    _validate_rea_runs(rea_paths)
    static_sources = _static_reference_paths()

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
            "schema": "information_country_records_regression_comparison.v1",
            "full": comparison["full"],
            "baseline": pin(BASELINE / f"{REGRESSION_BASENAME}.xml"),
            "baseline_failure_error_occurrences": comparison[
                "baseline_failure_error_occurrences"
            ],
            "baseline_unique_failure_error_nodes": comparison[
                "baseline_unique_failure_error_nodes"
            ],
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

    evidence = _evidence_paths()
    if not evidence:
        raise AssertionError("no batch52 evidence JSON found")
    required = {
        "loans-production-contract-001.json",
        "country-modifiers-source-contract-001.json",
        "country-modifiers-source-contract-002.json",
    }
    if not required <= {path.name for path in evidence}:
        raise AssertionError("country-record contract evidence is incomplete")
    previous = read(BASELINE / "development-summary-001.json")
    current_witnesses = []
    for name in ("before-control.json", "after-control.json"):
        path = STAGE / "live-acceptance-001" / name
        if path.exists():
            current_witnesses.append(pin(path))
    reference = next(
        (path for path in evidence if "expected" in path.name.lower()),
        evidence[0],
    )
    artifact_paths = [
        path for path in sorted(STAGE.rglob("*"))
        if path.is_file() and "source-snapshot" not in path.parts
    ]
    summary = {
        "schema": "information_development_summary.v1",
        "batch": 52,
        "status": "implemented_country_records_partial",
        "objective": previous.get("objective"),
        "goal_complete": False,
        "goal_status": "active",
        "scope": previous.get("scope"),
        "previous_goal_turn_classification": "progress",
        "delivered": {
            "topics": {
                "N01": ["loans"],
                "N07": ["modifier_id", "target", "effects"],
                "N08": [
                    "modifier_start_date",
                    "modifier_end_date",
                    "remaining_days",
                    "duration_type",
                ],
            },
            "coverage_changes": coverage.get("coverage_changes", []),
            "coverage": coverage.get("counts"),
            "actual_live_counts": coverage.get("actual_live_counts"),
            "remaining_fields": [
                "N01.war_income",
                "N07.name",
                "N07.description",
                "N07.source",
                "N08.removal_conditions",
            ],
            "complete": False,
        },
        "runtime_validation": live,
        "documentation_validation": document,
        "coverage": coverage,
        "tests": {
            "full": comparison["full"],
            "new_tests": comparison["new_tests"],
            "updated_or_renamed_cases": [],
            "baseline_failure_error_occurrences": comparison[
                "baseline_failure_error_occurrences"
            ],
            "baseline_unique_failure_error_nodes": comparison[
                "baseline_unique_failure_error_nodes"
            ],
            "counts_not_additive": True,
        },
        "runtime_identity": previous.get("runtime_identity"),
        "runtime_profile_pins": [
            pin(ROOT / relative)
            for relative in RUNTIME_PATHS
            if "profiles/" in relative
        ],
        "current_identity_witnesses": current_witnesses,
        "independent_reference": pin(reference),
        "inherited_batch51_sources": {
            "stage": BASELINE.relative_to(ROOT).as_posix(),
            "summary": pin(BASELINE / "development-summary-001.json"),
            "REA_inherited": False,
        },
        "static_sources": {
            "stage": STATIC_STAGE.relative_to(ROOT).as_posix(),
            "receipts": [pin(path) for path in rea_paths],
            "bounded_sources": [pin(path) for path in static_sources],
            "new_queries_stored_in_old_military_stage": len(rea_paths),
            "not_inherited_from_batch51": True,
        },
        "source_evidence": [pin(path) for path in evidence],
        "validation": {
            "business_actions_submitted": 0,
            "native_calls": 0,
            "game_functions_called": False,
            "save_restart_DLL_date_changes": False,
            "source_pins_before_after_match": True,
            "outbox": "delivered",
            "llm_read": "unknown",
            "new_REA_analysis": False,
            "REA_receipts_are_dedicated_batch52_static_sources": True,
            "historical_reference_reanalysis_is_not_original_capture": True,
        },
        "ownership": {
            "commands": "terminal",
            "workers": "terminal",
            "subscriptions": "cancelled/no active subscription",
            "MCP_servers": "exited0",
        },
        "next_work": {
            "N01": "war_income remains planned; monthly ledger fields retain their previous-month semantics",
            "N07": "name, description and source remain planned",
            "N08": "modifier_start_date, modifier_end_date, remaining_days and duration_type are promoted; removal_conditions remains planned",
            "full_scope": "All74topics397fields and phases2/3/4 remain active",
        },
        "source_snapshots": snapshots,
        "artifact_pins": [pin(path) for path in artifact_paths],
    }
    write("development-summary-001.json", summary)
    if not all(sha(ROOT / item["path"]) == item["sha256"] for item in summary["artifact_pins"]):
        raise AssertionError("an archived batch52 artifact changed after pinning")
    print(
        json.dumps(
            {
                "summary": pin(STAGE / "development-summary-001.json"),
                "full": comparison["full"],
                "new_cases": comparison["new_tests"]["cases"],
                "artifacts": len(summary["artifact_pins"]),
                "snapshots": len(snapshots),
                "static_rea_receipts": len(rea_paths),
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
        raise SystemExit(
            "usage: archive_information_country_records.py [--pin-before]"
        )
