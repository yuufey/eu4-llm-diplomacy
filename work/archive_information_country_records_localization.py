"""Archive batch53 country-record localization and selected relations.

The helper is inert on import.  ``--pin-before`` records the source files
before the live acceptance and full-suite receipts exist.  The default path is
intended for the root worker after those receipts are ready: it checks the
before/after pins, compares the current XML with batch52, and snapshots the
bounded sources.  It never starts MCP, a game, RPM, or REA work itself.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.archive_information_country_records import (  # noqa: E402
    RUNTIME_PATHS as BATCH52_RUNTIME_PATHS,
)


STAGE = ROOT / "work/runtime/information-country-records-localization-20261027-001"
BASELINE = ROOT / "work/runtime/information-country-records-20261027-001"
REGRESSION_BASENAME = "regression-full-002"
BASELINE_REGRESSION_BASENAME = "regression-full-001"

_ADDITIONAL_RUNTIME_PATHS = (
    "bridge/information/country_record_localization.py",
    "bridge/information/relation_records.py",
    "bridge/information/relation_state.py",
    "bridge/information/native_localization.py",
    "bridge/information/engine_dates.py",
    "bridge/information/profiles/country-loans-memory-1374-v2.json",
    "bridge/information/profiles/localization-memory-1374.json",
)
RUNTIME_PATHS = tuple(dict.fromkeys(BATCH52_RUNTIME_PATHS + _ADDITIONAL_RUNTIME_PATHS))

_CORE_SOURCE_PATHS = (
    "bridge/tests/test_information_country_record_localization.py",
    "bridge/tests/test_information_country_records_localized.py",
    "bridge/tests/test_information_trade_name_wiring.py",
    "bridge/tests/test_information_relation_records.py",
    "bridge/tests/test_information_relation_state.py",
    "bridge/tests/fixtures/information_relation_state_live_1374.json",
    "work/research_information_relation_projection.py",
    "work/research_information_relation_directions.py",
    "work/validate_information_country_records_localization_live.py",
    "work/capture_information_country_modifier_names.py",
    "work/probe_information_country_loans_v2.py",
    "work/reference_information_country_loans_v2.py",
    "work/research_information_loan_lender_dates.py",
    "work/research_information_loan_lender_dates_002.py",
    "bridge/information/country_loans_memory.py",
    "bridge/information/engine_dates.py",
    "work/archive_information_country_records_localization.py",
    "work/document_information_country_records_localization.py",
    "work/verify_information_country_records_localization_documents.py",
    "work/update_information_country_records_localization_coverage.py",
    "work/run_information_country_records_localization_regression.py",
    "docs/选定关系与修正文本接口.md",
    "docs/信息字段覆盖.json",
    "docs/信息导出与订阅开发计划.md",
    "docs/信息导出开发进展.md",
    "docs/信息接口使用说明.md",
    "HANDOFF.md",
    "README(agent).md",
)

_SOURCE_PATTERNS = (
    "bridge/tests/test_information_relation*.py",
    "bridge/tests/test_information_country_record_localization*.py",
    "work/*information_relation*.py",
    "work/*country_record_localization*.py",
)

_GENERATED_JSON = {
    "coverage-matrix-before-001.json",
    "coverage-update-001.json",
    "development-summary-001.json",
    "regression-added-cases-from-full-001.json",
    "regression-comparison-001.json",
    "runtime-source-pins-before-001.json",
    "runtime-source-pins-after-001.json",
}
_ABORTED_REGRESSION_LOG = STAGE / "regression-full-001.log"
_ABORTED_REGRESSION_XML = STAGE / "regression-full-001.xml"


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def pin(path: Path) -> dict:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": sha(path),
    }


def read(path: Path):
    return json.loads(path.read_bytes())


def write(name: str, value) -> None:
    target = STAGE / name
    with target.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def _case_key(case) -> str:
    return f"{case.get('classname')}::{case.get('name')}"


def tests(path: Path):
    cases = ET.parse(path).getroot().findall(".//testcase")
    bad = {
        _case_key(case)
        for case in cases
        if case.findall("failure") or case.findall("error")
    }
    occurrences = sum(
        len(case.findall("failure")) + len(case.findall("error"))
        for case in cases
    )
    return cases, bad, occurrences


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


def regression() -> dict:
    xml = STAGE / f"{REGRESSION_BASENAME}.xml"
    log = STAGE / f"{REGRESSION_BASENAME}.log"
    cases, bad, occurrences = tests(xml)
    old_cases, old_bad, old_occurrences = tests(
        BASELINE / f"{BASELINE_REGRESSION_BASENAME}.xml"
    )
    line = _summary_line(log)
    old_keys = {_case_key(case) for case in old_cases}
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
        "baseline_failure_error_occurrences": old_occurrences,
        "baseline_unique_failure_error_nodes": len(old_bad),
        "baseline_case_count": len(old_cases),
        "current_case_count": len(cases),
        "case_set_changed": old_keys != {_case_key(case) for case in cases},
    }


def pin_before() -> None:
    if not STAGE.is_dir():
        raise AssertionError(f"stage missing: {STAGE}")
    target = STAGE / "runtime-source-pins-before-001.json"
    if target.exists():
        raise AssertionError("batch53 source pins already exist")
    missing = [relative for relative in RUNTIME_PATHS if not (ROOT / relative).is_file()]
    if missing:
        raise AssertionError("runtime source missing: " + ", ".join(missing))
    write(
        target.name,
        {
            "schema": "information_runtime_source_pins.v1",
            "batch": 53,
            "baseline_stage": BASELINE.relative_to(ROOT).as_posix(),
            "timing": "after targeted checks and before live acceptance/full regression",
            "continuous_monitoring_claimed": False,
            "files": [pin(ROOT / relative) for relative in RUNTIME_PATHS],
        },
    )


def _source_paths() -> tuple[str, ...]:
    paths = list(RUNTIME_PATHS) + list(_CORE_SOURCE_PATHS)
    for pattern in _SOURCE_PATTERNS:
        paths.extend(
            path.relative_to(ROOT).as_posix()
            for path in sorted(ROOT.glob(pattern))
            if path.is_file()
        )
    return tuple(dict.fromkeys(relative for relative in paths if (ROOT / relative).is_file()))


def _evidence_paths() -> tuple[Path, ...]:
    return tuple(
        path
        for path in sorted(STAGE.rglob("*.json"))
        if path.name not in _GENERATED_JSON and "source-snapshot" not in path.parts
    )


def _verify_before() -> tuple[dict, list[dict]]:
    before = read(STAGE / "runtime-source-pins-before-001.json")
    after = []
    for item in before.get("files", []):
        path = ROOT / item["path"]
        if not path.is_file():
            raise AssertionError(f"pinned source disappeared: {path}")
        after.append(dict(pin(path), matches_before=sha(path) == item.get("sha256")))
    if not after or not all(item["matches_before"] for item in after):
        raise AssertionError("a frozen batch53 runtime source changed")
    return before, after


def _require_live_and_docs() -> tuple[dict, dict]:
    live = read(STAGE / "live-acceptance-001/report.json")
    if live.get("status") != "passed" or live.get("server_exit_code") != 0:
        raise AssertionError("localized relation live acceptance did not pass")
    if live.get("r01_uses_read_only_native_game_queries") is not True:
        raise AssertionError("R01 read-only native query fact is missing or false")
    checks = live.get("checks")
    if isinstance(checks, dict) and not all(checks.values()):
        raise AssertionError("localized relation live acceptance contains a failed check")
    document = read(STAGE / "document-verification-001.json")
    if document.get("status") != "passed":
        raise AssertionError("localized relation document verification did not pass")
    if document.get("new_game_queries_or_pytest_runs") != 0:
        raise AssertionError("document verification performed an unapproved run")
    return live, document


def _coverage_changes(coverage: dict) -> set[tuple[str, str]]:
    return {
        (item.get("topic"), item.get("field"))
        for item in coverage.get("coverage_changes", [])
    }


def _aborted_regression_receipt() -> dict:
    """Record the accidental ``--help`` run without treating it as a suite."""

    result = {
        "status": "aborted_before_completion",
        "command": "python work/run_information_country_records_localization_regression.py --help",
        "reason": (
            "The pre-argparse runner treated --help as its normal entry and started pytest; "
            "the process was force-stopped before pytest completed."
        ),
        "usable_as_full_regression": False,
        "xml_exists": _ABORTED_REGRESSION_XML.exists(),
        "log_exists": _ABORTED_REGRESSION_LOG.exists(),
    }
    if _ABORTED_REGRESSION_LOG.is_file():
        result["log"] = pin(_ABORTED_REGRESSION_LOG)
    if _ABORTED_REGRESSION_XML.is_file():
        result["xml"] = pin(_ABORTED_REGRESSION_XML)
    return result


def main() -> None:
    if not STAGE.is_dir() or not BASELINE.is_dir():
        raise AssertionError("batch53 stage or batch52 baseline is missing")
    before, after = _verify_before()
    live, document = _require_live_and_docs()

    comparison = regression()
    if comparison["full"]["new_failure_nodes"]:
        raise AssertionError(comparison["full"]["new_failure_nodes"])
    if comparison["new_tests"]["failure_error_occurrences"]:
        raise AssertionError("a newly added batch53 test failed")

    coverage_path = STAGE / "coverage-update-001.json"
    if not coverage_path.exists():
        raise AssertionError("batch53 coverage update receipt is missing")
    coverage = read(coverage_path)
    expected_fields = {
        ("N07", "name"),
        ("N07", "description"),
        ("R01", "relation_type"),
        ("R01", "status"),
        ("R01", "grantor"),
        ("R01", "recipient"),
    }
    if _coverage_changes(coverage) != expected_fields:
        raise AssertionError(
            f"unexpected localized relation coverage changes: {_coverage_changes(coverage)}"
        )
    if coverage.get("loan_coverage_unchanged") is not True:
        raise AssertionError("N01 loans coverage was not explicitly preserved")

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
            "schema": "information_country_records_localization_regression_comparison.v1",
            "full": comparison["full"],
            "baseline": pin(BASELINE / f"{BASELINE_REGRESSION_BASENAME}.xml"),
            "baseline_failure_error_occurrences": comparison[
                "baseline_failure_error_occurrences"
            ],
            "baseline_unique_failure_error_nodes": comparison[
                "baseline_unique_failure_error_nodes"
            ],
            "baseline_case_count": comparison["baseline_case_count"],
            "current_case_count": comparison["current_case_count"],
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
    required = {
        "relation-projection-contract-001.json",
        "relation-direction-source-001.json",
        "modifier-localization-contract-001.json",
    }
    if not required <= {path.name for path in evidence}:
        raise AssertionError("batch53 relation/localization evidence is incomplete")

    previous = read(BASELINE / "development-summary-001.json")
    current_witnesses = []
    for name in ("before-control.json", "after-control.json"):
        path = STAGE / "live-acceptance-001" / name
        if path.exists():
            current_witnesses.append(pin(path))
    reference = next(
        (path for path in evidence if "reference" in path.name.lower()), evidence[0]
    )
    artifact_paths = [
        path
        for path in sorted(STAGE.rglob("*"))
        if path.is_file() and "source-snapshot" not in path.parts
    ]
    summary = {
        "schema": "information_development_summary.v1",
        "batch": 53,
        "status": "implemented_country_records_localization_relation_partial",
        "objective": previous.get("objective"),
        "goal_complete": False,
        "goal_status": "active",
        "scope": previous.get("scope"),
        "previous_goal_turn_classification": "progress",
        "delivered": {
            "topics": {
                "N07": ["name", "description"],
                "R01": ["relation_type", "status", "grantor", "recipient"],
            },
            "coverage_changes": coverage.get("coverage_changes", []),
            "coverage": coverage.get("counts"),
            "actual_live_counts": coverage.get("actual_live_counts"),
            "loan_coverage": (
                "N01.loans remains partial; this batch preserves that coverage while carrying "
                "lender/calendar enhancements and adding localization/relationship metadata"
            ),
            "complete": False,
        },
        "runtime_validation": live,
        "documentation_validation": document,
        "coverage": coverage,
        "tests": {
            "full": comparison["full"],
            "new_tests": comparison["new_tests"],
            "counts_not_additive": True,
            "regression_001_incident": _aborted_regression_receipt(),
        },
        "runtime_identity": previous.get("runtime_identity"),
        "runtime_profile_pins": [
            pin(ROOT / relative)
            for relative in RUNTIME_PATHS
            if "profiles/" in relative and (ROOT / relative).is_file()
        ],
        "current_identity_witnesses": current_witnesses,
        "independent_reference": pin(reference),
        "inherited_batch52_sources": {
            "stage": BASELINE.relative_to(ROOT).as_posix(),
            "summary": pin(BASELINE / "development-summary-001.json"),
        },
        "validation": {
            "business_actions_submitted": live.get("business_actions_submitted"),
            "r01_uses_read_only_native_game_queries": live.get(
                "r01_uses_read_only_native_game_queries"
            ),
            "save_restart_or_date_advance": live.get("save_restart_or_date_advance"),
            "source_pins_before_after_match": True,
            "outbox": live.get("outbox"),
            "llm_read": "unknown",
            "new_REA_analysis": False,
            "historical_reference_reanalysis_is_not_original_capture": True,
        },
        "ownership": {
            "scope": "batch53 commands and deliverables; next-batch source research is tracked separately",
            "commands": "terminal",
            "workers": "terminal",
            "subscriptions": "cancelled/no active subscription",
            "MCP_servers": "exited0",
        },
        "next_work": {
            "N07": "modifier names and descriptions remain literal-cache/partial; UI binding and dynamic templates remain gaps",
            "R01": "selected country pair only; generic role direction, alliance/royal current state, enumeration and expiry remain gaps",
            "N01": "loans content and partial coverage are preserved",
            "full_scope": "All74topics397fields and phases2/3/4 remain active",
        },
        "source_evidence": [pin(path) for path in evidence],
        "source_snapshots": snapshots,
        "artifact_pins": [pin(path) for path in artifact_paths],
    }
    write("development-summary-001.json", summary)
    if not all(sha(ROOT / item["path"]) == item["sha256"] for item in summary["artifact_pins"]):
        raise AssertionError("an archived batch53 artifact changed after pinning")
    print(
        json.dumps(
            {
                "summary": pin(STAGE / "development-summary-001.json"),
                "full": comparison["full"],
                "new_cases": comparison["new_tests"]["cases"],
                "artifacts": len(summary["artifact_pins"]),
                "snapshots": len(snapshots),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pin-before", action="store_true")
    args = parser.parse_args()
    if args.pin_before:
        pin_before()
    else:
        main()
