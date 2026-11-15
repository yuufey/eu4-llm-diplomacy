"""Validate and summarize the batch-93 bounded regression artifacts."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from work import verify_information_subsidies_public_bounded as runner  # noqa: E402


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def finalize(destination: Path) -> dict[str, Any]:
    frozen = runner.verify_sources()
    _baseline, _baseline_comparison, baseline_pins = runner._verify_parent()
    comparison = runner.read_json(runner.COMPARISON_REPORT)
    boundary = runner.read_json(runner.BOUNDARY_REPORT)
    postverify = runner.read_json(runner.POSTVERIFY_REPORT)

    comparison_pin = runner.pin(runner.COMPARISON_REPORT)
    boundary_pin = runner.pin(runner.BOUNDARY_REPORT)
    postverify_pin = runner.pin(runner.POSTVERIFY_REPORT)
    xml_pin = runner.pin(runner.FULL_XML)
    coverage = comparison.get("collection_coverage", {})
    _require(comparison.get("schema") == "information.subsidies_public.bounded_regression_comparison.v1",
             "comparison_schema_invalid")
    _require(comparison.get("batch") == 93 and comparison.get("revision") == "001",
             "comparison_batch_revision_invalid")
    _require(comparison.get("status") == "passed_no_new_bad"
             and comparison.get("no_new_bad") is True,
             "comparison_has_new_bad_occurrences")
    _require(comparison.get("freeze") == frozen["freeze"]
             and comparison.get("parent_baseline_full") == baseline_pins["baseline_xml"]
             and comparison.get("current") == xml_pin,
             "comparison_input_pins_invalid")
    _require(boundary.get("schema") == "information.subsidies_public.bounded_full_boundary.v1"
             and boundary.get("status") == "completed"
             and boundary.get("xml") == xml_pin
             and boundary.get("nodeid_coverage") == comparison.get("nodeid_coverage"),
             "full_boundary_incomplete_or_mismatched")
    _require(postverify.get("schema") == "information.subsidies_public.bounded_postverify.v1"
             and postverify.get("batch") == 93 and postverify.get("revision") == "001"
             and postverify.get("status") == comparison.get("status")
             and postverify.get("freeze") == frozen["freeze"]
             and postverify.get("regression_comparison") == comparison_pin
             and postverify.get("current_sources_match_snapshots") is True
             and postverify.get("no_new_bad") is True,
             "postverify_incomplete_or_mismatched")
    _require(coverage.get("status") == "complete"
             and coverage.get("expected_node_count") == coverage.get("executed_node_count")
             and comparison.get("nodeid_count") == coverage.get("executed_node_count")
             and coverage.get("missing_node_ids") == []
             and coverage.get("duplicate_node_ids") == [],
             "nodeid_coverage_incomplete")

    baseline_bad = runner.common.bad_cases(runner.BASELINE_XML)
    current_bad = runner.common.bad_cases(runner.FULL_XML)
    added = current_bad - baseline_bad
    resolved = baseline_bad - current_bad
    _require(sum(baseline_bad.values()) == 141,
             "accepted_baseline_counter_changed")
    _require(sum(current_bad.values()) == comparison.get("current_bad_occurrences")
             and runner.common.counter_rows(added) == comparison.get("new_bad")
             and runner.common.counter_rows(resolved) == comparison.get("resolved_bad")
             and not added,
             "canonical_bad_counter_mismatch")
    junit = runner.common.junit_summary(runner.FULL_XML)
    _require(junit == comparison.get("junit_summary"), "merged_junit_summary_mismatch")
    expected_whole_suite_passed = (
        comparison.get("part_returncode_nonzero") == []
        and junit.get("failures") == 0 and junit.get("errors") == 0
    )
    _require(comparison.get("whole_suite_passed") is expected_whole_suite_passed
             and postverify.get("whole_suite_passed") is expected_whole_suite_passed,
             "whole_suite_status_mismatch")
    terminal = comparison.get("terminal_totals", {})
    _require(all(type(terminal.get(key)) is int and terminal[key] >= 0
                 for key in ("passed", "failed", "errors", "subtests")),
             "terminal_summary_invalid")
    _require(type(comparison.get("whole_suite_passed")) is bool,
             "whole_suite_status_missing")

    result = {
        "schema": "information.subsidies_public.bounded_finalization.v1",
        "status": "passed_no_new_bad",
        "batch": 93,
        "revision": "001",
        "baseline": baseline_pins,
        "source_freeze": frozen["freeze"],
        "comparison": comparison_pin,
        "boundary": boundary_pin,
        "postverify": postverify_pin,
        "full_xml": xml_pin,
        "terminal_totals": terminal,
        "junit_summary": junit,
        "baseline_bad_occurrences": sum(baseline_bad.values()),
        "current_bad_occurrences": sum(current_bad.values()),
        "new_bad": runner.common.counter_rows(added),
        "resolved_bad": runner.common.counter_rows(resolved),
        "no_new_bad": True,
        "whole_suite_passed": comparison["whole_suite_passed"],
        "note": "Compared against the accepted batch-92 baseline; no-new-bad does not itself mean the current suite is all green.",
    }
    runner.write_new(destination, result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    runner.add_path_arguments(parser)
    parser.add_argument("--finalization-report")
    args = parser.parse_args(argv)
    runner.configure_paths(args)
    destination = (runner._workspace_path(args.finalization_report)
                   if args.finalization_report
                   else runner.STAGE / "regression-finalization-001.json")
    print(json.dumps(finalize(destination), ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
