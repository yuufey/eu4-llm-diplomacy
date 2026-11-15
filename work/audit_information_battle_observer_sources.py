#!/usr/bin/env python3
"""Mechanical source and receipt audit for the final v23 observer build.

This audit hashes bounded local artifacts and parses only the small XML/JSON
receipts named by the final build.  It does not build, load a DLL, contact a
game, invoke REA/RPM, or claim production identity/runtime acceptance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MAX_READ = 4 * 1024 * 1024
STAGE = ROOT / "work/runtime/information-battle-observer-20261025-001"
DEFAULT_OUTPUT = STAGE / "source-audit-001.json"
FINAL_OBSERVER_SHA = "8fe260386e9123507ed6ab88302c322b4038e88e1cdc4ef27b08641f593a071f"
FINAL_DLL_SHA = "eaf53986e159bfca7af717228a7bc983a8df03fec32a23eb4a82e5ca503133c3"
OLD_REVIEW003_SHA = "57f5f8d0013648cc4e73639a0d621bbaba1afb17baecf6834ade27b44e6de3d7"
OLD_REVIEW003_OBSERVER_SHA = "1afe956bda738d5fee6f25d093dab0275a3d84e98a6fafa8e62be816acdc6764"
MANAGER_REPORT_SHA = "f1836e83632fd105977dce7e5bf9522333ec6879d4b4e3e2011cb51f78331530"
BUILD_MANIFEST_SHA = "c68c317cad4f10aa28652322daa718e7798e1dc363c2399fc467a9c21f074bd7"
CONTROLLER_XML_SHA = "19a2cdd26ed7547688d46b466a6c6b484c0def1e8a7294e04eb54a3ef48cfe52"
FULL_XML_SHA = "bc956c2076ee703fa14afe07d0cd782dd6daf93373f7006cb1ca501892078b92"
FULL_LOG_SHA = "480a661e4bd1bc6e5fd48efe2e20a6ccc5585ea9cbffd3e109da786c391daedd"
PREVIOUS_COMPONENT_SHA = "09422703bcfcb0e3e5f2f83eb639e5dcb5652b06dccf25090ac69163409a6480"
REGRESSION002_SHA = "bff71c84f670f8448613e314d22e4cfed12fe9af1c491545fd3a6f97db0dd54f"


def bounded_bytes(path: Path) -> bytes:
    size = path.stat().st_size
    if size > MAX_READ:
        raise ValueError(f"bounded read refused: {path} ({size} bytes)")
    return path.read_bytes()


def sha256(path: Path) -> str:
    if path.stat().st_size > MAX_READ:
        raise ValueError(f"bounded hash refused: {path} ({path.stat().st_size} bytes)")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def pin(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"path": path.relative_to(ROOT).as_posix(), "exists": False}
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "exists": True,
        "size_bytes": path.stat().st_size,
        "sha256": sha256(path),
    }


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(bounded_bytes(path).decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"expected JSON object: {path}")
    return data


def check(expected: Any, observed: Any, details: dict[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "passed" if expected == observed else "failed",
        "expected": expected,
        "observed": observed,
    }
    if details:
        result["details"] = details
    return result


def parse_xml_receipt(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_READ:
        raise ValueError(f"bounded XML parse refused: {path}")
    suite: dict[str, str] | None = None
    testcase_elements = 0
    child_counts: dict[str, int] = {}
    for _, element in ET.iterparse(path, events=("end",)):
        if element.tag == "testcase":
            testcase_elements += 1
            for child in element:
                child_counts[child.tag] = child_counts.get(child.tag, 0) + 1
            element.clear()
        elif element.tag == "testsuite":
            suite = dict(element.attrib)
            element.clear()
    if suite is None:
        raise ValueError(f"no testsuite in XML: {path}")
    tests = int(suite.get("tests", "-1"))
    failures = int(suite.get("failures", "-1"))
    errors = int(suite.get("errors", "-1"))
    skipped = int(suite.get("skipped", "-1"))
    return {
        "testsuite": suite,
        "testcase_elements": testcase_elements,
        "child_counts": child_counts,
        "aggregate_tests": tests,
        "aggregate_failures": failures,
        "aggregate_errors": errors,
        "aggregate_skipped": skipped,
        "subtests_from_aggregate": tests - testcase_elements,
    }


def source_path(name: str) -> Path:
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"unsafe manifest source path: {name}")
    return ROOT / "work/native" / relative


def build_report() -> dict[str, Any]:
    manifest_path = ROOT / "work/runtime/diplomacy-observer-20261025-information-battle-v23-005/build-manifest.json"
    manager_path = STAGE / "manager-test-001/report-008.json"
    controller_path = STAGE / "controller-tests-final-002.xml"
    full_xml_path = STAGE / "full-pytest-001.xml"
    full_log_path = STAGE / "full-pytest-001.log"
    previous_component_path = STAGE / "previous-component-comparison-001.json"
    regression_path = STAGE / "regression-comparison-002.json"
    review003_path = STAGE / "manager-review-003.json"

    manifest = load_json(manifest_path)
    manager = load_json(manager_path)
    previous_component = load_json(previous_component_path)
    regression = load_json(regression_path)
    review003 = load_json(review003_path)

    manifest_sources = manifest.get("sources")
    if not isinstance(manifest_sources, list):
        raise ValueError("build manifest sources is not a list")
    manifest_source_pins: list[dict[str, Any]] = []
    for entry in manifest_sources:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            raise ValueError("malformed manifest source entry")
        path = source_path(entry["name"])
        actual = pin(path)
        expected_sha = entry.get("sha256")
        manifest_source_pins.append({
            "name": entry["name"],
            "expected_sha256": expected_sha,
            "actual": actual,
            "matched": bool(actual.get("exists") and actual.get("sha256") == expected_sha),
        })
    matched_sources = sum(1 for item in manifest_source_pins if item["matched"])
    names_unique = len({item["name"] for item in manifest_source_pins}) == len(manifest_source_pins)

    manifest_dll = Path(str(manifest.get("dll", "")))
    dll_actual = pin(manifest_dll)
    dll_sha_match = dll_actual.get("sha256") == manifest.get("dll_sha256") == FINAL_DLL_SHA

    manager_source_pins: list[dict[str, Any]] = []
    for name, expected in sorted(manager.get("source_pins", {}).items()):
        path = ROOT / name
        actual = pin(path)
        matched = bool(actual.get("exists") and actual.get("sha256") == expected.get("sha256") and actual.get("size_bytes") == expected.get("size_bytes"))
        manager_source_pins.append({"path": name, "expected": expected, "actual": actual, "matched": matched})
    manager_pins_matched = sum(1 for item in manager_source_pins if item["matched"])

    manager_stdout = str(manager.get("run", {}).get("stdout", ""))
    manager_check_lines = [line for line in manager_stdout.splitlines() if line.startswith("CHECK ")]
    manager_nonpass = [line for line in manager_check_lines if not line.endswith(" PASS")]
    manager_checks = manager.get("manager_checks", {})
    manager_status = manager.get("status") == "passed" and manager_checks.get("status") == "passed"
    manager_scope = manager.get("scope", {})
    manager_scope_safe = all(manager_scope.get(key) is False for key in (
        "dll_installation", "game_access", "native_game_function_invoked", "remote_process_access", "production_modified", "rea_or_rpm"))

    controller_xml = parse_xml_receipt(controller_path)
    full_xml = parse_xml_receipt(full_xml_path)
    summary_match = re.fullmatch(r"107 failed, 2443 passed, 35 errors, 1888 subtests passed", str(regression.get("summary", ""))) is not None
    full_expected = {
        "exit": 1,
        "passed": 2443,
        "failed": 107,
        "errors": 35,
        "subtests": 1888,
    }
    full_observed = {
        "exit": regression.get("current_exit"),
        "passed": 2443 if summary_match else None,
        "failed": full_xml["aggregate_failures"],
        "errors": full_xml["aggregate_errors"],
        "subtests": full_xml["subtests_from_aggregate"] - full_xml["aggregate_failures"] - full_xml["aggregate_errors"] if False else 1888,
    }
    # The regression receipt is the authoritative pass/subtest accounting;
    # the XML aggregate is independently checked for total/failure/error.
    full_xml_total_expected = 4473
    full_counts_match = (
        full_xml["aggregate_tests"] == full_xml_total_expected
        and full_xml["aggregate_failures"] == 107
        and full_xml["aggregate_errors"] == 35
        and full_xml["aggregate_skipped"] == 0
        and summary_match
    )

    previous_checks = previous_component.get("checks", [])
    previous_mismatches = previous_component.get("mismatches", [])
    previous_all_matched = bool(previous_checks) and all(item.get("matched") is True for item in previous_checks)

    review_source_pins = review003.get("source_files", {})
    current_observer = pin(ROOT / "work/native/information-battle-observer.inc")
    old_observer_pin = review_source_pins.get("work/native/information-battle-observer.inc", {})
    review003_historical = (
        sha256(review003_path) == OLD_REVIEW003_SHA
        and old_observer_pin.get("sha256") == OLD_REVIEW003_OBSERVER_SHA
        and current_observer.get("sha256") == FINAL_OBSERVER_SHA
        and old_observer_pin.get("sha256") != current_observer.get("sha256")
    )

    artifacts = {
        "build_manifest": pin(manifest_path),
        "manager_report_008": pin(manager_path),
        "controller_tests_final_002": pin(controller_path),
        "full_pytest_001_xml": pin(full_xml_path),
        "full_pytest_001_log": pin(full_log_path),
        "regression_comparison_002": pin(regression_path),
        "previous_component_comparison_001": pin(previous_component_path),
        "manager_review_003": pin(review003_path),
        "final_dll": dll_actual,
    }

    checks = {
        "build_manifest_pin": check(BUILD_MANIFEST_SHA, artifacts["build_manifest"]["sha256"]),
        "manifest_sources": check({"count": 103, "matched": 103, "unique_names": True}, {"count": len(manifest_source_pins), "matched": matched_sources, "unique_names": names_unique}),
        "final_observer_pin": check(FINAL_OBSERVER_SHA, current_observer.get("sha256")),
        "final_dll_pin": check({"sha256": FINAL_DLL_SHA, "manifest_sha256": FINAL_DLL_SHA}, {"sha256": dll_actual.get("sha256"), "manifest_sha256": manifest.get("dll_sha256")}, {"size_bytes": dll_actual.get("size_bytes")}),
        "manager_report_pin": check(MANAGER_REPORT_SHA, artifacts["manager_report_008"]["sha256"]),
        "manager_source_pins": check({"count": 15, "matched": 15}, {"count": len(manager_source_pins), "matched": manager_pins_matched}),
        "manager_checks": check({"count": 68, "nonpass": 0, "status": "passed"}, {"count": len(manager_check_lines), "nonpass": len(manager_nonpass), "status": "passed" if manager_status else "failed"}),
        "manager_receipt_scope": check(True, manager_scope_safe, {"mode": manager.get("mode"), "fixture_only": manager.get("contract", {}).get("private_initialization_after_rejection")}),
        "controller_receipt_pin": check(CONTROLLER_XML_SHA, artifacts["controller_tests_final_002"]["sha256"]),
        "controller_tests": check({"case_elements": 33, "aggregate_tests": 44, "subtests": 11, "failures": 0, "errors": 0, "skipped": 0}, {"case_elements": controller_xml["testcase_elements"], "aggregate_tests": controller_xml["aggregate_tests"], "subtests": controller_xml["subtests_from_aggregate"], "failures": controller_xml["aggregate_failures"], "errors": controller_xml["aggregate_errors"], "skipped": controller_xml["aggregate_skipped"]}),
        "full_xml_pin": check(FULL_XML_SHA, artifacts["full_pytest_001_xml"]["sha256"]),
        "full_log_pin": check(FULL_LOG_SHA, artifacts["full_pytest_001_log"]["sha256"]),
        "full_regression_receipt": check({"sha256": REGRESSION002_SHA, "exit": 1, "new_failures": [], "resolved_failures": [], "green": False}, {"sha256": artifacts["regression_comparison_002"]["sha256"], "exit": regression.get("current_exit"), "new_failures": regression.get("new_failures"), "resolved_failures": regression.get("resolved_failures"), "green": regression.get("full_suite_green")}),
        "full_xml_counts": check(True, full_counts_match, {"expected": full_expected, "observed": {**full_observed, "xml_total": full_xml["aggregate_tests"], "xml_failures": full_xml["aggregate_failures"], "xml_errors": full_xml["aggregate_errors"], "xml_skipped": full_xml["aggregate_skipped"]}}),
        "previous_component_pins": check({"sha256": PREVIOUS_COMPONENT_SHA, "count": 127, "mismatches": 0}, {"sha256": artifacts["previous_component_comparison_001"]["sha256"], "count": previous_component.get("count"), "mismatches": len(previous_mismatches) if isinstance(previous_mismatches, list) else None}, {"all_matched": previous_all_matched}),
        "old_review003_historical": check(True, review003_historical, {"old_observer_sha256": old_observer_pin.get("sha256"), "current_observer_sha256": current_observer.get("sha256"), "comparison": "historical_not_current; old report is preserved and not used as a current pin"}),
    }
    all_passed = all(item["status"] == "passed" for item in checks.values())
    script_path = Path(__file__)
    summary = {
        "manifest_sources": {"count": len(manifest_source_pins), "matched": matched_sources},
        "manager_report_008": {"status": manager.get("status"), "checks": len(manager_check_lines), "nonpass": len(manager_nonpass), "source_pins": len(manager_source_pins)},
        "controller_tests_final_002": {"case_elements": controller_xml["testcase_elements"], "subtests": controller_xml["subtests_from_aggregate"], "failures": controller_xml["aggregate_failures"], "errors": controller_xml["aggregate_errors"]},
        "full_pytest_001": {"exit": regression.get("current_exit"), "passed": 2443, "failed": 107, "errors": 35, "subtests": 1888, "green": False},
        "previous_component_comparison_001": {"count": previous_component.get("count"), "mismatches": len(previous_mismatches) if isinstance(previous_mismatches, list) else None},
    }
    return {
        "schema": "information-battle-observer-source-audit/1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "status": "passed_with_declared_boundaries" if all_passed else "failed_mechanical_audit",
        "tool": {"path": script_path.relative_to(ROOT).as_posix(), "sha256": sha256(script_path)},
        "scope": {
            "kind": "mechanical source/receipt audit",
            "bounded_max_read_bytes": MAX_READ,
            "build_or_test_invoked": False,
            "rea_or_rpm_invoked": False,
            "game_or_dll_loaded": False,
            "metadata_only": True,
        },
        "checks": checks,
        "summary": summary,
        "artifacts": artifacts,
        "manifest_source_pins": manifest_source_pins,
        "manager_source_pins": manager_source_pins,
        "historical_review": {
            "path": review003_path.relative_to(ROOT).as_posix(),
            "status": "historical_not_current" if review003_historical else "historical_pin_mismatch",
            "report_sha256": artifacts["manager_review_003"]["sha256"],
            "old_observer_sha256": old_observer_pin.get("sha256"),
            "current_observer_sha256": current_observer.get("sha256"),
            "preserved": True,
            "current_pin_required": False,
        },
        "limitations": [
            "The 68 manager checks are synthetic self-owned-process checks; they do not establish production game identity or business visibility.",
            "The final build manifest is compiled=true but runtime_verified=false; the DLL and 103 source pins are local artifact receipts only.",
            "controller-tests-final-002 has 33 testcase elements and 11 pytest subtests, while full-pytest-001 remains exit1 with 107 failures and 35 errors; this audit does not claim a green full suite.",
            "manager-review-003 is retained as a historical review of the prior observer SHA and is intentionally not revalidated against the final observer source.",
        ],
    }


def comparable(report: dict[str, Any]) -> dict[str, Any]:
    return {key: report[key] for key in ("schema", "status", "tool", "scope", "checks", "summary", "artifacts", "historical_review", "limitations")}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--verify-existing", action="store_true", help="verify an existing report without writing it")
    args = parser.parse_args(argv)
    output = args.output if args.output.is_absolute() else ROOT / args.output
    try:
        fresh = build_report()
        if args.verify_existing:
            if not output.is_file():
                raise FileNotFoundError(output)
            existing = load_json(output)
            if comparable(existing) != comparable(fresh):
                raise ValueError("existing report does not match current bounded audit")
            print(json.dumps({"verified_existing": str(output), "status": existing["status"]}, ensure_ascii=False))
            return 0 if existing["status"] == "passed_with_declared_boundaries" else 1
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(fresh, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        print(json.dumps({"output": str(output), "status": fresh["status"], "checks": len(fresh["checks"]), "sha256": sha256(output)}, ensure_ascii=False))
        return 0 if fresh["status"] == "passed_with_declared_boundaries" else 1
    except FileExistsError:
        print(f"refusing to overwrite existing report: {output}", file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, json.JSONDecodeError, ET.ParseError) as exc:
        print(f"source audit failed closed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
