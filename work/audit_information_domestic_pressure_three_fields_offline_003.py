"""Audit the version-three three-field N04 contract while withholding live evidence.

The wrapper reads the versioned three-field test summary, current profile and
corrected contract, validates the static guard and merged catalog, compiles
bounded source files, and checks historical manifest pins.  It never reads a
game process, runs pytest, invokes MCP/RPM/REA, or creates a live fixture.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import py_compile
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.information.domestic_pressure_memory import _static_contract_guard  # noqa: E402
from work.verify_information_domestic_pressure import (  # noqa: E402
    EXPECTED_CATALOG,
    FIELDS,
    MAX_FILE_BYTES,
    MAX_PROFILE_BYTES,
    VerificationError,
    bounded_file,
    build_catalog,
    digest,
    read_json,
    validate_static_profiles,
)


STAGE = ROOT / "work/runtime/information-domestic-pressure-20261025-001"
PROFILE = ROOT / "bridge/information/profiles/domestic-pressure-memory-1374.json"
CONTRACT = STAGE / "native-domestic-pressure-contract-003.json"
SUMMARY = STAGE / "test-summary-003.json"
EXPECTED_PROFILE_SHA256 = "b727bcd112ace025fcbc0fce78e6194cbb5055642ff12fd85280356e8347d9fd"
EXPECTED_PROFILE_BYTES = 60428
EXPECTED_CONTRACT_SHA256 = "902bef470421f8abe3ac4636ce13cb2d2c57f60e2985fcc7c40a28ca89bcaeaf"
NATIVE_FIELDS = ("stability", "war_exhaustion", "corruption")
PLANNED_FIELDS = ("religious_unity", "overextension", "unrest")
PRESERVED_MANIFESTS = (
    (
        "work/runtime/information-country-scalars-20261024-001/delivery/manifest.json",
        "01bf780b08d13dab03c5c3de166fa9eb06114063ef5ac895face01a32e5e78b1",
        "batch-nine manifest",
    ),
    (
        "work/runtime/information-country-relations-20261024-001/delivery/manifest.json",
        "b24cf0c61c56a95e36621d764080a4f9c22025649970c9cfdfafe96927e2e6f7",
        "batch-eight manifest",
    ),
    (
        "work/runtime/information-dynamic-text-20261024-001/delivery/manifest.json",
        "c2feea2e334fb1796541956d440c55237451cf32d49d486b34c7ce06b8b6aafe",
        "batch-seven manifest",
    ),
)


def _record(path: Path, *, role: str, expected: str | None = None) -> dict[str, Any]:
    source = bounded_file(path)
    actual = digest(source)
    if expected is not None and actual != expected:
        raise VerificationError(f"artifact_sha_changed:{role}:{source}")
    return {"path": source.relative_to(ROOT.resolve()).as_posix(), "sha256": actual,
            "bytes": source.stat().st_size, "role": role}


def _write_new(path: Path, value: Any) -> None:
    destination = path.resolve()
    if not destination.is_relative_to(ROOT.resolve()):
        raise VerificationError(f"output_outside_workspace:{destination}")
    if destination.exists():
        raise FileExistsError(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(raw) > 16 * 1024 * 1024:
        raise VerificationError(f"audit_output_over_limit:{destination}")
    destination.write_bytes(raw)


def _source_pin_check(summary: dict[str, Any]) -> list[dict[str, Any]]:
    pins = summary.get("source_files")
    if not isinstance(pins, dict) or not pins:
        raise VerificationError("test_summary_source_files_missing")
    checked = []
    for name, item in pins.items():
        if not isinstance(item, dict):
            raise VerificationError(f"test_summary_source_pin_invalid:{name}")
        path = item.get("path", name)
        expected = item.get("sha256")
        if not isinstance(path, str) or not isinstance(expected, str):
            raise VerificationError(f"test_summary_source_pin_incomplete:{name}")
        checked.append(_record(ROOT / path, role=f"test-summary source:{name}", expected=expected))
    return checked


def _validate_summary(summary: dict[str, Any]) -> dict[str, Any]:
    if summary.get("schema") != "information-domestic-pressure-three-fields-regression-audit-v2":
        raise VerificationError("three_field_test_summary_schema_changed")
    scope = summary.get("field_scope")
    if not isinstance(scope, dict) or scope.get("native_fields") != list(NATIVE_FIELDS):
        raise VerificationError("three_field_test_summary_scope_changed")
    if scope.get("planned_fields") != list(PLANNED_FIELDS) or scope.get("native_coverage") != "partial":
        raise VerificationError("three_field_test_summary_planned_scope_changed")
    information = summary.get("information")
    if not isinstance(information, dict):
        raise VerificationError("three_field_test_summary_information_missing")
    statuses = information.get("case_element_statuses")
    if not isinstance(statuses, dict) or type(statuses.get("passed")) is not int:
        raise VerificationError("three_field_information_status_missing")
    if statuses.get("failure", 0) or statuses.get("error", 0) or statuses.get("skipped", 0):
        raise VerificationError("three_field_information_tests_not_clean")
    if statuses["passed"] != 546:
        raise VerificationError(f"three_field_information_test_pass_count_changed:{statuses['passed']}")
    targeted = summary.get("targeted_domestic_pressure_checkpoint")
    if not isinstance(targeted, dict) or targeted.get("status") != "passed":
        raise VerificationError("three_field_targeted_checkpoint_not_passed")
    targeted_status = targeted.get("case_element_statuses")
    if not isinstance(targeted_status, dict) or targeted_status.get("failure", 0) or targeted_status.get("error", 0):
        raise VerificationError("three_field_targeted_checkpoint_not_clean")
    if targeted_status.get("passed") != 546:
        raise VerificationError(f"three_field_targeted_test_pass_count_changed:{targeted_status.get('passed')}")
    if summary.get("live_validation", {}).get("status") != "pending":
        raise VerificationError("three_field_live_status_must_remain_pending")
    return {"information": statuses, "targeted": targeted_status,
            "source_files": _source_pin_check(summary)}


def _validate_profiles_and_contract() -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    if PROFILE.stat().st_size != EXPECTED_PROFILE_BYTES or digest(PROFILE) != EXPECTED_PROFILE_SHA256:
        raise VerificationError("domestic_profile_version3_pin_changed")
    if digest(CONTRACT) != EXPECTED_CONTRACT_SHA256:
        raise VerificationError("domestic_contract003_pin_changed")
    profile_groups = validate_static_profiles(PROFILE, CONTRACT)
    if len(profile_groups) != 7:
        raise VerificationError(f"profile_count_changed:{len(profile_groups)}")
    references = sum(len(group.get("references", [])) for group in profile_groups)
    if references != 80:
        raise VerificationError(f"profile_reference_count_changed:{references}")
    current = next((group for group in profile_groups
                    if group.get("profile_id") == "domestic-pressure-memory-1374"), None)
    if not isinstance(current, dict):
        raise VerificationError("current_domestic_profile_missing")
    profile = read_json(PROFILE, max_bytes=MAX_PROFILE_BYTES)
    if not isinstance(profile, dict) or profile.get("profile_version") != 3:
        raise VerificationError("domestic_profile_version_changed")
    contract = read_json(CONTRACT, max_bytes=MAX_FILE_BYTES)
    if not isinstance(contract, dict) or contract.get("contract_id") != "native-domestic-pressure-contract-003":
        raise VerificationError("corrected_domestic_contract_changed")
    fields = contract.get("fields")
    if not isinstance(fields, dict) or set(fields) != set(NATIVE_FIELDS):
        raise VerificationError("corrected_contract_field_set_changed")
    excluded = contract.get("excluded_fields")
    if not isinstance(excluded, dict) or set(excluded) != {"religious_unity", "overextension", "unrest"}:
        raise VerificationError("corrected_contract_exclusion_set_changed")
    return profile_groups, current, {
        "path": CONTRACT.relative_to(ROOT.resolve()).as_posix(),
        "sha256": digest(CONTRACT),
        "bytes": CONTRACT.stat().st_size,
        "contract_id": contract["contract_id"],
        "excluded_fields": sorted(excluded),
    }


def _validate_catalog() -> dict[str, Any]:
    catalog = build_catalog()
    if {key: catalog.get(key) for key in EXPECTED_CATALOG} != EXPECTED_CATALOG:
        raise VerificationError("catalog_counts_changed")
    topics = catalog.get("topics")
    if not isinstance(topics, list):
        raise VerificationError("catalog_topics_missing")
    n04 = next((item for item in topics if isinstance(item, dict) and item.get("topic_id") == "N04"), None)
    if not isinstance(n04, dict) or n04.get("status") != "available":
        raise VerificationError("N04_catalog_not_available")
    fields = n04.get("fields")
    expected_fields = set(NATIVE_FIELDS) | set(PLANNED_FIELDS)
    if not isinstance(fields, dict) or set(fields) != expected_fields:
        raise VerificationError("N04_catalog_six_field_set_changed")
    for field in NATIVE_FIELDS:
        item = fields[field]
        if item.get("coverage") != "partial":
            raise VerificationError(f"N04_catalog_native_coverage_changed:{field}")
    for field in PLANNED_FIELDS:
        if fields[field].get("coverage") != "planned":
            raise VerificationError(f"N04_catalog_planned_coverage_changed:{field}")
    return {
        "schema_version": 3,
        "topic_count": catalog["topic_count"],
        "field_count": catalog["field_count"],
        "available_topic_count": catalog["available_topic_count"],
        "field_counts": catalog["field_counts"],
        "topic_id": "N04",
        "status": n04["status"],
        "native_fields": {field: fields[field] for field in NATIVE_FIELDS},
        "planned_fields": {field: fields[field] for field in PLANNED_FIELDS},
        "catalog_is_not_live_acceptance": True,
    }


def _compile_sources() -> list[dict[str, Any]]:
    candidates = set((ROOT / "bridge/information").glob("*.py"))
    candidates.update((ROOT / "bridge/tests").glob("test_information*.py"))
    candidates.add(ROOT / "tools/serve_information.py")
    candidates.update((ROOT / "work").glob("*domestic_pressure*.py"))
    candidates.update((ROOT / "work").glob("*religious_unity*.py"))
    sources = [_record(path, role="compile source") for path in sorted(candidates)]
    with tempfile.TemporaryDirectory(prefix="information-domestic-pressure-three-fields-") as temp:
        target = Path(temp)
        for index, item in enumerate(sources):
            py_compile.compile(str(ROOT / item["path"]), cfile=str(target / f"{index}.pyc"), doraise=True)
    return sources


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, default=STAGE)
    parser.add_argument("--test-summary", type=Path, default=SUMMARY)
    parser.add_argument("--profile", type=Path, default=PROFILE)
    parser.add_argument("--contract", type=Path, default=CONTRACT)
    args = parser.parse_args(argv)
    stage = args.stage.resolve()
    if not stage.is_relative_to(ROOT.resolve()) or not stage.is_dir():
        raise VerificationError(f"stage_directory_required:{stage}")
    summary_path = args.test_summary.resolve()
    profile_path = args.profile.resolve()
    contract_path = args.contract.resolve()
    if summary_path != SUMMARY.resolve():
        raise VerificationError("test_summary_must_be_version_003")
    if profile_path != PROFILE.resolve() or contract_path != CONTRACT.resolve():
        raise VerificationError("profile_or_contract_path_changed")
    summary = read_json(summary_path)
    summary_check = _validate_summary(summary)
    profile_groups, current_profile, contract = _validate_profiles_and_contract()
    guard = _static_contract_guard()
    if guard.get("status") != "observed" or guard.get("unknown_conditions"):
        raise VerificationError("native_reader_static_contract_not_observed")
    if guard.get("profile_sha256") != current_profile.get("sha256"):
        raise VerificationError("static_guard_profile_sha_mismatch")
    coverage = _validate_catalog()
    compiled = _compile_sources()
    preserved = [_record(ROOT / path, role=role, expected=expected)
                 for path, expected, role in PRESERVED_MANIFESTS]
    report = {
        "schema": "information-domestic-pressure-three-fields-offline-source-audit-v3",
        "status": "offline_checks_passed_live_pending",
        "goal_complete": False,
        "native_capture_available": False,
        "live_mcp_accepted": False,
        "delivery_created": False,
        "field_scope": {
            "native_fields": list(NATIVE_FIELDS),
            "planned_fields": list(PLANNED_FIELDS),
            "native_coverage": "partial",
        },
        "profiles": profile_groups,
        "profile_count": len(profile_groups),
        "profile_reference_occurrences": sum(len(group.get("references", [])) for group in profile_groups),
        "current_profile": current_profile,
        "corrected_contract": contract,
        "native_reader_static_contract": guard,
        "coverage": coverage,
        "compiled_sources": compiled,
        "compiled_source_count": len(compiled),
        "test_summary": _record(summary_path, role="three-field test summary"),
        "test_summary_checks": summary_check,
        "preserved_manifests": preserved,
        "limitations": [
            "The three native fields remain partial until a fresh process capture and live MCP acceptance are available.",
            "religious_unity is explicitly planned; its EE0 province component is not published as final unity.",
            "This audit compiles and reads bounded artifacts only; it does not run pytest, game, RPM, MCP, or REA.",
            "Historical batch-seven, batch-eight, and batch-nine manifests are pinned and not copied recursively.",
        ],
    }
    _write_new(stage / "coverage-pending-003.json", coverage)
    _write_new(stage / "offline-source-audit-003.json", report)
    print(json.dumps({
        "status": report["status"],
        "profile_count": report["profile_count"],
        "profile_reference_occurrences": report["profile_reference_occurrences"],
        "compiled_source_count": report["compiled_source_count"],
        "catalog_counts": {key: coverage[key] for key in ("topic_count", "field_count", "available_topic_count", "field_counts")},
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
