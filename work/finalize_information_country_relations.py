"""Freeze the country-relation evidence and its offline source audit.

The final archive is intentionally blocked until this batch has a
``test-summary.json``.  It stores the native-query report and the separately
typed recorded-save cross-check as evidence; neither is relabeled as current
live state. Prior delivery manifests and exact pinned profile dependencies
are retained without recursively copying an older archive.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import shutil
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ROOT_RESOLVED = ROOT.resolve()
STAGE = ROOT / "work/runtime/information-country-relations-20261024-001"
PREVIOUS = ROOT / "work/runtime/information-dynamic-text-20261024-001/delivery/manifest.json"
PREVIOUS_SHA = "c2feea2e334fb1796541956d440c55237451cf32d49d486b34c7ce06b8b6aafe"
INSTALLATION = ROOT / "work/runtime/diplomacy-observer-20261024-information-a/installation.json"
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_PROFILE_BYTES = 64 * 1024
ARCHIVE_SUFFIXES = {".json", ".jsonl", ".xml", ".log", ".md", ".py", ".txt"}

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from work import verify_information_country_relations as checker


DOCS = (
    "HANDOFF.md",
    "README(agent).md",
    "docs/信息导出与订阅开发计划.md",
    "docs/信息导出开发进展.md",
    "docs/信息接口使用说明.md",
    "docs/信息服务合同.md",
    "docs/信息字段覆盖.json",
    "docs/LLM导出信息目录.md",
    "docs/国家资源信息接口.md",
    "docs/宗属关系信息接口.md",
    "docs/附庸接口与运行验收.md",
)
WORK_SCRIPTS = (
    "work/capture_information_country_relations.py",
    "work/validate_information_country_relations.py",
    "work/verify_information_country_relations_save.py",
    "work/verify_information_country_relations.py",
    "work/finalize_information_country_relations.py",
)
REQUIRED_FIXTURES = (
    "r73_favor_queries_real.json",
    "r74_economic_queries_real.json",
    "vassalization_r35_native_inspections.json",
)


def bounded_file(path: Path | str, *, max_bytes: int = MAX_ARCHIVE_BYTES) -> Path:
    """Resolve and validate a regular workspace file before reading it."""

    return checker.bounded_file(path, max_bytes=max_bytes)


def digest(path: Path | str, *, max_bytes: int = MAX_ARCHIVE_BYTES) -> str:
    return checker.digest(path, max_bytes=max_bytes)


def read_json(path: Path | str, *, max_bytes: int = MAX_ARCHIVE_BYTES) -> Any:
    return checker.read_json(path, max_bytes=max_bytes)


def _require_test_summary() -> tuple[Path, dict[str, Any]]:
    path = bounded_file(STAGE / "test-summary.json")
    summary = read_json(path)
    if not isinstance(summary, dict):
        raise ValueError("test-summary.json must be an object")
    information = summary.get("information")
    if not isinstance(information, dict):
        raise ValueError("test-summary.json has no information section")
    statuses = information.get("case_element_statuses")
    if not isinstance(statuses, dict):
        raise ValueError("test-summary.json has no information case statuses")
    if statuses.get("failure") != 0 or statuses.get("error") != 0:
        raise ValueError("Information tests are not clean; finalization is blocked")
    return path, summary


def _add_file(paths: set[Path], path: Path | str, *, required: bool = True) -> None:
    candidate = Path(path)
    if not candidate.exists():
        if required:
            raise ValueError(f"Required archive file is missing: {candidate}")
        return
    resolved = bounded_file(candidate)
    paths.add(resolved)


def _archive_paths(validation: dict[str, Any], test_summary_path: Path) -> set[Path]:
    """Collect the reviewed batch without traversing an old delivery archive."""

    paths: set[Path] = set()
    information_root = ROOT / "bridge/information"
    for path in information_root.rglob("*"):
        if path.is_file() and path.suffix.lower() in {".py", ".json", ".md", ".txt"}:
            _add_file(paths, path)

    tests_root = ROOT / "bridge/tests"
    for path in tests_root.glob("test_information*.py"):
        _add_file(paths, path)
    fixtures = tests_root / "fixtures"
    for path in fixtures.glob("information_*.json"):
        _add_file(paths, path)
    for name in REQUIRED_FIXTURES:
        _add_file(paths, fixtures / name)

    for relative in DOCS + WORK_SCRIPTS:
        _add_file(paths, ROOT / relative)
    audit_script = ROOT / "work/audit_information_country_relations_tests.py"
    _add_file(paths, audit_script, required=False)
    _add_file(paths, INSTALLATION)
    _add_file(paths, PREVIOUS)
    _add_file(paths, test_summary_path)

    # Keep the stage's failure/correction records and audit artifacts.  The
    # prior batch's delivery/files subtree is deliberately excluded.
    for path in STAGE.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in ARCHIVE_SUFFIXES:
            continue
        if "delivery" in path.relative_to(STAGE).parts:
            continue
        _add_file(paths, path)

    # Copy each exact profile dependency, including pinned historical helper
    # files. This does not traverse or copy a previous delivery directory.
    for record in validation["profile_references"]:
        source = ROOT / record["path"]
        _add_file(paths, source)
    validation["skipped_previous_delivery_references"] = []
    return paths


def _report_index(validation: dict[str, Any]) -> dict[str, Any]:
    reports = validation["reports"]
    return {
        "native_public": {
            "path": "work/runtime/information-country-relations-20261024-001/native-public-001/report.json",
            "sha256": reports["report_sha256"]["native"],
            "evidence_type": "native_query_read_only_not_pure_RPM",
        },
        "live_acceptance": {
            "path": "work/runtime/information-country-relations-20261024-001/live-acceptance-001/report.json",
            "sha256": reports["report_sha256"]["live"],
            "evidence_type": "native_query_periodic_read_only",
        },
        "save_crosscheck": {
            "path": "work/runtime/information-country-relations-20261024-001/save-crosscheck-002.json",
            "sha256": reports["report_sha256"]["save"],
            "evidence_type": "recorded_save_crosscheck",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="New archive directory under this batch's STAGE")
    args = parser.parse_args()

    output = args.output.expanduser().resolve()
    if not output.is_relative_to(STAGE.resolve()):
        raise ValueError("Archive output must be inside this batch STAGE")
    if output.exists():
        raise ValueError("Archive output must be new")

    # This check intentionally occurs before creating an archive directory.
    test_summary_path, test_summary = _require_test_summary()
    previous = bounded_file(PREVIOUS)
    if digest(previous) != PREVIOUS_SHA:
        raise ValueError("Previous immutable delivery manifest changed")

    validation = checker.run_validation(write_artifacts=False)
    coverage = validation["coverage"]
    if (coverage["topic_count"], coverage["field_count"], coverage["available_topic_count"]) != (74, 397, 34):
        raise ValueError("Catalog coverage changed before archive")
    if coverage["field_counts"] != {"available": 50, "partial": 104, "planned": 243}:
        raise ValueError("Catalog field coverage changed before archive")
    required_audits = (STAGE / "coverage.json", STAGE / "compile-audit.json", STAGE / "source-audit.json")
    for audit in required_audits:
        bounded_file(audit)

    paths = _archive_paths(validation, test_summary_path)
    # Resolve and size-check every source before creating the destination.
    checked_paths = sorted({bounded_file(path) for path in paths}, key=str)
    output.mkdir(parents=True, exist_ok=False)
    entries: list[dict[str, Any]] = []
    for path in checked_paths:
        relative = path.relative_to(ROOT_RESOLVED)
        destination = output / "files" / relative
        expected = digest(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
        if digest(destination) != expected or digest(path) != expected:
            raise ValueError(f"Source changed during archive copy: {path}")
        entries.append({"path": relative.as_posix(), "bytes": path.stat().st_size, "sha256": expected})

    test_information = test_summary.get("information", {})
    manifest = {
        "format": "information_country_relations_delivery_v1",
        "status": "source_and_evidence_snapshot_verified",
        "goal_complete": False,
        "file_count": len(entries),
        "files": entries,
        "tests": test_summary,
        "evidence_reports": _report_index(validation),
        "identity_and_raw_checks": validation["reports"]["pair_checks"],
        "profile_reference_checks": validation["profile_references"],
        "skipped_previous_delivery_references": validation.get("skipped_previous_delivery_references", []),
        "previous_manifest": validation["previous_manifest"],
        "configured_coverage": {
            "topics": coverage["topic_count"],
            "fields": coverage["field_count"],
            "available_topics": coverage["available_topic_count"],
            "field_counts": dict(coverage["field_counts"]),
            "new_composite_includes": ["NativeCountryStateSource", "NativeSubjectRelationSource",
                                        "StaticTradeSource", "MissionInformationSource"],
            "catalog_only_no_live_session": True,
            "registration_is_not_full_live_acceptance": True,
        },
        "compiled_source_fingerprints": validation["compile_audit"],
        "typed_sources": ["native_query", "recorded_save"],
        "evidence_types_separated": [
            "ordinary source contracts",
            "native query functions invoked; not pure RPM",
            "read-only periodic adapter acceptance",
            "recorded historical save cross-check",
            "offline catalog construction",
            "recorded fixture tests",
        ],
        "scope": {
            "observer": "FRA",
            "selected_pairs": ["FRA/ORL", "FRA/PAP"],
            "native_business_actions_submitted": False,
            "save_is_not_live_fallback": True,
            "world_generation_verified": False,
        },
        "information_test_summary": {
            "case_elements": test_information.get("case_elements"),
            "case_element_statuses": test_information.get("case_element_statuses"),
            "clean_information_failures": True,
        },
        "remaining": [
            "all target fields in the 74-topic information plan",
            "complete country-pair relation enumeration and all relation types",
            "complete country resources, modifiers, trade and other planned fields",
            "lossless event/change capture and positive live changes",
            "full native UI scope and trigger/progress evaluation",
            "complete per-battle contents and new event coverage",
            "full repository regression remains outside this information snapshot",
        ],
        "read_only_archival": True,
    }
    manifest_path = output / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if manifest_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("Archive manifest exceeds size budget")
    print(json.dumps({
        "format": manifest["format"], "status": manifest["status"],
        "goal_complete": manifest["goal_complete"], "file_count": manifest["file_count"],
        "configured_coverage": manifest["configured_coverage"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
