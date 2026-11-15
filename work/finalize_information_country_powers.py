"""在第九批信息测试摘要干净后建立本国点数证据快照。

终结器只复制经过 ``verify_information_country_powers`` 再核对的有界文件。
它拒绝覆盖已有 delivery，也不会递归复制旧批次归档；profile 中明确列出的
历史依赖仍按单个精确路径复制并逐文件复核。归档的 ``goal_complete`` 固定为
``false``，因为本批只完成有限的本国点数字段。
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ROOT_RESOLVED = ROOT.resolve()
STAGE = ROOT / "work/runtime/information-country-scalars-20261024-001"
PREVIOUS = ROOT / "work/runtime/information-country-relations-20261024-001/delivery/manifest.json"
PREVIOUS_SHA = "b24cf0c61c56a95e36621d764080a4f9c22025649970c9cfdfafe96927e2e6f7"
INSTALLATION = ROOT / "work/runtime/diplomacy-observer-20261024-information-a/installation.json"
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
ARCHIVE_SUFFIXES = {".json", ".xml", ".log", ".md", ".py", ".txt"}

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from work import verify_information_country_powers as checker  # noqa: E402


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
    "docs/国家点数原生来源.md",
)
WORK_SCRIPTS = (
    "work/capture_information_country_powers.py",
    "work/validate_information_country_powers.py",
    "work/freeze_information_country_powers.py",
    "work/verify_information_country_powers_save.py",
    "work/verify_information_country_powers.py",
    "work/finalize_information_country_powers.py",
    "work/research_information_power_access.py",
    "work/research_information_country_scalars.py",
    "work/audit_information_country_powers_tests.py",
)
REQUIRED_FIXTURES = (
    "r73_favor_queries_real.json",
    "r74_economic_queries_real.json",
    "vassalization_r35_native_inspections.json",
)


def bounded_file(path: Path | str, *, max_bytes: int = MAX_ARCHIVE_BYTES) -> Path:
    return checker.bounded_file(path, max_bytes=max_bytes)


def digest(path: Path | str, *, max_bytes: int = MAX_ARCHIVE_BYTES) -> str:
    return checker.digest(path, max_bytes=max_bytes)


def read_json(path: Path | str, *, max_bytes: int = MAX_ARCHIVE_BYTES) -> Any:
    return checker.read_json(path, max_bytes=max_bytes)


def _require_test_summary() -> tuple[Path, dict[str, Any]]:
    path = bounded_file(STAGE / "test-summary.json")
    summary = read_json(path)
    if not isinstance(summary, dict):
        raise ValueError("test_summary_object_required")
    information = summary.get("information")
    if not isinstance(information, dict):
        raise ValueError("test_summary_information_missing")
    statuses = information.get("case_element_statuses")
    if not isinstance(statuses, dict):
        raise ValueError("test_summary_information_statuses_missing")
    for key in ("failure", "error"):
        if type(statuses.get(key)) is not int or statuses[key] != 0:
            raise ValueError(f"information_test_status_not_zero:{key}")
    if type(statuses.get("passed")) is not int or statuses["passed"] <= 0:
        raise ValueError("information_test_pass_count_missing")
    directed = summary.get("targeted_powers_checkpoint")
    if not isinstance(directed, dict) or directed.get("status") != "passed":
        raise ValueError("final_directed_information_checkpoint_missing")
    artifacts = summary.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        raise ValueError("test_summary_artifact_pins_missing")
    for name, record in artifacts.items():
        source = bounded_file(ROOT / record["path"])
        if digest(source) != record["sha256"] or source.stat().st_size != record["bytes"]:
            raise ValueError("test_summary_artifact_changed:" + name)
    for key in ("failure", "error", "failed", "errors", "failures"):
        value = statuses.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value != 0:
            raise ValueError(f"information_tests_not_clean:{key}")
    # Some complete-suite summaries use a top-level aggregate. It is retained
    # in the archive, but a positive failure/error count always blocks it.
    for section_name, section in summary.items():
        if not isinstance(section, dict):
            continue
        for key in ("failure", "error", "failed", "errors", "failures"):
            value = section.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and value != 0:
                if section_name == "information":
                    raise ValueError(f"information_tests_not_clean:{section_name}.{key}")
    return path, summary


def _add_file(paths: set[Path], path: Path | str, *, required: bool = True,
              max_bytes: int = MAX_ARCHIVE_BYTES) -> None:
    candidate = Path(path)
    if not candidate.exists():
        if required:
            raise ValueError(f"archive_required_file_missing:{candidate}")
        return
    paths.add(bounded_file(candidate, max_bytes=max_bytes))


def _archive_paths(validation: dict[str, Any], test_summary_path: Path) -> set[Path]:
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
    _add_file(paths, INSTALLATION)
    _add_file(paths, PREVIOUS)
    _add_file(paths, test_summary_path)
    for record in read_json(test_summary_path)["artifacts"].values():
        _add_file(paths, ROOT / record["path"])
    for record in validation["reports"]["live"]["source_files"]:
        _add_file(paths, ROOT / record["path"])

    # Keep this batch's stage artifacts, while never walking/copying a delivery
    # subtree. sqlite databases and unrelated binary payloads are excluded.
    for path in STAGE.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in ARCHIVE_SUFFIXES:
            continue
        if "delivery" in path.relative_to(STAGE).parts:
            continue
        _add_file(paths, path)

    # Exact profile dependencies include old immutable helper copies when the
    # current profile intentionally points at them. They are added individually;
    # no previous delivery directory is traversed.
    for group in validation["profile_references"]:
        for record in group["references"]:
            _add_file(paths, ROOT / record["path"])
    return paths


def _assert_audits_match(validation: dict[str, Any]) -> None:
    expected = {
        "coverage.json": validation["coverage"],
        "compile-audit.json": validation["compile_audit"],
    }
    for name, value in expected.items():
        artifact = read_json(STAGE / name)
        if artifact != value:
            raise ValueError(f"stale_audit:{name}")
    source_audit = read_json(STAGE / "source-audit.json")
    if not isinstance(source_audit, dict) or source_audit.get("status") != "passed":
        raise ValueError("source_audit_not_passed")
    if source_audit.get("profile_reference_groups") != validation["profile_references"]:
        raise ValueError("stale_audit:source-audit.profile_reference_groups")
    if source_audit.get("current_source_fingerprints") != validation["compile_audit"]["files"]:
        raise ValueError("stale_audit:source-audit.current_source_fingerprints")
    if source_audit.get("native_reports") != validation["reports"]["report_sha256"]:
        raise ValueError("stale_audit:source-audit.native_reports")
    if source_audit.get("native_runtime_pins") != validation["reports"]["native_runtime"]:
        raise ValueError("stale_audit:source-audit.native_runtime_pins")
    if source_audit.get("fixture") != validation["fixture"]:
        raise ValueError("stale_audit:source-audit.fixture")


def _typed_evidence(validation: dict[str, Any]) -> dict[str, Any]:
    reports = validation["reports"]
    profile_refs = validation["profile_references"][0]["references"]
    rea = [item for item in profile_refs if item.get("role") == "REA semantic evidence"]
    ordinary = [item for item in profile_refs if item.get("role") != "REA semantic evidence"]
    return {
        "REA_static_semantic_contract": rea,
        "ordinary_static_and_profile": ordinary,
        "pure_RPM_native_runtime": [
            {"path": "work/runtime/information-country-scalars-20261024-001/native-runtime-001/native-capture.json",
             "sha256": reports["report_sha256"]["native_capture"],
             "kind": "bounded_RPM_two_pass_observation"},
            {"path": "work/runtime/information-country-scalars-20261024-001/native-runtime-001/report.json",
             "sha256": reports["report_sha256"]["native_runtime"],
             "kind": "runtime_capture_summary"},
        ],
        "mixed_native_query_periodic": [
            {"path": "work/runtime/information-country-scalars-20261024-001/live-acceptance-002/report.json",
             "sha256": reports["report_sha256"]["live"],
             "kind": "MCP_points_and_mixed_prestige_read_only_acceptance"},
        ],
        "recorded_save_crosscheck": [
            {"path": "work/runtime/information-country-scalars-20261024-001/save-powers-crosscheck-001.json",
             "sha256": reports["report_sha256"]["save"],
             "kind": "recorded_save_ordered_vector_only"},
        ],
    }


def _report_index(validation: dict[str, Any]) -> dict[str, Any]:
    reports = validation["reports"]["report_sha256"]
    result = {
        "native_capture": {
            "path": "work/runtime/information-country-scalars-20261024-001/native-runtime-001/native-capture.json",
            "sha256": reports["native_capture"],
            "evidence_type": "pure_RPM_runtime_observation",
        },
        "native_runtime": {
            "path": "work/runtime/information-country-scalars-20261024-001/native-runtime-001/report.json",
            "sha256": reports["native_runtime"],
            "evidence_type": "native_capture_summary",
        },
        "live_acceptance": {
            "path": "work/runtime/information-country-scalars-20261024-001/live-acceptance-002/report.json",
            "sha256": reports["live"],
            "evidence_type": "mixed_native_query_periodic_read_only",
        },
        "save_crosscheck": {
            "path": "work/runtime/information-country-scalars-20261024-001/save-powers-crosscheck-001.json",
            "sha256": reports["save"],
            "evidence_type": "recorded_save_crosscheck",
        },
    }
    previous_live = STAGE / "live-acceptance-001/report.json"
    if previous_live.is_file():
        result["superseded_live_acceptance_001"] = {
            "path": "work/runtime/information-country-scalars-20261024-001/live-acceptance-001/report.json",
            "sha256": digest(previous_live),
            "evidence_type": "superseded_prior_live_acceptance_retained_for_audit",
        }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="new delivery directory inside this batch STAGE")
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    if not output.is_relative_to(STAGE.resolve()):
        raise ValueError("archive_output_outside_batch_stage")
    if output.exists():
        raise ValueError("archive_output_must_be_new")

    # All guards happen before creating the destination directory.
    test_summary_path, test_summary = _require_test_summary()
    previous = bounded_file(PREVIOUS)
    if digest(previous) != PREVIOUS_SHA:
        raise ValueError("previous_delivery_manifest_changed")
    validation = checker.run_validation(write_artifacts=False)
    coverage = validation["coverage"]
    if (
        {key: coverage[key] for key in ("topic_count", "field_count", "available_topic_count")}
        != {key: checker.EXPECTED_COVERAGE[key] for key in ("topic_count", "field_count", "available_topic_count")}
    ):
        raise ValueError("catalog_coverage_changed_before_archive")
    if coverage["field_counts"] != checker.EXPECTED_COVERAGE["field_counts"]:
        raise ValueError("catalog_field_coverage_changed_before_archive")
    for name in ("coverage.json", "compile-audit.json", "source-audit.json"):
        bounded_file(STAGE / name)
    _assert_audits_match(validation)

    paths = _archive_paths(validation, test_summary_path)
    checked_paths = sorted({bounded_file(path) for path in paths}, key=str)
    output.mkdir(parents=True, exist_ok=False)
    entries: list[dict[str, Any]] = []
    for source in checked_paths:
        relative = source.relative_to(ROOT_RESOLVED)
        destination = output / "files" / relative
        expected = digest(source)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        if digest(destination) != expected or digest(source) != expected:
            raise ValueError(f"source_changed_during_archive:{relative}")
        entries.append({"path": relative.as_posix(), "bytes": source.stat().st_size,
                        "sha256": expected})

    test_information = test_summary.get("information", {})
    manifest = {
        "format": "information_country_powers_delivery_v1",
        "status": "source_and_evidence_snapshot_verified",
        "goal_complete": False,
        "file_count": len(entries),
        "files": entries,
        "tests": test_summary,
        "evidence_reports": _report_index(validation),
        "typed_evidence": _typed_evidence(validation),
        "identity_and_values": validation["reports"]["identity"],
        "native_runtime_pins": validation["reports"]["native_runtime"],
        "recorded_fixture": validation["fixture"],
        "profile_reference_checks": validation["profile_references"],
        "previous_manifest": validation["previous_manifest"],
        "configured_coverage": {
            "topics": coverage["topic_count"],
            "fields": coverage["field_count"],
            "available_topics": coverage["available_topic_count"],
            "field_counts": dict(coverage["field_counts"]),
            "new_composite_includes": ["NativeCountryStateSource", "N06.monarch_points"],
            "catalog_only_no_live_session": True,
            "registration_is_not_full_live_acceptance": True,
        },
        "compiled_source_fingerprints": validation["compile_audit"],
        "information_test_summary": {
            "case_elements": test_information.get("case_elements"),
            "case_element_statuses": test_information.get("case_element_statuses"),
            "clean_information_failures": True,
            "full_repository_regression_passing_is_not_claimed": True,
        },
        "scope": {
            "observer": "FRA",
            "country": "FRA",
            "native_business_actions_submitted": False,
            "save_is_not_live_fallback": True,
            "world_generation_verified": False,
            "values": validation["reports"]["identity"]["values"],
        },
        "remaining": [
            "remaining country resources, complete relations, modifiers and live trade",
            "atomic main-thread snapshot and world generation remain unverified",
            "complete native UI scope and trigger/progress evaluation remain outside this batch",
            "positive live changes, new events and complete per-battle content",
            "full repository regression retains historical failures and errors",
        ],
        "read_only_archival": True,
    }
    manifest_path = output / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if manifest_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("archive_manifest_over_limit")
    print(json.dumps({
        "format": manifest["format"], "status": manifest["status"],
        "goal_complete": manifest["goal_complete"], "file_count": manifest["file_count"],
        "configured_coverage": manifest["configured_coverage"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
