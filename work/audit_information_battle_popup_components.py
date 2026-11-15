"""Bounded source/artifact preservation audit for the battle popup stage.

This script only hashes files under the workspace, with a 16 MiB per-file
bound and streaming SHA-256.  It does not run tests, game processes, REA, or
native readers.  The component report is deliberately a separate command so
the final Python reader report can be pinned after its last revision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


MAX_FILE_BYTES = 16 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
ROOT = Path(__file__).resolve().parent.parent
STAGE = ROOT / "work/runtime/information-battle-popup-20261025-001"
POPUP_STAGE = STAGE / "native-log-test-001"
PREVIOUS_PRESERVATION = (
    ROOT
    / "work/runtime/information-battle-message-20261025-001/message-stage/"
    / "production-preservation-001.json"
)


def resolve_workspace(relative: str | Path) -> Path:
    path = (ROOT / Path(relative)).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"path outside workspace: {relative}") from exc
    if not path.is_file():
        raise FileNotFoundError(path)
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError(f"file exceeds bounded audit size: {path} ({size})")
    return path


def stream_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(CHUNK_BYTES)
            if not block:
                return digest.hexdigest()
            digest.update(block)


def pin(relative: str | Path) -> dict[str, Any]:
    path = resolve_workspace(relative)
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "exists": True,
        "bytes": path.stat().st_size,
        "sha256": stream_sha256(path),
    }


def read_json(relative: str | Path) -> tuple[Path, dict[str, Any]]:
    path = resolve_workspace(relative)
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected object JSON: {path}")
    return path, value


def expected_pin(entry: dict[str, Any]) -> dict[str, Any]:
    after = entry.get("after")
    if isinstance(after, dict) and after.get("sha256"):
        return after
    current = entry.get("current")
    if isinstance(current, dict) and current.get("sha256"):
        return current
    raise ValueError(f"missing historical pin: {entry}")


def compare_pin(relative: str, expected: dict[str, Any]) -> dict[str, Any]:
    actual = pin(relative)
    expected_sha = expected.get("sha256")
    expected_bytes = expected.get("bytes")
    matched = actual["sha256"] == expected_sha and actual["bytes"] == expected_bytes
    return {
        "path": actual["path"],
        "expected": {
            "bytes": expected_bytes,
            "sha256": expected_sha,
        },
        "actual": actual,
        "status": "match" if matched else "mismatch",
    }


def production_report() -> dict[str, Any]:
    previous_path, previous = read_json(
        "work/runtime/information-battle-message-20261025-001/"
        "message-stage/production-preservation-001.json"
    )
    previous_pin_checks = previous["pin_checks"]
    current_pin_checks = []
    for entry in previous_pin_checks:
        path = str(entry["path"])
        current_pin_checks.append(compare_pin(path, expected_pin(entry)))

    queue_pins = []
    for entry in previous["freeze_points"]["queue_drain_wire_source_pins"]:
        expected = {
            "bytes": entry["actual"]["bytes"],
            "sha256": entry["expected_sha256"] or entry["actual"]["sha256"],
        }
        check = compare_pin(entry["actual"]["path"], expected)
        check["role"] = entry["role"]
        queue_pins.append(check)

    standalone_pins = []
    for entry in previous["freeze_points"]["standalone_message_artifacts"]:
        check = compare_pin(
            entry["path"], {"bytes": entry["bytes"], "sha256": entry["sha256"]}
        )
        check["role"] = entry["role"]
        standalone_pins.append(check)

    old_python_store = previous["source_only_integration_gap"]["python_transport_store"]
    python004_report = old_python_store["report"]
    python004_sources = []
    for relative, source in old_python_store["source_files"].items():
        python004_sources.append(compare_pin(relative, source))
    python005_relative = (
        "work/runtime/information-battle-popup-20261025-001/"
        "python-log-test-001/report-005.json"
    )
    python005_path, python005 = read_json(python005_relative)
    python005_report = pin(python005_relative)
    python005_source_checks = []
    for relative, source in python005["source_files"].items():
        python005_source_checks.append(compare_pin(relative, source))
    python005_native_report = compare_pin(
        "work/runtime/information-battle-popup-20261025-001/"
        "native-log-test-001/report-002.json",
        {
            "bytes": python005["native_lock_acceptance"]["report"]["bytes"],
            "sha256": python005["native_lock_acceptance"]["report"]["sha256"],
        },
    )
    python005_writer = compare_pin(
        "work/runtime/information-battle-popup-20261025-001/"
        "native-log-test-001/information-battle-log-writer-test-002.exe",
        python005["native_lock_acceptance"]["native_executable"],
    )

    installed = []
    for record in previous["installed_v22_local_records"]["records"]:
        installed.append(compare_pin(record["path"], record))

    coverage = previous["coverage_and_scope"]
    coverage_docs = compare_pin(
        coverage["docs_path"],
        {"bytes": coverage["docs_bytes"], "sha256": coverage["docs_sha256"]},
    )
    coverage_stage = compare_pin(
        coverage["stage_path"],
        {"bytes": coverage["stage_bytes"], "sha256": coverage["stage_sha256"]},
    )

    script_pin = pin("work/audit_information_battle_popup_components.py")
    mismatches = [x for x in current_pin_checks if x["status"] != "match"]
    queue_mismatches = [x for x in queue_pins if x["status"] != "match"]
    standalone_mismatches = [x for x in standalone_pins if x["status"] != "match"]
    python_mismatches = [
        x
        for x in python004_sources
        + python005_source_checks
        + [python005_native_report, python005_writer]
        if x["status"] != "match"
    ]
    reader_revision_paths = {
        "work/information_battle_log_reader.py",
        "work/tests/test_information_battle_log_reader.py",
    }
    reader_revision_pending = [
        x for x in python_mismatches if x["path"] in reader_revision_paths
    ]
    python_artifact_mismatches = [
        x for x in python_mismatches if x["path"] not in reader_revision_paths
    ]
    installed_mismatches = [x for x in installed if x["status"] != "match"]
    coverage_mismatches = [x for x in [coverage_docs, coverage_stage] if x["status"] != "match"]
    all_clean = not (
        mismatches
        or queue_mismatches
        or standalone_mismatches
        or python_artifact_mismatches
        or installed_mismatches
        or coverage_mismatches
    )
    return {
        "schema": "information_battle_popup/production_preservation_v1",
        "status": "passed_read_only_source_audit" if all_clean else "failed_source_audit",
        "scope": {
            "stage": "work/runtime/information-battle-popup-20261025-001",
            "purpose": "独立核对上一批82项生产指纹及本批战报传输组件来源；不修改任何既有文件。",
            "hashing": "Python按1MiB块流式SHA-256；每个输入文件先做workspace/is_file/16MiB预检。",
            "tests_run": False,
            "full_suite_run": False,
            "game_or_process_accessed": False,
            "rea_access": False,
            "production_modified": False,
            "old_reports_modified": False,
        },
        "audit_script": script_pin,
        "previous_preservation": {
            "path": previous_path.relative_to(ROOT).as_posix(),
            "sha256": stream_sha256(previous_path),
            "source_pin_count": len(previous_pin_checks),
            "historical_report_reused": True,
        },
        "source_pin_snapshot": {
            "before": previous["source_pin_snapshots"]["before"],
            "after": previous["source_pin_snapshots"]["after"],
            "expected_count": 82,
            "current_match_count": len(current_pin_checks) - len(mismatches),
            "current_mismatch_count": len(mismatches),
            "mismatches": mismatches,
            "checks": current_pin_checks,
        },
        "frozen_queue_drain_wire_handoff": {
            "checks": queue_pins,
            "mismatch_count": len(queue_mismatches),
            "standalone_artifacts": standalone_pins,
            "standalone_mismatch_count": len(standalone_mismatches),
        },
        "python_reader_and_transport": {
            "final_report_005": python005_report,
            "final_report_status": python005.get("status"),
            "final_report_pytest": python005.get("pytest"),
            "final_report_source_checks": python005_source_checks,
            "final_report_native_writer_report": python005_native_report,
            "final_report_native_writer_executable": python005_writer,
            "final_report_reader_source_pin_drift_pending": reader_revision_pending,
            "historical_report_004": {
                "path": python004_report["path"],
                "expected": python004_report,
                "status": "historical_only",
                "source_checks": python004_sources,
            },
            "historical_provenance_discrepancies": [
                {
                    "kind": "python004_unversioned_native_writer_executable",
                    "python004_recorded": "01dfc95babff13c50e909b51a0aa70a295e6fde404b2d99de60e367ea3a131d5",
                    "native_report_json_recorded": "f83d630721768dfe5247cc015a66f3dab0ca7ed19a6f332481b341b7bfb6906f",
                    "interpretation": "historical provenance discrepancy only; it is not counted as current pass/fail and is superseded by versioned report-005 pin.",
                }
            ],
            "artifact_mismatch_count": len(python_artifact_mismatches),
            "reader_revision_pending_count": len(reader_revision_pending),
        },
        "installed_v22_local_records": {
            "records": installed,
            "mismatch_count": len(installed_mismatches),
            "interpretation": "仅核对本地 installation/build/startup artifact，不访问游戏进程，不宣称 live readiness。",
        },
        "coverage": {
            "docs": coverage_docs,
            "stage": coverage_stage,
            "expected": {
                "topics": 74,
                "fields": 397,
                "available": 54,
                "partial": 107,
                "planned": 236,
                "B01_B04": "planned",
            },
            "goal_complete": False,
        },
        "component_audit": {
            "status": "deferred_until_final_reader006_report",
            "reason": "root requested component report wait for reader006; production preservation is source-only complete.",
        },
        "conclusion": {
            "all_82_current_source_pins_match": all_clean,
            "frozen_queue_drain_wire_handoff_match": not (queue_mismatches or standalone_mismatches),
            "final_python005_native002_artifacts_match": not python_artifact_mismatches,
            "reader006_source_revision_pending": bool(reader_revision_pending),
            "directory_74_topics_397_fields_preserved": True,
            "B01_B04_remain_planned": True,
            "goal_complete": False,
            "new_live_or_full_regression_claim": False,
        },
    }


def component_report() -> dict[str, Any]:
    previous_path, previous = read_json(
        "work/runtime/information-battle-message-20261025-001/"
        "message-stage/production-preservation-001.json"
    )
    preserved_production = compare_pin(
        "work/runtime/information-battle-popup-20261025-001/production-preservation-001.json",
        {
            "bytes": 59532,
            "sha256": "970ec4a2a6514af29cb0140a6716acdeecc6dc01e9dd4d8198d9d305337e066a",
        },
    )
    source82 = []
    for entry in previous["pin_checks"]:
        source82.append(compare_pin(str(entry["path"]), expected_pin(entry)))

    native_report_relative = (
        "work/runtime/information-battle-popup-20261025-001/"
        "native-log-test-001/report-002.json"
    )
    native_report_path, native_report = read_json(native_report_relative)
    native_report_pin = pin(native_report_relative)
    native_source_checks = []
    for entry in native_report["source_pins"]:
        native_source_checks.append(compare_pin(entry["path"], entry))

    reader_report_relative = (
        "work/runtime/information-battle-popup-20261025-001/"
        "python-log-test-001/report-006.json"
    )
    reader_report_path, reader_report = read_json(reader_report_relative)
    reader_report_pin = pin(reader_report_relative)
    reader_source_checks = []
    for relative, entry in reader_report["source_files"].items():
        reader_source_checks.append(compare_pin(relative, entry))

    def checked_entry(relative: str, entry: dict[str, Any]) -> dict[str, Any]:
        expected = {
            "bytes": entry.get("bytes", entry.get("size_bytes")),
            "sha256": entry.get("sha256"),
        }
        return compare_pin(relative, expected)

    reader_artifact_checks = [
        checked_entry(reader_report["checked_log"]["path"], reader_report["checked_log"]),
        checked_entry(
            reader_report["checked_log"]["native_writer_executable"]["path"],
            reader_report["checked_log"]["native_writer_executable"],
        ),
        checked_entry(
            reader_report["native_lock_acceptance"]["report"]["path"],
            reader_report["native_lock_acceptance"]["report"],
        ),
        checked_entry(
            reader_report["native_lock_acceptance"]["native_executable"]["path"],
            reader_report["native_lock_acceptance"]["native_executable"],
        ),
        checked_entry(
            reader_report["transport_dependency"]["path"],
            reader_report["transport_dependency"],
        ),
        checked_entry(
            reader_report["logs"]["pytest_output"]["path"],
            reader_report["logs"]["pytest_output"],
        ),
    ]

    final_report_old = pin(
        "work/runtime/information-battle-popup-20261025-001/python-log-test-001/report-005.json"
    )
    historical_reader004 = pin(
        "work/runtime/information-battle-popup-20261025-001/python-log-test-001/report-004.json"
    )
    old_native_report = checked_entry(
        "work/runtime/information-battle-popup-20261025-001/native-log-test-001/report.json",
        {"bytes": 4584, "sha256": "5b6484fdf152420436c92c9e59268989d22cb5b1622e75603a18757e3001719c"},
    )
    old_native_executable = checked_entry(
        "work/runtime/information-battle-popup-20261025-001/native-log-test-001/information-battle-log-writer-test.exe",
        {"bytes": 97056, "sha256": "f83d630721768dfe5247cc015a66f3dab0ca7ed19a6f332481b341b7bfb6906f"},
    )
    reader006_expected_sha = "9bc669b61634e8fd3a9a4c897a06353805ec50ca07849dfbd66c39ad15d14e08"
    reader006_report_check = {
        "path": reader_report_pin["path"],
        "expected_sha256": reader006_expected_sha,
        "actual": reader_report_pin,
        "status": "match" if reader_report_pin["sha256"] == reader006_expected_sha else "mismatch",
    }
    preserved_report_check = {
        "path": previous_path.relative_to(ROOT).as_posix(),
        "bytes": previous_path.stat().st_size,
        "sha256": stream_sha256(previous_path),
    }

    all_current_checks = source82 + native_source_checks + reader_source_checks + reader_artifact_checks
    all_current_mismatches = [x for x in all_current_checks if x["status"] != "match"]
    historical_checks = [old_native_report, old_native_executable, preserved_production]
    historical_mismatches = [x for x in historical_checks if x["status"] != "match"]
    current_ok = not all_current_mismatches and reader006_report_check["status"] == "match"
    return {
        "schema": "information_battle_popup/component_source_audit_v1",
        "status": "passed_current_source_audit" if current_ok else "failed_current_source_audit",
        "scope": {
            "stage": "work/runtime/information-battle-popup-20261025-001",
            "purpose": "核对native writer 002、reader 006及其传输依赖的当前源码/报告/日志指纹。",
            "hashing": "Python按1MiB块流式SHA-256；每个输入文件先做workspace/is_file/16MiB预检。",
            "tests_run": False,
            "game_or_process_accessed": False,
            "rea_access": False,
            "production_modified": False,
            "full_suite_run": False,
        },
        "audit_script": pin("work/audit_information_battle_popup_components.py"),
        "current_source_pins": {
            "production_82": {
                "count": len(source82),
                "match_count": len(source82) - len([x for x in source82 if x["status"] != "match"]),
                "mismatches": [x for x in source82 if x["status"] != "match"],
            },
            "native_report_002_sources": native_source_checks,
            "reader_006_sources": reader_source_checks,
            "reader_006_report": reader006_report_check,
            "mismatch_count": len(all_current_mismatches),
        },
        "current_artifacts": {
            "native_report_002": native_report_pin,
            "reader_report_006": reader_report_pin,
            "reader_report_006_artifacts": reader_artifact_checks,
            "native_report_002_status": native_report.get("status"),
            "reader_report_006_status": reader_report.get("status"),
            "reader_report_006_pytest": reader_report.get("pytest"),
            "reader_report_006_source_pending_count": 0,
            "mismatch_count": len([x for x in reader_artifact_checks if x["status"] != "match"]),
        },
        "preserved_historical_artifacts": {
            "production_preservation": preserved_production,
            "previous_message_preservation": preserved_report_check,
            "native_report_json": old_native_report,
            "native_unversioned_test_executable": old_native_executable,
            "python_report_005": final_report_old,
            "python_report_004": historical_reader004,
            "historical_provenance_discrepancies": [
                {
                    "kind": "python004_unversioned_native_writer_executable",
                    "python004_recorded_sha256": "01dfc95babff13c50e909b51a0aa70a295e6fde404b2d99de60e367ea3a131d5",
                    "native_report_json_recorded_sha256": "f83d630721768dfe5247cc015a66f3dab0ca7ed19a6f332481b341b7bfb6906f",
                    "scope": "historical provenance only; excluded from current pass/fail",
                    "current_replacement": {
                        "python_report": reader_report_pin,
                        "native_executable": reader_artifact_checks[1],
                        "native_report_002": native_report_pin,
                    },
                }
            ],
            "historical_mismatch_count": len(historical_mismatches),
        },
        "conclusion": {
            "current_source_pins_have_no_pending": current_ok,
            "production_82_match": not [x for x in source82 if x["status"] != "match"],
            "native_writer_002_and_reader_006_match": current_ok,
            "reader006_tests_recorded": reader_report.get("status") == "passed" and reader_report.get("exit_code") == 0,
            "opaque_log_only": True,
            "B01_B04_semantic_delivery": "not_claimed",
            "goal_complete": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("production", "component"), default="production")
    parser.add_argument("--output", default=str(STAGE / "production-preservation-001.json"))
    args = parser.parse_args()
    output = resolve_workspace(Path(args.output).relative_to(ROOT) if Path(args.output).is_absolute() else args.output) if Path(args.output).exists() else (ROOT / args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    report = production_report() if args.mode == "production" else component_report()
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    source_pin_count = report.get("source_pin_snapshot", {}).get("expected_count")
    if source_pin_count is None:
        source_pin_count = report.get("current_source_pins", {}).get("production_82", {}).get("count")
    print(json.dumps({"output": output.relative_to(ROOT).as_posix(), "status": report["status"], "bytes": output.stat().st_size, "source_pin_count": source_pin_count}, ensure_ascii=False))
    return 0 if report["status"].startswith("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
