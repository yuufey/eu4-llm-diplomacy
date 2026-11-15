"""Bounded preservation/component audit for the battle-fragment stage.

The audit only hashes bounded workspace artifacts.  It does not run pytest,
REA, a game process, or a native reader.  The production mode can be run
before a later reassembly revision; component mode requires the final
reassembly report and validates that report separately.
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
STAGE = ROOT / "work/runtime/information-battle-fragments-20261025-001"
PREVIOUS_MESSAGE = (
    ROOT
    / "work/runtime/information-battle-message-20261025-001/message-stage/"
    / "production-preservation-001.json"
)
PREVIOUS_POPUP = (
    ROOT
    / "work/runtime/information-battle-popup-20261025-001/component-source-audit-001.json"
)


def resolve_workspace(relative: str | Path, *, allow_large: bool = False) -> Path:
    path = (ROOT / Path(relative)).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"path outside workspace: {relative}") from exc
    if not path.is_file():
        raise FileNotFoundError(path)
    if not allow_large and path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"file exceeds bounded audit size: {path} ({path.stat().st_size})")
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


def bounded_metadata(relative: str | Path) -> dict[str, Any]:
    """Record size for an oversized artifact without reading or hashing it."""

    path = resolve_workspace(relative, allow_large=True)
    size = path.stat().st_size
    if size <= MAX_FILE_BYTES:
        return pin(relative)
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "exists": True,
        "bytes": size,
        "sha256": None,
        "hash_status": "not_read_bounded_over_16MiB",
    }


def read_json(relative: str | Path) -> tuple[Path, dict[str, Any]]:
    path = resolve_workspace(relative)
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected object JSON: {path}")
    return path, value


def expected_pin(entry: dict[str, Any]) -> dict[str, Any]:
    for key in ("after", "current", "expected"):
        value = entry.get(key)
        if isinstance(value, dict) and value.get("sha256"):
            return value
    if entry.get("sha256"):
        return entry
    raise ValueError(f"missing expected pin: {entry}")


def compare_pin(relative: str | Path, expected: dict[str, Any]) -> dict[str, Any]:
    actual = pin(relative)
    wanted = {"bytes": expected.get("bytes"), "sha256": expected.get("sha256")}
    bytes_match = wanted["bytes"] is None or actual["bytes"] == wanted["bytes"]
    matched = actual["sha256"] == wanted["sha256"] and bytes_match
    return {
        "path": actual["path"],
        "expected": wanted,
        "actual": actual,
        "status": "match" if matched else "mismatch",
    }


def compare_record(record: dict[str, Any], *, role: str | None = None) -> dict[str, Any]:
    expected = record.get("expected") if isinstance(record.get("expected"), dict) else record
    result = compare_pin(record["path"], expected)
    if role is not None:
        result["role"] = role
    return result


def mismatches(checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [check for check in checks if check.get("status") not in (None, "match")]


def load_previous() -> tuple[Path, dict[str, Any]]:
    return read_json(PREVIOUS_MESSAGE.relative_to(ROOT))


def frozen_component_checks(previous_popup: dict[str, Any]) -> dict[str, Any]:
    source = previous_popup["current_source_pins"]
    source_checks = {
        "native_writer_sources": [compare_record(item) for item in source["native_report_002_sources"]],
        "reader_transport_sources": [compare_record(item) for item in source["reader_006_sources"]],
        "reader_report": compare_pin(
            source["reader_006_report"]["path"],
            {"bytes": source["reader_006_report"]["actual"]["bytes"],
             "sha256": source["reader_006_report"]["expected_sha256"]},
        ),
    }
    artifacts = [compare_record(item) for item in previous_popup["current_artifacts"]["reader_report_006_artifacts"]]
    all_checks = source_checks["native_writer_sources"] + source_checks["reader_transport_sources"] + [source_checks["reader_report"]] + artifacts
    return {
        "source_checks": source_checks,
        "artifact_checks": artifacts,
        "mismatch_count": len(mismatches(all_checks)),
        "checks": all_checks,
    }


def coverage_checks(previous: dict[str, Any]) -> dict[str, Any]:
    coverage = previous["coverage_and_scope"]
    checks = [
        compare_pin(coverage["docs_path"], {"bytes": coverage["docs_bytes"], "sha256": coverage["docs_sha256"]}),
        compare_pin(coverage["stage_path"], {"bytes": coverage["stage_bytes"], "sha256": coverage["stage_sha256"]}),
    ]
    actual = coverage["actual"]
    expected = coverage["expected"]
    core_counts_match = (
        actual.get("topic_count") == expected.get("topic_count")
        and actual.get("field_count") == expected.get("field_count")
        and actual.get("field_counts") == expected.get("field_counts")
    )
    return {
        "checks": checks,
        "mismatch_count": len(mismatches(checks)),
        "expected": coverage["expected"],
        "actual": coverage["actual"],
        "core_counts_match": core_counts_match,
        "B01_B04": coverage["B01_B04"],
        "goal_complete": coverage["goal_complete"],
    }


def receipt_gap() -> dict[str, Any]:
    index_path, index = read_json("work/runtime/information-battle-fragments-20261025-001/research-index-001.json")
    query = next(item for item in index["queries"] if item["name"] == "localized_format_14b33a0")
    request = compare_pin(query["request"]["path"], query["request"])
    readback = compare_pin(query["readback"]["path"], query["readback"])
    selected = compare_pin(query["selected"]["path"], query["selected"])
    evidence = bounded_metadata(query["evidence"]["path"])
    run_path = Path(query["request"]["path"]).parent / "run.json"
    run_relative = run_path.as_posix()
    run_exists = (ROOT / run_path).is_file()
    return {
        "research_index": pin(index_path.relative_to(ROOT)),
        "request": request,
        "readback": readback,
        "selected": selected,
        "evidence": evidence,
        "run": {
            "path": run_relative,
            "exists": run_exists,
            "status": "unknown_expected_gap" if not run_exists else "unexpected_present",
            "provider_exit_code": None,
            "provider_peak_committed_bytes": None,
        },
        "status": "unknown_expected_gap" if not run_exists else "review_required",
        "provider_exit_code": None,
        "provider_peak_committed_bytes": None,
        "receipt_synthesized": False,
        "reason": "historical postread guard rejected 32,568,212-byte evidence; missing run.json is preserved as unknown",
    }


def third_query() -> dict[str, Any]:
    directory = "work/runtime/information-battle-fragments-20261025-001/rea-message-membership-001"
    request_path, request = read_json(f"{directory}/request.json")
    run_path, run = read_json(f"{directory}/run.json")
    checks = [pin(request_path.relative_to(ROOT)), pin(run_path.relative_to(ROOT))]
    for name in ("evidence.json", "selected-evidence-001.json", "readback-recovery-001.json"):
        checks.append(pin(f"{directory}/{name}"))
    run_ok = (
        request.get("node") == "0x84c0b0"
        and run.get("provider_exit_code") == 0
        and run.get("wrapper_exit_code") == 0
        and run.get("status") == "completed"
        and run.get("cleanup", {}).get("closed_process_receipt") is True
        and run.get("database_unchanged") is True
    )
    return {
        "request": pin(request_path.relative_to(ROOT)),
        "run": pin(run_path.relative_to(ROOT)),
        "artifact_checks": checks,
        "request_node": request.get("node"),
        "procedure": request.get("procedure"),
        "provider_exit_code": run.get("provider_exit_code"),
        "wrapper_exit_code": run.get("wrapper_exit_code"),
        "status": run.get("status"),
        "closed_process_receipt": run.get("cleanup", {}).get("closed_process_receipt"),
        "database_unchanged": run.get("database_unchanged"),
        "checks_passed": run_ok,
    }


def harness_sources(query_report: dict[str, Any]) -> dict[str, Any]:
    checks = []
    for relative in ("reverse_engineering/cache_query.py", "reverse_engineering/ghidra_cache.py", "reverse_engineering/rea_cache_loader.mjs"):
        checks.append(pin(relative))
    report_expected = query_report["source_pins"]["reverse_engineering/cache_query.py"]
    report_check = compare_pin(report_expected["path"], report_expected)
    return {
        "checks": checks,
        "query_report_cache_query_check": report_check,
        "mismatch_count": len(mismatches([report_check])),
    }


def production_report() -> dict[str, Any]:
    previous_path, previous = load_previous()
    popup_path, popup = read_json(PREVIOUS_POPUP.relative_to(ROOT))
    source82 = [compare_pin(item["path"], expected_pin(item)) for item in previous["pin_checks"]]
    frozen_queue = []
    for item in previous["freeze_points"]["queue_drain_wire_source_pins"]:
        actual = item["actual"]
        frozen_queue.append(compare_pin(actual["path"], {"bytes": actual["bytes"], "sha256": item["expected_sha256"] or actual["sha256"]}))
    frozen_standalone = [compare_record(item) for item in previous["freeze_points"]["standalone_message_artifacts"]]
    transport = previous["source_only_integration_gap"]["python_transport_store"]
    transport_sources = [compare_record(entry) for entry in transport["source_files"].values()]
    transport_sources.append(compare_pin(transport["report"]["path"], transport["report"]))
    control_probe = compare_pin(
        previous["source_only_integration_gap"]["control_probe_line_sink"]["path"],
        {"bytes": (ROOT / previous["source_only_integration_gap"]["control_probe_line_sink"]["path"]).stat().st_size,
         "sha256": previous["source_only_integration_gap"]["control_probe_line_sink"]["sha256"]},
    )
    installed = [compare_record(item) for item in previous["installed_v22_local_records"]["records"]]
    coverage = coverage_checks(previous)
    frozen_components = frozen_component_checks(popup)
    gap = receipt_gap()
    query_report_path, query_report = read_json("work/runtime/information-battle-fragments-20261025-001/query-receipt-test-001/report-002.json")
    query_report_pin = pin(query_report_path.relative_to(ROOT))
    third = third_query()
    harness = harness_sources(query_report)
    all_checks = source82 + frozen_queue + frozen_standalone + transport_sources + [control_probe] + installed + coverage["checks"] + frozen_components["checks"] + third["artifact_checks"] + harness["checks"] + [harness["query_report_cache_query_check"]]
    current_mismatches = mismatches(all_checks)
    gap_ok = gap["status"] == "unknown_expected_gap" and gap["receipt_synthesized"] is False and gap["run"]["exists"] is False
    status = "passed_read_only_source_audit" if not current_mismatches and gap_ok and third["checks_passed"] else "failed_source_audit"
    return {
        "schema": "information_battle_fragments/production_preservation_v1",
        "status": status,
        "scope": {
            "stage": STAGE.relative_to(ROOT).as_posix(),
            "purpose": "独立核对第十七批82项生产pins、冻结传输组件与本批查询收据，不修改既有证据。",
            "hashing": "Python按1MiB块流式SHA-256；每个输入先做workspace/is_file/16MiB预检，32MB历史证据只记录有界元数据。",
            "tests_run": False,
            "game_or_process_accessed": False,
            "rea_access": False,
            "full_suite_run": False,
            "production_modified": False,
            "old_reports_modified": False,
        },
        "audit_script": pin("work/audit_information_battle_fragments_components.py"),
        "previous_preservation": {
            "path": previous_path.relative_to(ROOT).as_posix(),
            "sha256": stream_sha256(previous_path),
            "source_pin_count": len(previous["pin_checks"]),
            "historical_report_reused": True,
        },
        "previous_popup_component_audit": {
            "path": popup_path.relative_to(ROOT).as_posix(),
            "sha256": stream_sha256(popup_path),
            "status": popup.get("status"),
        },
        "source_pin_snapshot": {
            "expected_count": 82,
            "match_count": len(source82) - len(mismatches(source82)),
            "mismatch_count": len(mismatches(source82)),
            "checks": source82,
        },
        "frozen_queue_drain_wire": {
            "checks": frozen_queue,
            "mismatch_count": len(mismatches(frozen_queue)),
            "standalone_artifacts": frozen_standalone,
            "standalone_mismatch_count": len(mismatches(frozen_standalone)),
        },
        "frozen_writer_tailer_transport": {
            "previous_component_checks": frozen_components,
            "transport_source_checks": transport_sources,
            "control_probe": control_probe,
            "mismatch_count": frozen_components["mismatch_count"] + len(mismatches(transport_sources + [control_probe])),
        },
        "installed_v22_local_records": {
            "checks": installed,
            "mismatch_count": len(mismatches(installed)),
            "interpretation": "仅核对本地artifact/manifest，不访问游戏进程。",
        },
        "coverage": coverage,
        "query_receipt_002": {
            "report": query_report_pin,
            "status": query_report.get("status"),
            "tests": query_report.get("tests"),
            "source_pins": query_report.get("source_pins"),
        },
        "third_real_query": third,
        "current_harness_sources": harness,
        "historical_missing_receipt": gap,
        "conclusion": {
            "production_82_match": not mismatches(source82),
            "frozen_queue_drain_wire_match": not mismatches(frozen_queue + frozen_standalone),
            "frozen_writer_tailer_transport_match": frozen_components["mismatch_count"] == 0 and not mismatches(transport_sources + [control_probe]),
            "third_real_query_84c0b0_closed": third["checks_passed"],
            "old_14b33a0_run_missing_remains_unknown": gap_ok,
            "current_cache_query_receipt_002": query_report.get("status") == "passed",
            "coverage_74_397_preserved": coverage["core_counts_match"],
            "B01_B04": "planned",
            "goal_complete": False,
            "new_live_or_full_regression_claim": False,
            "current_mismatch_count": len(current_mismatches),
        },
    }


def report_entry_checks(report: dict[str, Any], groups: tuple[str, ...]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for group in groups:
        value = report.get(group, {})
        if isinstance(value, dict):
            for item in value.values():
                if isinstance(item, dict) and item.get("path") and item.get("sha256"):
                    checks.append(compare_pin(item["path"], item))
                elif isinstance(item, list):
                    for nested in item:
                        if isinstance(nested, dict) and nested.get("path") and nested.get("sha256"):
                            checks.append(compare_pin(nested["path"], nested))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and item.get("path") and item.get("sha256"):
                    checks.append(compare_pin(item["path"], item))
    return checks


def component_report() -> dict[str, Any]:
    production_path = STAGE / "production-preservation-001.json"
    if not production_path.is_file():
        raise FileNotFoundError(production_path)
    production = json.loads(production_path.read_text(encoding="utf-8"))
    if production.get("status") != "passed_read_only_source_audit":
        raise ValueError("production preservation must pass before component audit")
    previous_path, previous = load_previous()
    native_path, native = read_json("work/runtime/information-battle-fragments-20261025-001/native-fragment-test-001/report.json")
    native_pin = pin(native_path.relative_to(ROOT))
    native_sources = report_entry_checks(native, ("source_pins", "artifacts"))
    native_semantics = {
        "status_passed": native.get("status") == "passed",
        "opaque_only": native.get("scope", {}).get("opaque_only") is True,
        "no_game_or_rea": native.get("scope", {}).get("game_or_process_accessed") is False and native.get("scope", {}).get("rpm_or_rea") is False,
        "message_sizes": [item.get("total_bytes") for item in native.get("stream", {}).get("messages", [])],
        "expected_message_sizes": [1, 4032, 4033, 10037, 1048576],
        "five_messages": len(native.get("stream", {}).get("messages", [])) == 5,
        "duplicate_outer_record_count": native.get("stream", {}).get("duplicate_outer_record_count"),
        "fragment_total": native.get("stream", {}).get("fragment_total"),
    }
    reassembly_path, reassembly = read_json("work/runtime/information-battle-fragments-20261025-001/python-reassembly-test-001/report-002.json")
    reassembly_pin = pin(reassembly_path.relative_to(ROOT))
    reassembly_sources = report_entry_checks(reassembly, ("source_pins",))
    reassembly_artifacts = [
        compare_pin(reassembly["verification"]["pytest_output"]["path"], reassembly["verification"]["pytest_output"]),
    ]
    for item in reassembly["native_provenance"].values():
        if isinstance(item, dict) and item.get("path") and item.get("sha256"):
            reassembly_artifacts.append(compare_pin(item["path"], item))
    old_reassembly_path = reassembly["supersedes"]["path"]
    old_reassembly = compare_pin(old_reassembly_path, reassembly["supersedes"])
    query_path, query = read_json("work/runtime/information-battle-fragments-20261025-001/query-receipt-test-001/report-002.json")
    query_pin = pin(query_path.relative_to(ROOT))
    query_sources = report_entry_checks(query, ("source_pins",))
    query_junit = compare_pin(query["tests"]["junit"]["path"], query["tests"]["junit"])
    third = third_query()
    harness = harness_sources(query)
    gap = receipt_gap()
    all_current = native_sources + reassembly_sources + reassembly_artifacts + query_sources + [query_junit] + third["artifact_checks"] + harness["checks"] + [harness["query_report_cache_query_check"]]
    current_mismatch = mismatches(all_current)
    native_ok = native_semantics["status_passed"] and native_semantics["opaque_only"] and native_semantics["no_game_or_rea"] and native_semantics["message_sizes"] == native_semantics["expected_message_sizes"] and native_semantics["duplicate_outer_record_count"] == 1 and native_semantics["fragment_total"] == 268
    reassembly_ok = reassembly.get("status") == "passed" and reassembly.get("report_version") == 2 and reassembly.get("verification", {}).get("exit_code") == 0 and reassembly.get("verification", {}).get("tests_passed") == 13 and reassembly.get("verification", {}).get("subtests_passed") == 4
    query_ok = query.get("status") == "passed" and query.get("tests", {}).get("pytest", {}).get("tests") == 19
    gap_ok = gap["status"] == "unknown_expected_gap" and gap["receipt_synthesized"] is False and gap["run"]["exists"] is False
    status = "passed_current_fragment_component_audit" if not current_mismatch and native_ok and reassembly_ok and query_ok and third["checks_passed"] and gap_ok else "failed_current_fragment_component_audit"
    return {
        "schema": "information_battle_fragments/component_source_audit_v1",
        "status": status,
        "scope": {
            "stage": STAGE.relative_to(ROOT).as_posix(),
            "purpose": "核对分片native组件、重组report-002、query receipt-002及第十七批冻结传输组件的当前来源。",
            "hashing": "Python按1MiB块流式SHA-256；每个输入先做workspace/is_file/16MiB预检；不读32MB历史evidence。",
            "tests_run": False,
            "game_or_process_accessed": False,
            "rea_access": False,
            "full_suite_run": False,
            "production_modified": False,
            "old_reports_modified": False,
        },
        "audit_script": pin("work/audit_information_battle_fragments_components.py"),
        "production_preservation": pin("work/runtime/information-battle-fragments-20261025-001/production-preservation-001.json"),
        "previous_message_preservation": {
            "path": previous_path.relative_to(ROOT).as_posix(),
            "sha256": stream_sha256(previous_path),
            "source_pin_count": len(previous["pin_checks"]),
        },
        "current_components": {
            "native_fragment_report": native_pin,
            "native_fragment_sources_and_artifacts": native_sources,
            "native_semantics": native_semantics,
            "native_mismatch_count": len(mismatches(native_sources)),
            "python_reassembly_report_002": reassembly_pin,
            "python_reassembly_sources": reassembly_sources,
            "python_reassembly_artifacts": reassembly_artifacts,
            "python_reassembly_status": reassembly.get("status"),
            "python_reassembly_tests": reassembly.get("verification"),
            "python_reassembly_report_001_historical": old_reassembly,
            "query_receipt_report_002": query_pin,
            "query_receipt_sources": query_sources,
            "query_receipt_junit": query_junit,
            "query_receipt_status": query.get("status"),
            "query_receipt_tests": query.get("tests"),
            "third_real_query": third,
            "current_harness_sources": harness,
            "mismatch_count": len(current_mismatch),
        },
        "historical_missing_receipt": gap,
        "conclusion": {
            "current_fragment_sources_match": not current_mismatch,
            "native_fragment_five_group_validation": native_ok,
            "reassembly_report_002_current": reassembly_ok,
            "reassembly_report_001_preserved": old_reassembly["status"] == "match",
            "query_receipt_002_current": query_ok,
            "third_real_query_84c0b0_closed": third["checks_passed"],
            "old_14b33a0_run_missing_remains_unknown": gap_ok,
            "production_82_preservation_report_passed": production.get("status") == "passed_read_only_source_audit",
            "opaque_test_bytes_only": True,
            "B01_B04_semantic_delivery": "not_claimed",
            "goal_complete": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("production", "component"), default="production")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()
    output = Path(args.output) if args.output else STAGE / ("production-preservation-001.json" if args.mode == "production" else "component-source-audit-001.json")
    output = (ROOT / output).resolve() if not output.is_absolute() else output.resolve()
    output.relative_to(ROOT)
    output.parent.mkdir(parents=True, exist_ok=True)
    report = production_report() if args.mode == "production" else component_report()
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": output.relative_to(ROOT).as_posix(), "status": report["status"], "bytes": output.stat().st_size}, ensure_ascii=False))
    return 0 if report["status"].startswith("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
