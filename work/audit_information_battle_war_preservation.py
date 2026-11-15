#!/usr/bin/env python3
"""Audit retained information sources without opening the game or REA.

The audit is deliberately driven by the previous fragments preservation and
component reports.  It hashes only their explicitly pinned paths, so a new
reader or an unrelated worktree file cannot silently enter this preservation
scope.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FRAGMENTS_STAGE = ROOT / "work" / "runtime" / "information-battle-fragments-20261025-001"
WAR_STAGE = ROOT / "work" / "runtime" / "information-battle-war-records-20261025-001"
PREVIOUS_PRESERVATION = FRAGMENTS_STAGE / "production-preservation-001.json"
COMPONENT_AUDIT = FRAGMENTS_STAGE / "component-source-audit-001.json"
DEFAULT_OUTPUT = WAR_STAGE / "production-preservation-001.json"

PREVIOUS_PRESERVATION_SHA256 = (
    "d981be5d54ece14806bb0a64fa1ddaf0faf023f41493bb1ebafe7db733b94e34"
)
COMPONENT_AUDIT_SHA256 = (
    "1c3ec76f65c61954b50437f1fe9e16fe10e4b09724ca6187ad2259690f25c28c"
)
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 512 * 1024
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class PreservationAuditError(RuntimeError):
    """Raised when the retained audit inputs are not trustworthy."""


def _workspace_path(relative: str) -> Path:
    """Resolve a report path while rejecting absolute paths and escapes."""

    if not isinstance(relative, str) or not relative or len(relative) > 512:
        raise PreservationAuditError(f"invalid pinned path: {relative!r}")
    candidate = Path(relative)
    if candidate.is_absolute() or candidate.drive:
        raise PreservationAuditError(f"absolute pinned path is forbidden: {relative!r}")
    resolved = (ROOT / candidate).resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError as exc:
        raise PreservationAuditError(f"pinned path escapes workspace: {relative!r}") from exc
    return resolved


def _hash_file(path: Path, *, max_bytes: int = MAX_INPUT_BYTES) -> dict[str, Any]:
    """Stream one bounded file and detect a concurrent replacement."""

    result: dict[str, Any] = {"path": str(path.relative_to(ROOT)).replace("\\", "/")}
    try:
        before = path.stat()
    except OSError as exc:
        result.update({"exists": False, "status": "missing", "error": str(exc)})
        return result
    result["exists"] = path.is_file()
    result["bytes"] = before.st_size
    if not path.is_file():
        result["status"] = "not_file"
        return result
    if before.st_size > max_bytes:
        result.update({"status": "budget_exceeded", "max_bytes": max_bytes})
        return result

    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(HASH_CHUNK_BYTES), b""):
                digest.update(chunk)
    except OSError as exc:
        result.update({"status": "read_error", "error": str(exc)})
        return result
    after = path.stat()
    result["sha256"] = digest.hexdigest()
    result["status"] = "stable" if (before.st_size, before.st_mtime_ns) == (
        after.st_size,
        after.st_mtime_ns,
    ) else "changed_during_read"
    if result["status"] != "stable":
        result["bytes_after"] = after.st_size
        result["mtime_ns_before"] = before.st_mtime_ns
        result["mtime_ns_after"] = after.st_mtime_ns
    return result


def _load_json(path: Path, expected_sha256: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load a small retained report only after its fixed SHA-256 check."""

    actual = _hash_file(path, max_bytes=MAX_MANIFEST_BYTES)
    if actual.get("status") != "stable" or actual.get("sha256") != expected_sha256:
        raise PreservationAuditError(
            f"retained report pin mismatch: {path} expected {expected_sha256}, "
            f"got {actual.get('sha256')} ({actual.get('status')})"
        )
    try:
        data = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise PreservationAuditError(f"cannot parse retained report {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise PreservationAuditError(f"retained report is not an object: {path}")
    return data, actual


def _expected_from_row(row: Any) -> tuple[str, dict[str, Any]]:
    if not isinstance(row, dict):
        raise PreservationAuditError(f"pin row is not an object: {row!r}")
    relative = row.get("path")
    expected = row.get("expected")
    if expected is None and isinstance(row.get("sha256"), str):
        expected = {"bytes": row.get("bytes"), "sha256": row.get("sha256")}
    if not isinstance(relative, str) or not isinstance(expected, dict):
        raise PreservationAuditError(f"pin row has no expected identity: {row!r}")
    size = expected.get("bytes")
    digest = expected.get("sha256")
    if size is not None and (isinstance(size, bool) or not isinstance(size, int) or size < 0):
        raise PreservationAuditError(f"invalid expected size for {relative!r}")
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise PreservationAuditError(f"invalid expected SHA-256 for {relative!r}")
    _workspace_path(relative)
    return relative.replace("\\", "/"), {"bytes": size, "sha256": digest}


def _append_rows(
    pins: dict[str, dict[str, Any]],
    groups: dict[str, list[str]],
    group: str,
    rows: Any,
    provenance: str,
    input_errors: list[str],
) -> None:
    if not isinstance(rows, list):
        input_errors.append(f"{provenance} is not a list")
        return
    paths = groups.setdefault(group, [])
    for index, row in enumerate(rows):
        try:
            relative, expected = _expected_from_row(row)
        except PreservationAuditError as exc:
            input_errors.append(f"{provenance}[{index}]: {exc}")
            continue
        if relative not in paths:
            paths.append(relative)
        existing = pins.get(relative)
        if existing is None:
            pins[relative] = {
                "path": relative,
                "expected": expected,
                "provenance": [provenance],
            }
        else:
            if existing["expected"] != expected:
                input_errors.append(
                    f"conflicting expected pin for {relative}: "
                    f"{existing['expected']} vs {expected}"
                )
            if provenance not in existing["provenance"]:
                existing["provenance"].append(provenance)


def _rows(value: Any, key: str, input_errors: list[str], label: str) -> Any:
    if not isinstance(value, dict):
        input_errors.append(f"{label} is not an object")
        return []
    rows = value.get(key)
    if not isinstance(rows, list):
        input_errors.append(f"{label}.{key} is not a list")
        return []
    return rows


def _pin_map_rows(value: Any, input_errors: list[str], label: str) -> list[dict[str, Any]]:
    """Convert an older path->pin map to the row shape used by this audit."""

    if not isinstance(value, dict):
        input_errors.append(f"{label} is not an object")
        return []
    rows: list[dict[str, Any]] = []
    for path, pin in value.items():
        if not isinstance(pin, dict):
            input_errors.append(f"{label}[{path!r}] is not an object")
            continue
        rows.append({"path": path, "expected": pin})
    return rows


def _check_inputs() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    previous, previous_pin = _load_json(PREVIOUS_PRESERVATION, PREVIOUS_PRESERVATION_SHA256)
    components, components_pin = _load_json(COMPONENT_AUDIT, COMPONENT_AUDIT_SHA256)
    if previous.get("status") != "passed_read_only_source_audit":
        raise PreservationAuditError("previous fragments preservation was not passed")
    if components.get("status") != "passed_current_fragment_component_audit":
        raise PreservationAuditError("previous fragment component audit was not passed")
    snapshot = previous.get("source_pin_snapshot")
    if not isinstance(snapshot, dict) or snapshot.get("expected_count") != 82:
        raise PreservationAuditError("previous 82-pin snapshot is missing or has changed count")
    if not isinstance(snapshot.get("checks"), list) or len(snapshot["checks"]) != 82:
        raise PreservationAuditError("previous 82-pin check list is incomplete")
    return previous, components, {
        "previous_preservation": previous_pin,
        "component_audit": components_pin,
    }


def _collect_pins(previous: dict[str, Any], components: dict[str, Any]) -> tuple[dict[str, Any], dict[str, list[str]], list[str]]:
    pins: dict[str, dict[str, Any]] = {}
    groups: dict[str, list[str]] = {}
    input_errors: list[str] = []

    _append_rows(
        pins,
        groups,
        "information_production_82",
        previous["source_pin_snapshot"]["checks"],
        "fragments.production_preservation.source_pin_snapshot.checks",
        input_errors,
    )

    frozen_queue = previous.get("frozen_queue_drain_wire", {})
    _append_rows(pins, groups, "queue_drain_wire", _rows(frozen_queue, "checks", input_errors, "frozen_queue_drain_wire"), "fragments.frozen_queue_drain_wire.checks", input_errors)
    _append_rows(pins, groups, "queue_drain_wire", _rows(frozen_queue, "standalone_artifacts", input_errors, "frozen_queue_drain_wire"), "fragments.frozen_queue_drain_wire.standalone_artifacts", input_errors)

    frozen_writer = previous.get("frozen_writer_tailer_transport", {})
    if not isinstance(frozen_writer, dict):
        input_errors.append("frozen_writer_tailer_transport is not an object")
    else:
        component = frozen_writer.get("previous_component_checks", {})
        _append_rows(pins, groups, "writer_tailer_transport", _rows(component, "checks", input_errors, "previous_component_checks"), "fragments.frozen_writer_tailer_transport.previous_component_checks", input_errors)
        _append_rows(pins, groups, "writer_tailer_transport", _rows(frozen_writer, "transport_source_checks", input_errors, "frozen_writer_tailer_transport"), "fragments.frozen_writer_tailer_transport.transport_source_checks", input_errors)
        control_probe = frozen_writer.get("control_probe")
        if control_probe is not None:
            _append_rows(pins, groups, "writer_tailer_transport", [control_probe], "fragments.frozen_writer_tailer_transport.control_probe", input_errors)

    current = components.get("current_components", {})
    if not isinstance(current, dict):
        input_errors.append("component audit current_components is not an object")
        current = {}
    _append_rows(pins, groups, "fragment_reassembly", current.get("native_fragment_sources_and_artifacts", []), "components.native_fragment_sources_and_artifacts", input_errors)
    _append_rows(pins, groups, "fragment_reassembly", current.get("python_reassembly_sources", []), "components.python_reassembly_sources", input_errors)
    _append_rows(pins, groups, "fragment_reassembly", current.get("python_reassembly_artifacts", []), "components.python_reassembly_artifacts", input_errors)
    for key in ("native_fragment_report", "python_reassembly_report_002", "python_reassembly_report_001_historical"):
        value = current.get(key)
        if isinstance(value, dict):
            _append_rows(pins, groups, "fragment_reassembly", [value], f"components.{key}", input_errors)

    _append_rows(pins, groups, "rea_runner", current.get("query_receipt_sources", []), "components.query_receipt_sources", input_errors)
    query_junit = current.get("query_receipt_junit")
    if isinstance(query_junit, dict):
        _append_rows(pins, groups, "rea_runner", [query_junit], "components.query_receipt_junit", input_errors)
    harness = current.get("current_harness_sources", {})
    if isinstance(harness, dict):
        _append_rows(pins, groups, "rea_runner", harness.get("checks", []), "components.current_harness_sources.checks", input_errors)
        cache_check = harness.get("query_report_cache_query_check")
        if isinstance(cache_check, dict):
            _append_rows(pins, groups, "rea_runner", [cache_check], "components.current_harness_sources.query_report_cache_query_check", input_errors)
    third_query = current.get("third_real_query", {})
    if isinstance(third_query, dict):
        _append_rows(pins, groups, "rea_runner", third_query.get("artifact_checks", []), "components.third_real_query.artifact_checks", input_errors)

    old_harness = previous.get("current_harness_sources", {})
    if isinstance(old_harness, dict):
        _append_rows(pins, groups, "rea_runner", old_harness.get("checks", []), "fragments.current_harness_sources.checks", input_errors)
        cache_check = old_harness.get("query_report_cache_query_check")
        if isinstance(cache_check, dict):
            _append_rows(pins, groups, "rea_runner", [cache_check], "fragments.current_harness_sources.query_report_cache_query_check", input_errors)
    old_receipt = previous.get("query_receipt_002", {})
    if isinstance(old_receipt, dict):
        report = old_receipt.get("report")
        if isinstance(report, dict):
            _append_rows(pins, groups, "rea_runner", [report], "fragments.query_receipt_002.report", input_errors)
        _append_rows(
            pins,
            groups,
            "rea_runner",
            _pin_map_rows(old_receipt.get("source_pins", {}), input_errors, "fragments.query_receipt_002.source_pins"),
            "fragments.query_receipt_002.source_pins",
            input_errors,
        )
        junit = old_receipt.get("tests", {}).get("junit") if isinstance(old_receipt.get("tests"), dict) else None
        if isinstance(junit, dict):
            _append_rows(pins, groups, "rea_runner", [junit], "fragments.query_receipt_002.tests.junit", input_errors)
    old_third = previous.get("third_real_query", {})
    if isinstance(old_third, dict):
        _append_rows(pins, groups, "rea_runner", old_third.get("artifact_checks", []), "fragments.third_real_query.artifact_checks", input_errors)

    for paths in groups.values():
        paths.sort()
    return pins, groups, input_errors


def _audit_pins(pins: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for relative in sorted(pins):
        record = pins[relative]
        path = _workspace_path(relative)
        actual = _hash_file(path)
        expected = record["expected"]
        if actual.get("status") == "stable":
            status = "match" if (
                (expected["bytes"] is None or actual.get("bytes") == expected["bytes"])
                and actual.get("sha256") == expected["sha256"]
            ) else "mismatch"
        else:
            status = actual.get("status", "unknown")
        checks.append({
            "path": relative,
            "expected": expected,
            "actual": actual,
            "status": status,
            "provenance": record["provenance"],
        })
    return checks


def _summary(checks: list[dict[str, Any]]) -> dict[str, int]:
    result = {"count": len(checks), "match_count": 0, "mismatch_count": 0, "missing_count": 0, "budget_exceeded_count": 0}
    for check in checks:
        if check["status"] == "match":
            result["match_count"] += 1
        else:
            result["mismatch_count"] += 1
            if check["status"] == "missing":
                result["missing_count"] += 1
            if check["status"] == "budget_exceeded":
                result["budget_exceeded_count"] += 1
    return result


def run_audit(output: Path = DEFAULT_OUTPUT) -> dict[str, Any]:
    previous, components, input_records = _check_inputs()
    pins, groups, input_errors = _collect_pins(previous, components)
    if input_errors:
        raise PreservationAuditError("retained pin manifest errors: " + "; ".join(input_errors[:12]))
    checks = _audit_pins(pins)
    group_reports: dict[str, Any] = {}
    for group, paths in sorted(groups.items()):
        selected = [check for check in checks if check["path"] in set(paths)]
        group_reports[group] = {"paths": paths, **_summary(selected), "checks": selected}
    all_summary = _summary(checks)
    current_script = Path(__file__)
    script_pin = _hash_file(current_script, max_bytes=MAX_MANIFEST_BYTES)
    report: dict[str, Any] = {
        "schema": "information_battle_war_records/production_preservation_v1",
        "status": "passed_read_only_source_audit" if not input_errors and all_summary["mismatch_count"] == 0 else "failed_source_preservation",
        "scope": {
            "stage": "work/runtime/information-battle-war-records-20261025-001",
            "purpose": "独立核对上一批信息生产82项及既有战报传输、分片、重组和REA runner源pin。",
            "hashing": "Python按1MiB块流式SHA-256；单文件16MiB上限；不递归扫描工作区。",
            "game_or_process_accessed": False,
            "rea_or_rpm_accessed": False,
            "tests_run": False,
            "production_modified": False,
            "old_reports_modified": False,
            "new_reader_in_scope": False,
        },
        "audit_script": {"path": "work/audit_information_battle_war_preservation.py", **script_pin},
        "inputs": {
            "fragments_production_preservation": {"path": "work/runtime/information-battle-fragments-20261025-001/production-preservation-001.json", **input_records["previous_preservation"]},
            "fragments_component_source_audit": {"path": "work/runtime/information-battle-fragments-20261025-001/component-source-audit-001.json", **input_records["component_audit"]},
            "historical_message_preservation": {"path": "work/runtime/information-battle-message-20261025-001/message-stage/production-preservation-001.json", "sha256": previous.get("previous_preservation", {}).get("sha256")},
            "historical_popup_component_audit": {"path": "work/runtime/information-battle-popup-20261025-001/component-source-audit-001.json", "sha256": previous.get("previous_popup_component_audit", {}).get("sha256")},
        },
        "groups": group_reports,
        "overall": all_summary,
        "mismatch_paths": [check["path"] for check in checks if check["status"] != "match"],
        "conclusion": {
            "information_production_82_preserved": group_reports.get("information_production_82", {}).get("mismatch_count") == 0,
            "legacy_queue_drain_wire_preserved": group_reports.get("queue_drain_wire", {}).get("mismatch_count") == 0,
            "legacy_writer_tailer_transport_preserved": group_reports.get("writer_tailer_transport", {}).get("mismatch_count") == 0,
            "legacy_fragment_reassembly_preserved": group_reports.get("fragment_reassembly", {}).get("mismatch_count") == 0,
            "legacy_rea_runner_preserved": group_reports.get("rea_runner", {}).get("mismatch_count") == 0,
            "goal_complete": False,
        },
    }
    encoded = (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=False) + "\n").encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise PreservationAuditError(f"audit output exceeds {MAX_OUTPUT_BYTES} bytes")
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise PreservationAuditError(f"refusing to overwrite existing output: {output}")
    output.write_bytes(encoded)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    try:
        report = run_audit(args.output)
    except (OSError, PreservationAuditError, ValueError) as exc:
        print(f"preservation audit failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "status": report["status"],
        "output": str(args.output.resolve()),
        "overall": report["overall"],
        "mismatch_paths": report["mismatch_paths"],
        "group_counts": {name: value["count"] for name, value in report["groups"].items()},
    }, ensure_ascii=False, sort_keys=True))
    return 0 if report["status"] == "passed_read_only_source_audit" else 1


if __name__ == "__main__":
    raise SystemExit(main())
