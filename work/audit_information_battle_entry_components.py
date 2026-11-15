#!/usr/bin/env python3
"""Audit batch-20 entry components and preserve the previous source graph.

This is an offline, fail-closed audit.  It reads only explicitly named small
reports and re-hashes the 127 de-duplicated pins from the previous war-records
preservation report.  It never opens the game, a remote process, REA, or an
installation.  Missing final reports are reported as a blocked run and do not
create partial output files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
ENTRY_STAGE = ROOT / "work" / "runtime" / "information-battle-entry-20261025-001"
OWNED_STAGE = ROOT / "work" / "runtime" / "information-battle-owned-result-20261025-001"
WAR_STAGE = ROOT / "work" / "runtime" / "information-battle-war-records-20261025-001"

DEFAULT_OWNED_REPORT = (
    OWNED_STAGE / "owned-result-test-001" / "report-002.json"
)
DEFAULT_ABI_REPORT = ENTRY_STAGE / "abi-test-001" / "report-006.json"
DEFAULT_UNWIND_REPORT = ENTRY_STAGE / "unwind-test-001" / "report-003.json"
DEFAULT_INTEGRATION_REPORT = ENTRY_STAGE / "integration-test-001" / "report-007.json"
DEFAULT_LEDGER = ENTRY_STAGE / "entry-contract-ledger-001.json"
# 001 is the historical prepared index.  The current audit deliberately waits
# for the root's final 002 files instead of accepting that prepared state.
DEFAULT_RESEARCH_INDEX = ENTRY_STAGE / "research-index-002.json"
DEFAULT_RESEARCH_AUDIT = ENTRY_STAGE / "source-audit-002.json"
DEFAULT_OLD_PRESERVATION = WAR_STAGE / "production-preservation-001.json"
DEFAULT_COMPONENT_OUTPUT = ENTRY_STAGE / "component-source-audit-001.json"
DEFAULT_PRESERVATION_OUTPUT = ENTRY_STAGE / "production-preservation-001.json"

OLD_PRESERVATION_SHA256 = (
    "6c9b697781721ce2cd1008baae987bfdc5156cefa1238ae04641eb3042740ccc"
)
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
MAX_PIN_ROWS = 1024
MAX_WALK_DEPTH = 10
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class EntryComponentAuditError(RuntimeError):
    """A malformed or untrusted audit input."""


class MissingFinalInputs(EntryComponentAuditError):
    """Final reports are not ready; no output should be written."""

    def __init__(self, missing: list[str]):
        self.missing = missing
        super().__init__("final reports are not ready: " + "; ".join(missing))


def _relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def _workspace_path(value: str | Path) -> Path:
    """Resolve a pinned path while rejecting absolute paths and escapes."""

    if isinstance(value, Path):
        candidate = value
        if candidate.is_absolute():
            resolved = candidate.resolve()
        else:
            resolved = (ROOT / candidate).resolve()
    elif isinstance(value, str) and value and len(value) <= 1024:
        candidate = Path(value)
        if candidate.is_absolute() or candidate.drive:
            raise EntryComponentAuditError(f"absolute pinned path is forbidden: {value!r}")
        resolved = (ROOT / candidate).resolve()
    else:
        raise EntryComponentAuditError(f"invalid pinned path: {value!r}")
    try:
        resolved.relative_to(ROOT)
    except ValueError as exc:
        raise EntryComponentAuditError(f"pinned path escapes workspace: {value!r}") from exc
    return resolved


def _hash_file(path: Path, *, max_bytes: int = MAX_INPUT_BYTES) -> dict[str, Any]:
    """Stream one bounded file and reject a concurrent replacement."""

    result: dict[str, Any] = {"path": _relative(path)}
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
    try:
        after = path.stat()
    except OSError as exc:
        result.update({"status": "stat_after_read_error", "error": str(exc)})
        return result
    result["sha256"] = digest.hexdigest()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        result.update(
            {
                "status": "changed_during_read",
                "bytes_after": after.st_size,
                "mtime_ns_before": before.st_mtime_ns,
                "mtime_ns_after": after.st_mtime_ns,
            }
        )
    else:
        result["status"] = "stable"
    return result


def _load_json(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> tuple[dict[str, Any], dict[str, Any]]:
    """Hash and parse a small JSON object without reading oversized input."""

    pin = _hash_file(path, max_bytes=max_bytes)
    if pin.get("status") != "stable":
        raise EntryComponentAuditError(
            f"cannot read stable JSON {_relative(path)}: {pin.get('status')}"
        )
    try:
        raw = path.read_bytes()
        data = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EntryComponentAuditError(f"cannot parse JSON {_relative(path)}: {exc}") from exc
    if not isinstance(data, dict):
        raise EntryComponentAuditError(f"JSON root is not an object: {_relative(path)}")
    # Detect a replacement after the parse as well as during the streaming hash.
    after = _hash_file(path, max_bytes=max_bytes)
    if after.get("status") != "stable" or after.get("sha256") != pin.get("sha256"):
        raise EntryComponentAuditError(f"JSON changed after hash: {_relative(path)}")
    return data, pin


def _expected_pin(value: Any, *, label: str) -> tuple[str, dict[str, Any]]:
    if not isinstance(value, dict):
        raise EntryComponentAuditError(f"{label} is not an object")
    path = value.get("path")
    expected = value.get("expected") if isinstance(value.get("expected"), dict) else value
    digest = expected.get("sha256")
    size = expected.get("bytes", expected.get("size_bytes"))
    if not isinstance(path, str) or not path or len(path) > 1024:
        raise EntryComponentAuditError(f"{label} has invalid path")
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise EntryComponentAuditError(f"{label} has invalid SHA-256")
    if size is not None and (
        isinstance(size, bool) or not isinstance(size, int) or size < 0
    ):
        raise EntryComponentAuditError(f"{label} has invalid byte count")
    _workspace_path(path)
    return path.replace("\\", "/"), {"bytes": size, "sha256": digest}


def _audit_pin(path: str, expected: dict[str, Any], provenance: str) -> dict[str, Any]:
    actual = _hash_file(_workspace_path(path))
    if actual.get("status") == "stable":
        size_ok = expected.get("bytes") is None or actual.get("bytes") == expected.get("bytes")
        status = "match" if size_ok and actual.get("sha256") == expected.get("sha256") else "mismatch"
    else:
        status = actual.get("status", "unknown")
    return {
        "path": path,
        "expected": expected,
        "actual": actual,
        "status": status,
        "provenance": provenance,
    }


def _dedupe_pin_rows(rows: Iterable[tuple[str, Any, str]]) -> tuple[list[dict[str, Any]], list[str]]:
    """Normalize and deduplicate declared source/artifact rows."""

    by_path: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for path, value, provenance in rows:
        try:
            relative, expected = _expected_pin(value, label=provenance)
        except EntryComponentAuditError as exc:
            errors.append(str(exc))
            continue
        existing = by_path.get(relative)
        if existing is None:
            by_path[relative] = {
                "path": relative,
                "expected": expected,
                "provenance": [provenance],
            }
        else:
            if existing["expected"] != expected:
                errors.append(f"conflicting expected pin for {relative}: {provenance}")
            if provenance not in existing["provenance"]:
                existing["provenance"].append(provenance)
        if len(by_path) > MAX_PIN_ROWS:
            errors.append(f"declared pin count exceeds {MAX_PIN_ROWS}")
            break
    return [by_path[key] for key in sorted(by_path)], errors


def _specific_report_rows(kind: str, data: dict[str, Any]) -> tuple[list[tuple[str, Any, str]], list[str]]:
    rows: list[tuple[str, Any, str]] = []
    errors: list[str] = []
    if kind == "owned":
        value = data.get("source_pins")
        if not isinstance(value, dict):
            errors.append("owned report source_pins is missing")
        else:
            rows.extend((str(name), pin, f"source_pins.{name}") for name, pin in value.items())
        if isinstance(data.get("artifact"), dict):
            rows.append(("artifact", data["artifact"], "artifact"))
        else:
            errors.append("owned report artifact is missing")
    elif kind == "abi":
        value = data.get("sources")
        if not isinstance(value, dict):
            errors.append("ABI report sources is missing")
        else:
            rows.extend((str(name), dict(pin, path=name), f"sources.{name}") for name, pin in value.items() if isinstance(pin, dict))
        if isinstance(data.get("artifact"), dict):
            rows.append(("artifact", data["artifact"], "artifact"))
        else:
            errors.append("ABI report artifact is missing")
    elif kind == "unwind":
        value = data.get("source_pins")
        if not isinstance(value, dict):
            errors.append("unwind report source_pins is missing")
        else:
            rows.extend((str(name), pin, f"source_pins.{name}") for name, pin in value.items())
        if isinstance(data.get("artifact"), dict):
            rows.append(("artifact", data["artifact"], "artifact"))
        else:
            errors.append("unwind report artifact is missing")
    return rows, errors


_PIN_CONTAINER_KEYS = {
    "sources",
    "source_pins",
    "source_files",
    "artifacts",
    "artifact",
    "artifact_pins",
    "dependencies",
    "inputs",
    "reports",
    "current_source_pins",
    "source_manifest",
}


def _looks_like_workspace_path(value: str) -> bool:
    return (
        "/" in value
        or "\\" in value
        or value.endswith((".py", ".cpp", ".S", ".h", ".inc", ".json", ".exe", ".txt", ".log", ".sqlite3"))
    )


def _generic_pin_rows(value: Any, *, label: str, depth: int = 0) -> list[tuple[str, Any, str]]:
    """Find explicit path/SHA rows in a report, with bounded recursion."""

    if depth > MAX_WALK_DEPTH:
        return []
    rows: list[tuple[str, Any, str]] = []
    if isinstance(value, dict):
        if isinstance(value.get("path"), str) and isinstance(value.get("sha256"), str):
            if value.get("bytes") is not None or value.get("size_bytes") is not None:
                rows.append((value["path"], value, label))
        for key, child in value.items():
            # Several reports use a path->pin map under ``sources`` rather
            # than repeating the path inside each value.  Convert that map
            # entry to the same explicit row shape before recursing.
            if key in _PIN_CONTAINER_KEYS and isinstance(child, dict):
                for mapped_path, mapped_pin in child.items():
                    if (
                        isinstance(mapped_path, str)
                        and _looks_like_workspace_path(mapped_path)
                        and isinstance(mapped_pin, dict)
                        and isinstance(mapped_pin.get("sha256"), str)
                        and (mapped_pin.get("bytes") is not None or mapped_pin.get("size_bytes") is not None)
                    ):
                        rows.append(
                            (
                                mapped_path,
                                dict(mapped_pin, path=mapped_path),
                                f"{label}.{key}[{mapped_path}]",
                            )
                        )
            if key in _PIN_CONTAINER_KEYS or isinstance(child, (dict, list)):
                rows.extend(_generic_pin_rows(child, label=f"{label}.{key}", depth=depth + 1))
    elif isinstance(value, list):
        for index, child in enumerate(value[:MAX_PIN_ROWS]):
            rows.extend(_generic_pin_rows(child, label=f"{label}[{index}]", depth=depth + 1))
    return rows[:MAX_PIN_ROWS]


def _status_is_final(status: Any, *, strict_passed: bool) -> bool:
    if not isinstance(status, str) or not status.strip():
        return False
    normalized = status.lower()
    if any(word in normalized for word in ("pending", "missing", "failed", "blocked", "unknown", "prepared")):
        return False
    if strict_passed:
        return normalized == "passed" or normalized.startswith("passed_")
    return True


def _report_revision_from_artifact(data: dict[str, Any]) -> str | None:
    artifact = data.get("artifact")
    if not isinstance(artifact, dict) or not isinstance(artifact.get("path"), str):
        return None
    match = re.search(r"-(\d+)\.exe$", artifact["path"])
    return match.group(1) if match else None


def _inline_stream_record(value: Any, *, source: str) -> dict[str, Any] | None:
    if not isinstance(value, str):
        return None
    encoded = value.encode("utf-8")
    return {
        "source": source,
        "bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "status": "inline_report_captured",
    }


def _stdout_audit(kind: str, data: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Check external stdout pins where present, otherwise retain inline hash."""

    errors: list[str] = []
    inline_run = None
    inline_compile = None
    if isinstance(data.get("run"), dict):
        inline_run = _inline_stream_record(data["run"].get("stdout"), source="report.run.stdout")
        inline_compile = _inline_stream_record(
            data.get("compile", {}).get("stdout") if isinstance(data.get("compile"), dict) else None,
            source="report.compile.stdout",
        )
    artifact = data.get("artifact") if isinstance(data.get("artifact"), dict) else {}
    revision = _report_revision_from_artifact(data)
    external: list[dict[str, Any]] = []
    if kind in {"abi", "integration"} and revision:
        base = _workspace_path(artifact["path"]).parent
        expected_run = data.get("run_receipt", {}).get("stdout_sha256") if isinstance(data.get("run_receipt"), dict) else None
        expected_compile = data.get("compile_receipt", {}).get("stdout_sha256") if isinstance(data.get("compile_receipt"), dict) else None
        external.extend([
            {"role": "run", "path": base / f"run-{revision}.stdout.txt", "expected_sha256": expected_run},
            {"role": "compile", "path": base / f"compile-{revision}.stdout.txt", "expected_sha256": expected_compile},
        ])
    elif kind == "unwind" and revision:
        base = _workspace_path(artifact["path"]).parent
        external.extend([
            {"role": "run", "path": base / f"run-{revision}.stdout.log", "expected_sha256": None},
            {"role": "compile", "path": base / f"compile-{revision}.stdout.log", "expected_sha256": None},
        ])
    records: list[dict[str, Any]] = []
    for candidate in external:
        path = candidate["path"]
        if path.exists():
            actual = _hash_file(path)
            expected = candidate.get("expected_sha256")
            if expected is not None and (
                not isinstance(expected, str) or SHA256_RE.fullmatch(expected) is None
            ):
                errors.append(f"{candidate['role']} stdout receipt has invalid SHA")
            status = actual.get("status")
            if status == "stable" and isinstance(expected, str):
                status = "match" if actual.get("sha256") == expected else "mismatch"
            elif status == "stable":
                inline = inline_run if candidate["role"] == "run" else inline_compile
                if inline is not None:
                    status = "match" if actual.get("sha256") == inline.get("sha256") else "mismatch"
            if status != "match":
                errors.append(f"{candidate['role']} stdout pin {status} for {_relative(path)}")
            records.append({
                "role": candidate["role"],
                "path": _relative(path),
                "expected_sha256": expected,
                "actual": actual,
                "status": status,
            })
        else:
            records.append({
                "role": candidate["role"],
                "path": _relative(path),
                "expected_sha256": candidate.get("expected_sha256"),
                "status": "external_file_missing_inline_fallback",
            })
    if inline_run is not None:
        records.append(inline_run)
    if inline_compile is not None:
        records.append(inline_compile)
    if not records and kind in {"owned", "abi", "unwind", "integration"}:
        errors.append("report has no stdout receipt or captured stdout")
    return {"records": records, "external_required": False}, errors


def _audit_report(name: str, path: Path, kind: str) -> dict[str, Any]:
    data, report_pin = _load_json(path)
    strict = kind in {"owned", "abi", "unwind", "integration"}
    errors: list[str] = []
    if not _status_is_final(data.get("status"), strict_passed=strict):
        errors.append(f"{name} status is not final/passed: {data.get('status')!r}")
    integration_scope: dict[str, Any] | None = None
    if kind == "integration":
        integration_scope = {
            "read_only": data.get("read_only"),
            "game_access": data.get("game_access"),
            "rea_or_rpm": data.get("rea_or_rpm"),
            "owned_fixture_code_patch": data.get("owned_fixture_code_patch"),
        }
        if data.get("read_only") is not False:
            errors.append("integration final report must declare read_only=false for owned fixture writes")
        if data.get("game_access") is not False:
            errors.append("integration final report must declare game_access=false")
        if data.get("owned_fixture_code_patch") is not True:
            errors.append("integration final report must declare owned_fixture_code_patch=true")
    if kind in {"owned", "abi", "unwind"}:
        raw_rows, row_errors = _specific_report_rows(kind, data)
    else:
        raw_rows = _generic_pin_rows(data, label=name)
        row_errors = []
    rows, pin_errors = _dedupe_pin_rows(raw_rows)
    errors.extend(row_errors)
    errors.extend(pin_errors)
    if not rows:
        errors.append(f"{name} has no current source/artifact pins")
    checks = [_audit_pin(row["path"], row["expected"], ",".join(row["provenance"])) for row in rows]
    if any(check["status"] != "match" for check in checks):
        errors.append(f"{name} has source/artifact pin mismatch")
    stdout, stdout_errors = _stdout_audit(kind, data)
    errors.extend(stdout_errors)
    return {
        "path": _relative(path),
        "report_pin": report_pin,
        "schema": data.get("schema"),
        "status": data.get("status"),
        "status_final": not any("status is not final" in error for error in errors),
        "source_artifact_pins": checks,
        "stdout": stdout,
        "integration_scope": integration_scope,
        "errors": errors,
    }


def _load_previous_preservation(path: Path, expected_sha256: str) -> tuple[dict[str, Any], dict[str, Any]]:
    data, pin = _load_json(path)
    if pin.get("sha256") != expected_sha256:
        raise EntryComponentAuditError(
            f"previous preservation SHA mismatch: expected {expected_sha256}, got {pin.get('sha256')}"
        )
    if data.get("status") != "passed_read_only_source_audit":
        raise EntryComponentAuditError("previous war-records preservation is not passed")
    overall = data.get("overall")
    if not isinstance(overall, dict) or overall.get("count") != 127:
        raise EntryComponentAuditError("previous preservation does not declare 127 pins")
    return data, pin


def _previous_pins(data: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], list[str]]:
    pins: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    groups = data.get("groups")
    if not isinstance(groups, dict):
        raise EntryComponentAuditError("previous preservation groups are missing")
    for group_name, group in groups.items():
        if not isinstance(group, dict) or not isinstance(group.get("checks"), list):
            errors.append(f"group {group_name} has no checks list")
            continue
        for index, row in enumerate(group["checks"]):
            try:
                relative, expected = _expected_pin(row, label=f"groups.{group_name}.checks[{index}]")
            except EntryComponentAuditError as exc:
                errors.append(str(exc))
                continue
            existing = pins.get(relative)
            if existing is None:
                pins[relative] = {
                    "path": relative,
                    "expected": expected,
                    "provenance": [f"previous.groups.{group_name}.checks[{index}]"],
                }
            else:
                if existing["expected"] != expected:
                    errors.append(f"conflicting previous pin for {relative}")
                provenance = f"previous.groups.{group_name}.checks[{index}]"
                if provenance not in existing["provenance"]:
                    existing["provenance"].append(provenance)
    if len(pins) != 127:
        errors.append(f"deduplicated previous pin count is {len(pins)}, expected 127")
    return pins, errors


def _summary(checks: list[dict[str, Any]]) -> dict[str, int]:
    result = {
        "count": len(checks),
        "match_count": 0,
        "mismatch_count": 0,
        "missing_count": 0,
        "budget_exceeded_count": 0,
    }
    for check in checks:
        if check.get("status") == "match":
            result["match_count"] += 1
        else:
            result["mismatch_count"] += 1
            if check.get("status") == "missing":
                result["missing_count"] += 1
            if check.get("status") == "budget_exceeded":
                result["budget_exceeded_count"] += 1
    return result


def _history_artifact_boundary() -> dict[str, Any]:
    old = _hash_file(WAR_STAGE / "entry-unwind-pe-001.json")
    current = _hash_file(ENTRY_STAGE / "entry-unwind-pe-001.json")
    return {
        "old_misplaced_pe_report": {
            "path": _relative(WAR_STAGE / "entry-unwind-pe-001.json"),
            "actual": old,
            "treatment": "historical_extra_artifact_preserved",
        },
        "entry_regenerated_pe_report": {
            "path": _relative(ENTRY_STAGE / "entry-unwind-pe-001.json"),
            "actual": current,
            "treatment": "current_entry_stage_artifact",
        },
        "changed_old_content": False,
        "interpretation": "旧war-records位置的PE报告保留作历史额外artifact；entry阶段重新生成的报告单独核对，不能把它解释为修改旧内容。",
    }


def _preservation_report(
    old_data: dict[str, Any],
    old_pin: dict[str, Any],
    pins: dict[str, dict[str, Any]],
    input_errors: list[str],
    *,
    output_path: Path,
) -> dict[str, Any]:
    checks = [
        _audit_pin(row["path"], row["expected"], ",".join(row["provenance"]))
        for row in (pins[key] for key in sorted(pins))
    ]
    summary = _summary(checks)
    status = "passed_current_entry_preservation" if not input_errors and summary["mismatch_count"] == 0 else "failed_current_entry_preservation"
    information_checks = [
        row
        for row in checks
        if "information_production_82" in str(row.get("provenance", ""))
    ]
    report = {
        "schema": "information_battle_entry/production_preservation_v1",
        "status": status,
        "scope": {
            "stage": _relative(ENTRY_STAGE),
            "purpose": "重新核对上一批war-records production-preservation-001中的127个去重源码针，覆盖82项信息生产及旧传输、runner和重组组件。",
            "hashing": "Python按1MiB块流式SHA-256；单文件16MiB上限；仅访问显式pin，不递归扫描工作区。",
            "game_or_process_accessed": False,
            "rea_or_rpm_accessed": False,
            "tests_run": False,
            "production_modified": False,
            "old_reports_modified": False,
            "current_batch_production_changes": [],
        },
        "inputs": {
            "previous_war_records_preservation": {
                "path": _relative(DEFAULT_OLD_PRESERVATION),
                "expected_sha256": OLD_PRESERVATION_SHA256,
                "actual": old_pin,
                "status": "fixed_history_input",
            }
        },
        "source_pin_snapshot": {
            "expected_count": 127,
            "deduplicated": True,
            "checks": checks,
        },
        "overall": summary,
        "mismatch_paths": [row["path"] for row in checks if row["status"] != "match"],
        "input_errors": input_errors,
        "historical_artifact_boundary": _history_artifact_boundary(),
        "conclusion": {
            "previous_127_pins_match": summary["mismatch_count"] == 0 and not input_errors,
            "information_production_82_preserved": len(information_checks) == 82
            and all(row["status"] == "match" for row in information_checks),
            "old_misplaced_pe_report_rewritten": False,
            "goal_complete": False,
        },
        "output": {"path": _relative(output_path), "overwriting_existing": False},
    }
    return report


def _component_report(
    report_audits: dict[str, dict[str, Any]],
    preservation: dict[str, Any],
    input_pins: dict[str, dict[str, Any]],
    *,
    output_path: Path,
) -> dict[str, Any]:
    errors: list[str] = []
    for name, audit in report_audits.items():
        errors.extend(f"{name}: {error}" for error in audit.get("errors", []))
    if preservation.get("status") != "passed_current_entry_preservation":
        errors.append("previous 127-pin preservation did not pass")
    input_checks = [
        _audit_pin(row["path"], row["expected"], ",".join(row["provenance"]))
        for row in (input_pins[key] for key in sorted(input_pins))
    ]
    if any(check["status"] != "match" for check in input_checks):
        errors.append("root ledger/research or report input pin mismatch")
    status = "passed_current_entry_component_audit" if not errors else "failed_current_entry_component_audit"
    return {
        "schema": "information_battle_entry/component_source_audit_v1",
        "status": status,
        "scope": {
            "batch": "batch20",
            "stage": _relative(ENTRY_STAGE),
            "game_or_process_accessed": False,
            "rea_or_rpm_accessed": False,
            "tests_run": False,
            "production_modified": False,
            "current_production_change_expected": False,
            "coverage_goal": {"topic_count": 74, "field_count": 397, "B01_B04": "planned"},
            "goal_complete": False,
        },
        "inputs": {
            "component_reports": report_audits,
            "root_ledger_and_research": input_checks,
            "previous_preservation": {
                "path": preservation.get("inputs", {}).get("previous_war_records_preservation", {}).get("path"),
                "status": preservation.get("status"),
                "overall": preservation.get("overall"),
            },
        },
        "source_artifact_stdout_policy": {
            "source_and_executable": "每份当前报告只接受声明的path/size或bytes/SHA，随后重新流式哈希当前文件。",
            "stdout": "优先核对报告声明的外部stdout SHA；没有独立文件时保留报告内嵌stdout的UTF-8 SHA并标inline_report_captured，不把它伪装成独立OS收据。",
            "historical_revisions_excluded": [
                _relative(OWNED_STAGE / "owned-result-test-001" / "report.json"),
                _relative(ENTRY_STAGE / "abi-test-001" / "report-002.json"),
                _relative(ENTRY_STAGE / "unwind-test-001" / "report-002.json"),
            ],
            "historical_stdout_boundary": "旧失败或旧revision的stdout以各自报告内嵌全文及其报告SHA为准；共享外部log不被当作旧报告的当前pin，不回填、不改写，也不据此声称所有旧log未变。",
        },
        "historical_artifact_boundary": _history_artifact_boundary(),
        "errors": errors,
        "conclusion": {
            "current_reports_pinned": not errors,
            "previous_127_pins_preserved": preservation.get("status") == "passed_current_entry_preservation",
            "B01_B04": "planned",
            "goal_complete": False,
        },
        "output": {"path": _relative(output_path), "overwriting_existing": False},
    }


def _input_pin(path: Path, expected: dict[str, Any] | None = None, provenance: str = "input") -> dict[str, Any]:
    if expected is None:
        actual = _hash_file(path, max_bytes=MAX_JSON_BYTES)
        return {"path": _relative(path), "actual": actual, "provenance": provenance}
    return {
        "path": _relative(path),
        "expected": expected,
        "provenance": [provenance],
    }


def _collect_required_inputs(args: argparse.Namespace) -> dict[str, Path]:
    paths = {
        "owned_report": args.owned_report,
        "abi_report": args.abi_report,
        "unwind_report": args.unwind_report,
        "integration_report": args.integration_report,
        "entry_contract_ledger": args.ledger,
        "research_index": args.research_index,
        "research_source_audit": args.research_audit,
    }
    missing: list[str] = []
    resolved: dict[str, Path] = {}
    for name, value in paths.items():
        path = _workspace_path(value)
        resolved[name] = path
        if not path.is_file():
            missing.append(f"{name}:{_relative(path)}")
    if missing:
        raise MissingFinalInputs(missing)
    return resolved


def run_audit(args: argparse.Namespace, *, write: bool = True) -> tuple[dict[str, Any], dict[str, Any]]:
    paths = _collect_required_inputs(args)
    old_path = _workspace_path(args.old_preservation)
    if not old_path.is_file():
        raise MissingFinalInputs([f"old_preservation:{_relative(old_path)}"])
    component_output = _workspace_path(args.component_output)
    preservation_output = _workspace_path(args.preservation_output)
    if write and (component_output.exists() or preservation_output.exists()):
        raise EntryComponentAuditError("refusing to overwrite an existing new audit output")

    old_data, old_pin = _load_previous_preservation(old_path, args.old_preservation_sha256)
    pins, pin_errors = _previous_pins(old_data)
    preservation = _preservation_report(
        old_data,
        old_pin,
        pins,
        pin_errors,
        output_path=preservation_output,
    )

    report_audits = {
        "owned_result": _audit_report("owned_result", paths["owned_report"], "owned"),
        "entry_abi": _audit_report("entry_abi", paths["abi_report"], "abi"),
        "prefix_unwind": _audit_report("prefix_unwind", paths["unwind_report"], "unwind"),
        "integration": _audit_report("integration", paths["integration_report"], "integration"),
        "entry_contract_ledger": _audit_report("entry_contract_ledger", paths["entry_contract_ledger"], "generic"),
        "research_index": _audit_report("research_index", paths["research_index"], "generic"),
        "research_source_audit": _audit_report("research_source_audit", paths["research_source_audit"], "generic"),
    }
    input_rows: list[tuple[str, Any, str]] = []
    for name, path in paths.items():
        data, pin = _load_json(path)
        input_rows.append((name, {"path": _relative(path), "bytes": pin.get("bytes"), "sha256": pin.get("sha256")}, name))
        # The report audit already checks declared source pins; this pin binds the
        # report itself so a successful audit cannot silently use a later version.
        del data
    normalized, input_errors = _dedupe_pin_rows(input_rows)
    if input_errors:
        raise EntryComponentAuditError("required input pin errors: " + "; ".join(input_errors))
    component = _component_report(
        report_audits,
        preservation,
        {row["path"]: row for row in normalized},
        output_path=component_output,
    )
    if write:
        preservation_output.parent.mkdir(parents=True, exist_ok=True)
        component_output.parent.mkdir(parents=True, exist_ok=True)
        encoded_preservation = (json.dumps(preservation, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        encoded_component = (json.dumps(component, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        if len(encoded_preservation) > MAX_OUTPUT_BYTES or len(encoded_component) > MAX_OUTPUT_BYTES:
            raise EntryComponentAuditError(f"audit output exceeds {MAX_OUTPUT_BYTES} bytes")
        # Check once more immediately before creation; never overwrite old work.
        if component_output.exists() or preservation_output.exists():
            raise EntryComponentAuditError("refusing to overwrite an existing new audit output")
        preservation_output.write_bytes(encoded_preservation)
        try:
            component_output.write_bytes(encoded_component)
        except Exception:
            # Keep the first output as an explicit audit result, but never hide a
            # failed second write behind a success status.
            raise
    return component, preservation


def _default_args() -> argparse.Namespace:
    return argparse.Namespace(
        owned_report=DEFAULT_OWNED_REPORT,
        abi_report=DEFAULT_ABI_REPORT,
        unwind_report=DEFAULT_UNWIND_REPORT,
        integration_report=DEFAULT_INTEGRATION_REPORT,
        ledger=DEFAULT_LEDGER,
        research_index=DEFAULT_RESEARCH_INDEX,
        research_audit=DEFAULT_RESEARCH_AUDIT,
        old_preservation=DEFAULT_OLD_PRESERVATION,
        old_preservation_sha256=OLD_PRESERVATION_SHA256,
        component_output=DEFAULT_COMPONENT_OUTPUT,
        preservation_output=DEFAULT_PRESERVATION_OUTPUT,
    )


def main(argv: list[str] | None = None) -> int:
    defaults = _default_args()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owned-report", type=Path, default=defaults.owned_report)
    parser.add_argument("--abi-report", type=Path, default=defaults.abi_report)
    parser.add_argument("--unwind-report", type=Path, default=defaults.unwind_report)
    parser.add_argument("--integration-report", type=Path, default=defaults.integration_report)
    parser.add_argument("--ledger", type=Path, default=defaults.ledger)
    parser.add_argument("--research-index", type=Path, default=defaults.research_index)
    parser.add_argument("--research-audit", type=Path, default=defaults.research_audit)
    parser.add_argument("--old-preservation", type=Path, default=defaults.old_preservation)
    parser.add_argument("--old-preservation-sha256", default=defaults.old_preservation_sha256)
    parser.add_argument("--component-output", type=Path, default=defaults.component_output)
    parser.add_argument("--preservation-output", type=Path, default=defaults.preservation_output)
    parser.add_argument("--dry-run", action="store_true", help="核对并打印结果，不写两个新输出文件")
    args = parser.parse_args(argv)
    try:
        component, preservation = run_audit(args, write=not args.dry_run)
    except MissingFinalInputs as exc:
        print(json.dumps({"status": "blocked_missing_final_inputs", "missing": exc.missing}, ensure_ascii=False, sort_keys=True))
        return 3
    except (EntryComponentAuditError, OSError, ValueError) as exc:
        print(json.dumps({"status": "audit_error", "error": str(exc)}, ensure_ascii=False, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps({
        "status": component["status"],
        "component_output": _relative(_workspace_path(args.component_output)) if not args.dry_run else None,
        "preservation_output": _relative(_workspace_path(args.preservation_output)) if not args.dry_run else None,
        "preservation_status": preservation["status"],
        "preservation_overall": preservation["overall"],
        "component_errors": len(component["errors"]),
        "dry_run": args.dry_run,
    }, ensure_ascii=False, sort_keys=True))
    return 0 if component["status"] == "passed_current_entry_component_audit" else 1


if __name__ == "__main__":
    raise SystemExit(main())
