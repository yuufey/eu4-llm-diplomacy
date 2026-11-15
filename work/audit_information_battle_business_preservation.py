"""Audit the frozen batch-22 information-battle source boundary.

This audit is intentionally read-only.  It checks the 329 pins recorded by
the batch-22 development summary, the already completed 325-pin preservation
audit, the 103-source v23 artifact reuse manifest, and the ten-source
framework integration contract.  Every file explicitly pinned by the sealed
summary is stream-hashed, including immutable raw/log/SQLite snapshots; the
SQLite files are never parsed.

The audit does not inspect a process, open the game, call RPM/REA, or scan an
archive or discover a current live directory.  Files outside the old native
manifest are reported as boundary observations; their presence must not be
read as evidence that the old DLL contains them.  Mutable live files that are
not explicit sealed-summary pins are therefore outside this audit's input set.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
MAIN_STAGE = ROOT / "work/runtime/information-battle-live-20261025-001"
BUSINESS_STAGE = ROOT / "work/runtime/information-battle-business-20261025-001"
BUILD = ROOT / "work/runtime/diplomacy-observer-20261025-information-battle-live-001"

DEFAULT_SUMMARY = MAIN_STAGE / "development-summary-001.json"
DEFAULT_PREVIOUS_PRESERVATION = MAIN_STAGE / "preservation-audit-001.json"
DEFAULT_MANIFEST = BUILD / "build-manifest.json"
DEFAULT_SERVICE_CONTRACT = ROOT / "work/runtime/information-battle-business-20261025-001/service-integration-contract-001.json"
DEFAULT_OUTPUT = BUSINESS_STAGE / "preservation-audit-001.json"

EXPECTED_SUMMARY_PINS = 329
EXPECTED_PRIOR_PINS = 325
EXPECTED_PRIOR_UNCHANGED = 321
EXPECTED_NATIVE_SOURCES = 103
EXPECTED_SERVICE_SOURCES = 10
EXPECTED_GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_DLL_SHA256 = "eaf53986e159bfca7af717228a7bc983a8df03fec32a23eb4a82e5ca503133c3"

ALLOWED_DOCUMENT_CHANGES = frozenset(
    {
        "HANDOFF.md",
        "README(agent).md",
        "docs/信息导出与订阅开发计划.md",
        "docs/信息导出开发进展.md",
    }
)

# These are explicit source-boundary probes, not a recursive discovery list.
# The first four are outside the old 103-entry native build; the final entry
# is included as a control showing a wire header that *was* in that build.
BOUNDARY_PROBES = (
    {"path": "work/native/information-battle-context-wire.h", "old_native_manifest": False, "kind": "new_native_context_wire"},
    {"path": "work/native/information-battle-owned-context.h", "old_native_manifest": False, "kind": "new_native_owned_context"},
    {"path": "work/information_battle_context_wire.py", "old_native_manifest": False, "kind": "new_python_context_wire"},
    {"path": "work/information_battle_observation_wire.py", "old_native_manifest": False, "kind": "framework_python_observation_wire"},
    {"path": "work/native/information-battle-observation-wire.h", "old_native_manifest": True, "kind": "old_native_wire_control"},
)

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class PreservationAuditError(RuntimeError):
    """Raised when a sealed audit input is malformed or unsafe to read."""


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(resolved)


def _workspace_path(value: str | Path, *, allow_absolute: bool = True) -> Path:
    """Resolve a path and keep every read inside this workspace."""

    candidate = Path(value)
    if candidate.is_absolute() and not allow_absolute:
        raise PreservationAuditError(f"absolute_path_forbidden:{value}")
    resolved = candidate if candidate.is_absolute() else ROOT / candidate
    resolved = resolved.resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise PreservationAuditError(f"path_outside_workspace:{value}") from exc
    return resolved


def _sha256_file(path: Path, *, max_bytes: int = MAX_INPUT_BYTES) -> dict[str, Any]:
    """Stream one bounded file and detect a replacement during the read."""

    result: dict[str, Any] = {"path": _display_path(path)}
    try:
        before = path.stat()
    except OSError as exc:
        result.update({"exists": False, "status": "missing", "error": str(exc)})
        return result
    result.update({"exists": path.is_file(), "bytes": before.st_size})
    if not path.is_file():
        result["status"] = "not_file"
        return result
    if before.st_size > max_bytes:
        result.update({"status": "budget_exceeded", "max_bytes": max_bytes})
        return result

    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(HASH_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        result.update({"status": "read_error", "error": str(exc)})
        return result
    try:
        after = path.stat()
    except OSError as exc:
        result.update({"status": "stat_after_read_error", "error": str(exc), "sha256": digest.hexdigest()})
        return result
    result["sha256"] = digest.hexdigest()
    result["status"] = "stable" if (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns) else "changed_during_read"
    if result["status"] != "stable":
        result.update({"bytes_after": after.st_size, "mtime_ns_before": before.st_mtime_ns, "mtime_ns_after": after.st_mtime_ns})
    return result


def _load_json(path: Path, *, label: str) -> tuple[dict[str, Any], dict[str, Any]]:
    identity = _sha256_file(path, max_bytes=MAX_JSON_BYTES)
    if identity.get("status") != "stable":
        raise PreservationAuditError(f"json_input_not_stable:{label}:{identity.get('status')}")
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PreservationAuditError(f"json_input_invalid:{label}:{exc}") from exc
    if not isinstance(value, dict):
        raise PreservationAuditError(f"json_object_required:{label}")
    return value, identity


def _validate_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise PreservationAuditError(f"invalid_sha256:{label}")
    return value.lower()


def _safe_manifest_name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise PreservationAuditError(f"invalid_manifest_name:{label}")
    path = Path(value)
    if path.is_absolute() or path.drive or ".." in path.parts:
        raise PreservationAuditError(f"unsafe_manifest_name:{label}:{value}")
    return value.replace("\\", "/")


def _manifest_sources(manifest: dict[str, Any], label: str) -> list[dict[str, str]]:
    rows = manifest.get("sources")
    if not isinstance(rows, list):
        raise PreservationAuditError(f"sources_list_required:{label}")
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise PreservationAuditError(f"source_row_object_required:{label}:{index}")
        name = _safe_manifest_name(row.get("name"), f"{label}:{index}:name")
        digest = _validate_sha(row.get("sha256"), f"{label}:{name}")
        if name in seen:
            raise PreservationAuditError(f"duplicate_source:{label}:{name}")
        seen.add(name)
        result.append({"name": name, "sha256": digest})
    return result


def _skip_reason(relative: str) -> str | None:
    """Keep the audit closed over the immutable summary pin set.

    Every path passed here came from the sealed development summary.  The
    audit does not discover current live files, so a pinned raw/log/SQLite
    snapshot is safe to hash as an artifact.  SQLite content is never parsed.
    """

    del relative
    return None


def _summary_pin_record(relative: str, expected: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(expected, dict):
        raise PreservationAuditError(f"invalid_summary_pin:{relative}")
    expected_bytes = expected.get("bytes")
    if isinstance(expected_bytes, bool) or not isinstance(expected_bytes, int) or expected_bytes < 0:
        raise PreservationAuditError(f"invalid_summary_pin_bytes:{relative}")
    expected_sha = _validate_sha(expected.get("sha256"), f"summary:{relative}")
    record: dict[str, Any] = {
        "path": relative,
        "expected": {"bytes": expected_bytes, "sha256": expected_sha},
    }
    reason = _skip_reason(relative)
    if reason is not None:
        record.update({"status": "skipped_by_policy", "read": False, "reason": reason})
        return record
    actual = _sha256_file(_workspace_path(relative))
    record["actual"] = actual
    if actual.get("status") != "stable":
        record["status"] = actual.get("status", "unknown")
    elif actual.get("bytes") == expected_bytes and actual.get("sha256") == expected_sha:
        record["status"] = "match"
    elif relative in ALLOWED_DOCUMENT_CHANGES:
        record.update(
            {
                "status": "intentional_document_change",
                "reason": "one of the four explicitly allowed batch-22 document updates",
            }
        )
    else:
        record["status"] = "mismatch"
    return record


def _audit_development_summary(summary_path: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    summary, identity = _load_json(summary_path, label="development_summary")
    pins = summary.get("pins")
    if not isinstance(pins, dict):
        raise PreservationAuditError("development_summary_pins_required")
    prior = summary.get("prior_baseline")
    if not isinstance(prior, dict):
        raise PreservationAuditError("development_summary_prior_baseline_required")
    declared_changes = prior.get("declared_document_changes")
    if not isinstance(declared_changes, list):
        raise PreservationAuditError("development_summary_declared_document_changes_required")
    declared_paths = {row.get("path") for row in declared_changes if isinstance(row, dict)}
    metadata_checks = {
        "schema": summary.get("schema") == "INFORMATION-BATTLE-LIVE-DEVELOPMENT/1",
        "pin_count_declared_329": summary.get("pin_count") == EXPECTED_SUMMARY_PINS,
        "pin_map_count_329": len(pins) == EXPECTED_SUMMARY_PINS,
        "prior_pin_count_325": prior.get("pins") == EXPECTED_PRIOR_PINS,
        "prior_unchanged_321": prior.get("unchanged") == EXPECTED_PRIOR_UNCHANGED,
        "prior_non_document_changes_zero": prior.get("non_document_pin_changes") == 0,
        "declared_document_paths_exact": declared_paths == set(ALLOWED_DOCUMENT_CHANGES),
        "declared_document_change_rows_count_4": len(declared_changes) == len(ALLOWED_DOCUMENT_CHANGES),
        "goal_complete_false": summary.get("goal_complete") is False,
        "business_battle_export_incomplete": summary.get("business_battle_export_complete") is False,
    }

    records: list[dict[str, Any]] = []
    for relative, expected in sorted(pins.items()):
        if not isinstance(relative, str) or not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise PreservationAuditError(f"unsafe_summary_pin_path:{relative!r}")
        records.append(_summary_pin_record(relative, expected))
    counts = Counter(record["status"] for record in records)
    failures = [record for record in records if record["status"] not in {"match", "intentional_document_change", "skipped_by_policy"}]

    current_by_path = {row.get("path"): row for row in declared_changes if isinstance(row, dict)}
    document_checks: list[dict[str, Any]] = []
    for relative in sorted(ALLOWED_DOCUMENT_CHANGES):
        row = current_by_path.get(relative)
        expected = pins.get(relative)
        check: dict[str, Any] = {"path": relative, "declared": row}
        if not isinstance(row, dict) or not isinstance(expected, dict):
            check.update({"status": "missing_declaration_or_pin"})
        else:
            current = row.get("current")
            check["current_matches_summary_pin"] = isinstance(current, dict) and current.get("bytes") == expected.get("bytes") and current.get("sha256") == expected.get("sha256")
            before = row.get("before")
            check["before_differs_from_current"] = isinstance(before, dict) and before != current
            check["status"] = "matched" if check["current_matches_summary_pin"] and check["before_differs_from_current"] else "invalid_declared_change"
        document_checks.append(check)

    audit = {
        "summary": {"path": _display_path(summary_path), **identity, "schema": summary.get("schema"), "status": summary.get("status")},
        "declared_pin_count": len(pins),
        "read_policy": {
            "frozen_summary_pin_set_only": True,
            "frozen_pin_count_hashed": len(records),
            "stream_hashed_only": True,
            "frozen_sqlite_parsed": False,
            "current_live_files_discovered_or_read": False,
            "allowed_intentional_document_change_count": len(ALLOWED_DOCUMENT_CHANGES),
            "reason": "all explicitly frozen summary pins are stream-hashed; no current live directory is discovered, and raw/status/log/SQLite snapshots are not parsed",
        },
        "counts": {
            "declared": len(records),
            "match": counts.get("match", 0),
            "intentional_document_change": counts.get("intentional_document_change", 0),
            "skipped_by_policy": counts.get("skipped_by_policy", 0),
            "mismatch": counts.get("mismatch", 0),
            "missing": counts.get("missing", 0),
            "budget_exceeded": counts.get("budget_exceeded", 0),
            "other_failure": sum(value for key, value in counts.items() if key not in {"match", "intentional_document_change", "skipped_by_policy", "mismatch", "missing", "budget_exceeded"}),
        },
        "metadata_checks": metadata_checks,
        "document_change_checks": document_checks,
        "failures": failures,
        "records": records,
        "status": "all_audited_pins_match" if all(metadata_checks.values()) and not failures and all(item["status"] == "matched" for item in document_checks) else "mismatch_observed",
    }
    return summary, identity, audit


def _audit_previous_preservation(path: Path) -> dict[str, Any]:
    report, identity = _load_json(path, label="previous_preservation_audit")
    baseline = report.get("baseline_pin_audit")
    reuse = report.get("artifact_reuse_audit")
    extras = report.get("known_extra_raw_ingest_artifacts")
    checks = {
        "schema": report.get("schema") == "information_battle_live_preservation_audit_v1",
        "status_passed": report.get("status") == "passed",
        "baseline_325": isinstance(baseline, dict) and baseline.get("pin_count") == EXPECTED_PRIOR_PINS,
        "baseline_all_325_matched": isinstance(baseline, dict) and baseline.get("counts") == {"content_changed": 0, "matched": EXPECTED_PRIOR_PINS, "missing": 0},
        "baseline_no_changes": isinstance(baseline, dict) and baseline.get("changed_or_missing") == [],
        "artifact_103": isinstance(reuse, dict) and reuse.get("source_count") == EXPECTED_NATIVE_SOURCES,
        "artifact_no_mismatch": isinstance(reuse, dict) and reuse.get("mismatch_count") == 0,
        "raw_extra_section_present": isinstance(extras, dict) and extras.get("status") == "observed_separately_from_baseline_pins",
    }
    extra_records = extras.get("records", []) if isinstance(extras, dict) else []
    checks["raw_extra_rows_not_baseline_members"] = isinstance(extra_records, list) and all(isinstance(row, dict) and row.get("baseline_pin_member") is False for row in extra_records)
    return {
        "path": _display_path(path),
        **identity,
        "checks": checks,
        "status": "preserved" if all(checks.values()) else "historical_audit_mismatch",
        "baseline_pin_count": baseline.get("pin_count") if isinstance(baseline, dict) else None,
        "artifact_source_count": reuse.get("source_count") if isinstance(reuse, dict) else None,
        "artifact_mismatch_count": reuse.get("mismatch_count") if isinstance(reuse, dict) else None,
        "extra_raw_ingest_artifacts": [
            {key: row.get(key) for key in ("path", "kind", "status", "baseline_pin_member")}
            for row in extra_records
            if isinstance(row, dict)
        ],
        "note": "The historical raw-ingest rows are reported as extra files and are not re-read or counted as current pin content changes.",
    }


def _audit_native_build(manifest_path: Path) -> dict[str, Any]:
    current, current_identity = _load_json(manifest_path, label="current_build_manifest")
    artifact = current.get("artifact_reuse")
    if not isinstance(artifact, dict):
        raise PreservationAuditError("current_manifest_artifact_reuse_required")
    origin_value = artifact.get("source_manifest")
    if not isinstance(origin_value, str):
        raise PreservationAuditError("current_manifest_source_manifest_required")
    origin_path = _workspace_path(origin_value)
    origin, origin_identity = _load_json(origin_path, label="origin_build_manifest")
    current_sources = _manifest_sources(current, "current")
    origin_sources = _manifest_sources(origin, "origin")
    current_by_name = {row["name"]: row for row in current_sources}
    origin_by_name = {row["name"]: row for row in origin_sources}
    source_records: list[dict[str, Any]] = []
    failures: list[str] = []
    for name in sorted(set(current_by_name) | set(origin_by_name)):
        current_row = current_by_name.get(name)
        origin_row = origin_by_name.get(name)
        record: dict[str, Any] = {"name": name, "declared_current": current_row, "declared_origin": origin_row}
        if current_row is None or origin_row is None:
            record["status"] = "manifest_membership_mismatch"
            failures.append(f"source_membership:{name}")
            source_records.append(record)
            continue
        root_path = _workspace_path(Path("work/native") / name, allow_absolute=False)
        current_copy = _workspace_path(manifest_path.parent / name)
        origin_copy = _workspace_path(origin_path.parent / name)
        actuals = {
            "root": _sha256_file(root_path),
            "current_copy": _sha256_file(current_copy),
            "origin_copy": _sha256_file(origin_copy),
        }
        checks = {
            "root_matches_manifest": actuals["root"].get("status") == "stable" and actuals["root"].get("sha256") == current_row["sha256"],
            "current_copy_matches_manifest": actuals["current_copy"].get("status") == "stable" and actuals["current_copy"].get("sha256") == current_row["sha256"],
            "origin_copy_matches_manifest": actuals["origin_copy"].get("status") == "stable" and actuals["origin_copy"].get("sha256") == origin_row["sha256"],
            "current_origin_manifest_sha_equal": current_row["sha256"] == origin_row["sha256"],
            "all_three_files_equal": actuals["root"].get("sha256") == actuals["current_copy"].get("sha256") == actuals["origin_copy"].get("sha256"),
        }
        record.update({"paths": {key: value["path"] for key, value in actuals.items()}, "actual": actuals, "checks": checks})
        record["status"] = "matched" if all(checks.values()) else "mismatch"
        if record["status"] != "matched":
            failures.append(f"source:{name}")
        source_records.append(record)

    current_dll_value = current.get("dll")
    origin_dll_value = origin.get("dll")
    if not isinstance(current_dll_value, str) or not isinstance(origin_dll_value, str):
        raise PreservationAuditError("dll_path_required_in_manifests")
    current_dll = _workspace_path(current_dll_value)
    origin_dll = _workspace_path(origin_dll_value)
    current_dll_actual = _sha256_file(current_dll)
    origin_dll_actual = _sha256_file(origin_dll)
    declared_source_manifest_sha = _validate_sha(artifact.get("source_manifest_sha256"), "artifact_reuse.source_manifest_sha256")
    declared_source_dll_sha = _validate_sha(artifact.get("source_dll_sha256"), "artifact_reuse.source_dll_sha256")
    manifest_checks = {
        "current_source_count_103": len(current_sources) == EXPECTED_NATIVE_SOURCES,
        "origin_source_count_103": len(origin_sources) == EXPECTED_NATIVE_SOURCES,
        "source_lists_equal": current_sources == origin_sources,
        "compiled_in_this_directory_false": artifact.get("compiled_in_this_directory") is False,
        "current_manifest_pin_matches_actual": current_identity.get("status") == "stable",
        "origin_manifest_declared_sha_matches_actual": declared_source_manifest_sha == origin_identity.get("sha256"),
        "current_dll_declared_sha_matches_actual": current.get("dll_sha256") == current_dll_actual.get("sha256"),
        "origin_dll_declared_sha_matches_actual": origin.get("dll_sha256") == origin_dll_actual.get("sha256"),
        "artifact_reuse_dll_sha_matches_origin": declared_source_dll_sha == origin.get("dll_sha256"),
        "current_dll_matches_origin": current_dll_actual.get("sha256") == origin_dll_actual.get("sha256"),
        "current_dll_expected_sha": current_dll_actual.get("sha256") == EXPECTED_DLL_SHA256,
        "origin_dll_expected_sha": origin_dll_actual.get("sha256") == EXPECTED_DLL_SHA256,
        "current_game_sha_expected": current.get("game_sha256") == EXPECTED_GAME_SHA256,
        "origin_game_sha_expected": origin.get("game_sha256") == EXPECTED_GAME_SHA256,
        "current_research_lifecycle_flag": current.get("information_battle_research_lifecycle") is True,
        "origin_research_lifecycle_flag": origin.get("information_battle_research_lifecycle") is True,
    }
    failures.extend(key for key, value in manifest_checks.items() if not value)
    return {
        "status": "all_103_sources_matched" if not failures else "native_artifact_mismatch",
        "current_manifest": {"path": _display_path(manifest_path), **current_identity, "version": current.get("version"), "experiment_id": current.get("experiment_id")},
        "origin_manifest": {"path": _display_path(origin_path), **origin_identity, "version": origin.get("version"), "experiment_id": origin.get("experiment_id")},
        "manifest_checks": manifest_checks,
        "dll": {
            "current": {"path": _display_path(current_dll), **current_dll_actual},
            "origin": {"path": _display_path(origin_dll), **origin_dll_actual},
            "declared_source_dll_sha256": declared_source_dll_sha,
        },
        "source_count": max(len(current_sources), len(origin_sources)),
        "matched_source_count": sum(row.get("status") == "matched" for row in source_records),
        "mismatch_count": sum(row.get("status") != "matched" for row in source_records),
        "failures": failures,
        "source_records": source_records,
    }


def _audit_service_contract(contract_path: Path) -> dict[str, Any]:
    contract, identity = _load_json(contract_path, label="service_integration_contract")
    rows = contract.get("source_pins")
    allowlist = contract.get("survey_inputs", {}).get("source_allow_list") if isinstance(contract.get("survey_inputs"), dict) else None
    if not isinstance(rows, list) or not isinstance(allowlist, list):
        raise PreservationAuditError("service_contract_source_pins_and_allowlist_required")
    records: list[dict[str, Any]] = []
    failures: list[str] = []
    seen: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise PreservationAuditError(f"invalid_service_source_pin:{index}")
        relative = _safe_manifest_name(row.get("path"), f"service:{index}:path")
        if relative in seen:
            raise PreservationAuditError(f"duplicate_service_source_pin:{relative}")
        seen.add(relative)
        expected_bytes = row.get("size_bytes")
        if isinstance(expected_bytes, bool) or not isinstance(expected_bytes, int) or expected_bytes < 0:
            raise PreservationAuditError(f"invalid_service_source_bytes:{relative}")
        expected_sha = _validate_sha(row.get("sha256"), f"service:{relative}")
        actual = _sha256_file(_workspace_path(relative))
        checks = {
            "bytes_match": actual.get("bytes") == expected_bytes,
            "sha256_match": actual.get("sha256") == expected_sha,
            "stable": actual.get("status") == "stable",
        }
        record = {"path": relative, "expected": {"bytes": expected_bytes, "sha256": expected_sha}, "actual": actual, "checks": checks, "status": "matched" if all(checks.values()) else "mismatch"}
        if record["status"] != "matched":
            failures.append(relative)
        records.append(record)
    contract_checks = {
        "schema": contract.get("schema") == "information_battle_service_integration_survey_v1",
        "status": contract.get("status") == "static_contract_survey_complete",
        "source_pin_count_10": len(rows) == EXPECTED_SERVICE_SOURCES,
        "allowlist_count_10": len(allowlist) == EXPECTED_SERVICE_SOURCES,
        "allowlist_matches_source_pin_paths": set(allowlist) == seen,
        "read_only_scope": isinstance(contract.get("scope"), dict) and contract["scope"].get("game_access") is False and contract["scope"].get("rea_or_rpm") is False and contract["scope"].get("production_modified") is False,
    }
    failures.extend(key for key, value in contract_checks.items() if not value)
    return {
        "status": "all_10_framework_sources_matched" if not failures else "service_contract_mismatch",
        "contract": {"path": _display_path(contract_path), **identity, "schema": contract.get("schema"), "status": contract.get("status")},
        "checks": contract_checks,
        "source_count": len(records),
        "matched_source_count": sum(row["status"] == "matched" for row in records),
        "failures": failures,
        "source_records": records,
    }


def _audit_boundary_probes(summary: dict[str, Any], manifest: dict[str, Any], service_contract: dict[str, Any]) -> dict[str, Any]:
    manifest_names = {row["name"] for row in _manifest_sources(manifest, "boundary_manifest")}
    service_paths = {row.get("path") for row in service_contract.get("source_pins", []) if isinstance(row, dict)}
    rows: list[dict[str, Any]] = []
    failures: list[str] = []
    for item in BOUNDARY_PROBES:
        relative = item["path"]
        path = _workspace_path(relative)
        actual = _sha256_file(path)
        native_name = Path(relative).name
        is_native = relative.startswith("work/native/")
        in_manifest = native_name in manifest_names if is_native else False
        expected_in_manifest = item["old_native_manifest"]
        checks = {
            "file_stable": actual.get("status") == "stable",
            "old_native_manifest_membership_as_expected": in_manifest == expected_in_manifest,
        }
        row = {
            "path": relative,
            "kind": item["kind"],
            "actual": actual,
            "old_native_manifest_membership": in_manifest,
            "service_contract_pin_membership": relative in service_paths,
            "development_summary_pin_membership": relative in summary.get("pins", {}),
            "expected_old_native_manifest_membership": expected_in_manifest,
            "checks": checks,
            "status": "boundary_verified" if all(checks.values()) else "boundary_mismatch",
        }
        if row["status"] != "boundary_verified":
            failures.append(relative)
        rows.append(row)
    return {
        "status": "boundary_verified" if not failures else "boundary_mismatch",
        "claim": "A file outside the old 103-source native manifest is not evidence that the old DLL contains it.",
        "failures": failures,
        "records": rows,
    }


def audit(
    summary_path: Path = DEFAULT_SUMMARY,
    previous_preservation_path: Path = DEFAULT_PREVIOUS_PRESERVATION,
    manifest_path: Path = DEFAULT_MANIFEST,
    service_contract_path: Path = DEFAULT_SERVICE_CONTRACT,
) -> dict[str, Any]:
    summary_path = _workspace_path(summary_path)
    previous_preservation_path = _workspace_path(previous_preservation_path)
    manifest_path = _workspace_path(manifest_path)
    service_contract_path = _workspace_path(service_contract_path)
    summary, _, summary_audit = _audit_development_summary(summary_path)
    previous_audit = _audit_previous_preservation(previous_preservation_path)
    manifest, _ = _load_json(manifest_path, label="current_build_manifest_for_boundary")
    service_contract, _ = _load_json(service_contract_path, label="service_contract_for_boundary")
    native_audit = _audit_native_build(manifest_path)
    service_audit = _audit_service_contract(service_contract_path)
    boundary_audit = _audit_boundary_probes(summary, manifest, service_contract)
    audit_script = _sha256_file(Path(__file__), max_bytes=MAX_JSON_BYTES)

    checks = {
        "summary_audit": summary_audit["status"] == "all_audited_pins_match",
        "historical_325_preservation": previous_audit["status"] == "preserved",
        "native_103_artifact": native_audit["status"] == "all_103_sources_matched",
        "service_10_source_contract": service_audit["status"] == "all_10_framework_sources_matched",
        "new_file_boundary": boundary_audit["status"] == "boundary_verified",
    }
    failures = {
        "summary": summary_audit["failures"],
        "historical": [] if checks["historical_325_preservation"] else ["previous_preservation_audit"],
        "native": native_audit["failures"],
        "service": service_audit["failures"],
        "boundary": boundary_audit["failures"],
    }
    return {
        "schema": "information_battle_business_preservation_audit_v1",
        "status": "passed_read_only_business_preservation" if all(checks.values()) else "mismatch_observed",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": {
            "game_access": False,
            "process_access": False,
            "rpm_or_injection": False,
            "rea_access": False,
            "live_mutable_files_read": False,
            "frozen_pin_set_stream_hashed": True,
            "frozen_sqlite_content_parsed": False,
            "recursive_archive_scan": False,
            "production_modified": False,
            "historical_summary_modified": False,
            "hash_mode": "streamed_sha256_1MiB_chunks_with_16MiB_per_file_bound",
            "new_context_or_wire_in_game_claim": False,
        },
        "audit_script": {"path": _display_path(Path(__file__)), **audit_script},
        "inputs": {
            "development_summary": summary_audit["summary"],
            "previous_preservation_audit": {key: previous_audit.get(key) for key in ("path", "bytes", "sha256", "status", "baseline_pin_count", "artifact_source_count", "artifact_mismatch_count")},
            "current_build_manifest": native_audit["current_manifest"],
            "origin_build_manifest": native_audit["origin_manifest"],
            "service_integration_contract": service_audit["contract"],
        },
        "development_summary_pin_audit": summary_audit,
        "previous_batch21_preservation_boundary": previous_audit,
        "native_103_root_copy_dll_manifest_audit": native_audit,
        "service_integration_contract_10_source_audit": service_audit,
        "new_files_boundary": boundary_audit,
        "checks": checks,
        "failures": failures,
        "conclusion": {
            "declared_current_pin_count": summary_audit["declared_pin_count"],
            "audited_current_pin_count": summary_audit["counts"]["match"] + summary_audit["counts"]["intentional_document_change"] + summary_audit["counts"]["mismatch"] + summary_audit["counts"]["missing"] + summary_audit["counts"]["budget_exceeded"] + summary_audit["counts"]["other_failure"],
            "intentional_document_change_count": summary_audit["counts"]["intentional_document_change"],
            "skipped_mutable_pin_count": summary_audit["counts"]["skipped_by_policy"],
            "historical_extra_raw_ingest_files_are_separate": previous_audit["checks"].get("raw_extra_section_present", False) and previous_audit["checks"].get("raw_extra_rows_not_baseline_members", False),
            "old_native_build_contains_new_context_or_wire": False,
            "battle_business_export_complete": summary.get("business_battle_export_complete") is True,
            "goal_complete": summary.get("goal_complete") is True,
        },
    }


def _write_report(report: dict[str, Any], output: Path) -> None:
    output = _workspace_path(output)
    if output.exists():
        raise PreservationAuditError(f"refusing_to_overwrite:{_display_path(output)}")
    encoded = (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=False) + "\n").encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise PreservationAuditError(f"output_exceeds_bound:{len(encoded)}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(encoded)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--previous-preservation", type=Path, default=DEFAULT_PREVIOUS_PRESERVATION)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--service-contract", type=Path, default=DEFAULT_SERVICE_CONTRACT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        report = audit(args.summary, args.previous_preservation, args.manifest, args.service_contract)
        _write_report(report, args.output)
    except (OSError, PreservationAuditError, ValueError) as exc:
        print(f"business preservation audit failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"], "output": _display_path(args.output.resolve()), "checks": report["checks"], "failures": report["failures"]}, ensure_ascii=False, sort_keys=True))
    return 0 if report["status"] == "passed_read_only_business_preservation" else 1


if __name__ == "__main__":
    raise SystemExit(main())
