"""Create a scoped, metadata-only archive manifest for batch 72 gate tracing.

This helper copies four current documents into an exclusive mirror, then
stream-hashes the files already in the batch stage. The 446 source snapshots
are listed by reference to the prior passed freeze/postverify pins; they are
not copied again or rehashed. No game, service, RPM, MCP, native observer, or
build action is performed.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import xml.etree.ElementTree as ET
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-battle-gate-trace-20261028-001"
SNAPSHOT_ROOT = STAGE / "document-snapshots"
MANIFEST_PATH = STAGE / "artifact-manifest-001.json"
VERIFICATION_PATH = STAGE / "archive-verification-001.json"
FREEZE_PATH = STAGE / "source-freeze-001.json"
POSTVERIFY_PATH = STAGE / "source-post-run-verification-001.json"
FULL_PATH = STAGE / "regression-full-001.xml"
COMPARISON_PATH = STAGE / "regression-comparison-001.json"
SUMMARY_PATH = STAGE / "development-summary-001.json"
INDEPENDENT_AUDIT_PATH = STAGE / "independent-live-audit-001.json"
SNAPSHOT_RECEIPT_PATH = STAGE / "snapshot-receipt-001.json"
CHUNK_BYTES = 1024 * 1024
EXPECTED_STAGE_SOURCE_COUNT = 446
EXPECTED_BASELINE_SOURCE_COUNT = 312

DOCUMENTS = (
    ("HANDOFF.md", "HANDOFF.md"),
    ("README(agent).md", "README(agent).md"),
    ("docs/信息导出与订阅开发计划.md", "docs/信息导出与订阅开发计划.md"),
    ("docs/玩家国家与LLM观察方的战报路径.md", "docs/玩家国家与LLM观察方的战报路径.md"),
)
BASELINE_PATHS = (
    "work/runtime/information-battle-recipient-20261028-001/source-freeze-001.json",
    "work/runtime/information-battle-recipient-20261028-001/regression-full-001.xml",
    "work/runtime/information-battle-recipient-20261028-001/regression-comparison-001.json",
    "work/runtime/information-battle-recipient-20261028-001/source-post-run-verification-001.json",
)
BUILD_DIRS = (
    "work/runtime/diplomacy-observer-20261028-battle-gate-v32-001",
    "work/runtime/diplomacy-observer-20261028-battle-gate-v32-002",
)
OWNED_INPUTS_ROOT = ROOT / (
    "work/runtime/information-battle-recipient-20261028-001/owned-inputs-001"
)
CURRENT_INSTALL = ROOT / "work/runtime/diplomacy-observer-20261028-battle-gate-v32-002"
LIVE = STAGE / "live-001"


class ArchiveError(RuntimeError):
    """Raised when an archive input is missing or violates the batch contract."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ArchiveError(reason)


def workspace_path(raw: str | Path, *, strict: bool = True) -> Path:
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    resolved = candidate.resolve(strict=strict)
    try:
        resolved.relative_to(ROOT)
    except ValueError as exc:
        raise ArchiveError(f"path_outside_workspace:{raw}") from exc
    return resolved


def relative(path: Path) -> str:
    return path.resolve(strict=False).relative_to(ROOT).as_posix()


def regular_file_stat(path: Path) -> os.stat_result:
    result = path.lstat()
    require(stat.S_ISREG(result.st_mode), f"not_regular_file:{relative(path)}")
    return result


def file_pin(path: Path) -> dict[str, Any]:
    path = workspace_path(path)
    before = regular_file_stat(path)
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while block := stream.read(CHUNK_BYTES):
            digest.update(block)
            size += len(block)
    after = regular_file_stat(path)
    require(
        (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        == (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
        f"file_changed_during_hash:{relative(path)}",
    )
    require(size == before.st_size, f"hash_size_mismatch:{relative(path)}")
    return {"path": relative(path), "bytes": size, "sha256": digest.hexdigest()}


def read_json(path: Path) -> Any:
    path = workspace_path(path)
    require(path.stat().st_size <= 32 * 1024 * 1024, f"json_over_bound:{relative(path)}")
    try:
        with path.open("r", encoding="utf-8-sig") as stream:
            return json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ArchiveError(f"invalid_json:{relative(path)}:{type(exc).__name__}") from exc


def write_exclusive(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except FileExistsError as exc:
        raise ArchiveError(f"output_exists_preserve:{relative(path)}") from exc


def copy_document(source_raw: str, destination_relative: str) -> dict[str, Any]:
    source = workspace_path(source_raw)
    destination = SNAPSHOT_ROOT / Path(destination_relative)
    before = regular_file_stat(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    copied = 0
    try:
        with source.open("rb") as src, destination.open("xb") as dst:
            while block := src.read(CHUNK_BYTES):
                dst.write(block)
                digest.update(block)
                copied += len(block)
    except FileExistsError as exc:
        raise ArchiveError(f"document_snapshot_exists:{relative(destination)}") from exc
    after = regular_file_stat(source)
    snapshot_pin = file_pin(destination)
    source_unchanged = (before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_size, after.st_mtime_ns, after.st_ctime_ns
    )
    source_sha = digest.hexdigest()
    require(source_unchanged, f"document_changed_during_copy:{source_raw}")
    require(copied == before.st_size, f"document_copy_size_mismatch:{source_raw}")
    require(snapshot_pin["bytes"] == copied and snapshot_pin["sha256"] == source_sha,
            f"document_snapshot_pin_mismatch:{source_raw}")
    return {
        "source": {"path": relative(source), "bytes": copied, "sha256": source_sha},
        "source_metadata_stable": True,
        "snapshot": snapshot_pin,
        "copy_chunk_bytes": CHUNK_BYTES,
        "exclusive_output": True,
    }


def list_regular_files(root: Path) -> list[Path]:
    root = workspace_path(root)
    files: list[Path] = []
    for current, dirs, names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        dirs.sort()
        names.sort()
        for name in list(dirs):
            directory = current_path / name
            if directory.is_symlink():
                raise ArchiveError(f"symlink_directory_not_archived:{relative(directory)}")
        for name in names:
            path = current_path / name
            st = path.lstat()
            if stat.S_ISREG(st.st_mode):
                files.append(path)
            elif stat.S_ISLNK(st.st_mode):
                raise ArchiveError(f"symlink_file_not_archived:{relative(path)}")
    return sorted(files, key=relative)


def frozen_snapshot_references(freeze: dict[str, Any]) -> dict[str, dict[str, Any]]:
    records = freeze.get("files")
    require(isinstance(records, list) and len(records) == EXPECTED_STAGE_SOURCE_COUNT,
            "source_freeze_446_records_required")
    refs: dict[str, dict[str, Any]] = {}
    for record in records:
        require(isinstance(record, dict) and isinstance(record.get("snapshot"), dict),
                "freeze_snapshot_record_invalid")
        snapshot = record["snapshot"]
        path = workspace_path(snapshot.get("path", ""))
        name = relative(path)
        require(name.startswith(relative(STAGE / "source-snapshots-001") + "/"),
                f"freeze_snapshot_outside_source_snapshot_tree:{name}")
        require(name not in refs, f"duplicate_freeze_snapshot:{name}")
        refs[name] = {
            "bytes": snapshot.get("bytes"),
            "sha256": snapshot.get("sha256"),
            "original_source": record.get("source", {}).get("path"),
        }
    return refs


def stage_file_manifest(freeze: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    freeze_refs = frozen_snapshot_references(freeze)
    files = list_regular_files(STAGE)
    names = [relative(path) for path in files]
    excluded = {
        relative(MANIFEST_PATH),
        relative(VERIFICATION_PATH),
    }
    names = [name for name in names if name not in excluded]
    snapshot_root_rel = relative(STAGE / "source-snapshots-001") + "/"
    actual_snapshot_names = {name for name in names if name.startswith(snapshot_root_rel)}
    require(actual_snapshot_names == set(freeze_refs), "source_snapshot_tree_differs_from_freeze_manifest")

    entries: list[dict[str, Any]] = []
    reference_count = 0
    hashed_count = 0
    for path in files:
        name = relative(path)
        if name in excluded:
            continue
        if name.startswith(snapshot_root_rel):
            ref = freeze_refs[name]
            observed_size = regular_file_stat(path).st_size
            require(observed_size == ref["bytes"], f"source_snapshot_size_mismatch:{name}")
            entries.append({
                "path": name,
                "bytes": ref["bytes"],
                "sha256": ref["sha256"],
                "hash_method": "referenced_existing_source_freeze_snapshot_pin",
                "content_rehashed_for_archive": False,
                "source_freeze_source": ref["original_source"],
            })
            reference_count += 1
        else:
            pin = file_pin(path)
            entries.append({**pin, "hash_method": "stream_sha256", "content_rehashed_for_archive": True})
            hashed_count += 1
    require(len(entries) == len(names), "stage_manifest_entry_count_mismatch")
    return entries, {
        "regular_files_listed": len(entries),
        "content_stream_hashed_files": hashed_count,
        "existing_freeze_snapshot_references": reference_count,
        "excluded_self_referential_outputs": len(excluded),
    }


def sqlite_fetchall(connection: sqlite3.Connection, sql: str) -> list[tuple[Any, ...]]:
    cursor = connection.cursor()
    try:
        cursor.execute(sql)
        return cursor.fetchall()
    finally:
        cursor.close()


def sqlite_row_counts(connection: sqlite3.Connection) -> dict[str, int]:
    tables = [row[0] for row in sqlite_fetchall(
        connection, "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )]
    result: dict[str, int] = {}
    for table in tables:
        quoted = '"' + table.replace('"', '""') + '"'
        result[table] = int(sqlite_fetchall(connection, f"SELECT COUNT(*) FROM {quoted}")[0][0])
    return result


def sqlite_readonly_snapshot(path: Path) -> dict[str, Any]:
    uri = path.resolve().as_uri() + "?mode=ro&immutable=1"
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=30)
        cursor = connection.execute("PRAGMA query_only=ON")
        cursor.close()
        integrity = [str(row[0]) for row in sqlite_fetchall(connection, "PRAGMA integrity_check")]
        counts = sqlite_row_counts(connection)
        return {
            "path": relative(path),
            "open_mode": "mode=ro; immutable=1; query_only=ON",
            "integrity_check": integrity,
            "integrity_passed": integrity == ["ok"],
            "table_row_counts": counts,
            "total_rows": sum(counts.values()),
        }
    finally:
        if connection is not None:
            connection.close()


def build_review_pins() -> list[dict[str, Any]]:
    pins: list[dict[str, Any]] = []
    for revision in ("001", "002"):
        review_path = STAGE / f"build-review-{revision}.json"
        review = read_json(review_path)
        require(review.get("version") == 32 and review.get("native_sources") == 122,
                f"build_review_contract_mismatch:{revision}")
        require(review.get("gate_trace_macro") is True
                and review.get("country_control_macro") is False
                and review.get("wire_version") == 6,
                f"build_review_traits_mismatch:{revision}")
        artifacts = []
        for key, expected_name in (
            ("manifest", "build-manifest.json"),
            ("dll", "eu4_bridge_diplomacy_observer_v32.dll"),
        ):
            expected = review.get(key)
            require(isinstance(expected, dict), f"build_review_pin_missing:{revision}:{key}")
            path = workspace_path(expected.get("path", ""))
            require(path.name == expected_name, f"build_artifact_name_mismatch:{revision}:{key}")
            pin = file_pin(path)
            require(pin["bytes"] == expected.get("bytes")
                    and pin["sha256"] == expected.get("sha256"),
                    f"build_review_hash_mismatch:{revision}:{key}")
            artifacts.append({**pin, "role": key})
        manifest = read_json(workspace_path(review["manifest"]["path"]))
        require(manifest.get("version") == 32 and manifest.get("compiled") is True
                and manifest.get("runtime_verified") is False
                and manifest.get("native_source_count", 122) in (122, None),
                f"build_manifest_identity_invalid:{revision}")
        require(len(manifest.get("sources", [])) == 122,
                f"build_manifest_source_count_invalid:{revision}")
        pins.append({"revision": revision, "status": review.get("status"), "artifacts": artifacts})
    return pins


def baseline_pins() -> list[dict[str, Any]]:
    paths = [workspace_path(path) for path in BASELINE_PATHS]
    pins = [file_pin(path) for path in paths]
    freeze = read_json(paths[0])
    comparison = read_json(paths[2])
    postverify = read_json(paths[3])
    require(freeze.get("status") == "passed" and freeze.get("batch") == 71
            and freeze.get("count") == EXPECTED_BASELINE_SOURCE_COUNT
            and len(freeze.get("files", [])) == EXPECTED_BASELINE_SOURCE_COUNT,
            "batch71_freeze_contract_mismatch")
    require(comparison.get("no_new_bad") is True
            and comparison.get("new_failure_nodes") == []
            and comparison.get("new_test_failures") == [],
            "batch71_comparison_not_no_new_bad")
    require(postverify.get("status") == "passed"
            and postverify.get("source_count") == EXPECTED_BASELINE_SOURCE_COUNT
            and postverify.get("current_sources_match_snapshots") is True,
            "batch71_postverify_contract_mismatch")
    return [{**pin, "role": role} for pin, role in zip(
        pins, ("freeze", "full", "comparison", "post_run_verification")
    )]


def owned_inputs_pins() -> dict[str, Any]:
    files = list_regular_files(OWNED_INPUTS_ROOT)
    entries = [file_pin(path) for path in files]
    return {
        "root": relative(OWNED_INPUTS_ROOT),
        "file_count": len(entries),
        "total_bytes": sum(pin["bytes"] for pin in entries),
        "hash_method": "stream_sha256",
        "files": entries,
    }


def audit_and_live_checks(snapshot_receipt: dict[str, Any]) -> dict[str, Any]:
    summary = read_json(SUMMARY_PATH)
    audit = read_json(INDEPENDENT_AUDIT_PATH)
    acceptance = read_json(LIVE / "acceptance/report.json")
    natural = read_json(LIVE / "natural-window/report.json")
    world = read_json(STAGE / "final-world-001.json")
    status = read_json(STAGE / "final-snapshots/information-battle-status.json")
    journal = read_json(STAGE / "final-snapshots/information-battle-capture-journal.json")
    installation = read_json(STAGE / "final-snapshots/installation.json")

    require(summary.get("regression", {}).get("frozen_selected_sources") == 446,
            "summary_frozen_source_count_mismatch")
    require(summary.get("regression", {}).get("passed") == 3252
            and summary.get("regression", {}).get("failed") == 106
            and summary.get("regression", {}).get("errors") == 35
            and summary.get("regression", {}).get("no_new_bad_against_batch71") is True,
            "summary_regression_counts_mismatch")
    require(summary.get("live_findings", {}).get("FRA_direct_participant_events") == 0,
            "summary_FRA_participant_count_not_zero")

    require(audit.get("audit_status") == "passed", "independent_live_audit_not_passed")
    database_audit = audit.get("database_audit", {})
    require(database_audit.get("counts", {}).get("complete_messages") == 11
            and database_audit.get("counts", {}).get("battle_records") == 11
            and database_audit.get("raw_trace_rows") == 11
            and database_audit.get("raw_trace_matches_join_rows_exactly") is True,
            "independent_audit_11_record_counts_mismatch")
    participant = audit.get("participant_review", {})
    records = participant.get("records", [])
    require(len(records) == 11
            and participant.get("FRA_absent_from_both_sides_for_all_11") is True,
            "independent_audit_participant_contract_mismatch")
    route = audit.get("bounded_native_path_finding", {})
    route_checks = (
        "all_11_scope_completed_unambiguous_no_overflow_no_drops",
        "all_11_scope_guards_before_and_after_true",
        "all_11_context_cleanup_exit_samples_complete_and_consistent",
        "all_11_mode_zero_selected_and_default_ref_equal_physical_POR",
        "all_11_ui_slot_absent_and_override_known_false",
        "all_11_cleanup_entries_one_reject_mask_zero",
        "all_11_passed_marker_and_message_entry_counts_zero",
    )
    require(all(route.get(key) is True for key in route_checks),
            "independent_audit_client_route_negative_conditions_missing")
    for record in records:
        checks = record.get("trace_checks", {})
        require(record.get("FRA_observer_full_ref_absent_from_both_sides") is True
                and checks.get("scope_guards_before") is True
                and checks.get("scope_guards_after") is True
                and checks.get("observation_drops") == 0
                and checks.get("passed_marker_accepted") == 0
                and checks.get("message_entries") == 0
                and checks.get("line1_entries") == 0
                and checks.get("cleanup_entries") == 1
                and checks.get("cleanup_reject_mask") == 0,
                f"independent_audit_record_not_negative:{record.get('sequence')}")

    boundary = audit.get("acceptance_boundary", {})
    require(boundary.get("FRA_positive_battle_event_count") == 0
            and boundary.get("live_acceptance_status") == "failed"
            and boundary.get("failure_reason") == "natural_fra_event_absent_no_vacuous_pass",
            "FRA_failed_acceptance_boundary_mismatch")
    events = boundary.get("service_db_internal_events", {})
    require(events.get("rows") == 4
            and events.get("rows_are_diplomatic_proposals_not_battles") is True,
            "four_service_events_must_remain_diplomatic_proposals")
    require(acceptance.get("status") == "failed"
            and acceptance.get("error", {}).get("message") == "natural_fra_event_absent_no_vacuous_pass"
            and acceptance.get("server_exit_code") == 0,
            "acceptance_report_failure_or_server_state_mismatch")
    require(natural.get("status") == "observed_target_and_paused"
            and natural.get("start_raw") == 56562768
            and natural.get("target_raw") == 56563608
            and natural.get("captured") == "11"
            and natural.get("business_dispatch") is False
            and natural.get("save_requested") is False,
            "natural_window_record_mismatch")

    passes = world.get("passes", [])
    require(world.get("pid") == 37288 and world.get("session_id") == "37288-1dd66cf8a8a383c"
            and world.get("same_passes") is True and len(passes) == 2,
            "final_world_identity_or_duplicate_read_mismatch")
    for item in passes:
        require(item.get("current_tag") == "POR"
                and item.get("current_player_ref") == "010000bd00524f50"
                and item.get("date_raw") == 56563608
                and item.get("speed") == 0 and item.get("paused") is True
                and item.get("human_count_raw") == 1
                and item.get("controller_types_raw", {}).get("slots", {}).get("POR:189") == 1
                and item.get("controller_types_raw", {}).get("slots", {}).get("FRA:122") == 0,
                "final_world_state_mismatch")
    require(installation.get("pid") == 37288
            and installation.get("session_id") == "37288-1dd66cf8a8a383c"
            and installation.get("creation_filetime") == 134376605459560508,
            "installation_identity_mismatch")
    require(status.get("state") == "disabled" and status.get("captured") == "11"
            and status.get("gate_trace_records") == "11"
            and status.get("gate_trace_failures") == "0",
            "final_source_status_not_disabled_with_11_records")
    require(journal.get("state") == "completed-disabled" and journal.get("owned") is False
            and journal.get("identity", {}).get("pid") == 37288,
            "capture_journal_not_completed_disabled_unowned")
    final_capture = boundary.get("final_capture_state", {})
    require(final_capture.get("producer_state") == "disabled"
            and final_capture.get("consumer_count") == 0
            and final_capture.get("active_subscriptions") == []
            and final_capture.get("server_exit_code") == 0,
            "final_capture_state_not_disabled_unowned_server0")

    require(snapshot_receipt.get("status") == "passed"
            and snapshot_receipt.get("snapshot_counts") == {"files": 7, "databases": 3},
            "final_snapshot_receipt_not_passed")
    dbs = snapshot_receipt.get("database_snapshots", [])
    require(len(dbs) == 3, "final_database_snapshot_count_mismatch")
    db_records: list[dict[str, Any]] = []
    for db_record in dbs:
        db_path = workspace_path(db_record.get("snapshot", {}).get("path", ""))
        live_db = sqlite_readonly_snapshot(db_path)
        require(live_db["integrity_passed"] and live_db["table_row_counts"]
                == db_record.get("snapshot_table_row_counts")
                and live_db["total_rows"] == db_record.get("snapshot_total_rows"),
                f"final_database_snapshot_metadata_mismatch:{relative(db_path)}")
        db_records.append({
            "path": relative(db_path),
            "integrity_check": live_db["integrity_check"],
            "integrity_passed": live_db["integrity_passed"],
            "table_row_counts": live_db["table_row_counts"],
            "total_rows": live_db["total_rows"],
            "snapshot_receipt_pin": db_record.get("snapshot"),
        })

    return {
        "regression": {
            "passed": 3252, "failed": 106, "errors": 35, "subtests_passed": 1959,
            "no_new_bad_against_batch71": True,
            "source_count_frozen_and_postverified": 446,
        },
        "live_negative_result": {
            "client_route_records": 11,
            "land": 10, "naval": 1,
            "FRA_direct_participant_events": 0,
            "all_11_gate_to_message_entry_observations_negative": True,
            "scope_guards_before_and_after_true": True,
            "cleanup_entries_per_record": 1,
            "service_database_events": 4,
            "service_events_are": "diplomatic proposals, not battles",
            "FRA_acceptance_status": "failed",
            "FRA_acceptance_reason": "natural_fra_event_absent_no_vacuous_pass",
        },
        "current_world": {
            "pid": 37288, "session_id": "37288-1dd66cf8a8a383c",
            "physical_player": "POR", "physical_player_full_ref": "010000bd00524f50",
            "human_count": 1, "POR_controller": 1, "FRA_controller": 0,
            "date_raw": 56563608, "paused": True, "speed": 0,
            "capture_state": "disabled", "capture_owner": "unowned",
            "active_subscriptions": [], "server_exit_code": 0,
        },
        "final_database_integrity_and_rows": db_records,
        "b04_complete": False,
        "development_plan_complete": False,
    }


def verify_full_and_postverify(freeze_pin: dict[str, Any], baseline_pins: list[dict[str, Any]]) -> dict[str, Any]:
    freeze = read_json(FREEZE_PATH)
    post = read_json(POSTVERIFY_PATH)
    comparison = read_json(COMPARISON_PATH)
    summary = read_json(SUMMARY_PATH)
    require(freeze.get("status") == "passed" and freeze.get("batch") == 72
            and freeze.get("count") == EXPECTED_STAGE_SOURCE_COUNT
            and len(freeze.get("files", [])) == EXPECTED_STAGE_SOURCE_COUNT,
            "batch72_freeze_contract_mismatch")
    require(post.get("status") == "passed" and post.get("source_count") == EXPECTED_STAGE_SOURCE_COUNT
            and post.get("source_freeze", {}).get("sha256") == freeze_pin["sha256"]
            and post.get("current_sources_match_snapshots") is True,
            "batch72_postverify_contract_mismatch")
    full_pin = file_pin(FULL_PATH)
    comp_full = comparison.get("current_xml", {})
    require(comp_full.get("path") == relative(FULL_PATH)
            and comp_full.get("bytes") == full_pin["bytes"]
            and comp_full.get("sha256") == full_pin["sha256"],
            "batch72_full_comparison_pin_mismatch")
    require(comparison.get("no_new_bad") is True
            and comparison.get("new_failure_nodes") == []
            and comparison.get("new_test_failures") == [],
            "batch72_no_new_bad_failed")
    root = ET.parse(FULL_PATH).getroot()
    suite = root if root.tag == "testsuite" else root.find("testsuite")
    require(suite is not None, "regression_full_testsuite_missing")
    tests = int(suite.attrib["tests"])
    failures = int(suite.attrib["failures"])
    errors = int(suite.attrib["errors"])
    line = comparison.get("summary_line", "")
    require(tests == 5352 and failures == 106 and errors == 35
            and "3252 passed" in line and "106 failed" in line
            and "35 errors" in line and "1959 subtests passed" in line,
            "batch72_regression_summary_mismatch")
    require(summary.get("regression", {}).get("passed") == 3252
            and summary.get("regression", {}).get("failed") == 106
            and summary.get("regression", {}).get("errors") == 35
            and summary.get("regression", {}).get("subtests_passed") == 1959,
            "batch72_summary_and_xml_mismatch")
    require(post.get("source_count") == 446
            and post.get("baseline71_no_new_bad") is True,
            "batch72_postverify_446_or_baseline_mismatch")
    return {
        "full_xml": full_pin,
        "full_suite_tests_attribute": tests,
        "summary_line": line,
        "passed": 3252, "failed": failures, "errors": errors, "subtests_passed": 1959,
        "no_new_bad": comparison["no_new_bad"],
        "source_count": post["source_count"],
        "source_postverify": file_pin(POSTVERIFY_PATH),
        "baseline_pins": baseline_pins,
    }


def create_archive() -> tuple[dict[str, Any], dict[str, Any]]:
    require(STAGE.is_dir(), "batch72_stage_missing")
    for output in (SNAPSHOT_ROOT, MANIFEST_PATH, VERIFICATION_PATH):
        require(not output.exists(), f"output_exists_preserve:{relative(output)}")

    freeze = read_json(FREEZE_PATH)
    require(freeze.get("count") == EXPECTED_STAGE_SOURCE_COUNT,
            "source_freeze_446_count_required")
    snapshot_refs = frozen_snapshot_references(freeze)
    before_files = list_regular_files(STAGE)
    snap_root_prefix = relative(STAGE / "source-snapshots-001") + "/"
    present_source_snapshot_files = {
        relative(path) for path in before_files if relative(path).startswith(snap_root_prefix)
    }
    require(present_source_snapshot_files == set(snapshot_refs),
            "source_snapshot_tree_differs_from_existing_446_freeze")

    baseline = baseline_pins()
    builds = build_review_pins()
    owned_inputs = owned_inputs_pins()
    require(owned_inputs["file_count"] == 4, "owned_inputs_fixture_tree_unexpected_file_count")
    helper_pin = file_pin(Path(__file__))
    snapshot_receipt = read_json(SNAPSHOT_RECEIPT_PATH)
    verified_state = audit_and_live_checks(snapshot_receipt)
    batch72_regression = verify_full_and_postverify(file_pin(FREEZE_PATH), baseline)

    SNAPSHOT_ROOT.mkdir(exist_ok=False)
    document_records = [copy_document(source, destination) for source, destination in DOCUMENTS]
    doc_source_paths = {record["source"]["path"] for record in document_records}
    require(len(doc_source_paths) == 4, "document_mirror_source_count_mismatch")

    stage_entries, stage_counts = stage_file_manifest(freeze)
    sqlite_sidecars = [
        {"path": item["path"], "bytes": item["bytes"], "sha256": item["sha256"],
         "attribution": "unknown; recorded as found at archive time"}
        for item in stage_entries
        if item["path"].endswith(("-wal", "-shm"))
    ]
    stage_names = {record["path"] for record in stage_entries}
    for record in document_records:
        require(record["snapshot"]["path"] in stage_names,
                f"document_snapshot_missing_from_stage_manifest:{record['snapshot']['path']}")
    require(stage_counts["existing_freeze_snapshot_references"] == EXPECTED_STAGE_SOURCE_COUNT,
            "stage_manifest_source_snapshot_reference_count_mismatch")

    manifest = {
        "schema": "information.battle_gate_trace.scoped_artifact_manifest.v1",
        "status": "passed",
        "batch": 72,
        "scope": "batch72 immutable evidence only; not a whole-project archive",
        "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "hash_chunk_bytes": CHUNK_BYTES,
        "stage_root": relative(STAGE),
        "excluded_self_referential_paths": [relative(MANIFEST_PATH), relative(VERIFICATION_PATH)],
        "stage_file_counts": stage_counts,
        "stage_files": stage_entries,
        "sqlite_sidecars": sqlite_sidecars,
        "document_mirror": {
            "root": relative(SNAPSHOT_ROOT),
            "exclusive_stream_copies": True,
            "files": document_records,
        },
        "frozen_source_tree_reference": {
            "source_freeze": file_pin(FREEZE_PATH),
            "source_post_run_verification": file_pin(POSTVERIFY_PATH),
            "count": EXPECTED_STAGE_SOURCE_COUNT,
            "stage_snapshot_tree_file_count": len(present_source_snapshot_files),
            "snapshot_contents_rehashed": False,
            "snapshot_bytes_and_sha256_source": "existing passed source-freeze-001 snapshot pins, cross-referenced by source-post-run-verification-001",
            "current_snapshot_paths_and_sizes_matched_without_rehash": True,
        },
        "fixed_external_pins": {
            "v32_build_manifests_and_dlls": builds,
            "batch71_baseline": baseline,
            "batch71_owned_inputs_fixture_full_tree": owned_inputs,
            "archive_helper": helper_pin,
        },
        "validated_batch_evidence": {
            "regression": batch72_regression,
            "live_and_boundary": verified_state,
            "snapshot_receipt": file_pin(SNAPSHOT_RECEIPT_PATH),
        },
        "scope_boundary": {
            "only_this_batch_artifacts_claimed": True,
            "whole_development_plan_complete": False,
            "B04_complete": False,
            "FRA_positive_acceptance_claimed": False,
            "old_missing_61_item_or_other_history_claimed_repaired": False,
            "game_rpm_mcp_control_native_or_test_actions": False,
        },
    }
    write_exclusive(MANIFEST_PATH, manifest)
    manifest_pin = file_pin(MANIFEST_PATH)
    reread_manifest = read_json(MANIFEST_PATH)
    require(reread_manifest.get("status") == "passed"
            and len(reread_manifest.get("stage_files", [])) == stage_counts["regular_files_listed"],
            "written_manifest_readback_mismatch")

    verification = {
        "schema": "information.battle_gate_trace.archive_verification.v1",
        "status": "passed",
        "batch": 72,
        "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "manifest": manifest_pin,
        "checks": {
            "four_document_snapshots_stream_copied_exclusively": True,
            "all_stage_regular_files_listed_except_manifest_and_verification": True,
            "stage_regular_file_count": stage_counts["regular_files_listed"],
            "stage_source_snapshot_reference_count": stage_counts["existing_freeze_snapshot_references"],
            "stage_non_snapshot_content_stream_hash_count": stage_counts["content_stream_hashed_files"],
            "source_snapshot_tree_rehashed": False,
            "sqlite_sidecars_pinned_with_unknown_attribution": all(
                item["attribution"].startswith("unknown") for item in sqlite_sidecars
            ),
            "only_requested_external_pins_included": True,
            "v32_build001_build002_manifest_dll_pins_validated": True,
            "batch71_baseline_four_pins_validated": True,
            "owned_inputs_fixture_full_tree_pinned": owned_inputs["file_count"] == 4,
            "full_3252_106_35_no_new_bad": batch72_regression["no_new_bad"] is True,
            "postverify_446": batch72_regression["source_count"] == 446,
            "independent_11_client_route_negative_and_FRA_zero": True,
            "four_service_db_events_are_not_battles": True,
            "current_POR_human1_FRA0_date_paused": True,
            "capture_disabled_unowned_noactive_server0": True,
            "three_database_backups_integrity_and_rows_validated_read_only": all(
                row["integrity_passed"] for row in verified_state["final_database_integrity_and_rows"]
            ),
            "failed_FRA_acceptance_retained_truthfully": True,
            "B04_or_full_development_plan_not_claimed_complete": True,
            "no_full_stage_archive_walk_or_live_action": True,
        },
        "counts": {
            "stage_files": stage_counts["regular_files_listed"],
            "document_snapshots": len(document_records),
            "source_snapshots_referenced": EXPECTED_STAGE_SOURCE_COUNT,
            "external_build_artifacts": sum(len(item["artifacts"]) for item in builds),
            "batch71_baseline_pins": len(baseline),
            "owned_inputs_fixture_files": owned_inputs["file_count"],
            "sqlite_sidecars": len(sqlite_sidecars),
            "client_route_records": 11,
            "FRA_direct_battle_events": 0,
            "full_passed": 3252,
            "full_failed": 106,
            "full_errors": 35,
        },
        "boundary": "This is a scoped archive of batch72 evidence only. It preserves the failed FRA positive acceptance and does not claim full B04正文、visibility、or the full development plan.",
    }
    write_exclusive(VERIFICATION_PATH, verification)
    return manifest, verification


def main() -> int:
    try:
        manifest, verification = create_archive()
    except Exception as exc:
        print(json.dumps({
            "status": "failed",
            "error": f"{type(exc).__name__}:{exc}",
            "partial_outputs_preserved": True,
        }, ensure_ascii=False))
        return 2
    print(json.dumps({
        "status": verification["status"],
        "batch": manifest["batch"],
        "manifest": relative(MANIFEST_PATH),
        "manifest_sha256": file_pin(MANIFEST_PATH)["sha256"],
        "verification": relative(VERIFICATION_PATH),
        "verification_sha256": file_pin(VERIFICATION_PATH)["sha256"],
        "stage_file_count": len(manifest["stage_files"]),
        "source_snapshot_reference_count": manifest["stage_file_counts"]["existing_freeze_snapshot_references"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
