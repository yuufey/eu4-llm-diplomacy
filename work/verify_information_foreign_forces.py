"""Prepare and run the batch-87 foreign-force regression freeze.

The baseline is batch 86's one full bridge test run and 861 selected sources.
This verifier uses the accepted batch-87 live receipt and independent audit,
snapshots a deduplicated source union, then permits one full test run. Old
snapshots are never recursively added to the active source set.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from work import verify_information_foreign_manpower as batch86  # noqa: E402

common = batch86.common
STAGE = ROOT / "work/runtime/information-foreign-forces-20261029-001"
PREPARATION = STAGE / "full-harness-preparation-001"
BASE = ROOT / "work/runtime/information-foreign-military-resources-20261029-001"
BASE_BUILD_MANIFEST = ROOT / (
    "work/runtime/diplomacy-observer-20261028-battle-context-v33-001/build-manifest.json"
)
REVISION = "001"
BASE_BATCH = 86
BASE_COUNT = 861
BASE_BAD_OCCURRENCES = 141
BASELINE_SUMMARY = {"tests": 6603, "failures": 106, "errors": 35, "skipped": 0}
BASELINE_TERMINAL = "106 failed, 4448 passed, 35 errors, 2014 subtests passed"
BASELINE_ALLOWED_DELTAS = {
    "bridge/information/foreign_technology.py":
        "batch-87 force capture selection: share the force capture for force and visibility fields",
    "bridge/tests/test_information_foreign_manpower.py":
        "batch-87 selector assertion updates for force-only capture reuse",
    "bridge/tests/test_information_foreign_technology.py":
        "batch-87 selector assertion updates for force-only capture reuse",
    "docs/外国人力查询.md":
        "batch-87 cross-reference to the new force statistics guide",
    "docs/外国军事科技与观察方准入.md":
        "batch-87 documentation update for shared military-stat permission",
    "docs/信息字段覆盖.json":
        "batch-87 F02 visible army/navy coverage update from planned to partial",
}

PROFILE_PATH = "bridge/information/profiles/foreign-force-statistics-memory-1374.json"
PROFILE_SHA256 = "bb5ce60a84235945f8c753979414caebb133f3ff41f323e7b8f9b7dbdaf2b1d6"
PROFILE_ID = "foreign-force-statistics-memory-1374"
PROFILE_VERSION = 1
EXPECTED_CONFIGURED_FIELD_COUNTS = {"available": 62, "partial": 187, "planned": 148}
EXPECTED_LIVE_FIELD_COUNTS = {"available": 56, "partial": 151, "planned": 190}
EXPECTED_CONFIGURED_TOPIC_STATUS_COUNTS = {"available": 47, "partial": 4, "planned": 23}
EXPECTED_LIVE_CALLABLE_TOPICS = 42

SELECTOR_DELTA_PATH = (
    "work/runtime/information-foreign-forces-20261029-001/"
    "private-source-selector-delta-001.json"
)
SELECTOR_RECONSTRUCTION_PATH = (
    "work/runtime/information-foreign-forces-20261029-001/"
    "public-source-before-selector-fix-001.py"
)

# New source paths are explicit. Runtime captures, accepted receipts and large
# prior snapshot trees are inputs/evidence, not recursively enumerated sources.
CORE_SOURCES = (
    "bridge/information/foreign_forces_capture.py",
    "bridge/tests/test_information_foreign_forces_capture.py",
    "bridge/information/foreign_force_statistics_memory.py",
    "bridge/tests/test_information_foreign_force_statistics_memory.py",
    "bridge/tests/test_information_foreign_forces.py",
    PROFILE_PATH,
    "docs/外国陆海军统计查询.md",
    "work/create_information_foreign_force_statistics_profile.py",
    "work/update_information_foreign_forces_coverage.py",
    "work/finalize_information_foreign_forces.py",
    "work/verify_information_foreign_forces.py",
    "work/validate_information_live.py",
    "work/runtime/information-foreign-forces-20261029-001/probe_force_predicates_001.py",
    "work/runtime/information-foreign-forces-20261029-001/probe_force_statistics_001.py",
    "work/runtime/information-foreign-forces-20261029-001/ordinary-force-formatters-001/audit_force_formatters.py",
    "work/runtime/information-foreign-forces-20261029-001/serve_archived_forces_001.py",
    "work/runtime/information-foreign-forces-20261029-001/validate_forces_mcp_001.py",
    "work/runtime/information-foreign-forces-20261029-001/reconcile_forces_mcp_001.py",
    "work/runtime/information-foreign-forces-20261029-001/independent_forces_audit_001.py",
    "docs/外国军事科技与观察方准入.md",
    "docs/信息字段覆盖.json",
)
EVIDENCE_PATHS = (
    "work/runtime/information-foreign-forces-20261029-001/force-profile-build-001.json",
    "work/runtime/information-foreign-forces-20261029-001/force-predicate-map-research-001.json",
    "work/runtime/information-foreign-forces-20261029-001/force-unit-label-evidence-001.json",
    "work/runtime/information-foreign-forces-20261029-001/ordinary-force-formatters-001/ordinary-force-formatters-002.json",
    SELECTOR_DELTA_PATH,
    SELECTOR_RECONSTRUCTION_PATH,
    "work/runtime/information-foreign-forces-20261029-001/mcp-live-001/receipt.json",
    "work/runtime/information-foreign-forces-20261029-001/mcp-live-001/mcp-transcript.json",
    "work/runtime/information-foreign-forces-20261029-001/mcp-live-001/mcp-stderr.txt",
    "work/runtime/information-foreign-forces-20261029-001/mcp-live-001/source-pins-before.json",
    "work/runtime/information-foreign-forces-20261029-001/mcp-live-001/source-pins-after.json",
    "work/runtime/information-foreign-forces-20261029-001/mcp-live-002/receipt.json",
)
PRIVATE_RAW_PATHS = (
    "work/runtime/information-foreign-forces-20261029-001/forces-private-live-001/receipt.json",
    "work/runtime/information-foreign-forces-20261029-001/forces-private-live-001/ENG-raw.json",
    "work/runtime/information-foreign-forces-20261029-001/forces-private-live-001/BUR-raw.json",
    "work/runtime/information-foreign-forces-20261029-001/forces-private-live-001/ORL-raw.json",
)

RESEARCH_PYTHON = common.PYTHON
pin = common.pin
read_json = common.read_json
write_new = common.write_new
copy_stream = common.copy_stream


def _baseline_paths() -> dict[str, Path]:
    return {
        "freeze": BASE / "source-freeze-001.json",
        "full": BASE / "regression-full-001.xml",
        "log": BASE / "regression-full-001.log",
        "comparison": BASE / "regression-comparison-001.json",
        "postverify": BASE / "source-post-run-verification-001.json",
        "reservation": BASE / "full-execution-reservation-001.json",
        "boundary": BASE / "full-execution-boundary-001.json",
        "evidence_index": BASE / "final-evidence-index-001.json",
    }


def _tail(path: Path, limit: int = 8192) -> str:
    path = common.workspace(path)
    size = path.stat().st_size
    with path.open("rb") as stream:
        stream.seek(max(0, size - limit))
        return stream.read(limit).decode("utf-8", errors="replace")


def _reviewed_delta_map(items: list[str] | None) -> dict[str, str]:
    result = dict(BASELINE_ALLOWED_DELTAS)
    for item in items or []:
        path, separator, reason = item.partition("=")
        if not separator or not path.strip() or not reason.strip():
            raise ValueError("reviewed_baseline_delta_must_be_PATH_EQUALS_REASON")
        normalized = common.workspace(path.strip()).relative_to(ROOT).as_posix()
        result[normalized] = reason.strip()
    return result


def _extra_source_paths(items: list[str] | None) -> list[str]:
    return sorted({common.workspace(path).relative_to(ROOT).as_posix()
                   for path in (items or [])})


def baseline_inputs(reviewed_deltas: list[str] | None = None) -> tuple[dict, list[dict], dict, dict]:
    """Validate batch 86's accepted freeze, full-run baseline, and v33 build."""
    paths = _baseline_paths()
    frozen = read_json(paths["freeze"])
    files = frozen.get("files", [])
    if (frozen.get("schema") != "information.foreign_manpower.source_freeze.v1"
            or frozen.get("batch") != BASE_BATCH or frozen.get("revision") != "001"
            or frozen.get("status") != "passed" or frozen.get("count") != BASE_COUNT
            or len(files) != BASE_COUNT):
        raise ValueError("batch86_freeze_schema_or_count_mismatch")

    allowed = _reviewed_delta_map(reviewed_deltas)
    changes: list[dict] = []
    seen: set[str] = set()
    for row in files:
        source, snapshot = row["source"], row["snapshot"]
        name = source["path"]
        if name in seen:
            raise ValueError(f"batch86_duplicate_source:{name}")
        seen.add(name)
        if pin(snapshot["path"]) != snapshot:
            raise ValueError(f"batch86_snapshot_pin_mismatch:{name}")
        if (source.get("bytes"), source.get("sha256")) != (
                snapshot.get("bytes"), snapshot.get("sha256")):
            raise ValueError(f"batch86_source_snapshot_pair_mismatch:{name}")
        current = pin(name)
        if current != source:
            if name not in allowed:
                raise ValueError(f"unreviewed_batch86_source_change:{name}")
            changes.append({"path": name, "before": source, "after": current,
                            "reason": allowed[name]})

    comparison = read_json(paths["comparison"])
    postverify = read_json(paths["postverify"])
    reservation = read_json(paths["reservation"])
    boundary = read_json(paths["boundary"])
    evidence_index = read_json(paths["evidence_index"])
    full_pin, log_pin = pin(paths["full"]), pin(paths["log"])
    if (comparison.get("schema") != "information.foreign_manpower.regression_comparison.v1"
            or comparison.get("status") != "passed_no_new_bad"
            or comparison.get("batch") != BASE_BATCH
            or comparison.get("current") != full_pin or comparison.get("log") != log_pin
            or comparison.get("baseline_bad_occurrences") != BASE_BAD_OCCURRENCES
            or comparison.get("current_bad_occurrences") != BASE_BAD_OCCURRENCES
            or comparison.get("new_bad") != [] or comparison.get("no_new_bad") is not True
            or comparison.get("whole_suite_passed") is not False):
        raise ValueError("batch86_comparison_mismatch")
    if (postverify.get("status") != "passed_no_new_bad"
            or postverify.get("batch") != BASE_BATCH or postverify.get("count") != BASE_COUNT
            or postverify.get("freeze") != pin(paths["freeze"])
            or postverify.get("regression_comparison") != pin(paths["comparison"])
            or postverify.get("current_sources_match_snapshots") is not True
            or postverify.get("no_new_bad") is not True):
        raise ValueError("batch86_postverify_mismatch")
    if reservation.get("runs") != 1 or reservation.get("freeze") != pin(paths["freeze"]):
        raise ValueError("batch86_full_reservation_mismatch")
    argv = reservation.get("argv", [])
    if ("pytest" not in argv or "bridge/tests" not in argv
            or "--junitxml" not in argv or argv[-1] != str(paths["full"])):
        raise ValueError("batch86_full_argv_mismatch")
    if (boundary.get("returncode") != comparison.get("returncode")
            or boundary.get("xml") != full_pin or boundary.get("log") != log_pin):
        raise ValueError("batch86_full_boundary_mismatch")
    if (evidence_index.get("status") != "indexed" or evidence_index.get("batch") != 86
            or evidence_index.get("count") != 1079
            or len(evidence_index.get("files", [])) != 1079):
        raise ValueError("batch86_evidence_index_mismatch")

    old_bad = common.bad_cases(paths["full"])
    summary = common.junit_summary(paths["full"])
    if (sum(old_bad.values()) != BASE_BAD_OCCURRENCES
            or summary != BASELINE_SUMMARY
            or comparison.get("junit_summary") != summary
            or BASELINE_TERMINAL not in _tail(paths["log"])):
        raise ValueError("batch86_full_baseline_counts_mismatch")

    build = common.manifest_inputs(BASE_BUILD_MANIFEST)
    common.validate_build_inheritance(frozen, build)
    if len(build["native"]) != 125 or len(build["copies"]) != 125:
        raise ValueError("inherited_v33_source_count_mismatch")
    baseline_pins = {name: pin(path) for name, path in paths.items()}
    return frozen, changes, build, {"pins": baseline_pins,
                                    "summary": summary,
                                    "bad_occurrences": sum(old_bad.values()),
                                    "evidence_index_count": 1079}


def _profile_inputs() -> dict:
    module = importlib.import_module("bridge.information.foreign_forces_capture")
    profile_pin = pin(module.PROFILE_FILE)
    if (profile_pin["path"] != PROFILE_PATH or profile_pin["sha256"] != PROFILE_SHA256
            or module.PROFILE_SHA256 != PROFILE_SHA256):
        raise ValueError("foreign_forces_profile_pin_mismatch")
    profile = module._load_profile()
    if (not isinstance(profile, dict) or profile.get("profile_id") != PROFILE_ID
            or profile.get("profile_version") != PROFILE_VERSION
            or len(profile.get("code_guards", [])) != 7
            or not isinstance(profile.get("force_predicates"), dict)):
        raise ValueError("foreign_forces_profile_load_invalid")
    dependencies = []
    for item in profile.get("source_evidence", []) + profile.get("layout_dependencies", []):
        path = common.workspace(ROOT / item["path"])
        path.relative_to(ROOT)
        dependencies.append(path.relative_to(ROOT).as_posix())
    return {"module": pin(module.__file__), "profile": profile_pin,
            "loaded_profile_version": profile.get("profile_version"),
            "force_predicates_sha256": hashlib.sha256(
                json.dumps(profile["force_predicates"], sort_keys=True,
                           separators=(",", ":")).encode("utf-8")).hexdigest(),
            "dependencies": sorted(set(dependencies))}


def _selector_evidence() -> dict:
    note = read_json(STAGE / Path(SELECTOR_DELTA_PATH).name)
    if (note.get("status") != "passed"
            or note.get("schema") != "information.private_source_selector_delta.v1"
            or note.get("new_RPM_or_native_calls") is not False
            or note.get("no_reacquisition") is not True
            or note.get("original_capture_source_pins_unchanged") is not True):
        raise ValueError("private_selector_delta_not_accepted")
    original = note.get("original_private_receipt")
    if not isinstance(original, dict) or pin(original["path"]) != original:
        raise ValueError("private_selector_original_receipt_pin_mismatch")
    rebuilt = note.get("before_public_source")
    if (not isinstance(rebuilt, dict) or rebuilt.get("path") != SELECTOR_RECONSTRUCTION_PATH
            or rebuilt.get("provenance") !=
            "byte-exact reconstruction by reversing selector edit; not a contemporaneous backup"
            or pin(rebuilt["path"]) != {k: rebuilt[k] for k in ("path", "bytes", "sha256")}):
        raise ValueError("private_selector_reconstruction_pin_mismatch")
    current_changes = note.get("current_changes")
    if (not isinstance(current_changes, list) or len(current_changes) != 1
            or current_changes[0].get("current", {}).get("path") !=
            "bridge/information/foreign_technology.py"
            or pin("bridge/information/foreign_technology.py") != current_changes[0]["current"]):
        raise ValueError("private_selector_current_source_mismatch")
    raw_reports = note.get("saved_reports_revalidated")
    if not isinstance(raw_reports, list) or {row.get("country") for row in raw_reports} != {
            "ENG", "BUR", "ORL"}:
        raise ValueError("private_selector_saved_reports_missing")
    raw_pins = []
    for row in raw_reports:
        raw = row.get("raw")
        if (not isinstance(raw, dict) or row.get("strict_saved_replay_valid_under_current_collectors") is not True
                or pin(raw["path"]) != raw):
            raise ValueError("private_selector_raw_capture_pin_mismatch")
        raw_pins.append(raw)
    return {"delta_note": pin(SELECTOR_DELTA_PATH),
            "reconstructed_before_source": pin(SELECTOR_RECONSTRUCTION_PATH),
            "reconstruction_provenance": rebuilt["provenance"],
            "original_private_receipt": original,
            "revalidated_private_raws": sorted(raw_pins, key=lambda item: item["path"]),
            "current_public_source": current_changes[0]["current"]}


def _evidence_inputs() -> dict:
    evidence = {path: pin(path) for path in EVIDENCE_PATHS}
    private_files = [pin(path) for path in PRIVATE_RAW_PATHS]
    selector = _selector_evidence()
    failed_attempt = _failed_attempt_inputs()
    for item in selector["revalidated_private_raws"]:
        if item not in private_files:
            raise ValueError("private_selector_capture_not_in_source_evidence")
    return {"evidence_pins": evidence, "private_capture_pins": private_files,
            "selector_delta": selector, "preserved_failed_mcp_attempt": failed_attempt}


def _failed_attempt_inputs() -> dict:
    folder = STAGE / "mcp-live-001"
    receipt = read_json(folder / "receipt.json")
    before = read_json(folder / "source-pins-before.json")
    after = read_json(folder / "source-pins-after.json")
    transcript = read_json(folder / "mcp-transcript.json")
    if (receipt.get("schema") != "information.foreign_force_statistics_mcp_acceptance.v1"
            or receipt.get("status") != "failed"
            or receipt.get("server_started") is not False
            or receipt.get("archived_capture_count") != 0
            or receipt.get("archived_captures") != []
            or receipt.get("source_pins_unchanged") is not True
            or receipt.get("source_pins_unchanged_before_run") is not True
            or receipt.get("native_game_calls") is not False
            or receipt.get("business_dispatched") is not False
            or before != after
            or not isinstance(transcript, list)):
        raise ValueError("failed_mcp_001_not_retained_as_pre_query_failure")
    return {"receipt": pin(folder / "receipt.json"),
            "transcript": pin(folder / "mcp-transcript.json"),
            "stderr": pin(folder / "mcp-stderr.txt"),
            "source_pins_before": pin(folder / "source-pins-before.json"),
            "source_pins_after": pin(folder / "source-pins-after.json"),
            "status": "failed_before_server_start_no_capture",
            "server_started": False, "archived_capture_count": 0,
            "source_pins_unchanged": True}


def _topic_map(topics: list[dict]) -> dict[str, dict]:
    rows = {row.get("topic_id"): row for row in topics if isinstance(row, dict)}
    if len(rows) != len(topics) or None in rows:
        raise ValueError("topic_list_invalid_or_duplicate")
    return rows


def _coverage_inputs(discovery_path: Path, baseline: dict) -> dict:
    doc_path = ROOT / "docs/信息字段覆盖.json"
    doc = read_json(doc_path)
    old_doc_row = next((row for row in baseline["files"]
                        if row["source"]["path"] == "docs/信息字段覆盖.json"), None)
    if old_doc_row is None:
        raise ValueError("batch86_baseline_coverage_snapshot_missing")
    old_doc = read_json(old_doc_row["snapshot"]["path"])
    old_topics = _topic_map(old_doc["topics"])
    current_topics = _topic_map(doc["topics"])
    if set(old_topics) != set(current_topics):
        raise ValueError("configured_topic_set_changed")
    old_f02, current_f02 = old_topics.get("F02"), current_topics.get("F02")
    if not isinstance(old_f02, dict) or not isinstance(current_f02, dict):
        raise ValueError("f02_topic_missing")
    if set(old_f02["fields"]) != set(current_f02["fields"]):
        raise ValueError("f02_field_set_changed")
    for topic_id, row in old_topics.items():
        if topic_id != "F02" and current_topics[topic_id] != row:
            raise ValueError(f"unexpected_configured_topic_change:{topic_id}")
    configured = common.coverage_counts(doc["topics"])
    if (configured["topic_count"] != 74 or configured["field_count"] != 397
            or configured["field_counts"] != EXPECTED_CONFIGURED_FIELD_COUNTS
            or configured["topic_status_counts"] != EXPECTED_CONFIGURED_TOPIC_STATUS_COUNTS
            or configured["callable_topic_count"] != 47
            or doc.get("goal_complete") is not False
            or doc.get("expected_counts") != doc.get("counts")
            or doc.get("counts") != configured):
        raise ValueError("foreign_forces_configured_coverage_mismatch")
    if doc.get("configuration") != old_doc.get("configuration"):
        raise ValueError("unexpected_configuration_change")
    if current_f02.get("status") != "available":
        raise ValueError("f02_route_not_available")
    if (old_f02["fields"]["visible_army"].get("coverage") != "planned"
            or old_f02["fields"]["visible_navy"].get("coverage") != "planned"):
        raise ValueError("batch86_force_coverage_baseline_invalid")
    for field in ("visible_army", "visible_navy", "visibility"):
        if current_f02["fields"][field].get("coverage") != "partial":
            raise ValueError(f"f02_{field}_not_partial")
    for field_id, old_field in old_f02["fields"].items():
        current_field = current_f02["fields"][field_id]
        if field_id in ("visible_army", "visible_navy"):
            if current_field.get("coverage") != "partial":
                raise ValueError(f"f02_force_field_not_promoted:{field_id}")
        elif current_field.get("coverage") != old_field.get("coverage"):
            raise ValueError(f"unexpected_f02_coverage_change:{field_id}")
    compact_expected = {key: current_f02[key] for key in
                        ("fields", "context_scope", "source", "adapter_sources")
                        if key in current_f02}
    if doc.get("F02") != compact_expected:
        raise ValueError("f02_compact_row_mismatch")

    discovery = read_json(discovery_path)
    live_topics = _topic_map(discovery["topics"])
    actual = common.coverage_counts(discovery["topics"])
    if (actual["topic_count"] != 74 or actual["field_count"] != 397
            or actual["field_counts"] != EXPECTED_LIVE_FIELD_COUNTS
            or actual["callable_topic_count"] != EXPECTED_LIVE_CALLABLE_TOPICS
            or set(live_topics) != set(current_topics)):
        raise ValueError("foreign_forces_actual_coverage_shape_mismatch")
    if current_f02 != live_topics["F02"]:
        raise ValueError("f02_configured_discovery_row_mismatch")
    for topic_id, row in current_topics.items():
        if set(row["fields"]) != set(live_topics[topic_id].get("fields", {})):
            raise ValueError(f"live_field_set_changed:{topic_id}")
    return {"coverage_document": pin(doc_path), "discovery": pin(discovery_path),
            "configured_counts": configured, "actual_live_counts": actual,
            "goal_complete": False, "f02_status": current_f02["status"],
            "f02_partial_fields": ["visible_army", "visible_navy", "visibility"],
            "live_callable_topic_count": actual["callable_topic_count"]}


def _live_inputs(path: Path) -> dict:
    """Validate the accepted saved-delivery reconciliation and preserve its failed run."""
    receipt = read_json(path)
    expected_path = STAGE / "mcp-live-002" / "offline-reconciliation-001.json"
    if (common.workspace(path) != expected_path.resolve()
            or not isinstance(receipt, dict)
            or receipt.get("schema") != "information.foreign_force_statistics_mcp_acceptance.v1"
            or receipt.get("status") != "passed"
            or receipt.get("acceptance_basis") != "saved-delivery-and-archive-reconciliation"
            or receipt.get("observer") != "FRA"
            or receipt.get("targets") != ["ENG", "BUR", "ORL"]
            or receipt.get("fields") != ["visible_army", "visible_navy", "visibility"]
            or receipt.get("combined_query_fields") != [
                "military_technology", "manpower", "visible_army", "visible_navy", "visibility"]
            or receipt.get("server_started") is not True
            or receipt.get("server_exit_code") != 0
            or receipt.get("source_pins_unchanged") is not True
            or receipt.get("source_pins_unchanged_before_run") is not True
            or receipt.get("native_game_calls") is not False
            or receipt.get("business_dispatched") is not False
            or any(receipt.get(flag) is not False for flag in (
                "game_controls", "writes_to_game", "date_advance", "save_or_reload",
                "UI_control", "computer_use"))):
        raise ValueError("foreign_forces_accepted_reconciliation_identity_or_scope_mismatch")

    checks = receipt.get("checks")
    required_checks = {
        "no_active_subscriptions", "source_pins_unchanged", "capture_count_matches_delivery",
        "capture_count_matches_actual_provenance_references",
        "all_saved_capture_reports_strictly_replayed",
        "all_saved_query_report_and_periodic_items_revalidated",
        "manual_result_copies_excluded_from_capture_count",
        "cancelled_results_collected_after_cancel", "server_exit_code_zero",
    }
    periodic = receipt.get("periodic_counts")
    archives = receipt.get("archived_captures")
    expected_count = receipt.get("expected_capture_count")
    crosscheck_count = receipt.get("expected_capture_count_by_formula_crosscheck")
    archive_counts = receipt.get("archive_source_counts")
    if (not isinstance(checks, dict) or set(checks) != required_checks
            or any(value is not True for value in checks.values())
            or not isinstance(periodic, dict)
            or periodic.get("2", 0) < 2 or periodic.get("5", 0) < 1
            or receipt.get("two_cycles_met_before_cancel") is not True
            or receipt.get("primary_queries_and_periodic_minimum_completed") is not True
            or receipt.get("manual_result_copy_count_before_cancel") != 3
            or receipt.get("manual_result_copy_count_after_cancel") != 3
            or not isinstance(receipt.get("cancel_events"), list)
            or len(receipt["cancel_events"]) != 2
            or any(row.get("response_state") != "cancelled"
                   for row in receipt["cancel_events"])
            or not isinstance(archives, list)
            or expected_count != crosscheck_count
            or expected_count != len(archives)
            or receipt.get("archived_capture_count") != len(archives)
            or archive_counts != {"forces": 19, "technology": 1, "manpower": 1}
            or receipt.get("original_attempt_status") != "failed"
            or "foreign_technology_capture" not in str(receipt.get("original_error", ""))
            or "SCHEMA" not in str(receipt.get("original_error", ""))):
        raise ValueError("foreign_forces_accepted_reconciliation_checks_mismatch")

    reconciliation = receipt.get("offline_reconciliation")
    if (not isinstance(reconciliation, dict)
            or reconciliation.get("status") != "passed"
            or reconciliation.get("tool", {}).get("path") !=
            "work/runtime/information-foreign-forces-20261029-001/reconcile_forces_mcp_001.py"
            or pin(reconciliation["tool"]["path"]) != reconciliation["tool"]
            or reconciliation.get("legacy_technology_schema_shim", {}).get("source_files_modified") is not False
            or reconciliation.get("legacy_technology_schema_shim", {}).get("saved_reports_modified") is not False
            or reconciliation.get("legacy_technology_schema_shim", {}).get("capture_and_validate_capture_replay") is not True
            or reconciliation.get("original_source_pins_before_after_equal") is not True
            or reconciliation.get("current_original_input_pins_match") is not True):
        raise ValueError("foreign_forces_offline_reconciliation_not_reproducible")

    original_pin = receipt.get("original_mcp_receipt")
    original_path = STAGE / "mcp-live-002" / "receipt.json"
    if (not isinstance(original_pin, dict)
            or original_pin.get("path") != original_path.relative_to(ROOT).as_posix()
            or pin(original_path) != original_pin):
        raise ValueError("foreign_forces_original_failed_mcp002_pin_mismatch")
    original = read_json(original_path)
    if (original.get("status") != "failed"
            or original.get("archive_validation_error") != receipt.get("original_error")
            or original.get("server_started") is not True
            or original.get("server_exit_code") != 0
            or original.get("source_pins_unchanged") is not True):
        raise ValueError("foreign_forces_original_failed_mcp002_not_preserved")

    output_pins = receipt.get("output_file_pins")
    if not isinstance(output_pins, list) or not output_pins:
        raise ValueError("foreign_forces_accepted_outputs_missing")
    for row in output_pins:
        if not isinstance(row, dict) or pin(row.get("path", "")) != row:
            raise ValueError("foreign_forces_accepted_output_pin_mismatch")

    return {"receipt": pin(path), "status": "passed",
            "receipt_schema": receipt["schema"],
            "acceptance_basis": receipt["acceptance_basis"],
            "original_failed_attempt": original_pin,
            "original_failed_error": receipt["original_error"],
            "archive_count": len(archives), "archive_source_counts": archive_counts,
            "periodic_counts": periodic, "server_exit_code": receipt["server_exit_code"],
            "source_pins_unchanged": True,
            "output_file_pin_count": len(output_pins),
            "reconciliation_tool": reconciliation["tool"]}


def _audit_inputs(path: Path, live: dict) -> dict:
    audit = read_json(path)
    if (audit.get("schema") != "independent_foreign_forces_live_audit.v1"
            or audit.get("status") != "passed"):
        raise ValueError("foreign_forces_independent_audit_not_passed")
    if audit.get("auditor_source") != pin(
            "work/runtime/information-foreign-forces-20261029-001/independent_forces_audit_001.py"):
        raise ValueError("foreign_forces_auditor_source_pin_mismatch")
    mcp = audit.get("mcp")
    if (not isinstance(mcp, dict)
            or mcp.get("receipt") != live["receipt"]
            or mcp.get("accepted_reconciliation", {}).get("basis") !=
            "saved-delivery-and-archive-reconciliation"
            or mcp.get("capture_count") != live["archive_count"]
            or mcp.get("capture_source_counts") != live["archive_source_counts"]
            or mcp.get("independent_force_math_count") != 19
            or not isinstance(mcp.get("input_pins"), list)
            or live["receipt"] not in mcp["input_pins"]
            or live["original_failed_attempt"] not in mcp["input_pins"]):
        raise ValueError("foreign_forces_audit_receipt_or_archive_mismatch")
    audit_checks = audit.get("checks")
    if (not isinstance(audit_checks, list) or len(audit_checks) != 10
            or any(not isinstance(row, dict) or row.get("passed") is not True
                   for row in audit_checks)):
        raise ValueError("foreign_forces_audit_checks_incomplete")
    if (mcp.get("query_report_items_fields_deep_equal") is not True
            or mcp.get("after_cancel", {}).get("no_active_subscriptions") is not True
            or mcp.get("after_cancel", {}).get("subscriptions_cancelled") != 2
            or mcp.get("public_inner_hash_references") != live["archive_count"]):
        raise ValueError("foreign_forces_audit_receipt_pin_mismatch")
    return {"audit": pin(path), "status": "passed",
            "schema": audit.get("schema"),
            "check_count": len(audit_checks), "auditor_source": audit["auditor_source"],
            "accepted_receipt": mcp["receipt"],
            "capture_count": mcp["capture_count"],
            "independent_force_math_count": mcp["independent_force_math_count"]}


def source_paths(baseline: dict, build: dict, profile: dict,
                 extra: list[str]) -> list[str]:
    paths = {row["source"]["path"] for row in baseline["files"]}
    paths.update(CORE_SOURCES)
    paths.update(profile["dependencies"])
    paths.update(build["native"])
    paths.update(build["copies"])
    paths.update(common.workspace(path).relative_to(ROOT).as_posix() for path in extra)
    return sorted(paths)


def _outputs() -> list[Path]:
    return [STAGE / "source-freeze-001.json", STAGE / "source-snapshots-001",
            STAGE / "regression-full-001.xml", STAGE / "regression-full-001.log",
            STAGE / "full-execution-reservation-001.json",
            STAGE / "full-execution-boundary-001.json",
            STAGE / "regression-comparison-001.json",
            STAGE / "source-post-run-verification-001.json"]


def preflight(live_path: Path, audit_path: Path, discovery_path: Path,
              extra_sources: list[str] | None = None,
              reviewed_deltas: list[str] | None = None, *,
              check_outputs: bool = True) -> dict:
    if not live_path or not audit_path or not discovery_path:
        raise ValueError("preflight_requires_live_receipt_audit_discovery")
    baseline, changes, build, base_pins = baseline_inputs(reviewed_deltas)
    delta_policy = _reviewed_delta_map(reviewed_deltas)
    profile = _profile_inputs()
    evidence = _evidence_inputs()
    live = _live_inputs(live_path)
    audit = _audit_inputs(audit_path, live)
    coverage = _coverage_inputs(discovery_path, baseline)
    extras = _extra_source_paths(extra_sources)
    sources = source_paths(baseline, build, profile, extras)
    missing = [path for path in sources if not (ROOT / path).is_file()]
    if missing:
        raise FileNotFoundError(f"foreign_forces_source_missing:{missing}")
    if not RESEARCH_PYTHON.is_file():
        raise FileNotFoundError(f"research_python_missing:{RESEARCH_PYTHON}")
    if check_outputs and any(path.exists() for path in _outputs()):
        raise FileExistsError("foreign_forces_revision_001_already_used")
    return {"baseline": baseline, "baseline_changes": changes,
            "reviewed_delta_policy": delta_policy,
            "baseline_pins": base_pins, "build": build, "profile": profile,
            "historical_evidence": evidence, "live": live, "audit": audit,
            "coverage": coverage, "sources": sources, "extra_sources": extras,
            "input_paths": {"live_receipt": common.workspace(live_path).relative_to(ROOT).as_posix(),
                            "independent_audit": common.workspace(audit_path).relative_to(ROOT).as_posix(),
                            "discovery_json": common.workspace(discovery_path).relative_to(ROOT).as_posix()}}


def _freeze_inputs(ready: dict) -> dict:
    baseline_paths = _baseline_paths()
    return {"baseline_freeze": pin(baseline_paths["freeze"]),
            "baseline_full": pin(baseline_paths["full"]),
            "baseline_comparison": pin(baseline_paths["comparison"]),
            "baseline_postverify": pin(baseline_paths["postverify"]),
            "baseline_evidence_index": pin(baseline_paths["evidence_index"]),
            "baseline_changes": ready["baseline_changes"],
            "reviewed_delta_policy": ready["reviewed_delta_policy"],
            "baseline_pins": ready["baseline_pins"],
            "build_manifest": ready["build"]["manifest"],
            "build_dll": ready["build"]["dll"],
            "manifest_native_sources": ready["build"]["native"],
            "manifest_build_copies": ready["build"]["copies"],
            "manifest_source_names": ready["build"]["names"],
            "manifest_native_source_count": len(ready["build"]["native"]),
            "profile": ready["profile"],
            "historical_evidence": ready["historical_evidence"],
            "live": ready["live"], "independent_audit": ready["audit"],
            "coverage": ready["coverage"], "extra_sources": ready["extra_sources"],
            "input_paths": ready["input_paths"],
            "baseline_bad_occurrences": BASE_BAD_OCCURRENCES,
            "baseline_junit_summary": BASELINE_SUMMARY,
            "source_snapshot_policy":
                "batch86-861-selected-sources-plus-explicit-batch87-sources; no snapshot recursion; selector reconstruction is historical evidence only"}


def freeze(live_path: Path, audit_path: Path, discovery_path: Path,
           extra_sources: list[str] | None, reviewed_deltas: list[str] | None) -> dict:
    ready = preflight(live_path, audit_path, discovery_path, extra_sources,
                      reviewed_deltas, check_outputs=True)
    snapshot_dir = STAGE / "source-snapshots-001"
    target = STAGE / "source-freeze-001.json"
    inputs = _freeze_inputs(ready)
    before = {name: pin(name) for name in ready["sources"]}
    snapshot_dir.mkdir(parents=True, exist_ok=False)
    rows = []
    for name in ready["sources"]:
        snapshot = (snapshot_dir / Path(name)).resolve()
        snapshot.relative_to(snapshot_dir.resolve())
        copy_stream(name, snapshot)
        copied = pin(snapshot)
        if copied["sha256"] != before[name]["sha256"] or pin(name) != before[name]:
            raise RuntimeError(f"source_changed_during_freeze:{name}")
        rows.append({"source": before[name], "snapshot": copied})
    value = {"schema": "information.foreign_forces.source_freeze.v1",
             "batch": 87, "revision": REVISION, "status": "passed",
             "count": len(rows), "files": rows, **inputs,
             "created_at": common.stamp()}
    write_new(target, value)
    result = {"status": "passed", "phase": "freeze", "count": len(rows),
              "freeze": pin(target)}
    print(json.dumps(result, ensure_ascii=False))
    return result


def verify_sources(live_path: Path | None = None, audit_path: Path | None = None,
                   discovery_path: Path | None = None,
                   extra_sources: list[str] | None = None,
                   reviewed_deltas: list[str] | None = None) -> dict:
    frozen = read_json(STAGE / "source-freeze-001.json")
    if (frozen.get("schema") != "information.foreign_forces.source_freeze.v1"
            or frozen.get("batch") != 87 or frozen.get("revision") != REVISION
            or frozen.get("status") != "passed"):
        raise ValueError("foreign_forces_source_freeze_invalid")
    input_paths = frozen.get("input_paths", {})
    live_path = common.workspace(live_path or ROOT / input_paths["live_receipt"])
    audit_path = common.workspace(audit_path or ROOT / input_paths["independent_audit"])
    discovery_path = common.workspace(discovery_path or ROOT / input_paths["discovery_json"])
    if extra_sources is None:
        extra_sources = list(frozen.get("extra_sources", []))
    if reviewed_deltas is None:
        policy = frozen.get("reviewed_delta_policy", {})
        reviewed_deltas = [f"{path}={reason}" for path, reason in policy.items()]
    ready = preflight(live_path, audit_path, discovery_path, extra_sources,
                      reviewed_deltas, check_outputs=False)
    inputs = _freeze_inputs(ready)
    for key, expected in inputs.items():
        if frozen.get(key) != expected:
            raise ValueError(f"foreign_forces_freeze_{key}_changed")
    paths = ready["sources"]
    if (sorted(row["source"]["path"] for row in frozen.get("files", [])) != paths
            or frozen.get("count") != len(paths)
            or frozen.get("count") != len(frozen.get("files", []))):
        raise ValueError("foreign_forces_source_union_changed")
    for row in frozen["files"]:
        if pin(row["source"]["path"]) != row["source"]:
            raise ValueError(f"foreign_forces_current_source_changed:{row['source']['path']}")
        if pin(row["snapshot"]["path"]) != row["snapshot"]:
            raise ValueError(f"foreign_forces_snapshot_changed:{row['snapshot']['path']}")
        if (row["source"]["bytes"], row["source"]["sha256"]) != (
                row["snapshot"]["bytes"], row["snapshot"]["sha256"]):
            raise ValueError(f"foreign_forces_source_snapshot_mismatch:{row['source']['path']}")
    return frozen


def full(live_path: Path | None = None, audit_path: Path | None = None,
         discovery_path: Path | None = None,
         extra_sources: list[str] | None = None,
         reviewed_deltas: list[str] | None = None) -> int:
    frozen = verify_sources(live_path, audit_path, discovery_path,
                            extra_sources, reviewed_deltas)
    xml = STAGE / "regression-full-001.xml"
    log = STAGE / "regression-full-001.log"
    reservation = STAGE / "full-execution-reservation-001.json"
    boundary = STAGE / "full-execution-boundary-001.json"
    comparison_path = STAGE / "regression-comparison-001.json"
    postverify_path = STAGE / "source-post-run-verification-001.json"
    if any(path.exists() for path in (xml, log, reservation, boundary,
                                      comparison_path, postverify_path)):
        raise FileExistsError("foreign_forces_full_001_already_started")
    argv = [str(RESEARCH_PYTHON), "-B", "-m", "pytest", "-q", "bridge/tests",
            "--junitxml", str(xml)]
    write_new(reservation, {
        "runs": 1, "argv": argv,
        "freeze": pin(STAGE / "source-freeze-001.json"),
        "orchestrator_pid": os.getpid(),
        "memory_cap_bytes": 1024 * 1024 * 1024,
        "monitoring_policy":
            "monitor only this orchestrator's exact pytest child; do not poll unrelated processes",
        "started_at": common.stamp(),
    })
    try:
        with log.open("xb") as stream:
            result = subprocess.run(argv, cwd=ROOT, stdout=stream,
                                    stderr=subprocess.STDOUT, check=False)
    except Exception as exc:
        write_new(boundary, {"returncode": None, "log": pin(log),
                             "xml": pin(xml) if xml.is_file() else None,
                             "error": f"{type(exc).__name__}:{exc}",
                             "finished_at": common.stamp()})
        raise
    write_new(boundary, {"returncode": result.returncode, "log": pin(log),
                         "xml": pin(xml), "finished_at": common.stamp()})
    verify_sources(live_path, audit_path, discovery_path,
                   extra_sources, reviewed_deltas)
    old = common.bad_cases(BASE / "regression-full-001.xml")
    new = common.bad_cases(xml)
    added, resolved = new - old, old - new
    summary = common.junit_summary(xml)
    whole_suite_passed = result.returncode == 0 and not summary["failures"] and not summary["errors"]
    value = {
        "schema": "information.foreign_forces.regression_comparison.v1",
        "status": "passed_no_new_bad" if not added else "failed_new_bad",
        "batch": 87, "baseline": pin(BASE / "regression-full-001.xml"),
        "current": pin(xml), "log": pin(log),
        "baseline_bad_occurrences": sum(old.values()),
        "current_bad_occurrences": sum(new.values()),
        "new_bad": common.counter_rows(added),
        "resolved_bad": common.counter_rows(resolved),
        "no_new_bad": not added, "whole_suite_passed": whole_suite_passed,
        "returncode": result.returncode, "junit_summary": summary,
    }
    write_new(comparison_path, value)
    write_new(postverify_path, {
        "status": value["status"], "batch": 87, "count": frozen["count"],
        "freeze": pin(STAGE / "source-freeze-001.json"),
        "regression_comparison": pin(comparison_path),
        "current_sources_match_snapshots": True,
        "no_new_bad": not added, "whole_suite_passed": whole_suite_passed,
    })
    print(json.dumps(value, ensure_ascii=False))
    return 0 if not added else 2


def _arg_paths(args: argparse.Namespace) -> tuple[Path | None, Path | None, Path | None]:
    return tuple(common.workspace(path) if path else None
                 for path in (args.live_receipt, args.independent_audit, args.discovery_json))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("preflight", "freeze", "verify", "full"))
    parser.add_argument("--live-receipt")
    parser.add_argument("--independent-audit")
    parser.add_argument("--discovery-json")
    parser.add_argument("--extra-source", action="append", default=None,
                        help="Explicit batch-87 operator/evidence source path; repeat as needed")
    parser.add_argument("--reviewed-baseline-delta", action="append", default=None,
                        help="Additional reviewed baseline change as PATH=REASON")
    args = parser.parse_args(argv)
    live_path, audit_path, discovery_path = _arg_paths(args)
    if args.operation == "preflight":
        ready = preflight(live_path, audit_path, discovery_path, args.extra_source,
                          args.reviewed_baseline_delta, check_outputs=False)
        print(json.dumps({"status": "passed", "phase": "preflight",
                          "source_count": len(ready["sources"]),
                          "baseline_change_count": len(ready["baseline_changes"]),
                          "baseline_bad_occurrences": BASE_BAD_OCCURRENCES,
                          "coverage": ready["coverage"]["configured_counts"],
                          "live": ready["live"]}, ensure_ascii=False))
        return 0
    if args.operation == "freeze":
        freeze(live_path, audit_path, discovery_path, args.extra_source,
               args.reviewed_baseline_delta)
        return 0
    if args.operation == "verify":
        frozen = verify_sources(live_path, audit_path, discovery_path,
                                args.extra_source, args.reviewed_baseline_delta)
        print(json.dumps({"status": "passed", "phase": "verify",
                          "count": frozen["count"],
                          "freeze": pin(STAGE / "source-freeze-001.json")},
                         ensure_ascii=False))
        return 0
    return full(live_path, audit_path, discovery_path,
                args.extra_source, args.reviewed_baseline_delta)


if __name__ == "__main__":
    raise SystemExit(main())
