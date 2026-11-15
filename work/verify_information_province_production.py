"""Freeze and verify batch-81 province-production sources, then compare one full run.

This verifier inherits the batch-80 freeze and v33 build as immutable inputs.
It does not rebuild or install the native observer. Source copies and new
snapshots are hashed and copied with the shared 1 MiB streaming helpers.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from work import verify_information_province_details as batch80  # noqa: E402


common = batch80.prior
STAGE = ROOT / "work/runtime/information-province-production-20261029-001"
BASE = ROOT / "work/runtime/information-province-details-20261029-001"
REVISION = "001"
BASE_BATCH = 80
BASE_COUNT = 743
EXPECTED_BAD_OCCURRENCES = 141
EXPECTED_BASELINE_SUMMARY = {
    "tests": 6094,
    "failures": 106,
    "errors": 35,
    "skipped": 0,
}
EXPECTED_BASELINE_TERMINAL = "106 failed, 3948 passed, 35 errors, 2005 subtests passed"
EXPECTED_PROFILE_FIELDS = {
    "G02.owner", "G02.controller", "G02.culture", "G02.religion",
    "G02.autonomy", "G02.development", "G02.resource", "G02.center_of_trade",
}
ALL_G02_FIELDS = {
    "owner", "controller", "culture", "religion", "autonomy",
    "development", "resource", "center_of_trade",
}
PREVIOUS_PARTIAL_FIELDS = ("owner", "controller", "culture", "religion", "autonomy")
PROMOTED_FIELDS = ("development", "resource", "center_of_trade")
EXPECTED_CONFIGURED_FIELD_COUNTS = {"available": 62, "partial": 179, "planned": 156}
EXPECTED_CONFIGURED_TOPIC_COUNTS = {"available": 46, "partial": 4, "planned": 24}
EXPECTED_LIVE_FIELD_COUNTS = {"available": 56, "partial": 143, "planned": 198}
EXPECTED_LIVE_CALLABLE_TOPICS = 41

BUILD_MANIFEST = ROOT / (
    "work/runtime/diplomacy-observer-20261028-battle-context-v33-001/build-manifest.json"
)
INSTALLATION = ROOT / (
    "work/runtime/diplomacy-observer-20261028-battle-context-v33-001/installation.json"
)
RESEARCH_PYTHON = common.PYTHON

# These are the only batch-80 source paths allowed to differ from its freeze.
REVIEWED_BASELINE_CHANGES = {
    "bridge/information/province_state.py": "batch-81 public projection for three G02 fields",
    "bridge/information/province_detail_memory.py": "batch-81 selected province field integration",
    "bridge/information/province_state_capture.py": "batch-81 selected province capture integration",
    "bridge/tests/test_information_province_state.py": "batch-81 public projection tests",
    "bridge/tests/test_information_province_state_capture.py": "batch-81 capture integration tests",
    "docs/信息字段覆盖.json": "batch-81 G02 development/resource/center_of_trade coverage update",
}

EXTRA = (
    "bridge/information/province_development_memory.py",
    "bridge/information/province_resource_memory.py",
    "bridge/information/province_cot_memory.py",
    "bridge/tests/test_information_province_development_memory.py",
    "bridge/tests/test_information_province_resource_memory.py",
    "bridge/tests/test_information_province_cot_memory.py",
    "bridge/information/profiles/province-state-memory-1374-v3.json",
    "work/create_information_province_production_profile.py",
    "work/update_information_province_production_coverage.py",
    "work/verify_information_province_production.py",
    # The root-owned finalizer is a required source. Missing means preflight fails.
    "work/finalize_information_province_production.py",
)


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
    }


def _tail_text(path: Path, limit: int = 8192) -> str:
    path = common.workspace(path)
    size = path.stat().st_size
    with path.open("rb") as stream:
        stream.seek(max(0, size - limit))
        return stream.read(limit).decode("utf-8", errors="replace")


def baseline_inputs() -> tuple[dict, list[dict], dict, dict, dict]:
    """Verify all batch-80 snapshots, its sole full run, and reviewed deltas."""
    paths = _baseline_paths()
    frozen = read_json(paths["freeze"])
    if (frozen.get("schema") != "information.province_details.source_freeze.v1"
            or frozen.get("batch") != BASE_BATCH or frozen.get("status") != "passed"
            or frozen.get("count") != BASE_COUNT
            or frozen.get("count") != len(frozen.get("files", []))):
        raise ValueError("batch80_freeze_schema_or_count_mismatch")

    changes: list[dict] = []
    baseline_doc_snapshot = None
    for row in frozen["files"]:
        source, snapshot = row["source"], row["snapshot"]
        if pin(snapshot["path"]) != snapshot:
            raise ValueError(f"batch80_snapshot_pin_mismatch:{snapshot['path']}")
        if (source["bytes"], source["sha256"]) != (snapshot["bytes"], snapshot["sha256"]):
            raise ValueError(f"batch80_source_snapshot_pair_mismatch:{source['path']}")
        current = pin(source["path"])
        if current != source:
            if source["path"] not in REVIEWED_BASELINE_CHANGES:
                raise ValueError(f"unreviewed_batch80_source_change:{source['path']}")
            changes.append({
                "path": source["path"],
                "before": source,
                "after": current,
                "reason": REVIEWED_BASELINE_CHANGES[source["path"]],
            })
        if source["path"] == "docs/信息字段覆盖.json":
            baseline_doc_snapshot = snapshot
    if {row["path"] for row in changes} != set(REVIEWED_BASELINE_CHANGES):
        raise ValueError("batch80_reviewed_delta_set_mismatch")
    if baseline_doc_snapshot is None:
        raise ValueError("batch80_coverage_document_snapshot_missing")

    comparison = read_json(paths["comparison"])
    postverify = read_json(paths["postverify"])
    reservation = read_json(paths["reservation"])
    boundary = read_json(paths["boundary"])
    full_pin, log_pin = pin(paths["full"]), pin(paths["log"])
    if (comparison.get("schema") != "information.province_details.regression_comparison.v1"
            or comparison.get("status") != "passed_no_new_bad"
            or comparison.get("batch") != BASE_BATCH
            or comparison.get("current") != full_pin or comparison.get("log") != log_pin
            or comparison.get("baseline_bad_occurrences") != EXPECTED_BAD_OCCURRENCES
            or comparison.get("current_bad_occurrences") != EXPECTED_BAD_OCCURRENCES
            or comparison.get("new_bad") != [] or comparison.get("no_new_bad") is not True
            or comparison.get("whole_suite_passed") is not False):
        raise ValueError("batch80_comparison_mismatch")
    if (postverify.get("status") != "passed_no_new_bad"
            or postverify.get("batch") != BASE_BATCH or postverify.get("count") != BASE_COUNT
            or postverify.get("freeze") != pin(paths["freeze"])
            or postverify.get("regression_comparison") != pin(paths["comparison"])
            or postverify.get("current_sources_match_snapshots") is not True
            or postverify.get("no_new_bad") is not True):
        raise ValueError("batch80_postverify_mismatch")
    if reservation.get("runs") != 1 or reservation.get("freeze") != pin(paths["freeze"]):
        raise ValueError("batch80_full_reservation_mismatch")
    argv = reservation.get("argv", [])
    if not ("pytest" in argv and "bridge/tests" in argv and "--junitxml" in argv
            and argv[-1] == str(paths["full"])):
        raise ValueError("batch80_full_argv_mismatch")
    if (boundary.get("returncode") != comparison.get("returncode")
            or boundary.get("xml") != full_pin or boundary.get("log") != log_pin):
        raise ValueError("batch80_full_boundary_mismatch")

    bad = common.bad_cases(paths["full"])
    summary = common.junit_summary(paths["full"])
    if sum(bad.values()) != EXPECTED_BAD_OCCURRENCES:
        raise ValueError("batch80_full_bad_counter_mismatch")
    if summary != EXPECTED_BASELINE_SUMMARY or comparison.get("junit_summary") != summary:
        raise ValueError("batch80_full_junit_summary_mismatch")
    terminal = _tail_text(paths["log"])
    if EXPECTED_BASELINE_TERMINAL not in terminal:
        raise ValueError("batch80_full_terminal_summary_mismatch")

    build = common.manifest_inputs(BUILD_MANIFEST)
    common.validate_build_inheritance(frozen, build)
    baseline_pins = {name: pin(path) for name, path in paths.items()}
    baseline_pins["coverage_update"] = pin(BASE / "coverage-update-001.json")
    return frozen, changes, build, baseline_pins, baseline_doc_snapshot


def _profile_inputs() -> tuple[dict, dict]:
    receipt_path = STAGE / "province-profile-build-001.json"
    receipt = read_json(receipt_path)
    if receipt.get("status") != "created" or receipt.get("game_reads") is not False \
            or receipt.get("game_controls") is not False:
        raise ValueError("province_profile_build_not_offline_created")
    profile_pin = receipt.get("profile")
    if not isinstance(profile_pin, dict) or pin(profile_pin.get("path", "")) != profile_pin:
        raise ValueError("province_v3_profile_pin_mismatch")
    profile = read_json(profile_pin["path"])
    if profile.get("profile_version") != 3 or profile.get("game_version") != "1.37.4":
        raise ValueError("province_profile_version_mismatch")
    supported = profile.get("semantics", {}).get("supported_fields")
    if (not isinstance(supported, list) or len(supported) != 8
            or set(supported) != EXPECTED_PROFILE_FIELDS):
        raise ValueError("province_profile_supported_field_set_mismatch")
    if profile_pin["path"] != "bridge/information/profiles/province-state-memory-1374-v3.json":
        raise ValueError("province_v3_profile_path_mismatch")
    return pin(receipt_path), profile_pin


def _capture_ref_pin(row: object, label: str) -> dict:
    if not isinstance(row, dict) or not {"path", "bytes", "sha256"}.issubset(row):
        raise ValueError(f"{label}_capture_pin_invalid")
    if pin(row["path"]) != row:
        raise ValueError(f"{label}_capture_pin_mismatch")
    return row


def _audit_pin_rows(audit: dict) -> dict[str, dict]:
    rows = audit.get("input_pins")
    if not isinstance(rows, list):
        raise ValueError("independent_audit_input_pins_missing")
    result = {}
    for row in rows:
        if not isinstance(row, dict) or "path" not in row:
            raise ValueError("independent_audit_input_pin_invalid")
        path = row["path"]
        if path in result:
            raise ValueError(f"independent_audit_duplicate_input_pin:{path}")
        if pin(path) != row:
            raise ValueError(f"independent_audit_input_changed:{path}")
        result[path] = row
    return result


def _check_identity_row(row: dict, installation: dict, province_id: int,
                        positive: bool, label: str) -> None:
    if (row.get("province_id") != province_id or row.get("raw_replay_valid") is not True
            or row.get("pid") != installation.get("pid")
            or row.get("creation_filetime") != installation.get("creation_filetime")
            or row.get("session_id") != installation.get("session_id")
            or row.get("date") != 56564448 or row.get("physical_player") != "POR"
            or row.get("observer_role") != {"human_count": 1, "FRA_controller_type": 0}):
        raise ValueError(f"{label}_identity_or_replay_mismatch:{province_id}")
    expected_discovery = {"pass1": positive, "pass2": positive}
    if row.get("discovery_by_pass") != expected_discovery:
        raise ValueError(f"{label}_discovery_mismatch:{province_id}")
    statuses = row.get("field_statuses")
    if not isinstance(statuses, dict) or set(statuses) != {name.removeprefix("G02.") for name in EXPECTED_PROFILE_FIELDS}:
        raise ValueError(f"{label}_field_status_set_mismatch:{province_id}")
    if (any(value not in {"known", "unknown"} for value in statuses.values())
            or (not positive and any(value != "unknown" for value in statuses.values()))):
        raise ValueError(f"{label}_field_status_mismatch:{province_id}")


def acceptance_inputs(profile_pin: dict, build: dict) -> dict:
    """Bind the raw samples, MCP closure, profile, and independent audit."""
    installation = read_json(INSTALLATION)
    if (installation.get("game_sha256") != "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
            or installation.get("dll_sha256") != build["dll"]["sha256"]):
        raise ValueError("v33_installation_identity_mismatch")

    private_path = STAGE / "private-live-probe-001.json"
    negative_path = STAGE / "private-discovery-negative-001.json"
    zero_path = STAGE / "private-center-zero-001.json"
    mcp_path = STAGE / "mcp-live-001/receipt.json"
    audit_path = STAGE / "independent-live-audit-003.json"
    private, negative, zero = (
        read_json(private_path), read_json(negative_path), read_json(zero_path))
    mcp, audit = read_json(mcp_path), read_json(audit_path)
    if (private.get("status") != "passed" or private.get("observer") != "FRA"
            or private.get("game_controls") is not False
            or private.get("native_function_invoked") is not False):
        raise ValueError("private_positive_probe_not_passed")
    objects = private.get("objects")
    if not isinstance(objects, dict) or set(objects) != {"183", "184", "236"}:
        raise ValueError("private_positive_object_set_mismatch")
    positive_capture_pins = {}
    for province_id in (183, 184, 236):
        item = objects[str(province_id)]
        if item.get("status") != "passed":
            raise ValueError(f"private_positive_object_not_passed:{province_id}")
        positive_capture_pins[province_id] = _capture_ref_pin(
            item.get("capture"), f"private_{province_id}")
    if (negative.get("status") != "passed_negative"
            or negative.get("game_controls") is not False
            or negative.get("native_function_invoked") is not False
            or negative.get("field_data_reads") != 0):
        raise ValueError("private_negative_discovery_case_mismatch")
    negative_capture_pin = _capture_ref_pin(negative.get("capture"), "private_2000")
    zero_values = zero.get("values", {})
    zero_access = zero.get("access", {})
    if (zero.get("status") != "passed_zero" or zero.get("province_id") != 185
            or zero.get("game_controls") is not False
            or zero.get("native_function_invoked") is not False
            or zero.get("center_definition_reads") != 0
            or zero.get("context", {}).get("game_date") != 56564448
            or zero_access.get("read_only") is not True
            or zero_access.get("writes") is not False
            or zero_access.get("UI_control") is not False
            or zero_access.get("date_advance") is not False
            or zero_access.get("save_or_reload") is not False
            or zero_access.get("native_function_invoked") is not False
            or zero_values.get("G02.center_of_trade") != {"present": False, "level": 0}):
        raise ValueError("private_center_zero_receipt_mismatch")
    zero_capture_pin = _capture_ref_pin(zero.get("capture"), "private_center_zero_185")

    if (mcp.get("status") != "passed" or mcp.get("server_exit_code") != 0
            or mcp.get("source_pins_unchanged") is not True
            or mcp.get("checks", {}).get("no_active_subscriptions") is not True):
        raise ValueError("mcp_live_receipt_not_closed_cleanly")
    if (audit.get("status") != "passed" or audit.get("inputs_unchanged_during_audit") is not True
            or audit.get("issues") != []):
        raise ValueError("independent_live_audit_not_passed")

    audit_checks = audit.get("checks", {})
    raw_replay_count=audit_checks.get('all_raw_captures_replayed')
    if (type(raw_replay_count) is not int
            or raw_replay_count != 5+audit_checks.get('mcp_capture_replay_count',-1)
            or audit_checks.get("private_capture_replay_count") != 5
            or audit_checks.get("query_report_periodic_deep_field_equality") is not True
            or audit_checks.get("manual_list_results_deduplicated_against_query_report") is not True):
        raise ValueError("independent_live_capture_or_delivery_checks_mismatch")
    check_identity = audit_checks.get("installation_manifest_dll_profile_and_source_pins", {})
    if (check_identity.get("installation") != pin(INSTALLATION)
            or check_identity.get("manifest") != build["manifest"]
            or check_identity.get("dll") != build["dll"]
            or check_identity.get("profile") != profile_pin
            or check_identity.get("manifest_source_count") != 125):
        raise ValueError("independent_live_build_profile_binding_mismatch")

    private_rows = audit.get("private_captures")
    mcp_rows = audit.get("mcp_captures")
    if not isinstance(private_rows, list) or not isinstance(mcp_rows, list):
        raise ValueError("independent_live_capture_rows_missing")
    if len(private_rows) != 5:
        raise ValueError("independent_private_capture_row_count_mismatch")
    expected_private_ids = Counter({183: 1, 184: 1, 185: 1, 236: 1, 2000: 1})
    if Counter(row.get("province_id") for row in private_rows) != expected_private_ids:
        raise ValueError("independent_private_province_distribution_mismatch")

    audited_pins = _audit_pin_rows(audit)
    for row in private_rows + mcp_rows:
        province_id = row["province_id"]
        positive = province_id != 2000
        _check_identity_row(row, installation, province_id, positive, "capture")
        if (province_id == 185
                and row.get("field_statuses", {}).get("center_of_trade") != "known"):
            raise ValueError("private_center_zero_not_known_in_capture")
        raw_pin = pin(row["path"])
        if raw_pin["sha256"] != row.get("file_sha256"):
            raise ValueError(f"audited_capture_file_hash_mismatch:{row['path']}")
        if audited_pins.get(raw_pin["path"]) != raw_pin:
            raise ValueError(f"raw_capture_not_pinned_by_audit:{row['path']}")

    direct_private = {row["province_id"]: row for row in private_rows}
    for province_id, capture_pin in positive_capture_pins.items():
        audit_row = direct_private[province_id]
        if (capture_pin["path"] != audit_row["path"]
                or capture_pin["sha256"] != audit_row["file_sha256"]):
            raise ValueError(f"private_capture_audit_association_mismatch:{province_id}")
    audit_negative = direct_private[2000]
    if (negative_capture_pin["path"] != audit_negative["path"]
            or negative_capture_pin["sha256"] != audit_negative["file_sha256"]):
        raise ValueError("private_negative_capture_audit_association_mismatch")
    audit_zero = direct_private[185]
    if (zero_capture_pin["path"] != audit_zero["path"]
            or zero_capture_pin["sha256"] != audit_zero["file_sha256"]):
        raise ValueError("private_center_zero_capture_audit_association_mismatch")

    delivery = audit.get("public_delivery", {})
    delivery_counts = delivery.get("delivery_counts", delivery)
    intervals = delivery_counts.get("periodic_counts_by_interval", {})
    normalized_intervals = {str(key): value for key, value in intervals.items()}
    if (normalized_intervals.get("2", 0) < 2 or normalized_intervals.get("5", 0) < 1
            or any(type(value) is not int or value < 0 for value in normalized_intervals.values())):
        raise ValueError("independent_live_periodic_schedule_mismatch")
    expected_per_target = 2 + sum(normalized_intervals.values())
    expected_mcp_count = 4 * expected_per_target
    expected_mcp_ids = Counter({province_id: expected_per_target
                                for province_id in (183, 185, 236, 2000)})
    if (len(mcp_rows) != expected_mcp_count
            or Counter(row.get("province_id") for row in mcp_rows) != expected_mcp_ids
            or audit_checks.get("mcp_capture_replay_count") != expected_mcp_count
            or audit_checks.get("all_mcp_capture_sha_associations") != expected_mcp_count):
        raise ValueError("independent_mcp_capture_distribution_mismatch")
    if type(raw_replay_count) is not int or raw_replay_count != 5+expected_mcp_count:
        raise ValueError("independent_raw_capture_replay_incomplete")
    for field in PROMOTED_FIELDS:
        if not any(row.get("field_statuses", {}).get(field) == "known"
                   for row in private_rows + mcp_rows if row.get("province_id") != 2000):
            raise ValueError(f"promoted_field_has_no_positive_capture:{field}")

    for item_path in (private_path, negative_path, zero_path, mcp_path):
        row = pin(item_path)
        if audited_pins.get(row["path"]) != row:
            raise ValueError(f"audit_did_not_pin_acceptance_receipt:{row['path']}")

    if (delivery_counts.get("unique_nonmanual_capture_province_objects") != expected_mcp_count
            or delivery_counts.get("manual_copy_rows") != 2):
        raise ValueError("independent_live_manual_or_capture_count_mismatch")

    return {
        "installation": pin(INSTALLATION),
        "private_positive_report": pin(private_path),
        "private_negative_report": pin(negative_path),
        "private_center_zero_report": pin(zero_path),
        "private_capture_pins": [positive_capture_pins[k] for k in (183, 184, 236)]
        + [zero_capture_pin, negative_capture_pin],
        "mcp_receipt": pin(mcp_path),
        "independent_audit": pin(audit_path),
        "audited_private_capture_count": len(private_rows),
        "audited_mcp_capture_count": len(mcp_rows),
        "periodic_counts_by_interval": normalized_intervals,
        "profile": profile_pin,
    }


def coverage_inputs(baseline_doc_snapshot: dict) -> tuple[dict, dict, dict]:
    """Require only the three intended G02 promotions and preserve 73 topics."""
    update_path = STAGE / "coverage-update-001.json"
    update = read_json(update_path)
    before_doc = read_json(baseline_doc_snapshot["path"])
    current_doc = read_json(ROOT / "docs/信息字段覆盖.json")
    current_doc_pin = pin(ROOT / "docs/信息字段覆盖.json")
    expected_changes = {f"G02.{name}": ["planned", "partial"] for name in PROMOTED_FIELDS}
    if (update.get("status") != "updated_partial" or update.get("goal_complete") is not False
            or update.get("before_sha256") != baseline_doc_snapshot["sha256"]
            or update.get("after_sha256") != current_doc_pin["sha256"]
            or update.get("coverage_changes") != expected_changes):
        raise ValueError("province_coverage_update_receipt_mismatch")
    if update.get("scope") is None:
        raise ValueError("province_coverage_update_scope_missing")

    old_topics = {row["topic_id"]: row for row in before_doc["topics"]}
    new_topics = {row["topic_id"]: row for row in current_doc["topics"]}
    if (len(old_topics) != 74 or len(new_topics) != 74 or set(old_topics) != set(new_topics)):
        raise ValueError("province_coverage_topic_set_mismatch")
    for topic_id in old_topics.keys() - {"G02"}:
        if new_topics[topic_id] != old_topics[topic_id]:
            raise ValueError(f"unrelated_coverage_topic_changed:{topic_id}")

    old_g02, new_g02 = old_topics["G02"], new_topics["G02"]
    if set(old_g02["fields"]) != ALL_G02_FIELDS or set(new_g02["fields"]) != ALL_G02_FIELDS:
        raise ValueError("province_g02_field_set_mismatch")
    for field in PREVIOUS_PARTIAL_FIELDS:
        if (old_g02["fields"][field].get("coverage") != "partial"
                or new_g02["fields"][field] != old_g02["fields"][field]):
            raise ValueError(f"previous_partial_field_changed:{field}")
    for field in PROMOTED_FIELDS:
        before, after = old_g02["fields"][field], new_g02["fields"][field]
        if (before.get("coverage") != "planned" or after.get("coverage") != "partial"
                or after.get("complete") is not False):
            raise ValueError(f"province_field_promotion_mismatch:{field}")
    if any(field.get("coverage") == "planned" for field in new_g02["fields"].values()):
        raise ValueError("province_g02_still_has_planned_field")

    for key in old_g02:
        if key not in {"fields", "source", "scope_note"} and new_g02.get(key) != old_g02[key]:
            raise ValueError(f"unreviewed_g02_topic_metadata_change:{key}")
    discovery_path = STAGE / "mcp-live-001/discovery.json"
    discovery = read_json(discovery_path)
    discovery_g02 = next(row for row in discovery["topics"] if row.get("topic_id") == "G02")
    if new_g02 != discovery_g02:
        raise ValueError("province_g02_topic_differs_from_same_mcp_discovery")

    if set(current_doc.get("G02", {})) != set(before_doc.get("G02", {})):
        raise ValueError("province_g02_compact_key_set_changed")
    expected_compact={key:deepcopy(new_g02[key]) for key in before_doc['G02']}
    if current_doc["G02"] != expected_compact:
        raise ValueError("province_g02_compact_row_mismatch")
    if (current_doc["configuration"]["adapters"] != before_doc["configuration"]["adapters"]
            or len(current_doc["configuration"]["adapters"]) != 20):
        raise ValueError("province_adapter_configuration_changed")

    configured = common.coverage_counts(current_doc["topics"])
    if (configured["topic_count"] != 74 or configured["field_count"] != 397
            or configured["field_counts"] != EXPECTED_CONFIGURED_FIELD_COUNTS
            or configured["topic_status_counts"] != EXPECTED_CONFIGURED_TOPIC_COUNTS
            or configured["callable_topic_count"] != 46):
        raise ValueError("province_configured_coverage_counts_mismatch")
    if update.get("configured_counts") != configured or current_doc.get("counts") != configured \
            or current_doc.get("expected_counts") != configured:
        raise ValueError("province_configured_coverage_count_receipt_mismatch")

    actual = update.get("actual_live_counts", {})
    if (actual.get("topic_count") != 74 or actual.get("field_count") != 397
            or actual.get("field_counts") != EXPECTED_LIVE_FIELD_COUNTS
            or actual.get("callable_topic_count") != EXPECTED_LIVE_CALLABLE_TOPICS):
        raise ValueError("province_actual_live_coverage_counts_mismatch")
    if current_doc.get("goal_complete") is not False:
        raise ValueError("province_coverage_goal_incorrectly_marked_complete")

    expected_doc = deepcopy(before_doc)
    index = next(i for i, row in enumerate(expected_doc["topics"]) if row["topic_id"] == "G02")
    expected_doc["topics"][index] = deepcopy(new_g02)
    expected_doc["G02"] = expected_compact
    expected_doc["counts"] = configured
    expected_doc["expected_counts"] = deepcopy(configured)
    expected_doc["goal_complete"] = False
    assert current_doc == expected_doc
    return update, current_doc, {
        "coverage_update": pin(update_path),
        "coverage_document": current_doc_pin,
        "discovery": pin(discovery_path),
        "configured_counts": configured,
        "actual_live_counts": actual,
    }


def source_paths(frozen: dict, build: dict) -> list[str]:
    stage_scripts = [
        path.relative_to(ROOT).as_posix()
        for path in STAGE.rglob("*.py")
        if not any(part == "__pycache__" or part.startswith("source-snapshots-")
                   for part in path.parts)
    ]
    paths = {row["source"]["path"] for row in frozen["files"]}
    paths.update(EXTRA)
    paths.update(stage_scripts)
    paths.update(build["native"])
    paths.update(build["copies"])
    return sorted(paths)


def preflight(check_outputs: bool = True) -> dict:
    frozen, changes, build, baseline_pins, baseline_doc_snapshot = baseline_inputs()
    profile_build_pin, profile_pin = _profile_inputs()
    acceptance = acceptance_inputs(profile_pin, build)
    update, current_doc, coverage_pins = coverage_inputs(baseline_doc_snapshot)
    paths = source_paths(frozen, build)
    missing = [name for name in paths if not (ROOT / name).is_file()]
    if missing:
        raise FileNotFoundError(f"province81_required_source_missing:{missing}")
    if not RESEARCH_PYTHON.is_file():
        raise FileNotFoundError(f"research_python_missing:{RESEARCH_PYTHON}")
    reserved = [
        STAGE / f"source-freeze-{REVISION}.json",
        STAGE / f"regression-full-{REVISION}.xml",
        STAGE / f"regression-full-{REVISION}.log",
        STAGE / f"full-execution-reservation-{REVISION}.json",
        STAGE / f"full-execution-boundary-{REVISION}.json",
        STAGE / f"regression-comparison-{REVISION}.json",
        STAGE / f"source-post-run-verification-{REVISION}.json",
        STAGE / f"source-snapshots-{REVISION}",
    ]
    if check_outputs and any(path.exists() for path in reserved):
        raise FileExistsError(f"province81_revision_{REVISION}_already_used")
    return {
        "baseline_freeze": frozen,
        "baseline_reviewed_deltas": changes,
        "baseline_pins": baseline_pins,
        "build": build,
        "profile_build": profile_build_pin,
        "profile": profile_pin,
        "acceptance": acceptance,
        "coverage_update": update,
        "coverage_document": current_doc,
        "coverage_pins": coverage_pins,
        "sources": paths,
    }


def freeze() -> dict:
    ready = preflight(check_outputs=True)
    snapshot_dir = STAGE / f"source-snapshots-{REVISION}"
    target = STAGE / f"source-freeze-{REVISION}.json"
    originals = {name: pin(name) for name in ready["sources"]}
    snapshot_dir.mkdir(parents=True, exist_ok=False)
    rows = []
    for name in ready["sources"]:
        snapshot = (snapshot_dir / Path(name)).resolve()
        snapshot.relative_to(snapshot_dir.resolve())
        copy_stream(name, snapshot)
        copied = pin(snapshot)
        if copied["sha256"] != originals[name]["sha256"] or pin(name) != originals[name]:
            raise RuntimeError(f"source_changed_during_freeze:{name}")
        rows.append({"source": originals[name], "snapshot": copied})
    value = {
        "schema": "information.province_production.source_freeze.v1",
        "batch": 81,
        "revision": REVISION,
        "status": "passed",
        "count": len(rows),
        "files": rows,
        "baseline_freeze": pin(BASE / "source-freeze-001.json"),
        "baseline_reviewed_deltas": ready["baseline_reviewed_deltas"],
        "baseline_pins": ready["baseline_pins"],
        "build_manifest": ready["build"]["manifest"],
        "build_dll": ready["build"]["dll"],
        "manifest_native_source_count": len(ready["build"]["native"]),
        "manifest_native_sources": ready["build"]["native"],
        "manifest_build_copies": ready["build"]["copies"],
        "manifest_source_names": ready["build"]["names"],
        "profile_build": ready["profile_build"],
        "profile": ready["profile"],
        "acceptance": ready["acceptance"],
        "coverage_update": ready["coverage_pins"]["coverage_update"],
        "coverage_document": ready["coverage_pins"]["coverage_document"],
        "coverage_discovery": ready["coverage_pins"]["discovery"],
        "configured_counts": ready["coverage_pins"]["configured_counts"],
        "actual_live_counts": ready["coverage_pins"]["actual_live_counts"],
        "created_at": common.stamp(),
    }
    write_new(target, value)
    result = {"status": "passed", "phase": "freeze", "count": len(rows),
              "freeze": pin(target)}
    print(json.dumps(result, ensure_ascii=False))
    return result


def verify_sources() -> dict:
    frozen = read_json(STAGE / f"source-freeze-{REVISION}.json")
    if (frozen.get("schema") != "information.province_production.source_freeze.v1"
            or frozen.get("batch") != 81 or frozen.get("revision") != REVISION
            or frozen.get("status") != "passed"):
        raise ValueError("province81_source_freeze_invalid")
    ready = preflight(check_outputs=False)
    if frozen.get("baseline_freeze") != pin(BASE / "source-freeze-001.json"):
        raise ValueError("batch80_freeze_pin_changed")
    for key, ready_key in (
        ("baseline_reviewed_deltas", "baseline_reviewed_deltas"),
        ("baseline_pins", "baseline_pins"),
        ("build_manifest", None), ("build_dll", None),
        ("manifest_native_sources", None), ("manifest_build_copies", None),
        ("manifest_source_names", None), ("profile_build", "profile_build"),
        ("profile", "profile"), ("acceptance", "acceptance"),
    ):
        if ready_key is not None:
            expected = ready[ready_key]
        elif key == "build_manifest":
            expected = ready["build"]["manifest"]
        elif key == "build_dll":
            expected = ready["build"]["dll"]
        elif key == "manifest_native_sources":
            expected = ready["build"]["native"]
        elif key == "manifest_build_copies":
            expected = ready["build"]["copies"]
        else:
            expected = ready["build"]["names"]
        if frozen.get(key) != expected:
            raise ValueError(f"province81_freeze_{key}_changed")
    if frozen.get("manifest_native_source_count") != 125:
        raise ValueError("v33_source_count_changed")
    if (frozen.get("coverage_update") != ready["coverage_pins"]["coverage_update"]
            or frozen.get("coverage_document") != ready["coverage_pins"]["coverage_document"]
            or frozen.get("coverage_discovery") != ready["coverage_pins"]["discovery"]
            or frozen.get("configured_counts") != ready["coverage_pins"]["configured_counts"]
            or frozen.get("actual_live_counts") != ready["coverage_pins"]["actual_live_counts"]):
        raise ValueError("province81_coverage_inputs_changed")
    expected_paths = ready["sources"]
    if (sorted(row["source"]["path"] for row in frozen.get("files", [])) != expected_paths
            or frozen.get("count") != len(expected_paths)
            or frozen.get("count") != len(frozen.get("files", []))):
        raise ValueError("province81_source_union_changed")
    for row in frozen["files"]:
        if pin(row["source"]["path"]) != row["source"]:
            raise ValueError(f"province81_current_source_changed:{row['source']['path']}")
        if pin(row["snapshot"]["path"]) != row["snapshot"]:
            raise ValueError(f"province81_snapshot_changed:{row['snapshot']['path']}")
        if (row["source"]["bytes"], row["source"]["sha256"]) != (
                row["snapshot"]["bytes"], row["snapshot"]["sha256"]):
            raise ValueError(f"province81_source_snapshot_mismatch:{row['source']['path']}")
    return frozen


def full() -> int:
    frozen = verify_sources()
    xml = STAGE / f"regression-full-{REVISION}.xml"
    log = STAGE / f"regression-full-{REVISION}.log"
    reservation = STAGE / f"full-execution-reservation-{REVISION}.json"
    boundary = STAGE / f"full-execution-boundary-{REVISION}.json"
    comparison_path = STAGE / f"regression-comparison-{REVISION}.json"
    postverify_path = STAGE / f"source-post-run-verification-{REVISION}.json"
    if any(path.exists() for path in (xml, log, reservation, boundary,
                                      comparison_path, postverify_path)):
        raise FileExistsError(f"province81_full_{REVISION}_already_started")
    argv = [str(RESEARCH_PYTHON), "-B", "-m", "pytest", "-q", "bridge/tests",
            "--junitxml", str(xml)]
    write_new(reservation, {
        "runs": 1,
        "argv": argv,
        "freeze": pin(STAGE / f"source-freeze-{REVISION}.json"),
        "started_at": common.stamp(),
    })
    with log.open("xb") as stream:
        result = subprocess.run(argv, cwd=ROOT, stdout=stream,
                                stderr=subprocess.STDOUT, check=False)
    write_new(boundary, {
        "returncode": result.returncode,
        "log": pin(log),
        "xml": pin(xml),
        "finished_at": common.stamp(),
    })

    verify_sources()
    old = common.bad_cases(BASE / "regression-full-001.xml")
    new = common.bad_cases(xml)
    added, resolved = new - old, old - new
    value = {
        "schema": "information.province_production.regression_comparison.v1",
        "status": "passed_no_new_bad" if not added else "failed_new_bad",
        "batch": 81,
        "baseline": pin(BASE / "regression-full-001.xml"),
        "current": pin(xml),
        "log": pin(log),
        "baseline_bad_occurrences": sum(old.values()),
        "current_bad_occurrences": sum(new.values()),
        "new_bad": common.counter_rows(added),
        "resolved_bad": common.counter_rows(resolved),
        "no_new_bad": not added,
        "whole_suite_passed": result.returncode == 0,
        "returncode": result.returncode,
        "junit_summary": common.junit_summary(xml),
    }
    write_new(comparison_path, value)
    write_new(postverify_path, {
        "status": value["status"],
        "batch": 81,
        "count": frozen["count"],
        "freeze": pin(STAGE / f"source-freeze-{REVISION}.json"),
        "regression_comparison": pin(comparison_path),
        "current_sources_match_snapshots": True,
        "no_new_bad": not added,
        "whole_suite_passed": result.returncode == 0,
    })
    print(json.dumps(value, ensure_ascii=False))
    return 0 if not added else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("freeze", "verify", "full"))
    args = parser.parse_args(argv)
    if args.operation == "freeze":
        freeze()
        return 0
    if args.operation == "verify":
        frozen = verify_sources()
        print(json.dumps({"status": "passed", "count": frozen["count"]}))
        return 0
    return full()


if __name__ == "__main__":
    raise SystemExit(main())
