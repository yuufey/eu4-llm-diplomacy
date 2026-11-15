"""Archive batch 69 military-resources evidence without touching live state.

The default invocation is inert.  ``--run`` is the only entry point that may
create the exclusive archive and it is deliberately fail-closed: dynamic
source-freeze/post-run pins, the unchanged batch-68 archive, build identity,
the prepared-but-never-enabled battle source, the successful live acceptance
report, an explicitly linked external B04 recipient audit, and fresh immutable
SQLite snapshots must all validate first.

The archive copies only bounded build/document artifacts.  The large shared
checkpoint is pinned in place and is never copied.  The independently authored
B04 recipient audit remains at its original stage; a separately named related
source snapshot is mapped to that original path in the manifest. Working SQLite
files and WAL/SHM sidecars remain outside the ordinary artifact manifest; a
fresh backup is verified with ``mode=ro&immutable=1`` and every connection is
closed by the imported archive helper.  No game, MCP, native query, REA,
test, or RPM action is performed by this module.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any

from archive_information_war_score import (  # type: ignore[import-not-found]
    ArchiveError,
    backup_sqlite,
    copy_new,
    display_path,
    pin,
    read_json,
    require,
    stream_sha256,
    write_new,
)


ROOT = Path(__file__).resolve().parents[1]
STAGE = (
    ROOT / "work/runtime/information-country-force-resources-20261027-001"
).resolve()
OLD68 = (ROOT / "work/runtime/information-country-forces-20261027-001").resolve()
BUILD = (
    ROOT / "work/runtime/diplomacy-observer-20261028-information-resources-v30-005"
).resolve()

ARCHIVE = STAGE / "archive-verification-001.json"
SELF_READBACK = STAGE / "archive-self-readback-001.json"
RUNTIME_VERIFICATION = STAGE / "runtime-archive-verification-001.json"
DATABASE_VERIFICATION = STAGE / "database-snapshot-verification-001.json"
DOCUMENT_VERIFICATION = STAGE / "document-verification-001.json"

OLD68_ARCHIVE = OLD68 / "archive-verification-001.json"
OLD68_SELF_READBACK = OLD68 / "archive-self-readback-001.json"
OLD68_FINAL_READBACK = OLD68 / "final-readback-001.json"

SOURCE_REVISION = "004"
REGRESSION_REVISION = "004"
LIVE_REVISION = "003"
SOURCE_FREEZE = STAGE / f"source-freeze-{SOURCE_REVISION}.json"
SOURCE_POST_RUN_CANDIDATES = (
    STAGE / f"source-post-run-verification-{SOURCE_REVISION}.json",
    STAGE / f"source-freeze-postverify-{SOURCE_REVISION}.json",
)
HISTORICAL_SOURCE_EQUIVALENCE = STAGE / "source-equivalence-002-to-003.json"
FULL_EXECUTION_BOUNDARY = STAGE / f"full-execution-boundary-{REGRESSION_REVISION}.json"
SUMMARY = STAGE / "development-summary-001.json"
LIVE_REPORT = STAGE / f"live-acceptance-{LIVE_REVISION}" / "report.json"
HISTORICAL_LIVE_REPORT_002 = STAGE / "live-acceptance-002" / "report.json"
RECIPIENT_LINK = (
    STAGE / "battle-native-recipient-001" /
    "battle-native-recipient-evidence-link-001.json"
)
RELATED_SOURCE_SNAPSHOT_ROOT = STAGE / "related-source-snapshots-001"
RELATED_SOURCE_VERIFICATION = STAGE / "related-source-verification-001.json"
RECOVERY_AMENDMENT = (
    STAGE / "archive-helper-review-001" /
    "archive-helper-recovery-amendment-003.json"
)
PUBLICATION_HELPER_SNAPSHOT = (
    STAGE / "publication-helper-snapshots-003" /
    "work/archive_information_military_resources.py"
)

HASH_CHUNK_BYTES = 1024 * 1024
COPY_LIMIT_BYTES = 16 * 1024 * 1024
LARGE_CHECKPOINT_BYTES = COPY_LIMIT_BYTES
BATCH = 69
BATCH_MARKER_RE = re.compile(r"<!-- batch69-[^:]+:start -->")

EXPECTED_PID = 27716
EXPECTED_CREATION_FILETIME = 134376348223436218
EXPECTED_SESSION_ID = "27716-1dd6693a61275ba"
EXPECTED_DATE_RAW = 56562768
EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
EXPECTED_INSTALLATION_SHA256 = (
    "8669d71cfcf351ba7b53b394414930886002afac217efdbffab2f1c4f951d21b"
)
EXPECTED_BUILD_MANIFEST_SHA256 = (
    "753e456808fec521600a9ded95a6151e6a0e492a3577558d9c97e7ec139408a2"
)
EXPECTED_DLL_SHA256 = (
    "92fa4ea3b158e2ff42a69bce1cbbf7053b7f3a0ac128b25c9e5b7d1fb4bdc3ce"
)
RECIPIENT_AUDIT_OLD_PID = 42960
RECIPIENT_AUDIT_OLD_CREATION_FILETIME = 134375854500787403
RECIPIENT_AUDIT_OLD_SESSION_ID = "42960-1dd6620b1e8b4cb"

BUILD_REQUIRED = (
    "installation.json",
    "build-manifest.json",
    "eu4_bridge_diplomacy_observer_v30.dll",
    "information-battle-status.json",
    "control-probe.jsonl",
)
BATTLE_ABSENT_FILES = (
    "information-battle-binding.json",
    "information-battle-capture-journal.json",
    "information-battle-raw.jsonl",
)

DOCUMENTS = (
    "HANDOFF.md",
    "README(agent).md",
    "docs/信息导出与订阅开发计划.md",
    "docs/本国现存军队只读接口.md",
    "docs/本国水手与军队上限只读接口.md",
    "docs/信息字段覆盖.json",
)
MARKER_DOCUMENTS = {"HANDOFF.md", "README(agent).md", "docs/信息导出与订阅开发计划.md"}

EXCLUDED_MANIFEST_NAMES = {
    ARCHIVE.name,
    SELF_READBACK.name,
}

RECIPIENT_ORIGINAL_STAGE = (
    ROOT / "work/runtime/information-battle-native-recipient-20261027-001"
).resolve()


def _workspace_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def _external_pin(path: Path) -> dict[str, Any]:
    require(path.is_file(), f"missing_external_file:{path}")
    size, digest = stream_sha256(path)
    return {"path": path.resolve().as_posix(), "bytes": size, "sha256": digest}


def _top_marker(path: Path) -> str | None:
    try:
        with path.open("r", encoding="utf-8-sig") as stream:
            for _ in range(80):
                line = stream.readline()
                if not line:
                    break
                candidate = line.strip()
                if BATCH_MARKER_RE.fullmatch(candidate):
                    return candidate
    except (OSError, UnicodeError) as exc:
        raise ArchiveError(f"document_read_failed:{display_path(path)}:{exc}") from exc
    return None


def _first_existing(paths: tuple[Path, ...], reason: str) -> Path:
    for path in paths:
        if path.is_file():
            return path
    raise ArchiveError(reason)


def validate_source_freeze() -> dict[str, Any]:
    freeze = read_json(SOURCE_FREEZE)
    require(str(freeze.get("schema", "")).endswith(".source_freeze.v1"),
            "source_freeze_schema")
    require(freeze.get("status") == "passed", "source_freeze_not_passed")
    require(freeze.get("batch") == BATCH, "source_freeze_batch")
    require(freeze.get("hash_chunk_bytes") == HASH_CHUNK_BYTES,
            "source_freeze_hash_chunk")
    count = freeze.get("count")
    require(type(count) is int and count > 0, "source_freeze_dynamic_count")
    files = freeze.get("files")
    require(isinstance(files, list) and len(files) == count, "source_freeze_files")
    amendment = read_json(RECOVERY_AMENDMENT)
    helper_path = "work/archive_information_military_resources.py"
    require(amendment.get("status") == "passed"
            and amendment.get("batch") == BATCH,
            "recovery_amendment_status")
    require(amendment.get("changed_source_paths") == [helper_path]
            and amendment.get("production_or_tests_changed") is False,
            "recovery_amendment_scope")
    require(isinstance(amendment.get("reason"), str)
            and "checkpoint" in amendment["reason"].lower()
            and "archive" in amendment["reason"].lower(),
            "recovery_amendment_reason")
    amendment_snapshot = amendment.get("snapshot")
    amendment_after = amendment.get("after")
    require(isinstance(amendment_snapshot, dict)
            and isinstance(amendment_after, dict)
            and amendment_snapshot.get("path") == display_path(PUBLICATION_HELPER_SNAPSHOT)
            and pin(PUBLICATION_HELPER_SNAPSHOT) == amendment_snapshot,
            "recovery_amendment_snapshot_pin")
    require(amendment_after.get("bytes") == amendment_snapshot.get("bytes")
            and amendment_after.get("sha256") == amendment_snapshot.get("sha256"),
            "recovery_amendment_snapshot_content")
    seen: set[str] = set()
    unchanged_count = 0
    amended_helper: dict[str, Any] | None = None
    for item in files:
        require(isinstance(item, dict), "source_freeze_entry")
        expected_source = item.get("source")
        expected_snapshot = item.get("snapshot")
        require(isinstance(expected_source, dict) and isinstance(expected_snapshot, dict),
                "source_freeze_pins")
        source_name = str(expected_source.get("path", ""))
        snapshot_name = str(expected_snapshot.get("path", ""))
        require(source_name and source_name not in seen,
                f"duplicate_source_freeze:{source_name}")
        seen.add(source_name)
        source = _workspace_path(source_name)
        snapshot = _workspace_path(snapshot_name)
        current_source = pin(source)
        require(pin(snapshot) == expected_snapshot,
                f"runtime_snapshot_changed:{snapshot_name}")
        require(expected_source.get("bytes") == expected_snapshot.get("bytes")
                and expected_source.get("sha256") == expected_snapshot.get("sha256"),
                f"source_snapshot_hash_mismatch:{source_name}")
        if source_name == helper_path:
            require(amendment.get("before") == expected_source,
                    "recovery_amendment_before_pin_mismatch")
            require(amendment.get("frozen_snapshot") == expected_snapshot,
                    "recovery_amendment_frozen_snapshot_mismatch")
            require(amendment.get("after") == current_source
                    and current_source["path"] == helper_path
                    and current_source != expected_source,
                    "recovery_amendment_after_pin_mismatch")
            amended_helper = {
                "path": helper_path,
                "before": expected_source,
                "frozen_snapshot": expected_snapshot,
                "after": current_source,
            }
        else:
            require(current_source == expected_source,
                    f"runtime_source_changed:{source_name}")
            unchanged_count += 1
    require(amended_helper is not None,
            "recovery_amendment_helper_missing_from_freeze")
    require(unchanged_count == count - 1 == 178,
            "recovery_amendment_unchanged_count")

    post_path = _first_existing(
        SOURCE_POST_RUN_CANDIDATES, "source_post_run_verification_missing")
    post = read_json(post_path)
    post_schema = str(post.get("schema", ""))
    require(post_schema.endswith((".source_post_run_verification.v1",
                                  ".source_freeze_postverify.v1",
                                  ".source_postverify.v1")),
            "source_post_run_schema")
    require(post.get("status") == "passed", "source_post_run_not_passed")
    require(post.get("batch") == BATCH and post.get("count") == count,
            "source_post_run_identity")
    require(post.get("hash_chunk_bytes") == HASH_CHUNK_BYTES,
            "source_post_run_hash_chunk")
    require(post.get("current_matches_snapshots") is True,
            "source_current_snapshot_mismatch")
    require(post.get("freeze") == pin(SOURCE_FREEZE),
            "source_post_run_freeze_changed")
    return {
        "freeze": pin(SOURCE_FREEZE),
        "post_run_verification": pin(post_path),
        "count": count,
        "postverify_status": post["status"],
        "postverify_current_matches_snapshots_at_verification_time": True,
        "current_matches_all_frozen_sources": False,
        "unchanged_frozen_source_count": unchanged_count,
        "amended_frozen_source_count": 1,
        "publication_amendment": pin(RECOVERY_AMENDMENT),
        "publication_amendment_snapshot": pin(PUBLICATION_HELPER_SNAPSHOT),
        "publication_amendment_applies_only_to": amended_helper,
    }


def pin_historical_source_equivalence() -> dict[str, Any]:
    require(HISTORICAL_SOURCE_EQUIVALENCE.is_file(),
            "historical_source_equivalence_missing")
    return {
        "receipt": pin(HISTORICAL_SOURCE_EQUIVALENCE),
        "historical_only": True,
        "used_for_current_qualification": False,
        "applies_to_current_source_revision": False,
    }


def pin_historical_failed_live_002() -> dict[str, Any]:
    report = read_json(HISTORICAL_LIVE_REPORT_002)
    require(report.get("status") == "failed",
            "historical_live002_expected_failed_receipt")
    error = report.get("error")
    require(isinstance(error, dict)
            and error.get("message") == "production_capture_strict_validation_failed",
            "historical_live002_failure_identity")
    return {
        "report": pin(HISTORICAL_LIVE_REPORT_002),
        "status": "failed",
        "failure": error,
        "used_for_current_qualification": False,
        "original_retained_in_stage_artifacts": True,
    }


def validate_summary(expected_source_count: int | None = None) -> dict[str, Any]:
    summary = read_json(SUMMARY)
    require(str(summary.get("schema", "")).endswith(".development_summary.v1"),
            "summary_schema")
    require(summary.get("status") == "passed", "summary_not_passed")
    require(summary.get("batch") == BATCH, "batch69_summary_batch")
    source_count = summary.get("source_count")
    require(type(source_count) is int and source_count > 0,
            "summary_source_count")
    if expected_source_count is not None:
        require(source_count == expected_source_count,
                "summary_source_count_mismatch")
    coverage = summary.get("coverage")
    require(isinstance(coverage, dict)
            and set(coverage) == {"available", "partial", "planned"}
            and all(type(value) is int and value >= 0
                    for value in coverage.values()),
            "summary_coverage")
    require(summary.get("goal_complete") is False, "summary_goal_complete")
    runtime = summary.get("runtime")
    require(isinstance(runtime, dict), "summary_runtime")
    for key in ("pid", "creation_filetime", "session_id", "date_raw",
                "installation", "battle_source", "battle_capture_records"):
        require(key in runtime, f"summary_runtime_missing:{key}")
    require(summary.get("no_new_bad") is True, "summary_new_bad")
    require(isinstance(summary.get("full"), str) and summary["full"].strip(),
            "summary_full_footer")
    require(summary.get("read_only") is True,
            "summary_not_read_only")
    state_change = summary.get("new_save_restart_install_or_date_advance")
    require(state_change == {
        "save": False,
        "restart": True,
        "install_reused_dll": True,
        "date_advance": False,
    },
            "summary_disallowed_state_change")
    require(summary.get("computer_use") is False,
            "summary_computer_use")
    require(summary.get("business_dispatches") == 0,
            "summary_business_dispatch")
    qualification = summary.get("qualification")
    require(isinstance(qualification, dict), "summary_qualification")
    recovery = summary.get("recovery")
    require(isinstance(recovery, dict)
            and recovery.get("old_process_exit_cause") == "unknown"
            and recovery.get("live001_stopped_before_mcp_or_production_capture") is True
            and recovery.get("new_build_binary_and_119_sources_reused") is True
            and isinstance(recovery.get("outcome"), dict),
            "summary_recovery")
    visibility = summary.get("battle_visibility_progress")
    require(isinstance(visibility, dict)
            and visibility.get("getter_sample_session") == "42960-1dd6620b1e8b4cb"
            and visibility.get("historical_getter_sample_not_new_session_capture") is True
            and visibility.get("B04_complete") is False,
            "summary_recipient_scope")
    if "runtime_sample_applies_to_current_installation" in visibility:
        require(visibility.get("runtime_sample_applies_to_current_installation") is False,
                "summary_recipient_current_installation_claim")
    if "goal" in summary:
        require(summary.get("goal") == "active", "goal_not_active")
    return {
        "summary": pin(SUMMARY),
        "goal": "active",
        "status": summary["status"],
        "source_count": source_count,
        "coverage": coverage,
        "goal_complete": summary["goal_complete"],
        "runtime": runtime,
        "state_change": state_change,
        "recovery": recovery,
        "battle_visibility_progress": visibility,
        "qualification": qualification,
        "no_new_bad": summary["no_new_bad"],
        "full": summary["full"],
    }


def validate_regression() -> dict[str, Any]:
    comparison_path = STAGE / f"regression-comparison-{REGRESSION_REVISION}.json"
    xml_path = STAGE / f"regression-full-{REGRESSION_REVISION}.xml"
    log_path = STAGE / f"regression-full-{REGRESSION_REVISION}.log"
    comparison = read_json(comparison_path)
    require(comparison.get("status") in {
        "passed_no_new_failure_nodes", "passed_no_new_bad", "passed",
    },
            "regression_not_passed")
    if "new_failure_nodes" in comparison:
        require(comparison.get("new_failure_nodes") == [], "regression_new_failure_nodes")
    if "new_test_failures" in comparison:
        require(comparison.get("new_test_failures") == [], "regression_new_test_failures")
    if "no_new_bad" in comparison:
        require(comparison.get("no_new_bad") is True, "regression_new_bad")
    require(comparison.get("batch") == BATCH, "regression_comparison_batch")
    require(xml_path.is_file() and log_path.is_file(), "regression_outputs_missing")
    boundary = read_json(FULL_EXECUTION_BOUNDARY)
    require(boundary.get("schema") ==
            "information.military_resources.full_execution_boundary.v1",
            "full_execution_boundary_schema")
    require(boundary.get("batch") == BATCH and boundary.get("runs") == 1,
            "full_execution_boundary_identity")
    require(type(boundary.get("returncode")) is int,
            "full_execution_boundary_returncode")
    command = boundary.get("command")
    require(isinstance(command, list)
            and "-m" in command and "pytest" in command and "bridge/tests" in command,
            "full_execution_boundary_command")
    require(boundary.get("xml") == pin(xml_path)
            and boundary.get("log") == pin(log_path),
            "full_execution_boundary_outputs")
    return {
        "comparison": pin(comparison_path),
        "xml": pin(xml_path),
        "log": pin(log_path),
        "execution_boundary": pin(FULL_EXECUTION_BOUNDARY),
        "execution_returncode": boundary["returncode"],
        "status": comparison.get("status"),
        "no_new_bad": comparison.get("no_new_bad", True),
    }


def validate_live() -> dict[str, Any]:
    report = read_json(LIVE_REPORT)
    require(str(report.get("schema", "")).endswith(".live_acceptance.v1"),
            "live_acceptance_schema")
    require(report.get("status") == "passed", "live_acceptance_not_passed")
    require(report.get("server_exit_code") == 0, "live_acceptance_server_exit")
    checks = report.get("checks")
    require(isinstance(checks, dict) and checks
            and all(value is True for value in checks.values()),
            "live_acceptance_checks")
    require(report.get("read_only") is True, "live_acceptance_not_read_only")
    for key in ("native_game_calls", "business_dispatch",
                "information_tick_sent", "date_advance_save_reload",
                "computer_use"):
        require(report.get(key) is False, f"live_disallowed_action:{key}")
    # Accept a legacy explicit marker when present, but do not require it:
    # the current live helper's contract uses read_only/native_game_calls.
    if "native_read_only_queries" in report:
        require(report.get("native_read_only_queries") is True,
                "live_acceptance_not_native_read_only")
    identity = report.get("identity")
    identity_pins = report.get("identity_pins")
    build_manifest = report.get("build_manifest")
    require(isinstance(identity, dict)
            and identity.get("pid") == EXPECTED_PID
            and identity.get("creation_filetime") == EXPECTED_CREATION_FILETIME
            and identity.get("session_id") == EXPECTED_SESSION_ID
            and identity.get("game_sha256") == EXPECTED_EXE_SHA256
            and identity.get("dll_sha256") == EXPECTED_DLL_SHA256
            and identity.get("installation_sha256") == EXPECTED_INSTALLATION_SHA256,
            "live_installation_identity_mismatch")
    require(isinstance(identity_pins, dict)
            and identity_pins.get("pid") == EXPECTED_PID
            and identity_pins.get("creation_filetime") == EXPECTED_CREATION_FILETIME
            and identity_pins.get("session_id") == EXPECTED_SESSION_ID
            and identity_pins.get("game_sha256") == EXPECTED_EXE_SHA256
            and identity_pins.get("dll_sha256") == EXPECTED_DLL_SHA256
            and identity_pins.get("manifest_sha256") == EXPECTED_BUILD_MANIFEST_SHA256
            and identity_pins.get("game_date") == EXPECTED_DATE_RAW,
            "live_identity_pins_mismatch")
    expected_manifest = pin(BUILD / "build-manifest.json")
    require(isinstance(build_manifest, dict)
            and _workspace_path(str(build_manifest.get("path", ""))).resolve()
                == (BUILD / "build-manifest.json").resolve()
            and all(build_manifest.get(key) == expected_manifest[key]
                    for key in ("bytes", "sha256"))
            and build_manifest.get("version") == 30
            and build_manifest.get("native_source_count") == 119,
            "live_build_manifest_mismatch")
    return {
        "report": pin(LIVE_REPORT),
        "server_exit_code": report["server_exit_code"],
        "checks": len(checks),
        "identity": identity,
        "read_only": True,
        "native_game_calls": False,
        "business_dispatch": False,
        "information_tick_sent": False,
        "date_advance_save_reload": False,
        "computer_use": False,
    }


def validate_build() -> dict[str, Any]:
    for name in BUILD_REQUIRED:
        require((BUILD / name).is_file(), f"missing_build_receipt:{name}")
    installation = read_json(BUILD / "installation.json")
    manifest = read_json(BUILD / "build-manifest.json")
    status = read_json(BUILD / "information-battle-status.json")

    require(manifest.get("version") == 30, "build_version")
    require(manifest.get("experiment_id")
            == "diplomacy-observer-20261028-information-resources-v30-005",
            "build_experiment")
    require(installation.get("experiment_id")
            == "diplomacy-observer-20261028-information-resources-v30-005",
            "installation_experiment")
    require(installation.get("installation_returncode") == 0,
            "installation_returncode")
    require(installation.get("pid") == EXPECTED_PID,
            "installation_pid_changed")
    require(installation.get("creation_filetime") == EXPECTED_CREATION_FILETIME,
            "installation_creation_changed")
    require(installation.get("session_id") == EXPECTED_SESSION_ID,
            "installation_session_changed")
    require(installation.get("game_sha256") == EXPECTED_EXE_SHA256,
            "installation_exe_hash_changed")

    require(status.get("state") == "ready", "battle_source_not_ready")
    require(str(status.get("captured")) == "0"
            and str(status.get("last_sequence")) == "0",
            "battle_source_not_empty")
    require(status.get("code_patch_installed") is False,
            "battle_source_patch_installed")
    require(status.get("unwind_registered") is False,
            "battle_source_unwind_registered")
    for name in BATTLE_ABSENT_FILES:
        require(not (BUILD / name).exists(), f"prepared_battle_artifact_present:{name}")

    installation_pin = pin(BUILD / "installation.json")
    manifest_pin = pin(BUILD / "build-manifest.json")
    dll = pin(BUILD / "eu4_bridge_diplomacy_observer_v30.dll")
    require(installation_pin["sha256"] == EXPECTED_INSTALLATION_SHA256,
            "installation_receipt_hash_changed")
    require(manifest_pin["sha256"] == EXPECTED_BUILD_MANIFEST_SHA256,
            "build_manifest_hash_changed")
    require(dll["sha256"] == EXPECTED_DLL_SHA256
            and dll["sha256"] == str(installation.get("dll_sha256")),
            "dll_hash_mismatch")
    return {
        "installation": installation_pin,
        "manifest": manifest_pin,
        "dll": dll,
        "private_status": pin(BUILD / "information-battle-status.json"),
        "private_control": pin(BUILD / "control-probe.jsonl"),
        "pid": installation["pid"],
        "creation_filetime": installation["creation_filetime"],
        "session_id": installation["session_id"],
        "battle_state": status["state"],
        "captured": status["captured"],
        "last_sequence": status["last_sequence"],
        "code_patch_installed": status["code_patch_installed"],
        "unwind_registered": status["unwind_registered"],
        "binding_journal_raw_absent": True,
    }


def validate_recovery(summary: dict[str, Any], build: dict[str, Any]) -> dict[str, Any]:
    recovery = summary["recovery"]
    outcome_pin = recovery["outcome"]
    require(isinstance(outcome_pin, dict)
            and isinstance(outcome_pin.get("path"), str),
            "recovery_outcome_pin")
    outcome_path = _workspace_path(outcome_pin["path"])
    require(pin(outcome_path) == outcome_pin,
            "recovery_outcome_changed")
    outcome = read_json(outcome_path)
    require(outcome.get("status") == "ready",
            "recovery_outcome_not_ready")
    require(outcome.get("installation") == build["installation"]
            and outcome.get("manifest") == build["manifest"],
            "recovery_new_installation_pin_mismatch")
    health = outcome.get("health")
    control = outcome.get("control")
    require(isinstance(health, dict)
            and health.get("status") == "ready"
            and health.get("date_raw") == EXPECTED_DATE_RAW,
            "recovery_health")
    require(isinstance(control, dict)
            and control.get("pid") == EXPECTED_PID
            and control.get("player_slot") == 189
            and control.get("date_raw") == EXPECTED_DATE_RAW
            and control.get("speed") == 0
            and control.get("paused_flag") == 1
            and control.get("read_only") is True,
            "recovery_control")
    require(outcome.get("new_save") is False
            and outcome.get("computer_use") is False,
            "recovery_disallowed_actions")
    return {
        "summary_recovery": recovery,
        "outcome": outcome_pin,
        "outcome_status": outcome["status"],
        "new_installation": build["installation"],
        "new_manifest": build["manifest"],
        "health_ready_same_date": True,
        "control_paused_por_same_date": True,
        "new_save": False,
        "computer_use": False,
    }


def validate_previous68() -> dict[str, Any]:
    archive = read_json(OLD68_ARCHIVE)
    require(archive.get("status") == "passed" and archive.get("batch") == 68,
            "batch68_archive_not_passed")
    artifacts = archive.get("artifacts")
    declared = archive.get("artifact_count")
    require(type(declared) is int and declared == 284
            and isinstance(artifacts, list) and len(artifacts) == declared,
            "batch68_archive_artifacts")
    databases = archive.get("database_snapshots")
    require(isinstance(databases, list) and len(databases) == 2,
            "batch68_immutable_database_snapshots")
    for item in databases:
        require(isinstance(item, dict)
                and item.get("integrity") == "ok"
                and item.get("snapshot_verification") == "mode=ro&immutable=1"
                and isinstance(item.get("snapshot"), dict),
                "batch68_database_snapshot_entry")
        snapshot = item["snapshot"]
        path = _workspace_path(str(snapshot.get("path", "")))
        require(pin(path) == snapshot, f"batch68_database_snapshot_changed:{snapshot.get('path')}")

    checked = 0
    skipped_root_sources = 0
    mismatches: list[str] = []
    for item in artifacts:
        require(isinstance(item, dict) and isinstance(item.get("path"), str),
                "batch68_archive_invalid_pin")
        path = _workspace_path(item["path"])
        try:
            path.resolve().relative_to(OLD68.resolve())
        except ValueError:
            # Preserve historical pins outside the old stage without treating
            # authorized later source edits as a batch-68 archive change.
            skipped_root_sources += 1
            continue
        checked += 1
        if pin(path) != item:
            mismatches.append(item["path"])
    require(not mismatches, f"batch68_archive_pin_mismatch:{mismatches[0] if mismatches else ''}")
    self_readback = read_json(OLD68_SELF_READBACK)
    require(self_readback.get("status") == "passed"
            and self_readback.get("artifact_count") == declared,
            "batch68_archive_self_readback")
    final_readback = read_json(OLD68_FINAL_READBACK)
    require(final_readback.get("status") == "passed", "batch68_final_readback")
    return {
        "archive": pin(OLD68_ARCHIVE),
        "self_readback": pin(OLD68_SELF_READBACK),
        "final_readback": pin(OLD68_FINAL_READBACK),
        "declared_artifacts": declared,
        "pins_checked": checked,
        "skipped_authorized_root_source_pins": skipped_root_sources,
        "mismatches": len(mismatches),
        "old_stage_untouched": True,
        "immutable_database_snapshots": len(databases),
    }


def validate_shared_checkpoint() -> dict[str, Any]:
    final_readback = read_json(OLD68_FINAL_READBACK)
    declared = final_readback.get("shared_checkpoint", {}).get("pin")
    require(isinstance(declared, dict) and isinstance(declared.get("path"), str),
            "shared_checkpoint_pin_missing")
    actual = _external_pin(_workspace_path(declared["path"]))
    require(actual["bytes"] == declared.get("bytes")
            and actual["sha256"] == declared.get("sha256"),
            "shared_checkpoint_hash_changed")
    require(final_readback.get("shared_checkpoint", {}).get("archive_copied") is False,
            "shared_checkpoint_was_copied_in_batch68")
    require(final_readback.get("shared_checkpoint", {}).get("old_live_read_or_replayed") is False,
            "shared_checkpoint_replayed_in_batch68")
    require(final_readback.get("shared_checkpoint", {}).get("stage_eu4_files") == [],
            "batch68_stage_checkpoint_present")
    return {
        "pin": actual,
        "copied": False,
        "read_or_replayed": False,
        "source": "batch68_final_readback_shared_checkpoint",
    }


def validate_recipient_link() -> dict[str, Any]:
    link = read_json(RECIPIENT_LINK)
    require(link.get("schema") == "information.battle.native_recipient_evidence_link.v1",
            "recipient_evidence_link_schema")
    require(link.get("batch") == BATCH
            and link.get("status") == "passed_associated_source_not_main_archive",
            "recipient_evidence_link_status")
    scope = link.get("scope")
    relation = link.get("main_archive_relation")
    require(isinstance(scope, dict)
            and scope.get("source_report_kept_at_original_path") is True
            and scope.get("main_69_archive_membership") == "associated_source_only",
            "recipient_link_scope")
    require(isinstance(relation, dict)
            and relation.get("included_in_main_69_archive") is False
            and relation.get("original_path_preserved") is True,
            "recipient_link_archive_relation")

    associated = link.get("associated_source_artifacts")
    require(isinstance(associated, list) and associated,
            "recipient_link_artifacts_missing")
    checked: list[dict[str, Any]] = []
    prior_sample_identity: dict[str, Any] | None = None
    for item in associated:
        require(isinstance(item, dict), "recipient_link_artifact_entry")
        relative = str(item.get("path", ""))
        require(relative and relative == str(item.get("report_address", relative)),
                "recipient_link_original_path_mismatch")
        source = _workspace_path(relative).resolve()
        try:
            source.relative_to(RECIPIENT_ORIGINAL_STAGE)
        except ValueError as exc:
            raise ArchiveError(f"recipient_source_outside_original_stage:{relative}") from exc
        require(source.stat().st_size <= COPY_LIMIT_BYTES,
                f"recipient_source_over_copy_bound:{relative}")
        original = pin(source)
        require(original["path"] == relative.replace("\\", "/")
                and original["bytes"] == item.get("bytes")
                and original["sha256"] == item.get("sha256"),
                f"recipient_source_pin_mismatch:{relative}")

        if source.name == "recipient-source-audit-001.json":
            audit = read_json(source)
            installation_identity = audit.get("installation_identity")
            conclusion = audit.get("runtime_conclusion")
            require(isinstance(installation_identity, dict)
                    and isinstance(conclusion, dict),
                    "recipient_audit_runtime_identity_missing")
            expected = installation_identity.get("expected")
            require(isinstance(expected, dict),
                    "recipient_audit_expected_identity_missing")
            require(expected.get("pid") == RECIPIENT_AUDIT_OLD_PID
                    and expected.get("creation_filetime") == RECIPIENT_AUDIT_OLD_CREATION_FILETIME
                    and expected.get("session_id") == RECIPIENT_AUDIT_OLD_SESSION_ID
                    and expected.get("date_raw") == EXPECTED_DATE_RAW,
                    "recipient_audit_old_session_identity_mismatch")
            require((expected.get("pid"), expected.get("creation_filetime"),
                     expected.get("session_id"))
                    != (EXPECTED_PID, EXPECTED_CREATION_FILETIME, EXPECTED_SESSION_ID),
                    "recipient_audit_must_not_match_current_installation")
            first_ref = conclusion.get("selected_ref_pass1")
            second_ref = conclusion.get("selected_ref_pass2")
            require(isinstance(first_ref, dict) and isinstance(second_ref, dict),
                    "recipient_audit_selected_refs_missing")
            first_country = first_ref.get("tag")
            second_country = second_ref.get("tag")
            require(conclusion.get("date_match") is True
                    and first_country == "POR" and second_country == "POR",
                    "recipient_audit_sample_identity_unexpected")
            prior_sample_identity = {
                "pid": expected["pid"],
                "creation_filetime": expected["creation_filetime"],
                "session_id": expected["session_id"],
                "date_raw": expected["date_raw"],
                "selected_native_country": first_country,
                "information_observer": "FRA",
                "runtime_scope": "prior session only; does not describe the v30-005 installation",
            }

        checked.append({
            "original": original,
            "role": item.get("role"),
            "source_path": str(source),
        })

    require(prior_sample_identity is not None,
            "prior_session_recipient_audit_not_linked")

    return {
        "link": pin(RECIPIENT_LINK),
        "association_status": link["status"],
        "original_stage": display_path(RECIPIENT_ORIGINAL_STAGE),
        "prior_session_sample": prior_sample_identity,
        "current_installation": {
            "pid": EXPECTED_PID,
            "creation_filetime": EXPECTED_CREATION_FILETIME,
            "session_id": EXPECTED_SESSION_ID,
        },
        "current_session_match": False,
        "runtime_sample_applies_to_current_installation": False,
        "artifacts": checked,
    }


def snapshot_related_sources(association: dict[str, Any]) -> dict[str, Any]:
    checked: list[dict[str, Any]] = []
    for item in association["artifacts"]:
        original = item["original"]
        source = Path(item["source_path"]).resolve()
        original_relative = source.relative_to(RECIPIENT_ORIGINAL_STAGE)
        destination = (
            RELATED_SOURCE_SNAPSHOT_ROOT /
            RECIPIENT_ORIGINAL_STAGE.name /
            original_relative
        )
        snapshot = copy_new(source, destination, limit=COPY_LIMIT_BYTES)
        require(snapshot["source"] == original,
                f"recipient_original_changed_during_snapshot:{original['path']}")
        checked.append({
            "original": original,
            "snapshot": snapshot["snapshot"],
            "role": item.get("role"),
            "preservation": "related-source snapshot; original remains at its separate stage",
        })

    verification = {
        "schema": "information.country_force_resources.related_source_verification.v1",
        "status": "passed",
        "batch": BATCH,
        "link": association["link"],
        "association_status": association["association_status"],
        "main_archive_membership": "related-source-snapshot-only",
        "original_stage": association["original_stage"],
        "prior_session_sample": association["prior_session_sample"],
        "current_installation": association["current_installation"],
        "current_session_match": False,
        "runtime_sample_applies_to_current_installation": False,
        "evidence_classification": "prior-session-associated-source; not current v30-005 runtime evidence",
        "original_path_preserved": True,
        "originals_moved_or_modified": False,
        "artifacts": checked,
    }
    write_new(RELATED_SOURCE_VERIFICATION, verification)
    return verification


def working_database_paths() -> tuple[list[Path], list[Path]]:
    primary: list[Path] = []
    sidecars: list[Path] = []
    for path in sorted(STAGE.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(STAGE)
        if "final-database-snapshots" in relative.parts:
            continue
        lower = path.name.lower()
        if lower.endswith(("-wal", "-shm")):
            sidecars.append(path)
        elif path.suffix.lower() in {".sqlite", ".sqlite3", ".db"}:
            primary.append(path)
    return primary, sidecars


def snapshot_build_and_databases() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    final_dir = STAGE / "final-snapshots"
    database_dir = STAGE / "final-database-snapshots"
    final_dir.mkdir(exist_ok=False)
    database_dir.mkdir(exist_ok=False)

    copies: list[dict[str, Any]] = []
    for name in BUILD_REQUIRED:
        copies.append(copy_new(BUILD / name, final_dir / name))

    primary, sidecars = working_database_paths()
    require(primary, "working_databases_missing")
    backups = [
        backup_sqlite(source, database_dir / source.relative_to(STAGE))
        for source in primary
    ]
    excluded = [
        {
            "path": display_path(path),
            "bytes": path.stat().st_size,
            "reason": "working SQLite/WAL/SHM excluded; fresh immutable snapshot retained",
        }
        for path in primary + sidecars
    ]
    report = {
        "schema": "information.country_force_resources.database_snapshot_verification.v1",
        "status": "passed",
        "hash_chunk_bytes": HASH_CHUNK_BYTES,
        "backups": backups,
        "working_database_exclusions": excluded,
        "source_wal_shm_deleted": False,
        "source_databases_modified": False,
        "all_snapshots_closed_immutable_ro_verified": True,
        "fresh_snapshot_count": len(backups),
    }
    write_new(DATABASE_VERIFICATION, report)
    return copies, report


def snapshot_documents() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    copies: list[dict[str, Any]] = []
    markers: dict[str, str] = {}
    for relative in DOCUMENTS:
        source = ROOT / relative
        require(source.is_file(), f"missing_document:{relative}")
        marker = _top_marker(source) if relative in MARKER_DOCUMENTS else None
        if relative in MARKER_DOCUMENTS:
            require(marker is not None, f"batch69_document_marker_missing:{relative}")
            markers[relative] = marker
        if relative.endswith(".json"):
            read_json(source)
        checks.append({"source": pin(source), "marker": marker})
        copies.append(copy_new(source, STAGE / "document-snapshots" / relative))
    report = {
        "schema": "information.country_force_resources.document_verification.v1",
        "status": "passed",
        "documents": checks,
        "snapshots": copies,
        "markers": markers,
    }
    write_new(DOCUMENT_VERIFICATION, report)
    return report


def _is_working_database_artifact(path: Path) -> bool:
    relative = path.relative_to(STAGE)
    if "final-database-snapshots" in relative.parts:
        return False
    lower = path.name.lower()
    return lower.endswith(("-wal", "-shm")) or path.suffix.lower() in {".sqlite", ".sqlite3", ".db"}


def stage_artifacts() -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    artifacts: list[dict[str, Any]] = []
    database_exclusions: list[dict[str, Any]] = []
    large_exclusions: list[dict[str, Any]] = []
    for path in sorted(STAGE.rglob("*")):
        if not path.is_file():
            continue
        if path.name in EXCLUDED_MANIFEST_NAMES or path.name.startswith("final-readback"):
            continue
        if _is_working_database_artifact(path):
            database_exclusions.append({
                "path": display_path(path),
                "bytes": path.stat().st_size,
                "reason": "working SQLite/WAL/SHM excluded; immutable snapshot retained",
            })
            continue
        if path.suffix.lower() == ".eu4" and path.stat().st_size > LARGE_CHECKPOINT_BYTES:
            large_exclusions.append({
                "path": display_path(path),
                "bytes": path.stat().st_size,
                "reason": "large checkpoint excluded; shared checkpoint remains externally pinned in place",
            })
            continue
        artifacts.append(pin(path))
    return artifacts, database_exclusions, large_exclusions


def ensure_outputs_absent() -> None:
    for path in (
        ARCHIVE,
        SELF_READBACK,
        RUNTIME_VERIFICATION,
        DATABASE_VERIFICATION,
        DOCUMENT_VERIFICATION,
        RELATED_SOURCE_VERIFICATION,
        STAGE / "final-snapshots",
        STAGE / "final-database-snapshots",
        STAGE / "document-snapshots",
        RELATED_SOURCE_SNAPSHOT_ROOT,
    ):
        require(not path.exists(), f"archive_already_started:{display_path(path)}")


def archive() -> dict[str, Any]:
    require(STAGE.is_dir() and BUILD.is_dir(), "stage_or_build_missing")
    ensure_outputs_absent()

    source = validate_source_freeze()
    historical_equivalence = pin_historical_source_equivalence()
    historical_live002 = pin_historical_failed_live_002()
    summary = validate_summary(source["count"])
    regression = validate_regression()
    live = validate_live()
    build = validate_build()
    recovery = validate_recovery(summary, build)
    summary_runtime = summary["runtime"]
    require(summary_runtime.get("pid") == build["pid"]
            and summary_runtime.get("creation_filetime") == build["creation_filetime"]
            and summary_runtime.get("session_id") == build["session_id"],
            "summary_build_identity_mismatch")
    require(str(summary_runtime.get("installation", "")).replace("\\", "/")
            == display_path(BUILD / "installation.json"),
            "summary_installation_path_mismatch")
    require(summary_runtime.get("date_raw") == EXPECTED_DATE_RAW,
            "summary_unexpected_game_date")
    require(summary_runtime.get("battle_source") == "ready-never-enabled"
            and summary_runtime.get("battle_capture_records") == 0,
            "summary_battle_source_not_prepared")
    previous68 = validate_previous68()
    checkpoint = validate_shared_checkpoint()
    recipient = validate_recipient_link()
    qualification = summary["qualification"]
    require(qualification.get("freeze") == source["freeze"],
            "summary_freeze_receipt_mismatch")
    require(qualification.get("postverify") == source["post_run_verification"],
            "summary_postverify_receipt_mismatch")
    require(qualification.get("comparison") == regression["comparison"],
            "summary_comparison_receipt_mismatch")
    require(qualification.get("live") == live["report"],
            "summary_live_receipt_mismatch")
    visibility = summary["battle_visibility_progress"]
    require(visibility.get("associated_source") == recipient["link"]
            and visibility.get("native_selected_country") == "POR"
            and visibility.get("information_observer") == "FRA",
            "summary_recipient_source_mismatch")

    for relative in DOCUMENTS:
        document = ROOT / relative
        require(document.is_file(), f"missing_document:{relative}")
        if relative in MARKER_DOCUMENTS:
            require(_top_marker(document) is not None,
                    f"batch69_document_marker_missing:{relative}")
        if relative.endswith(".json"):
            read_json(document)
    require(working_database_paths()[0], "working_databases_missing")

    recipient = snapshot_related_sources(recipient)
    documents = snapshot_documents()
    build_copies, database = snapshot_build_and_databases()

    runtime = {
        "schema": "information.country_force_resources.runtime_archive_verification.v1",
        "status": "passed",
        "batch": BATCH,
        "summary": summary,
        "source": source,
        "historical_source_equivalence_002_to_003": historical_equivalence,
        "historical_failed_live_acceptance_002": historical_live002,
        "regression": regression,
        "live": live,
        "build": build,
        "recovery": recovery,
        "previous_batch68": previous68,
        "shared_checkpoint": checkpoint,
        "related_battle_native_recipient": recipient,
        "documents": documents,
        "build_snapshots": build_copies,
        "database_snapshots": database,
        "scope": {
            "game_started_by_archive": False,
            "mcp_started_by_archive": False,
            "native_queries_by_archive": False,
            "tests_run_by_archive": False,
            "rea_or_disassembly": False,
            "working_databases_modified": False,
            "wal_shm_deleted": False,
            "large_checkpoint_copied": False,
            "external_recipient_original_moved_or_modified": False,
            "recipient_audit_runtime_sample_applies_to_current_installation": False,
            "recipient_audit_session_matches_current_installation": False,
            "source_equivalence_002_to_003_used_for_current_qualification": False,
            "failed_live002_used_for_current_qualification": False,
            "failed_live002_receipt_retained": True,
            "external_recipient_membership": "linked-and-related-snapshot-mapped",
        },
    }
    write_new(RUNTIME_VERIFICATION, runtime)

    artifacts, database_exclusions, large_exclusions = stage_artifacts()
    database_manifest = [
        {
            "snapshot": item["snapshot"],
            "integrity": item["integrity"],
            "tables": item["tables"],
            "active_subscriptions": item["active_subscriptions"],
            "snapshot_verification": item["snapshot_verification"],
        }
        for item in database["backups"]
    ]
    manifest = {
        "schema": "information_country_force_resources_archive.v1",
        "status": "passed",
        "batch": BATCH,
        "goal": "active",
        "stage": display_path(STAGE),
        "build": display_path(BUILD),
        "hash_chunk_bytes": HASH_CHUNK_BYTES,
        "copy_limit_bytes": COPY_LIMIT_BYTES,
        "source_count": source["count"],
        "historical_source_equivalence_002_to_003": historical_equivalence,
        "historical_failed_live_acceptance_002": historical_live002,
        "recovery": recovery,
        "runtime_verification": pin(RUNTIME_VERIFICATION),
        "artifacts": artifacts,
        "artifact_count": len(artifacts),
        "excluded_working_databases": database_exclusions,
        "excluded_large_checkpoints": large_exclusions,
        "database_verification": pin(DATABASE_VERIFICATION),
        "database_snapshots": database_manifest,
        "previous_batch68": previous68,
        "shared_checkpoint": checkpoint,
        "related_source_associations": recipient["artifacts"],
        "recipient_evidence_link": recipient["link"],
        "scope": {
            "game_started_by_archive": False,
            "mcp_started_by_archive": False,
            "native_queries_by_archive": False,
            "tests_run_by_archive": False,
            "rea_or_disassembly": False,
            "working_database_files_in_artifacts": False,
            "wal_shm_in_artifacts": False,
            "immutable_snapshot_copies_only": True,
            "large_checkpoint_copied": False,
            "external_recipient_original_remains_at_original_path": True,
            "external_recipient_originals_moved_or_modified": False,
            "recipient_audit_runtime_sample_applies_to_new_installation": False,
            "recipient_audit_session_matches_new_installation": False,
            "source_equivalence_002_to_003_used_for_current_qualification": False,
            "failed_live002_used_for_current_qualification": False,
            "failed_live002_receipt_retained": True,
            "related_source_snapshot_mapping_explicit": True,
            "manifest_self_hash_excluded": True,
            "self_readback_excluded": True,
        },
    }
    write_new(ARCHIVE, manifest)

    for item in artifacts:
        require(pin(ROOT / item["path"]) == item,
                f"final_readback_mismatch:{item['path']}")
    write_new(
        SELF_READBACK,
        {
            "schema": "information_country_force_resources_archive_readback.v1",
            "status": "passed",
            "batch": BATCH,
            "manifest": pin(ARCHIVE),
            "artifact_count": len(artifacts),
            "all_artifact_pins_rechecked": True,
            "working_database_exclusions_rechecked": len(database_exclusions),
            "large_checkpoint_exclusions_rechecked": len(large_exclusions),
            "database_snapshots_independent": True,
            "manifest_self_hash_excluded": True,
            "self_readback_excluded": True,
        },
    )
    return {
        "status": "passed",
        "batch": BATCH,
        "artifact_count": len(artifacts),
        "database_snapshots": len(database_manifest),
        "old68_pins_checked": previous68["pins_checked"],
        "related_external_source_snapshots": len(recipient["artifacts"]),
        "readback": len(artifacts),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true",
                        help="perform the exclusive offline archive")
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({
            "status": "inert",
            "batch": BATCH,
            "stage": display_path(STAGE),
            "build": display_path(BUILD),
            "run_requires": "--run",
            "archive_outputs": [
                display_path(ARCHIVE), display_path(SELF_READBACK),
                display_path(RUNTIME_VERIFICATION),
                display_path(RELATED_SOURCE_VERIFICATION),
            ],
            "required_inputs": {
                "summary": display_path(SUMMARY),
                "source_freeze": display_path(SOURCE_FREEZE),
                "source_post_run_candidates": [
                    display_path(path) for path in SOURCE_POST_RUN_CANDIDATES
                ],
                "historical_source_equivalence_not_current_qualification": display_path(
                    HISTORICAL_SOURCE_EQUIVALENCE
                ),
                "historical_failed_live002_report": display_path(
                    HISTORICAL_LIVE_REPORT_002
                ),
                "regression_comparison": display_path(
                    STAGE / f"regression-comparison-{REGRESSION_REVISION}.json"
                ),
                "regression_xml": display_path(
                    STAGE / f"regression-full-{REGRESSION_REVISION}.xml"
                ),
                "regression_log": display_path(
                    STAGE / f"regression-full-{REGRESSION_REVISION}.log"
                ),
                "full_execution_boundary": display_path(FULL_EXECUTION_BOUNDARY),
                "live_report": display_path(LIVE_REPORT),
                "old68_archive": display_path(OLD68_ARCHIVE),
                "recipient_evidence_link": display_path(RECIPIENT_LINK),
                "build_installation": display_path(BUILD / "installation.json"),
                "build_manifest": display_path(BUILD / "build-manifest.json"),
                "battle_status": display_path(BUILD / "information-battle-status.json"),
                "private_control": display_path(BUILD / "control-probe.jsonl"),
            },
            "scope": {
                "archive_run": False,
                "game_or_mcp_or_native_or_rea_or_tests_or_rpm": False,
                "large_checkpoint_copy": False,
            },
        }, ensure_ascii=False))
        return 0
    try:
        result = archive()
    except ArchiveError as exc:
        print(json.dumps({"status": "blocked", "error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
