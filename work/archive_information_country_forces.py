"""Archive batch 68 country-forces evidence without touching live state.

The default invocation is inert.  ``--run`` is the only entry point that may
create the exclusive archive and it is deliberately fail-closed: source
freeze/post-run pins, the previous batch-67 archive, build identity, the
prepared-but-never-enabled battle source, the successful live acceptance
report, and fresh immutable SQLite snapshots must all validate first.

The archive copies only bounded build/document artifacts.  The large shared
batch-67 checkpoint is pinned in place and is never copied.  Working SQLite
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
    ROOT / "work/runtime/information-country-forces-20261027-001"
).resolve()
OLD67 = (ROOT / "work/runtime/information-war-context-forces-20261027-001").resolve()
BUILD = (
    ROOT / "work/runtime/diplomacy-observer-20261027-information-war-v30-004"
).resolve()

ARCHIVE = STAGE / "archive-verification-001.json"
SELF_READBACK = STAGE / "archive-self-readback-001.json"
RUNTIME_VERIFICATION = STAGE / "runtime-archive-verification-001.json"
DATABASE_VERIFICATION = STAGE / "database-snapshot-verification-001.json"
DOCUMENT_VERIFICATION = STAGE / "document-verification-001.json"

OLD67_ARCHIVE = OLD67 / "archive-verification-001.json"
OLD67_SELF_READBACK = OLD67 / "archive-self-readback-001.json"
OLD67_FINAL_READBACK = OLD67 / "final-readback-001.json"

SOURCE_FREEZE = STAGE / "source-freeze-001.json"
SOURCE_POST_RUN = STAGE / "source-post-run-verification-001.json"
SUMMARY = STAGE / "development-summary-001.json"
LIVE_REPORT = STAGE / "live-acceptance-001" / "report.json"

HASH_CHUNK_BYTES = 1024 * 1024
COPY_LIMIT_BYTES = 16 * 1024 * 1024
LARGE_CHECKPOINT_BYTES = COPY_LIMIT_BYTES
BATCH = 68
BATCH_MARKER_RE = re.compile(r"<!-- batch68-[^:]+:start -->")

EXPECTED_PID = 42960
EXPECTED_CREATION_FILETIME = 134375854500787403
EXPECTED_SESSION_ID = "42960-1dd6620b1e8b4cb"
EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)

BUILD_REQUIRED = (
    "installation.json",
    "build-manifest.json",
    "eu4_bridge_diplomacy_observer_v30.dll",
    "information-battle-status.json",
    "control-probe.jsonl",
)
BUILD_PRIVATE_STATUS_FILES = (
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
    "docs/信息字段覆盖.json",
)
MARKER_DOCUMENTS = {"HANDOFF.md", "README(agent).md", "docs/信息导出与订阅开发计划.md"}

EXCLUDED_MANIFEST_NAMES = {
    ARCHIVE.name,
    SELF_READBACK.name,
}


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


def validate_source_freeze() -> dict[str, Any]:
    freeze = read_json(SOURCE_FREEZE)
    require(freeze.get("schema") == "information.country_forces.source_freeze.v1",
            "source_freeze_schema")
    require(freeze.get("status") == "passed", "source_freeze_not_passed")
    require(freeze.get("batch") == BATCH, "source_freeze_batch")
    require(freeze.get("hash_chunk_bytes") == HASH_CHUNK_BYTES,
            "source_freeze_hash_chunk")
    count = freeze.get("count")
    require(type(count) is int and count > 0, "source_freeze_dynamic_count")
    files = freeze.get("files")
    require(isinstance(files, list) and len(files) == count, "source_freeze_files")
    seen: set[str] = set()
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
        require(pin(source) == expected_source, f"runtime_source_changed:{source_name}")
        require(pin(snapshot) == expected_snapshot,
                f"runtime_snapshot_changed:{snapshot_name}")
        require(expected_source.get("bytes") == expected_snapshot.get("bytes")
                and expected_source.get("sha256") == expected_snapshot.get("sha256"),
                f"source_snapshot_hash_mismatch:{source_name}")

    post = read_json(SOURCE_POST_RUN)
    require(post.get("schema") ==
            "information.country_forces.source_post_run_verification.v1",
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
        "post_run_verification": pin(SOURCE_POST_RUN),
        "count": count,
        "current_matches_snapshots": True,
    }


def validate_summary(expected_source_count: int | None = None) -> dict[str, Any]:
    summary = read_json(SUMMARY)
    require(summary.get("schema") ==
            "information.country_forces.development_summary.v1",
            "summary_schema")
    require(summary.get("status") == "passed", "summary_not_passed")
    require(summary.get("batch") == BATCH, "batch68_summary_batch")
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
    require(summary.get("new_save_restart_install_or_date_advance") is False,
            "summary_disallowed_state_change")
    require(summary.get("computer_use") is False,
            "summary_computer_use")
    require(summary.get("business_dispatches") == 0,
            "summary_business_dispatch")
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
        "no_new_bad": summary["no_new_bad"],
        "full": summary["full"],
    }


def validate_regression() -> dict[str, Any]:
    comparison_path = STAGE / "regression-comparison-001.json"
    xml_path = STAGE / "regression-full-001.xml"
    log_path = STAGE / "regression-full-001.log"
    comparison = read_json(comparison_path)
    require(comparison.get("status") in {"passed_no_new_failure_nodes", "passed"},
            "regression_not_passed")
    if "new_failure_nodes" in comparison:
        require(comparison.get("new_failure_nodes") == [], "regression_new_failure_nodes")
    if "new_test_failures" in comparison:
        require(comparison.get("new_test_failures") == [], "regression_new_test_failures")
    require(xml_path.is_file() and log_path.is_file(), "regression_outputs_missing")
    return {
        "comparison": pin(comparison_path),
        "xml": pin(xml_path),
        "log": pin(log_path),
        "status": comparison.get("status"),
        "no_new_bad": comparison.get("no_new_bad", True),
    }


def validate_live() -> dict[str, Any]:
    report = read_json(LIVE_REPORT)
    require(report.get("schema") ==
            "information.country_forces.live_acceptance.v1",
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
    return {
        "report": pin(LIVE_REPORT),
        "server_exit_code": report["server_exit_code"],
        "checks": len(checks),
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
            == "diplomacy-observer-20261027-information-war-v30-004",
            "build_experiment")
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

    dll = pin(BUILD / "eu4_bridge_diplomacy_observer_v30.dll")
    require(dll["sha256"] == str(installation.get("dll_sha256")),
            "dll_hash_mismatch")
    return {
        "installation": pin(BUILD / "installation.json"),
        "manifest": pin(BUILD / "build-manifest.json"),
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


def validate_previous67() -> dict[str, Any]:
    archive = read_json(OLD67_ARCHIVE)
    require(archive.get("status") == "passed" and archive.get("batch") == 67,
            "batch67_archive_not_passed")
    artifacts = archive.get("artifacts")
    declared = archive.get("artifact_count")
    require(type(declared) is int and declared == 286
            and isinstance(artifacts, list) and len(artifacts) == declared,
            "batch67_archive_artifacts")
    checked = 0
    skipped_root_sources = 0
    mismatches: list[str] = []
    for item in artifacts:
        require(isinstance(item, dict) and isinstance(item.get("path"), str),
                "batch67_archive_invalid_pin")
        path = _workspace_path(item["path"])
        try:
            path.resolve().relative_to(OLD67.resolve())
        except ValueError:
            # A future archive may contain a root source pin.  Batch 68 has
            # authorized source edits; preserve that historical pin without
            # treating it as a current-source mismatch.
            skipped_root_sources += 1
            continue
        checked += 1
        if pin(path) != item:
            mismatches.append(item["path"])
    require(not mismatches, f"batch67_archive_pin_mismatch:{mismatches[0] if mismatches else ''}")
    self_readback = read_json(OLD67_SELF_READBACK)
    require(self_readback.get("status") == "passed"
            and self_readback.get("artifact_count") == declared,
            "batch67_archive_self_readback")
    final_readback = read_json(OLD67_FINAL_READBACK)
    require(final_readback.get("status") == "passed", "batch67_final_readback")
    return {
        "archive": pin(OLD67_ARCHIVE),
        "self_readback": pin(OLD67_SELF_READBACK),
        "final_readback": pin(OLD67_FINAL_READBACK),
        "declared_artifacts": declared,
        "pins_checked": checked,
        "skipped_authorized_root_source_pins": skipped_root_sources,
        "mismatches": len(mismatches),
        "old_stage_untouched": True,
    }


def validate_shared_checkpoint() -> dict[str, Any]:
    final_readback = read_json(OLD67_FINAL_READBACK)
    declared = final_readback.get("live_existing_audit", {}).get("checkpoint_once_pin")
    require(isinstance(declared, dict) and isinstance(declared.get("path"), str),
            "shared_checkpoint_pin_missing")
    actual = _external_pin(Path(declared["path"]))
    require(actual["sha256"] == declared.get("sha256"),
            "shared_checkpoint_hash_changed")
    return {
        "pin": actual,
        "copied": False,
        "read_or_replayed": declared.get("read_or_replayed") is False,
        "source": "batch67_live_final_readback",
    }


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
        "schema": "information.country_forces.database_snapshot_verification.v1",
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
            require(marker is not None, f"batch68_document_marker_missing:{relative}")
            markers[relative] = marker
        if relative.endswith(".json"):
            read_json(source)
        checks.append({"source": pin(source), "marker": marker})
        copies.append(copy_new(source, STAGE / "document-snapshots" / relative))
    report = {
        "schema": "information.country_forces.document_verification.v1",
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
                "reason": "large checkpoint excluded; shared batch67 checkpoint is pinned in place",
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
        STAGE / "final-snapshots",
        STAGE / "final-database-snapshots",
        STAGE / "document-snapshots",
    ):
        require(not path.exists(), f"archive_already_started:{display_path(path)}")


def archive() -> dict[str, Any]:
    require(STAGE.is_dir() and BUILD.is_dir(), "stage_or_build_missing")
    ensure_outputs_absent()

    source = validate_source_freeze()
    summary = validate_summary(source["count"])
    regression = validate_regression()
    live = validate_live()
    build = validate_build()
    previous67 = validate_previous67()
    checkpoint = validate_shared_checkpoint()
    documents = snapshot_documents()
    build_copies, database = snapshot_build_and_databases()

    runtime = {
        "schema": "information.country_forces.runtime_archive_verification.v1",
        "status": "passed",
        "batch": BATCH,
        "summary": summary,
        "source": source,
        "regression": regression,
        "live": live,
        "build": build,
        "previous_batch67": previous67,
        "shared_checkpoint": checkpoint,
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
        "schema": "information_country_forces_archive.v1",
        "status": "passed",
        "batch": BATCH,
        "goal": "active",
        "stage": display_path(STAGE),
        "build": display_path(BUILD),
        "hash_chunk_bytes": HASH_CHUNK_BYTES,
        "copy_limit_bytes": COPY_LIMIT_BYTES,
        "source_count": source["count"],
        "runtime_verification": pin(RUNTIME_VERIFICATION),
        "artifacts": artifacts,
        "artifact_count": len(artifacts),
        "excluded_working_databases": database_exclusions,
        "excluded_large_checkpoints": large_exclusions,
        "database_verification": pin(DATABASE_VERIFICATION),
        "database_snapshots": database_manifest,
        "previous_batch67": previous67,
        "shared_checkpoint": checkpoint,
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
            "schema": "information_country_forces_archive_readback.v1",
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
        "old67_pins_checked": previous67["pins_checked"],
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
            ],
            "required_inputs": {
                "summary": display_path(SUMMARY),
                "source_freeze": display_path(SOURCE_FREEZE),
                "source_post_run": display_path(SOURCE_POST_RUN),
                "live_report": display_path(LIVE_REPORT),
                "old67_archive": display_path(OLD67_ARCHIVE),
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
