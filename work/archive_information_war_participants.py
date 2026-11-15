"""Archive batch 67 war-participant evidence without touching live state.

The default invocation is deliberately inert.  ``--run`` performs one
exclusive-create archive after the already completed source, regression, and
live receipts pass.  It does not start a game or MCP server, issue a native
query, run tests, or invoke REA.  Working SQLite files are backed up into
fresh files only after the recorded server exit; the originals and their
WAL/SHM sidecars remain outside the ordinary artifact manifest.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any

# The batch-66 module exposes these helpers without performing archive work at
# import time.  Reusing them keeps the new archive small and does not alter its
# stage globals or call its archive entry point.
from archive_information_war_score import (  # type: ignore[import-not-found]
    ArchiveError,
    backup_sqlite,
    copy_new,
    display_path,
    pin,
    read_json,
    require,
    write_new,
)


ROOT = Path(__file__).resolve().parents[1]
STAGE = Path(
    r"C:/Users/wangyufei/Documents/ChatGPT/欧陆风云4/"
    r"work/runtime/information-war-context-forces-20261027-001"
).resolve()
BUILD = ROOT / "work/runtime/diplomacy-observer-20261027-information-war-v30-004"
OLD66 = ROOT / "work/runtime/information-war-score-20261027-001"

ARCHIVE = STAGE / "archive-verification-001.json"
SELF_READBACK = STAGE / "archive-self-readback-001.json"
RUNTIME_VERIFICATION = STAGE / "runtime-archive-verification-001.json"
DATABASE_VERIFICATION = STAGE / "database-snapshot-verification-001.json"
DOCUMENT_VERIFICATION = STAGE / "document-verification-001.json"
SUPPLEMENTAL_VERIFICATION = STAGE / "supplemental-source-verification-001.json"
PREVIOUS66_READBACK = STAGE / "previous-batch66-archive-readback-001.json"

OLD66_ARCHIVE = OLD66 / "archive-verification-001.json"
OLD66_SELF_READBACK = OLD66 / "archive-self-readback-001.json"
OLD66_FINAL_READBACK = OLD66 / "final-readback-001.json"

HASH_CHUNK_BYTES = 1024 * 1024
COPY_LIMIT_BYTES = 16 * 1024 * 1024
SOURCE_COUNT = 163
BATCH_MARKER = "<!-- batch67-war-participants-summary:start -->"

BUILD_REQUIRED = (
    "installation.json",
    "build-manifest.json",
    "eu4_bridge_diplomacy_observer_v30.dll",
    "information-battle-status.json",
    "control-probe.jsonl",
)
BUILD_OPTIONAL = (
    "information-battle-binding.json",
    "information-battle-capture-journal.json",
    "information-battle-raw.jsonl",
)

# These are the current handoff/plan/coverage documents plus the three
# participant-related documents named by the batch owner and the automation
# runbook.  The first three carry the batch marker.
DOCUMENTS = (
    "HANDOFF.md",
    "README(agent).md",
    "docs/信息导出与订阅开发计划.md",
    "docs/信息字段覆盖.json",
    "docs/战争发现与议和信息接口.md",
    "docs/战报原生文本读取与传输.md",
    "docs/战争参战名单只读接口.md",
    "开发过程自动化.md",
)
MARKER_DOCUMENTS = {
    "HANDOFF.md",
    "README(agent).md",
    "docs/信息导出与订阅开发计划.md",
}

SUPPLEMENTAL_REQUIRED = (
    "work/verify_information_war_participants.py",
    "work/validate_information_war_participants_live.py",
    "work/finalize_information_war_participants.py",
    "work/archive_information_war_participants.py",
    "work/archive_information_war_score.py",
)

CONTROL_AUDIT_RE = re.compile(r"information-battle-control-audit-([0-9a-f]{32})\.jsonl\Z")
CONTROL_STARTED_RE = re.compile(r"information-battle-started-([0-9a-f]{32})\.json\Z")
CONTROL_RESPONSE_RE = re.compile(r"information-battle-response-([0-9a-f]{32})\.json\Z")
EXCLUDED_MANIFEST_NAMES = {
    "archive-verification-001.json",
    "archive-self-readback-001.json",
}


def validate_source_freeze() -> dict[str, Any]:
    freeze_path = STAGE / "source-freeze-001.json"
    freeze = read_json(freeze_path)
    require(freeze.get("status") == "passed", "source_freeze_not_passed")
    require(freeze.get("batch") == 67, "source_freeze_batch")
    require(freeze.get("count") == SOURCE_COUNT, "source_freeze_count")
    files = freeze.get("files")
    require(isinstance(files, list) and len(files) == SOURCE_COUNT, "source_freeze_files")
    seen: set[str] = set()
    for item in files:
        require(isinstance(item, dict), "source_freeze_entry")
        expected_source = item.get("source")
        expected_snapshot = item.get("snapshot")
        require(isinstance(expected_source, dict) and isinstance(expected_snapshot, dict),
                "source_freeze_pins")
        source_name = str(expected_source.get("path", ""))
        require(source_name not in seen, f"duplicate_source_freeze:{source_name}")
        seen.add(source_name)
        source = ROOT / source_name
        snapshot = ROOT / str(expected_snapshot.get("path", ""))
        require(pin(source) == expected_source, f"runtime_source_changed:{source_name}")
        require(pin(snapshot) == expected_snapshot, f"runtime_snapshot_changed:{snapshot}")
        require(expected_source.get("bytes") == expected_snapshot.get("bytes")
                and expected_source.get("sha256") == expected_snapshot.get("sha256"),
                f"source_snapshot_hash_mismatch:{source_name}")

    post_path = STAGE / "source-post-run-verification-001.json"
    post = read_json(post_path)
    require(post.get("status") == "passed", "source_post_run_verification_not_passed")
    require(post.get("batch") == 67 and post.get("count") == SOURCE_COUNT,
            "source_post_run_verification_identity")
    require(post.get("current_matches_snapshots") is True, "source_current_snapshot_mismatch")
    require(post.get("freeze") == pin(freeze_path), "source_post_run_freeze_changed")
    return {"freeze": pin(freeze_path), "post_run_verification": pin(post_path), "count": len(seen)}


def validate_summary() -> dict[str, Any]:
    path = STAGE / "development-summary-001.json"
    summary = read_json(path)
    require(summary.get("batch") == 67, "batch67_summary_batch")
    require(summary.get("goal") == "active", "goal_not_active")
    require(summary.get("status") == "batch_completed_full_plan_continues", "batch67_summary_status")
    return {"summary": pin(path), "goal": summary["goal"], "status": summary["status"]}


def validate_regression() -> dict[str, Any]:
    boundary_path = STAGE / "full-execution-boundary-001.json"
    comparison_path = STAGE / "regression-comparison-001.json"
    xml_path = STAGE / "regression-full-001.xml"
    log_path = STAGE / "regression-full-001.log"
    boundary = read_json(boundary_path)
    comparison = read_json(comparison_path)
    require(boundary.get("batch") == 67 and boundary.get("runs") == 1,
            "batch67_full_execution_boundary")
    require(boundary.get("returncode") in (0, 1), "batch67_full_returncode")
    require(comparison.get("status") == "passed_no_new_failure_nodes",
            "regression_not_passed")
    require(comparison.get("new_failure_nodes") == [] and comparison.get("new_test_failures") == [],
            "regression_new_failures")
    require(comparison.get("no_new_bad") is True, "regression_no_new_bad_missing")
    require(xml_path.is_file() and log_path.is_file(), "regression_outputs_missing")
    return {
        "boundary": pin(boundary_path),
        "comparison": pin(comparison_path),
        "xml": pin(xml_path),
        "log": pin(log_path),
        "status": comparison["status"],
        "no_new_bad": comparison["no_new_bad"],
    }


def validate_live() -> dict[str, Any]:
    report_path = STAGE / "live-acceptance-001" / "report.json"
    report = read_json(report_path)
    require(report.get("status") == "passed", "live001_not_passed")
    require(report.get("server_exit_code") == 0, "live001_server_exit")
    checks = report.get("checks")
    require(isinstance(checks, dict) and checks and all(value is True for value in checks.values()),
            "live001_checks")
    for key in ("business_dispatch", "date_advance_save_restart_install", "information_tick_sent"):
        require(report.get(key) is False, f"live001_disallowed_action:{key}")
    require(report.get("native_read_only_queries") is True, "live001_native_read_only")
    return {
        "report": pin(report_path),
        "server_exit_code": report["server_exit_code"],
        "checks": len(checks),
        "native_read_only_queries": True,
    }


def validate_build() -> dict[str, Any]:
    for name in BUILD_REQUIRED:
        require((BUILD / name).is_file(), f"missing_build_receipt:{name}")
    installation = read_json(BUILD / "installation.json")
    manifest = read_json(BUILD / "build-manifest.json")
    status = read_json(BUILD / "information-battle-status.json")
    require(manifest.get("version") == 30, "build_version")
    require(manifest.get("experiment_id") == "diplomacy-observer-20261027-information-war-v30-004",
            "build_experiment")
    require(installation.get("installation_returncode") == 0, "installation_returncode")
    require(status.get("state") == "ready", "native_status_not_ready")
    require(str(status.get("captured")) == "0" and str(status.get("last_sequence")) == "0",
            "native_status_not_empty")
    require(status.get("code_patch_installed") is False, "native_status_patch_installed")
    require(status.get("business_export_available") is False, "native_status_business_export")
    for key in ("pid", "creation_filetime", "dll_sha256"):
        if key in installation and key in status:
            require(str(installation[key]) == str(status[key]), f"status_identity:{key}")
        if key in installation and key in manifest:
            require(str(installation[key]) == str(manifest[key]), f"manifest_identity:{key}")
    dll = pin(BUILD / "eu4_bridge_diplomacy_observer_v30.dll")
    require(dll["sha256"] == str(installation.get("dll_sha256")), "dll_hash_mismatch")

    preflight_path = STAGE / "new-build-preflight-001.json"
    preflight = read_json(preflight_path)
    require(preflight.get("status") == "passed" and preflight.get("installed") is False,
            "new_build_preflight")
    require(preflight.get("dll_sha256") == dll["sha256"], "preflight_dll_hash")
    require(preflight.get("manifest_sha256") == pin(BUILD / "build-manifest.json")["sha256"],
            "preflight_manifest_hash")
    require((BUILD / "control-probe.jsonl").stat().st_size <= COPY_LIMIT_BYTES,
            "control_probe_over_bound")

    optional_present = [name for name in BUILD_OPTIONAL if (BUILD / name).is_file()]
    optional_absent = [name for name in BUILD_OPTIONAL if not (BUILD / name).exists()]
    return {
        "installation": pin(BUILD / "installation.json"),
        "manifest": pin(BUILD / "build-manifest.json"),
        "dll": dll,
        "native_status": pin(BUILD / "information-battle-status.json"),
        "control_probe": pin(BUILD / "control-probe.jsonl"),
        "optional_present": optional_present,
        "optional_absent": optional_absent,
        "state": status["state"],
        "captured": status["captured"],
        "last_sequence": status["last_sequence"],
    }


def validate_previous_batch66() -> dict[str, Any]:
    archive = read_json(OLD66_ARCHIVE)
    require(archive.get("status") == "passed" and archive.get("batch") == 66,
            "batch66_archive_not_passed")
    artifacts = archive.get("artifacts")
    require(archive.get("artifact_count") == 274 and isinstance(artifacts, list)
            and len(artifacts) == 274, "batch66_archive_artifacts")
    for item in artifacts:
        require(isinstance(item, dict) and isinstance(item.get("path"), str),
                "batch66_archive_invalid_pin")
        require(pin(ROOT / item["path"]) == item, f"batch66_archive_pin_mismatch:{item['path']}")
    self_readback = read_json(OLD66_SELF_READBACK)
    require(self_readback.get("status") == "passed" and self_readback.get("artifact_count") == 274,
            "batch66_self_readback")
    final_readback = read_json(OLD66_FINAL_READBACK)
    require(final_readback.get("status") == "passed", "batch66_final_readback")
    declared = final_readback.get("scope", {}).get("archive_declared_artifacts")
    require(declared == 274, "batch66_final_readback_count")
    receipt = {
        "schema": "information.war_participants.previous_archive_readback.v1",
        "status": "passed",
        "source_batch": 66,
        "archive": pin(OLD66_ARCHIVE),
        "self_readback": pin(OLD66_SELF_READBACK),
        "independent_final_readback": pin(OLD66_FINAL_READBACK),
        "declared_artifacts": 274,
        "pins_checked": 274,
        "mismatches": 0,
        "old_stage_untouched": True,
    }
    write_new(PREVIOUS66_READBACK, receipt)
    return receipt


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
    optional_absent: list[str] = []
    for name in BUILD_OPTIONAL:
        source = BUILD / name
        if source.is_file():
            copies.append(copy_new(source, final_dir / name))
        else:
            optional_absent.append(name)

    # If a prepared build contains native control triplets, preserve them;
    # there is no requirement for such triplets when the source was never
    # enabled.
    for source in sorted(BUILD.iterdir()):
        if not source.is_file() or source.name in BUILD_REQUIRED or source.name in BUILD_OPTIONAL:
            continue
        if (CONTROL_AUDIT_RE.fullmatch(source.name)
                or CONTROL_STARTED_RE.fullmatch(source.name)
                or CONTROL_RESPONSE_RE.fullmatch(source.name)):
            copies.append(copy_new(source, final_dir / source.name))

    primary, sidecars = working_database_paths()
    require(primary, "working_databases_missing")
    backups = [backup_sqlite(source, database_dir / source.relative_to(STAGE)) for source in primary]
    excluded = [
        {
            "path": display_path(path),
            "bytes": path.stat().st_size,
            "reason": "working SQLite/WAL/SHM excluded; immutable read-only snapshot retained",
        }
        for path in primary + sidecars
    ]
    report = {
        "schema": "information.war_participants.database_snapshot_verification.v1",
        "status": "passed",
        "backups": backups,
        "working_database_exclusions": excluded,
        "optional_build_absent": optional_absent,
        "source_databases_modified": False,
        "source_wal_shm_deleted": False,
        "all_snapshots_closed_immutable_ro_verified": True,
    }
    write_new(DATABASE_VERIFICATION, report)
    return copies, report


def _marker(text: str, relative: str) -> str | None:
    for line in text.splitlines()[:12]:
        if line.strip() == BATCH_MARKER:
            return line.strip()
    if relative in MARKER_DOCUMENTS:
        raise ArchiveError(f"batch67_document_marker_missing:{relative}")
    return None


def snapshot_documents_and_supplements() -> tuple[dict[str, Any], dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    copies: list[dict[str, Any]] = []
    for relative in DOCUMENTS:
        source = ROOT / relative
        require(source.is_file(), f"missing_document:{relative}")
        text = source.read_text(encoding="utf-8-sig") if relative in MARKER_DOCUMENTS else ""
        marker = _marker(text, relative) if relative in MARKER_DOCUMENTS else None
        if relative.endswith(".json"):
            read_json(source)
        checks.append({"source": pin(source), "marker": marker})
        copies.append(copy_new(source, STAGE / "document-snapshots" / relative))
    document_report = {
        "schema": "information.war_participants.document_verification.v1",
        "status": "passed",
        "documents": checks,
        "snapshots": copies,
        "marker": BATCH_MARKER,
    }
    write_new(DOCUMENT_VERIFICATION, document_report)

    source_copies: list[dict[str, Any]] = []
    for relative in SUPPLEMENTAL_REQUIRED:
        source = ROOT / relative
        require(source.is_file(), f"missing_supplemental:{relative}")
        source_copies.append(copy_new(source, STAGE / "supplemental-source-snapshots" / relative))
    supplemental_report = {
        "schema": "information.war_participants.supplemental_source_verification.v1",
        "status": "passed",
        "files": source_copies,
        "count": len(source_copies),
        "scope": "batch67 participants validator, finalizer, and archive closure",
    }
    write_new(SUPPLEMENTAL_VERIFICATION, supplemental_report)
    return document_report, supplemental_report


def is_working_database_artifact(path: Path) -> bool:
    relative = path.relative_to(STAGE)
    if "final-database-snapshots" in relative.parts:
        return False
    lower = path.name.lower()
    return lower.endswith(("-wal", "-shm")) or path.suffix.lower() in {".sqlite", ".sqlite3", ".db"}


def stage_artifacts() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    artifacts: list[dict[str, Any]] = []
    exclusions: list[dict[str, Any]] = []
    for path in sorted(STAGE.rglob("*")):
        if not path.is_file():
            continue
        if path.name in EXCLUDED_MANIFEST_NAMES or path.name.startswith("final-readback"):
            continue
        if is_working_database_artifact(path):
            exclusions.append({
                "path": display_path(path),
                "bytes": path.stat().st_size,
                "reason": "working SQLite/WAL/SHM excluded; immutable snapshot retained",
            })
            continue
        artifacts.append(pin(path))
    return artifacts, exclusions


def ensure_outputs_absent() -> None:
    for path in (
        ARCHIVE,
        SELF_READBACK,
        RUNTIME_VERIFICATION,
        DATABASE_VERIFICATION,
        DOCUMENT_VERIFICATION,
        SUPPLEMENTAL_VERIFICATION,
        PREVIOUS66_READBACK,
        STAGE / "final-snapshots",
        STAGE / "final-database-snapshots",
        STAGE / "document-snapshots",
        STAGE / "supplemental-source-snapshots",
    ):
        require(not path.exists(), f"archive_already_started:{display_path(path)}")


def archive() -> dict[str, Any]:
    require(STAGE.is_dir() and BUILD.is_dir(), "stage_or_build_missing")
    ensure_outputs_absent()

    summary = validate_summary()
    source = validate_source_freeze()
    regression = validate_regression()
    live = validate_live()
    build = validate_build()
    previous66 = validate_previous_batch66()
    documents, supplemental = snapshot_documents_and_supplements()
    build_copies, database = snapshot_build_and_databases()

    runtime = {
        "schema": "information.war_participants.runtime_archive_verification.v1",
        "status": "passed",
        "batch": 67,
        "summary": summary,
        "source": source,
        "regression": regression,
        "live": live,
        "build": build,
        "previous_batch66": previous66,
        "documents": documents,
        "supplemental": supplemental,
        "build_snapshots": build_copies,
        "database_snapshots": database,
        "scope": {
            "game_started_by_archive": False,
            "mcp_started_by_archive": False,
            "tests_run_by_archive": False,
            "rea_or_disassembly": False,
            "working_databases_modified": False,
            "wal_shm_deleted": False,
        },
    }
    write_new(RUNTIME_VERIFICATION, runtime)

    artifacts, exclusions = stage_artifacts()
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
        "schema": "information_war_participants_archive.v1",
        "status": "passed",
        "batch": 67,
        "goal": "active",
        "stage": display_path(STAGE),
        "build": display_path(BUILD),
        "hash_chunk_bytes": HASH_CHUNK_BYTES,
        "copy_limit_bytes": COPY_LIMIT_BYTES,
        "source_count": SOURCE_COUNT,
        "runtime_verification": pin(RUNTIME_VERIFICATION),
        "artifacts": artifacts,
        "artifact_count": len(artifacts),
        "excluded_working_databases": exclusions,
        "database_verification": pin(DATABASE_VERIFICATION),
        "database_snapshots": database_manifest,
        "previous_batch66": previous66,
        "scope": {
            "game_started_by_archive": False,
            "mcp_started_by_archive": False,
            "tests_run_by_archive": False,
            "rea_or_disassembly": False,
            "working_database_files_in_artifacts": False,
            "wal_shm_in_artifacts": False,
            "immutable_snapshot_copies_only": True,
            "manifest_self_hash_excluded": True,
            "final_readback_hash_excluded": True,
        },
    }
    write_new(ARCHIVE, manifest)

    for item in artifacts:
        require(pin(ROOT / item["path"]) == item, f"final_readback_mismatch:{item['path']}")
    write_new(
        SELF_READBACK,
        {
            "schema": "information_war_participants_archive_readback.v1",
            "status": "passed",
            "batch": 67,
            "manifest": pin(ARCHIVE),
            "artifact_count": len(artifacts),
            "all_artifact_pins_rechecked": True,
            "working_database_exclusions_rechecked": len(exclusions),
            "database_snapshots_independent": True,
            "old66_pins_checked": previous66["pins_checked"],
            "manifest_self_hash_excluded": True,
            "final_readback_hash_excluded": True,
        },
    )
    return {
        "status": "passed",
        "batch": 67,
        "artifact_count": len(artifacts),
        "database_snapshots": len(database_manifest),
        "old66_pins_checked": previous66["pins_checked"],
        "readback": len(artifacts),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="perform the exclusive offline archive")
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({
            "status": "inert",
            "batch": 67,
            "stage": display_path(STAGE),
            "build": display_path(BUILD),
            "run_requires": "--run",
            "required_inputs": {
                "summary": display_path(STAGE / "development-summary-001.json"),
                "source_freeze": display_path(STAGE / "source-freeze-001.json"),
                "source_post_run": display_path(STAGE / "source-post-run-verification-001.json"),
                "full_boundary": display_path(STAGE / "full-execution-boundary-001.json"),
                "regression_comparison": display_path(STAGE / "regression-comparison-001.json"),
                "live_report": display_path(STAGE / "live-acceptance-001" / "report.json"),
                "old66_archive": display_path(OLD66_ARCHIVE),
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
