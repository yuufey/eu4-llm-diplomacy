"""Archive batch 65 W01 war-discovery evidence without touching live state.

The default invocation is inert.  ``--run`` performs one exclusive-create
archive after the source freeze, live receipts, build identity, document,
database, and previous batch checks pass.  It never starts a game, MCP server,
test runner, natural window, or reverse-engineering scan.  Working SQLite
files are opened read-only and copied with ``Connection.backup`` into
independent snapshots; original databases and WAL/SHM sidecars are retained.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import shutil
import sqlite3
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-war-discovery-20261027-001"
BUILD = ROOT / "work/runtime/diplomacy-observer-20261027-information-battle-v30-003"

ARCHIVE = STAGE / "archive-verification-001.json"
SELF_READBACK = STAGE / "archive-self-readback-001.json"
RUNTIME_VERIFICATION = STAGE / "runtime-archive-verification-001.json"
DATABASE_VERIFICATION = STAGE / "database-snapshot-verification-001.json"
DOCUMENT_VERIFICATION = STAGE / "document-verification-001.json"
SUPPLEMENTAL_VERIFICATION = STAGE / "supplemental-source-verification-001.json"

BASELINE64 = ROOT / "work/runtime/information-battle-autonomous-live-20261027-001"
BASELINE64_ARCHIVE = BASELINE64 / "archive-verification-001.json"
BASELINE64_FINAL_READBACK = BASELINE64 / "final-readback-001.json"

HASH_CHUNK_BYTES = 1024 * 1024
COPY_LIMIT_BYTES = 16 * 1024 * 1024
JSON_LIMIT_BYTES = 4 * 1024 * 1024
SOURCE_COUNT = 154
MARKER = "<!-- batch65-war-discovery-summary:start -->"

BUILD_SNAPSHOT_NAMES = (
    "installation.json",
    "build-manifest.json",
    "eu4_bridge_diplomacy_observer_v30.dll",
    "information-battle-binding.json",
    "information-battle-status.json",
    "information-battle-capture-journal.json",
    "information-battle-raw.jsonl",
    "control-probe.jsonl",
)

DOCUMENTS = (
    "HANDOFF.md",
    "README(agent).md",
    "docs/信息导出与订阅开发计划.md",
    "docs/信息字段覆盖.json",
    "docs/战争发现与议和信息接口.md",
    "docs/战报原生文本读取与传输.md",
    "开发过程自动化.md",
)
MARKER_DOCUMENTS = {"HANDOFF.md", "README(agent).md", "docs/信息导出与订阅开发计划.md"}

SUPPLEMENTAL_REQUIRED = (
    "work/verify_information_war_discovery.py",
    "work/validate_information_war_peace_discovery_live.py",
    "work/finalize_information_war_discovery.py",
    "work/archive_information_war_discovery.py",
)

CONTROL_AUDIT_RE = re.compile(r"information-battle-control-audit-([0-9a-f]{32})\.jsonl\Z")
CONTROL_STARTED_RE = re.compile(r"information-battle-started-([0-9a-f]{32})\.json\Z")
CONTROL_RESPONSE_RE = re.compile(r"information-battle-response-([0-9a-f]{32})\.json\Z")

EXCLUDED_MANIFEST_NAMES = {
    "archive-verification-001.json",
    "archive-self-readback-001.json",
    "final-readback-001.json",
}


class ArchiveError(RuntimeError):
    """Fail-closed archive validation or exclusive-copy error."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ArchiveError(message)


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT.resolve()).as_posix()
    except ValueError as exc:
        raise ArchiveError(f"path_outside_workspace:{resolved}") from exc


def file_identity(path: Path) -> tuple[int, int, int, int]:
    stat = path.stat()
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns


def stream_sha256(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(HASH_CHUNK_BYTES)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def pin(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ArchiveError(f"missing_file:{display_path(path)}")
    size, digest = stream_sha256(path)
    return {"path": display_path(path), "bytes": size, "sha256": digest}


def read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ArchiveError(f"missing_json:{display_path(path)}")
    if path.stat().st_size > JSON_LIMIT_BYTES:
        raise ArchiveError(f"json_over_bound:{display_path(path)}")
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ArchiveError(f"invalid_json:{display_path(path)}:{exc}") from exc
    if not isinstance(value, dict):
        raise ArchiveError(f"json_object_required:{display_path(path)}")
    return value


def write_new(path: Path, value: Any) -> None:
    if path.exists():
        raise ArchiveError(f"refusing_to_overwrite:{display_path(path)}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()


def copy_new(source: Path, destination: Path, *, limit: int = COPY_LIMIT_BYTES) -> dict[str, Any]:
    if not source.is_file():
        raise ArchiveError(f"missing_copy_source:{display_path(source)}")
    if destination.exists():
        raise ArchiveError(f"refusing_to_overwrite:{display_path(destination)}")
    before_identity = file_identity(source)
    before_size, before_sha = stream_sha256(source)
    if before_size > limit:
        raise ArchiveError(f"copy_over_bound:{display_path(source)}:{before_size}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as incoming, destination.open("xb") as outgoing:
        shutil.copyfileobj(incoming, outgoing, length=HASH_CHUNK_BYTES)
        outgoing.flush()
    after_identity = file_identity(source)
    after_size, after_sha = stream_sha256(source)
    copied_size, copied_sha = stream_sha256(destination)
    require(
        before_identity == after_identity
        and (before_size, before_sha) == (after_size, after_sha),
        f"source_changed_during_copy:{display_path(source)}",
    )
    require(
        (copied_size, copied_sha) == (before_size, before_sha),
        f"copy_hash_mismatch:{display_path(destination)}",
    )
    return {
        "source": {"path": display_path(source), "bytes": before_size, "sha256": before_sha},
        "snapshot": pin(destination),
        "source_identity_stable": True,
    }


def validate_source_freeze() -> dict[str, Any]:
    freeze_path = STAGE / "source-freeze-001.json"
    freeze = read_json(freeze_path)
    require(freeze.get("status") == "passed", "source_freeze_not_passed")
    require(freeze.get("batch") == 65, "source_freeze_batch")
    require(freeze.get("count") == SOURCE_COUNT, "source_freeze_count")
    files = freeze.get("files")
    require(isinstance(files, list) and len(files) == SOURCE_COUNT, "source_freeze_files")
    checked = 0
    for item in files:
        require(isinstance(item, dict), "source_freeze_entry")
        expected_source = item.get("source")
        expected_snapshot = item.get("snapshot")
        require(
            isinstance(expected_source, dict) and isinstance(expected_snapshot, dict),
            "source_freeze_pins",
        )
        source = ROOT / str(expected_source.get("path", ""))
        snapshot = ROOT / str(expected_snapshot.get("path", ""))
        require(pin(source) == expected_source, f"runtime_source_changed:{display_path(source)}")
        require(
            pin(snapshot) == expected_snapshot,
            f"runtime_snapshot_changed:{display_path(snapshot)}",
        )
        require(
            expected_source.get("bytes") == expected_snapshot.get("bytes")
            and expected_source.get("sha256") == expected_snapshot.get("sha256"),
            f"source_snapshot_hash_mismatch:{display_path(source)}",
        )
        checked += 1

    post_path = STAGE / "source-post-run-verification-001.json"
    post = read_json(post_path)
    require(post.get("status") == "passed", "source_post_run_verification_not_passed")
    require(post.get("count") == SOURCE_COUNT, "source_post_run_verification_count")
    post_freeze = post.get("freeze")
    require(isinstance(post_freeze, dict), "source_post_run_freeze_pin_missing")
    require(post_freeze == pin(freeze_path), "source_post_run_freeze_changed")
    return {
        "freeze": pin(freeze_path),
        "post_run_verification": pin(post_path),
        "count": checked,
    }


def validate_summary() -> dict[str, Any]:
    path = STAGE / "development-summary-001.json"
    summary = read_json(path)
    require(summary.get("goal") == "active", "goal_not_active")
    require(
        summary.get("status") == "batch_completed_full_plan_continues",
        "batch65_summary_status",
    )
    return {"summary": pin(path), "goal": summary["goal"], "status": summary["status"]}


def validate_regression() -> dict[str, Any]:
    path = STAGE / "regression-comparison-001.json"
    value = read_json(path)
    require(value.get("status") == "passed_no_new_failure_nodes", "regression_not_passed")
    require(value.get("new_failure_nodes") == [], "regression_new_failure_nodes")
    require(value.get("new_test_failures") == [], "regression_new_test_failures")
    return {"comparison": pin(path), "status": value["status"], "summary": value.get("summary_line")}


def validate_live_receipts() -> dict[str, Any]:
    report_path = STAGE / "live-acceptance-003" / "report.json"
    report = read_json(report_path)
    require(report.get("status") == "passed", "live003_not_passed")
    require(report.get("server_exit_code") == 0, "live003_server_exit")
    checks = report.get("checks")
    require(isinstance(checks, dict) and checks and all(value is True for value in checks.values()), "live003_checks")

    audit_path = STAGE / "live-final-audit-001.json"
    audit = read_json(audit_path)
    require(audit.get("status") in {"passed", "passed_read_only_audit_with_future_same_server_unverified"}, "live_final_audit_not_passed")
    require(audit["old64_archive_532"]["all_declared_pins_match"] is True, "historical_archive_mismatch")
    require(audit["service_database"]["active_zero"] is True, "active_subscriptions_remain")
    require(read_json(STAGE / "live-final-audit-scope-note-001.json")["status"] == "passed", "audit_scope_correction_missing")
    return {
        "report": pin(report_path),
        "final_audit": pin(audit_path),
        "server_exit_code": report["server_exit_code"],
        "checks": len(checks),
    }


def validate_batch64_archive() -> dict[str, Any]:
    archive = read_json(BASELINE64_ARCHIVE)
    require(archive.get("status") == "passed", "batch64_archive_not_passed")
    require(archive.get("batch") == 64, "batch64_archive_batch")
    require(archive.get("artifact_count") == 532, "batch64_archive_artifact_count")
    artifacts = archive.get("artifacts")
    require(isinstance(artifacts, list) and len(artifacts) == 532, "batch64_archive_artifacts")

    readback_path = BASELINE64_FINAL_READBACK
    readback = read_json(readback_path)
    require(readback.get("status") == "passed", "batch64_final_readback_not_passed")
    archive_receipt = readback.get("archive")
    require(isinstance(archive_receipt, dict), "batch64_final_readback_archive")
    require(archive_receipt.get("declared_artifact_count") == 532, "batch64_readback_count")
    counts = archive_receipt.get("artifact_counts")
    require(isinstance(counts, dict), "batch64_readback_counts")
    for key in ("references", "matches"):
        require(counts.get(key) == 532, f"batch64_readback_{key}")
    for key in ("mismatches", "missing", "read_errors", "invalid_pins"):
        require(counts.get(key) == 0, f"batch64_readback_{key}")
    return {
        "archive": pin(BASELINE64_ARCHIVE),
        "independent_readback": pin(readback_path),
        "artifact_count": 532,
        "independent_audit": True,
    }


def count_raw_records(path: Path) -> int:
    require(path.stat().st_size <= COPY_LIMIT_BYTES, f"raw_over_bound:{display_path(path)}")
    count = 0
    header_seen = False
    with path.open("r", encoding="utf-8", newline="") as stream:
        for line_number, line in enumerate(stream, 1):
            line = line.strip()
            if not line:
                continue
            if not header_seen:
                require(line.startswith("EU4_OWNED_BATTLE_WIRE_V1 "), f"raw_header:{line_number}")
                header_seen = True
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ArchiveError(f"raw_json:{line_number}:{exc}") from exc
            require(
                isinstance(value, dict) and value.get("event") == "information_owned_battle_record",
                f"raw_record:{line_number}",
            )
            count += 1
    require(header_seen, "raw_header_missing")
    return count


def validate_build_receipts() -> dict[str, Any]:
    for name in BUILD_SNAPSHOT_NAMES:
        require((BUILD / name).is_file(), f"missing_build_receipt:{name}")
    installation = read_json(BUILD / "installation.json")
    manifest = read_json(BUILD / "build-manifest.json")
    binding = read_json(BUILD / "information-battle-binding.json")
    native = read_json(BUILD / "information-battle-status.json")
    journal = read_json(BUILD / "information-battle-capture-journal.json")

    experiment = "diplomacy-observer-20261027-information-battle-v30-003"
    require(manifest.get("version") == 30, "build_version")
    require(manifest.get("experiment_id") == experiment, "build_experiment")
    require(native.get("state") == "disabled", "native_not_disabled")
    require(str(native.get("captured")) == "11", "native_captured_count")
    require(str(native.get("last_sequence")) == "11", "native_last_sequence")
    require(journal.get("state") == "completed-disabled", "journal_not_completed_disabled")
    require(journal.get("owned") is False, "journal_still_owned")

    identity_keys = ("pid", "creation_filetime", "dll_sha256", "game_sha256")
    for key in identity_keys:
        if key in installation and key in native:
            require(str(installation[key]) == str(native[key]), f"native_identity:{key}")
        if key in installation and key in manifest:
            require(str(installation[key]) == str(manifest[key]), f"manifest_identity:{key}")
    require(str(binding.get("session_id")) == str(installation.get("session_id")), "binding_session")
    require(str(binding.get("dll_sha256")) == str(installation.get("dll_sha256")), "binding_dll")
    require(str(binding.get("game_sha256")) == str(installation.get("game_sha256")), "binding_game")

    raw_path = BUILD / "information-battle-raw.jsonl"
    require(count_raw_records(raw_path) == 11, "native_raw_record_count")
    require((BUILD / "control-probe.jsonl").stat().st_size <= COPY_LIMIT_BYTES, "control_probe_over_bound")

    audits = {
        match.group(1): path
        for path in BUILD.iterdir()
        if path.is_file() and (match := CONTROL_AUDIT_RE.fullmatch(path.name))
    }
    started = {
        match.group(1): path
        for path in BUILD.iterdir()
        if path.is_file() and (match := CONTROL_STARTED_RE.fullmatch(path.name))
    }
    responses = {
        match.group(1): path
        for path in BUILD.iterdir()
        if path.is_file() and (match := CONTROL_RESPONSE_RE.fullmatch(path.name))
    }
    require(audits and set(audits) == set(started) == set(responses), "native_control_receipt_triplets")
    return {
        "installation": pin(BUILD / "installation.json"),
        "manifest": pin(BUILD / "build-manifest.json"),
        "dll": pin(BUILD / "eu4_bridge_diplomacy_observer_v30.dll"),
        "native_status": pin(BUILD / "information-battle-status.json"),
        "capture_journal": pin(BUILD / "information-battle-capture-journal.json"),
        "raw_records": 11,
        "control_probe": pin(BUILD / "control-probe.jsonl"),
        "control_nonce_count": len(audits),
        "control_nonces": sorted(audits),
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


def backup_sqlite(source_path: Path, destination: Path) -> dict[str, Any]:
    if destination.exists():
        raise ArchiveError(f"refusing_to_overwrite:{display_path(destination)}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_before = pin(source_path)
    destination.open("xb").close()
    source_uri = source_path.resolve().as_uri() + "?mode=ro"
    try:
        with closing(sqlite3.connect(source_uri, uri=True)) as source:
            source.execute("PRAGMA query_only=ON")
            with closing(sqlite3.connect(destination)) as target:
                source.backup(target)
                target.commit()
                integrity = target.execute("PRAGMA integrity_check").fetchone()[0]
                table_names = [
                    row[0]
                    for row in target.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                    )
                ]
                active: int | None = None
                if "info_config" in table_names:
                    columns = {row[1] for row in target.execute("PRAGMA table_info(info_config)")}
                    require({"kind", "body"}.issubset(columns), "info_config_shape")
                    active = target.execute(
                        "SELECT COUNT(*) FROM info_config "
                        "WHERE kind='subscription' "
                        "AND json_extract(body, '$.state') IN ('active','enabled')"
                    ).fetchone()[0]
                require(integrity == "ok", f"sqlite_integrity:{display_path(source_path)}:{integrity}")
                require(active in (None, 0), f"sqlite_active_subscriptions:{display_path(source_path)}:{active}")
    except sqlite3.Error as exc:
        raise ArchiveError(f"sqlite_backup_failed:{display_path(source_path)}:{exc}") from exc
    source_after = pin(source_path)
    require(source_before == source_after, f"sqlite_source_changed:{display_path(source_path)}")
    return {
        "source": source_before,
        "snapshot": pin(destination),
        "integrity": integrity,
        "tables": table_names,
        "active_subscriptions": active,
        "backup_mode": "read_only_source_connection_to_independent_snapshot",
        "contextlib_closing": True,
    }


def snapshot_build_and_databases() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    final_dir = STAGE / "final-snapshots"
    database_dir = STAGE / "final-database-snapshots"
    final_dir.mkdir(exist_ok=False)
    database_dir.mkdir(exist_ok=False)

    copies: list[dict[str, Any]] = []
    for name in BUILD_SNAPSHOT_NAMES:
        copies.append(copy_new(BUILD / name, final_dir / name))

    audits = {
        match.group(1): path
        for path in BUILD.iterdir()
        if path.is_file() and (match := CONTROL_AUDIT_RE.fullmatch(path.name))
    }
    require(audits, "native_control_audits_missing")
    for nonce in sorted(audits):
        for source in (
            audits[nonce],
            BUILD / f"information-battle-started-{nonce}.json",
            BUILD / f"information-battle-response-{nonce}.json",
        ):
            copies.append(copy_new(source, final_dir / source.name))

    primary, sidecars = working_database_paths()
    backups = []
    for source in primary:
        backups.append(backup_sqlite(source, database_dir / source.relative_to(STAGE)))
    excluded = [
        {
            "path": display_path(path),
            "bytes": path.stat().st_size,
            "reason": "working SQLite or WAL/SHM sidecar excluded from archive artifacts; independent database snapshot is retained",
        }
        for path in primary + sidecars
    ]
    database_report = {
        "status": "passed",
        "hash_chunk_bytes": HASH_CHUNK_BYTES,
        "backups": backups,
        "working_database_exclusions": excluded,
        "source_wal_shm_deleted": False,
        "source_databases_modified": False,
    }
    write_new(DATABASE_VERIFICATION, database_report)
    return copies, database_report


def snapshot_documents_and_supplements() -> tuple[dict[str, Any], dict[str, Any]]:
    document_checks: list[dict[str, Any]] = []
    for relative in DOCUMENTS:
        source = ROOT / relative
        require(source.is_file(), f"missing_document:{relative}")
        if relative in MARKER_DOCUMENTS:
            text = source.read_text(encoding="utf-8-sig")
            require(text.startswith(MARKER), f"document_marker_missing:{relative}")
        if relative.endswith(".json"):
            read_json(source)
        document_checks.append({"source": pin(source), "marker_required": relative in MARKER_DOCUMENTS})

    document_copies = [
        copy_new(ROOT / relative, STAGE / "document-snapshots" / relative)
        for relative in DOCUMENTS
    ]
    write_new(
        DOCUMENT_VERIFICATION,
        {
            "status": "passed",
            "documents": document_checks,
            "snapshots": document_copies,
            "marker": MARKER,
            "goal": "active",
        },
    )

    source_copies = []
    for relative in SUPPLEMENTAL_REQUIRED:
        source = ROOT / relative
        require(source.is_file(), f"missing_supplemental:{relative}")
        source_copies.append(
            copy_new(source, STAGE / "supplemental-source-snapshots" / source.relative_to(ROOT))
        )
    write_new(
        SUPPLEMENTAL_VERIFICATION,
        {
            "status": "passed",
            "files": source_copies,
            "count": len(source_copies),
            "scope": "batch65 W01 verification, live validator, finalizer, and archive",
        },
    )
    return {"documents": document_checks, "marker": MARKER}, {"files": source_copies, "count": len(source_copies)}


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
        if path.name in EXCLUDED_MANIFEST_NAMES:
            continue
        if is_working_database_artifact(path):
            exclusions.append(
                {
                    "path": display_path(path),
                    "bytes": path.stat().st_size,
                    "reason": "working database/WAL/SHM excluded; independent final-database-snapshots retained",
                }
            )
            continue
        artifacts.append(pin(path))
    return artifacts, exclusions


def ensure_outputs_absent() -> None:
    outputs = (
        ARCHIVE,
        SELF_READBACK,
        RUNTIME_VERIFICATION,
        DATABASE_VERIFICATION,
        DOCUMENT_VERIFICATION,
        SUPPLEMENTAL_VERIFICATION,
        STAGE / "final-snapshots",
        STAGE / "final-database-snapshots",
        STAGE / "document-snapshots",
        STAGE / "supplemental-source-snapshots",
    )
    for path in outputs:
        require(not path.exists(), f"archive_already_started:{display_path(path)}")


def archive() -> dict[str, Any]:
    require(STAGE.is_dir() and BUILD.is_dir(), "stage_or_build_missing")
    ensure_outputs_absent()

    summary_check = validate_summary()
    source_check = validate_source_freeze()
    regression_check = validate_regression()
    live_check = validate_live_receipts()
    build_check = validate_build_receipts()
    batch64_check = validate_batch64_archive()
    document_check, supplemental_check = snapshot_documents_and_supplements()
    build_copies, database_check = snapshot_build_and_databases()

    runtime_check = {
        "status": "passed",
        "batch": 65,
        "summary": summary_check,
        "source": source_check,
        "regression": regression_check,
        "live": live_check,
        "build": build_check,
        "previous_batch64": batch64_check,
        "build_snapshots": build_copies,
        "database_snapshots": database_check,
        "documents": document_check,
        "supplemental": supplemental_check,
        "native_state": "disabled",
        "capture_journal": "completed-disabled/unowned",
        "scope": {
            "game_started": False,
            "mcp_started": False,
            "new_natural_window": False,
            "rea_or_disassembly": False,
            "working_databases_modified": False,
            "wal_shm_deleted": False,
        },
    }
    write_new(RUNTIME_VERIFICATION, runtime_check)

    artifacts, exclusions = stage_artifacts()
    manifest = {
        "schema": "information_war_discovery_archive.v1",
        "status": "passed",
        "batch": 65,
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
        "database_snapshots": database_check["backups"],
        "previous_batch64": batch64_check,
        "scope": {
            "game_started": False,
            "mcp_started": False,
            "new_natural_window": False,
            "rea_or_disassembly": False,
            "working_database_files_pinned_directly": False,
            "wal_shm_deleted": False,
        },
    }
    write_new(ARCHIVE, manifest)

    artifact_readback = 0
    for item in artifacts:
        require(pin(ROOT / item["path"]) == item, f"final_readback_mismatch:{item['path']}")
        artifact_readback += 1
    write_new(
        SELF_READBACK,
        {
            "schema": "information_war_discovery_archive_readback.v1",
            "status": "passed",
            "manifest": pin(ARCHIVE),
            "artifact_count": artifact_readback,
            "all_artifact_pins_rechecked": True,
            "working_database_exclusions_rechecked": len(exclusions),
            "database_snapshots_independent": True,
        },
    )
    return {
        "status": "passed",
        "batch": 65,
        "artifact_count": len(artifacts),
        "database_snapshots": len(database_check["backups"]),
        "control_receipt_snapshots": build_check["control_nonce_count"],
        "readback": artifact_readback,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="perform the exclusive offline archive")
    args = parser.parse_args()
    if not args.run:
        print(
            json.dumps(
                {
                    "status": "inert",
                    "batch": 65,
                    "stage": display_path(STAGE),
                    "build": display_path(BUILD),
                    "run_requires": "--run",
                },
                ensure_ascii=False,
            )
        )
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
