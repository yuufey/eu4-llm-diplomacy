"""Archive batch 66 war-score evidence without touching live state.

The default invocation is inert.  ``--run`` performs one exclusive-create
archive after the batch-66 source, full-suite, live, native, document, and
previous-archive checks pass.  It never starts a game, MCP server, test
runner, natural window, or reverse-engineering scan.

Working SQLite files are never copied as ordinary artifacts.  After the live
server receipt says it has exited, each working database is backed up through
SQLite into a new file, all writable connections are closed, and the new file
is checked through a separate ``mode=ro&immutable=1`` connection.  WAL/SHM
sidecars and the working database files stay outside the static artifact
manifest.
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
STAGE = Path(
    r"C:/Users/wangyufei/Documents/ChatGPT/欧陆风云4/"
    r"work/runtime/information-war-score-20261027-001"
).resolve()
BUILD = ROOT / "work/runtime/diplomacy-observer-20261027-information-battle-v30-003"

ARCHIVE = STAGE / "archive-verification-001.json"
SELF_READBACK = STAGE / "archive-self-readback-001.json"
RUNTIME_VERIFICATION = STAGE / "runtime-archive-verification-001.json"
DATABASE_VERIFICATION = STAGE / "database-snapshot-verification-001.json"
DOCUMENT_VERIFICATION = STAGE / "document-verification-001.json"
SUPPLEMENTAL_VERIFICATION = STAGE / "supplemental-source-verification-001.json"
PREVIOUS65_READBACK = STAGE / "previous-batch65-archive-readback-001.json"
LIVE_INDEPENDENT_AUDIT = STAGE / "live-independent-audit-001.json"
OLD65_PRESERVATION = STAGE / "old65-archive-preservation-001.json"

BASELINE65 = ROOT / "work/runtime/information-war-discovery-20261027-001"
BASELINE65_ARCHIVE = BASELINE65 / "archive-verification-001.json"
BASELINE65_FINAL_READBACK = BASELINE65 / "final-readback-001.json"

LIVE = STAGE / "live-acceptance-001"
HASH_CHUNK_BYTES = 1024 * 1024
COPY_LIMIT_BYTES = 16 * 1024 * 1024
JSON_LIMIT_BYTES = 4 * 1024 * 1024
SOURCE_COUNT = 159
BASELINE_SOURCE_COUNT = 154

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
    "docs/战争分数只读接口.md",
    "docs/战争分查询接口.md",
    "docs/逐场战报结算字段.md",
    "docs/战报订阅采集管理.md",
    "docs/战报原生文本读取与传输.md",
    "开发过程自动化.md",
)
MARKER_DOCUMENTS = {
    "HANDOFF.md",
    "README(agent).md",
    "docs/信息导出与订阅开发计划.md",
}

SUPPLEMENTAL_REQUIRED = (
    "work/verify_information_war_score.py",
    "work/validate_information_war_score_live.py",
    "work/run_r74_live_war_queries.py",
    "work/finalize_information_war_score.py",
    "work/archive_information_war_score.py",
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
        while True:
            chunk = incoming.read(HASH_CHUNK_BYTES)
            if not chunk:
                break
            outgoing.write(chunk)
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
    require(freeze.get("batch") == 66, "source_freeze_batch")
    require(freeze.get("count") == SOURCE_COUNT, "source_freeze_count")
    files = freeze.get("files")
    require(isinstance(files, list) and len(files) == SOURCE_COUNT, "source_freeze_files")
    paths: set[str] = set()
    checked = 0
    for item in files:
        require(isinstance(item, dict), "source_freeze_entry")
        expected_source = item.get("source")
        expected_snapshot = item.get("snapshot")
        require(
            isinstance(expected_source, dict) and isinstance(expected_snapshot, dict),
            "source_freeze_pins",
        )
        source_name = str(expected_source.get("path", ""))
        require(source_name not in paths, f"duplicate_source_freeze:{source_name}")
        paths.add(source_name)
        source = ROOT / source_name
        snapshot = ROOT / str(expected_snapshot.get("path", ""))
        require(pin(source) == expected_source, f"runtime_source_changed:{display_path(source)}")
        require(pin(snapshot) == expected_snapshot, f"runtime_snapshot_changed:{display_path(snapshot)}")
        require(
            expected_source.get("bytes") == expected_snapshot.get("bytes")
            and expected_source.get("sha256") == expected_snapshot.get("sha256"),
            f"source_snapshot_hash_mismatch:{display_path(source)}",
        )
        checked += 1
    require(
        {
            "bridge/war_score.py",
            "bridge/tests/test_war_score.py",
            "bridge/tests/test_information_war_score.py",
            "bridge/tests/fixtures/r74_live_war_score_real.json",
            "work/runtime/r74-live-war-queries-20261020-003/cases/selected_forward/public.json",
        }.issubset(paths),
        "war_score_sources_missing_from_freeze",
    )

    post_path = STAGE / "source-post-run-verification-001.json"
    post = read_json(post_path)
    require(post.get("status") == "passed", "source_post_run_verification_not_passed")
    require(post.get("count") == SOURCE_COUNT, "source_post_run_verification_count")
    require(post.get("current_matches_snapshots") is True, "source_current_snapshot_mismatch")
    post_freeze = post.get("freeze")
    require(isinstance(post_freeze, dict), "source_post_run_freeze_pin_missing")
    require(post_freeze == pin(freeze_path), "source_post_run_freeze_changed")
    return {"freeze": pin(freeze_path), "post_run_verification": pin(post_path), "count": checked}


def validate_summary() -> dict[str, Any]:
    path = STAGE / "development-summary-001.json"
    summary = read_json(path)
    require(summary.get("batch") == 66, "batch66_summary_batch")
    require(summary.get("goal") == "active", "goal_not_active")
    require(summary.get("status") == "batch_completed_full_plan_continues", "batch66_summary_status")
    return {"summary": pin(path), "batch": summary["batch"], "goal": summary["goal"], "status": summary["status"]}


def validate_regression() -> dict[str, Any]:
    xml_path = STAGE / "regression-full-001.xml"
    log_path = STAGE / "regression-full-001.log"
    boundary_path = STAGE / "full-execution-boundary-001.json"
    comparison_path = STAGE / "regression-comparison-001.json"
    require(xml_path.is_file() and log_path.is_file(), "batch66_regression_files_missing")
    boundary = read_json(boundary_path)
    require(boundary.get("runs") == 1, "batch66_full_not_single_run")
    require(boundary.get("returncode") in (0, 1), "batch66_full_returncode")
    comparison = read_json(comparison_path)
    require(comparison.get("status") == "passed_no_new_failure_nodes", "regression_not_passed")
    require(comparison.get("new_failure_nodes") == [], "regression_new_failure_nodes")
    require(comparison.get("new_test_failures") == [], "regression_new_test_failures")
    launcher_note_path = STAGE / "compare-launcher-note-001.json"
    launcher_note = read_json(launcher_note_path)
    require(launcher_note.get("status") == "corrected_without_test_rerun", "compare_launcher_note_status")
    require(launcher_note.get("tests_rerun") is False, "compare_launcher_note_tests_rerun")
    require(launcher_note.get("production_source_changed") is False, "compare_launcher_note_source_changed")
    return {
        "xml": pin(xml_path),
        "log": pin(log_path),
        "execution_boundary": pin(boundary_path),
        "comparison": pin(comparison_path),
        "compare_launcher_note": pin(launcher_note_path),
        "status": comparison["status"],
        "summary": comparison.get("summary_line"),
    }


def validate_live_receipts() -> dict[str, Any]:
    report_path = LIVE / "report.json"
    report = read_json(report_path)
    require(report.get("status") == "passed", "live001_not_passed")
    require(report.get("server_exit_code") == 0, "live001_server_exit")
    checks = report.get("checks")
    require(isinstance(checks, dict) and checks and all(value is True for value in checks.values()), "live001_checks")
    request_files = sorted(LIVE.glob("*-request.json"))
    response_files = sorted(LIVE.glob("*-response.json"))
    native_event_files = sorted(LIVE.glob("*-native-events.json"))
    require(request_files and response_files and native_event_files, "live001_request_logs_missing")
    require((LIVE / "mcp-transcript.json").is_file(), "live001_mcp_transcript_missing")
    require((LIVE / "mcp-stderr.txt").is_file(), "live001_mcp_stderr_missing")
    audit = read_json(LIVE_INDEPENDENT_AUDIT)
    require(audit.get("status") == "passed", "live_independent_audit_not_passed")
    preservation = read_json(OLD65_PRESERVATION)
    require(preservation.get("status") == "passed", "old65_preservation_not_passed")
    return {
        "report": pin(report_path),
        "server_exit_code": report["server_exit_code"],
        "checks": len(checks),
        "request_logs": len(request_files),
        "response_logs": len(response_files),
        "native_event_logs": len(native_event_files),
        "mcp_transcript": pin(LIVE / "mcp-transcript.json"),
        "independent_audit": pin(LIVE_INDEPENDENT_AUDIT),
        "old65_preservation": pin(OLD65_PRESERVATION),
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

    for key in ("pid", "creation_filetime", "dll_sha256"):
        if key in installation and key in native:
            require(str(installation[key]) == str(native[key]), f"native_identity:{key}")
        if key in installation and key in manifest:
            require(str(installation[key]) == str(manifest[key]), f"manifest_identity:{key}")
    # Some status writers intentionally omit game_sha256 and leave it null;
    # binding/journal/installation remain authoritative for that identity.
    if native.get("game_sha256") not in (None, ""):
        require(str(native["game_sha256"]) == str(installation.get("game_sha256")), "native_identity:game_sha256")
    require(str(binding.get("session_id")) == str(installation.get("session_id")), "binding_session")
    require(str(binding.get("dll_sha256")) == str(installation.get("dll_sha256")), "binding_dll")
    require(str(binding.get("game_sha256")) == str(installation.get("game_sha256")), "binding_game")

    raw_path = BUILD / "information-battle-raw.jsonl"
    raw_records = count_raw_records(raw_path)
    require(raw_records == 11, "native_raw_record_count")
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
        "binding": pin(BUILD / "information-battle-binding.json"),
        "native_status": pin(BUILD / "information-battle-status.json"),
        "capture_journal": pin(BUILD / "information-battle-capture-journal.json"),
        "raw_records": raw_records,
        "control_probe": pin(BUILD / "control-probe.jsonl"),
        "control_nonce_count": len(audits),
        "control_nonces": sorted(audits),
    }


def validate_previous_batch65() -> dict[str, Any]:
    archive = read_json(BASELINE65_ARCHIVE)
    require(archive.get("status") == "passed", "batch65_archive_not_passed")
    require(archive.get("batch") == 65, "batch65_archive_batch")
    require(archive.get("artifact_count") == 324, "batch65_archive_artifact_count")
    artifacts = archive.get("artifacts")
    require(isinstance(artifacts, list) and len(artifacts) == 324, "batch65_archive_artifacts")
    mismatches = []
    for item in artifacts:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            mismatches.append("invalid_pin")
            continue
        try:
            if pin(ROOT / item["path"]) != item:
                mismatches.append(item["path"])
        except ArchiveError:
            mismatches.append(item["path"])
    require(not mismatches, "batch65_archive_pin_mismatch:" + ",".join(mismatches[:8]))

    readback = read_json(BASELINE65_FINAL_READBACK)
    require(readback.get("status") == "passed", "batch65_final_readback_not_passed")
    declared = readback.get("scope", {}).get("archive_declared_artifacts")
    if declared is None:
        declared = readback.get("archive", {}).get("declared_artifact_count")
    require(declared == 324, "batch65_final_readback_count")
    receipt = {
        "schema": "information.war_score.previous_archive_readback.v1",
        "status": "passed",
        "source_batch": 65,
        "archive": pin(BASELINE65_ARCHIVE),
        "independent_final_readback": pin(BASELINE65_FINAL_READBACK),
        "declared_artifacts": 324,
        "pins_checked": 324,
        "mismatches": 0,
        "working_old_stage_untouched": True,
    }
    write_new(PREVIOUS65_READBACK, receipt)
    return receipt


def _active_subscription_count(connection: sqlite3.Connection, table_names: set[str]) -> int | None:
    if "info_config" not in table_names:
        return None
    with closing(connection.cursor()) as cursor:
        columns = {row[1] for row in cursor.execute("PRAGMA table_info(info_config)").fetchall()}
        require({"kind", "body"}.issubset(columns), "info_config_shape")
        rows = cursor.execute("SELECT kind,body FROM info_config").fetchall()
    active = 0
    for kind, body_text in rows:
        if kind != "subscription":
            continue
        body = json.loads(body_text)
        require(isinstance(body, dict), "info_config_subscription_body")
        if body.get("enabled") is True and body.get("state") in {"active", "enabled"}:
            active += 1
    return active


def _immutable_snapshot_check(path: Path) -> tuple[str, list[str], int | None]:
    uri = path.resolve().as_uri() + "?mode=ro&immutable=1"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        with closing(connection.cursor()) as cursor:
            integrity = cursor.execute("PRAGMA integrity_check").fetchone()[0]
            table_names = [
                row[0]
                for row in cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                ).fetchall()
            ]
        active = _active_subscription_count(connection, set(table_names))
    require(integrity == "ok", f"immutable_sqlite_integrity:{display_path(path)}:{integrity}")
    require(not path.with_name(path.name + "-wal").exists(), f"snapshot_wal_present:{display_path(path)}")
    require(not path.with_name(path.name + "-shm").exists(), f"snapshot_shm_present:{display_path(path)}")
    require(active in (None, 0), f"immutable_sqlite_active_subscriptions:{display_path(path)}:{active}")
    return integrity, table_names, active


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
    # Reserve the destination with O_EXCL before SQLite opens it for the
    # writable backup connection.  A failed run therefore cannot silently
    # reuse a previous database file.
    destination.open("xb").close()
    source_before = pin(source_path)
    source_uri = source_path.resolve().as_uri() + "?mode=ro"
    try:
        with closing(sqlite3.connect(source_uri, uri=True)) as source:
            source.execute("PRAGMA query_only=ON")
            with closing(source.cursor()) as cursor:
                source_integrity = cursor.execute("PRAGMA integrity_check").fetchone()[0]
                source_tables = [
                    row[0]
                    for row in cursor.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                    ).fetchall()
                ]
            require(source_integrity == "ok", f"sqlite_source_integrity:{display_path(source_path)}")
            source_active = _active_subscription_count(source, set(source_tables))
            require(source_active in (None, 0), f"sqlite_source_active:{display_path(source_path)}:{source_active}")
            with closing(sqlite3.connect(str(destination))) as target:
                source.backup(target)
                target.commit()
    except sqlite3.Error as exc:
        raise ArchiveError(f"sqlite_backup_failed:{display_path(source_path)}:{exc}") from exc

    source_after = pin(source_path)
    require(source_before == source_after, f"sqlite_source_changed:{display_path(source_path)}")
    integrity, table_names, active = _immutable_snapshot_check(destination)
    return {
        "snapshot": pin(destination),
        "integrity": integrity,
        "tables": table_names,
        "active_subscriptions": active,
        "source_path": source_before["path"],
        "source_bytes": source_before["bytes"],
        "source_sha256": source_before["sha256"],
        "backup_mode": "closed_server_read_only_source_to_fresh_snapshot",
        "snapshot_verification": "mode=ro&immutable=1",
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
    for nonce in sorted(audits):
        for source in (audits[nonce], started[nonce], responses[nonce]):
            copies.append(copy_new(source, final_dir / source.name))

    primary, sidecars = working_database_paths()
    require(primary, "working_databases_missing")
    backups = []
    for source in primary:
        backups.append(backup_sqlite(source, database_dir / source.relative_to(STAGE)))
    excluded = [
        {
            "path": display_path(path),
            "bytes": path.stat().st_size,
            "reason": "working SQLite/WAL/SHM excluded; only immutable read-only verified snapshot is archived",
        }
        for path in primary + sidecars
    ]
    database_report = {
        "schema": "information.war_score.database_snapshot_verification.v1",
        "status": "passed",
        "hash_chunk_bytes": HASH_CHUNK_BYTES,
        "backups": backups,
        "working_database_exclusions": excluded,
        "source_wal_shm_deleted": False,
        "source_databases_modified": False,
        "all_snapshots_closed_immutable_ro_verified": True,
    }
    write_new(DATABASE_VERIFICATION, database_report)
    return copies, database_report


def _current_batch_marker(text: str) -> str:
    for line in text.splitlines()[:12]:
        candidate = line.strip()
        if candidate.startswith("<!-- batch66-") and candidate.endswith(":start -->"):
            return candidate
    raise ArchiveError("batch66_document_marker_missing")


def snapshot_documents_and_supplements() -> tuple[dict[str, Any], dict[str, Any]]:
    document_checks: list[dict[str, Any]] = []
    markers: dict[str, str] = {}
    for relative in DOCUMENTS:
        source = ROOT / relative
        require(source.is_file(), f"missing_document:{relative}")
        marker_required = relative in MARKER_DOCUMENTS
        marker = None
        if marker_required:
            marker = _current_batch_marker(source.read_text(encoding="utf-8-sig"))
            markers[relative] = marker
        if relative.endswith(".json"):
            read_json(source)
        document_checks.append({"source": pin(source), "marker_required": marker_required, "marker": marker})

    document_copies = [copy_new(ROOT / relative, STAGE / "document-snapshots" / relative) for relative in DOCUMENTS]
    write_new(
        DOCUMENT_VERIFICATION,
        {
            "schema": "information.war_score.document_verification.v1",
            "status": "passed",
            "documents": document_checks,
            "snapshots": document_copies,
            "markers": markers,
            "goal": "active",
        },
    )

    source_copies = []
    for relative in SUPPLEMENTAL_REQUIRED:
        source = ROOT / relative
        require(source.is_file(), f"missing_supplemental:{relative}")
        source_copies.append(copy_new(source, STAGE / "supplemental-source-snapshots" / relative))
    write_new(
        SUPPLEMENTAL_VERIFICATION,
        {
            "schema": "information.war_score.supplemental_source_verification.v1",
            "status": "passed",
            "files": source_copies,
            "count": len(source_copies),
            "scope": "batch66 war-score validator, query helper, freeze/checker, and archive closure",
        },
    )
    return {"documents": document_checks, "markers": markers}, {"files": source_copies, "count": len(source_copies)}


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
                    "reason": "working database/WAL/SHM excluded; immutable snapshot retained",
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
        PREVIOUS65_READBACK,
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
    previous_check = validate_previous_batch65()
    document_check, supplemental_check = snapshot_documents_and_supplements()
    build_copies, database_check = snapshot_build_and_databases()

    runtime_check = {
        "schema": "information.war_score.runtime_archive_verification.v1",
        "status": "passed",
        "batch": 66,
        "summary": summary_check,
        "source": source_check,
        "regression": regression_check,
        "live": live_check,
        "build": build_check,
        "previous_batch65": previous_check,
        "build_snapshots": build_copies,
        "database_snapshots": database_check,
        "documents": document_check,
        "supplemental": supplemental_check,
        "scope": {
            "game_started": False,
            "mcp_started_by_archive": False,
            "new_natural_window_by_archive": False,
            "rea_or_disassembly": False,
            "working_databases_modified": False,
            "wal_shm_deleted": False,
        },
    }
    write_new(RUNTIME_VERIFICATION, runtime_check)

    artifacts, exclusions = stage_artifacts()
    database_manifest = [
        {
            "snapshot": item["snapshot"],
            "integrity": item["integrity"],
            "tables": item["tables"],
            "active_subscriptions": item["active_subscriptions"],
            "snapshot_verification": item["snapshot_verification"],
        }
        for item in database_check["backups"]
    ]
    manifest = {
        "schema": "information_war_score_archive.v1",
        "status": "passed",
        "batch": 66,
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
        "previous_batch65": previous_check,
        "scope": {
            "game_started_by_archive": False,
            "mcp_started_by_archive": False,
            "new_natural_window_by_archive": False,
            "working_database_files_in_artifacts": False,
            "wal_shm_in_artifacts": False,
            "immutable_snapshot_copies_only": True,
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
            "schema": "information_war_score_archive_readback.v1",
            "status": "passed",
            "batch": 66,
            "manifest": pin(ARCHIVE),
            "artifact_count": artifact_readback,
            "all_artifact_pins_rechecked": True,
            "working_database_exclusions_rechecked": len(exclusions),
            "database_snapshots_independent": True,
            "manifest_self_hash_excluded": True,
        },
    )
    return {
        "status": "passed",
        "batch": 66,
        "artifact_count": len(artifacts),
        "database_snapshots": len(database_manifest),
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
                    "batch": 66,
                    "stage": display_path(STAGE),
                    "build": display_path(BUILD),
                    "run_requires": "--run",
                    "required_inputs": {
                        "source_freeze": display_path(STAGE / "source-freeze-001.json"),
                        "source_post_run": display_path(STAGE / "source-post-run-verification-001.json"),
                        "full_xml": display_path(STAGE / "regression-full-001.xml"),
                        "full_log": display_path(STAGE / "regression-full-001.log"),
                        "full_execution_boundary": display_path(STAGE / "full-execution-boundary-001.json"),
                        "comparison": display_path(STAGE / "regression-comparison-001.json"),
                        "compare_launcher_note": display_path(STAGE / "compare-launcher-note-001.json"),
                        "live_report": display_path(LIVE / "report.json"),
                        "live_independent_audit": display_path(LIVE_INDEPENDENT_AUDIT),
                        "old65_preservation": display_path(OLD65_PRESERVATION),
                        "summary": display_path(STAGE / "development-summary-001.json"),
                    },
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
