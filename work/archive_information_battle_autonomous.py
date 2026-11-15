"""Archive batch64 autonomous battle-capture evidence without touching live state.

The default invocation is inert.  ``--run`` performs one exclusive-create archive
after the full source, receipt, document, and database checks pass.  It never
starts a game, MCP server, test runner, natural window, or reverse-engineering
scan.  SQLite sources are opened read-only and copied with ``Connection.backup``
to independent snapshots; source WAL/SHM files are retained and only recorded
as excluded working files.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import shutil
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-battle-autonomous-live-20261027-001"
BUILD = ROOT / "work/runtime/diplomacy-observer-20261027-information-battle-v30-003"
ARCHIVE = STAGE / "archive-verification-001.json"
FINAL_READBACK = STAGE / "archive-self-readback-001.json"
HASH_CHUNK_BYTES = 1024 * 1024
COPY_LIMIT_BYTES = 16 * 1024 * 1024
JSON_LIMIT_BYTES = 4 * 1024 * 1024
SOURCE_COUNT = 152
HISTORICAL_REFERENCE_COUNT = 987
MARKER = "<!-- batch64-autonomous-live-summary:start -->"

DOCUMENTS = (
    "HANDOFF.md",
    "README(agent).md",
    "docs/信息导出与订阅开发计划.md",
    "docs/战报订阅采集管理.md",
    "开发过程自动化.md",
)

SUPPLEMENTAL_REQUIRED = (
    "work/verify_information_battle_autonomous.py",
    "work/validate_information_battle_capture_autonomous_live.py",
    "work/bootstrap_information_battle_subscription.py",
    "work/validate_information_battle_status_reader_recovery.py",
    "work/save_information_battle_terminal_checkpoint.py",
    "work/finalize_information_battle_autonomous.py",
    "work/archive_information_battle_autonomous.py",
    "work/validate_information_peace_overextension_live.py",
)

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

CONTROL_AUDIT_RE = re.compile(r"information-battle-control-audit-([0-9a-f]{32})\.jsonl\Z")
CONTROL_STARTED_RE = re.compile(r"information-battle-started-([0-9a-f]{32})\.json\Z")
CONTROL_RESPONSE_RE = re.compile(r"information-battle-response-([0-9a-f]{32})\.json\Z")


class ArchiveError(RuntimeError):
    """Fail-closed archive validation or exclusive-copy error."""


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT.resolve()).as_posix()
    except ValueError as exc:
        raise ArchiveError(f"path_outside_workspace:{resolved}") from exc


def file_identity(path: Path) -> tuple[int, int, int, int]:
    stat = path.stat()
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)


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
    if before_identity != after_identity or before_size != after_size or before_sha != after_sha:
        raise ArchiveError(f"source_changed_during_copy:{display_path(source)}")
    if (copied_size, copied_sha) != (before_size, before_sha):
        raise ArchiveError(f"copy_hash_mismatch:{display_path(destination)}")
    return {
        "source": {"path": display_path(source), "bytes": before_size, "sha256": before_sha},
        "snapshot": pin(destination),
        "source_identity_stable": True,
    }


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ArchiveError(message)


def validate_goal_and_documents() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    for index, relative in enumerate(DOCUMENTS):
        path = ROOT / relative
        if not path.is_file():
            raise ArchiveError(f"missing_document:{relative}")
        text = path.read_text(encoding="utf-8-sig")
        if index < 3:
            require(text.startswith(MARKER), f"document_marker_missing:{relative}")
        docs.append({"source": pin(path), "goal_active": "goal active" in text[:16000]})
    require(any(item["goal_active"] for item in docs[:3]), "goal_not_active_in_latest_documents")
    return docs, {"marker": MARKER, "top_three_marked": True}


def validate_summary_if_present() -> dict[str, Any] | None:
    summaries = sorted(STAGE.glob("development-summary-*.json"))
    if not summaries:
        return None
    summary_path = summaries[-1]
    summary = read_json(summary_path)
    goal = summary.get("goal", summary.get("goal_status"))
    require(goal == "active", f"summary_goal_not_active:{display_path(summary_path)}")
    return {"summary": pin(summary_path), "goal": goal}


def validate_source_freeze() -> dict[str, Any]:
    freeze_path = STAGE / "source-freeze-002.json"
    freeze = read_json(freeze_path)
    require(freeze.get("status") == "passed", "source_freeze_not_passed")
    require(freeze.get("batch") == 64, "source_freeze_batch")
    require(freeze.get("count") == SOURCE_COUNT, "source_freeze_count")
    files = freeze.get("files")
    require(isinstance(files, list) and len(files) == SOURCE_COUNT, "source_freeze_files")
    checked: list[dict[str, Any]] = []
    for item in files:
        require(isinstance(item, dict), "source_freeze_entry")
        source_expected = item.get("source")
        snapshot_expected = item.get("snapshot")
        require(isinstance(source_expected, dict) and isinstance(snapshot_expected, dict), "source_freeze_pins")
        source = ROOT / str(source_expected.get("path", ""))
        snapshot = ROOT / str(snapshot_expected.get("path", ""))
        require(pin(source) == source_expected, f"runtime_source_changed:{display_path(source)}")
        require(pin(snapshot) == snapshot_expected, f"runtime_snapshot_changed:{display_path(snapshot)}")
        checked.append({"source": source_expected, "snapshot": snapshot_expected})

    post_path = STAGE / "source-post-run-verification-002.json"
    post = read_json(post_path)
    require(post.get("status") == "passed", "source_post_run_verification_not_passed")
    require(post.get("count") == SOURCE_COUNT, "source_post_run_verification_count")
    freeze_pin = pin(freeze_path)
    post_freeze = post.get("freeze") or post.get("source_freeze") or post.get("source_freeze_002")
    require(isinstance(post_freeze, dict), "source_post_run_freeze_pin_missing")
    require(post_freeze.get("path") == freeze_pin["path"] and post_freeze.get("sha256") == freeze_pin["sha256"],
            "source_post_run_freeze_changed")
    return {
        "freeze": freeze_pin,
        "post_run_verification": pin(post_path),
        "count": SOURCE_COUNT,
        "checked": len(checked),
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
            require(isinstance(value, dict) and value.get("event") == "information_owned_battle_record",
                    f"raw_record:{line_number}")
            count += 1
    require(header_seen, "raw_header_missing")
    return count


def validate_live_receipts() -> dict[str, Any]:
    live_path = STAGE / "live-acceptance-003" / "report.json"
    live = read_json(live_path)
    require(live.get("status") == "passed", "live003_not_passed")
    require(live.get("server_exit_code") == 0, "live003_server_exit")
    checks = live.get("checks")
    require(isinstance(checks, dict) and checks and all(value is True for value in checks.values()), "live003_checks")
    post = live.get("post_window")
    require(isinstance(post, dict), "live003_post_window_missing")
    first_db = post.get("first_database")
    stable_db = post.get("stable_database")
    require(isinstance(first_db, dict) and first_db.get("battle_records_count") == 11, "live003_raw_count")
    require(isinstance(stable_db, dict) and stable_db.get("battle_records_count") == 11, "live003_stable_raw_count")
    require(post.get("new_event_sequences") == [6], "live003_event_sequence")
    first_delivery = post.get("first_delivery")
    require(isinstance(first_delivery, dict) and first_delivery.get("count") == 1, "live003_event_count")
    event_ids = first_delivery.get("event_ids")
    require(isinstance(event_ids, list) and len(event_ids) == 1 and str(event_ids[0]).endswith(":6"), "live003_event_six")
    natural = live.get("natural_window", {}).get("report", {})
    require(natural.get("captured") == "11", "live003_natural_raw_count")
    raw_path = BUILD / "information-battle-raw.jsonl"
    require(count_raw_records(raw_path) == 11, "native_raw_record_count")
    failed: list[dict[str, Any]] = []
    for number in ("001", "002"):
        path = STAGE / f"live-acceptance-{number}" / "report.json"
        previous = read_json(path)
        require(previous.get("status") == "failed", f"live{number}_original_not_failed")
        failed.append({"report": pin(path), "preflight": pin(path.parent / "preflight-audit.json")})
    return {
        "report": pin(live_path),
        "status": live["status"],
        "server_exit_code": live["server_exit_code"],
        "raw_records": 11,
        "event_sequences": [6],
        "event_ids": event_ids,
        "failed_receipts_retained": failed,
    }


def validate_build_receipts() -> dict[str, Any]:
    required = [BUILD / name for name in BUILD_SNAPSHOT_NAMES]
    for path in required:
        require(path.is_file(), f"missing_build_receipt:{path.name}")
    installation = read_json(BUILD / "installation.json")
    manifest = read_json(BUILD / "build-manifest.json")
    binding = read_json(BUILD / "information-battle-binding.json")
    native = read_json(BUILD / "information-battle-status.json")
    journal = read_json(BUILD / "information-battle-capture-journal.json")
    require(manifest.get("version") == 30, "build_version")
    require(manifest.get("experiment_id") == "diplomacy-observer-20261027-information-battle-v30-003", "build_experiment")
    require(native.get("state") == "disabled", "native_not_disabled")
    require(str(native.get("captured")) == "11" and str(native.get("last_sequence")) == "11", "native_raw_count")
    require(journal.get("state") == "completed-disabled" and journal.get("owned") is False, "journal_not_closed_unowned")
    for key in ("pid", "creation_filetime", "dll_sha256", "game_sha256"):
        if key in installation and key in native:
            require(str(installation[key]) == str(native[key]), f"native_identity:{key}")
    require(str(binding.get("session_id")) == str(installation.get("session_id")), "binding_session")
    require(str(binding.get("dll_sha256")) == str(installation.get("dll_sha256")), "binding_dll")
    audits = {match.group(1): path for path in BUILD.iterdir()
              if path.is_file() and (match := CONTROL_AUDIT_RE.fullmatch(path.name))}
    started = {match.group(1): path for path in BUILD.iterdir()
               if path.is_file() and (match := CONTROL_STARTED_RE.fullmatch(path.name))}
    responses = {match.group(1): path for path in BUILD.iterdir()
                 if path.is_file() and (match := CONTROL_RESPONSE_RE.fullmatch(path.name))}
    require(audits and set(audits) == set(started) == set(responses), "native_control_receipt_triplets")
    return {
        "installation": pin(BUILD / "installation.json"),
        "manifest": pin(BUILD / "build-manifest.json"),
        "native_status": pin(BUILD / "information-battle-status.json"),
        "capture_journal": pin(BUILD / "information-battle-capture-journal.json"),
        "raw_records": 11,
        "control_nonce_count": len(audits),
        "control_nonces": sorted(audits),
    }


def validate_historical_archive() -> dict[str, Any]:
    path = STAGE / "historical-archive-verification-001.json"
    value = read_json(path)
    totals = value.get("totals", {})
    require(value.get("status") == "passed", "historical_archive_not_passed")
    require(totals.get("references") == HISTORICAL_REFERENCE_COUNT and totals.get("matches") == HISTORICAL_REFERENCE_COUNT,
            "historical_archive_reference_count")
    for key in ("mismatches", "missing", "read_errors", "invalid_pins"):
        require(totals.get(key) == 0, f"historical_archive_{key}")
    return {"verification": pin(path), "references": HISTORICAL_REFERENCE_COUNT}


def working_database_paths() -> tuple[list[Path], list[Path]]:
    primary: list[Path] = []
    sidecars: list[Path] = []
    for path in sorted(STAGE.rglob("*")):
        if not path.is_file() or "final-database-snapshots" in path.relative_to(STAGE).parts:
            continue
        lower = path.name.lower()
        if lower.endswith(("-wal", "-shm")):
            sidecars.append(path)
        elif path.suffix.lower() in {".sqlite", ".sqlite3", ".db"}:
            primary.append(path)
    return primary, sidecars


def quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def backup_sqlite(source_path: Path, destination: Path) -> dict[str, Any]:
    if destination.exists():
        raise ArchiveError(f"refusing_to_overwrite:{display_path(destination)}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_pin_before = pin(source_path)
    destination.open("xb").close()
    source_uri = source_path.resolve().as_uri() + "?mode=ro"
    try:
        with closing(sqlite3.connect(source_uri, uri=True)) as source:
            source.execute("PRAGMA query_only=ON")
            with closing(sqlite3.connect(destination)) as target:
                source.backup(target)
                target.commit()
                integrity = target.execute("PRAGMA integrity_check").fetchone()[0]
                table_names = [row[0] for row in target.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
                active = None
                if "info_config" in table_names:
                    columns = {row[1] for row in target.execute("PRAGMA table_info(info_config)")}
                    require({"kind", "body"}.issubset(columns), "info_config_shape")
                    active = target.execute(
                        "SELECT COUNT(*) FROM info_config "
                        "WHERE kind='subscription' AND json_extract(body, '$.state') IN ('active','enabled')"
                    ).fetchone()[0]
                require(integrity == "ok", f"sqlite_integrity:{display_path(source_path)}:{integrity}")
                require(active in (None, 0), f"sqlite_active_subscriptions:{display_path(source_path)}:{active}")
    except Exception:
        raise
    source_pin_after = pin(source_path)
    snapshot_pin = pin(destination)
    require(source_pin_before == source_pin_after, f"sqlite_source_changed:{display_path(source_path)}")
    return {
        "source": source_pin_before,
        "snapshot": snapshot_pin,
        "integrity": integrity,
        "tables": table_names,
        "active_subscriptions": active,
        "backup_mode": "read_only_source_connection_to_independent_snapshot",
    }


def snapshot_build_and_databases() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    final_dir = STAGE / "final-snapshots"
    database_dir = STAGE / "final-database-snapshots"
    final_dir.mkdir(exist_ok=False)
    database_dir.mkdir(exist_ok=False)
    copies: list[dict[str, Any]] = []
    for name in BUILD_SNAPSHOT_NAMES:
        copies.append(copy_new(BUILD / name, final_dir / name))
    audits = sorted(BUILD.glob("information-battle-control-audit-*.jsonl"))
    for audit in audits:
        nonce_match = CONTROL_AUDIT_RE.fullmatch(audit.name)
        require(nonce_match is not None, f"invalid_control_audit_name:{audit.name}")
        nonce = nonce_match.group(1)
        for source in (audit, BUILD / f"information-battle-started-{nonce}.json",
                       BUILD / f"information-battle-response-{nonce}.json"):
            copies.append(copy_new(source, final_dir / source.name))

    primary, sidecars = working_database_paths()
    backups = []
    for source in primary:
        relative = source.relative_to(STAGE)
        backups.append(backup_sqlite(source, database_dir / relative))
    excluded = [{
        "path": display_path(path),
        "bytes": path.stat().st_size,
        "reason": "working SQLite or WAL/SHM sidecar excluded from archive artifacts; independent database snapshot is retained",
    } for path in primary + sidecars]
    database_report = {
        "status": "passed",
        "hash_chunk_bytes": HASH_CHUNK_BYTES,
        "backups": backups,
        "working_database_exclusions": excluded,
        "source_wal_shm_deleted": False,
    }
    write_new(STAGE / "database-snapshot-verification-001.json", database_report)
    return copies, database_report


def optional_p05_sources() -> list[Path]:
    return []


def snapshot_documents_and_supplements() -> tuple[dict[str, Any], dict[str, Any]]:
    docs, doc_checks = validate_goal_and_documents()
    document_copies = []
    for relative in DOCUMENTS:
        source = ROOT / relative
        document_copies.append(copy_new(source, STAGE / "document-snapshots" / relative))
    write_new(STAGE / "document-verification-001.json", {
        "status": "passed",
        "documents": docs,
        "snapshots": document_copies,
        "checks": doc_checks,
    })

    paths: list[Path] = []
    for relative in SUPPLEMENTAL_REQUIRED:
        path = ROOT / relative
        require(path.is_file(), f"missing_supplemental:{relative}")
        paths.append(path)
    paths.extend(optional_p05_sources())
    unique_paths = list(dict.fromkeys(paths))
    copies = []
    for source in unique_paths:
        copies.append(copy_new(source, STAGE / "supplemental-source-snapshots" / source.relative_to(ROOT)))
    optional_missing = [
        "work/validate_information_battle_p05_acceptance.py",
        "work/validate_information_battle_p05_live.py",
        "work/validate_information_battle_p05.py",
    ]
    write_new(STAGE / "supplemental-source-verification-001.json", {
        "status": "passed",
        "files": copies,
        "p05_present": [display_path(path) for path in optional_p05_sources()],
        "p05_missing_at_archive_time": [relative for relative in optional_missing if not (ROOT / relative).is_file()],
        "scope": "batch64 verification, autonomous acceptance, bootstrap, status reader, save wrapper, P05 if present, finalizer, and archive",
    })
    return doc_checks, {"copies": copies, "count": len(copies)}


def is_working_database_artifact(path: Path) -> bool:
    relative = path.relative_to(STAGE)
    if "final-database-snapshots" in relative.parts:
        return False
    lower = path.name.lower()
    return lower.endswith(("-wal", "-shm")) or path.suffix.lower() in {".sqlite", ".sqlite3", ".db"}


def stage_artifacts() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    exclusions: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    for path in sorted(STAGE.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(STAGE)
        if path == ARCHIVE or path == FINAL_READBACK:
            continue
        if is_working_database_artifact(path):
            exclusions.append({"path": display_path(path), "bytes": path.stat().st_size,
                               "reason": "working database/WAL/SHM; see independent final-database-snapshots"})
            continue
        artifacts.append(pin(path))
    return artifacts, exclusions


def archive() -> dict[str, Any]:
    require(STAGE.is_dir() and BUILD.is_dir(), "stage_or_build_missing")
    require(not ARCHIVE.exists() and not FINAL_READBACK.exists(), "archive_already_started")
    goal_summary = validate_summary_if_present()
    source_check = validate_source_freeze()
    live_check = validate_live_receipts()
    build_check = validate_build_receipts()
    historical_check = validate_historical_archive()
    document_check, supplemental_check = snapshot_documents_and_supplements()
    build_copies, database_check = snapshot_build_and_databases()
    runtime_check = {
        "status": "passed",
        "build_snapshots": build_copies,
        "database_snapshots": database_check,
        "live": live_check,
        "build": build_check,
        "source": source_check,
        "historical": historical_check,
        "documents": document_check,
        "supplemental": supplemental_check,
        "native_state": "disabled",
        "capture_journal": "completed-disabled/unowned",
    }
    write_new(STAGE / "runtime-archive-verification-001.json", runtime_check)
    artifacts, exclusions = stage_artifacts()
    manifest = {
        "schema": "information_battle_autonomous_archive.v1",
        "status": "passed",
        "batch": 64,
        "goal": "active",
        "stage": display_path(STAGE),
        "build": display_path(BUILD),
        "hash_chunk_bytes": HASH_CHUNK_BYTES,
        "copy_limit_bytes": COPY_LIMIT_BYTES,
        "runtime_verification": pin(STAGE / "runtime-archive-verification-001.json"),
        "artifacts": artifacts,
        "artifact_count": len(artifacts),
        "excluded_working_databases": exclusions,
        "database_snapshots": database_check["backups"],
        "scope": {
            "game_started": False,
            "mcp_started": False,
            "new_natural_window": False,
            "rea_or_disassembly": False,
            "source_working_databases_pinned_directly": False,
            "wal_shm_deleted": False,
        },
    }
    write_new(ARCHIVE, manifest)
    manifest_pin = pin(ARCHIVE)
    readback_count = 0
    for item in artifacts:
        current = pin(ROOT / item["path"])
        require(current == item, f"final_readback_mismatch:{item['path']}")
        readback_count += 1
    write_new(FINAL_READBACK, {
        "schema": "information_battle_autonomous_archive_readback.v1",
        "status": "passed",
        "manifest": manifest_pin,
        "artifact_count": readback_count,
        "all_artifact_pins_rechecked": True,
        "working_database_exclusions_rechecked": len(exclusions),
    })
    return {"status": "passed", "artifact_count": len(artifacts), "database_snapshots": len(database_check["backups"]),
            "control_receipt_snapshots": build_check["control_nonce_count"], "readback": readback_count}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="perform the exclusive-create offline archive")
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "inert", "stage": display_path(STAGE), "build": display_path(BUILD)}))
        return 0
    print(json.dumps(archive(), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
