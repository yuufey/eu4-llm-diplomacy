"""Freeze the actual natural-window evidence after capture has been disabled.

This performs one read-only process preflight and one status read. It never
publishes a game-control or battle-control request. Live files are copied to
new paths; SQLite is backed up through its read-only connection.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.control_information_battle_observer import run_control
from work.probe_information_battle_v23 import run as run_probe

STAGE = ROOT / "work/runtime/information-battle-live-20261025-001"
INSTALL = ROOT / "work/runtime/diplomacy-observer-20261025-information-battle-live-001/installation.json"


def read(path: Path) -> dict:
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("JSON_SIZE_LIMIT:" + str(path))
    return json.loads(path.read_text(encoding="utf-8-sig"))


def pin(path: Path) -> dict:
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": path.relative_to(ROOT).as_posix(), "size_bytes": path.stat().st_size,
            "sha256": digest}


def write_new(path: Path, document: dict) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def copy_prefix(source: Path, target: Path, *, stable: bool) -> dict:
    with source.open("rb") as incoming, target.open("xb") as outgoing:
        before = os.fstat(incoming.fileno())
        remaining = before.st_size
        if remaining > 16 * 1024 * 1024:
            raise ValueError("SNAPSHOT_SIZE_LIMIT:" + str(source))
        while remaining:
            block = incoming.read(min(remaining, 256 * 1024))
            if not block:
                raise ValueError("SOURCE_SHORTENED_DURING_COPY")
            outgoing.write(block)
            remaining -= len(block)
        outgoing.flush()
        os.fsync(outgoing.fileno())
        after = os.fstat(incoming.fileno())
        named = source.stat()
    identity = lambda value: (value.st_dev, value.st_ino)
    if identity(before) != identity(after) or identity(before) != identity(named):
        raise ValueError("SOURCE_REPLACED_DURING_COPY")
    if stable and (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("STABLE_SOURCE_CHANGED_DURING_COPY")
    return {"source": source.relative_to(ROOT).as_posix(), "source_identity": list(identity(before)),
            "source_size_at_open": before.st_size, "source_size_after_copy": after.st_size,
            "copied_prefix_bytes": before.st_size, "requires_stable_source": stable,
            "snapshot": pin(target)}


def main() -> int:
    output = STAGE / "natural-capture-acceptance-001.json"
    directory = STAGE / "natural-capture-snapshots-001"
    if output.exists():
        raise FileExistsError(output)
    directory.mkdir(exist_ok=False)
    windows = [read(STAGE / f"natural-window-{index:03d}/report.json") for index in (1, 2)]
    assert [(item["start_raw"], item["target_raw"]) for item in windows] == [
        (56553384, 56553408), (56553408, 56554248)]
    assert all(item["status"] == "observed_target_and_paused" for item in windows)
    received = read(STAGE / "raw-after-window-002.json")
    reopened = read(STAGE / "raw-reopen-001.json")
    for item in (received, reopened):
        assert item["status"] == "passed" and item["closed"] is True
        assert item["message_page"]["returned"] == 18 and item["message_page"]["truncated"] is False
        assert len(item["messages"]) == 18
        assert not item["errors"]
    identity_keys = lambda item: [(row["message_id"], row["payload_sha256"], row["group_id"])
                                  for row in item["messages"]]
    assert identity_keys(received) == identity_keys(reopened)
    assert reopened["tailer"]["poll"]["status"] == "idle"
    assert reopened["tailer"]["poll"]["acked"] == 0
    assert reopened["transport"]["received_count"] == 18
    assert received["tailer"]["cursor"]["offset"] == reopened["tailer"]["cursor"]["offset"]
    assert received["tailer"]["cursor"]["file_identity"] == reopened["tailer"]["cursor"]["file_identity"]
    disabled = read(STAGE / "disable-after-window-001.json")
    assert disabled["status"] == "accepted"
    assert disabled["response"]["accepted"] is True
    assert disabled["response"]["state"] == "disabled"
    status = run_control(INSTALL, "status")
    native = status["native"]
    assert status["fresh"] is True and native["state"] == "disabled"
    assert native["captured"] == native["last_sequence"] == "18"
    assert all(native[key] == "0" for key in (
        "dropped_busy", "dropped_full", "dropped_foreign_thread", "copy_failures", "guard_failures", "fragment_queued"))
    assert native["fragment_sink_pending"] is False
    write_new(directory / "status-read.json", status)
    preflight = run_probe(INSTALL, directory / "final-preflight.json", "installed")
    assert preflight["status"] == "passed_read_only_preflight"
    for phase in ("before", "after"):
        snapshot = preflight[phase]
        assert snapshot["game_date"]["raw"] == 56554248
        assert snapshot["control"]["paused"]["value"] is True
        assert snapshot["control"]["speed"]["value"] == 0
        assert snapshot["physical_player"]["raw_hex"] == "504f5200bd000001"
    copied = []
    for name, target, stable in (
        ("installation.json", "installation.json", True),
        ("build-manifest.json", "build-manifest.json", True),
        ("information-battle-binding.json", "binding.json", True),
        ("information-battle-status.json", "native-status.json", False),
        ("information-battle-raw.jsonl", "raw.jsonl", True),
        ("control-probe.jsonl", "control-probe.jsonl", False),
    ):
        copied.append(copy_prefix(INSTALL.parent / name, directory / target, stable=stable))
    for source in sorted(INSTALL.parent.glob("information-battle-control.*")):
        if source.is_file() and source.suffix == ".json":
            copied.append(copy_prefix(source, directory / source.name, stable=True))
    raw_snapshot = directory / "raw.jsonl"
    assert raw_snapshot.stat().st_size == received["tailer"]["cursor"]["offset"]
    assert len(raw_snapshot.read_bytes().splitlines()) == 19
    database = STAGE / "raw-research.sqlite3"
    backup = directory / "raw-research.sqlite3"
    with backup.open("xb"):
        pass
    source = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)
    destination = sqlite3.connect(backup)
    try:
        source.backup(destination)
        integrity = destination.execute("PRAGMA integrity_check").fetchone()[0]
        assert integrity == "ok"
        names = [row[0] for row in destination.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        # Table names come from SQLite schema, never shell command text.
        counts = {name: destination.execute('SELECT count(*) FROM "' + name.replace('"', '""') + '"').fetchone()[0]
                  for name in names}
    finally:
        destination.close()
        source.close()
    manifest = {"schema": "BATTLE-NATURAL-SNAPSHOTS/1", "captured_at_utc": datetime.now(timezone.utc).isoformat(),
                "copies": copied, "database": pin(backup), "database_integrity": integrity,
                "database_tables": counts,
                "scope": {"game_control_sent": False, "business_dispatch": False,
                          "read_only_process_preflight": True, "sqlite_backup_from_read_only_connection": True}}
    write_new(directory / "snapshot-manifest.json", manifest)
    report = {"schema": "BATTLE-NATURAL-ACCEPTANCE/1", "status": "passed_raw_capture_business_unverified",
              "script": pin(Path(__file__)), "snapshot_manifest": pin(directory / "snapshot-manifest.json"),
              "window_days": [1, 35], "final_date_raw": 56554248, "paused": True,
              "physical_player": "POR", "capture_state": "disabled", "captured": 18,
              "sequence_range": [1, 18], "raw_payloads_strictly_decoded": 18,
              "receiver_reopened_without_new_frames_or_duplicate_messages": True,
              "dropped_or_failed_reported": 0, "stats_atomic_snapshot": False,
              "business_battle_complete": False, "visibility_verified": False,
              "all_game_battles_captured": False, "abi_fully_verified": False,
              "same_address_reload_verified": False, "goal_complete": False,
              "disable_wrapper_exception": {"shell_exit_code": 1,
                  "reason": "root summary checked native instead of response after accepted disable; full accepted response was saved",
                  "control_retried": False, "subsequent_status_verified_disabled": True},
              "dependencies": [pin(STAGE / item) for item in (
                  "natural-window-001/report.json", "natural-window-002/report.json",
                  "raw-after-window-002.json", "raw-reopen-001.json", "payload-analysis-001.json",
                  "disable-after-window-001.json", "natural-runner-test-001/report-002.json")]}
    write_new(output, report)
    print(json.dumps({"status": report["status"], "captured": 18,
                      "snapshot_files": len(copied), "database_integrity": integrity}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
