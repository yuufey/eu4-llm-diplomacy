"""Freeze the already completed checkpoint-save evidence without touching live state.

The archive reads the frozen outcome and the save tool's report/probes, copies
only the bounded JSON evidence and the requested control-log slice with
exclusive creation, and streams hashes for the checkpoint, R70, and three
rotating autosaves.  It never sends a control request, opens a game process,
uses RPM/REA, or copies the large save files.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-battle-context-live-20261025-001"
DEFAULT_OUTCOME = STAGE / "checkpoint-save-001/outcome-001.json"
DEFAULT_EVIDENCE_DIR = STAGE / "checkpoint-evidence-001"
DEFAULT_OUTPUT = STAGE / "checkpoint-acceptance-001.json"
DEFAULT_LIVE_DIR = ROOT / "work/runtime/diplomacy-observer-20261025-information-battle-live-001"
DEFAULT_OLD22_RAW = ROOT / "work/runtime/information-battle-live-20261025-001/natural-capture-snapshots-001/raw.jsonl"
DEFAULT_OLD22_RAW_REPORT = ROOT / "work/runtime/information-battle-live-20261025-001/raw-after-window-002.json"
DEFAULT_STAGE_CHECKPOINT = STAGE / "checkpoint-save-001/checkpoint.eu4"
ROTATING_AUTOSAVES = ("autosave.eu4", "old_autosave.eu4", "older_autosave.eu4")
HASH_CHUNK_BYTES = 1024 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_SLICE_BYTES = 4 * 1024 * 1024
MAX_RAW_BYTES = 4 * 1024 * 1024
EXPECTED_RAW_DATE = 56_554_248
EXPECTED_PLAYER_SLOT = 189
EXPECTED_PLAYER = "POR"
EXPECTED_R70_SHA = "ffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0"
SHA256_LENGTH = 64


class CheckpointArchiveError(RuntimeError):
    """Raised when the frozen checkpoint evidence cannot be archived safely."""


def _display(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(resolved)


def _identity(path: Path) -> dict[str, int]:
    try:
        stat_result = path.stat()
    except OSError as exc:
        raise CheckpointArchiveError(f"stat_failed:{path}:{exc}") from exc
    return {
        "device": int(stat_result.st_dev),
        "inode": int(stat_result.st_ino),
        "size_bytes": int(stat_result.st_size),
        "mtime_ns": int(stat_result.st_mtime_ns),
    }


def _hash(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as stream:
            while True:
                block = stream.read(HASH_CHUNK_BYTES)
                if not block:
                    break
                size += len(block)
                digest.update(block)
    except OSError as exc:
        raise CheckpointArchiveError(f"read_failed:{path}:{exc}") from exc
    return size, digest.hexdigest()


def _stable_pin(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise CheckpointArchiveError(f"missing_file:{path}")
    before = _identity(path)
    size, digest = _hash(path)
    after = _identity(path)
    if before != after or size != before["size_bytes"]:
        raise CheckpointArchiveError(f"source_changed_during_hash:{path}")
    return {
        "path": _display(path),
        "size_bytes": size,
        "sha256": digest,
        "identity": before,
        "stable": True,
    }


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise CheckpointArchiveError(f"missing_json:{path}")
    if path.stat().st_size > MAX_JSON_BYTES:
        raise CheckpointArchiveError(f"json_over_bound:{path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CheckpointArchiveError(f"invalid_json:{path}:{exc}") from exc
    if not isinstance(value, dict):
        raise CheckpointArchiveError(f"json_object_required:{path}")
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckpointArchiveError(message)


def _sha256_string(value: Any, label: str) -> str:
    _require(isinstance(value, str) and len(value) == SHA256_LENGTH, f"invalid_sha:{label}")
    try:
        int(value, 16)
    except ValueError as exc:
        raise CheckpointArchiveError(f"invalid_sha:{label}") from exc
    return value.lower()


def _copy_exclusive(source: Path, destination: Path) -> dict[str, Any]:
    if destination.exists():
        raise CheckpointArchiveError(f"refusing_to_overwrite:{destination}")
    before = _identity(source)
    before_size, before_sha = _hash(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with source.open("rb") as incoming, destination.open("xb") as outgoing:
            shutil.copyfileobj(incoming, outgoing, length=HASH_CHUNK_BYTES)
            outgoing.flush()
            os.fsync(outgoing.fileno())
    except OSError as exc:
        raise CheckpointArchiveError(f"copy_failed:{source}:{exc}") from exc
    after = _identity(source)
    after_size, after_sha = _hash(source)
    destination_size, destination_sha = _hash(destination)
    checks = {
        "source_identity_stable": before == after,
        "source_hash_stable": before_sha == after_sha and before_size == after_size,
        "destination_size_matches": destination_size == before_size,
        "destination_hash_matches": destination_sha == before_sha,
    }
    if not all(checks.values()):
        raise CheckpointArchiveError(f"copy_verification_failed:{source}")
    return {
        "source": {"path": _display(source), "identity": before, "size_bytes": before_size, "sha256": before_sha},
        "destination": {"path": _display(destination), "identity": _identity(destination), "size_bytes": destination_size, "sha256": destination_sha},
        "checks": checks,
    }


def _write_exclusive(path: Path, value: dict[str, Any]) -> None:
    if path.exists():
        raise CheckpointArchiveError(f"refusing_to_overwrite:{path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise CheckpointArchiveError(f"write_failed:{path}:{exc}") from exc


def _validate_probe(path: Path, label: str) -> dict[str, Any]:
    value = _load_json(path)
    checks = {
        "read_only": value.get("read_only") is True,
        "player_slot": value.get("player_slot") == EXPECTED_PLAYER_SLOT,
        "date_raw": value.get("date_raw") == EXPECTED_RAW_DATE,
        "speed": value.get("speed") == 0,
        "paused": value.get("paused_flag") == 1,
    }
    _require(all(checks.values()), f"probe_contract_failed:{label}")
    return {"label": label, "checks": checks, "signature": {key: value.get(key) for key in ("date_raw", "player_slot", "paused_flag", "speed")}}


def _copy_control_slice(source: Path, destination: Path, offsets: dict[str, Any], console_events: Any) -> dict[str, Any]:
    _require(isinstance(offsets, dict), "log_offsets_missing")
    start, end = offsets.get("start"), offsets.get("end")
    _require(isinstance(start, int) and not isinstance(start, bool), "log_start_invalid")
    _require(isinstance(end, int) and not isinstance(end, bool), "log_end_invalid")
    _require(0 <= start <= end, "log_offsets_order_invalid")
    _require(end - start <= MAX_SLICE_BYTES, "log_slice_over_bound")
    if destination.exists():
        raise CheckpointArchiveError(f"refusing_to_overwrite:{destination}")
    before = _identity(source)
    _require(end <= before["size_bytes"], "log_slice_past_eof")
    try:
        with source.open("rb") as incoming, destination.open("xb") as outgoing:
            incoming.seek(start)
            remaining = end - start
            while remaining:
                block = incoming.read(min(remaining, HASH_CHUNK_BYTES))
                if not block:
                    raise CheckpointArchiveError("log_slice_short_read")
                outgoing.write(block)
                remaining -= len(block)
            outgoing.flush()
            os.fsync(outgoing.fileno())
    except OSError as exc:
        raise CheckpointArchiveError(f"log_slice_copy_failed:{source}:{exc}") from exc
    after = _identity(source)
    _require(before == after, "log_source_changed_during_slice")
    slice_bytes = destination.read_bytes()
    try:
        text = slice_bytes.decode("utf-8")
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CheckpointArchiveError(f"log_slice_invalid_json:{exc}") from exc
    _require(all(isinstance(row, dict) for row in rows), "log_slice_objects_required")
    successes = [row for row in rows if row.get("event") == "control_console_result" and row.get("command") == "autosave" and row.get("success") is True]
    _require(len(successes) == 1, f"autosave_console_success_count:{len(successes)}")
    _require(isinstance(console_events, list) and len(console_events) == 1, "console_event_receipt_count")
    receipt = console_events[0]
    _require(receipt.get("event") == "control_console_result" and receipt.get("command") == "autosave" and receipt.get("success") is True, "console_event_receipt_invalid")
    _require(start <= receipt.get("offset", -1) < end and start < receipt.get("end_offset", -1) <= end, "console_event_offsets_outside_slice")
    size, digest = _hash(destination)
    return {
        "source": {"path": _display(source), "identity": before, "size_bytes": before["size_bytes"]},
        "offsets": {"start": start, "end": end, "bytes": end - start},
        "slice": {"path": _display(destination), "size_bytes": size, "sha256": digest, "line_count": len(rows)},
        "console_success_count": len(successes),
        "console_event_receipt": receipt,
        "checks": {
            "bounded_slice": end - start <= MAX_SLICE_BYTES,
            "source_identity_stable": before == after,
            "exactly_one_successful_autosave_console": len(successes) == 1,
            "receipt_inside_slice": True,
        },
    }


def _raw_stats(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise CheckpointArchiveError(f"missing_raw:{path}")
    before = _identity(path)
    _require(before["size_bytes"] <= MAX_RAW_BYTES, f"raw_over_bound:{path}")
    try:
        with path.open("r", encoding="utf-8", newline="") as stream:
            lines = stream.read().splitlines()
    except (OSError, UnicodeError) as exc:
        raise CheckpointArchiveError(f"raw_read_failed:{path}:{exc}") from exc
    after = _identity(path)
    _require(before == after, f"raw_changed:{path}")
    _require(lines and lines[0].startswith("EU4_OWNED_BATTLE_WIRE_V1 "), f"raw_header_invalid:{path}")
    rows = []
    for line_number, line in enumerate(lines[1:], 2):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise CheckpointArchiveError(f"raw_json_invalid:{path}:{line_number}") from exc
        _require(isinstance(value, dict), f"raw_object_required:{path}:{line_number}")
        rows.append(value)
    record_count = sum(value.get("event") == "information_owned_battle_record" for value in rows)
    _require(record_count == 18, f"raw_capture_count:{path}:{record_count}")
    pin = _stable_pin(path)
    return {
        "pin": pin,
        "header": lines[0],
        "line_count": len(lines),
        "payload_record_count": record_count,
        "checks": {"header_valid": True, "eighteen_payload_records": record_count == 18, "stable": True},
    }


def _rotating_records(manifest: dict[str, Any], backup_dir: Path, actual_dir: Path) -> dict[str, Any]:
    rotating = manifest.get("rotating_autosaves")
    _require(isinstance(rotating, dict), "rotating_autosaves_missing")
    result: dict[str, Any] = {}
    for name in ROTATING_AUTOSAVES:
        entry = rotating.get(name)
        _require(isinstance(entry, dict), f"rotating_manifest_missing:{name}")
        file_name = entry.get("name")
        _require(file_name == name and Path(file_name).name == file_name, f"rotating_name_invalid:{name}")
        baseline = _sha256_string(entry.get("sha256"), f"rotating.{name}.sha256")
        backup_pin = _stable_pin(backup_dir / file_name)
        actual_pin = _stable_pin(actual_dir / file_name)
        result[name] = {
            "baseline": {"size_bytes": entry.get("size"), "sha256": baseline},
            "backup": backup_pin,
            "current_user_data": actual_pin,
            "checks": {
                "backup_matches_baseline": backup_pin["sha256"] == baseline and backup_pin["size_bytes"] == entry.get("size"),
                "current_matches_baseline": actual_pin["sha256"] == baseline and actual_pin["size_bytes"] == entry.get("size"),
                "backup_current_equal": backup_pin["sha256"] == actual_pin["sha256"] and backup_pin["size_bytes"] == actual_pin["size_bytes"],
            },
        }
    _require(all(all(value["checks"].values()) for value in result.values()), "rotating_autosave_hash_mismatch")
    return result


def archive(
    *,
    outcome_path: Path = DEFAULT_OUTCOME,
    evidence_dir: Path = DEFAULT_EVIDENCE_DIR,
    output_path: Path = DEFAULT_OUTPUT,
    live_dir: Path = DEFAULT_LIVE_DIR,
    old22_raw: Path = DEFAULT_OLD22_RAW,
    old22_raw_report: Path = DEFAULT_OLD22_RAW_REPORT,
    stage_checkpoint: Path = DEFAULT_STAGE_CHECKPOINT,
) -> dict[str, Any]:
    if output_path.exists() or evidence_dir.exists():
        raise CheckpointArchiveError("refusing_to_overwrite_checkpoint_archive")
    outcome = _load_json(outcome_path)
    _require(outcome.get("status") == "saved_verified", "outcome_not_saved_verified")
    _require(outcome.get("attempt_started") is True, "outcome_attempt_missing")
    _require(outcome.get("retry_authorized") is False, "outcome_retry_not_closed")
    _require(outcome.get("game_date_advanced") is False, "outcome_date_advanced")
    _require(outcome.get("business_request_dispatched") is False, "outcome_business_request_dispatched")
    save_result = outcome.get("save_result")
    _require(isinstance(save_result, dict) and save_result.get("status") == "success", "save_result_not_success")
    restore = save_result.get("restore")
    _require(isinstance(restore, dict) and restore.get("errors") == [], "save_restore_errors")
    save_record = outcome.get("save")
    _require(isinstance(save_record, dict), "outcome_save_missing")
    expected_save_sha = _sha256_string(save_record.get("sha256"), "outcome.save.sha256")
    report_path = Path(save_result.get("report", ""))
    report = _load_json(report_path)
    _require(report.get("status") == "success", "save_report_not_success")
    _require(report.get("save", {}).get("sha256") == expected_save_sha, "save_report_hash_mismatch")

    probe_before_path = Path(save_result.get("probe_before", {}).get("path", ""))
    probe_after_path = Path(save_result.get("probe_after", {}).get("path", ""))
    probe_before = _validate_probe(probe_before_path, "before")
    probe_after = _validate_probe(probe_after_path, "after")
    _require(probe_before["signature"] == probe_after["signature"], "probe_before_after_changed")

    backup = save_result.get("backup")
    _require(isinstance(backup, dict), "backup_missing")
    backup_dir = Path(backup.get("path", ""))
    backup_manifest_path = backup_dir / "manifest.json"
    backup_manifest = _load_json(backup_manifest_path)
    _require(backup_manifest.get("created") is True, "backup_manifest_not_created")
    actual_save_path = Path(save_result.get("save", {}).get("path", save_record.get("path", "")))
    actual_save_dir = Path(save_result.get("save", {}).get("source", actual_save_path)).parent
    rotating = _rotating_records(backup_manifest, backup_dir, actual_save_dir)

    checkpoint_pin = _stable_pin(stage_checkpoint)
    current_checkpoint_pin = _stable_pin(Path(save_record["path"]))
    _require(checkpoint_pin["sha256"] == expected_save_sha, "stage_checkpoint_hash_mismatch")
    _require(current_checkpoint_pin["sha256"] == expected_save_sha, "current_checkpoint_hash_mismatch")
    _require(checkpoint_pin["size_bytes"] == current_checkpoint_pin["size_bytes"] == save_record.get("bytes"), "checkpoint_size_mismatch")

    protected = outcome.get("protected_r70_after")
    _require(isinstance(protected, dict), "protected_r70_missing")
    protected_path = Path(protected.get("path", ""))
    protected_pin = _stable_pin(protected_path)
    protected_sha = _sha256_string(protected.get("sha256"), "protected_r70_after.sha256")
    _require(protected_sha == EXPECTED_R70_SHA, "protected_r70_expected_hash_changed")
    _require(protected_pin["sha256"] == protected_sha, "protected_r70_hash_changed")

    evidence_dir.mkdir(parents=True, exist_ok=False)
    slice_path = evidence_dir / "control-probe-slice.jsonl"
    log_offsets = save_result.get("log_offsets")
    control_slice = _copy_control_slice(live_dir / "control-probe.jsonl", slice_path, log_offsets, save_result.get("console_events"))

    raw_live = _raw_stats(live_dir / "information-battle-raw.jsonl")
    raw_old22 = _raw_stats(old22_raw)
    old22_report_value = _load_json(old22_raw_report)
    _require(old22_report_value.get("status") == "passed", "old22_raw_report_not_passed")
    old22_page = old22_report_value.get("message_page")
    _require(isinstance(old22_page, dict) and old22_page.get("complete_groups") == 18 and old22_page.get("returned") == 18, "old22_capture_count_mismatch")
    old22_report_pin = _stable_pin(old22_raw_report)
    _require(raw_live["pin"]["sha256"] == raw_old22["pin"]["sha256"], "v23_raw_old22_raw_hash_mismatch")
    _require(raw_live["payload_record_count"] == raw_old22["payload_record_count"] == 18, "v23_raw_old22_capture_count_mismatch")

    copies = []
    copy_specs = (
        ("save_result_report", report_path, evidence_dir / "save-result-report.json"),
        ("probe_before", probe_before_path, evidence_dir / "probe-before.json"),
        ("probe_after", probe_after_path, evidence_dir / "probe-after.json"),
        ("backup_manifest", backup_manifest_path, evidence_dir / "backup-manifest.json"),
    )
    for label, source, destination in copy_specs:
        record = _copy_exclusive(source, destination)
        record["label"] = label
        copies.append(record)

    evidence_manifest = {
        "schema": "BATTLE-CHECKPOINT-EVIDENCE-SNAPSHOT/1",
        "status": "passed",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "copies": copies,
        "control_probe_slice": control_slice,
        "scope": {
            "game_access": False,
            "process_access": False,
            "control_request_sent": False,
            "rpm": False,
            "rea": False,
            "large_save_copied": False,
            "exclusive_copy": True,
        },
    }
    evidence_manifest_path = evidence_dir / "evidence-manifest.json"
    _write_exclusive(evidence_manifest_path, evidence_manifest)

    outcome_pin = _stable_pin(outcome_path)
    source_pins = {
        "archive_script": _stable_pin(Path(__file__)),
        "outcome": outcome_pin,
        "save_result_report": _stable_pin(report_path),
        "probe_before": _stable_pin(probe_before_path),
        "probe_after": _stable_pin(probe_after_path),
        "backup_manifest": _stable_pin(backup_manifest_path),
        "control_probe": control_slice["source"],
        "current_v23_raw": raw_live["pin"],
        "archived_v22_raw": raw_old22["pin"],
        "archived_v22_raw_report": old22_report_pin,
        "stage_checkpoint": checkpoint_pin,
        "current_user_checkpoint": current_checkpoint_pin,
        "protected_r70": protected_pin,
        "evidence_manifest": _stable_pin(evidence_manifest_path),
    }
    checks = {
        "outcome_saved_verified": True,
        "save_result_success": True,
        "restore_three_rotating_autosaves_without_errors": restore.get("rotating_restore_count") == 3 and not restore.get("errors"),
        "checkpoint_stage_matches_current_user_data": checkpoint_pin["sha256"] == current_checkpoint_pin["sha256"] == expected_save_sha,
        "protected_r70_hash_preserved": protected_pin["sha256"] == EXPECTED_R70_SHA,
        "rotating_backup_and_current_each_match_baseline": all(all(item["checks"].values()) for item in rotating.values()),
        "probe_before_after_same_date_player_pause": probe_before["signature"] == probe_after["signature"],
        "control_slice_has_one_successful_autosave_console": control_slice["checks"]["exactly_one_successful_autosave_console"],
        "old_v23_raw_equals_archived_v22_raw": raw_live["pin"]["sha256"] == raw_old22["pin"]["sha256"] and raw_live["payload_record_count"] == 18,
        "evidence_copies_all_verified": all(all(item["checks"].values()) for item in copies),
    }
    _require(all(checks.values()), "checkpoint_acceptance_check_failed")
    report_value = {
        "schema": "BATTLE-CHECKPOINT-ACCEPTANCE/1",
        "status": "passed_saved_verified",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": {
            "game_access": False,
            "process_access": False,
            "control_request_sent": False,
            "rpm": False,
            "rea": False,
            "save_executed_by_archive": False,
            "large_save_copied": False,
            "live_files_modified": False,
        },
        "outcome": {
            "pin": outcome_pin,
            "status": outcome.get("status"),
            "save_result_status": save_result.get("status"),
            "save_date": save_result.get("save", {}).get("inspection", {}).get("date"),
            "raw_date": EXPECTED_RAW_DATE,
            "player": EXPECTED_PLAYER,
            "player_slot": EXPECTED_PLAYER_SLOT,
            "paused": True,
        },
        "checkpoint": {
            "expected_sha256": expected_save_sha,
            "stage_copy": checkpoint_pin,
            "current_user_data": current_checkpoint_pin,
            "size_bytes": save_record.get("bytes"),
        },
        "protected_r70": protected_pin,
        "rotating_autosaves": rotating,
        "probes": {"before": probe_before, "after": probe_after},
        "control_probe_slice": control_slice,
        "old_raw_comparison": {
            "current_v23_raw": raw_live,
            "archived_v22_natural_raw": raw_old22,
            "archived_v22_capture_report": old22_report_pin,
            "capture_count": 18,
            "hash_equal": raw_live["pin"]["sha256"] == raw_old22["pin"]["sha256"],
            "note": "The raw JSONL equality is recorded at this archive boundary; it does not prove complete business battle semantics.",
        },
        "evidence_snapshot": {
            "directory": _display(evidence_dir),
            "manifest": _stable_pin(evidence_manifest_path),
            "copies": copies,
        },
        "source_pins": source_pins,
        "checks": checks,
        "boundary": "This archives one already successful, TEST_ONLY autosave and its read-only evidence. It does not authorize restart/install, prove complete battle ABI/business export, or alter any live/original file.",
    }
    _write_exclusive(output_path, report_value)
    report_value["report_path"] = _display(output_path)
    print(json.dumps({"status": report_value["status"], "output": _display(output_path), "evidence": _display(evidence_dir), "checks": checks}, ensure_ascii=False))
    return report_value


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outcome", type=Path, default=DEFAULT_OUTCOME)
    parser.add_argument("--evidence-dir", type=Path, default=DEFAULT_EVIDENCE_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--live-dir", type=Path, default=DEFAULT_LIVE_DIR)
    parser.add_argument("--old22-raw", type=Path, default=DEFAULT_OLD22_RAW)
    parser.add_argument("--old22-raw-report", type=Path, default=DEFAULT_OLD22_RAW_REPORT)
    parser.add_argument("--stage-checkpoint", type=Path, default=DEFAULT_STAGE_CHECKPOINT)
    args = parser.parse_args(list(argv) if argv is not None else None)
    archive(
        outcome_path=args.outcome.resolve(),
        evidence_dir=args.evidence_dir.resolve(),
        output_path=args.output.resolve(),
        live_dir=args.live_dir.resolve(),
        old22_raw=args.old22_raw.resolve(),
        old22_raw_report=args.old22_raw_report.resolve(),
        stage_checkpoint=args.stage_checkpoint.resolve(),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
