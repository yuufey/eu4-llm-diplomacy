"""Preserve the four batch-22 control receipt triplets.

Only the four frozen root command reports, their nonce-addressed started /
response / audit files, and the previous six-file snapshot manifest are read.
The live status, raw log, probe files, SQLite database, and game process are
never opened.  Receipt bytes are copied with exclusive creation and streamed
hashing; a source identity, size, and mtime change fails the archive.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
MAX_JSON_BYTES = 2 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
NONCE_RE = re.compile(r"[0-9a-f]{32}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

DEFAULT_STAGE = ROOT / "work/runtime/information-battle-live-20261025-001"
DEFAULT_SOURCE_DIR = ROOT / "work/runtime/diplomacy-observer-20261025-information-battle-live-001"
DEFAULT_OUTPUT_DIR = DEFAULT_STAGE / "control-receipts-snapshots-001"
DEFAULT_OUTPUT_MANIFEST = DEFAULT_OUTPUT_DIR / "manifest.json"
DEFAULT_PREVIOUS_MANIFEST = DEFAULT_STAGE / "natural-capture-snapshots-001/snapshot-manifest.json"

REPORT_SPECS = (
    ("enable", DEFAULT_STAGE / "enable-001.json", "enable", "enabled"),
    ("disable", DEFAULT_STAGE / "disable-001.json", "disable", "disabled"),
    ("resume", DEFAULT_STAGE / "resume-001.json", "enable", "enabled"),
    ("disable_after_window", DEFAULT_STAGE / "disable-after-window-001.json", "disable", "disabled"),
)


class ReceiptArchiveError(RuntimeError):
    """Raised when a frozen receipt or copy boundary fails closed."""


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(resolved)


def _sha256(path: Path) -> tuple[int, str]:
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


def _identity(path: Path) -> dict[str, Any]:
    stat_result = path.stat()
    return {
        "device": stat_result.st_dev,
        "inode": stat_result.st_ino,
        "size_bytes": stat_result.st_size,
        "mtime_ns": stat_result.st_mtime_ns,
    }


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ReceiptArchiveError(f"missing_json:{path}")
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ReceiptArchiveError(f"json_over_bound:{path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReceiptArchiveError(f"invalid_json:{path}:{exc}") from exc
    if not isinstance(value, dict):
        raise ReceiptArchiveError(f"json_object_required:{path}")
    return value


def _load_json_lines(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise ReceiptArchiveError(f"missing_jsonl:{path}")
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ReceiptArchiveError(f"jsonl_over_bound:{path}")
    result: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8", newline="") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ReceiptArchiveError(f"jsonl_object_required:{path}:{line_number}")
                result.append(value)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReceiptArchiveError(f"invalid_jsonl:{path}:{exc}") from exc
    return result


def _require_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value.lower()):
        raise ReceiptArchiveError(f"invalid_sha:{label}")
    return value.lower()


def _require_nonce(value: Any, label: str) -> str:
    if not isinstance(value, str) or not NONCE_RE.fullmatch(value):
        raise ReceiptArchiveError(f"invalid_nonce:{label}")
    return value


def _identity_fields(response: dict[str, Any]) -> dict[str, Any]:
    keys = ("pid", "creation_filetime", "installation", "generation", "exe_sha256", "dll_sha256")
    result = {key: response.get(key) for key in keys}
    if not isinstance(result["pid"], int) or isinstance(result["pid"], bool):
        raise ReceiptArchiveError("response_pid_invalid")
    for key in ("creation_filetime", "installation", "generation"):
        if not isinstance(result[key], str) or not result[key]:
            raise ReceiptArchiveError(f"response_identity_invalid:{key}")
    result["exe_sha256"] = _require_sha(result["exe_sha256"], "response.exe_sha256")
    result["dll_sha256"] = _require_sha(result["dll_sha256"], "response.dll_sha256")
    if result["generation"] != result["creation_filetime"]:
        raise ReceiptArchiveError("generation_creation_mismatch")
    return result


def _validate_report(path: Path, label: str, expected_command: str, expected_state: str) -> dict[str, Any]:
    report = _load_json(path)
    if report.get("status") != "accepted" or report.get("command") != expected_command:
        raise ReceiptArchiveError(f"root_report_not_accepted:{label}")
    nonce = _require_nonce(report.get("nonce"), f"{label}.nonce")
    response = report.get("response")
    if not isinstance(response, dict):
        raise ReceiptArchiveError(f"root_response_missing:{label}")
    if response.get("accepted") is not True or response.get("command") != expected_command or response.get("request_id") != nonce:
        raise ReceiptArchiveError(f"root_response_acceptance_mismatch:{label}")
    if response.get("state") != expected_state:
        raise ReceiptArchiveError(f"root_response_state_mismatch:{label}")
    identity = _identity_fields(response)
    if report.get("installation") != identity["installation"]:
        raise ReceiptArchiveError(f"root_installation_mismatch:{label}")
    return {
        "label": label,
        "path": path,
        "command": expected_command,
        "expected_state": expected_state,
        "nonce": nonce,
        "identity": identity,
        "response": response,
        "report": report,
    }


def _validate_started(path: Path, control: dict[str, Any]) -> dict[str, Any]:
    value = _load_json(path)
    nonce = control["nonce"]
    identity = control["identity"]
    checks = {
        "request_id": value.get("request_id") == nonce,
        "command": value.get("command") == control["command"],
        "pid": value.get("pid") == identity["pid"],
        "creation": value.get("creation") == identity["creation_filetime"],
        "installation": value.get("installation") == identity["installation"],
        "dll_sha256": value.get("dll_sha256") == identity["dll_sha256"],
        "result": value.get("result") == "started_outcome_requires_response",
        "player_ref_present": isinstance(value.get("player_ref"), str) and bool(value.get("player_ref")),
    }
    if not all(checks.values()):
        raise ReceiptArchiveError(f"started_receipt_mismatch:{path}")
    return {"checks": checks, "request_id": nonce, "player_ref": value["player_ref"]}


def _validate_response(path: Path, control: dict[str, Any]) -> dict[str, Any]:
    value = _load_json(path)
    identity = control["identity"]
    checks = {
        "schema": value.get("schema") == "EU4-BATTLE-SOURCE/1",
        "request_id": value.get("request_id") == control["nonce"],
        "command": value.get("command") == control["command"],
        "accepted": value.get("accepted") is True,
        "state": value.get("state") == control["expected_state"],
        "pid": value.get("pid") == identity["pid"],
        "creation_filetime": value.get("creation_filetime") == identity["creation_filetime"],
        "installation": value.get("installation") == identity["installation"],
        "generation": value.get("generation") == identity["generation"],
        "exe_sha256": value.get("exe_sha256") == identity["exe_sha256"],
        "dll_sha256": value.get("dll_sha256") == identity["dll_sha256"],
    }
    if not all(checks.values()):
        raise ReceiptArchiveError(f"response_receipt_mismatch:{path}")
    return {"checks": checks, "response": value}


def _validate_audit(path: Path, control: dict[str, Any], started: dict[str, Any]) -> dict[str, Any]:
    lines = _load_json_lines(path)
    if len(lines) != 2:
        raise ReceiptArchiveError(f"audit_line_count_mismatch:{path}:{len(lines)}")
    identity = control["identity"]
    prepared, outcome = lines
    prepared_checks = {
        "event": prepared.get("event") == "request_prepared",
        "nonce": prepared.get("nonce") == control["nonce"],
        "command": prepared.get("command") == control["command"],
        "pid": prepared.get("pid") == identity["pid"],
        "creation_filetime": prepared.get("creation_filetime") == identity["creation_filetime"],
        "installation": prepared.get("installation") == identity["installation"],
        "dll_sha256": prepared.get("dll_sha256") == identity["dll_sha256"],
        "player_ref": prepared.get("player_ref") == started["player_ref"],
    }
    outcome_response = outcome.get("response")
    if not isinstance(outcome_response, dict):
        raise ReceiptArchiveError(f"audit_outcome_response_missing:{path}")
    outcome_checks = {
        "event": outcome.get("event") == "outcome",
        "nonce": outcome.get("nonce") == control["nonce"],
        "command": outcome.get("command") == control["command"],
        "installation": outcome.get("installation") == identity["installation"],
        "response_request_id": outcome_response.get("request_id") == control["nonce"],
        "response_accepted": outcome_response.get("accepted") is True,
        "response_identity": all(outcome_response.get(key) == identity[key] for key in identity),
    }
    if not all(prepared_checks.values()) or not all(outcome_checks.values()):
        raise ReceiptArchiveError(f"audit_receipt_mismatch:{path}")
    return {"line_count": len(lines), "prepared_checks": prepared_checks, "outcome_checks": outcome_checks}


def _copy_stream(source: Path, destination: Path) -> dict[str, Any]:
    if destination.exists():
        raise ReceiptArchiveError(f"refusing_to_overwrite:{destination}")
    before_identity = _identity(source)
    before_size, before_sha = _sha256(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as source_stream, destination.open("xb") as destination_stream:
        shutil.copyfileobj(source_stream, destination_stream, length=HASH_CHUNK_BYTES)
        destination_stream.flush()
    after_identity = _identity(source)
    after_size, after_sha = _sha256(source)
    if before_identity != after_identity or before_size != after_size or before_sha != after_sha:
        raise ReceiptArchiveError(f"source_changed_during_copy:{source}")
    destination_size, destination_sha = _sha256(destination)
    if destination_size != before_size or destination_sha != before_sha:
        raise ReceiptArchiveError(f"destination_hash_mismatch:{destination}")
    return {
        "source": {"path": _display_path(source), "identity_before": before_identity, "identity_after": after_identity, "size_bytes": before_size, "sha256": before_sha},
        "destination": {"path": _display_path(destination), "identity": _identity(destination), "size_bytes": destination_size, "sha256": destination_sha},
        "checks": {
            "source_identity_stable": before_identity == after_identity,
            "source_hash_stable": before_sha == after_sha,
            "destination_size_matches": destination_size == before_size,
            "destination_hash_matches": destination_sha == before_sha,
        },
    }


def _previous_snapshot(previous_path: Path) -> dict[str, Any]:
    value = _load_json(previous_path)
    copies = value.get("copies")
    if not isinstance(copies, list):
        raise ReceiptArchiveError("previous_snapshot_copies_required")
    receipt_paths = [item.get("snapshot", {}).get("path") for item in copies if isinstance(item, dict) and any(token in str(item.get("source", "")) for token in ("information-battle-started-", "information-battle-response-", "information-battle-control-audit-"))]
    size, digest = _sha256(previous_path)
    return {
        "path": _display_path(previous_path),
        "size_bytes": size,
        "sha256": digest,
        "copy_count": len(copies),
        "receipt_entries_in_previous_manifest": len(receipt_paths),
        "receipt_entry_paths": receipt_paths,
        "statement": "The previous natural-capture snapshot contains six files; this archive adds the twelve nonce receipts separately and does not repair or rewrite the previous manifest.",
    }


def archive(output_dir: Path, output_manifest: Path, source_dir: Path, previous_manifest: Path) -> dict[str, Any]:
    if output_manifest.exists():
        raise ReceiptArchiveError(f"refusing_to_overwrite:{output_manifest}")
    controls = [_validate_report(path, label, command, state) for label, path, command, state in REPORT_SPECS]
    previous = _previous_snapshot(previous_manifest)
    archive_records: list[dict[str, Any]] = []
    for control in controls:
        nonce = control["nonce"]
        source_paths = (
            ("started", source_dir / f"information-battle-started-{nonce}.json"),
            ("response", source_dir / f"information-battle-response-{nonce}.json"),
            ("control_audit", source_dir / f"information-battle-control-audit-{nonce}.jsonl"),
        )
        started_path = source_paths[0][1]
        started = _validate_started(started_path, control)
        validations = {
            "started": started,
            "response": _validate_response(source_paths[1][1], control),
            "control_audit": _validate_audit(source_paths[2][1], control, started),
        }
        for kind, source_path in source_paths:
            destination_path = output_dir / source_path.name
            copy_record = _copy_stream(source_path, destination_path)
            archive_records.append({
                "receipt_kind": kind,
                "nonce": nonce,
                "command": control["command"],
                "root_report": _display_path(control["path"]),
                "identity": control["identity"],
                "validation": validations[kind],
                "copy": copy_record,
            })
    report_pins = []
    for control in controls:
        size, digest = _sha256(control["path"])
        report_pins.append({"label": control["label"], "path": _display_path(control["path"]), "size_bytes": size, "sha256": digest, "nonce": control["nonce"], "command": control["command"]})
    return {
        "schema": "BATTLE-CONTROL-RECEIPTS-SNAPSHOT/1",
        "status": "passed",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": {
            "game_access": False,
            "process_access": False,
            "rpm": False,
            "control_command_sent": False,
            "raw_log_read": False,
            "database_read": False,
            "source_files": 12,
            "copy_mode": "exclusive_streamed_copy_with_before_after_identity_and_hash",
        },
        "root_reports": report_pins,
        "previous_snapshot": previous,
        "source_directory": _display_path(source_dir),
        "receipt_count": len(archive_records),
        "nonce_count": len(controls),
        "receipts": archive_records,
        "checks": {
            "four_root_reports": len(controls) == 4,
            "distinct_nonces": len({control["nonce"] for control in controls}) == 4,
            "twelve_receipts": len(archive_records) == 12,
            "all_copy_checks": all(all(record["copy"]["checks"].values()) for record in archive_records),
            "previous_snapshot_exactly_six_files": previous["copy_count"] == 6,
            "previous_snapshot_receipts_not_rewritten": previous["receipt_entries_in_previous_manifest"] == 0,
        },
        "boundary": "Accepted control responses are preserved as receipts; they do not prove complete business battle export, visibility, ABI, or all-game capture.",
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, default=DEFAULT_SOURCE_DIR)
    parser.add_argument("--previous-manifest", type=Path, default=DEFAULT_PREVIOUS_MANIFEST)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_MANIFEST)
    args = parser.parse_args(list(argv) if argv is not None else None)
    output_dir = args.output_dir.resolve()
    output = args.output.resolve()
    if output.exists():
        raise SystemExit(f"refusing_to_overwrite:{output}")
    report = archive(output_dir, output, args.source_dir.resolve(), args.previous_manifest.resolve())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"status": report["status"], "output": _display_path(output), "receipt_count": report["receipt_count"], "checks": report["checks"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
