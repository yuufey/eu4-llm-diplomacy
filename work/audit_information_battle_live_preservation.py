"""Audit batch-21 pins and the batch-22 artifact-reuse copy.

This is a bounded, read-only filesystem audit.  It does not open the game,
read the live raw log, inspect a process, or recursively scan an archive.
Baseline pins are hashed one file at a time.  The v23 source manifest is
compared with its reused origin and with the 103 source files in the live
copy.  Known raw-ingest test reports are listed separately because they were
not members of the batch-21 325-pin set.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
MAX_JSON_BYTES = 16 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
SHA256_HEX_LEN = 64

DEFAULT_SUMMARY = ROOT / "work/runtime/information-battle-observer-20261025-001/development-summary-001.json"
DEFAULT_REUSE_MANIFEST = ROOT / "work/runtime/diplomacy-observer-20261025-information-battle-live-001/build-manifest.json"
DEFAULT_OUTPUT = ROOT / "work/runtime/information-battle-live-20261025-001/preservation-audit-001.json"

KNOWN_RAW_INGEST_ARTIFACTS = (
    {
        "path": "work/runtime/information-battle-observer-20261025-001/raw-ingest-test-001/report.json",
        "kind": "legacy_misplaced_raw_ingest_test_report",
        "expected_sha256": "bd8b6f35a2e01708e75958a326a1dbb5e7babd7e7cd560de524dc77a7612e9f6",
    },
    {
        "path": "work/runtime/information-battle-live-20261025-001/raw-ingest-test-001/report.json",
        "kind": "batch22_initial_raw_ingest_test_report",
        "expected_sha256": "23eb7fea729bf414ec6bb66f6e3e3c838f01dbbc1437b836c26c1346e5c56bd3",
    },
    {
        "path": "work/runtime/information-battle-live-20261025-001/raw-ingest-test-001/report-002.json",
        "kind": "batch22_current_raw_ingest_test_report",
        "expected_sha256": None,
    },
    {
        "path": "work/ingest_information_battle_raw_live.py",
        "kind": "batch22_raw_ingest_receiver_script",
        "expected_sha256": None,
    },
    {
        "path": "work/test_ingest_information_battle_raw_live.py",
        "kind": "batch22_raw_ingest_test_script",
        "expected_sha256": None,
    },
)


class AuditError(RuntimeError):
    """Raised when an audit input is malformed or exceeds its bound."""


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(resolved)


def _sha256(path: Path) -> tuple[int, str]:
    """Stream-hash one regular file without loading it into memory."""

    try:
        size = path.stat().st_size
    except OSError as exc:
        raise AuditError(f"stat_failed:{path}:{exc}") from exc
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(HASH_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        raise AuditError(f"read_failed:{path}:{exc}") from exc
    return size, digest.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise AuditError(f"json_stat_failed:{path}:{exc}") from exc
    if size > MAX_JSON_BYTES:
        raise AuditError(f"json_too_large:{path}:{size}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuditError(f"json_read_failed:{path}:{exc}") from exc
    if not isinstance(value, dict):
        raise AuditError(f"json_object_required:{path}")
    return value


def _relative_or_absolute(value: str, *, base: Path | None = None) -> Path:
    path = Path(value)
    if not path.is_absolute() and base is not None:
        path = base / path
    return path.resolve()


def _pin_record(path: Path, expected: dict[str, Any] | None = None) -> dict[str, Any]:
    record: dict[str, Any] = {"path": _display_path(path)}
    if expected is not None:
        record["expected_bytes"] = expected.get("bytes")
        record["expected_sha256"] = expected.get("sha256")
    if not path.is_file():
        record.update({"status": "missing", "observed_bytes": None, "observed_sha256": None})
        return record
    size, digest = _sha256(path)
    record["observed_bytes"] = size
    record["observed_sha256"] = digest
    if expected is None:
        record["status"] = "observed"
    else:
        size_match = size == expected.get("bytes")
        sha_match = digest == expected.get("sha256")
        record["size_match"] = size_match
        record["sha256_match"] = sha_match
        record["status"] = "matched" if size_match and sha_match else "content_changed"
    return record


def _validate_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != SHA256_HEX_LEN:
        raise AuditError(f"invalid_sha256:{label}")
    try:
        int(value, 16)
    except ValueError as exc:
        raise AuditError(f"invalid_sha256:{label}") from exc
    return value.lower()


def _source_entries(manifest: dict[str, Any], label: str) -> list[dict[str, str]]:
    entries = manifest.get("sources")
    if not isinstance(entries, list):
        raise AuditError(f"sources_list_required:{label}")
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            raise AuditError(f"invalid_source_entry:{label}:{index}")
        name = entry["name"]
        if not name or Path(name).is_absolute() or ".." in Path(name).parts:
            raise AuditError(f"unsafe_source_name:{label}:{name}")
        if name in seen:
            raise AuditError(f"duplicate_source_name:{label}:{name}")
        seen.add(name)
        result.append({"name": name, "sha256": _validate_sha(entry.get("sha256"), f"{label}:{name}")})
    return result


def _audit_baseline(summary_path: Path) -> dict[str, Any]:
    summary = _load_json(summary_path)
    pins = summary.get("pins")
    if not isinstance(pins, dict):
        raise AuditError("development_summary_pins_required")
    expected_count = summary.get("pin_count")
    if expected_count != len(pins) or expected_count != 325:
        raise AuditError(f"unexpected_baseline_pin_count:{expected_count}:{len(pins)}")
    records: list[dict[str, Any]] = []
    counts = {"matched": 0, "content_changed": 0, "missing": 0}
    for relative, expected in pins.items():
        if not isinstance(relative, str) or not isinstance(expected, dict):
            raise AuditError("invalid_baseline_pin_entry")
        path = _relative_or_absolute(relative, base=ROOT)
        record = _pin_record(path, expected)
        records.append(record)
        status = record["status"]
        counts[status] = counts.get(status, 0) + 1
    changed = [record for record in records if record["status"] != "matched"]
    return {
        "summary": {
            "path": _display_path(summary_path),
            "sha256": _sha256(summary_path)[1],
            "status": summary.get("status"),
            "goal_complete": summary.get("goal_complete"),
            "declared_pin_count": expected_count,
            "declared_pinned_bytes": summary.get("pinned_bytes"),
        },
        "pin_count": len(records),
        "counts": counts,
        "status": "all_matched" if not changed else "content_changes_observed",
        "changed_or_missing": changed,
        "records": records,
    }


def _audit_artifact_reuse(manifest_path: Path) -> dict[str, Any]:
    current = _load_json(manifest_path)
    current_dir = manifest_path.parent.resolve()
    reuse = current.get("artifact_reuse")
    if not isinstance(reuse, dict):
        raise AuditError("artifact_reuse_required")
    origin_value = reuse.get("source_manifest")
    if not isinstance(origin_value, str):
        raise AuditError("artifact_reuse_source_manifest_required")
    origin_path = _relative_or_absolute(origin_value, base=ROOT)
    origin = _load_json(origin_path)
    current_sources = _source_entries(current, "current")
    origin_sources = _source_entries(origin, "origin")
    current_by_name = {entry["name"]: entry for entry in current_sources}
    origin_by_name = {entry["name"]: entry for entry in origin_sources}
    names = sorted(set(current_by_name) | set(origin_by_name))
    source_records: list[dict[str, Any]] = []
    mismatches: list[dict[str, Any]] = []
    for name in names:
        current_entry = current_by_name.get(name)
        origin_entry = origin_by_name.get(name)
        current_path = current_dir / name
        origin_path_for_source = origin_path.parent / name
        record: dict[str, Any] = {
            "name": name,
            "manifest_membership": {
                "current": current_entry is not None,
                "origin": origin_entry is not None,
            },
            "declared_sha256": {
                "current": current_entry["sha256"] if current_entry else None,
                "origin": origin_entry["sha256"] if origin_entry else None,
            },
        }
        if current_entry is None or origin_entry is None:
            record["status"] = "manifest_membership_changed"
            mismatches.append(record)
            source_records.append(record)
            continue
        current_size, current_sha = _sha256(current_path) if current_path.is_file() else (None, None)
        origin_size, origin_sha = _sha256(origin_path_for_source) if origin_path_for_source.is_file() else (None, None)
        record["current_file"] = {"path": _display_path(current_path), "bytes": current_size, "sha256": current_sha}
        record["origin_file"] = {"path": _display_path(origin_path_for_source), "bytes": origin_size, "sha256": origin_sha}
        checks = {
            "manifest_sha_equal": current_entry["sha256"] == origin_entry["sha256"],
            "current_file_matches_manifest": current_sha == current_entry["sha256"],
            "origin_file_matches_manifest": origin_sha == origin_entry["sha256"],
            "copied_file_equal": current_sha is not None and current_sha == origin_sha,
        }
        record["checks"] = checks
        record["status"] = "matched" if all(checks.values()) else "mismatch"
        if record["status"] != "matched":
            mismatches.append(record)
        source_records.append(record)

    current_manifest_size, current_manifest_sha = _sha256(manifest_path)
    origin_manifest_size, origin_manifest_sha = _sha256(origin_path)
    current_dll_path = _relative_or_absolute(str(current.get("dll", "")), base=current_dir)
    origin_dll_path = _relative_or_absolute(str(origin.get("dll", "")), base=origin_path.parent)
    current_dll_size, current_dll_sha = _sha256(current_dll_path) if current_dll_path.is_file() else (None, None)
    origin_dll_size, origin_dll_sha = _sha256(origin_dll_path) if origin_dll_path.is_file() else (None, None)
    declared_source_manifest_sha = _validate_sha(reuse.get("source_manifest_sha256"), "artifact_reuse.source_manifest_sha256")
    declared_source_dll_sha = _validate_sha(reuse.get("source_dll_sha256"), "artifact_reuse.source_dll_sha256")
    manifest_checks = {
        "origin_manifest_declared_sha_matches_actual": declared_source_manifest_sha == origin_manifest_sha,
        "current_and_origin_manifest_sources_equal": current_sources == origin_sources,
        "current_manifest_source_count_103": len(current_sources) == 103,
        "origin_manifest_source_count_103": len(origin_sources) == 103,
        "compiled_in_this_directory_false": reuse.get("compiled_in_this_directory") is False,
        "current_dll_declared_sha_matches_actual": current.get("dll_sha256") == current_dll_sha,
        "origin_dll_declared_sha_matches_actual": origin.get("dll_sha256") == origin_dll_sha,
        "artifact_reuse_dll_sha_matches_origin": declared_source_dll_sha == origin.get("dll_sha256"),
        "current_live_dll_matches_origin": current_dll_sha is not None and current_dll_sha == origin_dll_sha,
    }
    if not all(manifest_checks.values()):
        mismatches.append({"kind": "manifest_or_dll", "checks": manifest_checks})
    return {
        "status": "all_103_sources_matched" if not mismatches else "reuse_mismatch_observed",
        "current_manifest": {
            "path": _display_path(manifest_path),
            "bytes": current_manifest_size,
            "sha256": current_manifest_sha,
            "source_count": len(current_sources),
            "experiment_id": current.get("experiment_id"),
        },
        "origin_manifest": {
            "path": _display_path(origin_path),
            "bytes": origin_manifest_size,
            "sha256": origin_manifest_sha,
            "source_count": len(origin_sources),
            "declared_sha256": declared_source_manifest_sha,
            "experiment_id": origin.get("experiment_id"),
        },
        "artifact_reuse": {
            "source_manifest": origin_value,
            "source_manifest_sha256": declared_source_manifest_sha,
            "source_dll_sha256": declared_source_dll_sha,
            "compiled_in_this_directory": reuse.get("compiled_in_this_directory"),
        },
        "dll": {
            "current": {"path": _display_path(current_dll_path), "bytes": current_dll_size, "sha256": current_dll_sha},
            "origin": {"path": _display_path(origin_dll_path), "bytes": origin_dll_size, "sha256": origin_dll_sha},
        },
        "manifest_checks": manifest_checks,
        "source_count": len(source_records),
        "matched_source_count": sum(record.get("status") == "matched" for record in source_records),
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
        "source_records": source_records,
    }


def _audit_known_extras() -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for item in KNOWN_RAW_INGEST_ARTIFACTS:
        path = ROOT / item["path"]
        record = _pin_record(path)
        record.update({"kind": item["kind"], "baseline_pin_member": False})
        expected = item.get("expected_sha256")
        if expected is not None and record["status"] != "missing":
            record["expected_sha256"] = expected
            record["expected_sha256_match"] = record["observed_sha256"] == expected
            record["status"] = "preserved" if record["expected_sha256_match"] else "changed_from_known_artifact"
        records.append(record)
    return {
        "status": "observed_separately_from_baseline_pins",
        "records": records,
        "note": "These raw-ingest reports/scripts are intentionally reported as extra artifacts; they are not counted as changes to the 325 baseline pins.",
    }


def audit(summary_path: Path, reuse_manifest: Path) -> dict[str, Any]:
    baseline = _audit_baseline(summary_path)
    artifact_reuse = _audit_artifact_reuse(reuse_manifest)
    extras = _audit_known_extras()
    baseline_ok = baseline["status"] == "all_matched"
    reuse_ok = artifact_reuse["status"] == "all_103_sources_matched"
    known_old_preserved = all(
        record.get("kind") != "legacy_misplaced_raw_ingest_test_report" or record.get("status") == "preserved"
        for record in extras["records"]
    )
    return {
        "schema": "information_battle_live_preservation_audit_v1",
        "status": "passed" if baseline_ok and reuse_ok and known_old_preserved else "mismatch_observed",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": {
            "game_access": False,
            "process_access": False,
            "live_raw_log_read": False,
            "control_command_sent": False,
            "rea_access": False,
            "recursive_archive_scan": False,
            "hash_mode": "streamed_sha256_1MiB_chunks",
        },
        "baseline_pin_audit": baseline,
        "artifact_reuse_audit": artifact_reuse,
        "known_extra_raw_ingest_artifacts": extras,
        "conclusion": {
            "baseline_pin_count": baseline["pin_count"],
            "baseline_content_or_missing_count": len(baseline["changed_or_missing"]),
            "artifact_reuse_source_count": artifact_reuse["source_count"],
            "artifact_reuse_mismatch_count": artifact_reuse["mismatch_count"],
            "distinction": "Baseline pin changes and extra raw-ingest artifacts are counted in separate sections; an extra report does not become a baseline content mismatch.",
        },
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--reuse-manifest", type=Path, default=DEFAULT_REUSE_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(list(argv) if argv is not None else None)
    output = args.output.resolve()
    if output.exists():
        raise SystemExit(f"refusing_to_overwrite:{output}")
    report = audit(args.summary.resolve(), args.reuse_manifest.resolve())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"status": report["status"], "output": _display_path(output), "baseline": report["conclusion"], "artifact_reuse": report["artifact_reuse_audit"]["status"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
