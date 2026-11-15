#!/usr/bin/env python3
"""Freeze mutable v23 lifecycle inputs, then audit a snapshot-only revision.

Revision 001 intentionally remains untouched.  This revision first copies the
small live status/control/wire/receipt inputs with exclusive creation and then
uses only those copies for the resulting report.  No process or control API is
opened by this script.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import pathlib
import sys
from typing import Any

import validate_information_battle_live_lifecycle as v1


SNAPSHOT_STAGE = v1.LIVE_STAGE / "lifecycle-snapshots-001"
DEFAULT_OUTPUT = v1.LIVE_STAGE / "lifecycle-acceptance-002.json"
SNAPSHOT_MAX_BYTES = 2 * 1024 * 1024


def now_utc() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def copy_snapshot(source: pathlib.Path, destination: pathlib.Path, observed_at: str) -> dict[str, Any]:
    if not source.is_file():
        raise v1.AuditError(f"missing live source: {source}")
    start = source.stat()
    if start.st_size > SNAPSHOT_MAX_BYTES:
        raise v1.AuditError(f"mutable source exceeds snapshot bound: {source} ({start.st_size} bytes)")
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = __import__("hashlib").sha256()
    total = 0
    try:
        with source.open("rb") as src, destination.open("xb") as dst:
            while True:
                chunk = src.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > SNAPSHOT_MAX_BYTES:
                    raise v1.AuditError(f"mutable source grew beyond bound: {source}")
                digest.update(chunk)
                dst.write(chunk)
    except Exception:
        raise
    end = source.stat()
    stable = start.st_size == end.st_size and start.st_mtime_ns == end.st_mtime_ns
    if not stable:
        raise v1.AuditError(f"live source changed while snapshotting: {source}")
    snapshot_sha = digest.hexdigest()
    return {
        "source": {
            "path": source.relative_to(v1.ROOT).as_posix(),
            "size_bytes": start.st_size,
            "mtime_ns": start.st_mtime_ns,
            "sha256": snapshot_sha,
        },
        "snapshot": {
            "path": destination.relative_to(v1.ROOT).as_posix(),
            "size_bytes": total,
            "sha256": snapshot_sha,
        },
        "observed_at_utc": observed_at,
        "source_stable_during_copy": True,
    }


def snapshot_inputs() -> dict[str, dict[str, Any]]:
    observed_at = now_utc()
    names: list[tuple[str, pathlib.Path]] = [
        ("installation", v1.LIVE_DIR / "installation.json"),
        ("binding", v1.LIVE_DIR / "information-battle-binding.json"),
        ("status", v1.LIVE_DIR / "information-battle-status.json"),
        ("raw", v1.LIVE_DIR / "information-battle-raw.jsonl"),
        ("control_probe", v1.LIVE_DIR / "control-probe.jsonl"),
        ("loader_output", v1.LIVE_DIR / "loader-output.txt"),
        ("build_manifest", v1.LIVE_DIR / "build-manifest.json"),
    ]
    for control_name, (_, nonce, _) in v1.EXPECTED_CONTROL.items():
        names.extend(
            [
                (f"started_{nonce}", v1.LIVE_DIR / f"information-battle-started-{nonce}.json"),
                (f"response_{nonce}", v1.LIVE_DIR / f"information-battle-response-{nonce}.json"),
            ]
        )
    SNAPSHOT_STAGE.mkdir(parents=True, exist_ok=False)
    records: dict[str, dict[str, Any]] = {}
    for label, source in names:
        suffix = source.suffix or ".bin"
        destination = SNAPSHOT_STAGE / f"{label}{suffix}"
        records[label] = copy_snapshot(source, destination, observed_at)
    manifest = {
        "schema": "INFORMATION-BATTLE-LIVE-LIFECYCLE-SNAPSHOT/1",
        "observed_at_utc": observed_at,
        "source_directory": v1.LIVE_DIR.relative_to(v1.ROOT).as_posix(),
        "snapshot_directory": SNAPSHOT_STAGE.relative_to(v1.ROOT).as_posix(),
        "bounded_bytes_per_file": SNAPSHOT_MAX_BYTES,
        "records": records,
    }
    manifest_path = SNAPSHOT_STAGE / "snapshot-manifest.json"
    with manifest_path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    manifest_sha, manifest_size = v1.sha256_file(manifest_path)
    return {
        "manifest": {
            "path": manifest_path.relative_to(v1.ROOT).as_posix(),
            "size_bytes": manifest_size,
            "sha256": manifest_sha,
        },
        "records": records,
    }


def snapshot_path(records: dict[str, dict[str, Any]], label: str) -> pathlib.Path:
    return v1.ROOT / records[label]["snapshot"]["path"]


def scan_jsonl(path: pathlib.Path) -> dict[str, Any]:
    line_count = 0
    invalid = 0
    oversize = 0
    events: dict[str, int] = {}
    with path.open("rb") as handle:
        for raw in handle:
            line_count += 1
            if len(raw) > v1.MAX_LINE_BYTES:
                oversize += 1
                continue
            try:
                item = json.loads(raw.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError):
                invalid += 1
                continue
            if isinstance(item, dict) and isinstance(item.get("event"), str):
                events[item["event"]] = events.get(item["event"], 0) + 1
    return {"lines": line_count, "invalid_lines": invalid, "oversize_lines": oversize, "event_counts": events}


def run(output: pathlib.Path, verify_existing: bool) -> dict[str, Any]:
    if verify_existing:
        data, record = v1.read_json(output)
        v1.require(data.get("schema") == "INFORMATION-BATTLE-LIVE-LIFECYCLE-AUDIT/2", "existing revision002 schema mismatch")
        v1.require(data.get("snapshot_only") is True, "existing report is not snapshot-only")
        return {"status": "verified", "path": record["path"], "bytes": record["size_bytes"], "sha256": record["sha256"]}

    snapshots = snapshot_inputs()
    records = snapshots["records"]
    installation, installation_record = v1.read_json(snapshot_path(records, "installation"))
    v1.require(installation.get("pid") == 39456, "installation PID mismatch")
    v1.require(installation.get("creation_filetime") == v1.EXPECTED_CREATION, "installation creation mismatch")
    v1.require(installation.get("session_id") == v1.EXPECTED_SESSION, "installation session mismatch")
    v1.require(installation.get("game_sha256") == v1.EXPECTED_GAME_SHA, "installation EXE hash mismatch")
    v1.require(installation.get("dll_sha256") == v1.EXPECTED_DLL_SHA, "installation DLL hash mismatch")
    v1.require(installation.get("installation_returncode") == 0, "installation return code mismatch")
    v1.require(installation.get("ready_reason") == "verified_load_confirmation", "installation readiness mismatch")
    v1.require(len(installation.get("ready_attempts") or []) == 1 and (installation.get("ready_attempts") or [])[0].get("outcome") == "ready", "ready attempt mismatch")
    v1.require(installation.get("runtime_verified") is False, "installation must not claim runtime_verified")

    binding, binding_record = v1.read_json(snapshot_path(records, "binding"))
    v1.require(binding.get("installation") == v1.EXPECTED_INSTALLATION, "binding installation mismatch")
    v1.require(binding.get("generation") == v1.EXPECTED_GENERATION, "binding generation mismatch")
    v1.require(binding.get("creation_filetime") == str(v1.EXPECTED_CREATION), "binding creation mismatch")
    v1.require(binding.get("session_id") == v1.EXPECTED_SESSION, "binding session mismatch")
    v1.require(binding.get("pid") == 39456, "binding PID mismatch")
    v1.require(binding.get("game_sha256") == v1.EXPECTED_GAME_SHA and binding.get("dll_sha256") == v1.EXPECTED_DLL_SHA, "binding hashes mismatch")

    phases: list[dict[str, Any]] = []
    for phase, expected_patch in v1.EXPECTED_PHASES:
        report_path = v1.LIVE_STAGE / phase / "report.json"
        report, report_record = v1.read_json(report_path)
        summary = v1.phase_snapshot(report, phase)
        v1.require(summary["expect_patch"] == expected_patch, f"{phase}: patch expectation mismatch")
        summary["report"] = report_record
        phases.append(summary)

    controls: dict[str, Any] = {}
    started: dict[str, Any] = {}
    for name, expected in v1.EXPECTED_CONTROL.items():
        controls[name] = v1.control_receipt(v1.LIVE_STAGE / name, expected)
        nonce = expected[1]
        started_file = snapshot_path(records, f"started_{nonce}")
        response_file = snapshot_path(records, f"response_{nonce}")
        started[name] = v1.started_response(started_file, response_file, expected)

    status, status_record = v1.read_json(snapshot_path(records, "status"))
    v1.require(status.get("pid") == 39456 and status.get("creation_filetime") == v1.EXPECTED_GENERATION, "status identity mismatch")
    v1.require(status.get("generation") == v1.EXPECTED_GENERATION and status.get("installation") == v1.EXPECTED_INSTALLATION, "status binding mismatch")
    v1.require(status.get("state") == "enabled", "snapshot final status is not enabled")
    v1.require(status.get("captured") == "0" and status.get("capture_complete") is False, "snapshot status capture changed")
    v1.require(status.get("business_export_available") is False and status.get("visibility_verified") is False, "snapshot status overclaims capture")
    v1.require(status.get("dll_sha256") == v1.EXPECTED_DLL_SHA and status.get("exe_sha256") == v1.EXPECTED_GAME_SHA, "snapshot status hash mismatch")

    status_before, status_before_record = v1.read_json(v1.LIVE_STAGE / "status-before-enable-001.json")
    v1.require(status_before.get("native", {}).get("code_patch_installed") is False, "default-off status already patched")
    v1.require(status_before.get("native", {}).get("captured") == "0", "default-off status captured data")

    raw_path = snapshot_path(records, "raw")
    raw_record = records["raw"]["snapshot"]
    raw_lines: list[str] = []
    with raw_path.open("rb") as handle:
        for line in handle:
            v1.require(len(line) <= v1.MAX_LINE_BYTES, "snapshot raw line exceeds bound")
            raw_lines.append(line.decode("utf-8", errors="strict").rstrip("\r\n"))
    v1.require(len(raw_lines) == 1 and raw_lines[0].startswith("EU4_OWNED_BATTLE_WIRE_V1 "), "snapshot raw must be header only")

    probe_path = snapshot_path(records, "control_probe")
    probe_scan = scan_jsonl(probe_path)
    v1.require(probe_scan["invalid_lines"] == 0 and probe_scan["oversize_lines"] == 0, "snapshot control-probe contains invalid lines")

    loader, loader_record = v1.read_json(snapshot_path(records, "loader_output"))
    v1.require(loader.get("bridge_thread_exit_status") == "0x0", "loader bridge exit mismatch")
    v1.require(loader.get("load_thread_exit_status") == "0x4a00000", "loader thread status mismatch")
    v1.require(loader.get("test_save_acknowledged") is True and loader.get("dll_unloaded") is False, "loader state mismatch")
    v1.require(loader.get("warnings") == [], "loader warnings present")

    manifest, manifest_record = v1.read_json(snapshot_path(records, "build_manifest"))
    v1.require(manifest.get("version") == 23 and manifest.get("compiled") is True, "snapshot manifest mismatch")
    v1.require(manifest.get("dll_sha256") == v1.EXPECTED_DLL_SHA and manifest.get("runtime_verified") is False, "snapshot manifest claims invalid runtime")

    restart, restart_record = v1.read_json(v1.LIVE_STAGE / "restart-outcome-001.json")
    pre_restart = v1.LIVE_STAGE / "pre-restart-001"
    v1.require(pre_restart.is_file() and not pre_restart.is_dir(), "pre-restart-001 must remain a file")
    v1.require(restart.get("state") == "restarted_verified_new_unloaded_process", "restart outcome mismatch")
    v1.require(restart.get("restart_shell_exit") == 0, "restart shell exit mismatch")
    v1.require("output is a file, not a directory" in restart.get("audit_exception", ""), "restart receipt failure missing")
    v1.require("No started receipt was created" in restart.get("audit_exception", ""), "restart no-receipt caveat missing")
    v1.require("Existing user restart authorization" in restart.get("audit_exception", ""), "restart authorization provenance missing")

    old_report = v1.LIVE_STAGE / "lifecycle-acceptance-001.json"
    old_report_record = v1.file_record(old_report)
    v1.require(old_report_record.get("exists") is True, "revision001 report missing")

    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    script_hash, script_size = v1.sha256_file(pathlib.Path(__file__).resolve())
    report = {
        "schema": "INFORMATION-BATTLE-LIVE-LIFECYCLE-AUDIT/2",
        "status": "passed_paused_v23_lifecycle_capture_unverified_revision2",
        "snapshot_only": True,
        "generated_by": {"path": pathlib.Path(__file__).resolve().relative_to(v1.ROOT).as_posix(), "size_bytes": script_size, "sha256": script_hash},
        "validator_revision001": v1.file_record(pathlib.Path(v1.__file__).resolve()),
        "scope": {"read_only_audit": True, "new_game_access": False, "new_control_commands": False, "new_rpm_or_rea": False, "business_dispatch_or_replay": False, "mutable_live_inputs_used_directly": False, "snapshot_exclusive_create": True},
        "snapshot": snapshots["manifest"],
        "mutable_input_records": records,
        "installation": installation_record,
        "binding": binding_record,
        "phases": phases,
        "control_receipts": controls,
        "started_response_pairs": started,
        "status_before_enable": status_before_record,
        "status_final_snapshot": status_record,
        "control_probe_snapshot": {"record": records["control_probe"]["snapshot"], "scan": probe_scan, "abi_verified": False},
        "wire_and_loader_snapshots": {"raw": raw_record, "raw_lines": len(raw_lines), "header_only": True, "loader": loader_record},
        "restart_outcome": {"record": restart_record, "pre_restart_input": v1.file_record(pre_restart), "receipt_failure_recorded": True, "started_receipt_created": False, "authorization_provenance": "restart-outcome records existing user authorization and fresh preflight; this audit grants no retrospective authorization"},
        "source_provenance": {"live_manifest_snapshot": manifest_record, "live_manifest_version": manifest.get("version"), "dll_sha256": v1.EXPECTED_DLL_SHA, "coff_stub_rva": "0x9ceb0", "historical_revision001_preserved": old_report_record},
        "checks": {"full_identity_creation_session_stable": True, "exe_and_dll_hashes_stable": True, "physical_player_por_slot189_stable": True, "all_phases_date_56553384_paused_speed0": True, "original_to_exact_installed_control_state": True, "coff_stub_rva_0x9ceb0": True, "disable_retained_patch_resources": True, "resume_same_installation_and_generation": True, "default_off_before_enable": True, "captured_records": 0, "abi_verified": False, "natural_battle_event_verified": False, "visibility_verified": False},
        "limitations": ["This revision is fixed to lifecycle-snapshots-001; later live status/control-probe/raw changes do not alter the report.", "The four phase reports prove identity, paused state, code guards, and lifecycle receipts; they do not prove a natural battle callback ABI.", "Zero captured records and a header-only raw snapshot are absence evidence, not ABI or visibility proof.", "The live inputs reuse the pinned v23-005 DLL/source manifest; revision001 remains unchanged.", "The restart pre-action receipt script failed because pre-restart-001 was a file rather than a directory; restart-outcome records existing authorization and fresh preflight without fabricating a prior receipt."],
    }
    try:
        with output.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
    except FileExistsError as exc:
        raise v1.AuditError(f"refusing to overwrite existing output: {output}") from exc
    digest, size = v1.sha256_file(output)
    return {"status": report["status"], "path": output.relative_to(v1.ROOT).as_posix(), "bytes": size, "sha256": digest}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=pathlib.Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--verify-existing", action="store_true")
    args = parser.parse_args()
    try:
        result = run(args.output.resolve(), args.verify_existing)
    except (v1.AuditError, OSError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
