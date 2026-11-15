#!/usr/bin/env python3
"""Bounded, read-only audit of the recorded v23 paused lifecycle.

This validator reads the already-produced live reports and control receipts.  It
does not open a process, send a command, alter a control file, or mutate any
historical artifact.  Output is exclusive-create so an audit cannot silently
replace a prior result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
LIVE_STAGE = ROOT / "work" / "runtime" / "information-battle-live-20261025-001"
LIVE_DIR = ROOT / "work" / "runtime" / "diplomacy-observer-20261025-information-battle-live-001"
DEFAULT_OUTPUT = LIVE_STAGE / "lifecycle-acceptance-001.json"
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_LINE_BYTES = 2 * 1024 * 1024
EXPECTED_GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_DLL_SHA = "eaf53986e159bfca7af717228a7bc983a8df03fec32a23eb4a82e5ca503133c3"
EXPECTED_DATE = 56553384
EXPECTED_PLAYER = "POR"
EXPECTED_SLOT = 189
EXPECTED_COFF_RVA = "0x9ceb0"
EXPECTED_INSTALLATION = "2441212204318969762"
EXPECTED_GENERATION = "134374061200954087"
EXPECTED_SESSION = "39456-1dd647f28e8d2e7"
EXPECTED_CREATION = 134374061200954087
EXPECTED_PHASES = (
    ("loaded-v23-original-001", "original"),
    ("enabled-v23-001", "installed"),
    ("disabled-v23-001", "installed"),
    ("resumed-v23-001", "installed"),
)
EXPECTED_CONTROL = {
    "enable-001.json": ("enable", "59941ce9dc9eec2ad71a9748e84d9e5e", "enabled"),
    "disable-001.json": ("disable", "3bee34fa52f24b5a8f73e3e658a94d29", "disabled"),
    "resume-001.json": ("enable", "3c6f171f1e9f0f137c2aac7e69f7fd78", "enabled"),
}


class AuditError(RuntimeError):
    pass


def sha256_file(path: pathlib.Path) -> tuple[str, int]:
    h = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            h.update(block)
    return h.hexdigest(), total


def read_json(path: pathlib.Path, *, limit: int = MAX_JSON_BYTES) -> tuple[Any, dict[str, Any]]:
    if not path.is_file():
        raise AuditError(f"missing file: {path}")
    size = path.stat().st_size
    if size > limit:
        raise AuditError(f"JSON exceeds bounded input: {path} ({size} bytes)")
    digest, actual_size = sha256_file(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuditError(f"invalid JSON: {path}: {exc}") from exc
    return value, {"path": path.relative_to(ROOT).as_posix(), "size_bytes": actual_size, "sha256": digest}


def file_record(path: pathlib.Path) -> dict[str, Any]:
    if not path.is_file():
        return {"path": path.relative_to(ROOT).as_posix(), "exists": False}
    digest, size = sha256_file(path)
    return {"path": path.relative_to(ROOT).as_posix(), "exists": True, "size_bytes": size, "sha256": digest}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AuditError(message)


def phase_snapshot(report: dict[str, Any], phase: str) -> dict[str, Any]:
    require(report.get("status") == "passed_read_only_preflight", f"{phase}: report status is not passed")
    require(report.get("evidence_kind") == "fresh_pure_rpm_preflight", f"{phase}: unexpected evidence kind")
    require(report.get("read_only") is True, f"{phase}: report is not read-only")
    require(report.get("completed") is True, f"{phase}: report incomplete")
    require(report.get("errors") == [], f"{phase}: report contains errors")
    request = report.get("request") or {}
    require(request.get("business_query_invoked") is False, f"{phase}: business query invoked")
    require(request.get("native_game_function_invoked") is False, f"{phase}: native game call invoked")
    require(request.get("target_memory_writes") is False, f"{phase}: target memory write recorded")
    require(request.get("save_or_reload") is False, f"{phase}: save/reload recorded")
    require(request.get("date_advance") is False, f"{phase}: date advance recorded")
    require(request.get("dll_injection") is False, f"{phase}: report records DLL injection")
    require(request.get("dll_unload") is False, f"{phase}: report records DLL unload")

    identity = report.get("identity") or {}
    require(identity.get("binding_verified") is True, f"{phase}: identity binding not verified")
    before_identity = identity.get("before") or {}
    after_identity = identity.get("after") or {}
    for side, item in (("before", before_identity), ("after", after_identity)):
        require(item.get("pid") == 39456, f"{phase}/{side}: PID mismatch")
        require(item.get("process_creation_filetime") == EXPECTED_CREATION, f"{phase}/{side}: creation mismatch")
        require(item.get("session_id") == EXPECTED_SESSION, f"{phase}/{side}: session mismatch")
        require(item.get("process_path_sha256_matches_expected") is True, f"{phase}/{side}: EXE hash mismatch")
        require(item.get("unknown_conditions") == [], f"{phase}/{side}: unknown identity conditions")

    loaded = report.get("loaded_dll") or {}
    loaded_after = loaded.get("after") or {}
    matches = loaded_after.get("matching_modules") or []
    require(loaded_after.get("expected_sha256") == EXPECTED_DLL_SHA, f"{phase}: expected DLL SHA mismatch")
    matching = [m for m in matches if m.get("sha256_matches_expected") is True]
    require(len(matching) == 1, f"{phase}: expected exactly one matching loaded v23 DLL")
    require(matching[0].get("sha256") == EXPECTED_DLL_SHA, f"{phase}: loaded DLL SHA mismatch")
    require(matching[0].get("path_matches_expected") is True, f"{phase}: loaded DLL path mismatch")

    guard = report.get("fixed_file_code_guard") or {}
    require(guard.get("status") == "observed", f"{phase}: fixed code guard not observed")
    require(guard.get("unknown_conditions") == [], f"{phase}: fixed code guard has unknown conditions")
    records = guard.get("records") or {}
    require(records.get("entry_238620_original", {}).get("matches") is True, f"{phase}: original entry guard mismatch")
    require(records.get("unwind_1de6c98_original", {}).get("matches") is True, f"{phase}: original unwind guard mismatch")

    doublepass = report.get("doublepass") or {}
    require(doublepass.get("performed") is True, f"{phase}: double pass missing")
    require(doublepass.get("consistent") is True, f"{phase}: double pass inconsistent")
    require(doublepass.get("mismatches") == [], f"{phase}: double pass mismatches")
    cleanup = report.get("cleanup") or {}
    handle_close = cleanup.get("handle_close") or {}
    require(handle_close.get("closed") is True and handle_close.get("success") is True, f"{phase}: RPM handle not closed")

    sides: dict[str, Any] = {}
    for side in ("before", "after"):
        snap = report.get(side) or {}
        control = snap.get("control") or {}
        paused = (control.get("paused") or {}).get("value")
        speed = (control.get("speed") or {}).get("value")
        game_date = snap.get("game_date") or {}
        player = snap.get("physical_player") or {}
        require(paused is True, f"{phase}/{side}: paused flag is not true")
        require(speed == 0, f"{phase}/{side}: speed is not zero")
        require(game_date.get("raw") == EXPECTED_DATE, f"{phase}/{side}: date mismatch")
        require(player.get("tag") == EXPECTED_PLAYER and player.get("slot") == EXPECTED_SLOT, f"{phase}/{side}: player mismatch")
        sides[side] = {
            "paused": paused,
            "speed": speed,
            "date_raw": game_date.get("raw"),
            "date_raw_hex": game_date.get("raw_hex"),
            "player_tag": player.get("tag"),
            "player_slot": player.get("slot"),
        }

    return {
        "name": phase,
        "status": report.get("status"),
        "expect_patch": request.get("expect_patch"),
        "identity": {
            "pid": before_identity.get("pid"),
            "creation_filetime": before_identity.get("process_creation_filetime"),
            "session_id": before_identity.get("session_id"),
            "process_path": before_identity.get("process_path"),
            "process_path_sha256_matches_expected": before_identity.get("process_path_sha256_matches_expected"),
        },
        "loaded_dll": {
            "sha256": matching[0].get("sha256"),
            "path": matching[0].get("path"),
            "size_bytes": matching[0].get("size_bytes"),
        },
        "fixed_code_guard": {
            "entry_rva": records.get("entry_238620_original", {}).get("rva"),
            "entry_matches": records.get("entry_238620_original", {}).get("matches"),
            "unwind_rva": records.get("unwind_1de6c98_original", {}).get("rva"),
            "unwind_matches": records.get("unwind_1de6c98_original", {}).get("matches"),
        },
        "before": sides["before"],
        "after": sides["after"],
        "rpm": {
            "calls": (report.get("access") or {}).get("rpm_calls"),
            "bytes_requested": (report.get("access") or {}).get("rpm_bytes_requested"),
        },
    }


def control_receipt(path: pathlib.Path, expected: tuple[str, str, str]) -> dict[str, Any]:
    command, nonce, expected_state = expected
    data, record = read_json(path)
    require(data.get("status") == "accepted", f"{path.name}: command not accepted")
    require(data.get("command") == command, f"{path.name}: command mismatch")
    require(data.get("nonce") == nonce, f"{path.name}: nonce mismatch")
    require(data.get("installation") == EXPECTED_INSTALLATION, f"{path.name}: installation mismatch")
    response = data.get("response") or {}
    require(response.get("accepted") is True, f"{path.name}: response not accepted")
    require(response.get("request_id") == nonce, f"{path.name}: response request_id mismatch")
    require(response.get("command") == command, f"{path.name}: response command mismatch")
    require(response.get("state") == expected_state, f"{path.name}: response state mismatch")
    require(response.get("installation") == EXPECTED_INSTALLATION, f"{path.name}: response installation mismatch")
    require(response.get("generation") == EXPECTED_GENERATION, f"{path.name}: generation changed")
    require(response.get("creation_filetime") == EXPECTED_GENERATION, f"{path.name}: response creation mismatch")
    require(response.get("dll_sha256") == EXPECTED_DLL_SHA, f"{path.name}: response DLL mismatch")
    require(response.get("exe_sha256") == EXPECTED_GAME_SHA, f"{path.name}: response EXE mismatch")
    require(response.get("patch_attempt_published") is True, f"{path.name}: patch publication missing")
    require(response.get("code_patch_installed") is True, f"{path.name}: patch not installed")
    require(response.get("publication_stage") == 7, f"{path.name}: publication stage mismatch")
    require(response.get("unwind_registered") is True, f"{path.name}: unwind not registered")
    require(response.get("dll_pinned") is True, f"{path.name}: DLL not pinned")
    require(response.get("captured") == "0", f"{path.name}: capture count changed")
    require(response.get("capture_complete") is False, f"{path.name}: capture unexpectedly complete")
    require(response.get("business_export_available") is False, f"{path.name}: business export available")
    require(response.get("visibility_verified") is False, f"{path.name}: visibility claimed verified")
    return {
        "file": record,
        "command": command,
        "nonce": nonce,
        "expected_state": expected_state,
        "installation": data.get("installation"),
        "response": {
            "state": response.get("state"),
            "reason": response.get("reason"),
            "generation": response.get("generation"),
            "captured": response.get("captured"),
            "code_patch_installed": response.get("code_patch_installed"),
            "publication_stage": response.get("publication_stage"),
            "unwind_registered": response.get("unwind_registered"),
            "dll_pinned": response.get("dll_pinned"),
            "business_export_available": response.get("business_export_available"),
            "capture_complete": response.get("capture_complete"),
            "visibility_verified": response.get("visibility_verified"),
        },
    }


def started_response(path: pathlib.Path, response_path: pathlib.Path, expected: tuple[str, str, str]) -> dict[str, Any]:
    command, nonce, _ = expected
    started, started_record = read_json(path)
    response, response_record = read_json(response_path)
    require(started.get("command") == command and started.get("request_id") == nonce, f"{path.name}: started receipt binding mismatch")
    require(started.get("installation") == EXPECTED_INSTALLATION, f"{path.name}: started installation mismatch")
    require(started.get("creation") == EXPECTED_CREATION.__str__(), f"{path.name}: started creation mismatch")
    require(started.get("dll_sha256") == EXPECTED_DLL_SHA, f"{path.name}: started DLL mismatch")
    require(response.get("request_id") == nonce and response.get("command") == command, f"{response_path.name}: response binding mismatch")
    return {"started": started_record, "response": response_record}


def run(output: pathlib.Path, verify_existing: bool) -> dict[str, Any]:
    if verify_existing:
        data, record = read_json(output)
        require(data.get("schema") == "INFORMATION-BATTLE-LIVE-LIFECYCLE-AUDIT/1", "existing report schema mismatch")
        return {"status": "verified", "path": record["path"], "bytes": record["size_bytes"], "sha256": record["sha256"]}

    installation_path = LIVE_DIR / "installation.json"
    installation, installation_record = read_json(installation_path)
    require(installation.get("pid") == 39456, "installation PID mismatch")
    require(installation.get("creation_filetime") == EXPECTED_CREATION, "installation creation mismatch")
    require(installation.get("session_id") == EXPECTED_SESSION, "installation session mismatch")
    require(installation.get("game_sha256") == EXPECTED_GAME_SHA, "installation EXE hash mismatch")
    require(installation.get("dll_sha256") == EXPECTED_DLL_SHA, "installation DLL hash mismatch")
    require(installation.get("installation_returncode") == 0, "installation return code mismatch")
    require(installation.get("ready_reason") == "verified_load_confirmation", "installation readiness reason mismatch")
    require(len(installation.get("ready_attempts") or []) == 1, "expected one ready attempt")
    require((installation.get("ready_attempts") or [])[0].get("outcome") == "ready", "ready attempt did not pass")
    require(installation.get("runtime_verified") is False, "installation must not claim runtime_verified")

    binding, binding_record = read_json(LIVE_DIR / "information-battle-binding.json")
    require(binding.get("installation") == EXPECTED_INSTALLATION, "binding installation mismatch")
    require(binding.get("generation") == EXPECTED_GENERATION, "binding generation mismatch")
    require(binding.get("creation_filetime") == EXPECTED_CREATION.__str__(), "binding creation mismatch")
    require(binding.get("session_id") == EXPECTED_SESSION, "binding session mismatch")
    require(binding.get("pid") == 39456, "binding PID mismatch")
    require(binding.get("game_sha256") == EXPECTED_GAME_SHA, "binding EXE hash mismatch")
    require(binding.get("dll_sha256") == EXPECTED_DLL_SHA, "binding DLL hash mismatch")

    phase_results: list[dict[str, Any]] = []
    phase_reports: list[dict[str, Any]] = []
    for phase, expected_patch in EXPECTED_PHASES:
        report_path = LIVE_STAGE / phase / "report.json"
        report, report_record = read_json(report_path)
        summary = phase_snapshot(report, phase)
        require(summary["expect_patch"] == expected_patch, f"{phase}: patch expectation mismatch")
        summary["report"] = report_record
        phase_results.append(summary)
        phase_reports.append(report_record)

    controls: dict[str, Any] = {}
    started: dict[str, Any] = {}
    for name, expected in EXPECTED_CONTROL.items():
        controls[name] = control_receipt(LIVE_STAGE / name, expected)
        nonce = expected[1]
        started_path = LIVE_DIR / f"information-battle-started-{nonce}.json"
        response_path = LIVE_DIR / f"information-battle-response-{nonce}.json"
        started[name] = started_response(started_path, response_path, expected)

    status_path = LIVE_DIR / "information-battle-status.json"
    status, status_record = read_json(status_path)
    require(status.get("pid") == 39456, "status PID mismatch")
    require(status.get("creation_filetime") == str(EXPECTED_CREATION), "status creation mismatch")
    require(status.get("generation") == EXPECTED_GENERATION, "status generation mismatch")
    require(status.get("installation") == EXPECTED_INSTALLATION, "status installation mismatch")
    require(status.get("state") == "enabled", "final status is not enabled")
    require(status.get("captured") == "0" and status.get("capture_complete") is False, "status capture changed")
    require(status.get("business_export_available") is False, "status business export available")
    require(status.get("visibility_verified") is False, "status visibility verified")
    require(status.get("dll_sha256") == EXPECTED_DLL_SHA and status.get("exe_sha256") == EXPECTED_GAME_SHA, "status hash mismatch")

    status_before, status_before_record = read_json(LIVE_STAGE / "status-before-enable-001.json")
    require(status_before.get("native", {}).get("code_patch_installed") is False, "default-off status already patched")
    require(status_before.get("native", {}).get("captured") == "0", "default-off status captured data")
    require(status_before.get("native", {}).get("state") == "ready", "default-off status not ready")
    require(status_before.get("native", {}).get("creation_filetime") == str(EXPECTED_CREATION), "default-off creation mismatch")

    raw_path = LIVE_DIR / "information-battle-raw.jsonl"
    raw_record = file_record(raw_path)
    raw_lines: list[str] = []
    with raw_path.open("rb") as handle:
        for raw_line in handle:
            if len(raw_line) > MAX_LINE_BYTES:
                raise AuditError("raw wire line exceeds bound")
            raw_lines.append(raw_line.decode("utf-8", errors="strict").rstrip("\r\n"))
    require(len(raw_lines) == 1, "raw file should contain only its header")
    require(raw_lines[0].startswith("EU4_OWNED_BATTLE_WIRE_V1 "), "raw header mismatch")
    loader, loader_record = read_json(LIVE_DIR / "loader-output.txt")
    require(loader.get("bridge_thread_exit_status") == "0x0", "loader bridge thread did not exit zero")
    require(loader.get("load_thread_exit_status") == "0x4a00000", "loader thread status mismatch")
    require(loader.get("test_save_acknowledged") is True, "loader save acknowledgement missing")
    require(loader.get("dll_unloaded") is False, "DLL unexpectedly unloaded")
    require(loader.get("warnings") == [], "loader warnings present")

    restart_path = LIVE_STAGE / "restart-outcome-001.json"
    restart, restart_record = read_json(restart_path)
    pre_restart = LIVE_STAGE / "pre-restart-001"
    require(pre_restart.is_file() and not pre_restart.is_dir(), "pre-restart-001 must remain a file")
    require(restart.get("state") == "restarted_verified_new_unloaded_process", "restart outcome state mismatch")
    require(restart.get("old_pid") == 42328, "restart old PID mismatch")
    require(restart.get("new_identity", {}).get("pid") == 39456, "restart new PID mismatch")
    require(restart.get("restart_shell_exit") == 0, "restart shell exit mismatch")
    require("output is a file, not a directory" in restart.get("audit_exception", ""), "restart receipt failure not recorded")
    require("No started receipt was created" in restart.get("audit_exception", ""), "restart started-receipt caveat missing")
    require("Existing user restart authorization" in restart.get("audit_exception", ""), "restart authorization provenance missing")

    manifest_path = LIVE_DIR / "build-manifest.json"
    manifest, manifest_record = read_json(manifest_path)
    require(manifest.get("version") == 23, "live manifest version mismatch")
    require(manifest.get("compiled") is True, "live manifest not compiled")
    require(manifest.get("dll_sha256") == EXPECTED_DLL_SHA, "live manifest DLL mismatch")
    require(manifest.get("runtime_verified") is False, "live manifest must not claim runtime verification")

    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    script_hash, script_size = sha256_file(pathlib.Path(__file__).resolve())
    report = {
        "schema": "INFORMATION-BATTLE-LIVE-LIFECYCLE-AUDIT/1",
        "status": "passed_paused_v23_lifecycle_capture_unverified",
        "generated_by": {"path": pathlib.Path(__file__).resolve().relative_to(ROOT).as_posix(), "size_bytes": script_size, "sha256": script_hash},
        "scope": {
            "read_only_audit": True,
            "new_game_access": False,
            "new_control_commands": False,
            "new_rpm_or_rea": False,
            "business_dispatch_or_replay": False,
            "output_exclusive_create": True,
            "bounded_json_bytes": MAX_JSON_BYTES,
            "bounded_jsonl_line_bytes": MAX_LINE_BYTES,
        },
        "installation": {
            "record": installation_record,
            "identity": {k: installation.get(k) for k in ("pid", "creation_filetime", "session_id", "game_sha256", "dll_sha256", "ready_reason", "runtime_verified")},
            "ready_attempts": installation.get("ready_attempts"),
        },
        "binding": binding_record,
        "phases": phase_results,
        "control_receipts": controls,
        "started_response_pairs": started,
        "status_before_enable": status_before_record,
        "status_final": status_record,
        "wire_and_loader": {"raw": raw_record, "raw_lines": len(raw_lines), "header_only": True, "loader": loader_record},
        "restart_outcome": {
            "record": restart_record,
            "pre_restart_input": file_record(pre_restart),
            "receipt_failure_recorded": True,
            "started_receipt_created": False,
            "authorization_provenance": "restart-outcome records existing user authorization and fresh preflight; this audit grants no retrospective authorization",
        },
        "provenance": {"live_manifest": manifest_record, "live_manifest_version": manifest.get("version"), "dll_sha256": EXPECTED_DLL_SHA, "coff_stub_rva": EXPECTED_COFF_RVA},
        "checks": {
            "full_identity_creation_session_stable": True,
            "exe_and_dll_hashes_stable": True,
            "physical_player_por_slot189_stable": True,
            "all_phases_date_56553384_paused_speed0": True,
            "original_to_exact_installed_control_state": True,
            "coff_stub_rva_0x9ceb0": True,
            "disable_retained_patch_resources": True,
            "resume_same_installation_and_generation": True,
            "default_off_before_enable": True,
            "captured_records": 0,
            "abi_verified": False,
            "natural_battle_event_verified": False,
            "visibility_verified": False,
        },
        "limitations": [
            "The four phase reports prove identity, paused state, code guards, and lifecycle receipts; they do not prove a natural battle callback ABI.",
            "Zero captured records and a header-only raw file are absence evidence, not ABI or visibility proof.",
            "The live reports reuse the pinned v23-005 DLL/source manifest; historical runtime/delivery/summary pins were not rewritten.",
            "The restart pre-action receipt script failed because pre-restart-001 was a file rather than a directory; orchestration continued and restart-outcome records the existing authorization and fresh preflight. No retrospective authorization is inferred.",
            "Runtime identity is observed in the supplied phase reports; this validator itself did not open the process or issue commands.",
        ],
    }
    try:
        with output.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
    except FileExistsError as exc:
        raise AuditError(f"refusing to overwrite existing output: {output}") from exc
    digest, size = sha256_file(output)
    return {"status": report["status"], "path": output.relative_to(ROOT).as_posix(), "bytes": size, "sha256": digest}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=pathlib.Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--verify-existing", action="store_true")
    args = parser.parse_args()
    try:
        result = run(args.output.resolve(), args.verify_existing)
    except (AuditError, OSError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
