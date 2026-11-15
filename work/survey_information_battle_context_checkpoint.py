"""Build a bounded, read-only checkpoint contract for the next observer restart.

This survey hashes only the small source files that define the existing save,
restart, and observer-install paths.  It never probes a process, writes a
request, opens a save, starts or stops the game, or calls HTTP/RPM/REA.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-battle-context-observer-20261025-001"
REPORT = STAGE / "checkpoint-contract-001.json"
MAX_SOURCE_BYTES = 16 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024

SOURCE_PINS = (
    {
        "path": "开发过程自动化.md",
        "role": "operator_workflow_and_save_evidence_gates",
        "lines": "1-237",
    },
    {
        "path": "tools/save_observer_experiment.py",
        "role": "current_date_operator_autosave_archiver",
        "lines": "1-657",
    },
    {
        "path": "work/probe_control_state.py",
        "role": "bounded_paused_player_date_readback",
        "lines": "1-26",
    },
    {
        "path": "work/native/restart-game.ps1",
        "role": "verified_exe_restart_and_continue_save_argument",
        "lines": "1-64",
    },
    {
        "path": "tools/start_diplomacy_observer.py",
        "role": "fresh_pid_manifest_install_and_ready_gate",
        "lines": "441-474",
    },
    {
        "path": "work/prepare_information_observer_reuse.py",
        "role": "historical_v22_reuse_helper_not_v24_compatible",
        "lines": "1-117",
    },
    {
        "path": "tools/verify_control_reload.py",
        "role": "legacy_reload_checker_incompatible_with_new_save_report",
        "lines": "1-62",
    },
)


def stream_hash(path: Path) -> dict[str, Any]:
    path = path.resolve()
    try:
        stat_before = path.stat()
    except OSError as error:
        return {"path": path.relative_to(ROOT).as_posix(), "status": "missing", "error": str(error)}
    result: dict[str, Any] = {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": stat_before.st_size,
    }
    if not path.is_file():
        result["status"] = "not_file"
        return result
    if stat_before.st_size > MAX_SOURCE_BYTES:
        result.update({"status": "over_bound", "max_bytes": MAX_SOURCE_BYTES})
        return result
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(HASH_CHUNK_BYTES), b""):
                digest.update(chunk)
        stat_after = path.stat()
    except OSError as error:
        result.update({"status": "read_error", "error": str(error)})
        return result
    result.update(
        {
            "sha256": digest.hexdigest(),
            "status": "stable" if (stat_before.st_size, stat_before.st_mtime_ns) == (stat_after.st_size, stat_after.st_mtime_ns) else "changed_during_read",
        }
    )
    return result


def source_records() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for pin in SOURCE_PINS:
        row = dict(pin)
        row["hash"] = stream_hash(ROOT / pin["path"])
        rows.append(row)
    return rows


def build_report() -> dict[str, Any]:
    return {
        "schema": "information_battle_context_checkpoint_contract/1",
        "status": "static_contract_complete_no_game_access",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "executed": {
            "game_action": False,
            "http": False,
            "save_request": False,
            "game_start_or_exit": False,
            "rpm": False,
            "rea": False,
        },
        "current_context": {
            "source": ["HANDOFF.md", "README(agent).md"],
            "installation": "work/runtime/diplomacy-observer-20261025-information-battle-live-001/installation.json",
            "pid": 39456,
            "creation_filetime": 134374061200954087,
            "session_id": "39456-1dd647f28e8d2e7",
            "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
            "dll_sha256": "eaf53986e159bfca7af717228a7bc983a8df03fec32a23eb4a82e5ca503133c3",
            "player": "POR",
            "observer_country": "FRA",
            "date_raw": 56554248,
            "paused": True,
            "speed": 0,
            "capture": "disabled",
            "runtime_rechecked_by_this_survey": False,
            "note": "These are the latest handoff facts; a future save must perform a fresh identity/state read before emitting its request.",
        },
        "preferred_save_tool": {
            "path": "tools/save_observer_experiment.py",
            "api": "run_experiment(installation: Path, name: str, timeout: int = 300, expected_date: str | None = None)",
            "request": "TEST_ONLY autosave\\n",
            "request_path": "<installation.parent>/game-control.request",
            "name_rule": "llm_diplomacy_<unique>.eu4; exclusive target creation; existing target rejected",
            "command_template": [
                "$python = Get-ProjectLocalValue -Name 'EU4_PYTHON'",
                "& $python -B .\\tools\\save_observer_experiment.py --installation .\\work\\runtime\\diplomacy-observer-20261025-information-battle-live-001\\installation.json --name llm_diplomacy_information_v24_checkpoint_20261025.eu4 --timeout 300",
            ],
            "expected_date_usage": "Optional. Supply only an independently verified calendar date; do not infer a save date from a raw integer by guesswork.",
            "why_not_run_control_save": "tools/run_control_save.py hard-codes POR/1445.2.5/raw 56459040 and is not valid for date_raw 56554248.",
        },
        "pre_request_gates": [
            "Fresh read-only probe confirms the same PID, creation_filetime, session_id, game SHA, and exactly one loaded DLL with the expected SHA.",
            "Fresh read-only observer status confirms capture disabled, no pending/processing control request, and no business request is outstanding.",
            "Observer health is ready; player_slot=189/POR, paused_flag=1, speed=0, and date_raw=56554248 are independently recorded.",
            "The checkpoint target name is absent from the save directory; the fixed R70 source save is not renamed or overwritten.",
            "No old TEST_ONLY request remains; use exclusive creation and wait for the previous request to be absent before saving.",
        ],
        "save_success_evidence": [
            "CLI and report status are success; the report path is newly allocated and preserved before restart.",
            "A new autosave file was observed after a successful console result, remained valid and stable for the tool's stability window, and was not accepted from console output alone.",
            "native_save.inspection and save.inspection are valid, player=POR, date is a real calendar string, and both file size and decompressed payload exceed the tool minimum.",
            "probe_before and probe_after both show player_slot=189, paused_flag=1, and the same date_raw=56554248; observer health remains ready and identity is unchanged.",
            "The copied target hash equals the source autosave hash and remains unchanged after rotating autosaves are restored; restore.errors is empty and rotating baseline hashes are verified.",
            "The target file, its SHA-256, the complete save-observer report, before/after probes, and the final disabled status are archived as immutable evidence before restart.",
        ],
        "restart_after_checkpoint": {
            "command_template": ".\\work\\native\\restart-game.ps1 -SavedTestGame -SaveName llm_diplomacy_information_v24_checkpoint_20261025.eu4",
            "script_contract": [
                "Checks the fixed 1.37.4 executable SHA and save-file existence, removes stale continue/continuelastsave, and appends the supplied filename.",
                "Outputs a new PID; the old PID/creation/session and old installation.json must never be reused.",
                "The script does not hash or inspect save contents, so the saved-file SHA and metadata gates above are mandatory before invocation.",
            ],
            "post_restart_sequence": [
                "Prepare a fresh v24 build directory and manifest; do not hot-replace the v23 DLL or reuse the old installation directory.",
                "Wait for the new PID and load-confirmation readiness, then install only the manifest-pinned v24 DLL with the updated installer.",
                "Record fresh installation.json identity, actual loaded module path/SHA, returncode=0, readiness, and paused POR state before any observer control.",
                "Keep capture disabled until a separate v24 live acceptance explicitly authorizes and verifies enable; no historical business request is retried.",
            ],
        },
        "static_blockers_and_gaps": [
            {
                "path": "tools/start_diplomacy_observer.py:453",
                "finding": "Current installer accepts only manifest versions 10, 21, 22, and 23; a v24 manifest currently fails BUILD_MANIFEST_MISMATCH.",
                "required_before_v24": "Update and independently test the v24 manifest/version/source/DLL guard before restarting for v24.",
            },
            {
                "path": "work/prepare_information_observer_reuse.py:16-21",
                "finding": "The reuse helper is hard-coded to the historical v22 source manifest and DLL.",
                "required_before_v24": "Use a v24-specific preparation helper or final v24 build manifest; do not copy this v22 artifact.",
            },
            {
                "path": "tools/verify_control_reload.py:21-52",
                "finding": "The legacy reload checker reads control-save-validation.json and report.advance, so it cannot validate save_observer_experiment.py output without an adapter.",
                "required_before_v24": "Use a new bounded reload checker that accepts the new save report and independently compares target SHA, POR, calendar date, paused state, and required contextual fields.",
            },
        ],
        "preservation_and_no_repeat": [
            "Use a new unique checkpoint filename; never overwrite the fixed R70 save or any existing target.",
            "Do not replay historical business requests, old natural windows, or the original final-pass request IDs.",
            "Do not treat a successful autosave console event as a saved checkpoint until file, hash, metadata, before/after state, and restore gates pass.",
        ],
        "script_sha_change_from_0723": {
            "previous_sha256": "0723b82bb00b393204fde67dd35676d1f12eeb03aa26ce42f0d91296b70196cb",
            "current_sha256": None,
            "minimal_reason": [
                "The audit now classifies the four explicitly allowed document pin changes as intentional_document_change instead of mismatches.",
                "The summary counts and audited-current-pin total include those four intentional rows, and other_failure excludes that category.",
                "No production source, native artifact, manifest, or preservation input was changed by that audit correction.",
            ],
        },
        "source_pins": source_records(),
        "survey_script": None,
    }


def main() -> int:
    report = build_report()
    script_hash = stream_hash(Path(__file__))
    report["survey_script"] = script_hash
    report["script_sha_change_from_0723"]["current_sha256"] = stream_hash(ROOT / "work/audit_information_battle_business_preservation.py").get("sha256")
    STAGE.mkdir(parents=True, exist_ok=True)
    if REPORT.exists():
        raise SystemExit(f"report_exists:{REPORT}")
    with REPORT.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"status": report["status"], "report": str(REPORT), "script_sha256": script_hash.get("sha256")}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
