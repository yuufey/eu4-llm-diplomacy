"""Save one uniquely reserved paused checkpoint after an artifact-bound audit.

Operator only. No retry loop: an existing reservation, even without an outcome,
prevents another attempt in that operation directory. The sole native request
is the existing TEST_ONLY autosave token, emitted by save_observer_experiment.
"""
from __future__ import annotations

import argparse
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "work"))
from local_config import user_data
from tools.control_information_battle_observer import run_control
from tools.save_observer_experiment import run_experiment, _validate_name
from work.probe_information_battle_installed import run as run_preflight

R70_NAME = "llm_diplomacy_r70_country_money_rejected_20261020.eu4"
R70_SHA = "ffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0"


def pin(path: Path) -> dict:
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": str(path.resolve()), "sha256": digest, "bytes": path.stat().st_size}


def write_new(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def pending_files(directory: Path) -> list[str]:
    return sorted(path.name for path in directory.iterdir()
                  if path.is_file() and path.name.endswith((".request", ".processing", ".intent")))


def run(installation: Path, output: Path, name: str, manifest_sha: str, dll_sha: str,
        expected_raw_date: int, expected_player_ref: str, expected_save_date: str) -> dict:
    _validate_name(name)
    date(*map(int, expected_save_date.split(".")))
    # Exclusive operation directory is the durable ownership reservation.
    output.mkdir(parents=True, exist_ok=False)
    installation = installation.resolve()
    audit: dict = {"schema": "BATTLE-CHECKPOINT-AUDIT/1", "checkpoint_name": name,
                   "installation": str(installation), "native_request_dispatched": False,
                   "expected_date_raw": expected_raw_date, "expected_player_ref": expected_player_ref,
                   "expected_save_date": expected_save_date}
    started = False
    try:
        preflight = run_preflight(installation, output / "preflight-001.json",
            expected_manifest_sha256=manifest_sha, expected_dll_sha256=dll_sha, expect_patch="installed")
        if preflight["status"] != "passed_read_only_installed_preflight":
            raise RuntimeError("INSTALLED_ARTIFACT_PREFLIGHT_FAILED_NO_SAVE")
        for phase in ("before", "after"):
            snapshot = preflight[phase]
            if (snapshot["game_date"]["raw"] != expected_raw_date
                    or int(snapshot["physical_player"]["value"], 0) != int(expected_player_ref, 16)
                    or snapshot["control"]["paused"]["value"] is not True
                    or snapshot["control"]["speed"]["value"] != 0):
                raise RuntimeError("WORLD_STATE_DIFFERS_NO_SAVE")
        audit["preflight"] = pin(output / "preflight-001.json")
        status = run_control(installation, "status")
        audit["source_status"] = status
        native = status.get("native", {})
        if (status.get("status") != "observed" or native.get("state") != "disabled"
                or native.get("fragment_sink_pending") is not False
                or str(native.get("fragment_queued")) != "0"):
            raise RuntimeError("CAPTURE_NOT_QUIESCENT_NO_SAVE")
        audit["pending_files"] = pending_files(installation.parent)
        if audit["pending_files"]:
            raise RuntimeError("PENDING_REQUEST_NO_SAVE")
        saves = (user_data() / "save games").resolve()
        protected = saves / R70_NAME
        original = pin(protected)
        if original["sha256"] != R70_SHA:
            raise RuntimeError("R70_PROTECTED_BASELINE_MISMATCH_NO_SAVE")
        if any(path.name.casefold() == name.casefold() for path in saves.iterdir()):
            raise RuntimeError("CHECKPOINT_TARGET_EXISTS_NO_SAVE")
        audit["protected_r70_before"] = original
        audit["save_tool"] = pin(ROOT / "tools/save_observer_experiment.py")
        audit["state"] = "audited_before_save_attempt"
        write_new(output / "pre-save-audit-001.json", audit)
        if pending_files(installation.parent):
            raise RuntimeError("REQUEST_APPEARED_NO_SAVE")
        write_new(output / "attempt-started-001.json", {
            "schema": "BATTLE-CHECKPOINT-RESERVATION/1", "state": "attempt_reserved_no_auto_retry",
            "checkpoint_name": name, "pre_save_audit": pin(output / "pre-save-audit-001.json"),
            "request_token": "TEST_ONLY autosave\n"})
        started = True
        result = run_experiment(installation, name, timeout=300, expected_date=expected_save_date)
        if result.get("status") != "success" or result["restore"]["errors"]:
            raise RuntimeError("SAVE_OR_ROTATING_RESTORE_NOT_VERIFIED")
        for phase in ("probe_before", "probe_after"):
            signature = result[phase]["signature"]
            if signature != {"date_raw": expected_raw_date, "player_slot": 189, "paused_flag": 1}:
                raise RuntimeError("SAVE_STATE_CHANGED")
        checkpoint = Path(result["save"]["path"])
        saved = pin(checkpoint)
        if saved["sha256"] != result["save"]["sha256"] or pin(protected) != original:
            raise RuntimeError("SAVED_OR_PROTECTED_FILE_HASH_MISMATCH")
        with checkpoint.open("rb") as source, (output / "checkpoint.eu4").open("xb") as target:
            shutil.copyfileobj(source, target, length=1024 * 1024)
        if pin(output / "checkpoint.eu4")["sha256"] != saved["sha256"]:
            raise RuntimeError("CHECKPOINT_SNAPSHOT_HASH_MISMATCH")
        after = run_preflight(installation, output / "preflight-after-002.json",
            expected_manifest_sha256=manifest_sha, expected_dll_sha256=dll_sha, expect_patch="installed")
        if after["status"] != "passed_read_only_installed_preflight" or after["after"] != {**preflight["after"], "phase": "after"}:
            raise RuntimeError("POST_SAVE_WORLD_OR_ARTIFACT_CHANGED")
        final_status = run_control(installation, "status")
        if final_status.get("status") != "observed" or final_status.get("native", {}).get("state") != "disabled":
            raise RuntimeError("POST_SAVE_SOURCE_STATE_CHANGED")
        outcome = {"schema": "BATTLE-CHECKPOINT-OUTCOME/1", "status": "saved_verified",
                   "attempt_started": True, "save": saved, "save_result": result,
                   "protected_r70_after": pin(protected), "source_status_after": final_status,
                   "pending_files_after": pending_files(installation.parent),
                   "game_date_advanced": False, "business_request_dispatched": False,
                   "retry_authorized": False}
        if outcome["pending_files_after"]:
            raise RuntimeError("REQUEST_NOT_CONSUMED_OR_OTHER_REQUEST_APPEARED")
        write_new(output / "outcome-001.json", outcome)
        print(json.dumps({"status": outcome["status"], "save": saved}, ensure_ascii=False), flush=True)
        return outcome
    except Exception as exc:
        failure = {"schema": "BATTLE-CHECKPOINT-OUTCOME/1", "status": "failed_no_retry",
                   "attempt_started": started, "native_outcome_may_be_unknown": started,
                   "error": f"{type(exc).__name__}:{exc}", "audit": audit,
                   "retry_authorized": False}
        write_new(output / "failure-001.json", failure)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--expected-dll-sha256", required=True)
    parser.add_argument("--expected-date-raw", type=int, required=True)
    parser.add_argument("--expected-player-ref", required=True)
    parser.add_argument("--expected-save-date", required=True)
    args = parser.parse_args()
    run(args.installation, args.output, args.name, args.expected_manifest_sha256,
        args.expected_dll_sha256, args.expected_date_raw, args.expected_player_ref, args.expected_save_date)


if __name__ == "__main__":
    main()
