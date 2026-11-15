"""Reserve one mature autosave before replacing a terminal battle collector.

This accepts a quiescent terminal collector without pretending it is disabled.
It neither resets that collector nor repeats an ambiguous save attempt.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.control_information_battle_observer import run_control
from tools.save_observer_experiment import run_experiment, _validate_name
from work.local_config import user_data
from work.probe_information_battle_installed import run as probe
from work.run_information_battle_checkpoint import R70_NAME, R70_SHA, pin, write_new


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--name", required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--expected-dll-sha256", required=True)
    parser.add_argument("--expected-date", required=True, type=int)
    parser.add_argument("--test-only", required=True, action="store_true")
    args = parser.parse_args()
    _validate_name(args.name)
    args.output.mkdir(parents=True, exist_ok=False)
    attempted = False
    try:
        before = probe(args.installation, args.output / "preflight-001.json",
                       expected_manifest_sha256=args.expected_manifest_sha256,
                       expected_dll_sha256=args.expected_dll_sha256, expect_patch="installed")
        if before["status"] != "passed_read_only_installed_preflight":
            raise ValueError("installed_preflight_failed")
        for key in ("before", "after"):
            world = before[key]
            if (world["game_date"]["raw"] != args.expected_date or world["physical_player"]["tag"] != "POR"
                    or world["physical_player"]["slot"] != 189 or world["control"]["speed"]["value"] != 0
                    or world["control"]["paused"]["value"] is not True):
                raise ValueError("paused_checkpoint_world_differs")
        status = run_control(args.installation, "status")
        native = status["native"]
        if (native["state"] != "fault" or native.get("fragment_sink_pending") is not False
                or int(native["fragment_queued"]) != 0 or int(native["open_message_scopes"]) != 0):
            raise ValueError("terminal_collector_not_quiescent")
        journal_path = args.installation.parent / "information-battle-capture-journal.json"
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        if journal["state"] != "completed-disabled" or journal["owned"] is not False:
            raise ValueError("ownership_not_closed")
        pending = [path.name for path in args.installation.parent.iterdir()
                   if path.is_file() and path.name.endswith((".req", ".request", ".processing", ".intent"))]
        if pending:
            raise ValueError("pending_request_no_save:" + str(pending))
        protected = user_data() / "save games" / R70_NAME
        original = pin(protected)
        if original["sha256"] != R70_SHA:
            raise ValueError("protected_save_differs")
        audit = {"status": "audited_before_save", "terminal_source": status,
                 "capture_journal": journal, "expected_date_raw": args.expected_date,
                 "protected_before": original, "native_collector_reset": False,
                 "save_tool": pin(ROOT / "tools/save_observer_experiment.py"),
                 "purpose": "preserve current paused world for a new DLL process; no basic save retest"}
        write_new(args.output / "pre-save-audit-001.json", audit)
        write_new(args.output / "attempt-started-001.json", {
            "token": "TEST_ONLY autosave\n", "retry_authorized": False, "checkpoint_name": args.name})
        attempted = True
        result = run_experiment(args.installation, args.name, timeout=300)
        if result.get("status") != "success" or result["restore"]["errors"]:
            raise ValueError("save_or_restore_not_verified")
        expected = {"date_raw": args.expected_date, "player_slot": 189, "paused_flag": 1}
        if any(result[key]["signature"] != expected for key in ("probe_before", "probe_after")):
            raise ValueError("save_world_changed")
        if pin(protected) != original:
            raise ValueError("protected_save_changed")
        checkpoint = Path(result["save"]["path"])
        with checkpoint.open("rb") as source, (args.output / "checkpoint.eu4").open("xb") as target:
            shutil.copyfileobj(source, target, length=1024 * 1024)
        if pin(args.output / "checkpoint.eu4")["sha256"] != result["save"]["sha256"]:
            raise ValueError("checkpoint_copy_differs")
        final = run_control(args.installation, "status")
        if final["native"]["state"] != "fault":
            raise ValueError("terminal_source_changed")
        outcome = {"status": "saved_verified", "save_result": result,
                   "checkpoint": pin(args.output / "checkpoint.eu4"), "terminal_source_after": final,
                   "protected_after": pin(protected), "new_advance": False, "business_dispatch": False}
        write_new(args.output / "outcome-001.json", outcome)
        print(json.dumps({"status": outcome["status"], "save": result["save"]}, ensure_ascii=False))
        return 0
    except Exception as error:
        write_new(args.output / "failure-001.json", {"status": "failed_no_retry", "attempt_started": attempted,
                  "error": f"{type(error).__name__}:{error}", "retry_authorized": False})
        raise


if __name__ == "__main__":
    raise SystemExit(main())
