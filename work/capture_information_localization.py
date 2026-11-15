"""Retain a bounded raw cache capture for the currently loaded mission IDs.

Only existing installation identity checks, ReadProcessMemory and control
snapshots are used. No game function, injection, save or action is invoked.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.information import localization_memory as lm, mission_memory as mm
from bridge.information.mission_texts import decode_template
from work.run_alliance_inbound_response import control_snapshot


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")


def members(report):
    assert report["status"] == "observed" and report["loaded_tasks"]["status"] == "observed"
    assert report["doublepass"]["task_consistent"] and report["cleanup"]["handle_close"]["closed"]
    return [{"root_id":root["root_id"], "task_id":task}
            for root in report["loaded_tasks"]["roots"] for task in root["task_ids"]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    installation = json.loads(args.installation.read_text(encoding="utf-8"))
    report = {"status":"failed", "read_only":True, "game_function_invoked":False}
    try:
        before = control_snapshot(installation["pid"], args.output / "before-control.json")
        assert (before["player_slot"], before["paused_flag"], before["date_raw"]) == (189,1,56553384)
        tasks = mm.capture(args.installation, "FRA", include_completed=True, include_tasks=True)
        write(args.output / "loaded-tasks-before.json", tasks)
        expected = members(tasks)
        keys = list(dict.fromkeys(item["task_id"]+suffix for suffix in ("_title","_desc") for item in expected))
        assert len(keys) <= lm.MAX_KEYS
        captured = lm.capture(args.installation, "FRA", keys)
        write(args.output / "native-cache.json", captured)
        assert captured["status"] == "observed" and captured["doublepass"]["consistent"]
        assert captured["cleanup"]["handle_close"]["closed"]
        assert captured["before"]["game_date"]["raw"] == before["date_raw"]
        assert captured["identity"]["installation_session_id"] == installation["session_id"]
        decoded = {key:decode_template(value["value_hex"], installation["native_text_codec"])
                   if value["status"] == "observed" else {"status":"unknown", "reason":value.get("unknown_reason")}
                   for key,value in captured["entries"].items()}
        write(args.output / "decoded-templates.json", decoded)
        later = mm.capture(args.installation, "FRA", include_completed=True, include_tasks=True)
        write(args.output / "loaded-tasks-after.json", later)
        assert members(later) == expected
        after = control_snapshot(installation["pid"], args.output / "after-control.json")
        assert (after["player_slot"], after["paused_flag"], after["date_raw"]) == (189,1,before["date_raw"])
        report.update(status="passed", session_id=installation["session_id"], task_count=len(expected),
                      key_count=len(keys), resolved_count=sum(v["status"] == "known" for v in decoded.values()),
                      unresolved_count=sum(v["status"] != "known" for v in decoded.values()),
                      language=captured["language"]["text"], codec=installation["native_text_codec"],
                      doublepass_consistent=True, handle_closed=True,
                      atomic_with_task_membership=False, game_date=before["date_raw"],
                      native_capture_sha256=hashlib.sha256((args.output / "native-cache.json").read_bytes()).hexdigest())
    except Exception as exc:
        report["error"] = {"type":type(exc).__name__, "message":str(exc)}
        raise
    finally:
        write(args.output / "report.json", report)
    print(json.dumps(report))


if __name__ == "__main__":
    main()
