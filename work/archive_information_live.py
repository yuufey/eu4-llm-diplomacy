"""Retain bounded authentic country inspection events for offline regression."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--acceptance", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    record = json.loads(args.installation.read_text(encoding="utf-8"))
    report_path = args.acceptance / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"] == "passed" and report["mode"] == "live"
    assert report["session_id"] == record["session_id"]
    log = args.installation.parent / "control-probe.jsonl"
    selected = {}
    read_bytes = 0
    limit = 2 * 1024 * 1024
    with log.open("rb") as stream:
        for line in stream:
            read_bytes += len(line)
            if read_bytes > limit:
                raise ValueError("Bounded event scan exceeded 2 MiB")
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if (event.get("event") != "native_alliance_inspection"
                    or event.get("session_id") != record["session_id"]
                    or event.get("actor") != "FRA" or event.get("recipient") != "PAP"
                    or event.get("date_raw") != 56553384):
                continue
            action = event.get("action_id")
            if action not in {"send_gift", "trade_favors_for_men"} or action in selected:
                continue
            selected[action] = {"raw": event, "source_line_sha256": sha(line),
                                "source_line_end_offset": read_bytes}
            if len(selected) == 2:
                break
    assert len(selected) == 2, selected.keys()
    assert selected["send_gift"]["raw"]["native_gift"]["actor_treasury_raw"] == 16645
    assert selected["trade_favors_for_men"]["raw"]["native_favor_trade"]["actor_manpower_raw"] == 37927
    assert selected["trade_favors_for_men"]["raw"]["available_diplomat_count"] == 1
    fixture = {"format": "information_country_live_1374_v1",
               "provenance": {"mode": "recorded", "original_mode": "live",
                              "session_id": record["session_id"], "observer": "FRA",
                              "player_slot": 189, "date_raw": 56553384,
                              "game_sha256": record["game_sha256"], "dll_sha256": record["dll_sha256"],
                              "source_report_sha256": sha(report_path.read_bytes()),
                              "native_text_codec": "eu4_escape", "read_only": True,
                              "scope": "country inspection; no submission or execution evidence"},
               "expected": {"treasury_raw": 16645, "manpower": 37927, "diplomats_available": 1},
               "events": selected}
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(fixture, output, ensure_ascii=False, indent=2)
        output.write("\n")
    print(json.dumps({"fixture": str(args.output), "sha256": sha(args.output.read_bytes()),
                      "read_bytes": read_bytes, "event_count": len(selected)}))


if __name__ == "__main__":
    main()
