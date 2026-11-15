"""Accept mission MCP reads and scheduling against one paused 1.37.4 scene.

No installation, business request, time advancement or save is performed.
The separate pre-existing save is read as historical evidence only.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.information.catalog import coverage_report
from bridge.information.mission_definitions import MissionDefinitionIndex
from bridge.information.missions import MissionInformationSource, NativeMissionReader
from bridge.information.saved_missions import SavedMissionSnapshot
from bridge.information.sources import DiplomacySource
from bridge.information.composite import CompositeSource
from bridge.information.country_state import NativeCountryStateSource
from bridge.information.static_data import StaticTradeSource
from work.run_alliance_inbound_response import control_snapshot
from work.validate_information_live import Client


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")


def query(topic, fields):
    return {"topic": topic, "object": {"type": "country", "country": "FRA"}, "fields": fields}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--save", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    installation = json.loads(args.installation.read_text(encoding="utf-8"))
    report = {"status": "failed", "checks": {}, "mode": "live", "session_id": installation["session_id"],
              "limits": ["Branch visibility and mission completion conditions are not evaluated",
                         "Rewards are definition expressions, not applied effects",
                         "Saved snapshot is historical and has no live session identity",
                         "No positive mission change was manufactured"]}
    client = None
    try:
        before = control_snapshot(installation["pid"], args.output / "before-control.json")
        assert before["player_slot"] == 189 and before["paused_flag"] == 1, before
        client = Client(args.installation, args.output, extra_args=["--mission-game-data"], tick=0.5)
        manual = client.call("information_query", request_id="mission-manual", queries=[
            query("M01", ["task_id", "branches"]), query("M02", ["prerequisites", "completion_status"]),
            query("M04", ["rewards"])])
        write(args.output / "manual-result.json", manual)
        assert manual["complete"] is True, manual
        assert manual["context"]["mode"] == "live" and manual["context"]["game_date"] == before["date_raw"], manual
        membership = manual["items"][0]["fields"]["branches"]["value"]["slots"]
        assert len(membership) == 5 and sum(len(slot["roots"]) for slot in membership) == 18, membership
        assert membership[-1]["roots"][-1] == "fra_missions_5_continuation", membership
        task_ids = manual["items"][0]["fields"]["task_id"]["value"]
        assert len(task_ids) == 61 and all(task["branch_visibility"] == "unknown" for task in task_ids), task_ids
        assert manual["items"][1]["fields"]["completion_status"]["value"]["completed_task_ids"] == []
        rewards = manual["items"][2]["fields"]["rewards"]["value"]
        assert rewards["evaluated"] is False and rewards["applied"] == "unknown", rewards
        used = manual["items"][0]["source"]["provenance"]["used_root_definitions"]
        assert len(used) == 18 and all(item["source"]["source_kind"] == "enabled_mod" for item in used), used
        report["checks"]["live_membership_completion_and_scoped_definitions"] = True
        saved_report = client.call("information_manage_report", request_id="mission-report", operation="create", config={
            "name": "current-mission-state", "queries": [query("M01", ["branches"]), query("M02", ["completion_status"])], "detail": "raw"})["report"]
        subscription = client.call("information_manage_subscription", request_id="mission-subscription", operation="create", config={
            "name": "mission-every-two-seconds", "kind": "periodic", "report_id": saved_report["id"], "enabled": True,
            "schedule": {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"}})["subscription"]
        deadline = time.monotonic()+6.5
        while time.monotonic() < deadline:
            time.sleep(0.25)
        results = client.call("information_list_results", limit=50)["results"]
        write(args.output / "periodic-results.json", results)
        generated = [item for item in results if item.get("subscription_id") == subscription["id"]]
        assert len(generated) >= 2 and all(item["complete"] for item in generated), generated
        assert all(item["items"][0]["fields"]["branches"]["value"]["slots"] == membership for item in generated)
        assert all(item["delivery"]["status"] == "delivered" and item["context"]["game_date"] == before["date_raw"] for item in generated)
        report["checks"]["periodic_same_source_while_paused"] = True
        client.call("information_manage_subscription", request_id="mission-cancel", operation="cancel",
                    subscription_id=subscription["id"], expected_version=subscription["version"])
        write(args.output / "runtime-status.json", client.call("information_status"))
        client.close()
        client = None
        snapshot = SavedMissionSnapshot(args.save, "FRA", expected_sha256="ffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0")
        save_data = snapshot.as_dict()
        write(args.output / "saved-snapshot.json", save_data)
        saved_slots = [{"slot": slot["index"], "roots": slot["root_ids"]} for slot in save_data["country_missions"]["mission_slots"]]
        old = {root for slot in saved_slots for root in slot["roots"]}
        current = {root for slot in membership for root in slot["roots"]}
        difference = {"only_in_live": sorted(current-old), "only_in_save": sorted(old-current),
                      "saved_completion_present": save_data["completed_missions"]["present"],
                      "saved_root_count": sum(len(slot["roots"]) for slot in saved_slots),
                      "live_root_count": sum(len(slot["roots"]) for slot in membership),
                      "live_completed_task_ids": [], "equal_root_ids_do_not_prove_branch_visibility": True}
        write(args.output / "save-live-comparison.json", difference)
        assert not difference["only_in_live"] and not difference["only_in_save"], difference
        assert difference["saved_root_count"] == 18 and difference["live_root_count"] == 18, difference
        assert difference["saved_completion_present"] is False, difference
        report["checks"]["saved_and_live_are_distinct"] = True
        after = control_snapshot(installation["pid"], args.output / "after-control.json")
        assert (after["player_slot"], after["paused_flag"], after["date_raw"]) == (189, 1, before["date_raw"]), after
        report["checks"]["pause_player_date_preserved"] = True
        base = DiplomacySource()
        definition_index = MissionDefinitionIndex()
        source = CompositeSource(base, [NativeCountryStateSource(base), StaticTradeSource(),
            MissionInformationSource(base, definition_index, NativeMissionReader(base))])
        coverage = coverage_report(source)
        coverage["configuration"] = {"native_country_state": True, "static_game_data": True, "mission_game_data": True,
            "mission_definitions_sha256": definition_index.context()["definitions_sha256"],
            "implementation_coverage_is_not_full_live_acceptance": True}
        write(args.output / "coverage.json", coverage)
        report.update(status="passed", captured_slots=5, captured_roots=18, mapped_task_definition_entries=len(task_ids),
                      periodic_results=len(generated), save_sha256=save_data["file"]["sha256"])
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        if client is not None:
            client.close()
        write(args.output / "report.json", report)
    print(json.dumps(report))


if __name__ == "__main__":
    main()
