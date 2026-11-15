"""Verify loaded child IDs through real MCP queries and paused scheduling.

The reference is a separately retained pure-RPM capture from this same process
and date. This runner never installs, saves, advances time or submits actions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.run_alliance_inbound_response import control_snapshot
from work.validate_information_live import Client


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--native-capture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    installation = json.loads(args.installation.read_text(encoding="utf-8"))
    raw = args.native_capture.read_bytes()
    capture = json.loads(raw)
    report = {"status":"failed", "checks":{}, "mode":"live",
        "scope":"captured_loaded_child_objects_and_current_rule_correspondence",
        "reference_capture_sha256":hashlib.sha256(raw).hexdigest(),
        "branch_visibility_evaluated":False, "task_trigger_evaluated":False}
    client = None
    try:
        assert capture["status"] == "observed" and capture["read_only"] is True
        assert capture["identity"]["installation_session_id"] == installation["session_id"]
        assert capture["identity"]["process_path_sha256"] == installation["game_sha256"]
        assert capture["doublepass"]["consistent"] is True and capture["doublepass"]["task_consistent"] is True
        assert capture["loaded_tasks"]["status"] == "observed" and capture["loaded_tasks"]["complete"] is True
        assert capture["cleanup"]["handle_close"]["closed"] is True
        before = control_snapshot(installation["pid"], args.output / "before-control.json")
        assert (before["player_slot"], before["paused_flag"], before["date_raw"]) == (189, 1, 56553384)
        assert capture["before"]["game_date"]["raw"] == before["date_raw"]
        expected = [{"root_id":root["root_id"], "task_id":task_id, "branch_visibility":"unknown"}
                    for root in capture["loaded_tasks"]["roots"] for task_id in root["task_ids"]]
        assert len(expected) == capture["loaded_tasks"]["total_task_count"]
        client = Client(args.installation, args.output, extra_args=["--mission-game-data"], tick=0.5)
        queries = [{"topic":"M01", "object":{"type":"country", "country":"FRA"}, "fields":["task_id","branches"]},
                   {"topic":"M02", "object":{"type":"country", "country":"FRA"}, "fields":["prerequisites","completion_status"]}]
        result = client.call("information_query", request_id="loaded-tasks-manual", queries=queries)
        write(args.output / "manual-result.json", result)
        assert result["complete"] is True
        first = result["items"][0]
        assert first["fields"]["task_id"]["value"] == expected
        assert first["fields"]["task_id"]["membership_source"] == "captured_loaded_task_objects"
        comparison = first["source"]["provenance"]["task_definition_comparison"]
        assert comparison["loaded_without_current_definition"] == []
        assert comparison["current_definition_not_loaded"] == []
        assert first["source"]["provenance"]["state"]["loaded_tasks_same_doublepass"] is True
        assert result["items"][1]["fields"]["completion_status"]["value"]["completed_task_ids"] == []
        prerequisites = result["items"][1]["fields"]["prerequisites"]["value"]
        assert [(x["root_id"],x["task_id"]) for x in prerequisites] == [(x["root_id"],x["task_id"]) for x in expected]
        report["checks"]["mcp_ids_match_independent_rpm_and_current_definitions"] = True
        selected = expected[0]
        selected_result = client.call("information_query", request_id="loaded-tasks-selected", queries=[
            dict(queries[0], parameters={"task_id":selected["task_id"]}),
            dict(queries[1], parameters={"task_id":selected["task_id"]})])
        write(args.output / "selected-result.json", selected_result)
        assert selected_result["complete"] is True
        assert selected_result["items"][0]["fields"]["task_id"]["value"] == [selected]
        assert selected_result["items"][1]["fields"]["completion_status"]["value"]["selected_task"] == {
            "task_id":selected["task_id"], "completed":False}
        report["checks"]["selected_task_bound_to_loaded_membership"] = True
        saved = client.call("information_manage_report", request_id="loaded-tasks-report", operation="create",
                            config={"name":"loaded-task-objects", "queries":queries, "detail":"raw"})["report"]
        subscription = client.call("information_manage_subscription", request_id="loaded-tasks-periodic", operation="create",
            config={"name":"loaded-tasks-every-two-seconds", "kind":"periodic", "report_id":saved["id"], "enabled":True,
                    "schedule":{"basis":"real", "every":2, "unit":"seconds", "missed":"coalesce"}})["subscription"]
        deadline = time.monotonic()+6.5
        while time.monotonic()<deadline:
            time.sleep(0.25)
        generated = [item for item in client.call("information_list_results", limit=50)["results"]
                     if item.get("subscription_id") == subscription["id"]]
        write(args.output / "periodic-results.json", generated)
        assert len(generated)>=2
        assert all(item["complete"] and item["items"][0]["fields"]["task_id"]["value"] == expected
                   and item["items"][1]["fields"]["prerequisites"]["value"] == prerequisites
                   and item["delivery"]["status"] == "delivered"
                   and item["context"]["game_date"] == before["date_raw"] for item in generated)
        client.call("information_manage_subscription", request_id="loaded-tasks-cancel", operation="cancel",
                    subscription_id=subscription["id"], expected_version=subscription["version"])
        report["checks"]["periodic_and_active_queries_share_loaded_membership"] = True
        client.close()
        client = None
        after = control_snapshot(installation["pid"], args.output / "after-control.json")
        assert (after["player_slot"], after["paused_flag"], after["date_raw"]) == (189, 1, before["date_raw"])
        report["checks"]["pause_player_date_preserved"] = True
        report.update(status="passed", session_id=installation["session_id"], root_count=len(capture["loaded_tasks"]["roots"]),
                      loaded_task_count=len(expected), periodic_results=len(generated), matching_definition_entries=len(prerequisites))
    except Exception as exc:
        report["error"] = {"type":type(exc).__name__, "message":str(exc)}
        raise
    finally:
        if client is not None:
            client.close()
        write(args.output / "report.json", report)
    print(json.dumps(report))


if __name__ == "__main__":
    main()
