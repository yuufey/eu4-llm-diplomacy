"""Validate derived mission prerequisites through MCP in the paused scene."""
from __future__ import annotations

import argparse
from collections import Counter
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
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    installation = json.loads(args.installation.read_text(encoding="utf-8"))
    report = {"status": "failed", "checks": {}, "mode": "live",
              "scope": "literal required_missions completion conjunction only",
              "branch_visibility_evaluated": False, "task_trigger_evaluated": False}
    client = None
    try:
        before = control_snapshot(installation["pid"], args.output / "before-control.json")
        assert (before["player_slot"], before["paused_flag"], before["date_raw"]) == (189, 1, 56553384)
        client = Client(args.installation, args.output, extra_args=["--mission-game-data"], tick=0.5)
        query = {"topic": "M02", "object": {"type": "country", "country": "FRA"},
                 "fields": ["prerequisites", "completion_status", "unlock_conditions", "currently_completable"]}
        result = client.call("information_query", request_id="prerequisites-manual", queries=[query])
        write(args.output / "manual-result.json", result)
        fields = result["items"][0]["fields"]
        assert result["complete"] is False and fields["currently_completable"]["status"] == "unsupported"
        assert fields["completion_status"]["value"]["completed_task_ids"] == []
        conditions = fields["unlock_conditions"]["value"]
        inputs = conditions["captured_inputs"]
        assert conditions["evaluated"] is False and inputs["status"] == "known"
        assert inputs["map_setup"]["value"] == {"raw": 0, "name": "normal"}
        assert len(inputs["country_flags"]) == 4 and all(value == {"status": "known", "value": False}
            for value in inputs["country_flags"].values())
        assert inputs["dlc_loaded"]["status"] == "known" and inputs["dlc_loaded"]["value"] == {"Domination": True}
        assert inputs["dlc_loaded"]["complete_inventory"] is False
        report["checks"]["branch_inputs_captured_without_visibility_inference"] = True
        entries = fields["prerequisites"]["value"]
        assert len(entries) == 61 and all(entry["evaluated"] is True for entry in entries)
        counts = Counter(entry["evaluation"]["satisfied"] for entry in entries)
        assert counts == {True: 13, False: 48}, counts
        for entry in entries:
            evaluation = entry["evaluation"]
            assert evaluation["semantics"]["scope"] == "required_missions_only"
            required = evaluation["required_task_ids"]
            assert evaluation["missing_task_ids"] == required
            assert evaluation["satisfied"] == (len(required) == 0)
        report["checks"]["all_61_prerequisites_and_partial_topic_boundary"] = True
        config_query = dict(query, fields=["prerequisites", "completion_status", "unlock_conditions"])
        saved_report = client.call("information_manage_report", request_id="prerequisites-report", operation="create",
            config={"name": "mission-prerequisite-status", "queries": [config_query], "detail": "raw"})["report"]
        subscription = client.call("information_manage_subscription", request_id="prerequisites-periodic", operation="create",
            config={"name": "mission-prerequisites-every-two-seconds", "kind": "periodic", "report_id": saved_report["id"],
                    "enabled": True, "schedule": {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"}})["subscription"]
        deadline = time.monotonic()+6.5
        while time.monotonic() < deadline:
            time.sleep(0.25)
        results = client.call("information_list_results", limit=50)["results"]
        generated = [item for item in results if item.get("subscription_id") == subscription["id"]]
        write(args.output / "periodic-results.json", generated)
        assert len(generated) >= 2
        assert all(item["complete"] and item["items"][0]["fields"]["prerequisites"]["value"] == entries for item in generated)
        assert all(item["items"][0]["fields"]["unlock_conditions"]["value"]["captured_inputs"] == inputs for item in generated)
        assert all(item["delivery"]["status"] == "delivered" and item["context"]["game_date"] == before["date_raw"] for item in generated)
        client.call("information_manage_subscription", request_id="prerequisites-cancel", operation="cancel",
                    subscription_id=subscription["id"], expected_version=subscription["version"])
        report["checks"]["periodic_uses_same_derived_state"] = True
        client.close()
        client = None
        after = control_snapshot(installation["pid"], args.output / "after-control.json")
        assert (after["player_slot"], after["paused_flag"], after["date_raw"]) == (189, 1, before["date_raw"])
        report["checks"]["pause_player_date_preserved"] = True
        report.update(status="passed", task_definition_entries=61, no_prerequisites=13, unmet_prerequisites=48,
                      completed_task_ids=[], periodic_results=len(generated), session_id=installation["session_id"],
                      domination_condition=True, complete_dlc_inventory=False)
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
