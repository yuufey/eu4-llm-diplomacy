"""Verify mission text queries and periodic delivery against independent RPM.

The reference contains raw selected-language cache bytes and actual loaded
task membership. This runner does not call game functions or submit actions.
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
from bridge.information.mission_texts import decode_template
from work.run_alliance_inbound_response import control_snapshot
from work.validate_information_live import Client


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    installation = json.loads(args.installation.read_text(encoding="utf-8"))
    raw = (args.reference / "native-cache.json").read_bytes()
    captured = json.loads(raw)
    tasks = json.loads((args.reference / "loaded-tasks-before.json").read_text(encoding="utf-8"))
    report = {"status":"failed", "checks":{}, "mode":"live", "scope":"literal_cache_texts_with_unresolved_templates",
              "reference_capture_sha256":hashlib.sha256(raw).hexdigest(),
              "dynamic_substitution_evaluated":False, "branch_visibility_evaluated":False}
    client = None
    try:
        assert captured["status"] == "observed" and captured["read_only"] is True
        assert captured["identity"]["installation_session_id"] == installation["session_id"]
        assert captured["identity"]["process_path_sha256"] == installation["game_sha256"]
        assert captured["doublepass"]["consistent"] and captured["cleanup"]["handle_close"]["closed"]
        assert tasks["loaded_tasks"]["status"] == "observed" and tasks["doublepass"]["task_consistent"]
        members = [{"root_id":root["root_id"], "task_id":task, "branch_visibility":"unknown"}
                   for root in tasks["loaded_tasks"]["roots"] for task in root["task_ids"]]
        expected = {}
        for field, suffix in (("name","_title"),("description","_desc")):
            expected[field] = [dict(decode_template(captured["entries"][item["task_id"]+suffix]["value_hex"],
                                  installation["native_text_codec"]), root_id=item["root_id"], task_id=item["task_id"],
                                  localization_key=item["task_id"]+suffix) for item in members]
        before = control_snapshot(installation["pid"], args.output / "before-control.json")
        assert (before["player_slot"],before["paused_flag"],before["date_raw"]) == (189,1,56553384)
        assert captured["before"]["game_date"]["raw"] == before["date_raw"]
        client = Client(args.installation,args.output,extra_args=["--mission-game-data"],tick=0.5)
        query = {"topic":"M01","object":{"type":"country","country":"FRA"},"fields":["task_id","name","description"]}
        result = client.call("information_query",request_id="localization-manual",queries=[query])
        write(args.output / "manual-result.json",result)
        assert result["status"] == "partial" and result["complete"] is False
        item = result["items"][0]
        assert item["fields"]["task_id"]["value"] == members
        for field in expected:
            value = item["fields"][field]["value"]
            assert value["entries"] == expected[field]
            assert value["language"] == captured["language"]["text"]
            assert value["resolved_count"]+value["unresolved_count"] == len(members)
            assert value["dynamic_substitution_evaluated"] is False
            assert all("text" not in entry for entry in value["entries"] if entry["status"] != "known")
        provenance = item["source"]["provenance"]["localization"]
        assert provenance["codec_source"] == "operator_session.native_text_codec"
        assert provenance["atomic_with_task_slots"] is False and provenance["world_generation_verified"] is False
        assert provenance["batches"][0]["profile_sha256"] == captured["profile"]["sha256"]
        assert provenance["batches"][0]["probe_sha256"] == captured["probe_script_sha256"]
        report["checks"]["active_all_loaded_texts_match_independent_cache"] = True
        selected = client.call("information_query",request_id="localization-selected",queries=[
            dict(query,parameters={"task_id":"fra_liberate_norm"})])
        write(args.output / "selected-result.json",selected)
        assert selected["complete"] is True
        assert selected["items"][0]["fields"]["name"]["value"]["entries"][0]["text"] == "解放诺曼底"
        assert selected["items"][0]["fields"]["description"]["value"]["entries"][0]["text"] == "诺曼底公国在法理上是法兰西王国的封邑，理应重归我等统治之下。"
        report["checks"]["selected_literal_texts_complete"] = True
        saved = client.call("information_manage_report",request_id="localization-report",operation="create",
                            config={"name":"mission-texts","queries":[query],"detail":"raw"})["report"]
        subscription = client.call("information_manage_subscription",request_id="localization-periodic",operation="create",
            config={"name":"mission-texts-two-seconds","kind":"periodic","report_id":saved["id"],"enabled":True,
                    "schedule":{"basis":"real","every":2,"unit":"seconds","missed":"coalesce"}})["subscription"]
        deadline = time.monotonic()+7
        while time.monotonic()<deadline:
            time.sleep(0.25)
        generated = [entry for entry in client.call("information_list_results",limit=50)["results"]
                     if entry.get("subscription_id") == subscription["id"]]
        write(args.output / "periodic-results.json",generated)
        assert len(generated)>=2
        for periodic in generated:
            assert periodic["complete"] is False and periodic["delivery"]["status"] == "delivered"
            assert periodic["context"]["game_date"] == before["date_raw"]
            assert all(periodic["items"][0]["fields"][field]["value"]["entries"] == expected[field] for field in expected)
        client.call("information_manage_subscription",request_id="localization-cancel",operation="cancel",
                    subscription_id=subscription["id"],expected_version=subscription["version"])
        report["checks"]["partial_periodic_results_delivered_with_unknowns"] = True
        client.close()
        client = None
        after = control_snapshot(installation["pid"],args.output / "after-control.json")
        assert (after["player_slot"],after["paused_flag"],after["date_raw"]) == (189,1,before["date_raw"])
        report["checks"]["pause_player_date_preserved"] = True
        report.update(status="passed",task_count=len(members),key_count=len(captured["entries"]),
                      literal_count=sum(entry["status"] == "known" for group in expected.values() for entry in group),
                      unresolved_count=sum(entry["status"] != "known" for group in expected.values() for entry in group),
                      language=captured["language"]["text"],codec=installation["native_text_codec"],
                      periodic_results=len(generated),session_id=installation["session_id"])
    except Exception as exc:
        report["error"] = {"type":type(exc).__name__,"message":str(exc)}
        raise
    finally:
        if client is not None:
            client.close()
        write(args.output / "report.json",report)
    print(json.dumps(report))


if __name__ == "__main__":
    main()
