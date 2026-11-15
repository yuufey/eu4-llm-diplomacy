"""Recover batch63 captured records using separate service/ingest databases.

No native control or new observation window is dispatched. This is a retained
log recovery receipt, separate from live002's successful producer lifecycle.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.validate_information_live import Client
from tools.control_information_battle_observer import run_control

STAGE = ROOT / "work/runtime/information-battle-capture-management-20261027-001"
INSTALLATION = ROOT / "work/runtime/diplomacy-observer-20261027-information-battle-v30-002/installation.json"
OUTPUT = STAGE / "live-acceptance-003"


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def put(name, value):
    with (OUTPUT / name).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main():
    OUTPUT.mkdir(parents=True, exist_ok=False)
    report = {"status": "running", "scope": "retained_log_recovery_after_live002",
              "native_control_sent": False, "new_natural_window": False,
              "separate_databases": True, "checks": {}}
    client = None
    subscription = None
    index = 0

    def call(name, **arguments):
        nonlocal index
        index += 1
        put(f"tool-{index:03d}-request.json", {"tool": name, "arguments": arguments})
        result = client.call(name, **arguments)
        put(f"tool-{index:03d}-response.json", result)
        return result

    try:
        before = run_control(INSTALLATION, "status")
        put("source-status-before.json", before)
        assert before["native"]["state"] == "disabled"
        installation = read(INSTALLATION)
        stream = read(STAGE / "battle-stream.json")
        assert Path(stream["database"]).resolve() != (OUTPUT / "information.sqlite3").resolve()
        reused = read(STAGE / "live-acceptance-001/tool-0002-information_manage_report-response.json")["report"]
        client = Client(INSTALLATION, OUTPUT, tick=1.0, extra_args=(
            "--battle-stream", str(STAGE / "battle-stream.json"),
            "--battle-ingest-installation", str(INSTALLATION)))
        saved = call("information_manage_report", request_id="batch63-recovery-report-003", operation="create",
                     config={"name": "captured log recovery", "detail": reused["detail"], "queries": reused["queries"]})["report"]
        subscription = call("information_manage_subscription", request_id="batch63-recovery-sub-003", operation="create", config={
            "name": "captured log recovery", "kind": "event", "report_id": saved["id"], "enabled": True,
            "binding": {"session_id": installation["session_id"], "observer": "FRA",
                        "game_version": "1.37.4", "game_sha256": installation["game_sha256"]},
            "event": {"types": ["battle_observation"]}})["subscription"]
        time.sleep(3.0)
        first = call("information_list_results", limit=100)["results"]
        time.sleep(1.2)
        second = call("information_list_results", limit=100)["results"]
        events = [item for item in second if item.get("subscription_id") == subscription["id"]]
        ids = [item["event"]["event_id"] for item in events]
        assert len(ids) == len(set(ids)), "duplicate event delivery"
        assert {item["result_id"] for item in first} == {item["result_id"] for item in second}, "result set changed on next scheduled tick"
        assert all(item["status"] in ("partial", "complete") for item in events)
        status = call("information_status")
        gaps = status.get("event_source", {}).get("gaps", [])
        assert not any(g.get("reason") in ("BATTLE_INGEST_FAILED", "BATTLE_EVENT_SOURCE_UNAVAILABLE") for g in gaps), gaps
        assert status["capture"]["managed"] is False
        new_ids = [event_id for event_id in ids if int(event_id.rsplit(":", 1)[1]) > 11]
        report.update(event_ids=ids, new_window_event_ids=new_ids, event_results=len(events),
                      future_in_same_server_verified=False, ingestion_gaps=gaps)
        report["checks"].update(scheduler_ingested_retained_log=True, scheduled_tick_dedup=True,
                                native_source_remained_unmanaged=True, battle_ingest_no_error=True)
        subscription = call("information_manage_subscription", request_id="batch63-recovery-cancel-003", operation="cancel",
                            subscription_id=subscription["id"], expected_version=subscription["version"])["subscription"]
        final = call("information_status")
        assert not any(row["subscription"]["state"] == "active" for row in final["subscriptions"])
        report["checks"]["cancelled_no_active"] = True
        report["status"] = "passed"
    except Exception as error:
        report["status"] = "failed"
        report["error"] = f"{type(error).__name__}:{error}"
    finally:
        if client:
            if subscription and subscription.get("state") == "active":
                try:
                    call("information_manage_subscription", request_id="batch63-recovery-cleanup-003", operation="cancel",
                         subscription_id=subscription["id"], expected_version=subscription["version"])
                except Exception as error:
                    report["cleanup_error"] = str(error)
            try:
                client.close()
                report["server_exit_code"] = client.process.returncode
            except Exception as error:
                report["status"] = "failed"
                report["close_error"] = str(error)
        after = run_control(INSTALLATION, "status")
        put("source-status-after.json", after)
        if after["native"]["state"] != "disabled":
            report["status"] = "failed"
        put("report.json", report)
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
