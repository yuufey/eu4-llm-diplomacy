"""Verify native node merchant tasks against independently decoded raw inputs."""
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
from work.validate_information_trade_power_live import CheckedClient


def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def query(node=None, fields=("merchant_task",)):
    obj = {"type": "trade_node", "node_id": node} if node else {"type": "country", "country": "FRA"}
    value = {"topic": "T05", "object": obj}
    if fields is not None:
        value["fields"] = list(fields)
    return value


def run(installation, reference, output):
    output.mkdir(parents=True, exist_ok=False)
    reference_bytes = reference.read_bytes()
    reference_value = json.loads(reference_bytes)
    expected = {**reference_value, **reference_value["header"]}
    assert expected["basis"] == "independent_archived_raw_and_native_merchant_presence_collection_predicate_not_public_values"
    assert len(expected["nodes"]) == 80 and expected["country"] == "FRA"
    binding = json.loads(installation.read_bytes())
    assert expected["session_id"] == binding["session_id"]
    before = control_snapshot(int(binding["pid"]), output / "before-control.json")
    assert (before["player_slot"], before["paused_flag"], before["speed"], before["date_raw"]) == (189, 1, 0, expected["game_date"])
    report = {"schema": "information_trade_merchant_task_live_acceptance.v1", "status": "running",
              "reference": str(reference), "reference_sha256": hashlib.sha256(reference_bytes).hexdigest(),
              "session_id": expected["session_id"], "game_date": expected["game_date"],
              "configuration": "native live sources plus --static-game-data; mission and battle sources disabled",
              "checks": {}, "periodic_results": 0, "business_actions_submitted": 0,
              "game_functions_called": False, "outbox": "not_yet_verified", "llm_read": "unknown"}
    client = subscription = None
    try:
        client = CheckedClient(installation.resolve(), output, extra_args=["--static-game-data"])
        discovery = client.call("information_discover")
        write(output / "discovery.json", discovery)
        topic = next(item for item in discovery["topics"] if item["topic_id"] == "T05")
        assert all(topic["fields"][key]["coverage"] == "partial" for key in ("income", "collection", "merchant_task"))
        assert all(topic["fields"][key]["coverage"] == "planned" for key in ("transfer", "steering_direction"))
        report["checks"]["three_T05_fields_partial_two_other_fields_planned"] = True

        def check(result, selected):
            assert result["delivery"]["status"] == "delivered"
            assert result["context"]["session_id"] == expected["session_id"]
            assert result["context"]["game_date"] == expected["game_date"]
            assert len(result["items"]) == len(selected)
            for item, node in zip(result["items"], selected):
                field = item["fields"]["merchant_task"]
                assert field["status"] == "known", field
                assert field["complete"] is False
                assert (field["unit"], field["scale"], field["period"], field["basis"], field["value_origin"]) == (
                    "state", 1, "current", "native_trade_node_merchant_presence_and_collection_predicate", "derived_from_copied_native_flags")
                wanted = expected["country_merchant_tasks"] if node is None else expected["nodes"][node]["merchant_task"]
                assert field["value"] == wanted, (node, field, wanted)
                if node is not None:
                    assert field["value"] in ("none", "collect", "transfer")
            assert result["complete"] is False

        keys = list(expected["nodes"])
        for start in range(0, len(keys), 16):
            selected = keys[start:start + 16]
            value = client.call("information_query", request_id=f"merchant-tasks-nodes-{start:03d}", queries=[query(key) for key in selected])
            write(output / f"node-queries-{start:03d}.json", value)
            check(value, selected)
        report["checks"]["all_80_node_tasks_match_raw_presence_and_predicate"] = True
        mixed_queries = [query(None, ("income", "collection", "merchant_task")),
                         query("champagne", ("income", "collection", "merchant_task")),
                         query("rheinland", ("income", "collection", "merchant_task"))]
        mixed = client.call("information_query", request_id="merchant-task-three-fields-001", queries=mixed_queries)
        write(output / "three-fields-query.json", mixed)
        check(mixed, [None, "champagne", "rheinland"])
        assert [item["fields"]["income"]["value"] for item in mixed["items"]] == [3813, 3813, 0]
        assert [item["fields"]["collection"]["value"] for item in mixed["items"]] == [["champagne"], True, False]
        report["checks"]["country_tasks_and_existing_collection_income_retained"] = True
        default = client.call("information_query", request_id="merchant-task-default-country-001", queries=[query(None, None)])
        write(output / "default-country-query.json", default)
        check(default, [None])
        assert all(default["items"][0]["fields"][key]["status"] != "known" for key in ("transfer", "steering_direction"))
        unknown = client.call("information_query", request_id="merchant-task-unknown-001", queries=[query("absent_native_node")])
        write(output / "unknown-node-query.json", unknown)
        assert unknown["items"][0]["fields"]["merchant_task"]["reason"] == "NODE_NOT_FOUND"
        report["checks"]["default_and_unknown_node_contracts"] = True

        config = client.call("information_manage_report", request_id="merchant-task-report-001", operation="create",
                             config={"name": "FRA商人任务与收集收入", "queries": mixed_queries, "detail": "raw"})
        write(output / "report-config.json", config)
        saved = client.call("information_query", request_id="merchant-task-report-query-001", report_id=config["report"]["id"])
        write(output / "report-query.json", saved)
        check(saved, [None, "champagne", "rheinland"])
        response = client.call("information_manage_subscription", request_id="merchant-task-subscribe-001", operation="create",
                               config={"name": "merchant-tasks-two-seconds", "kind": "periodic", "report_id": config["report"]["id"], "enabled": True,
                                       "schedule": {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"}})
        subscription = response["subscription"]
        write(output / "subscription-config.json", response)
        periodic = {}
        deadline = time.monotonic() + 30
        while len(periodic) < 3 and time.monotonic() < deadline:
            listed = client.call("information_list_results", limit=50)
            for value in listed.get("results", []):
                if value.get("subscription_id") == subscription["id"]:
                    check(value, [None, "champagne", "rheinland"])
                    periodic[value["result_id"]] = value
            if len(periodic) < 3:
                time.sleep(0.2)
        write(output / "periodic-results.json", list(periodic.values()))
        assert len(periodic) >= 3
        report["periodic_results"] = len(periodic)
        cancelled = client.call("information_manage_subscription", request_id="merchant-task-cancel-001", operation="cancel",
                                subscription_id=subscription["id"], expected_version=subscription["version"])
        subscription = cancelled["subscription"]
        write(output / "cancelled-subscription.json", cancelled)
        assert subscription["state"] == "cancelled"
        listed = client.call("information_manage_subscription", request_id="merchant-task-list-001", operation="list")
        write(output / "subscriptions-after.json", listed)
        assert all(item["state"] == "cancelled" for item in listed["subscriptions"])
        report["checks"]["report_three_periodic_deliveries_and_cancel_no_active"] = True
        report.update(status="passed", outbox="delivered", country_merchant_tasks=expected["country_merchant_tasks"])
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        if client is not None:
            try:
                if subscription is not None and subscription.get("state") != "cancelled":
                    client.call("information_manage_subscription", request_id="merchant-task-cleanup-cancel-001", operation="cancel",
                                subscription_id=subscription["id"], expected_version=subscription["version"])
                client.close()
            except Exception as exc:
                report.update(status="failed", cleanup_error={"type": type(exc).__name__, "message": str(exc)})
            report["server_exit_code"] = client.process.returncode
        after = control_snapshot(int(binding["pid"]), output / "after-control.json")
        report["checks"]["date_pause_player_preserved"] = all(before[key] == after[key] for key in ("date_raw", "paused_flag", "speed", "player_slot"))
        if not report["checks"]["date_pause_player_preserved"]:
            report["status"] = "failed"
        write(output / "report.json", report)
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.installation, args.reference, args.output))
