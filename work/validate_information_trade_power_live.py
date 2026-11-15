"""Compare T04 MCP results with independently captured raw trade inputs."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.information.tools import TOOL_DEFINITIONS, validate_schema
from work.run_alliance_inbound_response import control_snapshot
from work.validate_information_live import Client


def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


class CheckedClient(Client):
    def call(self, name, **arguments):
        definition = next(item for item in TOOL_DEFINITIONS if item["name"] == name)
        validate_schema(arguments, definition["inputSchema"], "arguments")
        return super().call(name, **arguments)


def query(node, fields=("country_power", "total_power")):
    result = {"topic": "T04", "object": {"type": "trade_node", "node_id": node}}
    if fields is not None:
        result["fields"] = list(fields)
    return result


def run(installation, reference, output):
    output.mkdir(parents=True, exist_ok=False)
    reference_bytes = reference.read_bytes()
    expected = json.loads(reference_bytes)
    # The reference is generated before starting this server, from raw RPM
    # inputs, without importing a production power reader or formula.
    assert expected["basis"] == "independent_raw_RPM_and_static_power_formula_not_public_values"
    binding = json.loads(installation.read_text(encoding="utf-8-sig"))
    assert expected["session_id"] == binding["session_id"]
    assert len(expected["nodes"]) == 80
    before = control_snapshot(int(binding["pid"]), output / "before-control.json")
    assert (before["player_slot"], before["paused_flag"], before["speed"], before["date_raw"]) == (189, 1, 0, expected["game_date"])
    report = {"schema": "information_trade_power_live_acceptance.v1", "status": "running",
              "reference": str(reference), "reference_sha256": hashlib.sha256(reference_bytes).hexdigest(),
              "session_id": expected["session_id"], "game_date": expected["game_date"],
              "configuration": "live native sources plus --static-game-data; no mission/battle sources",
              "checks": {}, "periodic_results": 0, "business_actions_submitted": 0,
              "game_functions_called": False, "outbox": "not_yet_verified", "llm_read": "unknown"}
    client = subscription = None
    try:
        client = CheckedClient(installation.resolve(), output, extra_args=["--static-game-data"])
        discovery = client.call("information_discover")
        write(output / "discovery.json", discovery)
        topic = next(t for t in discovery["topics"] if t["topic_id"] == "T04")
        for field in ("country_power", "total_power"):
            assert topic["fields"][field]["coverage"] == "partial"
        assert all(topic["fields"][field]["coverage"] == "planned" for field in ("shares", "sources"))
        report["checks"]["two_fields_discoverable_with_explicit_remaining_gaps"] = True

        def check(result, selected):
            assert result["context"]["session_id"] == expected["session_id"]
            assert result["context"]["game_date"] == expected["game_date"]
            assert result["delivery"]["status"] == "delivered"
            assert len(result["items"]) == len(selected)
            for item, node in zip(result["items"], selected):
                for field in ("country_power", "total_power"):
                    value = item["fields"][field]
                    raw = expected["nodes"][node][field + "_raw"]
                    assert value["status"] == "known", value
                    assert value["value"] == value["raw"] == raw
                    assert value["raw_hex"] == (raw & 0xFFFFFFFF).to_bytes(4, "little").hex()
                    assert (value["unit"], value["scale"], value["period"]) == ("trade_power", 1000, "current")
                    assert value["basis"] == "native_trade_node_power_caches"
                    origin = "derived_from_copied_native_caches" if field == "country_power" else "copied_native_cache"
                    assert value["value_origin"] == origin and value["complete"] is False
            assert result["complete"] is False

        keys = list(expected["nodes"])
        all_results = []
        for start in range(0, len(keys), 16):
            group = keys[start:start + 16]
            result = client.call("information_query", request_id=f"trade-power-nodes-{start:03d}", queries=[query(key) for key in group])
            write(output / f"node-queries-{start:03d}.json", result)
            check(result, group)
            all_results.append(result["result_id"])
        report["checks"]["all_80_node_country_and_total_values_match_independent_raw"] = True
        report["all_node_result_ids"] = all_results
        mixed = client.call("information_query", request_id="trade-power-default-fields-001", queries=[query("champagne", None)])
        write(output / "default-fields-query.json", mixed)
        check(mixed, ["champagne"])
        assert all(mixed["items"][0]["fields"][field]["status"] == "unsupported" for field in ("shares", "sources"))
        report["checks"]["default_fields_keep_shares_and_sources_unsupported"] = True
        unknown = client.call("information_query", request_id="trade-power-unknown-001", queries=[query("absent_native_node")])
        write(output / "unknown-node-query.json", unknown)
        assert all(value["reason"] == "NODE_NOT_FOUND" for value in unknown["items"][0]["fields"].values())
        report["checks"]["unknown_node_explicit"] = True

        config = client.call("information_manage_report", request_id="trade-power-report-001", operation="create",
                             config={"name": "FRA贸易竞争力", "queries": [query("champagne"), query("rheinland")], "detail": "raw"})
        write(output / "report-config.json", config)
        saved = client.call("information_query", request_id="trade-power-report-query-001", report_id=config["report"]["id"])
        write(output / "report-query.json", saved)
        check(saved, ["champagne", "rheinland"])
        report["checks"]["report_matches_independent_raw"] = True
        response = client.call("information_manage_subscription", request_id="trade-power-subscribe-001", operation="create",
                               config={"name": "trade-power-two-seconds", "kind": "periodic", "report_id": config["report"]["id"], "enabled": True,
                                       "schedule": {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"}})
        subscription = response["subscription"]
        write(output / "subscription-config.json", response)
        periodic = {}
        deadline = time.monotonic() + 30
        while len(periodic) < 3 and time.monotonic() < deadline:
            listed = client.call("information_list_results", limit=50)
            for result in listed.get("results", []):
                if result.get("subscription_id") == subscription["id"]:
                    check(result, ["champagne", "rheinland"])
                    periodic[result["result_id"]] = result
            if len(periodic) < 3:
                time.sleep(0.2)
        write(output / "periodic-results.json", list(periodic.values()))
        assert len(periodic) >= 3
        report["periodic_results"] = len(periodic)
        cancelled = client.call("information_manage_subscription", request_id="trade-power-cancel-001", operation="cancel",
                                subscription_id=subscription["id"], expected_version=subscription["version"])
        subscription = cancelled["subscription"]
        write(output / "cancelled-subscription.json", cancelled)
        assert subscription["state"] == "cancelled"
        listed = client.call("information_manage_subscription", request_id="trade-power-list-subscriptions-001", operation="list")
        write(output / "subscriptions-after.json", listed)
        assert all(item["state"] == "cancelled" for item in listed["subscriptions"])
        report["checks"]["three_periodic_results_delivered_and_subscription_cancelled"] = True
        report["champagne"] = expected["nodes"]["champagne"]
        report["rheinland"] = expected["nodes"]["rheinland"]
        report.update(status="passed", outbox="delivered")
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        if client is not None:
            try:
                if subscription is not None and subscription.get("state") != "cancelled":
                    client.call("information_manage_subscription", request_id="trade-power-cleanup-cancel-001", operation="cancel",
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
