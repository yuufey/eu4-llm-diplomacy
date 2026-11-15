"""Verify T04 share/source collections against independently copied entries."""
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


def query(node, fields=("shares", "sources")):
    result = {"topic": "T04", "object": {"type": "trade_node", "node_id": node}}
    if fields is not None:
        result["fields"] = list(fields)
    return result


def run(installation, reference, output):
    output.mkdir(parents=True, exist_ok=False)
    ref_bytes = reference.read_bytes()
    expected = json.loads(ref_bytes)
    assert expected["basis"] == "independent_raw_RPM_and_static_share_sources_not_public_values"
    binding = json.loads(installation.read_text(encoding="utf-8-sig"))
    assert expected["session_id"] == binding["session_id"]
    assert len(expected["nodes"]) == 80
    before = control_snapshot(int(binding["pid"]), output / "before-control.json")
    assert (before["player_slot"], before["paused_flag"], before["speed"], before["date_raw"]) == (189, 1, 0, expected["game_date"])
    report = {"schema": "information_trade_details_live_acceptance.v1", "status": "running",
              "reference": str(reference), "reference_sha256": hashlib.sha256(ref_bytes).hexdigest(),
              "session_id": expected["session_id"], "game_date": expected["game_date"],
              "configuration": "live native sources plus --static-game-data; no mission/battle sources",
              "checks": {}, "periodic_results": 0, "business_actions_submitted": 0,
              "game_functions_called": False, "outbox": "not_yet_verified", "llm_read": "unknown"}
    client = subscription = None
    try:
        client = CheckedClient(installation.resolve(), output, extra_args=["--static-game-data"])
        discovery = client.call("information_discover")
        write(output / "discovery.json", discovery)
        topic = next(item for item in discovery["topics"] if item["topic_id"] == "T04")
        assert all(topic["fields"][field]["coverage"] == "partial" for field in ("country_power", "total_power", "shares", "sources"))
        report["checks"]["all_four_fields_discoverable_with_partial_scope"] = True

        def check(result, selected):
            assert result["context"]["session_id"] == expected["session_id"]
            assert result["context"]["game_date"] == expected["game_date"]
            assert result["delivery"]["status"] == "delivered"
            assert len(result["items"]) == len(selected)
            for item, node in zip(result["items"], selected):
                reference_node = expected["nodes"][node]
                fields = item["fields"]
                for name, unit in (("shares", "ratio"), ("sources", "trade_power")):
                    field = fields[name]
                    assert field["status"] == "known", field
                    assert field["basis"] == "native_trade_node_share_and_source_caches"
                    assert field["value_origin"] == "copied_native_cache"
                    assert field["complete"] is False and field["period"] == "current"
                    assert field["unit"] == unit and field["scale"] == 1000
                    assert set(field["value"]) == {"FRA"}
                share = fields["shares"]["value"]["FRA"]
                assert share["raw"] == reference_node["share_raw"]
                assert share["raw_hex"] == reference_node["share_raw_hex"]
                assert share["unit"] == "ratio" and share["scale"] == 1000
                rows = fields["sources"]["value"]["FRA"]["rows"]
                reference_rows = reference_node["source_rows"]
                if isinstance(reference_rows, dict):
                    reference_rows = [dict(raw, native_key=key) for key, raw in reference_rows.items()]
                assert len(rows) == len(reference_rows)
                for row, raw in zip(rows, reference_rows):
                    for key in ("native_key", "raw", "raw_hex"):
                        assert row[key] == raw[key], (node, row, raw)
                    assert row["unit"] == "trade_power" and row["scale"] == 1000
            assert result["complete"] is False

        keys = list(expected["nodes"])
        result_ids = []
        for start in range(0, len(keys), 16):
            selected = keys[start:start + 16]
            result = client.call("information_query", request_id=f"trade-details-nodes-{start:03d}", queries=[query(node) for node in selected])
            write(output / f"node-queries-{start:03d}.json", result)
            check(result, selected)
            result_ids.append(result["result_id"])
        report["checks"]["all_80_node_share_caches_and_conditional_source_rows_match_raw"] = True
        report["all_node_result_ids"] = result_ids
        mixed = client.call("information_query", request_id="trade-details-all-four-fields-001", queries=[query("champagne", None)])
        write(output / "all-four-fields-query.json", mixed)
        check(mixed, ["champagne"])
        assert all(mixed["items"][0]["fields"][field]["status"] == "known" for field in ("country_power", "total_power"))
        assert len(mixed["items"][0]["source"]["sources"]) == 2
        report["checks"]["new_fields_and_existing_power_fields_share_one_topic"] = True
        unknown = client.call("information_query", request_id="trade-details-unknown-001", queries=[query("absent_native_node")])
        write(output / "unknown-node-query.json", unknown)
        assert all(value["reason"] == "NODE_NOT_FOUND" for value in unknown["items"][0]["fields"].values())
        report["checks"]["unknown_node_explicit"] = True
        config = client.call("information_manage_report", request_id="trade-details-report-001", operation="create",
                             config={"name": "FRA贸易份额与来源", "queries": [query("champagne"), query("rheinland")], "detail": "raw"})
        write(output / "report-config.json", config)
        saved = client.call("information_query", request_id="trade-details-report-query-001", report_id=config["report"]["id"])
        write(output / "report-query.json", saved)
        check(saved, ["champagne", "rheinland"])
        report["checks"]["report_matches_independent_raw"] = True
        response = client.call("information_manage_subscription", request_id="trade-details-subscribe-001", operation="create",
                               config={"name": "trade-details-two-seconds", "kind": "periodic", "report_id": config["report"]["id"], "enabled": True,
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
        cancelled = client.call("information_manage_subscription", request_id="trade-details-cancel-001", operation="cancel",
                                subscription_id=subscription["id"], expected_version=subscription["version"])
        subscription = cancelled["subscription"]
        write(output / "cancelled-subscription.json", cancelled)
        assert subscription["state"] == "cancelled"
        listed = client.call("information_manage_subscription", request_id="trade-details-subscriptions-001", operation="list")
        write(output / "subscriptions-after.json", listed)
        assert all(item["state"] == "cancelled" for item in listed["subscriptions"])
        report["checks"]["three_periodic_results_delivered_and_subscription_cancelled"] = True
        report.update(status="passed", outbox="delivered", champagne=expected["nodes"]["champagne"], rheinland=expected["nodes"]["rheinland"])
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        if client is not None:
            try:
                if subscription is not None and subscription.get("state") != "cancelled":
                    client.call("information_manage_subscription", request_id="trade-details-cleanup-cancel-001", operation="cancel",
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
