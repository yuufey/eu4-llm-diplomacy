"""Exercise T05 through existing MCP client against independent raw RPM."""
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
from work.validate_information_domestic_pressure import CompactMCPClient


def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def query(node=None, fields=("income",)):
    obj = {"type": "country", "country": "FRA"} if node is None else {"type": "trade_node", "node_id": node}
    return {"topic": "T05", "object": obj, "fields": list(fields)}


def run(installation, reference, output):
    output.mkdir(parents=True, exist_ok=False)
    ref_bytes = reference.read_bytes()
    expected = json.loads(ref_bytes)
    assert expected["basis"] == "independent_raw_RPM_and_bounded_PE_filter_not_public_values"
    binding = json.loads(installation.read_text(encoding="utf-8-sig"))
    assert expected["session_id"] == binding["session_id"]
    before = control_snapshot(int(binding["pid"]), output / "before-control.json")
    assert (before["player_slot"], before["paused_flag"], before["speed"], before["date_raw"]) == (189, 1, 0, expected["game_date"])
    report = {"schema": "information_trade_income_live_acceptance.v1", "status": "running",
              "reference": str(reference), "reference_sha256": hashlib.sha256(ref_bytes).hexdigest(),
              "session_id": expected["session_id"], "game_date": expected["game_date"],
              "total_raw": expected["total_raw"], "checks": {}, "periodic_results": 0,
              "business_actions_submitted": 0, "native_game_calls_for_trade": False}
    client = subscription = None
    try:
        client = CompactMCPClient(installation.resolve(), output, tick_seconds=0.25)
        discovery = client.call("information_discover")
        write(output / "discovery.json", discovery)
        topic = next(x for x in discovery["topics"] if x["topic_id"] == "T05")
        assert topic["fields"]["income"]["coverage"] in ("partial", "available")
        report["income_coverage"] = topic["fields"]["income"]["coverage"]

        def check(result, selected):
            assert result["delivery"]["status"] == "delivered"
            assert result["context"]["session_id"] == expected["session_id"]
            assert result["context"]["game_date"] == expected["game_date"]
            assert len(result["items"]) == len(selected)
            for item, node in zip(result["items"], selected):
                raw = expected["total_raw"] if node is None else expected["nodes"][node]["income_raw"]
                value = item["fields"]["income"]
                assert value["status"] == "known", value
                assert value["value"] == value["raw"] == raw
                assert value["raw_hex"] == (raw & 0xFFFFFFFF).to_bytes(4, "little").hex()
                assert value["unit"] == "ducats" and value["scale"] == 1000 and value["period"] == "month"
                assert value["basis"] == "native_trade_node_country_income_cache"
                if node is None:
                    assert value["value_origin"] == "derived_from_copied_native_caches"
            return result

        single = client.call("information_query", request_id="trade-income-country-001", queries=[query()])
        write(output / "country-query.json", single)
        check(single, [None])
        report["checks"]["country_total_matches_independent_raw"] = True
        # Query every live node in bounded groups; expected values predate the server.
        keys = list(expected["nodes"])
        all_results = []
        for start in range(0, len(keys), 16):
            group = keys[start:start+16]
            result = client.call("information_query", request_id=f"trade-income-nodes-{start:03d}", queries=[query(key) for key in group])
            check(result, group)
            all_results.append(result)
        write(output / "all-node-queries.json", all_results)
        report["checks"]["all_80_node_contributions_match_raw"] = len(keys) == 80
        mixed = client.call("information_query", request_id="trade-income-mixed-001",
                            queries=[query(fields=("income", "collection", "transfer", "merchant_task", "steering_direction"))])
        write(output / "mixed-query.json", mixed)
        check(mixed, [None])
        assert all(value["status"] == "unsupported" for key, value in mixed["items"][0]["fields"].items() if key != "income")
        report["checks"]["other_four_fields_remain_unsupported"] = True
        unknown = client.call("information_query", request_id="trade-income-unknown-001", queries=[query("absent_native_node")])
        write(output / "unknown-node-query.json", unknown)
        assert unknown["items"][0]["fields"]["income"]["reason"] == "NODE_NOT_FOUND"
        report["checks"]["unknown_node_explicit"] = True
        config = client.call("information_manage_report", request_id="trade-income-report-001", operation="create",
                             config={"name": "FRA贸易收入", "queries": [query(), query("champagne"), query("rheinland")], "detail": "raw"})
        write(output / "report-config.json", config)
        result = client.call("information_query", request_id="trade-income-report-query-001", report_id=config["report"]["id"])
        write(output / "report-query.json", result)
        check(result, [None, "champagne", "rheinland"])
        report["checks"]["report_matches_raw"] = True
        response = client.call("information_manage_subscription", request_id="trade-income-subscribe-001", operation="create",
                               config={"name": "trade-income-two-seconds", "kind": "periodic", "report_id": config["report"]["id"],
                                       "enabled": True, "schedule": {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"}})
        subscription = response["subscription"]
        write(output / "subscription-config.json", response)
        periodic = {}
        deadline = time.monotonic() + 30
        while len(periodic) < 3 and time.monotonic() < deadline:
            listed = client.call("information_list_results", limit=100)
            for result in listed.get("results", []):
                if result.get("subscription_id") == subscription["id"]:
                    check(result, [None, "champagne", "rheinland"])
                    periodic[result["result_id"]] = result
            if len(periodic) < 3:
                time.sleep(0.2)
        write(output / "periodic-results.json", list(periodic.values()))
        assert len(periodic) >= 3
        report["periodic_results"] = len(periodic)
        report["checks"]["three_periodic_results_delivered"] = True
        cancelled = client.call("information_manage_subscription", request_id="trade-income-cancel-001", operation="cancel",
                                subscription_id=subscription["id"], expected_version=subscription["version"])
        subscription = cancelled["subscription"]
        write(output / "cancelled-subscription.json", cancelled)
        assert subscription["state"] == "cancelled"
        report["checks"]["subscription_cancelled"] = True
        report["status"] = "passed"
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        if client is not None:
            try:
                if subscription is not None and subscription.get("state") != "cancelled":
                    client.call("information_manage_subscription", request_id="trade-income-cleanup-cancel-001", operation="cancel",
                                subscription_id=subscription["id"], expected_version=subscription["version"])
                client.close()
            except Exception as exc:
                report.update(status="failed", cleanup_error={"type": type(exc).__name__, "message": str(exc)})
            report["server_exit_code"] = client.process.returncode
        after = control_snapshot(int(binding["pid"]), output / "after-control.json")
        report["checks"]["paused_date_player_preserved"] = all(before[key] == after[key] for key in ("paused_flag", "speed", "date_raw", "player_slot"))
        if not report["checks"]["paused_date_player_preserved"]:
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
