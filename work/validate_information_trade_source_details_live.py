"""Verify additional native source containers through the real MCP service."""
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

SOURCE_ORDER = ("TP_PROVINCE_POWER", "TP_SHIP_POWER", "TRADE_POWER_CAPITAL", "MERCHANT_DOWNSTREAM_BONUS")


def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def query(node, fields=("sources",)):
    result = {"topic": "T04", "object": {"type": "trade_node", "node_id": node}}
    if fields is not None:
        result["fields"] = list(fields)
    return result


def reference_rows(node):
    rows = node["source_rows"]
    if isinstance(rows, dict):
        rows = [dict(value, native_key=key) for key, value in rows.items()]
    return sorted((row for row in rows if row.get("included", True)), key=lambda row: SOURCE_ORDER.index(row["native_key"]))


def run(installation, reference, output):
    output.mkdir(parents=True, exist_ok=False)
    raw = reference.read_bytes()
    expected = json.loads(raw)
    assert expected["basis"] == "independent_raw_RPM_and_static_extended_sources_not_public_values"
    binding = json.loads(installation.read_text(encoding="utf-8-sig"))
    assert binding["session_id"] == expected["session_id"] and len(expected["nodes"]) == 80
    before = control_snapshot(int(binding["pid"]), output / "before-control.json")
    assert (before["player_slot"], before["paused_flag"], before["speed"], before["date_raw"]) == (189, 1, 0, expected["game_date"])
    report = {"schema": "information_extended_trade_sources_live_acceptance.v1", "status": "running",
              "reference": str(reference), "reference_sha256": hashlib.sha256(raw).hexdigest(),
              "session_id": expected["session_id"], "game_date": expected["game_date"],
              "configuration": "live native sources plus --static-game-data; no mission/battle sources",
              "checks": {}, "periodic_results": 0, "business_actions_submitted": 0, "game_functions_called": False,
              "outbox": "not_yet_verified", "llm_read": "unknown"}
    client = subscription = None
    try:
        client = CheckedClient(installation.resolve(), output, extra_args=["--static-game-data"])
        discovery = client.call("information_discover")
        write(output / "discovery.json", discovery)
        topic = next(topic for topic in discovery["topics"] if topic["topic_id"] == "T04")
        assert topic["fields"]["sources"]["coverage"] == "partial"
        assert topic["fields"]["sources"]["unit"] == "mixed"
        report["checks"]["mixed_source_units_and_partial_scope_discoverable"] = True

        def check_container(actual, reference_container, *, transfer=False):
            assert actual["status"] == "known", actual
            wanted = reference_container["items"]
            items = actual["items"]
            assert len(items) == len(wanted)
            for item, source in zip(items, wanted):
                raw_value = source.get("raw", source.get("value_raw"))
                raw_hex = source.get("raw_hex", source.get("value_raw_hex"))
                assert item["raw"] == raw_value and item["raw_hex"] == raw_hex
                assert item["scale"] == 1000
                if transfer:
                    assert item["unit"] == "trade_power"
                    assert item["country"] == source["country_binding"]["country_tag"]
                    assert item["fullref_raw_hex"] == source["fullref_raw_hex"]
                else:
                    assert item["unit"] == "unknown"
                    assert item["name"]["status"] == "unknown"
                    assert item["name"]["raw_hex"] == source["name_raw_hex"]

        def check(result, selected):
            assert result["delivery"]["status"] == "delivered"
            assert result["context"]["session_id"] == expected["session_id"]
            assert result["context"]["game_date"] == expected["game_date"]
            assert len(result["items"]) == len(selected)
            for item, node_id in zip(result["items"], selected):
                field = item["fields"]["sources"]
                assert field["status"] == "known", field
                assert field["complete"] is False and field["unit"] == "mixed"
                source = field["value"]["FRA"]
                ref = expected["nodes"][node_id]
                wanted = reference_rows(ref)
                assert len(source["rows"]) == len(wanted), (node_id, source["rows"], wanted)
                for row, reference_row in zip(source["rows"], wanted):
                    for key in ("native_key", "raw", "raw_hex"):
                        assert row[key] == reference_row[key], (node_id, row, reference_row)
                    assert row["unit"] == "trade_power" and row["scale"] == 1000
                assert source["capital_status"]["status"] == "known"
                assert source["capital_status"]["included"] == any(row["native_key"] == "TRADE_POWER_CAPITAL" for row in wanted)
                check_container(source["dynamic_sources"], ref["dynamic_sources"])
                for direction in ("to", "from"):
                    check_container(source["transfer_sources"][direction], ref["transfer_sources"][direction], transfer=True)
                    assert all(item["direction"] == direction for item in source["transfer_sources"][direction]["items"])
            assert result["complete"] is False

        keys = list(expected["nodes"])
        for start in range(0, len(keys), 16):
            selected = keys[start:start + 16]
            result = client.call("information_query", request_id=f"extended-sources-nodes-{start:03d}", queries=[query(node) for node in selected])
            write(output / f"node-queries-{start:03d}.json", result)
            check(result, selected)
        report["checks"]["all_80_nodes_match_independent_fixed_dynamic_and_transfer_inputs"] = True
        mixed = client.call("information_query", request_id="extended-sources-four-fields-001", queries=[query("champagne", None)])
        write(output / "four-fields-query.json", mixed)
        check(mixed, ["champagne"])
        assert all(mixed["items"][0]["fields"][key]["status"] == "known" for key in ("shares", "country_power", "total_power"))
        report["checks"]["existing_three_fields_retained_in_default_query"] = True
        unknown = client.call("information_query", request_id="extended-sources-unknown-001", queries=[query("absent_native_node")])
        write(output / "unknown-node-query.json", unknown)
        assert unknown["items"][0]["fields"]["sources"]["reason"] == "NODE_NOT_FOUND"
        config = client.call("information_manage_report", request_id="extended-sources-report-001", operation="create",
                             config={"name": "FRA贸易来源明细", "queries": [query("champagne"), query("rheinland")], "detail": "raw"})
        write(output / "report-config.json", config)
        saved = client.call("information_query", request_id="extended-sources-report-query-001", report_id=config["report"]["id"])
        write(output / "report-query.json", saved)
        check(saved, ["champagne", "rheinland"])
        response = client.call("information_manage_subscription", request_id="extended-sources-subscribe-001", operation="create",
                               config={"name": "extended-sources-two-seconds", "kind": "periodic", "report_id": config["report"]["id"], "enabled": True,
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
        cancelled = client.call("information_manage_subscription", request_id="extended-sources-cancel-001", operation="cancel",
                                subscription_id=subscription["id"], expected_version=subscription["version"])
        subscription = cancelled["subscription"]
        write(output / "cancelled-subscription.json", cancelled)
        assert subscription["state"] == "cancelled"
        listed = client.call("information_manage_subscription", request_id="extended-sources-list-001", operation="list")
        write(output / "subscriptions-after.json", listed)
        assert all(item["state"] == "cancelled" for item in listed["subscriptions"])
        report["checks"]["report_and_three_periodic_deliveries_then_no_active_subscription"] = True
        report.update(status="passed", outbox="delivered", champagne=expected["nodes"]["champagne"], rheinland=expected["nodes"]["rheinland"])
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        if client is not None:
            try:
                if subscription is not None and subscription.get("state") != "cancelled":
                    client.call("information_manage_subscription", request_id="extended-sources-cleanup-cancel-001", operation="cancel",
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
    print(json.dumps({key: value for key, value in report.items() if key not in ("champagne", "rheinland")}, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.installation, args.reference, args.output))
