"""Validate native home-node and static T02 field coexistence through MCP."""
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
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def home_query(fields=("home_node",)):
    return {"topic": "T02", "object": {"type": "country", "country": "FRA"}, "fields": list(fields)}


def run(installation, reference, output):
    output.mkdir(parents=True, exist_ok=False)
    raw = reference.read_bytes()
    expected = json.loads(raw)
    assert expected["basis"] == "independent_raw_RPM_and_static_home_flag_not_public_values"
    graph = json.loads(Path(expected["reference"]).read_bytes())["trade_income_inputs"][0]
    expected_income = 0
    special = int.from_bytes(bytes.fromhex(graph["filter_special_country_slot_raw_hex"]), "little", signed=True)
    for node in graph["nodes"]:
        if int(node["predicate_rva"], 16) == 0x8F450:
            continue
        ac, ad, ae = bytes.fromhex(node["flags_ac_ad_ae_hex"])
        eligible = graph["country_slot"] == special or (ae != 0 and ac == 0) or (ad != 0 and not(ae != 0 and ac != 0))
        if eligible:
            expected_income = (expected_income + int.from_bytes(bytes.fromhex(node["income_raw_hex"]), "little", signed=True)) & 0xFFFFFFFF
    if expected_income >= 0x80000000:
        expected_income -= 0x100000000
    binding = json.loads(installation.read_text(encoding="utf-8-sig"))
    assert expected["session_id"] == binding["session_id"]
    before = control_snapshot(int(binding["pid"]), output/"before-control.json")
    assert (before["player_slot"], before["paused_flag"], before["speed"], before["date_raw"]) == (189, 1, 0, expected["game_date"])
    report = {"schema": "information_home_trade_node_live_acceptance.v1", "status": "running",
              "reference_sha256": hashlib.sha256(raw).hexdigest(), "session_id": expected["session_id"],
              "game_date": expected["game_date"], "home_node": expected["home_node"],
              "configuration": "live native sources plus --static-game-data; no mission/battle sources",
              "checks": {}, "periodic_results": 0, "business_actions_submitted": 0,
              "game_functions_called": False}
    client = subscription = None
    try:
        client = Client(installation.resolve(), output, extra_args=["--static-game-data"])
        discovery = client.call("information_discover")
        write(output/"discovery.json", discovery)
        t02 = next(t for t in discovery["topics"] if t["topic_id"] == "T02")
        assert all(t02["fields"][field]["coverage"] == "partial" for field in ("home_node", "upstream", "routes"))
        assert t02["fields"]["home_node"]["triggers"] == ["query", "periodic"]
        assert t02["fields"]["routes"]["triggers"] == ["query"]
        report["checks"]["native_and_static_field_capabilities_remain_distinct"] = True

        def check(result):
            assert result["context"]["session_id"] == expected["session_id"]
            assert result["context"]["game_date"] == expected["game_date"]
            assert result["delivery"]["status"] == "delivered"
            field = result["items"][0]["fields"]["home_node"]
            assert field["status"] == "known" and field["value"] == expected["home_node"], field
            assert field["basis"] == "native_trade_node_home_flag" and field["value_origin"] == "derived_from_copied_native_flags"
            assert field["native_home_flag_raw"] == expected["home_flags"][expected["home_node"]]
            assert field["native_home_flag_raw_hex"] == bytes([field["native_home_flag_raw"]]).hex()
            assert field["complete"] is False and result["complete"] is False

        single = client.call("information_query", request_id="home-node-single-001", queries=[home_query()])
        write(output/"single-query.json", single)
        check(single)
        report["checks"]["home_key_matches_independent_raw"] = True
        mixed = client.call("information_query", request_id="home-node-mixed-001", queries=[home_query(("home_node", "collect_node", "leak_direction"))])
        write(output/"mixed-query.json", mixed)
        check(mixed)
        assert all(mixed["items"][0]["fields"][field]["status"] == "unsupported" for field in ("collect_node", "leak_direction"))
        report["checks"]["planned_fields_remain_explicit_gaps"] = True
        combined = client.call("information_query", request_id="home-node-cross-source-001", queries=[home_query(),
                               {"topic": "T02", "object": {"type": "trade_node", "node_id": expected["home_node"]}, "fields": ["upstream", "routes"]},
                               {"topic": "T05", "object": {"type": "country", "country": "FRA"}, "fields": ["income"]}])
        write(output/"home-static-income-query.json", combined)
        check(combined)
        assert all(v["status"] == "known" for v in combined["items"][1]["fields"].values())
        assert combined["items"][2]["fields"]["income"]["raw"] == expected_income
        report["checks"]["native_home_static_routes_and_existing_income_coexist"] = True
        one_item = client.call("information_query", request_id="home-node-same-object-001", queries=[home_query(("home_node", "upstream"))])
        write(output/"same-topic-mixed-fields-query.json", one_item)
        check(one_item)
        assert one_item["items"][0]["fields"]["upstream"]["status"] == "unknown"
        assert len(one_item["items"][0]["source"]["sources"]) == 2
        report["checks"]["same_topic_field_owners_keep_separate_results"] = True
        config = client.call("information_manage_report", request_id="home-node-report-001", operation="create",
                             config={"name": "FRA本埠节点", "queries": [home_query()], "detail": "raw"})
        write(output/"report-config.json", config)
        saved = client.call("information_query", request_id="home-node-report-query-001", report_id=config["report"]["id"])
        write(output/"report-query.json", saved)
        check(saved)
        response = client.call("information_manage_subscription", request_id="home-node-subscribe-001", operation="create",
                               config={"name": "home-node-two-seconds", "kind": "periodic", "report_id": config["report"]["id"], "enabled": True,
                                       "schedule": {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"}})
        subscription = response["subscription"]
        write(output/"subscription-config.json", response)
        periodic = {}
        deadline = time.monotonic()+30
        while len(periodic) < 3 and time.monotonic() < deadline:
            listed = client.call("information_list_results", limit=50)
            for result in listed.get("results", []):
                if result.get("subscription_id") == subscription["id"]:
                    check(result)
                    periodic[result["result_id"]] = result
            if len(periodic) < 3:
                time.sleep(0.2)
        write(output/"periodic-results.json", list(periodic.values()))
        assert len(periodic) >= 3
        report["periodic_results"] = len(periodic)
        cancel = client.call("information_manage_subscription", request_id="home-node-cancel-001", operation="cancel",
                             subscription_id=subscription["id"], expected_version=subscription["version"])
        subscription = cancel["subscription"]
        write(output/"cancelled-subscription.json", cancel)
        assert subscription["state"] == "cancelled"
        report["checks"]["home_periodic_delivered_and_cancelled"] = True
        static_report = client.call("information_manage_report", request_id="home-node-static-report-001", operation="create",
                                    config={"name": "静态贸易线路", "detail": "raw", "queries": [{"topic": "T02", "object": {"type": "trade_node", "node_id": expected["home_node"]}, "fields": ["routes"]}]})
        rejected = client.rpc("tools/call", {"name": "information_manage_subscription", "arguments": {
            "request_id": "home-node-static-periodic-negative-001", "operation": "create",
            "config": {"name": "query-only-negative", "kind": "periodic", "enabled": True, "report_id": static_report["report"]["id"],
                       "schedule": {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"}}}})
        write(output/"query-only-subscription-rejection.json", rejected)
        error = json.loads(rejected["content"][0]["text"])["error"]
        assert error["code"] == "unsupported_trigger", error
        report["checks"]["query_only_static_field_not_granted_periodic_by_topic_union"] = True
        report["status"] = "passed"
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        if client is not None:
            try:
                if subscription is not None and subscription.get("state") != "cancelled":
                    client.call("information_manage_subscription", request_id="home-node-cleanup-cancel-001", operation="cancel",
                                subscription_id=subscription["id"], expected_version=subscription["version"])
                client.close()
            except Exception as exc:
                report.update(status="failed", cleanup_error={"type": type(exc).__name__, "message": str(exc)})
            report["server_exit_code"] = client.process.returncode
        after = control_snapshot(int(binding["pid"]), output/"after-control.json")
        report["checks"]["date_pause_player_preserved"] = all(before[key] == after[key] for key in ("date_raw", "paused_flag", "speed", "player_slot"))
        if not report["checks"]["date_pause_player_preserved"]:
            report["status"] = "failed"
        write(output/"report.json", report)
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


def resume_rejection(installation, reference, output):
    """Finish the validator's one missing configuration check; preserve run001."""
    previous_raw = (output/"report.json").read_bytes()
    previous = json.loads(previous_raw)
    assert previous["status"] == "failed" and previous["server_exit_code"] == 0
    assert previous["periodic_results"] == 3 and all(previous["checks"].values())
    assert "missing=['detail']" in previous["error"]["message"]
    expected = json.loads(reference.read_bytes())
    binding = json.loads(installation.read_text(encoding="utf-8-sig"))
    assert binding["session_id"] == expected["session_id"] == previous["session_id"]
    # Reuse the exact config shape of the successful original subscription,
    # changing only the report and name. Validate it before starting a server.
    from bridge.information.tools import TOOL_DEFINITIONS, validate_schema
    transcript = json.loads((output/"mcp-transcript.json").read_bytes())
    successful = next(item["body"]["params"]["arguments"] for item in transcript
                      if item["direction"] == "request" and item["body"].get("method") == "tools/call"
                      and item["body"]["params"]["arguments"].get("request_id") == "home-node-subscribe-001")
    original_config = json.loads((output/"static-report-config-recovery.json").read_bytes())
    negative_arguments = {"request_id": "home-static-periodic-negative-recovery-004", "operation": "create",
                          "config": dict(successful["config"], name="query-only-negative", report_id=original_config["report"]["id"])}
    definition = next(item for item in TOOL_DEFINITIONS if item["name"] == "information_manage_subscription")
    validate_schema(negative_arguments, definition["inputSchema"], "arguments")
    list_arguments = {"request_id": "home-subscriptions-recovery-list-004", "operation": "list"}
    validate_schema(list_arguments, definition["inputSchema"], "arguments")
    write(output/"validated-rejection-arguments-004.json", negative_arguments)
    before = control_snapshot(int(binding["pid"]), output/"before-control-recovery-004.json")
    assert (before["player_slot"], before["paused_flag"], before["speed"], before["date_raw"]) == (189, 1, 0, expected["game_date"])
    report = dict(previous, checks=dict(previous["checks"]), status="running",
                  original_report_sha256=hashlib.sha256(previous_raw).hexdigest(),
                  intermediate_report_sha256=hashlib.sha256((output/"report-002.json").read_bytes()).hexdigest(),
                  second_intermediate_report_sha256=hashlib.sha256((output/"report-003.json").read_bytes()).hexdigest(),
                  recovery="Only the configuration rejection check and cleanup are new. Original query/report/periodic records are reused, not rerun.")
    report.pop("error", None)
    client = None
    try:
        client = Client(installation.resolve(), output, suffix="-rejection-recovery-004", extra_args=["--static-game-data"])
        config = client.call("information_manage_report", request_id="home-static-report-recovery-get-004", operation="get",
                             report_id=original_config["report"]["id"])
        write(output/"static-report-config-recovery-get-004.json", config)
        rejected = client.rpc("tools/call", {"name": "information_manage_subscription", "arguments": negative_arguments})
        write(output/"query-only-subscription-rejection-recovery-004.json", rejected)
        assert json.loads(rejected["content"][0]["text"])["error"]["code"] == "unsupported_trigger", rejected
        report["checks"]["query_only_static_field_not_granted_periodic_by_topic_union"] = True
        listed = client.call("information_manage_subscription", **list_arguments)
        write(output/"subscriptions-after-recovery-004.json", listed)
        assert all(item["state"] == "cancelled" for item in listed["subscriptions"])
        report["checks"]["no_active_subscription_after_recovery"] = True
        report["status"] = "passed"
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        if client is not None:
            try:
                client.close()
            except Exception as exc:
                report.update(status="failed", cleanup_error={"type": type(exc).__name__, "message": str(exc)})
            report["server_exit_code"] = client.process.returncode
        after = control_snapshot(int(binding["pid"]), output/"after-control-recovery-004.json")
        preserved = all(before[key] == after[key] for key in ("date_raw", "paused_flag", "speed", "player_slot"))
        report["checks"]["recovery_date_pause_player_preserved"] = preserved
        if not preserved:
            report["status"] = "failed"
        write(output/"report-004.json", report)
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resume-rejection-only", action="store_true")
    args = parser.parse_args()
    action = resume_rejection if args.resume_rejection_only else run
    raise SystemExit(action(args.installation, args.reference, args.output))
