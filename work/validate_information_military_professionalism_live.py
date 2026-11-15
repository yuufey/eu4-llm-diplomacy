"""Accept the new professionalism cache through actual MCP and subscriptions."""
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
from work.validate_information_military_quality_live import query, write
from work.validate_information_trade_power_live import CheckedClient


def run(installation, reference, output):
    raw = reference.read_bytes()
    expected = json.loads(raw)
    header, field = expected["header"], expected["fields"]["professionalism"]
    assert field["status"] == "known" and field["complete"] is True and field["scale"] == 32768
    assert len(bytes.fromhex(field["raw_hex"])) == 8
    assert int.from_bytes(bytes.fromhex(field["raw_hex"]), "little", signed=True) == field["raw"]
    binding = json.loads(installation.read_bytes())
    assert binding["session_id"] == header["session_id"]
    output.mkdir(parents=True, exist_ok=False)
    before = control_snapshot(binding["pid"], output / "before-control.json")
    assert (before["date_raw"], before["player_slot"], before["paused_flag"], before["speed"]) == (header["game_date"], 189, 1, 0)
    report = {"schema": "information_military_professionalism_live_acceptance.v1", "status": "running",
              "reference": str(reference), "reference_sha256": hashlib.sha256(raw).hexdigest(),
              "session_id": header["session_id"], "game_date": header["game_date"],
              "configuration": "native live sources plus --static-game-data; mission and battle disabled",
              "checks": {}, "periodic_results": 0, "business_actions_submitted": 0,
              "game_functions_called": False, "llm_read": "unknown"}
    client = subscription = None

    def check(result, *, complete=True):
        assert result["delivery"]["status"] == "delivered"
        assert result["context"]["session_id"] == header["session_id"]
        assert result["context"]["game_date"] == header["game_date"]
        assert len(result["items"]) == 1 and result["complete"] is complete
        values = result["items"][0]["fields"]
        for key, wanted in field.items():
            assert values["professionalism"].get(key) == wanted, (key, values["professionalism"], wanted)
        return values

    try:
        client = CheckedClient(installation.resolve(), output, extra_args=["--static-game-data"])
        discovery = client.call("information_discover")
        write(output / "discovery.json", discovery)
        topic = next(item for item in discovery["topics"] if item["topic_id"] == "N03")
        assert all(topic["fields"][key]["coverage"] == "available" for key in
                   ("professionalism", "morale", "military_technology", "army_tradition"))
        assert topic["fields"]["discipline"]["coverage"] == "partial"
        assert topic["fields"]["military_modifiers"]["coverage"] == "planned"
        report["checks"]["N03_four_available_discipline_partial_one_planned"] = True
        result = client.call("information_query", request_id="military-professionalism-query-001", queries=[query(["professionalism"])])
        write(output / "professionalism-query.json", result)
        check(result)
        report["checks"]["professionalism_matches_archived_independent_raw_reference"] = True
        mixed = client.call("information_query", request_id="military-professionalism-mixed-001",
                            queries=[query(["professionalism", "military_technology", "army_tradition", "morale", "discipline"])])
        write(output / "five-fields-query.json", mixed)
        values = check(mixed, complete=False)
        for key, value in (("military_technology", 4), ("army_tradition", 21052),
                           ("morale", {"army": 3123, "navy": 2142}), ("discipline", 1000)):
            assert values[key]["status"] == "known" and values[key]["value"] == value
            assert values[key]["complete"] is (key != "discipline")
        default = client.call("information_query", request_id="military-professionalism-default-001", queries=[query()])
        write(output / "default-query.json", default)
        values = check(default, complete=False)
        assert values["military_modifiers"]["status"] != "known"
        report["checks"]["existing_four_fields_preserved_remaining_field_unsupported"] = True
        domestic_fields = ["stability", "war_exhaustion", "corruption", "religious_unity", "overextension", "unrest"]
        domestic = client.call("information_query", request_id="military-professionalism-domestic-001", queries=[query(domestic_fields, "N04")])
        write(output / "domestic-after-profile-rebind.json", domestic)
        assert all(domestic["items"][0]["fields"][key]["status"] == "known" for key in domestic_fields)
        report["checks"]["affected_domestic_six_fields_known_after_dependency_rebind"] = True
        config = client.call("information_manage_report", request_id="military-professionalism-report-001", operation="create",
                             config={"name": "FRA陆军职业度", "queries": [query(["professionalism"])], "detail": "raw"})
        write(output / "report-config.json", config)
        result = client.call("information_query", request_id="military-professionalism-report-query-001", report_id=config["report"]["id"])
        write(output / "report-query.json", result)
        check(result)
        response = client.call("information_manage_subscription", request_id="military-professionalism-subscribe-001", operation="create",
                               config={"name": "military-professionalism-two-seconds", "kind": "periodic", "report_id": config["report"]["id"], "enabled": True,
                                       "schedule": {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"}})
        subscription = response["subscription"]
        write(output / "subscription-config.json", response)
        periodic, deadline = {}, time.monotonic() + 30
        while len(periodic) < 3 and time.monotonic() < deadline:
            listed = client.call("information_list_results", limit=50)
            for value in listed.get("results", []):
                if value.get("subscription_id") == subscription["id"]:
                    check(value)
                    periodic[value["result_id"]] = value
            if len(periodic) < 3:
                time.sleep(0.2)
        write(output / "periodic-results.json", list(periodic.values()))
        assert len(periodic) >= 3
        report["periodic_results"] = len(periodic)
        cancelled = client.call("information_manage_subscription", request_id="military-professionalism-cancel-001", operation="cancel",
                                subscription_id=subscription["id"], expected_version=subscription["version"])
        subscription = cancelled["subscription"]
        write(output / "cancelled-subscription.json", cancelled)
        assert subscription["state"] == "cancelled"
        listed = client.call("information_manage_subscription", request_id="military-professionalism-list-001", operation="list")
        write(output / "subscriptions-after.json", listed)
        assert all(item["state"] == "cancelled" for item in listed["subscriptions"])
        report["checks"]["report_three_periodic_deliveries_cancel_no_active"] = True
        report.update(status="passed", outbox="delivered", values={"professionalism": field["value"]})
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        if client is not None:
            try:
                if subscription is not None and subscription.get("state") != "cancelled":
                    client.call("information_manage_subscription", request_id="military-professionalism-cleanup-cancel-001", operation="cancel",
                                subscription_id=subscription["id"], expected_version=subscription["version"])
                client.close()
            except Exception as exc:
                report.update(status="failed", cleanup_error={"type": type(exc).__name__, "message": str(exc)})
            report["server_exit_code"] = client.process.returncode
        after = control_snapshot(binding["pid"], output / "after-control.json")
        report["checks"]["date_pause_player_preserved"] = all(before[key] == after[key] for key in ("date_raw", "player_slot", "paused_flag", "speed"))
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
