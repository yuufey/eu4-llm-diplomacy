"""Accept the new N03 scalars using independent, previously captured bytes."""
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

FIELDS = ("military_technology", "army_tradition")
OTHER_FIELDS = ("morale", "discipline", "professionalism", "military_modifiers")


def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def query(fields=None, topic="N03"):
    value = {"topic": topic, "object": {"type": "country", "country": "FRA"}}
    if fields is not None:
        value["fields"] = list(fields)
    return value


def run(installation, reference, output):
    raw = reference.read_bytes()
    expected = json.loads(raw)
    header = expected["header"]
    assert header["country"] == "FRA" and set(expected["fields"]) == set(FIELDS)
    public_expected = {}
    for field in FIELDS:
        item = expected["fields"][field]
        assert item["status"] == "observed" and item["width"] == 4 and item["signed"] is True
        assert int.from_bytes(bytes.fromhex(item["raw_hex"]), "little", signed=True) == item["raw"]
        public_expected[field] = {
            "status": "known", "value": item["raw"], "raw": item["raw"], "raw_hex": item["raw_hex"],
            "unit": item["unit"], "scale": item["scale"], "period": item["period"],
            "basis": "native_country_technology_level_cache" if field == "military_technology" else item["basis"],
            "value_origin": item["value_origin"], "complete": True,
        }
    binding = json.loads(installation.read_bytes())
    assert binding["session_id"] == header["session_id"]
    output.mkdir(parents=True, exist_ok=False)
    before = control_snapshot(binding["pid"], output / "before-control.json")
    assert (before["date_raw"], before["player_slot"], before["paused_flag"], before["speed"]) == (header["game_date"], 189, 1, 0)
    report = {"schema": "information_military_quality_live_acceptance.v1", "status": "running",
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
        assert len(result["items"]) == 1
        values = result["items"][0]["fields"]
        for key in FIELDS:
            for name, wanted in public_expected[key].items():
                assert values[key].get(name) == wanted, (key, name, values[key], wanted)
        assert result["complete"] is complete
        return values

    try:
        client = CheckedClient(installation.resolve(), output, extra_args=["--static-game-data"])
        discovery = client.call("information_discover")
        write(output / "discovery.json", discovery)
        topic = next(item for item in discovery["topics"] if item["topic_id"] == "N03")
        assert all(topic["fields"][key]["coverage"] == "available" for key in FIELDS)
        assert all(topic["fields"][key]["coverage"] == "planned" for key in OTHER_FIELDS)
        report["checks"]["N03_two_available_four_planned"] = True
        result = client.call("information_query", request_id="military-quality-two-fields-001", queries=[query(FIELDS)])
        write(output / "two-fields-query.json", result)
        check(result)
        report["checks"]["both_scalars_match_independent_raw_reference"] = True
        default = client.call("information_query", request_id="military-quality-default-001", queries=[query()])
        write(output / "default-query.json", default)
        values = check(default, complete=False)
        assert all(values[key]["status"] != "known" for key in OTHER_FIELDS)
        report["checks"]["remaining_quality_fields_stay_unsupported"] = True
        domestic_fields = ["stability", "war_exhaustion", "corruption", "religious_unity", "overextension", "unrest"]
        domestic = client.call("information_query", request_id="military-parent-domestic-restored-001", queries=[query(domestic_fields, "N04")])
        write(output / "domestic-after-profile-rebind.json", domestic)
        assert all(domestic["items"][0]["fields"][key]["status"] == "known" for key in domestic_fields), domestic
        report["checks"]["affected_domestic_six_fields_known_after_dependency_rebind"] = True
        config = client.call("information_manage_report", request_id="military-quality-report-001", operation="create",
                             config={"name": "FRA军事科技与陆军传统", "queries": [query(FIELDS)], "detail": "raw"})
        write(output / "report-config.json", config)
        result = client.call("information_query", request_id="military-quality-report-query-001", report_id=config["report"]["id"])
        write(output / "report-query.json", result)
        check(result)
        response = client.call("information_manage_subscription", request_id="military-quality-subscribe-001", operation="create",
                               config={"name": "military-quality-two-seconds", "kind": "periodic", "report_id": config["report"]["id"], "enabled": True,
                                       "schedule": {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"}})
        subscription = response["subscription"]
        write(output / "subscription-config.json", response)
        periodic = {}
        deadline = time.monotonic() + 30
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
        cancelled = client.call("information_manage_subscription", request_id="military-quality-cancel-001", operation="cancel",
                                subscription_id=subscription["id"], expected_version=subscription["version"])
        subscription = cancelled["subscription"]
        write(output / "cancelled-subscription.json", cancelled)
        assert subscription["state"] == "cancelled"
        listed = client.call("information_manage_subscription", request_id="military-quality-list-001", operation="list")
        write(output / "subscriptions-after.json", listed)
        assert all(item["state"] == "cancelled" for item in listed["subscriptions"])
        report["checks"]["report_three_periodic_deliveries_cancel_no_active"] = True
        report.update(status="passed", outbox="delivered", values={key: public_expected[key]["value"] for key in FIELDS})
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        if client is not None:
            try:
                if subscription is not None and subscription.get("state") != "cancelled":
                    client.call("information_manage_subscription", request_id="military-quality-cleanup-cancel-001", operation="cancel",
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
