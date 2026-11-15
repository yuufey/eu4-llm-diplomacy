"""One MCP acceptance batch for localized modifiers, loans and R01 state.

Read-only native diplomacy queries are used by R01; country/text capture is
RPM-only.  This runner never installs, advances time, saves or submits an
action.  Consumer repairs must use its retained transcript.
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

from work.run_alliance_inbound_response import control_snapshot
from work.validate_information_trade_power_live import CheckedClient, write


def query(topic, fields=None):
    obj = ({"type": "country_pair", "actor": "FRA", "recipient": "ORL"}
           if topic == "R01" else {"type": "country", "country": "FRA"})
    result = {"topic": topic, "object": obj}
    if fields is not None:
        result["fields"] = fields
    return result


def check(result, literals, loans):
    assert result["delivery"]["status"] == "delivered" and result["complete"] is False
    assert result["context"]["session_id"] == literals["session_id"]
    assert result["context"]["game_date"] == literals["game_date"]
    items = {item["query"]["topic"]: item for item in result["items"]}
    assert set(items) == {"N01", "N07", "R01"}
    fields = items["N07"]["fields"]
    assert fields["modifier_id"]["value"] == literals["modifier_ids"]
    for name, prefix in (("name", ""), ("description", "desc_")):
        field = fields[name]
        assert field["status"] == "known" and field["complete"] is False
        assert len(field["value"]) == len(literals["modifier_ids"])
        for row in field["value"]:
            key = prefix + row["modifier_id"]
            assert row["key"] == key and row["status"] == "known"
            assert row["value"] == literals["entries"][key]["text"]
            assert row["language"] == literals["language"]
            assert row["codec"] == literals["codec"]
    # The independent reference keeps all raw values; new nested metadata is
    # checked recursively without requiring unrelated provenance equality.
    actual_loans = items["N01"]["fields"]["loans"]
    assert actual_loans["status"] == "known"
    expected_rows = loans["rows"]
    assert len(actual_loans["value"]) == len(expected_rows)

    def contains(actual, expected):
        if isinstance(expected, dict):
            assert isinstance(actual, dict)
            for key, value in expected.items():
                assert key in actual, key
                contains(actual[key], value)
        elif isinstance(expected, list):
            assert isinstance(actual, list) and len(actual) == len(expected)
            for a, e in zip(actual, expected):
                contains(a, e)
        else:
            assert actual == expected, (actual, expected)
    for actual, expected in zip(actual_loans["value"], expected_rows):
        for field in ("principal", "interest", "due"):
            assert actual[field]["raw"] == expected[field + "_raw"]
        contains(actual["lender"], expected["lender"])
        calendar = actual["due"]["calendar"]
        for key in ("reference_raw", "ticks_per_day", "days_per_year", "delta_ticks", "day_index",
                    "tick_of_day", "year_index", "day_of_year", "algorithm", "month_day_status",
                    "month", "day", "date"):
            if key in expected["due_calendar"]:
                assert calendar.get(key) == expected["due_calendar"][key], (key, calendar, expected["due_calendar"])
    relation = items["R01"]["fields"]
    assert relation["expires_at"]["status"] == "unsupported"
    states = {row["relation_type"]: row for row in relation["status"]["value"]}
    assert set(states) == {"vassalization", "guarantee", "support_independence", "military_access", "rival"}
    assert all(row["status"] == "known" for row in states.values()), states
    assert states["vassalization"]["value"] == "active"
    grantors = {row["relation_type"]: row for row in relation["grantor"]["value"]}
    recipients = {row["relation_type"]: row for row in relation["recipient"]["value"]}
    assert grantors["vassalization"]["value"] == "FRA"
    assert recipients["vassalization"]["value"] == "ORL"
    return items


def run(installation, literal_reference, loans_reference, output):
    output.mkdir(parents=True, exist_ok=False)
    literals = json.loads(literal_reference.read_bytes())
    loans = json.loads(loans_reference.read_bytes())
    binding = json.loads(installation.read_bytes())
    assert binding["session_id"] == literals["session_id"]
    before = control_snapshot(binding["pid"], output / "before-control.json")
    assert (before["date_raw"], before["player_slot"], before["paused_flag"], before["speed"]) == (literals["game_date"], 189, 1, 0)
    report = {"schema": "information_country_records_localization_acceptance.v1", "status": "running",
              "session_id": literals["session_id"], "game_date": literals["game_date"], "checks": {},
              "configuration": "live native sources plus static; mission/battle disabled",
              "business_actions_submitted": 0, "r01_uses_read_only_native_game_queries": True,
              "save_restart_or_date_advance": False, "llm_read": "unknown",
              "references": [{"path": str(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                             for p in (literal_reference, loans_reference)]}
    client = subscription = None
    queries = [query("N01", ["loans"]), query("N07", ["modifier_id", "name", "description"]), query("R01")]
    try:
        client = CheckedClient(installation.resolve(), output, extra_args=["--static-game-data"])
        discovery = client.call("information_discover")
        write(output / "discovery.json", discovery)
        for topic, names in (("N07", ["name", "description"]), ("R01", ["relation_type", "status", "grantor", "recipient"])):
            entry = next(t for t in discovery["topics"] if t["topic_id"] == topic)
            assert all(entry["fields"][name]["coverage"] == "partial" for name in names)
        result = client.call("information_query", request_id="records-localized-query-001", queries=queries)
        write(output / "query.json", result)
        check(result, literals, loans)
        report["checks"]["query_matches_raw_references_and_five_native_family_states"] = True
        configured = client.call("information_manage_report", request_id="records-localized-report-001", operation="create",
                                 config={"name": "FRA贷款、修正文本与选定关系", "queries": queries, "detail": "raw"})
        write(output / "report-config.json", configured)
        result = client.call("information_query", request_id="records-localized-report-query-001", report_id=configured["report"]["id"])
        write(output / "report-query.json", result)
        check(result, literals, loans)
        report["checks"]["configured_report_preserves_same_semantics"] = True
        response = client.call("information_manage_subscription", request_id="records-localized-subscribe-001", operation="create",
                               config={"name": "records-localized-periodic", "kind": "periodic", "report_id": configured["report"]["id"],
                                       "enabled": True, "schedule": {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"}})
        subscription = response["subscription"]
        write(output / "subscription-config.json", response)
        periodic = []
        deadline = time.monotonic() + 45
        while not periodic and time.monotonic() < deadline:
            listed = client.call("information_list_results", limit=50)
            periodic = [r for r in listed["results"] if r.get("subscription_id") == subscription["id"]]
            if not periodic:
                time.sleep(.2)
        write(output / "periodic-results.json", periodic)
        assert periodic
        for result in periodic:
            check(result, literals, loans)
        cancelled = client.call("information_manage_subscription", request_id="records-localized-cancel-001", operation="cancel",
                                subscription_id=subscription["id"], expected_version=subscription["version"])
        subscription = cancelled["subscription"]
        write(output / "cancelled-subscription.json", cancelled)
        listed = client.call("information_manage_subscription", request_id="records-localized-list-001", operation="list")
        write(output / "subscriptions-after.json", listed)
        assert all(s["state"] == "cancelled" for s in listed["subscriptions"])
        report.update(status="passed", periodic_results=len(periodic), outbox="delivered")
        report["checks"]["periodic_delivery_cancel_and_no_active_subscription"] = True
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        if client is not None:
            try:
                if subscription and subscription.get("state") != "cancelled":
                    client.call("information_manage_subscription", request_id="records-localized-cleanup-001", operation="cancel",
                                subscription_id=subscription["id"], expected_version=subscription["version"])
                client.close()
            except Exception as exc:
                report.update(status="failed", cleanup_error=str(exc))
            report["server_exit_code"] = client.process.returncode
        after = control_snapshot(binding["pid"], output / "after-control.json")
        report["checks"]["date_pause_player_preserved"] = all(before[k] == after[k] for k in ("date_raw", "player_slot", "paused_flag", "speed"))
        if not report["checks"]["date_pause_player_preserved"]:
            report["status"] = "failed"
        write(output / "report.json", report)
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("installation", "literal-reference", "loans-reference", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.installation, args.literal_reference, args.loans_reference, args.output))
