"""Validate partial monthly-ledger information against independent raw RPM.

Uses the existing MCP client. Treasury in the mixed query uses the established
read-only diplomatic inspection; no business action is submitted.
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
from work.validate_information_domestic_pressure import CompactMCPClient

FIELDS = ("monthly_income", "monthly_expenses", "monthly_balance")


def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def query(fields=FIELDS, *, reference=False):
    value = {"topic": "N01", "object": {"type": "country", "country": "FRA"}, "fields": list(fields)}
    if reference:
        value["parameters"] = {"reference_recipient": "PAP"}
    return value


def run(installation, reference, output):
    output.mkdir(parents=True, exist_ok=False)
    ref_bytes = reference.read_bytes()
    expected = json.loads(ref_bytes)
    assert expected["basis"] == "independent_raw_RPM_and_statically_audited_index_sets_not_public_values"
    values = expected["raw_values"]
    assert set(values) == set(FIELDS)
    binding = json.loads(installation.read_text(encoding="utf-8-sig"))
    assert expected["session_id"] == binding["session_id"]
    before = control_snapshot(int(binding["pid"]), output / "before-control.json")
    assert (before["player_slot"], before["paused_flag"], before["speed"]) == (189, 1, 0)
    assert before["date_raw"] == expected["game_date"]
    report = {"schema": "information_monthly_ledger_live_acceptance.v1", "status": "running",
              "reference": str(reference), "reference_sha256": hashlib.sha256(ref_bytes).hexdigest(),
              "session_id": expected["session_id"], "game_date": expected["game_date"],
              "expected_raw": values, "checks": {}, "periodic_results": 0,
              "gui_budget_projection_validated": False, "business_actions_submitted": 0,
              "mixed_treasury_uses_existing_read_only_inspection": True}
    client = subscription = None
    try:
        client = CompactMCPClient(installation.resolve(), output, tick_seconds=0.25)
        discovery = client.call("information_discover")
        write(output / "discovery.json", discovery)
        n01 = next(topic for topic in discovery["topics"] if topic["topic_id"] == "N01")
        assert all(n01["fields"][field]["coverage"] == "partial" for field in FIELDS)
        report["checks"]["three_fields_discovered_as_partial"] = True

        def check(result, selected):
            assert result["status"] == "partial" and result["complete"] is False
            assert result["delivery"]["status"] == "delivered"
            assert result["context"]["session_id"] == expected["session_id"]
            assert result["context"]["game_date"] == expected["game_date"]
            item = result["items"][0]
            assert item["complete"] is False
            assert set(item["fields"]) == set(selected)
            for field in FIELDS:
                if field not in selected:
                    continue
                value = item["fields"][field]
                raw = values[field]
                assert value["status"] == "known" and value["value"] == value["raw"] == raw
                assert value["raw_hex"] == (raw & 0xFFFFFFFF).to_bytes(4, "little").hex()
                assert value["unit"] == "ducats" and value["scale"] == 1000
                assert value["basis"] == "native_recurring_monthly_ledger"
                assert value["value_origin"] == "derived_from_copied_native_ledger"
                assert value["period"] == "month"
                assert value["reference_period"] == "previous_month"
                assert value["value_semantics"] == "previous_month_recurring_ledger"
                assert value["complete"] is False

        single = client.call("information_query", request_id="monthly-ledger-single-001",
                             queries=[query(["monthly_income"])])
        write(output / "single-query.json", single)
        check(single, ["monthly_income"])
        report["checks"]["income_without_counterparty_matches_raw"] = True
        six = ["treasury", *FIELDS, "loans", "war_income"]
        mixed = client.call("information_query", request_id="monthly-ledger-six-001",
                            queries=[query(six, reference=True)])
        write(output / "six-field-query.json", mixed)
        check(mixed, six)
        fields = mixed["items"][0]["fields"]
        assert fields["treasury"]["status"] == "known"
        assert all(fields[field]["status"] == "unsupported" for field in ("loans", "war_income"))
        report["checks"]["mixed_treasury_and_explicit_gaps_preserved"] = True

        config = client.call("information_manage_report", request_id="monthly-ledger-report-001",
                             operation="create", config={"name": "上月经常性收支台账", "queries": [query()], "detail": "raw"})
        write(output / "report-config.json", config)
        saved_query = client.call("information_query", request_id="monthly-ledger-report-query-001",
                                  report_id=config["report"]["id"])
        write(output / "report-query.json", saved_query)
        check(saved_query, FIELDS)
        report["checks"]["three_field_report_matches_independent_raw"] = True
        response = client.call("information_manage_subscription", request_id="monthly-ledger-periodic-001",
                               operation="create", config={"name": "monthly-ledger-two-seconds", "kind": "periodic",
                               "report_id": config["report"]["id"], "enabled": True,
                               "schedule": {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"}})
        subscription = response["subscription"]
        write(output / "subscription-config.json", response)
        periodic = {}
        deadline = time.monotonic() + 30
        while len(periodic) < 3 and time.monotonic() < deadline:
            listed = client.call("information_list_results", limit=50)
            for result in listed.get("results", []):
                if result.get("subscription_id") == subscription["id"]:
                    check(result, FIELDS)
                    periodic[result["result_id"]] = result
            if len(periodic) < 3:
                time.sleep(0.2)
        write(output / "periodic-results.json", list(periodic.values()))
        assert len(periodic) >= 3
        report["periodic_results"] = len(periodic)
        report["checks"]["three_partial_periodic_results_delivered"] = True
        cancelled = client.call("information_manage_subscription", request_id="monthly-ledger-cancel-001",
                                operation="cancel", subscription_id=subscription["id"], expected_version=subscription["version"])
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
                    client.call("information_manage_subscription", request_id="monthly-ledger-cleanup-cancel-001",
                                operation="cancel", subscription_id=subscription["id"], expected_version=subscription["version"])
            except Exception as exc:
                report.update(status="failed", cleanup_error={"type": type(exc).__name__, "message": str(exc)})
            try:
                client.close()
            except Exception as exc:
                report.update(status="failed", server_close_error={"type": type(exc).__name__, "message": str(exc)})
            report["server_exit_code"] = client.process.returncode
        after = control_snapshot(int(binding["pid"]), output / "after-control.json")
        preserved = all(before[key] == after[key] for key in ("paused_flag", "speed", "date_raw", "player_slot"))
        report["checks"]["paused_date_player_preserved"] = preserved
        if not preserved:
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
