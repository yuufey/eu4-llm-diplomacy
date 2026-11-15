"""Verify a newly exposed N04 field using the existing MCP client."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.run_alliance_inbound_response import control_snapshot
from work.validate_information_domestic_pressure import CompactMCPClient, _query


def run(installation: Path, reference: Path, output: Path, *, field="religious_unity"):
    output.mkdir(parents=True, exist_ok=False)
    def write(name, value):
        with (output / name).open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")

    original = json.loads(reference.read_text(encoding="utf-8"))
    assert original["status"] == "observed" and original["completed"] is True
    assert original["doublepass"]["consistent"] is True
    if field in ("overextension", "unrest"):
        native = original[f"{field}_inputs"][0]
        assert native["offset"] == {"overextension": "0xe48", "unrest": "0x2030"}[field]
        expected = int.from_bytes(bytes.fromhex(native["raw_hex"]), "little", signed=True)
        assert expected == native["raw"]
    else:
        native = original["unity_inputs"][0]
        assert native["cache_state"] != 1
        assert all(native["records"][str(key)]["processor"] == "0x0" for key in (168, 231))
        special = bool(native["special_type_flags"] & 0x40) and native["base_amounts"]["231"] != 0
        total = native["province_component"] + native["base_amounts"]["168"]
        expected = 1000 if special else max(0, (total + 2**31) % 2**32 - 2**31)
    document = json.loads(installation.read_text(encoding="utf-8-sig"))
    session = original["identity"]["installation_session_id"]
    date = native["date"]["value"]
    before = control_snapshot(int(document["pid"]), output / "before-control.json")
    assert before["paused_flag"] == 1 and before["speed"] == 0 and before["date_raw"] == date
    report = {"schema": "information_current_domestic_live_acceptance.v2", "status": "running", "field": field,
              "reference": str(reference), "expected_raw": expected, "session_id": session,
              "game_date": date, "checks": {}, "periodic_results": 0}
    client = subscription = None
    try:
        client = CompactMCPClient(installation.resolve(), output, tick_seconds=0.25)
        discovery = client.call("information_discover")
        write("discovery.json", discovery)

        def check(result, fields, *, complete=True):
            assert result["context"]["session_id"] == session
            assert result["context"]["game_date"] == date
            assert result["delivery"]["status"] == "delivered"
            assert result["complete"] is complete
            item = result["items"][0]
            assert set(item["fields"]) == set(fields)
            value = item["fields"][field]
            assert value["status"] == "known" and value["value"] == value["raw"] == expected
            assert value["unit"] == ("unrest" if field == "unrest" else "fraction")
            assert value["scale"] == 1000
            if field == "religious_unity":
                assert value["upper_clamp"] is False
                assert value["value_origin"] == "derived_from_copied_native_inputs"
            elif field == "overextension":
                assert value["basis"] == "native_ui_current_cache"
                assert value["value_origin"] == "copied_native_ui_cache"
            else:
                assert value["basis"] == "native_country_average_unrest_cache"
                assert value["value_origin"] == "copied_native_country_average_cache"
            for other in ("stability", "war_exhaustion", "corruption", "religious_unity", "overextension", "unrest"):
                if other in fields:
                    assert item["fields"][other]["status"] == "known"

        single = client.call("information_query", request_id=f"domestic-{field}-single-001",
                             queries=[_query([field])])
        write("single-query.json", single)
        check(single, [field])
        full_fields = ["stability", "war_exhaustion", "corruption", "religious_unity", "overextension", "unrest"]
        full = client.call("information_query", request_id=f"domestic-{field}-six-001",
                           queries=[_query(full_fields)])
        write("six-field-query.json", full)
        check(full, full_fields)
        mixed_fields = ["stability", field]
        mixed = client.call("information_query", request_id=f"domestic-{field}-mixed-001",
                            queries=[_query(mixed_fields)])
        write("mixed-query.json", mixed)
        check(mixed, mixed_fields)
        report["checks"]["single_full_mixed_query"] = True

        saved = client.call("information_manage_report", request_id=f"domestic-{field}-report-001",
                            operation="create", config={"name": field, "queries": [_query(full_fields)], "detail": "raw"})
        sub = client.call("information_manage_subscription", request_id=f"domestic-{field}-subscription-001",
                          operation="create", config={"name": field + "-periodic", "kind": "periodic",
                          "report_id": saved["report"]["id"], "enabled": True,
                          "schedule": {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"}})
        subscription = sub["subscription"]
        periodic = {}
        deadline = time.monotonic() + 30
        while len(periodic) < 3 and time.monotonic() < deadline:
            listed = client.call("information_list_results", limit=50)
            for result in listed.get("results", []):
                if result.get("subscription_id") == subscription["id"]:
                    check(result, full_fields)
                    periodic[result["result_id"]] = result
            if len(periodic) < 3:
                time.sleep(0.2)
        write("periodic-results.json", list(periodic.values()))
        assert len(periodic) >= 3
        report["periodic_results"] = len(periodic)
        report["checks"]["three_delivered_periodic_results"] = True
        cancelled = client.call("information_manage_subscription", request_id=f"domestic-{field}-cancel-001",
                                operation="cancel", subscription_id=subscription["id"], expected_version=subscription["version"])
        subscription = cancelled["subscription"]
        assert subscription["state"] == "cancelled"
        report["checks"]["subscription_cancelled"] = True
        report["status"] = "passed"
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        if client is not None:
            try:
                if subscription is not None and subscription.get("state") != "cancelled":
                    client.call("information_manage_subscription", request_id=f"domestic-{field}-cleanup-cancel-001",
                                operation="cancel", subscription_id=subscription["id"], expected_version=subscription["version"])
            except Exception as exc:
                report.update(status="failed", cleanup_error=type(exc).__name__)
            finally:
                client.close()
            report["server_exit_code"] = client.process.returncode
            if client.process.returncode != 0:
                report["status"] = "failed"
        after = control_snapshot(int(document["pid"]), output / "after-control.json")
        report["checks"]["paused_date_player_preserved"] = all(
            before[key] == after[key] for key in ("paused_flag", "speed", "date_raw", "player_slot"))
        if not report["checks"]["paused_date_player_preserved"]:
            report["status"] = "failed"
        write("report.json", report)
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--field", choices=("religious_unity", "overextension", "unrest"), default="religious_unity")
    args = parser.parse_args()
    raise SystemExit(run(args.installation, args.reference, args.output, field=args.field))
