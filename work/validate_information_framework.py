"""Exercise the information framework with existing real records, without game I/O.

This is historical-record integration, not live acquisition acceptance. It never
constructs a native session or replays any diplomatic action.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.information import InformationService
from bridge.information.sources import RecordedSource


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--installation", type=Path, default=ROOT / "work/runtime/diplomacy-observer-20261020-r73-trust-men-b/installation.json")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    database = args.output / "acceptance.sqlite3"
    if database.exists():
        parser.error("Use a new output directory; acceptance databases are not overwritten")
    query_path = ROOT / "bridge/tests/fixtures/r73_favor_queries_real.json"
    events_path = ROOT / "bridge/tests/fixtures/r73_favor_execution_real.json"
    original, events, installation = read(query_path), read(events_path), read(args.installation)
    if original["session_id"] != installation["session_id"]:
        raise ValueError("Recorded session/installation mismatch")
    expected_game_sha = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
    if installation["game_sha256"].lower() != expected_game_sha:
        raise ValueError("This archive is verified for the exact 1.37.4 image only")
    inputs = [{"path": str(path.relative_to(ROOT)), "sha256": sha(path)} for path in (query_path, events_path)]
    inputs.append({"path": str(args.installation), "sha256": sha(args.installation)})
    # FRA is the controlled country of this specific R73 archive, recorded in
    # HANDOFF's R73 running-acceptance section and the source fixture identities.
    manifest = {"context": {
        "status": "ready", "mode": "recorded", "complete": True,
        "session_id": original["session_id"], "observer": "FRA", "game_version": "1.37.4",
        "game_sha256": expected_game_sha, "dll_sha256": installation["dll_sha256"],
        "game_date": original["health"]["date_raw"],
        "game_day": original["health"]["date_raw"] // 24,
        "world_id": "archive:" + sha(query_path),
    }, "provenance": {"mode": "recorded", "inputs": inputs,
                      "observer_evidence": "HANDOFF.md R73 running acceptance; not the player tag"},
        "cases": original["cases"] + events["cases"], "events": events["cases"]}
    manifest_path = args.output / "recorded-manifest.json"
    write(manifest_path, manifest)
    source = RecordedSource(manifest_path)
    clock = [100.0]
    service = InformationService(source, database, clock=lambda: clock[0])
    context_query = {"topic": "C01", "object": {"type": "session"},
                     "fields": ["session_id", "observer", "game_version", "game_day"], "parameters": {}}
    favor_query = {"topic": "R05", "object": {"type": "country_pair", "actor": "FRA", "recipient": "PAP"},
                   "fields": ["trust", "favors_available"],
                   "parameters": {"action_id": "trade_favors_for_trust", "kind": "trust"}}
    try:
        manual = service.query("integration-manual", queries=[context_query, favor_query])
        assert manual["complete"] is True, manual
        partial_query = dict(favor_query, fields=["trust", "favors_available", "favors_direction"])
        partial = service.query("integration-partial", queries=[partial_query])
        assert partial["complete"] is False and partial["status"] == "partial", partial
        assert partial["items"][0]["fields"]["favors_direction"]["status"] == "unknown"
        report = service.manage_report("integration-report", "create", config={"queries": [context_query], "detail": "raw"})["report"]
        subscriptions = []
        for name, every in (("brief", 1), ("report", 3)):
            subscriptions.append(service.manage_subscription("integration-sub-" + name, "create", config={
                "name": name, "kind": "periodic", "report_id": report["id"],
                "schedule": {"basis": "real", "unit": "seconds", "every": every, "missed": "coalesce"}})["subscription"])
        event_type = source.poll_events(source.context(), None)["events"][0]["event_type"]
        event_subscription = service.manage_subscription("integration-event", "create", config={
            "kind": "event", "report_id": report["id"], "event": {"types": [event_type], "actors": ["FRA"], "recipients": ["PAP"]}})["subscription"]
        first = service.tick()
        assert any(r["subscription_id"] == event_subscription["id"] for r in first["results"]), first
        clock[0] = 101.0
        short = service.tick()
        clock[0] = 103.0
        both = service.tick()
        assert {r["subscription_id"] for r in short["results"]} == {subscriptions[0]["id"]}
        assert {r["subscription_id"] for r in both["results"]} == {s["id"] for s in subscriptions}
        assert all(r["context"]["mode"] == "recorded" and r["delivery"]["status"] == "delivered" for r in first["results"] + short["results"] + both["results"])
        write(args.output / "manual-result.json", manual)
        write(args.output / "partial-result.json", partial)
        write(args.output / "subscription-results.json", {"event": first, "short": short, "both": both})
        write(args.output / "runtime-status.json", service.status())
    finally:
        service.close()
    payloads = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "recorded-acceptance", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "information_query", "arguments": {"request_id": "mcp-real-record-query", "queries": [context_query, favor_query]}}},
    ]
    completed = subprocess.run([sys.executable, str(ROOT / "tools/serve_information.py"), "--database", str(args.output / "mcp.sqlite3"),
                                "--recorded-manifest", str(manifest_path)], input="\n".join(json.dumps(p) for p in payloads) + "\n",
                               capture_output=True, text=True, encoding="utf-8", cwd=ROOT, timeout=30)
    (args.output / "mcp-stdout.jsonl").write_text(completed.stdout, encoding="utf-8")
    (args.output / "mcp-stderr.txt").write_text(completed.stderr, encoding="utf-8")
    assert completed.returncode == 0, completed.stderr
    responses = [json.loads(line) for line in completed.stdout.splitlines()]
    tool_result = next(r for r in responses if r.get("id") == 3)["result"]
    assert tool_result.get("isError") is not True, tool_result
    result = json.loads(tool_result["content"][0]["text"])
    assert result["complete"] is True and result["context"]["mode"] == "recorded", result
    summary = {"status": "passed", "mode": "recorded", "live_acceptance": False,
               "inputs": inputs, "checks": ["real_record_query", "partial_remains_partial", "independent_periodic_tasks", "real_request_event_filter", "durable_outbox", "mcp_discovery_and_query"],
               "limitations": ["No live EU4 process was read or started", "Change sampling is validated by contract tests, not fresh game changes", "This does not verify all 74 topics"]}
    write(args.output / "report.json", summary)
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
