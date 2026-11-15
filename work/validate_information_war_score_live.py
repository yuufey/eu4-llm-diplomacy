"""Paused MCP verification of true war score and its real-time subscription."""
from __future__ import annotations
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.diplomacy import ObserverSession
from bridge.information.tools import TOOL_DEFINITIONS, validate_schema
from work.local_config import game_exe
from work.run_alliance_inbound_response import control_snapshot
from work.validate_information_peace_overextension_live import _ImmediateClient
from work.verify_information_battle_autonomous import read, pin, put

GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
DLL_SHA = "3d9e1fea9d8f34297a4a20646ea0b45d7d0f6a4af11cef6411586dd8b3264964"
EVENTS = {"native_live_war_score_inspection", "native_live_war_score_inspection_failed",
          "native_live_war_score_query_failed", "native_peace_empty_offer_inspection",
          "native_peace_context_inspection"}


def events_since(path, offset):
    size = path.stat().st_size - offset
    assert 0 <= size <= 2 * 1024 * 1024, "native suffix bound"
    with path.open("rb") as stream:
        stream.seek(offset)
        data = stream.read(size)
    rows = []
    for line in data.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and row.get("event") in EVENTS:
            rows.append(row)
    return rows


def check_values(result, war_id):
    assert result["delivery"]["status"] == "delivered"
    assert len(result["items"]) == 1
    item = result["items"][0]
    assert item["objects"] == [{"type": "war", "war_id": war_id, "actor": "FRA", "recipient": "BUR"}]
    score = item["fields"]["war_score"]
    goal = item["fields"]["cumulative_goal_score"]
    assert score["status"] == goal["status"] == "known"
    score, goal = score["value"], goal["value"]
    assert score["source"] == "war_score_query" and score["verified"] is True
    assert score["mode"] == "whole_war" and score["perspective"] == "actor"
    assert score["total"]["scale"] == 1 and goal["scale"] == 1000
    assert score["total"]["unit"] == goal["unit"] == "war_score_point"
    assert goal == score["goal"]["cumulative"]
    assert score["goal"]["present"] is True and score["goal"]["inapplicable"] is False
    for field in ("war_score_sources", "war_goal_controller", "duration"):
        assert item["fields"][field] == {"status": "unknown", "reason": "WAR_SCORE_FIELD_UNIMPLEMENTED"}
    assert item["complete"] is False and result["complete"] is False
    return {"score": score, "cumulative": goal}


def check_raw(values, events, war_id, session_id, date, *, multiple=False):
    scores = [event for event in events if event["event"] == "native_live_war_score_inspection"]
    parents = [event for event in events if event["event"] == "native_peace_empty_offer_inspection"]
    assert not any(event["event"] in {"native_live_war_score_inspection_failed", "native_live_war_score_query_failed"} for event in events)
    assert len(scores) == len(parents) and (len(scores) >= 1 if multiple else len(scores) == 1)
    parent_ids = {event["query_id"]: event for event in parents}
    assert len(parent_ids) == len(parents) == len({event["query_id"] for event in scores})
    for raw in scores:
        parent = parent_ids[raw["query_id"]]
        assert (raw["war_id"], raw["session_id"], raw["date_raw"], raw["actor"], raw["recipient"]) == (
            war_id, session_id, date, "FRA", "BUR")
        assert parent["submitted"] is False and parent["object_unchanged"] is True
        assert raw["war_context"]["war_id"] == war_id and raw["verification"]["verified"] is True
        score = raw["score"]
        assert values["score"]["total"]["raw"] == score["total_raw"]
        assert values["score"]["total"]["value"] == score["total_raw"] / score["total_scale"]
        assert values["cumulative"]["raw"] == score["goal"]["cumulative_raw"]
        assert values["cumulative"]["value"] == score["goal"]["cumulative_raw"] / score["goal"]["cumulative_scale"]
        for key in ("presence", "present", "inapplicable"):
            assert values["score"]["goal"][key] == score["goal"][key]
    return [raw["query_id"] for raw in scores] if multiple else scores[0]["query_id"]


def run(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    installation = args.installation.resolve(strict=True)
    identity = read(installation)
    assert (identity["pid"], identity["creation_filetime"], identity["game_sha256"], identity["dll_sha256"]) == (
        args.pid, args.creation_filetime, GAME_SHA, DLL_SHA)
    namespace = "war-score66-" + hashlib.sha256(str(output).encode()).hexdigest()[:16]
    log = installation.parent / "control-probe.jsonl"
    offset = log.stat().st_size
    client = subscription = None
    cancel_started = False
    report = {"schema": "information.war_score.live.v1", "status": "running", "checks": {},
              "installation": pin(installation), "identity": identity, "date_raw": args.expected_date,
              "business_dispatch": False, "advance_save_restart_install": False, "computer_use": False,
              "native_read_only_queries": True, "manual_tick_sent": False,
              "limitations": ["One actual FRA/BUR whole-war actor perspective; other conditions use offline tests.",
                              "Daily score, source breakdown, goal controller and duration remain unavailable.",
                              "Durable delivery does not prove LLM read."]}

    def call(label, name, **arguments):
        schema = next(tool["inputSchema"] for tool in TOOL_DEFINITIONS if tool["name"] == name)
        validate_schema(arguments, schema, "arguments")
        put(output / f"{label}-request.json", {"name": name, "arguments": arguments})
        phase_offset = log.stat().st_size
        response = client.call(name, **arguments)
        put(output / f"{label}-response.json", response)
        put(output / f"{label}-native-events.json", events_since(log, phase_offset))
        return response

    try:
        before = control_snapshot(args.pid, output / "before-control.json")
        assert tuple(before[key] for key in ("player_slot", "date_raw", "speed", "paused_flag")) == (189, args.expected_date, 0, 1)
        session = ObserverSession(installation, game_exe())
        health = session.health()
        put(output / "before-health.json", health)
        assert health["status"] == "ready" and health["date_raw"] == args.expected_date
        assert "native_live_war_score_query" in session.installation_capabilities()
        client = _ImmediateClient(installation, output, tick=1)
        discovery = call("01-discover", "information_discover")
        topic = next(t for t in discovery["topics"] if t["topic_id"] == "W02")
        assert "peace_context" in topic["parameters"]["properties"]
        assert "selection" not in topic["parameters"]["properties"]
        war = call("02-current-war", "information_query", request_id=namespace + "-war", queries=[{
            "topic": "W01", "object": {"type": "country_pair", "actor": "FRA", "recipient": "BUR"},
            "fields": ["war_id"], "parameters": {}}])
        war_id = war["items"][0]["fields"]["war_id"]["value"]
        report["war_id"] = war_id
        assert war["items"][0]["source"]["provenance"]["enumeration_complete"] is True
        query = {"topic": "W02", "object": {"type": "war", "war_id": war_id, "actor": "FRA", "recipient": "BUR"},
                 "fields": list(topic["fields"]), "parameters": {}}
        value = call("03-score-query", "information_query", request_id=namespace + "-score", queries=[query])
        expected = check_values(value, war_id)
        query_id = check_raw(expected, read(output / "03-score-query-native-events.json"), war_id,
                             identity["session_id"], args.expected_date)
        report["checks"]["query_matches_bound_native_raw"] = True
        report["checks"]["other_fields_remain_unknown"] = True
        configured = call("04-report", "information_manage_report", request_id=namespace + "-report", operation="create",
                          config={"name": "war-score66-report", "queries": [query], "detail": "raw"})
        periodic_offset = log.stat().st_size
        created = call("05-subscribe", "information_manage_subscription", request_id=namespace + "-subscribe", operation="create",
                       config={"name": "war-score66-periodic", "kind": "periodic", "report_id": configured["report"]["id"],
                               "enabled": True, "schedule": {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"}})
        subscription = created["subscription"]
        periodic = None
        for index in range(12):
            time.sleep(0.5)
            listed = call(f"06-results-{index:02}", "information_list_results", limit=50)
            periodic = next((r for r in listed["results"] if r.get("subscription_id") == subscription["id"]), None)
            if periodic:
                break
        assert periodic is not None
        put(output / "periodic-result.json", periodic)
        assert check_values(periodic, war_id) == expected
        periodic_events = events_since(log, periodic_offset)
        put(output / "periodic-native-events.json", periodic_events)
        periodic_ids = check_raw(expected, periodic_events, war_id, identity["session_id"], args.expected_date, multiple=True)
        assert query_id not in periodic_ids
        report["checks"]["fresh_scheduler_native_query_matches_active_query"] = True
        report["native_query_ids"] = {"active": query_id, "periodic": periodic_ids}
        cancel_started = True
        cancelled = call("07-cancel", "information_manage_subscription", request_id=namespace + "-cancel", operation="cancel",
                         subscription_id=subscription["id"], expected_version=subscription["version"])
        subscription = cancelled["subscription"]
        assert subscription["state"] == "cancelled"
        states = call("08-subscriptions", "information_manage_subscription", request_id=namespace + "-subscriptions", operation="list")
        assert all(s["state"] != "active" for s in states["subscriptions"])
        report["checks"]["cancelled_no_active_subscriptions"] = True
        report["values"] = expected
        report["status"] = "passed"
    except Exception as error:
        report.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
    finally:
        if client is not None:
            if subscription is not None and subscription.get("state") == "active" and not cancel_started:
                try:
                    cancel_started = True
                    call("cleanup-cancel", "information_manage_subscription", request_id=namespace + "-cleanup-cancel", operation="cancel",
                         subscription_id=subscription["id"], expected_version=subscription["version"])
                except Exception as error:
                    report["cleanup_error"] = str(error)
            try:
                client.close()
            except Exception as error:
                report.update(status="failed", close_error=str(error))
            report["server_exit_code"] = client.process.returncode
            if client.process.returncode != 0:
                report["status"] = "failed"
        put(output / "native-events.json", events_since(log, offset))
        after = control_snapshot(args.pid, output / "after-control.json")
        stable = tuple(after[key] for key in ("player_slot", "date_raw", "speed", "paused_flag")) == (189, args.expected_date, 0, 1)
        report["checks"]["paused_world_preserved"] = stable
        if not stable:
            report["status"] = "failed"
        put(output / "report.json", report)
    print(json.dumps({key: report.get(key) for key in ("status", "checks", "error", "server_exit_code", "war_id")}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--creation-filetime", type=int, required=True)
    parser.add_argument("--expected-date", type=int, required=True)
    parser.add_argument("--test-only", action="store_true", required=True)
    raise SystemExit(run(parser.parse_args()))
