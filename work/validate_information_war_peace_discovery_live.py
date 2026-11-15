"""Once-only paused MCP verification of W01 and selected peace projections."""
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
from work.local_config import game_exe
from work.run_alliance_inbound_response import control_snapshot
from work.validate_information_peace_overextension_live import _ImmediateClient
from work.verify_information_battle_autonomous import put, pin, read

GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
DLL_SHA = "3d9e1fea9d8f34297a4a20646ea0b45d7d0f6a4af11cef6411586dd8b3264964"


def log_suffix(path, offset):
    length = path.stat().st_size - offset
    if not 0 <= length <= 2 * 1024 * 1024:
        raise ValueError("native_log_suffix_bound")
    with path.open("rb") as stream:
        stream.seek(offset)
        lines = stream.read(length).splitlines()
    rows = []
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("event", "").startswith("native_peace_"):
            rows.append(row)
    return rows


def check_preview(result):
    assert result["delivery"]["status"] == "delivered"
    assert len(result["items"]) == 3
    values = {item["topic"]: {key: value["value"] for key, value in item["fields"].items()
                            if value["status"] == "known"} for item in result["items"]}
    p04, p05, p03 = values["P04"], values["P05"], values["P03"]
    assert p04["consequences"]["source"] == "native_peace_consequences"
    assert p04["consequences"]["scope"] == "constructed_offer"
    assert p04["consequences"]["requested_terms_applied"] is True
    assert p04["territorial_changes"] == p04["consequences"]["territorial"]
    assert p05["coalition"] == p04["consequences"]["coalition"]
    assert type(p03["acceptance_complete"]) is bool
    return values


def check_raw_preview(values, events, war_id, session_id, date):
    events = [event for event in events if event.get("event") == "native_peace_province_offer_inspection"]
    assert len(events) == 3
    assert len({event["query_id"] for event in events}) == 3
    for event in events:
        assert (event["event"], event["action_id"], event["war_id"], event["session_id"], event["date_raw"]) == (
            "native_peace_province_offer_inspection", "cede_province", war_id, session_id, date)
        assert event["submitted"] is False and event["object_unchanged"] is True
    public = values["P04"]["consequences"]
    raw = events[0]["native_consequences"]
    assert public["complete"] == raw["complete"]
    assert public["diplomatic_power"] == raw["diplomatic_power"]
    for key in ("available", "maximum_raw", "scale", "text_readable", "text_truncated", "coalition_possible"):
        assert public["aggressive_expansion"][key] == raw["aggressive_expansion"][key]
    assert len(public["territorial"]) == len(raw["territorial"])
    for projected, original in zip(public["territorial"], raw["territorial"], strict=True):
        assert all(projected[key] == value for key, value in original.items() if key != "provinces")
        assert len(projected["provinces"]) == len(original["provinces"])
        for pp, rp in zip(projected["provinces"], original["provinces"], strict=True):
            assert all(pp[key] == value for key, value in rp.items())
    coalition = values["P05"]["coalition"]
    raw_coalition = events[1]["native_consequences"]["coalition"]
    assert all(coalition[key] == value for key, value in raw_coalition.items() if key != "countries")
    assert len(coalition["countries"]) == len(raw_coalition["countries"])
    for pc, rc in zip(coalition["countries"], raw_coalition["countries"], strict=True):
        assert all(pc[key] == value for key, value in rc.items())
    if events[2]["native_evaluation"]["factors_complete"] is False:
        assert values["P03"]["acceptance_complete"] is False


def run(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    installation = args.installation.resolve(strict=True)
    identity = read(installation)
    assert (identity["pid"], identity["creation_filetime"], identity["game_sha256"], identity["dll_sha256"]) == (
        args.pid, args.creation_filetime, GAME_SHA, DLL_SHA)
    namespace = "war-peace65-" + hashlib.sha256(str(output).encode()).hexdigest()[:16]
    report = {"status": "running", "schema": "information.war_peace.live.v1", "checks": {},
              "installation": pin(installation), "identity": identity, "game_date": args.expected_date,
              "business_dispatch": False, "advance_save_restart": False, "computer_use": False,
              "native_read_only_queries": True, "automatic_information_tick": False,
              "limitations": ["Only one actual FRA/BUR war; multi/empty/incomplete use explicit synthetic tests.",
                              "Selected offer consequences remain partial; no peace execution.",
                              "Durable delivery does not prove LLM read."]}
    if args.resume_evidence:
        previous = read(args.resume_evidence / "report.json")
        assert previous["identity"] == identity and previous["game_date"] == args.expected_date
        assert previous["server_exit_code"] == 0 and previous["checks"]["paused_world_preserved"] is True
        assert not (args.resume_evidence / "05-report-request.json").exists()
        report["reused_reads"] = []
    client = subscription = None
    cancelling = False
    log = installation.parent / "control-probe.jsonl"
    offset = log.stat().st_size

    def call(label, name, **arguments):
        if args.resume_evidence and label in {"01-discover", "02-pair-query", "03-selected-query", "04-preview-query"}:
            base = args.resume_evidence
            original = read(base / f"{label}-request.json")
            assert original["name"] == name
            assert {k: v for k, v in original["arguments"].items() if k != "request_id"} == {
                k: v for k, v in arguments.items() if k != "request_id"}
            put(output / f"{label}-reuse.json", {"original_request": pin(base / f"{label}-request.json"),
                "original_response": pin(base / f"{label}-response.json"), "native_query_repeated": False})
            value = read(base / f"{label}-response.json")
            put(output / f"{label}-response.json", value)
            put(output / f"{label}-native-events.json", read(base / f"{label}-native-events.json"))
            report["reused_reads"].append(label)
            return value
        put(output / f"{label}-request.json", {"name": name, "arguments": arguments})
        current_offset = log.stat().st_size
        value = client.call(name, **arguments)
        put(output / f"{label}-response.json", value)
        put(output / f"{label}-native-events.json", log_suffix(log, current_offset))
        return value

    try:
        before = control_snapshot(args.pid, output / "before-control.json")
        assert tuple(before[key] for key in ("player_slot", "date_raw", "speed", "paused_flag")) == (189, args.expected_date, 0, 1)
        session = ObserverSession(installation, game_exe())
        health = session.health()
        put(output / "before-health.json", health)
        assert health["status"] == "ready" and health["date_raw"] == args.expected_date
        extra = ["--database", str(args.service_database.resolve())] if args.service_database else []
        client = _ImmediateClient(installation, output, tick=1, extra_args=extra)
        discovery = call("01-discover", "information_discover")
        w01 = next(topic for topic in discovery["topics"] if topic["topic_id"] == "W01")
        assert w01["source"] == "ObserverSession.inspect_peace_contexts"
        assert set(w01["parameters"]["properties"]) == {"action_id", "phase", "war_id"}
        assert w01["object_requirements"]["war"]["required"] == ["actor", "recipient"]
        report["checks"]["war_discovery_contract_exposed"] = True
        pair_query = {"topic": "W01", "object": {"type": "country_pair", "actor": "FRA", "recipient": "BUR"},
                      "fields": list(w01["fields"]), "parameters": {}}
        pair = call("02-pair-query", "information_query", request_id=namespace + "-pair", queries=[pair_query])
        item = pair["items"][0]
        war_id = item["fields"]["war_id"]["value"]
        report["war_id"] = war_id
        assert item["source"]["provenance"]["enumeration_complete"] is True
        assert item["source"]["provenance"]["candidate_count"] == 1
        assert item["objects"] == [{"type": "war", "war_id": war_id, "actor": "FRA", "recipient": "BUR"}]
        assert all(value == {"status": "unknown", "reason": "WAR_CONTEXT_FIELD_UNVERIFIED"}
                   for key, value in item["fields"].items() if key != "war_id")
        assert pair["status"] == "partial" and pair["complete"] is False
        report["checks"]["war_id_known_other_war_fields_unverified"] = True
        selected_query = deepcopy(pair_query)
        selected_query.update(object=item["objects"][0], fields=["war_id"])
        selected = call("03-selected-query", "information_query", request_id=namespace + "-selected", queries=[selected_query])
        assert selected["complete"] is True and selected["items"][0]["fields"]["war_id"]["value"] == war_id
        report["checks"]["explicit_current_war_selected"] = True
        params = {"action_id": "cede_province", "phase": "initiate", "peace_context": {
            "war_id": war_id, "direction": "demand", "terms": [{"action_id": "cede_province", "beneficiary": "FRA", "province_ids": [88]}]}}
        queries = [{"topic": topic, "object": deepcopy(item["objects"][0]), "fields": fields,
                    "parameters": deepcopy(params)} for topic, fields in (
                        ("P04", ["consequences", "territorial_changes"]), ("P05", ["coalition"]), ("P03", ["acceptance_complete"]))]
        preview = call("04-preview-query", "information_query", request_id=namespace + "-preview", queries=queries)
        expected = check_preview(preview)
        report["checks"]["peace_public_paths_and_cross_topic_values"] = True
        check_raw_preview(expected, read(output / "04-preview-query-native-events.json"), war_id,
                          identity["session_id"], args.expected_date)
        report["checks"]["same_query_native_raw_values_and_flags_match"] = True
        if args.resume_report:
            assert args.service_database and args.service_database.resolve() == (args.resume_report.parent / "information.sqlite3").resolve()
            configured = read(args.resume_report)
            assert configured["report"]["queries"] == queries
            put(output / "05-report-reuse.json", {"original": pin(args.resume_report), "report_create_repeated": False})
        else:
            configured = call("05-report", "information_manage_report", request_id=namespace + "-report", operation="create",
                              config={"name": "war-peace65-preview", "queries": queries, "detail": "raw"})
        created = call("06-subscribe", "information_manage_subscription", request_id=namespace + "-subscribe", operation="create",
                       config={"name": "war-peace65-periodic", "kind": "periodic", "report_id": configured["report"]["id"], "enabled": True,
                               "schedule": {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"}})
        subscription = created["subscription"]
        periodic = None
        for index in range(10):
            time.sleep(0.6)
            listed = call(f"07-results-{index:02}", "information_list_results", limit=50)
            periodic = next((r for r in listed["results"] if r.get("subscription_id") == subscription["id"]), None)
            if periodic:
                break
        assert periodic is not None
        put(output / "periodic-result.json", periodic)
        assert check_preview(periodic) == expected
        report["checks"]["scheduler_periodic_matches_query"] = True
        cancelling = True
        cancelled = call("08-cancel", "information_manage_subscription", request_id=namespace + "-cancel", operation="cancel",
                         subscription_id=subscription["id"], expected_version=subscription["version"])
        subscription = cancelled["subscription"]
        assert subscription["state"] == "cancelled"
        states = call("09-subscriptions", "information_manage_subscription", request_id=namespace + "-list", operation="list")
        assert all(s["state"] != "active" for s in states["subscriptions"])
        report["checks"]["cancelled_no_active_subscriptions"] = True
        report["values"] = expected
        report["status"] = "passed"
    except Exception as error:
        report.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
    finally:
        if client is not None:
            if subscription is not None and subscription.get("state") == "active" and not cancelling:
                try:
                    cancelling = True
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
        events = log_suffix(log, offset)
        put(output / "native-events.json", events)
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
    parser.add_argument("--resume-evidence", type=Path,
                        help="Reuse successful reads from a closed failed checker; continue only the unrequested periodic validation")
    parser.add_argument("--resume-report", type=Path, help="Original successful report response; never create it again")
    parser.add_argument("--service-database", type=Path, help="Reopen the database containing that report")
    raise SystemExit(run(parser.parse_args()))
