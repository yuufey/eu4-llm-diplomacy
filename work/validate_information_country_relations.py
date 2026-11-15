"""Verify prestige and selected-pair subject information through real MCP."""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.validate_information_live import Client
from work.run_alliance_inbound_response import control_snapshot


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    require(args.reference.stat().st_size <= 1024 * 1024, "Reference exceeds budget")
    reference = json.loads(args.reference.read_text(encoding="utf-8"))
    require(reference["status"] == "passed", "Reference failed")
    report = {"status": "failed", "read_only_native_query": True, "pure_RPM": False,
              "business_actions_submitted": False, "checks": {}}
    client = None
    try:
        before = control_snapshot(37376, args.output / "before-control.json")
        require((before["player_slot"], before["paused_flag"], before["date_raw"]) == (189, 1, 56553384), "Controls changed")
        client = Client(args.installation, args.output, extra_args=["--static-game-data", "--mission-game-data"])
        discovery = client.call("information_discover")
        write(args.output / "discovery.json", discovery)
        topics = {item["topic_id"]: item for item in discovery["topics"]}
        require(topics["N06"]["fields"]["prestige"]["scale"] == 1000, "Prestige scale missing")
        require(topics["R02"]["status"] == "available", "Subject route unavailable")
        prestige_query = {"topic": "N06", "object": {"type": "country", "country": "FRA"},
                          "fields": ["prestige"], "parameters": {"reference_recipient": "PAP"}}
        relation_queries = [{"topic": "R02", "object": {"type": "country_pair", "actor": "FRA", "recipient": tag},
                             "fields": ["overlord", "subject", "subject_type"], "parameters": {}}
                            for tag in ("ORL", "PAP")]
        queries = [prestige_query, *relation_queries]

        def check(result):
            require(result["complete"] is True and result["status"] == "complete", "Selected fields incomplete")
            require(result["context"]["session_id"] == reference["session_id"], "Session mismatch")
            require(result["context"]["game_date"] == before["date_raw"], "Date mismatch")
            items = result["items"]
            value = items[0]["fields"]["prestige"]
            expected = reference["captures"]["PAP"]["public"]["prestige_raw"]
            require((value["status"], value["value"], value["unit"], value["scale"])
                    == ("known", expected, "prestige", 1000), "Prestige projection mismatch")
            for item in items[1:]:
                tag = item["query"]["object"]["recipient"]
                raw = reference["captures"][tag]["public"]
                if raw["vassal_active"]:
                    expected = {"overlord": "FRA" if raw["actor_is_overlord"] else tag,
                                "subject": tag if raw["actor_is_overlord"] else "FRA",
                                "subject_type": raw["subject_type"]}
                    require(all(item["fields"][k]["status"] == "known" and item["fields"][k]["value"] == v
                                for k, v in expected.items()), "Selected relation differs")
                else:
                    require(all(v["status"] == "not_applicable" and "value" not in v for v in item["fields"].values()),
                            "Inactive pair was not explicitly not applicable")
                require(item["source"]["provenance"]["global_relation_claim"] is False, "Unexpected global relation claim")

        manual = client.call("information_query", request_id="country-relations-manual", queries=queries)
        write(args.output / "manual-result.json", manual)
        check(manual)
        report["checks"]["active_matches_independent_native_public_capture"] = True
        partial_query = dict(relation_queries[0], fields=["overlord", "subject", "subject_type", "permissions"])
        partial = client.call("information_query", request_id="country-relations-partial", queries=[partial_query])
        write(args.output / "partial-result.json", partial)
        require(partial["status"] == "partial" and partial["complete"] is False, "Missing field was hidden")
        require(partial["items"][0]["fields"]["overlord"]["value"] == "FRA", "Known endpoints lost")
        require(partial["items"][0]["fields"]["permissions"]["status"] == "unsupported", "Unimplemented field filled")
        report["checks"]["mixed_unimplemented_fields_preserve_known_endpoints"] = True
        saved = client.call("information_manage_report", request_id="country-relations-report", operation="create",
            config={"name": "prestige-and-selected-subjects", "queries": queries, "detail": "raw"})["report"]
        sub = client.call("information_manage_subscription", request_id="country-relations-periodic", operation="create",
            config={"name": "country-relations-two-seconds", "kind": "periodic", "report_id": saved["id"], "enabled": True,
                    "schedule": {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"}})["subscription"]
        deadline = time.monotonic() + 7
        while time.monotonic() < deadline:
            time.sleep(0.25)
        results = [r for r in client.call("information_list_results", limit=50)["results"] if r.get("subscription_id") == sub["id"]]
        write(args.output / "periodic-results.json", results)
        require(len(results) >= 2, "Too few periodic results")
        for result in results:
            check(result)
            require(result["delivery"]["status"] == "delivered", "Result not delivered")
        client.call("information_manage_subscription", request_id="country-relations-cancel", operation="cancel",
                    subscription_id=sub["id"], expected_version=sub["version"])
        report["checks"]["periodic_same_fields_delivered"] = True
        client.close()
        client = None
        after = control_snapshot(37376, args.output / "after-control.json")
        require(before == after, "Controls changed")
        report["checks"]["pause_player_date_preserved"] = True
        report.update(status="passed", session_id=reference["session_id"], periodic_results=len(results),
            prestige_raw=manual["items"][0]["fields"]["prestige"]["value"], prestige_scale=1000,
            relation_pairs=["FRA/ORL", "FRA/PAP"], native_reference_sha256=hashlib.sha256(args.reference.read_bytes()).hexdigest(),
            configured_field_counts=dict(Counter(f["coverage"] for t in discovery["topics"] for f in t["fields"].values())))
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        if client is not None:
            client.close()
        write(args.output / "report.json", report)
    print(json.dumps(report))


if __name__ == "__main__":
    main()
