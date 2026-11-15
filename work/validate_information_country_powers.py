"""Accept native powers through real information MCP and paused scheduling."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.run_alliance_inbound_response import control_snapshot
from work.validate_information_live import Client, sha, write


def require(value, reason):
    if not value:
        raise ValueError(reason)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    require(args.reference.stat().st_size < 1024 * 1024, "Reference too large")
    reference = json.loads(args.reference.read_text("utf-8"))
    require(reference["status"] == "passed", "Reference failed")
    report = {"status": "failed", "points_reader_pure_RPM": True,
              "mixed_prestige_query_invokes_readonly_native_predicates": True,
              "business_actions_submitted": False, "checks": {}}
    client = None
    try:
        before = control_snapshot(37376, args.output / "before-control.json")
        require((before["player_slot"], before["paused_flag"], before["date_raw"])
                == (189, 1, reference["date_raw"]), "Controls differ")
        client = Client(args.installation, args.output, extra_args=["--static-game-data", "--mission-game-data"])
        discovery = client.call("information_discover")
        write(args.output / "discovery.json", discovery)
        topics = {topic["topic_id"]: topic for topic in discovery["topics"]}
        meta = topics["N06"]["fields"]["monarch_points"]
        require(meta["coverage"] == "available" and meta["unit"] == "monarch_points"
                and meta["scale"] == 1, "Point metadata differs")
        require(meta["supported_countries"] == ["FRA"], "Point country boundary missing")
        query = {"topic": "N06", "object": {"type": "country", "country": "FRA"},
                 "fields": ["monarch_points"], "parameters": {}}

        def check(result):
            require(result["status"] == "complete" and result["complete"] is True, "Points incomplete")
            require(result["context"]["session_id"] == reference["session_id"], "Session differs")
            require(result["context"]["game_date"] == reference["date_raw"], "Date differs")
            item = result["items"][0]
            field = item["fields"]["monarch_points"]
            require(field["status"] == "known" and field["value"] == reference["values"], "Values differ")
            require(field["unit"] == "monarch_points" and field["scale"] == 1, "Unit differs")
            require(item["source"]["provenance"]["native_function_invoked"] is False, "Point reader called game")
            require(len(json.dumps(item, ensure_ascii=False).encode("utf-8")) < 64 * 1024, "Point result exceeds audit budget")

        manual = client.call("information_query", request_id="country-powers-manual", queries=[query])
        write(args.output / "manual-result.json", manual)
        check(manual)
        report["checks"]["points_only_empty_parameters_matches_independent_RPM"] = True
        mixed_query = dict(query, fields=["monarch_points", "prestige"],
                           parameters={"reference_recipient": "PAP"})
        mixed = client.call("information_query", request_id="country-powers-mixed", queries=[mixed_query])
        write(args.output / "mixed-result.json", mixed)
        require(mixed["status"] == "complete", "Mixed N06 incomplete")
        require(mixed["items"][0]["fields"]["monarch_points"]["value"] == reference["values"], "Mixed points differ")
        require(mixed["items"][0]["fields"]["prestige"]["value"] == -11643, "Mixed prestige differs")
        report["checks"]["mixed_prestige_and_points_keep_units"] = True
        partial_query = dict(query, fields=["monarch_points", "diplomatic_reputation"])
        partial = client.call("information_query", request_id="country-powers-partial", queries=[partial_query])
        write(args.output / "partial-result.json", partial)
        require(partial["status"] == "partial" and partial["complete"] is False, "Unsupported field hidden")
        require(partial["items"][0]["fields"]["monarch_points"]["value"] == reference["values"], "Partial lost points")
        require(partial["items"][0]["fields"]["diplomatic_reputation"]["status"] == "unsupported", "Reputation filled")
        report["checks"]["unsupported_field_preserves_points"] = True
        saved = client.call("information_manage_report", request_id="country-powers-report", operation="create",
                            config={"name": "native-country-powers", "queries": [query], "detail": "raw"})["report"]
        sub = client.call("information_manage_subscription", request_id="country-powers-periodic", operation="create",
                          config={"name": "powers-two-seconds", "kind": "periodic", "report_id": saved["id"], "enabled": True,
                                  "schedule": {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"}})["subscription"]
        deadline = time.monotonic() + 7
        while time.monotonic() < deadline:
            time.sleep(0.25)
        results = [r for r in client.call("information_list_results", limit=50)["results"]
                   if r.get("subscription_id") == sub["id"]]
        write(args.output / "periodic-results.json", results)
        require(len(results) >= 2, "Too few periodic samples")
        for result in results:
            check(result)
            require(result["delivery"]["status"] == "delivered", "Undelivered sample")
        client.call("information_manage_subscription", request_id="country-powers-cancel", operation="cancel",
                    subscription_id=sub["id"], expected_version=sub["version"])
        report["checks"]["periodic_samples_delivered_and_cancelled"] = True
        client.close()
        client = None
        after = control_snapshot(37376, args.output / "after-control.json")
        require(before == after, "Controls changed")
        report["checks"]["pause_player_date_preserved"] = True
        report.update(status="passed", session_id=reference["session_id"], values=reference["values"],
                      periodic_results=len(results), native_reference_sha256=sha(args.reference),
                      source_sha256=sha(Path(__file__)),
                      source_files={name: sha(ROOT / name) for name in (
                          "bridge/information/country_state.py",
                          "bridge/information/country_resources_memory.py",
                          "tools/serve_information.py")},
                      configured_field_counts=dict(Counter(f["coverage"] for t in discovery["topics"]
                                                          for f in t["fields"].values())))
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        if client is not None:
            client.close()
        write(args.output / "report.json", report)
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
