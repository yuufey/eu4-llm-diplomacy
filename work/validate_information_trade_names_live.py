"""Exercise current trade-node names through the existing MCP client.

Expected text comes from a separately captured native cache, decoded before
the public server starts. No game functions or business actions are called.
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
from work.validate_information_live import Client


def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def query(node_id, fields=("node_id", "name")):
    return {"topic": "T01", "object": {"type": "trade_node", "node_id": node_id},
            "fields": list(fields)}


def run(installation, reference, output):
    output.mkdir(parents=True, exist_ok=False)
    raw = reference.read_bytes()
    expected = json.loads(raw)
    names = expected["names"]
    assert expected["basis"] == "independent_raw_cache_bytes_decoded_without_public_normalizer"
    assert len(names) == 80
    binding = json.loads(installation.read_text(encoding="utf-8-sig"))
    assert expected["session_id"] == binding["session_id"]
    before = control_snapshot(int(binding["pid"]), output / "before-control.json")
    assert (before["player_slot"], before["paused_flag"], before["speed"]) == (189, 1, 0)
    assert before["date_raw"] == expected["game_date"]
    report = {"schema": "information_trade_name_live_acceptance.v1", "status": "running",
              "reference": str(reference), "reference_sha256": hashlib.sha256(raw).hexdigest(),
              "session_id": binding["session_id"], "game_date": expected["game_date"],
              "checks": {}, "public_node_count": 0, "periodic_results": {},
              "game_functions_called": False, "business_dispatched": False}
    client, subscriptions = None, {}
    try:
        client = Client(installation.resolve(), output, extra_args=["--static-game-data"])
        discovery = client.call("information_discover")
        write(output / "discovery.json", discovery)

        def check(result, node_ids):
            assert result["complete"] is True and result["status"] == "complete"
            assert result["delivery"]["status"] == "delivered"
            assert result["context"]["session_id"] == expected["session_id"]
            assert result["context"]["game_date"] == expected["game_date"]
            assert len(result["items"]) == len(node_ids)
            for item, node_id in zip(result["items"], node_ids):
                assert item["fields"]["node_id"] == {"status": "known", "value": node_id}
                assert item["fields"]["name"] == {"status": "known", "value": names[node_id]}
                assert item["complete"] is True
                source = item["source"]
                assert source["definitions_sha256"]
                localized = source["name_localization"]
                assert localized["key"] == node_id
                assert localized["language"] == expected["language"]
                assert localized["codec"] == expected["codec"]
                assert localized["raw_template_hex"]

        keys = sorted(names)
        results = []
        for offset in range(0, len(keys), 16):
            selected = keys[offset:offset + 16]
            result = client.call("information_query", request_id=f"trade-names-all-{offset:03d}-001",
                                 queries=[query(key) for key in selected])
            write(output / f"all-names-{offset:03d}.json", result)
            check(result, selected)
            results.append(result)
        report["public_node_count"] = sum(len(result["items"]) for result in results)
        report["checks"]["all_eighty_public_names_match_independent_bytes"] = True

        mixed = client.call("information_query", request_id="trade-names-topology-001", queries=[
            query("english_channel", ("node_id", "name", "provinces", "upstream", "downstream", "routes"))])
        write(output / "mixed-topology-query.json", mixed)
        check(mixed, ["english_channel"])
        assert mixed["items"][0]["fields"]["provinces"]["value"]
        report["checks"]["name_and_existing_topology_complete"] = True

        missing = client.call("information_query", request_id="trade-names-missing-001", queries=[
            query("not_a_real_trade_node")])
        write(output / "unknown-node-query.json", missing)
        assert missing["complete"] is False
        assert all(value["status"] == "unknown" and value["reason"] == "NODE_NOT_FOUND"
                   for value in missing["items"][0]["fields"].values())
        report["checks"]["unknown_node_preserved"] = True

        selected = ["english_channel", "sevilla", "constantinople"]
        saved = client.call("information_manage_report", request_id="trade-names-report-001", operation="create",
                            config={"name": "贸易节点名称", "queries": [query(key) for key in selected], "detail": "raw"})
        write(output / "report-config.json", saved)
        active = client.call("information_query", request_id="trade-names-report-query-001",
                             report_id=saved["report"]["id"])
        write(output / "report-query.json", active)
        check(active, selected)
        report["checks"]["saved_report_query_complete"] = True
        for every in (2, 3):
            created = client.call("information_manage_subscription", request_id=f"trade-names-periodic-{every}-001",
                                  operation="create", config={"name": f"trade-names-{every}s", "kind": "periodic",
                                  "report_id": saved["report"]["id"], "enabled": True,
                                  "schedule": {"basis": "real", "every": every, "unit": "seconds", "missed": "coalesce"}})
            sub = created["subscription"]
            subscriptions[sub["id"]] = sub
        write(output / "subscription-configs.json", list(subscriptions.values()))
        periodic = {sub_id: {} for sub_id in subscriptions}
        deadline = time.monotonic() + 35
        while any(len(values) < 2 for values in periodic.values()) and time.monotonic() < deadline:
            listed = client.call("information_list_results", limit=50)
            for result in listed.get("results", []):
                sub_id = result.get("subscription_id")
                if sub_id in periodic:
                    check(result, selected)
                    periodic[sub_id][result["result_id"]] = result
            if any(len(values) < 2 for values in periodic.values()):
                time.sleep(0.2)
        write(output / "periodic-results.json", {key: list(values.values()) for key, values in periodic.items()})
        assert all(len(values) >= 2 for values in periodic.values())
        report["periodic_results"] = {key: len(values) for key, values in periodic.items()}
        report["checks"]["two_frequencies_delivered_while_paused"] = True
        cancelled = []
        for sub_id, sub in subscriptions.copy().items():
            response = client.call("information_manage_subscription", request_id=f"trade-names-cancel-{sub_id}",
                                   operation="cancel", subscription_id=sub_id, expected_version=sub["version"])
            subscriptions[sub_id] = response["subscription"]
            assert subscriptions[sub_id]["state"] == "cancelled"
            cancelled.append(response)
        write(output / "cancelled-subscriptions.json", cancelled)
        report["checks"]["both_subscriptions_cancelled"] = True
        report["status"] = "passed"
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        if client is not None:
            try:
                for sub_id, sub in subscriptions.items():
                    if sub.get("state") != "cancelled":
                        client.call("information_manage_subscription", request_id=f"trade-names-cleanup-{sub_id}",
                                    operation="cancel", subscription_id=sub_id, expected_version=sub["version"])
            except Exception as exc:
                report.update(status="failed", cleanup_error={"type": type(exc).__name__, "message": str(exc)})
            finally:
                client.close()
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
