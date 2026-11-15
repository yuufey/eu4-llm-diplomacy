"""Validate information MCP queries and scheduling in one paused test game.

Only information tools and read-only control probes are used. This runner
never installs a DLL, advances time, saves, submits diplomacy, or creates a
proposal. A failed acceptance directory is retained and is never overwritten.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.diplomacy import ObserverSession
from work.local_config import game_exe
from work.run_alliance_inbound_response import control_snapshot


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


class Client:
    def __init__(self, installation, output, *, suffix="", tick=0.25, extra_args=()):
        self.messages = queue.Queue()
        self.identifier = 0
        self.transcript = []
        self.stderr = (output / ("mcp-stderr" + suffix + ".txt")).open("w", encoding="utf-8")
        self.path = output / ("mcp-transcript" + suffix + ".json")
        self.process = subprocess.Popen(
            [sys.executable, "tools/serve_information.py", "--operator-session", str(installation),
             "--observer", "FRA", "--database", str(output / "information.sqlite3"),
             "--journal", str(output / "diplomacy.sqlite3"), "--tick-seconds", str(tick), *extra_args],
            cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr,
            text=True, encoding="utf-8", bufsize=1)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        self.rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                                "clientInfo": {"name": "paused-live-acceptance", "version": "1"}})
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _read(self):
        for line in self.process.stdout:
            try:
                self.messages.put(json.loads(line))
            except ValueError:
                self.messages.put({"invalid_json": line})
        self.messages.put({"eof": True})

    def send(self, value):
        self.transcript.append({"direction": "request", "at": time.time(), "body": value})
        self.process.stdin.write(json.dumps(value, ensure_ascii=False) + "\n")
        self.process.stdin.flush()

    def rpc(self, method, params):
        self.identifier += 1
        self.send({"jsonrpc": "2.0", "id": self.identifier, "method": method, "params": params})
        response = self.messages.get(timeout=45)
        self.transcript.append({"direction": "response", "at": time.time(), "body": response})
        assert response.get("id") == self.identifier and "error" not in response, response
        return response["result"]

    def call(self, name, **arguments):
        result = self.rpc("tools/call", {"name": name, "arguments": arguments})
        assert result.get("isError") is not True, result
        value = json.loads(result["content"][0]["text"])
        assert "error" not in value, value
        return value

    def close(self):
        try:
            self.process.stdin.close()
            self.process.wait(timeout=45)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=10)
            raise
        finally:
            self.reader.join(timeout=2)
            self.stderr.close()
            write(self.path, self.transcript)
        assert self.process.returncode == 0, self.process.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    installation = args.installation.resolve(strict=True)
    session = ObserverSession(installation, game_exe())
    pid = int(session.record["pid"])
    report = {"status": "failed", "mode": "live", "session_id": session.session_id,
              "pid": pid, "game_sha256": session.record["game_sha256"],
              "dll_sha256": session.record["dll_sha256"], "installation_sha256": sha(installation),
              "scope": "paused_read_only_queries_and_real_time_scheduling", "checks": {},
              "limitations": ["No positive live state change or new event was manufactured",
                              "No game-day advancement, diplomacy, save or installation is performed",
                              "Only the explicitly requested fields are accepted, not all 74 topics"]}
    client = None
    acceptance_start = time.monotonic()
    try:
        before = control_snapshot(pid, args.output / "before-control.json")
        write(args.output / "before-health.json", session.health())
        assert session.health()["status"] == "ready", "Native source not ready"
        assert before["player_slot"] == 189 and before["paused_flag"] == 1, before
        context = {"topic": "C01", "object": {"type": "session"},
                   "fields": ["session_id", "observer", "game_version", "game_day"]}
        queries = [context] + [{"topic": topic, "object": {"type": "country", "country": "FRA"},
                                "fields": [field], "parameters": {"reference_recipient": "PAP"}}
                               for topic, field in (("N01", "treasury"), ("N02", "manpower"),
                                                    ("N05", "diplomats_available"))]
        client = Client(installation, args.output)
        definitions = client.rpc("tools/list", {})
        assert len(definitions["tools"]) == 9, definitions
        manual = client.call("information_query", request_id="live-manual", queries=queries)
        write(args.output / "manual-result.json", manual)
        assert manual["complete"] is True and manual["context"]["mode"] == "live", manual
        assert manual["context"]["observer"] == "FRA", manual
        assert manual["context"]["session_id"] == session.session_id, manual
        assert manual["context"]["game_date"] == before["date_raw"], manual
        report["checks"]["mcp_discovery_and_country_query"] = True
        report["values"] = {item["topic"]: item["fields"] for item in manual["items"]}
        repeated = client.call("information_query", request_id="live-manual", queries=queries)
        assert repeated["result_id"] == manual["result_id"], repeated
        report["checks"]["idempotent_query"] = True
        configuration = {"name": "paused-live-treasury", "detail": "raw", "queries": queries[:2]}
        saved = client.call("information_manage_report", request_id="live-report", operation="create",
                            config=configuration)["report"]

        def subscription(name, every, *, basis="real", kind="periodic"):
            return client.call("information_manage_subscription", request_id="live-create-" + name,
                               operation="create", config={"name": name, "kind": kind,
                               "report_id": saved["id"], "enabled": True,
                               "schedule": {"basis": basis, "every": every,
                                            "unit": "seconds" if basis == "real" else "days",
                                            "missed": "coalesce"}})["subscription"]

        short, long = subscription("short", 2), subscription("long", 5)
        game = subscription("game", 1, basis="game")
        change = subscription("change", 2, kind="change")
        start = time.monotonic()
        while time.monotonic() - start < 7:
            time.sleep(0.25)
        first = client.call("information_list_results", limit=100)["results"]
        write(args.output / "periodic-results.json", first)
        counts = Counter(item.get("subscription_id") for item in first)
        assert counts[short["id"]] >= 2 and counts[long["id"]] >= 1, dict(counts)
        assert not counts[game["id"]] and not counts[change["id"]], dict(counts)
        for item in first:
            assert item["complete"] is True and item["delivery"]["status"] == "delivered", item
            assert item["context"]["game_date"] == before["date_raw"], item
            assert item["items"][1]["fields"] == manual["items"][1]["fields"], item
        report["checks"]["independent_real_periods_same_source"] = True
        report["checks"]["paused_game_clock_does_not_fire"] = True
        status = client.call("information_status")
        write(args.output / "before-update-status.json", status)
        runtime = next(row["runtime"] for row in status["subscriptions"] if row["subscription"]["id"] == change["id"])
        assert runtime["last_attempt"]["status"] == "unchanged", runtime
        report["checks"]["unchanged_polling_no_false_change"] = True
        updated_config = {key: short[key] for key in ("name", "kind", "report_id", "binding", "schedule")}
        updated_config["enabled"] = True
        updated_config["schedule"] = dict(updated_config["schedule"], every=4)
        updated = client.call("information_manage_subscription", request_id="live-update-short", operation="update",
                              subscription_id=short["id"], expected_version=short["version"],
                              config=updated_config)["subscription"]
        assert updated["version"] == short["version"] + 1 and updated["schedule"]["every"] == 4
        paused = client.call("information_manage_subscription", request_id="live-pause-short", operation="pause",
                             subscription_id=short["id"], expected_version=updated["version"])["subscription"]
        checkpoint = {item["result_id"] for item in client.call("information_list_results", limit=100)["results"]}
        start = time.monotonic()
        while time.monotonic() - start < 5.5:
            time.sleep(0.25)
        later = client.call("information_list_results", limit=100)["results"]
        additions = [item for item in later if item["result_id"] not in checkpoint]
        assert any(item["subscription_id"] == long["id"] for item in additions), additions
        assert not any(item["subscription_id"] == short["id"] for item in additions), additions
        current = client.call("information_manage_subscription", request_id="live-get-long", operation="get",
                              subscription_id=long["id"])["subscription"]
        assert current["schedule"] == long["schedule"] and current["version"] == long["version"], current
        report["checks"]["update_and_pause_preserve_other_task"] = True
        cancelled = client.call("information_manage_subscription", request_id="live-cancel-short", operation="cancel",
                                subscription_id=short["id"], expected_version=paused["version"])["subscription"]
        assert cancelled["state"] == "cancelled", cancelled
        write(args.output / "final-status.json", client.call("information_status"))
        client.close()
        client = None
        client = Client(installation, args.output, suffix="-restarted", tick=0)
        restart = client.call("information_status")
        write(args.output / "restarted-status.json", restart)
        restored = next(row for row in restart["subscriptions"] if row["subscription"]["id"] == long["id"])
        assert restored["runtime"]["needs_rebind"] is True, restored
        assert restored["subscription"]["schedule"] == long["schedule"], restored
        report["checks"]["restart_restores_and_requires_world_revalidation"] = True
        client.close()
        client = None
        after = control_snapshot(pid, args.output / "after-control.json")
        write(args.output / "after-health.json", session.health())
        assert (after["player_slot"], after["paused_flag"], after["date_raw"]) == (189, 1, before["date_raw"]), after
        report["checks"]["player_pause_date_preserved"] = True
        report["counts_before_update"] = dict(counts)
        report["elapsed_real_seconds"] = time.monotonic() - acceptance_start
        report["status"] = "passed"
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        if client is not None:
            client.close()
        write(args.output / "report.json", report)
    print(json.dumps(report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
