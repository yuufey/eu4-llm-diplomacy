from contextlib import closing
import json
import os
from pathlib import Path
import subprocess
import sys

from bridge.game_tools import GameTools
from bridge.information.decision_desktop import enqueue_desktop_brief
from bridge.information.decision_mcp import decision_mcp
from bridge.information.decision_queue import DecisionQueue
from bridge.information.service import InformationService
from bridge.tests.test_information_service import FakeSource, create_report


def test_only_latest_due_brief_starts_once_and_recovery_keeps_turn_identity(tmp_path):
    database = tmp_path / "information.sqlite3"
    source = FakeSource()
    binding = {key: source.context()[key] for key in ("session_id", "game_version", "observer")}
    with closing(InformationService(source, database, owner="test-owner")) as service:
        subscription = service.manage_subscription("periodic-create", "create", config={
            "report_id": create_report(service, detail="brief")["id"],
            "kind": "periodic", "binding": binding,
            "schedule": {"basis": "game", "every": 7, "unit": "days", "missed": "coalesce"},
        })["subscription"]
        sid = subscription["id"]
        queue = DecisionQueue(database, service.owner, binding, days=7, check_only=True)
        assert service.tick()["results"] == []
        assert queue.claim_latest(sid, source.context()) is None

        source.game_day += 7
        first = service.tick()["results"][0]["result_id"]
        source.game_day += 7
        second = service.tick()["results"][0]["result_id"]
        assert first != second
        assert queue.claim_latest(sid, dict(source.context(), world_id="reloaded")) is None
        assert queue.claim_latest(sid, source.context())["result_id"] == second
        queue.save_thread("thread-1")
        queue.mark(second, "running", "turn-1")

        reopened = DecisionQueue(database, service.owner, binding, days=7, check_only=True)
        assert reopened.thread() == "thread-1"
        assert reopened.unresolved() == (second, "turn-1", "running")
        assert reopened.claim_latest(sid, source.context()) is None
        reopened.mark(second, "completed")
        assert reopened.claim_latest(sid, source.context()) is None

        source.game_day += 7
        third = service.tick()["results"][0]["result_id"]
        service.manage_subscription("pause", "pause", subscription_id=sid, expected_version=1)
        assert reopened.claim_latest(sid, source.context()) is None
        assert service.get_result(third)["result_id"] == third


def test_stdio_relay_uses_resident_service_and_connection_close_keeps_it_alive(tmp_path):
    source = FakeSource()
    database = tmp_path / "information.sqlite3"
    relay = Path(__file__).resolve().parents[2] / "tools" / "relay_decision_mcp.py"
    messages = [
        {"id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"}}},
        {"method": "notifications/initialized"},
        {"id": 2, "method": "tools/call", "params": {
            "name": "information_discover", "arguments": {"view": "full"},
            "_meta": {"progressToken": 2}}},
    ]
    stdin = "".join(json.dumps(dict(message, jsonrpc="2.0")) + "\n" for message in messages)
    with closing(InformationService(source, database)) as service:
        with decision_mcp(service, GameTools(service)) as (port, env):
            process = subprocess.run([sys.executable, "-B", str(relay), str(port)], input=stdin,
                                     encoding="utf-8", capture_output=True,
                                     env={**os.environ, **env}, timeout=10, check=True)
        _, response = map(json.loads, process.stdout.splitlines())
        output = json.loads(response["result"]["content"][0]["text"])
        assert output["context"]["session_id"] == source.session_id
        assert service.tick()["state"] == "processed"


def test_desktop_submission_uses_target_uuid_and_retains_queue_warning(monkeypatch):
    target = "01a1fe88-e305-7fc2-8ac3-673bb643b74a"
    message = "01a1feb1-2393-7521-af47-b8d3081699be"
    brief = {"result_id": "brief-1", "items": [{"game_date": "1444.12.2"}]}

    def run(command, **kwargs):
        assert command[:5] == ["codex.exe", "queue", "--thread", target, "--message"]
        assert "\n" in command[5] and "brief-1" in command[5]
        assert command[-1] == "--resume"
        return subprocess.CompletedProcess(command, 0, f"Queued message {message} for thread {target}.",
                                           "Warning: active writer")

    monkeypatch.setattr(subprocess, "run", run)
    assert enqueue_desktop_brief("codex.exe", target, brief, check_only=True) == {
        "message_id": message, "thread_id": target, "warning": "Warning: active writer",
    }
