"""Unified information and diplomacy tool registry contract tests."""
from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
import threading
import time
import unittest

import pytest

from bridge.game_tools import GameTools
from bridge.information.collection_lock import CollectionLock
from bridge.information.mcp import InformationMCPServer
from bridge.information.model import InformationError
from bridge.information.tools import TOOL_NAMES as INFORMATION_TOOL_NAMES
from bridge.tests.test_information_capture_runtime import _build_runtime, _live_args, wiring
from tools.serve_information import _run_jsonl


DIPLOMACY_TOOL_NAMES = (
    "list_diplomatic_actions",
    "inspect_diplomatic_action",
    "execute_diplomatic_action",
    "get_diplomatic_result",
)


class FakeDiplomacyTools:
    def __init__(self):
        self.calls = []
        self.results = {
            "list_diplomatic_actions": {"contract_version": 1, "actions": []},
            "inspect_diplomatic_action": {"inspection": "native-readable-result"},
            "execute_diplomatic_action": {
                "request_id": "conflict-1", "submitted": False, "status": "conflict",
                "reason": {"code": "REQUEST_ID_PAYLOAD_CONFLICT"},
            },
            "get_diplomatic_result": {
                "request_id": "missing-1", "submitted": False, "status": "unknown",
                "reason": {"code": "REQUEST_NOT_FOUND"},
            },
        }

    def _call(self, name, arguments):
        self.calls.append((name, arguments))
        return self.results[name]

    def list_diplomatic_actions(self, actor=None, recipient=None, category=None):
        return self._call("list_diplomatic_actions", {
            "actor": actor, "recipient": recipient, "category": category,
        })

    def inspect_diplomatic_action(self, action_id, actor, recipient,
                                  phase="initiate", parameters=None):
        return self._call("inspect_diplomatic_action", {
            "action_id": action_id, "actor": actor, "recipient": recipient,
            "phase": phase, "parameters": parameters,
        })

    def execute_diplomatic_action(self, request_id, action_id, actor, recipient,
                                  phase="initiate", parameters=None):
        return self._call("execute_diplomatic_action", {
            "request_id": request_id, "action_id": action_id, "actor": actor,
            "recipient": recipient, "phase": phase, "parameters": parameters,
        })

    def get_diplomatic_result(self, request_id):
        return self._call("get_diplomatic_result", {"request_id": request_id})


class FakeInformationService:
    def __init__(self, diplomacy_tools=None):
        self.diplomacy_tools = diplomacy_tools
        self.collection_lock = CollectionLock(":memory:")
        self.calls = []
        self.close_calls = 0
        self.closed = False
        self._closed = False

    def discover(self, topics=None):
        self.calls.append(("discover", {"topics": topics}))
        return {"ready": False, "topics": []}

    def query(self, request_id, queries=None, report_id=None):
        self.calls.append(("query", {
            "request_id": request_id, "queries": queries, "report_id": report_id,
        }))
        return {"result_id": "result-1", "request_id": request_id}

    def get_result(self, result_id):
        self.calls.append(("get_result", {"result_id": result_id}))
        return {"result_id": result_id}

    def manage_report(self, **kwargs):
        self.calls.append(("manage_report", kwargs))
        return {"ok": True, **kwargs}

    def manage_subscription(self, **kwargs):
        self.calls.append(("manage_subscription", kwargs))
        return {"ok": True, **kwargs}

    def configure(self, **kwargs):
        self.calls.append(("configure", kwargs))
        return {"ok": True, **kwargs}

    def status(self, subscription_id=None):
        self.calls.append(("status", {"subscription_id": subscription_id}))
        return {"status": "offline"}

    def list_results(self, limit=50):
        self.calls.append(("list_results", {"limit": limit}))
        return []

    def tick(self):
        self.calls.append(("tick", {}))
        return {"processed": 0}

    def close(self):
        self.close_calls += 1
        self.closed = True
        self._closed = True


def initialize(server: InformationMCPServer) -> None:
    response = server.handle({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        },
    })
    assert response["result"]["protocolVersion"] == "2025-03-26"
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


class GameToolsTests(unittest.TestCase):
    def setUp(self):
        self.diplomacy = FakeDiplomacyTools()
        self.service = FakeInformationService(self.diplomacy)
        # The production default resolves the exact instance retained by the service.
        self.tools = GameTools(self.service)

    def tearDown(self):
        if not self.service.closed:
            self.service.close()

    def test_discovery_combines_all_information_and_existing_diplomacy_tools(self):
        definitions = self.tools.definitions()
        names = tuple(item["name"] for item in definitions)
        self.assertEqual(names, INFORMATION_TOOL_NAMES + DIPLOMACY_TOOL_NAMES)
        self.assertEqual(len(names), 13)
        for item in definitions:
            self.assertEqual(item["inputSchema"]["type"], "object")
            self.assertFalse(item["inputSchema"]["additionalProperties"])

        definitions[0]["name"] = "mutated-copy"
        self.assertEqual(self.tools.definitions()[0]["name"], INFORMATION_TOOL_NAMES[0])

    def test_information_and_diplomacy_calls_share_the_service_and_keep_results(self):
        info_result = self.tools.call("information_discover", {})
        self.assertEqual(info_result, {"topics": []})
        self.assertEqual(self.service.calls[-1][0], "discover")

        expected = self.diplomacy.results["inspect_diplomatic_action"]
        result = self.tools.call("inspect_diplomatic_action", {
            "action_id": "offer_alliance", "actor": "FRA", "recipient": "ENG",
            "phase": "initiate", "parameters": {"nested": {"keep": [1, True]}},
        })
        self.assertIs(result, expected)
        self.assertEqual(self.diplomacy.calls, [(
            "inspect_diplomatic_action", {
                "action_id": "offer_alliance", "actor": "FRA", "recipient": "ENG",
                "phase": "initiate", "parameters": {"nested": {"keep": [1, True]}},
            },
        )])

    def test_execute_forwards_full_arguments_and_rejects_unknown_fields(self):
        arguments = {
            "request_id": "request-1", "action_id": "offer_alliance",
            "actor": "FRA", "recipient": "ENG", "phase": "initiate",
            "parameters": {"source": "caller", "value": [0, "x"]},
        }
        expected = self.diplomacy.results["execute_diplomatic_action"]
        self.assertIs(self.tools.call("execute_diplomatic_action", arguments), expected)
        self.assertEqual(self.diplomacy.calls[-1], ("execute_diplomatic_action", arguments))

        with self.assertRaises(InformationError) as error:
            self.tools.call("execute_diplomatic_action", {**arguments, "extra": True})
        self.assertEqual(error.exception.code, "invalid_parameters")
        self.assertEqual(len(self.diplomacy.calls), 1)

    def test_conflict_and_unknown_results_are_returned_without_retry(self):
        conflict = self.tools.call("execute_diplomatic_action", {
            "request_id": "conflict-1", "action_id": "offer_alliance",
            "actor": "FRA", "recipient": "ENG",
        })
        unknown = self.tools.call("get_diplomatic_result", {"request_id": "missing-1"})
        self.assertEqual(conflict["status"], "conflict")
        self.assertEqual(unknown["status"], "unknown")
        self.assertEqual([name for name, _ in self.diplomacy.calls], [
            "execute_diplomatic_action", "get_diplomatic_result",
        ])

    def test_diplomacy_tools_are_discoverable_offline_but_calls_are_explicitly_unready(self):
        service = FakeInformationService()
        tools = GameTools(service)
        self.assertEqual(
            tuple(item["name"] for item in tools.definitions()),
            INFORMATION_TOOL_NAMES + DIPLOMACY_TOOL_NAMES,
        )
        with self.assertRaises(InformationError) as error:
            tools.call("list_diplomatic_actions", {})
        self.assertEqual(error.exception.code, "source_unavailable")

    def test_mcp_and_jsonl_use_the_same_registered_game_tools(self):
        server = InformationMCPServer(self.service, tools=self.tools)
        output = io.StringIO()
        original_call = self.tools.call
        calls = []

        def recording_call(name, arguments=None):
            calls.append(name)
            return original_call(name, arguments)

        self.tools.call = recording_call
        try:
            self.assertIs(server.tools, self.tools)
            initialize(server)
            listed = server.handle({
                "jsonrpc": "2.0", "id": 2, "method": "tools/list",
                "params": {"_meta": {"progressToken": 2}},
            })
            self.assertEqual(
                tuple(item["name"] for item in listed["result"]["tools"]),
                INFORMATION_TOOL_NAMES + DIPLOMACY_TOOL_NAMES,
            )
            mcp_result = server.handle({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "get_diplomatic_result", "arguments": {"request_id": "missing-1"},
                           "_meta": {"progressToken": "test-call"}},
            })
            self.assertFalse(mcp_result["result"]["isError"])
            self.assertEqual(
                json.loads(mcp_result["result"]["content"][0]["text"])["status"], "unknown")

            line = json.dumps({
                "tool": "get_diplomatic_result", "arguments": {"request_id": "missing-1"},
            }) + "\n"
            with redirect_stdout(output):
                self.assertEqual(_run_jsonl(self.service, io.StringIO(line), tools=self.tools), 0)
            self.assertEqual(json.loads(output.getvalue())["status"], "unknown")
            self.assertEqual(calls, ["get_diplomatic_result", "get_diplomatic_result"])
        finally:
            server.close()

    def test_diplomacy_call_waits_for_background_collection_lock(self):
        self.service.collection_lock = CollectionLock(":memory:")
        entered = threading.Event()
        finished = threading.Event()
        failures = []

        def call_tool():
            try:
                entered.set()
                self.tools.call("execute_diplomatic_action", {
                    "request_id": "serialized-1", "action_id": "offer_alliance",
                    "actor": "FRA", "recipient": "ENG",
                })
            except BaseException as error:  # surfaced in the owning test thread
                failures.append(error)
            finally:
                finished.set()

        worker = threading.Thread(target=call_tool)
        with self.service.collection_lock.acquire() as acquired:
            self.assertTrue(acquired)
            worker.start()
            self.assertTrue(entered.wait(2))
            self.assertFalse(finished.wait(0.05))
            self.assertEqual(self.diplomacy.calls, [])
        self.assertTrue(finished.wait(3))
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(len(self.diplomacy.calls), 1)

    def test_mcp_close_owns_the_single_service_lifecycle_and_blocks_later_calls(self):
        server = InformationMCPServer(self.service, tools=self.tools)
        server.close()
        server.close()
        self.assertEqual(self.service.close_calls, 1)
        with self.assertRaises(InformationError) as error:
            self.tools.call("list_diplomatic_actions", {})
        self.assertEqual(error.exception.code, "service_closed")


def test_live_runtime_game_tools_share_the_original_diplomacy_and_journal(tmp_path, wiring):
    args = _live_args(tmp_path)
    service, journal = _build_runtime(args)
    server = None
    try:
        diplomacy = service.diplomacy_tools
        assert diplomacy is not None
        assert diplomacy.journal is journal
        assert diplomacy.session.path == args.operator_session

        # The source adapter and the newly exposed tool facade retain the same
        # DiplomacyTools object created by the live runtime factory.
        source = service.source
        visited = set()
        while source is not None and id(source) not in visited:
            visited.add(id(source))
            if hasattr(source, "kwargs") and "diplomacy_tools" in source.kwargs:
                assert source.kwargs["diplomacy_tools"] is diplomacy
                break
            source = getattr(source, "primary", None)
        else:
            raise AssertionError("the live diplomacy source adapter was not retained")

        tools = GameTools(service)
        assert tools.diplomacy is diplomacy
        server = InformationMCPServer(service, tools=tools)
        assert server.tools is tools
        server.close()
        server = None
        assert "service.close" in wiring.events
        assert journal.closed is False
        journal.close()
        assert wiring.events.count("journal.close") == 1
    finally:
        if server is not None:
            server.close()
        else:
            # _build_runtime returns the durable journal separately; the
            # process entry point owns closing it after the service transport.
            journal.close()


def test_native_country_and_clock_failure_keep_read_tools_available(tmp_path, wiring, monkeypatch):
    from bridge.diplomacy import ObserverSession
    from bridge.game_time_control import TOOL_NAME as CLOCK_TOOL
    from bridge.diplomat_recall import TOOL_NAME as RECALL_TOOL

    configured = []

    def fail_configuration(session, countries):
        configured.append(countries)
        raise RuntimeError("NATIVE_COUNTRY_CONTROL_CONFIGURATION_REJECTED: country_unavailable")

    def fail_clock(session):
        raise InformationError("permission_denied", "Clock requires a verified observer seat")

    monkeypatch.setattr(ObserverSession, "configure_controlled_countries", fail_configuration,
                        raising=False)
    monkeypatch.setattr("bridge.game_time_control.bind_game_time_control", fail_clock)
    args = _live_args(tmp_path)
    args.observer = "TUR"
    args.controlled_country = "ENG"
    args.allow_time_control = True
    service, journal = _build_runtime(args)
    service.collection_lock = CollectionLock(":memory:")
    service._closed = False
    diplomacy = FakeDiplomacyTools()
    diplomacy.can_recall_diplomat = True
    diplomacy.results["list_diplomatic_actions"] = {
        "actions": [{"phases": {"initiate": {"query": "native", "execute": "native_submission"}}}],
        "incoming_proposals": [{"id": "inbound", "execute": {"accept": "native_response"}}],
    }
    tools = GameTools(service, diplomacy)
    try:
        assert configured == [["ENG"]]
        listed = {item["name"] for item in tools.definitions()}
        assert {"information_query", "list_diplomatic_actions", "inspect_diplomatic_action",
                "get_diplomatic_result"} <= listed
        assert {"execute_diplomatic_action", RECALL_TOOL, CLOCK_TOOL}.isdisjoint(listed)
        for name in ("execute_diplomatic_action", RECALL_TOOL):
            with pytest.raises(InformationError, match="country_unavailable") as error:
                tools.call(name)
            assert error.value.code == "native_country_control_unavailable"
        with pytest.raises(InformationError, match="verified observer seat"):
            tools.call(CLOCK_TOOL)
        listing = tools.call("list_diplomatic_actions")
        assert listing["actions"][0]["phases"]["initiate"]["query"] == "native"
        assert listing["actions"][0]["phases"]["initiate"]["execute"] == "unavailable"
        assert listing["incoming_proposals"] == [{"id": "inbound"}]
        preview = tools.call("inspect_diplomatic_action", {
            "action_id": "offer_alliance", "actor": "ENG", "recipient": "TUR"})
        assert preview["inspection"] == "native-readable-result"
        assert preview["authorization"]["status"] == "unavailable"
        assert [name for name, _ in diplomacy.calls] == [
            "list_diplomatic_actions", "inspect_diplomatic_action"]
    finally:
        service.close()
        journal.close()


if __name__ == "__main__":
    unittest.main()
