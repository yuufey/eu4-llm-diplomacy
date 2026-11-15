"""Contract tests for information LLM tools and the dependency-free MCP wire."""
from __future__ import annotations

import io
import json
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from bridge.information.mcp import InformationMCPServer
from bridge.information.model import InformationError
from bridge.information.service import InformationService
from bridge.information.sources import RecordedSource
from bridge.information.tools import InformationTools, TOOL_NAMES


class FakeInformationService:
    def __init__(self):
        self.calls = []
        self.closed = False

    def discover(self):
        self.calls.append(("discover", {}))
        return {"ready": False, "topics": []}

    def query(self, request_id, queries=None, report_id=None):
        self.calls.append(("query", {"request_id": request_id, "queries": queries, "report_id": report_id}))
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
        self.closed = True


def initialize(server: InformationMCPServer, version: str = "2025-03-26"):
    response = server.handle({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        },
    })
    assert response["result"]["protocolVersion"] == version
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


class InformationToolTests(unittest.TestCase):
    def setUp(self):
        self.service = FakeInformationService()
        self.tools = InformationTools(self.service)

    def test_definitions_are_discoverable_and_strict(self):
        definitions = self.tools.definitions()
        self.assertEqual(tuple(item["name"] for item in definitions), TOOL_NAMES)
        self.assertEqual(len(definitions), 9)
        for item in definitions:
            self.assertEqual(item["inputSchema"]["type"], "object")
            self.assertFalse(item["inputSchema"]["additionalProperties"])
        definitions[0]["name"] = "changed"
        self.assertEqual(self.tools.definitions()[0]["name"], "information_discover")

    def test_dispatch_preserves_service_defaults(self):
        self.assertEqual(self.tools.call("information_discover", {}), {"topics": []})
        self.assertEqual(self.tools.call("information_list_results", {}), [])
        self.assertEqual(self.service.calls[-1], ("list_results", {"limit": 50}))
        self.tools.call("information_query", {
            "request_id": "q-1",
            "queries": [{
                "topic": "fixture",
                "object": {"type": "country", "id": "FRA"},
                "fields": ["value"],
                "parameters": {},
            }],
        })
        self.assertEqual(self.service.calls[-1][1]["request_id"], "q-1")
        self.assertIsNotNone(self.service.calls[-1][1]["queries"])
        self.assertIsNone(self.service.calls[-1][1]["report_id"])

    def test_unknown_and_extra_arguments_are_rejected(self):
        with self.assertRaises(InformationError) as unknown:
            self.tools.call("information_missing", {})
        self.assertEqual(unknown.exception.code, "unknown_tool")
        with self.assertRaises(InformationError) as extra:
            self.tools.call("information_discover", {"extra": True})
        self.assertEqual(extra.exception.code, "invalid_parameters")
        with self.assertRaises(InformationError):
            self.tools.call("information_manage_report", {
                "request_id": "r-1", "operation": "create", "config": {
                    "name": "x", "queries": [], "detail": "raw", "extra": 1,
                },
            })

    def test_operation_specific_requirements_are_checked(self):
        with self.assertRaises(InformationError):
            self.tools.call("information_query", {"request_id": "q-1"})
        with self.assertRaises(InformationError):
            self.tools.call("information_query", {
                "request_id": "q-2", "report_id": "report-1", "queries": [],
            })
        with self.assertRaises(InformationError):
            self.tools.call("information_manage_report", {"request_id": "r-1", "operation": "get"})
        with self.assertRaises(InformationError):
            self.tools.call("information_manage_subscription", {"request_id": "s-1", "operation": "pause"})
        with self.assertRaises(InformationError):
            self.tools.call("information_configure", {"request_id": "c-1", "operation": "update"})

    def test_updates_require_complete_config_and_version(self):
        with self.assertRaises(InformationError):
            self.tools.call("information_manage_report", {
                "request_id": "r-1", "operation": "update", "report_id": "report-1",
                "config": {"name": "partial", "queries": []}, "expected_version": 1,
            })
        with self.assertRaises(InformationError):
            self.tools.call("information_manage_subscription", {
                "request_id": "s-1", "operation": "update", "subscription_id": "subscription-1",
                "config": {"name": "partial", "kind": "periodic", "report_id": "report-1", "enabled": True},
                "expected_version": 1,
            })
        with self.assertRaises(InformationError):
            self.tools.call("information_manage_report", {
                "request_id": "r-2", "operation": "delete", "report_id": "report-1",
            })

    def test_subscription_shape_accepts_optional_binding_filters(self):
        value = {
            "request_id": "s-1",
            "operation": "create",
            "config": {
                "name": "events",
                "kind": "event",
                "report_id": "report-1",
                "enabled": True,
                "binding": {"session_id": "session-1", "observer": "FRA", "game_version": "1.37.4"},
                "event": {"types": ["battle_finished"], "actors": ["FRA"], "recipients": ["ENG"]},
            },
        }
        result = self.tools.call("information_manage_subscription", value)
        self.assertTrue(result["ok"])
        self.assertEqual(self.service.calls[-1][0], "manage_subscription")


class InformationMCPTests(unittest.TestCase):
    def setUp(self):
        self.service = FakeInformationService()
        self.server = InformationMCPServer(self.service)

    def tearDown(self):
        self.server.close()

    def test_initialize_negotiates_and_requires_initialized_notification(self):
        before = self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual(before["error"]["code"], -32600)
        initialize(self.server, "2024-11-05")
        response = self.server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        self.assertEqual([item["name"] for item in response["result"]["tools"]], list(TOOL_NAMES))

    def test_unknown_protocol_is_explicit(self):
        response = self.server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "9.9", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
        })
        # The server answers with a supported revision; the client may close
        # the connection if it cannot speak that revision.
        self.assertEqual(response["result"]["protocolVersion"], "2025-03-26")
        self.assertTrue(self.server.initialized)

    def test_tick_starts_after_initialized_notification(self):
        server = InformationMCPServer(self.service, tick_seconds=0.01)
        response = server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
        })
        self.assertEqual(response["result"]["protocolVersion"], "2025-03-26")
        time.sleep(0.03)
        self.assertFalse(any(call[0] == "tick" for call in self.service.calls))
        server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline and not any(call[0] == "tick" for call in self.service.calls):
            time.sleep(0.01)
        self.assertTrue(any(call[0] == "tick" for call in self.service.calls))
        server.close()

    def test_tools_call_returns_text_and_business_errors_without_killing_server(self):
        initialize(self.server)
        response = self.server.handle({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "information_discover", "arguments": {}},
        })
        self.assertFalse(response["result"]["isError"])
        self.assertEqual(json.loads(response["result"]["content"][0]["text"]), {"topics": []})

        bad = self.server.handle({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "information_query", "arguments": {"request_id": "bad", "extra": 1}},
        })
        self.assertEqual(bad["error"]["code"], -32602)
        ping = self.server.handle({"jsonrpc": "2.0", "id": 5, "method": "ping", "params": {}})
        self.assertEqual(ping["result"], {})

    def test_stdio_parse_error_is_a_line_response_and_server_continues(self):
        input_stream = io.StringIO(
            "not json\n"
            + json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
            }) + "\n"
            + '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
            + '{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n'
        )
        output_stream = io.StringIO()
        self.server.serve(input_stream, output_stream)
        responses = [json.loads(line) for line in output_stream.getvalue().splitlines()]
        self.assertEqual(responses[0]["error"]["code"], -32700)
        self.assertEqual(responses[1]["result"]["protocolVersion"], "2025-03-26")
        self.assertEqual(responses[2]["id"], 2)
        self.assertTrue(self.service.closed)


class InformationCLITests(unittest.TestCase):
    def test_offline_discover_subprocess_reports_unready_context(self):
        root = Path(__file__).resolve().parents[2]
        payload = (
            json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
            }) + "\n"
            + '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
            + json.dumps({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "information_discover", "arguments": {"view": "full"}},
            }) + "\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "information.sqlite3"
            completed = subprocess.run(
                [sys.executable, "tools/serve_information.py", "--database", str(database)],
                cwd=root,
                input=payload,
                text=True,
                capture_output=True,
                timeout=20,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        lines = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0]["result"]["protocolVersion"], "2025-03-26")
        self.assertFalse(lines[1]["result"]["isError"])
        discovered = json.loads(lines[1]["result"]["content"][0]["text"])
        self.assertEqual(discovered["context"]["status"], "unready")
        self.assertFalse(discovered["context"]["complete"])

    def test_documented_shapes_run_through_recorded_source_and_service(self):
        root = Path(__file__).resolve().parents[2]
        fixture_path = root / "bridge" / "tests" / "fixtures" / "r73_favor_queries_real.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        # The fixture deliberately lacks current-session identity.  The
        # wrapper supplies only independently verified recorded provenance;
        # it leaves world_id absent instead of inferring a world generation.
        manifest = deepcopy(fixture)
        manifest["context"] = {
            "status": "ready",
            "complete": True,
            "session_id": fixture["session_id"],
            "observer": "FRA",
            "game_version": "1.37.4",
            "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
            "game_date": fixture["health"]["date_raw"],
        }
        # The query archive has no event stream.  Add one explicit recorded
        # event so the documented event subscription is checked against the
        # real RecordedSource implementation without inferring live state.
        manifest["events"] = [{
            "event_id": "documented-event-1",
            "event_type": "diplomatic_proposal",
            "session_id": fixture["session_id"],
            "game_date": fixture["health"]["date_raw"],
            "payload": {"actors": ["SAV"], "recipients": ["FRA"]},
        }]
        query = {
            "topic": "C01",
            "object": {"type": "session"},
            "fields": ["game_date", "observer", "session_id"],
            "parameters": {},
        }
        with tempfile.TemporaryDirectory() as temporary:
            service = InformationService(RecordedSource(manifest), Path(temporary) / "information.sqlite3")
            tools = InformationTools(service)
            try:
                result = tools.call("information_query", {
                    "request_id": "documented-query",
                    "view": "full",
                    "queries": [query],
                })
                self.assertEqual(result["context"]["mode"], "recorded")
                self.assertEqual(result["context"]["observer"], "FRA")
                self.assertIsNone(result["context"]["world_id"])
                self.assertEqual(result["items"][0]["objects"], [{"type": "session"}])

                report = tools.call("information_manage_report", {
                    "request_id": "documented-report",
                    "operation": "create",
                    "config": {
                        "name": "短周期局势简报",
                        "queries": [query],
                        "detail": "brief",
                    },
                })["report"]
                binding = {
                    "session_id": fixture["session_id"],
                    "observer": "FRA",
                    "game_version": "1.37.4",
                }
                periodic = tools.call("information_manage_subscription", {
                    "request_id": "documented-periodic",
                    "operation": "create",
                    "config": {
                        "name": "每周局势报告",
                        "kind": "periodic",
                        "report_id": report["id"],
                        "enabled": True,
                        "binding": binding,
                        "schedule": {
                            "basis": "game",
                            "every": 7,
                            "unit": "days",
                            "missed": "coalesce",
                        },
                    },
                })["subscription"]
                self.assertEqual(periodic["state"], "active")
                event = tools.call("information_manage_subscription", {
                    "request_id": "documented-event",
                    "operation": "create",
                    "config": {
                        "name": "入站外交事件",
                        "kind": "event",
                        "report_id": report["id"],
                        "enabled": True,
                        "binding": binding,
                        "event": {
                            "types": ["diplomatic_proposal"],
                            "actors": ["SAV"],
                            "recipients": ["FRA"],
                        },
                    },
                })["subscription"]
                self.assertEqual(event["state"], "active")
            finally:
                service.close()


if __name__ == "__main__":
    unittest.main()
