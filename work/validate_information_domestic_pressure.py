"""Validate N04 through the live MCP server without changing game state.

The native reference is supplied by a separate capture process.  This script
does not use the MCP response to create its own expected values.  The MCP
wire audit stores request/response shapes and hashes only; complete JSON-RPC
payloads and native read logs are intentionally not written to the audit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.run_alliance_inbound_response import control_snapshot
from work.validate_information_live import sha, write


FIELDS = ("stability", "war_exhaustion", "corruption")
UNIMPLEMENTED_FIELDS = ("religious_unity", "overextension", "unrest")
SEED_FIELDS = FIELDS + UNIMPLEMENTED_FIELDS
UNITS = {
    "stability": "stability",
    "war_exhaustion": "war_exhaustion",
    "corruption": "corruption",
}
EXPECTED_VERSION = "1.37.4"
EXPECTED_GAME_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
MAX_REFERENCE_BYTES = 8 * 1024 * 1024


def require(value: Any, reason: str) -> None:
    if not value:
        raise ValueError(reason)


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _json_sha256(value: Any) -> str:
    return hashlib.sha256(_json_bytes(value)).hexdigest()


class MCPCallError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class CompactMCPClient:
    """Small stdio client that records only a compact wire audit."""

    def __init__(self, installation: Path, output: Path, *, tick_seconds: float = 0.25,
                 extra_server_args: list[str] | None = None):
        self.messages: queue.Queue[dict] = queue.Queue()
        self.identifier = 0
        self.audit: list[dict] = []
        self.audit_path = output / "mcp-wire-audit.json"
        self.closed = False
        self.process = subprocess.Popen(
            [
                sys.executable, "tools/serve_information.py",
                "--operator-session", str(installation), "--observer", "FRA",
                "--database", str(output / "information.sqlite3"),
                "--journal", str(output / "diplomacy.sqlite3"),
                "--tick-seconds", str(tick_seconds),
                *(extra_server_args or []),
            ],
            cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8", bufsize=1,
        )
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        try:
            self.initialize_result = self.rpc(
                "initialize",
                {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "domestic-pressure-acceptance", "version": "1"},
                },
            )
            require(
                self.initialize_result.get("protocolVersion") in {"2024-11-05", "2025-03-26"},
                "MCP server did not negotiate a supported protocol version",
            )
            self.send_notification("notifications/initialized")
        except Exception:
            self.closed = True
            try:
                if self.process.stdin is not None:
                    self.process.stdin.close()
            except Exception:
                pass
            if self.process.poll() is None:
                self.process.terminate()
                self.process.wait(timeout=10)
            self.reader.join(timeout=2)
            raise

    def _read(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            if not line.strip():
                continue
            try:
                self.messages.put(json.loads(line))
            except ValueError:
                self.messages.put({"_invalid_json": True})
        self.messages.put({"_eof": True})

    def _send(self, value: dict) -> None:
        if self.process.stdin is None:
            raise RuntimeError("MCP stdin is unavailable")
        self.process.stdin.write(json.dumps(value, ensure_ascii=False) + "\n")
        self.process.stdin.flush()

    def send_notification(self, method: str, params: dict | None = None) -> None:
        body = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            body["params"] = params
        self._send(body)
        self.audit.append({"kind": "notification", "method": method,
                           "parameter_keys": sorted((params or {}).keys())})

    def rpc(self, method: str, params: dict) -> dict:
        self.identifier += 1
        identifier = self.identifier
        self._send({"jsonrpc": "2.0", "id": identifier, "method": method, "params": params})
        response = self.messages.get(timeout=45)
        if response.get("_eof"):
            raise RuntimeError("MCP server exited before responding")
        if response.get("_invalid_json"):
            raise RuntimeError("MCP server emitted invalid JSON")
        entry = {
            "kind": "rpc",
            "id": identifier,
            "method": method,
            "parameter_keys": sorted(params.keys()),
            "response_keys": sorted(response.keys()),
            "response_bytes": len(_json_bytes(response)),
            "response_sha256": _json_sha256(response),
        }
        self.audit.append(entry)
        if response.get("id") != identifier:
            raise RuntimeError("MCP response id mismatch")
        if "error" in response:
            error = response.get("error")
            code = str(error.get("code", "jsonrpc_error")) if isinstance(error, dict) else "jsonrpc_error"
            message = str(error.get("message", "MCP JSON-RPC error")) if isinstance(error, dict) else str(error)
            raise MCPCallError(code, message)
        result = response.get("result")
        if not isinstance(result, dict):
            raise RuntimeError("MCP result is not an object")
        return result

    @staticmethod
    def _tool_value(result: dict) -> dict:
        if result.get("isError") is True:
            content = result.get("content")
            value = None
            if isinstance(content, list) and content and isinstance(content[0], dict):
                text = content[0].get("text")
                if isinstance(text, str):
                    try:
                        value = json.loads(text)
                    except ValueError:
                        value = None
            error = value.get("error") if isinstance(value, dict) else None
            if isinstance(error, dict):
                raise MCPCallError(str(error.get("code", "tool_error")), str(error.get("message", "MCP tool failed")))
            raise MCPCallError("tool_error", "MCP tool failed")
        content = result.get("content")
        require(isinstance(content, list) and content, "MCP tool returned no content")
        first = content[0]
        require(isinstance(first, dict) and isinstance(first.get("text"), str), "MCP tool content is not text")
        value = json.loads(first["text"])
        require(isinstance(value, dict), "MCP tool payload is not an object")
        if "error" in value:
            error = value["error"]
            if isinstance(error, dict):
                raise MCPCallError(str(error.get("code", "tool_error")), str(error.get("message", "MCP tool failed")))
            raise MCPCallError("tool_error", str(error))
        return value

    def call(self, name: str, **arguments: Any) -> dict:
        result = self.rpc("tools/call", {"name": name, "arguments": arguments})
        return self._tool_value(result)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        error: Exception | None = None
        try:
            if self.process.stdin is not None:
                self.process.stdin.close()
            self.process.wait(timeout=45)
        except subprocess.TimeoutExpired as exc:
            self.process.terminate()
            self.process.wait(timeout=10)
            error = exc
        finally:
            self.reader.join(timeout=2)
            write(self.audit_path, {
                "schema": "information_domestic_pressure_mcp_wire_audit_v1",
                "protocol_version": self.initialize_result.get("protocolVersion"),
                "server_info": self.initialize_result.get("serverInfo"),
                "capabilities": sorted(self.initialize_result.get("capabilities", {}).keys()),
                "entries": self.audit,
                "raw_payloads_written": False,
            })
        if error is not None:
            raise error
        require(self.process.returncode == 0, f"MCP server exited with {self.process.returncode}")


def _read_reference(path: Path) -> tuple[dict, str]:
    require(path.stat().st_size <= MAX_REFERENCE_BYTES, "Native reference is too large")
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    require(isinstance(value, dict), "Native reference is not an object")
    if isinstance(value.get("native_capture"), dict):
        value = value["native_capture"]
    elif isinstance(value.get("capture"), dict) and "field_results" in value["capture"]:
        value = value["capture"]
    require(value.get("status") == "observed", "Native reference is not observed")
    require(value.get("completed") is True, "Native reference is not completed")
    require(value.get("read_only") is True, "Native reference is not read-only")
    require(value.get("native_function_invoked") is False, "Native reference invoked a game function")
    require(value.get("country") == "FRA", "Native reference country is not FRA")
    require(value.get("complete") is True, "Native reference is incomplete")
    target_build = value.get("target_build")
    require(isinstance(target_build, dict), "Native reference target build is missing")
    require(target_build.get("version") == EXPECTED_VERSION, "Native reference game version differs")
    require(target_build.get("expected_exe_sha256", target_build.get("exe_sha256")) == EXPECTED_GAME_SHA256,
            "Native reference executable differs")
    fields = value.get("field_results")
    require(isinstance(fields, dict), "Native reference has no field_results")
    for field in FIELDS:
        item = fields.get(field)
        require(isinstance(item, dict) and item.get("status") == "known", f"Native reference lacks {field}")
        raw_value = item.get("raw")
        raw_hex = item.get("raw_hex")
        require(type(raw_value) is int and isinstance(raw_hex, str) and len(raw_hex) == 8, f"Native reference {field} malformed")
        require(int.from_bytes(bytes.fromhex(raw_hex), "little", signed=True) == raw_value, f"Native reference {field} bytes differ")
        require(item.get("unit") == UNITS[field] and item.get("scale") == 1000, f"Native reference {field} metadata differs")
    values = value.get("values")
    if values is not None:
        require(isinstance(values, dict), "Native reference values is not an object")
        for field in FIELDS:
            require(values.get(field) == fields[field]["raw"], f"Native reference {field} values differ")
    identity = value.get("identity")
    require(isinstance(identity, dict) and identity.get("binding_verified") is True,
            "Native reference identity is missing or unbound")
    session_id = identity.get("installation_session_id", identity.get("session_id"))
    installation_creation_filetime = identity.get("installation_creation_filetime", identity.get("creation_filetime"))
    process_creation_filetime = identity.get("process_creation_filetime", identity.get("process_creation"))
    before = value.get("before")
    game_date = None
    if isinstance(before, dict) and isinstance(before.get("game_date"), dict):
        game_date = before["game_date"].get("value")
    if game_date is None:
        game_date = value.get("date_raw")
    require(isinstance(session_id, str) and session_id, "Native reference session is missing")
    require(type(installation_creation_filetime) is int, "Native reference installation creation is missing")
    require(type(process_creation_filetime) is int, "Native reference process creation is missing")
    require(type(game_date) is int, "Native reference date is missing")
    after = value.get("after")
    require(isinstance(after, dict) and isinstance(after.get("game_date"), dict)
            and after["game_date"].get("value") == game_date,
            "Native reference before/after dates differ")
    doublepass = value.get("doublepass")
    require(isinstance(doublepass, dict)
            and doublepass.get("performed") is True
            and doublepass.get("consistent") is True
            and doublepass.get("mismatches", []) == [],
            "Native reference doublepass is not consistent")
    handle_close = value.get("cleanup", {}).get("handle_close", {})
    require(isinstance(handle_close, dict)
            and handle_close.get("status") == "closed"
            and handle_close.get("closed") is True,
            "Native reference handle was not closed")
    access = value.get("access", {})
    for key in ("native_game_calls", "target_memory_writes", "dll_injection", "date_advance", "save_or_reload"):
        require(access.get(key) is False, f"Native reference access guard failed: {key}")
    return {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "session_id": session_id,
        "installation_creation_filetime": installation_creation_filetime,
        "process_creation_filetime": process_creation_filetime,
        "game_date": game_date,
        "values": {field: fields[field]["raw"] for field in FIELDS},
        "raw_hex": {field: fields[field]["raw_hex"] for field in FIELDS},
    }, hashlib.sha256(raw).hexdigest()


def _field_summary(item: Any) -> dict:
    if not isinstance(item, dict):
        return {"status": "invalid"}
    return {
        key: item[key]
        for key in ("status", "value", "raw", "raw_hex", "unit", "scale", "reason")
        if key in item
    }


def _source_summary(source: Any) -> dict:
    if not isinstance(source, dict):
        return {}
    result = {key: source[key] for key in ("name", "context_scope", "complete") if key in source}
    provenance = source.get("provenance")
    if isinstance(provenance, dict):
        result["provenance"] = {
            key: provenance[key]
            for key in (
                "adapter", "capture", "read_only", "native_function_invoked", "scope",
                "supported_country", "target_build", "capture_report_sha256", "reason",
            )
            if key in provenance and key != "capture"
        }
    return result


def _result_summary(result: Any) -> dict:
    require(isinstance(result, dict), "MCP query result is not an object")
    summary = {
        key: result[key]
        for key in ("status", "complete", "result_id", "subscription_id", "trigger", "delivery")
        if key in result
    }
    context = result.get("context")
    if isinstance(context, dict):
        summary["context"] = {
            key: context[key]
            for key in ("status", "session_id", "observer", "game_version", "game_sha256", "game_date", "world_id")
            if key in context
        }
    items = []
    for item in result.get("items", []):
        if not isinstance(item, dict):
            continue
        items.append({
            "query": item.get("query"),
            "complete": item.get("complete"),
            "fields": {field: _field_summary(value) for field, value in item.get("fields", {}).items()},
            "source": _source_summary(item.get("source")),
        })
    summary["items"] = items
    return summary


def _check_context(result: dict, reference: dict, session_id: str, game_date: int) -> None:
    context = result.get("context")
    require(isinstance(context, dict), "MCP result context is missing")
    require(context.get("status") == "ready", "MCP result context is not ready")
    require(context.get("session_id") == session_id == reference["session_id"], "MCP session differs")
    require(context.get("observer") == "FRA", "MCP observer differs")
    require(context.get("game_version") == EXPECTED_VERSION, "MCP game version differs")
    require(context.get("game_sha256") == EXPECTED_GAME_SHA256, "MCP executable differs")
    require(context.get("game_date") == game_date == reference["game_date"], "MCP date differs")


def _check_result_fields(result: dict, requested_fields: list[str], reference: dict, session_id: str, game_date: int) -> dict:
    _check_context(result, reference, session_id, game_date)
    items = result.get("items")
    require(isinstance(items, list) and len(items) == 1, "MCP N04 result item count differs")
    item = items[0]
    require(isinstance(item, dict), "MCP N04 item is invalid")
    source = item.get("source")
    provenance = source.get("provenance") if isinstance(source, dict) else None
    require(isinstance(provenance, dict)
            and provenance.get("read_only") is True
            and provenance.get("native_function_invoked") is False,
            "MCP N04 source provenance is not read-only")
    fields = item.get("fields")
    require(isinstance(fields, dict), "MCP N04 fields are missing")
    result_values = {}
    for field in requested_fields:
        value = fields.get(field)
        require(isinstance(value, dict) and value.get("status") == "known", f"MCP field {field} is not known")
        raw = value.get("raw", value.get("value"))
        require(type(raw) is int and raw == reference["values"][field], f"MCP field {field} differs from native reference")
        require(value.get("value") == raw, f"MCP field {field} value/raw differ")
        raw_hex = value.get("raw_hex")
        require(isinstance(raw_hex, str) and len(raw_hex) == 8, f"MCP field {field} raw_hex invalid")
        require(int.from_bytes(bytes.fromhex(raw_hex), "little", signed=True) == raw, f"MCP field {field} bytes differ")
        require(value.get("unit") == UNITS[field] and value.get("scale") == 1000, f"MCP field {field} metadata differs")
        result_values[field] = raw
    return result_values


def _check_result(result: dict, requested_fields: list[str], reference: dict, session_id: str, game_date: int) -> dict:
    require(result.get("status") == "complete" and result.get("complete") is True, "MCP N04 result is incomplete")
    items = result.get("items")
    require(isinstance(items, list) and len(items) == 1
            and isinstance(items[0], dict) and items[0].get("complete") is True,
            "MCP N04 item is incomplete")
    return _check_result_fields(result, requested_fields, reference, session_id, game_date)


def _check_mixed_partial(result: dict, reference: dict, session_id: str, game_date: int) -> dict:
    require(result.get("status") == "partial" and result.get("complete") is False,
            "Mixed N04 result is not partial")
    values = _check_result_fields(result, list(FIELDS), reference, session_id, game_date)
    item = result["items"][0]
    require(item.get("complete") is False, "Mixed N04 item incorrectly reports complete")
    fields = item.get("fields", {})
    for field in UNIMPLEMENTED_FIELDS:
        require(fields.get(field, {}).get("status") == "unsupported", field + " was fabricated")
    return values


def _query(fields: list[str]) -> dict:
    return {
        "topic": "N04",
        "object": {"type": "country", "country": "FRA"},
        "fields": list(fields),
        "parameters": {},
    }


def _check_discovery(discovery: dict, expected_field_coverage: str = "partial") -> dict:
    require(
        expected_field_coverage in {"partial", "available"},
        "expected field coverage must be partial or available",
    )
    topics = discovery.get("topics")
    require(isinstance(topics, list), "Discovery topics are missing")
    n04 = next((topic for topic in topics if isinstance(topic, dict) and topic.get("topic_id") == "N04"), None)
    require(isinstance(n04, dict), "N04 is missing from discovery")
    require(n04.get("status") == "available", "N04 status is not available")
    metadata = n04.get("fields")
    require(isinstance(metadata, dict) and set(metadata) == set(SEED_FIELDS), "N04 seed field catalog differs")
    for field in FIELDS:
        item = metadata[field]
        require(
            item.get("coverage") == expected_field_coverage,
            f"N04 {field} coverage differs from expected {expected_field_coverage}",
        )
        require(item.get("unit") == UNITS[field] and item.get("scale") == 1000, f"N04 {field} metadata differs")
        require(item.get("supported_countries") == ["FRA"], f"N04 {field} country scope differs")
    for field in UNIMPLEMENTED_FIELDS:
        require(metadata[field].get("coverage") == "planned", f"N04 {field} should remain planned")
    require(set((n04.get("triggers") or ())) >= {"query", "periodic", "change"}, "N04 trigger contract differs")
    return {
        "topic_id": "N04",
        "status": n04.get("status"),
        "expected_field_coverage": expected_field_coverage,
        "fields": {field: metadata[field] for field in SEED_FIELDS},
        "triggers": n04.get("triggers"),
        "change_detection": n04.get("change_detection"),
        "planned_fields": list(UNIMPLEMENTED_FIELDS),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--reference", "--expected-reference", dest="reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tick-seconds", type=float, default=0.25)
    parser.add_argument("--wait-seconds", type=float, default=10.0)
    parser.add_argument(
        "--expected-field-coverage",
        choices=("partial", "available"),
        default="partial",
        help="Expected coverage for the three native fields (default: partial)",
    )
    args = parser.parse_args()
    require(args.tick_seconds > 0, "--tick-seconds must be positive")
    require(args.wait_seconds >= 6, "--wait-seconds must allow three two-second samples")
    args.output.mkdir(parents=True, exist_ok=False)
    installation = args.installation.resolve(strict=True)
    reference_path = args.reference.resolve(strict=True)
    reference, reference_sha = _read_reference(reference_path)
    report = {
        "status": "failed",
        "mode": "live_mcp",
        "country": "FRA",
        "fields": list(FIELDS),
        "expected_field_coverage": args.expected_field_coverage,
        "read_only": True,
        "native_function_invoked": False,
        "business_actions_submitted": False,
        "date_advance": False,
        "save_or_reload": False,
        "dll_installation": False,
        "historical_values_used": False,
        "native_reference": {"path": str(reference_path), "sha256": reference_sha},
        "checks": {},
    }
    client: CompactMCPClient | None = None
    before: dict | None = None
    pid: int | None = None
    try:
        from bridge.diplomacy import ObserverSession
        from work.local_config import game_exe

        session = ObserverSession(installation, game_exe())
        pid = int(session.record["pid"])
        before = control_snapshot(pid, args.output / "before-control.json")
        write(args.output / "before-health.json", session.health())
        require(
            (before["player_slot"], before["paused_flag"], before["date_raw"], before["speed"])
            == (189, 1, 56553384, 0),
            "Unexpected initial controls",
        )
        require(session.health()["status"] == "ready", "Native source not ready")
        require(session.session_id == reference["session_id"], "Reference session differs from installation")
        require(
            reference["installation_creation_filetime"] == session.record["creation_filetime"]
            and reference["process_creation_filetime"] == session.record["creation_filetime"],
            "Reference process creation differs from installation",
        )
        require(before["date_raw"] == reference["game_date"], "Reference date differs from installation")
        report["checks"]["paused_read_only_start"] = True

        client = CompactMCPClient(installation, args.output, tick_seconds=args.tick_seconds)
        report["mcp_protocol"] = {
            "protocol_version": client.initialize_result.get("protocolVersion"),
            "server_info": client.initialize_result.get("serverInfo"),
        }
        discovery = client.call("information_discover")
        discovery_summary = _check_discovery(discovery, args.expected_field_coverage)
        write(args.output / "discovery-summary.json", discovery_summary)
        report["checks"]["n04_discovery_scope_and_metadata"] = True

        full_query = _query(list(FIELDS))
        manual = client.call("information_query", request_id="domestic-pressure-manual", queries=[full_query])
        manual_values = _check_result(manual, list(FIELDS), reference, session.session_id, before["date_raw"])
        write(args.output / "manual-result.json", manual)
        report["checks"]["three_field_query_matches_independent_native"] = True

        single_results = {}
        for field in FIELDS:
            single = client.call(
                "information_query", request_id="domestic-pressure-single-" + field,
                queries=[_query([field])],
            )
            values = _check_result(single, [field], reference, session.session_id, before["date_raw"])
            single_results[field] = single
        write(args.output / "single-field-results.json", single_results)
        report["checks"]["single_field_selection_preserves_units_and_raw_bytes"] = True

        mixed_query = _query(list(SEED_FIELDS))
        mixed = client.call("information_query", request_id="domestic-pressure-mixed-unimplemented", queries=[mixed_query])
        _check_mixed_partial(mixed, reference, session.session_id, before["date_raw"])
        write(args.output / "mixed-unimplemented-result.json", mixed)
        report["checks"]["unimplemented_religious_unity_overextension_unrest_return_partial"] = True

        saved = client.call(
            "information_manage_report", request_id="domestic-pressure-report", operation="create",
            config={"name": "native-domestic-pressure", "queries": [full_query], "detail": "raw"},
        )
        report_config = saved.get("report")
        require(isinstance(report_config, dict), "N04 report was not created")
        sub_result = client.call(
            "information_manage_subscription", request_id="domestic-pressure-subscription", operation="create",
            config={
                "name": "domestic-pressure-two-seconds", "kind": "periodic",
                "report_id": report_config["id"], "enabled": True,
                "schedule": {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"},
            },
        )
        subscription = sub_result.get("subscription")
        require(isinstance(subscription, dict), "N04 subscription was not created")
        deadline = time.monotonic() + args.wait_seconds
        periodic = []
        while time.monotonic() < deadline:
            listed = client.call("information_list_results", limit=50)
            periodic = [item for item in listed.get("results", [])
                        if isinstance(item, dict) and item.get("subscription_id") == subscription["id"]]
            if len(periodic) >= 3:
                break
            time.sleep(min(0.25, max(0.01, deadline - time.monotonic())))
        require(len(periodic) >= 3, f"Too few two-second N04 samples: {len(periodic)}")
        periodic = periodic[:3]
        for item in periodic:
            _check_result(item, list(FIELDS), reference, session.session_id, before["date_raw"])
            require(item.get("delivery", {}).get("status") == "delivered", "N04 periodic result was not delivered")
        write(args.output / "periodic-results.json", periodic)
        report["checks"]["three_two_second_samples_delivered"] = True
        report["periodic_results"] = len(periodic)

        cancelled = client.call(
            "information_manage_subscription", request_id="domestic-pressure-cancel", operation="cancel",
            subscription_id=subscription["id"], expected_version=subscription["version"],
        )
        require(cancelled.get("subscription", {}).get("state") == "cancelled", "N04 subscription was not cancelled")
        report["checks"]["subscription_cancelled_without_game_action"] = True
        final_status = client.call("information_status")
        write(args.output / "final-status-summary.json", {
            key: final_status[key] for key in ("status", "owner", "context", "reports", "subscriptions", "results")
            if key in final_status
        })
        client.close()
        client = None
        after = control_snapshot(pid, args.output / "after-control.json")
        require(before == after, "Control state changed")
        report["checks"]["pause_player_date_preserved"] = True
        report.update(
            status="passed",
            session_id=session.session_id,
            pid=pid,
            game_sha256=session.record["game_sha256"],
            date_raw=before["date_raw"],
            values=manual_values,
            source_sha256=sha(Path(__file__)),
            installation_sha256=sha(installation),
            mcp_wire_audit_sha256=sha(args.output / "mcp-wire-audit.json"),
            source_files={name: sha(ROOT / name) for name in (
                "bridge/information/domestic_pressure.py",
                "bridge/information/domestic_pressure_memory.py",
                "tools/serve_information.py",
            )},
        )
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        if client is not None:
            try:
                client.close()
            except Exception as exc:
                report.setdefault("cleanup_errors", []).append({"type": type(exc).__name__, "message": str(exc)})
        if pid is not None and before is not None and not (args.output / "after-control.json").exists():
            try:
                after = control_snapshot(pid, args.output / "after-control.json")
                report["final_control_equal"] = after == before
                if after != before:
                    report.setdefault("error", {"type": "ValueError", "message": "Control state changed"})
            except Exception as exc:
                report.setdefault("cleanup_errors", []).append({"type": type(exc).__name__, "message": str(exc)})
        audit_path = args.output / "mcp-wire-audit.json"
        if audit_path.exists():
            report["mcp_wire_audit_sha256"] = sha(audit_path)
        write(args.output / "report.json", report)
    print(json.dumps(report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
