"""Run one recorded MCP composition check for the synthetic NTXT fixture.

This helper is deliberately inert by default.  ``--run`` is required before
it creates an MCP server.  The battle v6 input must be produced by the small
C++ native-text chain; this script never calls the Python encoder and never
claims that its text bytes came from a game capture.  It composes the real
FRA v4 fixture with that synthetic extension, queries B04 details/raw_text,
reuses the result in a report, and delivers one read-only battle event.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import queue
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bridge.information.tools import TOOL_DEFINITIONS, validate_schema
from bridge.information.battle_native_text import project_native_text
from work.information_battle_native_text_wire import (
    decode,
    decode_envelope,
    validate_base_v5,
)
from work.validate_information_live import Client


STAGE = ROOT / "work/runtime/information-battle-native-text-20261027-001/mcp-recorded-001"
DEFAULT_V6 = STAGE / "native-chain-v6.bin"
DEFAULT_MANIFEST = STAGE / "recorded-manifest.json"
DEFAULT_STREAM = STAGE / "battle-stream.json"
DEFAULT_INPUT = STAGE / "recorded-input.json"
DEFAULT_SOURCE_PIN = STAGE / "source-pin.json"
MAX_WIRE_BYTES = 512 * 1024
GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
SESSION_ID = "31460-1dd653f69242d7b"
INSTALLATION = "c0e98ec51191d191"
GENERATION = "01dd653f69242d7b"
OBSERVER_REF = "0100007a00415246"
GAME_VERSION = "1.37.4"
GAME_DATE = 56557728
EVENT_ID = f"battle-observation:{INSTALLATION}:{GENERATION}:1"
DEFINITION_HEX = b"LANDBATTLEOVER".hex()
TITLE_HEX = b"Fixture battle title".hex()
LINE1_HEX = b"Fixture line 1".hex()


class RecordedClient(Client):
    """The normal MCP stdio client with a recorded-only server command."""

    def __init__(self, manifest: Path, stream: Path, output: Path, *, tick: float = 0.1):
        self.messages = queue.Queue()
        self.identifier = 0
        self.transcript = []
        self.stderr = (output / "mcp-stderr.txt").open("x", encoding="utf-8")
        self.path = output / "mcp-transcript.json"
        command = [
            sys.executable,
            "tools/serve_information.py",
            "--recorded-manifest", str(manifest),
            "--battle-stream", str(stream),
            "--database", str(output / "information.sqlite3"),
            "--tick-seconds", str(tick),
        ]
        self.process = subprocess.Popen(
            command, cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.stderr, text=True, encoding="utf-8", bufsize=1,
        )
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        self.rpc(
            "initialize",
            {"protocolVersion": "2025-03-26", "capabilities": {},
             "clientInfo": {"name": "recorded-native-text-acceptance", "version": "1"}},
        )
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def call(self, name: str, **arguments: Any) -> Any:
        definition = next(item for item in TOOL_DEFINITIONS if item["name"] == name)
        validate_schema(arguments, definition["inputSchema"], "arguments")
        return super().call(name, **arguments)


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json(path: Path, limit: int = 16 * 1024 * 1024) -> Any:
    path = path.resolve(strict=True)
    if path.stat().st_size > limit:
        raise ValueError(f"json_over_bound:{path}")
    with path.open("r", encoding="utf-8-sig") as stream:
        return json.load(stream)


def _write_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def _copy_once(source: Path, target: Path) -> None:
    if target.exists():
        raise FileExistsError(f"refusing_to_overwrite:{target}")
    shutil.copyfile(source, target)


def _request_namespace(output: Path) -> str:
    digest = hashlib.sha256(str(output.resolve()).encode("utf-8")).hexdigest()[:16]
    return f"native-text-recorded-{digest}"


def _request_id(namespace: str, suffix: str) -> str:
    return f"{namespace}-{suffix}"


def _validate_native_input(v6_path: Path, input_path: Path, source_pin_path: Path) -> dict[str, Any]:
    raw = v6_path.read_bytes()
    if not 0 < len(raw) <= MAX_WIRE_BYTES:
        raise ValueError("v6_payload_size_out_of_bound")
    composed = decode(raw)
    envelope = decode_envelope(raw)
    if composed.get("wire6", {}).get("version") != 6:
        raise ValueError("not_v6_payload")
    if composed.get("native_text", {}).get("complete") is not False:
        raise ValueError("native_text_must_remain_partial")
    native_text = composed.get("native_text")
    if not isinstance(native_text, dict):
        raise ValueError("native_text_missing")
    metadata = native_text.get("message_metadata")
    if not isinstance(metadata, dict) or metadata.get("native_date", {}).get("value") != 56557272:
        raise ValueError("native_date_mismatch")
    fields = native_text.get("text_fields")
    if not isinstance(fields, dict):
        raise ValueError("native_text_fields_missing")
    expected = {
        "definition_key": (DEFINITION_HEX, "message_metadata"),
        "auxiliary_text": ("", "message_metadata"),
        "title_helper_candidate": (TITLE_HEX, "title_helper_candidate"),
        "line1_text": (LINE1_HEX, "native_line1"),
    }
    for name, (raw_hex, source) in expected.items():
        value = fields.get(name)
        if not isinstance(value, dict) or value.get("status") != "known":
            raise ValueError(f"native_text_{name}_not_known")
        if value.get("raw_hex") != raw_hex or value.get("source") != source:
            raise ValueError(f"native_text_{name}_raw_or_source_mismatch")
    if envelope.get("message_metadata", {}).get("raw_flags", {}).get("raw_flag_8c") != 0xA1:
        raise ValueError("native_raw_flag_8c_mismatch")
    if envelope.get("message_metadata", {}).get("raw_flags", {}).get("raw_flag_8d") != 0x5E:
        raise ValueError("native_raw_flag_8d_mismatch")
    input_meta = _read_json(input_path, limit=128 * 1024)
    if not isinstance(input_meta, dict) or input_meta.get("producer") != "native-cpp-chain":
        raise ValueError("native_producer_pin_missing")
    if input_meta.get("text_origin") != "synthetic_fixture":
        raise ValueError("synthetic_fixture_marker_missing")
    if input_meta.get("native_v6_sha256") != _sha_bytes(raw):
        raise ValueError("native_v6_pin_mismatch")
    pin = _read_json(source_pin_path, limit=128 * 1024)
    if not isinstance(pin, dict) or pin.get("text_origin") != "synthetic_fixture":
        raise ValueError("source_pin_synthetic_marker_missing")
    base_path = source_pin_path.parent / "base-v5.bin"
    base = base_path.read_bytes()
    if not validate_base_v5(base):
        raise ValueError("base_v5_validation_failed")
    if envelope.get("base_v5_payload_hex") != base.hex():
        raise ValueError("v6_base_v5_bytes_changed")
    # The decoder's internal key is ``message_metadata``; the public battle
    # projection intentionally renames it to ``metadata``.  Compare MCP
    # output with that public projection rather than an internal wire shape.
    public_native_text = project_native_text(composed)
    return {
        "payload_bytes": len(raw), "payload_sha256": _sha_bytes(raw),
        "base_v5_bytes": len(base), "base_v5_sha256": _sha_bytes(base),
        "wire": envelope.get("wire"), "native_text": public_native_text,
        "text_origin": "synthetic_fixture", "producer": "native-cpp-chain",
    }


def _validate_context(value: dict[str, Any]) -> None:
    context = value.get("context")
    if not isinstance(context, dict):
        raise AssertionError("context_missing")
    expected = {
        "status": "ready", "mode": "recorded", "session_id": SESSION_ID,
        "observer": "FRA", "game_version": GAME_VERSION,
        "game_sha256": GAME_SHA256, "game_date": GAME_DATE,
    }
    for key, wanted in expected.items():
        if context.get(key) != wanted:
            raise AssertionError(f"context_{key}_mismatch:{context.get(key)!r}")


def _details_assertion(result: dict[str, Any], *, expected_native: dict[str, Any]) -> dict[str, Any]:
    _validate_context(result)
    if result.get("complete") is not False:
        raise AssertionError("composed_result_must_be_partial")
    items = result.get("items")
    if not isinstance(items, list) or len(items) != 1:
        raise AssertionError("expected_one_battle_item")
    fields = items[0].get("fields")
    if not isinstance(fields, dict):
        raise AssertionError("battle_fields_missing")
    details = fields.get("details")
    if not isinstance(details, dict) or details.get("status") != "known":
        raise AssertionError("details_not_known")
    projected = details.get("value", {}).get("native_text")
    if projected != expected_native:
        raise AssertionError("native_text_projection_mismatch")
    raw_text = fields.get("raw_text")
    # ``unsupported`` is the accurate adapter result while the full B04 raw
    # text path is not implemented.  A future source may use ``unknown``;
    # neither state may expose a value or be treated as complete.
    if not isinstance(raw_text, dict) or raw_text.get("status") not in {
            "unknown", "unsupported"}:
        raise AssertionError("raw_text_must_remain_unknown_or_unsupported")
    if "value" in raw_text:
        raise AssertionError("raw_text_unresolved_must_not_have_value")
    if "complete" in raw_text and raw_text.get("complete") is not False:
        raise AssertionError("raw_text_unresolved_must_not_be_complete")
    return fields


def _resume_response(path: Path, query: dict[str, Any], *, expected_native: dict[str, Any],
                     label: str) -> tuple[dict[str, Any], str]:
    """Validate a saved response without contacting the MCP server."""
    response = _read_json(path, limit=16 * 1024 * 1024)
    if not isinstance(response, dict):
        raise ValueError(f"{label}_response_not_object")
    if response.get("request_id") is None and label == "query":
        raise ValueError("query_resume_request_id_missing")
    items = response.get("items")
    if not isinstance(items, list) or len(items) != 1:
        raise ValueError(f"{label}_resume_item_count_invalid")
    saved_query = items[0].get("query")
    if saved_query != query:
        raise ValueError(f"{label}_resume_query_shape_mismatch")
    _details_assertion(response, expected_native=expected_native)
    return response, str(response.get("request_id") or "")


def run(v6_path: Path, manifest: Path, stream: Path, input_path: Path,
        source_pin: Path, output: Path, *, resume_query: Path | None = None,
        resume_report_query: Path | None = None) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=False)
    v6_path = v6_path.resolve(strict=True)
    manifest = manifest.resolve(strict=True)
    stream = stream.resolve(strict=True)
    input_path = input_path.resolve(strict=True)
    source_pin = source_pin.resolve(strict=True)
    native = _validate_native_input(v6_path, input_path, source_pin)
    stream_config = _read_json(stream, limit=16 * 1024)
    recorded_manifest = _read_json(manifest, limit=128 * 1024)
    if stream_config.get("schema") != "EU4-BATTLE-STREAM/1":
        raise ValueError("battle_stream_schema_mismatch")
    binding = stream_config.get("binding")
    if not isinstance(binding, dict) or binding.get("mode") != "recorded":
        raise ValueError("recorded_battle_binding_missing")
    for key, wanted in (("session_id", SESSION_ID), ("installation", INSTALLATION),
                        ("generation", GENERATION), ("game_sha256", GAME_SHA256),
                        ("observer_ref", OBSERVER_REF)):
        if binding.get(key) != wanted:
            raise ValueError(f"battle_binding_{key}_mismatch")
    for key, wanted in (("status", "ready"), ("session_id", SESSION_ID),
                        ("game_version", GAME_VERSION), ("game_sha256", GAME_SHA256),
                        ("observer", "FRA"), ("game_date", GAME_DATE),
                        ("text_origin", "synthetic_fixture")):
        if recorded_manifest.get(key) != wanted:
            raise ValueError(f"recorded_manifest_{key}_mismatch")
    database = stream.parent / stream_config["database"]
    if not database.is_file():
        raise ValueError("battle_stream_database_missing")
    with sqlite3.connect(database) as connection:
        row = connection.execute("SELECT payload_sha256,total_bytes FROM complete_messages WHERE group_id=1").fetchone()
    if row != (native["payload_sha256"], native["payload_bytes"]):
        raise ValueError("battle_stream_payload_pin_mismatch")

    # Keep complete source bytes with the acceptance artifact for offline
    # replay.  All targets are new files in the new acceptance directory.
    _copy_once(v6_path, output / "native-chain-v6.bin")
    _copy_once(source_pin.parent / "base-v5.bin", output / "base-v5.bin")
    _copy_once(source_pin.parent / "fixture-v4-payload.bin", output / "fixture-v4-payload.bin")
    _write_json(output / "input-pins.json", {
        "schema": "information_battle_native_text_recorded_mcp_input_pin.v1",
        "text_origin": "synthetic_fixture", "native_producer": "native-cpp-chain",
        "v6": native, "source_pin": str(source_pin),
        "manifest": str(manifest), "battle_stream": str(stream),
        "database": str(database), "database_payload_sha256": _sha_file(database),
    })

    namespace = _request_namespace(output)
    query = {"topic": "B04", "object": {"type": "battle"},
             "fields": ["details", "raw_text"], "parameters": {"event_id": EVENT_ID}}
    report = {
        "schema": "information_battle_native_text_recorded_mcp_acceptance.v1",
        "status": "failed", "mode": "recorded", "text_origin": "synthetic_fixture",
        "native_producer": "native-cpp-chain", "session_id": SESSION_ID,
        "game_version": GAME_VERSION, "game_sha256": GAME_SHA256,
        "game_date": GAME_DATE, "observer": "FRA", "event_id": EVENT_ID,
        "request_namespace": namespace, "checks": {}, "periodic_results": 0,
        "business_actions_submitted": 0, "game_access": False,
        "native_game_capture": False, "raw_text_complete": False,
        "query_reused": resume_query is not None,
        "report_query_reused": resume_report_query is not None,
    }
    client: RecordedClient | None = None
    subscription: dict[str, Any] | None = None
    try:
        client = RecordedClient(manifest, stream, output)
        discovery = client.call("information_discover")
        _write_json(output / "discovery.json", discovery)
        topic = next((item for item in discovery.get("topics", [])
                      if item.get("topic_id") == "B04"), None)
        if not isinstance(topic, dict):
            raise AssertionError("B04_not_discoverable")
        topic_fields = topic.get("fields", {})
        if not all(name in topic_fields for name in ("details", "raw_text")):
            raise AssertionError("B04_details_or_raw_text_not_discoverable")
        report["checks"]["recorded_discovery_exposes_details_and_raw_text"] = True

        request_id = _request_id(namespace, "query")
        query_request = {"tool": "information_query", "request_id": request_id,
                         "queries": [query], "source": "new_mcp_query"}
        if resume_query is not None:
            resume_query = resume_query.resolve(strict=True)
            query_result, request_id = _resume_response(
                resume_query, query, expected_native=native["native_text"], label="query")
            query_request.update({
                "request_id": request_id, "source": "resumed_successful_response",
                "response_path": str(resume_query),
                "response_sha256": _sha_file(resume_query),
            })
        else:
            query_result = client.call("information_query", request_id=request_id, queries=[query])
        _write_json(output / "query-request.json", query_request)
        _write_json(output / "query.json", query_result)
        fields = _details_assertion(query_result, expected_native=native["native_text"])
        raw_status = fields["raw_text"]["status"]
        report["checks"]["query_composes_v6_native_text_and_unresolved_raw_text"] = True
        report["checks"]["original_query_response_reused_without_resubmit"] = (
            resume_query is not None
        )
        report["query_request_id"] = request_id
        report["raw_text_status"] = raw_status
        report["query_fields"] = fields

        report_config = client.call(
            "information_manage_report", request_id=_request_id(namespace, "report-create"),
            operation="create", config={"name": "recorded native battle text",
                                         "detail": "full", "queries": [query]},
        )
        _write_json(output / "report-create.json", report_config)
        saved_report = report_config.get("report")
        if not isinstance(saved_report, dict) or not isinstance(saved_report.get("id"), str):
            raise AssertionError("report_id_missing")
        report_request_id = _request_id(namespace, "report-query")
        report_request = {"tool": "information_query", "request_id": report_request_id,
                          "report_id": saved_report["id"], "source": "new_mcp_query"}
        if resume_report_query is not None:
            resume_report_query = resume_report_query.resolve(strict=True)
            report_result, old_report_request_id = _resume_response(
                resume_report_query, query, expected_native=native["native_text"],
                label="report")
            report_request.update({
                "request_id": old_report_request_id, "source": "resumed_successful_response",
                "response_path": str(resume_report_query),
                "response_sha256": _sha_file(resume_report_query),
                "new_report_id": saved_report["id"],
            })
        else:
            report_result = client.call(
                "information_query", request_id=report_request_id,
                report_id=saved_report["id"],
            )
        _write_json(output / "report-query-request.json", report_request)
        _write_json(output / "report-query.json", report_result)
        _details_assertion(report_result, expected_native=native["native_text"])
        report["report_query_request_id"] = report_request.get("request_id")
        report["checks"]["report_query_response_reused_without_resubmit"] = (
            resume_report_query is not None
        )
        report["checks"]["report_reuses_same_partial_native_text_projection"] = True

        subscription_result = client.call(
            "information_manage_subscription", request_id=_request_id(namespace, "event-create"),
            operation="create", config={
                "name": "recorded native battle event", "kind": "event",
                "report_id": saved_report["id"], "enabled": True,
                "binding": {"session_id": SESSION_ID, "observer": "FRA",
                             "game_version": GAME_VERSION, "game_sha256": GAME_SHA256},
                "event": {"types": ["battle_observation"]},
            },
        )
        _write_json(output / "subscription-create.json", subscription_result)
        subscription = subscription_result.get("subscription")
        if not isinstance(subscription, dict) or subscription.get("state") != "active":
            raise AssertionError("event_subscription_not_active")
        deadline = time.monotonic() + 15.0
        event_results: list[dict[str, Any]] = []
        while time.monotonic() < deadline:
            listed = client.call("information_list_results", limit=50)
            event_results = [item for item in listed.get("results", [])
                             if item.get("subscription_id") == subscription["id"]]
            if event_results:
                break
            time.sleep(0.2)
        _write_json(output / "event-results.json", event_results)
        if len(event_results) != 1:
            raise AssertionError(f"expected_one_event_result:{len(event_results)}")
        event_result = event_results[0]
        if event_result.get("delivery", {}).get("status") != "delivered":
            raise AssertionError("event_not_delivered")
        _details_assertion(event_result, expected_native=native["native_text"])
        report["periodic_results"] = 0
        report["checks"]["one_event_delivery_reuses_partial_native_text"] = True

        cancelled = client.call(
            "information_manage_subscription", request_id=_request_id(namespace, "event-cancel"),
            operation="cancel", subscription_id=subscription["id"],
            expected_version=subscription["version"],
        )
        _write_json(output / "subscription-cancel.json", cancelled)
        subscription = cancelled.get("subscription", subscription)
        listed = client.call(
            "information_manage_subscription", request_id=_request_id(namespace, "subscription-list"),
            operation="list",
        )
        _write_json(output / "subscriptions-after.json", listed)
        if any(item.get("state") == "active" for item in listed.get("subscriptions", [])):
            raise AssertionError("active_subscription_after_cancel")
        report["checks"]["event_cancel_and_no_active_subscription"] = True
        report["status"] = "passed"
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        if client is not None:
            try:
                if subscription is not None and subscription.get("state") == "active":
                    try:
                        client.call(
                            "information_manage_subscription", request_id=_request_id(namespace, "cleanup-cancel"),
                            operation="cancel", subscription_id=subscription["id"],
                            expected_version=subscription["version"],
                        )
                    except Exception as cleanup_error:
                        report["cleanup_cancel_error"] = str(cleanup_error)
            finally:
                try:
                    client.close()
                except Exception as close_error:
                    report["cleanup_close_error"] = str(close_error)
                report["server_exit_code"] = client.process.returncode
        _write_json(output / "report.json", report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="run recorded MCP acceptance")
    parser.add_argument("--v6-payload", type=Path, default=DEFAULT_V6)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--battle-stream", type=Path, default=DEFAULT_STREAM)
    parser.add_argument("--recorded-input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--source-pin", type=Path, default=DEFAULT_SOURCE_PIN)
    parser.add_argument("--resume-query", type=Path,
                        help="reuse a previously saved successful query response")
    parser.add_argument("--resume-report-query", type=Path,
                        help="reuse a previously saved successful report response")
    parser.add_argument("--output", type=Path,
                        default=STAGE / "mcp-recorded-acceptance-001")
    args = parser.parse_args(argv)
    if not args.run:
        print(json.dumps({"status": "idle", "hint": "pass --run to execute recorded MCP"}))
        return 0
    try:
        result = run(
            *(path.resolve() for path in (
                args.v6_payload, args.manifest, args.battle_stream,
                args.recorded_input, args.source_pin, args.output,
            )),
            resume_query=args.resume_query.resolve() if args.resume_query else None,
            resume_report_query=(args.resume_report_query.resolve()
                                 if args.resume_report_query else None),
        )
    except (OSError, ValueError, RuntimeError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps({"status": result.get("status"), "checks": result.get("checks"),
                      "output": str(args.output)}, ensure_ascii=False, sort_keys=True))
    return 0 if result.get("status") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
