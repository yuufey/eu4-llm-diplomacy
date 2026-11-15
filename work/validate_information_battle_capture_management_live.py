"""Validate the managed live battle-capture lifecycle through MCP.

The runner is inert until it is invoked with concrete live paths.  It starts
one operator-bound information server with ``--battle-manage-capture``, drives
two event subscriptions through the capture lease transitions, and records
the actual ``capture`` status after every transition.  The optional
``--test-only`` mode invokes the existing natural-window helper exactly once;
that helper remains the only process allowed to advance the paused test game.

This validator does not install a DLL, inject a process, submit diplomacy, or
retry an ambiguous natural-window dispatch.  The live path is intentionally
separate from the offline compile/fake path used by tests.
"""

from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import time
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bridge.information.tools import validate_schema


GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
GAME_VERSION = "1.37.4"
HEX16 = re.compile(r"^[0-9a-f]{16}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_PLAYER_TAGS = ("POR", "FRA")
MAX_JSON_BYTES = 512 * 1024
DEFAULT_EXPECTED_DATE = 56561088
DEFAULT_DAYS = 35


class AcceptanceUnavailable(RuntimeError):
    """The requested live acceptance has no safe bounded input."""


def _read_json(path: Path, *, limit: int = MAX_JSON_BYTES) -> Any:
    path = path.resolve(strict=True)
    size = path.stat().st_size
    if size <= 0 or size > limit:
        raise AcceptanceUnavailable(f"json_size_out_of_bound:{path}:{size}")
    with path.open("r", encoding="utf-8-sig") as stream:
        return json.load(stream)


def _write_json_new(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()


def _write_text_new(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(value)
        if value and not value.endswith("\n"):
            stream.write("\n")


def _fullref_tag(value: Any) -> str | None:
    if not isinstance(value, str) or HEX16.fullmatch(value) is None:
        return None
    try:
        raw = int(value, 16).to_bytes(8, "little")[:3].decode("ascii")
    except (OverflowError, UnicodeDecodeError):
        return None
    return raw if re.fullmatch(r"[A-Z0-9]{3}", raw) else None


def _require_int(value: Any, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or type(value) is not int:
        raise AcceptanceUnavailable(f"{label}_must_be_integer")
    if positive and value <= 0:
        raise AcceptanceUnavailable(f"{label}_must_be_positive")
    if value < 0:
        raise AcceptanceUnavailable(f"{label}_must_be_nonnegative")
    return value


def _load_live_inputs(installation_path: Path, stream_path: Path,
                      database_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    installation_path = installation_path.resolve(strict=True)
    stream_path = stream_path.resolve(strict=True)
    database_path = database_path.resolve()
    installation = _read_json(installation_path)
    if not isinstance(installation, dict):
        raise AcceptanceUnavailable("installation_not_object")
    session_id = installation.get("session_id")
    game_sha256 = installation.get("game_sha256")
    if not isinstance(session_id, str) or not session_id:
        raise AcceptanceUnavailable("installation_session_missing")
    if game_sha256 != GAME_SHA256:
        raise AcceptanceUnavailable("installation_game_sha_mismatch")
    creation = _require_int(installation.get("creation_filetime"), "creation_filetime", positive=True)

    stream = _read_json(stream_path, limit=256 * 1024)
    if (not isinstance(stream, dict)
            or set(stream) != {"schema", "database", "binding"}
            or stream.get("schema") != "EU4-BATTLE-STREAM/1"):
        raise AcceptanceUnavailable("battle_stream_shape_mismatch")
    configured_database = stream.get("database")
    if not isinstance(configured_database, str) or not configured_database:
        raise AcceptanceUnavailable("battle_stream_database_missing")
    configured_path = Path(configured_database)
    if not configured_path.is_absolute():
        configured_path = stream_path.parent / configured_path
    if configured_path.resolve() != database_path:
        raise AcceptanceUnavailable("battle_stream_database_differs_from_cli_database")
    if database_path.exists():
        raise AcceptanceUnavailable("database_must_be_new")

    binding = stream.get("binding")
    if not isinstance(binding, dict):
        raise AcceptanceUnavailable("battle_stream_binding_missing")
    if binding.get("mode") != "live":
        raise AcceptanceUnavailable("battle_stream_binding_not_live")
    if binding.get("game_sha256") != game_sha256:
        raise AcceptanceUnavailable("battle_stream_game_sha_mismatch")
    if binding.get("session_id") != session_id:
        raise AcceptanceUnavailable("battle_stream_session_mismatch")
    if binding.get("process_creation_filetime") != creation:
        raise AcceptanceUnavailable("battle_stream_creation_mismatch")
    for key in ("installation", "generation", "observer_ref"):
        if not isinstance(binding.get(key), str) or HEX16.fullmatch(binding[key]) is None:
            raise AcceptanceUnavailable(f"battle_stream_{key}_invalid")
    if _fullref_tag(binding["observer_ref"]) != "FRA":
        raise AcceptanceUnavailable("battle_stream_observer_must_be_FRA")
    return {
        "path": installation_path,
        "pid": installation.get("pid"),
        "creation_filetime": creation,
        "session_id": session_id,
        "game_sha256": game_sha256,
        "dll_sha256": installation.get("dll_sha256"),
    }, deepcopy(binding)


def _request_namespace(output: Path) -> str:
    # The absolute output path is stable within one acceptance and keeps all
    # request IDs unique without borrowing historical IDs.
    import hashlib
    digest = hashlib.sha256(str(output.resolve()).encode("utf-8")).hexdigest()[:16]
    return f"battle-capture-{digest}"


class StdioClient:
    """Small MCP stdio client that persists each successful wire exchange."""

    def __init__(self, installation: Path, stream: Path, database: Path,
                 output: Path, *, tick_seconds: float = 0.0):
        self.output = output
        self.messages: queue.Queue[dict[str, Any]] = queue.Queue()
        self.transcript: list[dict[str, Any]] = []
        self._rpc_id = 0
        self._wire_index = 0
        self._tool_index = 0
        self._closed = False
        self.tool_schemas: dict[str, Mapping[str, Any]] = {}
        stderr_path = output / "server-stderr.txt"
        self.stderr = stderr_path.open("x", encoding="utf-8")
        command = [
            sys.executable, str(ROOT / "tools/serve_information.py"),
            "--operator-session", str(installation), "--observer", "FRA",
            "--database", str(database), "--journal", str(output / "diplomacy.sqlite3"),
            "--battle-stream", str(stream),
            "--battle-ingest-installation", str(installation),
            "--battle-manage-capture", "--tick-seconds", str(tick_seconds),
        ]
        try:
            self.process = subprocess.Popen(
                command, cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=self.stderr, text=True, encoding="utf-8", bufsize=1,
            )
        except Exception:
            self.stderr.close()
            raise
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        try:
            self.rpc("initialize", {
                "protocolVersion": "2025-03-26", "capabilities": {},
                "clientInfo": {"name": "battle-capture-management", "version": "1"},
            })
            self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        except Exception:
            self.close()
            raise

    @property
    def last_tool_index(self) -> int:
        return self._tool_index

    def _read(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            if not line.strip():
                continue
            try:
                self.messages.put(json.loads(line))
            except ValueError:
                self.messages.put({"invalid_json": line})
        self.messages.put({"eof": True})

    def send(self, value: dict[str, Any]) -> None:
        self.transcript.append({"direction": "request", "at": time.time(), "body": value})
        if self.process.stdin is None:
            raise RuntimeError("mcp_stdin_unavailable")
        self.process.stdin.write(json.dumps(value, ensure_ascii=False) + "\n")
        self.process.stdin.flush()

    def _save_wire(self, request: dict[str, Any], response: dict[str, Any]) -> None:
        self._wire_index += 1
        prefix = f"mcp-wire-{self._wire_index:04d}"
        _write_json_new(self.output / f"{prefix}-request.json", request)
        _write_json_new(self.output / f"{prefix}-response.json", response)

    def rpc(self, method: str, params: Mapping[str, Any]) -> dict[str, Any]:
        self._rpc_id += 1
        request = {"jsonrpc": "2.0", "id": self._rpc_id,
                   "method": method, "params": dict(params)}
        self.send(request)
        deadline = time.monotonic() + 120
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"mcp_timeout:{method}")
            try:
                response = self.messages.get(timeout=min(remaining, 5.0))
            except queue.Empty:
                continue
            if response.get("eof"):
                raise RuntimeError(f"mcp_eof:{method}")
            if response.get("id") != self._rpc_id:
                self.transcript.append({"direction": "unsolicited", "at": time.time(), "body": response})
                continue
            self.transcript.append({"direction": "response", "at": time.time(), "body": response})
            self._save_wire(request, response)
            if "error" in response:
                raise RuntimeError(f"mcp_rpc_error:{response['error']}")
            result = response.get("result")
            if not isinstance(result, dict):
                raise RuntimeError(f"mcp_result_not_object:{method}")
            return result

    def set_tool_schemas(self, definitions: Mapping[str, Mapping[str, Any]]) -> None:
        self.tool_schemas = dict(definitions)

    def call(self, name: str, **arguments: Any) -> dict[str, Any]:
        schema = self.tool_schemas.get(name)
        if schema is not None:
            validate_schema(arguments, schema, "arguments")
        result = self.rpc("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError") is True:
            raise RuntimeError(f"mcp_tool_error:{name}")
        content = result.get("content")
        if not isinstance(content, list) or not content or not isinstance(content[0], dict):
            raise RuntimeError(f"mcp_tool_content_missing:{name}")
        text = content[0].get("text")
        if not isinstance(text, str):
            raise RuntimeError(f"mcp_tool_text_missing:{name}")
        value = json.loads(text)
        if not isinstance(value, dict):
            raise RuntimeError(f"mcp_tool_value_not_object:{name}")
        if "error" in value:
            raise RuntimeError(f"mcp_tool_value_error:{name}:{value['error']}")
        self._tool_index += 1
        prefix = f"tool-{self._tool_index:04d}-{name}"
        _write_json_new(self.output / f"{prefix}-request.json", {
            "tool": name, "arguments": arguments,
        })
        _write_json_new(self.output / f"{prefix}-response.json", value)
        return value

    def close(self) -> int | None:
        if self._closed:
            return self.process.returncode
        self._closed = True
        try:
            if self.process.stdin is not None:
                self.process.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        try:
            self.process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=15)
        finally:
            self.reader.join(timeout=3)
            self.stderr.close()
            if not (self.output / "mcp-transcript.json").exists():
                _write_json_new(self.output / "mcp-transcript.json", self.transcript)
        return self.process.returncode


def _capture_snapshot(status: Mapping[str, Any]) -> dict[str, Any]:
    capture = status.get("capture")
    if not isinstance(capture, Mapping):
        raise AcceptanceUnavailable("capture_status_missing")
    subscriptions = []
    for row in status.get("subscriptions", []):
        if not isinstance(row, Mapping):
            continue
        subscription = row.get("subscription", {})
        runtime = row.get("runtime", {})
        if isinstance(subscription, Mapping):
            subscriptions.append({
                "id": subscription.get("id"), "state": subscription.get("state"),
                "version": subscription.get("version"),
                "runtime_state": runtime.get("state") if isinstance(runtime, Mapping) else None,
            })
    capture_copy = {
        key: deepcopy(capture.get(key))
        for key in ("status", "managed", "owned", "consumer_count", "consumers",
                    "producer_state", "reason", "complete", "mode")
        if key in capture
    }
    return {
        "capture": capture_copy,
        "native": {
            "producer_state": capture.get("producer_state"),
            "owned": capture.get("owned"),
            "consumer_count": capture.get("consumer_count"),
            "reason": capture.get("reason"),
        },
        "context": deepcopy(status.get("context")),
        "subscriptions": subscriptions,
        "event_source": deepcopy(status.get("event_source")),
    }


def _assert_snapshot(snapshot: Mapping[str, Any], *, producer_state: str,
                     owned: bool, consumer_count: int) -> None:
    capture = snapshot["capture"]
    if capture.get("managed") is not True:
        raise AssertionError(f"capture_not_managed:{capture}")
    if capture.get("producer_state") != producer_state:
        raise AssertionError(f"capture_producer_state:{capture}")
    if capture.get("owned") is not owned:
        raise AssertionError(f"capture_owned:{capture}")
    if capture.get("consumer_count") != consumer_count:
        raise AssertionError(f"capture_consumer_count:{capture}")


def _event_results(value: Mapping[str, Any], subscription_id: str) -> list[dict[str, Any]]:
    result = []
    for item in value.get("results", []):
        if not isinstance(item, Mapping) or item.get("subscription_id") != subscription_id:
            continue
        if item.get("trigger") != "event" or not isinstance(item.get("event"), Mapping):
            continue
        result.append(dict(item))
    return result


def _request_id(namespace: str, name: str) -> str:
    return f"{namespace}-{name}"


def _step(client: StdioClient, report: dict[str, Any], label: str,
          tool: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
    value = client.call(tool, **dict(arguments))
    report.setdefault("steps", []).append({
        "label": label, "tool": tool, "tool_index": client.last_tool_index,
        "status": "success",
    })
    return value


def _status_step(client: StdioClient, report: dict[str, Any], label: str,
                 expected: tuple[str, bool, int] | None = None) -> dict[str, Any]:
    value = _step(client, report, label, "information_status", {})
    snapshot = _capture_snapshot(value)
    report.setdefault("lifecycle", []).append({"label": label, **snapshot})
    if expected is not None:
        _assert_snapshot(snapshot, producer_state=expected[0], owned=expected[1],
                         consumer_count=expected[2])
    return value


def _manage_subscription(client: StdioClient, report: dict[str, Any], namespace: str,
                         label: str, operation: str, *, subscription: Mapping[str, Any] | None = None,
                         config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    arguments: dict[str, Any] = {
        "request_id": _request_id(namespace, label), "operation": operation,
    }
    if subscription is not None:
        arguments["subscription_id"] = subscription["id"]
        arguments["expected_version"] = subscription["version"]
    if config is not None:
        arguments["config"] = dict(config)
    value = _step(client, report, label, "information_manage_subscription", arguments)
    result = value.get("subscription")
    if not isinstance(result, dict):
        raise AssertionError(f"subscription_missing:{label}")
    return result


def _delivery_arguments(client: StdioClient, tool: str) -> dict[str, Any]:
    """Use only arguments advertised by the live server's delivery schema."""
    schema = client.tool_schemas.get(tool, {})
    properties = schema.get("properties", {}) if isinstance(schema, Mapping) else {}
    return {"limit": 100} if isinstance(properties, Mapping) and "limit" in properties else {}


def _run_natural_window(args: argparse.Namespace, installation: Path,
                        output: Path, report: dict[str, Any]) -> None:
    if not args.test_only:
        report["natural_window"] = {"status": "not_requested"}
        return
    if args.expected_manifest_sha256 is None or args.expected_dll_sha256 is None:
        raise AcceptanceUnavailable("test_only_requires_expected_manifest_and_dll_sha256")
    for name, value in (("expected_manifest_sha256", args.expected_manifest_sha256),
                        ("expected_dll_sha256", args.expected_dll_sha256)):
        if HEX64.fullmatch(value) is None:
            raise AcceptanceUnavailable(f"{name}_must_be_lowercase_sha256")
    natural_output = ((args.natural_window_output or (output / "natural-window")).resolve())
    if natural_output.exists():
        raise AcceptanceUnavailable(f"natural_window_output_exists:{natural_output}")
    runtime_root = (ROOT / "work/runtime").resolve()
    try:
        natural_output.relative_to(runtime_root)
    except ValueError as exc:
        raise AcceptanceUnavailable("natural_window_output_must_be_under_work_runtime") from exc
    command = [
        sys.executable, str(ROOT / "work/run_information_battle_natural_window_installed.py"),
        "--installation", str(installation),
        "--expected-manifest-sha256", args.expected_manifest_sha256,
        "--expected-dll-sha256", args.expected_dll_sha256,
        "--days", str(args.days), "--expected-date", str(args.expected_date),
        "--expected-player-tag", getattr(args, "expected_player_tag", "POR"),
        "--output-dir", str(natural_output), "--test-only",
    ]
    started = time.time()
    timed_out = False
    try:
        completed = subprocess.run(
            command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
            timeout=240,
        )
        stdout, stderr, returncode = completed.stdout, completed.stderr, completed.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        returncode = None
    _write_text_new(output / "natural-window-stdout.txt", stdout)
    _write_text_new(output / "natural-window-stderr.txt", stderr)
    natural_report = None
    report_path = natural_output / "report.json"
    if report_path.is_file():
        try:
            natural_report = _read_json(report_path, limit=2 * 1024 * 1024)
        except Exception as error:
            natural_report = {"status": "unreadable", "error": f"{type(error).__name__}:{error}"}
    report["natural_window"] = {
        "status": (natural_report.get("status") if isinstance(natural_report, Mapping)
                   else "timeout" if timed_out else "missing_report"),
        "returncode": returncode, "timed_out": timed_out,
        "days": args.days, "expected_date": args.expected_date,
        "expected_physical_player_tag": getattr(args, "expected_player_tag", "POR"),
        "output": str(natural_output), "elapsed_seconds": time.time() - started,
        "report": natural_report,
        "no_retry": True,
    }


def run(args: argparse.Namespace) -> int:
    output = args.output.resolve()
    if output.exists():
        raise AssertionError(f"refusing_to_overwrite_output:{output}")
    output.mkdir(parents=True, exist_ok=False)
    report: dict[str, Any] = {
        "schema": "information_battle_capture_management_live.v1",
        "status": "running", "mode": "live", "mcp_started": False,
        "inputs": {
            "installation": str(args.installation), "battle_stream": str(args.battle_stream),
            "database": str(args.database), "output": str(output),
            "database_role": "shared service report/subscription DB and configured battle-ingest DB; must be new",
            "natural_window_output": str(args.natural_window_output) if args.natural_window_output else None,
            "test_only": bool(args.test_only), "expected_date": args.expected_date,
            "days": args.days,
            "expected_physical_player_tag": getattr(args, "expected_player_tag", "POR"),
        },
        "checks": {}, "steps": [], "lifecycle": [],
        "limitations": [
            "This validator never installs or injects a native module.",
            "Natural-window dispatch is attempted at most once and only with explicit --test-only.",
            "The current server exposes information_list_results as the durable delivery listing tool.",
        ],
    }
    client: StdioClient | None = None
    subscriptions: dict[str, dict[str, Any]] = {}
    namespace = _request_namespace(output)
    try:
        installation, stream_binding = _load_live_inputs(
            args.installation, args.battle_stream, args.database)
        report["identity"] = {
            key: installation.get(key)
            for key in ("pid", "creation_filetime", "session_id", "game_sha256", "dll_sha256")
        }
        report["binding"] = {
            key: stream_binding.get(key)
            for key in ("installation", "generation", "observer_ref", "session_id",
                        "process_creation_filetime", "mode")
        }
        client = StdioClient(installation["path"], args.battle_stream.resolve(),
                             args.database.resolve(), output)
        report["mcp_started"] = True
        listed = client.rpc("tools/list", {})
        definitions = {
            item["name"]: item["inputSchema"]
            for item in listed.get("tools", [])
            if isinstance(item, Mapping) and isinstance(item.get("name"), str)
            and isinstance(item.get("inputSchema"), Mapping)
        }
        required_tools = {
            "information_discover", "information_manage_report",
            "information_manage_subscription", "information_status",
            "information_tick",
        }
        if not required_tools.issubset(definitions):
            raise AssertionError(f"mcp_tool_schema_missing:{sorted(required_tools - set(definitions))}")
        delivery_tool = ("information_list_deliveries"
                         if "information_list_deliveries" in definitions
                         else "information_list_results")
        if delivery_tool not in definitions:
            raise AssertionError("mcp_delivery_listing_tool_missing")
        client.set_tool_schemas(definitions)
        report["tool_schema"] = {
            "names": sorted(definitions), "delivery_listing_tool": delivery_tool,
        }

        discovery = _step(client, report, "discover", "information_discover", {})
        topics = discovery.get("topics", [])
        b04 = next((item for item in topics if isinstance(item, Mapping)
                    and item.get("topic_id") == "B04"), None)
        if not isinstance(b04, Mapping):
            raise AssertionError("B04_not_discoverable")
        fields_meta = b04.get("fields")
        if not isinstance(fields_meta, Mapping):
            raise AssertionError("B04_fields_missing")
        fields = [field for field in ("details", "raw_text") if field in fields_meta]
        if not fields:
            raise AssertionError("B04_text_fields_missing")
        if "event" not in b04.get("triggers", []):
            raise AssertionError("B04_event_trigger_missing")
        report["checks"]["tool_schemas_and_B04_event_capability"] = True
        query = {"topic": "B04", "object": {"type": "battle"}, "fields": fields}
        report_config = _step(client, report, "report-create", "information_manage_report", {
            "request_id": _request_id(namespace, "report-create"), "operation": "create",
            "config": {"name": "managed live battle capture", "detail": "raw", "queries": [query]},
        })
        report_value = report_config.get("report")
        if not isinstance(report_value, Mapping) or not isinstance(report_value.get("id"), str):
            raise AssertionError("report_id_missing")
        report_id = report_value["id"]
        subscription_binding = {
            "session_id": installation["session_id"], "observer": "FRA",
            "game_version": GAME_VERSION, "game_sha256": GAME_SHA256,
        }
        base_config = {
            "kind": "event", "report_id": report_id, "enabled": True,
            "binding": subscription_binding,
            "event": {"types": ["battle_observation"]},
        }

        sub1 = _manage_subscription(client, report, namespace, "sub1-create", "create",
                                    config=dict(base_config, name="managed-battle-sub1"))
        if sub1.get("state") != "active":
            raise AssertionError(f"sub1_not_active:{sub1}")
        subscriptions["sub1"] = sub1
        _status_step(client, report, "after-sub1-create", expected=("enabled", True, 1))
        report["checks"]["sub1_manager_enabled_owned_one"] = True

        sub2 = _manage_subscription(client, report, namespace, "sub2-create", "create",
                                    config=dict(base_config, name="managed-battle-sub2"))
        if sub2.get("state") != "active":
            raise AssertionError(f"sub2_not_active:{sub2}")
        subscriptions["sub2"] = sub2
        _status_step(client, report, "after-sub2-create", expected=("enabled", True, 2))
        report["checks"]["sub2_added_as_second_consumer"] = True

        sub2 = _manage_subscription(client, report, namespace, "sub2-pause", "pause", subscription=sub2)
        subscriptions["sub2"] = sub2
        _status_step(client, report, "after-sub2-pause", expected=("enabled", True, 1))
        sub2 = _manage_subscription(client, report, namespace, "sub2-cancel", "cancel", subscription=sub2)
        subscriptions["sub2"] = sub2
        _status_step(client, report, "after-sub2-cancel", expected=("enabled", True, 1))
        report["checks"]["sub2_pause_cancel_keeps_sub1_enabled_owned"] = True

        sub1 = _manage_subscription(client, report, namespace, "sub1-pause", "pause", subscription=sub1)
        subscriptions["sub1"] = sub1
        _status_step(client, report, "after-sub1-pause", expected=("disabled", False, 0))
        report["checks"]["last_consumer_pause_disables_capture"] = True

        sub1 = _manage_subscription(client, report, namespace, "sub1-resume", "resume", subscription=sub1)
        subscriptions["sub1"] = sub1
        _status_step(client, report, "after-sub1-resume", expected=("enabled", True, 1))
        report["checks"]["resume_reenables_owned_capture"] = True

        # Drain retained records before time advances. A pre-existing battle
        # must not be presented as evidence of future capture.
        delivery_args = _delivery_arguments(client, delivery_tool)
        _step(client, report, "pre-window-tick", "information_tick", {})
        retained = _step(client, report, "pre-window-deliveries", delivery_tool, delivery_args)
        retained_ids = {item.get("event", {}).get("event_id")
                        for item in _event_results(retained, sub1["id"])}
        report["retained_event_ids_before_window"] = sorted(retained_ids)
        _run_natural_window(args, installation["path"], output, report)
        if args.test_only and report["natural_window"]["status"] != "observed_target_and_paused":
            raise AssertionError("natural_window_not_observed_target_and_paused_no_retry")
        first_tick = _step(client, report, "post-window-tick-1", "information_tick", {})
        first_delivery = _step(client, report, "post-window-deliveries-1", delivery_tool, delivery_args)
        second_tick = _step(client, report, "post-window-tick-2", "information_tick", {})
        second_delivery = _step(client, report, "post-window-deliveries-2", delivery_tool, delivery_args)
        del first_tick, second_tick
        first_events = _event_results(first_delivery, sub1["id"])
        second_events = _event_results(second_delivery, sub1["id"])
        first_keys = [(item.get("subscription_id"), item.get("event", {}).get("event_id"))
                      for item in first_events]
        second_keys = [(item.get("subscription_id"), item.get("event", {}).get("event_id"))
                       for item in second_events]
        if any(key[1] is None for key in second_keys):
            raise AssertionError("event_result_missing_event_id")
        counts = Counter(second_keys)
        if any(count > 1 for count in counts.values()):
            raise AssertionError(f"event_dedup_failed:{counts}")
        if {item.get("result_id") for item in first_events} != {item.get("result_id") for item in second_events}:
            raise AssertionError("second_tick_changed_result_id_set")
        if any(item.get("subscription_id") == sub2["id"]
               for item in second_delivery.get("results", [])
               if isinstance(item, Mapping) and item.get("trigger") == "event"):
            raise AssertionError("cancelled_sub2_received_event")
        report["event_observation"] = {
            "delivery_listing_tool": delivery_tool,
            "first_event_count": len(first_events), "second_event_count": len(second_events),
            "first_event_keys": first_keys, "second_event_keys": second_keys,
            "event_result_ids": [item.get("result_id") for item in second_events],
            "dedup_checked": True,
            "new_event_ids_after_window": sorted({key[1] for key in second_keys} - retained_ids),
            "natural_fra_event_absent": not bool({key[1] for key in second_keys} - retained_ids),
        }
        report["checks"]["post_window_tick_delivery_and_dedup_checked"] = True
        _status_step(client, report, "after-window-delivery", expected=("enabled", True, 1))

        sub1 = _manage_subscription(client, report, namespace, "sub1-cancel", "cancel", subscription=sub1)
        subscriptions["sub1"] = sub1
        final_status = _status_step(client, report, "after-sub1-cancel", expected=("disabled", False, 0))
        listed_subscriptions = _step(
            client, report, "subscription-list", "information_manage_subscription", {
                "request_id": _request_id(namespace, "subscription-list"),
                "operation": "list",
            })
        if not isinstance(listed_subscriptions.get("subscriptions"), list):
            raise AssertionError("subscription_list_shape_missing")
        listed_active = [
            row for row in listed_subscriptions["subscriptions"]
            if isinstance(row, Mapping) and row.get("state") == "active"
        ]
        if listed_active:
            raise AssertionError(f"listed_active_subscription_after_final_cancel:{listed_active}")
        active = [
            row for row in final_status.get("subscriptions", [])
            if isinstance(row, Mapping)
            and isinstance(row.get("subscription"), Mapping)
            and row["subscription"].get("state") == "active"
        ]
        if active:
            raise AssertionError(f"active_subscription_after_final_cancel:{active}")
        report["checks"]["final_cancel_no_active_subscriptions"] = True
        report["checks"]["final_list_no_active_subscriptions"] = True
        report["status"] = "passed"
    except Exception as error:
        report["status"] = "failed"
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if client is not None:
            # Cleanup only subscriptions whose last successful response still
            # says active.  An ambiguous request is never retried here.
            for name, subscription in list(subscriptions.items()):
                if subscription.get("state") != "active":
                    continue
                try:
                    closed = _manage_subscription(
                        client, report, namespace, f"cleanup-{name}-cancel", "cancel",
                        subscription=subscription)
                    subscriptions[name] = closed
                except Exception as error:
                    report.setdefault("cleanup_errors", []).append(
                        {"subscription": name, "type": type(error).__name__, "message": str(error)})
            try:
                report["server_exit_code"] = client.close()
            except Exception as error:
                report["status"] = "failed"
                report["cleanup_close_error"] = {
                    "type": type(error).__name__, "message": str(error),
                }
        if report.get("cleanup_errors"):
            report["status"] = "failed"
        if client is not None and report.get("server_exit_code") != 0:
            report["status"] = "failed"
        if report.get("server_exit_code") == 0:
            report.setdefault("checks", {})["server_exit_code_zero"] = True
        _write_json_new(output / "report.json", report)
    print(json.dumps({
        "status": report["status"], "output": str(output),
        "server_exit_code": report.get("server_exit_code"),
        "natural_window": report.get("natural_window", {"status": "not_requested"}),
    }, ensure_ascii=False, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", required=True, type=Path)
    parser.add_argument("--battle-stream", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--natural-window-output", type=Path)
    parser.add_argument("--test-only", action="store_true",
                        help="Run the existing once-only natural observation window exactly once")
    parser.add_argument("--expected-manifest-sha256")
    parser.add_argument("--expected-dll-sha256")
    parser.add_argument("--expected-date", type=int, default=DEFAULT_EXPECTED_DATE)
    parser.add_argument("--days", type=int, choices=(1, 5, 35), default=DEFAULT_DAYS)
    parser.add_argument("--expected-player-tag", choices=EXPECTED_PLAYER_TAGS, default="POR")
    args = parser.parse_args(argv)
    try:
        return run(args)
    except (OSError, ValueError, RuntimeError, AcceptanceUnavailable, AssertionError) as error:
        print(json.dumps({"status": "unavailable", "error": str(error)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
