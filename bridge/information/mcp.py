"""Small dependency-free MCP stdio server for information tools.

The repository deliberately does not require an MCP SDK.  This module
implements the legacy handshake shared by MCP ``2024-11-05`` and
``2025-03-26`` and the newline-delimited JSON-RPC stdio transport described by
the official specification. The default registry exposes information tools.
The game host supplies its combined registry to include diplomacy tools.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import logging
import math
import sys
import threading
from typing import Any, IO, TYPE_CHECKING

from .model import InformationError, canonical
from .tools import InformationTools

if TYPE_CHECKING:  # pragma: no cover
    from .service import InformationService


LOGGER = logging.getLogger(__name__)
SUPPORTED_PROTOCOL_VERSIONS = ("2025-03-26", "2024-11-05")
DEFAULT_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0]
SERVER_NAME = "eu4-information"
SERVER_VERSION = "1.0.0"


class MCPProtocolError(ValueError):
    """An error in the JSON-RPC/MCP envelope, not in a tool's business work."""

    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code = code
        self.data = data


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON number {value}")


def parse_json_line(line: str | bytes) -> Any:
    """Parse one UTF-8 JSON-RPC line and reject duplicate keys/constants."""

    if isinstance(line, bytes):
        line = line.decode("utf-8")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(line, object_pairs_hook=pairs, parse_constant=_reject_constant)


def _response(request_id: Any, *, result: Any = None, error: dict[str, Any] | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        value["error"] = error
    else:
        value["result"] = result
    return value


def _error_response(request_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return _response(request_id, error=error)


def _json_text(value: Any) -> str:
    """Encode a tool result as one MCP text content item."""

    try:
        return canonical(value)
    except InformationError:
        # The service contract should always produce JSON values.  If a custom
        # source violates that boundary, do not terminate the stdio server.
        return json.dumps({"error": {"code": "non_json_result", "message": "Tool returned a non-JSON value"}},
                          ensure_ascii=False, sort_keys=True)


@dataclass
class _TickLoop:
    service: "InformationService"
    seconds: float

    def __post_init__(self) -> None:
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self.seconds <= 0 or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="information-tick", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(self.seconds):
            try:
                self.service.tick()
            except Exception:  # the next tick must still be attempted
                LOGGER.exception("information tick failed; keeping stdio server alive")

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            # A tick may be inside a source read.  Wait for it to leave before
            # the service closes its SQLite connection; a timed join could
            # otherwise leave a worker using a closed database.
            self._thread.join()
        self._thread = None


class InformationMCPServer:
    """MCP request dispatcher backed by one information service instance."""

    def __init__(self, service: "InformationService", *, tick_seconds: float = 0.0,
                 tools: Any = None):
        if (type(tick_seconds) not in (int, float)
                or not math.isfinite(float(tick_seconds))
                or tick_seconds < 0):
            raise ValueError("tick_seconds must be a non-negative number")
        self.service = service
        self.tools = tools if tools is not None else InformationTools(service)
        self.protocol_version: str | None = None
        self.initialized = False
        self._initialized_notification = False
        self._closed = False
        self._tick_loop = _TickLoop(service, float(tick_seconds))

    @property
    def ready(self) -> bool:
        return self.initialized and self._initialized_notification and not self._closed

    def _initialize(self, request_id: Any, params: Any) -> dict[str, Any]:
        if self.initialized:
            raise MCPProtocolError(-32600, "initialize may only be sent once")
        if not isinstance(params, dict):
            raise MCPProtocolError(-32602, "initialize params must be an object")
        allowed = {"protocolVersion", "capabilities", "clientInfo"}
        extra = set(params) - allowed
        missing = {"protocolVersion", "capabilities", "clientInfo"} - set(params)
        if extra or missing:
            raise MCPProtocolError(-32602, "Invalid initialize params", {"missing": sorted(missing), "unknown": sorted(extra)})
        requested = params["protocolVersion"]
        if not isinstance(requested, str) or not requested:
            raise MCPProtocolError(-32602, "protocolVersion must be a string")
        if requested not in SUPPORTED_PROTOCOL_VERSIONS:
            # MCP lifecycle negotiation requires the server to answer with a
            # version it supports; the client decides whether it can continue
            # after seeing that response.  Select the current supported
            # revision rather than treating an unknown request as accepted.
            negotiated = DEFAULT_PROTOCOL_VERSION
            LOGGER.warning(
                "client requested unsupported MCP protocol %s; offering %s",
                requested,
                negotiated,
            )
        else:
            negotiated = requested
        if not isinstance(params["capabilities"], dict) or not isinstance(params["clientInfo"], dict):
            raise MCPProtocolError(-32602, "capabilities and clientInfo must be objects")
        client_info = params["clientInfo"]
        if (not isinstance(client_info.get("name"), str) or not client_info["name"]
                or not isinstance(client_info.get("version"), str) or not client_info["version"]):
            raise MCPProtocolError(-32602, "clientInfo requires non-empty name and version")
        self.protocol_version = negotiated
        self.initialized = True
        return {
            "protocolVersion": negotiated,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": getattr(self.tools, "instructions", (
                "Information tools are read-only. They query configured game information, "
                "manage subscriptions and write results to the SQLite outbox; they never execute diplomacy."
            )),
        }

    def _check_ready(self, method: str) -> None:
        if self._closed:
            raise MCPProtocolError(-32600, "Server is closed")
        if method in {"ping", "notifications/initialized"}:
            return
        if not self.initialized:
            raise MCPProtocolError(-32600, "Server is not initialized")
        if not self._initialized_notification:
            raise MCPProtocolError(-32600, "Client must send notifications/initialized before requests")

    def _handle_method(self, request_id: Any, method: str, params: Any, *, has_id: bool) -> dict[str, Any] | None:
        if self._closed:
            raise MCPProtocolError(-32600, "Server is closed")
        if method == "initialize":
            if not has_id:
                raise MCPProtocolError(-32600, "initialize must be a request")
            return _response(request_id, result=self._initialize(request_id, params))
        if method == "notifications/initialized":
            if has_id:
                raise MCPProtocolError(-32600, "notifications/initialized must not have an id")
            if not self.initialized:
                # Notifications have no response channel.  Record the issue in
                # stderr and leave the connection unready.
                LOGGER.warning("received notifications/initialized before initialize")
            else:
                self._initialized_notification = True
                self._tick_loop.start()
            return None
        if method == "ping":
            if params not in (None, {}):
                raise MCPProtocolError(-32602, "ping params must be an empty object")
            return _response(request_id, result={}) if has_id else None

        self._check_ready(method)
        if method == "tools/list":
            if params not in (None, {}):
                if not isinstance(params, dict) or set(params) - {"cursor"}:
                    raise MCPProtocolError(-32602, "tools/list accepts only cursor")
                if params.get("cursor") not in (None, ""):
                    raise MCPProtocolError(-32602, "No pagination cursor is supported")
            return _response(request_id, result={"tools": self.tools.definitions()}) if has_id else None

        if method == "tools/call":
            if not has_id:
                raise MCPProtocolError(-32600, "tools/call must be a request")
            if not isinstance(params, dict) or set(params) - {"name", "arguments"} or "name" not in params:
                raise MCPProtocolError(-32602, "tools/call requires name and optional arguments")
            name = params["name"]
            arguments = params.get("arguments", {})
            if not isinstance(arguments, dict):
                raise MCPProtocolError(-32602, "tools/call arguments must be an object")
            try:
                result = self.tools.call(name, arguments)
            except InformationError as error:
                if error.code == "unknown_tool":
                    return _error_response(request_id, -32602, str(error))
                if error.code == "invalid_parameters":
                    return _error_response(request_id, -32602, str(error), error.as_dict())
                return _response(request_id, result={
                    "content": [{"type": "text", "text": _json_text(error.as_dict())}],
                    "isError": True,
                })
            except Exception:
                LOGGER.exception("unhandled information tool exception")
                return _response(request_id, result={
                    "content": [{"type": "text", "text": _json_text({
                        "error": {"code": "internal_error", "message": "Information tool failed"}
                    })}],
                    "isError": True,
                })
            return _response(request_id, result={
                "content": [{"type": "text", "text": _json_text(result)}],
                "isError": False,
            })

        raise MCPProtocolError(-32601, f"Method not found: {method}")

    def handle(self, message: Any) -> dict[str, Any] | list[dict[str, Any]] | None:
        """Handle one parsed JSON-RPC message without raising to the caller."""

        if isinstance(message, list):
            if not message:
                return _error_response(None, -32600, "Empty JSON-RPC batch")
            # MCP initialization must be the first non-batch interaction.
            if any(isinstance(item, dict) and item.get("method") == "initialize" for item in message):
                return [_error_response(item.get("id"), -32600, "initialize must not be sent in a batch")
                        for item in message if isinstance(item, dict) and "id" in item]
            responses = []
            for item in message:
                response = self.handle(item)
                if isinstance(response, list):
                    responses.extend(response)
                elif response is not None:
                    responses.append(response)
            return responses or None

        request_id = message.get("id") if isinstance(message, dict) else None
        has_id = isinstance(message, dict) and "id" in message
        try:
            if not isinstance(message, dict):
                raise MCPProtocolError(-32600, "JSON-RPC message must be an object")
            if message.get("jsonrpc") != "2.0":
                raise MCPProtocolError(-32600, "jsonrpc must be '2.0'")
            if has_id and (
                    request_id is not None
                    and (type(request_id) not in (str, int, float)
                         or (type(request_id) is float and not math.isfinite(request_id)))):
                raise MCPProtocolError(-32600, "id must be a string, number or null")
            method = message.get("method")
            if not isinstance(method, str) or not method:
                raise MCPProtocolError(-32600, "method must be a non-empty string")
            unknown = set(message) - {"jsonrpc", "id", "method", "params"}
            if unknown:
                raise MCPProtocolError(-32600, f"Unknown JSON-RPC members: {sorted(unknown)}")
            return self._handle_method(request_id, method, message.get("params"), has_id=has_id)
        except MCPProtocolError as error:
            # JSON-RPC notifications have no response, including when their
            # envelope or method is invalid.  Requests retain the original
            # id so a client can correlate protocol failures.
            if not has_id:
                return None
            response_id = (None if request_id is not None
                           and (type(request_id) not in (str, int, float)
                                or (type(request_id) is float and not math.isfinite(request_id)))
                           else request_id)
            return _error_response(response_id, error.code, str(error), error.data)
        except Exception:
            # A malformed line or unexpected adapter exception must not bring
            # down a long-lived LLM connection.
            LOGGER.exception("unhandled MCP request exception")
            return _error_response(request_id, -32603, "Internal server error") if has_id else None

    def serve(self, input_stream: IO[str] | None = None, output_stream: IO[str] | None = None) -> int:
        """Run newline-delimited JSON-RPC until stdin closes."""

        input_stream = input_stream or sys.stdin
        output_stream = output_stream or sys.stdout
        try:
            for raw_line in input_stream:
                if not raw_line.strip():
                    continue
                try:
                    message = parse_json_line(raw_line)
                except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
                    response = _error_response(None, -32700, f"Parse error: {error}")
                else:
                    response = self.handle(message)
                if response is not None:
                    output_stream.write(json.dumps(response, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n")
                    output_stream.flush()
        finally:
            self.close()
        return 0

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._tick_loop.stop()
        closer = getattr(self.service, "close", None)
        if callable(closer):
            try:
                closer()
            except Exception:
                LOGGER.exception("information service close failed")


MCPServer = InformationMCPServer


def serve_stdio(service: "InformationService", *, tick_seconds: float = 0.0,
                input_stream: IO[str] | None = None,
                output_stream: IO[str] | None = None,
                tools: Any = None) -> int:
    """Serve one service over MCP stdio and return the process exit code."""

    return InformationMCPServer(service, tick_seconds=tick_seconds, tools=tools).serve(input_stream, output_stream)


__all__ = [
    "SUPPORTED_PROTOCOL_VERSIONS",
    "DEFAULT_PROTOCOL_VERSION",
    "InformationMCPServer",
    "MCPServer",
    "MCPProtocolError",
    "parse_json_line",
    "serve_stdio",
]
