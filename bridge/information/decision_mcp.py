"""Relay Codex stdio requests to the scheduler's own information service."""
from __future__ import annotations

from contextlib import contextmanager
import hmac
import json
import os
import secrets
import socket
import socketserver
import sys
import threading

from .mcp import InformationMCPServer, parse_json_line

_MAX_REQUEST = 1 << 20
_MAX_RESPONSE = 32 << 20
_TOKEN_ENV = "EU4_DECISION_MCP_TOKEN"


@contextmanager
def decision_mcp(service, tools):
    """Bind a private loopback relay. The scheduler retains service ownership."""
    token = secrets.token_hex(32)
    token_line = token.encode("ascii") + b"\n"

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                self.connection.settimeout(10)
                if not hmac.compare_digest(self.rfile.readline(len(token_line) + 1), token_line):
                    return
                self.connection.settimeout(None)
                mcp = InformationMCPServer(service, tools=tools)
                while line := self.rfile.readline(_MAX_REQUEST + 1):
                    if len(line) > _MAX_REQUEST:
                        return
                    try:
                        response = mcp.handle(parse_json_line(line))
                    except (ValueError, UnicodeError):
                        response = {"jsonrpc": "2.0", "id": None,
                                    "error": {"code": -32700, "message": "Invalid MCP JSON"}}
                    payload = json.dumps(response, ensure_ascii=False, allow_nan=False).encode("utf-8")
                    if len(payload) >= _MAX_RESPONSE:
                        return
                    self.wfile.write(payload + b"\n")
            except (ConnectionError, TimeoutError):
                return

    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler) as server:
        server.daemon_threads = True
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        worker.start()
        try:
            yield server.server_address[1], {_TOKEN_ENV: token}
        finally:
            server.shutdown()
            worker.join()


def relay_stdio(port: int) -> int:
    token = os.environ.get(_TOKEN_ENV)
    if not token:
        raise RuntimeError("The decision MCP relay requires an operator token")
    with socket.create_connection(("127.0.0.1", port), timeout=10) as client:
        client.settimeout(None)
        client.sendall(token.encode("ascii") + b"\n")
        with client.makefile("rb") as responses:
            for line in sys.stdin.buffer:
                client.sendall(line)
                response = responses.readline(_MAX_RESPONSE + 1)
                if not response or len(response) > _MAX_RESPONSE:
                    raise RuntimeError("The decision MCP relay closed without a response")
                if response != b"null\n":
                    sys.stdout.buffer.write(response)
                    sys.stdout.buffer.flush()
    return 0
