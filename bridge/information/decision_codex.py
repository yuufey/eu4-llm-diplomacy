"""Small synchronous adapter for the local Codex app-server JSON-RPC protocol.

The adapter owns one app-server child process. It deliberately does not change
the caller's Codex configuration (including sandbox settings) and does not
retry requests whose outcome may be ambiguous.
"""

from __future__ import annotations

import json
import math
import subprocess
import threading
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_CLIENT_INFO = {
    "name": "eu4_decision_orchestrator",
    "title": "EU4 Decision Orchestrator",
    "version": "1.0.0",
}
_TOOL_OUTPUT_NAME = "information_brief"
_TURN_NOTIFICATION_METHODS = {"turn/started", "turn/completed"}
_RECEIPT_REQUEST_METHODS = {"thread/start", "thread/resume", "turn/start"}
_RECEIPT_NOTIFICATION_PREFIXES = ("thread/", "turn/", "item/", "rawResponseItem/")
_MAX_TIMEOUT_SECONDS = 300.0


class CodexAppServerError(RuntimeError):
    """A protocol, process, or JSON-RPC failure from the app server."""


class CodexRPCError(CodexAppServerError):
    """A JSON-RPC error response, preserving its numeric code and data."""

    def __init__(self, method: str, error: dict[str, Any]):
        self.method = method
        self.code = error.get("code")
        self.data = error.get("data")
        message = error.get("message", "unknown JSON-RPC error")
        super().__init__(f"{method} failed with JSON-RPC error {self.code}: {message}")


@dataclass
class _PendingRequest:
    method: str
    event: threading.Event
    result: Any = None
    error: BaseException | None = None


class CodexDecisionClient:
    """Own a local Codex app-server process and expose the decision workflow.

    ``payload`` passed to :meth:`start_turn` is data for the
    ``information_brief`` tool output, not a bag of app-server turn parameters.
    The installed Codex CLI 0.166.0 protocol schema includes ``toolOutput``;
    that supported path is used directly and is not retried as a user message.

    ``receipts`` is an optional JSONL destination. It records the owned
    thread/turn requests and responses, plus thread, turn, item, and raw-response
    notifications. Authentication and unrelated server requests are excluded.
    """

    def __init__(
        self,
        command: list[str],
        cwd: Path,
        receipts: Path | None = None,
        *,
        request_timeout: float = 60.0,
        startup_timeout: float = 30.0,
        shutdown_timeout: float = 5.0,
    ) -> None:
        if not isinstance(command, list) or not command or not all(
            isinstance(part, str) and part for part in command
        ):
            raise ValueError("command must be a non-empty list of non-empty strings")
        self.command = list(command)
        self.cwd = Path(cwd).expanduser().resolve()
        if not self.cwd.is_dir():
            raise ValueError(f"app-server cwd is not a directory: {self.cwd}")
        self.receipts = Path(receipts).expanduser().resolve() if receipts is not None else None

        self.request_timeout = self._bounded_timeout("request_timeout", request_timeout)
        self.startup_timeout = self._bounded_timeout("startup_timeout", startup_timeout)
        self.shutdown_timeout = self._bounded_timeout("shutdown_timeout", shutdown_timeout)

        self._process: subprocess.Popen[str] | None = None
        self._stdout_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None
        self._receipt_file: Any = None
        self._receipt_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._stderr_lock = threading.Lock()
        self._thread_operation_lock = threading.RLock()
        self._next_request_id = 1
        self._pending: dict[int, _PendingRequest] = {}
        self._turn_notifications: deque[tuple[str, str, str]] = deque()
        self._turn_status: dict[tuple[str, str], str] = {}
        self._stderr_tail: deque[str] = deque(maxlen=100)
        self._fatal_error: BaseException | None = None
        self._stdout_eof = False
        self._closed = False

    @staticmethod
    def _bounded_timeout(name: str, value: float) -> float:
        try:
            seconds = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must be a finite positive number") from exc
        if not math.isfinite(seconds) or seconds <= 0:
            raise ValueError(f"{name} must be a finite positive number")
        return min(seconds, _MAX_TIMEOUT_SECONDS)

    def __enter__(self) -> CodexDecisionClient:
        if self._process is not None or self._closed:
            raise RuntimeError("CodexDecisionClient instances can be entered only once")

        if self.receipts is not None:
            self.receipts.parent.mkdir(parents=True, exist_ok=True)
            self._receipt_file = self.receipts.open("a", encoding="utf-8", newline="\n")

        try:
            self._process = subprocess.Popen(
                self.command,
                cwd=self.cwd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
            self._stdout_thread = threading.Thread(
                target=self._read_stdout,
                name="codex-app-server-stdout",
                daemon=True,
            )
            self._stderr_thread = threading.Thread(
                target=self._read_stderr,
                name="codex-app-server-stderr",
                daemon=True,
            )
            self._stdout_thread.start()
            self._stderr_thread.start()

            self._request(
                "initialize",
                {"clientInfo": dict(_CLIENT_INFO)},
                timeout=self.startup_timeout,
                record=False,
            )
            self._notify("initialized", record=False)
            return self
        except BaseException:
            self.close()
            raise

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def close(self) -> None:
        """Close pipes and reap the child with bounded graceful/forced waits."""
        if self._closed:
            return
        self._closed = True
        process = self._process
        if process is not None:
            stdin = process.stdin
            if stdin is not None:
                try:
                    stdin.close()
                except (BrokenPipeError, OSError, ValueError):
                    pass
            try:
                process.wait(timeout=self.shutdown_timeout)
            except subprocess.TimeoutExpired:
                try:
                    process.terminate()
                except OSError:
                    pass
                try:
                    process.wait(timeout=self.shutdown_timeout)
                except subprocess.TimeoutExpired:
                    try:
                        process.kill()
                    except OSError:
                        pass
                    process.wait(timeout=self.shutdown_timeout)

        for worker in (self._stdout_thread, self._stderr_thread):
            if worker is not None and worker is not threading.current_thread():
                worker.join(timeout=self.shutdown_timeout)

        with self._state_lock:
            self._fail_pending_locked(
                CodexAppServerError("Codex app-server client closed before receiving a response")
            )

        for stream in (
            process.stdout if process is not None else None,
            process.stderr if process is not None else None,
        ):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

        if self._receipt_file is not None:
            with self._receipt_lock:
                self._receipt_file.flush()
                self._receipt_file.close()
                self._receipt_file = None

    def open_thread(self, thread_id: str | None, instruction: str) -> str:
        """Start a thread with developer instructions, or resume it unchanged."""
        if thread_id is not None and not thread_id:
            raise ValueError("thread_id must be non-empty or None")
        if thread_id is None and not isinstance(instruction, str):
            raise TypeError("instruction must be a string")

        with self._thread_operation_lock:
            if thread_id is None:
                params: dict[str, Any] = {
                    "cwd": str(self.cwd),
                    "developerInstructions": instruction,
                }
                result = self._request("thread/start", params)
            else:
                # Do not send developerInstructions on resume: that would alter
                # the existing thread's instruction contract.
                result = self._request(
                    "thread/resume",
                    {"threadId": thread_id, "cwd": str(self.cwd)},
                )

        thread = result.get("thread") if isinstance(result, dict) else None
        returned_id = thread.get("id") if isinstance(thread, dict) else None
        if not isinstance(returned_id, str) or not returned_id:
            raise CodexAppServerError("app-server thread response did not include thread.id")
        if thread_id is not None and returned_id != thread_id:
            raise CodexAppServerError(
                f"app-server resumed thread {returned_id!r}, expected {thread_id!r}"
            )
        return returned_id

    def start_turn(self, thread_id: str, payload: dict[str, Any]) -> str:
        """Start one turn with ``payload`` supplied as tool output.

        The current protocol treats ``toolOutput`` as an alternative to normal
        user input. Consequently ``input`` is empty. A timeout is surfaced to
        the caller and is never retried, since the turn may already be running.
        """
        if not isinstance(thread_id, str) or not thread_id:
            raise ValueError("thread_id must be a non-empty string")
        if not isinstance(payload, dict):
            raise TypeError("payload must be a JSON object")
        brief = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        params: dict[str, Any] = {
            "threadId": thread_id,
            "cwd": str(self.cwd),
            "input": [],
            "toolOutput": {"name": _TOOL_OUTPUT_NAME, "output": brief},
        }
        with self._thread_operation_lock:
            result = self._request("turn/start", params)

        turn = result.get("turn") if isinstance(result, dict) else None
        turn_id = turn.get("id") if isinstance(turn, dict) else None
        if not isinstance(turn_id, str) or not turn_id:
            raise CodexAppServerError("app-server turn/start response did not include turn.id")
        return turn_id

    def collect_turns(self) -> list[tuple[str, str, str]]:
        """Drain turn notifications without waiting, then surface child failure."""
        with self._state_lock:
            events = list(self._turn_notifications)
            self._turn_notifications.clear()
            fatal_error = self._fatal_error
            stdout_eof = self._stdout_eof
            closed = self._closed
        if events:
            return events
        if not closed and (fatal_error is not None or stdout_eof):
            if isinstance(fatal_error, CodexAppServerError):
                raise fatal_error
            raise CodexAppServerError(
                f"app-server stopped before the decision workflow completed: {fatal_error or 'stdout closed'}"
            ) from fatal_error
        return []

    def read_turn_status(self, thread_id: str, turn_id: str) -> str | None:
        """Return a cached status or recover it with ``thread/read`` history."""
        if not thread_id or not turn_id:
            raise ValueError("thread_id and turn_id must be non-empty strings")
        key = (thread_id, turn_id)
        with self._state_lock:
            cached = self._turn_status.get(key)
        if cached is not None:
            return cached

        with self._thread_operation_lock:
            try:
                result = self._request(
                    "thread/read",
                    {"threadId": thread_id, "includeTurns": True},
                )
            except CodexRPCError as exc:
                # Older schemas may not expose thread/read; absence is the only
                # protocol error treated as an unavailable recovery path.
                if exc.code == -32601:
                    return None
                raise

        thread = result.get("thread") if isinstance(result, dict) else None
        turns = thread.get("turns") if isinstance(thread, dict) else None
        if not isinstance(turns, list):
            return None
        for turn in turns:
            if not isinstance(turn, dict) or turn.get("id") != turn_id:
                continue
            status = turn.get("status")
            if isinstance(status, str):
                with self._state_lock:
                    self._turn_status[key] = status
                return status
        return None

    def _request(
        self,
        method: str,
        params: dict[str, Any],
        *,
        timeout: float | None = None,
        record: bool = True,
    ) -> Any:
        process = self._process
        if process is None or process.stdin is None:
            raise RuntimeError("Codex app-server is not running; use the client as a context manager")
        if self._closed:
            raise RuntimeError("Codex app-server client is closed")

        wait_seconds = self.request_timeout if timeout is None else self._bounded_timeout("timeout", timeout)
        with self._state_lock:
            if self._fatal_error is not None:
                raise CodexAppServerError(f"app-server protocol reader failed: {self._fatal_error}")
            request_id = self._next_request_id
            self._next_request_id += 1
            pending = _PendingRequest(method=method, event=threading.Event())
            self._pending[request_id] = pending

        message = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        if record and method in _RECEIPT_REQUEST_METHODS:
            self._record_receipt("outbound", message)
        try:
            encoded = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
            with self._write_lock:
                process.stdin.write(encoded + "\n")
                process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as exc:
            with self._state_lock:
                self._pending.pop(request_id, None)
            raise self._process_failure("could not write app-server request") from exc

        if not pending.event.wait(wait_seconds):
            with self._state_lock:
                if not pending.event.is_set():
                    self._pending.pop(request_id, None)
                    raise TimeoutError(
                        f"{method} timed out after {wait_seconds:g}s; outcome may be ambiguous, so it was not retried"
                    )
        if pending.error is not None:
            raise pending.error
        return pending.result

    def _notify(self, method: str, params: Any = None, *, record: bool = True) -> None:
        process = self._process
        if process is None or process.stdin is None:
            raise RuntimeError("Codex app-server is not running")
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        try:
            encoded = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
            with self._write_lock:
                process.stdin.write(encoded + "\n")
                process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as exc:
            raise self._process_failure("could not write app-server notification") from exc
        if record and method in _RECEIPT_REQUEST_METHODS:
            self._record_receipt("outbound", message)

    def _read_stdout(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            return
        try:
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    message = json.loads(line)
                except json.JSONDecodeError as exc:
                    self._set_fatal_error(
                        CodexAppServerError(f"app-server wrote invalid JSON to stdout: {line[:240]!r}")
                    )
                    continue
                if not isinstance(message, dict):
                    self._set_fatal_error(CodexAppServerError("app-server JSON-RPC message was not an object"))
                    continue
                self._handle_message(message)
        except (OSError, ValueError) as exc:
            if not self._closed:
                self._set_fatal_error(CodexAppServerError(f"app-server stdout reader failed: {exc}"))
        finally:
            with self._state_lock:
                self._stdout_eof = True
                if not self._closed:
                    if self._fatal_error is None:
                        self._fatal_error = self._process_failure("app-server stdout closed")
                    self._fail_pending_locked(self._fatal_error)

    def _read_stderr(self) -> None:
        process = self._process
        if process is None or process.stderr is None:
            return
        try:
            for line in process.stderr:
                trimmed = line.rstrip()
                if trimmed:
                    with self._stderr_lock:
                        self._stderr_tail.append(trimmed[-4096:])
        except (OSError, ValueError):
            pass

    def _handle_message(self, message: dict[str, Any]) -> None:
        if "method" in message:
            method = message.get("method")
            if not isinstance(method, str):
                self._set_fatal_error(CodexAppServerError("app-server notification method was not a string"))
                return
            if "id" in message:
                # This adapter has no approval, console, or authentication UI.
                # Fail closed instead of leaving an unsupported server request
                # hanging or accidentally approving it. Do not put it in the
                # receipt, since server requests can contain console/auth data.
                self._send_server_error(message["id"], method)
                return
            params = message.get("params")
            self._handle_notification(method, params, message)
            return

        if "id" not in message:
            self._set_fatal_error(CodexAppServerError("app-server sent a message without id or method"))
            return

        request_id = message.get("id")
        with self._state_lock:
            pending = self._pending.pop(request_id, None)
            if pending is not None:
                error = message.get("error")
                if isinstance(error, dict):
                    pending.error = CodexRPCError(pending.method, error)
                elif "result" in message:
                    pending.result = message["result"]
                else:
                    pending.error = CodexAppServerError(
                        f"{pending.method} response had neither result nor error"
                    )
                pending.event.set()
        if pending is None:
            return

        if pending.method in _RECEIPT_REQUEST_METHODS:
            self._record_receipt("inbound", message, method_hint=pending.method)

    def _handle_notification(
        self,
        method: str,
        params: Any,
        message: dict[str, Any],
    ) -> None:
        if method in _RECEIPT_REQUEST_METHODS:
            self._record_receipt("inbound", message)
        elif method.startswith(_RECEIPT_NOTIFICATION_PREFIXES):
            self._record_receipt("inbound", message)

        if method not in _TURN_NOTIFICATION_METHODS or not isinstance(params, dict):
            return
        thread_id = params.get("threadId")
        turn = params.get("turn")
        if not isinstance(thread_id, str) or not isinstance(turn, dict):
            return
        turn_id = turn.get("id")
        status = turn.get("status")
        if not isinstance(turn_id, str) or not isinstance(status, str):
            return
        with self._state_lock:
            self._turn_notifications.append((thread_id, turn_id, status))
            self._turn_status[(thread_id, turn_id)] = status

    def _send_server_error(self, request_id: Any, method: str) -> None:
        process = self._process
        if process is None or process.stdin is None:
            return
        response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32601,
                "message": f"Client does not implement server request {method}",
            },
        }
        try:
            with self._write_lock:
                process.stdin.write(json.dumps(response, separators=(",", ":")) + "\n")
                process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            pass

    def _record_receipt(
        self,
        direction: str,
        message: dict[str, Any],
        *,
        method_hint: str | None = None,
    ) -> None:
        receipt_file = self._receipt_file
        if receipt_file is None:
            return
        method = message.get("method", method_hint)
        if method is not None:
            if direction == "outbound" and method not in _RECEIPT_REQUEST_METHODS:
                return
            if direction == "inbound" and method not in _RECEIPT_REQUEST_METHODS and not str(
                method
            ).startswith(_RECEIPT_NOTIFICATION_PREFIXES):
                return
        record = {"direction": direction, "message": message}
        if method_hint is not None and "method" not in message:
            record["requestMethod"] = method_hint
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        with self._receipt_lock:
            if self._receipt_file is not None:
                self._receipt_file.write(line + "\n")
                self._receipt_file.flush()

    def _set_fatal_error(self, error: BaseException) -> None:
        with self._state_lock:
            if self._fatal_error is None:
                self._fatal_error = error
            self._fail_pending_locked(error)

    def _fail_pending(self, error: BaseException) -> None:
        with self._state_lock:
            self._fail_pending_locked(error)

    def _fail_pending_locked(self, error: BaseException) -> None:
        pending_requests = list(self._pending.values())
        self._pending.clear()
        for pending in pending_requests:
            pending.error = error
            pending.event.set()

    def _process_failure(self, prefix: str) -> CodexAppServerError:
        with self._stderr_lock:
            stderr_tail = list(self._stderr_tail)
        if stderr_tail:
            return CodexAppServerError(f"{prefix}; stderr tail: {' | '.join(stderr_tail)}")
        return CodexAppServerError(prefix)
