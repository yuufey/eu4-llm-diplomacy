"""Observer-only game clock control through a fixed native request."""
from __future__ import annotations

import json
import os
import time
import uuid

from .information.collection_lock import CollectionLock
from .information.model import InformationError


TOOL_NAME = "set_game_speed"
PROTOCOL = "EU4SPEED1"
REQUEST_NAME = "game-speed.req"
RESULT_EVENT = "native_game_speed_result"
TOOL_DEFINITION = {
    "name": TOOL_NAME,
    "description": "控制观察者测试的游戏时间。0 暂停，1 至 5 恢复并设置对应速度。",
    "inputSchema": {
        "type": "object",
        "properties": {"speed": {"type": "integer", "minimum": 0, "maximum": 5}},
        "required": ["speed"],
        "additionalProperties": False,
    },
    "annotations": {
        "readOnlyHint": False, "destructiveHint": True,
        "idempotentHint": True, "openWorldHint": True,
    },
}

_FILETIME_EPOCH = 116444736000000000
_REQUEST_LIFETIME_SECONDS = 6
_RESULT_TIMEOUT_SECONDS = 8
_LOG_CHUNK_BYTES = 65536


def bind_game_time_control(session):
    """Grant the tool only for an explicitly selected observer installation."""
    from work.observer_runtime_ready import expected_physical_player

    if session is None or expected_physical_player(session.record) != "O00":
        raise InformationError("permission_denied", "Clock control requires a verified O00 observer installation")
    ack = session._installation_ack()
    if (ack is None or ack.get("native_game_speed_control") is not True
            or ack.get("native_game_speed_control_protocol") != PROTOCOL):
        raise InformationError("source_unavailable", "The observer DLL does not support clock control")
    return GameTimeControl(session)


class GameTimeControl:
    def __init__(self, session):
        self.session = session
        self.request = session.directory / REQUEST_NAME
        self.log = session.directory / "control-probe.jsonl"
        self.lock = CollectionLock(self.request)

    def __call__(self, speed: int) -> dict:
        if type(speed) is not int or not 0 <= speed <= 5:
            raise InformationError("invalid_parameters", "speed must be an integer from 0 to 5")
        try:
            with self.lock.acquire(blocking=False) as acquired:
                if not acquired:
                    raise InformationError("game_time_busy", "A clock request is already in progress")
                if self.session.physical_player_health(allow_date_progress=True).get("status") != "ready":
                    raise InformationError("source_unavailable", "The live O00 observer session is unready")
                offset = self.log.stat().st_size
                revision = time.time_ns()
                expires = (_FILETIME_EPOCH + revision // 100
                           + _REQUEST_LIFETIME_SECONDS * 10_000_000)
                line = f"{PROTOCOL}\t{self.session.session_id}\t{revision}\t{expires}\t{speed}\n"
                self._publish(line)
                return self._wait_for_result(offset, revision, speed)
        except OSError as error:
            raise InformationError("source_unavailable", "The clock request channel is unavailable") from error

    def _publish(self, line: str) -> None:
        temporary = self.request.with_suffix(f".{uuid.uuid4().hex}.pending")
        try:
            with temporary.open("x", encoding="ascii", newline="\n") as stream:
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())
            # A native reader sees the entire record at once. A request from
            # another process stays in place until the DLL consumes it.
            try:
                if os.name == "nt":
                    os.rename(temporary, self.request)
                else:
                    os.link(temporary, self.request)
            except FileExistsError as error:
                raise InformationError("game_time_busy", "A clock request is awaiting the game") from error
        finally:
            temporary.unlink(missing_ok=True)

    def _wait_for_result(self, offset: int, revision: int, speed: int) -> dict:
        deadline = time.monotonic() + _RESULT_TIMEOUT_SECONDS
        pending = b""
        while time.monotonic() < deadline:
            try:
                with self.log.open("rb") as stream:
                    stream.seek(offset)
                    data = stream.read(_LOG_CHUNK_BYTES)
                    offset = stream.tell()
            except OSError:
                data = b""
            lines = (pending + data).split(b"\n")
            pending = lines.pop()
            if len(pending) > _LOG_CHUNK_BYTES:
                pending = b""
            for raw in lines:
                if b'"native_game_speed_result"' not in raw:
                    continue
                try:
                    event = json.loads(raw)
                except (ValueError, UnicodeError):
                    continue
                if (not isinstance(event, dict) or event.get("event") != RESULT_EVENT
                        or event.get("session_id") != self.session.session_id
                        or type(event.get("revision")) is not int or event["revision"] != revision
                        or type(event.get("requested_speed")) is not int
                        or event["requested_speed"] != speed):
                    continue
                if event.get("status") == "rejected":
                    raise InformationError("game_time_rejected", "The game rejected the clock request")
                if event.get("status") == "unconfirmed":
                    raise InformationError("game_time_unconfirmed", "The game did not confirm the clock request")
                if (event.get("status") == "applied"
                        and type(event.get("speed")) is int and event["speed"] == speed
                        and event.get("paused") is (speed == 0)
                        and type(event.get("date_raw")) is int and event["date_raw"] > 0):
                    return {"status": "applied", "speed": event["speed"], "paused": event["paused"],
                            "game_date_raw": event["date_raw"]}
            if not data:
                time.sleep(0.05)
        raise InformationError("game_time_unconfirmed", "The game did not confirm the clock request")
