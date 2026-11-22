"""Clock permission, input and native confirmation contract."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from bridge.game_time_control import PROTOCOL, RESULT_EVENT, TOOL_NAME, bind_game_time_control
from bridge.game_tools import GameTools
from bridge.information.model import InformationError
from bridge.tests.test_game_tools import FakeInformationService


def test_clock_tool_requires_operator_opt_in():
    service = FakeInformationService()
    tools = GameTools(service)
    assert all(item["name"] != TOOL_NAME for item in tools.definitions())
    with pytest.raises(InformationError) as error:
        tools.call(TOOL_NAME, {"speed": 0})
    assert error.value.code == "permission_denied"

    service.game_time_control = lambda speed: {"speed": speed}
    tools = GameTools(service)
    assert TOOL_NAME in {item["name"] for item in tools.definitions()}
    for arguments in ({}, {"speed": True}, {"speed": 2.0}, {"speed": "0"},
                      {"speed": -1}, {"speed": 6}, {"speed": 0, "command": "help"}):
        with pytest.raises(InformationError) as error:
            tools.call(TOOL_NAME, arguments)
        assert error.value.code == "invalid_parameters"
    assert tools.call(TOOL_NAME, {"speed": 0}) == {"speed": 0}


@pytest.fixture
def observer(tmp_path):
    return SimpleNamespace(
        directory=tmp_path,
        session_id="observer-test",
        record={"preflight_player_tag": "---", "verified_loaded_player_tag": "O00"},
        _installation_ack=lambda: {"native_game_speed_control": True,
                                   "native_game_speed_control_protocol": PROTOCOL},
        information_health=lambda: {"status": "ready"},
        physical_player_health=lambda **_: {"status": "ready"},
    )


def test_requires_observer_installation_and_native_capability(observer):
    observer.record["preflight_player_tag"] = "TUR"
    with pytest.raises(InformationError) as error:
        bind_game_time_control(observer)
    assert error.value.code == "permission_denied"

    observer.record["preflight_player_tag"] = "O00"
    observer._installation_ack = lambda: {"native_game_speed_control": True}
    with pytest.raises(InformationError) as error:
        bind_game_time_control(observer)
    assert error.value.code == "source_unavailable"


def test_unready_player_cannot_publish_and_pending_request_is_preserved(observer):
    clock = bind_game_time_control(observer)
    clock.log.touch()
    observer.physical_player_health = lambda **_: {"status": "unready"}
    with pytest.raises(InformationError) as error:
        clock(1)
    assert error.value.code == "source_unavailable"
    assert not clock.request.exists()

    observer.physical_player_health = lambda **_: {"status": "ready"}
    clock.request.write_text("pending", encoding="ascii")
    with pytest.raises(InformationError) as error:
        clock(1)
    assert error.value.code == "game_time_busy"
    assert clock.request.read_text(encoding="ascii") == "pending"


@pytest.mark.parametrize(("status", "error_code"), [
    ("applied", None),
    ("rejected", "game_time_rejected"),
    ("unconfirmed", "game_time_unconfirmed"),
])
def test_confirm_only_matching_native_receipt(observer, monkeypatch, status, error_code):
    clock = bind_game_time_control(observer)
    clock.log.write_bytes(b'{"event":"old"}\n')
    publish = clock._publish

    def native_roundtrip(record):
        publish(record)
        magic, session_id, revision, expiry, speed = clock.request.read_bytes().decode("ascii").split("\t")
        assert (magic, session_id, speed) == (PROTOCOL, observer.session_id, "2\n")
        assert int(expiry) > 116444736000000000 + int(revision) // 100
        clock.request.unlink()
        event = {"event": RESULT_EVENT, "session_id": session_id, "revision": int(revision),
                 "requested_speed": 2, "speed": 2, "paused": False, "date_raw": 56456976,
                 "status": status}
        with clock.log.open("ab") as stream:
            for receipt in (dict(event, session_id="other"), dict(event, revision=int(revision) - 1),
                            dict(event, speed=1, status="applied"),
                            dict(event, requested_speed=3), event):
                stream.write(json.dumps(receipt).encode("ascii") + b"\n")

    monkeypatch.setattr(clock, "_publish", native_roundtrip)
    if error_code is None:
        assert clock(2) == {"status": "applied", "speed": 2, "paused": False, "game_date_raw": 56456976}
    else:
        with pytest.raises(InformationError) as error:
            clock(2)
        assert error.value.code == error_code
