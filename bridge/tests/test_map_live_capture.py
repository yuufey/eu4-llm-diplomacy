from __future__ import annotations

import json
from pathlib import Path

import bridge.map_live_capture as live


def _installation(tmp_path: Path) -> Path:
    path = tmp_path / "installation.json"
    path.write_text(json.dumps({"pid": 42}), encoding="utf-8")
    return path


def test_request_is_bounded_and_rejects_duplicates(tmp_path):
    path = _installation(tmp_path)
    assert live._validate_request(path, "TUR", [1, 2])[2] == (1, 2)
    for values in ([1, 1], [], list(range(live.MAX_PROVINCES + 1))):
        try:
            live._validate_request(path, "TUR", values)
        except live.MapLiveCaptureError:
            pass
        else:
            raise AssertionError("invalid request was accepted")


def test_observe_many_keeps_known_and_unknown_owners(monkeypatch):
    contexts = [{"game_date": 100, "observer": "TUR"}, {"game_date": 100, "observer": "TUR"}]
    monkeypatch.setattr(live._owner, "_guards", lambda *args: [{"status": "known"}])
    monkeypatch.setattr(live._owner, "_context", lambda *args: contexts.pop(0))
    values = {1: {"discovered": True, "owner": "TUR", "controller": "TUR"},
              2: {"discovered": False, "owner": None, "controller": None}}
    monkeypatch.setattr(live, "_read_pass", lambda *args: {"status": "observed", "values": values})
    result = live._observe_many(object(), 0x10000, "TUR", (1, 2), {})
    assert result["stable"] is True
    assert result["values"][1]["owner"] == "TUR"
    assert result["values"][2]["discovered"] is False


def test_capture_live_projects_identity_and_timings(monkeypatch, tmp_path):
    path = _installation(tmp_path)
    monkeypatch.setattr(live._owner, "_capture_common", lambda *args, **kwargs: {
        "status": "observed", "completed": True,
        "identity": {"installation_pid": 42, "process_creation_filetime": 77},
        "request": {"session_id": "s", "pid": 42, "creation_filetime": 77},
        "observation": {"stable": True, "context_after": {"game_date": 56896992},
                        "values": {1: {"discovered": True, "owner": "TUR", "controller": "TUR"}}},
        "access": {"calls": 5, "bytes_requested": 120},
    })
    result = live.capture_live(path, "TUR", [1])
    assert result["date"] == "1495.2.3"
    assert result["owners"] == {1: "TUR"}
    assert result["identity"]["pid"] == 42
    assert result["timings"]["rpm_calls"] == 5

def test_date_change_with_identical_provinces_rejects_snapshot(monkeypatch):
    dates = iter((56896992, 56897016))
    monkeypatch.setattr(live._owner, "_context", lambda *_: {"game_date": next(dates)})
    monkeypatch.setattr(live._owner, "_guards", lambda *_: [])
    monkeypatch.setattr(live, "_read_pass", lambda *_: {"values": {1: {"owner": "TUR"}}})
    assert not live._observe_many(None, 0, "TUR", (1,), {})["stable"]
