from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

from bridge.map_schedule import MapSchedule, MapScheduleError


class Clock:
    def __init__(self, date="1444.1.1"):
        self.date = date

    def __call__(self):
        return self.date


class Service:
    observer = "TUR"
    session_id = "session-1"


def install_publisher(monkeypatch, calls, failures=0):
    module = types.ModuleType("bridge.map_archive")

    def publish(service, directory, **view):
        calls.append((service, Path(directory), dict(view)))
        if len(calls) <= failures:
            raise RuntimeError("temporary export failure")
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "latest.marker").write_text(str(len(calls)), encoding="utf-8")
        return {"directory": str(directory), "view": view, "sequence": len(calls)}

    module.publish_map_bundle = publish
    monkeypatch.setitem(sys.modules, "bridge.map_archive", module)


def test_configure_publishes_once_and_repeated_configuration_is_idempotent(tmp_path, monkeypatch):
    calls = []
    install_publisher(monkeypatch, calls)
    clock = Clock()
    schedule = MapSchedule(Service(), tmp_path / "state.json", clock, tmp_path / "exports")

    first = schedule.manage("configure", "maps", 6, center_country="TUR")
    second = schedule.manage("configure", "maps", 6, center_country="TUR")

    assert first["status"] == "published"
    assert second["status"] == "already_configured"
    assert len(calls) == 1
    assert calls[0][1] == (tmp_path / "exports" / "maps").resolve()


def test_tick_uses_game_months_and_retries_a_failed_publication(tmp_path, monkeypatch):
    calls = []
    install_publisher(monkeypatch, calls, failures=1)
    clock = Clock("1444.1.1")
    schedule = MapSchedule(Service(), tmp_path / "state.json", clock, tmp_path / "exports")

    failed = schedule.manage("configure", "maps")
    assert failed["status"] == "error"
    assert schedule.status()["last_success_date"] is None

    succeeded = schedule.tick()
    assert succeeded["status"] == "published"
    clock.date = "1444.6.30"
    assert schedule.tick()["status"] == "waiting"
    clock.date = "1444.7.1"
    assert schedule.tick()["status"] == "published"
    clock.date = "1445.7.1"
    assert schedule.tick()["status"] == "published"
    assert len(calls) == 4


def test_disable_persists_and_reopen_restores_configuration(tmp_path, monkeypatch):
    calls = []
    install_publisher(monkeypatch, calls)
    clock = Clock("1444.1.1")
    state = tmp_path / "state.json"
    first = MapSchedule(Service(), state, clock, tmp_path / "exports")
    first.manage("configure", "maps", interval_months=3)
    first.manage("disable")

    reopened = MapSchedule(Service(), state, clock, tmp_path / "exports")
    assert reopened.tick()["status"] == "disabled"
    assert reopened.status()["directory"].endswith("exports\\maps") or reopened.status()["directory"].endswith("exports/maps")
    assert len(calls) == 1


def test_directory_must_stay_under_export_root(tmp_path, monkeypatch):
    install_publisher(monkeypatch, [])
    schedule = MapSchedule(Service(), tmp_path / "state.json", Clock(), tmp_path / "exports")
    with pytest.raises(MapScheduleError, match="OUTSIDE_EXPORT_ROOT"):
        schedule.manage("configure", tmp_path / "outside")


def test_due_date_preserves_day_and_clamps_short_month(tmp_path, monkeypatch):
    calls = []
    install_publisher(monkeypatch, calls)
    clock = Clock("1444.2.3")
    schedule = MapSchedule(Service(), tmp_path / "state.json", clock, tmp_path / "exports")
    schedule.manage("configure", "maps", interval_months=6)
    assert schedule.status()["next_due_date"] == "1444.8.3"
    clock.date = "1444.8.2"
    assert schedule.tick()["status"] == "waiting"
    clock.date = "1444.8.3"
    assert schedule.tick()["status"] == "published"


def test_disabled_tick_does_not_read_clock(tmp_path, monkeypatch):
    calls = []
    install_publisher(monkeypatch, calls)
    clock = Clock("1444.1.1")
    schedule = MapSchedule(Service(), tmp_path / "state.json", clock, tmp_path / "exports")
    schedule.manage("configure", "maps")
    schedule.manage("disable")

    def fail_clock():
        raise AssertionError("disabled schedule touched the game clock")

    schedule.clock = fail_clock
    assert schedule.tick()["status"] == "disabled"


def test_external_state_change_is_reloaded(tmp_path, monkeypatch):
    calls = []
    install_publisher(monkeypatch, calls)
    state = tmp_path / "state.json"
    clock = Clock()
    first = MapSchedule(Service(), state, clock, tmp_path / "exports")
    first.manage("configure", "one")
    second = MapSchedule(Service(), state, clock, tmp_path / "exports")
    second.manage("configure", "two")
    assert first.status()["directory"].endswith("exports\\two") or first.status()["directory"].endswith("exports/two")
