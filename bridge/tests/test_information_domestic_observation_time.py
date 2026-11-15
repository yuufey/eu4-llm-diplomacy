"""Domestic-pressure date handling inside macro observation windows."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information import domestic_pressure_memory as dpm
from bridge.information.observation_time import sampled_read
from bridge.tests import test_information_domestic_pressure as source_tests
from bridge.tests import test_information_domestic_pressure_memory as memory_tests


GAME_DATE = source_tests.GAME_DATE


@pytest.fixture
def memory_setup(monkeypatch):
    return memory_tests.capture_setup.__wrapped__(monkeypatch)


def _with_date(context: dict, game_date: int) -> dict:
    result = deepcopy(context)
    result["game_date"] = game_date
    result["game_date_raw"] = game_date
    return result


def _report_for_dates(session, before_date: int, after_date: int) -> dict:
    report = source_tests._report(session)
    for label, game_date in (("before", before_date), ("after", after_date)):
        snapshot = report[label]
        snapshot["game_date"]["value"] = game_date
        snapshot["game_date"]["raw_hex"] = source_tests._raw_hex(game_date)
    return report


def _queued_contexts(base, *contexts: dict) -> None:
    queue = [deepcopy(context) for context in contexts]
    base.context = lambda: queue.pop(0)


def _change_memory_date_after_first_pass(monkeypatch, setup, second_date: int) -> None:
    profile, kernel = setup
    original_snapshot = dpm._snapshot
    calls = 0

    def changing_snapshot(reader, module_base, country, active_profile, fields):
        nonlocal calls
        snapshot = original_snapshot(reader, module_base, country, active_profile, fields)
        calls += 1
        if calls == 1:
            globals_ = profile["globals"]
            date_offset = memory_tests._profile_int(globals_["game_date_offset"])
            memory_tests._put_s32(kernel.memory, memory_tests.GAME_POINTER + date_offset, second_date)
        return snapshot

    monkeypatch.setattr(dpm, "_snapshot", changing_snapshot)


def test_active_domestic_pressure_window_accepts_forward_sampling_dates(tmp_path: Path, monkeypatch, memory_setup):
    source, base, session, _calls = source_tests._source(
        tmp_path,
        report=lambda active_session: _report_for_dates(
            active_session, GAME_DATE + 2, GAME_DATE + 3,
        ),
    )
    supplied = base.context()
    before_context = _with_date(supplied, GAME_DATE + 1)
    after_context = _with_date(supplied, GAME_DATE + 2)
    _queued_contexts(base, before_context, after_context)
    query = source_tests._query(["stability"])

    with sampled_read(query, supplied) as window:
        result = source.read(query, supplied)

    assert result["fields"]["stability"]["status"] == "known"
    assert window.metadata()["start_game_date"] == GAME_DATE
    assert window.metadata()["end_game_date"] == GAME_DATE + 3

    _change_memory_date_after_first_pass(monkeypatch, memory_setup, GAME_DATE + 1)
    with sampled_read({"topic": "N04"}, supplied):
        report = dpm.capture(Path("fake-installation.json"), "FRA", ["stability"])
    assert report["status"] == "observed"
    assert report["before"]["game_date"]["value"] == GAME_DATE
    assert report["after"]["game_date"]["value"] == GAME_DATE + 1
    assert any(
        item.get("label") == "game.game_date" and item.get("raw_hex") == source_tests._raw_hex(GAME_DATE)
        for item in report["before"]["read_log"]
    )


def test_default_domestic_pressure_window_keeps_strict_date_equality(tmp_path: Path, monkeypatch, memory_setup):
    source, base, session, _calls = source_tests._source(
        tmp_path,
        report=lambda active_session: _report_for_dates(
            active_session, GAME_DATE + 1, GAME_DATE + 1,
        ),
    )
    context = base.context()
    result = source.read(source_tests._query(["stability"]), context)
    assert result["fields"]["stability"]["status"] == "unknown"
    assert "BEFORE_DATE" in result["fields"]["stability"]["reason"]

    _change_memory_date_after_first_pass(monkeypatch, memory_setup, GAME_DATE + 1)
    report = dpm.capture(Path("fake-installation.json"), "FRA", ["stability"])
    assert report["status"] == "doublepass_mismatch"
    assert any(path.startswith("$.game_date") for path in report["doublepass"]["mismatches"])


def test_active_domestic_pressure_window_rejects_date_rollback(tmp_path: Path, monkeypatch, memory_setup):
    source, base, _session, calls = source_tests._source(
        tmp_path / "supplied-context-rollback",
        report=lambda active_session: _report_for_dates(
            active_session, GAME_DATE + 2, GAME_DATE + 2,
        ),
    )
    supplied = _with_date(base.context(), GAME_DATE + 2)
    _queued_contexts(
        base, _with_date(supplied, GAME_DATE + 1), _with_date(supplied, GAME_DATE + 3),
    )
    query = source_tests._query(["stability"])
    with sampled_read(query, supplied):
        result = source.read(query, supplied)
    assert result["fields"]["stability"]["status"] == "unavailable"
    assert "CONTEXT_CHANGED_BEFORE_CAPTURE" in result["fields"]["stability"]["reason"]
    assert calls == []

    source, base, session, _calls = source_tests._source(
        tmp_path,
        report=lambda active_session: _report_for_dates(
            active_session, GAME_DATE + 2, GAME_DATE + 1,
        ),
    )
    supplied = base.context()
    _queued_contexts(base, _with_date(supplied, GAME_DATE + 1), _with_date(supplied, GAME_DATE + 3))
    query = source_tests._query(["stability"])
    with sampled_read(query, supplied):
        result = source.read(query, supplied)
    assert result["fields"]["stability"]["status"] == "unknown"
    assert "DATE_ORDER" in result["fields"]["stability"]["reason"]

    _change_memory_date_after_first_pass(monkeypatch, memory_setup, GAME_DATE - 1)
    with sampled_read({"topic": "N04"}, {"mode": "live", "game_date": GAME_DATE}):
        report = dpm.capture(Path("fake-installation.json"), "FRA", ["stability"])
    assert report["status"] == "doublepass_mismatch"
    assert any(path.startswith("$.game_date") for path in report["doublepass"]["mismatches"])


def test_active_domestic_pressure_window_still_rejects_identity_change(tmp_path: Path):
    source, base, _session, _calls = source_tests._source(
        tmp_path,
        report=lambda active_session: _report_for_dates(
            active_session, GAME_DATE + 2, GAME_DATE + 2,
        ),
    )
    supplied = base.context()
    before_context = _with_date(supplied, GAME_DATE + 1)
    after_context = _with_date(supplied, GAME_DATE + 2)
    after_context["world_id"] = "world-2"
    _queued_contexts(base, before_context, after_context)
    query = source_tests._query(["stability"])

    with sampled_read(query, supplied):
        result = source.read(query, supplied)

    assert result["fields"]["stability"]["status"] == "unknown"
    assert "CONTEXT_CHANGED_DURING_CAPTURE" in result["fields"]["stability"]["reason"]
