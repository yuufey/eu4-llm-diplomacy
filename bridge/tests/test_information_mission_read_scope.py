"""Focused tests for the per-read mission state collection scope."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import threading

import pytest

from bridge.information.composite import CompositeSource
from bridge.information.mission_chain_targets import MissionChainTargetsSource
from bridge.information.mission_chain_timing import MissionChainTimingSource
from bridge.information.mission_read_scope import (
    MissionReadSource,
    MissionScopedReader,
    capture_rule_inputs,
)
from bridge.information.missions import NativeMissionReader
from bridge.tests import test_information_mission_chain_targets as chain_fixture


def _m05_query(fields=("reward_timing", "linked_targets", "basis"), **parameters):
    return {
        "topic": "M05",
        "object": {"type": "country", "country": "FRA"},
        "fields": list(fields),
        "parameters": parameters or {"root_id": "root_main", "task_id": "task_core"},
    }


def _m03_query(fields=("provinces",)):
    return {
        "topic": "M03",
        "object": {"type": "country", "country": "FRA"},
        "fields": list(fields),
        "parameters": {},
    }


def _mission_stack():
    """Build the real mission/timing/targets composition over the 179 fixture."""
    _targets, missions, primary, state, definitions = chain_fixture.setup_source()
    old_calls = []
    rule_calls = []

    def old_reader(country):
        old_calls.append(country)
        return deepcopy(state.sample)

    def rule_reader(country):
        rule_calls.append(country)
        return deepcopy(state.sample)

    scoped = MissionScopedReader(old_reader, rule_reader)
    missions.reader = scoped
    timing = MissionChainTimingSource(missions)
    targets = MissionChainTargetsSource(missions)
    composite = CompositeSource(primary, [missions, timing, targets])
    source = MissionReadSource(composite, scoped)
    return SimpleNamespace(
        source=source,
        composite=composite,
        missions=missions,
        primary=primary,
        state=state,
        definitions=definitions,
        scoped=scoped,
        old_calls=old_calls,
        rule_calls=rule_calls,
    )


def test_capture_rule_inputs_forwards_lightweight_flags(monkeypatch):
    calls = []

    def fake_capture(*args, **kwargs):
        calls.append((args, kwargs))
        return {"status": "observed"}

    from bridge.information import mission_memory

    monkeypatch.setattr(mission_memory, "capture", fake_capture)
    result = capture_rule_inputs("install/installation.json", "FRA",
                                include_completed=False, include_tasks=False)

    assert result == {"status": "observed"}
    assert calls == [(
        ("install/installation.json", "FRA"),
        {
            "include_completed": False,
            "include_tasks": False,
            "include_prerequisites": True,
            "include_conditions": True,
            "include_triggers": False,
        },
    )]


def test_mixed_m05_uses_one_rule_reader_and_preserves_public_field_semantics():
    stack = _mission_stack()
    query = stack.source.validate_query(_m05_query())
    result = stack.source.read(query, stack.primary.context())

    assert stack.rule_calls == ["FRA"]
    assert stack.old_calls == []
    assert set(result["fields"]) == {"reward_timing", "linked_targets", "basis"}
    timing = result["fields"]["reward_timing"]
    assert timing["status"] == "known"
    assert timing["complete"] is False
    assert timing["value"]["conditions_evaluated"] is False
    assert timing["value"]["candidate_feasibility"] == "unknown"
    assert result["fields"]["linked_targets"]["complete"] is False
    assert result["fields"]["basis"]["complete"] is False
    collection = result["source"]["mission_collection"]
    assert collection["state_reader_calls"] == 1
    assert collection["shared_state_hits"] >= 1
    assert collection["cross_request_cache"] is False
    assert collection["trigger_progress_requested"] is False


def test_same_date_second_rule_query_starts_a_new_collection():
    stack = _mission_stack()
    context = stack.primary.context()

    first = stack.source.read(_m03_query(), context)
    second = stack.source.read(_m03_query(), context)

    assert first["source"]["mission_collection"]["state_reader_calls"] == 1
    assert second["source"]["mission_collection"]["state_reader_calls"] == 1
    assert stack.rule_calls == ["FRA", "FRA"]
    assert stack.old_calls == []


@pytest.mark.parametrize("topic,fields", [
    ("M01", ["task_id"]),
    ("M01", ["task_id", "name", "description", "branches"]),
    ("M02", ["completion_status"]),
    ("M02", ["prerequisites", "completion_status"]),
])
def test_mission_lists_and_completion_reuse_rule_inputs_without_changing_fields(topic, fields):
    stack = _mission_stack()
    query = {"topic": topic, "object": {"type": "country", "country": "FRA"},
             "fields": fields, "parameters": {}}
    expected = stack.composite.read(query, stack.primary.context())
    assert stack.old_calls == ["FRA"]
    stack.old_calls.clear()

    result = stack.source.read(query, stack.primary.context())

    assert result["fields"] == expected["fields"]
    assert stack.rule_calls == ["FRA"]
    assert stack.old_calls == []
    assert result["source"]["mission_collection"]["trigger_progress_requested"] is False


def test_full_native_reader_keeps_triggers_for_m02_eligibility_and_progress(monkeypatch):
    captured = {}

    def fake_capture(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        raise RuntimeError("stop after request audit")

    from bridge.information import mission_memory

    base = SimpleNamespace(
        session=SimpleNamespace(directory=Path("fixture-installation")),
        context=lambda: {
            "status": "ready", "observer": "FRA", "mode": "live",
            "session_id": "session", "game_date": 1,
        },
    )
    reader = NativeMissionReader(base)
    monkeypatch.setattr(mission_memory, "capture", fake_capture)
    with pytest.raises(RuntimeError, match="stop after request audit"):
        reader("FRA")

    assert captured["args"] == (Path("fixture-installation") / "installation.json", "FRA")
    assert captured["kwargs"] == {
        "include_completed": True,
        "include_tasks": True,
        "include_prerequisites": True,
        "include_conditions": True,
        "include_triggers": True,
    }

    stack = _mission_stack()
    m02 = {
        "topic": "M02",
        "object": {"type": "country", "country": "FRA"},
        "fields": ["currently_completable", "condition_progress"],
        "parameters": {},
    }
    result = stack.source.read(m02, stack.primary.context())
    assert set(result["fields"]) == {"currently_completable", "condition_progress"}
    assert stack.old_calls == ["FRA"]
    assert stack.rule_calls == []


def test_failed_capture_is_cached_within_scope_but_retried_by_next_query():
    calls = []

    def failing(country):
        calls.append(country)
        raise RuntimeError("capture failed")

    class DoubleReadSource:
        def __init__(self, reader):
            self.reader = reader

        def read(self, query, context):
            errors = []
            for _ in range(2):
                try:
                    self.reader("FRA")
                except RuntimeError as exc:
                    errors.append(str(exc))
            assert errors == ["capture failed", "capture failed"]
            return {"fields": {}, "complete": False}

    scoped = MissionScopedReader(lambda country: {"country": country}, failing)
    source = MissionReadSource(DoubleReadSource(scoped), scoped)
    query = _m03_query()
    context = {"status": "ready", "observer": "FRA"}

    first = source.read(query, context)
    assert calls == ["FRA"]
    assert first["source"]["mission_collection"]["shared_state_hits"] == 1

    second = source.read(query, context)
    assert calls == ["FRA", "FRA"]
    assert second["source"]["mission_collection"]["state_reader_calls"] == 1


def test_scope_exit_on_exception_clears_cache_and_returns_to_original_reader():
    original_calls = []
    rule_calls = []

    def original(country):
        original_calls.append(country)
        return {"origin": "original", "country": country}

    def rule(country):
        rule_calls.append(country)
        return {"origin": "rule", "country": country}

    scoped = MissionScopedReader(original, rule)
    with pytest.raises(ValueError, match="abort scope"):
        with scoped.collection({"date": 1}):
            assert scoped("FRA")["origin"] == "rule"
            raise ValueError("abort scope")

    assert scoped("FRA")["origin"] == "original"
    assert rule_calls == ["FRA"]
    assert original_calls == ["FRA"]


def test_reader_returns_deep_copies_to_each_consumer():
    calls = []
    payload = {"country": "FRA", "nested": {"tasks": ["task_owned"]}}

    def rule(country):
        calls.append(country)
        return payload

    scoped = MissionScopedReader(lambda country: {"origin": "old"}, rule)
    with scoped.collection({}):
        first = scoped("FRA")
        first["nested"]["tasks"].append("consumer_mutation")
        first["nested"]["extra"] = True
        second = scoped("FRA")

    assert calls == ["FRA"]
    assert second == {"country": "FRA", "nested": {"tasks": ["task_owned"]}}
    assert payload == {"country": "FRA", "nested": {"tasks": ["task_owned"]}}


def test_contextvar_isolates_nested_scopes_and_two_threads():
    calls = []
    lock = threading.Lock()
    barrier = threading.Barrier(2)

    def rule(country):
        ident = threading.get_ident()
        with lock:
            calls.append(ident)
            invocation = len(calls)
        if threading.current_thread() is not threading.main_thread():
            barrier.wait(timeout=5)
        return {"country": country, "thread": ident, "sequence": invocation}

    scoped = MissionScopedReader(lambda country: {"origin": "old"}, rule)
    with scoped.collection({"scope": "outer"}):
        outer_first = scoped("FRA")
        with scoped.collection({"scope": "nested"}):
            nested_first = scoped("FRA")
            nested_second = scoped("FRA")
        outer_second = scoped("FRA")
    assert outer_first == outer_second
    assert nested_first == nested_second
    assert outer_first != nested_first

    results = []
    errors = []

    def worker():
        try:
            with scoped.collection({"thread": threading.get_ident()}):
                first = scoped("FRA")
                second = scoped("FRA")
                results.append((first, second))
        except BaseException as exc:  # make worker failures visible to pytest
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert not any(thread.is_alive() for thread in threads)
    assert errors == []
    assert len(results) == 2
    assert all(first == second for first, second in results)
    assert len({first["thread"] for first, _ in results}) == 2


def test_catalog_validate_proxy_and_scope_rejections_remain_unchanged():
    stack = _mission_stack()
    query = _m05_query()

    assert stack.source.context() == stack.composite.context()
    assert stack.source.catalog() == stack.composite.catalog()
    assert stack.source.validate_query(query) == stack.composite.validate_query(query)

    wrong_country = deepcopy(query)
    wrong_country["object"]["country"] = "ENG"
    rejected_country = stack.source.read(wrong_country, stack.primary.context())
    assert all(field["status"] == "unavailable"
               and field["reason"] == "observer_scope_mismatch"
               for field in rejected_country["fields"].values())

    wrong_session = deepcopy(query)
    wrong_session["object"]["session_id"] = "different-session"
    rejected_session = stack.source.read(wrong_session, stack.primary.context())
    assert all(field["status"] == "unavailable"
               and field["reason"] == "session_scope_mismatch"
               for field in rejected_session["fields"].values())
    assert stack.old_calls == []
    assert stack.rule_calls == []


def test_reader_helpers_keep_the_original_bound_receiver():
    calls = []

    class Original:
        supported_countries = ("FRA",)

        def __call__(self, country):
            return {"country": country}

        def branch_inputs(self, country, context):
            calls.append((self, country, context))
            return {"status": "known", "value": "original helper"}

    original = Original()
    reader = MissionScopedReader(original, lambda country: {"origin": "rule"})
    context = {"observer": "FRA"}
    with reader.collection(context):
        assert reader.branch_inputs("FRA", context) == {"status": "known", "value": "original helper"}
        assert reader.supported_countries == ("FRA",)
    assert calls == [(original, "FRA", context)]
