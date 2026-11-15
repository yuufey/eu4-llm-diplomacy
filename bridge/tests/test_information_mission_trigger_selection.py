"""Selective mission-trigger capture stays bound to loaded tasks and read scopes."""
from __future__ import annotations

from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import mission_memory
from bridge.information import mission_trigger_memory as trigger
from bridge.information.mission_read_scope import MissionReadSource, MissionScopedReader
from bridge.information.mission_trigger_source import normalize_triggers
from bridge.information.missions import NativeMissionReader
from bridge.tests.test_information_mission_read_scope import _mission_stack
from bridge.tests.test_information_mission_trigger_capture import (
    fixture as _capture_fixture,
)
from bridge.tests.test_information_mission_task_memory import (
    FakeCaptureKernel,
    _capture_patches,
)
from bridge.tests.test_information_mission_trigger_memory import (
    _fixture as _trigger_fixture,
    _install_root,
)
from bridge.tests.test_information_mission_trigger_source import (
    _prerequisites,
    _report,
    _task,
)


class _GuardedTreeReader:
    def __init__(self, reader, forbidden_addresses):
        self.reader = reader
        self.forbidden_addresses = set(forbidden_addresses)
        self.attempts = []
        self.module_base = reader.module_base

    def __getattr__(self, name):
        return getattr(self.reader, name)

    def _read(self, address, size, label, method):
        if address in self.forbidden_addresses:
            self.attempts.append((address, size, label))
            raise AssertionError(f"unselected mission trigger tree was read: {label}")
        return method(address, size, label)

    def read(self, address, size, label):
        return self._read(address, size, label, self.reader.read)

    def read_code(self, address, size, label):
        method = getattr(self.reader, "read_code", self.reader.read)
        return self._read(address, size, label, method)


def _capture_full(reader, module, *, selector=None, snapshot=None):
    kernel = FakeCaptureKernel(module)
    options = {
        # Completion-list memory is unrelated to trigger selection and the
        # shared synthetic fixture intentionally leaves its candidate map unknown.
        "include_completed": False,
        "include_tasks": True,
        "include_prerequisites": True,
        "include_conditions": True,
        "include_triggers": True,
    }
    if selector is not None:
        options["trigger_selector"] = selector
    with ExitStack() as stack:
        for patcher in _capture_patches(reader, kernel, snapshot=snapshot):
            stack.enter_context(patcher)
        report = mission_memory.capture(
            Path("fake-installation.json"), "FRA", **options,
        )
    assert len(kernel.closed) == 1
    return report


def _selected_report(rows, selector, *, captured_selector=None, include_captured_selector=True):
    report = _report(rows)
    report["request"]["trigger_selector"] = deepcopy(selector)
    if include_captured_selector:
        report["mission_triggers"]["task_selector"] = deepcopy(
            selector if captured_selector is None else captured_selector)
    return report


def _m02_progress_query(parameters):
    return {
        "topic": "M02",
        "object": {"type": "country", "country": "FRA"},
        "fields": ["currently_completable", "condition_progress"],
        "parameters": deepcopy(parameters),
    }


def test_selection_filters_before_reading_an_unselected_task_tree():
    reader, module, country, loaded, guards, _definitions, pointers = _trigger_fixture(
        ("task_a", "task_b"))
    selected = loaded["tasks"][0]
    selector = {"root_id": selected["root_id"], "task_id": "task_a"}
    _install_root(reader, module, pointers["task_a"], [])
    unselected_root = pointers["task_b"] + trigger.TASK_TRIGGER_OFFSET
    guarded = _GuardedTreeReader(reader, {unselected_root})

    result = trigger.capture_triggers(
        guarded, module, country, loaded, code_guards=guards,
        task_selector=selector,
    )

    assert result["status"] == "observed"
    assert result["complete"] is True
    assert [(row["root_id"], row["task_id"]) for row in result["tasks"]] == [
        (selected["root_id"], "task_a")]
    assert result["task_selector"] == selector
    assert result["_compare"]["task_selector"] == selector
    assert [row["task_id"] for row in result["_compare"]["tasks"]] == ["task_a"]
    assert guarded.attempts == []


def test_unmatched_selector_returns_a_complete_empty_capture_without_tree_reads():
    reader, module, country, loaded, guards, _definitions, pointers = _trigger_fixture(
        ("task_a", "task_b"))
    blocked = {pointer + trigger.TASK_TRIGGER_OFFSET for pointer in pointers.values()}
    guarded = _GuardedTreeReader(reader, blocked)
    selector = {"task_id": "not_loaded"}

    result = trigger.capture_triggers(
        guarded, module, country, loaded, code_guards=guards,
        task_selector=selector,
    )

    assert result["status"] == "observed"
    assert result["complete"] is True
    assert result["tasks"] == []
    assert result["total_task_count"] == 0
    assert result["task_selector"] == selector
    assert result["_compare"]["tasks"] == []
    assert result["_compare"]["task_selector"] == selector
    assert guarded.attempts == []


def test_none_selector_preserves_legacy_full_task_capture():
    reader, module, country, loaded, guards, _definitions, pointers = _trigger_fixture(
        ("task_a", "task_b"))
    for task_id in ("task_a", "task_b"):
        _install_root(reader, module, pointers[task_id], [])

    result = trigger.capture_triggers(reader, module, country, loaded, code_guards=guards)

    assert result["status"] == "observed"
    assert [row["task_id"] for row in result["tasks"]] == ["task_a", "task_b"]
    assert result["task_selector"] is None
    assert result["_compare"]["task_selector"] is None


@pytest.mark.parametrize("selector", [
    {},
    {"other": "task_a"},
    {"task_id": "bad/task"},
])
def test_invalid_selectors_fail_closed_before_reading_any_task_tree(selector):
    reader, module, country, loaded, guards, _definitions, pointers = _trigger_fixture(
        ("task_a", "task_b"))
    guarded = _GuardedTreeReader(
        reader,
        {pointer + trigger.TASK_TRIGGER_OFFSET for pointer in pointers.values()},
    )

    result = trigger.capture_triggers(
        guarded, module, country, loaded, code_guards=guards,
        task_selector=selector,
    )

    assert result["status"] == "unknown"
    assert "MISSION_TRIGGER_SELECTOR_INVALID" in result["reason"]
    assert guarded.attempts == []


def test_full_capture_records_and_forwards_the_selected_trigger_scope():
    reader, module, _country = _capture_fixture()
    selector = {"task_id": "task_a"}

    report = _capture_full(reader, module, selector=selector)

    assert report["request"]["trigger_selector"] == selector
    assert report["doublepass"]["trigger_consistent"] is True
    assert report["mission_triggers"]["status"] == "observed"
    assert [row["task_id"] for row in report["mission_triggers"]["tasks"]] == ["task_a"]
    assert report["mission_triggers"]["task_selector"] == selector
    assert report["before"]["mission_triggers"]["task_selector"] == selector


def test_selected_trigger_capture_still_rejects_two_pass_input_drift():
    reader, module, country = _capture_fixture()
    selector = {"task_id": "task_a"}
    original_snapshot = mission_memory._snapshot
    calls = 0

    def drift_snapshot(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            # Keep the derived boolean stable while changing a sampled input.
            reader.dword_put(country + 0xDC4, 999999, signed=True)
        return original_snapshot(*args, **kwargs)

    report = _capture_full(reader, module, selector=selector, snapshot=drift_snapshot)

    assert report["doublepass"]["trigger_consistent"] is False
    assert report["mission_triggers"] == {
        "status": "unknown",
        "complete": False,
        "reason": "MISSION_TRIGGER_CAPTURE_OR_CONSISTENCY_FAILED",
    }


def test_normalizer_projects_only_the_selected_loaded_subset_and_accepts_legacy_full_events():
    selector = {"task_id": "task_a"}
    selected = normalize_triggers(
        _selected_report([_task("task_a")], selector),
        _prerequisites("task_a", "task_b"),
    )
    legacy = normalize_triggers(
        _report([_task("task_a"), _task("task_b")]),
        _prerequisites("task_a", "task_b"),
    )

    assert selected["status"] == "known"
    assert [row["task_id"] for row in selected["tasks"]] == ["task_a"]
    assert selected["task_selector"] == selector
    assert legacy["status"] == "known"
    assert [row["task_id"] for row in legacy["tasks"]] == ["task_a", "task_b"]
    assert legacy["task_selector"] is None


@pytest.mark.parametrize("corruption", [
    "missing_selected", "unselected_extra", "duplicate_selected",
    "reordered_selected", "selector_mismatch", "missing_selector_marker",
])
def test_normalizer_rejects_incomplete_or_mismatched_selected_task_sets(corruption):
    selector = {"task_id": "task_a"}
    rows = [_task("task_a")]
    captured_selector = selector
    include_selector_marker = True
    if corruption == "missing_selected":
        rows = []
    elif corruption == "unselected_extra":
        rows = [_task("task_a"), _task("task_b")]
    elif corruption == "duplicate_selected":
        rows = [_task("task_a"), _task("task_a")]
    elif corruption == "reordered_selected":
        selector = {"root_id": "loaded"}
        rows = [_task("task_b"), _task("task_a")]
        captured_selector = selector
    elif corruption == "selector_mismatch":
        captured_selector = {"task_id": "task_b"}
    else:
        include_selector_marker = False

    report = _selected_report(
        rows, selector, captured_selector=captured_selector,
        include_captured_selector=include_selector_marker,
    )
    normalized = normalize_triggers(report, _prerequisites("task_a", "task_b"))

    assert normalized["status"] == "unknown"


def test_native_reader_only_forwards_selection_for_its_builtin_capture(monkeypatch):
    base = SimpleNamespace(
        session=SimpleNamespace(directory=Path("fixture-installation")),
        context=lambda: {
            "status": "ready", "observer": "FRA", "mode": "live",
            "session_id": "session", "game_date": 1,
        },
    )
    selector = {"root_id": "root_main", "task_id": "task_core"}
    calls = []

    def capture(*args, **kwargs):
        calls.append((args, kwargs))
        return {"synthetic": True}

    builtin = NativeMissionReader(base)
    builtin.normalize = lambda _report, _context: {"loaded_tasks": {"status": "known"}}
    monkeypatch.setattr(mission_memory, "capture", capture)
    assert builtin.supports_trigger_selection is True
    builtin("FRA", trigger_selector=selector)
    assert calls[-1][1]["trigger_selector"] == selector
    assert calls[-1][1]["include_triggers"] is True

    legacy_calls = []

    def custom_capture(*args, **kwargs):
        legacy_calls.append((args, kwargs))
        return {"synthetic": True}

    custom = NativeMissionReader(base, capture=custom_capture)
    custom.normalize = lambda _report, _context: {"loaded_tasks": {"status": "known"}}
    assert custom.supports_trigger_selection is False
    custom("FRA", trigger_selector=selector)
    assert legacy_calls[-1][1] == {"include_completed": True, "include_tasks": True}


def test_selected_dynamic_m02_uses_original_reader_per_request_inside_its_scope():
    stack = _mission_stack()
    calls = []

    class SelectableStateReader:
        supports_trigger_selection = True

        def __call__(self, country, *, trigger_selector=None):
            calls.append((country, deepcopy(trigger_selector)))
            return deepcopy(stack.state.sample)

    scoped = MissionScopedReader(SelectableStateReader(), stack.scoped.rule_reader)
    stack.missions.reader = scoped
    source = MissionReadSource(stack.composite, scoped)
    context = stack.primary.context()
    selectors = [
        {"root_id": "root_main", "task_id": "task_core"},
        {"root_id": "root_main", "task_id": "task_owned"},
    ]

    results = [
        source.read(source.validate_query(_m02_progress_query(selector)), context)
        for selector in selectors
    ]

    assert calls == [("FRA", selector) for selector in selectors]
    assert stack.rule_calls == []
    for result, selector in zip(results, selectors):
        collection = result["source"]["mission_collection"]
        assert collection["state_reader_calls"] == 1
        assert collection["cross_request_cache"] is False
        assert collection["trigger_progress_requested"] is True
        assert collection["trigger_task_selector"] == selector


def test_selected_dynamic_m02_keeps_ordinary_country_callable_compatible():
    stack = _mission_stack()
    calls = []

    def ordinary_reader(country):
        calls.append(country)
        return deepcopy(stack.state.sample)

    scoped = MissionScopedReader(ordinary_reader, stack.scoped.rule_reader)
    stack.missions.reader = scoped
    source = MissionReadSource(stack.composite, scoped)
    selector = {"root_id": "root_main", "task_id": "task_core"}
    result = source.read(
        source.validate_query(_m02_progress_query(selector)), stack.primary.context())

    assert calls == ["FRA"]
    assert stack.rule_calls == []
    assert result["source"]["mission_collection"]["trigger_task_selector"] == selector
