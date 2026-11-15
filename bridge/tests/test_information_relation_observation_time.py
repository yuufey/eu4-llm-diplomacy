"""R01/R04 context-date binding inside macro observation windows."""
from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from bridge.information import relation_memory
from bridge.information.observation_time import sampled_read
from bridge.information.opinion import NativeOpinionSource
from bridge.information.opinion_modifiers import NativeOpinionModifiersSource
from bridge.information.relation_state import NativeRelationSource
from bridge.tests import test_information_opinion as opinion_tests
from bridge.tests import test_information_opinion_modifiers as modifier_tests
from bridge.tests import test_information_relation_state as relation_tests


GAME_DATE = relation_tests._context()["game_date"]


def _with_date(context: dict, date: int) -> dict:
    result = deepcopy(context)
    result["game_date"] = date
    result["game_date_raw"] = date
    return result


def _assert_known(result: dict, field: str) -> None:
    assert result["fields"][field]["status"] == "known"


def _relation_memory_report(before_date: int, after_date: int) -> dict:
    return {
        "context_before": {"status": "observed", "game_date": {"value": before_date}},
        "context_after": {"status": "observed", "game_date": {"value": after_date}},
        "fields": {"alliance": {"status": "known", "value": True}},
        "profile": {"sha256": "a" * 64},
    }


def test_active_r01_and_r04_accept_forward_context_dates(tmp_path):
    supplied = relation_tests._context()
    before = _with_date(supplied, GAME_DATE + 1)
    after = _with_date(supplied, GAME_DATE + 2)
    primary = relation_tests.RecordedPrimary(context=before)
    primary.diplomacy_tools.on_call = lambda *_args: setattr(primary, "_context", deepcopy(after))
    relation_source = NativeRelationSource(primary)
    relation_query = relation_tests._query("ORL", ["vassalization"])

    with sampled_read(relation_query, supplied):
        relation_result = relation_source.read(relation_query, supplied)
    _assert_known(relation_result, "status")
    assert relation_result["fields"]["status"]["value"][0]["value"] == "active"

    opinion_date = opinion_tests.CONTEXT["game_date"]
    opinion_before = _with_date(opinion_tests.CONTEXT, opinion_date + 1)
    opinion_after = _with_date(opinion_tests.CONTEXT, opinion_date + 2)
    opinion_harness = opinion_tests.CaptureHarness()
    opinion_source, opinion_primary, opinion_harness = opinion_tests._source(
        tmp_path,
        context=opinion_before,
        harness=opinion_harness,
    )
    opinion_harness.after_capture = lambda: opinion_primary._context.update(opinion_after)
    opinion_query = opinion_tests._query()
    with sampled_read(opinion_query, opinion_tests.CONTEXT):
        opinion_result = opinion_source.read(opinion_query, opinion_tests.CONTEXT)
        comparison = opinion_source.change_comparison(
            opinion_query, opinion_result, _with_date(opinion_tests.CONTEXT, opinion_date + 3),
        )
    _assert_known(opinion_result, "opinion")
    assert comparison is not None
    assert len(opinion_harness.validator_calls) == 1

    modifier_date = modifier_tests.CONTEXT["game_date"]
    modifier_before = _with_date(modifier_tests.CONTEXT, modifier_date + 1)
    modifier_after = _with_date(modifier_tests.CONTEXT, modifier_date + 2)
    modifier_primary = modifier_tests.Primary(tmp_path, context=modifier_before)
    modifier_harness = modifier_tests.CaptureHarness(
        after_capture=lambda: modifier_primary._context.update(modifier_after),
    )
    modifier_source = NativeOpinionModifiersSource(
        modifier_primary, capture=modifier_harness.capture, validator=modifier_harness.validate,
    )
    modifier_query = modifier_tests._query()
    with sampled_read(modifier_query, modifier_tests.CONTEXT):
        modifier_result = modifier_source.read(modifier_query, modifier_tests.CONTEXT)
    _assert_known(modifier_result, "opinion_modifiers")


def test_active_r01_memory_capture_rebinds_date_without_mutating_report(tmp_path, monkeypatch):
    supplied = relation_tests._context()
    before_context = _with_date(supplied, GAME_DATE + 1)
    after_context = _with_date(supplied, GAME_DATE + 3)
    report = _relation_memory_report(GAME_DATE + 2, GAME_DATE + 2)
    primary = relation_tests.RecordedPrimary(context=before_context)
    primary.session = SimpleNamespace(
        directory=tmp_path,
        record={"creation_filetime": 123456789},
        creation_filetime=123456789,
    )
    queued = [before_context, after_context]
    primary.context = lambda: deepcopy(queued.pop(0))
    validation_contexts = []

    def validate(captured, context, *_args):
        validation_contexts.append(deepcopy(context))
        return "game_date" not in context and captured is report

    monkeypatch.setattr(relation_memory, "validate_capture", validate)
    source = NativeRelationSource(primary, relation_capture=lambda *_args: report)
    query = relation_tests._query("LAN", ["alliance"])
    with sampled_read(query, supplied):
        result = source.read(query, supplied)

    _assert_known(result, "status")
    assert validation_contexts[0]["session_id"] == supplied["session_id"]
    assert validation_contexts[0]["world_id"] == supplied["world_id"]
    assert "game_date" not in validation_contexts[0]
    assert report["context_after"]["game_date"]["value"] == GAME_DATE + 2

    rollback = _relation_memory_report(GAME_DATE + 2, GAME_DATE + 1)
    primary = relation_tests.RecordedPrimary(context=before_context)
    primary.session = SimpleNamespace(
        directory=tmp_path,
        record={"creation_filetime": 123456789},
        creation_filetime=123456789,
    )
    queued = [before_context, after_context]
    primary.context = lambda: deepcopy(queued.pop(0))
    validation_contexts.clear()
    monkeypatch.setattr(relation_memory, "validate_capture", validate)
    source = NativeRelationSource(primary, relation_capture=lambda *_args: rollback)
    with sampled_read(query, supplied):
        result = source.read(query, supplied)
    assert result["fields"]["status"]["value"][0]["reason"] == "RELATION_MEMORY_CAPTURE_INVALID"
    assert validation_contexts == []


def test_default_context_date_binding_remains_strict(tmp_path):
    supplied = relation_tests._context()
    later = _with_date(supplied, GAME_DATE + 1)
    primary = relation_tests.RecordedPrimary(context=later)
    relation_source = NativeRelationSource(primary)
    relation_query = relation_tests._query("ORL", ["vassalization"])
    relation_result = relation_source.read(relation_query, supplied)
    assert relation_result["fields"]["status"]["status"] == "unavailable"
    assert relation_result["fields"]["status"]["reason"] == "BASE_CONTEXT_CHANGED_BEFORE_QUERY"
    assert primary.diplomacy_tools.calls == []

    opinion_source, _opinion_primary, opinion_harness = opinion_tests._source(
        tmp_path, context=_with_date(opinion_tests.CONTEXT, GAME_DATE + 1),
    )
    opinion_result = opinion_source.read(opinion_tests._query(), opinion_tests.CONTEXT)
    assert opinion_result["fields"]["opinion"]["status"] == "unavailable"
    assert opinion_harness.capture_calls == []

    modifier_source, _modifier_primary, modifier_harness = modifier_tests._source(
        tmp_path, context=_with_date(modifier_tests.CONTEXT, GAME_DATE + 1),
    )
    modifier_result = modifier_source.read(modifier_tests._query(), modifier_tests.CONTEXT)
    assert modifier_result["fields"]["opinion_modifiers"]["status"] == "unavailable"
    assert modifier_harness.capture_calls == []


def test_active_context_rollback_and_identity_changes_still_retract(tmp_path):
    supplied = relation_tests._context()
    before = _with_date(supplied, GAME_DATE + 1)
    rolled_back = _with_date(supplied, GAME_DATE)
    primary = relation_tests.RecordedPrimary(context=before)
    primary.diplomacy_tools.on_call = lambda *_args: setattr(primary, "_context", deepcopy(rolled_back))
    relation_source = NativeRelationSource(primary)
    relation_query = relation_tests._query("ORL", ["vassalization"])
    with sampled_read(relation_query, supplied):
        result = relation_source.read(relation_query, supplied)
    assert result["fields"]["status"]["status"] == "unknown"
    assert result["fields"]["status"]["reason"] == "CONTEXT_CHANGED_DURING_QUERY"

    for source_type, tests, field in (
        (NativeOpinionSource, opinion_tests, "opinion"),
        (NativeOpinionModifiersSource, modifier_tests, "opinion_modifiers"),
    ):
        base_date = tests.CONTEXT["game_date"]
        before = _with_date(tests.CONTEXT, base_date + 1)
        changed_identity = _with_date(tests.CONTEXT, base_date + 2)
        changed_identity["session_id"] = "different-session"
        primary = tests.Primary(tmp_path, context=before)
        harness = tests.CaptureHarness(
            after_capture=lambda p=primary, c=changed_identity: p._context.update(c),
        )
        source = source_type(primary, capture=harness.capture, validator=harness.validate)
        query = tests._query()
        with sampled_read(query, tests.CONTEXT):
            result = source.read(query, tests.CONTEXT)
        assert result["fields"][field] == {
            "status": "unknown", "reason": "CONTEXT_CHANGED_DURING_CAPTURE",
        }
        assert harness.validator_calls == []
