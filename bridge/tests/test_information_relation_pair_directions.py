"""R01 selected-pair coverage for the directed relation-memory adapter."""
from __future__ import annotations

from contextlib import closing
from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information.composite import CompositeSource
from bridge.information.declaration_roles import DeclarationParticipantRoles
from bridge.information.directed_relation_memory import validate_capture
from bridge.information.presentation import present_concise
from bridge.information.relation_state import NativeRelationSource
from bridge.information.service import InformationService
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools
from bridge.information import trade_income
from bridge.information.observation_time import sampled_read
from bridge.tests import test_information_directed_relation_memory as directed_fixtures
from bridge.tests import test_information_relation_state as relation_fixtures
from bridge.tests.test_information_sources import _LiveSession, _LiveTools
from bridge.tests.test_information_subject_pressure import _declaration_subject_report


_PAIR = ("guarantee", "military_access")
_INSTALLATION = Path("fixture-installation.json")
_CREATION_FILETIME = 123
_GAME_DATE = 56557728


class DirectedCapture:
    def __init__(self, reader, *, returned_recipient=None):
        self.reader = reader
        self.returned_recipient = returned_recipient
        self.calls = []

    def __call__(self, installation, actor, recipient, *, families):
        self.calls.append((installation, actor, recipient, list(families)))
        actual_recipient = self.returned_recipient or recipient
        return directed_fixtures._make_report(
            self.reader, recipient=actual_recipient, families=list(families))


def _activate_military_access(reader):
    """Make FRA's forward cache row active in the bounded test fixture."""
    vector = directed_fixtures.VECTORS[("FRA", "SAV", "military_access")]
    for start, raw in reader.segments.items():
        if start <= vector and vector + 4 <= start + len(raw):
            changed = bytearray(raw)
            changed[vector - start:vector - start + 4] = (1).to_bytes(4, "little")
            reader.segments[start] = bytes(changed)
            return
    raise AssertionError("fixture does not map the FRA→SAV military access vector")


def _deactivate_pair_families(reader):
    for family in _PAIR:
        vector = directed_fixtures.VECTORS[("FRA", "SAV", family)]
        for start, raw in reader.segments.items():
            if start <= vector and vector + 4 <= start + len(raw):
                changed = bytearray(raw)
                changed[vector - start:vector - start + 4] = (99).to_bytes(4, "little")
                reader.segments[start] = bytes(changed)
                break
        else:
            raise AssertionError(f"fixture does not map the FRA→SAV {family} vector")


def _service(monkeypatch, capture, *, context=None):
    monkeypatch.setattr(
        trade_income, "_session_binding",
        lambda _source: (_INSTALLATION, _CREATION_FILETIME, None))
    inspector = relation_fixtures.RecordedInspector()
    context = context or relation_fixtures._context(
        session_id="fixture-session", game_date=_GAME_DATE,
        game_date_raw=_GAME_DATE)
    primary = relation_fixtures.RecordedPrimary(context=context, inspector=inspector)
    adapter = NativeRelationSource(primary, directed_relation_capture=capture)
    primary.catalog_entries = adapter.catalog()
    source = CompositeSource(primary, [adapter])
    return InformationService(source, ":memory:"), inspector


def _pair_query(families=_PAIR):
    return relation_fixtures._query(
        "SAV", list(families), ["relation_type", "status", "grantor", "recipient"])


def _declaration_roles(monkeypatch, reader, candidates):
    monkeypatch.setattr(trade_income, "_session_binding",
                        lambda _source: (_INSTALLATION, _CREATION_FILETIME, None))
    backend = _LiveTools(_LiveSession())
    backend.session.directory = _INSTALLATION.parent
    backend.session.creation_filetime = _CREATION_FILETIME
    backend.session.record = dict(backend.session.record, creation_filetime=_CREATION_FILETIME)
    backend.session.health = lambda: {
        "status": "ready", "date_raw": _GAME_DATE, "complete": True, "reasons": []}
    calls = []

    def inspect(action, actor, recipient, phase, parameters):
        backend.inspect_calls.append((action, actor, recipient, phase, deepcopy(parameters)))
        return {"action_id": action, "actor": actor, "recipient": recipient, "phase": phase,
                "participants": {"called": True, "enumeration_complete": True,
                                 "candidates": deepcopy(candidates)}}

    def capture(installation, actor, recipient, *, families):
        calls.append((actor, recipient, list(families)))
        return directed_fixtures._make_report(
            reader, actor=actor, recipient=recipient, families=list(families))

    backend.inspect_diplomatic_action = inspect
    source = DiplomacySource(backend)
    # The bounded trace uses this session identity in both passes.
    backend.session.session_id = "fixture-session"
    relations = NativeRelationSource(source, directed_relation_capture=capture)
    source.declaration_roles = DeclarationParticipantRoles(source, relations)
    return source, backend, calls


def test_d03_guarantor_normal_tools_uses_foreign_pair_and_keeps_defender_role(monkeypatch):
    reader = directed_fixtures.build_fixture()
    segments = {start: bytearray(raw) for start, raw in reader.segments.items()}
    directed_fixtures._write(segments, directed_fixtures.VECTORS[("SAV", "ENG", "guarantee")],
                             (2).to_bytes(4, "little"))
    reader.segments = {start: bytes(raw) for start, raw in segments.items()}
    candidate = {"country": "SAV", "related_country": "ENG", "side": "defender",
                 "automatic": True, "selected": False}
    source, backend, calls = _declaration_roles(monkeypatch, reader, [candidate])
    with closing(InformationService(source, ":memory:")) as service:
        tools = InformationTools(service)
        query = {"topic": "D03", "object": {"type": "country_pair", "actor": "FRA", "recipient": "ENG"},
                 "fields": ["guarantors"], "parameters": {}}
        result = tools.call("information_query", {"request_id": "d03-guarantor", "queries": [query]})
        assert result["items"] == [{"actor": "FRA", "recipient": "ENG", "guarantors": [candidate]}]
        full = tools.call("information_get_result", {"result_id": result["result_id"], "view": "full"})
        field = full["items"][0]["fields"]["guarantors"]
        assert field["complete"] is True
        assert field["scope"] == "participant_candidates_current_relations"
        assert field["native_function_invoked"] is False
    assert calls == [("SAV", "ENG", ["guarantee"])]
    assert len(backend.inspect_calls) == 1


def test_d03_normal_tools_combines_guarantee_and_subject_readers_once_per_requested_role(monkeypatch):
    candidate = {"country": "ENG", "related_country": "FRA", "side": "attacker",
                 "automatic": True, "selected": False}
    source, backend, guarantees = _declaration_roles(monkeypatch, directed_fixtures.build_fixture(), [candidate])
    report, _, _ = _declaration_subject_report('FRA', game_date=_GAME_DATE,
                                               session_id='fixture-session', creation=_CREATION_FILETIME)
    subjects = []

    def capture(installation, request):
        subjects.append(deepcopy(request))
        return deepcopy(report)

    source.declaration_roles.subject_capture = capture
    with closing(InformationService(source, ':memory:')) as service:
        tools = InformationTools(service)
        result = tools.call('information_query', {'request_id': 'd03-combined-roles', 'queries': [{
            'topic': 'D03', 'object': {'type': 'country_pair', 'actor': 'FRA', 'recipient': 'SAV'},
            'fields': ['guarantors', 'subjects'], 'parameters': {}}]})
        assert result['items'] == [{'actor': 'FRA', 'recipient': 'SAV', 'guarantors': [],
                                    'subjects': [dict(candidate, overlord='FRA')]}]
        full = tools.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})
        assert full['complete'] is True
    assert guarantees == [('ENG', 'FRA', ['guarantee'])]
    assert len(subjects) == len(backend.inspect_calls) == 1


def test_d03_guarantor_direction_does_not_promote_reverse_relation(monkeypatch):
    reader = directed_fixtures.build_fixture(guarantee_reverse=False)
    candidate = {"country": "SAV", "related_country": "FRA", "side": "attacker",
                 "automatic": False, "selected": True}
    source, _, calls = _declaration_roles(monkeypatch, reader, [candidate])
    fields = source.declaration_roles.fields(
        {"participants": {"called": True, "enumeration_complete": True, "candidates": [candidate]}},
        source.context(), ["guarantors"])
    assert fields["guarantors"]["value"] == []
    assert fields["guarantors"]["complete"] is True
    assert calls == [("SAV", "FRA", ["guarantee"])]


def test_d03_guarantor_partial_capture_keeps_known_candidate(monkeypatch):
    reader = directed_fixtures.build_fixture()
    layout = directed_fixtures.subject._profile_layout(directed_fixtures.subject._load_profile())
    count = layout["families"]["guarantee"]["vector_count_offset"]
    reader.failures.add(directed_fixtures.OWNERS[("ENG", "SAV")] + count)
    candidates = [
        {"country": "SAV", "related_country": "FRA", "side": "attacker", "automatic": False, "selected": True},
        {"country": "ENG", "related_country": "SAV", "side": "defender", "automatic": False, "selected": False}]
    source, _, calls = _declaration_roles(monkeypatch, reader, candidates)
    fields = source.declaration_roles.fields(
        {"participants": {"called": True, "enumeration_complete": True, "candidates": candidates}},
        source.context(), ["guarantors"])
    field = fields["guarantors"]
    assert field["status"] == "known"
    assert field["value"] == [candidates[0]]
    assert field["complete"] is False and field["partial"] is True
    assert field["unresolved"][0]["country"] == "ENG"
    assert len(calls) == 2


@pytest.mark.parametrize("change", ["clock", "session"])
def test_d03_role_sampling_preserves_clock_progress_and_rejects_session_change(monkeypatch, change):
    candidate = {"country": "SAV", "related_country": "FRA", "side": "attacker",
                 "automatic": False, "selected": True}
    source, backend, _ = _declaration_roles(monkeypatch, directed_fixtures.build_fixture(), [candidate])
    capture = source.declaration_roles.relation_source.directed_relation_capture

    def changed(*args, **kwargs):
        report = capture(*args, **kwargs)
        if change == "clock":
            backend.session.health = lambda: {
                "status": "ready", "date_raw": _GAME_DATE + 24, "complete": True, "reasons": []}
        else:
            backend.session.session_id = "different-session"
        return report

    source.declaration_roles.relation_source.directed_relation_capture = changed
    context = source.context()
    with sampled_read({"topic": "D03"}, context) as window:
        fields = source.declaration_roles.fields(
            {"participants": {"called": True, "enumeration_complete": True, "candidates": [candidate]}},
            context, ["guarantors"])
    if change == "clock":
        assert fields["guarantors"]["value"] == [candidate]
        assert fields["guarantors"]["complete"] is True
        assert window.metadata()["end_game_date"] == _GAME_DATE + 24
    else:
        assert fields["guarantors"]["reason"] == "PARTICIPANT_RELATION_CONTEXT_CHANGED"


def test_d03_empty_candidate_set_and_incomplete_enumeration_keep_distinct_completeness(monkeypatch):
    source, _, calls = _declaration_roles(monkeypatch, directed_fixtures.build_fixture(), [])
    context = source.context()
    for complete in (True, False):
        fields = source.declaration_roles.fields(
            {"participants": {"called": True, "enumeration_complete": complete, "candidates": []}},
            context, ["guarantors", "subjects"])
        assert all(item["value"] == [] and item["complete"] is complete for item in fields.values())
    assert calls == []


@pytest.mark.parametrize("requested,participants", [
    (["subjects"], {}), (["allies"], {}),
    (["guarantors"], {"guarantors": ["SAV"]}),
])
def test_d03_guarantee_capture_is_limited_to_requested_missing_fields(monkeypatch, requested, participants):
    source, _, calls = _declaration_roles(monkeypatch, directed_fixtures.build_fixture(), [])
    result = source.declaration_roles.fields({"participants": participants}, source.context(), requested)
    assert calls == []
    if requested == ["subjects"]:
        assert result["subjects"]["status"] == "unknown"
    else:
        assert result == {}


def test_pair_batches_both_directed_families_and_projects_opposite_roles(monkeypatch):
    reader = directed_fixtures.build_fixture()
    _activate_military_access(reader)
    capture = DirectedCapture(reader)
    service, inspector = _service(monkeypatch, capture)
    try:
        result = service.query("r01-directed-batch", queries=[_pair_query()])
        item = relation_fixtures._item(result)

        assert capture.calls == [(_INSTALLATION, "FRA", "SAV", list(_PAIR))]
        assert inspector.calls == []
        for family in _PAIR:
            assert relation_fixtures._family_value(item, "status", family)["value"] == "active"
        assert relation_fixtures._family_value(item, "grantor", "guarantee")["value"] == "FRA"
        assert relation_fixtures._family_value(item, "recipient", "guarantee")["value"] == "SAV"
        assert relation_fixtures._family_value(item, "grantor", "military_access")["value"] == "SAV"
        assert relation_fixtures._family_value(item, "recipient", "military_access")["value"] == "FRA"

        concise = present_concise(result)["items"][0]
        assert concise["recipient"] == "SAV"
        assert "relation_recipient" in concise
        assert concise["relation_recipient"] == ["SAV", "FRA"]
    finally:
        service.close()


def test_inactive_directed_pair_has_no_grantor_or_recipient_role(monkeypatch):
    reader = directed_fixtures.build_fixture()
    _deactivate_pair_families(reader)
    capture = DirectedCapture(reader)
    service, inspector = _service(monkeypatch, capture)
    try:
        item = relation_fixtures._item(
            service.query("r01-directed-inactive", queries=[_pair_query()]))
        assert capture.calls == [(_INSTALLATION, "FRA", "SAV", list(_PAIR))]
        assert inspector.calls == []
        for family in _PAIR:
            assert relation_fixtures._family_value(item, "status", family)["value"] == "inactive"
            assert relation_fixtures._family_value(item, "grantor", family)["status"] == "not_applicable"
            assert relation_fixtures._family_value(item, "recipient", family)["status"] == "not_applicable"
    finally:
        service.close()


def test_unknown_memory_family_falls_back_without_erasing_known_sibling(monkeypatch):
    reader = directed_fixtures.build_fixture()
    _activate_military_access(reader)
    reader.failures.add(directed_fixtures.RECORDS[("FRA", "SAV")] + 0x18)
    capture = DirectedCapture(reader)
    service, inspector = _service(monkeypatch, capture)
    try:
        item = relation_fixtures._item(
            service.query("r01-directed-partial", queries=[_pair_query()]))

        assert capture.calls == [(_INSTALLATION, "FRA", "SAV", list(_PAIR))]
        assert [call[0] for call in inspector.calls] == ["proclaim_guarantee"]
        guarantee = relation_fixtures._family_value(item, "status", "guarantee")
        access = relation_fixtures._family_value(item, "status", "military_access")
        assert guarantee["status"] == "known" and guarantee["value"] == "inactive"
        assert access["status"] == "known" and access["value"] == "active"
        assert relation_fixtures._family_value(item, "grantor", "military_access")["value"] == "SAV"
        assert relation_fixtures._family_value(item, "recipient", "military_access")["value"] == "FRA"
    finally:
        service.close()


def test_validator_rejects_capture_for_a_different_recipient_and_uses_inspection(monkeypatch):
    reader = directed_fixtures.build_fixture()
    capture = DirectedCapture(reader, returned_recipient="ENG")
    context = relation_fixtures._context(
        session_id="fixture-session", game_date=_GAME_DATE,
        game_date_raw=_GAME_DATE)
    wrong_target = directed_fixtures._make_report(
        reader, recipient="ENG", families=["guarantee"])
    assert validate_capture(
        wrong_target, context, _CREATION_FILETIME, actor="FRA", recipient="SAV") is False

    service, inspector = _service(monkeypatch, capture, context=context)
    try:
        item = relation_fixtures._item(service.query(
            "r01-directed-wrong-target",
            queries=[relation_fixtures._query("SAV", ["guarantee"],
                                              ["relation_type", "status"])]))
        assert capture.calls == [(_INSTALLATION, "FRA", "SAV", ["guarantee"])]
        assert [call[0] for call in inspector.calls] == ["proclaim_guarantee"]
        assert relation_fixtures._family_value(item, "status", "guarantee")["value"] == "inactive"
    finally:
        service.close()
