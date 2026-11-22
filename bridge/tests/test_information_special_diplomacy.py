from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from bridge.information import relation_state, subject_relations, trade_league_memory
from bridge.information.model import InformationError
from bridge.information.special_diplomacy import FIELD, NativeSpecialDiplomacySource
from bridge.tests.test_information_relation_state import _context
from bridge.tests.test_information_trade_league_memory import _build_archived_capture


def _query(field=FIELD, *, object_type="country", country="FRA", parameters=None):
    obj = {"type": object_type}
    if object_type == "country":
        obj["country"] = country
    elif object_type == "session":
        obj["session_id"] = "relation-session"
    return {"topic": "S05", "object": obj, "fields": [field],
            "parameters": {} if parameters is None else parameters}


class FakeRelationSource:
    def __init__(self, context, report=None, reason=None, contexts=None):
        self._context = deepcopy(context)
        self._contexts = [deepcopy(value) for value in (contexts or [])]
        self.report = report
        self.reason = reason
        self.extension_calls = []
        self.context_calls = 0

    def context(self):
        return deepcopy(self._context)

    def _base_context(self):
        self.context_calls += 1
        if self._contexts:
            self._context = self._contexts.pop(0)
        return deepcopy(self._context), None

    def _extension_report(self, family, actor, recipient, context):
        self.extension_calls.append((family, actor, recipient, deepcopy(context)))
        return deepcopy(self.report), self.reason


def _actor_report(*, predicate, members, leader):
    return {
        "before": {"actor_record": {
            "status": "observed", "country": "FRA", "predicate": predicate,
            "members": [
                {"country": tag, "fullref_hex": "private", "slot": index,
                 "active": True, "league_leader": leader, "index": index}
                for index, tag in enumerate(members)
            ],
            "league_leader": leader,
            "league_object_pointer": "0x12345678",
        }}
    }


def _native_source(report, context, creation_filetime):
    capture_calls = []

    def capture(_installation, actor, recipient):
        capture_calls.append((actor, recipient))
        return deepcopy(report)

    base = SimpleNamespace(
        context=lambda: deepcopy(context),
        session=SimpleNamespace(
            directory="offline-trade-league-fixture",
            record={"creation_filetime": creation_filetime},
            creation_filetime=creation_filetime,
        ),
    )
    relation = relation_state.NativeRelationSource(
        base, trade_league_capture=capture
    )
    return relation, NativeSpecialDiplomacySource(relation), capture_calls


def test_catalog_validation_scope_and_pure_empty_parameters():
    relation = FakeRelationSource(_context())
    source = NativeSpecialDiplomacySource(relation)

    topic = source.catalog()[0]
    assert topic["topic_id"] == "S05" and topic["status"] == "available"
    assert list(topic["fields"]) == [FIELD]
    assert topic["fields"][FIELD]["coverage"] == "partial"
    assert topic["fields"][FIELD]["complete"] is False
    assert topic["observer_scope"] == []
    assert topic["triggers"] == ["query", "periodic", "change"]
    assert topic["change_detection"] == "sampled_state_comparison_not_lossless_events"
    assert source.validate_query(_query())["parameters"] == {}
    assert relation.extension_calls == [] and relation.context_calls == 0

    with pytest.raises(InformationError) as nonempty:
        source.validate_query(_query(parameters={"force": True}))
    assert nonempty.value.code == "invalid_parameters"
    with pytest.raises(InformationError) as foreign:
        source.validate_query(_query(country="ENG"), _context())
    assert foreign.value.code == "observer_scope_mismatch"


@pytest.mark.parametrize("observer", ["FRA", "HSA"])
def test_validated_native_capture_projects_trade_league_for_selected_country(observer):
    report, fixture, _before_reader, _after_reader = _build_archived_capture(observer)
    identity = fixture["identity"]
    creation = identity["creation_filetime"]
    context = _context(
        observer=observer, session_id=identity["session_id"],
        process_creation_filetime=creation,
        game_date=identity["game_date"], game_date_raw=identity["game_date"],
    )
    context["game_sha256"] = subject_relations._GAME_SHA256
    assert trade_league_memory.validate_capture(report, context, creation, observer, None)
    relation, source, capture_calls = _native_source(report, context, creation)
    assert source.relation_source is relation

    result = source.read(_query(country=observer), context)

    value = result["fields"][FIELD]["value"]
    assert result["fields"][FIELD]["status"] == "known"
    record = report["before"]["actor_record"]
    assert value == {"country": observer, "active": record["predicate"],
                     "leader": record["league_leader"],
                     "members": [member["country"] for member in record["members"]]}
    assert capture_calls == [(observer, None)]
    wrong_country = "HSA" if observer == "FRA" else "FRA"
    with pytest.raises(InformationError) as cross_observer:
        source.read(_query(country=wrong_country))
    assert cross_observer.value.code == "observer_scope_mismatch"
    assert capture_calls == [(observer, None)]
    assert "league_object_pointer" not in str(result)
    assert "fullref_hex" not in str(result)


def test_active_comes_from_predicate_and_members_keep_actor_and_native_order():
    context = _context()
    report = _actor_report(predicate=True, members=["FRA", "HSA", "RIG"], leader="HSA")
    relation = FakeRelationSource(context, report)
    source = NativeSpecialDiplomacySource(relation)

    result = source.read(_query(), context)

    assert result["fields"][FIELD]["value"] == {
        "country": "FRA", "active": True, "leader": "HSA",
        "members": ["FRA", "HSA", "RIG"],
    }
    assert result["complete"] is False


def test_unknown_upstream_reason_is_preserved_instead_of_projected_inactive():
    relation = FakeRelationSource(_context(), report=None,
                                  reason="TRADE_LEAGUE_VECTOR_IDENTITY_MISMATCH")
    source = NativeSpecialDiplomacySource(relation)

    result = source.read(_query(), relation.context())

    assert result["fields"][FIELD] == {
        "status": "unknown", "reason": "TRADE_LEAGUE_VECTOR_IDENTITY_MISMATCH",
    }


def test_session_and_unimplemented_fields_do_not_call_trade_league_reader():
    relation = FakeRelationSource(_context(), _actor_report(
        predicate=True, members=["FRA"], leader="FRA"
    ))
    source = NativeSpecialDiplomacySource(relation)

    session_result = source.read(_query(object_type="session"), relation.context())
    planned_result = source.read(_query("tributary"), relation.context())

    assert session_result["fields"][FIELD] == {
        "status": "unsupported", "reason": "S05_SESSION_OBJECT_NOT_IMPLEMENTED",
    }
    assert planned_result["fields"]["tributary"] == {
        "status": "unsupported", "reason": "S05_FIELD_NOT_IMPLEMENTED",
    }
    assert relation.extension_calls == []


def test_context_mismatch_before_or_during_read_retracts_result():
    before = _context()
    supplied = deepcopy(before)
    supplied["game_date"] += 1
    relation = FakeRelationSource(before, _actor_report(
        predicate=True, members=["FRA"], leader="FRA"
    ))
    source = NativeSpecialDiplomacySource(relation)
    early = source.read(_query(), supplied)
    assert early["fields"][FIELD] == {
        "status": "unavailable", "reason": "BASE_CONTEXT_CHANGED_BEFORE_QUERY",
    }
    assert relation.extension_calls == []

    after = deepcopy(before)
    after["game_date"] += 1
    after["game_date_raw"] += 1
    relation = FakeRelationSource(before, _actor_report(
        predicate=True, members=["FRA"], leader="FRA"
    ), contexts=[before, after])
    source = NativeSpecialDiplomacySource(relation)
    late = source.read(_query(), before)
    assert late["fields"][FIELD] == {
        "status": "unavailable", "reason": "CONTEXT_CHANGED_DURING_QUERY",
    }
    assert len(relation.extension_calls) == 1
