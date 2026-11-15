"""Contract tests for the selected-pair R02 subject relation adapter."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge.diplomacy import ObserverSession
from bridge.information.model import InformationError
from bridge.information.service import InformationService
from bridge.information.subject_relations import NativeSubjectRelationSource


FIXTURE = Path(__file__).parent / "fixtures" / "vassalization_r35_native_inspections.json"
RELATIONS_FIXTURE = (Path(__file__).parent / "fixtures"
                     / "information_country_relations_live_1374.json")
GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
DLL_SHA = "d" * 64


def _public_event(name: str) -> dict:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    event = deepcopy(payload["events"][name])
    event["date_raw"] = 56553384
    return ObserverSession._semantic_inspection(event, {}, "eu4_escape", False)


def _recorded_public(country: str) -> dict:
    payload = json.loads(RELATIONS_FIXTURE.read_text(encoding="utf-8"))
    return deepcopy(payload["captures"][country]["public"])


def _context(*, date: int = 56553384, **overrides) -> dict:
    value = {
        "status": "ready",
        "mode": "live",
        "complete": True,
        "observer": "FRA",
        "game_version": "1.37.4",
        "game_sha256": GAME_SHA,
        "dll_sha256": DLL_SHA,
        "session_id": "subject-session",
        "game_date": date,
        "game_date_raw": date,
        "world_id": "world-1",
        "paused": True,
    }
    value.update(overrides)
    return value


def _query(recipient: str = "SAV", fields: list[str] | None = None) -> dict:
    return {
        "topic": "R02",
        "object": {"type": "country_pair", "actor": "FRA", "recipient": recipient},
        "fields": fields or ["overlord", "subject", "subject_type"],
        "parameters": {},
    }


class _Tools:
    def __init__(self, public: dict | None = None, error: Exception | None = None):
        self.public = deepcopy(public)
        self.error = error
        self.calls: list[tuple] = []
        self.submit_calls: list[tuple] = []

    def inspect_diplomatic_action(self, *args):
        self.calls.append(args)
        if self.error is not None:
            raise self.error
        return deepcopy(self.public)


class _Base:
    def __init__(self, public: dict | None = None, contexts: list[dict] | None = None,
                 error: Exception | None = None):
        self.diplomacy_tools = _Tools(public, error)
        self.contexts = [deepcopy(item) for item in (contexts or [_context()])]
        self.context_calls = 0

    def context(self) -> dict:
        self.context_calls += 1
        if len(self.contexts) > 1:
            return deepcopy(self.contexts.pop(0))
        return deepcopy(self.contexts[0])


def _source(public: dict, *, contexts: list[dict] | None = None,
            error: Exception | None = None) -> tuple[NativeSubjectRelationSource, _Base]:
    base = _Base(public, contexts, error)
    return NativeSubjectRelationSource(base), base


def test_catalog_and_active_overlord_projection_are_pair_scoped() -> None:
    public = _public_event("cancel_vassalization")
    # The offline fixture is a verified active relation.  The source always
    # calls offer_vassalization, so retain the public family but set its action
    # to the query-only action expected by this adapter.
    public["action_id"] = "offer_vassalization"
    source, base = _source(public)

    catalog = source.catalog()
    assert len(catalog) == 1
    assert catalog[0]["topic_id"] == "R02"
    assert catalog[0]["status"] == "available"
    assert catalog[0]["supported_versions"] == ["1.37.4"]
    assert catalog[0]["observer_scope"] == ["FRA"]
    assert catalog[0]["triggers"] == ["query", "periodic", "change"]
    assert catalog[0]["change_detection"] == "sampled_state_comparison_not_lossless_events"

    result = source.read(_query())
    assert result["complete"] is True
    assert result["fields"] == {
        "overlord": {"status": "known", "value": "FRA"},
        "subject": {"status": "known", "value": "SAV"},
        "subject_type": {"status": "known", "value": "vassal"},
    }
    assert result["objects"] == [_query()["object"]]
    assert result["source"]["provenance"]["scope"] == "selected_country_pair"
    assert result["source"]["provenance"]["global_relation_claim"] is False
    assert base.diplomacy_tools.calls == [
        ("offer_vassalization", "FRA", "SAV", "initiate", {})
    ]
    assert base.diplomacy_tools.submit_calls == []


def test_active_reverse_role_derives_recipient_as_overlord() -> None:
    public = _public_event("cancel_vassalization")
    public.update({
        "action_id": "offer_vassalization",
        "actor": "FRA",
        "recipient": "SAV",
        "actor_is_overlord": False,
        "actor_is_subject": True,
    })
    source, _ = _source(public)
    result = source.read(_query())
    assert result["fields"] == {
        "overlord": {"status": "known", "value": "SAV"},
        "subject": {"status": "known", "value": "FRA"},
        "subject_type": {"status": "known", "value": "vassal"},
    }


def test_inactive_selected_pair_is_not_applicable_not_global_absence() -> None:
    public = _recorded_public("PAP")
    source, _ = _source(public)
    result = source.read(_query("PAP"))
    assert result["complete"] is True
    assert all(item["status"] == "not_applicable" for item in result["fields"].values())
    assert all(item["reason"] == "SELECTED_PAIR_HAS_NO_VASSAL_RELATION"
               for item in result["fields"].values())
    assert result["source"]["provenance"]["global_relation_claim"] is False
    assert result["source"]["provenance"]["public_projection"]["subject_type"] is None


def test_inactive_nonempty_subject_type_is_unknown_and_preserves_raw_projection() -> None:
    public = _public_event("offer_vassalization")
    public["action_id"] = "offer_vassalization"
    assert public["vassal_active"] is False
    assert public["subject_type"] == "vassal"
    source, _ = _source(public)
    result = source.read(_query())
    assert result["complete"] is False
    assert all(item == {
        "status": "unknown",
        "reason": "INACTIVE_SUBJECT_TYPE_NOT_EMPTY",
    } for item in result["fields"].values())
    assert result["source"]["provenance"]["public_projection"]["subject_type"] == "vassal"


def test_real_orl_public_fixture_without_submitted_marker_projects_appanage() -> None:
    public = _recorded_public("ORL")
    assert "submitted" not in public
    source, base = _source(public)
    result = source.read(_query("ORL"))
    assert result["complete"] is True
    assert result["fields"]["overlord"] == {"status": "known", "value": "FRA"}
    assert result["fields"]["subject"] == {"status": "known", "value": "ORL"}
    assert result["fields"]["subject_type"] == {"status": "known", "value": "appanage"}
    assert base.diplomacy_tools.calls == [
        ("offer_vassalization", "FRA", "ORL", "initiate", {})
    ]


def test_real_orl_fixture_runs_through_information_service(tmp_path) -> None:
    public = _recorded_public("ORL")
    source, _ = _source(public)
    service = InformationService(source, tmp_path / "subject.sqlite")
    try:
        topic = next(item for item in service.discover()["topics"] if item["topic_id"] == "R02")
        assert topic["status"] == "available"
        result = service.query("subject-orl-query", queries=[_query("ORL")])
        item = result["items"][0]
        assert item["complete"] is True
        assert (item["fields"]["overlord"]["status"],
                item["fields"]["overlord"]["value"]) == ("known", "FRA")
        assert (item["fields"]["subject"]["status"],
                item["fields"]["subject"]["value"]) == ("known", "ORL")
        assert (item["fields"]["subject_type"]["status"],
                item["fields"]["subject_type"]["value"]) == ("known", "appanage")
    finally:
        service.close()


@pytest.mark.parametrize("key,value", [
    ("status", "unready"),
    ("mode", "recorded"),
    ("complete", False),
    ("observer", "POR"),
    ("game_version", "1.37.5"),
    ("game_sha256", "0" * 64),
    ("dll_sha256", "dll"),
    ("session_id", ""),
    ("game_date", None),
    ("game_date_raw", None),
])
def test_incomplete_or_wrong_base_identity_never_publishes_values(key, value) -> None:
    public = _public_event("cancel_vassalization")
    public["action_id"] = "offer_vassalization"
    context = _context(**{key: value})
    source, base = _source(public, contexts=[context])
    result = source.read(_query())
    assert result["complete"] is False
    assert all(item["status"] == "unavailable" for item in result["fields"].values())
    assert base.diplomacy_tools.calls == []


@pytest.mark.parametrize("mutation,reason", [
    (lambda p: p.update({"action_id": "cancel_vassalization"}),
     "PUBLIC_PROJECTION_IDENTITY_MISMATCH"),
    (lambda p: p.update({"family": "guarantee"}),
     "PUBLIC_PROJECTION_IDENTITY_MISMATCH"),
    (lambda p: p.update({"phase": "accept"}),
     "PUBLIC_PROJECTION_IDENTITY_MISMATCH"),
    (lambda p: p.update({"recipient": "BUR"}),
     "PUBLIC_PROJECTION_IDENTITY_MISMATCH"),
    (lambda p: p.update({"submitted": True}),
     "PUBLIC_PROJECTION_SUBMISSION_MARKER_INVALID"),
    (lambda p: p.update({"vassal_state_verified": False}),
     "VASSAL_STATE_NOT_VERIFIED"),
    (lambda p: p["relationship_state"].update({"complete": False}),
     "RELATIONSHIP_STATE_INCOMPLETE"),
    (lambda p: p["relationship_state"].update({"vassal_active": False}),
     "VASSAL_ACTIVE_LAYERS_MISMATCH"),
    (lambda p: p.update({"actor_is_overlord": True, "actor_is_subject": True}),
     "RELATION_ROLE_AMBIGUOUS"),
    (lambda p: p.update({"subject_type": "中文"}),
     "SUBJECT_TYPE_INVALID_ASCII"),
])
def test_public_guard_failures_return_unknown_without_publishing_values(mutation, reason) -> None:
    public = _public_event("cancel_vassalization")
    public["action_id"] = "offer_vassalization"
    mutation(public)
    source, base = _source(public)
    result = source.read(_query())
    assert result["complete"] is False
    assert all(item == {"status": "unknown", "reason": reason}
               for item in result["fields"].values())
    assert len(base.diplomacy_tools.calls) == 1


def test_public_date_is_not_required_when_base_identity_is_complete() -> None:
    public = _public_event("cancel_vassalization")
    public.update({"action_id": "offer_vassalization", "date_raw": None})
    public.pop("submitted", None)
    source, _ = _source(public)
    result = source.read(_query())
    assert result["fields"]["overlord"] == {"status": "known", "value": "FRA"}


@pytest.mark.parametrize("changed", [
    {"game_date": 56553385, "game_date_raw": 56553385},
    {"session_id": "new-session"},
])
def test_base_context_is_rechecked_after_inspection(changed) -> None:
    public = _public_event("cancel_vassalization")
    public["action_id"] = "offer_vassalization"
    before = _context()
    after = {**before, **changed}
    source, base = _source(public, contexts=[before, after])
    result = source.read(_query())
    assert result["complete"] is False
    assert all(item == {"status": "unknown", "reason": "CONTEXT_CHANGED_DURING_QUERY"}
               for item in result["fields"].values())
    assert base.context_calls == 2


def test_inspector_error_is_unavailable_and_never_submitted() -> None:
    source, base = _source(_public_event("cancel_vassalization"),
                           error=RuntimeError("query failed"))
    result = source.read(_query())
    assert result["complete"] is False
    assert all(item == {"status": "unavailable", "reason": "INSPECT_CALL_FAILED:RuntimeError"}
               for item in result["fields"].values())
    assert base.diplomacy_tools.submit_calls == []


@pytest.mark.parametrize("bad", [
    {"topic": "R02", "object": {"type": "country_pair", "actor": "POR", "recipient": "SAV"},
     "fields": ["overlord"], "parameters": {}},
    {"topic": "R02", "object": {"type": "country_pair", "actor": "FRA", "recipient": "SAV"},
     "fields": ["overlord"], "parameters": {"x": 1}},
    {"topic": "R02", "object": {"type": "country_pair", "actor": "FRA", "recipient": "SAV"},
     "fields": ["unknown"], "parameters": {}},
    {"topic": "R02", "object": {"type": "country_pair", "actor": "FRA", "recipient": "SAV"},
     "fields": ["overlord", "overlord"], "parameters": {}},
])
def test_query_contract_rejects_out_of_scope_or_malformed_requests(bad) -> None:
    source, _ = _source(_public_event("cancel_vassalization"))
    with pytest.raises(InformationError):
        source.validate_query(bad, _context())


def test_poll_events_is_explicitly_sampled_state_only() -> None:
    source, _ = _source(_public_event("cancel_vassalization"))
    assert source.poll_events(_context(), {"cursor": 1}) == {
        "events": [], "cursor": {"cursor": 1}, "complete": True, "gaps": []
    }
