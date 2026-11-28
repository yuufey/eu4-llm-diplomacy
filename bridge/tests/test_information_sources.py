"""Focused contract tests for the information catalog and read-only adapters."""

from __future__ import annotations

from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge.diplomacy import DiplomacyTools
from bridge.diplomacy_journal import DurableJournal
from bridge.information import InformationService
from bridge.information.catalog import catalog, validate_query
from bridge.information.model import InformationError, identifier
from bridge.information.sources import DiplomacySource, RecordedSource
from bridge.information.tools import InformationTools


FIXTURE = Path(__file__).parent / "fixtures" / "r73_favor_queries_real.json"


class _LiveSession:
    session_id = "live-information-1"
    observer = "FRA"
    record = {
        "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        "dll_sha256": "d" * 64,
    }

    def __init__(self, *, ready: bool = True):
        self.ready = ready
        self.inbound = [{
            "proposal_id": "proposal-1", "action_id": "offer_alliance",
            "actor": "SAV", "recipient": "FRA", "phase": "initiate",
            "observer_status": "observed_pending", "parameters": {"kind": "defensive"},
        }]

    def health(self):
        return {
            "status": "ready" if self.ready else "unready",
            "date_raw": 56554848,
            "complete": self.ready,
            "reasons": [] if self.ready else [{"code": "SESSION_UNREADY"}],
        }

    def read_native_alliance_inbound_offers(self):
        return list(self.inbound)


class _LiveTools:
    def __init__(self, session):
        self.session = session
        self.journal = None
        self.inspect_calls = []

    def inspect_diplomatic_action(self, action_id, actor, recipient, phase="initiate", parameters=None):
        DiplomacyTools._validate(action_id, actor, recipient, phase, parameters or {})
        self.inspect_calls.append((action_id, actor, recipient, phase, parameters))
        return {
            "action_id": action_id, "actor": actor, "recipient": recipient,
            "phase": phase,
            "legality": {"status": "available", "reasons": []},
            "costs": {"stability": 0},
            "acceptance": {"predicted_response": "unknown"},
            "native_favor_trade": {
                "recipient_trust_raw": 50,
                "favors_available_raw": 23466,
                "kind": "trust",
            },
        }


def _query(topic, obj, fields, parameters=None):
    return {
        "topic": topic, "object": obj, "fields": fields,
        "parameters": {} if parameters is None else parameters,
    }


def _actual_declare_war_backend():
    document = json.loads((Path(__file__).parent / 'fixtures' /
                           'information_declare_war_participants_FRA_GEN_live_1374.json').read_bytes())
    inspection = document['inspection']
    backend = _LiveTools(_LiveSession())
    backend.session.health = lambda: {'status': 'ready', 'complete': True,
                                      'date_raw': document['game_date_raw'], 'reasons': []}

    def inspect(action, actor, recipient, phase, parameters):
        backend.inspect_calls.append((action, actor, recipient, phase, parameters))
        return deepcopy(inspection)

    backend.inspect_diplomatic_action = inspect
    return inspection, backend


@pytest.mark.parametrize('selected', [
    ['ally', 'willingness', 'reasons', 'land_promise_available'],
    ['ally', 'willingness', 'reasons', 'favor_requirement', 'land_promise_available'],
    ['ally'], ['willingness'], ['reasons'], ['land_promise_available'],
])
def test_actual_d04_candidates_reach_normal_tools_and_selected_concise_fields(tmp_path, selected):
    inspection, backend = _actual_declare_war_backend()
    query = _query('D04', {'type': 'country_pair', 'actor': 'FRA', 'recipient': 'GEN'}, selected,
                   {'selection': deepcopy(inspection['parameters']['requested'])})
    with closing(InformationService(DiplomacySource(backend), tmp_path / 'd04.sqlite3')) as service:
        tools = InformationTools(service)
        concise = tools.call('information_query', {'request_id': 'actual-d04', 'queries': [query]})
        item = concise['items'][0]
        assert set(item) == {'actor', 'recipient', 'allies'} | (
            {'favor_requirement'} if 'favor_requirement' in selected else set())
        assert len(item['allies']) == inspection['participants']['candidate_count'] == 9
        sav = next(row for row in item['allies'] if row['country'] == 'SAV')
        expected_keys = {'country'} | (set(selected) - {'ally', 'favor_requirement'})
        if 'ally' in selected:
            expected_keys |= {'side', 'automatic'}
            assert sav['side'] == 'attacker' and sav['automatic'] is False
        assert set(sav) == expected_keys
        if 'willingness' in selected:
            assert sav['willingness'] == {'score': -1037, 'threshold': 1}
        if 'reasons' in selected:
            assert len(sav['reasons']) == 8
            assert sav['reasons'][1] == {'value': -1000, 'text': '正在打另一场战争：'}
            assert all(set(reason) == {'value', 'text'} for reason in sav['reasons'])
        if 'land_promise_available' in selected:
            assert sav['land_promise_available'] is True
        if 'favor_requirement' in selected:
            assert item['favor_requirement'] is None
        full = tools.call('information_get_result', {'result_id': concise['result_id'], 'view': 'full'})
        fields = full['items'][0]['fields']
        assert set(fields) == set(selected)
        assert all(fields[name]['status'] == 'known' for name in selected if name != 'favor_requirement')
        if 'favor_requirement' in selected:
            assert fields['favor_requirement']['status'] == 'unknown'
    assert len(backend.inspect_calls) == 1
    assert backend.inspect_calls[0] == ('declare_war', 'FRA', 'GEN', 'initiate',
                                      inspection['parameters']['requested'])


@pytest.mark.parametrize('selected', [
    ['automatic_participants', 'allies', 'guarantors', 'subjects', 'co_belligerents'],
    ['automatic_participants'], ['allies'], ['co_belligerents'],
])
def test_actual_d03_plan_keeps_automatic_and_selected_roles_without_guessing_relations(tmp_path, selected):
    inspection, backend = _actual_declare_war_backend()
    query = _query('D03', {'type': 'country_pair', 'actor': 'FRA', 'recipient': 'GEN'}, selected,
                   {'selection': deepcopy(inspection['parameters']['requested'])})
    with closing(InformationService(DiplomacySource(backend), tmp_path / 'd03.sqlite3')) as service:
        tools = InformationTools(service)
        result = tools.call('information_query', {'request_id': 'actual-d03', 'queries': [query]})
        item = result['items'][0]
        assert set(item) == {'actor', 'recipient'} | set(selected)
        if 'automatic_participants' in selected:
            assert {row['country'] for row in item['automatic_participants']} == {
                'AMG', 'AUV', 'BOU', 'FOI', 'ORL', 'HES'}
            assert all(row['side'] == 'attacker' and row['automatic'] for row in item['automatic_participants'])
        if 'allies' in selected:
            assert item['allies'] == [{'country': 'SAV', 'side': 'attacker', 'automatic': False, 'selected': True}]
        if 'co_belligerents' in selected:
            assert item['co_belligerents'] == []
        full = tools.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})
        fields = full['items'][0]['fields']
        for field in ('guarantors', 'subjects'):
            if field in selected:
                assert item[field] is None
                assert fields[field]['reason'] == 'PARTICIPANT_RELATION_KIND_UNVERIFIED'
        for field in ('allies', 'co_belligerents'):
            if field in selected:
                assert fields[field]['scope'] == 'selected_preview'
    assert len(backend.inspect_calls) == 1


@pytest.mark.parametrize('table_complete,unmapped,target_required', [
    (True, [], False), (False, [], False),
    (True, [{'category_raw': 999}], False), (True, [], True),
])
def test_actual_d06_exposes_only_explicit_disabled_actions_and_table_completeness(
        tmp_path, table_complete, unmapped, target_required):
    inspection, backend = _actual_declare_war_backend()
    disabled = inspection['peace_term_rules']['disabled']
    partial_table = not table_complete or bool(unmapped) or target_required
    disabled.update(complete=table_complete, unmapped=unmapped, target_evaluation_required=target_required)
    if partial_table:
        disabled['disabled_actions'] = ['annex_country']
    inspection['peace_term_rules']['attacker_declared']['declared_justified_actions'] = ['demand_province']
    query = _query('D06', {'type': 'country_pair', 'actor': 'FRA', 'recipient': 'GEN'},
                   ['allowed_terms', 'forbidden_terms', 'beneficiaries', 'cost_rules'],
                   {'selection': deepcopy(inspection['parameters']['requested'])})
    with closing(InformationService(DiplomacySource(backend), tmp_path / 'd06.sqlite3')) as service:
        tools = InformationTools(service)
        result = tools.call('information_query', {'request_id': 'actual-d06', 'queries': [query]})
        item = result['items'][0]
        assert item['forbidden_terms'] == (['annex_country'] if partial_table else [])
        assert item['allowed_terms']['attacker']['declared_justified'] == ['demand_province']
        assert item['beneficiaries']['selected_war_goal']['country'] == 'FRA'
        assert item['cost_rules'] is None
        full = tools.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})
        field = full['items'][0]['fields']['forbidden_terms']
        assert field['table'] == disabled
        assert field['complete'] is (not partial_table)
        assert field['status'] == 'known'
    assert len(backend.inspect_calls) == 1


def test_d04_keeps_recorded_flat_participant_fields_and_original_score():
    from bridge.information.catalog import get_topic
    from bridge.information.sources import _field_result
    from bridge.information.presentation import present_concise

    old = {'participants': {'ally': 'SAV', 'willingness': -12,
                           'reasons': [{'value': -12, 'text': 'recorded reason'}],
                           'favor_requirement': 10, 'land_promise_available': False}}
    requested = list(old['participants'])
    fields, complete = _field_result(requested, old, get_topic('D04'))
    assert complete and {name: field['value'] for name, field in fields.items()} == old['participants']
    item = present_concise({'items': [{'topic': 'D04', 'fields': fields}]})['items'][0]
    assert item == old['participants']

    inspection = json.loads((Path(__file__).parent / 'fixtures' /
                            'information_declare_war_participants_FRA_GEN_live_1374.json').read_bytes())['inspection']
    sav = next(row for row in inspection['participants']['candidates'] if row['country'] == 'SAV')
    sav['willingness']['native_total_raw'] = 1000
    projected, _ = _field_result(['willingness', 'reasons'], inspection, get_topic('D04'))
    assert projected['willingness']['value']['SAV']['score'] == 1000
    assert projected['reasons']['value']['SAV'] == sav['willingness']['reasons']


@pytest.mark.parametrize("topic", ["D01", "D02", "D03", "D04", "D05", "D06"])
def test_selected_declare_war_report_forwards_existing_inspection_contract(tmp_path, topic):
    session = _LiveSession()
    backend = _LiveTools(session)
    source = DiplomacySource(backend)
    selection = {
        "casus_belli": "cb_core",
        "war_goal": {"province_id": 177, "beneficiary": "FRA"},
        "call_allies": ["SCO"], "promise_land_to": ["SCO"], "co_belligerents": ["BUR"],
    }
    selected_topic = next(item for item in source.catalog() if item["topic_id"] == topic)
    query = _query(topic, {"type": "country_pair", "actor": "FRA", "recipient": "ENG"},
                   [next(iter(selected_topic["fields"]))], {"selection": selection})
    with closing(InformationService(source, tmp_path / "information.sqlite3")) as service:
        tools = InformationTools(service)
        report = tools.call("information_manage_report", {
            "request_id": "selected-war-create", "operation": "create",
            "config": {"name": "selected war", "detail": "brief", "queries": [query]},
        })["report"]
        result = tools.call("information_query", {
            "request_id": "selected-war-query", "report_id": report["id"], "view": "full"})
    assert backend.inspect_calls == [("declare_war", "FRA", "ENG", "initiate", selection)]
    assert result["items"][0]["query"] == query


@pytest.mark.parametrize("changes", [
    {"war_goal": "take_core"},
    {"call_allies": ["SCO", "SCO"]},
    {"call_allies": ["FRA"]},
    {"promise_land_to": ["SCO"]},
])
def test_invalid_selected_declare_war_report_fails_before_inspection(tmp_path, changes):
    backend = _LiveTools(_LiveSession())
    source = DiplomacySource(backend)
    selection = {"casus_belli": "cb_core", "war_goal": {"province_id": 177, "beneficiary": "FRA"},
                 "call_allies": []}
    selection.update(changes)
    query = _query("D02", {"type": "country_pair", "actor": "FRA", "recipient": "ENG"},
                   ["legality_status"], {"selection": selection})
    with closing(InformationService(source, tmp_path / "information.sqlite3")) as service:
        with pytest.raises(InformationError):
            service.manage_report("invalid-selection", "create", config={"queries": [query]})
        assert service.manage_report("list-reports", "list")["reports"] == []
    assert backend.inspect_calls == []


def test_declare_war_selection_rejects_mixed_contexts_before_inspection():
    backend = _LiveTools(_LiveSession())
    source = DiplomacySource(backend)
    query = _query("D02", {"type": "country_pair", "actor": "FRA", "recipient": "ENG"},
                   ["legality_status"], {
                       "casus_belli": "cb_core",
                       "selection": {"casus_belli": "cb_core", "war_goal": {"province_id": 177, "beneficiary": "FRA"},
                                     "call_allies": []},
                   })
    with pytest.raises(InformationError, match="one declare-war selection"):
        source.read(query, source.context())
    assert backend.inspect_calls == []


def _recorded_fixture_with_manifest():
    """Attach explicit provenance to the historical query fixture.

    The fixture itself is a native query archive and intentionally does not
    claim a current observer.  This manifest records the already verified
    1.37.4 installation identity used for the recorded read.
    """
    archive = json.loads(FIXTURE.read_text(encoding="utf-8"))
    archive["manifest"] = {
        "status": "ready",
        "session_id": "3228-1dd6006ee2dc2bc",
        "observer": "FRA",
        "game_version": "1.37.4",
        "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        "dll_sha256": "f989a4de0ba60c1285907752179dd9626aea2611ed1a1a42771410bf0952fad3",
    }
    return archive


def test_catalog_has_all_74_topics_and_field_level_statuses():
    topics = catalog()
    assert len(topics) == 75
    assert len({item["topic_id"] for item in topics}) == 75
    assert {item["status"] for item in topics} == {"available", "planned"}
    for item in topics:
        assert item["catalog_ids"]
        assert item["fields"]
        assert item["parameters"]["type"] == "object"
        assert item["object_types"]
        assert set(item["triggers"]) <= {"query", "periodic", "change", "event"}
        for field in item["fields"].values():
            assert field["coverage"] in {"available", "partial", "planned"}


def test_validate_query_enforces_identity_and_observer_scope():
    query = _query("R05", {"type": "country_pair", "actor": "FRA", "recipient": "PAP"},
                   ["trust"], {"action_id": "trade_favors_for_trust", "kind": "trust"})
    assert validate_query(query, {"session_id": "s", "observer": "FRA"}) == query

    with pytest.raises(InformationError) as missing:
        validate_query(_query("R05", {"type": "country_pair"}, ["trust"]))
    assert missing.value.code == "invalid_object"

    with pytest.raises(InformationError) as scope:
        validate_query(_query("R05", {"type": "country_pair", "actor": "ENG", "recipient": "PAP"}, ["trust"]),
                       {"session_id": "s", "observer": "FRA"})
    assert scope.value.code == "observer_scope_mismatch"

    with pytest.raises(InformationError):
        validate_query(_query("R05", {"type": "country_pair", "actor": "FRA", "recipient": "FRA"}, ["trust"]))

    with pytest.raises(InformationError) as mismatch:
        validate_query(_query(
            "R05", {"type": "country_pair", "actor": "FRA", "recipient": "PAP"},
            ["trust"], {"action_id": "trade_favors_for_trust", "kind": "men"},
        ))
    assert mismatch.value.code == "invalid_parameters"

    with pytest.raises(InformationError):
        validate_query(_query(
            "A03", {"type": "country_pair", "actor": "FRA", "recipient": "PAP"},
            ["costs"], {"action_id": "trade_favors_for_trust", "kind": "trust"},
        ))


def test_live_source_reads_health_inspection_and_inbound_without_execution():
    session = _LiveSession()
    tools = _LiveTools(session)
    source = DiplomacySource(tools)
    context = source.context()
    assert context["status"] == "ready"
    assert context["mode"] == "live"
    assert context["observer"] == "FRA"
    assert context["game_version"] == "1.37.4"
    assert context["game_date"] == 56554848
    assert context["game_day"] == 56554848 // 24
    assert context["game_date_raw"] == 56554848

    result = source.read(_query(
        "A01", {"type": "country_pair", "actor": "FRA", "recipient": "PAP"},
        ["action_id", "legality_status", "costs"],
        {"action_id": "offer_alliance"},
    ), context)
    assert result["source"]["mode"] == "live"
    assert result["fields"]["action_id"] == {"status": "known", "value": "offer_alliance"}
    assert result["fields"]["legality_status"]["status"] == "known"
    assert tools.inspect_calls and tools.inspect_calls[0][0] == "offer_alliance"


    favor = source.read(_query(
        "R05", {"type": "country_pair", "actor": "FRA", "recipient": "PAP"},
        ["trust", "favors_available"],
        {"kind": "trust"},
    ), context)
    assert favor["fields"]["trust"] == {"status": "known", "value": 50}
    assert favor["fields"]["favors_available"] == {"status": "known", "value": 23466}
    assert tools.inspect_calls[-1][0] == "trade_favors_for_trust"
    assert tools.inspect_calls[-1][-1] == {}

    inbound = source.read(_query(
        "A04", {"type": "country_pair", "actor": "SAV", "recipient": "FRA"},
        ["proposal_id", "action_id", "proposal_status"],
    ), context)
    assert inbound["fields"]["proposal_id"]["status"] == "known"
    assert inbound["fields"]["proposal_status"]["status"] == "known"

    events = source.poll_events(context, None)
    assert events["events"][0]["source"]["mode"] == "live"
    assert events["events"][0]["event_type"] == "diplomatic_proposal"
    assert "execute" not in {call[0] for call in tools.inspect_calls}


def test_r05_balance_query_defaults_to_trust_and_identifies_favor_direction():
    backend = _LiveTools(_LiveSession())
    source = DiplomacySource(backend)
    result = source.read(_query(
        "R05", {"type": "country_pair", "actor": "FRA", "recipient": "PAP"},
        ["trust", "favors_available", "favors_direction"]), source.context())

    assert backend.inspect_calls[-1] == (
        "trade_favors_for_trust", "FRA", "PAP", "initiate", {})
    assert result["fields"]["trust"] == {"status": "known", "value": 50}
    assert result["fields"]["favors_available"] == {
        "status": "known", "value": 23466}
    assert result["fields"]["favors_direction"] == {
        "status": "known", "value": "actor_holds_for_recipient"}


@pytest.mark.parametrize("required", [True, False])
def test_action_diplomat_requirement_reuses_native_resource_projection(required):
    backend = _LiveTools(_LiveSession())
    inspect = backend.inspect_diplomatic_action

    def inspect_with_diplomats(*args):
        result = inspect(*args)
        result["resources"] = {"diplomats": {
            "native_requirement": required,
            "available_count": 2,
            "availability_verified": True,
            "allocation_verified": False,
            "source": "native_rule",
            "complete": False,
        }}
        return result

    backend.inspect_diplomatic_action = inspect_with_diplomats
    source = DiplomacySource(backend)
    result = source.read(_query(
        "A01", {"type": "country_pair", "actor": "FRA", "recipient": "PAP"},
        ["diplomat_required"], {"action_id": "offer_alliance"},
    ), source.context())
    assert result["fields"]["diplomat_required"] == {"status": "known", "value": required}
    assert len(backend.inspect_calls) == 1


@pytest.mark.parametrize("diagnostic,gate,expected", [
    ("§R- 最近已经派遣过外交官，所以直到§Y1470年11月27日§!我们才能再次派遣。§!\n\n要求他们领土的通行权。",
     False, {"blocked": True, "available_on": "1470年11月27日"}),
    ("§R- We have recently sent a diplomat, so we cannot send another until §Y27 November 1470§!.§!\n",
     False, {"blocked": True, "available_on": "27 November 1470"}),
    ("", True, {"blocked": False, "available_on": None}),
    ("拥有军事通行权", False, None),
    ("停战直到1470年11月27日。", False, None),
    ("最近已经派遣过外交官，所以直到1470年11月27日", False, None),
])
def test_action_cooldown_uses_selected_preview_without_additional_query(tmp_path, diagnostic, gate, expected):
    backend = _LiveTools(_LiveSession())
    inspect = backend.inspect_diplomatic_action

    def inspect_with_cooldown(*args):
        result = inspect(*args)
        result["native_diagnostic"] = {"text": diagnostic}
        result["native_rule_components"] = {"common_action_gate": gate}
        return result

    backend.inspect_diplomatic_action = inspect_with_cooldown
    query = _query("A01", {"type": "country_pair", "actor": "FRA", "recipient": "GEL"},
                   ["cooldown"], {"action_id": "ask_military_access"})
    with closing(InformationService(DiplomacySource(backend), tmp_path / "information.sqlite3")) as service:
        tools = InformationTools(service)
        result = tools.call("information_query", {"request_id": "cooldown-query", "queries": [query]})
        assert result["items"][0]["cooldown"] == expected
        stored = service.get_result(result["result_id"])
        field = stored["items"][0]["fields"]["cooldown"]
        assert field["status"] == ("known" if expected is not None else "unknown")
        assert tools.call("information_get_result", {"result_id": result["result_id"]}) == result
    assert len(backend.inspect_calls) == 1


def test_structured_action_cooldown_remains_usable():
    backend = _LiveTools(_LiveSession())
    inspect = backend.inspect_diplomatic_action

    def inspect_with_structured_cooldown(*args):
        result = inspect(*args)
        result["cooldown"] = {"blocked": True, "available_on": "1470.11.27"}
        return result

    backend.inspect_diplomatic_action = inspect_with_structured_cooldown
    source = DiplomacySource(backend)
    result = source.read(_query(
        "A01", {"type": "country_pair", "actor": "FRA", "recipient": "GEL"},
        ["cooldown"], {"action_id": "ask_military_access"},
    ), source.context())
    assert result["fields"]["cooldown"] == {
        "status": "known", "value": {"blocked": True, "available_on": "1470.11.27"}}


def test_live_unready_source_is_explicit():
    source = DiplomacySource(_LiveTools(_LiveSession(ready=False)))
    context = source.context()
    assert context["status"] == "unready"
    result = source.read(_query(
        "A01", {"type": "country_pair", "actor": "FRA", "recipient": "PAP"},
        ["legality_status"], {"action_id": "offer_alliance"}), context)
    assert result["fields"]["legality_status"]["status"] == "unavailable"


def test_recorded_real_fixture_preserves_provenance_and_raw_date():
    source = RecordedSource(_recorded_fixture_with_manifest())
    context = source.context()
    assert context["mode"] == "recorded"
    assert context["session_id"] == "3228-1dd6006ee2dc2bc"
    assert context["game_date"] == 56554848
    assert context["game_day"] == 56554848 // 24

    result = source.read(_query(
        "R05", {"type": "country_pair", "actor": "FRA", "recipient": "PAP"},
        ["trust", "favors_available", "favors_direction"],
        {"action_id": "trade_favors_for_trust", "kind": "trust"}), context)
    assert result["source"]["mode"] == "recorded"
    assert result["source"]["provenance"]["sha256"]
    assert result["fields"]["trust"] == {"status": "known", "value": 50}
    assert result["fields"]["favors_available"] == {"status": "known", "value": 23466}
    assert result["fields"]["favors_direction"] == {
        "status": "known", "value": "actor_holds_for_recipient"}
    r05 = next(item for item in catalog() if item["topic_id"] == "R05")
    assert r05["fields"]["favors_available"]["unit"] == "favors_raw"
    assert r05["fields"]["favors_available"]["scale"] == 1000
    assert "kind" not in r05["fields"]["favors_direction"]["paths"]
    assert "recipient" in r05["fields"]["trust"]["description"]
    assert "actor" in r05["fields"]["trust"]["description"]

    first = source.poll_events(context, None)
    second = source.poll_events(context, first["cursor"])
    assert first["events"]
    assert all(item["source"]["mode"] == "recorded" for item in first["events"])
    assert second["events"] == []


def test_recorded_identity_is_explicit_and_event_types_feed_service(tmp_path):
    unbound = RecordedSource(FIXTURE)
    assert unbound.context()["status"] == "unready"
    assert unbound.context()["observer"] is None

    source = RecordedSource(_recorded_fixture_with_manifest())
    assert source.event_types == ("native_alliance_inspection",)
    service = InformationService(source, tmp_path / "information.sqlite3")
    report = service.manage_report(
        "recorded-event-report", "create", config={
            "name": "recorded session context",
            "queries": [{
                "topic": "C01", "object": {"type": "session"},
                "fields": ["session_id"], "parameters": {},
            }],
            "detail": "full",
        },
    )["report"]
    subscription = service.manage_subscription(
        "recorded-event-subscription", "create", config={
            "name": "recorded native inspection events",
            "kind": "event", "report_id": report["id"], "enabled": True,
            "event": {"types": ["native_alliance_inspection"]},
        },
    )["subscription"]
    assert subscription["state"] == "active"
    tick = service.tick()
    assert tick["results"]
    assert tick["results"][0]["event"]["event_type"] == "native_alliance_inspection"
    service.close()


def test_durable_journal_events_integrate_with_service_and_report_gaps(tmp_path, monkeypatch):
    """Poll real offline journal records without dispatching a native action."""

    experiment_id = "information-journal-test"
    session_id = "information-journal-session"
    journal = DurableJournal(tmp_path / "journal.sqlite3", experiment_id, session_id)
    journal.register(
        "journal-request-1",
        {
            "action_id": "offer_alliance",
            "actor": "FRA",
            "recipient": "PAP",
            "phase": "initiate",
            "parameters": {},
        },
    )
    journal.record_evidence(
        "journal-request-1",
        "native_response",
        {"accepted": True},
        arrival_layer="native_response",
        event_id="journal-evidence-original",
        observed_at="2026-10-24T00:00:00+00:00",
    )

    class JournalSession:
        observer = "FRA"
        record = {
            "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
            "dll_sha256": "f989a4de0ba60c1285907752179dd9626aea2611ed1a1a42771410bf0952fad3",
        }

        def __init__(self):
            self.session_id = session_id
            self.experiment_id = experiment_id

        @staticmethod
        def health():
            return {
                "status": "ready",
                "date_raw": 56554848,
                "complete": True,
                "reasons": [],
            }

        @staticmethod
        def read_native_alliance_inbound_offers():
            return []

    class JournalTools:
        def __init__(self):
            self.session = JournalSession()
            self.journal = journal

    tools = JournalTools()
    source = DiplomacySource(tools)
    context = source.context()
    assert context["status"] == "ready"
    service = InformationService(source, tmp_path / "information.sqlite3")
    report = service.manage_report(
        "journal-event-report", "create", config={
            "name": "journal event context",
            "queries": [{
                "topic": "C01", "object": {"type": "session"},
                "fields": ["session_id"], "parameters": {},
            }],
            "detail": "full",
        },
    )["report"]
    service.manage_subscription(
        "journal-event-subscription", "create", config={
            "name": "journal actor recipient filter",
            "kind": "event", "report_id": report["id"], "enabled": True,
            "event": {
                "types": ["diplomatic_request_result", "evidence"],
                "actors": ["FRA"], "recipients": ["PAP"],
            },
        },
    )

    first = service.tick()
    assert len(first["results"]) == 2
    events = [result["event"] for result in first["results"]]
    assert {event["event_type"] for event in events} == {
        "diplomatic_request_result", "evidence",
    }
    for event in events:
        identifier(event["event_id"], "event_id")
        assert event["payload"]["actor"] == "FRA"
        assert event["payload"]["recipient"] == "PAP"
        assert event["game_date"] is None
        assert event["collected_game_date"] == context["game_date"]
    request_event = next(
        event for event in events if event["event_type"] == "diplomatic_request_result"
    )
    assert request_event["payload"]["identity"]["updated_at"]
    assert len(request_event["event_id"]) <= 128

    second = service.tick()
    assert second["results"] == []

    original_reader = journal.list_evidence_for_record
    monkeypatch.setattr(
        journal,
        "list_evidence_for_record",
        lambda record: (_ for _ in ()).throw(RuntimeError("offline evidence read failed")),
    )
    incomplete = source.poll_events(context, None)
    assert incomplete["complete"] is False
    assert "EVIDENCE_READ_FAILED:journal-request-1" in incomplete["gaps"]
    monkeypatch.setattr(journal, "list_evidence_for_record", original_reader)
    service.close()
    journal.close()



@pytest.mark.parametrize("actor,recipient,visible", [("FRA", "SAV", True), ("SAV", "GEN", False)])
def test_c04_request_query_uses_the_same_event_snapshot_as_subscription(tmp_path, actor, recipient, visible):
    backend = _LiveTools(_LiveSession())
    with closing(DurableJournal(tmp_path / "c04-journal.sqlite3", "c04-direct", backend.session.session_id)) as journal:
        backend.journal = journal
        record = journal.register("c04-request", {
            "action_id": "curry_favors", "actor": actor, "recipient": recipient,
            "phase": "initiate", "parameters": {},
        })
        source = DiplomacySource(backend)
        context = source.context()
        query = _query("C04", {"type": "session", "session_id": backend.session.session_id},
                       ["event_id", "event_type", "event_date", "event_payload"],
                       {"request_id": "c04-request"})
        with closing(InformationService(source, tmp_path / "c04-information.sqlite3")) as service:
            api = InformationTools(service)
            result = api.call("information_query", {"request_id": "c04-read", "queries": [query]})
            item = result["items"][0]
            if visible:
                event = source._journal_event(record, context, [])
                replay = source.replay_event(query, context, event)
                stored = service.get_result(result["result_id"])["items"][0]
                assert stored["fields"] == replay["fields"]
                assert item["event_id"] == event["event_id"]
                assert item["event_type"] == "diplomatic_request_result"
                assert item["event_payload"]["request"]["request_id"] == "c04-request"
            else:
                assert item["event_payload"] is None
                assert service.get_result(result["result_id"])["items"][0]["fields"]["event_id"]["reason"] == "REQUEST_OBSERVER_SCOPE_MISMATCH"
