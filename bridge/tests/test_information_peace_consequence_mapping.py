"""Recorded 1.37.4 peace consequence paths through the real information route.

The saved R66 public projection is used as the fixture.  The diplomacy stub
only replays that immutable projection through ``DiplomacySource``; it does
not call a native reader.  The synthetic acceptance payload is deliberately
separate so availability cannot be mistaken for completeness.
"""

from copy import deepcopy
from contextlib import closing
import hashlib
import json
from pathlib import Path

import pytest

from bridge.tests.legacy_france_adapter import FixedFranceDiplomacyTools as DiplomacyTools, FixedFranceObserverSession as ObserverSession
from bridge.information import InformationService
from bridge.information import catalog as information_catalog
from bridge.information.beneficiary_projection import declaration_beneficiaries, peace_fields
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools
from bridge.native_text import EU4_ESCAPE_CODEC
from bridge.tests.test_declarewar_details_r62_real import _SemanticSession
from bridge.tests import test_peace_province_tools as province_fixture


ROOT = Path(__file__).resolve().parents[2]
RAW_FIXTURE = ROOT / "bridge/tests/fixtures/r66_net_overextension_real.json"
PUBLIC_PROJECTION = (
    ROOT
    / "work/runtime/r66-netoe-consequence-queries-b-20261019-001"
    / "report-evidence/cases/demand-province-one/public.json"
)
RAW_FIXTURE_SHA256 = (
    "952f448e6fcbd69270e416f75cea288d3a5899a9b89532751fa719b13ca9015f"
)
PUBLIC_PROJECTION_SHA256 = (
    "194fdbb68be4c99c8293ebf3da308329fbd75b4d6bdf324f32d36069f2770371"
)
WAR_ID = "war_b0fb22dd717d14bf_00000001"
SESSION_ID = "17108-1dd5fca094cbafc"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class _RecordedSession:
    def __init__(self):
        self.session_id = SESSION_ID

    def health(self):
        return {
            "status": "ready",
            "complete": True,
            "session_id": SESSION_ID,
            "observer": "FRA",
            "game_version": "1.37.4",
            "game_date": 56551848,
            "game_day": 2356327,
            "world_id": "r66-b",
            "paused": True,
        }


class _RecordedDiplomacy:
    def __init__(self, public_projection: dict):
        self.session = _RecordedSession()
        self.public_projection = deepcopy(public_projection)
        self.calls = []

    def inspect_diplomatic_action(
            self, action_id, actor, recipient, phase, parameters):
        self.calls.append({
            "action_id": action_id,
            "actor": actor,
            "recipient": recipient,
            "phase": phase,
            "parameters": deepcopy(parameters),
        })
        return deepcopy(self.public_projection)


def _load_pinned_projection() -> dict:
    assert RAW_FIXTURE.is_file()
    assert PUBLIC_PROJECTION.is_file()
    assert _sha256(RAW_FIXTURE) == RAW_FIXTURE_SHA256
    assert _sha256(PUBLIC_PROJECTION) == PUBLIC_PROJECTION_SHA256
    raw = json.loads(RAW_FIXTURE.read_text(encoding="utf-8"))
    case = next(item for item in raw["cases"]
                if item.get("name") == "demand-province-one")
    assert case["source"]["query_id"] == "inspect_37d99a6e096146c7974e6b01046992f3"
    assert case["source"]["line"] == 204
    public = json.loads(PUBLIC_PROJECTION.read_text(encoding="utf-8"))
    assert public["action_id"] == "cede_province"
    assert public["actor"] == "FRA"
    assert public["recipient"] == "BUR"
    assert public["phase"] == "initiate"
    assert public["peace_context"]["war_id"] == WAR_ID
    return public


def _catalog_entry(topic_id: str) -> dict:
    return next(item for item in information_catalog._CATALOG
                if item["topic_id"] == topic_id)


def _query(topic: str, fields: list[str]) -> dict:
    return {
        "topic": topic,
        "object": {
            "type": "war",
            "war_id": WAR_ID,
            "actor": "FRA",
            "recipient": "BUR",
        },
        "fields": fields,
        "parameters": {
            "action_id": "cede_province",
            "phase": "initiate",
            "peace_context": {
                "war_id": WAR_ID,
                "direction": "demand",
                "terms": [{
                    "action_id": "cede_province",
                    "beneficiary": "FRA",
                    "province_ids": [88],
                }],
            },
        },
    }


def _country_pair_acceptance_query() -> dict:
    return {
        "topic": "A02",
        "object": {
            "type": "country_pair",
            "actor": "FRA",
            "recipient": "BUR",
        },
        "fields": ["acceptance_complete"],
        "parameters": {
            "action_id": "cede_province",
            "phase": "initiate",
        },
    }


def _field(result: dict, name: str) -> dict:
    return result["items"][0]["fields"][name]


def test_p04_consequence_paths_reach_saved_public_projection(tmp_path, monkeypatch):
    """Fixture-backed P04 paths retain old aliases and add public paths."""
    public = _load_pinned_projection()
    diplomacy = _RecordedDiplomacy(public)
    source = DiplomacySource(diplomacy, observer="FRA")
    service = InformationService(source, tmp_path / "information.sqlite3")
    entry = _catalog_entry("P04")
    consequences = entry["fields"]["consequences"]
    territorial = entry["fields"]["territorial_changes"]
    consequence_paths = list(consequences["paths"])
    territorial_paths = list(territorial["paths"])
    query = _query("P04", ["consequences", "territorial_changes"])
    try:
        assert consequence_paths[:2] == [
            "peace_context.consequences", "consequences",
        ]
        assert consequence_paths[-1] == "peace_consequences"
        assert territorial_paths == [
            "peace_context.territorial_changes",
            "peace_consequences.territorial",
        ]
        assert entry["fields"]["consequences"]["coverage"] == "partial"
        assert entry["fields"]["territorial_changes"]["coverage"] == "partial"

        # The pre-fix aliases cannot see this saved public projection.
        monkeypatch.setitem(
            consequences, "paths", ["peace_context.consequences", "consequences"])
        monkeypatch.setitem(
            territorial, "paths", ["peace_context.territorial_changes"])
        before = service.query("p04-before", queries=[query])
        assert _field(before, "consequences")["status"] == "unknown"
        assert _field(before, "territorial_changes")["status"] == "unknown"

        monkeypatch.setitem(consequences, "paths", consequence_paths)
        monkeypatch.setitem(territorial, "paths", territorial_paths)
        after = service.query("p04-after", queries=[query])
        assert _field(after, "consequences")["status"] == "known"
        assert _field(after, "consequences")["value"] == public["peace_consequences"]
        assert _field(after, "territorial_changes")["status"] == "known"
        assert _field(after, "territorial_changes")["value"] == public["peace_consequences"]["territorial"]
        assert after["items"][0]["complete"] is True
        assert len(diplomacy.calls) == 2
    finally:
        service.close()


def test_p05_coalition_path_reaches_saved_public_projection(tmp_path, monkeypatch):
    """Fixture-backed P05 coalition mapping is partial but known."""
    public = _load_pinned_projection()
    diplomacy = _RecordedDiplomacy(public)
    source = DiplomacySource(diplomacy, observer="FRA")
    service = InformationService(source, tmp_path / "information.sqlite3")
    field = _catalog_entry("P05")["fields"]["coalition"]
    fixed_paths = list(field["paths"])
    query = _query("P05", ["coalition"])
    try:
        assert fixed_paths == ["peace_context.coalition", "peace_consequences.coalition"]
        assert field["coverage"] == "partial"
        monkeypatch.setitem(field, "paths", ["peace_context.coalition"])
        before = service.query("p05-before", queries=[query])
        assert _field(before, "coalition")["status"] == "unknown"

        monkeypatch.setitem(field, "paths", fixed_paths)
        after = service.query("p05-after", queries=[query])
        assert _field(after, "coalition")["status"] == "known"
        assert _field(after, "coalition")["value"] == public["peace_consequences"]["coalition"]
        assert after["items"][0]["complete"] is True
        assert len(diplomacy.calls) == 2
    finally:
        service.close()


def test_p03_acceptance_complete_uses_complete_marker(tmp_path, monkeypatch):
    """Fixture and synthetic availability/false-complete cases stay distinct."""
    public = _load_pinned_projection()
    acceptance = public["acceptance"]
    assert acceptance["details_available"] is True
    assert acceptance["details_complete"] is False
    assert acceptance["complete"] is False

    field = _catalog_entry("P03")["fields"]["acceptance_complete"]
    fixed_paths = list(field["paths"])
    assert fixed_paths == ["acceptance.details_complete", "acceptance.complete"]
    query = _query("P03", ["acceptance_complete"])

    real_diplomacy = _RecordedDiplomacy(public)
    real_service = InformationService(
        DiplomacySource(real_diplomacy, observer="FRA"),
        tmp_path / "real.sqlite3",
    )
    try:
        # The former path returned availability=True, which was not a
        # completeness assertion for this recorded acceptance breakdown.
        monkeypatch.setitem(
            field, "paths", ["acceptance.details_available", "acceptance.complete"])
        before = real_service.query("p03-before", queries=[query])
        assert _field(before, "acceptance_complete") == {
            "status": "known", "value": True,
        }

        monkeypatch.setitem(field, "paths", fixed_paths)
        after = real_service.query("p03-after", queries=[query])
        assert _field(after, "acceptance_complete") == {
            "status": "known", "value": False,
        }
        assert after["items"][0]["complete"] is True
    finally:
        real_service.close()

    # Synthetic: availability is true while both reliable completion markers
    # are false.  The fixed contract must expose false, never availability.
    synthetic = deepcopy(public)
    synthetic["acceptance"] = {
        "details_available": True,
        "details_complete": False,
        "complete": False,
    }
    synthetic_diplomacy = _RecordedDiplomacy(synthetic)
    synthetic_service = InformationService(
        DiplomacySource(synthetic_diplomacy, observer="FRA"),
        tmp_path / "synthetic.sqlite3",
    )
    try:
        result = synthetic_service.query("p03-synthetic", queries=[query])
        assert _field(result, "acceptance_complete") == {
            "status": "known", "value": False,
        }
    finally:
        synthetic_service.close()


def test_a02_acceptance_complete_uses_complete_marker(tmp_path, monkeypatch):
    """Synthetic A02 availability cannot masquerade as completeness."""
    synthetic = {
        "acceptance": {
            "details_available": True,
            "details_complete": False,
            "complete": False,
        },
    }
    diplomacy = _RecordedDiplomacy(synthetic)
    service = InformationService(
        DiplomacySource(diplomacy, observer="FRA"),
        tmp_path / "a02.sqlite3",
    )
    field = _catalog_entry("A02")["fields"]["acceptance_complete"]
    fixed_paths = list(field["paths"])
    query = _country_pair_acceptance_query()
    try:
        assert fixed_paths == ["acceptance.details_complete", "acceptance.complete"]
        monkeypatch.setitem(
            field, "paths", ["acceptance.details_available", "acceptance.complete"])
        before = service.query("a02-before", queries=[query])
        assert _field(before, "acceptance_complete") == {
            "status": "known", "value": True,
        }

        monkeypatch.setitem(field, "paths", fixed_paths)
        after = service.query("a02-after", queries=[query])
        assert _field(after, "acceptance_complete") == {
            "status": "known", "value": False,
        }
        assert after["items"][0]["complete"] is True
    finally:
        service.close()


def _beneficiary_tools_query(public, event, query):
    backend = _RecordedDiplomacy(public)
    backend.session.session_id = event['session_id']
    backend.session.record = {'game_sha256': 'b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77',
                              'dll_sha256': 'd' * 64}
    backend.session.health = lambda: {'status': 'ready', 'complete': True,
        'date_raw': event['date_raw'], 'reasons': []}
    with closing(InformationService(DiplomacySource(backend, observer='FRA'), ':memory:')) as service:
        api = InformationTools(service)
        concise = api.call('information_query', {'request_id': 'beneficiary-projection', 'queries': [query]})
        full = api.call('information_get_result', {'result_id': concise['result_id'], 'view': 'full'})
    assert len(backend.calls) == 1
    return concise['items'][0], full['items'][0]


def _declare_beneficiary_fixture(name):
    document = json.loads((ROOT / 'bridge/tests/fixtures/declarewar_details_r62_real.json').read_bytes())
    record = next(row for row in document['events'] if row['name'] == name)
    event = record['event']
    public = DiplomacyTools(None, _SemanticSession(event)).inspect_diplomatic_action(
        'declare_war', event['actor'], event['recipient'], parameters=record['parameters'])
    return record, public


@pytest.mark.parametrize('name,country,province', [
    ('ENG_selected-1-cb_conquest-167-ORL', 'ORL', 167),
    ('ENG_selected-2-cb_core-167----', 'FRA', 167),
    ('BUR_selected-1-cb_conquest-88-ORL', 'ORL', 88),
    ('ENG_selected-3-cb_trade_war_triggered--1----', 'FRA', None),
])
def test_d06_beneficiaries_use_real_cb_candidates_and_selected_goal(name, country, province):
    record, public = _declare_beneficiary_fixture(name)
    original = deepcopy(public)
    event = record['event']
    query = {'topic': 'D06', 'object': {'type': 'country_pair', 'actor': event['actor'], 'recipient': event['recipient']},
             'fields': ['beneficiaries'], 'parameters': {'selection': record['parameters']}}
    item, full = _beneficiary_tools_query(public, event, query)
    value = item['beneficiaries']
    assert value['casus_belli'] == event['requested_casus_belli']
    assert value['selected_war_goal'] == {'country': country, 'province_id': province}
    assert {'country': country, 'province_id': province} in value['war_goal_candidates']
    field = full['fields']['beneficiaries']
    assert field['scope'] == 'queried_casus_belli_war_goal_candidates'
    assert all(row['casus_belli_key'] == value['casus_belli'] for row in field['native_candidates'])
    if country == 'FRA':
        assert any(row['beneficiary_tag'] == '---' for row in field['native_candidates'])
        assert field['native_selected_war_goal']['beneficiary'] == '---'
    assert public == original


def test_d06_beneficiaries_preserve_unmatched_no_province_sentinel_without_a_selected_goal():
    document = json.loads((ROOT / 'bridge/tests/fixtures/declare_war_r61_no_province_cb_real.json').read_bytes())
    event = document['event']
    public = DiplomacyTools(None, _SemanticSession(event)).inspect_diplomatic_action(
        'declare_war', 'FRA', 'ENG', parameters={'casus_belli': 'cb_independence_war',
            'war_goal': {'province_id': -1, 'beneficiary': 'FRA'}, 'call_allies': []})
    field = declaration_beneficiaries(public)
    assert field['value']['war_goal_candidates'] == [{'country': 'FRA', 'province_id': None}]
    assert field['value']['selected_war_goal'] is None
    assert field['native_candidates'][0]['beneficiary_tag'] == '---'
    assert field['native_candidates'][0]['beneficiary_identifier_verified'] is False


def test_d06_beneficiaries_keep_unverified_or_incomplete_candidates_partial():
    _, public = _declare_beneficiary_fixture('ENG_selected-1-cb_conquest-167-ORL')
    candidate = next(row for row in public['candidates'] if row['casus_belli_key'] == 'cb_conquest')
    public['candidates'] = [dict(candidate, beneficiary_identifier_verified=False)]
    field = declaration_beneficiaries(public)
    assert field['value']['war_goal_candidates'] == []
    assert field['value']['selected_war_goal'] == {'country': 'ORL', 'province_id': 167}
    assert field['complete'] is False
    assert field['unresolved_candidate_count'] == 1


def test_d06_beneficiaries_keep_empty_native_goal_set_distinct_from_selected_actor():
    document = json.loads((ROOT / 'bridge/tests/fixtures/information_declare_war_participants_FRA_GEN_live_1374.json').read_bytes())
    field = declaration_beneficiaries(document['inspection'])
    assert field['status'] == 'known'
    assert field['value']['war_goal_candidates'] == []
    assert field['value']['selected_war_goal'] == {'country': 'FRA', 'province_id': None}
    assert field['complete'] is True


def _peace_beneficiary_fixture(name):
    document = json.loads((ROOT / 'bridge/tests/fixtures/r67_ally_peace_real.json').read_bytes())
    case = document['queries']['cases'][name]
    event = case['native_event']
    semantic = ObserverSession._semantic_peace_province_offer_inspection(event, EU4_ESCAPE_CODEC)
    public = DiplomacyTools._apply_peace_execution_inspection(
        {'interface_support': {}, 'session': {'date_raw': event['date_raw']}, 'acceptance': {}, 'costs': {}},
        semantic, case['input'])
    public.update({key: event[key] for key in ('action_id', 'actor', 'recipient', 'phase')})
    return case, public


@pytest.mark.parametrize('name,country,status', [
    ('actor_94_FRA', 'FRA', 'unavailable'), ('subject_88_ORL', 'ORL', 'available'),
    ('ally_193_SAV', 'SAV', 'unavailable'), ('ally_91_SAV', 'SAV', 'unavailable'),
])
def test_p01_beneficiaries_normal_tools_replay_r67_candidates_and_plan_legality(name, country, status):
    case, public = _peace_beneficiary_fixture(name)
    original = deepcopy(public)
    event, context = case['native_event'], case['input']['peace_context']
    query = {'topic': 'P01', 'object': {'type': 'war', 'war_id': context['war_id'], 'actor': 'FRA', 'recipient': 'BUR'},
             'fields': ['war_id', 'terms', 'candidates', 'beneficiaries', 'scope'],
             'parameters': {'action_id': 'cede_province', 'peace_context': context}}
    item, full = _beneficiary_tools_query(public, event, query)
    assert item['terms'] == context['terms']
    assert item['war_id'] == context['war_id']
    assert len(item['candidates']) == 23
    assert all(row['selectable'] is None and 'source' not in row for row in item['candidates'])
    groups = {row['country']: row for row in item['beneficiaries']['candidates']}
    assert groups['ORL']['province_ids'] == [88]
    assert set(groups['SAV']['province_ids']) == {91, 193}
    assert groups[country]['selectable_province_ids'] == []
    assert item['beneficiaries']['selected_plan']['countries'] == [country]
    assert item['beneficiaries']['selected_plan']['legality'] == status
    assert 'requested_plan' not in item['beneficiaries']
    if status == 'unavailable':
        assert item['beneficiaries']['selected_plan']['legality_reasons']
    assert full['fields']['beneficiaries']['complete'] is False
    assert full['fields']['beneficiaries']['scope'] == 'current_peace_candidate_beneficiaries'
    assert full['fields']['candidates']['candidate_tables'] == public['parameters']['candidates']
    assert public == original


def test_p01_beneficiaries_keep_checked_selectability_separate_from_selection():
    _, public = _peace_beneficiary_fixture('subject_88_ORL')
    public['parameters']['candidates']['candidates'] = [
        {'province_id': 88, 'beneficiary': 'ORL', 'selected': True,
         'native_selectability_checked': True, 'native_selectable': True},
        {'province_id': 91, 'beneficiary': 'SAV', 'selected': False,
         'native_selectability_checked': True, 'native_selectable': False},
    ]
    public['parameters']['candidates']['candidate_count'] = 2
    field = peace_fields(public, ['beneficiaries'])['beneficiaries']
    groups = {row['country']: row for row in field['value']['candidates']}
    assert groups['ORL']['selectable_province_ids'] == [88]
    assert groups['SAV']['blocked_province_ids'] == [91]
    assert field['complete'] is True


def test_p01_beneficiaries_partial_enumeration_preserves_observed_rows():
    _, public = _peace_beneficiary_fixture('subject_88_ORL')
    public['parameters']['candidates'].update(candidates_complete=False, candidates_truncated=True)
    fields = peace_fields(public, ['candidates', 'beneficiaries'])
    assert len(fields['candidates']['value']) == 23
    assert fields['candidates']['complete'] is False
    assert fields['beneficiaries']['value']['candidates']
    assert fields['beneficiaries']['complete'] is False


def test_p01_beneficiaries_do_not_treat_unapplied_requested_terms_as_selected():
    _, public = _peace_beneficiary_fixture('subject_88_ORL')
    public['parameters']['actual'] = None
    public['peace_consequences']['requested_terms_applied'] = False
    fields = peace_fields(public, ['terms', 'beneficiaries'])
    assert 'terms' not in fields
    assert fields['beneficiaries']['value']['selected_plan'] is None
    assert fields['beneficiaries']['value']['candidates']


def test_p01_beneficiaries_keep_distinct_actual_money_and_province_recipients():
    document = json.loads((ROOT / 'bridge/tests/fixtures/r67_ally_peace_real.json').read_bytes())
    public = document['outbound_execution']['selected_inspection']
    field = peace_fields(public, ['beneficiaries'])['beneficiaries']
    assert field['value']['selected_plan']['countries'] == ['FRA', 'ORL']
    assert 'legality' not in public
    assert field['value']['selected_plan']['legality'] == 'unknown'


def test_p01_beneficiaries_real_unapplied_orl_request_keeps_request_and_selection_reason():
    path = ROOT / 'bridge/tests/fixtures/information_peace_beneficiary_miss_FRA_BUR_live_1374.json'
    document = json.loads(path.read_bytes())
    assert document['source']['sha256'] == 'd4612527b20784b705df1944ccf1f30b382b076a6792efd5d6d62ef75276814e'
    public = document['inspection']
    original = deepcopy(public)
    context = public['parameters']['requested']['peace_context']
    query = {'topic': 'P01', 'object': {'type': 'war', 'war_id': context['war_id'], 'actor': 'FRA', 'recipient': 'BUR'},
             'fields': ['terms', 'candidates', 'beneficiaries'],
             'parameters': {'action_id': 'cede_province', 'peace_context': context}}
    event = {'session_id': 'recorded-beneficiary-miss', 'date_raw': document['game_date_raw']}
    item, full = _beneficiary_tools_query(public, event, query)
    assert item['terms'] is None
    assert len(item['candidates']) == 23
    value = item['beneficiaries']
    assert {row['country'] for row in value['candidates']} == {'FRA'}
    assert value['selected_plan'] is None
    assert value['requested_plan'] == {'countries': ['ORL'], 'applied': False,
        'selection_reason': '请求的省份和受益国组合不在当前原生候选中。'}
    assert full['fields']['beneficiaries']['requested_plan_reason_code'] == 'NATIVE_PEACE_PROVINCE_CANDIDATE_ABSENT'
    assert public['legality']['status'] == 'unknown'
    assert public == original


def test_p01_beneficiaries_legacy_query6_list_keeps_native_enumeration_completeness():
    document = json.loads((ROOT / 'bridge/tests/fixtures/peace_province_r41e_real_inspections.json').read_bytes())
    event = next(row['event'] for row in document['events']
                 if row['event']['native_provinces']['selection_requested'] is False)
    public = province_fixture.PeaceProvinceToolsTests()._run_r41e_public_query(event, evaluation_ack=True, submission_ack=True)
    assert isinstance(public['parameters']['candidates'], list)
    context = public['parameters']['requested']['peace_context']
    query = {'topic': 'P01', 'object': {'type': 'country_pair', 'actor': 'FRA', 'recipient': event['recipient']},
             'fields': ['candidates', 'beneficiaries', 'scope'],
             'parameters': {'action_id': 'cede_province', 'peace_context': context}}
    item, full = _beneficiary_tools_query(public, event, query)
    assert len(item['candidates']) == event['native_provinces']['candidate_count'] == 41
    assert item['beneficiaries']['candidates']
    assert 'requested_plan' not in item['beneficiaries']
    assert full['fields']['candidates']['complete'] is event['native_provinces']['candidate_enumeration_complete']
    assert full['fields']['candidates']['candidate_tables'] == public['parameters']['candidates']


@pytest.mark.parametrize('fields', [['terms'], ['candidates'], ['beneficiaries'], ['scope']])
def test_p01_beneficiaries_projection_is_limited_to_requested_fields(fields):
    _, public = _peace_beneficiary_fixture('subject_88_ORL')
    assert set(peace_fields(public, fields)) == set(fields)


def test_p01_beneficiaries_default_white_peace_preserves_candidate_unavailability():
    public = {'action_id': 'white_peace', 'parameters': {'actual': {'peace_context': {
        'war_id': WAR_ID, 'direction': 'demand', 'terms': []}}, 'candidates': None}}
    fields = peace_fields(public, ['terms', 'candidates', 'beneficiaries'])
    assert set(fields) == {'terms'}
    assert fields['terms']['value'] == []


@pytest.mark.parametrize('topic', ['D06', 'P01'])
def test_beneficiaries_old_recorded_fields_keep_priority(topic):
    case, public = _peace_beneficiary_fixture('subject_88_ORL')
    if topic == 'D06':
        record, public = _declare_beneficiary_fixture('ENG_selected-1-cb_conquest-167-ORL')
        event = record['event']
        public['peace_rules'] = {'beneficiaries': ['SAV']}
        query = {'topic': topic, 'object': {'type': 'country_pair', 'actor': 'FRA', 'recipient': 'ENG'},
                 'fields': ['beneficiaries'], 'parameters': {'selection': record['parameters']}}
    else:
        event = case['native_event']
        public.setdefault('peace_context', {})['beneficiaries'] = ['SAV']
        query = {'topic': topic, 'object': {'type': 'country_pair', 'actor': 'FRA', 'recipient': 'BUR'},
                 'fields': ['beneficiaries'], 'parameters': {'action_id': 'cede_province', **case['input']}}
    item, full = _beneficiary_tools_query(public, event, query)
    assert item['beneficiaries'] == ['SAV']
    assert full['fields']['beneficiaries'] == {'status': 'known', 'value': ['SAV']}
