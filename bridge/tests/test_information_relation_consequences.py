"""Primary relationship consequences from existing typed response contracts."""
from contextlib import closing
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from bridge.diplomacy import ObserverSession
from bridge.information import InformationService
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools
from bridge.information.presentation import present_result
from bridge.tests.test_information_inbound_current import _fixture_event, ACTIVE_FIXTURE, PUBLIC_ID
from bridge.tests.test_information_inbound_favor_parameters import FavorTools


RELATIONS = {
    'offer_alliance': ('alliance', 'alliance_before', 'alliance_after'),
    'offer_royal_marriage': ('royal_marriage', 'royal_marriage_before', 'royal_marriage_after'),
    'ask_military_access': ('military_access', 'military_access_before', 'military_access_after'),
    'offer_vassalization': ('vassalization', 'vassalization_before', 'vassalization_after'),
}


def synthetic_inspection(action):
    event = deepcopy(_fixture_event(ACTIVE_FIXTURE))
    family, before, _after = RELATIONS[action]
    event.update(action_id=action, family=family, extra60=0)
    event[before] = False
    if action == 'ask_military_access':
        event.update(military_access_active=False, military_access_state_verified=True)
    if action == 'offer_vassalization':
        event.update(native_current_vassalization=False, native_current_vassalization_readable=True)
    assert ObserverSession._valid_native_inbound_inspection(
        event, event['query_id'], event['session_id'], event['actor'], event['phase'],
        event['native_proposal_id'], event['date_raw'], action)
    return event


def relation_source(action, event=None, public_id=PUBLIC_ID):
    event = synthetic_inspection(action) if event is None else event
    tools = FavorTools(event, public_id)
    proposal = {'proposal_id': public_id, 'action_id': action, 'actor': event['actor'],
                'recipient': 'FRA', 'observer_status': 'observed_pending', 'parameters': {}}
    tools.session.read_native_alliance_inbound_offers = lambda: [deepcopy(proposal)]
    query = {'topic': 'A04', 'object': {'type': 'session'},
             'fields': ['parameters', 'currently_pending', 'response_consequences'],
             'parameters': {'proposal_id': public_id, 'fresh_pending': True}}
    return DiplomacySource(tools), tools, query, event, proposal


@pytest.mark.parametrize('action', list(RELATIONS))
def test_primary_relation_preview_keeps_roles_and_partial_conditional_semantics(action):
    source, tools, query, event, _proposal = relation_source(action)
    fields = source.read(query, source.context())['fields']
    assert fields['parameters']['value'] == {} and fields['currently_pending']['value'] is True
    field = fields['response_consequences']
    assert field['status'] == 'known' and field['scope'] == 'primary_relationship_state'
    assert field['derived'] is True and field['complete'] is False
    assert field['response_executed'] is False and field['response_authority'] is False
    assert field['conditional_on'] == 'response_completes_in_inspected_state'
    assert 'OTHER_DIRECT_EFFECTS_NOT_PROJECTED' in field['gaps']
    accepted = field['value']['accept']['changes'][0]
    rejected = field['value']['reject']['changes'][0]
    assert accepted['relation'] == RELATIONS[action][0]
    assert accepted['before'] is False and accepted['after'] is True
    assert rejected['before'] is False and rejected['after'] is False
    assert accepted['actor'] == event['actor'] and accepted['recipient'] == 'FRA'
    if action == 'ask_military_access':
        assert accepted['beneficiary'] == event['actor'] and accepted['grantor'] == 'FRA'
    elif action == 'offer_vassalization':
        assert accepted['overlord'] == event['actor'] and accepted['subject'] == 'FRA'
    else:
        assert accepted['symmetric'] is True and accepted['countries'] == [event['actor'], 'FRA']
    assert field['value']['reject']['legality'] == 'not_inspected'
    assert len(tools.inspect_calls) == 1


@pytest.mark.parametrize('action', list(RELATIONS))
@pytest.mark.parametrize('phase,state', [('accept', 2), ('reject', 1)])
def test_conditional_primary_state_matches_the_existing_actual_result_validator(action, phase, state):
    source, _tools, query, event, _proposal = relation_source(action)
    field = source.read(query, source.context())['fields']['response_consequences']
    after = field['value'][phase]['changes'][0]['after']
    family, before_key, after_key = RELATIONS[action]
    response = {
        'event': ('native_diplomacy_relation_response_result'
                  if action in ('ask_military_access', 'offer_vassalization') else 'native_alliance_response_result'),
        'request_id': 'synthetic-primary-contract', 'session_id': event['session_id'],
        'actor': event['actor'], 'recipient': 'FRA', 'action_id': action, 'phase': phase,
        'date_raw': event['date_raw'], 'native_proposal_id': event['native_proposal_id'],
        'family': family, 'native_variant': 1, 'native_state': state,
        'response_verified': True, 'request_binding_verified': True, 'pending_removed': True,
        before_key: False, after_key: after,
    }
    result = ObserverSession._public_native_inbound_response_result(
        response, response['request_id'], event['session_id'], event['actor'], phase,
        event['date_raw'], event['native_proposal_id'], action)
    assert result is not None
    assert result['native_outcome'] == ('accepted' if phase == 'accept' else 'rejected')


@pytest.mark.parametrize('action', list(RELATIONS))
@pytest.mark.parametrize('before', [True, None, 0])
def test_unproven_absent_state_keeps_known_proposal_and_current_status(action, before):
    source, tools, query, _event, _proposal = relation_source(action)
    tools.envelope['native_inbound_inspection'][RELATIONS[action][1]] = before
    fields = source.read(query, source.context())['fields']
    assert fields['response_consequences']['status'] == 'unknown'
    assert fields['parameters']['value'] == {} and fields['currently_pending']['value'] is True
    assert len(tools.inspect_calls) == 1


@pytest.mark.parametrize('action', ['ask_military_access', 'offer_vassalization'])
@pytest.mark.parametrize('damage', ['family', 'state', 'readable'])
def test_directional_relation_guards_require_the_existing_native_state_proof(action, damage):
    source, tools, query, _event, _proposal = relation_source(action)
    native = tools.envelope['native_inbound_inspection']
    if damage == 'family':
        native['family'] = 'alliance'
    elif damage == 'state':
        native['military_access_active' if action == 'ask_military_access' else 'native_current_vassalization'] = True
    else:
        native['military_access_state_verified' if action == 'ask_military_access' else 'native_current_vassalization_readable'] = False
    assert source.read(query, source.context())['fields']['response_consequences']['status'] == 'unknown'


@pytest.mark.parametrize('action', list(RELATIONS))
@pytest.mark.parametrize('detail', ['full', 'brief'])
def test_normal_relation_report_reopen_and_snapshot_replay(action, detail, tmp_path):
    source, tools, query, _event, proposal = relation_source(action)
    database = tmp_path / 'information.sqlite3'
    with closing(InformationService(source, database)) as service:
        report = service.manage_report('relation-report', 'create', config={
            'name': 'primary relationship consequences', 'detail': detail, 'queries': [query]})['report']
        result = present_result(InformationTools(service).call('information_query', {
            "view": "full",
            'request_id': 'relation-query', 'report_id': report['id']}))
        assert result['items'][0]['fields']['response_consequences']['status'] == 'known'
        full = service.get_result(result['result_id'])
        assert (present_result(full) if detail == 'brief' else full) == result
        replay = source.replay_event(query, source.context(), {
            'event_type': 'diplomatic_proposal', 'observer': 'FRA', 'session_id': tools.session.session_id,
            'payload': proposal})
        assert replay['fields']['response_consequences']['status'] == 'unknown'
        assert len(tools.inspect_calls) == 1
    with closing(InformationService(source, database)) as reopened:
        assert reopened.get_result(full['result_id']) == full


def test_royal_native_before_state_from_batch289_reaches_the_normal_query(tmp_path):
    root = Path(__file__).resolve().parents[2]
    captured = root / 'work/runtime/information-response-previews-20261108-289-001/live-preview'
    raw = (captured / 'native-check-1.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == 'cc7f2d196d21b3fca31c3d8c8a018827325d66d9dcd03467dbde753bd9b5dc4b'
    native = json.loads(raw)['result']
    context = json.loads((captured / 'context-before.json').read_text(encoding='utf-8'))
    summary = json.loads((captured / 'summary.json').read_text(encoding='utf-8'))
    assert native['royal_marriage_before'] is False and native['actor'] == 'BOU'
    event = dict(native, session_id=context['session_id'])
    source, tools, query, _event, _proposal = relation_source(
        'offer_royal_marriage', event=event, public_id=summary['proposal_id'])
    database = tmp_path / 'information.sqlite3'
    with closing(InformationService(source, database)) as service:
        result = InformationTools(service).call('information_query', {
            "view": "full",
            'request_id': 'captured-royal-consequences', 'queries': [query]})
        field = result['items'][0]['fields']['response_consequences']
        assert field['status'] == 'known' and field['observation_game_date'] == 56460816
        assert field['value']['accept']['changes'][0]['countries'] == ['BOU', 'FRA']
        assert field['value']['accept']['changes'][0]['after'] is True
        assert field['value']['reject']['changes'][0]['after'] is False
        assert field['response_executed'] is False and len(tools.inspect_calls) == 1
    (tmp_path / 'captured-royal-consequences.json').write_text(json.dumps({
        'evidence_kind': 'projection_from_batch289_native_inspection_in_memory_harness',
        'current_game_inspection': False, 'new_response': False, 'result': result,
    }, ensure_ascii=False, indent=2), encoding='utf-8')
