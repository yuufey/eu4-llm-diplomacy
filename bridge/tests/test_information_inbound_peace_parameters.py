"""Received Peace terms through ordinary A04 queries and preserved event snapshots."""
from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge.diplomacy import DiplomacyTools, ObserverSession
from bridge.diplomacy_journal import DurableJournal
from bridge.information import InformationService
from bridge.information.sources import DiplomacySource
from bridge.information.presentation import present_concise
from bridge.information.tools import InformationTools
from bridge.tests.test_information_inbound_current import FakeTools, PUBLIC_ID
from bridge.tests.test_information_proposal_expiry import SESSION, offer, expired, session
from bridge.tests.test_peace_inbound_tools import peace_context, inbound_inspection


QUERY = {'topic': 'A04', 'object': {'type': 'session'}, 'fields': ['parameters'], 'parameters': {}}


def pending_event(context):
    event = offer('peace_offer')
    event['peace_context'] = deepcopy(context)
    event['peace_context']['original_actor'] = event['actor']
    return event


def complete_event():
    return pending_event(peace_context())


def test_received_complete_terms_reach_the_offer_and_safe_list_without_mutation(tmp_path):
    event = complete_event()
    original = deepcopy(event)
    observed = session(tmp_path, [event])
    public = observed.read_native_inbound_offers()[0]
    expected = {'peace_context': event['peace_context']}
    assert public['parameters'] == expected
    safe = DiplomacyTools._safe_inbound_proposal(dict(public, parameters={'native_token': 42}))
    assert safe['parameters'] == expected
    assert event == original
    public['parameters']['peace_context']['terms'].clear()
    assert event == original


@pytest.mark.parametrize('damage', [
    'partial', 'selected_partial', 'actor', 'recipient', 'direction', 'unknown_action',
    'private_field', 'empty_unproven', 'white_conflict', 'bool_amount',
])
def test_invalid_or_incomplete_context_keeps_parameters_unknown(tmp_path, damage):
    event = complete_event()
    context = event['peace_context']
    if damage == 'partial':
        context['complete'] = False
    elif damage == 'selected_partial':
        context['selected_terms_complete'] = False
    elif damage == 'actor':
        context['original_actor'] = 'ENG'
    elif damage == 'recipient':
        context['original_recipient'] = 'POR'
    elif damage == 'direction':
        context['direction'] = 'unknown'
    elif damage == 'unknown_action':
        context['terms'][0]['action_id'] = 'unknown'
    elif damage == 'private_field':
        context['terms'][0]['native_token'] = 42
    elif damage == 'empty_unproven':
        context['terms'] = []
    elif damage == 'white_conflict':
        context['white_peace'] = True
    else:
        context['terms'][0]['amount_raw'] = True
    observed = session(tmp_path, [event])
    public = observed.read_native_inbound_offers()[0]
    assert 'parameters' not in public
    assert 'parameters' not in DiplomacyTools._safe_inbound_proposal(dict(public, parameters={}))
    source = DiplomacySource(DiplomacyTools(None, observed))
    assert source.read(QUERY, source.context())['fields']['parameters']['status'] == 'unknown'


def test_explicit_white_peace_and_native_core_grouping_preserve_their_meaning(tmp_path):
    event = complete_event()
    event['peace_context'].update(terms=[], white_peace=True)
    white = ObserverSession._public_native_inbound_offer('a' * 32, event)
    assert white['parameters']['peace_context']['white_peace'] is True
    assert white['parameters']['peace_context']['terms'] == []
    event['peace_context'].update(white_peace=False, terms=[
        {'action_id': 'return_core', 'province_id': 12, 'core_owner': 'ENG'},
        {'action_id': 'return_core', 'province_id': 13, 'core_owner': 'ENG'},
    ])
    public = ObserverSession._public_native_inbound_offer('b' * 32, event)
    assert public['parameters']['peace_context']['terms'] == [
        {'action_id': 'return_core', 'province_ids': [12, 13], 'core_owner': 'ENG'}]


@pytest.mark.parametrize('detail', ['full', 'brief'])
def test_received_terms_query_events_expiry_and_reopen_use_one_snapshot(tmp_path, detail):
    event = complete_event()
    observed = session(tmp_path, [event, expired('peace_offer')])
    database = tmp_path / 'information.sqlite3'
    with closing(DurableJournal(tmp_path / 'journal.sqlite3', observed.experiment_id, SESSION)) as journal:
        source = DiplomacySource(DiplomacyTools(journal, observed))
        with closing(InformationService(source, database)) as service:
            report = service.manage_report('terms-report', 'create', config={
                'name': 'received peace terms', 'queries': [QUERY], 'detail': detail})['report']
            current = service.query('terms-query', report_id=report['id'])
            assert current['items'][0]['fields']['parameters']['value'] == {'peace_context': event['peace_context']}
            subscription = service.manage_subscription('terms-subscribe', 'create', config={
                'name': 'received peace terms', 'kind': 'event', 'report_id': report['id'],
                'enabled': True, 'event': {'types': ['diplomatic_proposal'], 'recipients': ['FRA']},
            })['subscription']
            delivered = service.tick()['results']
            assert len(delivered) == 2
            expected = event['peace_context']
            assert all(row['items'][0]['fields']['parameters']['value']['peace_context'] == expected
                       for row in delivered)
            assert delivered[1]['items'][0]['source']['gaps'] == ['ORIGINAL_PROPOSAL_LEGALITY_UNKNOWN']
            assert service.tick()['results'] == []
            full = [service.get_result(row['result_id']) for row in [current, *delivered]]
            service.manage_subscription('terms-cancel', 'cancel', subscription_id=subscription['id'],
                                        expected_version=subscription['version'])
        with closing(InformationService(source, database)) as reopened:
            for saved in full:
                assert reopened.get_result(saved['result_id']) == saved


class PeaceTools(FakeTools):
    def _envelope(self, event, public_id):
        native = ObserverSession._public_native_inbound_inspection(event, event['date_raw'], 'peace_offer')
        return {
            'action_id': 'peace_offer', 'actor': event['actor'], 'recipient': 'FRA', 'phase': 'accept',
            'decision_country': 'FRA', 'decision_country_verified': native['decision_country_verified'],
            'parameters': {'requested': {'proposal_id': public_id},
                           'actual': {'proposal_id': public_id, 'decision_country': 'FRA'}},
            'session': self.session.health(), 'native_inbound_inspection': native,
            'observed_inbound_proposal': {'proposal_id': public_id, 'action_id': 'peace_offer',
                'actor': event['actor'], 'recipient': 'FRA', 'currently_pending': native['pending_active']},
        }


def current_source(event=None):
    event = event or inbound_inspection()
    tools = PeaceTools(event)
    proposal = {'proposal_id': PUBLIC_ID, 'action_id': 'peace_offer', 'actor': event['actor'],
                'recipient': 'FRA', 'observer_status': 'observed_pending'}
    tools.session.read_native_alliance_inbound_offers = lambda: [deepcopy(proposal)]
    query = deepcopy(QUERY)
    query['parameters'] = {'proposal_id': PUBLIC_ID, 'fresh_pending': True}
    return DiplomacySource(tools), tools, query


@pytest.mark.parametrize('fields', [['parameters'], ['parameters', 'proposal_status', 'currently_pending']])
def test_selected_terms_reuse_one_fresh_inspection_and_never_cache_as_original(fields):
    source, tools, query = current_source()
    query['fields'] = fields
    result = source.read(query, source.context())
    params = result['fields']['parameters']
    assert params['status'] == 'known' and params['value'] == {'peace_context': peace_context()}
    assert params['proposal_id'] == PUBLIC_ID
    assert params['basis'] == 'selected_native_inbound_peace_inspection'
    assert len(tools.inspect_calls) == 1
    assert 'proposal_parameters' not in result['fields'].get('proposal_status', {})
    plain = deepcopy(query)
    plain['parameters'].pop('fresh_pending')
    assert source.read(plain, source.context())['fields']['parameters']['status'] == 'unknown'
    assert len(tools.inspect_calls) == 1


@pytest.mark.parametrize('damage', ['binding', 'inactive', 'invalid', 'partial', 'context_role'])
def test_fresh_terms_failures_cannot_publish_parameters(damage):
    source, tools, query = current_source()
    native = tools.envelope['native_inbound_inspection']
    if damage == 'binding':
        tools.envelope['parameters']['actual']['proposal_id'] = 'b' * 32
    elif damage == 'inactive':
        native.update(pending_active=False, reason='PENDING_NOT_ACTIVE')
        tools.envelope['observed_inbound_proposal']['currently_pending'] = False
    elif damage == 'invalid':
        native['native_validity'] = False
    elif damage == 'partial':
        native['selected_terms_complete'] = False
    else:
        native['peace_context']['original_actor'] = 'POR'
    result = source.read(query, source.context())
    assert result['fields']['parameters']['status'] == 'unknown'
    assert len(tools.inspect_calls) == 1


def test_time_advance_preserves_observed_peace_terms():
    source, tools, query = current_source()
    tools.drift_after_inspect = 24
    result = source.read(query, source.context())
    field = result['fields']['parameters']
    assert field['status'] == 'known'
    assert field['observation_game_date'] == tools.envelope['native_inbound_inspection']['date_raw']
    assert len(tools.inspect_calls) == 1


def test_archived_real_full_annex_inspection_supplies_received_terms_without_new_dispatch(tmp_path):
    path = Path(__file__).parent / 'fixtures/peace_country_r61_inbound_full_annex_real.json'
    fixture = json.loads(path.read_text(encoding='utf-8'))
    event = fixture['event']
    assert ObserverSession._valid_native_inbound_inspection(
        event, event['query_id'], event['session_id'], event['actor'], event['phase'],
        event['native_proposal_id'], event['date_raw'], 'peace_offer')
    source, tools, query = current_source(event)
    database = tmp_path / 'information.sqlite3'
    saved = []
    with closing(InformationService(source, database)) as service:
        information_tools = InformationTools(service)
        for detail in ('full', 'brief'):
            report = service.manage_report('archived-report-' + detail, 'create', config={
                'name': 'archived received peace terms', 'detail': detail, 'queries': [query]})['report']
            result = information_tools.call('information_query', {
                'request_id': 'archived-query-' + detail, 'report_id': report['id']})
            full = service.get_result(result['result_id'])
            field = full['items'][0]['fields']['parameters']
            assert field['status'] == 'known'
            assert field['value']['peace_context'] == fixture['expected']['peace_context']
            assert field['value']['peace_context']['terms'] == [
                {'action_id': 'release_nation', 'country': 'FLY', 'source': 'ENG'},
                {'action_id': 'full_annexation', 'country': 'TYR', 'beneficiary': 'FRA'},
            ]
            assert present_concise(full) == result
            saved.append(full)
            encoded = json.dumps(result)
            assert 'native_proposal_id' not in encoded and 'native_proposal_pointer' not in encoded
            assert 'token3c' not in encoded and event['query_id'] not in encoded
        assert len(tools.inspect_calls) == 2
        replay = source.replay_event(query, source.context(), {
            'event_type': 'diplomatic_proposal', 'session_id': tools.session.session_id,
            'observer': 'FRA', 'payload': tools.envelope['observed_inbound_proposal']})
        assert replay['fields']['parameters']['status'] == 'unknown'
        assert len(tools.inspect_calls) == 2
    with closing(InformationService(source, database)) as reopened:
        for result in saved:
            assert reopened.get_result(result['result_id']) == result
    (tmp_path / 'archived-query-results.json').write_text(json.dumps({
        'evidence_kind': 'archived_native_event_in_memory_inspector_harness',
        'current_game_inspection': False, 'fixture': path.name, 'results': saved,
    }, ensure_ascii=False, indent=2), encoding='utf-8')
