"""Selected Support Independence roles and legacy installation compatibility."""
from contextlib import closing
from copy import deepcopy

import pytest

from bridge import support_roles
from bridge.diplomacy import ObserverSession
from bridge.information import InformationService
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools
from bridge.information.presentation import present_result
from bridge.tests.test_information_inbound_current import ACTIVE_FIXTURE, PUBLIC_ID, _fixture_event
from bridge.tests.test_information_inbound_favor_parameters import FavorTools


def role_event(actor_subject=True, recipient_subject=False):
    event = deepcopy(_fixture_event(ACTIVE_FIXTURE))
    event.update(action_id='support_independence', family='support_independence', extra60=0,
                 support_independence_before=False, native_current_support_independence=False,
                 native_current_support_independence_readable=True, support_roles_readable=True,
                 support_actor_is_subject=actor_subject, support_recipient_is_subject=recipient_subject)
    return event


def support_source(event=None, capable=True):
    event = role_event() if event is None else event
    tools = FavorTools(event)
    tools.session.installation_capabilities = lambda: (
        frozenset([support_roles.CAPABILITY]) if capable else frozenset())
    proposal = {'proposal_id': PUBLIC_ID, 'action_id': 'support_independence',
                'actor': event['actor'], 'recipient': 'FRA', 'observer_status': 'observed_pending',
                'parameters': {}}
    tools.session.read_native_alliance_inbound_offers = lambda: [deepcopy(proposal)]
    query = {'topic': 'A04', 'object': {'type': 'session'},
             'fields': ['parameters', 'currently_pending', 'response_consequences'],
             'parameters': {'proposal_id': PUBLIC_ID, 'fresh_pending': True}}
    return DiplomacySource(tools), tools, query, proposal


@pytest.mark.parametrize('actor_subject', [True, False])
def test_both_support_directions_reach_the_normal_query(actor_subject):
    event = role_event(actor_subject, not actor_subject)
    assert ObserverSession._valid_native_inbound_inspection(
        event, event['query_id'], event['session_id'], event['actor'], event['phase'],
        event['native_proposal_id'], event['date_raw'], event['action_id'])
    source, tools, query, _proposal = support_source(event)
    fields = source.read(query, source.context())['fields']
    field = fields['response_consequences']
    assert field['status'] == 'known' and field['complete'] is False and field['derived'] is True
    accepted = field['value']['accept']['changes'][0]
    assert accepted['supporter'] == ('FRA' if actor_subject else event['actor'])
    assert accepted['supported_country'] == (event['actor'] if actor_subject else 'FRA')
    assert accepted['before'] is False and accepted['after'] is True
    assert field['value']['reject']['changes'][0]['after'] is False
    assert field['response_executed'] is False and field['response_authority'] is False
    assert fields['parameters']['value'] == {} and fields['currently_pending']['value'] is True
    assert len(tools.inspect_calls) == 1


@pytest.mark.parametrize('damage', ['missing', 'unreadable', 'both_subject', 'both_independent',
                                   'integer_bool', 'wrong_party', 'extra_private', 'wrong_supporter'])
def test_unproven_roles_leave_other_proposal_information_available(damage):
    event = role_event()
    if damage == 'missing':
        for key in support_roles.FIELDS:
            event.pop(key)
    elif damage == 'unreadable':
        event['support_roles_readable'] = False
    elif damage == 'both_subject':
        event['support_recipient_is_subject'] = True
    elif damage == 'both_independent':
        event['support_actor_is_subject'] = False
    elif damage == 'integer_bool':
        event['support_actor_is_subject'] = 1
    source, tools, query, _proposal = support_source(event)
    roles = tools.envelope['native_inbound_inspection'].get('support_roles')
    if damage == 'wrong_party':
        roles['actor'] = 'POR'
    elif damage == 'extra_private':
        roles['address'] = 'private'
    elif damage == 'wrong_supporter':
        roles['supporter'] = event['actor']
    fields = source.read(query, source.context())['fields']
    assert fields['response_consequences']['status'] == 'unknown'
    assert fields['parameters']['value'] == {} and fields['currently_pending']['value'] is True
    assert len(tools.inspect_calls) == 1


def test_legacy_event_retains_its_public_shape():
    event = role_event()
    for key in support_roles.FIELDS:
        event.pop(key)
    public = ObserverSession._public_native_inbound_inspection(event, event['date_raw'], event['action_id'])
    assert 'support_roles' not in public


def test_legacy_installation_skips_role_only_inspection_and_advertises_its_limit():
    source, tools, query, _proposal = support_source(capable=False)
    query['fields'] = ['response_consequences']
    field = source.read(query, source.context())['fields']['response_consequences']
    assert field == {'status': 'unknown', 'reason': 'NATIVE_SUPPORT_ROLE_CONTEXT_UNAVAILABLE'}
    assert tools.inspect_calls == []
    topic = next(item for item in source.catalog() if item['topic_id'] == 'A04')
    assert 'support_independence' not in topic['fields']['response_consequences']['supported_actions']
    assert topic['fields']['response_consequences']['support_role_context_available'] is False


@pytest.mark.parametrize('detail', ['full', 'brief'])
def test_role_consequences_persist_and_event_replay_avoids_current_inspection(detail, tmp_path):
    source, tools, query, proposal = support_source()
    database = tmp_path / 'information.sqlite3'
    with closing(InformationService(source, database)) as service:
        report = service.manage_report('support-role-report', 'create', config={
            'name': 'Support Independence commitment', 'detail': detail, 'queries': [query]})['report']
        result = present_result(InformationTools(service).call('information_query', {
            "view": "full",
            'request_id': 'support-role-query', 'report_id': report['id']}))
        assert result['items'][0]['fields']['response_consequences']['status'] == 'known'
        full = service.get_result(result['result_id'])
        assert (present_result(full) if detail == 'brief' else full) == result
        replay = source.replay_event(query, source.context(), {
            'event_type': 'diplomatic_proposal', 'observer': 'FRA',
            'session_id': tools.session.session_id, 'payload': proposal})
        assert replay['fields']['response_consequences']['status'] == 'unknown'
        assert len(tools.inspect_calls) == 1
    with closing(InformationService(source, database)) as reopened:
        assert reopened.get_result(full['result_id']) == full


@pytest.mark.parametrize('bad_tag', [None, '', 'fra', 'FR', 'FRAX', 123])
def test_roles_require_bound_country_tags(bad_tag):
    assert support_roles.project_roles(role_event(), bad_tag, 'FRA')['status'] == 'unknown'


@pytest.mark.parametrize('ack_value', [True, False, 1, 'true', None])
@pytest.mark.parametrize('game_sha', [support_roles.GAME_SHA256, '0' * 64])
def test_capability_requires_literal_ack_and_matching_game(ack_value, game_sha):
    session = object.__new__(ObserverSession)
    session.record = {'game_sha256': game_sha}
    session._installation_ack = lambda: {
        'caps': [support_roles.CAPABILITY], support_roles.CAPABILITY: ack_value,
        'native_inbound_alliance': True, 'native_support_independence_query': True,
        'native_inbound_support_independence_response': True,
    }
    capabilities = session.installation_capabilities()
    assert (support_roles.CAPABILITY in capabilities) == (
        ack_value is True and game_sha == support_roles.GAME_SHA256)


@pytest.mark.parametrize('missing', ['native_support_independence_query',
                                   'native_inbound_support_independence_response'])
def test_role_capability_requires_both_existing_adapters(missing):
    session = object.__new__(ObserverSession)
    session.record = {'game_sha256': support_roles.GAME_SHA256}
    ack = {support_roles.CAPABILITY: True, 'native_inbound_alliance': True,
           'native_support_independence_query': True,
           'native_inbound_support_independence_response': True}
    ack.pop(missing)
    session._installation_ack = lambda: ack
    assert support_roles.CAPABILITY not in session.installation_capabilities()
