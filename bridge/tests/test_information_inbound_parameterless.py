"""Known empty inbound terms stay distinct from uncaptured variable terms."""
from contextlib import closing
from copy import deepcopy

import pytest

from bridge.diplomacy import DiplomacyTools
from bridge.diplomacy_journal import DurableJournal
from bridge.information import InformationService
from bridge.information.sources import DiplomacySource
from bridge import proposal_expiry as expiry
from bridge.tests.test_information_proposal_expiry import (
    SESSION, expired, offer, session,
)


PARAMETERLESS = (
    'offer_alliance', 'offer_royal_marriage', 'support_independence',
    'ask_military_access', 'offer_vassalization',
)
VARIABLE_TERMS = (
    'trade_favors_for_gold', 'trade_favors_for_trust', 'trade_favors_for_men',
    'peace_offer',
)
QUERY = {
    'topic': 'A04', 'object': {'type': 'session'},
    'fields': ['proposal_id', 'action_id', 'parameters'], 'parameters': {},
}


@pytest.mark.parametrize('action', PARAMETERLESS)
def test_known_empty_parameters_reach_live_query_and_event_snapshot(tmp_path, action):
    observed = session(tmp_path, [offer(action)])
    public = observed.read_native_inbound_offers()[0]
    assert public['parameters'] == {}
    # Safe list projection derives the empty set from its closed action
    # contract and never copies arbitrary adapter-provided parameters.
    supplied = dict(public, parameters={'private-native-token': 'untrusted'})
    safe = DiplomacyTools._safe_inbound_proposal(supplied)
    assert safe['parameters'] == {}
    assert safe['legality_status'] == 'unknown'
    assert safe['currently_pending'] is None
    source = DiplomacySource(DiplomacyTools(None, observed))
    direct = source.read(QUERY, source.context())
    assert direct['fields']['parameters'] == {'status': 'known', 'value': {}}
    event = source.poll_events(source.context(), None)['events'][0]
    replay = source.replay_event(QUERY, source.context(), event)
    assert replay['fields']['parameters'] == direct['fields']['parameters']
    assert event['payload']['legality_status'] == 'unknown'
    assert event['payload']['currently_pending'] is None


@pytest.mark.parametrize('action', VARIABLE_TERMS)
def test_variable_term_actions_do_not_gain_known_empty_parameters(tmp_path, action):
    observed = session(tmp_path, [offer(action), expired(action)])
    public = observed.read_native_inbound_offers()[0]
    assert 'parameters' not in public
    safe = DiplomacyTools._safe_inbound_proposal(dict(public, parameters={}))
    assert 'parameters' not in safe
    source = DiplomacySource(DiplomacyTools(None, observed))
    result = source.read(QUERY, source.context())
    assert result['fields']['parameters']['status'] == 'unknown'
    terminal = observed.read_native_inbound_events()[-1]['payload']
    assert terminal['gaps'] == ['ORIGINAL_PROPOSAL_TERMS_PARTIAL']
    assert terminal['complete'] is False


@pytest.mark.parametrize('action', PARAMETERLESS)
def test_expiry_retains_empty_terms_and_separate_context_limitations(tmp_path, action):
    observed = session(tmp_path, [offer(action), expired(action)])
    events = observed.read_native_inbound_events()
    initial, terminal = [event['payload'] for event in events]
    assert initial['parameters'] == {}
    assert terminal['proposal_id'] == initial['proposal_id']
    assert terminal['parameters'] == {'proposal_lifecycle': terminal['lifecycle']}
    assert terminal['gaps'] == ['ORIGINAL_PROPOSAL_LEGALITY_UNKNOWN']
    assert terminal['complete'] is False
    assert terminal['legality_status'] == 'unknown'
    assert terminal['currently_pending'] is False
    assert observed.read_native_inbound_events() == events


def test_empty_parameters_and_expiry_survive_normal_delivery_and_reopen(tmp_path):
    observed = session(tmp_path, [offer('offer_royal_marriage'), expired('offer_royal_marriage')])
    database = tmp_path / 'information.sqlite3'
    with closing(DurableJournal(tmp_path / 'journal.sqlite3', observed.experiment_id, SESSION)) as journal:
        source = DiplomacySource(DiplomacyTools(journal, observed))
        with closing(InformationService(source, database)) as service:
            report = service.manage_report('terms-report', 'create', config={
                'name': 'proposal terms', 'queries': [QUERY], 'detail': 'full',
            })['report']
            subscription = service.manage_subscription('terms-subscribe', 'create', config={
                'name': 'proposal terms', 'kind': 'event', 'report_id': report['id'],
                'enabled': True, 'event': {'types': ['diplomatic_proposal'], 'recipients': ['FRA']},
            })['subscription']
            results = service.tick()['results']
            assert len(results) == 2
            assert results[0]['items'][0]['fields']['parameters']['value'] == {}
            assert results[1]['items'][0]['source']['gaps'] == ['ORIGINAL_PROPOSAL_LEGALITY_UNKNOWN']
            assert service.tick()['results'] == []
            service.manage_subscription('terms-cancel', 'cancel', subscription_id=subscription['id'],
                                        expected_version=subscription['version'])
        with closing(InformationService(source, database)) as reopened:
            for result in results:
                assert reopened.get_result(result['result_id'])['items'] == result['items']


def test_legacy_missing_parameters_keep_their_recorded_partial_terms(tmp_path):
    observed = session(tmp_path, [offer()])
    observed.read_native_inbound_offers()
    legacy = deepcopy(observed._inbound_private_proposals)
    for record in legacy.values():
        record['public'].pop('parameters', None)
    candidate = expiry.validate_expiry(expired(), SESSION)
    result = expiry.project_expiry(candidate, legacy, SESSION)
    assert result['payload']['gaps'] == ['ORIGINAL_PROPOSAL_TERMS_PARTIAL']
