"""Selected pending-state polling with recorded proofs and modeled transitions."""
from contextlib import closing

import pytest

from bridge.information import InformationError, InformationService
from bridge.information.battles import BattleInformationSource
from bridge.information.composite import CompositeSource
from bridge.information.tools import InformationTools
from bridge.tests.test_information_inbound_current import (
    ACTIVE_FIXTURE, INACTIVE_FIXTURE, PUBLIC_ID, _fixture_event, _source, _query,
)
from bridge.tests.test_information_service import FakeClock, subscription_config


def pending_query(**kwargs):
    return _query(fields=('currently_pending',), **kwargs)


def test_pending_catalog_exposes_guarded_partial_change_scope():
    source, backend = _source(_fixture_event(ACTIVE_FIXTURE))
    topic = next(item for item in source.catalog() if item['topic_id'] == 'A04')
    assert topic['fields']['currently_pending']['coverage'] == 'partial'
    assert topic['fields']['currently_pending']['unit'] == 'boolean'
    assert topic['fields']['currently_pending']['supported_observers'] == ['FRA']
    assert topic['change_scope']['fields'] == ['currently_pending']
    assert topic['change_scope']['required_parameters'] == {'fresh_pending': True}
    assert set(topic['triggers']) >= {'query', 'periodic', 'change'}
    assert backend.inspect_calls == []


def test_documented_session_selector_can_watch_an_explicit_proposal(tmp_path):
    source, backend = _source(_fixture_event(ACTIVE_FIXTURE))
    query = pending_query()
    query['object'] = {'type': 'session'}
    with closing(InformationService(source, tmp_path / 'information.sqlite3', clock=FakeClock())) as service:
        report = service.manage_report('session-report', 'create', config={
            'name': 'session selected pending state', 'detail': 'brief', 'queries': [query],
        })['report']
        service.manage_subscription('session-change', 'create',
            config=subscription_config(report['id'], kind='change'))
        result = InformationTools(service).call('information_query', {
            'request_id': 'session-pending-query', 'report_id': report['id'], 'view': 'full',
        })
        assert result['items'][0]['fields']['currently_pending']['value'] is True
    assert len(backend.inspect_calls) == 1


def advance_date(tools):
    # Advance the modeled clock while preserving the original historical fixture.
    tools.session.current_date += 24
    tools.envelope['session']['date_raw'] = tools.session.current_date
    tools.envelope['native_inbound_inspection']['date_raw'] = tools.session.current_date


def make_inactive(tools):
    # Model a transition for the active fixture while retaining the independent
    # proposal and session identities of the original historical records.
    tools.envelope['native_inbound_inspection'].update(
        pending_active=False, reason='PENDING_NOT_ACTIVE',
        decision_country_verified=False, native_validity=False)
    tools.envelope['observed_inbound_proposal']['currently_pending'] = False
    tools.envelope['decision_country_verified'] = False


def create_change(tools):
    report = tools.call('information_manage_report', {
        'request_id': 'pending-report', 'operation': 'create', 'config': {
            'name': 'selected pending state', 'detail': 'brief', 'queries': [pending_query()],
        },
    })['report']
    subscription = tools.call('information_manage_subscription', {
        'request_id': 'pending-subscription', 'operation': 'create',
        'config': subscription_config(report['id'], kind='change', every=5),
    })['subscription']
    return report, subscription


@pytest.mark.parametrize('fixture,pending', [(ACTIVE_FIXTURE, True), (INACTIVE_FIXTURE, False)])
def test_boolean_projection_reuses_one_validated_inspection(fixture, pending):
    event = _fixture_event(fixture)
    source, backend = _source(event)
    query = _query(fields=('proposal_status', 'currently_pending'), actor=event['actor'])
    result = source.read(query, source.context())
    field = result['fields']['currently_pending']
    assert field['status'] == 'known' and field['value'] is pending
    assert field['partial'] is True and field['complete'] is False
    assert field['proposal_id'] == PUBLIC_ID
    assert len(backend.inspect_calls) == 1
    assert result['source']['provenance']['response_executed'] is False


def test_default_boolean_remains_unknown_without_fresh_inspection(monkeypatch):
    source, backend = _source(_fixture_event(ACTIVE_FIXTURE))
    observed = backend.session.read_native_alliance_inbound_offers()[0]
    observed['currently_pending'] = True
    monkeypatch.setattr(backend.session, 'read_native_alliance_inbound_offers', lambda: [observed])
    result = source.read(pending_query(parameters={}), source.context())
    assert result['fields']['currently_pending']['status'] == 'unknown'
    assert 'value' not in result['fields']['currently_pending']
    assert backend.inspect_calls == []


def test_boolean_is_unavailable_in_captured_event_without_inspection():
    source, backend = _source(_fixture_event(ACTIVE_FIXTURE))
    context = source.context()
    event = {'event_type': 'diplomatic_proposal', 'event_id': 'inbound-fixture',
             'session_id': context['session_id'], 'observer': 'FRA',
             'payload': backend.session.read_native_alliance_inbound_offers()[0]}
    event['payload']['currently_pending'] = True
    result = source.replay_event(pending_query(), context, event)
    assert result['fields']['currently_pending']['status'] == 'unknown'
    assert result['fields']['currently_pending']['reason'] == 'CURRENT_PENDING_NOT_IN_EVENT_SNAPSHOT'
    assert backend.inspect_calls == []


def test_clock_and_capture_metadata_do_not_change_the_pending_comparison():
    source, backend = _source(_fixture_event(ACTIVE_FIXTURE))
    query = pending_query()
    context = source.context()
    first = source.read(query, context)
    comparison = source.change_comparison(query, first, context)
    assert comparison is not None
    advance_date(backend)
    later_context = source.context()
    second = source.read(query, later_context)
    assert first['source']['provenance'] != second['source']['provenance']
    assert first['fields'] == second['fields']
    assert source.change_comparison(query, second, later_context) == comparison


@pytest.mark.parametrize('damage', ['unknown', 'integer', 'wrong_id', 'wrong_proof', 'executed', 'missing_proof'])
def test_change_admission_rejects_incomplete_or_mismatched_proof(damage):
    source, _backend = _source(_fixture_event(ACTIVE_FIXTURE))
    query, context = pending_query(), source.context()
    sample = source.read(query, context)
    field = sample['fields']['currently_pending']
    provenance = sample['source']['provenance']
    if damage == 'unknown':
        field.update(status='unknown')
    elif damage == 'integer':
        field['value'] = 1
    elif damage == 'wrong_id':
        field['proposal_id'] = 'b' * 32
    elif damage == 'wrong_proof':
        provenance['native_status_proof']['pending_active'] = False
    elif damage == 'executed':
        provenance['response_executed'] = True
    else:
        provenance.pop('native_status_proof')
    assert source.change_comparison(query, sample, context) is None


@pytest.mark.parametrize('query', [pending_query(parameters={}), _query()])
def test_change_configuration_requires_selected_fresh_boolean(tmp_path, query):
    source, backend = _source(_fixture_event(ACTIVE_FIXTURE))
    with closing(InformationService(source, tmp_path / 'information.sqlite3')) as service:
        report = service.manage_report('bad-report', 'create', config={
            'name': 'invalid change scope', 'detail': 'brief', 'queries': [query],
        })['report']
        with pytest.raises(InformationError) as raised:
            service.manage_subscription('bad-change', 'create',
                config=subscription_config(report['id'], kind='change'))
        assert raised.value.code == 'unsupported_trigger'
    assert backend.inspect_calls == []


@pytest.mark.parametrize('wrapper', ['direct', 'composite'])
def test_pending_changes_notify_once_and_failed_reads_preserve_baseline(tmp_path, wrapper):
    source, backend = _source(_fixture_event(ACTIVE_FIXTURE))
    if wrapper == 'composite':
        source = CompositeSource(source)
    clock = FakeClock()
    with closing(InformationService(source, tmp_path / 'information.sqlite3', clock=clock)) as service:
        tools = InformationTools(service)
        _report, subscription = create_change(tools)
        clock.advance(5)
        assert tools.call('information_tick', {})['results'] == []
        baseline = service.status(subscription['id'])['subscriptions'][0]['runtime']['baseline']

        advance_date(backend)
        clock.advance(5)
        assert tools.call('information_tick', {})['results'] == []

        proof = backend.envelope.pop('native_inbound_inspection')
        clock.advance(5)
        assert tools.call('information_tick', {})['results'] == []
        runtime = service.status(subscription['id'])['subscriptions'][0]['runtime']
        assert runtime['baseline'] == baseline
        assert runtime['last_attempt']['status'] == 'read_failed_baseline_preserved'

        backend.envelope['native_inbound_inspection'] = proof
        make_inactive(backend)
        clock.advance(5)
        delivered = tools.call('information_tick', {'view': 'full'})['results']
        assert len(delivered) == 1 and delivered[0]['trigger'] == 'change'
        assert delivered[0]['items'][0]['fields']['currently_pending']['value'] is False
        assert delivered[0]['event'] is None
        assert delivered[0]['complete'] is False
        clock.advance(5)
        assert tools.call('information_tick', {})['results'] == []
        assert len(backend.inspect_calls) == 5
        tools.call('information_manage_subscription', {
            'request_id': 'pending-cancel', 'operation': 'cancel',
            'subscription_id': subscription['id'], 'expected_version': subscription['version'],
        })
        clock.advance(5)
        assert tools.call('information_tick', {})['results'] == []
        assert len(backend.inspect_calls) == 5


def test_battle_wrapper_forwards_the_selected_pending_comparison():
    source, _backend = _source(_fixture_event(ACTIVE_FIXTURE))
    query, context = pending_query(), source.context()
    sample = source.read(query, context)
    wrapper = BattleInformationSource.__new__(BattleInformationSource)
    wrapper.reads = CompositeSource(source)
    assert wrapper.change_comparison(query, sample, context) == source.change_comparison(query, sample, context)


def test_report_update_cannot_remove_required_freshness_from_active_change(tmp_path):
    source, backend = _source(_fixture_event(ACTIVE_FIXTURE))
    with closing(InformationService(source, tmp_path / 'information.sqlite3')) as service:
        tools = InformationTools(service)
        report, _subscription = create_change(tools)
        config = {'name': report['name'], 'detail': 'brief',
                  'queries': [pending_query(parameters={})]}
        with pytest.raises(InformationError) as raised:
            tools.call('information_manage_report', {
                'request_id': 'remove-freshness', 'operation': 'update', 'report_id': report['id'],
                'expected_version': report['version'], 'config': config,
            })
        assert raised.value.code == 'unsupported_trigger'
        saved = tools.call('information_manage_report', {
            'request_id': 'get-unchanged-report', 'operation': 'get', 'report_id': report['id'],
        })['report']
        assert saved == report
    assert backend.inspect_calls == []
