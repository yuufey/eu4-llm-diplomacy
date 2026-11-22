"""Normal H02 query, directional selection, C04 replay and durable subscriptions."""
from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from bridge import truce_expiry_observation as observation
from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.model import InformationError
from bridge.information.modifier_lifecycle_history import NativeModifierLifecycleHistorySource
from bridge.information.proposal_expiry_history import NativeProposalExpiryHistorySource
from bridge.information.truce_expiry_history import FIELD, NativeTruceExpiryHistorySource
from bridge.information.tools import InformationTools
from bridge.tests.test_information_country_modifier_events import make_source
from bridge.tests.test_truce_expiry_observation import END_DATE, GAME_DATE, SESSION_ID, native_ack, native_event


def query(obj=None, **parameters):
    return {'topic': 'H02', 'object': obj or {'type': 'session'}, 'fields': [FIELD], 'parameters': parameters}


def c04_query():
    return {'topic': 'C04', 'object': {'type': 'session'},
            'fields': ['event_id', 'event_type', 'event_date', 'event_payload'],
            'parameters': {'event_type': observation.EVENT_TYPE}}


@pytest.fixture
def sources(tmp_path):
    session, journal, primary = make_source(
        tmp_path, ack=native_ack(), session_id=SESSION_ID,
        events=[native_event(1), native_event(2, actor='SAV', recipient='FRA')])
    session.game_date = GAME_DATE + 48
    try:
        yield session, primary, NativeTruceExpiryHistorySource(primary)
    finally:
        journal.close()


def forbidden(*_args, **_kwargs):
    pytest.fail('Truce event/history replay attempted another primary or native read')


def test_configured_turkish_expiry_receipts_feed_c04_and_h02(tmp_path):
    from bridge import claim_expiry_observation as claim, subsidy_expiry_observation as subsidy
    from bridge.information.claim_expiry_history import NativeClaimExpiryHistorySource
    from bridge.information.subsidy_expiry_history import NativeSubsidyExpiryHistorySource
    from bridge.tests.test_claim_expiry_observation import (
        native_ack as claim_ack, native_event as claim_event, reference as claim_ref,
    )
    from bridge.tests.test_subsidy_expiry_observation import native_ack as subsidy_ack, native_event as subsidy_event

    ack = subsidy_ack() | claim_ack() | native_ack()
    ack.update(version=65, observer='TUR', native_country_control_configuration=True,
        native_country_control_protocol='EU4CONTROL1', native_country_control_ack='native_controlled_countries_set',
        native_country_control_request='controlled-countries.req', native_information_observer_configuration=True,
        native_country_modifier_scoped_schema=2, native_expiry_scoped_wire=2)
    events = []
    for event in (
        native_event(actor='TUR', recipient='SAV'),
        claim_event(claimant='TUR', owner='SAV', claimant_ref=claim_ref('TUR', 43)),
        subsidy_event(payer='TUR', recipient='SAV'),
    ):
        first, second = [value for key, value in event.items() if key.endswith('_ref') and key != 'observer_ref']
        events.append(dict(event, wire=2, observer_ref=first, session_id=SESSION_ID))
        events.append(dict(event, wire=2, observer_ref=second, session_id=SESSION_ID, sequence=2))
    session, journal, _ = make_source(tmp_path, ack=ack, session_id=SESSION_ID, observer='TUR', events=events)
    try:
        assert {module.SCOPED_CAPABILITY for module in (observation, claim, subsidy)} <= session.installation_capabilities()
        session.observed_countries = ('TUR', 'SAV')
        from bridge.diplomacy import DiplomacyTools
        from bridge.information.sources import DiplomacySource
        primary = DiplomacySource(DiplomacyTools(journal, session), observer='TUR')
        history = [NativeTruceExpiryHistorySource(primary), NativeClaimExpiryHistorySource(primary),
                   NativeSubsidyExpiryHistorySource(primary)]
        with closing(InformationService(CompositeSource(primary, history), tmp_path/'scoped.sqlite3')) as service:
            for adapter in history:
                adapter.history_reader = service.observed_events
            assert service.tick()['results'] == []
            context = primary.context()
            for module, adapter, field in zip((observation, claim, subsidy), history,
                                               ('truce_expiry', 'claim_expiry', 'subsidy_expiry')):
                event, = service.observed_events(context, event_types=[module.EVENT_TYPE])['events']
                assert event['observer'] == 'TUR' and event['payload']['scope'] == module.CONFIGURED_SCOPE
                assert event['source']['native_sequence'] == 1
                result = adapter.read(dict(query(), fields=[field]), context)
                assert result['fields'][field]['value'][0]['event_id'] == event['event_id']
                assert not module.valid_event_snapshot(event, dict(context, observer='SAV'))
    finally:
        journal.close()


def test_actual_controlled_expiry_keeps_native_date_through_shared_history(tmp_path):
    fixture_path = Path(__file__).parent / 'fixtures' / 'information_truce_expired_FRA_KLE_live_1374.json'
    fixture = json.loads(fixture_path.read_text(encoding='utf-8'))
    actual = fixture['event']
    session, journal, primary = make_source(
        tmp_path, ack=fixture['ack'], session_id=actual['session_id'],
        events=[fixture['native_event']])
    session.game_date = actual['collected_game_date']
    adapter = NativeTruceExpiryHistorySource(primary)
    try:
        with closing(InformationService(CompositeSource(primary, [adapter]),
                                        tmp_path / 'information.sqlite3')) as service:
            adapter.history_reader = service.observed_events
            assert service.tick()['results'] == []
            stored = service.observed_events(primary.context(), event_types=[observation.EVENT_TYPE])
            assert len(stored['events']) == 1
            event = stored['events'][0]
            assert event['event_id'] == actual['event_id']
            assert event['payload'] == actual['payload']
            assert event['game_date'] == actual['game_date'] == 56693256
            c04 = primary.replay_event(c04_query(), primary.context(), event)
            assert c04['complete'] and c04['fields']['event_payload']['value'] == actual['payload']
            result = InformationTools(service).call('information_query', {
                'request_id': 'actual-controlled-truce-history',
                'queries': [query({'type': 'country_pair', 'actor': 'FRA', 'recipient': 'KLE'})],
            })
            row = result['items'][0][FIELD][0]
            assert row['actor'] == 'FRA' and row['recipient'] == 'KLE'
            assert row['end_date'] == row['event_date'] == '1471.11.1'
            assert service.tick()['results'] == []
    finally:
        journal.close()


def snapshots(primary):
    return [row for row in primary.poll_events(primary.context(), None)['events']
            if row['event_type'] == observation.EVENT_TYPE]


def test_scope_or_boolean_capability_cannot_be_granted_by_caps_list(tmp_path):
    for index, ack in enumerate((native_ack(**{observation.CAPABILITY: False, 'caps': [observation.CAPABILITY]}),
                                 native_ack(version=61), native_ack(native_truce_expiry_scope='all'))):
        session, journal, primary = make_source(
            tmp_path / str(index), ack=ack, events=[native_event()], session_id=SESSION_ID)
        with closing(journal):
            assert observation.CAPABILITY not in session.installation_capabilities()
            assert observation.EVENT_TYPE not in primary.event_types
            assert session.read_native_truce_expiry_events() == {
                'events': [], 'complete': False, 'gaps': ['TRUCE_EXPIRY_SOURCE_UNAVAILABLE']}


def test_shared_poll_collects_once_and_c04_keeps_actual_occurrence_date(sources, monkeypatch):
    session, primary, _adapter = sources
    refresh = Mock(wraps=session.read_native_alliance_inbound_offers)
    monkeypatch.setattr(session, 'read_native_alliance_inbound_offers', refresh)
    context = primary.context()
    batch = primary.poll_events(context, None)
    assert batch['complete'] and not batch['gaps']
    assert len(batch['events']) == 2 and refresh.call_count == 1
    assert batch['cursor']['truce_expiry_sequence'] == 2
    assert observation.EVENT_TYPE in primary.event_types
    c04 = next(topic for topic in primary.catalog() if topic['topic_id'] == 'C04')
    assert c04['native_truce_expiry']['capture_available'] is True
    for event in batch['events']:
        assert observation.valid_event_snapshot(event, context)
        assert event['game_date'] == GAME_DATE and event['collected_game_date'] == GAME_DATE + 48
        result = primary.read_event(c04_query(), context, event)
        assert result == primary.replay_event(c04_query(), context, event)
        assert result['fields']['event_payload']['value'] == event['payload']
        assert result['game_date'] == GAME_DATE
    assert primary.poll_events(context, batch['cursor'])['events'] == [] and refresh.call_count == 2
    with pytest.raises(InformationError) as error:
        primary.poll_events(context, {'truce_expiry_sequence': True})
    assert error.value.code == 'invalid_cursor'
    primary.validate_event_filter({'types': [observation.EVENT_TYPE], 'actors': ['SAV'], 'recipients': ['FRA']})


def test_load_gate_excludes_temporary_startup_world(sources):
    session, primary, _adapter = sources
    session._macro_capture_ready = False
    session.record['ready_reason'] = 'verified_load_confirmation'
    first = primary.poll_events(primary.context(), None)
    assert first['events'] == [] and 'TRUCE_EXPIRY_STARTUP_CAPTURE_PENDING' in first['gaps']
    with (session.directory / 'control-probe.jsonl').open('a', encoding='utf-8') as stream:
        stream.write(json.dumps({'event': 'control_loaded_pause_requested'}) + '\n')
        stream.write(json.dumps(native_event(3)) + '\n')
    loaded = primary.poll_events(primary.context(), first['cursor'])
    assert loaded['complete'] and len(loaded['events']) == 1
    assert loaded['events'][0]['source']['native_sequence'] == 3


@pytest.mark.parametrize('method', ['read_event', 'replay_event'])
def test_h02_snapshot_replays_without_live_access(sources, monkeypatch, method):
    session, primary, adapter = sources
    event = snapshots(primary)[1]
    context = primary.context()
    adapter.history_reader = forbidden
    monkeypatch.setattr(primary, 'read', forbidden)
    monkeypatch.setattr(primary, 'poll_events', forbidden)
    monkeypatch.setattr(session, 'read_native_truce_expiry_events', forbidden)
    result = getattr(adapter, method)(query(), context, event)
    row = result['fields'][FIELD]['value'][0]
    assert row['actor'] == 'SAV' and row['recipient'] == 'FRA'
    assert row['end_date']['value'] == END_DATE
    assert row['event_date']['value'] == result['game_date'] == GAME_DATE
    assert result['source']['collected_game_date'] == GAME_DATE + 48 and result['complete'] is True


@pytest.mark.parametrize('obj,expected', [
    ({'type': 'session'}, 2), ({'type': 'country', 'country': 'FRA'}, 2),
    ({'type': 'country', 'country': 'SAV'}, 2), ({'type': 'country', 'country': 'ENG'}, 0),
    ({'type': 'country_pair', 'actor': 'FRA', 'recipient': 'SAV'}, 1),
    ({'type': 'country_pair', 'actor': 'SAV', 'recipient': 'FRA'}, 1),
    ({'type': 'country_pair', 'actor': 'FRA', 'recipient': 'ENG'}, 0),
])
def test_directional_history_selection_pagination_and_gaps(sources, obj, expected):
    _session, primary, adapter = sources
    events = list(reversed(snapshots(primary)))
    adapter.history_reader = Mock(return_value={
        'events': events, 'complete': False, 'gaps': ['NATIVE_GAP'], 'next_cursor': 'next-page'})
    context = primary.context()
    result = adapter.read(query(obj, limit=3, cursor='previous-page'), context)
    adapter.history_reader.assert_called_once_with(
        context, event_types=[observation.EVENT_TYPE], limit=3, cursor='previous-page')
    field = result['fields'][FIELD]
    assert len(field['value']) == expected
    assert field['status'] == 'known' and field['complete'] is False
    assert field['next_cursor'] == 'next-page' and field['gaps'] == ['NATIVE_GAP']
    if obj['type'] == 'country_pair':
        assert all(row['actor'] == obj['actor'] for row in field['value'])


@pytest.mark.parametrize('change', [
    {'event_id': 'forged'}, {'session_id': 'other-session'}, {'game_date': GAME_DATE - 1},
    {'complete': False}, {'objects': []},
])
def test_c04_and_h02_reject_invalid_persisted_snapshot(sources, change):
    _session, primary, adapter = sources
    event = dict(snapshots(primary)[0], **change)
    context = primary.context()
    assert primary.replay_event(c04_query(), context, event)['complete'] is False
    with pytest.raises(InformationError) as error:
        adapter.replay_event(query(), context, event)
    assert error.value.code == 'TRUCE_EXPIRY_SNAPSHOT_INVALID'


@pytest.mark.parametrize('parameter', ['request_id', 'case'])
@pytest.mark.parametrize('method', ['read', 'read_event', 'replay_event'])
def test_legacy_requests_keep_their_existing_entry(sources, monkeypatch, parameter, method):
    _session, primary, adapter = sources
    expected = {'fields': {FIELD: {'status': 'known', 'value': ['old-record']}}}
    delegate = Mock(return_value=expected)
    monkeypatch.setattr(primary, method, delegate)
    selector = query(**{parameter: 'legacy-record'})
    args = (selector, primary.context())
    if method != 'read':
        args += ({'event_id': 'old-event'},)
    assert getattr(adapter, method)(*args) == expected
    delegate.assert_called_once_with(*args)


def test_joint_subscription_query_cold_reopen_and_actor_filter(sources, tmp_path, monkeypatch):
    session, primary, adapter = sources
    modifiers = NativeModifierLifecycleHistorySource(primary)
    proposals = NativeProposalExpiryHistorySource(primary)
    source = CompositeSource(primary, [modifiers, proposals, adapter])
    selector = query()
    selector['fields'] = ['truce_expiry', 'modifier_lifecycle', 'proposal_expiry']
    database = tmp_path / 'information.sqlite3'
    poll = Mock(wraps=primary.poll_events)
    monkeypatch.setattr(primary, 'poll_events', poll)
    with closing(InformationService(source, database)) as service:
        for item in (adapter, modifiers, proposals):
            item.history_reader = service.observed_events
        api = InformationTools(service)
        report = api.call('information_manage_report', {
            'request_id': 'truce-expiry-report', 'operation': 'create',
            'config': {'name': 'H02 expiry', 'detail': 'full', 'queries': [selector]},
        })['report']
        api.call('information_manage_subscription', {
            'request_id': 'truce-expiry-subscription', 'operation': 'create',
            'config': {'name': 'incoming direction', 'kind': 'event', 'report_id': report['id'],
                       'enabled': True, 'event': {'types': [observation.EVENT_TYPE], 'actors': ['SAV']}},
        })
        results = api.call('information_tick', {'view': 'full'})['results']
        assert len(results) == 1 and poll.call_count == 1
        fields = results[0]['items'][0]['fields']
        assert fields['modifier_lifecycle']['value'] == [] and fields['proposal_expiry']['value'] == []
        assert len(fields[FIELD]['value']) == 1 and fields[FIELD]['value'][0]['actor'] == 'SAV'
        saved = deepcopy(results[0])
        page = api.call('information_query', {
            'request_id': 'truce-first-page', 'queries': [query(limit=1)], 'view': 'full'})
        field = page['items'][0]['fields'][FIELD]
        assert field['value'][0]['actor'] == 'SAV'
        final = api.call('information_query', {
            'request_id': 'truce-last-page', 'queries': [query(limit=1, cursor=field['next_cursor'])]})
        row = final['items'][0][FIELD][0]
        assert row['actor'] == 'FRA' and row['recipient'] == 'SAV' and isinstance(row['event_date'], str)
        assert poll.call_count == 1
        monkeypatch.setattr(session, 'read_native_truce_expiry_events', forbidden)
        assert source.replay_event(selector, primary.context(), saved['event'])['fields'][FIELD] == saved['items'][0]['fields'][FIELD]
        monkeypatch.undo()
        assert service.tick()['results'] == []
    with closing(InformationService(source, database)) as reopened:
        for item in (adapter, modifiers, proposals):
            item.history_reader = reopened.observed_events
        assert reopened.get_result(saved['result_id']) == saved
        assert len(adapter.read(query(), primary.context())['fields'][FIELD]['value']) == 2
        assert reopened.tick()['results'] == []
