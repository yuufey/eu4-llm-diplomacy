"""Normal H02 claim history, C04 snapshots and durable joint subscriptions."""
from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from bridge import claim_expiry_observation as observation
from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.model import InformationError
from bridge.information.claim_expiry_history import FIELD, NativeClaimExpiryHistorySource
from bridge.information.modifier_lifecycle_history import NativeModifierLifecycleHistorySource
from bridge.information.proposal_expiry_history import NativeProposalExpiryHistorySource
from bridge.information.subsidy_expiry_history import NativeSubsidyExpiryHistorySource
from bridge.information.truce_expiry_history import NativeTruceExpiryHistorySource
from bridge.information.tools import InformationTools
from bridge.tests.test_information_country_modifier_events import make_source
from bridge.tests.test_claim_expiry_observation import GAME_DATE, SESSION_ID, native_ack, native_event, snapshot


def query(obj=None, **parameters):
    return {'topic': 'H02', 'object': obj or {'type': 'session'}, 'fields': [FIELD], 'parameters': parameters}


def c04_query():
    return {'topic': 'C04', 'object': {'type': 'session'},
            'fields': ['event_id', 'event_type', 'event_date', 'event_payload'],
            'parameters': {'event_type': observation.EVENT_TYPE}}


def test_actual_controlled_expiry_keeps_native_identity_through_history_and_reopen(tmp_path):
    fixture_path = Path(__file__).parent / 'fixtures' / 'information_claim_expired_BRI_FRA_4386_live_1374.json'
    fixture = json.loads(fixture_path.read_text(encoding='utf-8'))
    actual = fixture['event']
    session, journal, primary = make_source(
        tmp_path, ack=fixture['ack'], session_id=actual['session_id'],
        events=[fixture['native_event']])
    session.game_date = actual['collected_game_date']
    adapter = NativeClaimExpiryHistorySource(primary)
    source = CompositeSource(primary, [adapter])
    database = tmp_path / 'information.sqlite3'
    selector = query({'type': 'country_pair', 'actor': 'BRI', 'recipient': 'FRA'})
    try:
        with closing(InformationService(source, database)) as service:
            adapter.history_reader = service.observed_events
            assert service.tick()['results'] == []
            stored = service.observed_events(primary.context(), event_types=[observation.EVENT_TYPE])
            assert stored['complete'] is True and stored['gaps'] == []
            assert len(stored['events']) == 1
            event = stored['events'][0]
            assert event['event_id'] == actual['event_id']
            assert event['payload'] == actual['payload']
            assert event['game_date'] == fixture['native_event']['date_raw'] == 56694720
            c04 = primary.replay_event(c04_query(), primary.context(), event)
            assert c04['complete'] and c04['fields']['event_payload']['value'] == actual['payload']
            result = InformationTools(service).call('information_query', {
                'request_id': 'actual-controlled-claim-history', 'queries': [selector]})
            row = result['items'][0][FIELD][0]
            assert row == {'event_id': actual['event_id'], 'event_type': observation.EVENT_TYPE,
                           'claimant': 'BRI', 'owner': 'FRA', 'province_id': 4386,
                           'event_date': '1472.1.1'}
            assert service.tick()['results'] == []
        with closing(InformationService(source, database)) as reopened:
            adapter.history_reader = reopened.observed_events
            replay = InformationTools(reopened).call('information_query', {
                'request_id': 'actual-controlled-claim-reopen', 'queries': [selector]})
            assert replay['items'][0][FIELD] == [row]
            assert reopened.tick()['results'] == []
    finally:
        journal.close()


@pytest.fixture
def sources(tmp_path):
    session, journal, primary = make_source(
        tmp_path, ack=native_ack(), session_id=SESSION_ID,
        events=[native_event(1), native_event(2, claimant='SAV', owner='FRA')])
    session.game_date = GAME_DATE + 48
    try:
        yield session, primary, NativeClaimExpiryHistorySource(primary)
    finally:
        journal.close()


def forbidden(*_args, **_kwargs):
    pytest.fail('Claim event/history replay attempted another primary or native read')


def snapshots(primary):
    return [row for row in primary.poll_events(primary.context(), None)['events']
            if row['event_type'] == observation.EVENT_TYPE]


def test_capability_requires_exact_ack_scope_and_boolean(tmp_path):
    for index, ack in enumerate((native_ack(**{observation.CAPABILITY: False, 'caps': [observation.CAPABILITY]}),
                                 native_ack(version=62), native_ack(native_claim_expiry_scope='all'))):
        session, journal, primary = make_source(
            tmp_path / str(index), ack=ack, events=[native_event()], session_id=SESSION_ID)
        with closing(journal):
            assert observation.CAPABILITY not in session.installation_capabilities()
            assert observation.EVENT_TYPE not in primary.event_types
            assert session.read_native_claim_expiry_events() == {
                'events': [], 'complete': False, 'gaps': ['CLAIM_EXPIRY_SOURCE_UNAVAILABLE']}


def test_shared_poll_c04_actual_date_and_action_role_filters(sources, monkeypatch):
    session, primary, _adapter = sources
    refresh = Mock(wraps=session.read_native_alliance_inbound_offers)
    monkeypatch.setattr(session, 'read_native_alliance_inbound_offers', refresh)
    context = primary.context()
    batch = primary.poll_events(context, None)
    assert batch['complete'] and not batch['gaps']
    assert len(batch['events']) == 2 and refresh.call_count == 1
    assert batch['cursor']['claim_expiry_sequence'] == 2
    assert observation.EVENT_TYPE in primary.event_types
    c04 = next(topic for topic in primary.catalog() if topic['topic_id'] == 'C04')
    assert c04['native_claim_expiry']['capture_available'] is True
    for event in batch['events']:
        assert observation.valid_event_snapshot(event, context)
        assert event['game_date'] == GAME_DATE and event['collected_game_date'] == GAME_DATE + 48
        result = primary.read_event(c04_query(), context, event)
        assert result == primary.replay_event(c04_query(), context, event)
        assert result['fields']['event_payload']['value'] == event['payload']
        assert result['game_date'] == GAME_DATE
    assert primary.poll_events(context, batch['cursor'])['events'] == [] and refresh.call_count == 2
    with pytest.raises(InformationError) as error:
        primary.poll_events(context, {'claim_expiry_sequence': True})
    assert error.value.code == 'invalid_cursor'
    for key in ('actors', 'recipients'):
        with pytest.raises(InformationError) as error:
            primary.validate_event_filter({'types': [observation.EVENT_TYPE], key: ['FRA']})
        assert error.value.code == 'unsupported_event_filter'


def test_load_gate_excludes_temporary_startup_world(sources):
    session, primary, _adapter = sources
    session._macro_capture_ready = False
    session.record['ready_reason'] = 'verified_load_confirmation'
    first = primary.poll_events(primary.context(), None)
    assert first['events'] == [] and 'CLAIM_EXPIRY_STARTUP_CAPTURE_PENDING' in first['gaps']
    with (session.directory / 'control-probe.jsonl').open('a', encoding='utf-8') as stream:
        stream.write(json.dumps({'event': 'control_loaded_pause_requested'}) + '\n')
        stream.write(json.dumps(native_event(3)) + '\n')
    loaded = primary.poll_events(primary.context(), first['cursor'])
    assert loaded['complete'] and len(loaded['events']) == 1
    assert loaded['events'][0]['source']['native_sequence'] == 3


@pytest.mark.parametrize('method', ['read_event', 'replay_event'])
def test_h02_snapshot_replay_keeps_business_summary_without_live_access(sources, monkeypatch, method):
    session, primary, adapter = sources
    event = snapshots(primary)[1]
    context = primary.context()
    adapter.history_reader = forbidden
    monkeypatch.setattr(primary, 'read', forbidden)
    monkeypatch.setattr(primary, 'poll_events', forbidden)
    monkeypatch.setattr(session, 'read_native_claim_expiry_events', forbidden)
    result = getattr(adapter, method)(query(), context, event)
    row = result['fields'][FIELD]['value'][0]
    assert row == {'event_id': event['event_id'], 'event_type': observation.EVENT_TYPE,
                   'claimant': 'SAV', 'owner': 'FRA', 'province_id': 186,
                   'event_date': {'status': 'known', 'value': GAME_DATE, 'unit': 'game_date_raw'}}
    assert result['game_date'] == GAME_DATE
    assert result['source']['collected_game_date'] == GAME_DATE + 48 and result['complete'] is True


@pytest.mark.parametrize('owner', ['FRA', '---'])
def test_h02_preserves_same_owner_and_unowned_province(sources, owner):
    _session, primary, adapter = sources
    result = adapter.read_event(query(), primary.context(), snapshot(native_event(owner=owner)))
    assert result['complete'] is True
    assert result['fields'][FIELD]['value'][0]['owner'] == ('FRA' if owner == 'FRA' else None)


@pytest.mark.parametrize('obj,expected', [
    ({'type': 'session'}, 2), ({'type': 'country', 'country': 'FRA'}, 2),
    ({'type': 'country', 'country': 'SAV'}, 2), ({'type': 'country', 'country': 'ENG'}, 0),
    ({'type': 'country_pair', 'actor': 'FRA', 'recipient': 'SAV'}, 1),
    ({'type': 'country_pair', 'actor': 'SAV', 'recipient': 'FRA'}, 1),
    ({'type': 'country_pair', 'actor': 'FRA', 'recipient': 'ENG'}, 0),
])
def test_claimant_to_owner_history_selection_pagination_and_gaps(sources, obj, expected):
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
        assert all(row['claimant'] == obj['actor'] for row in field['value'])


@pytest.mark.parametrize('change', [
    {'event_id': 'forged'}, {'session_id': 'other-session'}, {'game_date': -1},
    {'complete': False}, {'objects': []},
])
def test_c04_and_h02_reject_invalid_persisted_snapshot(sources, change):
    _session, primary, adapter = sources
    event = dict(snapshots(primary)[0], **change)
    context = primary.context()
    assert primary.replay_event(c04_query(), context, event)['complete'] is False
    with pytest.raises(InformationError) as error:
        adapter.replay_event(query(), context, event)
    assert error.value.code == 'CLAIM_EXPIRY_SNAPSHOT_INVALID'


@pytest.mark.parametrize('parameter', ['request_id', 'case'])
@pytest.mark.parametrize('method', ['read', 'read_event', 'replay_event'])
def test_legacy_request_routes_keep_existing_records(sources, monkeypatch, parameter, method):
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


def test_joint_h02_subscription_query_cold_reopen_and_deduplication(sources, tmp_path, monkeypatch):
    session, primary, adapter = sources
    histories = [NativeModifierLifecycleHistorySource(primary), NativeProposalExpiryHistorySource(primary),
                 NativeSubsidyExpiryHistorySource(primary), NativeTruceExpiryHistorySource(primary), adapter]
    source = CompositeSource(primary, histories)
    selector = query()
    selector['fields'] = ['claim_expiry', 'truce_expiry', 'subsidy_expiry', 'modifier_lifecycle', 'proposal_expiry']
    database = tmp_path / 'information.sqlite3'
    poll = Mock(wraps=primary.poll_events)
    monkeypatch.setattr(primary, 'poll_events', poll)
    with closing(InformationService(source, database)) as service:
        for item in histories:
            item.history_reader = service.observed_events
        api = InformationTools(service)
        report = api.call('information_manage_report', {
            'request_id': 'claim-expiry-report', 'operation': 'create',
            'config': {'name': 'H02 lifecycle', 'detail': 'full', 'queries': [selector]},
        })['report']
        api.call('information_manage_subscription', {
            'request_id': 'claim-expiry-subscription', 'operation': 'create',
            'config': {'name': 'claim expiry', 'kind': 'event', 'report_id': report['id'],
                       'enabled': True, 'event': {'types': [observation.EVENT_TYPE]}},
        })
        results = api.call('information_tick', {'view': 'full'})['results']
        assert len(results) == 2 and poll.call_count == 1
        for result in results:
            fields = result['items'][0]['fields']
            assert len(fields[FIELD]['value']) == 1
            assert all(fields[name]['value'] == [] for name in selector['fields'] if name != FIELD)
            assert result['complete'] is True
        saved = deepcopy(results[0])
        page = api.call('information_query', {
            'request_id': 'claim-first-page', 'queries': [query(limit=1)], 'view': 'full'})
        field = page['items'][0]['fields'][FIELD]
        assert field['value'][0]['claimant'] == 'SAV'
        final = api.call('information_query', {
            'request_id': 'claim-last-page', 'queries': [query(limit=1, cursor=field['next_cursor'])]})
        row = final['items'][0][FIELD][0]
        assert row['claimant'] == 'FRA' and row['owner'] == 'SAV' and row['province_id'] == 186
        assert isinstance(row['event_date'], str) and poll.call_count == 1
        monkeypatch.setattr(session, 'read_native_claim_expiry_events', forbidden)
        assert source.replay_event(selector, primary.context(), saved['event'])['fields'][FIELD] == saved['items'][0]['fields'][FIELD]
        monkeypatch.undo()
        assert service.tick()['results'] == []
    with closing(InformationService(source, database)) as reopened:
        for item in histories:
            item.history_reader = reopened.observed_events
        assert reopened.get_result(saved['result_id']) == saved
        assert len(adapter.read(query(), primary.context())['fields'][FIELD]['value']) == 2
        assert reopened.tick()['results'] == []
