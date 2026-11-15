"""Shared-cursor subsidy expiry, C04 snapshots and H02 durable history."""
from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from bridge import subsidy_expiry_observation as observation
from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.model import InformationError
from bridge.information.modifier_lifecycle_history import NativeModifierLifecycleHistorySource
from bridge.information.proposal_expiry_history import NativeProposalExpiryHistorySource
from bridge.information.subsidy_expiry_history import FIELD, NativeSubsidyExpiryHistorySource
from bridge.information.tools import InformationTools
from bridge.tests.test_information_country_modifier_events import make_source
from bridge.tests.test_subsidy_expiry_observation import GAME_DATE, SESSION_ID, native_ack, native_event


def query(obj=None, **parameters):
    return {'topic': 'H02', 'object': obj or {'type': 'session'},
            'fields': [FIELD], 'parameters': parameters}


def c04_query():
    return {'topic': 'C04', 'object': {'type': 'session'},
            'fields': ['event_id', 'event_type', 'event_date', 'event_payload'],
            'parameters': {'event_type': observation.EVENT_TYPE}}


def test_actual_monthly_expiry_keeps_native_date_through_history_and_reopen(tmp_path):
    fixture_path = Path(__file__).parent / 'fixtures' / 'information_subsidy_expired_POR_FRA_live_1374.json'
    fixture = json.loads(fixture_path.read_text(encoding='utf-8'))
    actual = fixture['event']
    session, journal, primary = make_source(
        tmp_path, ack=fixture['ack'], session_id=actual['session_id'],
        events=[fixture['native_event']])
    session.game_date = actual['collected_game_date']
    adapter = NativeSubsidyExpiryHistorySource(primary)
    source = CompositeSource(primary, [adapter])
    database = tmp_path / 'information.sqlite3'
    selector = query({'type': 'country_pair', 'actor': 'POR', 'recipient': 'FRA'})
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
            assert event['game_date'] == fixture['native_event']['date_raw'] == 56696136
            c04 = primary.replay_event(c04_query(), primary.context(), event)
            assert c04['complete'] and c04['fields']['event_payload']['value'] == actual['payload']
            result = InformationTools(service).call('information_query', {
                'request_id': 'actual-monthly-subsidy-history', 'queries': [selector]})
            row = result['items'][0][FIELD][0]
            assert row == {
                'event_id': actual['event_id'], 'event_type': observation.EVENT_TYPE,
                'payer': 'POR', 'recipient': 'FRA', 'monthly_amount': 1.0,
                'start_date': '1462.2.6', 'end_date': '1472.2.6', 'event_date': '1472.3.1',
            }
            assert service.tick()['results'] == []
        with closing(InformationService(source, database)) as reopened:
            adapter.history_reader = reopened.observed_events
            replay = InformationTools(reopened).call('information_query', {
                'request_id': 'actual-monthly-subsidy-reopen', 'queries': [selector]})
            assert replay['items'][0][FIELD] == [row]
            assert reopened.tick()['results'] == []
    finally:
        journal.close()


@pytest.fixture
def sources(tmp_path):
    session, journal, primary = make_source(
        tmp_path, ack=native_ack(), session_id=SESSION_ID,
        events=[native_event(1), native_event(2, payer='SAV', recipient='FRA')])
    session.game_date = GAME_DATE + 48
    adapter = NativeSubsidyExpiryHistorySource(primary)
    try:
        yield session, primary, adapter
    finally:
        journal.close()


def forbidden(*_args, **_kwargs):
    pytest.fail('Subsidy event/history projection attempted another primary or native read')


def snapshots(primary):
    return [row for row in primary.poll_events(primary.context(), None)['events']
            if row['event_type'] == observation.EVENT_TYPE]


def test_capability_cannot_be_granted_by_caps_list_or_older_ack(tmp_path):
    for index, ack in enumerate((native_ack(**{observation.CAPABILITY: False, 'caps': [observation.CAPABILITY]}),
                                 native_ack(version=61))):
        session, journal, primary = make_source(
            tmp_path / str(index), ack=ack, events=[native_event()], session_id=SESSION_ID)
        with closing(journal):
            assert observation.CAPABILITY not in session.installation_capabilities()
            assert observation.EVENT_TYPE not in primary.event_types
            assert session.read_native_subsidy_expiry_events() == {
                'events': [], 'complete': False, 'gaps': ['SUBSIDY_EXPIRY_SOURCE_UNAVAILABLE']}


def test_shared_primary_poll_collects_once_and_c04_preserves_event_snapshot(sources, monkeypatch):
    session, primary, _adapter = sources
    refresh = Mock(wraps=session.read_native_alliance_inbound_offers)
    monkeypatch.setattr(session, 'read_native_alliance_inbound_offers', refresh)
    context = primary.context()
    batch = primary.poll_events(context, None)
    assert batch['complete'] and not batch['gaps']
    assert len(batch['events']) == 2 and refresh.call_count == 1
    assert batch['cursor']['subsidy_expiry_sequence'] == 2
    assert observation.EVENT_TYPE in primary.event_types
    c04 = next(topic for topic in primary.catalog() if topic['topic_id'] == 'C04')
    assert c04['native_subsidy_expiry']['capture_available'] is True
    for event in batch['events']:
        assert observation.valid_event_snapshot(event, context)
        assert event['game_date'] == GAME_DATE
        assert event['collected_game_date'] == GAME_DATE + 48
        projected = primary.read_event(c04_query(), context, event)
        assert projected == primary.replay_event(c04_query(), context, event)
        assert projected['fields']['event_payload']['value'] == event['payload']
        assert projected['game_date'] == GAME_DATE
    assert primary.poll_events(context, batch['cursor'])['events'] == []
    assert refresh.call_count == 2
    with pytest.raises(InformationError) as error:
        primary.poll_events(context, {'subsidy_expiry_sequence': True})
    assert error.value.code == 'invalid_cursor'
    with pytest.raises(InformationError) as error:
        primary.validate_event_filter({'types': [observation.EVENT_TYPE], 'actors': ['FRA']})
    assert error.value.code == 'unsupported_event_filter'
    primary.validate_event_filter({'types': [observation.EVENT_TYPE], 'recipients': ['FRA']})


def test_confirmed_load_gate_skips_temporary_world_expiries(sources):
    session, primary, _adapter = sources
    session._macro_capture_ready = False
    session.record['ready_reason'] = 'verified_load_confirmation'
    first = primary.poll_events(primary.context(), None)
    assert first['events'] == []
    assert 'SUBSIDY_EXPIRY_STARTUP_CAPTURE_PENDING' in first['gaps']
    with (session.directory / 'control-probe.jsonl').open('a', encoding='utf-8') as stream:
        stream.write(json.dumps({'event': 'control_loaded_pause_requested'}) + '\n')
        stream.write(json.dumps(native_event(3)) + '\n')
    loaded = primary.poll_events(primary.context(), first['cursor'])
    assert loaded['complete'] and len(loaded['events']) == 1
    assert loaded['events'][0]['source']['native_sequence'] == 3


@pytest.mark.parametrize('method', ['read_event', 'replay_event'])
def test_h02_uses_verified_c04_without_repolling_and_keeps_actual_date(sources, monkeypatch, method):
    session, primary, adapter = sources
    events = snapshots(primary)
    context = primary.context()
    adapter.history_reader = forbidden
    monkeypatch.setattr(primary, 'read', forbidden)
    monkeypatch.setattr(primary, 'poll_events', forbidden)
    monkeypatch.setattr(session, 'read_native_subsidy_expiry_events', forbidden)
    result = getattr(adapter, method)(query(), context, events[1])
    row = result['fields'][FIELD]['value'][0]
    assert row['payer'] == 'SAV' and row['recipient'] == 'FRA'
    assert row['monthly_amount'] == {
        'status': 'known', 'value': 3750, 'raw': 3750, 'unit': 'ducats', 'scale': 1000, 'period': 'month'}
    assert row['start_date']['value'] == GAME_DATE - 8784
    assert row['end_date']['value'] == GAME_DATE - 24
    assert row['event_date']['value'] == result['game_date'] == GAME_DATE
    assert result['source']['collected_game_date'] == GAME_DATE + 48
    assert result['complete'] is True


@pytest.mark.parametrize('obj,expected', [
    ({'type': 'session'}, 2), ({'type': 'country', 'country': 'FRA'}, 2),
    ({'type': 'country', 'country': 'SAV'}, 2), ({'type': 'country', 'country': 'ENG'}, 0),
    ({'type': 'country_pair', 'actor': 'FRA', 'recipient': 'SAV'}, 2),
    ({'type': 'country_pair', 'actor': 'SAV', 'recipient': 'FRA'}, 2),
    ({'type': 'country_pair', 'actor': 'FRA', 'recipient': 'ENG'}, 0),
])
def test_history_object_selection_keeps_both_payment_directions(sources, obj, expected):
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
    assert result['game_date'] == context['game_date'] and result['complete'] is False


def test_unrelated_joint_event_and_event_filter_are_known_empty(sources):
    _session, primary, adapter = sources
    adapter.history_reader = forbidden
    event = {'event_type': 'diplomatic_proposal', 'game_date': GAME_DATE, 'event_id': 'other-event'}
    assert adapter.read_event(query(), primary.context(), event)['fields'][FIELD]['value'] == []
    field = adapter.read(query(event_type='country_modifier_added'), primary.context())['fields'][FIELD]
    assert field['value'] == [] and field['complete'] is True
    adapter.history_reader = None
    assert adapter.read(query(), primary.context())['fields'][FIELD] == {
        'status': 'unavailable', 'reason': 'EVENT_HISTORY_READER_NOT_BOUND'}


@pytest.mark.parametrize('change', [
    {'event_id': 'forged'}, {'session_id': 'other-session'}, {'game_date': GAME_DATE - 24},
    {'complete': False}, {'objects': []},
])
def test_c04_and_h02_reject_invalid_persisted_snapshot(sources, change):
    _session, primary, adapter = sources
    event = dict(snapshots(primary)[0], **change)
    context = primary.context()
    assert primary.replay_event(c04_query(), context, event)['complete'] is False
    with pytest.raises(InformationError) as error:
        adapter.replay_event(query(), context, event)
    assert error.value.code == 'SUBSIDY_EXPIRY_SNAPSHOT_INVALID'


@pytest.mark.parametrize('parameter', ['request_id', 'case'])
@pytest.mark.parametrize('method', ['read', 'read_event', 'replay_event'])
def test_legacy_request_routes_keep_existing_records(sources, monkeypatch, parameter, method):
    _session, primary, adapter = sources
    expected = {'fields': {FIELD: {'status': 'known', 'value': ['registered-old-record']}}}
    delegate = Mock(return_value=expected)
    monkeypatch.setattr(primary, method, delegate)
    selector = query(**{parameter: 'legacy-record'})
    args = (selector, primary.context())
    if method != 'read':
        args += ({'event_id': 'old-event'},)
    assert getattr(adapter, method)(*args) == expected
    delegate.assert_called_once_with(*args)


def test_normal_tools_joint_subscription_pagination_cold_reopen_and_no_duplicate_owner(
        sources, tmp_path, monkeypatch):
    session, primary, adapter = sources
    modifiers = NativeModifierLifecycleHistorySource(primary)
    proposals = NativeProposalExpiryHistorySource(primary)
    source = CompositeSource(primary, [modifiers, proposals, adapter])
    query_all = query()
    query_all['fields'] = ['subsidy_expiry', 'modifier_lifecycle', 'proposal_expiry']
    database = tmp_path / 'information.sqlite3'
    poll = Mock(wraps=primary.poll_events)
    monkeypatch.setattr(primary, 'poll_events', poll)
    with closing(InformationService(source, database)) as service:
        for item in (adapter, modifiers, proposals):
            item.history_reader = service.observed_events
        api = InformationTools(service)
        report = api.call('information_manage_report', {
            'request_id': 'subsidy-expiry-report', 'operation': 'create',
            'config': {'name': 'H02 lifecycle', 'detail': 'full', 'queries': [query_all]},
        })['report']
        api.call('information_manage_subscription', {
            'request_id': 'subsidy-expiry-subscription', 'operation': 'create',
            'config': {'name': 'subsidy expiry', 'kind': 'event', 'report_id': report['id'],
                       'enabled': True, 'event': {'types': [observation.EVENT_TYPE]}},
        })
        results = api.call('information_tick', {'view': 'full'})['results']
        assert len(results) == 2 and poll.call_count == 1
        for result in results:
            fields = result['items'][0]['fields']
            assert fields['modifier_lifecycle']['value'] == []
            assert fields['proposal_expiry']['value'] == []
            assert len(fields[FIELD]['value']) == 1
            assert result['complete'] is True
        saved = results[0]
        page = api.call('information_query', {
            'request_id': 'subsidy-history-first', 'queries': [query(limit=1)], 'view': 'full'})
        field = page['items'][0]['fields'][FIELD]
        assert field['value'][0]['payer'] == 'SAV'
        cursor = field['next_cursor']
        final = api.call('information_query', {
            'request_id': 'subsidy-history-last', 'queries': [query(limit=1, cursor=cursor)]})
        row = final['items'][0][FIELD][0]
        assert row['payer'] == 'FRA' and row['recipient'] == 'SAV'
        assert row['monthly_amount'] == 3.75
        assert 'start_date_raw' not in row and isinstance(row['event_date'], str)
        assert poll.call_count == 1
        monkeypatch.setattr(session, 'read_native_subsidy_expiry_events', forbidden)
        replayed = source.replay_event(query_all, primary.context(), saved['event'])
        assert replayed['fields'][FIELD] == saved['items'][0]['fields'][FIELD]
        monkeypatch.undo()
        assert service.tick()['results'] == []
    with closing(InformationService(source, database)) as reopened:
        for item in (adapter, modifiers, proposals):
            item.history_reader = reopened.observed_events
        assert reopened.get_result(saved['result_id']) == saved
        assert len(adapter.read(query(), primary.context())['fields'][FIELD]['value']) == 2
        assert reopened.tick()['results'] == []


@pytest.mark.parametrize('kind', ['change', 'periodic'])
def test_history_schedule_collects_new_events_without_event_subscription(tmp_path, kind, monkeypatch):
    session, journal, primary = make_source(
        tmp_path, ack=native_ack(), session_id=SESSION_ID)
    session.game_date = GAME_DATE
    adapter = NativeSubsidyExpiryHistorySource(primary)
    source = CompositeSource(primary, [adapter])
    poll = Mock(wraps=primary.poll_events)
    monkeypatch.setattr(primary, 'poll_events', poll)
    try:
        with closing(InformationService(source, tmp_path / 'information.sqlite3')) as service:
            adapter.history_reader = service.observed_events
            api = InformationTools(service)
            report = api.call('information_manage_report', {
                'request_id': 'subsidy-change-report', 'operation': 'create',
                'config': {'name': 'Subsidy history', 'detail': 'full', 'queries': [query()]},
            })['report']
            api.call('information_manage_subscription', {
                'request_id': 'subsidy-change-subscription', 'operation': 'create',
                'config': {'name': 'Subsidy history changes', 'kind': kind,
                           'report_id': report['id'], 'enabled': True,
                           'schedule': {'basis': 'game', 'every': 1, 'unit': 'days',
                                        'missed': 'coalesce'}},
            })
            session.game_date += 24
            baseline = service.tick()['results']
            assert len(baseline) == (1 if kind == 'periodic' else 0)
            assert poll.call_count == 1
            with (session.directory / 'control-probe.jsonl').open('a', encoding='utf-8') as stream:
                stream.write(json.dumps(native_event()) + '\n')
            session.game_date += 24
            results = service.tick()['results']
            assert len(results) == 1
            rows = results[0]['items'][0]['fields'][FIELD]['value']
            assert len(rows) == 1 and rows[0]['payer'] == 'FRA'
            assert poll.call_count == 2
            assert service.tick()['results'] == []
    finally:
        journal.close()


def test_background_history_collection_does_not_deliver_old_events_to_new_subscribers(tmp_path):
    _session, journal, primary = make_source(
        tmp_path, ack=native_ack(), session_id=SESSION_ID, events=[native_event()])
    adapter = NativeSubsidyExpiryHistorySource(primary)
    source = CompositeSource(primary, [adapter])
    try:
        with closing(InformationService(source, tmp_path / 'information.sqlite3')) as service:
            adapter.history_reader = service.observed_events
            api = InformationTools(service)
            assert service.tick()['results'] == []
            result = api.call('information_query', {
                'request_id': 'subsidy-history-no-subscription', 'queries': [query()], 'view': 'full'})
            assert len(result['items'][0]['fields'][FIELD]['value']) == 1
            report = api.call('information_manage_report', {
                'request_id': 'subsidy-later-report', 'operation': 'create',
                'config': {'name': 'Subsidy history', 'detail': 'full', 'queries': [query()]},
            })['report']
            api.call('information_manage_subscription', {
                'request_id': 'subsidy-later-subscription', 'operation': 'create',
                'config': {'name': 'New subsidy events', 'kind': 'event',
                           'report_id': report['id'], 'enabled': True,
                           'event': {'types': [observation.EVENT_TYPE]}},
            })
            assert service.tick()['results'] == []
    finally:
        journal.close()
