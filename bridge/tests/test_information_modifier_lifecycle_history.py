"""H02 reuses validated C04 snapshots and the durable event ledger."""
from contextlib import closing
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from bridge import country_modifier_observation as observation
from bridge.country_control_runtime import OBSERVATION_CAPABILITY
from bridge.diplomacy import DiplomacyTools
from bridge.information.sources import DiplomacySource
from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.model import InformationError
from bridge.information.modifier_lifecycle_history import (
    EVENT_TYPES, FIELD, NativeModifierLifecycleHistorySource,
)
from bridge.information.presentation import _concise_value
from bridge.information.tools import InformationTools
from bridge.tests.test_information_country_modifier_events import (
    COLLECTED_DATE, GAME_DATE, make_source, native_event,
)
from bridge.tests.test_information_country_modifier_expiry import expired, expiry_ack
from bridge.tests.test_information_country_modifier_removal import removed


def query(*, obj=None, **parameters):
    return {'topic': 'H02', 'object': obj or {'type': 'session'},
            'fields': [FIELD], 'parameters': parameters}


@pytest.fixture
def sources(tmp_path):
    session, journal, primary = make_source(
        tmp_path, ack=expiry_ack(), events=[native_event(1), removed(2), expired(3)])
    adapter = NativeModifierLifecycleHistorySource(primary)
    try:
        yield session, primary, adapter
    finally:
        journal.close()


def snapshots(primary):
    return [event for event in primary.poll_events(primary.context(), None)['events']
            if event['event_type'] in EVENT_TYPES]


def test_configured_observers_share_a_native_stream_without_sharing_public_history(tmp_path, monkeypatch):
    def scoped(sequence, country):
        fullref = (sequence << 32) | int.from_bytes(country.encode("ascii"), "little")
        return native_event(sequence, country=country, country_fullref=hex(fullref), schema_version=2)

    session, journal, _ = make_source(tmp_path, events=[scoped(1, "ENG"), scoped(2, "TUR")])
    session.observed_countries = ("ENG", "TUR")
    monkeypatch.setattr(session, "installation_capabilities", lambda: frozenset({
        observation.CAPABILITY, OBSERVATION_CAPABILITY,
    }))
    try:
        tur = DiplomacySource(DiplomacyTools(journal, session), observer="TUR")
        eng = DiplomacySource(DiplomacyTools(journal, session), observer="ENG")
        assert observation.EVENT_TYPE in tur.event_types == eng.event_types
        tur_events = snapshots(tur)
        eng_events = snapshots(eng)
        assert [event["payload"]["country"] for event in tur_events] == ["TUR"]
        assert [event["payload"]["country"] for event in eng_events] == ["ENG"]
        adapter = NativeModifierLifecycleHistorySource(tur)
        context = tur.context()
        result = adapter.replay_event(query(), context, tur_events[0])
        assert result["fields"][FIELD]["value"][0]["country"] == "TUR"
        assert not observation.valid_event_snapshot(eng_events[0], context)
    finally:
        journal.close()


def forbidden(*_args, **_kwargs):
    pytest.fail('Modifier history attempted an ordinary or native source read')


@pytest.mark.parametrize('index', [0, 1, 2])
@pytest.mark.parametrize('object_type', ['session', 'country'])
def test_event_and_replay_project_one_validated_snapshot_without_polling(
        sources, monkeypatch, index, object_type):
    session, primary, adapter = sources
    event = snapshots(primary)[index]
    context = primary.context()
    obj = {'type': object_type}
    if object_type == 'country':
        obj['country'] = 'FRA'
    c04_replay = Mock(wraps=primary.replay_event)
    monkeypatch.setattr(primary, 'replay_event', c04_replay)
    monkeypatch.setattr(primary, 'read', forbidden)
    monkeypatch.setattr(primary, 'poll_events', forbidden)
    monkeypatch.setattr(session, 'read_native_country_modifier_events', forbidden)
    adapter.history_reader = forbidden

    result = adapter.read_event(query(obj=obj), context, event)
    replay = adapter.replay_event(query(obj=obj), context, event)

    assert replay == result
    assert result['game_date'] == event['game_date'] == GAME_DATE
    assert result['source']['collected_game_date'] == COLLECTED_DATE
    assert result['source']['projection'] == 'event_snapshot'
    assert result['source']['date_semantics'] == event['source']['date_semantics']
    assert result['complete'] is True
    field = result['fields'][FIELD]
    assert field['status'] == 'known' and field['complete'] is True
    assert len(field['value']) == 1
    row = field['value'][0]
    assert row['event_id'] == event['event_id']
    assert row['event_type'] == event['event_type']
    assert row['change'] == event['payload']['change']
    assert row['country'] == 'FRA' and row['modifier_id'] == 'test_modifier'
    assert row['event_date'] == {'status': 'known', 'value': GAME_DATE, 'unit': 'game_date_raw'}
    assert row['start_date']['value'] == event['payload']['start_date_raw']
    assert row['end_date']['value'] == event['payload']['end_date_raw']
    assert len(c04_replay.call_args_list) == 2
    assert all(call.args[0]['topic'] == 'C04' for call in c04_replay.call_args_list)


@pytest.mark.parametrize('event_type', [None, *EVENT_TYPES])
def test_query_forwards_bounded_history_parameters_and_preserves_pagination(
        sources, monkeypatch, event_type):
    session, primary, adapter = sources
    events = list(reversed(snapshots(primary)))
    selected = [event for event in events if event_type is None or event['event_type'] == event_type]
    adapter.history_reader = Mock(return_value={
        'events': selected, 'next_cursor': 'next-page', 'complete': True, 'gaps': []})
    context = primary.context()
    monkeypatch.setattr(primary, 'read', forbidden)
    monkeypatch.setattr(primary, 'poll_events', forbidden)
    monkeypatch.setattr(session, 'read_native_country_modifier_events', forbidden)
    parameters = {'limit': 7, 'cursor': 'prior-page'}
    if event_type:
        parameters['event_type'] = event_type

    result = adapter.read(query(**parameters), context)

    adapter.history_reader.assert_called_once_with(
        context, event_types=(event_type,) if event_type else EVENT_TYPES,
        limit=7, cursor='prior-page')
    assert result['game_date'] == COLLECTED_DATE
    assert result['source']['projection'] == 'persisted_event_history'
    field = result['fields'][FIELD]
    assert [row['event_id'] for row in field['value']] == [event['event_id'] for event in selected]
    assert field['next_cursor'] == 'next-page'
    assert result['complete'] is True


def test_empty_history_is_known_and_stream_gaps_preserve_available_rows(sources):
    _session, primary, adapter = sources
    context = primary.context()
    adapter.history_reader = Mock(return_value={
        'events': [], 'next_cursor': None, 'complete': True, 'gaps': []})
    empty = adapter.read(query(), context)
    assert empty['fields'][FIELD]['value'] == [] and empty['complete'] is True
    adapter.history_reader.assert_called_once_with(
        context, event_types=EVENT_TYPES, limit=50, cursor=None)

    gaps = [{'stream': 'country_modifier', 'reason': 'NATIVE_SEQUENCE_GAP'}]
    adapter.history_reader.return_value.update(
        events=snapshots(primary)[1:2], complete=False, gaps=gaps)
    partial = adapter.read(query(), context)
    assert partial['fields'][FIELD]['status'] == 'known'
    assert len(partial['fields'][FIELD]['value']) == 1
    assert partial['fields'][FIELD]['complete'] is False
    assert partial['complete'] is False and partial['source']['gaps'] == gaps


def test_missing_reader_is_explicit_and_does_not_poll(sources, monkeypatch):
    _session, primary, adapter = sources
    monkeypatch.setattr(primary, 'read', forbidden)
    monkeypatch.setattr(primary, 'poll_events', forbidden)
    field = adapter.read(query(), primary.context())['fields'][FIELD]
    assert field == {'status': 'unavailable', 'reason': 'MODIFIER_LIFECYCLE_HISTORY_READER_REQUIRED'}
    assert adapter.poll_events(primary.context(), {'previous': 9}) == {
        'events': [], 'cursor': {'previous': 9}, 'complete': True, 'gaps': []}


@pytest.mark.parametrize('changes', [
    {'session_id': 'other-session'}, {'event_id': 'forged'}, {'complete': False},
    {'payload': {'country': 'FRA', 'modifier_id': 'unvalidated'}},
])
def test_event_and_history_use_existing_c04_validation(sources, changes):
    _session, primary, adapter = sources
    event = dict(snapshots(primary)[0], **changes)
    context = primary.context()
    with pytest.raises(InformationError) as error:
        adapter.replay_event(query(), context, event)
    assert error.value.code == 'MODIFIER_LIFECYCLE_SNAPSHOT_INVALID'
    adapter.history_reader = lambda *_args, **_kwargs: {
        'events': [event], 'next_cursor': None, 'complete': True, 'gaps': []}
    with pytest.raises(InformationError) as error:
        adapter.read(query(), context)
    assert error.value.code == 'MODIFIER_LIFECYCLE_SNAPSHOT_INVALID'


@pytest.mark.parametrize('selector,reason', [
    (query(obj={'type': 'country_pair', 'actor': 'FRA', 'recipient': 'BUR'}),
     'MODIFIER_LIFECYCLE_COUNTRY_PAIR_NOT_APPLICABLE'),
    (query(obj={'type': 'country', 'country': 'BUR'}), 'MODIFIER_LIFECYCLE_COUNTRY_NOT_OBSERVED'),
    (query(event_type='diplomatic_proposal'), 'MODIFIER_LIFECYCLE_EVENT_TYPE_NOT_APPLICABLE'),
])
def test_native_history_scope_is_explicit(sources, selector, reason):
    _session, primary, adapter = sources
    event = snapshots(primary)[0]
    adapter.history_reader = forbidden
    for result in (adapter.read(selector, primary.context()),
                   adapter.read_event(selector, primary.context(), event)):
        assert result['fields'][FIELD] == {'status': 'not_applicable', 'reason': reason}


def test_different_supported_event_filter_returns_empty_without_history(sources):
    _session, primary, adapter = sources
    event = snapshots(primary)[0]
    adapter.history_reader = forbidden
    field = adapter.read_event(query(event_type=observation.REMOVE_EVENT_TYPE),
                               primary.context(), event)['fields'][FIELD]
    assert field['value'] == [] and field['complete'] is True


@pytest.mark.parametrize('parameter', ['request_id', 'case'])
@pytest.mark.parametrize('method', ['read', 'read_event', 'replay_event'])
def test_explicit_legacy_association_keeps_its_original_route(sources, monkeypatch, parameter, method):
    _session, primary, adapter = sources
    context = primary.context()
    selector = query(obj={'type': 'country_pair', 'actor': 'FRA', 'recipient': 'BUR'},
                     **{parameter: 'existing-record'})
    expected = {'fields': {FIELD: {'status': 'known', 'value': ['existing-record']}},
                'source': {'name': 'DurableJournal'}}
    delegated = Mock(return_value=expected)
    monkeypatch.setattr(primary, method, delegated)
    adapter.history_reader = forbidden
    args = (selector, context) if method == 'read' else (selector, context, {'event_id': 'old-event'})

    assert getattr(adapter, method)(*args) == expected
    delegated.assert_called_once_with(*args)


@pytest.mark.parametrize('parameters', [{'limit': 0}, {'limit': 1001}, {'cursor': ''}])
def test_history_parameters_use_shared_schema(sources, parameters):
    _session, primary, adapter = sources
    with pytest.raises(InformationError):
        adapter.validate_query(query(**parameters), primary.context())


def test_normal_tools_subscription_query_pagination_reopen_and_dedupe(sources, tmp_path, monkeypatch):
    _session, primary, adapter = sources
    source = CompositeSource(primary, [adapter])
    database = tmp_path / 'information.sqlite3'
    poll = Mock(wraps=primary.poll_events)
    monkeypatch.setattr(primary, 'poll_events', poll)
    with closing(InformationService(source, database)) as service:
        adapter.history_reader = service.observed_events
        api = InformationTools(service)
        report = api.call('information_manage_report', {
            'request_id': 'modifier-h02-report', 'operation': 'create',
            'config': {'name': 'modifier lifecycle', 'queries': [query()], 'detail': 'full'},
        })['report']
        api.call('information_manage_subscription', {
            'request_id': 'modifier-h02-subscription', 'operation': 'create',
            'config': {'name': 'modifier lifecycle', 'kind': 'event', 'report_id': report['id'],
                       'enabled': True, 'event': {'types': list(EVENT_TYPES)}},
        })
        results = api.call('information_tick', {'view': 'full'})['results']
        assert len(results) == 3 and poll.call_count == 1
        assert all(result['complete'] is True for result in results)
        assert [result['items'][0]['fields'][FIELD]['value'][0]['change']
                for result in results] == ['added', 'removed', 'expired']
        assert all(result['items'][0]['game_date'] == GAME_DATE for result in results)
        saved = results[1]
        first = api.call('information_query', {
            'request_id': 'modifier-history-page-one', 'queries': [query(limit=2)], 'view': 'full'})
        field = first['items'][0]['fields'][FIELD]
        assert [row['change'] for row in field['value']] == ['expired', 'removed']
        cursor = field['next_cursor']
        assert cursor == saved['event']['event_id'] and poll.call_count == 1
        second = api.call('information_query', {
            'request_id': 'modifier-history-page-two',
            'queries': [query(limit=2, cursor=cursor)], 'view': 'full'})
        assert [row['change'] for row in second['items'][0]['fields'][FIELD]['value']] == ['added']
        assert second['items'][0]['fields'][FIELD]['next_cursor'] is None
        filtered = api.call('information_query', {
            'request_id': 'modifier-history-filter',
            'queries': [query(event_type=observation.REMOVE_EVENT_TYPE)], 'view': 'full'})
        assert [row['change'] for row in filtered['items'][0]['fields'][FIELD]['value']] == ['removed']
        assert poll.call_count == 1
        with pytest.raises(InformationError) as error:
            adapter.read(query(cursor='unknown-cursor'), primary.context())
        assert error.value.code == 'invalid_cursor'

    with closing(InformationService(source, database)) as reopened:
        adapter.history_reader = reopened.observed_events
        assert reopened.get_result(saved['result_id']) == saved
        history = adapter.read(query(obj={'type': 'country', 'country': 'FRA'}), primary.context())
        assert [row['change'] for row in history['fields'][FIELD]['value']] == ['expired', 'removed', 'added']
        assert reopened.tick()['results'] == []


@pytest.mark.parametrize('fixture_name,change,date,end', [
    ('information_country_modifier_FRA_power_to_provinces_live_1374.json',
     'added', '1470.12.19', '1480.12.19'),
    ('information_country_modifier_FRA_papal_removed_live_1374.json',
     'removed', '1471.10.11', '1483.12.30'),
])
def test_existing_runtime_samples_project_business_rows(tmp_path, fixture_name, change, date, end):
    root = Path(__file__).parent / 'fixtures'
    evidence = json.loads((root / fixture_name).read_text(encoding='utf-8'))
    ack_evidence = evidence
    if 'installation_ack_fixture' in evidence:
        ack_evidence = json.loads((root / evidence['installation_ack_fixture']).read_text(encoding='utf-8'))
    native = evidence['event']
    session, journal, primary = make_source(
        tmp_path, events=[native], session_id=native['session_id'],
        game_sha=evidence['game_sha256'], ack=ack_evidence['installation_ack'])
    with closing(journal):
        session.game_date = native['date_raw'] + 24
        adapter = NativeModifierLifecycleHistorySource(primary)
        event = snapshots(primary)[0]
        projected = adapter.replay_event(query(), primary.context(), event)
        row = _concise_value(projected['fields'][FIELD])[0]
        assert evidence['evidence_kind'] == 'observed_runtime'
        assert row == {
            'country': 'FRA', 'modifier_id': native['modifier_id'], 'change': change,
            'event_id': event['event_id'], 'event_type': event['event_type'],
            'event_date': date, 'start_date': None, 'end_date': end,
        }
        assert projected['game_date'] == native['date_raw']
