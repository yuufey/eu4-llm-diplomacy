"""Observe A01 once, then deliver deadline reminders without another inspection."""
from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from bridge.diplomacy_journal import DurableJournal
from bridge.information import InformationService
from bridge.information import cooldown_expiry as expiry
from bridge.information.composite import CompositeSource
from bridge.information.cooldown_expiry_history import CooldownExpiryHistorySource
from bridge.information.model import canonical
from bridge.information.sources import DiplomacySource
from bridge.information.sources import _action_cooldown_field
from bridge.information.tools import InformationTools
from bridge.tests.test_information_sources import _LiveSession, _LiveTools
from bridge.tests.test_diplomacy_tools import NativeSubmissionSession
from bridge.diplomacy import DiplomacyTools

DATE = expiry.deadline_raw('1470.11.26')
END = expiry.deadline_raw('1470.11.27')


def history(obj=None, **parameters):
    return {'topic': 'H02', 'object': obj or {'type': 'session'},
            'fields': ['cooldown_expiry'], 'parameters': parameters}


def a01():
    return {'topic': 'A01', 'object': {'type': 'country_pair', 'actor': 'FRA', 'recipient': 'GEL'},
            'fields': ['cooldown'], 'parameters': {'action_id': 'ask_military_access'}}


@contextmanager
def runtime(tmp_path, *, database=None, context=None):
    session = _LiveSession()
    session.inbound = []
    backend = _LiveTools(session)
    journal = DurableJournal(tmp_path / 'diplomacy.sqlite3')
    backend.journal = journal
    primary = DiplomacySource(backend, observer='FRA')
    current = context or dict(primary.context(), game_date=DATE, game_day=DATE // 24,
                              game_date_raw=DATE, world_id='cooldown-world')
    primary.context = lambda: deepcopy(current)
    inspector = backend.inspect_diplomatic_action

    def inspection(*args):
        value = inspector(*args)
        value['native_diagnostic'] = {'text': '最近已经派遣过外交官，所以直到1470年11月27日我们才能再次派遣。'}
        return value

    backend.inspect_diplomatic_action = Mock(side_effect=inspection)
    adapter = CooldownExpiryHistorySource(primary)
    service = InformationService(CompositeSource(primary, [adapter]), database or tmp_path / 'information.sqlite3')
    adapter.history_reader = service.observed_events
    primary.cooldown_reader = service.action_cooldown_expiries
    primary.event_types = (*primary.event_types, expiry.EVENT_TYPE)
    try:
        yield service, InformationTools(service), primary, backend, current, adapter
    finally:
        service.close()
        journal.close()


def advance(context, date):
    context.update(game_date=date, game_date_raw=date, game_day=date // 24)


def subscribe(service, **filters):
    report = service.manage_report('report', 'create', config={'name': 'Contact cooldowns', 'queries': [history()]})['report']
    return service.manage_subscription('subscribe', 'create', config={
        'kind': 'event', 'report_id': report['id'], 'event': {'types': [expiry.EVENT_TYPE], **filters}})['subscription']


@pytest.mark.parametrize('text', ['1470.11.27', '1470年11月27日', '27 November 1470'])
def test_supported_date_forms_use_existing_calendar(text):
    assert expiry.deadline_raw(text) == END


def test_diplomacy_inspection_preserves_the_native_waiting_tooltip(tmp_path):
    session = NativeSubmissionSession(common_action_gate=False, native_validity=False,
        initiation_gate=False, tooltip_gate=False,
        native_diagnostic_text='最近已经派遣过外交官，所以直到1470年11月27日我们才能再次派遣。',
        native_diagnostic_text_decoded=True, diagnostic_readable=True, diagnostic_truncated=False)
    journal = DurableJournal(tmp_path / 'native-query.sqlite3')
    try:
        value = DiplomacyTools(journal, session).inspect_diplomatic_action('offer_alliance', 'FRA', 'ENG')
        assert _action_cooldown_field(value) == {
            'status': 'known', 'basis': 'native_enroute_tooltip',
            'value': {'blocked': True, 'available_on': '1470年11月27日'}}
    finally:
        journal.close()


def test_retained_real_r68_tooltip_delivers_through_normal_tools(tmp_path, record_testsuite_property):
    fixture = Path(__file__).parent / 'fixtures/r68_diplomat_real.json'
    captured = json.loads(fixture.read_text(encoding='utf-8'))
    inspection = captured['records']['peace_selected_inspection']
    with runtime(tmp_path) as (service, api, _, backend, context, _):
        context['mode'] = 'recorded'
        advance(context, inspection['session']['date_raw'])
        backend.inspect_diplomatic_action = Mock(return_value=deepcopy(inspection))
        query = {'topic': 'A01', 'object': {'type': 'country_pair', 'actor': 'FRA', 'recipient': 'BUR'},
                 'fields': ['cooldown'], 'parameters': {'action_id': 'white_peace',
                     'selection': inspection['parameters']['requested']}}
        before = api.call('information_query', {'request_id': 'r68-native-wait', 'queries': [query]})
        assert before['items'][0]['cooldown']['available_on'] == '1455年11月12日'
        subscribe(service)
        assert service.tick()['results'] == []
        advance(context, expiry.deadline_raw('1455.11.12'))
        results = service.tick()['results']
        assert len(results) == 1
        public = api.call('information_get_result', {'result_id': results[0]['result_id']})
        row = public['items'][0]['cooldown_expiry'][0]
        assert (row['actor'], row['recipient'], row['available_on']) == ('FRA', 'BUR', '1455.11.12')
        assert backend.inspect_diplomatic_action.call_count == 1
        assert service.tick()['results'] == []
        record_testsuite_property('retained_r68_cooldown_delivery', json.dumps(row, ensure_ascii=False))


@pytest.mark.parametrize('text', [None, True, '', '1470.2.29', '0.13.1', '1 November',
                                  '27 Never 1470', '1470.11.27 extra', '999999.1.1'])
def test_invalid_date_is_not_scheduled(text):
    assert expiry.deadline_raw(text) is None


def test_query_once_then_native_poll_delivers_deadline_and_c04(tmp_path):
    with runtime(tmp_path) as (service, api, primary, backend, context, adapter):
        api.call('information_query', {'request_id': 'observe', 'queries': [a01()]})
        subscribe(service, actors=['FRA'], recipients=['GEL'])
        assert service.tick()['results'] == []
        advance(context, END)
        result = service.tick()['results']
        assert len(result) == 1
        public = api.call('information_get_result', {'result_id': result[0]['result_id']})
        assert public['items'][0]['cooldown_expiry'][0]['available_on'] == '1470.11.27'
        event = result[0]['event']
        assert event['game_date'] == END
        assert expiry.valid_event_snapshot(event, context)
        assert len(backend.inspect_calls) == 1
        query = {'topic': 'C04', 'object': {'type': 'session'},
                 'fields': ['event_id', 'event_type', 'event_date', 'event_payload'],
                 'parameters': {'event_type': expiry.EVENT_TYPE}}
        projected = primary.replay_event(query, context, event)
        assert projected['complete'] and projected['game_date'] == END
        assert primary.read_event(query, context, event) == projected
        assert service.tick()['results'] == []
        stored = api.call('information_query', {'request_id': 'history', 'queries': [history()]})
        assert stored['items'][0]['cooldown_expiry'] == public['items'][0]['cooldown_expiry']
        assert len(backend.inspect_calls) == 1


def saved(context, *, end='1470.11.27', blocked=True, basis='native_enroute_tooltip', obj=None):
    return {'context': deepcopy(context), 'event': None, 'items': [{
        'query': dict(a01(), **({'object': obj} if obj is not None else {})),
        'game_date': context['game_date'], 'fields': {'cooldown': {'status': 'known',
            'basis': basis, 'value': {'blocked': blocked, 'available_on': end}}}}]}


def insert(service, value, name='sample', owner='llm'):
    with service.db:
        service.db.execute('INSERT INTO info_results VALUES(?,?,?)', (owner, name, canonical(value)))


def test_renewals_across_bounded_pages_prevent_old_expiry(tmp_path, monkeypatch):
    with runtime(tmp_path) as (service, _, _, _, context, _):
        insert(service, saved(context), 'old')
        insert(service, saved(context, end='1470.12.1'), 'renewed')
        monkeypatch.setattr(expiry, 'PAGE_SIZE', 1)
        advance(context, END)
        first = expiry.poll(service.db, 'llm', context)
        assert first['events'] == [] and not first['complete']
        second = expiry.poll(service.db, 'llm', context, first['cursor'])
        assert second['events'] == [] and second['complete']
        advance(context, expiry.deadline_raw('1470.12.1'))
        third = expiry.poll(service.db, 'llm', context, second['cursor'])
        assert len(third['events']) == 1
        assert third['events'][0]['game_date'] == context['game_date']


@pytest.mark.parametrize('change', ['owner', 'session', 'observer', 'world', 'unknown', 'event', 'late', 'unclassified'])
def test_unrelated_or_unidentified_samples_do_not_create_deadlines(tmp_path, change):
    with runtime(tmp_path) as (service, _, _, _, context, _):
        value = saved(context)
        owner = 'llm'
        if change == 'owner': owner = 'other'
        if change == 'session': value['context']['session_id'] = 'other'
        if change == 'observer': value['context']['observer'] = 'SAV'
        if change == 'world': value['context']['world_id'] = 'other'
        if change == 'unknown': value['items'][0]['fields']['cooldown']['status'] = 'unknown'
        if change == 'event': value['event'] = {'event_type': 'old_snapshot'}
        if change == 'late': value['items'][0]['game_date'] = END
        if change == 'unclassified': value['items'][0]['fields']['cooldown'].pop('basis')
        insert(service, value, owner=owner)
        advance(context, END)
        assert expiry.poll(service.db, 'llm', context)['events'] == []


def test_pending_deadline_survives_reopen_and_owner_filter(tmp_path):
    database = tmp_path / 'information.sqlite3'
    with runtime(tmp_path, database=database) as (service, api, _, backend, context, _):
        api.call('information_query', {'request_id': 'observe', 'queries': [a01()]})
        subscribe(service)
        assert service.tick()['results'] == []
        assert backend.inspect_diplomatic_action.call_count == 1
        context = deepcopy(context)
    advance(context, END + 48)
    with runtime(tmp_path, database=database, context=context) as (service, api, _, backend, _, _):
        result = service.tick()['results']
        assert len(result) == 1 and backend.inspect_diplomatic_action.call_count == 0
        row = result[0]['items'][0]['fields']['cooldown_expiry']['value'][0]
        assert row['available_on']['value'] == END
        assert service.tick()['results'] == []
        reverse = {'type': 'country_pair', 'actor': 'GEL', 'recipient': 'FRA'}
        result = api.call('information_query', {'request_id': 'reverse', 'queries': [history(reverse)]})
        assert result['items'][0]['cooldown_expiry'] == []


def test_cleared_contact_wait_cancels_future_reminder(tmp_path):
    with runtime(tmp_path) as (service, _, _, _, context, _):
        insert(service, saved(context), 'old')
        insert(service, saved(context, blocked=False, end=None, basis='native_common_action_gate_passed'), 'clear')
        advance(context, END)
        assert expiry.poll(service.db, 'llm', context)['events'] == []


def test_forward_clock_and_repeated_historical_sample_keep_one_event(tmp_path):
    with runtime(tmp_path) as (service, _, _, _, context, _):
        value = saved(context, end='1470.11.28')
        value['items'][0]['game_date'] = END
        insert(service, value, 'forward')
        advance(context, expiry.deadline_raw('1470.11.28'))
        first = expiry.poll(service.db, 'llm', context)
        assert len(first['events']) == 1
        insert(service, value, 'duplicate-old-snapshot')
        second = expiry.poll(service.db, 'llm', context, first['cursor'])
        assert second['events'] == []


def test_a01_queries_keep_known_deadlines_while_the_game_advances(tmp_path):
    with runtime(tmp_path) as (service, api, _, backend, context, _):
        original = backend.inspect_diplomatic_action.side_effect

        def forward(*args):
            value = original(*args)
            advance(context, DATE + 24)
            return value

        backend.inspect_diplomatic_action.side_effect = forward
        public = api.call('information_query', {'request_id': 'forward-read', 'queries': [a01()]})
        assert public['items'][0]['cooldown']['blocked'] is True
        sample = service.get_result(public['result_id'])['items'][0]
        assert sample['fields']['cooldown']['status'] == 'known'
        assert sample['observation_window']['end_game_date'] == DATE + 24


def test_idempotent_event_data_ignores_poll_time_and_corruption(tmp_path):
    with runtime(tmp_path) as (_, _, _, _, context, _):
        event = expiry.event_for(context, 'FRA', 'GEL', END)
        advance(context, END + 100)
        assert expiry.valid_event_snapshot(event, context)
        assert expiry.event_for(context, 'FRA', 'GEL', END) == event
        event['payload']['available_on_raw'] += 24
        assert not expiry.valid_event_snapshot(event, context)


def test_legacy_queries_use_each_existing_entry_point(tmp_path):
    with runtime(tmp_path) as (_, _, primary, _, context, adapter):
        primary.read = Mock(return_value={'old': 'read'})
        primary.read_event = Mock(return_value={'old': 'event'})
        primary.replay_event = Mock(return_value={'old': 'replay'})
        query = history(request_id='old-request')
        assert adapter.read(query, context) == {'old': 'read'}
        assert adapter.read_event(query, context, {}) == {'old': 'event'}
        assert adapter.replay_event(query, context, {}) == {'old': 'replay'}
