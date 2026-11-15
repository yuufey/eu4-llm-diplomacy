"""Removal wire admission, shared sequence and persisted C04 delivery."""
from contextlib import closing
from copy import deepcopy

import pytest

from bridge import country_modifier_observation as observation
from bridge.information import InformationService
from bridge.information.model import InformationError
from bridge.information.tools import InformationTools
from bridge.tests.test_information_country_modifier_events import (
    COLLECTED_DATE, GAME_DATE, GAME_SHA, SESSION_ID, c04_query,
    make_source, native_ack, native_event,
)


def removal_ack(**changes):
    ack = native_ack(version=46)
    ack.update({observation.REMOVE_CAPABILITY: True, 'native_country_modifier_remove_wire': 1})
    ack.update(changes)
    return ack


def removed(sequence=1, **changes):
    fields = {'event': observation.REMOVE_NATIVE_EVENT, 'source': observation.REMOVE_SOURCE}
    fields.update(changes)
    return native_event(sequence, **fields)


@pytest.mark.parametrize('changes', [
    {'version': 45}, {'version': 57}, {'version': 46.0},
    {observation.REMOVE_CAPABILITY: 1}, {observation.REMOVE_CAPABILITY: False},
    {'native_country_modifier_remove_wire': True}, {'native_country_modifier_remove_wire': 2},
    {observation.CAPABILITY: False}, {'native_country_modifier_scope': 'all_country_modifiers'},
])
def test_removal_requires_its_literal_capability(changes):
    assert observation.supported_remove_ack(removal_ack(), GAME_SHA)
    assert not observation.supported_remove_ack(removal_ack(**changes), GAME_SHA)
    assert not observation.supported_remove_ack(removal_ack(), '0' * 64)


def test_shared_collector_orders_add_remove_add_and_deduplicates():
    collector = observation.Collector(SESSION_ID)
    for event in (native_event(1), removed(2), native_event(3), removed(2)):
        collector.observe(event, allow_removal=True)
    batch = collector.batch(0)
    assert batch['complete']
    assert [item['native_sequence'] for item in batch['events']] == [1, 2, 3]
    assert [item['payload']['change'] for item in batch['events']] == ['added', 'removed', 'added']
    assert len({item['event_id'] for item in batch['events']}) == 3
    assert len(collector.batch(1)['events']) == 2
    assert observation.public_observation(removed(source=observation.SOURCE), SESSION_ID) is None


def test_old_ack_and_caps_list_do_not_grant_removal(tmp_path):
    ack = native_ack()
    ack['caps'] = [observation.REMOVE_CAPABILITY]
    session, journal, source = make_source(tmp_path, ack=ack, events=[removed()])
    try:
        assert observation.REMOVE_CAPABILITY not in session.installation_capabilities()
        assert observation.REMOVE_EVENT_TYPE not in source.event_types
        assert session.read_native_country_modifier_events()['events'] == []
        topic = next(row for row in source.catalog() if row['topic_id'] == 'C04')
        assert not topic['native_country_modifier_removal']['capture_available']
    finally:
        journal.close()


def test_removed_source_uses_shared_cursor_and_actual_event_date(tmp_path):
    session, journal, source = make_source(tmp_path, ack=removal_ack(),
                                         events=[native_event(1), removed(2), native_event(3)])
    try:
        assert observation.REMOVE_EVENT_TYPE in source.event_types
        batch = source.poll_events(source.context(), None)
        events = [item for item in batch['events'] if item['event_type'] in observation.EVENT_SEMANTICS]
        assert [item['source']['native_sequence'] for item in events] == [1, 2, 3]
        event = events[1]
        assert event['event_type'] == observation.REMOVE_EVENT_TYPE
        assert event['game_date'] == GAME_DATE
        assert event['collected_game_date'] == COLLECTED_DATE
        assert event['payload']['change'] == 'removed'
        assert event['source']['date_semantics'] == 'native_remove_return_game_date'
        assert observation.valid_event_snapshot(event, source.context())
        assert batch['cursor']['country_modifier_sequence'] == 3
        assert source.poll_events(source.context(), batch['cursor'])['events'] == []
        topic = next(row for row in source.catalog() if row['topic_id'] == 'C04')
        assert topic['native_country_modifier_removal']['capture_available']
        assert topic['native_country_modifier_removal']['expiry_available'] is False
    finally:
        journal.close()


@pytest.mark.parametrize('role', ['actors', 'recipients'])
def test_removed_filters_reject_unproven_roles(tmp_path, role):
    _, journal, source = make_source(tmp_path, ack=removal_ack())
    try:
        with pytest.raises(InformationError) as error:
            source.validate_event_filter({'types': [observation.REMOVE_EVENT_TYPE], role: ['FRA']})
        assert error.value.code == 'unsupported_event_filter'
    finally:
        journal.close()


def test_removed_c04_subscription_persists_and_replays_without_native_reads(tmp_path, monkeypatch):
    session, journal, source = make_source(tmp_path, ack=removal_ack(), events=[removed()])
    database = tmp_path / 'information.sqlite3'
    query = c04_query()
    query['parameters']['event_type'] = observation.REMOVE_EVENT_TYPE
    try:
        with closing(InformationService(source, database)) as service:
            tools = InformationTools(service)
            report = tools.call('information_manage_report', {
                'request_id': 'removed-report', 'operation': 'create',
                'config': {'name': 'modifier changes', 'queries': [query], 'detail': 'full'},
            })['report']
            subscription = tools.call('information_manage_subscription', {
                'request_id': 'removed-subscription', 'operation': 'create',
                'config': {'name': 'modifier removals', 'kind': 'event', 'report_id': report['id'],
                           'enabled': True, 'event': {'types': [observation.REMOVE_EVENT_TYPE]}},
            })['subscription']
            result = tools.call('information_tick', {'view': 'full'})['results'][0]
            assert result['complete'] is True
            assert result['items'][0]['fields']['event_payload']['value']['change'] == 'removed'
            assert result['items'][0]['game_date'] == GAME_DATE
            event = result['event']

            def forbidden_read(*args, **kwargs):
                pytest.fail('Removal snapshot replay attempted a native read')

            monkeypatch.setattr(session, 'read_native_country_modifier_events', forbidden_read)
            monkeypatch.setattr(session, 'read_native_alliance_inbound_offers', forbidden_read)
            replay = source.replay_event(query, source.context(), event)
            assert replay['complete'] and replay['game_date'] == GAME_DATE
            for changes in (
                {'event_type': 'country_modifier_expired'}, {'event_type': []},
                {'source': {**event['source'], 'date_semantics': 'native_insert_return_game_date'}},
                {'payload': {**event['payload'], 'change': 'expired'}},
                {'session_id': 'other-session'}, {'event_id': 'wrong-id'},
            ):
                invalid = deepcopy(event)
                invalid.update(changes)
                assert not observation.valid_event_snapshot(invalid, source.context())
            tools.call('information_manage_subscription', {
                'request_id': 'removed-cancel', 'operation': 'cancel',
                'subscription_id': subscription['id'], 'expected_version': 1,
            })
        with closing(InformationService(source, database)) as reopened:
            assert reopened.get_result(result['result_id'])['items'] == result['items']
    finally:
        journal.close()
