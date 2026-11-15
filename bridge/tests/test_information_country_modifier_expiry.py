"""Native-selected expiry events share the existing C04 cursor and replay."""
from contextlib import closing
from copy import deepcopy

import pytest

from bridge import country_modifier_observation as observation
from bridge.information import InformationService
from bridge.information.tools import InformationTools
from bridge.tests.test_information_country_modifier_events import (
    GAME_DATE, GAME_SHA, SESSION_ID, c04_query, make_source, native_event,
)
from bridge.tests.test_information_country_modifier_removal import removal_ack, removed


def expiry_ack(**changes):
    ack = removal_ack(version=47)
    ack.update({observation.EXPIRY_CAPABILITY: True, 'native_country_modifier_expiry_wire': 1})
    ack.update(changes)
    return ack


def expired(sequence=1, **changes):
    values = {'event': observation.EXPIRY_NATIVE_EVENT, 'source': observation.EXPIRY_SOURCE,
              'start_date_raw': GAME_DATE-48, 'end_date_raw': GAME_DATE-24}
    values.update(changes)
    return native_event(sequence, **values)


@pytest.mark.parametrize('changes', [
    {'version': 46}, {'version': 57}, {'version': 47.0},
    {observation.EXPIRY_CAPABILITY: 1}, {'native_country_modifier_expiry_wire': True},
    {'native_country_modifier_expiry_wire': 2}, {observation.REMOVE_CAPABILITY: False},
    {observation.CAPABILITY: False},
])
def test_expiry_requires_its_literal_contract_and_parents(changes):
    assert observation.supported_expiry_ack(expiry_ack(), GAME_SHA)
    assert not observation.supported_expiry_ack(expiry_ack(**changes), GAME_SHA)
    assert not observation.supported_expiry_ack(expiry_ack(), '0'*64)


def test_shared_sequence_preserves_three_change_types():
    collector = observation.Collector(SESSION_ID)
    for event in (native_event(1), removed(2), expired(3), expired(3)):
        collector.observe(event, allow_removal=True, allow_expiry=True)
    batch = collector.batch(0)
    assert batch['complete']
    assert [item['payload']['change'] for item in batch['events']] == ['added', 'removed', 'expired']
    assert len({item['event_id'] for item in batch['events']}) == 3
    assert observation.public_observation(expired(source=observation.REMOVE_SOURCE), SESSION_ID) is None
    assert observation.public_observation(expired(end_date_raw=GAME_DATE+24), SESSION_ID) is None


def test_old_v46_and_copied_caps_do_not_enable_expiry(tmp_path):
    ack = removal_ack()
    ack['caps'] = [observation.EXPIRY_CAPABILITY]
    session, journal, source = make_source(tmp_path, ack=ack, events=[expired()])
    try:
        assert observation.EXPIRY_CAPABILITY not in session.installation_capabilities()
        assert observation.EXPIRY_EVENT_TYPE not in source.event_types
        assert session.read_native_country_modifier_events()['events'] == []
        topic = next(item for item in source.catalog() if item['topic_id'] == 'C04')
        assert not topic['native_country_modifier_expiry']['capture_available']
    finally:
        journal.close()


def test_expired_subscription_and_replay_preserve_native_date(tmp_path, monkeypatch):
    session, journal, source = make_source(tmp_path, ack=expiry_ack(), events=[expired()])
    database = tmp_path/'information.sqlite3'
    query = c04_query()
    query['parameters']['event_type'] = observation.EXPIRY_EVENT_TYPE
    try:
        topic = next(item for item in source.catalog() if item['topic_id'] == 'C04')
        assert topic['native_country_modifier_expiry']['capture_available']
        assert topic['native_country_modifier_removal']['expiry_available']
        with closing(InformationService(source, database)) as service:
            tools = InformationTools(service)
            report = tools.call('information_manage_report', {
                'request_id': 'expiry-report', 'operation': 'create',
                'config': {'name': 'expiry events', 'detail': 'full', 'queries': [query]},
            })['report']
            subscription = tools.call('information_manage_subscription', {
                'request_id': 'expiry-subscription', 'operation': 'create',
                'config': {'name': 'expiry events', 'kind': 'event', 'report_id': report['id'],
                           'enabled': True, 'event': {'types': [observation.EXPIRY_EVENT_TYPE]}},
            })['subscription']
            result = tools.call('information_tick', {'view': 'full'})['results'][0]
            event = result['event']
            assert result['complete']
            assert event['payload']['change'] == 'expired'
            assert event['game_date'] == GAME_DATE
            assert event['source']['date_semantics'] == 'native_expiry_remove_return_game_date'
            assert result['items'][0]['fields']['event_type']['value'] == observation.EXPIRY_EVENT_TYPE
            assert observation.valid_event_snapshot(event, source.context())

            def forbidden_read(*args, **kwargs):
                pytest.fail('Expiry snapshot replay attempted a native read')

            monkeypatch.setattr(session, 'read_native_country_modifier_events', forbidden_read)
            monkeypatch.setattr(session, 'read_native_alliance_inbound_offers', forbidden_read)
            replay = source.replay_event(query, source.context(), event)
            assert replay['complete'] and replay['game_date'] == GAME_DATE
            for changes in ({'event_type': observation.REMOVE_EVENT_TYPE},
                            {'payload': {**event['payload'], 'change': 'removed'}},
                            {'payload': {**event['payload'], 'end_date_raw': GAME_DATE+24}},
                            {'source': {**event['source'], 'date_semantics': 'native_remove_return_game_date'}}):
                invalid = deepcopy(event)
                invalid.update(changes)
                assert not observation.valid_event_snapshot(invalid, source.context())
            tools.call('information_manage_subscription', {
                'request_id': 'expiry-cancel', 'operation': 'cancel',
                'subscription_id': subscription['id'], 'expected_version': 1,
            })
        with closing(InformationService(source, database)) as reopened:
            assert reopened.get_result(result['result_id'])['items'] == result['items']
    finally:
        journal.close()
