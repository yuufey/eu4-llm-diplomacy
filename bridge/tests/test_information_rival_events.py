"""Normal C04 delivery, shared log ownership and durable rival snapshots."""
from contextlib import closing
from copy import deepcopy
import json

import pytest

from bridge import rival_observation as observation
from bridge.information import InformationService
from bridge.information.model import InformationError
from bridge.information.tools import InformationTools
from bridge.tests.test_information_country_modifier_events import (
    GAME_DATE, GAME_SHA, SESSION_ID, c04_query, make_source, native_event,
)
from bridge.tests.test_information_country_modifier_expiry import expiry_ack, expired


def rival_ack(**changes):
    ack = expiry_ack(version=48)
    ack.update({observation.CAPABILITY: True, 'native_rival_change_wire': 1,
                'native_rival_change_scope': observation.SCOPE})
    ack.update(changes)
    return ack


def state(count, target=False, old=False):
    return {'count': count, 'target_active': target, 'target_since_date_raw': GAME_DATE if target else -1,
            'old_active': old, 'old_since_date_raw': GAME_DATE-24 if old else -1}


def rival(sequence=1, **changes):
    event = {'event': observation.NATIVE_EVENT, 'schema_version': 1, 'session_id': SESSION_ID,
        'sequence': sequence, 'country': 'FRA', 'actor': 'ENG', 'target': 'FRA', 'old_rival': '---',
        'actor_fullref': '0x100474e45', 'target_fullref': '0x200415246', 'old_rival_fullref': '0x0',
        'operation': 'set', 'date_raw': GAME_DATE, 'before': state(0), 'after': state(1, True),
        'source': observation.SOURCE, 'complete': True}
    event.update(changes)
    return event


def query():
    value = c04_query()
    value['parameters']['event_type'] = observation.EVENT_TYPE
    return value


def test_capability_registration_and_shared_cursor_keep_modifier_and_rival_sequences_independent(tmp_path):
    rows = [native_event(1), rival(1), expired(2)]
    session, journal, source = make_source(tmp_path, ack=rival_ack(), events=rows)
    try:
        assert observation.CAPABILITY in session.installation_capabilities()
        assert observation.EVENT_TYPE in source.event_types
        topic = next(item for item in source.catalog() if item['topic_id'] == 'C04')
        assert topic['native_rival_change']['capture_available']
        assert not topic['native_rival_change']['direct_country_writes_covered']
        batch = source.poll_events(source.context(), None)
        assert [item['event_type'] for item in batch['events']] == [
            'country_modifier_added', 'country_modifier_expired', observation.EVENT_TYPE]
        assert batch['cursor']['country_modifier_sequence'] == 2
        assert batch['cursor']['rival_sequence'] == 1
        assert batch['complete']
        assert source.poll_events(source.context(), batch['cursor'])['events'] == []
        assert session.read_native_rival_events(refresh=False)['events'][0]['payload']['recipient'] == 'FRA'
        assert len(session.read_native_country_modifier_events(refresh=False)['events']) == 2
        log = session.directory/'control-probe.jsonl'
        assert session._inbound_log_offset == log.stat().st_size
        for invalid in (True, -1, '0'):
            with pytest.raises(InformationError, match='rival_sequence'):
                source.poll_events(source.context(), {'rival_sequence': invalid})
    finally:
        journal.close()


@pytest.mark.parametrize('changes,observer', [
    ({'version': 47}, 'FRA'), ({observation.CAPABILITY: False}, 'FRA'),
    ({'native_rival_change_wire': True}, 'FRA'), ({}, 'POR'),
])
def test_unproven_or_other_observer_source_is_not_registered(tmp_path, changes, observer):
    session, journal, source = make_source(tmp_path, ack=rival_ack(**changes), events=[rival()], observer=observer)
    try:
        assert observation.EVENT_TYPE not in source.event_types
        if observer == 'FRA':
            assert session.read_native_rival_events()['gaps'] == ['RIVAL_SOURCE_UNAVAILABLE']
    finally:
        journal.close()


def test_c04_subscriptions_role_filter_dedup_and_persistent_replay(tmp_path, monkeypatch):
    replaced = rival(2, target='BUR', target_fullref='0x300525542', old_rival='FRA',
        old_rival_fullref='0x200415246', operation='replace', before=state(1, False, True), after=state(1, True, False))
    session, journal, source = make_source(tmp_path, ack=rival_ack(), events=[rival(), replaced])
    database = tmp_path/'information.sqlite3'
    try:
        with closing(InformationService(source, database)) as service:
            api = InformationTools(service)
            report = api.call('information_manage_report', {'request_id': 'rival-report', 'operation': 'create',
                'config': {'name': 'Rival changes', 'detail': 'full', 'queries': [query()]}})['report']
            subscriptions = []
            for name, filters in (('all', {}), ('target-fra', {'actors': ['ENG'], 'recipients': ['FRA']})):
                subscriptions.append(api.call('information_manage_subscription', {
                    'request_id': 'rival-sub-'+name, 'operation': 'create',
                    'config': {'name': name, 'kind': 'event', 'enabled': True, 'report_id': report['id'],
                               'event': {'types': [observation.EVENT_TYPE], **filters}}})['subscription'])
            results = api.call('information_tick', {'view': 'full'})['results']
            assert len(results) == 3
            assert all(result['complete'] for result in results)
            assert sorted(result['event']['payload']['recipient'] for result in results) == ['BUR', 'FRA', 'FRA']
            assert len({result['event']['event_id'] for result in results}) == 2
            assert all(result['event']['game_date'] == GAME_DATE for result in results)
            assert all(result['items'][0]['source']['projection'] == 'event_snapshot' for result in results)
            assert api.call('information_tick', {})['results'] == []
            result = results[0]
            assert api.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})['items'] == result['items']
            for subscription in subscriptions:
                api.call('information_manage_subscription', {
                    'request_id': 'cancel-'+subscription['id'], 'operation': 'cancel',
                    'subscription_id': subscription['id'], 'expected_version': subscription['version']})

        def forbidden(*args, **kwargs):
            pytest.fail('Historical rival replay tried to read current native state')

        monkeypatch.setattr(session, 'read_native_rival_events', forbidden)
        monkeypatch.setattr(session, 'read_native_alliance_inbound_offers', forbidden)
        for result in results:
            event = result['event']
            projected = source.replay_event(query(), source.context(), event)
            assert projected['complete'] and projected['game_date'] == GAME_DATE
            assert projected['fields']['event_payload']['value'] == event['payload']
        with closing(InformationService(source, database)) as reopened:
            for result in results:
                assert reopened.get_result(result['result_id'])['items'] == result['items']
    finally:
        journal.close()


def test_invalid_snapshot_and_event_query_selector_fail_without_native_read(tmp_path, monkeypatch):
    session, journal, source = make_source(tmp_path, ack=rival_ack(), events=[rival()])
    try:
        event = source.poll_events(source.context(), None)['events'][0]
        monkeypatch.setattr(session, 'read_native_rival_events', lambda **kwargs: pytest.fail('live read'))
        for changes in ({'session_id': 'another'}, {'observer': 'POR'},
                        {'objects': [{'type': 'country', 'country': 'FRA'}]},
                        {'payload': {**event['payload'], 'after': deepcopy(event['payload']['before'])}},
                        {'source': {**event['source'], 'date_semantics': 'collected_date'}}):
            invalid = deepcopy(event)
            invalid.update(changes)
            assert not source.replay_event(query(), source.context(), invalid)['complete']
        other = query()
        other['parameters']['event_type'] = 'country_modifier_added'
        assert not source.replay_event(other, source.context(), event)['complete']
    finally:
        journal.close()


def test_shared_log_partial_line_reset_invalid_json_and_health_gaps(tmp_path):
    session, journal, source = make_source(tmp_path, ack=rival_ack())
    try:
        log = session.directory/'control-probe.jsonl'
        session.read_native_rival_events()
        encoded = json.dumps(rival()).encode()
        with log.open('ab') as stream:
            stream.write(encoded[:40])
        assert not session.read_native_rival_events()['events']
        with log.open('ab') as stream:
            stream.write(encoded[40:]+b'\n')
        assert len(session.read_native_rival_events()['events']) == 1
        with log.open('ab') as stream:
            stream.write(b'invalid json\n')
        assert 'RIVAL_LOG_INVALID_JSON' in session.read_native_rival_events()['gaps']
        log.write_text(json.dumps(rival_ack())+'\n', encoding='utf-8')
        assert 'RIVAL_LOG_RESET' in session.read_native_rival_events()['gaps']
    finally:
        journal.close()
