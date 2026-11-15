"""Wire-2 alliance-record observations delivered through public C04 APIs."""
from contextlib import closing
from copy import deepcopy

import pytest

from bridge import mission_availability_observation as availability
from bridge import mission_observation as mission
from bridge import relation_observation as relation_observation
from bridge.diplomacy import DiplomacyTools
from bridge.information import InformationService
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools
from bridge.tests.test_information_country_modifier_events import (
    GAME_DATE, GAME_SHA, SESSION_ID, LogSession, c04_query, make_source,
)
from bridge.tests.test_information_mission_availability_events import available
from bridge.tests.test_information_mission_set_events import inserted, set_ack
from bridge.tests.test_information_relation_events import relation


def record_ack(**changes):
    ack = set_ack()
    ack.update({
        'version': 54,
        relation_observation.CAPABILITY: True,
        relation_observation.RECORD_CAPABILITY: True,
        'native_relation_change_wire': 2,
        'native_relation_change_scope': relation_observation.RECORD_SCOPE,
    })
    ack.update(changes)
    return ack


def relation_record(sequence, path, *, before=False, after=True, **changes):
    event = relation(sequence, before=before, after=after, actor='FRA', recipient='CAS')
    event.update({
        'schema_version': 2,
        'source': relation_observation.RECORD_SOURCE,
        'observation_path': path,
        'command_state': 2 if path == 'command_return' else None,
        'command_mode': 1 if path == 'command_return' else None,
    })
    event.update(changes)
    return event


def relation_query():
    query = c04_query()
    query['parameters']['event_type'] = relation_observation.EVENT_TYPE
    return query


def legacy_snapshot(native):
    public = relation_observation.public_observation(native, SESSION_ID)
    assert public is not None
    return {
        'event_id': public['event_id'],
        'event_type': relation_observation.EVENT_TYPE,
        'session_id': SESSION_ID,
        'observer': 'FRA',
        'game_date': public['game_date'],
        'objects': deepcopy(public['objects']),
        'payload': deepcopy(public['payload']),
        'complete': True,
        'source': {
            'name': 'ObserverSession.read_native_relation_events', 'mode': 'live',
            'session_id': SESSION_ID, 'native_sequence': public['native_sequence'],
            'complete': True, 'scope': relation_observation.SCOPE,
            'date_semantics': relation_observation.DATE_SEMANTICS,
        },
    }


def test_v54_v55_v56_ack_requires_record_contract_and_keeps_mission_set_and_availability():
    ack = record_ack()
    assert relation_observation.supported_record_ack(ack, GAME_SHA)
    assert mission.supported_set_ack(ack, GAME_SHA)
    assert availability.supported_ack(ack, GAME_SHA)
    ack55 = record_ack(version=55)
    assert relation_observation.supported_record_ack(ack55, GAME_SHA)
    assert mission.supported_set_ack(ack55, GAME_SHA)
    assert availability.supported_ack(ack55, GAME_SHA)
    for changes in (
        {'version': 57},
        {relation_observation.RECORD_CAPABILITY: False},
        {'native_relation_change_wire': True},
        {'native_relation_change_wire': 1},
        {'native_relation_change_scope': relation_observation.SCOPE},
    ):
        assert not relation_observation.supported_record_ack(record_ack(**changes), GAME_SHA)
    assert not relation_observation.supported_record_ack(
        record_ack(**{relation_observation.RECORD_CAPABILITY: None}), GAME_SHA)


def test_alliance_record_paths_reach_c04_and_old_snapshots_replay(tmp_path, monkeypatch):
    ack = record_ack()
    native_rows = [
        relation_record(1, 'command_return', before=False, after=True),
        relation_record(2, 'alliance_record_enable', before=False, after=True),
        relation_record(3, 'alliance_record_disable', before=True, after=False),
        inserted(1),
        available(1),
    ]
    session, journal, source = make_source(tmp_path, ack=ack, events=native_rows)
    database = tmp_path / 'information.sqlite3'
    try:
        capabilities = session.installation_capabilities()
        assert relation_observation.RECORD_CAPABILITY in capabilities
        assert mission.SET_CAPABILITY in capabilities
        assert availability.CAPABILITY in capabilities
        metadata = next(row for row in source.catalog() if row['topic_id'] == 'C04')['native_relation_change']
        assert metadata['scope'] == relation_observation.RECORD_SCOPE
        assert metadata['alliance_record_writes_covered']

        batch = source.poll_events(source.context(), None)
        assert batch['complete'] and len(batch['events']) == 5
        assert batch['cursor']['relation_sequence'] == 3
        assert batch['cursor']['mission_sequence'] == 1
        assert batch['cursor']['mission_availability_sequence'] == 1
        observed = [row for row in batch['events'] if row['event_type'] == relation_observation.EVENT_TYPE]
        assert len(observed) == 3
        assert [row['payload']['observation_path'] for row in observed] == [
            'command_return', 'alliance_record_enable', 'alliance_record_disable']
        assert [row['payload']['before']['active'] for row in observed] == [False, False, True]
        assert [row['payload']['after']['active'] for row in observed] == [True, True, False]
        assert (observed[0]['payload']['command_state'], observed[0]['payload']['command_mode']) == (2, 1)
        assert all(row['payload']['command_state'] is None and row['payload']['command_mode'] is None
                   for row in observed[1:])
        for row in observed:
            assert row['payload']['scope'] == relation_observation.RECORD_SCOPE
            assert row['source']['scope'] == relation_observation.RECORD_SCOPE
            assert row['source']['date_semantics'] == relation_observation.RECORD_DATE_SEMANTICS
        assert source.poll_events(source.context(), batch['cursor'])['events'] == []

        with closing(InformationService(source, database)) as service:
            api = InformationTools(service)
            report = api.call('information_manage_report', {
                'request_id': 'record-report', 'operation': 'create',
                'config': {'name': 'Alliance record observations', 'detail': 'full',
                           'queries': [relation_query()]},
            })['report']
            subscription = api.call('information_manage_subscription', {
                'request_id': 'record-subscription', 'operation': 'create',
                'config': {'name': 'Alliance record observations', 'kind': 'event', 'enabled': True,
                           'report_id': report['id'],
                           'event': {'types': [relation_observation.EVENT_TYPE]}},
            })['subscription']
            results = api.call('information_tick', {'view': 'full'})['results']
            assert len(results) == 3 and all(row['complete'] for row in results)
            assert api.call('information_tick', {})['results'] == []
            for result in results:
                event = result['event']
                assert event['payload']['scope'] == relation_observation.RECORD_SCOPE
                assert event['source']['scope'] == relation_observation.RECORD_SCOPE
                assert event['source']['date_semantics'] == relation_observation.RECORD_DATE_SEMANTICS
                assert api.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})['items'] == result['items']
                frozen = source.read_event(relation_query(), source.context(), event)
                assert frozen['complete'] and frozen['game_date'] == event['game_date']
                assert frozen['fields']['event_payload']['value'] == event['payload']

            session.game_date += 120 * 24
            monkeypatch.setattr(session, 'read_native_relation_events',
                                lambda **kwargs: pytest.fail('snapshot replay reread native events'))
            for result in results:
                replay = source.replay_event(relation_query(), source.context(), result['event'])
                assert replay['complete'] and replay['game_date'] == result['event']['game_date']
                assert replay['fields']['event_payload']['value'] == result['event']['payload']

            archived = legacy_snapshot(relation(9))
            old_replay = source.replay_event(relation_query(), source.context(), archived)
            assert old_replay['complete'] and old_replay['game_date'] == GAME_DATE
            assert old_replay['fields']['event_payload']['value']['scope'] == relation_observation.SCOPE

        fresh_session = LogSession(session.directory / 'installation.json', session.game_exe)
        fresh_source = DiplomacySource(DiplomacyTools(journal, fresh_session))
        with closing(InformationService(fresh_source, database)) as service:
            api = InformationTools(service)
            assert api.call('information_tick', {})['results'] == []
            for result in results:
                assert api.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})['items'] == result['items']
            api.call('information_manage_subscription', {
                'request_id': 'record-subscription-cancel', 'operation': 'cancel',
                'subscription_id': subscription['id'], 'expected_version': subscription['version'],
            })
    finally:
        journal.close()


def test_v54_session_rejects_wire1_and_mixed_native_rows(tmp_path):
    valid = relation_record(1, 'alliance_record_enable')
    wrong_wire = relation(1)
    mixed = relation_record(1, 'alliance_record_disable', before=True, after=False,
                            source=relation_observation.SOURCE)
    session, journal, source = make_source(tmp_path, ack=record_ack(), events=[wrong_wire, mixed, valid])
    try:
        batch = session.read_native_relation_events()
        assert not batch['complete']
        assert batch['gaps'] == ['RELATION_OBSERVATION_INVALID']
        assert len(batch['events']) == 1
        assert batch['events'][0]['payload']['observation_path'] == 'alliance_record_enable'
        assert batch['events'][0]['payload']['scope'] == relation_observation.RECORD_SCOPE
    finally:
        journal.close()
