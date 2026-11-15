"""Partial root-condition observations through the normal C04 subscription path."""
from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge import mission_condition_observation as observation
from bridge import mission_observation, mission_availability_observation
from bridge.diplomacy import DiplomacyTools
from bridge.information import InformationService
from bridge.information.model import InformationError
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools
from bridge.tests.test_information_country_modifier_events import GAME_DATE, SESSION_ID, LogSession, c04_query, make_source
from bridge.tests.test_information_mission_availability_events import available
from bridge.tests.test_information_alliance_record_events import record_ack
from bridge.tests.test_information_war_declaration_events import reference


def condition_ack(**changes):
    ack = record_ack(version=56)
    ack.update({observation.CAPABILITY: True, 'native_mission_condition_wire': 1,
                'native_mission_condition_scope': observation.SCOPE})
    ack.update(changes)
    return ack


def condition(sequence=1, **changes):
    row = {'event': observation.NATIVE_EVENT, 'schema_version': 1, 'session_id': SESSION_ID,
        'sequence': sequence, 'country': 'FRA', 'country_fullref': reference('FRA', 1),
        'date_raw': GAME_DATE, 'previous_observed_date_raw': GAME_DATE-24,
        'mission_id_hex': 'french_reconquest'.encode().hex(), 'condition_index': 0,
        'condition_node': '0x200000', 'condition_method_rva': 0xbe9300,
        'satisfied_before': False, 'satisfied_after': True,
        'native_return_before': '0x100', 'native_return_after': '0x101',
        'root_condition_count': 3, 'observed_condition_count': 2,
        'source': observation.SOURCE, 'complete': False}
    row.update(changes)
    return row


def query():
    value = c04_query()
    value['parameters']['event_type'] = observation.EVENT_TYPE
    return value


def test_actual_normandy_events_merge_by_date_and_hide_native_details(tmp_path):
    directory = Path(__file__).parent / 'fixtures'
    fixture = json.loads((directory / 'information_mission_FRA_normandy_live_1374.json').read_text(encoding='utf-8'))
    ack_fixture = json.loads((directory / fixture['installation_ack_fixture']).read_text(encoding='utf-8'))
    rows = [row['event'] for row in fixture['records']]
    decoders = {module.NATIVE_EVENT: module for module in (
        observation, mission_observation, mission_availability_observation,
    )}
    expected = {}
    for row in rows:
        public = decoders[row['event']].public_observation(row, row['session_id'])
        assert public is not None
        expected[public['event_id']] = public['payload']
    session, journal, source = make_source(
        tmp_path, events=rows, session_id=rows[0]['session_id'],
        game_sha=fixture['game_sha256'], ack=ack_fixture['installation_ack'],
    )
    session.game_date = 56685192
    database = tmp_path / 'information.sqlite3'
    broad_query = c04_query()
    broad_query['parameters'] = {}
    try:
        with closing(InformationService(source, database)) as service:
            api = InformationTools(service)
            report = api.call('information_manage_report', {
                'request_id': 'normandy-events-report', 'operation': 'create',
                'config': {'name': 'Normandy events', 'detail': 'full', 'queries': [broad_query]},
            })['report']
            sub = api.call('information_manage_subscription', {
                'request_id': 'normandy-events-sub', 'operation': 'create',
                'config': {'name': 'Normandy events', 'kind': 'event', 'enabled': True,
                    'report_id': report['id'], 'event': {'types': [
                        'mission_completed', 'mission_availability_changed', 'mission_condition_changed',
                    ]}},
            })['subscription']
            results = api.call('information_tick', {'view': 'full'})['results']
            assert len(results) == len(expected) == 5
            dates = [result['event']['game_date'] for result in results]
            assert dates == sorted(dates)
            for result in results:
                event = result['event']
                assert event['payload'] == expected[event['event_id']]
                concise = api.call('information_get_result', {'result_id': result['result_id']})
                payload = concise['items'][0]['event_payload']
                assert payload['mission_id'] == 'fra_liberate_norm'
                assert not {'condition_node', 'condition_index', 'child_index', 'completion_path',
                    'native_return_before', 'native_return_after', 'previous_observed_date_raw'} & payload.keys()
                if event['event_type'] == 'mission_condition_changed':
                    assert payload['satisfied_before'] is False
                    assert payload['satisfied_after'] is True
            assert api.call('information_tick', {})['results'] == []
            api.call('information_manage_subscription', {
                'request_id': 'normandy-events-cancel', 'operation': 'cancel',
                'subscription_id': sub['id'], 'expected_version': sub['version'],
            })
        with closing(InformationService(source, database)) as reopened:
            for result in results:
                stored = reopened.get_result(result['result_id'])
                assert stored['items'] == result['items']
                assert stored['event'] == result['event']
    finally:
        journal.close()


def test_root_and_eligibility_share_log_with_independent_watermarks(tmp_path):
    session, journal, source = make_source(tmp_path, ack=condition_ack(), events=[condition(), available()])
    try:
        metadata = next(row for row in source.catalog() if row['topic_id'] == 'C04')['native_mission_condition']
        assert metadata['capture_available'] and not metadata['nested_condition_progress_covered']
        assert metadata['unvisited_conditions'] == 'unknown'
        assert metadata['max_root_conditions_per_task'] == 128 and metadata['max_tracked_tasks'] == 4096
        batch = source.poll_events(source.context(), None)
        assert batch['complete'] and len(batch['events']) == 2
        assert batch['cursor']['mission_condition_sequence'] == batch['cursor']['mission_availability_sequence'] == 1
        assert source.poll_events(source.context(), batch['cursor'])['events'] == []
        assert session._inbound_log_offset == (session.directory/'control-probe.jsonl').stat().st_size
        for value in (True, -1, '0'):
            with pytest.raises(InformationError, match='mission_condition_sequence'):
                source.poll_events(source.context(), {'mission_condition_sequence': value})
    finally:
        journal.close()


def test_partial_event_full_read_reopen_dedup_and_cancel(tmp_path, monkeypatch):
    session, journal, source = make_source(tmp_path, ack=condition_ack(), events=[condition()])
    database = tmp_path/'information.sqlite3'
    try:
        with closing(InformationService(source, database)) as service:
            api = InformationTools(service)
            report = api.call('information_manage_report', {'request_id': 'condition-report', 'operation': 'create',
                'config': {'name': 'Root condition progress', 'detail': 'full', 'queries': [query()]}})['report']
            sub = api.call('information_manage_subscription', {'request_id': 'condition-sub', 'operation': 'create',
                'config': {'name': 'Root condition progress', 'kind': 'event', 'enabled': True,
                    'report_id': report['id'], 'event': {'types': [observation.EVENT_TYPE]}}})['subscription']
            result, = api.call('information_tick', {'view': 'full'})['results']
            assert result['status'] == 'partial' and not result['complete']
            assert all(value['status'] == 'known' for value in result['items'][0]['fields'].values())
            assert api.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'}) == result
            assert api.call('information_tick', {})['results'] == []
            session.game_date += 120*24
            monkeypatch.setattr(session, 'read_native_mission_condition_events',
                lambda **kwargs: pytest.fail('event replay sampled the current task'))
            replay = source.read_event(query(), source.context(), result['event'])
            assert replay['game_date'] == GAME_DATE and not replay['complete']
            assert replay['fields']['event_payload']['value']['satisfied_after'] is True
            for mutation in ({'session_id': 'other'}, {'objects': []}, {'complete': True}):
                damaged = deepcopy(result['event'])
                damaged.update(mutation)
                rejected = source.replay_event(query(), source.context(), damaged)
                assert rejected['fields']['event_payload']['status'] == 'unavailable'
        fresh = LogSession(session.directory/'installation.json', session.game_exe)
        with closing(InformationService(DiplomacySource(DiplomacyTools(journal, fresh)), database)) as service:
            api = InformationTools(service)
            assert api.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'}) == result
            assert api.call('information_tick', {})['results'] == []
            api.call('information_manage_subscription', {'request_id': 'condition-cancel', 'operation': 'cancel',
                'subscription_id': sub['id'], 'expected_version': sub['version']})
            with (fresh.directory/'control-probe.jsonl').open('a', encoding='utf-8') as stream:
                stream.write(json.dumps(condition(2))+'\n')
            assert api.call('information_tick', {})['results'] == []
    finally:
        journal.close()


def test_condition_batch_gaps_and_native_writer_mismatch_are_retained(tmp_path):
    session, journal, source = make_source(tmp_path, ack=condition_ack(), events=[condition()])
    try:
        assert session.read_native_mission_condition_events()['complete']
        with (session.directory/'control-probe.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps({'event': observation.NATIVE_GAP, 'session_id': SESSION_ID,
                'dropped': 1, 'complete': False})+'\n')
            stream.write(json.dumps(condition(2, native_return_after='0x100'))+'\n')
        batch = session.read_native_mission_condition_events()
        assert not batch['complete'] and 'MISSION_CONDITION_CAPTURE_DROPPED' in batch['gaps']
        assert len(batch['events']) == 1
    finally:
        journal.close()


@pytest.mark.parametrize('ack_change', [{'version': 55}, {observation.CAPABILITY: False}, {'native_mission_condition_wire': 2}])
def test_unavailable_condition_capability_is_not_discovered(tmp_path, ack_change):
    session, journal, source = make_source(tmp_path, ack=condition_ack(**ack_change), events=[condition()])
    try:
        assert observation.CAPABILITY not in session.installation_capabilities()
        assert observation.EVENT_TYPE not in source.event_types
    finally:
        journal.close()
