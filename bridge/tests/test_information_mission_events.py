"""Native mission completion values through the normal shared C04 APIs."""
from contextlib import closing
from copy import deepcopy
import json

import pytest

from bridge import mission_observation as observation
from bridge.diplomacy import DiplomacyTools
from bridge.information import InformationService
from bridge.information.model import InformationError
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools
from bridge.tests.test_information_country_modifier_events import (
    GAME_DATE, GAME_SHA, SESSION_ID, LogSession, c04_query, make_source, native_event,
)
from bridge.tests.test_information_war_declaration_events import declaration, reference
from bridge.tests.test_information_rival_events import rival
from bridge.tests.test_information_relation_events import relation, relation_ack


def mission_ack(**changes):
    ack = relation_ack(version=51)
    ack.update({observation.CAPABILITY: True, 'native_mission_completion_wire': 1,
                'native_mission_completion_scope': observation.SCOPE})
    ack.update(changes)
    return ack


def completed(sequence=1, name='french_reconquest', **changes):
    event = {'event': observation.NATIVE_EVENT, 'schema_version': 1, 'session_id': SESSION_ID,
        'sequence': sequence, 'country': 'FRA', 'country_fullref': reference('FRA', 1),
        'date_raw': GAME_DATE, 'mission_id_hex': name.encode('ascii').hex(),
        'completed_before': False, 'completed_after': True, 'source': observation.SOURCE, 'complete': True}
    event.update(changes)
    return event


def query():
    result = c04_query()
    result['parameters']['event_type'] = observation.EVENT_TYPE
    return result


@pytest.mark.parametrize('name', ['french_reconquest', 'mission"quote\\slash', 'a' * 256])
def test_identifier_preserved_from_owned_hex_and_event_id_is_stable(name):
    decoded = observation.public_observation(completed(name=name), SESSION_ID)
    assert decoded['payload']['mission_id'] == name
    assert decoded['objects'] == [{'type': 'country', 'country': 'FRA'}]
    assert 'country_fullref' not in decoded['payload']
    assert decoded['event_id'] == observation.event_id(SESSION_ID, 1)
    assert observation.event_id(SESSION_ID, 2) != decoded['event_id']


@pytest.mark.parametrize('changes', [
    {'version': 50}, {'version': 53}, {'version': 51.0}, {observation.CAPABILITY: 1},
    {'native_mission_completion_wire': True}, {'native_mission_completion_scope': 'all_missions'},
    {'native_relation_change_observation': False}, {'native_war_declaration_observation': False},
])
def test_literal_ack_and_parent_contracts(changes):
    assert observation.supported_ack(mission_ack(), GAME_SHA)
    assert not observation.supported_ack(mission_ack(**changes), GAME_SHA)


@pytest.mark.parametrize('changes', [
    {'schema_version': True}, {'sequence': True}, {'date_raw': True}, {'complete': 1},
    {'completed_before': 0}, {'completed_before': True}, {'completed_after': 1}, {'completed_after': False},
    {'country': 'POR'}, {'country_fullref': reference('ENG', 1)}, {'country_fullref': []},
    {'mission_id_hex': ''}, {'mission_id_hex': 'xyz'}, {'mission_id_hex': 'f'}, {'mission_id_hex': 'ff'},
    {'mission_id_hex': '0a'}, {'mission_id_hex': '00'}, {'mission_id_hex': '61' * 257},
    {'source': 'sampled_mission_diff'}, {'extra': 1},
])
def test_malformed_or_noncompletion_rows_are_rejected(changes):
    assert observation.public_observation(completed(**changes), SESSION_ID) is None


def test_all_sources_share_one_cursor_and_mission_watermark_is_independent(tmp_path):
    session, journal, source = make_source(tmp_path, ack=mission_ack(),
        events=[native_event(1), rival(1), declaration(1), relation(1), completed(1)])
    try:
        assert observation.EVENT_TYPE in source.event_types
        metadata = next(topic for topic in source.catalog() if topic['topic_id'] == 'C04')['native_mission_completion']
        assert metadata['capture_available'] and not metadata['player_country_required']
        assert not metadata['condition_progress_covered']
        batch = source.poll_events(source.context(), None)
        assert batch['complete'] and len(batch['events']) == 5
        assert batch['cursor']['mission_sequence'] == batch['cursor']['relation_sequence'] == 1
        assert session._inbound_log_offset == (session.directory/'control-probe.jsonl').stat().st_size
        assert source.poll_events(source.context(), batch['cursor'])['events'] == []
        for invalid in (True, -1, '0'):
            with pytest.raises(InformationError, match='mission_sequence'):
                source.poll_events(source.context(), {'mission_sequence': invalid})
    finally:
        journal.close()


def test_public_report_subscription_frozen_date_cold_reopen_and_cancel(tmp_path, monkeypatch):
    session, journal, source = make_source(tmp_path, ack=mission_ack(), events=[completed(1)])
    database = tmp_path/'information.sqlite3'
    try:
        with closing(InformationService(source, database)) as service:
            api = InformationTools(service)
            report = api.call('information_manage_report', {'request_id': 'mission-report', 'operation': 'create',
                'config': {'name': 'Mission completion', 'detail': 'full', 'queries': [query()]}})['report']
            sub = api.call('information_manage_subscription', {'request_id': 'mission-sub', 'operation': 'create',
                'config': {'name': 'Completed missions', 'kind': 'event', 'enabled': True, 'report_id': report['id'],
                           'event': {'types': [observation.EVENT_TYPE]}}})['subscription']
            results = api.call('information_tick', {'view': 'full'})['results']
            assert len(results) == 1 and results[0]['complete']
            assert api.call('information_tick', {})['results'] == []
            result = results[0]
            assert api.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})['items'] == result['items']
            session.game_date += 24 * 120
            monkeypatch.setattr(session, 'read_native_mission_events', lambda **kw: pytest.fail('replay refreshed native state'))
            event = result['event']
            replay = source.read_event(query(), source.context(), event)
            assert replay['complete'] and replay['game_date'] == GAME_DATE
            assert replay['fields']['event_payload']['value']['mission_id'] == 'french_reconquest'
            for changes in ({'event_id': 'wrong'}, {'session_id': 'wrong'}, {'observer': 'POR'}, {'objects': []},
                            {'payload': {**event['payload'], 'completed_before': True}}):
                invalid = deepcopy(event)
                invalid.update(changes)
                assert not source.replay_event(query(), source.context(), invalid)['complete']
        fresh_session = LogSession(session.directory/'installation.json', session.game_exe)
        fresh_source = DiplomacySource(DiplomacyTools(journal, fresh_session))
        with closing(InformationService(fresh_source, database)) as service:
            api = InformationTools(service)
            assert api.call('information_tick', {})['results'] == []
            assert api.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})['items'] == result['items']
            with (fresh_session.directory/'control-probe.jsonl').open('a', encoding='utf-8') as stream:
                stream.write(json.dumps(completed(2, 'french_trade', date_raw=GAME_DATE+24))+'\n')
            later = api.call('information_tick', {'view': 'full'})['results']
            assert len(later) == 1 and later[0]['event']['game_date'] == GAME_DATE+24
            api.call('information_manage_subscription', {'request_id': 'cancel-mission-sub', 'operation': 'cancel',
                'subscription_id': sub['id'], 'expected_version': sub['version']})
    finally:
        journal.close()


def test_log_gaps_and_bounded_collector_are_retained(tmp_path, monkeypatch):
    monkeypatch.setattr(observation, 'MAX_EVENTS', 1)
    session, journal, source = make_source(tmp_path, ack=mission_ack(), events=[completed(1), completed(2)])
    try:
        batch = session.read_native_mission_events()
        assert batch['gaps'] == ['MISSION_CACHE_EVICTED'] and len(batch['events']) == 1
        with (session.directory/'control-probe.jsonl').open('a', encoding='utf-8') as stream:
            stream.write('{broken}\n')
            stream.write(json.dumps({'event': observation.NATIVE_GAP, 'session_id': SESSION_ID,
                                     'dropped': 1, 'complete': False})+'\n')
        assert {'MISSION_LOG_INVALID_JSON', 'MISSION_CAPTURE_DROPPED'} <= set(session.read_native_mission_events()['gaps'])
    finally:
        journal.close()
