"""Completed-set and archived command events share C04 without wire mixing."""
from contextlib import closing
from copy import deepcopy
import json

import pytest

from bridge import mission_observation as mission
from bridge import mission_availability_observation as availability
from bridge.diplomacy import DiplomacyTools
from bridge.information import InformationService
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools
from bridge.tests.test_information_country_modifier_events import (
    GAME_DATE, LogSession, c04_query, make_source, native_event,
)
from bridge.tests.test_information_mission_events import completed, mission_ack, query
from bridge.tests.test_information_mission_availability_events import availability_ack, available
from bridge.tests.test_information_relation_events import relation
from bridge.tests.test_information_rival_events import rival
from bridge.tests.test_information_war_declaration_events import declaration


def set_ack(**changes):
    ack = availability_ack(version=53)
    ack.update({'native_mission_completion_wire': 2, 'native_mission_completion_scope': mission.SET_SCOPE,
        mission.SET_CAPABILITY: True})
    ack.update(changes)
    return ack


def inserted(sequence=1, **changes):
    row = completed(sequence)
    row.update({'schema_version': 2, 'source': mission.SET_SOURCE, 'completion_path': 'script_effect',
        'country_fullref': '0x1200000100415246'})
    row.update(changes)
    return row


def test_set_and_availability_sources_share_cursor_and_keep_parent_sources(tmp_path):
    session, journal, source = make_source(tmp_path, ack=set_ack(), events=[
        native_event(1), rival(1), declaration(1), relation(1), inserted(1), available(1)])
    try:
        metadata = next(row for row in source.catalog() if row['topic_id'] == 'C04')['native_mission_completion']
        assert metadata['scope'] == mission.SET_SCOPE and metadata['verified_script_effect_source']
        assert not metadata['all_direct_writes_covered']
        assert mission.SET_CAPABILITY in session.installation_capabilities()
        assert availability.CAPABILITY in session.installation_capabilities()
        batch = source.poll_events(source.context(), None)
        assert batch['complete'] and len(batch['events']) == 6
        assert batch['cursor']['mission_sequence'] == batch['cursor']['mission_availability_sequence'] == 1
        event, = [row for row in batch['events'] if row['event_type'] == mission.EVENT_TYPE]
        assert event['source']['scope'] == mission.SET_SCOPE
        assert event['source']['date_semantics'] == mission.SET_DATE_SEMANTICS
        assert event['payload']['completion_path'] == 'script_effect'
        assert session._inbound_log_offset == (session.directory/'control-probe.jsonl').stat().st_size
        assert source.poll_events(source.context(), batch['cursor'])['events'] == []
    finally:
        journal.close()


def test_both_completion_paths_public_delivery_snapshot_and_cold_reopen(tmp_path, monkeypatch):
    session, journal, source = make_source(tmp_path, ack=set_ack(), events=[
        inserted(1, completion_path='command_handler'),
        inserted(2, date_raw=GAME_DATE+24, mission_id_hex=('x'*254+'"\\').encode().hex()),
        available(1)])
    database = tmp_path/'information.sqlite3'
    try:
        with closing(InformationService(source, database)) as service:
            api = InformationTools(service)
            selected = c04_query()
            selected['parameters'] = {}
            report = api.call('information_manage_report', {'request_id': 'set-report', 'operation': 'create',
                'config': {'name': 'Task observations', 'detail': 'full', 'queries': [selected]}})['report']
            sub = api.call('information_manage_subscription', {'request_id': 'set-sub', 'operation': 'create',
                'config': {'name': 'Task observations', 'kind': 'event', 'enabled': True,
                    'report_id': report['id'], 'event': {'types': [mission.EVENT_TYPE, availability.EVENT_TYPE]}}})['subscription']
            results = api.call('information_tick', {'view': 'full'})['results']
            assert len(results) == 3 and all(row['complete'] for row in results)
            completion_results = [row for row in results if row['event']['event_type'] == mission.EVENT_TYPE]
            assert {row['event']['payload']['completion_path'] for row in completion_results} == {'command_handler', 'script_effect'}
            assert api.call('information_tick', {})['results'] == []
            session.game_date += 120*24
            monkeypatch.setattr(session, 'read_native_mission_events', lambda **kw: pytest.fail('replay refreshed native state'))
            for row in completion_results:
                assert api.call('information_get_result', {'result_id': row['result_id'], 'view': 'full'})['items'] == row['items']
                frozen = source.read_event(query(), source.context(), row['event'])
                assert frozen['complete'] and frozen['game_date'] == row['event']['game_date']
                assert frozen['fields']['event_payload']['value'] == row['event']['payload']
                altered = deepcopy(row['event'])
                altered['source']['date_semantics'] = mission.DATE_SEMANTICS
                assert not source.replay_event(query(), source.context(), altered)['complete']
        fresh = LogSession(session.directory/'installation.json', session.game_exe)
        fresh_source = DiplomacySource(DiplomacyTools(journal, fresh))
        with closing(InformationService(fresh_source, database)) as service:
            api = InformationTools(service)
            assert api.call('information_tick', {})['results'] == []
            for row in results:
                assert api.call('information_get_result', {'result_id': row['result_id'], 'view': 'full'})['items'] == row['items']
            api.call('information_manage_subscription', {'request_id': 'set-cancel', 'operation': 'cancel',
                'subscription_id': sub['id'], 'expected_version': sub['version']})
    finally:
        journal.close()


@pytest.mark.parametrize('ack,wrong,right', [
    (mission_ack(), inserted(), completed()),
    (set_ack(), completed(), inserted()),
])
def test_native_session_never_mixes_mission_wires(tmp_path, ack, wrong, right):
    session, journal, source = make_source(tmp_path, ack=ack, events=[wrong, right])
    try:
        batch = session.read_native_mission_events()
        assert batch['gaps'] == ['MISSION_OBSERVATION_INVALID'] and len(batch['events']) == 1
        assert batch['events'][0]['payload']['scope'] == (
            mission.SET_SCOPE if ack['version'] == 53 else mission.SCOPE)
    finally:
        journal.close()


def test_legacy_payload_shape_and_scope_remain_unchanged(tmp_path):
    session, journal, source = make_source(tmp_path, ack=mission_ack(), events=[completed()])
    try:
        batch = source.poll_events(source.context(), None)
        event, = batch['events']
        assert set(event['payload']) == {'country', 'mission_id', 'completed_before', 'completed_after', 'scope'}
        assert event['payload']['scope'] == mission.SCOPE
        assert event['source']['date_semantics'] == mission.DATE_SEMANTICS
        assert 'completion_path' not in source.read_event(query(), source.context(), event)['fields']['event_payload']['value']
    finally:
        journal.close()
