"""Native eligibility observations through public C04 reports and subscriptions."""
from contextlib import closing
from copy import deepcopy
import json

import pytest

from bridge import mission_availability_observation as observation
from bridge.diplomacy import DiplomacyTools
from bridge.information import InformationService
from bridge.information.model import InformationError
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools
from bridge.tests.test_information_country_modifier_events import (
    GAME_DATE, SESSION_ID, LogSession, c04_query, make_source, native_event,
)
from bridge.tests.test_information_mission_events import completed, mission_ack
from bridge.tests.test_information_relation_events import relation
from bridge.tests.test_information_rival_events import rival
from bridge.tests.test_information_war_declaration_events import declaration, reference


def availability_ack(**changes):
    ack = mission_ack(version=52)
    ack.update({observation.CAPABILITY: True, 'native_mission_availability_wire': 1,
        'native_mission_availability_scope': observation.SCOPE})
    ack.update(changes)
    return ack


def available(sequence=1, **changes):
    row = {'event': observation.NATIVE_EVENT, 'schema_version': 1, 'session_id': SESSION_ID,
        'sequence': sequence, 'country': 'FRA', 'country_fullref': reference('FRA', 1),
        'date_raw': GAME_DATE, 'previous_observed_date_raw': GAME_DATE-24,
        'mission_id_hex': 'french_reconquest'.encode().hex(),
        'eligible_before': False, 'eligible_after': True, 'source': observation.SOURCE, 'complete': True}
    row.update(changes)
    return row


def query():
    value = c04_query()
    value['parameters']['event_type'] = observation.EVENT_TYPE
    return value


def test_sources_share_byte_cursor_and_availability_has_independent_watermark(tmp_path):
    session, journal, source = make_source(tmp_path, ack=availability_ack(),
        events=[native_event(1), rival(1), declaration(1), relation(1), completed(1), available(1)])
    try:
        metadata = next(row for row in source.catalog() if row['topic_id'] == 'C04')['native_mission_availability']
        assert metadata['capture_available'] and metadata['initial_observation'] == 'baseline_only'
        assert not metadata['all_state_changes_covered'] and not metadata['branch_visibility_verified']
        batch = source.poll_events(source.context(), None)
        assert batch['complete'] and len(batch['events']) == 6
        assert batch['cursor']['mission_availability_sequence'] == batch['cursor']['mission_sequence'] == 1
        assert session._inbound_log_offset == (session.directory/'control-probe.jsonl').stat().st_size
        assert source.poll_events(source.context(), batch['cursor'])['events'] == []
        for value in (True, -1, '0'):
            with pytest.raises(InformationError, match='mission_availability_sequence'):
                source.poll_events(source.context(), {'mission_availability_sequence': value})
    finally:
        journal.close()


def test_public_subscription_keeps_both_dates_cold_reopen_dedup_and_cancel(tmp_path, monkeypatch):
    session, journal, source = make_source(tmp_path, ack=availability_ack(), events=[available(1)])
    database = tmp_path/'information.sqlite3'
    try:
        with closing(InformationService(source, database)) as service:
            api = InformationTools(service)
            report = api.call('information_manage_report', {'request_id': 'availability-report', 'operation': 'create',
                'config': {'name': 'Task eligibility', 'detail': 'full', 'queries': [query()]}})['report']
            sub = api.call('information_manage_subscription', {'request_id': 'availability-sub', 'operation': 'create',
                'config': {'name': 'Task eligibility', 'kind': 'event', 'enabled': True,
                    'report_id': report['id'], 'event': {'types': [observation.EVENT_TYPE]}}})['subscription']
            result, = api.call('information_tick', {'view': 'full'})['results']
            assert result['complete'] and api.call('information_tick', {})['results'] == []
            assert api.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})['items'] == result['items']
            session.game_date += 24*120
            monkeypatch.setattr(session, 'read_native_mission_availability_events',
                lambda **kwargs: pytest.fail('replay read current native state'))
            event = result['event']
            replay = source.read_event(query(), source.context(), event)
            assert replay['complete'] and replay['game_date'] == GAME_DATE
            payload = replay['fields']['event_payload']['value']
            assert payload['eligible_before'] is False and payload['eligible_after'] is True
            assert payload['previous_observed_date_raw'] == GAME_DATE-24
            for changes in ({'session_id': 'other'}, {'objects': []},
                            {'payload': {**event['payload'], 'previous_observed_date_raw': GAME_DATE+1}}):
                altered = deepcopy(event)
                altered.update(changes)
                assert not source.replay_event(query(), source.context(), altered)['complete']
        fresh = LogSession(session.directory/'installation.json', session.game_exe)
        fresh_source = DiplomacySource(DiplomacyTools(journal, fresh))
        with closing(InformationService(fresh_source, database)) as service:
            api = InformationTools(service)
            assert api.call('information_tick', {})['results'] == []
            assert api.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})['items'] == result['items']
            with (fresh.directory/'control-probe.jsonl').open('a', encoding='utf-8') as stream:
                stream.write(json.dumps(available(2, date_raw=GAME_DATE+24,
                    previous_observed_date_raw=GAME_DATE, eligible_before=True, eligible_after=False))+'\n')
            later, = api.call('information_tick', {'view': 'full'})['results']
            assert later['event']['game_date'] == GAME_DATE+24
            assert later['items'][0]['fields']['event_payload']['value']['eligible_after'] is False
            api.call('information_manage_subscription', {'request_id': 'cancel-availability', 'operation': 'cancel',
                'subscription_id': sub['id'], 'expected_version': sub['version']})
    finally:
        journal.close()


@pytest.mark.parametrize('version', [51, 54])
def test_other_versions_do_not_enable_copied_availability_capability(tmp_path, version):
    session, journal, source = make_source(tmp_path, ack=availability_ack(version=version), events=[available(1)])
    try:
        assert observation.EVENT_TYPE not in source.event_types
        assert observation.CAPABILITY not in session.installation_capabilities()
    finally:
        journal.close()


def test_shared_log_errors_and_source_gaps_are_preserved(tmp_path):
    session, journal, source = make_source(tmp_path, ack=availability_ack(), events=[available(1)])
    try:
        assert session.read_native_mission_availability_events()['complete']
        with (session.directory/'control-probe.jsonl').open('a', encoding='utf-8') as stream:
            stream.write('{broken}\n')
            stream.write(json.dumps({'event': observation.NATIVE_GAP, 'session_id': SESSION_ID,
                'dropped': 1, 'complete': False})+'\n')
        gaps = session.read_native_mission_availability_events()['gaps']
        assert {'MISSION_AVAILABILITY_LOG_INVALID_JSON', 'MISSION_AVAILABILITY_CAPTURE_DROPPED'} <= set(gaps)
    finally:
        journal.close()
