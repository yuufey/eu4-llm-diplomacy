"""Record-source capability isolation, C04 snapshots and durable delivery."""
from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge import rival_observation as observation
from bridge.information import InformationService
from bridge.information.presentation import present_concise
from bridge.information.sources import RecordedSource
from bridge.information.tools import InformationTools
from bridge.tests.test_information_rival_events import GAME_DATE, SESSION_ID, make_source, query, rival, state
from bridge.tests.test_support_subject_relation_record_observation import support_subject_ack


def record_ack(**changes):
    ack = support_subject_ack(version=61)
    ack.update(native_rival_change_wire=2, native_rival_change_scope=observation.COMBINED_SCOPE,
               native_rival_record_observation=True, native_rival_record_count_basis=observation.COUNT_BASIS,
               session_id=SESSION_ID, observer='FRA')
    ack.update(changes)
    return ack


def record_event(sequence=1, *, remove=False):
    value = rival(sequence)
    value.update(schema_version=2, operation='remove' if remove else 'set',
                 source='country_rival_remove_return' if remove else 'country_rival_add_return',
                 observation_path='country_rival_remove' if remove else 'country_rival_add',
                 count_basis=observation.COUNT_BASIS,
                 before=state(1,True) if remove else state(0), after=state(0) if remove else state(1,True))
    return value


@pytest.mark.parametrize('changes', [
    {'schema_version': True}, {'schema_version': 2.0}, {'schema_version': 5},
    {'source': observation.SOURCE}, {'source': 'country_rival_remove_return'},
    {'observation_path': []}, {'observation_path': 'country_rival_remove'},
    {'count_basis': 'physical_nodes'}, {'count_basis': None}, {'operation': 'replace'},
    {'old_rival': 'ARA'}, {'complete': False}, {'unexpected': 'field'},
])
def test_record_decoder_rejects_unverified_shape_and_source(changes):
    value = record_event()
    value.update(changes)
    assert observation.public_observation(value,SESSION_ID) is None


def test_configured_observer_receives_record_and_replaced_rival_receipts(tmp_path):
    from bridge.diplomacy import DiplomacyTools
    from bridge.information.sources import DiplomacySource
    from bridge.tests.test_information_war_declaration_events import reference

    ack = record_ack(version=65, observer='TUR', native_country_control_configuration=True,
        native_country_control_protocol='EU4CONTROL1', native_country_control_ack='native_controlled_countries_set',
        native_country_control_request='controlled-countries.req', native_information_observer_configuration=True,
        native_country_modifier_scoped_schema=2, native_rival_change_scoped_schema=4)
    record = dict(record_event(1), schema_version=4, country='TUR', target='TUR',
                  target_fullref=reference('TUR', 43))
    replaced = rival(2, schema_version=3, country='TUR', target='FRA', old_rival='TUR',
                     old_rival_fullref=reference('TUR', 43), operation='replace',
                     before=state(1, old=True), after=state(1, target=True))
    other = dict(replaced, country='FRA', sequence=3)
    session, journal, _ = make_source(tmp_path, ack=ack, events=[record, replaced, other], observer='TUR')
    try:
        assert observation.SCOPED_CAPABILITY in session.installation_capabilities()
        session.observed_countries = ('FRA', 'TUR')
        source = DiplomacySource(DiplomacyTools(journal, session), observer='TUR')
        current = source.context()
        batch = source.poll_events(current, None)
        assert batch['complete'] and batch['cursor']['rival_sequence'] == 3
        assert [event['payload']['scope'] for event in batch['events']] == [
            observation.CONFIGURED_RECORD_SCOPE, observation.CONFIGURED_COMMAND_SCOPE,
        ]
        assert not observation.public_observation(dict(replaced, country='SAV'), SESSION_ID)
        for event in batch['events']:
            assert event['observer'] == 'TUR'
            assert source.replay_event(query(), current, event)['complete']
            assert not source.replay_event(query(), dict(current, observer='FRA'), event)['complete']
    finally:
        journal.close()


def test_collector_requires_record_permission_and_keeps_legacy_sequence_identity():
    collector = observation.Collector(SESSION_ID)
    collector.observe(record_event())
    assert not collector.batch(0)['events']
    assert 'RIVAL_OBSERVATION_INVALID' in collector.batch(0)['gaps']
    collector = observation.Collector(SESSION_ID)
    rows = [record_event(1),record_event(2,remove=True),rival(3)]
    for row in rows:
        collector.observe(row,allow_record=True)
    batch = collector.batch(0)
    assert batch['complete'] and len(batch['events']) == 3
    assert [row['native_sequence'] for row in batch['events']] == [1,2,3]
    assert [row['payload']['scope'] for row in batch['events']] == [observation.RECORD_SCOPE]*2+[observation.SCOPE]
    collector.observe(deepcopy(rows[0]),allow_record=True)
    assert len(collector.batch(0)['events']) == 3


def test_v60_copied_record_capability_does_not_grant_new_source(tmp_path):
    ack = support_subject_ack(caps=[observation.RECORD_CAPABILITY],session_id=SESSION_ID)
    session,journal,source = make_source(tmp_path,ack=ack,events=[record_event()])
    try:
        assert observation.CAPABILITY in session.installation_capabilities()
        assert observation.RECORD_CAPABILITY not in session.installation_capabilities()
        batch = source.poll_events(source.context(),None)
        assert not [event for event in batch['events'] if event['event_type'] == observation.EVENT_TYPE]
        assert not batch['complete']
    finally:
        journal.close()


def test_record_subscription_keeps_scope_dates_gaps_and_cold_full_results(tmp_path):
    rows = [record_event(),record_event(2,remove=True),rival(3)]
    session,journal,source = make_source(tmp_path,ack=record_ack(),events=rows)
    database = tmp_path/'information.sqlite3'
    try:
        assert observation.RECORD_CAPABILITY in session.installation_capabilities()
        topic = next(value for value in source.catalog() if value['topic_id'] == 'C04')
        assert topic['native_rival_change']['country_record_returns_covered'] is True
        assert topic['native_rival_change']['scope'] == observation.COMBINED_SCOPE
        assert topic['native_rival_change']['actor_role'] == 'rival_owner'
        assert topic['native_rival_change']['recipient_role'] == 'rival_target'
        assert topic['native_war_declaration']['actor_role'] == 'command_actor'
        assert topic['native_war_declaration']['recipient_role'] == 'command_target'
        with closing(InformationService(source,database)) as service:
            api = InformationTools(service)
            report = api.call('information_manage_report',{'request_id':'record-report','operation':'create',
                'config':{'name':'rival records','queries':[query()],'detail':'brief'}})['report']
            subscription = api.call('information_manage_subscription',{'request_id':'record-subscription','operation':'create',
                'config':{'name':'rival records','kind':'event','report_id':report['id'],'enabled':True,
                          'event':{'types':[observation.EVENT_TYPE]}}})['subscription']
            tick = api.call('information_tick',{})
            assert len(tick['results']) == 3
            saved = []
            for brief in tick['results']:
                full = api.call('information_get_result',{'result_id':brief['result_id'],'view':'full'})
                assert present_concise(full) == brief
                assert full['event']['game_date'] == GAME_DATE
                scope = full['event']['payload']['scope']
                assert full['items'][0]['source']['coverage'] == scope
                assert full['items'][0]['source']['date_semantics'] == observation.DATE_SEMANTICS_BY_SCOPE[scope]
                assert full['items'][0]['fields']['event_payload']['value'] == full['event']['payload']
                saved.append(full)
            assert api.call('information_tick',{})['results'] == []
            session.game_date += 120*24
            sample = source.read_event(query(),source.context(),saved[0]['event'])
            assert sample['complete'] and sample['fields']['event_date']['value'] == GAME_DATE
            api.call('information_manage_subscription',{'request_id':'record-cancel','operation':'cancel',
                'subscription_id':subscription['id'],'expected_version':subscription['version']})
        with closing(InformationService(RecordedSource({'context':source.context(),'cases':[]}),database)) as reopened:
            for full in saved:
                assert reopened.get_result(full['result_id']) == full
    finally:
        journal.close()


def test_live_rival_change_c04_brief_full_dedup_and_cold_reopen(tmp_path):
    fixture_root = Path(__file__).parent / 'fixtures'
    fixture = json.loads((fixture_root / 'information_rival_FRA_HAB_live_1374.json').read_text(encoding='utf-8'))
    ack_fixture = json.loads((fixture_root / fixture['installation_ack_fixture']).read_text(encoding='utf-8'))
    event = fixture['source_line']['event']
    ack = ack_fixture['installation_ack']
    assert fixture['evidence_kind'] == 'observed_runtime'
    assert fixture['game_sha256'] == ack_fixture['game_sha256']
    assert fixture['dll_sha256'] == ack_fixture['dll_sha256']
    assert ack['session_id'] == event['session_id']

    expected = observation.public_observation(event, event['session_id'])
    assert expected is not None
    session, journal, source = make_source(
        tmp_path,
        events=[event],
        session_id=event['session_id'],
        game_sha=fixture['game_sha256'],
        ack=ack,
    )
    session.game_date = event['date_raw']
    database = tmp_path / 'information.sqlite3'
    try:
        with closing(InformationService(source, database)) as service:
            api = InformationTools(service)
            report = api.call('information_manage_report', {
                'request_id': 'live-rival-report',
                'operation': 'create',
                'config': {
                    'name': 'live rival changes',
                    'queries': [query()],
                    'detail': 'brief',
                },
            })['report']
            api.call('information_manage_subscription', {
                'request_id': 'live-rival-subscription',
                'operation': 'create',
                'config': {
                    'name': 'live rival changes',
                    'kind': 'event',
                    'report_id': report['id'],
                    'enabled': True,
                    'event': {'types': [observation.EVENT_TYPE]},
                },
            })

            tick = api.call('information_tick', {})
            assert len(tick['results']) == 1
            concise = tick['results'][0]
            assert concise['event']['event_type'] == observation.EVENT_TYPE
            item = concise['items'][0]
            assert item['event_date'] == '1471.10.11'
            payload = item['event_payload']
            assert payload['after']['target_since'] == '1471.10.11'
            for state_label in ('before', 'after'):
                assert not any(key.endswith('_date_raw') for key in payload[state_label])
            assert 'old_rival' not in payload
            assert 'old_active' not in payload['before'] and 'old_since' not in payload['before']
            assert 'old_active' not in payload['after'] and 'old_since' not in payload['after']
            assert 'count_basis' not in payload

            result_id = concise['result_id']
            full = api.call('information_get_result', {'result_id': result_id, 'view': 'full'})
            assert present_concise(full) == concise
            full_payload = full['items'][0]['fields']['event_payload']['value']
            assert full_payload == expected['payload']
            assert full['event']['payload'] == expected['payload']
            assert api.call('information_tick', {})['results'] == []

        with closing(InformationService(RecordedSource({'context': source.context(), 'cases': []}), database)) as reopened:
            api = InformationTools(reopened)
            assert api.call('information_get_result', {'result_id': result_id}) == concise
            assert api.call('information_get_result', {'result_id': result_id, 'view': 'full'}) == full
    finally:
        journal.close()
