"""Relation-state decoding, shared cursor and public C04 delivery."""
from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge import relation_observation as observation
from bridge import mission_condition_observation
from bridge import rival_observation as rival_observation_module
from bridge.diplomacy import DiplomacyTools
from bridge.information import InformationService
from bridge.information.model import InformationError
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools
from bridge.tests.test_information_country_modifier_events import (
    GAME_DATE, GAME_SHA, SESSION_ID, LogSession, c04_query, make_source, native_event,
)
from bridge.tests.test_information_war_declaration_events import declaration, declaration_ack, reference
from bridge.tests.test_information_rival_events import rival


def relation_ack(**changes):
    ack = declaration_ack(version=50)
    ack.update({observation.CAPABILITY: True, 'native_relation_change_wire': 1,
                'native_relation_change_scope': observation.SCOPE})
    ack.update(changes)
    return ack


def state(kind='alliance', active=False):
    value = {'active': active, 'guarantee': None, 'support_roles': None, 'subject': None}
    if kind == 'guarantee':
        value['guarantee'] = {'actor_grants': active, 'recipient_grants': False}
    if kind == 'support_independence':
        value['support_roles'] = {'actor_is_subject': False, 'recipient_is_subject': True}
    if kind == 'subject':
        value['subject'] = {'actor_is_overlord': active, 'actor_is_subject': False,
                            'type': 'vassal' if active else None}
    return value


def relation(sequence=1, *, kind='alliance', before=False, after=True, actor='ENG', recipient='FRA', **changes):
    event = {'event': observation.NATIVE_EVENT, 'schema_version': 1, 'session_id': SESSION_ID,
        'sequence': sequence, 'country': 'FRA', 'actor': actor, 'recipient': recipient,
        'actor_fullref': reference(actor, 1), 'recipient_fullref': reference(recipient, 2),
        'date_raw': GAME_DATE, 'relation_kind': kind, 'command_state': 2, 'command_mode': 1,
        'before': state(kind, before), 'after': state(kind, after), 'source': observation.SOURCE, 'complete': True}
    event.update(changes)
    return event


def query():
    result = c04_query()
    result['parameters']['event_type'] = observation.EVENT_TYPE
    return result


@pytest.mark.parametrize('kind', observation.KINDS)
@pytest.mark.parametrize('before,after', [(False, True), (True, False), (True, True)])
def test_six_kinds_actual_change_and_no_op(kind, before, after):
    event = relation(kind=kind, before=before, after=after)
    decoded = observation.public_observation(event, SESSION_ID)
    assert (decoded is None) == (before == after)
    if decoded:
        assert decoded['payload']['before'] == event['before']
        assert decoded['payload']['after'] == event['after']
        assert 'actor_fullref' not in decoded['payload']
        event['after']['active'] = before
        assert decoded['payload']['after']['active'] == after


def test_subject_type_and_direction_change_without_boolean_transition():
    event = relation(kind='subject', before=True)
    event['after']['subject']['type'] = 'march'
    assert observation.public_observation(event, SESSION_ID)
    event['after']['subject'] = {'actor_is_overlord': False, 'actor_is_subject': True, 'type': 'vassal'}
    assert observation.public_observation(event, SESSION_ID)
    event['after']['subject']['actor_is_overlord'] = True
    assert observation.public_observation(event, SESSION_ID) is None


def test_guarantee_direction_change_with_preexisting_reverse_guarantee():
    event = relation(kind='guarantee', before=True)
    event['before']['guarantee'] = {'actor_grants': False, 'recipient_grants': True}
    event['after']['guarantee'] = {'actor_grants': True, 'recipient_grants': True}
    assert observation.public_observation(event, SESSION_ID)
    event['after']['active'] = False
    assert observation.public_observation(event, SESSION_ID) is None


@pytest.mark.parametrize('changes', [
    {'version': 49}, {'version': 54}, {'version': 50.0}, {observation.CAPABILITY: 1},
    {'native_relation_change_wire': True}, {'native_relation_change_scope': 'all_relations'},
    {'native_war_declaration_observation': False}, {'native_rival_change_observation': False},
])
def test_ack_rejects_inherited_or_nonliteral_contracts(changes):
    assert observation.supported_ack(relation_ack(), GAME_SHA)
    assert not observation.supported_ack(relation_ack(**changes), GAME_SHA)


@pytest.mark.parametrize('changes', [
    {'schema_version': True}, {'sequence': True}, {'date_raw': True}, {'command_state': True},
    {'command_state': 3}, {'command_mode': 2}, {'relation_kind': []}, {'actor': 'FRA', 'recipient': 'FRA'},
    {'actor_fullref': '0x123'}, {'recipient_fullref': []}, {'complete': 1},
    {'before': {'active': False}}, {'source': 'derived_sampling'}, {'extra': 1},
])
def test_native_malformed_records_rejected(changes):
    assert observation.public_observation(relation(**changes), SESSION_ID) is None


def test_pair_scope_support_roles_and_bounded_collector(monkeypatch):
    assert observation.public_observation(relation(actor='FRA', recipient='CAS'), SESSION_ID)
    assert observation.public_observation(relation(actor='ENG', recipient='CAS'), SESSION_ID) is None
    support = relation(kind='support_independence', before=True)
    support['after']['support_roles']['actor_is_subject'] = True
    assert observation.public_observation(support, SESSION_ID) is None
    monkeypatch.setattr(observation, 'MAX_EVENTS', 2)
    collector = observation.Collector(SESSION_ID)
    for sequence in (1, 2, 3):
        collector.observe(relation(sequence))
    assert collector.batch(0)['gaps'] == ['RELATION_CACHE_EVICTED']
    assert len(collector.batch(1)['events']) == 2
    collector.observe(relation(3, after=False, before=True))
    collector.observe(relation(5))
    assert {'RELATION_SEQUENCE_CONFLICT', 'RELATION_SEQUENCE_GAP'} <= set(collector.batch(3)['gaps'])


def test_all_sources_share_log_and_normal_subscription_cold_reopen(tmp_path, monkeypatch):
    events = [native_event(1), rival(1), declaration(1), relation(1), relation(2, kind='subject', actor='FRA', recipient='CAS')]
    session, journal, source = make_source(tmp_path, events=events, ack=relation_ack())
    try:
        assert observation.EVENT_TYPE in source.event_types
        metadata = next(topic for topic in source.catalog() if topic['topic_id'] == 'C04')['native_relation_change']
        assert metadata['capture_available'] and not metadata['direct_writes_covered']
        batch = source.poll_events(source.context(), None)
        assert batch['complete']
        assert len(batch['events']) == 5
        assert [batch['cursor'][key] for key in ('country_modifier_sequence', 'rival_sequence',
                                               'war_declaration_sequence', 'relation_sequence')] == [1, 1, 1, 2]
        assert session._inbound_log_offset == (session.directory/'control-probe.jsonl').stat().st_size
        for invalid in (True, -1, '0'):
            with pytest.raises(InformationError, match='relation_sequence'):
                source.poll_events(source.context(), {'relation_sequence': invalid})
        database = tmp_path/'information.sqlite3'
        with closing(InformationService(source, database)) as service:
            api = InformationTools(service)
            report = api.call('information_manage_report', {'request_id': 'relation-report', 'operation': 'create',
                'config': {'name': 'Relations', 'detail': 'full', 'queries': [query()]}})['report']
            subscriptions = []
            for label, filters in (('all', {}), ('actor-fra', {'actors': ['FRA'], 'recipients': ['CAS']})):
                subscriptions.append(api.call('information_manage_subscription', {
                    'request_id': 'relations-'+label, 'operation': 'create', 'config': {'name': label,
                    'kind': 'event', 'enabled': True, 'report_id': report['id'],
                    'event': {'types': [observation.EVENT_TYPE], **filters}}})['subscription'])
            results = api.call('information_tick', {'view': 'full'})['results']
            assert len(results) == 3 and all(result['complete'] for result in results)
            assert api.call('information_tick', {})['results'] == []
            for result in results:
                assert result['items'][0]['source']['projection'] == 'event_snapshot'
                assert api.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})['items'] == result['items']
            event = results[0]['event']
            session.game_date += 240
            monkeypatch.setattr(session, 'read_native_relation_events', lambda **kw: pytest.fail('replay read current relations'))
            replay = source.replay_event(query(), source.context(), event)
            assert replay['complete'] and replay['game_date'] == GAME_DATE
            invalid_event = deepcopy(event)
            invalid_event['event_id'] += '-wrong'
            assert not source.replay_event(query(), source.context(), invalid_event)['complete']
            for params in ({'request_id': 'unrelated'}, {'case': 'unrelated'}, {'event_type': 'rival_changed'}):
                wrong_query = query()
                wrong_query['parameters'].update(params)
                assert not source.replay_event(wrong_query, source.context(), event)['complete']

        fresh_session = LogSession(session.directory/'installation.json', session.game_exe)
        fresh_source = DiplomacySource(DiplomacyTools(journal, fresh_session))
        with closing(InformationService(fresh_source, database)) as service:
            api = InformationTools(service)
            assert api.call('information_tick', {})['results'] == []
            for result in results:
                assert api.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})['items'] == result['items']
            with (fresh_session.directory/'control-probe.jsonl').open('a', encoding='utf-8') as stream:
                stream.write(json.dumps(relation(3, kind='military_access', date_raw=GAME_DATE+24))+'\n')
            later = api.call('information_tick', {'view': 'full'})['results']
            assert len(later) == 1 and later[0]['event']['game_date'] == GAME_DATE+24
            for sub in subscriptions:
                api.call('information_manage_subscription', {'request_id': 'cancel-'+sub['id'], 'operation': 'cancel',
                    'subscription_id': sub['id'], 'expected_version': sub['version']})
    finally:
        journal.close()


@pytest.mark.parametrize(
    'fixture_name,recipient,relation_kind,observation_path,before_active,after_active,command_state,command_mode',
    [
        pytest.param(
            'information_relation_FRA_GEL_guarantee_live_1374.json',
            'GEL', 'guarantee', 'guarantee_record_enable', False, True, None, None,
            id='guarantee-enabled',
        ),
        pytest.param(
            'information_relation_FRA_HES_access_live_1374.json',
            'HES', 'military_access', 'military_record_enable', False, True, None, None,
            id='military-access-enabled',
        ),
        pytest.param(
            'information_relation_FRA_SAV_royal_live_1374.json',
            'SAV', 'royal_marriage', 'royal_record_enable', False, True, None, None,
            id='royal-marriage-enabled',
        ),
        pytest.param(
            'information_relation_FRA_SAV_alliance_live_1374.json',
            'SAV', 'alliance', 'alliance_record_enable', False, True, None, None,
            id='alliance-enabled',
        ),
        pytest.param(
            'information_relation_FRA_GEL_guarantee_removed_live_1374.json',
            'GEL', 'guarantee', 'guarantee_record_disable', True, False, None, None,
            id='guarantee-removed',
        ),
        pytest.param(
            'information_relation_FRA_LIT_support_direct_live_1374.json',
            'LIT', 'support_independence', 'command_return', False, True, 2, 1,
            id='support-independence-direct-handler',
        ),
        pytest.param(
            'information_relation_FRA_HES_subject_live_1374.json',
            'HES', 'subject', 'subject_record_enable', False, True, None, None,
            id='subject-enabled',
        ),
        pytest.param(
            'information_relation_FRA_HES_access_removed_live_1374.json',
            'HES', 'military_access', 'military_record_disable', True, False, None, None,
            id='military-access-removed-on-subjection',
        ),
    ],
)
def test_live_relation_record_fixtures_flow_through_normal_c04_delivery(
        tmp_path, fixture_name, recipient, relation_kind, observation_path, before_active, after_active,
        command_state, command_mode):
    fixture_path = Path(__file__).parent / 'fixtures' / fixture_name
    fixture = json.loads(fixture_path.read_text(encoding='utf-8'))
    event = fixture['event']
    assert fixture['evidence_kind'] in {
        'actual_runtime_native_relation_record_return', 'actual_runtime_native_relation_change'}
    assert fixture['line_bytes'] > 0 and len(fixture['line_sha256']) == 64
    assert event['schema_version'] == 5
    assert event['actor'] == 'FRA'
    assert event['recipient'] == recipient
    assert event['relation_kind'] == relation_kind
    assert event['observation_path'] == observation_path
    assert event['before']['active'] is before_active and event['after']['active'] is after_active

    ack = relation_ack(
        version=61,
        native_relation_change_wire=5,
        native_relation_change_scope=observation.SUPPORT_SUBJECT_RECORD_SCOPE,
        native_mission_condition_wire=2,
        native_mission_condition_scope=mission_condition_observation.COMBINED_SCOPE,
        native_rival_change_wire=2,
        native_rival_change_scope=rival_observation_module.COMBINED_SCOPE,
        native_rival_record_count_basis='active_nonretired_nodes',
        **{
            observation.RECORD_CAPABILITY: True,
            observation.ROYAL_RECORD_CAPABILITY: True,
            observation.DIRECTED_RECORD_CAPABILITY: True,
            observation.SUPPORT_SUBJECT_RECORD_CAPABILITY: True,
            mission_condition_observation.CAPABILITY: True,
            mission_condition_observation.PROVINCE_CAPABILITY: True,
            rival_observation_module.RECORD_CAPABILITY: True,
        },
    )
    ack['session_id'] = event['session_id']
    session, journal, source = make_source(
        tmp_path, events=[event], session_id=event['session_id'],
        game_sha=fixture['game_sha256'], ack=ack,
    )
    session.game_date = event['date_raw']
    database = tmp_path / 'information.sqlite3'
    try:
        assert observation.public_observation(event, session.session_id) is not None
        with closing(InformationService(source, database)) as service:
            api = InformationTools(service)
            report = api.call('information_manage_report', {
                'request_id': 'live-guarantee-report', 'operation': 'create',
                'config': {'name': 'Live guarantee', 'detail': 'full', 'queries': [query()]},
            })['report']
            api.call('information_manage_subscription', {
                'request_id': 'live-guarantee-subscription', 'operation': 'create',
                'config': {'name': 'Live guarantee', 'kind': 'event', 'enabled': True,
                           'report_id': report['id'], 'event': {'types': [observation.EVENT_TYPE]}},
            })

            delivered = api.call('information_tick', {})['results']
            assert len(delivered) == 1
            concise_payload = delivered[0]['items'][0]['event_payload']
            assert concise_payload['actor'] == 'FRA'
            assert concise_payload['recipient'] == recipient
            assert concise_payload['relation_kind'] == relation_kind
            assert concise_payload['before']['active'] is before_active
            assert concise_payload['after']['active'] is after_active
            assert not {'observation_path', 'command_state', 'command_mode'} & set(concise_payload)

            full = api.call('information_get_result', {
                'result_id': delivered[0]['result_id'], 'view': 'full',
            })
            full_payload = full['items'][0]['fields']['event_payload']['value']
            assert full_payload == observation.public_observation(event, session.session_id)['payload']
            assert full_payload['observation_path'] == observation_path
            assert full_payload['command_state'] == command_state
            assert full_payload['command_mode'] == command_mode
            assert full_payload['before'] == event['before']
            assert full_payload['after'] == event['after']
    finally:
        journal.close()
