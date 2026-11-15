"""Normal public declaration delivery and replay from captured participant values."""
from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge import war_declaration_observation as observation
from bridge.diplomacy import DiplomacyTools
from bridge.information import InformationService
from bridge.information.model import InformationError
from bridge.information.presentation import present_concise
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools
from bridge.tests.test_information_country_modifier_events import (
    GAME_DATE, GAME_SHA, SESSION_ID, LogSession, c04_query, make_source, native_event,
)
from bridge.tests.test_information_country_modifier_expiry import expired
from bridge.tests.test_information_rival_events import rival_ack, rival


def declaration_ack(**changes):
    ack = rival_ack(version=49)
    ack.update({observation.CAPABILITY: True, 'native_war_declaration_wire': 1,
                'native_war_declaration_scope': observation.SCOPE})
    ack.update(changes)
    return ack


def reference(tag, slot):
    return hex((slot << 32) | int.from_bytes(tag.encode('ascii'), 'little'))


def declaration(sequence=1, *, third_party=False, **changes):
    actor, recipient = 'ENG', 'FRA'
    side_a, side_b = ['ENG'], ['FRA']
    actor_side, recipient_side, observer_side = 1, 2, 2
    if third_party:
        recipient = 'CAS'
        side_a, side_b = ['CAS', 'FRA'], ['ENG', 'POR']
        actor_side, recipient_side, observer_side = 2, 1, 1
    participants = {'source': 'native_war_side_vectors', 'status': 'available', 'complete': True,
        'side_a': side_a, 'side_b': side_b, 'actor_side': 'side_a' if actor_side == 1 else 'side_b',
        'recipient_side': 'side_a' if recipient_side == 1 else 'side_b', 'reason': None}
    event = {'event': observation.NATIVE_EVENT, 'schema_version': 1, 'session_id': SESSION_ID,
        'sequence': sequence, 'country': 'FRA', 'actor': actor, 'recipient': recipient,
        'actor_fullref': reference(actor, 1), 'recipient_fullref': reference(recipient, 2 if recipient == 'FRA' else 3),
        'observer_fullref': reference('FRA', 2), 'war_id': f'war_0123456789abcdef_{sequence:08x}',
        'date_raw': GAME_DATE, 'actor_side': actor_side, 'recipient_side': recipient_side,
        'observer_side': observer_side, 'participants': participants, 'source': observation.SOURCE, 'complete': True}
    event.update(changes)
    return event


def query():
    result = c04_query()
    result['parameters']['event_type'] = observation.EVENT_TYPE
    return result


def test_three_change_sources_share_bytes_with_independent_native_cursors(tmp_path):
    rows = [native_event(1), rival(1), declaration(1), expired(2), declaration(2, third_party=True)]
    session, journal, source = make_source(tmp_path, ack=declaration_ack(), events=rows)
    try:
        assert observation.CAPABILITY in session.installation_capabilities()
        assert observation.EVENT_TYPE in source.event_types
        topic = next(item for item in source.catalog() if item['topic_id'] == 'C04')
        assert topic['native_war_declaration']['capture_available']
        assert topic['native_war_declaration']['attacker_defender_labels_verified']
        assert topic['native_war_declaration']['role_basis'] == observation.ROLE_BASIS
        batch = source.poll_events(source.context(), None)
        assert batch['complete']
        assert [item['event_type'] for item in batch['events']] == [
            'country_modifier_added', 'country_modifier_expired', 'rival_changed', 'war_declared', 'war_declared']
        assert batch['cursor']['country_modifier_sequence'] == 2
        assert batch['cursor']['rival_sequence'] == 1
        assert batch['cursor']['war_declaration_sequence'] == 2
        assert source.poll_events(source.context(), batch['cursor'])['events'] == []
        assert session._inbound_log_offset == (session.directory/'control-probe.jsonl').stat().st_size
        third = batch['events'][-1]
        assert third['payload']['observer_side'] == 'side_a'
        assert third['payload']['participants']['actor_side'] == 'side_b'
        assert {obj.get('country') for obj in third['objects'] if obj['type'] == 'country'} == {'FRA', 'ENG', 'CAS', 'POR'}
        assert third['objects'][0] == {'type': 'war', 'war_id': third['payload']['war_id'], 'actor': 'ENG', 'recipient': 'CAS'}
        for cursor in (True, -1, '0'):
            with pytest.raises(InformationError, match='war_declaration_sequence'):
                source.poll_events(source.context(), {'war_declaration_sequence': cursor})
    finally:
        journal.close()


@pytest.mark.parametrize('changes,observer', [
    ({'version': 48}, 'FRA'), ({'version': 57}, 'FRA'), ({observation.CAPABILITY: False}, 'FRA'),
    ({'native_war_declaration_wire': True}, 'FRA'), ({}, 'POR'),
])
def test_unsupported_source_is_not_discovered(tmp_path, changes, observer):
    session, journal, source = make_source(tmp_path, ack=declaration_ack(**changes), events=[declaration()], observer=observer)
    try:
        assert observation.EVENT_TYPE not in source.event_types
        if observer == 'FRA':
            assert session.read_native_war_declaration_events()['gaps'] == ['WAR_DECLARATION_SOURCE_UNAVAILABLE']
    finally:
        journal.close()


def test_subscription_roles_full_result_cold_reopen_dedup_and_later_event(tmp_path, monkeypatch):
    session, journal, source = make_source(tmp_path, ack=declaration_ack(),
        events=[declaration(1), declaration(2, third_party=True)])
    database = tmp_path/'information.sqlite3'
    try:
        with closing(InformationService(source, database)) as service:
            api = InformationTools(service)
            report = api.call('information_manage_report', {'request_id': 'declaration-report', 'operation': 'create',
                'config': {'name': 'Declared wars', 'detail': 'full', 'queries': [query()]}})['report']
            subscriptions = []
            for name, filters in (('all', {}), ('target-fra', {'actors': ['ENG'], 'recipients': ['FRA']})):
                subscriptions.append(api.call('information_manage_subscription', {
                    'request_id': 'declaration-sub-'+name, 'operation': 'create',
                    'config': {'name': name, 'kind': 'event', 'enabled': True, 'report_id': report['id'],
                               'event': {'types': [observation.EVENT_TYPE], **filters}}})['subscription'])
            results = api.call('information_tick', {'view': 'full'})['results']
            assert len(results) == 3 and all(result['complete'] for result in results)
            assert sorted(result['event']['payload']['recipient'] for result in results) == ['CAS', 'FRA', 'FRA']
            assert len({result['event']['event_id'] for result in results}) == 2
            assert all(result['event']['game_date'] == GAME_DATE for result in results)
            assert all(result['items'][0]['source']['projection'] == 'event_snapshot' for result in results)
            assert api.call('information_tick', {})['results'] == []
            filtered = subscriptions[1]
            api.call('information_manage_subscription', {'request_id': 'cancel-filtered', 'operation': 'cancel',
                'subscription_id': filtered['id'], 'expected_version': filtered['version']})

        fresh_session = LogSession(session.directory/'installation.json', session.game_exe)
        fresh_source = DiplomacySource(DiplomacyTools(journal, fresh_session))
        with closing(InformationService(fresh_source, database)) as reopened:
            api = InformationTools(reopened)
            for result in results:
                assert api.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})['items'] == result['items']
            assert api.call('information_tick', {})['results'] == []
            with (session.directory/'control-probe.jsonl').open('a', encoding='utf-8') as stream:
                stream.write(json.dumps(declaration(3, date_raw=GAME_DATE+24))+'\n')
            later = api.call('information_tick', {'view': 'full'})['results']
            assert len(later) == 1 and later[0]['event']['game_date'] == GAME_DATE+24
            api.call('information_manage_subscription', {'request_id': 'cancel-all', 'operation': 'cancel',
                'subscription_id': subscriptions[0]['id'], 'expected_version': subscriptions[0]['version']})

        def forbidden(*args, **kwargs):
            pytest.fail('Declaration snapshot replay attempted to refresh native state')

        monkeypatch.setattr(fresh_session, 'read_native_war_declaration_events', forbidden)
        monkeypatch.setattr(fresh_session, 'read_native_alliance_inbound_offers', forbidden)
        for result in results:
            event = result['event']
            replay = fresh_source.read_event(query(), fresh_source.context(), event)
            assert replay['complete'] and replay['game_date'] == GAME_DATE
            assert replay['fields']['event_payload']['value'] == observation.project_role_labels(event['payload'])
    finally:
        journal.close()


def test_malformed_snapshot_and_wrong_selector_fail_without_live_read(tmp_path, monkeypatch):
    session, journal, source = make_source(tmp_path, ack=declaration_ack(), events=[declaration()])
    try:
        event = source.poll_events(source.context(), None)['events'][0]
        monkeypatch.setattr(session, 'read_native_war_declaration_events', lambda **kwargs: pytest.fail('native read'))
        for changes in ({'session_id': 'other'}, {'observer': 'POR'}, {'objects': []},
                        {'payload': {**event['payload'], 'observer_side': 'side_a'}},
                        {'source': {**event['source'], 'date_semantics': 'collected_date'}}):
            invalid = deepcopy(event)
            invalid.update(changes)
            assert not source.replay_event(query(), source.context(), invalid)['complete']
        other = query()
        other['parameters']['event_type'] = 'rival_changed'
        assert not source.replay_event(other, source.context(), event)['complete']
    finally:
        journal.close()


def test_shared_log_partial_line_reset_and_malformed_rows_report_source_gaps(tmp_path):
    session, journal, source = make_source(tmp_path, ack=declaration_ack())
    try:
        log = session.directory/'control-probe.jsonl'
        session.read_native_war_declaration_events()
        encoded = json.dumps(declaration()).encode()
        with log.open('ab') as stream:
            stream.write(encoded[:40])
        assert session.read_native_war_declaration_events()['events'] == []
        with log.open('ab') as stream:
            stream.write(encoded[40:]+b'\n')
        assert len(session.read_native_war_declaration_events()['events']) == 1
        with log.open('ab') as stream:
            stream.write(b'invalid JSON\n')
        assert 'WAR_DECLARATION_LOG_INVALID_JSON' in session.read_native_war_declaration_events()['gaps']
        log.write_text(json.dumps(declaration_ack())+'\n', encoding='utf-8')
        assert 'WAR_DECLARATION_LOG_RESET' in session.read_native_war_declaration_events()['gaps']
    finally:
        journal.close()


def test_actual_fra_bur_declaration_delivers_role_labels_and_preserves_native_snapshot(tmp_path, monkeypatch):
    fixture = json.loads((Path(__file__).parent / 'fixtures' /
        'information_war_FRA_BUR_declaration_live_1374.json').read_text(encoding='utf-8'))
    native = fixture['event']
    assert fixture['evidence_kind'] == 'observed_runtime'
    assert observation.supported_ack(fixture['installation_ack'], fixture['game_sha256'])
    public = observation.public_observation(native, native['session_id'])
    assert public is not None
    session, journal, source = make_source(
        tmp_path, events=[native], session_id=native['session_id'],
        game_sha=fixture['game_sha256'], ack=fixture['installation_ack'],
    )
    session.game_date = native['date_raw']
    database = tmp_path / 'information.sqlite3'
    try:
        with closing(InformationService(source, database)) as service:
            api = InformationTools(service)
            report = api.call('information_manage_report', {
                'request_id': 'actual-war-report', 'operation': 'create',
                'config': {'name': 'Actual declaration', 'detail': 'full', 'queries': [query()]},
            })['report']
            sub = api.call('information_manage_subscription', {
                'request_id': 'actual-war-sub', 'operation': 'create',
                'config': {'name': 'Actual declaration', 'kind': 'event', 'enabled': True,
                    'report_id': report['id'], 'event': {
                        'types': ['war_declared'], 'actors': ['FRA'], 'recipients': ['BUR'],
                    }},
            })['subscription']
            results = api.call('information_tick', {})['results']
            assert len(results) == 1
            delivered = results[0]
            payload = delivered['items'][0]['event_payload']
            assert payload['attackers'] == ['FRA', 'AMG', 'AUV', 'BOU', 'FOI', 'ORL']
            assert payload['defenders'] == ['BUR', 'BRB', 'FLA', 'HOL']
            assert payload['observer_role'] == 'attacker'
            assert not {'participants', 'observer_side', 'role_basis'} & set(payload)
            assert 'payload' not in delivered['event']
            full = api.call('information_get_result', {'result_id': delivered['result_id'], 'view': 'full'})
            assert full['event']['payload'] == public['payload']
            assert full['event']['event_id'] == public['event_id']
            assert full['items'][0]['fields']['event_payload']['value'] == observation.project_role_labels(public['payload'])
            legacy = deepcopy(full)
            legacy['items'][0]['fields']['event_payload']['value'] = deepcopy(public['payload'])
            legacy_payload = present_concise(legacy)['items'][0]['event_payload']
            assert legacy_payload['participants']['side_a'] == public['payload']['participants']['side_a']
            assert legacy_payload['participants']['side_b'] == public['payload']['participants']['side_b']
            assert api.call('information_tick', {})['results'] == []
            api.call('information_manage_subscription', {
                'request_id': 'actual-war-cancel', 'operation': 'cancel',
                'subscription_id': sub['id'], 'expected_version': sub['version'],
            })

        def forbidden(*args, **kwargs):
            pytest.fail('Declaration replay attempted a new live observation')

        monkeypatch.setattr(session, 'read_native_war_declaration_events', forbidden)
        with closing(InformationService(source, database)) as reopened:
            assert reopened.get_result(full['result_id'])['items'] == full['items']
            replay = source.replay_event(query(), source.context(), full['event'])
            assert replay['fields']['event_payload'] == full['items'][0]['fields']['event_payload']
    finally:
        journal.close()
