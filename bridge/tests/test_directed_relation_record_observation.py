"""Strict public wire-4 decoding and session delivery for directed records."""
from contextlib import closing
from copy import deepcopy
import json

import pytest

from bridge import relation_observation as observation
from bridge.diplomacy import DiplomacyTools, ObserverSession
from bridge.information import InformationService
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools
from bridge.tests.test_information_country_modifier_events import (
    GAME_DATE as INFO_GAME_DATE,
    GAME_SHA as INFO_GAME_SHA,
    SESSION_ID as INFO_SESSION_ID,
    LogSession,
    make_source,
)
from bridge.tests.test_information_relation_events import query as relation_query
from bridge.tests.test_royal_relation_record_observation import (
    SESSION as ROYAL_SESSION,
    ack as royal_ack,
    royal_record,
    snapshot as snapshot_from_native,
)


GAME_SHA = observation.GAME_SHA256


def directed_ack(*, version=59, session_id=ROYAL_SESSION, **changes):
    """Extend the established complete v58 parent ACK with the v59 contract."""
    value = royal_ack(58)
    value.update({
        'session_id': session_id,
        'version': version,
        'native_relation_change_wire': 4,
        'native_relation_change_scope': observation.DIRECTED_RECORD_SCOPE,
        observation.DIRECTED_RECORD_CAPABILITY: True,
    })
    value.update(changes)
    return value


def directed_record(sequence=1, *, path='guarantee_record_enable', kind='guarantee',
                    before=False, after=True, **changes):
    """Reuse the established native relation fixture and promote it to schema 4."""
    event = royal_record(sequence, path=path, kind=kind, before=before, after=after)
    event.update({
        'schema_version': 4,
        'source': observation.DIRECTED_RECORD_SOURCE,
    })
    event.update(changes)
    return event


def _session_with_log(directory, ack_event, events):
    directory.mkdir(parents=True, exist_ok=True)
    record = {
        'experiment_id': 'directed-relation-record-350',
        'session_id': ROYAL_SESSION,
        'game_sha256': GAME_SHA,
        'game_version': '1.37.4',
        'dll_sha256': 'd' * 64,
        'observer': 'FRA',
        'world_id': 'directed-relation-record-world',
    }
    installation = directory / 'installation.json'
    installation.write_text(json.dumps(record), encoding='utf-8')
    rows = [ack_event, *events]
    (directory / 'control-probe.jsonl').write_text(
        ''.join(json.dumps(row, separators=(',', ':')) + '\n' for row in rows),
        encoding='utf-8',
    )
    return ObserverSession(installation, directory / 'unused-game.exe')


@pytest.mark.parametrize('path,kind,before,after', [
    ('alliance_record_enable', 'alliance', False, True),
    ('alliance_record_disable', 'alliance', True, False),
    ('royal_record_enable', 'royal_marriage', False, True),
    ('royal_record_disable', 'royal_marriage', True, False),
    ('guarantee_record_enable', 'guarantee', False, True),
    ('guarantee_record_disable', 'guarantee', True, False),
    ('military_record_enable', 'military_access', False, True),
    ('military_record_disable', 'military_access', True, False),
])
def test_schema4_decodes_the_eight_direct_record_paths(path, kind, before, after):
    event = directed_record(path=path, kind=kind, before=before, after=after)
    public = observation.public_observation(event, ROYAL_SESSION)

    assert public is not None
    assert public['payload']['scope'] == observation.DIRECTED_RECORD_SCOPE
    assert public['payload']['observation_path'] == path
    assert public['payload']['relation_kind'] == kind
    assert public['payload']['command_state'] is None
    assert public['payload']['command_mode'] is None


@pytest.mark.parametrize('kind', observation.KINDS)
def test_schema4_command_return_keeps_the_six_relation_kinds(kind):
    public = observation.public_observation(
        directed_record(path='command_return', kind=kind), ROYAL_SESSION)

    assert public is not None
    assert public['payload']['observation_path'] == 'command_return'
    assert public['payload']['relation_kind'] == kind
    assert public['payload']['command_state'] == 2
    assert public['payload']['command_mode'] == 1


def test_guarantee_direction_change_preserves_both_bits_when_or_is_unchanged():
    event = directed_record(path='guarantee_record_enable', kind='guarantee', before=True, after=True)
    event['before']['guarantee'] = {'actor_grants': True, 'recipient_grants': False}
    event['after']['guarantee'] = {'actor_grants': False, 'recipient_grants': True}

    public = observation.public_observation(event, ROYAL_SESSION)

    assert public is not None
    assert public['payload']['before']['active'] is True
    assert public['payload']['after']['active'] is True
    assert public['payload']['before']['guarantee'] == {
        'actor_grants': True, 'recipient_grants': False}
    assert public['payload']['after']['guarantee'] == {
        'actor_grants': False, 'recipient_grants': True}


@pytest.mark.parametrize('changes', [
    {'observation_path': 'unknown'},
    {'observation_path': 'alliance_record_enable', 'relation_kind': 'guarantee'},
    {'observation_path': 'royal_record_disable', 'relation_kind': 'alliance'},
    {'observation_path': 'guarantee_record_enable', 'relation_kind': 'military_access'},
    {'observation_path': 'military_record_disable', 'relation_kind': 'guarantee'},
    {'observation_path': 'alliance_record_enable', 'command_state': 2},
    {'observation_path': 'royal_record_enable', 'command_mode': 1},
    {'observation_path': 'command_return', 'command_state': None},
    {'observation_path': 'command_return', 'command_mode': None},
    {'observation_path': 'command_return', 'command_state': True},
    {'observation_path': 'command_return', 'command_mode': False},
    {'schema_version': True},
    {'schema_version': 3},
    {'schema_version': 4.0},
    {'source': observation.ROYAL_RECORD_SOURCE},
    {'source': observation.DIRECTED_RECORD_SOURCE + '_wrong'},
    {'complete': 1},
    {'sequence': True},
    {'date_raw': True},
    {'extra': 1},
])
def test_schema4_rejects_path_kind_state_and_integer_mismatches(changes):
    assert observation.public_observation(directed_record(**changes), ROYAL_SESSION) is None


def test_schema4_snapshot_keeps_directed_scope_and_record_date_semantics():
    archived = snapshot_from_native(directed_record())
    context = {'session_id': ROYAL_SESSION, 'observer': 'FRA', 'game_sha256': GAME_SHA}

    assert archived['payload']['scope'] == observation.DIRECTED_RECORD_SCOPE
    assert archived['source']['date_semantics'] == observation.RECORD_DATE_SEMANTICS
    assert observation.valid_event_snapshot(archived, context)
    changed = deepcopy(archived)
    changed['source']['scope'] = observation.ROYAL_RECORD_SCOPE
    assert not observation.valid_event_snapshot(changed, context)
    changed = deepcopy(archived)
    changed['source']['date_semantics'] = observation.DATE_SEMANTICS
    assert not observation.valid_event_snapshot(changed, context)


def test_v59_ack_requires_every_parent_capability_wire4_and_directed_scope():
    good = directed_ack()
    assert observation.supported_ack(good, GAME_SHA)
    assert observation.supported_record_ack(good, GAME_SHA)
    assert observation.supported_royal_record_ack(good, GAME_SHA)
    assert observation.supported_directed_record_ack(good, GAME_SHA)

    bad = []
    for capability in (observation.CAPABILITY, observation.RECORD_CAPABILITY,
                       observation.ROYAL_RECORD_CAPABILITY, observation.DIRECTED_RECORD_CAPABILITY):
        bad.append(directed_ack(**{capability: False}))
        bad.append(directed_ack(**{capability: 1}))
    bad.extend([
        directed_ack(native_relation_change_wire=True),
        directed_ack(native_relation_change_wire=3),
        directed_ack(native_relation_change_wire=5),
        directed_ack(native_relation_change_scope=observation.ROYAL_RECORD_SCOPE),
        directed_ack(version=60),
        directed_ack(version=True),
    ])
    assert all(not observation.supported_ack(candidate, GAME_SHA) for candidate in bad)
    assert all(not observation.supported_directed_record_ack(candidate, GAME_SHA) for candidate in bad)


def test_capability_scope_requires_the_full_directed_parent_chain():
    full = {observation.CAPABILITY, observation.RECORD_CAPABILITY,
            observation.ROYAL_RECORD_CAPABILITY, observation.DIRECTED_RECORD_CAPABILITY}
    assert observation.scope_for_capabilities(full) == observation.DIRECTED_RECORD_SCOPE
    assert observation.scope_for_capabilities(full - {observation.CAPABILITY}) is None
    assert observation.scope_for_capabilities(full - {observation.RECORD_CAPABILITY}) is None
    assert observation.scope_for_capabilities(full - {observation.ROYAL_RECORD_CAPABILITY}) is None
    assert observation.scope_for_capabilities(full - {observation.DIRECTED_RECORD_CAPABILITY}) == (
        observation.ROYAL_RECORD_SCOPE)


@pytest.mark.parametrize('flags,accepted', [
    ({}, False),
    ({'allow_record': True}, False),
    ({'allow_royal_record': True}, False),
    ({'allow_directed_record': True}, False),
    ({'allow_record': True, 'allow_royal_record': True}, False),
    ({'allow_record': True, 'allow_directed_record': True}, False),
    ({'allow_royal_record': True, 'allow_directed_record': True}, False),
    ({'allow_record': True, 'allow_royal_record': True, 'allow_directed_record': True}, True),
])
def test_collector_requires_all_three_flags_for_wire4(flags, accepted):
    collector = observation.Collector(ROYAL_SESSION)
    collector.observe(directed_record(), **flags)
    batch = collector.batch(0)

    assert bool(batch['events']) is accepted
    assert batch['gaps'] == ([] if accepted else ['RELATION_OBSERVATION_INVALID'])


def test_observer_session_consumes_v59_capabilities_and_wire4_records(tmp_path):
    event = directed_record()
    ack_event = directed_ack()
    session = _session_with_log(tmp_path, ack_event, [event])

    capabilities = session.installation_capabilities()
    assert {
        observation.CAPABILITY,
        observation.RECORD_CAPABILITY,
        observation.ROYAL_RECORD_CAPABILITY,
        observation.DIRECTED_RECORD_CAPABILITY,
    } <= capabilities
    batch = session.read_native_relation_events()
    assert batch['complete']
    assert batch['gaps'] == []
    assert len(batch['events']) == 1
    assert batch['events'][0]['payload']['scope'] == observation.DIRECTED_RECORD_SCOPE


def test_observer_session_rejects_untrusted_directed_caps_and_reports_source_unavailable(tmp_path):
    ack_event = directed_ack(**{observation.DIRECTED_RECORD_CAPABILITY: False})
    ack_event['caps'] = [observation.DIRECTED_RECORD_CAPABILITY]
    session = _session_with_log(tmp_path, ack_event, [directed_record()])

    capabilities = session.installation_capabilities()
    assert observation.DIRECTED_RECORD_CAPABILITY not in capabilities
    batch = session.read_native_relation_events()
    assert batch == {
        'events': [], 'complete': False, 'gaps': ['RELATION_SOURCE_UNAVAILABLE'],
    }


def test_c04_persists_and_reopens_schema4_directed_scope(tmp_path, monkeypatch):
    native = directed_record()
    native.update({'session_id': INFO_SESSION_ID, 'date_raw': INFO_GAME_DATE})
    ack_event = directed_ack(session_id=INFO_SESSION_ID)
    session, journal, source = make_source(
        tmp_path, events=[native], session_id=INFO_SESSION_ID, ack=ack_event)
    database = tmp_path / 'information.sqlite3'
    try:
        with closing(InformationService(source, database)) as service:
            api = InformationTools(service)
            report = api.call('information_manage_report', {
                'request_id': 'directed-relation-report', 'operation': 'create',
                'config': {'name': 'Directed relations', 'detail': 'full',
                           'queries': [relation_query()]},
            })['report']
            subscription = api.call('information_manage_subscription', {
                'request_id': 'directed-relation-subscription', 'operation': 'create',
                'config': {'name': 'Directed relations', 'kind': 'event', 'enabled': True,
                           'report_id': report['id'],
                           'event': {'types': [observation.EVENT_TYPE]}},
            })['subscription']
            results = api.call('information_tick', {'view': 'full'})['results']
            assert len(results) == 1
            result = results[0]
            archived = result['event']
            assert archived['payload']['scope'] == observation.DIRECTED_RECORD_SCOPE
            assert observation.valid_event_snapshot(archived, source.context())
            monkeypatch.setattr(session, 'read_native_relation_events',
                                lambda **kwargs: pytest.fail('snapshot replay queried the live relation log'))
            replay = source.replay_event(relation_query(), source.context(), archived)
            assert replay['complete']
            assert replay['game_date'] == INFO_GAME_DATE

        fresh_session = LogSession(session.directory / 'installation.json', session.game_exe)
        fresh_source = DiplomacySource(DiplomacyTools(journal, fresh_session))
        with closing(InformationService(fresh_source, database)) as service:
            api = InformationTools(service)
            assert api.call('information_tick', {})['results'] == []
            reopened = api.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})
            assert reopened['items'] == result['items']
            assert (reopened['items'][0]['fields']['event_payload']['value']['scope']
                    == observation.DIRECTED_RECORD_SCOPE)
            api.call('information_manage_subscription', {
                'request_id': 'directed-relation-subscription-cancel', 'operation': 'cancel',
                'subscription_id': subscription['id'], 'expected_version': subscription['version'],
            })
    finally:
        journal.close()
