"""Strict compatibility tests for mission completion wire 1 and wire 2."""
from copy import deepcopy

import pytest

from bridge import mission_observation as observation
from bridge.tests.test_information_relation_events import relation_ack
from bridge.tests.test_relation_record_observation import record_ack


GAME_SHA = observation.GAME_SHA256
SESSION = '330-mission-set-session'
DATE = 56_700_000


def fullref(tag='FRA', slot=7, generation=0x1200):
    return f'0x{((generation << 48) | (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")):x}'


def legacy_ack(version=51, **changes):
    ack = relation_ack(version=version)
    ack.update({observation.CAPABILITY: True,
                'native_mission_completion_wire': 1,
                'native_mission_completion_scope': observation.SCOPE})
    ack.update(changes)
    return ack


def set_ack(**changes):
    ack = relation_ack(version=53)
    ack.update({observation.CAPABILITY: True,
                observation.SET_CAPABILITY: True,
                'native_mission_completion_wire': 2,
                'native_mission_completion_scope': observation.SET_SCOPE})
    ack.update(changes)
    return ack


def native(sequence=1, *, name='french_reconquest', schema=1,
           completion_path='command_handler', **changes):
    event = {
        'event': observation.NATIVE_EVENT,
        'schema_version': schema,
        'session_id': SESSION,
        'sequence': sequence,
        'country': 'FRA',
        'country_fullref': fullref(),
        'date_raw': DATE,
        'mission_id_hex': name.encode('ascii').hex(),
        'completed_before': False,
        'completed_after': True,
        'source': observation.SOURCE if schema == 1 else observation.SET_SOURCE,
        'complete': True,
    }
    if schema in (2, 3):
        event['completion_path'] = completion_path
    event.update(changes)
    return event


def snapshot_from_native(event):
    public = observation.public_observation(event, SESSION)
    assert public is not None
    scope = public['payload']['scope']
    return {
        'event_id': public['event_id'],
        'event_type': observation.EVENT_TYPE,
        'session_id': SESSION,
        'observer': public['payload']['country'],
        'game_date': public['game_date'],
        'collected_game_date': DATE + 1,
        'objects': deepcopy(public['objects']),
        'payload': deepcopy(public['payload']),
        'complete': True,
        'sequence': 1,
        'source': {
            'name': 'ObserverSession.read_native_mission_events',
            'mode': 'live', 'session_id': SESSION,
            'native_sequence': public['native_sequence'], 'complete': True,
            'scope': scope,
            'date_semantics': observation.DATE_SEMANTICS_BY_SCOPE[scope],
        },
    }


@pytest.mark.parametrize('version', [51, 52])
def test_wire1_ack_and_archive_shape_remain_compatible(version):
    ack = legacy_ack(version)
    assert observation.supported_ack(ack, GAME_SHA)
    assert not observation.supported_set_ack(ack, GAME_SHA)
    event = native()
    decoded = observation.public_observation(event, SESSION)
    assert decoded == {
        'event_id': observation.event_id(SESSION, 1),
        'native_sequence': 1,
        'game_date': DATE,
        'objects': [{'type': 'country', 'country': 'FRA'}],
        'payload': {
            'country': 'FRA', 'mission_id': 'french_reconquest',
            'completed_before': False, 'completed_after': True, 'scope': observation.SCOPE,
        },
    }
    snap = snapshot_from_native(event)
    context = {'session_id': SESSION, 'observer': 'FRA', 'game_sha256': GAME_SHA}
    assert observation.valid_event_snapshot(snap, context)


def test_new_scope_can_bind_turkish_mission_and_reject_foreign_replay():
    event = native(schema=3, name='turkish_mission', country='TUR', country_fullref=fullref('TUR'))
    snapshot = snapshot_from_native(event)
    assert snapshot['payload']['country'] == 'TUR'
    assert snapshot['payload']['scope'] == observation.CONFIGURED_SET_SCOPE
    context = {'session_id': SESSION, 'observer': 'TUR', 'game_sha256': GAME_SHA}
    assert observation.valid_event_snapshot(snapshot, context)
    assert not observation.valid_event_snapshot(snapshot, context | {'observer': 'FRA'})
    assert observation.public_observation(event | {'country': 'ENG'}, SESSION) is None
    collector = observation.Collector(SESSION)
    collector.observe(event, allow_set=True, allow_scoped=True)
    assert collector.batch(0)['events'][0]['payload']['country'] == 'TUR'


def test_new_wire_ack_requires_both_capabilities_exact_scope_and_wire():
    ack = set_ack()
    assert observation.supported_ack(ack, GAME_SHA)
    assert observation.supported_set_ack(ack, GAME_SHA)
    assert not observation.supported_ack(legacy_ack(version=53), GAME_SHA)
    assert not observation.supported_set_ack(legacy_ack(version=52,
        **{observation.SET_CAPABILITY: True}), GAME_SHA)

    invalid = [
        (set_ack(**{observation.CAPABILITY: 1}), GAME_SHA),
        (set_ack(**{observation.SET_CAPABILITY: 1}), GAME_SHA),
        (set_ack(**{observation.SET_CAPABILITY: False}), GAME_SHA),
        (set_ack(native_mission_completion_wire=True), GAME_SHA),
        (set_ack(native_mission_completion_wire=1), GAME_SHA),
        (set_ack(native_mission_completion_wire=3), GAME_SHA),
        (set_ack(native_mission_completion_scope=observation.SCOPE), GAME_SHA),
        (set_ack(version=54), GAME_SHA),
        (set_ack(), '0' * 64),
        (set_ack(version=True), GAME_SHA),
    ]
    assert all(not observation.supported_ack(candidate, sha) for candidate, sha in invalid)
    assert not observation.supported_ack(None, GAME_SHA)


def test_wire2_ack_supports_v56_and_rejects_future_v57():
    ack = record_ack(version=56)
    ack.update({
        observation.CAPABILITY: True,
        observation.SET_CAPABILITY: True,
        'native_mission_completion_wire': 2,
        'native_mission_completion_scope': observation.SET_SCOPE,
    })
    assert observation.supported_ack(ack, GAME_SHA)
    assert observation.supported_set_ack(ack, GAME_SHA)
    future = dict(ack, version=57)
    assert not observation.supported_ack(future, GAME_SHA)
    assert not observation.supported_set_ack(future, GAME_SHA)


def test_legacy_ack_cannot_copy_the_new_set_capability_or_wire():
    copied = legacy_ack(version=52, **{observation.SET_CAPABILITY: True})
    assert not observation.supported_ack(copied, GAME_SHA)
    assert not observation.supported_set_ack(copied, GAME_SHA)
    assert not observation.supported_ack(legacy_ack(version=52, native_mission_completion_wire=2), GAME_SHA)
    assert not observation.supported_ack(legacy_ack(version=52, native_mission_completion_wire=True), GAME_SHA)


def test_capability_scope_selection_and_date_semantics_are_explicit():
    assert observation.scope_for_capabilities({observation.CAPABILITY}) == observation.SCOPE
    assert observation.scope_for_capabilities({observation.CAPABILITY, observation.SET_CAPABILITY}) == observation.SET_SCOPE
    assert observation.scope_for_capabilities({observation.SET_CAPABILITY}) is None
    assert observation.scope_for_capabilities(None) is None
    assert observation.DATE_SEMANTICS_BY_SCOPE == {
        observation.SCOPE: observation.DATE_SEMANTICS,
        observation.SET_SCOPE: observation.SET_DATE_SEMANTICS,
        observation.CONFIGURED_SET_SCOPE: observation.SET_DATE_SEMANTICS,
    }


@pytest.mark.parametrize('path', ['command_handler', 'script_effect'])
@pytest.mark.parametrize('name', ['mission"quote\\slash', 'a' * 256])
def test_wire2_public_payload_preserves_path_and_printable_name(path, name):
    event = native(name=name, schema=2, completion_path=path)
    decoded = observation.public_observation(event, SESSION)
    assert decoded['payload'] == {
        'country': 'FRA', 'mission_id': name,
        'completed_before': False, 'completed_after': True,
        'scope': observation.SET_SCOPE, 'completion_path': path,
    }
    assert decoded['objects'] == [{'type': 'country', 'country': 'FRA'}]
    assert 'country_fullref' not in decoded['payload']
    assert decoded['event_id'] == observation.event_id(SESSION, 1)
    assert observation.event_id(SESSION, 1) == observation.event_id(SESSION, 1)


@pytest.mark.parametrize('changes', [
    {'schema_version': True}, {'schema_version': 1.0}, {'schema_version': 4},
    {'sequence': True}, {'date_raw': True}, {'complete': 1},
    {'completed_before': 0}, {'completed_before': True},
    {'completed_after': 1}, {'completed_after': False},
    {'country': 'POR'}, {'country_fullref': fullref('ENG')},
    {'country_fullref': fullref(slot=4096)}, {'country_fullref': []},
    {'mission_id_hex': ''}, {'mission_id_hex': 'f'}, {'mission_id_hex': 'xyz'},
    {'mission_id_hex': '61' * 257}, {'mission_id_hex': '00'},
    {'source': 'other_source'}, {'event': 'native_mission_availability_changed'},
    {'session_id': 'other'}, {'extra': 1},
])
def test_wire1_malformed_or_mixed_rows_are_rejected(changes):
    assert observation.public_observation(native(**changes), SESSION) is None


@pytest.mark.parametrize('changes', [
    {'schema_version': True}, {'schema_version': 1}, {'schema_version': 2.0},
    {'schema_version': 4}, {'sequence': True}, {'date_raw': True}, {'complete': 1},
    {'completed_before': 1}, {'completed_before': True},
    {'completed_after': 0}, {'completed_after': False},
    {'country': 'POR'}, {'country_fullref': fullref('ENG')},
    {'country_fullref': fullref(slot=4096)}, {'country_fullref': []},
    {'mission_id_hex': ''}, {'mission_id_hex': '61' * 257}, {'mission_id_hex': 'ff'},
    {'source': observation.SOURCE}, {'event': 'native_mission_capture_gap'},
    {'completion_path': 'batch_initializer'}, {'completion_path': True},
    {'session_id': 'other'}, {'extra': 1},
])
def test_wire2_malformed_or_mixed_rows_are_rejected(changes):
    assert observation.public_observation(native(schema=2, **changes), SESSION) is None


def test_v1_wire_does_not_accept_v2_field_and_v2_wire_requires_path():
    legacy_with_path = native()
    legacy_with_path['completion_path'] = 'command_handler'
    assert observation.public_observation(legacy_with_path, SESSION) is None
    modern_without_path = native(schema=2)
    del modern_without_path['completion_path']
    assert observation.public_observation(modern_without_path, SESSION) is None
    for source in (observation.SOURCE, observation.SET_SOURCE + '_wrong'):
        assert observation.public_observation(native(schema=2, source=source), SESSION) is None


def test_fullref_keeps_nonzero_high_generation_and_rejects_bad_tag_or_slot():
    accepted = observation.public_observation(native(), SESSION)
    assert accepted is not None
    assert observation.public_observation(native(country_fullref=fullref('ENG')), SESSION) is None
    assert observation.public_observation(native(country_fullref=fullref(slot=4096)), SESSION) is None


@pytest.mark.parametrize('schema', [1, 2])
def test_snapshot_scope_date_and_payload_shapes_cannot_be_mixed(schema):
    event = snapshot_from_native(native(schema=schema))
    context = {'session_id': SESSION, 'observer': 'FRA', 'game_sha256': GAME_SHA}
    assert observation.valid_event_snapshot(event, context)

    mixed = deepcopy(event)
    mixed['source']['scope'] = observation.SET_SCOPE if schema == 1 else observation.SCOPE
    assert not observation.valid_event_snapshot(mixed, context)
    mixed = deepcopy(event)
    mixed['source']['date_semantics'] = observation.DATE_SEMANTICS if schema == 2 else observation.SET_DATE_SEMANTICS
    assert not observation.valid_event_snapshot(mixed, context)
    mixed = deepcopy(event)
    mixed['payload']['scope'] = observation.SET_SCOPE if schema == 1 else observation.SCOPE
    assert not observation.valid_event_snapshot(mixed, context)

    if schema == 1:
        mixed = deepcopy(event)
        mixed['payload']['completion_path'] = 'command_handler'
    else:
        mixed = deepcopy(event)
        del mixed['payload']['completion_path']
    assert not observation.valid_event_snapshot(mixed, context)


def test_collector_wire_isolation_and_replay_conflicts():
    legacy_collector = observation.Collector(SESSION)
    legacy_collector.observe(native())
    legacy_collector.observe(native(sequence=2, schema=2))
    assert [row['payload']['scope'] for row in legacy_collector.batch(0)['events']] == [observation.SCOPE]
    assert legacy_collector.batch(0)['gaps'] == ['MISSION_OBSERVATION_INVALID']

    set_collector = observation.Collector(SESSION)
    set_collector.observe(native(), allow_set=True)
    assert set_collector.batch(0)['events'] == []
    assert set_collector.batch(0)['gaps'] == ['MISSION_OBSERVATION_INVALID']

    set_collector = observation.Collector(SESSION)
    first = native(sequence=1, schema=2, completion_path='command_handler')
    second = native(sequence=2, schema=2, completion_path='script_effect')
    set_collector.observe(first, allow_set=True)
    set_collector.observe(second, allow_set=True)
    batch = set_collector.batch(0)
    assert batch['complete'] and not batch['gaps']
    assert [row['native_sequence'] for row in batch['events']] == [1, 2]
    assert all(row['payload']['scope'] == observation.SET_SCOPE for row in batch['events'])
    assert batch['events'][0]['payload']['completion_path'] == 'command_handler'
    assert batch['events'][1]['payload']['completion_path'] == 'script_effect'

    set_collector.observe(native(sequence=2, schema=2, completion_path='command_handler'), allow_set=True)
    assert set_collector.batch(0)['gaps'] == ['MISSION_SEQUENCE_CONFLICT']


def test_snapshot_requires_valid_path_and_event_identity():
    context = {'session_id': SESSION, 'observer': 'FRA', 'game_sha256': GAME_SHA}
    event = snapshot_from_native(native(schema=2, completion_path='command_handler'))
    assert observation.valid_event_snapshot(event, context)
    event['payload']['completion_path'] = 'unknown'
    assert not observation.valid_event_snapshot(event, context)
    event = snapshot_from_native(native(schema=2, completion_path='script_effect'))
    event['event_id'] = 'wrong'
    assert not observation.valid_event_snapshot(event, context)
