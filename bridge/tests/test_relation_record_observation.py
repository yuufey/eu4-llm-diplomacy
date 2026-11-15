"""Strict compatibility tests for relation command wire 1 and alliance-record wire 2."""
from copy import deepcopy

import pytest

from bridge import relation_observation as observation
from bridge.tests.test_information_relation_events import relation as _relation_fixture, relation_ack


GAME_SHA = observation.GAME_SHA256
SESSION = '332-relation-record-session'
DATE = 56_700_000


def relation(*args, **kwargs):
    event = _relation_fixture(*args, **kwargs)
    event['session_id'] = SESSION
    return event


def legacy_ack(version=50, **changes):
    ack = relation_ack(version=version)
    ack.update(changes)
    return ack


def record_ack(**changes):
    ack = relation_ack(version=54)
    ack.update({
        observation.CAPABILITY: True,
        observation.RECORD_CAPABILITY: True,
        'native_relation_change_wire': 2,
        'native_relation_change_scope': observation.RECORD_SCOPE,
    })
    ack.update(changes)
    return ack


def fullref(tag, slot, generation=0x1200):
    value = (generation << 48) | (slot << 32) | int.from_bytes(tag.encode('ascii'), 'little')
    return f'0x{value:x}'


def record(sequence=1, *, path='alliance_record_enable', kind='alliance', before=False, after=True,
           actor='ENG', recipient='FRA', **changes):
    event = relation(sequence, kind=kind, before=before, after=after, actor=actor, recipient=recipient)
    event.update({
        'schema_version': 2,
        'source': observation.RECORD_SOURCE,
        'observation_path': path,
        'command_state': 2 if path == 'command_return' else None,
        'command_mode': 1 if path == 'command_return' else None,
    })
    event.update(changes)
    return event


def snapshot_from_native(event):
    public = observation.public_observation(event, SESSION)
    assert public is not None
    scope = public['payload']['scope']
    return {
        'event_id': public['event_id'], 'event_type': observation.EVENT_TYPE,
        'session_id': SESSION, 'observer': 'FRA', 'game_date': public['game_date'],
        'objects': deepcopy(public['objects']), 'payload': deepcopy(public['payload']),
        'complete': True,
        'source': {
            'name': 'ObserverSession.read_native_relation_events', 'mode': 'live',
            'session_id': SESSION, 'native_sequence': public['native_sequence'], 'complete': True,
            'scope': scope, 'date_semantics': observation.DATE_SEMANTICS_BY_SCOPE[scope],
        },
    }


@pytest.mark.parametrize('version', [50, 51, 52, 53])
def test_wire1_ack_and_archived_payload_snapshot_remain_compatible(version):
    assert observation.supported_ack(legacy_ack(version), GAME_SHA)
    assert not observation.supported_record_ack(legacy_ack(version), GAME_SHA)
    native = relation(sequence=1)
    public = observation.public_observation(native, SESSION)
    assert public['payload'] == {
        'country': 'FRA', 'actor': 'ENG', 'recipient': 'FRA', 'relation_kind': 'alliance',
        'command_state': 2, 'command_mode': 1,
        'before': {'active': False, 'guarantee': None, 'support_roles': None, 'subject': None},
        'after': {'active': True, 'guarantee': None, 'support_roles': None, 'subject': None},
        'scope': observation.SCOPE,
    }
    assert public['event_id'] == observation.event_id(SESSION, 1)
    archived = snapshot_from_native(native)
    context = {'session_id': SESSION, 'observer': 'FRA', 'game_sha256': GAME_SHA}
    assert observation.valid_event_snapshot(archived, context)


def test_wire2_ack_requires_v54_through_v56_and_both_literal_capabilities():
    ack = record_ack()
    assert observation.supported_ack(ack, GAME_SHA)
    assert observation.supported_record_ack(ack, GAME_SHA)
    ack55 = record_ack(version=55)
    assert observation.supported_ack(ack55, GAME_SHA)
    assert observation.supported_record_ack(ack55, GAME_SHA)
    ack56 = record_ack(version=56)
    assert observation.supported_ack(ack56, GAME_SHA)
    assert observation.supported_record_ack(ack56, GAME_SHA)
    bad = [
        (record_ack(**{observation.CAPABILITY: 1}), GAME_SHA),
        (record_ack(**{observation.RECORD_CAPABILITY: 1}), GAME_SHA),
        (record_ack(**{observation.RECORD_CAPABILITY: False}), GAME_SHA),
        (record_ack(native_relation_change_wire=True), GAME_SHA),
        (record_ack(native_relation_change_wire=1), GAME_SHA),
        (record_ack(native_relation_change_wire=3), GAME_SHA),
        (record_ack(native_relation_change_scope=observation.SCOPE), GAME_SHA),
        (record_ack(version=57), GAME_SHA),
        (record_ack(version=True), GAME_SHA),
        (record_ack(), '0' * 64),
        (legacy_ack(version=54), GAME_SHA),
        (legacy_ack(version=53, **{observation.RECORD_CAPABILITY: True}), GAME_SHA),
    ]
    assert all(not observation.supported_ack(candidate, sha) for candidate, sha in bad)
    assert not observation.supported_ack(None, GAME_SHA)
    assert not observation.supported_record_ack(legacy_ack(version=53), GAME_SHA)


def test_capability_scope_and_semantics_map():
    assert observation.scope_for_capabilities({observation.CAPABILITY}) == observation.SCOPE
    assert observation.scope_for_capabilities({observation.CAPABILITY, observation.RECORD_CAPABILITY}) == observation.RECORD_SCOPE
    assert observation.scope_for_capabilities({observation.RECORD_CAPABILITY}) is None
    assert observation.scope_for_capabilities(None) is None
    assert observation.DATE_SEMANTICS_BY_SCOPE == {
        observation.SCOPE: observation.DATE_SEMANTICS,
        observation.RECORD_SCOPE: observation.RECORD_DATE_SEMANTICS,
        observation.ROYAL_RECORD_SCOPE: observation.RECORD_DATE_SEMANTICS,
        observation.DIRECTED_RECORD_SCOPE: observation.RECORD_DATE_SEMANTICS,
        observation.SUPPORT_SUBJECT_RECORD_SCOPE: observation.RECORD_DATE_SEMANTICS,
    }


@pytest.mark.parametrize('path,before,after', [
    ('command_return', False, True),
    ('alliance_record_enable', False, True),
    ('alliance_record_disable', True, False),
])
def test_wire2_decodes_three_actual_relation_return_paths(path, before, after):
    native = record(path=path, before=before, after=after)
    public = observation.public_observation(native, SESSION)
    assert public['payload']['observation_path'] == path
    assert public['payload']['scope'] == observation.RECORD_SCOPE
    assert public['payload']['before']['active'] is before
    assert public['payload']['after']['active'] is after
    assert public['objects'] == [
        {'type': 'country_pair', 'actor': 'ENG', 'recipient': 'FRA'},
        {'type': 'country', 'country': 'ENG'}, {'type': 'country', 'country': 'FRA'},
    ]
    assert 'actor_fullref' not in public['payload'] and 'recipient_fullref' not in public['payload']
    assert public['event_id'] == observation.event_id(SESSION, 1)


@pytest.mark.parametrize('changes', [
    {'observation_path': 'unknown'}, {'observation_path': True},
    {'observation_path': 'alliance_record_enable', 'relation_kind': 'guarantee'},
    {'observation_path': 'alliance_record_disable', 'relation_kind': 'subject'},
    {'observation_path': 'alliance_record_enable', 'command_state': 2},
    {'observation_path': 'alliance_record_enable', 'command_mode': 1},
    {'observation_path': 'command_return', 'command_state': None},
    {'observation_path': 'command_return', 'command_mode': None},
    {'observation_path': 'command_return', 'command_state': True},
    {'observation_path': 'command_return', 'command_mode': False},
    {'observation_path': 'alliance_record_enable', 'completed': True},
])
def test_wire2_path_and_command_state_rules_are_strict(changes):
    assert observation.public_observation(record(**changes), SESSION) is None


@pytest.mark.parametrize('changes', [
    {'schema_version': True}, {'schema_version': 1}, {'schema_version': 2.0},
    {'schema_version': 3}, {'source': observation.SOURCE},
    {'source': observation.RECORD_SOURCE + '_wrong'}, {'complete': 1},
    {'sequence': True}, {'date_raw': True}, {'actor': 'ENG1'},
    {'actor_fullref': '0x123'}, {'recipient_fullref': []},
    {'country': 'POR'}, {'relation_kind': []}, {'extra': 1},
])
def test_wire2_malformed_rows_and_wire_mixing_are_rejected(changes):
    assert observation.public_observation(record(), SESSION) is not None
    assert observation.public_observation(record(**changes), SESSION) is None


def test_wire1_rejects_record_path_extra_and_wire2_requires_path():
    old_with_path = relation()
    old_with_path['observation_path'] = 'command_return'
    assert observation.public_observation(old_with_path, SESSION) is None
    new_without_path = record()
    del new_without_path['observation_path']
    assert observation.public_observation(new_without_path, SESSION) is None


def test_record_paths_preserve_fullref_slot_checks_and_generation():
    native = record(actor='FRA', recipient='CAS')
    native['actor_fullref'] = fullref('FRA', 122)
    native['recipient_fullref'] = fullref('CAS', 90)
    assert observation.public_observation(native, SESSION) is not None
    native['actor_fullref'] = fullref('ENG', 122)
    assert observation.public_observation(native, SESSION) is None
    native = record()
    native['recipient_fullref'] = fullref('FRA', 4096)
    assert observation.public_observation(native, SESSION) is None


@pytest.mark.parametrize('wire', [1, 2])
def test_snapshot_scope_source_date_semantics_and_payload_shape_match(wire):
    native = relation() if wire == 1 else record(path='alliance_record_enable')
    event = snapshot_from_native(native)
    context = {'session_id': SESSION, 'observer': 'FRA', 'game_sha256': GAME_SHA}
    assert observation.valid_event_snapshot(event, context)
    for field, value in (
        ('scope', observation.RECORD_SCOPE if wire == 1 else observation.SCOPE),
        ('date_semantics', observation.RECORD_DATE_SEMANTICS if wire == 1 else observation.DATE_SEMANTICS),
    ):
        mixed = deepcopy(event)
        mixed['source'][field] = value
        assert not observation.valid_event_snapshot(mixed, context)
    mixed = deepcopy(event)
    mixed['payload']['scope'] = observation.RECORD_SCOPE if wire == 1 else observation.SCOPE
    assert not observation.valid_event_snapshot(mixed, context)
    mixed = deepcopy(event)
    if wire == 1:
        mixed['payload']['observation_path'] = 'command_return'
    else:
        del mixed['payload']['observation_path']
    assert not observation.valid_event_snapshot(mixed, context)


def test_collector_wire_isolation_and_health_gap_passthrough():
    old = observation.Collector(SESSION)
    old.observe(record())
    assert old.batch(0)['events'] == []
    assert old.batch(0)['gaps'] == ['RELATION_OBSERVATION_INVALID']

    new = observation.Collector(SESSION)
    new.observe(relation(), allow_record=True)
    assert new.batch(0)['events'] == []
    assert new.batch(0)['gaps'] == ['RELATION_OBSERVATION_INVALID']

    new = observation.Collector(SESSION)
    new.observe(record(sequence=1), allow_record=True)
    new.observe({'event': observation.NATIVE_GAP, 'session_id': SESSION, 'dropped': 1, 'complete': False})
    batch = new.batch(0)
    assert len(batch['events']) == 1
    assert batch['events'][0]['payload']['scope'] == observation.RECORD_SCOPE
    assert batch['gaps'] == ['RELATION_CAPTURE_DROPPED']

