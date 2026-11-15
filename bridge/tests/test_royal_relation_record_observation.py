"""Compatibility and strict wire-3 tests for royal-record observations."""
from copy import deepcopy

import pytest

from bridge import relation_observation as observation
from bridge import country_modifier_observation, mission_availability_observation
from bridge import mission_condition_observation, mission_observation, rival_observation
from bridge import war_declaration_observation
from bridge.tests.test_information_relation_events import relation as _relation_fixture, relation_ack


GAME_SHA = observation.GAME_SHA256
SESSION = 'royal-relation-record-session'
DATE = 56_700_000


def native_relation(sequence=1, *, kind='alliance', before=False, after=True, **changes):
    event = _relation_fixture(sequence=sequence, kind=kind, before=before, after=after)
    event['session_id'] = SESSION
    event['date_raw'] = DATE
    event.update(changes)
    return event


def royal_record(sequence=1, *, path='royal_record_enable', kind='royal_marriage', before=False,
                 after=True, actor='ENG', recipient='FRA', **changes):
    event = native_relation(sequence, kind=kind, before=before, after=after, actor=actor, recipient=recipient)
    event.update({
        'schema_version': 3,
        'source': observation.ROYAL_RECORD_SOURCE,
        'observation_path': path,
        'command_state': 2 if path == 'command_return' else None,
        'command_mode': 1 if path == 'command_return' else None,
    })
    event.update(changes)
    return event


def old_record(sequence=1, *, path='alliance_record_enable', before=False, after=True, **changes):
    event = native_relation(sequence, before=before, after=after)
    event.update({
        'schema_version': 2,
        'source': observation.RECORD_SOURCE,
        'observation_path': path,
        'command_state': 2 if path == 'command_return' else None,
        'command_mode': 1 if path == 'command_return' else None,
    })
    event.update(changes)
    return event


def ack(version, **changes):
    value = relation_ack(version=version)
    value.update({observation.CAPABILITY: True})
    if version <= 53:
        value.update({
            'native_relation_change_wire': 1,
            'native_relation_change_scope': observation.SCOPE,
        })
    elif version <= 57:
        value.update({
            observation.RECORD_CAPABILITY: True,
            'native_relation_change_wire': 2,
            'native_relation_change_scope': observation.RECORD_SCOPE,
        })
    else:
        value.update({
            observation.RECORD_CAPABILITY: True,
            observation.ROYAL_RECORD_CAPABILITY: True,
            'native_relation_change_wire': 3,
            'native_relation_change_scope': observation.ROYAL_RECORD_SCOPE,
        })
    if version in (57, 58):
        value.update({
            mission_observation.CAPABILITY: True,
            mission_observation.SET_CAPABILITY: True,
            'native_mission_completion_wire': 2,
            'native_mission_completion_scope': mission_observation.SET_SCOPE,
            mission_availability_observation.CAPABILITY: True,
            'native_mission_availability_wire': 1,
            'native_mission_availability_scope': mission_availability_observation.SCOPE,
            mission_condition_observation.CAPABILITY: True,
            mission_condition_observation.PROVINCE_CAPABILITY: True,
            'native_mission_condition_wire': 2,
            'native_mission_condition_scope': mission_condition_observation.COMBINED_SCOPE,
            country_modifier_observation.CAPABILITY: True,
            country_modifier_observation.REMOVE_CAPABILITY: True,
            country_modifier_observation.EXPIRY_CAPABILITY: True,
            'native_country_modifier_add_wire': 1,
            'native_country_modifier_scope': country_modifier_observation.SCOPE,
            'native_country_modifier_remove_wire': 1,
            'native_country_modifier_expiry_wire': 1,
            rival_observation.CAPABILITY: True,
            'native_rival_change_wire': 1,
            'native_rival_change_scope': rival_observation.SCOPE,
            war_declaration_observation.CAPABILITY: True,
            'native_war_declaration_wire': 1,
            'native_war_declaration_scope': war_declaration_observation.SCOPE,
        })
    value.update(changes)
    return value


def snapshot(native):
    public = observation.public_observation(native, SESSION)
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


@pytest.mark.parametrize('kind', observation.KINDS)
def test_wire3_command_return_supports_all_six_relation_kinds(kind):
    public = observation.public_observation(royal_record(path='command_return', kind=kind), SESSION)
    assert public is not None
    assert public['payload']['relation_kind'] == kind
    assert public['payload']['observation_path'] == 'command_return'
    assert public['payload']['command_state'] == 2
    assert public['payload']['command_mode'] == 1
    assert public['payload']['scope'] == observation.ROYAL_RECORD_SCOPE
    assert public['event_id'] == observation.event_id(SESSION, 1)


@pytest.mark.parametrize('path,before,after', [
    ('alliance_record_enable', False, True),
    ('alliance_record_disable', True, False),
    ('royal_record_enable', False, True),
    ('royal_record_disable', True, False),
])
def test_wire3_alliance_and_royal_record_returns(path, before, after):
    kind = 'alliance' if path.startswith('alliance_') else 'royal_marriage'
    public = observation.public_observation(
        royal_record(path=path, kind=kind, before=before, after=after), SESSION)
    assert public is not None
    assert public['payload']['observation_path'] == path
    assert public['payload']['command_state'] is None
    assert public['payload']['command_mode'] is None
    assert public['payload']['scope'] == observation.ROYAL_RECORD_SCOPE
    assert public['objects'] == [
        {'type': 'country_pair', 'actor': 'ENG', 'recipient': 'FRA'},
        {'type': 'country', 'country': 'ENG'}, {'type': 'country', 'country': 'FRA'},
    ]


@pytest.mark.parametrize('changes', [
    {'observation_path': 'unknown'},
    {'observation_path': 'alliance_record_enable'},
    {'observation_path': 'alliance_record_disable'},
    {'observation_path': 'royal_record_enable', 'relation_kind': 'alliance'},
    {'observation_path': 'royal_record_disable', 'relation_kind': 'guarantee'},
    {'observation_path': 'royal_record_enable', 'command_state': 2},
    {'observation_path': 'royal_record_disable', 'command_mode': 1},
    {'observation_path': 'command_return', 'command_state': None},
    {'observation_path': 'command_return', 'command_mode': None},
    {'observation_path': 'command_return', 'command_state': True},
    {'observation_path': 'command_return', 'command_mode': False},
    {'observation_path': 'command_return', 'command_state': 3},
    {'observation_path': 'command_return', 'command_mode': 2},
    {'observation_path': True},
    {'observation_path': 'royal_record_enable', 'extra': 1},
])
def test_wire3_path_kind_null_and_integer_rules_are_strict(changes):
    assert observation.public_observation(royal_record(**changes), SESSION) is None


@pytest.mark.parametrize('changes', [
    {'schema_version': True}, {'schema_version': 2}, {'schema_version': 3.0},
    {'source': observation.RECORD_SOURCE},
    {'source': observation.ROYAL_RECORD_SOURCE + '_wrong'},
    {'complete': 1}, {'sequence': True}, {'date_raw': True},
    {'country': 'POR'}, {'actor': 'ENG1'}, {'relation_kind': []}, {'extra': 1},
])
def test_wire3_requires_exact_native_shape_and_source(changes):
    assert observation.public_observation(royal_record(**changes), SESSION) is None


def test_wire2_and_wire3_payload_fields_are_identical_but_scope_and_path_are_isolated():
    assert set(old_record()) == set(royal_record())
    old = observation.public_observation(old_record(), SESSION)
    new = observation.public_observation(royal_record(), SESSION)
    assert old is not None and new is not None
    assert set(old['payload']) == set(new['payload'])
    assert old['payload']['scope'] == observation.RECORD_SCOPE
    assert new['payload']['scope'] == observation.ROYAL_RECORD_SCOPE
    assert observation.public_observation(old_record(schema_version=3), SESSION) is None
    assert observation.public_observation(royal_record(schema_version=2), SESSION) is None


def test_wire3_snapshots_use_royal_scope_and_existing_record_date_semantics():
    event = snapshot(royal_record())
    context = {'session_id': SESSION, 'observer': 'FRA', 'game_sha256': GAME_SHA}
    assert observation.valid_event_snapshot(event, context)
    assert event['source']['date_semantics'] == observation.RECORD_DATE_SEMANTICS
    for field, value in (
        ('scope', observation.RECORD_SCOPE),
        ('date_semantics', observation.DATE_SEMANTICS),
    ):
        changed = deepcopy(event)
        changed['source'][field] = value
        assert not observation.valid_event_snapshot(changed, context)
    changed = deepcopy(event)
    changed['payload']['scope'] = observation.RECORD_SCOPE
    assert not observation.valid_event_snapshot(changed, context)
    changed = deepcopy(event)
    del changed['payload']['observation_path']
    assert not observation.valid_event_snapshot(changed, context)


@pytest.mark.parametrize('version', [50, 51, 52, 53, 54, 55, 56, 57])
def test_old_ack_versions_cannot_advertise_royal_records(version):
    assert observation.supported_ack(ack(version), GAME_SHA)
    assert not observation.supported_ack(
        ack(version, **{observation.ROYAL_RECORD_CAPABILITY: True}), GAME_SHA)
    assert not observation.supported_royal_record_ack(ack(version), GAME_SHA)


def test_v58_requires_all_capabilities_wire3_and_royal_scope():
    good = ack(58)
    assert observation.supported_ack(good, GAME_SHA)
    assert observation.supported_record_ack(good, GAME_SHA)
    assert observation.supported_royal_record_ack(good, GAME_SHA)
    bad = [
        ack(58, **{observation.CAPABILITY: 1}),
        ack(58, **{observation.RECORD_CAPABILITY: 1}),
        ack(58, **{observation.RECORD_CAPABILITY: False}),
        ack(58, **{observation.ROYAL_RECORD_CAPABILITY: 1}),
        ack(58, **{observation.ROYAL_RECORD_CAPABILITY: False}),
        ack(58, native_relation_change_wire=True),
        ack(58, native_relation_change_wire=2),
        ack(58, native_relation_change_wire=59),
        ack(58, native_relation_change_scope=observation.RECORD_SCOPE),
        ack(58, native_relation_change_wire=2,
            native_relation_change_scope=observation.RECORD_SCOPE),
    ]
    version_59 = ack(58)
    version_59['version'] = 59
    bad.append(version_59)
    assert all(not observation.supported_ack(candidate, GAME_SHA) for candidate in bad)
    assert all(not observation.supported_royal_record_ack(candidate, GAME_SHA) for candidate in bad)


def test_capability_scope_requires_the_complete_royal_capability_chain():
    assert observation.scope_for_capabilities({observation.CAPABILITY}) == observation.SCOPE
    assert observation.scope_for_capabilities(
        {observation.CAPABILITY, observation.RECORD_CAPABILITY}) == observation.RECORD_SCOPE
    full = {observation.CAPABILITY, observation.RECORD_CAPABILITY, observation.ROYAL_RECORD_CAPABILITY}
    assert observation.scope_for_capabilities(full) == observation.ROYAL_RECORD_SCOPE
    assert observation.scope_for_capabilities({observation.CAPABILITY,
        observation.ROYAL_RECORD_CAPABILITY}) is None
    assert observation.scope_for_capabilities({observation.RECORD_CAPABILITY,
        observation.ROYAL_RECORD_CAPABILITY}) is None
    assert observation.scope_for_capabilities({observation.ROYAL_RECORD_CAPABILITY}) is None


@pytest.mark.parametrize('wire,native', [(1, native_relation()), (2, old_record())])
def test_old_wire_replay_ids_snapshots_and_dates_are_preserved(wire, native):
    public = observation.public_observation(native, SESSION)
    assert public is not None
    assert public['event_id'] == observation.event_id(SESSION, 1)
    archived = snapshot(native)
    context = {'session_id': SESSION, 'observer': 'FRA', 'game_sha256': GAME_SHA}
    assert observation.valid_event_snapshot(archived, context)
    assert archived['source']['date_semantics'] == (
        observation.DATE_SEMANTICS if wire == 1 else observation.RECORD_DATE_SEMANTICS)


def test_collector_accepts_only_the_negotiated_schema_and_preserves_gap_reporting():
    command = observation.Collector(SESSION)
    command.observe(old_record())
    assert command.batch(0)['events'] == []
    assert command.batch(0)['gaps'] == ['RELATION_OBSERVATION_INVALID']

    alliance_record = observation.Collector(SESSION)
    alliance_record.observe(royal_record())
    assert alliance_record.batch(0)['events'] == []
    assert alliance_record.batch(0)['gaps'] == ['RELATION_OBSERVATION_INVALID']

    royal = observation.Collector(SESSION)
    royal.observe(old_record(), allow_record=True, allow_royal_record=True)
    royal.observe(royal_record(sequence=1), allow_record=True)
    royal.observe(royal_record(sequence=1), allow_record=True, allow_royal_record=True)
    batch = royal.batch(0)
    assert len(batch['events']) == 1
    assert batch['events'][0]['event_id'] == observation.event_id(SESSION, 1)
    assert batch['events'][0]['payload']['scope'] == observation.ROYAL_RECORD_SCOPE
    assert batch['gaps'] == ['RELATION_OBSERVATION_INVALID']


def test_collector_accepts_wire3_only_when_both_record_flags_are_enabled():
    collector = observation.Collector(SESSION)
    collector.observe(royal_record(), allow_royal_record=True)
    assert collector.batch(0)['events'] == []
    assert collector.batch(0)['gaps'] == ['RELATION_OBSERVATION_INVALID']
    enabled = observation.Collector(SESSION)
    enabled.observe(royal_record(), allow_record=True, allow_royal_record=True)
    assert len(enabled.batch(0)['events']) == 1


def test_wire2_capture_drop_gap_semantics_are_preserved():
    collector = observation.Collector(SESSION)
    collector.observe(old_record(), allow_record=True)
    collector.observe({
        'event': observation.NATIVE_GAP, 'session_id': SESSION,
        'dropped': 1, 'complete': False,
    }, allow_record=True)
    batch = collector.batch(0)
    assert len(batch['events']) == 1
    assert batch['gaps'] == ['RELATION_CAPTURE_DROPPED']
