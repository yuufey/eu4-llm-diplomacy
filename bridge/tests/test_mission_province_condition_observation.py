from copy import deepcopy

import pytest

from bridge import mission_availability_observation as availability
from bridge import mission_condition_observation as observation


SESSION_ID = '345-mission-province-condition-session'
GAME_DATE = 56_700_048
GAME_SHA = observation.GAME_SHA256


def fullref(tag='FRA', slot=7, generation=0x1200):
    value = (generation << 48) | (slot << 32) | int.from_bytes(tag.encode('ascii'), 'little')
    return f'0x{value:x}'


def native_event(*, wire=1, sequence=1, before=False, after=True, **changes):
    event = {
        'event': observation.NATIVE_EVENT,
        'schema_version': wire,
        'session_id': SESSION_ID,
        'sequence': sequence,
        'country': 'FRA',
        'country_fullref': fullref(),
        'date_raw': GAME_DATE,
        'previous_observed_date_raw': GAME_DATE - 24,
        'mission_id_hex': 'french_reconquest'.encode('ascii').hex(),
        'condition_index': 1,
        'condition_node': '0x100001000',
        'condition_method_rva': 0xb98070 if wire == 1 else 0xbe9300,
        'satisfied_before': before,
        'satisfied_after': after,
        'native_return_before': '0x1234567800000101' if before else '0x1234567800000100',
        'native_return_after': '0xfedcba9876543201' if after else '0xfedcba9876543200',
        'root_condition_count': 4,
        'observed_condition_count': 2,
        'source': observation.SOURCE if wire == 1 else observation.PROVINCE_SOURCE,
        'complete': False,
    }
    if wire == 2:
        event.update({'child_index': 0, 'child_count': 1, 'province_id': 167})
    event.update(changes)
    return event


def snapshot_for(native):
    public = observation.public_observation(native, SESSION_ID)
    assert public is not None
    event = {
        'session_id': SESSION_ID,
        'observer': 'FRA',
        'event_type': observation.EVENT_TYPE,
        'complete': False,
        'payload': deepcopy(public['payload']),
        'objects': deepcopy(public['objects']),
        'event_id': public['event_id'],
        'game_date': public['game_date'],
        'source': {
            'session_id': SESSION_ID,
            'scope': public['payload']['scope'],
            'mode': 'live',
            'complete': False,
            'date_semantics': observation.DATE_SEMANTICS,
            'native_sequence': public['native_sequence'],
        },
    }
    context = {'session_id': SESSION_ID, 'observer': 'FRA', 'game_sha256': GAME_SHA}
    return event, context


def test_wire1_keeps_its_original_schema_and_public_payload():
    native = native_event()
    public = observation.public_observation(native, SESSION_ID)

    assert public is not None
    assert public['payload'] == {
        'country': 'FRA',
        'mission_id': 'french_reconquest',
        'condition_index': 1,
        'condition_node': '0x100001000',
        'condition_method_rva': 0xb98070,
        'satisfied_before': False,
        'satisfied_after': True,
        'native_return_before': native['native_return_before'],
        'native_return_after': native['native_return_after'],
        'root_condition_count': 4,
        'observed_condition_count': 2,
        'previous_observed_date_raw': GAME_DATE - 24,
        'scope': observation.SCOPE,
    }
    event, context = snapshot_for(native)
    assert observation.valid_event_snapshot(event, context)


def test_wire2_direct_area_province_return_decodes_and_snapshots():
    native = native_event(wire=2, sequence=5)
    public = observation.public_observation(native, SESSION_ID)

    assert public is not None
    assert public['payload'] == {
        'country': 'FRA',
        'mission_id': 'french_reconquest',
        'condition_index': 1,
        'condition_node': '0x100001000',
        'condition_method_rva': 0xbe9300,
        'satisfied_before': False,
        'satisfied_after': True,
        'native_return_before': native['native_return_before'],
        'native_return_after': native['native_return_after'],
        'root_condition_count': 4,
        'observed_condition_count': 2,
        'previous_observed_date_raw': GAME_DATE - 24,
        'scope': observation.PROVINCE_SCOPE,
        'child_index': 0,
        'child_count': 1,
        'province_id': 167,
        'condition_name': 'country_or_non_sovereign_subject_holds',
        'comparison_country': 'ROOT',
    }
    assert set(public['payload']) == observation._PROVINCE_PAYLOAD_FIELDS
    event, context = snapshot_for(native)
    assert event['source']['scope'] == observation.PROVINCE_SCOPE
    assert observation.valid_event_snapshot(event, context)


@pytest.mark.parametrize('changes', [
    {'schema_version': True},
    {'schema_version': 5},
    {'source': observation.SOURCE},
    {'condition_method_rva': 0xbe9301},
    {'child_index': True},
    {'child_index': -1},
    {'child_index': 1, 'child_count': 1},
    {'child_count': True},
    {'child_count': 0},
    {'child_count': 129},
    {'province_id': True},
    {'province_id': 0},
    {'province_id': 65536},
    {'root_condition_count': 129},
    {'observed_condition_count': 1},
    {'condition_index': 128},
    {'untrusted_extra': 1},
])
def test_wire2_rejects_bad_provenance_ranges_and_unknown_keys(changes):
    assert observation.public_observation(
        native_event(wire=2, **changes), SESSION_ID
    ) is None


@pytest.mark.parametrize('wire,changes', [
    (1, {'child_index': 0}),
    (1, {'source': observation.PROVINCE_SOURCE}),
    (2, {'child_count': None}),
    (2, {'source': observation.SOURCE}),
])
def test_wire_schemas_cannot_mix_or_omit_province_provenance(wire, changes):
    assert observation.public_observation(
        native_event(wire=wire, **changes), SESSION_ID
    ) is None


@pytest.mark.parametrize('mutation', [
    'payload_old_scope', 'payload_missing_child', 'payload_unknown_key',
    'source_old_scope', 'boolean_child_index', 'boolean_province_id', 'wrong_condition_name', 'wrong_comparison_country',
])
def test_wire2_snapshot_rejects_scope_mixing_unknown_keys_and_boolean_numbers(mutation):
    event, context = snapshot_for(native_event(wire=2))
    assert observation.valid_event_snapshot(event, context)

    if mutation == 'payload_old_scope':
        event['payload']['scope'] = observation.SCOPE
    elif mutation == 'payload_missing_child':
        del event['payload']['child_index']
    elif mutation == 'payload_unknown_key':
        event['payload']['extra'] = 'not allowed'
    elif mutation == 'source_old_scope':
        event['source']['scope'] = observation.SCOPE
    elif mutation == 'boolean_child_index':
        event['payload']['child_index'] = True
    elif mutation == 'boolean_province_id':
        event['payload']['province_id'] = True
    elif mutation == 'wrong_condition_name':
        event['payload']['condition_name'] = 'owned_by'
    elif mutation == 'wrong_comparison_country':
        event['payload']['comparison_country'] = 'POR'

    assert not observation.valid_event_snapshot(event, context)


def test_wire1_snapshot_rejects_new_scope_and_province_fields():
    event, context = snapshot_for(native_event())
    assert observation.valid_event_snapshot(event, context)
    event['payload']['scope'] = observation.PROVINCE_SCOPE
    assert not observation.valid_event_snapshot(event, context)

    event, context = snapshot_for(native_event())
    event['payload']['province_id'] = 167
    assert not observation.valid_event_snapshot(event, context)


def test_wire2_collector_deduplicates_same_event_with_stable_identity():
    collector = observation.Collector(SESSION_ID)
    native = native_event(wire=2, sequence=1)
    first = observation.public_observation(native, SESSION_ID)
    second = observation.public_observation(deepcopy(native), SESSION_ID)

    assert first is not None and second is not None
    assert first['event_id'] == second['event_id']
    collector.observe(native)
    collector.observe(deepcopy(native))
    batch = collector.batch(0)
    assert batch['complete']
    assert len(batch['events']) == 1
    assert batch['events'][0]['event_id'] == first['event_id']


def test_ack_keeps_v56_wire1_and_defines_v57_wire2_contract(monkeypatch):
    monkeypatch.setattr(availability, 'supported_ack', lambda ack, sha: sha == GAME_SHA)
    v56 = {
        'version': 56,
        observation.CAPABILITY: True,
        'native_mission_condition_wire': 1,
        'native_mission_condition_scope': observation.SCOPE,
    }
    v57 = {
        'version': 57,
        observation.CAPABILITY: True,
        observation.PROVINCE_CAPABILITY: True,
        'native_mission_condition_wire': 2,
        'native_mission_condition_scope': observation.COMBINED_SCOPE,
    }

    assert observation.supported_ack(v56, GAME_SHA)
    assert observation.supported_ack(v57, GAME_SHA)
    assert not observation.supported_province_ack(v56, GAME_SHA)
    assert observation.supported_province_ack(v57, GAME_SHA)
    incomplete_v57 = {**v57, observation.PROVINCE_CAPABILITY: False}
    assert not observation.supported_ack(incomplete_v57, GAME_SHA)
    assert not observation.supported_province_ack(incomplete_v57, GAME_SHA)
    assert not observation.supported_ack({**v56, 'native_mission_condition_wire': True}, GAME_SHA)
    assert not observation.supported_ack({**v56, 'native_mission_condition_wire': 2}, GAME_SHA)
    assert not observation.supported_ack({**v57, 'native_mission_condition_scope': observation.PROVINCE_SCOPE}, GAME_SHA)
    assert not observation.supported_ack({**v57, 'native_mission_condition_wire': True}, GAME_SHA)
    assert not observation.supported_ack(v57, '0' * 64)
