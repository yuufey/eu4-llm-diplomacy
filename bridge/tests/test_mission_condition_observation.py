"""Strict decoder and bounded collector for native root-condition returns."""
from copy import deepcopy
import hashlib

import pytest

from bridge import country_modifier_observation as modifiers
from bridge import mission_availability_observation as availability
from bridge import mission_condition_observation as observation
from bridge import mission_observation
from bridge import relation_observation
from bridge import rival_observation
from bridge import war_declaration_observation
from bridge.tests.test_relation_record_observation import record_ack


GAME_SHA = observation.GAME_SHA256
SESSION_ID = '339-mission-condition-session'
GAME_DATE = 56_700_024


def fullref(tag='FRA', slot=7, generation=0x1200):
    value = (generation << 48) | (slot << 32) | int.from_bytes(tag.encode('ascii'), 'little')
    return f'0x{value:x}'


def condition_ack(**changes):
    ack = record_ack(version=56)
    ack.update({
        mission_observation.CAPABILITY: True,
        mission_observation.SET_CAPABILITY: True,
        'native_mission_completion_wire': 2,
        'native_mission_completion_scope': mission_observation.SET_SCOPE,
        availability.CAPABILITY: True,
        'native_mission_availability_wire': 1,
        'native_mission_availability_scope': availability.SCOPE,
        observation.CAPABILITY: True,
        'native_mission_condition_wire': 1,
        'native_mission_condition_scope': observation.SCOPE,
    })
    ack.update(changes)
    return ack


def native_event(sequence=1, name='french_reconquest', *, before=False, after=True,
                 date=GAME_DATE, previous_date=GAME_DATE - 24, **changes):
    before_return = '0x1234567800000100' if not before else '0x1234567800000101'
    after_return = '0xfedcba9876543201' if after else '0xfedcba9876543200'
    event = {
        'event': observation.NATIVE_EVENT,
        'schema_version': 1,
        'session_id': SESSION_ID,
        'sequence': sequence,
        'country': 'FRA',
        'country_fullref': fullref(),
        'date_raw': date,
        'previous_observed_date_raw': previous_date,
        'mission_id_hex': name.encode('ascii').hex(),
        'condition_index': 1,
        'condition_node': '0x100001000',
        'condition_method_rva': 0xb98070,
        'satisfied_before': before,
        'satisfied_after': after,
        'native_return_before': before_return,
        'native_return_after': after_return,
        'root_condition_count': 4,
        'observed_condition_count': 2,
        'source': observation.SOURCE,
        'complete': False,
    }
    event.update(changes)
    return event


def persisted_snapshot():
    public = observation.public_observation(native_event(sequence=9), SESSION_ID)
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
            'scope': observation.SCOPE,
            'mode': 'live',
            'complete': False,
            'date_semantics': observation.DATE_SEMANTICS,
            'native_sequence': public['native_sequence'],
        },
    }
    context = {'session_id': SESSION_ID, 'observer': 'FRA', 'game_sha256': GAME_SHA}
    return event, context


def test_v56_ack_is_exact_and_composes_all_parent_observer_contracts():
    ack = condition_ack()
    assert modifiers.supported_ack(ack, GAME_SHA)
    assert modifiers.supported_remove_ack(ack, GAME_SHA)
    assert modifiers.supported_expiry_ack(ack, GAME_SHA)
    assert rival_observation.supported_ack(ack, GAME_SHA)
    assert war_declaration_observation.supported_ack(ack, GAME_SHA)
    assert relation_observation.supported_record_ack(ack, GAME_SHA)
    assert mission_observation.supported_set_ack(ack, GAME_SHA)
    assert availability.supported_ack(ack, GAME_SHA)
    assert observation.supported_ack(ack, GAME_SHA)

    rejected = [
        condition_ack(version=55),
        condition_ack(version=57),
        condition_ack(**{observation.CAPABILITY: 1}),
        condition_ack(**{observation.CAPABILITY: False}),
        condition_ack(native_mission_condition_wire=True),
        condition_ack(native_mission_condition_wire=0),
        condition_ack(native_mission_condition_wire=2),
        condition_ack(native_mission_condition_scope='all_mission_conditions'),
        condition_ack(native_mission_availability_wire=True),
        condition_ack(**{availability.CAPABILITY: False}),
        condition_ack(native_mission_completion_wire=1),
        condition_ack(native_relation_change_wire=1),
    ]
    assert all(not observation.supported_ack(candidate, GAME_SHA) for candidate in rejected)
    assert not observation.supported_ack(ack, '0' * 64)
    assert not observation.supported_ack(None, GAME_SHA)


@pytest.mark.parametrize('before,after', [(False, True), (True, False)])
def test_decoder_preserves_full_native_returns_and_only_emits_changed_children(before, after):
    native = native_event(before=before, after=after)
    public = observation.public_observation(native, SESSION_ID)

    assert public is not None
    assert public['game_date'] == GAME_DATE
    assert public['payload'] == {
        'country': 'FRA',
        'mission_id': 'french_reconquest',
        'condition_index': 1,
        'condition_node': '0x100001000',
        'condition_method_rva': 0xb98070,
        'satisfied_before': before,
        'satisfied_after': after,
        'native_return_before': native['native_return_before'],
        'native_return_after': native['native_return_after'],
        'root_condition_count': 4,
        'observed_condition_count': 2,
        'previous_observed_date_raw': GAME_DATE - 24,
        'scope': observation.SCOPE,
    }
    assert public['payload']['native_return_before'] == native['native_return_before']
    assert public['payload']['native_return_after'] == native['native_return_after']
    assert public['objects'] == [{'type': 'country', 'country': 'FRA'}]
    expected = hashlib.sha256(
        (SESSION_ID + '\0mission-condition\0' + '1').encode()
    ).hexdigest()[:32]
    assert public['event_id'] == 'mission-condition:' + expected


def test_fullref_keeps_generation_but_checks_fra_tag_and_slot():
    assert observation.public_observation(
        native_event(country_fullref='0x1200000100415246'), SESSION_ID
    ) is not None
    assert observation.public_observation(
        native_event(country_fullref=fullref('ENG')), SESSION_ID
    ) is None
    assert observation.public_observation(
        native_event(country_fullref=fullref('FRA', 4096)), SESSION_ID
    ) is None
    assert observation.public_observation(
        native_event(country_fullref='0X1200000100415246'), SESSION_ID
    ) is None


@pytest.mark.parametrize('name', ['french_reconquest', 'mission"quote\\slash', 'a' * 256])
def test_printable_ascii_mission_name_is_preserved(name):
    public = observation.public_observation(native_event(name=name), SESSION_ID)
    assert public is not None
    assert public['payload']['mission_id'] == name


@pytest.mark.parametrize('changes', [
    {'schema_version': True},
    {'schema_version': 2},
    {'sequence': True},
    {'sequence': 0},
    {'sequence': 2**63},
    {'country': 'POR'},
    {'country_fullref': fullref('ENG')},
    {'country_fullref': fullref('FRA', 4096)},
    {'country_fullref': []},
    {'date_raw': True},
    {'date_raw': 0},
    {'previous_observed_date_raw': True},
    {'previous_observed_date_raw': 0},
    {'previous_observed_date_raw': GAME_DATE + 1},
    {'mission_id_hex': ''},
    {'mission_id_hex': 'xyz'},
    {'mission_id_hex': 'f'},
    {'mission_id_hex': 'ff'},
    {'mission_id_hex': '00'},
    {'mission_id_hex': 'ff' * 257},
    {'condition_index': True},
    {'condition_index': -1},
    {'condition_index': 128},
    {'condition_node': '0x0'},
    {'condition_node': '0xffff'},
    {'condition_node': '0x800000000000'},
    {'condition_node': '0X100001000'},
    {'condition_method_rva': True},
    {'condition_method_rva': 0xfff},
    {'condition_method_rva': 0x1c00000},
    {'satisfied_before': 0},
    {'satisfied_after': 1},
    {'satisfied_before': False, 'satisfied_after': False},
    {'satisfied_before': True, 'satisfied_after': True},
    {'native_return_before': '0x'},
    {'native_return_after': 1},
    {'native_return_before': '0x1234567800000101'},
    {'native_return_after': '0xfedcba9876543200'},
    {'root_condition_count': 0},
    {'root_condition_count': 129},
    {'observed_condition_count': True},
    {'observed_condition_count': 0},
    {'observed_condition_count': 5},
    {'condition_index': 2, 'observed_condition_count': 2},
    {'source': 'sampled_mission_diff'},
    {'complete': True},
    {'complete': 0},
    {'untrusted_extra': True},
])
def test_malformed_rows_and_out_of_scope_values_are_rejected(changes):
    assert observation.public_observation(native_event(**changes), SESSION_ID) is None


def test_decoder_rejects_wrong_session_and_event_type():
    assert observation.public_observation(
        native_event(session_id='another-session'), SESSION_ID
    ) is None
    assert observation.public_observation(
        native_event(event='native_mission_completed'), SESSION_ID
    ) is None


@pytest.mark.parametrize('mutation', [
    'event_session', 'event_observer', 'context_observer', 'game_sha',
    'event_complete', 'payload_country', 'payload_scope', 'payload_extra',
    'future_previous_date', 'bad_method', 'bad_node', 'bad_return', 'objects',
    'source_session', 'source_scope', 'source_mode', 'source_complete',
    'date_semantics', 'source_sequence', 'event_id', 'no_change',
])
def test_persisted_snapshot_rejects_unbound_or_tampered_events(mutation):
    event, context = persisted_snapshot()
    assert observation.valid_event_snapshot(event, context)

    if mutation == 'event_session':
        event['session_id'] = 'foreign-session'
    elif mutation == 'event_observer':
        event['observer'] = 'ENG'
    elif mutation == 'context_observer':
        context['observer'] = 'ENG'
    elif mutation == 'game_sha':
        context['game_sha256'] = '0' * 64
    elif mutation == 'event_complete':
        event['complete'] = True
    elif mutation == 'payload_country':
        event['payload']['country'] = 'POR'
    elif mutation == 'payload_scope':
        event['payload']['scope'] = 'all_mission_conditions'
    elif mutation == 'payload_extra':
        event['payload']['untrusted'] = True
    elif mutation == 'future_previous_date':
        event['payload']['previous_observed_date_raw'] = event['game_date'] + 1
    elif mutation == 'bad_method':
        event['payload']['condition_method_rva'] = 0x1c00000
    elif mutation == 'bad_node':
        event['payload']['condition_node'] = '0x800000000000'
    elif mutation == 'bad_return':
        event['payload']['native_return_before'] = '0x1'
    elif mutation == 'objects':
        event['objects'] = [{'type': 'country', 'country': 'POR'}]
    elif mutation == 'source_session':
        event['source']['session_id'] = 'foreign-session'
    elif mutation == 'source_scope':
        event['source']['scope'] = 'all_mission_conditions'
    elif mutation == 'source_mode':
        event['source']['mode'] = 'fixture'
    elif mutation == 'source_complete':
        event['source']['complete'] = True
    elif mutation == 'date_semantics':
        event['source']['date_semantics'] = 'world_change_instant'
    elif mutation == 'source_sequence':
        event['source']['native_sequence'] += 1
    elif mutation == 'event_id':
        event['event_id'] = 'wrong'
    elif mutation == 'no_change':
        event['payload']['satisfied_after'] = event['payload']['satisfied_before']

    assert not observation.valid_event_snapshot(event, context)


def test_persisted_snapshot_requires_false_complete_in_both_envelopes():
    event, context = persisted_snapshot()
    event['source']['complete'] = False
    assert observation.valid_event_snapshot(event, context)
    event['complete'] = True
    assert not observation.valid_event_snapshot(event, context)
    event['complete'] = False
    event['source']['complete'] = True
    assert not observation.valid_event_snapshot(event, context)


def test_collector_deduplicates_identical_sequences_and_keeps_observation_partial():
    collector = observation.Collector(SESSION_ID)
    event = native_event()
    collector.observe(event)
    collector.observe(deepcopy(event))

    batch = collector.batch(0)
    assert batch['complete']
    assert len(batch['events']) == 1
    assert batch['events'][0]['payload']['previous_observed_date_raw'] == GAME_DATE - 24


def test_collector_marks_conflicting_sequences_and_sequence_jumps_incomplete():
    conflict = observation.Collector(SESSION_ID)
    conflict.observe(native_event(sequence=1))
    conflict.observe(native_event(sequence=1, name='french_trade'))
    conflict_batch = conflict.batch(0)
    assert not conflict_batch['complete']
    assert 'MISSION_CONDITION_SEQUENCE_CONFLICT' in conflict_batch['gaps']

    jump = observation.Collector(SESSION_ID)
    jump.observe(native_event(sequence=1))
    jump.observe(native_event(sequence=3))
    jump_batch = jump.batch(0)
    assert not jump_batch['complete']
    assert 'MISSION_CONDITION_SEQUENCE_GAP' in jump_batch['gaps']
    assert [row['native_sequence'] for row in jump_batch['events']] == [1, 3]


def test_collector_keeps_gap_and_health_status_incomplete():
    collector = observation.Collector(SESSION_ID)
    collector.observe({
        'event': observation.NATIVE_GAP,
        'session_id': SESSION_ID,
        'dropped': 1,
        'complete': False,
    })
    collector.observe({
        'event': 'diplomacy_observer_health',
        'session_id': SESSION_ID,
        'mission_condition_source': {
            'installed': False,
            'transport_fault': True,
            'queue_readable': True,
            'total_dropped': 1,
            'queued': 0,
        },
    })
    batch = collector.batch(0)
    assert not batch['complete']
    assert {
        'MISSION_CONDITION_CAPTURE_DROPPED',
        'MISSION_CONDITION_TRANSPORT_FAULT',
        'MISSION_CONDITION_SOURCE_UNAVAILABLE',
    } <= set(batch['gaps'])


def test_collector_marks_invalid_rows_and_health_and_ignores_foreign_sessions():
    collector = observation.Collector(SESSION_ID)
    collector.observe({
        'event': 'diplomacy_observer_health',
        'session_id': SESSION_ID,
        'mission_condition_source': {'installed': True},
    })
    collector.observe(native_event(session_id='foreign-session'))
    collector.observe(native_event(satisfied_after=0))
    batch = collector.batch(0)
    assert batch['events'] == []
    assert 'MISSION_CONDITION_HEALTH_INVALID' in batch['gaps']
    assert 'MISSION_CONDITION_OBSERVATION_INVALID' in batch['gaps']
