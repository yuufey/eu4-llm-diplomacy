"""B23 directional expiry wire and shared bounded collector contract."""
from copy import deepcopy

import pytest

from bridge import truce_expiry_observation as observation
from bridge.information.truce_date_math import direct_truce_expiry


SESSION_ID = 'truce-expiry-python'
INPUT_DATE = 56064000
END_DATE = direct_truce_expiry(INPUT_DATE, 0, 10, 5)['raw']
GAME_DATE = END_DATE


def reference(tag, slot):
    return hex(0x10000000000000 | (slot << 32) | int.from_bytes(tag.encode('ascii'), 'little'))


def native_event(sequence=1, *, actor='FRA', recipient='SAV', **changes):
    event = {
        'event': observation.NATIVE_EVENT, 'session_id': SESSION_ID, 'sequence': sequence,
        'date_raw': GAME_DATE, 'actor_ref': reference(actor, 1), 'recipient_ref': reference(recipient, 2),
        'observer_ref': reference('FRA', 1 if actor == 'FRA' else 2),
        'date_input_raw': INPUT_DATE, 'adjustment_raw': 0, 'configuration_a_raw': 10,
        'configuration_b_raw': 5, 'end_date_raw': END_DATE, 'source': observation.SOURCE, 'wire': 1,
    }
    event.update(changes)
    return event


def native_ack(**changes):
    ack = {'event': 'diplomacy_observer_installed', 'session_id': SESSION_ID,
           'observer': 'FRA', 'version': 62, observation.CAPABILITY: True,
           'native_truce_expiry_wire': 1, 'native_truce_expiry_scope': observation.SCOPE}
    ack.update(changes)
    return ack


def snapshot(event=None):
    event = native_event() if event is None else event
    public = observation.public_observation(event, SESSION_ID)
    return dict(public, event_type=observation.EVENT_TYPE, session_id=SESSION_ID, observer='FRA',
                complete=True, source={
                    'name': 'ObserverSession.read_native_truce_expiry_events', 'mode': 'live',
                    'session_id': SESSION_ID, 'native_sequence': public['native_sequence'],
                    'complete': True, 'scope': observation.SCOPE,
                    'date_semantics': observation.DATE_SEMANTICS})


def context():
    return {'session_id': SESSION_ID, 'observer': 'FRA', 'game_sha256': observation.GAME_SHA256}


@pytest.mark.parametrize('changes', [
    {'version': 61}, {'version': 65}, {'version': True}, {'version': 62.0},
    {observation.CAPABILITY: 1}, {observation.CAPABILITY: False},
    {'native_truce_expiry_wire': True}, {'native_truce_expiry_wire': 2},
    {'native_truce_expiry_scope': 'all_truces'},
])
def test_ack_requires_exact_version_wire_scope_and_executable(changes):
    assert observation.supported_ack(native_ack(), observation.GAME_SHA256)
    assert not observation.supported_ack(native_ack(**changes), observation.GAME_SHA256)
    assert not observation.supported_ack(native_ack(), '0' * 64)


@pytest.mark.parametrize('version', [62, 63, 64])
def test_truce_ack_supports_inherited_versions(version):
    assert observation.supported_ack(native_ack(version=version), observation.GAME_SHA256)


@pytest.mark.parametrize('actor,recipient', [('FRA', 'SAV'), ('SAV', 'FRA')])
def test_decoder_keeps_direction_and_expiry_at_equal_current_date(actor, recipient):
    public = observation.public_observation(native_event(actor=actor, recipient=recipient), SESSION_ID)
    assert public['game_date'] == GAME_DATE
    assert public['payload'] == {
        'actor': actor, 'recipient': recipient, 'date_input_raw': INPUT_DATE, 'adjustment_raw': 0,
        'configuration_a_raw': 10, 'configuration_b_raw': 5, 'end_date_raw': END_DATE,
        'scope': observation.SCOPE}
    assert public['objects'] == observation.objects(public['payload'])
    assert observation.valid_event_snapshot(snapshot(native_event(actor=actor, recipient=recipient)), context())


@pytest.mark.parametrize('changes', [
    {'event': 'native_truce_removed'}, {'source': 'direct_truce_removed'},
    {'wire': True}, {'wire': 2}, {'complete': True}, {'schema_version': 1},
    {'sequence': True}, {'sequence': 0}, {'sequence': 2**63}, {'session_id': 'other-session'},
    {'date_raw': END_DATE - 1}, {'date_raw': -1}, {'date_raw': True},
    {'date_input_raw': 2**31}, {'date_input_raw': -1}, {'end_date_raw': END_DATE + 1},
    {'adjustment_raw': True}, {'adjustment_raw': 128}, {'adjustment_raw': -129},
    {'configuration_a_raw': 2**31}, {'configuration_b_raw': True}, {'configuration_b_raw': 6},
    {'actor_ref': '0x0'}, {'recipient_ref': []}, {'actor_ref': reference('FRA', 4096)},
    {'observer_ref': reference('FRA', 3)}, {'observer_ref': reference('SAV', 2)},
    {'actor_ref': reference('SAV', 1), 'recipient_ref': reference('ENG', 2)},
    {'recipient_ref': reference('FRA', 2)},
])
def test_decoder_rejects_invalid_identity_inputs_and_unexpired_record(changes):
    assert observation.public_observation(native_event(**changes), SESSION_ID) is None


def test_complete_fullref_value_accepts_actual_shape_and_equivalent_zero_padding():
    event = native_event()
    assert event['actor_ref'] == '0x10000100415246'
    event['observer_ref'] = '0x0' + event['observer_ref'][2:]
    assert observation.public_observation(event, SESSION_ID)
    event['observer_ref'] = hex(int(event['actor_ref'], 16) + (1 << 48))
    assert observation.public_observation(event, SESSION_ID) is None


@pytest.mark.parametrize('changes', [
    {'session_id': 'other'}, {'observer': 'SAV'}, {'complete': False}, {'event_id': 'forged'},
    {'objects': []}, {'game_date': END_DATE - 1},
])
def test_snapshot_revalidates_expiry_direction_identity_and_occurrence_date(changes):
    assert not observation.valid_event_snapshot(dict(snapshot(), **changes), context())
    altered = snapshot()
    altered['source']['date_semantics'] = 'collection_date'
    assert not observation.valid_event_snapshot(altered, context())
    altered = snapshot()
    altered['payload']['end_date_raw'] += 24
    assert not observation.valid_event_snapshot(altered, context())
    assert not observation.valid_event_snapshot(snapshot(), dict(context(), game_sha256='0' * 64))


def test_collector_deduplicates_conflicts_gaps_health_and_eviction():
    collector = observation.Collector(SESSION_ID)
    collector.max_events = 2
    collector.observe(native_event(1))
    collector.observe(native_event(1))
    assert len(collector.batch(0)['events']) == 1 and collector.batch(0)['complete']
    collector.observe(native_event(1, date_raw=GAME_DATE + 24))
    collector.observe(native_event(3))
    collector.observe({'event': observation.NATIVE_GAP, 'session_id': SESSION_ID,
                       'complete': False, 'dropped': 2})
    collector.observe({'event': 'diplomacy_observer_health', 'session_id': SESSION_ID,
                       'truce_expiry_source': {'installed': True, 'queue_readable': True,
                           'queued': 0, 'dropped': 2, 'total_dropped': 2, 'transport_fault': False}})
    collector.observe(native_event(4))
    batch = collector.batch(0)
    assert [row['native_sequence'] for row in batch['events']] == [3, 4]
    assert set(batch['gaps']) == {'TRUCE_EXPIRY_SEQUENCE_CONFLICT', 'TRUCE_EXPIRY_SEQUENCE_GAP',
                                 'TRUCE_EXPIRY_CAPTURE_DROPPED', 'TRUCE_EXPIRY_CACHE_EVICTED'}
    assert batch['complete'] is False
    batch['events'][0]['payload']['actor'] = 'ENG'
    assert collector.batch(2)['events'][0]['payload']['actor'] == 'FRA'
    for invalid in (-1, True, 2**63):
        with pytest.raises(ValueError, match='TRUCE_EXPIRY_CURSOR_INVALID'):
            collector.batch(invalid)


def test_persisted_payload_has_no_process_reference():
    event = native_event()
    public = observation.public_observation(event, SESSION_ID)
    assert not any('ref' in key or 'address' in key for key in public['payload'])
    assert observation.event_id(SESSION_ID, 1) != observation.event_id(SESSION_ID, 2)
    assert observation.event_id(SESSION_ID, 1) != observation.event_id('other', 1)
    collector = observation.Collector(SESSION_ID)
    collector.observe(deepcopy(event))
    event['date_input_raw'] = 0
    assert collector.batch(0)['events'] == [public]
