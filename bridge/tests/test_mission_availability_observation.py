"""Strict decoder and bounded collector for native mission eligibility samples."""
from copy import deepcopy
import hashlib

import pytest

from bridge import mission_availability_observation as observation
from bridge import mission_observation
from bridge.tests.test_information_mission_events import (
    GAME_DATE, GAME_SHA, SESSION_ID, completed as completed_fixture,
    mission_ack as mission_ack_fixture,
)
from bridge.tests.test_relation_record_observation import record_ack


def fullref(tag, slot=1, generation=0x1200):
    value = (generation << 48) | (slot << 32) | int.from_bytes(tag.encode('ascii'), 'little')
    return f'0x{value:x}'


def availability_ack(**changes):
    ack = mission_ack_fixture(version=52)
    ack.update({
        observation.CAPABILITY: True,
        'native_mission_availability_wire': 1,
        'native_mission_availability_scope': observation.SCOPE,
    })
    ack.update(changes)
    return ack


def native_event(sequence=1, name='french_reconquest', *, before=False, after=True,
                 date=GAME_DATE, previous_date=GAME_DATE - 24, **changes):
    event = completed_fixture(sequence=sequence, name=name, date_raw=date)
    event.update({
        'event': observation.NATIVE_EVENT,
        'country_fullref': fullref('FRA', 1),
        'previous_observed_date_raw': previous_date,
        'eligible_before': before,
        'eligible_after': after,
        'source': observation.SOURCE,
        'complete': True,
    })
    event.pop('completed_before')
    event.pop('completed_after')
    event.update(changes)
    return event


def persisted_snapshot():
    public = observation.public_observation(native_event(sequence=9), SESSION_ID)
    event = {
        'session_id': SESSION_ID,
        'observer': 'FRA',
        'event_type': observation.EVENT_TYPE,
        'complete': True,
        'payload': deepcopy(public['payload']),
        'objects': deepcopy(public['objects']),
        'event_id': public['event_id'],
        'game_date': public['game_date'],
        'source': {
            'session_id': SESSION_ID,
            'scope': observation.SCOPE,
            'mode': 'live',
            'complete': True,
            'date_semantics': observation.DATE_SEMANTICS,
            'native_sequence': public['native_sequence'],
        },
    }
    context = {'session_id': SESSION_ID, 'observer': 'FRA', 'game_sha256': GAME_SHA}
    return event, context


def test_ack_requires_exact_v52_and_composes_the_mission_parent_contract():
    ack = availability_ack()
    assert observation.supported_ack(ack, GAME_SHA)

    rejected = [
        availability_ack(version=51),
        availability_ack(version=50),
        availability_ack(version=53),
        availability_ack(version=52.0),
        availability_ack(version=True),
        availability_ack(**{observation.CAPABILITY: 1}),
        availability_ack(**{observation.CAPABILITY: False}),
        availability_ack(native_mission_availability_wire=True),
        availability_ack(native_mission_availability_wire=0),
        availability_ack(native_mission_availability_wire=2),
        availability_ack(native_mission_availability_scope='all_mission_checks'),
        availability_ack(**{mission_observation.CAPABILITY: False}),
        availability_ack(native_mission_completion_wire=True),
        availability_ack(native_relation_change_scope='all_relations'),
    ]
    for bad_ack in rejected:
        assert not observation.supported_ack(bad_ack, GAME_SHA)
    assert not observation.supported_ack(ack, '0' * 64)


def test_v56_availability_ack_keeps_the_mission_and_relation_parent_contracts():
    ack = record_ack(version=56)
    ack.update({
        mission_observation.CAPABILITY: True,
        mission_observation.SET_CAPABILITY: True,
        'native_mission_completion_wire': 2,
        'native_mission_completion_scope': mission_observation.SET_SCOPE,
        observation.CAPABILITY: True,
        'native_mission_availability_wire': 1,
        'native_mission_availability_scope': observation.SCOPE,
    })
    assert observation.supported_ack(ack, GAME_SHA)
    assert not observation.supported_ack(dict(ack, version=57), GAME_SHA)


@pytest.mark.parametrize('before,after', [(False, True), (True, False)])
def test_native_return_maps_only_a_changed_eligibility_sample(before, after):
    event = native_event(before=before, after=after)
    public = observation.public_observation(event, SESSION_ID)

    assert public is not None
    assert public['game_date'] == GAME_DATE
    assert public['payload'] == {
        'country': 'FRA',
        'mission_id': 'french_reconquest',
        'eligible_before': before,
        'eligible_after': after,
        'previous_observed_date_raw': GAME_DATE - 24,
        'scope': observation.SCOPE,
    }
    assert public['objects'] == [{'type': 'country', 'country': 'FRA'}]
    assert 'country_fullref' not in public['payload']
    assert 'country_fullref' not in public['objects'][0]
    expected = hashlib.sha256(
        (SESSION_ID + '\0mission-availability\0' + '1').encode()
    ).hexdigest()[:32]
    assert public['event_id'] == 'mission-availability:' + expected


def test_fullref_retains_nonzero_generation_while_checking_fra_tag_and_slot():
    event = native_event(country_fullref='0x1200000100415246')
    assert observation.public_observation(event, SESSION_ID) is not None
    assert observation.public_observation(
        native_event(country_fullref=fullref('ENG', 1)), SESSION_ID) is None
    assert observation.public_observation(
        native_event(country_fullref=fullref('FRA', 4096)), SESSION_ID) is None
    assert observation.public_observation(
        native_event(country_fullref='0X1200000100415246'), SESSION_ID) is None


@pytest.mark.parametrize('name', [
    'french_reconquest', 'mission"quote\\slash', 'a' * 256,
])
def test_printable_ascii_identifier_is_preserved_from_owned_hex(name):
    public = observation.public_observation(native_event(name=name), SESSION_ID)
    assert public is not None
    assert public['payload']['mission_id'] == name


@pytest.mark.parametrize('changes', [
    {'schema_version': True},
    {'schema_version': 3},
    {'sequence': True},
    {'sequence': 0},
    {'sequence': 2**63},
    {'country': 'POR'},
    {'country_fullref': fullref('ENG', 1)},
    {'country_fullref': fullref('FRA', 4096)},
    {'country_fullref': []},
    {'date_raw': True},
    {'date_raw': 0},
    {'previous_observed_date_raw': True},
    {'previous_observed_date_raw': 0},
    {'previous_observed_date_raw': GAME_DATE + 1},
    {'eligible_before': 0},
    {'eligible_after': 1},
    {'eligible_before': False, 'eligible_after': False},
    {'eligible_before': True, 'eligible_after': True},
    {'source': 'sampled_mission_diff'},
    {'complete': 1},
    {'mission_id_hex': ''},
    {'mission_id_hex': 'xyz'},
    {'mission_id_hex': 'f'},
    {'mission_id_hex': 'ff'},
    {'mission_id_hex': '0a'},
    {'mission_id_hex': '00'},
    {'mission_id_hex': '61' * 257},
    {'untrusted_extra': True},
])
def test_malformed_rows_or_noncanonical_identity_are_rejected(changes):
    assert observation.public_observation(native_event(**changes), SESSION_ID) is None


def test_missing_native_date_provenance_is_rejected():
    event = native_event()
    del event['previous_observed_date_raw']
    assert observation.public_observation(event, SESSION_ID) is None


def test_decoder_rejects_wrong_session_and_event_type():
    assert observation.public_observation(
        native_event(session_id='another-session'), SESSION_ID) is None
    assert observation.public_observation(
        native_event(event='native_mission_completed'), SESSION_ID) is None


def test_event_identity_and_payload_are_stable_owned_snapshots():
    native = native_event(sequence=23)
    first = observation.public_observation(native, SESSION_ID)
    second = observation.public_observation(deepcopy(native), SESSION_ID)
    assert first is not None and second is not None
    assert first['event_id'] == second['event_id'] == observation.event_id(SESSION_ID, 23)

    native['eligible_after'] = False
    first['payload']['eligible_after'] = False
    fresh = observation.public_observation(native_event(sequence=23), SESSION_ID)
    assert fresh is not None
    assert fresh['payload']['eligible_after'] is True
    assert fresh['event_id'] == first['event_id']


@pytest.mark.parametrize('mutation', [
    'event_session', 'event_observer', 'context_observer', 'game_sha',
    'payload_country', 'payload_scope', 'payload_extra', 'future_previous_date',
    'objects', 'source_session', 'source_scope', 'source_mode', 'source_complete',
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
    elif mutation == 'payload_country':
        event['payload']['country'] = 'POR'
    elif mutation == 'payload_scope':
        event['payload']['scope'] = 'all_missions'
    elif mutation == 'payload_extra':
        event['payload']['untrusted'] = True
    elif mutation == 'future_previous_date':
        event['payload']['previous_observed_date_raw'] = event['game_date'] + 1
    elif mutation == 'objects':
        event['objects'] = [{'type': 'country', 'country': 'POR'}]
    elif mutation == 'source_session':
        event['source']['session_id'] = 'foreign-session'
    elif mutation == 'source_scope':
        event['source']['scope'] = 'all_missions'
    elif mutation == 'source_mode':
        event['source']['mode'] = 'fixture'
    elif mutation == 'source_complete':
        event['source']['complete'] = False
    elif mutation == 'date_semantics':
        event['source']['date_semantics'] = 'world_change_instant'
    elif mutation == 'source_sequence':
        event['source']['native_sequence'] += 1
    elif mutation == 'event_id':
        event['event_id'] = 'wrong'
    elif mutation == 'no_change':
        event['payload']['eligible_after'] = event['payload']['eligible_before']

    assert not observation.valid_event_snapshot(event, context)


def test_collector_deduplicates_identical_sequences_and_preserves_date_provenance():
    collector = observation.Collector(SESSION_ID)
    event = native_event()
    collector.observe(event)
    collector.observe(deepcopy(event))

    batch = collector.batch(0)
    assert batch['complete']
    assert len(batch['events']) == 1
    assert batch['events'][0]['payload']['previous_observed_date_raw'] == GAME_DATE - 24


def test_collector_marks_conflicting_sequence_payloads_incomplete():
    collector = observation.Collector(SESSION_ID)
    collector.observe(native_event(sequence=1))
    collector.observe(native_event(sequence=1, name='french_trade'))

    batch = collector.batch(0)
    assert not batch['complete']
    assert 'MISSION_AVAILABILITY_SEQUENCE_CONFLICT' in batch['gaps']
    assert len(batch['events']) == 1


def test_collector_marks_a_sequence_jump_incomplete():
    collector = observation.Collector(SESSION_ID)
    collector.observe(native_event(sequence=1))
    collector.observe(native_event(sequence=3))

    batch = collector.batch(0)
    assert not batch['complete']
    assert 'MISSION_AVAILABILITY_SEQUENCE_GAP' in batch['gaps']
    assert [item['native_sequence'] for item in batch['events']] == [1, 3]


def test_collector_preserves_drop_health_transport_and_unavailable_gaps():
    collector = observation.Collector(SESSION_ID)
    collector.observe({
        'event': observation.NATIVE_GAP, 'session_id': SESSION_ID,
        'dropped': 1, 'complete': False,
    })
    collector.observe({
        'event': 'diplomacy_observer_health', 'session_id': SESSION_ID,
        'mission_availability_source': {
            'installed': False, 'transport_fault': True, 'queue_readable': True,
            'total_dropped': 1, 'queued': 0,
        },
    })

    batch = collector.batch(0)
    assert not batch['complete']
    assert {
        'MISSION_AVAILABILITY_CAPTURE_DROPPED',
        'MISSION_AVAILABILITY_TRANSPORT_FAULT',
        'MISSION_AVAILABILITY_SOURCE_UNAVAILABLE',
    } <= set(batch['gaps'])


def test_collector_marks_invalid_health_and_ignores_foreign_sessions():
    collector = observation.Collector(SESSION_ID)
    collector.observe({
        'event': 'diplomacy_observer_health', 'session_id': SESSION_ID,
        'mission_availability_source': {'installed': True},
    })
    collector.observe(native_event(session_id='foreign-session'))
    batch = collector.batch(0)
    assert batch['events'] == []
    assert 'MISSION_AVAILABILITY_HEALTH_INVALID' in batch['gaps']


def test_collector_reports_eviction_only_for_cursors_behind_the_cache_watermark(monkeypatch):
    monkeypatch.setattr(observation, 'MAX_EVENTS', 2)
    collector = observation.Collector(SESSION_ID)
    for sequence in (1, 2, 3):
        collector.observe(native_event(sequence=sequence))

    stale = collector.batch(0)
    at_watermark = collector.batch(1)
    assert [row['native_sequence'] for row in stale['events']] == [2, 3]
    assert not stale['complete']
    assert 'MISSION_AVAILABILITY_CACHE_EVICTED' in stale['gaps']
    assert at_watermark['complete'] and at_watermark['gaps'] == []


def test_collector_marks_invalid_native_events_as_gaps():
    collector = observation.Collector(SESSION_ID)
    collector.observe(native_event(eligible_after=1))
    batch = collector.batch(0)
    assert not batch['complete']
    assert batch['gaps'] == ['MISSION_AVAILABILITY_OBSERVATION_INVALID']
