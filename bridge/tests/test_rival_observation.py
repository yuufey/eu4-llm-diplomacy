"""Strict decoder, owned snapshot and bounded collector checks for rival changes."""
from copy import deepcopy

import pytest

from bridge import country_modifier_observation as modifiers
from bridge import rival_observation as observation


SESSION = '322-rival-session'
DATE = 56_700_000


def fullref(tag, slot=7):
    return f'0x{(slot << 32) | int.from_bytes(tag.encode("ascii"), "little"):x}'


def state(count, target_active=False, target_since=-1, old_active=False, old_since=-1):
    return {
        'count': count,
        'target_active': target_active,
        'target_since_date_raw': target_since,
        'old_active': old_active,
        'old_since_date_raw': old_since,
    }


def parent_ack(**changes):
    ack = {
        'version': 48,
        modifiers.CAPABILITY: True,
        'native_country_modifier_add_wire': 1,
        'native_country_modifier_scope': modifiers.SCOPE,
        modifiers.REMOVE_CAPABILITY: True,
        'native_country_modifier_remove_wire': 1,
        modifiers.EXPIRY_CAPABILITY: True,
        'native_country_modifier_expiry_wire': 1,
        observation.CAPABILITY: True,
        'native_rival_change_wire': 1,
        'native_rival_change_scope': observation.SCOPE,
    }
    ack.update(changes)
    return ack


def native_event(sequence=1, **changes):
    event = {
        'event': observation.NATIVE_EVENT,
        'schema_version': 1,
        'session_id': SESSION,
        'sequence': sequence,
        'country': 'FRA',
        'actor': 'FRA',
        'target': 'ENG',
        'old_rival': '---',
        'actor_fullref': fullref('FRA'),
        'target_fullref': fullref('ENG'),
        'old_rival_fullref': '0x0',
        'operation': 'set',
        'date_raw': DATE,
        'before': state(0),
        'after': state(1, target_active=True, target_since=DATE - 24),
        'source': observation.SOURCE,
        'complete': True,
    }
    event.update(changes)
    return event


@pytest.mark.parametrize('changes', [
    {'version': 47},
    {'version': 48.0},
    {observation.CAPABILITY: 1},
    {'native_rival_change_wire': True},
    {'native_rival_change_scope': 'all_country_commands'},
    {modifiers.CAPABILITY: False},
    {'native_country_modifier_remove_wire': True},
    {modifiers.EXPIRY_CAPABILITY: 1},
    {'native_country_modifier_scope': 'all_country_modifiers'},
])
def test_ack_requires_literal_v48_rival_and_modifier_parent_contract(changes):
    assert observation.supported_ack(parent_ack(), modifiers.GAME_SHA256)
    assert not observation.supported_ack(parent_ack(**changes), modifiers.GAME_SHA256)
    for parent_change in (
        {'native_country_modifier_add_wire': True},
        {modifiers.REMOVE_CAPABILITY: False},
        {'native_country_modifier_expiry_wire': 2},
    ):
        assert not observation.supported_ack(parent_ack(**parent_change), modifiers.GAME_SHA256)
    assert not observation.supported_ack(parent_ack(), '0' * 64)


def test_v56_rival_ack_preserves_modifier_parent_contract_and_rejects_v57():
    assert observation.supported_ack(parent_ack(version=56), modifiers.GAME_SHA256)
    assert not observation.supported_ack(parent_ack(version=57), modifiers.GAME_SHA256)


@pytest.mark.parametrize('operation,old,before,after', [
    ('set', '---', state(0), state(1, target_active=True, target_since=DATE - 5)),
    ('remove', '---', state(1, target_active=True, target_since=DATE - 5), state(0)),
    ('replace', 'CAS', state(1, old_active=True, old_since=DATE - 10),
     state(1, target_active=True, target_since=DATE, old_active=False)),
    ('replace', 'CAS', state(0), state(1, target_active=True, target_since=DATE)),
    ('replace', 'CAS', state(1, old_active=True, old_since=DATE - 10), state(0)),
])
def test_native_operations_map_roles_and_owned_objects(operation, old, before, after):
    event = native_event(
        operation=operation,
        old_rival=old,
        old_rival_fullref='0x0' if old == '---' else fullref(old),
        before=before,
        after=after,
    )
    public = observation.public_observation(event, SESSION)

    assert public is not None
    assert public['game_date'] == DATE
    assert public['payload'] == {
        'country': 'FRA', 'actor': 'FRA', 'recipient': 'ENG',
        'old_rival': None if old == '---' else 'CAS', 'operation': operation,
        'before': before, 'after': after, 'scope': observation.SCOPE,
    }
    expected = ['FRA', 'ENG'] + ([] if old == '---' else ['CAS'])
    assert public['objects'] == [{'type': 'country', 'country': tag} for tag in expected]


@pytest.mark.parametrize('changes', [
    {'untrusted_extra': True},
    {'schema_version': True},
    {'sequence': True},
    {'actor': 'Fr'},
    {'target_fullref': fullref('FRA')},
    {'actor_fullref': fullref('FRA', slot=4096)},
    {'before': state(0), 'after': state(0)},
    {'after': state(0, target_active=True, target_since=DATE - 1)},
    {'after': state(1, target_active=True, target_since=DATE + 1)},
    {'session_id': 'other-session'},
])
def test_native_records_with_bad_fields_references_or_membership_are_rejected(changes):
    assert observation.public_observation(native_event(**changes), SESSION) is None


def test_decoded_event_id_is_stable_and_payload_is_an_owned_copy():
    native = native_event(sequence=23)
    first = observation.public_observation(native, SESSION)
    second = observation.public_observation(deepcopy(native), SESSION)

    assert first is not None and second is not None
    assert first['event_id'] == second['event_id'] == observation.event_id(SESSION, 23)
    native['after']['count'] = 17
    assert first['payload']['after']['count'] == 1
    first['payload']['after']['count'] = 18
    fresh = observation.public_observation(native_event(sequence=23), SESSION)
    assert fresh['event_id'] == first['event_id']
    assert fresh['payload']['after']['count'] == 1


def persisted_snapshot():
    public = observation.public_observation(native_event(sequence=9), SESSION)
    event = {
        'session_id': SESSION,
        'observer': 'FRA',
        'event_type': observation.EVENT_TYPE,
        'complete': True,
        'payload': deepcopy(public['payload']),
        'objects': deepcopy(public['objects']),
        'event_id': public['event_id'],
        'game_date': public['game_date'],
        'source': {
            'session_id': SESSION,
            'scope': observation.SCOPE,
            'mode': 'live',
            'complete': True,
            'date_semantics': observation.DATE_SEMANTICS,
            'native_sequence': public['native_sequence'],
        },
    }
    context = {'session_id': SESSION, 'observer': 'FRA', 'game_sha256': observation.GAME_SHA256}
    return event, context


@pytest.mark.parametrize('mutation', [
    'event_session',
    'event_observer',
    'context_observer',
    'game_sha',
    'role_objects',
    'source_session',
    'source_scope',
    'date_semantics',
    'no_op',
])
def test_persisted_snapshot_rejects_unbound_or_non_event_records(mutation):
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
    elif mutation == 'role_objects':
        event['objects'] = [{'type': 'country', 'country': 'FRA'}]
    elif mutation == 'source_session':
        event['source']['session_id'] = 'foreign-session'
    elif mutation == 'source_scope':
        event['source']['scope'] = 'all_rival_changes'
    elif mutation == 'date_semantics':
        event['source']['date_semantics'] = 'collection_time'
    elif mutation == 'no_op':
        event['payload']['after'] = deepcopy(event['payload']['before'])

    assert not observation.valid_event_snapshot(event, context)


def test_collector_deduplicates_identical_native_sequences():
    collector = observation.Collector(SESSION)
    event = native_event()
    collector.observe(event)
    collector.observe(deepcopy(event))

    batch = collector.batch(0)
    assert batch['complete']
    assert len(batch['events']) == 1
    assert batch['events'][0]['native_sequence'] == 1


def test_collector_marks_conflicting_sequence_payloads_incomplete():
    collector = observation.Collector(SESSION)
    collector.observe(native_event(sequence=1))
    collector.observe(native_event(
        sequence=1, operation='remove',
        before=state(1, target_active=True, target_since=DATE - 5), after=state(0),
    ))

    batch = collector.batch(0)
    assert not batch['complete']
    assert 'RIVAL_SEQUENCE_CONFLICT' in batch['gaps']
    assert len(batch['events']) == 1


def test_collector_marks_a_sequence_jump_incomplete():
    collector = observation.Collector(SESSION)
    collector.observe(native_event(sequence=1))
    collector.observe(native_event(sequence=3))

    batch = collector.batch(0)
    assert not batch['complete']
    assert 'RIVAL_SEQUENCE_GAP' in batch['gaps']
    assert [item['native_sequence'] for item in batch['events']] == [1, 3]


def test_collector_preserves_drop_health_and_transport_gaps():
    collector = observation.Collector(SESSION)
    collector.observe({
        'event': observation.NATIVE_GAP, 'session_id': SESSION,
        'dropped': 1, 'complete': False,
    })
    collector.observe({
        'event': 'diplomacy_observer_health', 'session_id': SESSION,
        'rival_change_source': {
            'installed': False, 'transport_fault': True, 'total_dropped': 1,
            'queue_readable': True, 'queued': 0,
        },
    })

    batch = collector.batch(0)
    assert not batch['complete']
    assert {'RIVAL_CAPTURE_DROPPED', 'RIVAL_TRANSPORT_FAULT', 'RIVAL_SOURCE_UNAVAILABLE'} <= set(batch['gaps'])


def test_collector_ignores_foreign_session_records():
    collector = observation.Collector(SESSION)
    collector.observe(native_event(session_id='foreign-session'))

    assert collector.batch(0) == {'events': [], 'complete': True, 'gaps': []}


def test_collector_reports_eviction_below_the_cache_watermark(monkeypatch):
    monkeypatch.setattr(observation, 'MAX_EVENTS', 2)
    collector = observation.Collector(SESSION)
    for sequence in (1, 2, 3):
        collector.observe(native_event(sequence=sequence))

    behind = collector.batch(0)
    at_watermark = collector.batch(1)
    assert [item['native_sequence'] for item in behind['events']] == [2, 3]
    assert not behind['complete'] and 'RIVAL_CACHE_EVICTED' in behind['gaps']
    assert at_watermark['complete'] and at_watermark['gaps'] == []
