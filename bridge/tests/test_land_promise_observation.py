"""Strict land-promise events preserve the actual sender and registered war."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge import land_promise_observation as observation


SESSION = '64-land-session'
DATE = 56692920
WAR_ID = 'war_0123456789abcdef_00000001'


def test_real_accepted_fra_sav_call_matches_the_delivered_snapshot():
    path = Path(__file__).with_name('fixtures') / 'land_promise_established_FRA_SAV_live_1374.json'
    fixture = json.loads(path.read_text(encoding='utf-8'))
    native, event = fixture['native'], fixture['event']
    public = observation.public_observation(native, native['session_id'])
    assert public['event_id'] == event['event_id']
    assert public['game_date'] == event['game_date'] == 56697264
    assert public['objects'] == event['objects']
    assert public['payload'] == event['payload']
    assert public['payload']['promisor'] == 'FRA'
    assert public['payload']['beneficiary'] == 'SAV'
    assert public['payload']['action_id'] == 'call_to_arms'
    assert observation.valid_event_snapshot(event, {
        'session_id': native['session_id'], 'observer': 'FRA',
        'game_sha256': fixture['game_sha256'], 'game_date': native['date_raw'], 'mode': 'live'})


def fullref(tag, slot=122):
    return hex((1 << 56) | (slot << 32) | int.from_bytes(tag.encode('ascii'), 'little'))


def native_ack(**changes):
    return {'event': 'diplomacy_observer_installed', 'session_id': SESSION, 'observer': 'FRA',
            'version': 64, observation.CAPABILITY: True, 'native_land_promise_wire': 1,
            'native_land_promise_scope': observation.SCOPE, **changes}


def native_event(sequence=1, promisor='FRA', beneficiary='SAV', **changes):
    return {'event': observation.NATIVE_EVENT, 'session_id': SESSION, 'sequence': sequence,
            'date_raw': DATE, 'promisor_ref': fullref(promisor), 'beneficiary_ref': fullref(beneficiary, 210),
            'observer_ref': fullref('FRA'), 'war_id': WAR_ID,
            'source': 'declare_war_return_promised_participant', 'wire': 1, **changes}


def context(**changes):
    return {'session_id': SESSION, 'observer': 'FRA', 'mode': 'live',
            'game_sha256': observation.GAME_SHA256, 'game_date': DATE + 24, **changes}


def snapshot(sequence=1, promisor='FRA', beneficiary='SAV', **changes):
    public = observation.public_observation(native_event(sequence, promisor, beneficiary, **changes), SESSION)
    assert public is not None
    return {'event_id': public['event_id'], 'event_type': observation.EVENT_TYPE, 'session_id': SESSION,
            'observer': 'FRA', 'game_date': public['game_date'], 'complete': True,
            'objects': deepcopy(public['objects']), 'payload': deepcopy(public['payload']),
            'source': {'mode': 'live', 'session_id': SESSION, 'complete': True,
                       'scope': observation.SCOPE, 'date_semantics': observation.DATE_SEMANTICS,
                       'native_sequence': public['native_sequence']}}


@pytest.mark.parametrize('source,action', list(observation.SOURCES.items()))
def test_sources_keep_accepted_command_direction_and_public_war(source, action):
    native = native_event(promisor='SAV', beneficiary='FRA', source=source)
    public = observation.public_observation(native, SESSION)
    assert public['payload'] == {'promisor': 'SAV', 'beneficiary': 'FRA', 'war_id': WAR_ID,
                                 'action_id': action, 'scope': observation.SCOPE}
    assert public['objects'][-1] == {'type': 'country_pair', 'actor': 'SAV', 'recipient': 'FRA'}
    assert public['objects'][0] == {'type': 'war', 'war_id': WAR_ID}
    assert observation.valid_event_snapshot(snapshot(source=source), context())


def test_fra_membership_scope_allows_other_countries_promise_in_fra_war():
    assert observation.public_observation(native_event(promisor='ENG'), SESSION)['payload']['promisor'] == 'ENG'
    assert observation.public_observation(native_event(promisor='ENG', observer_ref=fullref('POR')), SESSION) is None


@pytest.mark.parametrize('change', [
    {'event': 'native_call_to_arms_observed'}, {'session_id': 'other'}, {'sequence': True}, {'sequence': 0},
    {'sequence': 2**63}, {'date_raw': True}, {'date_raw': 0}, {'wire': True}, {'wire': 3}, {'war_id': None},
    {'war_id': 'war_0123'}, {'war_id': WAR_ID.upper()}, {'source': 'call_to_arms_before_executor'}, {'source': []},
    {'promisor_ref': fullref('fra')}, {'promisor_ref': '0x'}, {'promisor_ref': fullref('FRA', 4096)},
    {'beneficiary_ref': fullref('FRA')}, {'beneficiary_ref': fullref('---')}, {'observer_ref': fullref('POR')},
    {'observer_ref': fullref('FRA', 4096)}, {'extra': 'unbound'},
])
def test_invalid_native_records_are_rejected(change):
    assert observation.public_observation(native_event(**change), SESSION) is None


def test_full_reference_canonical_shape_accepts_other_high_bit_encoding():
    event = native_event()
    event['promisor_ref'] = hex(int(event['promisor_ref'], 16) ^ (1 << 60))
    assert observation.public_observation(event, SESSION) is not None
    event.pop('beneficiary_ref')
    assert observation.public_observation(event, SESSION) is None


@pytest.mark.parametrize('changes', [
    {'version': 63}, {'version': 65}, {'version': True}, {observation.CAPABILITY: False},
    {observation.CAPABILITY: 1}, {'native_land_promise_wire': True}, {'native_land_promise_wire': 2},
    {'native_land_promise_scope': 'all_wars'},
])
def test_exact_v64_capability_is_required(changes):
    assert not observation.supported_ack(native_ack(**changes), observation.GAME_SHA256)


def test_ack_requires_the_fixed_binary_and_top_level_capability():
    assert observation.supported_ack(native_ack(), observation.GAME_SHA256)
    assert not observation.supported_ack(native_ack(), '0' * 64)
    ack = native_ack()
    ack.pop(observation.CAPABILITY)
    ack['caps'] = [observation.CAPABILITY]
    assert not observation.supported_ack(ack, observation.GAME_SHA256)


@pytest.mark.parametrize('damage', ['object', 'event_id', 'session', 'observer', 'event_type', 'complete',
                                    'source_session', 'scope', 'date_semantics', 'sequence', 'source_complete'])
def test_c04_snapshots_require_bound_history(damage):
    event = snapshot()
    if damage == 'object':
        event['objects'].reverse()
    elif damage == 'event_id':
        event['event_id'] += 'x'
    elif damage == 'session':
        event['session_id'] = 'other'
    elif damage == 'observer':
        event['observer'] = 'POR'
    elif damage == 'event_type':
        event['event_type'] = 'war_declared'
    elif damage == 'complete':
        event['complete'] = False
    else:
        key = {'source_session': 'session_id', 'sequence': 'native_sequence',
               'source_complete': 'complete'}.get(damage, damage)
        event['source'][key] = False
    assert not observation.valid_event_snapshot(event, context())


def test_collector_owns_values_detects_conflicts_and_preserves_gap_health():
    collector = observation.Collector(SESSION)
    first = native_event()
    collector.observe(first)
    first['war_id'] = 'changed'
    assert collector.batch(0)['events'][0]['payload']['war_id'] == WAR_ID
    collector.observe(native_event())
    assert len(collector.batch(0)['events']) == 1
    collector.observe(native_event(war_id='war_0123456789abcdef_00000002'))
    assert 'LAND_PROMISE_SEQUENCE_CONFLICT' in collector.batch(0)['gaps']
    collector.observe(native_event(3))
    assert 'LAND_PROMISE_SEQUENCE_GAP' in collector.batch(0)['gaps']
    collector.observe({'event': observation.NATIVE_GAP, 'session_id': SESSION, 'complete': False, 'dropped': 1})
    assert 'LAND_PROMISE_CAPTURE_DROPPED' in collector.batch(0)['gaps']
    with pytest.raises(ValueError, match='LAND_PROMISE_CURSOR_INVALID'):
        collector.batch(True)


def test_collector_eviction_is_explicit_and_disabled_source_is_unavailable():
    collector = observation.Collector(SESSION)
    collector.max_events = 1
    collector.observe(native_event())
    collector.observe(native_event(2))
    assert 'LAND_PROMISE_CACHE_EVICTED' in collector.batch(0)['gaps']
    collector.observe({'event': 'diplomacy_observer_health', 'session_id': SESSION,
                       'land_promise_source': {'installed': False, 'transport_fault': False,
                                               'queued': 0, 'total_dropped': 0, 'queue_readable': True}})
    assert 'LAND_PROMISE_SOURCE_UNAVAILABLE' in collector.batch(1)['gaps']
