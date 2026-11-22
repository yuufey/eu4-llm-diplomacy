"""Exact natural-claim-expiry wire and session-bound collector contract."""
from copy import deepcopy

import pytest

from bridge import claim_expiry_observation as observation


SESSION_ID = 'claim-expiry-python'
GAME_DATE = 56692920


def reference(tag, slot, *, high=0x100000000000000):
    return hex(high | (slot << 32) | int.from_bytes(tag.encode('ascii'), 'little'))


def native_event(sequence=1, *, claimant='FRA', owner='SAV', **changes):
    claimant_slot = 122 if claimant == 'FRA' else 210
    owner_slot = 122 if owner == 'FRA' else 0 if owner == '---' else 210
    event = {'event': observation.NATIVE_EVENT, 'session_id': SESSION_ID, 'sequence': sequence,
             'date_raw': GAME_DATE, 'claimant_ref': reference(claimant, claimant_slot),
             'owner_ref': reference(owner, owner_slot), 'observer_ref': reference('FRA', 122),
             'province_id': 186, 'source': observation.SOURCE, 'wire': 1}
    event.update(changes)
    return event


def native_ack(**changes):
    ack = {'event': 'diplomacy_observer_installed', 'session_id': SESSION_ID,
           'observer': 'FRA', 'version': 63, observation.CAPABILITY: True,
           'native_claim_expiry_wire': 1, 'native_claim_expiry_scope': observation.SCOPE}
    ack.update(changes)
    return ack


def snapshot(event=None):
    event = native_event() if event is None else event
    public = observation.public_observation(event, SESSION_ID)
    return dict(public, event_type=observation.EVENT_TYPE, session_id=SESSION_ID, observer='FRA',
                complete=True, source={
                    'name': 'ObserverSession.read_native_claim_expiry_events', 'mode': 'live',
                    'session_id': SESSION_ID, 'native_sequence': public['native_sequence'],
                    'complete': True, 'scope': observation.SCOPE,
                    'date_semantics': observation.DATE_SEMANTICS})


def context():
    return {'session_id': SESSION_ID, 'observer': 'FRA', 'game_sha256': observation.GAME_SHA256}


@pytest.mark.parametrize('changes', [
    {'version': 62}, {'version': 65}, {'version': True}, {'version': 63.0},
    {observation.CAPABILITY: 1}, {observation.CAPABILITY: False},
    {'native_claim_expiry_wire': True}, {'native_claim_expiry_wire': 2},
    {'native_claim_expiry_scope': 'all_claims'},
])
def test_ack_requires_exact_version_wire_scope_and_executable(changes):
    assert observation.supported_ack(native_ack(), observation.GAME_SHA256)
    assert not observation.supported_ack(native_ack(**changes), observation.GAME_SHA256)
    assert not observation.supported_ack(native_ack(), '0' * 64)


@pytest.mark.parametrize('version', [63, 64])
def test_claim_ack_supports_inherited_versions(version):
    assert observation.supported_ack(native_ack(version=version), observation.GAME_SHA256)


@pytest.mark.parametrize('claimant,owner,expected_owner', [
    ('FRA', 'SAV', 'SAV'), ('SAV', 'FRA', 'FRA'), ('FRA', 'FRA', 'FRA'), ('FRA', '---', None),
])
def test_decoder_keeps_claimant_current_owner_province_and_actual_date(claimant, owner, expected_owner):
    public = observation.public_observation(native_event(claimant=claimant, owner=owner), SESSION_ID)
    assert public['game_date'] == GAME_DATE
    assert public['payload'] == {'claimant': claimant, 'owner': expected_owner,
                                  'province_id': 186, 'scope': observation.SCOPE}
    assert public['objects'] == observation.objects(public['payload'])
    assert observation.valid_event_snapshot(snapshot(native_event(claimant=claimant, owner=owner)), context())
    if expected_owner is None or claimant == owner:
        assert public['objects'] == [{'type': 'country', 'country': claimant}, {'type': 'province', 'province_id': 186}]


@pytest.mark.parametrize('changes', [
    {'event': 'native_claim_removed'}, {'source': 'claim_record_remove_return'},
    {'wire': True}, {'wire': 3}, {'complete': True}, {'schema_version': 1},
    {'sequence': True}, {'sequence': 0}, {'sequence': 2**63}, {'session_id': 'other-session'},
    {'date_raw': -1}, {'date_raw': True}, {'date_raw': 2**31},
    {'province_id': True}, {'province_id': 0}, {'province_id': 65536},
    {'claimant_ref': '0x0'}, {'owner_ref': []}, {'owner_ref': '0x0'},
    {'claimant_ref': reference('FRA', 4096)}, {'owner_ref': reference('SAV', 4096)},
    {'observer_ref': reference('FRA', 3)}, {'observer_ref': reference('SAV', 210)},
    {'claimant_ref': reference('BUR', 122), 'owner_ref': reference('SAV', 210)},
])
def test_decoder_rejects_other_removals_invalid_identity_and_malformed_values(changes):
    assert observation.public_observation(native_event(**changes), SESSION_ID) is None


def test_actual_fullrefs_and_canonical_alternative_high_bits_keep_full_value_equality():
    event = native_event()
    assert event['claimant_ref'] == '0x100007a00415246'
    assert event['owner_ref'] == '0x10000d200564153'
    event['claimant_ref'] = event['observer_ref'] = reference('FRA', 122, high=0x1100000000000000)
    assert observation.public_observation(event, SESSION_ID)
    event['observer_ref'] = reference('FRA', 122)
    assert observation.public_observation(event, SESSION_ID) is None


@pytest.mark.parametrize('changes', [
    {'session_id': 'other'}, {'observer': 'SAV'}, {'complete': False}, {'event_id': 'forged'},
    {'objects': []}, {'game_date': -1},
])
def test_snapshot_requires_source_scope_identity_and_supported_values(changes):
    assert not observation.valid_event_snapshot(dict(snapshot(), **changes), context())
    altered = snapshot()
    altered['source']['date_semantics'] = 'collection_date'
    assert not observation.valid_event_snapshot(altered, context())
    altered = snapshot()
    altered['payload']['claimant'] = 'ENG'
    assert not observation.valid_event_snapshot(altered, context())
    assert not observation.valid_event_snapshot(snapshot(), dict(context(), game_sha256='0' * 64))


def test_collector_uses_owned_payloads_deduplication_gaps_health_and_eviction():
    collector = observation.Collector(SESSION_ID)
    collector.max_events = 2
    event = native_event(1)
    collector.observe(deepcopy(event))
    collector.observe(deepcopy(event))
    event['province_id'] = 200
    assert collector.batch(0)['events'][0]['payload']['province_id'] == 186
    collector.observe(native_event(1, province_id=200))
    collector.observe(native_event(3))
    collector.observe({'event': observation.NATIVE_GAP, 'session_id': SESSION_ID,
                       'complete': False, 'dropped': 2})
    collector.observe({'event': 'diplomacy_observer_health', 'session_id': SESSION_ID,
                       'claim_expiry_source': {'installed': True, 'queue_readable': True,
                           'queued': 0, 'dropped': 2, 'total_dropped': 2, 'transport_fault': False}})
    collector.observe(native_event(4))
    batch = collector.batch(0)
    assert [row['native_sequence'] for row in batch['events']] == [3, 4]
    assert set(batch['gaps']) == {'CLAIM_EXPIRY_SEQUENCE_CONFLICT', 'CLAIM_EXPIRY_SEQUENCE_GAP',
                                 'CLAIM_EXPIRY_CAPTURE_DROPPED', 'CLAIM_EXPIRY_CACHE_EVICTED'}
    assert batch['complete'] is False
    batch['events'][0]['payload']['claimant'] = 'ENG'
    assert collector.batch(2)['events'][0]['payload']['claimant'] == 'FRA'
    for invalid in (-1, True, 2**63):
        with pytest.raises(ValueError, match='CLAIM_EXPIRY_CURSOR_INVALID'):
            collector.batch(invalid)
