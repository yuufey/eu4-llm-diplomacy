"""Exact subsidy-expiry wire, bounded collector and inherited v62 ACKs."""
from copy import deepcopy

import pytest

from bridge import country_modifier_observation, mission_availability_observation
from bridge import mission_condition_observation, mission_observation, relation_observation
from bridge import rival_observation, subsidy_expiry_observation as observation
from bridge import war_declaration_observation
from bridge.tests.test_information_rival_record_events import record_ack


SESSION_ID = 'subsidy-expiry-python'
GAME_DATE = 56692920


def reference(tag, slot):
    return hex(0x100000000000000 | (slot << 32) | int.from_bytes(tag.encode('ascii'), 'little'))


def native_event(sequence=1, *, payer='FRA', recipient='SAV', **changes):
    event = {
        'event': observation.NATIVE_EVENT, 'session_id': SESSION_ID, 'sequence': sequence,
        'date_raw': GAME_DATE, 'payer_ref': reference(payer, 122),
        'recipient_ref': reference(recipient, 129),
        'observer_ref': reference('FRA', 122 if payer == 'FRA' else 129),
        'start_date_raw': GAME_DATE - 8784, 'end_date_raw': GAME_DATE - 24,
        'monthly_amount_raw': 3750, 'source': observation.SOURCE, 'wire': 1,
    }
    event.update(changes)
    return event


def native_ack(**changes):
    ack = {'event': 'diplomacy_observer_installed', 'session_id': SESSION_ID,
           'observer': 'FRA', 'version': 62, observation.CAPABILITY: True,
           'native_subsidy_expiry_wire': 1}
    ack.update(changes)
    return ack


def snapshot(event=None):
    event = native_event() if event is None else event
    public = observation.public_observation(event, SESSION_ID)
    return dict(public, event_type=observation.EVENT_TYPE, session_id=SESSION_ID, observer='FRA',
                complete=True, source={
                    'name': 'ObserverSession.read_native_subsidy_expiry_events', 'mode': 'live',
                    'session_id': SESSION_ID, 'native_sequence': public['native_sequence'],
                    'complete': True, 'scope': observation.SCOPE,
                    'date_semantics': observation.DATE_SEMANTICS})


def context():
    return {'session_id': SESSION_ID, 'observer': 'FRA', 'game_sha256': observation.GAME_SHA256}


@pytest.mark.parametrize('changes', [
    {'version': 61}, {'version': 65}, {'version': True}, {'version': 62.0},
    {observation.CAPABILITY: 1}, {observation.CAPABILITY: False},
    {'native_subsidy_expiry_wire': True}, {'native_subsidy_expiry_wire': 2},
])
def test_ack_requires_its_exact_literal_contract(changes):
    assert observation.supported_ack(native_ack(), observation.GAME_SHA256)
    assert not observation.supported_ack(native_ack(**changes), observation.GAME_SHA256)
    assert not observation.supported_ack(native_ack(), '0' * 64)


@pytest.mark.parametrize('payer,recipient', [('FRA', 'SAV'), ('SAV', 'FRA')])
def test_decoder_keeps_both_payment_directions_and_actual_occurrence_date(payer, recipient):
    public = observation.public_observation(native_event(payer=payer, recipient=recipient), SESSION_ID)
    assert public['game_date'] == GAME_DATE
    assert public['payload'] == {
        'payer': payer, 'recipient': recipient, 'start_date_raw': GAME_DATE - 8784,
        'end_date_raw': GAME_DATE - 24, 'monthly_amount_raw': 3750, 'scope': observation.SCOPE}
    assert public['objects'] == observation.objects(public['payload'])
    assert observation.valid_event_snapshot(snapshot(native_event(payer=payer, recipient=recipient)), context())


@pytest.mark.parametrize('changes', [
    {'event': 'native_subsidy_cancelled'}, {'source': 'subsidy_record_remove_return'},
    {'wire': True}, {'wire': 2}, {'complete': True}, {'schema_version': 1},
    {'sequence': True}, {'sequence': 0}, {'sequence': 2**63}, {'session_id': 'other-session'},
    {'date_raw': GAME_DATE - 24}, {'date_raw': -1}, {'date_raw': True},
    {'start_date_raw': 2**31}, {'end_date_raw': -2**31 - 1}, {'monthly_amount_raw': True},
    {'monthly_amount_raw': 2**31}, {'payer_ref': '0x0'}, {'recipient_ref': []},
    {'observer_ref': reference('FRA', 123)}, {'observer_ref': reference('SAV', 129)},
    {'payer_ref': reference('SAV', 122), 'recipient_ref': reference('ENG', 129)},
    {'recipient_ref': reference('FRA', 129)}, {'payer_ref': reference('FRA', 4096)},
])
def test_decoder_rejects_other_removals_invalid_identity_and_nonexpired_rows(changes):
    assert observation.public_observation(native_event(**changes), SESSION_ID) is None


def test_reference_comparison_uses_full_value_and_amount_keeps_signed_i32_contract():
    event = native_event(monthly_amount_raw=-2**31, end_date_raw=-2**31)
    event['observer_ref'] = '0x0' + event['observer_ref'][2:]
    assert observation.public_observation(event, SESSION_ID)['payload']['monthly_amount_raw'] == -2**31
    event['observer_ref'] = hex(int(event['payer_ref'], 16) + (1 << 48))
    assert observation.public_observation(event, SESSION_ID) is None


@pytest.mark.parametrize('changes', [
    {'session_id': 'other'}, {'observer': 'SAV'}, {'complete': False}, {'event_id': 'forged'},
    {'objects': [{'type': 'country', 'country': 'FRA'}]}, {'game_date': GAME_DATE - 24},
])
def test_snapshot_reuses_scope_and_actual_expiry_validation(changes):
    assert not observation.valid_event_snapshot(dict(snapshot(), **changes), context())
    altered = snapshot()
    altered['source']['date_semantics'] = 'collection_date'
    assert not observation.valid_event_snapshot(altered, context())
    assert not observation.valid_event_snapshot(snapshot(), dict(context(), game_sha256='0' * 64))


def test_shared_collector_deduplicates_conflicts_gaps_health_and_eviction():
    collector = observation.Collector(SESSION_ID)
    collector.max_events = 2
    collector.observe(native_event(1))
    collector.observe(native_event(1))
    assert len(collector.batch(0)['events']) == 1 and collector.batch(0)['complete']
    collector.observe(native_event(1, monthly_amount_raw=4000))
    collector.observe(native_event(3))
    collector.observe({'event': observation.NATIVE_GAP, 'session_id': SESSION_ID,
                       'complete': False, 'dropped': 2})
    collector.observe({'event': 'diplomacy_observer_health', 'session_id': SESSION_ID,
                       'subsidy_expiry_source': {'installed': True, 'queue_readable': True,
                           'queued': 0, 'dropped': 2, 'total_dropped': 2, 'transport_fault': False}})
    collector.observe(native_event(4))
    batch = collector.batch(0)
    assert [row['native_sequence'] for row in batch['events']] == [3, 4]
    assert set(batch['gaps']) == {'SUBSIDY_EXPIRY_SEQUENCE_CONFLICT', 'SUBSIDY_EXPIRY_SEQUENCE_GAP',
                                 'SUBSIDY_EXPIRY_CAPTURE_DROPPED', 'SUBSIDY_EXPIRY_CACHE_EVICTED'}
    assert batch['complete'] is False
    batch['events'][0]['payload']['payer'] = 'ENG'
    assert collector.batch(2)['events'][0]['payload']['payer'] == 'FRA'


_PARENT_ACK_READERS = [
    country_modifier_observation.supported_ack, country_modifier_observation.supported_remove_ack,
    country_modifier_observation.supported_expiry_ack, rival_observation.supported_ack,
    rival_observation.supported_record_ack, war_declaration_observation.supported_ack,
    relation_observation.supported_ack, relation_observation.supported_record_ack,
    relation_observation.supported_royal_record_ack, relation_observation.supported_directed_record_ack,
    relation_observation.supported_support_subject_record_ack, mission_observation.supported_ack,
    mission_observation.supported_set_ack, mission_availability_observation.supported_ack,
    mission_condition_observation.supported_ack, mission_condition_observation.supported_province_ack,
]


@pytest.mark.parametrize('reader', _PARENT_ACK_READERS, ids=lambda value: value.__module__ + '.' + value.__name__)
def test_v62_through_v64_inherit_exact_v61_wire_and_parent_capabilities(reader):
    ack = record_ack()
    assert reader(ack, observation.GAME_SHA256)
    ack['version'] = 62
    assert reader(ack, observation.GAME_SHA256)
    ack['version'] = 63
    assert reader(ack, observation.GAME_SHA256)
    ack['version'] = 64
    assert reader(ack, observation.GAME_SHA256)
    ack['version'] = 65
    assert not reader(ack, observation.GAME_SHA256)


@pytest.mark.parametrize('version', [62, 63, 64])
def test_subsidy_ack_supports_inherited_versions(version):
    assert observation.supported_ack(native_ack(version=version), observation.GAME_SHA256)


@pytest.mark.parametrize('key,invalid', [
    ('native_rival_record_observation', 1), ('native_rival_change_wire', 1),
    ('native_relation_change_wire', 4), ('native_support_subject_record_observation', False),
    ('native_mission_condition_wire', 1), ('native_country_modifier_add_wire', True),
])
def test_v62_keeps_inherited_rejection_rules(key, invalid):
    ack = record_ack(version=62)
    ack[key] = invalid
    assert not country_modifier_observation.supported_ack(ack, observation.GAME_SHA256)
    assert not rival_observation.supported_ack(ack, observation.GAME_SHA256)
