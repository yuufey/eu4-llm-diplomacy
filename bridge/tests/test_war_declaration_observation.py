"""Strict public decoding and bounded collection for native war declarations."""
from copy import deepcopy

import pytest

from bridge import country_modifier_observation as modifiers
from bridge import rival_observation as rivals
from bridge import war_declaration_observation as observation
from bridge.war_participants import SOURCE as PARTICIPANT_SOURCE


GAME_SHA = observation.GAME_SHA256
SESSION = '324-war-session'
DATE = 56_700_000
WAR_ID = 'war_0123456789abcdef_00000001'


def fullref(tag, slot=7):
    return f'0x{(slot << 32) | int.from_bytes(tag.encode("ascii"), "little"):x}'


def participants(actor='FRA', recipient='ENG', *, side_a=None, side_b=None,
                 actor_side='side_a', recipient_side='side_b'):
    side_a = list(side_a if side_a is not None else (actor, 'SPA'))
    side_b = list(side_b if side_b is not None else (recipient, 'POR'))
    return {
        'source': PARTICIPANT_SOURCE,
        'status': 'available',
        'complete': True,
        'side_a': side_a,
        'side_b': side_b,
        'actor_side': actor_side,
        'recipient_side': recipient_side,
        'reason': None,
    }


def native_event(sequence=1, *, session_id=SESSION, actor='FRA', recipient='ENG',
                 side_a=None, side_b=None, actor_side='side_a', recipient_side='side_b',
                 observer_side=1, **changes):
    event = {
        'event': observation.NATIVE_EVENT,
        'schema_version': 1,
        'session_id': session_id,
        'sequence': sequence,
        'country': 'FRA',
        'actor': actor,
        'recipient': recipient,
        'actor_fullref': fullref(actor),
        'recipient_fullref': fullref(recipient),
        'observer_fullref': fullref('FRA'),
        'war_id': WAR_ID,
        'date_raw': DATE,
        'actor_side': 1 if actor_side == 'side_a' else 2,
        'recipient_side': 1 if recipient_side == 'side_a' else 2,
        'observer_side': observer_side,
        'participants': participants(actor, recipient, side_a=side_a, side_b=side_b,
                                     actor_side=actor_side, recipient_side=recipient_side),
        'source': observation.SOURCE,
        'complete': True,
    }
    event.update(changes)
    return event


def strict_ack(**changes):
    ack = {
        'version': 49,
        modifiers.CAPABILITY: True,
        'native_country_modifier_add_wire': 1,
        'native_country_modifier_scope': modifiers.SCOPE,
        modifiers.REMOVE_CAPABILITY: True,
        'native_country_modifier_remove_wire': 1,
        modifiers.EXPIRY_CAPABILITY: True,
        'native_country_modifier_expiry_wire': 1,
        rivals.CAPABILITY: True,
        'native_rival_change_wire': 1,
        'native_rival_change_scope': rivals.SCOPE,
        observation.CAPABILITY: True,
        'native_war_declaration_wire': 1,
        'native_war_declaration_scope': observation.SCOPE,
    }
    ack.update(changes)
    return ack


def test_ack_requires_v49_through_v56_literal_war_contract_and_all_parent_capabilities():
    ack = strict_ack()
    assert observation.supported_ack(ack, GAME_SHA)
    assert observation.supported_ack(strict_ack(version=50), GAME_SHA)
    assert observation.supported_ack(strict_ack(version=51), GAME_SHA)
    assert observation.supported_ack(strict_ack(version=52), GAME_SHA)
    assert observation.supported_ack(strict_ack(version=53), GAME_SHA)
    assert observation.supported_ack(strict_ack(version=54), GAME_SHA)
    assert observation.supported_ack(strict_ack(version=55), GAME_SHA)
    assert observation.supported_ack(strict_ack(version=56), GAME_SHA)

    rejected = [
        (strict_ack(version=48), GAME_SHA),
        (strict_ack(version=57), GAME_SHA),
        (strict_ack(version=True), GAME_SHA),
        (strict_ack(**{observation.CAPABILITY: 1}), GAME_SHA),
        (strict_ack(native_war_declaration_wire=True), GAME_SHA),
        (strict_ack(native_war_declaration_wire=2), GAME_SHA),
        (strict_ack(native_war_declaration_scope='all_wars'), GAME_SHA),
        (strict_ack(**{modifiers.CAPABILITY: False}), GAME_SHA),
        (strict_ack(native_country_modifier_add_wire=True), GAME_SHA),
        (strict_ack(native_country_modifier_scope='all_country_modifiers'), GAME_SHA),
        (strict_ack(**{modifiers.REMOVE_CAPABILITY: False}), GAME_SHA),
        (strict_ack(native_country_modifier_remove_wire=True), GAME_SHA),
        (strict_ack(**{modifiers.EXPIRY_CAPABILITY: False}), GAME_SHA),
        (strict_ack(native_country_modifier_expiry_wire=True), GAME_SHA),
        (strict_ack(**{rivals.CAPABILITY: False}), GAME_SHA),
        (strict_ack(native_rival_change_wire=True), GAME_SHA),
        (strict_ack(native_rival_change_scope='all_rival_changes'), GAME_SHA),
        (strict_ack(), '0' * 64),
    ]
    missing_parent = strict_ack()
    del missing_parent[modifiers.EXPIRY_CAPABILITY]
    rejected.append((missing_parent, GAME_SHA))
    fake_caps = strict_ack()
    del fake_caps[observation.CAPABILITY]
    fake_caps['caps'] = [observation.CAPABILITY]
    rejected.append((fake_caps, GAME_SHA))

    for bad_ack, sha256 in rejected:
        assert not observation.supported_ack(bad_ack, sha256)


@pytest.mark.parametrize('case', ['actor', 'recipient', 'third_party_actor_side_b'])
def test_native_membership_maps_fra_to_the_actual_participant_side(case):
    if case == 'actor':
        event = native_event()
        expected_actor, expected_recipient, expected_observer = 'FRA', 'ENG', 'side_a'
    elif case == 'recipient':
        event = native_event(actor='ENG', recipient='FRA', side_a=['FRA', 'SPA'],
                             side_b=['ENG', 'POR'], actor_side='side_b', recipient_side='side_a',
                             observer_side=1)
        expected_actor, expected_recipient, expected_observer = 'ENG', 'FRA', 'side_a'
    else:
        event = native_event(actor='ENG', recipient='CAS', side_a=['CAS', 'POR'],
                             side_b=['ENG', 'FRA'], actor_side='side_b', recipient_side='side_a',
                             observer_side=2)
        expected_actor, expected_recipient, expected_observer = 'ENG', 'CAS', 'side_b'

    public = observation.public_observation(event, SESSION)
    assert public is not None
    assert public['payload']['actor'] == expected_actor
    assert public['payload']['recipient'] == expected_recipient
    assert public['payload']['observer_side'] == expected_observer
    assert public['payload']['participants']['source'] == 'native_war_side_vectors'
    assert public['payload']['participants']['actor_side'] == event['participants']['actor_side']
    assert public['payload']['participants']['recipient_side'] == event['participants']['recipient_side']
    labeled = observation.project_role_labels(public['payload'])
    assert labeled['attackers'] == event['participants'][event['participants']['actor_side']]
    assert labeled['defenders'] == event['participants'][event['participants']['recipient_side']]
    assert labeled['observer_role'] == ('attacker' if expected_observer == event['participants']['actor_side'] else 'defender')
    assert 'attackers' not in public['payload']
    assert public['objects'][0] == {
        'type': 'war', 'war_id': WAR_ID, 'actor': expected_actor, 'recipient': expected_recipient,
    }


@pytest.mark.parametrize('changes', [
    {'schema_version': True},
    {'sequence': True},
    {'sequence': 0},
    {'country': 'POR'},
    {'complete': 1},
    {'source': 'native_war_declaration_fixture'},
    {'date_raw': True},
    {'actor_side': True},
    {'observer_side': True},
])
def test_native_rows_require_literal_fields_and_wire_side_numbers(changes):
    assert observation.public_observation(native_event(**changes), SESSION) is None


@pytest.mark.parametrize('mutation', [
    'wrong_source', 'unknown', 'overlap', 'observer_side_without_fra',
    'actor_side_mismatch', 'actor_missing',
])
def test_participants_require_complete_disjoint_sides_and_consistent_membership(mutation):
    event = native_event()
    raw = event['participants']
    if mutation == 'wrong_source':
        raw['source'] = 'query1_cache'
    elif mutation == 'unknown':
        event['participants'] = {
            'source': PARTICIPANT_SOURCE, 'status': 'unknown', 'complete': False,
            'side_a': [], 'side_b': [], 'actor_side': None, 'recipient_side': None,
            'reason': 'PARTICIPANT_UNREADABLE',
        }
    elif mutation == 'overlap':
        raw['side_b'].append('FRA')
    elif mutation == 'observer_side_without_fra':
        event['observer_side'] = 2
    elif mutation == 'actor_side_mismatch':
        event['actor_side'] = 2
    elif mutation == 'actor_missing':
        raw['side_a'] = ['SPA']

    assert observation.public_observation(event, SESSION) is None


@pytest.mark.parametrize('changes', [
    {'war_id': 'war_0123456789abcdef_0000001'},
    {'war_id': 'war_0123456789ABCDEF_00000001'},
    {'actor_fullref': fullref('ENG')},
    {'recipient_fullref': fullref('FRA')},
    {'observer_fullref': fullref('ENG')},
    {'actor_fullref': fullref('FRA', slot=4096)},
])
def test_opaque_war_ids_and_country_references_must_be_canonical(changes):
    assert observation.public_observation(native_event(**changes), SESSION) is None


def test_foreign_session_is_rejected_by_decoder_and_ignored_by_collector():
    event = native_event(session_id='other-session')
    assert observation.public_observation(event, SESSION) is None
    collector = observation.Collector(SESSION)
    collector.observe(event)
    assert collector.batch(0) == {'events': [], 'complete': True, 'gaps': []}


def test_event_identity_is_stable_and_decoded_participants_are_deep_copies():
    native = native_event(sequence=23)
    first = observation.public_observation(native, SESSION)
    second = observation.public_observation(deepcopy(native), SESSION)
    assert first is not None and second is not None
    assert first['event_id'] == second['event_id'] == observation.event_id(SESSION, 23)

    native['participants']['side_a'].append('CAS')
    assert first['payload']['participants']['side_a'] == ['FRA', 'SPA']
    first['payload']['participants']['side_a'].append('TUR')
    fresh = observation.public_observation(native_event(sequence=23), SESSION)
    assert fresh is not None and fresh['payload']['participants']['side_a'] == ['FRA', 'SPA']
    assert fresh['event_id'] == first['event_id']


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
    context = {'session_id': SESSION, 'observer': 'FRA', 'game_sha256': GAME_SHA}
    return event, context


@pytest.mark.parametrize('mutation', [
    'event_session', 'event_observer', 'context_observer', 'game_sha',
    'objects', 'source_session', 'source_scope', 'date_semantics', 'source_sequence',
])
def test_persisted_snapshot_rejects_cross_context_or_relabelled_sources(mutation):
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
    elif mutation == 'objects':
        event['objects'] = [{'type': 'country', 'country': 'FRA'}]
    elif mutation == 'source_session':
        event['source']['session_id'] = 'foreign-session'
    elif mutation == 'source_scope':
        event['source']['scope'] = 'all_wars'
    elif mutation == 'date_semantics':
        event['source']['date_semantics'] = 'collection_time'
    elif mutation == 'source_sequence':
        event['source']['native_sequence'] += 1

    assert not observation.valid_event_snapshot(event, context)


def test_collector_deduplicates_conflicts_and_reports_sequence_jumps():
    collector = observation.Collector(SESSION)
    event = native_event(sequence=1)
    collector.observe(event)
    collector.observe(deepcopy(event))
    collector.observe(native_event(sequence=1, date_raw=DATE + 1))
    collector.observe(native_event(sequence=3))

    batch = collector.batch(0)
    assert [row['native_sequence'] for row in batch['events']] == [1, 3]
    assert not batch['complete']
    assert set(batch['gaps']) == {'WAR_DECLARATION_SEQUENCE_CONFLICT', 'WAR_DECLARATION_SEQUENCE_GAP'}


def test_collector_preserves_drop_health_and_transport_gaps():
    collector = observation.Collector(SESSION)
    collector.observe({
        'event': observation.NATIVE_GAP, 'session_id': SESSION,
        'dropped': 1, 'complete': False,
    })
    collector.observe({
        'event': 'diplomacy_observer_health', 'session_id': SESSION,
        'war_declaration_source': {
            'installed': True, 'transport_fault': True, 'queue_readable': True,
            'total_dropped': 2, 'queued': 0,
        },
    })
    assert set(collector.batch(0)['gaps']) == {
        'WAR_DECLARATION_CAPTURE_DROPPED', 'WAR_DECLARATION_TRANSPORT_FAULT',
    }


def test_collector_reports_invalid_and_unavailable_health():
    collector = observation.Collector(SESSION)
    collector.observe({
        'event': 'diplomacy_observer_health', 'session_id': SESSION,
        'war_declaration_source': {
            'installed': False, 'transport_fault': False, 'queue_readable': True,
            'total_dropped': 0, 'queued': 0,
        },
    })
    collector.observe({
        'event': 'diplomacy_observer_health', 'session_id': SESSION,
        'war_declaration_source': {'installed': True},
    })
    assert set(collector.batch(0)['gaps']) == {
        'WAR_DECLARATION_HEALTH_INVALID', 'WAR_DECLARATION_SOURCE_UNAVAILABLE',
    }


def test_collector_eviction_only_marks_cursors_behind_the_evicted_sequence(monkeypatch):
    monkeypatch.setattr(observation, 'MAX_EVENTS', 2)
    collector = observation.Collector(SESSION)
    for sequence in range(1, 4):
        collector.observe(native_event(sequence=sequence))

    stale = collector.batch(0)
    current = collector.batch(1)
    assert stale['complete'] is False
    assert 'WAR_DECLARATION_CACHE_EVICTED' in stale['gaps']
    assert current['complete'] is True
    assert current['gaps'] == []
    assert [row['native_sequence'] for row in current['events']] == [2, 3]
