"""v10 ingest and public-event boundaries; synthetic RETR, retained base fixture."""
from copy import deepcopy
import hashlib
import struct

import pytest

from bridge.tests.test_information_battle_end_state_wire import _base7, _known
from bridge.tests.test_information_battles import load_fra_fixture, make_source
from work import information_battle_end_state_wire as v9
from work import information_battle_retreat_wire as v10
from work import ingest_information_battle_raw_live as ingest


def _frame(*, foreign_flags=(0, 1, 1, 2), own_flags=(0, 1, 1, 255), capture_source=None):
    base7 = _base7()
    base9 = v9.encode(base7, _known(base7, (0, 0)))
    decoded = v9.decode(base9)
    winner = decoded['observation']['summary']['control_byte']
    loser = 1 - winner
    own = decoded['context']['sides'][loser]['participants']['full_refs'][0]
    foreign = decoded['context']['sides'][winner]['participants']['full_refs'][0]
    snapshot = {'state': 'known', 'sequence': decoded['observation']['sequence'],
        'raw_date': decoded['observation']['result']['raw_date'], 'kind': decoded['context']['kind'],
        'losing_combat_side': loser, 'initial_unit_count': 3,
        'units': [{'ordinal': 0, 'owner_full_ref': own, 'raw_flags': list(own_flags)},
                  {'ordinal': 2, 'owner_full_ref': foreign, 'raw_flags': list(foreign_flags)}]}
    if capture_source is not None:
        snapshot['capture_source'] = capture_source
    return v10.encode(base9, snapshot), own


def _events(tmp_path, payload, observer_ref=None):
    tmp_path.mkdir()
    fixture = deepcopy(load_fra_fixture())
    fixture['payload_hex'] = payload.hex()
    fixture['context_date'] = max(fixture['context_date'],
        v10.decode(payload)['observation']['result']['raw_date'])
    observer = (int(observer_ref, 16).to_bytes(8, 'little')[:3].decode('ascii')
                if observer_ref is not None else 'FRA')
    source, *_ = make_source(tmp_path, fixture=fixture, observer=observer, observer_ref=observer_ref)
    return source.poll_events(source.context(), None)['events']


def test_public_event_marks_uncaptured_overrun_retreat_inapplicable(tmp_path):
    base7 = _base7()
    initial = v9.decode(v9.encode(base7, _known(base7, (0, 0))))
    loser = 1 - initial['observation']['summary']['control_byte']
    gates = [0, 0]
    gates[loser] = 1
    payload = v10.encode(v9.encode(base7, _known(base7, gates)), {'state': 'unknown'})
    own = initial['context']['sides'][loser]['participants']['full_refs'][0]
    event = _events(tmp_path / 'overrun', payload, f'{own:016x}')[0]
    retreat = event['payload']['battle_fields']['retreat']
    assert retreat['status'] == 'not_applicable'
    assert retreat['combat_side_index'] == loser
    assert event['source']['retreat_projection_version'] == 2
    assert event['complete'] is False


@pytest.mark.parametrize('capture_source', [None, 'unit_removal_state'])
def test_v10_ingest_retains_raw_for_private_verification(capture_source):
    payload, _ = _frame(capture_source=capture_source)
    version, decoded = ingest._decode_payload(payload)
    assert version == 10 and decoded == v10.decode(payload)
    message = {'group_id': 1, 'message_id': '1', 'payload': payload,
        'payload_sha256': hashlib.sha256(payload).hexdigest(), 'payload_bytes': len(payload),
        'total_bytes': len(payload), 'transport_complete': True}
    result = ingest._message_report(message,
        group={'received_count': 1, 'fragment_count': 1, 'status': 'complete'}, index=0)
    assert result['raw_payload_hex'] == payload.hex()
    assert result['decode']['wire_version'] == 10


@pytest.mark.parametrize('mutation', ['identity', 'trailing', 'base'])
def test_v10_ingest_rejects_malformed_envelope(mutation):
    payload = bytearray(_frame()[0])
    if mutation == 'identity':
        body = 20 + struct.unpack_from('<I', payload, 6)[0]
        payload[body] ^= 1
    elif mutation == 'base':
        payload[14:16] = (10).to_bytes(2, 'little')
    else:
        payload += b'\0'
    with pytest.raises(ingest.RawIngestError, match='v10_decode_failed'):
        ingest._decode_payload(bytes(payload))


@pytest.mark.parametrize('capture_source', [None, 'unit_removal_state'])
def test_public_event_exposes_own_positive_without_private_unit_values(tmp_path, capture_source):
    payload, own = _frame(capture_source=capture_source)
    events = _events(tmp_path / 'one', payload, f'{own:016x}')
    assert len(events) == 1
    event = events[0]
    retreat = event['payload']['battle_fields']['retreat']
    assert retreat['status'] == 'known'
    assert retreat['value']['observed_unit_count'] == 1
    assert retreat['value']['count_is_lower_bound'] is True
    expected_scope = ('observer_owned_units_before_combat_removal' if capture_source
                      else 'observer_owned_units_at_regular_battle_end')
    assert retreat['value']['scope'] == expected_scope
    assert event['source']['projection_version'] == 30
    assert event['source']['name'] == 'IBOW.v10'
    assert 'payload_sha256' not in event['source']
    assert event['source']['hash_basis'] == 'observer_visible_battle_fields'
    from bridge.tests.test_information_battles import contains_key
    assert all(not contains_key(event, key)
               for key in ('owner_full_ref', 'initial_unit_count', 'ordinal'))
    # The unchanged base has its own native-text raw_flags field. RETR flags
    # must not escape their projection, as also proved by the equality test.
    assert not contains_key(retreat, 'raw_flags')


@pytest.mark.parametrize('capture_source', [None, 'unit_removal_state'])
def test_foreign_flag_changes_do_not_change_any_public_event_or_digest(tmp_path, capture_source):
    first, own = _frame(foreign_flags=(0, 1, 1, 2), capture_source=capture_source)
    second, _ = _frame(foreign_flags=(255, 128, 2, 0), capture_source=capture_source)
    assert first != second
    assert hashlib.sha256(first).digest() != hashlib.sha256(second).digest()
    assert _events(tmp_path / 'first', first, f'{own:016x}') == _events(
        tmp_path / 'second', second, f'{own:016x}')


@pytest.mark.parametrize('capture_source', [None, 'unit_removal_state'])
def test_same_tag_wrong_generation_does_not_admit_observer(tmp_path, capture_source):
    payload, own = _frame(capture_source=capture_source)
    assert _events(tmp_path / 'wrong', payload, f'{own ^ (1 << 56):016x}') == []


@pytest.mark.parametrize('capture_source', [None, 'unit_removal_state'])
def test_winner_observer_does_not_learn_loser_retreat_flags_through_digest(tmp_path, capture_source):
    first, _ = _frame(own_flags=(0, 1, 1, 255), capture_source=capture_source)
    second, _ = _frame(own_flags=(255, 128, 2, 0), capture_source=capture_source)
    decoded = v10.decode(first)
    winner = decoded['observation']['summary']['control_byte']
    observer_ref = decoded['context']['sides'][winner]['participants']['full_refs'][0]
    before = _events(tmp_path / 'before', first, f'{observer_ref:016x}')
    after = _events(tmp_path / 'after', second, f'{observer_ref:016x}')
    assert len(before) == 1 and before == after
    assert before[0]['payload']['battle_fields']['retreat']['reason'] == 'FOREIGN_RETREAT_VISIBILITY_UNVERIFIED'
