"""Deadlines on verified current native queue entries, without response authority."""
from contextlib import closing
from copy import deepcopy
import struct

import pytest

from bridge import proposal_expiry
from bridge.information import InformationService
from bridge.information import native_pending_memory as native
from bridge.information.tools import InformationTools
from bridge.tests.test_information_native_pending_memory import _synthetic_memory, _capture
from bridge.tests.test_information_native_pending_source import setup, capture_report
from bridge.tests.test_information_pending_matters import _context, _query
from bridge.tests.test_information_proposal_expiry import offer, NOW
from bridge.tests.test_information_service import FakeClock, subscription_config


def current_queue(created, *, game_date=None):
    contract = native.load_contract()
    memory = _synthetic_memory(contract, [{}])
    header = bytearray(memory['blocks'][0x300000])
    struct.pack_into('<i', header, 0x2c, created)
    memory['blocks'][0x300000] = bytes(header)
    return native.read_queue(memory['read'], memory['country_pointer'], memory['recipient_ref'],
                             memory['module_base'], memory['session_id'], memory['resolve_country'],
                             contract, game_date=game_date)['value']


@pytest.mark.parametrize('created', [NOW - 96, 2**31 - 73])
def test_current_pending_deadline_reuses_the_observed_offer_threshold(created):
    value = current_queue(created)
    entry = value['entries'][0]
    original = offer()
    original.update(created2c=created, date2c=created)
    assert entry['deadline'] == proposal_expiry.project_deadline(original, enabled=True)
    assert entry['deadline']['value'] == created + 72
    assert native.validate_value(value) == value
    assert value['response_contexts_available'] is False
    assert 'proposal_id' not in entry and 'token3c' not in entry


@pytest.mark.parametrize('created', [0, -1, 2**31 - 72, 2**31 - 1])
def test_bad_pending_date_preserves_the_recognized_current_entry(created):
    value = current_queue(created)
    entry = value['entries'][0]
    assert entry['recognition'] == 'recognized'
    assert entry['deadline']['status'] == 'unknown'
    assert native.validate_value(value) == value


@pytest.mark.parametrize('damage', ['threshold', 'scale_bool', 'source_date_bool', 'basis', 'private_extra', 'unknown_extra'])
def test_closed_pending_projection_rejects_invalid_or_private_deadline(damage):
    value = current_queue(NOW - 96)
    field = value['entries'][0]['deadline']
    if damage == 'threshold':
        field['value'] += 1
    elif damage == 'scale_bool':
        field['scale'] = True
    elif damage == 'source_date_bool':
        field['pending_created_game_date'] = True
    elif damage == 'basis':
        field['basis'] = 'collection_date'
    elif damage == 'private_extra':
        field['private_pointer'] = '0x123400'
    else:
        value['entries'][0]['deadline'] = {**proposal_expiry.deadline_from_created_date(None), 'value': NOW}
    with pytest.raises(ValueError, match='NATIVE_PENDING_PUBLIC_DEADLINE_INVALID'):
        native.validate_value(value)


def test_legacy_projection_and_contract_keep_their_existing_shape():
    contract = native.load_contract()
    legacy = dict(contract, pending_deadline_verified=False)
    memory = _synthetic_memory(legacy, [{}])
    value = _capture(memory, legacy)['value']
    assert 'deadline' not in value['entries'][0]
    assert native.validate_value(value, legacy) == value
    assert native.validate_value(value) == value
    with pytest.raises(ValueError, match='NATIVE_PENDING_PUBLIC_DEADLINE_INVALID'):
        native.validate_value(current_queue(NOW - 96), legacy)


def test_future_creation_keeps_only_the_deadline_unknown():
    value = current_queue(NOW + 24, game_date=NOW)
    entry = value['entries'][0]
    assert entry['recognition'] == 'recognized'
    assert entry['deadline']['status'] == 'unknown'
    assert native.validate_value(value) == value


@pytest.mark.parametrize('game_date', [True, 0, -1, 2**31])
def test_invalid_current_date_rejects_snapshot(game_date):
    with pytest.raises(ValueError, match='NATIVE_PENDING_GAME_DATE_INVALID'):
        current_queue(NOW - 96, game_date=game_date)


@pytest.mark.parametrize('rva', [0x2f045d, 0xcf4e0])
def test_expiry_code_mismatch_stops_before_queue_read(monkeypatch, rva):
    contract = native.load_contract()
    base = 0x140000000
    reads = []

    def read(_reader, address, size, _label, _budget, _layout):
        reads.append(address)
        guard = next(row for row in contract['code_guards'] if base + row['rva'] == address)
        raw = bytes.fromhex(guard['raw_hex'])
        assert size == len(raw)
        return bytes([raw[0] ^ 1]) + raw[1:] if address == base + rva else raw

    monkeypatch.setattr(native.memory, '_profile_layout', lambda _profile: {})
    monkeypatch.setattr(native.memory, '_reader_read', read)
    with pytest.raises(ValueError, match='NATIVE_PENDING_RUNTIME_CODE_MISMATCH'):
        native._snapshot(None, base, {}, contract, 'synthetic', None)
    assert reads[-1] == base + rva


def test_query_report_change_and_reopen_preserve_current_deadlines(tmp_path, setup):
    source, base, state, _journal = setup
    initial_date = base._contexts[-1]['game_date']
    queue = current_queue(initial_date - 96)

    def capture(*_args):
        if state['failed']:
            return {'status': 'unknown', 'reason': 'NATIVE_PENDING_CAPTURE_FAILED'}
        report = capture_report(base._contexts[-1])
        report['value'] = deepcopy(queue)
        return report

    source.pending_capture = capture
    clock = FakeClock()
    database = tmp_path / 'deadline-information.sqlite3'
    with closing(InformationService(source, database, clock=clock)) as service:
        tools = InformationTools(service)
        report = tools.call('information_manage_report', {
            'request_id': 'deadline-report', 'operation': 'create', 'config': {
                'name': 'Current matters with deadlines', 'detail': 'brief', 'queries': [_query()]},
        })['report']
        result = tools.call('information_query', {"view": "full", 'request_id': 'deadline-query', 'report_id': report['id']})
        projected = result['items'][0]['fields']['pending_matters']['value']['native_inbound_pending']['value']
        assert projected['entries'][0]['deadline']['value'] == initial_date - 24
        subscription = tools.call('information_manage_subscription', {
            'request_id': 'deadline-change', 'operation': 'create',
            'config': subscription_config(report['id'], kind='change', every=5),
        })['subscription']

        def tick():
            clock.advance(5)
            return tools.call('information_tick', {"view": "full"})['results']

        assert tick() == []
        base._contexts = [_context(game_date=56554872)]
        assert tick() == []
        state['failed'] = True
        assert tick() == []
        queue['entries'] = []
        queue.update(native_queue_count=0, recognized_entry_count=0)
        state['failed'] = False
        delivered = tick()
        assert len(delivered) == 1 and tick() == []
        full = tools.call('information_get_result', {"view": "full", 'result_id': delivered[0]['result_id']})
        assert full == delivered[0]
        tools.call('information_manage_subscription', {
            'request_id': 'deadline-cancel', 'operation': 'cancel',
            'subscription_id': subscription['id'], 'expected_version': subscription['version'],
        })
    with closing(InformationService(source, database)) as reopened:
        assert InformationTools(reopened).call('information_get_result', {"view": "full", 'result_id': full['result_id']}) == full
