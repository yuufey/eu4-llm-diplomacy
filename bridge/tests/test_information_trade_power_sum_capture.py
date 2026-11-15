from copy import deepcopy

import pytest

from bridge.information import trade_power_sum_capture as capture


BASE = 0x140000000
DATA = 0x300000


class Reader:
    def __init__(self, guard=b'AB'):
        self.guard = guard
        self.rows = []

    def read(self, address, size, label):
        raw = self.guard if address == BASE+0x100 else (37).to_bytes(4, 'little')
        assert len(raw) == size
        self.rows.append({'address': hex(address), 'size': size, 'label': label,
                          'status': 'observed', 'raw_hex': raw.hex()})
        return raw


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setattr(capture, '_load_profile', lambda: {
        'code_guards': [{'name': 'sum', 'rva': '0x100', 'bytes': b'AB'.hex()}]})
    calls = []

    def leaf(reader, module_base, trade_record, country_scan):
        calls.append(1)
        raw = reader.read(DATA, 4, 'trade_power_sum.fixture.value')
        return {'status': 'observed', 'value': int.from_bytes(raw, 'little')}

    monkeypatch.setattr(capture._memory, 'read_fields', leaf)
    return calls


def record():
    reader = Reader()
    trade = {'country': 'FRA', 'id': 1}
    scan = {'status': 'observed', 'id': 2}
    result = capture.read_fields(reader, BASE, trade, scan)
    return result, trade, scan, reader.rows


def test_replay_binds_the_child_to_exact_parent_reads(configured):
    result, trade, scan, rows = record()
    assert result['status'] == 'observed'
    assert capture.validate_record(result, trade, scan, rows)
    assert len(configured) == 2


def test_changed_projected_value_is_rejected_without_new_native_reads(configured):
    result, trade, scan, rows = record()
    result['observation']['value'] += 1
    assert not capture.validate_record(result, trade, scan, rows)


def test_coherent_forged_child_trace_is_rejected_against_parent_log(configured):
    result, trade, scan, rows = record()
    result['raw_reads'][-1]['raw_hex'] = (38).to_bytes(4, 'little').hex()
    result['observation']['value'] = 38
    # Internal replay is coherent, but the real parent read remains 37.
    assert capture.validate_record(result, trade, scan)
    assert not capture.validate_record(result, trade, scan, rows)


@pytest.mark.parametrize('change', ['extra_read', 'missing_read', 'wrong_label', 'wrong_source'])
def test_replay_rejects_partial_or_unbound_proofs(configured, change):
    result, trade, scan, rows = record()
    if change == 'extra_read':
        result['raw_reads'].append(deepcopy(result['raw_reads'][-1]))
    elif change == 'missing_read':
        result['raw_reads'].pop()
    elif change == 'wrong_label':
        result['raw_reads'][-1]['label'] += '.changed'
    else:
        trade['id'] += 1
    assert not capture.validate_record(result, trade, scan, rows)


def test_guard_mismatch_stops_before_member_reads(configured):
    reader = Reader(guard=b'AC')
    result = capture.read_fields(reader, BASE, {}, {})
    assert result['status'] == 'unknown'
    assert result['runtime_code_guard']['status'] == 'mismatch'
    assert configured == []
    assert len(reader.rows) == 1


def test_retraction_cannot_retain_an_observed_child(configured):
    result, trade, scan, rows = record()
    withdrawn = capture.retract_record(result, 'parent_retracted')
    assert withdrawn['status'] == 'unknown' and withdrawn['observation'] is None
    assert not capture.validate_record(withdrawn, trade, scan, rows)
    assert result['status'] == 'observed'
