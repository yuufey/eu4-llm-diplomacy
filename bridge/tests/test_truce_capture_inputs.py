"""Private raw-input boundaries; these fixtures never open a process."""
from copy import deepcopy

import pytest

from bridge.information import truce_capture as capture


def memory(observer='FRA'):
    observer_ref = 0x0100007a00000000 | int.from_bytes(observer.encode('ascii'), 'little')
    bindings = {observer: {'country_pointer': '0x100000', 'slot': 122, 'fullref': hex(observer_ref)},
                'NAV': {'country_pointer': '0x200000', 'slot': 90, 'fullref': '0x0100005a0056414e'}}
    data = {0x300000 + 0x233dc88: (10).to_bytes(4, 'little'),
            0x300000 + 0x233dd8c: (5).to_bytes(4, 'little')}
    for actor, target, table in [(observer, 'NAV', 0x400000), ('NAV', observer, 0x500000)]:
        data[int(bindings[actor]['country_pointer'], 0) + 0x1510] = table.to_bytes(8, 'little')
        row = bytearray(0x48)
        row[:8] = (0x600000).to_bytes(8, 'little')
        row[0x10:0x18] = int(bindings[target]['fullref'], 0).to_bytes(8, 'little')
        row[0x24] = 255
        row[0x34:0x38] = (56551344).to_bytes(4, 'little')
        row[0x45] = 1 if actor == observer else 0
        data[table + bindings[target]['slot'] * 0x48] = bytes(row)
    return bindings, data


@pytest.mark.parametrize('observer', ['FRA', 'TUR'])
def test_generic_country_both_directions_and_signed_widths(observer):
    bindings, data = memory(observer)
    result = capture.read_inputs(lambda address, size, label: data[address], 0x300000, bindings, 'NAV',
                                 observer=observer)
    rows = result['value']['directed_records']
    assert [(row['actor'], row['target']) for row in rows] == [(observer, 'NAV'), ('NAV', observer)]
    assert [row['direct_flag'] for row in rows] == [True, False]
    assert [row['adjustment_signed_i8'] for row in rows] == [-1, -1]
    assert all(row['date_input_signed_i32'] == 56551344 and row['computed_expiry'] is None for row in rows)
    assert result['complete'] is False


@pytest.mark.parametrize('target', ['FRA', 'France', '', None, True])
def test_invalid_target_never_reads(target):
    calls = []
    with pytest.raises(ValueError):
        capture.read_inputs(lambda *args: calls.append(args), 0x300000, {}, target)
    assert calls == []


@pytest.mark.parametrize('slot', [True, -1, 4096, 91, '90'])
def test_bad_recipient_slot_is_rejected(slot):
    bindings, data = memory()
    bindings['NAV']['slot'] = slot
    with pytest.raises(ValueError):
        capture.read_inputs(lambda address, size, label: data[address], 0x300000, bindings, 'NAV')


@pytest.mark.parametrize('kind', ['short', 'null_owner', 'wrong_recipient'])
def test_row_cannot_supply_values_without_owner_and_recipient(kind):
    bindings, data = memory()
    key = 0x400000 + bindings['NAV']['slot'] * 0x48
    row = bytearray(data[key])
    if kind == 'short':
        row = row[:0x40]
    elif kind == 'null_owner':
        row[:8] = bytes(8)
    else:
        row[0x10:0x18] = bytes(8)
    data[key] = bytes(row)
    with pytest.raises(ValueError):
        capture.read_inputs(lambda address, size, label: data[address], 0x300000, bindings, 'NAV')


def test_profile_closure_keeps_old_base_immutable_and_adds_calendar_guards():
    profile = capture._load_profile()
    base = capture._base_capture._load_profile()
    assert profile['profile_id'] == capture.PROFILE_ID
    assert profile['field'] == 'R03.truce_until.inputs'
    assert len(profile['code_guards']) == len(base['code_guards']) + 12
    assert profile['code_guards'][:len(base['code_guards'])] == base['code_guards']
    assert len(profile['source_pins']) == 13


def test_admission_rejects_unverified_nonplayer_role(monkeypatch):
    monkeypatch.setattr(capture._owner, '_bound_admission', lambda *args: {
        'status': 'known', 'admitted': True, 'observer_nonplayer_role': {'verified': False}})
    gate = capture._admission(None, 0x300000, {}, 'FRA', 'NAV')
    assert gate['status'] == 'unknown' and gate['admitted'] is None


def test_guard_load_returns_independent_dicts():
    first = capture._load_profile()
    saved = deepcopy(first)
    first['code_guards'].clear()
    assert capture._load_profile() == saved
