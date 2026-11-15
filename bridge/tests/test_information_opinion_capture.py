from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import opinion_capture as capture
from bridge.information import country_reference_memory
from bridge.tests.test_information_opinion_memory import Memory


def setup(monkeypatch):
    memory = Memory()
    scan = {'status':'observed', 'requested':{'FRA':memory.fra,'ENG':memory.eng}}
    monkeypatch.setattr(country_reference_memory, 'resolve_countries',
                        lambda *args, **kwargs:deepcopy(scan))
    return memory


def admitted(*args):
    return {'status':'known','admitted':True,'observer_nonplayer_role':{'verified':True}}


def test_pinned_profile_reuses_selection_and_adds_both_direction_guards():
    profile = capture._load_profile()
    assert profile['profile_id'] == 'opinion-memory-1374'
    assert [row['name'] for row in profile['code_guards']] == [
        'diplomacy_country_selection', 'bilateral_opinion_first_cell',
        'bilateral_opinion_reverse_cell']


def test_shared_python_comment_or_equivalent_change_does_not_control_admission(monkeypatch):
    original = capture._owner._sha

    def source_hash(path):
        if Path(path).resolve() == Path(capture._owner.__file__).resolve():
            pytest.fail('ordinary shared Python source was treated as a runtime guard')
        return original(path)

    monkeypatch.setattr(capture._owner, '_sha', source_hash)
    assert capture._load_profile()['profile_id'] == 'opinion-memory-1374'


def test_changed_profile_is_still_rejected(tmp_path, monkeypatch):
    changed = tmp_path / 'profile.json'
    changed.write_bytes(capture.PROFILE_FILE.read_bytes() + b' ')
    monkeypatch.setattr(capture, 'PROFILE_FILE', changed)
    with pytest.raises(ValueError, match='OPINION_PROFILE_PIN'):
        capture._load_profile()


def test_changed_native_opinion_guard_is_still_rejected():
    profile = capture._load_profile()
    base = 0x140000000
    rows = {base + int(row['rva'], 0): bytes.fromhex(row['bytes']) for row in profile['code_guards']}
    address = base + int(profile['code_guards'][-1]['rva'], 0)
    rows[address] = bytes([rows[address][0] ^ 1]) + rows[address][1:]
    reader = SimpleNamespace(read=lambda address, _size, _label: rows[address])
    with pytest.raises(ValueError, match='FOREIGN_TECH_RUNTIME_CODE_MISMATCH'):
        capture._owner._guards(reader, base, profile)


def test_both_directions_are_compared_independently(monkeypatch):
    memory = setup(monkeypatch)
    result = capture._backend_read(memory, 0x140000000, 'ENG', admission_reader=admitted)
    assert result['status'] == 'observed'
    assert result['consistency']['status'] == 'stable'
    fields = result['targets'][0]['fields']
    assert [fields[name]['value']['opinion'] for name in capture.FIELDS] == [-200,177]
    assert len(memory.reads) == 36


def test_denied_country_never_reads_opinion_cells(monkeypatch):
    memory = setup(monkeypatch)
    gate = lambda *args:{'status':'known','admitted':False}
    result = capture._backend_read(memory, 0x140000000, 'ENG', admission_reader=gate)
    assert memory.reads == []
    assert all(row == {'status':'invisible','reason':'admission_denied'}
               for row in result['targets'][0]['fields'].values())


def test_one_direction_changes_between_passes_without_losing_other(monkeypatch):
    memory = setup(monkeypatch)
    def change(raw, label):
        if label == 'opinion.ENG.to.FRA.cell':
            count = sum(item[2] == label for item in memory.reads)
            return (177+count).to_bytes(2,'little',signed=True)
        return raw
    memory.override = change
    result = capture._backend_read(memory, 0x140000000, 'ENG', admission_reader=admitted)
    fields = result['targets'][0]['fields']
    assert fields[capture.FIELDS[0]]['status'] == 'known'
    assert fields[capture.FIELDS[1]]['status'] == 'unknown'
    assert 'value' not in fields[capture.FIELDS[1]]


def test_nonplayer_role_is_required_before_field_read(monkeypatch):
    monkeypatch.setattr(capture._owner, '_bound_admission', lambda *args:{
        'status':'known','admitted':True,'observer_nonplayer_role':{'verified':False}})
    gate = capture._admission(None, 0, {}, 'FRA', 'ENG')
    assert gate['status'] == 'unknown' and gate['admitted'] is None
    assert gate['reason'] == 'OBSERVER_NONPLAYER_ROLE_UNVERIFIED'
    assert gate['field_scope']['physical_player_equals_observer_required'] is False
