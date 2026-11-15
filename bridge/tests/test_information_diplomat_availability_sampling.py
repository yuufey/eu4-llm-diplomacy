from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information import diplomat_tasks_memory as memory
from bridge.information.country_state import NativeCountryStateSource
from bridge.information.diplomat_tasks import NativeDiplomatTasksSource
from bridge.information.observation_time import sampled_read
from bridge.tests import test_information_diplomat_tasks as source_tests
from bridge.tests import test_information_diplomat_tasks_memory as memory_tests


def _query():
    return {'topic': 'N05', 'object': {'type': 'country', 'country': 'FRA'},
            'fields': ['diplomats_available'], 'parameters': {'reference_recipient': 'ENG'}}


@pytest.mark.parametrize('states,expected', [([0, 2, 1, 0], 2), ([2, 1], 0), ([], 0), ([9, 0], 1)])
def test_normal_n05_entry_reuses_validated_idle_count(tmp_path, monkeypatch, states, expected):
    rows = [source_tests._row(index, state) for index, state in enumerate(states)]
    report = source_tests._report(rows)
    monkeypatch.setattr(memory, 'capture', lambda *args, **kwargs: deepcopy(report))
    monkeypatch.setattr(memory, 'validate_capture', lambda *args: True)
    base = source_tests._Base(tmp_path)
    context = base.context()
    with sampled_read(_query(), context):
        result = NativeCountryStateSource(base).read(_query(), context)
    assert result['fields']['diplomats_available'] == {'status': 'known', 'value': expected}
    assert result['source']['provenance']['native_function_invoked'] is False


def test_unreadable_task_graph_keeps_existing_public_projection_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(NativeDiplomatTasksSource, 'read', lambda *args:
        {'fields': {'diplomat_tasks': {'status': 'unknown', 'reason': 'unreadable'}}})
    inspected = {'actor': 'FRA', 'recipient': 'ENG',
        'resources': {'diplomats': {'availability_verified': True, 'available_count': 2}}}
    monkeypatch.setattr(NativeCountryStateSource, '_inspect', staticmethod(lambda *args: (inspected, None)))
    base = source_tests._Base(tmp_path)
    context = base.context()
    with sampled_read(_query(), context):
        result = NativeCountryStateSource(base).read(_query(), context)
    assert result['fields']['diplomats_available'] == {'status': 'known', 'value': 2}


def _capture_setup(monkeypatch, next_date):
    reader = memory_tests._reader()

    class Kernel:
        def OpenProcess(self, *args):
            return object()

    def identity(report, *args):
        report['identity'].update(installation_creation_filetime=123,
            installation_session_id='sample', process_creation_filetime=123,
            process_path='fake-eu4.exe', process_path_sha256=memory.EXPECTED_EXE_SHA256,
            process_path_sha256_matches_expected=True, process_creation_matches_installation=True,
            binding_verified=True)
        return memory_tests.MODULE_BASE

    monkeypatch.setattr(memory, '_load_installation', lambda path: {'pid': 1})
    monkeypatch.setattr(memory, '_configure_kernel', Kernel)
    monkeypatch.setattr(memory, '_capture_identity', identity)
    monkeypatch.setattr(memory, '_file_code_guard', lambda *args: {'status': 'observed'})
    monkeypatch.setattr(memory, 'AddressBoundedRPM', lambda *args: reader)
    monkeypatch.setattr(memory, '_close_process_handle', lambda *args:
        {'status': 'closed', 'success': True, 'closed': True})
    snapshot = memory._snapshot

    def changing_snapshot(*args):
        result = snapshot(*args)
        reader.i32(0x6500000000 + 0x1DD0, next_date)
        return result

    monkeypatch.setattr(memory, '_snapshot', changing_snapshot)
    return {'mode': 'live', 'session_id': 'sample', 'game_date': source_tests.GAME_DATE,
            'game_sha256': memory.EXPECTED_EXE_SHA256}


def test_diplomat_capture_accepts_forward_window_and_preserves_raw_dates(monkeypatch):
    context = _capture_setup(monkeypatch, source_tests.GAME_DATE + 24)
    with sampled_read(_query(), context):
        report = memory.capture(Path('fake-installation.json'))
        assert report['status'] == 'observed', report['errors']
        assert memory.validate_capture(report, context, 123)
        forged = deepcopy(report)
        forged['after']['game_date']['value'] += 24
        assert not memory.validate_capture(forged, context, 123)
    assert report['before']['game_date']['value'] == source_tests.GAME_DATE
    assert report['after']['game_date']['value'] == source_tests.GAME_DATE + 24
    assert not memory.validate_capture(report, context, 123)


@pytest.mark.parametrize('active_window,next_date', [(False, source_tests.GAME_DATE + 24),
    (True, source_tests.GAME_DATE - 24)])
def test_diplomat_capture_keeps_strict_default_and_rejects_rollback(monkeypatch, active_window, next_date):
    context = _capture_setup(monkeypatch, next_date)
    with sampled_read(_query(), context, enabled=active_window):
        report = memory.capture(Path('fake-installation.json'))
    assert report['status'] == 'doublepass_mismatch'
    assert '$.game_date' in report['doublepass']['mismatches']
