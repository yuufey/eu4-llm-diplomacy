"""Native prerequisite results require the same complete double-pass lifetime."""
from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information import mission_memory as mm
from bridge.information import mission_prerequisite_profile as pp
from bridge.tests.test_information_mission_task_memory import task_fixture, FakeCaptureKernel, _capture_patches

def fixture():
    reader, module, _ = task_fixture(('task_a',))
    profile = pp.load_profile()
    for guard in profile['code_guards']:
        reader.put(module + guard['rva'], bytes.fromhex(guard['raw_hex']))
    reader.put(0x740000 + 0x128, bytes(16))
    return reader, module

def capture(reader, module, *, close_result=True, snapshot=None):
    kernel = FakeCaptureKernel(module, close_result=close_result)
    with ExitStack() as stack:
        for patched in _capture_patches(reader, kernel, snapshot=snapshot):
            stack.enter_context(patched)
        report = mm.capture(Path('fake-installation.json'), 'FRA', include_completed=True,
                            include_tasks=True, include_prerequisites=True)
    assert len(kernel.closed) == 1
    return report

def test_prerequisites_share_successful_capture_and_handle_close():
    reader, module = fixture()
    report = capture(reader, module)
    assert report['status'] == 'observed'
    assert report['doublepass']['prerequisite_consistent'] is True
    assert report['loaded_prerequisites']['tasks'][0]['required_task_ids'] == []
    assert report['cleanup']['handle_close']['closed'] is True

def test_changed_raw_prerequisite_header_with_same_empty_ids_is_rejected():
    reader, module = fixture()
    original = mm._snapshot
    calls = 0
    def snapshot(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            reader.dword_put(0x740000 + 0x130, 1, signed=True)
        return original(*args, **kwargs)
    report = capture(reader, module, snapshot=snapshot)
    assert report['doublepass']['consistent'] is True
    assert report['doublepass']['task_consistent'] is True
    assert report['doublepass']['prerequisite_consistent'] is False
    assert report['loaded_prerequisites']['status'] == 'unknown'

def test_close_failure_withdraws_prerequisites():
    reader, module = fixture()
    report = capture(reader, module, close_result=False)
    assert report['status'] == 'cleanup_error'
    assert report['doublepass']['prerequisite_consistent'] is False
    assert report['loaded_prerequisites']['status'] == 'unknown'

def test_prerequisite_option_requires_task_capture():
    with pytest.raises(ValueError, match='requires include_tasks'):
        mm.capture(Path('never-opened.json'), 'FRA', include_prerequisites=True)

def test_tampered_profile_fails_before_open(tmp_path, monkeypatch):
    profile = tmp_path / 'profile.json'
    profile.write_bytes(pp.PROFILE_FILE.read_bytes() + b' ')
    monkeypatch.setattr(pp, 'PROFILE_FILE', profile)
    monkeypatch.setattr(mm, '_configure_kernel', lambda: pytest.fail('must not open a process'))
    report = mm.capture(Path('never-opened.json'), 'FRA', include_tasks=True, include_prerequisites=True)
    assert report['status'] == 'prerequisite_profile_mismatch'
    assert report['cleanup']['handle_close']['status'] == 'not_opened'
