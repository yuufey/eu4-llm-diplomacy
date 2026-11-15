from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import battle_observer_context as observer_context
from bridge.information.observation_time import active, sampled_read
from bridge.tests.test_information_foreign_technology_capture import (
    _make_fixture, CONTROLLER_TYPES, GAME_DATE, MODULE_BASE, WORLD,
)


def _fixture():
    _, _, _, fixture = _make_fixture(country='UTR')
    fixture['image'].put(CONTROLLER_TYPES + 300 * 4, b'\0' * 4)
    return fixture


def _schedule_dates(image, values):
    start = image.label_counts.get('foreign_tech.date', 0)

    def on_read(reader, address, _size, label, occurrence):
        if label == 'foreign_tech.date' and occurrence > start:
            index = min(occurrence - start - 1, len(values) - 1)
            reader.put_i32(address, values[index])

    image.on_read = on_read


def _prepare_capture_runtime(monkeypatch, fixture):
    native = observer_context.native
    fixture['reader'].read_log.clear()
    profile = native._load_profile()
    guard_bytes = {int(row['rva'], 0): bytes.fromhex(row['bytes'])
                   for row in profile['code_guards']}
    kernel = SimpleNamespace(open_calls=0, close_calls=0)

    def open_process(*_):
        kernel.open_calls += 1
        return object()

    def close_handle(_):
        kernel.close_calls += 1
        return True

    kernel.OpenProcess = open_process
    kernel.CloseHandle = close_handle
    monkeypatch.setattr(native._identity, '_load_installation', lambda _: {'pid': 777})
    monkeypatch.setattr(native._identity, '_configure_kernel', lambda: kernel)
    monkeypatch.setattr(native._identity, '_capture_identity',
        lambda report, *_: (report['identity'].update(
            process_path='synthetic.exe', installation_session_id='scope-test',
            installation_pid=777, installation_creation_filetime=42) or MODULE_BASE))
    monkeypatch.setattr(native._mm, '_read_pe_rva_bytes',
                        lambda _path, rva, _size: guard_bytes[rva])
    monkeypatch.setattr(native._parent, 'AddressBoundedRPM', lambda *_: fixture['reader'])
    return kernel


def test_live_c01_capture_accepts_forward_dates_and_replays_its_raw_trace(monkeypatch):
    fixture = _fixture()
    _schedule_dates(fixture['image'], [GAME_DATE + 24, GAME_DATE + 48,
                                      GAME_DATE + 72, GAME_DATE + 96])
    kernel = _prepare_capture_runtime(monkeypatch, fixture)

    with sampled_read({'topic': 'C01'}, {'mode': 'live', 'game_date': GAME_DATE}) as window:
        report = observer_context.capture_binding(Path('installation.json'), 'UTR', GAME_DATE)

    assert report['status'] == 'observed'
    assert report['trace_replay_verified'] is True
    assert report['passes'][0]['context']['game_date'] == GAME_DATE + 24
    assert report['passes'][1]['context']['game_date'] == GAME_DATE + 72
    assert window.dates[0] == GAME_DATE and window.dates[-1] == GAME_DATE + 96
    assert kernel.open_calls == kernel.close_calls == 1


def test_live_c01_capture_rejects_a_backward_date_within_a_pass():
    fixture = _fixture()
    _schedule_dates(fixture['image'], [GAME_DATE + 24, GAME_DATE + 23])

    with sampled_read({'topic': 'C01'}, {'mode': 'live', 'game_date': GAME_DATE}):
        with pytest.raises(ValueError, match='BATTLE_OBSERVER_WORLD_CHANGED'):
            observer_context.read_binding(fixture['reader'], MODULE_BASE, 'UTR', GAME_DATE)


def test_live_c01_capture_keeps_two_pass_identity_comparison_strict():
    fixture = _fixture()
    image = fixture['image']
    start = image.label_counts.get('foreign_tech.physical_client_reference', 0)

    def change_physical_country(reader, address, _size, label, occurrence):
        if (label == 'foreign_tech.physical_client_reference'
                and occurrence == start + 3):
            reader.put_u64(WORLD + 0x1E60, fixture['observer_fullref'])

    image.on_read = change_physical_country
    with sampled_read({'topic': 'C01'}, {'mode': 'live', 'game_date': GAME_DATE}):
        with pytest.raises(ValueError, match='BATTLE_OBSERVER_BINDING_CHANGED'):
            observer_context.read_binding(fixture['reader'], MODULE_BASE, 'UTR', GAME_DATE)


def test_direct_read_and_capture_remain_same_date_strict(monkeypatch):
    fixture = _fixture()
    _schedule_dates(fixture['image'], [GAME_DATE, GAME_DATE + 24])
    assert not active()

    with pytest.raises(ValueError, match='BATTLE_OBSERVER_WORLD_CHANGED'):
        observer_context.read_binding(fixture['reader'], MODULE_BASE, 'UTR', GAME_DATE)

    assert not active()

    capture_fixture = _fixture()
    _schedule_dates(capture_fixture['image'], [GAME_DATE, GAME_DATE + 24])
    kernel = _prepare_capture_runtime(monkeypatch, capture_fixture)
    report = observer_context.capture_binding(Path('installation.json'), 'UTR', GAME_DATE)
    assert report['status'] == 'unknown'
    assert report['reason'] == 'BATTLE_OBSERVER_WORLD_CHANGED'
    assert report['cleanup']['status'] == 'closed'
    assert kernel.open_calls == kernel.close_calls == 1
    assert not active()


def test_context_prefers_information_health_and_publishes_latest_native_date(monkeypatch):
    session = SimpleNamespace(
        record={'session_id': 'scope-test', 'game_version': '1.37.4',
                'pid': 777, 'creation_filetime': 42,
                'game_sha256': observer_context.native.EXE_SHA256},
        session_id='scope-test',
        health=lambda: pytest.fail('strict health fallback must not run when information_health exists'),
        information_health=lambda: {'status': 'ready', 'complete': True,
                                    'date_raw': GAME_DATE, 'observer': 'FRA', 'reasons': []},
    )
    expected = {}

    def capture(_installation, observer, expected_date):
        expected.update(observer=observer, date=expected_date, scoped=active())
        return {'status': 'observed',
                'identity': {'installation_session_id': 'scope-test', 'installation_pid': 777,
                             'installation_creation_filetime': 42},
                'passes': [
                    {'context': {'game_date': GAME_DATE + 24},
                     'observer': {'fullref': '010000e500525455'}},
                    {'context': {'game_date': GAME_DATE + 48},
                     'observer': {'fullref': '010000e500525455'}},
                ]}

    monkeypatch.setattr(observer_context, 'capture_binding', capture)
    source = observer_context.BattleObserverContextSource(session, Path('installation.json'), 'UTR')
    context = source.context()

    assert expected == {'observer': 'UTR', 'date': GAME_DATE, 'scoped': True}
    assert context['status'] == 'ready'
    assert context['game_date'] == context['game_date_raw'] == GAME_DATE + 48
    assert context['game_day'] == (GAME_DATE + 48) // 24
    assert not active()
