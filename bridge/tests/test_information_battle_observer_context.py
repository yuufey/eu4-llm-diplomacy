"""Battle information identities do not inherit diplomacy execution authority."""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import battle_observer_context as observer_context
from bridge.information.battle_observer_context import BattleObserverContextSource
from bridge.information.model import InformationError
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools
from bridge.tests.test_information_foreign_technology_capture import (
    _make_fixture, CONTROLLER_TYPES, GAME_DATE, MODULE_BASE, WORLD,
)
from bridge.tests.test_information_battle_outcome_tail import fixture13
from bridge.tests.test_information_battles import make_source, battle_topic_query, event_id
from tools.serve_information import _build_runtime, build_parser


@pytest.mark.parametrize('tag', ['UTR', 'HSK'])
def test_native_role_binding_accepts_a_non_french_nonplayer(tag):
    _, _, _, fixture = _make_fixture(country=tag)
    fixture['image'].put(CONTROLLER_TYPES + 300 * 4, b'\0' * 4)
    passes = observer_context.read_binding(fixture['reader'], MODULE_BASE, tag, GAME_DATE)
    assert len(passes) == 2 and passes[0] == passes[1]
    assert passes[0]['observer']['tag'] == tag
    assert passes[0]['physical']['tag'] == 'POR'
    assert passes[0]['role']['verified'] is True


@pytest.mark.parametrize('mutation', ['player', 'controller', 'date', 'second_controller'])
def test_native_role_binding_rejects_player_or_unstable_reads(mutation):
    _, _, _, fixture = _make_fixture(country='UTR')
    image = fixture['image']
    image.put(CONTROLLER_TYPES + 300 * 4, b'\0' * 4)
    if mutation == 'player':
        observer = 'POR'
    else:
        observer = 'UTR'
    if mutation == 'controller':
        image.put(CONTROLLER_TYPES + 300 * 4, (1).to_bytes(4, 'little'))
    elif mutation == 'date':
        image.put_i32(WORLD + 0x1dd0, GAME_DATE + 1)
    elif mutation == 'second_controller':
        existing_reads = image.label_counts.get('battle_observer.controller_type', 0)
        def change_on_read(reader, address, size, label, occurrence):
            if label == 'battle_observer.controller_type' and occurrence == existing_reads + 2:
                reader.put(address, (1).to_bytes(4, 'little'))
        image.on_read = change_on_read
    with pytest.raises(ValueError, match='BATTLE_OBSERVER_'):
        observer_context.read_binding(fixture['reader'], MODULE_BASE, observer, GAME_DATE)


@pytest.mark.parametrize('failure', [None, 'file_guard', 'runtime_guard', 'identity_after', 'role'])
def test_native_capture_closes_its_handle_on_success_and_partial_failure(monkeypatch, failure):
    _, _, _, fixture = _make_fixture(country='UTR')
    image = fixture['image']
    fixture['reader'].read_log.clear()
    image.put(CONTROLLER_TYPES + 300 * 4, (1 if failure == 'role' else 0).to_bytes(4, 'little'))
    native = observer_context.native
    profile = native._load_profile()
    expected = {int(row['rva'], 0): bytes.fromhex(row['bytes']) for row in profile['code_guards']}
    if failure == 'runtime_guard':
        image.put(MODULE_BASE + next(iter(expected)), b'\0')
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
    identity_calls = []
    def identity(report, *_):
        identity_calls.append(True)
        report['identity'].update(process_path='synthetic.exe', creation=1)
        if failure == 'identity_after' and len(identity_calls) == 2:
            report['identity']['creation'] = 2
        return MODULE_BASE
    monkeypatch.setattr(native._identity, '_capture_identity', identity)
    monkeypatch.setattr(native._mm, '_read_pe_rva_bytes',
        lambda _, rva, size: b'\0' * size if failure == 'file_guard' else expected[rva])
    monkeypatch.setattr(native._parent, 'AddressBoundedRPM', lambda *_: fixture['reader'])
    result = observer_context.capture_binding(Path('installation.json'), 'UTR', GAME_DATE)
    assert kernel.open_calls == kernel.close_calls == 1
    assert result['cleanup']['status'] == 'closed'
    assert result['status'] == ('observed' if failure is None else 'unknown')


class Session:
    def __init__(self, record, health):
        self.record = record
        self.session_id = record['session_id']
        self.health_value = health

    def health(self):
        return deepcopy(self.health_value)


def _fake_session():
    return Session({'session_id': 'scope-test', 'game_version': '1.37.4',
                    'pid': 777, 'creation_filetime': 42,
                    'game_sha256': observer_context.native.EXE_SHA256},
                   {'status': 'ready', 'complete': True, 'date_raw': GAME_DATE,
                    'observer': 'FRA', 'reasons': []})


def _role_capture(tag, fullref, session_id='scope-test'):
    return {'status': 'observed', 'passes': [{'observer': {'tag': tag, 'fullref': fullref}}],
            'identity': {'installation_session_id': session_id, 'installation_pid': 777,
                         'installation_creation_filetime': 42}}


def test_context_uses_a_verified_information_observer_and_preserves_execution_scope(monkeypatch):
    session = _fake_session()
    monkeypatch.setattr(observer_context, 'capture_binding',
                        lambda *_: _role_capture('UTR', '010000e500525455'))
    primary = BattleObserverContextSource(session, Path('installation.json'), 'UTR')
    context = primary.context()
    assert context['status'] == 'ready' and context['observer'] == 'UTR'
    assert context['observer_ref'] == '010000e500525455'
    assert primary.event_types == ()
    assert set(row['topic_id'] for row in primary.catalog()) == set(observer_context.TOPICS)
    assert primary.poll_events(context, None)['events'] == []
    assert session.health()['observer'] == 'FRA'
    existing = DiplomacySource(SimpleNamespace(session=session), observer='UTR')
    assert existing.context()['status'] == 'unready'
    with pytest.raises(InformationError, match='session context'):
        primary.validate_query({'topic': 'A04'})


@pytest.mark.parametrize('status', ['unready', 'stale'])
def test_unready_session_does_not_read_native_roles(monkeypatch, status):
    session = _fake_session()
    session.health_value['status'] = status
    def unexpected(*_):
        pytest.fail('unready health must not open a process')
    monkeypatch.setattr(observer_context, 'capture_binding', unexpected)
    assert BattleObserverContextSource(session, Path('installation.json'), 'UTR').context()['status'] != 'ready'


def test_failed_role_capture_keeps_context_unready(monkeypatch):
    monkeypatch.setattr(observer_context, 'capture_binding', lambda *_: {'status': 'unknown'})
    context = BattleObserverContextSource(_fake_session(), Path('installation.json'), 'UTR').context()
    assert context['status'] == 'unready'
    assert context['reasons'][-1]['code'] == 'BATTLE_OBSERVER_ROLE_UNVERIFIED'


@pytest.mark.parametrize('key', ['installation_session_id', 'installation_pid', 'installation_creation_filetime'])
def test_role_capture_cannot_rebind_a_different_session(monkeypatch, key):
    capture = _role_capture('UTR', '010000e500525455')
    capture['identity'][key] = 'different' if key == 'installation_session_id' else 888
    monkeypatch.setattr(observer_context, 'capture_binding', lambda *_: capture)
    context = BattleObserverContextSource(_fake_session(), Path('installation.json'), 'UTR').context()
    assert context['status'] == 'unready'
    assert context['reasons'][-1]['code'] == 'BATTLE_OBSERVER_SESSION_CHANGED'


@pytest.mark.parametrize('missing', ['--operator-session', '--observer', '--battle-stream'])
def test_battle_only_requires_explicit_operator_inputs(missing):
    pairs = {'--operator-session': 'installation.json', '--observer': 'UTR', '--battle-stream': 'stream.json'}
    arguments = ['--battle-only']
    for flag, value in pairs.items():
        if flag != missing:
            arguments.extend([flag, value])
    with pytest.raises(ValueError, match='requires'):
        _build_runtime(build_parser().parse_args(arguments))


@pytest.mark.parametrize('extra', ['--static-game-data', '--mission-game-data', '--empire-game-data'])
def test_battle_only_rejects_other_source_modes_before_opening(extra):
    args = build_parser().parse_args(['--battle-only', '--operator-session', 'installation.json',
        '--observer', 'UTR', '--battle-stream', 'stream.json', extra])
    with pytest.raises(ValueError, match='another information source'):
        _build_runtime(args)


def test_normal_server_entry_exposes_only_verified_observer_battles(monkeypatch, tmp_path):
    import bridge.diplomacy as diplomacy
    fixture, _, _, decoded = fixture13()
    ref = decoded['context']['sides'][0]['participants']['full_refs'][0]
    tag = ref.to_bytes(8, 'little')[:3].decode('ascii')
    recorded, _, _, database, _ = make_source(tmp_path, fixture, observer=tag,
        observer_ref=f'{ref:016x}', message_ids=('281',))
    binding = dict(recorded.battles.binding, mode='live')
    config = tmp_path / 'battle.json'
    config.write_text(json.dumps({'schema': 'EU4-BATTLE-STREAM/1',
                                 'database': str(database), 'binding': binding}), encoding='utf-8')
    session = Session({'session_id': binding['session_id'], 'game_sha256': binding['game_sha256'],
                       'game_version': '1.37.4', 'pid': 777, 'creation_filetime': 42},
                      {'status': 'ready', 'complete': True, 'date_raw': fixture['context_date'],
                       'observer': 'FRA', 'reasons': []})
    monkeypatch.setattr(diplomacy, 'ObserverSession', lambda *_: session)
    def unexpected(*_args, **_kwargs):
        pytest.fail('battle-only mode must not construct DiplomacyTools or a journal')
    monkeypatch.setattr(diplomacy, 'DiplomacyTools', unexpected)
    monkeypatch.setattr(observer_context, 'capture_binding',
                        lambda *_: _role_capture(tag, f'{ref:016x}', binding['session_id']))
    args = build_parser().parse_args(['--battle-only', '--operator-session', 'installation.json',
        '--observer', tag, '--battle-stream', str(config), '--database', str(tmp_path/'information.sqlite3'),
        '--journal', str(tmp_path/'unused-journal.sqlite3')])
    service, journal = _build_runtime(args)
    assert journal is None and not (tmp_path/'unused-journal.sqlite3').exists()
    try:
        tools = InformationTools(service)
        assert set(row['topic_id'] for row in service.source.catalog()) == {'C01', 'B01', 'B02', 'B03', 'B04', 'H01', 'W03'}
        query = battle_topic_query('B04', ['details'], selected_event=event_id(fixture, '281'))
        result = tools.call('information_query', {"view": "full", 'request_id': 'scoped-battle-query', 'queries': [query]})
        assert result['context']['observer'] == tag and result['context']['status'] == 'ready'
        assert result['items'][0]['fields']['details']['status'] == 'known'
        original = binding['observer_ref']
        service.source.battles.binding['observer_ref'] = '010000e500525455'
        assert service.source.battles._bound(service.source.context()) is False
        service.source.battles.binding['observer_ref'] = original
    finally:
        service.close()
