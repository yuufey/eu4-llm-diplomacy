from copy import deepcopy
import json
from types import SimpleNamespace
import pytest
from work.observer_runtime_ready import _stable_matching_heartbeat
from bridge.diplomacy import ObserverSession
from bridge.information.sources import DiplomacySource


def heartbeat(date, frames):
    return {'event': 'diplomacy_observer_health', 'session_id': 'running-test',
            'frames': frames, 'date_raw': date, 'thread': 12, 'player': 'POR',
            'state_readable': True, 'thread_changed': False}


def test_running_dates_are_available_only_for_the_read_only_mode():
    events = [heartbeat(100, 1), heartbeat(124, 2)]
    assert _stable_matching_heartbeat(events, 'running-test') is None
    assert _stable_matching_heartbeat(events, 'running-test', allow_date_progress=True) == events[-1]


@pytest.mark.parametrize('damage', ['date_backwards', 'thread', 'player', 'frame_backwards', 'unreadable'])
def test_running_mode_preserves_identity_and_monotonic_guards(damage):
    events = [heartbeat(100, 1), heartbeat(124, 2)]
    last = deepcopy(events[-1])
    if damage == 'date_backwards':
        last['date_raw'] = 99
    elif damage == 'thread':
        last['thread'] = 13
    elif damage == 'player':
        last['player'] = 'FRA'
    elif damage == 'frame_backwards':
        last['frames'] = 1
    else:
        last['state_readable'] = False
    events[-1] = last
    assert _stable_matching_heartbeat(events, 'running-test', allow_date_progress=True) is None


def test_information_source_uses_the_read_only_health_entry_point():
    session = SimpleNamespace(record={'game_version': '1.37.4', 'game_sha256': 'a' * 64},
                              session_id='running-test')
    session.health = lambda: {'status': 'unready'}
    session.information_health = lambda: {'status': 'ready', 'date_raw': 124, 'complete': True}
    source = DiplomacySource(SimpleNamespace(session=session), observer='FRA')
    assert source.context()['status'] == 'ready'
    assert source.context()['game_date'] == 124


@pytest.mark.parametrize('second_date', [100, 124])
@pytest.mark.parametrize('installed_player', [None, 'O00'])
def test_running_health_finds_the_pair_behind_a_busy_log_tail(tmp_path, monkeypatch, second_date, installed_player):
    import bridge.diplomacy as diplomacy
    session = object.__new__(ObserverSession)
    session.session_id = 'running-test'
    session.record = {'session_id': 'running-test', 'pid': 1, 'installation_returncode': 0, 'dll_sha256': 'test-dll'}
    if installed_player is not None:
        session.record['preflight_player_tag'] = installed_player
    session.directory = tmp_path
    session.game_exe = tmp_path / 'eu4.exe'
    monkeypatch.setattr(diplomacy, 'probe_identity', lambda *_: {
        'session_id': 'running-test', 'modules': [{'sha256': 'test-dll'}]})
    monkeypatch.setattr(diplomacy, '_RESPONSE_LOG_CHUNK_BYTES', 256)
    monkeypatch.setattr(diplomacy, '_HEALTH_LOG_MAX_TAIL_BYTES', 512)
    player = installed_player or 'POR'
    first = {**heartbeat(100, 1), 'player': player}
    second = {**heartbeat(second_date, 2), 'player': player}
    lines = [json.dumps(first), 'x' * 700, json.dumps(second), 'x' * 700]
    (tmp_path / 'control-probe.jsonl').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    assert session.health()['status'] == ('ready' if second_date == 100 else 'unready')
    assert session.information_health()['status'] == 'ready'
    if installed_player is not None:
        lines[2] = json.dumps({**second, 'player': 'POR'})
        (tmp_path / 'control-probe.jsonl').write_text('\n'.join(lines) + '\n', encoding='utf-8')
        assert session.information_health()['status'] == 'unready'
