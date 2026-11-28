import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import load_observer_save as subject


def test_verifies_observer_after_native_startup_pause(tmp_path, monkeypatch):
    installation = tmp_path / "installation.json"
    initial = {"pid": 123, "installation_returncode": 0, "preflight_player_tag": "---",
               "ready_reason": "verified_load_confirmation"}
    installation.write_text(json.dumps(initial), encoding="utf-8")
    (tmp_path / "control-probe.jsonl").write_text(
        '{"event":"popup_confirmation_callbacks_returned"}\n', encoding="utf-8")
    raw = 56456976
    health = {"status": "ready", "date_raw": raw}
    session = SimpleNamespace(record=dict(initial), physical_player_health=lambda: health)
    monkeypatch.setattr(subject, "game_exe", lambda: tmp_path / "eu4.exe")
    monkeypatch.setattr(subject, "ObserverSession", lambda *args: session)
    monkeypatch.setattr(subject, "wait_runtime_ready", lambda session: health)
    probes = iter((0, 1))
    monkeypatch.setattr(subject.time, "sleep", lambda seconds: None)

    def probe(pid, output, deadline):
        # Do not publish the expected player until an actual pause is observed.
        assert json.loads(installation.read_text(encoding="utf-8")) == initial
        return {"pid": pid, "read_only": True, "date_raw": raw, "paused_flag": next(probes)}

    monkeypatch.setattr(subject, "_probe_control_state", probe)
    result = subject._verify_loaded(installation, 123, {"player": "O00", "date": "1444.11.11"},
                                    (1444, 11, 11))

    assert result == {"player": "O00", "date": "1444.11.11", "paused": True,
                      "load_warning": "confirmed"}
    verified = json.loads(installation.read_text(encoding="utf-8"))
    assert verified["verified_loaded_player_tag"] == "O00"
    assert verified["verified_loaded_date_raw"] == raw


def test_stages_unicode_save_without_changing_original(tmp_path):
    saves = tmp_path / "save games"
    saves.mkdir()
    source = saves / "观察者开局.eu4"
    source.write_bytes(b"save contents")

    launch_save = subject._stage_save(source, saves)

    assert launch_save != source
    assert subject.load_warning_save_name(launch_save.name) == launch_save.name
    assert launch_save.read_bytes() == source.read_bytes() == b"save contents"


@pytest.mark.parametrize(("player", "date"), [("O00", "1444.11.11"), ("POR", "1445.2.5")])
def test_read_save_preserves_the_physical_player(tmp_path, player, date):
    path = tmp_path / "campaign.eu4"
    path.write_bytes(f'EU4txt\nplayer="{player}"\ndate={date}\n'.encode() + b" " * 100_001)

    metadata, numeric_date = subject._read_save(path)

    assert metadata["player"] == player
    assert numeric_date == tuple(map(int, date.split(".")))


def test_save_loader_gives_slow_startup_time_and_binds_the_confirmation_shortcut(tmp_path, monkeypatch):
    saves = tmp_path / "save games"
    saves.mkdir()
    save = saves / "观察者测试.eu4"
    save.write_bytes(b"save contents")
    manifest = tmp_path / "candidate" / "build-manifest.json"
    manifest.parent.mkdir()
    manifest.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(subject, "_read_save", lambda _: ({"player": "POR"}, (1445, 2, 5)))
    monkeypatch.setattr(subject, "user_data", lambda: tmp_path)
    monkeypatch.setattr(subject.shutil, "which", lambda _: "pwsh")
    monkeypatch.setattr(subject, "_verify_loaded", lambda *args: {"paused": True})
    staged_names = []

    def run(command, **kwargs):
        if "-SaveName" in command:
            staged_names.append(command[command.index("-SaveName") + 1])
            assert (saves / staged_names[-1]).read_bytes() == save.read_bytes()
            return SimpleNamespace(stdout=b"Game restarted; new PID: 123")
        if any(Path(arg).name == "start_diplomacy_observer.py" for arg in command):
            assert command[command.index("--wait-ready") + 1] == "300"
            assert command[command.index("--load-warning-save-name") + 1] == staged_names[-1]
            assert "--confirm-load-warning" in command

    monkeypatch.setattr(subject.subprocess, "run", run)
    assert subject.load_save(save, manifest)["pid"] == 123
    assert len(staged_names) == 1 and not (saves / staged_names[0]).exists()
