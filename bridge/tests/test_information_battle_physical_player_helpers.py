"""Offline checks for the explicit physical-player tag route."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

import pytest

from work import bootstrap_information_battle_subscription as bootstrap
from work import run_information_battle_natural_window as window
from work import run_information_battle_natural_window_installed as installed_window
from work import validate_information_battle_capture_management_live as management
from work import validate_information_battle_capture_autonomous_live as autonomous


PLAYER_REFS = {
    "POR": "0x0001000000524f50",
    "FRA": "0x0002000000415246",
}


def _preflight(tag: str) -> dict:
    def snapshot() -> dict:
        return {
            "game_date": {"raw": 56561088},
            "physical_player": {
                "tag": tag,
                "value": PLAYER_REFS[tag],
                "complete": True,
            },
            "control": {"speed": {"value": 0}, "paused": {"value": True}},
        }

    return {
        "status": "passed_read_only_installed_preflight",
        "logical_observer": "FRA",
        "before": snapshot(),
        "after": snapshot(),
    }


def _run_bootstrap(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, tag: str | None) -> tuple[list, Path, dict]:
    install_dir = tmp_path / "installation"
    install_dir.mkdir()
    installation = install_dir / "installation.json"
    installation.write_text("{}", encoding="utf-8")
    preflight = tmp_path / "preflight.json"
    preflight.write_text(json.dumps(_preflight(tag or "POR")), encoding="utf-8")
    output = tmp_path / "bootstrap"
    calls: list[tuple[str, str | None]] = []
    final_player_ref = f"{int(PLAYER_REFS[tag or 'POR'], 16):016x}"

    def fake_control(_installation: Path, command: str, player_ref: str | None = None) -> dict:
        calls.append((command, player_ref))
        if command == "status" and len(calls) == 1:
            return {"native": {"state": "ready", "captured": "0"}}
        if command == "enable":
            return {"status": "accepted", "response": {"state": "enabled"}}
        if command == "disable":
            return {"status": "accepted", "response": {"state": "disabled"}}
        if command == "status":
            return {
                "native": {"state": "disabled", "code_patch_installed": True},
                "binding": {"player_ref": final_player_ref},
            }
        raise AssertionError(command)

    monkeypatch.setattr(bootstrap, "run_control", fake_control)
    argv = [
        "bootstrap_information_battle_subscription.py",
        "--installation", str(installation), "--preflight", str(preflight),
        "--output", str(output), "--expected-date", "56561088", "--test-only",
    ]
    if tag is not None:
        argv.extend(("--expected-player-tag", tag))
    monkeypatch.setattr(sys, "argv", argv)
    assert bootstrap.main() is None
    return calls, output, json.loads(preflight.read_text(encoding="utf-8"))


@pytest.mark.parametrize(("tag", "explicit"), [("POR", None), ("FRA", "FRA")])
def test_bootstrap_binds_the_confirmed_fullref_with_default_or_explicit_tag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
    tag: str, explicit: str | None,
) -> None:
    calls, output, audit = _run_bootstrap(monkeypatch, tmp_path, explicit)
    expected_ref = f"{int(PLAYER_REFS[tag], 16):016x}"
    assert calls == [("status", None), ("enable", expected_ref), ("disable", None), ("status", None)]
    intent = json.loads((output / "intent.json").read_text(encoding="utf-8"))
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert intent["player_ref"] == expected_ref
    assert intent["physical_player_tag"] == tag
    assert report["player_ref"] == expected_ref
    assert audit["logical_observer"] == "FRA"
    assert json.loads(capsys.readouterr().out)["binding"]["player_ref"] == expected_ref


def test_bootstrap_rejects_wrong_physical_player_before_native_control(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    install_dir = tmp_path / "installation"
    install_dir.mkdir()
    installation = install_dir / "installation.json"
    installation.write_text("{}", encoding="utf-8")
    preflight = tmp_path / "preflight.json"
    preflight.write_text(json.dumps(_preflight("POR")), encoding="utf-8")
    calls: list[str] = []
    monkeypatch.setattr(bootstrap, "run_control", lambda *_args: calls.append("control"))
    monkeypatch.setattr(sys, "argv", [
        "bootstrap_information_battle_subscription.py", "--installation", str(installation),
        "--preflight", str(preflight), "--output", str(tmp_path / "out"),
        "--expected-date", "56561088", "--expected-player-tag", "FRA", "--test-only",
    ])
    with pytest.raises(ValueError, match="world_differs"):
        bootstrap.main()
    assert calls == []


def _completion_events(player: str) -> list[dict]:
    target = 56561112
    return [
        {"event": "control_console_result", "command": "0", "success": True},
        {"event": "control_advance_complete", "date_raw": target, "target_raw": target,
         "reached": True, "paused_command_success": True},
        {"event": "diplomacy_observer_health", "date_raw": target,
         "thread_changed": False, "state_readable": True, "player": player},
    ]


def test_natural_window_completion_uses_explicit_physical_tag_and_defaults_to_por() -> None:
    target = 56561112
    assert window.check_completion(_completion_events("POR"), target) is True
    assert window.check_completion(_completion_events("FRA"), target) is False
    assert window.check_completion(_completion_events("FRA"), target, "FRA") is True
    assert window.check_completion(_completion_events("POR"), target, "FRA") is False
    with pytest.raises(ValueError, match="expected_player_tag_must_be_POR_or_FRA"):
        window.check_completion(_completion_events("FRA"), target, "ENG")


def test_natural_window_execute_passes_expected_tag_to_completion(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    root = tmp_path / "workspace"
    runtime = root / "work" / "runtime"
    runtime.mkdir(parents=True)
    install_dir = root / "installation"
    install_dir.mkdir()
    installation = install_dir / "installation.json"
    installation.write_text(json.dumps({"pid": 41, "creation_filetime": 99,
                                        "session_id": "synthetic-session"}), encoding="utf-8")
    (install_dir / "control-probe.jsonl").write_text("", encoding="utf-8")
    monkeypatch.setattr(window, "ROOT", root)
    monkeypatch.setattr(window, "game_exe", lambda: root / "eu4.exe")
    monkeypatch.setattr(window, "probe_identity", lambda *_args: {
        "pid": 41, "creation_filetime": 99, "session_id": "synthetic-session"})
    dates = iter((56561088, 56561112))

    def fake_probe(_installation: Path, _output: Path) -> dict:
        date = next(dates)
        return {
            phase: {"game_date": {"raw": date},
                    "control": {"paused": {"value": True}, "speed": {"value": 0}}}
            for phase in ("before", "after")
        }

    monkeypatch.setattr(window, "probe", fake_probe)
    monkeypatch.setattr(window, "run_control", lambda *_args: {
        "native": {"state": "enabled", "code_patch_installed": True,
                   "captured": "1", "last_sequence": "1"}})

    def fake_publish(directory: Path, _text: str, _output: Path, _name: str) -> None:
        with (directory / "control-probe.jsonl").open("a", encoding="utf-8") as stream:
            for event in _completion_events("FRA"):
                stream.write(json.dumps(event) + "\n")

    monkeypatch.setattr(window, "publish_request", fake_publish)
    result = window.execute(installation, 1, 56561088, runtime / "window",
                           test_only=True, expected_player_tag="FRA")
    assert result["status"] == "observed_target_and_paused"
    assert result["expected_physical_player_tag"] == "FRA"
    intent = json.loads((runtime / "window" / "window-intent.json").read_text(encoding="utf-8"))
    assert intent["expected_physical_player_tag"] == "FRA"
    assert "observer" not in intent


@pytest.mark.parametrize(("tag", "include_flag"), [("POR", False), ("FRA", True)])
def test_installed_wrapper_passes_expected_player_tag_to_window(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, tag: str, include_flag: bool,
) -> None:
    output = tmp_path / "installed-window"
    captured: dict = {}

    def fake_probe(*_args, **_kwargs) -> dict:
        return {"status": "passed_read_only_installed_preflight"}

    def fake_execute(installation, days, expected_date, output_dir, *, test_only, expected_player_tag):
        captured.update(installation=installation, days=days, expected_date=expected_date,
                        test_only=test_only, expected_player_tag=expected_player_tag)
        output_dir.mkdir(parents=True)
        return {"status": "observed_target_and_paused"}

    monkeypatch.setattr(installed_window, "installed_probe", fake_probe)
    monkeypatch.setattr(installed_window.window, "execute", fake_execute)
    argv = [
        "run_information_battle_natural_window_installed.py", "--installation", str(tmp_path / "i.json"),
        "--expected-manifest-sha256", "a" * 64, "--expected-dll-sha256", "b" * 64,
        "--days", "1", "--expected-date", "56561088", "--output-dir", str(output), "--test-only",
    ]
    if include_flag:
        argv.extend(("--expected-player-tag", tag))
    monkeypatch.setattr(sys, "argv", argv)
    assert installed_window.main() == 0
    assert captured["expected_player_tag"] == tag


@pytest.mark.parametrize(("tag", "include_tag"), [("POR", False), ("FRA", True)])
def test_management_acceptor_forwards_tag_to_installed_wrapper(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, tag: str, include_tag: bool,
) -> None:
    root = tmp_path / "workspace"
    runtime = root / "work" / "runtime"
    runtime.mkdir(parents=True)
    monkeypatch.setattr(management, "ROOT", root)
    output = runtime / "acceptance"
    output.mkdir()
    natural_output = runtime / "natural-window"
    captured: dict = {}

    def fake_subprocess(command, **_kwargs):
        captured["command"] = command
        return subprocess.CompletedProcess(command, 0, "{}", "")

    monkeypatch.setattr(management.subprocess, "run", fake_subprocess)
    args = argparse.Namespace(
        test_only=True, expected_manifest_sha256="a" * 64, expected_dll_sha256="b" * 64,
        natural_window_output=natural_output, days=1, expected_date=56561088,
        observer="FRA",
    )
    if include_tag:
        args.expected_player_tag = tag
    management._run_natural_window(args, tmp_path / "installation.json", output, {})
    command = captured["command"]
    index = command.index("--expected-player-tag")
    assert command[index + 1] == tag
    assert "--observer" not in command


@pytest.mark.parametrize(("tag", "include_tag"), [("POR", False), ("FRA", True)])
def test_autonomous_acceptor_passes_physical_tag_through_natural_window(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, tag: str, include_tag: bool,
) -> None:
    root = tmp_path / "workspace"
    runtime = root / "work" / "runtime"
    runtime.mkdir(parents=True)
    monkeypatch.setattr(management, "ROOT", root)
    output = runtime / "autonomous-acceptance"
    output.mkdir()
    natural_output = runtime / "natural-window"
    captured: dict[str, object] = {}

    def fake_subprocess(command, **_kwargs):
        captured["command"] = command
        return subprocess.CompletedProcess(command, 0, "{}", "")

    monkeypatch.setattr(management.subprocess, "run", fake_subprocess)

    def fake_run(args: argparse.Namespace) -> int:
        captured["physical_tag"] = args.expected_player_tag
        report: dict = {}
        management._run_natural_window(
            args, tmp_path / "installation.json", output, report)
        captured["natural_report"] = report["natural_window"]
        return 0

    monkeypatch.setattr(autonomous, "run", fake_run)
    argv = [
        "--installation", str(tmp_path / "installation.json"),
        "--battle-stream", str(tmp_path / "battle-stream.json"),
        "--database", str(tmp_path / "service.sqlite3"),
        "--output", str(output), "--natural-window-output", str(natural_output),
        "--expected-manifest-sha256", "a" * 64,
        "--expected-dll-sha256", "b" * 64,
        "--expected-date", "56562768", "--days", "1", "--baseline-raw-count", "0",
        "--test-only",
    ]
    if include_tag:
        argv.extend(("--expected-player-tag", tag))

    assert autonomous.main(argv) == 0
    assert captured["physical_tag"] == tag
    assert captured["natural_report"]["expected_physical_player_tag"] == tag
    command = captured["command"]
    index = command.index("--expected-player-tag")
    assert command[index + 1] == tag
    assert "--observer" not in command

