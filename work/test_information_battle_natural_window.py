"""Synthetic, no-game tests for the TEST_ONLY natural-window runner."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys

import pytest

from work import run_information_battle_natural_window as runner


ORIGINAL_PUBLISH_REQUEST = runner.publish_request


def _installation(tmp_path: Path) -> tuple[Path, Path, dict]:
    fake_root = tmp_path / "workspace"
    runtime = fake_root / "work" / "runtime"
    runtime.mkdir(parents=True)
    directory = fake_root / "installation"
    directory.mkdir()
    identity = {
        "pid": 1234,
        "creation_filetime": 999,
        "session_id": "synthetic-session",
    }
    installation = directory / "installation.json"
    installation.write_text(json.dumps(identity), encoding="utf-8")
    (directory / "control-probe.jsonl").write_text("", encoding="utf-8")
    return fake_root, installation, identity


def _snapshot(date: int) -> dict:
    def one() -> dict:
        return {
            "game_date": {"raw": date},
            "control": {"paused": {"value": True}, "speed": {"value": 0}},
        }

    return {"before": one(), "after": one()}


def _status() -> dict:
    return {
        "native": {
            "state": "enabled",
            "code_patch_installed": True,
            "captured": "0",
            "last_sequence": "0",
        }
    }


def _configure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, target: int = 56553384):
    fake_root, installation, identity = _installation(tmp_path)
    monkeypatch.setattr(runner, "ROOT", fake_root)
    monkeypatch.setattr(runner, "game_exe", lambda: fake_root / "eu4.exe")
    monkeypatch.setattr(
        runner,
        "probe_identity",
        lambda pid, exe: {
            "pid": identity["pid"],
            "creation_filetime": identity["creation_filetime"],
            "session_id": identity["session_id"],
        },
    )
    calls = {"probe": 0, "status": 0, "publish": 0}

    def fake_probe(_installation: Path, output: Path) -> dict:
        calls["probe"] += 1
        date = target + 24 if calls["probe"] == 2 else target
        document = _snapshot(date)
        output.write_text(json.dumps(document), encoding="utf-8")
        return document

    def fake_control(_installation: Path, command: str) -> dict:
        assert command == "status"
        calls["status"] += 1
        return _status()

    def fake_publish(directory: Path, text: str, output: Path, name: str) -> None:
        calls["publish"] += 1
        assert text == "TEST_ONLY advance_1_days\n"
        target_date = target + 24
        events = [
            {"event": "control_console_result", "command": "0", "success": True},
            {
                "event": "control_advance_complete",
                "date_raw": target_date,
                "target_raw": target_date,
                "reached": True,
                "paused_command_success": True,
            },
            {
                "event": "diplomacy_observer_health",
                "date_raw": target_date,
                "thread_changed": False,
                "state_readable": True,
                "player": "POR",
            },
        ]
        with (directory / "control-probe.jsonl").open("a", encoding="utf-8") as stream:
            for event in events:
                stream.write(json.dumps(event) + "\n")

    monkeypatch.setattr(runner, "probe", fake_probe)
    monkeypatch.setattr(runner, "run_control", fake_control)
    monkeypatch.setattr(runner, "publish_request", fake_publish)
    return fake_root, installation, calls


def test_check_completion_requires_target_pause_console_and_following_health() -> None:
    target = 56553408
    complete = {
        "event": "control_advance_complete",
        "date_raw": target,
        "target_raw": target,
        "reached": True,
        "paused_command_success": True,
    }
    console = {"event": "control_console_result", "command": "0", "success": True}
    health = {
        "event": "diplomacy_observer_health",
        "date_raw": target,
        "thread_changed": False,
        "state_readable": True,
        "player": "POR",
    }
    assert runner.check_completion([console, complete, health], target) is True
    assert runner.check_completion([console, health, complete], target) is False
    assert runner.check_completion([console, {**complete, "date_raw": target - 24}, health], target) is False
    assert runner.check_completion([console, {**complete, "reached": False}, health], target) is False
    assert runner.check_completion([console, {**complete, "paused_command_success": False}, health], target) is False
    assert runner.check_completion([complete, health], target) is False
    assert runner.check_completion([console, complete, {**health, "thread_changed": True}], target) is False
    assert runner.check_completion([console, complete, {**health, "player": "FRA"}], target) is False


def test_execute_success_is_single_test_only_observation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake_root, installation, calls = _configure(monkeypatch, tmp_path)
    output = fake_root / "work" / "runtime" / "success"
    result = runner.execute(installation, days=1, expected_date=56553384, output=output, test_only=True)
    assert result["status"] == "observed_target_and_paused"
    assert result["request_published"] is True
    assert calls == {"probe": 2, "status": 2, "publish": 1}
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert report["business_dispatch"] is False
    assert report["business_battle_complete"] is False
    assert json.loads((output / "control-events.json").read_text(encoding="utf-8"))["events"]


@pytest.mark.parametrize("failure", ["probe", "status", "identity"])
def test_preflight_status_or_identity_failure_never_publishes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    fake_root, installation, calls = _configure(monkeypatch, tmp_path)
    if failure == "probe":
        monkeypatch.setattr(runner, "probe", lambda *_args: (_ for _ in ()).throw(RuntimeError("probe-failed")))
    elif failure == "status":
        monkeypatch.setattr(runner, "run_control", lambda *_args: (_ for _ in ()).throw(RuntimeError("status-failed")))
    else:
        monkeypatch.setattr(
            runner,
            "probe_identity",
            lambda *_args: {"pid": 1234, "creation_filetime": 998, "session_id": "wrong"},
        )
    output = fake_root / "work" / "runtime" / ("failure-" + failure)
    result = runner.execute(installation, days=1, expected_date=56553384, output=output, test_only=True)
    assert result["request_published"] is False
    assert calls["publish"] == 0
    assert result["status"] == "not_dispatched_or_publication_unknown"


def test_published_timeout_is_unknown_no_retry(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake_root, installation, calls = _configure(monkeypatch, tmp_path)
    monkeypatch.setattr(runner, "publish_request", lambda *_args: calls.__setitem__("publish", calls["publish"] + 1))
    ticks = iter((0.0, 200.0))
    monkeypatch.setattr(runner.time, "monotonic", lambda: next(ticks))
    output = fake_root / "work" / "runtime" / "timeout"
    result = runner.execute(installation, days=1, expected_date=56553384, output=output, test_only=True)
    assert result["status"] == "unknown_no_retry"
    assert result["request_published"] is True
    assert result["automatic_retry"] is False
    assert calls["publish"] == 1


def test_output_directory_and_request_publication_are_exclusive(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake_root, installation, calls = _configure(monkeypatch, tmp_path)
    output = fake_root / "work" / "runtime" / "existing"
    output.mkdir()
    with pytest.raises(FileExistsError):
        runner.execute(installation, days=1, expected_date=56553384, output=output)
    assert calls["publish"] == 0

    directory = tmp_path / "control"
    directory.mkdir()
    target = directory / "game-control.request"
    target.write_text("old", encoding="ascii")
    receipt_dir = tmp_path / "receipts"
    receipt_dir.mkdir()
    with pytest.raises(RuntimeError, match="CONTROL_REQUEST_ALREADY_PRESENT_NO_DISPATCH"):
        ORIGINAL_PUBLISH_REQUEST(directory, "TEST_ONLY advance_1_days\n", receipt_dir, "advance")
    assert target.read_text(encoding="ascii") == "old"
    assert not (receipt_dir / "advance-started.json").exists()


def test_direct_api_without_test_only_does_not_publish(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake_root, installation, calls = _configure(monkeypatch, tmp_path)
    output = fake_root / "work" / "runtime" / "direct-without-flag"
    result = runner.execute(installation, days=1, expected_date=56553384, output=output)
    assert result["status"] == "not_dispatched_or_publication_unknown"
    assert result["request_published"] is False
    assert "EXPLICIT_TEST_ONLY_SUPPORTED_WINDOW_REQUIRED" in result["error"]
    assert calls["publish"] == 0


@pytest.mark.parametrize("bad_kind", ["missing", "invalid-json"])
def test_missing_or_bad_installation_is_audited_without_publish(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, bad_kind: str
) -> None:
    fake_root, valid_installation, calls = _configure(monkeypatch, tmp_path)
    if bad_kind == "missing":
        installation = valid_installation.parent / "missing-installation.json"
    else:
        installation = valid_installation.parent / "bad-installation.json"
        installation.write_text("{bad", encoding="utf-8")
    output = fake_root / "work" / "runtime" / ("bad-installation-" + bad_kind)
    result = runner.execute(installation, days=1, expected_date=56553384, output=output, test_only=True)
    assert result["status"] == "not_dispatched_or_publication_unknown"
    assert result["request_published"] is False
    assert calls["publish"] == 0
    assert (output / "report.json").is_file()


def test_same_path_longer_control_log_replacement_is_rejected(tmp_path: Path) -> None:
    log = tmp_path / "control-probe.jsonl"
    log.write_bytes(b"old\n")
    expected = runner.log_identity(log.stat())
    replacement = tmp_path / "replacement.jsonl"
    replacement.write_bytes(b"new-longer-event\n")
    os.replace(replacement, log)
    with pytest.raises(RuntimeError, match="CONTROL_LOG_REPLACED_UNKNOWN"):
        runner.read_control_chunk(log, expected, 0)


def test_initial_partial_control_log_rejects_before_publish(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake_root, installation, calls = _configure(monkeypatch, tmp_path)
    (installation.parent / "control-probe.jsonl").write_bytes(b'{"event":"partial"}')
    output = fake_root / "work" / "runtime" / "partial-baseline"
    result = runner.execute(installation, days=1, expected_date=56553384, output=output, test_only=True)
    assert result["status"] == "not_dispatched_or_publication_unknown"
    assert result["request_published"] is False
    assert "CONTROL_LOG_INCOMPLETE_BASELINE_NO_DISPATCH" in result["error"]
    assert calls["publish"] == 0


def test_publish_exception_is_unknown_and_never_retried(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake_root, installation, calls = _configure(monkeypatch, tmp_path)

    def fail_publish(*_args: object) -> None:
        calls["publish"] += 1
        raise OSError("synthetic-publish-failure")

    monkeypatch.setattr(runner, "publish_request", fail_publish)
    output = fake_root / "work" / "runtime" / "publish-error"
    result = runner.execute(installation, days=1, expected_date=56553384, output=output, test_only=True)
    assert result["status"] == "unknown_no_retry"
    assert result["request_published"] is None
    assert result["automatic_retry"] is False
    assert calls["publish"] == 1


def test_cli_requires_test_only_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_information_battle_natural_window.py",
            "--installation",
            "dummy",
            "--days",
            "1",
            "--expected-date",
            "56553384",
            "--output-dir",
            "dummy-output",
        ],
    )
    with pytest.raises(SystemExit) as error:
        runner.main()
    assert error.value.code == 2

