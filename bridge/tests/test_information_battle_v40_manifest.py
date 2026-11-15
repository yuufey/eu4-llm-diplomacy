"""Strict synthetic v40 admission and read-only controller checks."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from bridge.tests import test_information_battle_v39_manifest as v39
from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start


TAIL_KEYS = (
    "information_battle_outcome_tail",
    "information_battle_outcome_tail_wire",
    "information_battle_outcome_tail_stage",
    "information_battle_outcome_tail_read_only",
    "information_battle_outcome_tail_complete",
)


def _make_v40_manifest_fixture(directory: Path, *, name_handoff: bool = False):
    manifest, old_dll = v39._make_manifest_fixture(directory, 39, name_handoff=name_handoff)
    old_dll.unlink()
    dll = directory / "eu4_bridge_diplomacy_observer_v40.dll"
    dll.write_bytes(b"synthetic-v40-outcome-tail-dll")
    manifest.update(version=40, dll=str(dll.resolve()),
                    dll_sha256=hashlib.sha256(dll.read_bytes()).hexdigest(),
                    information_battle_outcome_tail=True,
                    information_battle_outcome_tail_wire=13,
                    information_battle_outcome_tail_stage="entry_before_client_gate",
                    information_battle_outcome_tail_read_only=True,
                    information_battle_outcome_tail_complete=False)
    manifest["compiler_arguments"].append("-DINFORMATION_BATTLE_OUTCOME_TAIL=1")
    v39._add_sources(directory, manifest, start.INFORMATION_BATTLE_OUTCOME_TAIL_SOURCES,
                     "synthetic-v40:")
    (directory / "build-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return manifest, dll


def _make_control_fixture(directory: Path):
    manifest, dll = _make_v40_manifest_fixture(directory)
    module = {"name": dll.name, "path": str(dll.resolve()), "sha256": manifest["dll_sha256"]}
    identity = {
        "pid": 123,
        "creation_filetime": 456,
        "session_id": "synthetic-123-456",
        "game_sha256": manifest["game_sha256"],
        "modules": [module],
    }
    installation = {key: value for key, value in identity.items() if key != "modules"}
    installation.update(dll_sha256=manifest["dll_sha256"], modules_after_install=[module])
    installation_path = directory / "installation.json"
    installation_path.write_text(json.dumps(installation), encoding="utf-8")
    status = {
        "pid": 123,
        "creation_filetime": "456",
        "exe_sha256": manifest["game_sha256"],
        "dll_sha256": manifest["dll_sha256"],
        "state": "ready",
        "installation": "0",
        "generation": "0",
        "wire_version": 13,
        "native_title_query_enabled": False,
        "name_sources_enabled": True,
        "outcome_text_enabled": True,
        "outcome_tail_enabled": True,
    }
    (directory / control.STATUS_NAME).write_text(json.dumps(status), encoding="utf-8")
    return manifest, installation_path, identity


def _pins(directory: Path) -> dict[str, tuple[bytes, int]]:
    return {path.name: (path.read_bytes(), path.stat().st_mtime_ns)
            for path in directory.iterdir() if path.is_file()}


def test_v40_manifest_accepts_outcome_tail_on_complete_v39_source_set(tmp_path: Path):
    directory = tmp_path / "v40"
    manifest, _dll = _make_v40_manifest_fixture(directory)
    assert len(manifest["sources"]) == 144
    assert set(start.INFORMATION_BATTLE_OUTCOME_TAIL_SOURCES) <= {
        row["name"] for row in manifest["sources"]
    }
    assert "-DINFORMATION_BATTLE_OUTCOME_TEXT=1" in manifest["compiler_arguments"]
    assert "-DINFORMATION_BATTLE_NAME_SOURCES=1" in manifest["compiler_arguments"]
    assert "-DINFORMATION_BATTLE_NO_TITLE_QUERY_INVOKE=1" in manifest["compiler_arguments"]
    start._validate_information_battle_manifest(manifest, directory)
    control._validate_manifest(manifest, directory)


def test_v40_manifest_preserves_optional_name_handoff_source_set(tmp_path: Path):
    directory = tmp_path / "v40-name-handoff"
    manifest, _dll = _make_v40_manifest_fixture(directory, name_handoff=True)
    assert len(manifest["sources"]) == 147
    start._validate_information_battle_manifest(manifest, directory)
    control._validate_manifest(manifest, directory)


@pytest.mark.parametrize("mutation", [
    "missing_define", "wrong_define", "duplicate_define", "wrong_wire", "boolean_wire",
    "wrong_stage", "not_read_only", "complete", "missing_source", "extra_source",
    "duplicate_source", "wrong_source_pin",
])
def test_v40_rejects_incomplete_or_unpinned_outcome_tail(tmp_path: Path, mutation: str):
    directory = tmp_path / mutation
    manifest, _dll = _make_v40_manifest_fixture(directory)
    arguments = manifest["compiler_arguments"]
    source_name = start.INFORMATION_BATTLE_OUTCOME_TAIL_SOURCES[0]
    if mutation == "missing_define":
        arguments.remove("-DINFORMATION_BATTLE_OUTCOME_TAIL=1")
    elif mutation == "wrong_define":
        arguments[-1] = "-DINFORMATION_BATTLE_OUTCOME_TAIL=0"
    elif mutation == "duplicate_define":
        arguments.append("-DINFORMATION_BATTLE_OUTCOME_TAIL=1")
    elif mutation == "wrong_wire":
        manifest[TAIL_KEYS[1]] = 12
    elif mutation == "boolean_wire":
        manifest[TAIL_KEYS[1]] = True
    elif mutation == "wrong_stage":
        manifest[TAIL_KEYS[2]] = "after_client_gate"
    elif mutation == "not_read_only":
        manifest[TAIL_KEYS[3]] = False
    elif mutation == "complete":
        manifest[TAIL_KEYS[4]] = True
    elif mutation == "missing_source":
        manifest["sources"] = [row for row in manifest["sources"] if row["name"] != source_name]
    elif mutation == "extra_source":
        name, data = "unowned-outcome-tail-fixture.h", b"unowned source"
        (directory / name).write_bytes(data)
        manifest["sources"].append({"name": name, "sha256": hashlib.sha256(data).hexdigest()})
    elif mutation == "duplicate_source":
        manifest["sources"].append(copy.deepcopy(next(
            row for row in manifest["sources"] if row["name"] == source_name
        )))
    else:
        next(row for row in manifest["sources"] if row["name"] == source_name)["sha256"] = "f" * 64
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)


@pytest.mark.parametrize("edit", ["key", "define"])
def test_v39_remains_accepted_and_rejects_v40_outcome_tail(tmp_path: Path, edit: str):
    directory = tmp_path / f"v39-{edit}"
    manifest, _dll = v39._make_manifest_fixture(directory, 39)
    start._validate_information_battle_manifest(manifest, directory)
    control._validate_manifest(manifest, directory)
    if edit == "key":
        manifest[TAIL_KEYS[0]] = False
    else:
        manifest["compiler_arguments"].append("-DINFORMATION_BATTLE_OUTCOME_TAIL=0")
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)


def test_v40_cli_status_is_read_only_after_full_manifest_admission(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    directory = tmp_path / "v40-control"
    _manifest, installation, identity = _make_control_fixture(directory)
    monkeypatch.setattr(control, "probe_identity", lambda *_: identity)

    def no_write(*_args, **_kwargs):
        pytest.fail("status must not bind the process or publish a control request")

    monkeypatch.setattr(control, "_ensure_binding", no_write)
    monkeypatch.setattr(control, "_publish_request", no_write)
    before = _pins(directory)
    exit_code = control.main(["--installation", str(installation), "--command", "status"])
    captured = capsys.readouterr()
    after = _pins(directory)
    assert exit_code == 0
    result = json.loads(captured.out)
    assert captured.err == ""
    assert result["status"] == "observed" and result["fresh"] is True
    assert result["native"]["wire_version"] == 13
    assert result["native"]["native_title_query_enabled"] is False
    assert before == after
