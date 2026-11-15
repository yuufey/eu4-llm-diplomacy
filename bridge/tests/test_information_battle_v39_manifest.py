"""Strict synthetic v39 manifest and read-only controller admission checks."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from bridge.tests.test_information_battle_v37_manifest import make_v37_manifest_fixture
from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start


OUTCOME_TEXT_KEYS = (
    "information_battle_outcome_text",
    "information_battle_outcome_text_wire",
    "information_battle_outcome_text_stage",
    "information_battle_outcome_text_read_only",
    "information_battle_outcome_text_complete",
)


def _add_sources(directory: Path, manifest: dict, names: tuple[str, ...], prefix: str) -> None:
    for name in names:
        data = (prefix + name).encode("ascii")
        (directory / name).write_bytes(data)
        manifest["sources"].append({"name": name, "sha256": hashlib.sha256(data).hexdigest()})


def _make_manifest_fixture(directory: Path, version: int, *, name_handoff: bool = False):
    assert version in (38, 39)
    manifest, old_dll = make_v37_manifest_fixture(directory, name_handoff=name_handoff)
    old_dll.unlink()
    dll = directory / f"eu4_bridge_diplomacy_observer_v{version}.dll"
    dll.write_bytes(f"synthetic-v{version}-manifest-dll".encode("ascii"))
    manifest.update(
        version=version,
        dll=str(dll.resolve()),
        dll_sha256=hashlib.sha256(dll.read_bytes()).hexdigest(),
        information_battle_native_title_query=False,
        information_battle_native_title_query_mode="cached_sources_no_helper_invoke",
        information_battle_name_sources=True,
        information_battle_name_sources_wire=11,
        information_battle_name_sources_stage="entry_before_client_gate",
        information_battle_name_sources_read_only=True,
        information_battle_name_sources_complete=False,
    )
    manifest["compiler_arguments"].extend(
        ("-DINFORMATION_BATTLE_NAME_SOURCES=1", "-DINFORMATION_BATTLE_NO_TITLE_QUERY_INVOKE=1")
    )
    _add_sources(directory, manifest, start.INFORMATION_BATTLE_NAME_SOURCES_SOURCES,
                 f"synthetic-v{version}:")
    if version == 39:
        manifest.update(
            information_battle_outcome_text=True,
            information_battle_outcome_text_wire=12,
            information_battle_outcome_text_stage="entry_before_client_gate",
            information_battle_outcome_text_read_only=True,
            information_battle_outcome_text_complete=False,
        )
        manifest["compiler_arguments"].append("-DINFORMATION_BATTLE_OUTCOME_TEXT=1")
        _add_sources(directory, manifest, start.INFORMATION_BATTLE_OUTCOME_TEXT_SOURCES,
                     "synthetic-v39:")
    (directory / "build-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return manifest, dll


def _make_control_fixture(directory: Path):
    manifest, dll = _make_manifest_fixture(directory, 39)
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
        "wire_version": 12,
        "native_title_query_enabled": False,
        "name_sources_enabled": True,
        "outcome_text_enabled": True,
    }
    (directory / control.STATUS_NAME).write_text(json.dumps(status), encoding="utf-8")
    return manifest, installation_path, identity


def _pins(directory: Path) -> dict[str, tuple[bytes, int]]:
    return {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in directory.iterdir()
        if path.is_file()
    }


def test_v39_manifest_accepts_complete_outcome_text_sources(tmp_path: Path):
    directory = tmp_path / "v39"
    manifest, _dll = _make_manifest_fixture(directory, 39)

    assert len(manifest["sources"]) == 141
    assert set(start.INFORMATION_BATTLE_OUTCOME_TEXT_SOURCES) <= {
        record["name"] for record in manifest["sources"]
    }
    assert "-DINFORMATION_BATTLE_NAME_SOURCES=1" in manifest["compiler_arguments"]
    assert "-DINFORMATION_BATTLE_NO_TITLE_QUERY_INVOKE=1" in manifest["compiler_arguments"]
    assert "-DINFORMATION_BATTLE_OUTCOME_TEXT=1" in manifest["compiler_arguments"]
    assert not any("INFORMATION_CURRENT_COUNTRY_CONTROL" in arg
                   for arg in manifest["compiler_arguments"])
    start._validate_information_battle_manifest(manifest, directory)
    control._validate_manifest(manifest, directory)


def test_v39_manifest_preserves_optional_name_handoff_and_all_old_sources(tmp_path: Path):
    directory = tmp_path / "v39-name-handoff"
    manifest, _dll = _make_manifest_fixture(directory, 39, name_handoff=True)

    assert len(manifest["sources"]) == 144
    start._validate_information_battle_manifest(manifest, directory)
    control._validate_manifest(manifest, directory)


@pytest.mark.parametrize("mutation", [
    "missing_define",
    "wrong_define",
    "duplicate_define",
    "wrong_wire",
    "boolean_wire",
    "wrong_stage",
    "not_read_only",
    "complete",
    "missing_source",
    "extra_source",
    "duplicate_source",
    "wrong_source_pin",
])
def test_v39_manifest_rejects_incomplete_or_unpinned_outcome_text(tmp_path: Path, mutation: str):
    directory = tmp_path / mutation
    manifest, _dll = _make_manifest_fixture(directory, 39)
    arguments = manifest["compiler_arguments"]
    source_name = start.INFORMATION_BATTLE_OUTCOME_TEXT_SOURCES[0]
    if mutation == "missing_define":
        arguments.remove("-DINFORMATION_BATTLE_OUTCOME_TEXT=1")
    elif mutation == "wrong_define":
        arguments[-1] = "-DINFORMATION_BATTLE_OUTCOME_TEXT=0"
    elif mutation == "duplicate_define":
        arguments.append("-DINFORMATION_BATTLE_OUTCOME_TEXT=1")
    elif mutation == "wrong_wire":
        manifest[OUTCOME_TEXT_KEYS[1]] = 11
    elif mutation == "boolean_wire":
        manifest[OUTCOME_TEXT_KEYS[1]] = True
    elif mutation == "wrong_stage":
        manifest[OUTCOME_TEXT_KEYS[2]] = "after_client_gate"
    elif mutation == "not_read_only":
        manifest[OUTCOME_TEXT_KEYS[3]] = False
    elif mutation == "complete":
        manifest[OUTCOME_TEXT_KEYS[4]] = True
    elif mutation == "missing_source":
        manifest["sources"] = [row for row in manifest["sources"] if row["name"] != source_name]
    elif mutation == "extra_source":
        name = "unowned-outcome-text-fixture.h"
        data = b"unowned source"
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


def test_v38_manifest_remains_accepted_and_rejects_v39_outcome_text_metadata(tmp_path: Path):
    directory = tmp_path / "v38"
    manifest, _dll = _make_manifest_fixture(directory, 38)
    assert len(manifest["sources"]) == 138
    start._validate_information_battle_manifest(manifest, directory)
    control._validate_manifest(manifest, directory)

    manifest[OUTCOME_TEXT_KEYS[0]] = False
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)


def test_v38_manifest_rejects_v39_outcome_text_define(tmp_path: Path):
    directory = tmp_path / "v38-define"
    manifest, _dll = _make_manifest_fixture(directory, 38)
    manifest["compiler_arguments"].append("-DINFORMATION_BATTLE_OUTCOME_TEXT=1")
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)


def test_v39_cli_status_is_read_only_after_full_manifest_admission(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    directory = tmp_path / "v39-control"
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
    assert result["native"]["wire_version"] == 12
    assert result["native"]["native_title_query_enabled"] is False
    assert before == after
