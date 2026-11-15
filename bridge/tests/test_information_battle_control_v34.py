"""Offline v34 information-battle manifest and controller identity checks."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile

import pytest

from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start


GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
PLAYER_REF = "1234567890abcdef"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class V34ManifestFixture:
    """A complete synthetic v34 directory using the pinned source inventory."""

    def __init__(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.dll = self.root / "eu4_bridge_diplomacy_observer_v34.dll"
        self.dll.write_bytes(b"synthetic v34 observer dll")
        self.dll_sha = _sha256(self.dll)
        self.names = sorted(
            set(start.INFORMATION_BATTLE_V33_SOURCE_NAMES)
            | set(start.INFORMATION_DEBT_QUOTE_REQUIRED_SOURCES)
        )
        self.sources = {}
        records = []
        for name in self.names:
            path = self.root / name
            path.write_bytes(("synthetic-v34-source:" + name).encode("ascii"))
            self.sources[name] = path
            records.append({"name": name, "sha256": _sha256(path)})
        self.manifest = {
            "version": 34,
            "experiment_id": "information-battle-v34-control-test",
            "game_sha256": GAME_SHA,
            "dll_sha256": self.dll_sha,
            "information_battle_research_lifecycle": True,
            "native_war_participants_query": True,
            "information_battle_context_wire": 2,
            "information_battle_owned_context": True,
            "information_battle_naval_wire": 3,
            "information_battle_owned_naval": True,
            "information_battle_template_wire": 4,
            "information_battle_owned_template": True,
            "information_battle_message_scope": True,
            "information_battle_formatter_container": True,
            "information_battle_template_extensions": [1, 2],
            "information_battle_war_identity": True,
            "information_battle_war_identity_wire": 5,
            "information_battle_war_identity_scope": "observer_session",
            "information_battle_war_identity_read_only": True,
            "information_battle_war_identity_complete": False,
            "information_battle_native_text": True,
            "information_battle_native_text_wire": 6,
            "information_battle_native_text_scope": "observer_session",
            "information_battle_native_text_read_only": True,
            "information_battle_native_text_complete": False,
            "information_battle_native_title_query": True,
            "information_battle_native_title_query_mode": "native_helper_owned_output",
            "information_battle_native_title_query_wire": 6,
            "information_battle_native_title_query_complete": False,
            "information_battle_gate_trace": True,
            "information_battle_gate_trace_protocol": "EU4-BATTLE-GATE-TRACE/1",
            "information_battle_gate_trace_runtime_verified": False,
            "information_battle_display_context": True,
            "information_battle_display_context_wire": 7,
            "information_battle_display_context_scope": "same_battle_event",
            "information_battle_display_context_stage": "router_scope_exit",
            "information_battle_display_context_read_only": True,
            "information_battle_display_context_complete": False,
            "information_debt_quote_query": True,
            "information_debt_quote_query_wire": 1,
            "information_debt_quote_read_only": True,
            "information_debt_quote_fp_context": True,
            "compiler_arguments": [
                "-DBRIDGE_INFORMATION_BATTLE=1",
                "-DINFORMATION_BATTLE_CONTEXT=1",
                "-DINFORMATION_BATTLE_NAVAL=1",
                "-DINFORMATION_BATTLE_TEMPLATE=1",
                "-DINFORMATION_BATTLE_CONTAINER=1",
                "-DINFORMATION_BATTLE_WAR_IDENTITY=1",
                "-DINFORMATION_BATTLE_NATIVE_TEXT=1",
                "-DINFORMATION_BATTLE_NATIVE_TITLE_QUERY=1",
                "-DINFORMATION_BATTLE_GATE_TRACE=1",
                "-DINFORMATION_BATTLE_DISPLAY_CONTEXT=1",
                "-DBRIDGE_DEBT_QUOTE_QUERY=1",
            ],
            "sources": records,
        }
        self.manifest_path = self.root / "build-manifest.json"
        self.write_manifest(self.manifest)

    def write_manifest(self, manifest: dict) -> None:
        self.manifest = manifest
        self.manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True), encoding="utf-8"
        )

    def close(self) -> None:
        self.temp.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class V34ControlFixture(V34ManifestFixture):
    def __init__(self):
        super().__init__()
        self.installation_path = self.root / "installation.json"
        self.installation = {
            "pid": 43210,
            "creation_filetime": 99887766,
            "game_sha256": GAME_SHA,
            "session_id": "43210-v34-test-session",
            "dll_sha256": self.dll_sha,
            "modules_after_install": [{
                "name": self.dll.name,
                "path": str(self.dll),
                "sha256": self.dll_sha,
            }],
        }
        self.identity = {
            "pid": self.installation["pid"],
            "creation_filetime": self.installation["creation_filetime"],
            "game_sha256": GAME_SHA,
            "session_id": self.installation["session_id"],
            "modules": [{
                "name": self.dll.name,
                "path": str(self.dll),
                "sha256": self.dll_sha,
            }],
        }
        self.write_installation()

    def write_installation(self) -> None:
        self.installation_path.write_text(
            json.dumps(self.installation, ensure_ascii=False, sort_keys=True), encoding="utf-8"
        )

    def write_status(self, *, state: str = "ready") -> Path:
        path = self.root / control.STATUS_NAME
        path.write_text(json.dumps({
            "schema": "EU4-BATTLE-SOURCE/1", "request_id": "startup",
            "command": "startup", "accepted": True,
            "reason": "awaiting_process_bound_enable", "state": state,
            "pid": self.installation["pid"],
            "creation_filetime": str(self.installation["creation_filetime"]),
            "installation": "0", "generation": "0",
            "exe_sha256": GAME_SHA, "dll_sha256": self.dll_sha,
        }), encoding="utf-8")
        return path


def _patch_probe(monkeypatch, fixture: V34ControlFixture):
    monkeypatch.setattr(control, "probe_identity", lambda _pid, _exe: deepcopy(fixture.identity))
    monkeypatch.setattr(control, "game_exe", lambda: fixture.root / "eu4.exe")


def _assert_rejected(manifest: dict, directory: Path):
    with pytest.raises(SystemExit) as start_error:
        start._validate_information_battle_manifest(manifest, directory)
    assert str(start_error.value) == "BUILD_MANIFEST_MISMATCH"
    with pytest.raises(control.ControlError) as control_error:
        control._validate_manifest(manifest, directory)
    assert control_error.value.reason == "BUILD_MANIFEST_MISMATCH"


def test_v34_manifest_is_accepted_by_start_and_control_with_two_quote_sources():
    with V34ManifestFixture() as fixture:
        start._validate_information_battle_manifest(fixture.manifest, fixture.root)
        control._validate_manifest(fixture.manifest, fixture.root)
        assert fixture.manifest["version"] == 34
        assert len(fixture.manifest["sources"]) == 127
        assert set(start.INFORMATION_DEBT_QUOTE_REQUIRED_SOURCES) <= set(fixture.names)
        assert fixture.manifest["information_battle_display_context_wire"] == 7
        assert fixture.manifest["information_debt_quote_query_wire"] == 1


@pytest.mark.parametrize("mutation", [
    lambda data: data.update(version=35),
    lambda data: data.update(information_battle_display_context_wire=8),
    lambda data: data["sources"].pop(),
    lambda data: data["sources"][0].update(sha256="0" * 64),
])
def test_v34_manifest_rejects_version_wire_source_or_hash_mutations(mutation):
    with V34ManifestFixture() as fixture:
        mutant = deepcopy(fixture.manifest)
        mutation(mutant)
        _assert_rejected(mutant, fixture.root)


def test_v34_control_status_is_read_only_with_correct_module_identity(monkeypatch):
    with V34ControlFixture() as fixture:
        _patch_probe(monkeypatch, fixture)
        fixture.write_status()
        result = control.run_control(fixture.installation_path, "status")
        assert result["status"] == "observed"
        assert result["installation"] == "0"
        assert not (fixture.root / control.CONTROL_NAME).exists()
        assert not (fixture.root / control.BINDING_NAME).exists()


def test_v34_missing_installation_modules_cannot_be_replaced_by_heartbeat(monkeypatch):
    with V34ControlFixture() as fixture:
        _patch_probe(monkeypatch, fixture)
        fixture.installation.pop("modules_after_install")
        fixture.write_installation()
        fixture.write_status()
        with pytest.raises(control.ControlError) as error:
            control.run_control(fixture.installation_path, "status")
        assert error.value.reason == "MODULE_SET_NOT_UNIQUE"
        assert not (fixture.root / control.CONTROL_NAME).exists()
        assert not (fixture.root / control.BINDING_NAME).exists()


@pytest.mark.parametrize("mutation,reason", [
    (lambda identity: identity["modules"][0].update(sha256="0" * 64), "MODULE_HASH_MISMATCH"),
    (lambda identity: identity["modules"][0].update(path="C:/wrong-v34.dll"), "MODULE_PATH_MISMATCH"),
    (lambda identity: identity.update(session_id="other-session"), "SESSION_ID_MISMATCH"),
])
def test_v34_control_keeps_module_path_hash_and_session_guards(monkeypatch, mutation, reason):
    with V34ControlFixture() as fixture:
        _patch_probe(monkeypatch, fixture)
        mutation(fixture.identity)
        fixture.write_status()
        with pytest.raises(control.ControlError) as error:
            control.run_control(fixture.installation_path, "status")
        assert error.value.reason == reason
        assert not (fixture.root / control.CONTROL_NAME).exists()
        assert not (fixture.root / control.BINDING_NAME).exists()


def test_v34_enable_rejects_missing_metadata_without_creating_control_file(monkeypatch):
    with V34ControlFixture() as fixture:
        _patch_probe(monkeypatch, fixture)
        fixture.installation.pop("modules_after_install")
        fixture.write_installation()
        with pytest.raises(control.ControlError) as error:
            control.run_control(fixture.installation_path, "enable", PLAYER_REF)
        assert error.value.reason == "MODULE_SET_NOT_UNIQUE"
        assert not (fixture.root / control.CONTROL_NAME).exists()
        assert not (fixture.root / control.BINDING_NAME).exists()

