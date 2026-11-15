"""Offline v35/name-handoff manifest and ACK contract checks."""

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


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class V35NameHandoffFixture:
    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.dll = self.root / "eu4_bridge_diplomacy_observer_v35.dll"
        self.dll.write_bytes(b"synthetic v35 name-handoff observer dll")
        names = sorted(
            set(start.INFORMATION_BATTLE_V33_SOURCE_NAMES)
            | set(start.INFORMATION_DEBT_QUOTE_REQUIRED_SOURCES)
            | set(start.INFORMATION_BATTLE_NAME_HANDOFF_SOURCES)
        )
        records = []
        for name in names:
            path = self.root / name
            path.write_bytes(("synthetic-v35-source:" + name).encode("ascii"))
            records.append({"name": name, "sha256": _sha256(path)})
        self.manifest = {
            "version": 35,
            "experiment_id": "information-battle-v35-name-handoff-test",
            "game_sha256": GAME_SHA,
            "dll_sha256": _sha256(self.dll),
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
            "information_battle_name_handoff": True,
            "information_battle_name_handoff_wire": 8,
            "information_battle_name_handoff_stage": "before_pair_move",
            "information_battle_name_handoff_complete": False,
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
                "-DINFORMATION_BATTLE_NAME_HANDOFF=1",
            ],
            "sources": records,
        }

    def close(self) -> None:
        self.temp.cleanup()

    def __enter__(self) -> "V35NameHandoffFixture":
        return self

    def __exit__(self, *_args) -> None:
        self.close()


def _reject(manifest: dict, root: Path) -> None:
    with pytest.raises(SystemExit) as start_error:
        start._validate_information_battle_manifest(manifest, root)
    assert str(start_error.value) == "BUILD_MANIFEST_MISMATCH"
    with pytest.raises(control.ControlError) as control_error:
        control._validate_manifest(manifest, root)
    assert control_error.value.reason == "BUILD_MANIFEST_MISMATCH"


def test_v35_name_handoff_manifest_is_strictly_accepted_by_start_and_control():
    with V35NameHandoffFixture() as fixture:
        start._validate_information_battle_manifest(fixture.manifest, fixture.root)
        control._validate_manifest(fixture.manifest, fixture.root)
        assert fixture.manifest["version"] == 35
        assert len(fixture.manifest["sources"]) == 132
        assert set(start.INFORMATION_BATTLE_NAME_HANDOFF_SOURCES) <= {
            record["name"] for record in fixture.manifest["sources"]
        }
        assert fixture.manifest["information_battle_name_handoff_wire"] == 8
        assert fixture.manifest["information_battle_name_handoff_stage"] == "before_pair_move"
        assert fixture.manifest["information_battle_name_handoff_complete"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        lambda data: data.update({"information_battle_name_handoff": False}),
        lambda data: data.update({"information_battle_name_handoff_wire": 7}),
        lambda data: data.update({"information_battle_name_handoff_stage": "after_pair_move"}),
        lambda data: data.update({"information_battle_name_handoff_complete": True}),
        lambda data: data["compiler_arguments"].remove(
            "-DINFORMATION_BATTLE_NAME_HANDOFF=1"
        ),
        lambda data: data["sources"].pop(),
        lambda data: data["sources"][0].update({"sha256": "0" * 64}),
    ],
)
def test_v35_name_handoff_fields_sources_and_hashes_are_required(mutation):
    with V35NameHandoffFixture() as fixture:
        mutant = deepcopy(fixture.manifest)
        mutation(mutant)
        _reject(mutant, fixture.root)


def test_v34_does_not_silently_accept_name_handoff_metadata_or_macro():
    with V35NameHandoffFixture() as fixture:
        mutant = deepcopy(fixture.manifest)
        mutant["version"] = 34
        _reject(mutant, fixture.root)


def test_v35_native_ack_declares_wire8_and_name_handoff():
    source = (
        Path(__file__).resolve().parents[2]
        / "work"
        / "native"
        / "diplomacy-observer-v10.cpp"
    ).read_text(encoding="utf-8")
    assert r'\"native_information_battle_wire\":8' in source
    assert r'\"native_information_battle_name_handoff\":true' in source
    assert "version_marker[sizeof(\"\\\"version\\\":\")-1]='3'" in source
    assert "version_marker[sizeof(\"\\\"version\\\":\")]='5'" in source
