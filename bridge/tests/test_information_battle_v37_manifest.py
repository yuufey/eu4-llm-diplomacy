"""Independent v37 strict admission checks for start/control consumers."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start


def make_v37_manifest_fixture(directory: Path, *, name_handoff: bool = False):
    directory.mkdir(parents=True, exist_ok=True)
    dll_path = directory / "eu4_bridge_diplomacy_observer_v37.dll"
    dll_bytes = b"synthetic-v37-retreat-dll"
    dll_path.write_bytes(dll_bytes)

    names = (set(start.INFORMATION_BATTLE_V33_SOURCE_NAMES)
             | set(start.INFORMATION_DEBT_QUOTE_REQUIRED_SOURCES)
             | set(start.INFORMATION_BATTLE_END_STATE_SOURCES)
             | set(start.INFORMATION_BATTLE_RETREAT_SOURCES))
    if name_handoff:
        names |= set(start.INFORMATION_BATTLE_NAME_HANDOFF_SOURCES)
    else:
        names |= set(start.INFORMATION_BATTLE_END_STATE_HEADER_DEPENDENCIES)
    records = []
    for name in sorted(names):
        source = directory / name
        data = ("owned-v37:" + name).encode("ascii")
        source.write_bytes(data)
        records.append({"name": name, "sha256": hashlib.sha256(data).hexdigest()})

    arguments = [
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
        "-DINFORMATION_BATTLE_END_STATE=1",
        "-DINFORMATION_BATTLE_RETREAT=1",
    ]
    manifest = {
        "version": 37,
        "experiment_id": directory.name,
        "compiled": True,
        "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        "dll_sha256": hashlib.sha256(dll_bytes).hexdigest(),
        "dll": str(dll_path.resolve()),
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
        "information_battle_end_state": True,
        "information_battle_end_state_wire": 9,
        "information_battle_end_state_complete": False,
        "information_battle_retreat": True,
        "information_battle_retreat_wire": 10,
        "information_battle_retreat_stage": "regular_battle_end_unit_path_callback",
        "information_battle_retreat_complete": False,
        "compiler_arguments": arguments,
        "sources": records,
    }
    if name_handoff:
        manifest.update({
            "information_battle_name_handoff": True,
            "information_battle_name_handoff_wire": 8,
            "information_battle_name_handoff_stage": "before_pair_move",
            "information_battle_name_handoff_complete": False,
        })
        manifest["compiler_arguments"].append("-DINFORMATION_BATTLE_NAME_HANDOFF=1")
    (directory / "build-manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    return manifest, dll_path


def _write_manifest(directory: Path, manifest: dict) -> None:
    (directory / "build-manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )


def _downgrade_to_v36(directory: Path, manifest: dict) -> dict:
    value = copy.deepcopy(manifest)
    value["version"] = 36
    for key in (
        "information_battle_retreat",
        "information_battle_retreat_wire",
        "information_battle_retreat_stage",
        "information_battle_retreat_complete",
    ):
        value.pop(key, None)
    value["compiler_arguments"] = [
        item for item in value["compiler_arguments"]
        if not item.startswith("-DINFORMATION_BATTLE_RETREAT")
    ]
    value["sources"] = [
        record for record in value["sources"]
        if record["name"] not in start.INFORMATION_BATTLE_RETREAT_SOURCES
    ]
    old_dll = directory / "eu4_bridge_diplomacy_observer_v36.dll"
    old_bytes = b"synthetic-v36-end-state-dll"
    old_dll.write_bytes(old_bytes)
    value["dll"] = str(old_dll.resolve())
    value["dll_sha256"] = hashlib.sha256(old_bytes).hexdigest()
    _write_manifest(directory, value)
    return value


def test_v37_manifest_and_control_accept_retreat_with_name_hook_off(tmp_path: Path):
    directory = tmp_path / "v37-no-name-hook"
    manifest, _ = make_v37_manifest_fixture(directory)

    assert "information_battle_name_handoff" not in manifest
    assert not any("INFORMATION_BATTLE_NAME_HANDOFF" in item
                   for item in manifest["compiler_arguments"])
    start._validate_information_battle_manifest(manifest, directory)
    control._validate_manifest(manifest, directory)


def test_v37_manifest_keeps_optional_name_handoff_contract(tmp_path: Path):
    directory = tmp_path / "v37-with-name-hook"
    manifest, _ = make_v37_manifest_fixture(directory, name_handoff=True)
    start._validate_information_battle_manifest(manifest, directory)
    control._validate_manifest(manifest, directory)


def test_v37_accepts_opt_in_unit_removal_metadata_without_new_sources(tmp_path: Path):
    directory = tmp_path / "v37-unit-removal"
    manifest, _ = make_v37_manifest_fixture(directory)
    source_count = len(manifest["sources"])
    manifest["information_battle_retreat_unit_removal"] = True
    manifest["information_battle_retreat_max_extension_version"] = 2

    start._validate_information_battle_manifest(manifest, directory)
    control._validate_manifest(manifest, directory)
    assert len(manifest["sources"]) == source_count
    assert "information-battle-retreat-entry-plan.h" in {
        record["name"] for record in manifest["sources"]
    }


@pytest.mark.parametrize(("unit_removal", "max_version"), [
    (True, None),
    (None, 2),
    (False, 2),
    (1, 2),
    (True, 1),
    (True, True),
    (True, "2"),
])
def test_v37_rejects_partial_or_noncanonical_unit_removal_metadata(
    tmp_path: Path, unit_removal, max_version,
):
    directory = tmp_path / f"unit-removal-{unit_removal}-{max_version}"
    manifest, _ = make_v37_manifest_fixture(directory)
    if unit_removal is not None:
        manifest["information_battle_retreat_unit_removal"] = unit_removal
    if max_version is not None:
        manifest["information_battle_retreat_max_extension_version"] = max_version
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)


def test_v37_builder_emits_the_opt_in_retreat_extension_flags():
    script = (Path(__file__).resolve().parents[2]
              / "work/native/build-diplomacy-observer.ps1").read_text(encoding="utf-8")
    assert "$manifest.information_battle_retreat_stage = 'regular_battle_end_unit_path_callback'" in script
    assert "$manifest.information_battle_retreat_unit_removal = $true" in script
    assert "$manifest.information_battle_retreat_max_extension_version = 2" in script


@pytest.mark.parametrize("key,value", [
    ("information_battle_retreat", False),
    ("information_battle_retreat_wire", 9),
    ("information_battle_retreat_stage", "wrong_stage"),
    ("information_battle_retreat_complete", True),
])
def test_v37_rejects_missing_or_bad_retreat_metadata(tmp_path: Path, key: str, value):
    directory = tmp_path / f"bad-{key}"
    manifest, _ = make_v37_manifest_fixture(directory)
    manifest[key] = value
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)


@pytest.mark.parametrize("edit", ["missing", "wrong", "duplicate"])
def test_v37_retreat_define_must_be_exactly_one_value_one(tmp_path: Path, edit: str):
    directory = tmp_path / f"define-{edit}"
    manifest, _ = make_v37_manifest_fixture(directory)
    args = manifest["compiler_arguments"]
    args[:] = [item for item in args if not item.startswith("-DINFORMATION_BATTLE_RETREAT")]
    if edit == "wrong":
        args.append("-DINFORMATION_BATTLE_RETREAT=0")
    elif edit == "duplicate":
        args.extend(("-DINFORMATION_BATTLE_RETREAT=1", "-DINFORMATION_BATTLE_RETREAT=1"))
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)


@pytest.mark.parametrize("edit", ["missing_source", "unknown_source", "duplicate_source"])
def test_v37_retreat_sources_are_exact_and_unique(tmp_path: Path, edit: str):
    directory = tmp_path / f"source-{edit}"
    manifest, _ = make_v37_manifest_fixture(directory)
    if edit == "missing_source":
        manifest["sources"] = [
            row for row in manifest["sources"]
            if row["name"] != start.INFORMATION_BATTLE_RETREAT_SOURCES[0]
        ]
    elif edit == "unknown_source":
        unknown = "information-battle-unknown-retreat.h"
        data = b"unowned source"
        (directory / unknown).write_bytes(data)
        manifest["sources"].append({"name": unknown, "sha256": hashlib.sha256(data).hexdigest()})
    else:
        manifest["sources"].append(copy.deepcopy(manifest["sources"][0]))
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)


@pytest.mark.parametrize("extra", [
    {"information_battle_retreat": False},
    {"information_battle_retreat_unit_removal": True,
     "information_battle_retreat_max_extension_version": 2},
    {"compiler_define": "-DINFORMATION_BATTLE_RETREAT=1"},
])
def test_v36_rejects_new_retreat_keys_and_defines(tmp_path: Path, extra: dict):
    directory = tmp_path / "v36-reject-retreat"
    manifest, _ = make_v37_manifest_fixture(directory)
    manifest = _downgrade_to_v36(directory, manifest)
    if "compiler_define" in extra:
        manifest["compiler_arguments"].append(extra["compiler_define"])
    else:
        manifest.update(extra)
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)


def test_v36_manifest_remains_accepted_after_v37_extension(tmp_path: Path):
    directory = tmp_path / "v36-preserved"
    manifest, _ = make_v37_manifest_fixture(directory)
    manifest = _downgrade_to_v36(directory, manifest)
    start._validate_information_battle_manifest(manifest, directory)
    control._validate_manifest(manifest, directory)

