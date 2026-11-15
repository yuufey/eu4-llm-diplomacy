"""Offline validation for the v31 current-country manifest extension."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tools import control_information_battle_observer as controller
from tools import start_diplomacy_observer as starter
from work import probe_information_battle_installed as installed_probe


ROOT = Path(__file__).resolve().parents[2]
PARTICIPANT_SOURCES = (
    "peace-context-query.inc",
    "peace-war-context-query.inc",
    "peace-war-side-members.inc",
)
CURRENT_COUNTRY_SOURCES = (
    "information-current-country-control.inc",
    "information-current-country-control-plan.h",
    "information-current-country-control-policy.h",
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _base_manifest(version: int, participants: bool) -> dict:
    current = version == 31
    arguments = [
        "-DBRIDGE_INFORMATION_BATTLE=1",
        "-DINFORMATION_BATTLE_CONTEXT=1",
        "-DINFORMATION_BATTLE_NAVAL=1",
        "-DINFORMATION_BATTLE_TEMPLATE=1",
        "-DINFORMATION_BATTLE_CONTAINER=1",
        "-DINFORMATION_BATTLE_WAR_IDENTITY=1",
        "-DINFORMATION_BATTLE_NATIVE_TEXT=1",
        "-DINFORMATION_BATTLE_NATIVE_TITLE_QUERY=1",
    ]
    if current:
        arguments.append("-DBRIDGE_CURRENT_COUNTRY_CONTROL=1")
    value = {
        "version": version,
        "experiment_id": f"manifest-fixture-v{version}",
        "compiled": True,
        "runtime_verified": False,
        "game_sha256": installed_probe.EXPECTED_EXE_SHA256,
        "dll_sha256": "0" * 64,
        "compiler_arguments": arguments,
        "information_battle_research_lifecycle": True,
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
        "native_war_participants_query": participants,
        "sources": [],
    }
    if current:
        value.update(
            current_country_control_test_only=True,
            current_country_control_protocol="EU4COUNTRY1",
            current_country_control_entry_rva="0x779360",
        )
    return value


def _make_build(directory: Path, version: int = 31, participants: bool = True) -> tuple[dict, Path]:
    directory.mkdir(parents=True)
    manifest = _base_manifest(version, participants)
    required = list(
        starter.INFORMATION_CURRENT_COUNTRY_CONTROL_REQUIRED_SOURCES
        if version == 31 else starter.INFORMATION_BATTLE_NATIVE_TITLE_QUERY_REQUIRED_SOURCES
    )
    if participants:
        required.extend(PARTICIPANT_SOURCES)
    required = list(dict.fromkeys(required))
    expected_count = 118 + int(participants) + (3 if version == 31 else 0)
    assert len(required) <= expected_count

    source_records = []
    for name in required:
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(("fixture-source:" + name + "\n").encode("ascii"))
        source_records.append({"name": name, "sha256": _sha(path)})
    filler_index = 0
    while len(source_records) < expected_count:
        name = f"unrelated-source-{filler_index:03d}.inc"
        path = directory / name
        path.write_bytes(("fixture-source:" + name + "\n").encode("ascii"))
        source_records.append({"name": name, "sha256": _sha(path)})
        filler_index += 1
    manifest["sources"] = source_records
    dll_path = directory / f"eu4_bridge_diplomacy_observer_v{version}.dll"
    dll_path.write_bytes(b"offline synthetic DLL pin; never loaded")
    manifest["dll_sha256"] = _sha(dll_path)
    _write_manifest(directory, manifest)
    return manifest, dll_path


def _write_manifest(directory: Path, manifest: dict) -> Path:
    path = directory / "build-manifest.json"
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def _validate_probe(directory: Path, manifest: dict, dll_path: Path) -> dict:
    manifest_path = _write_manifest(directory, manifest)
    return installed_probe._validate_artifact(
        directory,
        expected_manifest_sha256=_sha(manifest_path),
        expected_dll_sha256=_sha(dll_path),
    )


def _assert_all_validators_reject(directory: Path, manifest: dict, dll_path: Path) -> None:
    _write_manifest(directory, manifest)
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        starter._validate_information_battle_manifest(manifest, directory)
    with pytest.raises(controller.ControlError, match="BUILD_MANIFEST_MISMATCH"):
        controller._validate_manifest(manifest, directory)
    with pytest.raises(installed_probe.InstalledProbeError):
        installed_probe._validate_artifact(
            directory,
            expected_manifest_sha256=_sha(directory / "build-manifest.json"),
            expected_dll_sha256=_sha(dll_path),
        )


def test_v31_manifest_is_accepted_by_starter_controller_and_probe(tmp_path: Path) -> None:
    manifest, dll_path = _make_build(tmp_path / "valid-v31")
    starter._validate_information_battle_manifest(manifest, tmp_path / "valid-v31")
    controller._validate_manifest(manifest, tmp_path / "valid-v31")
    artifact = _validate_probe(tmp_path / "valid-v31", manifest, dll_path)

    assert manifest["version"] == 31
    assert len(manifest["sources"]) == 122
    assert set(CURRENT_COUNTRY_SOURCES).issubset(
        {row["name"] for row in manifest["sources"]})
    assert artifact["source_count"] == 122
    assert artifact["current_country_control_capability"] == {
        "test_only": True,
        "protocol": "EU4COUNTRY1",
        "entry_rva": "0x779360",
        "runtime_verified": False,
        "compiler_macro": "-DBRIDGE_CURRENT_COUNTRY_CONTROL=1",
        "source_guard": True,
    }
    assert artifact["native_title_query_capability"]["complete"] is False


def test_v31_without_native_war_participants_uses_121_sources(tmp_path: Path) -> None:
    manifest, dll_path = _make_build(tmp_path / "valid-v31-without-participants", participants=False)
    starter._validate_information_battle_manifest(
        manifest, tmp_path / "valid-v31-without-participants")
    artifact = _validate_probe(
        tmp_path / "valid-v31-without-participants", manifest, dll_path)
    assert len(manifest["sources"]) == 121
    assert artifact["source_count"] == 121


def test_v30_manifest_remains_compatible(tmp_path: Path) -> None:
    manifest, dll_path = _make_build(tmp_path / "valid-v30", version=30)
    starter._validate_information_battle_manifest(manifest, tmp_path / "valid-v30")
    controller._validate_manifest(manifest, tmp_path / "valid-v30")
    artifact = _validate_probe(tmp_path / "valid-v30", manifest, dll_path)
    assert len(manifest["sources"]) == 119
    assert artifact["source_count"] == 119
    assert artifact["native_title_query_capability"]["complete"] is False
    assert "current_country_control_capability" not in artifact


@pytest.mark.parametrize(
    "mutation",
    [
        "compiler_flag",
        "test_only_trait",
        "protocol_trait",
        "entry_rva_trait",
        "runtime_verified",
        "native_title_complete",
        "host_fixture_macro",
        "missing_source",
        "tampered_source",
    ],
)
def test_v31_missing_or_changed_trait_and_sources_are_rejected(
    tmp_path: Path, mutation: str,
) -> None:
    directory = tmp_path / ("invalid-v31-" + mutation)
    manifest, dll_path = _make_build(directory)
    if mutation == "compiler_flag":
        manifest["compiler_arguments"].remove("-DBRIDGE_CURRENT_COUNTRY_CONTROL=1")
    elif mutation == "test_only_trait":
        manifest.pop("current_country_control_test_only")
    elif mutation == "protocol_trait":
        manifest["current_country_control_protocol"] = "OTHER"
    elif mutation == "entry_rva_trait":
        manifest["current_country_control_entry_rva"] = "0x779361"
    elif mutation == "runtime_verified":
        manifest["runtime_verified"] = True
    elif mutation == "native_title_complete":
        manifest["information_battle_native_title_query_complete"] = True
    elif mutation == "host_fixture_macro":
        manifest["compiler_arguments"].append(
            "-DINFORMATION_CURRENT_COUNTRY_HOST_FIXTURE=1")
    elif mutation == "missing_source":
        manifest["sources"] = [
            row for row in manifest["sources"]
            if row["name"] != "information-current-country-control-policy.h"
        ]
    elif mutation == "tampered_source":
        (directory / "information-current-country-control-plan.h").write_text(
            "tampered source\n", encoding="ascii")
    _assert_all_validators_reject(directory, manifest, dll_path)


def test_builder_declares_v31_flag_traits_and_all_three_sources_without_building() -> None:
    script = (ROOT / "work/native/build-diplomacy-observer.ps1").read_text(encoding="utf-8")
    assert "[switch]$CurrentCountryControl" in script
    assert "if ($CurrentCountryControl) { $InformationBattleNativeTitleQuery = $true }" in script
    assert "if ($CurrentCountryControl) { 31 }" in script
    assert "-DBRIDGE_CURRENT_COUNTRY_CONTROL=1" in script
    assert "INFORMATION_CURRENT_COUNTRY_HOST_FIXTURE" not in script
    assert "$manifest.current_country_control_test_only = $true" in script
    assert "$manifest.current_country_control_protocol = 'EU4COUNTRY1'" in script
    assert "$manifest.current_country_control_entry_rva = '0x779360'" in script
    for source in CURRENT_COUNTRY_SOURCES:
        assert source in script

