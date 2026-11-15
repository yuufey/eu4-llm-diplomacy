"""Strict v54 admission binds mission-source and alliance-record contracts."""
import hashlib
import json

import pytest

from bridge.tests.test_start_diplomacy_observer_v48 import fixture as v48_fixture
from bridge.tests.test_start_diplomacy_observer_v51 import (
    _set_source_hash,
    fixture as v51_fixture,
)
from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start
from work import probe_information_battle_v23 as probe


def fixture(directory):
    manifest, directory = v51_fixture(directory)
    manifest.update(
        version=54,
        native_relation_change_wire=2,
        native_relation_change_scope=start.ALLIANCE_RECORD_SCOPE,
        native_alliance_record_observation=True,
        native_mission_completion_wire=2,
        native_mission_completion_scope=start.MISSION_COMPLETED_SET_SCOPE,
        native_mission_completed_set_observation=True,
        native_mission_availability_observation=True,
        native_mission_availability_wire=1,
        native_mission_availability_scope=start.MISSION_AVAILABILITY_SCOPE,
        experiment_id="synthetic-macro-sources-v54",
    )
    manifest["compiler_arguments"].extend(
        f"-D{define}=1" for define in start.MACRO_SOURCE_DEFINE_NAMES)
    for name in start.MACRO_SOURCE_SOURCES:
        data = ("synthetic v54 " + name).encode()
        (directory / name).write_bytes(data)
        manifest["sources"].append({
            "name": name, "sha256": hashlib.sha256(data).hexdigest(),
        })

    ack_path = directory / start.MACRO_EVENT_ACK_SOURCE
    ack_text = ack_path.read_text(encoding="utf-8")
    for old, new in (
        (start.MACRO_EVENT_ACK_SOURCE_BLOCKS[1],
         start.MACRO_SOURCE_RELATION_ACK_BLOCK),
        (start.MACRO_EVENT_ACK_SOURCE_BLOCKS[2],
         start.MACRO_SOURCE_MISSION_ACK_BLOCK),
    ):
        assert ack_text.count(old) == 1
        ack_text = ack_text.replace(old, new)
    ack_text += "\n" + start.MACRO_SOURCE_AVAILABILITY_ACK_BLOCK + "\n"
    ack_text += start.MACRO_SOURCE_V54_VERSION_BLOCK + "\n"
    ack_path.write_text(ack_text, encoding="utf-8")
    _set_source_hash(manifest, start.MACRO_EVENT_ACK_SOURCE, ack_path)

    dll = directory / "eu4_bridge_diplomacy_observer_v54.dll"
    dll.write_bytes(b"synthetic v54 DLL pin")
    manifest["dll"] = str(dll.resolve())
    manifest["dll_sha256"] = hashlib.sha256(dll.read_bytes()).hexdigest()
    (directory / "build-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest, directory


def _write_probe_manifest(manifest, directory):
    (directory / "build-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def _assert_all_reject(manifest, directory):
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)
    with pytest.raises(control.ControlError) as caught:
        control._validate_manifest(manifest, directory)
    assert caught.value.reason == "BUILD_MANIFEST_MISMATCH"
    _write_probe_manifest(manifest, directory)
    assert probe._manifest_static_guard(directory)["status"] != "observed"


def test_v54_exact_contract_passes_all_static_entries(tmp_path, monkeypatch):
    manifest, directory = fixture(tmp_path / "candidate")
    assert len(manifest["sources"]) == 175
    start._validate_information_battle_manifest(manifest, directory)
    control._validate_manifest(manifest, directory)
    monkeypatch.setattr(
        probe, "_coff_symbol",
        lambda path, symbol=probe.STUB_SYMBOL: {
            "status": "observed", "source": "ordinary_pe_coff",
            "symbol": symbol, "rva": "0x1000",
        })
    report = probe._base_report(
        probe.DEFAULT_INSTALLATION, directory / "probe-static.json", "original")
    result = probe._static_prepare(report, directory)
    assert result["manifest"]["version"] == 54
    assert len(result["manifest"]["sources"]) == 175
    assert report["provenance"]["source"]["status"] == "observed"
    assert report["provenance"]["ordinary_pe_coff"]["status"] == "observed"


@pytest.mark.parametrize("mutation", [
    "relation_wire_bool", "mission_wire_bool", "availability_wire_bool",
    "war_parent_cap_missing", "war_parent_define_missing",
    "availability_flag_integer", "availability_scope_changed",
    "recordcap_missing", "recordcap_integer", "record_scope_changed",
    "setcap_missing", "setcap_integer", "set_scope_changed",
    "define_duplicate", "bare_define", "source_missing",
    "relation_ack_changed", "version_override_changed",
    "prototype_only", "deployment_not_verified",
])
def test_v54_rejects_malformed_or_prototype_contract(tmp_path, mutation):
    manifest, directory = fixture(tmp_path / "candidate")
    if mutation == "relation_wire_bool":
        manifest["native_relation_change_wire"] = True
    elif mutation == "mission_wire_bool":
        manifest["native_mission_completion_wire"] = True
    elif mutation == "availability_wire_bool":
        manifest["native_mission_availability_wire"] = True
    elif mutation == "war_parent_cap_missing":
        manifest.pop(start.WAR_DECLARATION_KEYS[0])
    elif mutation == "war_parent_define_missing":
        manifest["compiler_arguments"].remove(
            "-DBRIDGE_WAR_DECLARATION_OBSERVATION=1")
    elif mutation == "availability_flag_integer":
        manifest["native_mission_availability_observation"] = 1
    elif mutation == "availability_scope_changed":
        manifest["native_mission_availability_scope"] = "FRA_only"
    elif mutation == "recordcap_missing":
        manifest.pop(start.ALLIANCE_RECORD_CAPABILITY)
    elif mutation == "recordcap_integer":
        manifest[start.ALLIANCE_RECORD_CAPABILITY] = 1
    elif mutation == "record_scope_changed":
        manifest["native_relation_change_scope"] = "FRA_pair_only"
    elif mutation == "setcap_missing":
        manifest.pop(start.MISSION_COMPLETED_SET_CAPABILITY)
    elif mutation == "setcap_integer":
        manifest[start.MISSION_COMPLETED_SET_CAPABILITY] = 1
    elif mutation == "set_scope_changed":
        manifest["native_mission_completion_scope"] = "FRA_set_only"
    elif mutation == "define_duplicate":
        manifest["compiler_arguments"].append(
            "-DBRIDGE_ALLIANCE_RECORD_OBSERVATION=1")
    elif mutation == "bare_define":
        manifest["compiler_arguments"].remove(
            "-DBRIDGE_MISSION_COMPLETED_SET_OBSERVATION=1")
        manifest["compiler_arguments"].append(
            "-DBRIDGE_MISSION_COMPLETED_SET_OBSERVATION")
    elif mutation == "source_missing":
        missing = start.MACRO_SOURCE_SOURCES[0]
        manifest["sources"] = [row for row in manifest["sources"]
                               if row["name"] != missing]
    elif mutation == "relation_ack_changed":
        ack_path = directory / start.MACRO_EVENT_ACK_SOURCE
        ack_text = ack_path.read_text(encoding="utf-8")
        literal = r'\"native_relation_change_wire\":2'
        assert literal in ack_text
        ack_path.write_text(ack_text.replace(literal, r'\"native_relation_change_wire\":1'),
                            encoding="utf-8")
        _set_source_hash(manifest, start.MACRO_EVENT_ACK_SOURCE, ack_path)
    elif mutation == "version_override_changed":
        ack_path = directory / start.MACRO_EVENT_ACK_SOURCE
        ack_text = ack_path.read_text(encoding="utf-8")
        changed = start.MACRO_SOURCE_V54_VERSION_BLOCK.replace(
            "version_marker[sizeof(\"\\\"version\\\":\")]='4';",
            "version_marker[sizeof(\"\\\"version\\\":\")]='3';")
        assert changed != start.MACRO_SOURCE_V54_VERSION_BLOCK
        ack_path.write_text(
            ack_text.replace(start.MACRO_SOURCE_V54_VERSION_BLOCK, changed),
            encoding="utf-8")
        _set_source_hash(manifest, start.MACRO_EVENT_ACK_SOURCE, ack_path)
    elif mutation == "prototype_only":
        manifest["prototype_only"] = True
    elif mutation == "deployment_not_verified":
        manifest["deployment_admission_verified"] = False
    _assert_all_reject(manifest, directory)


@pytest.mark.parametrize("version", [49, 50, 52, 53, 56])
def test_only_v23_v48_v51_v54_and_v55_are_admitted(tmp_path, version):
    manifest, directory = fixture(tmp_path / "candidate")
    manifest["version"] = version
    _assert_all_reject(manifest, directory)


@pytest.mark.parametrize("key", sorted(start.MACRO_SOURCE_KEYS))
def test_v51_rejects_v54_macro_source_claims(tmp_path, key):
    manifest, directory = v51_fixture(tmp_path / "candidate")
    manifest[key] = True
    _assert_all_reject(manifest, directory)


@pytest.mark.parametrize("claim", ["define", "source"])
def test_v51_rejects_v54_macro_source_build_claims(tmp_path, claim):
    manifest, directory = v51_fixture(tmp_path / "candidate")
    if claim == "define":
        manifest["compiler_arguments"].append(
            "-DBRIDGE_MISSION_AVAILABILITY_OBSERVATION=1")
    else:
        name = start.MACRO_SOURCE_SOURCES[0]
        data = b"synthetic unadmitted availability source"
        (directory / name).write_bytes(data)
        manifest["sources"].append({
            "name": name, "sha256": hashlib.sha256(data).hexdigest(),
        })
    _assert_all_reject(manifest, directory)


@pytest.mark.parametrize("key", (
    "native_alliance_record_observation",
    "native_mission_completed_set_observation",
    *start.MISSION_AVAILABILITY_KEYS,
))
def test_v48_rejects_v54_macro_source_claims(tmp_path, key):
    manifest, directory = v48_fixture(tmp_path / "candidate")
    manifest[key] = True
    _assert_all_reject(manifest, directory)
