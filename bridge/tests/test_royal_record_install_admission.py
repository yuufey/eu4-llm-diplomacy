import copy
import hashlib
import json
from pathlib import Path
import shutil

import pytest

from bridge.tests.test_start_diplomacy_observer_v55 import fixture as v55_fixture
from bridge.tests.test_start_diplomacy_observer_v56 import fixture as v56_fixture
from bridge.tests.test_information_mission_province_install_admission import (
    _copy_v57,
    _set_source_hash,
)
from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start
from work import probe_information_battle_v23 as probe


ROOT = Path(__file__).resolve().parents[2]
FORMAL_V57 = ROOT / "work/runtime/diplomacy-observer-20261109-province-v57-346-001"
PROTOTYPE_V58 = ROOT / "work/runtime/diplomacy-observer-20261110-royal-v58-348-001"
FORMAL_V58 = ROOT / "work/runtime/diplomacy-observer-20261110-royal-v58-349-001"
ACK_SOURCE = start.MACRO_EVENT_ACK_SOURCE


def _write(manifest, directory):
    (directory / "build-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def _copy_candidate(source, directory):
    directory.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((source / "build-manifest.json").read_text(encoding="utf-8"))
    names = [row["name"] for row in manifest["sources"]]
    dll_name = f"eu4_bridge_diplomacy_observer_v{manifest['version']}.dll"
    names.append(dll_name)
    for name in names:
        shutil.copyfile(source / name, directory / name)
    manifest["dll"] = str((directory / dll_name).resolve())
    _write(manifest, directory)
    return manifest, directory


def _fixture_for_version(tmp_path, version):
    if version == 55:
        return v55_fixture(tmp_path / "candidate")
    if version == 56:
        return v56_fixture(tmp_path / "candidate")
    if version == 57:
        return _copy_v57(tmp_path)
    if version == 58:
        return _copy_candidate(FORMAL_V58, tmp_path / "candidate")
    raise AssertionError(version)


def _assert_all_accept(manifest, directory):
    start._validate_information_battle_manifest(manifest, directory)
    control._validate_manifest(manifest, directory)
    result = probe._manifest_static_guard(directory)
    assert result["status"] == "observed", result
    return result


def _assert_all_reject(manifest, directory):
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)
    with pytest.raises(control.ControlError) as caught:
        control._validate_manifest(manifest, directory)
    assert caught.value.reason == "BUILD_MANIFEST_MISMATCH"
    _write(manifest, directory)
    result = probe._manifest_static_guard(directory)
    assert result["status"] != "observed", result


def _set_cpp_hash(manifest, directory):
    _set_source_hash(manifest, ACK_SOURCE, directory / ACK_SOURCE)
    _write(manifest, directory)


def test_formal_v58_exact_contract_passes_all_three_static_entries():
    manifest = json.loads((FORMAL_V58 / "build-manifest.json").read_text(encoding="utf-8"))
    assert manifest["version"] == 58
    assert len(manifest["sources"]) == 183
    assert manifest["prototype_only"] is False
    assert manifest["formal_installation_admitted"] is True
    assert manifest["native_relation_change_observation"] is True
    assert type(manifest["native_relation_change_wire"]) is int
    assert manifest["native_relation_change_wire"] == 3
    assert manifest["native_relation_change_scope"] == start.ROYAL_RECORD_SCOPE
    assert manifest[start.ROYAL_RECORD_CAPABILITY] is True
    names = {row["name"] for row in manifest["sources"]}
    assert set(start.MISSION_CONDITION_SOURCES) <= names
    assert set(start.MISSION_PROVINCE_CONDITION_SOURCES) <= names
    assert set(start.ROYAL_RECORD_SOURCES) <= names
    arguments = manifest["compiler_arguments"]
    assert arguments.count(f"-D{start.ROYAL_RECORD_DEFINE}=1") == 1

    ack_text = (FORMAL_V58 / ACK_SOURCE).read_text(encoding="utf-8")
    assert ack_text.count(start.ROYAL_RECORD_RELATION_ACK_BLOCK) == 1
    assert ack_text.count(start.ROYAL_RECORD_V58_VERSION_BLOCK) == 1
    assert ack_text.count(start.MISSION_CONDITION_V56_VERSION_BLOCK) == 1
    assert ack_text.count(start.MISSION_PROVINCE_CONDITION_V57_VERSION_BLOCK) == 1

    result = _assert_all_accept(manifest, FORMAL_V58)
    assert result["source_count"] == 183
    assert result["observer_version"] == 58


@pytest.mark.parametrize("version", [55, 56, 57])
def test_frozen_pre_royal_sources_remain_compatible(version, tmp_path):
    manifest, directory = _fixture_for_version(tmp_path, version)
    _assert_all_accept(manifest, directory)


@pytest.mark.parametrize("version", [55, 56, 57])
def test_current_cpp_new_royal_blocks_are_inactive_for_old_formal_builds(version, tmp_path):
    manifest, directory = _fixture_for_version(tmp_path, version)
    shutil.copyfile(FORMAL_V58 / ACK_SOURCE, directory / ACK_SOURCE)
    _set_cpp_hash(manifest, directory)

    cpp_text = (directory / ACK_SOURCE).read_text(encoding="utf-8")
    assert cpp_text.count(start.ROYAL_RECORD_RELATION_ACK_BLOCK) == 1
    assert cpp_text.count(start.ROYAL_RECORD_V58_VERSION_BLOCK) == 1
    assert not any(start._compiler_define_values(arguments, start.ROYAL_RECORD_DEFINE)
                   for arguments in [manifest.get("compiler_arguments")])
    assert start.ROYAL_RECORD_CAPABILITY not in manifest
    assert not any(row["name"] in start.ROYAL_RECORD_SOURCES
                   for row in manifest["sources"])
    _assert_all_accept(manifest, directory)


@pytest.mark.parametrize("mutation", [
    "wire_bool", "wire_2", "scope", "capability_missing", "capability_integer",
    "define_missing", "define_zero", "define_duplicate", "define_bare",
    "source_missing", "source_duplicate", "source_tampered",
    "ack_missing", "ack_wrong_scope", "ack_duplicate",
    "marker_missing", "marker_wrong_digit", "marker_duplicate",
    "prototype_true", "prototype_missing", "formal_false", "formal_integer",
])
def test_v58_rejects_duplicate_or_mixed_royal_contracts(tmp_path, mutation):
    manifest, directory = _fixture_for_version(tmp_path, 58)
    if mutation == "wire_bool":
        manifest["native_relation_change_wire"] = True
    elif mutation == "wire_2":
        manifest["native_relation_change_wire"] = 2
    elif mutation == "scope":
        manifest["native_relation_change_scope"] = "FRA_pair_at_six_relation_command_or_alliance_record_returns"
    elif mutation == "capability_missing":
        manifest.pop(start.ROYAL_RECORD_CAPABILITY)
    elif mutation == "capability_integer":
        manifest[start.ROYAL_RECORD_CAPABILITY] = 1
    elif mutation == "define_missing":
        manifest["compiler_arguments"].remove(f"-D{start.ROYAL_RECORD_DEFINE}=1")
    elif mutation == "define_zero":
        manifest["compiler_arguments"].remove(f"-D{start.ROYAL_RECORD_DEFINE}=1")
        manifest["compiler_arguments"].append(f"-D{start.ROYAL_RECORD_DEFINE}=0")
    elif mutation == "define_duplicate":
        manifest["compiler_arguments"].append(f"-D{start.ROYAL_RECORD_DEFINE}=1")
    elif mutation == "define_bare":
        manifest["compiler_arguments"].remove(f"-D{start.ROYAL_RECORD_DEFINE}=1")
        manifest["compiler_arguments"].append(f"-D{start.ROYAL_RECORD_DEFINE}")
    elif mutation == "source_missing":
        name = start.ROYAL_RECORD_SOURCES[0]
        manifest["sources"] = [row for row in manifest["sources"] if row["name"] != name]
    elif mutation == "source_duplicate":
        name = start.ROYAL_RECORD_SOURCES[0]
        manifest["sources"].append(copy.deepcopy(
            next(row for row in manifest["sources"] if row["name"] == name)))
    elif mutation == "source_tampered":
        path = directory / start.ROYAL_RECORD_SOURCES[0]
        path.write_bytes(path.read_bytes() + b"\n// tampered\n")
    elif mutation.startswith("ack_"):
        path = directory / ACK_SOURCE
        text = path.read_text(encoding="utf-8")
        block = start.ROYAL_RECORD_RELATION_ACK_BLOCK
        if mutation == "ack_missing":
            text = text.replace(block, "")
        elif mutation == "ack_wrong_scope":
            text = text.replace(block, block.replace(
                start.ROYAL_RECORD_SCOPE, "FRA_pair_at_six_relation_or_royal_returns"))
        else:
            text += "\n" + block + "\n"
        path.write_text(text, encoding="utf-8")
        _set_cpp_hash(manifest, directory)
    elif mutation.startswith("marker_"):
        path = directory / ACK_SOURCE
        text = path.read_text(encoding="utf-8")
        block = start.ROYAL_RECORD_V58_VERSION_BLOCK
        if mutation == "marker_missing":
            text = text.replace(block, "")
        elif mutation == "marker_wrong_digit":
            text = text.replace(block, block.replace("]='8';", "]='9';"))
        else:
            text += "\n" + block + "\n"
        path.write_text(text, encoding="utf-8")
        _set_cpp_hash(manifest, directory)
    elif mutation == "prototype_true":
        manifest["prototype_only"] = True
    elif mutation == "prototype_missing":
        manifest.pop("prototype_only")
    elif mutation == "formal_false":
        manifest["formal_installation_admitted"] = False
    elif mutation == "formal_integer":
        manifest["formal_installation_admitted"] = 1

    _assert_all_reject(manifest, directory)


@pytest.mark.parametrize("version", [55, 56, 57])
@pytest.mark.parametrize("claim", ["capability", "define", "source", "wire"])
def test_pre_58_versions_reject_active_royal_claims(version, claim, tmp_path):
    manifest, directory = _fixture_for_version(tmp_path, version)
    shutil.copyfile(FORMAL_V58 / ACK_SOURCE, directory / ACK_SOURCE)
    _set_cpp_hash(manifest, directory)
    if claim == "capability":
        manifest[start.ROYAL_RECORD_CAPABILITY] = True
    elif claim == "define":
        manifest["compiler_arguments"].append(f"-D{start.ROYAL_RECORD_DEFINE}=1")
    elif claim == "source":
        name = start.ROYAL_RECORD_SOURCES[0]
        shutil.copyfile(FORMAL_V58 / name, directory / name)
        manifest["sources"].append({
            "name": name,
            "sha256": hashlib.sha256((directory / name).read_bytes()).hexdigest(),
        })
    else:
        manifest["native_relation_change_wire"] = 3
        manifest["native_relation_change_scope"] = start.ROYAL_RECORD_SCOPE
        manifest[start.ROYAL_RECORD_CAPABILITY] = True
    _assert_all_reject(manifest, directory)


@pytest.mark.parametrize("version", [56, 57, 58])
def test_start_main_reaches_readiness_and_install_stubs_for_formal_builds(
        version, tmp_path, monkeypatch):
    manifest, directory = _fixture_for_version(tmp_path, version)
    calls = []

    def ready(*args):
        calls.append("readiness")
        return {"session_id": "fixture"}, {}, None, "fixture", []

    def install(*args):
        calls.append("install")

    monkeypatch.setattr(start, "_wait_until_ready", ready)
    monkeypatch.setattr(start, "_install_once", install)
    monkeypatch.setattr(start, "get_value", lambda name: "fixture-python")
    start.main(["--pid", "1", "--manifest", str(directory / "build-manifest.json"),
                "--native-text-codec", "utf8"])
    assert calls == ["readiness", "install"]


def test_start_main_rejects_v59_before_readiness_or_install(tmp_path, monkeypatch):
    manifest, directory = _fixture_for_version(tmp_path, 58)
    manifest["version"] = 59
    _write(manifest, directory)
    calls = []

    def forbidden(*args):
        calls.append("forbidden")
        raise AssertionError("unsupported v59 reached readiness or install")

    monkeypatch.setattr(start, "_wait_until_ready", forbidden)
    monkeypatch.setattr(start, "_install_once", forbidden)
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start.main(["--pid", "1", "--manifest", str(directory / "build-manifest.json"),
                    "--native-text-codec", "utf8"])
    assert calls == []


def test_348_royal_v58_prototype_remains_rejected_by_all_three_entries(tmp_path):
    manifest, directory = _copy_candidate(PROTOTYPE_V58, tmp_path / "prototype")
    assert manifest["version"] == 58
    assert manifest["prototype_only"] is True
    assert manifest["formal_installation_admitted"] is False
    _assert_all_reject(manifest, directory)
