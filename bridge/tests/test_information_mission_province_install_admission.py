import copy
import hashlib
import json
from pathlib import Path
import shutil

import pytest

from bridge.tests.test_start_diplomacy_observer_v51 import _set_source_hash
from bridge.tests.test_start_diplomacy_observer_v55 import fixture as v55_fixture
from bridge.tests.test_start_diplomacy_observer_v56 import (
    _write_manifest,
    fixture as v56_fixture,
)
from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start
from work import probe_information_battle_v23 as probe


ROOT = Path(__file__).resolve().parents[2]
FORMAL_V57 = ROOT / "work/runtime/diplomacy-observer-20261109-province-v57-346-001"
PROTOTYPE_V57 = ROOT / "work/runtime/diplomacy-observer-20261109-province-v57-345-002"
MACRO_CPP = start.MACRO_EVENT_ACK_SOURCE


def _write(manifest, directory):
    (directory / "build-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def _copy_v57(tmp_path):
    directory = tmp_path / "candidate"
    directory.mkdir(parents=True)
    manifest = json.loads((FORMAL_V57 / "build-manifest.json").read_text(encoding="utf-8"))
    names = [record["name"] for record in manifest["sources"]]
    names.append(Path(manifest["dll"]).name)
    for name in names:
        shutil.copyfile(FORMAL_V57 / name, directory / name)
    manifest["dll"] = str((directory / Path(manifest["dll"]).name).resolve())
    _write(manifest, directory)
    return manifest, directory


@pytest.mark.parametrize("version", [56, 57])
def test_installer_main_reaches_the_readiness_and_install_seams_for_formal_builds(tmp_path, monkeypatch, version):
    _, directory = _copy_v57(tmp_path) if version == 57 else v56_fixture(tmp_path / "candidate")
    calls = []

    def ready(*args):
        calls.append("ready")
        return {"session_id": "fixture"}, {}, None, "fixture", []

    def install(*args):
        calls.append("install")

    monkeypatch.setattr(start, "_wait_until_ready", ready)
    monkeypatch.setattr(start, "_install_once", install)
    monkeypatch.setattr(start, "get_value", lambda name: "fixture-python")
    start.main(["--pid", "1", "--manifest", str(directory / "build-manifest.json"),
                "--native-text-codec", "utf8"])
    assert calls == ["ready", "install"]


def test_installer_main_rejects_future_version_before_readiness(tmp_path, monkeypatch):
    manifest, directory = _copy_v57(tmp_path)
    manifest["version"] = 58
    _write(manifest, directory)

    def forbidden(*args):
        raise AssertionError("readiness reached for a future build")

    monkeypatch.setattr(start, "_wait_until_ready", forbidden)
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start.main(["--pid", "1", "--manifest", str(directory / "build-manifest.json"),
                    "--native-text-codec", "utf8"])


def _copy_v56_with_current_cpp(tmp_path):
    manifest, directory = v56_fixture(tmp_path / "candidate")
    source = FORMAL_V57 / MACRO_CPP
    target = directory / MACRO_CPP
    shutil.copyfile(source, target)
    _set_source_hash(manifest, MACRO_CPP, target)
    _write_manifest(manifest, directory)
    return manifest, directory


def _assert_all_reject(manifest, directory):
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)
    with pytest.raises(control.ControlError) as caught:
        control._validate_manifest(manifest, directory)
    assert caught.value.reason == "BUILD_MANIFEST_MISMATCH"
    _write(manifest, directory)
    assert probe._manifest_static_guard(directory)["status"] != "observed"


def _assert_readonly_candidate_rejects(manifest, directory):
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)
    with pytest.raises(control.ControlError) as caught:
        control._validate_manifest(manifest, directory)
    assert caught.value.reason == "BUILD_MANIFEST_MISMATCH"
    assert probe._manifest_static_guard(directory)["status"] != "observed"


def test_formal_v57_candidate_passes_all_three_static_admission_entries():
    manifest = json.loads((FORMAL_V57 / "build-manifest.json").read_text(encoding="utf-8"))
    assert manifest["version"] == 57
    assert len(manifest["sources"]) == 181
    assert manifest["prototype_only"] is False
    assert manifest["formal_installation_admitted"] is True
    assert manifest["native_mission_condition_observation"] is True
    assert type(manifest["native_mission_condition_wire"]) is int
    assert manifest["native_mission_condition_wire"] == 2
    assert manifest["native_mission_condition_scope"] == start.MISSION_PROVINCE_CONDITION_SCOPE
    assert manifest[start.MISSION_PROVINCE_CONDITION_CAPABILITY] is True
    names = {row["name"] for row in manifest["sources"]}
    assert set(start.MISSION_CONDITION_SOURCES) <= names
    assert set(start.MISSION_PROVINCE_CONDITION_SOURCES) <= names
    arguments = manifest["compiler_arguments"]
    assert arguments.count(f"-D{start.MISSION_CONDITION_DEFINE}=1") == 1
    assert arguments.count(f"-D{start.MISSION_PROVINCE_CONDITION_DEFINE}=1") == 1

    ack_text = (FORMAL_V57 / MACRO_CPP).read_text(encoding="utf-8")
    assert ack_text.count(start.MISSION_PROVINCE_CONDITION_ACK_BLOCK) == 1
    assert ack_text.count(start.MISSION_CONDITION_ACK_BLOCK) == 0
    assert ack_text.count(start.MISSION_CONDITION_V56_VERSION_BLOCK) == 1
    assert ack_text.count(start.MISSION_PROVINCE_CONDITION_V57_VERSION_BLOCK) == 1

    start._validate_information_battle_manifest(manifest, FORMAL_V57)
    control._validate_manifest(manifest, FORMAL_V57)
    result = probe._manifest_static_guard(FORMAL_V57)
    assert result["status"] == "observed"
    assert result["source_count"] == 181
    assert result["observer_version"] == 57


@pytest.mark.parametrize("mutation", [
    "source_missing_0", "source_missing_1", "source_missing_2",
    "source_tampered_0", "source_tampered_1", "source_tampered_2",
    "source_duplicate", "condition_wire_bool", "condition_wire_1",
    "condition_scope", "condition_cap_false", "province_cap_missing",
    "province_cap_integer", "root_define_wrong", "root_define_duplicate",
    "province_define_missing", "province_define_wrong",
    "province_define_duplicate", "province_define_bare",
    "nested_ack_missing", "nested_ack_tampered", "nested_ack_duplicate",
    "version57_marker_missing", "version57_marker_tampered",
    "version57_marker_duplicate", "version56_marker_missing",
    "prototype_true", "prototype_missing", "formal_false", "formal_integer",
])
def test_formal_v57_rejects_tampered_sources_and_contract_literals(tmp_path, mutation):
    manifest, directory = _copy_v57(tmp_path)

    if mutation.startswith("source_missing_"):
        index = int(mutation.rsplit("_", 1)[1])
        name = start.MISSION_PROVINCE_CONDITION_SOURCES[index]
        manifest["sources"] = [row for row in manifest["sources"] if row["name"] != name]
    elif mutation.startswith("source_tampered_"):
        index = int(mutation.rsplit("_", 1)[1])
        path = directory / start.MISSION_PROVINCE_CONDITION_SOURCES[index]
        path.write_bytes(path.read_bytes() + b"\n// tampered\n")
    elif mutation == "source_duplicate":
        name = start.MISSION_PROVINCE_CONDITION_SOURCES[0]
        manifest["sources"].append(copy.deepcopy(
            next(row for row in manifest["sources"] if row["name"] == name)))
    elif mutation == "condition_wire_bool":
        manifest["native_mission_condition_wire"] = True
    elif mutation == "condition_wire_1":
        manifest["native_mission_condition_wire"] = 1
    elif mutation == "condition_scope":
        manifest["native_mission_condition_scope"] = "FRA_root_conjunction_child_returns"
    elif mutation == "condition_cap_false":
        manifest["native_mission_condition_observation"] = False
    elif mutation == "province_cap_missing":
        manifest.pop(start.MISSION_PROVINCE_CONDITION_CAPABILITY)
    elif mutation == "province_cap_integer":
        manifest[start.MISSION_PROVINCE_CONDITION_CAPABILITY] = 1
    elif mutation == "root_define_wrong":
        manifest["compiler_arguments"].remove(f"-D{start.MISSION_CONDITION_DEFINE}=1")
        manifest["compiler_arguments"].append(f"-D{start.MISSION_CONDITION_DEFINE}=0")
    elif mutation == "root_define_duplicate":
        manifest["compiler_arguments"].append(f"-D{start.MISSION_CONDITION_DEFINE}=1")
    elif mutation == "province_define_missing":
        manifest["compiler_arguments"].remove(
            f"-D{start.MISSION_PROVINCE_CONDITION_DEFINE}=1")
    elif mutation == "province_define_wrong":
        manifest["compiler_arguments"].remove(
            f"-D{start.MISSION_PROVINCE_CONDITION_DEFINE}=1")
        manifest["compiler_arguments"].append(
            f"-D{start.MISSION_PROVINCE_CONDITION_DEFINE}=0")
    elif mutation == "province_define_duplicate":
        manifest["compiler_arguments"].append(
            f"-D{start.MISSION_PROVINCE_CONDITION_DEFINE}=1")
    elif mutation == "province_define_bare":
        manifest["compiler_arguments"].remove(
            f"-D{start.MISSION_PROVINCE_CONDITION_DEFINE}=1")
        manifest["compiler_arguments"].append(
            f"-D{start.MISSION_PROVINCE_CONDITION_DEFINE}")
    elif mutation.startswith("nested_ack_"):
        path = directory / MACRO_CPP
        text = path.read_text(encoding="utf-8")
        block = start.MISSION_PROVINCE_CONDITION_ACK_BLOCK
        assert text.count(block) == 1
        if mutation == "nested_ack_missing":
            text = text.replace(block, "")
        elif mutation == "nested_ack_tampered":
            changed = block.replace(
                "FRA_root_and_direct_area_province_holding_returns",
                "FRA_root_area_province_holding_returns")
            text = text.replace(block, changed)
        else:
            text += "\n" + block + "\n"
        path.write_text(text, encoding="utf-8")
        _set_source_hash(manifest, MACRO_CPP, path)
    elif mutation.startswith("version57_marker_"):
        path = directory / MACRO_CPP
        text = path.read_text(encoding="utf-8")
        block = start.MISSION_PROVINCE_CONDITION_V57_VERSION_BLOCK
        assert text.count(block) == 1
        if mutation == "version57_marker_missing":
            text = text.replace(block, "")
        elif mutation == "version57_marker_tampered":
            text = text.replace(block, block.replace("]='7';", "]='8';"))
        else:
            text += "\n" + block + "\n"
        path.write_text(text, encoding="utf-8")
        _set_source_hash(manifest, MACRO_CPP, path)
    elif mutation == "version56_marker_missing":
        path = directory / MACRO_CPP
        text = path.read_text(encoding="utf-8")
        block = start.MISSION_CONDITION_V56_VERSION_BLOCK
        assert text.count(block) == 1
        path.write_text(text.replace(block, ""), encoding="utf-8")
        _set_source_hash(manifest, MACRO_CPP, path)
    elif mutation == "prototype_true":
        manifest["prototype_only"] = True
    elif mutation == "prototype_missing":
        manifest.pop("prototype_only")
    elif mutation == "formal_false":
        manifest["formal_installation_admitted"] = False
    elif mutation == "formal_integer":
        manifest["formal_installation_admitted"] = 1

    _assert_all_reject(manifest, directory)


def test_formal_v57_rejects_unknown_future_version(tmp_path):
    manifest, directory = _copy_v57(tmp_path)
    manifest["version"] = 58
    _assert_all_reject(manifest, directory)


def test_actual_v345_prototype_v57_remains_rejected_by_all_three_entries():
    manifest = json.loads((PROTOTYPE_V57 / "build-manifest.json").read_text(encoding="utf-8"))
    assert manifest["version"] == 57
    assert manifest["prototype_only"] is True
    assert manifest["formal_installation_admitted"] is False
    _assert_readonly_candidate_rejects(manifest, PROTOTYPE_V57)


def test_formal_v56_accepts_current_conditional_cpp_without_province_enablement(tmp_path):
    manifest, directory = _copy_v56_with_current_cpp(tmp_path)
    assert manifest["version"] == 56
    assert start.MISSION_PROVINCE_CONDITION_CAPABILITY not in manifest
    assert not any(start.MISSION_PROVINCE_CONDITION_DEFINE in item
                   for item in manifest["compiler_arguments"])
    assert not any(row["name"] in start.MISSION_PROVINCE_CONDITION_SOURCES
                   for row in manifest["sources"])
    start._validate_information_battle_manifest(manifest, directory)
    control._validate_manifest(manifest, directory)
    assert probe._manifest_static_guard(directory)["status"] == "observed"


@pytest.mark.parametrize("claim", ["capability", "define", "source", "wire", "tampered_marker"])
def test_v56_rejects_province_claims_and_unbound_57_marker(tmp_path, claim):
    manifest, directory = _copy_v56_with_current_cpp(tmp_path)
    if claim == "capability":
        manifest[start.MISSION_PROVINCE_CONDITION_CAPABILITY] = True
    elif claim == "define":
        manifest["compiler_arguments"].append(
            f"-D{start.MISSION_PROVINCE_CONDITION_DEFINE}=1")
    elif claim == "source":
        name = start.MISSION_PROVINCE_CONDITION_SOURCES[0]
        source = FORMAL_V57 / name
        target = directory / name
        shutil.copyfile(source, target)
        manifest["sources"].append({
            "name": name, "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        })
    elif claim == "wire":
        manifest["native_mission_condition_wire"] = 2
        manifest["native_mission_condition_scope"] = start.MISSION_PROVINCE_CONDITION_SCOPE
    else:
        path = directory / MACRO_CPP
        text = path.read_text(encoding="utf-8")
        block = start.MISSION_PROVINCE_CONDITION_V57_VERSION_BLOCK
        path.write_text(text.replace(block, block.replace("]='7';", "]='8';")),
                        encoding="utf-8")
        _set_source_hash(manifest, MACRO_CPP, path)
    _assert_all_reject(manifest, directory)


@pytest.mark.parametrize("base_fixture", [v55_fixture, v56_fixture])
def test_old_formal_versions_allow_the_exact_inactive_province_cpp_blocks(tmp_path, base_fixture):
    manifest, directory = base_fixture(tmp_path / "candidate")
    path = directory / MACRO_CPP
    shutil.copyfile(FORMAL_V57 / MACRO_CPP, path)
    _set_source_hash(manifest, MACRO_CPP, path)
    _write_manifest(manifest, directory)
    start._validate_information_battle_manifest(manifest, directory)
    control._validate_manifest(manifest, directory)
    assert probe._manifest_static_guard(directory)["status"] == "observed"


@pytest.mark.parametrize("version", [49, 50, 52, 53])
def test_v57_entrypoints_reject_unadmitted_versions(tmp_path, version):
    manifest, directory = _copy_v57(tmp_path)
    manifest["version"] = version
    _assert_all_reject(manifest, directory)
