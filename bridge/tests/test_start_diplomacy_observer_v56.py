"""Strict v56 admission inherits v55 and adds the formal mission condition source."""
import hashlib
import json
from pathlib import Path
import shutil

import pytest

from bridge.tests.test_start_diplomacy_observer_v48 import fixture as v48_fixture
from bridge.tests.test_start_diplomacy_observer_v51 import (
    _set_source_hash,
    fixture as v51_fixture,
)
from bridge.tests.test_start_diplomacy_observer_v54 import fixture as v54_fixture
from bridge.tests.test_start_diplomacy_observer_v55 import fixture as v55_fixture
from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start
from work import probe_information_battle_v23 as probe


ROOT = Path(__file__).resolve().parents[2]
FORMAL_V56 = ROOT / "work/runtime/diplomacy-observer-20261109-condition-v56-341-001"
PROTOTYPE_V56 = ROOT / "work/runtime/diplomacy-observer-20261109-condition-v56-340-001"


def fixture(directory):
    manifest, directory = v55_fixture(directory)
    manifest.update(
        version=56,
        experiment_id="synthetic-formal-mission-condition-v56",
        native_mission_condition_observation=True,
        native_mission_condition_wire=1,
        native_mission_condition_scope=start.MISSION_CONDITION_SCOPE,
        prototype_only=False,
        formal_installation_admitted=True,
    )
    manifest["compiler_arguments"].append(
        f"-D{start.MISSION_CONDITION_DEFINE}=1")

    for name in start.MISSION_CONDITION_SOURCES:
        source = FORMAL_V56 / name
        data = source.read_bytes()
        (directory / name).write_bytes(data)
        manifest["sources"].append({
            "name": name,
            "sha256": hashlib.sha256(data).hexdigest(),
        })

    ack_path = directory / start.MACRO_EVENT_ACK_SOURCE
    shutil.copyfile(FORMAL_V56 / start.MACRO_EVENT_ACK_SOURCE, ack_path)
    _set_source_hash(manifest, start.MACRO_EVENT_ACK_SOURCE, ack_path)

    dll = directory / "eu4_bridge_diplomacy_observer_v56.dll"
    dll.write_bytes(b"synthetic formal v56 DLL pin")
    manifest["dll"] = str(dll.resolve())
    manifest["dll_sha256"] = hashlib.sha256(dll.read_bytes()).hexdigest()
    _write_manifest(manifest, directory)
    return manifest, directory


def _write_manifest(manifest, directory):
    (directory / "build-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def _assert_all_reject(manifest, directory):
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)
    with pytest.raises(control.ControlError) as caught:
        control._validate_manifest(manifest, directory)
    assert caught.value.reason == "BUILD_MANIFEST_MISMATCH"
    _write_manifest(manifest, directory)
    assert probe._manifest_static_guard(directory)["status"] != "observed"


def _assert_readonly_candidate_rejects(manifest, directory):
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)
    with pytest.raises(control.ControlError) as caught:
        control._validate_manifest(manifest, directory)
    assert caught.value.reason == "BUILD_MANIFEST_MISMATCH"
    assert probe._manifest_static_guard(directory)["status"] != "observed"


def test_formal_341_candidate_passes_all_three_static_entries(tmp_path, monkeypatch):
    manifest = json.loads((FORMAL_V56 / "build-manifest.json").read_text(encoding="utf-8"))
    assert manifest["version"] == 56
    assert len(manifest["sources"]) == 178
    assert manifest["prototype_only"] is False
    assert manifest["formal_installation_admitted"] is True
    assert manifest["native_mission_condition_observation"] is True
    assert type(manifest["native_mission_condition_wire"]) is int
    assert manifest["native_mission_condition_wire"] == 1
    assert manifest["native_mission_condition_scope"] == start.MISSION_CONDITION_SCOPE
    assert {row["name"] for row in manifest["sources"]
            if row["name"] in start.MISSION_CONDITION_SOURCES} == set(
                start.MISSION_CONDITION_SOURCES)
    assert manifest["compiler_arguments"].count(
        f"-D{start.MISSION_CONDITION_DEFINE}=1") == 1

    ack_text = (FORMAL_V56 / start.MACRO_EVENT_ACK_SOURCE).read_text(encoding="utf-8")
    for block in (
        start.MACRO_EVENT_ACK_SOURCE_BLOCKS[0],
        start.MACRO_SOURCE_RELATION_ACK_BLOCK,
        start.MACRO_SOURCE_MISSION_ACK_BLOCK,
        start.MACRO_SOURCE_AVAILABILITY_ACK_BLOCK,
        start.MISSION_CONDITION_ACK_BLOCK,
        start.MACRO_SOURCE_V55_VERSION_BLOCK,
        start.MISSION_CONDITION_V56_VERSION_BLOCK,
    ):
        assert ack_text.count(block) == 1

    start._validate_information_battle_manifest(manifest, FORMAL_V56)
    control._validate_manifest(manifest, FORMAL_V56)
    assert probe._manifest_static_guard(FORMAL_V56)["status"] == "observed"

    monkeypatch.setattr(
        probe, "_coff_symbol",
        lambda path, symbol=probe.STUB_SYMBOL: {
            "status": "observed", "source": "ordinary_pe_coff",
            "symbol": symbol, "rva": "0x1000",
        })
    report = probe._base_report(
        probe.DEFAULT_INSTALLATION, tmp_path / "probe-static.json", "original")
    result = probe._static_prepare(report, FORMAL_V56)
    assert result["manifest"]["version"] == 56
    assert len(result["manifest"]["sources"]) == 178
    assert report["provenance"]["source"]["status"] == "observed"
    assert report["provenance"]["ordinary_pe_coff"]["status"] == "observed"


@pytest.mark.parametrize("mutation", [
    "capability_missing", "capability_integer", "wire_missing", "wire_bool",
    "wire_string", "scope_missing", "scope_changed", "define_missing",
    "define_wrong_value", "define_duplicate", "define_bare", "source_duplicate",
    "source_tampered", "ack_literal_missing", "ack_literal_tampered",
    "ack_literal_duplicate", "version_override_missing",
    "version_override_tampered", "version_override_duplicate",
    "prototype_missing", "prototype_only", "formal_missing", "formal_false",
    "formal_integer",
])
def test_v56_rejects_incomplete_wrong_or_tampered_condition_contract(tmp_path, mutation):
    manifest, directory = fixture(tmp_path / "candidate")
    if mutation == "capability_missing":
        manifest.pop(start.MISSION_CONDITION_KEYS[0])
    elif mutation == "capability_integer":
        manifest[start.MISSION_CONDITION_KEYS[0]] = 1
    elif mutation == "wire_missing":
        manifest.pop(start.MISSION_CONDITION_KEYS[1])
    elif mutation == "wire_bool":
        manifest[start.MISSION_CONDITION_KEYS[1]] = True
    elif mutation == "wire_string":
        manifest[start.MISSION_CONDITION_KEYS[1]] = "1"
    elif mutation == "scope_missing":
        manifest.pop(start.MISSION_CONDITION_KEYS[2])
    elif mutation == "scope_changed":
        manifest[start.MISSION_CONDITION_KEYS[2]] = "FRA_root_children"
    elif mutation == "define_missing":
        manifest["compiler_arguments"].remove(
            f"-D{start.MISSION_CONDITION_DEFINE}=1")
    elif mutation == "define_wrong_value":
        manifest["compiler_arguments"].remove(
            f"-D{start.MISSION_CONDITION_DEFINE}=1")
        manifest["compiler_arguments"].append(
            f"-D{start.MISSION_CONDITION_DEFINE}=0")
    elif mutation == "define_duplicate":
        manifest["compiler_arguments"].append(
            f"-D{start.MISSION_CONDITION_DEFINE}=1")
    elif mutation == "define_bare":
        manifest["compiler_arguments"].remove(
            f"-D{start.MISSION_CONDITION_DEFINE}=1")
        manifest["compiler_arguments"].append(
            f"-D{start.MISSION_CONDITION_DEFINE}")
    elif mutation == "source_duplicate":
        manifest["sources"].append(next(
            row for row in manifest["sources"]
            if row["name"] == start.MISSION_CONDITION_SOURCES[0]))
    elif mutation == "source_tampered":
        source = directory / start.MISSION_CONDITION_SOURCES[1]
        source.write_bytes(source.read_bytes() + b"\n// tampered\n")
    elif mutation == "ack_literal_missing":
        ack_path = directory / start.MACRO_EVENT_ACK_SOURCE
        text = ack_path.read_text(encoding="utf-8")
        assert start.MISSION_CONDITION_ACK_BLOCK in text
        ack_path.write_text(text.replace(start.MISSION_CONDITION_ACK_BLOCK, ""),
                            encoding="utf-8")
        _set_source_hash(manifest, start.MACRO_EVENT_ACK_SOURCE, ack_path)
    elif mutation == "ack_literal_tampered":
        ack_path = directory / start.MACRO_EVENT_ACK_SOURCE
        text = ack_path.read_text(encoding="utf-8")
        changed = start.MISSION_CONDITION_ACK_BLOCK.replace(
            "FRA_root_conjunction_child_returns", "FRA_root_conjunction_returns")
        assert changed != start.MISSION_CONDITION_ACK_BLOCK
        ack_path.write_text(text.replace(start.MISSION_CONDITION_ACK_BLOCK, changed),
                            encoding="utf-8")
        _set_source_hash(manifest, start.MACRO_EVENT_ACK_SOURCE, ack_path)
    elif mutation == "ack_literal_duplicate":
        ack_path = directory / start.MACRO_EVENT_ACK_SOURCE
        with ack_path.open("a", encoding="utf-8") as stream:
            stream.write("\n" + start.MISSION_CONDITION_ACK_BLOCK + "\n")
        _set_source_hash(manifest, start.MACRO_EVENT_ACK_SOURCE, ack_path)
    elif mutation == "version_override_missing":
        ack_path = directory / start.MACRO_EVENT_ACK_SOURCE
        text = ack_path.read_text(encoding="utf-8")
        assert start.MISSION_CONDITION_V56_VERSION_BLOCK in text
        ack_path.write_text(
            text.replace(start.MISSION_CONDITION_V56_VERSION_BLOCK, ""),
            encoding="utf-8")
        _set_source_hash(manifest, start.MACRO_EVENT_ACK_SOURCE, ack_path)
    elif mutation == "version_override_tampered":
        ack_path = directory / start.MACRO_EVENT_ACK_SOURCE
        text = ack_path.read_text(encoding="utf-8")
        changed = start.MISSION_CONDITION_V56_VERSION_BLOCK.replace(
            "]='6';", "]='5';")
        assert changed != start.MISSION_CONDITION_V56_VERSION_BLOCK
        ack_path.write_text(
            text.replace(start.MISSION_CONDITION_V56_VERSION_BLOCK, changed),
            encoding="utf-8")
        _set_source_hash(manifest, start.MACRO_EVENT_ACK_SOURCE, ack_path)
    elif mutation == "version_override_duplicate":
        ack_path = directory / start.MACRO_EVENT_ACK_SOURCE
        with ack_path.open("a", encoding="utf-8") as stream:
            stream.write("\n" + start.MISSION_CONDITION_V56_VERSION_BLOCK + "\n")
        _set_source_hash(manifest, start.MACRO_EVENT_ACK_SOURCE, ack_path)
    elif mutation == "prototype_missing":
        manifest.pop("prototype_only")
    elif mutation == "prototype_only":
        manifest["prototype_only"] = True
    elif mutation == "formal_missing":
        manifest.pop("formal_installation_admitted")
    elif mutation == "formal_false":
        manifest["formal_installation_admitted"] = False
    elif mutation == "formal_integer":
        manifest["formal_installation_admitted"] = 1
    _assert_all_reject(manifest, directory)


@pytest.mark.parametrize("missing", start.MISSION_CONDITION_SOURCES)
def test_each_v56_condition_source_is_required(tmp_path, missing):
    manifest, directory = fixture(tmp_path / "candidate")
    manifest["sources"] = [row for row in manifest["sources"]
                           if row["name"] != missing]
    _assert_all_reject(manifest, directory)


@pytest.mark.parametrize("version", [49, 50, 52, 53, 57])
def test_v56_rejects_unadmitted_or_unknown_versions(tmp_path, version):
    manifest, directory = fixture(tmp_path / "candidate")
    manifest["version"] = version
    _assert_all_reject(manifest, directory)


@pytest.mark.parametrize("base_version", ["v48", "v51", "v54", "v55"])
@pytest.mark.parametrize("claim", ["key", "define", "source"])
def test_pre56_versions_reject_condition_claims(tmp_path, base_version, claim):
    builders = {
        "v48": v48_fixture,
        "v51": v51_fixture,
        "v54": v54_fixture,
        "v55": v55_fixture,
    }
    manifest, directory = builders[base_version](tmp_path / "candidate")
    if claim == "key":
        manifest[start.MISSION_CONDITION_KEYS[0]] = True
    elif claim == "define":
        manifest["compiler_arguments"].append(
            f"-D{start.MISSION_CONDITION_DEFINE}=1")
    else:
        name = start.MISSION_CONDITION_SOURCES[0]
        data = b"synthetic unadmitted mission-condition source"
        (directory / name).write_bytes(data)
        manifest["sources"].append({
            "name": name, "sha256": hashlib.sha256(data).hexdigest(),
        })
    _assert_all_reject(manifest, directory)


def test_existing_v340_prototype56_remains_rejected_by_all_entries():
    manifest = json.loads((PROTOTYPE_V56 / "build-manifest.json").read_text(encoding="utf-8"))
    assert manifest["version"] == 56
    assert manifest["prototype_only"] is True
    assert manifest["formal_installation_admitted"] is False
    _assert_readonly_candidate_rejects(manifest, PROTOTYPE_V56)
