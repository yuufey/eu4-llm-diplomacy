"""Strict v51 admission binds all macro-event contracts and ACK source literals."""
import hashlib
import json

import pytest

from bridge.tests.test_start_diplomacy_observer_v48 import fixture as v48_fixture
from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start
from work import probe_information_battle_v23 as probe


CONTRACTS = (
    (start.WAR_DECLARATION_KEYS, start.WAR_DECLARATION_SCOPE,
     "BRIDGE_WAR_DECLARATION_OBSERVATION", start.WAR_DECLARATION_SOURCES),
    (start.RELATION_CHANGE_KEYS, start.RELATION_CHANGE_SCOPE,
     "BRIDGE_RELATION_OBSERVATION", start.RELATION_CHANGE_SOURCES),
    (start.MISSION_COMPLETION_KEYS, start.MISSION_COMPLETION_SCOPE,
     "BRIDGE_MISSION_COMPLETION_OBSERVATION", start.MISSION_COMPLETION_SOURCES),
)


def _set_source_hash(manifest, name, path):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    records = [row for row in manifest["sources"] if row["name"] == name]
    assert len(records) == 1
    records[0]["sha256"] = digest


def _write_probe_manifest(manifest, directory):
    (directory / "build-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def fixture(directory):
    manifest, directory = v48_fixture(directory)
    manifest["version"] = 51
    for keys, scope, define, sources in CONTRACTS:
        manifest[keys[0]] = True
        manifest[keys[1]] = 1
        manifest[keys[2]] = scope
        manifest["compiler_arguments"].append(f"-D{define}=1")
        for name in sources:
            data = ("synthetic v51 " + name).encode()
            (directory / name).write_bytes(data)
            manifest["sources"].append({
                "name": name, "sha256": hashlib.sha256(data).hexdigest(),
            })

    ack_name = start.MACRO_EVENT_ACK_SOURCE
    ack_path = directory / ack_name
    ack_path.write_text(
        ack_path.read_text(encoding="utf-8") + "\n"
        + "\n".join(start.MACRO_EVENT_ACK_SOURCE_BLOCKS) + "\n"
        + start.MACRO_EVENT_V51_VERSION_BLOCK + "\n",
        encoding="utf-8")
    _set_source_hash(manifest, ack_name, ack_path)

    manifest.update(
        compiled=True,
        experiment_id="synthetic-macro-events-v51",
        game_sha256=probe.EXPECTED_EXE_SHA256,
    )
    dll = directory / "eu4_bridge_diplomacy_observer_v51.dll"
    dll.write_bytes(b"synthetic v51 DLL pin")
    manifest["dll"] = str(dll.resolve())
    manifest["dll_sha256"] = hashlib.sha256(dll.read_bytes()).hexdigest()
    _write_probe_manifest(manifest, directory)
    return manifest, directory


def _assert_all_reject(manifest, directory):
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)
    with pytest.raises(control.ControlError) as caught:
        control._validate_manifest(manifest, directory)
    assert caught.value.reason == "BUILD_MANIFEST_MISMATCH"
    _write_probe_manifest(manifest, directory)
    result = probe._manifest_static_guard(directory)
    assert result["status"] != "observed"


def test_v51_exact_inherited_contract_passes_all_three_static_entries(
        tmp_path, monkeypatch):
    manifest, directory = fixture(tmp_path / "candidate")
    assert len(manifest["sources"]) == 168
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
    assert result["manifest"]["version"] == 51
    assert len(result["manifest"]["sources"]) == 168
    assert report["provenance"]["source"]["status"] == "observed"
    assert report["provenance"]["ordinary_pe_coff"]["status"] == "observed"


@pytest.mark.parametrize("mutation", [
    "duplicate_define", "bare_define", "source_missing", "scope_changed",
    "bool_wire", "flag_integer", "ack_version_literal_changed",
])
def test_v51_rejects_incomplete_or_malformed_macro_event_contract(tmp_path, mutation):
    manifest, directory = fixture(tmp_path / "candidate")
    if mutation == "duplicate_define":
        manifest["compiler_arguments"].append(
            "-DBRIDGE_MISSION_COMPLETION_OBSERVATION=1")
    elif mutation == "bare_define":
        manifest["compiler_arguments"].remove(
            "-DBRIDGE_RELATION_OBSERVATION=1")
        manifest["compiler_arguments"].append("-DBRIDGE_RELATION_OBSERVATION")
    elif mutation == "source_missing":
        missing = start.MISSION_COMPLETION_SOURCES[0]
        manifest["sources"] = [row for row in manifest["sources"]
                               if row["name"] != missing]
    elif mutation == "scope_changed":
        manifest[start.WAR_DECLARATION_KEYS[2]] = "FRA_only"
    elif mutation == "bool_wire":
        manifest[start.RELATION_CHANGE_KEYS[1]] = True
    elif mutation == "flag_integer":
        manifest[start.WAR_DECLARATION_KEYS[0]] = 1
    elif mutation == "ack_version_literal_changed":
        ack_name = start.MACRO_EVENT_ACK_SOURCE
        ack_path = directory / ack_name
        ack_text = ack_path.read_text(encoding="utf-8")
        assert start.MACRO_EVENT_V51_VERSION_BLOCK in ack_text
        changed_version_block = start.MACRO_EVENT_V51_VERSION_BLOCK.replace(
            "='1';", "='2';")
        ack_path.write_text(
            ack_text.replace(start.MACRO_EVENT_V51_VERSION_BLOCK,
                             changed_version_block),
            encoding="utf-8")
        _set_source_hash(manifest, ack_name, ack_path)
    _assert_all_reject(manifest, directory)


@pytest.mark.parametrize("keys", [contract[0] for contract in CONTRACTS])
def test_v51_requires_each_native_macro_event_capability(tmp_path, keys):
    manifest, directory = fixture(tmp_path / "candidate")
    manifest.pop(keys[0])
    _assert_all_reject(manifest, directory)


@pytest.mark.parametrize("version", [49, 50, 52])
def test_v49_v50_and_future_v52_are_not_admitted(tmp_path, version):
    manifest, directory = fixture(tmp_path / "candidate")
    manifest["version"] = version
    _assert_all_reject(manifest, directory)


@pytest.mark.parametrize("key,value", [
    ("deployment_admission_verified", False), ("prototype_only", True),
])
def test_v51_explicit_prototype_markers_are_rejected(tmp_path, key, value):
    manifest, directory = fixture(tmp_path / "prototype")
    manifest[key] = value
    _assert_all_reject(manifest, directory)


@pytest.mark.parametrize("key", (
    start.WAR_DECLARATION_KEYS + start.RELATION_CHANGE_KEYS
    + start.MISSION_COMPLETION_KEYS
))
def test_v48_rejects_each_new_macro_event_field(tmp_path, key):
    manifest, directory = v48_fixture(tmp_path / "candidate")
    manifest[key] = True
    _assert_all_reject(manifest, directory)


@pytest.mark.parametrize("claim", ["define", "source"])
def test_v48_rejects_new_macro_event_build_claims(tmp_path, claim):
    manifest, directory = v48_fixture(tmp_path / "candidate")
    if claim == "define":
        manifest["compiler_arguments"].append(
            "-DBRIDGE_MISSION_COMPLETION_OBSERVATION=1")
    else:
        name = start.WAR_DECLARATION_SOURCES[0]
        data = b"synthetic unadmitted war source"
        path = directory / name
        path.write_bytes(data)
        manifest["sources"].append({
            "name": name, "sha256": hashlib.sha256(data).hexdigest(),
        })
    _assert_all_reject(manifest, directory)


@pytest.mark.parametrize("mutation", ["valid", "missing_record", "changed_header", "unused_header"])
def test_war_registry_header_is_bound_to_the_actual_native_include(tmp_path, mutation):
    manifest, directory = fixture(tmp_path / "candidate")
    name = start.WAR_REGISTRY_SOURCE
    path = directory / name
    path.write_bytes(b"synthetic registry lifetime source")
    manifest["sources"].append({"name": name, "sha256": start.file_hash(path, refresh=True)})
    context = directory / "peace-context-query.inc"
    if mutation != "unused_header":
        context.write_text(context.read_text(encoding="utf-8") + f'\n#include "{name}"\n',
                           encoding="utf-8")
        _set_source_hash(manifest, context.name, context)
    if mutation == "missing_record":
        manifest["sources"] = [row for row in manifest["sources"] if row["name"] != name]
    elif mutation == "changed_header":
        path.write_bytes(b"changed registry lifetime source")
    if mutation == "valid":
        start._validate_information_battle_manifest(manifest, directory)
        control._validate_manifest(manifest, directory)
    else:
        _assert_all_reject(manifest, directory)
