"""Strict v55 admission retains the v54 schema with an exact version ACK."""
import hashlib
import json

import pytest

from bridge.tests.test_start_diplomacy_observer_v51 import _set_source_hash
from bridge.tests.test_start_diplomacy_observer_v54 import fixture as v54_fixture
from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start
from work import probe_information_battle_v23 as probe


def fixture(directory):
    manifest, directory = v54_fixture(directory)
    manifest.update(
        version=55,
        experiment_id="synthetic-macro-sources-v55",
    )
    ack_path = directory / start.MACRO_EVENT_ACK_SOURCE
    ack_text = ack_path.read_text(encoding="utf-8")
    assert ack_text.count(start.MACRO_SOURCE_V54_VERSION_BLOCK) == 1
    ack_text = ack_text.replace(
        start.MACRO_SOURCE_V54_VERSION_BLOCK,
        start.MACRO_SOURCE_V55_VERSION_BLOCK,
    )
    ack_path.write_text(ack_text, encoding="utf-8")
    _set_source_hash(manifest, start.MACRO_EVENT_ACK_SOURCE, ack_path)

    dll = directory / "eu4_bridge_diplomacy_observer_v55.dll"
    dll.write_bytes(b"synthetic v55 DLL pin")
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


def test_v55_exact_v54_contract_passes_all_static_entries(tmp_path, monkeypatch):
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
    assert result["manifest"]["version"] == 55
    assert len(result["manifest"]["sources"]) == 175
    assert report["provenance"]["source"]["status"] == "observed"
    assert report["provenance"]["ordinary_pe_coff"]["status"] == "observed"


@pytest.mark.parametrize("mutation", [
    "version_ack_changed", "prototype_only", "deployment_not_verified",
])
def test_v55_rejects_wrong_ack_or_prototype_markers(tmp_path, mutation):
    manifest, directory = fixture(tmp_path / "candidate")
    if mutation == "version_ack_changed":
        ack_path = directory / start.MACRO_EVENT_ACK_SOURCE
        ack_text = ack_path.read_text(encoding="utf-8")
        changed = start.MACRO_SOURCE_V55_VERSION_BLOCK.replace(
            "version_marker[sizeof(\"\\\"version\\\":\")]='5';",
            "version_marker[sizeof(\"\\\"version\\\":\")]='4';",
        )
        assert changed != start.MACRO_SOURCE_V55_VERSION_BLOCK
        ack_path.write_text(
            ack_text.replace(start.MACRO_SOURCE_V55_VERSION_BLOCK, changed),
            encoding="utf-8")
        _set_source_hash(manifest, start.MACRO_EVENT_ACK_SOURCE, ack_path)
    elif mutation == "prototype_only":
        manifest["prototype_only"] = True
    elif mutation == "deployment_not_verified":
        manifest["deployment_admission_verified"] = False
    _assert_all_reject(manifest, directory)


@pytest.mark.parametrize("version", [49, 50, 52, 53, 56])
def test_v55_rejects_unadmitted_versions(tmp_path, version):
    manifest, directory = fixture(tmp_path / "candidate")
    manifest["version"] = version
    _assert_all_reject(manifest, directory)
