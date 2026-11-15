"""Narrow tests for strict v34 manifest reuse in the read-only probe."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path

import pytest
from tools import start_diplomacy_observer as start


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "probe_information_battle_v34_manifest_compat",
    ROOT / "work" / "probe_information_battle_v23.py",
)
assert SPEC and SPEC.loader
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def _v34_build(tmp_path: Path) -> tuple[Path, Path, dict]:
    build_dir = tmp_path / "diplomacy-observer-v34-fixture"
    build_dir.mkdir()
    dll_path = build_dir / "eu4_bridge_diplomacy_observer_v34.dll"
    dll_bytes = b"synthetic-v34-dll-for-static-identity-test"
    dll_path.write_bytes(dll_bytes)
    manifest = {
        "version": 34,
        "experiment_id": build_dir.name,
        "compiled": True,
        "information_battle_research_lifecycle": True,
        "game_sha256": probe.EXPECTED_EXE_SHA256,
        "dll_sha256": hashlib.sha256(dll_bytes).hexdigest(),
        "dll": str(dll_path.resolve()),
        "sources": [{"name": "synthetic-source.h", "sha256": "a" * 64}],
    }
    (build_dir / "build-manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    return build_dir, dll_path, manifest


@pytest.mark.parametrize("shared_file", [True, False], ids=["hardlink", "separate-copy"])
def test_reused_manifest_accepts_dll_file_identity(tmp_path, monkeypatch, shared_file):
    build_dir, dll_path, manifest = _v34_build(tmp_path)
    original = tmp_path / "original.dll"
    dll_path.rename(original)
    if shared_file:
        os.link(original, dll_path)
    else:
        dll_path.write_bytes(original.read_bytes())
    manifest["dll"] = str(original.resolve())
    (build_dir / "build-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(probe, "_validate_installer_battle_manifest", lambda *_args: None)

    result = probe._manifest_static_guard(build_dir)

    assert result["checks"]["dll_file_sha256"] is True
    assert result["checks"]["dll_path"] is shared_file
    assert result["status"] == ("observed" if shared_file else "unknown")


def _v36_build(tmp_path: Path) -> tuple[Path, Path, dict]:
    build_dir = tmp_path / "diplomacy-observer-v36-fixture"
    build_dir.mkdir()
    dll_path = build_dir / "eu4_bridge_diplomacy_observer_v36.dll"
    dll_bytes = b"synthetic-v36-dll-for-static-identity-test"
    dll_path.write_bytes(dll_bytes)

    names = (set(start.INFORMATION_BATTLE_V33_SOURCE_NAMES)
             | set(start.INFORMATION_DEBT_QUOTE_REQUIRED_SOURCES)
             | set(start.INFORMATION_BATTLE_END_STATE_SOURCES)
             | set(start.INFORMATION_BATTLE_END_STATE_HEADER_DEPENDENCIES))
    records = []
    for name in sorted(names):
        source = build_dir / name
        data = ("owned-v36:" + name).encode("ascii")
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
    ]
    manifest = {
        "version": 36,
        "experiment_id": build_dir.name,
        "compiled": True,
        "game_sha256": probe.EXPECTED_EXE_SHA256,
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
        "compiler_arguments": arguments,
        "sources": records,
    }
    (build_dir / "build-manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    return build_dir, dll_path, manifest


def test_v34_manifest_guard_delegates_to_installer_and_binds_dll_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build_dir, dll_path, manifest = _v34_build(tmp_path)
    calls: list[tuple[dict, Path]] = []

    def strict_installer_validator(value: dict, directory: Path) -> None:
        calls.append((value, directory))
        assert value["version"] == 34
        assert value["sources"] == manifest["sources"]

    monkeypatch.setattr(probe, "_validate_installer_battle_manifest", strict_installer_validator)
    result = probe._manifest_static_guard(build_dir)

    assert result["status"] == "observed"
    assert result["observer_version"] == 34
    assert result["source"] == "tools.start_diplomacy_observer._validate_information_battle_manifest"
    assert result["dll_path"] == str(dll_path.resolve())
    assert result["dll_sha256"] == manifest["dll_sha256"]
    assert result["checks"]["dll_file_sha256"] is True
    assert len(calls) == 1 and calls[0][1] == build_dir


def test_v34_manifest_guard_keeps_installer_rejection_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build_dir, _, _ = _v34_build(tmp_path)

    def reject_manifest(_: dict, __: Path) -> None:
        raise SystemExit("BUILD_MANIFEST_MISMATCH")

    monkeypatch.setattr(probe, "_validate_installer_battle_manifest", reject_manifest)
    result = probe._manifest_static_guard(build_dir)

    assert result["status"] == "unknown"
    assert result["unknown_conditions"] == [
        "installer_manifest_validation_failed:BUILD_MANIFEST_MISMATCH"
    ]


def test_v34_manifest_guard_rejects_dll_bytes_changed_after_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build_dir, dll_path, _ = _v34_build(tmp_path)
    monkeypatch.setattr(probe, "_validate_installer_battle_manifest", lambda *_: None)
    dll_path.write_bytes(b"changed after the manifest was pinned")

    result = probe._manifest_static_guard(build_dir)

    assert result["status"] == "unknown"
    assert result["checks"]["dll_file_sha256"] is False
    assert "dll_file_sha256" in result["unknown_conditions"][-1]


def test_static_prepare_selects_versioned_v34_dll_not_v23_constant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build_dir, dll_path, manifest = _v34_build(tmp_path)
    monkeypatch.setattr(probe, "_validate_installer_battle_manifest", lambda *_: None)

    def coff(path: Path) -> dict:
        assert path == dll_path
        return {"status": "observed", "rva": "0x1040", "source": "ordinary_pe_coff"}

    monkeypatch.setattr(probe, "_coff_symbol", coff)
    report = {"target_build": {}, "provenance": {}, "stub": {}}
    build = probe._static_prepare(report, build_dir)

    assert build["dll_path"] == dll_path
    assert build["dll_sha256"] == manifest["dll_sha256"]
    assert report["target_build"]["observer_version"] == 34
    assert report["target_build"]["dll_path"].endswith("eu4_bridge_diplomacy_observer_v34.dll")
    assert report["stub"]["rva"] == "0x1040"


def test_v36_manifest_guard_uses_strict_installer_contract_without_name_hook(
    tmp_path: Path,
) -> None:
    build_dir, dll_path, manifest = _v36_build(tmp_path)

    assert "information_battle_name_handoff" not in manifest
    assert not any("INFORMATION_BATTLE_NAME_HANDOFF" in arg
                   for arg in manifest["compiler_arguments"])
    result = probe._manifest_static_guard(build_dir)

    assert result["status"] == "observed"
    assert result["observer_version"] == 36
    assert result["source"] == "tools.start_diplomacy_observer._validate_information_battle_manifest"
    assert result["dll_path"] == str(dll_path.resolve())
    assert result["dll_sha256"] == manifest["dll_sha256"]
    assert result["checks"]["dll_file_sha256"] is True


def test_static_prepare_selects_v36_dll_and_end_state_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build_dir, dll_path, manifest = _v36_build(tmp_path)

    def coff(path: Path) -> dict:
        assert path == dll_path
        return {"status": "observed", "rva": "0x1040", "source": "ordinary_pe_coff"}

    monkeypatch.setattr(probe, "_coff_symbol", coff)
    report = {"target_build": {}, "provenance": {}, "stub": {}}
    build = probe._static_prepare(report, build_dir)

    assert build["dll_path"] == dll_path
    assert build["dll_sha256"] == manifest["dll_sha256"]
    assert report["target_build"]["observer_version"] == 36
    assert report["target_build"]["dll_path"].endswith("eu4_bridge_diplomacy_observer_v36.dll")
    assert report["stub"]["rva"] == "0x1040"


def test_installation_binding_requires_manifest_experiment_and_hashes() -> None:
    build = {
        "manifest": {
            "experiment_id": "recovery-v34",
            "game_sha256": probe.EXPECTED_EXE_SHA256,
        },
        "dll_sha256": "f" * 64,
    }
    installation = {
        "experiment_id": "recovery-v34",
        "game_sha256": probe.EXPECTED_EXE_SHA256,
        "dll_sha256": "f" * 64,
    }

    probe._assert_installation_build_binding(installation, build)
    with pytest.raises(probe.V23ProbeError, match="installation_build_identity_mismatch"):
        probe._assert_installation_build_binding({**installation, "dll_sha256": "0" * 64}, build)
    with pytest.raises(probe.V23ProbeError, match="installation_build_identity_mismatch"):
        probe._assert_installation_build_binding({**installation, "experiment_id": "other"}, build)
