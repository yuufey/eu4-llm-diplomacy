"""Explicit v7 profile tests; v6/v33 remains a separate immutable contract."""
from __future__ import annotations

import hashlib
import json

import pytest

from bridge.information import foreign_economy_capture as capture_v6
from bridge.information import foreign_economy_capture_v7 as capture_v7
from bridge.information import native_ai_choice_mapping_memory as choice_v33
from bridge.information import native_ai_choice_mapping_memory_v34 as choice_v34
from bridge.information import target_debt_principal_memory_v34 as principal_v34


def test_v7_profile_uses_only_explicit_v34_mapping_and_preserves_v6_guards():
    v6 = capture_v6._load_profile()
    v7 = capture_v7._load_profile()

    assert v6["profile_version"] == 6
    assert capture_v6.PROFILE_SHA256 == (
        "3fbb65eadc9301765896bdde35d84e19f9e93e4b28f54a9820b30d5c2f213626")
    assert v7["profile_version"] == 7
    assert v7["base_profile"]["sha256"] == capture_v6.PROFILE_SHA256
    assert capture_v7.PROFILE_SHA256 == hashlib.sha256(
        capture_v7.PROFILE_FILE.read_bytes()).hexdigest()
    assert capture_v7.SCHEMA == capture_v6.SCHEMA
    assert v7["public_fields"] == v6["public_fields"]
    assert v7["code_guards"] == v6["code_guards"]
    assert v7["data_guards"] == v6["data_guards"]

    dep_paths = {row["path"] for row in v7["layout_dependencies"]}
    assert "bridge/information/target_debt_principal_memory_v34.py" in dep_paths
    assert "bridge/information/native_ai_choice_mapping_memory_v34.py" in dep_paths
    assert "bridge/information/profiles/native-ai-choice-hook-v34.json" in dep_paths
    assert "bridge/information/target_debt_principal_memory.py" not in dep_paths
    assert "bridge/information/native_ai_choice_mapping_memory.py" not in dep_paths
    assert "bridge/information/profiles/native-ai-choice-hook-v33.json" not in dep_paths

    assert choice_v33.HOOK_POINTER_DELTA == 0x56850
    assert choice_v33.ASSET_RELATIVE_PATH == "profiles/native-ai-choice-hook-v33.json"
    assert choice_v34.HOOK_POINTER_DELTA == 0x59690
    assert choice_v34.ASSET_RELATIVE_PATH == "profiles/native-ai-choice-hook-v34.json"
    assert choice_v34.SCHEMA == "information.native_ai_choice_mapping_memory.v2"
    assert principal_v34._choice is choice_v34
    scope = v7["target_debt_principal"]["native_ai_accept_scope"]
    assert scope["mapping_helper_schema"] == choice_v34.SCHEMA
    assert scope["hook_asset_sha256"] == choice_v34.ASSET_SHA256
    assert "installed_v34_gui_forwarding_subset" in scope
    assert "installed_v33_gui_forwarding_subset" not in scope


def test_v7_profile_does_not_claim_loaded_dll_or_runtime_installation_proof():
    profile = capture_v7._load_profile()
    assert profile["v34_compatibility"]["dll_runtime_verified"] is False
    assert profile["v34_compatibility"]["installed_choice_hook"][
        "runtime_reader_checks_whole_loaded_dll_hash"] is False
    assert profile["v34_compatibility"]["installed_choice_hook"][
        "rva"] == "0x59690"
    assert profile["target_debt_principal"]["native_ai_accept_scope"][
        "actual_UI_rendering_observed"] is False


def test_python_analysis_reference_keeps_fixed_dependency_pin(tmp_path, monkeypatch):
    profile = json.loads(capture_v7.PROFILE_FILE.read_text(encoding="utf-8"))
    source = tmp_path / "reader.py"
    source.write_text("current implementation\n", encoding="utf-8")
    evidence = tmp_path / "native-proof.json"
    raw = b'{"native_layout":1}'
    evidence.write_bytes(raw)
    profile["source_evidence"] = [{"path": source.name, "sha256": "0" * 64, "bytes": 1}]
    profile["layout_dependencies"] = [{"path": evidence.name,
        "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}]
    profile_path = tmp_path / "profile.json"
    profile_raw = json.dumps(profile).encode("utf-8")
    profile_path.write_bytes(profile_raw)
    monkeypatch.setattr(capture_v7, "ROOT", tmp_path)
    monkeypatch.setattr(capture_v7, "PROFILE_FILE", profile_path)
    monkeypatch.setattr(capture_v7, "PROFILE_SHA256", hashlib.sha256(profile_raw).hexdigest())

    assert capture_v7._load_profile() == profile
    evidence.write_bytes(raw.replace(b"1", b"2"))
    with pytest.raises(ValueError, match="FOREIGN_ECONOMY_PROFILE_DEPENDENCY"):
        capture_v7._load_profile()
