"""New v61 shared-entry M02 asset identity and proof contract."""
import hashlib
import json
import struct
from pathlib import Path

import pytest

from bridge.information import mission_observer_guard as guard
from bridge.information import mission_prerequisite_memory as prerequisite
from bridge.information import mission_prerequisite_profile as prerequisite_profile
from bridge.information import mission_trigger_profile as trigger_profile
from bridge.tests.test_information_mission_observer_guard import FakeReader

NEW_DLL_SHA256 = "5d3a679afde7a1069b69024e47210fd0841736877e0f63a1ee89f6a722513fb6"
OLD_DLL_SHA256 = "41079eae93a825c48428defff2430aa0a17707c92bb020fb2f0e77952cd5efc1"
NEW_MANIFEST_SHA256 = "5bfdd346d064f885d9f780c3a2a47ab1d3fd2a00adc6ed4b2f2891b1c0f2dd18"
P1_SCRIPT_DLL_SHA256 = "5a165ed11e91fb9e64159f63954d40af68a19f26ccf0a20358f5bba231a711bd"
P1_SCRIPT_MANIFEST_SHA256 = "71f0e07828e5477cd4d02acc2b945e2af43a3c762a7bf4f41c3e20ba99540236"
DIRECT_SUPPORT_DLL_SHA256 = "b5cfbc0544ab0b6573504e4df13041ed6d1dcaf2ba32ecc345790c510f4addca"
DIRECT_SUPPORT_MANIFEST_SHA256 = "ec592112a84d744b9a4bbd2fa36b99460df41612edd3f9130d896a942e4cc14b"
ROOT = Path(__file__).resolve().parents[2]


def _fixture(dll_sha256=NEW_DLL_SHA256):
    contract = guard._BUILDS[dll_sha256]
    asset = json.loads(contract["asset_file"].read_bytes())
    profile = trigger_profile.load_profile()
    source = next(row for row in profile["code_guards"] if row["rva"] == guard.ENTRY_RVA)
    reader = FakeReader()
    dll_base = 0x7FF900000000
    trampoline = 0x1A000000000
    reader.mission_observer_binding = {
        "dll_base": dll_base,
        "dll_path": "bound-shared-entry-observer.dll",
        "dll_sha256": dll_sha256,
        "build_manifest_sha256": contract["manifest_sha256"],
    }
    expected = bytes.fromhex(source["raw_hex"])
    hook = dll_base + asset["observe_rva"]
    patch = b"\xff\x25\0\0\0\0" + struct.pack("<Q", hook) + b"\x90" + expected[15:]
    reader.put(reader.module_base + guard.ENTRY_RVA, patch)
    reader.put(hook, bytes.fromhex(asset["observe_hex"]))
    reader.put(dll_base + asset["observe_unwind_rva"], bytes.fromhex(asset["observe_unwind_hex"]))
    reader.qword_put(dll_base + asset["game_base_rva"], reader.module_base)
    reader.qword_put(dll_base + asset["original_rva"], trampoline)
    reader.qword_put(dll_base + asset["executable_rva"], trampoline)
    continuation = reader.module_base + guard.ENTRY_RVA + 15
    jump = bytes.fromhex("c7842420000000") + struct.pack("<I", continuation & 0xFFFFFFFF)
    jump += bytes.fromhex("c7842424000000") + struct.pack("<I", continuation >> 32)
    jump += bytes.fromhex("ffa42420000000")
    reader.put(trampoline, guard.PREFIX + jump + bytes(20) + guard.PROJECTED_UNWIND)
    return reader, source, contract, asset, dll_base


def test_v61_shared_entry_asset_and_r11_source_closure_are_pinned():
    profile = trigger_profile.load_profile()
    contract = guard._BUILDS[NEW_DLL_SHA256]
    old_contract = guard._BUILDS[OLD_DLL_SHA256]
    asset_raw = contract["asset_file"].read_bytes()
    asset = json.loads(asset_raw)
    old_profile = json.loads((trigger_profile.PROFILE_FILE.parent
                              / "mission-trigger-memory-1374-v14-r3-sampling-r10.json").read_bytes())
    evidence_path = ROOT / asset["evidence_path"]
    evidence_raw = evidence_path.read_bytes()
    manifest_path = ROOT / contract["manifest_path"]
    manifest_raw = manifest_path.read_bytes()
    evidence = json.loads(evidence_raw)

    assert profile["profile_revision"] == 11
    assert trigger_profile.PROFILE_FILE.name == "mission-trigger-memory-1374-v14-r3-sampling-r11.json"
    assert old_profile["profile_revision"] == 10
    assert old_contract["asset_file"].name == "mission-observer-guard-v61.json"
    assert contract["version"] == contract["build_version"] == asset["build_version"] == 61
    assert contract["asset_file"].name == "mission-observer-guard-v61-shared-entry.json"
    assert hashlib.sha256(asset_raw).hexdigest() == contract["asset_sha256"]
    assert asset["dll_sha256"] == NEW_DLL_SHA256
    assert hashlib.sha256(manifest_raw).hexdigest() == contract["manifest_sha256"] == NEW_MANIFEST_SHA256
    assert hashlib.sha256(evidence_raw).hexdigest() == contract["evidence_sha256"] == asset["evidence_sha256"]
    assert evidence["target"]["dll_sha256"] == NEW_DLL_SHA256
    assert evidence["target"]["build_manifest_sha256"] == NEW_MANIFEST_SHA256
    assert asset["build_manifest_sha256"] == NEW_MANIFEST_SHA256
    assert asset["source_count"] == contract["source_count"] == 189
    pins = {row["path"]: row for row in profile["source_evidence"]}
    assert pins["bridge/information/profiles/mission-observer-guard-v61-shared-entry.json"]["sha256"] == contract["asset_sha256"]
    assert pins[asset["evidence_path"]]["sha256"] == contract["evidence_sha256"]
    assert pins["bridge/information/profiles/mission-trigger-memory-1374-v14-r3-sampling-r10.json"]["sha256"] == hashlib.sha256(
        (trigger_profile.PROFILE_FILE.parent / "mission-trigger-memory-1374-v14-r3-sampling-r10.json").read_bytes()).hexdigest()


def test_v61_shared_entry_sha_accepts_exact_m02_guard_and_manifest_binding():
    reader, source, contract, asset, dll_base = _fixture()
    report = prerequisite._validate_code_guards(reader, reader.module_base, [source])[0]
    proof = report["observer_patch"]
    assert report["matches"] is False
    assert proof["kind"] == "verified_v61_mission_availability_entry"
    assert proof["dll_sha256"] == NEW_DLL_SHA256
    assert proof["build_manifest_sha256"] == NEW_MANIFEST_SHA256
    assert proof["asset_sha256"] == contract["asset_sha256"]
    assert proof["hook_va"] == hex(dll_base + asset["observe_rva"])


def test_v61_shared_entry_rejects_a_manifest_identity_change():
    reader, source, *_ = _fixture()
    reader.mission_observer_binding["build_manifest_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="mission_observer_manifest_binding_mismatch"):
        prerequisite._validate_code_guards(reader, reader.module_base, [source])


@pytest.mark.parametrize("damage", [None, "manifest", "hook_body"])
def test_current_territorial_interest_build_uses_its_own_pinned_mission_guard(damage):
    dll_sha = "968ee8e84e0426c86bd8e1e59b4b944cada8f06c90d01540a3c09846a2f14646"
    reader, source, contract, asset, dll_base = _fixture(dll_sha)
    assert contract["source_count"] == asset["source_count"] == 190
    assert asset["evidence_sha256"] == contract["evidence_sha256"]
    assert asset["dll_sha256"] == dll_sha
    if damage == "manifest":
        reader.mission_observer_binding["build_manifest_sha256"] = "0" * 64
    elif damage == "hook_body":
        reader.put(dll_base + asset["observe_rva"], b"\xcc")
    if damage:
        with pytest.raises(ValueError):
            prerequisite._validate_code_guards(reader, reader.module_base, [source])
    else:
        report = prerequisite._validate_code_guards(reader, reader.module_base, [source])[0]
        assert report["observer_patch"]["dll_sha256"] == dll_sha
        assert report["observer_patch"]["asset_sha256"] == contract["asset_sha256"]


@pytest.mark.parametrize("dll_sha256,asset_name,manifest_sha256,source_count", [
    ("a2711a11fe942c2fe129d47c1748b1502e7a275b98f2a5513f568cff1983d7b4",
     "mission-observer-guard-v61-war-active-roster.json",
     "6093fa86bc38b83b23a9e382f293b3325718cc74d6d9cc11113b0d89fd5c93f8", 191),
    ("d4de6ce15edd9040e1aaa7ff1bdc14f67a535e1460d8c7de703984e5aad507a5",
     "mission-observer-guard-v61-war-recycling.json",
     "ae8797da65c649611d5d7356d79d35d809c0a1b74d6b134089a218fe30c4b6a1", 191),
    ("b6e0f879d99d84cd954315bdb8a9ecd880754c29df8b3ba7af7e0b22fe55a9fa",
     "mission-observer-guard-v61-war-lifetime.json",
     "155fa9d481746c3caab279bf0b11a5d166623771b4d4db319e79b1208ba67d05", 191),
    ("d4fbf00818b3736d6494d11577b190164958257c35fb2c3c4fd538e87c3bf397",
     "mission-observer-guard-v61-direct-declaration.json",
     "697911d5886110bf6ff87ffcf59df52be214dd04c4b6e143eba2b34d9127938c", 190),
    ("9bda79afaa5d0fe489e6c3a7a69b76ed73f516d7353c621d76dff9630a284481",
     "mission-observer-guard-v61-inbound-clock.json",
     "d69134bb4a8560c2b046607f9d1d883d6fc0065cd527af4e0996620c1f6563a6", 190),
    (P1_SCRIPT_DLL_SHA256, "mission-observer-guard-v61-p1-script.json", P1_SCRIPT_MANIFEST_SHA256, 190),
    (DIRECT_SUPPORT_DLL_SHA256, "mission-observer-guard-v61-direct-support.json", DIRECT_SUPPORT_MANIFEST_SHA256, 190),
])
def test_current_v61_build_asset_matches_its_exact_pe_review_and_binding(
        dll_sha256, asset_name, manifest_sha256, source_count):
    reader, source, contract, asset, dll_base = _fixture(dll_sha256)
    asset_raw = contract["asset_file"].read_bytes()
    asset = json.loads(asset_raw)
    evidence_path = ROOT / asset["evidence_path"]
    evidence_raw = evidence_path.read_bytes()
    evidence = json.loads(evidence_raw)
    manifest_raw = (ROOT / contract["manifest_path"]).read_bytes()

    assert contract["asset_file"].name == asset_name
    assert hashlib.sha256(asset_raw).hexdigest() == contract["asset_sha256"]
    assert hashlib.sha256(manifest_raw).hexdigest() == contract["manifest_sha256"]
    assert contract["manifest_sha256"] == manifest_sha256
    assert hashlib.sha256(evidence_raw).hexdigest() == contract["evidence_sha256"]
    assert contract["manifest_sha256"] == asset["build_manifest_sha256"]
    assert contract["source_count"] == asset["source_count"] == source_count
    assert asset["dll_sha256"] == dll_sha256
    assert evidence["evidence_kind"] == "ordinary_pe_coff_pdata_static_extraction"
    assert evidence["runtime_observation"] is False
    assert evidence["target"]["dll_sha256"] == dll_sha256
    assert evidence["target"]["build_manifest_sha256"] == contract["manifest_sha256"]

    game_base_rva = evidence["f03_gui_forwarder"]["game_module_base_global"]["rva"]
    for asset_section, evidence_section in (
        (asset, "mission_availability_observer"),
        (asset["condition"], "mission_condition_observer"),
        (asset["province"], "mission_condition_observer_province"),
    ):
        function = evidence[evidence_section]["function"]
        assert asset_section["observe_rva"] == function["rva_start"]
        assert asset_section["observe_end_rva"] == function["rva_end_exclusive"]
        assert asset_section["observe_hex"] == function["body_hex"]
        assert asset_section["observe_unwind_rva"] == function["unwind_rva"]
        assert asset_section["observe_unwind_hex"] == function["unwind_raw_hex"]
        assert asset_section["game_base_rva"] == game_base_rva
        assert asset_section["observe_pe_base_relocations"] == []

    report = prerequisite._validate_code_guards(reader, reader.module_base, [source])[0]
    proof = report["observer_patch"]
    assert proof["kind"] == "verified_v61_mission_availability_entry"
    assert proof["dll_sha256"] == dll_sha256
    assert proof["asset_sha256"] == contract["asset_sha256"]
    assert proof["hook_va"] == hex(dll_base + asset["observe_rva"])
