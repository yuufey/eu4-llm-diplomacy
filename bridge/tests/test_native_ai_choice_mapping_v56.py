"""Exact formal v56 condition GUI-forwarder and F03 profile pins."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from bridge.information import foreign_economy_capture_v7 as capture
from bridge.information import foreign_economy_projection_v7 as projection
from bridge.information import foreign_quality_visibility_memory as common
from bridge.information import native_ai_choice_mapping_memory_v34 as mapping
from bridge.information import target_debt_principal_memory_v34 as principal
from bridge.tests import test_foreign_debt_projection_v34 as old_projection
from bridge.tests import test_native_ai_choice_mapping_memory_v34 as old_mapping
from bridge.tests import test_native_ai_choice_mapping_memory_v41 as v41
from bridge.tests import test_target_debt_principal_memory_v34 as old_principal


ROOT = Path(capture.ROOT)
ASSET_PATH = ROOT / "bridge/information/profiles/native-ai-choice-hook-v56-condition.json"
REVIEW_PATH = ROOT / (
    "work/runtime/information-condition-release-20261109-341-001/"
    "asset-v56-condition-001/pe-review.json"
)
MANIFEST_PATH = ROOT / (
    "work/runtime/diplomacy-observer-20261109-condition-v56-341-001/build-manifest.json"
)
R22_REVIEW_PATH = ROOT / (
    "work/runtime/information-province-release-20261109-346-001/"
    "pe-review-v57-mission-and-f03-r2.json"
)
R22_MANIFEST_PATH = ROOT / (
    "work/runtime/diplomacy-observer-20261109-province-v57-346-001/build-manifest.json"
)


def install_v56(image, game_base):
    return v41.install(image, game_base, variant="56-condition")


def test_v56_asset_matches_frozen_dll_and_bounded_static_review():
    asset, raw = mapping._asset("56-condition")
    review = json.loads(REVIEW_PATH.read_text(encoding="utf-8"))
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8-sig"))

    assert hashlib.sha256(raw).hexdigest() == mapping.V56_CONDITION_ASSET_SHA256
    assert asset["hook_asset_tag"] == "56-condition"
    assert asset["dll_sha256"] == mapping.V56_CONDITION_HOOK_DLL_SHA256
    assert asset["game_executable_sha256"] == mapping.EXPECTED_EXE_SHA256
    assert asset["body_rva"] == mapping.V56_CONDITION_HOOK_POINTER_DELTA == 0x62DC0
    assert asset["favor_gold_original_global_rva"] == 0x1B5A6D8
    assert asset["body_end_rva_exclusive"] == 0x6324F
    assert asset["body_sha256"] == "24e45933ee505b6cb1e849448de24353fcc84d32e1f6dc13d7113f9d111782d7"
    assert asset["preferred_image_base"] == "0x34d010000"
    assert asset["game_module_base_global_rva"] == 0x22535A0
    assert asset["whole_loaded_dll_hash_verified"] is False
    assert asset["runtime_callback_execution_observed"] is False

    assert manifest["version"] == 56 and len(manifest["sources"]) == 178
    assert manifest["dll_sha256"] == mapping.V56_CONDITION_HOOK_DLL_SHA256
    assert manifest["runtime_verified"] is False
    assert review["evidence_kind"] == "ordinary_pe_coff_pdata_static_review"
    assert review["rea_evidence_id"] is None
    assert review["runtime_observation"] is False
    assert review["target"]["sha256"] == mapping.V56_CONDITION_HOOK_DLL_SHA256
    assert review["target"]["build_manifest"]["sha256"] == hashlib.sha256(
        MANIFEST_PATH.read_bytes()
    ).hexdigest()
    assert review["target"]["build_manifest"]["version"] == 56
    assert review["target"]["build_manifest"]["source_count"] == 178
    assert review["pe_headers"]["compared_prior_asset_sha256"] == (
        mapping.V55_MACRO_REPAIR_ASSET_SHA256
    )
    assert review["bounded_read_policy"]["whole_file_loaded"] is False
    assert review["pdata_function"] == {
        "rva_start": 0x62DC0,
        "rva_end_exclusive": 0x6324F,
        "byte_length": 1167,
        "unwind_info_rva": 0x68B018,
        "body_sha256": asset["body_sha256"],
    }
    assert review["unwind_info"]["raw_hex"] == "010904000901a90102300160"
    assert review["unwind_info"]["byte_length"] == 12
    assert review["coff_symbols"]["forwarder"]["rva"] == asset["body_rva"]
    assert review["coff_symbols"]["forwarder"]["section_virtual_address_hex"] == "0x1000"
    assert review["coff_symbols"]["game_module_base_global"]["rva"] == asset[
        "game_module_base_global_rva"
    ]
    assert review["coff_symbols"]["saved_original_global"]["rva"] == asset[
        "favor_gold_original_global_rva"
    ]
    assert all(review["coff_symbols"][key]["section_name"] == ".bss"
               for key in ("game_module_base_global", "saved_original_global"))


def test_v56_mapping_is_stable_and_reads_only_the_pinned_forwarder():
    image = old_mapping.MemoryImage()
    asset, pointer = install_v56(image, old_mapping.GAME_BASE)
    before = mapping.read_mapping(
        common._Trace(image), old_mapping.GAME_BASE, pointer, phase="before"
    )
    after_trace = common._Trace(image)
    after = mapping.read_mapping(
        after_trace, old_mapping.GAME_BASE, pointer, phase="after"
    )

    assert before == after
    assert before["mode"] == "installed_observer_gui_forwarding_v56"
    assert before["asset_sha256"] == mapping.V56_CONDITION_ASSET_SHA256
    assert before["dll_sha256_from_asset"] == mapping.V56_CONDITION_HOOK_DLL_SHA256
    assert before["body_rva"] == "0x62dc0"
    assert before["body_raw_hex"] == asset["body_hex"]
    assert before["body_matches_pinned_asset"] is True
    assert before["whole_loaded_dll_hash_verified"] is False
    assert after_trace.summary()["calls"] == 9
    assert after_trace.summary()["bytes_requested"] == 1280


@pytest.mark.parametrize(
    "damage", ["dos", "coff", "magic", "image_size", "body", "game_base", "original"]
)
def test_v56_damaged_runtime_mapping_stays_unknown(damage):
    image = old_mapping.MemoryImage()
    asset, pointer = install_v56(image, old_mapping.GAME_BASE)
    if damage == "dos":
        image.put(old_mapping.DLL_BASE, b"\0")
    elif damage == "coff":
        image.put(old_mapping.DLL_BASE + asset["pe_header_offset"], b"\0")
    elif damage == "magic":
        image.put(old_mapping.DLL_BASE + asset["pe_header_offset"] + 24, b"\0\0")
    elif damage == "image_size":
        image.put(
            old_mapping.DLL_BASE + asset["pe_header_offset"] + 24 + 56,
            b"\0" * 4,
        )
    elif damage == "body":
        image.put(pointer, b"\0")
    elif damage == "game_base":
        image.put_u64(old_mapping.DLL_BASE + asset["game_module_base_global_rva"], 0)
    else:
        image.put_u64(old_mapping.DLL_BASE + asset["favor_gold_original_global_rva"], 0)

    with pytest.raises(common._Unknown):
        mapping.read_mapping(common._Trace(image), old_mapping.GAME_BASE, pointer, phase="before")


@pytest.mark.parametrize("slot_delta", [1, 0x100])
def test_v56_wrong_pointer_delta_stays_unknown(slot_delta):
    image = old_mapping.MemoryImage()
    _asset, pointer = install_v56(image, old_mapping.GAME_BASE)
    with pytest.raises(common._Unknown):
        mapping.read_mapping(
            common._Trace(image), old_mapping.GAME_BASE, pointer + slot_delta, phase="before"
        )


def test_v56_asset_pin_mismatch_stays_unknown(monkeypatch):
    monkeypatch.setattr(mapping, "V56_CONDITION_ASSET_SHA256", "0" * 64)
    with pytest.raises(common._Unknown, match="CHOICE_MAPPING_ASSET_PIN_MISMATCH"):
        mapping._asset("56-condition")


def test_v56_principal_consumer_maps_mode_to_56(monkeypatch):
    original_environment = old_principal._environment

    def environment(**kwargs):
        image, observer, target = original_environment(**kwargs)
        _asset, pointer = install_v56(image, old_principal.BASE)
        image.put_u64(old_principal.BASE + principal.CURRENT_VALIDITY_HELPER_CELL_RVA, pointer)
        return image, observer, target

    monkeypatch.setattr(old_principal, "_environment", environment)
    item = old_projection._v34_item()
    permission = item["fields"][principal.FIELD]["raw_inputs"]["permission"]
    assert principal.validate_permission(permission)
    scope = permission["raw_inputs"]["scope_evidence"]["current_validity_helper_map"]
    assert scope["hook_asset_sha256"] == mapping.V56_CONDITION_ASSET_SHA256
    assert scope["accepted_mapping_modes"] == [
        "native_true",
        "installed_observer_gui_forwarding_v56",
    ]

    admitted = projection.project(
        item, "ENG", ["debt"], debt_scope=old_projection._disclosure_scope()
    )["debt"]
    assert admitted["value"]["total_debt"]["value"] == 1055.0
    denied = projection.project(item, "ENG", ["debt"], debt_scope=None)["debt"]
    assert denied["component_statuses"]["total_debt"]["status"] == "unknown"


def test_r27_current_sampling_profile_loads_with_exact_v56_v57_v58_v59_and_v60_dependencies():
    profile = capture._load_profile()
    main_path = ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r27.json"
    sampling_path = ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r27-sampling-r1.json"
    main = json.loads(main_path.read_text(encoding="utf-8"))
    sampling = json.loads(sampling_path.read_text(encoding="utf-8"))
    assert capture.PROFILE_FILE == sampling_path
    assert hashlib.sha256(sampling_path.read_bytes()).hexdigest() == capture.PROFILE_SHA256
    assert profile["profile_revision"] == main["profile_revision"] == sampling["profile_revision"] == 27
    accepted = main["target_debt_principal"]["native_ai_accept_scope"]["accepted_mapping_modes"]
    assert "installed_observer_gui_forwarding_v58" in accepted
    assert "installed_observer_gui_forwarding_v59" in accepted
    assert "installed_observer_gui_forwarding_v60" in accepted
    assert "installed_observer_gui_forwarding_v61" in accepted
    assert "installed_observer_gui_forwarding_v57" in accepted
    assert "installed_observer_gui_forwarding_v56" in accepted
    assert "installed_observer_gui_forwarding_v55" in accepted
    assert "installed_observer_gui_forwarding_v52" not in accepted
    assert "installed_observer_gui_forwarding_v53" not in accepted
    assert sampling["target_debt_principal"]["native_ai_accept_scope"][
        "accepted_mapping_modes"
    ] == accepted
    assert sampling["observation_time_revision"]["previous_profile"].endswith(
        "foreign-economy-memory-1374-v7-r26-sampling-r1.json"
    )

    layouts = {row["path"]: row["sha256"] for row in main["layout_dependencies"]}
    sources = {row["path"]: row["sha256"] for row in main["source_evidence"]}
    assert layouts["bridge/information/native_ai_choice_mapping_memory_v34.py"] == hashlib.sha256(
        (ROOT / "bridge/information/native_ai_choice_mapping_memory_v34.py").read_bytes()
    ).hexdigest()
    assert layouts["bridge/information/target_debt_principal_memory_v34.py"] == hashlib.sha256(
        (ROOT / "bridge/information/target_debt_principal_memory_v34.py").read_bytes()
    ).hexdigest()
    assert layouts[ASSET_PATH.relative_to(ROOT).as_posix()] == mapping.V56_CONDITION_ASSET_SHA256
    assert layouts["bridge/information/profiles/native-ai-choice-hook-v57-province.json"] == (
        mapping.V57_PROVINCE_ASSET_SHA256
    )
    assert sources[MANIFEST_PATH.relative_to(ROOT).as_posix()] == (
        "cf18ef0678f2912592067edb257b652e44032704811506c04a1038ade26e6e4d"
    )
    assert sources[REVIEW_PATH.relative_to(ROOT).as_posix()] == (
        "6611d3b0234907766d32ed754a0ff761b275d5c263e9e79ea798bbbb90d72ebd"
    )
    assert sources[R22_MANIFEST_PATH.relative_to(ROOT).as_posix()] == (
        "9a4d2888df127e22014fb238dcf9a912f0e2350120363b95febd9c26f8464785"
    )
    assert sources[R22_REVIEW_PATH.relative_to(ROOT).as_posix()] == (
        "e9c517bb678381129c8fd451cae9aed3d80f0bf2f9213c6452a959f5b0ad2853"
    )

