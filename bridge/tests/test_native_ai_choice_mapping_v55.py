"""Exact v55 macro-repair GUI-forwarder and F03 compatibility pins."""
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
from bridge.tests import test_native_ai_choice_mapping_v54 as v54
from bridge.tests import test_native_ai_choice_mapping_v47 as v47
from bridge.tests import test_native_ai_choice_mapping_v48 as v48
from bridge.tests import test_native_ai_choice_mapping_v51 as v51
from bridge.tests import test_target_debt_principal_memory_v34 as old_principal


ROOT = Path(capture.ROOT)
ASSET_PATH = ROOT / "bridge/information/profiles/native-ai-choice-hook-v55-macro-repair.json"
REVIEW_PATH = ROOT / (
    "work/runtime/information-macro-repair-release-20261109-336-001/"
    "asset-v55-macro-repair-001/pe-review.json"
)
MANIFEST_PATH = ROOT / (
    "work/runtime/diplomacy-observer-20261109-macro-repair-v55-336-001/build-manifest.json"
)
V56_REVIEW_PATH = ROOT / (
    "work/runtime/information-condition-release-20261109-341-001/"
    "asset-v56-condition-001/pe-review.json"
)
V56_MANIFEST_PATH = ROOT / (
    "work/runtime/diplomacy-observer-20261109-condition-v56-341-001/build-manifest.json"
)
R22_REVIEW_PATH = ROOT / (
    "work/runtime/information-province-release-20261109-346-001/"
    "pe-review-v57-mission-and-f03-r2.json"
)
R22_MANIFEST_PATH = ROOT / (
    "work/runtime/diplomacy-observer-20261109-province-v57-346-001/build-manifest.json"
)
R23_REVIEW_PATH = ROOT / (
    "work/runtime/information-royal-release-20261110-349-001/"
    "pe-review-v58-mission-and-f03.json"
)
R23_MANIFEST_PATH = ROOT / (
    "work/runtime/diplomacy-observer-20261110-royal-v58-349-001/build-manifest.json"
)


def install_v55(image, game_base):
    return v41.install(image, game_base, variant="55-macro-repair")


def test_v55_mapping_matches_the_exact_pinned_helper_and_static_review():
    asset, raw = mapping._asset("55-macro-repair")
    review = json.loads(REVIEW_PATH.read_text(encoding="utf-8"))
    assert hashlib.sha256(raw).hexdigest() == mapping.V55_MACRO_REPAIR_ASSET_SHA256
    assert asset["hook_asset_tag"] == "55-macro-repair"
    assert asset["dll_sha256"] == mapping.V55_MACRO_REPAIR_HOOK_DLL_SHA256
    assert asset["game_executable_sha256"] == mapping.EXPECTED_EXE_SHA256
    assert asset["body_rva"] == mapping.V55_MACRO_REPAIR_HOOK_POINTER_DELTA == 0x62B30
    assert asset["body_end_rva_exclusive"] == 0x62FBF
    assert asset["body_sha256"] == "506e19456cc42cbf516e1b0c7d0df15f6a8cb1d03fe630e092016a89dd9ba637"
    assert asset["preferred_image_base"] == "0x1e5930000"
    assert asset["game_module_base_global_rva"] == 0x130EF60
    assert asset["favor_gold_original_global_rva"] == 0xC16098
    assert asset["whole_loaded_dll_hash_verified"] is False
    assert asset["runtime_callback_execution_observed"] is False

    assert review["evidence_kind"] == "ordinary_pe_coff_pdata_static_review"
    assert review["rea_evidence_id"] is None
    assert review["runtime_observation"] is False
    assert review["target"]["sha256"] == mapping.V55_MACRO_REPAIR_HOOK_DLL_SHA256
    assert review["target"]["sha256"] == "f569c20465922e7f56b2fa45009da551501f690ea5549f3e13309b4ac8155ade"
    assert review["target"]["build_manifest"]["version"] == 55
    assert review["target"]["build_manifest"]["source_count"] == 175
    assert review["target"]["build_manifest"]["runtime_verified"] is False
    assert review["pe_headers"]["compared_prior_asset_sha256"] == (
        mapping.V54_MACRO_SOURCES_ASSET_SHA256
    )
    assert review["bounded_read_policy"]["whole_file_loaded"] is False
    assert review["pdata_function"] == {
        "rva_start": 0x62B30,
        "rva_end_exclusive": 0x62FBF,
        "byte_length": 1167,
        "unwind_info_rva": 0x67BFCC,
        "body_sha256": asset["body_sha256"],
    }
    assert review["unwind_info"]["raw_hex"] == "010904000901a90102300160"
    assert review["unwind_info"]["byte_length"] == 12
    assert review["coff_symbols"]["forwarder"]["rva"] == asset["body_rva"]
    assert review["coff_symbols"]["forwarder"]["section_virtual_address_hex"] == "0x1000"
    assert review["coff_symbols"]["forwarder"]["value_section_relative_hex"] == "0x61b30"
    assert review["coff_symbols"]["game_module_base_global"]["rva"] == asset[
        "game_module_base_global_rva"
    ]
    assert review["coff_symbols"]["game_module_base_global"]["section_virtual_address_hex"] == "0x680000"
    assert review["coff_symbols"]["game_module_base_global"]["value_section_relative_hex"] == "0xc8ef60"
    assert review["coff_symbols"]["saved_original_global"]["rva"] == asset[
        "favor_gold_original_global_rva"
    ]
    assert review["coff_symbols"]["saved_original_global"]["value_section_relative_hex"] == "0x596098"
    assert all(
        review["coff_symbols"][key]["section_name"] == ".bss"
        for key in ("game_module_base_global", "saved_original_global")
    )


def test_v55_mapping_is_stable_and_reads_only_the_forwarder_contract():
    image = old_mapping.MemoryImage()
    asset, pointer = install_v55(image, old_mapping.GAME_BASE)
    before = mapping.read_mapping(
        common._Trace(image), old_mapping.GAME_BASE, pointer, phase="before"
    )
    after_trace = common._Trace(image)
    after = mapping.read_mapping(
        after_trace, old_mapping.GAME_BASE, pointer, phase="after"
    )

    assert before == after
    assert before["mode"] == "installed_observer_gui_forwarding_v55"
    assert before["asset_sha256"] == mapping.V55_MACRO_REPAIR_ASSET_SHA256
    assert before["dll_sha256_from_asset"] == mapping.V55_MACRO_REPAIR_HOOK_DLL_SHA256
    assert before["body_rva"] == "0x62b30"
    assert before["body_raw_hex"] == asset["body_hex"]
    assert before["body_matches_pinned_asset"] is True
    assert before["whole_loaded_dll_hash_verified"] is False
    assert after_trace.summary()["calls"] == 9
    assert after_trace.summary()["bytes_requested"] == 1280


@pytest.mark.parametrize(
    "damage", ["dos", "coff", "magic", "image_size", "body", "game_base", "original"]
)
def test_v55_damaged_runtime_mapping_stays_unknown(damage):
    image = old_mapping.MemoryImage()
    asset, pointer = install_v55(image, old_mapping.GAME_BASE)
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
def test_v55_wrong_slot_stays_unknown(slot_delta):
    image = old_mapping.MemoryImage()
    _asset, pointer = install_v55(image, old_mapping.GAME_BASE)
    with pytest.raises(common._Unknown):
        mapping.read_mapping(
            common._Trace(image), old_mapping.GAME_BASE, pointer + slot_delta, phase="before"
        )


def test_v55_asset_pin_mismatch_stays_unknown(monkeypatch):
    monkeypatch.setattr(mapping, "V55_MACRO_REPAIR_ASSET_SHA256", "0" * 64)
    with pytest.raises(common._Unknown, match="CHOICE_MAPPING_ASSET_PIN_MISMATCH"):
        mapping._asset("55-macro-repair")


def test_v55_principal_consumer_maps_the_mode_to_55(monkeypatch):
    original_environment = old_principal._environment

    def environment(**kwargs):
        image, observer, target = original_environment(**kwargs)
        _asset, pointer = install_v55(image, old_principal.BASE)
        image.put_u64(old_principal.BASE + principal.CURRENT_VALIDITY_HELPER_CELL_RVA, pointer)
        return image, observer, target

    monkeypatch.setattr(old_principal, "_environment", environment)
    item = old_projection._v34_item()
    permission = item["fields"][principal.FIELD]["raw_inputs"]["permission"]
    assert principal.validate_permission(permission)
    scope = permission["raw_inputs"]["scope_evidence"]["current_validity_helper_map"]
    assert scope["hook_asset_sha256"] == mapping.V55_MACRO_REPAIR_ASSET_SHA256
    assert scope["accepted_mapping_modes"] == [
        "native_true",
        "installed_observer_gui_forwarding_v55",
    ]

    admitted = projection.project(
        item, "ENG", ["debt"], debt_scope=old_projection._disclosure_scope()
    )["debt"]
    assert admitted["value"]["total_debt"]["value"] == 1055.0
    denied = projection.project(item, "ENG", ["debt"], debt_scope=None)["debt"]
    assert denied["component_statuses"]["total_debt"]["status"] == "unknown"


def test_r27_sampling_profile_is_the_default_and_keeps_compatibility():
    profile = capture._load_profile()
    main_path = ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r27.json"
    sampling_path = ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r27-sampling-r1.json"
    main_profile = json.loads(main_path.read_text(encoding="utf-8"))
    sample_profile = json.loads(sampling_path.read_text(encoding="utf-8"))

    assert capture.PROFILE_FILE == sampling_path
    assert hashlib.sha256(sampling_path.read_bytes()).hexdigest() == capture.PROFILE_SHA256
    assert profile["profile_revision"] == main_profile["profile_revision"] == 27
    assert sample_profile["profile_revision"] == 27
    assert sample_profile["observation_time_revision"]["previous_profile"].endswith(
        "foreign-economy-memory-1374-v7-r26-sampling-r1.json"
    )
    accepted = main_profile["target_debt_principal"]["native_ai_accept_scope"][
        "accepted_mapping_modes"
    ]
    assert "installed_observer_gui_forwarding_v59" in accepted
    assert "installed_observer_gui_forwarding_v60" in accepted
    assert "installed_observer_gui_forwarding_v61" in accepted
    assert "installed_observer_gui_forwarding_v58" in accepted
    assert "installed_observer_gui_forwarding_v57" in accepted
    assert "installed_observer_gui_forwarding_v56" in accepted
    assert "installed_observer_gui_forwarding_v55" in accepted
    assert "installed_observer_gui_forwarding_v54" in accepted
    assert "installed_observer_gui_forwarding_v51" in accepted
    assert "installed_observer_gui_forwarding_v48" in accepted
    assert "installed_observer_gui_forwarding_v47" in accepted
    assert "installed_observer_gui_forwarding_v52" not in accepted
    assert "installed_observer_gui_forwarding_v53" not in accepted
    sample_accepted = sample_profile["target_debt_principal"]["native_ai_accept_scope"][
        "accepted_mapping_modes"
    ]
    assert sample_accepted == accepted
    assert sample_profile["observation_time_revision"]["previous_profile"].endswith(
        "foreign-economy-memory-1374-v7-r26-sampling-r1.json"
    )

    layout_pins = {row["path"]: row["sha256"] for row in main_profile["layout_dependencies"]}
    source_pins = {row["path"]: row["sha256"] for row in main_profile["source_evidence"]}
    assert layout_pins["bridge/information/native_ai_choice_mapping_memory_v34.py"] == hashlib.sha256(
        (ROOT / "bridge/information/native_ai_choice_mapping_memory_v34.py").read_bytes()
    ).hexdigest()
    assert layout_pins["bridge/information/target_debt_principal_memory_v34.py"] == hashlib.sha256(
        (ROOT / "bridge/information/target_debt_principal_memory_v34.py").read_bytes()
    ).hexdigest()
    assert layout_pins["bridge/information/profiles/native-ai-choice-hook-v55-macro-repair.json"] == (
        mapping.V55_MACRO_REPAIR_ASSET_SHA256
    )
    assert layout_pins["bridge/information/profiles/native-ai-choice-hook-v56-condition.json"] == (
        mapping.V56_CONDITION_ASSET_SHA256
    )
    assert layout_pins["bridge/information/profiles/native-ai-choice-hook-v57-province.json"] == (
        mapping.V57_PROVINCE_ASSET_SHA256
    )
    assert layout_pins["bridge/information/profiles/native-ai-choice-hook-v58-royal.json"] == (
        mapping.V58_ROYAL_ASSET_SHA256
    )
    assert source_pins[R23_MANIFEST_PATH.relative_to(ROOT).as_posix()] == (
        "379867300b974e847ac2b6d51d2fa61b15f34a4811fc2b6992d8d2fc984f9f36"
    )
    assert source_pins[R23_REVIEW_PATH.relative_to(ROOT).as_posix()] == (
        "bef8f160a8c9ad0db989365e488bc6c262abb9829023c58e8d52c3d61935e4eb"
    )
    assert source_pins[MANIFEST_PATH.relative_to(ROOT).as_posix()] == (
        "59045b9bddbc5a6af544b864979dbeff48d11e0de116725ea1e51a2809e0b470"
    )
    assert source_pins[REVIEW_PATH.relative_to(ROOT).as_posix()] == (
        "f7f2da3012969f14cee2f7f5d349b1dba8c8e8315081e9985b1a05905cfb128c"
    )
    assert source_pins[V56_MANIFEST_PATH.relative_to(ROOT).as_posix()] == (
        "cf18ef0678f2912592067edb257b652e44032704811506c04a1038ade26e6e4d"
    )
    assert source_pins[V56_REVIEW_PATH.relative_to(ROOT).as_posix()] == (
        "6611d3b0234907766d32ed754a0ff761b275d5c263e9e79ea798bbbb90d72ebd"
    )
    assert source_pins[R22_MANIFEST_PATH.relative_to(ROOT).as_posix()] == (
        "9a4d2888df127e22014fb238dcf9a912f0e2350120363b95febd9c26f8464785"
    )
    assert source_pins[R22_REVIEW_PATH.relative_to(ROOT).as_posix()] == (
        "e9c517bb678381129c8fd451cae9aed3d80f0bf2f9213c6452a959f5b0ad2853"
    )

    assert hashlib.sha256(
        (ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r17.json").read_bytes()
    ).hexdigest() == "d546aedc5ea599ab92f93fbd1333c5db2560b58355245fdda7df08d10e125b89"
    assert hashlib.sha256(
        (ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r17-sampling-r1.json").read_bytes()
    ).hexdigest() == "97b460c00cfbdca5f9b0ea354f679d0bad729487120b4a5abda5717bbd00a8d5"
    assert hashlib.sha256(
        (ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r18.json").read_bytes()
    ).hexdigest() == "277ef55a2d90a84c2c6e16de7436e1f6426ec0e1c14cb53cb229931481075ea5"
    assert hashlib.sha256(
        (ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r19.json").read_bytes()
    ).hexdigest() == "84dac82b0488479bff39c8ac9336fd3701bb5e831ce0a94aac520af65d14c674"
    assert hashlib.sha256(
        (ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r19-sampling-r1.json").read_bytes()
    ).hexdigest() == "86a83f4d8602891efbe7ee7699fdcac1f16030635a8d54b31e6f47c43c1b7725"
    assert hashlib.sha256(
        (ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r20.json").read_bytes()
    ).hexdigest() == "ec02e34d57f29a0fddc5f865b866254b6c245d8b8d0db81fccc4e40b375a0acc"
    assert hashlib.sha256(
        (ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r20-sampling-r1.json").read_bytes()
    ).hexdigest() == "abd8cc6f92d1a50c19760795d66a1f64973f884402b82d04cd85dc88d7ac4af4"
    assert hashlib.sha256(
        (ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r18-sampling-r1.json").read_bytes()
    ).hexdigest() == "1f09d986f0b5371953ec0c0cd488b06d4a93cb199e98df8e7381a689ad00910c"
    assert hashlib.sha256(
        (ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r16.json").read_bytes()
    ).hexdigest() == "e23a18b3a90c14dd6f39a62c5f49a1fc496a20cc3a06453d94a5e18c92116177"
    assert hashlib.sha256(
        (ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r16-sampling-r1.json").read_bytes()
    ).hexdigest() == "8671ce58e857b158858eefad95c639e41a7a1f058db750a09a6de84b3e85b3e8"


@pytest.mark.parametrize("dependency", ["asset", "review", "manifest", "mapping", "principal"])
def test_r27_loader_checks_fixed_dependencies_and_retains_python_references(monkeypatch, dependency):
    paths = {
        "asset": ROOT / "bridge/information/profiles/native-ai-choice-hook-v58-royal.json",
        "review": R23_REVIEW_PATH,
        "manifest": R23_MANIFEST_PATH,
        "mapping": ROOT / "bridge/information/native_ai_choice_mapping_memory_v34.py",
        "principal": ROOT / "bridge/information/target_debt_principal_memory_v34.py",
    }
    target = paths[dependency].resolve()
    original_sha = capture._sha

    def altered_sha(path):
        if path.resolve() == target:
            return "0" * 64
        return original_sha(path)

    monkeypatch.setattr(capture, "_sha", altered_sha)
    if target.suffix == ".py":
        profile = capture._load_profile()
        references = profile["source_evidence"] + profile["layout_dependencies"]
        reference = next(item for item in references if (ROOT / item["path"]).resolve() == target)
        assert reference["sha256"] != "0" * 64
    else:
        with pytest.raises(ValueError, match="FOREIGN_ECONOMY_PROFILE_DEPENDENCY"):
            capture._load_profile()


def test_previous_v54_v51_v48_and_v47_mappings_remain_byte_exact():
    v54.test_v54_mapping_is_stable_and_reads_only_the_forwarder_contract()
    v54_monkeypatch = pytest.MonkeyPatch()
    try:
        v54.test_v54_principal_consumer_maps_the_mode_to_54(v54_monkeypatch)
    finally:
        v54_monkeypatch.undo()
    v51.test_v51_mapping_is_stable_and_reads_only_the_forwarder_contract()
    v51_monkeypatch = pytest.MonkeyPatch()
    try:
        v51.test_v51_principal_consumer_maps_the_mode_to_51(v51_monkeypatch)
    finally:
        v51_monkeypatch.undo()
    v48.test_v48_rival_change_mapping_is_exact_and_bounded()
    monkeypatch = pytest.MonkeyPatch()
    try:
        v48.test_v48_mapping_is_accepted_by_the_existing_f03_principal_consumer(monkeypatch)
    finally:
        monkeypatch.undo()
    v47.test_v47_country_modifier_expiry_mapping_is_exact_and_bounded()

