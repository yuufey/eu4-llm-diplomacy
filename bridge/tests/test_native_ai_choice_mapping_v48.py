"""Exact v48 rival-change forwarding and F03 compatibility pins."""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
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
from bridge.tests import test_native_ai_choice_mapping_v46 as v46
from bridge.tests import test_native_ai_choice_mapping_v47 as v47
from bridge.tests import test_target_debt_principal_memory_v34 as old_principal


def install(image, game_base):
    return v41.install(image, game_base, variant="48-rival-change")


def test_v48_rival_change_mapping_is_exact_and_bounded():
    image = old_mapping.MemoryImage()
    asset, pointer = install(image, old_mapping.GAME_BASE)
    trace = common._Trace(image)
    before = mapping.read_mapping(trace, old_mapping.GAME_BASE, pointer, phase="before")
    after = mapping.read_mapping(
        common._Trace(image), old_mapping.GAME_BASE, pointer, phase="after"
    )

    assert before == after
    assert before["mode"] == "installed_observer_gui_forwarding_v48"
    assert before["asset_sha256"] == mapping.V48_RIVAL_CHANGE_ASSET_SHA256
    assert before["dll_sha256_from_asset"] == mapping.V48_RIVAL_CHANGE_HOOK_DLL_SHA256
    assert before["body_rva"] == "0x5de50"
    assert before["body_raw_hex"] == asset["body_hex"]
    assert before["body_matches_pinned_asset"] is True
    assert before["whole_loaded_dll_hash_verified"] is False
    assert trace.summary()["calls"] == 9
    assert trace.summary()["bytes_requested"] == 1280


@pytest.mark.parametrize(
    "damage", ["dos", "coff", "magic", "image_size", "body", "game_base", "original"]
)
def test_v48_damaged_mapping_stays_unknown(damage):
    image = old_mapping.MemoryImage()
    asset, pointer = install(image, old_mapping.GAME_BASE)
    module_base = old_mapping.DLL_BASE
    if damage == "dos":
        image.put(module_base, b"\0")
    elif damage == "coff":
        image.put(module_base + asset["pe_header_offset"], b"\0")
    elif damage == "magic":
        image.put(module_base + asset["pe_header_offset"] + 24, b"\0\0")
    elif damage == "image_size":
        image.put(module_base + asset["pe_header_offset"] + 24 + 56, b"\0" * 4)
    elif damage == "body":
        image.put(pointer, b"\0")
    elif damage == "game_base":
        image.put_u64(module_base + asset["game_module_base_global_rva"], 0)
    else:
        image.put_u64(module_base + asset["favor_gold_original_global_rva"], 0)

    with pytest.raises(common._Unknown):
        mapping.read_mapping(common._Trace(image), old_mapping.GAME_BASE, pointer, phase="before")


def test_v48_unaligned_pointer_and_bad_asset_pin_stay_unknown(monkeypatch):
    image = old_mapping.MemoryImage()
    _asset, pointer = install(image, old_mapping.GAME_BASE)
    with pytest.raises(common._Unknown):
        mapping.read_mapping(common._Trace(image), old_mapping.GAME_BASE, pointer + 1, phase="before")

    monkeypatch.setattr(mapping, "V48_RIVAL_CHANGE_ASSET_SHA256", "0" * 64)
    with pytest.raises(common._Unknown, match="CHOICE_MAPPING_ASSET_PIN_MISMATCH"):
        mapping._asset("48-rival-change")


def test_previous_v47_and_v46_mappings_remain_byte_exact():
    v47.test_v47_country_modifier_expiry_mapping_is_exact_and_bounded()
    v46.test_v46_country_modifier_remove_mapping_is_exact_and_bounded()


def test_v48_mapping_is_accepted_by_the_existing_f03_principal_consumer(monkeypatch):
    original_environment = old_principal._environment

    def environment(**kwargs):
        image, observer, target = original_environment(**kwargs)
        _asset, pointer = install(image, old_principal.BASE)
        image.put_u64(old_principal.BASE + principal.CURRENT_VALIDITY_HELPER_CELL_RVA, pointer)
        return image, observer, target

    monkeypatch.setattr(old_principal, "_environment", environment)
    item = old_projection._v34_item()
    permission = item["fields"][principal.FIELD]["raw_inputs"]["permission"]
    assert principal.validate_permission(permission)
    scope = permission["raw_inputs"]["scope_evidence"]["current_validity_helper_map"]
    assert scope["hook_asset_sha256"] == mapping.V48_RIVAL_CHANGE_ASSET_SHA256
    assert scope["accepted_mapping_modes"] == [
        "native_true",
        "installed_observer_gui_forwarding_v48",
    ]

    admitted = projection.project(
        item, "ENG", ["debt"], debt_scope=old_projection._disclosure_scope()
    )["debt"]
    assert admitted["value"]["total_debt"]["value"] == 1055.0
    denied = projection.project(item, "ENG", ["debt"], debt_scope=None)["debt"]
    assert denied["component_statuses"]["total_debt"]["status"] == "unknown"
    altered = deepcopy(permission)
    altered["raw_inputs"]["scope_evidence"]["current_validity_helper_map"]["hook_asset_sha256"] = (
        mapping.V47_COUNTRY_MODIFIER_EXPIRY_ASSET_SHA256
    )
    assert not principal.validate_permission(altered)


def test_current_profiles_keep_v48_proof_and_prior_profile_archives():
    root = Path(capture.ROOT)
    profile = capture._load_profile()
    main_path = root / "bridge/information/profiles/foreign-economy-memory-1374-v7-r27.json"
    sampling_path = root / "bridge/information/profiles/foreign-economy-memory-1374-v7-r27-sampling-r1.json"
    main_profile = json.loads(main_path.read_text())
    sampling_profile = json.loads(sampling_path.read_text())

    assert capture.PROFILE_FILE == sampling_path
    assert hashlib.sha256(sampling_path.read_bytes()).hexdigest() == capture.PROFILE_SHA256
    assert profile["profile_revision"] == main_profile["profile_revision"] == sampling_profile["profile_revision"] == 27
    accepted_modes = main_profile["target_debt_principal"]["native_ai_accept_scope"][
        "accepted_mapping_modes"
    ]
    assert "installed_observer_gui_forwarding_v56" in accepted_modes
    assert "installed_observer_gui_forwarding_v48" in accepted_modes
    assert "installed_observer_gui_forwarding_v47" in accepted_modes
    assert sampling_profile["observation_time_revision"]["previous_profile"].endswith(
        "foreign-economy-memory-1374-v7-r26-sampling-r1.json"
    )
    prior_main = root / "bridge/information/profiles/foreign-economy-memory-1374-v7-r17.json"
    prior_sampling = root / "bridge/information/profiles/foreign-economy-memory-1374-v7-r17-sampling-r1.json"
    assert hashlib.sha256(prior_main.read_bytes()).hexdigest() == (
        "d546aedc5ea599ab92f93fbd1333c5db2560b58355245fdda7df08d10e125b89"
    )
    assert hashlib.sha256(prior_sampling.read_bytes()).hexdigest() == (
        "97b460c00cfbdca5f9b0ea354f679d0bad729487120b4a5abda5717bbd00a8d5"
    )
    assert json.loads(prior_sampling.read_text())["observation_time_revision"]["previous_profile"].endswith(
        "foreign-economy-memory-1374-v7-r16-sampling-r1.json"
    )

    pins = {row["path"]: row["sha256"] for row in main_profile["layout_dependencies"]}
    v48_path = "bridge/information/" + mapping.V48_RIVAL_CHANGE_ASSET_RELATIVE_PATH
    assert pins[v48_path] == mapping.V48_RIVAL_CHANGE_ASSET_SHA256
    assert pins["bridge/information/profiles/native-ai-choice-hook-v47-country-modifier-expiry.json"] == (
        mapping.V47_COUNTRY_MODIFIER_EXPIRY_ASSET_SHA256
    )
    assert pins["bridge/information/profiles/native-ai-choice-hook-v46-country-modifier-remove.json"] == (
        mapping.V46_COUNTRY_MODIFIER_REMOVE_ASSET_SHA256
    )
    assert pins["bridge/information/profiles/native-ai-choice-hook-v45-country-modifier-add.json"] == (
        mapping.V45_COUNTRY_MODIFIER_ADD_ASSET_SHA256
    )

    manifest_path = "work/runtime/diplomacy-observer-20261109-rival-v48-322-001/build-manifest.json"
    review_path = "work/runtime/information-rival-delivery-20261109-322-001/asset-rival-evidence-001/pe-review.json"
    source_pins = {row["path"]: row["sha256"] for row in main_profile["source_evidence"]}
    assert manifest_path in source_pins and review_path in source_pins
    assert source_pins[manifest_path] == "bf0049ec88f69c5a712731dc0fc258afea89eff1ce36cd05d49aa856e453799f"
    assert source_pins[review_path] == "3d6627a36f13ffa07a643fdcc9555d45aa28d9c606bb3fec6658e1fd973e086f"

    review = json.loads((root / review_path).read_text())
    assert review["evidence_kind"] == "ordinary_pe_coff_pdata_static_review"
    assert review["target"]["sha256"] == mapping.V48_RIVAL_CHANGE_HOOK_DLL_SHA256
    assert review["bounded_read_policy"]["whole_file_loaded"] is False
    assert review["pdata_function"]["rva_start"] == 0x5DE50
    assert review["pdata_function"]["rva_end_exclusive"] == 0x5E2DF
    assert review["pdata_function"]["byte_length"] == 1167
    assert review["pdata_function"]["unwind_info_rva"] == 0x66FDF0
    assert review["pdata_function"]["body_sha256"] == "5b37e5097509c8773fbf574324774c6769f9f3a9ba8aaa1009a080218645667c"
    assert review["unwind_info"]["raw_hex"] == "010904000901a90102300160"

    sections = review["pe_headers"]["sections"]
    asset, _raw = mapping._asset("48-rival-change")
    expected = (
        ("game_module_base_global", "_ZL4base", "game_module_base_global_rva", "0xb20d20", "0x1194d20"),
        (
            "saved_original_global",
            "_ZN30bridge_alliance_inbound_detailL34inbound_favor_gold_choice_originalE",
            "favor_gold_original_global_rva",
            "0x427e78",
            "0xa9be78",
        ),
    )
    for key, symbol_name, asset_key, expected_value_hex, expected_rva_hex in expected:
        symbol = review["coff_symbols"][key]
        assert symbol["name"] == symbol_name
        section = sections[symbol["section_number"] - 1]
        calculated_rva = section["virtual_address"] + symbol["value_section_relative"]
        assert section["name"] == symbol["section_name"] == ".bss"
        assert symbol["section_virtual_address_hex"] == hex(section["virtual_address"]) == "0x674000"
        assert symbol["value_section_relative_hex"] == hex(symbol["value_section_relative"]) == expected_value_hex
        assert symbol["rva"] == calculated_rva == asset[asset_key]
        assert symbol["rva_hex"] == hex(calculated_rva) == expected_rva_hex

    old_main = root / "bridge/information/profiles/foreign-economy-memory-1374-v7-r16.json"
    old_sample = root / "bridge/information/profiles/foreign-economy-memory-1374-v7-r16-sampling-r1.json"
    assert hashlib.sha256(old_main.read_bytes()).hexdigest() == (
        "e23a18b3a90c14dd6f39a62c5f49a1fc496a20cc3a06453d94a5e18c92116177"
    )
    assert hashlib.sha256(old_sample.read_bytes()).hexdigest() == (
        "8671ce58e857b158858eefad95c639e41a7a1f058db750a09a6de84b3e85b3e8"
    )

    assert "installed_observer_gui_forwarding_v55" in accepted_modes
