"""Exact v47 country-modifier-expiry forwarding and F03 compatibility pins."""
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
from bridge.tests import test_target_debt_principal_memory_v34 as old_principal


def install(image, game_base):
    return v41.install(image, game_base, variant="47-country-modifier-expiry")


def test_v47_country_modifier_expiry_mapping_is_exact_and_bounded():
    image = old_mapping.MemoryImage()
    asset, pointer = install(image, old_mapping.GAME_BASE)
    trace = common._Trace(image)
    before = mapping.read_mapping(trace, old_mapping.GAME_BASE, pointer, phase="before")
    after = mapping.read_mapping(
        common._Trace(image), old_mapping.GAME_BASE, pointer, phase="after"
    )

    assert before == after
    assert before["mode"] == "installed_observer_gui_forwarding_v47"
    assert before["asset_sha256"] == mapping.V47_COUNTRY_MODIFIER_EXPIRY_ASSET_SHA256
    assert before["dll_sha256_from_asset"] == mapping.V47_COUNTRY_MODIFIER_EXPIRY_HOOK_DLL_SHA256
    assert before["body_rva"] == f"0x{asset['body_rva']:x}"
    assert before["body_rva"] == "0x5d510"
    assert before["body_raw_hex"] == asset["body_hex"]
    assert before["body_matches_pinned_asset"] is True
    assert before["whole_loaded_dll_hash_verified"] is False
    assert trace.summary()["calls"] == 9
    assert trace.summary()["bytes_requested"] == 113 + len(bytes.fromhex(asset["body_hex"]))


@pytest.mark.parametrize(
    "damage", ["dos", "coff", "magic", "image_size", "body", "game_base", "original"]
)
def test_v47_damaged_mapping_stays_unknown(damage):
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


def test_v47_unaligned_pointer_and_bad_asset_pin_stay_unknown(monkeypatch):
    image = old_mapping.MemoryImage()
    _asset, pointer = install(image, old_mapping.GAME_BASE)
    with pytest.raises(common._Unknown):
        mapping.read_mapping(common._Trace(image), old_mapping.GAME_BASE, pointer + 1, phase="before")

    monkeypatch.setattr(mapping, "V47_COUNTRY_MODIFIER_EXPIRY_ASSET_SHA256", "0" * 64)
    with pytest.raises(common._Unknown, match="CHOICE_MAPPING_ASSET_PIN_MISMATCH"):
        mapping._asset("47-country-modifier-expiry")


def test_previous_v46_country_modifier_remove_case_remains_byte_exact():
    v46.test_v46_country_modifier_remove_mapping_is_exact_and_bounded()


def test_v47_mapping_is_accepted_by_the_existing_f03_principal_consumer(monkeypatch):
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
    assert scope["hook_asset_sha256"] == mapping.V47_COUNTRY_MODIFIER_EXPIRY_ASSET_SHA256
    assert scope["accepted_mapping_modes"] == [
        "native_true",
        "installed_observer_gui_forwarding_v47",
    ]

    admitted = projection.project(
        item, "ENG", ["debt"], debt_scope=old_projection._disclosure_scope()
    )["debt"]
    assert admitted["value"]["total_debt"]["value"] == 1055.0
    denied = projection.project(item, "ENG", ["debt"], debt_scope=None)["debt"]
    assert denied["component_statuses"]["total_debt"]["status"] == "unknown"

    altered = deepcopy(permission)
    altered["raw_inputs"]["scope_evidence"]["current_validity_helper_map"]["hook_asset_sha256"] = (
        mapping.V46_COUNTRY_MODIFIER_REMOVE_ASSET_SHA256
    )
    assert not principal.validate_permission(altered)


def test_r16_mapping_and_sampling_profiles_pin_v47_and_keep_prior_assets():
    root = Path(capture.ROOT)
    profile = json.loads(
        (root / "bridge/information/profiles/foreign-economy-memory-1374-v7-r16.json").read_text()
    )
    mapping_profile = json.loads(
        (root / "bridge/information/profiles/foreign-economy-memory-1374-v7-r16.json").read_text()
    )
    sampling_path = root / "bridge/information/profiles/foreign-economy-memory-1374-v7-r16-sampling-r1.json"
    sampling_profile = json.loads(sampling_path.read_text())

    assert sampling_path.name == "foreign-economy-memory-1374-v7-r16-sampling-r1.json"
    sampling_raw = sampling_path.read_bytes()
    assert hashlib.sha256(sampling_raw).hexdigest() == "8671ce58e857b158858eefad95c639e41a7a1f058db750a09a6de84b3e85b3e8"
    assert profile["profile_revision"] == 16
    assert mapping_profile["profile_revision"] == sampling_profile["profile_revision"] == 16
    accepted_modes = profile["target_debt_principal"]["native_ai_accept_scope"][
        "accepted_mapping_modes"
    ]
    assert "installed_observer_gui_forwarding_v47" in accepted_modes
    assert sampling_profile["observation_time_revision"]["previous_profile"].endswith(
        "foreign-economy-memory-1374-v7-r15-sampling-r1.json"
    )

    pins = {row["path"]: row["sha256"] for row in profile["layout_dependencies"]}
    v47_asset_path = "bridge/information/" + mapping.V47_COUNTRY_MODIFIER_EXPIRY_ASSET_RELATIVE_PATH
    assert pins[v47_asset_path] == mapping.V47_COUNTRY_MODIFIER_EXPIRY_ASSET_SHA256
    assert pins["bridge/information/profiles/native-ai-choice-hook-v46-country-modifier-remove.json"] == (
        mapping.V46_COUNTRY_MODIFIER_REMOVE_ASSET_SHA256
    )
    assert pins["bridge/information/profiles/native-ai-choice-hook-v45-country-modifier-add.json"] == (
        mapping.V45_COUNTRY_MODIFIER_ADD_ASSET_SHA256
    )

    manifest_path = "work/runtime/diplomacy-observer-20261109-modifier-expiry-v47-320-001/build-manifest.json"
    review_path = "work/runtime/information-expiry-deployment-20261109-320-001/asset-country-modifier-expiry-evidence-001/pe-review.json"
    source_pins = {row["path"]: row["sha256"] for row in profile["source_evidence"]}
    assert manifest_path in source_pins and review_path in source_pins
    assert source_pins[manifest_path] == "df9757f40e5d08acc3133e96cb1244e9ef34dce9c275ca76f8cddfbc385e1e13"
    assert source_pins[review_path] == "85279a7febb51c6e017762599806fbf60870fcb3f51cb78bc6cf2199e6ee93b4"

    review = json.loads((root / review_path).read_text())
    assert review["evidence_kind"] == "ordinary_pe_coff_pdata_static_review"
    assert review["target"]["sha256"] == mapping.V47_COUNTRY_MODIFIER_EXPIRY_HOOK_DLL_SHA256
    assert review["source_context"]["line_start"] == 840
    assert review["source_context"]["line_end_inclusive"] == 863
    assert review["pdata_function"]["rva_start"] == 0x5D510
    assert review["pdata_function"]["rva_end_exclusive"] == 0x5D99F
    assert review["pdata_function"]["byte_length"] == 1167
    assert review["pdata_function"]["body_sha256"] == "c878f83ec48a8d8483965b4aea3e5cb49954019f02690d494c0f6ee2e7418ecf"

    sections = review["pe_headers"]["sections"]
    asset, _raw = mapping._asset("47-country-modifier-expiry")
    expected = (
        ("game_module_base_global", "_ZL4base", "game_module_base_global_rva", "0xb20ce0", "0x1190ce0"),
        (
            "saved_original_global",
            "_ZN30bridge_alliance_inbound_detailL34inbound_favor_gold_choice_originalE",
            "favor_gold_original_global_rva",
            "0x427e38",
            "0xa97e38",
        ),
    )
    for key, symbol_name, asset_key, expected_value_hex, expected_rva_hex in expected:
        symbol = review["coff_symbols"][key]
        assert symbol["name"] == symbol_name
        section = sections[symbol["section_number"] - 1]
        calculated_rva = section["virtual_address"] + symbol["value_section_relative"]
        assert section["name"] == symbol["section_name"] == ".bss"
        assert symbol["section_virtual_address_hex"] == hex(section["virtual_address"]) == "0x670000"
        assert symbol["value_section_relative_hex"] == hex(symbol["value_section_relative"]) == expected_value_hex
        assert symbol["rva"] == calculated_rva == asset[asset_key]
        assert symbol["rva_hex"] == hex(calculated_rva) == expected_rva_hex

    old_main = root / "bridge/information/profiles/foreign-economy-memory-1374-v7-r15.json"
    old_sample = root / "bridge/information/profiles/foreign-economy-memory-1374-v7-r15-sampling-r1.json"
    assert hashlib.sha256(old_main.read_bytes()).hexdigest() == (
        "4d1b1e8fa09cb49be7ca858b7bfc750eba7d0fd1a6e70ffd1cab091a14124d8d"
    )
    assert hashlib.sha256(old_sample.read_bytes()).hexdigest() == (
        "4c8703c784f5cfd5fbe14c3d255bd11b99621902134131d6582eed23d607d83c"
    )

