"""Exact v45 country-modifier-add GUI forwarding and default F03 pins."""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
from copy import deepcopy

import pytest

from bridge.information import foreign_economy_capture_v7 as capture
from bridge.information import foreign_economy_projection_v7 as projection
from bridge.information import foreign_quality_visibility_memory as common
from bridge.information import native_ai_choice_mapping_memory_v34 as mapping
from bridge.information import target_debt_principal_memory_v34 as principal
from bridge.tests import test_foreign_debt_projection_v34 as old_projection
from bridge.tests import test_native_ai_choice_mapping_memory_v34 as old_mapping
from bridge.tests import test_native_ai_choice_mapping_memory_v41 as v41
from bridge.tests import test_native_ai_choice_mapping_v44 as v44
from bridge.tests import test_target_debt_principal_memory_v34 as old_principal


def install(image, game_base):
    return v41.install(image, game_base, variant="45-country-modifier-add")


def test_v45_country_modifier_add_mapping_is_exact_and_bounded():
    image = old_mapping.MemoryImage()
    asset, pointer = install(image, old_mapping.GAME_BASE)
    trace = common._Trace(image)
    before = mapping.read_mapping(trace, old_mapping.GAME_BASE, pointer, phase="before")
    after = mapping.read_mapping(
        common._Trace(image), old_mapping.GAME_BASE, pointer, phase="after"
    )

    assert before == after
    assert before["mode"] == "installed_observer_gui_forwarding_v45"
    assert before["asset_sha256"] == mapping.V45_COUNTRY_MODIFIER_ADD_ASSET_SHA256
    assert before["dll_sha256_from_asset"] == mapping.V45_COUNTRY_MODIFIER_ADD_HOOK_DLL_SHA256
    assert before["body_rva"] == "0x5ced0"
    assert before["body_raw_hex"] == asset["body_hex"]
    assert before["body_matches_pinned_asset"] is True
    assert before["whole_loaded_dll_hash_verified"] is False
    assert trace.summary()["calls"] == 9
    assert trace.summary()["bytes_requested"] == 1280


@pytest.mark.parametrize(
    "damage", ["dos", "coff", "magic", "image_size", "body", "game_base", "original"]
)
def test_v45_damaged_mapping_stays_unknown(damage):
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


def test_v45_unaligned_pointer_stays_unknown():
    image = old_mapping.MemoryImage()
    _asset, pointer = install(image, old_mapping.GAME_BASE)
    with pytest.raises(common._Unknown):
        mapping.read_mapping(common._Trace(image), old_mapping.GAME_BASE, pointer + 1, phase="before")


def test_previous_v44_capacity_case_remains_byte_exact():
    v44.test_v44_unit_removal_capacity_selects_by_complete_body_and_refreshes_globals()


def test_v45_mapping_is_accepted_by_the_existing_f03_principal_consumer(monkeypatch):
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
    assert scope["hook_asset_sha256"] == mapping.V45_COUNTRY_MODIFIER_ADD_ASSET_SHA256
    assert scope["accepted_mapping_modes"] == [
        "native_true",
        "installed_observer_gui_forwarding_v45",
    ]

    admitted = projection.project(
        item, "ENG", ["debt"], debt_scope=old_projection._disclosure_scope()
    )["debt"]
    assert admitted["value"]["total_debt"]["value"] == 1055.0
    denied = projection.project(item, "ENG", ["debt"], debt_scope=None)["debt"]
    assert denied["component_statuses"]["total_debt"]["status"] == "unknown"

    altered = deepcopy(permission)
    altered["raw_inputs"]["scope_evidence"]["current_validity_helper_map"]["hook_asset_sha256"] = (
        mapping.V44_UNIT_REMOVAL_CAPACITY_ASSET_SHA256
    )
    assert not principal.validate_permission(altered)


def test_r14_mapping_and_sampling_profiles_pin_v45_and_keep_prior_assets():
    root = Path(capture.ROOT)
    profile = capture._load_profile()
    mapping_profile = json.loads(
        (root / "bridge/information/profiles/foreign-economy-memory-1374-v7-r14.json").read_text()
    )
    sampling_profile = json.loads(
        (root / "bridge/information/profiles/foreign-economy-memory-1374-v7-r14-sampling-r1.json").read_text()
    )

    assert profile["profile_revision"] >= 14
    assert mapping_profile["profile_revision"] == sampling_profile["profile_revision"] == 14
    accepted_modes = profile["target_debt_principal"]["native_ai_accept_scope"][
        "accepted_mapping_modes"
    ]
    assert "installed_observer_gui_forwarding_v45" in accepted_modes
    assert sampling_profile["observation_time_revision"]["previous_profile"].endswith(
        "foreign-economy-memory-1374-v7-r13-sampling-r1.json"
    )
    pins = {row["path"]: row["sha256"] for row in profile["layout_dependencies"]}
    v45_asset_path = "bridge/information/" + mapping.V45_COUNTRY_MODIFIER_ADD_ASSET_RELATIVE_PATH
    assert pins[v45_asset_path] == (
        mapping.V45_COUNTRY_MODIFIER_ADD_ASSET_SHA256
    )
    assert pins["bridge/information/profiles/native-ai-choice-hook-v44-unit-removal-retreat-capacity.json"] == (
        mapping.V44_UNIT_REMOVAL_CAPACITY_ASSET_SHA256
    )
    mapping_path = "bridge/information/native_ai_choice_mapping_memory_v34.py"
    mapping_row = next(row for row in profile["layout_dependencies"] if row["path"] == mapping_path)
    mapping_bytes = Path(mapping.__file__).read_bytes()
    assert pins[mapping_path] == hashlib.sha256(mapping_bytes).hexdigest()
    assert mapping_row["bytes"] == len(mapping_bytes)

