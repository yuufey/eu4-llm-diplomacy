"""Exact v61 shared-entry variant and r27 default F03 checks."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from bridge.information import foreign_economy_capture_v7 as capture
from bridge.information import foreign_quality_visibility_memory as common
from bridge.information import native_ai_choice_mapping_memory_v34 as mapping
from bridge.tests import test_native_ai_choice_mapping_memory_v34 as old_mapping
from bridge.tests import test_native_ai_choice_mapping_memory_v41 as v41


ROOT = Path(capture.ROOT)
STAGE = ROOT / "work/runtime/information-rival-release-20261110-360-001"
BUILD = ROOT / "work/runtime/diplomacy-observer-20261110-rival-record-v61-360-003"
ASSET_PATH = ROOT / "bridge/information/profiles/native-ai-choice-hook-v61-rival-shared-entry.json"
OLD_ASSET_PATH = ROOT / "bridge/information/profiles/native-ai-choice-hook-v61-rival-record.json"
R26_MAIN = ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r26.json"
R26_SAMPLE = ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r26-sampling-r1.json"
R27_MAIN = ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r27.json"
R27_SAMPLE = ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r27-sampling-r1.json"
PE_REVIEW = STAGE / "pe-review-v61-shared-mission-and-f03.json"
ASSET_REVIEW = STAGE / "f03-shared-asset-review-v61.json"
MANIFEST = BUILD / "build-manifest.json"
RELEASE = STAGE / "corrective-release-summary.json"

ASSET_SHA256 = "a8a27a8759e048397c21ec7b1569792e2295f04abe77cde1199f87d8b72b8c71"
OLD_ASSET_SHA256 = "97c9b4a50996c71b27483dc7b1452b0c079b8462a9816188c67036d096e6b4e1"
DLL_SHA256 = "5d3a679afde7a1069b69024e47210fd0841736877e0f63a1ee89f6a722513fb6"
MANIFEST_SHA256 = "5bfdd346d064f885d9f780c3a2a47ab1d3fd2a00adc6ed4b2f2891b1c0f2dd18"
PE_REVIEW_SHA256 = "b7ffde7cc70e59ce37db544bd9df60def55661ffc73c877afa6af06409784fae"
RELEASE_SHA256 = "204ec059bd8b7e0216d18b8dfd67ed69400a5dc0141562b0398fc29ab4de96ce"
R26_MAIN_SHA256 = "b3606cf291d42e369b6671099262e6fd566d5e47b2ed98a3eed6c2da91284d4d"
R26_SAMPLE_SHA256 = "15faed520df4ec9ee4ce7307c7d58b7811d43ecab867b7ec14f2be9abfcd3966"
R27_MAIN_SHA256 = "9d7f09334ac9abcda4b64bb185ac4da8c11f2023d0eca4a8c6b106cc8f14da3d"
R27_SAMPLE_SHA256 = "e777a56bc723154d0f07e20c2b18158c9277b57f613a28b88f20e36b9bad4e04"


def install_shared(image, game_base):
    return v41.install(image, game_base, variant="61-rival-shared-entry")


def test_shared_entry_asset_matches_exact_body_unwind_and_globals():
    asset, raw = mapping._asset("61-rival-shared-entry")
    review_raw = PE_REVIEW.read_bytes()
    review = json.loads(review_raw)
    manifest_raw = MANIFEST.read_bytes()
    manifest = json.loads(manifest_raw.decode("utf-8-sig"))
    forwarder = review["f03_gui_forwarder"]
    function = forwarder["function"]
    asset_review = json.loads(ASSET_REVIEW.read_text(encoding="utf-8"))

    assert hashlib.sha256(raw).hexdigest() == ASSET_SHA256
    assert asset["hook_asset_tag"] == "61-rival-shared-entry"
    assert asset["dll_sha256"] == mapping.V61_RIVAL_SHARED_ENTRY_HOOK_DLL_SHA256 == DLL_SHA256
    assert asset["body_rva"] == mapping.V61_RIVAL_SHARED_ENTRY_HOOK_POINTER_DELTA == 414144
    assert asset["body_rva"] == function["rva_start"] == function["symbol"]["rva"]
    assert asset["body_end_rva_exclusive"] == function["rva_end_exclusive"]
    assert asset["body_sha256"] == function["body_sha256"]
    assert asset["favor_gold_original_global_rva"] == forwarder["saved_original_global"]["rva"]
    assert asset["body_rva"] != asset["favor_gold_original_global_rva"]
    assert asset["game_module_base_global_rva"] == forwarder["game_module_base_global"]["rva"]
    assert asset_review["forwarder"]["unwind_rva"] == function["unwind_rva"]
    assert asset_review["forwarder"]["unwind_raw_hex"] == function["unwind_raw_hex"]
    assert hashlib.sha256(OLD_ASSET_PATH.read_bytes()).hexdigest() == OLD_ASSET_SHA256
    assert asset_review["previous_asset"]["unchanged"] is True
    assert manifest["version"] == 61 and len(manifest["sources"]) == 189
    assert hashlib.sha256(manifest_raw).hexdigest() == MANIFEST_SHA256
    assert hashlib.sha256(review_raw).hexdigest() == PE_REVIEW_SHA256
    assert review["target"]["dll_sha256"] == DLL_SHA256
    assert review["runtime_observation"] is False and review["rea_evidence_id"] is None


def test_shared_entry_and_rival_record_select_distinct_assets_with_the_same_mode():
    shared_image = old_mapping.MemoryImage()
    shared_asset, shared_pointer = install_shared(shared_image, old_mapping.GAME_BASE)
    shared = mapping.read_mapping(
        common._Trace(shared_image), old_mapping.GAME_BASE, shared_pointer, phase="before"
    )
    old_image = old_mapping.MemoryImage()
    old_asset, old_pointer = v41.install(
        old_image, old_mapping.GAME_BASE, variant="61-rival-record"
    )
    old = mapping.read_mapping(
        common._Trace(old_image), old_mapping.GAME_BASE, old_pointer, phase="before"
    )

    assert shared["mode"] == old["mode"] == "installed_observer_gui_forwarding_v61"
    assert shared["asset_sha256"] == ASSET_SHA256
    assert old["asset_sha256"] == OLD_ASSET_SHA256
    assert shared_asset["hook_asset_tag"] == "61-rival-shared-entry"
    assert old_asset["hook_asset_tag"] == "61-rival-record"
    assert shared_pointer == old_mapping.DLL_BASE + 414144
    assert old_pointer == old_mapping.DLL_BASE + 415104
    assert (old_pointer - shared_pointer) == 960
    assert (old_pointer - shared_pointer) % 0x10000 != 0


@pytest.mark.parametrize("damage", ["body", "pointer"])
def test_shared_entry_damage_fails_closed(damage):
    image = old_mapping.MemoryImage()
    _asset, pointer = install_shared(image, old_mapping.GAME_BASE)
    if damage == "body":
        image.put(pointer, b"\0")
    else:
        pointer += 1
    with pytest.raises(common._Unknown):
        mapping.read_mapping(common._Trace(image), old_mapping.GAME_BASE, pointer, phase="before")


def test_shared_entry_asset_pin_mismatch_fails_closed(monkeypatch):
    monkeypatch.setattr(mapping, "V61_RIVAL_SHARED_ENTRY_ASSET_SHA256", "0" * 64)
    with pytest.raises(common._Unknown, match="CHOICE_MAPPING_ASSET_PIN_MISMATCH"):
        mapping._asset("61-rival-shared-entry")


def test_r27_is_default_and_r26_profiles_remain_unchanged():
    profile = capture._load_profile()
    main = json.loads(R27_MAIN.read_text(encoding="utf-8"))
    sample = json.loads(R27_SAMPLE.read_text(encoding="utf-8"))
    assert hashlib.sha256(R26_MAIN.read_bytes()).hexdigest() == R26_MAIN_SHA256
    assert hashlib.sha256(R26_SAMPLE.read_bytes()).hexdigest() == R26_SAMPLE_SHA256
    assert hashlib.sha256(R27_MAIN.read_bytes()).hexdigest() == R27_MAIN_SHA256
    assert hashlib.sha256(R27_SAMPLE.read_bytes()).hexdigest() == capture.PROFILE_SHA256 == R27_SAMPLE_SHA256
    assert capture.PROFILE_FILE == R27_SAMPLE
    assert profile["profile_revision"] == main["profile_revision"] == sample["profile_revision"] == 27
    assert sample["observation_time_revision"]["previous_profile"].endswith(
        "foreign-economy-memory-1374-v7-r26-sampling-r1.json"
    )
    accepted = main["target_debt_principal"]["native_ai_accept_scope"]["accepted_mapping_modes"]
    assert accepted.count("installed_observer_gui_forwarding_v61") == 1
    assert sample["target_debt_principal"]["native_ai_accept_scope"]["accepted_mapping_modes"] == accepted
    layout = {row["path"]: row["sha256"] for row in main["layout_dependencies"]}
    sources = {row["path"]: row["sha256"] for row in main["source_evidence"]}
    assert layout[ASSET_PATH.relative_to(ROOT).as_posix()] == ASSET_SHA256
    assert layout["bridge/information/native_ai_choice_mapping_memory_v34.py"] == hashlib.sha256(
        (ROOT / "bridge/information/native_ai_choice_mapping_memory_v34.py").read_bytes()
    ).hexdigest()
    assert layout["bridge/information/target_debt_principal_memory_v34.py"] == hashlib.sha256(
        (ROOT / "bridge/information/target_debt_principal_memory_v34.py").read_bytes()
    ).hexdigest()
    assert sources[MANIFEST.relative_to(ROOT).as_posix()] == MANIFEST_SHA256
    assert sources[PE_REVIEW.relative_to(ROOT).as_posix()] == PE_REVIEW_SHA256
    assert sources[RELEASE.relative_to(ROOT).as_posix()] == RELEASE_SHA256
