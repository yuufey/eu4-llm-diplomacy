"""Exact v61 directed F03 GUI-forwarder and default-profile compatibility checks."""
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
STAGE = ROOT / "work/runtime/information-rival-release-20261110-360-001"
ASSET_PATH = ROOT / "bridge/information/profiles/native-ai-choice-hook-v61-rival-record.json"
R24_MAIN = ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r24.json"
R24_SAMPLE = ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r24-sampling-r1.json"
R25_MAIN = ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r25.json"
R25_SAMPLE = ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r25-sampling-r1.json"
R27_MAIN = ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r27.json"
R27_SAMPLE = ROOT / "bridge/information/profiles/foreign-economy-memory-1374-v7-r27-sampling-r1.json"
PE_REVIEW = STAGE / "pe-review-v61-mission-and-f03.json"
MANIFEST = ROOT / "work/runtime/diplomacy-observer-20261110-rival-record-v61-360-001/build-manifest.json"
EXPECTED_ASSET_SHA256 = "97c9b4a50996c71b27483dc7b1452b0c079b8462a9816188c67036d096e6b4e1"
EXPECTED_R24_MAIN_SHA256 = "326f0120609b118ab157edf311a5bfa7c4f7ab1abfd0f886aafbf5b8fac23383"
EXPECTED_R24_SAMPLE_SHA256 = "981094fbb644ee5877d8faa054bdacdb670d979b2012f757e21a4a4dd67a04b6"
EXPECTED_R25_MAIN_SHA256 = "ca50c0a4a056930d26663be03b1ff6d83537a0fb29e9f0c8ad2c993fd7cfc3f8"
EXPECTED_R25_SAMPLE_SHA256 = "2aa7f02cdbe41455c03a079ef781e538ca42381714f676b92f5e5024d0db525f"
EXPECTED_R27_MAIN_SHA256 = "9d7f09334ac9abcda4b64bb185ac4da8c11f2023d0eca4a8c6b106cc8f14da3d"
EXPECTED_R27_SAMPLE_SHA256 = "e777a56bc723154d0f07e20c2b18158c9277b57f613a28b88f20e36b9bad4e04"
EXPECTED_PE_REVIEW_SHA256 = "668eadf957e1e04ceb768caa4032bdb4fc2378378612b2d212c7e90fc0778364"
EXPECTED_MANIFEST_SHA256 = "2d6b73caeffa7f687b6c5aaf085e53d2996adbb30898b13a8bc06b299cdf8860"
EXPECTED_DLL_SHA256 = "41079eae93a825c48428defff2430aa0a17707c92bb020fb2f0e77952cd5efc1"


def install_v61(image, game_base):
    return v41.install(image, game_base, variant="61-rival-record")


def test_v61_asset_is_pinned_to_forwarder_body_rva_not_saved_original_global():
    asset, raw = mapping._asset("61-rival-record")
    review_raw = PE_REVIEW.read_bytes()
    review = json.loads(review_raw)
    manifest_raw = MANIFEST.read_bytes()
    manifest = json.loads(manifest_raw.decode("utf-8-sig"))
    forwarder = review["f03_gui_forwarder"]
    function = forwarder["function"]

    assert hashlib.sha256(raw).hexdigest() == EXPECTED_ASSET_SHA256
    assert asset["hook_asset_tag"] == "61-rival-record"
    assert asset["dll_sha256"] == mapping.V61_RIVAL_RECORD_HOOK_DLL_SHA256 == EXPECTED_DLL_SHA256
    assert asset["body_rva"] == mapping.V61_RIVAL_RECORD_HOOK_POINTER_DELTA
    assert asset["body_rva"] == function["rva_start"] == function["symbol"]["rva"]
    assert asset["body_end_rva_exclusive"] == function["rva_end_exclusive"]
    assert asset["body_sha256"] == function["body_sha256"]
    assert asset["favor_gold_original_global_rva"] == forwarder["saved_original_global"]["rva"]
    assert asset["body_rva"] != asset["favor_gold_original_global_rva"]
    assert asset["game_module_base_global_rva"] == forwarder["game_module_base_global"]["rva"]
    assert function["static_va_start"] == review["pe"]["preferred_image_base"] + asset["body_rva"]
    asset_review = json.loads((STAGE / "f03-asset-review-v61.json").read_text(encoding="utf-8"))
    assert asset_review["forwarder"]["unwind_rva"] == function["unwind_rva"]
    assert asset_review["forwarder"]["unwind_raw_hex"] == function["unwind_raw_hex"]
    assert asset_review["pe_base_relocation_inventory"] == review["pe_base_relocation_inventory"]
    assert manifest["version"] == 61 and len(manifest["sources"]) == 189
    assert hashlib.sha256(manifest_raw).hexdigest() == EXPECTED_MANIFEST_SHA256
    assert hashlib.sha256(review_raw).hexdigest() == EXPECTED_PE_REVIEW_SHA256
    assert review["target"]["game_executable_sha256"] == mapping.EXPECTED_EXE_SHA256
    assert review["target"]["source_count"] == 189
    assert review["source_manifest_verification"]["files_verified_against_sha256"] == 189
    assert review["source_manifest_verification"]["mismatches"] == []
    assert review["runtime_observation"] is False and review["rea_evidence_id"] is None


def test_v61_mapping_is_stable_and_reads_the_exact_forwarder_contract():
    image = old_mapping.MemoryImage()
    asset, pointer = install_v61(image, old_mapping.GAME_BASE)
    before = mapping.read_mapping(
        common._Trace(image), old_mapping.GAME_BASE, pointer, phase="before"
    )
    after_trace = common._Trace(image)
    after = mapping.read_mapping(
        after_trace, old_mapping.GAME_BASE, pointer, phase="after"
    )

    assert before == after
    assert before["mode"] == "installed_observer_gui_forwarding_v61"
    assert before["asset_sha256"] == EXPECTED_ASSET_SHA256
    assert before["dll_sha256_from_asset"] == EXPECTED_DLL_SHA256
    assert before["actual_pointer"] == hex(old_mapping.DLL_BASE + asset["body_rva"])
    assert before["body_rva"] == hex(asset["body_rva"])
    assert before["body_raw_hex"] == asset["body_hex"]
    assert before["body_matches_pinned_asset"] is True
    assert before["whole_loaded_dll_hash_verified"] is False
    assert after_trace.summary()["calls"] <= 128
    assert after_trace.summary()["bytes_requested"] <= 65536


@pytest.mark.parametrize("damage", ["body", "dos", "coff", "image_size", "module_base", "original", "pointer"])
def test_v61_damaged_hook_or_pointer_fails_closed(damage):
    image = old_mapping.MemoryImage()
    asset, pointer = install_v61(image, old_mapping.GAME_BASE)
    if damage == "body":
        image.put(pointer, b"\0")
    elif damage == "dos":
        image.put(old_mapping.DLL_BASE, b"\0")
    elif damage == "coff":
        image.put(old_mapping.DLL_BASE + asset["pe_header_offset"], b"\0")
    elif damage == "image_size":
        image.put_u32(old_mapping.DLL_BASE + asset["pe_header_offset"] + 24 + 56, 0)
    elif damage == "module_base":
        image.put_u64(old_mapping.DLL_BASE + asset["game_module_base_global_rva"], 0)
    elif damage == "original":
        image.put_u64(old_mapping.DLL_BASE + asset["favor_gold_original_global_rva"], 0)
    else:
        pointer += 1
    with pytest.raises(common._Unknown):
        mapping.read_mapping(common._Trace(image), old_mapping.GAME_BASE, pointer, phase="before")


def test_v61_asset_pin_mismatch_fails_closed(monkeypatch):
    monkeypatch.setattr(mapping, "V61_RIVAL_RECORD_ASSET_SHA256", "0" * 64)
    with pytest.raises(common._Unknown, match="CHOICE_MAPPING_ASSET_PIN_MISMATCH"):
        mapping._asset("61-rival-record")


def test_v61_principal_consumer_maps_exact_mode_to_61(monkeypatch):
    original_environment = old_principal._environment

    def environment(**kwargs):
        image, observer, target = original_environment(**kwargs)
        _asset, pointer = install_v61(image, old_principal.BASE)
        image.put_u64(old_principal.BASE + principal.CURRENT_VALIDITY_HELPER_CELL_RVA, pointer)
        return image, observer, target

    monkeypatch.setattr(old_principal, "_environment", environment)
    item = old_projection._v34_item()
    permission = item["fields"][principal.FIELD]["raw_inputs"]["permission"]
    assert principal.validate_permission(permission)
    scope = permission["raw_inputs"]["scope_evidence"]["current_validity_helper_map"]
    assert scope["hook_asset_sha256"] == EXPECTED_ASSET_SHA256
    assert scope["accepted_mapping_modes"] == [
        "native_true",
        "installed_observer_gui_forwarding_v61",
    ]
    admitted = projection.project(
        item, "ENG", ["debt"], debt_scope=old_projection._disclosure_scope()
    )["debt"]
    assert admitted["value"]["total_debt"]["value"] == 1055.0
    denied = projection.project(item, "ENG", ["debt"], debt_scope=None)["debt"]
    assert denied["component_statuses"]["total_debt"]["status"] == "unknown"


def test_r27_is_the_pinned_default_and_preserves_r26_history():
    profile = capture._load_profile()
    main = json.loads(R27_MAIN.read_text(encoding="utf-8"))
    sample = json.loads(R27_SAMPLE.read_text(encoding="utf-8"))
    assert hashlib.sha256(R24_MAIN.read_bytes()).hexdigest() == EXPECTED_R24_MAIN_SHA256
    assert hashlib.sha256(R24_SAMPLE.read_bytes()).hexdigest() == EXPECTED_R24_SAMPLE_SHA256
    assert hashlib.sha256(R25_MAIN.read_bytes()).hexdigest() == EXPECTED_R25_MAIN_SHA256
    assert hashlib.sha256(R25_SAMPLE.read_bytes()).hexdigest() == EXPECTED_R25_SAMPLE_SHA256
    assert hashlib.sha256(R27_MAIN.read_bytes()).hexdigest() == EXPECTED_R27_MAIN_SHA256
    assert hashlib.sha256(R27_SAMPLE.read_bytes()).hexdigest() == EXPECTED_R27_SAMPLE_SHA256
    assert capture.PROFILE_FILE == R27_SAMPLE
    assert profile["profile_revision"] == main["profile_revision"] == sample["profile_revision"] == 27
    assert sample["observation_time_revision"]["previous_profile"].endswith(
        "foreign-economy-memory-1374-v7-r26-sampling-r1.json"
    )
    accepted = main["target_debt_principal"]["native_ai_accept_scope"][
        "accepted_mapping_modes"
    ]
    assert accepted[-1] == "installed_observer_gui_forwarding_v61"
    assert all(f"installed_observer_gui_forwarding_v{version}" in accepted
               for version in (55, 56, 57, 58, 59, 60, 61))
    assert sample["target_debt_principal"]["native_ai_accept_scope"][
        "accepted_mapping_modes"
    ] == accepted
    layout = {row["path"]: row["sha256"] for row in main["layout_dependencies"]}
    sources = {row["path"]: row["sha256"] for row in main["source_evidence"]}
    assert layout[ASSET_PATH.relative_to(ROOT).as_posix()] == EXPECTED_ASSET_SHA256
    assert layout["bridge/information/native_ai_choice_mapping_memory_v34.py"] == hashlib.sha256(
        (ROOT / "bridge/information/native_ai_choice_mapping_memory_v34.py").read_bytes()
    ).hexdigest()
    assert layout["bridge/information/target_debt_principal_memory_v34.py"] == hashlib.sha256(
        (ROOT / "bridge/information/target_debt_principal_memory_v34.py").read_bytes()
    ).hexdigest()
    assert sources[MANIFEST.relative_to(ROOT).as_posix()] == EXPECTED_MANIFEST_SHA256
    assert sources[PE_REVIEW.relative_to(ROOT).as_posix()] == EXPECTED_PE_REVIEW_SHA256


@pytest.mark.parametrize("dependency", ["asset", "review", "manifest", "mapping", "principal"])
def test_r27_loader_checks_fixed_dependencies_and_retains_python_references(monkeypatch, dependency):
    paths = {
        "asset": ASSET_PATH,
        "review": PE_REVIEW,
        "manifest": MANIFEST,
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
