"""Pinned own-DLL v41 mapping, candidate replay and public debt admission."""
from copy import deepcopy
import hashlib
import json

import pytest

from bridge.information import foreign_quality_visibility_memory as common
from bridge.information import native_ai_choice_mapping_memory_v34 as mapping
from bridge.information import target_debt_principal_memory_v34 as principal
from bridge.information import foreign_economy_capture_v7 as capture
from bridge.information import foreign_economy_projection_v7 as projection
from bridge.tests import test_native_ai_choice_mapping_memory_v34 as old_mapping
from bridge.tests import test_target_debt_principal_memory_v34 as old_principal
from bridge.tests import test_foreign_debt_projection_v34 as old_projection


def historical_profile(revision):
    expected_sha256 = {
        10: "eaad36450e510cd8b4dcff5c7250f748d24a423e953e5ab0904df8493cc7ccbd",
        13: "a4dbf0b1a2aa5c8fc9971f7252cceefe4e85186736deb628063c6283eb6fc088",
    }[revision]
    path = capture.PROFILE_FILE.with_name(f"foreign-economy-memory-1374-v7-r{revision}.json")
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected_sha256
    profile = json.loads(raw)
    assert profile["profile_revision"] == revision
    return profile


def install(image, game_base, variant=41):
    asset, _raw = mapping._asset(variant)
    base = old_mapping.DLL_BASE
    pe = asset['pe_header_offset']
    image.put(base, bytes.fromhex(asset['dos_prefix_hex']))
    image.put(base + pe, bytes.fromhex(asset['coff_prefix_hex']))
    image.put(base + pe + 24, bytes.fromhex(asset['optional_header_magic_hex']))
    image.put(base + pe + 24 + 56, asset['size_of_image'].to_bytes(4, 'little'))
    pointer = base + asset['body_rva']
    image.put(pointer, bytes.fromhex(asset['body_hex']))
    image.put_u64(base + asset['game_module_base_global_rva'], game_base)
    original = game_base + asset['native_true_predicate_rva']
    image.put_u64(base + asset['favor_gold_original_global_rva'], original)
    image.put(original, bytes.fromhex(asset['native_true_predicate_hex']))
    return asset, pointer


def test_v41_mapping_preserves_budget_and_stable_proof():
    image = old_mapping.MemoryImage()
    asset, pointer = install(image, old_mapping.GAME_BASE)
    first = mapping.read_mapping(common._Trace(image), old_mapping.GAME_BASE, pointer, phase='before')
    trace = common._Trace(image)
    second = mapping.read_mapping(trace, old_mapping.GAME_BASE, pointer, phase='after')
    assert first == second
    assert first['mode'] == 'installed_observer_gui_forwarding_v41'
    assert first['asset_sha256'] == mapping.V41_ASSET_SHA256
    assert first['dll_sha256_from_asset'] == mapping.V41_HOOK_DLL_SHA256
    assert first['body_raw_hex'] == asset['body_hex']
    assert first['whole_loaded_dll_hash_verified'] is False
    assert trace.summary()['calls'] <= 128
    assert trace.summary()['bytes_requested'] <= 65536


@pytest.mark.parametrize('damage', ['body', 'coff', 'global', 'original', 'unaligned'])
def test_v41_unverified_mapping_stays_unknown(damage):
    image = old_mapping.MemoryImage()
    asset, pointer = install(image, old_mapping.GAME_BASE)
    if damage == 'body':
        image.put(pointer, b'\0')
    elif damage == 'coff':
        image.put(old_mapping.DLL_BASE + asset['pe_header_offset'], b'\0')
    elif damage == 'global':
        image.put_u64(old_mapping.DLL_BASE + asset['game_module_base_global_rva'], 0)
    elif damage == 'original':
        image.put_u64(old_mapping.DLL_BASE + asset['favor_gold_original_global_rva'], 0)
    else:
        pointer += 1
    with pytest.raises(common._Unknown):
        mapping.read_mapping(common._Trace(image), old_mapping.GAME_BASE, pointer, phase='before')


def test_v41_permission_and_leaf_replay_reach_the_public_total_only_with_scope(monkeypatch):
    original_environment = old_principal._environment

    def environment(**kwargs):
        image, observer, target = original_environment(**kwargs)
        _asset, pointer = install(image, old_principal.BASE)
        image.put_u64(old_principal.BASE + principal.CURRENT_VALIDITY_HELPER_CELL_RVA, pointer)
        return image, observer, target

    monkeypatch.setattr(old_principal, '_environment', environment)
    item = old_projection._v34_item()
    permission = item['fields'][principal.FIELD]['raw_inputs']['permission']
    assert principal.validate_permission(permission)
    scope = permission['raw_inputs']['scope_evidence']['current_validity_helper_map']
    assert scope['hook_asset_sha256'] == mapping.V41_ASSET_SHA256
    assert 'installed_observer_gui_forwarding_v41' in scope['accepted_mapping_modes']
    result = projection.project(item, 'ENG', ['debt'], debt_scope=old_projection._disclosure_scope())['debt']
    assert result['value']['total_debt']['value'] == 1055.0
    assert result['value']['total_debt']['includes_remaining_interest'] is False
    text = repr(result)
    assert 'raw_inputs' not in text and 'fullref' not in text
    denied = projection.project(item, 'ENG', ['debt'], debt_scope=None)['debt']
    assert denied['component_statuses']['total_debt']['status'] == 'unknown'
    altered = deepcopy(permission)
    altered['raw_inputs']['scope_evidence']['current_validity_helper_map']['hook_asset_sha256'] = '0' * 64
    assert not principal.validate_permission(altered)


def test_current_and_historical_economy_profiles_keep_v41_asset():
    current = capture._load_profile()
    assert current['profile_revision'] == 27
    profile = historical_profile(10)
    assert profile['profile_revision'] == 10
    records = profile['layout_dependencies']
    assert any(row['path'].endswith('native-ai-choice-hook-v41.json')
               and row['sha256'] == mapping.V41_ASSET_SHA256 for row in records)
    assert any(row['path'].endswith('native-ai-choice-hook-v41.json')
               and row['sha256'] == mapping.V41_ASSET_SHA256
               for row in current['layout_dependencies'])
