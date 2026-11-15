"""Exact GUI mapping for the v41 expiry candidate and its debt replay."""
from copy import deepcopy

import pytest

from bridge.information import foreign_quality_visibility_memory as common
from bridge.information import native_ai_choice_mapping_memory_v34 as mapping
from bridge.information import target_debt_principal_memory_v34 as principal
from bridge.information import foreign_economy_capture_v7 as capture
from bridge.information import foreign_economy_projection_v7 as projection
from bridge.tests import test_native_ai_choice_mapping_memory_v34 as old_mapping
from bridge.tests import test_native_ai_choice_mapping_memory_v41 as v41
from bridge.tests import test_target_debt_principal_memory_v34 as old_principal
from bridge.tests import test_foreign_debt_projection_v34 as old_projection


def install(image, game_base):
    return v41.install(image, game_base, variant='41-expiry')


def test_expiry_build_mapping_retains_actual_asset_and_stable_trace():
    image = old_mapping.MemoryImage()
    asset, pointer = install(image, old_mapping.GAME_BASE)
    trace = common._Trace(image)
    before = mapping.read_mapping(trace, old_mapping.GAME_BASE, pointer, phase='before')
    after = mapping.read_mapping(common._Trace(image), old_mapping.GAME_BASE, pointer, phase='after')
    assert before == after
    assert before['mode'] == 'installed_observer_gui_forwarding_v41'
    assert before['asset_sha256'] == mapping.V41_EXPIRY_ASSET_SHA256
    assert before['dll_sha256_from_asset'] == mapping.V41_EXPIRY_HOOK_DLL_SHA256
    assert before['body_raw_hex'] == asset['body_hex']
    assert before['whole_loaded_dll_hash_verified'] is False
    assert trace.summary()['calls'] <= 128
    assert trace.summary()['bytes_requested'] <= 65536


@pytest.mark.parametrize('damage', ['body', 'coff', 'global', 'original', 'unaligned'])
def test_expiry_build_rejects_damaged_mapping(damage):
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


def test_expiry_build_permission_replay_and_foreign_public_scope(monkeypatch):
    original = old_principal._environment

    def environment(**kwargs):
        image, observer, target = original(**kwargs)
        _asset, pointer = install(image, old_principal.BASE)
        image.put_u64(old_principal.BASE + principal.CURRENT_VALIDITY_HELPER_CELL_RVA, pointer)
        return image, observer, target

    monkeypatch.setattr(old_principal, '_environment', environment)
    item = old_projection._v34_item()
    permission = item['fields'][principal.FIELD]['raw_inputs']['permission']
    assert principal.validate_permission(permission)
    scope = permission['raw_inputs']['scope_evidence']['current_validity_helper_map']
    assert scope['hook_asset_sha256'] == mapping.V41_EXPIRY_ASSET_SHA256
    result = projection.project(item, 'ENG', ['debt'], debt_scope=old_projection._disclosure_scope())['debt']
    assert result['value']['total_debt']['value'] == 1055.0
    denied = projection.project(item, 'ENG', ['debt'], debt_scope=None)['debt']
    assert denied['component_statuses']['total_debt']['status'] == 'unknown'
    altered = deepcopy(permission)
    altered['raw_inputs']['scope_evidence']['current_validity_helper_map']['hook_asset_sha256'] = mapping.V41_ASSET_SHA256
    assert not principal.validate_permission(altered)


def test_profile_pins_the_expiry_build_asset():
    current = capture._load_profile()
    assert current['profile_revision'] == 27
    profile = v41.historical_profile(10)
    assert profile['profile_revision'] == 10
    assert any(row['path'].endswith('native-ai-choice-hook-v41-expiry.json')
               and row['sha256'] == mapping.V41_EXPIRY_ASSET_SHA256
               for row in profile['layout_dependencies'])
