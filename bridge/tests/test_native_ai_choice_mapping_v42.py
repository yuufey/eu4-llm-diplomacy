"""Pinned v42 GUI forwarding, private principal replay and public scope."""
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
    return v41.install(image, game_base, variant=42)


def test_v42_exact_mapping_preserves_bounded_reads_and_stable_proof():
    image = old_mapping.MemoryImage()
    asset, pointer = install(image, old_mapping.GAME_BASE)
    trace = common._Trace(image)
    before = mapping.read_mapping(trace, old_mapping.GAME_BASE, pointer, phase='before')
    after = mapping.read_mapping(common._Trace(image), old_mapping.GAME_BASE, pointer, phase='after')
    assert before == after
    assert before['mode'] == 'installed_observer_gui_forwarding_v42'
    assert before['asset_sha256'] == mapping.V42_ASSET_SHA256
    assert before['dll_sha256_from_asset'] == mapping.V42_HOOK_DLL_SHA256
    assert before['body_raw_hex'] == asset['body_hex']
    assert before['whole_loaded_dll_hash_verified'] is False
    assert trace.summary()['calls'] == 9
    assert trace.summary()['bytes_requested'] == 1280


@pytest.mark.parametrize('damage', ['body', 'coff', 'image_size', 'global', 'original', 'unaligned'])
def test_v42_damaged_mapping_remains_unknown(damage):
    image = old_mapping.MemoryImage()
    asset, pointer = install(image, old_mapping.GAME_BASE)
    if damage == 'body':
        image.put(pointer, b'\0')
    elif damage == 'coff':
        image.put(old_mapping.DLL_BASE + asset['pe_header_offset'], b'\0')
    elif damage == 'image_size':
        image.put(old_mapping.DLL_BASE + asset['pe_header_offset'] + 24 + 56, b'\0' * 4)
    elif damage == 'global':
        image.put_u64(old_mapping.DLL_BASE + asset['game_module_base_global_rva'], 0)
    elif damage == 'original':
        image.put_u64(old_mapping.DLL_BASE + asset['favor_gold_original_global_rva'], 0)
    else:
        pointer += 1
    with pytest.raises(common._Unknown):
        mapping.read_mapping(common._Trace(image), old_mapping.GAME_BASE, pointer, phase='before')


def test_v42_permission_replay_and_foreign_disclosure_stay_independent(monkeypatch):
    original = old_principal._environment

    def environment(**kwargs):
        image, observer, target = original(**kwargs)
        _, pointer = install(image, old_principal.BASE)
        image.put_u64(old_principal.BASE + principal.CURRENT_VALIDITY_HELPER_CELL_RVA, pointer)
        return image, observer, target

    monkeypatch.setattr(old_principal, '_environment', environment)
    item = old_projection._v34_item()
    permission = item['fields'][principal.FIELD]['raw_inputs']['permission']
    assert principal.validate_permission(permission)
    scope = permission['raw_inputs']['scope_evidence']['current_validity_helper_map']
    assert scope['hook_asset_sha256'] == mapping.V42_ASSET_SHA256
    assert scope['accepted_mapping_modes'] == ['native_true', 'installed_observer_gui_forwarding_v42']
    field = projection.project(item, 'ENG', ['debt'], debt_scope=old_projection._disclosure_scope())['debt']
    assert field['value']['total_debt']['value'] == 1055.0
    denied = projection.project(item, 'ENG', ['debt'], debt_scope=None)['debt']
    assert denied['component_statuses']['total_debt']['status'] == 'unknown'
    altered = deepcopy(permission)
    altered['raw_inputs']['scope_evidence']['current_validity_helper_map']['hook_asset_sha256'] = mapping.V41_RESULT_DATE_ASSET_SHA256
    assert not principal.validate_permission(altered)


def test_current_revision_retains_old_assets_and_pins_the_new_exact_asset():
    current = capture._load_profile()
    assert current['profile_revision'] == 27
    profile = v41.historical_profile(10)
    assert profile['profile_revision'] == 10
    pins = {row['path']: row['sha256'] for row in profile['layout_dependencies']}
    for path, expected in (
        (mapping.V41_ASSET_RELATIVE_PATH, mapping.V41_ASSET_SHA256),
        (mapping.V41_EXPIRY_ASSET_RELATIVE_PATH, mapping.V41_EXPIRY_ASSET_SHA256),
        (mapping.V41_PEACE_RETURN_ASSET_RELATIVE_PATH, mapping.V41_PEACE_RETURN_ASSET_SHA256),
        (mapping.V41_RESULT_DATE_ASSET_RELATIVE_PATH, mapping.V41_RESULT_DATE_ASSET_SHA256),
        (mapping.V42_ASSET_RELATIVE_PATH, mapping.V42_ASSET_SHA256),
    ):
        assert pins['bridge/information/' + path] == expected
