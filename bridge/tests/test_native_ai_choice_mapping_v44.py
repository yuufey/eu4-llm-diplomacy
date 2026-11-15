"""Pinned v44 GUI forwarding, private principal replay and public scope."""
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
    return v41.install(image, game_base, variant=44)


def install_router_origin(image, game_base):
    return v41.install(image, game_base, variant='44-router-origin')


def install_fragment_retry(image, game_base):
    return v41.install(image, game_base, variant='44-fragment-retry')


def install_ui_cleanup(image, game_base):
    return v41.install(image, game_base, variant='44-ui-cleanup')


def install_unit_removal(image, game_base):
    return v41.install(image, game_base, variant='44-unit-removal-retreat')


def install_unit_removal_capacity(image, game_base):
    return v41.install(image, game_base, variant='44-unit-removal-retreat-capacity')


def test_v44_exact_mapping_preserves_bounded_reads_and_stable_proof():
    image = old_mapping.MemoryImage()
    asset, pointer = install(image, old_mapping.GAME_BASE)
    trace = common._Trace(image)
    before = mapping.read_mapping(trace, old_mapping.GAME_BASE, pointer, phase='before')
    after = mapping.read_mapping(common._Trace(image), old_mapping.GAME_BASE, pointer, phase='after')
    assert before == after
    assert before['mode'] == 'installed_observer_gui_forwarding_v44'
    assert before['asset_sha256'] == mapping.V44_ASSET_SHA256
    assert before['dll_sha256_from_asset'] == mapping.V44_HOOK_DLL_SHA256
    assert before['body_raw_hex'] == asset['body_hex']
    assert before['whole_loaded_dll_hash_verified'] is False
    assert trace.summary()['calls'] == 9
    assert trace.summary()['bytes_requested'] == 1280


def test_v44_router_origin_exact_mapping_preserves_bounded_reads_and_stable_proof():
    image = old_mapping.MemoryImage()
    asset, pointer = install_router_origin(image, old_mapping.GAME_BASE)
    trace = common._Trace(image)
    before = mapping.read_mapping(trace, old_mapping.GAME_BASE, pointer, phase='before')
    after = mapping.read_mapping(common._Trace(image), old_mapping.GAME_BASE, pointer, phase='after')
    assert before == after
    assert before['mode'] == 'installed_observer_gui_forwarding_v44'
    assert before['asset_sha256'] == mapping.V44_ROUTER_ORIGIN_ASSET_SHA256
    assert before['dll_sha256_from_asset'] == mapping.V44_ROUTER_ORIGIN_HOOK_DLL_SHA256
    assert before['body_rva'] == '0x5c620'
    assert before['body_raw_hex'] == asset['body_hex']
    assert before['whole_loaded_dll_hash_verified'] is False
    assert trace.summary()['calls'] == 9
    assert trace.summary()['bytes_requested'] == 1280


def test_v44_fragment_retry_exact_mapping_selects_candidate_asset():
    image = old_mapping.MemoryImage()
    asset, pointer = install_fragment_retry(image, old_mapping.GAME_BASE)
    trace = common._Trace(image)
    proof = mapping.read_mapping(trace, old_mapping.GAME_BASE, pointer, phase='before')
    assert proof['mode'] == 'installed_observer_gui_forwarding_v44'
    assert proof['asset_sha256'] == mapping.V44_FRAGMENT_RETRY_ASSET_SHA256
    assert proof['dll_sha256_from_asset'] == mapping.V44_FRAGMENT_RETRY_HOOK_DLL_SHA256
    assert proof['body_rva'] == '0x5c620'
    assert proof['body_raw_hex'] == asset['body_hex']
    assert proof['whole_loaded_dll_hash_verified'] is False
    assert trace.summary()['calls'] == 9
    assert trace.summary()['bytes_requested'] == 1280


def test_v44_ui_cleanup_exact_mapping_selects_by_headers_and_complete_body():
    image = old_mapping.MemoryImage()
    asset, pointer = install_ui_cleanup(image, old_mapping.GAME_BASE)
    trace = common._Trace(image)
    proof = mapping.read_mapping(trace, old_mapping.GAME_BASE, pointer, phase='before')
    after = mapping.read_mapping(
        common._Trace(image), old_mapping.GAME_BASE, pointer, phase='after')
    assert proof == after
    assert proof['mode'] == 'installed_observer_gui_forwarding_v44'
    assert proof['asset_sha256'] == mapping.V44_UI_CLEANUP_ASSET_SHA256
    assert proof['dll_sha256_from_asset'] == mapping.V44_UI_CLEANUP_HOOK_DLL_SHA256
    assert proof['body_rva'] == '0x5c620'
    assert proof['body_raw_hex'] == asset['body_hex']
    assert proof['body_matches_pinned_asset'] is True
    assert proof['dos_header_matches_pinned_asset'] is True
    assert proof['coff_prefix_matches_pinned_asset'] is True
    assert proof['optional_header_magic_matches_pinned_asset'] is True
    assert proof['size_of_image_matches_pinned_asset'] is True
    assert proof['whole_loaded_dll_hash_verified'] is False
    assert trace.summary()['calls'] == 9
    assert trace.summary()['bytes_requested'] == 1280


def test_v44_unit_removal_exact_mapping_selects_the_new_pointer_and_asset():
    image = old_mapping.MemoryImage()
    asset, pointer = install_unit_removal(image, old_mapping.GAME_BASE)
    trace = common._Trace(image)
    proof = mapping.read_mapping(trace, old_mapping.GAME_BASE, pointer, phase='before')
    after = mapping.read_mapping(
        common._Trace(image), old_mapping.GAME_BASE, pointer, phase='after')
    assert proof == after
    assert proof['mode'] == 'installed_observer_gui_forwarding_v44'
    assert proof['asset_sha256'] == mapping.V44_UNIT_REMOVAL_ASSET_SHA256
    assert proof['dll_sha256_from_asset'] == mapping.V44_UNIT_REMOVAL_HOOK_DLL_SHA256
    assert proof['body_rva'] == '0x5cde0'
    assert proof['body_raw_hex'] == asset['body_hex']
    assert proof['body_matches_pinned_asset'] is True
    assert proof['whole_loaded_dll_hash_verified'] is False
    assert trace.summary()['calls'] == 9
    assert trace.summary()['bytes_requested'] == 1280


def test_v44_unit_removal_capacity_selects_by_complete_body_and_refreshes_globals():
    image = old_mapping.MemoryImage()
    asset, pointer = install_unit_removal_capacity(image, old_mapping.GAME_BASE)
    trace = common._Trace(image)
    proof = mapping.read_mapping(trace, old_mapping.GAME_BASE, pointer, phase='before')
    after = mapping.read_mapping(
        common._Trace(image), old_mapping.GAME_BASE, pointer, phase='after')
    assert proof == after
    assert proof['mode'] == 'installed_observer_gui_forwarding_v44'
    assert proof['asset_sha256'] == mapping.V44_UNIT_REMOVAL_CAPACITY_ASSET_SHA256
    assert proof['dll_sha256_from_asset'] == mapping.V44_UNIT_REMOVAL_CAPACITY_HOOK_DLL_SHA256
    assert proof['body_rva'] == '0x5cde0'
    assert proof['body_raw_hex'] == asset['body_hex']
    assert proof['game_module_base_global_rva'] == hex(asset['game_module_base_global_rva'])
    assert proof['saved_original_global_rva'] == hex(asset['favor_gold_original_global_rva'])
    assert proof['whole_loaded_dll_hash_verified'] is False
    assert trace.summary()['calls'] == 9
    assert trace.summary()['bytes_requested'] == 1280


@pytest.mark.parametrize(
    'damage', ['dos', 'coff', 'magic', 'image_size', 'body', 'global', 'original'])
def test_v44_ui_cleanup_damage_remains_unknown(damage):
    image = old_mapping.MemoryImage()
    asset, pointer = install_ui_cleanup(image, old_mapping.GAME_BASE)
    module_base = old_mapping.DLL_BASE
    if damage == 'dos':
        image.put(module_base, b'\0')
    elif damage == 'coff':
        image.put(module_base + asset['pe_header_offset'], b'\0')
    elif damage == 'magic':
        image.put(module_base + asset['pe_header_offset'] + 24, b'\0\0')
    elif damage == 'image_size':
        image.put(module_base + asset['pe_header_offset'] + 24 + 56, b'\0' * 4)
    elif damage == 'body':
        image.put(pointer, b'\0')
    elif damage == 'global':
        image.put_u64(module_base + asset['game_module_base_global_rva'], 0)
    else:
        image.put_u64(module_base + asset['favor_gold_original_global_rva'], 0)
    with pytest.raises(common._Unknown):
        mapping.read_mapping(common._Trace(image), old_mapping.GAME_BASE,
                             pointer, phase='before')


@pytest.mark.parametrize('damage', ['body', 'coff', 'image_size', 'global', 'original', 'unaligned'])
def test_v44_damaged_mapping_remains_unknown(damage):
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


def test_v44_permission_replay_and_foreign_disclosure_stay_independent(monkeypatch):
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
    assert scope['hook_asset_sha256'] == mapping.V44_ASSET_SHA256
    assert scope['accepted_mapping_modes'] == ['native_true', 'installed_observer_gui_forwarding_v44']
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
    profile = v41.historical_profile(13)
    assert profile['profile_revision'] == 13
    pins = {row['path']: row['sha256'] for row in profile['layout_dependencies']}
    for path, expected in (
        (mapping.V41_ASSET_RELATIVE_PATH, mapping.V41_ASSET_SHA256),
        (mapping.V41_EXPIRY_ASSET_RELATIVE_PATH, mapping.V41_EXPIRY_ASSET_SHA256),
        (mapping.V41_PEACE_RETURN_ASSET_RELATIVE_PATH, mapping.V41_PEACE_RETURN_ASSET_SHA256),
        (mapping.V41_RESULT_DATE_ASSET_RELATIVE_PATH, mapping.V41_RESULT_DATE_ASSET_SHA256),
        (mapping.V42_ASSET_RELATIVE_PATH, mapping.V42_ASSET_SHA256),
        (mapping.V43_ASSET_RELATIVE_PATH, mapping.V43_ASSET_SHA256),
        (mapping.V44_ASSET_RELATIVE_PATH, mapping.V44_ASSET_SHA256),
        (mapping.V44_ROUTER_ORIGIN_ASSET_RELATIVE_PATH,
         mapping.V44_ROUTER_ORIGIN_ASSET_SHA256),
        (mapping.V44_FRAGMENT_RETRY_ASSET_RELATIVE_PATH,
         mapping.V44_FRAGMENT_RETRY_ASSET_SHA256),
        (mapping.V44_UI_CLEANUP_ASSET_RELATIVE_PATH,
         mapping.V44_UI_CLEANUP_ASSET_SHA256),
        (mapping.V44_UNIT_REMOVAL_ASSET_RELATIVE_PATH,
         mapping.V44_UNIT_REMOVAL_ASSET_SHA256),
        (mapping.V44_UNIT_REMOVAL_CAPACITY_ASSET_RELATIVE_PATH,
         mapping.V44_UNIT_REMOVAL_CAPACITY_ASSET_SHA256),
    ):
        assert pins['bridge/information/' + path] == expected
