from copy import deepcopy

import pytest

from bridge.information import node_cash_aggregate as public
from bridge.information.province_trade_power import NativeProvinceTradePowerReader


def annotation(*, unresolved=False):
    return {'status': 'known', 'basis': public.BASIS, 'period': 'current', 'partial': True,
        'complete': False, 'native_function_invoked': False, 'value': {
            'node_id': 'champagne', 'center_province_id': 186, 'member_count': 2,
            'valued_member_count': 1 if unresolved else 2,
            'unresolved_province_ids': [183] if unresolved else [],
            'all_member_values_known': not unresolved,
            'province_input_sum_raw': None if unresolved else 110652,
            'calculated_node_cash_raw': None if unresolved else 9221,
            'cached_node_cash_raw': 9221, 'matches_cache': None if unresolved else True,
            'scale': 1000, 'unit': 'node_cash', 'current_only': True,
            'cache_refresh_verified': False, 'future_income_claimed': False}}


@pytest.mark.parametrize('unresolved', [False, True])
def test_annotation_preserves_partial_coverage_without_fabricated_total(unresolved):
    item = annotation(unresolved=unresolved)
    result = public.validate_annotation(item)
    assert result == item
    assert result is not item and result['value'] is not item['value']


@pytest.mark.parametrize('key,value', [
    ('member_count', True), ('valued_member_count', 3),
    ('unresolved_province_ids', [183]), ('all_member_values_known', False),
    ('matches_cache', False), ('calculated_node_cash_raw', 9222),
    ('cached_node_cash_raw', 1 << 31), ('future_income_claimed', True),
    ('cache_refresh_verified', True), ('unit', 'province_monthly_income')])
def test_inconsistent_or_overclaimed_public_values_are_rejected(key, value):
    item = annotation()
    item['value'][key] = value
    assert public.validate_annotation(item)['status'] == 'unknown'


def test_incomplete_members_cannot_have_a_numeric_total():
    item = annotation(unresolved=True)
    item['value']['calculated_node_cash_raw'] = 0
    assert public.validate_annotation(item)['status'] == 'unknown'


def test_negative_native_sum_uses_truncation_toward_zero():
    item = annotation()
    item['value'].update(province_input_sum_raw=-13, calculated_node_cash_raw=-1,
                         cached_node_cash_raw=-1)
    assert public.validate_annotation(item) == item


def test_public_node_key_reuses_loaded_node_grammar():
    item = annotation()
    item['value']['node_id'] = 'Node_A.a-b:1'
    assert public.validate_annotation(item) == item


def test_private_fields_cannot_leak_through_projection():
    item = annotation()
    raw = {k: deepcopy(v) for k, v in item.items() if k != 'native_function_invoked'}
    raw['raw_inputs'] = {'shared_valid': True, 'pointer': '0x12345678', 'reads': ['private']}
    target = {'fields': {public.FIELD: raw, 'G02.province_node_allocation': {
        'value': {k: item['value'][k] for k in ('node_id', 'center_province_id', 'member_count')}}},
        'field_consistency': {public.FIELD: {'status': 'stable'}}}
    assert public.project(target) == item
    target['fields']['G02.province_node_allocation']['value']['node_id'] = 'sevilla'
    assert public.project(target)['reason'] == 'NODE_CASH_NODE_BINDING_INVALID'


@pytest.mark.parametrize('value', [True, 1, 'yes', None])
def test_node_option_requires_previous_value_pipeline(value):
    with pytest.raises(ValueError, match='NODE_CASH_OPTION_INVALID'):
        NativeProvinceTradePowerReader(object(), with_node_cash=value)


def test_node_option_does_not_change_default_mode():
    assert NativeProvinceTradePowerReader(object()).with_node_cash is False
    reader = NativeProvinceTradePowerReader(object(), with_numeric_inputs=True,
        with_country_inputs=True, with_calculation=True, with_node_allocation=True,
        with_value_calculation=True, with_node_cash=True)
    assert reader.with_node_cash is True
