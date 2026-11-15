"""Quantity formatting boundaries and comparison with retained native text."""
from copy import deepcopy

import pytest

from bridge.information.battle_quantity_text import format_count_candidate, project_quantity_candidates
from bridge.information.battle_display_composition import project_display_composition
from bridge.tests.test_information_battle_display_composition import _decoded
from bridge.tests.test_information_battle_display import _load, LAND_FIXTURE, NAVAL_FIXTURE
from bridge.tests.test_information_battle_values import capture, naval_extension


@pytest.mark.parametrize('operand,expected', [
    (0, '0'), (1, '1'), (999, '999'), (1000, '1,000'), (1001, '1,001'),
    (1009, '1,009'), (1010, '1,010'), (1099, '1,099'), (1100, '1,100'),
    (99999, '99,999'), (100000, '100k'), (100999, '100k'), (101000, '101k'),
    (2147483, '2147k'), (1 << 24, '16777k'),
    (-1, '-1'), (-1000, '-1000'), (-100000, '-100000'), (-(1 << 24), '-16777216'),
])
def test_exact_count_format_has_native_thresholds_padding_and_signed_asymmetry(operand, expected):
    value = format_count_candidate(operand)
    assert value['status'] == 'known' and value['value'] == expected
    assert value['raw_hex'] == expected.encode('ascii').hex()
    assert value['native_formatter_invoked'] is False
    assert value['native_numeric_format_verified'] is False


@pytest.mark.parametrize('operand', [True, False, 1.0, None, '1', 1 << 31, -(1 << 31) - 1])
def test_non_i32_quantity_operands_are_unknown(operand):
    assert format_count_candidate(operand)['reason'] == 'QUANTITY_INTEGER_OPERAND_INVALID'


@pytest.mark.parametrize('operand', [(1 << 24) + 1, -(1 << 24) - 1, (1 << 31) - 1, -(1 << 31)])
def test_uncaptured_float_rounding_context_limits_the_model(operand):
    assert format_count_candidate(operand)['reason'] == 'QUANTITY_FLOAT_ROUNDING_CONTEXT_NOT_CAPTURED'


def test_land_count_keys_keep_combat_order_individual_truncation_and_literal_minus_zero():
    decoded = _decoded(layout=1)
    decoded.pop('message_template', None)
    decoded['context']['sides'][0]['raw_fields'] = [1000100, 2000000, 3000000, 1999, 2999, 0]
    original = deepcopy(decoded)
    result = project_quantity_candidates(decoded)
    values = result['candidates']
    assert len(values) == 20
    assert values['OURINFSTART']['value'] == '1,000'
    assert values['OURCAVSTART']['value'] == '2,000'
    assert values['OURARTSTART']['value'] == '3,000'
    assert values['OURINFLOST']['value'] == '-1'
    assert values['OURARTLOST']['value'] == '-0'
    assert values['OURINFEND']['value'] == '999'
    assert values['OURLOST']['quantity'] == values['ENEMYLOST']['quantity'] == 'aggregate_loss'
    composed = project_display_composition(decoded)
    control = next(row for row in composed['controls'] if row.get('widget') == 'Our_unit_type_2_1_text')
    assert control['template_key'] == 'OURINFSTART'
    assert control['text']['raw_hex'] == b'1,000'.hex()
    assert control['quantity_candidate']['combat_side_index'] == 0
    assert decoded == original


def _naval(*, gates=(0, 0), rows=(3, 3)):
    decoded = capture('information_battle_naval_seq4_recorded_v2_1374.json')
    return naval_extension(decoded, row_types=rows, raw_losses=((3000, 0, 0, 0), (4000, 0, 0, 0)),
        initial_fields=((10, 20, 30, 40), (50, 60, 70, 80)), gates=gates, control=0)


def test_naval_keys_keep_result_reordering_net_changes_and_plain_capture_count():
    values = project_quantity_candidates(_naval())['candidates']
    assert len(values) == 25
    assert values['OURCAVSTART']['value'] == '50'
    assert values['ENEMYCAVSTART']['value'] == '10'
    assert values['OURCAVLOST']['value'] == '-1'
    assert values['ENEMYCAVLOST']['value'] == '-6'
    assert values['OURCAVLOST']['quantity'] == 'net_ship_change'
    assert values['OURCAVEND']['value'] == '49'
    assert values['ENEMYCAVEND']['value'] == '4'
    assert values['CAPTURE']['value'] == '2'
    assert values['CAPTURE']['basis'] == 'fixed1374_17038d0_integer_model'


def test_naval_gate_and_unclassified_rows_preserve_independent_initial_and_capture_values():
    values = project_quantity_candidates(_naval(gates=(1, 0)))['candidates']
    assert values['OURCAVLOST']['value'] == '-50'
    assert values['OURCAVEND']['value'] == '0'
    values = project_quantity_candidates(_naval(rows=(3, 3, 99)))['candidates']
    assert values['OURCAVSTART']['value'] == '50'
    assert values['OURCAVLOST']['value'] == '-1'
    assert values['CAPTURE']['value'] == '3'


def test_legacy_naval_without_loss_extension_keeps_initial_candidates():
    decoded = capture('information_battle_naval_seq4_recorded_v2_1374.json')
    values = project_quantity_candidates(decoded)['candidates']
    assert values['OURARTSTART']['value'] == '8'
    assert values['OURARTLOST']['status'] == values['OURARTEND']['status'] == 'unknown'
    assert values['CAPTURE']['status'] == 'unknown'


def test_one_float_ambiguous_count_does_not_retract_sibling_counts():
    decoded = _naval()
    decoded['observation']['result']['sides'][1]['raw_fields'][3] = (1 << 24) + 1
    values = project_quantity_candidates(decoded)['candidates']
    assert values['OURCAVSTART']['status'] == 'unknown'
    assert values['OURINFSTART']['value'] == '60'


def test_invalid_quantity_raw_bytes_keep_the_name_line_and_buttons():
    decoded = _decoded()
    decoded.pop('message_template', None)
    decoded['context']['sides'][0]['raw_fields'][0] = True
    result = project_display_composition(decoded)
    assert result['quantity_candidate_status']['status'] == 'unknown'
    assert result['line1']['status'] == result['buttons']['status'] == 'known'


@pytest.mark.parametrize('name,count', [(LAND_FIXTURE, 20), (NAVAL_FIXTURE, 24)])
def test_model_bytes_match_real_retained_formatter_pairs(name, count):
    _, decoded, _ = _load(name)
    candidates = project_quantity_candidates(decoded)['candidates']
    compared = 0
    for pair in decoded['message_template']['pairs']:
        key = bytes.fromhex(pair['key_raw_hex']).decode('ascii')
        if key in candidates:
            assert candidates[key]['status'] == 'known'
            assert candidates[key]['raw_hex'] == pair['value_raw_hex']
            compared += 1
    assert compared == count
