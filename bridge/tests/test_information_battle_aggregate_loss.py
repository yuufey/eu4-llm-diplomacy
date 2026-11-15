"""Aggregate loss operands stay separate from unit sums and result ordering."""
from copy import deepcopy

import pytest

from bridge.information.battle_compact_loss_candidates import project_compact_loss_candidates
from bridge.information.battle_display_composition import project_display_composition
from bridge.information.battle_quantity_text import project_quantity_candidates
from bridge.information.battle_values import project_aggregate_losses, project_land_forces
from bridge.tests.test_information_battle_compact_loss_candidates import _synthetic_land_decoded
from bridge.tests.test_information_battle_display import _load, LAND_FIXTURE, NAVAL_FIXTURE
from bridge.tests.test_information_battle_values import capture


def _counts(decoded):
    return project_aggregate_losses(decoded)['value']['sides']


def test_retained_native_total_strings_match_summary_in_combat_order():
    _, decoded, _ = _load(LAND_FIXTURE)
    original = deepcopy(decoded)
    assert decoded['observation']['result']['sides'][0]['country'] in decoded['context']['sides'][1]['participants']['full_refs']
    assert [side['count']['value'] for side in _counts(decoded)] == [308, 3000]
    candidates = project_quantity_candidates(decoded)['candidates']
    pairs = {bytes.fromhex(p['key_raw_hex']).decode(): p['value_raw_hex']
             for p in decoded['message_template']['pairs']}
    for key in ('OURLOST', 'ENEMYLOST'):
        assert candidates[key]['raw_hex'] == pairs[key]
        assert candidates[key]['native_widget_text_verified'] is False
    assert decoded == original


def test_total_is_already_divided_and_independent_of_component_sum():
    decoded = capture('information_battle_FRA_live_v2_1374.json')
    decoded['observation']['summary']['raw_i32'][9:11] = [1234, 0]
    decoded['context']['sides'][0]['raw_fields'] = [4000, 4000, 4000, 1999, 1999, 1999]
    result = project_land_forces(decoded)['losses']['value']
    assert result['sides'][0]['component_sum'] == 3
    assert result['aggregate_display']['value']['sides'][0]['count']['value'] == 1234
    candidates = project_quantity_candidates(decoded)['candidates']
    assert candidates['OURLOST']['value'] == '-1,234'
    assert candidates['ENEMYLOST']['value'] == '-0'


@pytest.mark.parametrize('invalid', [True, -1, 1 << 31, 1.0, None, '5'])
def test_bad_aggregate_operand_keeps_other_side_and_unit_counts(invalid):
    _, decoded, _ = _load(LAND_FIXTURE)
    decoded['observation']['summary']['raw_i32'][9] = invalid
    sides = _counts(decoded)
    assert sides[0]['count']['status'] == 'unknown'
    assert sides[1]['count']['value'] == 3000
    values = project_quantity_candidates(decoded)['candidates']
    assert values['OURLOST']['status'] == 'unknown'
    assert values['ENEMYLOST']['value'] == '-3,000'
    assert values['OURINFSTART']['status'] == 'known'


@pytest.mark.parametrize('invalid', [None, [], [0] * 10, [0] * 12])
def test_bad_summary_shape_keeps_unit_candidates(invalid):
    _, decoded, _ = _load(LAND_FIXTURE)
    decoded['observation']['summary']['raw_i32'] = invalid
    assert project_aggregate_losses(decoded)['status'] == 'unknown'
    values = project_quantity_candidates(decoded)['candidates']
    assert values['OURLOST']['status'] == 'unknown'
    assert values['OURINFSTART']['status'] == 'known'


def test_valid_count_outside_exact_float_domain_remains_a_known_b02_operand():
    _, decoded, _ = _load(LAND_FIXTURE)
    decoded['observation']['summary']['raw_i32'][9] = (1 << 24) + 1
    assert _counts(decoded)[0]['count']['value'] == (1 << 24) + 1
    values = project_quantity_candidates(decoded)['candidates']
    assert values['OURLOST']['reason'] == 'QUANTITY_FLOAT_ROUNDING_CONTEXT_NOT_CAPTURED'
    assert values['ENEMYLOST']['status'] == 'known'


def test_compact_composition_uses_same_event_template_and_numeric_source():
    decoded = _synthetic_land_decoded(template=b'Loss $NUMBER$ / $NUMBER$', pairs=[])
    decoded['observation']['summary']['raw_i32'][9:11] = [1234, 0]
    composed = project_display_composition(decoded)
    rows = {r['widget']: r for r in composed['controls'] if r.get('widget') in ('OurLost', 'EnemyLost')}
    assert rows['OurLost']['text']['value'] == 'Loss -1,234 / -1,234'
    assert rows['EnemyLost']['text']['value'] == 'Loss -0 / -0'
    assert rows['OurLost']['compact_loss_candidate']['input_basis'] == 'same_event_summary_aggregate_loss_count_model'
    decoded.pop('message_template')
    assert project_display_composition(decoded)['controls'] == composed['controls']


@pytest.mark.parametrize('values', [(b'copied',), (b'a', b'b'), (b'\x10',)])
def test_compact_numeric_fallback_preserves_copied_input_errors(values):
    decoded = _synthetic_land_decoded(pairs=[{'key_raw_hex': b'OURLOST'.hex(),
                                            'value_raw_hex': value.hex()} for value in values])
    candidates = project_quantity_candidates(decoded)['candidates']
    compact = project_compact_loss_candidates(decoded, quantity_candidates=candidates)
    rows = {r['template_key']: r for r in compact['controls']}
    if values == (b'copied',):
        assert rows['OURLOST']['decoded']['value'] == 'copied'
    else:
        assert rows['OURLOST']['status'] == 'unknown'
    assert rows['ENEMYLOST']['status'] == 'known'


def test_missing_compact_template_keeps_numeric_candidate_and_unknown_widget_text():
    decoded = _synthetic_land_decoded(pairs=[], compact_state='absent')
    composed = project_display_composition(decoded)
    row = next(r for r in composed['controls'] if r.get('widget') == 'OurLost')
    assert row['quantity_candidate']['status'] == 'known'
    assert row['text']['status'] == 'unknown'


def test_naval_result_has_no_land_aggregate_keys():
    _, decoded, _ = _load(NAVAL_FIXTURE)
    values = project_quantity_candidates(decoded)['candidates']
    assert 'OURLOST' not in values and 'ENEMYLOST' not in values
    assert project_aggregate_losses(decoded)['status'] == 'unknown'
