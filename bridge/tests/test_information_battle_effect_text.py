"""Effect strings retain fixed-point signs, polarity and native color bytes."""
from copy import deepcopy

import pytest

from bridge.information.battle_effect_text import effect_text_candidate, project_effect_text_candidates
from bridge.information.battle_display_composition import project_display_composition
from bridge.tests.test_information_battle_display_composition import _decoded
from bridge.tests.test_information_battle_display import _load, LAND_FIXTURE, NAVAL_FIXTURE


@pytest.mark.parametrize('raw,digits,polarity,expected', [
    (0,2,1000,b'\xa7Y0.00'), (0,1,-1000,b'\xa7Y0.0'),
    (1,2,1000,b'\xa7G+0.00'), (-1,2,1000,b'\xa7R-0.00'),
    (1,2,-1000,b'\xa7R+0.00'), (-1,2,-1000,b'\xa7G-0.00'),
    (200,2,1000,b'\xa7G+0.20'), (-130,2,1000,b'\xa7R-0.13'),
    (2880,1,1000,b'\xa7G+2.8'), (-2999,2,1000,b'\xa7R-2.99'),
    (60,2,-1000,b'\xa7R+0.06'), (-120,2,-1000,b'\xa7G-0.12'),
    ((1<<31)-1,2,1000,b'\xa7G+2147483.64'),
    (-(1<<31)+1,1,1000,b'\xa7R-2147483.6'),
])
def test_effect_format_has_truncation_polarity_signed_zero_and_no_returned_reset(raw,digits,polarity,expected):
    value = effect_text_candidate(raw,digits,polarity)
    assert value['status'] == 'known' and value['raw_hex'] == expected.hex()
    assert not bytes.fromhex(value['raw_hex']).endswith(b'\xa7!')
    assert value['native_formatter_invoked'] is False
    assert value['native_numeric_format_verified'] is False


@pytest.mark.parametrize('raw,digits,polarity', [
    (True,2,1000), (None,2,1000), (1.0,2,1000), ('1',2,1000),
    (-(1<<31),2,1000), (1<<31,2,1000), (1,True,1000), (1,3,1000),
    (1,2,True), (1,2,1), (1,2,0),
])
def test_invalid_modes_and_noncanonical_or_abs_overflow_operands_are_unknown(raw,digits,polarity):
    assert effect_text_candidate(raw,digits,polarity)['status'] == 'unknown'


@pytest.mark.parametrize('kind', [1,2])
def test_effect_keys_use_combat_order_and_bad_operand_stays_local(kind):
    decoded = _decoded(kind=kind)
    decoded['observation']['summary']['raw_i32'][:6] = [2880,-2999,200,-130,60,-120]
    original = deepcopy(decoded)
    value = project_effect_text_candidates(decoded)
    assert value['status'] == 'known' and len(value['candidates']) == 6
    fields = value['candidates']
    assert fields['OURPRESTIGE']['raw_hex'] == b'\xa7G+0.20'.hex()
    assert fields['ENEMYPRESTIGE']['raw_hex'] == b'\xa7R-0.13'.hex()
    assert fields['OUREXHAUSTION']['raw_hex'] == b'\xa7R+0.06'.hex()
    assert fields['OURTRADITION']['combat_side_index'] == 0
    if kind == 2:
        assert fields['OURTRADITION']['effect'] == 'naval_tradition'
    assert decoded == original
    decoded['observation']['summary']['raw_i32'][2] = True
    fields = project_effect_text_candidates(decoded)['candidates']
    assert fields['OURPRESTIGE']['status'] == 'unknown'
    assert all(field['status'] == 'known' for key,field in fields.items() if key != 'OURPRESTIGE')


@pytest.mark.parametrize('values', [(b'Copied value',),(b'A',b'B'),(b'\x10',)])
def test_effect_fallback_keeps_copied_text_and_ambiguous_or_invalid_inputs(values):
    decoded = _decoded()
    decoded['message_template'] = {
        'source_kind':'formatter_container_before_cleanup',
        'raw_container_word_10':0,'raw_container_flag_14':0,'pair_count':len(values),
        'pairs':[{'key_raw_hex':b'OURPRESTIGE'.hex(),'value_raw_hex':value.hex()} for value in values]}
    composed = project_display_composition(decoded)
    row = next(row for row in composed['controls'] if row.get('widget') == 'our_prestige')
    assert row['effect_candidate']['status'] == 'known'
    if values == (b'Copied value',):
        assert row['text']['raw_hex'] == values[0].hex() and row['text']['derived'] is False
    else:
        assert row['text']['status'] == 'unknown'


def test_missing_effect_container_preserves_six_control_candidates_and_other_components():
    decoded = _decoded()
    decoded.pop('message_template',None)
    composed = project_display_composition(decoded)
    effects = [row for row in composed['controls'] if 'effect_candidate' in row]
    assert len(effects) == 6
    assert all(row['text']['status'] == 'known' and row['text']['derived'] for row in effects)
    assert composed['line1']['status'] == composed['buttons']['status'] == 'known'
    assert composed['full_display_complete'] is False


@pytest.mark.parametrize('name', [LAND_FIXTURE,NAVAL_FIXTURE])
def test_effect_candidates_match_all_six_real_native_formatter_pairs(name):
    _,decoded,_ = _load(name)
    candidates = project_effect_text_candidates(decoded)['candidates']
    pairs = {bytes.fromhex(pair['key_raw_hex']).decode('ascii'):pair['value_raw_hex']
             for pair in decoded['message_template']['pairs']}
    assert len(candidates) == 6
    assert all(candidate['status'] == 'known' and candidate['raw_hex'] == pairs[key]
               for key,candidate in candidates.items())
