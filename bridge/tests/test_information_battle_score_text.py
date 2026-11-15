"""Native integer truncation, sign/color order, and unsupported token boundaries."""
import pytest

from bridge.information.battle_score_text import score_suffix_candidate
from bridge.information.battle_outcome_composition import project_outcome_text_composition
from bridge.tests.test_information_battle_outcome_text import _decoded, _field
from bridge.tests.test_information_battle_outcome_composition import _configure, _phrase_literals


def template(raw):
    return {'status': 'known', 'length': len(raw), 'raw_hex': raw.hex()}


@pytest.mark.parametrize('raw,plain,styled', [
    (0, b'0.00', b'\xa7Y0.00\xa7!'),
    (1, b'0.00', b'\xa7G+0.00\xa7!'),
    (-1, b'-0.00', b'\xa7R-0.00\xa7!'),
    (999, b'0.99', b'\xa7G+0.99\xa7!'),
    (-999, b'-0.99', b'\xa7R-0.99\xa7!'),
    (1000, b'1.00', b'\xa7G+1.00\xa7!'),
    (-1000, b'-1.00', b'\xa7R-1.00\xa7!'),
    (1099, b'1.09', b'\xa7G+1.09\xa7!'),
    (-1099, b'-1.09', b'\xa7R-1.09\xa7!'),
    (2147483647, b'2147483.64', b'\xa7G+2147483.64\xa7!'),
    (-2147483647, b'-2147483.64', b'\xa7R-2147483.64\xa7!'),
])
def test_exact_default_two_digit_type7_plain_and_equals_plus(raw, plain, styled):
    result = score_suffix_candidate(template(b'[$VAL|=+$] / $VAL$'), raw)
    assert result['status'] == 'known'
    assert result['raw_hex'] == (b' [' + styled + b'] / ' + plain).hex()
    assert result['replacement_count'] == 2 and result['rounding'] == 'truncate_toward_zero'
    assert result['native_formatter_invoked'] is False
    assert result['native_numeric_format_verified'] is False
    assert result['append_condition_evaluated'] is False


@pytest.mark.parametrize('raw', [True, False, -(1 << 31), 1 << 31, '1000', 1.0, None])
def test_wrong_type_or_unmodeled_negation_boundary_remains_unknown(raw):
    assert score_suffix_candidate(template(b'$VAL|=+$'), raw)['status'] == 'unknown'


@pytest.mark.parametrize('raw', [b'$OTHER$', b'$VAL|+= $', b'$VAL|+=+$', b'$VAL|0$',
    b'$VAL|%$', b'\0', b'\x10'])
def test_other_tokens_modifiers_or_invalid_output_codec_are_not_guessed(raw):
    assert score_suffix_candidate(template(raw), 1000)['status'] == 'unknown'


@pytest.mark.parametrize('raw,expected', [(b'', b' '), (b'literal', b' literal'),
    (b'unmatched $VAL', b' unmatched $VAL')])
def test_literal_empty_and_unmatched_tail_follow_outer_formatter(raw, expected):
    result = score_suffix_candidate(template(raw), 1000)
    assert result['status'] == 'known' and result['raw_hex'] == expected.hex()


def test_template_status_or_length_cannot_supply_untrusted_bytes():
    assert score_suffix_candidate({'status': 'absent'}, 1000)['status'] == 'unknown'
    field = template(b'$VAL$')
    field['length'] = True
    assert score_suffix_candidate(field, 1000)['status'] == 'unknown'


def test_score_alternatives_do_not_choose_missing_event_predicate_or_disable_messenger():
    _, _, _, decoded = _decoded()
    _phrase_literals(decoded)
    decoded['outcome_text']['text_fields']['WARSCORE_FROM_BATTLE'] = _field(b'[$VAL|=+$ score]')
    mapping, observer = _configure(decoded, winner=0, observer_side=0)
    decoded['observation']['summary']['raw_i32'][6] = 1099
    decoded['observation']['result']['sides'][mapping.index(0)]['raw_fields'][8] = 0
    result = project_outcome_text_composition(decoded, mapping=mapping, observer_ref=observer)
    suffix = result['score_suffix']
    assert suffix['formatted_candidate']['raw_hex'] == b' [\xa7G+1.09\xa7! score]'.hex()
    assert suffix['modeled_numeric_format_supported'] is True
    assert suffix['append_condition']['status'] == 'unknown'
    assert suffix['omission_verified'] is False and suffix['numeric_format_verified'] is False
    assert result['winorlose']['status'] == 'unknown'
    assert result['winorlose']['candidate_if_appended']['raw_hex'] == b'Victory [\xa7G+1.09\xa7! score]'.hex()
    assert result['messenger']['status'] == 'known'
