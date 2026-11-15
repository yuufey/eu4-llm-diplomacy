"""Reference validity is not an AI/human gate; missing event globals stay unknown."""
import pytest

from bridge.information.battle_score_predicate import score_reference_predicate
from bridge.information.battle_outcome_composition import project_outcome_text_composition
from bridge.tests.test_information_battle_outcome_text import _decoded, _field
from bridge.tests.test_information_battle_outcome_composition import _configure, _phrase_literals


def reference(slot=122, *, top=1, kind=0):
    return int.from_bytes(b'FRA\0' + slot.to_bytes(2, 'little', signed=True)
                          + bytes((kind, top)), 'little')


@pytest.mark.parametrize('top,kind', [(0, 0), (0, 7), (1, 7), (255, 7)])
def test_metadata_rejects_before_any_global_values_are_required(top, kind):
    result = score_reference_predicate(reference(top=top, kind=kind))
    assert result['status'] == 'known' and result['value'] is False
    assert result['reason'] == 'REFERENCE_METADATA_REJECTED_BEFORE_SLOT_READS'


def test_an_ordinary_reference_does_not_invent_the_three_event_slots():
    result = score_reference_predicate(reference())
    assert result['status'] == 'unknown'
    assert result['reason'] == 'SAME_EVENT_RESERVED_SLOTS_NOT_CAPTURED'
    assert result['metadata_checks_passed'] is True
    assert 'value' not in result


@pytest.mark.parametrize('slot,slots,expected', [
    (122, (1, 2, 3), True), (122, (122, 2, 3), False),
    (122, (1, 122, 3), False), (122, (1, 2, 122), False),
    (-32768, (-32768, 0, 1), False), (-1, (65535, 0, 1), True),
    (32767, (-1, -2, -3), True),
])
def test_exact_signed_slot_comparisons(slot, slots, expected):
    result = score_reference_predicate(reference(slot), slots)
    assert result['status'] == 'known' and result['value'] is expected
    assert result['signed_slot'] == slot
    assert result['native_function_invoked'] is False


@pytest.mark.parametrize('ref,slots', [(True, (1, 2, 3)), (-1, (1, 2, 3)),
    (1 << 64, (1, 2, 3)), (reference(), (True, 2, 3)),
    (reference(), (1 << 31, 2, 3)), (reference(), (1, 2)), (reference(), '123')])
def test_malformed_reference_or_slot_evidence_never_proves_a_predicate(ref, slots):
    assert score_reference_predicate(ref, slots)['status'] == 'unknown'


@pytest.mark.parametrize('raw,status,text', [(b'Marshal reports', 'known', 'Marshal reports'),
    (b'', 'known', ''), (b'notice $', 'known', 'notice $'),
    (b'$COUNTRY$', 'unknown', None), (b'$VAL|=+$', 'unknown', None), (b'\x10', 'unknown', None)])
def test_messenger_uses_only_the_same_event_zero_argument_head_template(raw, status, text):
    _, _, _, decoded = _decoded()
    _phrase_literals(decoded)
    decoded['outcome_text']['text_fields']['MESSAGE_HEAD_MIL'] = _field(raw)
    mapping, observer = _configure(decoded, winner=0, observer_side=0)
    result = project_outcome_text_composition(decoded, mapping=mapping, observer_ref=observer)
    messenger = result['messenger']
    assert messenger['status'] == status
    assert messenger['format_parameter'] == 'MESSENGER'
    assert messenger['actual_parameter_assignment_verified'] is False
    assert messenger['window_title_verified'] is False
    if status == 'known':
        assert messenger['text'] == text and messenger['raw_hex'] == raw.hex()
    assert result['winorlose']['status'] == 'unknown'


def test_absent_head_does_not_disable_base_phrase_and_score_globals_stay_unknown():
    _, _, _, decoded = _decoded()
    _phrase_literals(decoded)
    decoded['outcome_text']['text_fields']['MESSAGE_HEAD_MIL'] = _field(state='absent')
    mapping, observer = _configure(decoded, winner=1, observer_side=1)
    result = project_outcome_text_composition(decoded, mapping=mapping, observer_ref=observer)
    assert result['observer_base_phrase']['status'] == 'known'
    assert result['messenger']['status'] == 'unknown'
    suffix = result['score_suffix']
    assert suffix['append_condition']['status'] == 'unknown'
    assert suffix['append_condition']['reference_full_ref'] == f"{decoded['context']['sides'][0]['participants']['full_refs'][0]:016x}"
    assert suffix['numeric_token_type'] == 7 and suffix['numeric_format_verified'] is False
    assert suffix['omission_verified'] is False


@pytest.mark.parametrize('invalid', ['bool', 'overflow'])
def test_bad_score_operand_does_not_retract_other_copied_text(invalid):
    _, _, _, decoded = _decoded()
    _phrase_literals(decoded)
    mapping, observer = _configure(decoded, winner=0, observer_side=0)
    decoded['observation']['summary']['raw_i32'][6] = True if invalid == 'bool' else (1 << 31) - 1
    if invalid == 'overflow':
        decoded['observation']['result']['sides'][mapping.index(0)]['raw_fields'][8] = (1 << 31) - 1
    result = project_outcome_text_composition(decoded, mapping=mapping, observer_ref=observer)
    assert result['score_suffix']['operand']['status'] == 'unknown'
    assert result['observer_base_phrase']['status'] == 'known'
    assert result['messenger']['status'] == 'known'
