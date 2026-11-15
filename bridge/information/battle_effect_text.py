"""Model the six fixed-build result-window effect strings."""
from work.information_battle_observation_wire import SUMMARY_RAW_COUNT
from .battle_body_candidate import _decode_output
from .battle_display_sides import project_side_identity
from .battle_effects import _decimal

PROVENANCE = {
    'exe_sha256': 'b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77',
    'formatter_rva': '0x23b3a0',
    'evidence_id': 'ev_dea37cc2f55b2bd0ae9ddb6324b8c06ad1666a343c8ed27d350865e1b5e6cba1',
}
FLAGS = {'derived': True, 'not_raw_text': True, 'native_formatter_invoked': False,
         'native_numeric_format_verified': False, 'native_parameter_assignment_verified': False,
         'native_widget_text_verified': False, 'runtime_popup_verified': False,
         'visibility_verified': False, 'complete': False}
EFFECTS = (('PRESTIGE', 2, 2, 1000), ('TRADITION', 0, 1, 1000), ('EXHAUSTION', 4, 2, -1000))


def _unknown(reason):
    return {**FLAGS, 'status': 'unknown', 'reason': reason}


def effect_text_candidate(raw, digits, color_polarity):
    if (type(raw) is not int or not -(1 << 31) < raw < 1 << 31
            or type(digits) is not int or digits not in (1, 2)
            or type(color_polarity) is not int or color_polarity not in (-1000, 1000)):
        return _unknown('EFFECT_FORMAT_OPERAND_OR_MODE_INVALID')
    signed_effect = raw * color_polarity
    color = b'\xa7G' if signed_effect > 0 else b'\xa7R' if signed_effect < 0 else b'\xa7Y'
    # The returned String32 ends after the number. The native routine only
    # appends the literal section-sign W percent to a separate temporary before destruction.
    output = color + _decimal(raw, digits, positive_sign=True).encode('ascii')
    return {**FLAGS, 'status': 'known', 'value': _decode_output(output), 'raw_hex': output.hex(),
            'codec': 'eu4_escape', 'basis': 'fixed1374_23b3a0_effect_model',
            'raw_operand': raw, 'scale': 1000, 'fraction_digits': digits,
            'color_polarity': color_polarity, 'rounding': 'truncate_toward_zero',
            'provenance': dict(PROVENANCE)}


def project_effect_text_candidates(decoded, *, mapping=None):
    try:
        context = decoded['context']
        kind = context['kind']
        sequence = decoded['observation']['sequence']
        date = decoded['observation']['result']['raw_date']
        if (type(kind) is not int or kind not in (1, 2) or type(sequence) is not int
                or not 0 < sequence < 1 << 64 or type(date) is not int or not 0 <= date < 1 << 31):
            return _unknown('EFFECT_EVENT_IDENTITY_INVALID')
        identity = project_side_identity(decoded, mapping)
        if identity['status'] != 'known':
            return _unknown('EFFECT_SIDE_CONTEXT_UNKNOWN')
        values = decoded['observation']['summary']['raw_i32']
        if not isinstance(values, (list, tuple)) or len(values) != SUMMARY_RAW_COUNT:
            return _unknown('EFFECT_SUMMARY_OPERANDS_INVALID')
        candidates = {}
        for side, label in enumerate(('OUR','ENEMY')):
            for effect, start, digits, polarity in EFFECTS:
                key = label + effect
                candidates[key] = {**effect_text_candidate(values[start + side], digits, polarity),
                    'template_key': key, 'combat_side_index': side, 'scope': 'whole_combat_side',
                    'quantity': 'result_window_side_operand',
                    'summary_offset': hex(0x20 + (start + side) * 4),
                    'effect': ('naval_tradition' if kind == 2 and effect == 'TRADITION'
                               else effect.lower())}
        return {**FLAGS, 'status': 'known', 'sequence': sequence, 'raw_date': date,
                'battle_kind': kind, 'candidates': candidates, 'provenance': dict(PROVENANCE)}
    except (KeyError, TypeError, ValueError, IndexError, UnicodeError, OverflowError):
        return _unknown('EFFECT_TEXT_INPUTS_INVALID')
