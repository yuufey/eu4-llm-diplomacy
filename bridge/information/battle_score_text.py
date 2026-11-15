"""Bounded type-7 VAL formatting for the captured battle-score template.

Only plain VAL and the observed VAL|=+ modifier sequence are supported. The
fixed-build path truncates thousandths to two digits, adds a positive sign
for '=', and emits native color bytes for '+'. It never invokes the engine.
"""
from .battle_body_candidate import _decode_output, _raw, OUTPUT_LIMIT_BYTES
from .battle_effects import _decimal


def score_suffix_candidate(template_field, raw_score):
    common = {'not_raw_text': True, 'native_formatter_invoked': False,
        'native_numeric_format_verified': False, 'complete': False,
        'basis': 'fixed1374_type7_VAL_plain_or_equals_plus_model', 'codec': 'eu4_escape'}
    if not isinstance(template_field, dict) or template_field.get('status') != 'known':
        return {**common, 'status': 'unknown', 'reason': 'SCORE_TEMPLATE_NOT_CAPTURED'}
    try:
        if type(raw_score) is not int or not -(1 << 31) < raw_score < 1 << 31:
            raise ValueError('signed i32 including negation bound')
        template = _raw(template_field.get('raw_hex'))
        if ('length' in template_field and (type(template_field['length']) is not int
                or template_field['length'] != len(template))):
            raise ValueError('declared template length')
        number = _decimal(raw_score, 2).encode('ascii')
        color = b'\xa7G' if raw_score > 0 else b'\xa7R' if raw_score < 0 else b'\xa7Y'
        styled = color + (b'+' if raw_score > 0 else b'') + number + b'\xa7!'
        pieces = [b' ']
        cursor = replacements = 0
        while cursor < len(template):
            opening = template.find(b'$', cursor)
            if opening < 0:
                pieces.append(template[cursor:])
                break
            pieces.append(template[cursor:opening])
            closing = template.find(b'$', opening + 1)
            if closing < 0:
                pieces.append(template[opening:])
                break
            token = template[opening + 1:closing]
            if token not in (b'VAL', b'VAL|=+'):
                raise ValueError('unsupported native numeric modifier or token')
            pieces.append(number if token == b'VAL' else styled)
            replacements += 1
            cursor = closing + 1
        if sum(map(len, pieces)) + 1 >= OUTPUT_LIMIT_BYTES:
            raise ValueError('native bounded expansion')
        output = b''.join(pieces)
        text = _decode_output(output)
    except (ValueError, UnicodeError):
        return {**common, 'status': 'unknown', 'reason': 'SCORE_TEMPLATE_OR_NUMERIC_FORMAT_UNSUPPORTED'}
    return {**common, 'status': 'known', 'reason': None, 'raw_hex': output.hex(), 'text': text,
            'numeric_operand_raw': raw_score, 'scale': 1000, 'fraction_digits': 2,
            'rounding': 'truncate_toward_zero', 'replacement_count': replacements,
            'append_condition_evaluated': False}
