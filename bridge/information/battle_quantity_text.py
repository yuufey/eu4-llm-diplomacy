"""Model fixed-build quantity strings from the captured B02 operands."""
from .battle_display_sides import project_side_identity
from .battle_effects import project_effects
from .battle_values import project_aggregate_losses, project_forces

PROVENANCE = {
    'exe_sha256': 'b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77',
    'count_formatter_rva': '0xae8a80',
    'count_evidence_id': 'ev_959dd5e56c1114bb51d5b23ab36d9685586c3bbf60f33296eb7a7cc7b361adb1',
    'capture_formatter_rva': '0x17038d0',
    'capture_evidence_id': 'ev_5e57fd1daeba55df4ffe2607197cecbcd62ff471c7e2294086d9db7dc57b618d',
}
FLAGS = {'derived': True, 'not_raw_text': True, 'native_formatter_invoked': False,
         'native_numeric_format_verified': False,
         'native_parameter_assignment_verified': False, 'native_widget_text_verified': False,
         'runtime_popup_verified': False, 'visibility_verified': False, 'complete': False}
UNITS = {
    1: (('CAV', 'cavalry'), ('INF', 'infantry'), ('ART', 'artillery')),
    2: (('CAV', 'heavy_ship'), ('INF', 'light_ship'), ('ART', 'galley'), ('TRANS', 'transport')),
}
PHASES = (('START', 'initial_forces'), ('LOST', 'losses'), ('END', 'remaining_forces'))


def _unknown(reason):
    return {**FLAGS, 'status': 'unknown', 'reason': reason}


def _integer(value):
    return type(value) is int and -(1 << 31) <= value < 1 << 31


def _text(value, operand, basis):
    return {**FLAGS, 'status': 'known', 'value': value, 'raw_hex': value.encode('ascii').hex(),
            'codec': 'eu4_escape', 'integer_operand': operand, 'basis': basis}


def format_count_candidate(operand):
    """Use scale 1000 where the native float conversions are all exact."""
    if not _integer(operand):
        return _unknown('QUANTITY_INTEGER_OPERAND_INVALID')
    if abs(operand) > 1 << 24:
        return _unknown('QUANTITY_FLOAT_ROUNDING_CONTEXT_NOT_CAPTURED')
    # Both int->float conversions, 1000/1000, and multiplication by one are
    # exact in this interval, independently of the live SSE rounding mode.
    if operand >= 100000:
        value = f'{operand // 1000}k'
    elif operand >= 1000:
        value = f'{operand // 1000},{operand % 1000:03d}'
    else:
        value = str(operand)
    return {**_text(value, operand, 'fixed1374_ae8a80_scale1000_model'),
            'format_scale': 1000, 'floating_point_basis': 'exact_conversions_and_operations',
            'provenance': dict(PROVENANCE)}


def project_quantity_candidates(decoded, *, mapping=None):
    """Keep the native combat-side labels and the existing force semantics."""
    try:
        context = decoded['context']
        kind = context['kind']
        sequence = decoded['observation']['sequence']
        date = decoded['observation']['result']['raw_date']
        if (type(kind) is not int or kind not in UNITS or type(sequence) is not int
                or not 0 < sequence < 1 << 64 or type(date) is not int or not 0 <= date < 1 << 31):
            return _unknown('QUANTITY_EVENT_IDENTITY_INVALID')
        identity = project_side_identity(decoded, mapping)
        if identity['status'] != 'known':
            return _unknown('QUANTITY_SIDE_CONTEXT_UNKNOWN')
        result_sides = identity['value']['sides']
        derived_mapping = []
        if all(side['result_side_index']['status'] == 'known' for side in result_sides):
            derived_mapping = [next(side['combat_side_index'] for side in result_sides
                                    if side['result_side_index']['value'] == index)
                               for index in range(2)]
        raw_rows = (context['sides'] if kind == 1 else decoded['observation']['result']['sides'])
        if any(not isinstance(side['raw_fields'], (list, tuple))
               or any(not _integer(value) for value in side['raw_fields']) for side in raw_rows):
            return _unknown('QUANTITY_RAW_OPERANDS_INVALID')
        forces = project_forces(decoded, derived_mapping)
        candidates = {}
        for side_index, label in enumerate(('OUR', 'ENEMY')):
            for token, unit in UNITS[kind]:
                for phase, field in PHASES:
                    source = forces[field]
                    key = label + token + phase
                    metadata = {'template_key': key, 'combat_side_index': side_index,
                                'unit': unit, 'phase': phase, 'scope': 'whole_combat_side'}
                    if source['status'] != 'known':
                        candidates[key] = {**_unknown(source['reason']), **metadata}
                        continue
                    operand = source['value']['sides'][side_index]['by_unit'][unit]
                    text = format_count_candidate(operand)
                    if kind == 1 and phase == 'LOST' and text['status'] == 'known':
                        # The consumer prefixes '-' even when the operand is zero.
                        text = {**text, 'value': '-' + text['value'],
                                'raw_hex': '2d' + text['raw_hex'], 'literal_prefix': '-'}
                    candidates[key] = {**text, **metadata,
                        'quantity': ('net_ship_change' if kind == 2 and phase == 'LOST'
                                     else 'unit_count')}
        if kind == 1:
            aggregate = project_aggregate_losses(decoded)
            for side_index, label in enumerate(('OUR', 'ENEMY')):
                key = label + 'LOST'
                count = (aggregate['value']['sides'][side_index]['count']
                         if aggregate['status'] == 'known' else aggregate)
                text = (format_count_candidate(count['value']) if count['status'] == 'known'
                        else _unknown(count['reason']))
                if text['status'] == 'known':
                    text = {**text, 'value': '-' + text['value'],
                            'raw_hex': '2d' + text['raw_hex'], 'literal_prefix': '-'}
                candidates[key] = {**text, 'template_key': key,
                    'combat_side_index': side_index, 'scope': 'whole_combat_side',
                    'quantity': 'aggregate_loss', 'unit': 'men',
                    'summary_offset': hex(0x44 + side_index * 4),
                    'operand_basis': 'native_summary_already_divided_by_1000'}
        if kind == 2:
            effects = project_effects(decoded, derived_mapping, None)
            capture = effects['ships_captured']
            if capture['status'] == 'known' and _integer(capture['value']['total']):
                total = capture['value']['total']
                candidates['CAPTURE'] = _text(str(total), total, 'fixed1374_17038d0_integer_model')
            else:
                candidates['CAPTURE'] = _unknown(capture.get('reason', 'CAPTURE_COUNT_INVALID'))
        return {**FLAGS, 'status': 'known', 'sequence': sequence, 'raw_date': date,
                'battle_kind': kind, 'candidates': candidates, 'provenance': dict(PROVENANCE)}
    except (KeyError, TypeError, ValueError, IndexError, StopIteration, OverflowError):
        return _unknown('QUANTITY_INPUTS_INVALID')
