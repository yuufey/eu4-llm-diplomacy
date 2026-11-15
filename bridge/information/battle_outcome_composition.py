"""Compose the selected observer's base phrase from fixed-build battle inputs.

This models a view for the admitted observer. It does not select the physical
client's native message branch or assume that its WINORLOSE omits a score.
"""
from .battle_body_candidate import _decode_output, _parts, _raw, _render_parts
from .battle_display_sides import PROVENANCE, project_side_identity
from .battle_outcome_text import project_outcome_text_sources
from .battle_effects import project_effects
from .battle_score_predicate import score_reference_predicate
from .battle_score_text import score_suffix_candidate
from .battle_outcome_tail import project_outcome_tail_sources
from .battle_values import project_outcome

FLAGS = {'not_raw_text': True, 'native_formatter_invoked': False,
         'native_branch_selection_verified': False, 'native_line1_verified': False,
         'runtime_popup_verified': False, 'visibility_verified': False,
         'full_display_complete': False, 'complete': False}


def _unknown(reason):
    return {'status': 'unknown', 'reason': reason}


def _failed(reason):
    return {**FLAGS, **_unknown(reason)}


def _literal(sources, key):
    field = sources['text_fields'][key]
    common = {'key': key, 'basis': 'same_event_zero_argument_cached_template',
              'derived': True, 'codec': 'eu4_escape'}
    if field['status'] != 'known':
        return {**common, **_unknown('OUTCOME_TEMPLATE_CACHE_ABSENT' if field['status'] == 'absent'
                                   else 'OUTCOME_TEMPLATE_UNKNOWN')}
    try:
        raw = _raw(field['raw_hex'])
        parts, count = _parts(raw)
        if count:
            raise ValueError('zero argument formatter')
        output = _render_parts(parts, b'')
        text = _decode_output(output)
    except (ValueError, UnicodeError):
        return {**common, **_unknown('OUTCOME_TEMPLATE_REQUIRES_UNSUPPORTED_FORMATTING_OR_CODEC')}
    return {**common, 'status': 'known', 'reason': None, 'raw_hex': output.hex(), 'text': text}


def project_outcome_text_composition(decoded, *, mapping=None, observer_ref=None):
    """Keep base phrase, parameter values, and unresolved final text separate.

    Existing B01 direction checks compare summary+4C against reordered
    result+108. OUR/ENEMY slots mean combat sides, not the observer's country.
    A nonparticipant never acquires a YOU_* phrase through this function.
    """
    sources = project_outcome_text_sources(decoded)
    if sources['status'] != 'known':
        return _failed('OUTCOME_COMPOSITION_SAME_EVENT_INPUTS_UNKNOWN')
    try:
        # Python bool compares equal to 0/1. Direct callers must not turn a
        # malformed representation into a verified battle direction.
        summary_winner = decoded['observation']['summary']['control_byte']
        result_flag = decoded['observation']['result']['flag108']
        if (type(summary_winner) is not int or type(result_flag) is not int
                or summary_winner not in (0, 1) or result_flag not in (0, 1)):
            return _failed('BATTLE_OUTCOME_INCONSISTENT')
        identity = project_side_identity(decoded, mapping, observer_ref)
        if identity['status'] != 'known':
            return _failed('OUTCOME_COMPOSITION_SIDE_CONTEXT_UNKNOWN')
        sides = identity['value']['sides']
        if any(side['result_side_index']['status'] != 'known' for side in sides):
            return _failed('OUTCOME_COMPOSITION_RESULT_MAPPING_UNKNOWN')
        if identity['value']['observer_template_label']['status'] != 'known':
            return _failed('OUTCOME_COMPOSITION_OBSERVER_NOT_UNIQUE_PARTICIPANT')
        derived_mapping = [next(side['combat_side_index'] for side in sides
                                if side['result_side_index']['value'] == index) for index in range(2)]
        outcome = project_outcome(decoded, derived_mapping, observer_ref)
        if outcome['status'] != 'known':
            return _failed(outcome['reason'])
        winner = outcome['value']['combat_side_index']
        observer_outcome = outcome['value']['observer_outcome']
        key = 'YOU_WON' if observer_outcome == 'victory' else 'YOU_LOST'
        observer_side = next(index for index, side in enumerate(decoded['context']['sides'])
                             if observer_ref in side['participants']['full_refs'])
        opponent_first = decoded['context']['sides'][1 - observer_side]['participants']['full_refs'][0]
        append_condition = score_reference_predicate(opponent_first)
        try:
            raw_score = decoded['observation']['summary']['raw_i32'][6]
            raw_bonus = decoded['observation']['result']['sides'][outcome['value']['result_side_index']]['raw_fields'][8]
            if any(type(value) is not int or not -(1 << 31) <= value < 1 << 31
                   for value in (raw_score, raw_bonus)):
                raise ValueError('typed score operands')
            effects = project_effects(decoded, derived_mapping, observer_ref)
            score_operand = effects['war_score']
        except (KeyError, TypeError, ValueError, IndexError, UnicodeError, OverflowError):
            score_operand = _unknown('SCORE_OPERANDS_INVALID')
    except (KeyError, TypeError, ValueError, StopIteration, UnicodeError, OverflowError):
        return _failed('OUTCOME_COMPOSITION_INPUT_INVALID')
    result = {**FLAGS, 'status': 'known', 'sequence': sources['sequence'],
        'raw_date': sources['raw_date'], 'battle_kind': sources['battle_kind'],
        'basis': 'fixed1374_native_winner_rebased_to_selected_observer',
        'provenance': dict(PROVENANCE), 'view_scope': 'selected_observer_not_physical_client',
        'observer_outcome': observer_outcome, 'winning_combat_side_index': winner,
        'observer_combat_side_index': observer_side,
        'observer_base_phrase': _literal(sources, key),
        'winorlose': _unknown('SCORE_APPEND_PREDICATE_AND_FORMAT_UNRESOLVED'),
        'messenger': {**_literal(sources, 'MESSAGE_HEAD_MIL'),
            'format_parameter': 'MESSENGER', 'wrapper_rva': '0x8c1cb0',
            'wrapper_basis': 'bounded_fixed1374_zero_argument_localization_wrapper',
            'actual_parameter_assignment_verified': False, 'window_title_verified': False},
        'native_physical_client_branch': _unknown('PHYSICAL_CLIENT_BRANCH_NOT_SELECTED'),
        'score_suffix': {**_unknown('SCORE_APPEND_PREDICATE_AND_FORMAT_UNRESOLVED'),
            'template_key': 'WARSCORE_FROM_BATTLE', 'omission_verified': False,
            'append_condition': append_condition,
            'predicate_country_basis': 'opponent_combat_side_first_participant_for_selected_observer',
            'operand': score_operand, 'numeric_token_type': 7,
            'numeric_format_verified': False},
        'ignored_legacy_parameter_name_probes': ['OTHERRESULT', 'MESSENGER']}
    if sources['battle_kind'] == 1:
        result['land_format_parameters'] = {
            # Native RESULT/OTHERRESULT are combat sides 0/1, including when
            # the observer is in side 1. They are not two localization keys.
            'RESULT': {**_literal(sources, 'RESULT_WON' if winner == 0 else 'RESULT_LOSS'),
                       'combat_side_index': 0, 'source_role': 'format_parameter'},
            'OTHERRESULT': {**_literal(sources, 'RESULT_WON' if winner == 1 else 'RESULT_LOSS'),
                            'combat_side_index': 1, 'source_role': 'format_parameter'}}
    else:
        result['naval_format_parameters'] = {
            **_unknown('NAVAL_PARAMETER_TEMPLATES_NOT_CAPTURED'),
            'missing_localization_inputs': ['COMBAT_FLEE', 'COMBAT_TRIUMPH',
                                           'COMBAT_WINNERTYPE_OUR', 'COMBAT_WINNERTYPE_THEIR']}
    suffix = result['score_suffix']
    candidate = _unknown('SCORE_OPERAND_UNKNOWN')
    if score_operand.get('status') == 'known':
        candidate = score_suffix_candidate(sources['text_fields']['WARSCORE_FROM_BATTLE'],
            score_operand['value']['sides'][observer_side]['raw'])
    suffix['formatted_candidate'] = candidate
    suffix['modeled_numeric_format_supported'] = candidate['status'] == 'known'
    base = result['observer_base_phrase']
    if base['status'] == 'known':
        result['winorlose']['candidate_if_not_appended'] = dict(base, condition='append_condition == false')
        if candidate['status'] == 'known':
            try:
                combined = bytes.fromhex(base['raw_hex']) + bytes.fromhex(candidate['raw_hex'])
                result['winorlose']['candidate_if_appended'] = {
                    'status': 'known', 'raw_hex': combined.hex(), 'text': _decode_output(combined),
                    'condition': 'append_condition == true', 'derived': True,
                    'native_formatter_invoked': False}
            except (ValueError, UnicodeError):
                result['winorlose']['candidate_if_appended'] = _unknown('SCORE_COMBINED_TEXT_INVALID')
    if isinstance(decoded.get('wire13'), dict) and decoded['wire13'].get('version') == 13:
        tail = project_outcome_tail_sources(decoded)
        result['tail_capture_status'] = tail['status']
        language_matches = (tail['status'] == 'known'
            and tail['text_fields']['language'].get('status') == 'known'
            and tail['text_fields']['language'].get('raw_hex') == sources['text_fields']['language'].get('raw_hex'))
        result['tail_language_consistent'] = language_matches
        if language_matches:
            condition = score_reference_predicate(opponent_first, tail['reserved_slots']['value'])
            suffix['append_condition'] = condition
            if condition['status'] == 'known':
                append = condition['value']
                chosen = result['winorlose'].get('candidate_if_appended' if append else 'candidate_if_not_appended', {})
                result['winorlose']['modeled_branch_selected'] = True
                result['winorlose']['selected_score_append'] = append
                if chosen.get('status') == 'known':
                    result['winorlose'].update(status='known', reason=None, raw_hex=chosen['raw_hex'],
                        text=chosen['text'], basis='same_event_selected_observer_composition',
                        native_parameter_assignment_verified=False)
                else:
                    result['winorlose']['reason'] = 'REQUIRED_SCORE_SUFFIX_OR_BASE_UNKNOWN'
            if sources['battle_kind'] == 2:
                victory = observer_outcome == 'victory'
                result['naval_format_parameters'] = {
                    'status': 'known', 'basis': 'fixed1374_direct_observer_branch_model',
                    'RESULT': {**_literal(sources, 'RESULT_WON' if victory else 'RESULT_LOSS'),
                               'source_role': 'format_parameter', 'scope': 'selected_observer'},
                    'OTHERRESULT': {**_literal(tail, 'COMBAT_FLEE' if victory else 'COMBAT_TRIUMPH'),
                                    'source_role': 'format_parameter', 'scope': 'other_combat_side'},
                    'WINNER': {**_literal(tail, 'COMBAT_WINNERTYPE_OUR' if victory else 'COMBAT_WINNERTYPE_THEIR'),
                               'source_role': 'format_parameter', 'scope': 'selected_observer'}}
        else:
            reason = 'OUTCOME_TAIL_LANGUAGE_MISMATCH' if tail['status'] == 'known' else 'OUTCOME_TAIL_INPUTS_UNKNOWN'
            suffix['append_condition'] = _unknown(reason)
            result['winorlose']['reason'] = reason
    return result
