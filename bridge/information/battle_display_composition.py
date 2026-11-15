"""Compose same-record text inputs and definition branches, never UI state."""
from copy import deepcopy

from .battle_body_candidate import _decode_output, _parts, _raw, _render_parts, project_body_candidate
from .battle_compact_loss_candidates import project_compact_loss_candidates
from .battle_display import project_display
from .battle_display_context import project_display_context
from .battle_native_text import project_native_text, project_raw_text
from .battle_outcome_composition import project_outcome_text_composition
from .battle_quantity_text import project_quantity_candidates
from .battle_effect_text import project_effect_text_candidates
from .battle_independent_line import project_independent_line

FLAGS = {
    'not_raw_text': True, 'native_formatter_invoked': False,
    'runtime_popup_verified': False, 'visibility_verified': False,
    'full_display_complete': False, 'complete': False,
}
BUTTONS = (('button1', '_BTN1', 'CenterOK'),
           ('button2', '_BTN2', 'AgreeButton'),
           ('button3', '_BTN3', 'DeclineButton'))
MAX_READABLE_TEXT_BYTES = 256 * 1024


def _unknown(reason):
    return {'status': 'unknown', 'reason': reason}


def project_readable_text(composition, *, include_unknown=True):
    """Join same-record sections while retaining their individual source paths."""
    if 'line1' not in composition and not composition.get('controls'):
        return _unknown('BATTLE_RESULT_TEXT_NOT_CAPTURED')
    selected = [('Line1', '/line1', composition.get('line1', {}))]
    non_text = []
    for index, control in enumerate(composition.get('controls', [])):
        if control['configured_text_assignment_condition'] is not True:
            continue
        path = f'/controls/{index}'
        if control.get('value_kind', 'text') not in ('text', 'formatted_text'):
            non_text.append({'template_key': control['template_key'], 'source_path': path})
            continue
        selected.append((control['template_key'], path + '/text', control.get('text', {})))
    for index, button in enumerate(composition.get('buttons', {}).get('controls', [])):
        if button['configured_text_assignment_condition'] is True:
            selected.append((button['widget'], f'/buttons/controls/{index}', button))

    identity = composition.get('side_identity', {})
    side_rows = identity.get('value', {}).get('sides', []) if identity.get('status') == 'known' else []
    template_sides = [{key: deepcopy(side[key]) for key in (
        'template_label', 'combat_side_index', 'participants', 'observer_participated')}
        for side in side_rows]
    sections, lines, omitted, omitted_identity = [], [], [], []
    used_bytes = 0
    for side in template_sides:
        label = '（观察国所在侧）' if side['observer_participated'] is True else ''
        line = f'[{side["template_label"]}] {"、".join(side["participants"])}{label}\n'
        line_bytes = len(line.encode('utf-8'))
        if used_bytes + line_bytes <= MAX_READABLE_TEXT_BYTES:
            lines.append(line)
            used_bytes += line_bytes
        else:
            omitted_identity.append(side['template_label'])
    for key, path, value in selected:
        text = value.get('text', value.get('value'))
        known = value.get('status') == 'known' and isinstance(text, str)
        section = {'key': key, 'source_path': path, 'status': 'known' if known else 'unknown'}
        if known:
            section.update(basis=value.get('basis'), derived=value.get('derived', True))
            line = f'[{key}] {text}\n'
        else:
            section['reason'] = value.get('reason', 'SECTION_TEXT_UNAVAILABLE')
            line = f'[{key}] [unknown {section["reason"]}]\n'
            if not include_unknown:
                section['included_in_text'] = False
                sections.append(section)
                continue
        line_bytes = len(line.encode('utf-8'))
        if used_bytes + line_bytes <= MAX_READABLE_TEXT_BYTES:
            lines.append(line)
            used_bytes += line_bytes
            section['included_in_text'] = True
        else:
            omitted.append(key)
            section['included_in_text'] = False
        sections.append(section)
    identity_complete = ('side_identity' not in composition
                         or identity.get('status') == 'known' and len(template_sides) == 2)
    complete = (not omitted and not omitted_identity and identity_complete
                and all(item['status'] == 'known' for item in sections))
    return {
        'status': 'known', 'projection_version': 3,
        'text': ''.join(lines), 'sections': sections,
        'basis': 'assembled_same_event_text_sections',
        'source_path_base': 'B04.details.value.display_composition',
        'order_basis': composition.get('order_basis'),
        'known_section_count': sum(item['status'] == 'known' for item in sections),
        'unknown_section_count': sum(item['status'] == 'unknown' for item in sections),
        'selected_text_complete': complete,
        'content_scope': 'configured_result_text_sections',
        'template_sides': template_sides,
        'non_text_controls': non_text,
        'remaining_gaps': list(composition.get('remaining_gaps', [])),
        'omitted_section_keys': omitted,
        'omitted_identity_labels': omitted_identity,
        'output_limit_bytes': MAX_READABLE_TEXT_BYTES,
        'output_limit_reached': bool(omitted or omitted_identity),
        'is_native_raw_text': False, 'complete': complete,
        'runtime_popup_verified': False, 'visibility_verified': False,
    }


def _definition(context):
    kind = context.get('battle_kind')
    fields = context.get('text_fields', {})
    expected = {1: b'LANDBATTLEOVER', 2: b'NAVALBATTLEOVER'}.get(kind)
    return (expected is not None and fields.get('definition_key', {}).get('status') == 'known'
            and fields['definition_key'].get('raw_hex') == expected.hex()
            and fields.get('language', {}).get('status') == 'known')


def project_button_candidates(decoded):
    """The native popup passes zero arguments for all three button labels.

    Paired tokens therefore remain unresolved here, even when another field
    happens to contain a similarly named value. Cache absence is not hiding.
    """
    context = project_display_context(decoded)
    if context.get('status') != 'known' or not _definition(context):
        return {**FLAGS, **_unknown('BUTTON_CANDIDATE_SAME_EVENT_DEFINITION_UNKNOWN')}
    flag = context.get('button_flag_raw')
    if type(flag) is not int or not 0 <= flag <= 255:
        return {**FLAGS, **_unknown('BUTTON_CANDIDATE_FLAG_INVALID')}
    controls = []
    for field_name, suffix, widget in BUTTONS:
        selected = flag == 0 if field_name == 'button1' else flag != 0 if field_name == 'button2' else True
        item = {**FLAGS, 'field': field_name, 'localization_suffix': suffix, 'widget': widget,
                'format_argument_count': 0, 'configured_text_assignment_condition': selected,
                'condition_basis': ('definition_button_flag == 0' if field_name == 'button1' else
                                    'definition_button_flag != 0' if field_name == 'button2' else
                                    'text_assigned_in_both_definition_branches'),
                'actual_visibility': _unknown('RUNTIME_BUTTON_VISIBILITY_NOT_CAPTURED')}
        field = context['text_fields'][field_name]
        if field.get('status') != 'known':
            item.update(_unknown('BUTTON_CANDIDATE_CACHE_KEY_ABSENT_NOT_HIDDEN'
                                 if field.get('status') == 'absent' else 'BUTTON_CANDIDATE_TEMPLATE_UNKNOWN'))
        else:
            try:
                raw = _raw(field.get('raw_hex'))
                parts, count = _parts(raw)
                if count:
                    raise ValueError('zero argument formatter')
                output = _render_parts(parts, b'')
                text = _decode_output(output)
                item.update(status='known', reason=None, raw_hex=output.hex(), text=text,
                            codec='eu4_escape', basis='same_event_literal_zero_argument_template')
            except (ValueError, UnicodeError):
                item.update(_unknown('BUTTON_CANDIDATE_TEMPLATE_REQUIRES_UNSUPPORTED_FORMATTING'))
        controls.append(item)
    return {**FLAGS, 'status': 'known', 'button_flag_raw': flag,
            'sequence': context['sequence'], 'raw_date': context['raw_date'],
            'battle_kind': context['battle_kind'], 'controls': controls}


def project_display_composition(decoded, *, mapping=None, observer_ref=None):
    """Keep copied text, derived candidates and native Line1 distinguishable.

    Only the definition's branch is selected. No projection of a visibility
    bit, callback availability, screen order, or a rendered window is made.
    """
    context = project_display_context(decoded)
    if context.get('status') != 'known' or not _definition(context):
        return {**FLAGS, **_unknown('DISPLAY_COMPOSITION_SAME_EVENT_DEFINITION_UNKNOWN')}
    kind = context['battle_kind']
    layout = 'naval' if kind == 2 else 'land_compact' if context['layout_raw'] == 0 else 'land_detailed'
    native = project_raw_text(project_native_text(decoded), wire_version=6)
    display = project_display(decoded, mapping=mapping, observer_ref=observer_ref,
                              native_line1=native, include_uncaptured_bindings=True)
    if display.get('status') != 'known':
        return {**FLAGS, **_unknown('DISPLAY_COMPOSITION_CONTROL_INPUTS_UNKNOWN')}
    outcome = project_outcome_text_composition(decoded, mapping=mapping, observer_ref=observer_ref)
    physical_ref = (decoded.get('context') or {}).get('physical_player_full_ref')
    rebase_outcome = observer_ref is not None and observer_ref != physical_ref
    quantities = project_quantity_candidates(decoded, mapping=mapping)
    quantity_candidates = quantities.get('candidates', {})
    compact = project_compact_loss_candidates(decoded, quantity_candidates=quantity_candidates)
    compact_by_widget = {item['widget']: item for item in compact.get('controls', [])}
    effects = project_effect_text_candidates(decoded, mapping=mapping)
    effect_candidates = effects.get('candidates', {})
    controls = []
    for original in display['value']['controls']:
        item = {key: deepcopy(original[key]) for key in
                ('template_key', 'widget', 'control_path', 'value_kind', 'layout', 'side_binding')
                if key in original}
        item.update(not_raw_text=True, runtime_widget_verified=False, visibility_verified=False,
                    configured_text_assignment_condition=original['layout'] in ('common', layout))
        copied = original['display_text']
        if copied.get('status') == 'known':
            assert len(original['inputs']) == 1
            source = original['inputs'][0]
            item['text'] = {'status': 'known', 'value': copied['value'],
                            'raw_hex': source['value_raw_hex'], 'codec': 'eu4_escape',
                            'basis': 'same_event_copied_native_control_input',
                            'pair_index': source['pair_index'], 'derived': False}
        elif original.get('widget') in compact_by_widget:
            candidate = compact_by_widget[original['widget']]
            item['text'] = ({'status': 'known', 'value': candidate['decoded']['value'],
                             'raw_hex': candidate['raw_hex'], 'codec': candidate['codec'],
                             'basis': 'derived_compact_loss_candidate', 'derived': True,
                             'pair_index': candidate['input_pair_index']}
                            if candidate.get('status') == 'known' else
                            _unknown(candidate.get('reason', 'COMPACT_CANDIDATE_UNKNOWN')))
        else:
            item['text'] = deepcopy(copied)
        quantity = quantity_candidates.get(original['template_key'])
        if quantity is not None:
            item['quantity_candidate'] = deepcopy(quantity)
            if (not original['inputs'] and quantity.get('status') == 'known'
                    and original.get('widget') not in ('OurLost', 'EnemyLost')):
                item['text'] = deepcopy(quantity)
        if original.get('widget') in compact_by_widget:
            item['compact_loss_candidate'] = deepcopy(compact_by_widget[original['widget']])
        effect = effect_candidates.get(original['template_key'])
        if effect is not None:
            item['effect_candidate'] = deepcopy(effect)
            if not original['inputs'] and effect.get('status') == 'known':
                item['text'] = deepcopy(effect)
        if original['template_key'] == 'WINORLOSE' and (
                outcome.get('status') == 'known' or rebase_outcome):
            candidate = outcome.get('winorlose', _unknown(outcome.get(
                'reason', 'SELECTED_OBSERVER_OUTCOME_UNKNOWN')))
            item['selected_observer_candidate'] = deepcopy(candidate)
            # Copied WINORLOSE describes the physical client. Preserve that
            # observation separately when composing for a different country.
            if rebase_outcome:
                item['native_client_text'] = {
                    **deepcopy(item['text']), 'view_scope': 'physical_client'}
            if not original['inputs'] or rebase_outcome:
                item['text'] = ({
                    'status': 'known', 'value': candidate['text'], 'raw_hex': candidate['raw_hex'],
                    'codec': 'eu4_escape', 'basis': 'derived_selected_observer_winorlose',
                    'derived': True, 'view_scope': outcome['view_scope'],
                    'native_parameter_assignment_verified': False,
                } if candidate.get('status') == 'known' else {
                    **_unknown(candidate.get('reason', 'SELECTED_OBSERVER_OUTCOME_UNKNOWN')),
                    'view_scope': 'selected_observer_not_physical_client'})
        # Numeric/icon inputs retain their existing fixed-build frame contracts.
        for key in ('native_frame_requests', 'declared_frame_asset'):
            if key in original:
                item[key] = deepcopy(original[key])
        controls.append(item)
    body = project_body_candidate(decoded)
    independent = project_independent_line(decoded)
    if native.get('status') == 'known':
        line = native['value']['sections'][0]
        line1 = {'status': 'known', 'text': line['text'], 'raw_hex': line['raw_hex'],
                 'basis': 'wire6_native_line1', 'derived': False, 'native_line1_verified': True}
    elif independent.get('status') == 'known':
        line1 = deepcopy(independent)
    elif body.get('status') == 'known':
        line1 = {'status': 'known', 'text': body['decoded']['value'], 'raw_hex': body['raw_hex'],
                 'basis': 'derived_name_line_candidate', 'derived': True,
                 'input_source': body['input_source'], 'native_line1_verified': False}
    else:
        line1 = _unknown(body.get('reason', 'DISPLAY_COMPOSITION_LINE1_UNKNOWN'))
    buttons = project_button_candidates(decoded)
    gaps = []
    if not line1.get('native_line1_verified'):
        gaps.append('native_line1')
    for control in controls:
        if control['configured_text_assignment_condition'] is not True:
            continue
        control_name = control.get('widget', control['template_key'])
        if control['value_kind'] in ('text', 'formatted_text'):
            if control['text'].get('status') != 'known':
                gaps.append('control_text:' + control_name)
        elif control.get('native_frame_requests', {}).get('status') != 'known':
            gaps.append('control_input:' + control_name)
    for button in buttons.get('controls', []):
        if (button['configured_text_assignment_condition'] is True
                and button.get('status') != 'known'):
            gaps.append('button_text:' + button['widget'])
    gaps.extend(('runtime_widget_state_and_visibility', 'complete_native_window_text'))
    return {**FLAGS, 'status': 'known', 'projection_version': 2, 'sequence': context['sequence'],
            'native_formatter_invoked': line1.get('native_formatter_invoked', False),
            'raw_date': context['raw_date'], 'battle_kind': kind,
            'basis': 'same_event_control_inputs_and_definition_branches',
            'order_basis': 'static_binding_declaration_order_not_screen_order',
            'configured_layout': layout, 'configured_layout_raw': context['layout_raw'],
            'control_template_capture': deepcopy(display['value'].get(
                'template_capture', {'status': 'known'})),
            'quantity_candidate_status': {key: quantities[key] for key in ('status', 'reason')
                                          if key in quantities},
            'effect_candidate_status': {key: effects[key] for key in ('status', 'reason')
                                        if key in effects},
            'actual_layout': _unknown('RUNTIME_LAYOUT_NOT_CAPTURED'),
            'title': _unknown('NATIVE_WINDOW_TITLE_NOT_CAPTURED'),
            'line1': line1, 'buttons': buttons,
            'controls': controls, 'side_identity': deepcopy(display['value']['side_identity']),
            'unbound_pair_indexes': deepcopy(display['value']['unbound_pair_indexes']),
            'remaining_gaps': gaps}
