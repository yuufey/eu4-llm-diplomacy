"""Summarize selected same-event battle facts at the presentation boundary."""
from copy import deepcopy


TOPIC_FIELDS = {
    'B01': ('event_id', 'battle_type', 'name', 'location', 'end_date', 'sides', 'war_id', 'winner'),
    'B02': ('initial_forces', 'losses', 'remaining_forces'),
    'B03': ('war_score', 'prestige', 'army_tradition', 'naval_tradition', 'war_exhaustion', 'ships_captured', 'annihilation', 'retreat'),
}
REQUIRED = ('battle_type', 'name', 'sides', 'winner', 'initial_forces', 'losses', 'remaining_forces')
LABELS = {'attacker': '进攻方', 'defender': '防守方', 'victory': '战胜', 'defeat': '战败',
          'men': '人', 'ships': '艘', 'land': '陆战', 'naval': '海战'}
SIDE_EFFECTS = (('war_score', '战争分'), ('prestige', '威望'), ('army_tradition', '陆军传统'),
                ('naval_tradition', '海军传统'), ('war_exhaustion', '厌战'))


def _known(field):
    return isinstance(field, dict) and field.get('status') == 'known' and 'value' in field


def _side_metric(field, index, participants, path):
    """Retain whole-side component sums and the native naval net-change label."""
    if not _known(field):
        return {'status': field.get('status', 'unknown'), 'reason': field.get('reason', 'FIELD_NOT_SELECTED')}
    value = field['value']
    matches = [(offset, side) for offset, side in enumerate(value['sides'])
               if side['combat_side_index'] == index]
    if len(matches) != 1 or matches[0][1]['participants'] != participants:
        return {'status': 'unknown', 'reason': 'BATTLE_BRIEF_SIDE_IDENTITY_MISMATCH'}
    offset, side = matches[0]
    count = side['component_sum']
    if type(count) is not int or value['unit'] not in ('men', 'ships') or value['scale'] != 1:
        return {'status': 'unknown', 'reason': 'BATTLE_BRIEF_COUNT_UNSUPPORTED'}
    return {'status': 'known', 'value': count, 'unit': value['unit'], 'scale': 1,
            'quantity': value.get('quantity', 'displayed_component_sum'),
            'scope': value['scope'], 'source_path': f'{path}/value/sides/{offset}/component_sum',
            'basis': value['basis']}


def _side_effect(field, field_name, index, participants, path):
    """Retain the source's whole-side operand and its formatted display value."""
    if not isinstance(field, dict):
        return {'status': 'unknown', 'reason': 'BATTLE_BRIEF_EFFECT_UNSUPPORTED'}
    if not _known(field):
        return {'status': field.get('status', 'unknown'), 'reason': field.get('reason', 'FIELD_NOT_SELECTED')}
    value = field['value']
    if not isinstance(value, dict) or not isinstance(value.get('sides'), list):
        return {'status': 'unknown', 'reason': 'BATTLE_BRIEF_EFFECT_UNSUPPORTED'}
    matches = [(offset, side) for offset, side in enumerate(value['sides'])
               if isinstance(side, dict) and type(side.get('combat_side_index')) is int
               and side['combat_side_index'] == index]
    if len(matches) != 1 or matches[0][1].get('participants') != participants:
        return {'status': 'unknown', 'reason': 'BATTLE_BRIEF_SIDE_IDENTITY_MISMATCH'}
    offset, side = matches[0]
    if (value.get('unit') != field_name or value.get('scale') != 1000
            or value.get('scope') != 'whole_combat_side'
            or value.get('quantity') != 'result_window_side_operand'
            or type(side.get('raw')) is not int or not isinstance(side.get('display_numeric'), str)
            or not isinstance(side.get('amount_decimal'), str) or not isinstance(value.get('basis'), str)):
        return {'status': 'unknown', 'reason': 'BATTLE_BRIEF_EFFECT_UNSUPPORTED'}
    return {'status': 'known', 'raw': side['raw'], 'amount_decimal': side['amount_decimal'],
            'display_numeric': side['display_numeric'], 'unit': value['unit'], 'scale': value['scale'],
            'scope': value['scope'], 'quantity': value['quantity'], 'basis': value['basis'],
            'source_path': f'{path}/value/sides/{offset}/raw',
            'display_source_path': f'{path}/value/sides/{offset}/display_numeric'}


def _side_annihilation(field, index, participants, path):
    if not _known(field):
        return None
    value = field['value']
    if (not isinstance(value, dict) or value.get('scope') != 'whole_combat_side'
            or value.get('basis') != 'native_combat_side_overrun_marker'
            or not isinstance(value.get('sides'), list)):
        return None
    matches = [(offset, side) for offset, side in enumerate(value['sides'])
               if isinstance(side, dict) and type(side.get('combat_side_index')) is int
               and side['combat_side_index'] == index]
    if len(matches) != 1:
        return None
    offset, side = matches[0]
    state = side.get('annihilated', {})
    if side.get('participants') != participants or not _known(state) or state['value'] is not True:
        return None
    return {'status': 'known', 'value': True, 'scope': value['scope'], 'basis': value['basis'],
            'source_path': f'{path}/value/sides/{offset}/annihilated/value'}


def _side_retreat(field, index, participants, observer, path):
    if not _known(field):
        return None
    value = field['value']
    if (not isinstance(value, dict) or value.get('retreating') is not True
            or value.get('scope') not in ('observer_owned_units_at_regular_battle_end',
                                         'observer_owned_units_before_combat_removal')
            or value.get('observer') != observer or observer not in participants
            or type(value.get('combat_side_index')) is not int or value['combat_side_index'] != index):
        return None
    return {'status': 'known', 'value': True, 'scope': value['scope'], 'observer': observer,
            'source_path': f'{path}/value/retreating'}


def _side_capture(field, index, participants, path):
    if not _known(field):
        return None
    value = field['value']
    if (not isinstance(value, dict) or value.get('scope') != 'whole_combat_side'
            or value.get('quantity') != 'native_result_window_capture_count'
            or value.get('unit') != 'ships' or type(value.get('scale')) is not int or value['scale'] != 1
            or type(value.get('total')) is not int or value['total'] < 0
            or not _known(value.get('capturing_side'))):
        return None
    side = value['capturing_side']['value']
    if (not isinstance(side, dict) or type(side.get('combat_side_index')) is not int
            or side['combat_side_index'] != index or side.get('participants') != participants):
        return None
    return {'status': 'known', 'value': value['total'], 'unit': 'ships', 'scale': 1,
            'scope': value['scope'], 'quantity': value['quantity'],
            'source_path': f'{path}/value/total'}


def _project(event_id, fields, paths, observer):
    facts = {name: deepcopy(value) for name, value in fields.items()}
    missing = [name for name in REQUIRED if not _known(fields.get(name))]
    lines, sides = [], []
    name = fields.get('name', {})
    kind = fields.get('battle_type', {})
    title = str(name['value']) if _known(name) else '战役名称未知'
    battle_type = LABELS.get(kind.get('value'), '战斗类型未知') if _known(kind) else '战斗类型未知'
    lines.append(title + '，' + battle_type + '。')
    winner = fields.get('winner', {})
    if _known(winner) and winner['value'].get('observer_outcome') in ('victory', 'defeat'):
        lines.append('观察国' + observer + LABELS[winner['value']['observer_outcome']] + '。')
    else:
        lines.append('胜负未知。')
    side_field = fields.get('sides', {})
    if _known(side_field):
        indices = [side['combat_side_index'] for side in side_field['value']]
        if len(indices) != 2 or set(indices) != {0, 1}:
            raise ValueError('BATTLE_BRIEF_SIDE_MAPPING_UNRESOLVED')
        for offset, side in enumerate(side_field['value']):
            index, participants = side['combat_side_index'], side['participants']
            if side.get('participants_complete') is not True or not participants:
                raise ValueError('BATTLE_BRIEF_PARTICIPANTS_UNRESOLVED')
            role = side.get('role', {})
            projected = {'combat_side_index': index, 'participants': deepcopy(participants),
                         'role': deepcopy(role), 'observer_participated': side['observer_participated'],
                         'source_path': f'{paths["sides"]}/value/{offset}'}
            parts = []
            for field_name, label in (('initial_forces', '各类初始合计'),
                                      ('losses', '各类损失合计'), ('remaining_forces', '各类剩余合计')):
                metric = _side_metric(fields.get(field_name, {}), index, participants, paths.get(field_name, ''))
                projected[field_name] = metric
                if metric['status'] == 'known':
                    if metric['quantity'] == 'net_ship_change':
                        label = '舰船净变化'
                    parts.append(label + str(metric['value']) + LABELS[metric['unit']])
                else:
                    parts.append(label + '未知')
            prefix = LABELS.get(role.get('value'), '阵营') if _known(role) else '阵营'
            lines.append(prefix + ' ' + '、'.join(participants) + '。' + '，'.join(parts) + '。')
            effects, effect_parts = {}, []
            for field_name, label in SIDE_EFFECTS:
                supported_kind = {'army_tradition': 'land', 'naval_tradition': 'naval'}.get(field_name)
                if field_name not in fields or (supported_kind is not None and kind.get('value') != supported_kind):
                    continue
                effect = _side_effect(fields[field_name], field_name, index, participants, paths[field_name])
                effects[field_name] = effect
                effect_parts.append(label + (effect['display_numeric'] if effect['status'] == 'known' else '未知'))
            if effects:
                projected['effects'] = effects
                lines.append('该参战侧的战报结果量为' + '，'.join(effect_parts) + '。')
            outcomes, outcome_parts = {}, []
            annihilation = _side_annihilation(fields.get('annihilation'), index, participants,
                                               paths.get('annihilation', ''))
            if annihilation is not None:
                outcomes['annihilation'] = annihilation
                outcome_parts.append('该参战侧被歼灭')
            retreat = _side_retreat(fields.get('retreat'), index, participants, observer, paths.get('retreat', ''))
            if retreat is not None:
                outcomes['retreat'] = retreat
                if retreat['scope'] == 'observer_owned_units_before_combat_removal':
                    outcome_parts.append('观察国有参战部队处于撤退状态')
                else:
                    outcome_parts.append('观察国有参战部队开始撤退')
            captured = _side_capture(fields.get('ships_captured'), index, participants, paths.get('ships_captured', ''))
            if captured is not None:
                outcomes['ships_captured'] = captured
                outcome_parts.append('该参战侧俘获舰船' + str(captured['value']) + '艘')
            if outcomes:
                projected['outcomes'] = outcomes
                lines.append('，'.join(outcome_parts) + '。')
            sides.append(projected)
    return {'status': 'known', 'event_id': event_id, 'observer': observer,
            'text': '\n'.join(lines), 'facts': facts, 'sides': sides, 'source_paths': paths,
            'missing_core_fields': missing, 'basis': 'selected_same_event_structured_fields',
            'is_native_raw_text': False, 'complete': False,
            'scope': 'captured_record_and_whole_combat_sides',
            'limitations': ['SOURCE_FIELD_LIMITATIONS_APPLY', 'FULL_ORIGINAL_TEXT_REMAINS_SEPARATE']}


def project_battle_briefs(result):
    """Group selected fields by explicit record ID, never by location or date."""
    groups = {}
    event = result.get('event')
    event = event if isinstance(event, dict) else {}
    trigger_id = event.get('event_id') if event.get('event_type') == 'battle_observation' else None
    context = result.get('context')
    observer = context.get('observer', '') if isinstance(context, dict) else ''
    for item_index, item in enumerate(result['items']):
        if not isinstance(item, dict):
            continue
        query = item.get('query') or {}
        if not isinstance(query, dict):
            continue
        topic = item.get('topic') or query.get('topic')
        if not isinstance(topic, str) or topic not in TOPIC_FIELDS:
            continue
        fields = item.get('fields', {})
        parameters = query.get('parameters', {})
        if not isinstance(fields, dict) or not isinstance(parameters, dict):
            continue
        selected_id = parameters.get('event_id')
        observed_id = fields.get('event_id', {})
        observed_id = observed_id['value'] if _known(observed_id) else None
        event_id = selected_id or observed_id or trigger_id
        if not isinstance(event_id, str) or not event_id:
            continue
        group = groups.setdefault(event_id, {'fields': {}, 'paths': {}, 'conflict': False})
        if observed_id is not None and event_id != observed_id:
            group['conflict'] = True
        for name in TOPIC_FIELDS[topic]:
            if name not in fields:
                continue
            if name in group['fields'] and group['fields'][name] != fields[name]:
                group['conflict'] = True
            group['fields'][name] = fields[name]
            group['paths'][name] = f'/items/{item_index}/fields/{name}'
    output = []
    for event_id, group in groups.items():
        try:
            if group['conflict']:
                raise ValueError('BATTLE_BRIEF_CONFLICTING_SELECTED_FIELDS')
            output.append(_project(event_id, group['fields'], group['paths'], observer))
        except (KeyError, TypeError, ValueError, AttributeError):
            output.append({'status': 'unknown', 'event_id': event_id,
                           'reason': 'BATTLE_BRIEF_FIELDS_UNRESOLVED', 'complete': False})
    return output
