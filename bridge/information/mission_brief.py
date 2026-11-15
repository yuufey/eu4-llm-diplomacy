"""Associate selected mission claims with same-report task facts."""
from copy import deepcopy


MAX_TASKS = 64
MAX_RULES = 128


def _key(item, task):
    objects = item.get('objects', [])
    if not isinstance(objects, list):
        return None
    countries = [obj.get('country') for obj in objects
                 if isinstance(obj, dict) and obj.get('type') == 'country']
    date = item.get('game_date')
    root, task_id = task.get('root_id'), task.get('task_id')
    dated = (type(date) is int and date > 0) or (type(date) is str and bool(date))
    if (len(countries) != 1 or not isinstance(countries[0], str) or not dated
            or not isinstance(root, str) or not isinstance(task_id, str)):
        return None
    source = item.get('source', {})
    if not isinstance(source, dict):
        return None
    return (countries[0], date, root, task_id, source.get('mode'),
            source.get('session_id'), source.get('observer'))


def _fact(items, key, topic, field, collection, attribute, expected_type):
    matches = []
    for index, item in enumerate(items):
        if not isinstance(item, dict) or item.get('topic') != topic:
            continue
        fields = item.get('fields')
        if not isinstance(fields, dict):
            continue
        value = fields.get(field, {})
        if not isinstance(value, dict) or value.get('status') != 'known':
            continue
        container = value.get('value')
        if not isinstance(container, dict):
            continue
        rows = container.get(collection, [])
        if not isinstance(rows, list):
            continue
        for offset, row in enumerate(rows):
            if isinstance(row, dict) and key is not None and _key(item, row) == key:
                matches.append((row.get(attribute) if row.get('status') == 'known' else None,
                    f'/items/{index}/fields/{field}/value/{collection}/{offset}/{attribute}'))
    if (not matches or any(type(value) is not expected_type for value, _ in matches)
            or any(value != matches[0][0] for value, _ in matches)):
        return {'status': 'unknown', 'reason': 'MISSION_BRIEF_FACT_UNAVAILABLE_OR_CONFLICTING'}
    return {'status': 'known', 'value': matches[0][0],
            'source_paths': [path for _, path in matches]}


def project_mission_claim_briefs(result):
    """Use declarations and completion facts without evaluating reward effects."""
    items = result.get('items', [])
    summaries = []
    for index, item in enumerate(items):
        if not isinstance(item, dict) or item.get('topic') != 'M04':
            continue
        fields = item.get('fields')
        if not isinstance(fields, dict):
            continue
        field = fields.get('claims', {})
        if not isinstance(field, dict) or field.get('status') != 'known':
            continue
        value = field.get('value')
        if not isinstance(value, dict) or value.get('semantics') != 'declared_literal_effect_rules':
            continue
        tasks = value.get('rules')
        if not isinstance(tasks, list):
            continue
        for offset, task in enumerate(tasks):
            if not isinstance(task, dict) or task.get('status') != 'known':
                continue
            if len(summaries) == MAX_TASKS:
                summaries[-1]['omitted_task_count'] += 1
                continue
            key = _key(item, task)
            name = _fact(items, key, 'M01', 'name', 'entries', 'text', str)
            completable = _fact(items, key, 'M02', 'currently_completable',
                                'tasks', 'currently_completable', bool)
            path = f'/items/{index}/fields/claims/value/rules/{offset}'
            rules = task.get('rules', [])
            if not isinstance(rules, list):
                continue
            claims = []
            for rule_index, rule in enumerate(rules[:MAX_RULES]):
                if not isinstance(rule, dict):
                    continue
                command = rule.get('command')
                node, scopes = rule.get('raw_node'), rule.get('parent_scope')
                if (command not in ('add_claim', 'add_permanent_claim')
                        or not isinstance(node, dict) or not isinstance(scopes, list)):
                    continue
                scopes = [scope.get('key') for scope in scopes
                          if isinstance(scope, dict) and scope.get('key') != 'effect']
                claims.append({
                    'command': command,
                    'recipient_expression': deepcopy(node.get('value')),
                    'declared_scope_keys': scopes,
                    'context_status': rule.get('context_status', 'unknown'),
                    'source_path': f'{path}/rules/{rule_index}',
                    'condition_context_path': f'{path}/rules/{rule_index}/condition_context',
                    'applicability': 'unknown', 'applied': 'unknown',
                })
                candidate = rule.get('declared_area_candidates')
                if isinstance(candidate, dict):
                    claims[-1]['declared_area_candidates'] = {
                        key: deepcopy(candidate[key]) for key in
                        ('status', 'reason', 'kind', 'identifier', 'candidate_province_ids',
                         'reward_limits_evaluated', 'applied', 'current_limit_evaluation') if key in candidate}
                    claims[-1]['declared_area_candidates']['source_path'] = f'{path}/rules/{rule_index}/declared_area_candidates'
            label = name['value'] if name['status'] == 'known' else task.get('task_id', '未知任务')
            state = '任务当前可完成' if completable.get('value') is True else (
                '任务当前不可完成' if completable.get('value') is False else '任务当前可完成性未知')
            lines = [f'{label}。{state}。']
            if not rules:
                lines.append('所选字段未发现字面宣称规则。')
            for claim in claims:
                kind = '永久宣称' if claim['command'] == 'add_permanent_claim' else '宣称'
                scopes = '/'.join(str(scope) for scope in claim['declared_scope_keys']) or 'effect'
                lines.append(f'声明{kind}，作用域 {scopes}，接收方表达式 {claim["recipient_expression"]}。')
                candidate = claim.get('declared_area_candidates', {})
                if candidate.get('status') == 'known':
                    members = candidate['candidate_province_ids']
                    current = candidate.get('current_limit_evaluation', {})
                    if 'satisfying_province_ids' in current:
                        included = ', '.join(map(str, current['satisfying_province_ids'])) or '无'
                        excluded = ', '.join(map(str, current['excluded_province_ids'])) or '无'
                        unknown = ', '.join(map(str, current['unknown_province_ids'])) or '无'
                        lines.append(f'按当前状态满足地区奖励限制的省份为 {included}，不满足为 {excluded}，未知为 {unknown}。')
                    else:
                        lines.append(f'该地区的候选省份为 {", ".join(map(str, members))}，奖励限制尚未求值。'
                                     if members else '该地区定义未列出候选省份，奖励限制尚未求值。')
            if any('current_limit_evaluation' in claim.get('declared_area_candidates', {}) for claim in claims):
                lines.append('地区限制判断采用当前状态，任务完成时需重新读取。奖励实际执行状态未知。')
            else:
                lines.append('奖励条件与作用域适用性尚未求值，奖励实际执行状态未知。')
            summaries.append({
                'projection_version': 1,
                'root_id': task.get('root_id'), 'task_id': task.get('task_id'),
                'country': key[0] if key else None, 'game_date': item.get('game_date'),
                'name': name, 'currently_completable': completable,
                'claims': claims, 'source_path': path, 'text': '\n'.join(lines),
                'omitted_rule_count': max(0, len(rules) - MAX_RULES),
                'unrepresented_rule_count': len(rules) - len(claims),
                'omitted_task_count': 0,
                'basis': 'selected_same_report_mission_facts_and_declared_claim_rules',
                'reward_conditions_evaluated': False, 'reward_execution_observed': False,
                'complete': False,
            })
    return summaries
