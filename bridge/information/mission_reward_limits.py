"""Evaluate the selected direct-area reward limits against current inputs."""
from copy import deepcopy
import json

from .foreign_country_memory import _tag_ok


MAX_PROVINCES = 64
MAX_OUTPUT_BYTES = 512 * 1024
PREDICATES = frozenset({'is_core', 'owned_by', 'country_or_non_sovereign_subject_holds'})


def _limit_node(task, rule):
    if (task.get('context_table_status') != 'structural_only'
            or rule.get('raw_node', {}).get('value') != 'ROOT'
            or rule.get('raw_node', {}).get('assignment') != '='):
        return None
    parents = rule.get('parent_scope', [])
    if len(parents) != 2:
        return None
    contexts = task.get('context_table', [])
    refs = rule.get('context_refs', [])
    if not isinstance(contexts, list) or not isinstance(refs, list) or len(refs) != 2:
        return None
    by_id = {row.get('context_id'): row for row in contexts if isinstance(row, dict)}
    if len(by_id) != len(contexts):
        return None
    selected = [by_id.get(ref.get('context_id'), {}) for ref in refs if isinstance(ref, dict)]
    if (len(selected) != 2 or selected[0].get('kind') != 'control'
            or selected[0].get('path') != parents[1].get('path')
            or selected[0].get('key') != parents[1].get('key')
            or selected[1].get('key') != 'limit' or selected[1].get('kind') != 'condition'
            or selected[1].get('parent_scope') != parents):
        return None
    return selected[1].get('raw_node')


def _supported(node, depth=0, budget=None):
    budget = [0] if budget is None else budget
    budget[0] += 1
    if depth > 8 or budget[0] > 64 or not isinstance(node, dict) or node.get('assignment') != '=':
        return False
    if depth == 0 and node.get('key') != 'limit':
        return False
    key, children = node.get('key'), node.get('children')
    if not isinstance(children, list):
        return False
    if node.get('kind') == 'scalar':
        return key in PREDICATES and node.get('value') == 'ROOT' and not children
    if node.get('kind') != 'block' or key not in ('limit', 'AND', 'OR', 'NOT'):
        return False
    if (key == 'limit') != (depth == 0):
        return False
    if key == 'NOT' and len(children) != 1:
        return False
    return bool(children) and all(_supported(child, depth + 1, budget) for child in children)


def _evaluate(node, checks):
    key = node['key']
    if node['kind'] == 'scalar':
        row = checks.get(key, {})
        value = row.get('value')
        return value if row.get('status') == 'known' and type(value) is bool else None
    values = [_evaluate(child, checks) for child in node['children']]
    if key == 'NOT':
        return None if values[0] is None else not values[0]
    if key == 'OR':
        return True if True in values else (None if None in values else False)
    return False if False in values else (None if None in values else True)


def project_current_limits(field, reader, context):
    result = deepcopy(field)
    if result.get('status') != 'known' or not isinstance(result.get('value'), dict):
        return result
    pending, province_ids, seen = [], [], set()
    for task in result['value'].get('rules', []):
        for rule in task.get('rules', []):
            candidate = rule.get('declared_area_candidates', {})
            if candidate.get('status') != 'known':
                continue
            node = _limit_node(task, rule)
            if not _supported(node):
                candidate['current_limit_evaluation'] = {
                    'status': 'unknown', 'reason': 'REWARD_LIMIT_SHAPE_UNSUPPORTED'}
                continue
            pending.append((candidate, node))
            for province_id in candidate['candidate_province_ids']:
                if province_id not in seen:
                    seen.add(province_id)
                    province_ids.append(province_id)
    if not pending:
        return result
    inputs = {}
    reason = 'REWARD_LIMIT_READER_UNAVAILABLE'
    if callable(reader):
        try:
            captured = reader(province_ids[:MAX_PROVINCES], context)
            if (isinstance(captured, dict) and all(
                    type(captured.get(key)) is type(context.get(key))
                    and captured.get(key) == context.get(key)
                    for key in ('observer', 'session_id', 'game_date'))
                    and _tag_ok(context.get('observer')) and context.get('session_id')
                    and context.get('game_date') is not None
                    and isinstance(captured.get('provinces'), dict)):
                inputs = captured['provinces']
                reason = 'REWARD_LIMIT_INPUT_UNAVAILABLE'
            else:
                reason = 'REWARD_LIMIT_CONTEXT_MISMATCH'
        except Exception:
            reason = 'REWARD_LIMIT_COLLECTION_FAILED'
    selected_ids = set(province_ids[:MAX_PROVINCES])
    output_bytes = 0
    for candidate, node in pending:
        rows, satisfied, excluded, unknown = [], [], [], []
        for province_id in candidate['candidate_province_ids']:
            data = inputs.get(str(province_id), {}) if province_id in selected_ids else {}
            if not isinstance(data, dict):
                data = {}
            checks = data.get('checks', {}) if data.get('status') == 'known' else {}
            if not isinstance(checks, dict):
                checks = {}
            value = _evaluate(node, checks)
            row = {'province_id': province_id, 'status': 'known' if value is not None else 'unknown',
                   'satisfies_limit': value, 'inputs': {}}
            if data.get('basis') == 'pinned_province_core_owner_and_native_subject_criterion':
                row['source'] = {'basis': data['basis'], 'profile_sha256': data.get('profile_sha256')}
            for name in sorted(PREDICATES):
                check = checks.get(name, {})
                if isinstance(check, dict) and check.get('status') == 'known' and type(check.get('value')) is bool:
                    row['inputs'][name] = {'status': 'known', 'value': check['value']}
            if value is True:
                satisfied.append(province_id)
            elif value is False:
                excluded.append(province_id)
            else:
                unknown.append(province_id)
                row['reason'] = ('REWARD_LIMIT_PROVINCE_BUDGET' if province_id not in selected_ids
                                 else reason)
            if len(rows) < MAX_PROVINCES:
                rows.append(row)
        evaluation = {
            'status': 'known' if not unknown else 'unknown',
            'basis': 'current_snapshot_static_reward_limit_with_native_inputs',
            'observer': context['observer'], 'session_id': context.get('session_id'),
            'game_date': context['game_date'], 'provinces': rows,
            'satisfying_province_ids': satisfied, 'excluded_province_ids': excluded,
            'unknown_province_ids': unknown, 'complete': not unknown,
            'omitted_province_row_count': len(candidate['candidate_province_ids']) - len(rows),
            'execution_observed': False,
            'snapshot_atomic_main_thread': False,
        }
        size = len(json.dumps(evaluation, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))
        if output_bytes + size > MAX_OUTPUT_BYTES:
            evaluation = {'status': 'unknown', 'reason': 'REWARD_LIMIT_OUTPUT_BUDGET',
                          'execution_observed': False}
        else:
            output_bytes += size
        candidate['current_limit_evaluation'] = evaluation
    return result
