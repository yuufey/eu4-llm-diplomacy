"""Project captured required_missions without substituting current disk rules."""
from copy import deepcopy
import re

from .mission_prerequisite_profile import PROFILE_SHA256
from .mission_requirements import evaluate_prerequisites

ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')

def gap(reason):
    return {'status': 'unknown', 'reason': reason}

def normalize_prerequisites(report, loaded):
    captured = report.get('loaded_prerequisites')
    if (report.get('request', {}).get('include_prerequisites') is not True
            or report.get('doublepass', {}).get('prerequisite_consistent') is not True
            or report.get('prerequisite_profile_sha256') != PROFILE_SHA256
            or report.get('cleanup', {}).get('handle_close', {}).get('closed') is not True
            or not isinstance(captured, dict) or captured.get('status') != 'observed'
            or captured.get('complete') is not True or loaded.get('status') != 'known'):
        return gap('LOADED_PREREQUISITES_NOT_VERIFIED')
    expected = [(root['root_id'], task) for root in loaded['roots'] for task in root['task_ids']]
    records = captured.get('tasks')
    if not isinstance(records, list) or len(records) != len(expected) or len(records) > 4096:
        return gap('LOADED_PREREQUISITE_TASKS_INCOMPLETE')
    tasks, total = [], 0
    for record, pair in zip(records, expected):
        if not isinstance(record, dict) or (record.get('root_id'), record.get('task_id')) != pair:
            return gap('LOADED_PREREQUISITE_TASK_MISMATCH')
        ids = record.get('required_task_ids')
        vector = record.get('vector')
        if (not isinstance(ids, list) or len(ids) > 512
                or any(not isinstance(value, str) or not ID.fullmatch(value) for value in ids)
                or not isinstance(vector, dict) or type(vector.get('count')) is not int
                or vector['count'] != len(ids)):
            return gap('LOADED_PREREQUISITE_VECTOR_INVALID')
        total += len(ids)
        if total > 4096:
            return gap('LOADED_PREREQUISITE_LIMIT')
        tasks.append({'root_id': pair[0], 'task_id': pair[1], 'required_task_ids': deepcopy(ids)})
    return {'status': 'known', 'tasks': tasks, 'profile_sha256': PROFILE_SHA256}

def project_prerequisites(state, loaded_entries, definitions, game_version):
    """None means this reader did not request native prerequisite capture."""
    if 'loaded_prerequisites' not in state:
        return None
    if game_version != '1.37.4':
        return gap('PREREQUISITE_SEMANTICS_VERSION_UNSUPPORTED')
    captured = state['loaded_prerequisites']
    if not isinstance(captured, dict) or captured.get('status') != 'known':
        return gap(captured.get('reason', 'LOADED_PREREQUISITES_NOT_VERIFIED')
                   if isinstance(captured, dict) else 'LOADED_PREREQUISITES_INVALID')
    if loaded_entries is None:
        return gap('LOADED_TASK_MEMBERSHIP_REQUIRED')
    records = captured.get('tasks')
    if not isinstance(records, list) or len(records) > 4096:
        return gap('LOADED_PREREQUISITES_INVALID')
    by_pair = {}
    for record in records:
        if not isinstance(record, dict):
            return gap('LOADED_PREREQUISITES_INVALID')
        pair = (record.get('root_id'), record.get('task_id'))
        ids = record.get('required_task_ids')
        if (any(not isinstance(value, str) or not ID.fullmatch(value) for value in pair)
                or pair in by_pair or not isinstance(ids, list) or len(ids) > 512
                or any(not isinstance(value, str) or not ID.fullmatch(value) for value in ids)):
            return gap('LOADED_PREREQUISITES_INVALID')
        by_pair[pair] = ids
    definition_map = {(task['root_id'], task['task_id']): task for task in definitions}
    conditions = state.get('mission_conditions', {})
    condition_map = {}
    if (isinstance(conditions,dict) and conditions.get('status')=='known'
            and conditions.get('canonical_pointer_keys_verified') is True):
        rows=conditions.get('tasks')
        if not isinstance(rows,list) or len(rows)>4096:
            return gap('MISSION_CONDITION_RECORD_INVALID')
        for row in rows:
            if not isinstance(row,dict) or any(not isinstance(row.get(key),str) for key in ('root_id','task_id')):
                return gap('MISSION_CONDITION_RECORD_INVALID')
            pair=(row['root_id'],row['task_id'])
            if pair in condition_map:
                return gap('MISSION_CONDITION_RECORD_INVALID')
            condition_map[pair]=row
    entries = []
    for task in loaded_entries:
        pair = (task['root_id'], task['task_id'])
        if pair not in by_pair:
            return gap('LOADED_PREREQUISITE_TASKS_INCOMPLETE')
        ids = by_pair[pair]
        evaluation = {'status': 'known' if not ids else 'unknown',
                      'satisfied': True if not ids else None,
                      'required_task_ids': deepcopy(ids),
                      'missing_task_ids': [] if not ids else None,
                      'scope': 'loaded_required_missions_only',
                      'native_function_called': False}
        if ids:
            evaluation['reason'] = 'CANONICAL_PREREQUISITE_DEFINITION_LOOKUP_NOT_CAPTURED'
        if pair in condition_map:
            condition = condition_map[pair]
            required = condition.get('required')
            if (not isinstance(required,list) or any(not isinstance(item,dict) for item in required)
                    or [item.get('task_id') for item in required]!=ids
                    or any(type(item.get('completed')) is not bool for item in required)
                    or type(condition.get('prerequisites_satisfied')) is not bool
                    or condition['prerequisites_satisfied']!=all(item['completed'] for item in required)):
                return gap('MISSION_CONDITION_RECORD_INVALID')
            evaluation.update(status='known',satisfied=condition['prerequisites_satisfied'],
                              missing_task_ids=[item['task_id'] for item in required if not item['completed']],
                              canonical_pointer_keys_verified=True,required_definitions=deepcopy(required))
            evaluation.pop('reason',None)
        definition = definition_map.get(pair)
        rules = deepcopy(definition.get('required_missions')) if definition is not None else None
        declared = evaluate_prerequisites(rules, state.get('completed_missions'), game_version=game_version)
        entries.append({'root_id': pair[0], 'task_id': pair[1],
                        'value_origin': 'captured_loaded_required_missions',
                        'required_task_ids': deepcopy(ids), 'declared_rules': rules,
                        'declared_rule_evaluation': declared,
                        'declared_rules_match_loaded_ids': (
                            declared['required_task_ids'] == ids if declared['required_task_ids'] is not None else None),
                        'evaluated': evaluation['status'] == 'known', 'evaluation': evaluation})
    return {'status': 'known', 'value': entries, 'complete': False,
            'value_origin': 'captured_loaded_required_missions',
            'task_trigger_evaluated': False, 'branch_visibility_evaluated': False}
