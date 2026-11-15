"""Expose bounded native prerequisite and eligibility short-circuit results."""
from copy import deepcopy

from .mission_condition_profile import PROFILE_SHA256

def gap(reason):
    return {'status':'unknown','reason':reason}

def normalize_conditions(report, prerequisites):
    captured=report.get('mission_conditions')
    if (report.get('request',{}).get('include_conditions') is not True
            or report.get('doublepass',{}).get('condition_consistent') is not True
            or report.get('condition_profile_sha256')!=PROFILE_SHA256
            or report.get('cleanup',{}).get('handle_close',{}).get('closed') is not True
            or not isinstance(captured,dict) or captured.get('status')!='observed'
            or captured.get('complete') is not True or prerequisites.get('status')!='known'):
        return gap('MISSION_CONDITIONS_NOT_VERIFIED')
    records=captured.get('tasks');expected=prerequisites.get('tasks')
    if not isinstance(records,list) or not isinstance(expected,list) or len(records)!=len(expected) or len(records)>4096:
        return gap('MISSION_CONDITION_TASKS_INCOMPLETE')
    tasks=[]
    for row,task in zip(records,expected):
        if not isinstance(row,dict) or (row.get('root_id'),row.get('task_id'))!=(task['root_id'],task['task_id']):
            return gap('MISSION_CONDITION_TASK_MISMATCH')
        required=row.get('required')
        if (type(row.get('task_completed')) is not bool or type(row.get('prerequisites_satisfied')) is not bool
                or not isinstance(required,list) or len(required)!=len(task['required_task_ids'])
                or any(not isinstance(item,dict) or item.get('task_id')!=name or type(item.get('completed')) is not bool
                       for item,name in zip(required,task['required_task_ids']))
                or row['prerequisites_satisfied']!=all(item['completed'] for item in required)):
            return gap('MISSION_CONDITION_RECORD_INVALID')
        tasks.append({'root_id':task['root_id'],'task_id':task['task_id'],
            'task_completed':row['task_completed'],'prerequisites_satisfied':row['prerequisites_satisfied'],
            'required':[{'task_id':item['task_id'],'completed':item['completed']} for item in required]})
    return {'status':'known','tasks':tasks,'canonical_pointer_keys_verified':True,'profile_sha256':PROFILE_SHA256}

def project_eligibility(state, entries, game_version):
    captured=state.get('mission_conditions')
    if game_version!='1.37.4':
        return gap('MISSION_ELIGIBILITY_VERSION_UNSUPPORTED')
    if entries is None:
        return gap('LOADED_TASK_MEMBERSHIP_REQUIRED')
    if not isinstance(captured,dict) or captured.get('status')!='known' or captured.get('canonical_pointer_keys_verified') is not True:
        return gap(captured.get('reason','NATIVE_MISSION_CONDITIONS_NOT_CAPTURED') if isinstance(captured,dict)
                   else 'NATIVE_MISSION_CONDITIONS_NOT_CAPTURED')
    records=captured.get('tasks')
    if not isinstance(records,list) or len(records)>4096:
        return gap('MISSION_CONDITIONS_INVALID')
    by_pair={}
    for row in records:
        if not isinstance(row,dict):
            return gap('MISSION_CONDITIONS_INVALID')
        pair=(row.get('root_id'),row.get('task_id'))
        if (any(not isinstance(value,str) for value in pair) or pair in by_pair
                or type(row.get('task_completed')) is not bool or type(row.get('prerequisites_satisfied')) is not bool):
            return gap('MISSION_CONDITIONS_INVALID')
        by_pair[pair]=row
    tasks=[]
    from .mission_trigger_source import trigger_results
    trigger_by_pair=trigger_results(state) or {}
    for entry in entries:
        pair=(entry['root_id'],entry['task_id'])
        if pair not in by_pair:
            return gap('MISSION_CONDITION_TASKS_INCOMPLETE')
        row=by_pair[pair]
        reason=('TASK_ALREADY_COMPLETED' if row['task_completed'] else
                'REQUIRED_MISSIONS_NOT_COMPLETED' if not row['prerequisites_satisfied'] else
                'TASK_TRIGGER_NOT_EVALUATED')
        trigger=trigger_by_pair.get(pair,gap('TASK_TRIGGER_NOT_EVALUATED'))
        trigger_known=(isinstance(trigger,dict) and trigger.get('status')=='known'
                       and type(trigger.get('satisfied')) is bool)
        if reason=='TASK_TRIGGER_NOT_EVALUATED' and trigger_known:
            reason='TASK_TRIGGER_SATISFIED' if trigger['satisfied'] else 'TASK_TRIGGER_NOT_SATISFIED'
        determined=reason!='TASK_TRIGGER_NOT_EVALUATED'
        tasks.append({'root_id':pair[0],'task_id':pair[1],'status':'known' if determined else 'unknown',
            'currently_completable':(reason=='TASK_TRIGGER_SATISFIED') if determined else None,'reason':reason,
            'checks':{'already_completed':row['task_completed'],'prerequisites_satisfied':row['prerequisites_satisfied'],
                      'task_trigger':deepcopy(trigger)}})
    return {'status':'known','value':{'tasks':tasks,'task_count':len(tasks),
        'known_false_count':sum(row['currently_completable'] is False for row in tasks),
        **({'known_true_count':sum(row['currently_completable'] is True for row in tasks)} if trigger_by_pair else {}),
        'unknown_count':sum(row['status']=='unknown' for row in tasks)},
        'complete':False,'value_origin':('derived_native_eligibility_with_partial_trigger_tree' if trigger_by_pair
                                      else 'derived_native_eligibility_short_circuit'),
        'native_function_called':False,'task_trigger_evaluated':False,'branch_visibility_evaluated':False}
