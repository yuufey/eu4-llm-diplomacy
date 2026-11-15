"""Normalize and inspect explicit diplomatic action previews.

The shared core returns action previews grouped under the caller's normalized
plans. It does not attach task/scenario semantics and has no execution adapter.
"""
from copy import deepcopy
import re

from .model import InformationError,canonical

MAX_PLANS=8
MAX_ACTIONS=16
MAX_INPUT_BYTES=65536
_ID=re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z')
_COUNTRY=re.compile(r'[A-Z]{3}\Z')


def normalize_plans(value,actor,*,plan_id_pattern=None):
    """Validate explicit action plans using existing diplomacy normalizers.

    ``plan_id_pattern`` is an optional compiled regular expression for the plan
    identifiers only. Action IDs retain the existing 64-character M05 rule.
    """
    # Bound serialized size before entering the existing action normalizers.
    if len(canonical(value).encode('utf-8'))>MAX_INPUT_BYTES:
        raise InformationError('invalid_parameters','Candidate plans exceed byte budget')
    if not isinstance(value,list) or not 1<=len(value)<=MAX_PLANS:
        raise InformationError('invalid_parameters','candidate_plans requires 1-8 explicit plans')
    plan_id_re=_ID if plan_id_pattern is None else plan_id_pattern
    if not callable(getattr(plan_id_re,'fullmatch',None)):
        raise TypeError('plan_id_pattern must be a compiled regular expression')
    from bridge.diplomacy import ObserverSession
    from bridge.peace_execution import normalize_peace_execution_parameters
    result=[];plan_ids=set();total=0
    for plan in value:
        if (not isinstance(plan,dict) or set(plan)!={'id','actions'}
                or not isinstance(plan['id'],str) or not plan_id_re.fullmatch(plan['id'])
                or plan['id'] in plan_ids or not isinstance(plan['actions'],list)
                or not 1<=len(plan['actions'])<=MAX_ACTIONS):
            raise InformationError('invalid_parameters','Invalid or duplicate candidate plan')
        plan_ids.add(plan['id']);actions=[];ids=set()
        for action in plan['actions']:
            total+=1
            if total>MAX_ACTIONS:
                raise InformationError('invalid_parameters','At most 16 candidate actions per query')
            if (not isinstance(action,dict) or set(action)!={'id','action_id','recipient','parameters'}
                    or not isinstance(action['id'],str) or not _ID.fullmatch(action['id'])
                    or action['id'] in ids or not isinstance(action['recipient'],str)
                    or not _COUNTRY.fullmatch(action['recipient']) or action['recipient']==actor
                    or action['action_id'] not in ('declare_war','cede_province')):
                raise InformationError('invalid_parameters','Invalid or duplicate candidate action')
            ids.add(action['id'])
            try:
                if action['action_id']=='declare_war':
                    selected=ObserverSession._normalize_declare_war_parameters(
                        action['parameters'],actor=actor,recipient=action['recipient'])
                    if selected is None:
                        raise ValueError('EXPLICIT_DECLARE_WAR_SELECTION_REQUIRED')
                    params={'casus_belli':selected['casus_belli'],
                        'war_goal':{k:selected[k] for k in ('province_id','beneficiary')},
                        'call_allies':deepcopy(selected['call_allies'])}
                    for k in ('promise_land_to','co_belligerents'):
                        if k in selected:params[k]=deepcopy(selected[k])
                else:
                    params=normalize_peace_execution_parameters('cede_province',actor,
                        action['recipient'],'initiate',action['parameters'])
                    if not any(t['action_id']=='cede_province' for t in params['peace_context']['terms']):
                        raise ValueError('TERRITORIAL_TERM_REQUIRED')
            except (TypeError,ValueError,KeyError) as exc:
                raise InformationError('invalid_parameters',str(exc)) from exc
            actions.append(dict(deepcopy(action),parameters=params))
        result.append({'id':plan['id'],'actions':actions})
    return result


def _unknown(reason):
    return {'status':'unknown','reason':reason,'complete':False}


def project_inspection(action,actor,context,inspected):
    """Qualify the tool's native-bound public result, not a query echo."""
    if not isinstance(inspected,dict) or inspected.get('error_code'):
        return _unknown('CANDIDATE_INSPECTION_UNAVAILABLE')
    session=inspected.get('session')
    if (any(inspected.get(k)!=v for k,v in {'action_id':action['action_id'],
            'actor':actor,'recipient':action['recipient'],'phase':'initiate'}.items())
            or inspected.get('submitted') is not False
            or not isinstance(session,dict) or session.get('status')!='ready'
            or type(session.get('date_raw')) is not int
            or session['date_raw']!=context.get('game_date')):
        return _unknown('CANDIDATE_INSPECTION_IDENTITY_MISMATCH')
    params=action['parameters']
    if action['action_id']=='declare_war':
        actual=inspected.get('parameters',{})
        actual=(actual.get('actual') if isinstance(actual,dict) and actual.get('complete') is True else None)
        expected={'casus_belli':params['casus_belli'],'war_goal':params['war_goal'],
                  'call_allies':params['call_allies']}
        if (inspected.get('selection_requested') is not True
                or inspected.get('selection_matched') is not True
                or type(inspected.get('selection_match_count')) is not int
                or inspected['selection_match_count']!=1
                or inspected.get('requested_casus_belli')!=params['casus_belli']
                or type(inspected.get('requested_province_id')) is not int
                or inspected.get('requested_province_id')!=params['war_goal']['province_id']
                or inspected.get('requested_beneficiary')!=params['war_goal']['beneficiary']
                or not isinstance(actual,dict)
                or any(actual.get(k)!=v for k,v in expected.items())
                or any(actual.get(k,[])!=params.get(k,[]) for k in ('promise_land_to','co_belligerents'))):
            return _unknown('CANDIDATE_DECLARE_WAR_SELECTION_UNVERIFIED')
        costs=inspected.get('costs')
        if (not isinstance(costs,dict) or costs.get('context')!='selected_parameters'
                or costs.get('status')!='partial' or costs.get('complete') is not False
                or not isinstance(costs.get('items'),list)):
            return _unknown('CANDIDATE_DECLARE_WAR_COSTS_UNAVAILABLE')
        rows=[];seen=set()
        for item in costs['items']:
            if not isinstance(item,dict):continue
            resource=item.get('resource');raw=item.get('amount_raw')
            if resource not in ('stability_loss','war_exhaustion'):continue
            if resource in seen:return _unknown('CANDIDATE_DECLARE_WAR_DUPLICATE_COST_RESOURCE')
            seen.add(resource)
            if (type(raw) is not int or not -(1<<31)<=raw<(1<<31)
                    or type(item.get('native_raw')) is not int
                    or item.get('native_raw')!=raw or type(item.get('scale')) is not int
                    or item['scale']!=1000 or item.get('unit')!=resource
                    or item.get('unit_verified') is not True or item.get('scale_verified') is not True
                    or item.get('source')!='native_rule' or item.get('complete') is not True
                    or type(item.get('amount')) not in (int,float) or item['amount']!=raw/1000):
                continue
            rows.append({'resource':resource,'amount_raw':raw,'scale':1000,'unit':resource,
                'source':'native_rule','action_actor':actor,'amount':item['amount'],
                'amount_decimal':('-' if raw<0 else '')+str(abs(raw)//1000)+'.'+str(abs(raw)%1000).zfill(3),
                'cost_country':{'status':'derived','country':actor,'basis':'declaring_actor_rule_context'}})
        if not rows:return _unknown('CANDIDATE_DECLARE_WAR_NO_VERIFIED_COST_ITEMS')
        return {'status':'known','complete':False,'items':rows,
            'unknown_dimensions':['additional_declaration_costs','war_duration_and_losses',
                                  'later_peace_and_expansion_costs','trade_and_diplomatic_opportunity_costs']+
                [r+'_unverified_or_missing' for r in ('stability_loss','war_exhaustion')
                 if r not in {i['resource'] for i in rows}],
            'basis':'native_selected_declare_war_rule_preview','submitted':False}
    peace=inspected.get('peace_context')
    if (not isinstance(peace,dict) or any(peace.get(k)!=v for k,v in params['peace_context'].items())):
        return _unknown('CANDIDATE_PEACE_SELECTION_UNVERIFIED')
    # Exact territorial preview identity alone does not establish all costs.
    # Reuse the existing action projection, retaining unknown/unavailable values.
    from .catalog import get_topic
    from .sources import _field_result
    previews={}
    for topic_id in ('P02','P05'):
        topic=get_topic(topic_id)
        names=(['war_score_cost'] if topic_id=='P02' else list(topic['fields']))
        fields,_=_field_result(names,inspected,topic)
        previews[topic_id]=fields
    return {'status':'known','complete':False,'items':[],
        'preview_fields':previews,'basis':'exact_current_war_territorial_preview',
        'unknown_dimensions':['complete_current_peace_costs','future_war_and_multistep_costs',
                              'trade_and_diplomatic_opportunity_costs'],'submitted':False}


def inspect_plans(inspector,plans,actor,context):
    """Inspect normalized plans and share identical action previews per read.

    The returned mapping is purpose-neutral: ``plans`` retains each caller plan
    id and ordered action result, with read-local call and cache-hit counts.
    """
    outputs=[];cache={};calls=hits=0
    for plan in plans:
        actions=[]
        for action in plan['actions']:
            key=canonical({'actor':actor,'action_id':action['action_id'],
                'recipient':action['recipient'],'parameters':action['parameters']})
            if key in cache:
                hits+=1;projected=deepcopy(cache[key])
            else:
                calls+=1
                try:
                    inspected=inspector(action['action_id'],actor,action['recipient'],
                                         'initiate',deepcopy(action['parameters']))
                    projected=project_inspection(action,actor,context,inspected)
                except Exception:
                    projected=_unknown('CANDIDATE_INSPECTION_FAILED')
                cache[key]=deepcopy(projected)
            actions.append(dict(deepcopy(action),actor=actor,phase='initiate',costs=projected))
        outputs.append({'id':plan['id'],'actions':actions,'complete':False,
            'combined_future_state_evaluated':False,
            'total_cost':_unknown('CROSS_ACTION_TOTAL_NOT_EVALUATED')})
    return {'plans':outputs,'inspector_calls':calls,'shared_result_hits':hits}
