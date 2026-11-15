"""Compose M05 projections over one captured task state.

The existing chain/timing projectors retain their semantics. This boundary
keeps the selected task, definition generation and observer context together;
it does not evaluate script conditions or invent candidate costs.
"""
from copy import deepcopy

from .mission_chain_targets import CHAIN_FIELDS, MissionChainTargetsSource
from .mission_chain_timing import FIELD as TIMING_FIELD, MissionChainTimingSource
from .missions import MissionInformationSource
from .model import InformationError, canonical

FIELDS=(*CHAIN_FIELDS,TIMING_FIELD)
_CONTEXT_KEYS=('status','mode','observer','session_id','world_id','game_version','game_sha256','game_date')


class MissionAnalysisSource:
    event_types=()

    def __init__(self,missions,cost_reader=None):
        self.missions=missions
        self._selector=MissionChainTimingSource(missions)
        self.cost_reader=cost_reader

    def context(self):
        return deepcopy(self.missions.context())

    def catalog(self):
        topic=deepcopy(self._selector.catalog()[0])
        chain=MissionChainTargetsSource(self.missions).catalog()[0]
        topic['source']=type(self).__name__
        topic['triggers']=['query','periodic'] if self.missions.scheduling else ['query']
        topic['fields'].update(deepcopy(chain['fields']))
        for field in topic['fields'].values():
            field['source']=type(self).__name__
            field['runtime_validation']='existing M05 projections over one captured task state'
        if self.cost_reader is not None:
            from .mission_candidate_costs import MAX_PLANS,MAX_ACTIONS
            topic['parameters']['properties']['candidate_plans']={
                'type':'array','minItems':1,'maxItems':MAX_PLANS,'items':{
                    'type':'object','required':['id','actions'],'additionalProperties':False,
                    'properties':{'id':{'type':'string','maxLength':64},'actions':{
                        'type':'array','minItems':1,'maxItems':MAX_ACTIONS,'items':{
                            'type':'object','required':['id','action_id','recipient','parameters'],
                            'additionalProperties':False,'properties':{
                                'id':{'type':'string','maxLength':64},
                                'action_id':{'type':'string','enum':['declare_war','cede_province']},
                                'recipient':{'type':'string','pattern':'^[A-Z]{3}$'},
                                'parameters':{'type':'object','additionalProperties':True}}}}}}}
            topic['fields']['costs']={'coverage':'partial','complete':False,
                'source':type(self).__name__,'period':'current_state_action_previews',
                'basis':'explicit_candidate_actions_with_native_selection_binding',
                'description':'所选任务的显式候选行动成本预览；各行动独立按当前局势读取，不模拟未来状态或完整战役代价',
                'gaps':['CALLER_SELECTED_TASK_ASSOCIATION_NOT_EVALUATED','FUTURE_MULTISTEP_STATE_NOT_SIMULATED',
                    'COMPLETE_CAMPAIGN_COSTS_UNKNOWN','TRADE_DIPLOMATIC_OPPORTUNITY_COSTS_UNKNOWN']}
        return [topic]

    def validate_query(self,query,context=None):
        if not isinstance(query,dict):
            raise InformationError('invalid_parameters','M05 query must be an object')
        fields=query.get('fields');supported=(*FIELDS,'costs') if self.cost_reader is not None else FIELDS
        if (not isinstance(fields,list) or not fields
                or any(not isinstance(f,str) or f not in supported for f in fields)
                or len(set(fields))!=len(fields)):
            raise InformationError('invalid_fields','Unsupported M05 analysis field')
        base=deepcopy(query);plans=None
        if self.cost_reader is not None and isinstance(base.get('parameters'),dict):
            plans=base['parameters'].pop('candidate_plans',None)
            if 'candidate_plans' in query['parameters']:
                from .mission_candidate_costs import normalize_plans
                country=base.get('object',{}).get('country') if isinstance(base.get('object'),dict) else None
                plans=normalize_plans(plans,country)
        normalized=self._selector.validate_query(dict(base,fields=[TIMING_FIELD]),context)
        if plans is not None:normalized['parameters']['candidate_plans']=plans
        return dict(normalized,fields=deepcopy(fields))

    @staticmethod
    def _failed(fields,reason,status='unknown'):
        return {f:{'status':status,'reason':reason,'complete':False,'partial':True} for f in fields}

    def read(self,query,context=None):
        current=deepcopy(context) if isinstance(context,dict) else self.context()
        normalized=self.validate_query(query,current)
        fields=normalized['fields']
        output={'topic':'M05','fields':{},'complete':False,'game_date':current.get('game_date'),
            'objects':[deepcopy(normalized['object'])],
            'source':{'name':type(self).__name__,'mode':current.get('mode'),
                'session_id':current.get('session_id'),'observer':current.get('observer'),
                'complete':False,'status':'unavailable'}}
        if current.get('status')!='ready':
            output['fields']=self._failed(fields,'source_unavailable','unavailable')
            return output
        try:
            state=self.missions._state(normalized['object']['country'],current)
        except Exception as exc:
            output['fields']=self._failed(fields,getattr(exc,'code','mission_read_failed'),'unavailable')
            return output
        # Only this call above reaches the original reader. Existing projectors
        # can request their own views without taking another native snapshot.
        frozen=MissionInformationSource(self.missions.base_source,self.missions.definitions,
            lambda country:deepcopy(state),scheduling=False,scope_index=self.missions.scope_index)
        components=[]
        projected_query=deepcopy(normalized)
        plans=projected_query['parameters'].pop('candidate_plans',None)
        try:
            definitions_before=deepcopy(self.missions.definitions.context())
            chain_fields=[f for f in fields if f in CHAIN_FIELDS]
            if 'costs' in fields and 'basis' not in chain_fields:chain_fields.append('basis')
            if chain_fields:
                components.append(MissionChainTargetsSource(frozen).read(
                    dict(deepcopy(projected_query),fields=chain_fields),current))
            if TIMING_FIELD in fields:
                components.append(MissionChainTimingSource(frozen).read(
                    dict(deepcopy(projected_query),fields=[TIMING_FIELD]),current))
            costs=None
            if 'costs' in fields:
                anchor=next((p['fields'].get('basis') for p in components if 'basis' in p.get('fields',{})),None)
                if not plans:
                    costs=self._failed(['costs'],'MISSION_CANDIDATE_PLANS_REQUIRED')['costs']
                elif not isinstance(anchor,dict) or anchor.get('status')!='known':
                    costs=self._failed(['costs'],'MISSION_CANDIDATE_TASK_BINDING_UNVERIFIED')['costs']
                else:
                    costs=self.cost_reader.read(plans,normalized['object']['country'],current,
                                                projected_query['parameters'])
            definitions_after=self.missions.definitions.context()
            after=self.context()
            if canonical(definitions_before)!=canonical(definitions_after):
                output['fields']=self._failed(fields,'MISSION_ANALYSIS_DEFINITIONS_CHANGED')
            elif (not isinstance(after,dict) or any(current.get(k)!=after.get(k) for k in _CONTEXT_KEYS)):
                output['fields']=self._failed(fields,'MISSION_ANALYSIS_CONTEXT_CHANGED')
            else:
                for part in components:
                    output['fields'].update({f:deepcopy(v) for f,v in part.get('fields',{}).items() if f in fields})
                if costs is not None:output['fields']['costs']=deepcopy(costs)
                for f in fields:
                    output['fields'].setdefault(f,self._failed([f],'MISSION_ANALYSIS_FIELD_MISSING')[f])
        except Exception as exc:
            output['fields']=self._failed(fields,getattr(exc,'code','mission_projection_failed'),'unavailable')
        output['source'].update(status='observed',provenance={
            'single_captured_state':True,'atomic_with_action_previews':False,
            'selector':deepcopy(normalized['parameters']),
            'components':[deepcopy(p.get('source',{})) for p in components]})
        return output

    def poll_events(self,context,cursor):
        return {'events':[],'cursor':deepcopy(cursor or {}),'complete':True,'gaps':[]}
