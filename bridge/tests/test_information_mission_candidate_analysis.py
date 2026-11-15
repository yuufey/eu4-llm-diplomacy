"""Candidate previews remain anchored to the captured selected task."""
from copy import deepcopy

from bridge.information.composite import CompositeSource
from bridge.information.mission_analysis import MissionAnalysisSource
from bridge.tests.test_information_mission_chain_targets import setup_source


PLANS=[{'id':'plan-a','actions':[{'id':'declare','action_id':'declare_war',
    'recipient':'ENG','parameters':{'casus_belli':'no_casus_belli',
        'war_goal':{'province_id':-1,'beneficiary':'FRA'},'call_allies':[]}}]}]


class Costs:
    def __init__(self,mutate=None):self.calls=[];self.mutate=mutate

    def read(self,plans,actor,context,selector):
        self.calls.append(deepcopy((plans,actor,context,selector)))
        if self.mutate:self.mutate()
        return {'status':'known','partial':True,'complete':False,
                'value':{'selector':deepcopy(selector),'plans':deepcopy(plans)}}


def setup(mutator=None):
    _,missions,primary,state,definitions=setup_source()
    costs=Costs(mutator)
    return MissionAnalysisSource(missions,cost_reader=costs),primary,state,definitions,costs


def query(fields=('linked_targets','basis','reward_timing','costs'),plans=PLANS):
    parameters={'root_id':'root_main','task_id':'task_core'}
    if plans is not None:parameters['candidate_plans']=deepcopy(plans)
    return {'topic':'M05','object':{'type':'country','country':'FRA'},
            'fields':list(fields),'parameters':parameters}


def test_all_four_fields_share_task_state_and_only_explicit_plan_reaches_cost_reader():
    source,primary,state,_,costs=setup()
    result=source.read(query(),primary.context())
    assert set(result['fields'])=={'linked_targets','basis','reward_timing','costs'}
    assert all(f['status']=='known' for f in result['fields'].values())
    assert state.calls==1 and len(costs.calls)==1
    plans,actor,context,selector=costs.calls[0]
    assert plans==PLANS and actor=='FRA' and context==primary.context()
    assert selector=={'root_id':'root_main','task_id':'task_core'}
    assert result['source']['provenance']['atomic_with_action_previews'] is False


def test_missing_plan_or_unknown_loaded_task_does_not_trigger_action_inspection():
    source,primary,state,_,costs=setup()
    missing=source.read(query(fields=('costs',),plans=None),primary.context())
    assert missing['fields']['costs']['reason']=='MISSION_CANDIDATE_PLANS_REQUIRED'
    bad=query(fields=('costs',));bad['parameters']['task_id']='absent'
    invalid=source.read(bad,primary.context())
    assert invalid['fields']['costs']['reason']=='MISSION_CANDIDATE_TASK_BINDING_UNVERIFIED'
    assert costs.calls==[] and state.calls==2


def test_plan_is_not_inspected_when_only_existing_task_fields_are_requested():
    source,primary,state,_,costs=setup()
    result=source.read(query(fields=('basis','reward_timing')),primary.context())
    assert all(v['status']=='known' for v in result['fields'].values())
    assert state.calls==1 and costs.calls==[]


def test_context_changed_during_preview_withdraws_all_task_and_cost_fields():
    source,primary,state,_,costs=setup()
    costs.mutate=lambda:primary.state.current.update(game_date=primary.context()['game_date']+1)
    result=source.read(query(),primary.context())
    assert len(costs.calls)==1 and state.calls==1
    assert all(f['reason']=='MISSION_ANALYSIS_CONTEXT_CHANGED' and 'value' not in f
               for f in result['fields'].values())


def test_candidate_catalog_coexists_with_existing_fields_in_one_owner():
    source,primary,_,_,_=setup()
    combined=CompositeSource(primary,[source])
    normalized=combined.validate_query(query())
    assert normalized==query()
    topic=next(t for t in combined.catalog() if t['topic_id']=='M05')
    assert topic['fields']['costs']['coverage']=='partial'
    assert topic['parameters']['required']==['root_id','task_id']
    assert topic['parameters']['properties']['candidate_plans']['maxItems']==8


def test_world_identity_changed_during_preview_withdraws_the_join():
    source,primary,_,_,costs=setup()
    costs.mutate=lambda:primary.state.current.update(world_id='replacement-world')
    result=source.read(query(),primary.context())
    assert all(f['reason']=='MISSION_ANALYSIS_CONTEXT_CHANGED' for f in result['fields'].values())


def test_identical_failed_previews_are_shared_only_within_this_request():
    from bridge.information.mission_candidate_costs import MissionCandidateCostReader
    calls=[]
    def failed(*args):
        calls.append(deepcopy(args))
        raise RuntimeError('unavailable')
    plans=deepcopy(PLANS)
    alternate=deepcopy(PLANS[0]);alternate['id']='plan-b';alternate['actions'][0]['id']='same-selection'
    plans.append(alternate)
    reader=MissionCandidateCostReader(failed)
    first=reader.read(plans,'FRA',{'game_date':10},{'root_id':'r','task_id':'t'})
    assert len(calls)==1
    assert first['value']['inspection_collection']=={
        'scope':'one_m05_read','inspector_calls':1,'shared_result_hits':1,'cross_request_cache':False}
    assert all(p['actions'][0]['costs']['status']=='unknown' for p in first['value']['plans'])
    reader.read(plans,'FRA',{'game_date':10},{'root_id':'r','task_id':'t'})
    assert len(calls)==2


def test_change_subscription_is_rejected_before_reading_task_or_action(tmp_path):
    import pytest
    from bridge.information import InformationService,InformationError
    source,primary,state,_,costs=setup()
    source.missions.scheduling=True
    combined=CompositeSource(primary,[source])
    assert next(t for t in combined.catalog() if t['topic_id']=='M05')['triggers']==['query','periodic']
    service=InformationService(combined,tmp_path/'capabilities.sqlite3')
    try:
        report=service.manage_report('candidate-report','create',config={'queries':[query()]})['report']
        with pytest.raises(InformationError) as exc:
            service.manage_subscription('candidate-change','create',config={
                'kind':'change','report_id':report['id'],'schedule':{
                    'basis':'real','every':2,'unit':'seconds','missed':'coalesce'}})
        assert exc.value.code=='unsupported_trigger'
        assert state.calls==0 and costs.calls==[]
    finally:
        service.close()
