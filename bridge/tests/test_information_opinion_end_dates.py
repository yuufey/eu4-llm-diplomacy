from copy import deepcopy
import pytest
from bridge.information.opinion_end_dates import NativeOpinionEndDatesSource
from bridge.information import opinion_end_dates_capture as capture
from bridge.information.model import InformationError
from bridge.tests.test_information_opinion_modifiers import Primary,CaptureHarness,_report,_record

def record(date=56972136,mode=0):
    return _record('timed_modifier',-20000,date=date,flags={'24':0,'26':mode})

@pytest.mark.parametrize('date,text',[(56972136,'1503.9.2'),(56560344,'1456.8.30'),(43808760,'1.1.1')])
def test_stored_schedule_uses_existing_native_calendar(date,text):
    row=NativeOpinionEndDatesSource._project_record(record(date))
    assert row['status']=='known' and row['scheduled_end_date']==text
    assert row['scheduled_end_date_raw']==date
    assert row['actual_removal_evaluated'] is False and row['schedule_state']=='stored_unverified'

def test_non_fixed_mode_does_not_expose_unused_date_or_predict_forever():
    row=NativeOpinionEndDatesSource._project_record(record(-1234,1))
    assert row=={'status':'not_applicable','modifier_id':'timed_modifier',
                 'reason':'RECORD_USES_NON_FIXED_DURATION_MODE','actual_removal_evaluated':False}

@pytest.mark.parametrize('date,mode,reason',[(0,0,'OPINION_END_DATE_CALENDAR_RANGE'),
    (56972136,2,'OPINION_END_DATE_MODE_UNSUPPORTED')])
def test_invalid_date_or_mode_is_unknown(date,mode,reason):
    assert NativeOpinionEndDatesSource._project_record(record(date,mode))['reason']==reason

def test_bad_typed_raw_value_and_unknown_class_remain_unknown():
    row=record();row['current_opinion_raw']+=1
    assert NativeOpinionEndDatesSource._project_record(row)['status']=='unknown'
    unknown={'status':'unknown','reason':'OPINION_MODIFIER_CLASS_UNSUPPORTED'}
    assert NativeOpinionEndDatesSource._project_record(unknown)==unknown

def query(actor='FRA',recipient='ENG'):
    return {'topic':'R04','object':{'type':'country_pair','actor':actor,'recipient':recipient},
            'fields':['end_date'],'parameters':{}}

def source(tmp_path,report=None,**harness_args):
    primary=Primary(tmp_path);harness=CaptureHarness(report or _report(outgoing=[record()],incoming=[record(mode=1)]),**harness_args)
    return NativeOpinionEndDatesSource(primary,capture=harness.capture,validator=harness.validate),harness,primary

def test_reverse_pair_keeps_dates_non_fixed_mode_and_duplicate_keys(tmp_path):
    provider,harness,_=source(tmp_path,_report(outgoing=[record(),record(56560344)],incoming=[record(mode=1)]))
    result=provider.read(query('ENG','FRA'))
    field=result['fields']['end_date']
    assert (field['status'],field['unit'],field['scale'],field['complete'])==('known','game_date',1,False)
    assert [d['holder'] for d in field['value']]==['ENG','FRA']
    assert field['value'][0]['records'][0]['status']=='not_applicable'
    assert [r['scheduled_end_date'] for r in field['value'][1]['records']]==['1503.9.2','1456.8.30']
    assert len(harness.capture_calls)==1
    assert 'opinion_modifiers' not in result['fields']
    assert provider.catalog()[0]['fields']['end_date']['coverage']=='partial'

def test_unknown_record_does_not_remove_a_known_sibling(tmp_path):
    provider,_,_=source(tmp_path,_report(outgoing=[{'status':'unknown','reason':'OPINION_MODIFIER_CLASS_UNSUPPORTED'},record()],incoming=[]))
    rows=provider.read(query())['fields']['end_date']['value'][0]['records']
    assert [r['status'] for r in rows]==['unknown','known']

@pytest.mark.parametrize('actor,recipient',[('ENG','POR'),('FRA','FRA')])
def test_scope_is_the_same_explicit_observer_pair(actor,recipient,tmp_path):
    provider,_,_=source(tmp_path)
    with pytest.raises(InformationError):provider.validate_query(query(actor,recipient))

def test_replay_rejection_withdraws_field(tmp_path):
    provider,_,_=source(tmp_path,validator_result=False)
    assert provider.read(query())['fields']['end_date']['status']=='unknown'

def test_context_change_during_capture_is_unknown(tmp_path):
    provider,harness,primary=source(tmp_path)
    harness.after_capture=lambda:primary._context.update(session_id='new-session')
    assert provider.read(query())['fields']['end_date']['status']=='unknown'

def test_capture_profile_and_strict_owner_contract(monkeypatch):
    assert capture._load_profile()['profile_id']==capture.PROFILE_ID
    monkeypatch.setattr(capture.owner,'_capture_common',lambda *a,**k:k)
    result=capture.capture('installation','ENG')
    assert result['observe'] is capture.records._observe and result['schema']==capture.SCHEMA
    with pytest.raises(ValueError):capture.capture('installation','FRA')
    assert not capture.validate_capture({'schema':'wrong'},{},1,'ENG')
