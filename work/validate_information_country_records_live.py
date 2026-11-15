"""Accept loans and current modifier records via MCP query/report/periodic."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.run_alliance_inbound_response import control_snapshot
from work.validate_information_military_quality_live import write
from work.validate_information_trade_power_live import CheckedClient

def query(topic,fields=None):
    result=dict(topic=topic,object={'type':'country','country':'FRA'},parameters={})
    if fields is not None:result['fields']=fields
    return result

def loan_core(row):
    return (row['principal']['raw'],row['interest']['raw'],row['due']['raw'],row['lender']['raw_fullref_hex'])

def run(installation,modifiers_reference,loans_reference,output):
    modifier=json.loads(modifiers_reference.read_text(encoding='utf-8'))
    loan=json.loads(loans_reference.read_text(encoding='utf-8'))
    header=modifier['header']
    raw_path=ROOT/loan['source']['path']
    raw_bytes=raw_path.read_bytes()
    assert hashlib.sha256(raw_bytes).hexdigest()==loan['source']['sha256']
    raw=json.loads(raw_bytes)
    assert raw['identity']['installation_session_id']==header['session_id']
    assert raw['identity']['process_creation_filetime']==header['creation_filetime']
    assert all(r['game_date']['value']==header['game_date'] for r in raw['loan_inputs'])
    binding=json.loads(installation.read_text(encoding='utf-8'))
    assert binding['session_id']==header['session_id']
    output.mkdir(parents=True,exist_ok=False)
    before=control_snapshot(binding['pid'],output/'before-control.json')
    assert (before['date_raw'],before['player_slot'],before['paused_flag'],before['speed'])==(header['game_date'],189,1,0)
    report=dict(schema='information_country_records_live_acceptance.v1',status='running',
                session_id=header['session_id'],game_date=header['game_date'],checks={},periodic_results=0,
                configuration='native live sources plus --static-game-data; mission and battle disabled',
                business_actions_submitted=0,game_functions_called=False,llm_read='unknown')
    client=subscription=None
    specs={t:list(modifier['queries'][t]) for t in ('N07','N08')}
    specs['N01']=['loans']
    queries=[query(t,specs[t]) for t in ('N01','N07','N08')]
    def check(result,topics):
        assert result['delivery']['status']=='delivered' and result['complete'] is False
        assert result['context']['session_id']==header['session_id'] and result['context']['game_date']==header['game_date']
        assert len(result['items'])==len(topics)
        for item,topic in zip(result['items'],topics):
            values=item['fields']
            if topic=='N01':
                field=values['loans']
                assert field['status']=='known' and field['complete'] is False
                assert field['unit']=='loan_records' and field['scale']==1
                assert [loan_core(r) for r in field['value']]==[loan_core(r) for r in loan['fields']['loans']['value']]
            else:
                for field,expected in modifier['queries'][topic].items():
                    for key,value in expected.items():assert values[field].get(key)==value,(topic,field,key,values[field],value)
        return result['items']
    try:
        client=CheckedClient(installation.resolve(),output,extra_args=['--static-game-data'])
        discovery=client.call('information_discover')
        write(output/'discovery.json',discovery)
        for topic,fields in specs.items():
            entry=next(t for t in discovery['topics'] if t['topic_id']==topic)
            assert all(entry['fields'][f]['coverage']=='partial' for f in fields)
        report['checks']['eight_new_fields_discovered_as_partial']=True
        for topic,filename in (('N01','loans-query.json'),('N07','modifiers-query.json'),('N08','modifier-dates-query.json')):
            result=client.call('information_query',request_id='country-records-'+topic.lower()+'-001',queries=[query(topic,specs[topic])])
            write(output/filename,result)
            check(result,[topic])
        report['checks']['loans_and_modifier_fields_match_independent_raw_references']=True
        mixed=client.call('information_query',request_id='country-records-monthly-mixed-001',
                          queries=[query('N01',['loans','monthly_income','monthly_expenses','monthly_balance'])])
        write(output/'loans-and-monthly-query.json',mixed)
        check(mixed,['N01'])
        assert all(mixed['items'][0]['fields'][f]['status']=='known' for f in ('monthly_income','monthly_expenses','monthly_balance'))
        report['checks']['existing_monthly_fields_preserved_in_same_topic']=True
        for topic,missing in (('N07',['name','description','source']),('N08',['removal_conditions'])):
            result=client.call('information_query',request_id='country-records-default-'+topic.lower()+'-001',queries=[query(topic)])
            write(output/('default-'+topic.lower()+'-query.json'),result)
            check(result,[topic])
            assert all(result['items'][0]['fields'][f]['status']!='known' for f in missing)
        domestic_fields=['stability','war_exhaustion','corruption','religious_unity','overextension','unrest']
        domestic=client.call('information_query',request_id='country-records-domestic-001',queries=[query('N04',domestic_fields)])
        write(output/'domestic-after-profile-rebind.json',domestic)
        assert all(domestic['items'][0]['fields'][f]['status']=='known' for f in domestic_fields)
        report['checks']['domestic_six_fields_and_planned_modifier_gaps_preserved']=True
        config=client.call('information_manage_report',request_id='country-records-report-001',operation='create',
                           config={'name':'FRA当前贷款与国家修正','queries':queries,'detail':'raw'})
        write(output/'report-config.json',config)
        result=client.call('information_query',request_id='country-records-report-query-001',report_id=config['report']['id'])
        write(output/'report-query.json',result)
        check(result,['N01','N07','N08'])
        response=client.call('information_manage_subscription',request_id='country-records-subscribe-001',operation='create',
                             config={'name':'country-records-two-seconds','kind':'periodic','report_id':config['report']['id'],
                                     'enabled':True,'schedule':{'basis':'real','every':2,'unit':'seconds','missed':'coalesce'}})
        subscription=response['subscription']
        write(output/'subscription-config.json',response)
        periodic={};deadline=time.monotonic()+45
        while len(periodic)<3 and time.monotonic()<deadline:
            listed=client.call('information_list_results',limit=50)
            for value in listed.get('results',[]):
                if value.get('subscription_id')==subscription['id']:
                    check(value,['N01','N07','N08']);periodic[value['result_id']]=value
            if len(periodic)<3:time.sleep(.2)
        write(output/'periodic-results.json',list(periodic.values()))
        assert len(periodic)>=3
        report['periodic_results']=len(periodic)
        cancelled=client.call('information_manage_subscription',request_id='country-records-cancel-001',operation='cancel',
                              subscription_id=subscription['id'],expected_version=subscription['version'])
        subscription=cancelled['subscription']
        write(output/'cancelled-subscription.json',cancelled)
        listed=client.call('information_manage_subscription',request_id='country-records-list-001',operation='list')
        write(output/'subscriptions-after.json',listed)
        assert all(s['state']=='cancelled' for s in listed['subscriptions'])
        report['checks']['report_three_periodic_deliveries_cancel_no_active']=True
        report.update(status='passed',outbox='delivered')
    except Exception as exc:
        report.update(status='failed',error={'type':type(exc).__name__,'message':str(exc)})
    finally:
        if client is not None:
            try:
                if subscription is not None and subscription.get('state')!='cancelled':
                    client.call('information_manage_subscription',request_id='country-records-cleanup-cancel-001',operation='cancel',
                                subscription_id=subscription['id'],expected_version=subscription['version'])
                client.close()
            except Exception as exc:report.update(status='failed',cleanup_error=str(exc))
            report['server_exit_code']=client.process.returncode
        after=control_snapshot(binding['pid'],output/'after-control.json')
        report['checks']['date_pause_player_preserved']=all(before[k]==after[k] for k in ('date_raw','player_slot','paused_flag','speed'))
        if not report['checks']['date_pause_player_preserved']:report['status']='failed'
        write(output/'report.json',report)
    print(json.dumps(report,ensure_ascii=False))
    return 0 if report['status']=='passed' else 1

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--installation',type=Path,required=True)
    p.add_argument('--modifiers-reference',type=Path,required=True)
    p.add_argument('--loans-reference',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    raise SystemExit(run(a.installation,a.modifiers_reference,a.loans_reference,a.output))
