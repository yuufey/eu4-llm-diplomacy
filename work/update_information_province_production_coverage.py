"""Promote the three live-verified G02 fields without claiming completeness."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.update_information_foreign_technology_coverage import counts,read
from work.verify_information_foreign_technology import write_new
STAGE=ROOT/'work/runtime/information-province-production-20261029-001'
FIELDS=('development','resource','center_of_trade')


def main():
    path=ROOT/'docs/信息字段覆盖.json';old_raw=path.read_bytes();before=json.loads(old_raw);matrix=deepcopy(before)
    assert before['counts']['field_counts']=={'available':62,'partial':176,'planned':159}
    mcp=read(STAGE/'mcp-live-001/receipt.json');discovery=read(STAGE/'mcp-live-001/discovery.json')
    positive=read(STAGE/'private-live-probe-001.json');negative=read(STAGE/'private-discovery-negative-001.json')
    zero=read(STAGE/'private-center-zero-001.json')
    assert mcp['status']==positive['status']=='passed'
    assert negative['status']=='passed_negative' and zero['status']=='passed_zero'
    assert mcp['server_exit_code']==0 and mcp['source_pins_unchanged']
    assert mcp['periodic_counts']['2']>=2 and mcp['periodic_counts']['5']>=1
    assert mcp['archived_capture_count']==4*(2+sum(mcp['periodic_counts'].values()))
    assert mcp['checks']['no_active_subscriptions'] and mcp['checks']['capture_count_matches_delivery']
    topic=next(row for row in discovery['topics'] if row['topic_id']=='G02')
    index=next(i for i,row in enumerate(matrix['topics']) if row['topic_id']=='G02');old=matrix['topics'][index]
    assert set(topic['fields'])==set(old['fields']) and len(topic['fields'])==8
    for name in FIELDS:
        assert old['fields'][name]['coverage']=='planned'
        assert topic['fields'][name]['coverage']=='partial' and topic['fields'][name]['complete'] is False
    assert all(value==old['fields'][name] for name,value in topic['fields'].items() if name not in FIELDS)
    matrix['topics'][index]=deepcopy(topic)
    matrix['G02']={key:deepcopy(topic[key]) for key in ('fields','context_scope','source','adapter_sources') if key in topic}
    assert matrix['configuration']['adapters'].count('NativeProvinceStateSource')==1
    matrix['counts']=counts(matrix['topics']);matrix['expected_counts']=deepcopy(matrix['counts'])
    assert matrix['counts']['field_counts']=={'available':62,'partial':179,'planned':156}
    assert matrix['counts']['topic_count']==74 and matrix['counts']['field_count']==397
    assert matrix['counts']['callable_topic_count']==46 and matrix['goal_complete'] is False
    assert all(a==b for a,b in zip(before['topics'],matrix['topics']) if a['topic_id']!='G02')
    with (STAGE/'coverage-before-001.json').open('xb') as stream:stream.write(old_raw)
    raw=(json.dumps(matrix,ensure_ascii=False,indent=2)+'\n').encode('utf-8');path.write_bytes(raw)
    write_new(STAGE/'coverage-update-001.json',{'status':'updated_partial','goal_complete':False,
        'coverage_changes':{'G02.'+name:['planned','partial'] for name in FIELDS},
        'before_sha256':hashlib.sha256(old_raw).hexdigest(),'after_sha256':hashlib.sha256(raw).hexdigest(),
        'configured_counts':matrix['counts'],'actual_live_counts':counts(discovery['topics']),
        'scope':'All eight G02 fields are partial. Positive logical-FRA discovery only; development retains effective signed-i32 total, resource only localization key/icon index, center presence/level/kind/sprite key. Full visibility, translated resource name, latent resources, complete tooltips and costs, cache freshness/atomicity remain incomplete.'})
    print(matrix['counts'])


if __name__=='__main__':main()
