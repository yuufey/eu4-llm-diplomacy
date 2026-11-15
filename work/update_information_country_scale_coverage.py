"""Promote only the three F01 fields verified by this batch's real delivery."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.update_information_foreign_technology_coverage import counts,read
STAGE=ROOT/'work/runtime/information-foreign-scale-20261029-001'
FIELDS=('development','subject_scale','major_power')


def main():
    path=ROOT/'docs/信息字段覆盖.json';raw=path.read_bytes();matrix=json.loads(raw)
    before=deepcopy(matrix)
    assert matrix['counts']['field_counts']=={'available':62,'partial':179,'planned':156}
    live=read(STAGE/'mcp-live-001/receipt.json')
    assert live['status']=='passed' and live['server_exit_code']==0 and live['source_pins_unchanged']
    assert live['checks']['no_active_subscriptions'] and live['checks']['capture_count_matches_delivery']
    discovery=read(STAGE/'mcp-live-001/discovery.json')
    topic=next(t for t in discovery['topics'] if t['topic_id']=='F01')
    index=next(i for i,t in enumerate(matrix['topics']) if t['topic_id']=='F01')
    old=matrix['topics'][index]
    assert set(old['fields'])==set(topic['fields'])==set(FIELDS)|{'territory','wars'}
    assert all(old['fields'][f]['coverage']=='planned' and topic['fields'][f]['coverage']=='partial' for f in FIELDS)
    assert all(old['fields'][f]==topic['fields'][f] for f in ('territory','wars'))
    matrix['topics'][index]=deepcopy(topic)
    matrix['F01']={k:deepcopy(topic[k]) for k in ('fields','context_scope','source','adapter_sources') if k in topic}
    matrix['configuration']['adapters'].append('NativeCountryScaleSource')
    matrix['counts']=counts(matrix['topics']);matrix['expected_counts']=deepcopy(matrix['counts'])
    assert matrix['counts']['field_counts']=={'available':62,'partial':182,'planned':153}
    assert matrix['counts']['topic_count']==74 and matrix['counts']['field_count']==397
    assert matrix['goal_complete'] is False
    assert all(a==b for a,b in zip(before['topics'],matrix['topics']) if a['topic_id']!='F01')
    with (STAGE/'coverage-before-001.json').open('xb') as stream:stream.write(raw)
    new=(json.dumps(matrix,ensure_ascii=False,indent=2)+'\n').encode('utf-8');path.write_bytes(new)
    receipt={'status':'updated_partial','goal_complete':False,
             'coverage_changes':{'F01.'+f:['planned','partial'] for f in FIELDS},
             'before_sha256':hashlib.sha256(raw).hexdigest(),'after_sha256':hashlib.sha256(new).hexdigest(),
             'configured_counts':matrix['counts'],'actual_live_counts':counts(discovery['topics']),
             'scope':'own development cache, bounded weighted subject-vector contribution, native great-power glow condition; territory/wars remain planned'}
    with (STAGE/'coverage-update-001.json').open('x',encoding='utf-8',newline='\n') as stream:
        json.dump(receipt,stream,ensure_ascii=False,indent=2);stream.write('\n')
    print(json.dumps(receipt,ensure_ascii=False))


if __name__=='__main__':main()
