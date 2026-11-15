"""Promote only the actually delivered F01 current-country war projection."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.update_information_foreign_technology_coverage import counts,read
STAGE=ROOT/'work/runtime/information-country-wars-20261029-001'


def main():
    path=ROOT/'docs/信息字段覆盖.json';raw=path.read_bytes();matrix=json.loads(raw)
    before=deepcopy(matrix)
    assert matrix['counts']['field_counts']=={'available':62,'partial':183,'planned':152}
    receipt=read(STAGE/'mcp-live-001/receipt.json');discovery=read(STAGE/'mcp-live-001/discovery.json')
    assert receipt['status']=='passed' and receipt['server_exit_code']==0 and receipt['source_pins_unchanged']
    assert receipt['checks']['no_active_subscriptions'] and receipt['checks']['capture_count_matches_delivery']
    assert receipt['archived_capture_count']==len(receipt['targets'])*(2+sum(receipt['periodic_counts'].values()))
    topic=next(t for t in discovery['topics'] if t['topic_id']=='F01')
    index=next(i for i,t in enumerate(matrix['topics']) if t['topic_id']=='F01');old=matrix['topics'][index]
    assert set(topic['fields'])==set(old['fields'])
    assert old['fields']['wars']['coverage']=='planned' and topic['fields']['wars']['coverage']=='partial'
    assert topic['fields']['territory']['coverage']=='partial'
    for field in ('development','territory','subject_scale','major_power'):
        assert topic['fields'][field]['coverage']==old['fields'][field]['coverage']=='partial'
    matrix['topics'][index]=deepcopy(topic)
    matrix['F01']={k:deepcopy(topic[k]) for k in ('fields','context_scope','source','adapter_sources') if k in topic}
    assert 'NativeCountryScaleSource' in matrix['configuration']['adapters']
    matrix['counts']=counts(matrix['topics']);matrix['expected_counts']=deepcopy(matrix['counts'])
    assert matrix['counts']['field_counts']=={'available':62,'partial':184,'planned':151}
    assert matrix['counts']['topic_count']==74 and matrix['counts']['field_count']==397 and matrix['goal_complete'] is False
    assert all(a==b for a,b in zip(before['topics'],matrix['topics']) if a['topic_id']!='F01')
    with (STAGE/'coverage-before-001.json').open('xb') as stream:stream.write(raw)
    updated=(json.dumps(matrix,ensure_ascii=False,indent=2)+'\n').encode('utf-8');path.write_bytes(updated)
    value={'status':'updated_partial','goal_complete':False,'coverage_changes':{'F01.wars':['planned','partial']},
        'before_sha256':hashlib.sha256(raw).hexdigest(),'after_sha256':hashlib.sha256(updated).hexdigest(),
        'configured_counts':matrix['counts'],'actual_live_counts':counts(discovery['topics']),
        'scope':'current_country_opponent_index only; global membership, object lifetime and complete F01 remain unfinished'}
    with (STAGE/'coverage-update-001.json').open('x',encoding='utf-8',newline='\n') as stream:
        json.dump(value,stream,ensure_ascii=False,indent=2);stream.write('\n')
    print(json.dumps(value,ensure_ascii=False))


if __name__=='__main__':main()
