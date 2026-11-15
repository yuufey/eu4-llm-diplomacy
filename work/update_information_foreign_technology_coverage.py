"""Merge only the live-verified partial F02 capability into the coverage matrix."""
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
STAGE=ROOT/'work/runtime/information-foreign-visibility-20261029-001'


def read(path):
    assert path.stat().st_size<=10*1024*1024
    return json.loads(path.read_text(encoding='utf-8-sig'))


def counts(topics):
    fields=Counter(field['coverage'] for topic in topics for field in topic['fields'].values())
    statuses=Counter(topic['status'] for topic in topics)
    return {'topic_count':len(topics),'field_count':sum(fields.values()),
        'topic_status_counts':{key:statuses[key] for key in ('available','partial','planned')},
        'field_counts':{key:fields[key] for key in ('available','partial','planned')},
        'available_topic_count':statuses['available'],'callable_topic_count':statuses['available']}


def main():
    path=ROOT/'docs/信息字段覆盖.json';old_raw=path.read_bytes();matrix=json.loads(old_raw)
    before=deepcopy(matrix)
    assert matrix['counts']['field_counts']=={'available':62,'partial':164,'planned':171}
    live=read(STAGE/'mcp-live-001/receipt.json')
    assert live['status']=='passed' and live['server_exit_code']==0 and live['source_pins_unchanged']
    discovery=read(STAGE/'mcp-live-001/discovery.json')
    topic=next(row for row in discovery['topics'] if row['topic_id']=='F02')
    index=next(i for i,row in enumerate(matrix['topics']) if row['topic_id']=='F02')
    old_topic=matrix['topics'][index]
    assert topic['fields'].keys()==old_topic['fields'].keys()
    for field in ('military_technology','visibility'):
        assert old_topic['fields'][field]['coverage']=='planned' and topic['fields'][field]['coverage']=='partial'
    for field in set(topic['fields'])-{'military_technology','visibility'}:
        assert topic['fields'][field]==old_topic['fields'][field]
    matrix['topics'][index]=deepcopy(topic)
    matrix['F02']={key:deepcopy(topic[key]) for key in ('fields','context_scope','source','adapter_sources') if key in topic}
    matrix['configuration']['adapters'].append('NativeForeignTechnologySource')
    matrix['counts']=counts(matrix['topics']);matrix['expected_counts']=deepcopy(matrix['counts'])
    assert matrix['counts']['field_counts']=={'available':62,'partial':166,'planned':169}
    assert matrix['counts']['topic_count']==74 and matrix['counts']['field_count']==397
    assert matrix['goal_complete'] is False
    assert all(a==b for a,b in zip(before['topics'],matrix['topics']) if a['topic_id']!='F02')
    with (STAGE/'coverage-before-001.json').open('xb') as stream:stream.write(old_raw)
    new_raw=(json.dumps(matrix,ensure_ascii=False,indent=2)+'\n').encode('utf-8')
    path.write_bytes(new_raw)
    receipt={'status':'updated_partial','goal_complete':False,'coverage_changes':{
        'F02.military_technology':['planned','partial'],'F02.visibility':['planned','partial']},
        'before_sha256':hashlib.sha256(old_raw).hexdigest(),'after_sha256':hashlib.sha256(new_raw).hexdigest(),
        'configured_counts':matrix['counts'],'actual_live_counts':counts(discovery['topics']),
        'scope':'Only military technology and its observer-reindexed country-view predicate; actual UI and other F02 fields remain incomplete'}
    with (STAGE/'coverage-update-001.json').open('x',encoding='utf-8',newline='\n') as stream:
        json.dump(receipt,stream,ensure_ascii=False,indent=2);stream.write('\n')
    print(json.dumps(receipt,ensure_ascii=False))


if __name__=='__main__':main()
