"""Merge only the live-verified S02.faith partial capability."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.update_information_foreign_technology_coverage import counts,read
STAGE=ROOT/'work/runtime/information-foreign-scalars-20261029-001'


def main():
    path=ROOT/'docs/信息字段覆盖.json';old_raw=path.read_bytes();matrix=json.loads(old_raw)
    before=deepcopy(matrix)
    assert matrix['counts']['field_counts']=={'available':62,'partial':166,'planned':169}
    live=read(STAGE/'mcp-live-001/receipt.json');discovery=read(STAGE/'mcp-live-001/discovery.json')
    assert live['status']=='passed' and live['server_exit_code']==0 and live['source_pins_unchanged']
    topic=next(x for x in discovery['topics'] if x['topic_id']=='S02')
    index=next(i for i,x in enumerate(matrix['topics']) if x['topic_id']=='S02')
    old=matrix['topics'][index]
    assert old['fields'].keys()==topic['fields'].keys()
    assert old['fields']['faith']['coverage']=='planned' and topic['fields']['faith']['coverage']=='partial'
    assert all(value==old['fields'][key] for key,value in topic['fields'].items() if key!='faith')
    matrix['topics'][index]=deepcopy(topic)
    matrix['S02']={k:deepcopy(topic[k]) for k in ('fields','context_scope','source','adapter_sources') if k in topic}
    assert 'NativeCountryFaithSource' not in matrix['configuration']['adapters']
    matrix['configuration']['adapters'].append('NativeCountryFaithSource')
    matrix['counts']=counts(matrix['topics']);matrix['expected_counts']=deepcopy(matrix['counts'])
    assert matrix['counts']['field_counts']=={'available':62,'partial':167,'planned':168}
    assert matrix['counts']['topic_count']==74 and matrix['counts']['field_count']==397
    assert matrix['goal_complete'] is False
    assert all(a==b for a,b in zip(before['topics'],matrix['topics']) if a['topic_id']!='S02')
    with (STAGE/'coverage-before-001.json').open('xb') as stream:stream.write(old_raw)
    new_raw=(json.dumps(matrix,ensure_ascii=False,indent=2)+'\n').encode('utf-8');path.write_bytes(new_raw)
    receipt={'status':'updated_partial','goal_complete':False,
        'coverage_changes':{'S02.faith':['planned','partial']},
        'before_sha256':hashlib.sha256(old_raw).hexdigest(),'after_sha256':hashlib.sha256(new_raw).hexdigest(),
        'configured_counts':matrix['counts'],'actual_live_counts':counts(discovery['topics']),
        'scope':'Primary religion cached name bytes, strict eu4_escape decoded text and icon frame request; configuration key/ID, full tooltip, secondary faith and actual UI remain incomplete'}
    with (STAGE/'coverage-update-001.json').open('x',encoding='utf-8',newline='\n') as stream:
        json.dump(receipt,stream,ensure_ascii=False,indent=2);stream.write('\n')
    print(json.dumps(receipt,ensure_ascii=False))


if __name__=='__main__':main()
