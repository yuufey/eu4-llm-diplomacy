"""Merge only the three live-verified partial G02 culture/religion/autonomy fields."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.update_information_foreign_technology_coverage import counts,read
STAGE=ROOT/'work/runtime/information-province-details-20261029-001'
FIELDS=('culture','religion','autonomy')


def main():
    path=ROOT/'docs/信息字段覆盖.json';old_raw=path.read_bytes();matrix=json.loads(old_raw)
    before=deepcopy(matrix)
    assert matrix['counts']['field_counts']=={'available':62,'partial':173,'planned':162}
    receipt=read(STAGE/'mcp-live-001/receipt.json');discovery=read(STAGE/'mcp-live-001/discovery.json')
    positive=read(STAGE/'private-live-probe-001.json');negative=read(STAGE/'private-discovery-negative-001.json')
    assert receipt['status']==positive['status']=='passed' and negative['status']=='passed_negative'
    assert receipt['server_exit_code']==0 and receipt['source_pins_unchanged']
    assert receipt['archived_capture_count']==15 and receipt['periodic_counts']=={'2':2,'5':1}
    topic=next(x for x in discovery['topics'] if x['topic_id']=='G02')
    index=next(i for i,x in enumerate(matrix['topics']) if x['topic_id']=='G02');old=matrix['topics'][index]
    assert set(old['fields'])==set(topic['fields']) and len(topic['fields'])==8
    for field in FIELDS:
        assert old['fields'][field]['coverage']=='planned'
        assert topic['fields'][field]['coverage']=='partial' and topic['fields'][field]['complete'] is False
    assert all(value==old['fields'][key] for key,value in topic['fields'].items() if key not in FIELDS)
    matrix['topics'][index]=deepcopy(topic)
    matrix['G02']={key:deepcopy(topic[key]) for key in ('fields','context_scope','source','adapter_sources') if key in topic}
    assert matrix['configuration']['adapters'].count('NativeProvinceStateSource')==1
    matrix['counts']=counts(matrix['topics']);matrix['expected_counts']=deepcopy(matrix['counts'])
    assert matrix['counts']['field_counts']=={'available':62,'partial':176,'planned':159}
    assert matrix['counts']['topic_count']==74 and matrix['counts']['field_count']==397
    assert matrix['counts']['callable_topic_count']==46 and matrix['goal_complete'] is False
    assert all(a==b for a,b in zip(before['topics'],matrix['topics']) if a['topic_id']!='G02')
    with (STAGE/'coverage-before-001.json').open('xb') as stream:stream.write(old_raw)
    raw=(json.dumps(matrix,ensure_ascii=False,indent=2)+'\n').encode('utf-8');path.write_bytes(raw)
    update={'status':'updated_partial','goal_complete':False,
        'coverage_changes':{'G02.'+name:['planned','partial'] for name in FIELDS},
        'before_sha256':hashlib.sha256(old_raw).hexdigest(),'after_sha256':hashlib.sha256(raw).hexdigest(),
        'configured_counts':matrix['counts'],'actual_live_counts':counts(discovery['topics']),
        'scope':'Five bounded province fields with positive FRA discovery only: owner/controller tags, culture/religion name caches, religion frame request, autonomy clamp. Zero bit stays unknown with no field reads; full visibility, development/resource/center of trade, full labels/tooltips and atomic freshness remain incomplete.'}
    with (STAGE/'coverage-update-001.json').open('x',encoding='utf-8',newline='\n') as stream:
        json.dump(update,stream,ensure_ascii=False,indent=2);stream.write('\n')
    print(json.dumps(update,ensure_ascii=False))


if __name__=='__main__':main()
