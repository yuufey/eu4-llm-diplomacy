"""Update G02 name-source metadata without promoting partial field coverage."""
from copy import deepcopy
from pathlib import Path
import hashlib
import json
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.verify_information_foreign_technology import read_json,write_new
from work.update_information_foreign_technology_coverage import counts

STAGE=ROOT/'work/runtime/information-province-resource-localization-20261029-001'
EXPECTED={'available':62,'partial':184,'planned':151}


def main():
    path=ROOT/'docs/信息字段覆盖.json';raw=path.read_bytes();matrix=json.loads(raw)
    before=deepcopy(matrix);assert matrix['counts']['field_counts']==EXPECTED
    receipt=read_json(STAGE/'mcp-live-001/offline-reconciliation-002.json')
    discovery=read_json(STAGE/'mcp-live-001/discovery.json')
    assert receipt['status']=='passed' and receipt['source_pins_unchanged'] and receipt['server_exit_code']==0
    assert receipt['targets']==[183,184,236,2000] and receipt['checks']['no_active_subscriptions']
    assert receipt['archived_capture_count']==len(receipt['targets'])*(2+sum(receipt['periodic_counts'].values()))
    old=next(row for row in matrix['topics'] if row['topic_id']=='G02')
    topic=next(row for row in discovery['topics'] if row['topic_id']=='G02')
    assert set(old['fields'])==set(topic['fields']) and len(topic['fields'])==8
    assert all(row['coverage']=='partial' for row in topic['fields'].values())
    assert 'TRANSLATED_RESOURCE_NAME_NOT_CAPTURED' in old['fields']['resource']['gaps']
    assert 'NATIVE_FNV1_HASH_ONLY' in topic['fields']['resource']['gaps']
    assert 'TRANSLATED_RESOURCE_NAME_NOT_CAPTURED' not in topic['fields']['resource']['gaps']
    position=matrix['topics'].index(old);matrix['topics'][position]=deepcopy(topic)
    matrix['G02']={key:deepcopy(topic[key]) for key in ('fields','context_scope','source','adapter_sources') if key in topic}
    matrix['counts']=counts(matrix['topics']);matrix['expected_counts']=deepcopy(matrix['counts'])
    assert matrix['counts']['field_counts']==EXPECTED and matrix['counts']['field_count']==397
    assert matrix['counts']['topic_count']==74 and matrix['goal_complete'] is False
    assert all(a==b for a,b in zip(before['topics'],matrix['topics']) if a['topic_id']!='G02')
    with (STAGE/'coverage-before-001.json').open('xb') as stream:stream.write(raw)
    updated=(json.dumps(matrix,ensure_ascii=False,indent=2)+'\n').encode('utf-8');path.write_bytes(updated)
    result={'status':'updated_source_metadata','goal_complete':False,'coverage_changes':{},
        'source_extension':'G02.resource.name cached literal','coverage_counts_unchanged':True,
        'configured_counts':matrix['counts'],'actual_live_counts':counts(discovery['topics']),
        'before_sha256':hashlib.sha256(raw).hexdigest(),'after_sha256':hashlib.sha256(updated).hexdigest()}
    write_new(STAGE/'coverage-update-001.json',result);print(result)


if __name__=='__main__':main()
