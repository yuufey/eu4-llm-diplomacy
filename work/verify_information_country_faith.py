"""Freeze batch-77 sources, run bridge tests once, and retain baseline deltas."""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work import verify_information_foreign_technology as prior

STAGE=ROOT/'work/runtime/information-foreign-scalars-20261029-001'
REVISION='002'
BASE=ROOT/'work/runtime/information-foreign-visibility-20261029-001'
pin,read,write=prior.pin,prior.read_json,prior.write_new
REVIEWED={'bridge/information/foreign_technology_capture.py':'share existing identity/ROM/handle/trace owner with field-specific trusted hooks',
    'tools/serve_information.py':'register S02.faith adapter',
    'docs/信息字段覆盖.json':'merge only S02.faith verified partial capability'}
EXTRA=('bridge/information/foreign_country_memory.py','bridge/tests/test_information_foreign_country_memory.py',
    'bridge/information/country_faith_memory.py','bridge/tests/test_information_country_faith_memory.py',
    'bridge/information/country_faith_capture.py','bridge/tests/test_information_country_faith_capture.py',
    'bridge/information/country_faith.py','bridge/tests/test_information_country_faith.py',
    'bridge/information/profiles/country-faith-memory-1374.json',
    'bridge/information/profiles/country-faith-memory-1374-v2.json',
    'work/query_information_cached_native.py','work/create_information_country_faith_profile.py',
    'work/verify_information_country_faith.py','work/update_information_country_faith_coverage.py',
    'work/create_information_country_faith_name_profile.py',
    'work/finalize_information_country_faith.py',
    'work/runtime/information-foreign-scalars-20261029-001/probe_faith_001.py',
    'work/runtime/information-foreign-scalars-20261029-001/probe_faith_002.py',
    'work/runtime/information-foreign-scalars-20261029-001/serve_archived_faith_001.py',
    'work/runtime/information-foreign-scalars-20261029-001/validate_faith_mcp_001.py')


def baseline():
    frozen=read(BASE/'source-freeze-001.json')
    assert frozen['batch']==76 and frozen['status']=='passed' and frozen['count']==len(frozen['files'])==630
    changes=[]
    for row in frozen['files']:
        source,snapshot=row['source'],row['snapshot']
        assert pin(snapshot['path'])==snapshot
        assert (source['bytes'],source['sha256'])==(snapshot['bytes'],snapshot['sha256'])
        current=pin(source['path'])
        if current!=source:
            assert source['path'] in REVIEWED,source['path']
            changes.append({'before':source,'after':current,'reason':REVIEWED[source['path']]})
    assert {x['before']['path'] for x in changes}==set(REVIEWED)
    comparison=read(BASE/'regression-comparison-001.json');post=read(BASE/'source-post-run-verification-001.json')
    assert comparison['status']=='passed_no_new_bad' and comparison['current']==pin(BASE/'regression-full-001.xml')
    assert comparison['new_bad']==[] and comparison['current_bad_occurrences']==141
    assert post['status']=='passed_no_new_bad' and post['count']==630
    assert post['freeze']==pin(BASE/'source-freeze-001.json') and post['regression_comparison']==pin(BASE/'regression-comparison-001.json')
    assert sum(prior.bad_cases(BASE/'regression-full-001.xml').values())==141
    doc_snapshot=next(x['snapshot']['path'] for x in frozen['files'] if x['source']['path']=='docs/信息字段覆盖.json')
    before=read(doc_snapshot);current=read(ROOT/'docs/信息字段覆盖.json')
    discovery=read(STAGE/'mcp-live-001/discovery.json');receipt=read(STAGE/'mcp-live-001/receipt.json')
    update=read(STAGE/'coverage-update-002.json')
    assert receipt['status']=='passed' and receipt['server_exit_code']==0 and receipt['source_pins_unchanged']
    assert update['before_sha256']==pin(doc_snapshot)['sha256'] and update['after_sha256']==pin(ROOT/'docs/信息字段覆盖.json')['sha256']
    assert update['coverage_changes']=={'S02.faith':['planned','partial']}
    topic=next(x for x in discovery['topics'] if x['topic_id']=='S02')
    index=next(i for i,x in enumerate(before['topics']) if x['topic_id']=='S02')
    assert set(topic['fields'])==set(before['topics'][index]['fields'])
    assert before['topics'][index]['fields']['faith']['coverage']=='planned' and topic['fields']['faith']['coverage']=='partial'
    assert all(v==before['topics'][index]['fields'][k] for k,v in topic['fields'].items() if k!='faith')
    expected=deepcopy(before);expected['topics'][index]=topic
    expected['S02']={k:deepcopy(topic[k]) for k in ('fields','context_scope','source','adapter_sources') if k in topic}
    assert 'NativeCountryFaithSource' not in expected['configuration']['adapters']
    expected['configuration']['adapters'].append('NativeCountryFaithSource')
    expected['counts']=prior.coverage_counts(expected['topics']);expected['expected_counts']=deepcopy(expected['counts'])
    assert expected['counts']['field_counts']=={'available':62,'partial':167,'planned':168}
    assert current==expected
    build=prior.manifest_inputs(prior.BUILD_MANIFEST);prior.validate_build_inheritance(frozen,build)
    return frozen,changes,build


def sources(frozen,build):
    return sorted(set([x['source']['path'] for x in frozen['files']]+list(EXTRA)+build['native']+build['copies']))


def freeze():
    frozen,changes,build=baseline();paths=sources(frozen,build)
    target=STAGE/f'source-freeze-{REVISION}.json';snapdir=STAGE/f'source-snapshots-{REVISION}'
    assert not target.exists() and not snapdir.exists()
    originals={name:pin(name) for name in paths};snapdir.mkdir(exist_ok=False)
    rows=[]
    for name in paths:
        snapshot=snapdir/name;prior.copy_stream(name,snapshot)
        copied=pin(snapshot)
        assert copied['sha256']==originals[name]['sha256'] and pin(name)==originals[name]
        rows.append({'source':originals[name],'snapshot':copied})
    value={'schema':'information.country_faith.source_freeze.v1','batch':77,'status':'passed','revision':REVISION,
        'count':len(rows),'files':rows,'reviewed_baseline_deltas':changes,
        'baseline':{name:pin(BASE/name) for name in ('source-freeze-001.json','regression-full-001.xml',
            'regression-comparison-001.json','source-post-run-verification-001.json')},
        'build_manifest':build['manifest'],'build_dll':build['dll'],'manifest_native_source_count':125,
        'manifest_native_sources':build['native'],'manifest_build_copies':build['copies'],'manifest_source_names':build['names'],
        'coverage_update':pin(STAGE/'coverage-update-002.json'),'created_at':prior.stamp()}
    write(target,value);print(json.dumps({'status':'passed','phase':'freeze','count':len(rows)}))


def verify_sources():
    frozen=read(STAGE/f'source-freeze-{REVISION}.json');base,changes,build=baseline()
    assert frozen['batch']==77 and frozen['status']=='passed'
    assert frozen['reviewed_baseline_deltas']==changes
    assert frozen['build_manifest']==build['manifest'] and frozen['build_dll']==build['dll']
    assert frozen['coverage_update']==pin(STAGE/'coverage-update-002.json')
    for name,item in frozen['baseline'].items():assert pin(BASE/name)==item
    assert sorted(x['source']['path'] for x in frozen['files'])==sources(base,build)
    assert frozen['count']==len(frozen['files'])
    for row in frozen['files']:
        assert pin(row['source']['path'])==row['source']
        assert pin(row['snapshot']['path'])==row['snapshot']
    return frozen


def full():
    frozen=verify_sources()
    xml,log=STAGE/f'regression-full-{REVISION}.xml',STAGE/f'regression-full-{REVISION}.log'
    reservation=STAGE/f'full-execution-reservation-{REVISION}.json'
    assert not any(x.exists() for x in (xml,log,reservation))
    argv=[str(prior.PYTHON),'-B','-m','pytest','-q','bridge/tests','--junitxml',str(xml)]
    write(reservation,{'runs':1,'argv':argv,'freeze':pin(STAGE/f'source-freeze-{REVISION}.json'),'started_at':prior.stamp()})
    with log.open('xb') as stream:
        result=subprocess.run(argv,cwd=ROOT,stdout=stream,stderr=subprocess.STDOUT,check=False)
    write(STAGE/f'full-execution-boundary-{REVISION}.json',{'returncode':result.returncode,'log':pin(log),'xml':pin(xml),'finished_at':prior.stamp()})
    verify_sources();old,new=prior.bad_cases(BASE/'regression-full-001.xml'),prior.bad_cases(xml)
    added,resolved=new-old,old-new
    value={'status':'passed_no_new_bad' if not added else 'failed_new_bad','batch':77,
        'baseline':pin(BASE/'regression-full-001.xml'),'current':pin(xml),'log':pin(log),
        'baseline_bad_occurrences':sum(old.values()),'current_bad_occurrences':sum(new.values()),
        'new_bad':prior.counter_rows(added),'resolved_bad':prior.counter_rows(resolved),
        'no_new_bad':not added,'whole_suite_passed':result.returncode==0,'returncode':result.returncode,
        'junit_summary':prior.junit_summary(xml)}
    write(STAGE/f'regression-comparison-{REVISION}.json',value)
    write(STAGE/f'source-post-run-verification-{REVISION}.json',{'status':value['status'],'batch':77,
        'count':frozen['count'],'freeze':pin(STAGE/f'source-freeze-{REVISION}.json'),
        'regression_comparison':pin(STAGE/f'regression-comparison-{REVISION}.json'),
        'current_sources_match_snapshots':True,'no_new_bad':not added,'whole_suite_passed':result.returncode==0})
    print(json.dumps(value));return 0 if not added else 2


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('operation',choices=('freeze','full','verify'))
    args=parser.parse_args()
    if args.operation=='freeze':freeze()
    elif args.operation=='verify':print(json.dumps({'status':'passed','count':verify_sources()['count']}))
    else:raise SystemExit(full())
