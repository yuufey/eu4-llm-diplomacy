"""Explicit batch62 source freeze/full regression; default is inert."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.finalize_information_trade_transfer import pin, read_json, _summary_line
from work.probe_information_diplomat_tasks import write

STAGE=ROOT/'work/runtime/information-battle-native-title-20261027-001'
BASE=ROOT/'work/runtime/information-battle-native-observer-20261027-001'
BUILD=ROOT/'work/runtime/diplomacy-observer-20261027-information-battle-v30-001'
EXTRA=(
    'work/native/information-battle-owned-title-query.h',
    'work/native/information-battle-title-query-plan.h',
    'work/native/tests/information-battle-owned-title-query-test.cpp',
    'work/test_information_battle_owned_title_query.py',
    'work/native/tests/information-battle-native-title-observer-test.cpp',
    'work/test_information_battle_native_title_observer.py',
    'work/prepare_information_battle_native_title_live.py',
    'work/validate_information_battle_native_title_live.py',
    'work/validate_information_battle_native_text_live_003.py',
    'work/run_information_battle_natural_window_installed.py',
    'work/finalize_information_battle_native_title.py',
    'work/native/tests/information-battle-title-query-plan-guard-test.cpp',
    'work/test_information_battle_title_query_plan_guard.py',
)


def freeze(revision=1):
    actual=STAGE/f'actual-observer-fixture-{2 if revision==1 else 5:03d}/report.json'
    unit=ROOT/f'work/runtime/information-battle-owned-title-query-20261027-001/title-query-test-{4 if revision==1 else 5:03d}/report.json'
    build=BUILD if revision==1 else BUILD.with_name('diplomacy-observer-20261027-information-battle-v30-002')
    a,u=read_json(actual),read_json(unit)
    if a['status']!='passed' or u['status']!='passed':
        raise ValueError('fixture_not_passed')
    for record in a['source_pins'].values():
        current=pin(ROOT/record['path'])
        if any(current[k]!=record[k] for k in ('bytes','sha256')):
            raise ValueError('actual_fixture_source_changed:'+record['path'])
    for path,digest in u['sources'].items():
        if pin(ROOT/path)['sha256']!=digest:
            raise ValueError('unit_fixture_source_changed:'+path)
    guard_receipts=[]
    if revision==2:
        guard_path=STAGE/'title-query-plan-guard-001/report-001.json'
        guard=read_json(guard_path)
        if guard['status']!='passed': raise ValueError('plugin_guard_fixture_not_passed')
        for path,record in guard['sources'].items():
            current=pin(ROOT/path)
            if any(current[k]!=record[k] for k in ('bytes','sha256')):
                raise ValueError('plugin_guard_fixture_source_changed:'+path)
        guard_receipts.append(pin(guard_path))
    manifest=read_json(build/'build-manifest.json')
    for record in manifest['sources']:
        if pin(ROOT/'work/native'/record['name'])['sha256']!=record['sha256']:
            raise ValueError('build_source_changed:'+record['name'])
    inherited=read_json(BASE/'runtime-source-pins-after-002.json')['files']
    paths=list(dict.fromkeys([p['path'] for p in inherited]+list(EXTRA)))
    result={'batch':62,'previous_goal_turn':'progress',
        'revision':revision,
        'timing':'after selected v30 build/unit/actual-helper fixture; before formal full',
        'files':[pin(ROOT/path) for path in paths],
        'fixture_receipts':[pin(actual),pin(unit)]+guard_receipts,
        'build_manifest':pin(build/'build-manifest.json'),
        'coverage_before':pin(ROOT/'docs/信息字段覆盖.json'),
        'baseline':pin(BASE/'development-summary-001.json'),
        'scope':{'topics':74,'fields':397,'phases':[2,3,4],
                 'autonomous_subscriptions':True,'full_B01_B04':'incomplete'}}
    write(STAGE/f'runtime-source-pins-before-{revision:03d}.json',result)
    return {'status':'frozen','files':len(paths)}


def verify(revision=1):
    frozen=read_json(STAGE/f'runtime-source-pins-before-{revision:03d}.json')['files']
    current=[pin(ROOT/p['path']) for p in frozen]
    if current!=frozen: raise ValueError('runtime_source_changed')
    return current


def full(revision=1):
    verify(revision)
    log,xml=STAGE/f'regression-full-{revision:03d}.log',STAGE/f'regression-full-{revision:03d}.xml'
    if log.exists() or xml.exists(): raise ValueError('formal_full_already_started')
    command=[sys.executable,'-m','pytest','-q','bridge/tests',f'--junitxml={xml}']
    with log.open('xb') as stream:
        result=subprocess.run(command,cwd=ROOT,stdout=stream,stderr=subprocess.STDOUT)
    write(STAGE/f'full-execution-boundary-{revision:03d}.json',{
        'command':command,'exit_code':result.returncode,'source_unchanged':verify(revision)})
    print(_summary_line(log))
    return result.returncode


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',nargs='?',choices=('freeze','full'))
    parser.add_argument('--revision',type=int,choices=(1,2),default=1)
    args=parser.parse_args()
    if args.phase is None:
        parser.print_help();return 0
    if args.phase=='freeze': print(freeze(args.revision));return 0
    return full(args.revision)


if __name__=='__main__': raise SystemExit(main())
