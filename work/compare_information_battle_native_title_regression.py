"""Read retained JUnit XML/logs only; never run tests or access the game."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.finalize_information_trade_transfer import pin, _test_cases, _summary_line

STAGE=ROOT/'work/runtime/information-battle-native-title-20261027-001'
BASE=ROOT/'work/runtime/information-battle-native-observer-20261027-001'


def compare(old: Path, current: Path) -> dict:
    old_cases,old_bad,old_occ=_test_cases(old)
    cases,bad,occ=_test_cases(current)
    key=lambda c:f"{c.get('classname')}::{c.get('name')}"
    old_keys=set(map(key,old_cases))
    keys=set(map(key,cases))
    added=keys-old_keys
    result={
        'schema':'information.battle.native_title.regression_comparison.v1',
        'baseline_xml':pin(old),'current_xml':pin(current),
        'baseline_suite_attributes':[s.attrib for s in ET.parse(old).getroot().iter('testsuite')],
        'current_suite_attributes':[s.attrib for s in ET.parse(current).getroot().iter('testsuite')],
        'baseline_failure_error_occurrences':old_occ,'failure_error_occurrences':occ,
        'baseline_unique_failure_error_nodes':len(old_bad),'unique_failure_error_nodes':len(bad),
        'baseline_case_count':len(old_cases),'current_case_count':len(cases),
        'added_nodes':sorted(added),'removed_nodes':sorted(old_keys-keys),
        'new_failure_nodes':sorted(bad-old_bad),'resolved_failure_nodes':sorted(old_bad-bad),
        'new_test_failures':[key(c) for c in cases if key(c) in added and (c.findall('error') or c.findall('failure'))],
        'log':pin(current.with_suffix('.log')),
        'summary_line':_summary_line(current.with_suffix('.log')),
        'new_test_runs':0,
    }
    result['status']='passed_no_new_failure_nodes' if not result['new_failure_nodes'] and not result['new_test_failures'] else 'failed_new_regressions'
    return result


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run',action='store_true')
    p.add_argument('--revision',type=int,choices=(1,2,61),required=False)
    a=p.parse_args()
    if not a.run:
        print(json.dumps({'status':'inert'}));return
    if a.revision is None:p.error('--revision required with --run')
    old=BASE/'regression-full-002.xml'
    current=STAGE/f'regression-full-{a.revision:03d}.xml'
    output=STAGE/f'regression-comparison-{a.revision:03d}.json'
    if a.revision==61:
        current=old
        old=ROOT/'work/runtime/information-battle-native-text-20261027-001/regression-full-001.xml'
        output=STAGE/'batch61-regression-recomputed-001.json'
    if output.exists():raise FileExistsError(output)
    result=compare(old,current)
    if a.revision==61:
        result['original_receipt_recovered']=False
        result['reason']='Batch62 agent overwrote the historical comparison receipt. Raw JUnit/log inputs remain. This is a new semantic recomputation, not byte recovery.'
    with output.open('x',encoding='utf-8',newline='\n') as stream:
        json.dump(result,stream,ensure_ascii=False,indent=2);stream.write('\n')
    print(json.dumps({'status':result['status'],'added':len(result['added_nodes']),
                      'new_failures':len(result['new_failure_nodes']),
                      'failure_occurrences':result['failure_error_occurrences']}))


if __name__=='__main__':main()
