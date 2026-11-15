"""Freeze and regress the v29 observer; no default action or game access."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.finalize_information_trade_transfer import pin, read_json, _summary_line
from work.probe_information_diplomat_tasks import write

STAGE = ROOT / 'work/runtime/information-battle-native-observer-20261027-001'
BASE = ROOT / 'work/runtime/information-battle-native-text-20261027-001'
EXTRA = (
    'work/native/information-battle-observer.inc',
    'work/native/build-diplomacy-observer.ps1',
    'tools/start_diplomacy_observer.py',
    'bridge/tests/test_start_diplomacy_observer_information_battle.py',
    'work/probe_information_battle_installed.py',
    'work/tests/test_probe_information_battle_installed.py',
    'work/ingest_information_battle_raw_live.py',
    'work/test_ingest_information_battle_raw_live.py',
    'work/tests/test_information_battle_native_text_ingest.py',
    'work/native/entry-patch-transaction.inc',
    'work/native/information-battle-line1-observer-stub.S',
    'work/native/tests/information-battle-line1-observer-abi.S',
    'work/native/tests/information-battle-line1-observer-abi.cpp',
    'work/test_information_battle_line1_observer_abi.py',
    'work/native/tests/information-battle-line1-observer-abi-002.S',
    'work/native/tests/information-battle-line1-observer-abi-002.cpp',
    'work/test_information_battle_line1_observer_abi_002.py',
    'work/test_information_battle_line1_observer_abi_003.py',
    'work/native/tests/information-battle-line1-observer-abi-004.S',
    'work/native/tests/information-battle-line1-observer-abi-004.cpp',
    'work/test_information_battle_line1_observer_abi_004.py',
    'work/native/test-entry-patch-five-targets.cpp',
    'work/test_information_battle_entry_patch_five_targets.py',
    'work/native/tests/information-battle-native-text-observer-test.cpp',
    'work/test_information_battle_native_text_observer.py',
    'work/validate_information_battle_native_text_live.py',
    'work/finalize_information_battle_native_observer.py',
)


def freeze(manager_report: Path, line1_abi_report: Path, revision: int = 1):
    component_paths = [manager_report, line1_abi_report,
                       STAGE / 'patch-five-targets-001/report.json']
    for receipt_path in component_paths:
        receipt = read_json(receipt_path)
        if receipt.get('status') != 'passed':
            raise ValueError('native_fixture_not_passed:' + str(receipt_path))
        for recorded in receipt.get('source_pins', {}).values():
            current = pin(ROOT / recorded['path'])
            if any(current[key] != recorded[key] for key in ('bytes', 'sha256')):
                raise ValueError('native_fixture_source_changed:' + recorded['path'])
    old = read_json(BASE / 'runtime-source-pins-after-001.json')
    paths = list(dict.fromkeys([p['path'] for p in old['files']] + list(EXTRA)))
    result = {
        'batch': 61, 'revision': revision, 'files': [pin(ROOT / p) for p in paths],
        'timing': ('after native and targeted checks; before formal full and live install'
                   if revision == 1 else
                   'after controller v29 port and targeted checks; before final full; existing v29 installation reused'),
        'manager_receipt': pin(manager_report),
        'native_component_receipts': [pin(p) for p in component_paths],
        'line1_static_source': pin(STAGE / 'line1-owner-source-006.json'),
        'coverage_before': pin(ROOT / 'docs/信息字段覆盖.json'),
        'baseline': pin(BASE / 'development-summary-001.json'),
        'previous_turn_classification': 'progress',
        'scope': {'topics': 74, 'fields': 397, 'phases': [2, 3, 4],
                  'autonomous_subscriptions': True, 'full_B01_B04': 'incomplete'},
    }
    if revision > 1:
        result['prior_formal_boundary'] = pin(STAGE / 'full-execution-boundary-001.json')
        result['source_transition'] = 'controller version gate and matching tests; native DLL unchanged'
        result['reused_build_manifest'] = pin(ROOT / 'work/runtime/diplomacy-observer-20261027-information-battle-v29-001/build-manifest.json')
    write(STAGE / f'runtime-source-pins-before-{revision:03d}.json', result)
    return {'status': 'frozen', 'files': len(result['files'])}


def verify(revision: int = 1):
    frozen = read_json(STAGE / f'runtime-source-pins-before-{revision:03d}.json')
    current = [pin(ROOT / item['path']) for item in frozen['files']]
    if current != frozen['files']:
        raise ValueError('frozen_source_changed')
    return current


def full(revision: int = 1):
    verify(revision)
    log, xml = STAGE / f'regression-full-{revision:03d}.log', STAGE / f'regression-full-{revision:03d}.xml'
    if log.exists() or xml.exists():
        raise ValueError('formal_full_already_started')
    command = [sys.executable, '-m', 'pytest', '-q', 'bridge/tests', f'--junitxml={xml}']
    with log.open('xb') as stream:
        result = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT)
    write(STAGE / f'full-execution-boundary-{revision:03d}.json', {
        'command': command, 'exit_code': result.returncode, 'source_unchanged': verify(revision),
    })
    print(_summary_line(log))
    return result.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', nargs='?', choices=('freeze', 'full'))
    parser.add_argument('--manager-report', type=Path)
    parser.add_argument('--line1-abi-report', type=Path)
    parser.add_argument('--revision',type=int,choices=range(1,100),default=1)
    args = parser.parse_args()
    if args.phase is None:
        parser.print_help()
        return 0
    if args.phase == 'freeze':
        if args.manager_report is None or args.line1_abi_report is None:
            parser.error('freeze requires --manager-report and --line1-abi-report')
        print(freeze(args.manager_report.resolve(strict=True),args.line1_abi_report.resolve(strict=True),args.revision))
        return 0
    return full(args.revision)


if __name__ == '__main__':
    raise SystemExit(main())
