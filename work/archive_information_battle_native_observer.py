"""Archive batch 61 after its completed full/live receipts; default is inert."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.finalize_information_battle_native_observer import STAGE, BASE, verify
from work.finalize_information_trade_transfer import pin, read_json
from work.probe_information_diplomat_tasks import write

BUILD = ROOT / 'work/runtime/diplomacy-observer-20261027-information-battle-v29-001'
DOCUMENTS = (
    'HANDOFF.md', 'README(agent).md', 'docs/信息导出与订阅开发计划.md',
    'docs/战报原生文本读取与传输.md', '开发过程自动化.md',
    'docs/外交开发推进复盘.md', 'docs/信息字段覆盖.json',
)
SUPPLEMENTAL = (
    'work/run_information_battle_natural_window_installed.py',
    'work/validate_information_battle_native_text_live_003.py',
    'work/archive_information_battle_native_observer.py',
)


def archive() -> dict:
    frozen = verify(2)
    before = read_json(STAGE / 'runtime-source-pins-before-002.json')
    live = read_json(STAGE / 'live-acceptance-003/report.json')
    comparison = read_json(STAGE / 'regression-comparison-001.json')
    ingest = read_json(STAGE / 'raw-ingest-001.json')
    natural = read_json(STAGE / 'natural-window-v29-002/report.json')
    disabled = read_json(STAGE / 'disable-001.json')['response']
    checkpoint = read_json(STAGE / 'checkpoint-v29-001/outcome-001.json')
    matrix = read_json(ROOT / 'docs/信息字段覆盖.json')
    assert live['status'] == 'passed' and all(live['checks'].values())
    assert live['server_exit_code'] == 0 and live['event_results'] == 3
    assert live['query_reused_offline'] and live['report_query_reused_offline']
    assert comparison['status'] == 'passed_no_new_failure_nodes'
    assert ingest['status'] == 'passed' and len(ingest['messages']) == 16
    assert natural['status'] == 'observed_target_and_paused'
    assert natural['request_published'] is True and natural['target_raw'] == 56560248
    assert disabled['state'] == 'disabled' and not disabled['fragment_sink_pending']
    assert disabled['open_message_scopes'] == 0
    assert disabled['native_metadata_copied'] == '0' and disabled['line1_copied'] == '0'
    assert checkpoint['status'] == 'saved_verified'
    assert pin(ROOT / 'docs/信息字段覆盖.json') == before['coverage_before']
    for rel in DOCUMENTS[:3]:
        text = (ROOT / rel).read_text(encoding='utf-8')
        assert text.startswith('<!-- batch61-native-observer-summary:start -->')
        assert all(token in text[:4200] for token in ('56560248', '3020', '397', '18592'))
    for rel in ('manager-test-017/report.json', 'line1-observer-abi-004/report.json',
                'patch-five-targets-001/report.json'):
        assert read_json(STAGE / rel)['status'] == 'passed'

    write(STAGE / 'runtime-source-pins-after-002.json', {
        'batch': 61, 'revision': 2, 'files': frozen,
        'timing': 'after full002 and live003; 134 frozen files unchanged',
        'supplemental_not_in_formal_full_freeze': [pin(ROOT / p) for p in SUPPLEMENTAL],
    })
    source_paths = list(dict.fromkeys([p['path'] for p in frozen] + list(SUPPLEMENTAL) + list(DOCUMENTS)))
    pairs = []
    for rel in source_paths:
        source = ROOT / rel
        destination = STAGE / 'source-snapshots-final-002' / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        with source.open('rb') as src, destination.open('xb') as dst:
            shutil.copyfileobj(src, dst, length=1024 * 1024)
        a, b = pin(source), pin(destination)
        assert (a['bytes'], a['sha256']) == (b['bytes'], b['sha256'])
        pairs.append({'source': a, 'snapshot': b})
    write(STAGE / 'source-snapshot-verification-002.json', {
        'status': 'passed', 'runtime_frozen_count': len(frozen),
        'supplemental_count': len(SUPPLEMENTAL), 'document_count': len(DOCUMENTS),
        'pairs': pairs, 'all_copies_equal': True,
    })
    write(STAGE / 'document-verification-001.json', {
        'status': 'passed', 'latest_batch': 61,
        'files': [pin(ROOT / p) for p in DOCUMENTS],
        'coverage_unchanged': True, 'coverage': matrix['counts'],
        'full_scope_continues': True, 'native_text_positive_in_live': False,
    })

    summary = {
        'schema': 'information_battle_native_observer_development.v1',
        'batch': 61, 'status': 'progress', 'goal_status': 'active',
        'objective': '按照docs/信息导出与订阅开发计划.md开发完整信息导出与自主订阅',
        'scope': {'topics': 74, 'fields': 397, 'phases': [2, 3, 4],
                  'autonomous_subscriptions': True, 'full_B01_B04': 'incomplete'},
        'coverage': matrix['counts'], 'coverage_changed': False,
        'implemented': [
            'v29 observer uses owned native text capture and v6 wire on the actual native source',
            'five-target patch transaction and Line1 original-register/unwind preservation',
            'private message-copy guard, conflict retraction and existing v5 retention',
            'v29 build/start/control/installed probe plus v6 raw persistence',
        ],
        'identity': live['identity'], 'final_control': live['control_after'],
        'installation': pin(BUILD / 'installation.json'),
        'build_manifest': pin(BUILD / 'build-manifest.json'),
        'native_source_count': 116, 'wire_version': 6,
        'native_text_codec': 'eu4_escape',
        'natural_window': natural,
        'native_source_final': {'state': disabled['state'],
            'captured': int(disabled['captured']), 'container_copied': int(disabled['container_copied']),
            'native_metadata_copied': 0, 'line1_candidates': 0, 'line1_copied': 0,
            'resources_retained_for_process_lifetime': True},
        'raw_ingestion': {'status': ingest['status'], 'messages': 16,
                          'receipt': pin(STAGE / 'raw-ingest-001.json')},
        'live': {'status': live['status'], 'checks': live['checks'],
                 'event_results': live['event_results'], 'event_ids': live['event_ids'],
                 'server_exit_code': 0, 'request_ids': live['request_ids'],
                 'query_and_report_origin': 'live-acceptance-002; reused offline by live003',
                 'event_subscription': 'new selector-free report in live003; old subscription cancelled',
                 'receipt': pin(STAGE / 'live-acceptance-003/report.json')},
        'formal_regression': {'selected': 'regression-full-002',
            'passed': 3020, 'failed': 106, 'errors': 35, 'subtests_passed': 1920,
            'elapsed_seconds': 370.60, 'new_tests': 8, 'new_tests_all_passed': True,
            'new_failure_nodes': 0, 'resolved_failure_nodes': 0,
            'baseline_failure_error_occurrences': 141, 'baseline_failure_error_nodes': 128,
            'comparison': pin(STAGE / 'regression-comparison-001.json'),
            'historical_full001': '3017 passed /106 failed /35 errors /1915 subtests; before controller v29 port; 134 exact source copies retained'},
        'native_fixture_evidence': {
            'manager017': 'passed; actual observer callback with synthetic image, 64 native checks; two Line1 copies, conflict retract/latch verified',
            'abi004': '89/89; actual production stub, register state and compiled PE unwind',
            'patch_five001': '68/68; private RX apply/trampolines/rollback',
            'not_live_text_evidence': True,
        },
        'checkpoint': {'receipt': pin(STAGE / 'checkpoint-v29-001/outcome-001.json'),
                       'save': checkpoint['save'], 'mature_save_reused_once': True,
                       'basic_save_or_dedicated_reload_test': False,
                       'rotating_autosaves_restored': True},
        'source_boundaries': {'frozen_runtime_count': len(frozen),
            'selected_freeze': pin(STAGE / 'runtime-source-pins-before-002.json'),
            'after': pin(STAGE / 'runtime-source-pins-after-002.json'),
            'supplemental_not_in_full_freeze': [pin(ROOT / p) for p in SUPPLEMENTAL],
            'snapshot_verification': pin(STAGE / 'source-snapshot-verification-002.json')},
        'selected_source_contract': pin(STAGE / 'line1-join-contract-002.json'),
        'selected_static_owner': pin(STAGE / 'line1-owner-source-006.json'),
        'new_REA_function_queries': 2,
        'evidence_layers': ['cached REA static functions', 'ordinary PE/COFF and source inference',
                            'owned synthetic native fixtures', 'installed pure RPM guards',
                            'actual natural battle v6 transport', 'live MCP with original query reuse'],
        'historical_failures_retained': [
            'source/ABI/manager development diagnostic attempts before selected receipts',
            'full001 before controller port, exact source copies retained',
            'natural-window-v29-001 rejected old v23 probe; request_published=false',
            'live001 strict configuration rejection before MCP initialization, no query',
            'live002 selected-event report yielded 3 results; 8/15 selector mismatch; selected7 query/report succeeded',
        ],
        'limitations': [
            'No installed-game metadata or Line1 candidate occurred in this window; actual positive text capture is unverified.',
            'Title, complete window text, raw_text, visibility and complete B01-B04 remain incomplete.',
            'Ordinary background startup is observed; a complete locked-desktop startup trial is not claimed.',
            'The full regression retains 141 existing failure/error occurrences; it is not green.',
        ],
        'next': 'Obtain a real message/Line1 candidate using existing background/native control, then continue title/full-window and remaining plan fields.',
        'no_repeat': 'Historical successful/dispatched/unknown actions, original final-pass IDs, unclosed ownership and original120 remain forbidden; especially SIE->FRA military access proposal1 and r70_country_money_001_outbound.',
        'documents': pin(STAGE / 'document-verification-001.json'),
        'baseline': pin(BASE / 'development-summary-001.json'),
    }
    write(STAGE / 'development-summary-001.json', summary)

    exclusions = {'archive-verification-001.json', 'final-readback-001.json'}
    artifact_paths = sorted(p for p in STAGE.rglob('*') if p.is_file()
                            and not any(part.startswith('source-snapshots') for part in p.relative_to(STAGE).parts)
                            and p.name not in exclusions
                            and p.suffix in {'.json', '.log', '.xml', '.bin', '.sqlite', '.txt', '.md'})
    artifacts = [pin(p) for p in artifact_paths]
    write(STAGE / 'archive-verification-001.json', {
        'status': 'passed', 'snapshot_count': len(pairs), 'artifact_count': len(artifacts),
        'snapshots': pairs, 'artifacts': artifacts,
        'scope': 'streamed SHA-256; selected and historical receipts retained, no game access',
    })
    return {'status': 'archived_progress', 'snapshots': len(pairs), 'artifacts': len(artifacts)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({'status': 'inert'}))
        return 0
    print(json.dumps(archive()))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
