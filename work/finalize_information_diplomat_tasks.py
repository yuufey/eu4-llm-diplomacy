"""Explicit freeze/full/finish phases for batch59; import and help are inert."""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.finalize_information_trade_transfer import (
    pin, read_json, _topic_counts, _topic, _test_cases, _summary_line, _count,
)

STAGE = ROOT / 'work/runtime/information-diplomat-favor-tasks-20261027-001'
BASE = ROOT / 'work/runtime/information-trade-transfer-20261027-001'
INSTALLATION = ROOT / 'work/runtime/diplomacy-observer-20261027-information-battle-v28-002/installation.json'
ADDED = (
    'bridge/information/catalog.py',
    'bridge/information/diplomat_tasks.py',
    'bridge/information/diplomat_tasks_memory.py',
    'bridge/information/profiles/diplomat-tasks-memory-1374.json',
    'bridge/tests/test_information_diplomat_tasks.py',
    'bridge/tests/test_information_diplomat_tasks_memory.py',
    'bridge/tests/test_information_favor_tasks.py',
)
DOC = ROOT / 'docs/外交官与人情任务只读接口.md'
REVISION = '001'
LIVE_REVISION = None


def selected(name):
    return name.replace('-001.', f'-{REVISION}.')


def live_directory():
    return STAGE / f'live-acceptance-{LIVE_REVISION or REVISION}'


def write(name, value):
    path = STAGE / selected(name)
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    return path


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + '.batch59.tmp')
    with temporary.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    temporary.replace(path)


def frozen():
    before = read_json(STAGE / selected('runtime-source-pins-before-001.json'))
    after = [pin(ROOT / item['path']) for item in before['files']]
    if after != before['files']:
        raise ValueError('frozen_runtime_changed')
    supplemental_path = STAGE / 'supplemental-source-pins-001.json'
    if supplemental_path.exists():
        supplemental = read_json(supplemental_path)
        if supplemental['revision'] == int(REVISION):
            additional = [pin(ROOT / item['path']) for item in supplemental['files']]
            if additional != supplemental['files']:
                raise ValueError('supplemental_source_changed')
            after += additional
    return after


def freeze():
    baseline = read_json(BASE / 'runtime-source-pins-before-001.json')
    paths = list(dict.fromkeys(baseline['runtime_paths'] + list(ADDED)))
    matrix = ROOT / 'docs/信息字段覆盖.json'
    if (STAGE / selected('coverage-matrix-before-001.json')).exists():
        raise ValueError('freeze_already_exists')
    files = [pin(ROOT / name) for name in paths]
    profile_path = ROOT / 'bridge/information/profiles/diplomat-tasks-memory-1374.json'
    profile = read_json(profile_path)
    write('source-contract-001.json', {
        'schema': 'information_diplomat_favor_source_contract.v1', 'batch': 59,
        'version': '1.37.4', 'game_sha256': profile['executable']['sha256'],
        'profile': pin(profile_path), 'N05_source_evidence': profile['source_evidence'],
        'R05_source': pin(ROOT / 'work/runtime/information-favor-tasks-20261027-001/favor-tasks-source-001.json'),
        'independent_current_inputs': [pin(STAGE / name) for name in ('independent-raw-001.json', 'independent-expected-001.json', 'independent-favor-raw-001.json', 'independent-favor-expected-001.json')],
        'evidence_layers': {'new_REA_function_analysis': False,
                            'static': 'accepted bounded native source and historical state observations; see profile evidence kinds',
                            'current_RPM': 'independent current bytes, same bound installation, two consistent passes, closed handle',
                            'runtime_public_query': 'pending live acceptance; not inferred from static evidence'},
        'gaps': ['capacity is not vector length', 'lifecycle dates are raw only',
                 'only 0x3378 task family classified', 'no current returning sample',
                 'R05 network and monthly progress unavailable', 'world generation/GUI not independently established'],
        'dispatch_authorized_by_static_findings': False,
    })
    shutil.copyfile(matrix, STAGE / selected('coverage-matrix-before-001.json'))
    write('runtime-source-pins-before-001.json', {
        'schema': 'information_runtime_source_pins.v1', 'batch': 59,
        'runtime_paths': paths, 'files': files,
        'timing': 'before formal full and live acceptance',
        'baseline': pin(BASE / 'development-summary-001.json'),
        'coverage_before': pin(STAGE / selected('coverage-matrix-before-001.json')),
    })
    print(json.dumps({'runtime_paths': len(files)}))
    return 0


def full():
    frozen()
    log = STAGE / selected('regression-full-001.log')
    xml = STAGE / selected('regression-full-001.xml')
    if log.exists() or xml.exists():
        raise ValueError('formal_run_already_started')
    command = [sys.executable, '-m', 'pytest', '-q', 'bridge/tests', f'--junitxml={xml}']
    with log.open('xb') as stream:
        result = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT)
    write('full-execution-boundary-001.json', {
        'schema': 'information_full_execution.v1', 'batch': 59,
        'command': command, 'exit_code': result.returncode,
        'runtime_files_unchanged': frozen(),
    })
    print(_summary_line(log))
    return result.returncode


def comparison():
    xml, log = STAGE / selected('regression-full-001.xml'), STAGE / selected('regression-full-001.log')
    cases, bad, occurrences = _test_cases(xml)
    oldcases, oldbad, oldoccurrences = _test_cases(BASE / 'regression-full-001.xml')
    key = lambda c: f"{c.get('classname')}::{c.get('name')}"
    added = set(map(key, cases)) - set(map(key, oldcases))
    summary = _summary_line(log)
    result = {
        'command': 'python -m pytest -q bridge/tests',
        'passed': _count(summary, 'passed'), 'failed': _count(summary, 'failed'),
        'errors': _count(summary, 'errors'), 'subtests_passed': _count(summary, 'subtests passed'),
        'summary': summary, 'whole_suite_green': not bad,
        'failure_error_occurrences': occurrences, 'unique_failure_error_nodes': len(bad),
        'new_failure_nodes': sorted(bad - oldbad), 'resolved_failure_nodes': sorted(oldbad - bad),
        'new_or_renamed_tests': sorted(added), 'net_case_delta': len(cases) - len(oldcases),
        'new_test_failures': [key(c) for c in cases if key(c) in added and (c.findall('failure') or c.findall('error'))],
        'baseline_failure_error_occurrences': oldoccurrences,
        'xml': pin(xml), 'log': pin(log), 'boundary': pin(STAGE / selected('full-execution-boundary-001.json')),
    }
    if result['new_failure_nodes'] or result['new_test_failures']:
        raise ValueError('new_regression_failure_requires_resolution')
    return result


def coverage(live):
    discovery = read_json(live_directory() / 'discovery.json')
    context = discovery['context']
    if context.get('session_id') != live['session_id'] or context.get('game_date') != live['game_date'] or context.get('observer') != 'FRA':
        raise ValueError('discovery_live_context_mismatch')
    before = read_json(STAGE / selected('coverage-matrix-before-001.json'))
    merged = deepcopy(before)
    changes = []
    for topic_id, field in [('N05', 'diplomat_tasks'), ('R05', 'favor_tasks')]:
        target, observed = _topic(merged['topics'], topic_id), _topic(discovery['topics'], topic_id)
        descriptor = deepcopy(observed['fields'][field])
        if target['fields'][field]['coverage'] != 'planned' or descriptor['coverage'] != 'partial':
            raise ValueError('coverage_transition_invalid')
        descriptor['complete'] = False
        target['fields'][field] = descriptor
        changes.append({'topic': topic_id, 'field': field, 'before': 'planned', 'after': 'partial'})
        alias = merged.setdefault(topic_id, {})
        alias.setdefault('fields', {})[field] = deepcopy(descriptor)
        for key in ('context_scope', 'source', 'object_types', 'parameters', 'triggers'):
            if key in observed:
                alias[key] = deepcopy(observed[key])
    # R05 explicitly describes the unavailable country-network request too.
    _topic(merged['topics'], 'R05')['object_types'] = deepcopy(_topic(discovery['topics'], 'R05')['object_types'])
    for key in ('parameters', 'source', 'context_scope', 'adapter_sources'):
        observed = _topic(discovery['topics'], 'N05')
        if key in observed:
            _topic(merged['topics'], 'N05')[key] = deepcopy(observed[key])
    configured, actual = _topic_counts(merged['topics']), _topic_counts(discovery['topics'])
    for counts in (configured, actual):
        if (counts['topic_count'], counts['field_count']) != (74, 397):
            raise ValueError('full_catalog_scope_changed')
    merged.update(counts=configured, expected_counts=deepcopy(configured), goal_complete=False)
    adapters = merged['configuration']['adapters']
    if 'NativeDiplomatTasksSource' not in adapters:
        adapters.append('NativeDiplomatTasksSource')
    # Only declared field/object changes and their aggregate counts are allowed.
    reverse = deepcopy(merged)
    for topic_id, field in [('N05', 'diplomat_tasks'), ('R05', 'favor_tasks')]:
        _topic(reverse['topics'], topic_id)['fields'][field] = deepcopy(_topic(before['topics'], topic_id)['fields'][field])
        if topic_id in before:
            reverse[topic_id] = deepcopy(before[topic_id])
        else:
            reverse.pop(topic_id, None)
    _topic(reverse['topics'], 'R05')['object_types'] = deepcopy(_topic(before['topics'], 'R05')['object_types'])
    for key in ('parameters', 'source', 'context_scope', 'adapter_sources'):
        prior = _topic(before['topics'], 'N05')
        if key in prior:
            _topic(reverse['topics'], 'N05')[key] = deepcopy(prior[key])
        else:
            _topic(reverse['topics'], 'N05').pop(key, None)
    reverse['configuration'] = deepcopy(before['configuration'])
    for key in ('counts', 'expected_counts', 'goal_complete'):
        if key in before:
            reverse[key] = deepcopy(before[key])
        else:
            reverse.pop(key, None)
    if reverse != before:
        raise ValueError('undeclared_coverage_change')
    atomic_json(ROOT / 'docs/信息字段覆盖.json', merged)
    receipt = {'schema': 'information_coverage_update.v1', 'batch': 59, 'status': 'passed',
               'changes': changes, 'configuration_counts': configured, 'live_counts': actual,
               'stored_before_counts': before.get('counts'), 'recomputed_before_counts': _topic_counts(before['topics']),
               'count_policy': 'recompute from all 74 topic descriptors; prior aggregate counts were stale',
               'metadata_changes': ['R05.object_types includes explicitly unavailable country network',
                                    'N05 shared parameter schema and CompositeSource ownership metadata',
                                    'configuration.adapters adds NativeDiplomatTasksSource',
                                    'N05/R05 top-level aliases copy current source metadata',
                                    'aggregate counts recomputed from topic fields'],
               'all_other_field_descriptors_preserved': True, 'live_receipt': pin(live_directory() / 'report.json')}
    write('coverage-update-001.json', receipt)
    return receipt


def docs(tests, cover, binding, identity, game_date):
    text = '''# 外交官与人情任务只读接口

法国当前读取到4个外交官实例：0号在勃艮第建立间谍网，1号执行指向奥尔良的未知类型任务，2、3号空闲。实例数量不作为外交官总容量。N05.diplomat_tasks 提供状态、ID、目标完整引用、任务 token 和原始生命周期日期；日期槽位尚不能解释为预计返回日。未知 token 保留原值，不猜测任务类型。

R05.favor_tasks 提供指定国家对中 actor 向 recipient 获取人情的当前状态。当前 FRA→BUR 为 task_active=false；这不表示外交官没有在该国执行其他任务。只读检查复用 stop_curry_favors，名称不表示提交停止动作。全网任务、月度增长及进度继续缺失，两字段保持 partial、complete=false。

目录接受 country 请求以明确返回 FAVOR_TASKS_COUNTRY_NETWORK_UNAVAILABLE；它不提供全网任务列表。

```json
{"tool":"information_query","arguments":{"request_id":"tasks-example-001","queries":[{"topic":"N05","object":{"type":"country","country":"FRA"},"fields":["diplomat_tasks"],"parameters":{}},{"topic":"R05","object":{"type":"country_pair","actor":"FRA","recipient":"BUR"},"fields":["favor_tasks"],"parameters":{}}]}}
```

上述查询可用于信息报告和周期订阅。R05混合查询沿用 action_id/kind 的选择，只执行一次 inspection；若选定人情兑换动作，任务字段返回 unknown。外交官可用数仍沿用 N05.diplomats_available，diplomats_total、relations_count 和 relations_limit 继续 planned。

'''
    text += f"本批正式完整回归：{tests['passed']} passed、{tests['failed']} failed、{tests['errors']} errors，另{tests['subtests_passed']}个子测试通过。新增失败节点{len(tests['new_failure_nodes'])}，完整开发计划继续。\n\n"
    text += '收据选择：live001在服务启动时因N05参数规则冲突退出，未执行查询；修正后live002的查询结果正确，验收器误读主题位置而停止。live003复用该查询，完成报告和周期交付，8项检查通过、服务exit0。full001已中断，不作为完整回归；最终采用full002。原件均保留，未重发成功查询。\n\n'
    text += f'来源与实机验收见 [批次归档](../work/runtime/information-diplomat-favor-tasks-20261027-001/development-summary-{REVISION}.json)。\n'
    with DOC.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(text)
    paragraph = f'''<!-- batch59-diplomat-favor-summary:start -->
## 第五十九批：外交官与获取人情任务

已接通N05.diplomat_tasks与R05.favor_tasks，均partial、complete=false。FRA当前4个实例、2个空闲，0号在BUR建立间谍网，1号指向ORL且任务类型未知；FRA→BUR获取人情任务未激活。原始日期不作为预计返回日，实例数量不作为总容量。查询、报告及周期交付与独立原始读取对照通过，调用见[外交官与人情任务接口](docs/外交官与人情任务只读接口.md)。

完整回归{tests['passed']} passed、{tests['failed']} failed、{tests['errors']} errors，另{tests['subtests_passed']}子测试通过；新增失败节点{len(tests['new_failure_nodes'])}，既有失败/错误{tests['failure_error_occurrences']}次、{tests['unique_failure_error_nodes']}节点。配置{cover['configuration_counts']['field_counts']}，实机{cover['live_counts']['field_counts']}，均74主题397字段。完整阶段2/3/4、LLM自主订阅及完整B01–B04继续，goal active。

复用v28-002安装，PID{binding['pid']}、creation{binding['creation_filetime']}、session{binding['session_id']}、1.37.4 EXE SHA {binding['game_sha256']}、DLL SHA {binding['dll_sha256']}；日期{game_date}、POR/slot189、speed0、paused1。本批N05独立/生产读取为纯RPM，R05公开入口为既有原生只读inspection；无外交业务、保存、重启、换DLL或日期推进。锁屏不能扩大成后台自动化阻塞，继续按《开发过程自动化.md》复用成熟入口。

归档入口work/runtime/information-diplomat-favor-tasks-20261027-001/development-summary-{REVISION}.json。历史成功、已派发、unknown、原final-pass IDs、未闭合ownership和原120-action batch均不重试，尤其SIE→FRA military access proposal1及r70_country_money_001_outbound。下一步继续N05容量/返回日期、R05全网及完整B01–B04。

收据选用live003和full002。live001启动失败、live002检查器失败、full001中断均保留；live003复用002原query，仅继续报告和周期验收，8项检查通过、1条periodic、server0。源码91项于full002前冻结，另2项schema接入源码于full002期间补记指纹并在结束后复核；不声称93项均有运行前指纹。
<!-- batch59-diplomat-favor-summary:end -->

'''
    for relative in ('HANDOFF.md', 'README(agent).md', 'docs/信息导出与订阅开发计划.md'):
        path = ROOT / relative
        original = path.read_text(encoding='utf-8')
        if 'batch59-diplomat-favor-summary:start' in original:
            raise ValueError('batch59_docs_already_present')
        temporary = path.with_suffix(path.suffix + '.batch59.tmp')
        with temporary.open('x', encoding='utf-8', newline='\n') as stream:
            stream.write(paragraph + original)
        temporary.replace(path)
    return write('document-verification-001.json', {
        'status': 'passed', 'batch': 59, 'document': pin(DOC),
        'scope_retained': ['74 topics', '397 fields', 'phase2', 'phase3', 'phase4', 'full B01-B04', 'LLM subscriptions'],
        'files': [pin(ROOT / p) for p in ('HANDOFF.md', 'README(agent).md', 'docs/信息导出与订阅开发计划.md', '开发过程自动化.md')],
    })


def finish():
    runtime = frozen()
    live_path = live_directory() / 'report.json'
    live = read_json(live_path)
    if live['status'] != 'passed' or not live['checks'] or not all(v is True for v in live['checks'].values()):
        raise ValueError('live_acceptance_not_passed')
    if live.get('server_exit_code', live.get('server_exit')) != 0 or live['periodic_results'] < 1:
        raise ValueError('live_not_closed_or_delivered')
    installation = read_json(INSTALLATION)
    raw = read_json(STAGE / 'independent-raw-001.json')
    identity = raw['identity']
    reference = read_json(STAGE / 'independent-expected-001.json')
    game_date = reference['date']['value']
    if identity['installation_session_id'] != installation['session_id'] or identity['process_creation_filetime'] != installation['creation_filetime']:
        raise ValueError('current_identity_mismatch')
    if live.get('session_id') != installation['session_id'] or live.get('game_date') != game_date or live.get('scopes') != {'N05': 'country_scope:FRA', 'R05': 'selected_country_pair:FRA->BUR'}:
        raise ValueError('live_current_context_mismatch')
    if identity['process_path_sha256'] != installation['game_sha256'] or live.get('read_only') is not True or type(live.get('business_actions_submitted')) is not int or live['business_actions_submitted'] != 0:
        raise ValueError('current_binary_or_business_scope_mismatch')
    for name, filename in [('n05', 'independent-expected-001.json'), ('r05', 'independent-favor-expected-001.json')]:
        ref = STAGE / filename
        recorded = live['references'][name]
        if Path(recorded['path']).resolve() != ref.resolve() or recorded['sha256'] != pin(ref)['sha256']:
            raise ValueError('live_reference_pin_mismatch')
    context = read_json(live_directory() / 'discovery.json')['context']
    if any(context.get(key) != installation[field] for key, field in [('session_id', 'session_id'), ('game_sha256', 'game_sha256'), ('dll_sha256', 'dll_sha256')]):
        raise ValueError('discovery_current_installation_mismatch')
    tests = comparison()
    write('regression-comparison-001.json', tests)
    cover = coverage(live)
    docreceipt = docs(tests, cover, installation, identity, game_date)
    write('runtime-source-pins-after-001.json', {'batch': 59, 'files': runtime, 'unchanged': True})
    sources = [ROOT / item['path'] for item in runtime]
    sources += [ROOT / p for p in ('work/probe_information_diplomat_tasks.py', 'work/probe_information_favor_tasks.py', 'work/validate_information_diplomat_tasks_live.py', 'work/finalize_information_diplomat_tasks.py', 'docs/信息字段覆盖.json', '开发过程自动化.md', 'HANDOFF.md', 'README(agent).md', 'docs/信息导出与订阅开发计划.md')]
    sources += [DOC]
    sources += [ROOT / 'work/finalize_information_trade_transfer.py',
                ROOT / 'work/runtime/information-favor-tasks-20261027-001/favor-tasks-source-001.json',
                STAGE / selected('source-contract-001.json')]
    snapshots = []
    for path in sorted(set(sources)):
        relative = path.relative_to(ROOT)
        target = STAGE / f'source-snapshots-{REVISION}' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as output, path.open('rb') as source:
            shutil.copyfileobj(source, output)
        original, copied = pin(path), pin(target)
        if original['sha256'] != copied['sha256']:
            raise ValueError('source_snapshot_mismatch')
        snapshots.append({'source': original, 'copy': copied})
    baseline = read_json(BASE / 'development-summary-001.json')
    summary = {
        'schema': 'information_diplomat_favor_tasks_development_summary.v1', 'batch': 59,
        'status': 'progress', 'objective': baseline['objective'], 'goal_status': 'active', 'goal_complete': False,
        'scope': {'topics': 74, 'fields': 397, 'N05.diplomat_tasks': 'partial', 'R05.favor_tasks': 'partial', 'complete': False},
        'remaining_full_scope': baseline['remaining_full_scope'],
        'delivered': ['N05.diplomat_tasks partial', 'R05.favor_tasks selected pair partial'],
        'runtime_validation': pin(live_path), 'documentation_validation': pin(docreceipt),
        'runtime_identity': {'installation': pin(INSTALLATION), 'identity': identity, 'live_session': live.get('session_id'), 'game_date': game_date},
        'coverage': cover, 'tests': tests, 'source_snapshot': snapshots,
        'source_snapshot_policy': {'pre_full_runtime_files': 91,
                                   'supplemental_files_sampled_during_full': 2,
                                   'supplemental_receipt': pin(STAGE / 'supplemental-source-pins-001.json'),
                                   'all_93_pinned_before_full_claimed': False,
                                   'unchanged_code_not_retested_for_pin_timing': True},
        'source_layers': {'new_REA_function_analysis': False, 'N05': 'bounded pure RPM; accepted historical state/family evidence', 'R05': 'accepted R71 ordinary static contract; independent current RPM; existing native read-only inspection'},
        'no_repeat': {'historical_success_dispatched_unknown_original_ids_unclosed_ownership': 'not retried', 'original_120_batch': 'not replayed', 'business_actions_submitted': 0},
        'next_work': ['N05 capacity and lifecycle date semantics', 'R05 network tasks', 'full B01-B04 and remaining phases2/3/4'],
        'receipt_selection': {'live': 'live-acceptance-003/report.json',
                              'formal_full': 'regression-full-002.xml/.log',
                              'retained_history': ['live001 startup schema conflict before query',
                                                   'live002 consumer topic-location assertion failed after successful query',
                                                   'full001 interrupted; not a complete regression'],
                              'successful_query_not_reissued': True},
        'baseline': pin(BASE / 'development-summary-001.json'),
    }
    summary_path = write('development-summary-001.json', summary)
    artifacts = [pin(p) for p in sorted(STAGE.rglob('*')) if p.is_file() and not any(part.startswith('source-snapshots') for part in p.parts) and p.suffix in {'.json', '.log', '.xml'}]
    write('archive-verification-001.json', {'status': 'passed', 'batch': 59, 'summary': pin(summary_path),
                                          'snapshots_verified': len(snapshots), 'artifacts': artifacts,
                                          'runtime_unchanged': frozen() == runtime})
    print(json.dumps({'status': 'progress', 'tests': tests['summary'], 'coverage': cover['configuration_counts']['field_counts']}))
    return 0


def main():
    global REVISION, LIVE_REVISION
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('freeze', 'full', 'finish'), nargs='?')
    parser.add_argument('--revision', type=int, choices=range(1, 10), default=1)
    parser.add_argument('--live-revision', type=int, choices=range(1, 10))
    args = parser.parse_args()
    REVISION = f'{args.revision:03d}'
    LIVE_REVISION = f'{args.live_revision:03d}' if args.live_revision is not None else None
    if args.phase is None:
        parser.print_help()
        return 0
    return {'freeze': freeze, 'full': full, 'finish': finish}[args.phase]()


if __name__ == '__main__':
    raise SystemExit(main())
