"""Freeze, regress and archive batch60; default/help perform no work."""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.finalize_information_trade_transfer import pin, read_json, _test_cases, _summary_line, _count, _topic_counts
from work.probe_information_diplomat_tasks import write

STAGE = ROOT / 'work/runtime/information-battle-native-text-20261027-001'
BASE = ROOT / 'work/runtime/information-diplomat-favor-tasks-20261027-001'
SOURCES = (
    'bridge/information/battles.py', 'bridge/information/battle_native_text.py',
    'bridge/tests/test_information_battle_native_text.py',
    'work/native/information-battle-owned-native-text.h',
    'work/native/tests/information-battle-owned-native-text-test.cpp',
    'work/test_information_battle_owned_native_text.py',
    'work/native/information-battle-native-text-wire.h',
    'work/native/tests/information-battle-native-text-wire-test.cpp',
    'work/information_battle_native_text_wire.py',
    'work/test_information_battle_native_text_wire.py',
    'work/tests/test_information_battle_native_text_wire.py',
    'work/native/information-battle-line1-entry-plan.h',
    'work/native/information-battle-line1-entry-stub.S',
    'work/native/tests/information-battle-line1-entry-test.cpp',
    'work/native/tests/information-battle-line1-abi.S',
    'work/test_information_battle_line1_entry.py',
    'work/native/tests/information-battle-native-text-chain.cpp',
    'work/test_information_battle_native_text_chain.py',
    'work/validate_information_battle_native_text_recorded.py',
    'work/finalize_information_battle_native_text.py',
)


def put(name, value):
    path = STAGE / name
    write(path, value)
    return path


def verify():
    frozen = read_json(STAGE / 'runtime-source-pins-before-001.json')
    current = [pin(ROOT / p['path']) for p in frozen['files']]
    if current != frozen['files']:
        raise ValueError('frozen_source_changed')
    return current


def freeze():
    previous = read_json(BASE / 'runtime-source-pins-after-002.json')
    paths = list(dict.fromkeys([p['path'] for p in previous['files']] + list(SOURCES)))
    files = [pin(ROOT / p) for p in paths]
    return put('runtime-source-pins-before-001.json', {
        'batch': 60, 'files': files, 'timing': 'after targeted and recorded MCP; before formal full',
        'coverage_before': pin(ROOT / 'docs/信息字段覆盖.json'),
        'baseline': pin(BASE / 'development-summary-002.json'),
    })


def full():
    verify()
    log, xml = STAGE / 'regression-full-001.log', STAGE / 'regression-full-001.xml'
    if log.exists() or xml.exists():
        raise ValueError('formal_full_already_started')
    command = [sys.executable, '-m', 'pytest', '-q', 'bridge/tests', f'--junitxml={xml}']
    with log.open('xb') as output:
        result = subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
    put('full-execution-boundary-001.json', {'command': command, 'exit_code': result.returncode,
                                           'source_unchanged': verify()})
    print(_summary_line(log))
    return result.returncode


def comparison():
    xml, log = STAGE / 'regression-full-001.xml', STAGE / 'regression-full-001.log'
    cases, bad, occurrences = _test_cases(xml)
    oldcases, oldbad, oldoccurrences = _test_cases(BASE / 'regression-full-002.xml')
    key = lambda c: f"{c.get('classname')}::{c.get('name')}"
    added = set(map(key, cases)) - set(map(key, oldcases))
    summary = _summary_line(log)
    result = {
        'passed': _count(summary, 'passed'), 'failed': _count(summary, 'failed'),
        'errors': _count(summary, 'errors'), 'subtests_passed': _count(summary, 'subtests passed'),
        'summary': summary, 'failure_error_occurrences': occurrences,
        'unique_failure_error_nodes': len(bad), 'new_failure_nodes': sorted(bad - oldbad),
        'resolved_failure_nodes': sorted(oldbad - bad), 'baseline_occurrences': oldoccurrences,
        'new_or_renamed_tests': sorted(added), 'net_case_delta': len(cases) - len(oldcases),
        'new_test_failures': [key(c) for c in cases if key(c) in added and (c.findall('error') or c.findall('failure'))],
        'xml': pin(xml), 'log': pin(log), 'command': 'python -m pytest -q bridge/tests',
    }
    if result['new_failure_nodes'] or result['new_test_failures']:
        raise ValueError('new_regression_failure')
    return result


def finish(mcp_path):
    runtime = verify()
    tests = comparison()
    mcp = read_json(mcp_path)
    if mcp.get('status') != 'passed' or not mcp.get('checks') or not all(value is True for value in mcp['checks'].values()):
        raise ValueError('recorded_MCP_not_passed')
    required_checks = {
        'recorded_discovery_exposes_details_and_raw_text',
        'query_composes_v6_native_text_and_unresolved_raw_text',
        'report_reuses_same_partial_native_text_projection',
        'one_event_delivery_reuses_partial_native_text',
        'event_cancel_and_no_active_subscription',
    }
    if not required_checks.issubset(mcp['checks']):
        raise ValueError('recorded_MCP_required_check_missing')
    expected = {
        'mode': 'recorded', 'text_origin': 'synthetic_fixture',
        'native_producer': 'native-cpp-chain', 'server_exit_code': 0,
        'business_actions_submitted': 0, 'game_access': False,
        'native_game_capture': False, 'raw_text_complete': False,
        'query_reused': True, 'raw_text_status': 'unsupported',
    }
    if any(type(mcp.get(key)) is not type(value) or mcp[key] != value
           for key, value in expected.items()):
        raise ValueError('recorded_MCP_scope_or_cleanup_mismatch')
    events = read_json(mcp_path.parent / 'event-results.json')
    if len(events) != 1 or events[0].get('delivery', {}).get('status') != 'delivered':
        raise ValueError('recorded_MCP_event_not_delivered')
    subscriptions = read_json(mcp_path.parent / 'subscriptions-after.json')
    if any(item.get('state') == 'active' for item in subscriptions.get('subscriptions', [])):
        raise ValueError('recorded_MCP_subscription_still_active')
    for path in ('owned-native-text-test-003/report.json', 'line1-entry-test-001/report.json',
                 'native-wire-test-001/report-005.json', 'native-wire-test-001/replay-v5-006.json',
                 'native-text-chain-001/report.json'):
        receipt = read_json(STAGE / path)
        if receipt.get('status') != 'passed':
            raise ValueError('component_receipt_not_passed:' + path)
        for source_path, recorded_pin in receipt.get('sources', {}).items():
            current_pin = pin(ROOT / source_path)
            if any(current_pin[key] != recorded_pin[key] for key in ('bytes', 'sha256')):
                raise ValueError('component_source_changed:' + source_path)
    matrix = ROOT / 'docs/信息字段覆盖.json'
    before = read_json(STAGE / 'runtime-source-pins-before-001.json')['coverage_before']
    if pin(matrix) != before:
        raise ValueError('coverage_changed_without_live_evidence')
    counts = _topic_counts(read_json(matrix)['topics'])
    put('regression-comparison-001.json', tests)
    put('runtime-source-pins-after-001.json', {'files': runtime, 'unchanged': True})
    document = ROOT / 'docs/战报原生文本读取与传输.md'
    text = '''# 战报原生文本读取与传输

已实现原生字符串复制、v6无指针封装和公开B04消费者。`details.value.native_text`分开保留消息定义key、辅助文字、标题候选和正文首行的原始字节、来源与解码结果；已知空字符串、未知与未提供分别表达。

当前实机仍使用v28/wire5，v6采集尚未接入observer、构建和安装。新增字符串样本由自有C++夹具通过Reader、双遍复制、合并及v6编码生成，标记为synthetic fixture；这证明生产者与公开消费者能够对接，不证明游戏实际输出了这些文字。完整窗口文本、全部控件、可见性及完整B01–B04继续开发，raw_text和完整展示状态不因本批改变。

静态来源确认：消息定义key位于definition+0x38；标题helper把结果写入调用者的32字节字符串对象；正文首行setter会把输入移入widget+0x170，再清空输入。因此首行入口在setter前复制。REA静态证据、自有RX/ABI执行和游戏实际事件分别记录。

v6嵌入完整v5原字节，旧版本仍由既有解码器处理。20条封存实机v5数据的兼容解码与离线v6包装均通过，战争编号和模板保持。新字段仍保留complete=false；这20条旧数据没有新增原生文字。

查询可选择B04的details和raw_text；报告和事件订阅共用该投影。raw_text仍返回unsupported/FIELD_NOT_IMPLEMENTED_BY_ADAPTER，不计为已完成字段。已通过recorded MCP对照，见批次收据。

'''
    text += f"正式全回归：{tests['passed']} passed、{tests['failed']} failed、{tests['errors']} errors，另{tests['subtests_passed']}个子测试通过；新增失败节点{len(tests['new_failure_nodes'])}。\n\n"
    text += '来源与测试见[批次归档](../work/runtime/information-battle-native-text-20261027-001/development-summary-001.json)。\n'
    with document.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(text)
    section = f'''<!-- batch60-native-text-summary:start -->
## 第六十批：原生战报文字的复制、传输与公开消费

已实现owned-native-text双遍复制/冲突撤回、IBOW.v6/NTXT封装和B04.details.native_text投影，保留四类文字的来源、原始字节及知识态。新增两个REA函数证据；Line1入口自有RX trampoline与ABI测试通过。20条真实旧v5载荷兼容回放通过。C++合成Reader→复制/合并→v6编码→recorded MCP查询/报告/事件交付完成；文字是synthetic fixture，不能称为实机文字采集。详见[原生文本读取与传输](docs/战报原生文本读取与传输.md)。

完整回归{tests['passed']} passed、{tests['failed']} failed、{tests['errors']} errors，另{tests['subtests_passed']}子测试通过；新增{len(tests['new_or_renamed_tests'])}项全通过，新增失败节点0。覆盖表未改，仍74主题397字段、配置60/159/178；完整阶段2/3/4、LLM自主订阅和完整B01–B04继续，goal active。

实机安装继续沿用59批v28-002/wire5，最后实测PID17112、creation134375498253940149、session17112-1dd65cdbff135b5、date56559408、POR/slot189/speed0/paused1。本批没有打开游戏进程、保存、启动、日期推进或外交派发；游戏仍运行与否未在本批重新检查。新原生组件未接入observer/build，不重复注入、不热替换。下一步把metadata和Line1入口接入现有scope/record，复用成熟保存与后台启动，安装新版本后验证自然事件；锁屏不能扩大成后台自动化阻塞。

归档入口work/runtime/information-battle-native-text-20261027-001/development-summary-001.json。新REA仅为静态函数分析，无游戏执行授权；历史成功、已派发、unknown、原final-pass IDs、未闭合ownership及原120-action batch均不重试，尤其SIE→FRA military access proposal1和r70_country_money_001_outbound。
<!-- batch60-native-text-summary:end -->

'''
    for name in ('HANDOFF.md', 'README(agent).md', 'docs/信息导出与订阅开发计划.md'):
        path = ROOT / name
        old = path.read_text(encoding='utf-8')
        if 'batch60-native-text-summary:start' in old:
            raise ValueError('docs_already_prepended')
        temp = path.with_suffix(path.suffix + '.batch60.tmp')
        with temp.open('x', encoding='utf-8', newline='\n') as stream:
            stream.write(section + old)
        temp.replace(path)
    files = [ROOT / item['path'] for item in runtime] + [document, matrix]
    files += [ROOT / name for name in ('HANDOFF.md', 'README(agent).md', 'docs/信息导出与订阅开发计划.md')]
    files += list(STAGE.glob('*source-*.json')) + [STAGE / 'localized-format-selected-001.json']
    copies = []
    for source in sorted(set(files)):
        target = STAGE / 'source-snapshots' / source.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as output, source.open('rb') as input_stream:
            shutil.copyfileobj(input_stream, output)
        if pin(source)['sha256'] != pin(target)['sha256']:
            raise ValueError('copy_mismatch')
        copies.append({'source': pin(source), 'copy': pin(target)})
    baseline = read_json(BASE / 'development-summary-002.json')
    summary = {
        'schema': 'information_battle_native_text_development_summary.v1', 'batch': 60, 'status': 'progress',
        'objective': baseline['objective'], 'goal_complete': False, 'goal_status': 'active',
        'scope': {'topics': 74, 'fields': 397, 'phases': [2, 3, 4], 'autonomous_subscriptions': True, 'full_B01_B04': 'incomplete'},
        'delivered': ['bounded owned native text and merge', 'v6 framing and semantic decode', 'Line1 entry plan and owned ABI fixture', 'B04 partial native-text projection and recorded MCP'],
        'not_delivered': ['v6 installed game capture', 'actual title/Line1 runtime samples', 'complete B04 window text'],
        'recorded_acceptance': pin(mcp_path), 'recorded_text_origin': 'synthetic C++ Reader fixture',
        'tests': tests, 'coverage': {'changed': False, 'configuration_counts': counts, 'matrix': pin(matrix)},
        'runtime_source_unchanged': verify(), 'source_snapshot': copies,
        'current_installation_reference': 'work/runtime/diplomacy-observer-20261027-information-battle-v28-002/installation.json; last verified batch59, not reopened',
        'next_work': ['observer scope integration and new build', 'mature checkpoint/restart and once-only install', 'natural-event native text capture and public comparison', 'remaining full plan'],
        'source_layers': {'new_REA_functions': ['0x8c02a0', '0x152ad10'], 'old_REA_formatter': '0x14b33a0 reused', 'runtime_game_access': False, 'owned_native_fixture_execution': True},
        'baseline': pin(BASE / 'development-summary-002.json'),
    }
    summary_path = put('development-summary-001.json', summary)
    artifacts = [pin(p) for p in sorted(STAGE.rglob('*')) if p.is_file() and 'source-snapshots' not in p.parts and p.suffix in ('.json', '.log', '.xml', '.bin', '.exe')]
    put('archive-verification-001.json', {'status': 'passed', 'summary': pin(summary_path), 'source_copies': len(copies), 'artifacts': artifacts})
    print({'status': 'progress', 'tests': tests['summary'], 'new_tests': len(tests['new_or_renamed_tests'])})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', nargs='?', choices=('freeze', 'full', 'finish'))
    parser.add_argument('--mcp-report', type=Path)
    args = parser.parse_args()
    if args.phase is None:
        parser.print_help()
        return 0
    if args.phase == 'freeze':
        print(freeze())
        return 0
    if args.phase == 'full':
        return full()
    if args.mcp_report is None:
        parser.error('finish requires --mcp-report')
    finish(args.mcp_report.resolve(strict=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
