"""Publish batch87 after the complete, bounded-process full002 regression."""
from collections import deque
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.verify_information_foreign_technology import pin, read_json as read, write_new as write

STAGE = ROOT / 'work/runtime/information-foreign-forces-20261029-001'
MARKER = 'batch87-foreign-forces-current'


def prepend(path, body):
    raw = path.read_bytes()
    assert len(raw) < 4 * 1024 * 1024
    text = raw.decode('utf-8-sig')
    assert MARKER not in text
    backup = STAGE / 'historical-docs' / path.relative_to(ROOT)
    backup.parent.mkdir(parents=True, exist_ok=True)
    with backup.open('xb') as stream:
        stream.write(raw)
    text = re.sub(r'<!-- batch87-in-progress:start -->.*?<!-- batch87-in-progress:end -->\s*',
                  '', text, count=1, flags=re.S)
    path.write_text(f'<!-- {MARKER}:start -->\n{body}\n<!-- {MARKER}:end -->\n\n' + text,
                    encoding='utf-8', newline='\n')


def main():
    from work.verify_information_foreign_forces_bounded import verify_sources
    frozen = verify_sources()
    comparison = read(STAGE / 'regression-comparison-002.json')
    private = read(STAGE / 'forces-private-live-001/receipt.json')
    mcp = read(STAGE / 'mcp-live-002/offline-reconciliation-001.json')
    audit = read(STAGE / 'independent-live-audit-001.json')
    failed_startup = read(STAGE / 'mcp-live-001/receipt.json')
    delta = read(STAGE / 'private-source-selector-delta-001.json')
    assert comparison['no_new_bad']
    assert private['status'] == mcp['status'] == audit['status'] == delta['status'] == 'passed'
    assert mcp['server_exit_code'] == 0 and mcp['source_pins_unchanged']
    assert mcp['checks']['no_active_subscriptions']
    assert mcp['original_attempt_status'] == 'failed'
    assert pin(ROOT / mcp['original_mcp_receipt']['path']) == mcp['original_mcp_receipt']
    assert failed_startup['status'] == 'failed' and failed_startup['archived_capture_count'] == 0
    assert failed_startup['server_started'] is False
    matrix = read(ROOT / 'docs/信息字段覆盖.json')
    assert matrix['counts']['field_counts'] == {'available': 62, 'partial': 187, 'planned': 148}
    assert matrix['counts']['topic_count'] == 74 and matrix['counts']['field_count'] == 397
    totals = comparison['terminal_totals']
    assert all(type(totals[key]) is int and totals[key] >= 0
               for key in ('passed', 'failed', 'errors', 'subtests'))
    coverage = comparison['collection_coverage']
    assert coverage['status'] == 'complete'
    assert coverage['expected_node_count'] == coverage['executed_node_count']
    assert coverage['missing_node_ids'] == coverage['duplicate_node_ids'] == []
    texttotals = ' / '.join(f'{totals[key]} {key}' for key in ('passed', 'failed', 'errors', 'subtests'))
    short = (
        '## 第87批：外国士兵与船只统计已接入\n\n'
        'F02.visible_army与visible_navy由planned提升为partial，分别提供原生外交士兵统计值与船只数，公共projection_version3。陆军另附record_count，不把记录数当作人数。英国50970人/51记录/30船，勃艮第27224/28/11，奥尔良5052/6/0。军力质量继续planned；实际渲染、缓存新鲜度与完整战场视野尚未证明。见[接口](LINK)。\n\n'
        f'3份metadata研究与3份production private均保存并严格重放；MCP002查询、报告和2秒/5秒周期通过，周期{mcp["periodic_counts"]}，{mcp["archived_capture_count"]}份原始报告按实际来源散列关联，订阅取消、server0。组合查询验证科技、人力、军力三来源。物理POR、非玩家FRA、raw56564448保持，无切国、推进、保存、游戏重启、注入、业务派发、游戏函数调用或Computer Use。\n\n'
        f'分批完整回归002为{texttotals}，Counter141→{comparison["current_bad_occurrences"]}，新增0，整套仍非全绿；{frozen["count"]}份选定来源冻结复核。覆盖62 available/187 partial/148 planned，实际live56/151/190。完整74/397、阶段2/3/4和B01–B04继续，goal active。\n')
    technical = (
        '\n首个full001因测试进程峰值提交内存1063440384B超过1000000000B上限而中止；原partial日志与资源停止收据保留，没有把它当完整结果。full002将同一bridge/tests全集按权威collection nodeids顺序分批、单进程逐批执行，汇合全部JUnit与原86基线Counter比较；不是缩减测试范围。expected/executed nodeids逐项一致，缺项/重复均空。原886来源及snapshots未改，两新增执行/发布源码在freeze002另存快照，总888来源；source-freeze001与未执行的旧publisher仍保留。\n\n'
        '\nB23 SHA b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77，preferred main VA0x140000000，地址均RVA。ef9e70按group virtual+80 AL真累加record+28，AL假才按+88选择计数分支；f0ed60同控件对应DIP_LAND_FORCE/DIP_NAVAL_FORCE及SPY_ARMY_ENTRY/SPY_NAVY_ENTRY。英文提示明确Soldiers/Ships。14bf1e0接收低32(sum*1000) fixed1000编码、precision0；14bee40接收整数count、buffer32、precision2。单位是这条完整原生显示链的解释，未推导旧N02 kind码或每条记录在别处的普遍物理含义，actual_UI_observed=false。\n\n'
        '本批实采vtable1c42540的+80/+88分别8f440(true,b001c3)/8f450(false,32c0c3)，1cca618相反；8B runtime/file相符，按exact3B constant-AL leaf至RET定边界，不捏造pdata或调用getter。unsupported vtable/method仍unknown。count formatter普通001只覆盖primary pdata，002补CHAININFO至14bf05c末RET；stat formatter至14bf352。普通有界GNU objdump、REA与实际RPM分别记录，原001保留。profile33883B/SHAbb5ce60a84235945f8c753979414caebb133f3ff41f323e7b8f9b7dbdaf2b1d6，7 guards/10699B每boundary。\n\n'
        '新leaf局部256KiB/4096 calls/单读16KiB、128nodes/4096records，叠加父512KiB；两字段按依赖保留raw，army低32和与display编码分开，navy按vector长度且不读记录内容。字段与两遍输出必须JSONsafe，deny/unknown不读force resources，共享身份不稳全撤回。初稿研究budget错误包住完整国家扫描，root在实采前按真实5624calls发现并移到field局部；hash scope与known研究状态合同也在首采前修正。\n\n'
        '公开selector曾额外采manpower来取得visibility，已改force请求复用forcecap；explicit manpower仍采，all5仍三来源。原private曾顺手pin publicsource，但不执行其selector；e122→ba309的唯一delta已审查，旧publicsource是byte-exact逆向重建而非前置snapshot，3原报告以相同collector/profile重放，没有为pin重采。原MCP001因legacy technology缺SCHEMA在启动前失败、0capture，原件/前置源码保留；修wrapper并通过无server/无RPC启动检查后运行新MCP002，非游戏重启或历史业务重试。MCP002已完成实际采集，但离线archive校验另一处仍假设同一旧SCHEMA属性，原failed收据保留；独立reconcile只在离线进程按真实legacy合同shim该常量并重放既有报告，没有重采或覆盖producer输入。\n\n'
        '当前v33/PID30548/creation134376782534496994/session30548-1dd66f8c50752e2、DLL/manifest及125 native/build copies保持。旧120/successful/dispatched/unknown、原final-pass IDs和未闭合ownership禁重试；尤其SIE→FRA military_access proposal1、r70_country_money_001_outbound、r71_country_por_to_fra_001、r71_country_fra_to_por_001。旧35天checkpoint不回载。\n\n'
        '用户的“如果”不是已知差异；玩家与非玩家UI或消息路径仍需逐项核实。本批不证明消息存在或缺失。继续完整F02军力质量及其余计划字段、F01完整领土/战争生命周期、G02完整提示/价格/可见性、B04法国新正例与完整阶段2/3/4。原件：work/runtime/information-foreign-forces-20261029-001/。\n')
    docs = ['HANDOFF.md', 'README(agent).md', 'docs/信息导出与订阅开发计划.md',
            'docs/信息计划验收清单.md', 'docs/信息导出开发进展.md']
    for name in docs:
        link = ('docs/' if not name.startswith('docs/') else '') + '外国陆海军统计查询.md'
        prepend(ROOT / name, short.replace('LINK', link) + (technical if name == 'HANDOFF.md' else ''))
    docs += ['docs/外国陆海军统计查询.md', 'docs/外国人力查询.md',
             'docs/外国军事科技与观察方准入.md', 'docs/信息字段覆盖.json']
    for name in docs:
        dest = STAGE / 'doc-mirrors-001' / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        with (ROOT / name).open('rb') as source, dest.open('xb') as target:
            while block := source.read(1024 * 1024):
                target.write(block)
    write(STAGE / 'development-summary-001.json', {
        'batch': 87, 'status': 'partial_fields_extended', 'goal_complete': False,
        'goal_scope': 'all74/397 and complete phases2/3/4 B01-B04',
        'coverage': matrix['counts'], 'actual_live_counts': read(STAGE / 'coverage-update-001.json')['actual_live_counts'],
        'source_count': frozen['count'], 'freeze': pin(STAGE / 'source-freeze-002.json'),
        'regression': dict(pin(STAGE / 'regression-comparison-002.json'), totals=totals),
        'collection_coverage': coverage,
        'full_xml': pin(STAGE / 'bounded-full-002/regression-full-002.xml'),
        'full_log': pin(STAGE / 'bounded-full-002/regression-full-002.log'),
        'incomplete_full_001': pin(STAGE / 'full-harness-preparation-001/full-resource-stop-001.json'),
        'parent_freeze_001': pin(STAGE / 'source-freeze-001.json'),
        'private': pin(STAGE / 'forces-private-live-001/receipt.json'),
        'mcp': pin(STAGE / 'mcp-live-002/offline-reconciliation-001.json'),
        'original_mcp_attempt': pin(STAGE / 'mcp-live-002/receipt.json'),
        'mcp_acceptance_basis': mcp['acceptance_basis'],
        'audit': pin(STAGE / 'independent-live-audit-001.json'),
        'failed_mcp_startup': pin(STAGE / 'mcp-live-001/receipt.json'),
        'private_source_delta': pin(STAGE / 'private-source-selector-delta-001.json'),
        'native_contract': pin(STAGE / 'foreign-force-statistics-source-contract-001.json'),
        'docs': [pin(ROOT / name) for name in docs]})
    files = [pin(path) for path in sorted(STAGE.rglob('*')) if path.is_file()]
    write(STAGE / 'final-evidence-index-001.json',
          {'batch': 87, 'count': len(files), 'files': files, 'status': 'indexed'})
    print({'status': 'published_partial_fields', 'artifacts': len(files), 'goal_complete': False})


if __name__ == '__main__':
    main()
