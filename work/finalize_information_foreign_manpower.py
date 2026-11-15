"""Publish the verified F02 manpower increment and retain the complete goal."""
from collections import deque
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.verify_information_foreign_technology import pin, read_json as read, write_new as write

STAGE = ROOT / 'work/runtime/information-foreign-military-resources-20261029-001'
MARKER = 'batch86-foreign-manpower-current'


def prepend(path, body):
    raw = path.read_bytes()
    assert len(raw) < 4 * 1024 * 1024
    text = raw.decode('utf-8-sig')
    assert MARKER not in text
    dest = STAGE / 'historical-docs' / path.relative_to(ROOT)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open('xb') as stream:
        stream.write(raw)
    text = re.sub(r'<!-- batch86-in-progress:start -->.*?<!-- batch86-in-progress:end -->\s*',
                  '', text, count=1, flags=re.S)
    path.write_text(f'<!-- {MARKER}:start -->\n{body}\n<!-- {MARKER}:end -->\n\n' + text,
                    encoding='utf-8', newline='\n')


def main():
    from work.verify_information_foreign_manpower import verify_sources
    frozen = verify_sources()
    comparison = read(STAGE / 'regression-comparison-001.json')
    private = read(STAGE / 'manpower-private-live-001/receipt.json')
    mcp = read(STAGE / 'mcp-live-001/offline-reconciliation-001.json')
    audit = read(STAGE / 'independent-live-audit-001.json')
    assert comparison['no_new_bad']
    assert private['status'] == mcp['status'] == audit['status'] == 'passed'
    assert mcp['server_exit_code'] == 0 and mcp['source_pins_unchanged']
    assert mcp['checks']['no_active_subscriptions'] and all(value is True for value in mcp['checks'].values())
    assert mcp['original_attempt_status'] == 'failed'
    assert pin(ROOT / mcp['original_mcp_receipt']['path']) == mcp['original_mcp_receipt']
    matrix = read(ROOT / 'docs/信息字段覆盖.json')
    assert matrix['counts']['field_counts'] == {'available': 62, 'partial': 185, 'planned': 150}
    assert matrix['counts']['topic_count'] == 74 and matrix['counts']['field_count'] == 397
    with (STAGE / 'regression-full-001.log').open(encoding='utf-8', errors='replace') as stream:
        tail = ''.join(deque(stream, maxlen=20))
    totals = {key: int(re.search(r'(\d+) ' + key, tail).group(1))
              for key in ('passed', 'failed', 'errors', 'subtests')}
    texttotals = ' / '.join(f'{totals[key]} {key}' for key in ('passed', 'failed', 'errors', 'subtests'))
    short = (
        '## 第86批：外国人力与其独立准入条件已接入\n\n'
        'F02.manpower由planned提升为partial，提供储备原值、三项原生贡献和合计。visibility分别报告国家查看条件与人力军事统计条件，公共projection_version2。英国2239、勃艮第20395、奥尔良20623；当前三项贡献计数均0，准入走public_options。组件类别、物理人数单位及最终UI文字尚未全部确认，单位保留native_manpower_statistic/scale1。见[接口](LINK)。\n\n'
        f'三份私有实采及公开采集已保存并严格重放；查询、报告和2秒/5秒周期交付通过，实际周期{mcp["periodic_counts"]}，订阅已取消、server0。物理POR、非玩家FRA、raw56564448保持。没有切国、推进、保存、重启、注入、业务派发、游戏函数调用或Computer Use。\n\n'
        f'唯一full为{texttotals}，Counter141→{comparison["current_bad_occurrences"]}，新增0，整套仍非全绿；{frozen["count"]}份选定来源冻结并复核。覆盖62 available/185 partial/150 planned。完整74/397、阶段2/3/4和B01–B04继续，goal active。\n')
    technical = (
        '\nB23 SHA b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77，preferred main VA0x140000000，函数地址均RVA。新REA ef9e70确认selected ref+138、observer ref+148及manpower/两类部队控件共同条件；378ff0按目标+238链表首个观察方槽匹配及now<expiry判断，读取器另加完整引用相等守卫。未确认记录业务名称，不猜联盟/间谍语义。34dda0读三项u16计数及条件定义+54，caller加db8储备，均保留low32算术。ae8fe0有float32格式化路径，未执行或模拟。2892d0是国家名称选择，不是人力数值getter；f0bc30是外交动作列表更新，均保留排除记录。\n\n'
        '普通PE/Capstone与REA证据、实际RPM分开。378ff0范围378ff0..379051、34dda0范围34dda0..34de07没有pdata，按有界可达CFG至末RET确定，未补造展开记录。profile31119B/SHA6911d974130d0f83a64ae041a5521038ef93b1128a95cc05a4f9c2dee7f608da，5 guards/11402B每boundary。保留首个无pdata构建失败；普通seed002第三项实为unwind RVA的更正已记录。\n\n'
        '父层继续真实完整国家扫描、FRA AI控制器核对、同一只读handle和有序trace；人力permission留在依赖字段内，不能扩大科技准入到其它军力字段。审查发现permission两层接口不匹配，会拒绝真实schema；已在实采前修正并通过直接串联测试；共享变化仍全撤回。公开值白名单过滤私有地址。非零贡献分支当前只有离线测试；缓存新鲜度、原子性和实际UI显示未证明。军队/海军两个虚表predicate的分类、单位与外国军力质量继续。\n\n'
        '当前v33/PID30548/creation134376782534496994/session30548-1dd66f8c50752e2、DLL/manifest与125 native/build copies保持。原120/successful/dispatched/unknown、原final-pass IDs及未闭合ownership禁止重试；尤其SIE→FRA military_access proposal1、r70_country_money_001_outbound、r71_country_por_to_fra_001、r71_country_fra_to_por_001；旧35天checkpoint不回载。\n\n'
        '用户的“如果”不是已知差异。玩家/非玩家UI与消息路径需逐项核实，不能从缺少记录推断功能不存在。继续全部F02及其它计划字段、F01完整领土/战争生命周期、G02完整提示/价格/可见性与B04法国新正例。原件：work/runtime/information-foreign-military-resources-20261029-001/。\n')
    docs = ['HANDOFF.md', 'README(agent).md', 'docs/信息导出与订阅开发计划.md',
            'docs/信息计划验收清单.md', 'docs/信息导出开发进展.md']
    for name in docs:
        link = ('docs/' if not name.startswith('docs/') else '') + '外国人力查询.md'
        prepend(ROOT / name, short.replace('LINK', link) + (technical if name == 'HANDOFF.md' else ''))
    docs += ['docs/外国人力查询.md', 'docs/外国军事科技与观察方准入.md', 'docs/信息字段覆盖.json']
    for name in docs:
        target = STAGE / 'doc-mirrors-001' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with (ROOT / name).open('rb') as source, target.open('xb') as dest:
            while block := source.read(1024 * 1024):
                dest.write(block)
    write(STAGE / 'development-summary-001.json', {
        'batch': 86, 'status': 'partial_field_extended', 'goal_complete': False,
        'goal_scope': 'all74/397 and complete phases2/3/4 B01-B04', 'coverage': matrix['counts'],
        'actual_live_counts': read(STAGE / 'coverage-update-001.json')['actual_live_counts'],
        'source_count': frozen['count'], 'freeze': pin(STAGE / 'source-freeze-001.json'),
        'regression': dict(pin(STAGE / 'regression-comparison-001.json'), totals=totals),
        'private': pin(STAGE / 'manpower-private-live-001/receipt.json'),
        'mcp': pin(STAGE / 'mcp-live-001/offline-reconciliation-001.json'),
        'original_mcp_attempt': pin(STAGE / 'mcp-live-001/receipt.json'),
        'mcp_acceptance_basis': mcp['acceptance_basis'], 'retained_mcp_error': mcp['original_error'],
        'audit': pin(STAGE / 'independent-live-audit-001.json'),
        'native_contract': pin(STAGE / 'foreign-military-source-contract-001.json'),
        'docs': [pin(ROOT / name) for name in docs]})
    files = [pin(path) for path in sorted(STAGE.rglob('*')) if path.is_file()]
    write(STAGE / 'final-evidence-index-001.json',
          {'batch': 86, 'count': len(files), 'files': files, 'status': 'indexed'})
    print({'status': 'published_partial_field', 'artifacts': len(files), 'goal_complete': False})


if __name__ == '__main__':
    main()
