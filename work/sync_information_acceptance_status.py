"""Replace stale current-status prose using retained, bounded batch evidence."""
from pathlib import Path
import json
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.verify_information_foreign_technology import pin,read_json,write_new

STAGE=ROOT/'work/runtime/information-next-sources-20261029-001'
CURRENT=ROOT/'work/runtime/information-country-person-20261029-001'
BATTLE=ROOT/'work/runtime/information-battle-autonomous-live-20261027-001'
CONTEXT=ROOT/'work/runtime/information-battle-event-context-20261028-001'


def main():
    STAGE.mkdir(exist_ok=True)
    matrix=read_json(ROOT/'docs/信息字段覆盖.json');summary=read_json(CURRENT/'development-summary-001.json')
    assert summary['batch']==78 and summary['goal_complete'] is False
    assert matrix['counts']==summary['coverage']
    assert matrix['counts']['field_counts']=={'available':62,'partial':171,'planned':164}
    for name in ('mcp','independent_raw_audit','postverify'):
        item=summary[name];assert pin(ROOT/item['path'])==item
    mcp=read_json(ROOT/summary['mcp']['path']);post=read_json(ROOT/summary['postverify']['path'])
    assert mcp['status']=='passed' and mcp['server_exit_code']==0 and mcp['source_pins_unchanged']
    assert mcp['checks']['no_active_subscriptions'] and mcp['archived_capture_count']==5
    assert post['status']=='passed_no_new_bad' and post['count']==694
    battle=read_json(BATTLE/'development-summary-001.json')
    report_pin=battle['live']['report'];assert pin(ROOT/report_pin['path'])==report_pin
    battle_report=read_json(ROOT/report_pin['path']);assert battle_report['status']=='passed'
    assert battle['live']['checks']['natural_fra_event_positive'] is True
    context=read_json(CONTEXT/'development-summary-001.json')
    assert context['live']['captured']==13 and context['live']['FRA_participation']==0
    groups=[]
    for group in ('C','N','F','R','M','G','T','D','W','P','A','S','H','B'):
        topics=[t for t in matrix['topics'] if t['topic_id'].startswith(group)]
        counts={key:0 for key in ('available','partial','planned')}
        for topic in topics:
            for field in topic['fields'].values():counts[field['coverage']]+=1
        groups.append((group,len(topics),counts))
    rows='\n'.join(f"| {group} | {n} | {c['available']} | {c['partial']} | {c['planned']} |" for group,n,c in groups)
    text=f'''# 信息计划验收清单

更新至第78批，2026-10-29。完整目标仍为74个主题、397个字段及阶段二、三、四；goal active。本清单描述现有证据能证明的范围，不将部分字段、记录回放或一次实采当作整项计划完成。

当前配置目录为62个 available、171个 partial、164个 planned 字段，45个主题可调用。partial 表示已提供有限内容，仍有明确缺项；available 也只表示该字段声明的范围。完整性与可见范围还需读取具体结果。当前进程与禁止重放规则以 [HANDOFF 顶部](../HANDOFF.md) 为准。

第78批实际服务未启用全部可选来源，其目录为56 available / 135 partial / 206 planned、40个可调用主题；这是该次启动的配置范围，与完整配置目录分开统计。来源见[矩阵](信息字段覆盖.json)、[第78批摘要](../work/runtime/information-country-person-20261029-001/development-summary-001.json)及[实际服务收据](../work/runtime/information-country-person-20261029-001/mcp-live-001/receipt.json)。

## 已证明的链路与未完成的阶段门

| 计划要求 | 当前证据及范围 | 仍需完成 |
| --- | --- | --- |
| 阶段零：目录、对象、结果和来源合同 | 框架及74/397字段覆盖矩阵已有实现；不同来源声明版本、对象、状态与完整性 | 继续为待开发字段确认实际来源；目录登记本身不算可用 |
| 阶段一：自主查询、配置和多周期订阅 | 框架实现持久配置、版本及运行状态；第78批真实MCP查询、报告、2秒两条和5秒一条交付一致，取消后无活动订阅、server0 | 全部目标来源的组合覆盖、跨游戏会话/读档恢复等整体验收仍未闭合 |
| 记录回放与实时读取 | 两种来源在结果中区分；第78批保留5份实际MCP capture及2份private capture，原始读取可重建 | 历史记录不能证明当前世界的新事件、完整UI或LLM已读 |
| 新事件及采集生命周期 | 第64批同一服务自然窗口曾启用来源、捕获并交付FRA参战事件，取消后关闭自有采集；因此不能再把全部新事件链路写成missing | 该证据属于当时v30会话；第74批v33新窗口13场无FRA直接参战，当前版本法国新正例仍未满足 |
| 状态正向变化 | 已有变化检测与状态保存框架；具体实时正例按各来源原件判断 | 不以周期轮询覆盖期间全部变化；跨来源的变化/历史门仍未完整证明 |
| 阶段二：状态与规则信息 | 45主题可调用；S02.faith、S04人物、F02科技等已有部分实时来源；分组统计见下表 | 164个planned字段以及partial字段的剩余内容；不能仅靠unsupported入口完成 |
| 阶段三：逐场事件及通知 | B01–B04现为22个partial、3个planned字段，已有原始采集、解析、持久化、查询和订阅交付 | 完整B04文本/展示条件、B03撤退与歼灭，以及其余要求的请求/关系/修正/任务生命周期即时来源 |
| 阶段四：整体验收与使用说明 | 各已接入来源已有窄范围验收和接口说明；第78批694份选定源码冻结并复核 | 全目录逐项验收、重叠订阅/并发/热更新/重启/读档/失败恢复的完整组合仍未证明 |

第78批完整回归为3722 passed、106 failed、35 errors，另2005个subtests；相对第77批新增失败0、解决0，既有失败/错误仍为141项，整套尚未全绿。证据见[比较结果](../work/runtime/information-country-person-20261029-001/regression-comparison-001.json)和[冻结来源复核](../work/runtime/information-country-person-20261029-001/source-post-run-verification-001.json)。

## 当前字段分组

这张表直接统计当前配置矩阵，不表示组内全部字段已完成实机或完整UI验收。

| 目录前缀 | 主题数 | available | partial | planned |
| --- | ---: | ---: | ---: | ---: |
{rows}

## B01–B04的证据边界

当前B01–B04已有可调用的部分字段，不能继续按第22批旧结论全部写为planned。B03的annihilation、retreat及B04的raw_text仍planned；其余22项为partial，完整战报目标未完成。

第64批[真实服务报告](../work/runtime/information-battle-autonomous-live-20261027-001/live-acceptance-003/report.json)证明当时法国参与事件的自动采集和交付。第74批[摘要](../work/runtime/information-battle-event-context-20261028-001/development-summary-001.json)则记录v33自然窗口13场、FRA直接参战0、同事件上下文13份known。两次运行的会话、载荷和验收范围分别保留，不能互相补造法国新正例。

消息定义、模板、缓存文字、格式化请求和实际控件显示仍分别判断。非玩家是否有某种原生消息或UI差异，须确认具体路径与条件；缺少一条消息或Line1内容不足以证明其普遍缺失。不会切为物理玩家法国来制造验收。

## 后续实施与本次文档修正

继续按原计划接入状态/规则字段，并补完整事件内容与条件。省份状态及外国实力来源的窄盘点进行中；只有确认对象身份、FRA可知范围、单位和具体读取语义后才提升覆盖。不得重放历史成功、已派发、unknown、原final-pass或所有权未闭合动作来验证导出。

本次只更新状态说明，没有重新采样、操作游戏、运行回归或提升任何字段覆盖。第22批旧清单按原始字节保存在[历史副本](../work/runtime/information-next-sources-20261029-001/historical-docs/信息计划验收清单.md)；它属于当时记录，不覆盖本页当前状态。完整输入与修改收据见[文档更新收据](../work/runtime/information-next-sources-20261029-001/acceptance-doc-sync-001.json)。
'''
    paths=('docs/信息计划验收清单.md','docs/信息导出开发进展.md')
    before=[]
    for name in paths:
        path=ROOT/name;before.append(pin(path));target=STAGE/'historical-docs'/path.name
        assert path.stat().st_size<2*1024*1024;target.parent.mkdir(exist_ok=True)
        with target.open('xb') as stream:stream.write(path.read_bytes())
    (ROOT/paths[0]).write_text(text,encoding='utf-8',newline='\n')
    path=ROOT/paths[1];old=path.read_text(encoding='utf-8-sig')
    title='# 信息导出与订阅开发进展\n';assert old.startswith(title)
    current='''
<!-- acceptance-current-78:start -->
## 当前状态：已更新至第78批

完整范围仍为74主题397字段，当前配置62 available / 171 partial / 164 planned、45主题可调用，计划继续。第78批已接入S04统治者、继承人、王朝及人物栏联统显示分支，均partial；此前S02主宗教与F02外国军事科技也已接入。查询、报告及两个周期已通过窄范围实采核对，完整UI和其余字段没有因此完成。

第78批完整回归3722 passed / 106 failed / 35 errors / 2005 subtests，无新增失败，既有141项问题保留。当前进程、身份和禁重试规则见[最新HANDOFF](../HANDOFF.md)，阶段门及B01–B04范围见[更新后的验收清单](信息计划验收清单.md)，字段以[覆盖矩阵](信息字段覆盖.json)为准。下面各批内容保留历史口径，不覆盖本节最新统计。
<!-- acceptance-current-78:end -->

'''
    assert 'acceptance-current-78:start' not in old
    path.write_text(title+current+old[len(title):],encoding='utf-8',newline='\n')
    inputs=[ROOT/'docs/信息字段覆盖.json',CURRENT/'development-summary-001.json',
        CURRENT/'mcp-live-001/receipt.json',CURRENT/'source-post-run-verification-001.json',
        CURRENT/'regression-comparison-001.json',BATTLE/'development-summary-001.json',
        ROOT/report_pin['path'],CONTEXT/'development-summary-001.json']
    write_new(STAGE/'acceptance-doc-sync-001.json',{'status':'updated_from_retained_evidence',
        'goal_complete':False,'inputs':[pin(p) for p in inputs],'before':before,
        'historical_copies':[pin(STAGE/'historical-docs'/Path(n).name) for n in paths],
        'after':[pin(ROOT/n) for n in paths],'builder':pin(Path(__file__).resolve()),
        'new_game_reads':False,'game_controls':False,'new_test_run':False,'coverage_promoted':False})
    print(json.dumps({'status':'updated_from_retained_evidence','documents':2,'goal_complete':False}))


if __name__=='__main__':main()
