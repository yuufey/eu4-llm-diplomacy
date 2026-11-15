"""Publish the verified G02 subset and current, evidence-bounded plan status."""
from collections import deque
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.verify_information_province_state import STAGE,REVISION,read,write,pin,verify_sources


def replace_marker(path,old_marker,new_marker,body):
    old=path.read_text(encoding='utf-8-sig')
    old,count=re.subn(rf'<!-- {old_marker}:start -->.*?<!-- {old_marker}:end -->\s*',
        '',old,count=1,flags=re.S)
    assert count==1 and new_marker not in old
    path.write_text(f'<!-- {new_marker}:start -->\n'+body+f'<!-- {new_marker}:end -->\n\n'+old,
        encoding='utf-8',newline='\n')


def main():
    frozen=verify_sources();comparison=read(STAGE/f'regression-comparison-{REVISION}.json')
    audit=read(STAGE/'independent-live-audit-002.json');mcp=read(STAGE/'mcp-live-001/receipt.json')
    positive=read(STAGE/'private-live-probe-001.json');negative=read(STAGE/'private-discovery-negative-001.json')
    assert comparison['no_new_bad'] and audit['status']==mcp['status']==positive['status']=='passed'
    assert negative['status']=='passed_negative' and mcp['server_exit_code']==0
    assert mcp['archived_capture_count']==15 and mcp['periodic_counts']=={'2':2,'5':1}
    with (STAGE/f'regression-full-{REVISION}.log').open(encoding='utf-8',errors='replace') as stream:
        tail=''.join(deque(stream,maxlen=20))
    totals={key:int(re.search(r'(\d+) '+re.escape(key),tail).group(1))
        for key in ('passed','failed','errors','subtests')}
    result='/'.join(f'{totals[k]} {k}' for k in ('passed','failed','errors','subtests'))
    matrix=read(ROOT/'docs/信息字段覆盖.json');counts=matrix['counts']
    assert counts['field_counts']=={'available':62,'partial':173,'planned':162}
    guide='''# 省份所有者与控制者查询

G02 现支持查询已确认被非玩家法国（FRA）发现的省份，返回当前所有者和控制者的国家标签。物理玩家不必是法国；读取器单独核对FRA角色、完整国家引用及该国的省份发现位。

```json
{
  "topic": "G02",
  "object": {"type": "province", "province_id": 183},
  "fields": ["owner", "controller"],
  "parameters": {}
}
```

| 字段 | value示例 | 含义 |
| --- | --- | --- |
| owner | FRA | 当前原生省份记录中的所有者国家标签 |
| controller | ENG | 当前原生省份记录中的控制者国家标签；与所有者分别读取 |

两字段均为partial、complete=false，单位country_tag、scale=1。对象为单个province，province_id须为1..65535的整数且存在于当前省份数组；不接受国家对象或额外参数。同一查询可放入报告和周期订阅。

每遍先核对FRA的完整国家引用、Human count=1及FRA controller=0，再绑定省份ID与规范记录，检查FRA槽对应的发现位。仅位为1时读取owner/controller引用；位为0或证据不足返回unknown，没有value，也不会读取这两个字段。这里的unknown不等于已经证明该省份不可见；完整原生可见条件仍未闭合。

国家引用还需通过表长度、槽号、指针和country+0x20完整引用回验。无主及未支持的特殊引用保留unknown。两遍共享身份/发现证据变化时撤回两字段；单字段原始数据变化只撤回该字段。两遍读取不等于游戏线程的原子快照。

本批真实采集：183的owner/controller为FRA/FRA，236为ENG/ENG；2000两遍发现位均为0，两字段unknown且轨迹没有字段读取。查询、报告及2秒/5秒周期交付一致，订阅已取消。原始capture与公开结果的关联已独立核对。

这不是完整UI观察，也不证明缓存刷新时点或全部省份可见性。发展度、文化、宗教、自治度、资源和贸易中心六字段仍planned。原生面板的own/foreign背景切换只决定样式，不能据此判断信息权限。本批没有切国、推进时间、保存、重启、注入或执行游戏函数。
'''
    guide_path=ROOT/'docs/省份所有者与控制者查询.md'
    with guide_path.open('x',encoding='utf-8',newline='\n') as stream:stream.write(guide)
    handoff=("## 第79批：按法国发现位接通省份所有者与控制者\n\n"
        "完整74主题397字段、阶段2/3/4和B01–B04继续，goal active；只提升G02.owner/controller为partial，其余六字段仍planned。不是通过注册unsupported缩减目标。详见[接口说明](docs/省份所有者与控制者查询.md)。\n\n"
        "省份绑定由world+1c90/1c98推count、独立world+1ca8取records、id*2e10定位、record+20回等ID。Actor为完整ref绑定的非玩家FRA；Human1/FRA controller0单独验证，不把物理玩家改成FRA。新REA a0acf0的valid-ref分支清province+5e0中该国位，错误文字明确undiscover；本版只支持发现位1正例。位0不读owner(+468)/controller(+470)，保持unknown而不推断invisible；完整UI/cache flags仍未闭合。引用逐字段核DB count/slot/country+20全64位；无主/特殊refs未知。共享身份/准入变化撤回两字段，单字段变化只撤回该字段。\n\n"
        "parent复用原只读owner，inner固定country=FRA只是观察方身份锚，outer对象、observe closure与raw ID读取独立绑定province_id。profile province-state-memory-1374.json为22351B/SHAb65c313ef475af29b1ab3dc2e08286e130239a7eb43fdb6eb74c24c058a1b789，4段main ROM guard。Backend统一read异常类型以稳定错误重放，不比较无关国家行变化。primitive14/backend22/capture26/public51项最后定向通过；各早期fixture/标签/断言错误原件保留。\n\n"
        "实际v33/PID30548/creation134376782534496994/session30548-1dd66f8c50752e2，EXE B23（b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77）、物理POR、FRA AI、raw56564448。183 FRA/FRA与236 ENG/ENG两正例、2000两遍发现位0/字段unknown/无字段读负例，均raw replay通过。真实MCP主动/报告/2秒2次/5秒1次覆盖3对象，15份实际capture归档；18份总raw replay与21组公开fields独立审计通过，2条manual列表副本不另算采集；订阅取消、server0。probe计数错取read_calls导致null的原件保留，offline access readback核calls=5614/bytes58378，未重采。\n\n"
        "普通PE与REA继续分开：provinceview ctor13430d0/vtable1d79138、selected pointer writer1347920、slot48/50为1346f90/13467a0；own/foreign背景不是权限。a0cff0旧pseudo的首参0经原始指令确认实际保留入口RCX；a28190的REA因移除不可达块而只剩false，不能用作真实predicate，434B普通反汇编与74c1c0上下文保留。发展度分量/完整显示条件继续研究，不以静态定位当公开能力。所有RVA/范围/旧证据与限制见native-province-findings-002.json及后续可见性研究原件。\n\n"
        f"{frozen['count']}份选定来源pre-full冻结并复核；唯一full为{result}，Counter141→{comparison['current_bad_occurrences']}、新增0/解决0，整套仍非全绿。覆盖74/397、62 available/173 partial/162 planned、46 callable；本次实际live56/137/204、41callable单独统计。验收清单/开发进展的过期22/53批当前结论已按原件修正，历史原字节保留。\n\n"
        "没有保存/重启/注入/推进/切国/外交业务/Computer Use或游戏函数调用。125 native/build copies/DLL未变；模块/patch/unwind仍至进程退出。旧35天checkpoint不回载重播，历史120/successful/dispatched/unknown/final-pass/未闭合ownership禁重试，尤其SIE→FRA military_access proposal1、r70_country_money_001_outbound、r71_country_por_to_fra_001及r71_country_fra_to_por_001。继续其余G02、F01、完整B04和法国新正例。摘要与index位于work/runtime/information-next-sources-20261029-001/。\n")
    for name in ('HANDOFF.md','README(agent).md','docs/信息导出与订阅开发计划.md'):
        short=("## 第79批：省份所有者与控制者已接入\n\n"
            "G02.owner/controller均partial，只对已确认FRA发现位1的省份读取；位0返回unknown且不读字段，不称invisible。183实采FRA/FRA、236 ENG/ENG、2000未知负例通过。物理POR、LLM非玩家FRA不变；不是以背景样式或选中pointer存储判断权限。见[接口说明]("+
            ('docs/' if name=='README(agent).md' else '')+"省份所有者与控制者查询.md)。\n\n"
            "主动/报告及两个周期覆盖3对象，15实际capture归档、18份raw重放及21组公开fields独立审计通过；取消订阅/server0。无保存/重启/注入/推进/切国/外交动作或Computer Use。\n\n"+
            f"唯一full为{result}，无新增失败，既有141项问题保留；{frozen['count']}来源已冻结复核。覆盖74/397、62 available/173 partial/162 planned、46callable。其余G02及完整阶段2/3/4和B01–B04继续，goal active；身份/原件/禁重放规则见HANDOFF顶部。\n")
        replace_marker(ROOT/name,'batch79-province-in-progress','batch79-province-current',handoff if name=='HANDOFF.md' else short)
    old_acceptance=ROOT/'docs/信息计划验收清单.md'
    snapshot=STAGE/'historical-docs/信息计划验收清单-78.md'
    with snapshot.open('xb') as stream:stream.write(old_acceptance.read_bytes())
    groups=[]
    for prefix in ('C','N','F','R','M','G','T','D','W','P','A','S','H','B'):
        topics=[t for t in matrix['topics'] if t['topic_id'].startswith(prefix)]
        cc={key:0 for key in ('available','partial','planned')}
        for topic in topics:
            for field in topic['fields'].values():cc[field['coverage']]+=1
        groups.append(f"| {prefix} | {len(topics)} | {cc['available']} | {cc['partial']} | {cc['planned']} |")
    acceptance='''# 信息计划验收清单

更新至第79批，2026-10-29。完整74主题397字段、阶段二/三/四与B01–B04目标继续，goal active。当前配置62 available / 173 partial / 162 planned、46主题可调用；partial不是完整交付。具体字段条件以[矩阵](信息字段覆盖.json)和结果为准。

本次实际服务目录为56 available / 137 partial / 204 planned、41主题可调用，因未开启全部可选来源，与完整配置分别统计。当前身份及禁止重放规则见[HANDOFF](../HANDOFF.md)。

| 阶段或要求 | 现有证据范围 | 未完成内容 |
| --- | --- | --- |
| 阶段零：公共合同和来源目录 | 统一模型及74/397字段记录已有实现 | 逐项补真实来源；登记名称不等于可调用 |
| 阶段一：自主查询、配置和订阅 | 框架已有持久配置、版本及调度；79批真实查询、报告、2秒/5秒交付和取消通过 | 全部来源组合、跨游戏会话/读档恢复等整体验收未闭合 |
| 状态读取 | 当前部分来源有实采、原始数据和投影核对；79批含已知省份与未知省份短路 | 剩余162 planned及partial字段缺项；原始缓存不等于完整UI或原子快照 |
| 变化和新事件 | 64批同一服务曾自然捕获并交付FRA参战事件，取消后关闭自有采集 | 当时v30证据不补证v33法国新正例；变化检测不能冒称捕获每次变化 |
| 阶段二：状态与规则 | 46主题部分可调用；G02新增owner/controller，六个其它G02字段仍planned | 全目录及partial缺项，特别外国实力、领土、规则和推算来源 |
| 阶段三：即时事件 | B01–B04已有22 partial / 3 planned字段，含采集、解析、持久化和订阅路径 | B04完整文本、B03撤退/歼灭，以及请求、关系、修正、任务生命周期等缺口 |
| 阶段四：整体核对 | 已接入来源有窄范围交叉核对、说明及回归 | 全目录逐项完成、并发/重叠订阅/热更新/重启/读档/失败恢复的完整组合未证明 |

## 当前配置分组

| 前缀 | 主题数 | available | partial | planned |
| --- | ---: | ---: | ---: | ---: |
'''+ '\n'.join(groups)+f'''

第79批完整回归为{result}，新增失败0、解决0，既有141项失败/错误仍在，整套尚未全绿；{frozen['count']}份选定源码已冻结复核。见[比较结果](../work/runtime/information-next-sources-20261029-001/regression-comparison-001.json)及[来源复核](../work/runtime/information-next-sources-20261029-001/source-post-run-verification-001.json)。

## 本批真实范围

省份183为FRA/FRA、236为ENG/ENG；2000发现位0，字段unknown且没有读取owner/controller。3份private与15份实际MCP capture均有原始读取重放，公开查询/报告/两个周期的21组fields关联通过，2条manual列表副本不算额外采集。位0的unknown不推断invisible，完整可见条件、特殊/无主引用、缓存刷新和其它六字段继续开发。见[接口](省份所有者与控制者查询.md)及[独立审计](../work/runtime/information-next-sources-20261029-001/independent-live-audit-002.json)。

## 战报和历史范围

[64批报告](../work/runtime/information-battle-autonomous-live-20261027-001/live-acceptance-003/report.json)证明当时法国事件的自动采集与交付；[74批摘要](../work/runtime/information-battle-event-context-20261028-001/development-summary-001.json)记录v33新窗口13场、法国直接参战0。两次会话及载荷分别解释，完整UI/法国新正例未完成。B03 annihilation、retreat及B04 raw_text仍planned；缺一条消息或Line1内容不够，不能证明非玩家普遍没有消息。

此前过期的22批清单及78批更新都保留[历史副本](../work/runtime/information-next-sources-20261029-001/historical-docs/信息计划验收清单-78.md)。来源、日期、身份和完整性不得跨记录补造；只读查询也不授予外交执行权限。继续原计划，不重放历史成功/已派发/unknown/final-pass/未闭合所有权动作，不把LLM已收到结果说成已经阅读或决策。
'''
    old_acceptance.write_text(acceptance,encoding='utf-8',newline='\n')
    progress=ROOT/'docs/信息导出开发进展.md';old=progress.read_text(encoding='utf-8-sig')
    block=(f"<!-- acceptance-current-79:start -->\n## 当前状态：已更新至第79批\n\n"
        "完整74主题397字段继续，当前配置62 available / 173 partial / 162 planned、46主题可调用。G02 owner/controller已接入按FRA发现位的只读查询、报告和周期；发现位0返回unknown且不读字段，其余六项仍planned。\n\n"+
        f"完整回归{result}，无新增失败，既有141项问题保留。说明见[省份接口](省份所有者与控制者查询.md)，阶段范围见[验收清单](信息计划验收清单.md)，最新身份与禁重放见[HANDOFF](../HANDOFF.md)。下面各批保留历史口径，不覆盖本节。\n<!-- acceptance-current-79:end -->")
    old,n=re.subn(r'<!-- acceptance-current-78:start -->.*?<!-- acceptance-current-78:end -->',block,old,count=1,flags=re.S)
    assert n==1;progress.write_text(old,encoding='utf-8',newline='\n')
    docs=['HANDOFF.md','README(agent).md','docs/信息导出与订阅开发计划.md','docs/省份所有者与控制者查询.md',
        'docs/信息计划验收清单.md','docs/信息导出开发进展.md','docs/信息字段覆盖.json']
    for name in docs:
        destination=STAGE/'doc-mirrors-001'/name;destination.parent.mkdir(parents=True,exist_ok=True)
        with (ROOT/name).open('rb') as source,destination.open('xb') as target:
            while chunk:=source.read(1024*1024):target.write(chunk)
    write(STAGE/'development-summary-001.json',{'schema':'information.province_state.development_summary.v1',
        'batch':79,'status':'partial_feature_verified','goal_complete':False,
        'goal_scope':'74 topics /397 fields; complete stages2/3/4 and B01-B04 remain active',
        'coverage':counts,'actual_live_counts':read(STAGE/'coverage-update-001.json')['actual_live_counts'],
        'freeze':pin(STAGE/f'source-freeze-{REVISION}.json'),'source_count':frozen['count'],
        'postverify':pin(STAGE/f'source-post-run-verification-{REVISION}.json'),
        'regression':dict(pin(STAGE/f'regression-comparison-{REVISION}.json'),totals=totals),
        'profile':pin(ROOT/'bridge/information/profiles/province-state-memory-1374.json'),
        'positive':pin(STAGE/'private-live-probe-001.json'),'negative':pin(STAGE/'private-discovery-negative-001.json'),
        'mcp':pin(STAGE/'mcp-live-001/receipt.json'),'independent_raw_audit':pin(STAGE/'independent-live-audit-002.json'),
        'actual_UI_observed':False,'full_visibility_proved':False,'docs':[pin(ROOT/name) for name in docs]})
    rows=[pin(path) for path in STAGE.rglob('*') if path.is_file()
        and not any(part.startswith('source-snapshots-') or part=='__pycache__' for part in path.parts)
        and path.name!='final-evidence-index-001.json']
    write(STAGE/'final-evidence-index-001.json',{'schema':'information.province_state.selected_evidence_index.v1',
        'scope':'Selected stage artifacts including failed attempts, historical docs and 7 current doc mirrors; excludes source snapshots/cache/index itself',
        'count':len(rows),'files':sorted(rows,key=lambda x:x['path'])})
    verify_sources();print({'status':'published_partial','sources':frozen['count'],'artifacts':len(rows),'totals':totals})


if __name__=='__main__':main()
