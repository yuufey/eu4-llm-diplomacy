"""Publish the verified batch-78 result without changing its source freeze."""
from collections import deque
import json
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.verify_information_country_person import STAGE,read,write,pin,verify_sources,REVISION


def main():
    frozen=verify_sources();regression=read(STAGE/f'regression-comparison-{REVISION}.json')
    audit=read(STAGE/'independent-live-audit-005.json')
    review=read(STAGE/'person-plugin-integration-review-001.json')
    mcp=read(STAGE/'mcp-live-001/receipt.json');probe=read(STAGE/'private-live-probe-003.json')
    assert regression['no_new_bad'] is True and audit['status']==review['status']=='passed'
    assert mcp['status']==probe['status']=='passed' and mcp['server_exit_code']==0
    with (STAGE/f'regression-full-{REVISION}.log').open(encoding='utf-8',errors='replace') as stream:
        tail=''.join(deque(stream,maxlen=20))
    totals={key:int(re.search(r'(\d+) '+re.escape(key),tail).group(1))
        for key in ('passed','failed','errors','subtests')}
    matrix=read(ROOT/'docs/信息字段覆盖.json');counts=matrix['counts'];fc=counts['field_counts']
    fraction=f"{fc['available']} available/{fc['partial']} partial/{fc['planned']} planned"
    result=f"{totals['passed']} passed/{totals['failed']} failed/{totals['errors']} errors/{totals['subtests']} subtests"
    assert mcp['archived_capture_count']==5 and mcp['periodic_counts']=={'2':2,'5':1}
    for tag,ruler,heir,ra,ha in (('ENG','爱德华 IV 约克','亨利 都铎',40,27),('FRA','路易 XI 德 瓦卢瓦','路易 德 瓦卢瓦',33,9)):
        values=probe['values'][tag]
        assert values['S04.ruler']['name']['value']['text']==ruler and values['S04.ruler']['age']['value']==ra
        assert values['S04.heir']['name']['value']['text']==heir and values['S04.heir']['age']['value']==ha
    profile=ROOT/'bridge/information/profiles/country-person-memory-1374-v3.json'
    guide='''# 统治者与继承信息查询

S04 现支持查询单个国家的统治者、继承人、王朝名称和人物栏使用的联统显示分支。逻辑观察方是非玩家法国（FRA）；目标可为法国本国或获准查看的其他国家。读取器分别确认观察方与目标，不要求游戏的物理玩家等于法国。

```json
{
  "topic": "S04",
  "object": {"type": "country", "country": "ENG"},
  "fields": ["ruler", "heir", "dynasty", "personal_union"],
  "parameters": {}
}
```

同一查询可用于报告和周期订阅。四个字段均为部分实现（partial），结果的 complete 为 false。当前不支持该来源的 country_pair 查询；succession_dispute 仍未实现。

| 字段 | 已读取或计算的内容 | 含义限制 |
| --- | --- | --- |
| ruler | 姓名组件、行政/外交/军事能力、年龄和人物栏显示方式 | 摄政姓名、完整头衔及完整提示尚未实现 |
| heir | 人物栏是否显示、原生 NO_HEIR 分支、姓名组件、年龄及当前继承权强度 | 栏被隐藏不表示没有继承人；不预测未来继承结果 |
| dynasty | 统治者与继承人姓名所用的王朝名称组件 | 不提供稳定王朝 ID，也不等于完整王朝关系 |
| personal_union | 人物栏是否使用上级国家统治者分支及相应国家 | 不提供完整联统成员名单 |

每个姓名、年龄或强度组件都有自己的状态。已知组件保留 value；不能确认的组件为 unknown，并给出原因。姓名保留严格解码后的 text、EU4 escape 原始编码 raw_hex 和 encoding。地址、完整内存轨迹及内部插件信息留在私有采集文件，不进入公共字段值。

姓名读取会核对原版指令，或当前指定 plugin64.dll 的跳转、代码范围及回调/返回指针。已确认的插件规则按王朝前缀决定姓名组件的顺序；未识别的改写使姓名返回 unknown。插件路径超过254字节的组合暂不支持。这里计算的是已确认函数路径的结果，没有调用游戏姓名函数或观察实际控件。

年龄按已确认的365日日历及生日计算；统治者提示的未知生日条件单独保留。年龄算法已在独立进程中用1049个输入与未改写的原始代码及另一套日历计算核对；这不属于在游戏中调用函数。继承权强度保留 raw、scale=1000、运行时弱/强阈值及分类，分类遵循原函数的比较顺序。

本批正式只读采集确认英国统治者“爱德华 IV 约克”、40岁，继承人“亨利 都铎”、27岁；法国统治者“路易 XI 德 瓦卢瓦”、33岁，继承人“路易 德 瓦卢瓦”、9岁。这些是当前缓存与固定路径的投影，不代表完整 UI 已验收。主动查询、报告及2秒/5秒两个周期的交付已核对，订阅已取消。

本批没有切国、推进时间、保存、重启、注入或外交派发。前次因原版指令不符而拒绝的采集及旧 profile 均保留；新 profile 明确识别实际插件，不通过忽略修改字节来放行。
'''
    guide_path=ROOT/'docs/统治者与继承信息查询.md'
    with guide_path.open('x',encoding='utf-8',newline='\n') as stream:stream.write(guide)
    detailed=("## 第78批：先确认实际姓名插件，人物与继承查询已接入\n\n"
        "完整74主题397字段、阶段2/3/4及B01–B04继续，goal active。玩家/非玩家UI差异仍须逐项证实；本批发现的是当前已加载插件的姓名函数改写，不能泛称非玩家没有UI。LLM逻辑观察及控制方保持非玩家FRA，当前物理玩家POR。\n\n"
        "S04 ruler/heir/dynasty/personal_union四字段planned→partial，succession_dispute仍planned，只接country对象。统治者姓名/能力/年龄、继承人人物栏/NO_HEIR/姓名/年龄/当前claim及王朝组件独立报告；heir_panel true才显示人物栏，false隐藏不等于无继承人；NO_HEIR仅由人物vtable58的已确认constfalse分支得到。联统只实现人物栏使用上级统治者的条件，不是完整名单或继承预测。见[接口说明](docs/统治者与继承信息查询.md)。\n\n"
        "profile-v1及private-live-eng/fra-001原ROM拒绝件保留。实际EXE a4b2fc..a4b30a的14B跳到plugin64.dll+3dd84；新v3核原版或明确插件变体，按各自ASLR计算模块基址，逐读header/代码guard和slots+0=main+a4b316、slots+8=plugin+38410。磁盘DLL为538112B/SHAa73a8b6c82e620fc7d577bdb64df731b779a72bb43c2363a11ed12be23a9d819。callback的right为空格+dynasty；len(right)>=3且right[1]==BF时取dynasty[1:]+base，否则base+空格+dynasty，插件组合限254B。原版指令两侧继续完整校验，14B窗口也被单独正向核验，没有盲目mask。v2实采仍因header ImageBase返回姓名unknown，原件保留；v3要求该8B精确等于jump派生的实际模块基址，其余1016B逐字节一致。普通PE推断、实际RPM、REA及owned复制执行分别留账，未观察完整UI。\n\n"
        "年龄owned-age-verified-001由root实际执行：1049/1049三方匹配、child23612 exit0/VirtualFree true；ruler未知生日阈值单独保留。此前worker的533/PID46444及无原产物SHA已撤回，不得引用/补造。a559c0无REA procedure的失败件保留，claim getter仅有普通精确12B证据。\n\n"
        "正式private003两目标及MCP主动/报告/2秒2条与5秒1条均通过，5份MCP原始capture逐一归档，订阅取消、server0，独立审计核全部raw trace重放与交付关联。ENG“爱德华 IV 约克”40/“亨利 都铎”27；FRA“路易 XI 德 瓦卢瓦”33/“路易 德 瓦卢瓦”9。当前v33/PID30548/creation134376782534496994/session30548-1dd66f8c50752e2、EXE B23、125 native/build copies/DLL保持；各实采Human1/FRA controller0、物理POR、raw56564448。没有游戏保存/重启/注入/推进/切国/外交业务/Computer Use。\n\n"
        f"选定{frozen['count']}来源在唯一full前冻结并复核。full为{result}；既有Counter141→{regression['current_bad_occurrences']}，新增{len(regression['new_bad'])}、解决{len(regression['resolved_bad'])}，整套仍非全绿。覆盖74/397、{fraction}、{counts['callable_topic_count']} callable。所有失败尝试和独立review见本stage摘要/index；不为通过检查补造历史文件或跳过旧失败。\n\n"
        "下一步继续其余计划字段、完整B04及法国新正例；不回载35天旧checkpoint、不重跑历史120或successful/dispatched/unknown/final-pass/未闭合ownership，尤其SIE→FRA military_access proposal1、r70_country_money_001_outbound、r71_country_por_to_fra_001及r71_country_fra_to_por_001。当前模块/patch/unwind保留到进程退出。完整原件work/runtime/information-country-person-20261029-001/development-summary-001.json及final-evidence-index-001.json。\n")
    marker='batch78-country-person-current';old_marker='batch78-country-person-in-progress'
    for name in ('HANDOFF.md','README(agent).md','docs/信息导出与订阅开发计划.md'):
        path=ROOT/name;previous=path.read_text(encoding='utf-8-sig')
        pattern=rf'<!-- {old_marker}:start -->.*?<!-- {old_marker}:end -->\s*'
        previous,count=re.subn(pattern,'',previous,count=1,flags=re.S)
        assert count==1 and marker not in previous
        body=detailed if name=='HANDOFF.md' else (
            "## 第78批：统治者与继承四字段已接入\n\n"
            "先确认实际路径，再决定非玩家是否需要其它方案。当前姓名函数有已加载plugin64.dll改写；新读取器正向核验原版或指定插件的代码/回调/返回地址，没有据此推断非玩家普遍缺少UI。S04 ruler/heir/dynasty/personal_union均partial，只接country；完整标签、摄政、联统名单及succession_dispute仍未完成。见[接口说明]("+
            ('docs/' if name=='README(agent).md' else '')+"统治者与继承信息查询.md)。\n\n"
            "保持物理POR、LLM非玩家FRA、raw56564448。英国及法国的private003与真实MCP主动/报告/两个周期通过，5份原始MCP capture留存、订阅取消、server0；无切国/时间推进/保存/重启/注入/业务派发或Computer Use。1049案例独立年龄夹具是真实owned执行；先前无原件的533案例说法已撤回。\n\n"+
            f"唯一full为{result}，无新增失败，整套仍非全绿；{frozen['count']}来源pre-full冻结并复核。覆盖74/397、{fraction}、{counts['callable_topic_count']} callable。完整阶段2/3/4、B01–B04和法国新战报正例继续，goal active。身份、边界、失败原件及禁重试规则见HANDOFF顶部。\n")
        path.write_text(f'<!-- {marker}:start -->\n'+body+f'<!-- {marker}:end -->\n\n'+previous,
            encoding='utf-8',newline='\n')
    docs=['HANDOFF.md','README(agent).md','docs/信息导出与订阅开发计划.md',
        'docs/统治者与继承信息查询.md','docs/信息字段覆盖.json']
    for name in docs:
        target=STAGE/'doc-mirrors-001'/name;target.parent.mkdir(parents=True,exist_ok=True)
        with (ROOT/name).open('rb') as source,target.open('xb') as destination:
            while block:=source.read(1024*1024):destination.write(block)
    summary={'schema':'information.country_person.development_summary.v1','batch':78,'status':'partial_feature_verified',
        'goal_complete':False,'goal_scope':'74 topics /397 fields; complete stages2/3/4 and B01-B04 remain active',
        'coverage':counts,'actual_live_counts':read(STAGE/'coverage-update-001.json')['actual_live_counts'],
        'regression':dict(pin(STAGE/f'regression-comparison-{REVISION}.json'),totals=totals),
        'freeze':pin(STAGE/f'source-freeze-{REVISION}.json'),'source_count':frozen['count'],
        'postverify':pin(STAGE/f'source-post-run-verification-{REVISION}.json'),
        'profile':pin(profile),'private_probe':pin(STAGE/'private-live-probe-003.json'),
        'mcp':pin(STAGE/'mcp-live-001/receipt.json'),'independent_raw_audit':pin(STAGE/'independent-live-audit-005.json'),
        'plugin_review':pin(STAGE/'person-plugin-integration-review-001.json'),
        'owned_age':pin(STAGE/'owned-age-verified-001/receipt.json'),
        'unsupported_worker_execution_claim_withdrawn':True,'actual_UI_observed':False,
        'docs':[pin(ROOT/name) for name in docs]}
    write(STAGE/'development-summary-001.json',summary)
    rows=[]
    for path in STAGE.rglob('*'):
        if (path.is_file() and not any(part.startswith('source-snapshots-') for part in path.parts)
            and '__pycache__' not in path.parts and path.name!='final-evidence-index-001.json'):
            rows.append(pin(path))
    write(STAGE/'final-evidence-index-001.json',{'schema':'information.country_person.selected_evidence_index.v1',
        'scope':'Selected stage artifacts and 5 doc mirrors; excludes source snapshots, cache and index itself',
        'count':len(rows),'files':sorted(rows,key=lambda x:x['path'])})
    verify_sources();print(json.dumps({'status':'published_partial','source_count':frozen['count'],
        'evidence_count':len(rows),'totals':totals},ensure_ascii=False))


if __name__=='__main__':main()
