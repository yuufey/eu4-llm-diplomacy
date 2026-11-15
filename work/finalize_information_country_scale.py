"""Publish batch 82 only after raw replay, real delivery and regression checks."""
from collections import deque
from pathlib import Path
import json
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.verify_information_foreign_technology import pin,read_json,write_new

STAGE=ROOT/'work/runtime/information-foreign-scale-20261029-001'
MARKER='batch82-country-scale-current'


def prepend(path,body):
    raw=path.read_bytes();assert len(raw)<4*1024*1024
    text=raw.decode('utf-8-sig');assert MARKER not in text
    backup=STAGE/'historical-docs'/path.relative_to(ROOT);backup.parent.mkdir(parents=True,exist_ok=True)
    with backup.open('xb') as stream:stream.write(raw)
    path.write_text(f'<!-- {MARKER}:start -->\n{body}\n<!-- {MARKER}:end -->\n\n'+text,
                    encoding='utf-8',newline='\n')


def main():
    from work.verify_information_country_scale import verify_sources
    frozen=verify_sources()
    audit=read_json(STAGE/'independent-live-audit-005.json')
    mcp=read_json(STAGE/'mcp-live-001/receipt.json')
    comparison=read_json(STAGE/'regression-comparison-001.json')
    sample=read_json(STAGE/'private-live-probe-001.json')
    assert audit['status']==mcp['status']==sample['status']=='passed'
    assert comparison['no_new_bad'] is True
    assert mcp['server_exit_code']==0 and mcp['checks']['no_active_subscriptions']
    assert mcp['archived_capture_count']==3*(2+sum(mcp['periodic_counts'].values()))
    matrix=read_json(ROOT/'docs/信息字段覆盖.json')
    counts=matrix['counts'];assert counts['field_counts']=={'available':62,'partial':182,'planned':153}
    with (STAGE/'regression-full-001.log').open(encoding='utf-8',errors='replace') as stream:
        tail=''.join(deque(stream,maxlen=20))
    totals={name:int(re.search(r'(\d+) '+name,tail).group(1)) for name in ('passed','failed','errors','subtests')}
    totaltext=' / '.join(f'{totals[key]} {key}' for key in ('passed','failed','errors','subtests'))
    rawcount=3+mcp['archived_capture_count']
    short=(
        '## 第82批：外国实力的三个字段已接入，具体含义分别保留\n\n'
        'F01.development、subject_scale、major_power由planned提升为partial。发展度是本国缓存；属国规模只提供原生贡献列表的计数和加权发展度，不称完整属国层级；major_power只投影已核实的列强glow条件，不提供排行。领土规模与战争仍planned。\n\n'
        '实际法国本国发展度258、加权属国贡献62.5，列表5项；英国363、7、2项；奥尔良50、0、0项。列强条件分别false/true/false。物理POR、非玩家FRA、raw56564448保持；没有切国、保存、重启、注入、推进、游戏函数调用、外交派发或Computer Use。\n\n'
        f'{rawcount}份原始capture逐份重放；MCP查询、报告和2秒/5秒周期交付关联通过，实际周期{mcp["periodic_counts"]}，取消订阅、server0。原producer在三份采样之后的收据路径错误由离线重放修复，原件保留，未重采；后置pin不冒称前置冻结。\n\n'
        f'唯一full为{totaltext}，Counter141→{comparison["current_bad_occurrences"]}，新增{len(comparison["new_bad"])}；整套仍非全绿。{frozen["count"]}份选定来源冻结并复核。覆盖62 available/182 partial/153 planned；完整74/397、阶段2/3/4、B01–B04与goal继续。见[接口](LINK)。\n')
    tech=(
        '\n根审查修正两个引用分支：正常country fullref最高字节非零才有效；无overlord按最高字节为0判断，不能仅比较整ref是否为0。修正前后专项均保留。发展度缓存e1c与加权贡献1a18/1a20由7cf0f0 tooltip链证明；权重来自233f8ac，不固定写死500；排除类型按原生六flag短路顺序。\n\n'
        'profile country-scale-memory-1374.json为24071B/SHAf002d35d7485968648bf327521e4dacc9942a35ca14ec84a5382a087aaa8e4e5、6ROM guards。列强f17530→1295e0/7cf080/288f；未闭合TLS分支保持unknown。country-view准入是保守导出条件，不是全部原生字段可见性的证明；没有观察实际UI。1344只证实qualifier，不能冒充领土数；1548/1554缓存也不能直接冒充战争数。后续num_of_cities静态种子和战争关联研究单独保留，未注册为能力。\n\n'
        '继续G02资源译文及完整提示/可见性、F01领土和战争、完整B04与法国新正例；具体UI或消息差异须先查明，不从缺少记录推断AI没有原生消息。当前v33/PID30548/creation134376782534496994/session30548-1dd66f8c50752e2，B23、125 native/build copies/DLL/manifest保持。历史120/successful/dispatched/unknown/original-final-pass/未闭合ownership禁止重试，尤其SIE→FRA military_access proposal1、r70_country_money_001_outbound、r71_country_por_to_fra_001、r71_country_fra_to_por_001；旧35天checkpoint不回载。\n\n'
        '完整证据位于work/runtime/information-foreign-scale-20261029-001/。\n')
    guide='''# 国家发展度与外国实力查询

F01接入三个partial字段，观察方为非玩家法国（FRA）；country对象可为法国或外国。物理玩家仍为葡萄牙。

```json
{"topic":"F01","object":{"type":"country","country":"ENG"},"fields":["development","subject_scale","major_power"],"parameters":{}}
```

| 字段 | 值及含义 | 限制 |
| --- | --- | --- |
| development | 有符号32位千分整数，英国363000即363 | 本国缓存，不含属国加权贡献或列强评分 |
| subject_scale | reference_count/included_count/excluded_count、weighted_development_raw、development_scale、weight_raw、weight_scale | 原生贡献列表的汇总，不是完整属国数或层级 |
| major_power | 布尔值，来自原生列强glow条件 | 不提供列强排行、分数或完整成员列表 |

subject_scale两个scale均为1000；英国本次原始贡献7000即7，weight_raw=500即0.5。读取实际权重，而非固定为一半；按原生属国类型排除条件筛选，并保留有符号截零和32位加法规则。空列表可为known的0，不等于unknown。

三个字段可任意组合，支持查询、报告和周期订阅，无额外参数。territory和wars尚未提供。字段读失败或双遍变化返回unknown且无value；共享身份或准入变化撤回全部字段。两遍一致不代表原子快照。

列强feature的部分分支依赖执行线程TLS，尚未闭合；只有已确认的条件决定结果时才输出known，其余unknown。国家查看条件用作保守导出边界，不等于每个原生widget的完整显示条件。这里没有执行游戏函数，也没有观察UI。

实际读取法国258/属国贡献62.5、英国363/7、奥尔良50/0；列强条件false/true/false。这是本次状态，不凭非玩家身份推断标记值。缓存刷新、完整可见性、属国层级、排行、领土和战争仍需继续。
'''
    guidepath=ROOT/'docs/国家发展度与外国实力查询.md'
    with guidepath.open('x',encoding='utf-8',newline='\n') as stream:stream.write(guide)
    docs=['HANDOFF.md','README(agent).md','docs/信息导出与订阅开发计划.md',
          'docs/信息计划验收清单.md','docs/信息导出开发进展.md']
    for name in docs:
        link=('docs/' if not name.startswith('docs/') else '')+'国家发展度与外国实力查询.md'
        prepend(ROOT/name,short.replace('LINK',link)+(tech if name=='HANDOFF.md' else ''))
    for name in docs+['docs/国家发展度与外国实力查询.md','docs/信息字段覆盖.json']:
        target=STAGE/'doc-mirrors-001'/name;target.parent.mkdir(parents=True,exist_ok=True)
        with (ROOT/name).open('rb') as src,target.open('xb') as out:
            while block:=src.read(1024*1024):out.write(block)
    write_new(STAGE/'development-summary-001.json',{
        'batch':82,'status':'partial_feature_verified','goal_complete':False,
        'goal_scope':'74 topics /397 fields, complete phases2/3/4 and B01-B04',
        'coverage':counts,'actual_live_counts':read_json(STAGE/'coverage-update-001.json')['actual_live_counts'],
        'source_count':frozen['count'],'freeze':pin(STAGE/'source-freeze-001.json'),
        'regression':dict(pin(STAGE/'regression-comparison-001.json'),totals=totals),
        'postverify':pin(STAGE/'source-post-run-verification-001.json'),
        'private':pin(STAGE/'private-live-probe-001.json'),'mcp':pin(STAGE/'mcp-live-001/receipt.json'),
        'audit':pin(STAGE/'independent-live-audit-005.json'),'raw_capture_count':rawcount,
        'docs':[pin(ROOT/n) for n in docs+['docs/国家发展度与外国实力查询.md']]})
    artifacts=[pin(p) for p in sorted(STAGE.rglob('*')) if p.is_file()]
    write_new(STAGE/'final-evidence-index-001.json',{'batch':82,'status':'indexed','count':len(artifacts),'files':artifacts})
    print(json.dumps({'status':'published_partial','count':len(artifacts),'goal_complete':False},ensure_ascii=False))


if __name__=='__main__':main()
