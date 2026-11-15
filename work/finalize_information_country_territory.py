"""Publish the verified city-count extension and preserve unresolved war work."""
from collections import deque
from pathlib import Path
import json
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.verify_information_foreign_technology import pin,read_json as read,write_new as write
STAGE=ROOT/'work/runtime/information-country-territory-wars-20261029-001'
MARKER='batch83-country-territory-current'
AUDIT='independent-live-audit-005.json'


def prepend(path,body):
    raw=path.read_bytes();assert len(raw)<4*1024*1024
    text=raw.decode('utf-8-sig');assert MARKER not in text
    backup=STAGE/'historical-docs'/path.relative_to(ROOT);backup.parent.mkdir(parents=True,exist_ok=True)
    with backup.open('xb') as stream:stream.write(raw)
    text=re.sub(r'<!-- batch83-in-progress:start -->.*?<!-- batch83-in-progress:end -->\s*','',text,count=1,flags=re.S)
    path.write_text(f'<!-- {MARKER}:start -->\n{body}\n<!-- {MARKER}:end -->\n\n'+text,encoding='utf-8',newline='\n')


def main():
    from work.verify_information_country_territory import verify_sources
    frozen=verify_sources();comparison=read(STAGE/'regression-comparison-001.json')
    audit=read(STAGE/AUDIT);mcp=read(STAGE/'mcp-live-001/receipt.json');sample=read(STAGE/'private-live-probe-001.json')
    research=read(STAGE/'private-war-shape-receipt-001.json')
    assert comparison['no_new_bad'] and audit['status']==mcp['status']==sample['status']=='passed'
    assert research['status']=='passed_private_research' and research['source_pins_unchanged']
    assert mcp['server_exit_code']==0 and mcp['checks']['no_active_subscriptions']
    assert mcp['archived_capture_count']==3*(2+sum(mcp['periodic_counts'].values()))
    matrix=read(ROOT/'docs/信息字段覆盖.json');counts=matrix['counts']
    assert counts['field_counts']=={'available':62,'partial':183,'planned':152}
    with (STAGE/'regression-full-001.log').open(encoding='utf-8',errors='replace') as stream:tail=''.join(deque(stream,maxlen=20))
    totals={k:int(re.search(r'(\d+) '+k,tail).group(1)) for k in ('passed','failed','errors','subtests')}
    texttotals=' / '.join(f'{totals[k]} {k}' for k in ('passed','failed','errors','subtests'))
    city_raw=3+mcp['archived_capture_count'];all_raw=city_raw+2
    short=(
        '## 第83批：先证实country Scope，再接入城市计数\n\n'
        'F01.territory新增city_count，提升为partial，只表示原生num_of_cities缓存，不是完整拥有省份数或领土清单。法国21、英国44、奥尔良4；原三字段保持，公共projection_version2。F01.wars仍planned，完整74/397、阶段2/3/4和B01–B04继续。\n\n'
        f'{city_raw}份城市管道raw逐份重放，另2份战争形状研究原件单独重放，共{all_raw}份。真实查询、报告及两个周期交付通过，周期{mcp["periodic_counts"]}，{mcp["archived_capture_count"]}份MCP采集；manual结果副本不算新采集，订阅取消/server0。物理POR、非玩家FRA、raw56564448保持，无保存、重启、注入、推进、切国、外交执行、游戏函数调用或Computer Use。\n\n'
        f'唯一full为{texttotals}，Counter141→{comparison["current_bad_occurrences"]}，新增0，整套仍非全绿。{frozen["count"]}选定来源冻结并复核；配置62 available/183 partial/152 planned、47 callable，actual live56/147/194、42 callable。见[接口](LINK)。\n')
    technical=(
        '\n6a7b20把num_of_cities绑定vtable1ca0210；slot+10的6e01e0 exact17B读R8+1fc8并乘1000，这是脚本number编码。6a7140的类型传播警告保留，普通ABI独立证明6a7256的R8来自country DB、6a7486是province stride2e10；a85fa0直接格式化原始缓存供CV_BREAK_COUNTRY_CITIES。未观察实际UI，不把脚本编码当显示。profile-v2 39733B/SHA4086b68c543c5f832b54cbd8db91a753f46fc19e3ca7aa973e59e5f449a60912，10 ROM guards/14610B，v1原件保留。\n\n'
        '战争研究发现旧R2依赖1.37.5；旧WAR_VT1d1f768在B23落在字符串区域，已明确拒绝作为当前profile。当前只读FRA/ENG关联分别10/2行，却各只有1个不同对象；实采vtable RVA1d1f6f0，REA d85520构造器又证其marker0x165、vector布局。没有将关联行数或旧地址冒充战争数量/当前布局。既有W01仍是pair枚举，完整country战争枚举、共享war_ID/生命周期、全局容器与可见性继续。COFF找到了v33观测器registry静态符号，但本批未运行时解析其地址或初始化状态。\n\n'
        f'城市leaf最终23、capture15、public76专项通过；capture首收据误把JUnit根计数记0，corrected收据保留15/15，不重跑。独立审计以{AUDIT}为准；其它失败原件如有均保留。完整拥有省份数/清单、cache writer/新鲜度、完整UI可见性仍缺，不以partial关闭目标。\n\n'
        '当前v33/PID30548/creation134376782534496994/session30548-1dd66f8c50752e2、B23、125 native/build copies/DLL/manifest保持。旧35天checkpoint不回载；历史120/successful/dispatched/unknown/original-final-pass/未闭合ownership禁止重试，尤其SIE→FRA military_access proposal1、r70_country_money_001_outbound、r71_country_por_to_fra_001、r71_country_fra_to_por_001。UI/消息差异须逐项证实，继续F01完整领土/战争、G02译文/提示、完整B04与法国新正例。\n\n'
        '本批全部原件在work/runtime/information-country-territory-wars-20261029-001/。\n')
    guide='''# 国家发展度与外国实力查询

F01支持四个partial字段，逻辑观察方为非玩家法国FRA，物理玩家保持葡萄牙。country对象可为法国或外国。

```json
{"topic":"F01","object":{"type":"country","country":"ENG"},"fields":["development","territory","subject_scale","major_power"],"parameters":{}}
```

| 字段 | 本次英国值 | 含义与限制 |
| --- | --- | --- |
| development | 363000 | development_raw、scale1000，即本国发展度363，不含属国加权贡献 |
| territory | {"city_count":44} | native_city_count、scale1；原生num_of_cities缓存，不是完整拥有省份数或清单 |
| subject_scale | reference_count2、weighted_development_raw7000 | 只汇总原生贡献列表；development_scale1000、weight_raw500、weight_scale1000，不称完整属国层级 |
| major_power | true | 原生列强glow条件，不提供排行或完整成员身份 |

四字段可任意组合用于查询、报告和周期订阅，不接受额外参数。wars仍planned。公共projection_version为2，字段和整体均complete=false。缺少依据或双遍不一致返回unknown且无value；共享身份/准入变化撤回全部字段。两个外部读遍不是原子快照。

city_count从国家缓存直接读取，支持0..65535整数。脚本getter把它乘1000作为脚本数值编码；tooltip另一路直接格式化原始整数，本接口以scale1输出计数。0是真实可表达值，不与unknown混用。完整省份数、城市/殖民地的完整归属清单、缓存写入和刷新时点未闭合。

本次法国city_count21、英国44、奥尔良4。没有切换玩家来制造UI。国家查看条件只作为保守导出边界，不代表每个原生控件的完整可见性；未观察实际UI。列强feature的未闭合线程TLS分支继续unknown，原生贡献列表也不能代替完整属国名单。

战争研究原件仅用于确认当前对象布局。敌对国家关联行数不等于战争数；当前vtable地址必须按本版EXE和实时对象核对，旧1.37.5布局不作为本版能力。
'''
    guidepath=ROOT/'docs/国家发展度与外国实力查询.md';backup=STAGE/'historical-docs/国家发展度与外国实力查询-82.md'
    backup.parent.mkdir(parents=True,exist_ok=True)
    with backup.open('xb') as stream:stream.write(guidepath.read_bytes())
    guidepath.write_text(guide,encoding='utf-8',newline='\n')
    docs=['HANDOFF.md','README(agent).md','docs/信息导出与订阅开发计划.md','docs/信息计划验收清单.md','docs/信息导出开发进展.md']
    for name in docs:
        link=('docs/' if not name.startswith('docs/') else '')+'国家发展度与外国实力查询.md'
        prepend(ROOT/name,short.replace('LINK',link)+(technical if name=='HANDOFF.md' else ''))
    docs+=['docs/国家发展度与外国实力查询.md','docs/信息字段覆盖.json']
    for name in docs:
        target=STAGE/'doc-mirrors-001'/name;target.parent.mkdir(parents=True,exist_ok=True)
        with (ROOT/name).open('rb') as source,target.open('xb') as dest:
            while block:=source.read(1024*1024):dest.write(block)
    write(STAGE/'development-summary-001.json',{'batch':83,'status':'partial_feature_verified','goal_complete':False,
        'goal_scope':'74 topics /397 fields; complete phases2/3/4 and B01-B04','coverage':counts,
        'actual_live_counts':read(STAGE/'coverage-update-001.json')['actual_live_counts'],
        'source_count':frozen['count'],'freeze':pin(STAGE/'source-freeze-001.json'),
        'regression':dict(pin(STAGE/'regression-comparison-001.json'),totals=totals),
        'postverify':pin(STAGE/'source-post-run-verification-001.json'),'audit':pin(STAGE/AUDIT),
        'mcp':pin(STAGE/'mcp-live-001/receipt.json'),'private':pin(STAGE/'private-live-probe-001.json'),
        'research':pin(STAGE/'private-war-shape-receipt-001.json'),'city_raw_count':city_raw,'all_raw_count':all_raw,
        'docs':[pin(ROOT/name) for name in docs]})
    files=[pin(p) for p in sorted(STAGE.rglob('*')) if p.is_file()]
    write(STAGE/'final-evidence-index-001.json',{'batch':83,'count':len(files),'files':files,'status':'indexed'})
    print(json.dumps({'status':'published_partial','count':len(files),'goal_complete':False},ensure_ascii=False))


if __name__=='__main__':main()
