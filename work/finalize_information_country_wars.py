"""Publish batch-84 evidence without closing the full information-export goal."""
from collections import deque
from pathlib import Path
import json
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.verify_information_foreign_technology import pin,read_json as read,write_new as write
STAGE=ROOT/'work/runtime/information-country-wars-20261029-001'
MARKER='batch84-country-wars-current'


def prepend(path,body):
    raw=path.read_bytes();assert len(raw)<4*1024*1024
    text=raw.decode('utf-8-sig');assert MARKER not in text
    backup=STAGE/'historical-docs'/path.relative_to(ROOT);backup.parent.mkdir(parents=True,exist_ok=True)
    with backup.open('xb') as stream:stream.write(raw)
    text=re.sub(r'<!-- batch84-in-progress:start -->.*?<!-- batch84-in-progress:end -->\s*','',text,count=1,flags=re.S)
    path.write_text(f'<!-- {MARKER}:start -->\n{body}\n<!-- {MARKER}:end -->\n\n'+text,encoding='utf-8',newline='\n')


def main():
    from work.verify_information_country_wars import verify_sources
    frozen=verify_sources();comparison=read(STAGE/'regression-comparison-001.json')
    audit=read(STAGE/'independent-live-audit-001.json')
    mcp=read(STAGE/'mcp-live-001/receipt.json');sample=read(STAGE/'private-live-probe-001.json')
    assert comparison['no_new_bad'] and audit['status']==mcp['status']==sample['status']=='passed'
    assert mcp['server_exit_code']==0 and mcp['checks']['no_active_subscriptions']
    assert mcp['archived_capture_count']==len(mcp['targets'])*(2+sum(mcp['periodic_counts'].values()))
    matrix=read(ROOT/'docs/信息字段覆盖.json');counts=matrix['counts']
    assert counts['field_counts']=={'available':62,'partial':184,'planned':151}
    with (STAGE/'regression-full-001.log').open(encoding='utf-8',errors='replace') as stream:
        tail=''.join(deque(stream,maxlen=20))
    totals={k:int(re.search(r'(\d+) '+k,tail).group(1)) for k in ('passed','failed','errors','subtests')}
    texttotals=' / '.join(f'{totals[k]} {k}' for k in ('passed','failed','errors','subtests'))
    profile=pin(ROOT/'bridge/information/profiles/country-scale-memory-1374-v4.json')
    short=(
        '## 第84批：核对当前国家的战争对象与双方成员\n\n'
        'F01.wars由planned提升为partial，提供当前国家敌对关联表中的去重战争数、双方成员及可关联的共享war ID。F01五字段均partial，公共projection_version3；不称全局完整战争枚举，生命周期、角色和领导者仍未证实。完整74/397、阶段2/3/4与B01–B04继续，goal active。\n\n'
        '实际FRA关联10行、1场战争；ORL关联同一个共享ID war_1c5b10c9b19ce405_00000007。ENG是另一对象，关联已有registry ID4；POR的0场战争以实际双遍读取为据。双方成员按非玩家FRA逐项准入，未准入者不输出国家标签。具体结果见本批原件与[接口](LINK)。\n\n'
        f'公开查询、报告与2秒/5秒周期通过；实际周期{mcp["periodic_counts"]}，{mcp["archived_capture_count"]}份MCP采集，manual结果副本不算新采集。独立审计通过、订阅取消/server0。物理POR、非玩家FRA、raw56564448保持，无保存、重启、注入、推进、切国、业务派发、游戏函数调用或Computer Use。\n\n'
        f'唯一full为{texttotals}；Counter141→{comparison["current_bad_occurrences"]}，新增0，整套仍非全绿。{frozen["count"]}选定来源冻结并复核；配置62 available/184 partial/151 planned、47 callable，actual live56/148/193、42 callable。\n')
    technical=(
        '\n当前B23 SHA b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77，preferred main VA0x140000000；所有函数地址均RVA。3f7570读取country1548/1554的16B关联行，d942f0消费war+48/+78双方vector，d85520构造器确认vtable1d1f6f0和marker0x165；a85fa0的country289b用于at-war提示分支。REA语义、普通PE代码字节和实际只读观察分别保留；未观察实际UI，不套用旧1.37.5的vtable。\n\n'
        '本批最初registry有6项、FRA当前对象未注册。一次既有只读QUERY1（FRA/BUR，inspect_9737ed1fdfa549b7a2a6be570429edf8）关联第7项；submitted=false，不构造offer或调用游戏函数。此query不重试。生产读取器只读registry，永不注册ID。16hex前缀为creation的SplitMix64 epoch，序号不是pointer；初稿leaf误把前缀当pointer，root审查发现后修正，早期失败收据保留。实采又发现helper的hex(pointer)与补零16位正则不兼容，以及raw range的tuple落盘变list导致strict重放失败；v4同时修正，旧v3与错放83目录的原件保留，位置说明明确不属于83冻结/index。\n\n'
        f'profile-v4 {profile["bytes"]}B/SHA{profile["sha256"]}，13段main ROM guards/16417B，另2段DLL代码guards/3902B。原v1/v2/v3保持。DLL绑定借用父层已认证只读handle，重放仅使用记录的前后metadata；registry头、代码、creation、entry序号和pointer关联都核对，但append-only registry没有对象生命周期失效机制，因此lifetime=false。绑定变化只撤回wars，ID不可得不丢弃独立证实的成员结构。\n\n'
        '成员准入使用父层真实完整国家扫描及重验fullref，未伪造None填充扫描。敌对表、side vectors、目标只在一侧、反向关联及双遍一致性都通过后才输出partial。shared身份/准入变化仍全撤回；单字段变化按依赖撤回。current-country cache不能证明全局容器完备性，也不能证明字段全部UI可见性。\n\n'
        '当前v33/PID30548/creation134376782534496994/session30548-1dd66f8c50752e2、B23、125 native/build copies/DLL/manifest保持。旧35天checkpoint不回载；历史120/successful/dispatched/unknown/original-final-pass/未闭合ownership禁止重试，尤其SIE→FRA military_access proposal1、r70_country_money_001_outbound、r71_country_por_to_fra_001、r71_country_fra_to_por_001。\n\n'
        '用户的“如果”是待核实情形；UI/原生消息差异必须具体查明，不从没有记录推断非玩家没有功能。继续F01完整领土/战争及生命周期、G02译文/提示、完整B04与法国新正例。原件：work/runtime/information-country-wars-20261029-001/。\n')
    guide='''# 国家发展度与外国实力查询

F01支持五个partial字段。逻辑观察和操控方为非玩家法国FRA，物理玩家保持葡萄牙；查询对象可以是法国或外国。

```json
{"topic":"F01","object":{"type":"country","country":"ENG"},"fields":["development","territory","subject_scale","major_power","wars"],"parameters":{}}
```

| 字段 | 含义与限制 |
| --- | --- |
| development | 本国发展度缓存，scale1000；英国363000表示363，不含属国加权贡献 |
| territory | {"city_count":44}为英国原生num_of_cities缓存，scale1；不是完整省份数或归属清单 |
| subject_scale | 原生贡献列表的计数及加权发展度；英国2项、7000，不称完整属国层级 |
| major_power | 原生列强glow条件；英国true，不提供排行或完整成员身份 |
| wars | at_war、去重war_count和wars数组；只覆盖当前国家敌对关联表，不保证全局完备 |

五字段可任意组合用于查询、报告和周期订阅，不接受额外参数。公共projection_version为3，字段和整体均complete=false。缺少依据或双遍不一致返回unknown且无value；共享身份/准入变化撤回全部字段。两个外部读遍不是原子快照。

wars中的每场战争提供target_side及side_a/side_b成员描述；side标签不宣称攻守角色。成员只有通过法国查看准入才输出country标签，其余保留invisible或unknown及原因。membership_complete仅指本次对象两侧结构已核对，不表示所有国家标签可见；identities_complete另行表示标签是否都已获准输出。roles_verified始终false。

war_id只有在已加载观测器的共享registry中匹配时才是known，identity_scope为observer_session，lifetime_verified为false。没有注册项时ID保持unknown，已独立核实的计数和成员仍可输出。读取不会主动注册ID或执行业务动作；registry未解决pointer重用、对象销毁与代际身份问题。外层global_membership_verified及lifetime_verified也始终false。

本次法国10行关联只对应1场战争；奥尔良共享同一个ID，英国对应另一对象，已有registry ID4。葡萄牙实采0场，0和unknown分开。不能把关联行数当战争数；也不能为取得完整ID而重复外交动作。

city_count支持0..65535，法国21、英国44、奥尔良4。脚本getter的乘1000属于脚本number编码；本接口以scale1输出原始计数。完整省份清单、缓存写入和刷新时点、完整战争容器及字段全部UI可见性仍待开发。

国家查看条件是保守导出边界，不能代替每个原生控件的具体可见性判断。未切换物理玩家制造UI，也未因缺少记录断言非玩家没有原生消息功能。
'''
    guidepath=ROOT/'docs/国家发展度与外国实力查询.md'
    backup=STAGE/'historical-docs/国家发展度与外国实力查询-83.md';backup.parent.mkdir(parents=True,exist_ok=True)
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
    write(STAGE/'development-summary-001.json',{'batch':84,'status':'partial_feature_verified','goal_complete':False,
        'goal_scope':'74 topics /397 fields; complete phases2/3/4 and B01-B04','coverage':counts,
        'actual_live_counts':read(STAGE/'coverage-update-001.json')['actual_live_counts'],
        'source_count':frozen['count'],'freeze':pin(STAGE/'source-freeze-001.json'),
        'regression':dict(pin(STAGE/'regression-comparison-001.json'),totals=totals),
        'postverify':pin(STAGE/'source-post-run-verification-001.json'),
        'audit':pin(STAGE/'independent-live-audit-001.json'),'mcp':pin(STAGE/'mcp-live-001/receipt.json'),
        'private':pin(STAGE/'private-live-probe-001.json'),
        'native_contract':pin(STAGE/'native-country-wars-contract-001.json'),
        'docs':[pin(ROOT/name) for name in docs]})
    files=[pin(p) for p in sorted(STAGE.rglob('*')) if p.is_file()]
    write(STAGE/'final-evidence-index-001.json',{'batch':84,'count':len(files),'files':files,'status':'indexed'})
    print(json.dumps({'status':'published_partial','count':len(files),'goal_complete':False},ensure_ascii=False))


if __name__=='__main__':main()
