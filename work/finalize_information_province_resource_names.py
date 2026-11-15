"""Publish verified cached resource names and preserve the full remaining goal."""
from collections import deque
from pathlib import Path
import json
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.verify_information_foreign_technology import pin,read_json as read,write_new as write
STAGE=ROOT/'work/runtime/information-province-resource-localization-20261029-001'
MARKER='batch85-resource-name-current'


def backup(path):
    dest=STAGE/'historical-docs'/path.relative_to(ROOT);dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open('xb') as stream:stream.write(path.read_bytes())


def prepend(path,body):
    raw=path.read_bytes();assert len(raw)<4*1024*1024
    text=raw.decode('utf-8-sig');assert MARKER not in text;backup(path)
    text=re.sub(r'<!-- batch85-in-progress:start -->.*?<!-- batch85-in-progress:end -->\s*','',text,count=1,flags=re.S)
    path.write_text(f'<!-- {MARKER}:start -->\n{body}\n<!-- {MARKER}:end -->\n\n'+text,encoding='utf-8',newline='\n')


def main():
    from work.verify_information_province_resource_names import verify_sources
    frozen=verify_sources();comparison=read(STAGE/'regression-comparison-001.json')
    audit=read(STAGE/'independent-live-audit-001.json');mcp=read(STAGE/'mcp-live-001/offline-reconciliation-002.json')
    private=read(STAGE/'private-live-probe-001.json');profile=pin(ROOT/'bridge/information/profiles/province-state-memory-1374-v4.json')
    assert comparison['no_new_bad'] and audit['status']==mcp['status']==private['status']=='passed'
    assert mcp['server_exit_code']==0 and mcp['checks']['no_active_subscriptions']
    assert mcp['archived_capture_count']==len(mcp['targets'])*(2+sum(mcp['periodic_counts'].values()))
    matrix=read(ROOT/'docs/信息字段覆盖.json');assert matrix['counts']['field_counts']=={'available':62,'partial':184,'planned':151}
    examples=audit['resource_examples'];assert [row['province_id'] for row in examples]==[183,184,236]
    with (STAGE/'regression-full-001.log').open(encoding='utf-8',errors='replace') as stream:
        tail=''.join(deque(stream,maxlen=20))
    totals={key:int(re.search(r'(\d+) '+key,tail).group(1)) for key in ('passed','failed','errors','subtests')}
    texttotals=' / '.join(f'{totals[key]} {key}' for key in ('passed','failed','errors','subtests'))
    example_text='；'.join(f'{row["province_id"]}的{row["value"]["localization_key"]}为“{row["value"]["name"]["text"]}”' for row in examples)
    short=(
        '## 第85批：省份资源名称已读取到缓存字面译文\n\n'
        'G02.resource在原有key/icon上新增name子项，公共projection_version4。名称来自同一父层只读采集中的当前语言缓存；不称最终UI文字。名称缺失、动态模板或名称单独变化时保留稳定key/icon，共享身份变化仍全撤回。八字段继续partial，覆盖计数62 available/184 partial/151 planned不变；完整74/397、阶段2/3/4和B01–B04继续，goal active。\n\n'
        f'实采{example_text}。2000发现位0，八字段unknown且无字段或本地化读取。物理POR、非玩家FRA、raw56564448保持，无切国、推进、保存、重启、注入、业务派发、游戏函数调用或Computer Use。见[接口](LINK)。\n\n'
        f'保存后的私有报告和公开采集均逐份严格重放；查询、报告及2秒/5秒周期通过，实际周期{mcp["periodic_counts"]}、{mcp["archived_capture_count"]}份MCP采集，取消订阅/server0。首次客户端15秒等待未达周期阈值，最终取消后保存结果已满足；离线核对后接收，未重启或重采。独立审计{audit["checks"]}项通过，manual结果副本不计新采集。唯一full为{texttotals}，Counter141→{comparison["current_bad_occurrences"]}，新增0，整套仍非全绿；{frozen["count"]}选定来源冻结并复核。\n')
    technical=(
        '\nB23 SHA b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77，preferred main VA0x140000000，本文函数地址均RVA。复用既有1379450 tradegoods_name→a16960 selected province+458→1f7890 definition+18 String32→14b33a0 FNV1→16faf60缓存lower_bound证据，无新REA查询或游戏translator调用。普通PE字节、REA和实际RPM分开记录；name仅表示缓存中的非空字面值，不证明控件可见、格式化或渲染。\n\n'
        f'profile-v4 {profile["bytes"]}B/SHA{profile["sha256"]}，19段ROM guards/62093B每boundary，v1/v2/v3保留。新pure adapter复用localization_memory._snapshot，局部calls2048/total65536/single16384，叠加父512KiB预算；同一handle/ordered trace重建语言、FNV entry和pool bytes。公开以显式eu4_escape解码，$及[]动态标记不展开。hash-only lookup没有字面源key证明，literal_key_collision_excluded=false；secondary records、全局排序、缓存新鲜度和原子性仍未验证。\n\n'
        '未改共享province_state_memory，避免使F01等既有profile失效。名称协调只在共享证据stable且剥除name及其私有快照后resource全部基础raw严格一致时保留base；base变化继续撤回resource。source用白名单导出name，错误和动态模板不泄漏私有地址。\n\n'
        '初次身份辅助脚本的report初始化和cleanup API错误有单独失败说明；未做RPM/游戏调用，后续身份只读句柄显式关闭。public测试曾错放81stage，原件保留、流复制到85，位置说明明确不是81冻结/index成员；不以复制或重采补造先前收据。此前141坏项仍保留，84封存XML的窄盘点没有information_*失败节点，不能据此宣称完整阶段四已验收。\n\n'
        '当前v33/PID30548/creation134376782534496994/session30548-1dd66f8c50752e2、125 native/build copies/DLL/manifest保持。禁止重试原120、successful/dispatched/unknown、原final-pass IDs及未闭合ownership；尤其SIE→FRA military_access proposal1、r70_country_money_001_outbound、r71_country_por_to_fra_001、r71_country_fra_to_por_001；旧35天checkpoint不回载。\n\n'
        '继续完整G02提示/可见性/潜在资源/价格，F01全局战争枚举/生命周期与完整领土，完整B04和法国新正例及其余计划字段。用户的“如果”不能当作既定差异；UI/消息差异仍须逐项查明。原件：work/runtime/information-province-resource-localization-20261029-001/。\n')
    first=examples[0]['value'];full_example=json.dumps(first,ensure_ascii=False,indent=2)
    rows='\n'.join(f'| {row["province_id"]} | {row["value"]["localization_key"]} | {row["value"]["name"]["text"]} | {row["value"]["name"]["language"]} |' for row in examples)
    guide=f'''# 省份资源名称查询

G02.resource现在提供资源key、定义图标索引和可用时的缓存字面名称。逻辑观察方为非玩家法国FRA，物理玩家保持葡萄牙；仍需先通过该省份的法国发现证据。

```json
{{"topic":"G02","object":{{"type":"province","province_id":183}},"fields":["resource"],"parameters":{{}}}}
```

本次183的value为：

```json
{full_example}
```

| 省份 | key | 本次缓存名称 | 观察到的语言 |
| --- | --- | --- | --- |
{rows}

name.status为known时，text由raw_hex按明确的eu4_escape编码解码；language来自运行中的缓存头；本次标识为l_english而内容为中文，两者分别按实采报告，不用语言标签猜文字内容。lookup_semantics为native_FNV1_hash_only，表示复用了游戏按FNV1哈希搜索缓存的方法；literal_key_collision_excluded=false表示没有证明源key文本无碰撞。它不是最终控件文字或UI可见性证明。

未找到key、读取失败或名称包含$、[]动态标记时，name为unknown并带原因；稳定的key/icon仍可输出。名称单独变化也只撤回name。资源定义或基础raw变化撤回resource，共享身份、观察方或发现证据变化撤回八字段。实际的0、空集合与unknown继续分开。

名称读取与省份字段共用父层已认证的只读handle和有序raw trace。保存后的JSON会重读并严格重放；没有执行本地化函数或切换物理玩家。两个读取遍不是原子快照，缓存刷新时点仍未知。

省份2000的法国发现位为0，因此八字段unknown且不读任何字段或本地化数据。资源潜在值、价格、完整提示及字段全部UI可见性尚未提供；G02仍全部partial、complete=false。查询、报告与周期订阅使用同一来源。
'''
    guidepath=ROOT/'docs/省份资源名称查询.md';assert not guidepath.exists();guidepath.write_text(guide,encoding='utf-8',newline='\n')
    oldguide=ROOT/'docs/省份所有者与控制者查询.md';text=oldguide.read_text(encoding='utf-8-sig');backup(oldguide)
    text=text.replace('本地化键及定义中的图标索引；不是译文或实际帧请求','本地化键、定义图标索引及name子项；缓存字面名称见下文，不是实际帧请求')
    text=text.replace('资源提示实际调用本地化函数，因此当前只把输入键作为资源标识，不宣称已有译文。潜在资源、价格等未提供。',
        '资源名的静态路径会把key传给本地化函数；当前已读取相同缓存中的字面名称，放在name子项中。名称不可得时保留key/icon；没有执行该游戏函数或证明UI渲染。完整示例及状态见[资源名称](省份资源名称查询.md)。潜在资源、价格等未提供。')
    text=text.replace('单字段原始数据变化撤回该字段。','单字段基础原始数据变化撤回该字段；资源名称单独变化时保留稳定key/icon并把name置为unknown。')
    oldguide.write_text(text,encoding='utf-8',newline='\n')
    docs=['HANDOFF.md','README(agent).md','docs/信息导出与订阅开发计划.md','docs/信息计划验收清单.md','docs/信息导出开发进展.md']
    for name in docs:
        link=('docs/' if not name.startswith('docs/') else '')+'省份资源名称查询.md'
        prepend(ROOT/name,short.replace('LINK',link)+(technical if name=='HANDOFF.md' else ''))
    docs+=['docs/省份资源名称查询.md','docs/省份所有者与控制者查询.md','docs/信息字段覆盖.json']
    for name in docs:
        target=STAGE/'doc-mirrors-001'/name;target.parent.mkdir(parents=True,exist_ok=True)
        with (ROOT/name).open('rb') as source,target.open('xb') as dest:
            while block:=source.read(1024*1024):dest.write(block)
    write(STAGE/'development-summary-001.json',{'batch':85,'status':'partial_semantics_extended','goal_complete':False,
        'goal_scope':'all74/397 and complete phases2/3/4, B01-B04','coverage':matrix['counts'],
        'actual_live_counts':read(STAGE/'coverage-update-001.json')['actual_live_counts'],
        'source_count':frozen['count'],'freeze':pin(STAGE/'source-freeze-001.json'),
        'regression':dict(pin(STAGE/'regression-comparison-001.json'),totals=totals),
        'audit':pin(STAGE/'independent-live-audit-001.json'),'mcp':pin(STAGE/'mcp-live-001/offline-reconciliation-002.json'),
        'private':pin(STAGE/'private-live-probe-001.json'),'resource_examples':examples,
        'docs':[pin(ROOT/name) for name in docs]})
    files=[pin(path) for path in sorted(STAGE.rglob('*')) if path.is_file()]
    write(STAGE/'final-evidence-index-001.json',{'batch':85,'count':len(files),'files':files,'status':'indexed'})
    print({'status':'published_partial_semantics','artifacts':len(files),'goal_complete':False})


if __name__=='__main__':main()
