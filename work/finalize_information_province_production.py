"""Publish the verified G02 extension while retaining the full active plan."""
from collections import deque
from pathlib import Path
import re
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.verify_information_province_production import STAGE,read_json as read,write_new as write,pin,verify_sources
AUDIT='independent-live-audit-003.json'


def copy(source,target):
    target.parent.mkdir(parents=True,exist_ok=True)
    with source.open('rb') as inp,target.open('xb') as out:
        while block:=inp.read(1024*1024):out.write(block)


def prepend(path,marker,body):
    assert path.stat().st_size<4*1024*1024
    old=path.read_text(encoding='utf-8-sig');assert marker not in old
    path.write_text(f'<!-- {marker}:start -->\n{body}\n<!-- {marker}:end -->\n\n'+old,encoding='utf-8',newline='\n')


def main():
    frozen=verify_sources();comparison=read(STAGE/'regression-comparison-001.json')
    audit=read(STAGE/AUDIT);mcp=read(STAGE/'mcp-live-001/receipt.json')
    positive=read(STAGE/'private-live-probe-001.json');negative=read(STAGE/'private-discovery-negative-001.json')
    zero=read(STAGE/'private-center-zero-001.json')
    assert comparison['no_new_bad'] and audit['status']==mcp['status']==positive['status']=='passed'
    assert negative['status']=='passed_negative' and zero['status']=='passed_zero'
    assert mcp['server_exit_code']==0 and mcp['checks']['no_active_subscriptions']
    assert mcp['archived_capture_count']==4*(2+sum(mcp['periodic_counts'].values()))
    with (STAGE/'regression-full-001.log').open(encoding='utf-8',errors='replace') as stream:
        tail=''.join(deque(stream,maxlen=20))
    totals={key:int(re.search(r'(\d+) '+re.escape(key),tail).group(1))
        for key in ('passed','failed','errors','subtests')}
    result='/'.join(f'{totals[key]} {key}' for key in ('passed','failed','errors','subtests'))
    matrix=read(ROOT/'docs/信息字段覆盖.json');counts=matrix['counts']
    assert counts['field_counts']=={'available':62,'partial':179,'planned':156}
    profile=pin(ROOT/'bridge/information/profiles/province-state-memory-1374-v3.json')
    stage=STAGE.relative_to(ROOT).as_posix();raw_count=5+mcp['archived_capture_count']
    guide='''# 省份状态查询

G02 八字段均已接入，但都为partial、complete=false。观察方是非玩家法国（FRA），物理玩家保持葡萄牙。只有法国的省份发现证据为正时才读取字段；证据不足返回unknown且没有value。

```json
{"topic":"G02","object":{"type":"province","province_id":183},"fields":["owner","controller","development","culture","religion","autonomy","resource","center_of_trade"],"parameters":{}}
```

| 字段 | value示例 | 含义及单位 |
| --- | --- | --- |
| owner / controller | FRA | 分别验证的所有者／控制者国家标签，country_tag、scale=1 |
| development | 23000 | 有效发展度千分整数，即23，development、scale=1000 |
| culture | {"name":{"text":"法兰西","raw_hex":"10d56c107051107f89","encoding":"eu4_escape"}} | 名称缓存，不含接受度颜色 |
| religion | {"name":{"text":"天主教","raw_hex":"10295911494e105965","encoding":"eu4_escape"},"icon_frame_request":1} | 名称缓存与帧请求，不代表已渲染 |
| autonomy | 850 | percent、scale=1000，即0.85%；保留格式化前精度 |
| resource | {"localization_key":"paper","icon_index":28} | 本地化键及定义中的图标索引；不是译文或实际帧请求 |
| center_of_trade | {"present":true,"level":2,"kind":"inland","sprite_key":"GFX_center_of_trade_inland_2"} | 存在、级别、类型及原生规则生成的sprite键；不证明渲染 |

没有贸易中心时为known的`{"present":false,"level":0}`。这是已确认的空指针分支，不与unknown混用。非空对象的无效级别返回unknown，不伪造成没有贸易中心。

对象是单个province，province_id为1..65535的整数且必须存在于当前省份数组；可单独或共同查询八字段，放入报告及周期订阅，不接受额外参数。

每遍先核对FRA完整国家引用、Human1/FRA controller0、规范省份ID和记录，再检查该国发现位。位0不读任何八字段；unknown不等于已经证明不可见。共享身份或发现证据变化撤回全部字段，单字段原始数据变化撤回该字段。两遍读取不是原子快照。

发展度按实际面板的有效分量计算：三个基础值，以及仅在所有者部落指针非空且其目标省份ID匹配时加入的分量。部落分量先按C++有符号除法向零截断到整点，再相加；分量与总和保留原生32位加法解释。面板最后显示整数，这里公开原始千分整数，不执行游戏函数。

资源提示实际调用本地化函数，因此当前只把输入键作为资源标识，不宣称已有译文。潜在资源、价格等未提供。贸易中心读取状态与升级／降级权限分开；费用、权限和完整提示未提供。文化／宗教前缀、完整可见性和缓存刷新时点也未全部闭合。

本批实采183为发展度23、paper、内陆二级；184为17、grain、内陆一级；236为20、cloth、沿海二级。185为15、paper、无贸易中心，且没有读取定义对象；2000发现位0，八字段unknown且无字段数据读取。物理玩家POR、逻辑观察和操控方FRA保持不变；没有切国制造UI。
'''
    guide_path=ROOT/'docs/省份所有者与控制者查询.md';acceptance=ROOT/'docs/信息计划验收清单.md'
    copy(guide_path,STAGE/'historical-docs/省份状态查询-80.md')
    copy(acceptance,STAGE/'historical-docs/信息计划验收清单-80.md')
    guide_path.write_text(guide,encoding='utf-8',newline='\n')
    short=("## 第81批：发展度、资源与贸易中心已接入，G02八字段均为partial\n\n"
        "新增development/resource/center_of_trade三字段。发展度是含条件部落分量的有效千分整数；资源提供本地化键和图标索引，未取得译文；贸易中心提供存在、级别、类型和sprite键，空指针为known无中心。实际183为23/paper/内陆2级，184为17/grain/内陆1级，236为20/cloth/沿海2级；185为15/paper/无中心且未读定义。2000八字段unknown且无字段数据读。见[接口说明](LINK)。\n\n"
        f"{raw_count}份实际raw capture重放，查询、报告及2秒/5秒周期交付关联通过；实际周期{mcp['periodic_counts']}，{mcp['archived_capture_count']}份MCP采集，不把manual列表副本算作采集。取消订阅/server0；物理POR、非玩家FRA、raw56564448保持。没有保存、重启、注入、推进、切国、外交执行、游戏函数调用或Computer Use。\n\n"
        f"唯一full为{result}，Counter141→{comparison['current_bad_occurrences']}，新增0；整套仍非全绿。{frozen['count']}选定来源已冻结复核。配置62 available/179 partial/156 planned、46 callable，实际live56/143/198、41 callable。八字段接通不等于完成G02所有缺项；完整74/397、阶段2/3/4和B01–B04继续，goal active。\n")
    technical=(f"\nprofile-v3 {profile['bytes']}B/SHA{profile['sha256']}，17 ROM guards；v1/v2原件保留。发展度实际caller1373ea0/e318c0 flags0/1、a0cff0→a0d520/a0de60/a0d9c0，C++截零及i32 wrap有分别保留的REA和普通PE依据。原pseudo首个RCX误标0的限制及普通指令修正继续保留。资源1379450 tooltip→a16960 exact8B getter→1f7890复制definition+18 String32键到14b33a0，本批不执行该本地化函数。\n\n"
        "正确贸易中心子面板vtable为1d7d1b0；138db50把center_of_trade_button/icon绑定panel[96]/[97]，1390750读province+960→object+8→definition+10/+14；1386380生成GFX key。先前1d79138属于主view，不是该child。cot_button是误用的简称，精确GUI名center_of_trade_button/icon；旧负扫描不证明功能不存在。138d4e0无pdata但REA证实leaf constructor，不补造边界。完整B23 SHA、RVA/VA、范围、证据ID及未闭合条件见本stage两份native contract。\n\n"
        "新增leaf development29/resource31/cot39、capture45/public113项最后通过；早期期望值/fixture失败保留。独立audit的路径与metadata适配失败也保留，不通过重采修正审计。公共投影严格白名单；任何共享身份变化全撤回，单字段必要读失败或raw变化按依赖撤回。发现位0不执行任何leaf。\n\n"
        "当前v33/PID30548/creation134376782534496994/session30548-1dd66f8c50752e2、B23、Human1/FRA0/物理POR。125 native及125 build copies/DLL/manifest不变。历史120/successful/dispatched/unknown/original-final-pass/未闭合ownership禁止重试，尤其SIE→FRA military_access proposal1、r70_country_money_001_outbound、r71_country_por_to_fra_001及r71_country_fra_to_por_001。旧35天checkpoint不回载重播，当前模块/patch/unwind仍至进程退出。\n\n"
        "继续G02资源译文/完整可见性和提示、F01外国实力、完整B04及法国新正例等原计划缺口。UI或消息差异须按具体路径和事实判断，不能从未采到消息推断AI没有消息。\n\n"
        f"本批原件、独立审计、比较、summary/index位于{stage}/；通过审计为{AUDIT}。\n")
    for name in ('HANDOFF.md','README(agent).md','docs/信息导出与订阅开发计划.md'):
        link=('docs/' if not name.startswith('docs/') else '')+'省份所有者与控制者查询.md'
        prepend(ROOT/name,'batch81-province-production-current',short.replace('LINK',link)+(technical if name=='HANDOFF.md' else ''))
    groups=[]
    for prefix in ('C','N','F','R','M','G','T','D','W','P','A','S','H','B'):
        topics=[t for t in matrix['topics'] if t['topic_id'].startswith(prefix)];cc={key:0 for key in ('available','partial','planned')}
        for topic in topics:
            for field in topic['fields'].values():cc[field['coverage']]+=1
        groups.append(f"| {prefix} | {len(topics)} | {cc['available']} | {cc['partial']} | {cc['planned']} |")
    acceptance.write_text('''# 信息计划验收清单

更新至第81批，2026-10-29。完整目标仍为74主题397字段、阶段二/三/四和B01–B04，goal active。当前配置62 available /179 partial /156 planned、46主题可调用；本次实际live为56/143/198、41主题可调用。登记、接通和partial均不能代替完整验收。

| 范围 | 当前证据 | 待完成 |
| --- | --- | --- |
| 阶段零/一 | 模型、目录、持久配置、版本、查询报告和周期框架；81批八字段真实交付与取消通过 | 全部来源组合及跨会话恢复 |
| 阶段二 | G02八字段均partial，含发现位负例、贸易中心有／无的真实分支 | 156 planned和partial缺项；资源译文、潜在资源、完整提示／可见性，外国实力及规则 |
| 阶段三 | B01–B04已有22 partial /3 planned字段及采集、解析、持久化、订阅路径 | B03撤退／歼灭、B04完整文本及其它事件生命周期 |
| 阶段四 | 新来源定向测试、原始重放和交付关联、完整回归比较 | 全目录并发、热更新、重启／读档及失败恢复的完整组合 |

| 前缀 | 主题数 | available | partial | planned |
| --- | ---: | ---: | ---: | ---: |
'''+ '\n'.join(groups)+f'''

第81批唯一full为{result}，既有141项失败／错误保留，新增0，整套仍未全绿；{frozen['count']}选定来源已冻结复核。见[比较](../{stage}/regression-comparison-001.json)及[独立审计](../{stage}/{AUDIT})。

本批5份private和{mcp['archived_capture_count']}份MCP原件均可重放，四个MCP对象含已发现185的无贸易中心分支及2000未知负例。资源键不是已译名称，sprite键不是实际渲染，双遍一致不是原子快照。范围见[接口](省份所有者与控制者查询.md)。80批清单保留[原件](../{stage}/historical-docs/信息计划验收清单-80.md)。

64批法国事件正例与74批v33窗口分别解释，不互补未采字段。B03 annihilation/retreat及B04 raw_text仍planned；具体UI／消息差异尚须查证。当前身份和禁重放规则见[HANDOFF](../HANDOFF.md)。
''',encoding='utf-8',newline='\n')
    progress=ROOT/'docs/信息导出开发进展.md';text=progress.read_text(encoding='utf-8-sig')
    block='<!-- acceptance-current-81:start -->\n'+short.replace('LINK','省份所有者与控制者查询.md')+'\n<!-- acceptance-current-81:end -->'
    text,n=re.subn(r'<!-- acceptance-current-80:start -->.*?<!-- acceptance-current-80:end -->',block,text,count=1,flags=re.S)
    assert n==1;progress.write_text(text,encoding='utf-8',newline='\n')
    docs=['HANDOFF.md','README(agent).md','docs/信息导出与订阅开发计划.md','docs/省份所有者与控制者查询.md',
        'docs/信息计划验收清单.md','docs/信息导出开发进展.md','docs/信息字段覆盖.json']
    for name in docs:copy(ROOT/name,STAGE/'doc-mirrors-001'/name)
    write(STAGE/'development-summary-001.json',{'schema':'information.province_production.development_summary.v1',
        'batch':81,'status':'partial_feature_verified','goal_complete':False,
        'goal_scope':'74 topics /397 fields; complete stages2/3/4 and B01-B04 remain active',
        'coverage':counts,'actual_live_counts':read(STAGE/'coverage-update-001.json')['actual_live_counts'],
        'source_count':frozen['count'],'freeze':pin(STAGE/'source-freeze-001.json'),
        'postverify':pin(STAGE/'source-post-run-verification-001.json'),
        'regression':dict(pin(STAGE/'regression-comparison-001.json'),totals=totals),'profile':profile,
        'positive':pin(STAGE/'private-live-probe-001.json'),'negative':pin(STAGE/'private-discovery-negative-001.json'),
        'center_zero':pin(STAGE/'private-center-zero-001.json'),'mcp':pin(STAGE/'mcp-live-001/receipt.json'),
        'independent_raw_audit':pin(STAGE/AUDIT),'raw_capture_count':raw_count,
        'actual_UI_observed':False,'full_visibility_proved':False,'resource_translated_name_captured':False,
        'docs':[pin(ROOT/name) for name in docs]})
    rows=[pin(path) for path in STAGE.rglob('*') if path.is_file()
        and not any(part.startswith('source-snapshots-') or part=='__pycache__' for part in path.parts)
        and path.name!='final-evidence-index-001.json']
    write(STAGE/'final-evidence-index-001.json',{'schema':'information.province_production.selected_evidence_index.v1',
        'scope':'Selected stage artifacts including failures, ordinary/REA evidence, history/docs; excludes source snapshots/cache/index itself',
        'count':len(rows),'files':sorted(rows,key=lambda row:row['path'])})
    verify_sources();print({'status':'published_partial','sources':frozen['count'],'artifacts':len(rows),'totals':totals})


if __name__=='__main__':main()
