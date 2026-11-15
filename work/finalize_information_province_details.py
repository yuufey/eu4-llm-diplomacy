"""Publish the verified three-field extension without closing the full goal."""
from collections import deque
from pathlib import Path
import re
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.verify_information_province_details import STAGE,read_json as read,write_new as write,pin,verify_sources


def prepend(path,marker,body):
    assert path.stat().st_size<4*1024*1024
    old=path.read_text(encoding='utf-8-sig');assert marker not in old
    path.write_text(f'<!-- {marker}:start -->\n{body}\n<!-- {marker}:end -->\n\n'+old,
        encoding='utf-8',newline='\n')


def copy(source,target):
    target.parent.mkdir(parents=True,exist_ok=True)
    with source.open('rb') as inp,target.open('xb') as out:
        while block:=inp.read(1024*1024):out.write(block)


def main():
    frozen=verify_sources();comparison=read(STAGE/'regression-comparison-001.json')
    audit=read(STAGE/'independent-live-audit-003.json');mcp=read(STAGE/'mcp-live-001/receipt.json')
    positive=read(STAGE/'private-live-probe-001.json');negative=read(STAGE/'private-discovery-negative-001.json')
    assert comparison['no_new_bad'] and audit['status']==mcp['status']==positive['status']=='passed'
    assert negative['status']=='passed_negative' and mcp['server_exit_code']==0
    assert mcp['archived_capture_count']==15 and mcp['periodic_counts']=={'2':2,'5':1}
    with (STAGE/'regression-full-001.log').open(encoding='utf-8',errors='replace') as stream:
        tail=''.join(deque(stream,maxlen=20))
    totals={key:int(re.search(r'(\d+) '+re.escape(key),tail).group(1))
        for key in ('passed','failed','errors','subtests')}
    result='/'.join(f'{totals[key]} {key}' for key in ('passed','failed','errors','subtests'))
    matrix=read(ROOT/'docs/信息字段覆盖.json');counts=matrix['counts']
    assert counts['field_counts']=={'available':62,'partial':176,'planned':159}
    profile=pin(ROOT/'bridge/information/profiles/province-state-memory-1374-v2.json')
    stage=STAGE.relative_to(ROOT).as_posix()
    guide='''# 省份状态查询

G02 现支持所有者、控制者、文化、宗教和自治度五字段。观察方为非玩家法国（FRA）；物理玩家保持葡萄牙。只读取已确认法国发现位为1的省份，证据不足返回unknown，没有value。

```json
{"topic":"G02","object":{"type":"province","province_id":183},"fields":["owner","controller","culture","religion","autonomy"],"parameters":{}}
```

| 字段 | value示例 | 单位与含义 |
| --- | --- | --- |
| owner | FRA | country_tag，scale=1；当前所有者 |
| controller | FRA | country_tag，scale=1；当前控制者，单独验证 |
| culture | {"name":{"text":"法兰西","raw_hex":"10d56c107051107f89","encoding":"eu4_escape"}} | 名称缓存，不含接受度颜色前缀 |
| religion | {"name":{"text":"天主教","raw_hex":"10295911494e105965","encoding":"eu4_escape"},"icon_frame_request":1} | 名称缓存与有符号图标帧请求，不代表已渲染 |
| autonomy | 25000 | percent，scale=1000，即25%；示例值并非本批实采值 |

五字段均为partial、complete=false，可单独或共同查询，并放入报告和周期订阅。province_id为1..65535的整数且必须存在于当前省份数组，不接受额外参数。

父级每遍分别核对FRA完整国家引用、Human1/FRA controller0、规范省份记录与ID，再检查FRA槽的发现位。位0不读取这五个字段；unknown不等于证明不可见。完整可见性规则仍在研究。

文化、宗教读取原生面板使用的定义指针及有界String32名称，严格按EU4 escape解码。原生键、接受度前缀及完整提示未提供。自治度按min(max(current,lower),upper)计算，再将显示下限设为0；公开整数保留格式化前精度。原生面板随后转浮点并请求一位小数，这里不宣称完整UI文字一致。

共享身份或发现证据变化会撤回全部字段；单字段原始数据变化只撤回该字段。双遍读取不等于原子快照，也不证明缓存刷新时点。无主及特殊国家引用仍unknown。

本批实际183为FRA/FRA、文化法兰西，236为ENG/ENG、文化英格兰；两者宗教天主教、帧请求1、自治度0。2000发现位0，五字段unknown且没有字段数据读取。真实查询、报告及2秒/5秒周期交付一致，订阅已取消。18份原始capture重放和21组公开fields关联已独立核对，结果列表中的manual副本不算额外采集。

发展度、资源和贸易中心三字段仍planned。原生面板存在所有者相关按钮及颜色分支，这些静态路径不能证明非玩家国家没有信息或消息；本批未观察FRA实际UI。完整74主题397字段、阶段二/三/四和B01–B04继续开发。
'''
    old_guide=ROOT/'docs/省份所有者与控制者查询.md'
    acceptance=ROOT/'docs/信息计划验收清单.md'
    copy(old_guide,STAGE/'historical-docs/省份所有者与控制者查询-79.md')
    copy(acceptance,STAGE/'historical-docs/信息计划验收清单-79.md')
    old_guide.write_text(guide,encoding='utf-8',newline='\n')
    short=("## 第80批：先确认具体读取路径，再接入省份文化、宗教和自治度\n\n"
        "G02新增culture/religion/autonomy三字段partial，连同owner/controller支持五字段查询、报告和周期订阅。物理玩家POR、逻辑观察及操控方非玩家FRA不变；按钮权限与信息读取分开，不先假定非玩家没有UI或消息。见[接口说明](LINK)。\n\n"
        "实际183文化法兰西、236英格兰，两者宗教天主教/frame1、自治度0；2000发现位0，五字段unknown且无字段数据读。18份raw重放、21组fields关联通过；15份实际MCP capture，2秒2次/5秒1次，取消订阅/server0。未执行游戏函数、保存、重启、注入、推进、切国或Computer Use。\n\n"
        f"唯一full为{result}，Counter141→{comparison['current_bad_occurrences']}，新增0；整套仍非全绿。{frozen['count']}选定来源已冻结复核，配置62 available/176 partial/159 planned、46 callable，实际live56/140/201、41 callable。完整74/397及阶段2/3/4、B01–B04继续，goal active。\n")
    technical=(f"\nprofile-v2为{profile['bytes']}B/SHA{profile['sha256']}，7段原生ROM guard；v1原字节保留。父级只在FRA角色、自身准入及省份发现位均通过后调用有界leaf；新generic callback保留默认owner/controller行为、共享预算与逐字段撤回。名字仅缓存，不含接受度色前缀；religion frame是signed-i32输入；autonomy为max(0,min(max(current,lower),upper))的百分数千分整数。\n\n"
        "REA链：1347920→1376a10存panel+20；136a7a0/vtable1d7bae8；136eed0调+10/+8，对应13762f0名称、1373ea0数值、136efe0宗教图标。所有RVA、范围、B23 SHA、REA IDs及限制见native-province-details-findings-001.json；普通PE表前缀和e318c0 flags单独记账。development实际caller flags0/1已确认，但effective helpers未闭合；resource/cot仍研究。13762f0的不可达块警告及去掉颜色前缀的范围明确保留，不扩称完整UI。\n\n"
        "当前v33/PID30548/creation134376782534496994/session30548-1dd66f8c50752e2，B23/Human1/FRA0/物理POR/raw56564448。125 native及125 build copies/DLL/manifest继承不变。primitive原14、generic34、scalar47、identity21、capture35、public75专项最后通过；失败runner/语法尝试、root合同脚本及audit001/002失败原件保留。80批caller审查误放79stage的文件不在79冻结/index，位置说明保留，未补证79。\n\n"
        "历史120/successful/dispatched/unknown/original-final-pass/未闭合ownership禁止重试，尤其SIE→FRA military_access proposal1、r70_country_money_001_outbound、r71_country_por_to_fra_001及r71_country_fra_to_por_001。旧35天checkpoint不回载重播；当前模块/patch/unwind仍至进程退出。继续发展度、资源、贸易中心、F01、完整B04和法国新正例，不把未采到消息当成AI没有消息。\n\n"
        f"全部本批收据、比较、摘要/index位于{stage}/。\n")
    for name in ('HANDOFF.md','README(agent).md','docs/信息导出与订阅开发计划.md'):
        link=('docs/' if not name.startswith('docs/') else '')+'省份所有者与控制者查询.md'
        body=short.replace('LINK',link)+(technical if name=='HANDOFF.md' else '')
        prepend(ROOT/name,'batch80-province-details-current',body)
    groups=[]
    for prefix in ('C','N','F','R','M','G','T','D','W','P','A','S','H','B'):
        topics=[t for t in matrix['topics'] if t['topic_id'].startswith(prefix)]
        cc={key:0 for key in ('available','partial','planned')}
        for topic in topics:
            for field in topic['fields'].values():cc[field['coverage']]+=1
        groups.append(f"| {prefix} | {len(topics)} | {cc['available']} | {cc['partial']} | {cc['planned']} |")
    acceptance.write_text('''# 信息计划验收清单

更新至第80批，2026-10-29。目标保持完整74主题397字段、阶段二/三/四和B01–B04，goal active。当前配置62 available /176 partial /159 planned、46主题可调用；本次实际live目录56/140/201、41主题可调用。partial不代表完成全部字段要求。

| 范围 | 当前证据 | 待完成 |
| --- | --- | --- |
| 阶段零/一 | 74/397合同、持久配置、版本、查询报告和周期框架；80批新增字段真实交付与取消通过 | 全部来源组合与跨会话恢复 |
| 阶段二 | 46主题部分可调用；G02五字段已有实采与未知负例 | 159 planned及partial缺项，含发展度、资源、贸易中心、外国实力和规则 |
| 阶段三 | B01–B04已有22 partial /3 planned字段及采集、解析、持久化、订阅路径 | B03撤退/歼灭、B04完整文本及其它生命周期缺口 |
| 阶段四 | 新来源定向、raw重放、公开交付关联及全回归比较 | 全目录、并发、热更新、重启/读档、失败恢复的完整组合 |

省份183/236的文化、宗教、自治度及所有者/控制者均有实采；2000发现位0，五字段未知且无字段读取。3 private与15 MCP capture独立重放、21组公开fields关联通过，2条manual列表副本不算额外采集。原始缓存、帧请求及双遍一致均不代表实际UI或原子快照。见[接口](省份所有者与控制者查询.md)。

| 前缀 | 主题数 | available | partial | planned |
| --- | ---: | ---: | ---: | ---: |
'''+ '\n'.join(groups)+f'''

第80批唯一full：{result}。既有141项失败/错误保留，新增0，整套仍未全绿；{frozen['count']}份选定来源已冻结复核。见[比较](../{stage}/regression-comparison-001.json)及[独立审计](../{stage}/independent-live-audit-003.json)。

64批法国战斗正例与74批v33窗口分别解释，不能互补未采字段。B03 annihilation/retreat及B04 raw_text仍planned；非玩家UI或消息是否不同须具体查证。当前身份和禁重放规则见[HANDOFF](../HANDOFF.md)。此前79批清单保留[原件](../{stage}/historical-docs/信息计划验收清单-79.md)。
''',encoding='utf-8',newline='\n')
    progress=ROOT/'docs/信息导出开发进展.md';text=progress.read_text(encoding='utf-8-sig')
    block='<!-- acceptance-current-80:start -->\n'+short.replace('LINK','省份所有者与控制者查询.md')+'\n<!-- acceptance-current-80:end -->'
    text,n=re.subn(r'<!-- acceptance-current-79:start -->.*?<!-- acceptance-current-79:end -->',block,text,count=1,flags=re.S)
    assert n==1;progress.write_text(text,encoding='utf-8',newline='\n')
    docs=['HANDOFF.md','README(agent).md','docs/信息导出与订阅开发计划.md','docs/省份所有者与控制者查询.md',
        'docs/信息计划验收清单.md','docs/信息导出开发进展.md','docs/信息字段覆盖.json']
    for name in docs:copy(ROOT/name,STAGE/'doc-mirrors-001'/name)
    write(STAGE/'development-summary-001.json',{'schema':'information.province_details.development_summary.v1',
        'batch':80,'status':'partial_feature_verified','goal_complete':False,
        'goal_scope':'74 topics /397 fields; complete stages2/3/4 and B01-B04 remain active',
        'coverage':counts,'actual_live_counts':read(STAGE/'coverage-update-001.json')['actual_live_counts'],
        'freeze':pin(STAGE/'source-freeze-001.json'),'source_count':frozen['count'],
        'postverify':pin(STAGE/'source-post-run-verification-001.json'),
        'regression':dict(pin(STAGE/'regression-comparison-001.json'),totals=totals),'profile':profile,
        'positive':pin(STAGE/'private-live-probe-001.json'),'negative':pin(STAGE/'private-discovery-negative-001.json'),
        'mcp':pin(STAGE/'mcp-live-001/receipt.json'),'independent_raw_audit':pin(STAGE/'independent-live-audit-003.json'),
        'actual_UI_observed':False,'full_visibility_proved':False,'docs':[pin(ROOT/name) for name in docs]})
    rows=[pin(path) for path in STAGE.rglob('*') if path.is_file()
        and not any(part.startswith('source-snapshots-') or part=='__pycache__' for part in path.parts)
        and path.name!='final-evidence-index-001.json']
    write(STAGE/'final-evidence-index-001.json',{'schema':'information.province_details.selected_evidence_index.v1',
        'scope':'Selected stage artifacts including failed attempts/history/doc mirrors; excludes source snapshots/cache/index itself',
        'count':len(rows),'files':sorted(rows,key=lambda row:row['path'])})
    verify_sources();print({'status':'published_partial','sources':frozen['count'],'artifacts':len(rows),'totals':totals})


if __name__=='__main__':main()
