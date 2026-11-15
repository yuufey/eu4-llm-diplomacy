"""Publish batch-77 handoff and a selected artifact index after verification."""
from collections import deque
import json
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.verify_information_country_faith import STAGE,read,write,pin,verify_sources,REVISION


def main():
    frozen=verify_sources();regression=read(STAGE/f'regression-comparison-{REVISION}.json')
    audit=read(STAGE/'independent-live-audit-001.json');review=read(STAGE/'shared-capture-review-003.json')
    assert regression['no_new_bad'] is True and audit['status']=='passed'
    mcp=read(STAGE/'mcp-live-001/receipt.json');probe=read(STAGE/'private-live-probe-002.json')
    assert mcp['status']==probe['status']=='passed' and mcp['server_exit_code']==0
    with (STAGE/f'regression-full-{REVISION}.log').open(encoding='utf-8',errors='replace') as stream:
        tail=''.join(deque(stream,maxlen=20))
    totals={key:int(re.search(r'(\d+) '+re.escape(key),tail).group(1))
            for key in ('passed','failed','errors','subtests')}
    matrix=read(ROOT/'docs/信息字段覆盖.json');counts=matrix['counts'];field_counts=counts['field_counts']
    fraction=f"{field_counts['available']} available/{field_counts['partial']} partial/{field_counts['planned']} planned"
    result=f"{totals['passed']} passed/{totals['failed']} failed/{totals['errors']} errors/{totals['subtests']} subtests"
    full_refs={}
    for tag in ('ENG','FRA'):
        capture=read(STAGE/f'private-live-{tag.lower()}-002.json')
        full_refs[tag]=capture['observation']['backend']['targets'][0]['fullref']
    text=(f"## 第77批：先以实采确认字段含义，主宗教名称已接入\n\n"
        "保持物理玩家POR、逻辑观察及操控方为非玩家FRA，不切国制造UI。先确认具体数据和路径，不因缺少消息记录就推断AI没有原生消息；完整74主题397字段、阶段2/3/4与B01–B04目标不变，goal active。\n\n"
        "S02.faith新增主宗教名称缓存、EU4 escape原始编码及图标帧请求，均partial；FRA本国及foreign目标分开按完整ref绑定。初始把定义+b0暂按配置键解释，实际9B输入10295911494e105965使ASCII校验返回unknown；原profile/两份采样/失败收据保留。现v2严格解码为“天主教”，不称配置键、宗教ID或实际UI。见[接口说明](docs/非玩家观察方的主宗教查询.md)。\n\n"
        "新增foreign_country_memory按字段共用完整国家解析、FRA准入及双遍比较：已知拒绝不读字段；共享身份/准入变化全体撤回，单字段变化只撤回该字段。shared owner复用进程、会话、ROM、日期、关闭和ordered trace；已修失败RPM操作的确定性错误重放，校验cleanup以及access flags/调用数/字节预算，新faith必须有access元数据。未知值不伪造成字节或零；旧F02包形状和scope保留，最终旧接口31项通过。\n\n"
        "实际v33/PID30548/session30548-1dd66f8c50752e2、EXE B23与125 native/build copies/DLL不变；两份002实采均Human1/FRA controller0、物理POR、raw56564448，ENG和FRA均名称“天主教”/icon1，完整ref分别为"+full_refs['ENG']+"、"+full_refs['FRA']+"。无保存、重启、注入、日期推进、切国、业务派发或Computer Use。真实MCP一次主动/一次报告、2秒两次/5秒一次交付一致，实际5份capture逐份归档，订阅取消、server0。独立审计只核raw capture及交付关联，不称实际UI或LLM已读。\n\n"
        f"正式{frozen['count']}份选定来源在唯一full前冻结并在结束后复核。full为{result}，Counter既有141→141、新增和解决均空，整套仍非全绿。generic最终11项、leaf名称最终26项、公共投影最终27项及capture专项结果见原收据；所有失败尝试保留。公共专项误写的目录information-country-faith-20261029-001保留原路径，不搬移或补造边界。REA四个窄查询复用只读completed cache，DB未变；人物渲染/摄政条件与外交listbox分开记录，不以它们证明完整人物或领土字段。\n\n"
        f"覆盖74/397、{fraction}、{counts['callable_topic_count']} callable；只将S02.faith planned→partial。法国新战报正例、完整B04及其余阶段继续。旧检查点不得回载重播、历史120及successful/dispatched/unknown/final-pass/未闭合ownership禁止重试，尤其SIE→FRA military_access proposal1、r70_country_money_001_outbound、r71_country_por_to_fra_001及r71_country_fra_to_por_001。完整证据见work/runtime/information-foreign-scalars-20261029-001/development-summary-001.json和final-evidence-index-001.json。\n")
    marker='batch77-country-faith-current'
    for name in ('HANDOFF.md','README(agent).md','docs/信息导出与订阅开发计划.md'):
        path=ROOT/name;previous=path.read_text(encoding='utf-8-sig')
        assert marker not in previous
        body=text if name=='HANDOFF.md' else (f"## 第77批：非玩家观察方的主宗教名称\n\nS02.faith已接入当前主宗教缓存名称、原始EU4 escape编码和图标帧请求，均partial。首轮实采拒绝了错误的配置键解释，修正后法国和英国均取得“天主教”/icon1；逻辑观察方仍为非玩家FRA，物理玩家POR，raw56564448不变。查询、报告及2秒/5秒周期交付通过，5份实际MCP capture保留、订阅取消、server0。见[接口说明]("+('docs/' if name=='README(agent).md' else '')+"非玩家观察方的主宗教查询.md)。\n\n"+f"唯一full为{result}，相对76批无新增失败，整套仍非全绿；{frozen['count']}份选定来源pre-full冻结并复核。覆盖74/397、{fraction}、{counts['callable_topic_count']} callable。完整阶段2/3/4、B01–B04和法国战报新正例继续，goal active。最新身份、失败尝试、独立审查及禁重试规则见HANDOFF顶部。\n")
        path.write_text(f'<!-- {marker}:start -->\n'+body+f'<!-- {marker}:end -->\n\n'+previous,encoding='utf-8',newline='\n')
    docs=['HANDOFF.md','README(agent).md','docs/信息导出与订阅开发计划.md','docs/非玩家观察方的主宗教查询.md','docs/信息字段覆盖.json']
    mirrors=STAGE/'doc-mirrors-001'
    for name in docs:
        target=mirrors/name;target.parent.mkdir(parents=True,exist_ok=True)
        with (ROOT/name).open('rb') as source,target.open('xb') as destination:
            while block:=source.read(1024*1024):destination.write(block)
    summary={'schema':'information.country_faith.development_summary.v1','batch':77,'status':'partial_feature_verified',
        'goal_complete':False,'goal_scope':'74 topics /397 fields; complete stages2/3/4 and B01-B04 remain active',
        'coverage':counts,'actual_live_counts':read(STAGE/'coverage-update-002.json')['actual_live_counts'],
        'regression':dict(pin(STAGE/f'regression-comparison-{REVISION}.json'),totals=totals),
        'freeze':pin(STAGE/f'source-freeze-{REVISION}.json'),'source_count':frozen['count'],
        'postverify':pin(STAGE/f'source-post-run-verification-{REVISION}.json'),
        'private_probe':pin(STAGE/'private-live-probe-002.json'),'mcp':pin(STAGE/'mcp-live-001/receipt.json'),
        'independent_raw_audit':pin(STAGE/'independent-live-audit-001.json'),
        'shared_owner_review':pin(STAGE/'shared-capture-review-003.json'),
        'native_findings':pin(STAGE/'native-field-findings-001.json'),
        'initial_key_interpretation_withdrawn':True,'actual_UI_observed':False,
        'extra_public_test_stage':'work/runtime/information-country-faith-20261029-001/faith-public-targeted-001',
        'docs':[pin(ROOT/name) for name in docs]}
    write(STAGE/'development-summary-001.json',summary)
    rows=[]
    for path in STAGE.rglob('*'):
        if (path.is_file() and not any(part.startswith('source-snapshots-') for part in path.parts) and '__pycache__' not in path.parts
                and path.name!='final-evidence-index-001.json'):
            rows.append(pin(path))
    extra=ROOT/'work/runtime/information-country-faith-20261029-001/faith-public-targeted-001'
    for path in extra.rglob('*'):
        if path.is_file() and '__pycache__' not in path.parts:rows.append(pin(path))
    write(STAGE/'final-evidence-index-001.json',{'schema':'information.country_faith.selected_evidence_index.v1',
        'scope':'selected stage artifacts, 5 doc mirrors, and public tests in their actual separate directory; excludes source snapshots/cache/index itself',
        'count':len(rows),'files':sorted(rows,key=lambda x:x['path'])})
    verify_sources();print(json.dumps({'status':'published_partial','source_count':frozen['count'],'evidence_count':len(rows),'totals':totals},ensure_ascii=False))


if __name__=='__main__':main()
