"""Batch62 archive only. No game, test runner, or MCP invocation."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil

ROOT=Path(__file__).resolve().parents[1]
STAGE=ROOT/'work/runtime/information-battle-native-title-20261027-001'
BUILD=ROOT/'work/runtime/diplomacy-observer-20261027-information-battle-v30-002'
SUPPLEMENTS=(
    'work/research_information_battle_title_plugin_binding.py',
    'work/compare_information_battle_native_title_regression.py',
    'work/validate_information_battle_native_title_live_002.py',
    'work/validate_information_battle_native_title_live_003.py',
    'work/validate_information_battle_native_text_live_004.py',
    'work/archive_information_battle_native_title.py',
)


def read(path: Path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def pin(path: Path):
    path=path.resolve()
    with path.open('rb') as stream:
        digest=hashlib.file_digest(stream,'sha256').hexdigest()
    return {'path':path.relative_to(ROOT).as_posix(),
            'bytes':path.stat().st_size,'sha256':digest}


def put(path: Path, value):
    with path.open('x',encoding='utf-8',newline='\n') as stream:
        json.dump(value,stream,ensure_ascii=False,indent=2);stream.write('\n')


def snapshot():
    before=read(STAGE/'runtime-source-pins-before-002.json')
    current=[pin(ROOT/item['path']) for item in before['files']]
    if current!=before['files']:raise ValueError('frozen147_source_changed')
    destination=STAGE/'source-snapshots-final'
    destination.mkdir(exist_ok=False)
    snapshots=[]
    for item in current:
        target=destination/item['path']
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(ROOT/item['path'],target)
        actual=pin(target)
        if any(actual[key]!=item[key] for key in ('bytes','sha256')):
            raise ValueError('snapshot_mismatch:'+item['path'])
        snapshots.append({'source':item,'snapshot':actual})
    result={'status':'passed','timing':'after formal full002 completion',
            'files':current,'snapshots':snapshots,'count':len(current),
            'full_boundary':pin(STAGE/'full-execution-boundary-002.json')}
    put(STAGE/'runtime-source-pins-after-002.json',result)
    return {'status':'passed','source_snapshots':len(current)}


def finish():
    live=read(STAGE/'live-acceptance-003/report.json')
    regression=read(STAGE/'regression-comparison-002.json')
    native=read(STAGE/'disable-001.json')['response']
    installation=read(BUILD/'installation.json')
    frozen=read(STAGE/'runtime-source-pins-after-002.json')
    if live['status']!='passed' or not all(v is True for v in live['checks'].values()):
        raise ValueError('MCP_not_passed')
    if live['server_exit_code']!=0 or live['event_results']!=1:
        raise ValueError('MCP_result_count_or_exit')
    if regression['status']!='passed_no_new_failure_nodes':raise ValueError('new_regression')
    if native['state']!='disabled' or any(int(native[k])!=11 for k in (
        'captured','title_query_attempted','title_query_destroyed','title_query_copied')):
        raise ValueError('native_counts_or_state')
    if native['title_query_failures']!='0':raise ValueError('native_title_failure')
    if [pin(ROOT/item['path']) for item in frozen['files']]!=frozen['files']:
        raise ValueError('frozen_source_changed')
    title=live['query']['native_text']['title_helper_candidate']
    if title['decoded'].get('value')!='库内奥战役':raise ValueError('selected_title_changed')
    current_coverage=pin(ROOT/'docs/信息字段覆盖.json')
    expected_coverage=read(STAGE/'runtime-source-pins-before-002.json')['coverage_before']
    if current_coverage!=expected_coverage:raise ValueError('coverage_changed')
    supplemental=[]
    for relative in SUPPLEMENTS:
        source=pin(ROOT/relative)
        target=STAGE/'source-snapshots-supplemental'/relative
        target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as output, (ROOT/relative).open('rb') as input_stream:
            shutil.copyfileobj(input_stream,output)
        copied=pin(target)
        if any(source[k]!=copied[k] for k in ('bytes','sha256')):raise ValueError('supplement_copy')
        supplemental.append({'source':source,'snapshot':copied})
    put(STAGE/'supplemental-source-pins-001.json',{
        'timing':'independent diagnostics/comparison/archive and acceptance fixes; not part of formal147',
        'files':supplemental,'production_modified':False})
    put(STAGE/'coverage-update-001.json',{'status':'unchanged','topics':74,'fields':397,
        'available':60,'partial':159,'planned':178,'coverage':current_coverage,
        'full_phases':[2,3,4],'full_B01_B04':'incomplete','goal':'active'})
    summary={
        'schema':'information.battle.native_title.development_summary.v1','batch':62,
        'status':'progress','goal':'active','topics':74,'fields':397,
        'capability':'Guarded native title-helper output in B04.details.native_text.title_helper_candidate',
        'native':{'wire':6,'records':11,'title_attempted':11,'title_destroyed':11,
                  'title_copied':11,'title_failures':0,'source_state':'disabled'},
        'selected_title':title,'event_ids':live['event_ids'],'event_results':live['event_results'],
        'MCP':{'status':live['status'],'checks':live['checks'],'server_exit_code':0,
               'query_reused_offline':live['query_reused_offline'],
               'report_ids':live['report_ids'],'receipt':pin(STAGE/'live-acceptance-003/report.json')},
        'identity':live['identity'],'physical_player':'POR','observer':'FRA',
        'control':live['control_after'],'installation':pin(BUILD/'installation.json'),
        'manifest':pin(BUILD/'build-manifest.json'),'native_source_count':118,
        'regression':{'passed':3024,'failed':106,'errors':35,'subtests_passed':1936,
                      'new_test_nodes':len(regression['added_nodes']),'new_failure_nodes':0,
                      'whole_suite_green':False,'receipt':pin(STAGE/'regression-comparison-002.json')},
        'source_freeze':{'count':147,'receipt':pin(STAGE/'runtime-source-pins-after-002.json'),
                         'supplemental':pin(STAGE/'supplemental-source-pins-001.json')},
        'fixtures':{'owned_query_checks':12,'plan_guard_cases':19,'actual_observer_checks':124,
                    'plugin_callee_executed_in_fixture':False},
        'failed_history_retained':['v30-001 BridgeStart30 with no title invocation; no reinjection',
            'actual fixture003 compile failure; fixture004 initialization failure',
            'live001 expected/payload tuple reversal before MCP start',
            'live002 unselected report cannot answer selected-event query; original successful query reused by003',
            'full001 before compatibility correction; exact145 source snapshots retained'],
        'automation':{'corrective_restart_once':True,'checkpoint_reused':True,'new_save_for_corrective_restart':False,
                      'native_confirmation':True,'computer_use_in_corrective_restart':False,
                      'natural_window':'56560248 -> 56561088; one35-day TEST_ONLY request'},
        'archive_incident':pin(STAGE/'archive-incident-001.json'),
        'limitations':['candidate title only; complete GUI/title binding and visibility unverified',
                      'message metadata and Line1 remain unknown; raw_text unsupported',
                      'full74 topics/397 fields, phases2/3/4 and autonomous subscriptions remain unfinished'],
        'no_repeat':'Historical successful/dispatched/unknown actions, original final-pass IDs, unclosed ownership and original120-action batch remain forbidden; SIE->FRA military_access proposal1 and r70_country_money_001_outbound must not repeat',
    }
    put(STAGE/'development-summary-001.json',summary)
    marker='batch62-native-title-summary'
    paragraphs=(
        'v30/wire6已取得真实战报标题候选。一次35天自然观察raw56560248→56561088，11条战斗记录，11次标题调用、复制和销毁完成，失败0；法国事件1返回“库内奥战役”，原始字节与独立NTXT解析一致。标题候选不等同于完整窗口文字，消息元数据、Line1、可见性和完整B01–B04继续开发。',
        '真实MCP的查询、单场报告和不指定单场事件的订阅通过9项检查，事件1只交付一次，下一tick无重复，已取消且无活动订阅、server0。live003复用live002原成功query；live001参数顺序错误、live002报告配置错误均保留，修正只涉及独立验收脚本，没有重查已成功查询或重放游戏业务。',
        '正式full002为3024 passed、106 failed、35 errors，另1936子测试通过；新增4项全通过，新增失败节点0，既有失败错误仍141次、128节点。147项源码在full002前冻结并在结束后核对、留存精确副本；后续独立验收修正和归档脚本另列。覆盖仍74主题397字段、60 available/159 partial/178 planned；完整阶段2/3/4及LLM自主订阅继续，goal active。',
        '当前安装为work/runtime/diplomacy-observer-20261027-information-battle-v30-002/installation.json，PID36240、creation134375709192033676、session36240-1dd65fedcd5158c，EXE1.37.4 SHA b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77，DLL SHA747c8ec25fb88d630378726c1f73f936936d3ce4d50a21f44aceadf2351def3b，118 native sources。最后POR/slot189、raw56561088、speed0、paused1，采集disabled，五个入口补丁和展开资源仍随进程存在。旧PID27860已退出，禁止使用旧安装控制。',
        'v30-001被现有plugin64.dll的标题拼接跳转拦在启动guard，未调用标题函数。修正核对插件文件身份、原始代码、桥接片段、调用/返回槽和展开信息后，复用本批已保存checkpoint切换新DLL；不重复保存、不在同进程重新注入。新进程后台启动和原生确认完成载入，没有Computer Use。成熟成就窗口关闭入口另见《开发过程自动化.md》第4节，包含既有WM_CHAR小写c脚本。',
        '归档更正：本批代理误覆盖第61批regression-comparison-001.json，精确原件未恢复；其余207个旧归档件核对一致，原XML/log保留，另行复算仍为新增8项通过、无新增失败。使用本批batch61-regression-recomputed-001.json；不能继续声称旧archive整体哈希验证通过。详见archive-incident-001.json。',
        '历史successful/dispatched/unknown、原final-pass IDs、未闭合ownership和原120-action batch继续禁重试，尤其SIE→FRA military access proposal1和r70_country_money_001_outbound。下一步继续完整窗口文本、可见性及开发计划其余缺项。',
    )
    for relative in ('HANDOFF.md','README(agent).md','docs/信息导出与订阅开发计划.md'):
        path=ROOT/relative
        existing=path.read_text(encoding='utf-8-sig')
        if marker in existing:raise ValueError('documentation_already_updated')
        link='../work' if relative.startswith('docs/') else 'work'
        body='\n\n'.join(paragraphs)
        body+='\n\n归档入口：['+'第62批摘要'+f']({link}/runtime/information-battle-native-title-20261027-001/development-summary-001.json)。'
        block=f'<!-- {marker}:start -->\n## 第六十二批：实机战报标题候选\n\n{body}\n<!-- {marker}:end -->\n\n'
        path.write_text(block+existing,encoding='utf-8',newline='\n')
    text_path=ROOT/'docs/战报原生文本读取与传输.md'
    text_path.write_text('''# 战报原生文本读取与传输

第六十二批已通过v30在游戏原生战斗帧中生成标题候选，并以IBOW.v6/NTXT传输到B04。一次35天自然观察得到11条记录，11次标题调用均完成复制和销毁；来源已关闭，游戏保持暂停。

法国直接参战的事件1返回“库内奥战役”。公开字段位于 `details.value.native_text.title_helper_candidate`，包含 `raw_hex`、`codec=eu4_escape`、`source=title_helper_candidate` 和解码结果。独立手工NTXT解析核对原始字节，真实MCP查询、单场报告和不限定事件的订阅通过，事件只交付一次，下一tick无重复，订阅已取消、无活动订阅、server0。查询沿用live002原件；最终验收为live003。

消息定义key、辅助文字和Line1本次仍为unknown；`raw_text`仍为unsupported/FIELD_NOT_IMPLEMENTED_BY_ADAPTER。标题候选不是已验证的完整GUI窗口，`complete`与`full_display_complete`继续为false，可见性和完整B01–B04继续开发。

原生读取限制在已认证的帧线程、router、combat和kind1/2内。输出由调用者持有，复制后恰好销毁一次；来源图、代码、世界对象、玩家与日期在调用前后核对。当前插件会替换标题拼接的14字节，兼容入口仅接受已核对的插件文件SHA、桥接片段、callee/unwind和准确调用/返回槽；未放宽为任意外部跳转。

v30-001因这一已存在的跳转而启动失败，未调用标题函数；原件保留。v30-002在新进程安装一次，复用已保存的checkpoint和成熟原生确认。实际观察只提交一次35天TEST_ONLY推进，没有外交业务或构造战斗。关闭采集后，补丁、模块与展开资源仍随进程保留。

离线检查分别为：owned-output组件12项、代码guard19项、实际observer夹具124项。夹具执行原始标题helper和析构机器码，插件callee未在夹具执行；它的正负例仅检查代码guard。REA静态证据、普通PE/RPM读取、自有夹具执行与真实战斗调用分别记录。

正式full002为3024 passed、106 failed、35 errors，另1936子测试通过；新增4项通过，无新增失败节点。147项源码在full002前冻结并在结束后核对；独立验收脚本修正另列，不声称属于这次全回归。

当前结果见[第62批摘要](../work/runtime/information-battle-native-title-20261027-001/development-summary-001.json)和[真实MCP验收](../work/runtime/information-battle-native-title-20261027-001/live-acceptance-003/report.json)。第61批比较JSON曾被本批代理误覆盖，原XML/log未改；应使用[新复算收据](../work/runtime/information-battle-native-title-20261027-001/batch61-regression-recomputed-001.json)，不沿用旧archive的整体哈希通过结论。

此前第60批完成20条旧v5兼容回放和合成文字链路；第61批接入五个入口并取得16条真实v6记录，但当时没有标题、消息元数据或Line1候选。旧数据不因新版本而补填文字。
''',encoding='utf-8',newline='\n')
    docs=[ROOT/p for p in ('HANDOFF.md','README(agent).md','docs/信息导出与订阅开发计划.md',
                           'docs/战报原生文本读取与传输.md','开发过程自动化.md')]
    put(STAGE/'document-verification-001.json',{
        'status':'passed','documents':[pin(p) for p in docs],
        'checks':{'latest62_at_top':all(marker in p.read_text(encoding='utf-8').splitlines()[0] for p in docs[:3]),
                  'existing_warning_shortcut_documented':'confirm_observed_achievement_warning.py' in docs[-1].read_text(encoding='utf-8')}})
    paths=[p for p in STAGE.rglob('*') if p.is_file()]
    paths += [BUILD/'build-manifest.json',BUILD/'eu4_bridge_diplomacy_observer_v30.dll',BUILD/'installation.json']
    paths += [ROOT/'work/runtime/plugin-title-hook-source-001'/name for name in (
        'source-001.json','source-002.json','source-003.json','fun-1800373a0-375cb.bin',
        'fun-1800373a0-pdata.bin','fun-1800373a0-unwind-7bbb0.bin')]
    artifacts=[pin(p) for p in sorted(set(paths))]
    put(STAGE/'archive-verification-001.json',{
        'status':'passed','artifact_count':len(artifacts),'artifacts':artifacts,
        'runtime_source_snapshots':147,'supplemental_source_snapshots':len(supplemental),
        'historical61_archive_valid':False,'historical61_incident':pin(STAGE/'archive-incident-001.json')})
    return {'status':'progress','artifact_count':len(artifacts),'title':title['decoded']['value']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',nargs='?',choices=('snapshot','finish'))
    args=parser.parse_args()
    if args.phase is None:
        print(json.dumps({'status':'inert'}));return
    print(json.dumps(snapshot() if args.phase=='snapshot' else finish(),ensure_ascii=False))


if __name__=='__main__':main()
