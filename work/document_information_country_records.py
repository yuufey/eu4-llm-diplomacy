"""Publish batch52 only from the actual live and full-regression receipts."""
from __future__ import annotations
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.archive_information_country_records import STAGE,read,regression

MARKER='2026-10-27 第五十二批：'

def prepend(name,text,after_title=False):
    path=ROOT/name
    previous=path.read_text(encoding='utf-8')
    assert MARKER not in previous[:9000],name
    previous=previous.replace('第五十一批陆军职业度（最新）','第五十一批陆军职业度（历史）',1)
    if after_title:
        title,rest=previous.split('\n',1)
        content=title+'\n\n'+text.rstrip()+'\n\n'+rest.lstrip('\n')
    else:content=text.rstrip()+'\n\n'+previous
    path.write_text(content,encoding='utf-8',newline='\n')

def main():
    live=read(STAGE/'live-acceptance-001/report.json')
    coverage=read(STAGE/'coverage-update-001.json')
    result=regression()
    full,added=result['full'],result['new_tests']
    assert live['status']=='passed' and live['server_exit_code']==0 and all(live['checks'].values())
    assert not full['new_failure_nodes'] and not added['failure_error_occurrences']
    tests=(f"完整回归为{full['passed']}项通过、{full['failed']}项失败、{full['errors']}项错误，另{full['subtests_passed']}个子测试通过；"
           f"较51批新增失败节点{len(full['new_failure_nodes'])}、解决{len(full['resolved_failure_nodes'])}，全套仍非全绿。"
           f"新增{added['cases']}个用例均通过，已包含在完整统计中。")
    paragraph=(MARKER+'新增当前贷款及直接国家修正记录。N01返回3笔本金128、131、131杜卡特、利率均2%的贷款；贷款方映射及原始到期值的日历解释保留缺项。'
               'N07提供修正标识、目标及定义效果，N08提供原始起止日期、剩余期限与持续类型；当前两条修正剩余5341天和3063天，默认起始日期保持unknown。'
               '这8个字段均为partial，真实MCP主动查询、报告和三条两秒周期交付已与独立原始记录对照，订阅已取消。'
               '直接实例列表与全部修正来源、最终有效属性分开；名称、说明、来源、移除条件及N03完整军事修正继续开发。'
               '配置覆盖为60 available / 128 partial / 209 planned、40个可调用主题；本次实机目录为60 / 117 / 220、37个可调用主题，均74主题397字段。'
               +tests+'本批复用原进程和DLL。完整开发计划继续，调用见[国家贷款与当前修正只读接口](国家贷款与当前修正只读接口.md)。')
    for name in ('docs/信息导出与订阅开发计划.md','docs/信息接口使用说明.md'):
        prepend(name,paragraph,True)
    prepend('docs/信息导出开发进展.md','## 第五十二批：当前贷款与国家修正\n\n'+paragraph,True)
    prepend('docs/国家贷款与当前修正只读接口.md',
            MARKER+'本页8字段已通过真实MCP查询、报告及三条两秒周期交付，取消后无活动订阅，服务退出码0。'+tests,True)
    previous=(ROOT/'HANDOFF.md').read_text(encoding='utf-8').split('\n## ',1)[0]
    identity='\n\n'.join(p for p in previous.split('\n\n') if p.startswith('当前PID') or p.startswith('世界仍领先'))
    assert 'PID31460' in identity and 'SIE→FRA' in identity
    handoff=('## 2026-10-27 第五十二批当前贷款与国家修正（最新）\n\n'
             +paragraph.replace('[国家贷款与当前修正只读接口](国家贷款与当前修正只读接口.md)','docs/国家贷款与当前修正只读接口.md')
             +'\n\n归档入口work/runtime/information-country-records-20261027-001/development-summary-001.json。'
             '新增NativeCountryRecordsSource：N01.loans、N07.modifier_id/target/effects、N08.modifier_start_date/modifier_end_date/remaining_days/duration_type。'
             'N01与原NativeCountryStateSource共享同一参数合同，loans-only不需要reference_recipient；月度三个账本字段与N04六字段实机保留。'
             '\n\n普通PE country writer2DC6E0..2E125B中R15=country、RSI=output，2E0076..2E00D9沿country+1F0、node+0 item、node+10 next写token2968 modifier。'
             'REA114B00返回item+30 definition；实机vtable1CE7F08/+8→D2F280 wrapper→+10 B359E0，后者读取definition+158 SSO稳定key及INSTANCE+40/+44日期、+48..4B flags。'
             'definition+58/+64是8B {index,signed32raw}效果列表，8E67C0以manager=*(base+2358060)、stride60、record+50 selector输出，246BF0 signed /1000。'
             '每个效果的业务单位、激活与最终属性未闭合，不能将这些定义值标为最终生效值。Source003枚举token仅选定2968链闭合；其余模式命中仍是候选。'
             'Source004开头2E0020未对齐，原件保留，005从已确认边界2E0076重新闭合；无整映像反汇编。'
             '\n\n328CA0的AddTemporaryModifier将nonnegative days*24+game+1DD0 currentRaw传给B35620，写instance+44；negative duration使用静态43800000。'
             '构造默认43808760在serializer中省略，不能当真实起始日期。finite remaining raw=end-current，unitdays/scale24，不钳制过期负值；无固定到期与默认unknown分开。'
             'country-modifiers-source-contract002 SHA3fd682f918ccb7a54b281cc799291fe58db61e02953c6d631e799511bf933a89明确各offset对象基址。'
             '\n\nRoot审查发现modifier初版把日期flags从definition读出、fixture镜像同错，还引入未经证明的header count/tail/prev约束。'
             '最终v2改为instance字节与head/next NUL终止+cycle/max128，并用独立raw002重放；v1 profile SHA6cd3c0cf0c705b190741458e0359e6f4597ef11e847fbd41bc42533d2a34dc2f保留。'
             '启用v2 SHAda533caf9d3c9bfb21f8fd56bd197ab5935f5aaa1b5e48a861f0fba6c54a4c76。母reader增加strict include_country_loans/include_country_modifiers，top/before/after、doublepass和cleanup/context撤回统一处理。'
             '\n\n贷款country+DE8 intrusive list由独立source001闭合，lender fullref+20、interest signed32+28 /1000 percent、principal signed32+2C whole ducats、due raw+30。'
             '当前raw三条128/131/131、interest2000、lender2d2d2d0000000000、due56590344/56593392/56598528。'
             'profile SHA8c3ab5ed8c72e859d2af6d1a8f689901de94243ca903c6af0a103ed32af9e481；vtable限制EXE rdata与method text，精确RTTI仍未闭合。'
             '实机vtable1CBC338与86AEC0/D2F280/86B110静态补充单独保存。参考脚本VA误作hex-bytes已修正，probe预算改预扣；非空raw replay真实validator通过。'
             '\n\n独立modifier RPM001/002与loan RPM001均双遍一致/closed，0native/gamecall。modifier expected001 SHAf2ddec02933ff2ffa0b3176da1b3d9fa430655682575f4b69c706d16426de3f9和loan expected001由原始字节独立重算，均不导入新production reader、不从MCP回填。'
             '修复reader/validator后重放原raw，没有新增采样。5次新REA cached函数查询均accepted、库不变、noanalysis/closed；普通PE、REA、RPM和MCP分层。'
             'MCP新字段、同topic月度混合、default显式缺项、N04六字段、report/3periodic/cancel/noactive/serverexit0通过；outboxdelivered/llm_readunknown。'
             '\n\nN04仅父依赖重绑domestic v6 SHA4b1903a49e3f84ad4802fcd1a03229f208bb475587ac6b7bbefbe3b0b13f235b，v5保留、native布局/guards不变。'
             'coverage helper先遗漏N01既有owner、又把配置任务覆盖与未启用任务的实机目录相比；均在原discovery上离线修复，无MCP重跑。'
             +tests+'配置60/128/209、40callable；actual60/117/220、37callable。完整74主题397字段、阶段2/3/4、自主订阅及完整B01–B04继续goal active。'
             '\n\n'+identity+
             '\n\n历史完整性：39两份wiring-tests001 XML/log原字节仍未恢复，旧pin不改；45草稿已按原SHA重建，46至51原件保留。'
             '本批新stage排他收据、源码冻结及before/after pins、实机/全回归/文档统一收尾，自有shell/MCP/worker终态。'
             '下一步补贷款方银行/外国映射、到期日历、当前修正名称/说明/来源与条件；N03完整军事分类、N01完整预算、R01关系网及B01–B04继续开发。'
             'R01现有selected-pair relationship_state来源已离线核对，见information-relations-20261027-001/relation-source-001.json；不把pending/legality当现有关系。')
    prepend('HANDOFF.md',handoff)
    readme=('## 2026-10-27 第五十二批当前贷款与国家修正（最新）\n\n'
            +paragraph.replace('](国家贷款与当前修正只读接口.md)','](docs/国家贷款与当前修正只读接口.md)')
            +'\n\n先读HANDOFF最新节及52批development-summary-001.json。当前PID31460/session31460-1dd653f69242d7b/date56557728/v27-002，physicalPOR/observerFRA。'
            'modifiers v2只读直接实例列表，日期来自instance、key/effects来自definition，仍partial；身份、no-repeat及历史完整性见HANDOFF。')
    prepend('README(agent).md',readme)
    print(json.dumps(dict(documents_updated=6,tests=full['summary_line'],new_cases=added['cases'],counts=coverage['counts']),ensure_ascii=False))

if __name__=='__main__':main()
