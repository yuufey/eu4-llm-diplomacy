"""Write batch43 documentation from final acceptance and regression records."""
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
STAGE=ROOT/"work/runtime/information-trade-state-20261027-001"


def prepend(relative,text,after_title=False):
    path=ROOT/relative
    assert path.stat().st_size<2*1024*1024
    raw=path.read_text(encoding="utf-8")
    assert "第四十三批" not in raw[:4000]
    if after_title:
        title,rest=raw.split("\n",1)
        raw=title+"\n\n"+text.rstrip()+"\n\n"+rest.lstrip("\n")
    else:
        raw=text.rstrip()+"\n\n"+raw
    raw=raw.replace("第四十二批贸易收入（最新）","第四十二批贸易收入（历史）",1)
    path.write_text(raw,encoding="utf-8",newline="\n")


def main():
    live=json.loads((STAGE/"live-acceptance-001/report-004.json").read_bytes())
    view=json.loads((STAGE/"live-object-view-001/report-002.json").read_bytes())
    coverage=json.loads((STAGE/"coverage-update-001.json").read_bytes())
    assert live["status"]==view["status"]=="passed"
    with (STAGE/"regression-full-002.log").open("rb") as stream:
        stream.seek(0,2)
        stream.seek(max(0,stream.tell()-8192))
        tail=stream.read().decode("utf-8",errors="replace")
    line=[line for line in tail.splitlines() if " passed" in line and " in " in line][-1]
    def count(label):
        match=re.search(r"(\d+) "+label+r"\b",line)
        return int(match.group(1)) if match else 0
    counts={key:count(key) for key in ("passed","failed","errors","subtests passed")}
    regression=f"最终完整回归为{counts['passed']}项通过、{counts['failed']}项失败、{counts['errors']}项错误，另{counts['subtests passed']}个子测试通过；全套仍非全绿。"
    figures=lambda item:f"{item['field_counts']['available']} available / {item['field_counts']['partial']} partial / {item['field_counts']['planned']} planned"
    paragraph=("2026-10-27 第四十三批：T02 `home_node` 已接入原生本埠标志，当前 FRA 返回 `champagne`。真实查询、报告和三条两秒周期结果与独立采样一致；字段保持 partial、complete=false。"
               "组合层新增按字段选择适配器，T02 的本埠状态与静态上游、线路可共同使用；字段各自保留对象范围和触发能力。节点对象的默认查询继续返回线路，本埠字段标为 not_applicable；静态线路仍仅支持主动查询，周期订阅会被明确拒绝。"
               f"配置矩阵为 {figures(coverage['counts'])}、{coverage['counts']['callable_topic_count']}个可调用主题；本次启用静态、未启用任务/战报来源的实机目录为 {figures(coverage['actual_live_counts'])}、{coverage['actual_live_counts']['callable_topic_count']}个可调用主题，均为74主题397字段。"
               +regression+"本批未保存或重启游戏、未换DLL、推进日期或执行外交业务。完整目标继续开发，调用方式见[本埠贸易节点接口](本埠贸易节点接口.md)。")
    prepend("docs/信息导出与订阅开发计划.md",paragraph,True)
    prepend("docs/信息导出开发进展.md","## 第四十三批：本埠节点与同主题字段分流\n\n"+paragraph,True)
    prepend("docs/信息接口使用说明.md",paragraph,True)
    contract=("## 同主题字段来自不同适配器\n\n"
              "组合层允许不同适配器实现同一主题中的不同字段；重复拥有同一字段仍会被拒绝。每个字段保留自己的对象类型、版本和触发能力，订阅按实际请求字段校验。"
              "例如 T02.home_node 接受 FRA 国家对象并支持周期读取；静态 upstream/routes 接受节点对象并仅支持主动查询。主题列出的触发方式是各来源的合集，调用者还应查看字段的 triggers。\n\n"
              "一个查询可以读取多个来源的字段。组合层只向各来源发送其负责的字段，并分别保留来源、失败原因及静态/实时范围；实时来源不可用或会话变化时，仍保留有效的静态结果。"
              "默认字段跨越不同对象视角时，当前视角不适用的字段单独返回 not_applicable，不阻断其他字段。只请求不受支持的对象视角时仍会明确拒绝。"
              "各适配器对同一查询的参数 schema 和对象规范化结果必须一致，否则整体拒绝配置。主来源继续独立轮询事件，读取适配器不会增加事件消费者。")
    prepend("docs/信息服务合同.md",contract,True)
    interface=ROOT/"docs/本埠贸易节点接口.md"
    raw=interface.read_text(encoding="utf-8")
    raw+="\n\n"+regression+" 新增用例已包含在完整统计中，不与定向测试重复累加。默认节点查询修正后的实机结果见 `live-object-view-001/report-002.json`。\n"
    interface.write_text(raw,encoding="utf-8",newline="\n")
    handoff=f"""## 2026-10-27 第四十三批本埠节点与字段分流（最新）

T02.home_node已接入真实MCP query/report/periodic，FRA当前champagne，独立rawAD=1/hex01，全部80真节点唯一非零。partial/completefalse，basis native_trade_node_home_flag，origin derived_from_copied_native_flags；value是ASCII node_id字符串，原生byte另存native_home_flag_raw/raw_hex。新profile home-trade-node-memory-1374 SHA3090fc60dd6c99b03adb1e1e317069cc37de5816422bb5eb814dfede8124e957，source-index fca029b41fbd17c271a5d880d659e8562914e7b7a73ae506983dba0c1386c56f，5guards283B。旧trade-income profile1375800668ed0ddec29d2e5f8efe8e1369d1e4da8b0aa6916b5b970078b137cd/旧countryprofile均不改。完整74topics397fields、阶段2/3/4、LLM自主订阅、完整B01–B04继续goal active。先读docs/外交开发推进复盘.md、docs/本埠贸易节点接口.md；集中入口work/runtime/information-trade-state-20261027-001/development-summary-001.json。

home_trade_node_memory复用已验证trade_income完整graph与source digest，附加本埠guard/AD读取，恰好一个AD非零才known；零/多候选明确unknown。母capture显式include_trade_income=True/include_home_trade_node=True，后者严格bool并要求前者；默认旧三点/旧income-only不变。top/before/after、双遍、cleanup撤回覆盖home；NativeTradeHomeSource复用母报告/旧trade三份校验再验证新child三份和前后context。高层测试003及reader测试实际使用真实profile/fakeboundedreader/validator，不把早期stub测试当最终证据。

有界普通PE：B58C40按fullref signed slot、runtime+18 table、strideC0返回entry+AD；UI13D4143输入来自所选country+20，AL非零选TRADE_TRANSIT_NODE_CAPITAL，磁盘英文localization明确home node，source报告分层固定getter/调用窗口/字节/localeSHA。AD=home已闭合；AC/AE merchant_task、collection、transfer映射仍未证明，不能猜。REA仅binary_session inventory(openfalse)，无新默认Ghidra全映像尝试。生产amount A11920/A12C20新增ABI合同，unit/TLS/缓存未闭合，当前完整预算仍未实现。

CompositeSource现允许同topic不重叠字段，重叠仍duplicate_adapter_topic，参数schema或规范化冲突拒绝。query_catalog/query_capabilities按实际owner处理scope/version/observer/triggers；service订阅不能因topic trigger合集给query-only字段授权。多来源结果保留各field_context_scopes和source，live失败/跨会话不吞static成功；主poll事件只一次。T02home国家对象和Static节点路线共存。默认trade_node全字段曾被country-only owner阻断，已修正：有适用owner时跳过不适用owner校验、该字段not_applicable；仅请求不适用owner仍invalid_object。source-revision-001固定原MCP版本与最终版本差异（仅Composite），before002/after002固定最终源码，不能把before001当最终相同。

原native/home/static/income及三条2秒周期在首server已通过并取消；尾部负例验证器漏detail，随后漏enabled/missed，report.json/002/003失败保留。最终复制原成功subscription配置并在启动server前校验完整MCP schema，只补待完成负例，report004 passed，无原query/report/periodic重跑。default对象修正补充MCP实际已正确返回，但验证器精确dict断言漏了unit/scale；保留原failedreport，只读重析同query得到live-object-view report002 passed，无新请求。所有5个MCP server exit0/订阅cancelled/noactive，business0/nativegamecalls0；outboxdelivered/llm_readunknown。最新control在live-object-view after-control，date56557728/player189/paused1/speed0。

{regression}最终full002在default对象修正后运行；full001是修正前完整记录，二者不能加计数。失败/新增比较见regression-comparison-001。配置矩阵{figures(coverage['counts'])}、{coverage['counts']['callable_topic_count']}callable；actual含static无mission/battle为{figures(coverage['actual_live_counts'])}、{coverage['actual_live_counts']['callable_topic_count']}callable。覆盖仅T02.home_node planned→partial，T02原已可调用所以配置callable不增加。

当前仍PID31460/creation134374886912306555/session31460-1dd653f69242d7b，physicalPOR/fullref010000bd00524f50，observerFRA/fullref0100007a00415246（slot动态读取）。EXE1.37.4/SHA b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77；v27-002目录work/runtime/diplomacy-observer-20261026-information-battle-v27-002，DLL7350b45e5bd318e446a24d1e06988cc9266a1a5b8ffeab31db246c516ffdedb7，manifest25c6c5ba977e741cdf77ec41ce3b568040d57da62e2cbf331ef02b513ee7ace9/110sources。battle disabled仍33批noncecc54f5529d68e71a964e45f302bf6f7c；4entry/RX/unwind/DLL保留到process exit。无game save/restart/DLL/date/business。

世界仍比v27 checkpoint领先35天。checkpoint llm_diplomacy_information_v27_checkpoint_20261026_001.eu4/raw56556888/POR1456.4.8/43275970B/SHA759a1515a1b27fc308de5bd67097ac03e3976726f4bd417a9099ebfdcdfd841b；R70保护保存SHAffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0。必要换DLL前成熟工具保留，不载旧档重放、不重复基础保存验收。旧PID34612/v26勿控制。原120、历史success/dispatched/unknown、original final-pass IDs、unclosed ownership禁重试，尤其SIE→FRA militaryaccess proposal1/r70_country_money_001_outbound；新纠错完整audit/--test-only。启动授权开发过程自动化.md，HTTP一次回答不重复。自有shell与workers均终态。

历史归档事故沿用42批：39两份wiring-tests-001 XML/log被覆盖且原字节未恢复，旧pin不改；42历史incident及prior-integrity明确其他检查结果，不能声称历史全部完整。本43批新输出仅当前stage/exclusive，原失败收据与版本完整保留。

下一步优先T04 country_power/total_power：trade-power-source-002已固定UI current_power精确运算、total runtime+C8纯DWORDcopy/scale1000；旧生产trade record已有整192B entry，包括44/48/4C/50/54，独立raw43只收入/flags，需要扩展独立probe这些inputs和每node+C8四字节，复用原graph。先补运行参考/profile，再接入两字段partial cache；不要因shares/sources尚缺而阻止这两个已闭合字段，也不要重做已有home/income验收。完整merchant任务、各国可见范围、预算其他分项和B04 fulltitle/Line1/buttons/layout/raw_text继续。
"""
    prepend("HANDOFF.md",handoff)
    prepend("README(agent).md","## 2026-10-27 第四十三批本埠节点与字段分流（最新）\n\n"+paragraph+
            "\n\n先读HANDOFF最新节及43批development-summary-001.json；旧39两份目标测试收据的归档事故仍未恢复，不改旧pin。当前game PID31460/session31460-1dd653f69242d7b/date56557728/v27-002，physicalPOR/observerFRA。下一步按trade-power-source-002推进T04 country_power/total_power；shares/sources和merchant-task语义缺口独立保留，不再重复现有partial验收。")
    print(json.dumps({"docs_written":7,"full_summary":line},ensure_ascii=False))


if __name__=="__main__":
    main()
