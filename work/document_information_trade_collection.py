"""Update batch47 documentation after actual service and regression receipts."""
from __future__ import annotations
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.archive_information_trade_collection import STAGE, regression, read


def prepend(relative, text, *, after_title=False):
    path = ROOT / relative
    raw = path.read_text(encoding="utf-8")
    assert "第四十七批" not in raw[:4000]
    if after_title:
        title, rest = raw.split("\n", 1)
        raw = title + "\n\n" + text.rstrip() + "\n\n" + rest.lstrip("\n")
    else:
        raw = text.rstrip() + "\n\n" + raw
    raw = raw.replace("第四十六批贸易来源明细（最新）", "第四十六批贸易来源明细（历史）", 1)
    path.write_text(raw, encoding="utf-8", newline="\n")


def main():
    live = read(STAGE / "live-acceptance-001/report.json")
    coverage = read(STAGE / "coverage-update-001.json")
    assert live["status"] == "passed" and live["server_exit_code"] == 0 and all(live["checks"].values())
    full, added, _, _ = regression()
    assert not full["new_failure_nodes"] and added["failure_error_occurrences"] == 0
    tests = (f"完整回归为{full['passed']}项通过、{full['failed']}项失败、{full['errors']}项错误，另{full['subtests_passed']}个子测试通过；"
             f"较46批新增失败节点{len(full['new_failure_nodes'])}、解决{len(full['resolved_failure_nodes'])}，全套仍非全绿。"
             f"新增{added['cases']}个用例均通过，已包含在完整统计中。")
    paragraph = ("2026-10-27 第四十七批：T05 `collection` 已接入原生收集组合谓词。按节点查询返回布尔值，按FRA国家查询返回按原生顺序排列的收集节点列表；当前只有`champagne`。"
                 "collection与income可在一次采集中共同读取；false只表示收集谓词不满足，不代表没有商人或正在转移。"
                 "T04动态来源名称也已接入现有原生本地化读取器：字面文本可返回名称，模板、缺失键和失败仍为未知，来源数量保持独立；数值单位仍未知。"
                 "当前80节点动态来源均为空，非空名称只完成真实验证器与本地化读取器的离线接线测试，不声称取得了实机非空样本。"
                 "collection的80节点、国家列表、收入混合查询、报告和三条两秒周期交付均已通过实机对照，订阅取消、服务正常退出。"
                 "两个主题仍保持partial、complete=false，商人任务、贸易转移及steering方向继续开发。"
                 "配置覆盖为56 available / 118 partial / 223 planned、37个可调用主题；本次含静态、未启用任务/战报来源的实机目录为56 / 107 / 234、34个可调用主题，均74主题397字段。"
                 + tests + "本批未保存、重启、换DLL、推进日期或执行外交业务。完整计划继续，调用见[贸易收入与收集接口](贸易收入只读接口.md)和[贸易来源接口](贸易竞争力只读接口.md)。")
    for relative in ("docs/信息导出与订阅开发计划.md", "docs/信息接口使用说明.md"):
        prepend(relative, paragraph, after_title=True)
    prepend("docs/信息导出开发进展.md", "## 第四十七批：原生收集谓词与动态来源名称\n\n" + paragraph, after_title=True)
    receipt = ("\n\n第四十七批实机验收通过：80节点收集谓词、国家列表、收入混合查询、报告和三次周期交付均符合独立参考；订阅取消、服务退出码0。"
               "当前动态来源为空，非空名称仅有离线接线证据。见[实机验收报告](../work/runtime/information-trade-merchant-state-20261027-001/live-acceptance-001/report.json)。" + tests + "\n")
    for relative in ("docs/贸易收入只读接口.md", "docs/贸易竞争力只读接口.md"):
        with (ROOT / relative).open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(receipt)
    old = (ROOT / "HANDOFF.md").read_text(encoding="utf-8").split("## 2026-10-27 第四十五批", 1)[0]
    identity = old.split("当前仍PID", 1)[1].split("历史归档事故", 1)[0].strip()
    handoff = f"""## 2026-10-27 第四十七批收集谓词与动态名称（最新）

T05.collection真实MCP query/report/periodic已交付，FRA/1.37.4/emptyparams、country或trade_node。node value bool，country value原生顺序node_id列表，当前['champagne']；unitstate/scale1/periodcurrent/basisnative_trade_node_collection_predicate/originderived_from_copied_native_flags，partial/completefalse。复用旧trade_income单次capture、母/三份trade真实validator、nodes[].eligible；income仍month/ducats/1000，不额外读graph或新profile。transfer/merchant_task/steering_direction继续unsupported。T04来源动态name已条件接入中性NativeLocalizationReader，其他份额/power/来源容器保留。完整74topics397fields、阶段2/3/4、LLM自主订阅、完整B01–B04继续goal active。先读docs/外交开发推进复盘.md、两贸易接口文档；入口work/runtime/information-trade-merchant-state-20261027-001/development-summary-001.json。

merchant-state-source002闭合原生101CB60 status：mode0且B58C70 true输出TRADE_MERCHANT_ALREADY_COLLECTING，mode1且false输出...TRANSFERRING，gate无效走UNABLE。B58C70现有组合谓词可提供collection，不要求先分解AC/AE；有效entry为前置，缺失/非法不得false。完整谓词在有效entry且非specialslot时是AE==0?AD!=0:AC==0；specialslot沿原完整规则。false包含多类条件失败，不能推出none或transfer，商人存在性未独立闭合。B5E100唯一direct caller B59855/B59550将DL置1、R8B透传，四caller25AE52/25B9D3/27427A/305C9C仍待参数语义；无需继续追loggerguard或通用bool parser。001将泛型parser VA14125b340写进RVA字段，source-address-correction001明确RVA125b340，001原件不改。普通有界PE/locale、归档raw、MCP分层，无新REA全映像分析。

dynamic lookup14B33A0/16FAF60与localization-memory1374精确同一字节/FNV1参数/global2357B00/表/池布局；复用旧非空任务key原始entry/pool/value/doublepass证据，不能当非空trade来源。新adapter只在sources、选中node动态observed非空时筛ASCII[!-~]1..160+NUL、去重、懒建中性reader；无codec/inapplicable/invalidkey不冒称名称，literal known保留value/key/raw_hex/language/codec/raw_template_hex/reader_provenance。模板/缺失/异常只nameunknown，不丢数量/旧rows等；最终context改变撤回此次全部字段。名称与数量不原子，值unitunknown，当前80动态空，无实机非空name正例。新真实childvalidator+中性reader capture-seam离线例覆盖中文、模板、缺失、过滤/去重、失败和context；不冒称live。

独立expected-trade-collection001 SHAe31b4f3345e078ce4fca38c891ebeb37addf81add3d2101af58294e07db9fd28；归档42raw005与45C0raw002同session/date/fullref/slot/specialslot2、80节点192B/flags两遍一致，独立重算B58C70，无新RPM采样/生产reader import。rawflag参考SHA4ff9f85c9f9b1de52155a95a95a76862257b5c9ef28367355f3d6fa922fd0425；ACADAEAF:78节点00000000、champagne00010100、rheinland01000100，仅作storage证据不单独命名flags。旧profiles、46source-index/raw/reference均不改。

MCP全部80节点collection与独立原始参考一致；countrylist、income mixed/default、未知node、T04旧四字段与空dynamic、report、3条两秒周期和cancel/noactive通过；serverexit0/outboxdelivered/llm_readunknown。最新独立pause/date/player见47 aftercontrol，56557728/paused1/speed0/slot189。无nativegamecall/write/save/restart/DLL/date/business。{tests}失败/错误{full['failure_error_occurrences']}次/{full['unique_failure_error_nodes']}唯一节点，旧债分类沿用45收据，不改旧pin或伪造历史。覆盖56/118/223、37callable；actual56/107/234、34callable，均74/397，只有collection planned→partial。

当前仍PID{identity}

历史归档事故沿用42批：39两份wiring-tests001 XML/log原字节未恢复，旧pin不改；45 expected草稿已按原SHA重建，46各版本原件保留。47新收据仅当前stage/newfilename；collection-tests001初版用了stub validator，002新增production profile/real reader/real validator端到端例，001不冒充真实validator证据。自有shell/MCP/workers均终态。

下一步可从B59550四caller继续商人存在性/任务及steering direction；不将aggregate collection false或T04 TO/FROM点数直接等同任务/transfer关系。动态值单位、完整倍率及外国visibility仍未闭合；成熟country_identity前256槽位不是完整active/visible列表。完整当前预算生产/税/费用、B04 fulltitle/Line1/buttons/layout/raw_text及其他计划字段继续，不重复既有partial验收代替开发。
"""
    prepend("HANDOFF.md", handoff)
    paragraph = paragraph.replace("(贸易收入只读接口.md)", "(docs/贸易收入只读接口.md)").replace("(贸易竞争力只读接口.md)", "(docs/贸易竞争力只读接口.md)")
    prepend("README(agent).md", "## 2026-10-27 第四十七批收集谓词与动态名称（最新）\n\n" + paragraph +
            "\n\n先读HANDOFF最新节及47批development-summary-001.json。collection是原生组合谓词，false不推出商人任务；动态name只有literal可known，数量单位仍unknown。当前PID31460/session31460-1dd653f69242d7b/date56557728/v27-002，physicalPOR/observerFRA，no-repeat与历史归档事故见HANDOFF。")
    print(json.dumps({"docs_written": 7, "full": full["summary_line"], "new_cases": added["cases"], "counts": coverage["counts"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
