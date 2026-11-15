"""Publish batch48 results using completed live and full-suite receipts."""
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.archive_information_trade_merchant_task import STAGE, read, regression


def prepend(relative, text, *, after_title=False):
    path = ROOT / relative
    raw = path.read_text(encoding="utf-8")
    assert "第四十八批" not in raw[:4000], relative
    raw = raw.replace("第四十七批收集谓词与动态名称（最新）", "第四十七批收集谓词与动态名称（历史）", 1)
    if after_title:
        title, rest = raw.split("\n", 1)
        raw = title + "\n\n" + text.rstrip() + "\n\n" + rest.lstrip("\n")
    else:
        raw = text.rstrip() + "\n\n" + raw
    path.write_text(raw, encoding="utf-8", newline="\n")


def main():
    live = read(STAGE / "live-acceptance-001/report.json")
    coverage = read(STAGE / "coverage-update-002.json")
    comparison = regression()
    full, added = comparison["full"], comparison["new_tests"]
    assert live["status"] == "passed" and live["server_exit_code"] == 0 and all(live["checks"].values())
    assert not full["new_failure_nodes"] and added["cases"] == 7 and not added["failure_error_occurrences"]
    assert len(comparison["updated_or_renamed_cases"]) == 1
    tests = (f"完整回归为{full['passed']}项通过、{full['failed']}项失败、{full['errors']}项错误，另{full['subtests_passed']}个子测试通过；"
             f"较47批新增失败节点{len(full['new_failure_nodes'])}、解决{len(full['resolved_failure_nodes'])}，全套仍非全绿。"
             f"新增{added['cases']}个用例均通过，已包含在完整统计中；另1个既有collection用例调整了未实现字段及名称，不计为新增。")
    paragraph = ("2026-10-27 第四十八批：T05 `merchant_task` 已接入。按贸易节点返回 `none`、`collect` 或 `transfer`，按国家列出当前有商人的节点和任务，保留原生顺序。"
                 "本次FRA为 `rheinland → transfer`、`champagne → collect`，其余78节点为none；全部80节点与独立原始参考一致。"
                 "商人任务、收集资格和收入可以共同查询，报告及三条两秒周期结果已交付，订阅已取消、服务正常退出。"
                 "字段保持partial、complete=false，尚未覆盖商人行进中和空闲的完整生命周期；独立transfer字段和steering方向继续开发。"
                 "配置覆盖为56 available / 119 partial / 222 planned、37个可调用主题；本次含静态、未启用任务/战报来源的实机目录为56 / 108 / 233、34个可调用主题，均74主题397字段。"
                 + tests + "本批复用现有游戏进程、DLL及读取链路。完整计划继续，调用见[贸易收入与商人任务接口](贸易收入只读接口.md)。")
    for relative in ("docs/信息导出与订阅开发计划.md", "docs/信息接口使用说明.md"):
        prepend(relative, paragraph, after_title=True)
    prepend("docs/信息导出开发进展.md", "## 第四十八批：节点商人任务\n\n" + paragraph, after_title=True)

    receipt = ("第四十八批实机结果：FRA在莱茵兰转移、香槟收集，其余78节点无商人标志；80节点与独立参考一致。"
               "三字段共同查询、报告和三条两秒周期交付通过，订阅已取消，服务退出码0。"
               "见[本批验收报告](../work/runtime/information-trade-merchant-task-20261027-001/live-acceptance-001/report.json)。")
    path = ROOT / "docs/贸易收入只读接口.md"
    raw = path.read_text(encoding="utf-8")
    assert "第四十八批实机结果" not in raw
    title, rest = raw.split("\n", 1)
    raw = title + "\n\n" + receipt + "\n\n" + rest.lstrip("\n")
    raw += "\n\n第四十八批回归：" + tests + "\n"
    path.write_text(raw, encoding="utf-8", newline="\n")

    handoff = f"""## 2026-10-27 第四十八批节点商人任务（最新）

T05.merchant_task已通过真实MCP query/report/periodic。FRA/1.37.4/空参数，trade_node返回none/collect/transfer，country返回原生顺序活动行；本次rheinland→transfer、champagne→collect，其余78节点none。unit=state/scale=1/period=current，basis=native_trade_node_merchant_presence_and_collection_predicate，origin=derived_from_copied_native_flags；partial/complete=false。与income/collection共享原capture和真实验证器，未新增profile或读取图。独立transfer与steering_direction仍unsupported，完整transit/idle生命周期未覆盖。入口work/runtime/information-trade-merchant-task-20261027-001/development-summary-001.json；使用见docs/贸易收入只读接口.md。

merchant-serialization-source002以普通有界PE证明B5E190是输入到输出的serializer，AE→selector2C09→has_trader，AD→2C94→has_capital，AC→E1→type。17091B0解析selector并写输出，42C610输出布尔yes/no。002明确撤回001“没有写回input或调用parser所以不能是serializer”的错误负面推理；001原件及有效字节范围保留。商人任务为AE==0→none；AE非零且既有B58C70谓词true→collect、false→transfer。collection=false单独仍不能推出任务，AE0的本埠可以collection=true而task=none。静态键绑定、归档raw参考及当前公开观测分层，不声称已证明原生缓存刷新或所有商人生命周期。无新REA分析，禁止重试默认全映像路径。

独立expected-trade-merchant-task001 SHA b9b34f9f796a5688b49b9c461440489e779c981ce2c415660d4db08a8d62c51e，复用45批完整C0 entry两遍及47批flags/collection归档，绑定session/date/FRA fullref/slot122/specialslot2和EXE；不导入生产reader，不以MCP值为输入，也未做新的独立RPM采样。当前MCP全部80任务、country列表、income/collection混合、default/未知节点、报告与3条2秒周期均匹配；cancel/noactive、serverexit0、outboxdelivered/llm_readunknown。最新pause/date/player为48 after-control：56557728/paused1/speed0/slot189。

{tests}失败/错误{full['failure_error_occurrences']}次/{full['unique_failure_error_nodes']}唯一节点，旧债分类沿用45收据。覆盖56/119/222、37callable；actual56/108/233、34callable；仅merchant_task planned→partial。完整74主题397字段、阶段2/3/4、LLM自主订阅及完整B01–B04继续goal active，不能将partial称完成全部计划。

当前PID31460/creation134374886912306555/session31460-1dd653f69242d7b；physicalPOR/fullref010000bd00524f50，observerFRA/fullref0100007a00415246。EXE1.37.4/SHA b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77；安装work/runtime/diplomacy-observer-20261026-information-battle-v27-002，DLL7350b45e5bd318e446a24d1e06988cc9266a1a5b8ffeab31db246c516ffdedb7，manifest25c6c5ba977e741cdf77ec41ce3b568040d57da62e2cbf331ef02b513ee7ace9/110sources。battle disabled仍33批noncecc54f5529d68e71a964e45f302bf6f7c；4entry/RX/unwind/DLL保留至process exit。

世界仍领先v27 checkpoint35天。checkpoint llm_diplomacy_information_v27_checkpoint_20261026_001.eu4/raw56556888/POR1456.4.8/43275970B/SHA759a1515a1b27fc308de5bd67097ac03e3976726f4bd417a9099ebfdcdfd841b；R70保护保存SHAffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0。本批无save/restart/DLL/date/nativegamecall/business；成熟保存启动直接复用，不重新验收基本保存能力，启动已获开发过程自动化.md授权。旧PID34612/v26勿控制。原120、历史success/dispatched/unknown、original final-pass IDs及unclosed ownership禁重试，尤其SIE→FRA militaryaccess proposal1与r70_country_money_001_outbound；新纠错需完整audit/--test-only。HTTP问题已回答一次，不重复。

历史完整性：39两份wiring-tests001 XML/log原字节仍未恢复，旧pin不改；45 expected草稿已按原SHA重建，46各版本和47原件保留。48使用新stage排他收据及源码快照；自有shell/MCP/worker均已终态。

下一步：N01当前生产/税/贷款/费用、N03军事质量六字段、R01关系网络和完整B01–B04等继续按原计划推进。next-source-reuse001核对现有代码，仅已交付月度台账有可直接复用的完整来源；不能将历史保存或B01战斗快照伪装成实时国家字段。贸易完整transit/idle、transfer关系、steering方向、动态单位/倍率和外国visibility仍缺；已有前256country槽位不是完整active/visible名单。复盘要求集中批次收尾，并优先新增业务能力，避免用重复partial验收替代开发。
"""
    prepend("HANDOFF.md", handoff)
    root_paragraph = paragraph.replace("(贸易收入只读接口.md)", "(docs/贸易收入只读接口.md)")
    prepend("README(agent).md", "## 2026-10-27 第四十八批节点商人任务（最新）\n\n" + root_paragraph +
            "\n\n先读HANDOFF最新节及48批development-summary-001.json。商人存在由AE/has_trader绑定，完整行进与空闲生命周期仍缺。当前PID31460/session31460-1dd653f69242d7b/date56557728/v27-002、physicalPOR/observerFRA；身份、no-repeat及历史归档事故见HANDOFF。")
    print(json.dumps({"documents_updated": 6, "full": full["summary_line"], "new_cases": added["cases"], "counts": coverage["counts"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
