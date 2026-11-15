"""Write the current batch result once after real acceptance and regression."""
from __future__ import annotations
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-budget-collectors-20261027-001"


def prepend(relative, text, *, after_title=False):
    path = ROOT / relative
    assert path.stat().st_size < 2 * 1024 * 1024
    raw = path.read_text(encoding="utf-8")
    assert "第四十二批" not in raw[:4000]
    if after_title:
        title, rest = raw.split("\n", 1)
        raw = title + "\n\n" + text.rstrip() + "\n\n" + rest.lstrip("\n")
    else:
        raw = text.rstrip() + "\n\n" + raw
    path.write_text(raw, encoding="utf-8", newline="\n")


def main():
    live = json.loads((STAGE / "live-acceptance-001/report.json").read_bytes())
    coverage = json.loads((STAGE / "coverage-update-001.json").read_bytes())
    assert live["status"] == "passed" and live["server_exit_code"] == 0
    with (STAGE / "regression-full-001.log").open("rb") as stream:
        stream.seek(0, 2)
        stream.seek(max(0, stream.tell()-8192))
        tail = stream.read().decode("utf-8", errors="replace")
    line = [line for line in tail.splitlines() if " passed" in line and " in " in line][-1]
    def count(label):
        match = re.search(r"(\d+) " + label + r"\b", line)
        return int(match.group(1)) if match else 0
    values = {key: count(key) for key in ("passed", "failed", "errors", "subtests passed")}
    configured = coverage["counts"]["field_counts"]
    actual = coverage["actual_live_counts"]["field_counts"]
    figures = lambda x: f"{x['available']} available / {x['partial']} partial / {x['planned']} planned"
    regression = f"完整 bridge/tests 一次为{values['passed']}项通过、{values['failed']}项失败、{values['errors']}项错误，另{values['subtests passed']}个子测试通过；完整套件仍非全绿。"
    paragraph = (
        "2026-10-27 第四十二批：T05 `income` 已接入真实游戏中的贸易节点国家收入缓存。FRA 按国家查询的合计为3.813金币/月，按 `trade_node` 查询可取得各节点贡献；全部80个节点与服务启动前独立原始采样一致，香槟节点贡献3.813，其余节点为0。报告查询和三条两秒周期结果已交付，订阅已取消、服务正常退出。字段保持 partial、complete=false，保留原缓存、收集资格与收入贡献的区别；其余四个T05字段继续未实现。"
        f"当前配置覆盖为 {figures(configured)}，{coverage['counts']['callable_topic_count']}个可调用主题；本次未启用静态/任务/战报源的实际目录为 {figures(actual)}，{coverage['actual_live_counts']['callable_topic_count']}个可调用主题，均为74主题397字段。"
        + regression + "本批没有保存、重启、换DLL、推进日期或执行外交业务。完整计划、当前预算其余分项和完整B01–B04继续开发。调用方式见[贸易收入只读接口](贸易收入只读接口.md)。"
    )
    prepend("docs/信息导出与订阅开发计划.md", paragraph, after_title=True)
    prepend("docs/信息导出开发进展.md", "## 第四十二批：T05 贸易节点收入\n\n" + paragraph, after_title=True)
    prepend("docs/信息接口使用说明.md", paragraph, after_title=True)
    path = ROOT / "docs/贸易收入只读接口.md"
    raw = path.read_text(encoding="utf-8")
    raw += ("\n\n实机MCP验收已通过：80个节点、国家合计、含未实现字段的混合查询和报告均符合独立原始数据；三条两秒周期结果 delivered，订阅 cancelled，服务退出码0。"
            "前后日期56557728、玩家槽189、paused1、speed0保持不变。验收记录为 `work/runtime/information-budget-collectors-20261027-001/live-acceptance-001/report.json`。\n\n"
            + regression + " 新模块的定向结果包含在完整回归统计中，不重复累加。\n")
    raw = raw.replace("独立原始采样已确认，公开MCP验收结果待本批补入", "独立原始采样与公开MCP验收均已确认")
    path.write_text(raw, encoding="utf-8", newline="\n")
    handoff = f"""## 2026-10-27 第四十二批贸易收入（最新）

T05.income已接入真实MCP query/report/periodic。FRA国家合计raw3813=3.813ducats/month，80节点与独立raw005及expected-trade-income-001逐项一致；唯一eligible为champagne，rheinland是steering/贡献0。metadata partial/completefalse，countrytotal origin derived_from_copied_native_caches，eligible node copied_native_cache，排除节点返回派生贡献0并保留cache_income_raw和flags；basis native_trade_node_country_income_cache。其余collection/transfer/merchant_task/steering_direction仍unsupported，未知node NODE_NOT_FOUND。完整74topics397fields、阶段2/3/4、LLM自主订阅、完整B01–B04仍goal active。先读docs/外交开发推进复盘.md、docs/贸易收入只读接口.md；本批入口work/runtime/information-budget-collectors-20261027-001/development-summary-001.json。

纯RPM复用country_resources_memory.capture，include_trade_income=False默认旧三点/旧profile不变，显式True添加top/before/after；严格bool、身份/日期/双遍/cleanup撤回不变。trade-income-memory-1374 profile SHA1375800668ed0ddec29d2e5f8efe8e1369d1e4da8b0aa6916b5b970078b137cd，source-index SHA8350859150dae894212d2ed15e8f5c528e590b91e9f52401010bbdb761f60955，16guards2866B。NativeTradeIncomeSource校验母报告/子record三份和读取前后context，公开provenance收敛为必要原始字段及record digest。serve只在live分支接入，无任务/本地化/nativecall。N01上月台账接口及口径继续保留。

有界普通PE：B65AD0从module+242BE28解引用manager，manager+0/+8 begin/end，C9720/C3050返回outpointer，C9A30 stride8。旧enumeration001错误保留，由002纠正。definition虚表+40只认8F440 true/8F450 false，各真实leaf3B，16B窗口含INT3不是正文。81definitions含Null占位，80真节点；definition+10 ASCII key（与静态80keys/location逐项相同），+30是本地化显示名。generic mission helper本身不证明trade业务类型，key-corroboration报告分层记录。definition+DC signedcenter→gameglobal233FE58→game+1CA8+center*2E10→province+E8 runtime，runtime+A8匹配definition。table runtime+18，signed16 countryfullrefbytes4:6*C0，income+34，AC/AD/AE flags，specialslotglobal233D8B8。B58C70筛选后逐signed32回绕加总→view+54C/INCOMETRADE。333310/333620只是系数，生产amount为A11920/A12C20；当前完整预算仍未实现。

独立raw005两遍身份/date一致、handleclosed、126940B/2376RPMcalls/mask410；无游戏函数/写入/heapscan。001/002/003失败保留（global间接、display误认key），004原displayraw和005真实key完整采样分开。实际MCP全部80nodes/country/mixed/report及3条2秒周期结果符合预期，cancelled/server0；before/aftercontrol均date56557728/player189/paused1/speed0。业务0，outboxdelivered/llm_readunknown。{regression} 新增/解决节点以regression-comparison-001为准；新定向用例只计入full一次。配置矩阵{figures(configured)}、{coverage['counts']['callable_topic_count']}callable；actual无optional为{figures(actual)}、{coverage['actual_live_counts']['callable_topic_count']}callable。

归档事故必须保留：复用worker误把本批7pass输出覆盖了39批wiring-tests-001.xml/log；root已移动新输出到本批misplaced-*，未找到两份原始字节，旧summary pins不改。historical-test-receipt-overwrite-001记录原expected/newSHA及缺失，不能声称39全部pins仍可验证。39完整suite、live回执、source快照和40/41档案独立保留。本批另有一份来源报告曾误放41，已byte-for-byte移出，见artifact-relocation-001。后续新收据只写当前stage，先明确worker输出目录。

当前仍PID31460/creation134374886912306555/session31460-1dd653f69242d7b，physicalPOR/fullref010000bd00524f50，observerFRA/fullref0100007a00415246（slot来自runtime，不固定122）。EXE1.37.4/SHA b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77；v27-002安装work/runtime/diplomacy-observer-20261026-information-battle-v27-002，DLL7350b45e5bd318e446a24d1e06988cc9266a1a5b8ffeab31db246c516ffdedb7，manifest25c6c5ba977e741cdf77ec41ce3b568040d57da62e2cbf331ef02b513ee7ace9/110sources。最新pause为本批after-control；battle disabled仍33批noncecc54f5529d68e71a964e45f302bf6f7c，4entry/RX/unwind/DLL留至process exit。

世界仍比v27 checkpoint领先35天，必要换DLL前用成熟保存工具集中保留，不载旧档重放、不重复保存验收。checkpoint llm_diplomacy_information_v27_checkpoint_20261026_001.eu4/raw56556888/POR1456.4.8/43275970B/SHA759a1515a1b27fc308de5bd67097ac03e3976726f4bd417a9099ebfdcdfd841b；R70保护保存SHAffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0。旧PID34612/v26勿控制。原120、历史success/dispatched/unknown、original final-pass IDs、unclosed ownership禁重试，尤其SIE→FRA militaryaccess proposal1及r70_country_money_001_outbound；新纠错完整audit/--test-only。自动启动授权开发过程自动化.md，HTTP一次回答不重复。自有shell/MCP/pytest及workers均终态。

下一步继续当前预算真实生产、税及其他收入/费用收集器，或其他尚未实现字段；不要再验收已有partial代替开发。B04仍projection9，fulltitle/Line1/buttons/layout/raw_text缺口继续。
"""
    prepend("HANDOFF.md", handoff)
    prepend("README(agent).md", "## 2026-10-27 第四十二批贸易收入（最新）\n\n" + paragraph
            + "\n\n先读HANDOFF最新节及本批development-summary-001.json，运行身份/no-repeat沿用其中完整记录。source profile、80节点原始采样、MCP/周期交付与完整回归分层归档。39批两份定向wiring测试收据被本批输出误覆盖且原字节暂未恢复，见historical-test-receipt-overwrite-001；旧pin未修改，不能声称全部历史归档完整。当前game仍PID31460/session31460-1dd653f69242d7b/date56557728/v27-002，physicalPOR/observerFRA，无保存/重启/换DLL/日期推进。下一步继续预算真实生产等其余字段，完整goal保持active。")
    print(json.dumps({"docs_written": 6, "regression": values, "configured_counts": coverage["counts"], "actual_counts": coverage["actual_live_counts"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
