"""Document batch46 only after its actual integration receipts exist."""
from __future__ import annotations
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.archive_information_trade_source_details import STAGE, BASELINE, regression, sha


def prepend(relative, text, *, after_title=False):
    path = ROOT / relative
    raw = path.read_text(encoding="utf-8")
    assert "第四十六批" not in raw[:4000]
    if after_title:
        title, rest = raw.split("\n", 1)
        raw = title + "\n\n" + text.rstrip() + "\n\n" + rest.lstrip("\n")
    else:
        raw = text.rstrip() + "\n\n" + raw
    raw = raw.replace("第四十五批贸易份额与来源（最新）", "第四十五批贸易份额与来源（历史）", 1)
    path.write_text(raw, encoding="utf-8", newline="\n")


def main():
    live = json.loads((STAGE / "live-acceptance-001/report.json").read_bytes())
    coverage = json.loads((STAGE / "coverage-update-001.json").read_bytes())
    assert live["status"] == "passed" and live["server_exit_code"] == 0 and all(live["checks"].values())
    full, added, _, _ = regression()
    assert not full["new_failure_nodes"] and added["failure_error_occurrences"] == 0
    test_text = (f"完整回归为{full['passed']}项通过、{full['failed']}项失败、{full['errors']}项错误，另{full['subtests_passed']}个子测试通过；"
                 f"与45批相比新增失败节点{len(full['new_failure_nodes'])}、解决{len(full['resolved_failure_nodes'])}，全套仍非全绿。"
                 f"新增{added['cases']}个用例均通过，已包含在完整统计中。")
    paragraph = ("2026-10-27 第四十六批：T04 `sources` 新增主贸易城市加成、动态来源容器和本国转出/转入的竞争力明细。"
                 "当前FRA主贸易城市加成在香槟节点为5点；4个节点共有5条转入明细，绑定ORL/AUV国家引用后返回数量。"
                 "动态列表当前80节点均为空；非空时保留原始值和名称字节，显示名称与业务单位仍为未知。"
                 "转移数量为竞争力点数，方向来自转出/转入容器，保留数值原始正负号。"
                 "全部80节点已与独立原始采样对照，四字段共同查询、报告和三条两秒周期交付通过，订阅已取消、服务正常退出。"
                 "sources外层单位改为mixed，各明细保留自身单位；仍为partial、complete=false，修正倍率、竞争国可见范围等继续开发。"
                 "覆盖计数保持56 available / 117 partial / 224 planned、37个可调用主题；本次含静态、未启用任务/战报来源的实机目录为56 / 106 / 235、34个可调用主题，均为74主题397字段。"
                 + test_text + "本批未保存或重启游戏、未换DLL、推进日期或执行外交业务。完整计划继续开发，调用方法见[贸易竞争力只读接口](贸易竞争力只读接口.md)。")
    for relative in ("docs/信息导出与订阅开发计划.md", "docs/信息接口使用说明.md"):
        prepend(relative, paragraph, after_title=True)
    prepend("docs/信息导出开发进展.md", "## 第四十六批：主贸易城市与转移来源明细\n\n" + paragraph, after_title=True)
    interface = ROOT / "docs/贸易竞争力只读接口.md"
    interface_text = interface.read_text(encoding="utf-8")
    pending = "本批新增的 `capital_status`、动态容器和 `transfer_sources.to/from` 目前只有有界独立 raw/reference 与适配器合同；Batch46 MCP 尚未运行，本文不预写成功或回归统计。root 完成 live acceptance 后再补入本批收据。"
    assert pending in interface_text
    interface.write_text(interface_text.replace(pending, "第四十六批新增来源已完成实机对照，具体收据与回归统计见下文。", 1), encoding="utf-8", newline="\n")
    with (ROOT / "docs/贸易竞争力只读接口.md").open("a", encoding="utf-8", newline="\n") as stream:
        stream.write("\n\n第四十六批实机验收通过：80节点的固定来源、空动态列表和转移数量均与独立参考一致；四字段共同查询、报告及三次周期交付通过，订阅取消、服务正常退出。见[实机收据](../work/runtime/information-trade-source-details-20261027-001/live-acceptance-001/report.json)。" + test_text + "\n")
    prior = (ROOT / "HANDOFF.md").read_text(encoding="utf-8").split("## 2026-10-27 第四十四批", 1)[0]
    identity = prior.split("当前仍PID", 1)[1].split("历史归档事故", 1)[0].strip()
    profile_path = ROOT / "bridge/information/profiles/trade-details-memory-1374-v3.json"
    profile = json.loads(profile_path.read_bytes())
    guard_bytes = sum(len(bytes.fromhex(g["hex"])) for g in profile["code_guards"])
    handoff = f"""## 2026-10-27 第四十六批贸易来源明细（最新）

T04.sources已扩展主贸易城市加成、动态列表、本国TO/FROM转移明细，真实MCP query/report/periodic通过。FRA/trade_node/1.37.4/emptyparams。sources unit=mixed，value.FRA含rows/capital_status/dynamic_sources/transfer_sources.to/from/multiplier；各point行signed32/1000 trade_power，dynamic单位unknown，名称raw bytes/lookupunknown；原shares与power字段保留。champagne主贸易城市加成raw5000=5点；FROM四节点五元素（ORL/AUV）经country_table[fullrefslot]+20完全匹配才公开tag。partial/completefalse，完整74topics397fields、阶段2/3/4、LLM自主订阅、完整B01–B04继续goal active。先读docs/外交开发推进复盘.md与docs/贸易竞争力只读接口.md；入口work/runtime/information-trade-source-details-20261027-001/development-summary-001.json。

普通有界PE和locale证明：country+14C8→anchor+E8与runtime_node精确相同才取global233F2F0主贸易城市加成，实际英文Main Trade City in area，不是省份capital；dynamic entry90为link(item0/next10)，item34 signed值、item10名称对象、capacity在item28，NUL终止而非猜长度，14B33A0名称lookup未闭合，单位仍unknown。B5DCD0入口R8指向entry60/78，QWORD[R8]已是首element，element0 fullref、8 signed值、18 next；TO/FROM方向来自容器，locale另加−/+前缀，不能从raw正负推断方向。source-modifiers004纠正003的方向文字，003原件保留。B57F55倍率路径是共同后继，province28与downstream40分支不会整体屏蔽倍率；382E70/382DD0/2F2640复杂getter仍未闭合，TRADE_MULTI_EXPLA继续unknown，不求和伪装完整power。静态、RPM、公开值分层，无新REA分析或GUI身份/刷新时机声明。

生产profile改用v3 SHA{sha(profile_path)}，source-index003 SHA{profile['source_index']['sha256']}，{len(profile['code_guards'])}guards/{guard_bytes}B；v1/v2和旧income/power/home/countryprofiles保留。reader复用已验证graph和192Bentry，新增身份链和有界元素读取；每遍扩展128KiB，发起前计入预算，三链共享每节点64/全局256元素，名称最多1024B，所有read纳入母512KiB。未知/环/限额/故障仅撤回对应子域，旧shares/三来源保留；top/before/after双遍与cleanup撤回、完整profile/record校验仍在。adapter单次capture与前后context、选中节点provenance。

独立raw001将空dynamic误判，002为只读重析；tail003首元素多解引用错误保留，004为新补充RPM采样，不是003只读修复。raw004 SHA2eb1e445a569d7400b82b4896615622c3d33673cf98e5d860d364cd208c09a08，131324B/2894calls、80节点双遍、扩展2192B/遍、句柄closed；capital/dynamic沿用002 seed，未重复整entry。最终独立expected002 SHAfb34b9a34cd2ff799f022084b1b90668ccd855a78936f16b0763bf0ee5cb603e，不导入生产reader/公开值；v2/expected001保留，新版本新编号。80动态列表全空、TO全空；非空动态和TO/负数/故障路径仅由有界fake测试覆盖，不能冒称实机正例。

全部80节点新来源与独立输入一致，默认四字段、未知node、report、3条两秒周期、cancel/noactive通过，server exit0/outboxdelivered/llm_readunknown。最新pause/date/player见46 aftercontrol，56557728/paused1/speed0/slot189，无nativegamecall/write/save/restart/DLL/date/business。{test_text}失败/错误{full['failure_error_occurrences']}次/{full['unique_failure_error_nodes']}唯一节点，旧债分类沿用45收据，不改旧pin或伪造历史文件。覆盖计数56/117/224、37callable；actual56/106/235、34callable，均74/397，仅扩展partial内容而不升级覆盖。

当前仍PID{identity}

历史归档事故沿用42批：39两份wiring-tests001 XML/log原字节未恢复，旧pin不改，详见42 incident/prior-integrity。45 expected草稿曾同名改形状，已确定性重建原SHA并保留收据；46各profile/index/raw/reference均分版本保留，不改旧stage。自有shell/MCP/workers均终态。

下一步见next-trade-entry001：T05.transfer/merchant-task须另证原生业务含义，T04的TO/FROM点数容器不能直接当T05关系字段。动态名称lookup/业务单位、完整倍率与竞争国visibility仍缺。成熟country_identity前256槽位/2048B窗口不是完整active/visible列表，不开放任意外国查询。完整当前预算生产/税/费用、B04 fulltitle/Line1/buttons/layout/raw_text及其他计划字段继续，不以重跑已有partial验收代替新开发。
"""
    prepend("HANDOFF.md", handoff)
    prepend("README(agent).md", "## 2026-10-27 第四十六批贸易来源明细（最新）\n\n" + paragraph.replace(
        "[贸易竞争力只读接口](贸易竞争力只读接口.md)", "[贸易竞争力只读接口](docs/贸易竞争力只读接口.md)") +
        "\n\n先读HANDOFF最新节及46批development-summary-001.json。主贸易城市加成与TO/FROM点数已闭合；动态名称/单位、倍率和竞争国可见范围仍未知。PID31460/session31460-1dd653f69242d7b/date56557728/v27-002，physicalPOR/observerFRA；no-repeat与历史归档事故见HANDOFF。")
    print(json.dumps({"docs_written": 6, "full": full["summary_line"], "new_cases": added["cases"], "counts": coverage["counts"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
