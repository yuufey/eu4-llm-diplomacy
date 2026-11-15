"""Publish batch49 from the retained MCP and full-suite receipts."""
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.archive_information_military_quality import STAGE, read, regression


def prepend(relative, text, *, after_title=False):
    path = ROOT / relative
    raw = path.read_text(encoding="utf-8")
    assert "第四十九批" not in raw[:4000], relative
    raw = raw.replace("第四十八批节点商人任务（最新）", "第四十八批节点商人任务（历史）", 1)
    if after_title:
        title, rest = raw.split("\n", 1)
        raw = title + "\n\n" + text.rstrip() + "\n\n" + rest.lstrip("\n")
    else:
        raw = text.rstrip() + "\n\n" + raw
    path.write_text(raw, encoding="utf-8", newline="\n")


def main():
    live = read(STAGE / "live-acceptance-001/report.json")
    coverage = read(STAGE / "coverage-update-001.json")
    comparison = regression()
    full, added = comparison["full"], comparison["new_tests"]
    assert live["status"] == "passed" and live["server_exit_code"] == 0 and all(live["checks"].values())
    assert not full["new_failure_nodes"] and not added["failure_error_occurrences"]
    tests = (f"完整回归为{full['passed']}项通过、{full['failed']}项失败、{full['errors']}项错误，另{full['subtests_passed']}个子测试通过；"
             f"较48批新增失败节点{len(full['new_failure_nodes'])}、解决{len(full['resolved_failure_nodes'])}，全套仍非全绿。"
             f"新增{added['cases']}个用例均通过，已包含在完整统计中。")
    paragraph = ("2026-10-27 第四十九批：N03新增军事科技等级和陆军传统，FRA当前分别为4级、21.052点。"
                 "`military_technology`和`army_tradition`均为available、字段complete=true，支持共同查询、报告与周期订阅。"
                 "真实MCP的查询、报告和三条两秒周期结果均与独立原始参考一致，订阅已取消、服务正常退出。"
                 "默认N03仍包含四个未实现字段，整体complete=false；士气、纪律、职业度和军事修正继续开发。"
                 "同时修正N04读取配置对父读取器的过期源码依赖，六个既有国内压力字段恢复实际读取，覆盖等级不变。"
                 "配置覆盖为58 available / 119 partial / 220 planned、38个可调用主题；本次含静态、未启用任务/战报来源的实机目录为58 / 108 / 231、35个可调用主题，均74主题397字段。"
                 + tests + "本批复用现有进程和DLL，完整计划继续。调用见[军事质量只读接口](军事质量只读接口.md)。")
    for relative in ("docs/信息导出与订阅开发计划.md", "docs/信息接口使用说明.md"):
        prepend(relative, paragraph, after_title=True)
    prepend("docs/信息导出开发进展.md", "## 第四十九批：军事科技与陆军传统\n\n" + paragraph, after_title=True)
    receipt = ("第四十九批实机结果：FRA军事科技等级为4，陆军传统raw=21052、scale=1000，即21.052点。"
               "双字段查询、报告和三条两秒周期交付均与独立参考一致，取消后无活动订阅，服务退出码0。"
               "见[实机报告](../work/runtime/information-military-quality-20261027-001/live-acceptance-001/report.json)。")
    prepend("docs/军事质量只读接口.md", receipt + "\n\n" + tests, after_title=True)

    handoff = f"""## 2026-10-27 第四十九批军事科技与陆军传统（最新）

N03两个新字段已通过真实MCP query/report/periodic：military_technology=4、army_tradition=21052/1000即21.052点；FRA/country/1.37.4/空参数，available、字段complete=true。显式双字段query完整，默认六字段因morale/discipline/professionalism/military_modifiers仍planned而complete=false。调用见docs/军事质量只读接口.md；归档入口work/runtime/information-military-quality-20261027-001/development-summary-001.json。完整74主题397字段、阶段2/3/4、LLM自主订阅及完整B01–B04继续goal active。

普通有界PE证据：military-technology-source002由6DF5A0的mil_tech查找绑定定义index，经country+2440→vector128/130读取signed32等级；不假定固定index2，也不消费只属布局推断的+138。source001原件保留，002纠正其capacity证据描述。army_tradition由6E01B0 country+E40 signed32 getter、357200 clamp0..100000、token2951和UI十进制/1000共同绑定；tradition-source004/005区分显示除法与1707B30原始32位serializer。两字段分别使用technology_level/scale1与army_tradition/scale1000、current、直接缓存origin。读取不调用native getter，不承诺缓存刷新时机或主线程原子性。

morale-discipline-source002纠正001：+9874/+987C是morale输入/倍率，33FFA0/340C50返回格式化字符串；341850仍缺globalmanager+2CE0 callback，不得发布简化discipline。professionalism虽有Qword serializer与UI比例候选，country别名绑定未闭合，继续planned。静态机器码、独立RPM和MCP结果分层，无新REA分析；禁止默认全映像路径。有界缓存后续路线见work/runtime/next-rea-cache-route-001.json，真正使用前核对其中精确cache路径和只读参数。

独立RPM native-military-quality-inputs001原始报告为doublepass_mismatch：两遍业务字节相同，比较器误将累计parent_bytes_before差异当数据变化。原报告SHA e69c35435cad35155843b0e028a4b5b78d66cf02b0ec48fbe54792941f2f6800保持不变；reference-accounting-reanalysis001仅剔除这一计数比较，expected-military-quality001是只读重析参考，不冒充原报告passed，也未再次采样。参考SHA ec8f772225d78eab87317d7c8bfdfde5184484313f3895fa1d2a303c043f9241，原始tech04000000/army3c520000，绑定FRA fullref/slot122、session/date/creation/EXE。不导入新生产军事reader、不使用MCP值作参考输入。

父country_resources_memory新增strictbool include_military_quality，在同一母capture中采集两个独立child，绑定before/after和真实validator，未知子字段可独立撤回，母context变化全部撤回。两份新profile分别为military-quality-memory-1374 SHA3f9113e7d5d87ae1ce19fc4b63e5034d1806f98c2a5630d847d06510fbcb6c32、military-tradition-memory-1374 SHA638f356e2244c903f9a82db6ce6a51a00662d73d9e14b4dd2d945c1c3b5ae20d。N04旧profile父源码pin在48批已过期；旧文件不改，v2 SHA5b3c903251d87069fd74c9ab8b04db45d1b4b2f5604c49469e17a480bc151c35只更新父依赖/版本说明，偏移和guards不变。真实MCP复查六个N04字段全部known；历史fixture明确绑定自己的旧profile，不弱化实时guard。

双字段query、默认四字段unsupported、report、3条两秒periodic、cancel/noactive、serverexit0通过；outboxdelivered/llm_readunknown。最新pause/date/player见49 live-acceptance-001/after-control.json，56557728/paused1/speed0/slot189。{tests}失败/错误{full['failure_error_occurrences']}次/{full['unique_failure_error_nodes']}唯一节点，旧债分类沿用45收据。覆盖58/119/220、38callable；actual58/108/231、35callable；仅N03两个字段planned→available。

当前PID31460/creation134374886912306555/session31460-1dd653f69242d7b，physicalPOR/fullref010000bd00524f50，observerFRA/fullref0100007a00415246。EXE1.37.4/SHA b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77；安装work/runtime/diplomacy-observer-20261026-information-battle-v27-002，DLL7350b45e5bd318e446a24d1e06988cc9266a1a5b8ffeab31db246c516ffdedb7，manifest25c6c5ba977e741cdf77ec41ce3b568040d57da62e2cbf331ef02b513ee7ace9/110sources。battle disabled仍33批noncecc54f5529d68e71a964e45f302bf6f7c；4entry/RX/unwind/DLL保留至process exit。

世界仍领先v27 checkpoint35天。checkpoint llm_diplomacy_information_v27_checkpoint_20261026_001.eu4/raw56556888/POR1456.4.8/43275970B/SHA759a1515a1b27fc308de5bd67097ac03e3976726f4bd417a9099ebfdcdfd841b；R70保护保存SHAffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0。成熟保存和启动直接复用，不重新验收基本保存功能；启动已获开发过程自动化.md授权。旧PID34612/v26勿控制。原120、历史success/dispatched/unknown、original final-pass IDs及unclosed ownership禁重试，尤其SIE→FRA militaryaccess proposal1和r70_country_money_001_outbound；新纠错需完整audit/--test-only。HTTP问题已回答一次，不重复。本批无save/restart/DLL/date/nativegamecall/business。

历史完整性：39两份wiring-tests001 XML/log原字节仍未恢复，旧pin不改；45 expected草稿已按原SHA重建，46各版本及47/48原件保留。49用新stage排他收据和源码快照；自有shell/MCP/worker均终态。下一步继续N03其余四字段、N01完整当前预算、R01关系网络与完整B01–B04，优先新业务能力，按批次集中收尾；不要用重复partial验收代替开发。
"""
    prepend("HANDOFF.md", handoff)
    prepend("README(agent).md", "## 2026-10-27 第四十九批军事科技与陆军传统（最新）\n\n" +
            paragraph.replace("(军事质量只读接口.md)", "(docs/军事质量只读接口.md)") +
            "\n\n先读HANDOFF最新节及49批development-summary-001.json。军事等级按mil_tech定义查index，不假定固定槽；军传统直接缓存/1000。原独立采样001的累计计数误判仅作只读重析，未重采；N04过期父依赖用v2修正。当前PID31460/session31460-1dd653f69242d7b/date56557728/v27-002，physicalPOR/observerFRA；身份、no-repeat和历史归档事故见HANDOFF。")
    print(json.dumps({"documents_updated": 6, "full": full["summary_line"], "new_cases": added["cases"], "counts": coverage["counts"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
