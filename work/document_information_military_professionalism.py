"""Publish batch51 from the frozen source, actual MCP and full-suite receipts."""
from __future__ import annotations
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.archive_information_military_professionalism import STAGE, read, regression


def prepend(relative, text, *, after_title=False, marker="2026-10-27 第五十一批："):
    path = ROOT / relative
    raw = path.read_text(encoding="utf-8")
    assert marker not in raw[:8000], relative
    raw = raw.replace("第五十批士气与纪律（最新）", "第五十批士气与纪律（历史）", 1)
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
             f"较50批新增失败节点{len(full['new_failure_nodes'])}、解决{len(full['resolved_failure_nodes'])}，全套仍非全绿。"
             f"新增{added['cases']}个用例均通过，已包含在完整统计中。")
    paragraph = ("2026-10-27 第五十一批：N03新增陆军职业度，FRA当前raw为655，按32768缩放为比例，约2%。"
                 "`professionalism`保留有符号64位整数和八字节原始编码，字段available、complete=true，支持主动查询、报告与周期订阅。"
                 "真实MCP结果与上一批独立采样的原始字节一致，五项军事字段共同查询、三条两秒周期交付和取消均通过。"
                 "科技、传统及士气继续可用，纪律仍partial，军事修正继续开发。配置覆盖为60 available / 120 partial / 217 planned、38个可调用主题；"
                 "本次含静态、未启用任务/战报来源的实机目录为60 / 109 / 228、35个可调用主题，均74主题397字段。"
                 + tests + "本批复用原进程和DLL，没有新增独立RPM采样。完整计划继续，调用见[军事质量只读接口](军事质量只读接口.md)。")
    for relative in ("docs/信息导出与订阅开发计划.md", "docs/信息接口使用说明.md"):
        prepend(relative, paragraph, after_title=True)
    prepend("docs/信息导出开发进展.md", "## 第五十一批：陆军职业度\n\n" + paragraph, after_title=True)
    receipt = ("第五十一批实机结果：FRA职业度raw655、八字节编码8f02000000000000、scale32768，即约2%。"
               "单字段查询完整，包含部分支持纪律的五字段查询保持complete=false；报告和三条两秒周期均与独立参考一致，"
               "订阅已取消、服务退出码0。见[实机报告](../work/runtime/information-military-professionalism-20261027-001/live-acceptance-001/report.json)。")
    prepend("docs/军事质量只读接口.md", receipt + "\n\n" + tests,
            after_title=True, marker="第五十一批实机结果：")

    previous = (ROOT / "HANDOFF.md").read_text(encoding="utf-8").split("## 2026-10-27 第四十九批", 1)[0]
    paragraphs = previous.split("\n\n")
    identity = next(value for value in paragraphs if value.startswith("当前PID31460/"))
    controls = next(value for value in paragraphs if value.startswith("世界仍领先v27 checkpoint35天。"))
    handoff = f"""## 2026-10-27 第五十一批陆军职业度（最新）

N03.professionalism已通过真实MCP query/report/periodic。FRA/1.37.4/country/空参数，value/raw655，raw_hex8f02000000000000，unitratio/scale32768/periodcurrent，basis native_country_army_professionalism_cache，origin copied_native_country_army_professionalism_cache；available、字段complete=true。raw/32768为比例，约1.9989%，两位百分数显示约2.00%；不是655%，也不按1000缩放。单字段结果完整；与tech4、army_tradition21052、morale3123/2142及partial discipline1000同一capture的五字段结果保持complete=false。military_modifiers仍planned，纪律enabled非零线程贡献缺口仍在。调用见docs/军事质量只读接口.md；归档入口work/runtime/information-military-professionalism-20261027-001/development-summary-001.json。

新ordinary bounded PE source professionalism-scale-source001 SHA38c22216a0a66ede57132ce41f74f5b20d046c5650318eb552cb64fe5a330cdf固化14B2B40..14B3309的type8分支14B308A、frame+58和32768常量；REX.W CVTSI2SD为signed64，模板$VALUE|Y%2$选择百分比/精度2。新增解码2407B，没有新REA或整映像分析。50已闭合的UI currentcountry→9A530→country+50和writer token36D6/%lld共同绑定直接8B缓存。生产read不再解引用country+50、不调用formatter或native getter，也不声称刷新时机、主线程原子性、训练收益或职业度变化公式。50被拒绝的32MB REA14B33A0原run保持postread_guard_error，未用它替代已接收Evidence或重复查询。

military_professionalism_memory/profile SHA6ba4de58e640483d39fa928758549eee0d81cf2f61fb079df57d84e30cc93d00，bounded signed QWORD、8KiB child预算、预扣、真实profile/code/record验证。母country_resources_memory在同一strict include_military_quality下加入military_professionalism，top/before/after、doublepass、cleanup整体撤回及请求上下文检查完整。无效child仅撤回职业度，稳定兄弟字段保留；母context变化全部撤回。原始字节离线回放包含profile静态补全guards，明确不将静态补全冒充旧RPM guard证据。

独立参考expected-military-professionalism001 SHAc8aba5b60e5a3879a8347fd83fe3c5998e87f650a325c4df2603b98b78aa20eb复用50 immutable raw003，按50 summary原pin核对，双遍/句柄closed/完整FRA fullref465241007a000001/slot122/日期56557728/creation/session/EXE一致，独立signed8B解码655。单位来自新static proof，不从MCP回填，不导入生产职业度reader，本批0新增独立RPM。当前MCP复制的新原生数据与该参考匹配，五字段混合及default的military_modifiers unsupported均如实保留；report、3条两秒periodic、cancel/noactive/serverexit0通过。outboxdelivered/llm_readunknown。最新pause/date/player见51 after-control：56557728/paused1/speed0/slot189。

N04仅父源码依赖重绑至domestic v5 SHAbaa4610a31a1293a418bcc14b2827e3cb4dceec3ac5c2b679201bfe800111fad，v4原件保留、native布局/guards与覆盖不变；真实MCP六个既有字段全部known。{tests}失败/错误{full['failure_error_occurrences']}次/{full['unique_failure_error_nodes']}唯一节点，既有债务分类沿用45收据。配置60/120/217、38callable；actual60/109/228、35callable；仅professionalism planned→available。完整74主题397字段、阶段2/3/4、LLM自主订阅及完整B01–B04继续goal active。

{identity}

{controls}

历史完整性：39两份wiring-tests001 XML/log原字节仍未恢复，旧pin不改；45 expected草稿按原SHA重建，46至50原件保留。51用新stage排他收据与源码快照；自有shell/MCP/worker均终态。下一步N03.military_modifiers见next-military-modifiers-source001：已有keyed numeric cache只提供数值，不等于active modifiers及其定义、来源、对象、期限、移除条件和效果；不能挑几个ID或把697槽位冒充完整军事修正。继续其实际容器/definition连接、纪律线程分支、N01完整预算、R01关系网络及完整B01–B04。成熟保存启动复用，消费错误重读原记录，按批次集中收尾。
"""
    prepend("HANDOFF.md", handoff, marker="第五十一批陆军职业度（最新）")
    prepend("README(agent).md", "## 2026-10-27 第五十一批陆军职业度（最新）\n\n" +
            paragraph.replace("(军事质量只读接口.md)", "(docs/军事质量只读接口.md)") +
            "\n\n先读HANDOFF最新节及51批development-summary-001.json。职业度为country+50的inline signedQword、ratio/32768；旧raw003可直接复用，未重采。军事修正仍缺active容器/定义及来源期限连接，纪律仍缺enabled非零线程路径。当前PID31460/session31460-1dd653f69242d7b/date56557728/v27-002，physicalPOR/observerFRA；身份、no-repeat和历史完整性见HANDOFF。")
    print(json.dumps({"documents_updated": 6, "full": full["summary_line"], "new_cases": added["cases"],
                      "counts": coverage["counts"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
