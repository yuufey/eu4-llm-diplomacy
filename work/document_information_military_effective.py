"""Publish batch50 using the completed actual MCP and full-suite receipts."""
from __future__ import annotations
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.archive_information_military_effective import STAGE, read, regression


def prepend(relative, text, *, after_title=False, marker="2026-10-27 第五十批："):
    path = ROOT / relative
    raw = path.read_text(encoding="utf-8")
    assert marker not in raw[:8000], relative
    raw = raw.replace("第四十九批军事科技与陆军传统（最新）", "第四十九批军事科技与陆军传统（历史）", 1)
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
    runs = [read(path) for path in sorted(STAGE.glob("rea-*/run.json"))]
    assert runs and all(run["database_unchanged"] is True and run["cleanup"]["closed_process_receipt"] is True for run in runs)
    accepted = sum(run["exit_code"] == 0 for run in runs)
    rejected = len(runs) - accepted
    assert all(run["exit_code"] == 0 or run["reason"] == "postread_guard_rejected" for run in runs)
    tests = (f"完整回归为{full['passed']}项通过、{full['failed']}项失败、{full['errors']}项错误，另{full['subtests_passed']}个子测试通过；"
             f"较49批新增失败节点{len(full['new_failure_nodes'])}、解决{len(full['resolved_failure_nodes'])}，全套仍非全绿。"
             f"新增{added['cases']}个用例均通过，已包含在完整统计中。")
    paragraph = ("2026-10-27 第五十批：N03新增本国陆海军士气缓存和纪律计算，FRA当前陆军士气为3.123、海军士气为2.142、纪律为100%。"
                 "`morale`返回army/navy两个原始整数，scale=1000，字段available、complete=true；"
                 "`discipline`为partial、complete=false，支持原生处理器结果不依赖未知线程标志的分支，相关非零贡献仍返回具体缺项原因。"
                 "两字段及既有科技、传统的共同查询、报告和三条两秒周期交付均通过实机对照，订阅已取消、服务退出码0。"
                 "职业度和军事修正仍待开发。配置覆盖为59 available / 120 partial / 218 planned、38个可调用主题；"
                 "本次含静态、未启用任务/战报来源的实机目录为59 / 109 / 229、35个可调用主题，均74主题397字段。"
                 + tests + "本批复用现有游戏进程和DLL。完整计划继续，调用见[军事质量只读接口](军事质量只读接口.md)。")
    for relative in ("docs/信息导出与订阅开发计划.md", "docs/信息接口使用说明.md"):
        prepend(relative, paragraph, after_title=True)
    prepend("docs/信息导出开发进展.md", "## 第五十批：陆海军士气与纪律\n\n" + paragraph, after_title=True)
    receipt = ("第五十批实机结果：FRA陆军士气raw3123/1000=3.123、海军士气raw2142/1000=2.142，"
               "纪律raw1000/1000=1.000，即100%。两字段、既有科技与传统共同查询、报告及三条两秒周期交付均通过，"
               "订阅已取消，服务退出码0。见[实机报告](../work/runtime/information-military-effective-20261027-001/live-acceptance-001/report.json)。")
    prepend("docs/军事质量只读接口.md", receipt + "\n\n" + tests,
            after_title=True, marker="第五十批实机结果：")

    previous = (ROOT / "HANDOFF.md").read_text(encoding="utf-8").split("## 2026-10-27 第四十八批", 1)[0]
    paragraphs = previous.split("\n\n")
    identity = next(value for value in paragraphs if value.startswith("当前PID31460/"))
    controls = next(value for value in paragraphs if value.startswith("世界仍领先v27 checkpoint35天。"))
    handoff = f"""## 2026-10-27 第五十批士气与纪律（最新）

N03.morale和discipline已通过真实MCP query/report/periodic。FRA/1.37.4/country/空参数：morale value/raw={{army:3123,navy:2142}}，raw_hex army330c0000/navy5e080000，unitmorale/scale1000/current/basis native_country_morale_caches/origin copied_native_country_morale_cache，available、字段complete=true；discipline value/raw1000/raw_hexe8030000，ratio/1000/current/basis native_country_discipline_calculation/origin derived_from_copied_native_inputs，partial、complete=false。显式士气查询完整，含纪律的报告保持partial。既有military_technology=4和army_tradition=21052保留；professionalism/military_modifiers仍planned。调用见docs/军事质量只读接口.md，归档入口work/runtime/information-military-effective-20261027-001/development-summary-001.json。

morale-effective-source003闭合country+9874/+987C current army/navy caches、signed32和scale1000，119FB40/119FFD0写tag9/kind2的数值record；直接缓存字段不要求先重建tooltip。旧49 source002把neutral1000误读为9874本身；新REA33FFA0证明比较实际在country+E0C（maintenance），003明确更正并保留旧原件。morale不声称重构最大值全部公式、缓存刷新或主线程原子性。

纪律getter341850读取country正常modifier cache28D0中的key77，使用首匹配dense/sparse值；数据库必须先解引用globalRVA2358060，再+77*60+40，不能把global地址加index当静态slot RVA。实际processor vtable1CC9400/+8→8F71D0，由8F1DF0构造。处理器从raw77开始，按global233FF0C/233FF2C/233FF54与233FEB6及TLS slot0+10门控，加入key102/1BB/1D2/1C2的原生截断贡献。公开计算保留signed32 wrap和下限10；空processor或已识别processor的门关闭/贡献为0时可知。enabled非零贡献返回MILITARY_PROCESSOR_THREAD_CONTEXT_UNAVAILABLE，不假定TLS为0。当前四gate关闭、各raw0，结果1000。

生产military_effective初版把内嵌28D0误读为pointer，fake也镜像该错误；root对照成熟religious_unity和独立raw发现。最终reader/validator与fixture已修为内嵌对象，原profile/source-contract001保留，启用v2 SHA018fa77f0774e53075dd3536bd9578880fbc903f8074709b46755f5a34045868、source-contract002。独立raw003的字段字节离线重放通过，完整production guards由静态profile补齐的部分明确注明，未将其冒充RPM guard证据。morale profile SHA d7fc255f69092e6886c2d153e23ab839c22f914832799529d728968a2f16bfa6。母reader同一include_military_quality加入两child，top/before/after、doublepass、cleanup撤回和单次capture共享；坏child不抹掉稳定兄弟字段。

独立RPM三份原件均observed/双遍一致/handleclosed，001定位实际callback；002补新发现的callback四输入与flags；003补新闭合morale缓存和profession raw。003的profession raw655只是country+50 signedQword存储证据，公开接口仍未提供其换算。expected002 SHA33f2e9d74c5d889a0c5a3c912aa5d325c3dbcedc33c7905ff5723198157789e3来自独立raw003重算，不导入生产military reader或MCP值；仅discipline的expected001保留。新执行{len(runs)}次REA函数查询复用同SHA完整缓存，{accepted}次完整成功、{rejected}次provider成功但wrapper后读因32MB JSON超过10MB限制拒绝；所有数据库unchanged/closed，无重新分析全映像。拒绝的原run不改为成功，保留载荷只作后续有界提取入口。普通PE、已接收REA、被拒绝载荷、RPM和MCP分层。profession真正参数展开callee为14B2B40。worker收尾报告type8 case14B308A读取frame+58，模板%2选择%.2f、路径为raw*100/32768；尚未形成006证据文件，不能据这段口头结论直接发布。下一批先将1993B有界函数及静态常量固化，再接入；无需重采raw655，也不再追析构函数。

N04 native布局和覆盖不变；同批父源码增加optional children后最终domestic v4 SHA c326468add21b0ff3434957b6a5426297c72fe011bc091654a3440b944a58b15仅更新父依赖/版本说明。v2和中间v3保留，v3没有实机验收声明；v4真实MCP六个字段均known。新两字段、默认其余未实现、四字段混合、report、3条两秒periodic、cancel/noactive、serverexit0全部通过；outboxdelivered/llm_readunknown。最新pause/date/player见50 after-control：56557728/paused1/speed0/slot189。

{tests}失败/错误{full['failure_error_occurrences']}次/{full['unique_failure_error_nodes']}唯一节点，既有债务分类沿用45收据。配置59/120/218、38callable；actual59/109/229、35callable；仅morale planned→available与discipline planned→partial。完整74主题397字段、阶段2/3/4、LLM自主订阅及完整B01–B04继续goal active。新增能力不能替代完整目录最终验收。

{identity}

{controls}

历史完整性：39两份wiring-tests001 XML/log原字节未恢复，旧pin不改；45 expected草稿已按原SHA重建，46/47/48/49原件保留。50修正只新增版本，源码在实机/全回归前冻结，收尾快照按该版本保存，自有shell/MCP/worker终态。下一步优先固化professionalism type8分支/常量（标量包装15C260、特殊溢出14BEE40按具体需要补），完成公开接线；再继续纪律非零线程分支、military_modifiers、N01完整预算、R01关系网络与完整B01–B04。成熟保存启动直接复用，消费错误用原始记录修复，按批次集中收尾。
"""
    prepend("HANDOFF.md", handoff, marker="第五十批士气与纪律（最新）")
    prepend("README(agent).md", "## 2026-10-27 第五十批士气与纪律（最新）\n\n" +
            paragraph.replace("(军事质量只读接口.md)", "(docs/军事质量只读接口.md)") +
            "\n\n先读HANDOFF最新节及50批development-summary-001.json。morale是两侧current caches，discipline仍缺enabled非零线程贡献；profession仅raw655及type8模板链，不得猜scale。当前PID31460/session31460-1dd653f69242d7b/date56557728/v27-002，physicalPOR/observerFRA；完整身份、no-repeat及历史完整性见HANDOFF。")
    print(json.dumps({"documents_updated": 6, "full": full["summary_line"], "new_cases": added["cases"],
                      "REA_queries": len(runs), "counts": coverage["counts"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
