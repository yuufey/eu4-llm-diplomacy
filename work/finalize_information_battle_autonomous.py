"""Record batch64 results after the once-only live checks have ended."""
from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from work.verify_information_battle_autonomous import ROOT, STAGE, read, pin, put


def main():
    live = read(STAGE / "live-acceptance-003/report.json")
    peace = read(STAGE / "peace-live-002/report.json")
    full = read(STAGE / "regression-comparison-002.json")
    sources = read(STAGE / "source-post-run-verification-002.json")
    historical = read(STAGE / "historical-archive-verification-001.json")
    installation = ROOT / "work/runtime/diplomacy-observer-20261027-information-battle-v30-003/installation.json"
    identity = read(installation)
    if live["status"] != "passed" or live["server_exit_code"] != 0:
        raise ValueError("autonomous_live_not_complete")
    if sources["count"] != 152 or full["new_failure_nodes"] or full["new_test_failures"]:
        raise ValueError("source_or_regression_verification_failed")
    peace_passed = peace["status"] == "passed"
    peace_line = (
        "P05.overextension 已补入 peace_consequences.overextension 路径，保留旧路径。真实R66结果投影测试通过；当前战争的一次只读发现和一次真实MCP查询也已核对：索取省份88的方案使BUR预计过度扩张12%→0、FRA 0→12%。原始值120/scale1000、fraction单位和国家方向保持原样；这只是选定条款的只读预览，不是议和执行或完整战争上下文。peace-live001在native/MCP前因验收脚本调用了错误对象的方法失败；修正为ObserverSession路由后，peace-live002通过，未重查已成功请求。"
        if peace_passed else
        "P05.overextension 已补入 peace_consequences.overextension 路径，保留旧路径；真实R66结果投影测试通过。当前实机查询未取得可判定正例，具体限制见 peace-live-002/report.json，不把夹具投影称为当前实机通过。"
    )
    summary = {
        "schema": "information.battle.autonomous.development_summary.v1", "batch": 64,
        "goal": "active", "status": "batch_completed_full_plan_continues",
        "changes": [
            "Reject service/ingestion SQLite aliases before constructing live ingestion or capture manager.",
            "Preserve native status publication stage/error; retry transient heartbeat publication up to 3 seconds without command replay or game-thread sleep.",
            "Add P05 peace_consequences.overextension fallback, preserving prior paths and source semantics.",
        ],
        "live": {"report": pin(STAGE / "live-acceptance-003/report.json"),
                 "checks": live["checks"], "natural_window": live["natural_window"],
                 "post_window": live["post_window"], "server_exit_code": 0},
        "peace": {"status": peace["status"], "report": pin(STAGE / "peace-live-002/report.json"),
                  "first_failure": pin(STAGE / "peace-live-001/report.json"),
                  "first_failure_no_native_or_mcp": True},
        "regression": {"formal": "full002", "summary": full["summary_line"],
                       "new_passed_tests": 5, "new_failure_nodes": [], "existing_failure_error_occurrences": 141,
                       "existing_unique_failure_error_nodes": 128, "sources": 152},
        "native_fixture": {"report": pin(STAGE / "native-fixtures-126/report.json"),
                           "checks": 156, "evidence_kind": "own synthetic process fixture"},
        "status_reader_live": pin(STAGE / "status-reader-recovery-001/report.json"),
        "old_source_fault": {"installation": "v30-002", "pid": 36240,
                             "exact_original_win32_error": "not recorded by old code",
                             "original_failure_retained": "live-acceptance-001/report.json", "old_process_exited": True},
        "checkpoint": {"report": pin(STAGE / "checkpoint-v30-003-001/outcome-001.json"),
                       "sha256": "57cbc5c9ccd9325700a1d46714ce4ebb2ed5710e0b5f36c8a5c69a2f931d6c2c",
                       "bytes": 43252429, "before_restart": True, "basic_save_retest": False},
        "installation": {"path": pin(installation), "pid": identity["pid"],
                         "creation_filetime": identity["creation_filetime"], "session_id": identity["session_id"],
                         "game_sha256": identity["game_sha256"], "dll_sha256": identity["dll_sha256"],
                         "native_sources": 118, "wire": 6, "whole_feature_runtime_verified": False},
        "final_world": {"physical_player": "POR", "slot": 189, "date_raw": 56562768,
                        "paused": True, "speed": 0, "capture": "disabled", "journal": "completed-disabled",
                        "owned": False, "active_subscriptions": 0},
        "coverage": {"topics": 74, "fields": 397, "available": 60, "partial": 159, "planned": 178},
        "preserved_failures": {"full001": True, "live001": "old collector fault; no MCP/control/advance",
                               "live002": "zero-baseline checker expected first sequence 1; no MCP/control/advance",
                               "helper_correction": "independent validator only, original bytes in acceptance-source-snapshots-002"},
        "historical_archives": pin(STAGE / "historical-archive-verification-001.json"),
        "limitations": ["Delivery to durable outbox does not prove LLM read.",
                        "B04 raw_text remains unsupported; details and native title candidates are partial.",
                        "Visibility, full window text, metadata/Line1, and full B01-B04 remain incomplete.",
                        "Full phases 2/3/4 and 74-topic 397-field plan remain active.",
                        "Historical batch61 overwritten comparison original remains unrecovered."],
        "no_repeat": ["historical successful/dispatched/unknown", "original final-pass request IDs",
                      "unclosed ownership", "original 120-action batch", "SIE->FRA military_access proposal1",
                      "r70_country_money_001_outbound"],
        "computer_use": False, "diplomacy_business_dispatch": False,
    }
    put(STAGE / "development-summary-001.json", summary)
    body = f"""<!-- batch64-autonomous-live-summary:start -->
## 第六十四批：战报订阅在同一服务内自动采集与交付

一次35天 TEST_ONLY 自然观察 raw56561928→56562768 已在同一服务内完成：首个事件订阅启用来源，原生记录0→11，后台定时摄取并交付法国参与的事件6，下一次列出结果时编号稳定且无重复。已取消订阅，无活动订阅，采集disabled、journal completed-disabled/unowned、server0。没有 information_tick、外交业务或构造战斗；durable outbox交付不代表LLM已阅读，B04正文仍unsupported、details为partial。

服务启动现在拒绝与摄取数据库同文件的配置，包含路径别名和硬链接。旧v30-002采集器在暂停期间进入fault，其原始Win32错误未记录，不能断言确切原因。新代码保存发布阶段和错误，仅对heartbeat的瞬态发布失败有限重试（最多3秒、无游戏线程Sleep、不重发控制）。自有原生夹具156项通过；实机禁用来源下持有状态文件读取句柄后出现6次替换错误5，释放后恢复发布，采集与控制均未触发。

{peace_line}

正式 full002：3058 passed、106 failed、35 errors，另1938子测试通过；相对63批新增5项全通过，无新增失败节点，既有141次失败/错误、128节点。152份运行源码在full002前冻结并于全部验收后核对。full001与失败live001/002原件保留；两次失败均未启动MCP或推进日期，唯一自然窗口属于live003。覆盖仍74主题397字段、60 available/159 partial/178 planned；完整阶段2/3/4、LLM自主订阅与完整B01–B04继续，goal active。

当前为 work/runtime/diplomacy-observer-20261027-information-battle-v30-003/installation.json：PID36432、creation134375780666987441、session36432-1dd660f811253b1，EXE1.37.4 SHA b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77，DLL SHA3d9e1fea9d8f34297a4a20646ea0b45d7d0f6a4af11cef6411586dd8b3264964、118 native sources、wire6。最后POR/slot189、raw56562768、speed0/paused1；补丁和展开资源仍随进程存在。旧PID36240已退出，禁止再用旧安装控制。

换DLL前复用成熟autosave保存一次checkpoint（43252429B、SHA57cbc5c9ccd9325700a1d46714ce4ebb2ed5710e0b5f36c8a5c69a2f931d6c2c），恢复3份轮换存档；后台启动和 --confirm-load-warning 原生确认完成载入，只安装一次，没有Computer Use或基础保存/重载复测。成就提示备用入口仍为《开发过程自动化.md》第4节WM_CHAR小写c，当前已载入不重复发送。

旧62批447件和63批540件全部哈希匹配；新夹具125/126误写旧stage后仅移动了这些新增文件，原报告字节及路径映射保留。61批比较JSON原件仍未恢复。历史successful/dispatched/unknown、原final-pass IDs、未闭合ownership及原120-action batch继续禁重试，尤其SIE→FRA military access proposal1和r70_country_money_001_outbound。

收据见[第64批摘要](WORKLINK/development-summary-001.json)；调用见[战报订阅采集管理](DOCLINK)。下一步继续完整窗口文字、可见性和计划其余字段；W01战争发现的复数列表与单数字段路径缺口尚未修复。
<!-- batch64-autonomous-live-summary:end -->

"""
    for relative in ("HANDOFF.md", "README(agent).md", "docs/信息导出与订阅开发计划.md"):
        path = ROOT / relative
        previous = path.read_text(encoding="utf-8")
        if "batch64-autonomous-live-summary:start" in previous:
            raise ValueError("batch64_already_written:" + relative)
        parent = "../" if relative.startswith("docs/") else ""
        text = body.replace("WORKLINK", parent + "work/runtime/information-battle-autonomous-live-20261027-001").replace("DOCLINK", ("" if parent else "docs/") + "战报订阅采集管理.md")
        path.write_text(text + previous, encoding="utf-8", newline="\n")
    documentation = ROOT / "docs/战报订阅采集管理.md"
    text = documentation.read_text(encoding="utf-8")
    text = text[:text.index("## 当前验证边界")]
    text += """## 当前验证边界

第64批的live003已补上同一服务实例在自然观察中同时采集和交付的实证。新安装零记录起步，创建一个B04事件订阅后来源启用；35天自然观察产生11条记录，后台一秒定时处理交付法国参与的事件6。没有调用information_tick，后续结果编号稳定且无重复，持久结果可读取。取消后无活动订阅，管理器释放自有来源，journal completed-disabled、来源disabled、server0。详细收据见[实机报告](../work/runtime/information-battle-autonomous-live-20261027-001/live-acceptance-003/report.json)。

该结果的details可用、raw_text仍unsupported，整体partial/complete=false；durable outbox交付不证明LLM已阅读。原生记录的传输完整不等于完整窗口文字或全部战斗可见性。其他可知战斗、metadata、Line1及完整B01–B04仍有缺口。

原生heartbeat发布现在记录status_write_stage、status_write_error、status_publication_failures和status_publication_pending。共享/锁冲突及replace阶段的ACCESS_DENIED按帧有限重试，最多3秒；非replace阶段的权限错误及持续失败仍终止，不重发enable/disable。读取句柄阻塞替换、释放后恢复已经在禁用的实机来源下通过；旧v30-002原始fault的确切Win32错误没有记录，不能从新测试倒推为已查明。

第63批已通过的共享与暂停/恢复步骤继续保留；其live002共库摄取失败的旧结论仍由独立审计撤销，第64批不会把这份旧失败改写成成功。64批live001被旧source fault拦在只读preflight，live002被独立零基线检查器拦截，均无MCP启动、控制或日期推进；只有live003执行了自然窗口。

正式full002为3058 passed、106 failed、35 errors，另1938子测试通过；较63批新增5项全通过，无新增失败节点。152份源码在回归前冻结并在实机结束后核对。当前进程身份与后续操作以HANDOFF最新段为准。
"""
    documentation.write_text(text, encoding="utf-8", newline="\n")
    automation = ROOT / "开发过程自动化.md"
    text = automation.read_text(encoding="utf-8")
    note = "2026-10-27续接说明："
    pos = text.index(note)
    text = text[:pos] + "2026-10-27第64批实测：换用v30-003前复用成熟autosave保存当前暂停现场，后台重启后由observer安装器的 `--confirm-load-warning` 完成原生确认和载入，未使用Computer Use。仅安装一次；保存和35天自然观察为本批实际开发所需操作，没有另设基础保存或重载验收。证据见 `work/runtime/information-battle-autonomous-live-20261027-001/checkpoint-v30-003-001/outcome-001.json`、`installer-001.log` 和 `natural-window-001/report.json`。当前运行身份以HANDOFF顶部为准。\n\n" + text[pos:]
    automation.write_text(text, encoding="utf-8", newline="\n")
    print(json.dumps({"status": "passed", "batch": 64, "goal": "active", "peace": peace["status"]}))


if __name__ == "__main__":
    main()
