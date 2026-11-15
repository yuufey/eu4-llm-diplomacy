"""Write batch63 conclusions from retained receipts; no game or test calls."""
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.archive_information_battle_capture_management import BUILD, STAGE, pin, put, read


def main():
    regression = read(STAGE / "regression-comparison-002.json")
    initial = read(STAGE / "live-acceptance-001/report.json")
    corrective = read(STAGE / "live-acceptance-002/report.json")
    recovery = read(STAGE / "live-acceptance-003/report.json")
    audit = read(STAGE / "live002-delivery-audit-001.json")
    control = read(STAGE / "final-control-001.json")
    native = read(STAGE / "final-source-status-001.json")["native"]
    installation = read(BUILD / "installation.json")
    if regression["new_failure_nodes"] or regression["new_test_failures"]:
        raise ValueError("new_regressions")
    if corrective["status"] != "passed" or recovery["status"] != "passed":
        raise ValueError("selected_receipts_failed")
    if native["state"] != "disabled" or control["paused_flag"] != 1 or control["speed"] != 0 or control["date_raw"] != 56561928:
        raise ValueError("final_state")
    preserved_checks = {key: initial["checks"][key] for key in (
        "sub1_manager_enabled_owned_one", "sub2_added_as_second_consumer",
        "sub2_pause_cancel_keeps_sub1_enabled_owned", "last_consumer_pause_disables_capture")}
    if not all(preserved_checks.values()):
        raise ValueError("shared_capture_evidence")
    summary = {
        "schema": "information.battle.capture_management.development_summary.v1",
        "batch": 63, "status": "progress", "goal": "active",
        "capability": "Subscription ownership and bounded heartbeat freshness for the already-installed passive producer",
        "topics": 74, "fields": 397, "coverage": {"available": 60, "partial": 159, "planned": 178},
        "identity": {key: installation[key] for key in ("pid", "creation_filetime", "session_id", "game_sha256", "dll_sha256")},
        "physical_player": "POR", "observer": "FRA", "control": control,
        "native": {"state": native["state"], "wire": 6, "initial_records": 11,
                   "final_records": int(native["captured"]), "new_records": int(native["captured"]) - 11,
                   "source_complete": False, "patches_remain_process_lifetime": True},
        "shared_lifecycle": {"receipt": pin(STAGE / "live-acceptance-001/report.json"),
                             "original_overall_status": "failed_at_resume_stale_heartbeat", "preserved_checks": preserved_checks},
        "corrective_lifecycle": {"receipt": pin(STAGE / "live-acceptance-002/report.json"),
                                  "status": "passed_for_producer_lifecycle_and_natural_window",
                                  "invalid_delivery_conclusions": True, "audit": pin(STAGE / "live002-delivery-audit-001.json")},
        "natural_window": corrective["natural_window"],
        "delivery_recovery": {"receipt": pin(STAGE / "live-acceptance-003/report.json"),
                              "event_ids": recovery["event_ids"], "new_window_event_ids": recovery["new_window_event_ids"],
                              "event_results": recovery["event_results"], "server_exit_code": recovery["server_exit_code"],
                              "checks": recovery["checks"], "scope": "autonomous consumption of retained raw log, with separate SQLite files",
                              "future_capture_and_delivery_in_same_server_verified": False},
        "regression": {"receipt": pin(STAGE / "regression-comparison-002.json"),
                       "summary": regression["summary_line"], "added_tests": len(regression["added_nodes"]),
                       "new_failure_nodes": [], "existing_failure_error_occurrences": regression["failure_error_occurrences"]},
        "source_freeze": pin(STAGE / "source-freeze-002.json"), "frozen_source_count": 151,
        "automation": {"computer_use": False, "save": False, "restart": False, "native_reinjection": False,
                       "new_natural_windows": 1, "historical_window_replayed": False,
                       "mature_warning_entry": "tools/confirm_observed_achievement_warning.py; WM_CHAR lowercase c"},
        "limitations": [
            "live002 ingestion failed because service and battle ingestion shared one SQLite file; empty delivery does not prove FRA absence",
            "live003 recovered event18 from the already captured new window; it did not rerun capture or advance",
            "live same-server collection plus automatic delivery during one natural window still requires evidence",
            "Complete GUI text, message metadata, Line1, visibility, full B01-B04, all74 topics/397 fields and phases2/3/4 remain unfinished",
        ],
        "no_repeat": "Historical successful/dispatched/unknown actions, original final-pass IDs, unclosed ownership and original120-action batch remain forbidden; especially SIE->FRA military_access proposal1 and r70_country_money_001_outbound",
    }
    put(STAGE / "development-summary-001.json", summary)
    marker = "batch63-capture-management-summary"
    paragraphs = (
        "已把战报订阅接到已安装采集器的启停：首个订阅启用，多个订阅共享，最后一个释放时只关闭本管理器拥有的来源。--battle-manage-capture 显式启用这一管理；单独 --battle-ingest-installation 仍只刷新日志数据库。服务返回配置与实际采集状态，unknown/pending 不重发。",
        "实机 live001 的首启、共享与最后暂停成功；立即恢复暴露旧 heartbeat 被当作外部来源的时序缺陷。已新增状态文件 observed_at_ns 和 journal 完成时间比较，最多3秒只读等待新状态，控制不重发。live002 在新订阅上补验暂停/恢复并最终关闭，复用原共享成功步骤。",
        "唯一新35天 TEST_ONLY 自然窗口 raw56561088→56561928，原生记录11→21，随后暂停。live002 因服务和摄取共用 SQLite 文件而摄取失败，原空结果不能证明没有法国战报；独立审计撤销其交付/去重/法国缺席结论。live003 分离数据库，从保留日志由后台定时处理交付事件1和新窗口事件18，下一次处理无重复；未再推进或启用采集。同一服务在自然观察中同时采集和交付仍未实证。",
        "正式 full002：3053 passed、106 failed、35 errors，另1938子测试通过；较62批新增29项全通过，无新增失败节点，既有141次失败/错误、128节点。151份源码在 full002 前留存并于结束后核对；full001、freeze001 和失败 live001 原件保留。覆盖仍74主题397字段、60 available/159 partial/178 planned；完整阶段2/3/4、LLM自主订阅与 B01–B04 继续，goal active。",
        "沿用 v30-002 installation：PID36240、creation134375709192033676、session36240-1dd65fedcd5158c，EXE1.37.4 SHA b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77，DLL SHA747c8ec25fb88d630378726c1f73f936936d3ce4d50a21f44aceadf2351def3b、118 native sources。最后 POR/slot189、raw56561928、speed0/paused1；采集disabled、journal completed-disabled、无活动订阅，两个最终MCP服务均exit0。补丁与展开资源仍随进程存在。",
        "本批未保存、重启、重新注入或使用 Computer Use。成就提示已有《开发过程自动化.md》第4节的原生确认及 WM_CHAR 小写 c 入口；当前已载入，不重复发送。历史成功/已派发/unknown、原final-pass IDs、未闭合ownership和原120-action batch继续禁重试，尤其 SIE→FRA military access proposal1 与 r70_country_money_001_outbound。第61批比较JSON误覆盖事件仍按第62批说明保留，未声称原件恢复。",
    )
    for relative in ("HANDOFF.md", "README(agent).md", "docs/信息导出与订阅开发计划.md"):
        path = ROOT / relative
        original = path.read_bytes()
        if len(original) > 10 * 1024 * 1024 or marker.encode() in original:
            raise ValueError("document_size_or_existing_marker:" + relative)
        prefix = "../" if relative.startswith("docs/") else ""
        text = (f"<!-- {marker}:start -->\n## 第六十三批：订阅管理已安装的战报采集器\n\n" +
                "\n\n".join(paragraphs) +
                f"\n\n调用见[战报订阅采集管理]({prefix}docs/战报订阅采集管理.md)，收据见[第63批摘要]({prefix}work/runtime/information-battle-capture-management-20261027-001/development-summary-001.json)。\n<!-- {marker}:end -->\n\n")
        path.write_bytes(text.encode("utf-8") + original)
    print(json.dumps({"status": "progress", "goal": "active", "new_records": 10,
                      "recovered_event_results": recovery["event_results"], "added_tests": len(regression["added_nodes"])}))


if __name__ == "__main__":
    main()
