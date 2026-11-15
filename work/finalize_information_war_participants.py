"""Publish batch67's verified scope while preserving the full development goal."""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.information.catalog import get_topic
from work.verify_information_war_participants import STAGE, pin, read_json, write_new


def main():
    live = read_json(STAGE / "live-acceptance-001/report.json")
    comparison = read_json(STAGE / "regression-comparison-001.json")
    audit = read_json(STAGE / "live-independent-audit-001.json")
    post = read_json(STAGE / "source-post-run-verification-001.json")
    checkpoint = read_json(STAGE / "checkpoint-war-members-001/outcome-001.json")
    identity = live["identity"]
    build_dir = ROOT / "work/runtime/diplomacy-observer-20261027-information-war-v30-004"
    status = read_json(build_dir / "information-battle-status.json")
    assert live["status"] == audit["status"] == post["status"] == "passed"
    assert all(live["checks"].values()) and live["server_exit_code"] == 0
    assert post["count"] == 163 and comparison["no_new_bad"] is True
    assert checkpoint["status"] == "saved_verified"
    assert status["state"] == "ready" and str(status["captured"]) == "0"
    assert status["code_patch_installed"] is False and status["unwind_registered"] is False
    public = read_json(STAGE / "live-acceptance-001/02-w01-query-response.json")
    participants = public["items"][0]["fields"]["participants"]["value"]
    marker = "<!-- batch67-war-participants-summary:start -->"
    docs = ("HANDOFF.md", "README(agent).md", "docs/信息导出与订阅开发计划.md")
    for name in docs:
        assert marker not in (ROOT / name).read_text(encoding="utf-8")
    for name in ("development-summary-001.json", "coverage-metadata-update-001.json"):
        assert not (STAGE / name).exists()
    coverage_path = ROOT / "docs/信息字段覆盖.json"
    before = pin(coverage_path)
    coverage = read_json(coverage_path)
    topic_index = next(i for i, topic in enumerate(coverage["topics"]) if topic["topic_id"] == "W01")
    topic = get_topic("W01")
    assert {k: v["coverage"] for k, v in topic["fields"].items()} == {
        k: v["coverage"] for k, v in coverage["topics"][topic_index]["fields"].items()}
    coverage["topics"][topic_index] = topic
    counts = dict(Counter(field["coverage"] for item in coverage["topics"] for field in item["fields"].values()))
    assert counts == coverage["counts"]["field_counts"]
    coverage["war_participants_selected_read"] = {
        "batch": 67, "metadata_topics_updated": ["W01"], "coverage_counts_unchanged": True,
        "live": "work/runtime/information-war-context-forces-20261027-001/live-acceptance-001/report.json",
        "war_id": live["war_id"], "session_id": identity["session_id"], "date_raw": live["expected"]["date_raw"],
        "source": "native_war_side_vectors", "side_a_count": len(participants["side_a"]),
        "side_b_count": len(participants["side_b"]), "participant_lists_complete": True,
        "leaders_roles_join_dates_verified": False, "full_war_context_complete": False,
        "same_date_reload_verified": False,
    }
    backup = STAGE / "documentation-before-finalize-001"
    for name in (*docs, "docs/信息字段覆盖.json"):
        path = backup / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as output:
            output.write((ROOT / name).read_bytes())
    coverage_path.write_text(json.dumps(coverage, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_new(STAGE / "coverage-metadata-update-001.json", {
        "status": "passed", "before": before, "after": pin(coverage_path),
        "before_snapshot": pin(backup / "docs/信息字段覆盖.json"), "topics_updated": ["W01"],
        "field_counts": counts, "counts_upgraded": False,
    })
    summary = {
        "schema": "information.war_participants.development_summary.v1", "batch": 67,
        "status": "batch_completed_full_plan_continues", "goal": "active", "goal_complete": False,
        "previous_goal_turn": "progress: batch66 implemented and verified W02 active and periodic war score reads",
        "changes": {"native_QUERY1": "Direct stable side-vector reads from the current registered war; no offer construction or game getter call.",
                    "bridge": "Pointer-free optional extension validated before projection; exact top-level capability required.",
                    "W01": "Known country-tag lists and actor/recipient sides for the selected war; no leadership or role inference.",
                    "installer": "Optional acknowledged extension requires the shared native source and the exact 119-source v30 build."},
        "regression": {"summary": comparison["summary_line"], "new_passed": len(comparison["added_nodes"]),
                       "new_failure_nodes": [], "existing_failure_error_occurrences": comparison["failure_error_occurrences"],
                       "existing_failure_error_nodes": comparison["unique_failure_error_nodes"], "frozen_sources": 163},
        "native_fixture": pin(STAGE / "native-participants-unit-001/fixture-report-002.json"),
        "python_targeted": pin(STAGE / "participants-python-test-001/participants-python-test-001.json"),
        "live": pin(STAGE / "live-acceptance-001/report.json"),
        "independent_audit": pin(STAGE / "live-independent-audit-001.json"),
        "source_post_run": pin(STAGE / "source-post-run-verification-001.json"),
        "participants": participants, "war_id": live["war_id"],
        "native_query_ids": {"active": live["active_native_query_id"], "periodic": live["periodic_native_query_id"]},
        "checkpoint": pin(STAGE / "checkpoint-war-members-001/outcome-001.json"),
        "checkpoint_save": checkpoint["save"], "coverage": coverage["counts"],
        "final_world": {"installation": live["installation"]["path"], "pid": identity["pid"],
                        "creation_filetime": identity["creation_filetime"], "session_id": identity["session_id"],
                        "game_sha256": identity["game_sha256"], "dll_sha256": identity["dll_sha256"],
                        "manifest_sha256": live["build_manifest"]["sha256"], "native_sources": 119,
                        "physical_player": "POR", "slot": 189, "date_raw": 56562768,
                        "speed": 0, "paused": True, "active_subscriptions": 0,
                        "battle_source_state": "ready", "battle_source_ever_enabled": False, "battle_captured": 0,
                        "battle_entry_patches_installed": False, "battle_unwind_registered": False,
                        "battle_binding_journal_raw": "absent, because the prepared source has never been enabled",
                        "observer_frame_hook_and_module": "remain installed for the game process lifetime"},
        "actions": {"business_dispatch": False, "advance": False, "checkpoint_save_count": 1,
                    "restart_count": 1, "install_count": 1, "computer_use": False},
        "research": {name: pin(STAGE / name) for name in (
            "country-army-record-semantics-001.json", "country-army-count-callers-001.json",
            "line1-dependency-review-001.json", "war-context-source-audit-001.json",
            "native-integration-review-001.json", "native-integration-review-scope-note-001.json",
            "regression-debt-scope-audit-001.json")},
        "remaining": ["W01 leaders, join dates, co-belligerent roles and complete visibility",
                      "N02 force-count units, active/deployed semantics, navy and force limits",
                      "W02 source rows, goal controller, daily score and duration", "Full B01-B04 text and visibility",
                      "All remaining 74-topic/397-field scope and phases 2/3/4"],
        "same_date_reload_verified": False, "llm_read": "unknown",
    }
    write_new(STAGE / "development-summary-001.json", summary)
    body = f"""{marker}
## 第六十七批：战争两侧参战名单

W01 已接通原生两侧国家向量：直接读取本次国家对发现的战争，不构造议和或调用游戏 getter。双遍检查向量头、完整国家引用及国家对象，拒绝重复、跨侧重叠和双方侧别歧义；失败或输出超限时保留战争编号、将名单置为未知。side_a/side_b 不表示进攻方、防御方或领导人，leaders、join_dates、co_belligerent_roles 继续 unknown。

新安装的真实 MCP 主动查询与后台周期查询各取得独立 query_id；两侧8国和10国、FRA side_a/BUR side_b，与三次独立 RPM 快照中的双遍原始读取一致。仅含编号和名单的查询可完整，全字段查询仍partial。订阅已取消，无活动订阅，server0。DLL安装和迁移期间未推进日期，POR/slot189、1456.12.9/raw56562768、speed0/paused1。

正式 full001：{comparison['summary_line']}。比66批新增{len(comparison['added_nodes'])}项通过，无新增失败节点；既有141次失败/错误、128节点。163份来源在 full 与 live 前冻结，结束后逐项核对。原生自有内存夹具11项通过。覆盖只更新 W01 元数据，仍74主题397字段、60 available/159 partial/178 planned；完整阶段2/3/4、LLM自主订阅与完整B01–B04继续，goal active。

当前安装为 work/runtime/diplomacy-observer-20261027-information-war-v30-004/installation.json：PID42960、creation134375854500787403、session42960-1dd6620b1e8b4cb，EXE1.37.4 SHA b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77、DLL SHA92fa4ea3b158e2ff42a69bce1cbbf7053b7f3a0ac128b25c9e5b7d1fb4bdc3ce、119 native sources。旧36432已退出，不沿用旧安装控制或战争编号。

新战报来源为ready、累计0，尚未启用；battle entry补丁和unwind均false，binding/journal/raw不存在是此状态的正常边界。observer帧钩子及模块仍随进程存在。没有新增自然战斗窗口；旧采集记录仍按旧会话归档，不写入新会话。

为换DLL复用成熟autosave保存现场一次（43393512B、SHA c65f8c991420338465888d8a55f9487da3eb6ab3aca65872ae1f58c6ff850a5d），恢复三份轮换存档。后台启动、--confirm-load-warning原生确认和载入完成，只安装一次；未使用Computer Use，也未安排基础保存或重载专项验收。

N02追到Declare War敌我兵力展示，但record+28单位及active/deployed语义仍未闭合，不升级字段。战报静态路径存在同步窗口填充分支，不能把Line1缺失归因于等待不足；真实正文与可见性继续研究。既有回归债审计未发现当前信息服务测试失败；hot-reload没有独立测试节点，不据此宣称验收完成。

调用见[战争参战名单](DOCLINK)，原件与审计见[第67批摘要](WORKLINK/development-summary-001.json)。历史successful/dispatched/unknown、原final-pass IDs、未闭合ownership及原120-action batch继续禁重试，尤其SIE→FRA military access proposal1和r70_country_money_001_outbound。61批比较JSON精确原件仍未恢复，不宣称旧61归档整体通过。
<!-- batch67-war-participants-summary:end -->

"""
    for name in docs:
        path = ROOT / name
        prefix = "../" if name.startswith("docs/") else ""
        current = body.replace("DOCLINK", ("" if prefix else "docs/") + "战争参战名单只读接口.md").replace(
            "WORKLINK", prefix + "work/runtime/information-war-context-forces-20261027-001")
        path.write_text(current + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    print(json.dumps({"status": "passed", "goal": "active", "counts": counts}))


if __name__ == "__main__":
    main()
