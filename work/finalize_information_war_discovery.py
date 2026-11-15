"""Update batch65 coverage metadata and the current handoff from sealed receipts."""
from __future__ import annotations
from collections import Counter
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.information.catalog import get_topic
from work.verify_information_war_discovery import STAGE, read, pin, put


def main():
    live = read(STAGE / "live-acceptance-003/report.json")
    regression = read(STAGE / "regression-comparison-001.json")
    assert live["status"] == "passed" and live["server_exit_code"] == 0
    assert not regression["new_failure_nodes"] and not regression["new_test_failures"]
    assert read(STAGE / "source-post-run-verification-001.json")["count"] == 154
    audit = read(STAGE / "live-final-audit-001.json")
    assert audit["status"] in {"passed", "passed_read_only_audit_with_future_same_server_unverified"}
    assert audit["old64_archive_532"]["all_declared_pins_match"] is True
    assert audit["service_database"]["active_zero"] is True
    assert read(STAGE / "live-final-audit-scope-note-001.json")["status"] == "passed"
    coverage_path = ROOT / "docs/信息字段覆盖.json"
    coverage = read(coverage_path)
    before = pin(coverage_path)
    changed = {"W01", "P03", "P04", "P05", "A02"}
    for index, topic in enumerate(coverage["topics"]):
        if topic["topic_id"] in changed:
            current = get_topic(topic["topic_id"])
            assert {k: v["coverage"] for k, v in current["fields"].items()} == {
                k: v["coverage"] for k, v in topic["fields"].items()}
            coverage["topics"][index] = current
    actual_counts = Counter(field["coverage"] for topic in coverage["topics"] for field in topic["fields"].values())
    assert dict(actual_counts) == coverage["counts"]["field_counts"]
    coverage["war_peace_discovery"] = {
        "batch": 65, "metadata_topics_updated": sorted(changed), "coverage_counts_unchanged": True,
        "live": "work/runtime/information-war-discovery-20261027-001/live-acceptance-003/report.json",
        "query_origin": "live-acceptance-001", "report_origin": "live-acceptance-002",
        "war_id": live["war_id"], "date_raw": live["game_date"],
        "full_war_context_complete": False, "same_date_reload_verified": False,
        "A02_evidence": "synthetic completeness negative, no new A02 live query",
    }
    coverage_path.write_text(json.dumps(coverage, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    put(STAGE / "coverage-metadata-update-001.json", {"status": "passed", "before": before,
        "after": pin(coverage_path), "field_counts": dict(actual_counts), "topics_updated": sorted(changed),
        "counts_upgraded": False})
    summary = {
        "schema": "information.war_discovery.development_summary.v1", "batch": 65, "goal": "active",
        "status": "batch_completed_full_plan_continues", "war_id": live["war_id"],
        "changes": {"W01": "Dedicated session/date-checked pair discovery, explicit war selection and public candidate objects.",
                    "P04": "Preserve complete/available/scope while exposing consequences and territorial projection.",
                    "P05": "Expose coalition object with genuine empty collection and native completeness.",
                    "P03_A02": "Use completeness rather than details availability."},
        "regression": {"summary": regression["summary_line"], "new_passed": len(regression["added_nodes"]),
                       "new_failure_nodes": [], "existing_failure_error_occurrences": 141,
                       "existing_failure_error_nodes": 128, "frozen_sources": 154},
        "live": pin(STAGE / "live-acceptance-003/report.json"), "independent_audit": pin(STAGE / "live-final-audit-001.json"),
        "audit_scope_correction": pin(STAGE / "live-final-audit-scope-note-001.json"),
        "evidence_reuse": {"queries": "live001 original successful responses; no query replay",
                           "report": "live002 original report and database; no report-create replay",
                           "live003": "first valid subscription, one scheduler result, cancel, server0",
                           "live001_failure": "checker counted private diagnostic events as final inspections",
                           "live002_failure": "required subscription name absent; rejected before checked-client RPC"},
        "coverage": coverage["counts"], "goal_complete": False,
        "final_world": {"installation": "work/runtime/diplomacy-observer-20261027-information-battle-v30-003/installation.json",
                        "pid": 36432, "creation_filetime": 134375780666987441,
                        "session_id": "36432-1dd660f811253b1", "physical_player": "POR", "slot": 189,
                        "date_raw": 56562768, "speed": 0, "paused": True,
                        "dll_sha256": "3d9e1fea9d8f34297a4a20646ea0b45d7d0f6a4af11cef6411586dd8b3264964",
                        "native_sources": 118, "wire": 6, "capture_state": "disabled", "captured": 11,
                        "capture_journal": "completed-disabled/unowned", "active_subscriptions": 0},
        "actions": {"business_dispatch": False, "advance": False, "save": False, "restart": False,
                    "install": False, "computer_use": False, "native_read_only_queries": True},
        "remaining": ["Full W01 participants/leaders/join dates/roles", "W02-P06 missing producers and scoped projections",
                      "All remaining 74-topic/397-field scope", "Full B01-B04 text and visibility", "Phases 2/3/4"],
        "same_date_reload_verified": False, "llm_read": "unknown",
    }
    if (STAGE / "line1-retention-001.json").exists():
        summary["line1_static_research"] = pin(STAGE / "line1-retention-001.json")
    put(STAGE / "development-summary-001.json", summary)
    body = f"""<!-- batch65-war-discovery-summary:start -->
## 第六十五批：LLM发现当前战争并查询选定议和后果

W01已改用一次ObserverSession.inspect_peace_contexts读取：唯一候选返回编号，多候选通过公开objects供选择，真实空集合、不完整枚举与旧编号未找到分别表达。编号、国家对、会话和日期及读取后context均校验，不猜第一场战争，不把两国标签当作完整参战者。完整领导人、参战者、加入日期和角色仍unknown。

P04后果总览/领土变化、P05包围网候选已接通既有公开peace_consequences；原始单位和complete/available/scope保持原样。P03及A02.acceptance_complete改取完整性标记，不再把details_available当作完整。A02本批仅有合成反例验证；P03、P04、P05取得实机正例。

真实MCP先用W01取得当前FRA→BUR战争，再显式选择；索取省份88的P04/P05/P03主动查询与同次3个原生结果逐项核对。后果总览complete=false、包围网候选available/complete=true且0个国家、接受明细完整性false。后台周期报告与主动原件一致，已取消、无活动订阅、server0。live001检查器误计内部诊断行，live002订阅缺name在RPC前拒绝；live003复用001成功查询与002成功report/数据库，只继续未执行的订阅与周期验证，没有重放原成功请求。

正式full001：3074 passed、106 failed、35 errors，另1938子测试通过；比64批新增16项全通过，无新增失败节点，既有141次失败/错误、128节点。154份源码在full和live前冻结并在结束后核对。覆盖矩阵只同步5个主题的来源与参数/路径，未升级覆盖计数：74主题397字段、60 available/159 partial/178 planned。完整阶段2/3/4、LLM自主订阅与完整B01–B04继续，goal active。

继续复用v30-003：PID36432、creation134375780666987441、session36432-1dd660f811253b1，1.37.4 EXE SHAb23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77、DLL SHA3d9e1fea9d8f34297a4a20646ea0b45d7d0f6a4af11cef6411586dd8b3264964、118 native sources、wire6。实测POR/slot189、raw56562768、speed0/paused1；来源disabled、累计11记录、journal completed-disabled/unowned，无活动订阅。补丁与展开资源仍随进程存在；不使用旧PID36240。本批无日期推进、保存、重启、安装、外交业务或Computer Use。

战报正文继续单列静态研究；Line1真实样本、metadata、完整展示与可见范围仍未完成，不因定位到函数或候选标题而升级为完整B04。现有保存、后台启动和成就提示确认入口继续复用《开发过程自动化.md》，不安排基础功能复测。

接口见[战争发现与议和信息](DOCLINK)，原件与独立审计见[第65批摘要](WORKLINK/development-summary-001.json)。历史successful/dispatched/unknown、原final-pass IDs、未闭合ownership及原120-action batch继续禁重试，尤其SIE→FRA military access proposal1和r70_country_money_001_outbound。61批比较JSON精确原件仍未恢复，不宣称其旧archive整体通过。
<!-- batch65-war-discovery-summary:end -->

"""
    for name in ("HANDOFF.md", "README(agent).md", "docs/信息导出与订阅开发计划.md"):
        path = ROOT / name
        old = path.read_text(encoding="utf-8")
        assert "batch65-war-discovery-summary:start" not in old
        prefix = "../" if name.startswith("docs/") else ""
        current = body.replace("DOCLINK", ("" if prefix else "docs/") + "战争发现与议和信息接口.md").replace("WORKLINK", prefix + "work/runtime/information-war-discovery-20261027-001")
        path.write_text(current + old, encoding="utf-8", newline="\n")
    print(json.dumps({"status": "passed", "goal": "active", "counts": dict(actual_counts)}))


if __name__ == "__main__":
    main()
