"""Record batch66 results without upgrading incomplete topic coverage."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.information.catalog import get_topic
from work.verify_information_war_score import STAGE, pin, read_json, write_new


def main():
    live = read_json(STAGE / "live-acceptance-001/report.json")
    comparison = read_json(STAGE / "regression-comparison-001.json")
    post = read_json(STAGE / "source-post-run-verification-001.json")
    audit = read_json(STAGE / "live-independent-audit-001.json")
    preservation = read_json(STAGE / "old65-archive-preservation-001.json")
    assert live["status"] == "passed" and live["server_exit_code"] == 0
    assert all(live["checks"].values())
    assert comparison["no_new_bad"] is True
    assert post["status"] == "passed" and post["count"] == 159
    assert audit["status"] == preservation["status"] == "passed"
    marker = "<!-- batch66-war-score-summary:start -->"
    doc_names = ("HANDOFF.md", "README(agent).md", "docs/信息导出与订阅开发计划.md")
    for name in doc_names:
        assert marker not in (ROOT / name).read_text(encoding="utf-8")
    for name in ("coverage-metadata-update-001.json", "development-summary-001.json"):
        assert not (STAGE / name).exists()
    coverage_path = ROOT / "docs/信息字段覆盖.json"
    old_coverage = coverage_path.read_bytes()
    before_pin = pin(coverage_path)
    coverage = json.loads(old_coverage)
    counts_before = deepcopy(coverage["counts"])
    topic_index = next(i for i, topic in enumerate(coverage["topics"]) if topic["topic_id"] == "W02")
    old_topic = coverage["topics"][topic_index]
    current = get_topic("W02")
    assert {k: v["coverage"] for k, v in current["fields"].items()} == {
        k: v["coverage"] for k, v in old_topic["fields"].items()}
    coverage["topics"][topic_index] = current
    field_counts = dict(Counter(field["coverage"] for topic in coverage["topics"]
                               for field in topic["fields"].values()))
    assert field_counts == counts_before["field_counts"]
    coverage["war_score_selected_read"] = {
        "batch": 66, "metadata_topics_updated": ["W02"], "coverage_counts_unchanged": True,
        "live": "work/runtime/information-war-score-20261027-001/live-acceptance-001/report.json",
        "war_id": live["war_id"], "date_raw": live["date_raw"],
        "mode": "whole_war", "perspective": "actor", "native_capability": "native_live_war_score_query",
        "total_scale": 1, "cumulative_goal_scale": 1000,
        "goal_presence_preserved": True, "full_war_context_complete": False,
        "other_fields": "WAR_SCORE_FIELD_UNIMPLEMENTED", "same_date_reload_verified": False,
    }
    backups = STAGE / "documentation-before-finalize-001"
    for name in (*doc_names, "docs/信息字段覆盖.json", "docs/战争分数只读接口.md"):
        target = backups / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write((ROOT / name).read_bytes())
    coverage_path.write_text(json.dumps(coverage, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_new(STAGE / "coverage-metadata-update-001.json", {
        "status": "passed", "before": before_pin, "after": pin(coverage_path),
        "topics_updated": ["W02"], "field_counts": field_counts, "counts_upgraded": False,
        "before_snapshot": pin(backups / "docs/信息字段覆盖.json"),
    })
    world = {
        "installation": live["installation"]["path"], "pid": live["identity"]["pid"],
        "creation_filetime": live["identity"]["creation_filetime"],
        "session_id": live["identity"]["session_id"], "physical_player": "POR", "slot": 189,
        "date_raw": live["date_raw"], "speed": 0, "paused": True,
        "game_sha256": live["identity"]["game_sha256"], "dll_sha256": live["identity"]["dll_sha256"],
        "native_sources": 118, "wire": 6, "capture_state": "disabled", "captured": 11,
        "capture_journal": "completed-disabled/unowned", "active_subscriptions": 0,
        "patches_and_unwind_resources": "remain installed for the game process lifetime",
    }
    summary = {
        "schema": "information.war_score.development_summary.v1", "batch": 66,
        "status": "batch_completed_full_plan_continues", "goal": "active", "goal_complete": False,
        "war_id": live["war_id"],
        "changes": {
            "W02": "One selected empty peace inspection supplies true total and cumulative goal score with current identity guards.",
            "goal_presence": "Native presence, present and inapplicable are public; genuine zero differs from no configured goal and read failure.",
            "catalog": "Only white_peace/initiate and explicitly selected war; terms are empty; war selectors must agree.",
        },
        "regression": {"summary": comparison["summary_line"], "new_passed": len(comparison["added_nodes"]),
                       "new_failure_nodes": [], "existing_failure_error_occurrences": comparison["failure_error_occurrences"],
                       "existing_failure_error_nodes": comparison["unique_failure_error_nodes"], "frozen_sources": 159},
        "live": pin(STAGE / "live-acceptance-001/report.json"),
        "independent_audit": pin(STAGE / "live-independent-audit-001.json"),
        "old65_archive_preservation": pin(STAGE / "old65-archive-preservation-001.json"),
        "source_post_run": pin(STAGE / "source-post-run-verification-001.json"),
        "acceptance_scripts_before_live": pin(STAGE / "acceptance-scripts-before-live-001.json"),
        "actual_score": {"actor": "FRA", "recipient": "BUR", "mode": "whole_war", "perspective": "actor",
                         "total": live["values"]["score"]["total"], "cumulative_goal": live["values"]["cumulative"]},
        "native_query_ids": live["native_query_ids"], "coverage": coverage["counts"], "final_world": world,
        "country_forces_research": {
            "evidence_kind": "ordinary bounded static disassembly; no new REA or runtime result",
            "receipt": pin(STAGE / "country-army-getter-static-001.json"),
            "function_rva": "[0xee5430,0xee5701)", "bytes": 721,
            "candidate_active_record_inputs": "country+0xd18 linked record +0x28; semantics and ownership remain unresolved",
            "excluded_active_count_guess": "+0x10b8 family contributes definition-scaled additional/queued output",
            "N02_coverage_upgraded": False,
        },
        "actions": {"business_dispatch": False, "advance": False, "save": False, "restart": False,
                    "install": False, "computer_use": False, "native_read_only_queries": True},
        "remaining": ["W02 score sources, goal controller, duration and daily score", "Full W01 participants/leaders/join dates/roles",
                      "N02 army/navy/sailor/force limit producers", "Full B01-B04 text and visibility",
                      "All remaining 74-topic/397-field scope and phases 2/3/4"],
        "same_date_reload_verified": False, "llm_read": "unknown",
    }
    write_new(STAGE / "development-summary-001.json", summary)
    body = f"""{marker}
## 第六十六批：选定战争的真实分数与周期订阅

W02 已接通既有原生战争分数查询。先用 W01 取得当前编号，再明确提供国家对和战争编号；一次空白议和只读预览供多个字段共享，未提交议和。查询前后核对会话与日期，并检查能力、编号、国家方向、模式及单位。仅支持 whole_war、actor 视角；总分 scale=1，累计战争目标分 scale=1000，保留原始符号。

目标存在性现已随公开结果返回。真实零值、明确没有战争目标、目标存在但读取失败分别表达。W02 的分数来源明细、目标控制方、持续时间和每日分数仍缺合格来源；分数对象 complete 不能表示全部战争上下文完整。

真实 MCP 在当前 FRA→BUR 战争取得总分 {live['values']['score']['total']['value']}、累计目标分 {live['values']['cumulative']['value']}。主动查询及同服务后台周期读取各有独立原生 query_id，均与各自原始结果一致。订阅已取消，无活动订阅，server0；日期保持56562768、POR/slot189、speed0/paused1。

正式 full001：{comparison['summary_line']}。相对65批新增{len(comparison['added_nodes'])}项通过，无新增失败节点；既有失败/错误仍141次、128节点。159份来源在 full 和 live 前冻结，结束后逐项核对。覆盖矩阵仅同步 W02 来源、参数及字段说明，仍为74主题397字段、60 available/159 partial/178 planned。完整阶段2/3/4、LLM自主订阅和完整B01–B04继续，goal active。

N02 仅增加721字节的普通静态审计：RVA [ee5430,ee5701)，+d18链接记录的+28是候选现役分类求和输入；+10b8一组属于definition-scaled additional/queued输出，不能用作现役兵力或上限。语义、单位和所有权尚未闭合，不升级字段。该结果不是新增REA证据或实机读数。

继续复用 v30-003：PID36432、creation134375780666987441、session36432-1dd660f811253b1，EXE1.37.4 SHA b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77、DLL SHA 3d9e1fea9d8f34297a4a20646ea0b45d7d0f6a4af11cef6411586dd8b3264964、118 native sources、wire6。采集disabled、累计11记录，journal completed-disabled/unowned；补丁与展开资源仍随进程存在。本批无日期推进、保存、重启、安装、外交业务或Computer Use。成熟保存、后台启动和成就提示关闭继续复用《开发过程自动化.md》。

接口见[战争分数只读接口](DOCLINK)，原件与审计见[第66批摘要](WORKLINK/development-summary-001.json)。旧65批324件归档保持原哈希。历史successful/dispatched/unknown、原final-pass IDs、未闭合ownership及原120-action batch继续禁重试，尤其SIE→FRA military access proposal1和r70_country_money_001_outbound。61批比较JSON精确原件仍未恢复，不宣称旧61归档整体通过。
<!-- batch66-war-score-summary:end -->

"""
    for name in doc_names:
        path = ROOT / name
        old = path.read_text(encoding="utf-8")
        prefix = "../" if name.startswith("docs/") else ""
        current_body = body.replace("DOCLINK", ("" if prefix else "docs/") + "战争分数只读接口.md").replace(
            "WORKLINK", prefix + "work/runtime/information-war-score-20261027-001")
        path.write_text(current_body + old, encoding="utf-8", newline="\n")
    print(json.dumps({"status": "passed", "goal": "active", "counts": field_counts}))


if __name__ == "__main__":
    main()
