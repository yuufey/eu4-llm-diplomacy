"""Publish the final batch53 documentation summary when receipts are ready.

The command is deliberately guarded.  Until the live acceptance, formal
``regression-full-002`` and coverage receipts are present and internally
consistent it only reports ``not_ready`` and leaves all current documents
untouched.  It never starts pytest, MCP, a game, RPM, REA, or a native read.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.archive_information_country_records_localization import (  # noqa: E402
    REGRESSION_BASENAME,
    STAGE,
    pin,
    regression,
)


DOCS = (
    ROOT / "HANDOFF.md",
    ROOT / "README(agent).md",
    ROOT / "docs/信息导出与订阅开发计划.md",
    ROOT / "docs/信息导出开发进展.md",
    ROOT / "docs/信息接口使用说明.md",
)
PUBLIC_DOC = ROOT / "docs/选定关系与修正文本接口.md"
LIVE_REPORT = STAGE / "live-acceptance-001/report.json"
LIVE_QUERY = STAGE / "live-acceptance-001/query.json"
COVERAGE = STAGE / "coverage-update-001.json"
LITERAL_REFERENCE = STAGE / "literal-reference-001/expected-literals.json"
LOAN_REFERENCE = STAGE / "expected-loans-002.json"
FULL_XML = STAGE / f"{REGRESSION_BASENAME}.xml"
FULL_LOG = STAGE / f"{REGRESSION_BASENAME}.log"

_EXPECTED_COVERAGE = {
    ("N07", "name"),
    ("N07", "description"),
    ("R01", "relation_type"),
    ("R01", "status"),
    ("R01", "grantor"),
    ("R01", "recipient"),
}
_IN_PROGRESS_HEADING = "## 2026-10-27 第五十三批关系状态与修正文本（进行中）"
_PREVIOUS_LATEST_HEADING = "## 2026-10-27 第五十二批当前贷款与国家修正（最新）"
_PREVIOUS_HISTORY_HEADING = "## 2026-10-27 第五十二批当前贷款与国家修正（历史）"


class NotReady(RuntimeError):
    pass


def read_json(path: Path) -> Any:
    return json.loads(path.read_bytes())


def _field_counts(counts: dict[str, Any]) -> str:
    fields = counts.get("field_counts", {})
    return (
        f"{fields.get('available', 0)} available / "
        f"{fields.get('partial', 0)} partial / "
        f"{fields.get('planned', 0)} planned"
    )


def _require_file(path: Path) -> None:
    if not path.is_file():
        raise NotReady(f"missing receipt: {path.relative_to(ROOT).as_posix()}")


def _verified_facts() -> dict[str, Any]:
    """Read the concrete values that the final summary is allowed to state."""

    query = read_json(LIVE_QUERY)
    relation = next(
        (item for item in query.get("items", []) if item.get("topic") == "R01"),
        None,
    )
    if not relation:
        raise NotReady("live R01 query item is missing")
    active = next(
        (
            row
            for row in relation.get("fields", {}).get("status", {}).get("value", [])
            if row.get("relation_type") == "vassalization"
            and row.get("status") == "known"
            and row.get("value") == "active"
        ),
        None,
    )
    if not active:
        raise NotReady("live R01 vassalization active row is missing")
    objects = relation.get("objects", [])
    if not objects or objects[0].get("actor") != "FRA" or objects[0].get("recipient") != "ORL":
        raise NotReady("live R01 selected FRA->ORL pair is missing")

    literals = read_json(LITERAL_REFERENCE)
    entries = literals.get("entries", {})
    literal_names = {
        key: entries[key].get("text")
        for key in ("papal_sanction_for_church_taxes", "shady_people")
        if key in entries
    }
    if set(literal_names) != {"papal_sanction_for_church_taxes", "shady_people"}:
        raise NotReady("the two localized modifier names are missing")

    loans = read_json(LOAN_REFERENCE)
    rows = loans.get("rows", [])
    if len(rows) != 3 or any(row.get("lender", {}).get("mapping") != "BANK" for row in rows):
        raise NotReady("expected loan reference does not contain three BANK rows")
    loan_dates = [row.get("due_calendar", {}).get("date") for row in rows]
    if any(not date for date in loan_dates):
        raise NotReady("expected loan reference has an unknown calendar date")
    return {
        "relation": "FRA→ORL vassalization=active",
        "modifier_names": list(literal_names.values()),
        "loan_dates": loan_dates,
        "loan_profile_sha256": loans.get("production_v2_profile_sha256"),
        "target_exe_sha256": loans.get("target_exe_sha256"),
    }


def collect_ready_inputs() -> dict[str, Any]:
    """Read final receipts without executing any producer or test."""

    for path in (
        LIVE_REPORT,
        LIVE_QUERY,
        LITERAL_REFERENCE,
        LOAN_REFERENCE,
        COVERAGE,
        FULL_XML,
        FULL_LOG,
    ):
        _require_file(path)
    facts = _verified_facts()
    live = read_json(LIVE_REPORT)
    if live.get("status") != "passed" or live.get("server_exit_code") != 0:
        raise NotReady("live acceptance is not passed/server0")
    checks = live.get("checks")
    if isinstance(checks, dict) and not all(checks.values()):
        raise NotReady("live acceptance contains a failed check")
    if live.get("r01_uses_read_only_native_game_queries") is not True:
        raise NotReady("R01 read-only native query fact is absent")

    coverage = read_json(COVERAGE)
    changes = {
        (item.get("topic"), item.get("field"))
        for item in coverage.get("coverage_changes", [])
    }
    if changes != _EXPECTED_COVERAGE:
        raise NotReady(f"coverage delta is not the six batch53 fields: {changes}")
    if coverage.get("loan_coverage_unchanged") is not True:
        raise NotReady("loan coverage preservation is not recorded")
    configured = coverage.get("counts")
    actual = coverage.get("actual_live_counts")
    for label, counts in (("configured", configured), ("actual", actual)):
        if not isinstance(counts, dict) or counts.get("topic_count") != 74 or counts.get("field_count") != 397:
            raise NotReady(f"{label} coverage is not 74 topics/397 fields")
    if coverage.get("goal_complete") is not False or coverage.get("goal_status") != "active":
        raise NotReady("coverage goal is not explicitly active/incomplete")

    comparison = regression()
    if comparison["full"]["new_failure_nodes"]:
        raise NotReady("formal regression has new failure nodes")
    if comparison["new_tests"]["failure_error_occurrences"]:
        raise NotReady("formal regression has failing new tests")
    if not comparison["full"].get("xml"):
        raise NotReady("formal regression XML pin is missing")
    return {
        "live": live,
        "coverage": coverage,
        "comparison": comparison,
        "facts": facts,
        "artifacts": {
            "live_report": pin(LIVE_REPORT),
            "live_query": pin(LIVE_QUERY),
            "literal_reference": pin(LITERAL_REFERENCE),
            "loan_reference": pin(LOAN_REFERENCE),
            "coverage": pin(COVERAGE),
            "full_xml": pin(FULL_XML),
            "full_log": pin(FULL_LOG),
        },
    }


def _summary(data: dict[str, Any]) -> str:
    live = data["live"]
    coverage = data["coverage"]
    comparison = data["comparison"]
    facts = data["facts"]
    full = comparison["full"]
    configured = coverage["counts"]
    actual = coverage["actual_live_counts"]
    return (
        f"实机已交付：{facts['relation']}，并保留五类关系状态；"
        f"报告、{live.get('periodic_results', 0)} 次周期结果已送达并取消，当前无活动订阅。"
        f"N07 两条修正名称为“{facts['modifier_names'][0]}”和“{facts['modifier_names'][1]}”，"
        "name/description 的四项归档文字均为 known，但 UI 消费者绑定仍未证实，字段保持 partial。"
        f"N01 已核对三笔 BANK 贷款，到期日为 {', '.join(facts['loan_dates'])}；"
        "贷款字段仍为 partial，外国 lender、显示文本和完整 RTTI 仍是明确缺口。"
        f"配置字段覆盖为 {_field_counts(configured)}、{configured.get('callable_topic_count', 0)} 个可调用主题；"
        f"本次 live discovery 为 {_field_counts(actual)}、{actual.get('callable_topic_count', 0)} 个可调用主题；"
        "两组统计均为74个主题、397个字段，不能混用。"
        f"正式完整回归使用 `{REGRESSION_BASENAME}.xml/.log`："
        f"{full.get('passed', 0)} passed、{full.get('failed', 0)} failed、"
        f"{full.get('errors', 0)} errors、{full.get('subtests_passed', 0)} 个子测试通过；"
        f"新增 {comparison['new_tests'].get('cases', 0)} 个用例全部通过，"
        f"既有失败债务为 {full.get('failure_error_occurrences', 0)} 次、"
        f"{full.get('unique_failure_error_nodes', 0)} 个节点；完整计划继续。"
        f"实机报告为 `{LIVE_REPORT.relative_to(ROOT).as_posix()}`。"
    )


def _handoff_tail(data: dict[str, Any]) -> str:
    live = data["live"]
    facts = data["facts"]
    return (
        f"当前53批实机身份为 session `{live.get('session_id')}`、game_date "
        f"`{live.get('game_date')}`、observer FRA、1.37.4 EXE SHA "
        f"`{facts['target_exe_sha256']}`；loan v2 profile SHA "
        f"`{facts['loan_profile_sha256']}`。贷款和本地化 raw 来自只读 native/RPM 对照，"
        "日期的月日展开来自 bounded ordinary static calendar source，未新增 RPM；"
        "R01 查询使用只读原生外交查询，未提交业务动作、保存、重启或推进日期。"
        "MODIFIER_UI_TEXT_BINDING_UNVERIFIED 仍保留，下一步继续完整 B01–B04、阶段二/三/四、"
        "关系网络和 modifier UI consumer binding；覆盖总范围仍是74个主题、397个字段，goal保持active。"
        "禁止重放沿用52批精确指针：历史成功、已派发或 unknown action、原 final-pass request ID、"
        "未闭合 ownership 和原120-action batch均不可重试。"
        "下一独立入口由 `/root/trade_name_adapter` 负责："
        "`work/research-next/relation_current.py` 与 "
        "`work/runtime/information-relation-current-20261027-001/` 的 source 已整理，"
        "production/capture 待完成，不计入本53批终态。"
    )


def _replace_handoff_block(text: str, block: str) -> str:
    pattern = re.compile(
        r"\A" + re.escape(_IN_PROGRESS_HEADING) + r"\n.*?(?=^## |\Z)",
        re.MULTILINE | re.DOTALL,
    )
    if not pattern.search(text):
        raise NotReady("batch53 in-progress block is absent from HANDOFF/README")
    return pattern.sub(block.rstrip() + "\n\n", text, count=1)


def _mark_previous_batch_historical(text: str) -> str:
    if _PREVIOUS_LATEST_HEADING not in text:
        raise NotReady("batch52 latest heading is absent from HANDOFF/README")
    return text.replace(_PREVIOUS_LATEST_HEADING, _PREVIOUS_HISTORY_HEADING, 1)


def _insert_after_title(text: str, entry: str) -> str:
    if "第五十三批" in "\n".join(text.splitlines()[:8]):
        raise NotReady("a batch53 final entry already exists in a current document")
    first_end = text.find("\n")
    if first_end < 0 or not text.startswith("#"):
        raise NotReady("document title is not in the expected form")
    return text[: first_end + 1] + "\n" + entry.rstrip() + "\n\n" + text[first_end + 1 :]


def render_documents(data: dict[str, Any]) -> dict[Path, str]:
    summary = _summary(data)
    handoff_block = (
        "## 2026-10-27 第五十三批关系状态与修正文本（最新）\n\n"
        + summary
        + "\n\n"
        + _handoff_tail(data)
        + "\n\n归档入口、full002 统计、coverage 和文档验证收据均位于 "
        "`work/runtime/information-country-records-localization-20261027-001/`；"
        "regression-full-001 是此前误触发 --help 后中止的部分日志，不作为完整回归。"
    )
    plan_entry = (
        "2026-10-27 第五十三批："
        + summary
        + "\n调用见[选定关系与修正文本接口](选定关系与修正文本接口.md)。"
    )
    progress_entry = "## 第五十三批：关系状态与修正文本\n\n" + summary + "\n\n"
    api_entry = (
        "2026-10-27 第五十三批：R01 选定国家对和 N07 直接修正名称/说明已完成正式收尾，"
        "接口仍按 partial/unknown 边界返回；覆盖与正式回归统计见本批收据。"
        "调用示例见[选定关系与修正文本接口](选定关系与修正文本接口.md)。\n\n"
    )
    return {
        DOCS[0]: _mark_previous_batch_historical(
            _replace_handoff_block(DOCS[0].read_text(encoding="utf-8"), handoff_block)
        ),
        DOCS[1]: _mark_previous_batch_historical(
            _replace_handoff_block(DOCS[1].read_text(encoding="utf-8"), handoff_block)
        ),
        DOCS[2]: _insert_after_title(DOCS[2].read_text(encoding="utf-8"), plan_entry),
        DOCS[3]: _insert_after_title(DOCS[3].read_text(encoding="utf-8"), progress_entry),
        DOCS[4]: _insert_after_title(DOCS[4].read_text(encoding="utf-8"), api_entry),
    }


def main() -> int:
    try:
        data = collect_ready_inputs()
        rendered = render_documents(data)
    except NotReady as exc:
        print(json.dumps({"status": "not_ready", "reason": str(exc)}, ensure_ascii=False))
        return 2
    for path, text in rendered.items():
        path.write_text(text, encoding="utf-8", newline="\n")
    print(json.dumps({
        "status": "updated",
        "documents": [path.relative_to(ROOT).as_posix() for path in rendered],
        "stage": STAGE.relative_to(ROOT).as_posix(),
        "goal_complete": False,
        "goal_status": "active",
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    raise SystemExit(main())
