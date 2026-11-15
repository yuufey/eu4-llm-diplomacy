"""Publish batch 68 metadata after the source, regression and live receipts pass."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from work.verify_information_country_forces import STAGE, pin, read_json, write_new


def main():
    for name in ("development-summary-001.json", "coverage-update-001.json"):
        if (STAGE / name).exists():
            raise FileExistsError(STAGE / name)
    freeze = read_json(STAGE / "source-freeze-001.json")
    post = read_json(STAGE / "source-post-run-verification-001.json")
    comparison = read_json(STAGE / "regression-comparison-001.json")
    live = read_json(STAGE / "live-acceptance-001/report.json")
    if (freeze.get("status") != "passed" or post.get("status") != "passed"
            or freeze.get("count") != post.get("count")
            or comparison.get("no_new_bad") is not True or live.get("status") != "passed"
            or live.get("server_exit_code") != 0):
        raise ValueError("batch68_qualification_not_complete")

    from bridge.information.composite import CompositeSource
    from bridge.information.country_state import NativeCountryStateSource
    from bridge.information.country_forces import NativeCountryForcesSource, FIELDS
    from bridge.information.sources import DiplomacySource

    primary = DiplomacySource(observer="FRA")
    source = CompositeSource(primary, [NativeCountryForcesSource(primary), NativeCountryStateSource(primary)])
    topic = next(t for t in source.catalog() if t["topic_id"] == "N02")
    path = ROOT / "docs/信息字段覆盖.json"
    before = pin(path)
    matrix = read_json(path)
    write_new(STAGE / "coverage-matrix-before-001.json", matrix)
    old = next(t for t in matrix["topics"] if t["topic_id"] == "N02")
    if any(old["fields"][f]["coverage"] != "planned" for f in FIELDS):
        raise ValueError("unexpected_N02_baseline")
    index = matrix["topics"].index(old)
    matrix["topics"][index] = deepcopy(topic)
    matrix["N02"] = {"fields": {f: deepcopy(topic["fields"][f]) for f in FIELDS},
                     "source": topic["source"], "parameters": deepcopy(topic["parameters"]),
                     "context_scope": topic["context_scope"], "scope": "FRA direct existing unit records",
                     "live": "work/runtime/information-country-forces-20261027-001/live-acceptance-001/report.json"}
    adapters = matrix["configuration"]["adapters"]
    if "NativeCountryForcesSource" not in adapters:
        adapters.insert(0, "NativeCountryForcesSource")
    counts = {"available": 0, "partial": 0, "planned": 0}
    for entry in matrix["topics"]:
        for field in entry["fields"].values():
            counts[field["coverage"]] += 1
    if counts != {"available": 60, "partial": 163, "planned": 174}:
        raise ValueError(f"unexpected_coverage_counts:{counts}")
    for key in ("counts", "expected_counts"):
        matrix[key]["field_counts"] = deepcopy(counts)
    matrix["goal_complete"] = False
    path.write_text(json.dumps(matrix, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_new(STAGE / "coverage-update-001.json", {
        "status": "passed", "batch": 68, "before": before, "after": pin(path),
        "new_partial_fields": list(FIELDS), "counts": counts,
        "matrix_maintenance_opened_game": False, "goal_complete": False,
    })

    # Use the actual pytest footer rather than substituting a planned count.
    log = (STAGE / "regression-full-001.log").read_text(encoding="utf-8")
    footer = next(line.strip("= \r\n") for line in reversed(log.splitlines())
                  if "passed" in line and "failed" in line and " in " in line)
    summary = {
        "schema": "information.country_forces.development_summary.v1", "status": "passed",
        "batch": 68, "full": footer, "no_new_bad": True, "source_count": freeze["count"],
        "coverage": counts, "goal_complete": False,
        "implemented": list(FIELDS), "country": "FRA", "quantity_units": ["regiments", "ships"],
        "observed": {"regiments": 48, "ships": 12, "army_strength_raw": 41564,
                     "navy_strength_raw": 9149, "strength_scale": 1000},
        "semantic_limits": ["men conversion unproved", "kind2 and kind5 labels unresolved",
                            "actual kind5 retracts projection", "combat readiness unclassified",
                            "sailors and force limits planned"],
        "runtime": {"pid": 42960, "creation_filetime": 134375854500787403,
                    "session_id": "42960-1dd6620b1e8b4cb", "date_raw": 56562768,
                    "installation": "work/runtime/diplomacy-observer-20261027-information-war-v30-004/installation.json",
                    "battle_source": "ready-never-enabled", "battle_capture_records": 0},
        "read_only": True, "new_save_restart_install_or_date_advance": False,
        "computer_use": False, "business_dispatches": 0,
        "qualification": {"freeze": pin(STAGE / "source-freeze-001.json"),
                          "postverify": pin(STAGE / "source-post-run-verification-001.json"),
                          "comparison": pin(STAGE / "regression-comparison-001.json"),
                          "live": pin(STAGE / "live-acceptance-001/report.json")},
    }
    write_new(STAGE / "development-summary-001.json", summary)
    note = f'''<!-- batch68-country-forces-summary:start -->
## 第六十八批：本国现存陆海军单位

N02 已接通 army_size、navy_size、army_composition、navy_composition，通过同一纯RPM来源支持主动查询和周期报告。数量单位为团和艘，strength 保留保存数据对应的原始比例单位、scale1000。当前FRA的48团与12艘，及陆军strength raw41564/舰船9149，与独立RPM和既有checkpoint的60个单位逐编号一致。不能把这些strength直接称为已证实人数或船数。

原生类别0/1/3/4/6名称已核对；类别2和5名称仍未知，实际遇到类别5会撤回投影。现存单位未区分战斗就绪等状态，不汇总属国/盟国；四字段保持partial、complete=false，sailors与force_limits继续planned。仅单位查询可省略reference_recipient，与manpower混合仍必填。planned-only查询不会调用人力外交预览。

正式 full001：{footer}。相对67批无新增失败，{freeze['count']}份来源在full和live前冻结并于结束后复核。真实MCP主动查询和同服务后台周期报告均与独立参考一致；已取消订阅，无活动订阅，server0。覆盖为74主题397字段、60 available/163 partial/174 planned。完整阶段2/3/4、LLM自主订阅与完整B01–B04继续，goal active。

继续复用v30-004：PID42960、creation134375854500787403、session42960-1dd6620b1e8b4cb；EXE1.37.4 SHAb23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77，DLL SHA92fa4ea3b158e2ff42a69bce1cbbf7053b7f3a0ac128b25c9e5b7d1fb4bdc3ce，119 native sources。POR/slot189、1456.12.9/raw56562768、speed0/paused1保持。战报来源ready、累计0，尚未启用；entry/unwind未安装，binding/journal/raw不存在是正常准备态。observer帧钩子和模块仍随进程存在。

本批无保存、重启、安装、日期推进、外交业务或Computer Use。复用《开发过程自动化.md》的后台启动和成就提示确认，不重做成熟保存/载入基础验收。历史successful/dispatched/unknown、原final-pass IDs、未闭合ownership及原120-action batch继续禁重试，尤其SIE→FRA military access proposal1和r70_country_money_001_outbound；61批比较JSON原件仍未恢复。

调用见[本国现存军队](docs/本国现存军队只读接口.md)，原件见[第68批摘要](work/runtime/information-country-forces-20261027-001/development-summary-001.json)。下一步继续剩余军力语义、完整战报文字和可见性及计划其余字段。
<!-- batch68-country-forces-summary:end -->

'''
    for name in ("HANDOFF.md", "README(agent).md", "docs/信息导出与订阅开发计划.md"):
        target = ROOT / name
        old_text = target.read_text(encoding="utf-8-sig")
        if "<!-- batch68-country-forces-summary:start -->" in old_text:
            raise ValueError("batch68_marker_already_present:" + name)
        text = note if not name.startswith("docs/") else note.replace("(docs/", "(").replace("(work/runtime/", "(../work/runtime/")
        target.write_text(text + old_text, encoding="utf-8")
    print(json.dumps({"status": "passed", "batch": 68, "source_count": freeze["count"], "counts": counts}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
