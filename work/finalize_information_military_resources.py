"""Publish batch 69 metadata only after frozen regression and live acceptance."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from work.verify_information_military_resources import STAGE, pin, read_json, write_new


def main():
    for name in ("development-summary-001.json", "coverage-update-001.json"):
        if (STAGE / name).exists():
            raise FileExistsError(STAGE / name)
    freeze = read_json(STAGE / "source-freeze-004.json")
    post = read_json(STAGE / "source-post-run-verification-004.json")
    comparison = read_json(STAGE / "regression-comparison-004.json")
    live = read_json(STAGE / "live-acceptance-003/report.json")
    if (freeze.get("status") != "passed" or post.get("status") != "passed"
            or freeze.get("count") != post.get("count")
            or comparison.get("no_new_bad") is not True or live.get("status") != "passed"
            or live.get("server_exit_code") != 0):
        raise ValueError("batch69_qualification_not_complete")
    expected = live["expected"]
    if (expected["sailors"]["raw"] != 2597984 or expected["sailors"]["display_value"] != 2597
            or expected["force_limits"]["land"]["value"] != 56
            or expected["force_limits"]["naval"]["value"] != 25):
        raise ValueError("unexpected_qualified_military_resources")

    from bridge.information.composite import CompositeSource
    from bridge.information.country_state import NativeCountryStateSource
    from bridge.information.country_forces import NativeCountryForcesSource
    from bridge.information.military_resources import NativeMilitaryResourcesSource, FIELDS
    from bridge.information.sources import DiplomacySource

    primary = DiplomacySource(observer="FRA")
    source = CompositeSource(primary, [NativeCountryForcesSource(primary),
                                      NativeMilitaryResourcesSource(primary),
                                      NativeCountryStateSource(primary)])
    topic = next(t for t in source.catalog() if t["topic_id"] == "N02")
    path = ROOT / "docs/信息字段覆盖.json"
    before = pin(path)
    matrix = read_json(path)
    old = next(t for t in matrix["topics"] if t["topic_id"] == "N02")
    if any(old["fields"][f]["coverage"] != "planned" for f in FIELDS):
        raise ValueError("unexpected_N02_baseline")
    write_new(STAGE / "coverage-matrix-before-001.json", matrix)
    matrix["topics"][matrix["topics"].index(old)] = deepcopy(topic)
    matrix["N02"] = {"fields": deepcopy(topic["fields"]), "source": topic["source"],
                     "parameters": deepcopy(topic["parameters"]),
                     "context_scope": topic["context_scope"],
                     "scope": "FRA current manpower, existing units, sailors and native force limits",
                     "live": "work/runtime/information-country-force-resources-20261027-001/live-acceptance-003/report.json"}
    adapters = matrix["configuration"]["adapters"]
    if "NativeMilitaryResourcesSource" not in adapters:
        adapters.insert(adapters.index("NativeCountryForcesSource") + 1, "NativeMilitaryResourcesSource")
    counts = {"available": 0, "partial": 0, "planned": 0}
    for entry in matrix["topics"]:
        for field in entry["fields"].values():
            counts[field["coverage"]] += 1
    if counts != {"available": 61, "partial": 164, "planned": 172}:
        raise ValueError(f"unexpected_coverage_counts:{counts}")
    for key in ("counts", "expected_counts"):
        matrix[key]["field_counts"] = deepcopy(counts)
    matrix["goal_complete"] = False
    path.write_text(json.dumps(matrix, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_new(STAGE / "coverage-update-001.json", {
        "status": "passed", "batch": 69, "before": before, "after": pin(path),
        "new_available_fields": ["sailors"], "new_partial_fields": ["force_limits"],
        "counts": counts, "matrix_maintenance_opened_game": False, "goal_complete": False,
    })

    log = (STAGE / "regression-full-004.log").read_text(encoding="utf-8")
    footer = next(line.strip("= \r\n") for line in reversed(log.splitlines())
                  if "passed" in line and "failed" in line and " in " in line)
    recipient = STAGE / "battle-native-recipient-001/battle-native-recipient-evidence-link-001.json"
    summary = {
        "schema": "information.military_resources.development_summary.v1", "status": "passed",
        "batch": 69, "full": footer, "no_new_bad": True,
        "retained_full001": pin(STAGE / "regression-comparison-001.json"),
        "full001_correction": "stale heartbeat fixture now uses journal boundary and always closes its manager; production unchanged", "source_count": freeze["count"],
        "retained_live_failures": [pin(STAGE / "live-acceptance-001/report.json"), pin(STAGE / "live-acceptance-002/report.json")],
        "inline_modifier_correction": "country+0x28d0 is inline; strict validation rejected the mistaken pointer in live002 before MCP",
        "coverage": counts, "goal_complete": False, "implemented": list(FIELDS), "country": "FRA",
        "observed": deepcopy(expected),
        "semantic_limits": ["FRA and pinned EU4 1.37.4 only", "max_sailors offset unresolved",
                            "nonnull force processors unsupported", "naval GUI sample not audited",
                            "two-pass consistency is not an atomic cache-freshness guarantee"],
        "runtime": {"pid": 27716, "creation_filetime": 134376348223436218,
                    "session_id": "27716-1dd6693a61275ba", "date_raw": 56562768,
                    "installation": "work/runtime/diplomacy-observer-20261028-information-resources-v30-005/installation.json",
                    "battle_source": "ready-never-enabled", "battle_capture_records": 0},
        "battle_visibility_progress": {"associated_source": pin(recipient),
                                       "native_selected_country": "POR", "information_observer": "FRA",
                                       "getter_sample_session": "42960-1dd6620b1e8b4cb",
                                       "historical_getter_sample_not_new_session_capture": True, "B04_complete": False},
        "read_only": True, "new_save_restart_install_or_date_advance": {
            "save": False, "restart": True, "install_reused_dll": True, "date_advance": False},
        "recovery": {"outcome": pin(STAGE / "recovery-v30-005-001/recovery-outcome-001.json"),
                     "old_process_exit_cause": "unknown", "live001_stopped_before_mcp_or_production_capture": True,
                     "new_build_binary_and_119_sources_reused": True},
        "computer_use": False, "business_dispatches": 0,
        "qualification": {"freeze": pin(STAGE / "source-freeze-004.json"),
                          "postverify": pin(STAGE / "source-post-run-verification-004.json"),
                          "comparison": pin(STAGE / "regression-comparison-004.json"),
                          "live": pin(STAGE / "live-acceptance-003/report.json")},
        "receipt_incident": {"original_preopen_failure_receipt_deleted": True,
                             "original_bytes_recovered": False,
                             "after_the_fact_description": pin(STAGE / "force-limit-rpm-001/pre-open-pin-failure-001.json"),
                             "failed_attempt_openprocess_or_rpm": False},
    }
    write_new(STAGE / "development-summary-001.json", summary)
    note = f'''<!-- batch69-military-resources-summary:start -->
## 第六十九批：本国水手与军队上限

N02 已接通 sailors 与 force_limits 的主动查询和后台周期报告。FRA当前水手 raw2597984、scale1000，即2597.984；界面整数2597按原生float32转换得到。独立既有checkpoint与新只读采集一致。水手字段为available，最大水手量的内存来源尚未闭合。

陆军上限56团、海军上限25艘，由原生getter使用的四个modifier缓存输入37777/16946/500/500计算；两个base及两个percentage的processor均为空。保留原生截零、千分位及最小1的计算规则，不用48团/12艘现存数量冒充上限。上限保持partial、complete=false；非空动态processor、海军GUI独立样本与原子缓存时效仍有边界。仅本地单位/水手/上限查询可省略reference_recipient，与manpower混合仍必填。

正式full004：{footer}。full001的旧心跳夹具因未来1ms假时间误判并遗留锁，已把旧心跳固定在journal边界并用finally关闭manager；原失败收据保留。full004相对68批无新增失败。live002曾因把内嵌modifier误当指针而在MCP前被严格校验拒绝，已纠正布局并补回归反例；原采集及失败收据保留。{freeze['count']}份来源在full004和live003前冻结并在结束后复核。真实MCP主动查询与同服务后台周期结果均对独立参考；已取消订阅，无活动订阅，server0。覆盖为74主题397字段、61 available/164 partial/172 planned。完整阶段2/3/4、LLM自主订阅与完整B01–B04继续，goal active。

战报资格路径新增旧42960会话原生国家getter的双遍只读证据：该样本选择POR/slot189，信息观察方FRA；当前battle override为空。静态资格比较使用该原生fullref，不能把逻辑观察方直接代入。此结论只证明当前样本及静态路径，不证明历史战斗收件人，也未完成Line1、完整正文或可见范围验收。

旧42960在live001健康检查前已退出，未启动MCP或执行生产采集；退出原因未知。已按自动化文档后台恢复同一checkpoint并完成一次原生确认、一次安装。当前为v30-005：PID27716、creation134376348223436218、session27716-1dd6693a61275ba；EXE1.37.4 SHAb23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77，DLL SHA92fa4ea3b158e2ff42a69bce1cbbf7053b7f3a0ac128b25c9e5b7d1fb4bdc3ce，119 native sources。POR、1456.12.9/raw56562768、speed0/paused1保持。战报ready、累计0且从未启用，entry/unwind未安装，binding/journal/raw不存在是正常准备态；observer帧钩子与模块仍随进程存在。

本批无新保存、日期推进、外交业务或Computer Use；恢复复用了原119份来源及同一DLL。live003使用新会话的独立RPM参考，旧会话原件保留。候选探针曾在OpenProcess前因pin错误退出，其临时失败收据被误删，原字节未恢复；保留事后说明，修正后只执行一次实际候选RPM。历史successful/dispatched/unknown、原final-pass IDs、未闭合ownership及原120-action batch继续禁重试，尤其SIE→FRA military access proposal1和r70_country_money_001_outbound；61批比较JSON原件仍未恢复。

接口见[本国水手与军队上限](docs/本国水手与军队上限只读接口.md)，原件见[第69批摘要](work/runtime/information-country-force-resources-20261027-001/development-summary-001.json)。下一步继续完整战报文字、可见性及计划其余来源。
<!-- batch69-military-resources-summary:end -->

'''
    for name in ("HANDOFF.md", "README(agent).md", "docs/信息导出与订阅开发计划.md"):
        target = ROOT / name
        old_text = target.read_text(encoding="utf-8-sig")
        if "<!-- batch69-military-resources-summary:start -->" in old_text:
            raise ValueError("batch69_marker_already_present:" + name)
        text = note if not name.startswith("docs/") else note.replace("(docs/", "(").replace("(work/runtime/", "(../work/runtime/")
        target.write_text(text + old_text, encoding="utf-8")
    previous = ROOT / "docs/本国现存军队只读接口.md"
    old_text = previous.read_text(encoding="utf-8-sig")
    previous.write_text(old_text.replace("`sailors`、`force_limits` 尚未接通。",
                                        "`sailors`、`force_limits` 现由[水手与军队上限接口](本国水手与军队上限只读接口.md)提供。"), encoding="utf-8")
    print(json.dumps({"status": "passed", "batch": 69, "source_count": freeze["count"], "counts": counts}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
