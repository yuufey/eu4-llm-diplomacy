"""Update batch45 progress from the final MCP and full-regression records."""
from __future__ import annotations
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.archive_information_trade_income import sha, tests

STAGE = ROOT / "work/runtime/information-trade-share-20261027-001"
BASELINE = ROOT / "work/runtime/information-trade-power-20261027-001"


def read(path):
    return json.loads(path.read_bytes())


def prepend(relative, text, *, after_title=False):
    path = ROOT / relative
    raw = path.read_text(encoding="utf-8")
    assert "第四十五批" not in raw[:4000]
    if after_title:
        title, rest = raw.split("\n", 1)
        raw = title + "\n\n" + text.rstrip() + "\n\n" + rest.lstrip("\n")
    else:
        raw = text.rstrip() + "\n\n" + raw
    raw = raw.replace("第四十四批贸易竞争力（最新）", "第四十四批贸易竞争力（历史）", 1)
    path.write_text(raw, encoding="utf-8", newline="\n")


def main():
    live = read(STAGE / "live-acceptance-001/report.json")
    coverage = read(STAGE / "coverage-update-001.json")
    reference = read(STAGE / "expected-trade-details-001.json")
    profile_path = ROOT / "bridge/information/profiles/trade-details-memory-1374.json"
    profile = read(profile_path)
    assert live["status"] == "passed" and live["server_exit_code"] == 0 and all(live["checks"].values())
    with (STAGE / "regression-full-001.log").open("rb") as stream:
        stream.seek(0, 2)
        stream.seek(max(0, stream.tell() - 8192))
        tail = stream.read().decode("utf-8", errors="replace")
    line = [line for line in tail.splitlines() if " passed" in line and " in " in line][-1]
    cases, bad, occurrences = tests(STAGE / "regression-full-001.xml")
    old_cases, old_bad, _ = tests(BASELINE / "regression-full-001.xml")
    key = lambda case: f"{case.get('classname')}::{case.get('name')}"
    old_keys = {key(case) for case in old_cases}
    added = [case for case in cases if key(case) not in old_keys]
    added_bad = sum(len(c.findall("failure")) + len(c.findall("error")) for c in added)
    def count(label):
        match = re.search(r"(\d+) " + label + r"\b", line)
        return int(match.group(1)) if match else 0
    figures = lambda item: f"{item['field_counts']['available']} available / {item['field_counts']['partial']} partial / {item['field_counts']['planned']} planned"
    regression = (f"完整回归为{count('passed')}项通过、{count('failed')}项失败、{count('errors')}项错误，另{count('subtests passed')}个子测试通过。"
                  f"较44批新增失败节点{len(bad-old_bad)}、解决{len(old_bad-bad)}；全套仍非全绿。新增{len(added)}个用例、其中失败或错误{added_bad}项，已包含在完整统计中。")
    share_raw = reference["nodes"]["champagne"]["share_raw"]
    province_raw = reference["nodes"]["champagne"]["source_inputs"]["TP_PROVINCE_POWER"]["raw"]
    downstream_raw = reference["nodes"]["rheinland"]["source_inputs"]["MERCHANT_DOWNSTREAM_BONUS"]["raw"]
    paragraph = ("2026-10-27 第四十五批：T04 新增 `shares` 和 `sources`，按国家组织结果，当前提供 FRA。"
                 f"香槟节点原生份额为{share_raw}/1000，即{share_raw/10:.1f}%；省份竞争力来源为{province_raw/1000:.3f}点。莱茵兰节点的份额为0，下游商人转移来源为{downstream_raw/1000:.3f}点。"
                 "份额直接复制独立缓存；来源读取省份、轻型船只和下游商人转移三类原生行，并按原生条件省略不显示的行。全部80节点已与独立原始采样对照，报告和三条两秒周期结果已交付、订阅已取消。"
                 "四个T04字段可在同一查询中共同读取，均保持 partial、complete=false；竞争国可见范围、首都、动态来源列表和修正项继续开发。"
                 f"配置矩阵为{figures(coverage['counts'])}、{coverage['counts']['callable_topic_count']}个可调用主题；本次含静态、未启用任务/战报源的实际目录为{figures(coverage['actual_live_counts'])}、{coverage['actual_live_counts']['callable_topic_count']}个可调用主题，均为74主题397字段。"
                 + regression + "本批未保存或重启游戏、未换DLL、推进日期或执行外交业务。完整计划继续开发，见[贸易竞争力只读接口](贸易竞争力只读接口.md)。")
    prepend("docs/信息导出与订阅开发计划.md", paragraph, after_title=True)
    prepend("docs/信息导出开发进展.md", "## 第四十五批：原生份额与竞争力来源\n\n" + paragraph, after_title=True)
    prepend("docs/信息接口使用说明.md", paragraph, after_title=True)
    with (ROOT / "docs/贸易竞争力只读接口.md").open("a", encoding="utf-8", newline="\n") as stream:
        stream.write("\n\n本批实机验收通过：80节点份额及条件来源行、四字段混合查询、报告和三次周期交付均符合独立参考；订阅已取消，服务正常退出。见[验收报告](../work/runtime/information-trade-share-20261027-001/live-acceptance-001/report.json)。" + regression + "\n")
    previous = (ROOT / "HANDOFF.md").read_text(encoding="utf-8")
    current = previous.split("## 2026-10-27 第四十三批", 1)[0]
    identity = current.split("当前仍PID", 1)[1].split("历史归档事故", 1)[0].strip()
    historical = current.split("历史归档事故", 1)[1].split("下一步继续", 1)[0].strip()
    historical = historical.replace("本44批新输出", "本45批新输出")
    historical = historical.replace("本45批新输出仅当前stage/exclusive", "本45批收据限定当前stage，参考草稿形状修订另有恢复记录")
    guards = profile["code_guards"]
    handoff = f"""## 2026-10-27 第四十五批贸易份额与来源（最新）

T04.shares/sources已接入真实MCP query/report/periodic，trade_node/FRA observer/1.37.4/emptyparams。shares value按country映射raw/raw_hex/unitratio/scale1000；sources value按country映射rows。champagne share raw{share_raw}即{share_raw/10:.1f}%，province raw{province_raw}即{province_raw/1000:.3f} trade_power；rheinland share0/downstream raw{downstream_raw}即{downstream_raw/1000:.3f}。partial/completefalse，basis native_trade_node_share_and_source_caches，origin copied_native_cache。当前只FRA，sources仅TP_PROVINCE_POWER/TP_SHIP_POWER/MERCHANT_DOWNSTREAM_BONUS三行。完整74topics397fields、阶段2/3/4、LLM自主订阅及完整B01–B04继续goal active。先读docs/外交开发推进复盘.md、docs/贸易竞争力只读接口.md；集中入口work/runtime/information-trade-share-20261027-001/development-summary-001.json。

share-source002纠正研究方向：B58D00的最终标量经node+B0及income-factor，是income-like返回；T04份额应直接读entry+2C。B58E45把2C乘100并格式化百分数，native key TRADE_NODE_POWER_SHARE绑定此缓存；不从44 country_power/total_power相除。power-sources-source002以14BC950完整formatter和三个direct caller证明province28/ship1C/downstream40均signed32/scale1000；province/ship非零才显示，downstream仅signed>0，保持province→ship→downstream顺序。capital、dynamic_entry90_list、multiplier、native_tail未实现且不补零/不声称三行合计完整country_power。普通有界PE/磁盘locale/独立RPM/MCP分层；不宣称live widget身份或刷新时机已证明。

新trade-details profile SHA{sha(profile_path)}，source-index {profile['source_index']['path']}/SHA{profile['source_index']['sha256']}，{len(guards)}guards/{sum(len(bytes.fromhex(g['hex'])) for g in guards)}B；旧income/power/home/countryprofiles不变。trade_details_memory只消费已验证旧trade graph/192Bentry并读自身guards，无新entry/graph读取；严格绑定oldtrade digest/module/country/fullref/slot，保留source_inputs含被排除值与条件、source_rows只含已显示三类。parent include_trade_details strictbool/requiresincome，top/before/after、双遍、cleanup撤回和旧seam保留。新NativeTradeDetailsSource与旧power字段分流，共同T04四字段；单次details capture、母/三份trade/三份details真实validator及前后context，provenance仅选中节点。

独立raw native-trade-entry-inputs002/SHA16b85c12b4f9acb0f2abeab219854a2ce4bb1d8b7bf3185d467b33b9f1dd877a，157660RPMbytes/2536calls，80真节点整192Bentry两遍一致，Null跳过、句柄closed/身份日期绑定。001已采到raw但postcheck访问date对象字段错误而failed保留；002是新纯RPM采样，不冒称只读恢复。probe继承的domestic-pressure/stability profile/fields只是country-locator元数据。expected001完全独立解包raw，不导入生产reader或公开值；最终列表形状SHA{sha(STAGE/'expected-trade-details-001.json')}。pin/MCP前初稿曾同名改写dict→list并删除offset注释；已确定性重建到expected-trade-details-draft001，SHA{sha(STAGE/'expected-trade-details-draft-001.json')}与root当时观察完全相同，是参考草稿恢复而非新RPM。sources样本含省份4节点、轻船0节点、下游4节点；轻船非零路径由离线fake memory覆盖，不冒称live正例。

全部80节点新字段逐项一致；四字段同query、未知node、report、3条两秒周期及取消/noactive通过，MCP server exit0/outboxdelivered/llm_readunknown。最新pause/date/player见45 live-acceptance aftercontrol，56557728/paused1/speed0/slot189。无gamefunction/write/save/restart/DLL/date/business。{regression}失败/错误{occurrences}次/{len(bad)}唯一节点；比较见regression-comparison001。现有失败分类triage沿用44 fullXML：121次缺失历史文件、3次frozen源码差异、2次Python Path API缺失，15次需单独根因，不改旧pin或伪造历史文件消除失败。配置{figures(coverage['counts'])}/{coverage['counts']['callable_topic_count']}callable；actual{figures(coverage['actual_live_counts'])}/{coverage['actual_live_counts']['callable_topic_count']}callable，仅shares/sources planned→partial。

当前仍PID{identity}

历史归档事故{historical}

下一步：竞争国选择设计见country-scope-design001。成熟country_identity仅扫描前256个槽位/2048B窗口，不是完整active或player-visible列表；保持FRA母身份与目标fullref/entry分开，visibility未知不能开放任意外国信息。继续capital/dynamic list/multiplier/native-tail和merchant-task/transfer；当前完整预算生产/税/费用及B04 fulltitle/Line1/buttons/layout/raw_text继续缺项。完整目标未完成，不以重跑既有partial代替新字段开发。
"""
    prepend("HANDOFF.md", handoff)
    prepend("README(agent).md", "## 2026-10-27 第四十五批贸易份额与来源（最新）\n\n" + paragraph.replace(
        "[贸易竞争力只读接口](贸易竞争力只读接口.md)", "[贸易竞争力只读接口](docs/贸易竞争力只读接口.md)") +
        "\n\n先读HANDOFF最新节及45批development-summary-001.json。shares来自独立entry2C缓存，B58D00返回收入；三来源保持原生条件和缺口。PID31460/session31460-1dd653f69242d7b/date56557728/v27-002，physicalPOR/observerFRA；no-repeat和39归档事故见HANDOFF。")
    print(json.dumps({"docs_written": 6, "full_summary": line, "new_cases": len(added)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
