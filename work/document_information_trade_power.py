"""Update user and continuation documentation from batch44 final evidence."""
from __future__ import annotations
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.archive_information_trade_income import sha, tests

STAGE = ROOT / "work/runtime/information-trade-power-20261027-001"
BASELINE = ROOT / "work/runtime/information-trade-state-20261027-001"


def read(path):
    return json.loads(path.read_bytes())


def prepend(relative, text, *, after_title=False):
    path = ROOT / relative
    raw = path.read_text(encoding="utf-8")
    assert "第四十四批" not in raw[:4000]
    if after_title:
        title, rest = raw.split("\n", 1)
        raw = title + "\n\n" + text.rstrip() + "\n\n" + rest.lstrip("\n")
    else:
        raw = text.rstrip() + "\n\n" + raw
    raw = raw.replace("第四十三批本埠节点与字段分流（最新）", "第四十三批本埠节点与字段分流（历史）", 1)
    path.write_text(raw, encoding="utf-8", newline="\n")


def main():
    live = read(STAGE / "live-acceptance-001/report.json")
    coverage = read(STAGE / "coverage-update-001.json")
    profile_path = ROOT / "bridge/information/profiles/trade-power-memory-1374.json"
    profile = read(profile_path)
    reference = read(STAGE / "expected-trade-power-002.json")
    assert live["status"] == "passed" and live["server_exit_code"] == 0 and all(live["checks"].values())
    with (STAGE / "regression-full-001.log").open("rb") as stream:
        stream.seek(0, 2)
        stream.seek(max(0, stream.tell() - 8192))
        tail = stream.read().decode("utf-8", errors="replace")
    line = [line for line in tail.splitlines() if " passed" in line and " in " in line][-1]
    cases, bad, occurrences = tests(STAGE / "regression-full-001.xml")
    old_cases, old_bad, _ = tests(BASELINE / "regression-full-002.xml")
    key = lambda case: f"{case.get('classname')}::{case.get('name')}"
    old_keys = {key(case) for case in old_cases}
    added = [case for case in cases if key(case) not in old_keys]
    def count(label):
        match = re.search(r"(\d+) " + label + r"\b", line)
        return int(match.group(1)) if match else 0
    figures = lambda item: f"{item['field_counts']['available']} available / {item['field_counts']['partial']} partial / {item['field_counts']['planned']} planned"
    regression = (f"完整回归为{count('passed')}项通过、{count('failed')}项失败、{count('errors')}项错误，另{count('subtests passed')}个子测试通过。"
                  f"与43批相比新增失败节点{len(bad-old_bad)}、解决{len(old_bad-bad)}；全套仍非全绿。新增{len(added)}个用例已包含在完整统计中，不与定向测试累加。")
    champagne = reference["nodes"]["champagne"]
    country = champagne["country_power_raw"]
    total = champagne["total_power_raw"]
    paragraph = ("2026-10-27 第四十四批：T04 新增 `country_power` 和 `total_power`，可按贸易节点读取 FRA 的竞争力与节点总竞争力。"
                 f"香槟节点当前分别为{country/1000:.3f}和{total/1000:.3f}，全部80个节点的两项结果均与服务启动前的独立原始采样及参考计算一致；报告与三条两秒周期结果已交付，订阅已取消。"
                 "两字段保持 partial、complete=false；本国数值由原始缓存按原生公式派生，总竞争力为另一缓存的直接复制。竞争国、份额和来源分解继续开发。"
                 "原始指令复核纠正了旧说明中的判断宽度：商先缩窄为32位，再与零比较；新边界测试覆盖了旧说明无法正确处理的输入。"
                 f"配置矩阵为{figures(coverage['counts'])}、{coverage['counts']['callable_topic_count']}个可调用主题；本次含静态、未启用任务/战报源的实机目录为{figures(coverage['actual_live_counts'])}、{coverage['actual_live_counts']['callable_topic_count']}个可调用主题，均为74主题397字段。"
                 + regression + "本批未保存或重启游戏、未换DLL、推进日期或执行外交业务。完整计划继续开发，调用方式见[贸易竞争力只读接口](贸易竞争力只读接口.md)。")
    prepend("docs/信息导出与订阅开发计划.md", paragraph, after_title=True)
    prepend("docs/信息导出开发进展.md", "## 第四十四批：节点贸易竞争力\n\n" + paragraph, after_title=True)
    prepend("docs/信息接口使用说明.md", paragraph, after_title=True)
    interface = ROOT / "docs/贸易竞争力只读接口.md"
    with interface.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write("\n\n实机验收已完成：全部80节点的两字段、主动报告和三次周期交付与独立参考一致，服务正常退出。见[验收报告](../work/runtime/information-trade-power-20261027-001/live-acceptance-001/report.json)。" + regression + "\n")
    previous = (ROOT / "HANDOFF.md").read_text(encoding="utf-8")
    current = previous.split("## 2026-10-27 第四十二批", 1)[0]
    identity_paragraphs = current.split("当前仍PID", 1)[1].split("历史归档事故", 1)[0]
    historical = current.split("历史归档事故", 1)[1].split("下一步优先", 1)[0].strip()
    historical = historical.replace("本43批新输出", "本44批新输出")
    guards = profile["code_guards"]
    handoff = f"""## 2026-10-27 第四十四批贸易竞争力（最新）

T04.country_power/total_power已接入真实MCP query/report/periodic，object trade_node、FRA observer、1.37.4，emptyparams。champagne raw{country}/{total}，scale1000即{country/1000:.3f}/{total/1000:.3f} trade_power，periodcurrent。80真节点两字段逐项匹配独立raw43与expected002；shares/sources仍unsupported，竞争国未开放。partial/completefalse，basis native_trade_node_power_caches；country origin derived_from_copied_native_caches，total copied_native_cache。完整74topics397fields、阶段2/3/4、LLM自主订阅及完整B01–B04继续goal active。先读docs/外交开发推进复盘.md、docs/贸易竞争力只读接口.md；集中入口work/runtime/information-trade-power-20261027-001/development-summary-001.json。

trade_power_memory复用已验证旧trade graph/完整192Bentry，每node只额外RPM runtime+C8四字节。新profile SHA{sha(profile_path)}，source-index {profile['source_index']['path']}/SHA{profile['source_index']['sha256']}，{len(guards)}guards/{sum(len(bytes.fromhex(g['hex'])) for g in guards)}B；旧income/home/countryprofile不变。parent严格include_trade_power=True须include_trade_income=True，旧default/income/home路径保留；新child纳入top/before/after、双遍与cleanup撤回。adapter一次capture、母/三份trade/三份power真实validator、context前后检查；provenance只保留选中节点inputs/guards/digest。

核心纠正：43trade-power-source002文字误把TEST EDX解释成64位判断。真实85d2/440f4fc2要求q32=i32(trunc0(i32(44)*i32(4C)/1000))，先max(0,q32)，再signedmin(cap48)，加int32(54-50)后最终int32回绕，无末尾clamp。44旧source-index001/expected001/profile初版快照保留，新addendum002/source-index002/expected002为最终来源；边界覆盖q64正但低32负，以及q64负但低32正。UI widget+58身份及live widget/runtime pointer equality仍未观察，不声称GUI比对；country值是已绑定FRA entry的公式派生，total是runtime+C8复制。普通有界PE、静态推断、原始RPM与公开MCP分层，无新REA全映像分析。

真实MCP全部80nodes、默认字段含shares/sources缺口、未知node、report和3条两秒周期通过，订阅取消/noactive，server exit0，outboxdelivered/llm_readunknown。最新before/aftercontrol来自44 live-acceptance，date56557728/player189/paused1/speed0保持。独立raw使用43 native-trade-power-inputs002/SHA bce332fe9ea537ed66910e45d1f490c6e33bda085c017728c323669d2c09f608，两遍80nodes、130780B/2696calls/handleclosed；本批不重复raw采样。

{regression}失败/错误{occurrences}次、{len(bad)}唯一节点，比较见regression-comparison001。配置{figures(coverage['counts'])}/{coverage['counts']['callable_topic_count']}callable；actual{figures(coverage['actual_live_counts'])}/{coverage['actual_live_counts']['callable_topic_count']}callable。仅两T04字段planned→partial。

当前仍PID{identity_paragraphs.strip()}

历史归档事故{historical}

下一步继续贸易竞争国、份额/来源与merchant-task/transfer语义，或其他未实现字段；不能把本次两个缓存直接相除当原生share。当前完整预算生产/税/费用和B04 fulltitle/Line1/buttons/layout/raw_text继续缺项。不要以重复已有partial验收代替新字段开发。
"""
    prepend("HANDOFF.md", handoff)
    prepend("README(agent).md", "## 2026-10-27 第四十四批贸易竞争力（最新）\n\n" + paragraph.replace(
        "[贸易竞争力只读接口](贸易竞争力只读接口.md)", "[贸易竞争力只读接口](docs/贸易竞争力只读接口.md)") +
        "\n\n先读HANDOFF最新节及44批development-summary-001.json。新合同采用source-index002/expected002，旧错误说明及初版输出保留。当前PID31460/session31460-1dd653f69242d7b/date56557728/v27-002，physicalPOR/observerFRA；历史no-repeat与39批归档事故见HANDOFF。")
    print(json.dumps({"docs_written": 6, "full_summary": line, "new_cases": len(added)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
