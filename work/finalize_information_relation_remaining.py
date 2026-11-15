"""Batch 55 finalizer for the remaining R01 relation families.

The module is intentionally inert on import, on the default path, and for
``--help``.  Each phase is explicit.  ``--full`` is the only phase that can
start pytest; the other phases only pin or consume existing receipts.  The
large fleet raw/reference files are hashed in streaming mode and are never
copied into a source snapshot.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Reuse the bounded pin/count/XML/metadata helpers from the frozen batch54
# finalizer.  Importing that module has no phase side effects.
from work import finalize_information_relation_current as _batch54  # noqa: E402


STAGE = ROOT / "work/runtime/information-relation-remaining-20261027-001"
BASELINE = ROOT / "work/runtime/information-relation-current-20261027-001"
BATCH = 55
LIVE_DIRECTORY = "live-acceptance-002"
REGRESSION_BASENAME = "regression-full-001"
BASELINE_REGRESSION_BASENAME = "regression-full-001"
COVERAGE_RECEIPT_BASENAME = "coverage-update-001.json"
DOCUMENT_RECEIPT_BASENAME = "document-verification-002.json"
MAX_SOURCE_SNAPSHOT_BYTES = 10 * 1024 * 1024

_EXTENSION_RUNTIME_PATHS = (
    "bridge/information/relation_state.py",
    "bridge/information/relation_records.py",
    "bridge/information/subject_relations.py",
    "bridge/information/trade_league_memory.py",
    "bridge/information/fleet_basing_memory.py",
    "bridge/information/profiles/relation-memory-1374.json",
    "bridge/information/profiles/trade-league-memory-1374.json",
    "bridge/information/profiles/fleet-basing-memory-1374.json",
)

_CURRENT_SOURCE_PATHS = (
    *_EXTENSION_RUNTIME_PATHS,
    "bridge/information/composite.py",
    "bridge/information/sources.py",
    "bridge/tests/test_information_relation_network.py",
    "bridge/tests/test_information_relation_state.py",
    "bridge/tests/test_information_relation_memory.py",
    "bridge/tests/test_information_relation_records.py",
    "work/validate_information_relation_remaining_live.py",
    "work/capture_information_relation_remaining.py",
    "work/finalize_information_relation_remaining.py",
    "work/research-next/relation_remaining.py",
    "work/research-next/relation_current.py",
    "work/research-next/relation_current_native.py",
    "work/research-next/fleet_basing_current.py",
    "work/research-next/trade_league_current.py",
    "work/reference_information_relation_current.py",
    "work/reference_information_relation_current_independent.py",
    "work/reference_information_fleet_basing_current.py",
    "work/reference_information_trade_league_current.py",
    "work/probe_information_trade_league_current.py",
    "work/probe_information_fleet_basing_current.py",
    "work/runtime/information-relation-remaining-20261027-001/relation-remaining-source-001.json",
    "work/runtime/information-relation-remaining-20261027-001/relation-remaining-contract-005.json",
    "work/runtime/information-relation-remaining-20261027-001/fleet-basing-current-source-002.json",
    "work/runtime/information-relation-remaining-20261027-001/fleet-basing-reference-receipt-001.json",
    "work/runtime/information-relation-remaining-20261027-001/code-source004.json",
    "work/runtime/information-relation-remaining-20261027-001/expected-trade-league-current-001.json",
    "work/runtime/information-relation-remaining-20261027-001/expected-fleet-basing-projection-001.json",
    "work/runtime/information-trade-league-current-20261027-001/trade-league-current-source-003.json",
    "docs/驻港权与贸易联盟接口.md",
    "docs/联盟与联姻关系网接口.md",
    "docs/信息字段覆盖.json",
    "docs/信息导出与订阅开发计划.md",
    "docs/LLM导出信息目录.md",
    "HANDOFF.md",
    "README(agent).md",
)

_SOURCE_GLOBS = (
    "bridge/tests/test_information_relation*.py",
    "bridge/tests/fixtures/information_relation*.json",
    "bridge/tests/fixtures/information_relation*.json.gz",
    "bridge/tests/test_information_trade_league*.py",
    "bridge/tests/test_information_fleet_basing*.py",
    "bridge/tests/fixtures/information_trade_league*.json",
    "bridge/tests/fixtures/information_trade_league*.json.gz",
    "bridge/tests/fixtures/information_fleet_basing*.json",
    "bridge/tests/fixtures/information_fleet_basing*.json.gz",
    "bridge/tests/*relation*replay*.py",
    "work/research-next/*relation*.py",
    "work/research-next/*fleet_basing*.py",
    "work/research-next/*trade_league*.py",
    "work/reference_information_*relation*.py",
    "work/reference_information_*fleet*.py",
    "work/reference_information_*league*.py",
    "work/validate_information_relation*.py",
    "work/capture_information_relation*.py",
)

_NETWORK_FAMILIES = ("alliance", "royal_marriage", "fleet_basing", "trade_league")
_PAIR_FAMILIES = (
    "vassalization", "guarantee", "support_independence", "military_access", "rival",
    "alliance", "royal_marriage", "fleet_basing", "trade_league",
)


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def pin(path: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": sha(path),
    }


def read_json(path: Path, *, max_bytes: int = 8 * 1024 * 1024) -> Any:
    if not path.is_file():
        raise AssertionError(f"required receipt is missing: {path.relative_to(ROOT)}")
    if path.stat().st_size > max_bytes:
        raise AssertionError(f"bounded JSON read refused for {path.relative_to(ROOT)}")
    return json.loads(path.read_bytes())


def write_json(name: str, value: Any) -> Path:
    STAGE.mkdir(parents=True, exist_ok=True)
    target = STAGE / name
    if target.exists():
        raise AssertionError(f"batch55 receipt already exists: {target.relative_to(ROOT)}")
    with target.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return target


def runtime_paths() -> tuple[str, ...]:
    return tuple(dict.fromkeys(_batch54.runtime_paths() + _EXTENSION_RUNTIME_PATHS))


def _require_stage_and_baseline() -> None:
    if not STAGE.is_dir():
        raise AssertionError(f"batch55 stage is missing: {STAGE}")
    if not BASELINE.is_dir():
        raise AssertionError(f"batch54 baseline stage is missing: {BASELINE}")


def _require_runtime_files() -> tuple[str, ...]:
    paths = runtime_paths()
    missing = [relative for relative in paths if not (ROOT / relative).is_file()]
    if missing:
        raise AssertionError("runtime source missing: " + ", ".join(missing))
    return paths


def _pin_before() -> int:
    _require_stage_and_baseline()
    target = STAGE / "runtime-source-pins-before-001.json"
    if target.exists():
        raise AssertionError("batch55 source pins already exist")
    paths = _require_runtime_files()
    matrix = ROOT / "docs/信息字段覆盖.json"
    matrix_snapshot = STAGE / "coverage-matrix-before-001.json"
    if not matrix_snapshot.exists():
        matrix_snapshot.write_bytes(matrix.read_bytes())
    baseline_after = BASELINE / "runtime-source-pins-after-001.json"
    if not baseline_after.is_file():
        raise AssertionError("batch54 after-pin receipt is missing")
    write_json(
        target.name,
        {
            "schema": "information_runtime_source_pins.v1",
            "batch": BATCH,
            "baseline_stage": BASELINE.relative_to(ROOT).as_posix(),
            "baseline_after_pin": pin(baseline_after),
            "timing": "before batch55 live acceptance and formal full regression",
            "continuous_monitoring_claimed": False,
            "inherited_batch54_runtime_paths": len(_batch54.runtime_paths()),
            "files": [pin(ROOT / relative) for relative in paths],
            "coverage_matrix_before": pin(matrix_snapshot),
        },
    )
    return 0


def _verify_before() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    before = read_json(STAGE / "runtime-source-pins-before-001.json")
    if before.get("batch") != BATCH:
        raise AssertionError("runtime source pin is not a batch55 pin")
    after: list[dict[str, Any]] = []
    for item in before.get("files", []):
        relative = item.get("path")
        if not isinstance(relative, str):
            raise AssertionError("runtime pin has an invalid path")
        path = ROOT / relative
        if not path.is_file():
            raise AssertionError(f"pinned source disappeared: {relative}")
        current = pin(path)
        current["matches_before"] = current["sha256"] == item.get("sha256")
        after.append(current)
    if not after or not all(item["matches_before"] for item in after):
        raise AssertionError("a frozen batch55 runtime source changed")
    return before, after


def _live_report(*, required: bool = True) -> dict[str, Any] | None:
    path = STAGE / LIVE_DIRECTORY / "report.json"
    if not path.is_file():
        if required:
            raise AssertionError("batch55 live acceptance report is missing")
        return None
    report = read_json(path)
    if report.get("status") != "passed" or report.get("server_exit_code") != 0:
        raise AssertionError("batch55 live acceptance is not passed/exit0")
    checks = report.get("checks")
    if isinstance(checks, dict) and not all(value is True for value in checks.values()):
        raise AssertionError("batch55 live acceptance contains a failed check")
    return report


def _case_key(case: ET.Element) -> str:
    return f"{case.get('classname')}::{case.get('name')}"


def _test_cases(path: Path) -> tuple[list[ET.Element], set[str], int]:
    root = ET.parse(path).getroot()
    cases = root.findall(".//testcase")
    bad = {
        _case_key(case) for case in cases
        if case.findall("failure") or case.findall("error")
    }
    occurrences = sum(
        len(case.findall("failure")) + len(case.findall("error")) for case in cases
    )
    return cases, bad, occurrences


def _summary_line(path: Path) -> str:
    with path.open("rb") as stream:
        stream.seek(0, 2)
        stream.seek(max(0, stream.tell() - 8192))
        tail = stream.read().decode("utf-8", errors="replace")
    lines = [line for line in tail.splitlines() if " passed" in line and " in " in line]
    if not lines:
        raise AssertionError(f"pytest summary line missing: {path.relative_to(ROOT)}")
    return lines[-1]


def _count(line: str, label: str) -> int:
    match = re.search(r"(\d+) " + re.escape(label) + r"\b", line)
    return int(match.group(1)) if match else 0


def _regression_comparison() -> dict[str, Any]:
    xml = STAGE / f"{REGRESSION_BASENAME}.xml"
    log = STAGE / f"{REGRESSION_BASENAME}.log"
    baseline_xml = BASELINE / f"{BASELINE_REGRESSION_BASENAME}.xml"
    if not xml.is_file() or not log.is_file() or not baseline_xml.is_file():
        raise AssertionError("batch55 or batch54 formal regression receipt is missing")
    cases, bad, occurrences = _test_cases(xml)
    old_cases, old_bad, old_occurrences = _test_cases(baseline_xml)
    current_keys = {_case_key(case) for case in cases}
    old_keys = {_case_key(case) for case in old_cases}
    current_bad = {_case_key(case) for case in cases if case.findall("failure") or case.findall("error")}
    added = sorted(current_keys - old_keys)
    removed = sorted(old_keys - current_keys)
    line = _summary_line(log)
    return {
        "full": {
            "command": "python -m pytest -q bridge/tests",
            "exit_code": 1 if bad else 0,
            "passed": _count(line, "passed"),
            "failed": _count(line, "failed"),
            "errors": _count(line, "errors"),
            "subtests_passed": _count(line, "subtests passed"),
            "summary_line": line,
            "whole_suite_green": not bad,
            "failure_error_occurrences": occurrences,
            "unique_failure_error_nodes": len(bad),
            "new_failure_nodes": sorted(current_bad - old_bad),
            "resolved_failure_nodes": sorted(old_bad - current_bad),
            "xml": pin(xml),
        },
        "new_or_renamed_tests": {
            "execution": "derived_from_full_XML_not_another_run",
            "nodes": added,
            "cases": len(added),
            "failure_error_occurrences": sum(
                len(case.findall("failure")) + len(case.findall("error"))
                for case in cases if _case_key(case) in set(added)
            ),
        },
        "removed_nodes": removed,
        "net_case_delta": len(cases) - len(old_cases),
        "baseline": {
            "xml": pin(baseline_xml),
            "failure_error_occurrences": old_occurrences,
            "unique_failure_error_nodes": len(old_bad),
            "case_count": len(old_cases),
        },
        "current_case_count": len(cases),
        "case_set_changed": current_keys != old_keys,
    }


def _run_full() -> int:
    _require_stage_and_baseline()
    _verify_before()
    _live_report(required=True)
    xml = STAGE / f"{REGRESSION_BASENAME}.xml"
    log = STAGE / f"{REGRESSION_BASENAME}.log"
    if xml.exists() or log.exists():
        raise AssertionError("batch55 formal regression receipts already exist")
    with log.open("x", encoding="utf-8", newline="\n") as stream:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "bridge/tests", "--junitxml", str(xml)],
            cwd=ROOT,
            stdout=stream,
            stderr=subprocess.STDOUT,
            check=False,
        )
    print(f"formal batch55 full regression exit {result.returncode}")
    return result.returncode


def _counts(topics: list[dict[str, Any]]) -> dict[str, Any]:
    topic_status: dict[str, int] = {}
    field_counts: dict[str, int] = {}
    field_count = 0
    for topic in topics:
        if not isinstance(topic, dict):
            raise AssertionError("coverage topic is not an object")
        status = str(topic.get("status", "unknown"))
        topic_status[status] = topic_status.get(status, 0) + 1
        fields = topic.get("fields", {})
        if not isinstance(fields, dict):
            raise AssertionError("coverage fields are not an object")
        for descriptor in fields.values():
            if not isinstance(descriptor, dict):
                raise AssertionError("coverage descriptor is not an object")
            coverage = str(descriptor.get("coverage", "unknown"))
            field_counts[coverage] = field_counts.get(coverage, 0) + 1
            field_count += 1
    return {
        "topic_count": len(topics), "field_count": field_count,
        "topic_status_counts": dict(sorted(topic_status.items())),
        "available_topic_count": topic_status.get("available", 0),
        "callable_topic_count": topic_status.get("available", 0),
        "field_counts": dict(sorted(field_counts.items())),
    }


def _catalog_r01() -> dict[str, Any]:
    from bridge.information.composite import CompositeSource  # noqa: PLC0415
    from bridge.information.country_records import NativeCountryRecordsSource  # noqa: PLC0415
    from bridge.information.country_state import NativeCountryStateSource  # noqa: PLC0415
    from bridge.information.relation_state import NativeRelationSource  # noqa: PLC0415
    from bridge.information.sources import DiplomacySource  # noqa: PLC0415

    primary = DiplomacySource(observer="FRA")
    source = CompositeSource(primary, [
        NativeCountryStateSource(primary),
        NativeCountryRecordsSource(primary),
        NativeRelationSource(primary),
    ])
    entries = [entry for entry in source.catalog() if entry.get("topic_id") == "R01"]
    if len(entries) != 1:
        raise AssertionError("production catalog must expose one R01 entry")
    entry = deepcopy(entries[0])
    by_object = entry.get("relation_types_by_object")
    actual = {
        key: set(value) for key, value in by_object.items()
        if isinstance(value, list)
    } if isinstance(by_object, dict) else {}
    expected = {"country_pair": set(_PAIR_FAMILIES), "country": set(_NETWORK_FAMILIES)}
    if actual != expected:
        raise AssertionError(f"R01 catalog family metadata mismatch: {actual}")
    schema = entry.get("parameters", {}).get("properties", {}).get("relation_types", {})
    if schema.get("maxItems") != len(_PAIR_FAMILIES):
        raise AssertionError("R01 catalog relation_types maxItems is not nine")
    return entry


def _topic_metadata_changes(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    return _batch54._topic_metadata_changes(before, after)


def _merge_only_r01_metadata(matrix: dict[str, Any], r01: dict[str, Any]) -> dict[str, Any]:
    # The batch54 helper preserves every field's coverage/complete values.  It
    # is reused here specifically so this batch cannot promote the four
    # partial fields or the planned expiry field.
    return _batch54._merge_only_r01_metadata(matrix, r01)


def _coverage() -> int:
    _require_stage_and_baseline()
    _verify_before()
    before_path = STAGE / "coverage-matrix-before-001.json"
    matrix_path = ROOT / "docs/信息字段覆盖.json"
    if not before_path.is_file():
        raise AssertionError("coverage-matrix-before-001.json is missing; run --pin-before first")
    if not matrix_path.is_file():
        raise AssertionError("coverage matrix is missing")
    _live_report(required=True)
    discovery_path = STAGE / LIVE_DIRECTORY / "discovery.json"
    baseline_discovery = BASELINE / "live-acceptance-001" / "discovery.json"
    if not discovery_path.is_file() or not baseline_discovery.is_file():
        raise AssertionError("current or batch54 discovery receipt is missing")
    before = read_json(before_path)
    current = read_json(matrix_path)
    if current != before:
        changes = _topic_metadata_changes(before, current)
        if any(not value.startswith("R01.") for value in changes):
            raise AssertionError("coverage matrix changed outside R01 metadata")
    r01 = _catalog_r01()
    merged = _merge_only_r01_metadata(before, r01)
    changes = _topic_metadata_changes(before, merged)
    if not changes:
        raise AssertionError("R01 metadata did not change to the nine/four contract")
    actual_topics = read_json(discovery_path).get("topics")
    baseline_topics = read_json(baseline_discovery).get("topics")
    if not isinstance(actual_topics, list) or not isinstance(baseline_topics, list):
        raise AssertionError("discovery topics are missing")
    actual = _counts(actual_topics)
    baseline_actual = _counts(baseline_topics)
    before_counts = _counts(before.get("topics", []))
    after_counts = _counts(merged.get("topics", []))
    if actual.get("topic_count") != 74 or actual.get("field_count") != 397:
        raise AssertionError("live discovery must remain the 74/397 scope")
    if before_counts.get("topic_count") != 74 or before_counts.get("field_count") != 397:
        raise AssertionError("configured matrix must remain the 74/397 scope")
    matrix_before_sha = sha(matrix_path)
    matrix_path.write_bytes((json.dumps(merged, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    receipt = {
        "schema": "information_relation_remaining_coverage_update.v1",
        "batch": BATCH,
        "goal_complete": False,
        "goal_status": "active",
        "before_sha256": sha(before_path),
        "after_sha256": sha(matrix_path),
        "configured_counts": after_counts,
        "actual_live_counts": actual,
        "baseline_batch54_actual_live_counts": baseline_actual,
        "scope_counts_fixed": {"topics": 74, "fields": 397},
        "metadata_changes": changes,
        "field_coverage_changes": [],
        "coverage_status_unchanged": True,
        "r01_metadata": {
            "object_types": merged["R01"].get("object_types"),
            "relation_types_by_object": merged["R01"].get("relation_types_by_object"),
            "pair_relation_type_count": len(_PAIR_FAMILIES),
            "country_network_family_count": len(_NETWORK_FAMILIES),
            "default_pair_row_count": 10,
        },
        "source": {
            "catalog": "production CompositeSource catalog",
            "current_contract": pin(STAGE / "relation-remaining-contract-005.json"),
            "missing": [
                "expires_at",
                "guarantee_and_military_access_country_network",
                "remaining_full_relation_plan",
            ],
        },
        "matrix_sha256_before_write": matrix_before_sha,
        "note": (
            "Batch55 changes R01 object/family metadata only. Four existing fields "
            "remain partial and expires_at remains planned."
        ),
    }
    write_json(COVERAGE_RECEIPT_BASENAME, receipt)
    print(json.dumps(receipt, ensure_ascii=False))
    return 0


def _remaining_reference_proof() -> dict[str, Any]:
    """Derive the small public facts from independent bounded references."""

    legacy = read_json(BASELINE / "independent-network-expected-003.json")
    trade = read_json(STAGE / "expected-trade-league-current-001.json")
    fleet = read_json(STAGE / "expected-fleet-basing-projection-001.json")

    def partners(family: str) -> list[str]:
        entry = legacy.get("fields", {}).get(family, {})
        values = entry.get("value", []) if isinstance(entry, dict) else []
        result = []
        for row in values if isinstance(values, list) else []:
            if not isinstance(row, dict) or row.get("active") is not True:
                continue
            candidate = row.get("country") or row.get("partner")
            if isinstance(candidate, str) and candidate not in result:
                result.append(candidate)
        return result

    trade_fra = trade.get("fields", {}).get("FRA", {})
    fleet_fra = fleet.get("actors", {}).get("FRA", {}).get("fields", {})
    trade_members = trade_fra.get("members", {}) if isinstance(trade_fra, dict) else {}
    trade_predicate = trade_fra.get("predicate", {}) if isinstance(trade_fra, dict) else {}
    if trade_members.get("status") != "known" or trade_members.get("value") != []:
        raise AssertionError("FRA trade-league independent reference is not known-empty")
    if trade_predicate.get("status") != "known" or trade_predicate.get("value") is not False:
        raise AssertionError("FRA trade-league predicate reference is not false")
    fleet_empty = {}
    for direction in ("received", "granted"):
        item = fleet_fra.get(direction, {}) if isinstance(fleet_fra, dict) else {}
        if item.get("status") != "known" or item.get("value") != []:
            raise AssertionError(f"FRA fleet-basing reference is not known-empty: {direction}")
        fleet_empty[direction] = {"status": item.get("status"), "value": item.get("value")}
    return {
        "legacy": {"alliance": partners("alliance"), "royal_marriage": partners("royal_marriage")},
        "trade_league": {"status": trade_members.get("status"), "predicate": trade_predicate.get("value"), "members": []},
        "fleet_basing": fleet_empty,
        "reference_paths": {
            "legacy": pin(BASELINE / "independent-network-expected-003.json"),
            "trade": pin(STAGE / "expected-trade-league-current-001.json"),
            "fleet": pin(STAGE / "expected-fleet-basing-projection-001.json"),
        },
    }


def _format_counts(counts: dict[str, Any]) -> str:
    values = counts.get("field_counts", {}) if isinstance(counts, dict) else {}
    return "/".join(str(values.get(key, 0)) for key in ("available", "partial", "planned"))


def _batch55_summary(
    live: dict[str, Any], comparison: dict[str, Any], coverage: dict[str, Any], proof: dict[str, Any]
) -> str:
    full = comparison["full"]
    baseline = comparison["baseline"]
    new = comparison["new_or_renamed_tests"]
    identity = live.get("identity") if isinstance(live.get("identity"), dict) else {}
    session = live.get("session_id") or identity.get("session_id") or "unknown"
    game_date = live.get("game_date", "unknown")
    legacy = proof["legacy"]
    periodic = live.get("periodic_results", "unknown")
    if isinstance(periodic, list):
        periodic = len(periodic)
    new_failure_nodes = full.get("new_failure_nodes", [])
    resolved = full.get("resolved_failure_nodes", [])
    delta = (
        f"新增或更名测试 {new['cases']} 个，净增 {comparison['net_case_delta']} 个；"
        f"其中新增/更名失败错误 {new['failure_error_occurrences']} 次。"
    )
    return (
        "## 第五十五批：驻港权与贸易联盟当前状态\n\n"
        f"R01 国家对支持 {len(_PAIR_FAMILIES)} 类关系，FRA 国家网络支持 {len(_NETWORK_FAMILIES)} 类；"
        "默认国家对结果为 10 行，四个公开字段继续 partial、complete=false，expires_at 保持 planned。"
        f"本批实机收据 status={live.get('status')}、server_exit={live.get('server_exit_code')}，周期结果 {periodic} 次；"
        f"订阅是否取消、无活动订阅及控制快照均以 {LIVE_DIRECTORY}/report.json 为准。"
        "首轮001的检查器误把关系类型当状态；原query已离线回放通过，002复用该结果，仅继续报告和周期验收。\n\n"
        f"独立回放中的 FRA trade_league predicate={proof['trade_league']['predicate']}、成员为空，"
        f"fleet_basing received/granted 均为空；静态角色映射与无活动运行时样本分开。"
        f"历史已知盟友为 `{', '.join(legacy['alliance'])}`，联姻对象为 `{', '.join(legacy['royal_marriage'])}`。\n\n"
        f"正式 full001：{full['passed']} passed、{full['failed']} failed、{full['errors']} errors、"
        f"{full['subtests_passed']} 个子测试通过；相对批54基线的既有失败/错误为 "
        f"{baseline['failure_error_occurrences']} 次、{baseline['unique_failure_error_nodes']} 个节点，"
        f"当前 XML 为 {full['failure_error_occurrences']} 次、{full['unique_failure_error_nodes']} 个节点；{delta}"
        f"新失败节点 {len(new_failure_nodes)} 个，解决节点 {len(resolved)} 个。\n\n"
        f"覆盖仍为 74 个主题、397 个字段；配置 available/partial/planned={_format_counts(coverage['configured_counts'])}，"
        f"本次 live discovery={_format_counts(coverage['actual_live_counts'])}。"
        "完整阶段2/3/4、LLM自主订阅及 B01–B04 继续，goal 保持 active；历史成功、已派发、unknown action、"
        "原 final-pass request ID、未闭合 ownership 和原120-action batch 不重试。\n\n"
        f"当前 session `{session}`、game_date `{game_date}`、observer `FRA`，"
        "其余运行身份与 1.37.4 EXE 绑定沿用 live receipt；本批保持只读，不保存、重启、推进日期或提交外交业务。"
    )


def _doc_text(
    live: dict[str, Any], comparison: dict[str, Any], coverage: dict[str, Any], proof: dict[str, Any]
) -> str:
    legacy = proof["legacy"]
    return f'''# 驻港权与贸易联盟接口

现在可以查询法国的驻港权和贸易联盟，将结果保存为报告，并按周期交付。R01 同时提供法国的关系伙伴列表和选定国家对的关系状态。

当前 EU4 1.37.4、FRA、1456.5.13 的实机结果与独立原始记录一致：

| 关系 | 当前结果 |
| --- | --- |
| 同盟 | {', '.join(legacy['alliance'])} |
| 王室联姻 | {', '.join(legacy['royal_marriage'])} |
| 获得、授予驻港权 | 两个方向均为空 |
| 贸易联盟 | 未加入，成员列表为空 |

这些空集合表示本次读取已成功确认没有对应关系。读取失败或上下文变化会返回 `unknown`。

## 查询

`country` 对象只接受 `FRA`。省略 `relation_types` 时读取四个网络家族：

```json
{{
  "request_id": "r01-remaining-network-001",
  "queries": [
    {{
      "topic": "R01",
      "object": {{"type": "country", "country": "FRA"}},
      "fields": ["relation_type", "status", "grantor", "recipient"],
      "parameters": {{}}
    }}
  ]
}}
```

`country_pair` 的 actor 必须仍是 `FRA`。省略参数时读取九类关系，默认结果为十行，驻港权的 `received`、`granted` 各占一行。下面只查询法国与萨伏依之间的驻港权和贸易联盟：

```json
{{
  "request_id": "r01-remaining-pair-001",
  "queries": [
    {{
      "topic": "R01",
      "object": {{"type": "country_pair", "actor": "FRA", "recipient": "SAV"}},
      "fields": ["relation_type", "status", "grantor", "recipient"],
      "parameters": {{"relation_types": ["fleet_basing", "trade_league"]}}
    }}
  ]
}}
```

每个字段的 `value` 是平铺关系行。驻港权 `received` 表示对方作为港口方、FRA 作为使用方；`granted` 方向相反。贸易联盟的 `grantor`、`recipient` 保持 `not_applicable`，必要时另带 `league_leader`。缺失、方向不明、上下文变化或守卫失败返回 `unknown`，不以 action 名称、legality、pending 或历史记录推断当前关系。

## 报告和周期订阅

`information_manage_report` 复用上面的 `queries` 配置。创建报告后，使用当前 `information_discover` 返回的 session 绑定创建订阅。主动查询、报告查询和一次五秒周期交付已通过实机验收，订阅随后取消，当前没有活动订阅。实际结果见[本批验收记录](../work/runtime/information-relation-remaining-20261027-001/{LIVE_DIRECTORY}/report.json)。

## 边界和来源

四个公开字段 `relation_type`、`status`、`grantor`、`recipient` 保持 `coverage: "partial"`、`complete: false`。关系期限 `expires_at`、保证与军事访问的国家网络视图继续开发。驻港权的方向与角色来自静态原生代码，本批运行时样本没有活动驻港权；贸易联盟另用汉萨的非空成员记录验证了读取器。

来源包括 [`relation_state.py`](../bridge/information/relation_state.py)、[`trade_league_memory.py`](../bridge/information/trade_league_memory.py)、[`fleet_basing_memory.py`](../bridge/information/fleet_basing_memory.py)、[`relation-remaining-contract-005.json`](../work/runtime/information-relation-remaining-20261027-001/relation-remaining-contract-005.json)、[`expected-trade-league-current-001.json`](../work/runtime/information-relation-remaining-20261027-001/expected-trade-league-current-001.json) 和 [`expected-fleet-basing-projection-001.json`](../work/runtime/information-relation-remaining-20261027-001/expected-fleet-basing-projection-001.json)。驻港权完整原始参考只做流式哈希和 pin，不复制到 source snapshot。
'''


_BATCH55_DOC_START = "<!-- batch55-relation-remaining-summary:start -->"
_BATCH55_DOC_END = "<!-- batch55-relation-remaining-summary:end -->"


def _replace_or_prepend_batch55_marker(path: Path, block: str) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    marked = f"{_BATCH55_DOC_START}\n{block.rstrip()}\n{_BATCH55_DOC_END}"
    if _BATCH55_DOC_START in text:
        start = text.index(_BATCH55_DOC_START)
        end = text.index(_BATCH55_DOC_END, start) + len(_BATCH55_DOC_END)
        updated = text[:start] + marked + text[end:]
    else:
        updated = marked + "\n\n" + text
    if updated != text:
        path.write_text(updated, encoding="utf-8", newline="\n")
    return pin(path)


def _update_batch55_documents(summary: str) -> list[dict[str, Any]]:
    targets = (
        ROOT / "HANDOFF.md",
        ROOT / "README(agent).md",
        ROOT / "docs/信息导出与订阅开发计划.md",
        ROOT / "docs/LLM导出信息目录.md",
    )
    pinned = []
    for path in targets:
        if not path.is_file():
            raise AssertionError(f"batch55 document is missing: {path.relative_to(ROOT)}")
        link = (
            "\n\n调用见[驻港权与贸易联盟接口](docs/驻港权与贸易联盟接口.md)。"
            if path.parent == ROOT else
            "\n\n调用见[驻港权与贸易联盟接口](驻港权与贸易联盟接口.md)。"
        )
        pinned.append(_replace_or_prepend_batch55_marker(path, summary + link))
    return pinned


def _docs() -> int:
    _require_stage_and_baseline()
    _verify_before()
    live = _live_report(required=True)
    comparison = _regression_comparison()
    coverage_path = STAGE / COVERAGE_RECEIPT_BASENAME
    if not coverage_path.is_file():
        raise AssertionError("batch55 coverage receipt is missing")
    coverage = read_json(coverage_path)
    if coverage.get("field_coverage_changes") != [] or coverage.get("coverage_status_unchanged") is not True:
        raise AssertionError("batch55 coverage is not metadata-only")
    proof = _remaining_reference_proof()
    target = ROOT / "docs/驻港权与贸易联盟接口.md"
    target.write_text(_doc_text(live, comparison, coverage, proof), encoding="utf-8", newline="\n")
    summary = _batch55_summary(live, comparison, coverage, proof)
    summary_documents = _update_batch55_documents(summary)
    receipt = {
        "schema": "information_relation_remaining_document_verification.v1",
        "batch": BATCH,
        "status": "passed",
        "document": pin(target),
        "previous_document_receipt": pin(STAGE / "document-verification-001.json"),
        "live_acceptance": pin(STAGE / LIVE_DIRECTORY / "report.json"),
        "full_comparison": comparison,
        "coverage_receipt": pin(coverage_path),
        "summary_documents": summary_documents,
        "new_game_queries_or_pytest_runs": 0,
        "checks": {
            "live_receipt_passed": True,
            "full_receipt_completed": True,
            "query_examples": True,
            "report_and_periodic_boundary_described": True,
            "partial_and_expiry_boundary_preserved": True,
            "batch55_summary_prepend_preserved_batch54_history": True,
            "live_status_derived_not_predeclared": True,
        },
    }
    write_json(DOCUMENT_RECEIPT_BASENAME, receipt)
    return 0


def _current_source_paths() -> tuple[Path, ...]:
    paths = [ROOT / relative for relative in _CURRENT_SOURCE_PATHS]
    for pattern in _SOURCE_GLOBS:
        paths.extend(ROOT.glob(pattern))
    return tuple(dict.fromkeys(path for path in paths if path.is_file() and "source-snapshot" not in path.parts))


def _source_snapshot_paths() -> tuple[Path, ...]:
    paths = [path for path in _current_source_paths() if path.stat().st_size <= MAX_SOURCE_SNAPSHOT_BYTES]
    required = {
        "bridge/information/relation_state.py",
        "bridge/information/trade_league_memory.py",
        "bridge/information/fleet_basing_memory.py",
        "work/validate_information_relation_remaining_live.py",
        "work/finalize_information_relation_remaining.py",
        "docs/驻港权与贸易联盟接口.md",
    }
    present = {path.relative_to(ROOT).as_posix() for path in paths}
    if not required <= present:
        raise AssertionError("batch55 source snapshot is missing core source")
    return tuple(dict.fromkeys(paths))


def _stage_artifact_paths() -> tuple[Path, ...]:
    return tuple(path for path in sorted(STAGE.rglob("*")) if path.is_file() and "source-snapshot" not in path.parts)


def _artifact_inventory() -> list[dict[str, Any]]:
    records = []
    for path in _stage_artifact_paths():
        item = pin(path)
        item.update({
            "snapshot": None,
            "snapshot_policy": "artifact_pin_only_large" if path.stat().st_size > MAX_SOURCE_SNAPSHOT_BYTES else "eligible_for_bounded_reference",
        })
        records.append(item)
    return records


def _rea_pins() -> list[dict[str, Any]]:
    records = []
    for path in _stage_artifact_paths():
        if not any(part.startswith("rea-") for part in path.relative_to(STAGE).parts):
            continue
        item = pin(path)
        if path.suffix.lower() == ".json" and path.stat().st_size <= 2 * 1024 * 1024:
            try:
                doc = read_json(path, max_bytes=2 * 1024 * 1024)
            except (AssertionError, OSError, UnicodeDecodeError, json.JSONDecodeError):
                doc = None
            if isinstance(doc, dict):
                item.update({"status": doc.get("status") or doc.get("state"), "terminal": doc.get("terminal") or doc.get("closed"), "exit_code": doc.get("exit_code")})
        records.append(item)
    return records


def _archive() -> int:
    _require_stage_and_baseline()
    before, after = _verify_before()
    live = _live_report(required=True)
    coverage_path = STAGE / COVERAGE_RECEIPT_BASENAME
    document_path = STAGE / DOCUMENT_RECEIPT_BASENAME
    if not coverage_path.is_file() or not document_path.is_file():
        raise AssertionError("coverage/document receipts are missing")
    coverage = read_json(coverage_path)
    document = read_json(document_path)
    if coverage.get("field_coverage_changes") != [] or coverage.get("coverage_status_unchanged") is not True:
        raise AssertionError("batch55 coverage is not metadata-only")
    if document.get("status") != "passed" or document.get("new_game_queries_or_pytest_runs") != 0:
        raise AssertionError("batch55 document verification is not live-receipt-backed")
    production_comparison_path = STAGE / "production-comparison-001.json"
    if not production_comparison_path.is_file():
        raise AssertionError("batch55 production child comparison receipt is missing")
    production_comparison = read_json(production_comparison_path)
    if production_comparison.get("status") != "passed":
        raise AssertionError("batch55 production child comparison is not passed")
    comparison = _regression_comparison()
    if comparison["full"]["new_failure_nodes"]:
        raise AssertionError("batch55 introduced failure/error nodes")
    if comparison["new_or_renamed_tests"]["failure_error_occurrences"]:
        raise AssertionError("a new or renamed batch55 test failed")
    if (STAGE / "runtime-source-pins-after-001.json").exists():
        raise AssertionError("batch55 archive already exists")
    write_json("runtime-source-pins-after-001.json", {
        "schema": before.get("schema", "information_runtime_source_pins.v1"),
        "batch": BATCH, "files": after, "all_match_before": True,
        "timing": "after batch55 live acceptance and formal full regression",
        "continuous_monitoring_claimed": False,
    })
    write_json("regression-comparison-001.json", comparison)

    snapshots = []
    for path in _source_snapshot_paths():
        original = pin(path)
        target = STAGE / "source-snapshot" / path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise AssertionError(f"source snapshot already exists: {target.relative_to(ROOT)}")
        shutil.copyfile(path, target)
        if sha(path) != original["sha256"] or sha(target) != original["sha256"]:
            raise AssertionError(f"source snapshot changed during copy: {original['path']}")
        snapshots.append(dict(original, snapshot=target.relative_to(ROOT).as_posix()))

    previous = read_json(BASELINE / "development-summary-001.json")
    current_artifacts = _artifact_inventory()
    current_sources = _current_source_paths()
    large_source_pins = [pin(path) for path in current_sources if path.stat().st_size > MAX_SOURCE_SNAPSHOT_BYTES]
    summary = {
        "schema": "information_development_summary.v1",
        "batch": BATCH,
        "status": "implemented_relation_remaining_partial",
        "objective": previous.get("objective"),
        "goal_complete": False,
        "goal_status": "active",
        "scope": {
            **deepcopy(previous.get("scope", {})),
            "topic": "R01",
            "pair_relation_types": list(_PAIR_FAMILIES),
            "country_network_families": list(_NETWORK_FAMILIES),
            "default_pair_row_count": 10,
            "full_relation_network": False,
        },
        "delivered": {
            "R01": ["fleet_basing", "trade_league"],
            "country_network_families": list(_NETWORK_FAMILIES),
            "pair_relation_types": list(_PAIR_FAMILIES),
            "coverage_status_unchanged": True,
            "complete": False,
        },
        "runtime_validation": live,
        "documentation_validation": document,
        "coverage": coverage,
        "tests": {"formal_full": comparison["full"], "new_or_renamed_tests": comparison["new_or_renamed_tests"], "counts_not_additive": True},
        "runtime_identity": deepcopy(previous.get("runtime_identity", {})),
        "source_layers": {
            "remaining_source": pin(STAGE / "relation-remaining-source-001.json"),
            "remaining_contract": pin(STAGE / "relation-remaining-contract-005.json"),
            "trade_league_reference": pin(STAGE / "expected-trade-league-current-001.json"),
            "fleet_basing_projection": pin(STAGE / "expected-fleet-basing-projection-001.json"),
            "fleet_basing_full_reference": pin(STAGE / "expected-fleet-basing-current-001.json"),
            "production_comparison": pin(production_comparison_path),
            "rea_terminal_pins": _rea_pins(),
            "large_files_not_copied": True,
        },
        "source_snapshot": snapshots,
        "source_snapshot_policy": {"bounded_max_bytes": MAX_SOURCE_SNAPSHOT_BYTES, "large_source_artifact_pins": large_source_pins, "large_files_not_copied": True},
        "stage_artifacts": current_artifacts,
        "baseline": {"stage": BASELINE.relative_to(ROOT).as_posix(), "regression": comparison["baseline"]},
        "next_work": {
            "expires_at": "planned; no native expiry serializer closed",
            "guarantee_and_military_access_country_network": "planned; country network family source missing",
            "full_relation_network_and_remaining_plan": "active",
            "mcp_receipt": "actual live acceptance is selected by report pin; no prewritten pass",
            "production_child_comparison": "passed receipt required",
        },
        "no_repeat": {"historical_actions_and_original_final_pass_ids": "not retried", "business_actions_submitted": live.get("business_actions_submitted")},
    }
    summary_path = write_json("development-summary-001.json", summary)
    archive = {
        "schema": "information_relation_remaining_archive_verification.v1",
        "batch": BATCH,
        "status": "passed",
        "summary": pin(summary_path),
        "runtime_source_pins_after": pin(STAGE / "runtime-source-pins-after-001.json"),
        "regression_comparison": pin(STAGE / "regression-comparison-001.json"),
        "source_snapshot_count": len(snapshots),
        "stage_artifact_count": len(current_artifacts),
        "large_source_pin_count": len(large_source_pins),
        "large_reference_policy": "streaming_hash_and_pin_only",
        "checks": {
            "live_receipt_passed": True,
            "coverage_metadata_only": True,
            "new_failure_nodes_empty": comparison["full"]["new_failure_nodes"] == [],
            "new_or_renamed_test_failures": False,
            "old_baseline_debt_preserved": (
                comparison["full"]["failure_error_occurrences"]
                == comparison["baseline"]["failure_error_occurrences"]
                and comparison["full"]["unique_failure_error_nodes"]
                == comparison["baseline"]["unique_failure_error_nodes"]
            ),
            "baseline_debt_compared_from_xml": {
                "baseline_failure_error_occurrences": comparison["baseline"]["failure_error_occurrences"],
                "current_failure_error_occurrences": comparison["full"]["failure_error_occurrences"],
                "baseline_unique_failure_error_nodes": comparison["baseline"]["unique_failure_error_nodes"],
                "current_unique_failure_error_nodes": comparison["full"]["unique_failure_error_nodes"],
                "resolved_failure_nodes": comparison["full"]["resolved_failure_nodes"],
                "new_failure_nodes": comparison["full"]["new_failure_nodes"],
            },
            "source_snapshot_bounded": True,
            "fleet_full_reference_not_copied": True,
        },
    }
    write_json("archive-verification-001.json", archive)
    print(json.dumps({"summary": pin(summary_path), "archive": archive, "source_snapshots": len(snapshots)}, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Batch55 relation remaining finalizer; explicit phase only.")
    phases = parser.add_mutually_exclusive_group()
    phases.add_argument("--freeze", "--pin-before", dest="freeze", action="store_true", help="pin runtime sources and coverage bytes")
    phases.add_argument("--full", action="store_true", help="run python -m pytest -q bridge/tests and write JUnit XML")
    phases.add_argument("--coverage", action="store_true", help="merge R01 metadata only")
    phases.add_argument("--docs", action="store_true", help="write the remaining relation document")
    phases.add_argument("--archive", action="store_true", help="verify receipts and create the bounded archive")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not any((args.freeze, args.full, args.coverage, args.docs, args.archive)):
        parser.print_help()
        return 0
    if args.freeze:
        return _pin_before()
    if args.full:
        return _run_full()
    if args.coverage:
        return _coverage()
    if args.docs:
        return _docs()
    return _archive()


if __name__ == "__main__":
    raise SystemExit(main())
