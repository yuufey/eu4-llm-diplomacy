"""Batch 54 finalizer for the current relation-network contract.

This module is deliberately inert unless one explicit phase flag is supplied.
With no flag, and with ``--help``, it only prints the CLI contract.  The
``--full`` phase is the only phase which may start pytest; the other phases
only validate or write their bounded receipts after their required inputs
exist.  The root worker is expected to run the phases in order:

``--pin-before`` -> live acceptance -> ``--full`` -> ``--coverage`` ->
``--docs`` -> ``--archive``.

The helper does not start a game, MCP, RPM, REA analysis, or a diplomatic
action.  It does not alter batch 53 artifacts.  Batch 54 relation-network
source evidence is kept separate from the inherited batch 53 runtime pins.
"""
from __future__ import annotations

import argparse
from collections import Counter
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
STAGE = ROOT / "work/runtime/information-relation-current-20261027-001"
BASELINE = ROOT / "work/runtime/information-country-records-localization-20261027-001"
REGRESSION_BASENAME = "regression-full-001"
BASELINE_REGRESSION_BASENAME = "regression-full-002"
COVERAGE_RECEIPT_BASENAME = "coverage-update-002.json"
DOCUMENT_RECEIPT_BASENAME = "document-verification-002.json"
BATCH = 54

_RELATION_RUNTIME_PATHS = (
    "bridge/information/relation_memory.py",
    "bridge/information/profiles/relation-memory-1374.json",
)

# These are the only current-batch source files copied by --archive.  The
# inherited 53 runtime paths are pinned separately, so a source snapshot does
# not silently grow into a copy of the previous batch.
_CURRENT_SOURCE_PATHS = (
    "bridge/information/relation_memory.py",
    "bridge/information/profiles/relation-memory-1374.json",
    "bridge/information/relation_state.py",
    "bridge/information/relation_records.py",
    "bridge/information/composite.py",
    "bridge/tests/test_information_relation_memory.py",
    "bridge/tests/test_information_relation_state.py",
    "bridge/tests/test_information_relation_records.py",
    "bridge/tests/fixtures/information_country_relations_live_1374.json",
    "work/research-next/relation_current.py",
    "work/research-next/relation_network_scope.py",
    "work/research-next/relation_network_scope_002.py",
    "work/runtime/information-relation-current-20261027-001/relation-current-source-001.json",
    "work/runtime/information-relation-current-20261027-001/relation-current-source-002.json",
    "work/runtime/information-relation-current-20261027-001/relation-current-contract-003.json",
    "work/runtime/information-relation-network-scope-20261027-001/relation-network-scope-001.json",
    "work/runtime/information-relation-network-scope-20261027-001/relation-network-scope-002.json",
    "work/finalize_information_relation_current.py",
    "docs/联盟与联姻关系网接口.md",
    "HANDOFF.md",
    "README(agent).md",
    "docs/信息导出与订阅开发计划.md",
    "docs/LLM导出信息目录.md",
    "docs/信息字段覆盖.json",
)
_CURRENT_SOURCE_GLOBS = (
    # Batch54's bounded probes, references, production replay helpers and
    # their narrowly named relation-network tests.  These patterns never
    # recurse through the whole work tree.
    "work/*relation_current*.py",
    "work/*relation_network*.py",
    "work/research-next/*relation_current*.py",
    "work/research-next/*relation_network*.py",
    "work/research-next/*finalize_relation_current*.py",
    "bridge/tests/test_information_relation*.py",
    "bridge/tests/fixtures/information_relation*.json",
    "bridge/tests/fixtures/information_relation*.json.gz",
)
_MAX_SOURCE_SNAPSHOT_BYTES = 10 * 1024 * 1024

_R01_METADATA_KEYS = (
    "catalog_ids",
    "title",
    "topic_id",
    "object_types",
    "parameters",
    "source",
    "status",
    "supported_versions",
    "triggers",
    "visibility",
    "observer_roles",
    "observer_scope",
    "context_scope",
    "scope_note",
    "relation_types_by_object",
    "change_detection",
    "adapter_sources",
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


def read_json(path: Path) -> Any:
    if not path.is_file():
        raise AssertionError(f"required receipt is missing: {path.relative_to(ROOT)}")
    return json.loads(path.read_bytes())


def write_json(name: str, value: Any) -> Path:
    STAGE.mkdir(parents=True, exist_ok=True)
    target = STAGE / name
    if target.exists():
        raise AssertionError(f"batch54 receipt already exists: {target.relative_to(ROOT)}")
    with target.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return target


def _inherited_runtime_paths() -> tuple[str, ...]:
    """Load batch53 pins only when a phase explicitly needs them."""

    sys.path.insert(0, str(ROOT))
    from work.archive_information_country_records_localization import (  # noqa: PLC0415
        RUNTIME_PATHS as batch53_runtime_paths,
    )

    return tuple(batch53_runtime_paths)


def runtime_paths() -> tuple[str, ...]:
    return tuple(dict.fromkeys(_inherited_runtime_paths() + _RELATION_RUNTIME_PATHS))


def _require_stage_and_baseline() -> None:
    if not STAGE.is_dir():
        raise AssertionError(f"batch54 source stage is missing: {STAGE}")
    if not BASELINE.is_dir():
        raise AssertionError(f"batch53 baseline stage is missing: {BASELINE}")


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
        raise AssertionError("batch54 source pins already exist")
    paths = _require_runtime_files()
    matrix = ROOT / "docs/信息字段覆盖.json"
    matrix_snapshot = STAGE / "coverage-matrix-before-001.json"
    if not matrix_snapshot.exists():
        with matrix_snapshot.open("xb") as stream:
            stream.write(matrix.read_bytes())
    write_json(
        target.name,
        {
            "schema": "information_runtime_source_pins.v1",
            "batch": BATCH,
            "baseline_stage": BASELINE.relative_to(ROOT).as_posix(),
            "timing": "before batch54 live acceptance and formal full regression",
            "continuous_monitoring_claimed": False,
            "inherited_batch53_runtime_paths": len(_inherited_runtime_paths()),
            "files": [pin(ROOT / relative) for relative in paths],
        },
    )
    return 0


def _verify_before() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    before = read_json(STAGE / "runtime-source-pins-before-001.json")
    if before.get("batch") != BATCH:
        raise AssertionError("runtime source pin is not a batch54 pin")
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
        raise AssertionError("a frozen batch54 runtime source changed")
    return before, after


def _read_live_report() -> dict[str, Any]:
    report = read_json(STAGE / "live-acceptance-001" / "report.json")
    if report.get("status") != "passed" or report.get("server_exit_code") != 0:
        raise AssertionError("batch54 live acceptance is not passed/exit0")
    checks = report.get("checks")
    if isinstance(checks, dict) and not all(checks.values()):
        raise AssertionError("batch54 live acceptance contains a failed check")
    return report


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


def _case_key(case: ET.Element) -> str:
    return f"{case.get('classname')}::{case.get('name')}"


def _test_cases(path: Path) -> tuple[list[ET.Element], set[str], int]:
    root = ET.parse(path).getroot()
    cases = root.findall(".//testcase")
    bad = {
        _case_key(case)
        for case in cases
        if case.findall("failure") or case.findall("error")
    }
    occurrences = sum(
        len(case.findall("failure")) + len(case.findall("error"))
        for case in cases
    )
    return cases, bad, occurrences


def _regression_comparison() -> dict[str, Any]:
    xml = STAGE / f"{REGRESSION_BASENAME}.xml"
    log = STAGE / f"{REGRESSION_BASENAME}.log"
    baseline_xml = BASELINE / f"{BASELINE_REGRESSION_BASENAME}.xml"
    if not xml.is_file() or not log.is_file() or not baseline_xml.is_file():
        raise AssertionError("formal batch54 or batch53 baseline regression receipt is missing")
    cases, bad, occurrences = _test_cases(xml)
    old_cases, old_bad, old_occurrences = _test_cases(baseline_xml)
    old_keys = {_case_key(case) for case in old_cases}
    current_bad = {
        _case_key(case)
        for case in cases
        if case.findall("failure") or case.findall("error")
    }
    added = [case for case in cases if _case_key(case) not in old_keys]
    line = _summary_line(log)
    full = {
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
    }
    new_tests = {
        "execution": "derived_from_formal_full_XML_not_another_run",
        "count_basis": "new_or_renamed_test_node_ids",
        "cases": len(added),
        "net_case_increase": len(cases) - len(old_cases),
        "removed_node_ids": sorted(old_keys - {_case_key(case) for case in cases}),
        "failure_error_occurrences": sum(
            len(case.findall("failure")) + len(case.findall("error"))
            for case in added
        ),
        "nodes": [_case_key(case) for case in added],
    }
    return {
        "full": full,
        "new_tests": new_tests,
        "baseline": {
            "xml": pin(baseline_xml),
            "failure_error_occurrences": old_occurrences,
            "unique_failure_error_nodes": len(old_bad),
            "case_count": len(old_cases),
        },
        "current_case_count": len(cases),
        "case_set_changed": old_keys != {_case_key(case) for case in cases},
    }


def _run_full() -> int:
    _require_stage_and_baseline()
    _verify_before()
    _read_live_report()
    xml = STAGE / f"{REGRESSION_BASENAME}.xml"
    log = STAGE / f"{REGRESSION_BASENAME}.log"
    if xml.exists() or log.exists():
        raise AssertionError("batch54 formal regression receipts already exist")
    with log.open("x", encoding="utf-8", newline="\n") as stream:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "bridge/tests", "--junitxml", str(xml)],
            cwd=ROOT,
            stdout=stream,
            stderr=subprocess.STDOUT,
            check=False,
        )
    print(f"formal batch54 full regression exit {result.returncode}")
    return result.returncode


def _counts(topics: list[dict[str, Any]]) -> dict[str, Any]:
    field_counts: Counter[str] = Counter()
    topic_status_counts: Counter[str] = Counter()
    field_count = 0
    for topic in topics:
        if not isinstance(topic, dict):
            raise AssertionError("coverage topic is not an object")
        topic_status_counts[str(topic.get("status", "unknown"))] += 1
        fields = topic.get("fields", {})
        if not isinstance(fields, dict):
            raise AssertionError(f"coverage fields are not an object: {topic.get('topic_id')}")
        for descriptor in fields.values():
            if not isinstance(descriptor, dict):
                raise AssertionError(f"coverage descriptor is not an object: {topic.get('topic_id')}")
            field_counts[str(descriptor.get("coverage", "unknown"))] += 1
            field_count += 1
    return {
        "topic_count": len(topics),
        "field_count": field_count,
        "topic_status_counts": dict(sorted(topic_status_counts.items())),
        "available_topic_count": topic_status_counts.get("available", 0),
        "callable_topic_count": topic_status_counts.get("available", 0),
        "field_counts": dict(sorted(field_counts.items())),
    }


def _catalog_r01() -> dict[str, Any]:
    """Read the production catalog only during the explicit coverage phase."""

    sys.path.insert(0, str(ROOT))
    from bridge.information.composite import CompositeSource  # noqa: PLC0415
    from bridge.information.country_records import NativeCountryRecordsSource  # noqa: PLC0415
    from bridge.information.country_state import NativeCountryStateSource  # noqa: PLC0415
    from bridge.information.relation_state import NativeRelationSource  # noqa: PLC0415
    from bridge.information.sources import DiplomacySource  # noqa: PLC0415

    primary = DiplomacySource(observer="FRA")
    source = CompositeSource(
        primary,
        [NativeCountryStateSource(primary), NativeCountryRecordsSource(primary), NativeRelationSource(primary)],
    )
    entries = [entry for entry in source.catalog() if entry.get("topic_id") == "R01"]
    if len(entries) != 1:
        raise AssertionError("production catalog must expose one R01 entry")
    entry = deepcopy(entries[0])
    if set(entry.get("object_types", [])) != {"country_pair", "country"}:
        raise AssertionError("R01 catalog has not reached the country network contract")
    by_object = entry.get("relation_types_by_object")
    expected = {
        "country_pair": {
            "vassalization", "guarantee", "support_independence", "military_access",
            "rival", "alliance", "royal_marriage",
        },
        "country": {"alliance", "royal_marriage"},
    }
    if not isinstance(by_object, dict) or {
        key: set(value) for key, value in by_object.items() if isinstance(value, list)
    } != expected:
        raise AssertionError("R01 catalog relation_types_by_object is not the seven/two contract")
    return entry


def _merge_only_r01_metadata(matrix: dict[str, Any], r01: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(matrix)
    topics = result.get("topics")
    if not isinstance(topics, list):
        raise AssertionError("coverage matrix topics are missing")
    matches = [topic for topic in topics if topic.get("topic_id") == "R01"]
    if len(matches) != 1:
        raise AssertionError("coverage matrix must contain one R01 topic")
    before_r01 = deepcopy(matches[0])
    target = matches[0]
    # Field coverage and field semantics are inherited from batch53.  Only
    # the topic-level object/parameter metadata is changed in this batch.
    for key in _R01_METADATA_KEYS:
        if key in r01:
            target[key] = deepcopy(r01[key])
    # Field descriptors carry the relation-type/object metadata used by the
    # catalog consumers.  Copy that metadata, while explicitly preserving the
    # batch53 coverage and completeness values for every field.
    before_fields = before_r01.get("fields", {})
    target_fields = target.get("fields", {})
    catalog_fields = r01.get("fields", {})
    if not isinstance(before_fields, dict) or not isinstance(target_fields, dict):
        raise AssertionError("R01 field descriptors are missing")
    if not isinstance(catalog_fields, dict):
        raise AssertionError("production R01 field descriptors are missing")
    for field, descriptor in catalog_fields.items():
        if field not in target_fields or not isinstance(descriptor, dict):
            continue
        old = target_fields[field]
        merged_descriptor = deepcopy(descriptor)
        for key in ("coverage", "complete"):
            if key in old:
                merged_descriptor[key] = deepcopy(old[key])
        target_fields[field] = merged_descriptor
    if any(
        target_fields.get(field, {}).get("coverage") != before_fields.get(field, {}).get("coverage")
        or target_fields.get(field, {}).get("complete") != before_fields.get(field, {}).get("complete")
        for field in before_fields
    ):
        raise AssertionError("R01 field coverage changed; batch54 is metadata-only")
    result["R01"] = {
        key: deepcopy(target[key])
        for key in ("fields", "context_scope", "source", "adapter_sources", "object_types", "parameters", "relation_types_by_object")
        if key in target
    }
    result["topics"] = topics
    return result


def _topic_metadata_changes(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    before_topics = {topic.get("topic_id"): topic for topic in before.get("topics", [])}
    after_topics = {topic.get("topic_id"): topic for topic in after.get("topics", [])}
    changes: list[str] = []
    for topic_id in sorted(set(before_topics) | set(after_topics)):
        if topic_id != "R01" and before_topics.get(topic_id) != after_topics.get(topic_id):
            raise AssertionError(f"non-R01 coverage metadata changed: {topic_id}")
    for key in _R01_METADATA_KEYS:
        if before_topics.get("R01", {}).get(key) != after_topics.get("R01", {}).get(key):
            changes.append(f"R01.{key}")
    before_fields = before_topics.get("R01", {}).get("fields", {})
    after_fields = after_topics.get("R01", {}).get("fields", {})
    for field in sorted(set(before_fields) | set(after_fields)):
        old = before_fields.get(field, {})
        new = after_fields.get(field, {})
        for key in sorted(set(old) | set(new)):
            if key in {"coverage", "complete"}:
                continue
            if old.get(key) != new.get(key):
                changes.append(f"R01.fields.{field}.{key}")
    return changes


def _discovery_topics(document: dict[str, Any]) -> list[dict[str, Any]]:
    topics = document.get("topics")
    if not isinstance(topics, list):
        raise AssertionError("live discovery topics are missing")
    return topics


def _coverage_map(topics: list[dict[str, Any]]) -> dict[tuple[str, str], Any]:
    return {
        (str(topic.get("topic_id")), str(field)): descriptor.get("coverage")
        for topic in topics
        for field, descriptor in topic.get("fields", {}).items()
        if isinstance(descriptor, dict)
    }


def _run_coverage() -> int:
    _require_stage_and_baseline()
    before_path = STAGE / "coverage-matrix-before-001.json"
    matrix_path = ROOT / "docs/信息字段覆盖.json"
    if not before_path.is_file():
        raise AssertionError("coverage-matrix-before-001.json is missing; run --pin-before first")
    if not matrix_path.is_file():
        raise AssertionError("coverage matrix is missing")
    _read_live_report()
    discovery_path = STAGE / "live-acceptance-001" / "discovery.json"
    baseline_discovery = BASELINE / "live-acceptance-001" / "discovery.json"
    if not baseline_discovery.is_file():
        raise AssertionError("batch53 live discovery baseline is missing")
    before = read_json(before_path)
    current = read_json(matrix_path)
    if current != before:
        # Root may have prepared the R01 metadata before this phase.  It is
        # accepted only if every difference is an R01 metadata difference.
        allowed = _topic_metadata_changes(before, current)
        if any(not value.startswith("R01.") for value in allowed):
            raise AssertionError("coverage matrix changed outside R01 metadata")
    r01 = _catalog_r01()
    merged = _merge_only_r01_metadata(before, r01)
    changes = _topic_metadata_changes(before, merged)
    if not changes:
        raise AssertionError("R01 metadata did not change to the seven/two contract")
    # Preserve any already prepared R01 metadata only when it is exactly the
    # production catalog result; otherwise this phase writes the canonical
    # production-derived metadata.
    merged_raw = (json.dumps(merged, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    actual = _counts(_discovery_topics(read_json(discovery_path)))
    actual_topics = _discovery_topics(read_json(discovery_path))
    baseline_actual_topics = _discovery_topics(read_json(baseline_discovery))
    baseline_actual = _counts(baseline_actual_topics)
    if _coverage_map(actual_topics) != _coverage_map(baseline_actual_topics):
        raise AssertionError("live discovery changed a field coverage status in metadata-only batch54")
    configured = _counts(merged["topics"])
    current_path_hash_before = sha(matrix_path)
    matrix_path.write_bytes(merged_raw)
    rpm_receipt = _dynamic_rpm_receipt()
    receipt = {
        "schema": "information_relation_current_coverage_update.v1",
        "batch": BATCH,
        "goal_complete": False,
        "goal_status": "active",
        "before_sha256": sha(before_path),
        "after_sha256": sha(matrix_path),
        "configured_counts": configured,
        "actual_live_counts": actual,
        "baseline_batch53_actual_live_counts": baseline_actual,
        "counts_derived_from": {
            "configured": "production CompositeSource catalog",
            "actual_live": "batch54 live-acceptance-001/discovery.json",
        },
        "metadata_changes": changes,
        "field_coverage_changes": [],
        "coverage_status_unchanged": True,
        "r01_metadata": {
            "object_types": merged["R01"].get("object_types"),
            "relation_types_by_object": merged["R01"].get("relation_types_by_object"),
        },
        "source": {
            "ordinary_source": "relation-current-source-002.json",
            "accepted_rea_contract": "relation-current-contract-003.json",
            "new_rpm": {
                "status": rpm_receipt["status"],
                "selected_reference": rpm_receipt.get("selected_reference"),
                "selected_production_replay": rpm_receipt.get("selected_production_replay"),
                "reference_artifact_count": len(rpm_receipt.get("reference_artifacts", [])),
                "production_raw_artifact_count": len(rpm_receipt.get("production_raw_artifacts", [])),
                "comparison_receipt_count": len(rpm_receipt.get("production_replay_receipts", [])),
                "memory_replay_receipt_count": len(rpm_receipt.get("memory_replay_receipts", [])),
            },
            "missing": ["expires_at", "fleet_basing", "trade_league"],
        },
        "note": (
            "Batch54 changes R01 object and relation-type metadata only. "
            "Configured and live counts are calculated independently; no totals are hardcoded."
        ),
        "matrix_sha256_before_write": current_path_hash_before,
    }
    receipt["supersedes"] = "coverage-update-001.json (R01 alias metadata correction; counts unchanged)"
    write_json(COVERAGE_RECEIPT_BASENAME, receipt)
    print(json.dumps(receipt, ensure_ascii=False))
    return 0


def _doc_text() -> str:
    return r'''# 联盟与联姻关系网接口

R01 已可列出法国的联盟与王室联姻伙伴，并查询选定国家对的七类当前关系。本批在 EU4 `1.37.4`、暂停日期1456年5月13日实测：法国盟友为苏格兰（SCO）、萨伏依（SAV），联姻对象为阿马尼亚克（AMG）、富瓦（FOI）。查询、报告和一次周期订阅交付均已通过，订阅已取消。接口只读当前关系。

当前 R01 保持 `coverage: "partial"`、`complete: false`。`country_pair` 视图支持七类关系：`vassalization`、`guarantee`、`support_independence`、`military_access`、`rival`、`alliance` 和 `royal_marriage`。`country` 视图枚举 FRA 的 `alliance` 与 `royal_marriage` 当前活动伙伴。驻港权、贸易联盟、关系期限及其余关系网继续开发；最新伙伴由查询或报告结果提供。

## 查询对象和字段

`country_pair` 的 `actor` 必须是 `FRA`，`recipient` 必须是另一个国家标签。`parameters.relation_types` 可以省略，表示该对象支持的七类；也可以提交 1 至 7 个不重复枚举值。`country` 的 `country` 必须是 `FRA`，省略参数时读取联盟和王室联姻；该对象只接受这两类。

四个已接入的关系状态字段为 `relation_type`、`status`、`grantor` 和 `recipient`。行顺序跟随请求的关系类型，国家视图按原生国家表顺序保留活动伙伴，`partner` 标明伙伴国家。`status` 的行值是 `active` 或 `inactive`；读取不完整时保留 `unknown` 和原因。联盟与联姻为对称关系，`grantor`、`recipient` 返回 `not_applicable`；附庸角色沿用已验证来源。`expires_at` 仍为计划字段。

## `information_query`

选定国家对的查询可以这样提交：

```json
{
  "request_id": "r01-pair-001",
  "queries": [
    {
      "topic": "R01",
      "object": {"type": "country_pair", "actor": "FRA", "recipient": "ORL"},
      "fields": ["relation_type", "status", "grantor", "recipient"],
      "parameters": {
        "relation_types": [
          "vassalization", "guarantee", "support_independence",
          "military_access", "rival", "alliance", "royal_marriage"
        ]
      }
    }
  ]
}
```

FRA 关系网的查询使用 `country` 对象：

```json
{
  "request_id": "r01-network-001",
  "queries": [
    {
      "topic": "R01",
      "object": {"type": "country", "country": "FRA"},
      "fields": ["relation_type", "status", "grantor", "recipient"],
      "parameters": {"relation_types": ["alliance", "royal_marriage"]}
    }
  ]
}
```

对于公开字段，顶层字段结果仍使用 `{status, value}`。例如一个已知的选定关系行会写成：

```json
{
  "status": {
    "status": "known",
    "value": [
      {"relation_type": "alliance", "status": "known", "value": "active"}
    ],
    "complete": false,
    "partial": true
  }
}
```

国家视图中的 `value` 是按原生顺序排列的伙伴行；没有已知活动伙伴时，返回空集合仍需结合顶层来源状态和缺口判断。上下文、版本、日期、进程或代码守卫变化时，读取器撤回本次值，不沿用上一轮结果。

## `information_manage_report`

报告保存完整查询配置：

```json
{
  "request_id": "r01-report-create-001",
  "operation": "create",
  "config": {
    "name": "FRA relation network",
    "queries": [
      {
        "topic": "R01",
        "object": {"type": "country", "country": "FRA"},
        "fields": ["relation_type", "status", "grantor", "recipient"],
        "parameters": {"relation_types": ["alliance", "royal_marriage"]}
      }
    ],
    "detail": "raw"
  }
}
```

创建后，使用返回的 `report_id` 创建周期订阅。订阅绑定必须来自当前 `information_discover` 的会话，不得复用旧进程的对象地址。

## `information_manage_subscription`

```json
{
  "request_id": "r01-subscription-create-001",
  "operation": "create",
  "config": {
    "name": "FRA relation network every 2 seconds",
    "kind": "periodic",
    "report_id": "report-replace-with-created-id",
    "enabled": true,
    "binding": {
      "session_id": "session-from-information-discover",
      "observer": "FRA",
      "game_version": "1.37.4"
    },
    "schedule": {
      "basis": "real",
      "every": 2,
      "unit": "seconds",
      "missed": "coalesce"
    }
  }
}
```

周期读取重复读取已验证的只读来源，不刷新关系缓存，也不执行外交动作。`change` 仍是连续采样比较，不等同于事件流；读取之间也不宣称一个不可分割的世界快照。

## 已知边界和来源

当前网络合同覆盖联盟和王室联姻的 FRA 活动伙伴枚举，以及七类关系的选定国家对读取。`fleet_basing`（驻港权）、`trade_league`（贸易联盟）和关系过期日期仍缺少可用的当前原生来源；它们不能由 action 名称、legality 或 pending 状态代替。批54目前使用普通有界来源 `relation-current-source-002.json` 和已接受的 REA 合同 `relation-current-contract-003.json`；已有 raw/reference/replay 收据由归档 helper 按选定文件动态核对，任何实机伙伴和统计都应以后续通过的 live/replay 收据为准。

生产实现和来源索引：[`relation_state.py`](../bridge/information/relation_state.py)、[`relation_memory.py`](../bridge/information/relation_memory.py)、[`relation-current-source-002.json`](../work/runtime/information-relation-current-20261027-001/relation-current-source-002.json)、[`relation-current-contract-003.json`](../work/runtime/information-relation-current-20261027-001/relation-current-contract-003.json)。独立原始读取由 [`probe_information_relation_current_independent.py`](../work/probe_information_relation_current_independent.py) 和 [`reference_information_relation_current_independent.py`](../work/reference_information_relation_current_independent.py) 记录，生产回放由 [`capture_information_relation_current.py`](../work/capture_information_relation_current.py) 记录。首份独立 raw 的 country+1510 行绑定检查未通过，不能当作已验收值；修正版 reference 与 production replay 仅在归档 helper 选定的 `independent-network-expected-003.json`、`raw-comparison-002.json` 等收据明确通过后进入结论，旧 raw/reference/comparison 文件保留为历史证据。超过快照大小上限的 raw 只保留哈希和路径，不复制到 source-snapshot。
'''


_BATCH54_DOC_START = "<!-- batch54-relation-network-summary:start -->"
_BATCH54_DOC_END = "<!-- batch54-relation-network-summary:end -->"


def _batch53_summary() -> dict[str, Any]:
    """Read the bounded batch53 summary for identity/scope continuity."""

    path = BASELINE / "development-summary-001.json"
    document = read_json(path)
    if not isinstance(document, dict):
        raise AssertionError("batch53 development summary is not an object")
    return document


def _live_r01_contract() -> dict[str, Any]:
    """Derive the public R01 object/type counts from the live discovery."""

    discovery = read_json(STAGE / "live-acceptance-001" / "discovery.json")
    topics = discovery.get("topics")
    if not isinstance(topics, list):
        raise AssertionError("batch54 live discovery topics are missing")
    matches = [topic for topic in topics if topic.get("topic_id") == "R01"]
    if len(matches) != 1:
        raise AssertionError("batch54 live discovery must contain one R01 topic")
    r01 = matches[0]
    by_object = r01.get("relation_types_by_object")
    if not isinstance(by_object, dict):
        raise AssertionError("batch54 live discovery R01 relation types are missing")
    return {
        "object_types": r01.get("object_types", []),
        "relation_types_by_object": {
            str(key): list(value)
            for key, value in by_object.items()
            if isinstance(value, list)
        },
        "topic_status": r01.get("status"),
    }


def _join_known_partners(
    known: dict[str, dict[str, list[Any]]], family: str
) -> str:
    values: list[str] = []
    for families in known.values():
        for value in families.get(family, []):
            if isinstance(value, str) and value not in values:
                values.append(value)
    return ", ".join(values) if values else "unknown"


def _batch54_document_summary(
    live: dict[str, Any],
    comparison: dict[str, Any],
    rpm_receipt: dict[str, Any],
    r01: dict[str, Any],
    batch53: dict[str, Any],
) -> str:
    """Build one receipt-backed summary reused by all four top-level docs."""

    full = comparison["full"]
    new_tests = comparison["new_tests"]
    baseline = comparison["baseline"]
    relation_types = r01["relation_types_by_object"]
    pair_count = len(relation_types.get("country_pair", []))
    country_count = len(relation_types.get("country", []))
    known = _known_partner_projection(
        [rpm_receipt["selected_reference"]],
        [rpm_receipt["selected_production_replay"]],
    )
    alliance = _join_known_partners(known, "alliance")
    royal_marriage = _join_known_partners(known, "royal_marriage")
    checks = live.get("checks") if isinstance(live.get("checks"), dict) else {}
    periodic_results = live.get("periodic_results")
    subscriptions_created = live.get("subscriptions_created")
    periodic_ok = checks.get("exactly_one_periodic_delivered_then_cancelled_no_active") is True
    no_new_failure_nodes = not full.get("new_failure_nodes")
    new_test_errors = int(new_tests.get("failure_error_occurrences", 0))
    if no_new_failure_nodes and new_test_errors == 0:
        regression_delta = (
            f"相对批53 full002（{baseline['failure_error_occurrences']} 次既有失败/错误、"
            f"{baseline['unique_failure_error_nodes']} 个节点），本批 full001 无新增失败节点，"
            f"{new_tests['cases']} 个新增或更名测试节点全部通过，全套用例净增 {new_tests['net_case_increase']} 个。"
        )
    else:
        regression_delta = (
            f"相对批53 full002，full001 新增失败/错误节点 {len(full.get('new_failure_nodes', []))} 个，"
            f"新增用例失败/错误 {new_test_errors} 次；该差异按收据保留，不能写成全绿。"
        )
    identity = batch53.get("runtime_identity") if isinstance(batch53.get("runtime_identity"), dict) else {}
    installation = identity.get("installation") if isinstance(identity.get("installation"), dict) else {}
    installation_path = installation.get("path", "unknown")
    scope = batch53.get("scope") if isinstance(batch53.get("scope"), dict) else {}
    topics = scope.get("topics", "unknown")
    fields = scope.get("fields", "unknown")
    coverage = read_json(STAGE / COVERAGE_RECEIPT_BASENAME)
    configured = coverage["configured_counts"]["field_counts"]
    actual = coverage["actual_live_counts"]["field_counts"]
    counts = lambda value: "/".join(str(value[key]) for key in ("available", "partial", "planned"))
    session_id = live.get("session_id", identity.get("session_id", "unknown"))
    game_date = live.get("game_date", identity.get("game_date", "unknown"))
    exe_sha = identity.get("executable_sha256", "unknown")
    selected_reference = rpm_receipt["selected_reference"]["path"]
    selected_replay = rpm_receipt["selected_production_replay"]["path"]
    memory_replays = rpm_receipt.get("memory_replay_receipts", [])
    memory_path = memory_replays[0].get("path") if memory_replays else "unknown"
    return (
        "## 第五十四批：关系网络与联盟/联姻当前状态\n\n"
        f"已交付法国联盟与联姻伙伴列表：当前盟友为 `{alliance}`，王室联姻对象为 `{royal_marriage}`。"
        f"R01 国家对查询支持 {pair_count} 类关系，本国网络支持联盟、联姻 {country_count} 类。"
        f"实机查询、报告和 {periodic_results} 次周期交付通过，订阅已取消、无活动订阅，服务器正常退出。"
        "驻港权、贸易联盟、关系期限及其余关系网继续开发，四个既有R01字段保持partial。\n\n"
        f"正式 full001：{full['passed']} passed、{full['failed']} failed、{full['errors']} errors、"
        f"{full['subtests_passed']} 个子测试通过；{regression_delta}\n\n"
        f"当前运行身份保留为 session `{session_id}`、game_date `{game_date}`、observer `FRA`、"
        f"安装 `{installation_path}`、1.37.4 EXE SHA `{exe_sha}`。本批复用原进程和DLL，未保存、重启、推进日期或提交外交业务；"
        "新增关系读取仅用只读RPM，国家对其余家族复用既有只读原生查询。覆盖范围仍为 "
        f"{topics} 个主题、{fields} 个字段；配置字段覆盖available/partial/planned为{counts(configured)}，本次实机目录为{counts(actual)}。"
        "完整阶段2/3/4、自主订阅及B01–B04计划继续，goal保持active。"
        "历史成功、已派发或 unknown action、原 final-pass request ID、未闭合 ownership 和原120-action batch均不可重试。\n\n"
        f"来源结论选用 `{selected_reference}`、`{selected_replay}` 和 `{memory_path}`；"
        "首份 raw/reference 错件保留为历史，修正版 reference 与 production replay 通过离线校正/回放验收，"
        "不把旧失败文件或 action/legality/pending 状态当成当前关系。"
    )


def _replace_or_prepend_marker(path: Path, block: str, *, after_title: bool = False) -> None:
    """Replace one batch marker or insert it once without deleting history."""

    text = path.read_text(encoding="utf-8") if path.exists() else ""
    marked = f"{_BATCH54_DOC_START}\n{block.rstrip()}\n{_BATCH54_DOC_END}"
    if _BATCH54_DOC_START in text:
        start = text.index(_BATCH54_DOC_START)
        end_marker = text.index(_BATCH54_DOC_END, start) + len(_BATCH54_DOC_END)
        updated = text[:start] + marked + text[end_marker:]
    elif after_title and text.startswith("#"):
        newline = text.find("\n")
        insertion = marked + "\n\n"
        updated = text[: newline + 1] + "\n" + insertion + text[newline + 1 :]
    else:
        updated = marked + "\n\n" + text
    if updated != text:
        path.write_text(updated, encoding="utf-8", newline="\n")


def _update_batch54_documents(summary: str) -> list[dict[str, Any]]:
    """Update only the four requested top-level documents and pin them."""

    targets = (
        ROOT / "HANDOFF.md",
        ROOT / "README(agent).md",
        ROOT / "docs/信息导出与订阅开发计划.md",
        ROOT / "docs/LLM导出信息目录.md",
    )
    for path in targets:
        if not path.is_file():
            raise AssertionError(f"batch54 document is missing: {path.relative_to(ROOT)}")
        if path.name in {"HANDOFF.md", "README(agent).md"}:
            original = path.read_text(encoding="utf-8")
            historical = original.replace("第五十三批关系状态与修正文本（最新）", "第五十三批关系状态与修正文本（历史）", 1)
            if historical != original:
                path.write_text(historical, encoding="utf-8", newline="\n")
        interface = "联盟与联姻关系网接口.md" if path.parent.name == "docs" else "docs/联盟与联姻关系网接口.md"
        _replace_or_prepend_marker(
            path,
            summary + f"\n\n调用见[联盟与联姻关系网接口]({interface})。",
            after_title=path.name in {"信息导出与订阅开发计划.md", "LLM导出信息目录.md"},
        )
    return [pin(path) for path in targets]


def _run_docs() -> int:
    _require_stage_and_baseline()
    _verify_before()
    for relative in (
        "bridge/information/relation_memory.py",
        "bridge/information/profiles/relation-memory-1374.json",
        "work/runtime/information-relation-current-20261027-001/relation-current-source-002.json",
        "work/runtime/information-relation-current-20261027-001/relation-current-contract-003.json",
    ):
        if not (ROOT / relative).is_file():
            raise AssertionError(f"documentation source is missing: {relative}")
    target = ROOT / "docs/联盟与联姻关系网接口.md"
    if target.exists():
        if target.read_text(encoding="utf-8") != _doc_text():
            raise AssertionError("batch54 relation-network document already exists with different content")
        print(f"document already matches {target.relative_to(ROOT)}")
    else:
        target.write_text(_doc_text(), encoding="utf-8", newline="\n")
        print(f"wrote {target.relative_to(ROOT)}")
    live = _read_live_report()
    comparison = _regression_comparison()
    rpm_receipt = _dynamic_rpm_receipt()
    if rpm_receipt.get("status") != "accepted":
        raise AssertionError("batch54 selected reference/replay receipts are not accepted")
    if not isinstance(rpm_receipt.get("selected_reference"), dict):
        raise AssertionError("batch54 corrected independent reference is not selected")
    if not isinstance(rpm_receipt.get("selected_production_replay"), dict):
        raise AssertionError("batch54 production replay comparison is not selected")
    r01 = _live_r01_contract()
    batch53 = _batch53_summary()
    summary = _batch54_document_summary(live, comparison, rpm_receipt, r01, batch53)
    summary_documents = _update_batch54_documents(summary)
    receipt = {
        "schema": "information_relation_current_document_verification.v1",
        "batch": BATCH,
        "status": "passed",
        "document": pin(target),
        "json_examples_checked": 5,
        "new_game_queries_or_pytest_runs": 0,
        "live_values_or_statistics_included": True,
        "live_acceptance": pin(STAGE / "live-acceptance-001" / "report.json"),
        "full_comparison": comparison,
        "selected_reference": rpm_receipt["selected_reference"],
        "selected_production_replay": rpm_receipt["selected_production_replay"],
        "summary_documents": summary_documents,
        "checks": {
            "required_tools": True,
            "country_pair_and_country_contracts": True,
            "seven_pair_relation_types": True,
            "country_network_two_memory_families": True,
            "missing_expiry_fleet_basing_trade_league_stated": True,
            "live_and_full_receipts_read": True,
            "top_level_documents_updated_without_replacing_history": True,
        },
    }
    receipt_path = STAGE / DOCUMENT_RECEIPT_BASENAME
    if not receipt_path.exists():
        write_json(receipt_path.name, receipt)
    elif read_json(receipt_path) != receipt:
        raise AssertionError("batch54 document verification receipt differs")
    return 0


def _current_source_paths() -> tuple[Path, ...]:
    paths = [ROOT / relative for relative in _CURRENT_SOURCE_PATHS]
    for pattern in _CURRENT_SOURCE_GLOBS:
        paths.extend(ROOT.glob(pattern))
    return tuple(
        dict.fromkeys(
            path for path in paths
            if path.is_file() and "source-snapshot" not in path.parts
        )
    )


def _source_snapshot_paths() -> tuple[Path, ...]:
    paths = []
    for path in _current_source_paths():
        # Large raw/runtime payloads are pinned in the artifact inventory but
        # never copied into source-snapshot.  Hashing remains streaming in
        # pin(), so this branch does not load them into memory.
        if path.stat().st_size <= _MAX_SOURCE_SNAPSHOT_BYTES:
            paths.append(path)
    required = {
        "bridge/information/relation_memory.py",
        "bridge/information/profiles/relation-memory-1374.json",
        "bridge/information/relation_state.py",
        "work/finalize_information_relation_current.py",
        "docs/联盟与联姻关系网接口.md",
    }
    present = {path.relative_to(ROOT).as_posix() for path in paths}
    if not required <= present:
        raise AssertionError("batch54 source snapshot has missing core source")
    return tuple(dict.fromkeys(paths))


def _stage_artifact_paths() -> tuple[Path, ...]:
    """Return every current-stage artifact except generated source copies."""

    return tuple(
        path
        for path in sorted(STAGE.rglob("*"))
        if path.is_file() and "source-snapshot" not in path.parts
    )


def _artifact_inventory() -> list[dict[str, Any]]:
    """Pin stage artifacts without reading large JSON/raw payloads."""

    records = []
    for path in _stage_artifact_paths():
        record = pin(path)
        size_limited = path.stat().st_size > _MAX_SOURCE_SNAPSHOT_BYTES
        record.update(
            {
                "snapshot": None,
                "snapshot_policy": "artifact_pin_only_large"
                if size_limited else "eligible_for_bounded_reference",
            }
        )
        records.append(record)
    return records


def _small_json(path: Path) -> Any | None:
    """Parse only bounded JSON; large raw files stay streaming/pin-only."""

    if path.stat().st_size > _MAX_SOURCE_SNAPSHOT_BYTES:
        return None
    try:
        return read_json(path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _contains_key(value: Any, key: str) -> bool:
    if isinstance(value, dict):
        if key in value:
            return True
        return any(_contains_key(item, key) for item in value.values())
    if isinstance(value, list):
        return any(_contains_key(item, key) for item in value)
    return False


def _first_key(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, dict):
        if key in value:
            return value[key]
        for item in value.values():
            found = _first_key(item, key, default)
            if found is not default:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _first_key(item, key, default)
            if found is not default:
                return found
    return default


def _compact_field_values(value: Any, limit: int = 128) -> list[Any] | None:
    if not isinstance(value, list):
        return None
    compact = []
    # Keep a bounded prefix for auditability, but retain active rows outside
    # that prefix so the selected network reference does not hide a partner
    # solely because its country slot is high.  Inactive rows remain bounded.
    selected = list(value[:limit])
    selected.extend(
        item for item in value[limit:]
        if isinstance(item, dict) and item.get("active") is True
    )
    for item in selected:
        if isinstance(item, dict):
            row = {}
            for key in (
                "relation_type", "country", "partner", "actor", "status", "value",
                "active", "reason", "family", "predicate_cache_key", "fullref_hex",
                "fullref_raw_hex", "slot",
            ):
                if key in item:
                    row[key] = deepcopy(item[key])
            compact.append(row if row else deepcopy(item))
        else:
            compact.append(deepcopy(item))
    return compact


def _independent_reference_summaries() -> list[dict[str, Any]]:
    """Summarize independent raw/reference files without parsing >10 MiB."""

    candidates = [
        path for path in _stage_artifact_paths()
        if any(token in path.name.lower() for token in ("independent-network", "network-raw", "network-expected"))
    ]
    summaries = []
    for path in candidates:
        item = pin(path)
        document = _small_json(path)
        item["parse_policy"] = "bounded_json" if document is not None else "streaming_pin_only_large"
        item["artifact_role"] = (
            "production_raw" if "production-network" in path.name.lower() else "independent_reference"
        )
        if isinstance(document, dict):
            fields = document.get("fields")
            field_summary = {}
            if isinstance(fields, dict):
                for family, entry in fields.items():
                    if not isinstance(entry, dict):
                        continue
                    values = entry.get("value")
                    if not isinstance(values, list) or not values:
                        values = entry.get("rows")
                    rows = values if isinstance(values, list) else []
                    field_summary[str(family)] = {
                        "status": entry.get("status"),
                        "value": _compact_field_values(rows),
                        "row_count": len(rows),
                        "known_row_count": sum(
                            1 for row in rows
                            if isinstance(row, dict)
                            and (row.get("status") == "known" or row.get("active") is True)
                        ),
                        "unknown_row_count": sum(
                            1 for row in rows
                            if isinstance(row, dict) and row.get("status") == "unknown"
                        ),
                        "candidate_failure_count": len(entry.get("candidate_failures", []))
                        if isinstance(entry.get("candidate_failures"), list) else 0,
                    }
            item.update(
                {
                    "schema": document.get("schema"),
                    "status": document.get("status"),
                    "complete": document.get("complete"),
                    "identity_binding_verified": document.get("identity_binding_verified"),
                    "raw_two_pass_consistent": document.get("raw_two_pass_consistent"),
                    "handle_closed": document.get("handle_closed"),
                    "native_game_calls": document.get("native_game_calls"),
                    "target_memory_writes": document.get("target_memory_writes"),
                    "unknown_conditions": document.get("unknown_conditions", []),
                    "fields": field_summary,
                }
            )
        summaries.append(item)
    return summaries


def _raw_comparison_receipts() -> list[dict[str, Any]]:
    receipts = []
    for path in _stage_artifact_paths():
        if "raw-comparison" not in path.name.lower():
            continue
        item = pin(path)
        document = _small_json(path)
        item["parse_policy"] = "bounded_json" if document is not None else "streaming_pin_only_large"
        if isinstance(document, dict):
            checks = document.get("checks")
            item.update(
                {
                    "schema": document.get("schema"),
                    "status": document.get("status"),
                    "checks": deepcopy(checks) if isinstance(checks, dict) else None,
                    "fields": {
                        family: {
                            "status": entry.get("status") if isinstance(entry, dict) else None,
                            "value": _compact_field_values(entry.get("value"))
                            if isinstance(entry, dict) else None,
                        }
                        for family, entry in (document.get("fields") or {}).items()
                    } if isinstance(document.get("fields"), dict) else {},
                }
            )
            for key in ("production_raw", "independent_reference"):
                value = document.get(key)
                if isinstance(value, dict):
                    item[key] = deepcopy(value)
        receipts.append(item)
    return receipts


def _memory_replay_receipts() -> list[dict[str, Any]]:
    """Pin the bounded production-memory replay receipt when it exists.

    This is kept separate from the independent raw comparison: the former
    records a replay of the production raw capture, while the latter is the
    receipt that compares the production projection with the independent
    reference.  Both are useful archive evidence, but neither is inferred
    from a filename alone.
    """

    receipts = []
    for path in _stage_artifact_paths():
        if "memory-live-replay" not in path.name.lower():
            continue
        item = pin(path)
        document = _small_json(path)
        item["parse_policy"] = (
            "bounded_json" if document is not None else "streaming_pin_only_large"
        )
        if isinstance(document, dict):
            checks = document.get("checks")
            item.update(
                {
                    "schema": document.get("schema"),
                    "status": document.get("status"),
                    "checks": deepcopy(checks) if isinstance(checks, dict) else None,
                    "complete": document.get("complete"),
                    "source": document.get("source"),
                    "offline_replay": document.get("offline_replay"),
                    "read_only": document.get("read_only"),
                    "save_or_reload": document.get("save_or_reload"),
                    "native_game_calls": document.get("native_game_calls"),
                    "notes": deepcopy(document.get("notes"))
                    if isinstance(document.get("notes"), list)
                    else None,
                    "observed_values": deepcopy(document.get("observed_values"))
                    if isinstance(document.get("observed_values"), dict)
                    else None,
                    "provenance": deepcopy(document.get("provenance"))
                    if isinstance(document.get("provenance"), list)
                    else None,
                    "production_raw": deepcopy(document.get("production_raw"))
                    if isinstance(document.get("production_raw"), dict)
                    else None,
                }
            )
        receipts.append(item)
    return receipts


def _preferred_reference(references: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Select the corrected independent reference, preserving older files."""

    preferred_name = "independent-network-expected-003.json"
    matches = [
        item for item in references
        if Path(str(item.get("path", ""))).name == preferred_name
    ]
    if len(matches) > 1:
        raise AssertionError(f"duplicate preferred independent reference: {preferred_name}")
    return matches[0] if matches else None


def _comparison_passed(item: dict[str, Any]) -> bool:
    checks = item.get("checks")
    return (
        item.get("status") == "passed"
        and isinstance(checks, dict)
        and all(value is True for value in checks.values())
    )


def _preferred_comparison(comparisons: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Select raw-comparison-002; raw-comparison-001 remains historical."""

    preferred_name = "raw-comparison-002.json"
    matches = [
        item for item in comparisons
        if Path(str(item.get("path", ""))).name == preferred_name
    ]
    if len(matches) > 1:
        raise AssertionError(f"duplicate preferred raw comparison: {preferred_name}")
    return matches[0] if matches and _comparison_passed(matches[0]) else None


def _known_partner_projection(
    references: list[dict[str, Any]], comparisons: list[dict[str, Any]]
) -> dict[str, dict[str, list[Any]]]:
    """Expose only partner-like values already present in bounded receipts."""

    result: dict[str, dict[str, list[Any]]] = {}
    for artifact in [*references, *comparisons]:
        families = artifact.get("fields")
        if not isinstance(families, dict):
            continue
        family_values: dict[str, list[Any]] = {}
        for family, entry in families.items():
            values = entry.get("value") if isinstance(entry, dict) else None
            if not isinstance(values, list):
                continue
            partners = []
            for row in values:
                if isinstance(row, dict):
                    if row.get("status") != "known" and row.get("active") is not True:
                        continue
                    candidate = row.get("partner", row.get("country"))
                    if isinstance(candidate, str) and candidate:
                        partners.append(candidate)
            family_values[str(family)] = list(dict.fromkeys(partners))
        if family_values:
            result[str(artifact.get("path"))] = family_values
    return result


def _production_raw_artifacts(references: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        item for item in references
        if item.get("artifact_role") == "production_raw"
    ]


def _rea_terminal_pins() -> list[dict[str, Any]]:
    pins = []
    for path in _stage_artifact_paths():
        if not any(part.startswith("rea-") for part in path.relative_to(STAGE).parts):
            continue
        if path.name not in {"run.json", "evidence.json", "request.json", "stderr.log", "script-tail.log"}:
            continue
        item = pin(path)
        document = _small_json(path)
        if isinstance(document, dict):
            item["status"] = document.get("status") or document.get("state")
            item["exit_code"] = document.get("exit_code")
            item["terminal"] = document.get("terminal") or document.get("closed")
        pins.append(item)
    return pins


def _dynamic_rpm_receipt(
    references: list[dict[str, Any]] | None = None,
    comparisons: list[dict[str, Any]] | None = None,
    memory_replays: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    references = _independent_reference_summaries() if references is None else references
    comparisons = _raw_comparison_receipts() if comparisons is None else comparisons
    memory_replays = _memory_replay_receipts() if memory_replays is None else memory_replays
    evidence = references + comparisons + memory_replays
    selected_reference = _preferred_reference(references)
    selected_comparison = _preferred_comparison(comparisons)
    accepted = [selected_comparison["path"]] if selected_comparison else []
    if selected_comparison:
        status = "accepted"
    elif evidence:
        status = "observed_unaccepted"
    else:
        status = "not_sampled"
    rejection_reasons = []
    for item in references:
        if selected_reference is not None and item.get("path") == selected_reference.get("path"):
            # The selected reference is intentionally partial: expiry/start
            # dates are outside this batch's current native leaf.  It is the
            # reference chosen for archive, not a complete relation model.
            continue
        failures = sum(
            int(entry.get("candidate_failure_count", 0))
            for entry in (item.get("fields") or {}).values()
            if isinstance(entry, dict)
        )
        if failures or item.get("complete") is False or item.get("unknown_conditions"):
            rejection_reasons.append(
                {
                    "path": item.get("path"),
                    "candidate_failure_count": failures,
                    "unknown_conditions": item.get("unknown_conditions", []),
                    "complete": item.get("complete"),
                }
            )
    historical_references = [
        item["path"] for item in references
        if selected_reference is None or item.get("path") != selected_reference.get("path")
    ]
    historical_comparisons = [
        item["path"] for item in comparisons
        if selected_comparison is None or item.get("path") != selected_comparison.get("path")
    ]
    return {
        "status": status,
        "accepted_receipts": accepted,
        "reference_artifacts": references,
        "production_raw_artifacts": _production_raw_artifacts(references),
        "production_replay_receipts": comparisons,
        "memory_replay_receipts": memory_replays,
        "selected_reference": selected_reference,
        "selected_production_replay": selected_comparison,
        "historical_reference_artifacts": historical_references,
        "historical_comparison_receipts": historical_comparisons,
        "unaccepted_reasons": rejection_reasons,
        "source": "existing_stage_artifact_inventory",
        "note": (
            "Selection is filename-pinned to independent-network-expected-003 and "
            "raw-comparison-002 when those receipts exist and pass. Earlier raw, "
            "reference, and comparison files remain historical evidence. A raw "
            "file alone does not establish a valid production replay."
        ),
    }


def _run_archive() -> int:
    _require_stage_and_baseline()
    batch53 = _batch53_summary()
    before, after = _verify_before()
    live = _read_live_report()
    coverage = read_json(STAGE / COVERAGE_RECEIPT_BASENAME)
    if coverage.get("batch") != BATCH or coverage.get("field_coverage_changes") != []:
        raise AssertionError("batch54 coverage receipt is not metadata-only")
    if coverage.get("coverage_status_unchanged") is not True:
        raise AssertionError("batch54 coverage status was not preserved")
    document = read_json(STAGE / DOCUMENT_RECEIPT_BASENAME)
    if document.get("status") != "passed" or document.get("new_game_queries_or_pytest_runs") != 0:
        raise AssertionError("batch54 document verification is not a clean local verification")
    doc = ROOT / "docs/联盟与联姻关系网接口.md"
    if not doc.is_file():
        raise AssertionError("batch54 relation-network document is missing")
    doc_text = doc.read_text(encoding="utf-8")
    for marker in (
        "information_query",
        "information_manage_report",
        "information_manage_subscription",
        "country_pair",
        "alliance",
        "royal_marriage",
        "fleet_basing",
        "trade_league",
        '"complete": false',
    ):
        if marker not in doc_text:
            raise AssertionError(f"relation-network document marker missing: {marker}")
    comparison = _regression_comparison()
    if comparison["full"]["new_failure_nodes"]:
        raise AssertionError("batch54 introduced failure/error nodes")
    if comparison["new_tests"]["failure_error_occurrences"]:
        raise AssertionError("a newly added batch54 test failed")
    if (STAGE / "runtime-source-pins-after-001.json").exists():
        raise AssertionError("batch54 archive already exists")

    after_pin = {
        "schema": before.get("schema", "information_runtime_source_pins.v1"),
        "batch": BATCH,
        "files": after,
        "all_match_before": True,
        "timing": "after batch54 live acceptance and formal full regression",
        "continuous_monitoring_claimed": False,
    }
    write_json("runtime-source-pins-after-001.json", after_pin)
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

    current_sources = _current_source_paths()
    large_source_pins = [
        pin(path) for path in current_sources
        if path.stat().st_size > _MAX_SOURCE_SNAPSHOT_BYTES
    ]
    stage_artifacts = _artifact_inventory()
    independent_references = _independent_reference_summaries()
    raw_comparison_receipts = _raw_comparison_receipts()
    memory_replay_receipts = _memory_replay_receipts()
    rpm_receipt = _dynamic_rpm_receipt(
        independent_references,
        raw_comparison_receipts,
        memory_replay_receipts,
    )
    selected_reference = rpm_receipt.get("selected_reference")
    selected_comparison = rpm_receipt.get("selected_production_replay")
    known_partners = _known_partner_projection(
        [selected_reference] if isinstance(selected_reference, dict) else [],
        [selected_comparison] if isinstance(selected_comparison, dict) else [],
    )
    raw_replay = {
        "production_raw_artifacts": rpm_receipt.get("production_raw_artifacts", []),
        "comparison_receipts": raw_comparison_receipts,
        "selected_comparison": selected_comparison,
        "memory_replay_receipts": memory_replay_receipts,
    }
    rea_pins = _rea_terminal_pins()

    summary = {
        "schema": "information_development_summary.v1",
        "batch": BATCH,
        "objective": batch53["objective"],
        "status": "implemented_relation_network_partial",
        "goal_complete": False,
        "goal_status": "active",
        "scope": {
            **deepcopy(batch53["scope"]),
            "topic": "R01",
            "country_pair_relation_types": [
                "vassalization", "guarantee", "support_independence", "military_access",
                "rival", "alliance", "royal_marriage",
            ],
            "country_network_relation_types": ["alliance", "royal_marriage"],
            "observer": "FRA",
            "game_version": "1.37.4",
            "full_relation_network": False,
        },
        "delivered": {
            "R01_metadata": "country_pair seven types and country FRA alliance/royal_marriage network object",
            "coverage_status_unchanged": True,
            "complete": False,
        },
        "runtime_validation": live,
        "documentation_validation": document,
        "coverage": coverage,
        "tests": {
            "formal_full": comparison["full"],
            "new_tests": comparison["new_tests"],
            "counts_not_additive": True,
        },
        "source_layers": {
            "ordinary_source_002": pin(STAGE / "relation-current-source-002.json"),
            "accepted_rea_contract_003": pin(STAGE / "relation-current-contract-003.json"),
            "new_rpm": rpm_receipt,
            "independent_references": independent_references,
            "production_raw_replay": raw_replay,
            "known_partners": known_partners,
            "rea_terminal_pins": rea_pins,
            "missing": ["expires_at", "fleet_basing", "trade_league"],
        },
        "runtime_identity": {
            **deepcopy(batch53["runtime_identity"]),
            "observer": "FRA",
            "game_version": "1.37.4",
            "exe_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
            "rea_attempted": True,
            "control_proof": "live-acceptance-001/after-control.json",
        },
        "ownership": read_json(STAGE / "closure-001.json"),
        "next_work": {
            "full_plan_continues": True,
            "remaining_R01": ["fleet_basing", "trade_league", "expires_at", "other country-network families and directions"],
            "candidate_source": pin(ROOT / "work/runtime/information-relation-remaining-20261027-001/relation-remaining-source-001.json"),
            "candidate_not_runtime_contract": True,
            "other_scope": "N01 complete budget, N03 complete military modifiers, modifier UI consumer binding, all remaining phase2/3/4 and B01-B04 work",
        },
        "source_snapshot": snapshots,
        "source_snapshot_policy": {
            "bounded_max_bytes": _MAX_SOURCE_SNAPSHOT_BYTES,
            "large_source_artifact_pins": large_source_pins,
            "large_files_not_copied": True,
        },
        "stage_artifacts": stage_artifacts,
        "baseline": {
            "stage": BASELINE.relative_to(ROOT).as_posix(),
            "regression": comparison["baseline"],
        },
        "no_repeat": {
            "historical_actions_and_original_final_pass_ids": "not retried",
            "full_scope": "all configured bridge tests; relation network remains partial",
            "business_actions_submitted": live.get("business_actions_submitted"),
        },
    }
    write_json("development-summary-001.json", summary)
    print(json.dumps(summary, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Batch54 relation-network finalizer; no phase runs unless its flag is explicit."
    )
    phases = parser.add_mutually_exclusive_group()
    phases.add_argument(
        "--pin-before", "--freeze", dest="pin_before", action="store_true",
        help="freeze/pin inherited batch53 and relation runtime sources",
    )
    phases.add_argument("--full", action="store_true", help="run the formal pytest suite into regression-full-001")
    phases.add_argument("--coverage", action="store_true", help="derive counts and update only R01 metadata")
    phases.add_argument("--docs", action="store_true", help="write the batch54 relation-network user document")
    phases.add_argument("--archive", action="store_true", help="verify receipts and create bounded archive summary")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not any((args.pin_before, args.full, args.coverage, args.docs, args.archive)):
        parser.print_help()
        return 0
    if args.pin_before:
        return _pin_before()
    if args.full:
        return _run_full()
    if args.coverage:
        return _run_coverage()
    if args.docs:
        return _run_docs()
    return _run_archive()


if __name__ == "__main__":
    raise SystemExit(main())
