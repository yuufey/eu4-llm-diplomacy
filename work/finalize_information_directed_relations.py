"""Batch 56 finalizer for the directed guarantee/military-access network.

The module is inert on import, on the default path, and for ``--help``.
Only ``--full`` may start pytest.  The other phases consume or create bounded
receipts after their explicit prerequisites are present.  Large raw/reference
artifacts are streamed for hashes and are never copied into source snapshots.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Reuse the already reviewed bounded XML/count helpers.  Importing the module
# has no phase side effects; its phases are called only through this file.
from work import finalize_information_relation_remaining as _batch55  # noqa: E402


STAGE = ROOT / "work/runtime/information-relation-network-remaining-20261027-001"
BASELINE = ROOT / "work/runtime/information-relation-remaining-20261027-001"
SECONDARY_REPLAY_STAGE = ROOT / "work/runtime/information-directed-relations-20261027-001"
LEGACY_NETWORK_STAGE = ROOT / "work/runtime/information-relation-remaining-20261027-001"
BATCH = 56
LIVE_DIRECTORY = "live-acceptance-002"
REGRESSION_BASENAME = "regression-full-001"
BASELINE_REGRESSION_BASENAME = "regression-full-001"
COVERAGE_RECEIPT_BASENAME = "coverage-update-001.json"
DOCUMENT_RECEIPT_BASENAME = "document-verification-001.json"
PRODUCTION_COMPARISON_BASENAME = "production-comparison-001.json"
CONTRACT_PATH = "work/runtime/information-relation-network-remaining-20261027-001/relation-network-contract-003.json"
CONTRACT_SHA256 = "26ce4537760fdf97bb5be7c660797e564f8bfc7a1205ad80ff04884e9ef6786c"
MAX_SOURCE_SNAPSHOT_BYTES = 10 * 1024 * 1024

COUNTRY_NETWORK_FAMILIES = (
    "alliance", "royal_marriage", "fleet_basing", "trade_league",
    "guarantee", "military_access",
)
PAIR_FAMILIES = (
    "vassalization", "guarantee", "support_independence", "military_access",
    "rival", "alliance", "royal_marriage", "fleet_basing", "trade_league",
)
R01_FIELDS = ("relation_type", "status", "grantor", "recipient")
R01_MARKER_START = "<!-- batch56-directed-relations-summary:start -->"
R01_MARKER_END = "<!-- batch56-directed-relations-summary:end -->"

_EXTENSION_RUNTIME_PATHS = (
    "bridge/information/directed_relation_memory.py",
    "bridge/information/profiles/directed-relations-memory-1374.json",
)
_EXPLICIT_SOURCE_PATHS = (
    *(_EXTENSION_RUNTIME_PATHS),
    "bridge/tests/test_information_directed_relation_memory.py",
    "work/validate_information_directed_relations_live.py",
    "work/capture_information_directed_relations_current.py",
    "work/probe_information_directed_relations_current.py",
    "work/reference_information_directed_relations_current.py",
    "work/finalize_information_directed_relations.py",
    "work/research-next/relation_next_network.py",
    "work/research-next/finalize_directed_relation_contract.py",
    CONTRACT_PATH,
    "work/runtime/information-relation-network-remaining-20261027-001/source-001.json",
    "work/runtime/information-relation-network-remaining-20261027-001/source-002.json",
    "work/runtime/information-relation-network-remaining-20261027-001/directed-relations-current-inputs-001.json",
    "work/runtime/information-relation-network-remaining-20261027-001/directed-relations-witness-candidates-001.json",
    "work/runtime/information-relation-network-remaining-20261027-001/expected-directed-relations-projection-001.json",
    "work/runtime/information-relation-network-remaining-20261027-001/probe-source-001.py",
    "work/runtime/information-relation-network-remaining-20261027-001/probe-source-recovery-001.json",
    "work/runtime/information-relation-network-remaining-20261027-001/directed-relations-witness-guarantee-inputs-001.json",
    "work/runtime/information-relation-network-remaining-20261027-001/directed-relations-witness-military-inputs-001.json",
    "work/runtime/information-relation-network-remaining-20261027-001/expected-directed-relations-witness-guarantee-001.json",
    "work/runtime/information-relation-network-remaining-20261027-001/expected-directed-relations-witness-military-001.json",
    "work/runtime/information-relation-network-remaining-20261027-001/role-binding-004.json",
    "work/runtime/information-relation-network-remaining-20261027-001/rea-reuse-audit-001.json",
    "docs/保证与军事访问关系网接口.md",
)
_SOURCE_GLOBS = (
    "bridge/tests/test_information_directed_relation*.py",
    "bridge/tests/test_information_*directed*relation*.py",
    "bridge/tests/fixtures/information_directed_relation*.json",
    "bridge/tests/fixtures/information_directed_relation*.json.gz",
    "bridge/tests/fixtures/*directed*relation*.json",
    "bridge/tests/fixtures/*directed*relation*.json.gz",
    "work/validate_information_directed_relation*.py",
    "work/capture_information_directed_relation*.py",
    "work/probe_information_directed_relation*.py",
    "work/reference_information_directed_relation*.py",
    "work/research-next/*directed*relation*.py",
    "work/runtime/information-directed-relations-20261027-001/*directed-relation*.json",
    "work/runtime/information-directed-relations-20261027-001/*directed-relation*.json.gz",
    "work/runtime/information-directed-relations-20261027-001/replay_*.py",
    "work/runtime/information-directed-relations-20261027-001/*capture*.py",
    "work/runtime/information-directed-relations-20261027-001/*live*.py",
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


def _contract_pin() -> dict[str, Any]:
    item = pin(ROOT / CONTRACT_PATH)
    if item["sha256"] != CONTRACT_SHA256:
        raise AssertionError(
            f"directed relation contract SHA mismatch: {item['sha256']} != {CONTRACT_SHA256}"
        )
    return item


def read_json(path: Path, *, max_bytes: int = 8 * 1024 * 1024) -> Any:
    if not path.is_file():
        raise AssertionError(f"required file is missing: {path.relative_to(ROOT)}")
    if path.stat().st_size > max_bytes:
        raise AssertionError(f"bounded JSON read refused: {path.relative_to(ROOT)}")
    return json.loads(path.read_bytes())


def write_json(name: str, value: Any) -> Path:
    STAGE.mkdir(parents=True, exist_ok=True)
    target = STAGE / name
    if target.exists():
        raise AssertionError(f"batch56 receipt already exists: {target.relative_to(ROOT)}")
    with target.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return target


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".batch56.tmp")
    if temporary.exists():
        raise AssertionError(f"temporary output already exists: {temporary}")
    with temporary.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
    os.replace(temporary, path)


def _require_stage_and_baseline() -> None:
    if not STAGE.is_dir():
        raise AssertionError(f"batch56 stage is missing: {STAGE}")
    if not BASELINE.is_dir():
        raise AssertionError(f"batch55 baseline stage is missing: {BASELINE}")


def _runtime_paths() -> tuple[str, ...]:
    return tuple(dict.fromkeys(_batch55.runtime_paths() + _EXTENSION_RUNTIME_PATHS))


def _current_source_paths() -> tuple[Path, ...]:
    paths = [ROOT / relative for relative in _EXPLICIT_SOURCE_PATHS]
    for pattern in _SOURCE_GLOBS:
        paths.extend(ROOT.glob(pattern))
    return tuple(dict.fromkeys(
        path for path in paths
        if path.is_file() and "source-snapshot" not in path.parts
    ))


def _require_runtime_files() -> tuple[str, ...]:
    paths = _runtime_paths()
    missing = [relative for relative in paths if not (ROOT / relative).is_file()]
    if missing:
        raise AssertionError("runtime source missing: " + ", ".join(missing))
    return paths


def _pin_before() -> int:
    _require_stage_and_baseline()
    before_path = STAGE / "runtime-source-pins-before-001.json"
    matrix_snapshot = STAGE / "coverage-matrix-before-001.json"
    if before_path.exists() or matrix_snapshot.exists():
        raise AssertionError("batch56 before pins or coverage snapshot already exists")
    paths = _require_runtime_files()
    matrix = ROOT / "docs/信息字段覆盖.json"
    if not matrix.is_file():
        raise AssertionError("coverage matrix is missing")
    baseline_after = BASELINE / "runtime-source-pins-after-001.json"
    if not baseline_after.is_file():
        raise AssertionError("batch55 after-pin receipt is missing")
    with matrix_snapshot.open("xb") as stream, matrix.open("rb") as source:
        shutil.copyfileobj(source, stream)
    write_json(
        before_path.name,
        {
            "schema": "information_runtime_source_pins.v1",
            "batch": BATCH,
            "baseline_stage": BASELINE.relative_to(ROOT).as_posix(),
            "baseline_after_pin": pin(baseline_after),
            "timing": "before batch56 live acceptance and formal full regression",
            "continuous_monitoring_claimed": False,
            "inherited_batch55_runtime_paths": len(_batch55.runtime_paths()),
            "extension_runtime_paths": list(_EXTENSION_RUNTIME_PATHS),
            "files": [pin(ROOT / relative) for relative in paths],
            "coverage_matrix_before": pin(matrix_snapshot),
        },
    )
    return 0


def _verify_before() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    before = read_json(STAGE / "runtime-source-pins-before-001.json")
    if before.get("batch") != BATCH:
        raise AssertionError("runtime source pin is not a batch56 pin")
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
        raise AssertionError("a frozen batch56 runtime source changed")
    matrix_snapshot = STAGE / "coverage-matrix-before-001.json"
    if not matrix_snapshot.is_file():
        raise AssertionError("coverage matrix snapshot is missing")
    return before, after


def _live_report(*, required: bool = True) -> dict[str, Any] | None:
    path = STAGE / LIVE_DIRECTORY / "report.json"
    if not path.is_file():
        if required:
            raise AssertionError("batch56 live acceptance report is missing")
        return None
    report = read_json(path)
    exit_code = report.get("server_exit_code", report.get("server_exit"))
    if report.get("status") != "passed" or exit_code != 0:
        raise AssertionError("batch56 live acceptance is not passed/exit0")
    checks = report.get("checks")
    if isinstance(checks, dict) and not all(value is True for value in checks.values()):
        raise AssertionError("batch56 live acceptance contains a failed check")
    return report


def _production_comparison(*, required: bool = True) -> dict[str, Any] | None:
    path = STAGE / PRODUCTION_COMPARISON_BASENAME
    if not path.is_file():
        if required:
            raise AssertionError("batch56 production comparison receipt is missing")
        return None
    comparison = read_json(path)
    if comparison.get("status") != "passed":
        raise AssertionError("batch56 production comparison is not passed")
    return comparison


def _optional_json(path: Path) -> Any | None:
    """Read a small optional receipt without making it a phase prerequisite."""
    if not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
        return None
    return read_json(path)


def _relation_query_documents(live: Mapping[str, Any], production: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any]]]:
    documents: list[tuple[str, Mapping[str, Any]]] = []

    def add(label: str, value: Any) -> None:
        if isinstance(value, Mapping) and isinstance(value.get("items"), list):
            documents.append((label, value))

    for label, value in (
        ("live.query_result", live.get("query_result")),
        ("live.query", live.get("query")),
        ("live.result", live.get("result")),
        ("production.query_result", production.get("query_result")),
        ("production.query", production.get("query")),
    ):
        add(label, value)
    for path in (
        STAGE / LIVE_DIRECTORY / "query.json",
        STAGE / LIVE_DIRECTORY / "report-query.json",
        LEGACY_NETWORK_STAGE / "live-acceptance-002" / "query.json",
        LEGACY_NETWORK_STAGE / "live-acceptance-002" / "report-query.json",
    ):
        value = _optional_json(path)
        if value is not None:
            add(path.relative_to(ROOT).as_posix(), value)
    return documents


def _relation_snapshot(live: Mapping[str, Any], production: Mapping[str, Any]) -> dict[str, Any]:
    """Project concrete FRA network partners from passed live/production receipts.

    The secondary live-replay receipt is only a fallback for the two new
    directed families when the phase-specific query receipt is not present.
    It carries the closed raw observation and its zero-value checks; it never
    upgrades an absent or failed query to a known result.
    """
    families: dict[str, dict[str, Any]] = {
        family: {
            "known": False,
            "partners": [],
            "directions": {"granted": set(), "received": set()},
        }
        for family in COUNTRY_NETWORK_FAMILIES
    }
    sources: list[str] = []
    for source, document in _relation_query_documents(live, production):
        seen_in_document = False
        for item in document.get("items", []):
            if not isinstance(item, Mapping):
                continue
            query = item.get("query") if isinstance(item.get("query"), Mapping) else {}
            obj = query.get("object") if isinstance(query.get("object"), Mapping) else {}
            if obj.get("type") != "country" or obj.get("country") != "FRA":
                continue
            requested = query.get("parameters", {}).get("relation_types", [])
            if not isinstance(requested, list):
                requested = []
            for family in requested:
                if family in families:
                    families[family]["known"] = True
                    seen_in_document = True
            fields = item.get("fields") if isinstance(item.get("fields"), Mapping) else {}
            status_field = fields.get("status") if isinstance(fields.get("status"), Mapping) else {}
            rows = status_field.get("value") if isinstance(status_field.get("value"), list) else []
            for row in rows:
                if not isinstance(row, Mapping):
                    continue
                family = row.get("relation_type")
                partner = row.get("partner") or row.get("country")
                if family not in families or not isinstance(partner, str):
                    continue
                families[family]["known"] = True
                seen_in_document = True
                if row.get("status") == "known" and row.get("value") == "active":
                    if partner not in families[family]["partners"]:
                        families[family]["partners"].append(partner)
                    direction = row.get("direction")
                    if direction in families[family]["directions"]:
                        families[family]["directions"][direction].add(partner)
        if seen_in_document:
            sources.append(source)

    for replay_name in ("directed-relation-real-replay-001.json", "directed-relation-live-replay-001.json"):
        replay_path = SECONDARY_REPLAY_STAGE / replay_name
        replay = _optional_json(replay_path)
        if not isinstance(replay, Mapping) or replay.get("status") != "passed":
            continue
        observed = replay.get("observed") if isinstance(replay.get("observed"), Mapping) else {}
        checks = replay.get("checks") if isinstance(replay.get("checks"), Mapping) else {}
        network = observed.get("network") if isinstance(observed.get("network"), Mapping) else {}
        for family in ("guarantee", "military_access"):
            if family in network:
                value_count = network.get(f"{family}_value_count")
                known = value_count == 0
            else:
                status = checks.get(f"{family}_status")
                value_count = checks.get(f"{family}_value_count")
                unknown_count = checks.get(f"{family}_unknown_row_count")
                known = status == "known" and value_count == 0 and unknown_count == 0
            if known and not families[family]["known"]:
                families[family]["known"] = True
                sources.append(replay_path.relative_to(ROOT).as_posix())
        if all(families[family]["known"] for family in ("guarantee", "military_access")):
            break

    return {"families": families, "sources": list(dict.fromkeys(sources))}


def _relation_result_sentence(snapshot: Mapping[str, Any]) -> str:
    families = snapshot.get("families", {})

    def partners(family: str, label: str) -> str:
        item = families.get(family, {})
        if not item.get("known"):
            return f"{label}=unknown"
        values = list(item.get("partners", ()))
        return f"{label}伙伴={','.join(values) if values else '无'}"

    def directed(family: str, label: str) -> str:
        item = families.get(family, {})
        if not item.get("known"):
            return f"{label}双向=unknown"
        values = item.get("partners", set())
        directions = item.get("directions", {})
        if not values and not directions.get("granted") and not directions.get("received"):
            return f"{label} 双向均为空"
        granted = ",".join(sorted(directions.get("granted", ()))) or "无"
        received = ",".join(sorted(directions.get("received", ()))) or "无"
        return f"{label} granted={granted}, received={received}"

    return (
        "收据中的 FRA 当前结果为 "
        f"{directed('guarantee', 'guarantee')}；"
        f"{directed('military_access', 'military_access')}；"
        f"{partners('alliance', 'alliance')}；"
        f"{partners('royal_marriage', 'royal_marriage')}。"
    )


def _case_key(case: ET.Element) -> str:
    return f"{case.get('classname')}::{case.get('name')}"


def _regression_comparison() -> dict[str, Any]:
    xml = STAGE / f"{REGRESSION_BASENAME}.xml"
    log = STAGE / f"{REGRESSION_BASENAME}.log"
    baseline_xml = BASELINE / f"{BASELINE_REGRESSION_BASENAME}.xml"
    if not xml.is_file() or not log.is_file() or not baseline_xml.is_file():
        raise AssertionError("batch56 or batch55 formal regression receipt is missing")
    cases, bad, occurrences = _batch55._test_cases(xml)
    old_cases, old_bad, old_occurrences = _batch55._test_cases(baseline_xml)
    current_keys = {_case_key(case) for case in cases}
    old_keys = {_case_key(case) for case in old_cases}
    added = sorted(current_keys - old_keys)
    removed = sorted(old_keys - current_keys)
    current_bad = {_case_key(case) for case in cases if case.findall("failure") or case.findall("error")}
    line = _batch55._summary_line(log)
    added_set = set(added)
    added_bad = sum(
        len(case.findall("failure")) + len(case.findall("error"))
        for case in cases if _case_key(case) in added_set
    )
    return {
        "full": {
            "command": "python -m pytest -q bridge/tests",
            "passed": _batch55._count(line, "passed"),
            "failed": _batch55._count(line, "failed"),
            "errors": _batch55._count(line, "errors"),
            "subtests_passed": _batch55._count(line, "subtests passed"),
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
            "failure_error_occurrences": added_bad,
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
        raise AssertionError("batch56 formal regression receipts already exist")
    with log.open("x", encoding="utf-8", newline="\n") as stream:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "bridge/tests", "--junitxml", str(xml)],
            cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, check=False,
        )
    print(f"formal batch56 full regression exit {result.returncode}")
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
        "topic_count": len(topics),
        "field_count": field_count,
        "topic_status_counts": dict(sorted(topic_status.items())),
        "available_topic_count": topic_status.get("available", 0),
        "callable_topic_count": topic_status.get("available", 0),
        "field_counts": dict(sorted(field_counts.items())),
    }


def _catalog_r01() -> dict[str, Any]:
    # This import is deliberately inside the explicit coverage phase.  The
    # default/help path therefore does not import or instantiate production
    # sources, and cannot accidentally open a reader.
    from bridge.information.composite import CompositeSource
    from bridge.information.country_records import NativeCountryRecordsSource
    from bridge.information.country_state import NativeCountryStateSource
    from bridge.information.relation_state import NativeRelationSource
    from bridge.information.sources import DiplomacySource

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
    expected = {"country_pair": set(PAIR_FAMILIES), "country": set(COUNTRY_NETWORK_FAMILIES)}
    if actual != expected:
        raise AssertionError(f"R01 catalog family metadata mismatch: {actual}")
    schema = entry.get("parameters", {}).get("properties", {}).get("relation_types", {})
    if schema.get("maxItems") != len(PAIR_FAMILIES):
        raise AssertionError("R01 catalog relation_types maxItems is not nine")
    return entry


def _merge_r01_metadata(matrix: dict[str, Any], r01: dict[str, Any]) -> dict[str, Any]:
    merged = _batch55._batch54._merge_only_r01_metadata(matrix, r01)
    topic = next(item for item in merged["topics"] if item.get("topic_id") == "R01")
    fields = topic.get("fields", {})
    for field in R01_FIELDS:
        descriptor = fields.get(field, {})
        if descriptor.get("coverage") != "partial" or descriptor.get("complete") is not False:
            raise AssertionError(f"R01 field coverage changed for {field}")
    if fields.get("expires_at", {}).get("coverage") != "planned":
        raise AssertionError("R01 expires_at coverage changed")
    return merged


def _coverage() -> int:
    _require_stage_and_baseline()
    _verify_before()
    _live_report(required=True)
    before_path = STAGE / "coverage-matrix-before-001.json"
    matrix_path = ROOT / "docs/信息字段覆盖.json"
    discovery_path = STAGE / LIVE_DIRECTORY / "discovery.json"
    baseline_discovery = next(
        (BASELINE / name / "discovery.json" for name in ("live-acceptance-002", "live-acceptance-001")
         if (BASELINE / name / "discovery.json").is_file()),
        None,
    )
    if not before_path.is_file() or not matrix_path.is_file() or not discovery_path.is_file():
        raise AssertionError("batch56 coverage inputs are missing")
    if baseline_discovery is None:
        raise AssertionError("batch55 discovery receipt is missing")
    before = read_json(before_path)
    current = read_json(matrix_path)
    changes = _batch55._topic_metadata_changes(before, current)
    if any(not value.startswith("R01.") for value in changes):
        raise AssertionError("coverage matrix changed outside R01 metadata")
    merged = _merge_r01_metadata(before, _catalog_r01())
    metadata_changes = _batch55._topic_metadata_changes(before, merged)
    if not metadata_changes:
        raise AssertionError("R01 metadata did not change to the six/nine contract")
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
    _atomic_write_text(matrix_path, json.dumps(merged, ensure_ascii=False, indent=2) + "\n")
    receipt = {
        "schema": "information_directed_relation_coverage_update.v1",
        "batch": BATCH,
        "goal_complete": False,
        "goal_status": "active",
        "before_sha256": sha(before_path),
        "after_sha256": sha(matrix_path),
        "configured_counts": after_counts,
        "actual_live_counts": actual,
        "baseline_batch55_actual_live_counts": baseline_actual,
        "scope_counts_fixed": {"topics": 74, "fields": 397},
        "metadata_changes": metadata_changes,
        "field_coverage_changes": [],
        "coverage_status_unchanged": True,
        "r01_metadata": {
            "object_types": merged["R01"].get("object_types"),
            "relation_types_by_object": merged["R01"].get("relation_types_by_object"),
            "pair_relation_type_count": len(PAIR_FAMILIES),
            "country_network_family_count": len(COUNTRY_NETWORK_FAMILIES),
            "default_pair_row_count": 10,
        },
        "source": {"catalog": "production CompositeSource catalog", "contract": _contract_pin()},
        "matrix_sha256_before_write": matrix_before_sha,
        "note": "Batch56 changes R01 object/family metadata only; four public fields remain partial and expires_at remains planned.",
    }
    write_json(COVERAGE_RECEIPT_BASENAME, receipt)
    print(json.dumps(receipt, ensure_ascii=False))
    return 0


def _format_counts(counts: dict[str, Any]) -> str:
    values = counts.get("field_counts", {}) if isinstance(counts, dict) else {}
    return "/".join(str(values.get(key, 0)) for key in ("available", "partial", "planned"))


def _summary_text(live: dict[str, Any], comparison: dict[str, Any], coverage: dict[str, Any], production: dict[str, Any]) -> str:
    full = comparison["full"]
    baseline = comparison["baseline"]
    periodic = live.get("periodic_results", [])
    periodic_count = len(periodic) if isinstance(periodic, list) else periodic
    identity = live.get("identity") if isinstance(live.get("identity"), dict) else {}
    session = live.get("session_id") or identity.get("session_id") or identity.get("installation_session_id") or "unknown"
    game_date = live.get("game_date", identity.get("game_date", "unknown"))
    observer = live.get("observer") or identity.get("observer") or "FRA"
    relations = _relation_result_sentence(_relation_snapshot(live, production))
    return (
        "## 第五十六批：保证与军事访问关系网\n\n"
        f"R01 国家网络合同覆盖 {len(COUNTRY_NETWORK_FAMILIES)} 类关系，国家对合同保留 {len(PAIR_FAMILIES)} 类；"
        "默认国家对结果为10行（驻港权占两行，其余八类各占一行），四个公开字段继续 partial、complete=false，expires_at 保持 planned。"
        f"生产比较收据 status={production.get('status')}；实机收据 status={live.get('status')}，周期结果 {periodic_count} 次。"
        f"{relations}\n\n"
        f"正式 full001：{full['passed']} passed、{full['failed']} failed、{full['errors']} errors、"
        f"{full['subtests_passed']} 个子测试通过；相对批55基线既有失败/错误为 {baseline['failure_error_occurrences']} 次、"
        f"{baseline['unique_failure_error_nodes']} 个节点，当前为 {full['failure_error_occurrences']} 次、"
        f"{full['unique_failure_error_nodes']} 个节点；新增失败节点 {len(full['new_failure_nodes'])} 个，"
        f"解决节点 {len(full['resolved_failure_nodes'])} 个；新增或更名测试 {comparison['new_or_renamed_tests']['cases']} 个，"
        f"净增 {comparison['net_case_delta']} 个。\n\n"
        f"覆盖范围保持74个主题、397个字段；配置 available/partial/planned={_format_counts(coverage['configured_counts'])}，"
        f"live discovery={_format_counts(coverage['actual_live_counts'])}。完整阶段2/3/4、LLM自主订阅和 B01–B04 范围继续，"
        "完整计划继续，goal保持 active；"
        "历史成功、已派发、unknown action、原 final-pass request ID、未闭合 ownership 和原120-action batch不重试。\n\n"
        f"运行身份为 session `{session}`、game_date `{game_date}`、observer `{observer}`；"
        f"live receipt 的 read_only={live.get('read_only', 'unknown')}、"
        f"business_actions_submitted={live.get('business_actions_submitted', 'unknown')}。"
        "本批不保存、不重启、不推进日期，不提交外交业务。"
    )


def _replace_marker(path: Path, block: str) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    marked = f"{R01_MARKER_START}\n{block.rstrip()}\n{R01_MARKER_END}"
    if R01_MARKER_START in text:
        start = text.index(R01_MARKER_START)
        end = text.index(R01_MARKER_END, start) + len(R01_MARKER_END)
        updated = text[:start] + marked + text[end:]
    else:
        updated = marked + "\n\n" + text
    if updated != text:
        _atomic_write_text(path, updated)
    return pin(path)


def _update_summary_documents(summary: str) -> list[dict[str, Any]]:
    targets = (
        ROOT / "HANDOFF.md", ROOT / "README(agent).md",
        ROOT / "docs/信息导出与订阅开发计划.md", ROOT / "docs/LLM导出信息目录.md",
    )
    result = []
    for path in targets:
        if not path.is_file():
            raise AssertionError(f"batch56 document is missing: {path.relative_to(ROOT)}")
        link = ("\n\n调用见[保证与军事访问关系网接口](docs/保证与军事访问关系网接口.md)。"
                if path.parent == ROOT else
                "\n\n调用见[保证与军事访问关系网接口](保证与军事访问关系网接口.md)。")
        result.append(_replace_marker(path, summary + link))
    return result


def _doc_text(live: dict[str, Any], comparison: dict[str, Any], coverage: dict[str, Any], production: dict[str, Any]) -> str:
    full = comparison["full"]
    periodic = live.get("periodic_results", [])
    periodic_count = len(periodic) if isinstance(periodic, list) else periodic
    identity = live.get("identity") if isinstance(live.get("identity"), dict) else {}
    session = live.get("session_id") or identity.get("session_id") or identity.get("installation_session_id") or "unknown"
    game_date = live.get("game_date", identity.get("game_date", "unknown"))
    observer = live.get("observer") or identity.get("observer") or "FRA"
    relations = _relation_result_sentence(_relation_snapshot(live, production))
    return f'''# 保证与军事访问关系网接口

R01 现在可以查询法国的联盟、王室联姻、驻港权、贸易联盟、保证独立和军事通行权六类当前关系。新增的保证和军事通行权会分别列出法国给予其他国家、其他国家给予法国的关系。主动查询、保存的报告和周期订阅共用这一接口。

{relations}这些结果已通过实际查询、报告和 {periodic_count} 次周期交付验证；订阅已取消。

本接口的四个公开字段 `relation_type`、`status`、`grantor`、`recipient` 仍为 `coverage: "partial"`、`complete: false`。`expires_at` 尚未实现，不能从关系存在与否推导到期日期。

## 查询对象和字段

`country_pair` 的 `actor` 必须是观察国 `FRA`，`recipient` 必须是另一个国家标签。省略 `relation_types` 时请求九类关系；指定时提交1至9个不重复枚举值。默认结果为10行：驻港权占两行，其余八类各占一行；保证独立和军事通行权在国家对查询中各保持单行。

`country` 的 `country` 必须是 `FRA`。省略 `relation_types` 时请求六类国家网络关系；驻港权、保证独立和军事通行权按两个方向分别投影，其余三类按各自原生国家容器投影。国家列表只在完整原生扫描和上下文守卫通过后公开。未读完整、代码守卫失败、前后上下文不一致或方向尚未证明时返回 `unknown`，不把缺失数据当作 inactive。

`country_pair` 的旧 guarantee 有效性只证明双方存在任一方向的保证关联，不能由该布尔值填写 `grantor`/`recipient`。国家网络的 guarantee 方向要对原生关系记录 `+0x18` 和目标引用中的国家槽位做有符号16位比较后才公开；这一步不比较标签或引用代际。军事通行权表示显式外交 access 关系，不等于战争、属国或其他条件下的实际军队移动权限。

## `information_query`

```json
{{
  "request_id": "r01-directed-pair-001",
  "queries": [{{
    "topic": "R01",
    "object": {{"type": "country_pair", "actor": "FRA", "recipient": "ORL"}},
    "fields": ["relation_type", "status", "grantor", "recipient"],
    "parameters": {{"relation_types": ["guarantee", "military_access"]}}
  }}]
}}
```

国家网络查询使用同一工具：

```json
{{
  "request_id": "r01-directed-network-001",
  "queries": [{{
    "topic": "R01",
    "object": {{"type": "country", "country": "FRA"}},
    "fields": ["relation_type", "status", "grantor", "recipient"],
    "parameters": {{"relation_types": ["alliance", "royal_marriage", "fleet_basing", "trade_league", "guarantee", "military_access"]}}
  }}]
}}
```

公开字段的结果使用 `{{"status": "known", "value": [...]}}` 结构；每一行保留 `relation_type` 和该关系的 `status`。`grantor`、`recipient` 只有在原生方向已证实后才填入端点；否则保留 `unknown` 或 `not_applicable`，不按 action 名称猜测。

## `information_manage_report`

报告保存与主动查询相同的 `queries`：

```json
{{
  "request_id": "r01-directed-report-create-001",
  "operation": "create",
  "config": {{
    "name": "FRA directed relations",
    "queries": [{{
      "topic": "R01",
      "object": {{"type": "country", "country": "FRA"}},
      "fields": ["relation_type", "status", "grantor", "recipient"],
      "parameters": {{"relation_types": ["guarantee", "military_access"]}}
    }}],
    "detail": "raw"
  }}
}}
```

## `information_manage_subscription`

```json
{{
  "request_id": "r01-directed-subscription-create-001",
  "operation": "create",
  "config": {{
    "name": "FRA directed relations every 2 seconds",
    "kind": "periodic",
    "report_id": "report-id-from-create",
    "enabled": true,
    "binding": {{
      "session_id": "session-id-from-information_discover",
      "observer": "FRA",
      "game_version": "1.37.4"
    }},
    "schedule": {{"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"}}
  }}
}}
```

订阅只重复只读采样；它不刷新关系、不执行保证或军事访问动作，也不把连续采样当作不可分割的世界快照。

## 来源和边界

当前静态合同固定于 EU4 1.37.4、EXE SHA `b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77`，合同文件为 [`relation-network-contract-003.json`](../work/runtime/information-relation-network-remaining-20261027-001/relation-network-contract-003.json)。保证当前关系谓词读取原生关系行的 owner 向量；军事通行权复用已审核的 owner 向量谓词。`role-binding-004.json` 证明保证方向使用记录 `+0x18` 与目标引用的有符号16位国家槽位比较；该步骤不检查完整标签或代际。军事通行权仅指显式外交 access。关系方向映射和国家扫描仍受代码守卫、完整读取和运行时上下文限制。

本批生产实现、profile 和独立来源分别由 [`directed_relation_memory.py`](../bridge/information/directed_relation_memory.py)、[`directed-relations-memory-1374.json`](../bridge/information/profiles/directed-relations-memory-1374.json)、[`source-002.json`](../work/runtime/information-relation-network-remaining-20261027-001/source-002.json)、[`role-binding-004.json`](../work/runtime/information-relation-network-remaining-20261027-001/role-binding-004.json) 和 [`expected-directed-relations-projection-001.json`](../work/runtime/information-relation-network-remaining-20261027-001/expected-directed-relations-projection-001.json) 提供。未实现或未验证的字段保持 `unknown`/`partial`，不由历史 action、legality、pending 或存档替代。

## 批56实际结果与收据

正式 full001 为 {full['passed']} passed、{full['failed']} failed、{full['errors']} errors、{full['subtests_passed']} 个子测试通过；新增失败节点 {len(full['new_failure_nodes'])} 个，解决节点 {len(full['resolved_failure_nodes'])} 个。覆盖配置为 {_format_counts(coverage['configured_counts'])}，live discovery 为 {_format_counts(coverage['actual_live_counts'])}，四个公开字段和 expires_at 的覆盖等级保持不变。完整阶段2/3/4、LLM自主订阅及 B01–B04 继续，goal保持 active。

实机运行身份为 session `{session}`、game_date `{game_date}`、observer `{observer}`；验收状态为 `{live.get('status')}`，服务器退出码为 {live.get('server_exit_code', 'unknown')}。首轮001因游戏帧心跳过期返回会话未就绪，原结果保留；恢复后使用002的新只读请求完成验收。本批没有保存、重启、推进日期或提交外交业务。

以下链接是本批 finalizer 使用的工程收据：

- 实机：[`{LIVE_DIRECTORY}/report.json`](../work/runtime/information-relation-network-remaining-20261027-001/{LIVE_DIRECTORY}/report.json)
- 生产回放比较：[`production-comparison-001.json`](../work/runtime/information-relation-network-remaining-20261027-001/production-comparison-001.json)
- 回归 XML/日志：[`regression-full-001.xml`](../work/runtime/information-relation-network-remaining-20261027-001/regression-full-001.xml)、[`regression-full-001.log`](../work/runtime/information-relation-network-remaining-20261027-001/regression-full-001.log)
- 覆盖收据：[`coverage-update-001.json`](../work/runtime/information-relation-network-remaining-20261027-001/coverage-update-001.json)
'''


def _docs() -> int:
    _require_stage_and_baseline()
    _verify_before()
    live = _live_report(required=True)
    comparison = _regression_comparison()
    coverage = read_json(STAGE / COVERAGE_RECEIPT_BASENAME)
    if coverage.get("field_coverage_changes") != [] or coverage.get("coverage_status_unchanged") is not True:
        raise AssertionError("batch56 coverage is not metadata-only")
    production = _production_comparison(required=True)
    target = ROOT / "docs/保证与军事访问关系网接口.md"
    _atomic_write_text(target, _doc_text(live, comparison, coverage, production))
    summary = _summary_text(live, comparison, coverage, production)
    summary_documents = _update_summary_documents(summary)
    receipt = {
        "schema": "information_directed_relation_document_verification.v1",
        "batch": BATCH,
        "status": "passed",
        "document": pin(target),
        "live_acceptance": pin(STAGE / LIVE_DIRECTORY / "report.json"),
        "production_comparison": pin(STAGE / PRODUCTION_COMPARISON_BASENAME),
        "full_comparison": comparison,
        "coverage_receipt": pin(STAGE / COVERAGE_RECEIPT_BASENAME),
        "summary_documents": summary_documents,
        "new_game_queries_or_pytest_runs": 0,
        "checks": {
            "live_receipt_passed": True,
            "production_comparison_passed": True,
            "full_receipt_completed": True,
            "coverage_metadata_only": True,
            "partial_and_expiry_boundary_preserved": True,
            "document_status_derived_from_receipts": True,
        },
    }
    write_json(DOCUMENT_RECEIPT_BASENAME, receipt)
    return 0


def _source_snapshot_paths() -> tuple[Path, ...]:
    paths = [path for path in _current_source_paths() if path.stat().st_size <= MAX_SOURCE_SNAPSHOT_BYTES]
    required = {
        "bridge/information/directed_relation_memory.py",
        "work/finalize_information_directed_relations.py",
        CONTRACT_PATH,
        "docs/保证与军事访问关系网接口.md",
    }
    present = {path.relative_to(ROOT).as_posix() for path in paths}
    if not required <= present:
        raise AssertionError("batch56 source snapshot is missing core source")
    if not any(
        relative.startswith("bridge/tests/")
        and "directed" in Path(relative).name
        and "relation" in Path(relative).name
        for relative in present
    ):
        raise AssertionError("batch56 source snapshot is missing directed-relation tests")
    return tuple(dict.fromkeys(paths))


def _stage_artifact_paths() -> tuple[Path, ...]:
    return tuple(path for path in sorted(STAGE.rglob("*")) if path.is_file() and "source-snapshot" not in path.parts)


def _artifact_inventory() -> list[dict[str, Any]]:
    result = []
    for path in _stage_artifact_paths():
        item = pin(path)
        item["snapshot"] = None
        item["snapshot_policy"] = (
            "artifact_pin_only_large" if path.stat().st_size > MAX_SOURCE_SNAPSHOT_BYTES
            else "eligible_for_bounded_reference"
        )
        result.append(item)
    return result


def _archive() -> int:
    _require_stage_and_baseline()
    before, after = _verify_before()
    live = _live_report(required=True)
    production = _production_comparison(required=True)
    coverage_path = STAGE / COVERAGE_RECEIPT_BASENAME
    document_path = STAGE / DOCUMENT_RECEIPT_BASENAME
    if not coverage_path.is_file() or not document_path.is_file():
        raise AssertionError("batch56 coverage/document receipts are missing")
    coverage = read_json(coverage_path)
    document = read_json(document_path)
    if coverage.get("field_coverage_changes") != [] or coverage.get("coverage_status_unchanged") is not True:
        raise AssertionError("batch56 coverage is not metadata-only")
    if document.get("status") != "passed" or document.get("new_game_queries_or_pytest_runs") != 0:
        raise AssertionError("batch56 document verification is not receipt-backed")
    comparison = _regression_comparison()
    if comparison["full"]["new_failure_nodes"]:
        raise AssertionError("batch56 introduced failure/error nodes")
    if comparison["new_or_renamed_tests"]["failure_error_occurrences"]:
        raise AssertionError("a new or renamed batch56 test failed")
    after_path = STAGE / "runtime-source-pins-after-001.json"
    if after_path.exists():
        raise AssertionError("batch56 archive already exists")
    write_json("runtime-source-pins-after-001.json", {
        "schema": "information_runtime_source_pins.v1", "batch": BATCH,
        "files": after, "all_match_before": True,
        "timing": "after batch56 live acceptance and formal full regression",
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
    previous_path = BASELINE / "development-summary-001.json"
    previous = read_json(previous_path) if previous_path.is_file() else {}
    current_artifacts = _artifact_inventory()
    current_sources = _current_source_paths()
    large_source_pins = [pin(path) for path in current_sources if path.stat().st_size > MAX_SOURCE_SNAPSHOT_BYTES]
    summary = {
        "schema": "information_development_summary.v1", "batch": BATCH,
        "status": "implemented_directed_relation_network_partial",
        "objective": previous.get("objective", "R01 guarantee and military-access country network"),
        "goal_complete": False, "goal_status": "active",
        "scope": {
            "topic": "R01", "pair_relation_types": list(PAIR_FAMILIES),
            "country_network_families": list(COUNTRY_NETWORK_FAMILIES),
            "default_pair_row_count": 10, "full_relation_network": False,
            "topics": 74, "fields": 397,
        },
        "delivered": {
            "country_network_families": list(COUNTRY_NETWORK_FAMILIES),
            "pair_relation_types": list(PAIR_FAMILIES),
            "coverage_status_unchanged": True, "complete": False,
        },
        "runtime_validation": live, "production_comparison": production,
        "documentation_validation": document, "coverage": coverage,
        "tests": {"formal_full": comparison["full"], "new_or_renamed_tests": comparison["new_or_renamed_tests"], "counts_not_additive": True},
        "runtime_identity": deepcopy(previous.get("runtime_identity", {})),
        "source_layers": {
            "contract": _contract_pin(),
            "source_001": pin(ROOT / "work/runtime/information-relation-network-remaining-20261027-001/source-001.json"),
            "source_002": pin(ROOT / "work/runtime/information-relation-network-remaining-20261027-001/source-002.json"),
            "production_comparison": pin(STAGE / PRODUCTION_COMPARISON_BASENAME),
            "large_files_not_copied": True,
        },
        "source_snapshot": snapshots,
        "source_snapshot_policy": {"bounded_max_bytes": MAX_SOURCE_SNAPSHOT_BYTES, "large_source_artifact_pins": large_source_pins, "large_files_not_copied": True},
        "stage_artifacts": current_artifacts,
        "baseline": {"stage": BASELINE.relative_to(ROOT).as_posix(), "regression": comparison["baseline"]},
        "next_work": {"expires_at": "planned; no native expiry source closed", "full_relation_network": "active", "goal": "active"},
        "no_repeat": {"historical_actions_and_original_final_pass_ids": "not retried", "business_actions_submitted": live.get("business_actions_submitted")},
    }
    summary_path = write_json("development-summary-001.json", summary)
    archive = {
        "schema": "information_directed_relation_archive_verification.v1", "batch": BATCH, "status": "passed",
        "summary": pin(summary_path), "runtime_source_pins_after": pin(after_path),
        "regression_comparison": pin(STAGE / "regression-comparison-001.json"),
        "source_snapshot_count": len(snapshots), "stage_artifact_count": len(current_artifacts),
        "large_source_pin_count": len(large_source_pins), "large_reference_policy": "streaming_hash_and_pin_only",
        "checks": {
            "live_receipt_passed": True, "production_comparison_passed": True,
            "coverage_metadata_only": True, "new_failure_nodes_empty": comparison["full"]["new_failure_nodes"] == [],
            "new_or_renamed_test_failures": False,
            "old_baseline_debt_preserved": (
                comparison["full"]["failure_error_occurrences"] == comparison["baseline"]["failure_error_occurrences"]
                and comparison["full"]["unique_failure_error_nodes"] == comparison["baseline"]["unique_failure_error_nodes"]
            ),
            "source_snapshot_bounded": True,
        },
    }
    write_json("archive-verification-001.json", archive)
    print(json.dumps({"summary": pin(summary_path), "archive": archive, "source_snapshots": len(snapshots)}, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Batch56 directed-relation finalizer; explicit phase only.")
    phases = parser.add_mutually_exclusive_group()
    phases.add_argument("--freeze", action="store_true", help="pin runtime sources and original coverage bytes")
    phases.add_argument("--full", action="store_true", help="run only python -m pytest -q bridge/tests")
    phases.add_argument("--coverage", action="store_true", help="merge R01 metadata only")
    phases.add_argument("--docs", action="store_true", help="write the live-backed public document and summaries")
    phases.add_argument("--archive", action="store_true", help="verify receipts and create bounded archive summary")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not any((args.freeze, args.full, args.coverage, args.docs, args.archive)):
        build_parser().print_help()
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
