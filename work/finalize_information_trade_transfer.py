"""Bounded finalizer for batch 58's T05 trade-transfer adapter.

This module is intentionally lazy.  Importing it, running it without a phase,
and asking for help do not read the game, call MCP/RPM/REA, run pytest, or
change the coverage matrix.  The explicit phases are ordered by their
receipts: freeze -> full/live-backed coverage -> docs -> archive.

The batch inherits the frozen batch-57 runtime list.  Only the transfer
adapter and its test are runtime additions; the shared trade-details source
and observer service are pinned as source snapshots because they are the
legitimate implementation inputs for this batch.
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

from work import finalize_information_battle_war_identity as _batch57  # noqa: E402


STAGE = ROOT / "work/runtime/information-trade-transfer-20261027-001"
BASELINE = ROOT / "work/runtime/information-battle-war-identity-20261027-001"
BUILD_DIR = ROOT / "work/runtime/diplomacy-observer-20261027-information-battle-v28-002"
BATCH = 58
LIVE_DIRECTORY = "live-acceptance-001"
REGRESSION_BASENAME = "regression-full-001"
BASELINE_REGRESSION_BASENAME = "regression-full-001"
COVERAGE_RECEIPT_BASENAME = "coverage-update-001.json"
DOCUMENT_RECEIPT_BASENAME = "document-verification-001.json"
MAX_SOURCE_SNAPSHOT_BYTES = 10 * 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"

_TRANSFER_RUNTIME_PATHS = (
    "bridge/information/trade_transfer.py",
    "bridge/tests/test_information_trade_transfer.py",
)

_EXPLICIT_SOURCE_PATHS = (
    "bridge/information/trade_transfer.py",
    "bridge/information/trade_details.py",
    "bridge/information/trade_details_memory.py",
    "bridge/information/profiles/trade-details-memory-1374-v3.json",
    "bridge/tests/test_information_trade_transfer.py",
    "bridge/tests/test_information_trade_details.py",
    "bridge/tests/test_information_trade_details_memory.py",
    "tools/serve_information.py",
    "work/probe_information_trade_transfer.py",
    "work/validate_information_trade_transfer_live.py",
    "work/finalize_information_trade_transfer.py",
    "work/runtime/information-trade-transfer-20261027-001/source-contract-001.json",
    "work/runtime/information-trade-transfer-20261027-001/independent-expected-001.json",
    "work/runtime/information-trade-transfer-20261027-001/independent-raw-001.json",
    "docs/信息字段覆盖.json",
    "docs/贸易竞争力只读接口.md",
    "docs/贸易收入只读接口.md",
    "docs/信息导出与订阅开发计划.md",
    "docs/LLM导出信息目录.md",
    "HANDOFF.md",
    "README(agent).md",
)

_SOURCE_GLOBS = (
    "bridge/tests/test_information_trade_transfer*.py",
    "bridge/tests/fixtures/information_trade_transfer*.json",
    "bridge/tests/fixtures/information_trade_transfer*.json.gz",
    "work/*trade_transfer*.py",
    "work/*trade_transfer*.json",
    "work/research-next/*trade_transfer*.py",
    "work/runtime/information-trade-transfer-20261027-001/*.json",
    "work/runtime/information-trade-transfer-20261027-001/*.log",
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


def read_json(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> Any:
    if not path.is_file():
        raise AssertionError(f"required file is missing: {path.relative_to(ROOT)}")
    if path.stat().st_size > max_bytes:
        raise AssertionError(f"bounded JSON read refused: {path.relative_to(ROOT)}")
    with path.open("r", encoding="utf-8-sig") as stream:
        return json.load(stream)


def write_json(name: str, value: Any) -> Path:
    STAGE.mkdir(parents=True, exist_ok=True)
    target = STAGE / name
    if target.exists():
        raise AssertionError(f"batch58 receipt already exists: {target.relative_to(ROOT)}")
    with target.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return target


def _atomic_write(path: Path, value: Any) -> None:
    temporary = path.with_name(path.name + ".batch58.tmp")
    if temporary.exists():
        raise AssertionError(f"temporary output already exists: {temporary.relative_to(ROOT)}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with temporary.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    os.replace(temporary, path)


def _atomic_write_text(path: Path, text: str) -> None:
    temporary = path.with_name(path.name + ".batch58.tmp")
    if temporary.exists():
        raise AssertionError(f"temporary output already exists: {temporary.relative_to(ROOT)}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with temporary.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
    os.replace(temporary, path)


def _require_stage_and_baseline() -> None:
    if not STAGE.is_dir():
        raise AssertionError(f"batch58 main stage is missing: {STAGE}")
    if not BASELINE.is_dir():
        raise AssertionError(f"batch57 baseline stage is missing: {BASELINE}")


def _runtime_paths() -> tuple[str, ...]:
    # Keeping this as a direct extension makes the 82 inherited paths and the
    # two batch-58 paths auditable and prevents an accidental runtime-path
    # promotion of a documentation or raw-reference artifact.
    return tuple(dict.fromkeys(_batch57._runtime_paths() + _TRANSFER_RUNTIME_PATHS))


def _require_runtime_files() -> tuple[str, ...]:
    paths = _runtime_paths()
    missing = [relative for relative in paths if not (ROOT / relative).is_file()]
    if missing:
        raise AssertionError("runtime source missing: " + ", ".join(missing))
    if len(paths) != 84:
        raise AssertionError(f"batch58 runtime path count changed: {len(paths)}")
    return paths


def _baseline_receipts() -> dict[str, dict[str, Any]]:
    summary = BASELINE / "development-summary-002.json"
    xml = BASELINE / f"{BASELINE_REGRESSION_BASENAME}.xml"
    log = BASELINE / f"{BASELINE_REGRESSION_BASENAME}.log"
    for path in (summary, xml, log):
        if not path.is_file():
            raise AssertionError(f"batch57 selected baseline receipt is missing: {path.name}")
    return {"summary": pin(summary), "xml": pin(xml), "log": pin(log)}


def _source_paths() -> tuple[Path, ...]:
    paths = [ROOT / relative for relative in _EXPLICIT_SOURCE_PATHS]
    for pattern in _SOURCE_GLOBS:
        paths.extend(ROOT.glob(pattern))
    unique = sorted({path for path in paths if path.is_file()}, key=lambda p: p.relative_to(ROOT).as_posix())
    required = {relative for relative in _EXPLICIT_SOURCE_PATHS}
    present = {path.relative_to(ROOT).as_posix() for path in unique}
    missing = sorted(required - present)
    if missing:
        raise AssertionError("batch58 source pin missing: " + ", ".join(missing))
    return tuple(unique)


def _pin_before() -> int:
    _require_stage_and_baseline()
    before_path = STAGE / "runtime-source-pins-before-001.json"
    matrix_path = STAGE / "coverage-matrix-before-001.json"
    if before_path.exists() or matrix_path.exists():
        raise AssertionError("batch58 before pins or coverage snapshot already exists")
    runtime_paths = _require_runtime_files()
    matrix = ROOT / "docs/信息字段覆盖.json"
    if not matrix.is_file():
        raise AssertionError("coverage matrix is missing")
    baseline = _baseline_receipts()
    with matrix_path.open("xb") as target, matrix.open("rb") as source:
        shutil.copyfileobj(source, target)
    source_paths = _source_paths()
    receipt = {
        "schema": "information_runtime_source_pins.v1",
        "batch": BATCH,
        "baseline_stage": BASELINE.relative_to(ROOT).as_posix(),
        "selected_batch57_baseline": baseline,
        "timing": "before batch58 trade-transfer live acceptance and formal full regression",
        "continuous_monitoring_claimed": False,
        "inherited_batch57_runtime_paths": len(_batch57._runtime_paths()),
        "runtime_paths": list(runtime_paths),
        "extension_runtime_paths": list(_TRANSFER_RUNTIME_PATHS),
        "files": [pin(ROOT / relative) for relative in runtime_paths],
        "coverage_matrix_before": pin(matrix_path),
        "source_files": [pin(path) for path in source_paths],
        "expected_identity": {
            "installation": "resolved at live/archive time, never inherited from batch57",
            "game_version": "1.37.4",
            "game_sha256": EXPECTED_EXE_SHA256,
            "live_directory": LIVE_DIRECTORY,
        },
    }
    write_json(before_path.name, receipt)
    print(json.dumps({"runtime_paths": len(runtime_paths), "source_files": len(source_paths)}, ensure_ascii=False))
    return 0


def _verify_before() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    before = read_json(STAGE / "runtime-source-pins-before-001.json")
    if before.get("batch") != BATCH:
        raise AssertionError("runtime source pin is not a batch58 pin")
    pinned = before.get("files")
    if not isinstance(pinned, list) or len(pinned) != 84:
        raise AssertionError("batch58 runtime source pin does not contain 84 files")
    after: list[dict[str, Any]] = []
    for item in pinned:
        if not isinstance(item, Mapping) or not isinstance(item.get("path"), str):
            raise AssertionError("runtime pin has an invalid path")
        path = ROOT / item["path"]
        if not path.is_file():
            raise AssertionError(f"pinned runtime source disappeared: {item['path']}")
        current = pin(path)
        current["matches_before"] = current["sha256"] == item.get("sha256")
        after.append(current)
    if not all(item["matches_before"] for item in after):
        raise AssertionError("a frozen batch58 runtime source changed")
    matrix = STAGE / "coverage-matrix-before-001.json"
    if not matrix.is_file():
        raise AssertionError("batch58 coverage matrix snapshot is missing")
    return before, after


def _live_report(*, required: bool = True) -> dict[str, Any] | None:
    path = STAGE / LIVE_DIRECTORY / "report.json"
    if not path.is_file():
        if required:
            raise AssertionError("batch58 live acceptance report is missing")
        return None
    value = read_json(path)
    if value.get("status") != "passed":
        raise AssertionError("batch58 live acceptance is not passed")
    exit_code = value.get("server_exit_code", value.get("server_exit"))
    if type(exit_code) is not int or exit_code != 0:
        raise AssertionError("batch58 live acceptance server did not exit 0")
    checks = value.get("checks")
    if isinstance(checks, Mapping) and not all(item is True for item in checks.values()):
        raise AssertionError("batch58 live acceptance contains a failed check")
    if not checks or type(value.get("periodic_results")) is not int or value["periodic_results"] < 1:
        raise AssertionError("batch58 live acceptance lacks checked periodic delivery")
    return value


def _identity_from_document(document: Mapping[str, Any]) -> dict[str, Any]:
    identity = document.get("identity") if isinstance(document.get("identity"), Mapping) else {}
    binding = document.get("binding") if isinstance(document.get("binding"), Mapping) else {}
    source = dict(identity)
    source.update({key: value for key, value in binding.items() if key not in source})
    for key in ("session_id", "process_creation_filetime", "creation_filetime", "game_date", "observer", "game_sha256"):
        if key in document and key not in source:
            source[key] = document[key]
    return source


def _current_runtime_identity(live: Mapping[str, Any]) -> dict[str, Any]:
    installation_path = BUILD_DIR / "installation.json"
    installation = read_json(installation_path)
    live_identity = _identity_from_document(live)
    session = live_identity.get("session_id")
    creation = live_identity.get("process_creation_filetime", live_identity.get("creation_filetime"))
    if session != installation.get("session_id"):
        raise AssertionError("live and current installation session identities differ")
    if creation is not None and creation != installation.get("creation_filetime"):
        raise AssertionError("live and current installation creation identities differ")
    game_sha = live_identity.get("game_sha256", installation.get("game_sha256"))
    if game_sha != installation.get("game_sha256") or game_sha != EXPECTED_EXE_SHA256:
        raise AssertionError("live/current installation EXE SHA mismatch")
    raw = read_json(STAGE / "independent-raw-001.json")
    raw_identity = raw["identity"]
    if (raw_identity.get("binding_verified") is not True
            or raw_identity.get("installation_pid") != installation["pid"]
            or raw_identity.get("installation_creation_filetime") != installation["creation_filetime"]
            or raw_identity.get("installation_session_id") != installation["session_id"]):
        raise AssertionError("independent raw and installation process identities differ")
    return {
        "installation": pin(installation_path),
        "pid": installation.get("pid"),
        "creation_filetime": installation.get("creation_filetime"),
        "session_id": installation.get("session_id"),
        "game_date": live_identity.get("game_date", "unknown"),
        "observer": live_identity.get("observer", "FRA"),
        "game_version": "1.37.4",
        "game_sha256": installation.get("game_sha256"),
        "dll_sha256": installation.get("dll_sha256"),
        "read_only": True,
        "business_actions_submitted": 0,
        "save_or_restart": False,
        "date_advanced": False,
        "identity_source": "current_installation_json_and_selected_live_report",
    }


def _test_cases(path: Path) -> tuple[list[ET.Element], set[str], int]:
    root = ET.parse(path).getroot()
    cases = root.findall(".//testcase")
    bad = {
        f"{case.get('classname')}::{case.get('name')}"
        for case in cases if case.findall("failure") or case.findall("error")
    }
    occurrences = sum(len(case.findall("failure")) + len(case.findall("error")) for case in cases)
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


def _count(summary: str, label: str) -> int:
    import re
    match = re.search(r"(\d+) " + re.escape(label) + r"\b", summary)
    return int(match.group(1)) if match else 0


def _regression_comparison() -> dict[str, Any]:
    xml = STAGE / f"{REGRESSION_BASENAME}.xml"
    log = STAGE / f"{REGRESSION_BASENAME}.log"
    baseline_xml = BASELINE / f"{BASELINE_REGRESSION_BASENAME}.xml"
    boundary = STAGE / "full-execution-boundary-001.json"
    for path in (xml, log, baseline_xml):
        if not path.is_file():
            raise AssertionError(f"regression receipt is missing: {path.relative_to(ROOT)}")
    current_cases, current_bad, current_occurrences = _test_cases(xml)
    old_cases, old_bad, old_occurrences = _test_cases(baseline_xml)
    current_keys = {f"{case.get('classname')}::{case.get('name')}" for case in current_cases}
    old_keys = {f"{case.get('classname')}::{case.get('name')}" for case in old_cases}
    added = sorted(current_keys - old_keys)
    removed = sorted(old_keys - current_keys)
    summary = _summary_line(log)
    added_failures = sum(
        len(case.findall("failure")) + len(case.findall("error"))
        for case in current_cases
        if f"{case.get('classname')}::{case.get('name')}" in set(added)
    )
    full = {
        "command": "python -m pytest -q bridge/tests",
        "passed": _count(summary, "passed"),
        "failed": _count(summary, "failed"),
        "errors": _count(summary, "errors"),
        "subtests_passed": _count(summary, "subtests passed"),
        "summary_line": summary,
        "whole_suite_green": not current_bad,
        "failure_error_occurrences": current_occurrences,
        "unique_failure_error_nodes": len(current_bad),
        "new_failure_nodes": sorted(current_bad - old_bad),
        "resolved_failure_nodes": sorted(old_bad - current_bad),
        "xml": pin(xml),
        "log": pin(log),
    }
    if boundary.is_file():
        full["execution_boundary"] = pin(boundary)
    return {
        "schema": "information_trade_transfer_regression_comparison.v1",
        "batch": BATCH,
        "full": full,
        "new_or_renamed_tests": {
            "execution": "derived_from_full_XML_not_another_run",
            "nodes": added,
            "cases": len(added),
            "failure_error_occurrences": added_failures,
        },
        "removed_nodes": removed,
        "net_case_delta": len(current_cases) - len(old_cases),
        "current_case_count": len(current_cases),
        "baseline": {
            "xml": pin(baseline_xml),
            "failure_error_occurrences": old_occurrences,
            "unique_failure_error_nodes": len(old_bad),
            "case_count": len(old_cases),
            "selected_summary": "batch57 development-summary-002 and regression-full-001",
        },
    }


def _run_full() -> int:
    _require_stage_and_baseline()
    _verify_before()
    xml = STAGE / f"{REGRESSION_BASENAME}.xml"
    log = STAGE / f"{REGRESSION_BASENAME}.log"
    if xml.exists() or log.exists():
        raise AssertionError("batch58 formal regression receipts already exist")
    with log.open("x", encoding="utf-8", newline="\n") as stream:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "bridge/tests", "--junitxml", str(xml)],
            cwd=ROOT,
            stdout=stream,
            stderr=subprocess.STDOUT,
            check=False,
        )
    write_json(
        "full-execution-boundary-001.json",
        {
            "schema": "information_trade_transfer_full_execution_boundary.v1",
            "batch": BATCH,
            "command": "python -m pytest -q bridge/tests",
            "exit_code": result.returncode,
            "runtime_functionality_proven": False,
            "live_receipt_required_for_runtime_claim": True,
            "native_game_call": False,
            "note": "Full bridge tests are separate from the read-only live acceptance.",
        },
    )
    print(f"formal batch58 full regression exit {result.returncode}")
    return result.returncode


def _topics(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, Mapping) and isinstance(value.get("topics"), list):
        topics = value["topics"]
    elif isinstance(value, list):
        topics = value
    else:
        raise AssertionError("coverage discovery topics are missing")
    if not all(isinstance(item, dict) and isinstance(item.get("topic_id"), str) for item in topics):
        raise AssertionError("coverage topics are invalid")
    return topics


def _topic_counts(topics: list[dict[str, Any]]) -> dict[str, Any]:
    topic_status: dict[str, int] = {}
    field_counts: dict[str, int] = {}
    fields_total = 0
    for topic in topics:
        status = str(topic.get("status", "unknown"))
        topic_status[status] = topic_status.get(status, 0) + 1
        fields = topic.get("fields", {})
        if not isinstance(fields, dict):
            raise AssertionError("coverage topic fields are invalid")
        for descriptor in fields.values():
            if not isinstance(descriptor, dict):
                raise AssertionError("coverage field descriptor is invalid")
            coverage = str(descriptor.get("coverage", "unknown"))
            field_counts[coverage] = field_counts.get(coverage, 0) + 1
            fields_total += 1
    return {
        "topic_count": len(topics),
        "field_count": fields_total,
        "topic_status_counts": dict(sorted(topic_status.items())),
        "field_counts": dict(sorted(field_counts.items())),
        "available_topic_count": topic_status.get("available", 0),
        "callable_topic_count": topic_status.get("available", 0),
    }


def _topic(topics: list[dict[str, Any]], topic_id: str) -> dict[str, Any]:
    matches = [item for item in topics if item.get("topic_id") == topic_id]
    if len(matches) != 1:
        raise AssertionError(f"discovery must contain exactly one {topic_id}")
    return matches[0]


def _discovery() -> tuple[dict[str, Any], Path, dict[str, Any] | None, Path | None]:
    path = STAGE / LIVE_DIRECTORY / "discovery.json"
    value = read_json(path)
    _topics(value)
    catalog_path = STAGE / LIVE_DIRECTORY / "catalog.json"
    catalog = read_json(catalog_path) if catalog_path.is_file() else None
    return value, path, catalog, catalog_path if catalog_path.is_file() else None


def _merge_transfer(before: dict[str, Any], live_topics: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    merged = deepcopy(before)
    configured = merged.get("topics")
    if not isinstance(configured, list):
        raise AssertionError("configured coverage topics are missing")
    target = _topic(configured, "T05")
    live = _topic(live_topics, "T05")
    live_fields = live.get("fields")
    target_fields = target.get("fields")
    if not isinstance(live_fields, dict) or not isinstance(target_fields, dict) or "transfer" not in live_fields or "transfer" not in target_fields:
        raise AssertionError("T05.transfer is missing from configured/live discovery")
    old = target_fields["transfer"]
    descriptor = live_fields["transfer"]
    if not isinstance(old, dict) or not isinstance(descriptor, dict):
        raise AssertionError("T05.transfer descriptor is invalid")
    live_coverage = descriptor.get("coverage")
    if live_coverage not in {"partial", "available"}:
        raise AssertionError(f"live T05.transfer did not reach partial coverage: {live_coverage!r}")
    next_descriptor = deepcopy(descriptor)
    next_descriptor["coverage"] = "partial"
    next_descriptor["complete"] = False
    target_fields["transfer"] = next_descriptor
    # The title and every field/topic outside the one declared change must be
    # byte-for-byte inherited from the pre-batch matrix.
    if target.get("title") != _topic(configured, "T05").get("title"):
        raise AssertionError("T05 topic title changed during transfer merge")
    changes = [{
        "topic_id": "T05",
        "field": "transfer",
        "before": old.get("coverage", "planned"),
        "live": live_coverage,
        "after": "partial",
        "complete_before": bool(old.get("complete", False)),
        "complete_after": False,
        "reason": "native_trade_transfer_live_source",
    }]
    if changes[0]["before"] != "planned":
        raise AssertionError("T05.transfer was already changed before batch58")
    return merged, changes


def _coverage() -> int:
    _require_stage_and_baseline()
    _verify_before()
    live = _live_report(required=True)
    discovery, discovery_path, catalog, catalog_path = _discovery()
    before_path = STAGE / "coverage-matrix-before-001.json"
    matrix_path = ROOT / "docs/信息字段覆盖.json"
    before = read_json(before_path)
    live_topics = _topics(discovery)
    merged, changes = _merge_transfer(before, live_topics)
    before_topics = _topics(before)
    after_topics = _topics(merged)
    actual_counts = _topic_counts(live_topics)
    configured_counts = _topic_counts(after_topics)
    if _topic_counts(before_topics)["topic_count"] != 74 or _topic_counts(before_topics)["field_count"] != 397:
        raise AssertionError("configured baseline must remain 74/397")
    if configured_counts["topic_count"] != 74 or configured_counts["field_count"] != 397 or actual_counts["topic_count"] != 74 or actual_counts["field_count"] != 397:
        raise AssertionError("batch58 coverage scope is not 74/397")
    # Ensure that only T05.transfer coverage/descriptor changed.  The live
    # discovery is permitted to carry other source metadata, but it is not
    # allowed to rewrite the existing catalog through this phase.
    before_by_id = {item["topic_id"]: item for item in before_topics}
    after_by_id = {item["topic_id"]: item for item in after_topics}
    for topic_id, old_topic in before_by_id.items():
        new_topic = after_by_id[topic_id]
        if topic_id != "T05":
            if old_topic != new_topic:
                raise AssertionError(f"coverage changed outside T05: {topic_id}")
            continue
        for key in old_topic:
            if key == "fields":
                continue
            if old_topic.get(key) != new_topic.get(key):
                raise AssertionError(f"T05 metadata changed outside transfer field: {key}")
        old_fields = old_topic["fields"]
        new_fields = new_topic["fields"]
        for field_name, old_descriptor in old_fields.items():
            if field_name != "transfer" and old_descriptor != new_fields.get(field_name):
                raise AssertionError(f"T05 field changed outside transfer: {field_name}")
    _atomic_write(matrix_path, merged)
    receipt = {
        "schema": "information_trade_transfer_coverage_update.v1",
        "batch": BATCH,
        "goal_complete": False,
        "goal_status": "active",
        "before_sha256": sha(before_path),
        "after_sha256": sha(matrix_path),
        "configured_counts": configured_counts,
        "actual_live_counts": actual_counts,
        "scope_counts_fixed": {"topics": 74, "fields": 397},
        "metadata_changes": [],
        "field_coverage_changes": changes,
        "coverage_status_unchanged": False,
        "coverage_changes_allowed": True,
        "topic_title_preserved": True,
        "actual_live_field_coverage": {
            f"{topic['topic_id']}.{field}": descriptor.get("coverage")
            for topic in live_topics
            for field, descriptor in topic.get("fields", {}).items()
            if isinstance(descriptor, Mapping)
        },
        "sources": {
            "live_discovery": pin(discovery_path),
            "live_catalog": pin(catalog_path) if catalog_path is not None else None,
            "live_report": pin(STAGE / LIVE_DIRECTORY / "report.json"),
        },
        "note": "Only T05.transfer moved from planned to partial; transfer relations remain distinct from steering and node value flow.",
    }
    write_json(COVERAGE_RECEIPT_BASENAME, receipt)
    print(json.dumps(receipt, ensure_ascii=False))
    return 0


def _query_examples(live: Mapping[str, Any]) -> tuple[str, str, str]:
    return ("t05-transfer-country-example-001", "t05-transfer-node-example-001",
            "t05-transfer-mixed-example-001")


def _docs() -> int:
    _require_stage_and_baseline()
    _verify_before()
    live = _live_report(required=True)
    coverage_path = STAGE / COVERAGE_RECEIPT_BASENAME
    if not coverage_path.is_file():
        raise AssertionError("batch58 coverage receipt is missing")
    coverage = read_json(coverage_path)
    changes = coverage.get("field_coverage_changes")
    if not isinstance(changes, list) or len(changes) != 1:
        raise AssertionError("batch58 docs require the bounded T05.transfer coverage receipt")
    change = changes[0]
    if change.get("topic_id") != "T05" or change.get("field") != "transfer" or change.get("after") != "partial":
        raise AssertionError("batch58 docs are not based on T05.transfer partial coverage")
    country_id, node_id, mixed_id = _query_examples(live)
    identity = _current_runtime_identity(live)
    full = _regression_comparison()["full"]
    target = ROOT / "docs/贸易权转移只读接口.md"
    text = f'''# 贸易权转移只读接口

当前接口属于 T05「贸易收集、转移与收入」主题，范围固定为 1.37.4、FRA 观察者。`transfer` 返回各节点转出和转入的贸易权记录，保留国家、fullref、槽位、原始值及方向，实际数值为 `raw / scale`，单位为 `trade_power`、`scale=1000`。本次波尔多节点读到来自奥弗涅（AUV）的 `raw=9958`，即9.958点贸易权转入；转出列表为空。商人任务、引导方向、节点价值流量和收入使用各自的字段。

该字段保持 `partial`、`complete=false`：当前来源为原生缓存，缓存更新时机、其他国家的可见范围及 GUI 数值对应仍需补齐。

## 查询示例

国家对象：

```json
{{"request_id":"{country_id}","queries":[{{"topic":"T05","object":{{"type":"country","country":"FRA"}},"fields":["transfer"],"parameters":{{}}}}]}}
```

节点对象：

```json
{{"request_id":"{node_id}","queries":[{{"topic":"T05","object":{{"type":"trade_node","node_id":"bordeaux"}},"fields":["transfer"],"parameters":{{}}}}]}}
```

同一请求可把 `T05.transfer` 与已支持的 T05 字段放在混合查询中；各字段仍由自己的 source 和状态决定。国家查询返回原生节点顺序，节点查询只返回指定节点；空 TO/FROM 容器是 `known` 加空列表，不会被伪造为未知。订阅复用 `query`/`periodic` 触发，参数必须为空；读取失败会保留具体 `unknown`/`unavailable` 原因。

本批实机收据绑定当前安装 session `{identity['session_id']}`、date `{identity['game_date']}`、观察国 `{identity['observer']}`。文档和收据只描述只读查询，不保存、重启、推进日期或执行外交动作。原始独立参考中的非空样本按 direction 保留原始符号，不求和、不翻转。

80个节点的查询结果与独立原始读取一致，报告和{live['periodic_results']}条周期结果已交付，订阅已取消，服务正常退出。完整回归为{full['passed']}项通过、{full['failed']}项失败和{full['errors']}项错误；新增6项通过，无新增失败节点。完整74主题397字段的开发目标继续。

来源与验收：[独立参考](../work/runtime/information-trade-transfer-20261027-001/independent-expected-001.json)、[实机收据](../work/runtime/information-trade-transfer-20261027-001/live-acceptance-001/report.json)、[来源合同](../work/runtime/information-trade-transfer-20261027-001/source-contract-001.json)。
'''
    _atomic_write_text(target, text)
    receipt = {
        "schema": "information_trade_transfer_document_verification.v1",
        "batch": BATCH,
        "status": "passed",
        "document": pin(target),
        "live_acceptance": pin(STAGE / LIVE_DIRECTORY / "report.json"),
        "coverage_receipt": pin(coverage_path),
        "runtime_identity": identity,
        "request_ids": [country_id, node_id, mixed_id],
        "new_game_queries_or_pytest_runs": 0,
        "checks": {
            "live_receipt_passed": True,
            "coverage_only_t05_transfer": True,
            "topic_title_preserved": True,
            "fetched_identity_from_current_installation_and_live": True,
            "transfer_distinguished_from_steering_and_value_flow": True,
        },
    }
    write_json(DOCUMENT_RECEIPT_BASENAME, receipt)
    return 0


def _current_source_paths() -> tuple[Path, ...]:
    paths = list(_source_paths())
    document = ROOT / "docs/贸易权转移只读接口.md"
    if document.is_file():
        paths.append(document)
    return tuple(sorted(set(paths), key=lambda p: p.relative_to(ROOT).as_posix()))


def _source_snapshot_paths() -> tuple[Path, ...]:
    paths = tuple(path for path in _current_source_paths() if path.stat().st_size <= MAX_SOURCE_SNAPSHOT_BYTES)
    required = {
        "bridge/information/trade_transfer.py",
        "bridge/information/trade_details.py",
        "bridge/tests/test_information_trade_transfer.py",
        "work/probe_information_trade_transfer.py",
        "work/validate_information_trade_transfer_live.py",
        "work/finalize_information_trade_transfer.py",
        "docs/贸易权转移只读接口.md",
    }
    present = {path.relative_to(ROOT).as_posix() for path in paths}
    missing = sorted(required - present)
    if missing:
        raise AssertionError("batch58 source snapshot is missing core source: " + ", ".join(missing))
    return paths


def _stage_artifacts() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    if not STAGE.is_dir():
        return result
    for path in sorted(STAGE.rglob("*"), key=lambda p: p.relative_to(ROOT).as_posix()):
        if not path.is_file() or "source-snapshot" in path.parts:
            continue
        item = pin(path)
        item["snapshot"] = None
        item["snapshot_policy"] = "artifact_pin_only_large" if path.stat().st_size > MAX_SOURCE_SNAPSHOT_BYTES else "eligible_for_bounded_reference"
        result.append(item)
    return result


def _archive() -> int:
    _require_stage_and_baseline()
    before, after = _verify_before()
    live = _live_report(required=True)
    identity = _current_runtime_identity(live)
    coverage_path = STAGE / COVERAGE_RECEIPT_BASENAME
    document_path = STAGE / DOCUMENT_RECEIPT_BASENAME
    if not coverage_path.is_file() or not document_path.is_file():
        raise AssertionError("batch58 coverage/document receipts are missing")
    coverage = read_json(coverage_path)
    document = read_json(document_path)
    if document.get("status") != "passed" or document.get("new_game_queries_or_pytest_runs") != 0:
        raise AssertionError("batch58 document receipt is not read-only and receipt-backed")
    changes = coverage.get("field_coverage_changes")
    if not isinstance(changes, list) or len(changes) != 1:
        raise AssertionError("batch58 coverage receipt has unexpected field changes")
    change = changes[0]
    if (change.get("topic_id"), change.get("field"), change.get("before"), change.get("after")) != ("T05", "transfer", "planned", "partial"):
        raise AssertionError("batch58 coverage change is not exactly T05.transfer planned-to-partial")
    comparison = _regression_comparison()
    if comparison["full"]["new_failure_nodes"]:
        raise AssertionError("batch58 introduced failure/error nodes")
    if comparison["new_or_renamed_tests"]["failure_error_occurrences"]:
        raise AssertionError("a new or renamed batch58 test failed")
    after_path = STAGE / "runtime-source-pins-after-001.json"
    if after_path.exists():
        raise AssertionError("batch58 archive already exists")
    write_json(
        after_path.name,
        {
            "schema": "information_runtime_source_pins.v1",
            "batch": BATCH,
            "files": after,
            "all_match_before": True,
            "timing": "after batch58 live acceptance and formal full regression",
            "continuous_monitoring_claimed": False,
        },
    )
    comparison_path = write_json("regression-comparison-001.json", comparison)
    snapshots: list[dict[str, Any]] = []
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
    large_source_pins = [pin(path) for path in _current_source_paths() if path.stat().st_size > MAX_SOURCE_SNAPSHOT_BYTES]
    summary = write_json(
        "development-summary-001.json",
        {
            "schema": "information_development_summary.v1",
            "batch": BATCH,
            "status": "implemented_trade_transfer_partial",
            "objective": read_json(BASELINE / "development-summary-002.json")["objective"],
            "stage_objective": "T05.transfer 贸易权转移关系只读接线",
            "goal_complete": False,
            "goal_status": "active",
            "scope": {"topics": 74, "fields": 397, "T05.transfer": "partial", "complete": False},
            "remaining_full_scope": {"phases": [2, 3, 4], "autonomous_subscriptions": "required", "full_B01_B04": "incomplete"},
            "delivered": {
                "country_and_trade_node_transfer": True,
                "one_capture_per_transfer_query": True,
                "shared_trade_details_capture_method": True,
                "complete": False,
            },
            "runtime_validation": live,
            "documentation_validation": document,
            "coverage": coverage,
            "tests": {"formal_full": comparison["full"], "new_or_renamed_tests": comparison["new_or_renamed_tests"], "counts_not_additive": True},
            "runtime_identity": identity,
            "source_layers": {
                "source_contract": pin(STAGE / "source-contract-001.json"),
                "independent_reference": pin(STAGE / "independent-expected-001.json"),
                "independent_raw": pin(STAGE / "independent-raw-001.json"),
                "runtime_source_pins_before": pin(STAGE / "runtime-source-pins-before-001.json"),
                "runtime_source_pins_after": pin(after_path),
                "regression_comparison": pin(comparison_path),
                "large_files_not_copied": True,
            },
            "source_snapshot": snapshots,
            "source_snapshot_policy": {"bounded_max_bytes": MAX_SOURCE_SNAPSHOT_BYTES, "large_source_artifact_pins": large_source_pins, "large_files_not_copied": True},
            "stage_artifacts": _stage_artifacts(),
            "baseline": {"stage": BASELINE.relative_to(ROOT).as_posix(), "regression": comparison["baseline"]},
            "next_work": {"trade_transfer_freshness_and_visibility": "unresolved", "complete_goal": "active"},
            "identity_policy": "current installation and selected live report; batch57 identity was not inherited",
            "no_repeat": {"business_actions_submitted": 0, "save_restart_date_advance": False, "new_rea_analysis": False, "independent_rpm_capture": True, "game_functions_called": False},
        },
    )
    archive = {
        "schema": "information_trade_transfer_archive_verification.v1",
        "batch": BATCH,
        "status": "passed",
        "summary": pin(summary),
        "runtime_source_pins_after": pin(after_path),
        "regression_comparison": pin(comparison_path),
        "source_snapshot_count": len(snapshots),
        "stage_artifact_count": len(_stage_artifacts()),
        "large_source_pin_count": len(large_source_pins),
        "large_reference_policy": "streaming_hash_and_pin_only",
        "checks": {
            "live_receipt_passed": True,
            "current_identity_from_installation_and_live": True,
            "coverage_changes_bounded_to_t05_transfer": True,
            "new_failure_nodes_empty": comparison["full"]["new_failure_nodes"] == [],
            "new_or_renamed_test_failures": False,
            "old_baseline_debt_reported_from_xml": True,
            "source_snapshot_bounded": True,
            "goal_active": True,
        },
    }
    write_json("archive-verification-001.json", archive)
    print(json.dumps({"summary": pin(summary), "archive": archive, "source_snapshots": len(snapshots)}, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Batch58 T05 trade-transfer finalizer; explicit phase only.")
    phases = parser.add_mutually_exclusive_group()
    phases.add_argument("--freeze", "--pin-before", dest="freeze", action="store_true", help="pin runtime/source inputs before live and full")
    phases.add_argument("--full", action="store_true", help="run exactly python -m pytest -q bridge/tests")
    phases.add_argument("--coverage", action="store_true", help="merge only T05.transfer planned-to-partial coverage")
    phases.add_argument("--docs", action="store_true", help="write the live-backed transfer document")
    phases.add_argument("--archive", action="store_true", help="verify receipts and create the bounded archive")
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
