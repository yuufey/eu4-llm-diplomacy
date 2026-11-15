"""Batch 57 finalizer for the session-scoped battle-war identity source.

The module has five explicit phases: ``--freeze``, ``--full``, ``--coverage``,
``--docs`` and ``--archive``.  Importing the module, invoking it without a
phase, and invoking ``--help`` are inert.  Only ``--full`` may start pytest;
none of the phases starts a game, an RPM capture, an REA query, an MCP call,
or a diplomacy action.

The finalizer keeps the v28 build plan and the 56-batch baseline separate from
the new war-identity evidence.  Large runtime artifacts are hashed in bounded
streaming mode and are pinned instead of copied into a source snapshot.
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

from work import finalize_information_directed_relations as _batch56  # noqa: E402


STAGE = ROOT / "work/runtime/information-battle-war-identity-20261027-001"
BINDING_STAGE = ROOT / "work/runtime/information-battle-war-binding-20261027-001"
BASELINE = ROOT / "work/runtime/information-relation-network-remaining-20261027-001"
BUILD_DIR = ROOT / "work/runtime/diplomacy-observer-20261027-information-battle-v28-002"
BATCH = 57
# B01 supports query/event delivery in the selected post-unlock receipt.  Keep
# this explicit so finalization cannot accidentally consume the earlier failed
# periodic attempts in live-acceptance-003/004.
SELECTED_LIVE_DIRECTORY = "live-acceptance-006"
LIVE_DIRECTORY = SELECTED_LIVE_DIRECTORY
REGRESSION_BASENAME = "regression-full-001"
BASELINE_REGRESSION_BASENAME = "regression-full-001"
COVERAGE_RECEIPT_BASENAME = "coverage-update-002.json"
DOCUMENT_RECEIPT_BASENAME = "document-verification-002.json"
PRODUCTION_COMPARISON_BASENAME = "production-comparison-001.json"
FULL_BOUNDARY_RECEIPT_BASENAME = "full-execution-boundary-001.json"
MAX_SOURCE_SNAPSHOT_BYTES = 10 * 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_BUILD_VERSION = 28
EXPECTED_BUILD_SOURCE_COUNT = 112
BATTLE_METADATA_TOPICS = ("B01", "B02", "B03", "B04")

_WAR_RUNTIME_PATHS = (
    "bridge/information/battle_ingest.py",
    "bridge/information/battles.py",
    "bridge/information/battle_values.py",
    "work/information_battle_war_memory.py",
    "work/native/diplomacy-observer-v10.cpp",
    "work/native/information-battle-observer.inc",
    "work/native/information-battle-war-binding.h",
    "work/native/information-battle-war-identity-wire.h",
    "work/native/test-information-battle-war-binding.cpp",
    "work/native/build-diplomacy-observer.ps1",
    "tools/start_diplomacy_observer.py",
    "tools/control_information_battle_observer.py",
    "bridge/tests/test_information_battle_war_native.py",
    "bridge/tests/test_start_diplomacy_observer.py",
    "bridge/tests/test_control_information_battle_observer.py",
    "work/probe_information_battle_installed.py",
    "work/test_probe_information_battle_installed.py",
    "work/tests/test_probe_information_battle_installed.py",
)

_EXPLICIT_SOURCE_PATHS = (
    *_WAR_RUNTIME_PATHS,
    "work/research-next/battle_war_identity.py",
    "work/compare_information_battle_war_production.py",
    "work/replay_information_battle_war_binding.py",
    "work/finalize_information_battle_war_identity.py",
    "work/runtime/information-battle-war-identity-20261027-001/source-001.json",
    "work/runtime/information-battle-war-identity-20261027-001/source-002.json",
    "work/runtime/information-battle-war-identity-20261027-001/war-binding-contract-001.json",
    "work/runtime/information-battle-war-identity-20261027-001/build-v28-001.log",
    "work/runtime/information-battle-war-identity-20261027-001/build-v28-002.log",
    "work/runtime/information-battle-war-binding-20261027-001/war-binding-fixture-001.json",
    "work/runtime/information-battle-war-binding-20261027-001/war-binding-replay-001.json",
    "docs/战报战争编号接口.md",
    "docs/信息字段覆盖.json",
    "docs/信息导出与订阅开发计划.md",
    "docs/LLM导出信息目录.md",
    "HANDOFF.md",
    "README(agent).md",
)

_SOURCE_GLOBS = (
    "bridge/tests/test_information_battle_war*.py",
    "bridge/tests/test_start_diplomacy_observer.py",
    "bridge/tests/test_control_information_battle_observer.py",
    "bridge/tests/fixtures/information_battle_war*.json",
    "bridge/tests/fixtures/information_battle_war*.json.gz",
    "work/research-next/*war_identity*.py",
    "work/*battle_war*.py",
    "work/*war_identity*.py",
    "work/*war_binding*.py",
    "work/native/information-battle-war-*.h",
    "work/native/test-information-battle-war*.cpp",
    "work/runtime/information-battle-war-identity-20261027-001/*.json",
    "work/runtime/information-battle-war-identity-20261027-001/*.log",
    "work/runtime/information-battle-war-binding-20261027-001/*.json",
)

_BUILD_ARTIFACT_PATHS = (
    "work/runtime/diplomacy-observer-20261027-information-battle-v28-002/build-manifest.json",
    "work/runtime/diplomacy-observer-20261027-information-battle-v28-002/eu4_bridge_diplomacy_observer_v28.dll",
    "work/runtime/diplomacy-observer-20261027-information-battle-v28-002/install-v28-002.log",
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
    return json.loads(path.read_bytes())


def write_json(name: str, value: Any) -> Path:
    STAGE.mkdir(parents=True, exist_ok=True)
    target = STAGE / name
    if target.exists():
        raise AssertionError(f"batch57 receipt already exists: {target.relative_to(ROOT)}")
    with target.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return target


def _atomic_write_text(path: Path, text: str) -> None:
    temporary = path.with_name(path.name + ".batch57.tmp")
    if temporary.exists():
        raise AssertionError(f"temporary output already exists: {temporary.relative_to(ROOT)}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with temporary.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
    os.replace(temporary, path)


def _require_stage_and_baseline() -> None:
    if not STAGE.is_dir():
        raise AssertionError(f"batch57 main stage is missing: {STAGE}")
    if not BASELINE.is_dir():
        raise AssertionError(f"batch56 baseline stage is missing: {BASELINE}")


def _runtime_paths() -> tuple[str, ...]:
    return tuple(dict.fromkeys(_batch56._runtime_paths() + _WAR_RUNTIME_PATHS))


def _require_runtime_files() -> tuple[str, ...]:
    paths = _runtime_paths()
    missing = [relative for relative in paths if not (ROOT / relative).is_file()]
    if missing:
        raise AssertionError("runtime source missing: " + ", ".join(missing))
    return paths


def _build_plan() -> dict[str, Any]:
    manifest_path = BUILD_DIR / "build-manifest.json"
    dll_path = BUILD_DIR / "eu4_bridge_diplomacy_observer_v28.dll"
    if not manifest_path.is_file() or not dll_path.is_file():
        raise AssertionError("v28-002 build manifest or DLL is missing")
    manifest = read_json(manifest_path, max_bytes=8 * 1024 * 1024)
    if manifest.get("version") != EXPECTED_BUILD_VERSION or manifest.get("compiled") is not True:
        raise AssertionError("v28-002 build manifest is not a successful version-28 build")
    if manifest.get("game_sha256") != EXPECTED_EXE_SHA256:
        raise AssertionError("v28-002 build target EXE SHA mismatch")
    sources = manifest.get("sources")
    if not isinstance(sources, list) or len(sources) != EXPECTED_BUILD_SOURCE_COUNT:
        raise AssertionError("v28-002 build source count is not 112")
    dll_sha = sha(dll_path)
    if manifest.get("dll_sha256") != dll_sha:
        raise AssertionError("v28-002 manifest/DLL SHA mismatch")
    source_pins: list[dict[str, Any]] = []
    for item in sources:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise AssertionError("v28-002 manifest has an invalid source item")
        source_path = BUILD_DIR / item["name"]
        if not source_path.is_file():
            raise AssertionError(f"v28-002 build source is missing: {item['name']}")
        current = pin(source_path)
        if current["sha256"] != item.get("sha256"):
            raise AssertionError(f"v28-002 build source changed: {item['name']}")
        source_pins.append(current)
    logs = []
    for name in ("build-v28-001.log", "build-v28-002.log"):
        path = STAGE / name
        if not path.is_file():
            raise AssertionError(f"build receipt missing: {name}")
        logs.append(pin(path))
    install_log = BUILD_DIR / "install-v28-002.log"
    if install_log.is_file():
        install_pin: dict[str, Any] | None = pin(install_log)
    else:
        install_pin = None
    return {
        "build_directory": BUILD_DIR.relative_to(ROOT).as_posix(),
        "version": manifest.get("version"),
        "compiled": manifest.get("compiled"),
        "runtime_verified": manifest.get("runtime_verified"),
        "game_sha256": manifest.get("game_sha256"),
        "dll": pin(dll_path),
        "manifest": pin(manifest_path),
        "source_count": len(source_pins),
        "source_files": source_pins,
        "build_logs": logs,
        "install_log": install_pin,
        "war_identity": {
            "enabled": manifest.get("information_battle_war_identity"),
            "wire_version": manifest.get("information_battle_war_identity_wire"),
            "scope": manifest.get("information_battle_war_identity_scope"),
            "read_only": manifest.get("information_battle_war_identity_read_only"),
            "complete": manifest.get("information_battle_war_identity_complete"),
        },
    }


def _source_pins() -> list[dict[str, Any]]:
    paths = [ROOT / relative for relative in _EXPLICIT_SOURCE_PATHS]
    for pattern in _SOURCE_GLOBS:
        paths.extend(ROOT.glob(pattern))
    paths.extend(ROOT / relative for relative in _BUILD_ARTIFACT_PATHS)
    unique = sorted({path for path in paths if path.is_file()}, key=lambda path: path.relative_to(ROOT).as_posix())
    required = {
        relative
        for relative in _EXPLICIT_SOURCE_PATHS
        if relative not in {"docs/战报战争编号接口.md"}
    }
    present = {path.relative_to(ROOT).as_posix() for path in unique}
    missing = sorted(required - present)
    if missing:
        raise AssertionError("batch57 source pin missing: " + ", ".join(missing))
    return [pin(path) for path in unique]


def _pin_before() -> int:
    _require_stage_and_baseline()
    before_path = STAGE / "runtime-source-pins-before-001.json"
    matrix_snapshot = STAGE / "coverage-matrix-before-001.json"
    if before_path.exists() or matrix_snapshot.exists():
        raise AssertionError("batch57 before pins or coverage snapshot already exists")
    runtime_paths = _require_runtime_files()
    matrix = ROOT / "docs/信息字段覆盖.json"
    if not matrix.is_file():
        raise AssertionError("coverage matrix is missing")
    baseline_after = BASELINE / "runtime-source-pins-after-001.json"
    if not baseline_after.is_file():
        raise AssertionError("batch56 after-pin receipt is missing")
    with matrix_snapshot.open("xb") as target, matrix.open("rb") as source:
        shutil.copyfileobj(source, target)
    build = _build_plan()
    source_files = _source_pins()
    write_json(
        before_path.name,
        {
            "schema": "information_runtime_source_pins.v1",
            "batch": BATCH,
            "baseline_stage": BASELINE.relative_to(ROOT).as_posix(),
            "baseline_after_pin": pin(baseline_after),
            "timing": "before batch57 live acceptance and formal full regression",
            "continuous_monitoring_claimed": False,
            "inherited_batch56_runtime_paths": len(_batch56._runtime_paths()),
            "runtime_paths": list(runtime_paths),
            "extension_runtime_paths": list(_WAR_RUNTIME_PATHS),
            "files": [pin(ROOT / relative) for relative in runtime_paths],
            "coverage_matrix_before": pin(matrix_snapshot),
            "v28_build_plan": build,
            "batch57_source_files": source_files,
        },
    )
    return 0


def _verify_before() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    before = read_json(STAGE / "runtime-source-pins-before-001.json")
    if before.get("batch") != BATCH:
        raise AssertionError("runtime source pin is not a batch57 pin")
    after: list[dict[str, Any]] = []
    for item in before.get("files", []):
        relative = item.get("path")
        if not isinstance(relative, str):
            raise AssertionError("runtime pin has an invalid path")
        path = ROOT / relative
        if not path.is_file():
            raise AssertionError(f"pinned runtime source disappeared: {relative}")
        current = pin(path)
        current["matches_before"] = current["sha256"] == item.get("sha256")
        after.append(current)
    if not after or not all(item["matches_before"] for item in after):
        raise AssertionError("a frozen batch57 runtime source changed")
    matrix_snapshot = STAGE / "coverage-matrix-before-001.json"
    if not matrix_snapshot.is_file():
        raise AssertionError("coverage matrix snapshot is missing")
    _build_plan()
    return before, after


def _live_report(*, required: bool = True) -> dict[str, Any] | None:
    path = STAGE / LIVE_DIRECTORY / "report.json"
    if not path.is_file():
        if required:
            raise AssertionError("batch57 live acceptance report is missing")
        return None
    report = read_json(path)
    exit_code = report.get("server_exit_code", report.get("server_exit"))
    if report.get("status") != "passed" or exit_code != 0:
        raise AssertionError("batch57 live acceptance is not passed/exit0")
    checks = report.get("checks")
    if isinstance(checks, dict) and not all(value is True for value in checks.values()):
        raise AssertionError("batch57 live acceptance contains a failed check")
    event_results = report.get("event_results")
    if isinstance(event_results, list):
        if not event_results:
            raise AssertionError("selected batch57 live acceptance has no event results")
    elif isinstance(event_results, int) and not isinstance(event_results, bool):
        if event_results <= 0:
            raise AssertionError("selected batch57 live acceptance has no event results")
    elif isinstance(event_results, Mapping):
        nested = event_results.get("results")
        if isinstance(nested, list) and not nested:
            raise AssertionError("selected batch57 live acceptance has no event results")
        if not event_results:
            raise AssertionError("selected batch57 live acceptance has no event results")
    else:
        raise AssertionError("selected batch57 live acceptance lacks event_results")
    return report


def _production_comparison(*, required: bool = True) -> dict[str, Any] | None:
    path = STAGE / PRODUCTION_COMPARISON_BASENAME
    if not path.is_file():
        if required:
            raise AssertionError("batch57 production comparison receipt is missing")
        return None
    value = read_json(path)
    if value.get("status") != "passed":
        raise AssertionError("batch57 production comparison is not passed")
    scope = value.get("scope")
    if not isinstance(scope, Mapping) or scope.get("fields") != ["B01.war_id"]:
        raise AssertionError("batch57 production comparison scope is broader than B01.war_id")
    if scope.get("full_B01_B04_claimed") is not False:
        raise AssertionError("batch57 production comparison must not claim full B01-B04")
    if value.get("offline_replay") is not True or value.get("producer_backfill") is not False:
        raise AssertionError("batch57 production comparison is not an offline non-backfill receipt")
    return value


def _case_key(case: ET.Element) -> str:
    return f"{case.get('classname')}::{case.get('name')}"


def _test_cases(path: Path) -> tuple[list[ET.Element], set[str], int]:
    root = ET.parse(path).getroot()
    cases = root.findall(".//testcase")
    bad = {_case_key(case) for case in cases if case.findall("failure") or case.findall("error")}
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
    boundary_path = STAGE / FULL_BOUNDARY_RECEIPT_BASENAME
    if not xml.is_file() or not log.is_file() or not baseline_xml.is_file() or not boundary_path.is_file():
        raise AssertionError("batch57 or batch56 formal regression receipt is missing")
    boundary = read_json(boundary_path)
    if boundary.get("runtime_functionality_proven") is not False:
        raise AssertionError("batch57 full boundary receipt must state that runtime functionality is unproven")
    cases, bad, occurrences = _test_cases(xml)
    old_cases, old_bad, old_occurrences = _test_cases(baseline_xml)
    current_keys = {_case_key(case) for case in cases}
    old_keys = {_case_key(case) for case in old_cases}
    added = sorted(current_keys - old_keys)
    removed = sorted(old_keys - current_keys)
    current_bad = {_case_key(case) for case in cases if case.findall("failure") or case.findall("error")}
    summary = _summary_line(log)
    added_bad = sum(
        len(case.findall("failure")) + len(case.findall("error"))
        for case in cases if _case_key(case) in set(added)
    )
    return {
        "full": {
            "command": "python -m pytest -q bridge/tests",
            "passed": _count(summary, "passed"),
            "failed": _count(summary, "failed"),
            "errors": _count(summary, "errors"),
            "subtests_passed": _count(summary, "subtests passed"),
            "summary_line": summary,
            "whole_suite_green": not bad,
            "failure_error_occurrences": occurrences,
            "unique_failure_error_nodes": len(bad),
            "new_failure_nodes": sorted(current_bad - old_bad),
            "resolved_failure_nodes": sorted(old_bad - current_bad),
            "xml": pin(xml),
            "log": pin(log),
            "execution_boundary": pin(boundary_path),
            "runtime_functionality_proven": False,
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
            "expected_batch56_summary": "2964 passed, 106 failed, 35 errors, 1894 subtests passed",
        },
        "current_case_count": len(cases),
        "case_set_changed": current_keys != old_keys,
    }


def _run_full() -> int:
    _require_stage_and_baseline()
    _verify_before()
    xml = STAGE / f"{REGRESSION_BASENAME}.xml"
    log = STAGE / f"{REGRESSION_BASENAME}.log"
    if xml.exists() or log.exists():
        raise AssertionError("batch57 formal regression receipts already exist")
    with log.open("x", encoding="utf-8", newline="\n") as stream:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "bridge/tests", "--junitxml", str(xml)],
            cwd=ROOT,
            stdout=stream,
            stderr=subprocess.STDOUT,
            check=False,
        )
    boundary = {
        "schema": "information_battle_war_identity_full_execution_boundary.v1",
        "batch": BATCH,
        "status": "completed_tests_runtime_unproven" if result.returncode == 0 else "completed_with_test_failures_runtime_unproven",
        "command": "python -m pytest -q bridge/tests",
        "exit_code": result.returncode,
        "junit_xml": pin(xml),
        "log": pin(log),
        "live_receipt_required_for_runtime_claim": True,
        "runtime_functionality_proven": False,
        "native_game_call": False,
        "note": "The formal bridge suite, including local native wire checks, does not establish successful v28 installation or live game behavior. The live acceptance phase remains a separate prerequisite for docs and archive.",
    }
    write_json(FULL_BOUNDARY_RECEIPT_BASENAME, boundary)
    print(f"formal batch57 full regression exit {result.returncode}")
    return result.returncode


def _topic_counts(topics: list[dict[str, Any]]) -> dict[str, Any]:
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


def _live_discovery() -> tuple[dict[str, Any], Path, dict[str, Any] | None, Path | None]:
    discovery_path = STAGE / LIVE_DIRECTORY / "discovery.json"
    discovery = read_json(discovery_path)
    topics = discovery.get("topics")
    if not isinstance(topics, list):
        raise AssertionError("batch57 live discovery topics are missing")
    catalog_path = STAGE / LIVE_DIRECTORY / "catalog.json"
    catalog = read_json(catalog_path) if catalog_path.is_file() else None
    return discovery, discovery_path, catalog, catalog_path if catalog_path.is_file() else None


def _topic_by_id(topics: list[Any], topic_id: str) -> dict[str, Any]:
    matches = [topic for topic in topics if isinstance(topic, dict) and topic.get("topic_id") == topic_id]
    if len(matches) != 1:
        raise AssertionError(f"live discovery must contain exactly one {topic_id} topic")
    return matches[0]


def _merge_battle_metadata(
    before: dict[str, Any], live_topics: list[Any]
) -> tuple[dict[str, Any], list[str], list[dict[str, Any]]]:
    merged = deepcopy(before)
    before_topics = merged.get("topics")
    if not isinstance(before_topics, list):
        raise AssertionError("coverage snapshot topics are missing")
    live_by_id = {topic.get("topic_id"): topic for topic in live_topics if isinstance(topic, dict)}
    configured_by_id = {topic.get("topic_id"): topic for topic in before_topics if isinstance(topic, dict)}
    changes: list[str] = []
    field_coverage_changes: list[dict[str, Any]] = []
    metadata_keys = (
        "catalog_ids", "title", "topic_id", "object_types", "parameters", "source",
        "status", "supported_versions", "triggers", "visibility", "observer_roles",
        "observer_scope", "context_scope", "scope_note", "change_detection", "adapter_sources",
    )
    for topic_id in BATTLE_METADATA_TOPICS:
        target = configured_by_id.get(topic_id)
        live_topic = live_by_id.get(topic_id)
        if not isinstance(target, dict) or not isinstance(live_topic, dict):
            raise AssertionError(f"live/configured discovery is missing {topic_id}")
        for key in metadata_keys:
            if key not in live_topic:
                continue
            next_value = deepcopy(live_topic[key])
            # A battle-on discovery may report the topic as available while
            # its fields are still partial.  The configured matrix must not
            # promote an existing planned topic from that observation.
            if key == "status" and next_value == "available":
                # A battle-on observation may expose callable source metadata,
                # but this batch is not allowed to promote a B01-B04 topic to
                # available.  Keep the configured matrix at partial until a
                # later batch proves the complete public contract.
                next_value = "partial"
            if target.get(key) != next_value:
                target[key] = next_value
                changes.append(f"{topic_id}.{key}")
        before_fields = target.get("fields")
        live_fields = live_topic.get("fields")
        if not isinstance(before_fields, dict) or not isinstance(live_fields, dict):
            raise AssertionError(f"{topic_id} fields missing from configured/live discovery")
        if set(before_fields) != set(live_fields):
            raise AssertionError(f"{topic_id} field names differ between configured/live discovery")
        for field_name, live_descriptor in live_fields.items():
            if not isinstance(live_descriptor, dict):
                raise AssertionError(f"live {topic_id}.{field_name} descriptor is invalid")
            if live_descriptor.get("complete") is True:
                raise AssertionError(f"live {topic_id}.{field_name} cannot promote complete=true")
            old = before_fields[field_name]
            if not isinstance(old, dict):
                raise AssertionError(f"configured {topic_id}.{field_name} is invalid")
            old_coverage = old.get("coverage", "planned")
            live_coverage = live_descriptor.get("coverage", old_coverage)
            if live_coverage not in {"planned", "partial", "available"}:
                raise AssertionError(f"unexpected live coverage {topic_id}.{field_name}: {live_coverage}")
            next_coverage = old_coverage
            if old_coverage == "planned" and live_coverage in {"partial", "available"}:
                next_coverage = "partial"
                field_coverage_changes.append({
                    "topic_id": topic_id,
                    "field": field_name,
                    "before": old_coverage,
                    "live": live_coverage,
                    "after": next_coverage,
                    "complete_before": bool(old.get("complete", False)),
                    "complete_after": False,
                    "reason": "planned_to_partial_battle_on_source",
                })
            elif old_coverage == "partial":
                next_coverage = "partial"
            elif old_coverage == "available":
                next_coverage = "available"
            next_descriptor = deepcopy(live_descriptor)
            next_descriptor["coverage"] = next_coverage
            # The B01-B04 fields expose source metadata only in this batch;
            # none of them is complete yet.
            next_descriptor["complete"] = False
            if next_descriptor != old:
                before_fields[field_name] = next_descriptor
                changes.append(f"{topic_id}.fields.{field_name}")
    # The other seventy topics must remain byte-for-byte equal in the merged
    # configured matrix.  This also prevents mission/configuration changes
    # from being mistaken for this battle-on update.
    before_other = {t.get("topic_id"): t for t in before_topics if isinstance(t, dict) and t.get("topic_id") not in BATTLE_METADATA_TOPICS}
    after_other = {t.get("topic_id"): t for t in merged.get("topics", []) if isinstance(t, dict) and t.get("topic_id") not in BATTLE_METADATA_TOPICS}
    if before_other != after_other:
        raise AssertionError("coverage merge changed a non-B01-B04 topic")
    return merged, changes, field_coverage_changes


def _validate_coverage_receipt(coverage: Mapping[str, Any]) -> None:
    if coverage.get("scope_counts_fixed") != {"topics": 74, "fields": 397}:
        raise AssertionError("coverage receipt scope is not 74/397")
    for key in ("configured_counts", "actual_live_counts"):
        counts = coverage.get(key)
        if not isinstance(counts, Mapping) or counts.get("topic_count") != 74 or counts.get("field_count") != 397:
            raise AssertionError(f"coverage receipt lacks separate 74/397 {key}")
    allowed = set(BATTLE_METADATA_TOPICS)
    for change in coverage.get("metadata_changes", []):
        if not isinstance(change, str) or change.split(".", 1)[0] not in allowed:
            raise AssertionError("coverage metadata change escaped B01-B04")
    for change in coverage.get("field_coverage_changes", []):
        if not isinstance(change, Mapping) or change.get("topic_id") not in allowed:
            raise AssertionError("coverage field change escaped B01-B04")
        if change.get("before") != "planned" or change.get("after") != "partial":
            raise AssertionError("coverage field change is not planned-to-partial")
        if change.get("complete_after") is not False:
            raise AssertionError("coverage field change promoted complete=true")
    if coverage.get("coverage_changes_allowed") is not True:
        raise AssertionError("coverage receipt lacks its bounded change declaration")
    live_field_coverage = coverage.get("actual_live_field_coverage")
    if not isinstance(live_field_coverage, Mapping):
        raise AssertionError("coverage receipt lacks actual live field coverage")


def _coverage() -> int:
    _require_stage_and_baseline()
    _verify_before()
    _live_report(required=True)
    before_path = STAGE / "coverage-matrix-before-001.json"
    matrix_path = ROOT / "docs/信息字段覆盖.json"
    if not before_path.is_file() or not matrix_path.is_file():
        raise AssertionError("batch57 coverage inputs are missing")
    discovery, discovery_path, catalog, catalog_path = _live_discovery()
    before = read_json(before_path)
    topics = discovery.get("topics")
    if not isinstance(topics, list):
        raise AssertionError("live discovery topics are missing")
    for topic_id in BATTLE_METADATA_TOPICS:
        _topic_by_id(topics, topic_id)
    merged, metadata_changes, field_coverage_changes = _merge_battle_metadata(before, topics)
    if not metadata_changes:
        raise AssertionError("live B01-B04 metadata did not produce a coverage update")
    before_counts = _topic_counts(before.get("topics", []))
    after_counts = _topic_counts(merged.get("topics", []))
    actual_counts = _topic_counts(topics)
    if before_counts["topic_count"] != 74 or before_counts["field_count"] != 397:
        raise AssertionError("configured baseline must remain the 74/397 scope")
    if after_counts["topic_count"] != 74 or after_counts["field_count"] != 397:
        raise AssertionError("configured matrix must remain the 74/397 scope")
    if actual_counts["topic_count"] != 74 or actual_counts["field_count"] != 397:
        raise AssertionError("live discovery must remain the 74/397 scope")
    before_field_coverage = {
        (topic.get("topic_id"), name): descriptor.get("coverage")
        for topic in before.get("topics", [])
        for name, descriptor in topic.get("fields", {}).items()
    }
    after_field_coverage = {
        (topic.get("topic_id"), name): descriptor.get("coverage")
        for topic in merged.get("topics", [])
        for name, descriptor in topic.get("fields", {}).items()
    }
    actual_field_coverage = {
        (topic.get("topic_id"), name): descriptor.get("coverage")
        for topic in topics
        for name, descriptor in topic.get("fields", {}).items()
    }
    for key, old_coverage in before_field_coverage.items():
        new_coverage = after_field_coverage.get(key)
        if key[0] in BATTLE_METADATA_TOPICS:
            if old_coverage == "planned" and new_coverage not in {"planned", "partial"}:
                raise AssertionError(f"{key} was promoted beyond partial")
        elif old_coverage != new_coverage:
            raise AssertionError(f"non-B01-B04 field coverage changed: {key}")
    matrix_before_sha = sha(matrix_path)
    _atomic_write_text(matrix_path, json.dumps(merged, ensure_ascii=False, indent=2) + "\n")
    receipt = {
        "schema": "information_battle_war_identity_coverage_update.v1",
        "batch": BATCH,
        "goal_complete": False,
        "goal_status": "active",
        "before_sha256": sha(before_path),
        "after_sha256": sha(matrix_path),
        "configured_counts": after_counts,
        "actual_live_counts": actual_counts,
        "scope_counts_fixed": {"topics": 74, "fields": 397},
        "metadata_changes": metadata_changes,
        "field_coverage_changes": field_coverage_changes,
        "coverage_status_unchanged": not bool(field_coverage_changes),
        "coverage_changes_allowed": True,
        "actual_live_field_coverage": {f"{topic_id}.{field}": value for (topic_id, field), value in actual_field_coverage.items()},
        "sources": {
            "live_discovery": pin(discovery_path),
            "live_catalog": pin(catalog_path) if catalog_path is not None else None,
        },
        "note": "B01-B04 source metadata is synchronized from the battle-on live/catalog result. Configured fields may move from planned to partial, never to available, and all four topics remain incomplete.",
    }
    write_json(COVERAGE_RECEIPT_BASENAME, receipt)
    print(json.dumps(receipt, ensure_ascii=False))
    return 0


def _live_identity(live: Mapping[str, Any]) -> tuple[str, Any, str]:
    identity = live.get("identity") if isinstance(live.get("identity"), Mapping) else {}
    binding = live.get("binding") if isinstance(live.get("binding"), Mapping) else {}
    event_binding = live.get("event_binding") if isinstance(live.get("event_binding"), Mapping) else {}
    session = (
        live.get("session_id")
        or identity.get("session_id")
        or identity.get("installation_session_id")
        or binding.get("session_id")
        or event_binding.get("session_id")
        or "unknown"
    )
    game_date: Any = live.get("game_date") or identity.get("game_date")
    after_control_path = STAGE / LIVE_DIRECTORY / "after-control.json"
    if after_control_path.is_file():
        after_control = read_json(after_control_path)
        if isinstance(after_control, Mapping) and after_control.get("date_raw") is not None:
            game_date = after_control.get("date_raw")
    if game_date is None:
        game_date = "unknown"
    observer = live.get("observer") or identity.get("observer") or binding.get("observer") or event_binding.get("observer") or "FRA"
    return str(session), game_date, str(observer)


def _war_result_sentence(live: Mapping[str, Any], production: Mapping[str, Any]) -> str:
    for document in (production, live):
        result = document.get("result") if isinstance(document.get("result"), Mapping) else document.get("war_identity")
        if isinstance(result, Mapping):
            status = result.get("status") or result.get("value_status")
            if status:
                return f"当前外交 `war_id` 结果状态为 `{status}`。"
    return "当前外交 `war_id` 结果以实机收据中的 session-scoped 记录为准。"


def _selected_b01_query_facts() -> dict[str, Any]:
    query_path = STAGE / LIVE_DIRECTORY / "query.json"
    query = read_json(query_path)
    items = query.get("items") if isinstance(query, Mapping) else None
    if not isinstance(items, list):
        raise AssertionError("selected live B01 query items are missing")
    matches = [
        item for item in items
        if isinstance(item, Mapping)
        and isinstance(item.get("query"), Mapping)
        and item["query"].get("topic") == "B01"
    ]
    if len(matches) != 1:
        raise AssertionError("selected live B01 query is not unique")
    item = matches[0]
    query_meta = item["query"]
    fields = item.get("fields")
    if not isinstance(fields, Mapping):
        raise AssertionError("selected live B01 fields are missing")
    war_field = fields.get("war_id")
    if not isinstance(war_field, Mapping) or war_field.get("status") != "known":
        raise AssertionError("selected live B01 war_id is not known")
    sides_field = fields.get("sides")
    sides = sides_field.get("value") if isinstance(sides_field, Mapping) else None
    participants: list[str] = []
    representatives: list[str] = []
    if isinstance(sides, list):
        for side in sides:
            if not isinstance(side, Mapping):
                continue
            values = side.get("participants")
            if isinstance(values, list):
                participants.extend(str(value) for value in values)
            representative = side.get("representative")
            if isinstance(representative, str):
                representatives.append(representative)
    parameters = query_meta.get("parameters") if isinstance(query_meta, Mapping) else {}
    event_id = parameters.get("event_id") if isinstance(parameters, Mapping) else None
    if not isinstance(event_id, str) or not event_id:
        raise AssertionError("selected live B01 event_id is missing")
    return {
        "request_id": query.get("request_id"),
        "event_id": event_id,
        "war_id": war_field.get("value"),
        "fields": list(query_meta.get("fields", [])) if isinstance(query_meta.get("fields"), list) else [],
        "participants": participants,
        "representatives": representatives,
    }


def _doc_text(live: dict[str, Any], production: dict[str, Any], comparison: dict[str, Any], coverage: dict[str, Any]) -> str:
    session, game_date, observer = _live_identity(live)
    query_facts = _selected_b01_query_facts()
    full = comparison["full"]
    configured = coverage["configured_counts"]["field_counts"]
    actual = coverage["actual_live_counts"]["field_counts"]
    event_results = live.get("event_results", [])
    if isinstance(event_results, list):
        event_count: Any = len(event_results)
    elif isinstance(event_results, int) and not isinstance(event_results, bool):
        event_count = event_results
    elif isinstance(event_results, Mapping):
        nested = event_results.get("results")
        event_count = len(nested) if isinstance(nested, list) else len(event_results)
    else:
        event_count = "unknown"
    event_date = live.get("independent_wire_reference", {}).get("raw_date") if isinstance(live.get("independent_wire_reference"), Mapping) else "unknown"
    war_id = query_facts["war_id"]
    event_id = query_facts["event_id"]
    participants = ", ".join(dict.fromkeys(query_facts["participants"])) or "unknown"
    representatives = ", ".join(dict.fromkeys(query_facts["representatives"])) or "unknown"
    fields = ", ".join(query_facts["fields"])
    return f'''# 战报战争编号接口

本接口读取观察国在当前游戏会话中可见的外交战报结果，并返回外交信息模型中的 `war_id` 字段。当前原生来源证明该编号与外交共享 registry 在 observer session 内一致；跨会话稳定性、对象 generation 和 cross-save 绑定仍未证实。

## 当前能力

当前批次的实机收据状态为 `{live.get('status')}`，服务器退出码为 `{live.get('server_exit_code', live.get('server_exit', 'unknown'))}`；生产比较收据为 `{production.get('status')}`。{_war_result_sentence(live, production)}主动查询、报告和事件结果都复用相同的只读会话绑定；实机收据记录了 {event_count} 条事件结果。

本次观察器绑定 session `{session}`、当前 game date `{game_date}`、观察国 `{observer}`；事件自身的 raw date 为 `{event_date}`，二者是不同语义。样本的外交 `war_id` 为 `{war_id}`；FRA 是参战方之一，完整参战国为 `{participants}`，双方结果代表为 `{representatives}`。新的 session、进程或 EXE 绑定需要重新查询当前状态；这不会改写事件自身的历史日期。公开接口读取已采集的战报，不提交外交动作。

## 查询示例

```json
{{
  "request_id": "b01-war-identity-example-001",
  "queries": [{{
    "topic": "B01",
    "object": {{"type": "battle"}},
    "parameters": {{"event_id": "{event_id}"}},
    "fields": [{', '.join(json.dumps(field, ensure_ascii=False) for field in query_facts['fields'])}]
  }}]
}}
```

返回结果中的外交 `war_id` 只在本次 observer session 内有效。它不是新造的 native integer，也不能据此推出跨 session 或 cross-save 的稳定身份。`status: "known"` 表示本次读取通过了身份、代码守卫和当前上下文检查；如果战争引用、双方关系行或结果对象无法绑定，接口返回 `unknown` 或 `partial`，不会用历史存档或相邻战争记录补齐缺失字段。

战争两侧保留原生顺序。双方国家 fullref 用于核对当前国家表中的槽位；fullref 不等同于稳定标签，也不能单独推出战争结束日期、胜者或结果文本。

## 覆盖与边界

本批覆盖矩阵仍为 74 个主题、397 个字段。配置矩阵当前按本批 live/catalog 结果计算为 available/partial/planned = `{configured.get('available', 0)}`/`{configured.get('partial', 0)}`/`{configured.get('planned', 0)}`；live discovery 为 `{actual.get('available', 0)}`/`{actual.get('partial', 0)}`/`{actual.get('planned', 0)}`。B01、B02、B03、B04 均保持 `partial` 且 `complete: false`；本次样本只证明 B01 的 `war_id`，B02–B04 的完整战报结果仍未实现。目录中仍为 `planned` 或 `unsupported` 的额外字段保持原状态，不因事件原始字节而升级。

外交 `war_id` 当前仍是 session-scoped；稳定公共编号、对象 generation/cross-save 绑定、跨会话去重、完整战争历史、战争名称的本地化绑定和 B01–B04 完整结果尚未闭合。

## 来源与验证收据

- 实机：[`{LIVE_DIRECTORY}/report.json`](../work/runtime/information-battle-war-identity-20261027-001/{LIVE_DIRECTORY}/report.json)
- 事件：[`{LIVE_DIRECTORY}/event-results.json`](../work/runtime/information-battle-war-identity-20261027-001/{LIVE_DIRECTORY}/event-results.json)
- 原始主动查询：[`live-acceptance-003/query.json`](../work/runtime/information-battle-war-identity-20261027-001/live-acceptance-003/query.json)
- 报告查询：[`live-acceptance-004/report-query.json`](../work/runtime/information-battle-war-identity-20261027-001/live-acceptance-004/report-query.json)
- 生产比较：[`{PRODUCTION_COMPARISON_BASENAME}`](../work/runtime/information-battle-war-identity-20261027-001/{PRODUCTION_COMPARISON_BASENAME})
- 回归：[`{REGRESSION_BASENAME}.xml`](../work/runtime/information-battle-war-identity-20261027-001/{REGRESSION_BASENAME}.xml)、[`{REGRESSION_BASENAME}.log`](../work/runtime/information-battle-war-identity-20261027-001/{REGRESSION_BASENAME}.log)，结果为 {full['passed']} passed、{full['failed']} failed、{full['errors']} errors。
- 覆盖：[`{COVERAGE_RECEIPT_BASENAME}`](../work/runtime/information-battle-war-identity-20261027-001/{COVERAGE_RECEIPT_BASENAME})
- 原生合同：[`war-binding-contract-001.json`](../work/runtime/information-battle-war-identity-20261027-001/war-binding-contract-001.json)
'''


def _docs() -> int:
    _require_stage_and_baseline()
    _verify_before()
    live = _live_report(required=True)
    production = _production_comparison(required=True)
    comparison = _regression_comparison()
    coverage = read_json(STAGE / COVERAGE_RECEIPT_BASENAME)
    _validate_coverage_receipt(coverage)
    target = ROOT / "docs/战报战争编号接口.md"
    _atomic_write_text(target, _doc_text(live, production, comparison, coverage))
    receipt = {
        "schema": "information_battle_war_identity_document_verification.v1",
        "batch": BATCH,
        "status": "passed",
        "document": pin(target),
        "live_acceptance": pin(STAGE / LIVE_DIRECTORY / "report.json"),
        "production_comparison": pin(STAGE / PRODUCTION_COMPARISON_BASENAME),
        "full_comparison": comparison,
        "coverage_receipt": pin(STAGE / COVERAGE_RECEIPT_BASENAME),
        "new_game_queries_or_pytest_runs": 0,
        "checks": {
            "live_receipt_passed": True,
            "production_comparison_passed": True,
            "full_receipt_completed": True,
            "coverage_changes_bounded_to_b01_b04": True,
            "session_scope_and_unknown_boundaries_documented": True,
            "document_status_derived_from_receipts": True,
        },
    }
    write_json(DOCUMENT_RECEIPT_BASENAME, receipt)
    return 0


def _current_source_paths() -> tuple[Path, ...]:
    paths = [ROOT / relative for relative in _EXPLICIT_SOURCE_PATHS]
    for pattern in _SOURCE_GLOBS:
        paths.extend(ROOT.glob(pattern))
    paths.extend(ROOT / relative for relative in _BUILD_ARTIFACT_PATHS)
    return tuple(sorted({path for path in paths if path.is_file()}, key=lambda path: path.relative_to(ROOT).as_posix()))


def _source_snapshot_paths() -> tuple[Path, ...]:
    paths = [path for path in _current_source_paths() if path.stat().st_size <= MAX_SOURCE_SNAPSHOT_BYTES]
    required = {
        "bridge/information/battle_ingest.py",
        "bridge/information/battles.py",
        "work/native/information-battle-war-binding.h",
        "work/native/information-battle-war-identity-wire.h",
        "work/native/diplomacy-observer-v10.cpp",
        "work/native/information-battle-observer.inc",
        "tools/start_diplomacy_observer.py",
        "tools/control_information_battle_observer.py",
        "work/replay_information_battle_war_binding.py",
        "work/finalize_information_battle_war_identity.py",
        "docs/战报战争编号接口.md",
    }
    present = {path.relative_to(ROOT).as_posix() for path in paths}
    if not required <= present:
        raise AssertionError("batch57 source snapshot is missing core source: " + ", ".join(sorted(required - present)))
    return tuple(dict.fromkeys(paths))


def _stage_artifacts() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for path in sorted(STAGE.rglob("*"), key=lambda item: item.relative_to(ROOT).as_posix()):
        if not path.is_file() or "source-snapshot" in path.parts:
            continue
        item = pin(path)
        item["snapshot"] = None
        item["snapshot_policy"] = "artifact_pin_only_large" if path.stat().st_size > MAX_SOURCE_SNAPSHOT_BYTES else "eligible_for_bounded_reference"
        result.append(item)
    return result


def _current_runtime_identity(live: Mapping[str, Any]) -> dict[str, Any]:
    installation_path = BUILD_DIR / "installation.json"
    installation = read_json(installation_path)
    binding = live["binding"]
    control = read_json(STAGE / LIVE_DIRECTORY / "after-control.json")
    if installation["session_id"] != binding["session_id"] or installation["creation_filetime"] != binding["process_creation_filetime"]:
        raise AssertionError("selected live and installation process identities differ")
    return {
        "installation": pin(installation_path), "pid": installation["pid"],
        "creation": installation["creation_filetime"], "session_id": installation["session_id"],
        "game_date": control["date_raw"], "physical_player": "POR", "observer": binding["observer"],
        "executable_version": "1.37.4", "executable_sha256": installation["game_sha256"],
        "dll_sha256": installation["dll_sha256"], "native_sources": 112, "wire_version": 5,
        "read_only": False, "information_queries_read_only": True,
        "save_or_reload": True, "dll_install": True, "date_advance": True,
        "business_dispatch": False, "rea_attempted": False,
        "control_proof": pin(STAGE / LIVE_DIRECTORY / "after-control.json"),
        "action_scope": "batch57 checkpoint/restart/install and two new natural observation windows; no diplomacy dispatch",
    }


def _archive() -> int:
    _require_stage_and_baseline()
    before, after = _verify_before()
    live = _live_report(required=True)
    production = _production_comparison(required=True)
    coverage_path = STAGE / COVERAGE_RECEIPT_BASENAME
    document_path = STAGE / DOCUMENT_RECEIPT_BASENAME
    if not coverage_path.is_file() or not document_path.is_file():
        raise AssertionError("batch57 coverage/document receipts are missing")
    coverage = read_json(coverage_path)
    document = read_json(document_path)
    _validate_coverage_receipt(coverage)
    if document.get("status") != "passed" or document.get("new_game_queries_or_pytest_runs") != 0:
        raise AssertionError("batch57 document verification is not receipt-backed")
    comparison = _regression_comparison()
    if comparison["full"]["new_failure_nodes"]:
        raise AssertionError("batch57 introduced failure/error nodes")
    if comparison["new_or_renamed_tests"]["failure_error_occurrences"]:
        raise AssertionError("a new or renamed batch57 test failed")
    after_path = STAGE / "runtime-source-pins-after-001.json"
    if after_path.exists():
        raise AssertionError("batch57 archive already exists")
    write_json(
        after_path.name,
        {
            "schema": "information_runtime_source_pins.v1",
            "batch": BATCH,
            "files": after,
            "all_match_before": True,
            "timing": "after batch57 live acceptance and formal full regression",
            "continuous_monitoring_claimed": False,
        },
    )
    write_json("regression-comparison-001.json", comparison)
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
    previous = {}
    previous_path = BASELINE / "development-summary-001.json"
    if previous_path.is_file():
        previous = read_json(previous_path)
    current_sources = _current_source_paths()
    large_source_pins = [pin(path) for path in current_sources if path.stat().st_size > MAX_SOURCE_SNAPSHOT_BYTES]
    summary_path = write_json(
        "development-summary-001.json",
        {
            "schema": "information_development_summary.v1",
            "batch": BATCH,
            "status": "implemented_battle_war_identity_session_scoped_partial",
            "objective": previous.get("objective", "按照docs\\信息导出与订阅开发计划.md进行开发。"),
            "stage_objective": "B01 当前外交战报 war_id 只读接线与 session 绑定",
            "goal_complete": False,
            "goal_status": "active",
            "scope": {
                "topics": 74,
                "fields": 397,
                "B01": "partial_source_metadata_incomplete",
                "B02_B04": "partial_source_metadata_incomplete",
                "full_B01_B04": False,
                "stable_public_war_id": False,
            },
            "delivered": {
                "session_scoped_war_id": True,
                "wire_version": 5,
                "coverage_changes_bounded_to_b01_b04": True,
                "complete": False,
            },
            "runtime_validation": live,
            "production_comparison": production,
            "documentation_validation": document,
            "coverage": coverage,
            "coverage_counts": {
                "configured": deepcopy(coverage.get("configured_counts")),
                "actual_live": deepcopy(coverage.get("actual_live_counts")),
            },
            "tests": {"formal_full": comparison["full"], "new_or_renamed_tests": comparison["new_or_renamed_tests"], "counts_not_additive": True},
            "runtime_identity": _current_runtime_identity(live),
            "source_layers": {
                "source_001": pin(STAGE / "source-001.json"),
                "source_002": pin(STAGE / "source-002.json"),
                "war_binding_contract": pin(STAGE / "war-binding-contract-001.json"),
                "war_binding_fixture": pin(BINDING_STAGE / "war-binding-fixture-001.json"),
                "war_binding_replay": pin(BINDING_STAGE / "war-binding-replay-001.json"),
                "v28_build_manifest": pin(BUILD_DIR / "build-manifest.json"),
                "v28_dll": pin(BUILD_DIR / "eu4_bridge_diplomacy_observer_v28.dll"),
                "large_files_not_copied": True,
            },
            "source_snapshot": snapshots,
            "source_snapshot_policy": {"bounded_max_bytes": MAX_SOURCE_SNAPSHOT_BYTES, "large_source_artifact_pins": large_source_pins, "large_files_not_copied": True},
            "stage_artifacts": _stage_artifacts(),
            "baseline": {"stage": BASELINE.relative_to(ROOT).as_posix(), "regression": comparison["baseline"]},
            "next_work": {
                "stable_public_war_id": "unresolved",
                "B01_B04_full_results": "active",
                "goal": "active",
            },
            "no_repeat": {"historical_actions_and_original_final_pass_ids": "not retried", "business_actions_submitted": live.get("business_actions_submitted")},
        },
    )
    archive = {
        "schema": "information_battle_war_identity_archive_verification.v1",
        "batch": BATCH,
        "status": "passed",
        "summary": pin(summary_path),
        "runtime_source_pins_after": pin(after_path),
        "regression_comparison": pin(STAGE / "regression-comparison-001.json"),
        "source_snapshot_count": len(snapshots),
        "stage_artifact_count": len(_stage_artifacts()),
        "large_source_pin_count": len(large_source_pins),
        "large_reference_policy": "streaming_hash_and_pin_only",
        "checks": {
            "live_receipt_passed": True,
            "production_comparison_passed": True,
            "coverage_changes_bounded_to_b01_b04": True,
            "new_failure_nodes_empty": comparison["full"]["new_failure_nodes"] == [],
            "new_or_renamed_test_failures": False,
            "old_baseline_debt_preserved": (
                comparison["full"]["failure_error_occurrences"] == comparison["baseline"]["failure_error_occurrences"]
                and comparison["full"]["unique_failure_error_nodes"] == comparison["baseline"]["unique_failure_error_nodes"]
            ),
            "source_snapshot_bounded": True,
            "goal_active": True,
        },
    }
    write_json("archive-verification-001.json", archive)
    print(json.dumps({"summary": pin(summary_path), "archive": archive, "source_snapshots": len(snapshots)}, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Batch57 battle-war identity finalizer; explicit phase only.")
    phases = parser.add_mutually_exclusive_group()
    phases.add_argument("--freeze", action="store_true", help="pin batch57 sources, v28 build, and original coverage bytes")
    phases.add_argument("--full", action="store_true", help="run exactly python -m pytest -q bridge/tests")
    phases.add_argument("--coverage", action="store_true", help="synchronize B01 metadata from this batch's live/catalog discovery")
    phases.add_argument("--docs", action="store_true", help="write the live-backed battle-war identity document")
    phases.add_argument("--archive", action="store_true", help="verify receipts and create the bounded batch57 archive")
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
