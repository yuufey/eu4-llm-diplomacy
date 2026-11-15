"""Freeze and verify the v32 passive battle-gate trace source and regression run.

This metadata-only helper reads source files, retained JUnit XML, and explicit
manifest pins.  Its ``full`` phase runs the Python bridge test suite once; no
phase builds a DLL or contacts EU4, RPM, MCP, or a native observer endpoint.
The helper itself and its C++ fixture runner are pinned separately as metadata.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import start_diplomacy_observer as _start  # noqa: E402


STAGE = ROOT / "work/runtime/information-battle-gate-trace-20261028-001"
BASELINE_STAGE = ROOT / "work/runtime/information-battle-recipient-20261028-001"
BASELINE_FREEZE = BASELINE_STAGE / "source-freeze-001.json"
BASELINE_FULL = BASELINE_STAGE / "regression-full-001.xml"
BASELINE_COMPARISON = BASELINE_STAGE / "regression-comparison-001.json"
BASELINE_POSTVERIFY = BASELINE_STAGE / "source-post-run-verification-001.json"
REVIEW_PATH = STAGE / "verification-helper-review-002/review-002.json"
CHUNK_BYTES = 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_BATCH71_SOURCE_COUNT = 312
EXPECTED_V32_NATIVE_SOURCE_COUNT = 122
DEFAULT_PYTHON = Path(r"C:\Users\wangyufei\anaconda3\envs\research\python.exe")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

# Existing batch-71 sources with an explicitly reviewed v32 delta.  Any other
# difference from the pinned batch-71 source set blocks freeze and verify.
REVIEWED_EXISTING_PATHS = {
    "work/native/information-battle-observer.inc": "passive gate-trace instrumentation",
    "work/native/information-battle-entry-stub.S": "v32 passive gate-trace entry wiring",
    "work/native/entry-patch-transaction.inc": "v32 gate-trace patch transaction wiring",
    "work/native/build-diplomacy-observer.ps1": "v32 build flag, source and manifest wiring",
    "tools/start_diplomacy_observer.py": "v32 manifest/source validation",
    "tools/control_information_battle_observer.py": "v32 controller manifest acceptance",
    "work/probe_information_battle_installed.py": "v32 installed-artifact capability validation",
    "bridge/tests/test_start_diplomacy_observer_information_battle.py": "v32 start/build manifest tests",
    "bridge/tests/test_control_information_battle_observer.py": "v32 controller manifest tests",
    "work/tests/test_probe_information_battle_installed.py": "v32 installed-probe manifest tests",
}

REQUIRED_GATE_HEADERS = (
    "work/native/information-battle-owned-gate-inputs.h",
    "work/native/information-battle-gate-trace.h",
    "work/native/information-battle-gate-marker-entry-plan.h",
)
REQUIRED_GATE_CPP_TESTS = (
    "work/native/tests/information-battle-owned-gate-inputs-test.cpp",
    "work/native/tests/information-battle-gate-trace-test.cpp",
    "work/native/tests/information-battle-gate-marker-entry-plan-test.cpp",
    "work/native/tests/information-battle-gate-marker-abi-test.cpp",
)
OPTIONAL_GATE_FIXTURES = (
    "work/native/tests/information-battle-gate-marker-abi.S",
)
REQUIRED_PIPELINE_SOURCES = (
    "bridge/diplomacy.py",
    "work/observer_runtime_ready.py",
    "tools/serve_information.py",
)
REQUIRED_AUDIT_SOURCES = (
    "work/audit_information_battle_gate_trace.py",
    "bridge/tests/test_information_battle_gate_trace_audit.py",
)
OWNED_TRACE_RUNNER = (
    "work/runtime/information-battle-gate-trace-20261028-001/"
    "owned-trace-001/runner/run_owned_trace_test.py"
)
OWNED_TRACE_ATTEMPT_RUNNER = (
    "work/runtime/information-battle-gate-trace-20261028-001/"
    "owned-trace-001/runner/run_owned_trace_test_attempt004.py"
)
OWNED_TRACE_PASS_RECEIPTS = (
    "work/runtime/information-battle-gate-trace-20261028-001/"
    "owned-trace-001/receipt/attempt-004.json",
    "work/runtime/information-battle-gate-trace-20261028-001/"
    "owned-trace-001/receipt/attempt-004-output.jsonl",
    "work/runtime/information-battle-gate-trace-20261028-001/"
    "owned-trace-001/runner/attempt-004/information-battle-gate-trace-test.exe",
)
SEPARATE_METADATA_PATHS = (
    "work/verify_information_battle_gate_trace.py",
    "work/compare_information_battle_native_title_regression.py",
    OWNED_TRACE_RUNNER,
    OWNED_TRACE_ATTEMPT_RUNNER,
    *OWNED_TRACE_PASS_RECEIPTS,
    "work/runtime/information-battle-gate-trace-20261028-001/"
    "verification-helper-review-001/review-001.json",
    "work/runtime/information-battle-gate-trace-20261028-001/"
    "verification-helper-review-002/review-002.json",
    "work/runtime/information-battle-gate-trace-20261028-001/"
    "verification-helper-review-003/review-003.json",
)
GATE_MANIFEST_SOURCE_NAMES = (
    "information-battle-owned-gate-inputs.h",
    "information-battle-gate-trace.h",
    "information-battle-gate-marker-entry-plan.h",
)
FORBIDDEN_CURRENT_COUNTRY_SOURCES = frozenset(
    _start.INFORMATION_CURRENT_COUNTRY_CONTROL_ONLY_SOURCES
)


class VerificationError(RuntimeError):
    """Raised when a source, receipt, or phase contract is not satisfied."""


def _workspace_path(raw: str | Path) -> Path:
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    resolved = candidate.resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise VerificationError(f"path_outside_workspace:{raw}") from exc
    return resolved


def _relative(path: Path) -> str:
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def _pin(path: Path) -> dict[str, Any]:
    path = path.resolve(strict=True)
    if not path.is_file():
        raise VerificationError(f"not_a_file:{path}")
    before = path.stat()
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(CHUNK_BYTES):
            digest.update(chunk)
            size += len(chunk)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise VerificationError(f"file_changed_during_hash:{path}")
    return {"path": _relative(path), "bytes": size, "sha256": digest.hexdigest()}


def _read_json(path: Path) -> Any:
    if not path.is_file():
        raise VerificationError(f"missing_json:{path}")
    if path.stat().st_size > MAX_JSON_BYTES:
        raise VerificationError(f"json_over_bound:{path}")
    try:
        with path.open("r", encoding="utf-8-sig") as stream:
            return json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"invalid_json:{path}:{type(exc).__name__}") from exc


def _write_new(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except FileExistsError as exc:
        raise VerificationError(f"output_exists:{path}") from exc


def _copy_stream(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with source.open("rb") as src, target.open("xb") as dst:
            while chunk := src.read(CHUNK_BYTES):
                dst.write(chunk)
    except FileExistsError as exc:
        raise VerificationError(f"snapshot_exists:{target}") from exc


def _baseline_inputs(freeze_path: Path, full_path: Path,
                     comparison_path: Path,
                     postverify_path: Path) -> tuple[dict, dict, dict, dict]:
    freeze = _read_json(freeze_path)
    files = freeze.get("files")
    if (freeze.get("schema") != "information.battle_recipient.source_freeze.v1"
            or freeze.get("status") != "passed" or freeze.get("batch") != 71
            or freeze.get("count") != EXPECTED_BATCH71_SOURCE_COUNT
            or not isinstance(files, list) or len(files) != EXPECTED_BATCH71_SOURCE_COUNT):
        raise VerificationError("batch71_baseline_must_be_passed_312_source_freeze")

    seen: set[str] = set()
    reviewed_changes: list[dict[str, Any]] = []
    for item in files:
        source = item.get("source") if isinstance(item, dict) else None
        snapshot = item.get("snapshot") if isinstance(item, dict) else None
        if not isinstance(source, dict) or not isinstance(snapshot, dict):
            raise VerificationError("batch71_baseline_source_record_invalid")
        source_path = _workspace_path(source.get("path", ""))
        source_name = _relative(source_path)
        if source_name in seen:
            raise VerificationError(f"batch71_baseline_duplicate_source:{source_name}")
        seen.add(source_name)
        if (source.get("bytes") != snapshot.get("bytes")
                or source.get("sha256") != snapshot.get("sha256")):
            raise VerificationError(f"batch71_original_snapshot_pin_mismatch:{source_name}")
        if _pin(_workspace_path(snapshot.get("path", ""))) != snapshot:
            raise VerificationError(f"batch71_original_snapshot_changed:{source_name}")
        current = _pin(source_path)
        if current != source:
            reason = REVIEWED_EXISTING_PATHS.get(source_name)
            if reason is None:
                raise VerificationError(f"unreviewed_batch71_source_change:{source_name}")
            reviewed_changes.append({
                "path": source_name,
                "before": source,
                "after": current,
                "reason": reason,
            })

    comparison = _read_json(comparison_path)
    full_pin = _pin(full_path)
    comp_xml = comparison.get("current_xml")
    if (comparison.get("schema") != "information.battle_recipient.regression_comparison.v1"
            or comparison.get("no_new_bad") is not True
            or comparison.get("new_failure_nodes") != []
            or comparison.get("new_test_failures") != []
            or not isinstance(comp_xml, dict)
            or comp_xml.get("path") != _relative(full_path)
            or comp_xml.get("bytes") != full_pin["bytes"]
            or comp_xml.get("sha256") != full_pin["sha256"]):
        raise VerificationError("batch71_baseline_comparison_not_pinned_no_new_bad")

    postverify = _read_json(postverify_path)
    post_freeze = postverify.get("source_freeze")
    post_comparison = postverify.get("regression_comparison")
    full_execution = postverify.get("full_execution")
    if (postverify.get("schema") != "information.battle_recipient.source_post_run_verification.v1"
            or postverify.get("status") != "passed"
            or postverify.get("source_count") != EXPECTED_BATCH71_SOURCE_COUNT
            or postverify.get("current_sources_match_snapshots") is not True
            or postverify.get("baseline70_snapshots_match_original_pins") is not True
            or postverify.get("baseline70_no_new_bad") is not True
            or postverify.get("metadata_helpers_runtime_freeze_member") is not False
            or postverify.get("metadata_helpers_match_separate_pins") is not True
            or not isinstance(post_freeze, dict)
            or post_freeze != _pin(freeze_path)
            or not isinstance(post_comparison, dict)
            or post_comparison != _pin(comparison_path)
            or not isinstance(full_execution, dict)):
        raise VerificationError("batch71_baseline_postverify_mismatch")
    if _pin(_workspace_path(full_execution.get("path", ""))) != full_execution:
        raise VerificationError("batch71_baseline_full_execution_pin_mismatch")
    if postverify.get("regression_comparison") != _pin(comparison_path):
        raise VerificationError("batch71_baseline_postverify_comparison_pin_mismatch")

    baseline_pins = {
        "freeze": _pin(freeze_path),
        "full": full_pin,
        "comparison": _pin(comparison_path),
        "post_run_verification": _pin(postverify_path),
        "source_count": len(files),
        "no_new_bad": comparison["no_new_bad"],
        "reviewed_existing_changes": reviewed_changes,
    }
    return freeze, comparison, postverify, baseline_pins


def _validate_v32_manifest(manifest_path: Path) -> tuple[
        dict[str, Any], list[str], list[str], dict[str, Any]]:
    manifest_path = manifest_path.resolve(strict=True)
    manifest = _read_json(manifest_path)
    required_traits = {
        "version": 32,
        "compiled": True,
        "runtime_verified": False,
        "native_war_participants_query": True,
        "information_battle_research_lifecycle": True,
        "information_battle_context_wire": 2,
        "information_battle_owned_context": True,
        "information_battle_naval_wire": 3,
        "information_battle_owned_naval": True,
        "information_battle_template_wire": 4,
        "information_battle_owned_template": True,
        "information_battle_message_scope": True,
        "information_battle_formatter_container": True,
        "information_battle_template_extensions": [1, 2],
        "information_battle_war_identity": True,
        "information_battle_war_identity_wire": 5,
        "information_battle_war_identity_scope": "observer_session",
        "information_battle_war_identity_read_only": True,
        "information_battle_war_identity_complete": False,
        "information_battle_native_text": True,
        "information_battle_native_text_wire": 6,
        "information_battle_native_text_scope": "observer_session",
        "information_battle_native_text_read_only": True,
        "information_battle_native_text_complete": False,
        "information_battle_native_title_query": True,
        "information_battle_native_title_query_mode": "native_helper_owned_output",
        "information_battle_native_title_query_wire": 6,
        "information_battle_native_title_query_complete": False,
        "information_battle_gate_trace": True,
        "information_battle_gate_trace_protocol": "EU4-BATTLE-GATE-TRACE/1",
        "information_battle_gate_trace_runtime_verified": False,
    }
    for key, expected in required_traits.items():
        if manifest.get(key) != expected:
            raise VerificationError(f"build_manifest_trait_mismatch:{key}")
    if (any(key.startswith("current_country_control") for key in manifest)
            or any("host_fixture" in key.lower() for key in manifest)):
        raise VerificationError("current_country_control_manifest_fields_forbidden")
    if manifest.get("game_sha256") != EXPECTED_EXE_SHA256:
        raise VerificationError("build_manifest_game_sha_mismatch")
    dll_sha = manifest.get("dll_sha256")
    if not isinstance(dll_sha, str) or HEX64.fullmatch(dll_sha) is None:
        raise VerificationError("build_manifest_dll_sha_invalid")

    arguments = manifest.get("compiler_arguments")
    if (not isinstance(arguments, list)
            or "-DINFORMATION_BATTLE_GATE_TRACE=1" not in arguments
            or _start._has_compiler_define(arguments, "BRIDGE_CURRENT_COUNTRY_CONTROL")
            or _start._has_compiler_define(
                arguments, "INFORMATION_CURRENT_COUNTRY_HOST_FIXTURE")):
        raise VerificationError("v32_gate_trace_macro_or_forbidden_macro_mismatch")

    rows = manifest.get("sources")
    if not isinstance(rows, list) or len(rows) != EXPECTED_V32_NATIVE_SOURCE_COUNT:
        raise VerificationError("v32_manifest_native_source_count_mismatch")
    if tuple(_start.INFORMATION_BATTLE_GATE_TRACE_REQUIRED_SOURCES[-3:]) != GATE_MANIFEST_SOURCE_NAMES:
        raise VerificationError("gate_trace_source_contract_drift")

    source_names: list[str] = []
    native_paths: list[str] = []
    copy_paths: list[str] = []
    seen: set[str] = set()
    manifest_directory = manifest_path.parent.resolve()
    for row in rows:
        if not isinstance(row, dict):
            raise VerificationError("build_manifest_source_record_invalid")
        name, expected_sha = row.get("name"), row.get("sha256")
        if (not isinstance(name, str) or not name or Path(name).name != name
                or name in {".", ".."} or not isinstance(expected_sha, str)
                or HEX64.fullmatch(expected_sha) is None):
            raise VerificationError("build_manifest_source_path_or_hash_invalid")
        if name in seen:
            raise VerificationError(f"build_manifest_duplicate_source:{name}")
        seen.add(name)
        native_path = _workspace_path(f"work/native/{name}")
        copy_path = (manifest_directory / name).resolve()
        try:
            copy_path.relative_to(ROOT.resolve())
        except ValueError as exc:
            raise VerificationError(f"manifest_source_copy_outside_workspace:{name}") from exc
        if copy_path.parent != manifest_directory:
            raise VerificationError(f"manifest_source_copy_path_invalid:{name}")
        native_pin = _pin(native_path)
        copy_pin = _pin(copy_path)
        if native_pin["sha256"] != expected_sha:
            raise VerificationError(f"manifest_native_source_sha_mismatch:{name}")
        if copy_pin["sha256"] != expected_sha:
            raise VerificationError(f"manifest_source_copy_sha_mismatch:{name}")
        source_names.append(name)
        native_paths.append(native_pin["path"])
        copy_paths.append(copy_pin["path"])

    required_names = set(_start.INFORMATION_BATTLE_GATE_TRACE_REQUIRED_SOURCES)
    if not required_names.issubset(seen):
        raise VerificationError("v32_manifest_required_gate_or_inherited_sources_missing")
    if seen.intersection(FORBIDDEN_CURRENT_COUNTRY_SOURCES):
        raise VerificationError("v32_manifest_current_country_control_sources_forbidden")

    dll_value = manifest.get("dll")
    if not isinstance(dll_value, str) or not dll_value:
        raise VerificationError("build_manifest_dll_path_missing")
    dll_path = _workspace_path(dll_value)
    if (dll_path.name != "eu4_bridge_diplomacy_observer_v32.dll"
            or dll_path.parent != manifest_directory):
        raise VerificationError("build_manifest_dll_version_path_mismatch")
    dll_pin = _pin(dll_path)
    if dll_pin["sha256"] != dll_sha:
        raise VerificationError("build_manifest_dll_sha_mismatch")
    return manifest, native_paths, copy_paths, {
        "path": _pin(manifest_path),
        "source_count": len(source_names),
        "source_names": source_names,
        "dll": dll_pin,
    }


def _extra_runtime_paths() -> list[str]:
    paths = [*REQUIRED_GATE_HEADERS, *REQUIRED_GATE_CPP_TESTS,
             *REQUIRED_PIPELINE_SOURCES, *REQUIRED_AUDIT_SOURCES]
    for fixture in OPTIONAL_GATE_FIXTURES:
        if _workspace_path(fixture).is_file():
            paths.append(fixture)
    return paths


def _source_union(baseline: dict[str, Any], native_paths: list[str],
                  copy_paths: list[str]) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for item in baseline["files"]:
        name = _relative(_workspace_path(item["source"]["path"]))
        if name not in seen:
            names.append(name)
            seen.add(name)
    for name in (*native_paths, *copy_paths, *_extra_runtime_paths()):
        path = _workspace_path(name)
        _pin(path)
        normalized = _relative(path)
        if normalized not in seen:
            names.append(normalized)
            seen.add(normalized)
    return names


def _metadata_pins() -> list[dict[str, Any]]:
    return [_pin(_workspace_path(name)) for name in SEPARATE_METADATA_PATHS]


def freeze(revision: str, manifest_path: Path,
           baseline_freeze: Path, baseline_full: Path,
           baseline_comparison: Path, baseline_postverify: Path) -> int:
    output = STAGE / f"source-freeze-{revision}.json"
    snapshot_root = STAGE / f"source-snapshots-{revision}"
    if output.exists() or snapshot_root.exists():
        raise VerificationError("freeze_revision_already_used")
    baseline, old_comparison, _old_postverify, baseline_pins = _baseline_inputs(
        baseline_freeze, baseline_full, baseline_comparison, baseline_postverify)
    manifest, native_paths, copy_paths, build_info = _validate_v32_manifest(manifest_path)
    names = _source_union(baseline, native_paths, copy_paths)
    native_hashes = {
        path: _pin(_workspace_path(path))["sha256"] for path in native_paths
    }
    copy_hashes = {
        path: _pin(_workspace_path(path))["sha256"] for path in copy_paths
    }

    files: list[dict[str, Any]] = []
    for name in names:
        source = _workspace_path(name)
        before = _pin(source)
        if name in native_hashes and before["sha256"] != native_hashes[name]:
            raise VerificationError(f"manifest_source_changed_before_snapshot:{name}")
        if name in copy_hashes and before["sha256"] != copy_hashes[name]:
            raise VerificationError(f"manifest_copy_changed_before_snapshot:{name}")
        snapshot = snapshot_root / Path(name)
        _copy_stream(source, snapshot)
        copied = _pin(snapshot)
        after = _pin(source)
        if copied["sha256"] != before["sha256"] or after != before:
            raise VerificationError(f"source_snapshot_race_or_mismatch:{name}")
        files.append({"source": before, "snapshot": copied})

    metadata = _metadata_pins()
    baseline_names = {
        _relative(_workspace_path(item["source"]["path"])) for item in baseline["files"]
    }
    required_runtime_names = [*REQUIRED_GATE_HEADERS, *REQUIRED_GATE_CPP_TESTS,
                              *REQUIRED_PIPELINE_SOURCES, *REQUIRED_AUDIT_SOURCES]
    for fixture in OPTIONAL_GATE_FIXTURES:
        if fixture in names:
            required_runtime_names.append(fixture)
    value = {
        "schema": "information.battle_gate_trace.source_freeze.v1",
        "status": "passed",
        "batch": 72,
        "revision": revision,
        "count": len(files),
        "baseline": {
            **baseline_pins,
            "batch": 71,
            "source_count": len(baseline["files"]),
            "no_new_bad": old_comparison["no_new_bad"],
        },
        "build_manifest": {key: value for key, value in build_info.items()
                            if key != "source_names"},
        "manifest_native_sources": native_paths,
        "manifest_source_copies": copy_paths,
        "manifest_source_names": build_info["source_names"],
        "required_runtime_paths": required_runtime_names,
        "additional_sources": [name for name in names if name not in baseline_names],
        "source_union": {
            "batch71_original_sources": len(baseline["files"]),
            "manifest_native_sources": len(native_paths),
            "manifest_source_copies": len(copy_paths),
            "gate_headers": list(REQUIRED_GATE_HEADERS),
            "gate_cpp_tests": list(REQUIRED_GATE_CPP_TESTS),
            "critical_pipeline_sources": list(REQUIRED_PIPELINE_SOURCES),
            "operator_audit_sources": list(REQUIRED_AUDIT_SOURCES),
            "optional_gate_fixtures_included": [
                name for name in OPTIONAL_GATE_FIXTURES if name in names
            ],
            "deduplicated_union_count": len(names),
        },
        "deduplicated": True,
        "hash_chunk_bytes": CHUNK_BYTES,
        "separate_metadata_helpers": {
            "runtime_freeze_member": False,
            "pins_scope": "independently pinned metadata tools and owned fixture evidence",
            "paths": list(SEPARATE_METADATA_PATHS),
            "pins": metadata,
        },
        "files": files,
    }
    _write_new(output, value)
    print(json.dumps({"status": "passed", "phase": "freeze", "revision": revision,
                      "source_count": len(files),
                      "manifest_source_count": len(native_paths)}, ensure_ascii=False))
    return 0


def _verify_frozen(revision: str, baseline_freeze: Path,
                   baseline_full: Path, baseline_comparison: Path,
                   baseline_postverify: Path) -> tuple[dict, dict]:
    freeze_path = STAGE / f"source-freeze-{revision}.json"
    frozen = _read_json(freeze_path)
    files = frozen.get("files")
    if (frozen.get("schema") != "information.battle_gate_trace.source_freeze.v1"
            or frozen.get("status") != "passed" or frozen.get("batch") != 72
            or frozen.get("revision") != revision or not isinstance(files, list)
            or frozen.get("count") != len(files)):
        raise VerificationError("invalid_batch72_source_freeze")
    baseline, comparison, postverify, baseline_pins = _baseline_inputs(
        baseline_freeze, baseline_full, baseline_comparison, baseline_postverify)
    frozen_baseline = frozen.get("baseline")
    if (not isinstance(frozen_baseline, dict)
            or frozen_baseline.get("freeze") != baseline_pins["freeze"]
            or frozen_baseline.get("full") != baseline_pins["full"]
            or frozen_baseline.get("comparison") != baseline_pins["comparison"]
            or frozen_baseline.get("post_run_verification") != baseline_pins["post_run_verification"]
            or frozen_baseline.get("reviewed_existing_changes")
                != baseline_pins["reviewed_existing_changes"]):
        raise VerificationError("batch71_baseline_changed_since_freeze")

    build_record = frozen.get("build_manifest")
    if not isinstance(build_record, dict) or not isinstance(build_record.get("path"), dict):
        raise VerificationError("build_manifest_pin_missing_from_freeze")
    manifest_path = _workspace_path(build_record["path"].get("path", ""))
    _manifest, native_paths, copy_paths, current_build = _validate_v32_manifest(manifest_path)
    if (current_build["path"] != build_record["path"]
            or current_build["dll"] != build_record.get("dll")
            or current_build["source_count"] != build_record.get("source_count")
            or native_paths != frozen.get("manifest_native_sources")
            or copy_paths != frozen.get("manifest_source_copies")
            or current_build["source_names"] != frozen.get("manifest_source_names")):
        raise VerificationError("build_manifest_or_dll_changed_since_freeze")
    expected_names = set(_source_union(baseline, native_paths, copy_paths))

    seen: set[str] = set()
    for item in files:
        source, snapshot = item.get("source"), item.get("snapshot")
        if not isinstance(source, dict) or not isinstance(snapshot, dict):
            raise VerificationError("batch72_source_record_invalid")
        source_path = _workspace_path(source.get("path", ""))
        name = _relative(source_path)
        if name in seen:
            raise VerificationError(f"batch72_duplicate_source:{name}")
        seen.add(name)
        if _pin(source_path) != source:
            raise VerificationError(f"frozen_source_changed:{name}")
        if _pin(_workspace_path(snapshot.get("path", ""))) != snapshot:
            raise VerificationError(f"frozen_snapshot_changed:{name}")
    if seen != expected_names:
        missing = sorted(expected_names - seen)
        extra = sorted(seen - expected_names)
        raise VerificationError(f"frozen_source_union_mismatch:missing={missing}:extra={extra}")

    if any(name in seen for name in SEPARATE_METADATA_PATHS):
        raise VerificationError("metadata_helper_or_fixture_evidence_in_runtime_freeze")
    metadata = frozen.get("separate_metadata_helpers", {})
    expected_metadata = _metadata_pins()
    if (metadata.get("runtime_freeze_member") is not False
            or metadata.get("paths") != list(SEPARATE_METADATA_PATHS)
            or metadata.get("pins") != expected_metadata):
        raise VerificationError("separate_metadata_pins_changed")
    return frozen, {
        "baseline": baseline,
        "comparison": comparison,
        "postverify": postverify,
        "baseline_pins": baseline_pins,
    }


def full(revision: str, baseline_freeze: Path,
         baseline_full: Path, baseline_comparison: Path,
         baseline_postverify: Path) -> int:
    frozen, _ = _verify_frozen(
        revision, baseline_freeze, baseline_full, baseline_comparison, baseline_postverify)
    if not DEFAULT_PYTHON.is_file():
        raise VerificationError(f"research_python_missing:{DEFAULT_PYTHON}")
    xml = STAGE / f"regression-full-{revision}.xml"
    log = STAGE / f"regression-full-{revision}.log"
    reservation = STAGE / f"full-execution-reservation-{revision}.json"
    boundary = STAGE / f"full-execution-boundary-{revision}.json"
    if any(path.exists() for path in (xml, log, reservation, boundary)):
        raise VerificationError("full_revision_already_reserved_or_run")
    command = [str(DEFAULT_PYTHON), "-B", "-m", "pytest", "-q", "bridge/tests",
               "--junitxml", str(xml)]
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    _write_new(reservation, {
        "schema": "information.battle_gate_trace.full_reservation.v1",
        "revision": revision,
        "runs": 1,
        "status": "started",
        "frozen_source_count": frozen["count"],
        "command": command,
        "started_at": started,
    })
    returncode: int | None = None
    error: str | None = None
    try:
        with log.open("xb") as stream:
            result = subprocess.run(command, cwd=ROOT, stdout=stream,
                                    stderr=subprocess.STDOUT, check=False)
        returncode = result.returncode
    except OSError as exc:
        error = f"{type(exc).__name__}:{exc}"
    receipt = {
        "schema": "information.battle_gate_trace.full_execution_boundary.v1",
        "revision": revision,
        "runs": 1,
        "status": "completed" if returncode is not None else "failed_to_start_or_collect",
        "command": command,
        "started_at": started,
        "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "returncode": returncode,
        "error": error,
        "xml": _pin(xml) if xml.is_file() else None,
        "log": _pin(log) if log.is_file() else None,
        "reservation": _pin(reservation),
    }
    _write_new(boundary, receipt)
    print(json.dumps({"phase": "full", "revision": revision,
                      "returncode": returncode, "runs": 1,
                      "xml_written": receipt["xml"] is not None}, ensure_ascii=False))
    return returncode if returncode is not None else 2


def compare(revision: str, baseline_freeze: Path,
            baseline_full: Path, baseline_comparison: Path,
            baseline_postverify: Path) -> int:
    _verify_frozen(revision, baseline_freeze, baseline_full,
                   baseline_comparison, baseline_postverify)
    xml = STAGE / f"regression-full-{revision}.xml"
    log = STAGE / f"regression-full-{revision}.log"
    boundary = _read_json(STAGE / f"full-execution-boundary-{revision}.json")
    if (boundary.get("schema") != "information.battle_gate_trace.full_execution_boundary.v1"
            or boundary.get("status") != "completed" or boundary.get("runs") != 1
            or boundary.get("xml") != _pin(xml) or boundary.get("log") != _pin(log)):
        raise VerificationError("full_execution_receipt_or_artifact_mismatch")
    output = STAGE / f"regression-comparison-{revision}.json"
    if output.exists():
        raise VerificationError("comparison_revision_already_written")
    base_comparison = _read_json(baseline_comparison)
    from work.compare_information_battle_native_title_regression import compare as compare_xml

    value = compare_xml(baseline_full, xml)
    value.update({
        "schema": "information.battle_gate_trace.regression_comparison.v1",
        "revision": revision,
        "baseline_batch": 71,
        "baseline_freeze": _pin(baseline_freeze),
        "baseline_full": _pin(baseline_full),
        "baseline_comparison": _pin(baseline_comparison),
        "baseline_post_run_verification": _pin(baseline_postverify),
        "baseline_no_new_bad": base_comparison["no_new_bad"],
    })
    value["no_new_bad"] = (
        base_comparison["no_new_bad"] is True
        and not value["new_failure_nodes"]
        and not value["new_test_failures"]
    )
    value["status"] = ("passed_no_new_bad" if value["no_new_bad"]
                        else "failed_new_bad_or_baseline_not_qualified")
    _write_new(output, value)
    print(json.dumps({"phase": "compare", "revision": revision,
                      "status": value["status"],
                      "new_failure_nodes": len(value["new_failure_nodes"]),
                      "new_test_failures": len(value["new_test_failures"])}, ensure_ascii=False))
    return 0 if value["no_new_bad"] else 2


def verify(revision: str, baseline_freeze: Path,
           baseline_full: Path, baseline_comparison: Path,
           baseline_postverify: Path) -> int:
    frozen, info = _verify_frozen(
        revision, baseline_freeze, baseline_full, baseline_comparison, baseline_postverify)
    boundary_path = STAGE / f"full-execution-boundary-{revision}.json"
    boundary = _read_json(boundary_path)
    comparison_path = STAGE / f"regression-comparison-{revision}.json"
    comparison_value = _read_json(comparison_path)
    if (boundary.get("schema") != "information.battle_gate_trace.full_execution_boundary.v1"
            or boundary.get("status") != "completed" or boundary.get("runs") != 1):
        raise VerificationError("full_execution_not_completed_once")
    xml_path = STAGE / f"regression-full-{revision}.xml"
    log_path = STAGE / f"regression-full-{revision}.log"
    reservation_path = STAGE / f"full-execution-reservation-{revision}.json"
    xml_pin, log_pin, reservation_pin = _pin(xml_path), _pin(log_path), _pin(reservation_path)
    if (boundary.get("xml") != xml_pin or boundary.get("log") != log_pin
            or boundary.get("reservation") != reservation_pin):
        raise VerificationError("full_execution_artifact_pin_mismatch")
    if (comparison_value.get("schema") != "information.battle_gate_trace.regression_comparison.v1"
            or comparison_value.get("no_new_bad") is not True
            or comparison_value.get("baseline_freeze") != info["baseline_pins"]["freeze"]
            or comparison_value.get("baseline_full") != info["baseline_pins"]["full"]
            or comparison_value.get("baseline_comparison") != info["baseline_pins"]["comparison"]
            or comparison_value.get("baseline_post_run_verification")
                != info["baseline_pins"]["post_run_verification"]
            or comparison_value.get("current_xml") != xml_pin):
        raise VerificationError("regression_comparison_input_pins_mismatch")
    output = STAGE / f"source-post-run-verification-{revision}.json"
    value = {
        "schema": "information.battle_gate_trace.source_post_run_verification.v1",
        "status": "passed",
        "batch": 72,
        "revision": revision,
        "source_count": frozen["count"],
        "source_freeze": _pin(STAGE / f"source-freeze-{revision}.json"),
        "current_sources_match_snapshots": True,
        "baseline71_snapshots_match_original_pins": True,
        "baseline71_no_new_bad": info["comparison"]["no_new_bad"],
        "full_execution": _pin(boundary_path),
        "regression_comparison": _pin(comparison_path),
        "metadata_helpers_runtime_freeze_member": False,
        "metadata_helpers_match_separate_pins": True,
        "hash_chunk_bytes": CHUNK_BYTES,
    }
    _write_new(output, value)
    print(json.dumps({"phase": "verify", "revision": revision,
                      "status": value["status"], "source_count": frozen["count"]},
                     ensure_ascii=False))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("freeze", "full", "compare", "verify"))
    parser.add_argument("--revision", type=int, default=1,
                        help="each revision has exclusive freeze/full/comparison outputs")
    parser.add_argument("--build-manifest", type=Path,
                        help="required for freeze; a compiled v32 manifest")
    parser.add_argument("--baseline-freeze", type=Path, default=BASELINE_FREEZE)
    parser.add_argument("--baseline-full", type=Path, default=BASELINE_FULL)
    parser.add_argument("--baseline-comparison", type=Path, default=BASELINE_COMPARISON)
    parser.add_argument("--baseline-postverify", type=Path, default=BASELINE_POSTVERIFY)
    args = parser.parse_args(argv)
    if args.revision < 1 or args.revision > 999:
        parser.error("--revision must be in 1..999")
    revision = f"{args.revision:03d}"
    try:
        baseline_freeze = _workspace_path(args.baseline_freeze)
        baseline_full = _workspace_path(args.baseline_full)
        baseline_comparison = _workspace_path(args.baseline_comparison)
        baseline_postverify = _workspace_path(args.baseline_postverify)
        if args.phase == "freeze":
            if args.build_manifest is None:
                parser.error("freeze requires --build-manifest")
            return freeze(revision, _workspace_path(args.build_manifest),
                          baseline_freeze, baseline_full, baseline_comparison,
                          baseline_postverify)
        if args.phase == "full":
            return full(revision, baseline_freeze, baseline_full,
                        baseline_comparison, baseline_postverify)
        if args.phase == "compare":
            return compare(revision, baseline_freeze, baseline_full,
                           baseline_comparison, baseline_postverify)
        return verify(revision, baseline_freeze, baseline_full,
                      baseline_comparison, baseline_postverify)
    except (OSError, ValueError, VerificationError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "failed", "phase": args.phase,
                          "revision": revision,
                          "error": f"{type(exc).__name__}:{exc}"}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
