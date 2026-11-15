"""Freeze the bounded static evidence for the battle-capture contract research.

This script consumes three already-completed read-only REA reports and the
existing callback/event integration surveys.  It does not query REA, access a
game process, invoke native code, or inspect the large Ghidra cache.  The
side-identity ledger is an explicit required input; a missing or malformed
ledger fails closed rather than producing an incomplete freeze.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-battle-capture-contract-20261025-001"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_ADAPTER_SHA256 = "93620e986ea9ea17f5b6a8e56a5077772af0090a8d0eb467019aea40d38a689d"
EXPECTED_MANIFEST_SHA256 = "de1c738fa2bc9027ceacadabb7828d9890f5f9ff57ec4cde60494968f927333a"
EXPECTED_DATABASE_SHA256 = "8eec1cad93cce37d2f958c100570550bc7212c5aa86b92b7cf03950f85a83161"
EXPECTED_PRESET = "eu4-persistent-default-analysis-v1"
IMAGE_BASE = 0x140000000
MAX_EVIDENCE_BYTES = 3 * 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
EXPECTED_RELEASE_LEDGER_SHA256 = "3a711b04e80da20a0adb469c189bce643d8b98931ca0c25a11106506c13bca8e"
EXPECTED_RELEASE_SCRIPT_SHA256 = "8f32e26f3df0ed137c2650a1b9c13613c00df003fc347ce44418e8dbaa81be9a"
EXPECTED_RESULT_VTABLE_PATH = "work/runtime/information-battles-20261025-001/battle-stage/result-vtable-window-001.json"
EXPECTED_RESULT_VTABLE_SHA256 = "6139e4ee994a3e303eb71c1eb7a0e119f8fca9ce626e10406aa3ef6727b7dbb3"
RESULT_RELEASE_LEDGER_PATH = STAGE / "result-release-ledger-001.json"
RESULT_RELEASE_SCRIPT_PATH = ROOT / "work/probe_information_battle_result_release.py"
RESULT_VTABLE_PATH = ROOT / EXPECTED_RESULT_VTABLE_PATH

EVIDENCE_SPECS: tuple[dict[str, Any], ...] = (
    {
        "name": "naval_captured_results",
        "directory": "rea-naval-captured-results-001",
        "expected_id": "ev_ba2f394615966814a83a2a7efe7d010b1b032d6a5b0e006eb5ec43986470de41",
        "expected_procedure": "0x140237150",
        "expected_rva": "0x237150",
        "body": {
            "ranges": [("0x140237150", "0x140237949")],
            "total_bytes": 2042,
            "span_bytes": 2042,
            "non_contiguous": False,
            "contains_entry": True,
        },
    },
    {
        "name": "side_commander_selector",
        "directory": "rea-side-commander-selector-001",
        "expected_id": "ev_66949db89bae83ffb97d97534caf7313ed6692fd7db61ea141f6b78b1c40a973",
        "expected_procedure": "0x14021feb0",
        "expected_rva": "0x21feb0",
        "body": {
            "ranges": [("0x14021feb0", "0x14021ff84")],
            "total_bytes": 213,
            "span_bytes": 213,
            "non_contiguous": False,
            "contains_entry": True,
        },
    },
    {
        "name": "side_country_selector",
        "directory": "rea-side-country-selector-001",
        "expected_id": "ev_eb423943852560c33b8bf764a143cd8c925e88887656fb8f828bfd24719d719d",
        "expected_procedure": "0x14021c7d0",
        "expected_rva": "0x21c7d0",
        "body": {
            "ranges": [("0x14021c7d0", "0x14021c8e0")],
            "total_bytes": 273,
            "span_bytes": 273,
            "non_contiguous": False,
            "contains_entry": True,
        },
    },
)

RELEASE_EVIDENCE_SPEC: dict[str, Any] = {
    "name": "result_release_cleanup",
    "directory": "rea-result-release-001",
    "expected_id": "ev_fb35b596d32c105001f1e50c620ff980139638757c9c71e8bd7674c591206154",
    "expected_procedure": "0x1401dd090",
    "expected_rva": "0x1dd090",
    "body": {
        "ranges": [("0x1401dd090", "0x1401dd0df")],
        "total_bytes": 80,
        "span_bytes": 80,
        "non_contiguous": False,
        "contains_entry": True,
    },
}

RELATED_REPORTS: tuple[dict[str, Any], ...] = (
    {
        "name": "callback_lifetime_survey",
        "path": STAGE / "callback-lifetime-survey-001.json",
        "expected_schema": "information_battle_capture_contract/callback-lifetime-survey-001",
        "required": True,
    },
    {
        "name": "event_integration_survey",
        "path": STAGE / "event-integration-survey-001.json",
        "expected_schema": "information-battle-capture-event-integration-survey-001",
        "required": True,
    },
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _load_json(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> tuple[dict[str, Any], bytes]:
    path = path.resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"JSON input exceeds bound: {path} ({size} > {max_bytes})")
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root is not an object: {path}")
    return value, raw


def _body_descriptor(procedure: dict[str, Any], expected: dict[str, Any], path: Path) -> dict[str, Any]:
    body = procedure.get("body")
    if not isinstance(body, dict):
        raise ValueError(f"REA body missing: {path}")
    ranges = body.get("ranges")
    expected_ranges = expected["ranges"]
    if not isinstance(ranges, list) or len(ranges) != len(expected_ranges):
        raise ValueError(f"REA body range count changed: {path}")
    converted: list[dict[str, Any]] = []
    total = 0
    for item, (expected_start, expected_end) in zip(ranges, expected_ranges):
        if not isinstance(item, dict):
            raise ValueError(f"REA body range is not an object: {path}")
        start = item.get("start")
        end = item.get("end")
        if start != expected_start or end != expected_end:
            raise ValueError(f"REA body range changed: {path}")
        start_int = int(start, 16)
        end_int = int(end, 16)
        if end_int < start_int:
            raise ValueError(f"REA body range is reversed: {path}")
        length = end_int - start_int + 1
        total += length
        converted.append(
            {
                "start_va": hex(start_int),
                "end_va_inclusive": hex(end_int),
                "start_rva": hex(start_int - IMAGE_BASE),
                "end_rva_inclusive": hex(end_int - IMAGE_BASE),
                "bytes_inclusive": length,
            }
        )
    for key in ("total_bytes", "span_bytes", "non_contiguous", "contains_entry"):
        if body.get(key) != expected[key]:
            raise ValueError(f"REA body {key} changed: {path}")
    if total != expected["total_bytes"]:
        raise ValueError(f"REA inclusive body total changed: {path}")
    return {
        "ranges_inclusive": converted,
        "total_bytes": body["total_bytes"],
        "span_bytes": body["span_bytes"],
        "non_contiguous": body["non_contiguous"],
        "contains_entry": body["contains_entry"],
        "provenance": body.get("provenance"),
    }


def _validate_shared_params(
    request: dict[str, Any],
    run: dict[str, Any],
    profile_params: dict[str, Any],
    path: Path,
    shared: dict[str, Any] | None,
) -> dict[str, Any]:
    request_keys = (
        "target_sha256",
        "cache",
        "preset",
        "adapter_sha256",
        "completed_manifest_sha256",
        "completed_database_sha256",
        "query_reanalysis",
        "java_heap",
        "process_memory_limit_bytes",
        "timeout_seconds",
    )
    for key in request_keys:
        if request.get(key) != run.get(key):
            raise ValueError(f"request/run parameter mismatch {key}: {path.parent}")
    if request.get("target_sha256") != EXPECTED_EXE_SHA256:
        raise ValueError(f"REA target SHA changed: {path.parent}")
    if request.get("preset") != EXPECTED_PRESET:
        raise ValueError(f"REA preset changed: {path.parent}")
    if request.get("adapter_sha256") != EXPECTED_ADAPTER_SHA256:
        raise ValueError(f"REA adapter SHA changed: {path.parent}")
    if request.get("completed_manifest_sha256") != EXPECTED_MANIFEST_SHA256:
        raise ValueError(f"REA completed manifest SHA changed: {path.parent}")
    if request.get("completed_database_sha256") != EXPECTED_DATABASE_SHA256:
        raise ValueError(f"REA completed database SHA changed: {path.parent}")
    if request.get("query_reanalysis") is not False or request.get("java_heap") != "512M":
        raise ValueError(f"REA query policy changed: {path.parent}")
    if request.get("process_memory_limit_bytes") != 1024 * 1024 * 1024:
        raise ValueError(f"REA process limit changed: {path.parent}")
    if not isinstance(request.get("cache"), str) or not request["cache"]:
        raise ValueError(f"REA cache path missing: {path.parent}")
    profile_expected = {
        "analyzer_preset": EXPECTED_PRESET,
        "local_adapter_sha256": EXPECTED_ADAPTER_SHA256,
        "completed_manifest_sha256": EXPECTED_MANIFEST_SHA256,
        "completed_database_sha256": EXPECTED_DATABASE_SHA256,
        "query_reanalysis": False,
        "database_mutation": "read-only-no-save",
        "import_mode": "persistent-completed-project-read-only",
    }
    for key, expected in profile_expected.items():
        if profile_params.get(key) != expected:
            raise ValueError(f"REA profile parameter {key} changed: {path}")
    if shared is None:
        return {
            "cache": request["cache"],
            "preset": request["preset"],
            "adapter_sha256": request["adapter_sha256"],
            "completed_manifest_sha256": request["completed_manifest_sha256"],
            "completed_database_sha256": request["completed_database_sha256"],
        }
    for key in ("cache", "preset", "adapter_sha256", "completed_manifest_sha256", "completed_database_sha256"):
        if request.get(key) != shared.get(key):
            raise ValueError(f"REA shared parameter {key} changed: {path.parent}")
    return shared


def _evidence_descriptor(spec: dict[str, Any], shared: dict[str, Any] | None) -> tuple[dict[str, Any], dict[str, Any]]:
    directory = STAGE / spec["directory"]
    evidence_path = directory / "evidence.json"
    request_path = directory / "request.json"
    run_path = directory / "run.json"
    evidence, evidence_raw = _load_json(evidence_path, max_bytes=MAX_EVIDENCE_BYTES)
    request, request_raw = _load_json(request_path)
    run, run_raw = _load_json(run_path)
    if evidence.get("evidence_id") != spec["expected_id"]:
        raise ValueError(f"Evidence ID changed: {evidence_path}")
    subject_sha = evidence.get("subject", {}).get("digest", {}).get("sha256")
    if subject_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"Evidence target SHA changed: {evidence_path}")
    raw_result = evidence.get("raw_result")
    normalized_result = evidence.get("normalized_result")
    if not isinstance(raw_result, dict) or not isinstance(raw_result.get("value"), dict):
        raise ValueError(f"REA raw result missing: {evidence_path}")
    if not isinstance(normalized_result, dict):
        raise ValueError(f"REA normalized result missing: {evidence_path}")
    raw_value = raw_result["value"]
    if raw_value != normalized_result:
        raise ValueError(f"REA raw/normalized result mismatch: {evidence_path}")
    procedure = raw_value.get("procedure")
    if not isinstance(procedure, dict) or procedure.get("address") != spec["expected_procedure"]:
        raise ValueError(f"REA procedure changed: {evidence_path}")
    if request.get("node") != spec["expected_rva"] or request.get("procedure") != spec["expected_procedure"]:
        raise ValueError(f"REA request address changed: {request_path}")
    if run.get("node") != spec["expected_rva"] or run.get("procedure") != spec["expected_procedure"]:
        raise ValueError(f"REA run address changed: {run_path}")
    if run.get("exit_code") != 0 or run.get("reason") != "completed" or run.get("database_unchanged") is not True:
        raise ValueError(f"REA run did not complete read-only: {run_path}")
    processes = run.get("processes")
    if (
        not isinstance(processes, list)
        or not processes
        or any(not isinstance(item, dict) for item in processes)
        or any(item.get("still_running_same_process") is not False for item in processes)
        or any(item.get("peak_committed_bytes", 2**31) >= 1024 * 1024 * 1024 for item in processes)
    ):
        raise ValueError(f"REA process closure/memory guard failed: {run_path}")
    profile = evidence.get("analysis_profile")
    if not isinstance(profile, dict) or not isinstance(profile.get("parameters"), dict):
        raise ValueError(f"REA analysis profile missing: {evidence_path}")
    provider = profile.get("provider")
    if not isinstance(provider, dict) or provider.get("id") != "ghidra" or provider.get("version") != "12.1.4":
        raise ValueError(f"REA provider changed: {evidence_path}")
    profile_params = profile["parameters"]
    shared = _validate_shared_params(request, run, profile_params, evidence_path, shared)
    limitations = evidence.get("limitations", [])
    if not any("-readOnly" in str(item) and "-noanalysis" in str(item) for item in limitations):
        raise ValueError(f"REA readOnly/noanalysis limitation missing: {evidence_path}")
    body = _body_descriptor(procedure, spec["body"], evidence_path)
    procedure_va = int(procedure["address"], 16)
    descriptor = {
        "name": spec["name"],
        "evidence": {
            "path": _relative(evidence_path),
            "bytes": len(evidence_raw),
            "sha256": _sha256_file(evidence_path),
            "evidence_id": evidence["evidence_id"],
            "target_exe_sha256": subject_sha,
            "raw_normalized_equal": True,
            "raw_value_canonical_sha256": _canonical_sha(raw_value),
            "normalized_value_canonical_sha256": _canonical_sha(normalized_result),
            "authority": "shipped-artifact-static-analysis_only",
        },
        "procedure": {
            "name": procedure.get("name"),
            "address_va": procedure_va and hex(procedure_va),
            "rva": hex(procedure_va - IMAGE_BASE),
            "body": body,
        },
        "request": {
            "path": _relative(request_path),
            "bytes": len(request_raw),
            "sha256": _sha256_file(request_path),
            "node": request.get("node"),
            "procedure": request.get("procedure"),
            "cache": request.get("cache"),
            "preset": request.get("preset"),
            "adapter_sha256": request.get("adapter_sha256"),
            "completed_manifest_sha256": request.get("completed_manifest_sha256"),
            "completed_database_sha256": request.get("completed_database_sha256"),
            "query_reanalysis": request.get("query_reanalysis"),
            "java_heap": request.get("java_heap"),
            "process_memory_limit_bytes": request.get("process_memory_limit_bytes"),
            "timeout_seconds": request.get("timeout_seconds"),
        },
        "run": {
            "path": _relative(run_path),
            "bytes": len(run_raw),
            "sha256": _sha256_file(run_path),
            "exit_code": run.get("exit_code"),
            "reason": run.get("reason"),
            "elapsed_seconds": run.get("elapsed_seconds"),
            "database_unchanged": run.get("database_unchanged"),
            "processes": run.get("processes"),
        },
        "profile": {
            "digest": profile.get("digest"),
            "provider": provider,
            "analyzer_preset": profile_params.get("analyzer_preset"),
            "local_adapter_sha256": profile_params.get("local_adapter_sha256"),
            "completed_manifest_sha256": profile_params.get("completed_manifest_sha256"),
            "completed_database_sha256": profile_params.get("completed_database_sha256"),
            "query_reanalysis": profile_params.get("query_reanalysis"),
            "database_mutation": profile_params.get("database_mutation"),
            "import_mode": profile_params.get("import_mode"),
        },
        "cache": {
            "path": request.get("cache"),
            "request_run_profile_parameters_consistent": True,
        },
        "query_policy": {
            "read_only": True,
            "noanalysis": True,
            "native_function_invoked": False,
            "runtime_observed": False,
        },
    }
    return descriptor, shared


def _related_report_descriptor(spec: dict[str, Any]) -> dict[str, Any]:
    path = Path(spec["path"]).resolve()
    document, raw = _load_json(path)
    if document.get("schema") != spec["expected_schema"]:
        raise ValueError(f"related report schema changed: {path}")
    if spec["name"] == "callback_lifetime_survey":
        required = {
            "status": "static_survey_complete_runtime_unresolved",
            "read_only": True,
            "game_access": False,
            "native_function_invoked": False,
            "new_rea_executed": False,
            "goal_complete": False,
        }
    else:
        required = {
            "status": "read_only_source_survey",
            "runtime_observed": False,
            "native_invoked": False,
        }
    for key, expected in required.items():
        if document.get(key) != expected:
            raise ValueError(f"related report guard {key} changed: {path}")
    target = document.get("target_build")
    if isinstance(target, dict):
        if target.get("executable_sha256") != EXPECTED_EXE_SHA256:
            raise ValueError(f"related report target SHA changed: {path}")
    elif spec["name"] == "event_integration_survey":
        # This source survey predates a target_build object; its scope is still
        # static and has no runtime target claim.  Keep the report separate.
        scope = str(document.get("scope", ""))
        if "battle" not in scope.lower():
            raise ValueError(f"event integration scope changed: {path}")
    return {
        "name": spec["name"],
        "path": _relative(path),
        "bytes": len(raw),
        "sha256": _sha256_file(path),
        "schema": document.get("schema"),
        "status": document.get("status"),
        "runtime_observed": document.get("runtime_observed", False),
        "native_invoked": document.get("native_invoked", document.get("native_function_invoked", False)),
        "goal_complete": document.get("goal_complete", False),
        "source_file_count": len(document.get("source_files", [])) if isinstance(document.get("source_files"), list) else None,
    }


def _side_identity_descriptor(path: Path) -> dict[str, Any]:
    document, raw = _load_json(path)
    if not isinstance(document.get("status"), str) or not document["status"]:
        raise ValueError(f"side identity ledger status missing: {path}")
    runtime_observed = document.get("runtime_observed", False)
    native_invoked = document.get("native_invoked", document.get("native_function_invoked", False))
    if runtime_observed is True or native_invoked is True:
        raise ValueError(f"side identity ledger is not static/read-only: {path}")
    if (
        document.get("read_only") is False
        or document.get("game_access") is True
        or document.get("game_accessed") is True
        or document.get("new_native_calls") is True
        or document.get("new_hooks_installed") is True
    ):
        raise ValueError(f"side identity ledger read-only guard changed: {path}")
    # The ledger may use target_build, target_exe_sha256, or identity.target_executable_sha256.
    candidates = [
        document.get("target_build", {}).get("executable_sha256") if isinstance(document.get("target_build"), dict) else None,
        document.get("target_exe_sha256"),
        document.get("identity", {}).get("target_executable_sha256") if isinstance(document.get("identity"), dict) else None,
    ]
    candidates = [item for item in candidates if item is not None]
    if candidates and any(item != EXPECTED_EXE_SHA256 for item in candidates):
        raise ValueError(f"side identity ledger target SHA changed: {path}")
    return {
        "name": "side_identity_ledger",
        "path": _relative(path),
        "bytes": len(raw),
        "sha256": _sha256_file(path),
        "schema": document.get("schema"),
        "status": document.get("status"),
        "runtime_observed": runtime_observed,
        "native_invoked": native_invoked,
        "read_only": document.get("read_only", True),
        "target_sha_present_and_checked": bool(candidates),
    }


def _validate_event_source_files(report_path: Path) -> list[dict[str, Any]]:
    report, _raw = _load_json(report_path)
    source_files = report.get("source_files")
    if not isinstance(source_files, list):
        raise ValueError(f"event integration source_files missing: {report_path}")
    checked: list[dict[str, Any]] = []
    for item in source_files:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not isinstance(item.get("sha256"), str):
            raise ValueError(f"event integration source pin malformed: {report_path}")
        path = (ROOT / item["path"]).resolve()
        try:
            path.relative_to(ROOT.resolve())
        except ValueError as exc:
            raise ValueError(f"event source path escapes workspace: {path}") from exc
        if not path.is_file():
            raise FileNotFoundError(path)
        size = path.stat().st_size
        if size > MAX_JSON_BYTES:
            raise ValueError(f"event source exceeds 16 MiB bound: {path}")
        actual = _sha256_file(path)
        if actual != item["sha256"]:
            raise ValueError(f"event source SHA changed: {path}")
        checked.append({"path": item["path"], "bytes": size, "sha256": actual, "role": item.get("role")})
    return checked


def _resolve_workspace_file(relative_path: str, *, max_bytes: int) -> Path:
    if not isinstance(relative_path, str) or not relative_path or Path(relative_path).is_absolute():
        raise ValueError(f"workspace source path is not relative: {relative_path!r}")
    path = (ROOT / relative_path).resolve()
    try:
        path.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise ValueError(f"workspace source path escapes root: {relative_path}") from exc
    if not path.is_file():
        raise FileNotFoundError(path)
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"workspace source exceeds bound: {path} ({size} > {max_bytes})")
    return path


def _release_artifact_descriptor() -> dict[str, Any]:
    ledger, ledger_raw = _load_json(RESULT_RELEASE_LEDGER_PATH)
    ledger_sha = _sha256_file(RESULT_RELEASE_LEDGER_PATH)
    if ledger_sha != EXPECTED_RELEASE_LEDGER_SHA256:
        raise ValueError(f"result-release ledger SHA changed: {RESULT_RELEASE_LEDGER_PATH}")
    if ledger.get("schema") != "information_battle_result_release_ledger_v1":
        raise ValueError(f"result-release ledger schema changed: {RESULT_RELEASE_LEDGER_PATH}")
    if ledger.get("status") != "bounded_static_cleanup_and_release_path":
        raise ValueError(f"result-release ledger status changed: {RESULT_RELEASE_LEDGER_PATH}")
    if ledger.get("target_exe_sha256") != EXPECTED_EXE_SHA256:
        raise ValueError(f"result-release ledger target SHA changed: {RESULT_RELEASE_LEDGER_PATH}")
    if ledger.get("static_image_base") != hex(IMAGE_BASE):
        raise ValueError(f"result-release ledger image base changed: {RESULT_RELEASE_LEDGER_PATH}")
    if ledger.get("runtime_observed") is not False:
        raise ValueError(f"result-release ledger runtime guard changed: {RESULT_RELEASE_LEDGER_PATH}")
    if type(ledger.get("new_native_calls")) is not int or ledger.get("new_native_calls") != 0:
        raise ValueError(f"result-release ledger native-call guard changed: {RESULT_RELEASE_LEDGER_PATH}")
    if type(ledger.get("new_hooks_installed")) is not int or ledger.get("new_hooks_installed") != 0:
        raise ValueError(f"result-release ledger hook guard changed: {RESULT_RELEASE_LEDGER_PATH}")
    if ledger.get("catalog_promotion") is not False:
        raise ValueError(f"result-release ledger promotion guard changed: {RESULT_RELEASE_LEDGER_PATH}")
    if not isinstance(ledger.get("observations"), list) or not ledger["observations"]:
        raise ValueError(f"result-release ledger observations missing: {RESULT_RELEASE_LEDGER_PATH}")
    if not isinstance(ledger.get("capture_consequences"), list) or not ledger["capture_consequences"]:
        raise ValueError(f"result-release ledger capture limits missing: {RESULT_RELEASE_LEDGER_PATH}")
    if not isinstance(ledger.get("derived_interpretation"), str) or not ledger["derived_interpretation"]:
        raise ValueError(f"result-release ledger interpretation missing: {RESULT_RELEASE_LEDGER_PATH}")
    if not isinstance(ledger.get("historical_report_caveat"), str) or "runtime" not in ledger["historical_report_caveat"].lower():
        raise ValueError(f"result-release ledger runtime caveat missing: {RESULT_RELEASE_LEDGER_PATH}")

    rea_sources = ledger.get("rea_sources")
    if not isinstance(rea_sources, list) or len(rea_sources) != 2:
        raise ValueError(f"result-release ledger REA source count changed: {RESULT_RELEASE_LEDGER_PATH}")
    rea_pins: list[dict[str, Any]] = []
    for source in rea_sources:
        if not isinstance(source, dict):
            raise ValueError(f"result-release ledger REA source malformed: {RESULT_RELEASE_LEDGER_PATH}")
        source_path = _resolve_workspace_file(source.get("path"), max_bytes=MAX_EVIDENCE_BYTES)
        size = source_path.stat().st_size
        if type(source.get("bytes")) is not int or source["bytes"] != size:
            raise ValueError(f"result-release ledger source size changed: {source_path}")
        actual_sha = _sha256_file(source_path)
        if source.get("sha256") != actual_sha:
            raise ValueError(f"result-release ledger source SHA changed: {source_path}")
        rea_pins.append(
            {
                "path": source["path"],
                "bytes": size,
                "sha256": actual_sha,
                "evidence_id": source.get("evidence_id"),
                "rva": source.get("rva"),
                "static_va": source.get("static_va"),
                "body_inclusive": source.get("body_inclusive"),
            }
        )
    first = rea_pins[0]
    expected_release_path = _relative(STAGE / RELEASE_EVIDENCE_SPEC["directory"] / "evidence.json")
    if (
        first["path"] != expected_release_path
        or first["evidence_id"] != RELEASE_EVIDENCE_SPEC["expected_id"]
        or first["rva"] != RELEASE_EVIDENCE_SPEC["expected_rva"]
        or first["static_va"] != RELEASE_EVIDENCE_SPEC["expected_procedure"]
    ):
        raise ValueError(f"result-release ledger primary REA source changed: {RESULT_RELEASE_LEDGER_PATH}")

    ordinary = ledger.get("ordinary_pe_source")
    if not isinstance(ordinary, dict):
        raise ValueError(f"result-release ledger ordinary PE source missing: {RESULT_RELEASE_LEDGER_PATH}")
    if ordinary.get("path") != EXPECTED_RESULT_VTABLE_PATH or ordinary.get("sha256") != EXPECTED_RESULT_VTABLE_SHA256:
        raise ValueError(f"result-release ledger ordinary PE pin changed: {RESULT_RELEASE_LEDGER_PATH}")
    ordinary_path = _resolve_workspace_file(ordinary["path"], max_bytes=MAX_JSON_BYTES)
    ordinary_size = ordinary_path.stat().st_size
    if type(ordinary.get("bytes")) is not int or ordinary["bytes"] != ordinary_size:
        raise ValueError(f"result-release ledger ordinary PE size changed: {ordinary_path}")
    ordinary_doc, _ordinary_raw = _load_json(ordinary_path)
    if ordinary_doc.get("schema") != "information_battle_result_vtable_window_v1" or ordinary_doc.get("status") != "observed_static_pe_window":
        raise ValueError(f"ordinary PE report schema/status changed: {ordinary_path}")
    if ordinary_doc.get("evidence_kind") != "ordinary_PE_bytes_and_pdata_metadata":
        raise ValueError(f"ordinary PE evidence kind changed: {ordinary_path}")
    target = ordinary_doc.get("target")
    if not isinstance(target, dict) or target.get("sha256") != EXPECTED_EXE_SHA256 or target.get("image_base") != hex(IMAGE_BASE):
        raise ValueError(f"ordinary PE target guard changed: {ordinary_path}")
    if target.get("fixed_sha_guard") is not True or target.get("fixed_size_guard") is not True:
        raise ValueError(f"ordinary PE fixed target guard missing: {ordinary_path}")
    window = ordinary_doc.get("window")
    if not isinstance(window, dict) or window.get("rva") != "0x1c448d0":
        raise ValueError(f"ordinary PE vtable window changed: {ordinary_path}")
    source = ordinary_doc.get("source")
    if not isinstance(source, dict) or not source.get("probe_script_sha256") or not source.get("pe_helper_sha256"):
        raise ValueError(f"ordinary PE source provenance missing: {ordinary_path}")
    ordinary_pin = {
        "path": EXPECTED_RESULT_VTABLE_PATH,
        "bytes": ordinary_size,
        "sha256": EXPECTED_RESULT_VTABLE_SHA256,
        "schema": ordinary_doc["schema"],
        "status": ordinary_doc["status"],
        "evidence_kind": ordinary_doc["evidence_kind"],
        "window_rva": window["rva"],
        "slot_0_target_rva": ordinary.get("slot_0_target_rva"),
        "target_exe_sha256": target["sha256"],
        "probe_script_sha256": source["probe_script_sha256"],
        "pe_helper_sha256": source["pe_helper_sha256"],
    }
    if ordinary_pin["slot_0_target_rva"] != RELEASE_EVIDENCE_SPEC["expected_rva"]:
        raise ValueError(f"result-release ledger slot0 target changed: {RESULT_RELEASE_LEDGER_PATH}")

    if not RESULT_RELEASE_SCRIPT_PATH.is_file():
        raise FileNotFoundError(RESULT_RELEASE_SCRIPT_PATH)
    release_script_sha = _sha256_file(RESULT_RELEASE_SCRIPT_PATH)
    if release_script_sha != EXPECTED_RELEASE_SCRIPT_SHA256:
        raise ValueError(f"result-release probe script SHA changed: {RESULT_RELEASE_SCRIPT_PATH}")
    return {
        "ledger": {
            "path": _relative(RESULT_RELEASE_LEDGER_PATH),
            "bytes": len(ledger_raw),
            "sha256": ledger_sha,
            "schema": ledger["schema"],
            "status": ledger["status"],
            "runtime_observed": ledger["runtime_observed"],
            "new_native_calls": ledger["new_native_calls"],
            "new_hooks_installed": ledger["new_hooks_installed"],
            "catalog_promotion": ledger["catalog_promotion"],
        },
        "rea_source_pins": rea_pins,
        "ordinary_pe_source": ordinary_pin,
        "probe_script": {
            "path": _relative(RESULT_RELEASE_SCRIPT_PATH),
            "bytes": RESULT_RELEASE_SCRIPT_PATH.stat().st_size,
            "sha256": release_script_sha,
        },
    }


def _write_json(path: Path, document: dict[str, Any]) -> None:
    encoded = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise ValueError(f"generated report exceeds 4 MiB: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(encoded)
    json.loads(temporary.read_text(encoding="utf-8"))
    temporary.replace(path)


def build_reports(*, side_identity_ledger: Path, revision: int = 1, stage: Path = STAGE) -> tuple[Path, Path]:
    if type(revision) is not int or not 1 <= revision <= 999:
        raise ValueError("revision must be an integer from 1 through 999")
    index_path = stage.resolve() / f"research-index-{revision:03d}.json"
    audit_path = stage.resolve() / f"source-audit-{revision:03d}.json"
    if index_path.exists() or audit_path.exists():
        raise FileExistsError(f"refusing to overwrite existing freeze output: {index_path} / {audit_path}")
    script_path = Path(__file__).resolve()
    shared: dict[str, Any] | None = None
    rea_descriptors: list[dict[str, Any]] = []
    evidence_specs = EVIDENCE_SPECS + ((RELEASE_EVIDENCE_SPEC,) if revision >= 2 else ())
    for spec in evidence_specs:
        descriptor, shared = _evidence_descriptor(spec, shared)
        rea_descriptors.append(descriptor)
    related = [_related_report_descriptor(spec) for spec in RELATED_REPORTS]
    event_report_path = next(spec["path"] for spec in RELATED_REPORTS if spec["name"] == "event_integration_survey")
    event_sources = _validate_event_source_files(Path(event_report_path))
    side_identity = _side_identity_descriptor(side_identity_ledger.resolve())
    release_artifacts = _release_artifact_descriptor() if revision >= 2 else None
    script_sha = _sha256_file(script_path)
    index = {
        "schema": f"information-battle-capture-research-index-{revision:03d}",
        "revision": revision,
        "status": "static_research_frozen_runtime_unresolved",
        "read_only": True,
        "runtime_observed": False,
        "native_function_invoked": False,
        "dispatch_authorized": False,
        "goal_complete": False,
        "target_build": {
            "game_version": "1.37.4",
            "executable_sha256": EXPECTED_EXE_SHA256,
            "image_base": hex(IMAGE_BASE),
            "address_convention": "fixed-build RVA/VA; REA body ranges are inclusive",
        },
        "analysis_identity": {
            "provider": "Ghidra",
            "provider_version": "12.1.4",
            "preset": EXPECTED_PRESET,
            "adapter_sha256": EXPECTED_ADAPTER_SHA256,
            "completed_manifest_sha256": EXPECTED_MANIFEST_SHA256,
            "completed_database_sha256": EXPECTED_DATABASE_SHA256,
            "database_mode": "persistent-completed-project-read-only",
        },
        "script": {"path": _relative(script_path), "sha256": script_sha},
        "rea_evidence": rea_descriptors,
        "related_reports": related,
        "related_event_source_pins": event_sources,
        "side_identity_ledger": side_identity,
        "interpretation_limits": [
            "The three REA records are fixed-build static observations only; no native function was invoked and no runtime battle was observed.",
            "The callback-lifetime report is a static call-order and ownership-gap survey; the event-integration report is a source wiring survey, not a battle payload contract.",
            "The callback report's synchronous-retention conclusion is a static call-order inference only; reentrancy, field/pointer validity, and the legal runtime lifetime remain unverified until runtime observation.",
            "The side identity ledger is retained as a separate static source pin; it does not establish runtime side orientation, war identity, or observer visibility.",
            "No result-object field semantics, units, event identity, or safe native hook ABI is promoted by this freeze.",
        ],
    }
    if release_artifacts is not None:
        index["release_artifacts"] = release_artifacts
        index["interpretation_limits"].extend(
            [
                "The 1DD090 release record and result-vtable report remain bounded static evidence; callee names, allocation contracts, ownership, and runtime release timing are not independently proved.",
                "The result-release path does not authorize calling, hooking, or asynchronously retaining the result object; copy any candidate strings only within a future runtime-validated lifetime.",
            ]
        )
    _write_json(index_path, index)
    index_sha = _sha256_file(index_path)
    checks = [
        {"name": "fixed_target_executable", "passed": all(item["evidence"]["target_exe_sha256"] == EXPECTED_EXE_SHA256 for item in rea_descriptors)},
        {"name": "expected_evidence_ids", "passed": len(rea_descriptors) == len(evidence_specs)},
        {"name": "raw_normalized_match", "passed": all(item["evidence"]["raw_normalized_equal"] for item in rea_descriptors)},
        {"name": "request_run_profile_cache_pins", "passed": all(item["cache"]["request_run_profile_parameters_consistent"] for item in rea_descriptors)},
        {"name": "all_rea_runs_completed_and_closed", "passed": all(item["run"]["exit_code"] == 0 and all(p["still_running_same_process"] is False for p in item["run"]["processes"]) for item in rea_descriptors)},
        {"name": "all_read_only_noanalysis", "passed": all(item["query_policy"]["read_only"] and item["query_policy"]["noanalysis"] and not item["query_policy"]["native_function_invoked"] for item in rea_descriptors)},
        {"name": "body_ranges_pinned", "passed": all(item["procedure"]["body"]["ranges_inclusive"] for item in rea_descriptors)},
        {"name": "related_reports_pinned", "passed": len(related) == 2 and all(item["sha256"] for item in related)},
        {"name": "event_integration_sources_pinned", "passed": bool(event_sources)},
        {"name": "side_identity_ledger_present_static", "passed": side_identity["runtime_observed"] is not True and side_identity["native_invoked"] is not True},
    ]
    if release_artifacts is not None:
        checks.extend(
            [
                {"name": "result_release_ledger_pinned_static", "passed": release_artifacts["ledger"]["runtime_observed"] is False and release_artifacts["ledger"]["catalog_promotion"] is False},
                {"name": "result_release_sources_pinned", "passed": len(release_artifacts["rea_source_pins"]) == 2 and all(item["sha256"] for item in release_artifacts["rea_source_pins"])},
                {"name": "ordinary_result_vtable_pinned", "passed": release_artifacts["ordinary_pe_source"]["sha256"] == EXPECTED_RESULT_VTABLE_SHA256},
                {"name": "result_release_probe_script_pinned", "passed": release_artifacts["probe_script"]["sha256"] == EXPECTED_RELEASE_SCRIPT_SHA256},
            ]
        )
    audit = {
        "schema": f"information-battle-capture-source-audit-{revision:03d}",
        "revision": revision,
        "status": "passed_static_source_audit_runtime_unresolved",
        "read_only": True,
        "runtime_observed": False,
        "native_function_invoked": False,
        "dispatch_authorized": False,
        "goal_complete": False,
        "target_exe_sha256": EXPECTED_EXE_SHA256,
        "script": {"path": _relative(script_path), "sha256": script_sha},
        "research_index": {"path": _relative(index_path), "sha256": index_sha},
        "rea_evidence": rea_descriptors,
        "related_reports": related,
        "related_event_source_pins": event_sources,
        "side_identity_ledger": side_identity,
        "checks": checks,
        "all_checks_passed": all(item["passed"] for item in checks),
        "limitations": index["interpretation_limits"],
    }
    if release_artifacts is not None:
        audit["release_artifacts"] = release_artifacts
    _write_json(audit_path, audit)
    return index_path, audit_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", type=int, default=1, help="three-digit output revision; existing outputs are never overwritten")
    parser.add_argument("--side-identity-ledger", type=Path, default=STAGE / "side-identity-ledger-001.json")
    parser.add_argument("--stage", type=Path, default=STAGE)
    args = parser.parse_args(argv)
    index_path, audit_path = build_reports(side_identity_ledger=args.side_identity_ledger, revision=args.revision, stage=args.stage)
    print(json.dumps({
        "index": _relative(index_path),
        "index_sha256": _sha256_file(index_path),
        "audit": _relative(audit_path),
        "audit_sha256": _sha256_file(audit_path),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
