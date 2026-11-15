"""Freeze bounded static battle-result research for the fixed 1.37.4 build.

This script joins six already completed, read-only REA reports.  It does not
start REA, inspect a process, invoke the game, or change production code.  The
large ``FUN_14022e6b0`` report is deliberately read through the selected-span
and recovery reports produced by :mod:`extract_information_battle_evidence`;
the 10 MiB-plus source document is hashed as a stream but is never loaded as
one JSON value.

The resulting index is a static research record.  A procedure address or a
call graph in it is not a runtime reader, an on-action binding, or permission
to dispatch a game action.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from work.freeze_information_country_powers import (  # noqa: E402
    IMAGE_BASE,
    _write_json_new,
    read_json_bounded,
    relpath,
    sha256_file,
)


STAGE = ROOT / "work" / "runtime" / "information-battles-20261025-001"
INDEX_PATH = STAGE / "research-index-001.json"
SOURCE_AUDIT_PATH = STAGE / "source-audit-001.json"
EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
EXPECTED_GAME_VERSION = "1.37.4"
EXPECTED_IMAGE_BASE = IMAGE_BASE
EXPECTED_PRESET = "eu4-persistent-default-analysis-v1"
EXPECTED_ADAPTER_SHA256 = (
    "93620e986ea9ea17f5b6a8e56a5077772af0090a8d0eb467019aea40d38a689d"
)
EXPECTED_MANIFEST_SHA256 = (
    "de1c738fa2bc9027ceacadabb7828d9890f5f9ff57ec4cde60494968f927333a"
)
EXPECTED_DATABASE_SHA256 = (
    "8eec1cad93cce37d2f958c100570550bc7212c5aa86b92b7cf03950f85a83161"
)
EXPECTED_BATCH_MANIFEST_SHA256 = (
    "aa50a2a5b2c58097e5444829836e902994c8ebbf5d03d55aa59ae755717b517a"
)
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_PSEUDOCODE_CHARS = 64 * 1024
MAX_CALL_GRAPH_ITEMS = 256


REA_SPECS: tuple[dict[str, Any], ...] = (
    {
        "directory": "rea-battle-result-router-001",
        "name": "battle_result_router",
        "rva": 0x23A020,
        "role": "battle result router",
        "semantic_status": "router_only",
        "anchors": ("SetupResults", "FUN_140237d80", "FUN_140238620"),
    },
    {
        "directory": "rea-battle-result-builder-001",
        "name": "non_siege_result_builder",
        "rva": 0x237D80,
        "role": "non-siege result builder",
        "semantic_status": "builder_structure_observed_field_semantics_unknown",
        "anchors": ("SetupNonSiegeResults", "FUN_140237fc0", "FUN_140237950"),
    },
    {
        "directory": "rea-battle-result-object-001",
        "name": "battle_result_object",
        "rva": 0x237FC0,
        "role": "battle result object candidate",
        "semantic_status": "result_object_candidate_field_semantics_unknown",
        "anchors": (
            "param_1[4] + 0x118",
            "param_1[4] + 0x11c",
            "param_1[4] + 0x120",
            "/ 1000",
        ),
    },
    {
        "directory": "rea-battle-loss-summary-001",
        "name": "battle_loss_summary",
        "rva": 0x237950,
        "role": "directory loss-summary candidate",
        "semantic_status": "aggregate_unknown_temporary_directory_name",
        "anchors": ("param_2 + 0x18", "param_2 + 0x1c"),
    },
    {
        "directory": "rea-battle-result-effects-001",
        "name": "perparticipant_result_effects",
        "rva": 0x238620,
        "role": "per-participant callback and variable writes",
        "semantic_status": "callback_variable_writes_field_semantics_unknown",
        "anchors": ("param_3 + 0xdc", "param_1[6] + 0x20"),
    },
    {
        "directory": "rea-message-dispatch-001",
        "name": "battle_message_dispatch",
        "rva": 0x22E6B0,
        "role": "battle message/score formatting dispatch candidate",
        "semantic_status": "selected_static_dispatch_pseudocode_only",
        "anchors": ("WARSCORE_FROM_BATTLE", "MESSAGE_HEAD_MIL", "OUREXHAUSTION"),
        "large": True,
    },
)


SURVEY_FILES: tuple[tuple[str, str], ...] = (
    (
        "work/runtime/information-battles-20261025-001/source-survey-001.json",
        "bounded source survey; battle result source unresolved",
    ),
    (
        "work/runtime/information-battles-20261025-001/message-key-xrefs-001.json",
        "ordinary notification-key xrefs; payload unverified",
    ),
    (
        "work/runtime/information-battles-20261025-001/gui-key-xrefs-001.json",
        "ordinary GUI-key xrefs; payload unverified",
    ),
    (
        "work/runtime/information-battles-20261025-001/naval-message-field-ledger-001.json",
        "selected pseudocode naval field ledger; units and lifetime unresolved",
    ),
    (
        "work/runtime/information-battles-20261025-001/battle-stage/gui-source-survey-001.json",
        "GUI/source survey; native payload ABI unverified",
    ),
    (
        "work/runtime/information-battles-20261025-001/battle-stage/on-action-source-survey-001.json",
        "static on_action survey; effective runtime merge unresolved",
    ),
)


NATIVE_SOURCE_FILES: tuple[tuple[str, str], ...] = (
    ("work/native/live-war-score-query.inc", "existing native public war-score query source"),
    ("work/native/live-war-score-query.h", "existing native public war-score query contract"),
    ("work/native/test-live-war-score-query.cpp", "existing native query test source"),
    ("work/inspect_native_war.py", "existing save/native war inspection helper"),
)


EXISTING_PROOF_FILES: tuple[tuple[str, str], ...] = (
    (
        "work/runtime/r56-engine-war-structure-20261018-001/report.json",
        "recorded war structure proof; no per-battle payload",
    ),
    (
        "work/runtime/r74-live-war-queries-20261020-001/report.json",
        "recorded public whole-war query; no battle payload",
    ),
    (
        "work/runtime/r74-live-war-queries-20261020-002/report.json",
        "recorded follow-up public query; not a battle reader",
    ),
    (
        "work/runtime/r74-live-war-queries-20261020-003/report.json",
        "recorded public query; not a battle reader",
    ),
)


PRODUCTION_FILES: tuple[tuple[str, str], ...] = (
    ("bridge/information/mission_reward_rules.py", "current M04 reward-rule helper"),
    ("bridge/information/domestic_pressure_memory.py", "current N04 bounded reader"),
    ("bridge/information/domestic_pressure.py", "current N04 adapter"),
    ("tools/serve_information.py", "current information service entrypoint"),
)


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_json(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> tuple[dict[str, Any], int, str]:
    return read_json_bounded(path, max_bytes=max_bytes)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _hex_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"boolean_not_integer:{label}")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        try:
            number = int(value, 0)
        except ValueError as exc:
            raise ValueError(f"invalid_integer:{label}:{value}") from exc
    else:
        raise ValueError(f"invalid_integer:{label}")
    if number < 0:
        raise ValueError(f"negative_integer:{label}")
    return number


def _address_record(address: Any, name: Any = None) -> dict[str, Any]:
    va = _hex_int(address, "reference.address")
    _require(va >= EXPECTED_IMAGE_BASE, "reference_below_image_base")
    record: dict[str, Any] = {
        "va": hex(va),
        "rva": hex(va - EXPECTED_IMAGE_BASE),
    }
    if isinstance(name, str):
        record["name"] = name
    return record


def _reference_list(value: Any, label: str) -> list[dict[str, Any]]:
    _require(isinstance(value, list), f"{label}_not_list")
    _require(len(value) <= MAX_CALL_GRAPH_ITEMS, f"{label}_over_bound")
    result: list[dict[str, Any]] = []
    for item in value:
        _require(isinstance(item, Mapping), f"{label}_item_not_object")
        result.append(_address_record(item.get("address"), item.get("name")))
    return result


def _ranges(body: Mapping[str, Any], label: str) -> dict[str, Any]:
    raw_ranges = body.get("ranges")
    _require(isinstance(raw_ranges, list) and raw_ranges, f"{label}_ranges_missing")
    ranges: list[dict[str, Any]] = []
    parsed: list[tuple[int, int]] = []
    for item in raw_ranges:
        _require(isinstance(item, Mapping), f"{label}_range_not_object")
        start = _hex_int(item.get("start"), f"{label}.start")
        end = _hex_int(item.get("end"), f"{label}.end")
        _require(start >= EXPECTED_IMAGE_BASE and end >= start, f"{label}_range_invalid")
        parsed.append((start, end))
        ranges.append(
            {
                "va_start": hex(start),
                "va_end_inclusive": hex(end),
                "va_end_exclusive": hex(end + 1),
                "rva_start": hex(start - EXPECTED_IMAGE_BASE),
                "rva_end_inclusive": hex(end - EXPECTED_IMAGE_BASE),
                "rva_end_exclusive": hex(end - EXPECTED_IMAGE_BASE + 1),
            }
        )
    min_va = min(start for start, _ in parsed)
    max_va = max(end for _, end in parsed)
    total = sum(end - start + 1 for start, end in parsed)
    span = max_va - min_va + 1
    _require(body.get("total_bytes") == total, f"{label}_total_bytes_mismatch")
    _require(body.get("span_bytes") == span, f"{label}_span_bytes_mismatch")
    return {
        "rva_start": hex(min_va - EXPECTED_IMAGE_BASE),
        "rva_end_inclusive": hex(max_va - EXPECTED_IMAGE_BASE),
        "rva_end_exclusive": hex(max_va - EXPECTED_IMAGE_BASE + 1),
        "va_start": hex(min_va),
        "va_end_inclusive": hex(max_va),
        "va_end_exclusive": hex(max_va + 1),
        "total_body_bytes": total,
        "span_bytes": span,
        "range_count": len(ranges),
        "end_semantics": "REA procedure.body.ranges end is inclusive",
        "ranges": ranges,
    }


def _pseudocode_summary(pseudocode: Any, anchors: tuple[str, ...], label: str) -> dict[str, Any]:
    _require(isinstance(pseudocode, str), f"{label}_pseudocode_missing")
    _require(len(pseudocode) <= MAX_PSEUDOCODE_CHARS, f"{label}_pseudocode_over_bound")
    missing = [anchor for anchor in anchors if anchor not in pseudocode]
    _require(not missing, f"{label}_anchor_missing:{missing}")
    snippets: list[dict[str, Any]] = []
    for anchor in anchors:
        position = pseudocode.find(anchor)
        begin = max(0, position - 120)
        end = min(len(pseudocode), position + len(anchor) + 220)
        snippets.append({"anchor": anchor, "char_offset": position, "excerpt": pseudocode[begin:end]})
    return {
        "chars": len(pseudocode),
        "sha256_utf8": _sha256_bytes(pseudocode.encode("utf-8")),
        "anchors": list(anchors),
        "anchor_excerpts": snippets,
    }


def _fixed_metadata(value: Mapping[str, Any], label: str) -> dict[str, Any]:
    parameters = value.get("parameters")
    _require(isinstance(parameters, Mapping), f"{label}_parameters_missing")
    checks = {
        "analyzer_preset": parameters.get("analyzer_preset") == EXPECTED_PRESET,
        "target_format": parameters.get("target_format") == "pe",
        "target_kind": parameters.get("target_kind") == "executable",
        "architecture": parameters.get("architecture") == "x86_64",
        "import_mode": parameters.get("import_mode") == "persistent-completed-project-read-only",
        "database_mutation": parameters.get("database_mutation") == "read-only-no-save",
        "query_reanalysis": parameters.get("query_reanalysis") is False,
        "adapter_sha256": parameters.get("local_adapter_sha256") == EXPECTED_ADAPTER_SHA256,
        "manifest_sha256": parameters.get("completed_manifest_sha256") == EXPECTED_MANIFEST_SHA256,
        "database_sha256": parameters.get("completed_database_sha256") == EXPECTED_DATABASE_SHA256,
    }
    _require(all(checks.values()), f"{label}_profile_guard_failed:{checks}")
    return {"status": "passed", "checks": checks}


def _request_record(path: Path, spec: Mapping[str, Any]) -> dict[str, Any]:
    request, size, digest = _read_json(path, max_bytes=64 * 1024)
    expected = {
        "target_sha256": EXPECTED_EXE_SHA256,
        "node": hex(spec["rva"]),
        "procedure": hex(EXPECTED_IMAGE_BASE + spec["rva"]),
        "preset": EXPECTED_PRESET,
        "adapter_sha256": EXPECTED_ADAPTER_SHA256,
        "completed_manifest_sha256": EXPECTED_MANIFEST_SHA256,
        "completed_database_sha256": EXPECTED_DATABASE_SHA256,
        "query_reanalysis": False,
        "java_heap": "512M",
        "process_memory_limit_bytes": 1024 * 1024 * 1024,
    }
    checks = {key: request.get(key) == value for key, value in expected.items()}
    _require(all(checks.values()), f"{path}_request_guard_failed:{checks}")
    return {
        "path": relpath(path),
        "bytes": size,
        "sha256": digest,
        "checks": checks,
        "status": "passed",
    }


def _run_record(path: Path, spec: Mapping[str, Any], evidence_id: str) -> dict[str, Any]:
    run, size, digest = _read_json(path, max_bytes=64 * 1024)
    expected = {
        "target_sha256": EXPECTED_EXE_SHA256,
        "node": hex(spec["rva"]),
        "procedure": hex(EXPECTED_IMAGE_BASE + spec["rva"]),
        "preset": EXPECTED_PRESET,
        "adapter_sha256": EXPECTED_ADAPTER_SHA256,
        "completed_manifest_sha256": EXPECTED_MANIFEST_SHA256,
        "completed_database_sha256": EXPECTED_DATABASE_SHA256,
        "query_reanalysis": False,
        "java_heap": "512M",
        "process_memory_limit_bytes": 1024 * 1024 * 1024,
        "exit_code": 0,
        "reason": "completed",
        "database_unchanged": True,
        "evidence_id": evidence_id,
    }
    checks = {key: run.get(key) == value for key, value in expected.items()}
    _require(all(checks.values()), f"{path}_run_guard_failed:{checks}")
    processes = run.get("processes")
    _require(isinstance(processes, list) and processes, f"{path}_process_receipt_missing")
    peaks: list[int] = []
    for process in processes:
        _require(isinstance(process, Mapping), f"{path}_process_record_invalid")
        peak = process.get("peak_committed_bytes")
        _require(isinstance(peak, int) and not isinstance(peak, bool), f"{path}_peak_invalid")
        _require(peak < 1024 * 1024 * 1024, f"{path}_process_over_memory_bound")
        _require(process.get("still_running_same_process") is False, f"{path}_process_still_running")
        peaks.append(peak)
    return {
        "path": relpath(path),
        "bytes": size,
        "sha256": digest,
        "checks": checks,
        "process_count": len(processes),
        "peak_committed_bytes": max(peaks),
        "status": "passed",
    }


def _procedure_record(spec: Mapping[str, Any], evidence: Mapping[str, Any], path: Path, size: int, digest: str) -> dict[str, Any]:
    _require(evidence.get("evidence_id", "").startswith("ev_"), f"{path}_evidence_id_missing")
    subject = evidence.get("subject")
    _require(isinstance(subject, Mapping), f"{path}_subject_missing")
    _require(subject.get("digest", {}).get("sha256") == EXPECTED_EXE_SHA256, f"{path}_exe_sha_mismatch")
    provider = evidence.get("provider")
    _require(isinstance(provider, Mapping) and provider.get("version") == "12.1.4", f"{path}_provider_guard_failed")
    profile_guard = _fixed_metadata(evidence.get("analysis_profile", {}), f"{path}.analysis_profile")
    value = evidence.get("raw_result", {}).get("value")
    _require(isinstance(value, Mapping), f"{path}_raw_value_missing")
    procedure = value.get("procedure")
    _require(isinstance(procedure, Mapping), f"{path}_procedure_missing")
    address = _hex_int(procedure.get("address"), f"{path}.procedure.address")
    _require(address - EXPECTED_IMAGE_BASE == spec["rva"], f"{path}_procedure_rva_mismatch")
    body = procedure.get("body")
    _require(isinstance(body, Mapping), f"{path}_body_missing")
    body_record = _ranges(body, f"{path}.body")
    _require(body_record["rva_start"] == hex(spec["rva"]), f"{path}_body_start_mismatch")
    pseudocode = _pseudocode_summary(value.get("pseudocode"), tuple(spec["anchors"]), str(path))
    result = {
        "name": spec["name"],
        "role": spec["role"],
        "semantic_status": spec["semantic_status"],
        "evidence_id": evidence["evidence_id"],
        "evidence_path": relpath(path),
        "evidence_sha256": digest,
        "evidence_bytes": size,
        "provider": {"id": provider.get("id"), "name": provider.get("name"), "version": provider.get("version")},
        "analysis_profile_guard": profile_guard,
        "procedure": {
            "name": procedure.get("name"),
            "va": hex(address),
            "rva": hex(address - EXPECTED_IMAGE_BASE),
        },
        "rea_body_range": body_record,
        "pseudocode": pseudocode,
        "callers": _reference_list(value.get("callers"), f"{path}.callers"),
        "callees": _reference_list(value.get("callees"), f"{path}.callees"),
        "authority": {
            "kind": "static_rea_evidence_only",
            "native_function_invoked": False,
            "runtime_reader_established": False,
            "dispatch_authorized": False,
        },
    }
    return result


def _selected_value(report: Mapping[str, Any], key: str) -> Any:
    entry = report.get("raw_result_value", {}).get(key)
    _require(isinstance(entry, Mapping) and entry.get("status") == "observed", f"selected_{key}_not_observed")
    return entry.get("value")


def _large_procedure_record(spec: Mapping[str, Any]) -> dict[str, Any]:
    directory = STAGE / str(spec["directory"])
    selected_path = directory / "selected-evidence-001.json"
    recovery_path = directory / "readback-recovery-001.json"
    source_path = directory / "evidence.json"
    selected, selected_size, selected_sha = _read_json(selected_path)
    recovery, recovery_size, recovery_sha = _read_json(recovery_path)
    source_info = selected.get("source")
    _require(isinstance(source_info, Mapping), "large_source_identity_missing")
    source_size = source_info.get("size_bytes")
    source_sha = source_info.get("sha256")
    # The normal historical helper limit is 10 MiB; this source is just over
    # that limit but remains below the 16 MiB bound used for the other reports.
    _require(isinstance(source_size, int) and source_size > 10 * 1024 * 1024, "large_source_size_not_recorded")
    _require(isinstance(source_sha, str) and len(source_sha) == 64, "large_source_sha_missing")
    _require(source_path.stat().st_size == source_size, "large_source_size_changed")
    _, actual_source_sha = sha256_file(source_path, max_bytes=32 * 1024 * 1024)
    _require(actual_source_sha == source_sha, "large_source_sha_changed")
    top = selected.get("top_level")
    _require(isinstance(top, Mapping), "large_selected_top_missing")
    evidence_id = top.get("evidence_id", {}).get("value")
    subject_sha = top.get("subject", {}).get("value", {}).get("digest", {}).get("sha256")
    provider = top.get("provider", {}).get("value")
    _require(isinstance(evidence_id, str) and evidence_id.startswith("ev_"), "large_evidence_id_missing")
    _require(subject_sha == EXPECTED_EXE_SHA256, "large_subject_sha_mismatch")
    _require(isinstance(provider, Mapping) and provider.get("version") == "12.1.4", "large_provider_guard_failed")
    profile_value = top.get("analysis_profile", {}).get("value")
    profile_guard = _fixed_metadata(profile_value, "large.analysis_profile")
    procedure = _selected_value(selected, "procedure")
    _require(isinstance(procedure, Mapping), "large_procedure_missing")
    address = _hex_int(procedure.get("address"), "large.procedure.address")
    _require(address - EXPECTED_IMAGE_BASE == spec["rva"], "large_procedure_rva_mismatch")
    body = procedure.get("body")
    _require(isinstance(body, Mapping), "large_body_missing")
    body_record = _ranges(body, "large.body")
    _require(body_record["rva_start"] == hex(spec["rva"]), "large_body_start_mismatch")
    pseudo = _selected_value(selected, "pseudocode")
    pseudocode_record = _pseudocode_summary(pseudo, tuple(spec["anchors"]), "large.pseudocode")
    callers = _reference_list(_selected_value(selected, "callers"), "large.callers")
    callees = _reference_list(_selected_value(selected, "callees"), "large.callees")
    request_record = _request_record(directory / "request.json", spec)
    recovery_request = recovery.get("request")
    _require(isinstance(recovery_request, Mapping) and recovery_request.get("all_fixed_checks_pass") is True, "large_recovery_request_guard_failed")
    _require(recovery.get("selected_status") == "observed", "large_selected_status_failed")
    provider_runtime = recovery.get("provider_runtime")
    _require(isinstance(provider_runtime, Mapping) and provider_runtime.get("run_json_present") is False, "large_run_presence_changed")
    _require(provider_runtime.get("provider_exit_code") is None and provider_runtime.get("provider_peak_committed_bytes") is None, "large_unknown_runtime_was_inferred")
    postread = recovery.get("original_shell_postread")
    _require(isinstance(postread, Mapping) and postread.get("exit_code") == 1, "large_postread_receipt_missing")
    return {
        "name": spec["name"],
        "role": spec["role"],
        "semantic_status": spec["semantic_status"],
        "evidence_id": evidence_id,
        "evidence_path": relpath(source_path),
        "evidence_sha256": source_sha,
        "evidence_bytes": source_size,
        "source_integrity": "hash_streamed_selected_spans_only_whole_json_not_validated",
        "selected_report": {"path": relpath(selected_path), "bytes": selected_size, "sha256": selected_sha},
        "recovery_report": {"path": relpath(recovery_path), "bytes": recovery_size, "sha256": recovery_sha},
        "provider": {"id": provider.get("id"), "name": provider.get("name"), "version": provider.get("version")},
        "analysis_profile_guard": profile_guard,
        "procedure": {
            "name": procedure.get("name"),
            "va": hex(address),
            "rva": hex(address - EXPECTED_IMAGE_BASE),
        },
        "rea_body_range": body_record,
        "pseudocode": pseudocode_record,
        "callers": callers,
        "callees": callees,
        "execution_receipt": {
            "run_json_present": False,
            "provider_exit_code": None,
            "provider_peak_committed_bytes": None,
            "status": "unknown",
            "reason": "run.json absent; provider exit and peak remain unknown",
            "original_shell_postread": {
                "shell_id": postread.get("shell_id"),
                "exit_code": postread.get("exit_code"),
                "phase": postread.get("phase"),
                "reported_reason": postread.get("reported_reason"),
            },
        },
        "request": request_record,
        "authority": {
            "kind": "static_rea_selected_spans_only",
            "native_function_invoked": False,
            "runtime_reader_established": False,
            "dispatch_authorized": False,
        },
    }


def collect_rea_records() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for spec in REA_SPECS:
        directory = STAGE / str(spec["directory"])
        if spec.get("large"):
            records.append(_large_procedure_record(spec))
            continue
        evidence_path = directory / "evidence.json"
        request_path = directory / "request.json"
        run_path = directory / "run.json"
        evidence, size, digest = _read_json(evidence_path)
        record = _procedure_record(spec, evidence, evidence_path, size, digest)
        record["request"] = _request_record(request_path, spec)
        record["run"] = _run_record(run_path, spec, str(record["evidence_id"]))
        records.append(record)
    return records


def _file_record(relative_path: str, role: str, *, required: bool = True) -> dict[str, Any]:
    path = ROOT / relative_path
    if not path.exists():
        if required:
            raise FileNotFoundError(path)
        return {"path": relative_path, "role": role, "status": "missing"}
    size, digest = sha256_file(path, max_bytes=MAX_JSON_BYTES)
    return {"path": relative_path, "role": role, "bytes": size, "sha256": digest, "status": "observed"}


def _production_pins() -> list[dict[str, Any]]:
    result = [_file_record(path, role) for path, role in PRODUCTION_FILES]
    result.append(
        {
            "path": "work/runtime/information-mission-rewards-20261025-001/delivery/manifest.json",
            "role": "previous batch exact baseline manifest",
            "expected_sha256": EXPECTED_BATCH_MANIFEST_SHA256,
            **_file_record(
                "work/runtime/information-mission-rewards-20261025-001/delivery/manifest.json",
                "previous batch exact baseline manifest",
            ),
        }
    )
    manifest = result[-1]
    _require(manifest.get("sha256") == EXPECTED_BATCH_MANIFEST_SHA256, "previous_batch_manifest_sha_mismatch")
    return result


def _coverage_record() -> dict[str, Any]:
    path = ROOT / "docs/信息字段覆盖.json"
    data, size, digest = _read_json(path)
    counts = data.get("counts")
    _require(isinstance(counts, Mapping), "coverage_counts_missing")
    expected = {
        "topic_count": 74,
        "field_count": 397,
        "callable_topic_count": 35,
        "available_topic_count": 35,
    }
    actual = {key: counts.get(key) for key in expected}
    actual["field_counts"] = counts.get("field_counts")
    _require(actual["field_counts"] == {"available": 51, "partial": 110, "planned": 236}, "coverage_field_counts_changed")
    _require(all(actual[key] == value for key, value in expected.items()), f"coverage_counts_changed:{actual}")
    _require(data.get("goal_complete") is False, "coverage_goal_complete_unexpected")
    return {
        "path": relpath(path),
        "bytes": size,
        "sha256": digest,
        "counts": actual,
        "goal_complete": False,
        "status": data.get("status"),
    }


def _survey_records() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path, role in SURVEY_FILES:
        records.append(_file_record(path, role))
    for path, role in EXISTING_PROOF_FILES:
        records.append(_file_record(path, role))
    return records


def _native_source_records() -> list[dict[str, Any]]:
    return [_file_record(path, role) for path, role in NATIVE_SOURCE_FILES]


def _index(records: list[dict[str, Any]], coverage: dict[str, Any], surveys: list[dict[str, Any]], native_sources: list[dict[str, Any]], production: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": "information_battles_research_index_v1",
        "status": "static_rea_indexed_runtime_unresolved",
        "batch": "information-battles-20261025-001",
        "scope": {
            "read_only": True,
            "game_version": EXPECTED_GAME_VERSION,
            "executable_sha256": EXPECTED_EXE_SHA256,
            "image_base": hex(EXPECTED_IMAGE_BASE),
            "no_game_or_process": True,
            "no_new_rea": True,
            "no_dispatch": True,
            "large_evidence_policy": "22e6b0 uses selected/recovery; source is streamed-hashed and whole JSON remains unvalidated",
        },
        "analysis_identity": {
            "preset": EXPECTED_PRESET,
            "adapter_sha256": EXPECTED_ADAPTER_SHA256,
            "completed_manifest_sha256": EXPECTED_MANIFEST_SHA256,
            "completed_database_sha256": EXPECTED_DATABASE_SHA256,
        },
        "rea_records": records,
        "source_surveys_and_proof_boundaries": surveys,
        "native_source_hashes": native_sources,
        "production_pins": production,
        "coverage_snapshot": coverage,
        "on_action_boundary": {
            "status": "static_definitions_observed_effective_runtime_merge_unresolved",
            "native_enum_mapping": "unknown",
            "runtime_capture": False,
            "dispatch_authorized": False,
        },
        "interpretation_limits": [
            "The six procedures are fixed-build static REA observations, not a public battle reader contract.",
            "The loss-summary directory name is temporary; its semantics are recorded only as aggregate unknown.",
            "The result object, non-siege builder, effects callback, and router do not establish field names, units, sign, ownership, lifetime, land/naval parity, or retention.",
            "Message and GUI string references do not prove a structured battle payload.",
            "Existing war-score/save/native proof remains a separate recorded/static boundary and does not authorize runtime dispatch.",
            "B01-B04 remain planned; no positive battle event, complete trigger, or per-battle runtime observation is present.",
        ],
        "goal_complete": False,
    }


def _source_audit(index: Mapping[str, Any], coverage: dict[str, Any], surveys: list[dict[str, Any]], native_sources: list[dict[str, Any]], production: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": "information_battles_source_audit_v1",
        "status": "passed_static_freeze_runtime_unresolved",
        "batch": "information-battles-20261025-001",
        "identity": index["scope"],
        "production_changed": False,
        "native_function_invoked": False,
        "runtime_observation": False,
        "dispatch_authorized": False,
        "rea_count": len(index["rea_records"]),
        "rea_evidence_ids": [record["evidence_id"] for record in index["rea_records"]],
        "rea_boundaries": [
            {
                "name": record["name"],
                "evidence_id": record["evidence_id"],
                "evidence_sha256": record["evidence_sha256"],
                "procedure": record["procedure"],
                "rea_body_range": record["rea_body_range"],
                "semantic_status": record["semantic_status"],
            }
            for record in index["rea_records"]
        ],
        "source_surveys": surveys,
        "native_source_hashes": native_sources,
        "existing_native_proof_boundary": {
            "kind": "recorded_or_static_only",
            "runtime_reader": False,
            "dispatch_authorized": False,
            "notes": "War-score, save, GUI and on_action evidence is retained for boundary checking; none closes a per-battle result reader.",
        },
        "production_pins": production,
        "coverage": {
            **coverage,
            "battle_topics": {
                "B01": "planned",
                "B02": "planned",
                "B03": "planned",
                "B04": "planned",
            },
        },
        "unknowns": [
            "per-battle result object public field layout",
            "land/naval result parity and field units",
            "closed-result retention and event identity",
            "on_action effective runtime merge and native enum binding",
            "positive runtime battle event and complete trigger inputs",
        ],
        "goal_complete": False,
    }


def build() -> tuple[dict[str, Any], dict[str, Any]]:
    if INDEX_PATH.exists() or SOURCE_AUDIT_PATH.exists():
        raise FileExistsError("refusing_to_overwrite_battle_research_outputs")
    coverage = _coverage_record()
    records = collect_rea_records()
    surveys = _survey_records()
    native_sources = _native_source_records()
    production = _production_pins()
    index = _index(records, coverage, surveys, native_sources, production)
    audit = _source_audit(index, coverage, surveys, native_sources, production)
    return index, audit


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    index, audit = build()
    index_bytes, index_sha = _write_json_new(INDEX_PATH, index, overwrite=False)
    audit_bytes, audit_sha = _write_json_new(SOURCE_AUDIT_PATH, audit, overwrite=False)
    print(
        json.dumps(
            {
                "status": "passed",
                "research_index": {"path": relpath(INDEX_PATH), "bytes": index_bytes, "sha256": index_sha},
                "source_audit": {"path": relpath(SOURCE_AUDIT_PATH), "bytes": audit_bytes, "sha256": audit_sha},
                "rea_count": len(index["rea_records"]),
                "goal_complete": False,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
