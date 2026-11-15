"""Freeze the bounded battle-layout REA evidence already in the layout stage.

This is a readback-only freezer.  It does not call REA, inspect a process, or
start the game.  The 0x232a80 evidence is 10 MiB-plus, so its selected fields
are read through the existing mmap span scanner; the raw document is only
stream-hashed and is never passed to ``json.load``.

The resulting index keeps the seven requested fixed-build procedures separate
from runtime semantics.  The 0x1dcb10 query is retained as a selection error
and is explicitly excluded from the side-writer interpretation; 0x1dce20 is
the selected side-writer candidate.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
STAGE = ROOT / "work" / "runtime" / "information-battle-layout-20261025-001"
IMAGE_BASE = 0x140000000
EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
GAME_VERSION = "1.37.4"
PROVIDER_VERSION = "12.1.4"
PRESET = "eu4-persistent-default-analysis-v1"
ADAPTER_SHA256 = "93620e986ea9ea17f5b6a8e56a5077772af0090a8d0eb467019aea40d38a689d"
MANIFEST_SHA256 = "de1c738fa2bc9027ceacadabb7828d9890f5f9ff57ec4cde60494968f927333a"
DATABASE_SHA256 = "8eec1cad93cce37d2f958c100570550bc7212c5aa86b92b7cf03950f85a83161"
PROCESS_LIMIT = 1024 * 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_REQUEST_BYTES = 64 * 1024
MAX_RUN_BYTES = 64 * 1024
MAX_REFERENCES = 256


REA_SPECS: tuple[dict[str, Any], ...] = (
    {
        "rva": 0x1DD020,
        "directory": "rea-result-initializer-001",
        "role": "battle result initializer",
        "semantic_status": "initializer_structure_observed_field_semantics_unknown",
        "kind": "selected",
    },
    {
        "rva": 0x1DD930,
        "directory": "rea-result-postprocess-001",
        "role": "battle result postprocess",
        "semantic_status": "postprocess_structure_observed_field_semantics_unknown",
        "kind": "selected",
    },
    {
        "rva": 0x232A80,
        "directory": "rea-land-result-message-001",
        "role": "land result message dispatch candidate",
        "semantic_status": "selected_static_dispatch_pseudocode_only",
        "kind": "large",
    },
    {
        "rva": 0x1DCA60,
        "directory": "rea-side-initializer-001",
        "role": "side-result initializer",
        "semantic_status": "side_initializer_structure_observed_field_semantics_unknown",
        "kind": "raw",
    },
    {
        "rva": 0x1DD240,
        "directory": "rea-result-member-002-001",
        "role": "result save-key writer candidate",
        "semantic_status": "conditional_writer_literals_observed_field_semantics_unknown",
        "kind": "raw",
    },
    {
        "rva": 0x1DCB10,
        "directory": "rea-side-writer-candidate-001",
        "role": "incorrect side-writer candidate retained for audit",
        "semantic_status": "selection_error",
        "selection_error": True,
        "kind": "raw",
    },
    {
        "rva": 0x1DCE20,
        "directory": "rea-side-writer-001",
        "role": "selected side-result save writer",
        "semantic_status": "writer_structure_observed_field_semantics_unknown",
        "kind": "raw",
    },
)


RELATED_REPORTS: tuple[tuple[str, str], ...] = (
    (
        "work/runtime/information-battle-layout-20261025-001/result-save-keys-001.json",
        "result writer compiled save-key inventory; runtime key-vector override unresolved",
    ),
    (
        "work/runtime/information-battle-layout-20261025-001/side-save-keys-001.json",
        "side writer compiled save-key inventory; runtime key-vector override unresolved",
    ),
    (
        "work/runtime/information-battle-layout-20261025-001/land-message-field-ledger-001.json",
        "land-message selected pseudocode field ledger; units and lifetime unresolved",
    ),
    (
        "work/runtime/information-battles-20261025-001/battle-stage/result-vtable-window-001.json",
        "older-stage bounded result vtable window; static architecture boundary",
    ),
    (
        "work/runtime/information-battles-20261025-001/layout/capture-integration-survey-001.json",
        "older-stage capture architecture survey; capture module not implemented",
    ),
    (
        "work/runtime/information-battle-layout-20261025-001/native-buffer-test-001/report.json",
        "bounded queue/buffer test; not battle payload evidence",
    ),
    (
        "work/runtime/information-battle-layout-20261025-001/startup-path-audit-001.json",
        "read-only startup/install path audit; no new runtime run",
    ),
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _sha256_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def _relpath(path: Path) -> str:
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def _json(path: Path, *, limit: int = MAX_JSON_BYTES) -> tuple[dict[str, Any], int, str]:
    size = path.stat().st_size
    _require(size <= limit, f"json_over_bound:{path}:{size}>{limit}")
    raw = path.read_bytes()
    _require(len(raw) == size, f"file_changed_during_read:{path}")
    value = json.loads(raw.decode("utf-8-sig"))
    _require(isinstance(value, dict), f"json_object_required:{path}")
    return value, size, hashlib.sha256(raw).hexdigest()


def _int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"boolean_not_integer:{label}")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as error:
            raise ValueError(f"invalid_integer:{label}:{value}") from error
    raise ValueError(f"invalid_integer:{label}")


def _observed(entry: Any, label: str) -> Any:
    _require(isinstance(entry, Mapping), f"{label}_not_object")
    _require(entry.get("status") == "observed", f"{label}_not_observed")
    return entry.get("value")


def _profile_guard(profile: Any, label: str) -> dict[str, Any]:
    _require(isinstance(profile, Mapping), f"{label}_profile_missing")
    parameters = profile.get("parameters")
    _require(isinstance(parameters, Mapping), f"{label}_profile_parameters_missing")
    expected = {
        "analyzer_preset": PRESET,
        "target_format": "pe",
        "target_kind": "executable",
        "architecture": "x86_64",
        "import_mode": "persistent-completed-project-read-only",
        "database_mutation": "read-only-no-save",
        "query_reanalysis": False,
        "local_adapter_sha256": ADAPTER_SHA256,
        "completed_manifest_sha256": MANIFEST_SHA256,
        "completed_database_sha256": DATABASE_SHA256,
    }
    checks = {key: parameters.get(key) == value for key, value in expected.items()}
    _require(all(checks.values()), f"{label}_profile_guard_failed:{checks}")
    return {
        "status": "passed",
        "checks": checks,
        "profile_digest": profile.get("digest"),
        "parameters_keys": sorted(str(key) for key in parameters),
    }


def _body_ranges(body: Any, label: str) -> dict[str, Any]:
    _require(isinstance(body, Mapping), f"{label}_body_missing")
    raw_ranges = body.get("ranges")
    _require(isinstance(raw_ranges, list) and raw_ranges, f"{label}_ranges_missing")
    ranges: list[dict[str, Any]] = []
    parsed: list[tuple[int, int]] = []
    for index, raw in enumerate(raw_ranges):
        _require(isinstance(raw, Mapping), f"{label}_range_{index}_not_object")
        start = _int(raw.get("start"), f"{label}.ranges[{index}].start")
        end = _int(raw.get("end"), f"{label}.ranges[{index}].end")
        _require(start >= IMAGE_BASE and end >= start, f"{label}_range_{index}_invalid")
        parsed.append((start, end))
        ranges.append(
            {
                "va_start": hex(start),
                "va_end_inclusive": hex(end),
                "va_end_exclusive": hex(end + 1),
                "rva_start": hex(start - IMAGE_BASE),
                "rva_end_inclusive": hex(end - IMAGE_BASE),
                "rva_end_exclusive": hex(end - IMAGE_BASE + 1),
            }
        )
    total = sum(end - start + 1 for start, end in parsed)
    min_start = min(start for start, _ in parsed)
    max_end = max(end for _, end in parsed)
    span = max_end - min_start + 1
    _require(body.get("total_bytes") == total, f"{label}_total_bytes_mismatch")
    _require(body.get("span_bytes") == span, f"{label}_span_bytes_mismatch")
    return {
        "rva_start": hex(min_start - IMAGE_BASE),
        "rva_end_inclusive": hex(max_end - IMAGE_BASE),
        "rva_end_exclusive": hex(max_end - IMAGE_BASE + 1),
        "va_start": hex(min_start),
        "va_end_inclusive": hex(max_end),
        "va_end_exclusive": hex(max_end + 1),
        "total_body_bytes": total,
        "span_bytes": span,
        "range_count": len(ranges),
        "end_semantics": "REA procedure.body.ranges end is inclusive",
        "ranges": ranges,
    }


def _references(value: Any, label: str) -> list[dict[str, Any]]:
    _require(isinstance(value, list), f"{label}_not_list")
    _require(len(value) <= MAX_REFERENCES, f"{label}_over_bound")
    result: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        _require(isinstance(item, Mapping), f"{label}_{index}_not_object")
        address = _int(item.get("address"), f"{label}[{index}].address")
        _require(address >= IMAGE_BASE, f"{label}_{index}_below_image")
        record: dict[str, Any] = {
            "va": hex(address),
            "rva": hex(address - IMAGE_BASE),
        }
        if isinstance(item.get("name"), str):
            record["name"] = item["name"]
        result.append(record)
    return result


def _pseudocode_record(value: Any, label: str) -> dict[str, Any]:
    _require(isinstance(value, str), f"{label}_missing")
    encoded = value.encode("utf-8")
    _require(len(encoded) <= 2 * 1024 * 1024, f"{label}_over_bound")
    return {
        "utf8_bytes": len(encoded),
        "sha256_utf8": hashlib.sha256(encoded).hexdigest(),
        "line_count": value.count("\n") + 1,
    }


def _request_record(path: Path, rva: int) -> dict[str, Any]:
    data, size, digest = _json(path, limit=MAX_REQUEST_BYTES)
    expected = {
        "target_sha256": EXE_SHA256,
        "node": hex(rva),
        "procedure": hex(IMAGE_BASE + rva),
        "preset": PRESET,
        "adapter_sha256": ADAPTER_SHA256,
        "completed_manifest_sha256": MANIFEST_SHA256,
        "completed_database_sha256": DATABASE_SHA256,
        "query_reanalysis": False,
        "java_heap": "512M",
        "process_memory_limit_bytes": PROCESS_LIMIT,
    }
    checks = {key: data.get(key) == value for key, value in expected.items()}
    _require(all(checks.values()), f"{path}_request_guard_failed:{checks}")
    return {
        "path": _relpath(path),
        "bytes": size,
        "sha256": digest,
        "checks": checks,
        "status": "passed",
    }


def _run_record(path: Path, rva: int, evidence_id: str) -> dict[str, Any]:
    data, size, digest = _json(path, limit=MAX_RUN_BYTES)
    expected = {
        "target_sha256": EXE_SHA256,
        "node": hex(rva),
        "procedure": hex(IMAGE_BASE + rva),
        "preset": PRESET,
        "adapter_sha256": ADAPTER_SHA256,
        "completed_manifest_sha256": MANIFEST_SHA256,
        "completed_database_sha256": DATABASE_SHA256,
        "query_reanalysis": False,
        "java_heap": "512M",
        "process_memory_limit_bytes": PROCESS_LIMIT,
        "exit_code": 0,
        "reason": "completed",
        "database_unchanged": True,
        "evidence_id": evidence_id,
    }
    checks = {key: data.get(key) == value for key, value in expected.items()}
    processes = data.get("processes")
    _require(isinstance(processes, list) and processes, f"{path}_process_receipt_missing")
    process_records: list[dict[str, Any]] = []
    for index, process in enumerate(processes):
        _require(isinstance(process, Mapping), f"{path}_process_{index}_not_object")
        peak = process.get("peak_committed_bytes")
        _require(isinstance(peak, int) and not isinstance(peak, bool), f"{path}_peak_invalid")
        _require(peak < PROCESS_LIMIT, f"{path}_peak_over_1gb")
        _require(process.get("still_running_same_process") is False, f"{path}_process_not_closed")
        process_records.append(
            {
                "peak_committed_bytes": peak,
                "below_1gb": True,
                "closed": True,
            }
        )
    checks["process_receipt"] = True
    _require(all(checks.values()), f"{path}_run_guard_failed:{checks}")
    return {
        "path": _relpath(path),
        "bytes": size,
        "sha256": digest,
        "checks": checks,
        "processes": process_records,
        "peak_committed_bytes": max(item["peak_committed_bytes"] for item in process_records),
        "status": "passed",
    }


def _raw_projection(spec: Mapping[str, Any]) -> dict[str, Any]:
    directory = STAGE / str(spec["directory"])
    evidence_path = directory / "evidence.json"
    _require(evidence_path.is_file(), f"evidence_missing:{evidence_path}")
    selected_path = directory / "selected-evidence-001.json"
    readback_path = directory / "readback-recovery-001.json"
    kind = str(spec["kind"])
    selected_report: dict[str, Any] | None = None
    readback_report: dict[str, Any] | None = None

    if kind == "raw":
        evidence, size, digest = _json(evidence_path)
        top = {
            "evidence_id": {"status": "observed", "value": evidence.get("evidence_id")},
            "subject": {"status": "observed", "value": evidence.get("subject")},
            "provider": {"status": "observed", "value": evidence.get("provider")},
            "analysis_profile": {"status": "observed", "value": evidence.get("analysis_profile")},
        }
        raw_value = evidence.get("raw_result", {}).get("value")
        _require(isinstance(raw_value, Mapping), f"{evidence_path}_raw_value_missing")
        values = {
            key: {"status": "observed", "value": raw_value.get(key)}
            for key in ("procedure", "pseudocode", "callers", "callees")
        }
        source = {"path": _relpath(evidence_path), "size_bytes": size, "sha256": digest}
        raw_integrity = "bounded_json_loaded"
    else:
        _require(selected_path.is_file(), f"selected_report_missing:{selected_path}")
        if kind == "large":
            # This call hashes and mmap-scans only selected top-level/raw-result
            # spans; it never deserializes the 10 MiB-plus source document.
            from work.extract_information_battle_layout_evidence import _extract_selected

            extracted = _extract_selected(evidence_path)
            _require(extracted.get("status") == "observed", f"{evidence_path}_selected_scan_not_observed")
            top = extracted.get("top_level")
            values = extracted.get("raw_result_value")
            source = extracted.get("source")
            _require(isinstance(top, Mapping) and isinstance(values, Mapping), f"{evidence_path}_selected_projection_missing")
            _require(isinstance(source, Mapping), f"{evidence_path}_source_identity_missing")
            raw_integrity = "mmap_selected_spans_whole_json_not_validated"
        else:
            selected, selected_size, selected_digest = _json(selected_path)
            _require(selected.get("status") == "observed", f"{selected_path}_not_observed")
            top = selected.get("top_level")
            values = selected.get("raw_result_value")
            source = selected.get("source")
            _require(isinstance(top, Mapping) and isinstance(values, Mapping), f"{selected_path}_projection_missing")
            _require(isinstance(source, Mapping), f"{selected_path}_source_identity_missing")
            selected_report = {
                "path": _relpath(selected_path),
                "bytes": selected_size,
                "sha256": selected_digest,
            }
            raw_integrity = "mmap_selected_spans_whole_json_not_validated"
        if kind == "large":
            selected, selected_size, selected_digest = _json(selected_path)
            _require(selected.get("status") == "observed", f"{selected_path}_not_observed")
            selected_source = selected.get("source")
            _require(isinstance(selected_source, Mapping), f"{selected_path}_source_missing")
            _require(selected_source.get("sha256") == source.get("sha256"), f"{selected_path}_source_sha_mismatch")
            _require(selected_source.get("size_bytes") == source.get("size_bytes"), f"{selected_path}_source_size_mismatch")
            selected_report = {
                "path": _relpath(selected_path),
                "bytes": selected_size,
                "sha256": selected_digest,
            }

    actual_source_size, actual_source_sha = _sha256_file(evidence_path)
    _require(source.get("size_bytes") == actual_source_size, f"{evidence_path}_source_size_changed")
    _require(source.get("sha256") == actual_source_sha, f"{evidence_path}_source_sha_changed")
    if readback_path.is_file():
        readback, readback_size, readback_digest = _json(readback_path)
        _require(readback.get("status") == "observed", f"{readback_path}_not_observed")
        _require(readback.get("evidence", {}).get("sha256") == actual_source_sha, f"{readback_path}_source_sha_mismatch")
        _require(readback.get("request", {}).get("all_fixed_checks_pass") is True, f"{readback_path}_request_guard_failed")
        _require(readback.get("profile_audit", {}).get("status") == "observed", f"{readback_path}_profile_guard_failed")
        readback_report = {
            "path": _relpath(readback_path),
            "bytes": readback_size,
            "sha256": readback_digest,
            "status": readback.get("status"),
        }

    evidence_id = _observed(top.get("evidence_id"), f"{evidence_path}.evidence_id")
    _require(isinstance(evidence_id, str) and evidence_id.startswith("ev_"), f"{evidence_path}_evidence_id_invalid")
    subject = _observed(top.get("subject"), f"{evidence_path}.subject")
    provider = _observed(top.get("provider"), f"{evidence_path}.provider")
    profile = _observed(top.get("analysis_profile"), f"{evidence_path}.analysis_profile")
    _require(isinstance(subject, Mapping), f"{evidence_path}_subject_invalid")
    _require(subject.get("digest", {}).get("sha256") == EXE_SHA256, f"{evidence_path}_subject_sha_mismatch")
    _require(isinstance(provider, Mapping) and provider.get("version") == PROVIDER_VERSION, f"{evidence_path}_provider_mismatch")
    procedure = _observed(values.get("procedure"), f"{evidence_path}.procedure")
    _require(isinstance(procedure, Mapping), f"{evidence_path}_procedure_invalid")
    address = _int(procedure.get("address"), f"{evidence_path}.procedure.address")
    rva = int(spec["rva"])
    _require(address == IMAGE_BASE + rva, f"{evidence_path}_procedure_rva_mismatch")
    body = _body_ranges(procedure.get("body"), f"{evidence_path}.procedure.body")
    _require(body["rva_start"] == hex(rva), f"{evidence_path}_body_entry_mismatch")
    pseudocode = _pseudocode_record(_observed(values.get("pseudocode"), f"{evidence_path}.pseudocode"), f"{evidence_path}.pseudocode")
    callers = _references(_observed(values.get("callers"), f"{evidence_path}.callers"), f"{evidence_path}.callers")
    callees = _references(_observed(values.get("callees"), f"{evidence_path}.callees"), f"{evidence_path}.callees")
    return {
        "evidence_id": evidence_id,
        "evidence_path": _relpath(evidence_path),
        "evidence_bytes": actual_source_size,
        "evidence_sha256": actual_source_sha,
        "source_integrity": raw_integrity,
        "selected_report": selected_report,
        "readback_report": readback_report,
        "subject_sha256": subject.get("digest", {}).get("sha256"),
        "provider": {"id": provider.get("id"), "name": provider.get("name"), "version": provider.get("version")},
        "profile_guard": _profile_guard(profile, str(evidence_path)),
        "procedure": {
            "name": procedure.get("name"),
            "va": hex(address),
            "rva": hex(address - IMAGE_BASE),
        },
        "rea_body_range": body,
        "pseudocode": pseudocode,
        "callers": callers,
        "callees": callees,
    }


def _rea_record(spec: Mapping[str, Any]) -> dict[str, Any]:
    directory = STAGE / str(spec["directory"])
    projection = _raw_projection(spec)
    request = _request_record(directory / "request.json", int(spec["rva"]))
    run = _run_record(directory / "run.json", int(spec["rva"]), str(projection["evidence_id"]))
    selection_error = bool(spec.get("selection_error"))
    return {
        "rva": hex(int(spec["rva"])),
        "va": hex(IMAGE_BASE + int(spec["rva"])),
        "role": spec["role"],
        "semantic_status": spec["semantic_status"],
        "selection_role": "selection_error" if selection_error else "selected_layout_evidence",
        "usable_for_writer_semantics": not selection_error,
        **projection,
        "request": request,
        "run": run,
        "authority": {
            "kind": "static_rea_evidence_only",
            "read_only": True,
            "native_function_invoked": False,
            "game_access": False,
            "runtime_reader_established": False,
            "dispatch_authorized": False,
        },
    }


def _related_file(path_text: str, role: str) -> dict[str, Any]:
    path = ROOT / path_text
    _require(path.is_file(), f"related_file_missing:{path}")
    size, digest = _sha256_file(path)
    record: dict[str, Any] = {
        "path": path_text,
        "role": role,
        "bytes": size,
        "sha256": digest,
        "status": "observed",
    }
    if size <= MAX_JSON_BYTES and path.suffix.lower() == ".json":
        data, _, _ = _json(path)
        record["schema"] = data.get("schema")
        record["report_status"] = data.get("status")
        if path.name == "startup-path-audit-001.json":
            record["static_operations_only"] = data.get("operations_not_performed")
        if path.name in {"result-save-keys-001.json", "side-save-keys-001.json"}:
            record["goal_complete"] = data.get("goal_complete", False)
    return record


def build() -> tuple[dict[str, Any], dict[str, Any]]:
    index_path = STAGE / "research-index-001.json"
    audit_path = STAGE / "source-audit-001.json"
    if index_path.exists() or audit_path.exists():
        raise FileExistsError("refusing_to_overwrite_battle_layout_research_outputs")
    rea_records = [_rea_record(spec) for spec in REA_SPECS]
    related = [_related_file(path, role) for path, role in RELATED_REPORTS]
    selection_errors = [record for record in rea_records if record["selection_role"] == "selection_error"]
    index = {
        "schema": "information_battle_layout_research_index_v1",
        "status": "static_rea_indexed_runtime_unresolved",
        "batch": "information-battle-layout-20261025-001",
        "scope": {
            "read_only": True,
            "game_version": GAME_VERSION,
            "executable_sha256": EXE_SHA256,
            "image_base": hex(IMAGE_BASE),
            "no_new_rea": True,
            "no_game_or_process": True,
            "no_rpm": True,
            "no_dispatch": True,
            "large_evidence_policy": "0x232a80 source is streamed-hashed and mmap-selected; whole JSON syntax is not revalidated",
        },
        "analysis_identity": {
            "provider": "Ghidra",
            "provider_version": PROVIDER_VERSION,
            "preset": PRESET,
            "adapter_sha256": ADAPTER_SHA256,
            "completed_manifest_sha256": MANIFEST_SHA256,
            "completed_database_sha256": DATABASE_SHA256,
            "process_memory_limit_bytes": PROCESS_LIMIT,
        },
        "rea_count": len(rea_records),
        "usable_layout_evidence_count": len(rea_records) - len(selection_errors),
        "selection_error_count": len(selection_errors),
        "rea_records": rea_records,
        "related_reports": related,
        "semantic_boundaries": {
            "wrong_candidate": {
                "rva": "0x1dcb10",
                "evidence_id": next(record["evidence_id"] for record in rea_records if record["rva"] == "0x1dcb10"),
                "status": "selection_error",
                "used_for_writer_semantics": False,
                "reason": "1dcb10 is retained as the rejected side-writer candidate; 1dce20 is the selected side-writer query.",
            },
            "selected_side_writer": {
                "rva": "0x1dce20",
                "status": "static_writer_structure_only",
                "field_semantics": "unknown",
                "runtime_key_vector_override": "unknown",
            },
        },
        "interpretation_limits": [
            "All seven records are fixed 1.37.4 static REA observations; none is a runtime reader or callable native query contract.",
            "Procedure body ranges preserve REA inclusive end semantics and are reported separately from the RVA/VA entry.",
            "Save-key inventories record compiled literals only. They do not assign a field, width, sign, scale, side, or current runtime membership.",
            "The land message ledger, old vtable window, and architecture survey remain static boundaries; they do not prove a structured battle payload or event identity.",
            "B01-B04 remain planned; no live battle event, complete trigger, or runtime positive change was captured.",
        ],
        "goal_complete": False,
    }
    audit = {
        "schema": "information_battle_layout_source_audit_v1",
        "status": "passed_static_freeze_runtime_unresolved",
        "batch": index["batch"],
        "identity": index["scope"],
        "rea_count": len(rea_records),
        "usable_layout_evidence_count": len(rea_records) - len(selection_errors),
        "selection_error_count": len(selection_errors),
        "fixed_executable_sha256": EXE_SHA256,
        "all_profile_request_run_guards": True,
        "all_processes_closed_below_1gb": True,
        "large_evidence_readback": {
            "rva": "0x232a80",
            "method": "existing mmap span scanner",
            "raw_json_loaded_as_whole": False,
            "raw_json_syntax_revalidated": False,
            "selected_and_recovery_reports": True,
        },
        "rea_boundaries": [
            {
                "rva": record["rva"],
                "va": record["va"],
                "evidence_id": record["evidence_id"],
                "evidence_path": record["evidence_path"],
                "evidence_sha256": record["evidence_sha256"],
                "request_sha256": record["request"]["sha256"],
                "run_sha256": record["run"]["sha256"],
                "profile_guard": record["profile_guard"],
                "rea_body_range": record["rea_body_range"],
                "selection_role": record["selection_role"],
                "usable_for_writer_semantics": record["usable_for_writer_semantics"],
            }
            for record in rea_records
        ],
        "related_reports": related,
        "runtime_and_authority": {
            "native_function_invoked": False,
            "game_or_process_called": False,
            "new_rea_called": False,
            "production_changed": False,
            "dispatch_authorized": False,
            "runtime_reader_established": False,
        },
        "unknowns": [
            "battle result field names, units, sign and ownership",
            "runtime key-vector membership and override path",
            "result object lifetime, retention, event identity and deduplication",
            "land/naval parity and effective on_action/native enumeration",
            "positive runtime battle event and complete B01-B04 capture contract",
        ],
        "goal_complete": False,
    }
    return index, audit


def _write_new(path: Path, value: Mapping[str, Any]) -> tuple[int, str]:
    if path.exists():
        raise FileExistsError(f"refusing_to_overwrite:{path}")
    raw = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.write_bytes(raw)
    return len(raw), hashlib.sha256(raw).hexdigest()


def main() -> int:
    index, audit = build()
    index_path = STAGE / "research-index-001.json"
    audit_path = STAGE / "source-audit-001.json"
    index_bytes, index_sha = _write_new(index_path, index)
    audit_bytes, audit_sha = _write_new(audit_path, audit)
    print(json.dumps({
        "status": "passed",
        "research_index": {"path": _relpath(index_path), "bytes": index_bytes, "sha256": index_sha},
        "source_audit": {"path": _relpath(audit_path), "bytes": audit_bytes, "sha256": audit_sha},
        "rea_count": index["rea_count"],
        "selection_error_count": index["selection_error_count"],
        "goal_complete": False,
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
