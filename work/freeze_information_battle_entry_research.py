"""Archive the bounded 53-byte war-lookup REA receipt.

This is a read-only archival verifier.  It consumes the already completed
request, evidence, and run receipts for FUN_140a688b0.  It never invokes REA,
opens the game, reads a process, or treats the static lookup as a battle/war
business reader.  The root semantic ledger is an independent gate; while it
is absent the generated reports remain prepared and incomplete.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work" / "runtime" / "information-battle-entry-20261025-001"
QUERY_REL = (
    "work/runtime/information-battle-entry-20261025-001/"
    "rea-country-relation-war-001"
)
REQUEST_REL = f"{QUERY_REL}/request.json"
EVIDENCE_REL = f"{QUERY_REL}/evidence.json"
RUN_REL = f"{QUERY_REL}/run.json"
INDEX_PATH = STAGE / "research-index-001.json"
SOURCE_AUDIT_PATH = STAGE / "source-audit-001.json"
ROOT_LEDGER_REL = (
    "work/runtime/information-battle-entry-20261025-001/"
    "warlookup-ledger-001.json"
)

FIXED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
FIXED_EXE_SIZE = 38_463_016
IMAGE_BASE = 0x140000000
PROCEDURE_RVA = 0xA688B0
PROCEDURE_VA = IMAGE_BASE + PROCEDURE_RVA
PROCEDURE_SPAN_BYTES = 53
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_PROCESS_MEMORY = 1024 * 1024 * 1024
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


def _relative(path: Path) -> str:
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def _sha256(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            digest.update(block)
    return size, digest.hexdigest()


def _pin(path: Path, *, required: bool = True) -> dict[str, Any]:
    if not path.is_file():
        if required:
            raise FileNotFoundError(path)
        return {
            "path": _relative(path),
            "status": "missing",
            "exists": False,
            "size_bytes": None,
            "sha256": None,
        }
    size, digest = _sha256(path)
    return {
        "path": _relative(path),
        "status": "present",
        "exists": True,
        "size_bytes": size,
        "sha256": digest,
    }


def _json(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    size = path.stat().st_size
    if size > MAX_JSON_BYTES:
        raise ValueError(f"json_over_bound:{_relative(path)}:{size}")
    with path.open("rb") as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) != size:
        raise ValueError(f"file_changed_during_read:{_relative(path)}")
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError(f"json_over_bound:{_relative(path)}")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"json_object_required:{_relative(path)}")
    return value, {
        "path": _relative(path),
        "size_bytes": size,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"mapping_required:{label}")
    return value


def _check(checks: dict[str, bool], name: str, value: bool) -> None:
    checks[name] = bool(value)


def _receipt_checks(
    request: Mapping[str, Any],
    run: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> dict[str, bool]:
    checks: dict[str, bool] = {}
    subject = _mapping(evidence.get("subject"), "evidence.subject")
    digest = _mapping(subject.get("digest"), "evidence.subject.digest")
    target_sha = digest.get("sha256")
    _check(checks, "request_target_sha_matches", request.get("target_sha256") == target_sha)
    _check(checks, "run_target_sha_matches", run.get("target_sha256") == target_sha)
    _check(checks, "fixed_executable_sha", target_sha == FIXED_EXE_SHA256)
    # The completed REA subject envelope records the digest/format but omits
    # the byte count.  Keep the fixed-build size from the stage contract in
    # the index without pretending that this particular envelope proved it.
    _check(checks, "fixed_executable_size_consistent",
           subject.get("size") in (None, FIXED_EXE_SIZE))
    _check(checks, "fixed_native_pe", subject.get("format") == "pe"
           and subject.get("architecture") == "x86_64")
    _check(checks, "request_node", request.get("node") == "0xa688b0")
    _check(checks, "request_procedure", request.get("procedure") == "0x140a688b0")
    _check(checks, "run_node", run.get("node") == "0xa688b0")
    _check(checks, "run_procedure", run.get("procedure") == "0x140a688b0")
    _check(checks, "request_preset", request.get("preset") == EXPECTED_PRESET)
    _check(checks, "request_read_only", request.get("query_reanalysis") is False)
    _check(checks, "request_memory_limit", request.get("process_memory_limit_bytes")
           == MAX_PROCESS_MEMORY)
    _check(checks, "run_completed", run.get("status") == "completed"
           and run.get("reason") == "completed")
    _check(checks, "provider_exit_zero", run.get("provider_exit_code") == 0)
    _check(checks, "wrapper_exit_zero", run.get("wrapper_exit_code") == 0)
    _check(checks, "process_exit_zero", run.get("exit_code") == 0)
    cleanup = _mapping(run.get("cleanup"), "run.cleanup")
    _check(checks, "cleanup_closed", cleanup.get("status") == "complete"
           and cleanup.get("closed_process_receipt") is True)
    postread = _mapping(run.get("postread"), "run.postread")
    _check(checks, "postread_zero", postread.get("status") == "read"
           and postread.get("exit_code") == 0)
    _check(checks, "database_unchanged", run.get("database_unchanged") is True)

    processes = run.get("processes")
    process_ok = isinstance(processes, list) and bool(processes)
    if process_ok:
        for process in processes:
            row = _mapping(process, "run.process")
            peak = row.get("peak_committed_bytes")
            process_ok = process_ok and isinstance(peak, int) and not isinstance(peak, bool)
            process_ok = process_ok and peak < MAX_PROCESS_MEMORY
            process_ok = process_ok and row.get("still_running_same_process") is False
    _check(checks, "processes_closed_under_one_gib", process_ok)

    profile = _mapping(evidence.get("analysis_profile"), "evidence.analysis_profile")
    parameters = _mapping(profile.get("parameters"), "analysis_profile.parameters")
    _check(checks, "provider_ghidra", _mapping(profile.get("provider"), "profile.provider").get("id") == "ghidra")
    _check(checks, "read_only_import", parameters.get("import_mode")
           == "persistent-completed-project-read-only")
    _check(checks, "read_only_database", parameters.get("database_mutation") == "read-only-no-save")
    _check(checks, "profile_no_reanalysis", parameters.get("query_reanalysis") is False)
    _check(checks, "adapter_pin", parameters.get("local_adapter_sha256") == EXPECTED_ADAPTER_SHA256)
    _check(checks, "manifest_pin", parameters.get("completed_manifest_sha256") == EXPECTED_MANIFEST_SHA256)
    _check(checks, "database_pin", parameters.get("completed_database_sha256") == EXPECTED_DATABASE_SHA256)
    _check(checks, "evidence_observed", evidence.get("confidence") == "observed"
           and evidence.get("authority") == "shipped-artifact")
    return checks


def _static_shape(evidence: Mapping[str, Any]) -> dict[str, Any]:
    normalized = _mapping(evidence.get("normalized_result"), "evidence.normalized_result")
    procedure = _mapping(normalized.get("procedure"), "normalized.procedure")
    body = _mapping(procedure.get("body"), "normalized.procedure.body")
    ranges = body.get("ranges")
    if not isinstance(ranges, list) or len(ranges) != 1:
        raise ValueError("warlookup_expected_one_body_range")
    body_range = _mapping(ranges[0], "normalized.procedure.body.ranges[0]")
    start = body_range.get("start")
    end = body_range.get("end")
    if start != "0x140a688b0" or end != "0x140a688e4":
        raise ValueError(f"warlookup_body_range_mismatch:{start}:{end}")
    if body.get("total_bytes") != PROCEDURE_SPAN_BYTES or body.get("span_bytes") != PROCEDURE_SPAN_BYTES:
        raise ValueError("warlookup_body_size_mismatch")
    if body.get("non_contiguous") is not False or body.get("contains_entry") is not True:
        raise ValueError("warlookup_body_shape_mismatch")
    assembly = normalized.get("assembly")
    if not isinstance(assembly, list) or len(assembly) > 256:
        raise ValueError("warlookup_assembly_shape_mismatch")
    pseudo = normalized.get("pseudocode")
    if not isinstance(pseudo, str) or len(pseudo.encode("utf-8")) > 64 * 1024:
        raise ValueError("warlookup_pseudocode_shape_mismatch")
    return {
        "procedure_name": procedure.get("name"),
        "classification": procedure.get("classification"),
        "address": procedure.get("address"),
        "rva": hex(PROCEDURE_RVA),
        "body": {
            "start_va": "0x140a688b0",
            "end_va_inclusive": "0x140a688e4",
            "span_bytes": PROCEDURE_SPAN_BYTES,
            "non_contiguous": body.get("non_contiguous"),
            "contains_entry": body.get("contains_entry"),
        },
        "assembly": list(assembly),
        "assembly_count": len(assembly),
        "pseudocode": pseudo,
        "callers_count": len(normalized.get("callers", []))
        if isinstance(normalized.get("callers"), list) else None,
        "callees_count": len(normalized.get("callees", []))
        if isinstance(normalized.get("callees"), list) else None,
        "mechanical_observations": {
            "reads_receiver_qword_at_0x00_then_table_pointer_at_0x50": True,
            "reads_count_at_0x5c_and_scales_by_0x10": True,
            "compares_key_derived_from_param1_plus_0x10_high_dword": True,
            "returns_qword_at_matching_entry_plus_0x08_or_zero": True,
            "business_war_identity_proven": False,
            "runtime_reader_proven": False,
        },
    }


def _write_new(path: Path, value: Mapping[str, Any]) -> tuple[int, str]:
    if path.exists():
        raise FileExistsError(f"refusing_to_overwrite:{_relative(path)}")
    raw = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
    return len(raw), hashlib.sha256(raw).hexdigest()


def build() -> tuple[dict[str, Any], dict[str, Any]]:
    request, request_meta = _json(ROOT / REQUEST_REL)
    evidence, evidence_meta = _json(ROOT / EVIDENCE_REL)
    run, run_meta = _json(ROOT / RUN_REL)
    checks = _receipt_checks(request, run, evidence)
    static_shape = _static_shape(evidence)
    if not all(checks.values()):
        failed = [name for name, value in checks.items() if not value]
        raise ValueError(f"receipt_checks_failed:{failed}")

    pins = {
        "request": request_meta,
        "evidence": evidence_meta,
        "run": run_meta,
        "freeze_script": _pin(Path(__file__)),
    }
    ledger = _pin(ROOT / ROOT_LEDGER_REL, required=False)
    ledger_ready = ledger.get("exists") is True
    index: dict[str, Any] = {
        "schema": "information_battle_entry_static_research_index_v1",
        "status": "prepared_root_ledger_pending" if not ledger_ready else "prepared",
        "complete": False,
        "production_authorized": False,
        "generated_by": _relative(Path(__file__)),
        "target": {
            "game_version": "1.37.4",
            "executable_sha256": FIXED_EXE_SHA256,
            "executable_size_bytes": FIXED_EXE_SIZE,
            "image_base": hex(IMAGE_BASE),
        },
        "query": {
            "name": "country_relation_warlookup_candidate",
            "directory": QUERY_REL,
            "rva": hex(PROCEDURE_RVA),
            "va": hex(PROCEDURE_VA),
            "evidence_id": evidence.get("evidence_id"),
            "semantic_status": "static_53_byte_lookup_candidate_business_semantics_unresolved",
        },
        "receipts": {
            "checks": checks,
            "request": request_meta,
            "evidence": evidence_meta,
            "run": run_meta,
        },
        "static_shape": static_shape,
        "artifact_pins": pins,
        "root_ledger": {
            "path": ROOT_LEDGER_REL,
            "status": "present" if ledger_ready else "missing",
            "pin": ledger,
            "required_for": "semantic research freeze and any public business interpretation",
        },
        "limitations": [
            "This is a read-only REA receipt archive; no REA query was run by this script.",
            "The 53-byte function mechanically scans a table and returns a qword or zero; no war/battle identity or business field meaning is established.",
            "Static assembly/pseudocode is not runtime behavior, a live reader, or an InformationService source.",
            "A separate root ledger is required before this research can be marked complete.",
        ],
    }
    index_size, index_sha = _write_new(INDEX_PATH, index)
    source_audit: dict[str, Any] = {
        "schema": "information_battle_entry_static_source_audit_v1",
        "status": index["status"],
        "complete": False,
        "index": {
            "path": _relative(INDEX_PATH),
            "size_bytes": index_size,
            "sha256": index_sha,
        },
        "checks": checks,
        "query_artifacts": pins,
        "static_shape": {
            "rva": hex(PROCEDURE_RVA),
            "body_span_bytes": PROCEDURE_SPAN_BYTES,
            "assembly_count": static_shape["assembly_count"],
            "static_lookup_only": True,
        },
        "root_ledger": index["root_ledger"],
        "scope_boundary": {
            "static_evidence": True,
            "runtime_observed": False,
            "live_process_access": False,
            "rea_invoked": False,
            "business_semantics_verified": False,
        },
        "limitations": index["limitations"],
    }
    _write_new(SOURCE_AUDIT_PATH, source_audit)
    return index, source_audit


def verify_existing() -> int:
    for path in (INDEX_PATH, SOURCE_AUDIT_PATH):
        if not path.is_file():
            raise FileNotFoundError(path)
        size, digest = _sha256(path)
        print(json.dumps({"path": _relative(path), "size_bytes": size, "sha256": digest}))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-existing", action="store_true")
    args = parser.parse_args()
    if args.verify_existing:
        return verify_existing()
    index, audit = build()
    print(json.dumps({
        "status": index["status"],
        "index": _relative(INDEX_PATH),
        "source_audit": _relative(SOURCE_AUDIT_PATH),
        "index_sha256": _sha256(INDEX_PATH)[1],
        "source_audit_sha256": _sha256(SOURCE_AUDIT_PATH)[1],
        "complete": audit["complete"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
