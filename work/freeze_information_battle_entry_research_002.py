"""Freeze the verified static entry-contract revision 002.

This is an archival verifier only.  It consumes the root contract ledger, the
bounded PE metadata, already completed owned-memory unwind fixtures, and the
single completed A688B0 REA receipt.  It never invokes REA, opens the game,
attaches to a process, changes an installed binary, or treats a synthetic
fixture as a production hook.

Revision 001 is intentionally left untouched.  The two output files use
exclusive creation so an existing archive cannot be silently replaced.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work" / "runtime" / "information-battle-entry-20261025-001"
INDEX_PATH = STAGE / "research-index-002.json"
SOURCE_AUDIT_PATH = STAGE / "source-audit-002.json"

FIXED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
FIXED_EXE_SIZE = 38_463_016
IMAGE_BASE = 0x140000000
REA_RVA = 0xA688B0
REA_VA = IMAGE_BASE + REA_RVA
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_PROCESS_MEMORY = 1024 * 1024 * 1024
NEW_REA_SHELL = 61597
NEW_REA_ELAPSED_SECONDS = 37.09
NEW_REA_EVIDENCE_ID = (
    "ev_15a90cdd6f1fac2564cae44bf01ac0529c31e82f5b5c42460d43556094f47833"
)
LEDGER_REL = (
    "work/runtime/information-battle-entry-20261025-001/"
    "entry-contract-ledger-001.json"
)
LEDGER_SCRIPT_REL = "work/probe_information_battle_entry_contract.py"
REA_DIR_REL = (
    "work/runtime/information-battle-entry-20261025-001/"
    "rea-country-relation-war-001"
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


def _load_json(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
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


def _pin_matches(actual: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    return (
        actual.get("path") == expected.get("path")
        and actual.get("size_bytes") == expected.get("bytes", expected.get("size_bytes"))
        and actual.get("sha256") == expected.get("sha256")
    )


def _check_ledger(
    ledger: Mapping[str, Any],
    ledger_pin: Mapping[str, Any],
    current_header: Mapping[str, Any],
    current_ledger_script: Mapping[str, Any],
) -> dict[str, bool]:
    checks: dict[str, bool] = {}
    target = _mapping(ledger.get("target"), "ledger.target")
    scope = _mapping(ledger.get("scope"), "ledger.scope")
    _check(checks, "ledger_schema", ledger.get("schema") == "information_battle_entry_contract_v1")
    _check(checks, "ledger_status", ledger.get("status") == "static_contract_with_owned_process_checks")
    _check(checks, "ledger_target_version", target.get("version") == "1.37.4")
    _check(checks, "ledger_target_executable", target.get("exe_sha256") == FIXED_EXE_SHA256)
    _check(checks, "ledger_target_image_base", target.get("static_image_base") == hex(IMAGE_BASE))
    _check(checks, "ledger_scope_one_new_rea", scope.get("new_REA_queries") == 1)
    _check(checks, "ledger_scope_no_new_game_access", scope.get("new_game_access") is False)
    _check(checks, "ledger_scope_no_hook", scope.get("game_hook_installed") is False)
    _check(checks, "ledger_scope_no_dispatch", scope.get("business_dispatch") is False)
    _check(checks, "ledger_scope_not_complete", scope.get("overall_complete") is False)
    plan_ref = _mapping(ledger.get("plan_header"), "ledger.plan_header")
    script_ref = _mapping(ledger.get("script"), "ledger.script")
    _check(checks, "ledger_plan_pin_matches", _pin_matches(current_header, plan_ref))
    _check(checks, "ledger_script_pin_matches", _pin_matches(current_ledger_script, script_ref))
    _check(checks, "ledger_pin_present", ledger_pin.get("sha256") is not None)
    _check(checks, "ledger_evidence_id", NEW_REA_EVIDENCE_ID in json.dumps(ledger, sort_keys=True))
    return checks


def _check_rea_receipt(
    request: Mapping[str, Any],
    evidence: Mapping[str, Any],
    run: Mapping[str, Any],
) -> tuple[dict[str, bool], dict[str, Any]]:
    checks: dict[str, bool] = {}
    subject = _mapping(evidence.get("subject"), "evidence.subject")
    digest = _mapping(subject.get("digest"), "evidence.subject.digest")
    profile = _mapping(evidence.get("analysis_profile"), "evidence.analysis_profile")
    parameters = _mapping(profile.get("parameters"), "analysis_profile.parameters")
    cleanup = _mapping(run.get("cleanup"), "run.cleanup")
    postread = _mapping(run.get("postread"), "run.postread")
    _check(checks, "rea_request_target", request.get("target_sha256") == FIXED_EXE_SHA256)
    _check(checks, "rea_evidence_target", digest.get("sha256") == FIXED_EXE_SHA256)
    _check(checks, "rea_run_target", run.get("target_sha256") == FIXED_EXE_SHA256)
    _check(checks, "rea_request_node", request.get("node") == "0xa688b0")
    _check(checks, "rea_run_node", run.get("node") == "0xa688b0")
    _check(checks, "rea_request_procedure", request.get("procedure") == "0x140a688b0")
    _check(checks, "rea_run_procedure", run.get("procedure") == "0x140a688b0")
    _check(checks, "rea_read_only_request", request.get("query_reanalysis") is False)
    _check(checks, "rea_memory_limit", request.get("process_memory_limit_bytes") == MAX_PROCESS_MEMORY)
    _check(checks, "rea_completed", run.get("status") == "completed" and run.get("reason") == "completed")
    _check(checks, "rea_provider_zero", run.get("provider_exit_code") == 0)
    _check(checks, "rea_wrapper_zero", run.get("wrapper_exit_code") == 0)
    _check(checks, "rea_process_zero", run.get("exit_code") == 0)
    _check(checks, "rea_cleanup_closed", cleanup.get("status") == "complete" and cleanup.get("closed_process_receipt") is True)
    _check(checks, "rea_postread_clean", postread.get("status") == "read" and postread.get("exit_code") == 0)
    _check(checks, "rea_database_unchanged", run.get("database_unchanged") is True)
    _check(checks, "rea_evidence_id", evidence.get("evidence_id") == NEW_REA_EVIDENCE_ID)
    processes = run.get("processes")
    process_summary: list[dict[str, Any]] = []
    process_ok = isinstance(processes, list) and bool(processes)
    peak_max = 0
    if process_ok:
        for raw_process in processes:
            process = _mapping(raw_process, "run.process")
            peak = process.get("peak_committed_bytes")
            row_ok = isinstance(peak, int) and not isinstance(peak, bool) and peak < MAX_PROCESS_MEMORY
            row_ok = row_ok and process.get("still_running_same_process") is False
            process_ok = process_ok and row_ok
            if isinstance(peak, int) and not isinstance(peak, bool):
                peak_max = max(peak_max, peak)
            process_summary.append({
                "pid": process.get("pid"),
                "peak_committed_bytes": peak,
                "still_running_same_process": process.get("still_running_same_process"),
                "row_valid": row_ok,
            })
    _check(checks, "rea_processes_closed_under_one_gib", process_ok)
    _check(checks, "rea_provider_ghidra", _mapping(profile.get("provider"), "profile.provider").get("id") == "ghidra")
    _check(checks, "rea_read_only_import", parameters.get("import_mode") == "persistent-completed-project-read-only")
    _check(checks, "rea_read_only_database", parameters.get("database_mutation") == "read-only-no-save")
    _check(checks, "rea_profile_no_reanalysis", parameters.get("query_reanalysis") is False)
    receipt = {
        "shell_id": NEW_REA_SHELL,
        "shell_id_source": "root-provided terminal receipt; run.json does not embed shell ids",
        "evidence_id": evidence.get("evidence_id"),
        "elapsed_seconds_from_run": run.get("elapsed_seconds"),
        "elapsed_seconds_from_root_receipt": NEW_REA_ELAPSED_SECONDS,
        "provider_exit_code": run.get("provider_exit_code"),
        "wrapper_exit_code": run.get("wrapper_exit_code"),
        "process_exit_code": run.get("exit_code"),
        "processes": process_summary,
        "peak_committed_bytes_max": peak_max,
        "process_memory_limit_bytes": request.get("process_memory_limit_bytes"),
    }
    _check(checks, "rea_elapsed_matches_root_receipt", run.get("elapsed_seconds") == NEW_REA_ELAPSED_SECONDS)
    return checks, receipt


def _check_entry_reports(
    report_final: Mapping[str, Any],
    report_failed_1: Mapping[str, Any],
    report_failed_2: Mapping[str, Any],
    report_encoding_1: Mapping[str, Any],
    report_encoding_2: Mapping[str, Any],
    final_report_pin: Mapping[str, Any],
    old_report_1_pin: Mapping[str, Any],
    old_report_2_pin: Mapping[str, Any],
) -> dict[str, bool]:
    checks: dict[str, bool] = {}
    scope = _mapping(report_final.get("scope"), "report003.scope")
    revision = _mapping(report_final.get("revision"), "report003.revision")
    previous = _mapping(revision.get("previous_reports"), "report003.revision.previous_reports")
    _check(checks, "final_unwind_status_passed", report_final.get("status") == "passed")
    _check(checks, "final_unwind_scope_owned_only", scope.get("owned_virtualalloc_only") is True)
    _check(checks, "final_unwind_no_game_access", scope.get("game_access") is False)
    _check(checks, "final_unwind_no_remote_process", scope.get("remote_process_access") is False)
    _check(checks, "final_unwind_no_rea", scope.get("rea_access") is False)
    _check(checks, "final_unwind_no_relaxed_expectations", revision.get("expectations_relaxed") is False)
    _check(checks, "final_unwind_prev_report1_pin", _pin_matches(old_report_1_pin, _mapping(previous.get("report.json"), "previous.report")))
    _check(checks, "final_unwind_prev_report2_pin", _pin_matches(old_report_2_pin, _mapping(previous.get("report-002.json"), "previous.report-002")))
    _check(checks, "final_unwind_self_pin", final_report_pin.get("sha256") == final_report_pin.get("sha256"))
    _check(checks, "failed_unwind1_preserved", report_failed_1.get("status") == "failed")
    _check(checks, "failed_unwind2_preserved", report_failed_2.get("status") == "failed")
    _check(checks, "encoding_control1_failed", report_encoding_1.get("status") == "failed")
    _check(checks, "encoding_control2_passed", report_encoding_2.get("status") == "passed")
    observations = _mapping(report_final.get("observations"), "report003.observations")
    checks_text = observations.get("checks")
    _check(checks, "final_unwind_no_failed_checks", isinstance(checks_text, list) and not any(" FAIL" in str(v) for v in checks_text))
    experiment = _mapping(report_final.get("experiment"), "report003.experiment")
    legal = experiment.get("legal_unwind_pcs")
    _check(checks, "final_unwind_legal_points", isinstance(legal, list) and len(legal) == 12)
    diagnostic = experiment.get("diagnostic_only_pcs")
    _check(checks, "final_unwind_diagnostic_points", isinstance(diagnostic, list) and len(diagnostic) == 17)
    _check(checks, "final_report_pin_present", final_report_pin.get("sha256") is not None)
    return checks


def _check_pe_report(report: Mapping[str, Any], label: str) -> dict[str, bool]:
    checks: dict[str, bool] = {}
    scope = _mapping(report.get("scope"), f"{label}.scope")
    _check(checks, f"{label}_status", report.get("status") == "observed_static_pe_unwind_metadata")
    _check(checks, f"{label}_static", report.get("runtime_observed") is False and report.get("rea_invoked") is False)
    _check(checks, f"{label}_no_process", report.get("game_or_process_accessed") is False and scope.get("game_access") is False)
    return checks


def _pin_groups() -> dict[str, dict[str, dict[str, Any]]]:
    def group(items: list[str]) -> dict[str, dict[str, Any]]:
        return {_relative(ROOT / rel): _pin(ROOT / rel) for rel in items}

    return {
        "static_contract": group([
            LEDGER_REL,
            LEDGER_SCRIPT_REL,
            "work/native/information-battle-entry-plan.h",
        ]),
        "owned_process_fixture": group([
            "work/native/test-information-battle-entry-unwind-003.cpp",
            "work/test_information_battle_entry_unwind_003.py",
            "work/runtime/information-battle-entry-20261025-001/unwind-test-001/report-003.json",
            "work/runtime/information-battle-entry-20261025-001/unwind-test-001/test-information-battle-entry-unwind-003.exe",
        ]),
        "historical_failed_controls": group([
            "work/native/test-information-battle-entry-unwind.cpp",
            "work/test_information_battle_entry_unwind.py",
            "work/runtime/information-battle-entry-20261025-001/unwind-test-001/report.json",
            "work/runtime/information-battle-entry-20261025-001/unwind-test-001/report-002.json",
            "work/runtime/information-battle-entry-20261025-001/unwind-test-001/test-information-battle-entry-unwind-002.exe",
        ]),
        "encoding_controls": group([
            "work/native/test-information-battle-entry-jump-encoding.cpp",
            "work/test_information_battle_entry_jump_encoding.py",
            "work/runtime/information-battle-entry-20261025-001/unwind-jump-encoding-test-001/report.json",
            "work/runtime/information-battle-entry-20261025-001/unwind-jump-encoding-test-001/test-information-battle-entry-jump-encoding.exe",
            "work/native/test-information-battle-entry-jump-encoding-002.cpp",
            "work/test_information_battle_entry_jump_encoding_002.py",
            "work/runtime/information-battle-entry-20261025-001/unwind-jump-encoding-test-002/report.json",
            "work/runtime/information-battle-entry-20261025-001/unwind-jump-encoding-test-002/test-information-battle-entry-jump-encoding-002.exe",
        ]),
        "pe_metadata": group([
            "work/probe_information_battle_entry_unwind.py",
            "work/runtime/information-battle-entry-20261025-001/entry-unwind-pe-001.json",
            "work/runtime/information-battle-war-records-20261025-001/entry-unwind-pe-001.json",
        ]),
        "surveys": group([
            "work/survey_information_battle_entry_unwind.py",
            "work/survey_information_battle_entry_payload.py",
            "work/runtime/information-battle-entry-20261025-001/infrastructure-survey-001.json",
            "work/runtime/information-battle-entry-20261025-001/payload-source-survey-001.json",
        ]),
        "rea_a688b0_receipts": group([
            f"{REA_DIR_REL}/request.json",
            f"{REA_DIR_REL}/evidence.json",
            f"{REA_DIR_REL}/run.json",
            f"{REA_DIR_REL}/ghidra-tail.log",
            f"{REA_DIR_REL}/script-tail.log",
            f"{REA_DIR_REL}/stderr.log",
        ]),
        "ledger_referenced_static_artifacts": group([
            "work/runtime/information-battles-20261025-001/rea-battle-result-router-001/evidence.json",
            "work/runtime/information-battle-war-records-20261025-001/callback-entry-selected-001.json",
        ]),
        "previous_revision": group([
            "work/runtime/information-battle-entry-20261025-001/research-index-001.json",
            "work/runtime/information-battle-entry-20261025-001/source-audit-001.json",
        ]),
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
    ledger, ledger_meta = _load_json(ROOT / LEDGER_REL)
    current_header = _pin(ROOT / "work/native/information-battle-entry-plan.h")
    current_ledger_script = _pin(ROOT / LEDGER_SCRIPT_REL)
    checks = _check_ledger(ledger, ledger_meta, current_header, current_ledger_script)

    request, request_meta = _load_json(ROOT / f"{REA_DIR_REL}/request.json")
    evidence, evidence_meta = _load_json(ROOT / f"{REA_DIR_REL}/evidence.json")
    run, run_meta = _load_json(ROOT / f"{REA_DIR_REL}/run.json")
    rea_checks, rea_receipt = _check_rea_receipt(request, evidence, run)
    checks.update(rea_checks)

    final_report, final_report_meta = _load_json(ROOT / "work/runtime/information-battle-entry-20261025-001/unwind-test-001/report-003.json")
    failed_1, failed_1_meta = _load_json(ROOT / "work/runtime/information-battle-entry-20261025-001/unwind-test-001/report.json")
    failed_2, failed_2_meta = _load_json(ROOT / "work/runtime/information-battle-entry-20261025-001/unwind-test-001/report-002.json")
    encoding_1, encoding_1_meta = _load_json(ROOT / "work/runtime/information-battle-entry-20261025-001/unwind-jump-encoding-test-001/report.json")
    encoding_2, encoding_2_meta = _load_json(ROOT / "work/runtime/information-battle-entry-20261025-001/unwind-jump-encoding-test-002/report.json")
    checks.update(_check_entry_reports(final_report, failed_1, failed_2, encoding_1, encoding_2, final_report_meta, failed_1_meta, failed_2_meta))

    current_pe, current_pe_meta = _load_json(ROOT / "work/runtime/information-battle-entry-20261025-001/entry-unwind-pe-001.json")
    misplaced_pe, misplaced_pe_meta = _load_json(ROOT / "work/runtime/information-battle-war-records-20261025-001/entry-unwind-pe-001.json")
    checks.update(_check_pe_report(current_pe, "current_pe"))
    checks.update(_check_pe_report(misplaced_pe, "misplaced_pe"))

    previous_index, previous_index_meta = _load_json(ROOT / "work/runtime/information-battle-entry-20261025-001/research-index-001.json")
    previous_audit, previous_audit_meta = _load_json(ROOT / "work/runtime/information-battle-entry-20261025-001/source-audit-001.json")
    _check(checks, "previous_index_preserved_prepared", previous_index.get("status") == "prepared_root_ledger_pending")
    _check(checks, "previous_audit_preserved_prepared", previous_audit.get("status") == "prepared_root_ledger_pending")

    groups = _pin_groups()
    _check(checks, "all_required_artifacts_present", all(pin.get("exists") is True for group in groups.values() for pin in group.values()))
    if not all(checks.values()):
        failed = [name for name, value in checks.items() if not value]
        raise ValueError(f"freeze_checks_failed:{failed}")

    report003_scope = _mapping(final_report.get("scope"), "report003.scope")
    index: dict[str, Any] = {
        "schema": "information_battle_entry_static_research_index_v2",
        "revision": 2,
        "status": "static_research_frozen_runtime_unresolved",
        "complete": False,
        "production_authorized": False,
        "generated_by": _relative(Path(__file__)),
        "target": {
            "game_version": "1.37.4",
            "executable_sha256": FIXED_EXE_SHA256,
            "executable_size_bytes": FIXED_EXE_SIZE,
            "image_base": hex(IMAGE_BASE),
            "rva": hex(REA_RVA),
            "va": hex(REA_VA),
        },
        "revision_history": {
            "previous_index": previous_index_meta,
            "previous_source_audit": previous_audit_meta,
            "previous_status": "prepared_root_ledger_pending",
            "previous_outputs_unchanged": True,
        },
        "source_contract": {
            "description": "root-pinned static contract and plan header; does not install a hook or dispatch business work",
            "ledger": ledger_meta,
            "plan_header": current_header,
            "contract_script": current_ledger_script,
        },
        "owned_process_fixture": {
            "description": "synthetic VirtualAlloc/RtlAddFunctionTable/RtlVirtualUnwind test only",
            "report": final_report_meta,
            "scope": report003_scope,
            "status": final_report.get("status"),
            "production_patch": False,
            "game_process": False,
        },
        "static_rea": {
            "description": "single bounded A688B0 REA receipt; static table lookup semantics remain unresolved",
            "evidence_id": NEW_REA_EVIDENCE_ID,
            "rva": hex(REA_RVA),
            "va": hex(REA_VA),
            "body_span_bytes": 53,
            "receipt": rea_receipt,
            "checks": {name: value for name, value in rea_checks.items()},
            "semantic_status": "static_slot_lookup_not_public_war_identity",
        },
        "controls": {
            "failed_unwind_001": failed_1_meta,
            "failed_unwind_002": failed_2_meta,
            "encoding_comparison_001": encoding_1_meta,
            "encoding_comparison_002": encoding_2_meta,
            "failed_controls_preserved": True,
            "expectations_relaxed": False,
        },
        "pe_metadata": {
            "current": current_pe_meta,
            "misplaced_extra_artifact": {
                "path": misplaced_pe_meta["path"],
                "pin": misplaced_pe_meta,
                "meaning": "historical extra copy in the war-records stage; retained explicitly and not treated as absence",
            },
        },
        "artifacts": groups,
        "checks": checks,
        "runtime_and_scope_boundary": {
            "static_contract": True,
            "owned_process_fixture": True,
            "static_rea": True,
            "live_game_process_access": False,
            "new_game_access": False,
            "game_hook_installed": False,
            "business_dispatch": False,
            "information_service_integration": False,
            "B01_B04_complete": False,
            "production_authorized": False,
            "these_evidence_classes_are_not_interchangeable": True,
        },
        "limitations": [
            "The unwind fixture exercises an owned synthetic image, not the installed game or a published patch.",
            "The A688B0 result is a bounded static slot lookup; stable public war/battle identity and complete payload are unresolved.",
            "Natural entry ABI, thread/reentry, visibility, object lifetime, complete source coverage, and subscription delivery remain unverified.",
            "The historical failed controls and the old-stage PE copy are preserved as evidence and are not suppressed by the passing fixture.",
        ],
    }
    index_size, index_sha = _write_new(INDEX_PATH, index)
    audit: dict[str, Any] = {
        "schema": "information_battle_entry_static_source_audit_v2",
        "revision": 2,
        "status": index["status"],
        "complete": False,
        "generated_by": _relative(Path(__file__)),
        "index": {
            "path": _relative(INDEX_PATH),
            "size_bytes": index_size,
            "sha256": index_sha,
        },
        "source_pins": groups,
        "checks": checks,
        "receipt": {
            "A688B0": rea_receipt,
            "single_new_rea_query": True,
        },
        "scope_boundary": index["runtime_and_scope_boundary"],
        "previous_revision": {
            "index": previous_index_meta,
            "source_audit": previous_audit_meta,
            "unchanged": True,
        },
        "limitations": index["limitations"],
    }
    _write_new(SOURCE_AUDIT_PATH, audit)
    return index, audit


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
        "failed_checks": [name for name, value in audit["checks"].items() if not value],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
