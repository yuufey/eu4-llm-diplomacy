"""Bounded source/component audit for the final battle-war memory reader.

This audit consumes already-recorded offline/live reports.  It hashes only
workspace files at or below the bounded input size, never opens a game
process, invokes REA/RPM, runs tests, or changes an existing report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
STAGE = ROOT / "work/runtime/information-battle-war-records-20261025-001"
MAX_FILE_BYTES = 16 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024

READER = "work/information_battle_war_memory.py"
READER_SHA = "fcfe22512bc719c766b7b26da3e56c4155fd5ff2f32c80efb26d2108af8f02ae"
READER_BYTES = 80317
TEST = "work/tests/test_information_battle_war_memory.py"
TEST_SHA = "d5518c232c7bf36575b0654e9be500e602c3e88a44aff346a9692a5f5bdf7fc3"
TEST_BYTES = 27737

REPORT_003 = "work/runtime/information-battle-war-records-20261025-001/memory-reader-test-001/report-003.json"
REPORT_003_SHA = "d21ddda81bd6f32c30f6e5590ba3210efc66ceb85d71ed0ce6e67516e1d7f79d"
REPORT_003_BYTES = 3286

BUR_REPORT = "work/runtime/information-battle-war-records-20261025-001/live-fra-bur-002/report.json"
BUR_SHA = "8e6cd850b7112cc5f52ea4ee5dd445e54fa45ca03a7626275a137dfb1b8d286f"
BUR_BYTES = 1404833
ENG_REPORT = "work/runtime/information-battle-war-records-20261025-001/live-fra-eng-001/report.json"
ENG_SHA = "a887658589e613896405b885d057a2d430d99c7eec6cbbad3ee6dd6239e57bbe"
ENG_BYTES = 1012803

HISTORY_CONTRACT = "work/runtime/information-battle-war-records-20261025-001/history-root-contract-001.json"
HISTORY_CONTRACT_SHA = "0513f377569a2c2c990e08ba5d782c0f02d7a1b228e35ba394f9ca85229eb9df"
HISTORY_CONTRACT_BYTES = 4245

INDEX_002 = "work/runtime/information-battle-war-records-20261025-001/research-index-002.json"
INDEX_002_SHA = "314119494c596a195f6f07ec2feb8378c686504819d436d65dd18997ac1cdc63"
INDEX_002_BYTES = 104326
SOURCE_AUDIT_002 = "work/runtime/information-battle-war-records-20261025-001/source-audit-002.json"
SOURCE_AUDIT_002_SHA = "8c55718f9bb99bae6135a4d2de7ef95ca8166c5e336a038a1f8d3eeff553f661"
SOURCE_AUDIT_002_BYTES = 57239
LEDGER_001 = "work/runtime/information-battle-war-records-20261025-001/war-result-retention-ledger-001.json"
LEDGER_001_SHA = "a04abb14cf1100b27f99cd0ed7c00d879303381fa341dff92ffd7289f821379c"
LEDGER_001_BYTES = 27275
FREEZE_SCRIPT = "work/freeze_information_battle_war_research.py"
FREEZE_SCRIPT_SHA = "43f95c6d492a7e3605a081c6eed577d4fd35b504c069263dcf478770f4af9371"

PRESERVATION = "work/runtime/information-battle-war-records-20261025-001/production-preservation-001.json"
PRESERVATION_SHA = "6c9b697781721ce2cd1008baae987bfdc5156cefa1238ae04641eb3042740ccc"
PRESERVATION_BYTES = 107781

EXE_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
DLL_SHA = "d80ef39d66d263788c0af4df0892b4ff781e5e3b3f9aea7ebe33759327e457db"
SESSION = "42328-1dd6450312dc2fb"
CREATION_FILETIME = 134373859476226811
GAME_DATE = 56553384
BUR_RESULT_DATE = 56552232


def resolve_workspace(relative: str | Path, *, allow_large: bool = False) -> Path:
    path = (ROOT / Path(relative)).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"path outside workspace: {relative}") from exc
    if not path.is_file():
        raise FileNotFoundError(path)
    size = path.stat().st_size
    if not allow_large and size > MAX_FILE_BYTES:
        raise ValueError(f"file exceeds bounded audit size: {path} ({size})")
    return path


def stream_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(CHUNK_BYTES)
            if not block:
                return digest.hexdigest()
            digest.update(block)


def pin(relative: str | Path) -> dict[str, Any]:
    path = resolve_workspace(relative)
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "exists": True,
        "bytes": path.stat().st_size,
        "sha256": stream_sha256(path),
    }


def compare_pin(relative: str | Path, expected_sha: str, expected_bytes: int | None = None) -> dict[str, Any]:
    actual = pin(relative)
    bytes_match = expected_bytes is None or actual["bytes"] == expected_bytes
    matched = actual["sha256"] == expected_sha and bytes_match
    return {
        "path": actual["path"],
        "expected": {"bytes": expected_bytes, "sha256": expected_sha},
        "actual": actual,
        "status": "match" if matched else "mismatch",
    }


def compare_record(record: dict[str, Any]) -> dict[str, Any]:
    path = record.get("path")
    if not isinstance(path, str):
        raise ValueError(f"record has no path: {record!r}")
    expected_sha = record.get("expected_sha256") or record.get("sha256")
    if not isinstance(expected_sha, str):
        raise ValueError(f"record has no sha256: {record!r}")
    expected_bytes = record.get("expected_size_bytes")
    if expected_bytes is None:
        expected_bytes = record.get("size_bytes", record.get("bytes"))
    return compare_pin(path, expected_sha, expected_bytes)


def read_json(relative: str | Path) -> tuple[Path, dict[str, Any]]:
    path = resolve_workspace(relative)
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return path, value


def ok(checks: dict[str, bool]) -> bool:
    return all(checks.values())


def artifact_summary(relative: str, expected_sha: str, expected_bytes: int) -> dict[str, Any]:
    check = compare_pin(relative, expected_sha, expected_bytes)
    return {"check": check, "matched": check["status"] == "match"}


def _identity_summary(value: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "installation_pid",
        "installation_session_id",
        "installation_creation_filetime",
        "process_creation_filetime",
        "process_creation_utc",
        "process_path_sha256",
        "process_path_sha256_matches_expected",
        "module_path_matches_process",
        "process_creation_matches_installation",
    )
    return {key: value.get(key) for key in keys}


def _dll_summary(value: dict[str, Any]) -> dict[str, Any]:
    matching = value.get("matching_modules")
    module = matching[0] if isinstance(matching, list) and len(matching) == 1 and isinstance(matching[0], dict) else {}
    return {
        "expected_name": value.get("expected_name"),
        "expected_sha256": value.get("expected_sha256"),
        "expected_path": value.get("expected_path"),
        "matching_module_count": len(matching) if isinstance(matching, list) else None,
        "matching_module": {
            "name_matches_expected": module.get("name_matches_expected"),
            "path_matches_expected": module.get("path_matches_expected"),
            "sha256": module.get("sha256"),
            "sha256_matches_expected": module.get("sha256_matches_expected"),
        },
    }


def audit_live_report(relative: str, expected_sha: str, expected_bytes: int, recipient: str, expected_wars: int, expected_results: int, *, bur: bool) -> dict[str, Any]:
    report_pin = compare_pin(relative, expected_sha, expected_bytes)
    _, report = read_json(relative)
    target = report.get("target_build") or {}
    identity = report.get("identity") or {}
    before_identity = report.get("identity_before") or {}
    after_identity = report.get("identity_after") or {}
    before = report.get("before") or {}
    after = report.get("after") or {}
    before_control = before.get("control") or {}
    after_control = after.get("control") or {}
    access = report.get("access") or {}
    doublepass = report.get("doublepass") or {}
    cleanup = report.get("cleanup") or {}
    handle_close = cleanup.get("handle_close") or {}
    dll = report.get("dll_installation") or {}
    dll_before = dll.get("before") or {}
    dll_after = dll.get("after") or {}

    identity_fields = (
        "installation_pid",
        "installation_session_id",
        "installation_creation_filetime",
        "process_creation_filetime",
        "process_creation_utc",
        "process_path_sha256",
    )
    identity_stable = all(
        identity.get(key) == before_identity.get(key) == after_identity.get(key)
        for key in identity_fields
    )
    date_before = (before.get("game_date") or {}).get("raw")
    date_after = (after.get("game_date") or {}).get("raw")
    paused_before = (before_control.get("paused") or {}).get("value")
    paused_after = (after_control.get("paused") or {}).get("value")
    speed_before = (before_control.get("speed") or {}).get("value")
    speed_after = (after_control.get("speed") or {}).get("value")

    common_checks = {
        "report_pin": report_pin["status"] == "match",
        "status_observed": report.get("status") == "observed",
        "evidence_runtime_observation": report.get("evidence_kind") == "pure_runtime_observation_not_static_evidence",
        "reader_probe_name": report.get("probe") == "information-battle-war-memory",
        "reader_probe_sha": report.get("probe_script_sha256") == READER_SHA,
        "probe_script_workspace_name": str(report.get("probe_script", "")).replace("\\", "/").endswith(READER),
        "read_only": report.get("read_only") is True,
        "native_function_not_invoked": report.get("native_function_invoked") is False,
        "no_semantic_completion_claim": report.get("complete") is False and report.get("battle_complete") is False,
        "retained_subset": report.get("retained_subset_only") is True,
        "all_battles_not_claimed": report.get("all_battles_captured") is False,
        "public_war_id_not_claimed": report.get("public_war_id_available") is False,
        "visibility_not_claimed": report.get("visibility") is False,
        "build_version": target.get("version") == "1.37.4",
        "build_exe_pin": target.get("expected_exe_sha256") == EXE_SHA,
        "build_dll_pin": target.get("expected_dll_sha256") == DLL_SHA,
        "identity_binding": identity.get("binding_verified") is True,
        "identity_expected_creation": identity.get("installation_creation_filetime") == CREATION_FILETIME,
        "identity_expected_session": identity.get("installation_session_id") == SESSION,
        "identity_expected_exe": identity.get("process_path_sha256") == EXE_SHA,
        "identity_stable_before_after": identity_stable,
        "identity_before_matches_installation": before_identity.get("process_creation_matches_installation") is True,
        "identity_after_matches_installation": after_identity.get("process_creation_matches_installation") is True,
        "dll_before_pin": _dll_summary(dll_before)["expected_sha256"] == DLL_SHA and _dll_summary(dll_before)["matching_module"]["sha256_matches_expected"] is True,
        "dll_after_pin": _dll_summary(dll_after)["expected_sha256"] == DLL_SHA and _dll_summary(dll_after)["matching_module"]["sha256_matches_expected"] is True,
        "dll_before_after_same": _dll_summary(dll_before) == _dll_summary(dll_after),
        "date_double_read_equal": date_before == date_after == GAME_DATE,
        "pause_double_read": paused_before is True and paused_after is True and speed_before == speed_after == 0,
        "doublepass_performed": doublepass.get("performed") is True,
        "doublepass_consistent": doublepass.get("consistent") is True and doublepass.get("all_read_bytes_compared") is True and doublepass.get("mismatches") == [],
        "rpm_only_mask": access.get("open_process_mask") == "QUERY_INFORMATION|VM_READ" and access.get("open_process_mask_hex") == "0x410",
        "rpm_budget": isinstance(access.get("rpm_bytes_requested"), int) and access.get("rpm_bytes_requested") <= access.get("rpm_total_limit") <= 4194304,
        "rpm_single_read_bound": access.get("rpm_single_read_limit") == 65536,
        "no_writes": access.get("target_memory_writes") is False,
        "no_native_calls": access.get("native_game_calls") is False,
        "no_side_effects": all(access.get(key) is False for key in ("date_advance", "dll_injection", "private_heap_scan", "save_or_reload", "ui_control")),
        "handle_closed": handle_close.get("closed") is True and handle_close.get("success") is True and handle_close.get("status") == "closed",
        "recipient_observed": ((before.get("recipient_country") or {}).get("country_handle") or {}).get("tag") == recipient and ((after.get("recipient_country") or {}).get("country_handle") or {}).get("tag") == recipient,
        "war_count": len(report.get("wars") or []) == expected_wars,
        "result_count": len(report.get("results") or []) == expected_results,
        "results_not_truncated": report.get("results_truncated") is False,
    }

    wars = report.get("wars") or []
    results = report.get("results") or []
    history = (wars[0].get("history") or {}) if wars else {}
    result_dates: list[Any] = []
    for entry in results:
        result = entry.get("result") if isinstance(entry, dict) else None
        if isinstance(result, dict):
            timeline = result.get("timeline_date")
            if isinstance(timeline, dict):
                result_dates.append(timeline.get("raw"))
    if bur:
        common_checks.update(
            {
                "bur_result_date": result_dates == [BUR_RESULT_DATE],
                "bur_history_unknown": history.get("status") == "unknown" and len(history.get("unknown_conditions") or []) > 0,
                "bur_retained_observation_incomplete": report.get("retained_observation_complete") is False,
            }
        )
    else:
        common_checks.update(
            {
                "eng_no_results": result_dates == [],
                "eng_observation_recorded": report.get("retained_observation_complete") is True,
            }
        )

    return {
        "report_pin": report_pin,
        "checks": common_checks,
        "mismatch_count": sum(not value for value in common_checks.values()),
        "identity_before": _identity_summary(before_identity),
        "identity_after": _identity_summary(after_identity),
        "dll_before": _dll_summary(dll_before),
        "dll_after": _dll_summary(dll_after),
        "pause_and_date": {
            "before": {"paused": paused_before, "speed": speed_before, "game_date_raw": date_before},
            "after": {"paused": paused_after, "speed": speed_after, "game_date_raw": date_after},
            "equal": date_before == date_after and paused_before == paused_after,
        },
        "doublepass": {
            "performed": doublepass.get("performed"),
            "consistent": doublepass.get("consistent"),
            "all_read_bytes_compared": doublepass.get("all_read_bytes_compared"),
            "mismatches": doublepass.get("mismatches"),
        },
        "access": {
            "open_process_mask": access.get("open_process_mask"),
            "open_process_mask_hex": access.get("open_process_mask_hex"),
            "rpm_calls": access.get("rpm_calls"),
            "rpm_bytes_requested": access.get("rpm_bytes_requested"),
            "rpm_single_read_limit": access.get("rpm_single_read_limit"),
            "rpm_total_limit": access.get("rpm_total_limit"),
            "writes": access.get("target_memory_writes"),
            "native_calls": access.get("native_game_calls"),
        },
        "counts": {"wars": len(wars), "results": len(results), "result_dates": result_dates},
        "probe_script_sha256": report.get("probe_script_sha256"),
        "history": {
            "status": history.get("status") if bur else None,
            "unknown_condition_count": len(history.get("unknown_conditions") or []) if bur else None,
            "retained_observation_complete": report.get("retained_observation_complete"),
        },
        "classification": "read_only_live_rpm_observation; retained subset only; not complete battle capture",
    }


def audit_report_003() -> dict[str, Any]:
    report_pin = compare_pin(REPORT_003, REPORT_003_SHA, REPORT_003_BYTES)
    _, report = read_json(REPORT_003)
    sources = report.get("source_files") or []
    source_checks = [compare_record(item) for item in sources if isinstance(item, dict)]
    pytest_verification = next((item for item in report.get("verification", []) if "pytest" in str(item.get("command", ""))), {})
    checks = {
        "report_pin": report_pin["status"] == "match",
        "status_passed": report.get("status") == "passed",
        "report_version": report.get("report_version") == 3,
        "offline_scope": report.get("scope") == "offline_fake_kernel_only",
        "source_count": len(sources) == 2,
        "source_pins_match": all(item.get("status") == "match" for item in source_checks),
        "recorded_18_pass": pytest_verification.get("status") == "passed" and pytest_verification.get("passed") == 18 and pytest_verification.get("failed") == 0 and pytest_verification.get("errors") == 0,
        "safety_no_live": report.get("safety", {}).get("game_access") is False and report.get("safety", {}).get("rpm_live") is False and report.get("safety", {}).get("native_function_invoked") is False and report.get("safety", {}).get("writes") is False,
        "completion_not_claimed": "complete=false" in " ".join(report.get("limitations", [])) and report.get("safety", {}).get("full_tests") is False,
    }
    return {
        "report_pin": report_pin,
        "checks": checks,
        "mismatch_count": sum(not value for value in checks.values()),
        "source_checks": source_checks,
        "recorded_verification": report.get("verification"),
        "scope": report.get("scope"),
        "limitations": report.get("limitations"),
    }


def audit_history_contract() -> dict[str, Any]:
    contract_pin = compare_pin(HISTORY_CONTRACT, HISTORY_CONTRACT_SHA, HISTORY_CONTRACT_BYTES)
    _, contract = read_json(HISTORY_CONTRACT)
    saved = contract.get("saved_runtime_observation", {}).get("report") or {}
    script = contract.get("script") or {}
    helper = contract.get("PE_helper") or {}
    ledger = contract.get("retention_ledger") or {}
    checks = [
        compare_record(saved),
        compare_record(script),
        compare_record(helper),
        compare_record(ledger),
    ]
    scope = contract.get("scope") or {}
    semantic_checks = {
        "contract_pin": contract_pin["status"] == "match",
        "schema": contract.get("schema") == "information_battle_history_root_contract_v1",
        "fixed_build": contract.get("target", {}).get("build") == "1.37.4" and contract.get("target", {}).get("exe_sha256") == EXE_SHA,
        "script_helper_pins": all(item.get("status") == "match" for item in checks[1:3]),
        "saved_observation_pin": checks[0].get("status") == "match",
        "ledger_pin": checks[3].get("status") == "match" and ledger.get("sha256") == LEDGER_001_SHA,
        "no_runtime_side_effects": all(scope.get(key) is False for key in ("new_game_access", "new_REA_query", "native_call", "hook_installed", "overall_complete")),
        "root_semantics_preserved": contract.get("reader_contract", {}).get("critical_distinction", "").startswith("Root90 returns true"),
    }
    return {
        "contract_pin": contract_pin,
        "checks": semantic_checks,
        "mismatch_count": sum(not value for value in semantic_checks.values()),
        "source_checks": checks,
        "scope": scope,
        "root_vtable_rva": contract.get("reader_contract", {}).get("root_vtable_rva"),
        "root_slot_targets": contract.get("reader_contract", {}).get("root_slot_targets"),
        "critical_distinction": contract.get("reader_contract", {}).get("critical_distinction"),
    }


def audit_static_freeze() -> dict[str, Any]:
    index_pin = compare_pin(INDEX_002, INDEX_002_SHA, INDEX_002_BYTES)
    source_pin = compare_pin(SOURCE_AUDIT_002, SOURCE_AUDIT_002_SHA, SOURCE_AUDIT_002_BYTES)
    ledger_pin = compare_pin(LEDGER_001, LEDGER_001_SHA, LEDGER_001_BYTES)
    freeze_pin = compare_pin(FREEZE_SCRIPT, FREEZE_SCRIPT_SHA)
    _, index = read_json(INDEX_002)
    _, source = read_json(SOURCE_AUDIT_002)
    _, ledger = read_json(LEDGER_001)
    static_boundary = index.get("static_live_boundary") or source.get("static_live_boundary") or {}
    checks = {
        "index_pin": index_pin["status"] == "match",
        "source_audit_pin": source_pin["status"] == "match",
        "ledger_pin": ledger_pin["status"] == "match",
        "freeze_script_pin": freeze_pin["status"] == "match",
        "index_static_status": index.get("status") == "static_research_frozen_runtime_unresolved" and index.get("goal_complete") is False,
        "index_no_runtime_claim": index.get("runtime_observed") is False and index.get("native_function_invoked") is False and index.get("game_access") is False,
        "source_static_status": source.get("status") == "static_research_frozen_runtime_unresolved" and source.get("all_static_checks_pass") is True and source.get("no_runtime_claim") is True,
        "four_queries_static_pass": source.get("query_count") == 4 and all(value == "passed_static_query_audit" for value in (source.get("query_statuses") or {}).values()),
        "boundary_kept": static_boundary.get("runtime_battle_reader_established") is False and static_boundary.get("read_only_live_preflight_is_not_battle_capture") is True,
        "ledger_scope_unresolved": ledger.get("scope", {}).get("overall_complete") is False and ledger.get("scope", {}).get("battle_complete") is False and ledger.get("scope", {}).get("native_function_invoked") is False,
    }
    return {
        "checks": checks,
        "mismatch_count": sum(not value for value in checks.values()),
        "pins": {"research_index_002": index_pin, "source_audit_002": source_pin, "retention_ledger_001": ledger_pin, "freeze_script": freeze_pin},
        "status": index.get("status"),
        "static_live_boundary": static_boundary,
        "ledger_scope": ledger.get("scope"),
    }


def audit_production_preservation() -> dict[str, Any]:
    preservation_pin = compare_pin(PRESERVATION, PRESERVATION_SHA, PRESERVATION_BYTES)
    _, report = read_json(PRESERVATION)
    overall = report.get("overall") or {}
    groups = report.get("groups") or {}
    group_summary = {
        name: {key: value.get(key) for key in ("count", "match_count", "mismatch_count", "missing_count", "budget_exceeded_count") if key in value}
        for name, value in groups.items()
        if isinstance(value, dict)
    }
    checks = {
        "report_pin": preservation_pin["status"] == "match",
        "status_passed": report.get("status") == "passed_read_only_source_audit",
        "127_matches": overall.get("count") == 127 and overall.get("match_count") == 127,
        "no_mismatch_missing_budget": overall.get("mismatch_count") == 0 and overall.get("missing_count") == 0 and overall.get("budget_exceeded_count") == 0,
        "scope_read_only": report.get("scope", {}).get("game_or_process_accessed") is False and report.get("scope", {}).get("rea_or_rpm_accessed") is False and report.get("scope", {}).get("tests_run") is False,
        "scope_preserved": report.get("scope", {}).get("production_modified") is False and report.get("scope", {}).get("old_reports_modified") is False,
        "goal_not_claimed": report.get("conclusion", {}).get("goal_complete") is False,
    }
    return {
        "report_pin": preservation_pin,
        "checks": checks,
        "mismatch_count": sum(not value for value in checks.values()),
        "overall": overall,
        "groups": group_summary,
        "audit_script": report.get("audit_script"),
        "interpretation": "127-pin result is reused as a recorded preservation audit; this component audit does not repeat its per-file scan.",
    }


def component_report() -> dict[str, Any]:
    report_003 = audit_report_003()
    bur = audit_live_report(BUR_REPORT, BUR_SHA, BUR_BYTES, "BUR", 1, 1, bur=True)
    eng = audit_live_report(ENG_REPORT, ENG_SHA, ENG_BYTES, "ENG", 0, 0, bur=False)
    history = audit_history_contract()
    static_freeze = audit_static_freeze()
    preservation = audit_production_preservation()
    source_checks = [
        compare_pin(READER, READER_SHA, READER_BYTES),
        compare_pin(TEST, TEST_SHA, TEST_BYTES),
        report_003["report_pin"],
    ]
    all_mismatch = (
        sum(item.get("status") != "match" for item in source_checks)
        + report_003["mismatch_count"]
        + bur["mismatch_count"]
        + eng["mismatch_count"]
        + history["mismatch_count"]
        + static_freeze["mismatch_count"]
        + preservation["mismatch_count"]
    )
    # Include the audit script itself after it exists, but do not mutate prior reports.
    audit_script_pin = pin("work/audit_information_battle_war_components.py")
    status = "passed_component_source_audit" if all_mismatch == 0 else "failed_component_source_audit"
    return {
        "schema": "information_battle_war_records/component_source_audit_v1",
        "status": status,
        "scope": {
            "stage": STAGE.relative_to(ROOT).as_posix(),
            "purpose": "独立核对最终memory reader、18项离线验证、两份有界read-only RPM报告及历史/静态来源边界。",
            "hashing": "Python按1MiB块流式SHA-256；JSON输入先做16MiB有界检查；不读取大PE/raw，不运行测试、REA、RPM或游戏。",
            "tests_run": False,
            "game_or_process_accessed": False,
            "rea_or_rpm_accessed": False,
            "production_modified": False,
            "old_reports_modified": False,
        },
        "audit_script": audit_script_pin,
        "source_pins": {
            "reader": source_checks[0],
            "test": source_checks[1],
            "memory_reader_report_003": source_checks[2],
            "live_probe_sha_consistency": {
                "expected_reader_sha256": READER_SHA,
                "bur_report_recorded_probe_sha256": bur.get("probe_script_sha256"),
                "eng_report_recorded_probe_sha256": eng.get("probe_script_sha256"),
                "match": bur["checks"].get("reader_probe_sha") is True and eng["checks"].get("reader_probe_sha") is True,
            },
        },
        "offline_report_003": report_003,
        "live_reports": {
            "live_fra_bur_002": bur,
            "live_fra_eng_001": eng,
        },
        "history_root_contract": history,
        "current_static_freeze": static_freeze,
        "production_preservation_127": preservation,
        "classification": {
            "static_research": "preserved separately in research-index-002/source-audit-002/retention-ledger-001",
            "live_observation": "read-only RPM retained-subset observations; before/after identity, pause/date, close and raw-budget checks passed",
            "battle_capture_complete": False,
            "retained_observation_complete_bur": False,
            "unknown_history_preserved_bur": True,
            "goal_complete": False,
        },
        "conclusion": {
            "source_components_match": all(item.get("status") == "match" for item in source_checks),
            "offline_18_pass_recorded": report_003["checks"].get("recorded_18_pass") is True,
            "bur_1_war_1_result_date_56552232": bur["mismatch_count"] == 0 and bur["counts"]["result_dates"] == [BUR_RESULT_DATE],
            "eng_0_war_0_result": eng["mismatch_count"] == 0 and eng["counts"]["wars"] == 0 and eng["counts"]["results"] == 0,
            "history_contract_source_pins_match": history["mismatch_count"] == 0,
            "static_live_boundary_preserved": static_freeze["mismatch_count"] == 0,
            "production_127_pins_reused_pass": preservation["mismatch_count"] == 0,
            "read_only_only": True,
            "complete_battle_claim": False,
            "goal_complete": False,
            "mismatch_count": all_mismatch,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=None)
    args = parser.parse_args()
    output = Path(args.output) if args.output else STAGE / "component-source-audit-001.json"
    output = (ROOT / output).resolve() if not output.is_absolute() else output.resolve()
    output.relative_to(ROOT)
    output.parent.mkdir(parents=True, exist_ok=True)
    report = component_report()
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": output.relative_to(ROOT).as_posix(), "status": report["status"], "bytes": output.stat().st_size}, ensure_ascii=False))
    return 0 if report["status"].startswith("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
