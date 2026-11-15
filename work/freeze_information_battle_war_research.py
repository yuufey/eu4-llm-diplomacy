"""Prepare a bounded static index for the fixed-build war-record queries.

This is an archival verifier, not a query runner.  It consumes the selected
and recovery files made by ``extract_information_battle_war_evidence.py`` and
the already completed request/run receipts.  It refuses to call REA, start a
game, invoke native code, or label a static procedure as a runtime battle or
war reader.  The root retention ledger is deliberately a separate gate: when
it is absent the generated index is a prepared, incomplete research record,
not a frozen semantic result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work" / "runtime" / "information-battle-war-records-20261025-001"
IMAGE_BASE = 0x140000000
FIXED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
FIXED_EXE_SIZE = 38_463_016
EXPECTED_PRESET = "eu4-persistent-default-analysis-v1"
EXPECTED_ADAPTER_SHA256 = "93620e986ea9ea17f5b6a8e56a5077772af0090a8d0eb467019aea40d38a689d"
EXPECTED_MANIFEST_SHA256 = "de1c738fa2bc9027ceacadabb7828d9890f5f9ff57ec4cde60494968f927333a"
EXPECTED_DATABASE_SHA256 = "8eec1cad93cce37d2f958c100570550bc7212c5aa86b92b7cf03950f85a83161"
PROCESS_MEMORY_LIMIT = 1024 * 1024 * 1024
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
RETENTION_LEDGER_REL = "work/runtime/information-battle-war-records-20261025-001/war-result-retention-ledger-001.json"
EXISTING_READERS_REL = "work/runtime/information-battle-war-records-20261025-001/existing-war-readers-survey-001.json"
PASSIVE_HOOK_REL = "work/runtime/information-battle-war-records-20261025-001/passive-hook-infrastructure-001.json"
LIVE_PREFLIGHT_REL = "work/runtime/information-battle-war-records-20261025-001/live-preflight-001/report.json"
SAVE_CROSSCHECK_REL = "work/runtime/information-battle-war-records-20261025-001/save-crosscheck-001/report.json"

EXPECTED_CONTEXT_REPORTS: dict[str, dict[str, Any]] = {
    EXISTING_READERS_REL: {
        "bytes": 23933,
        "sha256": "1ac8f0e5e4d91e8dc94da9d5ec305b809ecea34f2178691d482d0e331cdc3526",
        "classification": "static_current_1374_source_survey",
    },
    PASSIVE_HOOK_REL: {
        "bytes": 28946,
        "sha256": "92e4ca9d12a0d113df9340da1a8d7163d6878ce875f6c0698b1ecba5516fd1fb",
        "classification": "static_source_only_hook_survey",
    },
    LIVE_PREFLIGHT_REL: {
        "bytes": 8066,
        "sha256": "7c4da5888aee980ebaa9326928721ad230982648e228e44eaab4c7858f1e4c15",
        "classification": "read_only_live_identity_and_pause_preflight",
    },
    SAVE_CROSSCHECK_REL: {
        "bytes": 13331,
        "sha256": "eea091933913e1edb8b77d5dfa3b7fe02bd1dc802097d78aa51ae54e8244f9af",
        "classification": "recorded_save_static_crosscheck",
    },
}

QUERY_SPECS: tuple[dict[str, Any], ...] = (
    {
        "name": "war_result_retain",
        "directory": "rea-war-result-retain-001",
        "rva": 0xD89A80,
        "evidence_id": "ev_09d14e848427a1ccc47ef38639261998f557fe988622a6cb44417f70ddc370be",
        "semantic_boundary": "static result retention/record construction candidate; semantic war ownership is unresolved",
    },
    {
        "name": "war_result_binding",
        "directory": "rea-result-war-binding-001",
        "rva": 0x1DD3C0,
        "evidence_id": "ev_e0a32ef721d9d9338289ffa18d0c634ad990e51926fd895320ba0e2fbb3351d3",
        "semantic_boundary": "static compute/result candidate at result84/FC; query name does not prove binding",
    },
    {
        "name": "war_history_append",
        "directory": "rea-war-history-append-001",
        "rva": 0xD8FF10,
        "evidence_id": "ev_56f6735890a8a3ee8919a5e7b25dc031f87ee1afb5242c0a9d7b39359b1fa6e0",
        "semantic_boundary": "static history/append candidate; persistence ownership and runtime trigger are unresolved",
    },
    {
        "name": "war_history_date_set",
        "directory": "rea-history-date-set-001",
        "rva": 0x7E7FB0,
        "evidence_id": "ev_76e2c137910b7b747b329b716db096cd32ce69b78eb895add4d2fb8540f941e2",
        "semantic_boundary": "static date-field propagation candidate; date ownership and battle meaning are unresolved",
    },
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _load_object(path: Path) -> tuple[dict[str, Any], int, str]:
    path = path.resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    size = path.stat().st_size
    if size > MAX_JSON_BYTES:
        raise ValueError(f"json_over_bound:{_relative(path)}:{size}>{MAX_JSON_BYTES}")
    raw = path.read_bytes()
    if len(raw) != size:
        raise ValueError(f"file_changed_during_read:{_relative(path)}")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"json_object_required:{_relative(path)}")
    return value, size, hashlib.sha256(raw).hexdigest()


def _write_new(path: Path, value: Mapping[str, Any]) -> tuple[int, str]:
    if path.exists():
        raise FileExistsError(f"refusing_to_overwrite:{path}")
    raw = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(raw) > MAX_OUTPUT_BYTES:
        raise ValueError(f"output_over_bound:{_relative(path)}:{len(raw)}>{MAX_OUTPUT_BYTES}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return len(raw), hashlib.sha256(raw).hexdigest()


def _source_pin(path: Path, *, size: int | None = None, sha256: str | None = None) -> dict[str, Any]:
    actual_size = path.stat().st_size
    actual_sha = _sha256(path)
    return {
        "path": _relative(path),
        "size_bytes": actual_size,
        "sha256": actual_sha,
        "size_matches_expected": size is None or actual_size == size,
        "sha256_matches_expected": sha256 is None or actual_sha == sha256,
    }


def _pin_expected(
    relative_path: str,
    *,
    expected_size: int | None = None,
    expected_sha256: str | None = None,
    classification: str | None = None,
) -> dict[str, Any]:
    """Stream a source pin and retain a typed missing/mismatch result."""

    path = ROOT / relative_path
    result: dict[str, Any] = {
        "path": relative_path,
        "classification": classification,
        "expected_size_bytes": expected_size,
        "expected_sha256": expected_sha256,
    }
    if not path.is_file():
        result.update(
            {
                "status": "missing",
                "exists": False,
                "size_bytes": None,
                "sha256": None,
                "size_matches_expected": False if expected_size is not None else None,
                "sha256_matches_expected": False if expected_sha256 is not None else None,
            }
        )
        return result
    actual_size = path.stat().st_size
    actual_sha = _sha256(path)
    size_ok = expected_size is None or actual_size == expected_size
    sha_ok = expected_sha256 is None or actual_sha == expected_sha256
    result.update(
        {
            "status": "passed" if size_ok and sha_ok else "mismatch",
            "exists": True,
            "size_bytes": actual_size,
            "sha256": actual_sha,
            "size_matches_expected": size_ok,
            "sha256_matches_expected": sha_ok,
        }
    )
    return result


def _canonical_sha(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _receipt_audit(run: Mapping[str, Any], provider_runtime: Mapping[str, Any]) -> dict[str, Any]:
    processes = run.get("processes")
    process_rows: list[dict[str, Any]] = []
    if isinstance(processes, list):
        for row in processes:
            if not isinstance(row, Mapping):
                process_rows.append({"valid": False})
                continue
            peak = row.get("peak_committed_bytes")
            process_rows.append(
                {
                    "pid": row.get("pid"),
                    "peak_committed_bytes": peak,
                    "below_1gb": isinstance(peak, int) and not isinstance(peak, bool) and peak < PROCESS_MEMORY_LIMIT,
                    "closed": row.get("still_running_same_process") is False,
                }
            )
    checks = {
        "run_status_completed": run.get("status") == "completed",
        "run_reason_completed": run.get("reason") == "completed",
        "provider_exit_code_zero": run.get("provider_exit_code") == 0,
        "wrapper_exit_code_zero": run.get("wrapper_exit_code") == 0,
        "process_exit_code_zero": run.get("exit_code") == 0,
        "supervisor_completed": run.get("supervisor_reason") == "completed",
        "cleanup_complete": isinstance(run.get("cleanup"), Mapping)
        and run["cleanup"].get("status") == "complete"
        and run["cleanup"].get("closed_process_receipt") is True,
        "postread_read_zero": isinstance(run.get("postread"), Mapping)
        and run["postread"].get("status") == "read"
        and run["postread"].get("exit_code") == 0,
        "database_unchanged": run.get("database_unchanged") is True,
        "provider_runtime_passed": provider_runtime.get("status") == "passed",
        "all_processes_closed_under_1gb": bool(process_rows)
        and all(row.get("below_1gb") and row.get("closed") for row in process_rows),
    }
    return {
        "status": "passed" if all(checks.values()) else "mismatch",
        "checks": checks,
        "provider_exit_code": run.get("provider_exit_code"),
        "wrapper_exit_code": run.get("wrapper_exit_code"),
        "process_exit_code": run.get("exit_code"),
        "processes": process_rows,
        "provider_peak_committed_bytes": provider_runtime.get("provider_peak_committed_bytes"),
        "cleanup": run.get("cleanup"),
        "postread": run.get("postread"),
    }


def _related_source_inventory() -> dict[str, Any]:
    """Verify the retention ledger and its bounded static/live context pins."""

    ledger_path = ROOT / RETENTION_LEDGER_REL
    ledger, ledger_size, ledger_sha = _load_object(ledger_path)
    checks: dict[str, bool] = {
        "ledger_schema": ledger.get("schema") == "information_battle_war_retention_ledger_v1",
        "ledger_target_build": ledger.get("target", {}).get("build") == "1.37.4"
        and ledger.get("target", {}).get("executable_sha256") == FIXED_EXE_SHA256
        and ledger.get("target", {}).get("static_image_base") == hex(IMAGE_BASE),
    }
    sources = ledger.get("sources")
    if not isinstance(sources, Mapping):
        raise ValueError("retention_ledger_sources_missing")

    query_key_to_name = {
        "retain": "war_result_retain",
        "score": "war_result_binding",
        "append": "war_history_append",
        "date": "war_history_date_set",
    }
    ledger_query_pins: dict[str, Any] = {}
    for key, name in query_key_to_name.items():
        row = sources.get(key)
        if not isinstance(row, Mapping) or not isinstance(row.get("selected"), Mapping):
            raise ValueError(f"retention_ledger_selected_missing:{key}")
        selected = row["selected"]
        pin = _pin_expected(
            str(selected["path"]),
            expected_size=selected.get("bytes"),
            expected_sha256=selected.get("sha256"),
            classification="static_selected_readback",
        )
        ledger_query_pins[name] = {
            "ledger_key": key,
            "rva": row.get("rva"),
            "evidence_id": row.get("evidence_id"),
            "selected": pin,
            "raw_normalized_comparison": row.get("raw_normalized_comparison"),
            "Ghidra_body_inclusive": row.get("Ghidra_body_inclusive"),
        }
        checks[f"ledger_selected_{key}"] = pin.get("status") == "passed"

    legacy_raw_pins: dict[str, Any] = {}
    for key, label, classification in (
        ("callback", "battle_result_effects", "legacy_static_rea_raw_effects"),
        ("router", "battle_result_router", "legacy_static_rea_raw_router"),
    ):
        row = sources.get(key)
        if not isinstance(row, Mapping) or not isinstance(row.get("raw"), Mapping):
            raise ValueError(f"retention_ledger_raw_missing:{key}")
        raw = row["raw"]
        raw_pin = _pin_expected(
            str(raw["path"]),
            expected_size=raw.get("bytes"),
            expected_sha256=raw.get("sha256"),
            classification=classification,
        )
        raw_path = ROOT / str(raw["path"])
        query_dir = raw_path.parent
        request_path = query_dir / "request.json"
        run_path = query_dir / "run.json"
        run_value: dict[str, Any] | None = None
        if run_path.is_file():
            run_value, _, _ = _load_object(run_path)
        legacy_raw_pins[label] = {
            "rva": row.get("rva"),
            "evidence_id": row.get("evidence_id"),
            "raw": raw_pin,
            "request": _pin_expected(_relative(request_path), classification="legacy_query_request"),
            "run": _pin_expected(_relative(run_path), classification="legacy_query_receipt"),
            "run_shape": {
                "reason": run_value.get("reason") if run_value else None,
                "process_exit_code": run_value.get("exit_code") if run_value else None,
                "provider_exit_code": run_value.get("provider_exit_code") if run_value else None,
                "wrapper_exit_code": run_value.get("wrapper_exit_code") if run_value else None,
                "database_unchanged": run_value.get("database_unchanged") if run_value else None,
                "separate_provider_wrapper_fields_available": bool(
                    run_value and "provider_exit_code" in run_value and "wrapper_exit_code" in run_value
                ),
            },
            "semantic_boundary": "static legacy evidence only; raw receipt schema does not establish a runtime reader",
        }
        checks[f"legacy_{key}_raw_pin"] = raw_pin.get("status") == "passed"

    callback = sources.get("callback")
    callback_selected_pin = None
    if isinstance(callback, Mapping) and isinstance(callback.get("selected"), Mapping):
        selected = callback["selected"]
        callback_selected_pin = _pin_expected(
            str(selected["path"]),
            expected_size=selected.get("bytes"),
            expected_sha256=selected.get("sha256"),
            classification="static_bounded_callback_readback",
        )
    checks["callback_selected_pin"] = isinstance(callback_selected_pin, Mapping) and callback_selected_pin.get("status") == "passed"

    ordinary_pe = ledger.get("ordinary_PE")
    ordinary_pe_checks = {
        "object_present": isinstance(ordinary_pe, Mapping),
        "evidence_kind_static": isinstance(ordinary_pe, Mapping)
        and ordinary_pe.get("evidence_kind") == "ordinary_PE_bytes_not_REA_or_runtime",
        "executable_sha_fixed": isinstance(ordinary_pe, Mapping)
        and ordinary_pe.get("executable", {}).get("sha256") == FIXED_EXE_SHA256,
        "executable_size_fixed": isinstance(ordinary_pe, Mapping)
        and ordinary_pe.get("executable", {}).get("bytes") == FIXED_EXE_SIZE,
        "windows_present": isinstance(ordinary_pe, Mapping)
        and isinstance(ordinary_pe.get("windows"), list)
        and len(ordinary_pe["windows"]) >= 3,
    }
    checks["ordinary_pe_windows"] = all(ordinary_pe_checks.values())

    ledger_script = ledger.get("script")
    if not isinstance(ledger_script, Mapping):
        raise ValueError("retention_ledger_script_missing")
    retention_script_pin = _pin_expected(
        str(ledger_script["path"]),
        expected_size=ledger_script.get("bytes"),
        expected_sha256=ledger_script.get("sha256"),
        classification="static_retention_ledger_generator",
    )
    helper_pins: list[dict[str, Any]] = []
    for helper in ledger.get("helpers", []):
        if not isinstance(helper, Mapping):
            helper_pins.append({"status": "invalid"})
            continue
        helper_pins.append(
            _pin_expected(
                str(helper["path"]),
                expected_size=helper.get("bytes"),
                expected_sha256=helper.get("sha256"),
                classification="static_research_helper",
            )
        )
    checks["retention_script_pin"] = retention_script_pin.get("status") == "passed"
    checks["retention_helpers_pins"] = bool(helper_pins) and all(pin.get("status") == "passed" for pin in helper_pins)

    context_reports: dict[str, Any] = {}
    for rel, expected in EXPECTED_CONTEXT_REPORTS.items():
        pin = _pin_expected(
            rel,
            expected_size=expected["bytes"],
            expected_sha256=expected["sha256"],
            classification=expected["classification"],
        )
        context_reports[rel] = {"pin": pin}
        if pin.get("status") != "passed":
            checks[f"context_report_{Path(rel).name}"] = False

    readers_path = ROOT / EXISTING_READERS_REL
    readers, _, _ = _load_object(readers_path)
    reader_source_pins: list[dict[str, Any]] = []
    for source in readers.get("sources", []):
        if not isinstance(source, Mapping):
            reader_source_pins.append({"status": "invalid"})
            continue
        reader_source_pins.append(
            _pin_expected(
                str(source["path"]),
                expected_size=source.get("bytes"),
                expected_sha256=source.get("sha256"),
                classification=str(source.get("kind", "survey_source")),
            )
        )
    checks["existing_readers_source_pins"] = bool(reader_source_pins) and all(
        pin.get("status") == "passed" for pin in reader_source_pins
    )
    checks["existing_readers_report_pin"] = context_reports[EXISTING_READERS_REL]["pin"].get("status") == "passed"

    passive_path = ROOT / PASSIVE_HOOK_REL
    passive, _, _ = _load_object(passive_path)
    passive_generator = passive.get("generator") if isinstance(passive.get("generator"), Mapping) else {}
    passive_generator_pin = _pin_expected(
        str(passive_generator.get("path", "")),
        expected_size=passive_generator.get("bytes"),
        expected_sha256=passive_generator.get("sha256"),
        classification="static_passive_hook_survey_generator",
    )
    passive_source_pins: list[dict[str, Any]] = []
    for source in passive.get("source_pins", []):
        if not isinstance(source, Mapping):
            passive_source_pins.append({"status": "invalid"})
            continue
        passive_source_pins.append(
            _pin_expected(
                str(source["path"]),
                expected_size=source.get("bytes"),
                expected_sha256=source.get("sha256"),
                classification=str(source.get("role", "passive_hook_source")),
            )
        )
    checks["passive_report_pin"] = context_reports[PASSIVE_HOOK_REL]["pin"].get("status") == "passed"
    checks["passive_generator_pin"] = passive_generator_pin.get("status") == "passed"
    checks["passive_source_pins"] = bool(passive_source_pins) and all(
        pin.get("status") == "passed" for pin in passive_source_pins
    )

    live_path = ROOT / LIVE_PREFLIGHT_REL
    live_report, _, _ = _load_object(live_path)
    live_scope = live_report.get("scope", {})
    live_checks = live_report.get("checks", {})
    live_separation_checks = {
        "status_read_only_preflight": live_report.get("status") == "passed_read_only_preflight",
        "report_checks_passed": live_report.get("all_checks_passed") is True,
        "read_only": live_scope.get("read_only") is True,
        "no_native_game_calls": live_scope.get("native_game_calls") is False,
        "no_dispatch": live_scope.get("dispatch_or_requests") is False,
        "no_save_or_date_advance": live_scope.get("save_or_date_advance") is False,
        "fresh_checks_nonempty": bool(live_checks),
    }
    checks["live_preflight_pin"] = context_reports[LIVE_PREFLIGHT_REL]["pin"].get("status") == "passed"
    checks["live_preflight_separated"] = all(live_separation_checks.values())

    save_path = ROOT / SAVE_CROSSCHECK_REL
    save_report, _, _ = _load_object(save_path)
    save_separation_checks = {
        "recorded_status": str(save_report.get("status", "")).startswith("passed_static_save_crosscheck"),
        "read_only": save_report.get("read_only") is True,
        "no_native_query": save_report.get("native_query_called") is False,
        "no_rea": save_report.get("rea_called") is False,
        "no_game_access": save_report.get("game_access") is False,
    }
    checks["save_crosscheck_pin"] = context_reports[SAVE_CROSSCHECK_REL]["pin"].get("status") == "passed"
    checks["save_crosscheck_separated"] = all(save_separation_checks.values())

    ledger_pin = {
        "path": RETENTION_LEDGER_REL,
        "size_bytes": ledger_size,
        "sha256": ledger_sha,
        "status": "passed",
    }
    return {
        "status": "passed" if all(checks.values()) else "mismatch",
        "checks": checks,
        "retention_ledger": {
            "pin": ledger_pin,
            "schema": ledger.get("schema"),
            "target": ledger.get("target"),
            "script": retention_script_pin,
            "helpers": helper_pins,
            "claims_count": len(ledger.get("claims", [])) if isinstance(ledger.get("claims"), list) else None,
            "scope": ledger.get("scope"),
        },
        "ledger_query_pins": ledger_query_pins,
        "legacy_static_rea": legacy_raw_pins,
        "callback_selected": callback_selected_pin,
        "ordinary_pe_windows": {
            "value": ordinary_pe,
            "canonical_sha256": _canonical_sha(ordinary_pe),
            "checks": ordinary_pe_checks,
            "classification": "ordinary_fixed_pe_bytes_static_only",
        },
        "context_reports": context_reports,
        "existing_readers": {
            "report": context_reports[EXISTING_READERS_REL]["pin"],
            "schema": readers.get("schema"),
            "status": readers.get("status"),
            "generator": {"status": "not_pinned_in_report", "path": None},
            "source_pins": reader_source_pins,
            "source_checks": {"all_passed": checks["existing_readers_source_pins"]},
        },
        "passive_hook": {
            "report": context_reports[PASSIVE_HOOK_REL]["pin"],
            "schema": passive.get("schema"),
            "status": passive.get("status"),
            "generator": passive_generator_pin,
            "source_pins": passive_source_pins,
            "source_checks": {"all_passed": checks["passive_source_pins"]},
        },
        "live_preflight": {
            "report": context_reports[LIVE_PREFLIGHT_REL]["pin"],
            "schema": live_report.get("schema"),
            "status": live_report.get("status"),
            "classification": "read_only_live_identity_and_pause_preflight; not battle payload evidence",
            "scope": live_scope,
            "checks": live_checks,
            "separation_checks": live_separation_checks,
        },
        "save_crosscheck": {
            "report": context_reports[SAVE_CROSSCHECK_REL]["pin"],
            "schema": save_report.get("schema"),
            "status": save_report.get("status"),
            "classification": "recorded_save_static_crosscheck; not live/native identity",
            "separation_checks": save_separation_checks,
        },
        "static_live_boundary": {
            "static_rea_and_source_surveys": True,
            "read_only_live_preflight_is_not_battle_capture": True,
            "recorded_save_is_not_live_native": True,
            "runtime_battle_reader_established": False,
        },
    }


def _query_record(spec: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    directory = STAGE / str(spec["directory"])
    selected_path = directory / "selected-evidence-001.json"
    recovery_path = directory / "readback-recovery-001.json"
    evidence_path = directory / "evidence.json"
    request_path = directory / "request.json"
    run_path = directory / "run.json"
    selected, selected_size, selected_sha = _load_object(selected_path)
    recovery, recovery_size, recovery_sha = _load_object(recovery_path)
    request, request_size, request_sha = _load_object(request_path)
    run, run_size, run_sha = _load_object(run_path)
    evidence_size = evidence_path.stat().st_size
    evidence_sha = _sha256(evidence_path)
    runtime = selected.get("provider_runtime")
    if not isinstance(runtime, Mapping):
        raise ValueError(f"provider_runtime_missing:{_relative(selected_path)}")
    identity = selected.get("identity_audit")
    if not isinstance(identity, Mapping):
        raise ValueError(f"identity_audit_missing:{_relative(selected_path)}")
    query = selected.get("query")
    if not isinstance(query, Mapping):
        raise ValueError(f"query_metadata_missing:{_relative(selected_path)}")
    comparison = selected.get("normalized_comparison")
    if not isinstance(comparison, Mapping):
        raise ValueError(f"normalized_comparison_missing:{_relative(selected_path)}")
    checks = {
        "selected_status_observed": selected.get("status") == "observed",
        "recovery_status_observed": recovery.get("status") == "observed",
        "selected_source_matches_evidence": selected.get("source", {}).get("sha256") == evidence_sha,
        "recovery_source_matches_evidence": recovery.get("evidence", {}).get("sha256") == evidence_sha,
        "selected_recovery_source_equal": selected.get("source", {}).get("sha256") == recovery.get("evidence", {}).get("sha256"),
        "evidence_id_matches_spec": identity.get("evidence_id") == spec["evidence_id"],
        "identity_status_passed": identity.get("status") == "passed",
        "request_guard_passed": selected.get("request", {}).get("all_fixed_checks_pass") is True,
        "all_selected_values_equal": all(item.get("status") == "equal" for item in comparison.values()),
        "profile_guard_observed": selected.get("profile_audit", {}).get("status") == "observed",
        "cache_guard_passed": selected.get("cache_audit", {}).get("status") == "passed",
        "provider_exit_code_zero": runtime.get("provider_exit_code") == 0,
        "wrapper_exit_code_zero": runtime.get("wrapper_exit_code") == 0,
        "provider_runtime_passed": runtime.get("status") == "passed",
        "target_build_fixed": query.get("target_sha256") == FIXED_EXE_SHA256 and query.get("fixed_build") == "1.37.4",
        "rva_matches_spec": query.get("authorised_rva") == hex(int(spec["rva"])),
        "procedure_matches_spec": query.get("authorised_procedure") == hex(IMAGE_BASE + int(spec["rva"])),
    }
    receipt = _receipt_audit(run, runtime)
    checks["run_receipt_passed"] = receipt.get("status") == "passed"
    procedure = (
        selected.get("normalized_result", {}).get("procedure", {}).get("value")
        if isinstance(selected.get("normalized_result"), Mapping)
        else None
    )
    procedure_summary: dict[str, Any] = {}
    if isinstance(procedure, Mapping):
        procedure_summary = {
            "address": procedure.get("address"),
            "name": procedure.get("name"),
            "signature": procedure.get("signature"),
            "body": procedure.get("body"),
            "classification": procedure.get("classification"),
        }
    query_index = {
        "schema": "information_battle_war_query_index_v1",
        "name": spec["name"],
        "status": "passed_static_query_audit" if all(checks.values()) else "mismatch",
        "read_only": True,
        "runtime_observed": False,
        "native_function_invoked": False,
        "game_access": False,
        "dispatch_authorized": False,
        "target_build": {
            "game_version": "1.37.4",
            "executable_sha256": FIXED_EXE_SHA256,
            "executable_size_expected": FIXED_EXE_SIZE,
            "image_base": hex(IMAGE_BASE),
            "rva": hex(int(spec["rva"])),
            "va": hex(IMAGE_BASE + int(spec["rva"])),
            "address_convention": "REA body ranges are inclusive; entry RVA/VA are separate",
        },
        "semantic_boundary": spec["semantic_boundary"],
        "procedure": procedure_summary,
        "provider_receipt": {
            "provider": "Ghidra",
            "provider_version": selected.get("top_level", {}).get("provider", {}).get("value", {}).get("version"),
            "provider_exit_code": runtime.get("provider_exit_code"),
            "wrapper_exit_code": runtime.get("wrapper_exit_code"),
            "status": runtime.get("status"),
            "peak_committed_bytes": runtime.get("provider_peak_committed_bytes"),
            "receipt_audit": receipt,
        },
        "source_pins": {
            "evidence": _source_pin(evidence_path, size=evidence_size, sha256=evidence_sha),
            "request": _source_pin(request_path, size=request_size, sha256=request_sha),
            "run": _source_pin(run_path, size=run_size, sha256=run_sha),
            "selected": _source_pin(selected_path, size=selected_size, sha256=selected_sha),
            "recovery": _source_pin(recovery_path, size=recovery_size, sha256=recovery_sha),
        },
        "request": {
            "path": _relative(request_path),
            "sha256": request_sha,
            "target_sha256": request.get("target_sha256"),
            "node": request.get("node"),
            "procedure": request.get("procedure"),
            "preset": request.get("preset"),
            "adapter_sha256": request.get("adapter_sha256"),
            "completed_manifest_sha256": request.get("completed_manifest_sha256"),
            "completed_database_sha256": request.get("completed_database_sha256"),
            "query_reanalysis": request.get("query_reanalysis"),
            "java_heap": request.get("java_heap"),
            "process_memory_limit_bytes": request.get("process_memory_limit_bytes"),
        },
        "evidence": {
            "evidence_id": identity.get("evidence_id"),
            "path": _relative(evidence_path),
            "size_bytes": evidence_size,
            "sha256": evidence_sha,
            "selected_status": selected.get("status"),
            "raw_normalized_selected_comparison": comparison,
        },
        "selected": {
            "path": _relative(selected_path),
            "size_bytes": selected_size,
            "sha256": selected_sha,
            "status": selected.get("status"),
        },
        "recovery": {
            "path": _relative(recovery_path),
            "size_bytes": recovery_size,
            "sha256": recovery_sha,
            "status": recovery.get("status"),
            "method": recovery.get("parser_boundary", {}).get("method"),
        },
        "checks": checks,
        "limitations": [
            "This is bounded static REA readback from a completed fixed-build dossier; it is not a runtime reader or battle event capture.",
            "Procedure names, result offsets, callers, and date writes do not by themselves establish war identity, ownership, trigger, or complete payload semantics.",
            "The root retention ledger and any runtime validation remain separate gates.",
        ],
    }
    query_audit = {
        "schema": "information_battle_war_query_audit_v1",
        "name": spec["name"],
        "status": query_index["status"],
        "checks": checks,
        "all_static_checks_pass": all(checks.values()),
        "provider_wrapper": {
            "provider_exit_code": runtime.get("provider_exit_code"),
            "wrapper_exit_code": runtime.get("wrapper_exit_code"),
            "provider_peak_committed_bytes": runtime.get("provider_peak_committed_bytes"),
            "run_status": runtime.get("run_status"),
            "run_reason": runtime.get("run_reason"),
        },
        "source_pins": query_index["source_pins"],
        "semantic_boundary": spec["semantic_boundary"],
        "no_runtime_claim": True,
    }
    return query_index, query_audit


def _run(revision: str) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    audits: list[dict[str, Any]] = []
    record_directories: list[str] = []
    for spec in QUERY_SPECS:
        index, audit = _query_record(spec)
        records.append(index)
        audits.append(audit)
        record_directories.append(str(spec["directory"]))
    related = _related_source_inventory()
    script_pin = _source_pin(Path(__file__))
    all_queries_passed = all(item.get("status") == "passed_static_query_audit" for item in records)
    context_passed = related.get("status") == "passed"
    context_summary = {
        "retention_ledger": related.get("retention_ledger", {}).get("pin"),
        "callback_selected": related.get("callback_selected"),
        "legacy_static_rea": {
            name: value.get("raw") for name, value in related.get("legacy_static_rea", {}).items()
        },
        "ordinary_pe_windows": {
            "canonical_sha256": related.get("ordinary_pe_windows", {}).get("canonical_sha256"),
            "classification": related.get("ordinary_pe_windows", {}).get("classification"),
        },
        "existing_readers_report": related.get("existing_readers", {}).get("report"),
        "passive_hook_report": related.get("passive_hook", {}).get("report"),
        "live_preflight_report": related.get("live_preflight", {}).get("report"),
        "static_live_boundary": related.get("static_live_boundary"),
    }
    for item, audit in zip(records, audits):
        item["revision"] = revision
        item["archive_context"] = context_summary
        item["limitations"] = [
            "This query is a bounded static fixed-build readback; it is not a runtime reader or battle event capture.",
            "The retention ledger and related source surveys pin the static observations but do not establish a natural hook, object lifetime, observer visibility, or complete payload.",
            "The live preflight is read-only identity/date/pause metadata and is kept separate from static REA evidence.",
        ]
        audit["revision"] = revision
        audit["archive_context"] = context_summary
        audit["no_runtime_claim"] = True
        # The query files are written below from the stable parallel list; no
        # existing revision is overwritten.
    for item, audit, directory in zip(records, audits, record_directories):
        query_dir = STAGE / directory
        _write_new(query_dir / f"query-index-{revision}.json", item)
        _write_new(query_dir / f"query-audit-{revision}.json", audit)
    checks = {
        "four_queries_present": len(records) == 4,
        "all_query_audits_passed": all(item.get("all_static_checks_pass") is True for item in audits),
        "fixed_build": all(item.get("target_build", {}).get("executable_sha256") == FIXED_EXE_SHA256 for item in records),
        "provider_wrapper_receipts_zero": all(
            item.get("provider_receipt", {}).get("provider_exit_code") == 0
            and item.get("provider_receipt", {}).get("wrapper_exit_code") == 0
            for item in records
        ),
        "selected_and_recovery_pinned": all(
            item.get("selected", {}).get("sha256") and item.get("recovery", {}).get("sha256") for item in records
        ),
        "retention_context_pins_passed": context_passed,
    }
    status = "static_research_frozen_runtime_unresolved" if all_queries_passed and context_passed else "static_research_incomplete"
    index = {
        "schema": "information_battle_war_records_research_index_v1",
        "revision": revision,
        "status": status,
        "read_only": True,
        "runtime_observed": False,
        "native_function_invoked": False,
        "game_access": False,
        "dispatch_authorized": False,
        "goal_complete": False,
        "target_build": {
            "game_version": "1.37.4",
            "executable_sha256": FIXED_EXE_SHA256,
            "executable_size": FIXED_EXE_SIZE,
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
        "script": {
            "path": _relative(Path(__file__)),
            "size_bytes": script_pin["size_bytes"],
            "sha256": script_pin["sha256"],
        },
        "extractor": {
            "path": _relative(ROOT / "work" / "extract_information_battle_war_evidence.py"),
            "size_bytes": (ROOT / "work" / "extract_information_battle_war_evidence.py").stat().st_size,
            "sha256": _sha256(ROOT / "work" / "extract_information_battle_war_evidence.py"),
            "method": "mmap_bounded_json_span_scan",
            "max_selected_value_bytes": 2 * 1024 * 1024,
            "whole_document_json_loaded": False,
        },
        "queries": records,
        "checks": checks,
        "retention_context": related,
        "root_retention_ledger": related["retention_ledger"],
        "live_preflight": related["live_preflight"],
        "static_live_boundary": related["static_live_boundary"],
        "limitations": [
            "All four records are bounded static observations from fixed 1.37.4 evidence; none establishes a runtime reader, hook, or complete battle/war payload.",
            "The result/binding/history/date labels are mechanical query labels and bounded interpretations, not proven business semantics.",
            "The retention ledger, callback readback, legacy effects/router raw, ordinary PE windows, existing-reader survey, and passive-hook survey are pinned as static evidence.",
            "The fresh live preflight is only read-only process identity/date/pause metadata; it is not battle payload or hook acceptance.",
            "No REA query, game access, RPM, native function invocation, or dispatch was performed by this archival script.",
        ],
    }
    audit = {
        "schema": "information_battle_war_records_source_audit_v1",
        "revision": revision,
        "status": status,
        "all_static_checks_pass": all(checks.values()),
        "checks": checks,
        "query_count": len(records),
        "query_statuses": {item["name"]: item["status"] for item in records},
        "provider_wrapper_exit_codes": {
            item["name"]: {
                "provider_exit_code": item.get("provider_receipt", {}).get("provider_exit_code"),
                "wrapper_exit_code": item.get("provider_receipt", {}).get("wrapper_exit_code"),
            }
            for item in records
        },
        "root_retention_ledger": index["root_retention_ledger"],
        "retention_context": related,
        "live_preflight": related["live_preflight"],
        "static_live_boundary": related["static_live_boundary"],
        "script": index["script"],
        "extractor": index["extractor"],
        "source_pins": {
            item["name"]: item["source_pins"] for item in records
        },
        "no_runtime_claim": True,
    }
    _write_new(STAGE / f"research-index-{revision}.json", index)
    _write_new(STAGE / f"source-audit-{revision}.json", audit)
    return {
        "status": status,
        "checks": checks,
        "index": _relative(STAGE / f"research-index-{revision}.json"),
        "audit": _relative(STAGE / f"source-audit-{revision}.json"),
        "queries": [
            {
                "name": item["name"],
                "query_index": _relative(STAGE / directory / f"query-index-{revision}.json")
                if (STAGE / directory / f"query-index-{revision}.json").exists()
                else None,
                "status": item["status"],
            }
            for item, directory in zip(records, record_directories)
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", default="001", help="new output suffix; existing outputs are never overwritten")
    args = parser.parse_args(argv)
    result = _run(str(args.revision))
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"war-record static freeze failed closed: {exc}", file=sys.stderr)
        raise SystemExit(1)
