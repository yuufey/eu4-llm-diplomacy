"""Bounded static readback for the fixed-build war-record REA queries.

The queries in this stage have already run.  This script only reads their
saved request/evidence/run files.  It reuses the previous mmap JSON
SpanScanner, selects small result members, and never materializes a large
evidence document.  It does not query REA, start a game, invoke native code,
or treat a static function name as battle/war semantics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import sys
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from work.extract_information_battle_evidence import (  # noqa: E402
    FIXED_PRESET,
    FIXED_TARGET_SHA256,
    MAX_DEPTH,
    MAX_KEY_BYTES,
    MAX_SELECTED_VALUE_BYTES,
    _SpanScanner,
    _cache_audit,
    _decode_span,
    _file_identity,
    _find_member,
    _profile_audit,
    _sha256_file,
)
from work.extract_information_battle_layout_evidence import _run_audit  # noqa: E402


STAGE = ROOT / "work" / "runtime" / "information-battle-war-records-20261025-001"
IMAGE_BASE = 0x140000000
ALLOWED_RVAS = frozenset({0xD89A80, 0x1DD3C0, 0xD8FF10, 0x7E7FB0})
MAX_REQUEST_BYTES = 64 * 1024
MAX_RUN_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
PROCESS_MEMORY_LIMIT = 1024 * 1024 * 1024
SELECTED_NAMES = ("procedure", "pseudocode", "assembly", "callees")
TOP_NAMES = ("evidence_id", "subject", "provider", "analysis_profile", "parameters")

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


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _parse_rva(value: str) -> int:
    try:
        rva = int(value, 0)
    except ValueError as exc:
        raise ValueError(f"invalid_rva:{value}") from exc
    if rva not in ALLOWED_RVAS:
        raise ValueError(f"rva_not_authorized:{hex(rva)}")
    return rva


def _json_object(path: Path, *, max_bytes: int) -> tuple[dict[str, Any], int, str]:
    size = path.stat().st_size
    _require(size <= max_bytes, f"json_over_bound:{path}:{size}>{max_bytes}")
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    _require(len(raw) == size, f"file_changed_during_read:{path}")
    _require((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns), f"file_changed_during_read:{path}")
    value = json.loads(raw.decode("utf-8"))
    _require(isinstance(value, dict), f"json_object_required:{path}")
    return value, size, hashlib.sha256(raw).hexdigest()


def _empty_value(path: str, status: str = "missing") -> dict[str, Any]:
    return {"path": path, "status": status, "value": None, "limit_bytes": MAX_SELECTED_VALUE_BYTES}


def _span_values(scanner: _SpanScanner, view: mmap.mmap, start: int, end: int, prefix: str) -> tuple[dict[str, Any], str | None]:
    found, error = _find_member(scanner, start, end, set(SELECTED_NAMES))
    result: dict[str, Any] = {}
    for key in SELECTED_NAMES:
        span = found.get(key)
        if span is None:
            result[key] = _empty_value(f"{prefix}.{key}")
        else:
            result[key] = _decode_span(view, *span, path=f"{prefix}.{key}")
    return result, error


def _extract_selected(evidence: Path) -> dict[str, Any]:
    """Decode only bounded members from raw and normalized result objects."""

    identity_before = _file_identity(evidence)
    source_sha = _sha256_file(evidence)
    identity_after_hash = _file_identity(evidence)
    if identity_before != identity_after_hash:
        return {
            "status": "source_changed_during_hash",
            "source": {**identity_after_hash, "sha256": source_sha},
            "parser": {"integrity": "unknown_not_full_json_validated"},
        }

    top_results: dict[str, Any] = {}
    raw_values: dict[str, Any] = {}
    normalized_values: dict[str, Any] = {}
    parser_error: str | None = None
    raw_result_span: dict[str, int] | None = None
    normalized_result_span: dict[str, int] | None = None

    with evidence.open("rb") as stream:
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as view:
            scanner = _SpanScanner(view)
            top_spans, parser_error = _find_member(scanner, 0, len(view), {"evidence_id", "subject", "provider", "analysis_profile", "parameters", "raw_result", "normalized_result"})
            for key in TOP_NAMES:
                span = top_spans.get(key)
                top_results[key] = _empty_value(key) if span is None else _decode_span(view, *span, path=key)

            raw_span = top_spans.get("raw_result")
            if raw_span is None:
                raw_values = {key: _empty_value(f"raw_result.value.{key}") for key in SELECTED_NAMES}
            else:
                raw_members, raw_error = _find_member(scanner, *raw_span, {"value"})
                if raw_error and parser_error is None:
                    parser_error = f"raw_result:{raw_error}"
                value_span = raw_members.get("value")
                if value_span is None:
                    raw_values = {key: _empty_value(f"raw_result.value.{key}") for key in SELECTED_NAMES}
                else:
                    raw_result_span = {"start_byte": value_span[0], "end_byte_exclusive": value_span[1], "span_bytes": value_span[1] - value_span[0]}
                    raw_values, value_error = _span_values(scanner, view, *value_span, "raw_result.value")
                    if value_error and parser_error is None:
                        parser_error = f"raw_result.value:{value_error}"

            normalized_span = top_spans.get("normalized_result")
            if normalized_span is None:
                normalized_values = {key: _empty_value(f"normalized_result.{key}") for key in SELECTED_NAMES}
            else:
                normalized_result_span = {"start_byte": normalized_span[0], "end_byte_exclusive": normalized_span[1], "span_bytes": normalized_span[1] - normalized_span[0]}
                normalized_values, normalized_error = _span_values(scanner, view, *normalized_span, "normalized_result")
                if normalized_error and parser_error is None:
                    parser_error = f"normalized_result:{normalized_error}"
            identity_after = _file_identity(evidence)

    source_stable = identity_before == identity_after
    values = [*top_results.values(), *raw_values.values(), *normalized_values.values()]
    statuses = [value.get("status") for value in values]
    if not source_stable:
        status = "source_changed_during_parse"
    elif parser_error:
        status = "partial"
    elif all(value == "observed" for value in statuses):
        status = "observed"
    else:
        status = "partial"
    return {
        "status": status,
        "source": {**identity_before, "sha256": source_sha, "stable_before_after": source_stable},
        "parser": {
            "kind": "mmap_bounded_json_span_scan_reused_previous_battle_extractor",
            "integrity": "unknown_not_full_json_validated",
            "max_selected_value_bytes": MAX_SELECTED_VALUE_BYTES,
            "max_key_bytes": MAX_KEY_BYTES,
            "max_depth": MAX_DEPTH,
            "top_level_parse_error": parser_error,
            "raw_result_value_span": raw_result_span,
            "normalized_result_span": normalized_result_span,
            "selected_values_are_individually_decoded": True,
            "whole_document_json_loaded": False,
        },
        "top_level": top_results,
        "raw_result_value": raw_values,
        "normalized_result": normalized_values,
    }


def _request_audit(request_path: Path, request: Mapping[str, Any], rva: int) -> dict[str, Any]:
    expected = {
        "target_sha256": FIXED_TARGET_SHA256,
        "node": hex(rva),
        "procedure": hex(IMAGE_BASE + rva),
        "preset": FIXED_PRESET,
        "adapter_sha256": "93620e986ea9ea17f5b6a8e56a5077772af0090a8d0eb467019aea40d38a689d",
        "completed_manifest_sha256": "de1c738fa2bc9027ceacadabb7828d9890f5f9ff57ec4cde60494968f927333a",
        "completed_database_sha256": "8eec1cad93cce37d2f958c100570550bc7212c5aa86b92b7cf03950f85a83161",
        "query_reanalysis": False,
        "java_heap": "512M",
        "process_memory_limit_bytes": PROCESS_MEMORY_LIMIT,
    }
    checks = {key: request.get(key) == expected_value for key, expected_value in expected.items()}
    return {
        "path": str(request_path.resolve()),
        "sha256": _sha256_file(request_path),
        "actual": {key: request.get(key) for key in expected},
        "checks": checks,
        "all_fixed_checks_pass": all(checks.values()),
    }


def _identity_audit(
    extracted: Mapping[str, Any],
    request: Mapping[str, Any],
    rva: int,
    expected_evidence_id: str | None = None,
) -> dict[str, Any]:
    top = extracted.get("top_level", {})
    subject_entry = top.get("subject", {})
    provider_entry = top.get("provider", {})
    evidence_entry = top.get("evidence_id", {})
    params_entry = top.get("parameters", {})
    subject = subject_entry.get("value") if isinstance(subject_entry, Mapping) else None
    provider = provider_entry.get("value") if isinstance(provider_entry, Mapping) else None
    params = params_entry.get("value") if isinstance(params_entry, Mapping) else None
    raw_proc = extracted.get("raw_result_value", {}).get("procedure", {})
    norm_proc = extracted.get("normalized_result", {}).get("procedure", {})
    raw_proc_value = raw_proc.get("value") if isinstance(raw_proc, Mapping) else None
    norm_proc_value = norm_proc.get("value") if isinstance(norm_proc, Mapping) else None
    subject_sha = subject.get("digest", {}).get("sha256") if isinstance(subject, Mapping) else None
    provider_version = provider.get("version") if isinstance(provider, Mapping) else None
    raw_address = raw_proc_value.get("address") if isinstance(raw_proc_value, Mapping) else None
    norm_address = norm_proc_value.get("address") if isinstance(norm_proc_value, Mapping) else None
    checks = {
        "evidence_id_observed": evidence_entry.get("status") == "observed" and isinstance(evidence_entry.get("value"), str),
        "evidence_id_matches_spec": expected_evidence_id is None or evidence_entry.get("value") == expected_evidence_id,
        "subject_observed": subject_entry.get("status") == "observed",
        "fixed_executable_sha256": subject_sha == FIXED_TARGET_SHA256,
        "provider_observed": provider_entry.get("status") == "observed",
        "provider_version_12_1_4": provider_version == "12.1.4",
        "parameters_observed": params_entry.get("status") == "observed",
        "parameters_procedure": isinstance(params, Mapping) and params.get("procedure") == request.get("procedure"),
        "raw_procedure_observed": raw_proc.get("status") == "observed",
        "raw_procedure_address": raw_address == request.get("procedure") == hex(IMAGE_BASE + rva),
        "normalized_procedure_observed": norm_proc.get("status") == "observed",
        "normalized_procedure_address": norm_address == request.get("procedure") == hex(IMAGE_BASE + rva),
    }
    return {
        "status": "passed" if all(checks.values()) else "mismatch",
        "checks": checks,
        "evidence_id": evidence_entry.get("value"),
        "subject_sha256": subject_sha,
        "provider_version": provider_version,
        "raw_procedure_address": raw_address,
        "normalized_procedure_address": norm_address,
        "authorised_rva": hex(rva),
        "authorised_procedure": hex(IMAGE_BASE + rva),
    }


def _compare_values(extracted: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    raw_values = extracted.get("raw_result_value", {})
    normalized_values = extracted.get("normalized_result", {})
    for key in SELECTED_NAMES:
        raw = raw_values.get(key, {})
        normalized = normalized_values.get(key, {})
        raw_status = raw.get("status")
        normalized_status = normalized.get("status")
        item: dict[str, Any] = {"raw_status": raw_status, "normalized_status": normalized_status}
        if raw_status == "observed" and normalized_status == "observed":
            raw_value = raw.get("value")
            normalized_value = normalized.get("value")
            if raw_value == normalized_value:
                item["status"] = "equal"
            else:
                raw_bytes = json.dumps(raw_value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
                normalized_bytes = json.dumps(normalized_value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
                item.update({
                    "status": "mismatch",
                    "raw_sha256": hashlib.sha256(raw_bytes).hexdigest(),
                    "normalized_sha256": hashlib.sha256(normalized_bytes).hexdigest(),
                    "raw_json_bytes": len(raw_bytes),
                    "normalized_json_bytes": len(normalized_bytes),
                })
        else:
            item["status"] = "unknown"
            item["reason"] = "one or both selected spans were missing, oversized, or undecodable"
        result[key] = item
    return result


def _provider_runtime(query: Path, request: Mapping[str, Any], evidence_id: str) -> dict[str, Any]:
    run_path = query / "run.json"
    if not run_path.is_file():
        return {
            "run_json_path": str(run_path.resolve()),
            "run_json_present": False,
            "provider_exit_code": None,
            "wrapper_exit_code": None,
            "provider_peak_committed_bytes": None,
            "status": "unknown",
            "reason": "run.json absent; provider exit and peak remain unknown",
            "original_shell_postread": {
                "shell_id": 52519,
                "exit_code": 1,
                "phase": "postread",
                "reported_reason": "normal post-read helper refused the 32,568,212-byte evidence because the 10 MiB input limit was exceeded",
                "evidence_kind": "reported_runtime_note",
            },
        }
    run, _, _ = _json_object(run_path, max_bytes=MAX_RUN_BYTES)
    audit = _run_audit(run_path, run, request, evidence_id)
    receipt_checks = {
        "provider_exit_code_zero": run.get("provider_exit_code") == 0,
        "wrapper_exit_code_zero": run.get("wrapper_exit_code") == 0,
        "status_completed": run.get("status") == "completed",
        "reason_completed": run.get("reason") == "completed",
        "supervisor_completed": run.get("supervisor_reason") == "completed",
        "cleanup_complete": isinstance(run.get("cleanup"), Mapping)
        and run["cleanup"].get("status") == "complete"
        and run["cleanup"].get("closed_process_receipt") is True,
        "postread_exit_zero": isinstance(run.get("postread"), Mapping)
        and run["postread"].get("exit_code") == 0,
        "database_unchanged": run.get("database_unchanged") is True,
    }
    runtime_ok = audit.get("status") == "passed" and all(receipt_checks.values())
    return {
        "run_json_path": str(run_path.resolve()),
        "run_json_present": True,
        "provider_exit_code": run.get("provider_exit_code"),
        "wrapper_exit_code": run.get("wrapper_exit_code"),
        "process_exit_code": run.get("exit_code"),
        "run_status": run.get("status"),
        "run_reason": run.get("reason"),
        "receipt_checks": receipt_checks,
        "provider_peak_committed_bytes": audit.get("peak_committed_bytes"),
        "status": "passed" if runtime_ok else "mismatch",
        "audit": audit,
    }


def _write_new(path: Path, value: Mapping[str, Any]) -> tuple[int, str]:
    if path.exists():
        raise FileExistsError(f"refusing_to_overwrite:{path}")
    raw = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _require(len(raw) <= MAX_OUTPUT_BYTES, f"output_over_bound:{path}:{len(raw)}>{MAX_OUTPUT_BYTES}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return len(raw), hashlib.sha256(raw).hexdigest()


def run_query(
    query: Path,
    rva: int,
    *,
    expected_evidence_id: str | None = None,
    semantic_boundary: str | None = None,
) -> tuple[Path, Path]:
    query = query.resolve()
    stage = STAGE.resolve()
    try:
        query.relative_to(stage)
    except ValueError as exc:
        raise ValueError(f"query_outside_war_records_stage:{query}") from exc
    _require(query.is_dir(), f"query_directory_missing:{query}")
    evidence = query / "evidence.json"
    request_path = query / "request.json"
    selected_path = query / "selected-evidence-001.json"
    readback_path = query / "readback-recovery-001.json"
    _require(evidence.is_file(), f"evidence_missing:{evidence}")
    _require(request_path.is_file(), f"request_missing:{request_path}")
    request, _, _ = _json_object(request_path, max_bytes=MAX_REQUEST_BYTES)
    request_audit = _request_audit(request_path, request, rva)
    _require(request_audit["all_fixed_checks_pass"], f"request_guard_failed:{request_audit['checks']}")
    extracted = _extract_selected(evidence)
    identity_audit = _identity_audit(extracted, request, rva, expected_evidence_id)
    _require(identity_audit["status"] == "passed", f"identity_or_procedure_guard_failed:{identity_audit['checks']}")
    evidence_id = identity_audit["evidence_id"]
    extracted["query"] = {
        "directory": query.relative_to(stage).as_posix(),
        "authorised_rva": hex(rva),
        "authorised_procedure": hex(IMAGE_BASE + rva),
        "fixed_build": "1.37.4",
        "target_sha256": FIXED_TARGET_SHA256,
        "semantic_boundary": semantic_boundary,
    }
    extracted["request"] = request_audit
    extracted["identity_audit"] = identity_audit
    extracted["profile_audit"] = _profile_audit(extracted, dict(request))
    extracted["cache_audit"] = _cache_audit(dict(request))
    extracted["normalized_comparison"] = _compare_values(extracted)
    extracted["provider_runtime"] = _provider_runtime(query, request, evidence_id)
    extracted["authority"] = {
        "kind": "bounded_static_rea_readback",
        "native_function_invoked": False,
        "game_access": False,
        "dispatch_authorized": False,
    }
    selected_size, selected_sha = _write_new(selected_path, extracted)
    provider_runtime = extracted.get("provider_runtime", {})
    provider_complete = provider_runtime.get("run_json_present") is True and provider_runtime.get("status") == "passed"
    selected_spans_complete = extracted.get("status") == "observed" and all(item.get("status") == "equal" for item in extracted["normalized_comparison"].values())
    readback = {
        "schema": "information_battle_war_records_evidence_readback_recovery_v1",
        "status": "observed" if selected_spans_complete and provider_complete else "partial_readback",
        "query": extracted["query"],
        "evidence": {
            "path": str(evidence.resolve()),
            "sha256": extracted.get("source", {}).get("sha256"),
            "size_bytes": extracted.get("source", {}).get("size_bytes"),
            "selected_report_path": str(selected_path.resolve()),
            "selected_report_bytes": selected_size,
            "selected_report_sha256": selected_sha,
        },
        "request": request_audit,
        "identity_audit": identity_audit,
        "profile_audit": extracted.get("profile_audit"),
        "cache_audit": extracted.get("cache_audit"),
        "normalized_comparison": extracted.get("normalized_comparison"),
        "provider_runtime": extracted.get("provider_runtime"),
        "parser_boundary": {
            "method": "mmap_bounded_json_span_scan_reused_previous_extractor",
            "max_selected_value_bytes": MAX_SELECTED_VALUE_BYTES,
            "whole_document_json_validated": False,
            "integrity": "unknown_not_full_json_validated",
            "raw_json_materialized": False,
        },
        "limitations": [
            "Only top identity/profile/provider/evidence_id and selected procedure/pseudocode/assembly/callees spans were decoded.",
            "Raw and normalized values are compared only for those selected spans.",
            "Provider and wrapper exit codes are kept as separate receipt fields; a shell/post-read result is not substituted for either.",
            "No REA query, game access, RPM, native function invocation, or helper-limit change was performed.",
        ],
    }
    _write_new(readback_path, readback)
    return selected_path, readback_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--query", type=Path, help="one REA query directory under the war-records stage")
    parser.add_argument("--rva", help="authorised fixed-build RVA for --query")
    args = parser.parse_args(argv)
    if args.query is not None:
        _require(args.rva is not None, "--rva_required_with_query")
        selected, readback = run_query(args.query, _parse_rva(args.rva))
        print(json.dumps({"status": "passed", "selected": str(selected), "readback": str(readback)}, ensure_ascii=False))
        return 0
    _require(args.rva is None, "--rva_only_valid_with_query")
    results = []
    for spec in QUERY_SPECS:
        selected, readback = run_query(
            STAGE / spec["directory"],
            spec["rva"],
            expected_evidence_id=spec["evidence_id"],
            semantic_boundary=spec["semantic_boundary"],
        )
        results.append({"name": spec["name"], "selected": str(selected), "readback": str(readback)})
    print(json.dumps({"status": "passed", "queries": results}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"fragment readback failed closed: {exc}", file=sys.stderr)
        raise SystemExit(1)
