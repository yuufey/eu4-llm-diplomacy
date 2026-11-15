"""Extract bounded evidence spans for the fixed-build battle-layout queries.

The previous battle extractor owns the mmap/span scanner.  This wrapper keeps
that scanner and the cache-commitment audit, but makes the query directory and
the authorised RVA explicit.  It can therefore be used for the layout queries
at ``0x1dd020``, ``0x1dd930`` and ``0x232a80`` without copying the original
evidence document into memory.  Each selected value is capped by the previous
2 MiB limit; a missing ``run.json`` produces unknown provider exit/peak fields.

This module is readback-only.  It never invokes REA, opens a game process, or
calls a native/game function.
"""
from __future__ import annotations

import argparse
import json
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


STAGE = ROOT / "work" / "runtime" / "information-battle-layout-20261025-001"
IMAGE_BASE = 0x140000000
ADAPTER_SHA256 = "93620e986ea9ea17f5b6a8e56a5077772af0090a8d0eb467019aea40d38a689d"
MANIFEST_SHA256 = "de1c738fa2bc9027ceacadabb7828d9890f5f9ff57ec4cde60494968f927333a"
DATABASE_SHA256 = "8eec1cad93cce37d2f958c100570550bc7212c5aa86b92b7cf03950f85a83161"
PROCESS_MEMORY_LIMIT = 1024 * 1024 * 1024
ALLOWED_RVAS = frozenset({0x1DD020, 0x1DD930, 0x232A80})
MAX_REQUEST_BYTES = 64 * 1024
MAX_RUN_BYTES = 64 * 1024


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
    digest = _sha256_file(path)
    raw = path.read_bytes()
    _require(len(raw) == size, f"file_changed_during_read:{path}")
    value = json.loads(raw.decode("utf-8"))
    _require(isinstance(value, dict), f"json_object_required:{path}")
    return value, size, digest


def _extract_selected(evidence: Path) -> dict[str, Any]:
    """Scan only the fixed top-level/raw-result members of one evidence file."""
    identity_before = _file_identity(evidence)
    source_sha = _sha256_file(evidence)
    identity_after_hash = _file_identity(evidence)
    if identity_before != identity_after_hash:
        return {
            "status": "source_changed_during_hash",
            "source": {**identity_after_hash, "sha256": source_sha},
            "parser": {"integrity": "unknown_not_full_json_validated"},
        }

    selected_top = {"evidence_id", "subject", "provider", "analysis_profile", "raw_result"}
    selected_names = {"procedure", "pseudocode", "callers", "callees"}
    top_results: dict[str, Any] = {}
    raw_value_results: dict[str, Any] = {}
    parser_error: str | None = None
    raw_result_span: dict[str, int] | None = None

    with evidence.open("rb") as stream:
        import mmap

        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as view:
            scanner = _SpanScanner(view)
            top_spans, parser_error = _find_member(scanner, 0, len(view), selected_top)
            for key in ("evidence_id", "subject", "provider", "analysis_profile"):
                span = top_spans.get(key)
                if span is None:
                    top_results[key] = {"path": key, "status": "missing"}
                else:
                    top_results[key] = _decode_span(view, *span, path=key)

            raw_span = top_spans.get("raw_result")
            if raw_span is None:
                raw_value_results = {
                    key: {"path": f"raw_result.value.{key}", "status": "missing"}
                    for key in sorted(selected_names)
                }
            else:
                raw_result_span = {
                    "start_byte": raw_span[0],
                    "end_byte_exclusive": raw_span[1],
                    "span_bytes": raw_span[1] - raw_span[0],
                }
                raw_members, raw_error = _find_member(scanner, *raw_span, {"value"})
                if raw_error and parser_error is None:
                    parser_error = f"raw_result: {raw_error}"
                value_span = raw_members.get("value")
                if value_span is None:
                    raw_value_results = {
                        key: {"path": f"raw_result.value.{key}", "status": "missing"}
                        for key in sorted(selected_names)
                    }
                else:
                    value_members, value_error = _find_member(scanner, *value_span, selected_names)
                    if value_error and parser_error is None:
                        parser_error = f"raw_result.value: {value_error}"
                    for key in sorted(selected_names):
                        span = value_members.get(key)
                        if span is None:
                            raw_value_results[key] = {
                                "path": f"raw_result.value.{key}",
                                "status": "missing",
                            }
                        else:
                            raw_value_results[key] = _decode_span(
                                view, *span, path=f"raw_result.value.{key}"
                            )
            identity_after = _file_identity(evidence)

    source_stable = identity_before == identity_after
    statuses = [
        value.get("status")
        for value in [*top_results.values(), *raw_value_results.values()]
    ]
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
            "raw_result_span": raw_result_span,
            "selected_values_are_individually_decoded": True,
        },
        "top_level": top_results,
        "raw_result_value": raw_value_results,
    }


def _request_audit(request_path: Path, request: Mapping[str, Any], rva: int) -> dict[str, Any]:
    expected = {
        "target_sha256": FIXED_TARGET_SHA256,
        "node": hex(rva),
        "procedure": hex(IMAGE_BASE + rva),
        "preset": FIXED_PRESET,
        "adapter_sha256": ADAPTER_SHA256,
        "completed_manifest_sha256": MANIFEST_SHA256,
        "completed_database_sha256": DATABASE_SHA256,
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


def _run_audit(run_path: Path, run: Mapping[str, Any], request: Mapping[str, Any], evidence_id: str) -> dict[str, Any]:
    expected = {
        "target_sha256": FIXED_TARGET_SHA256,
        "node": request.get("node"),
        "procedure": request.get("procedure"),
        "preset": FIXED_PRESET,
        "adapter_sha256": ADAPTER_SHA256,
        "completed_manifest_sha256": MANIFEST_SHA256,
        "completed_database_sha256": DATABASE_SHA256,
        "query_reanalysis": False,
        "java_heap": "512M",
        "process_memory_limit_bytes": PROCESS_MEMORY_LIMIT,
        "exit_code": 0,
        "reason": "completed",
        "database_unchanged": True,
        "evidence_id": evidence_id,
    }
    checks = {key: run.get(key) == value for key, value in expected.items()}
    processes = run.get("processes")
    process_checks: list[dict[str, Any]] = []
    if isinstance(processes, list) and processes:
        for process in processes:
            if not isinstance(process, Mapping):
                process_checks.append({"status": "invalid"})
                continue
            peak = process.get("peak_committed_bytes")
            process_checks.append(
                {
                    "peak_committed_bytes": peak,
                    "below_1gb": isinstance(peak, int) and not isinstance(peak, bool) and peak < PROCESS_MEMORY_LIMIT,
                    "closed": process.get("still_running_same_process") is False,
                }
            )
    process_ok = bool(process_checks) and all(item.get("below_1gb") and item.get("closed") for item in process_checks)
    checks["process_receipt"] = process_ok
    return {
        "path": str(run_path.resolve()),
        "bytes": run_path.stat().st_size,
        "sha256": _sha256_file(run_path),
        "status": "passed" if all(checks.values()) else "mismatch",
        "checks": checks,
        "processes": process_checks,
        "exit_code": run.get("exit_code"),
        "peak_committed_bytes": max(
            (item.get("peak_committed_bytes") for item in process_checks if isinstance(item.get("peak_committed_bytes"), int)),
            default=None,
        ),
    }


def _provider_runtime(query: Path, request: Mapping[str, Any], evidence_id: str) -> dict[str, Any]:
    run_path = query / "run.json"
    if not run_path.is_file():
        return {
            "run_json_path": str(run_path.resolve()),
            "run_json_present": False,
            "provider_exit_code": None,
            "provider_peak_committed_bytes": None,
            "status": "unknown",
            "reason": "run.json absent; provider exit and peak are unknown",
        }
    run, _, _ = _json_object(run_path, max_bytes=MAX_RUN_BYTES)
    audit = _run_audit(run_path, run, request, evidence_id)
    return {
        "run_json_path": str(run_path.resolve()),
        "run_json_present": True,
        "provider_exit_code": run.get("exit_code"),
        "provider_peak_committed_bytes": audit.get("peak_committed_bytes"),
        "status": audit.get("status"),
        "audit": audit,
    }


def _identity_and_procedure_audit(extracted: Mapping[str, Any], rva: int) -> dict[str, Any]:
    subject_entry = extracted.get("top_level", {}).get("subject", {})
    provider_entry = extracted.get("top_level", {}).get("provider", {})
    procedure_entry = extracted.get("raw_result_value", {}).get("procedure", {})
    subject = subject_entry.get("value") if isinstance(subject_entry, Mapping) else None
    provider = provider_entry.get("value") if isinstance(provider_entry, Mapping) else None
    procedure = procedure_entry.get("value") if isinstance(procedure_entry, Mapping) else None
    subject_sha = subject.get("digest", {}).get("sha256") if isinstance(subject, Mapping) else None
    provider_version = provider.get("version") if isinstance(provider, Mapping) else None
    address_text = procedure.get("address") if isinstance(procedure, Mapping) else None
    try:
        address = int(address_text, 0) if isinstance(address_text, str) else None
    except ValueError:
        address = None
    checks = {
        "subject_observed": subject_entry.get("status") == "observed",
        "fixed_executable_sha256": subject_sha == FIXED_TARGET_SHA256,
        "provider_observed": provider_entry.get("status") == "observed",
        "provider_version_12_1_4": provider_version == "12.1.4",
        "procedure_observed": procedure_entry.get("status") == "observed",
        "procedure_rva": address == IMAGE_BASE + rva,
    }
    return {
        "status": "passed" if all(checks.values()) else "mismatch",
        "checks": checks,
        "subject_sha256": subject_sha,
        "provider_version": provider_version,
        "procedure_address": hex(address) if isinstance(address, int) else None,
        "authorised_rva": hex(rva),
    }


def _json_write_new(path: Path, value: Mapping[str, Any]) -> tuple[int, str]:
    if path.exists():
        raise FileExistsError(f"refusing_to_overwrite:{path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.write_bytes(raw)
    return len(raw), _sha256_file(path)


def run_query(query: Path, rva: int) -> tuple[Path, Path]:
    query = query.resolve()
    stage = STAGE.resolve()
    try:
        query.relative_to(stage)
    except ValueError as exc:
        raise ValueError(f"query_outside_battle_layout_stage:{query}") from exc
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
    identity_audit = _identity_and_procedure_audit(extracted, rva)
    _require(identity_audit["status"] == "passed", f"identity_or_procedure_guard_failed:{identity_audit['checks']}")
    evidence_id_entry = extracted.get("top_level", {}).get("evidence_id", {})
    evidence_id = evidence_id_entry.get("value") if evidence_id_entry.get("status") == "observed" else None
    _require(isinstance(evidence_id, str) and evidence_id.startswith("ev_"), "evidence_id_unobserved")
    extracted["query"] = {
        "directory": query.relative_to(stage).as_posix(),
        "authorised_rva": hex(rva),
        "authorised_procedure": hex(IMAGE_BASE + rva),
        "fixed_build": "1.37.4",
        "target_sha256": FIXED_TARGET_SHA256,
    }
    extracted["request"] = request_audit
    extracted["identity_audit"] = identity_audit
    extracted["profile_audit"] = _profile_audit(extracted, dict(request))
    extracted["cache_audit"] = _cache_audit(dict(request))
    extracted["provider_runtime"] = _provider_runtime(query, request, evidence_id)
    extracted["authority"] = {
        "kind": "bounded_static_rea_readback",
        "native_function_invoked": False,
        "game_access": False,
        "dispatch_authorized": False,
    }
    selected_size, selected_sha = _json_write_new(selected_path, extracted)
    provider_runtime = extracted.get("provider_runtime", {})
    readback_status = (
        "observed"
        if extracted.get("status") == "observed" and provider_runtime.get("run_json_present") is True
        else "partial_readback"
    )
    readback = {
        "schema": "information_battle_layout_evidence_readback_recovery_v1",
        "status": readback_status,
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
        "provider_runtime": extracted.get("provider_runtime"),
        "parser_boundary": {
            "method": "mmap_bounded_json_span_scan_reused_previous_extractor",
            "max_selected_value_bytes": MAX_SELECTED_VALUE_BYTES,
            "whole_document_json_validated": False,
            "integrity": "unknown_not_full_json_validated",
        },
        "limitations": [
            "Only selected subject/provider/profile/procedure/pseudocode/callers/callees spans were decoded.",
            "This readback does not infer provider exit or memory peak when run.json is absent.",
            "No REA query, game access, RPM, or native function invocation was performed by this extractor.",
        ],
    }
    _json_write_new(readback_path, readback)
    return selected_path, readback_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--query", type=Path, required=True, help="REA query directory under the battle-layout stage")
    parser.add_argument("--rva", required=True, help="authorised fixed-build RVA: 0x1dd020, 0x1dd930, or 0x232a80")
    args = parser.parse_args(argv)
    rva = _parse_rva(args.rva)
    selected, readback = run_query(args.query, rva)
    print(json.dumps({"status": "passed", "selected": str(selected), "readback": str(readback)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
