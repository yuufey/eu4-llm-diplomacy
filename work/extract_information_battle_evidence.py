"""Bounded recovery of the oversized battle-dispatch REA evidence.

The provider wrote an evidence JSON larger than the normal 10 MiB readback
limit.  This module deliberately does not load that document as one Python
object.  It scans JSON spans through an mmap, copies only selected values no
larger than ``MAX_SELECTED_VALUE_BYTES``, and records that whole-document JSON
validity was not re-established.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path
import sys
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STAGE = ROOT / "work" / "runtime" / "information-battles-20261025-001"
DEFAULT_QUERY = DEFAULT_STAGE / "rea-message-dispatch-001"
DEFAULT_EVIDENCE = DEFAULT_QUERY / "evidence.json"
DEFAULT_REQUEST = DEFAULT_QUERY / "request.json"
DEFAULT_SELECTED = DEFAULT_QUERY / "selected-evidence-001.json"
DEFAULT_READBACK = DEFAULT_QUERY / "readback-recovery-001.json"

FIXED_TARGET_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
FIXED_NODE = "0x22e6b0"
FIXED_PROCEDURE = "0x14022e6b0"
FIXED_PRESET = "eu4-persistent-default-analysis-v1"
MAX_SELECTED_VALUE_BYTES = 2 * 1024 * 1024
MAX_KEY_BYTES = 4096
MAX_DEPTH = 1024
MAX_EXCERPT_CHARS = 12000


class ScanError(ValueError):
    """A bounded JSON span could not be located."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_identity(path: Path) -> dict[str, Any]:
    stat = path.stat()
    return {
        "path": str(path.resolve()),
        "size_bytes": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "mtime_utc": __import__("datetime").datetime.fromtimestamp(
            stat.st_mtime, __import__("datetime").timezone.utc
        ).isoformat(),
    }


class _SpanScanner:
    """Scan JSON structure without materializing values."""

    def __init__(self, view: mmap.mmap, *, max_depth: int = MAX_DEPTH) -> None:
        self.view = view
        self.size = len(view)
        self.max_depth = max_depth

    def _skip_ws(self, pos: int, limit: int) -> int:
        while pos < limit and self.view[pos] in b" \t\r\n":
            pos += 1
        return pos

    def _string_end(self, pos: int, limit: int) -> int:
        if pos >= limit or self.view[pos] != ord('"'):
            raise ScanError(f"expected JSON string at byte {pos}")
        pos += 1
        while pos < limit:
            value = self.view[pos]
            if value == ord('\\'):
                pos += 2
                if pos > limit:
                    raise ScanError("truncated JSON escape")
                continue
            if value == ord('"'):
                return pos + 1
            pos += 1
        raise ScanError("unterminated JSON string")

    def _key(self, start: int, end: int) -> str:
        if end - start > MAX_KEY_BYTES:
            raise ScanError("JSON key exceeds bounded key size")
        try:
            value = json.loads(bytes(self.view[start:end]).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ScanError(f"invalid JSON key: {exc}") from exc
        if not isinstance(value, str):
            raise ScanError("JSON object key did not decode to a string")
        return value

    def _value_end(self, start: int, limit: int, depth: int = 0) -> int:
        if start >= limit:
            raise ScanError("missing JSON value")
        first = self.view[start]
        if first == ord('"'):
            return self._string_end(start, limit)
        if first not in (ord('{'), ord('[')):
            pos = start
            while pos < limit and self.view[pos] not in b" \t\r\n,]}":
                pos += 1
            if pos == start:
                raise ScanError(f"empty JSON primitive at byte {start}")
            return pos
        if depth >= self.max_depth:
            raise ScanError("JSON nesting exceeds bounded depth")
        expected = [ord('}') if first == ord('{') else ord(']')]
        pos = start + 1
        while expected:
            if pos >= limit:
                raise ScanError("truncated JSON container")
            value = self.view[pos]
            if value == ord('"'):
                pos = self._string_end(pos, limit)
                continue
            if value == ord('{'):
                if len(expected) >= self.max_depth:
                    raise ScanError("JSON nesting exceeds bounded depth")
                expected.append(ord('}'))
                pos += 1
                continue
            if value == ord('['):
                if len(expected) >= self.max_depth:
                    raise ScanError("JSON nesting exceeds bounded depth")
                expected.append(ord(']'))
                pos += 1
                continue
            if value in (ord('}'), ord(']')):
                if value != expected[-1]:
                    raise ScanError(f"mismatched JSON closer at byte {pos}")
                expected.pop()
                pos += 1
                continue
            pos += 1
        return pos

    def members(self, start: int, limit: int) -> Iterable[tuple[str, int, int]]:
        """Yield direct object members as (key, value_start, value_end)."""
        pos = self._skip_ws(start, limit)
        if pos >= limit or self.view[pos] != ord('{'):
            raise ScanError(f"expected JSON object at byte {pos}")
        pos += 1
        while True:
            pos = self._skip_ws(pos, limit)
            if pos >= limit:
                raise ScanError("truncated JSON object")
            if self.view[pos] == ord('}'):
                return
            key_start = pos
            key_end = self._string_end(pos, limit)
            key = self._key(key_start, key_end)
            pos = self._skip_ws(key_end, limit)
            if pos >= limit or self.view[pos] != ord(':'):
                raise ScanError(f"missing colon after JSON key {key!r}")
            pos = self._skip_ws(pos + 1, limit)
            value_start = pos
            value_end = self._value_end(value_start, limit)
            yield key, value_start, value_end
            pos = self._skip_ws(value_end, limit)
            if pos >= limit:
                raise ScanError("truncated JSON object separator")
            if self.view[pos] == ord(','):
                pos += 1
                continue
            if self.view[pos] == ord('}'):
                return
            raise ScanError(f"unexpected JSON object separator at byte {pos}")


def _decode_span(
    view: mmap.mmap,
    start: int,
    end: int,
    *,
    path: str,
) -> dict[str, Any]:
    span = end - start
    result: dict[str, Any] = {
        "path": path,
        "start_byte": start,
        "end_byte_exclusive": end,
        "span_bytes": span,
        "limit_bytes": MAX_SELECTED_VALUE_BYTES,
    }
    if span > MAX_SELECTED_VALUE_BYTES:
        result.update({"status": "omitted_oversize", "value": None})
        return result
    try:
        value = json.loads(bytes(view[start:end]))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        result.update({"status": "decode_failed", "value": None, "error": str(exc)})
        return result
    result.update({"status": "observed", "value": value})
    return result


def _find_member(
    scanner: _SpanScanner,
    start: int,
    end: int,
    wanted: set[str],
) -> tuple[dict[str, tuple[int, int]], str | None]:
    found: dict[str, tuple[int, int]] = {}
    try:
        for key, value_start, value_end in scanner.members(start, end):
            if key in wanted:
                found[key] = (value_start, value_end)
    except ScanError as exc:
        return found, str(exc)
    return found, None


def _extract_selected(evidence: Path) -> dict[str, Any]:
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
                                view,
                                *span,
                                path=f"raw_result.value.{key}",
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
            "kind": "mmap_bounded_json_span_scan",
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


def _request_audit(request_path: Path, request: dict[str, Any]) -> dict[str, Any]:
    checks = {
        "target_sha256": request.get("target_sha256") == FIXED_TARGET_SHA256,
        "node": str(request.get("node", "")).lower() == FIXED_NODE,
        "procedure": str(request.get("procedure", "")).lower() == FIXED_PROCEDURE,
        "preset": request.get("preset") == FIXED_PRESET,
        "query_reanalysis_false": request.get("query_reanalysis") is False,
        "java_heap_512m": request.get("java_heap") == "512M",
        "memory_limit_1g": request.get("process_memory_limit_bytes") == 1024**3,
    }
    return {
        "path": str(request_path.resolve()),
        "sha256": _sha256_file(request_path),
        "actual": {
            "target_sha256": request.get("target_sha256"),
            "node": request.get("node"),
            "procedure": request.get("procedure"),
            "preset": request.get("preset"),
            "adapter_sha256": request.get("adapter_sha256"),
            "completed_manifest_sha256": request.get("completed_manifest_sha256"),
            "completed_database_sha256": request.get("completed_database_sha256"),
        },
        "checks": checks,
        "all_fixed_checks_pass": all(checks.values()),
    }


def _profile_audit(selected: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    row = selected.get("top_level", {}).get("analysis_profile", {})
    if row.get("status") != "observed" or not isinstance(row.get("value"), dict):
        return {"status": "unknown", "reason": "analysis_profile missing_or_oversize"}
    profile = row["value"]
    parameters = profile.get("parameters") if isinstance(profile.get("parameters"), dict) else profile
    if not isinstance(parameters, dict):
        return {"status": "unknown", "reason": "analysis_profile.parameters is not an object"}
    checks = {
        "analyzer_preset": parameters.get("analyzer_preset") == request.get("preset"),
        "local_adapter_sha256": parameters.get("local_adapter_sha256") == request.get("adapter_sha256"),
        "completed_manifest_sha256": parameters.get("completed_manifest_sha256") == request.get("completed_manifest_sha256"),
        "completed_database_sha256": parameters.get("completed_database_sha256") == request.get("completed_database_sha256"),
    }
    return {
        "status": "observed" if all(checks.values()) else "mismatch",
        "checks": checks,
        "parameters_keys": sorted(parameters),
    }


def _cache_audit(request: dict[str, Any]) -> dict[str, Any]:
    cache_value = request.get("cache")
    result: dict[str, Any] = {
        "requested_path": cache_value,
        "database_commitment_function": "reverse_engineering.cache_query.database_commitment",
        "request_database_sha256": request.get("completed_database_sha256"),
        "actual_database_sha256": None,
        "database_sha256_matches": False,
        "status": "unknown",
    }
    if not isinstance(cache_value, str):
        result["reason"] = "request.cache is not a string"
        return result
    cache = Path(cache_value)
    if not cache.is_dir():
        result["reason"] = "cache directory is missing"
        return result
    try:
        sys.path.insert(0, str(ROOT))
        from reverse_engineering.cache_query import database_commitment

        actual = database_commitment(cache)
    except Exception as exc:  # pragma: no cover - environment-specific cache errors
        result["reason"] = f"database_commitment failed: {type(exc).__name__}: {exc}"
        return result
    result["actual_database_sha256"] = actual
    result["database_sha256_matches"] = actual == request.get("completed_database_sha256")
    result["status"] = "passed" if result["database_sha256_matches"] else "mismatch"
    return result


def _address_summary(value: Any, *, limit: int = 64) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []

    def visit(node: Any) -> None:
        if len(found) >= limit:
            return
        if isinstance(node, dict):
            for key, item in node.items():
                if key in {"address", "source_address", "target_address", "caller_address"} and isinstance(item, str):
                    found.append({"key": key, "value": item})
                visit(item)
                if len(found) >= limit:
                    return
        elif isinstance(node, list):
            for item in node:
                visit(item)
                if len(found) >= limit:
                    return

    visit(value)
    return found


def _pseudocode_excerpt(value: Any) -> dict[str, Any]:
    if not isinstance(value, str):
        return {"status": "not_text"}
    lines = value.splitlines()
    needles = ("battle", "message", "dispatch", "war", "caller", "recipient", "0x")
    selected = [line for line in lines if any(needle in line.lower() for needle in needles)]
    excerpt = "\n".join(selected[:300]) if selected else value
    truncated = len(excerpt) > MAX_EXCERPT_CHARS
    return {
        "status": "observed",
        "text": excerpt[:MAX_EXCERPT_CHARS],
        "truncated": truncated,
        "source_chars": len(value),
    }


def _json_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run(*, evidence: Path, request_path: Path, selected_path: Path, readback_path: Path) -> tuple[Path, Path]:
    request = json.loads(request_path.read_text(encoding="utf-8"))
    if not isinstance(request, dict):
        raise ValueError("request.json must contain an object")
    extracted = _extract_selected(evidence)
    request_audit = _request_audit(request_path, request)
    extracted["request"] = request_audit
    extracted["profile_audit"] = _profile_audit(extracted, request)
    extracted["cache_audit"] = _cache_audit(request)
    callers = extracted.get("raw_result_value", {}).get("callers", {})
    pseudocode = extracted.get("raw_result_value", {}).get("pseudocode", {})
    extracted["derived_readback_hints"] = {
        "direct_caller_addresses": _address_summary(callers.get("value")) if callers.get("status") == "observed" else [],
        "pseudocode_excerpt": _pseudocode_excerpt(pseudocode.get("value")) if pseudocode.get("status") == "observed" else {"status": pseudocode.get("status", "missing")},
    }
    _json_write(selected_path, extracted)
    selected_sha = _sha256_file(selected_path)

    run_path = request_path.with_name("run.json")
    provider_runtime = {
        "run_json_path": str(run_path.resolve()),
        "run_json_present": run_path.is_file(),
        "provider_exit_code": None,
        "provider_peak_committed_bytes": None,
        "status": "unknown",
        "reason": "run.json is absent; provider exit and peak must not be inferred from the shell post-read failure.",
    }
    readback = {
        "schema": "information_battle_evidence_readback_recovery_v1",
        "status": "partial_readback",
        "evidence": {
            "path": str(evidence.resolve()),
            "sha256": extracted.get("source", {}).get("sha256"),
            "size_bytes": extracted.get("source", {}).get("size_bytes"),
            "selected_report_path": str(selected_path.resolve()),
            "selected_report_sha256": selected_sha,
        },
        "request": request_audit,
        "profile_audit": extracted.get("profile_audit"),
        "cache_audit": extracted.get("cache_audit"),
        "provider_runtime": provider_runtime,
        "original_shell_postread": {
            "shell_id": 23042,
            "exit_code": 1,
            "phase": "postread",
            "reported_reason": "The normal _read_json helper refused the 10,577,723-byte evidence because its 10 MiB input limit was exceeded.",
            "evidence_kind": "reported_runtime_note",
        },
        "parser_boundary": {
            "method": "mmap_bounded_json_span_scan",
            "max_selected_value_bytes": MAX_SELECTED_VALUE_BYTES,
            "whole_document_json_validated": False,
            "integrity": "unknown_not_full_json_validated",
        },
        "selected_status": extracted.get("status"),
        "limitations": [
            "This report recovers selected JSON spans only; it is not a provider run receipt.",
            "The absent run.json leaves provider exit code and peak memory unknown.",
            "No REA query, game access, or helper-limit change was performed.",
        ],
    }
    _json_write(readback_path, readback)
    return selected_path, readback_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--request", type=Path, default=DEFAULT_REQUEST)
    parser.add_argument("--selected", type=Path, default=DEFAULT_SELECTED)
    parser.add_argument("--readback", type=Path, default=DEFAULT_READBACK)
    args = parser.parse_args(argv)
    selected, readback = run(
        evidence=args.evidence,
        request_path=args.request,
        selected_path=args.selected,
        readback_path=args.readback,
    )
    print(json.dumps({"selected": str(selected), "readback": str(readback)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
