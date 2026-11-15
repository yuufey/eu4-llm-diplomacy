"""Bounded ordinary-PE survey for domestic-pressure resource names.

This module deliberately does one narrow thing: it searches the fixed 1.37.4
executable for six explicitly requested ASCII tokens.  NUL-boundary matches,
substring occurrences, and raw RIP-relative byte-pattern candidates are kept
as separate evidence classes.  The latter are only candidates; this script
does not disassemble, attach to a process, call REA/RPM, or infer a getter.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE, check_memory_budget, rip_references  # noqa: E402


EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
EXPECTED_EXE_BYTES = 38_463_016
EXPECTED_IMAGE_BASE = 0x140000000
MAX_EXE_BYTES = 64 * 1024 * 1024
MAX_CONTEXT_BYTES = 100
MAX_MATCHES_PER_TARGET = 256
MAX_RIP_CANDIDATES_PER_TARGET = 128
MAX_FUNCTION_SPAN_BYTES = 0x6000

TARGETS = (
    "STABILITY",
    "WAR_EXHAUSTION",
    "CORRUPTION",
    "RELIGIOUS_UNITY",
    "stability",
    "war_exhaustion",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _section_for_offset(pe: PE, offset: int) -> dict[str, Any] | None:
    for section in pe.sections:
        if section["raw"] <= offset < section["raw"] + section["size"]:
            return section
    return None


def _location(pe: PE, file_offset: int) -> dict[str, Any]:
    rva = pe.to_rva(file_offset)
    section = _section_for_offset(pe, file_offset)
    return {
        "file_offset": hex(file_offset),
        "rva": None if rva is None else hex(rva),
        "static_va": None if rva is None else hex(pe.base + rva),
        "section": None if section is None else section["name"],
    }


def _bounded_context(data: bytes, start: int, end: int) -> tuple[int, int, bytes]:
    if end < start or end - start > MAX_CONTEXT_BYTES:
        raise ValueError("context target exceeds the bounded context limit")
    spare = MAX_CONTEXT_BYTES - (end - start)
    left = min(start, spare // 2)
    context_start = start - left
    context_end = min(len(data), context_start + MAX_CONTEXT_BYTES)
    if context_end < end:
        context_end = end
        context_start = max(0, context_end - MAX_CONTEXT_BYTES)
    return context_start, context_end, data[context_start:context_end]


def _ascii_context(raw: bytes) -> str:
    return "".join(chr(value) if 32 <= value < 127 else "." for value in raw)


def _identifier_byte(value: int | None) -> bool:
    return value is not None and (
        0x30 <= value <= 0x39
        or 0x41 <= value <= 0x5A
        or 0x61 <= value <= 0x7A
        or value == 0x5F
    )


def _boundary_reason(prefix: int | None, suffix: int | None, exact: bool) -> str:
    if exact:
        return "prefix_is_token_boundary_and_suffix_is_nul"
    reasons: list[str] = []
    if _identifier_byte(prefix):
        reasons.append("prefix_identifier_byte")
    if suffix != 0:
        reasons.append("suffix_not_nul")
    if not reasons:
        reasons.append("not_exact_nul_boundary")
    return "+".join(reasons)


def _string_row(
    pe: PE,
    data: bytes,
    target: str,
    file_offset: int,
    needle: bytes,
    exact: bool,
) -> dict[str, Any]:
    end = file_offset + len(needle)
    prefix = data[file_offset - 1] if file_offset else None
    suffix = data[end] if end < len(data) else None
    context_start, context_end, context = _bounded_context(data, file_offset, end)
    return {
        "target": target,
        "encoding": "ascii",
        "match_kind": "exact_nul_boundary" if exact else "substring_candidate",
        "boundary_reason": _boundary_reason(prefix, suffix, exact),
        "prefix_byte": None if prefix is None else hex(prefix),
        "suffix_byte": None if suffix is None else hex(suffix),
        "nul_terminated": suffix == 0,
        "byte_length": len(needle),
        **_location(pe, file_offset),
        "context_file_offset": [hex(context_start), hex(context_end)],
        "context_hex": context.hex(),
        "context_ascii": _ascii_context(context),
    }


def _find_offsets(data: bytes, needle: bytes) -> tuple[list[int], bool]:
    """Return at most the configured number of offsets and a truncation flag."""
    offsets: list[int] = []
    start = 0
    truncated = False
    while True:
        position = data.find(needle, start)
        if position < 0:
            break
        if len(offsets) < MAX_MATCHES_PER_TARGET:
            offsets.append(position)
        else:
            truncated = True
            break
        start = position + 1
    return offsets, truncated


def _rip_rows(pe: PE, target: str, target_rva: int) -> list[dict[str, Any]]:
    """Convert raw helper hits to bounded location/unwind metadata only."""
    raw_hits = rip_references(pe, {target_rva}).get(target_rva, [])
    rows: list[dict[str, Any]] = []
    seen: set[int] = set()
    for raw in raw_hits:
        instruction_rva = int(raw["instruction_rva"], 16)
        if instruction_rva in seen:
            continue
        seen.add(instruction_rva)
        if len(rows) >= MAX_RIP_CANDIDATES_PER_TARGET:
            break
        instruction_offset = pe.to_offset(instruction_rva)
        function = pe.function(instruction_rva)
        function_range = None
        function_span = None
        unwind_rva = None
        function_static_range = None
        if function is not None:
            function_start, function_end, unwind = function
            function_range = [hex(function_start), hex(function_end)]
            function_span = function_end - function_start
            unwind_rva = hex(unwind)
            function_static_range = [hex(pe.base + function_start), hex(pe.base + function_end)]
        row: dict[str, Any] = {
            "target": target,
            "target_rva": hex(target_rva),
            "target_static_va": hex(pe.base + target_rva),
            "instruction_rva": hex(instruction_rva),
            "instruction_static_va": hex(pe.base + instruction_rva),
            "instruction_file_offset": (
                None if instruction_offset is None else hex(instruction_offset)
            ),
            "raw_window_hex": (
                None
                if instruction_offset is None
                else pe.data[instruction_offset : instruction_offset + 16].hex()
            ),
            "candidate_function_range_rva": function_range,
            "candidate_function_range_static_va": function_static_range,
            "unwind_info_rva": unwind_rva,
            "function_span_bytes": function_span,
            "function_span_under_0x6000": (
                None if function_span is None else function_span < MAX_FUNCTION_SPAN_BYTES
            ),
            "priority": (
                "preferred_bounded_function"
                if function_span is not None and function_span < MAX_FUNCTION_SPAN_BYTES
                else "large_or_unresolved_unwind_function_candidate"
            ),
            "evidence": "ordinary_static_raw_rip_relative_byte_pattern_candidate_no_disassembly",
        }
        rows.append(row)
    return rows


def build_report(exe_path: Path) -> dict[str, Any]:
    check_memory_budget()
    size = exe_path.stat().st_size
    if size > MAX_EXE_BYTES:
        raise ValueError(f"refusing executable larger than {MAX_EXE_BYTES} bytes")
    if size != EXPECTED_EXE_BYTES:
        raise ValueError(f"unexpected executable size: {size}")
    sha256 = _sha256(exe_path)
    if sha256 != EXPECTED_EXE_SHA256:
        raise ValueError("executable SHA-256 does not match the fixed 1.37.4 build")
    pe = PE(exe_path)
    if pe.base != EXPECTED_IMAGE_BASE:
        raise ValueError(f"unexpected PE image base: {hex(pe.base)}")
    data = pe.data
    exact_matches: list[dict[str, Any]] = []
    substring_matches: list[dict[str, Any]] = []
    target_summary: list[dict[str, Any]] = []
    rip_matches: list[dict[str, Any]] = []
    for target in TARGETS:
        needle = target.encode("ascii")
        offsets, truncated = _find_offsets(data, needle)
        exact_for_target: list[dict[str, Any]] = []
        substring_for_target: list[dict[str, Any]] = []
        for file_offset in offsets:
            end = file_offset + len(needle)
            prefix = data[file_offset - 1] if file_offset else None
            suffix = data[end] if end < len(data) else None
            exact = not _identifier_byte(prefix) and suffix == 0
            row = _string_row(pe, data, target, file_offset, needle, exact)
            if exact:
                exact_for_target.append(row)
                exact_matches.append(row)
            else:
                substring_for_target.append(row)
                substring_matches.append(row)
        target_summary.append(
            {
                "target": target,
                "occurrences_considered": len(offsets),
                "scan_truncated_at_limit": truncated,
                "exact_nul_count": len(exact_for_target),
                "substring_candidate_count": len(substring_for_target),
            }
        )
        for row in exact_for_target:
            rva_text = row.get("rva")
            if rva_text is None:
                continue
            target_rva = int(rva_text, 16)
            rows = _rip_rows(pe, target, target_rva)
            row["rip_candidate_count"] = len(rows)
            row["rip_candidates"] = rows
            rip_matches.extend(rows)
    check_memory_budget()
    preferred: list[dict[str, Any]] = []
    seen_preferred: set[tuple[str, str]] = set()
    for row in rip_matches:
        if not row["function_span_under_0x6000"]:
            continue
        key = (row["target"], row["instruction_rva"])
        if key in seen_preferred:
            continue
        seen_preferred.add(key)
        preferred.append(row)
    script_path = Path(__file__).resolve()
    return {
        "schema": "information_domestic_pressure_static_survey_v1",
        "evidence_kind": "ordinary_static_bounded_pe_string_and_rip_survey_not_rea_evidence",
        "analysis": {
            "explicit_targets_only": True,
            "whole_image_disassembly": False,
            "disassembly_performed": False,
            "rea_called": False,
            "runtime_or_rpm": False,
            "process_or_game_access": False,
            "search_encoding": "ASCII",
            "max_context_bytes": MAX_CONTEXT_BYTES,
            "max_matches_per_target": MAX_MATCHES_PER_TARGET,
            "max_rip_candidates_per_target": MAX_RIP_CANDIDATES_PER_TARGET,
            "preferred_function_span_bytes": f"<0x{MAX_FUNCTION_SPAN_BYTES:x}",
            "exact_definition": "target bytes with a non-identifier prefix boundary and an immediate NUL suffix",
            "identifier_prefix_bytes": "ASCII letters, digits, underscore",
            "rip_helper": "work.discover_diplomacy.rip_references raw LEA/MOV byte pattern",
        },
        "exe": {
            "path": str(exe_path.resolve()),
            "sha256": sha256,
            "bytes": size,
            "image_base": hex(pe.base),
        },
        "script": {
            "path": str(script_path),
            "sha256": _sha256(script_path),
        },
        "targets": list(TARGETS),
        "exact_nul_matches": exact_matches,
        "substring_candidates": substring_matches,
        "rip_candidates": rip_matches,
        "preferred_bounded_rip_candidates": preferred,
        "target_summary": target_summary,
        "summary": {
            "exact_nul_match_count": len(exact_matches),
            "substring_candidate_count": len(substring_matches),
            "rip_candidate_count": len(rip_matches),
            "preferred_bounded_rip_candidate_count": len(preferred),
            "targets_without_exact_nul_match": [
                row["target"] for row in target_summary if row["exact_nul_count"] == 0
            ],
        },
        "unresolved": [
            "A string location or raw RIP pattern does not prove a field, balance, getter, formatter, or GUI semantic.",
            "Unwind metadata only bounds a candidate function; no instruction decoding or ABI review was performed.",
            "No runtime value, process identity, module relocation, address validity, scale, or unit was observed.",
            "Substring absence is not evidence that a resource name is absent from all encodings or generated data.",
            "REA evidence and any later runtime observation must be recorded separately from this ordinary survey.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = build_report(args.exe)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists():
        raise FileExistsError(f"refusing to overwrite existing report: {args.output}")
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    args.output.write_text(encoded, encoding="utf-8")
    print(json.dumps({"output": str(args.output.resolve()), **report["summary"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
