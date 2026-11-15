"""Narrow ordinary-PE survey for ``country + 0xEE0`` byte-pattern candidates.

The survey searches only the fixed 1.37.4 executable's ``.text`` section for
the little-endian four-byte pattern ``e0 0e 00 00``.  Each retained raw hit is
bounded to a ``.pdata`` function range when one exists.  The pattern is only a
candidate byte occurrence: this script does not decode instructions, infer a
RIP/disp32 operand, call REA, attach to a process, or read runtime memory.
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

from work.discover_diplomacy import PE, check_memory_budget  # noqa: E402


EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
EXPECTED_EXE_BYTES = 38_463_016
EXPECTED_IMAGE_BASE = 0x140000000
MAX_EXE_BYTES = 64 * 1024 * 1024
MAX_CONTEXT_BYTES = 80
MAX_CANDIDATES = 25
PATTERN = bytes.fromhex("e00e0000")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _section_for_offset(pe: PE, file_offset: int) -> dict[str, Any] | None:
    for section in pe.sections:
        if section["raw"] <= file_offset < section["raw"] + section["size"]:
            return section
    return None


def _hex_range(values: tuple[int, int] | list[int] | None) -> list[str] | None:
    return None if values is None else [hex(value) for value in values]


def _bounded_context(data: bytes, start: int, end: int) -> tuple[int, int, bytes]:
    if end < start or end - start > MAX_CONTEXT_BYTES:
        raise ValueError("candidate context exceeds the bounded context limit")
    width = end - start
    spare = MAX_CONTEXT_BYTES - width
    left = min(start, spare // 2)
    context_start = start - left
    context_end = min(len(data), context_start + MAX_CONTEXT_BYTES)
    if context_end < end:
        context_end = end
        context_start = max(0, context_end - MAX_CONTEXT_BYTES)
    return context_start, context_end, data[context_start:context_end]


def _context_ascii(raw: bytes) -> str:
    return "".join(chr(value) if 32 <= value < 127 else "." for value in raw)


def _candidate(pe: PE, data: bytes, file_offset: int, index: int) -> dict[str, Any]:
    rva = pe.to_rva(file_offset)
    if rva is None:
        raise ValueError(f".text candidate has no RVA: {hex(file_offset)}")
    section = _section_for_offset(pe, file_offset)
    if section is None or section["name"] != ".text":
        raise ValueError("candidate escaped the .text section")
    context_start, context_end, context = _bounded_context(
        data, file_offset, file_offset + len(PATTERN)
    )
    function = pe.function(rva)
    function_range = None
    unwind_rva = None
    if function is not None:
        function_start, function_end, unwind = function
        function_range = (function_start, function_end)
        unwind_rva = hex(unwind)
    context_rva_start = pe.to_rva(context_start)
    context_rva_end = pe.to_rva(context_end - 1)
    return {
        "candidate_index": index,
        "pattern_hex": PATTERN.hex(),
        "file_offset": hex(file_offset),
        "rva": hex(rva),
        "static_va": hex(pe.base + rva),
        "section": section["name"],
        "context_file_offset": [hex(context_start), hex(context_end)],
        "context_rva": (
            None
            if context_rva_start is None or context_rva_end is None
            else [hex(context_rva_start), hex(context_rva_end + 1)]
        ),
        "context_hex": context.hex(),
        "context_ascii": _context_ascii(context),
        "pdata_function_range_rva": _hex_range(function_range),
        "pdata_function_range_static_va": (
            None
            if function_range is None
            else [hex(pe.base + function_range[0]), hex(pe.base + function_range[1])]
        ),
        "pdata_unwind_info_rva": unwind_rva,
        "pdata_function_span_bytes": (
            None if function_range is None else function_range[1] - function_range[0]
        ),
        "mapping_status": (
            "mapped_to_pdata_function"
            if function_range is not None
            else "no_pdata_function_for_rva"
        ),
        "interpretation": (
            "ordinary_static_raw_byte_candidate_only; instruction_boundary_and_disp32_semantics_unresolved"
        ),
    }


def build_report(exe_path: Path) -> dict[str, Any]:
    check_memory_budget()
    exe_path = exe_path.resolve(strict=True)
    size = exe_path.stat().st_size
    if size > MAX_EXE_BYTES:
        raise ValueError(f"refusing executable larger than {MAX_EXE_BYTES} bytes")
    if size != EXPECTED_EXE_BYTES:
        raise ValueError(f"unexpected executable size: {size}")
    exe_sha = _sha256(exe_path)
    if exe_sha != EXPECTED_EXE_SHA256:
        raise ValueError("executable SHA-256 does not match the fixed 1.37.4 build")
    pe = PE(exe_path)
    if pe.base != EXPECTED_IMAGE_BASE:
        raise ValueError(f"unexpected PE image base: {hex(pe.base)}")
    text = next((section for section in pe.sections if section["name"] == ".text"), None)
    if text is None:
        raise ValueError("PE has no .text section")
    text_start = text["raw"]
    text_end = text_start + text["size"]
    data = pe.data
    offsets: list[int] = []
    cursor = text_start
    while True:
        position = data.find(PATTERN, cursor, text_end)
        if position < 0:
            break
        offsets.append(position)
        cursor = position + 1
    candidates = [_candidate(pe, data, offset, index) for index, offset in enumerate(offsets[:MAX_CANDIDATES])]
    check_memory_budget()
    script_path = Path(__file__).resolve()
    return {
        "schema": "information_domestic_pressure_religious_unity_access_candidates_v1",
        "evidence_kind": "ordinary_static_bounded_pe_raw_pattern_and_pdata_mapping_not_rea_evidence",
        "analysis": {
            "target": "country_plus_0xEE0_candidate_disp32",
            "pattern_hex": PATTERN.hex(),
            "search_section": ".text",
            "whole_image_disassembly": False,
            "instruction_decoding": False,
            "rea_called": False,
            "runtime_or_rpm": False,
            "process_or_game_access": False,
            "candidate_limit": MAX_CANDIDATES,
            "context_limit_bytes": MAX_CONTEXT_BYTES,
            "function_mapping": ".pdata PE runtime-function bounds only",
        },
        "exe": {
            "path": str(exe_path),
            "sha256": exe_sha,
            "bytes": size,
            "image_base": hex(pe.base),
        },
        "text_section": {
            "file_offset": [hex(text_start), hex(text_end)],
            "rva": [hex(text["rva"]), hex(text["rva"] + text["size"])],
            "raw_size": text["size"],
            "virtual_size": text["virtual_size"],
        },
        "script": {"path": str(script_path), "sha256": _sha256(script_path)},
        "pattern_hits_total": len(offsets),
        "candidates": candidates,
        "truncated": len(offsets) > MAX_CANDIDATES,
        "unresolved": [
            "The four bytes may be data or an immediate/displacement inside an instruction; no decoding was performed.",
            "A .pdata range bounds a function candidate but does not prove that this byte occurrence is an access to country+0xEE0.",
            "No runtime module relocation, pointer validity, field value, unit, fraction semantics, or getter behavior was observed.",
            "The candidate list is capped at 25 raw hits; omitted hits are not classified.",
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
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output.resolve()), "pattern_hits_total": report["pattern_hits_total"], "candidates": len(report["candidates"])}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
