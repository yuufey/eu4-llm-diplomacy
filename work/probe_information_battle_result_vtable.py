"""Read-only bounded PE window probe for the naval/battle result vtable candidate.

This probe reads exactly one 128-byte window from the fixed 1.37.4 executable.
It records pointer values, PE section membership, and the bounded runtime-function
range supplied by the PE ``.pdata`` table.  It does not disassemble, attach to a
process, call a game function, or infer vtable length or slot semantics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any

from discover_diplomacy import PE, check_memory_budget


TARGET_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
TARGET_SIZE = 38_463_016
IMAGE_BASE = 0x140000000
VTABLE_RVA = 0x1C448D0
WINDOW_BYTES = 128
SLOT_BYTES = 8
SLOT_COUNT = WINDOW_BYTES // SLOT_BYTES
DEFAULT_EXE = Path(
    "work/runtime/ghidra-full/"
    "b23fa0e1f698d31b-20261014T054913Z-6dda97/input/eu4.exe"
)
DEFAULT_OUTPUT = Path(
    "work/runtime/information-battles-20261025-001/"
    "battle-stage/result-vtable-window-001.json"
)


def _hex(value: int | None) -> str | None:
    return None if value is None else hex(value)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _section_for_rva(pe: PE, rva: int, size: int = 1) -> dict[str, Any] | None:
    """Return the raw-backed section only when the complete span is backed."""
    if rva < 0 or size < 0:
        return None
    end = rva + size
    for section in pe.sections:
        start = section["rva"]
        raw_end = start + section["size"]
        if start <= rva and end <= raw_end:
            return section
    return None


def _section_record(section: dict[str, Any] | None) -> dict[str, Any] | None:
    if section is None:
        return None
    return {
        "name": section["name"],
        "rva": _hex(section["rva"]),
        "virtual_size": section["virtual_size"],
        "raw_file_offset": _hex(section["raw"]),
        "raw_size": section["size"],
        "flags": _hex(section["flags"]),
        "executable": bool(section["flags"] & 0x20000000),
    }


def _pdata_rows(pe: PE) -> list[dict[str, Any]]:
    """Read PE runtime-function rows without decoding any instructions."""
    section = next((s for s in pe.sections if s["name"] == ".pdata"), None)
    if section is None:
        return []
    rows: list[dict[str, Any]] = []
    limit = section["raw"] + section["size"]
    for file_offset in range(section["raw"], limit - 11, 12):
        start, end, unwind = struct.unpack_from("<III", pe.data, file_offset)
        if 0 < start < end:
            rows.append(
                {
                    "start_rva": start,
                    "end_rva_exclusive": end,
                    "unwind_rva": unwind,
                    "file_offset": file_offset,
                    "raw_hex": pe.data[file_offset:file_offset + 12].hex(),
                }
            )
    return rows


def _pdata_match(pe: PE, pdata_rows: list[dict[str, Any]], target_rva: int) -> dict[str, Any] | None:
    """Return the containing .pdata row, preserving its half-open range."""
    if target_rva < 0:
        return None
    for row in pdata_rows:
        if row["start_rva"] <= target_rva < row["end_rva_exclusive"]:
            return {
                "source": "PE .pdata runtime-function row",
                "range_kind": "half_open",
                "start_rva": _hex(row["start_rva"]),
                "end_rva_exclusive": _hex(row["end_rva_exclusive"]),
                "start_va": _hex(IMAGE_BASE + row["start_rva"]),
                "end_va_exclusive": _hex(IMAGE_BASE + row["end_rva_exclusive"]),
                "unwind_rva": _hex(row["unwind_rva"]),
                "unwind_va": _hex(IMAGE_BASE + row["unwind_rva"]),
                "entry_file_offset": _hex(row["file_offset"]),
                "entry_raw_hex": row["raw_hex"],
            }
    return None


def _target_record(pe: PE, pdata_rows: list[dict[str, Any]], raw_value: int) -> dict[str, Any]:
    target_rva = raw_value - IMAGE_BASE if raw_value >= IMAGE_BASE else None
    target_section = _section_for_rva(pe, target_rva) if target_rva is not None else None
    file_offset = pe.to_offset(target_rva) if target_rva is not None else None
    executable = (
        bool(target_section and target_section["flags"] & 0x20000000)
        if target_section is not None
        else False
    )
    return {
        "raw_qword_hex": raw_value.to_bytes(8, "little", signed=False).hex(),
        "target_va": _hex(raw_value),
        "target_rva": _hex(target_rva),
        "file_backed": file_offset is not None,
        "file_offset": _hex(file_offset),
        "executable": executable,
        "section": _section_record(target_section),
        "pdata": _pdata_match(pe, pdata_rows, target_rva) if target_rva is not None else None,
    }


def probe(exe: Path) -> dict[str, Any]:
    before_size = exe.stat().st_size
    if before_size != TARGET_SIZE:
        raise ValueError(f"unexpected executable size: {before_size} != {TARGET_SIZE}")
    pe = PE(exe)
    after_size = exe.stat().st_size
    if len(pe.data) != TARGET_SIZE or after_size != TARGET_SIZE:
        raise ValueError("executable changed size while being read")
    actual_sha = _sha256(pe.data)
    if actual_sha != TARGET_SHA256:
        raise ValueError(f"unexpected executable SHA-256: {actual_sha}")
    if pe.base != IMAGE_BASE:
        raise ValueError(f"unexpected PE image base: {hex(pe.base)}")

    window_offset = pe.to_offset(VTABLE_RVA)
    window_section = _section_for_rva(pe, VTABLE_RVA, WINDOW_BYTES)
    if window_offset is None or window_section is None:
        raise ValueError("vtable window is not fully file-backed")
    raw_window = pe.data[window_offset:window_offset + WINDOW_BYTES]
    if len(raw_window) != WINDOW_BYTES:
        raise ValueError("short vtable window")

    pdata_section = next((s for s in pe.sections if s["name"] == ".pdata"), None)
    pdata_rows = _pdata_rows(pe)
    slots: list[dict[str, Any]] = []
    for index, raw_value in enumerate(struct.unpack("<16Q", raw_window)):
        slot_rva = VTABLE_RVA + index * SLOT_BYTES
        slots.append(
            {
                "index": index,
                "slot_rva": _hex(slot_rva),
                "slot_va": _hex(IMAGE_BASE + slot_rva),
                "slot_file_offset": _hex(window_offset + index * SLOT_BYTES),
                "slot_raw_qword_hex": raw_value.to_bytes(8, "little", signed=False).hex(),
                "slot_location": {
                    "file_backed": _section_for_rva(pe, slot_rva, SLOT_BYTES) is not None,
                    "executable": bool(window_section["flags"] & 0x20000000),
                    "section": _section_record(window_section),
                },
                "target": _target_record(pe, pdata_rows, raw_value),
            }
        )

    return {
        "schema": "information_battle_result_vtable_window_v1",
        "status": "observed_static_pe_window",
        "evidence_kind": "ordinary_PE_bytes_and_pdata_metadata",
        "target": {
            "path": str(exe.resolve()),
            "size_bytes": len(pe.data),
            "sha256": actual_sha,
            "image_base": _hex(pe.base),
            "fixed_sha_guard": True,
            "fixed_size_guard": True,
            "size_before_read": before_size,
            "size_after_read": after_size,
        },
        "window": {
            "rva": _hex(VTABLE_RVA),
            "va": _hex(IMAGE_BASE + VTABLE_RVA),
            "file_offset": _hex(window_offset),
            "bytes": WINDOW_BYTES,
            "raw_hex": raw_window.hex(),
            "sha256": _sha256(raw_window),
            "section": _section_record(window_section),
        },
        "slots": slots,
        "pdata": {
            "section": _section_record(pdata_section),
            "row_count_observed": len(pdata_rows),
            "matching_is_bounded_half_open_containment": True,
            "instructions_decoded": False,
        },
        "layout_limits": {
            "window_bytes": WINDOW_BYTES,
            "slot_bytes": SLOT_BYTES,
            "slot_count_in_window": SLOT_COUNT,
            "vtable_total_length_known": False,
            "all_slots_asserted_same_table": False,
            "slot_semantics_inferred": False,
        },
        "source": {
            "probe_script": str(Path(__file__).resolve()),
            "probe_script_sha256": _sha256(Path(__file__).read_bytes()),
            "probe_script_size_bytes": Path(__file__).stat().st_size,
            "pe_helper": "work/discover_diplomacy.py:PE",
            "pe_helper_sha256": _sha256((Path(__file__).resolve().parent / "discover_diplomacy.py").read_bytes()),
        },
        "limitations": [
            "Only the fixed 128-byte window was read; the vtable total length is unknown.",
            "The 16 qwords are window entries only; no claim is made that all belong to one vtable.",
            "PE .pdata containment gives a bounded half-open runtime-function range, not function semantics.",
            "No instruction bytes were disassembled and no slot role, ABI, ownership, or lifecycle was inferred.",
            "This is ordinary static PE evidence, not runtime observation or REA evidence.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, default=DEFAULT_EXE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    check_memory_budget()
    report = probe(args.exe)
    check_memory_budget()
    if args.output.exists():
        raise FileExistsError(f"refusing to overwrite existing output: {args.output}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "output_sha256": _sha256(args.output.read_bytes()),
        "window_sha256": report["window"]["sha256"],
        "slots": len(report["slots"]),
        "pdata_rows": report["pdata"]["row_count_observed"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
