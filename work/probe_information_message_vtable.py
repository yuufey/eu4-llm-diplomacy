"""Read one bounded static PE window for the battle message vtable candidate.

The probe maps the fixed 1.37.4 executable read-only, hashes it with bounded
streaming reads, and reads exactly 128 bytes beginning at the requested RVA.
It reports the 16 qwords, their PE section/executable status, and any
containing half-open PE ``.pdata`` runtime-function row.  It does not decode
instructions, call REA or game code, attach to a process, or infer that the
window is a complete vtable or that any slot has a semantic role.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import struct
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_EXE_SIZE = 38_463_016
IMAGE_BASE = 0x140000000
VTABLE_RVA = 0x1C426E0
WINDOW_BYTES = 128
SLOT_BYTES = 8
SLOT_COUNT = WINDOW_BYTES // SLOT_BYTES
MAX_EXE_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_BYTES = 1 * 1024 * 1024
DEFAULT_EXE = ROOT / (
    "work/runtime/ghidra-full/"
    "b23fa0e1f698d31b-20261014T054913Z-6dda97/input/eu4.exe"
)
DEFAULT_OUTPUT = ROOT / (
    "work/runtime/information-battle-message-20261025-001/"
    "message-vtable-window-001.json"
)

_IMAGE_SCN_MEM_EXECUTE = 0x20000000


def _hex(value: int | None) -> str | None:
    return None if value is None else hex(value)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _section_record(section: dict[str, Any] | None) -> dict[str, Any] | None:
    if section is None:
        return None
    return {
        "name": section["name"],
        "rva": _hex(section["rva"]),
        "virtual_size": section["virtual_size"],
        "raw_file_offset": _hex(section["raw_pointer"]),
        "raw_size": section["raw_size"],
        "characteristics": _hex(section["characteristics"]),
        "executable": bool(section["characteristics"] & _IMAGE_SCN_MEM_EXECUTE),
    }


def _parse_pe(mm: mmap.mmap) -> dict[str, Any]:
    size = mm.size()
    if size > MAX_EXE_BYTES:
        raise ValueError(f"executable exceeds bounded size: {size} > {MAX_EXE_BYTES}")
    if size < 0x40 or bytes(mm[:2]) != b"MZ":
        raise ValueError("target is not an MZ executable")
    pe_offset = struct.unpack_from("<I", mm, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset + 24 > size:
        raise ValueError("invalid PE header offset")
    if bytes(mm[pe_offset : pe_offset + 4]) != b"PE\0\0":
        raise ValueError("invalid PE signature")
    machine, section_count, _timestamp, _symptr, _symbols, optional_size, characteristics = struct.unpack_from(
        "<HHIIIHH", mm, pe_offset + 4
    )
    if machine != 0x8664 or not 1 <= section_count <= 96:
        raise ValueError("target is not bounded x86-64 PE")
    optional = pe_offset + 24
    if optional + optional_size > size or optional_size < 32:
        raise ValueError("PE optional header exceeds file")
    magic = struct.unpack_from("<H", mm, optional)[0]
    if magic != 0x20B:
        raise ValueError("target is not PE32+")
    image_base = struct.unpack_from("<Q", mm, optional + 24)[0]
    sections_offset = optional + optional_size
    if sections_offset + section_count * 40 > size:
        raise ValueError("PE section table exceeds file")
    sections: list[dict[str, Any]] = []
    for index in range(section_count):
        offset = sections_offset + index * 40
        name = bytes(mm[offset : offset + 8]).split(b"\0", 1)[0].decode("ascii", errors="replace")
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", mm, offset + 8
        )
        section_characteristics = struct.unpack_from("<I", mm, offset + 36)[0]
        if raw_pointer + raw_size > size:
            raise ValueError(f"PE section exceeds file: {name}")
        sections.append(
            {
                "name": name,
                "rva": virtual_address,
                "virtual_size": virtual_size,
                "raw_size": raw_size,
                "raw_pointer": raw_pointer,
                "characteristics": section_characteristics,
            }
        )
    return {
        "machine": machine,
        "characteristics": characteristics,
        "section_count": section_count,
        "image_base": image_base,
        "sections": sections,
    }


def _section_for_rva(pe: dict[str, Any], rva: int, size: int = 1) -> dict[str, Any] | None:
    if rva < 0 or size < 0:
        return None
    for section in pe["sections"]:
        start = section["rva"]
        end = start + section["raw_size"]
        if start <= rva and rva + size <= end:
            return section
    return None


def _rva_to_file_offset(pe: dict[str, Any], rva: int, size: int) -> int | None:
    section = _section_for_rva(pe, rva, size)
    if section is None:
        return None
    return section["raw_pointer"] + (rva - section["rva"])


def _pdata_rows(mm: mmap.mmap, pe: dict[str, Any]) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    section = next((item for item in pe["sections"] if item["name"] == ".pdata"), None)
    if section is None:
        return None, []
    rows: list[dict[str, Any]] = []
    raw_start = section["raw_pointer"]
    raw_end = raw_start + section["raw_size"]
    usable_end = raw_end - ((raw_end - raw_start) % 12)
    for file_offset in range(raw_start, usable_end, 12):
        start_rva, end_rva, unwind_rva = struct.unpack_from("<III", mm, file_offset)
        if 0 < start_rva < end_rva:
            rows.append(
                {
                    "start_rva": start_rva,
                    "end_rva_exclusive": end_rva,
                    "unwind_rva": unwind_rva,
                    "file_offset": file_offset,
                    "raw_hex": bytes(mm[file_offset : file_offset + 12]).hex(),
                }
            )
    return section, rows


def _pdata_match(rows: list[dict[str, Any]], target_rva: int | None) -> dict[str, Any] | None:
    if target_rva is None:
        return None
    for row in rows:
        if row["start_rva"] <= target_rva < row["end_rva_exclusive"]:
            return {
                "source": "PE .pdata IMAGE_RUNTIME_FUNCTION_ENTRY",
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


def _target_record(pe: dict[str, Any], rows: list[dict[str, Any]], raw_value: int) -> dict[str, Any]:
    target_rva = raw_value - IMAGE_BASE if raw_value >= IMAGE_BASE else None
    target_section = _section_for_rva(pe, target_rva) if target_rva is not None else None
    file_offset = _rva_to_file_offset(pe, target_rva, 1) if target_rva is not None else None
    return {
        "raw_qword_hex": raw_value.to_bytes(8, "little", signed=False).hex(),
        "target_va": _hex(raw_value) if target_rva is not None else None,
        "target_rva": _hex(target_rva),
        "file_backed": file_offset is not None,
        "file_offset": _hex(file_offset),
        "section": _section_record(target_section),
        "executable": bool(target_section and target_section["characteristics"] & _IMAGE_SCN_MEM_EXECUTE),
        "pdata": _pdata_match(rows, target_rva),
    }


def probe(executable: Path) -> dict[str, Any]:
    executable = executable.resolve()
    before_size = executable.stat().st_size
    if before_size != EXPECTED_EXE_SIZE:
        raise ValueError(f"unexpected executable size: {before_size} != {EXPECTED_EXE_SIZE}")
    sha_before = _sha256_file(executable)
    if sha_before != EXPECTED_EXE_SHA256:
        raise ValueError(f"unexpected executable SHA-256: {sha_before}")
    with executable.open("rb") as handle:
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            pe = _parse_pe(mm)
            if pe["image_base"] != IMAGE_BASE:
                raise ValueError(f"unexpected PE image base: {pe['image_base']:#x}")
            window_offset = _rva_to_file_offset(pe, VTABLE_RVA, WINDOW_BYTES)
            window_section = _section_for_rva(pe, VTABLE_RVA, WINDOW_BYTES)
            if window_offset is None or window_section is None:
                raise ValueError("vtable window is not fully file-backed")
            raw_window = bytes(mm[window_offset : window_offset + WINDOW_BYTES])
            if len(raw_window) != WINDOW_BYTES:
                raise ValueError("short vtable window")
            pdata_section, pdata_rows = _pdata_rows(mm, pe)
            slots: list[dict[str, Any]] = []
            for index, raw_value in enumerate(struct.unpack("<16Q", raw_window)):
                slot_rva = VTABLE_RVA + index * SLOT_BYTES
                slot_section = _section_for_rva(pe, slot_rva, SLOT_BYTES)
                slots.append(
                    {
                        "index": index,
                        "slot_rva": _hex(slot_rva),
                        "slot_va": _hex(IMAGE_BASE + slot_rva),
                        "slot_file_offset": _hex(window_offset + index * SLOT_BYTES),
                        "slot_raw_qword_hex": raw_value.to_bytes(8, "little", signed=False).hex(),
                        "slot_location": {
                            "file_backed": slot_section is not None,
                            "section": _section_record(slot_section),
                            "executable": bool(slot_section and slot_section["characteristics"] & _IMAGE_SCN_MEM_EXECUTE),
                        },
                        "target": _target_record(pe, pdata_rows, raw_value),
                    }
                )
            after_size = executable.stat().st_size
    if after_size != EXPECTED_EXE_SIZE or after_size != before_size:
        raise ValueError("executable size changed while being read")
    sha_after = _sha256_file(executable)
    if sha_after != sha_before or sha_after != EXPECTED_EXE_SHA256:
        raise ValueError("executable SHA changed while being read")
    script_path = Path(__file__).resolve()
    return {
        "schema": "information_battle_message_vtable_window_v1",
        "status": "observed_static_pe_window",
        "evidence_kind": "ordinary_PE_bytes_and_pdata_metadata",
        "read_only": True,
        "runtime_observed": False,
        "native_function_invoked": False,
        "target": {
            "path": str(executable),
            "size_bytes": after_size,
            "sha256": sha_after,
            "image_base": _hex(pe["image_base"]),
            "fixed_sha_guard": True,
            "fixed_size_guard": True,
            "size_before_read": before_size,
            "size_after_read": after_size,
            "sha_before_read": sha_before,
            "sha_after_read": sha_after,
        },
        "window": {
            "rva": _hex(VTABLE_RVA),
            "va": _hex(IMAGE_BASE + VTABLE_RVA),
            "file_offset": _hex(window_offset),
            "bytes": WINDOW_BYTES,
            "raw_hex": raw_window.hex(),
            "sha256": hashlib.sha256(raw_window).hexdigest(),
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
            "probe_script": str(script_path),
            "probe_script_sha256": _sha256_file(script_path),
            "probe_script_size_bytes": script_path.stat().st_size,
            "method": "stream-hash plus read-only mmap PE header/section/.pdata parsing and one 128-byte window",
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
    parser.add_argument("--executable", type=Path, default=DEFAULT_EXE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    report = probe(args.executable)
    encoded = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise ValueError(f"output exceeds bounded size: {len(encoded)} > {MAX_OUTPUT_BYTES}")
    if args.output.exists():
        raise FileExistsError(f"refusing to overwrite existing output: {args.output}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(encoded)
    print(json.dumps({
        "output": str(args.output),
        "output_sha256": hashlib.sha256(encoded).hexdigest(),
        "window_sha256": report["window"]["sha256"],
        "slots": len(report["slots"]),
        "pdata_rows": report["pdata"]["row_count_observed"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
