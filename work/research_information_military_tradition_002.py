"""Narrow ordinary-PE follow-up for the army_tradition property.

This is source002 for Batch49.  It deliberately follows only the field
registration tail already identified in source001, the static property table,
and the table's +0x10 getter.  It does not attach to the game, call native
code, use RPM, or decode any of the previously reported large functions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE, check_memory_budget, make_disassembler  # noqa: E402
from work.local_config import game_exe  # noqa: E402
from work.research_information_branch_inputs import _decode_range  # noqa: E402


EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
EXPECTED_EXE_BYTES = 38_463_016
EXPECTED_IMAGE_BASE = 0x140000000
MAX_EXE_BYTES = 64 * 1024 * 1024
MAX_SINGLE_DECODE_BYTES = 4 * 1024
MAX_TOTAL_DECODE_BYTES = 8 * 1024

REGISTRATION_RANGE = (0x6A80BA, 0x6A80F0, "army_tradition_registration_tail")
GETTER_RANGE = (0x6E01B0, 0x6E01BD, "army_tradition_vtable_plus_10_getter")
VTABLE_RVA = 0x1CA0240
VTABLE_READ_BYTES = 0x40
GETTER_RVA = 0x6E01B0
GETTER_SLOT = 0x10
COUNTRY_OFFSET = 0xE40

SOURCE001 = ROOT / "work" / "runtime" / "information-military-quality-20261027-001" / "tradition-source-001.json"


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _sha256_path_if_present(path: Path) -> str | None:
    return _sha256_file(path) if path.is_file() else None


def _location(pe: PE, rva: int) -> dict[str, Any]:
    offset = pe.to_offset(rva)
    section = None
    if offset is not None:
        for candidate in pe.sections:
            if candidate["raw"] <= offset < candidate["raw"] + candidate["size"]:
                section = candidate["name"]
                break
    return {
        "rva": hex(rva),
        "file_offset": None if offset is None else hex(offset),
        "static_va": hex(pe.base + rva),
        "section": section,
    }


def _decode(pe: PE, md, begin: int, end: int) -> list[dict[str, Any]]:
    check_memory_budget()
    if end <= begin or end - begin > MAX_SINGLE_DECODE_BYTES:
        raise ValueError(f"decode range exceeds bound: {begin:#x}:{end:#x}")
    return _decode_range(pe, md, begin, end)


def _range_record(pe: PE, rows: list[dict[str, Any]], begin: int, end: int, label: str) -> dict[str, Any]:
    raw = pe.bytes_at(begin, end - begin)
    if len(raw) != end - begin:
        raise ValueError(f"range not backed by PE: {begin:#x}:{end:#x}")
    return {
        "label": label,
        "rva_range": [hex(begin), hex(end)],
        "static_va_range": [hex(pe.base + begin), hex(pe.base + end)],
        "bytes": len(raw),
        "sha256": _sha256_bytes(raw),
        "pdata_function": None if pe.function(begin) is None else [hex(pe.function(begin)[0]), hex(pe.function(begin)[1])],
        "instruction_count": len(rows),
    }


def _selected(rows: list[dict[str, Any]], addresses: list[int]) -> list[dict[str, Any]]:
    by_rva = {int(row["rva"], 16): row for row in rows}
    return [by_rva.get(address, {"rva": hex(address), "decode_missing": True}) for address in addresses]


def _vtable_entries(pe: PE, raw: bytes) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for slot in range(0, len(raw), 8):
        value = struct.unpack_from("<Q", raw, slot)[0]
        item: dict[str, Any] = {
            "slot": hex(slot),
            "bytes": raw[slot : slot + 8].hex(),
            "static_va": hex(value),
        }
        if pe.base <= value < pe.base + len(pe.data):
            target_rva = value - pe.base
            item["target_rva"] = hex(target_rva)
            item["target_location"] = _location(pe, target_rva)
        else:
            item["target_rva"] = None
            item["target_location"] = None
        entries.append(item)
    return entries


def build_report() -> dict[str, Any]:
    path = game_exe()
    size = path.stat().st_size
    if size > MAX_EXE_BYTES:
        raise ValueError(f"refusing executable larger than {MAX_EXE_BYTES} bytes")
    binary_sha = _sha256_file(path)
    if binary_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"unexpected executable SHA-256: {binary_sha}")
    if size != EXPECTED_EXE_BYTES:
        raise ValueError(f"unexpected executable size: {size}")

    pe = PE(path)
    if pe.base != EXPECTED_IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.base:#x}")
    md, decoder = make_disassembler(ROOT / "work" / "deps")

    reg_begin, reg_end, reg_label = REGISTRATION_RANGE
    get_begin, get_end, get_label = GETTER_RANGE
    reg_rows = _decode(pe, md, reg_begin, reg_end)
    getter_rows = _decode(pe, md, get_begin, get_end)
    planned_decode = (reg_end - reg_begin) + (get_end - get_begin)
    if planned_decode > MAX_TOTAL_DECODE_BYTES:
        raise ValueError(f"planned decode exceeds total bound: {planned_decode}")

    vtable_raw = pe.bytes_at(VTABLE_RVA, VTABLE_READ_BYTES)
    if len(vtable_raw) != VTABLE_READ_BYTES:
        raise ValueError("vtable window is not fully backed by PE")
    entries = _vtable_entries(pe, vtable_raw)
    getter_entry = entries[GETTER_SLOT // 8]
    if getter_entry.get("target_rva") != hex(GETTER_RVA):
        raise ValueError(f"unexpected vtable +0x10 target: {getter_entry.get('target_rva')}")

    source001_sha = _sha256_path_if_present(SOURCE001)
    return {
        "schema": "information_military_quality_static_source_v2",
        "status": "partial",
        "source_kind": "ordinary_pe_bounded_static",
        "scope": "N03.army_tradition_and_professionalism",
        "supersedes": None,
        "binary": {
            "path": str(path),
            "size": size,
            "sha256": binary_sha,
            "image_base": hex(pe.base),
            "version_pin": "EU4 1.37.4",
        },
        "method": {
            "game_or_rpm": False,
            "rea": False,
            "native_calls": False,
            "decoder": "capstone" if decoder is not None else "objdump_bounded_fallback",
            "follow_up_scope": "only registration tail, static property table, and its vtable +0x10 getter",
            "decode_limits": {
                "max_single_bytes": MAX_SINGLE_DECODE_BYTES,
                "max_total_bytes": MAX_TOTAL_DECODE_BYTES,
                "planned_total_bytes": planned_decode,
            },
            "prior_large_functions_not_redecoded": True,
        },
        "prior_source": {
            "path": str(SOURCE001),
            "sha256": source001_sha,
            "role": "source001 retained unchanged; its bounded professionalism display rows are cited for the correction below",
        },
        "bounded_ranges": [
            _range_record(pe, reg_rows, reg_begin, reg_end, reg_label),
            {
                "label": "army_tradition_static_property_vtable_bytes",
                "rva_range": [hex(VTABLE_RVA), hex(VTABLE_RVA + VTABLE_READ_BYTES)],
                "static_va_range": [hex(pe.base + VTABLE_RVA), hex(pe.base + VTABLE_RVA + VTABLE_READ_BYTES)],
                "bytes": len(vtable_raw),
                "sha256": _sha256_bytes(vtable_raw),
                "decoded": False,
            },
            _range_record(pe, getter_rows, get_begin, get_end, get_label),
        ],
        "selected_instructions": {
            "registration_tail": _selected(reg_rows, [0x6A80BA, 0x6A80C1, 0x6A80C8, 0x6A80CD, 0x6A80D4, 0x6A80DB, 0x6A80E2, 0x6A80E9]),
            "getter": _selected(getter_rows, [0x6E01B0, 0x6E01B7, 0x6E01B9, 0x6E01BC]),
        },
        "static_property_table": {
            "property_object": _location(pe, VTABLE_RVA),
            "raw_hex": vtable_raw.hex(),
            "raw_sha256": _sha256_bytes(vtable_raw),
            "entries": entries,
            "selected_getter": {
                "slot": hex(GETTER_SLOT),
                "target": _location(pe, GETTER_RVA),
                "target_static_va": hex(pe.base + GETTER_RVA),
                "target_rva": hex(GETTER_RVA),
                "pdata_function": None,
                "bounded_code_ends_at_ret": True,
            },
        },
        "field_findings": {
            "army_tradition": {
                "field_literal": "army_tradition",
                "registration": {
                    "status": "closed_static_property_object_and_vtable_slot",
                    "key_registration_rva": hex(0x6A80BA),
                    "key_target_rva": hex(0x1CA8C78),
                    "property_object": _location(pe, VTABLE_RVA),
                    "lea_static_property": "LEA RAX,[RIP+0x15f816c] => 0x141ca0240",
                    "stack_aliases": [
                        "MOV [RBP+0x550],RAX at 0x6a80d4",
                        "LEA RAX,[RBP+0x550] at 0x6a80db",
                        "MOV [RBP+0x588],RAX at 0x6a80e2",
                        "MOV [RBP+0x590],RBX at 0x6a80e9",
                    ],
                    "vtable_slot_0x10": {
                        "rva": hex(GETTER_RVA),
                        "static_va": hex(pe.base + GETTER_RVA),
                        "bytes": vtable_raw[GETTER_SLOT : GETTER_SLOT + 8].hex(),
                    },
                },
                "country_storage_getter": {
                    "status": "closed_as_direct_32bit_cache_copy_static",
                    "getter_rva": hex(GETTER_RVA),
                    "abi_input_register": "R8",
                    "abi_output_register": "RDX",
                    "source_expression": "DWORD PTR [R8+0xe40]",
                    "destination_expression": "DWORD PTR [RDX]",
                    "return_expression": "RAX=RDX",
                    "storage_offset": hex(COUNTRY_OFFSET),
                    "width": "32-bit load and 32-bit store",
                    "signedness": "raw 32-bit bit pattern; this getter performs no signed comparison or extension",
                    "arithmetic": "none; no DIV/IDIV, multiply, shift, clamp, or scale operation in the bounded getter",
                    "unit_scale": {
                        "status": "unknown",
                        "reason": "The getter is a direct cache copy. No bounded serializer/threshold or numeric formatter was followed in this source002 budget.",
                    },
                    "runtime_identity": {
                        "status": "static_abi_only",
                        "reason": "R8 is the getter's input object in static code; no runtime observation proves that it is the current FRA country object for a particular call.",
                    },
                },
            },
            "professionalism": {
                "field_literal": "army_professionalism",
                "source001_text_correction": {
                    "status": "corrected_in_source002_without_modifying_source001",
                    "prior_report_path": "field_findings.professionalism.numeric_display_paths.ratio_path",
                    "prior_report_sha256": source001_sha,
                    "evidence_rvas": [hex(0xD03104), hex(0xD03108), hex(0xD03110), hex(0xD03117), hex(0xD0311C)],
                    "exact_instruction_order_from_source001_rows": [
                        "MOV RAX,QWORD PTR [RSI+0x68]",
                        "IMUL RAX,QWORD PTR [RIP+0x12ceb88] (constant 0x320000 / 3276800)",
                        "SAR RAX,0xf",
                        "CVTSI2SD XMM2,RAX",
                        "MULSD XMM2,XMM6 (reciprocal 1/32768)",
                    ],
                    "correct_formula": "q64 = low64_signed(signed_qword(raw) * 0x320000); q64 = arithmetic_shift_right(q64, 15); displayed = double(signed_qword(q64)) / 32768.0",
                    "why_simple_division_is_wrong": "The multiply-and-shift precedes the reciprocal scaling; replacing the path with raw/32768 drops the 0x320000 multiplier and changes the result.",
                    "no_new_decode": True,
                },
            },
        },
        "conclusion": {
            "army_tradition": "static property registration now reaches a direct 32-bit cache getter at country-object offset 0xe40; runtime FRA identity and public unit scale remain unobserved",
            "professionalism": "source001 ratio-path wording requires the exact multiply-by-0x320000, arithmetic-shift-15, then reciprocal-32768 sequence recorded above",
            "publication": "do_not_mark_available_or_complete_true_from_static_source002_alone",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "work" / "runtime" / "information-military-quality-20261027-001" / "tradition-source-002.json",
    )
    args = parser.parse_args()
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "status": report["status"], "planned_total_decode_bytes": report["method"]["decode_limits"]["planned_total_bytes"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
