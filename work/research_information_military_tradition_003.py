"""Bounded writer and unit evidence for the army_tradition country field.

This source003 follows only the small setter/additive wrapper and one already
identified compiled condition.  It keeps the getter evidence in source002 and
does not decode the large UI or descriptor functions again.
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
MAX_TOTAL_DECODE_BYTES = 4 * 1024

SETTER_RANGE = (0x357200, 0x3572C3, "army_tradition_setter_and_clamp")
ADDER_RANGE = (0x357390, 0x3573B4, "army_tradition_additive_wrapper")
CONDITION_RANGE = (0x2DF50E, 0x2DF546, "army_tradition_compiled_condition_slice")

SOURCE002 = ROOT / "work" / "runtime" / "information-military-quality-20261027-001" / "tradition-source-002.json"
SOURCE001 = ROOT / "work" / "runtime" / "information-military-quality-20261027-001" / "tradition-source-001.json"


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


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
    function = pe.function(begin)
    return {
        "label": label,
        "rva_range": [hex(begin), hex(end)],
        "static_va_range": [hex(pe.base + begin), hex(pe.base + end)],
        "bytes": len(raw),
        "sha256": _sha256_bytes(raw),
        "pdata_function": None if function is None else [hex(function[0]), hex(function[1])],
        "instruction_count": len(rows),
    }


def _raw_data(pe: PE, rva: int, size: int, label: str) -> dict[str, Any]:
    raw = pe.bytes_at(rva, size)
    if len(raw) != size:
        raise ValueError(f"data range not backed by PE: {rva:#x}:{rva + size:#x}")
    ascii_text = "".join(chr(value) if 32 <= value < 127 else "." for value in raw)
    return {
        "label": label,
        "location": _location(pe, rva),
        "rva_range": [hex(rva), hex(rva + size)],
        "bytes": size,
        "sha256": _sha256_bytes(raw),
        "raw_hex": raw.hex(),
        "ascii_projection": ascii_text,
    }


def _selected(rows: list[dict[str, Any]], addresses: list[int]) -> list[dict[str, Any]]:
    by_rva = {int(row["rva"], 16): row for row in rows}
    return [by_rva.get(address, {"rva": hex(address), "decode_missing": True}) for address in addresses]


def build_report() -> dict[str, Any]:
    path = game_exe()
    size = path.stat().st_size
    if size > MAX_EXE_BYTES:
        raise ValueError(f"refusing executable larger than {MAX_EXE_BYTES} bytes")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    binary_sha = digest.hexdigest()
    if binary_sha != EXPECTED_EXE_SHA256 or size != EXPECTED_EXE_BYTES:
        raise ValueError(f"unexpected executable identity: {size} bytes {binary_sha}")
    pe = PE(path)
    if pe.base != EXPECTED_IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.base:#x}")
    md, decoder = make_disassembler(ROOT / "work" / "deps")

    setter_rows = _decode(pe, md, SETTER_RANGE[0], SETTER_RANGE[1])
    adder_rows = _decode(pe, md, ADDER_RANGE[0], ADDER_RANGE[1])
    condition_rows = _decode(pe, md, CONDITION_RANGE[0], CONDITION_RANGE[1])
    planned_decode = sum(end - begin for begin, end, _ in (SETTER_RANGE, ADDER_RANGE, CONDITION_RANGE))
    if planned_decode > MAX_TOTAL_DECODE_BYTES:
        raise ValueError(f"planned decode exceeds bound: {planned_decode}")

    log_literal = _raw_data(pe, 0x1C5CB88, 0x40, "SetArmyTradition_log_literal_and_source")
    token_2951 = _raw_data(pe, 0x2096D40, 0x30, "compiled_army_tradition_token")
    token_271B = _raw_data(pe, 0x2036378, 0x30, "compiled_add_army_tradition_token")

    return {
        "schema": "information_military_quality_static_source_v3",
        "status": "partial",
        "source_kind": "ordinary_pe_bounded_static",
        "scope": "N03.army_tradition",
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
            "follow_up_scope": "setter/clamp, additive wrapper, and one compiled condition slice only",
            "decode_limits": {
                "max_single_bytes": MAX_SINGLE_DECODE_BYTES,
                "max_total_bytes": MAX_TOTAL_DECODE_BYTES,
                "planned_total_bytes": planned_decode,
            },
            "prior_large_functions_not_redecoded": True,
        },
        "prior_sources": {
            "source001": {"path": str(SOURCE001), "sha256": _sha256_file(SOURCE001)},
            "source002": {"path": str(SOURCE002), "sha256": _sha256_file(SOURCE002)},
        },
        "bounded_ranges": [
            _range_record(pe, setter_rows, *SETTER_RANGE),
            _range_record(pe, adder_rows, *ADDER_RANGE),
            _range_record(pe, condition_rows, *CONDITION_RANGE),
        ],
        "bounded_data": [log_literal, token_2951, token_271B],
        "selected_instructions": {
            "setter_and_clamp": _selected(
                setter_rows,
                [0x357212, 0x357267, 0x35726D, 0x35726F, 0x357275, 0x357279, 0x35727B, 0x357283, 0x35728B, 0x357295, 0x35729A, 0x35729E, 0x3572AC],
            ),
            "additive_wrapper": _selected(adder_rows, [0x357394, 0x357396, 0x35739D, 0x3573A5, 0x3573AA]),
            "compiled_condition": _selected(condition_rows, [0x2DF51E, 0x2DF525, 0x2DF528, 0x2DF539, 0x2DF541, 0x2DF546]),
        },
        "field_findings": {
            "army_tradition": {
                "field_literal": "army_tradition",
                "setter": {
                    "status": "closed_direct_country_writer_and_clamp",
                    "function_rva_range": [hex(SETTER_RANGE[0]), hex(SETTER_RANGE[1])],
                    "country_alias": "RDI=RCX at 0x357212",
                    "source_literal": {
                        "rva": hex(0x1C5CB88),
                        "text": "SetArmyTradition, %s, %d",
                        "source_file_and_line": "C:\\mnt\\gsg\\eu4\\eu4\\eu4\\source\\country.cpp:29220",
                        "raw_sha256": log_literal["sha256"],
                    },
                    "value_path": [
                        "MOV EAX,DWORD PTR [RDI+0xe40] at 0x357267 (old value)",
                        "MOV ECX,DWORD PTR [RSI] at 0x35726d (new 32-bit value)",
                        "MOV DWORD PTR [RDI+0xe40],ECX at 0x35726f",
                    ],
                    "lower_bound": {
                        "comparison": "TEST ECX,ECX; JNS",
                        "negative_action": "ECX=0; store DWORD [RDI+0xe40]=0",
                    },
                    "upper_bound": {
                        "comparison": "CMP ECX,0x186a0; JLE",
                        "constant_decimal": 100000,
                        "over_bound_action": "store DWORD [RDI+0xe40]=0x186a0",
                    },
                    "change_flag": "if clamped/new value differs from old EAX, set BYTE [RDI+0x2882]=1 and refresh [RDI+0x2858]",
                    "width": "32-bit load/store and 32-bit signed comparisons",
                },
                "additive_wrapper": {
                    "status": "closed_add_then_setter",
                    "function_rva_range": [hex(ADDER_RANGE[0]), hex(ADDER_RANGE[1])],
                    "country_alias": "RCX is passed unchanged to setter",
                    "delta_input": "DWORD PTR [RDX]",
                    "current_input": "DWORD PTR [RCX+0xe40]",
                    "operation": "ADD R8D,EDX at 0x35739d; 32-bit wrap precedes the setter/clamp call",
                    "call": "0x3573aa -> 0x357200 with temporary DWORD pointer",
                },
                "compiled_condition": {
                    "status": "offset_and_token_association_closed",
                    "slice_rva_range": [hex(CONDITION_RANGE[0]), hex(CONDITION_RANGE[1])],
                    "offset_read": "LEA RDX,[R15+0xe40] at 0x2df51e; CMP DWORD PTR [RDX],0 at 0x2df525",
                    "nonzero_branch": "when nonzero, MOV EDX,0x2951 at 0x2df539 then CALL 0x1707a10 at 0x2df541",
                    "token_data": {
                        "token": "0x2951",
                        "data_rva": hex(0x2096D40),
                        "adjacent_literal": "army_tradition",
                    },
                    "runtime_alias": "R15 is a static candidate object alias; no runtime country identity is claimed",
                },
                "compiled_effect_token": {
                    "status": "data_association_only",
                    "token": "0x271b",
                    "data_rva": hex(0x2036378),
                    "adjacent_literal": "add_army_tradition",
                    "caveat": "No large dispatcher/effect body was decoded in source003; this data token does not by itself prove a caller or parameter conversion.",
                },
                "unit_and_scale": {
                    "status": "bounded_scale_candidate",
                    "raw_domain": "signed 32-bit storage, clamped to inclusive 0..100000",
                    "max_raw": 100000,
                    "scale_candidate": 1000,
                    "candidate_reason": "0x186a0 is exactly 100 * 1000, matching the bounded army-tradition domain",
                    "explicit_divide_or_formatter": "not found in the new bounded writer/condition slices",
                    "publication_caveat": "The writer proves the raw domain and the 100000 ceiling; an explicit numeric formatter or parser multiply/divide is still required before treating scale=1000 as independently closed.",
                },
            }
        },
        "conclusion": {
            "army_tradition": "country+0xe40 writer, additive update, signed 0..100000 clamp, SetArmyTradition source label, and compiled nonzero condition are statically bounded; scale 1000 remains a strong max-domain candidate but lacks a new explicit formatter/parser conversion in this slice",
            "publication": "do_not_mark_available_or_complete_true_from_source003_static_evidence_alone",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "work" / "runtime" / "information-military-quality-20261027-001" / "tradition-source-003.json",
    )
    args = parser.parse_args()
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "status": report["status"], "planned_total_decode_bytes": report["method"]["decode_limits"]["planned_total_bytes"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
