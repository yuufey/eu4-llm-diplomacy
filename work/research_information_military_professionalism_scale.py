"""Freeze the bounded type-8 professionalism scale contract.

This is ordinary static PE evidence for the fixed EU4 1.37.4 executable.  It
decodes only the complete 0x14b2b40 type-dispatch/formatter function and two
small direct callees.  It never opens the game, uses RPM/native calls, invokes
REA, or reads the rejected 14b33a0 provider payload.
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
MAX_SINGLE_DECODE_BYTES = 16 * 1024
MAX_TOTAL_DECODE_BYTES = 16 * 1024

OUTPUT = ROOT / (
    "work/runtime/information-military-professionalism-20261027-001/"
    "professionalism-scale-source-001.json"
)

# Complete .pdata functions.  The first is 1,993 bytes; the two direct
# callees are deliberately kept as separate bounded ranges.
CODE_RANGES = (
    (0x14B2B40, 0x14B3309, "type8_dispatch_formatter"),
    (0x15C260, 0x15C2BD, "scalar_text_wrapper"),
    (0x14BEE40, 0x14BEF81, "special_overflow_formatter"),
)

# Existing static reports are inputs only.  Their bytes are pinned so a later
# report cannot silently change the country +0x50/QWORD lineage.
PRIOR_SOURCE_PINS = {
    "professionalism_binding_001": (
        "work/runtime/information-military-effective-20261027-001/"
        "professionalism-binding-001.json",
        "814a28e4ea89432d3c7f34395912ac3555e4486d6ccdd5b4035db3ed7cd6686b",
    ),
    "professionalism_binding_002_getter_9a530": (
        "work/runtime/information-military-effective-20261027-001/"
        "professionalism-binding-002.json",
        "2a219bfd1aaf79f35456124257d9fa83182b7eeead26ea8ba55fc17a659868dd",
    ),
    "professionalism_binding_003": (
        "work/runtime/information-military-effective-20261027-001/"
        "professionalism-binding-003.json",
        "2b38155655a9f4b9fd80c3e09b89997ec6f770a413d4746746bae38821620c5e",
    ),
    "professionalism_binding_004": (
        "work/runtime/information-military-effective-20261027-001/"
        "professionalism-binding-004.json",
        "043e5c27b6a4a214f6d85128ca542e07a9a4e30a980205b190e9ce9dd6384f4c",
    ),
    "professionalism_binding_005": (
        "work/runtime/information-military-effective-20261027-001/"
        "professionalism-binding-005.json",
        "460f5be44102a2ddf6e8f2b4fb64ac674388c166da80e2f4e75e18a4bca79356",
    ),
    "professionalism_country_writer_36d6": (
        "work/runtime/information-military-quality-20261027-001/"
        "professionalism-writer-001.json",
        "3b96614e48c7f818e23e6d7c53769b149ee9b3b8b31221450c129797c625e047",
    ),
    "professionalism_ui_template": (
        "work/runtime/information-military-quality-20261027-001/"
        "professionalism-ui-001.json",
        "018ac39cbd1ce6d0bd2eab77d60fa97223c09e93e7da80be93468417f700753a",
    ),
    "professionalism_code_36d6": (
        "work/runtime/information-military-quality-20261027-001/"
        "professionalism-code-001.json",
        "a63530150788320a5e57a5630edda77627f93a9c1750405b6eadc0cfbb465e02",
    ),
}


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _source_pin(name: str, relative: str, expected_sha256: str) -> dict[str, Any]:
    path = ROOT / relative
    if not path.is_file():
        raise FileNotFoundError(path)
    actual = _sha256_file(path)
    if actual != expected_sha256:
        raise RuntimeError(f"source_pin_mismatch:{name}:{actual}")
    return {
        "path": relative,
        "sha256": actual,
        "bytes": path.stat().st_size,
        "evidence_kind": "prior_ordinary_static_report",
    }


def _decode(pe: PE, md: Any, begin: int, end: int) -> list[dict[str, Any]]:
    if end <= begin or end - begin > MAX_SINGLE_DECODE_BYTES:
        raise ValueError(f"decode_range_out_of_bound:{begin:#x}:{end:#x}")
    if not pe.executable(begin) or not pe.executable(end - 1):
        raise ValueError(f"decode_range_not_executable:{begin:#x}:{end:#x}")
    check_memory_budget()
    return _decode_range(pe, md, begin, end)


def _range_record(
    pe: PE,
    rows: list[dict[str, Any]],
    begin: int,
    end: int,
    label: str,
) -> dict[str, Any]:
    raw = pe.bytes_at(begin, end - begin)
    if len(raw) != end - begin:
        raise RuntimeError(f"range_not_file_backed:{begin:#x}:{end:#x}")
    pdata_fragments = [
        [hex(start), hex(stop)]
        for start, stop, _unwind in pe.functions
        if start < end and stop > begin
    ]
    return {
        "label": label,
        "start_rva": hex(begin),
        "end_rva_exclusive": hex(end),
        "start_static_va": hex(pe.base + begin),
        "end_static_va_exclusive": hex(pe.base + end),
        "byte_length": len(raw),
        "bytes_sha256": _sha256_bytes(raw),
        "pdata_fragments_intersecting_range": pdata_fragments,
        "function_boundary_from_pdata": (
            pdata_fragments[0] if len(pdata_fragments) == 1 else None
        ),
        "range_note": (
            "The 1,993-byte type8 range ends at the ret instruction 0x14b3308; "
            "its final adjacent .pdata fragment extends into embedded jump-table/data bytes."
            if begin == 0x14B2B40
            else None
        ),
        "decoded_instruction_count": len(rows),
    }


def _by_rva(rows: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    return {int(row["rva"], 16): row for row in rows}


def _expect(
    rows: list[dict[str, Any]],
    rva: int,
    raw: str,
    mnemonic: str | None = None,
    operands: str | None = None,
) -> dict[str, Any]:
    row = _by_rva(rows).get(rva)
    if row is None:
        raise RuntimeError(f"instruction_missing:{rva:#x}")
    if row.get("bytes") != raw:
        raise RuntimeError(f"instruction_bytes_changed:{rva:#x}:{row.get('bytes')}")
    if mnemonic is not None and row.get("mnemonic") != mnemonic:
        raise RuntimeError(f"instruction_mnemonic_changed:{rva:#x}")
    if operands is not None and row.get("operands") != operands:
        raise RuntimeError(f"instruction_operands_changed:{rva:#x}")
    return row


def _selected(rows: list[dict[str, Any]], addresses: list[int]) -> list[dict[str, Any]]:
    mapping = _by_rva(rows)
    result = []
    for address in addresses:
        if address not in mapping:
            raise RuntimeError(f"selected_instruction_missing:{address:#x}")
        result.append(mapping[address])
    return result


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
        "static_va": hex(pe.base + rva),
        "file_offset": None if offset is None else hex(offset),
        "section": section,
    }


def _constant(
    pe: PE,
    rva: int,
    size: int,
    label: str,
    decoded_value: Any,
    encoding: str,
) -> dict[str, Any]:
    raw = pe.bytes_at(rva, size)
    if len(raw) != size:
        raise RuntimeError(f"constant_not_file_backed:{label}")
    return {
        "label": label,
        "location": _location(pe, rva),
        "raw_hex": raw.hex(),
        "bytes_sha256": _sha256_bytes(raw),
        "encoding": encoding,
        "decoded_value": decoded_value,
    }


def _decode_f32(raw: bytes) -> float:
    return struct.unpack("<f", raw)[0]


def _decode_f64(raw: bytes) -> float:
    return struct.unpack("<d", raw)[0]


def _parse_jump_table(pe: PE) -> dict[str, Any]:
    rva = 0x14B337C
    raw = pe.bytes_at(rva, 24)
    if len(raw) != 24:
        raise RuntimeError("type_jump_table_not_file_backed")
    values = list(struct.unpack("<6I", raw))
    expected = [0x14B2D57, 0x14B2DA5, 0x14B2DD6, 0x14B2E28, 0x14B2EDA, 0x14B308A]
    if values != expected:
        raise RuntimeError(f"type_jump_table_changed:{values!r}")
    return {
        "location": _location(pe, rva),
        "entry_width_bytes": 4,
        "raw_hex": raw.hex(),
        "bytes_sha256": _sha256_bytes(raw),
        "entries": [
            {"type_tag": index + 3, "table_index": index, "target_rva": hex(value)}
            for index, value in enumerate(values)
        ],
        "type8": {"table_index": 5, "target_rva": "0x14b308a"},
        "addressing": "DWORD RVA loaded from image-base-relative table, then image base is added before jmp rcx",
    }


def _parse_template_tables(pe: PE) -> dict[str, Any]:
    selector_rva = 0x14B3338
    selector = pe.bytes_at(selector_rva, 53)
    if len(selector) != 53:
        raise RuntimeError("parser_selector_not_file_backed")
    dispatch_rva = 0x14B330C
    dispatch = pe.bytes_at(dispatch_rva, 32)
    if len(dispatch) != 32:
        raise RuntimeError("parser_dispatch_not_file_backed")

    def handler_for(character: str) -> tuple[int, int]:
        index = ord(character) - 0x25
        if not 0 <= index < len(selector):
            raise RuntimeError(f"parser_character_out_of_table:{character}")
        slot = selector[index]
        target = struct.unpack_from("<I", dispatch, slot * 4)[0]
        return index, target

    expected = {"%": 0x14B2CA4, "2": 0x14B2CC8, "Y": 0x14B2CFB}
    mappings = {}
    for character, target in expected.items():
        index, actual = handler_for(character)
        if actual != target:
            raise RuntimeError(f"parser_handler_changed:{character}:{actual:#x}")
        mappings[character] = {
            "ascii": ord(character),
            "selector_index": index,
            "dispatch_slot": selector[index],
            "handler_rva": hex(actual),
        }
    return {
        "selector_table": {
            "location": _location(pe, selector_rva),
            "entry_width_bytes": 1,
            "raw_hex": selector.hex(),
            "bytes_sha256": _sha256_bytes(selector),
        },
        "dispatch_table": {
            "location": _location(pe, dispatch_rva),
            "entry_width_bytes": 4,
            "raw_hex": dispatch.hex(),
            "bytes_sha256": _sha256_bytes(dispatch),
            "addressing": "absolute RVA entries consumed as image-base-relative handler RVAs",
        },
        "literal_handlers": mappings,
        "template": "$VALUE|Y%2$",
        "resolved_effect": {
            "percent_marker": "% -> dl=1",
            "color_marker": "Y -> ebx receives the marker byte; it does not set r10b",
            "precision": "2 -> r9d=2",
            "special_ratio_branch": "r10b remains 0 for this template, so type8 enters 0x14b3110",
        },
    }


def build_report() -> dict[str, Any]:
    executable = game_exe()
    size = executable.stat().st_size
    if size > MAX_EXE_BYTES:
        raise RuntimeError(f"refusing_executable_larger_than_bound:{size}")
    pe = PE(executable)
    digest = _sha256_bytes(pe.data)
    if size != EXPECTED_EXE_BYTES or digest != EXPECTED_EXE_SHA256:
        raise RuntimeError(f"unexpected_executable:{size}:{digest}")
    if pe.base != EXPECTED_IMAGE_BASE:
        raise RuntimeError(f"unexpected_image_base:{pe.base:#x}")

    source_pins = {
        name: _source_pin(name, relative, expected)
        for name, (relative, expected) in PRIOR_SOURCE_PINS.items()
    }

    planned = sum(end - begin for begin, end, _ in CODE_RANGES)
    if planned > MAX_TOTAL_DECODE_BYTES:
        raise RuntimeError(f"planned_decode_exceeds_bound:{planned}")
    md, decoder = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    decoded: dict[str, list[dict[str, Any]]] = {}
    ranges = []
    for begin, end, label in CODE_RANGES:
        rows = _decode(pe, md, begin, end)
        decoded[label] = rows
        ranges.append(_range_record(pe, rows, begin, end, label))

    type8 = decoded["type8_dispatch_formatter"]
    wrapper = decoded["scalar_text_wrapper"]
    overflow = decoded["special_overflow_formatter"]

    # Dispatch and type-8 entry.
    _expect(type8, 0x14B2D2A, "438b4c0628", "mov", "ecx,DWORD PTR [r14+r8*1+0x28]")
    _expect(type8, 0x14B2D2F, "8d41fd", "lea", "eax,[rcx-0x3]")
    _expect(type8, 0x14B2D32, "83f805", "cmp", "eax,0x5")
    _expect(type8, 0x14B2D3B, "4c8d1dbed2b4fe", "lea")
    _expect(type8, 0x14B2D4A, "418b8c837c334b01", "mov")
    _expect(type8, 0x14B2D52, "4903cb", "add", "rcx,r11")
    _expect(type8, 0x14B2D55, "ffe1", "jmp", "rcx")
    _expect(type8, 0x14B308A, "4f8b440658", "mov", "r8,QWORD PTR [r14+r8*1+0x58]")
    _expect(type8, 0x14B308F, "4d85c0", "test", "r8,r8")
    _expect(type8, 0x14B30A1, "4584d2", "test", "r10b,r10b")
    _expect(type8, 0x14B30A4, "746a", "je", "0x1414b3110")

    # Literal parser facts needed to select the normal percentage path.
    _expect(type8, 0x14B2C44, "f30f100514ec9000", "movss")
    _expect(type8, 0x14B2C4C, "32d2", "xor", "dl,dl")
    _expect(type8, 0x14B2C53, "4532d2", "xor", "r10b,r10b")
    _expect(type8, 0x14B2C68, "0f28d0", "movaps", "xmm2,xmm0")
    _expect(type8, 0x14B2C6E, "41b102", "mov", "r9b,0x2")
    _expect(type8, 0x14B2CA4, "b201", "mov", "dl,0x1")
    _expect(type8, 0x14B2CC8, "448d4ad0", "lea", "r9d,[rdx-0x30]")
    _expect(type8, 0x14B2CFB, "0fb6da", "movzx", "ebx,dl")

    # Normal type-8 percentage path.  The REX.W forms of CVTSI2SD are
    # deliberately asserted: both conversions are signed 64-bit integer input.
    _expect(type8, 0x14B30CF, "488d4dc7", "lea", "rcx,[rbp-0x39]")
    _expect(type8, 0x14B30D6, "f2490f2ad0", "cvtsi2sd", "xmm2,r8")
    _expect(type8, 0x14B30DB, "f20f591535e49000", "mulsd")
    _expect(type8, 0x14B30E3, "66490f7ed0", "movq", "r8,xmm2")
    _expect(type8, 0x14B30FE, "4b8b94cb807bc301", "mov")
    _expect(type8, 0x14B3106, "e85591cafe", "call", "0x14015c260")
    _expect(type8, 0x14B3110, "84d2", "test", "dl,dl")
    _expect(type8, 0x14B3112, "743c", "je", "0x1414b3150")
    _expect(type8, 0x14B312E, "f30f5915c6e79000", "mulss")
    _expect(type8, 0x14B3139, "f30f5ac2", "cvtss2sd", "xmm0,xmm2")
    _expect(type8, 0x14B313D, "f20f58c1", "addsd", "xmm0,xmm1")
    _expect(type8, 0x14B3141, "f2480f2cc0", "cvttsd2si", "rax,xmm0")
    _expect(type8, 0x14B3146, "490fafc0", "imul", "rax,r8")
    _expect(type8, 0x14B314A, "48c1f80f", "sar", "rax,0xf")
    _expect(type8, 0x14B3150, "498bc0", "mov", "rax,r8")
    _expect(type8, 0x14B315A, "f2480f2ad0", "cvtsi2sd", "xmm2,rax")
    _expect(type8, 0x14B315F, "f20f5915b1e39000", "mulsd")
    _expect(type8, 0x14B3167, "66490f7ed0", "movq", "r8,xmm2")
    _expect(type8, 0x14B3178, "e8e390cafe", "call", "0x14015c260")

    # The wrapper only forwards the selected format/value arguments.  It is
    # included to close the direct scalar sink without decoding its callees.
    _expect(wrapper, 0x15C260, "4889542410", "mov")
    _expect(wrapper, 0x15C265, "4c89442418", "mov")
    _expect(wrapper, 0x15C281, "e81a6df3ff", "call", "0x140092fa0")
    _expect(wrapper, 0x15C2A4, "488b08", "mov", "rcx,QWORD PTR [rax]")
    _expect(wrapper, 0x15C2AB, "e8749e8e01", "call", "0x141a46124")
    _expect(wrapper, 0x15C2BC, "c3", "ret")

    # The overflow callee is only the r10b!=0 fallback; pin its entry and the
    # callsite argument but do not use it for the literal professionalism path.
    _expect(type8, 0x14B30BB, "41b840000000", "mov", "r8d,0x40")
    _expect(type8, 0x14B30C5, "e876bd0000", "call", "0x1414bee40")
    _expect(overflow, 0x14BEE40, "48895c2418", "mov")

    jump_table = _parse_jump_table(pe)
    parser_tables = _parse_template_tables(pe)

    constants = {
        "f64_reciprocal_32768": _constant(
            pe, 0x1DC1518, 8, "1/32768", _decode_f64(pe.bytes_at(0x1DC1518, 8)), "IEEE754 binary64"
        ),
        "f32_percent_base_100": _constant(
            pe, 0x1DC1860, 4, "100.0", _decode_f32(pe.bytes_at(0x1DC1860, 4)), "IEEE754 binary32"
        ),
        "f32_ratio_denominator_32768": _constant(
            pe, 0x1DC18FC, 4, "32768.0", _decode_f32(pe.bytes_at(0x1DC18FC, 4)), "IEEE754 binary32"
        ),
        "f64_round_plus_half": _constant(
            pe, 0x1DC1630, 8, "+0.5", _decode_f64(pe.bytes_at(0x1DC1630, 8)), "IEEE754 binary64"
        ),
        "f64_round_minus_half": _constant(
            pe, 0x1DC19B8, 8, "-0.5", _decode_f64(pe.bytes_at(0x1DC19B8, 8)), "IEEE754 binary64"
        ),
    }

    format_table_rva = 0x1C37B80
    format_table_raw = pe.bytes_at(format_table_rva, 24)
    format_ptrs = list(struct.unpack("<3Q", format_table_raw))
    expected_ptrs = [pe.base + 0x1DBF508, pe.base + 0x1DBF5C8, pe.base + 0x1DBF5C0]
    # The first two pointers are format strings used by neighbouring precision
    # entries; the type8 literal selects index 2 and therefore %.2f.
    if format_ptrs != expected_ptrs:
        raise RuntimeError(f"format_pointer_table_changed:{format_ptrs!r}")
    format_string_rva = 0x1DBF5C0
    format_string_raw = pe.bytes_at(format_string_rva, 8)
    if format_string_raw[:5] != b"%.2f\0":
        raise RuntimeError("precision_two_format_changed")

    contract = {
        "field": "army_professionalism",
        "country_offset": "0x50",
        "width_bytes": 8,
        "signed": True,
        "storage": "raw_signed_qword",
        "unit": "ratio",
        "scale": 32768,
        "period": "current",
        "basis": "native_country_army_professionalism_cache",
        "value_origin": "copied_native_country_army_professionalism_cache",
        "display": {
            "locale_key": "ARMY_PROFESSIONALISM_VALUE",
            "template": "$VALUE|Y%2$",
            "unit": "percent",
            "precision": 2,
            "effective_display_formula": "signed_qword(raw) * 100 / 32768, with the shown signed multiply/arithmetic-shift path",
        },
        "static_source_formula": {
            "ratio": "signed_qword(raw) / 32768",
            "percent_template": "signed_qword(raw) * 100 / 32768",
            "normal_branch": "r10b == 0",
            "signed_conversion": "REX.W CVTSI2SD from r8/rax; signed 64-bit integer input",
            "rounding_detail": "percentage branch forms 100*32768 in binary32, converts with CVTTSD2SI, multiplies raw, then arithmetic SAR 15 before reciprocal conversion",
        },
    }

    return {
        "schema": "information_military_professionalism_scale_source.v1",
        "status": "partial_static_scale_contract_closed",
        "source_kind": "ordinary_pe_bounded_static_not_REA",
        "scope": "N03.army_professionalism.country_cache_to_type8_display_scale",
        "binary": {
            "path": str(executable),
            "size": size,
            "sha256": digest,
            "image_base": hex(pe.base),
            "version_pin": "EU4 1.37.4",
            "address_note": "All addresses below are static RVAs; static VA=image_base+RVA. No runtime module base is inferred.",
        },
        "method": {
            "game_or_rpm": False,
            "rea_invoked": False,
            "native_calls": False,
            "decoder": "capstone" if decoder is not None else "bounded_objdump_fallback",
            "decode_limits": {
                "max_single_bytes": MAX_SINGLE_DECODE_BYTES,
                "max_total_bytes": MAX_TOTAL_DECODE_BYTES,
                "planned_total_bytes": planned,
                "decoded_ranges": len(CODE_RANGES),
            },
            "scope_note": "Only the complete type8 function and two direct small callees were decoded. The large fb4ba0 UI function and rejected 14b33a0 payload were not read.",
        },
        "source_pins": source_pins,
        "prior_lineage": {
            "getter": {
                "rva": "0x9a530",
                "expression": "RAX = QWORD PTR [RCX+0x50]",
                "role": "current-country +0x50 raw QWORD getter from prior bounded report",
            },
            "country_writer": {
                "token_id": "0x36d6",
                "token_text": "army_professionalism",
                "field_expression": "country + 0x50",
                "serializer_format": "%lld",
                "role": "prior country-writer and signed-QWORD textual corroboration",
            },
            "fbe450_frame": {
                "type_tag": 8,
                "raw_value_offset": "0x58",
                "business_consumer": "0x14b33a0",
                "role": "prior binding chain; this report closes the downstream type8 scale in 0x14b2b40",
            },
        },
        "bounded_ranges": ranges,
        "type_dispatch": {
            "entry_load": _selected(type8, [0x14B2D2A, 0x14B2D2F, 0x14B2D32]),
            "jump_table": jump_table,
            "type8_entry": {
                "target_rva": "0x14b308a",
                "load": _selected(type8, [0x14B308A, 0x14B308F, 0x14B3092, 0x14B3096, 0x14B3099, 0x14B309D]),
                "raw_value": "QWORD PTR [frame_entry + 0x58]",
                "signedness": "subsequent REX.W CVTSI2SD treats the QWORD as signed int64",
            },
        },
        "template_parser": parser_tables,
        "type8_numeric_path": {
            "selected_branch": "r10b == 0 -> 0x14b3110 for $VALUE|Y%2$",
            "normal_ratio_path": _selected(type8, [0x14B30CF, 0x14B30D6, 0x14B30DB, 0x14B30E3, 0x14B3150, 0x14B315A, 0x14B315F, 0x14B3167]),
            "percentage_path": _selected(type8, [0x14B3110, 0x14B3112, 0x14B311C, 0x14B3126, 0x14B312E, 0x14B3139, 0x14B313D, 0x14B3141, 0x14B3146, 0x14B314A]),
            "format_selection": _selected(type8, [0x14B30FE, 0x14B3106, 0x14B3171, 0x14B3178]),
            "signed_cvtsi2sd": {
                "r8_source": {
                    "rva": "0x14b30d6",
                    "bytes": "f2490f2ad0",
                    "rex_w": True,
                    "source_width_bits": 64,
                    "signed": True,
                },
                "rax_source": {
                    "rva": "0x14b315a",
                    "bytes": "f2480f2ad0",
                    "rex_w": True,
                    "source_width_bits": 64,
                    "signed": True,
                },
            },
            "effective_math": {
                "ratio_without_percent": "signed_i64(raw) / 32768",
                "percent_with_literal_template": "signed_i64(raw) * 100 / 32768",
                "machine_sequence": [
                    "xmm2 = 100.0f * 32768.0f",
                    "cvtss2sd xmm0,xmm2",
                    "addsd xmm0, +/-0.5",
                    "cvttsd2si rax,xmm0",
                    "imul rax,r8",
                    "sar rax,0xf",
                    "cvtsi2sd xmm2,rax",
                    "mulsd xmm2,1/32768",
                ],
                "rounding_caveat": "The report preserves the exact truncation/arithmetic-shift sequence; it does not replace it with an unqualified real-number rounding claim.",
            },
            "special_branch": {
                "condition": "r10b != 0",
                "fallback_rva": "0x14bee40",
                "callsite": _selected(type8, [0x14B30BB, 0x14B30C5]),
                "not_selected_for_template": True,
            },
        },
        "constants": constants,
        "format_table": {
            "location": _location(pe, format_table_rva),
            "raw_hex": format_table_raw.hex(),
            "bytes_sha256": _sha256_bytes(format_table_raw),
            "precision_entries": [
                {"precision": index, "pointer_static_va": hex(value), "pointer_rva": hex(value - pe.base)}
                for index, value in enumerate(format_ptrs)
            ],
            "selected_precision_2": {
                "format_location": _location(pe, format_string_rva),
                "raw_hex": format_string_raw.hex(),
                "bytes_sha256": _sha256_bytes(format_string_raw),
                "text": "%.2f",
            },
        },
        "direct_scalar_sink": {
            "rva": "0x15c260",
            "range": ["0x15c260", "0x15c2bd"],
            "role": "forwards format pointer and numeric QWORD bits to downstream text helpers; no scale operation in this wrapper",
            "selected_instructions": _selected(wrapper, [0x15C260, 0x15C265, 0x15C26A, 0x15C281, 0x15C286, 0x15C2A4, 0x15C2AB, 0x15C2BC]),
        },
        "contract": contract,
        "limitations": [
            "Static evidence closes the source width/sign conversion and scale path, but does not observe a live FRA object or cache-refresh timing.",
            "The discarded 14b33a0 provider payload remains postread_guard_error and is not used here as accepted REA evidence.",
            "The type8 formatter's downstream 0x92fa0/0x1a46124 callees were not decoded; their absence does not affect the already closed multiply/shift scale path.",
        ],
        "conclusion": {
            "closed": [
                "Type tag 8 selects 0x14b308a through the six-entry jump table.",
                "Type8 reads the raw QWORD at frame entry +0x58 and consumes it through signed REX.W CVTSI2SD.",
                "$VALUE|Y%2$ sets the percent marker and precision 2, selecting %.2f.",
                "The static path establishes ratio scale 32768 and effective percent presentation raw*100/32768.",
                "The requested production contract is raw signed QWORD, ratio/32768, current country cache lineage.",
            ],
            "not_observed": [
                "No runtime/native call, cache refresh event, or live-country identity was observed.",
            ],
            "publication": "Suitable as the static source contract for a fail-closed production profile; runtime acceptance remains a separate task.",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists() and not args.force:
        raise FileExistsError(f"refusing_to_overwrite:{args.output}")
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "status": report["status"],
                "decode_bytes": report["method"]["decode_limits"]["planned_total_bytes"],
                "type8_target": report["type_dispatch"]["type8_entry"]["target_rva"],
                "scale": report["contract"]["scale"],
                "unit": report["contract"]["unit"],
                "display": report["contract"]["display"]["effective_display_formula"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
