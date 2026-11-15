"""Bounded ordinary-PE evidence for current-country morale and discipline.

This is a static survey for the pinned EU4 1.37.4 executable.  It deliberately
does not use REA runtime evidence, RPM, a game process, or native calls.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE, check_memory_budget, make_disassembler, rip_references
from work.local_config import game_exe
from work.research_information_branch_inputs import _decode_range


EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = 0x140000000
MAX_TOTAL_DECODE = 0x8000

# Every range is bounded and the largest one is below the 16 KiB per-function
# limit.  The two small windows in the 0xeb/0xfb builders establish the country
# identity before their label/getter windows are interpreted.
RANGES = (
    (0x687640, 0x687941, "army_navy_object_country_selection_and_type"),
    (0x33fca0, 0x33ff98, "land_morale_modifier_adjustment_helper"),
    (0x33ffa0, 0x340819, "land_morale_display_getter"),
    (0x340820, 0x340A62, "land_morale_formatter"),
    (0x340A70, 0x340C46, "naval_morale_modifier_adjustment_helper"),
    (0x340C50, 0x341463, "naval_morale_display_getter"),
    (0x341470, 0x341849, "naval_morale_formatter"),
    (0x341850, 0x341FCA, "discipline_modifier_getter"),
    (0x8E9CE0, 0x8E9D37, "keyed_country_modifier_wrapper"),
    (0x237580, 0x2375D8, "naval_morale_signed32_consumer"),
    (0x23E430, 0x23E480, "land_morale_signed32_consumer"),
    (0xEB496E, 0xEB49B8, "military_view_current_country_selection"),
    (0xEB6AD4, 0xEB6C37, "land_morale_keyed_modifier_display"),
    (0xFB4BE0, 0xFB4C3F, "military_quality_view_current_country_selection"),
    (0xFB7EEE, 0xFB81CE, "land_and_naval_morale_labels_and_calls"),
    (0xFB9BBA, 0xFB9E90, "discipline_labels_and_keyed_call"),
)

STRING_TERMS = (
    "land_morale",
    "naval_morale",
    "discipline",
    "MILITARY_TACTICS",
    "LAND_MORALE",
    "NAVAL_MORALE",
    "DISCIPLINE",
    "DISCIPLINE_LONG",
)


def _section(pe: PE, rva: int):
    for sec in pe.sections:
        size = max(sec["size"], sec["virtual_size"])
        if sec["rva"] <= rva < sec["rva"] + size:
            return sec["name"]
    return None


def _location(pe: PE, rva: int):
    offset = pe.to_offset(rva)
    return {
        "rva": hex(rva),
        "va": hex(pe.base + rva),
        "file_offset": hex(offset) if offset is not None else None,
        "section": _section(pe, rva),
    }


def _ascii_survey(pe: PE):
    matches = []
    for term in STRING_TERMS:
        needle = term.encode("ascii") + b"\0"
        cursor = 0
        while True:
            offset = pe.data.find(needle, cursor)
            if offset < 0:
                break
            cursor = offset + 1
            # Keep exact string starts; do not report a substring of a larger
            # identifier as a separate semantic label.
            if offset and chr(pe.data[offset - 1]) in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_":
                continue
            rva = pe.to_rva(offset)
            if rva is None:
                continue
            item = {"term": term, **_location(pe, rva), "bytes_hex": needle.hex()}
            # The lowercase keys have data descriptors immediately before the
            # NUL string.  The preceding DWORD is recorded as a literal token
            # only; it is not treated as country storage.
            if term in {"land_morale", "naval_morale", "discipline"} and offset >= 4:
                token_rva = pe.to_rva(offset - 4)
                if token_rva is not None:
                    token = struct.unpack("<I", pe.data[offset - 4:offset])[0]
                    item["preceding_literal_token"] = {
                        **_location(pe, token_rva),
                        "token": token,
                        "token_hex": hex(token),
                    }
            matches.append(item)
    return matches


def _label_candidates(pe: PE, strings):
    targets = {int(item["rva"], 16) for item in strings if item["term"] in {
        "MILITARY_TACTICS", "LAND_MORALE", "NAVAL_MORALE", "DISCIPLINE", "DISCIPLINE_LONG"
    }}
    refs = rip_references(pe, targets)
    result = {}
    for rva in sorted(targets):
        candidates = []
        for candidate in refs.get(rva, []):
            candidates.append(candidate)
        result[hex(rva)] = candidates
    return result


def _range_record(pe: PE, md, start: int, end: int, purpose: str):
    raw = pe.bytes_at(start, end - start)
    pdata = pe.function(start)
    return {
        "purpose": purpose,
        "start": _location(pe, start),
        "end_exclusive": _location(pe, end),
        "byte_length": len(raw),
        "bytes_sha256": hashlib.sha256(raw).hexdigest(),
        "pdata": {
            "start_rva": hex(pdata[0]),
            "end_rva_exclusive": hex(pdata[1]),
            "unwind_rva": hex(pdata[2]),
        } if pdata else None,
        "instructions": _decode_range(pe, md, start, end),
    }


def run(output: Path):
    check_memory_budget()
    pe = PE(game_exe())
    actual_sha = hashlib.sha256(pe.data).hexdigest()
    if actual_sha != EXE_SHA256 or pe.base != IMAGE_BASE:
        raise RuntimeError(f"unexpected executable identity: sha={actual_sha} base={hex(pe.base)}")
    total = sum(end - start for start, end, _ in RANGES)
    if total > MAX_TOTAL_DECODE:
        raise RuntimeError(f"bounded decode budget exceeded: {total} > {MAX_TOTAL_DECODE}")
    if any(end <= start or end - start > 0x4000 for start, end, _ in RANGES):
        raise RuntimeError("invalid bounded range")

    md, decoder = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    strings = _ascii_survey(pe)
    report = {
        "schema": "information_military_morale_discipline_static.v1",
        "evidence_kind": "ordinary_bounded_PE_not_REA",
        "exe": {
            "path": str(pe.path),
            "sha256": EXE_SHA256,
            "bytes": len(pe.data),
            "static_image_base": hex(pe.base),
        },
        "runtime_or_RPM": False,
        "game_or_native_calls": 0,
        "whole_image_disassembly": False,
        "decoder": "Capstone " + decoder.__version__ if md is not None else "bounded objdump",
        "decode_budget": {"total_bytes": total, "max_total_bytes": MAX_TOTAL_DECODE, "max_per_range": 0x4000},
        "literal_string_survey": strings,
        "literal_label_rip_candidates": _label_candidates(pe, strings),
        "findings": {
            "current_country_identity": {
                "status": "strong_static_binding",
                "range_rva": ["0x687640", "0x687941"],
                "details": [
                    "The object builder derives province = province_base + signed32([input+0x28]) * 0x2e10.",
                    "It reads [province+0x468] as a full-reference value, shifts right 32, indexes the country table at module+0x233d8b0 plus 0x118, and keeps the selected country pointer in r15.",
                    "The later military-view window performs the analogous full-reference lookup and keeps the selected country pointer in r12/r14.",
                ],
            },
            "land_morale": {
                "status": "strong_static_binding",
                "country_storage": {
                    "offset": "0x9874",
                    "width_bits": 32,
                    "signed_arithmetic": True,
                    "signed_consumer_rva": "0x23e451 (movsxd rcx,DWORD PTR [rcx+0x9874])",
                    "unit": "fixed-point morale multiplier (1000 = 1.0)",
                    "scale": 1000,
                    "neutral_raw": 1000,
                },
                "type_selector": {
                    "rva": "0x6877e4",
                    "land_object_type_values": [0, 1, 2],
                    "else_field": "country+0x987c (naval path)",
                },
                "getter_and_adjustment": {
                    "function_rva": "0x33ffa0",
                    "direct_read_rva": "0x340570",
                    "source": "DWORD [country+0x9874]",
                    "modifier_helper": "0x33fca0",
                    "behavior": "when the country scale gate is not neutral, the modifier helper result is subtracted with DWORD arithmetic before formatting",
                },
                "display": {
                    "label_rva": "0x1c5b9a0",
                    "label_call_rvas": ["0x3408c4", "0xfb804e", "0xeb6bfe"],
                    "formatter_rva": "0x340820",
                    "neutral_compare": "0x3e8",
                },
                "alternate_keyed_view": {
                    "current_country_register": "r14",
                    "container_offset": "0x28c0",
                    "key": "0x10a",
                    "scale_argument_raw": "0x3e8",
                    "wrapper": "0x8e9ce0",
                    "display_call": "0xeb6bc8",
                    "note": "This is a second keyed country-modifier path; ordinary static evidence does not assert that its effective value is byte-for-byte identical to the +0x9874 base field in every UI path.",
                },
            },
            "naval_morale": {
                "status": "strong_static_binding",
                "country_storage": {
                    "offset": "0x987c",
                    "width_bits": 32,
                    "signed_arithmetic": True,
                    "signed_consumer_rva": "0x2375b4 (movsxd rcx,DWORD PTR [r8+0x987c])",
                    "unit": "fixed-point morale multiplier (1000 = 1.0)",
                    "scale": 1000,
                    "neutral_raw": 1000,
                },
                "type_selector": {
                    "rva": "0x6877e4",
                    "land_object_type_values": [0, 1, 2],
                    "else_field": "country+0x987c",
                },
                "getter_and_adjustment": {
                    "function_rva": "0x340c50",
                    "direct_read_rva": "0x340ffa",
                    "source": "DWORD [country+0x987c]",
                    "modifier_helper": "0x340a70",
                    "behavior": "the naval display path reads the DWORD field, applies its bounded modifier helper when the country gate is non-neutral, and formats the result",
                },
                "display": {
                    "label_rva": "0x1c5b9e0",
                    "label_call_rvas": ["0x341517", "0xfb80fe", "0xeb7206"],
                    "formatter_rva": "0x341470",
                    "neutral_compare": "0x3e8",
                },
                "scope_note": "The type-gated object path distinguishes the naval field from the land field; no claim is made that the object itself is a country rather than a country-owned army/navy view until the selected-country binding is used.",
            },
            "discipline": {
                "status": "keyed_current_country_getter_static; standalone_offset_unresolved",
                "country_storage": {
                    "container_offset": "0x28c0",
                    "entry_key_dword": "0x77",
                    "entry_value_offset": "0x4",
                    "entry_value_width_bits": 32,
                    "signed_arithmetic": True,
                    "signed_consumer_rva": "0x341901 (cmovl after the DWORD effective-value compare)",
                    "base_raw": 1000,
                    "unit": "fixed-point discipline multiplier (1000 = 1.0)",
                    "scale": 1000,
                    "minimum_raw": 10,
                },
                "getter": {
                    "function_rva": "0x341850",
                    "country_register": "rcx",
                    "output_register": "rdx",
                    "details": [
                        "The helper initializes the output DWORD to 0x3e8.",
                        "It obtains the country modifier container from country+0x28c0, finds key 0x77, reads the entry DWORD at +0x4, adds it with 32-bit arithmetic, and clamps the result to at least 10.",
                        "An additional manager callback at module-global-derived +0x2ce0 can add another DWORD contribution; this is part of the effective getter path.",
                    ],
                },
                "display": {
                    "short_label_rva": "0x1d48960",
                    "long_label_rva": "0x1d48850",
                    "keyed_wrapper_call_rva": "0xfb9e6a",
                    "long_label_call_rva": "0xfb9e86",
                    "ui_current_country_register": "r14 (selected in 0xfb4c05..0xfb4c1e)",
                },
                "semantic_caveat": "The same 0x341850 helper/key is reused in a MILITARY_TACTICS explanatory branch. The DISCIPLINE/DISCIPLINE_LONG label path is the direct semantic binding for discipline; callers reached through MILITARY_TACTICS must not automatically be treated as a second discipline field.",
            },
        },
        "ranges": [_range_record(pe, md, start, end, purpose) for start, end, purpose in RANGES],
        "limits_and_unknowns": [
            "This report proves ordinary static storage/getter/display paths only; it does not prove runtime freshness, process identity, or a live value.",
            "The land/naval +0x9874/+0x987c fields are DWORDs and are treated as signed fixed-point values because their consumers use DWORD subtraction and signed comparisons; no ABI source declaration is available.",
            "The bounded callers establish the 0x3e8 neutral fixed-point convention.  The shared 0x14bc950 formatter body belongs to a much larger pdata function and is intentionally not decoded in this report, so the exact final presentation routine is not independently re-derived here.",
            "The keyed discipline cache has no standalone fixed country offset identified in the bounded evidence; its key/value entry and effective getter are closed.",
            "Indirect calls, large UI functions, and modifier callback internals outside the listed bounded windows remain unresolved.",
        ],
    }
    check_memory_budget()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({
        "output": str(output),
        "bytes": output.stat().st_size,
        "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "decode_bytes": total,
    }, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.output)
