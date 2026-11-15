"""Bounded follow-up for the numeric morale record writers.

The previous morale report followed the FB80 land/naval display builders.  This
file adds only the small, separate record-producing branches that copy
country+0x9874/+0x987c into a typed value record before formatting text.  It
also records the LAND_MORALE/NAVAL_MORALE property-registration paths so that
registration is not confused with a numeric widget assignment.

This is ordinary bounded PE analysis only.  It does not run REA, attach to a
game, read process memory, invoke native code, or disassemble a whole image.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE, check_memory_budget, make_disassembler
from work.local_config import game_exe
from work.research_information_branch_inputs import _decode_range


EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = 0x140000000
MAX_TOTAL_DECODE = 0x8000

SOURCE_001 = ROOT / "work/runtime/information-military-quality-20261027-001/morale-discipline-source-001.json"
SOURCE_001_SHA256 = "93fd027a25b109214443370ba999bf07e24e3010fe687dec66820d1e32ed0276"
PRIOR_EFFECTIVE = ROOT / "work/runtime/information-military-effective-20261027-001/morale-effective-source-001.json"
PRIOR_EFFECTIVE_SHA256 = "f9a68ad086c2b6686a8f0e14c0c6fdb1d6cf411dcd7b950f9fdf44a7a520f9b9"

OUTPUT = ROOT / "work/runtime/information-military-effective-20261027-001/morale-widget-source-001.json"

# The two 0x8d windows are mid-function callsites, while the 0x8f windows are
# complete small functions.  The two 0x119f windows begin at pdata function
# entries and stop after the land/naval numeric-record cases; the functions
# continue with unrelated switch cases.
RANGES = (
    (0x8D99F2, 0x8D9A49, "land_property_registration_callsite"),
    (0x8D9A70, 0x8D9AB5, "naval_property_registration_callsite"),
    (0x8F0650, 0x8F08EF, "naval_property_registration_builder"),
    (0x8F1540, 0x8F17EE, "land_property_registration_builder"),
    (0x8F1820, 0x8F1ACE, "naval_property_registration_builder_analog"),
    (0x8F45F0, 0x8F471D, "property_record_copy_helper"),
    (0x94F30, 0x94F79, "ui_text_object_copy_helper"),
    (0x1703E70, 0x1703E95, "ui_string_append_helper"),
    (0x119FB40, 0x119FC9D, "land_numeric_record_dispatch_and_writer"),
    (0x119FFD0, 0x11A0141, "naval_numeric_record_dispatch_and_writer"),
)


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def pin(path: Path, expected: str) -> dict:
    actual = digest(path)
    if actual != expected:
        raise RuntimeError(f"input_pin_mismatch:{path}:{actual}")
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": actual,
        "bytes": path.stat().st_size,
        "evidence_kind": "pinned_prior_ordinary_static_report",
    }


def load_report(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as stream:
        report = json.load(stream)
    if not isinstance(report, dict):
        raise RuntimeError(f"report_not_object:{path}")
    return report


def section(pe: PE, rva: int):
    for item in pe.sections:
        size = max(item["size"], item["virtual_size"])
        if item["rva"] <= rva < item["rva"] + size:
            return item["name"]
    return None


def location(pe: PE, rva: int) -> dict:
    offset = pe.to_offset(rva)
    return {
        "rva": hex(rva),
        "va": hex(pe.base + rva),
        "file_offset": hex(offset) if offset is not None else None,
        "section": section(pe, rva),
    }


def range_record(pe: PE, md, start: int, end: int, purpose: str) -> dict:
    if end <= start or end - start > 0x4000:
        raise RuntimeError(f"invalid_bounded_range:{purpose}")
    raw = pe.bytes_at(start, end - start)
    pdata = pe.function(start)
    return {
        "purpose": purpose,
        "start": location(pe, start),
        "end_exclusive": location(pe, end),
        "byte_length": len(raw),
        "bytes_hex": raw.hex(),
        "bytes_sha256": hashlib.sha256(raw).hexdigest(),
        "pdata": {
            "start_rva": hex(pdata[0]),
            "end_rva_exclusive": hex(pdata[1]),
            "unwind_rva": hex(pdata[2]),
        }
        if pdata
        else None,
        "instructions": _decode_range(pe, md, start, end),
        "evidence_kind": "new_bounded_ordinary_PE_instruction_record",
    }


def old_range(report: dict, purpose: str) -> dict:
    for item in report.get("ranges", []):
        if item.get("purpose") == purpose:
            return item
    raise KeyError(purpose)


def reused_window(report: dict, purpose: str, start: int, end: int) -> dict:
    source = old_range(report, purpose)
    source_start = int(source["start"]["rva"], 16)
    source_end = int(source["end_exclusive"]["rva"], 16)
    if not source_start <= start < end <= source_end:
        raise RuntimeError(f"old_window_outside_source:{purpose}")
    raw = bytearray(end - start)
    covered: set[int] = set()
    selected = []
    for item in source.get("instructions", []):
        address = int(item["rva"], 16)
        code = bytes.fromhex(item["bytes"])
        finish = address + len(code)
        if address < end and finish > start:
            if address < start or finish > end:
                raise RuntimeError(f"old_window_splits_instruction:{purpose}:{address:#x}")
            raw[address - start : finish - start] = code
            covered.update(range(address, finish))
            selected.append(item)
    if covered != set(range(start, end)):
        raise RuntimeError(f"old_window_gap:{purpose}")
    raw_bytes = bytes(raw)
    return {
        "purpose": purpose,
        "start": {"rva": hex(start), "va": hex(IMAGE_BASE + start), "section": ".text"},
        "end_exclusive": {"rva": hex(end), "va": hex(IMAGE_BASE + end), "section": ".text"},
        "byte_length": len(raw_bytes),
        "bytes_hex": raw_bytes.hex(),
        "bytes_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "source_pdata": source.get("pdata"),
        "instructions": selected,
        "evidence_kind": "reused_bounded_ordinary_PE_instruction_record",
    }


def source_literal(report: dict, term: str) -> dict:
    for item in report.get("literal_string_survey", []):
        if item.get("term") == term:
            return item
    raise KeyError(term)


def make_report() -> dict:
    prior_source = load_report(SOURCE_001)
    ranges = []

    check_memory_budget()
    pe = PE(game_exe())
    actual_sha = hashlib.sha256(pe.data).hexdigest()
    if actual_sha != EXE_SHA256 or pe.base != IMAGE_BASE:
        raise RuntimeError(f"unexpected_executable_identity:{actual_sha}:{pe.base:#x}")
    total = sum(end - start for start, end, _ in RANGES)
    if total > MAX_TOTAL_DECODE:
        raise RuntimeError(f"bounded_decode_budget_exceeded:{total}")
    md, decoder = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    for start, end, purpose in RANGES:
        ranges.append(range_record(pe, md, start, end, purpose))
    check_memory_budget()

    old_land = reused_window(prior_source, "land_and_naval_morale_labels_and_calls", 0xFB8048, 0xFB80CF)
    old_naval = reused_window(prior_source, "land_and_naval_morale_labels_and_calls", 0xFB80F8, 0xFB817F)

    land_literal = source_literal(prior_source, "LAND_MORALE")
    naval_literal = source_literal(prior_source, "NAVAL_MORALE")

    report = {
        "report_id": "information-military-morale-widget-source-001",
        "schema": "information_military_morale_widget_static.v1",
        "evidence_kind": "ordinary_bounded_PE_static",
        "target": {
            "exe_sha256": EXE_SHA256,
            "image_base": hex(IMAGE_BASE),
            "address_rule": "VA = image_base + RVA; all end addresses are exclusive",
            "runtime_or_RPM": False,
            "game_or_native_calls": False,
            "REA_query": False,
            "whole_image_disassembly": False,
        },
        "source_pins": [
            pin(SOURCE_001, SOURCE_001_SHA256),
            pin(PRIOR_EFFECTIVE, PRIOR_EFFECTIVE_SHA256),
        ],
        "decoder": "Capstone " + decoder.__version__ if md is not None else "bounded objdump",
        "decode_budget": {
            "new_bounded_bytes": total,
            "max_new_bounded_bytes": MAX_TOTAL_DECODE,
            "max_per_range": 0x4000,
            "note": "Only the listed small functions/callsites were decoded; no full UI function or image was disassembled.",
        },
        "literal_bindings": {
            "land": land_literal,
            "naval": naval_literal,
            "registration_tokens": {
                "land": {"token": "0x2903", "descriptor_key": "0x2a", "label_rva": "0x1c5b9a0"},
                "naval": {"token": "0x2904", "descriptor_key": "0x2b", "label_rva": "0x1c5b9e0"},
            },
            "evidence_kind": "reused_literal_survey_plus_new_bounded_rip_callsite",
        },
        "registration_paths": {
            "land": {
                "callsite": next(x for x in ranges if x["purpose"] == "land_property_registration_callsite"),
                "builder": next(x for x in ranges if x["purpose"] == "land_property_registration_builder"),
                "observed": [
                    "0x8d9a18 writes descriptor token 0x2903 and 0x8d9a0e writes descriptor key 0x2a.",
                    "0x8d9a2e passes the LAND_MORALE literal to 0x8f1540; 0x8d9a43 calls that registration/object builder.",
                    "The bounded 0x8f1540 body constructs/copies a property object and never reads a country pointer or +0x9874.",
                ],
            },
            "naval": {
                "callsite": next(x for x in ranges if x["purpose"] == "naval_property_registration_callsite"),
                "builder": next(x for x in ranges if x["purpose"] == "naval_property_registration_builder"),
                "analog_builder": next(x for x in ranges if x["purpose"] == "naval_property_registration_builder_analog"),
                "observed": [
                    "0x8d9a8a writes descriptor token 0x2904 and 0x8d9a80 writes descriptor key 0x2b.",
                    "0x8d9a9b passes the NAVAL_MORALE literal to 0x8f0650; 0x8d9ab0 calls that registration/object builder.",
                    "The bounded 0x8f0650/0x8f1820 bodies construct/copy property objects and never read a country pointer or +0x987c.",
                ],
            },
            "semantic_status": "registration_only; no numeric country value is established by these label/property paths",
        },
        "numeric_record_writers": {
            "land": {
                "function": {
                    "entry_rva": "0x119fb40",
                    "end_rva_exclusive": "0x119ffd0",
                    "unwind_rva": "0x1f13450",
                    "dispatch": "r8d is range-checked against 7 and selects an RVA-relative jump-table target.",
                },
                "bounded_window": next(x for x in ranges if x["purpose"] == "land_numeric_record_dispatch_and_writer"),
                "case_instructions": [
                    {"rva": "0x119fc4a", "effect": "mov eax,DWORD PTR [r9+0x9874]", "meaning": "copy signed DWORD source bytes; no arithmetic"},
                    {"rva": "0x119fc51", "effect": "mov DWORD PTR [rbx],0x9", "meaning": "typed record tag"},
                    {"rva": "0x119fc57", "effect": "mov DWORD PTR [rbx+0x40],eax", "meaning": "raw source value in record payload"},
                    {"rva": "0x119fc5a", "effect": "mov DWORD PTR [rbx+0x4],0x2", "meaning": "record/display kind"},
                ],
                "abi_alias": [
                    "At entry 0x119fb59 saves original R9 in RBX as the record destination.",
                    "0x119fb5c moves original RDX into R9; the case therefore reads original RDX+0x9874 and passes that same pointer as RCX to 0x33ffa0.",
                    "The fifth stack argument is loaded at 0x119fc61 and receives the formatted text object after the raw record write.",
                ],
                "text_side_effect": "0x119fc78 calls 0x33ffa0, then 0x119fc83 calls 0x94f30 to copy the returned string object into the fifth-argument destination; this is a separate text presentation step.",
                "semantic_status": "numeric_record_write_proven; exact visible widget/control consumer remains unresolved",
            },
            "naval": {
                "function": {
                    "entry_rva": "0x119ffd0",
                    "end_rva_exclusive": "0x11a0468",
                    "unwind_rva": "0x1f1348c",
                    "dispatch": "r8d is range-checked against 7 and selects an RVA-relative jump-table target.",
                },
                "bounded_window": next(x for x in ranges if x["purpose"] == "naval_numeric_record_dispatch_and_writer"),
                "case_instructions": [
                    {"rva": "0x11a00e9", "effect": "mov eax,DWORD PTR [r9+0x987c]", "meaning": "copy signed DWORD source bytes; no arithmetic"},
                    {"rva": "0x11a00f0", "effect": "mov DWORD PTR [rbx],0x9", "meaning": "typed record tag"},
                    {"rva": "0x11a00f6", "effect": "mov DWORD PTR [rbx+0x40],eax", "meaning": "raw source value in record payload"},
                    {"rva": "0x11a00f9", "effect": "mov DWORD PTR [rbx+0x4],0x2", "meaning": "record/display kind"},
                ],
                "abi_alias": [
                    "At entry 0x119ffec saves original R9 in RBX as the record destination.",
                    "0x119ffef moves original RDX into R9; the case therefore reads original RDX+0x987c and passes that same pointer as RCX to 0x340c50.",
                    "The fifth stack argument is loaded at 0x11a0100 and receives the formatted text object after the raw record write.",
                ],
                "text_side_effect": "0x11a0117 calls 0x340c50, then 0x11a0122 calls 0x94f30 to copy the returned string object into the fifth-argument destination; this is a separate text presentation step.",
                "semantic_status": "numeric_record_write_proven; exact visible widget/control consumer remains unresolved",
            },
            "shared_record_layout": {
                "record_destination": "original R9 (saved in RBX before R9 is repurposed)",
                "tag_offset": "0x0",
                "tag_value": 9,
                "raw_value_offset": "0x40",
                "raw_width_bits": 32,
                "kind_offset": "0x4",
                "kind_value": 2,
                "arithmetic": "none before the record store; the DWORD is copied verbatim",
            },
        },
        "fb80_display_builder_paths": {
            "land": old_land,
            "naval": old_naval,
            "classification": "display/string-object builder path, reused from pinned prior report",
            "contrast": [
                "FB80 calls 0x33ffa0/0x340c50 with RDX as an output slot and then sends RAX to 0x141703e70 for text-object append/copy.",
                "The numeric-record functions separately store the raw DWORD at record+0x40 before performing their text copy.",
                "Therefore the FB80 builder result is not evidence that its return pointer is the numeric widget value.",
            ],
        },
        "helper_windows": {
            "property_record_copy": next(x for x in ranges if x["purpose"] == "property_record_copy_helper"),
            "ui_text_object_copy": next(x for x in ranges if x["purpose"] == "ui_text_object_copy_helper"),
            "ui_string_append": next(x for x in ranges if x["purpose"] == "ui_string_append_helper"),
            "observed": [
                "0x8f45f0 copies a property/record object and bit flags; it has no country or morale offset access.",
                "0x94f30 copies a small string object; it does not compute a numeric value.",
                "0x1703e70 appends/copies a string object and returns the destination; it is not a scalar getter.",
            ],
        },
        "answer": {
            "numeric_widget_vs_tooltip": "The new 0x119fb40/0x119ffd0 branches are the smallest static evidence of a numeric value-record assignment: +0x9874/+0x987c is copied verbatim into record+0x40 with tag=9 and kind=2. The FB80 path remains a separate formatted-text builder. The final visible widget/control consumer of the typed record is still not identified.",
            "plus_9874_semantics": "These bytes prove a direct signed-DWORD copy into a numeric record and a separate formatter input. They do not prove that +0x9874/+0x987c is the final maximum, a total multiplier, or the complete effective morale; prior 0x33ffa0/0x340c50 helper/neutral branches still govern the display-builder path.",
            "scale": "The existing pinned formatter evidence remains the only /1000 display-scale evidence. The new record writer performs no scale, clamp, or modifier arithmetic.",
        },
        "minimal_remaining_question": {
            "rvas": ["0x119fb40", "0x119ffd0"],
            "question": "Which caller/consumer interprets record tag=9, payload+0x40, kind=2 as the visible army/navy morale numeric control, and does it apply any additional scale or label-specific semantics?",
            "smallest_next_static_target": "the direct caller or generic record consumer immediately above/after these two switch functions; no need to revisit 0x33ffa0/0x340c50 builder bodies",
            "status": "unresolved_without caller/consumer evidence",
        },
        "limits_and_unknowns": [
            "Ordinary static evidence only; no runtime value, freshness, or UI render observation was made.",
            "The direct record writer copies raw signed DWORD bytes but does not establish the complete N03 maximum-morale semantics.",
            "Property registration and label tokens establish registration metadata, not the numeric value callback.",
            "The exact visible widget/control consumer of the typed record was not followed; the report intentionally stops at the smallest useful writer functions.",
        ],
        "ranges": ranges,
    }
    return report


def main() -> None:
    report = make_report()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    if OUTPUT.exists():
        raise RuntimeError(f"refusing_to_overwrite:{OUTPUT}")
    with OUTPUT.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(OUTPUT)
    print(json.dumps({"new_bounded_bytes": report["decode_budget"]["new_bounded_bytes"], "ranges": len(report["ranges"])}, ensure_ascii=False))


if __name__ == "__main__":
    main()
