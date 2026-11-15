"""Extract the bounded effective land/naval morale assembly contract.

This batch is a static follow-up to the already pinned ordinary-PE reports.
It does not run REA, attach to a game, invoke native code, or disassemble a
new image.  The selected instruction windows are reconstructed from the
bounded instruction records in morale-discipline-source-001 and are included
so the report keeps the exact RVA/VA distinction and byte hashes.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-military-effective-20261027-001"
SOURCE_001 = ROOT / "work/runtime/information-military-quality-20261027-001/morale-discipline-source-001.json"
SOURCE_002 = ROOT / "work/runtime/information-military-quality-20261027-001/morale-discipline-source-002.json"
FORMATTER_SOURCE = ROOT / "work/runtime/information-trade-source-details-20261027-001/trade-details-source-index-003.json"

EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = 0x140000000
SOURCE_001_SHA256 = "93fd027a25b109214443370ba999bf07e24e3010fe687dec66820d1e32ed0276"
SOURCE_002_SHA256 = "db4bd888912fca012c32bed29fda79e6c45f0d1dfc03b989158d97a6b89baf67"
FORMATTER_SOURCE_SHA256 = "43f7f699c61ea08f7e298aeda210368c296df6d6addeb5db65ac7401f52e7674"

OUTPUT = STAGE / "morale-effective-source-001.json"


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def pin(path: Path, expected: str) -> dict:
    actual = digest(path)
    if actual != expected:
        raise RuntimeError(f"input_pin_mismatch:{path}:{actual}")
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": actual,
        "bytes": path.stat().st_size,
        "evidence_kind": "pinned_static_report_input",
    }


def load(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise RuntimeError(f"report_not_object:{path}")
    return value


def _source_range(report: dict, purpose: str) -> dict:
    for item in report["ranges"]:
        if item.get("purpose") == purpose:
            return item
    raise KeyError(purpose)


def _location(rva: int, section: str = ".text") -> dict:
    return {
        "rva": hex(rva),
        "va": hex(IMAGE_BASE + rva),
        "section": section,
    }


def bounded_window(report: dict, purpose: str, start: int, end: int) -> dict:
    """Reconstruct a contiguous byte window from an existing bounded report."""
    source = _source_range(report, purpose)
    source_start = int(source["start"]["rva"], 16)
    source_end = int(source["end_exclusive"]["rva"], 16)
    if not (source_start <= start < end <= source_end):
        raise RuntimeError(f"window_outside_source:{purpose}:{start:#x}:{end:#x}")
    raw = bytearray(end - start)
    covered: set[int] = set()
    selected = []
    for instruction in source["instructions"]:
        address = int(instruction["rva"], 16)
        code = bytes.fromhex(instruction["bytes"])
        instruction_end = address + len(code)
        if address < end and instruction_end > start:
            if address < start or instruction_end > end:
                raise RuntimeError(
                    f"window_splits_instruction:{purpose}:{address:#x}:{instruction_end:#x}"
                )
            raw[address - start : instruction_end - start] = code
            covered.update(range(address, instruction_end))
            selected.append(instruction)
    if covered != set(range(start, end)):
        missing = sorted(set(range(start, end)) - covered)
        raise RuntimeError(f"window_has_gap:{purpose}:{missing[:4]}")
    raw_bytes = bytes(raw)
    return {
        "source_purpose": purpose,
        "start": _location(start),
        "end_exclusive": _location(end),
        "byte_length": len(raw_bytes),
        "bytes_hex": raw_bytes.hex(),
        "bytes_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "source_pdata": source.get("pdata"),
        "instructions": selected,
        "evidence_kind": "reused_bounded_ordinary_PE_instruction_record",
    }


def range_pin(report: dict, purpose: str) -> dict:
    source = _source_range(report, purpose)
    return {
        "purpose": purpose,
        "start": source["start"],
        "end_exclusive": source["end_exclusive"],
        "byte_length": source["byte_length"],
        "bytes_sha256": source["bytes_sha256"],
        "pdata": source.get("pdata"),
        "evidence_kind": "reused_bounded_ordinary_PE_range",
    }


def instruction(report: dict, purpose: str, rva: int) -> dict:
    source = _source_range(report, purpose)
    for item in source["instructions"]:
        if int(item["rva"], 16) == rva:
            return item
    raise KeyError(f"{purpose}:{rva:#x}")


def make_report() -> dict:
    source_001 = load(SOURCE_001)
    source_002 = load(SOURCE_002)
    formatter_source = load(FORMATTER_SOURCE)

    source_pins = [
        pin(SOURCE_001, SOURCE_001_SHA256),
        pin(SOURCE_002, SOURCE_002_SHA256),
        pin(FORMATTER_SOURCE, FORMATTER_SOURCE_SHA256),
    ]

    land_assembly = bounded_window(source_001, "land_morale_display_getter", 0x34055F, 0x3405B1)
    naval_assembly = bounded_window(source_001, "naval_morale_display_getter", 0x340FEA, 0x341046)
    land_helper = bounded_window(source_001, "land_morale_modifier_adjustment_helper", 0x33FE11, 0x33FF82)
    naval_helper_a = bounded_window(source_001, "naval_morale_modifier_adjustment_helper", 0x340A70, 0x340B82)
    naval_helper_b = bounded_window(source_001, "naval_morale_modifier_adjustment_helper", 0x340B82, 0x340C31)
    land_fallback = bounded_window(source_001, "land_morale_display_getter", 0x34071B, 0x3407CF)
    naval_fallback = bounded_window(source_001, "naval_morale_display_getter", 0x3411AA, 0x3412D7)
    land_callsite = bounded_window(source_001, "land_and_naval_morale_labels_and_calls", 0xFB8048, 0xFB80CF)
    naval_callsite = bounded_window(source_001, "land_and_naval_morale_labels_and_calls", 0xFB80F8, 0xFB817F)
    country_selection = bounded_window(source_001, "military_quality_view_current_country_selection", 0xFB4C05, 0xFB4C22)

    formatter_guard = None
    for guard in formatter_source.get("code_guards", []):
        if guard.get("name") == "fixed_point_formatter_14bc950":
            formatter_guard = {
                "name": guard["name"],
                "kind": guard["kind"],
                "rva": guard["rva"],
                "rva_end_exclusive": guard["rva_end_exclusive"],
                "va": guard["va"],
                "va_end_exclusive": guard["va_end_exclusive"],
                "sha256": guard["sha256"],
                "pdata_boundary": [guard["rva"], guard["rva_end_exclusive"]],
                "evidence_kind": "pinned_bounded_formatter_report; no new decode",
            }
            break
    if formatter_guard is None:
        raise RuntimeError("fixed_point_formatter_guard_missing")

    land_consumer = range_pin(source_002, "country_indexed_land_field_consumer")
    naval_consumer = range_pin(source_002, "country_indexed_naval_field_consumer")

    report = {
        "report_id": "information-military-effective-morale-source-001",
        "schema": "information_military_effective_morale_static.v1",
        "evidence_kind": "ordinary_bounded_PE_static_reassembly_from_pinned_reports",
        "target": {
            "exe_sha256": EXE_SHA256,
            "image_base": hex(IMAGE_BASE),
            "address_rule": "VA = image_base + RVA; all end addresses are exclusive",
            "runtime_or_RPM": False,
            "game_or_native_calls": False,
            "REA_query": False,
            "whole_image_disassembly": False,
        },
        "source_pins": source_pins,
        "decode_budget": {
            "new_decode_bytes": 0,
            "reused_bounded_window_bytes": sum(
                item["byte_length"]
                for item in (
                    land_assembly,
                    naval_assembly,
                    land_helper,
                    naval_helper_a,
                    naval_helper_b,
                    land_fallback,
                    naval_fallback,
                    land_callsite,
                    naval_callsite,
                    country_selection,
                )
            ),
            "max_new_decode_bytes_for_batch": 0xC000,
            "max_per_new_range": 0x4000,
            "note": "No new PE decode was needed; all selected bytes are reconstructed from pinned bounded ordinary-PE records.",
        },
        "country_binding": {
            "military_quality_selection_window": country_selection,
            "selection_steps": [
                "0xfb4c05 loads the selected full reference from the view state.",
                "0xfb4c0f shifts the full reference right by 32 and sign-extends the 16-bit slot.",
                "0xfb4c17 loads the country table at module-global+0x118 and 0xfb4c1e selects the country pointer into R14.",
                "0xfb80ba/0xfb816a move that same R14 into RCX for the land/naval builders.",
            ],
            "land_builder_rcx": "current country pointer (R14 at caller; saved as R15 at 0x33ffc2)",
            "naval_builder_rcx": "current country pointer (R14 at caller; saved as RDI at 0x340c6e)",
        },
        "formatter_contract": {
            "helper_rva": "0x14bc950",
            "helper_va": "0x1414bc950",
            "range": formatter_guard,
            "caller_arguments": {
                "rcx": "destination string object",
                "rdx": "address of a signed DWORD raw/effective value",
                "r8d": 2,
                "r9b": 1,
            },
            "display_formula_from_pinned_formatter_report": "signed_i32(raw_or_effective) / 1000",
            "scope": "This closes the displayed fixed-point scale; it does not by itself prove freshness or a standalone getter ABI.",
        },
        "fields": {
            "army_morale": {
                "native_label_context": "LAND_MORALE display branch at caller 0xfb804e/0xfb80bd",
                "country_storage": {
                    "offset": "0x9874",
                    "width_bits": 32,
                    "signed": True,
                    "neutral_raw": 1000,
                    "scale": 1000,
                    "unit": "fixed-point morale multiplier",
                    "consumer_range": land_consumer,
                },
                "gate": {
                    "rva": "0x34055f",
                    "instruction": instruction(source_001, "land_morale_display_getter", 0x34055F),
                    "condition": "i32(country+0xe0c) == 1000",
                    "semantic_status": "comparison is proven; the business name of country+0xe0c is unresolved",
                },
                "non_neutral_assembly": {
                    "window": land_assembly,
                    "formula": "effective_raw = wrap_i32(i32(country+0x9874) - i32(land_helper(country, input=1000, r9=0)))",
                    "steps": [
                        "0x340570 loads DWORD [R15+0x9874] into EBX.",
                        "0x340577 stores 0x3e8 as the helper input.",
                        "0x34058c calls 0x33fca0 with RCX=country, RDX=output slot, R8=input slot, R9D=0.",
                        "0x340591 subtracts the helper output DWORD from EBX with 32-bit wrap.",
                        "0x340593 stores EBX as the value passed by address to 0x14bc950 with kind=2/flag=1.",
                    ],
                    "arithmetic": "The subtraction is DWORD arithmetic; interpret the final slot as signed i32 before dividing by 1000 for display.",
                },
                "neutral_fallback": {
                    "window": land_fallback,
                    "branch_target": "0x34071b",
                    "observed": [
                        "The neutral branch does not load country+0x9874.",
                        "It resolves country+0x28c0 and builds a keyed record with key 0x2a and a 0x3e8 value before the output-object path.",
                    ],
                    "status": "fallback scalar is not independently closed; a raw +0x9874-only reader would be wrong on this branch",
                },
                "helper": {
                    "function_rva": "0x33fca0",
                    "range": range_pin(source_001, "land_morale_modifier_adjustment_helper"),
                    "core_window": land_helper,
                    "direct_dependencies": [
                        "country+0x2440 then +0x28 supplies a base term",
                        "country+0x28c0 is passed to 0x93d5c0; keyed fallback 0x252 is read from the returned container",
                        "module-global 0x142358060+0xdf00 and +0x1000 expose indirect [vtable+0x8] callbacks",
                        "the final stage uses key 0x2a and clamps against DWORD [0x14233da38]+0xa",
                    ],
                    "arithmetic_observed": "The helper combines signed DWORD terms, forms 64-bit products, uses the high-product path followed by SAR 7 and sign correction, truncates to DWORD, then repeats a scaled stage and clamps.",
                    "status": "assembly path closed for the helper call; callback/container values and their business semantics remain unresolved",
                },
                "status": "non_neutral_effective_display_assembly_closed; neutral_fallback_and_dynamic_helper_inputs_unresolved",
            },
            "naval_morale": {
                "native_label_context": "NAVAL_MORALE display branch at caller 0xfb80fe/0xfb816d",
                "country_storage": {
                    "offset": "0x987c",
                    "width_bits": 32,
                    "signed": True,
                    "neutral_raw": 1000,
                    "scale": 1000,
                    "unit": "fixed-point morale multiplier",
                    "consumer_range": naval_consumer,
                },
                "gate": {
                    "rva": "0x340fea",
                    "instruction": instruction(source_001, "naval_morale_display_getter", 0x340FEA),
                    "condition": "i32(country+0xe10) == 1000",
                    "semantic_status": "comparison is proven; the business name of country+0xe10 is unresolved",
                },
                "non_neutral_assembly": {
                    "window": naval_assembly,
                    "formula": "effective_raw = wrap_i32(i32(country+0x987c) - i32(naval_helper(country, input=1000)))",
                    "steps": [
                        "0x340ffa loads DWORD [RDI+0x987c] into EBX.",
                        "0x341000 stores 0x3e8 as the helper input.",
                        "0x34101b calls 0x340a70 with RCX=country, RDX=output slot, R8=input slot.",
                        "0x341020 subtracts the helper output DWORD from EBX with 32-bit wrap.",
                        "0x341022 stores EBX as the value passed by address to 0x14bc950 with kind=2/flag=1.",
                    ],
                    "arithmetic": "The subtraction is DWORD arithmetic; interpret the final slot as signed i32 before dividing by 1000 for display.",
                },
                "neutral_fallback": {
                    "window": naval_fallback,
                    "branch_target": "0x3411aa",
                    "observed": [
                        "The neutral branch does not load country+0x987c.",
                        "It resolves country+0x28c0 and builds keyed records using keys 0x253 and 0x2b, each with a 0x3e8 value, before the output-object path.",
                    ],
                    "status": "fallback scalar is not independently closed; a raw +0x987c-only reader would be wrong on this branch",
                },
                "helper": {
                    "function_rva": "0x340a70",
                    "range": range_pin(source_001, "naval_morale_modifier_adjustment_helper"),
                    "core_windows": [naval_helper_a, naval_helper_b],
                    "direct_dependencies": [
                        "country+0x2440 then +0x2c supplies a base term",
                        "country+0x28c0 is passed to 0x93d5c0; keyed fallback 0x253 is read from the returned container",
                        "module-global 0x142358060+0xdf60 and +0x1060 expose indirect [vtable+0x8] callbacks",
                        "the second stage uses key 0x2b and clamps against DWORD [0x14233da38]+0xa",
                    ],
                    "arithmetic_observed": "The helper combines signed DWORD terms, uses the high-product path followed by SAR 7 and sign correction, truncates to DWORD, then repeats a scaled stage and clamps.",
                    "status": "assembly path closed for the helper call; callback/container values and their business semantics remain unresolved",
                },
                "status": "non_neutral_effective_display_assembly_closed; neutral_fallback_and_dynamic_helper_inputs_unresolved",
            },
        },
        "static_conclusion": {
            "newly_closed": [
                "The UI current-country alias is the country pointer selected through full-reference high-16 slot and table+0x118, passed in RCX to both builders.",
                "For the non-neutral gate branches, each builder's final fixed-point display input is an explicit 32-bit raw-field-minus-helper assembly.",
                "The land and naval raw fields are distinct signed DWORD offsets (0x9874 and 0x987c), and the common formatter displays the signed result at scale 1000.",
                "The neutral branches are proven to use keyed country-container fallback records rather than the raw field.",
            ],
            "not_closed": [
                "The complete standalone maximum-morale getter ABI is not present: both named builders return formatted string/object pointers.",
                "The helper outputs depend on country+0x28c0 keyed records, country+0x2440 terms, module-manager indirect callbacks, and their exact value semantics; those direct callees/callback bodies were not decoded in this bounded follow-up.",
                "The semantic names of gate fields country+0xe0c/country+0xe10 and the complete neutral fallback scalar are unresolved.",
                "No runtime value, freshness, process identity, or main-thread atomicity was observed.",
            ],
            "implementation_boundary": "A production reader may not expose country+0x9874/0x987c as complete morale. It can only reproduce the non-neutral display scalar after closing the listed helper dependencies and must handle the keyed neutral fallback separately.",
        },
        "runtime_evidence": {
            "performed": False,
            "RPM": False,
            "game_calls": False,
            "result": "static_only",
        },
        "limits_and_unknowns": [
            "This report reuses the exact bounded ordinary-PE instruction records pinned by source-001/source-002; it does not claim new REA evidence.",
            "The formatter report is an independent static report for the same fixed executable and is used only for the signed_i32/1000 display contract.",
            "All cited code ranges retain RVA/VA, byte length, and byte SHA; no ASLR absolute pointer is used as a profile guard here.",
            "No conclusion is drawn about runtime freshness or whether the display builder's adjusted value equals every other game subsystem's maximum-morale scalar.",
        ],
    }
    return report


def main() -> None:
    if OUTPUT.exists():
        raise RuntimeError(f"refusing_to_overwrite:{OUTPUT}")
    report = make_report()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({
        "output": OUTPUT.relative_to(ROOT).as_posix(),
        "bytes": OUTPUT.stat().st_size,
        "sha256": digest(OUTPUT),
        "new_decode_bytes": report["decode_budget"]["new_decode_bytes"],
        "reused_bounded_window_bytes": report["decode_budget"]["reused_bounded_window_bytes"],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
