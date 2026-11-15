"""Bounded ordinary-PE follow-up for military morale/discipline semantics.

This follow-up deliberately separates country-owned morale-related caches from
the complete country maximum-morale value.  It reuses the large, already
audited source-001 report for the two UI builders and decodes only small new
windows around labelled score consumers, an additional naval consumer, and
the discipline effective-value helper.
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
MAX_TOTAL_DECODE = 0x2000
SOURCE_001 = ROOT / "work/runtime/information-military-quality-20261027-001/morale-discipline-source-001.json"
SOURCE_001_SHA256 = "93fd027a25b109214443370ba999bf07e24e3010fe687dec66820d1e32ed0276"

# These are intentionally small windows.  The first two show a country
# lookup followed by the raw land/naval field consumers; the next two show the
# labelled/ratio consumers; the last one closes the discipline base/callback
# path.  No large UI or formatter body is decoded here.
RANGES = (
    (0x23E422, 0x23E4A7, "country_indexed_land_field_consumer"),
    (0x237593, 0x2375FF, "country_indexed_naval_field_consumer"),
    (0x3BE22C, 0x3BE340, "mil_score_morale_field_consumer"),
    (0x3BD2C4, 0x3BD360, "additional_naval_ratio_field_consumer"),
    (0x341850, 0x341904, "discipline_effective_value_and_manager_callback"),
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


def _range_record(pe: PE, md, start: int, end: int, purpose: str):
    raw = pe.bytes_at(start, end - start)
    pdata = pe.function(start)
    return {
        "purpose": purpose,
        "start": _location(pe, start),
        "end_exclusive": _location(pe, end),
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
    }


def _source_001_pin():
    if not SOURCE_001.exists():
        raise RuntimeError(f"missing prior report: {SOURCE_001}")
    actual = hashlib.sha256(SOURCE_001.read_bytes()).hexdigest()
    if actual != SOURCE_001_SHA256:
        raise RuntimeError(f"source-001 changed: {actual}")
    return {"path": str(SOURCE_001), "sha256": actual}


def run(output: Path):
    check_memory_budget()
    prior = _source_001_pin()
    pe = PE(game_exe())
    actual_sha = hashlib.sha256(pe.data).hexdigest()
    if actual_sha != EXE_SHA256 or pe.base != IMAGE_BASE:
        raise RuntimeError(
            f"unexpected executable identity: sha={actual_sha} base={hex(pe.base)}"
        )
    total = sum(end - start for start, end, _ in RANGES)
    if total > MAX_TOTAL_DECODE:
        raise RuntimeError(f"bounded decode budget exceeded: {total} > {MAX_TOTAL_DECODE}")
    if any(end <= start or end - start > 0x4000 for start, end, _ in RANGES):
        raise RuntimeError("invalid bounded range")

    md, decoder = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    report = {
        "schema": "information_military_morale_discipline_static.v2",
        "evidence_kind": "ordinary_bounded_PE_not_REA",
        "exe": {
            "path": str(pe.path),
            "sha256": EXE_SHA256,
            "bytes": len(pe.data),
            "static_image_base": hex(pe.base),
        },
        "prior_report": prior,
        "runtime_or_RPM": False,
        "game_or_native_calls": 0,
        "whole_image_disassembly": False,
        "decoder": "Capstone " + decoder.__version__ if md is not None else "bounded objdump",
        "decode_budget": {
            "new_bounded_bytes": total,
            "max_new_bounded_bytes": MAX_TOTAL_DECODE,
            "max_per_range": 0x4000,
        },
        "findings": {
            "raw_morale_fields": {
                "status": "country_owned_morale_related_cache; complete_maximum_unresolved",
                "land": {
                    "field_rva": "0x9874",
                    "width_bits": 32,
                    "signed_consumer": "0x23e451 and 0x3be231 use MOVSXD",
                    "neutral_raw": 1000,
                    "scale": 1000,
                    "unit": "fixed-point multiplier (1000 = 1.0)",
                    "evidence": [
                        "0x23e430..0x23e44d selects a country through fullref>>32 and country_table+0x118 before reading country+0x9874.",
                        "0x23e451 sign-extends the DWORD, then 0x23e465/0x23e47e multiply the value by 0x3e8 in a bounded calculation added to [r13+0x50].",
                        "0x3be231 reads the same signed DWORD, multiplies by 0x3e8, and the enclosing path is labelled MIL_SCORE_MORALE at 0x3be326.",
                    ],
                    "not_proven": "The bounded paths do not expose a standalone country maximum-land-morale getter or prove that this cache alone is the final N03 country value.",
                },
                "naval": {
                    "field_rva": "0x987c",
                    "width_bits": 32,
                    "signed_consumer": "0x2375b4 and 0x3bd315 use MOVSXD",
                    "neutral_raw": 1000,
                    "scale": 1000,
                    "unit": "fixed-point multiplier (1000 = 1.0)",
                    "evidence": [
                        "0x237593..0x2375b0 selects a country from a full-reference-derived table slot before reading country+0x987c.",
                        "0x2375b4 sign-extends the DWORD and applies a *0x3e8 fixed-point calculation before comparing it with another accumulator.",
                        "0x3bd315 reads the same field after a ratio calculation and applies signed 64-bit arithmetic plus *0x3e8; the selected path is not a standalone maximum-naval-morale return.",
                    ],
                    "not_proven": "No bounded evidence identifies a standalone country maximum-naval-morale getter or proves the ratio/score consumer is the complete N03 value.",
                },
            },
            "display_builders": {
                "status": "string_object_builders_not_scalar_getters",
                "land": {
                    "function_rva": "0x33ffa0",
                    "caller_rvas": ["0x21fc89", "0xfb80bd", "0x119fc78"],
                    "return_evidence_from_source_001": [
                        "0x3407cf MOV RAX,R12 immediately precedes the epilogue and 0x3407ec RET.",
                        "The function feeds the large formatter at 0x14bc950 and returns the formatted object pointer.",
                    ],
                },
                "naval": {
                    "function_rva": "0x340c50",
                    "caller_rvas": ["0x21fcae", "0xfb816d", "0x11a0117"],
                    "return_evidence_from_source_001": [
                        "0x34140c MOV RAX,RSI immediately precedes the epilogue and 0x341425 RET.",
                        "The function feeds the large formatter at 0x14bc950 and returns the formatted object pointer.",
                    ],
                },
                "interpretation": "Neither builder is a complete numeric country getter; their field reads are display inputs and their returns are UI/string-object pointers.",
            },
            "discipline": {
                "status": "effective_keyed_getter_static_with_unresolved_indirect_callback",
                "country_container_offset": "0x28c0",
                "entry_key": "0x77",
                "entry_value_offset": "0x4",
                "entry_value_width_bits": 32,
                "output_width_bits": 32,
                "base_raw": 1000,
                "minimum_raw": 10,
                "scale": 1000,
                "unit": "fixed-point multiplier (1000 = 1.0)",
                "manager_global": {
                    "rva": "0x2358060",
                    "va": "0x142358060",
                    "callback_offset": "0x2ce0",
                },
                "formula_observed": [
                    "0x341875 initializes [rdx] to 0x3e8.",
                    "0x34187b obtains the country+0x28c0 keyed container; the scan at 0x3418b7 compares entry keys with 0x77, and the hit path reads the entry DWORD (the alternate compact representation reads +0x3bc).",
                    "0x3418d2 loads module-derived global 0x142358060, then 0x3418d9 reads +0x2ce0. If non-null, 0x3418f0 calls the indirect vtable slot [callback+0x8] with local output storage; 0x3418f6 adds the callback DWORD to [rdx].",
                    "0x3418fa..0x341904 clamps the signed effective DWORD to at least 10.",
                ],
                "callback_unknown": "The indirect +0x2ce0 callback body and its own source semantics were not decoded; omitting it would understate the effective country result.",
                "semantic_binding": "The DISCIPLINE/DISCIPLINE_LONG label callers in source-001 bind this helper to discipline; the shared helper also appears in a MILITARY_TACTICS explanatory branch, which must remain separate.",
            },
        },
        "ranges": [
            _range_record(pe, md, start, end, purpose)
            for start, end, purpose in RANGES
        ],
        "limits_and_unknowns": [
            "This is ordinary static evidence only; it does not observe a live value, freshness, process identity, or runtime callback result.",
            "The 1000 convention is a fixed-point multiplier convention, not proof that raw 1000 is a final morale score of 1.0 after all modifiers.",
            "The +0x9874/+0x987c fields are country-indexed and consumed by labelled score/display paths, but a complete country maximum land/naval morale scalar path remains unresolved in the bounded evidence.",
            "The 0x33ffa0 and 0x340c50 functions are explicitly retained as display/string builders; do not expose their return pointers as numeric morale values.",
            "The discipline result is closer to an implementable effective getter, but the manager callback at +0x2ce0 is indirect and its internal contribution remains unresolved.",
            "Large formatter 0x14bc950 and unrelated large UI functions were not decoded again.",
        ],
    }
    check_memory_budget()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    print(
        json.dumps(
            {
                "output": str(output),
                "bytes": output.stat().st_size,
                "sha256": digest,
                "new_decode_bytes": total,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python work/research_information_military_morale_002.py OUTPUT.json")
    run(Path(sys.argv[1]))
