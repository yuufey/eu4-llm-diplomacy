"""Bound the current-country professionalism value display path.

This is an ordinary, bounded PE follow-up to ``professionalism-binding-001``.
It reuses the already decoded UI prefix and adds only the uncovered tail of
the same UI function plus the tiny country-field getter and the value widget's
local helper calls.  The important question here is whether the UI path turns
``country + 0x50`` into another unit before localization.  No game, RPM, REA
database, or production reader is used.
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

from work.discover_diplomacy import (  # noqa: E402
    PE,
    check_memory_budget,
    make_disassembler,
    rip_references,
)
from work.local_config import game_exe  # noqa: E402
from work.research_information_branch_inputs import _decode_range  # noqa: E402


EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
EXPECTED_EXE_BYTES = 38_463_016
EXPECTED_IMAGE_BASE = 0x140000000
MAX_EXE_BYTES = 64 * 1024 * 1024
MAX_SINGLE_DECODE_BYTES = 16 * 1024
MAX_TOTAL_DECODE_BYTES = 32 * 1024

# The first range is the tail not covered by professionalism-ui-001.  The
# other ranges are complete tiny helpers or a small complete pdata function.
# Total = 6,960 + 11 + 187 + 27 + 538 = 7,723 bytes.
DECODE_RANGES = (
    (0xFB88A0, 0xFBA3D0, "professionalism_ui_tail"),
    (0x9A530, 0x9A53B, "country_field_50_getter"),
    (0xFBE450, 0xFBE50B, "professionalism_value_widget"),
    (0xFAAAC0, 0xFAAADB, "country_ui_derived_object_helper"),
    (0x14B33A0, 0x14B35BA, "localized_key_lookup_helper"),
)

PROFESSIONALISM_KEY_RVA = 0x1CE7BB8
PROFESSIONALISM_KEY = b"army_professionalism\0"
VALUE_KEY_RVA = 0x1D48CC8
VALUE_KEY = b"ARMY_PROFESSIONALISM_VALUE\0"
VALUE_LITERAL_RVA = 0x1C420F8
VALUE_LITERAL = b"VALUE\0"

PRIOR_PATHS = {
    "professionalism_ui_001": ROOT
    / "work/runtime/information-military-quality-20261027-001/professionalism-ui-001.json",
    "professionalism_binding_001": ROOT
    / "work/runtime/information-military-effective-20261027-001/professionalism-binding-001.json",
    "professionalism_code_001": ROOT
    / "work/runtime/information-military-quality-20261027-001/professionalism-code-001.json",
}


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
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
        "static_va": hex(pe.base + rva),
        "file_offset": None if offset is None else hex(offset),
        "section": section,
    }


def _decode(pe: PE, md, begin: int, end: int) -> list[dict[str, Any]]:
    if end <= begin or end - begin > MAX_SINGLE_DECODE_BYTES:
        raise ValueError(f"decode range exceeds bound: {begin:#x}:{end:#x}")
    check_memory_budget()
    return _decode_range(pe, md, begin, end)


def _range_record(
    pe: PE, rows: list[dict[str, Any]], begin: int, end: int, label: str
) -> dict[str, Any]:
    raw = pe.bytes_at(begin, end - begin)
    if len(raw) != end - begin:
        raise ValueError(f"range is not file-backed: {begin:#x}:{end:#x}")
    function = pe.function(begin)
    return {
        "label": label,
        "start_rva": hex(begin),
        "end_rva_exclusive": hex(end),
        "start_va": hex(pe.base + begin),
        "end_va_exclusive": hex(pe.base + end),
        "byte_length": len(raw),
        "bytes_sha256": _sha256_bytes(raw),
        "function_boundary_from_pdata": None
        if function is None
        else [hex(function[0]), hex(function[1])],
        "decoded_instruction_count": len(rows),
        "instructions": rows,
    }


def _selected(rows: list[dict[str, Any]], addresses: list[int]) -> list[dict[str, Any]]:
    by_rva = {int(row["rva"], 16): row for row in rows}
    return [
        by_rva.get(address, {"rva": hex(address), "decode_missing": True})
        for address in addresses
    ]


def _prior(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(path)
    return json.loads(path.read_text(encoding="utf-8"))


def _token_check(pe: PE, rva: int, expected: bytes) -> dict[str, Any]:
    raw = pe.bytes_at(rva, len(expected))
    if raw != expected:
        raise ValueError(f"unexpected literal at {rva:#x}: {raw!r}")
    return {
        "location": _location(pe, rva),
        "raw_hex": raw.hex(),
        "text": expected[:-1].decode("ascii"),
    }


def _enrich_rip_candidates(pe: PE) -> list[dict[str, Any]]:
    candidates = rip_references(pe, {PROFESSIONALISM_KEY_RVA}).get(
        PROFESSIONALISM_KEY_RVA, []
    )
    result = []
    for item in candidates:
        row = dict(item)
        instruction = int(row["instruction_rva"], 16)
        fn = pe.function(instruction)
        row["instruction_location"] = _location(pe, instruction)
        row["pdata_function_verified"] = None if fn is None else [hex(fn[0]), hex(fn[1])]
        result.append(row)
    return result


def _arith(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    names = {
        "div",
        "idiv",
        "imul",
        "mul",
        "sar",
        "shr",
        "shl",
        "sal",
        "cvtsi2sd",
        "cvttsd2si",
        "cvtsi2ss",
        "cvttss2si",
    }
    return [row for row in rows if row.get("mnemonic", "").lower() in names]


def build_report() -> dict[str, Any]:
    path = game_exe()
    size = path.stat().st_size
    if size > MAX_EXE_BYTES:
        raise ValueError(f"refusing executable larger than {MAX_EXE_BYTES} bytes")
    pe = PE(path)
    digest = _sha256_bytes(pe.data)
    if digest != EXPECTED_EXE_SHA256 or size != EXPECTED_EXE_BYTES:
        raise ValueError(f"unexpected executable identity: {size} bytes {digest}")
    if pe.base != EXPECTED_IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.base:#x}")

    md, decoder = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    planned_decode = sum(end - begin for begin, end, _ in DECODE_RANGES)
    if planned_decode > MAX_TOTAL_DECODE_BYTES:
        raise ValueError(f"planned decode exceeds total bound: {planned_decode}")
    decoded: dict[str, list[dict[str, Any]]] = {}
    ranges: list[dict[str, Any]] = []
    for begin, end, label in DECODE_RANGES:
        rows = _decode(pe, md, begin, end)
        decoded[label] = rows
        ranges.append(_range_record(pe, rows, begin, end, label))

    tail = decoded["professionalism_ui_tail"]
    getter = decoded["country_field_50_getter"]
    widget = decoded["professionalism_value_widget"]
    key_helper = decoded["localized_key_lookup_helper"]
    all_widget_arith = _arith(widget)
    all_key_helper_arith = _arith(key_helper)
    if not any(
        row.get("operands", "").lower() == "rax,qword ptr [rcx+0x50]"
        for row in getter
    ):
        raise ValueError("country+0x50 getter load was not found")
    if not any("QWORD PTR [rbx]" in row.get("operands", "") for row in widget):
        raise ValueError("value widget does not load the getter result")
    value_target = hex(pe.base + VALUE_KEY_RVA)
    if not any(
        row.get("rva") == hex(0xFB9289)
        and value_target in row.get("operands", "")
        for row in tail
    ):
        raise ValueError("tail does not reference the professionalism value key target")

    ui_prior = _prior(PRIOR_PATHS["professionalism_ui_001"])
    binding_prior = _prior(PRIOR_PATHS["professionalism_binding_001"])
    code_prior = _prior(PRIOR_PATHS["professionalism_code_001"])
    prior_ui_rows = ui_prior["ranges"][0].get("instructions", [])

    return {
        "schema": "information_military_professionalism_country_display_binding_static.v2",
        "status": "partial",
        "source_kind": "ordinary_pe_bounded_static_not_REA",
        "scope": "N03.army_professionalism.current_country_display_path",
        "binary": {
            "path": str(path),
            "size": size,
            "sha256": digest,
            "image_base": hex(pe.base),
            "version_pin": "EU4 1.37.4",
        },
        "method": {
            "game_or_rpm": False,
            "rea": False,
            "native_calls": False,
            "decoder": "capstone" if decoder is not None else "bounded_objdump_fallback",
            "decode_limits": {
                "max_single_bytes": MAX_SINGLE_DECODE_BYTES,
                "max_total_bytes": MAX_TOTAL_DECODE_BYTES,
                "planned_total_bytes": planned_decode,
            },
            "scope_note": (
                "The prior 0xfb4ba0..0xfb88a0 UI slice is reused by hash.  This run decodes only its "
                "6,960-byte uncovered tail, the 0x9a530 country+0x50 leaf, the value-widget leaf, "
                "and the bounded localization helper; no whole-function or whole-image disassembly."
            ),
        },
        "prior_sources": {
            name: {
                "path": p.relative_to(ROOT).as_posix(),
                "sha256": _sha256_file(p),
            }
            for name, p in PRIOR_PATHS.items()
        },
        "literal_targets": {
            "army_professionalism": _token_check(pe, PROFESSIONALISM_KEY_RVA, PROFESSIONALISM_KEY),
            "army_professionalism_value": _token_check(pe, VALUE_KEY_RVA, VALUE_KEY),
            "value_argument_literal": _token_check(pe, VALUE_LITERAL_RVA, VALUE_LITERAL),
        },
        "army_professionalism_rip_candidates": _enrich_rip_candidates(pe),
        "prior_ui_current_country_prefix": {
            "source": "professionalism-ui-001",
            "range": {
                "start_rva": "0xfb4ba0",
                "end_rva_exclusive": "0xfb88a0",
                "bytes_sha256": ui_prior["ranges"][0]["bytes_sha256"],
            },
            "selected_instructions": _selected(
                prior_ui_rows,
                [0xFB4BDD, 0xFB4BE4, 0xFB4BF5, 0xFB4BFE, 0xFB4C05, 0xFB4C0C,
                 0xFB4C0F, 0xFB4C13, 0xFB4C17, 0xFB4C1E, 0xFB4C22],
            ),
            "alias": (
                "The existing UI prefix selects the current country from global+0x1e68/0x1e60, "
                "indexes the country table via fullref high bits, and keeps that country object in R14."
            ),
        },
        "new_bounded_ranges": ranges,
        "selected_new_instructions": {
            "ui_tail_value_path": _selected(
                tail,
                [0xFB9265, 0xFB9268, 0xFB926D, 0xFB9270, 0xFB9277, 0xFB927A,
                 0xFB927F, 0xFB9282, 0xFB9289, 0xFB9294, 0xFB92B3, 0xFB92B6,
                 0xFB92CF, 0xFB92D3, 0xFB92D6],
            ),
            "country_field_50_getter": _selected(getter, [0x9A530, 0x9A534, 0x9A537, 0x9A53A]),
            "value_widget": _selected(
                widget,
                [0xFBE467, 0xFBE46A, 0xFBE4B0, 0xFBE4B3, 0xFBE4BB, 0xFBE4C1,
                 0xFBE4C6, 0xFBE4CD, 0xFBE4D0, 0xFBE4D5, 0xFBE4DD, 0xFBE4E9,
                 0xFBE4EE],
            ),
            "country_ui_derived_object_helper": _selected(
                decoded["country_ui_derived_object_helper"],
                [0xFAAAC0, 0xFAAAC4, 0xFAAACB, 0xFAAAD0],
            ),
            "localized_key_lookup_helper": _selected(
                key_helper,
                [0x14B33A0, 0x14B33BE, 0x14B33D2, 0x14B33E2, 0x14B33FB,
                 0x14B3403, 0x14B3497, 0x14B34AC, 0x14B35A8],
            ),
        },
        "display_binding": {
            "country_alias": {
                "status": "closed_static_ui_alias_reused_from_prior_prefix",
                "expression": "R14 = current country object selected by the UI prefix",
                "evidence": "professionalism-ui-001 prefix at 0xfb4bdd..0xfb4c22",
            },
            "getter": {
                "status": "closed_static_direct_leaf",
                "rva": "0x9a530",
                "static_va": hex(pe.base + 0x9A530),
                "abi": "RCX=country, RDX=out_qword",
                "effect": [
                    "RAX = QWORD PTR [RCX+0x50]",
                    "QWORD PTR [RDX] = RAX",
                    "RAX = RDX",
                ],
                "raw_bytes": pe.bytes_at(0x9A530, 0xB).hex(),
                "meaning": "The value widget obtains the current country's +0x50 QWORD through this leaf.",
            },
            "value_widget": {
                "status": "closed_as_raw_forward_to_localized_value_argument",
                "callsite_rva": "0xfb927a",
                "callsite_effect": (
                    "RCX=R14; call 0x9a530 with RDX=&[RBP+0x240]; RAX=&[RBP+0x240] is copied to R9."
                ),
                "widget_rva": "0xfbe450",
                "widget_effect": (
                    "R9 is copied to RBX and QWORD PTR [RBX] is loaded at 0xfbe4b0, then retained in the "
                    "widget's local argument frame at 0xfbe4b3 while key ARMY_PROFESSIONALISM_VALUE is resolved."
                ),
                "key_lookup_rva": "0x14b33a0",
                "argument_literal": "VALUE at 0x1c420f8",
                "arithmetic_in_widget": all_widget_arith,
                "arithmetic_in_key_lookup": [
                    {
                        **row,
                        "classification": "FNV/hash or allocator arithmetic, not a numeric conversion of the +0x50 value",
                    }
                    for row in all_key_helper_arith
                ],
            },
        },
        "candidate_display_paths": {
            "ratio_path_0xd02da0": {
                "prior_source": "professionalism-ui-001 / professionalism-code-001",
                "status": "separate_unlinked_candidate",
                "source_expression": "QWORD PTR [RSI+0x68]",
                "nominal_scale": 32768,
                "reason_not_reused": "No bounded alias connects RSI+0x68 to the current-country R14+0x50 getter path.",
            },
            "percent_path_0xd03d90": {
                "prior_source": "professionalism-ui-001 / professionalism-code-001",
                "status": "separate_unlinked_candidate",
                "source_expression": "QWORD PTR [[R14+0x68]+0x108]",
                "nominal_scale": 32768,
                "reason_not_reused": "Its R14 is local to that formatter and no static chain reaches the current-country +0x50 leaf.",
            },
        },
        "unit_and_scale": {
            "status": "public_unit_unresolved_static_boundary_identity_closed",
            "source_raw_contract": "signed/opaque QWORD at country+0x50; getter and widget perform no multiply/divide/shift/cast conversion",
            "identity_boundary": {
                "status": "closed",
                "formula": "display_argument_raw = i64_bits(country_qword_at_0x50)",
                "evidence": ["0x9a530", "0xfb927a", "0xfbe4b0", "0xfbe4b3"],
            },
            "public_semantics": {
                "status": "unresolved",
                "reason": "The generic localized argument machinery receives the raw value and the VALUE key, but the bounded EXE evidence does not contain the locale/template numeric unit or a proven scale operation.",
            },
            "do_not_infer": [
                "Do not apply the 32768 ratio/percent scale from 0xd02da0/0xd03d90 to this country+0x50 path.",
                "Do not publish percent, ducats, or a 1000/32768 scale from this identity-only forwarding chain.",
            ],
        },
        "minimum_remaining_gap": {
            "status": "locale_or_public_semantics_gap",
            "items": [
                "A pinned locale/template or independently proven formatter contract is needed to name the public unit and scale.",
                "The static chain now proves current-country R14 -> country+0x50 -> ARMY_PROFESSIONALISM_VALUE, but it does not prove a runtime FRA identity.",
            ],
        },
        "conclusion": {
            "country_display_binding": "closed: current UI R14 reaches 0x9a530, which copies country+0x50 into the ARMY_PROFESSIONALISM_VALUE argument frame",
            "conversion": "closed as identity/raw forwarding through the bounded getter and value widget; no numeric scale operation is present there",
            "public_unit_scale": "unresolved: leave N03 professionalism partial until locale/template semantics or another direct formatter contract is pinned",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT
        / "work/runtime/information-military-effective-20261027-001/professionalism-binding-002.json",
    )
    args = parser.parse_args()
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "status": report["status"],
                "planned_total_decode_bytes": report["method"]["decode_limits"]["planned_total_bytes"],
                "country_display_binding": report["conclusion"]["country_display_binding"],
                "conversion": report["conclusion"]["conversion"],
                "public_unit_scale": report["conclusion"]["public_unit_scale"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
