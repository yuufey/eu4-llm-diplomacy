"""Bounded UI formatter evidence for the army_tradition field.

The large military-quality UI report was produced by the parent worker.  This
follow-up only decodes its small formatter call target and records the
selector-specific field access and decimal scale.  It deliberately does not
redecode the UI function or claim a runtime country identity.
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

WRAPPER_RANGE = (0x4109C0, 0x4109E6, "army_tradition_ui_formatter_wrapper")
HELPER_RANGE = (0x410420, 0x4109BF, "generic_value_to_text_helper")

SOURCE003 = (
    ROOT
    / "work"
    / "runtime"
    / "information-military-quality-20261027-001"
    / "tradition-source-003.json"
)
UI_SOURCE = (
    ROOT
    / "work"
    / "runtime"
    / "information-military-quality-20261027-001"
    / "professionalism-ui-001.json"
)


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


def _decode(pe: PE, md, begin: int, end: int) -> list[dict[str, Any]]:
    check_memory_budget()
    if end <= begin or end - begin > MAX_SINGLE_DECODE_BYTES:
        raise ValueError(f"decode range exceeds bound: {begin:#x}:{end:#x}")
    return _decode_range(pe, md, begin, end)


def _range_record(
    pe: PE, rows: list[dict[str, Any]], begin: int, end: int, label: str
) -> dict[str, Any]:
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
        "pdata_function": None
        if function is None
        else [hex(function[0]), hex(function[1])],
        "instruction_count": len(rows),
    }


def _selected(rows: list[dict[str, Any]], addresses: list[int]) -> list[dict[str, Any]]:
    by_rva = {int(row["rva"], 16): row for row in rows}
    return [by_rva.get(address, {"rva": hex(address), "decode_missing": True}) for address in addresses]


def _binary_identity(path: Path) -> tuple[PE, str, int]:
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
    return pe, binary_sha, size


def build_report() -> dict[str, Any]:
    path = game_exe()
    pe, binary_sha, size = _binary_identity(path)
    md, decoder = make_disassembler(ROOT / "work" / "deps")

    wrapper_rows = _decode(pe, md, WRAPPER_RANGE[0], WRAPPER_RANGE[1])
    helper_rows = _decode(pe, md, HELPER_RANGE[0], HELPER_RANGE[1])
    planned_decode = (WRAPPER_RANGE[1] - WRAPPER_RANGE[0]) + (
        HELPER_RANGE[1] - HELPER_RANGE[0]
    )
    if planned_decode > MAX_TOTAL_DECODE_BYTES:
        raise ValueError(f"planned decode exceeds bound: {planned_decode}")

    return {
        "schema": "information_military_quality_static_source_v4",
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
            "follow_up_scope": "only the UI formatter wrapper and its small direct helper",
            "decode_limits": {
                "max_single_bytes": MAX_SINGLE_DECODE_BYTES,
                "max_total_bytes": MAX_TOTAL_DECODE_BYTES,
                "planned_total_bytes": planned_decode,
            },
            "large_ui_function_reused": True,
            "runtime_validation": False,
        },
        "prior_sources": {
            "source003": {"path": str(SOURCE003), "sha256": _sha256_file(SOURCE003)},
            "ui_source": {
                "path": str(UI_SOURCE),
                "sha256": _sha256_file(UI_SOURCE),
                "reported_schema": "information_military_professionalism_static.v1",
                "reported_ui_range": ["0xfb4ba0", "0xfb88a0"],
            },
        },
        "ui_callsite_reused": {
            "provenance": str(UI_SOURCE),
            "provenance_sha256": _sha256_file(UI_SOURCE),
            "country_alias_chain": {
                "source_report": "professionalism-ui-001",
                "reported_range": ["0xfb4c05", "0xfb4c1e"],
                "result": "R14 is the current country object alias at the formatter call",
            },
            "army_tradition_call": [
                {
                    "rva": "0xfb7d0e",
                    "bytes": "488d15630fcf00",
                    "instruction": "LEA RDX,[RIP+0xcf0f63] -> 0x141ca8c78",
                    "meaning": "army_tradition localization key address from the parent UI report",
                },
                {
                    "rva": "0xfb7d73",
                    "bytes": "4c8d45d0",
                    "instruction": "LEA R8,[RBP-0x30]",
                    "meaning": "formatter-side source/value context passed by the UI caller",
                },
                {
                    "rva": "0xfb7d77",
                    "bytes": "488d9540020000",
                    "instruction": "LEA RDX,[RBP+0x240]",
                    "meaning": "text/output buffer argument",
                },
                {
                    "rva": "0xfb7d7e",
                    "bytes": "498bce",
                    "instruction": "MOV RCX,R14",
                    "meaning": "current country object argument",
                },
                {
                    "rva": "0xfb7d81",
                    "bytes": "e83a8c45ff",
                    "instruction": "CALL 0x1404109c0",
                    "meaning": "small formatter wrapper analysed below",
                },
            ],
        },
        "bounded_ranges": [
            _range_record(pe, wrapper_rows, *WRAPPER_RANGE),
            _range_record(pe, helper_rows, *HELPER_RANGE),
        ],
        "selected_instructions": {
            "wrapper": _selected(
                wrapper_rows,
                [
                    0x4109C0,
                    0x4109C2,
                    0x4109C6,
                    0x4109CC,
                    0x4109D1,
                    0x4109D4,
                    0x4109D8,
                    0x4109DD,
                    0x4109E0,
                    0x4109E4,
                    0x4109E5,
                ],
            ),
            "selector_and_signed_value_path": _selected(
                helper_rows,
                [
                    0x410441,
                    0x410444,
                    0x410447,
                    0x41044A,
                    0x41048C,
                    0x410491,
                    0x410496,
                    0x410499,
                    0x41049C,
                    0x4104A0,
                    0x4104A3,
                    0x4104B4,
                    0x4104B7,
                    0x4104C5,
                    0x4104CD,
                ],
            ),
            "signed_decimal_scale_path": _selected(
                helper_rows,
                [
                    0x410684,
                    0x410687,
                    0x41068A,
                    0x41068C,
                    0x410691,
                    0x4106A4,
                    0x4106A9,
                    0x4106AB,
                    0x4106AE,
                    0x4106B2,
                    0x4106B5,
                    0x4106B8,
                    0x4106BB,
                    0x4106BE,
                    0x4106C1,
                    0x4106D8,
                    0x4106DF,
                    0x4106E1,
                    0x4106E7,
                    0x4106EA,
                ],
            ),
        },
        "field_findings": {
            "army_tradition": {
                "raw_storage": {
                    "source": "tradition-source-003",
                    "source_sha256": _sha256_file(SOURCE003),
                    "country_offset": "0xe40",
                    "width": "signed 32-bit DWORD load/store",
                    "setter_domain": "inclusive 0..100000",
                },
                "formatter_wrapper": {
                    "rva_range": ["0x4109c0", "0x4109e6"],
                    "pdata_range": ["0x4109c0", "0x4109e6"],
                    "arguments": {
                        "rcx": "forwarded unchanged to helper; UI report binds it to current country R14",
                        "rdx": "saved and returned as RAX after helper; UI output/text buffer",
                        "r8": "saved in wrapper stack frame; helper selector is set independently",
                        "r9d": "0x58",
                    },
                    "selector_setup": [
                        "MOV R9D,0x58 at 0x4109c6",
                        "LEA R8D,[R9-2] at 0x4109d4, therefore R8D=0x56",
                        "CALL 0x140410420 at 0x4109d8",
                    ],
                },
                "helper_selector_and_load": {
                    "rva_range": ["0x410420", "0x4109bf"],
                    "argument_aliases": [
                        "MOV EDI,R9D at 0x410441",
                        "MOV ESI,R8D at 0x410444",
                        "MOV R15,RDX at 0x410447",
                        "MOV RBX,RCX at 0x41044a",
                    ],
                    "selector": {
                        "army_selector": "0x56",
                        "instructions": [
                            "MOV ECX,0xe40 at 0x41048c",
                            "MOV EDX,0xe44 at 0x410491",
                            "CMP ESI,0x56 at 0x410496",
                            "CMOVNE ECX,EDX at 0x410499",
                        ],
                        "meaning": "the wrapper's 0x56 selects country+0xe40; the alternate selector selects country+0xe44",
                    },
                    "signed_value_operations": [
                        "MOVSXD RDX,DWORD PTR [RCX+RBX] at 0x41049c",
                        "MOVSXD RAX,DWORD PTR [RAX] at 0x4104a0",
                        "IMUL RDX,RAX at 0x4104a3",
                        "MOV R14,RDX; SAR R14,7 at 0x4104b4..0x4104b7",
                        "TEST R14D,R14D; CMOVS R14D,0 at 0x4104c5..0x4104cd",
                    ],
                    "direct_callee_followed": False,
                    "unresolved_multiplier": "the pointer-producing 0x14093d5c0 path and its signed value were not followed; this report does not replace that multiplier with a guessed runtime value",
                },
                "explicit_formatter_scale": {
                    "status": "closed_for_the_selected_ui_decimal_renderer",
                    "instructions": [
                        "TEST R14D,R14D and NEG ESI for signed sign handling at 0x410687..0x410691",
                        "MOV EAX,0x10624dd3; IMUL ESI at 0x4106a4..0x4106a9 (integer quotient path)",
                        "MOV R14D,EDX; SAR R14D,6; SHR EAX,31; ADD R14D,EAX at 0x4106ab..0x4106b8",
                        "CALL 0x1417061a0 with ECX=R14D at 0x4106bb..0x4106c1",
                        "IMUL EAX,R14D,0x3e8 at 0x4106d8",
                        "SUB ESI,EAX; LEA ECX,[RSI+0x3e8] at 0x4106df..0x4106e1",
                        "CALL 0x1417061a0 with ECX=the fractional remainder at 0x4106e7..0x4106ea",
                    ],
                    "scale": 1000,
                    "semantics": "the helper renders a signed fixed-point value as integer part plus a base-1000 fractional remainder; 0x3e8 is an explicit formatter constant, not inferred from the 100000 clamp",
                    "field_binding": "the same helper invocation uses selector 0x56 to load country+0xe40 before entering this generic signed decimal path",
                },
                "publication_caveats": [
                    "This is static formatter evidence only; no game/RPM/runtime country identity was collected.",
                    "The generic helper's additional signed multiplier path remains unresolved, so no new public numeric value is fabricated.",
                    "The formatter uses the 0x56 selector for army_tradition and the alternate 0xe44 selector is not mapped to this field.",
                ],
            }
        },
        "conclusion": {
            "army_tradition": "source003's scale candidate is upgraded to explicit static UI formatter evidence: selector 0x56 selects country+0xe40 and the selected signed decimal renderer uses scale 1000.",
            "publication": "retain static/partial status until the runtime/source contract separately verifies the country context and any unresolved multiplier semantics",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT
        / "work"
        / "runtime"
        / "information-military-quality-20261027-001"
        / "tradition-source-004.json",
    )
    args = parser.parse_args()
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "status": report["status"],
                "planned_total_decode_bytes": report["method"]["decode_limits"][
                    "planned_total_bytes"
                ],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
