"""Bounded ordinary-PE evidence for the N03 military-quality fields.

This report is deliberately narrower than a native reader.  It proves the
literal field registrations and the bounded UI formatting paths that can be
located from those literals, while keeping the country-object getter and
runtime observation questions explicit when the bounded static evidence does
not close them.  It never attaches to the game, calls native code, uses RPM,
or uses a whole-image REA analysis.
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

from work.discover_diplomacy import PE, check_memory_budget, make_disassembler, rip_references  # noqa: E402
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


# These are complete .pdata functions or small, explicit helper windows.  The
# largest function is 0x265c bytes; the total is 26,753 bytes.  The helper
# window crosses only three adjacent .pdata fragments and is bounded to the
# key-lookup body used by the field registrar.
DECODE_RANGES = (
    (0x6A7B20, 0x6A878C, "army_tradition_field_registration"),
    (0x8CDaf0, 0x8D114C, "army_tradition_ui_label_dispatch"),
    (0x8ED690, 0x8EED99, "country_scope_field_registration"),
    (0x8F40F0, 0x8F42FB, "field_descriptor_registration_helper"),
    (0x8EEDA0, 0x8EEEF0, "bounded_field_key_lookup_helper"),
    (0xB33AC0, 0xB3457D, "army_professionalism_snapshot_registration"),
    (0xB43450, 0xB437A8, "descriptor_constructor_callsite"),
    (0xB3D860, 0xB3DB53, "descriptor_object_constructor"),
    (0x10B22B3, 0x10B22CF, "descriptor_slot_copy_window"),
    (0xD02DA0, 0xD0360D, "army_professionalism_ratio_display"),
    (0xD03D90, 0xD042C8, "army_professionalism_percent_display"),
)


TARGET_RVAS = {
    "army_tradition": 0x1CA8C78,
    "army_professionalism": 0x1CE7BB8,
}


def _sha256(path: Path) -> str:
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


def _ascii(raw: bytes) -> str:
    return "".join(chr(value) if 32 <= value < 127 else "." for value in raw)


def _literal_matches(pe: PE, value: str) -> list[dict[str, Any]]:
    needle = value.encode("ascii") + b"\0"
    rows: list[dict[str, Any]] = []
    cursor = 0
    while True:
        offset = pe.data.find(needle, cursor)
        if offset < 0:
            break
        rva = pe.to_rva(offset)
        if rva is not None:
            left = max(0, offset - 24)
            right = min(len(pe.data), offset + len(needle) + 48)
            rows.append(
                {
                    **_location(pe, rva),
                    "literal": value,
                    "context_hex": pe.data[left:right].hex(),
                    "context_ascii": _ascii(pe.data[left:right]),
                    "evidence": "exact_ascii_nul_terminated_literal",
                }
            )
        cursor = offset + 1
    return rows


def _decode_rows(pe: PE, md, begin: int, end: int) -> list[dict[str, Any]]:
    check_memory_budget()
    if end <= begin or end - begin > MAX_SINGLE_DECODE_BYTES:
        raise ValueError(f"decode range exceeds bounded per-range limit: {begin:#x}:{end:#x}")
    rows = _decode_range(pe, md, begin, end)
    return rows


def _select(rows: list[dict[str, Any]], addresses: list[int]) -> list[dict[str, Any]]:
    by_rva = {int(row["rva"], 16): row for row in rows}
    selected: list[dict[str, Any]] = []
    for address in addresses:
        row = by_rva.get(address)
        if row is None:
            selected.append({"rva": hex(address), "decode_missing": True})
            continue
        selected.append(row)
    return selected


def _range_record(pe: PE, rows: list[dict[str, Any]], begin: int, end: int, label: str) -> dict[str, Any]:
    raw = pe.bytes_at(begin, end - begin)
    if len(raw) != end - begin:
        raise ValueError(f"range is not fully backed by the PE: {begin:#x}:{end:#x}")
    pdata = pe.function(begin)
    return {
        "label": label,
        "rva_range": [hex(begin), hex(end)],
        "static_va_range": [hex(pe.base + begin), hex(pe.base + end)],
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "pdata_function": None if pdata is None else [hex(pdata[0]), hex(pdata[1])],
        "instruction_count": len(rows),
    }


def _constant(pe: PE, rva: int, size: int = 8) -> dict[str, Any]:
    raw = pe.bytes_at(rva, size)
    result: dict[str, Any] = {**_location(pe, rva), "bytes": raw.hex()}
    if size == 8:
        result.update(
            {
                "u64": struct.unpack("<Q", raw)[0],
                "i64": struct.unpack("<q", raw)[0],
                "double": struct.unpack("<d", raw)[0],
            }
        )
    return result


def build_report() -> dict[str, Any]:
    path = game_exe()
    size = path.stat().st_size
    if size > MAX_EXE_BYTES:
        raise ValueError(f"refusing executable larger than {MAX_EXE_BYTES} bytes")
    sha256 = _sha256(path)
    if sha256 != EXPECTED_EXE_SHA256:
        raise ValueError(f"unexpected executable SHA-256: {sha256}")
    if size != EXPECTED_EXE_BYTES:
        raise ValueError(f"unexpected executable size: {size}")

    pe = PE(path)
    if pe.base != EXPECTED_IMAGE_BASE:
        raise ValueError(f"unexpected PE image base: {pe.base:#x}")
    md, decoder = make_disassembler(ROOT / "work" / "deps")

    total_decode = sum(end - begin for begin, end, _ in DECODE_RANGES)
    if total_decode > MAX_TOTAL_DECODE_BYTES:
        raise ValueError(f"planned decode exceeds total limit: {total_decode}")
    decoded: dict[str, list[dict[str, Any]]] = {}
    ranges: list[dict[str, Any]] = []
    for begin, end, label in DECODE_RANGES:
        rows = _decode_rows(pe, md, begin, end)
        decoded[label] = rows
        ranges.append(_range_record(pe, rows, begin, end, label))

    # One raw RIP-relative pass is used only for the two exact field keys.  A
    # candidate is retained as a candidate until its selected instruction is in
    # one of the bounded decoded windows above.
    refs = rip_references(pe, set(TARGET_RVAS.values()))
    refs_json = {
        name: refs.get(rva, []) for name, rva in TARGET_RVAS.items()
    }

    selected = {
        "army_tradition_registration": _select(
            decoded["army_tradition_field_registration"],
            [0x6A80BA, 0x6A80C1, 0x6A80C8],
        ),
        "army_tradition_scope_slot": _select(
            decoded["country_scope_field_registration"],
            [0x8ED6B4, 0x8EDBF8, 0x8EDBFF, 0x8EDC06],
        ),
        "field_descriptor_helper": _select(
            decoded["field_descriptor_registration_helper"],
            [0x8F4111, 0x8F4114, 0x8F412C, 0x8F412F, 0x8F4139],
        ),
        "bounded_key_lookup": _select(
            decoded["bounded_field_key_lookup_helper"],
            [0x8EEDB4, 0x8EEDB7, 0x8EEE20, 0x8EEE2A, 0x8EEE38, 0x8EEE50, 0x8EEE60, 0x8EEE7A],
        ),
        "descriptor_same_displacement_constructor": _select(
            decoded["descriptor_object_constructor"],
            [0xB3D874, 0xB3D877, 0xB3D888, 0xB3DB04],
        ),
        "descriptor_constructor_callsite": _select(
            decoded["descriptor_constructor_callsite"],
            [0xB43565, 0xB43576, 0xB4357C, 0xB43581, 0xB43584],
        ),
        "descriptor_slot_copy_window": _select(
            decoded["descriptor_slot_copy_window"],
            [0x10B22C1, 0x10B22C8],
        ),
        "army_tradition_ui_labels": _select(
            decoded["army_tradition_ui_label_dispatch"],
            [0x8D0D40, 0x8D0D62, 0x8D0D69, 0x8D0E0B, 0x8D0E2A, 0x8D0E31],
        ),
        "army_professionalism_snapshot_registration": _select(
            decoded["army_professionalism_snapshot_registration"],
            [0xB3444B, 0xB34451, 0xB34458, 0xB3445D],
        ),
        "army_professionalism_ratio_display": _select(
            decoded["army_professionalism_ratio_display"],
            [0xD02DC9, 0xD02DD3, 0xD030D2, 0xD03104, 0xD03108, 0xD03110, 0xD03117, 0xD0311C, 0xD03125, 0xD03130],
        ),
        "army_professionalism_percent_display": _select(
            decoded["army_professionalism_percent_display"],
            [0xD03DB5, 0xD03DBC, 0xD03E17, 0xD03E1B, 0xD03E28, 0xD03E5A, 0xD03E62, 0xD03E69, 0xD03E6E, 0xD03E7B, 0xD03E86],
        ),
    }

    return {
        "schema": "information_military_quality_static_source_v1",
        "status": "partial",
        "source_kind": "ordinary_pe_bounded_static",
        "scope": "N03.army_tradition_and_professionalism",
        "binary": {
            "path": str(path),
            "size": size,
            "sha256": sha256,
            "image_base": hex(pe.base),
            "version_pin": "EU4 1.37.4",
        },
        "method": {
            "game_or_rpm": False,
            "rea": False,
            "native_calls": False,
            "string_search": "exact_ascii_nul_terminated",
            "xref_pass": "single_bounded_raw_rip_relative_candidate_pass",
            "decoder": "capstone" if decoder is not None else "objdump_bounded_fallback",
            "decode_limits": {
                "max_single_bytes": MAX_SINGLE_DECODE_BYTES,
                "max_total_bytes": MAX_TOTAL_DECODE_BYTES,
                "planned_total_bytes": total_decode,
            },
        },
        "literal_targets": {
            name: {
                "target": _location(pe, rva),
                "exact_matches": _literal_matches(pe, name),
            }
            for name, rva in TARGET_RVAS.items()
        },
        "rip_candidates": refs_json,
        "bounded_ranges": ranges,
        "decode_skips": [
            {
                "instruction_rva": hex(0xFB7D0E),
                "function_rva_range": [hex(0xFB4BA0), hex(0xFBA3D0)],
                "reason": "candidate function exceeds the 16 KiB per-function bound; no whole function decode was attempted",
            }
        ],
        "selected_instructions": selected,
        "fixed_constants": {
            "raw_scale_32768_reciprocal": _constant(pe, 0x1DC1518),
            "percent_multiplier_100_times_32768": _constant(pe, 0x1FD1C98),
            "display_format_strings": {
                **_location(pe, 0x1DBF5C8),
                "bytes": pe.bytes_at(0x1DBF5C8, 32).hex(),
                "nul_strings": [part.decode("ascii") for part in pe.bytes_at(0x1DBF5C8, 32).split(b"\0") if part],
            },
        },
        "field_findings": {
            "army_tradition": {
                "field_literal": "army_tradition",
                "registration": {
                    "status": "closed_as_named_scope_field_registration",
                    "key_rva": hex(TARGET_RVAS["army_tradition"]),
                    "scope_object_alias": "RCX copied to R14 at 0x8ed6b4",
                    "slot_expression": "R14+0x8d0",
                    "key_expression": "RIP literal at 0x8edbff -> 0x141ca8c78",
                    "registration_call_rva": hex(0x8EDC06),
                    "helper_rva": hex(0x8F40F0),
                    "helper_effect": "key lookup then descriptor pointer/ready byte written at the supplied slot",
                },
                "same_displacement_constructor": {
                    "status": "observed_distinct_object_not_aliased",
                    "function_rva_range": [hex(0xB3D860), hex(0xB3DB53)],
                    "instruction_rva": hex(0xB3DB04),
                    "write": "DWORD PTR [RDI+0x8d0] = ESI",
                    "width": "32-bit store in this constructor only",
                    "callsite": {
                        "allocation_rva": hex(0xB43565),
                        "allocation_size": hex(0x910),
                        "object_alias": "RAX passed as RCX to 0xb3d860 at 0xb43581..0xb43584",
                        "index_argument": "R8D=R12D",
                        "name_argument": "RDX=[RSP+0x20]",
                    },
                    "copy_path": {
                        "window_rva_range": [hex(0x10B22B3), hex(0x10B22CF)],
                        "instructions": "MOV RAX,QWORD PTR [RSI+0x8d0]; MOV QWORD PTR [RDI+0x8d0],RAX",
                        "interpretation": "The scope/descriptor object's same-displacement member is copied as a QWORD pointer in this bounded copy path, consistent with a descriptor slot rather than a proven numeric country scalar.",
                    },
                    "caveat": "The constructor is reached from a separately allocated 0x910-byte descriptor/table object; no static alias to the scope object at 0x8ed690 was proven.",
                },
                "country_storage_getter": {
                    "status": "unclosed",
                    "reason": "The bounded key registrar stores a descriptor, not a direct FRA/country pointer or scalar load; the descriptor's indirect vtable getter remains unresolved.",
                },
                "signed_width": {"status": "unknown", "reason": "No bounded current-country scalar load was found."},
                "unit_scale": {"status": "unknown", "reason": "The uppercase UI label path has no numeric source in the bounded window; combat-result scale is a separate field and is not reused."},
                "display": {
                    "status": "label_only",
                    "literal_rva": hex(0x1CC15D8),
                    "callsite_rvas": [hex(0x8D0D62), hex(0x8D0E2A)],
                    "localizer_call": hex(0x14B33A0),
                    "condition": "[object+0x1c8]+0x58 == 2 selects ARMY_TRADITION label branch",
                    "value_source": "not present in this bounded label-dispatch slice",
                },
            },
            "professionalism": {
                "field_literal": "army_professionalism",
                "registration": {
                    "status": "closed_as_named_snapshot_registration_and_display_key",
                    "key_rva": hex(TARGET_RVAS["army_professionalism"]),
                    "snapshot_registration": {
                        "instruction_rva": hex(0xB34451),
                        "key_pass": "RDX=0x141ce7bb8",
                        "descriptor_index_argument": "R8D=0x14",
                        "call": hex(0x950110),
                        "country_alias": "not supplied by this callsite",
                    },
                },
                "country_storage_getter": {
                    "status": "unclosed",
                    "reason": "Both numeric paths use an object alias local to their formatter (RSI or R14); neither is statically proven to be the current country object, and no direct FRA getter call is present in the bounded slices.",
                },
                "numeric_display_paths": {
                    "ratio_path": {
                        "function_rva_range": [hex(0xD02DA0), hex(0xD0360D)],
                        "source_expression": "QWORD PTR [RSI+0x68]",
                        "signed_width": "signed 64-bit (CVTSI2SD QWORD)",
                        "formula": "double(signed_qword(raw)) * (1.0 / 32768.0)",
                        "scale": 32768,
                        "format": "%.1f",
                        "formatter_call": hex(0x15C260),
                        "key_localizer_call": hex(0x14B33A0),
                        "evidence_rvas": [hex(0xD030D2), hex(0xD03104), hex(0xD03108), hex(0xD03110), hex(0xD03117), hex(0xD0311C), hex(0xD03125), hex(0xD03130)],
                    },
                    "percent_path": {
                        "function_rva_range": [hex(0xD03D90), hex(0xD042C8)],
                        "source_expression": "QWORD PTR [[R14+0x68]+0x108]",
                        "signed_width": "signed 64-bit multiply/shift and CVTSI2SD QWORD",
                        "formula_exact_instruction_order": "q64 = low64_signed(raw * 0x320000); q64 = arithmetic_shift_right(q64, 15); display = double(q64) * (1.0 / 32768.0)",
                        "nominal_no_overflow_equivalent": "raw * 100 / 32768",
                        "scale": 32768,
                        "multiplier_constant": 3276800,
                        "format": "%.1f",
                        "formatter_call": hex(0x15C260),
                        "key_localizer_call": hex(0x14B33A0),
                        "evidence_rvas": [hex(0xD03E28), hex(0xD03E5A), hex(0xD03E62), hex(0xD03E69), hex(0xD03E6E), hex(0xD03E7B), hex(0xD03E86)],
                    },
                },
                "unit_semantics": {
                    "status": "display_scale_closed_but_object_semantics_not_closed",
                    "raw_scale": 32768,
                    "display_forms": ["ratio", "percentage-like multiplier 100"],
                    "caveat": "The two call paths are distinct and must not be collapsed into a single public unit until their caller/UI context is identified.",
                },
            },
        },
        "conclusion": {
            "army_tradition": "static key and scope-slot registration found; current-country getter, signed width, and unit scale remain unresolved",
            "professionalism": "static key and two signed-QWORD display conversions found; current-country getter/alias and the authoritative public unit remain unresolved",
            "publication": "do_not_mark_available_or_complete_true_from_this_static_report",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "work" / "runtime" / "information-military-quality-20261027-001" / "tradition-source-001.json",
    )
    args = parser.parse_args()
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "status": report["status"], "planned_total_decode_bytes": report["method"]["decode_limits"]["planned_total_bytes"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
