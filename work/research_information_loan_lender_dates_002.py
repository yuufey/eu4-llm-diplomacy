"""Bounded static follow-up for the EU4 loan due-date month/day path.

This companion follows the small date-formatting call chain.
It uses only the ordinary PE and bounded objdump fallback; it never starts the
game, attaches to a process, invokes REA, or updates the production date
projection.  The two calls at ``0x6e58ac`` and ``0x6e58b5`` resolve to the
bounded month-name and day-of-month helpers at ``0x14c74a0`` and
``0x14c8020``.  Their month-length table and long/short name arrays are
recorded explicitly; the report keeps the path's fixed-365/fixed-28 behavior
separate from any broader calendar claims.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE, make_disassembler
from work.local_config import game_exe
from work.research_information_loan_lender_dates import (
    _decode_range,
    _hash_bytes,
    _hash_file,
    _range_record,
)


EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
IMAGE_BASE = 0x140000000
MAX_SINGLE_RANGE_BYTES = 4096
MAX_TOTAL_DECODE_BYTES = 16 * 1024
REFERENCE_RAW = 43_800_000
TICKS_PER_DAY = 24
MONTH_LENGTHS = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
DEFAULT_OUTPUT = ROOT / (
    "work/runtime/information-country-records-localization-20261027-001/"
    "date-calendar-source-002.json"
)

# The first two ranges are complete bounded functions already used by source
# 001.  The next three are the directly called day/month helpers and their
# day-of-year leaf.  The final helper is the decimal signed-integer writer
# called immediately after the two date-component calls.
CODE_RANGES = (
    (0x6E5860, 0x6E5B6F, "native_date_formatter"),
    (0xCFD70, 0xCFE04, "native_date_calendar_leaf"),
    (0xCFE10, 0xCFE77, "native_day_of_year_helper"),
    (0x14C74A0, 0x14C7641, "native_month_name_helper"),
    (0x14C8020, 0x14C813F, "native_day_of_month_helper"),
    (0x17061A0, 0x1706273, "native_signed_decimal_writer"),
)

MONTH_LENGTH_TABLE = (0x1C3A5C8, 0x1C3A5F8)

RDATA_MONTH_WINDOW = (0x1CAA730, 0x1CAA850)
RDATA_DIRECT_FORMAT_STRINGS = {
    0x1CAA74C: b"DD\0",
    0x1CAA750: b"MM\0",
    0x1CAA754: b"YYYY\0",
    0x1CAA768: b"LONG_EU3_DATE_STRING\0",
    0x1CAA780: b"MONTH\0",
}
RDATA_ADJACENT_FORMAT_STRINGS = {
    0x1CAA7F0: b"SI_DATE_DAY\0",
    0x1CAA800: b"SI_DATE_MONTH\0",
    0x1CAA810: b"SI_DATE_YEAR\0",
}
RDATA_MONTH_LITERALS = {
    0x1CAA734: b"feb\0",
    0x1CAA738: b"jan\0",
    0x1CAA73C: b"jun\0",
    0x1CAA740: b"may\0",
    0x1CAA744: b"apr\0",
    0x1CAA748: b"mar\0",
    0x1CAA820: b"oct\0",
    0x1CAA824: b"sep\0",
    0x1CAA828: b"aug\0",
    0x1CAA82C: b"jul\0",
    0x1CAA848: b"dec\0",
    0x1CAA84C: b"nov\0",
}

MONTH_SHORT_STRINGS = {
    0: (0x1D8C480, b"Jan\0"),
    1: (0x1D8C3D4, b"Feb\0"),
    2: (0x1D8C3D0, b"Mar\0"),
    3: (0x1D8C3CC, b"Apr\0"),
    4: (0x1D8C454, b"May\0"),
    5: (0x1D8C3C8, b"Jun\0"),
    6: (0x1D8C3C4, b"Jul\0"),
    7: (0x1D8C3C0, b"Aug\0"),
    8: (0x1D8C3BC, b"Sep\0"),
    9: (0x1D8C3B8, b"Oct\0"),
    10: (0x1D8C424, b"Nov\0"),
    11: (0x1D8C420, b"Dec\0"),
}

# The native helper deliberately reuses the short ``May`` literal in the
# long-name array because both forms have the same spelling.
MONTH_LONG_STRINGS = {
    0: (0x1D8C478, b"January\0"),
    1: (0x1D8C468, b"February\0"),
    2: (0x1D8C460, b"March\0"),
    3: (0x1D8C458, b"April\0"),
    4: (0x1D8C454, b"May\0"),
    5: (0x1D8C4CC, b"June\0"),
    6: (0x1D8C4C4, b"July\0"),
    7: (0x1D8C4BC, b"August\0"),
    8: (0x1D8C4B0, b"September\0"),
    9: (0x1D8C4A8, b"October\0"),
    10: (0x1D8C498, b"November\0"),
    11: (0x1D8C488, b"December\0"),
}


def _string_record(pe: PE, rva: int, expected: bytes) -> dict[str, Any]:
    actual = pe.bytes_at(rva, len(expected))
    if actual != expected:
        raise AssertionError(
            f"string bytes changed at RVA {rva:#x}: {actual.hex()} != {expected.hex()}"
        )
    file_offset = pe.to_offset(rva)
    return {
        "rva": hex(rva),
        "va": hex(pe.base + rva),
        "file_offset": hex(file_offset) if file_offset is not None else None,
        "raw_hex": expected.hex(),
        "text": expected.rstrip(b"\0").decode("ascii", "replace"),
    }


def _raw_record(pe: PE, begin: int, end: int, label: str) -> dict[str, Any]:
    raw = pe.bytes_at(begin, end - begin)
    if len(raw) != end - begin:
        raise AssertionError(f"range is not file-backed: {begin:#x}:{end:#x}")
    file_offset = pe.to_offset(begin)
    return {
        "label": label,
        "start_rva": hex(begin),
        "end_rva_exclusive": hex(end),
        "start_va": hex(pe.base + begin),
        "end_va_exclusive": hex(pe.base + end),
        "file_offset": hex(file_offset) if file_offset is not None else None,
        "byte_length": len(raw),
        "bytes_sha256": _hash_bytes(raw),
        "raw_hex": raw.hex(),
        "range_is_explicit": True,
    }


def _dword_table_record(pe: PE, begin: int, end: int, label: str) -> dict[str, Any]:
    record = _raw_record(pe, begin, end, label)
    raw = pe.bytes_at(begin, end - begin)
    if len(raw) % 4:
        raise AssertionError("DWORD table width is not divisible by four")
    import struct

    record["signed_dwords"] = list(struct.unpack("<" + "i" * (len(raw) // 4), raw))
    record["unsigned_dwords"] = list(struct.unpack("<" + "I" * (len(raw) // 4), raw))
    return record


def _selected(instructions: list[dict[str, str]], addresses: tuple[int, ...]):
    by_rva = {int(row["rva"], 16): row for row in instructions}
    missing = [hex(rva) for rva in addresses if rva not in by_rva]
    if missing:
        raise AssertionError(f"decoder did not return instruction(s): {missing}")
    return [by_rva[rva] for rva in addresses]


def _pin(path: Path, role: str) -> dict[str, Any]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": _hash_file(path),
        "role": role,
    }


def _fixed_calendar_projection(raw: int) -> dict[str, Any]:
    """Replay only the bounded fixed-365/fixed-28 native path."""
    delta_ticks = raw - REFERENCE_RAW
    day_index, tick_of_day = divmod(delta_ticks, TICKS_PER_DAY)
    year_index, day_of_year = divmod(day_index, 365)
    remainder = day_of_year
    month_index = 0
    while remainder >= MONTH_LENGTHS[month_index]:
        remainder -= MONTH_LENGTHS[month_index]
        month_index += 1
    return {
        "raw_unsigned": raw & 0xFFFFFFFF,
        "raw_hex": (raw & 0xFFFFFFFF).to_bytes(4, "little").hex(),
        "reference_raw": REFERENCE_RAW,
        "delta_ticks": delta_ticks,
        "day_index": day_index,
        "tick_of_day": tick_of_day,
        "year_index": year_index,
        "month_index_zero_based": month_index,
        "month": month_index + 1,
        "day_of_year_zero_based": day_of_year,
        "day_zero_based": remainder,
        "day": remainder + 1,
        "ticks_per_day": TICKS_PER_DAY,
        "days_per_year": 365,
        "algorithm": "native_cfd70_cfe10_fixed365_then_14c74a0_14c8020_fixed_month_lengths",
    }


def build_report() -> dict[str, Any]:
    executable = Path(game_exe())
    pe = PE(executable)
    exe_sha256 = _hash_bytes(pe.data)
    if exe_sha256 != EXPECTED_EXE_SHA256:
        raise ValueError(f"unsupported game binary SHA-256: {exe_sha256}")
    if pe.base != IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.base:#x}")

    md, _capstone = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    decoded: dict[str, list[dict[str, str]]] = {}
    ranges: list[dict[str, Any]] = []
    total = 0
    for begin, end, label in CODE_RANGES:
        if end <= begin or end - begin > MAX_SINGLE_RANGE_BYTES:
            raise AssertionError(f"single range limit failure: {begin:#x}:{end:#x}")
        if not pe.executable(begin) or not pe.executable(end - 1):
            raise AssertionError(f"range is not executable: {begin:#x}:{end:#x}")
        total += end - begin
        if total > MAX_TOTAL_DECODE_BYTES:
            raise AssertionError("total bounded decode limit failure")
        decoded[label] = _decode_range(pe, md, begin, end)
        ranges.append(_range_record(pe, decoded[label], begin, end, label))

    formatter = decoded["native_date_formatter"]
    leaf = decoded["native_date_calendar_leaf"]
    day_of_year = decoded["native_day_of_year_helper"]
    month_name = decoded["native_month_name_helper"]
    day_of_month = decoded["native_day_of_month_helper"]
    decimal = decoded["native_signed_decimal_writer"]

    selected = {
        "date_formatter_call_chain": _selected(
            formatter,
            (
                0x6E589A,  # raw DWORD -> fixed calendar arithmetic leaf
                0x6E58AC,  # month-name helper
                0x6E58B5,  # day-of-month helper
                0x6E58DB,  # signed decimal writer
                0x6E5908,  # zero-padding threshold
                0x6E5A63,  # DD key
                0x6E5A99,  # MONTH key
                0x6E5AD5,  # YYYY key
                0x6E5AFE,  # LONG_EU3_DATE_STRING key
            ),
        ),
        "calendar_leaf_boundaries": _selected(
            leaf,
            (
                0xCFD70,   # raw DWORD load
                0xCFD79,   # subtract 43800000
                0xCFD80,   # signed negative branch
                0xCFDA0,   # exact 24-tick branch
                0xCFDC4,   # signed day/year branch
                0xCFDE6,   # exact 365-day branch
                0xCFDE8,   # clear negative-year correction
                0xCFE03,
            ),
        ),
        "day_of_year_helper": _selected(
            day_of_year,
            (
                0xCFE14,
                0xCFE17,
                0xCFE1E,
                0xCFE41,
                0xCFE4E,
                0xCFE53,
                0xCFE6C,
                0xCFE6F,
            ),
        ),
        "month_name_helper": _selected(
            month_name,
            (
                0x14C74C4,
                0x14C74C9,
                0x14C74CC,
                0x14C74DB,
                0x14C74DF,
                0x14C74E2,
                0x14C74E4,
                0x14C7607,
                0x14C760B,
                0x14C7612,
                0x14C7620,
            ),
        ),
        "day_of_month_helper": _selected(
            day_of_month,
            (
                0x14C803B,
                0x14C8040,
                0x14C804A,
                0x14C8050,
                0x14C8056,
                0x14C8058,
                0x14C8061,
                0x14C8063,
                0x14C80D4,
                0x14C8120,
                0x14C8123,
                0x14C812D,
            ),
        ),
        "decimal_writer_boundaries": _selected(
            decimal,
            (
                0x17061A7,
                0x17061AB,
                0x17061C6,
                0x17061CA,
                0x1706269,
            ),
        ),
    }

    month_window = _raw_record(
        pe, RDATA_MONTH_WINDOW[0], RDATA_MONTH_WINDOW[1], "month_and_date_rdata_block"
    )
    month_length_table = _dword_table_record(
        pe,
        MONTH_LENGTH_TABLE[0],
        MONTH_LENGTH_TABLE[1],
        "native_month_length_table",
    )
    direct_format_strings = {
        hex(rva): _string_record(pe, rva, expected)
        for rva, expected in RDATA_DIRECT_FORMAT_STRINGS.items()
    }
    adjacent_format_strings = {
        hex(rva): _string_record(pe, rva, expected)
        for rva, expected in RDATA_ADJACENT_FORMAT_STRINGS.items()
    }
    month_literals = {
        hex(rva): _string_record(pe, rva, expected)
        for rva, expected in RDATA_MONTH_LITERALS.items()
    }
    month_short_strings = {
        str(index): _string_record(pe, rva, expected)
        for index, (rva, expected) in MONTH_SHORT_STRINGS.items()
    }
    month_long_strings = {
        str(index): _string_record(pe, rva, expected)
        for index, (rva, expected) in MONTH_LONG_STRINGS.items()
    }

    source001 = ROOT / (
        "work/runtime/information-country-records-localization-20261027-001/"
        "loan-lender-date-source-001.json"
    )
    reference = ROOT / "work/reference_information_country_loans_v2.py"

    return {
        "schema": "information_loan_date_calendar_source.v2",
        "report_id": "date-calendar-source-002",
        "status": "partial_fixed_365_28_month_day_components_closed",
        "evidence_kind": "ordinary_pe_bounded_static_only",
        "target_build": {
            "version": "1.37.4",
            "exe_sha256": exe_sha256,
            "image_base": hex(IMAGE_BASE),
            "path": str(executable),
            "rva_rule": "VA = image_base + RVA; RVA/VA/runtime pointers remain distinct",
        },
        "limits": {
            "max_single_range_bytes": MAX_SINGLE_RANGE_BYTES,
            "max_total_decode_bytes": MAX_TOTAL_DECODE_BYTES,
            "decoded_bytes": total,
            "rea_used": False,
            "rpm_used": False,
            "game_started": False,
            "save_or_business_write": False,
            "decoder": "capstone_if_available_else_bounded_objdump",
        },
        "pins": [
            _pin(Path(__file__), "this bounded source script"),
            _pin(source001, "prior lender/date source; retained and not modified"),
            _pin(reference, "reference rows-only replay shape; not imported by production reader"),
        ],
        "bounded_scope": {
            "ranges": ranges,
            "selected_instructions": selected,
            "resolved_call_targets": [
                {
                    "callsite_rva": "0x6e58ac",
                    "target_rva": "0x14c74a0",
                    "target_va": hex(IMAGE_BASE + 0x14C74A0),
                    "target_pdata": ["0x14c74a0", "0x14c7641"],
                    "role": "month_name_helper",
                    "status": "bounded_function_closed",
                },
                {
                    "callsite_rva": "0x6e58b5",
                    "target_rva": "0x14c8020",
                    "target_va": hex(IMAGE_BASE + 0x14C8020),
                    "target_pdata": ["0x14c8020", "0x14c813f"],
                    "role": "day_of_month_helper",
                    "status": "bounded_function_closed",
                },
                {
                    "callsite_rva": "0x6e58db",
                    "target_rva": "0x17061a0",
                    "target_va": hex(IMAGE_BASE + 0x17061A0),
                    "target_pdata": ["0x17061a0", "0x17061dc"],
                    "status": "bounded_signed_decimal_writer",
                    "reason": "the bounded code continues through its local branch target at 0x170625a",
                },
            ],
        },
        "month_day_contract": {
            "record_offset": "0x30",
            "raw_width_bytes": 4,
            "raw_unit": "eu4_hour_tick",
            "ticks_per_day": 24,
            "reference_raw_constant": "0x29c55c0",
            "reference_raw_constant_decimal": 43800000,
            "calendar_leaf": {
                "rva": "0xcfd70",
                "operation": "signed raw-reference arithmetic with 24-tick day quotient and 365-day year quotient",
                "fixed_year_divisor": 365,
                "leap_switch_present": False,
                "leap_switch_status": "not present in the bounded leaf or its day-of-year helper",
            },
            "day_of_year_helper": {
                "rva": "0xcfe10",
                "formula": "day_of_year = floor((raw-reference)/24) - 365*year_index, with the negative residual correction from 0xcfe41/0xcfe43",
                "range": "0..364 under the fixed table path",
                "month_length_table_rva": "0x1c3a5c8",
                "month_length_table": [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31],
                "leap_switch_present": False,
            },
            "negative_input": {
                "status": "closed_for_leaf_arithmetic",
                "branches": [
                    "0xcfd80 jns selects the nonnegative raw-reference path",
                    "0xcfda0 je detects an exact 24-tick boundary before signed correction",
                    "0xcfdc4 jns selects the nonnegative day/year path",
                    "0xcfde6 jne preserves the negative-year correction for non-exact 365-day residuals",
                ],
                "meaning": "the leaf has explicit floor-style handling for dates before the 43800000 reference; no sentinel meaning is inferred",
            },
            "zero_and_sentinel": {
                "zero_input": "no sentinel branch in 0xcfd70; raw=0 enters its ordinary negative arithmetic",
                "formatter_threshold": "0x6e5908 cmp ebx,0xa selects zero-padding after the day helper returns; it is a decimal formatting boundary, not a missing-date sentinel",
                "month_index_guard": "0x14c74df cmp ebx,0xb / 0x14c74e2 jbe accepts indices 0..11; the else branch clears the output string",
                "sentinel_status": "no explicit raw-date sentinel in the bounded path",
            },
            "month_day_helpers": {
                "call_order": ["0x6e58ac -> 0x14c74a0", "0x6e58b5 -> 0x14c8020"],
                "status": "month_and_day_components_closed_static",
                "month_name_helper": {
                    "rva": "0x14c74a0",
                    "input": "r8d copied from date formatter r8b",
                    "month_index": "0-based ebx selected by subtracting the fixed month-length table",
                    "long_short_branch": "r8d==0 selects the 12 full-name pointers; r8d!=0 selects the 12 three-letter pointers",
                    "invalid_index": "ebx>11 clears the destination string object",
                    "output": "selected month name passed as rdx to 0x14b33a0 with destination rdi",
                },
                "day_of_month_helper": {
                    "rva": "0x14c8020",
                    "input": "same date context in rcx; calls 0xcfe10 for day_of_year",
                    "formula": "returns day_of_year minus the sum of month lengths before the selected 0-based month",
                    "return_indexing": "0-based; caller 0x6e58ba performs lea ebx,[rax+1] before decimal formatting",
                    "leap_behavior": "fixed February=28 and fixed year=365; no leap switch in this path",
                },
                "production_guidance": "the static source now supports a month/day engine helper contract; production engine_dates.py/profile remain unchanged until parent pins and implements it",
            },
        },
        "month_rdata": {
            "window": month_window,
            "month_length_table": month_length_table,
            "month_short_strings_by_index": month_short_strings,
            "month_long_strings_by_index": month_long_strings,
            "format_keys_referenced_by_date_formatter": direct_format_strings,
            "adjacent_date_format_keys_in_same_rdata_block": adjacent_format_strings,
            "month_name_literals": month_literals,
            "literal_order_status": "the month helper's RIP-relative pointer arrays prove the numeric 0..11 mapping; the separate 0x1caa734/0x1caa820 block remains localization-key data rather than the selected pointer table",
            "direct_xref_status": "bounded date formatter directly references DD, MONTH, YYYY, and LONG_EU3_DATE_STRING; the adjacent helper directly references the 12 month-length DWORDs and the 24 long/short name strings",
        },
        "static_sample_projection": {
            "status": "ordinary_pe_replay_only_no_new_runtime_sample",
            "current_raw": 56557728,
            "current_projection": _fixed_calendar_projection(56557728),
            "due_raw_values": [56590344, 56593392, 56598528],
            "due_projections": [
                _fixed_calendar_projection(raw)
                for raw in (56590344, 56593392, 56598528)
            ],
            "prior_source001_values": ["1460.2.1", "1460.6.7", "1461.1.7"],
            "prior_comparison_status": "current_raw_matches_1456.5.13; static_fixed365_helper_replays_due_rows_2_and_3_as_1460.6.8_and_1461.1.8",
            "caveat": "the prior source-001 values were a derived cross-check and are retained unchanged; this report records the direct bounded helper replay and does not rewrite source-001",
        },
        "reference_output_shape": {
            "script": reference.relative_to(ROOT).as_posix(),
            "top_level_keys": [
                "schema",
                "status",
                "source_path",
                "source_sha256",
                "source_profile_sha256",
                "target_exe_sha256",
                "production_v2_profile_sha256",
                "new_runtime_sample",
                "native_function_invoked",
                "rows",
                "unknown_lender_rows",
                "date_algorithm",
            ],
            "row_keys": [
                "record_address",
                "lender",
                "principal_raw",
                "interest_raw",
                "due_raw",
                "due_calendar",
            ],
            "comparison_boundary": "rows is the authoritative replay collection; this shape intentionally does not mirror production fields.loans.value",
            "due_calendar_extension": "month_day can be derived from the fixed-365/fixed-28 helper contract, but the existing rows-only reference script still emits its prior month_day null shape until production engine_dates.py is deliberately updated",
        },
        "runtime_observation_boundary": {
            "new_rpm_count": 0,
            "new_game_calls": 0,
            "prior_samples_not_replayed_here": True,
        },
        "implementation_boundary": {
            "closed_now": [
                "24-tick raw-to-day arithmetic and 365-day year arithmetic",
                "negative raw-reference floor-style branch and exact 24/365 boundary checks",
                "fixed month-length table, 0-based month selection, 0-based day-of-month plus caller +1",
                "long/short month-name selection and invalid month-index clear branch",
                "signed decimal zero/negative rendering helper",
                "date-format key and month-literal storage evidence",
            ],
            "must_remain_unknown": [
                "leap-year behavior outside this fixed-365/fixed-28 formatter path",
                "any missing-date sentinel contract outside the bounded loan formatter",
                "production month/day projection and any engine_dates.py/profile update until parent pins this report",
            ],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    report = build_report()
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    print(json.dumps({
        "status": report["status"],
        "output": str(output),
        "decoded_bytes": report["limits"]["decoded_bytes"],
        "month_day_status": report["month_day_contract"]["month_day_helpers"]["status"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
