"""Bounded 1.37.4 source study for loan lender and expiry-date semantics.

This is a static companion to the batch-52 current-loans reader.  It does
not open the game, use RPM, call REA, or update any production profile.  The
report distinguishes the special ``---`` lender branch from the fullref
country path and records the bounded native date conversion path without
inventing an epoch or a runtime lender value that was not sampled.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE, make_disassembler
from work.local_config import game_exe


EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
IMAGE_BASE = 0x140000000
MAX_SINGLE_RANGE_BYTES = 4096
MAX_TOTAL_DECODE_BYTES = 16 * 1024
DEFAULT_OUTPUT = ROOT / (
    "work/runtime/information-country-records-localization-20261027-001/"
    "loan-lender-date-source-001.json"
)

# Each range is either a complete pdata function or a deliberately explicit
# leaf/call-site window.  The large row function and generic date helpers are
# not disassembled wholesale.
CODE_RANGES = (
    (0x86B2E0, 0x86B4B1, "loan_lender_display_helper"),
    (0x2892D0, 0x28935D, "loan_fullref_country_lookup"),
    (0xEB158E, 0xEB1598, "loan_row_scalar_inputs"),
    (0xEB1942, 0xEB19A0, "loan_expiry_row_callsite"),
    (0x6E5860, 0x6E5B6F, "native_date_formatter"),
    (0xCFD70, 0xCFE04, "native_date_calendar_leaf"),
)


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _decode_range(pe: PE, md: Any, begin: int, end: int) -> list[dict[str, str]]:
    """Decode one bounded range with Capstone or bounded objdump fallback."""
    raw = pe.bytes_at(begin, end - begin)
    if len(raw) != end - begin:
        raise AssertionError(f"range is not file-backed: {begin:#x}:{end:#x}")
    if md is not None:
        return [
            {
                "rva": hex(ins.address - pe.base),
                "bytes": ins.bytes.hex(),
                "mnemonic": ins.mnemonic,
                "operands": ins.op_str,
            }
            for ins in md.disasm(raw, pe.base + begin)
        ]
    command = [
        "objdump", "-d", "-w", "-Mintel",
        f"--start-address={pe.base + begin:#x}",
        f"--stop-address={pe.base + end:#x}",
        str(pe.path),
    ]
    result = subprocess.run(
        command, capture_output=True, text=True, errors="replace",
        check=True, timeout=30,
    )
    if len(result.stdout) > 8 * 1024 * 1024:
        raise ValueError("bounded objdump output exceeded 8 MiB")
    pattern = re.compile(
        r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)"
        r"\s*(\S+)(?:\s+(.*))?$"
    )
    rows: list[dict[str, str]] = []
    for line in result.stdout.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        rva = int(match.group(1), 16) - pe.base
        if begin <= rva < end:
            rows.append({
                "rva": hex(rva),
                "bytes": "".join(match.group(2).split()).lower(),
                "mnemonic": match.group(3),
                "operands": match.group(4) or "",
            })
    return rows


def _by_rva(instructions: list[dict[str, str]], rva: int) -> dict[str, str]:
    for row in instructions:
        if int(row["rva"], 16) == rva:
            return row
    raise AssertionError(f"decoder did not return instruction at {rva:#x}")


def _selected(instructions: list[dict[str, str]], addresses: tuple[int, ...]):
    return [_by_rva(instructions, rva) for rva in addresses]


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


def _assert_bytes(pe: PE, expected: dict[int, str]) -> None:
    for rva, wanted in expected.items():
        actual = pe.bytes_at(rva, len(wanted) // 2).hex()
        if actual != wanted:
            raise AssertionError(
                f"unexpected bytes at RVA {rva:#x}: {actual} != {wanted}"
            )


def _range_record(pe: PE, instructions: list[dict[str, str]], begin: int, end: int, label: str):
    raw = pe.bytes_at(begin, end - begin)
    fn = pe.function(begin)
    return {
        "label": label,
        "start_rva": hex(begin),
        "end_rva_exclusive": hex(end),
        "start_va": hex(pe.base + begin),
        "end_va_exclusive": hex(pe.base + end),
        "byte_length": len(raw),
        "bytes_sha256": _hash_bytes(raw),
        "function_boundary_from_pdata": [hex(fn[0]), hex(fn[1])] if fn else None,
        "decoded_instruction_count": len(instructions),
        "range_is_explicit": True,
    }


def _pin(path: Path, role: str) -> dict[str, Any]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": _hash_file(path),
        "role": role,
    }


def _sample_date_projection() -> dict[str, Any]:
    """Return only arithmetic derived from the already pinned raw sample.

    The calendar label is a cross-check from the existing session archive,
    not a new runtime observation.  The static leaf proves 24-hour ticks and
    the fixed reference constant; this helper intentionally does not pretend
    to be a production date converter.
    """
    current_raw = 56_557_728
    current_calendar = "1456.5.13"
    dues = [56_590_344, 56_593_392, 56_598_528]
    return {
        "status": "derived_crosscheck",
        "source": "existing batch-52 native loan raw; no new RPM",
        "current_raw": current_raw,
        "current_calendar": current_calendar,
        "ticks_per_day": 24,
        "due_raw_values": dues,
        "delta_days_from_current": [(raw - current_raw) // 24 for raw in dues],
        "calendar_values": ["1460.2.1", "1460.6.7", "1461.1.7"],
        "calendar_values_status": "derived_from_pinned_current_calendar_and_24h_tick; not a new runtime sample",
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
    ranges = []
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

    _assert_bytes(
        pe,
        {
            0x86B2F8: "44384927",       # lender fullref high byte
            0x86B2FC: "752e",           # foreign/fullref branch
            0x86B301: "44384136",       # estate_loan flag
            0x86B30A: "488d15b7f03e01", # ESTATE string
            0x86B31B: "488d150e104501", # BANK string
            0x86B32C: "488d5920",       # record + lender fullref
            0x86B338: "e893dfa1ff",     # 2892d0
            0x2892DE: "4c8b1dcb450b02", # country DB global
            0x2892EF: "48c1e820",       # high-word extraction
            0x2892F6: "4c0fbfd0",       # signed i16 slot
            0x2892FA: "498b8318010000", # DB + 0x118
            0x289301: "4a8b1cd0",       # table[slot]
            0x289305: "4883bb8026000000", # +0x2680 gate
            0x28930F: "488d8390260000", # +0x2690 string object
            0xEB158E: "448b7a2c",       # principal
            0xEB1592: "8b7a28",         # interest
            0xEB1595: "8b4230",         # expiry raw
            0xEB1942: "498b4e40",       # formatter context
            0xEB1949: "488d15b05ce800", # loan_expire key
            0xEB1950: "ff9098000000",   # key lookup
            0xEB195C: "488d55b0",       # date output/string frame
            0xEB1960: "488d8d08010000", # raw expiry frame
            0xEB1967: "e8f43e83ff",     # native date formatter 6e5860
            0xCFD70: "448b01",          # read raw date
            0xCFD79: "4181e8c0559c02", # subtract 43800000
            0xCFD85: "b8abaaaa2a",      # /24 magic
            0xCFDC9: "b8b1f98cb3",      # /365 magic
            0xCFDDE: "69c26d010000",   # *365
            0xCFE03: "c3",              # leaf return
        },
    )

    selected = {
        "lender_special_branch": _selected(
            decoded["loan_lender_display_helper"],
            (0x86B2F8, 0x86B2FC, 0x86B301, 0x86B30A, 0x86B31B, 0x86B32C, 0x86B338),
        ),
        "foreign_fullref_lookup": _selected(
            decoded["loan_fullref_country_lookup"],
            (0x2892DE, 0x2892EF, 0x2892F6, 0x2892FA, 0x289301, 0x289305, 0x28930F),
        ),
        "loan_expiry_scalar_and_calls": _selected(
            decoded["loan_row_scalar_inputs"], (0xEB158E, 0xEB1592, 0xEB1595)
        ) + _selected(
            decoded["loan_expiry_row_callsite"],
            (0xEB1942, 0xEB1949, 0xEB1950, 0xEB195C, 0xEB1960, 0xEB1967, 0xEB1977, 0xEB1982),
        ),
        "date_calendar_leaf": _selected(
            decoded["native_date_calendar_leaf"],
            (0xCFD70, 0xCFD79, 0xCFD85, 0xCFDA9, 0xCFDB4, 0xCFDC9, 0xCFDDE, 0xCFDEB, 0xCFE03),
        ),
    }

    token_strings = {
        "loan": _string_record(pe, 0x2082020, b"\xad\x28\x00\x00loan\0"),
        "interest": _string_record(pe, 0x2082228, b"\xae\x28\x00\x00interest\0"),
        "lender": _string_record(pe, 0x2082430, b"\xaf\x28\x00\x00lender\0"),
        "expiry_date": _string_record(pe, 0x2082638, b"\xb0\x28\x00\x00expiry_date\0"),
    }
    display_strings = {
        "bank": _string_record(pe, 0x1CBC330, b"BANK\0"),
        "estate": _string_record(pe, 0x1C5A3C8, b"ESTATE\0"),
        "loan_expire": _string_record(pe, 0x1D37600, b"loan_expire\0"),
        "loan_expire_template": _string_record(
            pe, 0x1D37610, b"CV_ECONOMY_LOAN_EXPIRE\0"
        ),
    }

    loans_path = ROOT / "work/runtime/information-country-records-20261027-001/native-loans-inputs-001.json"
    expected_path = ROOT / "work/runtime/information-country-records-20261027-001/expected-loans-001.json"
    calendar_crosscheck_path = ROOT / "work/runtime/information-country-records-20261027-001/source-snapshot/HANDOFF.md"
    trade_resolver_path = ROOT / "work/runtime/information-trade-source-details-20261027-001/next-trade-entry-001.json"

    return {
        "schema": "information_loan_lender_dates_source.v1",
        "report_id": "loan-lender-date-source-001",
        "status": "partial_lender_special_and_expiry_calendar_boundary_closed",
        "evidence_kind": "ordinary_pe_bounded_static_with_prior_runtime_cross_pins",
        "target_build": {
            "version": "1.37.4",
            "exe_sha256": exe_sha256,
            "image_base": hex(IMAGE_BASE),
            "path": str(executable),
            "rva_rule": "VA = image_base + RVA; runtime VA/heap pointers remain separate",
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
        "prior_pins": [
            _pin(loans_path, "batch-52 raw loan sample; reused, not sampled again"),
            _pin(expected_path, "batch-52 independent raw replay expectation"),
            _pin(calendar_crosscheck_path, "pinned session raw-to-calendar cross-check; not a new runtime sample"),
            _pin(trade_resolver_path, "same resolver's strict foreign fullref/tag boundary"),
        ],
        "bounded_scope": {"ranges": ranges, "selected_instructions": selected},
        "strings": {"token_strings": token_strings, "display_strings": display_strings},
        "lender_contract": {
            "record_fullref_offset": "0x20",
            "record_fullref_width_bytes": 8,
            "special_presence_byte_offset": "0x27",
            "special_flag_offset": "0x36",
            "special_flag_key": "estate_loan",
            "special_branch": [
                {
                    "condition": "byte(record+0x27)==0 and byte(record+0x36)!=0",
                    "display_input": "ESTATE",
                    "status": "closed_static",
                },
                {
                    "condition": "byte(record+0x27)==0 and byte(record+0x36)==0",
                    "display_input": "BANK",
                    "status": "closed_static",
                },
            ],
            "foreign_fullref_path": {
                "helper_rva": "0x2892d0",
                "database_global_rva": "0x233d8b0",
                "database_table_offset": "0x118",
                "slot_formula": "signed_i16(fullref >> 32)",
                "entry_formula": "database_table[slot]",
                "entry_gate": "entry+0x2680 != 0",
                "display_field": "entry+0x2690 (SSO string object; not renamed as a TAG)",
                "country_identity_rule": "reuse the pinned resolver contract: after exact table/fullref equality, expose fullref[0:3] only if ASCII TAG\0; otherwise keep unknown",
                "status": "closed_with_pinned_same_resolver_identity_rule",
            },
            "current_sample_binding": {
                "lender_fullref_raw_hex": "2d2d2d0000000000",
                "special_presence_byte": 0,
                "special_flag_byte": None,
                "status": "bank_or_estate_unknown_until_record_plus_0x36_is_observed",
                "reason": "batch-52 raw record intentionally covered +0x20..+0x33 only; it does not contain the +0x36 estate_loan byte",
            },
        },
        "expiry_contract": {
            "record_offset": "0x30",
            "width_bytes": 4,
            "signed": False,
            "raw_unit": "eu4_hour_tick",
            "ticks_per_day": 24,
            "nested_native_key": "expiry_date",
            "display_key": "loan_expire",
            "display_template_key": "CV_ECONOMY_LOAN_EXPIRE",
            "row_call_chain": [
                "loan_record+0x30 -> row stack raw DWORD",
                "row calls native date formatter RVA 0x6e5860 with pointer to raw DWORD",
                "date formatter calls leaf RVA 0xcfd70",
                "row inserts formatted date into CV_ECONOMY_LOAN_EXPIRE",
            ],
            "calendar_leaf": {
                "reference_raw_constant": "0x29c55c0",
                "reference_raw_constant_decimal": 43800000,
                "operation": "raw - 43800000, signed floor by 24 to day component, then signed year quotient using 365-day arithmetic; month/day expansion is in the formatter's adjacent helper path",
                "status": "native_tick_and_reference_arithmetic_closed_month_day_expansion_bounded_but_not_renamed",
            },
            "sample_projection": _sample_date_projection(),
            "unknowns": [
                "The report does not promote the prior raw loan sample's missing +0x36 byte to BANK or ESTATE.",
                "The formatter's adjacent month/day and leap-day helper is reached from 0x6e5860 but is not assigned a separate semantic function name here; calendar projections are cross-checked from the pinned current calendar and 24-hour tick evidence.",
                "No loan due-date update writer or refresh timing is claimed.",
            ],
        },
        "runtime_observation_boundary": {
            "status": "prior_observation_reused_only",
            "source_path": str(loans_path.relative_to(ROOT)).replace("\\", "/"),
            "source_sha256": _hash_file(loans_path),
            "sample_due_raw_values": [56590344, 56593392, 56598528],
            "sample_lender_raw_hex": "2d2d2d0000000000",
            "new_rpm_count": 0,
            "new_game_calls": 0,
        },
        "implementation_boundary": {
            "reader_can_publish_now": [
                "lender raw_fullref and special-vs-foreign branch status",
                "foreign country TAG only after strict table/fullref match",
                "due raw DWORD, unit eu4_hour_tick, scale 1",
                "calendar projection only when the session calendar context is pinned",
            ],
            "reader_must_keep_unknown": [
                "special --- current BANK versus ESTATE until +0x36 is sampled",
                "invalid foreign slot/table gate or mismatched fullref",
                "unbound due calendar without a current session date/calendar context",
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
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "output": str(output), "decoded_bytes": report["limits"]["decoded_bytes"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
