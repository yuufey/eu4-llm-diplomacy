"""Offline v2 loan reference replay.

This reference intentionally does not import ``country_loans_memory``.  It
only replays archived raw rows or a future v2 raw report, preserving the
missing ``+0x36`` byte as unknown and applying the independently pinned
24-tick/365-day arithmetic.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


V2_PROFILE_SHA256 = "686d88ef6b2dd02e12067d3fc2e7a942c39b131cf504bbe7bcf4f130d706cf69"
EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
REFERENCE_RAW = 43_800_000
TICKS_PER_DAY = 24
DAYS_PER_YEAR = 365
MONTH_LENGTHS = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
MONTH_DAY_STATUS = "month_and_day_components_closed_static"
CALENDAR_SOURCE_PATH = (
    "work/runtime/information-country-records-localization-20261027-001/"
    "date-calendar-source-002.json"
)
CALENDAR_SOURCE_SHA256 = "fd851ea9a6869e61b2ae05dbb251136ff281fe3801907568900a60a8fa800957"
SUPERSEDED_SOURCE_PATH = (
    "work/runtime/information-country-records-localization-20261027-001/"
    "loan-lender-date-source-001.json"
)
SUPERSEDED_SOURCE_SHA256 = "a43a2bc9bd258670ff3e9531b13b66388fc72cb84434b4967ec9a93b83d7d62a"
UINT32_MASK = 0xFFFFFFFF
INT32_SIGN = 0x80000000
UINT32_MODULUS = 0x100000000


def _signed32(value: int) -> int:
    value &= UINT32_MASK
    return value - UINT32_MODULUS if value & INT32_SIGN else value


def _month_day(day_of_year: int) -> tuple[int, int]:
    remaining = day_of_year
    for month_index, month_length in enumerate(MONTH_LENGTHS):
        if remaining < month_length:
            return month_index + 1, remaining + 1
        remaining -= month_length
    raise ValueError("day_of_year_out_of_fixed_365_range")


def _project_date(raw: int) -> dict[str, Any]:
    raw_unsigned = raw & UINT32_MASK
    reference_unsigned = REFERENCE_RAW & UINT32_MASK
    delta_unsigned = (raw_unsigned - reference_unsigned) & UINT32_MASK
    delta = _signed32(delta_unsigned)
    day_index, tick_of_day = divmod(delta, TICKS_PER_DAY)
    year_index, day_of_year = divmod(day_index, DAYS_PER_YEAR)
    month, day = _month_day(day_of_year)
    return {
        "raw_unsigned": raw_unsigned,
        "raw_signed32": _signed32(raw_unsigned),
        "raw_hex": raw_unsigned.to_bytes(4, "little").hex(),
        "reference_raw": REFERENCE_RAW,
        "reference_raw_unsigned": reference_unsigned,
        "ticks_per_day": TICKS_PER_DAY,
        "days_per_year": DAYS_PER_YEAR,
        "delta_ticks_unsigned": delta_unsigned,
        "delta_ticks": delta,
        "day_index": day_index,
        "tick_of_day": tick_of_day,
        "year_index": year_index,
        "day_of_year": day_of_year,
        "algorithm": "signed32_wrap_floor((raw-reference_raw)/24),floor(day_index/365)",
        "month_index_zero_based": month - 1,
        "month": month,
        "day_of_month_zero_based": day - 1,
        "day": day,
        "month_day": f"{month}.{day}",
        "date": f"{year_index}.{month}.{day}",
        "month_day_status": MONTH_DAY_STATUS,
        "calendar_source": {
            "path": CALENDAR_SOURCE_PATH,
            "sha256": CALENDAR_SOURCE_SHA256,
            "status": "ordinary_pe_bounded_static_only",
        },
    }


def _loan_rows(report: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    inputs = report.get("loan_inputs")
    if not isinstance(inputs, list) or not inputs:
        raise ValueError("loan_inputs_missing")
    first = inputs[0]
    rows = first.get("nodes") if isinstance(first, Mapping) else None
    if not isinstance(rows, list):
        raise ValueError("loan_nodes_missing")
    return rows


def replay(input_path: Path) -> dict[str, Any]:
    raw = input_path.read_bytes()
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("reference_input_too_large")
    report = json.loads(raw.decode("utf-8"))
    if not isinstance(report, Mapping):
        raise ValueError("reference_shape_invalid")
    rows: list[dict[str, Any]] = []
    unknown_lender = 0
    for row in _loan_rows(report):
        fields = bytes.fromhex(str(row.get("record_fields_raw_hex", "")))
        if len(fields) != 20:
            raise ValueError("record_fields_width_invalid")
        lender = int.from_bytes(fields[:8], "little")
        presence = fields[7]
        special_hex = row.get("special_flag_raw_hex")
        special = None if special_hex in (None, "") else bytes.fromhex(str(special_hex))
        if presence == 0:
            mapping = None if special is None else ("ESTATE" if special[0] else "BANK")
            lender_status = "known" if mapping is not None else "unknown"
            lender_reason = None if mapping is not None else "special_lender_flag_unobserved"
        else:
            mapping = None
            lender_status = "unknown"
            lender_reason = "foreign_fullref_requires_runtime_table_identity"
        if lender_status == "unknown":
            unknown_lender += 1
        due_unsigned = int.from_bytes(fields[16:20], "little", signed=False)
        rows.append({
            "record_address": row.get("record_address"),
            "lender": {
                "status": lender_status,
                "mapping": mapping,
                "raw_fullref": lender,
                "raw_fullref_hex": fields[:8].hex(),
                "special_presence_raw": presence,
                "special_presence_raw_hex": bytes([presence]).hex(),
                "special_flag_raw": special[0] if special is not None else None,
                "special_flag_raw_hex": special.hex() if special is not None else None,
                "reason": lender_reason,
            },
            "principal_raw": int.from_bytes(fields[12:16], "little", signed=True),
            "interest_raw": int.from_bytes(fields[8:12], "little", signed=True),
            "due_raw": int.from_bytes(fields[16:20], "little", signed=True),
            "due_calendar": _project_date(due_unsigned),
        })
    return {
        "schema": "information_country_loans_v2_reference.v1",
        "status": "replayed",
        "source_path": str(input_path),
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "source_profile_sha256": report.get("profile", {}).get("sha256") if isinstance(report.get("profile"), Mapping) else None,
        "target_exe_sha256": EXE_SHA256,
        "production_v2_profile_sha256": V2_PROFILE_SHA256,
        "new_runtime_sample": False,
        "native_function_invoked": False,
        "rows": rows,
        "unknown_lender_rows": unknown_lender,
        "calendar_source": {
            "path": CALENDAR_SOURCE_PATH,
            "sha256": CALENDAR_SOURCE_SHA256,
            "status": "ordinary_pe_bounded_static_only",
        },
        "supersedes": {
            "path": SUPERSEDED_SOURCE_PATH,
            "sha256": SUPERSEDED_SOURCE_SHA256,
            "reason": "source-002 closes fixed-365/month-day replay and corrects the later two derived dates without rewriting source-001",
        },
        "date_algorithm": {
            "reference_raw": REFERENCE_RAW,
            "ticks_per_day": TICKS_PER_DAY,
            "days_per_year": DAYS_PER_YEAR,
            "algorithm": "signed32_wrap_floor((raw-reference_raw)/24),floor(day_index/365)",
            "month_lengths": list(MONTH_LENGTHS),
            "month_day_status": MONTH_DAY_STATUS,
            "calendar_source": {
                "path": CALENDAR_SOURCE_PATH,
                "sha256": CALENDAR_SOURCE_SHA256,
                "status": "ordinary_pe_bounded_static_only",
            },
            "supersedes": {
                "path": SUPERSEDED_SOURCE_PATH,
                "sha256": SUPERSEDED_SOURCE_SHA256,
                "reason": "source-002 closes fixed-365/month-day replay and corrects the later two derived dates without rewriting source-001",
            },
        },
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("refusing_to_overwrite_output")
    result = replay(args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"status": result["status"], "rows": len(result["rows"]), "unknown_lender_rows": result["unknown_lender_rows"]}))
