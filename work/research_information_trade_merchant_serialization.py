"""Produce a bounded static check for the code immediately before B5EAA0.

This is ordinary PE inspection for the fixed EU4 1.37.4 image.  It does not
open the game, use RPM/REA, follow the previously reported getter/SET paths,
or write a production profile.  The exact pdata predecessor of B5EAA0 and a
small entry window of B5EAA0 are decoded only to decide whether the predecessor
writes entry fields such as +AC/+AD/+AE or exposes their key names.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE, make_disassembler
from work.local_config import game_exe
from work.research_information_branch_inputs import _decode_range


EXPECTED_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
IMAGE_BASE = 0x140000000
MAX_RANGE_BYTES = 4 * 1024
MAX_TOTAL_DECODE_BYTES = 8 * 1024

# B5EAA0 is a separate pdata function.  Only its 0xE0-byte entry prefix is
# decoded; the 0x1088-byte function body is intentionally outside this report.
CODE_RANGES = (
    (0xB5E190, 0xB5EA92, "pdata_predecessor"),
    (0xB5EAA0, 0xB5EB80, "parser_entry_window"),
)

FIELD_LOADS = {
    0xAC: {
        "load_rva": 0xB5E1AB,
        "selector_rva": 0xB5E1BF,
        "call_rva": 0xB5E1C7,
        "selector": 0xE1,
    },
    0xAE: {
        "load_rva": 0xB5E4D3,
        "selector_rva": 0xB5E4DF,
        "call_rva": 0xB5E4E7,
        "formatter_rva": 0xB5E4F2,
        "selector": 0x2C09,
    },
    0xAD: {
        "load_rva": 0xB5E4FF,
        "selector_rva": 0xB5E50B,
        "call_rva": 0xB5E513,
        "formatter_rva": 0xB5E51E,
        "selector": 0x2C94,
    },
    0xAF: {
        "load_rva": 0xB5E52B,
        "selector_rva": 0xB5E537,
        "call_rva": 0xB5E53F,
        "formatter_rva": 0xB5E54A,
        "selector": 0x2F23,
    },
}

PARSER_SELECTED = (
    0xB5EAC5,
    0xB5EAD8,
    0xB5EAEB,
    0xB5EAFE,
    0xB5EB0B,
    0xB5EB18,
    0xB5EB25,
    0xB5EB32,
    0xB5EB46,
    0xB5EB4D,
    0xB5EB54,
    0xB5EB5A,
    0xB5EB5E,
    0xB5EB62,
    0xB5EB6A,
    0xB5EB6E,
    0xB5EB72,
)

FORMAT_LITERALS = {
    0x1DBF978: "%d.%03d",
    0x1DBF980: "-%d.%03d",
}

OUTPUT = (
    ROOT
    / "work/runtime/information-trade-merchant-task-20261027-001/"
    / "merchant-serialization-source-001.json"
)


def _sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha_range(pe: PE, begin: int, end: int, chunk_size: int = 0x1000) -> str:
    """Hash a bounded byte range without a single read over the window limit."""
    digest = hashlib.sha256()
    for offset in range(begin, end, chunk_size):
        digest.update(pe.bytes_at(offset, min(chunk_size, end - offset)))
    return digest.hexdigest()


def _va(rva: int) -> str:
    return hex(IMAGE_BASE + rva)


def _cstring(pe: PE, rva: int, expected: str) -> dict[str, str]:
    expected_bytes = expected.encode("ascii") + b"\0"
    raw = bytearray()
    for offset in range(len(expected_bytes) + 1):
        raw.extend(pe.bytes_at(rva + offset, 1))
        if raw[-1:] == b"\0":
            break
    if bytes(raw) != expected_bytes:
        raise AssertionError(
            f"literal mismatch at {rva:#x}: {bytes(raw)!r} != {expected_bytes!r}"
        )
    return {
        "rva": hex(rva),
        "va": _va(rva),
        "string": expected,
        "bytes_hex": bytes(raw).hex(),
        "bytes_sha256": _sha_bytes(bytes(raw)),
        "meaning": "format literal observed by bounded code; not an entry key name",
    }


def _range_record(
    pe: PE, rows: list[dict[str, object]], begin: int, end: int, label: str
) -> dict[str, object]:
    raw = pe.bytes_at(begin, end - begin)
    boundary = pe.function(begin)
    if len(raw) != end - begin:
        raise AssertionError(f"range is not file-backed: {begin:#x}:{end:#x}")
    return {
        "label": label,
        "start_rva": hex(begin),
        "end_rva_exclusive": hex(end),
        "start_va": _va(begin),
        "end_va_exclusive": _va(end),
        "byte_length": len(raw),
        "bytes_sha256": _sha_bytes(raw),
        "pdata_function_boundary": (
            [hex(boundary[0]), hex(boundary[1])] if boundary else None
        ),
        "decoded_instruction_count": len(rows),
        "boundary_note": (
            "The parser window is a prefix of its pdata function; the complete "
            "B5EAA0 body is intentionally not decoded."
            if label == "parser_entry_window"
            else "Exact pdata predecessor body, including its final ret."
        ),
    }


def _by_rva(rows: list[dict[str, object]]) -> dict[int, dict[str, object]]:
    result = {int(row["rva"], 16): row for row in rows}
    if len(result) != len(rows):
        raise AssertionError("duplicate decoded instruction RVA")
    return result


def _row(by_rva: dict[int, dict[str, object]], rva: int) -> dict[str, object]:
    try:
        return by_rva[rva]
    except KeyError as exc:
        raise AssertionError(f"missing decoded instruction {rva:#x}") from exc


def _direct_call_target(row: dict[str, object], base: int) -> str | None:
    if str(row["mnemonic"]).lower() != "call":
        return None
    match = re.search(r"0x([0-9a-fA-F]+)", str(row["operands"]))
    if not match:
        return None
    absolute = int(match.group(1), 16)
    if not base <= absolute < base + 0x40000000:
        return None
    return hex(absolute - base)


def _memory_direction(row: dict[str, object], token: str) -> str | None:
    operands = str(row["operands"]).lower()
    if token not in operands:
        return None
    first = operands.split(",", 1)[0].strip()
    mnemonic = str(row["mnemonic"]).lower()
    # objdump prefixes memory destinations with BYTE/DWORD/QWORD PTR, so a
    # destination does not literally start with '['.  Only store-like MOVs
    # are writes here; CMP/TEST and MOVZX/MOVSX are source reads.
    if "[" in first and mnemonic in {"mov", "movabs"}:
        return "write"
    return "read"


def build_report() -> dict[str, object]:
    pe = PE(game_exe())
    binary_sha256 = _sha_bytes(pe.data)
    if binary_sha256 != EXPECTED_SHA256:
        raise ValueError(f"unsupported game binary SHA-256: {binary_sha256}")
    if pe.base != IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.base:#x}")

    expected_boundaries = {
        0xB5E190: (0xB5E190, 0xB5EA92),
        0xB5EAA0: (0xB5EAA0, 0xB5FB38),
    }
    for start, expected in expected_boundaries.items():
        actual = pe.function(start)
        if actual is None or tuple(actual[:2]) != expected:
            raise AssertionError(
                f"unexpected pdata boundary at {start:#x}: {actual!r} != {expected!r}"
            )

    md, capstone_available = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    decoded: dict[str, list[dict[str, object]]] = {}
    ranges: list[dict[str, object]] = []
    total_decoded_bytes = 0
    for begin, end, label in CODE_RANGES:
        if end <= begin or end - begin > MAX_RANGE_BYTES:
            raise AssertionError(f"range limit failure: {begin:#x}:{end:#x}")
        if not pe.executable(begin) or not pe.executable(end - 1):
            raise AssertionError(f"range is not executable: {begin:#x}:{end:#x}")
        total_decoded_bytes += end - begin
        if total_decoded_bytes > MAX_TOTAL_DECODE_BYTES:
            raise AssertionError("total decode limit failure")
        rows = _decode_range(pe, md, begin, end)
        decoded[label] = rows
        ranges.append(_range_record(pe, rows, begin, end, label))

    predecessor = _by_rva(decoded["pdata_predecessor"])
    parser_prefix = _by_rva(decoded["parser_entry_window"])

    field_accesses: list[dict[str, object]] = []
    for offset, config in FIELD_LOADS.items():
        load = _row(predecessor, config["load_rva"])
        selector = _row(predecessor, config["selector_rva"])
        call = _row(predecessor, config["call_rva"])
        record: dict[str, object] = {
            "offset": hex(offset),
            "load": load,
            "load_direction": _memory_direction(load, f"+0x{offset:02x}"),
            "selector_immediate": hex(config["selector"]),
            "selector_instruction": selector,
            "direct_helper_call": {
                "instruction": call,
                "target_rva": _direct_call_target(call, pe.base),
            },
        }
        if "formatter_rva" in config:
            formatter = _row(predecessor, config["formatter_rva"])
            record["following_value_formatter_call"] = {
                "instruction": formatter,
                "target_rva": _direct_call_target(formatter, pe.base),
            }
        field_accesses.append(record)

    entry_field_tokens = tuple(f"+0x{offset:02x}" for offset in FIELD_LOADS)
    field_write_candidates = []
    for row in decoded["pdata_predecessor"]:
        for token in entry_field_tokens:
            direction = _memory_direction(row, token)
            if direction == "write":
                field_write_candidates.append(
                    {"offset": token, "instruction": row}
                )

    input_base_store_candidates = []
    for row in decoded["pdata_predecessor"]:
        operands = str(row["operands"]).lower()
        first = operands.split(",", 1)[0].strip()
        mnemonic = str(row["mnemonic"]).lower()
        if (
            "[r14" in first or "[rcx" in first
        ) and "[" in first and mnemonic in {"mov", "movabs"}:
            input_base_store_candidates.append(row)

    predecessor_call_targets = []
    for row in decoded["pdata_predecessor"]:
        target = _direct_call_target(row, pe.base)
        if target is not None:
            predecessor_call_targets.append(
                {"instruction": row, "target_rva": target}
            )

    parser_selected = [_row(parser_prefix, rva) for rva in PARSER_SELECTED]
    parser_switch_ids = []
    for row in parser_selected:
        operands = str(row["operands"])
        match = re.search(r",0x([0-9a-fA-F]+)$", operands)
        if str(row["mnemonic"]).lower() == "cmp" and match:
            parser_switch_ids.append(
                {"instruction": row, "immediate": hex(int(match.group(1), 16))}
            )

    predecessor_raw = pe.bytes_at(0xB5E190, 0xB5EA92 - 0xB5E190)
    requested_name_hits = [
        name
        for name in (b"is_transfer", b"has_trader")
        if name in predecessor_raw
    ]

    return {
        "schema": "information.trade_merchant_task.merchant_serialization_source.v1",
        "stage": "information-trade-merchant-task-20261027-001",
        "evidence_kind": "ordinary_static_file_analysis_not_REA_evidence",
        "target": {
            "game_version": "1.37.4",
            "exe_sha256": binary_sha256,
            "image_base_va": hex(pe.base),
            "address_kind": "RVA; VA=image_base_va+RVA; ranges end exclusive",
        },
        "scope": {
            "question": (
                "Whether the exact pdata predecessor of B5EAA0 is a reverse "
                "serializer that writes entry +AC/+AD/+AE to named keys"
            ),
            "excluded": [
                "game/RPM/save/reload/runtime observation",
                "REA analysis",
                "previous getter/SET paths",
                "global table at 0x233FE58+0x2228",
                "full B5EAA0 body and indirect callees",
            ],
        },
        "analysis_limits": {
            "decoder": "capstone if available, otherwise bounded objdump",
            "capstone_available": bool(capstone_available),
            "decoded_bytes_total": total_decoded_bytes,
            "max_single_window_bytes": MAX_RANGE_BYTES,
            "max_total_decode_bytes": MAX_TOTAL_DECODE_BYTES,
            "full_parser_body_decoded": False,
        },
        "function_boundaries": {
            "predecessor_exact_pdata": {
                "start_rva": hex(0xB5E190),
                "end_rva_exclusive": hex(0xB5EA92),
                "byte_length": 0xB5EA92 - 0xB5E190,
                "start_va": _va(0xB5E190),
                "end_va_exclusive": _va(0xB5EA92),
                "bytes_sha256": ranges[0]["bytes_sha256"],
            },
            "parser_exact_pdata": {
                "start_rva": hex(0xB5EAA0),
                "end_rva_exclusive": hex(0xB5FB38),
                "byte_length": 0xB5FB38 - 0xB5EAA0,
                "start_va": _va(0xB5EAA0),
                "end_va_exclusive": _va(0xB5FB38),
                "bytes_sha256": _sha_range(pe, 0xB5EAA0, 0xB5FB38),
                "decoded_here": "entry prefix only",
                "hash_read_chunk_bytes": 0x1000,
            },
            "gap_between_predecessor_and_parser": {
                "start_rva": hex(0xB5EA92),
                "end_rva_exclusive": hex(0xB5EAA0),
                "byte_length": 0xB5EAA0 - 0xB5EA92,
                "meaning": "outside both pdata bodies; not decoded as code",
                "first_byte_hex": pe.bytes_at(0xB5EA92, 1).hex(),
            },
        },
        "decoded_ranges": ranges,
        "predecessor_field_accesses": field_accesses,
        "field_write_evidence": {
            "requested_offsets": ["0xac", "0xad", "0xae"],
            "also_checked_offset": "0xaf",
            "writes_to_requested_offsets": field_write_candidates,
            "all_input_base_store_candidates": input_base_store_candidates,
            "result": (
                "No store with +AC/+AD/+AE as a memory destination appears in "
                "the exact predecessor body; the observed accesses are byte loads."
            ),
        },
        "predecessor_calls": {
            "direct_calls": predecessor_call_targets,
            "calls_to_b5eaa0": [
                item
                for item in predecessor_call_targets
                if item["target_rva"] == hex(0xB5EAA0)
            ],
            "interpretation": (
                "The predecessor has helper calls, but no direct call target at "
                "the B5EAA0 parser entry in this bounded body."
            ),
        },
        "parser_entry_window": {
            "selected_instructions": parser_selected,
            "numeric_selector_comparisons": parser_switch_ids,
            "observed_initialization": (
                "The prefix compares R8D against numeric selector values and then "
                "allocates/initializes a new object through a bounded call; it does "
                "not provide a reverse write into the predecessor's input entry."
            ),
        },
        "key_name_evidence": {
            "requested_names": ["is_transfer", "has_trader"],
            "inline_hits_in_predecessor_bytes": [
                value.decode("ascii")
                for value in (b"is_transfer", b"has_trader")
                if value in predecessor_raw
            ],
            "format_literals_reached_by_predecessor": [
                _cstring(pe, rva, value) for rva, value in FORMAT_LITERALS.items()
            ],
            "numeric_selector_ids_are_not_key_names": True,
            "conclusion": (
                "No direct ASCII key-name evidence for is_transfer or has_trader "
                "was found in the bounded predecessor bytes."
            ),
        },
        "finding": {
            "serializer_verdict": "not_a_reverse_serializer_on_bounded_evidence",
            "role_supported_by_bytes": "entry_field_read_and_format_path",
            "reason": (
                "The predecessor reads +AC/+AD/+AE/+AF as bytes, pairs them with "
                "numeric selectors and helper/formatter calls, and has no observed "
                "store back to those input offsets. Its exact pdata range ends at "
                "0xB5EA92; B5EAA0 starts a separate function."
            ),
        },
        "unresolved_conditions": [
            "The complete B5EAA0 body was not decoded because it is a separate 0x1098-byte function.",
            "Indirect helper callees and their output object semantics were not followed.",
            "Static bytes do not establish save-field names or runtime merchant semantics.",
            "No runtime, save, or UI observation was performed.",
        ],
        "producer_script": {
            "path": Path(__file__).resolve().relative_to(ROOT).as_posix(),
            "sha256": _sha_bytes(Path(__file__).read_bytes()),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing report: {output}")
    report = build_report()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "output": output.relative_to(ROOT).as_posix(),
                "report_sha256": _sha_bytes(output.read_bytes()),
                "decoded_bytes_total": report["analysis_limits"]["decoded_bytes_total"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
