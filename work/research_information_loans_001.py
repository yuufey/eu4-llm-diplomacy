"""Bounded static source study for current-country loans (EU4 1.37.4).

This report deliberately separates the current 1.37.4 PE observations from the
older 1.37.5 action-object mapping and from the previous-month economy ledger.
It does not open the game, call RPM/REA, or inspect a save.  The only decoded
windows are the country loan-list writer, the loan row view, its lender lookup,
and two tiny intrusive-list helpers.
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


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE, make_disassembler
from work.local_config import game_exe


EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
IMAGE_BASE = 0x140000000
MAX_RANGE_BYTES = 16 * 1024
MAX_TOTAL_DECODE_BYTES = 16 * 1024
DEFAULT_OUTPUT = ROOT / "work/runtime/information-loans-20261027-001/loans-source-001.json"


# All windows are either a complete .pdata function or an explicit leaf window.
# The country writer itself is much larger; only the exact loan-loop context is
# decoded here.
CODE_RANGES = (
    (0x2DF620, 0x2DF67A, "country_writer_loan_container_context"),
    (0xEB1560, 0xEB19CB, "loan_row_view_function"),
    (0x86B2E0, 0x86B4B1, "loan_lender_display_helper"),
    (0x2892D0, 0x28935D, "lender_fullref_country_lookup_function"),
    (0x9A010, 0x9A014, "loan_iterator_payload_leaf"),
    (0xC00C0, 0xC00CE, "loan_iterator_next_leaf"),
)


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _decode_range(pe: PE, md, begin: int, end: int):
    """Decode exactly one explicit range; objdump is a bounded fallback."""
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
        "objdump",
        "-d",
        "-w",
        "-Mintel",
        f"--start-address={pe.base + begin:#x}",
        f"--stop-address={pe.base + end:#x}",
        str(pe.path),
    ]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        errors="replace",
        check=True,
        timeout=30,
    )
    if len(result.stdout) > 8 * 1024 * 1024:
        raise ValueError("bounded objdump output exceeded 8 MiB")
    pattern = re.compile(
        r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)"
        r"\s*(\S+)(?:\s+(.*))?$"
    )
    rows = []
    for line in result.stdout.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        rva = address - pe.base
        if not begin <= rva < end:
            continue
        rows.append(
            {
                "rva": hex(rva),
                "bytes": "".join(match.group(2).split()).lower(),
                "mnemonic": match.group(3),
                "operands": match.group(4) or "",
            }
        )
    return rows


def _by_rva(instructions, rva: int):
    for row in instructions:
        if int(row["rva"], 16) == rva:
            return row
    raise AssertionError(f"decoder did not return instruction at {rva:#x}")


def _selected(instructions, addresses):
    return [_by_rva(instructions, rva) for rva in addresses]


def _assert_bytes(pe: PE, expected):
    for rva, expected_hex in expected.items():
        actual = pe.bytes_at(rva, len(expected_hex) // 2).hex()
        if actual != expected_hex:
            raise AssertionError(
                f"unexpected bytes at RVA {rva:#x}: {actual} != {expected_hex}"
            )


def _range_record(pe: PE, instructions, begin: int, end: int, label: str):
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
        "function_boundary_from_pdata": (
            [hex(fn[0]), hex(fn[1])] if fn else None
        ),
        "decoded_instruction_count": len(instructions),
        "range_is_explicit": True,
    }


def _prior_pin(path: Path, role: str):
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": _hash_file(path),
        "role": role,
    }


def _string_record(pe: PE, rva: int, expected: bytes):
    actual = pe.bytes_at(rva, len(expected))
    if actual != expected:
        raise AssertionError(
            f"string/token bytes changed at RVA {rva:#x}: "
            f"{actual.hex()} != {expected.hex()}"
        )
    off = pe.to_offset(rva)
    return {
        "rva": hex(rva),
        "va": hex(pe.base + rva),
        "file_offset": hex(off) if off is not None else None,
        "raw_hex": expected.hex(),
        "text": expected.rstrip(b"\0").decode("ascii", "replace"),
    }


def _locale_record(path: Path, keys):
    raw = path.read_bytes()
    records = []
    for line_no, line in enumerate(raw.splitlines(), 1):
        logical_line = line.lstrip()
        for key in keys:
            if logical_line.startswith(key.encode("ascii") + b":"):
                records.append(
                    {
                        "key": key,
                        "line": line_no,
                        "raw_hex": line.hex(),
                        "text": line.decode("utf-8", "replace"),
                    }
                )
    if {item["key"] for item in records} != set(keys):
        raise AssertionError("English loan localization keys are incomplete")
    return {
        "path": str(path),
        "sha256": _hash_file(path),
        "records": records,
        "role": "static_display_semantics_only",
    }


def build_report():
    executable = Path(game_exe())
    pe = PE(executable)
    exe_sha256 = _hash_bytes(pe.data)
    if exe_sha256 != EXPECTED_EXE_SHA256:
        raise ValueError(f"unsupported game binary SHA-256: {exe_sha256}")
    if pe.base != IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.base:#x}")

    md, _capstone = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    decoded = {}
    ranges = []
    total = 0
    for begin, end, label in CODE_RANGES:
        if not 0 <= begin < end or end - begin > MAX_RANGE_BYTES:
            raise AssertionError(f"range limit failure: {begin:#x}:{end:#x}")
        if not pe.executable(begin) or not pe.executable(end - 1):
            raise AssertionError(f"range is not executable: {begin:#x}:{end:#x}")
        total += end - begin
        if total > MAX_TOTAL_DECODE_BYTES:
            raise AssertionError("total decode limit failure")
        instructions = _decode_range(pe, md, begin, end)
        decoded[label] = instructions
        ranges.append(_range_record(pe, instructions, begin, end, label))

    _assert_bytes(
        pe,
        {
            # Country writer's current loan container loop.
            0x2DF631: "498b87e80d0000",
            0x2DF64B: "e8c0a9dbff",
            0x2DF650: "4c8b00",
            0x2DF653: "baad280000",
            0x2DF65B: "e8c0824201",
            0x2DF667: "e8540adeff",
            0x2DF674: "75ce",
            # Loan row input fields and display calls.
            0xEB158A: "48895150",
            0xEB158E: "448b7a2c",
            0xEB1592: "8b7a28",
            0xEB1595: "8b4230",
            0xEB15A5: "488d15d45de800",
            0xEB1608: "488d15815de800",
            0xEB161F: "498b4e50",
            0xEB1628: "4169dfe8030000",
            0xEB162F: "0318",
            0xEB16EA: "b8d34d6210",
            0xEB1718: "69c7e8030000",
            0xEB171E: "2bf0",
            0xEB1949: "488d15b05ce800",
            0xEB1960: "48 8d 8d 08 01 00 00".replace(" ", ""),
            # The lender display helper passes loan_record+0x20 to the
            # fullref country lookup, after its presence/fallback flags.
            0x86B2F8: "44384927",
            0x86B2FC: "752e",
            0x86B32C: "488d5920",
            0x86B338: "e893dfa1ff",
            # Lender helper: loan+0x20 is a fullref object; the helper maps its
            # signed high-word slot through database global +0x118.
            0x2892DE: "4c8b1dcb450b02",
            0x2892E9: "488b01",
            0x2892EF: "48c1e820",
            0x2892F6: "4c0fbfd0",
            0x2892FA: "498b8318010000",
            0x289301: "4a8b1cd0",
            0x289305: "4883bb8026000000",
            0x28930F: "488d8390260000",
            # Intrusive list payload/next helpers.
            0x9A010: "488b01",
            0xC00C0: "488b01",
            0xC00C3: "488b5010",
            0xC00C7: "488bc1",
            0xC00CA: "488911",
        },
    )

    selected = {
        "country_writer_loan_container": _selected(
            decoded["country_writer_loan_container_context"],
            (0x2DF631, 0x2DF64B, 0x2DF650, 0x2DF653, 0x2DF65B, 0x2DF667, 0x2DF674),
        ),
        "loan_row_view_fields": _selected(
            decoded["loan_row_view_function"],
            (
                0xEB158A,
                0xEB158E,
                0xEB1592,
                0xEB1595,
                0xEB15A5,
                0xEB1608,
                0xEB161F,
                0xEB1628,
                0xEB162F,
                0xEB16EA,
                0xEB1718,
                0xEB171E,
                0xEB1949,
                0xEB1960,
            ),
        ),
        "lender_fullref_lookup": _selected(
            decoded["lender_fullref_country_lookup_function"],
            (0x2892DE, 0x2892E9, 0x2892EF, 0x2892F6, 0x2892FA, 0x289301, 0x289305, 0x28930F),
        ),
        "lender_display_helper": _selected(
            decoded["loan_lender_display_helper"],
            (0x86B2F8, 0x86B2FC, 0x86B32C, 0x86B338),
        ),
        "loan_iterator_helpers": (
            _selected(decoded["loan_iterator_payload_leaf"], (0x9A010,))
            + _selected(
                decoded["loan_iterator_next_leaf"],
                (0xC00C0, 0xC00C3, 0xC00C7, 0xC00CA),
            )
        ),
    }

    token_strings = {
        "loan": _string_record(pe, 0x2082020, b"\xad\x28\x00\x00loan\x00"),
        "loan_lender": _string_record(pe, 0x1D37380, b"loan_lender\x00"),
        "loan_amount_interest": _string_record(
            pe, 0x1D37390, b"loan_amount_interest\x00"
        ),
        "loan_expire": _string_record(pe, 0x1D37600, b"loan_expire\x00"),
    }

    locale_path = executable.parent / "localisation/EU4_l_english.yml"
    locale = _locale_record(
        locale_path,
        (
            "CV_ECONOMY_LOAN_LENDER",
            "CV_ECONOMY_LOAN_AMOUNT_INTEREST",
            "CV_ECONOMY_LOAN_TOTAL",
            "CV_ECONOMY_LOAN_EXPIRE",
        ),
    )

    prior_path = ROOT / "work/runtime/information-military-modifiers-20261027-001/active-military-modifiers-source-003.json"
    prior_sources = []
    if prior_path.exists():
        prior_sources.append(
            _prior_pin(
                prior_path,
                "prior current-SHA bounded report containing the same country-writer loan token references",
            )
        )

    report = {
        "schema": "information_loans_source.v1",
        "report_id": "information-loans-source-001",
        "evidence_kind": "ordinary_bounded_PE_current_1374_static_not_runtime",
        "status": "partial_current_loan_record_fields_closed",
        "task_scope": (
            "Close a current country loan owner/container and user-visible record fields "
            "without using the previous-month loan expense total or the old 1.37.5 action object."
        ),
        "binary": {
            "path": str(executable),
            "sha256": exe_sha256,
            "image_base": hex(pe.base),
            "rva_rule": "VA = image_base + RVA; all offsets below are object-relative unless stated otherwise",
            "version_pin": "EU4 1.37.4",
        },
        "limits": {
            "max_single_range_bytes": MAX_RANGE_BYTES,
            "max_total_decode_bytes": MAX_TOTAL_DECODE_BYTES,
            "decoded_bytes": total,
            "rea_used": False,
            "rpm_used": False,
            "game_started": False,
            "save_or_business_write": False,
            "decoder": "capstone_if_available_else_bounded_objdump",
        },
        "prior_sources": prior_sources,
        "string_evidence": token_strings,
        "localization_evidence": locale,
        "code_ranges": ranges,
        "selected_instructions": selected,
        "country_loan_container": {
            "owner": {
                "object": "CCountry candidate (same R15 country register as the current country writer)",
                "country_offset": "0xde8",
                "source_rva": "0x2df631",
                "source_va": hex(pe.base + 0x2DF631),
                "formula": "loan_container = *(QWORD *)(country + 0xde8)",
                "static_status": "closed for the current country-writer path",
            },
            "container_shape": {
                "kind": "intrusive singly-linked node sequence (static helper shape)",
                "head_pointer_storage": "country+0xde8 -> iterator/current-node pointer",
                "node_payload_pointer_offset": "0x0",
                "node_next_pointer_offset": "0x10",
                "payload_formula": "loan_record = *(QWORD *)current_node",
                "next_formula": "current_node = *(QWORD *)(current_node + 0x10)",
                "termination": "current_node == 0",
                "source_helpers": ["0x9a010", "0xc00c0"],
                "static_status": "closed for the writer loop; node allocation/count policy is not closed",
            },
            "serialization": {
                "token_rva": "0x2082020",
                "token_key": "loan",
                "token_id": "0x28ad",
                "generic_writer_rva": "0x707920",
                "formula": "write_object(output, 0x28ad, loan_record)",
                "static_status": "pointer handoff closed; nested loan serializer body not decoded in this bounded task",
            },
        },
        "loan_record_fields": {
            "lender": {
                "offset": "0x20",
                "width_bytes": 8,
                "representation": "fullref QWORD (the lender display helper reads the QWORD and uses signed high-word slot)",
                "formula": "lender_fullref = *(uint64_t *)(loan_record + 0x20)",
                "lookup": {
                    "helper_rva": "0x2892d0",
                    "database_global_rva": "0x233d8b0",
                    "database_table_offset": "0x118",
                    "slot_formula": "slot = sign_extend(int16(fullref >> 32))",
                    "country_entry_formula": "country_entry = database[slot]",
                    "display_value_offset": "0x2690",
                    "validity_gate": "entry+0x2680 != 0 before returning entry+0x2690",
                },
                "ui_label": "loan_lender / CV_ECONOMY_LOAN_LENDER",
                "static_status": "fullref-to-country-table lookup closed; absent-lender fallback flags and display identity remain unresolved",
            },
            "interest": {
                "offset": "0x28",
                "width_bytes": 4,
                "signed": True,
                "raw_role": "signed fixed-point integer consumed by the loan_amount_interest row",
                "scale": 1000,
                "unit": "percent",
                "formula": "interest_percent = signed_i32(raw_interest) / 1000.0",
                "evidence": [
                    "loan row loads DWORD [record+0x28] into EDI at RVA 0xeb1592",
                    "the bounded UI path takes abs/sign, divides by 1000 using 0x10624dd3 and SAR 6, and formats the remainder against *1000",
                    "CV_ECONOMY_LOAN_AMOUNT_INTEREST substitutes this value into $INTEREST$ followed by %",
                ],
                "static_status": "current UI value/scale closed; exact native writer/storage update path is not closed",
            },
            "amount": {
                "offset": "0x2c",
                "width_bytes": 4,
                "signed": True,
                "raw_role": "whole-ducat amount component promoted into the amount-with-interest display",
                "scale": 1,
                "unit": "ducats",
                "promotion": "signed_i32(raw_amount) * 1000 before combining the bounded helper result",
                "formula": "amount_display_raw1000 = signed_i32(raw_amount) * 1000 + loan_amount_helper(record)[0]",
                "ui_label": "loan_amount_interest / CV_ECONOMY_LOAN_AMOUNT_INTEREST ($AMOUNT$¤)",
                "static_status": "stored-width and ducat promotion closed; helper-derived total/interest formula is intentionally unresolved",
            },
            "expiry": {
                "offset": "0x30",
                "width_bytes": 4,
                "raw_role": "date scalar passed to the loan_expire formatter",
                "unit": "engine_date_raw",
                "formula": "expiry_date_raw = *(uint32_t *)(loan_record + 0x30)",
                "ui_label": "loan_expire / CV_ECONOMY_LOAN_EXPIRE",
                "static_status": "source field and display path closed; date epoch/encoding and duration conversion are unresolved",
            },
        },
        "usable_contract": {
            "minimum_current_fields": [
                "loan_record lender fullref at +0x20, with country-table slot validation",
                "loan_record interest signed32 / 1000 percent at +0x28",
                "loan_record amount signed32 whole ducats at +0x2c (promoted to /1000 display arithmetic)",
                "loan_record expiry DWORD at +0x30 as an engine date raw value",
            ],
            "identity_guard": [
                "pin the current EXE SHA-256 above",
                "bind every record to the country+0xde8 traversal and the loan token 0x28ad",
                "validate lender fullref high-word slot and database entry before exposing a lender tag/name",
                "do not equate the amount-with-interest helper output with a plain principal or monthly ledger expense without the helper/storage writer",
            ],
        },
        "unresolved": [
            "The generic nested loan serializer at RVA 0x707920 and the loan object writer are not decoded here; the country loop proves the current container/payload handoff, while the UI row proves the current field offsets and labels.",
            "A direct static call-edge from the country writer payload to the loan row constructor is not present in the bounded windows; the shared loan-specific token/layout is strong static corroboration, not a runtime identity claim.",
            "RVA 0x86b4e0 derives the amount-with-interest helper result from the record and date; its exact principal/interest/expiry formula and update writer remain outside this source contract.",
            "The +0x30 date scalar's epoch/encoding and whether it is stored as an expiry date or duration-derived date are not proven.",
            "No current runtime loan count, amount, lender tag, or expiration value was sampled; no live/RPM/game claim is made.",
        ],
        "explicit_exclusions": [
            "docs/native-action-fields-1375.md and the old 1.37.5 offerloan action-object offsets are excluded from the current 1.37.4 record contract.",
            "monthly-ledger-source-001 and EXPENSELOAN/loan expense totals are not used as a current loan container or record substitute.",
            "No static rule, maximum-loan policy, or recorded save value is presented as a current loan instance.",
        ],
    }
    return report


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"status": report["status"], "output": str(args.output), "decoded_bytes": report["limits"]["decoded_bytes"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
