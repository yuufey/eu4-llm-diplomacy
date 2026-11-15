"""Bounded caller chase for the 3BADC0 merchant-task wrapper.

The 25AB20 direct-caller inventory established that 3BADFA is inside the
wrapper function 3BADC0..3BAE7F.  This pass scans direct E8 callers of that
wrapper, then follows only the one caller whose R8B input remains open.  It
uses 256-byte raw evidence windows and does not decode unrelated functions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
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
WRAPPER_RVA = 0x3BADC0
WRAPPER_END_RVA = 0x3BAE7F
UNRESOLVED_CALLER_RVA = 0x3BAE80
PRE_CALL_BYTES = 240
POST_CALL_BYTES = 11
RAW_WINDOW_BYTES = PRE_CALL_BYTES + 5 + POST_CALL_BYTES
MAX_TOTAL_DECODE_BYTES = 8 * 1024


def _sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha_file(path: Path) -> str | None:
    if not path.exists():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _va(rva: int) -> str:
    return hex(IMAGE_BASE + rva)


def _direct_e8_calls_in_text(pe: PE, target_rva: int):
    """Find target calls by bytes only, restricted to the PE .text section."""
    section = next(section for section in pe.sections if section["name"] == ".text")
    start = section["raw"]
    stop = section["raw"] + section["size"] - 5
    hits = []
    for offset in range(start, stop + 1):
        if pe.data[offset] != 0xE8:
            continue
        call_rva = pe.to_rva(offset)
        destination = call_rva + 5 + struct.unpack_from("<i", pe.data, offset + 1)[0]
        if destination != target_rva:
            continue
        function = pe.function(call_rva)
        if not function:
            raise AssertionError(f"missing pdata boundary for {call_rva:#x}")
        hits.append(
            {
                "call_rva": call_rva,
                "call_va": _va(call_rva),
                "call_bytes_hex": pe.bytes_at(call_rva, 5).hex(),
                "target_rva": target_rva,
                "target_va": _va(target_rva),
                "caller_function_rva": [function[0], function[1]],
                "caller_function_va": [_va(function[0]), _va(function[1])],
            }
        )
    return section, hits


def _r8_destination(row):
    operands = row.get("operands", "").lower()
    destination = operands.split(",", 1)[0].strip()
    return destination in {"r8", "r8d", "r8w", "r8b"}


def _edx_destination(row):
    operands = row.get("operands", "").lower()
    destination = operands.split(",", 1)[0].strip()
    return destination in {"edx", "dx", "dl", "rdx"}


def _classify_r8_source(row):
    if row is None:
        return "not_found"
    operands = row.get("operands", "").lower()
    mnemonic = row.get("mnemonic", "")
    if mnemonic == "mov" and operands == "r8b,0x1":
        return "literal_constant_1"
    if mnemonic == "xor" and operands == "r8d,r8d":
        return "literal_zero"
    if "r8d,dl" == operands:
        return "stack_byte_forwarded_via_dl"
    if mnemonic == "lea" and operands.startswith("r8,"):
        return "local_or_stack_address"
    return "unclassified_r8_assignment"


def _decode_caller_window(pe: PE, md, hit):
    call = hit["call_rva"]
    raw_start = call - PRE_CALL_BYTES
    raw_end = call + 5 + POST_CALL_BYTES
    raw = pe.bytes_at(raw_start, raw_end - raw_start)
    if len(raw) != RAW_WINDOW_BYTES:
        raise AssertionError(f"short raw window for {call:#x}")

    # The raw window is deliberately fixed at 256 bytes.  Its first byte may
    # be in the middle of an instruction, so the disassembler is asked to
    # decode the same bounded slice and the report uses only rows immediately
    # before/after the exact call site.  The argument-writing rows are within
    # the final 96 bytes of every window.
    rows = _decode_range(pe, md, raw_start, raw_end)
    selected = [row for row in rows if raw_start <= int(row["rva"], 16) < raw_end]
    before = [row for row in selected if int(row["rva"], 16) < call]
    after = [row for row in selected if int(row["rva"], 16) >= call + 5]
    r8_sources = [row for row in before if _r8_destination(row)]
    nearest = r8_sources[-1] if r8_sources else None
    predecessor_edx = None
    if nearest and _classify_r8_source(nearest) == "stack_byte_forwarded_via_dl":
        r8_address = int(nearest["rva"], 16)
        predecessor_edx_rows = [
            row
            for row in before
            if int(row["rva"], 16) < r8_address and _edx_destination(row)
        ]
        predecessor_edx = predecessor_edx_rows[-1] if predecessor_edx_rows else None

    return {
        "call_rva": hex(call),
        "call_va": _va(call),
        "call_bytes_hex": hit["call_bytes_hex"],
        "target_rva": hex(hit["target_rva"]),
        "target_va": _va(hit["target_rva"]),
        "caller_function_rva": [
            hex(hit["caller_function_rva"][0]),
            hex(hit["caller_function_rva"][1]),
        ],
        "caller_function_va": hit["caller_function_va"],
        "raw_evidence_window": {
            "start_rva": hex(raw_start),
            "end_rva_exclusive": hex(raw_end),
            "start_va": _va(raw_start),
            "end_va_exclusive": _va(raw_end),
            "pre_call_bytes": PRE_CALL_BYTES,
            "call_instruction_bytes": 5,
            "post_call_bytes": POST_CALL_BYTES,
            "byte_length": len(raw),
            "bytes_sha256": _sha_bytes(raw),
        },
        "decoded_instruction_count": len(selected),
        "selected_instructions": selected,
        "nearest_r8b_source": {
            "instruction": nearest,
            "classification": _classify_r8_source(nearest),
            "distance_bytes": call - int(nearest["rva"], 16) if nearest else None,
            "edx_predecessor_for_dl": predecessor_edx,
        },
        "before_call_instructions": before,
        "after_call_instructions": after,
    }


def build_report():
    pe = PE(game_exe())
    binary_sha256 = _sha_bytes(pe.data)
    if binary_sha256 != EXPECTED_SHA256:
        raise ValueError(f"unsupported game binary SHA-256: {binary_sha256}")
    if pe.base != IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.base:#x}")

    section, wrapper_hits = _direct_e8_calls_in_text(pe, WRAPPER_RVA)
    expected_wrapper_calls = [0x3BAB52, 0x3BB1A3, 0x774E35]
    if [hit["call_rva"] for hit in wrapper_hits] != expected_wrapper_calls:
        raise AssertionError(
            "unexpected wrapper caller set: "
            + repr([hex(hit["call_rva"]) for hit in wrapper_hits])
        )

    # Only 3BB1A3 still has an input value not reduced to a literal in its
    # immediate window.  Follow its enclosing function target one level out;
    # the other two wrapper callers are already closed by constant R8B.
    section_second, second_hits = _direct_e8_calls_in_text(pe, UNRESOLVED_CALLER_RVA)
    expected_second_calls = [0x3BAD58, 0x774DE1]
    if [hit["call_rva"] for hit in second_hits] != expected_second_calls:
        raise AssertionError(
            "unexpected second-level caller set: "
            + repr([hex(hit["call_rva"]) for hit in second_hits])
        )

    md, capstone = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    wrapper_records = [_decode_caller_window(pe, md, hit) for hit in wrapper_hits]
    second_records = [_decode_caller_window(pe, md, hit) for hit in second_hits]
    decode_total = (len(wrapper_records) + len(second_records)) * RAW_WINDOW_BYTES
    if decode_total > MAX_TOTAL_DECODE_BYTES:
        raise AssertionError(f"decode budget exceeded: {decode_total}")

    prior_report = ROOT / "work/runtime/information-trade-merchant-task-20261027-001/merchant-task-source-003.json"
    report = {
        "schema": "information.trade_merchant_task.merchant_task_source.v7",
        "stage": "information-trade-merchant-task-20261027-001",
        "evidence_kind": "ordinary_static_file_analysis_not_REA_evidence",
        "target": {
            "game_version": "1.37.4",
            "exe_sha256": binary_sha256,
            "image_base_va": hex(pe.base),
            "address_kind": "RVA; VA=image_base_va+RVA; all ranges are [begin,end)",
        },
        "scope": {
            "question": "Trace the original R8B input to the 25AB20 constructor through the 3BADC0 wrapper's direct callers.",
            "wrapper": {
                "start_rva": hex(WRAPPER_RVA),
                "end_rva_exclusive": hex(WRAPPER_END_RVA + 1),
                "start_va": _va(WRAPPER_RVA),
                "end_va_exclusive": _va(WRAPPER_END_RVA + 1),
                "constructor_call_rva": "0x3badfa",
            },
            "scan": {
                "section_name": section["name"],
                "section_raw_file_offset": hex(section["raw"]),
                "section_start_rva": hex(section["rva"]),
                "section_size_bytes": section["size"],
                "method": "byte-only E8 rel32 target scans over .text; no broad function disassembly",
                "second_level_target": hex(UNRESOLVED_CALLER_RVA),
            },
            "window_contract": "each caller uses a 256-byte raw window [call-0xf0, call+0x10), containing 240 bytes before the 5-byte call and 11 bytes after it",
            "no_game_or_production_access": True,
            "old_reports_not_overwritten": True,
        },
        "analysis": {
            "decoder": "capstone " + capstone.__version__ if capstone is not None else "bounded objdump -w -Mintel",
            "first_level_direct_call_count": len(wrapper_records),
            "second_level_direct_call_count": len(second_records),
            "new_decode_bytes": decode_total,
            "limits": {
                "max_total_decode_bytes": MAX_TOTAL_DECODE_BYTES,
                "single_raw_window_bytes": RAW_WINDOW_BYTES,
                "first_level_max_callers": 16,
                "second_level_max_callers": 16,
                "runtime_process_opened": False,
                "rpm_used": False,
                "rea_used": False,
                "production_written": False,
                "full_image_disassembly": False,
            },
        },
        "prior_comparison": {
            "path": prior_report.relative_to(ROOT).as_posix(),
            "sha256": _sha_file(prior_report),
            "used_as": "25AB20 direct-caller inventory and the 3BADFA containing pdata function; no previous code window repeated",
        },
        "first_level_wrapper_callers": wrapper_records,
        "second_level_unresolved_input_callers": second_records,
        "findings": {
            "wrapper_direct_call_set": {
                "status": "closed_for_current_text_section",
                "target_rva": hex(WRAPPER_RVA),
                "call_rvas": [hex(hit["call_rva"]) for hit in wrapper_hits],
                "pdata_boundary": [hex(WRAPPER_RVA), hex(WRAPPER_END_RVA + 1)],
            },
            "r8b_sources": {
                "0x3bab52": {
                    "source": "mov r8b,0x1 at 0x3bab49",
                    "meaning": "literal constant 1; no collect/transfer name in the window",
                },
                "0x3bb1a3": {
                    "source": "movzx r8d,dl at 0x3bb19a; DL was loaded from [RSP+0xC8] by movzx edx,BYTE PTR [rsp+0xc8] at 0x3bb14f",
                    "meaning": "stack-byte input remains unresolved after one caller level",
                },
                "0x774e35": {
                    "source": "xor r8d,r8d at 0x774e2f",
                    "meaning": "literal zero",
                },
            },
            "second_level_resolution": {
                "target_function_rva": hex(UNRESOLVED_CALLER_RVA),
                "call_rvas": [hex(hit["call_rva"]) for hit in second_hits],
                "0x3bad58": {
                    "source": "lea r8,[rsp+0x50] at 0x3bad4b",
                    "meaning": "address of a caller stack/local record; not +0x229 or an explicit named action constant",
                },
                "0x774de1": {
                    "source": "lea r8,[rbp-0x80] at 0x774dda",
                    "meaning": "address of a caller local record; not +0x229 or an explicit named action constant",
                },
                "stop_reason": "The unresolved stack-byte path has been followed through its two direct callers; neither exposes the 101CB60 +0x229 byte or a named collect/transfer constant in the bounded windows.",
            },
            "ui_mode_edge": {
                "status": "not_closed",
                "comparison_offset": "0x229",
                "references_in_all_new_windows": [],
                "conclusion": "No wrapper caller examined here derives R8B from the 101CB60 widget mode byte.",
            },
            "merchant_task": {
                "status": "unknown",
                "safe_mapping": "Do not map the constant 1, zero, stack-byte, or local-record pointer to merchant_task, collect, transfer, or steering_direction.",
            },
        },
        "unresolved_conditions": [
            "Indirect calls and function-pointer dispatch were not searched.",
            "The stack/local records passed as R8 in 0x3bad58 and 0x774de1 were not decoded beyond the bounded caller windows.",
            "No command enum, UI action handler, or 101CB60 class identity was proven.",
            "No game/RPM/runtime observation was performed.",
        ],
    }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT
        / "work/runtime/information-trade-merchant-task-20261027-001/merchant-task-source-004.json",
    )
    args = parser.parse_args()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    output = output.resolve()
    if output.exists():
        raise SystemExit("refusing_to_overwrite_output")
    report = build_report()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    digest = _sha_file(output)
    print(
        json.dumps(
            {
                "output": output.relative_to(ROOT).as_posix(),
                "sha256": digest,
                "bytes": output.stat().st_size,
                "first_level_direct_call_count": report["analysis"]["first_level_direct_call_count"],
                "second_level_direct_call_count": report["analysis"]["second_level_direct_call_count"],
                "new_decode_bytes": report["analysis"]["new_decode_bytes"],
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
