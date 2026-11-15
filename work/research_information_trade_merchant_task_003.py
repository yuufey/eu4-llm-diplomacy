"""Bounded direct-caller inventory for the 25AB20 merchant-task constructor.

The scan is byte-only over the current PE ``.text`` section.  Only the four
direct E8 rel32 callers of 25AB20 are decoded, using a 96-byte pre-call and
16-byte post-call evidence window (plus the containing function start solely
to keep the disassembly instruction-aligned).  No formatter, serializer, or
logger path is followed in this pass.
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
TARGET_RVA = 0x25AB20
PRE_CALL_BYTES = 96
POST_CALL_BYTES = 16
MAX_TOTAL_DECODE_BYTES = 4 * 1024


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


def _instruction_map(rows):
    return {int(row["rva"], 16): row for row in rows}


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
            raise AssertionError(f"missing pdata function for caller {call_rva:#x}")
        hits.append(
            {
                "call_rva": call_rva,
                "call_va": _va(call_rva),
                "call_bytes_hex": pe.bytes_at(call_rva, 5).hex(),
                "target_rva": target_rva,
                "target_va": _va(target_rva),
                "pdata_function_boundary_rva": [function[0], function[1]],
                "pdata_function_boundary_va": [_va(function[0]), _va(function[1])],
            }
        )
    return section, hits


def _r8_destination(row):
    operands = row.get("operands", "").lower()
    destination = operands.split(",", 1)[0].strip()
    return destination in {"r8", "r8d", "r8w", "r8b"}


def _classify_r8_source(row):
    operands = row.get("operands", "").lower()
    if "[rdi+0x64]" in operands:
        return "object_plus_0x64_byte"
    if row.get("mnemonic") == "xor" and operands == "r8d,r8d":
        return "literal_zero"
    if row.get("mnemonic") == "movzx" and operands == "r8d,bl":
        return "incoming_r8b_captured_in_bl"
    return "unclassified_r8_assignment"


def _call_record(pe: PE, md, hit):
    call = hit["call_rva"]
    function_start, function_end = hit["pdata_function_boundary_rva"]
    window_start = call - PRE_CALL_BYTES
    window_end = call + 5 + POST_CALL_BYTES
    if window_start < function_start:
        # This does not change the requested raw evidence window.  It only
        # starts decoding at the pdata boundary so every returned instruction
        # is aligned; all selected rows remain inside the requested window.
        decode_start = function_start
    else:
        # Decode from the function boundary whenever available.  The four
        # callers are all close enough to their boundaries for this to stay
        # well below the total budget.
        decode_start = function_start
    rows = _decode_range(pe, md, decode_start, window_end)
    selected = [
        row
        for row in rows
        if window_start <= int(row["rva"], 16) < window_end
    ]
    before = [row for row in selected if int(row["rva"], 16) < call]
    after = [row for row in selected if int(row["rva"], 16) >= call + 5]
    r8_sources = [row for row in before if _r8_destination(row)]
    nearest = r8_sources[-1] if r8_sources else None
    raw_window = pe.bytes_at(window_start, window_end - window_start)
    return {
        "call_rva": hex(call),
        "call_va": _va(call),
        "call_bytes_hex": hit["call_bytes_hex"],
        "target_rva": hex(TARGET_RVA),
        "target_va": _va(TARGET_RVA),
        "pdata_function_boundary_rva": [hex(function_start), hex(function_end)],
        "pdata_function_boundary_va": [_va(function_start), _va(function_end)],
        "raw_evidence_window": {
            "start_rva": hex(window_start),
            "end_rva_exclusive": hex(window_end),
            "start_va": _va(window_start),
            "end_va_exclusive": _va(window_end),
            "pre_call_bytes": PRE_CALL_BYTES,
            "call_instruction_bytes": 5,
            "post_call_bytes": POST_CALL_BYTES,
            "byte_length": len(raw_window),
            "bytes_sha256": _sha_bytes(raw_window),
        },
        "decode_window": {
            "start_rva": hex(decode_start),
            "end_rva_exclusive": hex(window_end),
            "byte_length": window_end - decode_start,
            "instruction_count_in_requested_window": len(selected),
            "selected_instructions": selected,
        },
        "nearest_r8b_source": {
            "instruction": nearest,
            "classification": _classify_r8_source(nearest) if nearest else "not_found",
            "distance_bytes": call - int(nearest["rva"], 16) if nearest else None,
        },
        "r8b_widget_0x229_references_in_window": [
            row
            for row in selected
            if "+0x229" in row.get("operands", "").lower()
        ],
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

    section, hits = _direct_e8_calls_in_text(pe, TARGET_RVA)
    expected_calls = [0x2742B4, 0x2742EC, 0x3BADFA, 0x9D8F27]
    if [hit["call_rva"] for hit in hits] != expected_calls:
        raise AssertionError(
            f"unexpected direct 25AB20 callers: {[hex(hit['call_rva']) for hit in hits]}"
        )

    md, capstone = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    records = []
    decode_total = 0
    for hit in hits:
        record = _call_record(pe, md, hit)
        decode_total += record["decode_window"]["byte_length"]
        records.append(record)
    if decode_total > MAX_TOTAL_DECODE_BYTES:
        raise AssertionError(f"decode budget exceeded: {decode_total}")

    # The explicit current UI mode offset is carried in the prior bounded
    # report only as a comparison point.  No direct caller window above
    # contains that field, which is the result this pass needs to preserve.
    ui_mode_offset = "0x229"
    no_widget_mode_sources = all(
        not record["r8b_widget_0x229_references_in_window"] for record in records
    )
    if not no_widget_mode_sources:
        raise AssertionError("unexpected widget+0x229 source in constructor callers")

    prior_report = ROOT / "work/runtime/information-trade-merchant-task-20261027-001/merchant-task-source-002.json"
    report = {
        "schema": "information.trade_merchant_task.merchant_task_source.v6",
        "stage": "information-trade-merchant-task-20261027-001",
        "evidence_kind": "ordinary_static_file_analysis_not_REA_evidence",
        "target": {
            "game_version": "1.37.4",
            "exe_sha256": binary_sha256,
            "image_base_va": hex(pe.base),
            "address_kind": "RVA; VA=image_base_va+RVA; all ranges are [begin,end)",
        },
        "scope": {
            "question": "Inventory every direct E8 caller of constructor 25AB20 and identify the nearest R8B source.",
            "target_constructor_rva": hex(TARGET_RVA),
            "scan": {
                "section_name": section["name"],
                "section_raw_file_offset": hex(section["raw"]),
                "section_start_rva": hex(section["rva"]),
                "section_size_bytes": section["size"],
                "method": "byte-only E8 rel32 target scan over .text; no broad disassembly",
            },
            "window_contract": "for each call, raw [call-0x60, call+0x15) = 96 bytes before, 5-byte call, 16 bytes after; instruction decode starts at pdata function boundary and only reports rows inside that raw window",
            "no_game_or_production_access": True,
            "old_reports_not_overwritten": True,
        },
        "analysis": {
            "decoder": "capstone " + capstone.__version__ if capstone is not None else "bounded objdump -w -Mintel",
            "direct_call_count": len(records),
            "new_decode_bytes": decode_total,
            "limits": {
                "max_total_decode_bytes": MAX_TOTAL_DECODE_BYTES,
                "single_call_raw_window_bytes": PRE_CALL_BYTES + 5 + POST_CALL_BYTES,
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
            "used_as": "prior named 101CB60 widget+0x229 mode and constructor-call conclusion; no code window reused as new decode",
            "ui_mode_offset_rva": ui_mode_offset,
            "ui_mode_contract": "prior bounded report: mode 0 collecting-label branch, mode 1 transferring-label branch",
        },
        "direct_callers": records,
        "findings": {
            "direct_call_set": {
                "status": "closed_for_current_text_section",
                "call_rvas": [hex(hit["call_rva"]) for hit in hits],
                "meaning": "The current .text byte scan found exactly four direct rel32 callers of 25AB20.",
            },
            "r8b_sources": {
                "0x2742b4": "[RDI+0x64] byte, loaded at 0x2742a5",
                "0x2742ec": "[RDI+0x64] byte, loaded at 0x2742dd",
                "0x3badfa": "incoming caller R8B captured in EBX at 0x3badd7 and re-emitted to R8D at 0x3badf0",
                "0x9d8f27": "literal zero from XOR R8D,R8D at 0x9d8f1f",
            },
            "widget_mode_edge": {
                "status": "not_found_in_direct_constructor_callers",
                "widget_mode_offset": ui_mode_offset,
                "references_in_all_four_windows": [],
                "conclusion": "None of the four direct constructor callers derives R8B from a +0x229 byte. The object+0x64 sources are not shown to be the 101CB60 widget, and the parameter/zero sources do not identify a collect/transfer action.",
            },
            "merchant_task": {
                "status": "unknown",
                "safe_mapping": "Do not map AC or constructor R8B to merchant_task, collect, transfer, or steering_direction from these callers.",
            },
        },
        "unresolved_conditions": [
            "The scan closes direct E8 callers in the current .text section only; indirect calls and function-pointer dispatch were not searched.",
            "The semantic identity of object+0x64 and the incoming R8B parameter remains unknown.",
            "No class-identity comparison to 101CB60 was needed because no direct caller window contained +0x229.",
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
        / "work/runtime/information-trade-merchant-task-20261027-001/merchant-task-source-003.json",
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
                "direct_call_count": report["analysis"]["direct_call_count"],
                "new_decode_bytes": report["analysis"]["new_decode_bytes"],
                "call_rvas": report["findings"]["direct_call_set"]["call_rvas"],
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
