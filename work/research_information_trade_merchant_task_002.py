"""Bounded ordinary-static follow-up for the T05 merchant-task chain.

This pass connects the already named ``101CB60`` UI mode read and the only
bounded ``TRADE_MERCHANT_PRESENT`` literal reference to the existing state
evidence.  It deliberately does not repeat the constructor, serializer, or
logger windows from source-001/source-002.  A missing edge is recorded as a
bounded negative result rather than being filled in with an AC/AE business
name.
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
MAX_SINGLE_DECODE_BYTES = 4 * 1024
MAX_TOTAL_DECODE_BYTES = 16 * 1024

# Only the new literal-registration/format-assembly context is decoded here.
# The 101CB60 and constructor windows are imported by hash from earlier
# bounded reports and are not decoded again.
CODE_RANGES = (
    (0x4B1400, 0x4B1800, "trade_merchant_present_reference_context"),
    # This is the complete pdata-bounded callee reached by the reference
    # record's call at 0x4b164c.  It is still only 988 bytes, and is decoded
    # to check the formatter body for an entry+AE/AC state branch.
    (0x14A6D90, 0x14A716C, "trade_merchant_present_format_callee"),
)


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


def _selected(decoded, label, addresses):
    mapping = _instruction_map(decoded[label])
    missing = [hex(address) for address in addresses if address not in mapping]
    if missing:
        raise AssertionError(f"decoder did not return {label} instructions: {missing}")
    return [mapping[address] for address in addresses]


def _range_record(pe: PE, rows, begin: int, end: int, label: str):
    raw = pe.bytes_at(begin, end - begin)
    function = pe.function(begin)
    return {
        "label": label,
        "start_rva": hex(begin),
        "end_rva_exclusive": hex(end),
        "start_va": _va(begin),
        "end_va_exclusive": _va(end),
        "byte_length": len(raw),
        "bytes_sha256": _sha_bytes(raw),
        "pdata_function_boundary": (
            [hex(function[0]), hex(function[1])] if function else None
        ),
        "coverage": (
            "complete_explicit_window"
            if function and begin == function[0] and end == function[1]
            else "partial_or_explicit_window"
        ),
        "decoded_instruction_count": len(rows),
    }


def _direct_e8_calls_in_window(pe: PE, begin: int, end: int, target_rva: int):
    """Find direct E8 rel32 calls without reading outside this old window."""
    raw = pe.bytes_at(begin, end - begin)
    hits = []
    for offset in range(0, max(0, len(raw) - 4)):
        if raw[offset] != 0xE8:
            continue
        call_rva = begin + offset
        destination = call_rva + 5 + struct.unpack_from("<i", raw, offset + 1)[0]
        if destination != target_rva:
            continue
        hits.append(
            {
                "call_rva": hex(call_rva),
                "call_va": _va(call_rva),
                "target_rva": hex(target_rva),
                "target_va": _va(target_rva),
                "call_bytes_hex": raw[offset : offset + 5].hex(),
                "evidence": "bounded raw E8 rel32 scan; no disassembly claim",
            }
        )
    return hits


def _cstring(pe: PE, rva: int, expected: str):
    raw = bytearray()
    for offset in range(512):
        byte = pe.bytes_at(rva + offset, 1)
        if not byte:
            break
        raw.extend(byte)
        if byte == b"\0":
            break
    wanted = expected.encode("ascii") + b"\0"
    if bytes(raw) != wanted:
        raise AssertionError(f"literal mismatch at {rva:#x}: {bytes(raw)!r}")
    return {
        "rva": hex(rva),
        "va": _va(rva),
        "string_or_format": expected,
        "bytes_hex": bytes(raw).hex(),
        "bytes_sha256": _sha_bytes(bytes(raw)),
        "evidence": "ordinary native PE ASCII literal; no runtime locale claim",
    }


def _prior_report(relative_path: str):
    path = ROOT / relative_path
    with path.open("r", encoding="utf-8") as stream:
        return path, json.load(stream)


def _reused_range(report: dict, label: str, source_path: Path):
    item = next(item for item in report.get("ranges", []) if item.get("label") == label)
    return {
        "label": item["label"],
        "start_rva": item["start_rva"],
        "end_rva_exclusive": item["end_rva_exclusive"],
        "start_va": item["start_va"],
        "end_va_exclusive": item["end_va_exclusive"],
        "byte_length": item["byte_length"],
        "bytes_sha256": item["bytes_sha256"],
        "coverage": item.get("coverage"),
        "reused_without_new_decode": True,
        "source_report": source_path.relative_to(ROOT).as_posix(),
    }


def _prior_instruction_rows(report: dict, group: str, addresses):
    rows = report["selected_instructions"][group]
    mapping = _instruction_map(rows)
    missing = [hex(address) for address in addresses if address not in mapping]
    if missing:
        raise AssertionError(f"prior report lacks {group} instructions: {missing}")
    return [mapping[address] for address in addresses]


def build_report():
    pe = PE(game_exe())
    binary_sha256 = _sha_bytes(pe.data)
    if binary_sha256 != EXPECTED_SHA256:
        raise ValueError(f"unsupported game binary SHA-256: {binary_sha256}")
    if pe.base != IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.base:#x}")

    md, capstone = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    decoded = {}
    ranges = []
    total = 0
    for begin, end, label in CODE_RANGES:
        if end <= begin or end - begin > MAX_SINGLE_DECODE_BYTES:
            raise AssertionError(f"single-range limit failure: {begin:#x}:{end:#x}")
        if not pe.executable(begin) or not pe.executable(end - 1):
            raise AssertionError(f"range is not executable: {begin:#x}:{end:#x}")
        total += end - begin
        if total > MAX_TOTAL_DECODE_BYTES:
            raise AssertionError("total decode limit failure")
        rows = _decode_range(pe, md, begin, end)
        decoded[label] = rows
        ranges.append(_range_record(pe, rows, begin, end, label))

    state_path, state = _prior_report(
        "work/runtime/information-trade-merchant-state-20261027-001/merchant-state-source-002.json"
    )
    task_path, task = _prior_report(
        "work/runtime/information-trade-merchant-task-20261027-001/merchant-task-source-001.json"
    )
    presence_path, presence = _prior_report(
        "work/runtime/information-trade-merchant-task-20261027-001/merchant-presence-source-001.json"
    )

    ui_begin, ui_end = 0x101CB60, 0x101D0B2
    ctor_calls_in_ui = _direct_e8_calls_in_window(pe, ui_begin, ui_end, 0x25AB20)
    b58c70_calls_in_ui = _direct_e8_calls_in_window(pe, ui_begin, ui_end, 0xB58C70)
    if ctor_calls_in_ui:
        raise AssertionError("unexpected 25AB20 call in the bounded 101CB60 UI window")
    if [item["call_rva"] for item in b58c70_calls_in_ui] != ["0x101cd27", "0x101cd7a"]:
        raise AssertionError("unexpected B58C70 call set in the bounded UI window")

    present_xref_rva = 0x4B163D
    present_xref_raw = pe.bytes_at(present_xref_rva, 7)
    if len(present_xref_raw) != 7 or present_xref_raw[:3] != b"\x48\x8d\x15":
        raise AssertionError("unexpected TRADE_MERCHANT_PRESENT xref instruction")
    present_xref_target = present_xref_rva + 7 + struct.unpack_from("<i", present_xref_raw, 3)[0]
    if present_xref_target != 0x1C6F048:
        raise AssertionError(f"TRADE_MERCHANT_PRESENT xref mismatch: {present_xref_target:#x}")

    selected_ui = _prior_instruction_rows(
        state,
        "merchant_status_ui_gate",
        (
            0x101CD0D,
            0x101CD14,
            0x101CD16,
            0x101CD18,
            0x101CD27,
            0x101CD2C,
            0x101CD4B,
            0x101CD74,
            0x101CD7A,
            0x101CD7F,
            0x101CD81,
            0x101CD9E,
            0x101CF2C,
            0x101CF3B,
        ),
    )

    selected_present = _selected(
        decoded,
        "trade_merchant_present_reference_context",
        (
            0x4B15A9,
            0x4B15B0,
            0x4B15BF,
            0x4B1636,
            0x4B163D,
            0x4B1644,
            0x4B164C,
            0x4B165A,
            0x4B165F,
        ),
    )
    selected_format = _selected(
        decoded,
        "trade_merchant_present_format_callee",
        (
            0x14A6DB4,
            0x14A6DB7,
            0x14A6DE0,
            0x14A6E49,
            0x14A6E86,
            0x14A6F33,
            0x14A703C,
            0x14A708B,
            0x14A70ED,
            0x14A7116,
            0x14A715D,
        ),
    )

    format_rows = decoded["trade_merchant_present_format_callee"]
    format_state_accesses = [
        row
        for row in format_rows
        if "+0xae" in row.get("operands", "").lower()
        or "+0xac" in row.get("operands", "").lower()
    ]
    format_b58c70_calls = _direct_e8_calls_in_window(
        pe, 0x14A6D90, 0x14A716C, 0xB58C70
    )
    if format_state_accesses or format_b58c70_calls:
        raise AssertionError(
            "unexpected entry flag or B58C70 access in the complete format callee"
        )

    report = {
        "schema": "information.trade_merchant_task.merchant_task_source.v5",
        "stage": "information-trade-merchant-task-20261027-001",
        "evidence_kind": "ordinary_static_file_analysis_not_REA_evidence",
        "target": {
            "game_version": "1.37.4",
            "exe_sha256": binary_sha256,
            "image_base_va": hex(pe.base),
            "address_kind": "RVA; VA=image_base_va+RVA; all ranges are [begin,end)",
        },
        "scope": {
            "question": "Can the named UI collect/transfer mode reach the AC constructor byte, and does TRADE_MERCHANT_PRESENT have a bounded entry+AE state branch?",
            "new_work": "one 0x400-byte xref context, one complete 988-byte formatter callee, plus raw E8 checks confined to the reused 101CB60 window",
            "reused_prior": "source-001 constructor/serializer and source-002 B59550/UI/presence paths; no duplicate parser/logger decode",
            "no_game_or_production_access": True,
            "old_reports_not_overwritten": True,
        },
        "analysis": {
            "decoder": "capstone " + capstone.__version__ if capstone is not None else "bounded objdump -w -Mintel",
            "decoded_bytes": total,
            "range_count": len(CODE_RANGES),
            "limits": {
                "single_code_range_bytes": MAX_SINGLE_DECODE_BYTES,
                "total_code_decode_bytes": MAX_TOTAL_DECODE_BYTES,
                "runtime_process_opened": False,
                "rpm_used": False,
                "rea_used": False,
                "production_written": False,
                "full_image_disassembly": False,
            },
            "raw_window_checks": {
                "101CB60_window": {
                    "start_rva": hex(ui_begin),
                    "end_rva_exclusive": hex(ui_end),
                    "target_25ab20_constructor": ctor_calls_in_ui,
                    "target_b58c70_aggregate": b58c70_calls_in_ui,
                    "method": "bounded raw E8 rel32 scan over the already hashed UI window",
                },
            },
        },
        "prior_evidence": {
            "merchant_state_source_002": {
                "path": state_path.relative_to(ROOT).as_posix(),
                "sha256": _sha_file(state_path),
                "used_as": "constructor-call/UI mode bytes and B59550/AE state contract; no new decode",
            },
            "merchant_task_source_001": {
                "path": task_path.relative_to(ROOT).as_posix(),
                "sha256": _sha_file(task_path),
                "used_as": "constructor callers, numeric serializer limits and old merchant_task unknown; no new decode",
            },
            "merchant_presence_source_001": {
                "path": presence_path.relative_to(ROOT).as_posix(),
                "sha256": _sha_file(presence_path),
                "used_as": "bounded STEER_NO_TRADER/entry+AE==0 partial path; no new decode",
            },
        },
        "ranges": ranges,
        "reused_prior_ranges": [
            _reused_range(state, "merchant_status_ui_gate", state_path),
        ],
        "selected_instructions": {
            "new_present_reference_context": selected_present,
            "new_present_format_callee": selected_format,
            "reused_named_ui_mode_gate": selected_ui,
        },
        "static_literals": [
            _cstring(pe, 0x1C6F048, "TRADE_MERCHANT_PRESENT"),
            _cstring(pe, 0x1D4FD48, "TRADE_MERCHANT_ALREADY_COLLECTING"),
            _cstring(pe, 0x1D4FD70, "TRADE_MERCHANT_ALREADY_TRANSFERRING"),
        ],
        "named_ui_mode_to_ac": {
            "status": "no_direct_constructor_edge_in_bounded_window",
            "mode_field": {
                "rva": "0x101cd0d",
                "operands": "movzx edx,BYTE PTR [rdi+0x229]",
                "meaning_from_prior_report": "mode 0 selects the collecting check; mode 1 selects the transferring check; other values fall through the UI unable/fallback path",
            },
            "mode_branches": {
                "mode_0": "B58C70 at 0x101cd7a; B58C70 true reaches TRADE_MERCHANT_ALREADY_COLLECTING at 0x101cd9e",
                "mode_1": "B58C70 at 0x101cd27; B58C70 false reaches TRADE_MERCHANT_ALREADY_TRANSFERRING at 0x101cd4b",
            },
            "constructor_target": {
                "rva": "0x25ab20",
                "ui_window_direct_calls": ctor_calls_in_ui,
                "result": "the reused 101CB60 bytes contain no direct call to 25AB20; the two calls in the window are the existing B58C70 aggregate checks",
            },
            "prior_constructor_callers": task["constructor_and_serialization"]["constructor_callers"],
            "conclusion": "The named widget mode is statically tied to the two B58C70 status-label branches, but no bounded edge ties widget+0x229 to constructor R8B or cached AC. AC remains unmapped to collect/transfer mode.",
        },
        "present_literal_followup": {
            "literal": {
                "rva": "0x1c6f048",
                "va": _va(0x1C6F048),
                "value": "TRADE_MERCHANT_PRESENT",
            },
            "only_known_direct_xref": {
                "rva": hex(present_xref_rva),
                "va": _va(present_xref_rva),
                "bytes_hex": present_xref_raw.hex(),
                "target_rva": hex(present_xref_target),
            },
            "bounded_context": {
                "range": "0x4b1400..0x4b1800",
                "selected": "repeated lea r8,<table-slot>; lea rdx, <ASCII key>; lea rcx,<stack record>; call 0x14a6d90, followed by cleanup/formatter calls",
                "state_reads": {
                    "entry_plus_0xae": False,
                    "entry_plus_0xac": False,
                    "b58c70_call": False,
                    "conditional_branch": False,
                },
                "interpretation": "This xref is a repeated key-registration/format-assembly record, not a bounded state branch. It does not establish merchant presence or a relation to AE.",
            },
            "format_callee": {
                "range": "0x14a6d90..0x14a716c",
                "pdata_coverage": "complete_function_boundary",
                "call_inputs_at_xref": {
                    "r8": "table/registration slot pointer",
                    "rdx": "ASCII key pointer",
                    "rcx": "stack record/object pointer",
                },
                "first_body_copies": {
                    "rva_0x14a6db4": "mov r12,r8",
                    "rva_0x14a6db7": "mov r14,rdx",
                },
                "entry_flag_accesses": format_state_accesses,
                "b58c70_calls": format_b58c70_calls,
                "generic_branches_present": True,
                "entry_ae_or_ac_branch": False,
                "interpretation": "The complete callee has generic formatter/table branches and string-buffer operations, but no entry+0xAE/+0xAC access and no B58C70 call. Its known inputs are registration/format data, so it cannot close TRADE_MERCHANT_PRESENT to a native merchant state.",
            },
            "result": "no_present_to_ae_edge_closed",
        },
        "bounded_presence_partial": {
            "source_report": presence_path.relative_to(ROOT).as_posix(),
            "status": "partial_reused",
            "condition": "after B58C70 returns false, ordinary entry+0xAE==0 can reach STEER_NO_TRADER; the special-slot/other guards remain part of the aggregate path",
            "safe_use": "This is a native status-label path only; it does not prove AE means merchant-present, and false does not imply none/transfer.",
        },
        "findings": {
            "merchant_present": {
                "status": "not_closed",
                "evidence": "The literal has one bounded direct RIP xref, and the decoded context contains only registration/format assembly with no entry+AE read or branch.",
                "safe_mapping": "Keep merchant presence unknown; do not derive it from collection false or from entry+0xAE==0.",
            },
            "merchant_task": {
                "status": "unknown",
                "evidence": "Named UI mode branches are connected to B58C70 labels, while all bounded 25AB20 callers remain object/lifecycle or numeric-state paths; no command, enum, or locale key reaches AC.",
                "collect_transfer_semantics": "not proven",
                "public_mapping": "Do not expose merchant_task, transfer, or steering_direction from this evidence.",
            },
            "collection": {
                "status": "aggregate_only_reused",
                "meaning": "B58C70 remains the closed collection-style aggregate predicate; the named UI labels do not expand it into a task enum.",
            },
        },
        "unresolved_conditions": [
            "No direct 101CB60 -> 25AB20 constructor edge was present in the bounded UI function; indirect UI command construction was not searched broadly.",
            "The only TRADE_MERCHANT_PRESENT xref was followed through 0x4b1400..0x4b1800; its surrounding function is much larger and was not decoded beyond this 1 KiB context.",
            "The semantic owner of object +0x64/+0x9c and the AC/AE business names remain unknown.",
            "No game/RPM/runtime observation was performed, so no current merchant presence/task state is asserted.",
        ],
    }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT
        / "work/runtime/information-trade-merchant-task-20261027-001/merchant-task-source-002.json",
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
                "decoded_bytes": report["analysis"]["decoded_bytes"],
                "range_count": len(report["ranges"]),
                "ui_constructor_calls": report["analysis"]["raw_window_checks"]["101CB60_window"]["target_25ab20_constructor"],
                "present_context_state_reads": report["present_literal_followup"]["bounded_context"]["state_reads"],
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
