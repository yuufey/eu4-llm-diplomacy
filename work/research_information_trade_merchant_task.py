"""Bounded ordinary-static follow-up for T05 merchant-task state.

This report follows the four already-known B59550 callers only far enough to
bind the byte/object dataflow and the nearest constructor/serializer paths.
It reuses the previous B59550/B5E100 and aggregate-gate evidence instead of
decoding those functions again.  A byte field copied through a constructor or
serialized with a numeric tag is kept separate from a proven collect/transfer
meaning.
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
MAX_TOTAL_DECODE_BYTES = 24 * 1024

# The B59550 callers and B5E100 wrapper were decoded in merchant-state-source
# 002.  These are new, narrow constructor/serializer/lifecycle windows.
CODE_RANGES = (
    (0x25AB20, 0x25ABF7, "merchant_task_object_constructor"),
    (0x274410, 0x274710, "merchant_task_serializer_parser"),
    (0x3BADC0, 0x3BAE80, "merchant_task_constructor_caller"),
    (0x9D8F0E, 0x9D8F50, "merchant_task_default_constructor_caller"),
    (0x305C40, 0x305CA1, "merchant_task_state_cleanup"),
)

LITERALS = {
    0x1C6F048: "TRADE_MERCHANT_PRESENT",
    0x1D4FCD8: "TRADE_MERCHANT_UNABLE",
    0x1D4FD48: "TRADE_MERCHANT_ALREADY_COLLECTING",
    0x1D4FD70: "TRADE_MERCHANT_ALREADY_TRANSFERRING",
    0x1D648D8: "%d",
    0x1D6D084: "%i",
}


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


def _prior_ranges(report: dict, labels: set[str]) -> list[dict]:
    result = []
    for item in report.get("ranges", []):
        if item.get("label") in labels:
            result.append({
                "label": item["label"],
                "start_rva": item["start_rva"],
                "end_rva_exclusive": item["end_rva_exclusive"],
                "start_va": item["start_va"],
                "end_va_exclusive": item["end_va_exclusive"],
                "byte_length": item["byte_length"],
                "bytes_sha256": item["bytes_sha256"],
                "coverage": item.get("coverage"),
                "reused_without_new_decode": True,
                "source_report": "work/runtime/information-trade-merchant-state-20261027-001/merchant-state-source-002.json",
            })
    return result


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

    prior_path, prior = _prior_report(
        "work/runtime/information-trade-merchant-state-20261027-001/merchant-state-source-002.json"
    )
    presence_path, presence = _prior_report(
        "work/runtime/information-trade-merchant-task-20261027-001/merchant-presence-source-001.json"
    )
    old_task_path, old_task = _prior_report(
        "work/runtime/information-trade-state-20261027-001/merchant-task-source-001.json"
    )

    present_xref_rva = 0x4B163D
    present_xref_raw = pe.bytes_at(present_xref_rva, 7)
    present_xref_target = present_xref_rva + 7 + struct.unpack_from("<i", present_xref_raw, 3)[0]
    if present_xref_target != 0x1C6F048:
        raise AssertionError(
            f"TRADE_MERCHANT_PRESENT xref mismatch: {present_xref_target:#x}"
        )

    selected = {
        "merchant_task_object_constructor": _selected(
            decoded,
            "merchant_task_object_constructor",
            (0x25AB20, 0x25AB34, 0x25AB3E, 0x25ABDD),
        ),
        "merchant_task_serializer_parser": _selected(
            decoded,
            "merchant_task_serializer_parser",
            (
                0x274410, 0x274520, 0x274569, 0x2745D0,
                0x2745E3, 0x2746A3, 0x2746B2, 0x2746BE,
                0x2746D4, 0x2746E2, 0x2746ED, 0x2746F4,
            ),
        ),
        "merchant_task_constructor_caller": _selected(
            decoded,
            "merchant_task_constructor_caller",
            (0x3BADCF, 0x3BADF0, 0x3BADFA, 0x3BAE00, 0x3BAE44),
        ),
        "merchant_task_default_constructor_caller": _selected(
            decoded,
            "merchant_task_default_constructor_caller",
            (0x9D8F0E, 0x9D8F1F, 0x9D8F27, 0x9D8F3A),
        ),
        "merchant_task_state_cleanup": _selected(
            decoded,
            "merchant_task_state_cleanup",
            (0x305C40, 0x305C7C, 0x305C88, 0x305C8D, 0x305C95, 0x305C98, 0x305C9C),
        ),
    }

    # These instructions are copied from the prior bounded report by hash,
    # rather than decoded again in this stage.
    reused_callers = {
        "source_report_sha256": _sha_file(prior_path),
        "b59550_direct_callers": [
            {
                "call_rva": "0x25ae52",
                "call_va": _va(0x25AE52),
                "call_bytes_hex": "e8f9e68f00",
                "object_rcx": "[R13+0x80]",
                "fullref_rdx": "[R13+0x40]",
                "ac_r8b": "[R13+0x9c]",
                "nearby_state": "[R13+0x98]=1 before the wrapper; no named task key",
            },
            {
                "call_rva": "0x25b9d3",
                "call_va": _va(0x25B9D3),
                "call_bytes_hex": "e878db8f00",
                "object_rcx": "[R13+0x80]",
                "fullref_rdx": "[R13+0x40]",
                "ac_r8b": "[R13+0x9c]",
                "nearby_state": "same wrapper after [R13+0x98] state checks; no named task key",
            },
            {
                "call_rva": "0x27427a",
                "call_va": _va(0x27427A),
                "call_bytes_hex": "e8d1528e00",
                "object_rcx": "RSI=[R11+0xe8] node-like object",
                "fullref_rdx": "[RCX_at_entry+0x50]",
                "ac_r8b": "[RDI+0x64]",
                "result_use": "AL is copied to [[RBX+0x10]+0x9c] at 0x274287",
            },
            {
                "call_rva": "0x305c9c",
                "call_va": _va(0x305C9C),
                "call_bytes_hex": "e8af388500",
                "object_rcx": "anchor/runtime object retained by the identity comparison",
                "fullref_rdx": "[R13+0x20]",
                "ac_r8b": "literal 0 after clearing source +0x9c",
                "result_use": "cleanup/reset path; no task label",
            },
        ],
        "wrapper_contract": {
            "source_report": "work/runtime/information-trade-merchant-state-20261027-001/merchant-state-source-002.json",
            "entry_rva": "0xb59550",
            "setter_rva": "0xb5e100",
            "caller_r8b": "forwarded as B5E100 AC input",
            "caller_dl": "literal 1 at 0xb59850, forwarded as B5E100 AE input",
            "entry_rcx": "computed entry pointer RSI",
            "not_redecoded": True,
        },
        "node_caller_result_copy": {
            "rva": "0x274287",
            "va": _va(0x274287),
            "bytes_hex": "88819c000000",
            "effect": "copy B59550 return AL into task-like object +0x9c",
        },
    }

    report = {
        "schema": "information.trade_state.merchant_task_source.v4",
        "stage": "information-trade-merchant-task-20261027-001",
        "evidence_kind": "ordinary_static_file_analysis_not_REA_evidence",
        "target": {
            "game_version": "1.37.4",
            "exe_sha256": binary_sha256,
            "image_base_va": hex(pe.base),
            "address_kind": "RVA; VA=image_base_va+RVA; all ranges are [begin,end)",
        },
        "scope": {
            "question": "T05 merchant_task and merchant existence: bind B59550 caller bytes to object lifecycle/serialization, or leave collect/transfer semantics unresolved",
            "priority": "0x27427a object+0x64, then 0x25ae52/0x25b9d3 object+0x9c",
            "reused_prior": "B59550/B5E100 wrapper, direct caller set, aggregate B58C70 and UI gate are imported by hash; no whole-function repeat",
            "no_game_or_production_access": True,
            "old_reports_not_overwritten": True,
        },
        "analysis": {
            "decoder": (
                "capstone " + capstone.__version__
                if capstone is not None
                else "bounded objdump -w -Mintel"
            ),
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
        },
        "prior_evidence": {
            "merchant_state_source_002": {
                "path": prior_path.relative_to(ROOT).as_posix(),
                "sha256": _sha_file(prior_path),
                "used_as": "B59550/B5E100 caller bytes, wrapper AC/AE dataflow and 101CB60 UI labels; not overwritten",
            },
            "merchant_presence_source_001": {
                "path": presence_path.relative_to(ROOT).as_posix(),
                "sha256": _sha_file(presence_path),
                "used_as": "bounded STEER_NO_TRADER path after B58C70 false; not decoded again",
            },
            "merchant_task_source_001": {
                "path": old_task_path.relative_to(ROOT).as_posix(),
                "sha256": _sha_file(old_task_path),
                "used_as": "B58C70 aggregate predicate contract; not decoded again",
            },
        },
        "ranges": ranges,
        "reused_prior_ranges": _prior_ranges(
            prior,
            {"b59550_setter_wrapper", "b59550_callers_state_machine", "b59550_caller_node_state", "b59550_caller_vector_cleanup"},
        ),
        "selected_instructions": selected,
        "static_literals": [_cstring(pe, rva, value) for rva, value in LITERALS.items()],
        "reused_caller_dataflow": reused_callers,
        "constructor_and_serialization": {
            "constructor_25ab20": {
                "function_rva": "0x25ab20",
                "input_r8b": "captured as EDI at 0x25ab34",
                "write": "BYTE [RBX+0x9c]=DIL at 0x25abdd",
                "meaning_closed": "object lifecycle/state byte is copied from the caller; no collect/transfer name",
            },
            "constructor_callers": [
                {
                    "call_rva": "0x3badfa",
                    "call_va": _va(0x3BADFA),
                    "r8b_source": "caller R8B copied through EBX and passed to 25AB20",
                    "nearby_assignments": "new object +0x40 receives [RBP+0x20]; [RDI+0x18]=2 after construction",
                    "task_semantics": "unresolved object/state type",
                },
                {
                    "call_rva": "0x9d8f27",
                    "call_va": _va(0x9D8F27),
                    "r8b_source": "literal zero in R8D before 25AB20",
                    "nearby_assignments": "default/error construction path; no collect/transfer key",
                    "task_semantics": "unresolved object/state type",
                },
                {
                    "call_rva": "0x2742b4/0x2742ec",
                    "call_va": [_va(0x2742B4), _va(0x2742EC)],
                    "r8b_source": "[RDI+0x64] from the prioritized caller object",
                    "nearby_assignments": "fallback objects are created with the same +0x64 byte copied into +0x9c",
                    "task_semantics": "lifecycle/dataflow only; no named mode",
                },
            ],
            "serializer_274410": {
                "field_plus_0x60": {
                    "tag": "0x1b",
                    "format_literal_rva": "0x1d648d8",
                    "format_literal": "%d",
                    "effect": "writes numeric object +0x60 through generic serializer",
                },
                "field_plus_0x64": {
                    "tag": "0xe1",
                    "format_literal_rva": "0x1d648d8",
                    "format_literal": "%d",
                    "effect": "writes numeric object +0x64 through the same generic serializer",
                },
            },
            "parser_2745d0": {
                "dispatch": {
                    "tag_0x1b": "0x2746e2 parses %i from [input+0x444] into object+0x60",
                    "tag_0xe1": "0x2746a3 parses %i from [input+0x444] into a byte temporary, then stores it to object+0x64 at 0x2746d4",
                    "tag_0x2843": "separate province/runtime path; not followed",
                    "tag_0x289d": "separate path; not followed",
                },
                "format_literal": {
                    "rva": "0x1d6d084",
                    "va": _va(0x1D6D084),
                    "bytes_hex": "256900",
                    "value": "%i",
                },
                "semantic_limit": "numeric persistence tag proves object field serialization, not collect/transfer business meaning",
            },
        },
        "lifecycle_and_locale": {
            "cleanup_305c9c": {
                "write_rva": "0x305c8d",
                "write_va": _va(0x305C8D),
                "bytes_hex": "41c6809c00000000",
                "effect": "clears source object +0x9c, then wrapper receives R8D=0 at 0x305c95",
                "meaning": "reset/cleanup lifecycle; not transfer proof",
            },
            "present_literal": {
                "rva": "0x1c6f048",
                "va": _va(0x1C6F048),
                "bytes_hex": "54524144455f4d45524348414e545f50524553454e5400",
                "value": "TRADE_MERCHANT_PRESENT",
                "locale": "native ASCII key; language-table lookup not followed",
                "xref": {
                    "rva": hex(present_xref_rva),
                    "va": _va(present_xref_rva),
                    "bytes_hex": present_xref_raw.hex(),
                    "effect": "string-registration/format assembly xref, outside the four B59550 caller paths",
                    "semantic_use_proven": False,
                },
            },
            "mode_labels_reused": {
                "collecting_rva": "0x1d4fd48",
                "transferring_rva": "0x1d4fd70",
                "unable_rva": "0x1d4fcd8",
                "meaning": "labels belong to the prior 101CB60 UI gate; they do not name the +0x64/+0x9c fields",
            },
            "prior_steer_no_trader": {
                "source_report": presence_path.relative_to(ROOT).as_posix(),
                "status": "bounded_label_only",
                "meaning": "ordinary entry+0xae==0 after B58C70 false can reach STEER_NO_TRADER; this does not prove AE means merchant-present or a task enum",
            },
        },
        "findings": {
            "merchant_present": {
                "status": "not_closed",
                "evidence": "TRADE_MERCHANT_PRESENT literal exists, but its only direct RIP xref in this static scan is a registration/format path, not a state branch; B59550 callers carry only bytes/pointers",
                "safe_mapping": "keep merchant presence unknown; do not convert collection false or entry+0xae==0 into no-merchant",
            },
            "merchant_task": {
                "status": "unknown",
                "evidence": "0x27427a proves object+0x64 -> B59550 AC input and return AL -> another object+0x9c; 0x25ae52/0x25b9d3 prove object+0x9c -> AC input; 0xe1 serializer/parser tag proves persistence only",
                "collect_transfer_semantics": "not proven; no bounded caller passes a collect/transfer command, locale key, or enum discriminator",
                "public_mapping": "do not expose merchant_task; retain aggregate collection predicate and native flags separately",
            },
            "collection": {
                "status": "aggregate_only_reused",
                "meaning": "B58C70 eligibility remains the only closed collection-style bool; mode labels and lifecycle bytes do not expand it into merchant_task",
            },
        },
        "unresolved_conditions": [
            "The C++ identity and semantic ownership of object +0x64/+0x9c remain unknown.",
            "Serializer tags 0x1b/0xe1 are numeric field IDs; no locale or collect/transfer enum mapping was found in the bounded windows.",
            "The 0x14125b340 parser/formatter callee and generic serializer implementation were intentionally not followed.",
            "Indirect callers and UI command construction outside the four B59550 direct callers were not claimed closed.",
            "No game/RPM/runtime observation was performed, so no current merchant task state is asserted.",
        ],
    }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT
        / "work/runtime/information-trade-merchant-task-20261027-001/merchant-task-source-001.json",
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
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
