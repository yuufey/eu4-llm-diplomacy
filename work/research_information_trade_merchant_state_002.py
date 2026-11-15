"""Bounded ordinary-static follow-up for the merchant aggregate gate.

This stage adds only the direct callers of B5E100/B59550 and a complete
bounded read of the 101CB60 UI gate.  It does not decode the logger, the
generic boolean parser, or the already-closed AD path.  The result separates
the native aggregate eligibility predicate from the unresolved AC/AE business
names and from the UI's mode-specific collecting/transferring messages.
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

# All five windows are new for this follow-up.  The aggregate predicate
# B58C70 itself is imported from the previous report by hash; it is not
# decoded again here.
CODE_RANGES = (
    (0xB59550, 0xB599BF, "b59550_setter_wrapper"),
    (0x25AD40, 0x25BA2F, "b59550_callers_state_machine"),
    (0x2741B0, 0x2743F9, "b59550_caller_node_state"),
    (0x3052C0, 0x305D44, "b59550_caller_vector_cleanup"),
    (0x101CB60, 0x101D0B2, "merchant_status_ui_gate"),
)

STRING_LITERALS = {
    0x1D4FCD8: "TRADE_MERCHANT_UNABLE",
    0x1D4FD48: "TRADE_MERCHANT_ALREADY_COLLECTING",
    0x1D4FD70: "TRADE_MERCHANT_ALREADY_TRANSFERRING",
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


def _direct_e8_calls(pe: PE, target_rva: int):
    """Find direct E8 rel32 calls without disassembling the image."""
    hits = []
    for section in pe.sections:
        if not section["flags"] & 0x20000000:
            continue
        start = section["raw"]
        stop = section["raw"] + section["size"] - 5
        for offset in range(start, stop + 1):
            if pe.data[offset] != 0xE8:
                continue
            call_rva = pe.to_rva(offset)
            destination = call_rva + 5 + struct.unpack_from("<i", pe.data, offset + 1)[0]
            if destination != target_rva:
                continue
            function = pe.function(call_rva)
            hits.append(
                {
                    "call_rva": hex(call_rva),
                    "call_va": _va(call_rva),
                    "target_rva": hex(target_rva),
                    "target_va": _va(target_rva),
                    "call_bytes_hex": pe.bytes_at(call_rva, 5).hex(),
                    "pdata_function": (
                        [hex(function[0]), hex(function[1])] if function else None
                    ),
                    "evidence": "raw E8 rel32 candidate; callsite is validated by bounded decode below",
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
        "key_or_literal": expected,
        "bytes_hex": bytes(raw).hex(),
        "bytes_sha256": _sha_bytes(bytes(raw)),
        "evidence": "ordinary native PE literal; no runtime locale claim",
    }


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


def _prior_report():
    path = ROOT / "work/runtime/information-trade-merchant-state-20261027-001/merchant-state-source-001.json"
    with path.open("r", encoding="utf-8") as stream:
        return path, json.load(stream)


def _b58c70_contract(prior):
    guard = prior["prior_evidence"]["prior_merchant_task_report"]
    old_path = ROOT / guard["path"]
    with old_path.open("r", encoding="utf-8") as stream:
        old = json.load(stream)
    target = next(
        item
        for item in old["target_and_callsite_guards"]
        if item["rva"] == "0xb58c70"
    )
    return {
        "source_report": old_path.relative_to(ROOT).as_posix(),
        "source_report_sha256": _sha_file(old_path),
        "target_rva": target["rva"],
        "target_va": target["va"],
        "target_bytes_hex": target["bytes_hex"],
        "target_bytes_sha256": target["bytes_sha256"],
        "reused_without_new_decode": True,
        "contract": {
            "special_slot": "special slot with a non-null computed entry returns true",
            "entry_pointer_precondition": "the computed entry must be a valid non-null pointer before this leaf is called; the non-special path dereferences +0xAE without a preceding null-safe false return",
            "special_null_entry": "a special-slot null pointer is outside the valid contract; after the special test the fallthrough also reaches the +0xAE dereference",
            "non_special_ae_zero": "returns true only when AD is nonzero",
            "non_special_ae_nonzero": "returns true only when AC is zero; AC nonzero returns false regardless of AD",
            "semantic_scope": "aggregate entry eligibility used by native income/steering paths, not a collect/transfer/none enum",
        },
    }


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

    call_b5e100 = _direct_e8_calls(pe, 0xB5E100)
    call_b59550 = _direct_e8_calls(pe, 0xB59550)
    if [item["call_rva"] for item in call_b5e100] != ["0xb59855"]:
        raise AssertionError("unexpected direct B5E100 caller set")
    if [item["call_rva"] for item in call_b59550] != [
        "0x25ae52",
        "0x25b9d3",
        "0x27427a",
        "0x305c9c",
    ]:
        raise AssertionError("unexpected direct B59550 caller set")

    selected = {
        "b59550_setter_wrapper": _selected(
            decoded,
            "b59550_setter_wrapper",
            (
                0xB59550,
                0xB59569,
                0xB59570,
                0xB59575,
                0xB595D7,
                0xB5981E,
                0xB59825,
                0xB5982A,
                0xB5984C,
                0xB59850,
                0xB59852,
                0xB59855,
            ),
        ),
        "b59550_callers_state_machine": _selected(
            decoded,
            "b59550_callers_state_machine",
            (
                0x25AD62,
                0x25AD6C,
                0x25AE2C,
                0x25AE3F,
                0x25AE47,
                0x25AE4B,
                0x25AE52,
                0x25B8E1,
                0x25B950,
                0x25B98A,
                0x25B9C7,
                0x25B9CF,
                0x25B9D3,
                0x25B7E8,
            ),
        ),
        "b59550_caller_node_state": _selected(
            decoded,
            "b59550_caller_node_state",
            (
                0x2741BF,
                0x2741CD,
                0x2741E4,
                0x2741F7,
                0x274272,
                0x274277,
                0x27427A,
            ),
        ),
        "b59550_caller_vector_cleanup": _selected(
            decoded,
            "b59550_caller_vector_cleanup",
            (
                0x3052E2,
                0x3052F8,
                0x305C7C,
                0x305C83,
                0x305C8D,
                0x305C95,
                0x305C98,
                0x305C9C,
            ),
        ),
        "merchant_status_ui_gate": _selected(
            decoded,
            "merchant_status_ui_gate",
            (
                0x101CC0A,
                0x101CC1D,
                0x101CC26,
                0x101CC32,
                0x101CC38,
                0x101CC40,
                0x101CC4C,
                0x101CC53,
                0x101CCBB,
                0x101CCC8,
                0x101CCCF,
                0x101CCD8,
                0x101CCEF,
                0x101CD04,
                0x101CD0D,
                0x101CD14,
                0x101CD16,
                0x101CD18,
                0x101CD21,
                0x101CD27,
                0x101CD2C,
                0x101CD2E,
                0x101CD34,
                0x101CD40,
                0x101CD4B,
                0x101CD56,
                0x101CD74,
                0x101CD7A,
                0x101CD7F,
                0x101CD81,
                0x101CD87,
                0x101CD9E,
                0x101CDA9,
                0x101CDC7,
                0x101CC8E,
                0x101CF0D,
                0x101CF18,
                0x101CF21,
                0x101CF2C,
                0x101CF3B,
                0x101CF44,
                0x101CF4A,
                0x101D08A,
            ),
        ),
    }

    prior_path, prior = _prior_report()
    report = {
        "schema": "information.trade_state.merchant_task_source.v3",
        "stage": "information-trade-merchant-state-20261027-001",
        "evidence_kind": "ordinary_static_file_analysis_not_REA_evidence",
        "target": {
            "game_version": "1.37.4",
            "exe_sha256": binary_sha256,
            "image_base_va": hex(pe.base),
            "address_kind": "RVA; VA=image_base_va+RVA; all ranges are [begin,end)",
        },
        "scope": {
            "question": "T05 collection/merchant_task: direct B5E100 callers and the complete 101CB60 aggregate UI gate",
            "new_decode_only": "B59550/B59550 callers and 101CB60 windows; B58C70 is reused from the prior hashed report",
            "no_game_or_production_access": True,
            "old_report_is_not_overwritten": True,
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
            "direct_call_scan": {
                "method": "raw E8 rel32 scan over executable PE sections; only the bounded caller windows are decoded",
                "target_b5e100": call_b5e100,
                "target_b59550": call_b59550,
            },
        },
        "prior_evidence": {
            "merchant_state_source_001": {
                "path": prior_path.relative_to(ROOT).as_posix(),
                "sha256": _sha_file(prior_path),
                "used_as": "previous-window hashes and conclusions; not overwritten",
            },
            "merchant_task_source_001": {
                "path": "work/runtime/information-trade-state-20261027-001/merchant-task-source-001.json",
                "sha256": _sha_file(
                    ROOT / "work/runtime/information-trade-state-20261027-001/merchant-task-source-001.json"
                ),
                "used_as": "B58C70 target bytes and prior aggregate-predicate evidence; not decoded again",
            },
        },
        "ranges": ranges,
        "selected_instructions": selected,
        "string_literals": [_cstring(pe, rva, value) for rva, value in STRING_LITERALS.items()],
        "setter_callers": {
            "target_setter": {
                "rva": "0xb5e100",
                "va": _va(0xB5E100),
                "direct_callsite": "0xb59855",
                "direct_callsite_bytes": pe.bytes_at(0xB59855, 5).hex(),
                "wrapper_dataflow": {
                    "entry_rva": "0xb59550",
                    "r8b": "captured at 0xb59569 as R13B and forwarded at 0xb5984c",
                    "dl": "set to literal 1 at 0xb59850 immediately before the B5E100 call",
                    "rcx": "computed entry pointer RSI at 0xb59852",
                    "effect": "B5E100 receives caller R8B as AC input and a fixed AE=1 input under its existing +0x38 guard",
                },
            },
            "direct_b59550_callers": [
                {
                    "call_rva": "0x25ae52",
                    "rcx": "[R13+0x80]",
                    "rdx": "[R13+0x40] fullref-like value",
                    "r8b": "[R13+0x9C]",
                    "nearby_state": "writes [R13+0x98]=1 and then invokes the wrapper",
                    "command_or_key": None,
                },
                {
                    "call_rva": "0x25b9d3",
                    "rcx": "[R13+0x80]",
                    "rdx": "[R13+0x40] fullref-like value",
                    "r8b": "[R13+0x9C]",
                    "nearby_state": "reached after [R13+0x98] state checks; the same wrapper path",
                    "command_or_key": None,
                },
                {
                    "call_rva": "0x27427a",
                    "rcx": "RSI=[R11+0xE8] node-like object",
                    "rdx": "[RCX_at_entry+0x50] fullref-like value",
                    "r8b": "[RDI+0x64]",
                    "nearby_state": "entry+AE is tested before the wrapper; no collect/transfer locale key is passed",
                    "command_or_key": None,
                },
                {
                    "call_rva": "0x305c9c",
                    "rcx": "anchor/runtime object retained from the identity comparison",
                    "rdx": "[R13+0x20] fullref-like value",
                    "r8b": "literal 0 after [R8+0x9C]=0",
                    "nearby_state": "vector/list cleanup clears the source object's +0x9C before the wrapper; no transfer business label is proven",
                    "command_or_key": None,
                },
            ],
            "conclusion": "The direct callers provide state bytes/fullrefs/node objects; no bounded callsite passes a named collect/transfer command or serialization key. The only setter DL reaching B5E100 is the wrapper's literal 1, so AC/AE business names remain open.",
            "indirect_callers": "Not claimed closed; the scan only proves the four direct E8 callers above.",
        },
        "aggregate_ui_gate": {
            "function_rva": "0x101cb60",
            "context_gates_before_b58c70": [
                "[RDI+0x50] must be non-null on the initial path; a null value routes to the later unable/fallback path",
                "[RDI+0x60] and its +0xA8 node definition must be non-null",
                "0x6FFFC0(R11, selected_locale/fullref) must yield a runtime node whose +0x20 center equals definition +0xDC",
                "[R11+0x10] is non-null on the initial path; its business type is not proven",
                "the output string buffer RBX must be non-null before formatting; this is an output guard, not merchant presence",
            ],
            "mode_1": {
                "source_rva": "0x101cd0d",
                "predicate_call": "0x101cd27 -> 0x140b58c70",
                "true": "returns without the ALREADY_TRANSFERRING label",
                "false": "formats TRADE_MERCHANT_ALREADY_TRANSFERRING at 0x101cd4b",
            },
            "mode_0": {
                "source_rva": "0x101cd0d",
                "predicate_call": "0x101cd7a -> 0x140b58c70",
                "false": "returns without the ALREADY_COLLECTING label",
                "true": "formats TRADE_MERCHANT_ALREADY_COLLECTING at 0x101cd9e",
            },
            "fallback": {
                "label": "TRADE_MERCHANT_UNABLE",
                "rva": "0x101cc8e/0x101ce2c",
                "meaning": "context/runtime-node gates failed before the B58C70 status branch; this is the only explicit unable path in the window",
            },
            "merchant_present_precondition": {
                "status": "no_independent_explicit_check_proven",
                "reason": "The window checks trade-node/context pointers and runtime identity, but does not test a separate merchant-present field or entry pointer before calling B58C70.",
            },
        },
        "b58c70_aggregate_mapping": _b58c70_contract(prior),
        "findings": {
            "collection": {
                "status": "closed_for_aggregate_eligibility_only",
                "public_mapping": "B58C70 may be exposed as a native aggregate collection/entry eligibility gate when the context gates above pass; keep the basis explicitly aggregate_eligibility and do not call it a merchant_task enum.",
                "why": "The same predicate is consumed by the existing income/steering gate and directly controls the mode-0 ALREADY_COLLECTING branch.",
                "boundary": "A raw false is not a distinct none/no-merchant value; it is defined only for a valid entry pointer and reflects flag combinations that fail the aggregate formula. A null/invalid entry is outside the leaf contract, not a proven false result.",
            },
            "merchant_task": {
                "status": "unknown",
                "reason": "The UI has mode-specific collecting/transferring labels, but the predicate is aggregate and the direct setter callers do not supply a named command/key. AC/AE decomposition remains unresolved.",
            },
            "merchant_present": {
                "status": "not_independently_proven",
                "reason": "Null context/runtime pointers route to TRADE_MERCHANT_UNABLE, while the B58C70 leaf requires a valid computed entry pointer and has no separate presence bit. No distinct none/no-merchant result was established.",
            },
            "predicate_false": {
                "status": "ambiguous_by_contract",
                "includes": [
                    "non-special AE=0 and AD=0",
                    "non-special AE!=0 and AC!=0",
                    "UI context gate failure is handled separately by TRADE_MERCHANT_UNABLE before the B58C70 branch",
                    "null/invalid computed entry is outside the leaf contract and must not be converted into a false/none value",
                ],
            },
        },
        "unresolved_conditions": [
            "AC and AE producer state bytes still have no proven domain names; direct callers do not close collect/transfer semantics.",
            "Indirect calls or callers outside the four direct E8 sites were not claimed closed.",
            "The [R11+0x10] pointer and B58C70 computed entry are not independently named as merchant-presence fields.",
            "A production collection reader should expose aggregate eligibility with provenance/context status, not reinterpret false as none or as a three-valued merchant_task.",
        ],
    }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT
        / "work/runtime/information-trade-merchant-state-20261027-001/merchant-state-source-002.json",
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
