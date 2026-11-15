"""Bounded ordinary-static study of trade merchant state and entry flags.

This stage follows the existing +0xAC/+0xAD/+0xAE getter/predicate paths into
native UI labels and bounded writers.  It is deliberately PE-only: it does not
open the game, call RPM/REA, or change production code.  The older merchant
task report is reused as evidence for the B58C40/B58C70 leaf contract; the
windows below are the only new instruction bytes decoded by this script.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
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
MAX_TOTAL_DECODE_BYTES = 32 * 1024

# New bounded windows.  The B5EAA0 function is 4248 bytes in pdata; its
# [B5EAA0,B5FAA0) window intentionally stops at the 4 KiB limit and is marked
# partial in the report.  It contains all flag-field dispatches used here.
CODE_RANGES = (
    (0x101CB60, 0x101D0B2, "merchant_task_ui"),
    (0x13CA870, 0x13CB45A, "transit_label_ui"),
    (0x13D8CC0, 0x13D9CC0, "mainport_collect_ui"),
    (0xB51370, 0xB51FC5, "ad_anchor_writer"),
    (0xB5E100, 0xB5E183, "ac_ae_setter"),
    (0xB5EAA0, 0xB5FAA0, "flag_field_parser_partial"),
    (0xB61610, 0xB617EA, "flag_copy"),
    (0x322A00, 0x322A62, "entry_constructor"),
)

STRING_LITERALS = {
    0x1D4FCD8: "TRADE_MERCHANT_UNABLE",
    0x1D4FC78: "TRADE_TRANSIT_NODE",
    0x1D4FD10: "TRADE_TRANSIT_NODE_CAPITAL",
    0x1D4FD48: "TRADE_MERCHANT_ALREADY_COLLECTING",
    0x1D4FD70: "TRADE_MERCHANT_ALREADY_TRANSFERRING",
    0x1D81568: "TRADEMAP_MAINPORT_TITLE",
    0x1D81580: "TRADEMAP_MAINPORT_DESC",
    0x1D81598: "TRADEMAP_WE_COLLECT",
    0x1D81688: "TRADEMAP_OUTGOING_EXP",
    0x1D816A0: "trade_mission_transit",
    0x1CE8E68: "SetTrader, %s, %d, %d",
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
        raise AssertionError(
            f"literal mismatch at {rva:#x}: {bytes(raw)!r} != {wanted!r}"
        )
    return {
        "rva": hex(rva),
        "va": _va(rva),
        "locale_key_or_debug_literal": expected,
        "bytes_hex": bytes(raw).hex(),
        "bytes_sha256": _sha_bytes(bytes(raw)),
        "evidence": "native PE literal; translation/display resolution is outside this static stage",
    }


def _range_record(pe: PE, rows, begin: int, end: int, label: str):
    raw = pe.bytes_at(begin, end - begin)
    function = pe.function(begin)
    pdata = [hex(function[0]), hex(function[1])] if function else None
    return {
        "label": label,
        "start_rva": hex(begin),
        "end_rva_exclusive": hex(end),
        "start_va": _va(begin),
        "end_va_exclusive": _va(end),
        "byte_length": len(raw),
        "bytes_sha256": _sha_bytes(raw),
        "pdata_function_boundary": pdata,
        "coverage": (
            "partial_pdata_function"
            if function and (begin > function[0] or end < function[1])
            else "complete_explicit_window"
        ),
        "decoded_instruction_count": len(rows),
    }


def _selected(decoded, label, addresses):
    mapping = _instruction_map(decoded[label])
    missing = [hex(address) for address in addresses if address not in mapping]
    if missing:
        raise AssertionError(f"decoder did not return {label} instructions: {missing}")
    return [mapping[address] for address in addresses]


def _prior_evidence():
    paths = {
        "prior_merchant_task_report": ROOT
        / "work/runtime/information-trade-state-20261027-001/merchant-task-source-001.json",
        "prior_trade_power_report": ROOT
        / "work/runtime/information-trade-state-20261027-001/trade-power-source-002.json",
        "archived_raw_flag_runtime": ROOT
        / "work/runtime/information-trade-merchant-state-20261027-001/native-flag-inputs-from-archived-raw-001.json",
        "dynamic_lookup_static_report": ROOT
        / "work/runtime/information-trade-merchant-state-20261027-001/dynamic-lookup-source-001.json",
    }
    return {
        key: {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": _sha_file(path),
            "used_as": (
                "reused static evidence; not decoded again"
                if key.endswith("report")
                else "separate corroboration/context; not used as static flag semantics"
            ),
        }
        for key, path in paths.items()
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

    selected_instructions = {
        "merchant_task_ui": _selected(
            decoded,
            "merchant_task_ui",
            (
                0x101CD0D,
                0x101CD21,
                0x101CD27,
                0x101CD2C,
                0x101CD2E,
                0x101CD44,
                0x101CD4B,
                0x101CD56,
                0x101CD74,
                0x101CD7A,
                0x101CD7F,
                0x101CD81,
                0x101CD97,
                0x101CD9E,
                0x101CDA9,
            ),
        ),
        "transit_label_ui": _selected(
            decoded,
            "transit_label_ui",
            (0x13CADA1, 0x13CADB0, 0x13CADD1, 0x13CADBC),
        ),
        "mainport_collect_ui": _selected(
            decoded,
            "mainport_collect_ui",
            (
                0x13D9A32,
                0x13D9A39,
                0x13D9AB9,
                0x13D9AC4,
                0x13D9BC5,
                0x13D9C23,
                0x13D9C2E,
            ),
        ),
        "ad_anchor_writer": _selected(
            decoded,
            "ad_anchor_writer",
            (
                0xB51720,
                0xB517D0,
                0xB517E0,
                0xB517EF,
                0xB517F7,
                0xB51D46,
                0xB51E57,
                0xB51E5E,
                0xB51E67,
                0xB51E7D,
                0xB51E87,
                0xB51EA8,
            ),
        ),
        "ac_ae_setter": _selected(
            decoded,
            "ac_ae_setter",
            (0xB5E10C, 0xB5E110, 0xB5E11B, 0xB5E15C, 0xB5E168, 0xB5E16F),
        ),
        "flag_field_parser_partial": _selected(
            decoded,
            "flag_field_parser_partial",
            (
                0xB5EAC2,
                0xB5EC1D,
                0xB5EC2E,
                0xB5EC35,
                0xB5EC51,
                0xB5EC62,
                0xB5EC6D,
                0xB5EC81,
                0xB5EC88,
                0xB5EC92,
                0xB5EC99,
                0xB5ECA0,
                0xB5ED74,
                0xB5ED7B,
            ),
        ),
        "flag_copy": _selected(
            decoded,
            "flag_copy",
            (
                0xB61788,
                0xB6178F,
                0xB61795,
                0xB6179C,
                0xB617A2,
                0xB617A9,
                0xB617AF,
                0xB617B6,
            ),
        ),
        "entry_constructor": _selected(
            decoded,
            "entry_constructor",
            (0x322A29, 0x322A2F, 0x322A36),
        ),
    }

    literals = [_cstring(pe, rva, value) for rva, value in STRING_LITERALS.items()]

    report = {
        "schema": "information.trade_state.merchant_task_source.v2",
        "stage": "information-trade-merchant-state-20261027-001",
        "evidence_kind": "ordinary_static_file_analysis_not_REA_evidence",
        "target": {
            "game_version": "1.37.4",
            "exe_sha256": binary_sha256,
            "image_base_va": hex(pe.base),
            "address_kind": "RVA; VA=image_base_va+RVA; all ranges are [begin,end)",
        },
        "scope": {
            "question": "T05 collection/merchant_task: follow +0xAC/+0xAD/+0xAE through native UI labels and bounded writers",
            "runtime_entry_layout_reused": "country/node +0x18 table; signed slot * 0xC0; entry flag bytes +0xAC/+0xAD/+0xAE",
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
            "new_decode_budget_statement": "Only the eight explicit windows in ranges are decoded in this stage; prior B58C40/B58C70 evidence is reused by hash.",
        },
        "prior_evidence": _prior_evidence(),
        "ranges": ranges,
        "selected_instructions": selected_instructions,
        "string_literals": literals,
        "writer_and_reader_trace": {
            "ac_ae_setter": {
                "status": "structurally_closed_business_semantics_open",
                "function_rva": "0xb5e100",
                "function_va": _va(0xB5E100),
                "pdata_boundary": ["0xb5e100", "0xb5e183"],
                "abi_dataflow": {
                    "rcx": "copied to RDI and used as the target object",
                    "r8b": "copied to ESI and written to target +0xAC",
                    "dl": "copied to EBP low byte and written to target +0xAE",
                },
                "guard_branch": "call 0x14014D4B80; continue only when BYTE PTR [RAX+0x38] & 1 is nonzero",
                "writes": [
                    {
                        "rva": "0xb5e168",
                        "va": _va(0xB5E168),
                        "bytes_hex": pe.bytes_at(0xB5E168, 7).hex(),
                        "instruction": "mov BYTE PTR [rdi+0xac],sil",
                    },
                    {
                        "rva": "0xb5e16f",
                        "va": _va(0xB5E16F),
                        "bytes_hex": pe.bytes_at(0xB5E16F, 7).hex(),
                        "instruction": "mov BYTE PTR [rdi+0xae],bpl",
                    },
                ],
                "nearby_literal": "SetTrader, %s, %d, %d is passed to a logger at 0x14014D4DB0; this is contextual debug evidence only, not a field-name proof.",
                "business_meaning": None,
                "next_narrow_entry": {
                    "rva": "0x14d4b80",
                    "reason": "resolve the +0x38 bit guard and the producer/call context before assigning a public merchant-task meaning",
                },
            },
            "flag_field_parser": {
                "status": "structurally_closed_business_semantics_open",
                "function_rva": "0xb5eaa0",
                "pdata_boundary": ["0xb5eaa0", "0xb5fb38"],
                "window": "[0xb5eaa0,0xb5faa0), partial because pdata function is 4248 bytes",
                "target_register": "R13=RCX at 0xb5eac2",
                "ac_path": {
                    "parser_call": "0x140125B340",
                    "assignment": "0xb5ec35 mov BYTE PTR [r13+0xac],al",
                    "input": "parsed byte from the scratch output at [RBP+0x3D0]; the key-name table is not decoded here",
                },
                "ad_ae_paths": [
                    {
                        "rva": "0xb5ec81",
                        "assignment_target": "R13+0xAD",
                        "helper": "0x140170F650",
                    },
                    {
                        "rva": "0xb5ec99",
                        "assignment_target": "R13+0xAE",
                        "helper": "0x140170F650",
                    },
                    {
                        "rva": "0xb5ed74",
                        "assignment_target": "R13+0xAF",
                        "helper": "0x140170F650",
                    },
                ],
                "branch_detail": "The dispatch subtracts 0x2AFC, then 0x0F/0xFE and compares 0x8B before the AD/AE helper branches; these raw token cases have no proven locale-name mapping in this stage.",
                "business_meaning": None,
                "next_narrow_entry": {
                    "rva": "0x14125b340",
                    "reason": "identify the AC parser's source/value contract and recover field-key names without treating numeric cases as names",
                },
            },
            "ad_anchor_writer": {
                "status": "partial_home_discriminator",
                "function_rva": "0xb51370",
                "pdata_boundary": ["0xb51370", "0xb51fc5"],
                "entry_selection": "After R13 is the trade-node object, the loop loads a country-like vector element at [R12], reads its fullref at +0x20, sign-extends the high 16-bit slot, and computes R13=[R15+0x18]+slot*0xC0 (0xb517d0..0xb517f7).",
                "producer": {
                    "condition_true": "[([RBP-0x1]+0x14C8)+0xE8] == R15",
                    "true_write": "entry +0xAD = 1 at 0xb51e67",
                    "false_write": "if prior entry +0xAD != 0, entry +0xAD = 0 at 0xb51e87",
                    "raw_write_bytes": {
                        "0xb51e67": pe.bytes_at(0xB51E67, 8).hex(),
                        "0xb51e87": pe.bytes_at(0xB51E87, 8).hex(),
                    },
                },
                "relation_to_existing_capital_source": "The +0x14C8 -> +0xE8 identity chain matches the independently bounded capital/home source shape; this closes AD as a native home/capital-style transit discriminator at partial static confidence, not as collect/transfer.",
                "unclosed": "The exact caller-level types for [RBP-0x1] and R15 are not fully named by this window; the next narrow entries are 0x140B53920/0x140B54070 if stronger object typing is required.",
            },
            "flag_copy": {
                "status": "closed_as_raw_propagation_only",
                "function_rva": "0xb61610",
                "copies": "The sequence at 0xb61788..0xb617b6 copies AC, AD, AE, and AF byte-for-byte from [RDI+offset] to [RBX+offset]; it creates no semantic mapping.",
            },
            "entry_constructor": {
                "status": "closed_as_initialization_only",
                "function_rva": "0x322a00",
                "writes": "0x322a2f clears the AC word and 0x322a36 clears AE; this is object construction, not a task producer.",
            },
        },
        "ui_trace": {
            "merchant_task_status_messages": {
                "function_rva": "0x101cb60",
                "mode_source": "BYTE PTR [RDI+0x229]",
                "mode_1_transfer_message": {
                    "predicate_call": "0x101cd27 -> 0x140b58c70",
                    "branch": "if B58C70 returns false, format TRADE_MERCHANT_ALREADY_TRANSFERRING at 0x101cd4b",
                    "locale_key_rva": "0x1d4fd70",
                },
                "mode_0_collect_message": {
                    "predicate_call": "0x101cd7a -> 0x140b58c70",
                    "branch": "if B58C70 returns true, format TRADE_MERCHANT_ALREADY_COLLECTING at 0x101cd9e",
                    "locale_key_rva": "0x1d4fd48",
                },
                "interpretation": "This proves a native UI action/status path for collecting versus transferring, but B58C70 is an aggregate eligibility predicate over entry fields and surrounding guards. The branch does not prove that AC or AE alone denotes either action.",
            },
            "ad_transit_messages": {
                "function_rva": "0x13ca870",
                "predicate": "BYTE PTR [RDX+0xAD] at 0x13cada1",
                "labels": [
                    {"rva": "0x1d4fd10", "key": "TRADE_TRANSIT_NODE_CAPITAL", "use_rva": "0x13cadb0"},
                    {"rva": "0x1d4fc78", "key": "TRADE_TRANSIT_NODE", "use_rva": "0x13cadd1"},
                ],
                "interpretation": "AD directly selects the capital/transit label in this bounded UI path; the writer above supplies a matching country-anchor identity condition.",
            },
            "collect_mainport_labels": {
                "function_rva": "0x13d8cc0",
                "labels": [
                    {"rva": "0x1d81568", "key": "TRADEMAP_MAINPORT_TITLE", "use_rva": "0x13d9a32"},
                    {"rva": "0x1d81580", "key": "TRADEMAP_MAINPORT_DESC", "use_rva": "0x13d9ab9"},
                    {"rva": "0x1d81598", "key": "TRADEMAP_WE_COLLECT", "use_rva": "0x13d9c2e"},
                ],
                "nearby_trade_power_call": "0x13d9bc5/0x13d9c23 call 0x140b58d00",
                "interpretation": "The bounded slice emits main-port and WE_COLLECT keys, but contains no AC/AE read feeding those labels. Keep this as an unlinked label path, not a flag mapping.",
            },
        },
        "runtime_corroboration": {
            "evidence_kind": "separate archived raw observation, not static evidence",
            "path": "work/runtime/information-trade-merchant-state-20261027-001/native-flag-inputs-from-archived-raw-001.json",
            "sha256": _sha_file(
                ROOT
                / "work/runtime/information-trade-merchant-state-20261027-001/native-flag-inputs-from-archived-raw-001.json"
            ),
            "used_by_this_script": False,
            "limitation": "Raw AC/AD/AE combinations and repeated snapshots do not label AC/AE or authorize a collect/transfer/none mapping.",
        },
        "findings": {
            "AC": {
                "status": "not_closed_business_semantics",
                "writer": "B5E100 writes caller-supplied R8B to entry+0xAC under a +0x38 bit guard; B5EAA0 also parses a boolean into +0xAC; B61610 copies it raw.",
                "ui_relation": "B58C70 consumes AC only inside an aggregate predicate that drives the collecting/transferring status messages; no direct AC-only label or getter was closed.",
                "public_mapping": None,
            },
            "AD": {
                "status": "partial_home_or_capital_discriminator",
                "writer": "B51370 sets entry+0xAD from equality between a country-like +0x14C8/+0xE8 anchor and the current node identity, then clears it on mismatch.",
                "ui_relation": "B58C40 and the direct UI path select TRADE_TRANSIT_NODE_CAPITAL versus TRADE_TRANSIT_NODE.",
                "public_mapping": "home/capital-style transit discriminator only; do not expose as collect/transfer",
            },
            "AE": {
                "status": "not_closed_business_semantics",
                "writer": "B5E100 writes caller-supplied DL to entry+0xAE under a +0x38 bit guard; B5EAA0 parses a boolean into +0xAE; B61610 copies it raw.",
                "ui_relation": "AE participates in B58C70/entry gates, but no direct AE-only native label or producer meaning was closed.",
                "public_mapping": None,
            },
            "merchant_task": {
                "status": "partial_ui_status_only",
                "labels": [
                    "TRADE_MERCHANT_ALREADY_COLLECTING",
                    "TRADE_MERCHANT_ALREADY_TRANSFERRING",
                ],
                "predicate": "B58C70 aggregate bool with action mode at widget +0x229",
                "reason": "The native UI distinguishes collecting and transferring messages, but the bounded evidence does not decompose that bool into AC/AE or prove a three-valued collect/transfer/none field.",
                "public_mapping": None,
            },
            "collection": {
                "status": "not_proven",
                "reason": "TRADEMAP_WE_COLLECT is an unlinked main-port label in the bounded UI slice; it is not evidence that AC or AE is a collection flag.",
            },
            "transfer": {
                "status": "not_proven",
                "reason": "The already-transferring message is selected by UI action mode plus the B58C70 aggregate result; no direct transfer relation/value getter was closed.",
            },
        },
        "unresolved_conditions": [
            "AC and AE producer arguments/key IDs are structurally visible but their native domain names remain unresolved.",
            "B58C70 combines AC/AD/AE with other entry fields; it cannot be reused as a per-flag merchant_task enum.",
            "The B5E100 +0x38 guard and callers are unresolved; inspect 0x14014D4B80 and its narrow call/reference context before assigning task semantics.",
            "The B5EAA0 parser's numeric dispatch keys have no proven locale-name mapping; do not infer names from 0x2B0B/0x2C09/0x2C94.",
            "Runtime raw snapshots corroborate storage only and do not turn the partial static trace into observed UI semantics.",
        ],
    }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT
        / "work/runtime/information-trade-merchant-state-20261027-001/merchant-state-source-001.json",
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
    print(
        json.dumps(
            {
                "output": output.relative_to(ROOT).as_posix(),
                "sha256": _sha_file(output),
                "bytes": output.stat().st_size,
                "decoded_bytes": report["analysis"]["decoded_bytes"],
                "range_count": len(report["ranges"]),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
