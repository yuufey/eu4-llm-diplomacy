"""Bounded static evidence for the remaining trade source/multiplier rows.

This Batch-46 report is ordinary, bounded PE analysis only.  It does not attach
to the game, execute a native function, use RPM/REA, or change production code.
The report deliberately keeps the multiplier tail separate from the already
closed trade-power rows: the code path is a display/source path, not proof that
the value is a trade-power point or a sum of the three source rows.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work" / "runtime" / "information-trade-source-details-20261027-001"
OUTPUT = STAGE / "source-modifiers-001.json"
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE, make_disassembler  # noqa: E402
from work.local_config import game_exe  # noqa: E402
from work.research_information_branch_inputs import _decode_range  # noqa: E402


EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
IMAGE_BASE = 0x140000000
MAX_SINGLE_DECODE = 8 * 1024
MAX_TOTAL_DECODE = 24 * 1024

FUNCTIONS = {
    "b57700_source_builder": (0xB57700, 0xB58354),
    "382e70_native_source_accumulator": (0x382E70, 0x38388D),
    "b5def0_detail_string_builder": (0xB5DEF0, 0xB5E0FB),
}

SELECTED_RVAS = {
    "b57700_source_builder": (
        0xB57749, 0xB5774D, 0xB57750, 0xB57754, 0xB57758, 0xB5775C,
        0xB57760, 0xB57763, 0xB57F55, 0xB57F5C, 0xB57F63, 0xB57F66,
        0xB57F69, 0xB57F70, 0xB57F74, 0xB57F79, 0xB57F7B, 0xB57F81,
        0xB57F86, 0xB57F88, 0xB57F8B, 0xB57F92, 0xB57F99, 0xB57F9C,
        0xB57F9F, 0xB57FA6, 0xB57FAA, 0xB57FAF, 0xB57FB7, 0xB57FBA,
        0xB57FC0, 0xB57FC4, 0xB5808E, 0xB58099, 0xB580A0, 0xB580A4,
        0xB5819D, 0xB581A3, 0xB581B4, 0xB581B8, 0xB581BB, 0xB581C1,
    ),
    "382e70_native_source_accumulator": (
        0x382E9E, 0x382EA1, 0x382EA4, 0x382EA7, 0x382EBA, 0x382EC1,
        0x382EC5, 0x382ED5, 0x382EDC, 0x382EE6, 0x382EF6, 0x382F0C,
        0x382F10, 0x382F14, 0x382F17, 0x382F25, 0x382F2D, 0x383677,
        0x38367E, 0x38368B, 0x38369F, 0x3836A5, 0x3836AC, 0x3836B2,
        0x3836C0, 0x3836C7, 0x3836CD, 0x3836D0, 0x3836D3, 0x3836D6,
        0x3836DD, 0x3836E0, 0x3836E7, 0x3836EB, 0x3836EE, 0x3836F6,
        0x383703, 0x38383D, 0x383842, 0x383844, 0x383848, 0x38384C,
        0x38385D, 0x38387A,
    ),
    "b5def0_detail_string_builder": (
        0xB5DF0C, 0xB5DF0F, 0xB5DF1E, 0xB5DF23, 0xB5DF30, 0xB5DF3A,
        0xB5DF60, 0xB5DF64, 0xB5DF68, 0xB5DF6C, 0xB5DFED, 0xB5DFF1,
        0xB5DFF5, 0xB5DFF9, 0xB5E03A, 0xB5E041, 0xB5E047, 0xB5E052,
        0xB5E058, 0xB5E066, 0xB5E09D, 0xB5E0D7, 0xB5E0EA, 0xB5E0EE,
    ),
}


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _relative(path: Path) -> str:
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def _range_record(pe: PE, rows: list[dict], begin: int, end: int, name: str) -> dict:
    raw = pe.bytes_at(begin, end - begin)
    pdata = pe.function(begin)
    if pdata is None or pdata[0] != begin or pdata[1] != end:
        raise AssertionError(f"{name} is not an exact pdata function: {pdata}")
    return {
        "name": name,
        "rva_exclusive": [hex(begin), hex(end)],
        "va_exclusive": [hex(IMAGE_BASE + begin), hex(IMAGE_BASE + end)],
        "byte_length": len(raw),
        "raw_range_sha256": _sha256_bytes(raw),
        "pdata_unwind_rva": hex(pdata[2]),
        "decoded_instruction_count": len(rows),
        "address_semantics": "RVA; VA=image_base_va+RVA; end is exclusive",
    }


def _selected(rows: list[dict], addresses: tuple[int, ...]) -> list[dict]:
    by_rva = {int(row["rva"], 16): row for row in rows}
    missing = [hex(address) for address in addresses if address not in by_rva]
    if missing:
        raise AssertionError(f"decoder did not return selected instructions: {missing}")
    result = []
    for address in addresses:
        row = dict(by_rva[address])
        row["va"] = hex(IMAGE_BASE + address)
        result.append(row)
    return result


def _literal(pe: PE, rva: int, size: int, *, text: str | None = None) -> dict:
    raw = pe.bytes_at(rva, size)
    record = {
        "rva": hex(rva),
        "va": hex(IMAGE_BASE + rva),
        "byte_length": len(raw),
        "bytes_hex": raw.hex(),
        "sha256": _sha256_bytes(raw),
    }
    if text is not None:
        record["text"] = text
    return record


def _prior(path: Path, role: str) -> dict:
    if not path.exists():
        return {"path": _relative(path), "role": role, "missing": True}
    return {
        "path": _relative(path),
        "sha256": _sha256_path(path),
        "role": role,
        "evidence_kind": "prior_ordinary_static_report",
    }


def build_report() -> dict:
    exe = Path(game_exe())
    pe = PE(exe)
    exe_sha = _sha256_bytes(pe.data)
    if exe_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"unsupported game binary SHA-256: {exe_sha}")
    if pe.base != IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.base:#x}")

    md, capstone = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    decoded: dict[str, list[dict]] = {}
    ranges = []
    total = 0
    for name, (begin, end) in FUNCTIONS.items():
        if end <= begin or end - begin > MAX_SINGLE_DECODE:
            raise AssertionError(f"single decode limit failure: {name}")
        if not pe.executable(begin) or not pe.executable(end - 1):
            raise AssertionError(f"non-executable range: {name}")
        total += end - begin
        if total > MAX_TOTAL_DECODE:
            raise AssertionError(f"total decode limit failure: {total}")
        rows = _decode_range(pe, md, begin, end)
        decoded[name] = rows
        ranges.append(_range_record(pe, rows, begin, end, name))

    selected = {
        name: _selected(rows, SELECTED_RVAS[name])
        for name, rows in decoded.items()
    }

    prior_share = ROOT / "work/runtime/information-trade-share-20261027-001/share-source-001.json"
    prior_formatter = ROOT / "work/runtime/information-trade-share-20261027-001/power-sources-source-002.json"
    prior_formatter_old = ROOT / "work/runtime/information-trade-share-20261027-001/power-sources-source-001.json"

    report = {
        "schema": "information.trade_source_modifiers_static.v1",
        "report_id": "information-trade-source-modifiers-001",
        "batch": 46,
        "stage": "information-trade-source-details-20261027-001",
        "generated_on": "2026-10-27",
        "status": "partial_static_multiplier_tail_and_detail_string",
        "scope": {
            "topic_id": "T04",
            "fields": ["sources", "TRADE_MULTI_EXPLA", "native_tail"],
            "object": "trade_node",
            "question": "Close the bounded native inputs and display/detail path for the remaining trade multiplier source; do not conflate it with trade-power points or a source-row sum.",
            "mode": "ordinary bounded PE only, with prior Batch-45 reports reused as static evidence",
            "no_game": True,
            "no_runtime_access": True,
            "no_rpm": True,
            "no_rea": True,
            "no_production_changes": True,
            "single_decode_limit_bytes": MAX_SINGLE_DECODE,
            "total_decode_limit_bytes": MAX_TOTAL_DECODE,
        },
        "target": {
            "game_version": "1.37.4",
            "exe_path": str(exe),
            "exe_sha256": exe_sha,
            "image_base_va": hex(IMAGE_BASE),
            "address_rule": "RVA and VA are separate; VA=image_base_va+RVA; ranges are half-open",
        },
        "input_evidence": [
            _prior(prior_share, "Batch-45 B57700 source-builder and entry-layout evidence"),
            _prior(prior_formatter, "Batch-45 signed fixedpoint formatter evidence"),
            _prior(prior_formatter_old, "Batch-45 source-001 retained source-row/multiplier context"),
        ],
        "decoded_code_ranges": ranges,
        "decoder": {
            "name": "capstone " + capstone.__version__ if capstone is not None else "bounded objdump -d -w -Mintel",
            "decoded_bytes": total,
            "decoded_instruction_count": sum(len(rows) for rows in decoded.values()),
            "selected_instruction_groups": list(FUNCTIONS),
        },
        "selected_instructions": selected,
        "literal_evidence": {
            "TRADE_MULTI_EXPLA": _literal(
                pe, 0x1CE8B70, len(b"TRADE_MULTI_EXPLA\0"), text="TRADE_MULTI_EXPLA"
            ),
            "TRANSFER_TRADE_POWER_TO": _literal(
                pe, 0x1CE8E30, len(b"TRANSFER_TRADE_POWER_TO\0"), text="TRANSFER_TRADE_POWER_TO"
            ),
            "TRANSFER_TRADE_POWER_FROM": _literal(
                pe, 0x1CE8E48, len(b"TRANSFER_TRADE_POWER_FROM\0"), text="TRANSFER_TRADE_POWER_FROM"
            ),
            "generic_short_format_key_context": _literal(
                pe, 0x1C3299C, 0x20, text="\\n\\0\\0\\0_short\\0... (binary literal context)"
            ),
        },
        "multiplier_contract": {
            "source_row_guard": {
                "entry_offset": "0x28",
                "condition": "signed_i32([selected_entry+0x28]) != 0",
                "evidence": "B57700 RVA 0xb57763 loads DWORD [r13+0x28], followed by the nonzero branch in the same pdata function",
                "meaning": "eligibility/display guard only; it does not establish the value unit",
            },
            "entry_selection": {
                "selected_entry": "[object+0x18] + sign_extend_i16(high16(R8))*0xc0",
                "object_input": "B57700 preserves the initial RCX object, loads [object+0x18], and forms the selected entry in R13",
                "stride": 192,
                "rva": ["0xb57749", "0xb57754", "0xb57758", "0xb5775c", "0xb57760"],
                "va": ["0x140b57749", "0x140b57754", "0x140b57758", "0x140b5775c", "0x140b57760"],
            },
            "b57700_to_382e70_calls": [
                {
                    "call_rva": "0xb57f74",
                    "call_va": "0x140b57f74",
                    "rcx": "QWORD PTR [RSI + RAX], where RAX was loaded from [0x14233d8b0]+0x118",
                    "rdx": "&local DWORD [RBP+0xc0]",
                    "r8": "R12, the original node/container argument preserved by B57700",
                    "r9": 0,
                    "callee_rva": "0x382e70",
                    "callee_va": "0x140382e70",
                },
                {
                    "call_rva": "0xb57faa",
                    "call_va": "0x140b57faa",
                    "rcx": "QWORD PTR [RSI + RAX], same static selector expression",
                    "rdx": "&local DWORD [RBP+0xc0]",
                    "r8": "R12",
                    "r9": 0,
                    "callee_rva": "0x382e70",
                    "callee_va": "0x140382e70",
                },
            ],
            "b57700_postprocess": {
                "returned_pointer_read": "B57700 reads signed DWORD [RAX] after 382E70 returns its RDX output pointer",
                "formula": "signed_i32(raw + 1000), then lower clamp to 10 via CMOVL; no upper clamp is shown in this window",
                "rvas": ["0xb57f79", "0xb57f7b", "0xb57f81", "0xb57f86", "0xb57f88"],
                "display_call": {
                    "call_rva": "0xb57fc4",
                    "call_va": "0x1414bbd90",
                    "raw_pointer": "RDX=RAX from the second 382E70 call",
                    "r8d": 2,
                    "r9b": 1,
                    "scale_claim": "the fixed 1000 display scale is inherited from the preceding signed arithmetic/formatter context; this report does not call it trade_power",
                },
            },
        },
        "native_accumulator_382e70": {
            "pdata": {
                "rva_exclusive": ["0x382e70", "0x38388d"],
                "va_exclusive": ["0x140382e70", "0x14038388d"],
                "byte_length": 2589,
            },
            "abi": {
                "rcx": "input object/container saved as R14",
                "rdx": "output pointer saved as R13; return RAX is this same pointer",
                "r8": "node/container object saved as R15",
                "r9": "optional/context pointer saved as R12; B57700 passes zero",
            },
            "raw_inputs": [
                {
                    "expression": "QWORD PTR [RCX+0x20]",
                    "use": "packed high-half selector; high 16 bits are sign-extended before table indexing",
                    "rvas": ["0x382eba", "0x382ec1", "0x382ec5", "0x382ee6"],
                    "unknown": "the exact native fullref type/domain of RCX+0x20 is not proven by this static window",
                },
                {
                    "expression": "QWORD PTR [R8+0x18]",
                    "use": "selected entry table base; selector is expanded as slot*3*0x40 = slot*0xc0",
                    "rvas": ["0x382ef6"],
                },
                {
                    "expression": "QWORD PTR [R8+0x40] .. [R8+0x48]",
                    "use": "begin/end vector; count is (end-begin)/4 using a reciprocal multiply",
                    "rvas": ["0x382f0c", "0x382f10", "0x382f14", "0x382f17", "0x382f25"],
                    "element_stride": 4,
                    "unknown": "the vector's business identity and producer are outside this bounded function",
                },
            ],
            "output": {
                "expression": "signed_i32([RDX]) after the final accumulator writes [R13]=EAX",
                "rvas": ["0x383848", "0x38384c", "0x38385d", "0x38387a"],
                "raw_is_not": ["not proven trade_power points", "not proven a sum of TP_PROVINCE_POWER/TP_SHIP_POWER/MERCHANT_DOWNSTREAM_BONUS"],
            },
            "tail_path": {
                "predicate": "B58C70(R15, [entry+0x20]) must return true; selected entry [R15+0x18 + selector*0xc0 + 0xad] must be zero",
                "predicate_call_rva": "0x38367e",
                "ad_guard_rva": "0x3836a5",
                "factor_call": {
                    "call_rva": "0x3836c0",
                    "call_va": "0x1403836c0",
                    "callee_rva": "0x382dd0",
                    "rcx": "R14 (candidate native entry/object)",
                    "rdx": "&local [RBP+0xf0]",
                    "return_use": "signed_i32([RAX]) is multiplied into the q32 value",
                    "source_status": "unresolved; 382DD0 was not expanded under the bounded budget",
                },
                "arithmetic": {
                    "q32": "max(0, signed_i32([RSP+0x30] + 1000)); ADD operates in 32-bit Ebx and CMOVNS selects zero on a negative signed result",
                    "product": "signed_i64(q32) * signed_i32([RAX])",
                    "reciprocal_path": "one-operand IMUL with M=0x20c49ba5e353f7cf, SAR high product by 7, then add sign correction",
                    "scale_inference": "M is ceil(2^71/1000); the sequence is consistent with signed truncation by 1000, but the native field's unit/name remains unresolved",
                    "accumulate": "add resulting signed DWORD to [RSP+0x30] at RVA 0x3836f6",
                },
            },
            "alternate_entry_path": {
                "condition": "selected entry +0xad is nonzero",
                "call_rva": "0x38383d",
                "callee_rva": "0x2f2640",
                "use": "adds DWORD [RAX] to the accumulator",
                "source_status": "unresolved; this path is not identified as the same multiplier cache",
            },
            "unfollowed_callees": [
                "0x382dd0 (factor/cache output)",
                "0x2f2640 (alternate entry path)",
                "0xb58c70 (predicate; prior report proves eligibility only)",
            ],
        },
        "detail_string_b5def0": {
            "abi": {
                "rcx": "selected entry pointer (B57700 passes R13)",
                "rdx": "destination string object (B57700 passes &local [RBP+0x38])",
                "return": "RAX=destination string object",
                "callsite": {
                    "rva": "0xb581bb",
                    "va": "0x140b581bb",
                    "direct_caller": "B57700 only in the bounded .text call scan",
                },
            },
            "entry_inputs": [
                {
                    "offset": "0x60",
                    "argument": "R8=&[entry+0x60]",
                    "helper_call_rva": "0xb5df6c",
                    "helper_callee_rva": "0xb5dcd0",
                },
                {
                    "offset": "0x78",
                    "argument": "R8=&[entry+0x78]",
                    "helper_call_rva": "0xb5dff9",
                    "helper_callee_rva": "0xb5dcd0",
                },
            ],
            "temporary_labels": {
                "to": {
                    "rva": "0x1ce8e30",
                    "va": "0x141ce8e30",
                    "text": "TRANSFER_TRADE_POWER_TO",
                    "role": "literal copied into the first temporary object before B5DCD0; candidate label only",
                },
                "from": {
                    "rva": "0x1ce8e48",
                    "va": "0x141ce8e48",
                    "text": "TRANSFER_TRADE_POWER_FROM",
                    "role": "literal copied into the second temporary object before B5DCD0; candidate label only",
                },
            },
            "assembly": {
                "first_detail": "B5DCD0 writes a local string at [RBP-0x11] from entry+0x60 and the first temporary literal",
                "second_detail": "B5DCD0 writes a local string at [RBP+0xf] from entry+0x78 and the second temporary literal",
                "conditional": "if QWORD [RBP-0x1] is nonzero, B5DEF0 calls generic formatter 0x932f0 with rdata key at RVA 0x1c3299c (contains _short) on the first detail",
                "return_build": "destination is zero-initialized, first detail is appended, then second detail is formatted/appended; the exact helper-owned condition and text encoding remain unresolved",
            },
            "unit": {
                "status": "unknown",
                "reason": "B5DEF0 contains no numeric scale or currency/trade-power conversion; the _short formatter and TRANSFER_* literals do not prove the returned unit",
            },
            "unfollowed_callees": [
                "0xb5dcd0 (field/detail producer for +0x60 and +0x78)",
                "0x950b0/0x950b0 and 0x95110 (string allocation/append helpers)",
                "0x932f0 (generic formatting helper)",
            ],
        },
        "display_binding": {
            "label": "TRADE_MULTI_EXPLA",
            "label_rva": "0x1ce8b70",
            "label_va": "0x141ce8b70",
            "builder_call_rva": "0xb580a4",
            "builder_call_va": "0x140b580a4",
            "builder_callee_rva": "0x8edc0",
            "observed_arguments": {
                "rcx": "local display object [RBP+0x58]",
                "rdx": "&literal TRADE_MULTI_EXPLA",
                "r9": "&local value/string context [RBP-0x68]",
            },
            "meaning": "static UI label binding for the row; it does not turn the accumulator into trade_power or establish cache freshness",
        },
        "closed": [
            "B57700 selects a 0xc0 entry and gates this path on signed nonzero entry+0x28.",
            "B57700 calls 382E70 with an explicit output pointer and reads its signed DWORD result, then adds 1000 and lower-clamps to 10 before the display formatter.",
            "382E70's ABI, packed selector/table layout, 4-byte vector scan, AD guard, factor call, signed q32 arithmetic, reciprocal /1000-like tail, and final output write are statically bounded.",
            "B5DEF0 consumes selected-entry offsets +0x60 and +0x78 through B5DCD0 and returns a composed string; B57700 binds the display row to TRADE_MULTI_EXPLA.",
        ],
        "unknowns": [
            "The exact country-object/fullref domain represented by B57700's RSI+global+0x118 selector is not independently closed here; prior Batch-45 report is retained as corroboration.",
            "382DD0's returned factor/cache and 2F2640's alternate value source are not decoded; no native field name or producer is claimed.",
            "B5DCD0's conditions, localization substitution, raw numeric fields, and unit are not closed; TRANSFER_* strings are candidate labels only.",
            "Runtime freshness, cache update timing, GUI/runtime pointer identity, and current values are not observed by this static report.",
            "The multiplier accumulator is not a proof of trade_power points and must not be added to the three already closed source rows.",
        ],
        "future_runtime_offsets": {
            "purpose": "If a later bounded reader is authorized, these are the exact unresolved reads; this report performs none of them.",
            "selected_entry": [
                {"offset": "0x28", "role": "B57700 nonzero display guard"},
                {"offset": "0x60", "role": "first B5DCD0 detail input"},
                {"offset": "0x78", "role": "second B5DCD0 detail input"},
                {"offset": "0xad", "role": "382E70 tail/alternate-path guard in the selected table entry"},
            ],
            "native_object": [
                {"offset": "0x20", "role": "packed selector consumed by 382E70"},
                {"offset": "0x18", "role": "selected-entry table base"},
                {"offset": "0x40", "role": "vector begin used by 382E70"},
                {"offset": "0x48", "role": "vector end used by 382E70"},
            ],
            "unresolved_factor": {
                "callee_rva": "0x382dd0",
                "output": "DWORD [returned_pointer]",
                "note": "The returned pointer and field meaning require a separately bounded reader/analysis; do not substitute a trade-power field or a sum."
            },
            "detail_helper": {
                "callee_rva": "0xb5dcd0",
                "input_entry_offsets": ["0x60", "0x78"],
                "output": "temporary strings passed into B5DEF0's destination builder",
                "condition_and_unit": "unresolved until the helper's bounded contract is proven",
            },
        },
        "verification": {
            "script": _relative(Path(__file__)),
            "all_shell_work_completed": True,
            "game_access": False,
            "native_function_execution": False,
            "rpm_used": False,
            "rea_access": False,
            "production_written": False,
            "resource_limits": {
                "single_function_bytes": {name: end - begin for name, (begin, end) in FUNCTIONS.items()},
                "total_decode_bytes": total,
                "single_decode_limit_bytes": MAX_SINGLE_DECODE,
                "total_decode_limit_bytes": MAX_TOTAL_DECODE,
                "process_memory_limit": "bounded ordinary Python; no whole-file disassembly",
            },
        },
    }
    return report


def main() -> int:
    report = build_report()
    STAGE.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": _relative(OUTPUT),
        "sha256": _sha256_path(OUTPUT),
        "decoded_bytes": report["decoder"]["decoded_bytes"],
        "decoded_instruction_count": report["decoder"]["decoded_instruction_count"],
        "output_bytes": OUTPUT.stat().st_size,
        "decoder": report["decoder"]["name"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
