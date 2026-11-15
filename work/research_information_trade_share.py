"""Produce the bounded Batch 45 static contract for T04 trade shares.

This is an ordinary, bounded PE read.  It deliberately does not open the game,
use RPM/REA, or turn the static result into a runtime observation.  The only
new artifact written by this script is ``share-source-001.json`` in the Batch
45 stage directory.
"""
from __future__ import annotations

import hashlib
import json
import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE, check_memory_budget, make_disassembler
from work.local_config import game_exe
from work.research_information_branch_inputs import _decode_range


EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
IMAGE_BASE = 0x140000000
MAIN_RANGE = (0xB58D00, 0xB5921E)
UI_RANGES = (
    (0x101DAC6, 0x101DAF5, "ui_share_callsite_101dae4"),
    (0x101E894, 0x101E8B1, "ui_share_callsite_101e8ac"),
)
MAX_SINGLE_BYTES = 8 * 1024
MAX_TOTAL_BYTES = 16 * 1024
STAGE = ROOT / "work/runtime/information-trade-share-20261027-001"
OUTPUT = STAGE / "share-source-001.json"
OUTPUT_002 = STAGE / "share-source-002.json"
OLD_STAGE = ROOT / "work/runtime/information-trade-state-20261027-001"


def _hex(value: int) -> str:
    return hex(value)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _i32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _trunc0(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        raise ValueError("denominator must be positive")
    magnitude = abs(numerator) // denominator
    return -magnitude if numerator < 0 else magnitude


def _range_record(pe: PE, md, begin: int, end: int, label: str):
    if end - begin > MAX_SINGLE_BYTES:
        raise AssertionError("single bounded range exceeds 8 KiB")
    if not pe.executable(begin) or not pe.executable(end - 1):
        raise AssertionError(f"range is not executable: {begin:#x}:{end:#x}")
    raw = pe.bytes_at(begin, end - begin)
    if len(raw) != end - begin:
        raise AssertionError("bounded range is not fully file-backed")
    instructions = _decode_range(pe, md, begin, end)
    function = pe.function(begin)
    record = {
        "label": label,
        "rva_start": _hex(begin),
        "rva_end_exclusive": _hex(end),
        "va_start": _hex(pe.base + begin),
        "va_end_exclusive": _hex(pe.base + end),
        "byte_length": len(raw),
        "raw_hex": raw.hex(),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "decoded_instruction_count": len(instructions),
        "instructions": instructions,
    }
    if function:
        record["containing_pdata_function"] = {
            "rva_start": _hex(function[0]),
            "rva_end_exclusive": _hex(function[1]),
            "va_start": _hex(pe.base + function[0]),
            "va_end_exclusive": _hex(pe.base + function[1]),
            "pdata_unwind_rva": _hex(function[2]) if len(function) > 2 else None,
        }
    return record


def _row(rows, rva: int):
    for row in rows:
        if int(row["rva"], 16) == rva:
            return row
    raise AssertionError(f"decoder did not return instruction at {rva:#x}")


def _assert_bytes(pe: PE, expected: dict[int, str]):
    for rva, wanted in expected.items():
        actual = pe.bytes_at(rva, len(wanted) // 2).hex()
        if actual != wanted:
            raise AssertionError(
                f"unexpected bytes at RVA {rva:#x}: {actual} != {wanted}"
            )


def _direct_call_targets(instructions):
    targets = {}
    for row in instructions:
        if row["mnemonic"] != "call":
            continue
        operand = row["operands"].strip()
        if not operand.lower().startswith("0x"):
            continue
        try:
            va = int(operand, 16)
        except ValueError:
            continue
        if va < IMAGE_BASE:
            continue
        target_rva = va - IMAGE_BASE
        targets.setdefault(target_rva, []).append(int(row["rva"], 16))
    return targets


def _prior_report_pin(path: Path):
    report = json.loads(path.read_text(encoding="utf-8"))
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": _file_sha256(path),
        "report_id": report.get("report_id"),
        "evidence_kind": "prior_ordinary_bounded_static_report",
    }


def build_report():
    check_memory_budget()
    pe = PE(game_exe())
    exe_sha = hashlib.sha256(pe.data).hexdigest()
    if exe_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"unsupported game binary SHA-256: {exe_sha}")
    if pe.base != IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.base:#x}")

    main_boundary = pe.function(MAIN_RANGE[0])
    if not main_boundary or main_boundary[:2] != MAIN_RANGE:
        raise AssertionError(f"B58D00 pdata boundary changed: {main_boundary!r}")

    md, _ = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    main = _range_record(pe, md, *MAIN_RANGE, "trade_share_scalar_function")
    ui_ranges = [
        _range_record(pe, md, begin, end, label)
        for begin, end, label in UI_RANGES
    ]
    total_decoded_bytes = main["byte_length"] + sum(
        record["byte_length"] for record in ui_ranges
    )
    if total_decoded_bytes > MAX_TOTAL_BYTES:
        raise AssertionError("total bounded decode exceeds 16 KiB")

    rows = main["instructions"]
    _assert_bytes(
        pe,
        {
            0xB58D26: "498bd8",
            0xB58D2C: "4c8be9",
            0xB58D32: "49c1ef20",
            0xB58D36: "4d0fbfc7",
            0xB58D50: "48634e2c",
            0xB58D54: "496385b0000000",
            0xB58D5B: "480fafc8",
            0xB58D6F: "49c1fe07",
            0xB58D7D: "4584c9",
            0xB58D94: "4a8b3cc0",
            0xB58DB7: "8b4d6f",
            0xB58DC7: "480fbfc0",
            0xB58DDD: "3b15d54a7e01",
            0xB58DF5: "4863d1",
            0xB591DC: "45893424",
            0xB591E8: "498bc4",
        },
    )

    # These exact rows are the semantic anchors.  Keeping the complete bounded
    # instruction windows above makes branch direction and operand width
    # independently reviewable without reading an unbounded disassembly.
    expected_rows = {
        0xB58D50: "movsxd",
        0xB58D54: "movsxd",
        0xB58D5B: "imul",
        0xB58D6F: "sar",
        0xB58D76: "shr",
        0xB58D7A: "add",
        0xB58D7D: "test",
        0xB58D80: "je",
        0xB58DB7: "mov",
        0xB58DBA: "add",
        0xB58DF5: "movsxd",
        0xB58DF8: "movsxd",
        0xB58DFB: "imul",
        0xB591DC: "mov",
        0xB591E8: "mov",
    }
    for rva, mnemonic in expected_rows.items():
        if _row(rows, rva)["mnemonic"] != mnemonic:
            raise AssertionError(f"unexpected mnemonic at {rva:#x}")

    ui_first = ui_ranges[0]["instructions"]
    ui_second = ui_ranges[1]["instructions"]
    for rowset, rva in ((ui_first, 0x101DAE4), (ui_second, 0x101E8AC)):
        row = _row(rowset, rva)
        if row["mnemonic"] != "call" or "0x140b58d00" not in row["operands"].lower():
            raise AssertionError(f"share callsite drift at {rva:#x}: {row}")
    _assert_bytes(
        pe,
        {
            0x101DAD4: "4c89742420",
            0x101DAD9: "41b101",
            0x101DADC: "488d5567",
            0x101DAE0: "488b4f60",
            0x101DAE4: "e817b2b3ff",
            0x101DAE9: "488bd0",
            0x101DAF0: "e87bf6ffff",
            0x101E898: "4d8b4020",
            0x101E89C: "4c897c2420",
            0x101E8A1: "41b101",
            0x101E8A4: "488d5577",
            0x101E8A8: "488b4f60",
            0x101E8AC: "e84fa4b3ff",
        },
    )

    calls = _direct_call_targets(rows)
    scalar_callees = {
        0x093D5C0: {
            "va": _hex(IMAGE_BASE + 0x093D5C0),
            "call_sites_rva": [_hex(rva) for rva in calls.get(0x093D5C0, [])],
            "role": "R9 factor path: obtains an object/value used at [returned+0x8]; ABI/semantic type unresolved",
            "scalar_path": True,
        },
        0x03330A0: {
            "va": _hex(IMAGE_BASE + 0x03330A0),
            "call_sites_rva": [_hex(rva) for rva in calls.get(0x03330A0, [])],
            "role": "R9 factor path: writes a signed32 detail/factor candidate through RDX output local",
            "scalar_path": True,
        },
    }
    direct_callees = []
    for target_rva, sites in sorted(calls.items()):
        target = scalar_callees.get(target_rva, {})
        direct_callees.append(
            {
                "target_rva": _hex(target_rva),
                "target_va": _hex(IMAGE_BASE + target_rva),
                "call_sites_rva": [_hex(site) for site in sites],
                "scalar_path": bool(target.get("scalar_path", False)),
                "role": target.get(
                    "role",
                    "post-value detail/formatting or cold cleanup; not needed to derive the returned scalar",
                ),
            }
        )

    old_001 = OLD_STAGE / "trade-power-source-001.json"
    old_002 = OLD_STAGE / "trade-power-source-002.json"
    for path in (old_001, old_002):
        if not path.is_file():
            raise FileNotFoundError(path)

    # The old report's selected range is a useful independent pin, but the new
    # artifact is based on this run's raw bytes and bounded decode.
    prior_001 = json.loads(old_001.read_text(encoding="utf-8"))
    if prior_001.get("target", {}).get("exe_sha256") not in (None, exe_sha):
        raise AssertionError("prior source report has a different PE identity")

    report = {
        "report_id": "information-trade-share-source-001",
        "batch": 45,
        "generated_on": "2026-10-27",
        "status": "bounded_static_share_scalar_partial",
        "scope": {
            "field": "T04.shares",
            "object": "trade_node",
            "purpose": "close the native scalar share candidate without using country_power/total_power",
            "evidence_layers": [
                "ordinary_bounded_PE_disassembly",
                "prior_ordinary_static_report_pin",
            ],
            "runtime_observation": False,
            "game_or_RPM_access": False,
            "REA_invoked": False,
        },
        "target": {
            "exe_sha256": exe_sha,
            "image_base_va": _hex(pe.base),
            "rva_is_module_relative": True,
            "main_function_rva": [_hex(MAIN_RANGE[0]), _hex(MAIN_RANGE[1])],
            "main_function_va": [
                _hex(pe.base + MAIN_RANGE[0]),
                _hex(pe.base + MAIN_RANGE[1]),
            ],
            "main_function_pdata_unwind_rva": _hex(main_boundary[2]),
        },
        "input_evidence": [_prior_report_pin(old_001), _prior_report_pin(old_002)],
        "bounded_decode": {
            "single_range_limit_bytes": MAX_SINGLE_BYTES,
            "total_range_limit_bytes": MAX_TOTAL_BYTES,
            "total_decoded_bytes": total_decoded_bytes,
            "ranges": [main, *ui_ranges],
        },
        "abi_contract": {
            "rcx": "object pointer; the UI caller supplies [widget+0x60], but the native domain/country identity is unresolved",
            "rdx": "writable 4-byte output pointer; normal path stores DWORD [rdx]=r14d and returns RAX=RDX",
            "r8": "packed selector; signed16 slot = sign_extend((R8 >> 32) & 0xffff); entry = [RCX+0x18] + slot*0xc0",
            "r9b": "branch selector; zero skips factor/detail multiplier, nonzero enters factor path and changes the scalar",
            "fifth_stack_argument": "entry [RSP0+0x28], observed as [RBP+0x7f]; gates extra detail formatting after scalar work; native type unresolved",
            "null_selected_entry": "writes zero DWORD to original RDX and returns original RDX",
        },
        "scalar_formula": {
            "base": "q64 = trunc0(int64(signext_i32(entry+0x2c)) * int64(signext_i32(object+0xb0)) / 1000)",
            "r9_zero": "result_i32 = i32(q64)",
            "r9_nonzero": [
                "detail_i32 = signed32 written by direct callee VA 0x1403330a0 to [RBP+0x6f] after VA 0x14093d5c0 supplies its input object",
                "factor_i32 = i32(detail_i32 + 1000)",
                "if selected entry is non-null and (slot == signed32(global DWORD VA 0x14233d8b8) OR selected_entry[0xae] != 0), factor_i32 = i32(factor_i32 + signed32(global DWORD VA 0x14233e53c))",
                "q2_64 = trunc0(int64(i32(q64)) * int64(factor_i32) / 1000)",
                "result_i32 = i32(q2_64)",
            ],
            "output": "DWORD [RDX] = result_i32; RAX = RDX",
            "scale": 1000,
            "clamp_or_percentage_normalization": "none observed in this scalar function",
        },
        "instruction_width_contract": {
            "entry_0x2c": "movsxd signed32 to 64-bit",
            "object_0xb0": "movsxd signed32 to 64-bit",
            "base_product": "signed64 IMUL followed by reciprocal signed division with truncation toward zero",
            "factor_product": "base q64 is explicitly narrowed to signed32 by movsxd r14d before signed64 IMUL with signed32 factor",
            "final_store": "low32 DWORD store; no saturating clamp",
            "pure_examples": [
                {
                    "name": "signed_base_and_trunc0",
                    "entry_0x2c": -2000,
                    "object_0xb0": 1500,
                    "base_q64": -3000,
                    "base_result_i32": -3000,
                },
                {
                    "name": "factor_branch_signed32_narrowing",
                    "entry_0x2c": 2000000000,
                    "object_0xb0": 2000000000,
                    "base_q64": 4000000000000000,
                    "i32_base_before_factor": _i32(4000000000000000),
                    "factor_i32": 1000,
                    "result_i32": _i32(4000000000000000),
                    "note": "R9 path does not multiply the full q64; it first narrows q64 to signed32.",
                },
                {
                    "name": "factor_add_wraps_signed32",
                    "detail_i32": 2147483647,
                    "factor_i32": _i32(2147483647 + 1000),
                    "note": "the ADD at B58DBA is a 32-bit signed wrap before sign extension at B58DF5.",
                },
            ],
        },
        "r9_branch_contract": {
            "ui_call_sites": [
                {
                    "rva": _hex(0x101DAE4),
                    "va": _hex(IMAGE_BASE + 0x101DAE4),
                    "r9b": 1,
                    "output_local_rva": _hex(0x67),
                    "rcx_source": "[RDI+0x60]",
                    "stack_arg_setup": "[RSP+0x20]=R14",
                },
                {
                    "rva": _hex(0x101E8AC),
                    "va": _hex(IMAGE_BASE + 0x101E8AC),
                    "r9b": 1,
                    "output_local_rva": _hex(0x77),
                    "rcx_source": "[RDI+0x60]",
                    "stack_arg_setup": "[RSP+0x20]=R15",
                },
            ],
            "interpretation": "R9=true is on both observed UI scalar call sites and changes the stored scalar; it is not only tooltip formatting. R9=false returns the unmultiplied base path.",
        },
        "node_b0_semantics": {
            "confirmed": "object+0xb0 is a signed32 multiplicand in the B58D00 scalar formula, distinct from runtime node+0xc8 used by the separate total_power cache contract",
            "not_confirmed": "whether +0xb0 is an eligible-country denominator, a published node aggregate, or another native scalar; B58D00 does not iterate nodes or derive a denominator",
            "eligibility_observation": "entry+0xae is read only as a conditional gate for the optional R9 global-factor addition; it is not used as the base denominator",
        },
        "direct_callees": direct_callees,
        "labels": [
            {
                "text": "TRADE_NODE_POWER_SHARE",
                "rva": _hex(0x1CE8BE8),
                "va": _hex(IMAGE_BASE + 0x1CE8BE8),
                "role": "static label family reused by prior trade-power report",
            },
            {
                "text": "TRADE_INCOME_FACTORS",
                "rva": _hex(0x1CE8C00),
                "va": _hex(IMAGE_BASE + 0x1CE8C00),
                "role": "static factor label family reused by prior trade-power report",
            },
        ],
        "unresolved": [
            "The exact semantic/domain identity of RCX=[widget+0x60], including country selector and runtime freshness, is not proven by this bounded code.",
            "The exact producer and meaning of object+0xb0 are unresolved; no eligible denominator or node-sum claim is made.",
            "Callees VA 0x14093d5c0 and 0x1403330a0 are on the R9 scalar path, but their own ABI/domain and factor semantics were not expanded under the 16 KiB budget.",
            "Global DWORDs VA 0x14233d8b8 and 0x14233e53c are fixed static inputs to the optional factor gate/addition; their game-level meanings are unresolved.",
            "No runtime RPM payload for +0x2c/+0xb0 and no share normalization or country/node freshness observation was performed.",
        ],
        "decision": {
            "static_formula": "partially closed: output pointer, base multiplicands, reciprocal /1000, R9 factor path, signed widths, and final low32 store are exact",
            "production_ready": False,
            "reason": "factor callees, +0xb0 meaning, object/country domain, and runtime freshness remain unverified",
            "do_not_substitute": "do not derive T04.shares from country_power or total_power",
        },
        "verification": {
            "raw_main_sha256": main["raw_sha256"],
            "expected_main_raw_sha256": "e4c68e3ba174497c7eea0fc6861301a673fbe1464c5958ed28b3012ba91e3477",
            "main_raw_sha256_matches_prior_pin": main["raw_sha256"] == "e4c68e3ba174497c7eea0fc6861301a673fbe1464c5958ed28b3012ba91e3477",
            "bounded_ranges_decoded": len([main, *ui_ranges]),
            "decoded_bytes": total_decoded_bytes,
            "all_shell_work_in_process": True,
        },
    }
    return report


def _source1_subrange(source1, begin: int, end: int, label: str):
    """Project a small raw-byte range from the already pinned source001 run."""
    main = next(
        record
        for record in source1["bounded_decode"]["ranges"]
        if record["label"] == "trade_share_scalar_function"
    )
    main_begin = int(main["rva_start"], 16)
    main_end = int(main["rva_end_exclusive"], 16)
    if not main_begin <= begin < end <= main_end:
        raise AssertionError("source001 subrange is outside the pinned main range")
    raw = bytes.fromhex(main["raw_hex"])[begin - main_begin : end - main_begin]
    return {
        "label": label,
        "rva_start": _hex(begin),
        "rva_end_exclusive": _hex(end),
        "va_start": _hex(IMAGE_BASE + begin),
        "va_end_exclusive": _hex(IMAGE_BASE + end),
        "byte_length": len(raw),
        "raw_hex": raw.hex(),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "source": "source001_pinned_raw_range",
    }


def _static_c_string(pe: PE, rva: int, label: str):
    raw = pe.bytes_at(rva, 256)
    end = raw.find(b"\x00")
    if end < 0:
        raise AssertionError(f"unterminated static string at {rva:#x}")
    payload = raw[: end + 1]
    return {
        "label": label,
        "rva": _hex(rva),
        "va": _hex(IMAGE_BASE + rva),
        "text": payload[:-1].decode("ascii"),
        "bytes_hex": payload.hex(),
        "bytes_sha256": hashlib.sha256(payload).hexdigest(),
    }


def build_source002():
    """Build the follow-up that separates the raw share row from B58D00 income."""
    source1_path = STAGE / "share-source-001.json"
    if not source1_path.is_file():
        raise FileNotFoundError(source1_path)
    source1 = json.loads(source1_path.read_text(encoding="utf-8"))
    source1_sha = _file_sha256(source1_path)
    if source1.get("report_id") != "information-trade-share-source-001":
        raise AssertionError("unexpected source001 report identity")

    check_memory_budget()
    pe = PE(game_exe())
    exe_sha = hashlib.sha256(pe.data).hexdigest()
    if exe_sha != EXPECTED_EXE_SHA256 or pe.base != IMAGE_BASE:
        raise ValueError("source002 PE identity does not match the pinned 1.37.4 target")
    md, _ = make_disassembler(ROOT / "work/deps/capstone-5.0.7")

    # This window is aligned to the first UI function's instructions.  It
    # contains the literal income selector, B58D00 call, its fixed-point
    # formatter, and the row-builder key written immediately before the call.
    ui = _range_record(
        pe, md, 0x101DA77, 0x101DB29, "ui_income_key_b58d00_row_builder"
    )
    # B5B320 is the adjacent current-power-style getter used by the second UI
    # branch.  Its split pdata records are retained separately below; this is a
    # contiguous 236-byte ordinary window, not an assertion that pdata has one
    # single function body here.
    current_power_helper = _range_record(
        pe, md, 0xB5B320, 0xB5B40C, "adjacent_current_power_helper_b5b320"
    )
    current_power_helper["pdata_subranges"] = []
    for address in (0xB5B320, 0xB5B342, 0xB5B3FE):
        boundary = pe.function(address)
        if boundary:
            current_power_helper["pdata_subranges"].append(
                {
                    "entry_rva": _hex(address),
                    "rva_start": _hex(boundary[0]),
                    "rva_end_exclusive": _hex(boundary[1]),
                    "pdata_unwind_rva": _hex(boundary[2]),
                }
            )
    decoded_bytes = ui["byte_length"] + current_power_helper["byte_length"]
    if decoded_bytes > MAX_TOTAL_BYTES:
        raise AssertionError("source002 bounded decode exceeds 16 KiB")

    _assert_bytes(
        pe,
        {
            0x101DAA1: "488d158853d200",
            0x101DAA8: "41ff9098000000",
            0x101DAC6: "66c745d7a400",
            0x101DAD9: "41b101",
            0x101DAE4: "e817b2b3ff",
            0x101DAE9: "488bd0",
            0x101DAF0: "e87bf6ffff",
            0x101DAF6: "4c8d45d7",
            0x101DB01: "e83a620cff",
            0xB5B324: "4c6399dc000000",
            0xB5B347: "486399bc000000",
            0xB5B368: "49634144",
            0xB5B36C: "4963494c",
            0xB5B388: "418b4154",
            0xB5B392: "412b4150",
            0xB5B39F: "4403c0",
            0xB5B3F6: "418912",
        },
    )

    ui_rows = ui["instructions"]
    helper_rows = current_power_helper["instructions"]
    for rowset, rva, mnemonic in (
        (ui_rows, 0x101DAA1, "lea"),
        (ui_rows, 0x101DAE4, "call"),
        (ui_rows, 0x101DAF0, "call"),
        (ui_rows, 0x101DB01, "call"),
        (helper_rows, 0xB5B368, "movsxd"),
        (helper_rows, 0xB5B36C, "movsxd"),
        (helper_rows, 0xB5B3F6, "mov"),
    ):
        if _row(rowset, rva)["mnemonic"] != mnemonic:
            raise AssertionError(f"source002 instruction drift at {rva:#x}")

    source1_main_rows = next(
        record["instructions"]
        for record in source1["bounded_decode"]["ranges"]
        if record["label"] == "trade_share_scalar_function"
    )
    ratio_rvas = (
        0xB58E45,
        0xB58E84,
        0xB58E89,
        0xB58E8B,
        0xB58E95,
        0xB58E97,
        0xB58EAF,
        0xB58EB6,
        0xB58EB8,
        0xB58EC1,
        0xB58EF2,
        0xB58EFC,
        0xB58F03,
        0xB58F0E,
    )
    ratio_rows = [_row(source1_main_rows, rva) for rva in ratio_rvas]
    ratio_format_range = _source1_subrange(
        source1, 0xB58E45, 0xB58EC9, "b58d00_entry_2c_percentage_format_path"
    )

    static_strings = [
        _static_c_string(pe, 0x1D42E30, "income_selector_key"),
        _static_c_string(pe, 0x1CE8BE8, "native_share_detail_label"),
        _static_c_string(pe, 0x1CE8C00, "native_income_factor_detail_label"),
        _static_c_string(pe, 0x1C329DC, "formatter_kind_key"),
    ]

    # Pure arithmetic examples document the exact fixed-point transformation
    # visible in B58E45..B58EB6 without presenting it as a runtime observation.
    ratio_examples = []
    for raw in (123, -123):
        scaled100 = _i32(raw * 100)
        absolute = abs(scaled100)
        whole = absolute // 1000
        remainder = absolute - whole * 1000
        ratio_examples.append(
            {
                "raw_entry_0x2c": raw,
                "signed32_raw_times_100": scaled100,
                "sign": "-" if scaled100 < 0 else "+",
                "whole_percent_before_formatter": whole,
                "remainder_milli_percent": remainder,
            }
        )

    report = {
        "report_id": "information-trade-share-source-002",
        "batch": 45,
        "generated_on": "2026-10-27",
        "status": "bounded_static_share_cache_binding_partial",
        "supplement_to": {
            "path": source1_path.relative_to(ROOT).as_posix(),
            "sha256": source1_sha,
            "report_id": source1["report_id"],
        },
        "target": {
            "game_version": "1.37.4",
            "exe_sha256": exe_sha,
            "image_base_va": _hex(pe.base),
            "address_rule": "RVA and VA are separate; ranges are half-open",
        },
        "scope": {
            "topic_id": "T04",
            "field": "shares",
            "object": "trade_node",
            "question": "separate the raw entry share cache from the B58D00 composite income-like return",
            "mode": "ordinary bounded PE analysis plus pinned source001 evidence",
            "no_game": True,
            "no_runtime_access": True,
            "no_rea": True,
            "no_production_changes": True,
            "additional_decode_bytes": decoded_bytes,
        },
        "bounded_decode": {
            "single_range_limit_bytes": MAX_SINGLE_BYTES,
            "total_range_limit_bytes": MAX_TOTAL_BYTES,
            "new_ranges": [ui, current_power_helper],
            "source001_reused_raw_range": ratio_format_range,
        },
        "native_string_evidence": static_strings,
        "ui_binding": {
            "first_path": {
                "income_key_setup": {
                    "load_rva": _hex(0x101DAA1),
                    "load_va": _hex(IMAGE_BASE + 0x101DAA1),
                    "instruction": "lea rdx,[rip+...] # 0x141d42e30",
                    "key": "income",
                    "call_rva": _hex(0x101DAA8),
                    "call_va": _hex(IMAGE_BASE + 0x101DAA8),
                    "callee": "QWORD PTR [R8+0x98]",
                    "interpretation": "the native income selector/key is passed on the same control-flow path immediately before B58D00",
                },
                "row_token": {
                    "rva": _hex(0x101DAC6),
                    "instruction": "mov WORD PTR [RBP-0x29],0xa4",
                    "meaning": "numeric row/control token consumed by the subsequent row builder; its localization mapping is not independently identified",
                },
                "scalar_call": {
                    "rva": _hex(0x101DAE4),
                    "va": _hex(IMAGE_BASE + 0x101DAE4),
                    "callee": _hex(IMAGE_BASE + 0xB58D00),
                    "r9b": 1,
                    "output_then_formatter": [
                        {"rva": _hex(0x101DAE9), "instruction": "mov rdx,rax"},
                        {"rva": _hex(0x101DAF0), "callee": _hex(IMAGE_BASE + 0x101D170)},
                    ],
                    "row_builder_after_formatter": {
                        "rva": _hex(0x101DB01),
                        "callee": _hex(IMAGE_BASE + 0x00E3D40),
                        "arguments": "R8=&[RBP-0x29] (the 0xa4 token), RDX=formatted output, RCX=&[RBP-0x9]",
                    },
                    "binding_strength": "strong_static_income_path; the row-builder helper itself was not decoded",
                },
            },
            "second_path": {
                "scalar_call": {
                    "rva": _hex(0x101E8AC),
                    "va": _hex(IMAGE_BASE + 0x101E8AC),
                    "callee": _hex(IMAGE_BASE + 0xB58D00),
                    "r9b": 1,
                    "rcx_source": "[RDI+0x60]",
                    "post_call": "direct jump at 0x101e8b1 to the next UI block; no immediate 0xa4 write is present in the bounded predecessor/post-call window",
                    "key_status": "not independently closed for this path",
                }
            },
        },
        "entry_0x2c_share_contract": {
            "raw_source": "selected entry + 0x2c, signed32",
            "fixed_point_scale": 1000,
            "percentage_format_path": {
                "exact_rows_reused_from_source001": ratio_rows,
                "formula": "p100_i32 = i32(i32(entry+0x2c) * 100); sign/abs are prepared; whole_percent = trunc0(abs(p100_i32)/1000); remainder_milli_percent = abs(p100_i32) - whole_percent*1000",
                "observed_order": [
                    "B58E45: signed32 IMUL entry+0x2c by 0x64",
                    "B58E84..B58E97: reciprocal /1000 quotient with sign/absolute handling",
                    "B58EAF..B58EB6: quotient*1000 subtracted to retain the fractional remainder",
                    "B58EB8..B58EC1: remainder+1000 sent through the decimal formatter",
                ],
                "pure_examples": ratio_examples,
            },
            "native_detail_label": {
                "label": "TRADE_NODE_POWER_SHARE",
                "load_rva": _hex(0xB58F03),
                "label_rva": _hex(0x1CE8BE8),
                "formatter_kind": "VAL at RVA 0x1c329dc is loaded at B58EFC",
                "row_builder_call_rva": _hex(0xB58F0E),
                "meaning": "the raw +0x2c value is explicitly formatted as a percentage/detail row; this is separate from the already-computed B58D00 return scalar",
            },
            "decision": "+0x2c is a viable native share cache input for T04.shares, subject to runtime entry-table/selector guards; B58D00's composite return must not be named shares solely because its detail path contains the share label.",
        },
        "b58d00_return_binding": {
            "base_inputs": ["entry+0x2c raw share fixed-point", "object+0xb0 signed32 multiplicand"],
            "factor_detail_label": {
                "label": "TRADE_INCOME_FACTORS",
                "load_rva": _hex(0xB58FFD),
                "label_rva": _hex(0x1CE8C00),
                "interpretation": "the detail branch names income factors after the share percentage row",
            },
            "static_role": "composite trade-income-like value candidate: share input multiplied by an object scalar and optionally adjusted by the R9 factor path",
            "not_share_contract": "the return scalar is not the raw ratio; its base arithmetic already multiplies +0x2c by +0xb0 and the UI path selects the income key",
            "caveats": [
                "The exact semantic type of +0xb0 and the two factor callees remain unresolved.",
                "The English locale translation of the native keys is not present in the pinned evidence; only native ASCII keys are proven.",
            ],
        },
        "adjacent_b5b320_comparison": {
            "range": ["0xb5b320", "0xb5b40c"],
            "role": "separate current-power-style helper observed in the second UI path, not a share formatter",
            "inputs": ["object+0xbc", "object+0xdc", "entry+0x44", "entry+0x4c", "entry+0x48", "entry+0x50", "entry+0x54"],
            "key_rows": [
                {"rva": _hex(0xB5B324), "instruction": "movsxd r11,DWORD PTR [rcx+0xdc]"},
                {"rva": _hex(0xB5B347), "instruction": "movsxd rbx,DWORD PTR [rcx+0xbc]"},
                {"rva": _hex(0xB5B368), "instruction": "movsxd rax,DWORD PTR [r9+0x44]"},
                {"rva": _hex(0xB5B36C), "instruction": "movsxd rcx,DWORD PTR [r9+0x4c]"},
                {"rva": _hex(0xB5B388), "instruction": "mov eax,DWORD PTR [r9+0x54]"},
                {"rva": _hex(0xB5B392), "instruction": "sub eax,DWORD PTR [r9+0x50]"},
                {"rva": _hex(0xB5B39F), "instruction": "add r8d,eax"},
                {"rva": _hex(0xB5B3F6), "instruction": "mov DWORD PTR [r10],edx"},
            ],
            "conclusion": "this helper is the current-power/cap/delta family already separated in source001/source002; it supplies no evidence that B58D00 return or +0x2c is the current_power field",
        },
        "locale_status": {
            "native_keys_proven": ["income", "TRADE_NODE_POWER_SHARE", "TRADE_INCOME_FACTORS", "VAL"],
            "english_text_proven": False,
            "reason": "the bounded PE and prior reports expose native localization tokens only; no locale file/archive was read under this task's scope",
        },
        "unresolved": [
            "The exact English translation of the native keys and the internal semantics of row-builder 0x1400e3d40 remain unresolved.",
            "The second B58D00 UI callsite's numeric row token is not independently visible in its bounded predecessor/post-call window.",
            "Runtime freshness, selector-to-country alignment, and the native producer/cache location for entry+0x2c remain unobserved.",
            "B58D00 +0xb0 and R9 factor callees remain income-side unknowns and do not block the static +0x2c share-cache candidate.",
        ],
        "decision": {
            "share_field": "read the selected entry raw signed32 at +0x2c as a 1000-scaled native share candidate; do not derive it from country_power/total_power",
            "b58d00_field": "keep the B58D00 composite return as a separate income-like candidate, not T04.shares",
            "production_ready": False,
            "reason": "runtime freshness/selector guards and exact public row schema are still required",
        },
        "verification": {
            "source001_sha256": source1_sha,
            "new_decode_bytes": decoded_bytes,
            "ui_range_raw_sha256": ui["raw_sha256"],
            "b5b320_window_raw_sha256": current_power_helper["raw_sha256"],
            "all_shell_work_completed": True,
            "game_access": False,
            "rpm_used": False,
            "rea_access": False,
        },
    }
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--revision", choices=("001", "002"), default="001")
    args = parser.parse_args()
    check_memory_budget()
    report = build_report() if args.revision == "001" else build_source002()
    STAGE.mkdir(parents=True, exist_ok=True)
    output = OUTPUT if args.revision == "001" else OUTPUT_002
    if output.exists():
        raise FileExistsError(f"refusing to overwrite existing artifact: {output}")
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    check_memory_budget()
    print(json.dumps({
        "output": output.relative_to(ROOT).as_posix(),
        "sha256": _file_sha256(output),
        "decoded_bytes": report["verification"].get(
            "decoded_bytes", report["verification"].get("new_decode_bytes")
        ),
        "main_raw_sha256": report["verification"].get(
            "raw_main_sha256", report["verification"].get("source001_sha256")
        ),
        "direct_callee_count": len(report.get("direct_callees", [])),
        "status": report["status"],
    }, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
