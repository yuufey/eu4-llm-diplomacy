"""Generate a bounded static ABI contract for the production amount path.

This batch deliberately reuses the already decoded A11920 evidence from the
tax-collector report.  It decodes only A12C20 and its two direct numeric
helpers, A11110 and A13E40.  It never opens the game, invokes RPM/REA, writes
production code, or treats the static arithmetic as a proven game value.
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
MAX_RANGE_BYTES = 8 * 1024
MAX_TOTAL_DECODE_BYTES = 32 * 1024
PRIOR_TAX_REPORT = ROOT / "work/runtime/information-budget-collectors-20261027-001/tax-collector-contract-001.json"
DEFAULT_OUTPUT = ROOT / "work/runtime/information-trade-state-20261027-001/production-amount-contract-001.json"


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_file(path: Path) -> str:
    return _hash_bytes(path.read_bytes())


def _range_record(pe: PE, start: int, end: int, label: str, instructions: list[dict]) -> dict:
    raw = pe.bytes_at(start, end - start)
    return {
        "label": label,
        "rva_exclusive": [hex(start), hex(end)],
        "va_exclusive": [hex(pe.base + start), hex(pe.base + end)],
        "byte_length": end - start,
        "raw_range_sha256": _hash_bytes(raw),
        "function_boundary": {
            "rva_start": hex(start),
            "rva_end": hex(end),
            "byte_length": end - start,
        },
        "instruction_count": len(instructions),
        "decoder": "bounded ordinary PE disassembly (capstone when available; bounded objdump fallback)",
    }


def _selected(rows: list[dict], rvas: tuple[int, ...]) -> list[dict]:
    wanted = {hex(rva) for rva in rvas}
    return [row for row in rows if row["rva"] in wanted]


def _assert_selected(rows: list[dict], rvas: tuple[int, ...], label: str) -> None:
    got = {row["rva"] for row in rows}
    missing = [hex(rva) for rva in rvas if hex(rva) not in got]
    if missing:
        raise AssertionError(f"{label} missing expected instructions: {missing}")


def _function(pe: PE, rva: int, label: str) -> tuple[int, int, int, list[dict], dict]:
    boundary = pe.function(rva)
    if boundary is None:
        raise ValueError(f"no .pdata boundary for {label} at {rva:#x}")
    start, end, pdata_rva = boundary
    if start != rva:
        raise ValueError(f"{label} boundary starts at {start:#x}, expected {rva:#x}")
    if end <= start or end - start > MAX_RANGE_BYTES:
        raise ValueError(f"{label} boundary exceeds one-range limit: {start:#x}:{end:#x}")
    if not pe.executable(start) or not pe.executable(end - 1):
        raise ValueError(f"{label} boundary is not executable")
    return start, end, pdata_rva, [], {
        "rva_start": hex(start),
        "rva_end": hex(end),
        "byte_length": end - start,
        "pdata_rva": hex(pdata_rva),
    }


def build_report() -> dict:
    pe = PE(Path(game_exe()))
    binary_sha256 = _hash_bytes(pe.data)
    if binary_sha256 != EXPECTED_SHA256:
        raise ValueError(f"unsupported game binary SHA-256: {binary_sha256}")
    if pe.base != IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.base:#x}")

    if not PRIOR_TAX_REPORT.is_file():
        raise FileNotFoundError(PRIOR_TAX_REPORT)
    prior = json.loads(PRIOR_TAX_REPORT.read_text(encoding="utf-8"))
    prior_sha256 = _hash_file(PRIOR_TAX_REPORT)
    prior_target = prior.get("target", {})
    if prior_target.get("sha256") not in (None, EXPECTED_SHA256):
        raise ValueError("prior tax report targets a different binary")
    prior_instruction_evidence = prior.get("a11920_pre_544_contract", {}).get(
        "instruction_evidence", {}
    )
    prior_range = prior_instruction_evidence.get("range_rva_exclusive", [])
    if len(prior_range) != 2:
        raise ValueError("prior A11920 evidence has no bounded range")
    prior_start, prior_end = (int(value, 16) for value in prior_range)
    prior_actual_sha256 = _hash_bytes(pe.bytes_at(prior_start, prior_end - prior_start))
    if prior_actual_sha256 != prior_instruction_evidence.get("raw_range_sha256"):
        raise ValueError("prior A11920 raw bytes do not match this PE")

    md, _capstone = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    requested = ((0xA12C20, "a12c20"), (0xA11110, "a11110"), (0xA13E40, "a13e40"))
    decoded: dict[str, list[dict]] = {}
    ranges: list[dict] = []
    total = 0
    boundaries: dict[str, dict] = {}
    for rva, label in requested:
        start, end, pdata_rva, _unused, boundary = _function(pe, rva, label)
        instructions = _decode_range(pe, md, start, end)
        decoded[label] = instructions
        total += end - start
        if total > MAX_TOTAL_DECODE_BYTES:
            raise ValueError("new bounded decode total exceeds 32 KiB")
        boundary["pdata_rva"] = hex(pdata_rva)
        boundaries[label] = boundary
        ranges.append(_range_record(pe, start, end, label, instructions))

    a12c20_rows = decoded["a12c20"]
    a11110_rows = decoded["a11110"]
    a13e40_rows = decoded["a13e40"]

    a12c20_selected_rvas = (
        0xA12C4A, 0xA12C55, 0xA12C57, 0xA12C5E, 0xA12C65,
        0xA12D70, 0xA12D73, 0xA12D78, 0xA12D7B, 0xA12D80,
        0xA12D87, 0xA12D89, 0xA12DB7, 0xA12E2F, 0xA12E32,
        0xA12E77, 0xA13213, 0xA13226, 0xA13250, 0xA13255,
        0xA1325A, 0xA13261, 0xA13266, 0xA13269, 0xA13902,
        0xA13909, 0xA13910, 0xA1392D,
    )
    a11110_selected_rvas = (
        0xA11129, 0xA1112C, 0xA1112F, 0xA11132, 0xA111A2,
        0xA11247, 0xA112C5, 0xA11372, 0xA113C9, 0xA118F2,
        0xA11908,
    )
    a13e40_selected_rvas = (
        0xA13E5D, 0xA13E60, 0xA13E63, 0xA13E6B, 0xA13E71,
        0xA13E7B, 0xA13E8B, 0xA13ED8, 0xA145E0, 0xA145E3,
        0xA145F9,
    )
    _assert_selected(a12c20_rows, a12c20_selected_rvas, "a12c20")
    _assert_selected(a11110_rows, a11110_selected_rvas, "a11110")
    _assert_selected(a13e40_rows, a13e40_selected_rvas, "a13e40")

    all_rows = a12c20_rows + a11110_rows + a13e40_rows
    tls_rows = [
        row for row in all_rows
        if any(token in (row["mnemonic"] + " " + row["operands"]).lower()
               for token in ("fs:", "gs:", "tls", "__tls"))
    ]

    a11920 = prior.get("a11920_pre_544_contract", {})
    callsites = a11920.get("callsites", [])
    caller_body = a11920.get("body", [])
    return {
        "report_id": "production-amount-contract-001",
        "batch": 43,
        "generated_on": "2026-10-27",
        "status": "partial_static_contract_only",
        "scope": {
            "included": [
                "Reuse prior bounded A11920 evidence from tax-collector-contract-001",
                "Bounded ordinary PE decode of A12C20, A11110, and A13E40",
                "Register/stack ABI, direct output writes, direct getter result flow, and explicit TLS scan",
            ],
            "excluded": [
                "No EB7B20 re-decode",
                "No runtime/game/RPM/REA invocation",
                "No production code, profile, DLL, or native call changes",
                "No claim that the computed DWORD is a production amount or any particular unit",
            ],
        },
        "target": {
            "exe": str(pe.path),
            "version": "1.37.4",
            "sha256": binary_sha256,
            "image_base": hex(pe.base),
            "address_convention": "RVA is image-relative; VA = image_base + RVA; ordinary PE, not REA evidence",
        },
        "prior_evidence": {
            "path": PRIOR_TAX_REPORT.relative_to(ROOT).as_posix(),
            "sha256": prior_sha256,
            "evidence_kind": "reused_bounded_ordinary_static_report",
            "a11920_callsites": callsites,
            "a11920_body": caller_body,
            "a11920_instruction_evidence": a11920.get("instruction_evidence"),
            "a11920_raw_bytes_rechecked": {
                "rva_exclusive": [hex(prior_start), hex(prior_end)],
                "sha256": prior_actual_sha256,
                "matches_prior_report": True,
                "decode_repeated": False,
            },
        },
        "function_boundaries": boundaries,
        "new_decode": {
            "ranges": ranges,
            "total_byte_length": total,
            "limits": {
                "max_single_range_bytes": MAX_RANGE_BYTES,
                "max_total_decode_bytes": MAX_TOTAL_DECODE_BYTES,
            },
            "selected_instructions": {
                "a12c20": _selected(a12c20_rows, a12c20_selected_rvas),
                "a11110": _selected(a11110_rows, a11110_selected_rvas),
                "a13e40": _selected(a13e40_rows, a13e40_selected_rvas),
            },
        },
        "a11920_contract": {
            "entry_registers": {
                "rcx": "province-table record candidate P (per prior report; not the country candidate)",
                "rdx": "DWORD out pointer",
                "r8": "optional auxiliary/context gate",
                "r9": "saved byte/flag for the nonzero auxiliary path",
            },
            "guard": [
                "TEST BYTE [RCX+0x958],0x10; set branches to A12C20",
                "CMP DWORD [RCX+0x3F8],0x3E7; >=999 branches to A12C20",
            ],
            "direct_path": {
                "condition": "both guards clear and R8==0",
                "write": "DWORD [original RDX] = 0",
                "return": "RAX = original RDX out pointer",
            },
            "alternate_path": {
                "call": "A12C20",
                "return": "caller overwrites A12C20's RAX with original RDX and returns that pointer",
                "direct_province_write_observed": False,
            },
            "side_effect_boundary": "A11920 directly writes only its caller-provided DWORD on the direct path; indirect helper side effects remain outside this contract.",
        },
        "a12c20_contract": {
            "function": {
                "rva": "0xa12c20",
                "va": hex(pe.base + 0xA12C20),
                "range": ["0xa12c20", "0xa13964"],
            },
            "direct_call_from_a11920": {
                "rcx": "same province pointer P",
                "rdx": "same caller DWORD out pointer; saved as R14",
                "r8": "LEA R8,[caller RSP+0x44]",
                "r9": "LEA R9,[caller RSP+0x40]",
                "stack_plus_0x28": "caller RDI, which A11920 copied from its incoming R8",
                "stack_plus_0x30": "caller byte store of incoming R9B; semantic type is unresolved",
                "internal_initial_scalar": "A12C4A XOR EDI,EDI; the observed A12C20 body does not consume incoming R8 as an amount scalar",
            },
            "entry_and_return": {
                "entry_write": "DWORD [RDX] = 0 at A12C55",
                "province_read": "QWORD [RCX+0x458], then BYTE [that+0x80] at A12C57/A12C5E",
                "branch": "zero byte selects the A13E40 fallback at A13213; nonzero enters the A11110/main path",
                "return": "RAX = R14, where R14 is the original RDX out pointer",
                "final_writes": "Several paths write a computed DWORD to [R14]; an explicit [R14]=0 also exists at A13909 on the sign-dependent path after the computed write. Exact path coverage needs runtime or broader semantic analysis.",
            },
            "getter_result_flow": {
                "a11110_main": {
                    "call_setup": "RCX=P, RDX=&[RSP+0x68], R8=RDI (optional context/string object), R9=&[RSP+0x40], stack +0x20=&[RBP+0xB8]",
                    "result": "A11110 writes a signed 32-bit aggregate to [RSP+0x68] and returns RAX=&[RSP+0x68]; A12C20 reads [RAX] at A12D89 and combines it with DWORD *[RBP+0xD0] before writing [R14] at A12DB7",
                },
                "indirect_getter": {
                    "call": "FF 50 08 at A12E2F through a global object/vtable",
                    "result": "writes DWORD [RSP+0x40]; A12C20 reads it at A12E32, applies signed arithmetic, and adds the result to [R14] at A12E77",
                },
                "a13e40_fallback": {
                    "call_setup": "RCX=P, RDX=&[RBP+0x0], R8=&[RSP+0x68], R9=&[RSP+0x40], stack +0x20=RDI, +0x28=&[RBP+0xB8], +0x30=&[RBP+0xB0]",
                    "result": "A13E40 writes its computed DWORD to the supplied RDX and returns that pointer; A12C20 reads [RAX] at A13266 and writes [R14] at A13269",
                },
            },
            "direct_side_effects": {
                "writes": [
                    "caller out DWORD [RDX]/[R14]",
                    "callee stack locals and temporary string/storage objects",
                ],
                "direct_write_to_province_record": False,
                "indirect_callee_side_effects": "unknown; vtable/helper calls are visible but their persistent writes were not expanded",
            },
        },
        "a11110_contract": {
            "function": {"rva": "0xa11110", "range": ["0xa11110", "0xa1191d"]},
            "inputs_at_a12c20_call": {
                "rcx": "province P",
                "rdx": "&[RSP+0x68] result DWORD",
                "r8": "A12C20 RDI optional context pointer",
                "r9": "&[RSP+0x40] auxiliary DWORD pointer",
                "stack_plus_0x20": "&[RBP+0xB8]",
            },
            "getter_results": "Four indirect [vtable+0x8] calls load intermediate DWORDs; the function combines them with *R9 and writes [RDX] at A113C9.",
            "return": "RAX = original RDX result pointer at A118F2; RET at A11908",
            "direct_persistent_write_observed": False,
        },
        "a13e40_contract": {
            "function": {"rva": "0xa13e40", "range": ["0xa13e40", "0xa1461e"]},
            "inputs_at_a12c20_call": {
                "rcx": "province P",
                "rdx": "temporary DWORD result pointer",
                "r8": "pointer to scalar copied into local [RBP+0x58]",
                "r9": "pointer to scalar copied into local [RBP+0x50]",
                "stack_plus_0x20": "pointer to local [RBP+0x50]",
            },
            "getter_results": "Calls A11110 and additional indirect getters; writes computed DWORD to supplied RDX at A13ED8/A145E0.",
            "return": "RAX = original RDX result pointer at A145E3; RET at A145F9",
            "direct_persistent_write_observed": False,
        },
        "thread_tls": {
            "explicit_scan": {
                "decoded_ranges": ["a12c20", "a11110", "a13e40"],
                "fs_gs_tls_rows": tls_rows,
                "finding": "No FS:/GS: or explicit TLS operand was present in the newly decoded instruction rows.",
            },
            "known_call_requirements": [
                "A valid province record P and its +0x458 pointer/object state",
                "A valid caller output DWORD and the context/auxiliary pointers used by the alternate path",
                "Initialized global objects/vtables reached through indirect calls",
            ],
            "unknown": [
                "Game-thread affinity, locks, object lifetime, and initialization ordering",
                "TLS or thread checks inside indirect helpers/vtable targets outside these bounded ranges",
                "Whether calling from a non-game thread is safe",
            ],
            "runtime_status": "No runtime or game call was made, so no thread/TLS condition is proven sufficient.",
        },
        "province_cache_reuse": {
            "source_checked": [
                "bridge/information/trade_income_memory.py",
                "bridge/information/country_resources_memory.py",
            ],
            "finding": "The existing trade reader derives/stores province and province+0xE8 trade-runtime linkage, but it does not copy A11920/A12C20 inputs province+0x458, province+0x958, or province+0x3F8, nor a production amount result.",
            "reusable": "Only structural province identity/linkage may be investigated later; no copied production amount cache is available for this contract.",
            "caveat": "A11920's callsite derivation includes lookup 0x14009A010 before forming the province record, so equality with the trade reader's province pointer is not proven by this batch.",
        },
        "amount_interpretation": {
            "status": "unresolved",
            "known": [
                "A12C20/A11110/A13E40 perform signed integer arithmetic, including 0x3E8 constants and reciprocal-multiply sequences.",
                "Those instructions prove only the observed integer operations and output-pointer flow.",
            ],
            "not_proven": [
                "production amount meaning",
                "ducats/unit scale",
                "current-month versus forecast/GUI semantics",
                "whether indirect getter values are cached, live, or context-dependent",
            ],
        },
        "decision": {
            "production_reader_authorized": False,
            "reason": "Static ABI/output flow is partially closed, but amount semantics, runtime safety, and thread/TLS sufficiency remain unproven.",
            "stop_condition": "Stop this narrow contract here; do not expand into a general economic framework without a new bounded evidence request.",
        },
        "verification": {
            "binary_sha256_checked": True,
            "image_base_checked": True,
            "new_decode_total_bytes": total,
            "new_decode_limit_ok": total <= MAX_TOTAL_DECODE_BYTES,
            "game_access": False,
            "rpm": False,
            "rea": False,
            "production_files_modified": False,
        },
        "generator": {
            "path": Path(__file__).relative_to(ROOT).as_posix(),
            "sha256": _hash_file(Path(__file__)),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": args.output.relative_to(ROOT).as_posix(),
        "sha256": _hash_file(args.output),
        "new_decode_total_bytes": report["verification"]["new_decode_total_bytes"],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
