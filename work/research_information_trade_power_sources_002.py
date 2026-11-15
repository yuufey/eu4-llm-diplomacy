"""Refine the three fixed trade-power source rows with the shared formatter.

This is a new Batch-45 evidence report.  It decodes only the exact pdata
function containing helper 0x14bc950 and three small caller windows around
the province, light-ship, and downstream rows.  It never starts the game,
uses RPM/REA, or changes production code or the earlier source-001 report.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work" / "runtime" / "information-trade-share-20261027-001"
OUTPUT = STAGE / "power-sources-source-002.json"
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE, make_disassembler  # noqa: E402
from work.local_config import game_exe  # noqa: E402
from work.research_information_branch_inputs import _decode_range  # noqa: E402


EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = 0x140000000
HELPER_RVA = 0x14BC950
MAX_SINGLE_RANGE = 8 * 1024
MAX_TOTAL_DECODE = 16 * 1024

# The starts and ends are instruction boundaries selected from the already
# bounded B57700..B58354 function.  Each window contains one raw load, the
# helper call, and the subsequent row builder call.
ROW_WINDOWS = {
    "TP_PROVINCE_POWER": (0xB57763, 0xB577B6),
    "TP_SHIP_POWER": (0xB57890, 0xB578E1),
    "MERCHANT_DOWNSTREAM_BONUS": (0xB57E49, 0xB57E94),
}

ROW_SELECTED_RVAS = {
    "TP_PROVINCE_POWER": (
        0xB57763, 0xB5777D, 0xB57783, 0xB57788, 0xB5778B,
        0xB5778F, 0xB57796, 0xB5779A, 0xB577A0, 0xB577B1,
    ),
    "TP_SHIP_POWER": (
        0xB57896, 0xB578A1, 0xB578A7, 0xB578AC, 0xB578AF,
        0xB578B5, 0xB578BC, 0xB578C1, 0xB578C7, 0xB578DC,
    ),
    "MERCHANT_DOWNSTREAM_BONUS": (
        0xB57E49, 0xB57E4D, 0xB57E4F, 0xB57E55, 0xB57E5D,
        0xB57E62, 0xB57E65, 0xB57E69, 0xB57E70, 0xB57E74,
        0xB57E7A, 0xB57E8F,
    ),
}

HELPER_SELECTED_RVAS = (
    0x14BC976,  # movsxd r12,r8d: signed formatter kind
    0x14BC982,  # compare the pointed DWORD with zero
    0x14BCA04,  # mov eax,DWORD PTR [rdi]
    0x14BCA2B,  # sign test
    0x14BCA36,  # neg magnitude candidate
    0x14BCA39,  # retain signed magnitude for nonnegative input
    0x14BCA4B,  # reciprocal for division by 1000
    0x14BCA50,
    0x14BCA56,
    0x14BCA60,
    0x14BCA69,  # integer part formatter
    0x14BCA86,  # quotient * 1000
    0x14BCA8D,  # remainder
    0x14BCA90,  # remainder + 1000 for fractional formatter
    0x14BCA9A,  # fractional formatter
    0x14BCA9F,  # decimal point
    0x14BCCDA,  # R9 display/language selector
)

ROW_CONTRACTS = {
    "TP_PROVINCE_POWER": {
        "entry_offset": "0x28",
        "raw_load_rva": "0xb57763",
        "call_rva": "0xb5779a",
        "builder_rva": "0xb577b1",
        "condition": "signed DWORD [entry+0x28] != 0",
        "localization_line": 23,
        "localization_text": "TP_PROVINCE_POWER:0 \"From Provinces: $VAL$\"",
    },
    "TP_SHIP_POWER": {
        "entry_offset": "0x1c",
        "raw_load_rva": "0xb57896",
        "call_rva": "0xb578c1",
        "builder_rva": "0xb578dc",
        "condition": "signed DWORD [entry+0x1c] != 0",
        "localization_line": 24,
        "localization_text": "TP_SHIP_POWER:0 \"From Light Ships: $VAL$\"",
    },
    "MERCHANT_DOWNSTREAM_BONUS": {
        "entry_offset": "0x40",
        "raw_load_rva": "0xb57e49",
        "call_rva": "0xb57e74",
        "builder_rva": "0xb57e8f",
        "condition": "signed DWORD [entry+0x40] > 0",
        "localization_line": 149,
        "localization_text": "MERCHANT_DOWNSTREAM_BONUS:0 \"Transfers from traders downstream: $VAL$\"",
    },
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


def _display_path(path: Path) -> str:
    """Keep workspace paths short while preserving an external source path."""
    try:
        return _relative(path)
    except ValueError:
        return str(path)


def _range_record(
    pe: PE,
    rows: list[dict],
    begin: int,
    end: int,
    name: str,
    *,
    require_boundary: bool = False,
) -> dict:
    raw = pe.bytes_at(begin, end - begin)
    pdata = pe.function(begin)
    if pdata is None:
        raise AssertionError(f"{name} must be covered by pdata: {pdata}")
    if require_boundary and pdata[0] != begin:
        raise AssertionError(f"{name} must begin at its pdata function boundary: {pdata}")
    return {
        "name": name,
        "rva_exclusive": [hex(begin), hex(end)],
        "va_exclusive": [hex(IMAGE_BASE + begin), hex(IMAGE_BASE + end)],
        "byte_length": len(raw),
        "raw_range_sha256": _sha256_bytes(raw),
        "pdata_function_boundary": [hex(pdata[0]), hex(pdata[1])],
        "pdata_unwind_rva": hex(pdata[2]),
        "decoded_instruction_count": len(rows),
        "address_semantics": "RVA; VA=image_base_va+RVA; end is exclusive",
    }


def _selected(rows: list[dict], addresses: tuple[int, ...], name: str) -> list[dict]:
    by_rva = {int(row["rva"], 16): row for row in rows}
    missing = [hex(address) for address in addresses if address not in by_rva]
    if missing:
        raise AssertionError(f"decoder did not return {name}: {missing}")
    return [by_rva[address] for address in addresses]


def _localization_evidence(path: Path) -> dict:
    wanted = {23, 24, 149}
    lines: dict[str, dict] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        for number, line in enumerate(stream, 1):
            if number not in wanted:
                continue
            raw = line.rstrip("\r\n")
            lines[str(number)] = {
                "line": number,
                "text": raw,
                "bytes_hex": raw.encode("utf-8").hex(),
                "sha256": _sha256_bytes(raw.encode("utf-8")),
            }
    if set(lines) != {"23", "24", "149"}:
        raise AssertionError(f"missing localization lines: {sorted(lines)}")
    return {
        "path": str(path),
        "sha256": _sha256_path(path),
        "encoding": "utf-8-sig text; line hashes cover the exact text without the line ending",
        "lines": lines,
    }


def build_report() -> dict:
    exe = Path(game_exe())
    pe = PE(exe)
    exe_sha = _sha256_bytes(pe.data)
    if exe_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"unsupported game binary SHA-256: {exe_sha}")
    if pe.base != IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.base:#x}")

    helper_boundary = pe.function(HELPER_RVA)
    if helper_boundary is None or helper_boundary[0] != HELPER_RVA:
        raise AssertionError(f"helper pdata boundary is not rooted at {HELPER_RVA:#x}: {helper_boundary}")
    helper_begin, helper_end, _ = helper_boundary
    if helper_end <= helper_begin or helper_end - helper_begin > MAX_SINGLE_RANGE:
        raise AssertionError(f"helper range exceeds bound: {helper_boundary}")

    for name, (begin, end) in ROW_WINDOWS.items():
        if end <= begin or end - begin > MAX_SINGLE_RANGE:
            raise AssertionError(f"row range exceeds bound: {name}")
        if not pe.executable(begin) or not pe.executable(end - 1):
            raise AssertionError(f"row range is not executable: {name}")
        if pe.function(begin) is None or pe.function(end - 1) is None:
            raise AssertionError(f"row range lacks pdata: {name}")

    md, capstone = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    helper_rows = _decode_range(pe, md, helper_begin, helper_end)
    row_rows = {
        name: _decode_range(pe, md, begin, end)
        for name, (begin, end) in ROW_WINDOWS.items()
    }
    decoded_bytes = (helper_end - helper_begin) + sum(end - begin for begin, end in ROW_WINDOWS.values())
    if decoded_bytes > MAX_TOTAL_DECODE:
        raise AssertionError(f"total decode limit exceeded: {decoded_bytes}")

    helper_selected = _selected(helper_rows, HELPER_SELECTED_RVAS, "helper_formatter")
    row_selected = {
        name: _selected(rows, ROW_SELECTED_RVAS[name], name)
        for name, rows in row_rows.items()
    }

    localization_path = exe.parent / "localisation" / "tradenodes_l_english.yml"
    localization = _localization_evidence(localization_path)
    prior_report = STAGE / "power-sources-source-001.json"

    report = {
        "schema": "information.trade_power.sources_static.v2",
        "report_id": "information-trade-power-sources-source-002",
        "batch": 45,
        "stage": "information-trade-share-20261027-001",
        "generated_on": "2026-10-27",
        "status": "partial_static_fixedpoint_rows",
        "scope": {
            "topic_id": "T04",
            "fields": ["sources"],
            "object": "trade_node",
            "question": "Close the source/formatter contract for province, light-ship, and downstream trade-power rows while retaining capital/list/multiplier gaps separately.",
            "mode": "ordinary bounded PE plus disk localization",
            "no_game": True,
            "no_runtime_access": True,
            "no_rea": True,
            "no_production_changes": True,
            "single_decode_limit_bytes": MAX_SINGLE_RANGE,
            "total_decode_limit_bytes": MAX_TOTAL_DECODE,
        },
        "target": {
            "game_version": "1.37.4",
            "exe_path": str(exe),
            "exe_sha256": exe_sha,
            "image_base_va": hex(IMAGE_BASE),
            "address_rule": "RVA and VA are separate; VA=image_base_va+RVA; all ranges are half-open",
        },
        "input_evidence": [
            {
                "path": _relative(prior_report),
                "sha256": _sha256_path(prior_report),
                "role": "Batch-45 source-001 bounded B577 source/ABI report; retained unchanged",
                "evidence_kind": "prior_ordinary_static_report",
            },
            {
                "path": _display_path(localization_path),
                "sha256": localization["sha256"],
                "role": "English disk localization for native labels and row use",
                "evidence_kind": "disk_localization",
                "selected_lines": [23, 24, 149],
            },
        ],
        "decoded_code_ranges": [
            _range_record(
                pe,
                helper_rows,
                helper_begin,
                helper_end,
                "helper_14bc950_full_pdata_function",
                require_boundary=True,
            ),
            *[
                _range_record(pe, row_rows[name], begin, end, f"{name}_direct_rowcall")
                for name, (begin, end) in ROW_WINDOWS.items()
            ],
        ],
        "decoder": {
            "name": "capstone " + capstone.__version__ if capstone is not None else "bounded objdump -d -w -Mintel",
            "decoded_bytes": decoded_bytes,
            "decoded_instruction_count": len(helper_rows) + sum(len(rows) for rows in row_rows.values()),
            "selected_instruction_groups": ["helper_formatter", *ROW_WINDOWS],
        },
        "localization": localization,
        "selected_instructions": {
            "helper_formatter": helper_selected,
            "direct_rowcalls": row_selected,
        },
        "helper_contract": {
            "rva": hex(HELPER_RVA),
            "pdata_boundary": [hex(helper_begin), hex(helper_end)],
            "observed_arguments": {
                "rcx": "caller supplies the destination string object address",
                "rdx": "caller supplies a pointer to the temporary raw DWORD; helper dereferences DWORD [rdx]",
                "r8d": "signed formatter kind; helper sign-extends it to R12D and all three rows pass kind=1",
                "r9b": "format/language selection flag; helper reads it at RVA 0x14bccda and all three rows pass 1",
            },
            "signed32_evidence": [
                "RVA 0x14bca04 loads exactly DWORD [rdi] into EAX, with no wider source value.",
                "RVA 0x14bca2b tests EAX for sign and RVA 0x14bca36 negates the 32-bit value; RVA 0x14bca39 uses CMOVNS to retain the original nonnegative value.",
                "The arithmetic remains in EAX/R14D/R15D and the formatter receives the signed-derived integer/fraction components.",
            ],
            "fixedpoint_1000_evidence": [
                "RVA 0x14bca4b loads reciprocal constant 0x10624dd3; the following signed multiply/shift path forms the integer quotient of the nonnegative magnitude by 1000.",
                "RVA 0x14bca86 multiplies the quotient by 0x3e8 and RVA 0x14bca8d subtracts it from the magnitude to obtain the remainder.",
                "RVA 0x14bca90 adds 0x3e8 to the remainder before the second formatter call at 0x14bca9a, then RVA 0x14bca9f writes the decimal point.",
                "Thus this helper formats the pointed signed DWORD as a three-decimal fixed-point value raw/1000; it does not introduce a separate cache conversion.",
            ],
            "kind_scope": "kind=1 enters the positive-kind fractional path.  The exact public name of the kind enum is unresolved, but it is identical for all three requested rows.",
            "display_scope": "R9B=1 is observed on all three calls; its visible helper use selects formatting/language state, not the raw cache field or the 1000 arithmetic.",
        },
        "rows": {
            label: {
                **contract,
                "native_key": label,
                "localization": {
                    "path": _display_path(localization_path),
                    "line": contract["localization_line"],
                    "text": localization["lines"][str(contract["localization_line"])]["text"],
                    "role": "native UI row label/use evidence; not a runtime value sample",
                },
                "direct_call_arguments": {
                    "rcx": "destination string object address",
                    "rdx": "address of the stored raw DWORD at [rbp+0xc0]",
                    "r8d": 1,
                    "r9b": 1,
                    "helper_rva": hex(HELPER_RVA),
                    "builder_rva": contract["builder_rva"],
                },
                "raw_semantics": "signed 32-bit cache DWORD copied unchanged into the helper input slot",
                "unit": "trade_power points (source-row semantic; not ducats/trade value)",
                "scale": 1000,
                "display_formula": "display_value = signed_i32(raw) / 1000",
                "reader_disposition": "safe partial row: expose raw/raw_hex and display_value only when the native row condition is true; omit the row when the condition is false",
                "evidence_kind": "ordinary static disassembly corroborated by disk localization",
            }
            for label, contract in ROW_CONTRACTS.items()
        },
        "breakdown": {
            "closed_rows": [
                "TP_PROVINCE_POWER: entry+0x28, nonzero signed i32, trade-power source, fixed scale 1000",
                "TP_SHIP_POWER: entry+0x1c, nonzero signed i32, trade-power source, fixed scale 1000",
                "MERCHANT_DOWNSTREAM_BONUS: entry+0x40, positive signed i32, downstream trade-power source, fixed scale 1000",
            ],
            "partial_reader_shape": {
                "native_key": "one of the three exact keys",
                "entry_offset": "0x1c/0x28/0x40 as specified per key",
                "raw": "signed int32 loaded from the entry",
                "raw_hex": "the two's-complement 32-bit encoding of raw",
                "condition": "apply the per-row nonzero or >0 guard before publishing a row",
                "value": "raw / 1000.0 trade_power points",
                "period_and_freshness": "unknown; this static report does not prove refresh timing",
            },
            "separate_gaps": {
                "TRADE_POWER_CAPITAL": "retained from source-001; global scalar and identity condition are known, but its runtime value/refresh and unit scale are not closed by this helper",
                "dynamic_entry_0x90_list": "retained from source-001; item value/name shape is known, but runtime count, ownership, and row semantics remain unknown",
                "TRADE_MULTI_EXPLA": "retained from source-001; scalar getter/vector relationship and visible formatter path remain separate from these three direct cache rows",
            },
        },
        "unknowns": [
            "The C++ enum name represented by helper R8D kind=1 is unresolved; only its observed call value and branch behavior are closed.",
            "The row builder contract and cache update/refresh producer are outside these bounded windows.",
            "Runtime freshness, per-node availability, and the current value of each entry field are not claimed by this static report.",
            "Capital, dynamic list, and multiplier rows are not promoted by the three-row helper proof.",
        ],
        "verification": {
            "script": _relative(Path(__file__)),
            "all_shell_work_completed": True,
            "game_access": False,
            "rpm_used": False,
            "rea_access": False,
            "production_written": False,
            "previous_source_001_untouched": True,
            "resource_limits": {
                "helper_function_bytes": helper_end - helper_begin,
                "direct_row_window_bytes": {name: end - begin for name, (begin, end) in ROW_WINDOWS.items()},
                "total_decode_bytes": decoded_bytes,
                "single_window_limit_bytes": MAX_SINGLE_RANGE,
                "total_decode_limit_bytes": MAX_TOTAL_DECODE,
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
        "helper_bytes": report["verification"]["resource_limits"]["helper_function_bytes"],
        "row_window_bytes": report["verification"]["resource_limits"]["direct_row_window_bytes"],
        "decoded_bytes": report["decoder"]["decoded_bytes"],
        "decoded_instruction_count": report["decoder"]["decoded_instruction_count"],
        "decoder": report["decoder"]["name"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
