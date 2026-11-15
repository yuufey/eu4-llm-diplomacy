"""Produce the bounded Batch-45 trade-power source breakdown.

This report decodes only the already identified B57700..B58354 function in
the pinned EU4 PE.  It records the register/offset relationships visible in
that window and keeps helper contracts, native type names, and runtime values
unknown when the window cannot prove them.  It does not open the game, use
RPM/REA, or modify production code/profile data.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work" / "runtime" / "information-trade-share-20261027-001"
OUTPUT = STAGE / "power-sources-source-001.json"
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE, make_disassembler  # noqa: E402
from work.local_config import game_exe  # noqa: E402
from work.research_information_branch_inputs import _decode_range  # noqa: E402


EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = 0x140000000
FUNCTION_BEGIN = 0xB57700
FUNCTION_END = 0xB58354
CALLER_BEGIN = 0x101EDC0
CALLER_END = 0x101EE05
MAX_SINGLE_RANGE = 8 * 1024
MAX_TOTAL_DECODE = 24 * 1024

LABEL_RVAS = {
    "TP_PROVINCE_POWER": 0x1CE8BA8,
    "TP_SHIP_POWER": 0x1CE8B28,
    "TRADE_POWER_CAPITAL": 0x1CE8B38,
    "MERCHANT_DOWNSTREAM_BONUS": 0x1CE8B50,
    "TRADE_MULTI_EXPLA": 0x1CE8B70,
}

SELECTED_RVAS = {
    "incoming_abi_and_entry_selection": (
        0xB57721, 0xB57724, 0xB57749, 0xB5774D, 0xB57750,
        0xB57754, 0xB57758, 0xB5775C, 0xB57760, 0xB57763,
    ),
    "province_row": (
        0xB57775, 0xB5777D, 0xB57788, 0xB5778B, 0xB5778F,
        0xB57796, 0xB577A0, 0xB577A6,
    ),
    "ship_row": (
        0xB5787A, 0xB5787D, 0xB57881, 0xB57885, 0xB5788D,
        0xB57890, 0xB57896, 0xB578A1, 0xB578AC, 0xB578AF,
        0xB578B5, 0xB578C7, 0xB578D1,
    ),
    "selected_vector_and_capital": (
        0xB579A3, 0xB579AA, 0xB579B2, 0xB579B9, 0xB579C0,
        0xB579C4, 0xB579CB, 0xB579D2, 0xB579D8, 0xB579DE,
        0xB579E4, 0xB579E9, 0xB579F2, 0xB57A03, 0xB57A0D,
    ),
    "linked_source_list": (
        0xB57B5E, 0xB57B6C, 0xB57B75, 0xB57B80, 0xB57B83,
        0xB57B91, 0xB57B94, 0xB57B9A, 0xB57BA1, 0xB57BCF,
        0xB57BD2, 0xB57BE0, 0xB57C00, 0xB57C03, 0xB57C08,
        0xB57E32, 0xB57E36, 0xB57E39,
    ),
    "downstream_and_multiplier": (
        0xB57E49, 0xB57E4D, 0xB57E55, 0xB57E62, 0xB57E65,
        0xB57E69, 0xB57E84, 0xB57E8F, 0xB57F55, 0xB57F5C,
        0xB57F63, 0xB57F66, 0xB57F69, 0xB57F70, 0xB57F74,
        0xB57F79, 0xB57F7B, 0xB57F86, 0xB57F8B, 0xB57F92,
        0xB57F99, 0xB57FA6, 0xB57FAA, 0xB57FB7, 0xB57FC4,
        0xB58099,
    ),
    "r9_roles_and_return": (
        0xB57788, 0xB578AC, 0xB579E9, 0xB57B91, 0xB57F63,
        0xB57FB2, 0xB57FB7, 0xB581B4, 0xB58297, 0xB582EE,
    ),
}

CALLER_SELECTED_RVAS = {
    "direct_b577_caller_fullref": (
        0x101EDE0, 0x101EDE4, 0x101EDE8, 0x101EDEC, 0x101EDF0,
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


def _c_string(pe: PE, rva: int) -> tuple[str, bytes]:
    raw = bytearray()
    for offset in range(256):
        byte = pe.bytes_at(rva + offset, 1)
        if not byte:
            break
        raw.extend(byte)
        if byte == b"\0":
            break
    value = bytes(raw).split(b"\0", 1)[0].decode("ascii")
    return value, bytes(raw)


def _range_record(pe: PE, rows: list[dict], begin: int, end: int, name: str) -> dict:
    raw = pe.bytes_at(begin, end - begin)
    pdata = pe.function(begin)
    return {
        "name": name,
        "rva_exclusive": [hex(begin), hex(end)],
        "va_exclusive": [hex(IMAGE_BASE + begin), hex(IMAGE_BASE + end)],
        "byte_length": len(raw),
        "raw_range_sha256": _sha256_bytes(raw),
        "pdata_function_boundary": [hex(pdata[0]), hex(pdata[1])] if pdata else None,
        "pdata_unwind_rva": hex(pdata[2]) if pdata else None,
        "decoded_instruction_count": len(rows),
        "address_semantics": "RVA; VA=image_base_va+RVA; end is exclusive",
    }


def _selected(rows: list[dict]) -> dict[str, list[dict]]:
    by_rva = {int(row["rva"], 16): row for row in rows}
    result: dict[str, list[dict]] = {}
    for name, addresses in SELECTED_RVAS.items():
        missing = [hex(address) for address in addresses if address not in by_rva]
        if missing:
            raise AssertionError(f"decoder did not return {name}: {missing}")
        result[name] = [by_rva[address] for address in addresses]
    return result


def _selected_from(rows: list[dict], groups: dict[str, tuple[int, ...]]) -> dict[str, list[dict]]:
    by_rva = {int(row["rva"], 16): row for row in rows}
    result: dict[str, list[dict]] = {}
    for name, addresses in groups.items():
        missing = [hex(address) for address in addresses if address not in by_rva]
        if missing:
            raise AssertionError(f"decoder did not return {name}: {missing}")
        result[name] = [by_rva[address] for address in addresses]
    return result


def _prior(path: Path, role: str) -> dict:
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
    for begin, end, label in (
        (FUNCTION_BEGIN, FUNCTION_END, "trade_power_sources_builder"),
        (CALLER_BEGIN, CALLER_END, "direct_b577_caller"),
    ):
        if end - begin > MAX_SINGLE_RANGE:
            raise AssertionError(f"single decode range exceeds limit: {label}")
        if not pe.executable(begin) or not pe.executable(end - 1):
            raise AssertionError(f"range is not executable: {label}")

    md, capstone = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    rows = _decode_range(pe, md, FUNCTION_BEGIN, FUNCTION_END)
    caller_rows = _decode_range(pe, md, CALLER_BEGIN, CALLER_END)
    decoded_bytes = (FUNCTION_END - FUNCTION_BEGIN) + (CALLER_END - CALLER_BEGIN)
    if decoded_bytes > MAX_TOTAL_DECODE:
        raise AssertionError("total decode limit exceeded")
    selected = _selected(rows)
    selected.update(_selected_from(caller_rows, CALLER_SELECTED_RVAS))

    labels = {}
    for label, rva in LABEL_RVAS.items():
        value, raw = _c_string(pe, rva)
        if value != label:
            raise AssertionError(f"label guard changed at {rva:#x}: {value!r}")
        labels[label] = {
            "rva": hex(rva),
            "va": hex(IMAGE_BASE + rva),
            "text": value,
            "bytes_hex": raw.hex(),
            "bytes_sha256": _sha256_bytes(raw),
        }

    old_stage = ROOT / "work" / "runtime" / "information-trade-state-20261027-001"
    prior = [
        _prior(
            old_stage / "trade-power-source-001.json",
            "Batch-43 B57700 source report being refined here",
        ),
        _prior(
            old_stage / "trade-power-source-002.json",
            "Batch-43 current-power corroboration; retained as separate prior evidence",
        ),
        _prior(
            old_stage / "research_trade_power_source.py",
            "prior bounded decoder and range declaration",
        ),
    ]

    report = {
        "schema": "information.trade_power.sources_static.v1",
        "report_id": "information-trade-power-sources-source-001",
        "batch": 45,
        "stage": "information-trade-share-20261027-001",
        "generated_on": "2026-10-27",
        "status": "partial_static_sources_contract",
        "scope": {
            "topic_id": "T04",
            "fields": ["sources"],
            "object": "trade_node",
            "question": "Close the five B57700 source labels, their register inputs, scalar/vector/list relations, conditions, and visible arithmetic without claiming an unobserved runtime source schema.",
            "mode": "ordinary bounded PE analysis",
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
        "input_evidence": prior,
        "decoded_code_ranges": [
            _range_record(pe, rows, FUNCTION_BEGIN, FUNCTION_END, "trade_power_sources_builder"),
            _range_record(pe, caller_rows, CALLER_BEGIN, CALLER_END, "direct_b577_caller"),
        ],
        "decoder": {
            "name": "capstone " + capstone.__version__ if capstone is not None else "bounded objdump -d -w -Mintel",
            "decoded_bytes": decoded_bytes,
            "decoded_instruction_count": len(rows) + len(caller_rows),
            "selected_instruction_groups": list(selected),
        },
        "string_guards": labels,
        "selected_instructions": selected,
        "findings": {
            "incoming_abi": {
                "rcx": {
                    "observed": [
                        "RCX is copied to R12 at RVA 0xb57724 and the qword at [RCX+0x18] is used as the entry-table base.",
                        "The original RCX/R12 is forwarded to helper calls at 0xb57afa and 0xb57b56.",
                    ],
                    "contract": "node-like object with an entry-table pointer at +0x18",
                    "native_type": "unknown; this window does not identify a C++ class or country/province domain",
                },
                "r8": {
                    "observed": [
                        "R8 is copied unchanged to RBX at RVA 0xb57721.",
                        "slot_i16=sign_extend_i16((R8>>32)&0xffff) is formed at 0xb57750..0xb57758.",
                        "entry=[RCX+0x18]+slot_i16*0xc0 is formed at 0xb5774d..0xb57760.",
                        "The complete R8/RBX value is forwarded as R8 to helper calls at 0xb57af0 and 0xb57b4c.",
                        "The bounded direct caller window loads R8 from [RDI+0x58], then [R8+0x20], and calls B57700 at 0x101edf0; this closes the immediate source as a wrapper +0x20 packed fullref candidate.",
                    ],
                    "contract": "packed fullref/selector; the direct caller supplies wrapper+0x20, and the high signed16 selects the 0xc0 entry",
                    "low_32_semantics": "opaque in this window; preserved and forwarded, not independently decoded",
                    "stride": "0xc0 bytes",
                    "selector_signed": True,
                },
                "r9": {
                    "observed": [
                        "No read of the incoming R9 occurs before R9 is overwritten by r9b=1 or r9d=0 in the bounded function.",
                        "Internal source-row formatter calls synthesize R9=1; the scalar getter call at 0xb57f74 synthesizes R9=0.",
                    ],
                    "contract": "incoming R9 ignored or semantically dead in this function; its caller meaning is unresolved",
                },
                "rdx": {
                    "observed": "Incoming RDX is saved at [rsp+0x10], but its native output/detail type is not resolved by this window.",
                },
            },
            "entry_scalar_rows": {
                "TP_PROVINCE_POWER": {
                    "label": labels["TP_PROVINCE_POWER"],
                    "unit": "trade_power source value; numeric scale unresolved",
                    "raw_source": "DWORD [entry+0x28]",
                    "entry_offset": "0x28",
                    "condition": "include only when the loaded DWORD is nonzero (test eax,eax; je 0xb5787a)",
                    "conversion": "copied to the local value slot, then passed through helper 0x1414bc950 and row builder 0x14008ecd0",
                    "scale": "unresolved in B57700..B58354; no numeric conversion is visible before the helper",
                    "signedness": "unresolved; only zero/nonzero is tested in this window",
                },
                "TP_SHIP_POWER": {
                    "label": labels["TP_SHIP_POWER"],
                    "unit": "trade_power source value; numeric scale unresolved",
                    "raw_source": "DWORD [entry+0x1c]",
                    "entry_offset": "0x1c",
                    "condition": "include only when the loaded DWORD is nonzero (test ecx,ecx; je 0xb579a3)",
                    "conversion": "copied to the local value slot, then passed through helper 0x1414bc950 and row builder 0x14008ecd0",
                    "scale": "unresolved in B57700..B58354; no numeric conversion is visible before the helper",
                    "signedness": "unresolved; only zero/nonzero is tested in this window",
                },
                "TRADE_POWER_CAPITAL": {
                    "label": labels["TRADE_POWER_CAPITAL"],
                    "unit": "trade_power source value; numeric scale unresolved",
                    "raw_source": "DWORD [VA 0x14233f2f0 / RVA 0x233f2f0]",
                    "condition": "include only when selected_vector[slot]+0x14c8 points to an object whose +0xe8 equals the input RCX node",
                    "conversion": "loaded to the local value slot and passed through helper 0x1414bc950 and row builder 0x14008ecd0",
                    "scale": "unresolved; the BSS/global scalar has no file-backed numeric value in this static window",
                    "signedness": "unresolved; loaded with MOV EAX,DWORD",
                },
                "MERCHANT_DOWNSTREAM_BONUS": {
                    "label": labels["MERCHANT_DOWNSTREAM_BONUS"],
                    "unit": "trade_power source value; numeric scale unresolved",
                    "raw_source": "DWORD [entry+0x40]",
                    "entry_offset": "0x40",
                    "condition": "include only when signed DWORD [entry+0x40] is greater than zero (test eax,eax; jle 0xb57f55)",
                    "conversion": "passed to helper 0x1414bc950 and row builder 0x14008ecd0",
                    "scale": "unresolved in B57700..B58354; no direct unit conversion is visible for this row",
                    "signedness": "signed for the jle condition; the displayed value's semantic unit remains unresolved",
                },
            },
            "trade_multi_expla": {
                "label": labels["TRADE_MULTI_EXPLA"],
                "unit": "trade multiplier explanation value; semantic base unit unresolved",
                "condition": "the same signed [entry+0x40] > 0 guard gates this block",
                "scalar_getter": {
                    "call_va": hex(IMAGE_BASE + 0x382E70),
                    "call_rva": "0x382e70",
                    "rcx": "selected_vector[slot]",
                    "rdx": "&local_value_slot",
                    "r8": "input node RCX/R12",
                    "r9": "0",
                    "return_use": "DWORD [RAX] is copied to EBX",
                },
                "visible_math": [
                    "adjusted_i32 = i32(raw_i32 + 1000)",
                    "adjusted_i32 = max_signed(adjusted_i32, 10)",
                    "sign and absolute value are prepared in R15D",
                    "magic multiply 0x10624dd3 followed by signed shift 6 derives the /1000 decimal quotient",
                    "remainder = abs(adjusted_i32) - quotient*1000; remainder+1000 is sent to the fractional formatter",
                ],
                "format_calls": [
                    {"rva": "0x17061a0", "role": "integer/fractional decimal formatter"},
                    {"rva": "0x8edc0", "role": "TRADE_MULTI_EXPLA row builder"},
                ],
                "scale": "the visible decimal path uses 1000 arithmetic; underlying multiplier unit and runtime source freshness remain unresolved",
            },
            "selected_vector_and_scalar_cache": {
                "global": {
                    "va": "0x14233d8b0",
                    "rva": "0x233d8b0",
                    "expression": "QWORD [global] -> QWORD [+0x118]",
                    "role": "base of a slot-indexed pointer vector/list candidate",
                },
                "index": "signed selector slot from R8, multiplied by 8",
                "selected_object": "[vector_base + slot*8]",
                "identity_check": "QWORD [[selected_object+0x14c8]+0xe8] == input RCX node",
                "uses": ["TRADE_POWER_CAPITAL inclusion", "TRADE_MULTI_EXPLA scalar getter RCX"],
                "container_type": "vector/list shape observed; element type and ownership unknown",
            },
            "linked_source_list": {
                "head": "QWORD [entry+0x90]",
                "link_shape": "for link p: item=QWORD [p], next=QWORD [p+0x10]; loop until p==0",
                "item_fields": {
                    "value": "DWORD [item+0x34]",
                    "name": "std::string-like object at item+0x10; length/capacity are read at relative +0x18/+0x20 with inline threshold 0x10",
                },
                "row_path": "item value is formatted with helper 0x1414bc950 (kind=2), item name is combined by 0x1414b33a0, and the pair is appended through 0x1400e3b80",
                "fixed_label": "none in this window; these are dynamic linked-list detail rows",
                "runtime_count": "unknown; no runtime list capture in this static-only batch",
            },
            "return_and_unmapped_tail": {
                "return": "RAX receives QWORD [RBP+0xc8] at 0xb582ee; the native return object is unresolved",
                "tail": "optional tail processing calls 0xb5def0 with the selected entry and local string state; no requested label is tied to it within this window",
            },
        },
        "implemented_breakdown": {
            "source_row_schema": {
                "fixed_rows": [
                    {"label": "TP_PROVINCE_POWER", "raw": "entry+0x28", "condition": "nonzero"},
                    {"label": "TP_SHIP_POWER", "raw": "entry+0x1c", "condition": "nonzero"},
                    {"label": "TRADE_POWER_CAPITAL", "raw": "global+0x233f2f0 DWORD", "condition": "selected-object identity matches node"},
                    {"label": "MERCHANT_DOWNSTREAM_BONUS", "raw": "entry+0x40", "condition": ">0 signed"},
                    {"label": "TRADE_MULTI_EXPLA", "raw": "scalar_getter(selected_object,node)", "condition": "entry+0x40 > 0"},
                ],
                "dynamic_rows": {
                    "raw": "entry+0x90 linked-list item+0x34",
                    "name": "item+0x10 string",
                    "next": "link+0x10",
                    "count": "unknown until runtime observation",
                },
                "selector": "R8 high signed16 -> entry index; full R8 forwarded as opaque fullref/selector",
                "unit": "trade_power for the four raw source rows; trade_multiplier for TRADE_MULTI_EXPLA; per-row numeric scale is not closed by this window",
            },
            "production_readiness": {
                "fixed_raw_sources_closed": True,
                "conditions_closed": True,
                "vector_and_list_shape_closed": True,
                "per_row_unit_scale_closed": False,
                "runtime_row_count_and_values_closed": False,
                "native_type_and_fullref_low32_closed": False,
                "safe_next_step": "A bounded reader may expose raw fixed rows and dynamic list candidates only with separate unknown status and runtime guards; do not publish a normalized source amount or competitor share from these static findings alone.",
            },
        },
        "unknowns": [
            "Exact native C++ type and domain of RCX node object.",
            "Whether R8 low32 is a country identity, generation, or another packed selector field; only high signed16 is consumed here.",
            "Incoming R9 caller contract; B57700 overwrites it before any read.",
            "Semantic units/scale and signedness of province, ship, capital, and downstream raw DWORDs after helper formatting.",
            "Runtime value and freshness of global RVA 0x233f2f0 scalar.",
            "Element type/ownership/count and label semantics of the entry+0x90 linked list.",
            "Exact contracts of helper calls 0x14bc950, 0x8ecd0, 0x382e70, 0x14bbd90, 0x14b33a0, 0xe3b80, 0xb54070, 0xb53920, and 0xb5def0; they were not decoded in this batch.",
            "Whether this source breakdown is refreshed with the same schedule as the current-power/total-power caches.",
        ],
        "verification": {
            "script": _relative(Path(__file__)),
            "all_shell_work_completed": True,
            "game_access": False,
            "rpm_used": False,
            "rea_access": False,
            "production_written": False,
            "resource_limits": {
                "single_window_bytes": FUNCTION_END - FUNCTION_BEGIN,
                "caller_window_bytes": CALLER_END - CALLER_BEGIN,
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
        "range_bytes": FUNCTION_END - FUNCTION_BEGIN,
        "caller_range_bytes": CALLER_END - CALLER_BEGIN,
        "decoded_instruction_count": report["decoder"]["decoded_instruction_count"],
        "decoder": report["decoder"]["name"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
