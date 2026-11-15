"""Batch-46 follow-up: bounded callee contracts for trade source details.

This report keeps source-modifiers-001.json unchanged.  It decodes only the
three small callees requested for the second pass and the already bounded
B57700 CFG window/function needed to correct the guard interpretation.  It
does not attach to or execute the game, use RPM/REA, or change production code.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import deque
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work" / "runtime" / "information-trade-source-details-20261027-001"
OUTPUT = STAGE / "source-modifiers-002.json"
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE, make_disassembler  # noqa: E402
from work.local_config import game_exe  # noqa: E402
from work.research_information_branch_inputs import _decode_range  # noqa: E402


EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
IMAGE_BASE = 0x140000000
MAX_SINGLE_DECODE = 8 * 1024
MAX_TOTAL_DECODE = 16 * 1024

FUNCTIONS = {
    "b57700_source_builder_cfg": (0xB57700, 0xB58354),
    "b5dcd0_detail_element_builder": (0xB5DCD0, 0xB5DEEC),
    "2892d0_key_country_resolver": (0x2892D0, 0x28935D),
    "1f4700_to_from_formatter": (0x1F4700, 0x1F4841),
    "382dd0_factor_cache_getter": (0x382DD0, 0x382E6A),
    "2f2640_native_tail_accumulator": (0x2F2640, 0x2F2997),
}

CFG_SELECTED = (
    0xB57763, 0xB57777, 0xB5787A, 0xB57E49, 0xB57E4D, 0xB57E4F,
    0xB57E55, 0xB57F42, 0xB57F4B, 0xB57F55, 0xB57F74, 0xB57F79,
    0xB57F7B, 0xB57F81, 0xB57F86, 0xB57F88, 0xB57FAA, 0xB57FAF,
    0xB57FC4, 0xB58099, 0xB580A4, 0xB581BB,
)


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


def _with_va(rows: list[dict]) -> list[dict]:
    result = []
    for row in rows:
        item = dict(row)
        item["va"] = hex(IMAGE_BASE + int(row["rva"], 16))
        result.append(item)
    return result


def _selected(rows: list[dict], addresses: tuple[int, ...]) -> list[dict]:
    by_rva = {int(row["rva"], 16): row for row in rows}
    missing = [hex(address) for address in addresses if address not in by_rva]
    if missing:
        raise AssertionError(f"missing CFG instruction records: {missing}")
    return _with_va([by_rva[address] for address in addresses])


def _range_record(pe: PE, rows: list[dict], begin: int, end: int, name: str) -> dict:
    pdata = pe.function(begin)
    raw = pe.bytes_at(begin, end - begin)
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


def _prior(path: Path, role: str) -> dict:
    if not path.exists():
        return {"path": _relative(path), "role": role, "missing": True}
    return {
        "path": _relative(path),
        "sha256": _sha256_path(path),
        "role": role,
        "evidence_kind": "prior_ordinary_static_report",
    }


def _branch_target(row: dict) -> int | None:
    match = re.search(r"0x([0-9a-fA-F]+)$", row.get("operands", ""))
    return int(match.group(1), 16) - IMAGE_BASE if match else None


def _cfg_edges(rows: list[dict]) -> dict[int, set[int]]:
    addresses = [int(row["rva"], 16) for row in rows]
    edges = {address: set() for address in addresses}
    for index, address in enumerate(addresses):
        mnemonic = rows[index]["mnemonic"]
        next_address = addresses[index + 1] if index + 1 < len(addresses) else None
        target = _branch_target(rows[index])
        if mnemonic == "jmp":
            if target is not None:
                edges[address].add(target)
        elif mnemonic.startswith("j"):
            if target is not None:
                edges[address].add(target)
            if next_address is not None:
                edges[address].add(next_address)
        elif mnemonic in {"ret", "int3"}:
            continue
        elif next_address is not None:
            # Calls return to the next instruction for this static reachability
            # check; their native callee semantics are recorded separately.
            edges[address].add(next_address)
    return edges


def _reachable(edges: dict[int, set[int]], start: int, goal: int) -> dict:
    queue = deque([start])
    previous: dict[int, int | None] = {start: None}
    while queue:
        current = queue.popleft()
        if current == goal:
            path = []
            cursor: int | None = current
            while cursor is not None:
                path.append(cursor)
                cursor = previous[cursor]
            path.reverse()
            return {"reachable": True, "path_length": len(path), "path_prefix_rva": [hex(x) for x in path[:16]]}
        for target in edges.get(current, ()):
            if target in edges and target not in previous:
                previous[target] = current
                queue.append(target)
    return {"reachable": False, "path_length": None, "path_prefix_rva": []}


def _literal(pe: PE, rva: int, size: int, text: str) -> dict:
    raw = pe.bytes_at(rva, size)
    return {
        "rva": hex(rva),
        "va": hex(IMAGE_BASE + rva),
        "byte_length": len(raw),
        "bytes_hex": raw.hex(),
        "sha256": _sha256_bytes(raw),
        "text": text,
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

    cfg_rows = decoded["b57700_source_builder_cfg"]
    cfg = _cfg_edges(cfg_rows)
    entry28_skip = _reachable(cfg, 0xB5787A, 0xB57F55)
    entry40_nonpositive = _reachable(cfg, 0xB57F55, 0xB57F55)
    entry40_positive = _reachable(cfg, 0xB57E55, 0xB57F55)

    prior = STAGE / "source-modifiers-001.json"
    report = {
        "schema": "information.trade_source_modifiers_static.v2",
        "report_id": "information-trade-source-modifiers-002",
        "batch": 46,
        "stage": "information-trade-source-details-20261027-001",
        "generated_on": "2026-10-27",
        "status": "partial_static_detail_and_native_tail_contracts",
        "scope": {
            "topic_id": "T04",
            "fields": ["sources", "TRADE_MULTI_EXPLA", "native_tail"],
            "object": "trade_node",
            "question": "Close B5DCD0 details and the small 382DD0/2F2640 callees, while correcting B57700 CFG guard scope.",
            "mode": "ordinary bounded PE only; source-modifiers-001 retained unchanged",
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
            _prior(prior, "Batch-46 source-modifiers-001 retained unchanged"),
            _prior(ROOT / "work/runtime/information-trade-share-20261027-001/share-source-001.json", "Batch-45 B57700 source-builder context"),
        ],
        "decoded_code_ranges": ranges,
        "decoder": {
            "name": "capstone " + capstone.__version__ if capstone is not None else "bounded objdump -d -w -Mintel",
            "decoded_bytes": total,
            "decoded_instruction_count": sum(len(rows) for rows in decoded.values()),
            "full_body_callees": [
                "b5dcd0_detail_element_builder",
                "2892d0_key_country_resolver",
                "1f4700_to_from_formatter",
                "382dd0_factor_cache_getter",
                "2f2640_native_tail_accumulator",
            ],
        },
        "selected_instructions": {
            "b57700_cfg": _selected(cfg_rows, CFG_SELECTED),
            "b5dcd0_full_body": _with_va(decoded["b5dcd0_detail_element_builder"]),
            "2892d0_full_body": _with_va(decoded["2892d0_key_country_resolver"]),
            "1f4700_full_body": _with_va(decoded["1f4700_to_from_formatter"]),
            "382dd0_full_body": _with_va(decoded["382dd0_factor_cache_getter"]),
            "2f2640_full_body": _with_va(decoded["2f2640_native_tail_accumulator"]),
        },
        "cfg_guard_correction": {
            "entry_0x28": {
                "load_rva": "0xb57763",
                "branch_rva": "0xb57777",
                "branch": "JE 0x140b5787a",
                "target_va": "0x140b5787a",
                "target_role": "skip the province-row value/formatter block",
                "reachability_to_multiplier": entry28_skip,
                "conclusion": "entry+0x28 is a province-row guard only. It must not be used as the multiplier-row guard; its skip target still reaches the common multiplier start at B57F55 in this function CFG.",
            },
            "entry_0x40": {
                "load_rva": "0xb57e49",
                "test_rva": "0xb57e4d",
                "branch_rva": "0xb57e4f",
                "branch": "JLE 0x140b57f55",
                "target_va": "0x140b57f55",
                "nonpositive_to_multiplier": entry40_nonpositive,
                "positive_fallthrough_to_multiplier": entry40_positive,
                "positive_path": "fallthrough formats the downstream row at B57E55..B57F50, then reaches B57F55",
                "conclusion": "entry+0x40 controls the downstream-row display only; both <=0 and >0 paths reach B57F55. It is not a guard for the multiplier call.",
            },
            "trade_multi_label": {
                "label_rva": "0x1ce8b70",
                "label_va": "0x141ce8b70",
                "builder_call_rva": "0xb580a4",
                "builder_call_va": "0x140b580a4",
                "direct_flow": "after B57FC4's fixed display call and local string setup, B58099 loads the label and B580A4 calls 0x8EDC0; no conditional branch surrounds this label call in the decoded continuation",
                "scope": "unconditional once the common multiplier continuation is reached; earlier unrelated source-row/cleanup branches can determine whether the function reaches that continuation",
                "not_proven": "this does not establish a runtime cache refresh or a trade_power unit",
            },
        },
        "b5dcd0_contract": {
            "function": {
                "rva_exclusive": ["0xb5dcd0", "0xb5deec"],
                "va_exclusive": ["0x140b5dcd0", "0x140b5deec"],
                "byte_length": 540,
            },
            "abi": {
                "rcx": "unused in this body; B5DEF0 supplies the selected entry but B5DCD0's data input is R8",
                "rdx": "destination string object; initialized empty and returned in RAX",
                "r8": "pointer to a linked detail container; [R8] is the first element pointer",
                "r9": "label/context string object saved as R12; B5DEF0 supplies TRANSFER_TRADE_POWER_TO or _FROM",
            },
            "container_layout": {
                "root": "element = QWORD [R8]; null root returns the empty destination",
                "element_key_or_object": {"offset": "0x00", "expression": "QWORD [element+0x00]", "use": "saved and passed to 0x2892D0 for key/object resolution"},
                "element_raw": {"offset": "0x08", "expression": "signed DWORD [element+0x08]", "use": "absolute-value/sign handling and fixedpoint text formatting"},
                "element_next": {"offset": "0x18", "expression": "QWORD [element+0x18]", "use": "next element; loop repeats while nonzero"},
                "count": "no count is read in this body; enumeration is a next-pointer chain",
            },
            "element_country_fullref": {
                "element_value": "QWORD [element+0x00] is copied to a local QWORD and passed by address to 0x2892D0 with RDX=R8=R9=0",
                "selector": "2892D0 reads high16(QWORD [local]) as signed_i16 slot",
                "country_table": "QWORD [0x14233d8b0]+0x118; country=table[slot]",
                "direct_condition": "if QWORD [country+0x2680] != 0, 2892D0 returns country+0x2690",
                "fallback": "otherwise, with R9=0, 2892D0 calls 0x3c8c00(country) and enters its fallback/shared continuation; the exact returned field is not renamed here",
                "conclusion": "the element key/object is a packed country-fullref carrier for this resolver; its low bits and final display-object field remain unresolved",
            },
            "value_format": {
                "raw": "signed_i32([element+0x08])",
                "formula": "format signed raw/1000 with reciprocal M=0x10624dd3 and the signed correction path after SAR 6",
                "evidence_rvas": ["0xb5dd8e", "0xb5dda8", "0xb5dda9", "0xb5dda4", "0xb5dda8", "0xb5ddc9", "0xb5ddd0"],
                "text_helpers": ["0x17061a0", "0x95110"],
                "unit": "unknown; only fixedpoint text scaling is proven",
            },
            "to_from_binding": {
                "literal_input": "R9 string object data is selected at B5DE1B..B5DE2A (inline versus heap representation)",
                "formatter_call_rva": "0xb5de4d",
                "formatter_call_va": "0x140b5de4d",
                "formatter_callee_rva": "0x1f4700",
                "arguments": {
                    "rcx": "&local destination [RBP+0xf]",
                    "rdx": "TO/FROM label string data from R9",
                    "r8": "static table at RVA 0x1c49730",
                    "r9": "RAX returned by 0x2892D0 from the element +0 key/object",
                    "stack_0x20": "RVA 0x1c329dc literal context",
                    "stack_0x28": "&local accumulator [RBP-0x31]",
                },
                "literal_evidence": {
                    "to": _literal(pe, 0x1CE8E30, len(b"TRANSFER_TRADE_POWER_TO\0"), "TRANSFER_TRADE_POWER_TO"),
                    "from": _literal(pe, 0x1CE8E48, len(b"TRANSFER_TRADE_POWER_FROM\0"), "TRANSFER_TRADE_POWER_FROM"),
                    "separator_context": _literal(pe, 0x1C3299C, 0x20, "\\n\\0\\0\\0_short\\0..."),
                },
                "meaning": "the caller's TO/FROM literal is a real formatter input for each linked element; exact localized grammar is delegated to 0x1F4700 and is not guessed here",
                "formatter_followup": {
                    "abi": "1F4700 saves RCX=destination, RDX=TO/FROM label data, R8=static table, R9=resolved country/key result",
                    "label_use": "1F4700 passes the label data as RDX to 0x14b33a0 with R9D=2, then completes the destination through 0x1a332e4",
                    "direction_semantics": "B5DEF0 pairs entry+0x60 with TRANSFER_TRADE_POWER_TO and entry+0x78 with TRANSFER_TRADE_POWER_FROM; these are explicit transfer directions, not a guessed generic name",
                },
            },
            "conditions": {
                "null_root": "[R8]==0 returns empty output",
                "separator": "when destination length is already above the short-string threshold, the body takes the separator path using the rdata beginning at 0x1c3299c",
                "negative_value": "negative raw values receive '-' and are formatted by magnitude; no positive-only guard is present",
                "next": "[element+0x18]==0 ends the chain; otherwise the next element is processed",
            },
            "output": "destination is accumulated from per-element formatted text and returned as RAX=RDX; B5DEF0 then combines the +0x60 and +0x78 detail strings",
            "unfollowed_callees": ["0x3c8c00 country fallback", "0x14b33a0 label formatter core", "0x17061a0 decimal writer", "0x932f0 generic string helper", "0x95110 append helper"],
        },
        "382dd0_contract": {
            "function": {
                "rva_exclusive": ["0x382dd0", "0x382e6a"],
                "va_exclusive": ["0x140382dd0", "0x140382e6a"],
                "byte_length": 154,
            },
            "abi": {"rcx": "source object; +0x28c0 is passed to 0x93d5c0", "rdx": "output DWORD pointer", "return": "RAX=RDX"},
            "direct_cache_layout": {
                "probe": "P = 0x93d5c0(QWORD [RCX+0x28c0]); Q = P+0x08",
                "flagged": "if BYTE [Q+0x10] != 0, direct_value = DWORD [Q+0x58+0x12f4] (P+0x1354)",
                "list": "otherwise count=signed DWORD [Q+0x64], list=QWORD [Q+0x58]; scan stride 8 for DWORD key 0x25e and use the following DWORD as direct_value",
                "empty_or_missing": "zero direct_value when count<=0 or key 0x25e is absent",
            },
            "optional_manager": {
                "manager": "QWORD [0x142358060]+0xe380",
                "when_nonnull": "vtable slot +0 is read and [vtable+0x8] is called with Q=R8, &temporary_adjusted=RDX, &direct_value=R9; output uses the returned DWORD [temporary_adjusted]",
                "when_null": "output uses direct_value",
            },
            "final_formula": "out=signed_i32(selected_or_virtual_value + signed_i32(DWORD [0x14233ded8]))",
            "evidence_rvas": ["0x382dd9", "0x382de0", "0x382de9", "0x382df0", "0x382dfc", "0x382e10", "0x382e26", "0x382e2d", "0x382e50", "0x382e57", "0x382e5f"],
            "unit": "unknown; this is a signed native cache/virtual-manager result used as a factor input by 382E70, not proven trade_power",
            "unfollowed_callees": ["0x93d5c0", "virtual [vtable+0x8]"],
        },
        "2f2640_contract": {
            "function": {
                "rva_exclusive": ["0x2f2640", "0x2f2997"],
                "va_exclusive": ["0x1402f2640", "0x1402f2997"],
                "byte_length": 855,
            },
            "abi": {"rcx": "main object", "rdx": "output DWORD pointer", "r8": "optional display/context pointer saved as R15; B383830 supplies 382E70's R12", "return": "RAX=RDX"},
            "global_gate": {"rva": "0x233e29c", "va": "0x14233e29c", "condition": "zero writes output 0; nonzero is also the per-eligible-candidate increment in the non-display loop"},
            "candidate_vector": {
                "begin": "QWORD [[main+0x1480]+0x08]+0x20",
                "end": "QWORD [[main+0x1480]+0x08]+0x28",
                "stride": 8,
                "count": "(end-begin)/8",
                "type_filter": "BYTE [candidate+0x18] == 2",
            },
            "country_and_visibility": {
                "selected_slot": "signed_i16(high16(QWORD [main+0x20]))",
                "country_table": "QWORD [0x14233d8b0]+0x118, indexed by selected_slot",
                "fallback_state": "country[+0x14b0]+0xe8 when candidate[+0x10] is null; otherwise candidate[+0x10]+0x38",
                "visibility_index": "signed_i32(selected_slot*[manager+0x21bc] + [state+0x120])",
                "visibility_guard": "0 <= index < [manager+0x2238] and BYTE [[manager+0x2230]+index] != 0",
            },
            "entry_flags": {
                "entry_table": "[state+0x18] + signed_i16(high16([main+0x20]))*0xc0",
                "flag_ac": "BYTE [entry+0xac] == 1 is required by the accumulation loop",
                "flag_ad": "BYTE [entry+0xad] == 0 selects the first-loop early-return/display branch; nonzero continues the scan",
            },
            "non_display_path_from_382e70": {
                "caller_context": "382E70's R9 is zero from B57700, and 2F2640 receives that zero as R15",
                "first_scan": "if an eligible candidate reaches flag AD==0, zero-context path jumps to final output without the display loop; otherwise the second scan runs",
                "second_scan": "each eligible flag AC==1 candidate adds the global DWORD at 0x14233e29c to ESI; final ESI is capped by DWORD [0x14233e2a0]",
                "output": "DWORD [RDX]=capped signed accumulator; no per-node numeric field is read here",
            },
            "display_path": "nonzero R15 formats candidate+0xa8+0x30 through 0x97fb0/0x1f4700 and 0x932f0; B57700 does not supply this context",
            "unit": "unknown; the global increment/cap and flags are closed, but no trade_power or multiplier unit is proven",
            "unfollowed_callees": ["0x97fb0", "0x1f4700", "0x932f0", "0x95660"],
        },
        "disposition": {
            "multiplier_guard": "Do not gate the 382E70 multiplier path on entry+0x28 or entry+0x40. The former is province-only; the latter branches to the multiplier start for <=0 and falls through to it after the downstream row for >0.",
            "trade_multi_expla": "Treat TRADE_MULTI_EXPLA as the row label of the common continuation, direct-bound at B580A4 after the fixed display call; it is not evidence that the value is a trade_power source row.",
            "b5dcd0": "A future reader may enumerate the +0x60/+0x78 linked chains and preserve each signed raw +0x08, key/object +0, next +0x18, and TO/FROM provenance, but must leave key resolution, formatter grammar, and unit explicit until the unfollowed callees are closed.",
            "382dd0_2f2640": "These are bounded native cache/list contracts with exact fields and conditions; keep them separate from the three direct trade-power rows and do not sum or rename them.",
        },
        "unknowns": [
            "0x2892d0 and 0x1f4700 determine the key/name mapping and final TO/FROM grammar; this report does not claim a localization key beyond the literal inputs.",
            "0x93d5c0 and the optional virtual [vtable+8] determine the 382DD0 factor value; cache freshness and unit remain unknown.",
            "2F2640's global DWORD, visibility bitset and candidate flags are statically identified, but the business label of the aggregate remains unknown.",
            "No runtime values, current freshness, GUI pointer identity, game state, save/restart, or native call execution are claimed.",
        ],
        "verification": {
            "script": _relative(Path(__file__)),
            "all_shell_work_completed": True,
            "game_access": False,
            "native_function_execution": False,
            "rpm_used": False,
            "rea_access": False,
            "production_written": False,
            "source_modifiers_001_untouched": True,
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
        "entry_28_skip_reaches_multiplier": report["cfg_guard_correction"]["entry_0x28"]["reachability_to_multiplier"]["reachable"],
        "entry_40_both_paths_reach_multiplier": report["cfg_guard_correction"]["entry_0x40"]["nonpositive_to_multiplier"]["reachable"] and report["cfg_guard_correction"]["entry_0x40"]["positive_fallthrough_to_multiplier"]["reachable"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
