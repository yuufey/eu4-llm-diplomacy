#!/usr/bin/env python3
"""Extract the bounded placeholder-evaluator contract from retained REA evidence.

The script reads only the new 1.4 MiB Evidence and the existing small selected
14B33A0 excerpt.  It does not invoke REA, inspect a live process, or read the
large provider report behind the old selected excerpt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


ROOT = Path(__file__).resolve().parents[1]
FIXED_VERSION = "1.37.4"
FIXED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
STATIC_BASE = 0x140000000
MAX_READ_BYTES = 2 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024

NEW_EVIDENCE = "work/runtime/information-battle-business-20261025-001/rea-placeholder-evaluator-001/evidence.json"
NEW_EVIDENCE_SHA256 = "4589bab1e91efe651f091b78f50f74ae052d58ac318229fd63979c2ec2e89de2"
NEW_EVIDENCE_ID = "ev_98d904c613050a4bf92325b92281660b363852c45270b98d20479484d40100c9"
OLD_SELECTED = "work/runtime/information-battle-fragments-20261025-001/rea-localized-format-001/selected-evidence-001.json"
OLD_SELECTED_SHA256 = "48dfd0dec340cf031b64fe5d7f08ad6958179af736093cd91e93ea56d41a7bdc"
OLD_EVIDENCE_ID = "ev_48919e3903f355e10997c47979823883c122867db887ce13bc26cb04cf244167"


def _sha256(path: Path) -> str:
    if not path.is_file():
        raise FileNotFoundError(path)
    size = path.stat().st_size
    if size > MAX_READ_BYTES:
        raise ValueError(f"bounded evidence exceeds read limit: {path} ({size})")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(CHUNK_BYTES)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


def _load_json(root: Path, relative: str, expected_sha256: str) -> Dict[str, Any]:
    path = root / relative
    actual = _sha256(path)
    if actual != expected_sha256:
        raise ValueError(f"SHA mismatch for {relative}: {actual} != {expected_sha256}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"expected JSON object: {relative}")
    return data


def _hex(value: Any) -> int:
    if isinstance(value, int):
        return value
    return int(str(value), 16)


def _rva(value: Any) -> str:
    return f"0x{(_hex(value) - STATIC_BASE):x}"


def _va(rva: int) -> str:
    return f"0x{STATIC_BASE + rva:x}"


def _body_ranges(procedure: Dict[str, Any]) -> List[Dict[str, Any]]:
    body = procedure["body"]
    result: List[Dict[str, Any]] = []
    for item in body["ranges"]:
        start = _hex(item["start"])
        end = _hex(item["end"])
        if end < start:
            raise ValueError("invalid inclusive body range")
        result.append(
            {
                "start_va": f"0x{start:x}",
                "end_va_inclusive": f"0x{end:x}",
                "start_rva": _rva(start),
                "end_rva_inclusive": _rva(end),
                "end_rva_exclusive_derived": _rva(end + 1),
                "bytes_from_inclusive_endpoints": end - start + 1,
            }
        )
    return result


def _assembly_map(assembly: Iterable[str]) -> Dict[int, str]:
    result: Dict[int, str] = {}
    for item in assembly:
        address, text = item.split(": ", 1)
        result[_hex(address)] = text
    return result


def _assembly_window(assembly: Dict[int, str], name: str, addresses: Iterable[int]) -> Dict[str, Any]:
    rows = []
    for address in addresses:
        if address not in assembly:
            raise ValueError(f"assembly instruction not found: 0x{address:x}")
        rows.append(
            {
                "va": f"0x{address:x}",
                "rva": _rva(address),
                "text": assembly[address],
            }
        )
    return {"name": name, "instructions": rows}


def _line_refs(lines: List[str], refs: Iterable[int]) -> Dict[str, Any]:
    result = {}
    for line_number in refs:
        if not 1 <= line_number <= len(lines):
            raise ValueError(f"pseudocode line out of range: {line_number}")
        result[str(line_number)] = lines[line_number - 1].strip()
    return result


def _parameter_contract(native_api: Dict[str, Any]) -> Dict[str, Any]:
    params = []
    for item in native_api["parameters"]:
        params.append(
            {
                "ordinal": item["ordinal"],
                "name": item["name"],
                "recovered_type": item["data_type"],
                "storage": item["storage"],
                "confidence": item["confidence"],
            }
        )
    ret = native_api["return_type"]
    return {
        "parameters": params,
        "return": {
            "recovered_type": ret["data_type"],
            "storage": ret["storage"],
            "confidence": ret["confidence"],
        },
        "semantic_types": "not closed by default Ghidra signature; roles below are expression-level observations",
    }


def build_report(root: Path) -> Dict[str, Any]:
    evidence = _load_json(root, NEW_EVIDENCE, NEW_EVIDENCE_SHA256)
    selected = _load_json(root, OLD_SELECTED, OLD_SELECTED_SHA256)

    if evidence.get("evidence_id") != NEW_EVIDENCE_ID:
        raise ValueError("new Evidence ID mismatch")
    raw = evidence["raw_result"]["value"]
    procedure = raw["procedure"]
    if procedure["address"] != "0x1414b2b40":
        raise ValueError("unexpected placeholder procedure")
    body_ranges = _body_ranges(procedure)
    if len(body_ranges) != 1 or body_ranges[0]["end_va_inclusive"] != "0x1414b3308":
        raise ValueError("unexpected retained REA body range")
    if procedure["body"]["total_bytes"] != 1993:
        raise ValueError("unexpected retained REA body size")

    old_id = selected["top_level"]["evidence_id"]["value"]
    if old_id != OLD_EVIDENCE_ID:
        raise ValueError("old selected Evidence ID mismatch")
    old_procedure = selected["raw_result_value"]["procedure"]["value"]
    if old_procedure["address"] != "0x1414b33a0":
        raise ValueError("unexpected old caller procedure")

    pseudo_lines = raw["pseudocode"].splitlines()
    assembly = _assembly_map(raw["assembly"])
    # The ranges are deliberately sparse: these are only the machine facts
    # needed to tie the expression-level offsets and calls to the fixed image.
    assembly_windows = [
        _assembly_window(
            assembly,
            "entry_and_argument_spills",
            [0x1414B2B40, 0x1414B2B45, 0x1414B2B4A, 0x1414B2B4F, 0x1414B2B56],
        ),
        _assembly_window(
            assembly,
            "descriptor_key_scan_and_stride",
            [
                0x1414B2BB5,
                0x1414B2BC0,
                0x1414B2BC9,
                0x1414B2BD3,
                0x1414B2BE9,
                0x1414B2BEE,
                0x1414B2BF5,
                0x1414B2C05,
                0x1414B2C09,
            ],
        ),
        _assembly_window(
            assembly,
            "type_dispatch_and_value_offsets",
            [
                0x1414B2D1F,
                0x1414B2D23,
                0x1414B2D26,
                0x1414B2D2A,
                0x1414B2D2F,
                0x1414B2D55,
                0x1414B2D57,
                0x1414B2DA5,
                0x1414B2DD6,
                0x1414B2E28,
                0x1414B2EDA,
                0x1414B308A,
                0x1414B321B,
                0x1414B3285,
            ],
        ),
        _assembly_window(
            assembly,
            "output_calls_and_return",
            [
                0x1414B31E0,
                0x1414B31E5,
                0x1414B31F8,
                0x1414B31FD,
                0x1414B32E1,
                0x1414B32E9,
                0x1414B32F2,
                0x1414B32F7,
                0x1414B3308,
            ],
        ),
    ]

    body = body_ranges[0]
    old_raw = selected["raw_result_value"]
    old_ps_lines = old_raw["pseudocode"]["value"].splitlines()
    old_asm = old_raw["assembly"]["value"]
    caller_call = [item for item in old_asm if item.startswith("0x1414b34b1:")]
    if len(caller_call) != 1:
        raise ValueError("old caller callsite not found")

    return {
        "schema": "information_battle_placeholder_contract.v1",
        "status": "passed_static_mechanical_extraction",
        "read_only": True,
        "rea_invoked_by_this_script": False,
        "game_access": False,
        "rpm_access": False,
        "native_function_invoked": False,
        "complete_ui_claim": False,
        "visibility_claim": False,
        "fixed_build": {
            "version": FIXED_VERSION,
            "exe_sha256": FIXED_EXE_SHA256,
            "static_image_base": "0x140000000",
            "address_note": "RVA is static VA minus 0x140000000; no runtime module base is inferred.",
        },
        "evidence": {
            "new_placeholder": {
                "path": NEW_EVIDENCE,
                "size_bytes": (root / NEW_EVIDENCE).stat().st_size,
                "sha256": NEW_EVIDENCE_SHA256,
                "evidence_id": NEW_EVIDENCE_ID,
                "provider": evidence["provider"],
                "operation": evidence["operation"],
                "analysis_profile": evidence["analysis_profile"]["parameters"],
                "authority": evidence["authority"],
            },
            "old_localized_selected": {
                "path": OLD_SELECTED,
                "size_bytes": (root / OLD_SELECTED).stat().st_size,
                "sha256": OLD_SELECTED_SHA256,
                "evidence_id": OLD_EVIDENCE_ID,
                "underlying_provider_report": selected["source"],
                "provider_runtime": selected["provider_runtime"],
            },
        },
        "function": {
            "name": procedure["name"],
            "start_va": body["start_va"],
            "end_va_inclusive": body["end_va_inclusive"],
            "start_rva": body["start_rva"],
            "end_rva_inclusive": body["end_rva_inclusive"],
            "end_rva_exclusive_derived": body["end_rva_exclusive_derived"],
            "body_ranges_inclusive": body_ranges,
            "total_bytes": procedure["body"]["total_bytes"],
            "span_bytes": procedure["body"]["span_bytes"],
            "provider_non_contiguous": procedure["body"]["non_contiguous"],
            "range_warning": {
                "first_pe_range_start_rva": "0x14b2b40",
                "first_pe_range_end_rva_exclusive": "0x14b2b8c",
                "first_pe_range_bytes": 0x4C,
                "meaning": "A 76-byte PE/pdata entry window is not the complete REA function body. The report preserves the retained REA inclusive endpoint through 0x14b3308 and does not substitute the first window for the body.",
            },
            "signature": _parameter_contract(raw["native_api"]),
        },
        "descriptor_contract": {
            "array_base_expression": "param_5",
            "count_expression": "param_6",
            "entry_stride_bytes": 0x68,
            "key": {
                "entry_offset": "0x0 (read as qword pointer-or-null)",
                "inline_storage_offset": "0x8",
                "capacity_offset": "0x20",
                "heap_pointer_when_capacity_gt_15": "0x8",
                "semantics": "The evaluator reads qword(entry+0); if null, it uses the String32-like storage at entry+0x8 and checks capacity at entry+0x20; capacity > 0xF selects qword(entry+0x8) as the heap pointer.",
                "pseudocode_lines": _line_refs(pseudo_lines, [52, 58, 59, 60, 61, 71]),
            },
            "type": {
                "offset": "0x28",
                "expression": "*(int *)(param_5 + index*0x68 + 0x28)",
                "pseudocode_lines": _line_refs(pseudo_lines, [171, 172, 174]),
            },
            "values": [
                {"type": 1, "kind": "String32_like", "value_offset": "0x30", "inline_offset": "0x30", "capacity_offset": "0x48", "length_or_advance_offset": "0x40", "pseudocode_lines": _line_refs(pseudo_lines, [350, 351, 352, 353, 370])},
                {"type": 2, "kind": "NUL_terminated_char_pointer", "value_offset": "0x60", "pseudocode_lines": _line_refs(pseudo_lines, [372, 373, 374, 380, 392])},
                {"type": 3, "kind": "float", "value_offset": "0x60", "pseudocode_lines": _line_refs(pseudo_lines, [175, 176, 183])},
                {"type": 4, "kind": "double", "value_offset": "0x60", "pseudocode_lines": _line_refs(pseudo_lines, [185, 186, 193])},
                {"type": 5, "kind": "signed_int32", "value_offset": "0x60", "pseudocode_lines": _line_refs(pseudo_lines, [200, 201, 203])},
                {"type": 6, "kind": "unsigned_int32", "value_offset": "0x60", "pseudocode_lines": _line_refs(pseudo_lines, [215, 216, 217])},
                {"type": 7, "kind": "signed_int32", "value_offset": "0x50", "pseudocode_lines": _line_refs(pseudo_lines, [249, 250, 253])},
                {"type": 8, "kind": "signed_int64_observed", "value_offset": "0x58", "pseudocode_lines": _line_refs(pseudo_lines, [312, 313, 316])},
            ],
            "other_types": "No additional value interpretation is established; default handling only has explicit branches for type 1 and type 2.",
        },
        "key_matching": {
            "scan": "Find the first '|' or param_4; compare the candidate descriptor key against param_3+1 using the measured candidate length.",
            "no_match": "return param_1 unchanged",
            "pseudocode_lines": _line_refs(pseudo_lines, [44, 47, 52, 66, 67, 68, 69, 71, 72, 73]),
            "machine_evidence": assembly_windows[1],
        },
        "format_flags": {
            "initial_defaults": {
                "scale": "fVar31=100.0; fVar32 starts at fVar31",
                "precision_or_digit": "cVar22=2",
                "suffix_marker": "cVar17=0",
                "sign_or_mode": "bVar* flags start false",
            },
            "tokens": [
                {"token": "%", "effect": "bVar5=true; fVar32=fVar31"},
                {"token": "&", "effect": "bVar5=true; fVar32=1.0"},
                {"token": "*", "effect": "bVar2=true"},
                {"token": "+", "effect": "bVar6=true; local_res8=false"},
                {"token": "-", "effect": "bVar6=true; local_res8=true"},
                {"token": "0..9", "effect": "cVar22=token-'0'"},
                {"token": "=", "effect": "bVar4=true"},
                {"token": "B,C,G,H,L,R,T,W,Y,b,c,g", "effect": "cVar17=token"},
                {"token": "U", "effect": "bVar30=true"},
                {"token": "_", "effect": "bVar3=true"},
            ],
            "output_markers": {
                "nonzero_cVar17_prefix": "bytes 0xA7, cVar17",
                "nonzero_cVar17_suffix": "bytes 0xA7, 0x21",
                "pseudocode_lines": _line_refs(pseudo_lines, [93, 99, 100, 104, 112, 115, 119, 123, 135, 138, 153, 156, 164, 165, 166, 426, 427, 428]),
            },
        },
        "type_switch_behavior": {
            "numeric": "Types 3/4/5/6/7/8 build local_88 using numeric formatting helpers and then use the common prefix/suffix path.",
            "string_type_1": "Copies a String32-like value from entry+0x30; if capacity > 0xF it dereferences the heap pointer at entry+0x30, otherwise it uses inline bytes beginning at entry+0x30. Optional U flag uppercases the first output character.",
            "string_type_2": "Copies the NUL-terminated pointer at entry+0x60 and advances by its observed NUL length; optional U flag uppercases the first output character.",
            "unknown_type": "No semantic result is assigned for other type values; the provider evidence does not justify a broader type map.",
            "pseudocode_lines": _line_refs(pseudo_lines, [171, 174, 175, 185, 200, 215, 249, 312, 349, 350, 372, 395, 397, 410, 422, 425]),
        },
        "raw_output_and_return": {
            "return_expression": "return param_1",
            "returned_value": "char* output cursor in RAX; direct string branches copy bytes through NUL, numeric branches write formatted ASCII through helpers",
            "raw_byte_behavior": "Type 1 and type 2 copy source bytes until NUL; U may mutate the first output byte via toupper. This is an expression-level observation, not a complete-text or encoding contract.",
            "common_formatter": "FUN_14015c260(param_1, \"%s%s%s%s%s\", ...)",
            "pseudocode_lines": _line_refs(pseudo_lines, [351, 357, 360, 373, 378, 380, 381, 384, 387, 391, 392, 397, 422, 423, 431]),
            "machine_evidence": assembly_windows[3],
        },
        "caller_context": {
            "function": {
                "name": old_procedure["name"],
                "start_va": "0x1414b33a0",
                "end_va_inclusive": "0x1414b35b9",
                "start_rva": "0x14b33a0",
                "end_rva_inclusive": "0x14b35b9",
                "body_bytes": old_procedure["body"]["total_bytes"],
            },
            "callsite": {
                "va": "0x1414b34b1",
                "rva": "0x14b34b1",
                "assembly": caller_call[0],
                "evidence_id": OLD_EVIDENCE_ID,
            },
            "expression_level": {
                "lookup": "FNV-1 style hash of param_2, then FUN_1416faf60(*DAT_142357b00, hash)",
                "placeholder_split": "FUN_141a351ec(..., 0x24) locates '$' segments before and after each placeholder",
                "evaluator_call": "FUN_1414b2b40(_Dest + _Count, local_44, lVar3, lVar4) in pseudocode; machine arguments also spill caller param_3/param_4 as callee param_5/param_6",
                "output_limit": "After the call, caller rejects/clears the result when _Dest - param_2 > 0xFC00.",
                "pseudocode_lines": _line_refs(old_ps_lines, [25, 33, 51, 54, 64, 65, 66, 67, 68, 69, 81, 82, 102, 103]),
            },
            "limitation": "The caller proves segmented template expansion and a bounded scratch/output path; it does not prove a complete UI frame, a country-known predicate, or observer visibility.",
        },
        "unknown_callees": [
            {"va": "0x14015c260", "rva": "0x15c260", "name": "FUN_14015c260", "role": "common formatted write/copy used by numeric and final prefix/suffix paths", "semantic_status": "unknown"},
            {"va": "0x1414bec60", "rva": "0x14bec60", "name": "FUN_1414bec60", "role": "type-6 integer formatting helper", "semantic_status": "unknown"},
            {"va": "0x1414bee40", "rva": "0x14bee40", "name": "FUN_1414bee40", "role": "integer/compact formatting helper", "semantic_status": "unknown"},
            {"va": "0x1417036d0", "rva": "0x17036d0", "name": "FUN_1417036d0", "role": "type-5 scaled numeric formatting helper", "semantic_status": "unknown"},
            {"va": "0x141703780", "rva": "0x1703780", "name": "FUN_141703780", "role": "type-7/type-8 formatting helper", "semantic_status": "unknown"},
            {"va": "0x1417061a0", "rva": "0x17061a0", "name": "FUN_1417061a0", "role": "decimal component formatting helper", "semantic_status": "unknown"},
            {"va": "0x141a471b0", "rva": "0x1a471b0", "name": "strncmp", "role": "key comparison", "semantic_status": "callee identity observed; broader contract not analyzed"},
            {"va": "0x141a4adc8", "rva": "0x1a4adc8", "name": "toupper", "role": "optional first-byte mutation", "semantic_status": "callee identity observed; locale behavior not analyzed"},
            {"va": "0x141a79180", "rva": "0x1a79180", "name": "floorf", "role": "type-8 scaling branch", "semantic_status": "callee identity observed; business semantics unknown"},
            {"va": "indirect:PTR_DAT_141c37b80", "role": "double-format table selected by digit/precision byte", "semantic_status": "target strings/functions not resolved here"},
        ],
        "unresolved": [
            "The descriptor type numbers are expression-level observations, not a complete public type enum.",
            "Formatting helper behavior, locale/encoding, allocation, and buffer ownership remain unresolved.",
            "The function formats one selected placeholder/value; it does not establish complete UI text or observer-country visibility.",
            "The retained new Evidence body is preserved as the provider's complete-inclusive range; the 76-byte PE entry window must not be used as a replacement.",
        ],
    }


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=None)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("work/runtime/information-battle-business-20261025-001/placeholder-contract-001.json"),
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    root = (args.workspace or ROOT).resolve()
    output = args.output if args.output.is_absolute() else root / args.output
    report = build_report(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"output": str(output), "sha256": _sha256(output), "status": report["status"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
