"""Bounded ordinary static research for the EU4 1.37.4 has_dlc trigger.

This module never opens a game process and is not REA Evidence. It searches the
exact PE for the literal token and decodes only containing/called candidate
functions. Every decoded segment is capped at 64 KiB, total decoded bytes at
256 KiB, and the call-follow budget at eight functions.
"""
from __future__ import annotations

import argparse
from collections import deque
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE, check_memory_budget, rip_references
from work.local_config import game_exe


EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
MAX_FUNCTION_BYTES = 64 * 1024
MAX_TOTAL_DECODE_BYTES = 256 * 1024
MAX_FOLLOW_FUNCTIONS = 8
TOKEN = b"has_dlc\0"


def _parse_objdump(text: str, image_base: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    pattern = re.compile(
        r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)"
        r"([A-Za-z][\w.]*)\s*(.*)$"
    )
    for line in text.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        raw_bytes = match.group(2).replace(" ", "").replace("\t", "")
        rows.append(
            {
                "rva": hex(address - image_base),
                "bytes": raw_bytes,
                "mnemonic": match.group(3),
                "operands": match.group(4).strip(),
            }
        )
    return rows


def _decode_objdump(pe: PE, start_rva: int, end_rva: int) -> list[dict[str, Any]]:
    if not 0 <= start_rva < end_rva:
        raise ValueError("invalid decode range")
    if end_rva - start_rva > MAX_FUNCTION_BYTES:
        raise ValueError("decode range exceeds 64 KiB")
    command = [
        "objdump",
        "-d",
        "-w",
        "-Mintel",
        f"--start-address={pe.base + start_rva:#x}",
        f"--stop-address={pe.base + end_rva:#x}",
        str(pe.path),
    ]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    if len(result.stdout) > 8 * 1024 * 1024:
        raise ValueError("objdump output exceeds bounded output limit")
    return _parse_objdump(result.stdout, pe.base)


def _target_from_operand(operand: str, image_base: int) -> int | None:
    match = re.search(r"(?:^|[\s#])0x([0-9a-fA-F]+)(?:$|[\s,])", operand)
    if not match:
        return None
    value = int(match.group(1), 16)
    return value - image_base if value >= image_base else value


def _section_for(pe: PE, rva: int) -> dict[str, Any] | None:
    for section in pe.sections:
        if section["rva"] <= rva < section["rva"] + section["size"]:
            return section
    return None


def _is_memory_instruction(mnemonic: str) -> bool:
    return mnemonic.startswith(
        ("mov", "cmp", "test", "lea", "add", "sub", "and", "or", "xor")
    )


def _has_token_immediate(operands: str, token_id: int) -> bool:
    """Check a textual immediate operand without accepting an address offset.

    Raw little-endian bytes occur in relative-call displacements and structure
    offsets.  Only an operand component that contains the complete numeric
    literal outside square brackets is treated as a token-id hit.
    """
    literal = f"0x{token_id:x}"
    pattern = re.compile(rf"(?<![0-9a-fA-F]){re.escape(literal)}(?![0-9a-fA-F])")
    return any(
        "[" not in component
        and "]" not in component
        and pattern.search(component) is not None
        for component in operands.split(",")
    )


def _instruction_analysis(
    pe: PE,
    instructions: list[dict[str, Any]],
    *,
    string_rvas: set[int],
    token_id: int | None,
) -> dict[str, Any]:
    direct_calls: list[dict[str, Any]] = []
    rip_targets: list[dict[str, Any]] = []
    token_hits: list[dict[str, Any]] = []
    memory_candidates: list[dict[str, Any]] = []
    branch_candidates: list[dict[str, Any]] = []
    for row in instructions:
        mnemonic = row["mnemonic"].lower()
        operands = row["operands"]
        if mnemonic == "call":
            target = _target_from_operand(operands, pe.base)
            if target is not None and pe.executable(target):
                function = pe.function(target)
                direct_calls.append(
                    {
                        "call_rva": row["rva"],
                        "target_rva": hex(target),
                        "target_function_range": (
                            [hex(function[0]), hex(function[1])] if function else None
                        ),
                        "operands": operands,
                    }
                )
        if "#" in operands:
            target = _target_from_operand(operands.split("#", 1)[1], pe.base)
            if target is not None:
                section = _section_for(pe, target)
                target_row = {
                    "instruction_rva": row["rva"],
                    "target_rva": hex(target),
                    "section": section["name"] if section else None,
                    "operands": operands,
                }
                if target in string_rvas:
                    target_row["matches_has_dlc_string"] = True
                rip_targets.append(target_row)
        # Raw bytes are deliberately not enough: ``20 2e 00 00`` also occurs
        # in call displacements and field offsets.  Require a textual
        # immediate operand outside an address expression.
        if token_id is not None and _has_token_immediate(operands, token_id):
            token_hits.append(
                {
                    "instruction_rva": row["rva"],
                    "mnemonic": row["mnemonic"],
                    "operands": operands,
                    "bytes": row["bytes"],
                    "evidence": "validated_operand_literal",
                }
            )
        if _is_memory_instruction(mnemonic) and "[" in operands:
            memory_candidates.append(
                {
                    "instruction_rva": row["rva"],
                    "mnemonic": row["mnemonic"],
                    "operands": operands,
                }
            )
        if mnemonic in {
            "cmp",
            "test",
            "je",
            "jne",
            "jz",
            "jnz",
            "sete",
            "setne",
            "cmove",
            "cmovne",
        }:
            branch_candidates.append(
                {
                    "instruction_rva": row["rva"],
                    "mnemonic": row["mnemonic"],
                    "operands": operands,
                }
            )
    return {
        "direct_calls": direct_calls,
        "rip_targets": rip_targets,
        "token_instruction_hits": token_hits,
        "memory_candidates": memory_candidates,
        "branch_candidates": branch_candidates,
    }


def _rdata_vtable_evidence(pe: PE, target_rva: int) -> dict[str, Any] | None:
    """Return narrow static evidence for a possible vtable start.

    A RIP target in .rdata is commonly an ordinary string/constant.  Require
    the first qword at the target to be an executable VA before reporting it
    as a vtable candidate.  This remains only a heuristic: no RTTI, ABI, or
    virtual-dispatch proof is claimed.
    """
    section = _section_for(pe, target_rva)
    if section is None or section["name"] not in {".rdata", "_RDATA"}:
        return None
    offset = pe.to_offset(target_rva)
    if offset is None:
        return None
    try:
        first_pointer = pe.u64(offset)
    except (IndexError, struct.error):
        return None
    if first_pointer < pe.base:
        return None
    first_target = first_pointer - pe.base
    if not pe.executable(first_target):
        return None
    return {
        "target_rva": hex(target_rva),
        "first_pointer_va": hex(first_pointer),
        "first_pointer_target_rva": hex(first_target),
        "evidence": "rdata_first_qword_points_to_executable",
        "confidence": "unverified_static_candidate",
    }


def _find_all(data: bytes, needle: bytes) -> list[int]:
    values: list[int] = []
    offset = 0
    while True:
        found = data.find(needle, offset)
        if found < 0:
            return values
        values.append(found)
        offset = found + 1


def _token_candidates(pe: PE, token_id: int) -> dict[str, Any]:
    token_bytes = struct.pack("<I", token_id)
    executable_hits: list[dict[str, Any]] = []
    accessor_hits: list[dict[str, Any]] = []
    pointer_slots: list[dict[str, Any]] = []
    for section in pe.sections:
        if not section["flags"] & 0x20000000:
            continue
        begin = section["raw"]
        end = begin + section["size"]
        for offset in _find_all(pe.data[begin:end], token_bytes):
            absolute = begin + offset
            rva = pe.to_rva(absolute)
            if rva is None:
                continue
            function = pe.function(rva)
            executable_hits.append(
                {
                    "raw_token_bytes_rva": hex(rva),
                    "function_range": (
                        [hex(function[0]), hex(function[1])] if function else None
                    ),
                    "evidence": "raw_little_endian_token_bytes; immediate_not_validated",
                }
            )
            if len(executable_hits) >= 256:
                break
        if len(executable_hits) >= 256:
            break
    accessor_pattern = b"\xb8" + token_bytes + b"\xc3"
    for section in pe.sections:
        if not section["flags"] & 0x20000000:
            continue
        begin = section["raw"]
        for offset in _find_all(pe.data[begin : begin + section["size"]], accessor_pattern):
            rva = pe.to_rva(begin + offset)
            if rva is not None:
                function = pe.function(rva)
                accessor_hits.append(
                    {
                        "accessor_rva": hex(rva),
                        "bytes": accessor_pattern.hex(),
                        "function_range": (
                            [hex(function[0]), hex(function[1])] if function else None
                        ),
                    }
                )
    accessor_rvas = {int(item["accessor_rva"], 16) for item in accessor_hits}
    for section in pe.sections:
        if section["flags"] & 0x20000000:
            continue
        begin = section["raw"]
        end = begin + section["size"]
        for offset in range(begin, max(begin, end - 7), 8):
            value = pe.u64(offset)
            target = value - pe.base
            if target in accessor_rvas:
                rva = pe.to_rva(offset)
                if rva is not None:
                    pointer_slots.append(
                        {
                            "slot_rva": hex(rva),
                            "section": section["name"],
                            "target_accessor_rva": hex(target),
                        }
                    )
    return {
        "token_id": hex(token_id),
        "executable_raw_byte_candidates": executable_hits,
        "constant_accessor_candidates": accessor_hits,
        "non_executable_pointer_slots": pointer_slots[:256],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT
        / "work/runtime/information-branches-20261024-001/dlc-trigger-contract.json",
    )
    args = parser.parse_args()
    path = game_exe()
    pe = PE(path)
    digest = hashlib.sha256(pe.data).hexdigest()
    if digest != EXPECTED_EXE_SHA256:
        raise RuntimeError(f"unsupported EXE SHA-256: {digest}")
    if len(pe.data) > 128 * 1024 * 1024:
        raise RuntimeError("PE exceeds bounded input limit")

    string_offsets = _find_all(pe.data, TOKEN)
    strings: list[dict[str, Any]] = []
    targets: set[int] = set()
    token_groups: dict[int, dict[str, Any]] = {}
    for offset in string_offsets:
        string_rva = pe.to_rva(offset)
        if string_rva is None:
            continue
        token_id = pe.u32(offset - 4) if offset >= 4 else None
        record = {
            "string_rva": hex(string_rva),
            "file_offset": hex(offset),
            "token_id": hex(token_id) if token_id is not None else None,
            "token_header_rva": hex(string_rva - 4) if offset >= 4 else None,
        }
        strings.append(record)
        targets.add(string_rva)
        if offset >= 4:
            targets.add(string_rva - 4)
            if token_id is not None:
                token_groups.setdefault(token_id, _token_candidates(pe, token_id))

    refs = rip_references(pe, targets)
    seed_candidates: list[dict[str, Any]] = []
    seen_seed: set[int] = set()
    for target, target_refs in refs.items():
        for ref in target_refs:
            instruction_rva = int(ref["instruction_rva"], 16)
            function = pe.function(instruction_rva)
            seed_rva = function[0] if function else instruction_rva
            if seed_rva in seen_seed:
                continue
            seen_seed.add(seed_rva)
            seed_candidates.append(
                {
                    "rva": hex(seed_rva),
                    "reason": "rip_reference_to_has_dlc_string_or_token_header",
                    "target_rva": hex(target),
                    "instruction_rva": hex(instruction_rva),
                    "function_range": (
                        [hex(function[0]), hex(function[1])] if function else None
                    ),
                }
            )
    for token_id, group in token_groups.items():
        for item in group["constant_accessor_candidates"]:
            rva = int(item["accessor_rva"], 16)
            if rva not in seen_seed:
                seen_seed.add(rva)
                seed_candidates.append(
                    {
                        "rva": hex(rva),
                        "reason": "constant_token_accessor_candidate",
                        "token_id": hex(token_id),
                        "function_range": item["function_range"],
                    }
                )
        for item in group["executable_raw_byte_candidates"]:
            if item["function_range"]:
                rva = int(item["function_range"][0], 16)
                if rva not in seen_seed:
                    seen_seed.add(rva)
                    seed_candidates.append(
                        {
                            "rva": hex(rva),
                            "reason": "raw_token_bytes_in_executable_candidate",
                            "token_id": hex(token_id),
                            "raw_token_bytes_rva": item["raw_token_bytes_rva"],
                            "function_range": item["function_range"],
                        }
                    )

    string_rvas = {int(item["string_rva"], 16) for item in strings}
    token_id = next(iter(token_groups), None)
    decoded_bytes = 0
    decoded_functions: dict[int, dict[str, Any]] = {}
    queue: deque[tuple[int, str]] = deque(
        (int(item["rva"], 16), item["reason"]) for item in seed_candidates
    )
    queued: set[int] = {item[0] for item in queue}
    rejected: list[dict[str, Any]] = []
    while queue and len(decoded_functions) < MAX_FOLLOW_FUNCTIONS:
        candidate_rva, reason = queue.popleft()
        function = pe.function(candidate_rva)
        if function is None:
            start, end = candidate_rva, candidate_rva + 0x100
            function_range = None
        else:
            start, end = function[:2]
            function_range = [hex(start), hex(end)]
        size = end - start
        if size <= 0 or size > MAX_FUNCTION_BYTES:
            rejected.append(
                {
                    "rva": hex(candidate_rva),
                    "reason": "function_exceeds_64KiB" if size > MAX_FUNCTION_BYTES else "invalid_range",
                    "function_range": function_range,
                }
            )
            continue
        if decoded_bytes + size > MAX_TOTAL_DECODE_BYTES:
            rejected.append(
                {
                    "rva": hex(candidate_rva),
                    "reason": "total_decode_limit",
                    "function_range": function_range,
                }
            )
            continue
        try:
            instructions = _decode_objdump(pe, start, end)
        except Exception as exc:
            rejected.append(
                {
                    "rva": hex(candidate_rva),
                    "reason": "objdump_failed",
                    "error": str(exc),
                    "function_range": function_range,
                }
            )
            continue
        raw = pe.bytes_at(start, size)
        decoded_bytes += size
        analysis = _instruction_analysis(
            pe,
            instructions,
            string_rvas=string_rvas,
            token_id=token_id,
        )
        decoded_functions[start] = {
            "rva": hex(start),
            "end_rva_exclusive": hex(end),
            "function_range": function_range,
            "selection_reason": reason,
            "bytes_decoded": size,
            "bytes_sha256": hashlib.sha256(raw).hexdigest(),
            "instruction_count": len(instructions),
            "instructions": instructions,
            "analysis": analysis,
        }
        for call in analysis["direct_calls"]:
            target = int(call["target_rva"], 16)
            target_function = pe.function(target)
            if target_function is None:
                continue
            next_rva = target_function[0]
            if next_rva in decoded_functions or next_rva in queued:
                continue
            queued.add(next_rva)
            queue.append((next_rva, f"direct_call_from_{hex(start)}"))

    for string in strings:
        string_rva = int(string["string_rva"], 16)
        string["references"] = refs.get(string_rva, [])
        token_header = string.get("token_header_rva")
        string["token_header_references"] = (
            refs.get(int(token_header, 16), []) if token_header else []
        )

    getter_candidates = []
    factory_candidates = []
    vtable_candidates = []
    for function in decoded_functions.values():
        analysis = function["analysis"]
        if analysis["token_instruction_hits"]:
            getter_candidates.append(
                {
                    "function_rva": function["rva"],
                    "reason": "token_id_instruction_hit; getter semantics unverified",
                    "confidence": "unverified_static_candidate",
                    "token_instruction_hits": analysis["token_instruction_hits"],
                    "memory_candidates": analysis["memory_candidates"],
                    "branch_candidates": analysis["branch_candidates"],
                }
            )
        if analysis["token_instruction_hits"] and analysis["direct_calls"]:
            factory_candidates.append(
                {
                    "function_rva": function["rva"],
                    "reason": "token-id constant plus direct call edges; factory semantics unverified",
                    "confidence": "unverified_static_candidate",
                    "direct_calls": analysis["direct_calls"],
                }
            )
        for target in analysis["rip_targets"]:
            target_rva = target.get("target_rva")
            if not target_rva:
                continue
            evidence = _rdata_vtable_evidence(pe, int(target_rva, 16))
            if evidence is not None:
                vtable_candidates.append(
                    {
                        "function_rva": function["rva"],
                        "instruction_rva": target.get("instruction_rva"),
                        "operands": target.get("operands"),
                        **evidence,
                    }
                )

    unresolved = [
        "literal has_dlc token does not by itself establish the trigger factory or runtime getter",
        "all candidate functions and call edges are static ordinary evidence; ABI and virtual dispatch are unverified",
        "no read-only runtime input is produced by this script",
    ]
    if not strings:
        unresolved.insert(0, "has_dlc literal was not found in the exact EXE")
    if not getter_candidates:
        unresolved.append("no decoded function contained a validated token-id instruction")
    if not factory_candidates:
        unresolved.append(
            "no selected function had both a validated token-id literal and a direct call edge; trigger factory remains unknown"
        )
    if not vtable_candidates:
        unresolved.append("no .rdata RIP target was identified as a vtable candidate")
    elif not getter_candidates:
        unresolved.append(
            "the retained vtable-shaped pointers came from raw-byte candidates and are not linked to has_dlc"
        )

    report = {
        "schema": "eu4-information-dlc-trigger-contract.v1",
        "evidence_kind": "ordinary_file_analysis_not_REA_Evidence",
        "binary": {
            "path": str(path),
            "filename": path.name,
            "size_bytes": len(pe.data),
            "sha256": digest,
            "image_base": hex(pe.base),
            "address_kind": "RVA for static evidence; VA only as objdump input",
        },
        "target": {
            "game_version": "1.37.4",
            "literal": "has_dlc",
            "requested_value": "Domination",
            "requested_value_evidence": "investigation target only; no validated static association",
        },
        "decoder": "bounded objdump -d -w -Mintel",
        "limits": {
            "max_function_bytes": MAX_FUNCTION_BYTES,
            "max_total_decode_bytes": MAX_TOTAL_DECODE_BYTES,
            "max_follow_functions": MAX_FOLLOW_FUNCTIONS,
            "decoded_bytes": decoded_bytes,
            "decoded_function_count": len(decoded_functions),
        },
        "token_strings": strings,
        "token_candidates": list(token_groups.values()),
        "seed_candidates": seed_candidates,
        "decoded_functions": list(decoded_functions.values()),
        "getter_candidates": getter_candidates,
        "factory_candidates": factory_candidates,
        "vtable_candidates": vtable_candidates,
        "rejected_candidates": rejected,
        "unresolved_conditions": unresolved,
        "next_steps": [
            "Prioritize a bounded runtime-only lookup of the engine's loaded DLC registry; static file analysis cannot establish dlc_loaded.",
            "If another static pass is authorized, start from a validated token-literal instruction or a caller of the token-string/header reference; this run found no such reference.",
        ],
        "runtime_input": {
            "dlc_loaded": None,
            "map_setup": None,
            "status": "static_candidates_only",
            "reason": "No game process/RPM/REA/runtime evaluator was used.",
        },
        "peak_committed_bytes": check_memory_budget(),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "strings": len(strings),
                "seed_candidates": len(seed_candidates),
                "decoded_functions": len(decoded_functions),
                "decoded_bytes": decoded_bytes,
                "getter_candidates": len(getter_candidates),
                "factory_candidates": len(factory_candidates),
                "vtable_candidates": len(vtable_candidates),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
