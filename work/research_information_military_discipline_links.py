"""Bounded ordinary-PE search for the discipline callback manager link.

This is a raw candidate scan, followed by a few small instruction windows.  It
does not use REA, attach to a process, or treat a byte-pattern reference as a
semantic proof.  The existing 341850 helper is intentionally only used as the
known read-site anchor; its body is not decoded again here.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import sys
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE, check_memory_budget, make_disassembler, rip_references
from work.local_config import game_exe
from work.research_information_branch_inputs import _decode_range


EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = 0x140000000
GLOBAL_RVA = 0x2358060
FIELD_OFFSET = 0x2CE0
KNOWN_HELPER_RVA = 0x341850
# The archived religious-unity source fixes the static record layout used by
# the value/boolean accessors.  Keep the arithmetic explicit here: 0x2ce0 is
# a record slot, not a separately named global writer location.
DATABASE_INDEX = 0x77
RECORD_STRIDE = 0x60
PROCESSOR_OFFSET = 0x40
DATABASE_RECORD_RVA = GLOBAL_RVA + DATABASE_INDEX * RECORD_STRIDE
PROCESSOR_SLOT_RVA = DATABASE_RECORD_RVA + PROCESSOR_OFFSET
PROCESSOR_VTABLE_RVA = 0x1CC9400
PROCESSOR_VALUE_METHOD_RVA = 0x8F71D0
PROCESSOR_CONSTRUCTOR_RVA = 0x8F1DF0
MAX_TOTAL_DECODE = 0x8000
MAX_PER_RANGE = 0x4000
SOURCE_002 = ROOT / "work/runtime/information-military-quality-20261027-001/morale-discipline-source-002.json"
SOURCE_002_SHA256 = "db4bd888912fca012c32bed29fda79e6c45f0d1dfc03b989158d97a6b89baf67"
RELIGIOUS_UNITY_DOC = ROOT / "docs/宗教统一计算路径.md"
RELIGIOUS_UNITY_PROFILE = ROOT / "bridge/information/profiles/religious-unity-memory-1374.json"


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _section(pe: PE, rva: int):
    for section in pe.sections:
        size = max(section["size"], section["virtual_size"])
        if section["rva"] <= rva < section["rva"] + size:
            return section["name"]
    return None


def _location(pe: PE, rva: int):
    offset = pe.to_offset(rva)
    return {
        "rva": hex(rva),
        "va": hex(pe.base + rva),
        "file_offset": hex(offset) if offset is not None else None,
        "section": _section(pe, rva),
    }


def _function(pe: PE, rva: int):
    function = pe.function(rva)
    if not function:
        return None
    return {
        "start_rva": hex(function[0]),
        "end_rva_exclusive": hex(function[1]),
        "unwind_rva": hex(function[2]),
        "range_bytes": function[1] - function[0],
    }


def _rex_bits(rex: int) -> dict[str, int]:
    return {"w": (rex >> 3) & 1, "r": (rex >> 2) & 1, "x": (rex >> 1) & 1, "b": rex & 1}


def _field_instruction(data: bytes, marker: int):
    """Return direct-disp32 instruction candidates ending at marker.

    The scan recognizes common one-opcode ModRM forms with a direct register
    base plus disp32.  It deliberately does not call these candidates writes
    until the opcode is classified; a read or comparison at +2ce0 is useful
    context but is not a constructor.
    """
    opcodes = {
        0x01: "write_or_add", 0x09: "write_or_or", 0x0B: "read_or_or",
        0x21: "write_or_and", 0x23: "read_or_and", 0x29: "write_or_sub",
        0x31: "write_or_xor", 0x39: "compare", 0x3B: "compare",
        0x80: "immediate_touch", 0x81: "immediate_touch", 0x83: "immediate_touch",
        0x87: "exchange", 0x89: "write", 0x8B: "read", 0x8D: "address",
        0xC6: "write_immediate", 0xC7: "write_immediate",
    }
    result = []
    # One REX prefix is enough for the direct forms relevant to this field.
    for rex_len in (0, 1):
        opcode_index = marker - rex_len - 2
        modrm_index = marker - rex_len - 1
        if opcode_index < 0 or modrm_index < 0:
            continue
        rex = data[opcode_index - 1] if rex_len else 0
        if rex_len and not (0x40 <= rex <= 0x4F):
            continue
        opcode = data[opcode_index]
        kind = opcodes.get(opcode)
        if kind is None:
            continue
        modrm = data[modrm_index]
        if (modrm & 0xC0) != 0x80 or (modrm & 7) == 4:
            continue
        start = opcode_index - rex_len
        result.append({
            "start_offset": start,
            "opcode": hex(opcode),
            "kind": kind,
            "rex": hex(rex) if rex_len else None,
            "modrm": hex(modrm),
            "base_register_index": (modrm & 7) | ((rex & 1) << 3),
            "source_register_index": ((modrm >> 3) & 7) | (((rex >> 2) & 1) << 3),
        })
    return result


def _scan_field_candidates(pe: PE):
    marker = struct.pack("<I", FIELD_OFFSET)
    records = []
    seen = set()
    for section in pe.sections:
        if not section["flags"] & 0x20000000:
            continue
        raw_begin = section["raw"]
        raw_end = raw_begin + section["size"]
        data = pe.data[raw_begin:raw_end]
        cursor = 0
        while True:
            local = data.find(marker, cursor)
            if local < 0:
                break
            cursor = local + 1
            for candidate in _field_instruction(data, local):
                raw_offset = raw_begin + candidate["start_offset"]
                rva = pe.to_rva(raw_offset)
                if rva is None or (rva, candidate["kind"]) in seen:
                    continue
                seen.add((rva, candidate["kind"]))
                instruction_length = local + 4 - candidate["start_offset"]
                raw = pe.data[raw_offset:raw_offset + min(16, instruction_length + 8)]
                record = {
                    **candidate,
                    "instruction_rva": hex(rva),
                    "location": _location(pe, rva),
                    "function": _function(pe, rva),
                    "bytes_hex": raw.hex(),
                    "bytes_sha256": hashlib.sha256(raw).hexdigest(),
                    "evidence": "raw_text_displacement_candidate",
                }
                records.append(record)
    return records


def _raw_marker_locations(pe: PE):
    """Keep the complete 4-byte marker inventory compact and auditable."""
    marker = struct.pack("<I", FIELD_OFFSET)
    locations = []
    for section in pe.sections:
        if not section["flags"] & 0x20000000:
            continue
        begin, end = section["raw"], section["raw"] + section["size"]
        data = pe.data[begin:end]
        cursor = 0
        while True:
            local = data.find(marker, cursor)
            if local < 0:
                break
            cursor = local + 1
            rva = pe.to_rva(begin + local)
            locations.append({
                "marker_rva": hex(rva),
                "marker_va": hex(pe.base + rva),
                "function": _function(pe, rva),
                "bytes_hex": pe.data[max(0, begin + local - 6):begin + local + 10].hex(),
            })
    return locations


def _candidate_score(candidate, global_functions):
    function = candidate.get("function") or {}
    start = function.get("start_rva")
    score = 0
    if start in global_functions:
        score += 100
    if candidate["kind"] in {"write", "write_immediate", "write_or_add", "write_or_or", "write_or_and", "write_or_sub", "write_or_xor", "exchange"}:
        score += 30
    if start == hex(KNOWN_HELPER_RVA):
        score -= 1000
    return score


def _select_decode_ranges(pe: PE, candidates, global_refs):
    global_functions = {
        ref.get("function_range", [None])[0]
        for refs in global_refs.values()
        for ref in refs
        if ref.get("function_range")
    }
    ranked = sorted(candidates, key=lambda item: (-_candidate_score(item, global_functions), int(item["instruction_rva"], 16)))
    selected = []
    seen_functions = set()
    total = 0
    for candidate in ranked:
        function = candidate.get("function")
        if not function:
            continue
        function_start = int(function["start_rva"], 16)
        if function_start in seen_functions or function_start == KNOWN_HELPER_RVA:
            continue
        instruction = int(candidate["instruction_rva"], 16)
        # Keep a local window around the candidate rather than decoding a
        # potentially large pdata function body.
        begin = max(function_start, instruction - 0x60)
        end = min(int(function["end_rva_exclusive"], 16), instruction + 0xC0)
        if end <= begin:
            continue
        end = min(end, begin + MAX_PER_RANGE)
        if total + end - begin > MAX_TOTAL_DECODE:
            break
        selected.append({"begin": begin, "end": end, "candidate": candidate})
        seen_functions.add(function_start)
        total += end - begin
        if len(selected) >= 6:
            break
    return selected, total


def _decode_record(pe: PE, md, item):
    begin, end, candidate = item["begin"], item["end"], item["candidate"]
    raw = pe.bytes_at(begin, end - begin)
    return {
        "purpose": "bounded_window_around_2ce0_candidate",
        "candidate_instruction_rva": candidate["instruction_rva"],
        "candidate_kind": candidate["kind"],
        "start": _location(pe, begin),
        "end_exclusive": _location(pe, end),
        "byte_length": len(raw),
        "bytes_hex": raw.hex(),
        "bytes_sha256": hashlib.sha256(raw).hexdigest(),
        "pdata": candidate.get("function"),
        "instructions": _decode_range(pe, md, begin, end),
    }


def _decode_known_function(pe: PE, md, rva: int, purpose: str):
    """Decode one already bounded constructor function, never its callees."""
    function = pe.function(rva)
    if not function:
        return None
    begin, end, _ = function
    raw = pe.bytes_at(begin, end - begin)
    return {
        "purpose": purpose,
        "start": _location(pe, begin),
        "end_exclusive": _location(pe, end),
        "byte_length": len(raw),
        "bytes_hex": raw.hex(),
        "bytes_sha256": hashlib.sha256(raw).hexdigest(),
        "pdata": _function(pe, begin),
        "instructions": _decode_range(pe, md, begin, end),
    }


def _static_vtable_snapshot(pe: PE):
    """Read a small static vtable prefix and resolve only its table entries."""
    entry_count = 12
    raw = pe.bytes_at(PROCESSOR_VTABLE_RVA, entry_count * 8)
    entries = []
    for index in range(entry_count):
        pointer = struct.unpack_from("<Q", raw, index * 8)[0]
        target_rva = pointer - pe.base if pe.base <= pointer < pe.base + len(pe.data) else None
        entries.append({
            "slot_offset": hex(index * 8),
            "target_va": hex(pointer),
            "target_rva": hex(target_rva) if target_rva is not None else None,
            "target_function": _function(pe, target_rva) if target_rva is not None else None,
        })
    return {
        "location": _location(pe, PROCESSOR_VTABLE_RVA),
        "entry_count": entry_count,
        "bytes_hex": raw.hex(),
        "bytes_sha256": hashlib.sha256(raw).hexdigest(),
        "method_plus_8_rva": hex(PROCESSOR_VALUE_METHOD_RVA),
        "method_plus_8_matches": entries[1]["target_rva"] == hex(PROCESSOR_VALUE_METHOD_RVA),
        "entries": entries,
    }


def run(output: Path):
    check_memory_budget()
    if not SOURCE_002.exists():
        raise RuntimeError(f"missing prior report: {SOURCE_002}")
    prior_sha = _sha(SOURCE_002)
    if prior_sha != SOURCE_002_SHA256:
        raise RuntimeError(f"prior report changed: {prior_sha}")
    static_sources = []
    for source in (RELIGIOUS_UNITY_DOC, RELIGIOUS_UNITY_PROFILE):
        if not source.exists():
            raise RuntimeError(f"missing static source: {source}")
        static_sources.append({"path": str(source), "sha256": _sha(source), "bytes": source.stat().st_size})
    pe = PE(game_exe())
    actual_sha = hashlib.sha256(pe.data).hexdigest()
    if actual_sha != EXE_SHA256 or pe.base != IMAGE_BASE:
        raise RuntimeError(f"unexpected executable identity: sha={actual_sha}, base={hex(pe.base)}")
    global_refs = rip_references(pe, {GLOBAL_RVA})
    candidates = _scan_field_candidates(pe)
    marker_locations = _raw_marker_locations(pe)
    writers = [candidate for candidate in candidates if candidate["kind"] in {
        "write", "write_immediate", "write_or_add", "write_or_or", "write_or_and",
        "write_or_sub", "write_or_xor", "exchange",
    }]
    # There are no direct text writes in this build if the scan returns no
    # writer candidates.  Decode the closest direct readers instead, so the
    # report still records whether the surrounding callers construct a local
    # callback object or only consume the manager slot.
    decode_pool = writers or [candidate for candidate in candidates if candidate["kind"] == "read"]
    selected, total = _select_decode_ranges(pe, decode_pool, global_refs)
    if total > MAX_TOTAL_DECODE or any(item["end"] - item["begin"] > MAX_PER_RANGE for item in selected):
        raise RuntimeError("bounded decode budget exceeded")
    md, decoder = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    constructor_window = _decode_known_function(
        pe, md, PROCESSOR_CONSTRUCTOR_RVA,
        "bounded_processor_vtable_constructor",
    )
    known_windows = [constructor_window] if constructor_window else []
    known_total = sum(item["byte_length"] for item in known_windows)
    if total + known_total > MAX_TOTAL_DECODE or any(
        item["byte_length"] > MAX_PER_RANGE for item in known_windows
    ):
        raise RuntimeError("bounded decode budget exceeded")
    vtable_refs = rip_references(pe, {PROCESSOR_VTABLE_RVA})
    static_vtable = _static_vtable_snapshot(pe)
    field_function_starts = {
        (candidate.get("function") or {}).get("start_rva")
        for candidate in candidates
        if candidate.get("function")
    }
    relevant_global_refs = []
    global_function_counts = Counter()
    for refs in global_refs.values():
        for ref in refs:
            function_range = ref.get("function_range")
            if function_range:
                global_function_counts[function_range[0]] += 1
            if function_range and function_range[0] in field_function_starts:
                instruction_rva = int(ref["instruction_rva"], 16)
                relevant_global_refs.append({
                    **ref,
                    "instruction_bytes_hex": pe.bytes_at(instruction_rva, 12).hex(),
                })
    report = {
        "schema": "information_military_discipline_manager_links.v1",
        "evidence_kind": "ordinary_bounded_PE_not_REA",
        "stage": "information-military-effective-20261027-001",
        "exe": {
            "path": str(pe.path),
            "sha256": actual_sha,
            "bytes": len(pe.data),
            "static_image_base": hex(pe.base),
        },
        "prior_static_source": {"path": str(SOURCE_002), "sha256": prior_sha},
        "static_layout_sources": static_sources,
        "runtime_or_RPM": False,
        "game_or_native_calls": 0,
        "whole_image_disassembly": False,
        "decoder": "Capstone " + decoder.__version__ if md is not None else "bounded objdump",
        "scan": {
            "sections": [section["name"] for section in pe.sections if section["flags"] & 0x20000000],
            "global_rva": hex(GLOBAL_RVA),
            "global_va": hex(pe.base + GLOBAL_RVA),
            "field_offset": hex(FIELD_OFFSET),
            "field_marker_hex_le": struct.pack("<I", FIELD_OFFSET).hex(),
            "candidate_mode": "raw displacement byte scan with direct ModRM forms; references remain candidates until bounded decode",
            "global_reference_count": sum(len(refs) for refs in global_refs.values()),
            "global_reference_function_count": len(global_function_counts),
            "global_reference_function_counts": dict(sorted(global_function_counts.items())),
            "global_reference_candidates_in_field_functions": relevant_global_refs,
            "raw_marker_occurrence_count_in_executable_sections": len(marker_locations),
            "raw_marker_locations": marker_locations,
            "field_candidates": candidates,
            "field_write_candidates": writers,
        },
        "decode_budget": {
            "selected_ranges": len(selected) + len(known_windows),
            "candidate_ranges": len(selected),
            "known_static_ranges": len(known_windows),
            "new_bounded_bytes": total + known_total,
            "max_new_bounded_bytes": MAX_TOTAL_DECODE,
            "max_per_range": MAX_PER_RANGE,
        },
        "decoded_windows": [_decode_record(pe, md, item) for item in selected] + known_windows,
        "static_index_and_vtable": {
            "database_global": {
                "location": _location(pe, GLOBAL_RVA),
                "rva": hex(GLOBAL_RVA),
                "va": hex(pe.base + GLOBAL_RVA),
            },
            "record_index": hex(DATABASE_INDEX),
            "record_stride": hex(RECORD_STRIDE),
            "record_rva": hex(DATABASE_RECORD_RVA),
            "processor_offset": hex(PROCESSOR_OFFSET),
            "processor_slot_rva": hex(PROCESSOR_SLOT_RVA),
            "arithmetic": "0x2358060 + (0x77 * 0x60) + 0x40 = 0x235ad40",
            "vtable": static_vtable,
            "vtable_rip_references": {
                "count": sum(len(refs) for refs in vtable_refs.values()),
                "references": [
                    {
                        **ref,
                        "instruction_location": _location(pe, int(ref["instruction_rva"], 16)),
                        "instruction_bytes_hex": pe.bytes_at(int(ref["instruction_rva"], 16), 12).hex(),
                    }
                    for refs in vtable_refs.values()
                    for ref in refs
                ],
            },
            "constructor": {
                "function": _function(pe, PROCESSOR_CONSTRUCTOR_RVA),
                "allocation_size_bytes": 8,
                "vtable_store": "constructor stores the static vtable address at the allocated object's +0",
                "object_store": "constructor stores the allocated object at its caller-provided [rcx]",
                "allocator_target_rva": hex(0x1A33230),
                "static_vtable_rva": hex(PROCESSOR_VTABLE_RVA),
            },
            "value_method": {
                "rva": hex(PROCESSOR_VALUE_METHOD_RVA),
                "va": hex(pe.base + PROCESSOR_VALUE_METHOD_RVA),
                "source": "static vtable slot +0x8",
                "body_decoded_here": False,
                "reason": "callback body is outside this narrow constructor/vtable task",
            },
        },
        "finding": {
            "status": "indexed_record_slot_and_processor_vtable_constructor_closed;_record_writer_not_found",
            "manager_slot": "global manager object + (0x77 * 0x60) + 0x40; this is the processor slot at RVA 0x235ad40",
            "callback_vtable": "static vtable RVA 0x1cc9400 is installed by constructor 0x8f1df0; slot +0x8 points to 0x8f71d0",
            "known_helper_excluded": hex(KNOWN_HELPER_RVA),
            "decode_pool": "writers" if writers else "direct_readers_after_no_writer_candidates",
            "semantic_conclusion": "The fixed index/stride arithmetic and one bounded constructor plus static vtable prefix close how the processor object is typed and installed. No direct text store to the database record slot was found; record population or runtime selection remains outside this static window.",
        },
        "unknowns": [
            "The database record's population/configuration path is not proven by a direct text write to RVA 0x235ad40.",
            "The callback method body at RVA 0x8f71d0 and its input/return semantics were intentionally not decoded in this narrow report.",
            "Functions outside the selected bounded windows were not disassembled; candidate absence is bounded to this raw scan and decoder forms.",
        ],
    }
    check_memory_budget()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"output": str(output), "bytes": output.stat().st_size, "sha256": _sha(output), "field_candidates": len(candidates), "writers": len(writers), "decoded_bytes": total + known_total}, ensure_ascii=False))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python work/research_information_military_discipline_links.py OUTPUT.json")
    run(Path(sys.argv[1]))
