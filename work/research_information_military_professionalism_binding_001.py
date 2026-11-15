"""Bound the country binding and raw-width contract for army_professionalism.

This follow-up is ordinary, bounded PE analysis only.  It closes the local
``R15`` def-use question in the already identified country writer by decoding
that one 19,323-byte ``.pdata`` function in two ranges (each below the local
16 KiB limit).  The small serializer and UI reports are reused as pinned
prior evidence; this script does not open the game, use RPM/REA, or modify a
production profile.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE, check_memory_budget, make_disassembler  # noqa: E402
from work.local_config import game_exe  # noqa: E402
from work.research_information_branch_inputs import _decode_range  # noqa: E402


EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
EXPECTED_EXE_BYTES = 38_463_016
EXPECTED_IMAGE_BASE = 0x140000000
MAX_EXE_BYTES = 64 * 1024 * 1024
MAX_SINGLE_DECODE_BYTES = 16 * 1024
MAX_TOTAL_DECODE_BYTES = 48 * 1024

WRITER_START = 0x2DC6E0
WRITER_END = 0x2E125B
# The writer is 19,323 bytes.  Splitting at a non-instruction boundary is
# safe for this report because Capstone is fed each slice from its own start;
# selected instructions are all away from the split and the byte hashes pin
# the exact ranges.  The purpose is to inspect register writes, not to infer
# semantics from a truncated call at the split.
DECODE_RANGES = (
    (WRITER_START, 0x2E0000, "country_writer_part_a"),
    (0x2E0000, WRITER_END, "country_writer_part_b"),
)

TOKEN_RVA = 0x2231038
TOKEN_ID = 0x36D6
TOKEN_TEXT = b"army_professionalism\0"
SERIALIZER_RVA = 0x1707A50
SERIALIZER_FORMAT_RVA = 0x1DBF524

PRIOR_PATHS = {
    "country_writer_contract": ROOT
    / "work/runtime/information-loaded-tasks-20261024-001/delivery/files/work/runtime/information-branches-20261024-001/country-flag-contract.json",
    "professionalism_code_001": ROOT
    / "work/runtime/information-military-quality-20261027-001/professionalism-code-001.json",
    "professionalism_ui_001": ROOT
    / "work/runtime/information-military-quality-20261027-001/professionalism-ui-001.json",
    "tradition_source_001": ROOT
    / "work/runtime/information-military-quality-20261027-001/tradition-source-001.json",
    "tradition_source_002": ROOT
    / "work/runtime/information-military-quality-20261027-001/tradition-source-002.json",
    "tradition_source_003": ROOT
    / "work/runtime/information-military-quality-20261027-001/tradition-source-003.json",
}


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _location(pe: PE, rva: int) -> dict[str, Any]:
    offset = pe.to_offset(rva)
    section = None
    if offset is not None:
        for candidate in pe.sections:
            if candidate["raw"] <= offset < candidate["raw"] + candidate["size"]:
                section = candidate["name"]
                break
    return {
        "rva": hex(rva),
        "static_va": hex(pe.base + rva),
        "file_offset": None if offset is None else hex(offset),
        "section": section,
    }


def _decode(pe: PE, md, begin: int, end: int) -> list[dict[str, Any]]:
    if end <= begin or end - begin > MAX_SINGLE_DECODE_BYTES:
        raise ValueError(f"decode range exceeds bound: {begin:#x}:{end:#x}")
    check_memory_budget()
    return _decode_range(pe, md, begin, end)


def _range_record(
    pe: PE, rows: list[dict[str, Any]], begin: int, end: int, label: str
) -> dict[str, Any]:
    raw = pe.bytes_at(begin, end - begin)
    if len(raw) != end - begin:
        raise ValueError(f"range is not file-backed: {begin:#x}:{end:#x}")
    function = pe.function(begin)
    return {
        "label": label,
        "start_rva": hex(begin),
        "end_rva_exclusive": hex(end),
        "start_va": hex(pe.base + begin),
        "end_va_exclusive": hex(pe.base + end),
        "byte_length": len(raw),
        "bytes_sha256": _sha256_bytes(raw),
        "function_boundary_from_pdata": None
        if function is None
        else [hex(function[0]), hex(function[1])],
        "decoded_instruction_count": len(rows),
    }


def _find(rows: list[dict[str, Any]], rva: int) -> dict[str, Any]:
    for row in rows:
        if int(row["rva"], 16) == rva:
            return row
    return {"rva": hex(rva), "decode_missing": True}


def _rows_by_rva(decoded: dict[str, list[dict[str, Any]]]) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}
    for rows in decoded.values():
        for row in rows:
            result[int(row["rva"], 16)] = row
    return result


def _prior_report(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(path)
    return json.loads(path.read_text(encoding="utf-8"))


def _serializer_evidence(prior_code: dict[str, Any]) -> dict[str, Any]:
    serializer_range = None
    for item in prior_code.get("ranges", []):
        if item.get("start_rva") == hex(SERIALIZER_RVA) or item.get("start_rva") == "0x1707a50":
            serializer_range = item
            break
    if serializer_range is None:
        raise ValueError("pinned professionalism code report lacks serializer range")
    rows: list[dict[str, Any]] = []
    for item in prior_code["ranges"]:
        if item is serializer_range:
            rows = item.get("instructions", [])
            break
    by_rva = {int(row["rva"], 16): row for row in rows}
    required = (0x1707A60, 0x1707A68, 0x1707A6B, 0x1707A77, 0x1707A87)
    selected = [by_rva.get(rva, {"rva": hex(rva), "decode_missing": True}) for rva in required]
    arithmetic = {
        "div",
        "idiv",
        "imul",
        "mul",
        "sar",
        "shr",
        "shl",
        "sal",
        "cvtsi2sd",
        "cvttsd2si",
    }
    arithmetic_rows = [row for row in rows if row.get("mnemonic", "").lower() in arithmetic]
    if not any("QWORD PTR [rbx]" in row.get("operands", "") for row in rows):
        raise ValueError("serializer body does not contain the expected QWORD load")
    if arithmetic_rows:
        raise ValueError(f"unexpected arithmetic in serializer body: {arithmetic_rows}")
    return {
        "range": {
            "start_rva": serializer_range.get("start_rva", "0x1707a50"),
            "end_rva_exclusive": serializer_range.get("end_rva_exclusive", "0x1707ab1"),
            "bytes_sha256": serializer_range["bytes_sha256"],
            "byte_length": serializer_range.get("byte_length", 97),
            "provenance": "professionalism-code-001",
        },
        "selected_instructions": selected,
        "arithmetic_mnemonics_found": [],
    }


def build_report() -> dict[str, Any]:
    path = game_exe()
    size = path.stat().st_size
    if size > MAX_EXE_BYTES:
        raise ValueError(f"refusing executable larger than {MAX_EXE_BYTES} bytes")
    pe = PE(path)
    digest = _sha256_bytes(pe.data)
    if digest != EXPECTED_EXE_SHA256 or size != EXPECTED_EXE_BYTES:
        raise ValueError(f"unexpected executable identity: {size} bytes {digest}")
    if pe.base != EXPECTED_IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.base:#x}")
    function = pe.function(WRITER_START)
    if function is None or function[:2] != (WRITER_START, WRITER_END):
        raise ValueError(f"unexpected .pdata country-writer boundary: {function}")

    md, decoder = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    planned_decode = sum(end - begin for begin, end, _ in DECODE_RANGES)
    if planned_decode != WRITER_END - WRITER_START or planned_decode > MAX_TOTAL_DECODE_BYTES:
        raise ValueError("bounded decode accounting mismatch")
    decoded: dict[str, list[dict[str, Any]]] = {}
    ranges: list[dict[str, Any]] = []
    for begin, end, label in DECODE_RANGES:
        rows = _decode(pe, md, begin, end)
        decoded[label] = rows
        ranges.append(_range_record(pe, rows, begin, end, label))
    all_rows = _rows_by_rva(decoded)

    init = _find(list(all_rows.values()), 0x2DC708)
    if init.get("operands") != "r15,rcx":
        raise ValueError(f"unexpected R15 initialization: {init}")
    assignment_rows = []
    restore_rows = []
    for row in all_rows.values():
        operands = row.get("operands", "").strip().lower()
        destination = operands.split(",", 1)[0].strip()
        if destination in {"r15", "r15d"} and row.get("mnemonic", "").lower() not in {"push", "pop"}:
            assignment_rows.append(row)
        if row.get("mnemonic", "").lower() == "pop" and destination == "r15":
            restore_rows.append(row)
    if len(assignment_rows) != 1 or int(assignment_rows[0]["rva"], 16) != 0x2DC708:
        raise ValueError(f"unexpected R15 assignments: {assignment_rows}")
    post_init_assignments = [
        row for row in assignment_rows if int(row["rva"], 16) > 0x2DC708
    ]
    if post_init_assignments:
        raise ValueError(f"R15 was rewritten after entry alias: {post_init_assignments}")
    if len(restore_rows) != 1:
        raise ValueError(f"unexpected R15 restore count: {restore_rows}")

    token_raw = pe.bytes_at(TOKEN_RVA, 4 + len(TOKEN_TEXT))
    if token_raw[:4] != TOKEN_ID.to_bytes(4, "little") or token_raw[4:] != TOKEN_TEXT:
        raise ValueError(f"unexpected professionalism token bytes: {token_raw.hex()}")
    format_raw = pe.bytes_at(SERIALIZER_FORMAT_RVA, 8)
    if format_raw[:5] != b"%lld\0":
        raise ValueError(f"unexpected serializer format literal: {format_raw.hex()}")

    prior = {}
    prior_json = {}
    for name, prior_path in PRIOR_PATHS.items():
        prior[name] = {
            "path": prior_path.relative_to(ROOT).as_posix(),
            "sha256": _sha256_file(prior_path),
        }
        if name in {"country_writer_contract", "professionalism_code_001"}:
            prior_json[name] = _prior_report(prior_path)

    serializer = _serializer_evidence(prior_json["professionalism_code_001"])
    relevant_rvas = (
        0x2DC708,
        0x2DF1D7,
        0x2DF51E,
        0x2DFC28,
        0x2DFC35,
        0x2DFC39,
        0x2DFC3E,
        0x2DFC41,
        0x2E124F,
    )
    selected = {hex(rva): all_rows.get(rva, {"rva": hex(rva), "decode_missing": True}) for rva in relevant_rvas}
    r15_mentions = [row for row in all_rows.values() if "r15" in row.get("operands", "").lower()]

    return {
        "schema": "information_military_professionalism_country_binding_static.v1",
        "status": "partial",
        "source_kind": "ordinary_pe_bounded_static_not_REA",
        "scope": "N03.army_professionalism.country_field_binding",
        "binary": {
            "path": str(path),
            "size": size,
            "sha256": digest,
            "image_base": hex(pe.base),
            "version_pin": "EU4 1.37.4",
        },
        "method": {
            "game_or_rpm": False,
            "rea": False,
            "native_calls": False,
            "decoder": "capstone" if decoder is not None else "bounded_objdump_fallback",
            "decode_limits": {
                "max_single_bytes": MAX_SINGLE_DECODE_BYTES,
                "max_total_bytes": MAX_TOTAL_DECODE_BYTES,
                "planned_total_bytes": planned_decode,
            },
            "scope_note": "Only the already pinned .pdata country writer was decoded, split into two bounded slices to verify R15 def-use; no whole-file scan or large UI re-decode was performed.",
        },
        "prior_sources": prior,
        "bounded_ranges": ranges,
        "token": {
            "id": hex(TOKEN_ID),
            "text": "army_professionalism",
            "location": _location(pe, TOKEN_RVA),
            "raw_hex": token_raw.hex(),
            "evidence": "exact token/string pair immediately preceding the field serializer registration data",
        },
        "selected_instructions": selected,
        "r15_def_use": {
            "function_rva_range": [hex(WRITER_START), hex(WRITER_END)],
            "function_static_va_range": [hex(pe.base + WRITER_START), hex(pe.base + WRITER_END)],
            "entry_alias": "MOV R15,RCX at 0x2dc708",
            "assignment_count": len(assignment_rows),
            "post_entry_assignments": post_init_assignments,
            "restore": restore_rows,
            "r15_mention_count": len(r15_mentions),
            "result": "R15 remains the first argument (RCX) throughout this complete .pdata body; no R15/R15D destination write occurs after the entry copy.",
            "country_role_evidence": {
                "prior_contract": "The pinned ordinary-static country-writer report labels the same .pdata range 0x2dc6e0..0x2e125b and records country-layout field serialization.",
                "same_object_known_country_field": "At 0x2df51e the same R15 base addresses +0xe40, the army_tradition country cache closed by tradition-source-002/003; the professionalism field uses the same unchanged base at +0x50.",
                "runtime_identity": "not observed: this static report does not claim that a particular runtime call is the FRA object.",
            },
        },
        "field_contract": {
            "field": "army_professionalism",
            "country_object_alias": {
                "status": "closed_static_entry_alias",
                "expression": "country = R15 = entry RCX; field address = country + 0x50",
                "evidence_rva": "0x2dfc35",
                "token_evidence_rva": "0x2dfc39",
                "serializer_call_rva": "0x2dfc41",
            },
            "storage": {
                "offset": "0x50",
                "address_expression": "&country[0x50]",
                "consumer_load": "QWORD PTR [R8] at serializer 0x1707a68, with R8=&country[0x50]",
                "width": "64-bit",
                "signedness": "signed textual interpretation at the pinned %lld format; the machine-level QWORD load itself preserves the raw 64-bit bit pattern",
            },
            "serializer": {
                "rva": hex(SERIALIZER_RVA),
                "static_va": hex(pe.base + SERIALIZER_RVA),
                "format_literal": {
                    "location": _location(pe, SERIALIZER_FORMAT_RVA),
                    "raw_hex": format_raw.hex(),
                    "text": "%lld",
                    "meaning": "signed long-long decimal formatting",
                },
                "evidence": serializer,
                "scale_operation": {
                    "status": "none_in_this_body",
                    "reason": "The pinned serializer body loads and forwards the QWORD; no DIV/IDIV/MUL/IMUL/shift conversion is present.",
                },
            },
            "unit_and_scale": {
                "status": "unresolved",
                "raw_contract": "read as signed int64/raw QWORD for this serializer path",
                "reason": "The serializer does not scale the value.  The archived UI candidates at 0xd02da0 and 0xd03d90 read different formatter-local objects (+0x68 and +0x68/+0x108), and no bounded alias links either path to country+0x50.",
                "do_not_infer": [
                    "Do not reuse the UI candidate scale 32768 as the country+0x50 source scale.",
                    "Do not publish a ducat/percent/ratio unit from the %lld serializer alone.",
                ],
            },
        },
        "minimum_remaining_gap": {
            "status": "runtime_and_semantic_gap",
            "items": [
                "A runtime-independent source/producer or a bounded direct caller is still needed to prove the public unit/scale of country+0x50.",
                "The static alias is country-writer entry RCX, but no runtime observation proves which call supplies FRA.",
                "The two UI ratio/percent candidates remain separate until a caller or object-layout chain connects them to +0x50.",
            ],
            "next_narrow_entry": "A direct source/producer for country+0x50 or a direct caller that supplies the country object and labels the UI path; no broader decode is justified by this report.",
        },
        "conclusion": {
            "country_binding": "closed for the static country-writer object alias: R15 is entry RCX with no later rewrite, and token 0x36d6 serializes country+0x50",
            "raw_width": "closed as signed QWORD at the serializer boundary",
            "scale_unit": "not closed; serializer has no conversion and UI candidates are not statically linked",
            "publication": "keep N03 professionalism partial/planned until an independent source or runtime contract closes scale/unit and FRA identity",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT
        / "work/runtime/information-military-effective-20261027-001/professionalism-binding-001.json",
    )
    args = parser.parse_args()
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "status": report["status"],
                "planned_total_decode_bytes": report["method"]["decode_limits"]["planned_total_bytes"],
                "country_binding": report["conclusion"]["country_binding"],
                "raw_width": report["conclusion"]["raw_width"],
                "scale_unit": report["conclusion"]["scale_unit"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
