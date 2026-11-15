"""Bound the type-8 professionalism argument after ``fbe450``.

This is an ordinary, bounded PE follow-up.  It follows the actual
``fbe450`` callsite through the small record-builder and object helpers, and
checks the nearest UI consumers.  It deliberately does not treat the
unrelated ``raw * 1000`` helper as the professionalism scale: the value
consumer that interprets frame ``+0x28 == 8`` is still outside this bounded
chain.  No game, RPM, REA database, or production reader is used.
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
MAX_TOTAL_DECODE_BYTES = 8 * 1024

PRIOR_002 = ROOT / (
    "work/runtime/information-military-effective-20261027-001/"
    "professionalism-binding-002.json"
)
EXPECTED_PRIOR_002_SHA256 = (
    "2a219bfd1aaf79f35456124257d9fa83182b7eeead26ea8ba55fc17a659868dd"
)
PRIOR_003 = ROOT / (
    "work/runtime/information-military-effective-20261027-001/"
    "professionalism-binding-003.json"
)
EXPECTED_PRIOR_003_SHA256 = (
    "2b38155655a9f4b9fd80c3e09b89997ec6f770a413d4746746bae38821620c5e"
)
OUTPUT = ROOT / (
    "work/runtime/information-military-effective-20261027-001/"
    "professionalism-binding-004.json"
)

# Every range is a complete tiny helper or a small, exact pdata function.
# The sum is 1,068 bytes; no whole UI function is decoded here.
DECODE_RANGES = (
    (0x1A33274, 0x1A332E4, "record_builder_prefix"),
    (0x1A332E4, 0x1A3334F, "record_builder_tail"),
    (0x8EE90, 0x8EEB0, "record_callback"),
    (0x95660, 0x956BE, "string_cleanup"),
    (0x94F30, 0x94F79, "post_widget_string_copy"),
    (0x94510, 0x9457F, "post_widget_string_assign"),
    (0x94B00, 0x94C3C, "localized_string_builder"),
    (0x1EDE00, 0x1EDEBB, "tag7_sibling_builder"),
    # These three are raw leaf/thunk windows without pdata entries.
    (0x954C0, 0x954D0, "unrelated_raw_times_1000_leaf"),
    (0x954F0, 0x954FC, "placeholder_leaf"),
    (0x956C0, 0x956C8, "string_cleanup_thunk"),
)


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_pinned(path: Path, expected_sha256: str) -> dict[str, Any]:
    actual = _sha256_file(path)
    if actual != expected_sha256:
        raise RuntimeError(f"input_pin_mismatch:{path}:{actual}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"report_not_object:{path}")
    return value


def _decode(pe: PE, md: Any, begin: int, end: int) -> list[dict[str, Any]]:
    if end <= begin or end - begin > MAX_SINGLE_DECODE_BYTES:
        raise ValueError(f"decode range exceeds bound: {begin:#x}:{end:#x}")
    check_memory_budget()
    return _decode_range(pe, md, begin, end)


def _range_record(
    pe: PE, rows: list[dict[str, Any]], begin: int, end: int, label: str
) -> dict[str, Any]:
    raw = pe.bytes_at(begin, end - begin)
    if len(raw) != end - begin:
        raise RuntimeError(f"range_not_file_backed:{begin:#x}:{end:#x}")
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
        "instructions": rows,
    }


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


def _select(rows: list[dict[str, Any]], addresses: list[int]) -> list[dict[str, Any]]:
    by_rva = {int(row["rva"], 16): row for row in rows}
    return [
        by_rva.get(address, {"rva": hex(address), "decode_missing": True})
        for address in addresses
    ]


def _prior_range(prior: dict[str, Any], label: str) -> dict[str, Any]:
    for item in prior.get("new_bounded_ranges", []):
        if item.get("label") == label:
            return item
    raise RuntimeError(f"prior_range_missing:{label}")


def _prior_selected(prior: dict[str, Any], label: str, addresses: list[int]) -> list[dict[str, Any]]:
    return _select(_prior_range(prior, label).get("instructions", []), addresses)


def _expect_instruction(
    rows: list[dict[str, Any]], address: int, raw: str, operands: str | None = None
) -> None:
    by_rva = {int(row["rva"], 16): row for row in rows}
    row = by_rva.get(address)
    if row is None or row.get("bytes") != raw:
        raise RuntimeError(f"instruction_mismatch:{address:#x}")
    if operands is not None and row.get("operands") != operands:
        raise RuntimeError(f"operand_mismatch:{address:#x}")


def _call_target(raw: bytes, rva: int, instruction_length: int) -> int:
    # rel32 E8 target, used only for a few already-selected call rows.
    displacement = int.from_bytes(raw[1:5], "little", signed=True)
    return rva + instruction_length + displacement


def build_report() -> dict[str, Any]:
    executable = game_exe()
    size = executable.stat().st_size
    if size > MAX_EXE_BYTES:
        raise RuntimeError(f"refusing_executable_larger_than_bound:{size}")
    pe = PE(executable)
    exe_sha = _sha256_bytes(pe.data)
    if size != EXPECTED_EXE_BYTES or exe_sha != EXPECTED_EXE_SHA256:
        raise RuntimeError(f"unexpected_executable:{size}:{exe_sha}")
    if pe.base != EXPECTED_IMAGE_BASE:
        raise RuntimeError(f"unexpected_image_base:{pe.base:#x}")

    prior_002 = _load_pinned(PRIOR_002, EXPECTED_PRIOR_002_SHA256)
    prior_003 = _load_pinned(PRIOR_003, EXPECTED_PRIOR_003_SHA256)
    md, decoder = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    planned = sum(end - begin for begin, end, _ in DECODE_RANGES)
    if planned > MAX_TOTAL_DECODE_BYTES:
        raise RuntimeError(f"planned_decode_exceeds_bound:{planned}")
    decoded: dict[str, list[dict[str, Any]]] = {}
    ranges: list[dict[str, Any]] = []
    for begin, end, label in DECODE_RANGES:
        rows = _decode(pe, md, begin, end)
        decoded[label] = rows
        ranges.append(_range_record(pe, rows, begin, end, label))

    builder_tail = decoded["record_builder_tail"]
    callback = decoded["record_callback"]
    cleanup = decoded["string_cleanup"]
    post_copy = decoded["post_widget_string_copy"]
    post_assign = decoded["post_widget_string_assign"]
    placeholder = decoded["placeholder_leaf"]
    unrelated_times_1000 = decoded["unrelated_raw_times_1000_leaf"]
    cleanup_thunk = decoded["string_cleanup_thunk"]
    _expect_instruction(
        builder_tail,
        0x1A3330C,
        "490faff8",
        "rdi,r8",
    )
    _expect_instruction(callback, 0x8EE9D, "e8be670000", "0x140095660")
    _expect_instruction(cleanup, 0x95673, "488b09", "rcx,QWORD PTR [rcx]")
    _expect_instruction(post_copy, 0x94F45, "e816070000", "0x140095660")
    _expect_instruction(placeholder, 0x954F0, "b82d2d2d00", "eax,0x2d2d2d")
    _expect_instruction(placeholder, 0x954F5, "c3")
    _expect_instruction(unrelated_times_1000, 0x954C0, "69c2e8030000", "eax,edx,0x3e8")
    _expect_instruction(unrelated_times_1000, 0x954C6, "8901", "DWORD PTR [rcx],eax")
    _expect_instruction(cleanup_thunk, 0x956C0, "e99bffffff")

    callback_slot = pe.bytes_at(0x1B67860, 8)
    if callback_slot != bytes.fromhex("9099a74101000000"):
        raise RuntimeError("callback_slot_changed")
    callback_target = int.from_bytes(callback_slot, "little") - pe.base
    if callback_target != 0x1A79990:
        raise RuntimeError(f"unexpected_callback_thunk:{callback_target:#x}")
    thunk = pe.bytes_at(0x1A79990, 2)
    if thunk != bytes.fromhex("ffe0"):
        raise RuntimeError("callback_thunk_not_jmp_rax")

    prior_tail = _prior_range(prior_002, "professionalism_ui_tail")
    prior_call_rows = _prior_selected(
        prior_002,
        "professionalism_ui_tail",
        [
            0xFB9294,
            0xFB9299,
            0xFB929C,
            0xFB92A0,
            0xFB92A5,
            0xFB92A9,
            0xFB92AE,
            0xFB9394,
            0xFB93A8,
            0xFB93B4,
            0xFB93F1,
            0xFB9458,
            0xFB9472,
        ],
    )
    expected_targets = {
        0xFB9294: 0xFBE450,
        0xFB92A0: 0x94F30,
        0xFB92A9: 0x956C0,
        0xFB92AE: 0x954F0,
        0xFB9394: 0x94B00,
        0xFB93A8: 0x94510,
        0xFB93B4: 0x94F30,
        0xFB93F1: 0x954C0,
        0xFB9458: 0xD0070,
        0xFB9472: 0x1EDE00,
    }
    for row in prior_call_rows:
        rva = int(row["rva"], 16)
        if rva not in expected_targets:
            continue
        raw = bytes.fromhex(row["bytes"])
        if not raw or raw[0] != 0xE8:
            raise RuntimeError(f"prior_call_not_rel32:{rva:#x}")
        target = _call_target(raw, rva, len(raw))
        if target != expected_targets[rva]:
            raise RuntimeError(f"prior_call_target_changed:{rva:#x}:{target:#x}")

    # The prior report contains the exact fbe450 frame and the caller's bounded
    # tail.  Reuse it by hash; this run's new decode is limited to callees.
    fbe_frame = prior_003.get("fbe450_frame")
    if not isinstance(fbe_frame, dict):
        raise RuntimeError("prior_fbe_frame_missing")
    frame_fields = fbe_frame.get("fields", {})
    if frame_fields.get("type_tag_candidate", {}).get("raw_dword") != 8:
        raise RuntimeError("prior_frame_tag_changed")
    if frame_fields.get("raw_value_qword", {}).get("location") != "[RSP+0x98] = frame_base + 0x58":
        raise RuntimeError("prior_frame_value_location_changed")

    return {
        "schema": "information_military_professionalism_type8_consumer_static.v1",
        "status": "partial",
        "source_kind": "ordinary_pe_bounded_static_not_REA",
        "scope": "N03.army_professionalism.type8_numeric_consumer_boundary",
        "binary": {
            "path": str(executable),
            "size": size,
            "sha256": exe_sha,
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
                "planned_total_bytes": planned,
            },
            "scope_note": (
                "Only complete small callees/thunks around the fbe450 record path were decoded. "
                "The large fb4ba0..fba3d0 UI function and the generic formatter were not decoded "
                "again; its exact callsite rows are reused from the pinned prior report."
            ),
        },
        "source_pins": {
            "professionalism_binding_002": {
                "path": PRIOR_002.relative_to(ROOT).as_posix(),
                "sha256": EXPECTED_PRIOR_002_SHA256,
                "bytes": PRIOR_002.stat().st_size,
            },
            "professionalism_binding_003": {
                "path": PRIOR_003.relative_to(ROOT).as_posix(),
                "sha256": EXPECTED_PRIOR_003_SHA256,
                "bytes": PRIOR_003.stat().st_size,
            },
        },
        "new_bounded_ranges": ranges,
        "callback_indirection": {
            "slot": {
                **_location(pe, 0x1B67860),
                "raw_hex": callback_slot.hex(),
                "decoded_static_va": hex(pe.base + callback_target),
                "meaning": "indirect callback slot read by both record-builder functions",
            },
            "thunk": {
                **_location(pe, 0x1A79990),
                "raw_hex": pe.bytes_at(0x1A79990, 16).hex(),
                "instruction": "jmp rax",
                "target_selected_by_slot": "0x8ee90",
            },
        },
        "fbe450_to_ui_chain": {
            "caller": {
                "function_range": ["0xfb4ba0", "0xfba3d0"],
                "callsite_rva": "0xfb9294",
                "callsite_target": "0xfbe450",
                "callsite_source": "pinned professionalism-binding-002 professionalism_ui_tail",
            },
            "frame": {
                "base": "RSP+0x40",
                "type_tag_offset": "0x28",
                "type_tag_value": 8,
                "raw_value_offset": "0x58",
                "raw_value_location": "[RSP+0x98]",
                "source": "pinned professionalism-binding-003 fbe450_frame",
            },
            "immediate_post_call_rows": prior_call_rows[:7],
            "classification": {
                "fbe450": "builds/returns the destination object after placing the VALUE argument record",
                "0x94f30": "copies a 32-byte string/object and clears the source",
                "0x956c0": "jmp thunk to 0x95660 string cleanup",
                "0x954f0": "returns the literal integer 0x2d2d2d ('---'); no frame value input",
            },
        },
        "record_builder": {
            "prefix": {
                "rva": "0x1a33274",
                "range": ["0x1a33274", "0x1a332e4"],
                "role": "bounded callback/vector initialization",
            },
            "tail": {
                "rva": "0x1a332e4",
                "range": ["0x1a332e4", "0x1a3334f"],
                "role": "bounded record-builder loop",
                "arithmetic": {
                    "rva": "0x1a3330c",
                    "instruction": "imul rdi,r8",
                    "meaning": "pointer/index arithmetic for frame + 0x68 when called with rdx=0x68,r8=1",
                    "not_value_scaling": True,
                },
            },
            "callback": {
                "rva": "0x8ee90",
                "calls": ["0x95660"],
                "role": "string-like object cleanup/copy helper",
            },
            "numeric_consumer_found": False,
            "reason": (
                "The bounded builder and callback contain no conversion of frame+0x28 or frame+0x58. "
                "Their only imul is address arithmetic, and 0x95660 only handles string capacity/freeing."
            ),
        },
        "nearest_candidate_consumers": {
            "localized_string_builder_0x94b00": {
                "range": ["0x94b00", "0x94c3c"],
                "role": "NUL-terminated string/object construction and cleanup",
                "numeric_conversion_found": False,
            },
            "string_assign_0x94510": {
                "range": ["0x94510", "0x9457f"],
                "role": "string-like object copy followed by NUL scan/helper call",
                "numeric_conversion_found": False,
            },
            "unrelated_times_1000_leaf_0x954c0": {
                "range": ["0x954c0", "0x954d0"],
                "raw_hex": pe.bytes_at(0x954C0, 16).hex(),
                "instruction": "imul eax,edx,0x3e8; mov [rcx],eax; ret",
                "formula": "i32(edx) * 1000, low 32 bits",
                "callsite": {
                    "rva": "0xfb93f1",
                    "arguments_from_pinned_tail": {
                        "rcx": "[RBP+0x240]",
                        "edx": 1,
                    },
                },
                "connected_to_fbe450_frame": False,
                "scale_reuse_allowed": False,
                "reason": "The callsite is a later unrelated UI field and does not consume the VALUE frame or country+0x50 QWORD.",
            },
            "tag7_sibling_0x1ede00": {
                "range": ["0x1ede00", "0x1edebb"],
                "tag_rva": "0x1ede5a",
                "tag_value": 7,
                "raw_input": "DWORD PTR [RDI] copied to [RSP+0x90]",
                "meaning": "representation sibling only; does not define tag8 semantics or scale",
            },
        },
        "type8_dispatch": {
            "status": "not_located_within_bounded_callees",
            "searched_ranges": [
                ["0x1a33274", "0x1a3334f"],
                ["0x8ee90", "0x8eeb0"],
                ["0x94b00", "0x94c3c"],
                ["0x94510", "0x9457f"],
            ],
            "negative_evidence": [
                "No frame+0x28 comparison/branch or numeric conversion appears in these small callees.",
                "The fbe450 path calls 0x14b33a0 and 0x1a332e4, not the separately proven 0x14bc950 fixed-point formatter.",
            ],
            "minimum_cache_query_targets": [
                {"rva": "0xfb4ba0", "reason": "actual UI caller; follow object after 0xfb9294"},
                {"rva": "0xfbe450", "reason": "type8 frame producer; confirm record ABI"},
                {"rva": "0x1a332e4", "reason": "record-builder ABI/callback"},
                {"rva": "0x94f30", "reason": "first immediate post-call object consumer"},
                {"rva": "0x94510", "reason": "nearby string/template argument builder"},
            ],
        },
        "unit_and_scale": {
            "status": "unresolved",
            "closed": [
                "The frame carries type/tag candidate 8 and copies the country+0x50 QWORD verbatim into frame+0x58.",
                "The nearest bounded builder/object consumers do not transform that QWORD.",
                "A separate 0x954c0 raw*1000 leaf exists, but its callsite is disconnected and is not reusable evidence.",
            ],
            "unresolved": [
                "The consumer that interprets frame+0x28 == 8 is not identified.",
                "Therefore source scale, ratio-versus-percent convention, and any conversion to the percent locale directive remain unknown.",
            ],
            "do_not_infer": [
                "Do not apply signed_i32/1000 from 0x14bc950 without a callsite/ABI connection.",
                "Do not apply 0x954c0's *1000 helper to professionalism.",
                "Do not infer scale from the independent raw QWORD sample or from the locale percent directive alone.",
            ],
        },
        "conclusion": {
            "closed": [
                "The actual fbe450 callsite is 0xfb9294 in pdata function 0xfb4ba0..0xfba3d0.",
                "The record-builder chain is 0x1a332e4 -> indirect callback 0x8ee90 -> 0x95660, and it is string/object machinery rather than numeric scaling.",
                "The nearest post-call helpers 0x94f30/0x956c0/0x954f0 are object copy, cleanup, and placeholder helpers.",
            ],
            "unresolved": [
                "A type8 numeric formatter/dispatch branch beyond this object chain remains unclosed.",
                "Professionalism stays planned/partial at the storage-to-display unit boundary.",
            ],
            "publication": "Use the listed minimum cache query targets for pseudocode; do not publish a professionalism scale from this report.",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists() and not args.force:
        raise FileExistsError(f"refusing to overwrite existing report: {args.output}")
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "status": report["status"],
                "planned_total_bytes": report["method"]["decode_limits"]["planned_total_bytes"],
                "numeric_consumer_found": report["record_builder"]["numeric_consumer_found"],
                "type8_dispatch": report["type8_dispatch"]["status"],
                "unit_scale": report["unit_and_scale"]["status"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
