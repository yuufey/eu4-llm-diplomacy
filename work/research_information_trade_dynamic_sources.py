"""Generate the bounded static contract for the dynamic trade-source list.

This report deliberately does not attach to the game or use REA.  It decodes
only the list loop, the name lookup leaf, and two small formatter windows from
the pinned EU4 1.37.4 PE.  The existing raw entry capture is read only to
record the already-observed empty-list result; it is not used as a source of a
public dynamic-source value.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE, check_memory_budget, make_disassembler  # noqa: E402
from work.local_config import game_exe  # noqa: E402
from work.research_information_branch_inputs import _decode_range  # noqa: E402


EXPECTED_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
IMAGE_BASE = 0x140000000
MAX_SINGLE_DECODE_BYTES = 8 * 1024
MAX_TOTAL_DECODE_BYTES = 16 * 1024

STAGE = ROOT / "work" / "runtime" / "information-trade-source-details-20261027-001"
RAW_ENTRY_PATH = ROOT / "work" / "runtime" / "information-trade-share-20261027-001" / "native-trade-entry-inputs-002.json"
POWER_SOURCE_001 = ROOT / "work" / "runtime" / "information-trade-share-20261027-001" / "power-sources-source-001.json"
POWER_SOURCE_002 = ROOT / "work" / "runtime" / "information-trade-share-20261027-001" / "power-sources-source-002.json"
EXPECTED_INPUT_SHA256 = {
    POWER_SOURCE_001: "d80bed3a2dcf1a6adf80580a632f1864871b3a9c404e32ae45ad4a787a2d3488",
    POWER_SOURCE_002: "952d2bfc5e9d9dfb2e0012d834b0d548a281f0ac29d5e6b5fbfa062f99d010e9",
    RAW_ENTRY_PATH: "16b85c12b4f9acb0f2abeab219854a2ce4bb1d8b7bf3185d467b33b9f1dd877a",
}

# Every range is a half-open RVA range.  The longest range is 0x2e4 bytes and
# the total is well below the repository's bounded-analysis limits.
RANGES = (
    (0xB57B5E, 0xB57E42, "dynamic_list_loop"),
    (0x14B33A0, 0x14B35BA, "dynamic_name_lookup_leaf"),
    (0x14BCA00, 0x14BCAE7, "formatter_kind1_window"),
    (0x14BCD9C, 0x14BCE77, "formatter_kind2_window"),
)

LIST_SELECTED = (
    0xB57B5E, 0xB57B6C, 0xB57B6F, 0xB57B80, 0xB57B83, 0xB57B86,
    0xB57B91, 0xB57B94, 0xB57B9A, 0xB57BA1, 0xB57BA5, 0xB57BCF,
    0xB57BD2, 0xB57BD6, 0xB57BDB, 0xB57BDD, 0xB57C00, 0xB57C03,
    0xB57C08, 0xB57C0A, 0xB57C30, 0xB57C64, 0xB57E32, 0xB57E36,
    0xB57E39,
)
NAME_SELECTED = (
    0x14B33A0, 0x14B33C5, 0x14B33CF, 0x14B33D2, 0x14B33D8,
    0x14B33DB, 0x14B33E0, 0x14B33E2, 0x14B33F0, 0x14B33FB,
    0x14B33FE, 0x14B3501, 0x14B3509, 0x14B3515, 0x14B3572,
    0x14B359C, 0x14B359F,
)
KIND1_SELECTED = (
    0x14BCA00, 0x14BCA04, 0x14BCA2B, 0x14BCA33, 0x14BCA4B,
    0x14BCA50, 0x14BCA60, 0x14BCA69, 0x14BCA7B, 0x14BCA81,
    0x14BCA86, 0x14BCAA8,
)
KIND2_SELECTED = (
    0x14BCD9C, 0x14BCD9E, 0x14BCDC0, 0x14BCDC9, 0x14BCDE0,
    0x14BCDE5, 0x14BCDF4, 0x14BCDFD, 0x14BCE0F, 0x14BCE15,
    0x14BCE1A, 0x14BCE3A,
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _hex(value: int) -> str:
    return hex(value)


def _selected(rows, addresses):
    by_rva = {int(row["rva"], 16): row for row in rows}
    missing = [hex(address) for address in addresses if address not in by_rva]
    if missing:
        raise RuntimeError(f"decoder missed selected instruction(s): {missing}")
    return [by_rva[address] for address in addresses]


def _range_record(pe, md, begin: int, end: int, label: str):
    size = end - begin
    if size <= 0 or size > MAX_SINGLE_DECODE_BYTES:
        raise ValueError(f"invalid bounded range {begin:#x}..{end:#x}")
    rows = _decode_range(pe, md, begin, end)
    function = pe.function(begin)
    if function is None:
        pdata = None
    else:
        pdata = {
            "function_rva_range": [_hex(function[0]), _hex(function[1])],
            "unwind_rva": _hex(function[2]),
            "body_range_semantics": "pdata half-open function range; selected window is narrower",
        }
    return {
        "label": label,
        "rva_range": [_hex(begin), _hex(end)],
        "va_range": [_hex(IMAGE_BASE + begin), _hex(IMAGE_BASE + end)],
        "bytes": size,
        "bytes_sha256": _sha256_bytes(pe.bytes_at(begin, size)),
        "instruction_count": len(rows),
        "pdata": pdata,
        "instructions": rows,
    }, rows


def _runtime_empty_list_observation(path: Path):
    """Summarize existing raw capture without treating it as a new sample."""
    actual_sha = _sha256_file(path)
    expected_sha = EXPECTED_INPUT_SHA256.get(path)
    if expected_sha is not None and actual_sha != expected_sha:
        raise RuntimeError(f"unexpected existing evidence SHA-256 for {path}: {actual_sha}")
    data = json.loads(path.read_text(encoding="utf-8"))
    passes = data.get("trade_entries_inputs", [])
    pass_results = []
    for pass_record in passes:
        heads = []
        for entry in pass_record.get("trade_entry_nodes", []):
            if not entry.get("entry_read"):
                continue
            raw = bytes.fromhex(entry.get("entry_raw_hex", ""))
            if len(raw) < 0x98:
                raise ValueError("existing raw entry is shorter than entry+0x90+8")
            heads.append(int.from_bytes(raw[0x90:0x98], "little"))
        pass_results.append({
            "entry_read_count": len(heads),
            "nonzero_head_count": sum(head != 0 for head in heads),
            "head_values_all_zero": bool(heads) and all(head == 0 for head in heads),
            "head_offset": "0x90",
            "head_width_bytes": 8,
        })
    return {
        "path": str(path.relative_to(ROOT)).replace("\\", "/"),
        "sha256": _sha256_file(path),
        "evidence_kind": data.get("evidence_kind"),
        "status": data.get("status"),
        "no_new_sampling": True,
        "passes": len(pass_results),
        "pass_results": pass_results,
        "identity": {
            "country": data.get("country"),
            "game_version": data.get("target_build", {}).get("version"),
            "exe_sha256": data.get("target_build", {}).get("expected_exe_sha256"),
            "session_id": data.get("strict_identity_contract", {}).get("session_id"),
            "game_date_raw": data.get("strict_identity_contract", {}).get("game_date_raw"),
        },
        "interpretation": (
            "The two existing raw passes observed empty entry+0x90 heads for all "
            "80 true-predicate nodes. This is an empty-list observation, not "
            "evidence that the static linked-list shape is absent."
        ),
    }


def build_report():
    check_memory_budget()
    exe = game_exe()
    pe = PE(exe)
    exe_sha = _sha256_file(exe)
    if exe_sha != EXPECTED_SHA256:
        raise RuntimeError(f"unexpected executable SHA-256: {exe_sha}")
    md, _capstone = make_disassembler(None)

    decoded = []
    rows_by_label = {}
    total = 0
    for begin, end, label in RANGES:
        total += end - begin
        if total > MAX_TOTAL_DECODE_BYTES:
            raise RuntimeError("bounded decode total exceeded")
        record, rows = _range_record(pe, md, begin, end, label)
        decoded.append(record)
        rows_by_label[label] = rows

    static_inputs = []
    for path, role in ((POWER_SOURCE_001, "prior B57700 linked-list report"),
                       (POWER_SOURCE_002, "prior 14BC950 formatter report")):
        actual_sha = _sha256_file(path)
        expected_sha = EXPECTED_INPUT_SHA256.get(path)
        if expected_sha is not None and actual_sha != expected_sha:
            raise RuntimeError(f"unexpected prior report SHA-256 for {path}: {actual_sha}")
        static_inputs.append({
            "path": str(path.relative_to(ROOT)).replace("\\", "/"),
            "sha256": actual_sha,
            "role": role,
            "evidence_kind": "prior_ordinary_static_report",
        })

    list_rows = rows_by_label["dynamic_list_loop"]
    name_rows = rows_by_label["dynamic_name_lookup_leaf"]
    kind1_rows = rows_by_label["formatter_kind1_window"]
    kind2_rows = rows_by_label["formatter_kind2_window"]

    return {
        "schema": "information.trade_power.dynamic_sources_static.v1",
        "report_id": "information-trade-dynamic-source-001",
        "batch": 46,
        "stage": "information-trade-source-details-20261027-001",
        "generated_on": "2026-10-27",
        "status": "partial_static_dynamic_list_contract",
        "scope": {
            "topic_id": "T04",
            "field": "sources",
            "object": "trade_node",
            "question": (
                "Close the bounded shape and display path of the entry+0x90 "
                "dynamic source list without assigning an unproven unit or sum."
            ),
            "mode": "ordinary bounded PE analysis plus reuse of prior raw evidence",
            "no_game": True,
            "no_runtime_sampling": True,
            "no_rea": True,
            "no_production_changes": True,
            "single_decode_limit_bytes": MAX_SINGLE_DECODE_BYTES,
            "total_decode_limit_bytes": MAX_TOTAL_DECODE_BYTES,
            "decoded_bytes_total": total,
        },
        "target": {
            "game_version": "1.37.4",
            "exe_path": str(exe),
            "exe_sha256": exe_sha,
            "image_base_va": _hex(IMAGE_BASE),
            "address_rule": "RVA and VA are separate; VA=image_base_va+RVA; all ranges are half-open",
        },
        "input_evidence": static_inputs,
        "runtime_evidence": _runtime_empty_list_observation(RAW_ENTRY_PATH),
        "decoded_code_ranges": [
            {key: value for key, value in record.items() if key != "instructions"}
            for record in decoded
        ],
        "decoder": {
            "engine": "capstone if installed, otherwise bounded objdump",
            "range_reader": "work.research_information_branch_inputs._decode_range",
            "all_decoded_bytes_are_bounded": True,
            "no_whole_image_disassembly": True,
        },
        "selected_instructions": {
            "dynamic_list_loop": _selected(list_rows, LIST_SELECTED),
            "dynamic_name_lookup_leaf": _selected(name_rows, NAME_SELECTED),
            "formatter_kind1": _selected(kind1_rows, KIND1_SELECTED),
            "formatter_kind2": _selected(kind2_rows, KIND2_SELECTED),
        },
        "static_contract": {
            "chain": {
                "head": {
                    "entry_offset": "0x90",
                    "read": "qword",
                    "rva": "0xb57b5e",
                    "instruction": "mov rbx,QWORD PTR [r13+0x90]",
                },
                "link": {
                    "p_item_offset": "0x0",
                    "p_next_offset": "0x10",
                    "item_read": "QWORD [p]",
                    "next_read": "QWORD [p+0x10]",
                    "tail_condition": "p==0",
                    "evidence_rvas": ["0xb57b80", "0xb57e32", "0xb57e39"],
                },
                "native_order": [
                    "load item",
                    "load item+0x34 raw DWORD",
                    "format value with 0x14bc950 kind=2",
                    "resolve item+0x10 name object to a NUL-terminated character pointer",
                    "lookup/construct localized destination through 0x14b33a0",
                    "append the name/value pair through 0x1400e3b80",
                    "load p+0x10 and continue",
                ],
                "per_row_filter": {
                    "observed_before_format": "none",
                    "observed_before_name_lookup": "none",
                    "head_only_guard": "test rbx,rbx; je",
                    "raw_zero_or_negative_is_not_skipped_in_window": True,
                    "caveat": "unknown callee semantics do not authorize a public row filter",
                },
            },
            "value": {
                "raw_source": "DWORD [item+0x34]",
                "offset_from_item": "0x34",
                "width_bytes": 4,
                "load_rva": "0xb57b83",
                "load_kind": "DWORD bits copied to a local slot",
                "formatter_call": {
                    "rva": "0xb57ba5",
                    "va": _hex(IMAGE_BASE + 0xB57BA5),
                    "target_rva": "0x14bc950",
                    "rcx": "&local_string_at_rbp+0x58",
                    "rdx": "&local_i32_at_rbp+0xc0",
                    "r8d": 2,
                    "r9b": 1,
                },
                "numeric_presentation": {
                    "kind2_and_kind1": (
                        "Both bounded helper windows load a signed DWORD, use the "
                        "0x10624dd3 reciprocal path, multiply the integer quotient "
                        "by 0x3e8, and format a decimal remainder."
                    ),
                    "scale": "1000 is visible in the formatter arithmetic",
                    "unit": "unknown",
                    "percentage_vs_absolute": "unresolved",
                    "trade_power_point_vs_modifier": "unresolved",
                    "do_not_sum": True,
                    "reason": "no dynamic row label/unit or runtime non-empty row is available",
                },
            },
            "name": {
                "object_base": "item+0x10",
                "representation": "MSVC-like string object candidate; exact C++ type remains unresolved",
                "capacity_field": {
                    "offset_from_object": "0x18",
                    "effective_item_offset": "0x28",
                    "read": "QWORD [item+0x10+0x18]",
                    "threshold": "0x10",
                    "evidence_rva": "0xb57bd6",
                },
                "pointer_selection": {
                    "short_capacity": "char pointer = object base (item+0x10, inline storage)",
                    "long_capacity": "char pointer = QWORD [object base] (QWORD [item+0x10])",
                    "evidence_rva": ["0xb57bdb", "0xb57bdd"],
                },
                "termination": "caller scans bytes until NUL; no length field is consumed in this window",
                "construction": {
                    "rva": "0xb57c0f",
                    "target_rva": "0x95110",
                    "meaning": "construct/copy temporary string from selected pointer and scanned length; exact C++ ABI unresolved",
                },
                "lookup": {
                    "call_rva": "0xb57c30",
                    "target_rva": "0x14b33a0",
                    "destination": "&local_string_at_rbp-0x28 (RCX)",
                    "source": "&temporary_name_at_rsp+0x38 (RDX)",
                    "r8d": 0,
                    "r9d": 0,
                    "leaf_evidence": {
                        "hash": "FNV-1a-like NUL-terminated byte loop",
                        "lookup_call_rva": "0x16faf60",
                        "destination_string_initialization_rvas": ["0x14b3501", "0x14b3509", "0x14b3515"],
                    },
                },
                "display_semantics": {
                    "fixed_literal_label": False,
                    "source_is_runtime_text": True,
                    "locale_key": "candidate_not_proven",
                    "dynamic_template": "unknown",
                    "literal_display": "not established",
                    "classification": "dynamic_lookup_candidate",
                    "reason": "the leaf hashes the NUL-terminated input and performs a table lookup, but the dynamic item text and locale table are not captured here",
                },
            },
        },
        "bounded_read_schema": {
            "entry_head": {
                "offset": "0x90",
                "width_bytes": 8,
                "read_kind": "pointer",
                "required_before_follow": ["validated entry address", "pointer readability/range guard"],
            },
            "link": {
                "item_offset": "0x0",
                "next_offset": "0x10",
                "pointer_width_bytes": 8,
                "max_nodes": "caller-supplied finite cap; static report does not close runtime count",
                "cycle_policy": "seen-pointer set; cycle returns unknown",
                "null_item_policy": "unknown/reject before item-field reads",
            },
            "item": {
                "value_offset": "0x34",
                "value_width_bytes": 4,
                "preserve": ["raw_hex", "raw_bits", "signed_i32_view"],
                "normalization": "none until unit/semantic contract is closed",
            },
            "name": {
                "object_offset": "0x10",
                "capacity_offset_from_object": "0x18",
                "inline_threshold": 16,
                "heap_pointer_offset_from_object": "0x0",
                "inline_pointer": "object_base",
                "max_name_bytes": "caller-supplied finite cap",
                "read_until": "NUL",
                "locale_resolution": "retain raw input and lookup status; do not synthesize display text",
            },
            "output_row": {
                "status": "unknown until a non-empty chain and unit/locale guards are available",
                "raw_value_hex": "required",
                "raw_name_bytes_or_key": "required",
                "formatted_value": "optional evidence only; not a normalized power amount",
                "order": "head-to-tail native link order",
            },
        },
        "unknowns": [
            "Runtime list count, non-empty values, list ownership, and freshness are not closed; the reused two-pass capture had all heads zero.",
            "The exact C++ type and allocator/ownership rules for the link and item objects are not closed.",
            "The kind=2 formatter's public unit is not closed; visible division-by-1000 formatting does not prove percentage versus absolute trade power or modifier semantics.",
            "The dynamic item+0x10 text is not proven to be a locale key, a dynamic template, or already-display text; 0x14b33a0 is only a lookup candidate from the bounded leaf.",
            "Exact 0x1400e3b80 row-builder/output container semantics and any downstream filtering are not closed.",
            "No source sum or replacement for country_power/total_power is authorized; item+0x34 values must not be added as power points.",
        ],
        "conclusion": {
            "closed": [
                "entry+0x90 head and p/item/next offsets",
                "item+0x34 raw DWORD load",
                "item+0x10 string-object pointer selection with object+0x18 capacity threshold",
                "head-to-tail processing order and the kind=2/name/append call chain",
                "visible fixed-point 1000 presentation arithmetic in kind=1 and kind=2 formatter paths",
            ],
            "not_publishable": [
                "normalized dynamic-source unit/value",
                "power-point or modifier classification",
                "locale-resolved row label",
                "sum of dynamic rows as trade power",
            ],
            "next_implementation_boundary": (
                "A reader may capture a finite, cycle-checked raw chain with raw name bytes, "
                "raw value bits, and formatter provenance. It must return unknown for a "
                "missing/non-readable/cyclic/over-cap chain, retain raw names when lookup "
                "is unresolved, and keep the row value separate from normalized power fields."
            ),
        },
        "verification": {
            "exe_sha256_checked": True,
            "prior_report_sha256_checked": True,
            "existing_runtime_raw_sha256_checked": True,
            "json_self_validated_by_writer": True,
            "game_access": False,
            "rea_access": False,
            "production_files_changed": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=STAGE / "dynamic-source-001.json",
    )
    args = parser.parse_args()
    report = build_report()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # Parse the exact bytes that were written so a malformed report cannot be
    # mistaken for a completed bounded analysis.
    json.loads(output.read_text(encoding="utf-8"))
    print(json.dumps({
        "path": str(output.relative_to(ROOT)).replace("\\", "/"),
        "sha256": _sha256_file(output),
        "decoded_bytes_total": report["scope"]["decoded_bytes_total"],
        "range_count": len(report["decoded_code_ranges"]),
        "runtime_nonzero_heads": [
            p["nonzero_head_count"] for p in report["runtime_evidence"]["pass_results"]
        ],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
