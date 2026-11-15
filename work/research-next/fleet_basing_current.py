"""Bounded ordinary-PE review of the 1.37.4 fleet-basing predicates.

This source-only probe verifies the two fleet-access action vtables in the
fixed 1.37.4 executable and records only small predicate/container windows.
It does not call the game, REA, RPM, MCP, or any production reader.  The
predicate methods are retained as current-container candidates; their boolean
result is not promoted to a complete relation-state serializer.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

# Allow the bounded helper imports when this file is invoked directly from
# PowerShell rather than as a package module.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from work.discover_diplomacy import PE
from work.research_information_branch_inputs import _decode_range


ROOT = Path(__file__).resolve().parents[2]
TARGET_PATH = Path(
    r"D:\Downloads\Europa Universalis IV（1.37.4）\Europa Universalis IV\eu4.exe"
)
TARGET_VERSION = "1.37.4"
TARGET_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
IMAGE_BASE = 0x140000000
DEFAULT_OUTPUT = ROOT / (
    "work/runtime/information-relation-remaining-20261027-001/"
    "fleet-basing-current-source-002.json"
)

# These are deliberately small instruction windows around the endpoint and
# container accesses.  The complete methods are recorded through .pdata
# boundaries, but are never disassembled wholesale.
DECODE_WINDOWS: tuple[tuple[str, int, int], ...] = (
    ("fleet_plus80_endpoint_and_row", 0x52FC40, 0x52FCB1),
    ("fleet_plus80_fallback_list", 0x53003A, 0x5300D7),
    ("fleet_plus80_item_scan", 0x53013B, 0x53019E),
    ("offer_plus80_endpoint_and_row", 0x533FF8, 0x5340A1),
    ("offer_plus80_reciprocal_row", 0x534172, 0x5341A7),
    ("offer_plus80_reciprocal_branch", 0x5344A1, 0x5344D4),
)

VECTORS = (
    {
        "name": "fleet_access",
        "vtable_rva": 0x1C7EF90,
        "token_leaf_rva": 0x5302B0,
        "token": 0x2DD6,
        "token_bytes": "b8d62d0000c3",
    },
    {
        "name": "offer_fleet_access",
        "vtable_rva": 0x1C7F1F0,
        "token_leaf_rva": 0x534690,
        "token": 0x2DD7,
        "token_bytes": "b8d72d0000c3",
    },
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def hex_rva(value: int) -> str:
    return f"0x{value:x}"


def hex_va(value: int) -> str:
    return f"0x{IMAGE_BASE + value:x}"


def function_record(pe: PE, rva: int) -> dict[str, Any]:
    function = pe.function(rva)
    if function is None:
        return {
            "rva": hex_rva(rva),
            "va": hex_va(rva),
            "pdata": None,
        }
    start, end, unwind = function
    return {
        "rva": hex_rva(rva),
        "va": hex_va(rva),
        "pdata": {
            "rva_start": hex_rva(start),
            "rva_end_exclusive": hex_rva(end),
            "va_start": hex_va(start),
            "va_end_exclusive": hex_va(end),
            "unwind_rva": hex_rva(unwind),
        },
    }


def vtable_record(pe: PE, spec: dict[str, Any]) -> dict[str, Any]:
    table = int(spec["vtable_rva"])
    raw = pe.bytes_at(table, 0x120)
    if len(raw) != 0x120:
        raise ValueError(f"short vtable read at {hex_rva(table)}")
    entries: list[dict[str, str]] = []
    for slot in range(0, 0x120, 8):
        pointer = pe.u64(pe.to_offset(table + slot))
        value_rva = pointer - IMAGE_BASE if pointer >= IMAGE_BASE else pointer
        entries.append(
            {
                "slot": hex_rva(slot),
                "pointer_va": hex_va(value_rva)
                if pointer >= IMAGE_BASE
                else hex(pointer),
                "target_rva": hex_rva(value_rva),
            }
        )
    token_rva = int(spec["token_leaf_rva"])
    token_raw = pe.bytes_at(token_rva, 6)
    expected = bytes.fromhex(str(spec["token_bytes"]))
    if token_raw != expected:
        raise ValueError(
            f"token leaf mismatch for {spec['name']}: {token_raw.hex()}"
        )
    token_value = int.from_bytes(token_raw[1:5], "little")
    if token_value != int(spec["token"]):
        raise ValueError(f"token value mismatch for {spec['name']}")
    return {
        "name": spec["name"],
        "vtable_rva": hex_rva(table),
        "vtable_va": hex_va(table),
        "vtable_bytes": len(raw),
        "vtable_raw_sha256": sha256_bytes(raw),
        "token_slot": "0x98",
        "token_leaf": function_record(pe, token_rva),
        "token_leaf_bytes": token_raw.hex(),
        "token": token_value,
        "entries": entries,
    }


def decode_window(pe: PE, name: str, begin: int, end: int) -> dict[str, Any]:
    raw = pe.bytes_at(begin, end - begin)
    if len(raw) != end - begin:
        raise ValueError(f"short decode window {name}")
    rows = _decode_range(pe, None, begin, end)
    return {
        "name": name,
        "rva_start": hex_rva(begin),
        "rva_end_exclusive": hex_rva(end),
        "va_start": hex_va(begin),
        "va_end_exclusive": hex_va(end),
        "bytes_examined": len(raw),
        "raw_sha256": sha256_bytes(raw),
        "instructions": rows,
    }


def source_ref(relative: str, role: str) -> dict[str, Any]:
    path = ROOT / relative
    result: dict[str, Any] = {
        "path": relative,
        "exists": path.is_file(),
        "role": role,
    }
    if path.is_file():
        result["bytes"] = path.stat().st_size
        result["sha256"] = sha256_file(path)
    return result


def build_report() -> dict[str, Any]:
    if not TARGET_PATH.is_file():
        raise FileNotFoundError(TARGET_PATH)
    actual_sha = sha256_file(TARGET_PATH)
    if actual_sha != TARGET_SHA256:
        raise ValueError(f"target SHA mismatch: {actual_sha}")
    pe = PE(TARGET_PATH)
    if pe.base != IMAGE_BASE:
        raise ValueError(f"unexpected image base: {hex(pe.base)}")
    vector_records = [vtable_record(pe, spec) for spec in VECTORS]
    method_records = {
        "fleet_plus80": {
            "slot": "0x80",
            **function_record(pe, 0x52FC20),
        },
        "fleet_plus88": {
            "slot": "0x88",
            **function_record(pe, 0x5301E0),
        },
        "offer_plus80": {
            "slot": "0x80",
            **function_record(pe, 0x533FD0),
        },
        "offer_plus88": {
            "slot": "0x88",
            **function_record(pe, 0x5345C0),
        },
    }
    windows = [decode_window(pe, *item) for item in DECODE_WINDOWS]
    total_decoded = sum(item["bytes_examined"] for item in windows)
    if total_decoded > 16 * 1024:
        raise ValueError("bounded decode budget exceeded")

    return {
        "schema": "information_relation_fleet_basing_source.v1",
        "stage": "information-relation-remaining-20261027-001",
        "report_id": "fleet-basing-current-source-002",
        "review_scope": {
            "purpose": "1.37.4 current fleet-basing container/predicate source",
            "ordinary_pe_only": True,
            "rea": False,
            "rpm": False,
            "game_query": False,
            "mcp": False,
            "production_changes": False,
            "no_whole_image_disassembly": True,
            "decode_windows": len(windows),
            "decoded_bytes_total": total_decoded,
        },
        "target_binary": {
            "version": TARGET_VERSION,
            "path": str(TARGET_PATH),
            "sha256": actual_sha,
            "bytes": TARGET_PATH.stat().st_size,
            "image_base": hex(IMAGE_BASE),
        },
        "entry_seeds": vector_records,
        "predicate_methods": method_records,
        "current_container_observations": {
            "status": "bounded_current_container_predicate_candidate",
            "not_a_complete_serializer": True,
            "endpoint_fields": {
                "action_plus_0x10": {
                    "role": "first_endpoint_slot_input",
                    "operation": "logical_shr_32_then_signed_16",
                },
                "action_plus_0x20": {
                    "role": "second_endpoint_slot_input",
                    "operation": "logical_shr_32_then_signed_16",
                },
            },
            "country_lookup": {
                "global_rva": "0x233d8b0",
                "table_offset": "0x118",
                "index_unit": "8-byte country pointer",
            },
            "row_vector": {
                "country_relation_table_offset": "0x1510",
                "row_stride": "0x48",
                "first_vector": {
                    "begin_offset": "0x50",
                    "count_offset": "0x5c",
                    "element_stride": "0x10",
                    "comparison": "element[0] against row+0x10-derived signed endpoint",
                },
                "reciprocal_vector_seen_in_offer": {
                    "owner_pointer": "row[0]",
                    "begin_offset": "0xf8",
                    "count_offset": "0x104",
                    "element_stride": "0x10",
                    "comparison": "element[0] against row+0x10-derived signed endpoint",
                },
            },
            "fleet_fallback_list": {
                "status": "current_container_candidate",
                "country_object_offset": "0xd18",
                "node_item_offset": "0x0",
                "node_next_offset": "0x10",
                "item_vtable_slot": "0x88",
                "item_match_path": "item+0xe8 then +0x468, high 16 bits compared to second endpoint slot",
                "predicate_method_rva": "0x5301e0",
                "unresolved": [
                    "item type and vtable +0x88 business name",
                    "whether this list is active fleet-basing state or an action/eligibility cache",
                    "date/expiry and remaining bytes",
                ],
            },
            "offer_reciprocal_path": {
                "status": "bounded_predicate_only",
                "method_rva": "0x533fd0",
                "same_action_endpoint_fields": True,
                "unresolved": [
                    "the exact native role of first versus second endpoint",
                    "whether vector membership means active rights, offerability, or another gate",
                ],
            },
        },
        "direction": {
            "status": "partial",
            "action_family_context": {
                "fleet_access": "prior action catalog describes requesting/holding side -> port country",
                "offer_fleet_access": "prior action catalog describes port country -> fleet user",
            },
            "current_predicate_binding": "only first/second fullref inputs are statically proven here; grantor/recipient role is unresolved",
            "no_expiry_proof": True,
        },
        "decoded_windows": windows,
        "unresolved_callees": [
            {"rva": "0x4e9d30", "role": "item-vtable +0x88 helper called by fleet fallback"},
            {"rva": "0x36d0e0", "role": "country/action predicate gate"},
            {"rva": "0x3d7b90", "role": "relation/object helper in predicate branches"},
            {"rva": "0xa697a0", "role": "offer predicate helper"},
            {"rva": "0x2f1cc0", "role": "country/object byte predicate"},
        ],
        "source_refs": [
            source_ref(
                "work/runtime/information-relation-remaining-20261027-001/"
                "relation-remaining-source-001.json",
                "prior boundary: 1.37.5 candidates were action-only and not current proof",
            ),
            source_ref(
                "work/runtime/information-relation-current-20261027-001/"
                "relation-current-contract-003.json",
                "current relation target/identity guard",
            ),
            source_ref(
                "bridge/diplomacy_catalog.json",
                "prior action direction labels, retained as context only",
            ),
            source_ref(
                "work/research-next/relation_remaining.py",
                "prior source-only inventory script",
            ),
        ],
        "next_minimum_gap": [
            "Root-owned exact-function analysis of 0x5301e0/0x4e9d30 to identify the fleet-list item and active-state semantics.",
            "A bounded current-record read proving first endpoint is grantor/port and second is fleet user (or the reverse).",
            "A date/expiry serializer or explicit proof that fleet-basing rights have no expiry field.",
            "Runtime two-pass corroboration remains required before public current-state coverage.",
        ],
        "script": {
            "path": "work/research-next/fleet_basing_current.py",
            "sha256": sha256_file(Path(__file__)),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if output.exists():
        raise FileExistsError(f"refusing to overwrite {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    report = build_report()
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"output": str(output), "bytes": output.stat().st_size}, ensure_ascii=False))


if __name__ == "__main__":
    main()
