"""Create the bounded discipline child contract and pinned profile.

The script reads only small archived reports plus bounded bytes from the fixed
PE.  It never opens the game or invokes native code.  Runtime addresses are
kept out of the profile; the manager pointer is read from
``module_base + modifier_database_global_rva`` before applying the indexed
record calculation.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
STAGE = ROOT / "work" / "runtime" / "information-military-effective-20261027-001"
CONTRACT_PATH = STAGE / "source-contract-001.json"
PROFILE_PATH = ROOT / "bridge" / "information" / "profiles" / "military-effective-memory-1374.json"
PROFILE_ID = "military-effective-memory-1374"
EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
GAME_VERSION = "1.37.4"
REPORT_LIMIT = 128 * 1024

HELPER_RVA = 0x341850
HELPER_BYTES = 180
PROCESSOR_RVA = 0x8F71D0
PROCESSOR_BYTES = 904
CONSTRUCTOR_RVA = 0x8F1DF0
VTABLE_RVA = 0x1CC9400
PROCESSOR_METHOD_RVA = 0x8F71D0
MODIFIER_GLOBAL_RVA = 0x2358060
MODIFIER_INDEX = 0x77
MODIFIER_STRIDE = 0x60
PROCESSOR_OFFSET = 0x40


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def read_small(path: Path, *, limit: int = REPORT_LIMIT) -> tuple[dict[str, Any], bytes]:
    size = path.stat().st_size
    if size <= 0 or size > limit:
        raise ValueError(f"source_size_out_of_bound:{path}:{size}")
    raw = path.read_bytes()
    if len(raw) != size or len(raw) > limit:
        raise ValueError(f"source_size_changed:{path}")
    document = json.loads(raw.decode("utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"source_json_shape_invalid:{path}")
    return document, raw


def source_item(path: Path, role: str, *, require_json: bool = False) -> dict[str, Any]:
    size = path.stat().st_size
    if size <= 0 or size > REPORT_LIMIT:
        raise ValueError(f"source_size_out_of_bound:{path}:{size}")
    if require_json:
        read_small(path)
    return {
        "path": str(path.relative_to(ROOT)).replace("\\", "/"),
        "sha256": digest(path),
        "bytes": size,
        "role": role,
    }


def write_exclusive(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def _guard(pe: Any, start: int, length: int, name: str) -> dict[str, Any]:
    raw = pe.bytes_at(start, length)
    if len(raw) != length:
        raise ValueError(f"guard_length_invalid:{name}:{len(raw)}")
    return {
        "name": name,
        "rva": hex(start),
        "rva_end_exclusive": hex(start + length),
        "hex": raw.hex(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def main() -> None:
    from work.discover_diplomacy import PE
    from work.local_config import game_exe

    pe = PE(game_exe())
    actual_sha = hashlib.sha256(pe.data).hexdigest()
    if actual_sha != EXE_SHA256 or pe.base != 0x140000000:
        raise ValueError(f"executable_identity_mismatch:{actual_sha}:{hex(pe.base)}")

    source_paths = [
        (
            STAGE / "morale-effective-source-001.json",
            "bounded effective-source index; no runtime values imported",
            True,
        ),
        (
            STAGE / "discipline-links-003.json",
            "bounded ordinary-PE indexed slot and processor-vtable construction",
            True,
        ),
        (
            ROOT / "work/runtime/information-military-quality-20261027-001/morale-discipline-source-002.json",
            "bounded discipline helper and keyed modifier layout",
            True,
        ),
        (
            ROOT / "docs/宗教统一计算路径.md",
            "mature dense/sparse modifier-cache layout reference",
            False,
        ),
        (
            ROOT / "bridge/information/profiles/religious-unity-memory-1374.json",
            "mature bounded modifier-cache profile reference",
            True,
        ),
    ]
    sources = [source_item(path, role, require_json=require_json) for path, role, require_json in source_paths]

    rea_341850 = STAGE / "rea-discipline-341850-001/evidence.json"
    rea_8f71d0 = STAGE / "rea-discipline-processor-8f71d0-001/evidence.json"
    rea_refs = [
        {
            "path": str(rea_341850.relative_to(ROOT)).replace("\\", "/"),
            "sha256": digest(rea_341850),
            "bytes": rea_341850.stat().st_size,
            "function_rva": hex(HELPER_RVA),
            "body_bytes_used_for_contract": HELPER_BYTES,
            "role": "archived REA evidence for the discipline helper; referenced, not loaded into the child",
        },
        {
            "path": str(rea_8f71d0.relative_to(ROOT)).replace("\\", "/"),
            "sha256": digest(rea_8f71d0),
            "bytes": rea_8f71d0.stat().st_size,
            "function_rva": hex(PROCESSOR_RVA),
            "body_bytes_used_for_contract": PROCESSOR_BYTES,
            "role": "archived REA evidence for the recognized processor; referenced, not loaded into the child",
        },
    ]

    helper_guard = _guard(pe, HELPER_RVA, HELPER_BYTES, "discipline_helper_341850")
    processor_guard = _guard(pe, PROCESSOR_RVA, PROCESSOR_BYTES, "discipline_processor_8f71d0_full")
    constructor_raw = pe.bytes_at(CONSTRUCTOR_RVA, 0x29)
    vtable_raw = pe.bytes_at(VTABLE_RVA, 0x60)
    if int.from_bytes(vtable_raw[8:16], "little") != pe.base + PROCESSOR_METHOD_RVA:
        raise ValueError("processor_vtable_slot_plus_8_mismatch")

    contract = {
        "schema": "information_military_effective_static_contract.v1",
        "evidence_kind": "ordinary_bounded_PE_with_archived_REA_references",
        "stage": "information-military-effective-20261027-001",
        "exe": {
            "sha256": actual_sha,
            "bytes": len(pe.data),
            "static_image_base": hex(pe.base),
        },
        "runtime_or_RPM": False,
        "game_or_native_calls": 0,
        "whole_image_disassembly": False,
        "source_evidence": sources,
        "archived_rea_references": rea_refs,
        "layout": {
            "country_cache_state_offset": "0x28c8",
            "country_modifier_object_offset": "0x28d0",
            "modifier_dense_flag_offset": "0x10",
            "modifier_values_pointer_offset": "0x58",
            "modifier_sparse_count_offset": "0x64",
            "modifier_id": "0x77",
            "modifier_database_global_rva": hex(MODIFIER_GLOBAL_RVA),
            "modifier_record_index": hex(MODIFIER_INDEX),
            "modifier_record_stride": hex(MODIFIER_STRIDE),
            "modifier_processor_offset": hex(PROCESSOR_OFFSET),
            "processor_vtable_rva": hex(VTABLE_RVA),
            "processor_method_rva": hex(PROCESSOR_METHOD_RVA),
            "global_flags": {
                "specific_102": "0x233ff0c",
                "specific_1bb": "0x233ff2c",
                "specific_1d2_and_1c2": "0x233ff54",
                "special": "0x233feb6",
            },
            "dense_modifier_value_offset": "0x3bc",
            "processor_dense_offsets": {
                "0x102": "0x814",
                "0x1bb": "0xddc",
                "0x1d2": "0xe94",
                "0x1c2": "0xe14",
            },
            "sparse_entry_stride": 8,
            "max_sparse_count": 8192,
            "read_budget_bytes": 98304,
        },
        "guards": [helper_guard, processor_guard],
        "static_vtable": {
            "rva": hex(VTABLE_RVA),
            "bytes_hex": vtable_raw.hex(),
            "sha256": hashlib.sha256(vtable_raw).hexdigest(),
            "slot_plus_8_rva": hex(PROCESSOR_METHOD_RVA),
        },
        "constructor": {
            "rva": hex(CONSTRUCTOR_RVA),
            "bytes_hex": constructor_raw.hex(),
            "sha256": hashlib.sha256(constructor_raw).hexdigest(),
            "allocation_size": 8,
            "description": "bounded ordinary-PE constructor stores 0x1cc9400 at allocated object +0",
        },
        "formula": {
            "base_raw": 1000,
            "modifier_sum": "signed int32 keyed modifier 0x77 is added to base before the recognized processor result",
            "processor_gate": "specific global byte == 0 or special global byte != 0",
            "processor_inputs": "0x102/0x1bb/0x1d2/0x1c2 are truncated raw*1000/5000, /10000, /10000, /10000",
            "thread_context": "TLS slot +0x10 is unresolved; nonzero enabled contribution remains unknown",
            "final": "signed int32 wrap of 1000 + processor result, then signed minimum 10",
        },
        "unknown_conditions": [
            "The manager pointer is runtime data and must be read from module_base+0x2358060 before applying index/stride/offset.",
            "The recognized processor body is guarded but its TLS slot is not read by this child.",
            "Cache freshness, main-thread atomicity, and foreign-country visibility are outside this child contract.",
        ],
    }
    write_exclusive(CONTRACT_PATH, contract)

    contract_raw = CONTRACT_PATH.read_bytes()
    profile = {
        "profile_id": PROFILE_ID,
        "profile_version": 1,
        "game_version": GAME_VERSION,
        "executable": {"sha256": EXE_SHA256, "image_base": "0x140000000"},
        "source_evidence": [
            {
                "path": str(CONTRACT_PATH.relative_to(ROOT)).replace("\\", "/"),
                "sha256": hashlib.sha256(contract_raw).hexdigest(),
                "bytes": len(contract_raw),
                "role": "final discipline child source contract",
            },
            *sources,
        ],
        "layout": contract["layout"],
        "semantics": {
            "field": "discipline",
            "basis": "native_country_discipline_calculation",
            "value_origin": "derived_from_copied_native_inputs",
            "unit": "ratio",
            "scale": 1000,
            "period": "current",
            "complete": False,
            "raw_encoding": "signed int32 final effective result; raw_hex preserves four little-endian bytes",
        },
        "code_guards": [helper_guard, processor_guard],
        "read_constraints": {
            "pointer_min": "0x10000",
            "pointer_max": "0x7fffffffffff",
            "manager_slot": "read qword at module_base+0x2358060, then manager+(0x77*0x60)+0x40; never use 0x235ad40 as a process address",
            "modifier_cache": "country+0x28c8 state 1 is CALCULATING; country+0x28d0 object uses +0x10/+0x58/+0x64",
            "sparse": "signed entry pairs {id,value}, stride 8, first matching id, max 8192 entries",
            "processor": "only vtable 0x1cc9400 with +0x8 method 0x8f71d0 and full 904-byte guard may use callback inputs",
            "failure": "guard mismatch, state calculating, unsupported processor, malformed pointers/counts, budget/read failure or unresolved TLS contribution remains unknown",
        },
        "unknown_conditions": contract["unknown_conditions"],
    }
    write_exclusive(PROFILE_PATH, profile)
    print(json.dumps({
        "contract": str(CONTRACT_PATH.relative_to(ROOT)).replace("\\", "/"),
        "contract_sha256": hashlib.sha256(contract_raw).hexdigest(),
        "contract_bytes": len(contract_raw),
        "profile": str(PROFILE_PATH.relative_to(ROOT)).replace("\\", "/"),
        "profile_sha256": digest(PROFILE_PATH),
        "profile_bytes": PROFILE_PATH.stat().st_size,
        "guards": [(item["name"], len(bytes.fromhex(item["hex"]))) for item in profile["code_guards"]],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
