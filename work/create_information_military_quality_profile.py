"""Create the bounded military-quality child profile from pinned PE reports.

This script only reads the two small, already archived ordinary-PE reports.  It
does not open the game, call native code, or load the executable image.  The
profile contains RVA-relative guards and layout offsets; it deliberately does
not embed runtime/ASLR pointers.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work" / "runtime" / "information-military-quality-20261027-001"
PROFILE_PATH = ROOT / "bridge" / "information" / "profiles" / "military-quality-memory-1374.json"
PROFILE_ID = "military-quality-memory-1374"
EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
GAME_VERSION = "1.37.4"
REPORT_LIMIT = 128 * 1024


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def read_report(name: str) -> tuple[dict[str, Any], Path, bytes]:
    path = STAGE / name
    size = path.stat().st_size
    if size <= 0 or size > REPORT_LIMIT:
        raise ValueError(f"report_size_out_of_bound:{name}:{size}")
    raw = path.read_bytes()
    if len(raw) != size or len(raw) > REPORT_LIMIT:
        raise ValueError(f"report_size_changed:{name}")
    document = json.loads(raw.decode("utf-8"))
    if not isinstance(document, dict) or document.get("schema") != "information_military_technology_static.v1":
        raise ValueError(f"report_schema_invalid:{name}")
    executable = document.get("exe")
    if not isinstance(executable, dict) or executable.get("sha256", "").lower() != EXE_SHA256:
        raise ValueError(f"report_exe_mismatch:{name}")
    if document.get("runtime_or_RPM") is not False or document.get("whole_image_disassembly") is not False:
        raise ValueError(f"report_evidence_kind_invalid:{name}")
    return document, path, raw


def range_bytes(document: dict[str, Any], range_index: int) -> tuple[int, int, bytes]:
    ranges = document.get("ranges")
    if not isinstance(ranges, list) or range_index >= len(ranges):
        raise ValueError("range_missing")
    item = ranges[range_index]
    start = int(item["start"]["rva"], 0)
    end = int(item["end_exclusive"]["rva"], 0)
    instructions = item.get("instructions")
    if not isinstance(instructions, list) or not instructions:
        raise ValueError("range_instructions_missing")
    current = start
    chunks: list[bytes] = []
    for instruction in instructions:
        rva = int(instruction["rva"], 0)
        raw = bytes.fromhex(instruction["bytes"])
        if rva != current:
            raise ValueError(f"range_has_gap:{hex(current)}:{hex(rva)}")
        chunks.append(raw)
        current += len(raw)
    raw = b"".join(chunks)
    if current != end or len(raw) != end - start:
        raise ValueError(f"range_length_mismatch:{hex(start)}")
    return start, end, raw


def write_exclusive(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main() -> None:
    getter, getter_path, getter_raw = read_report("military-technology-code-004.json")
    singleton, singleton_path, singleton_raw = read_report("military-technology-code-005.json")
    contract_path = STAGE / "military-technology-source-002.json"
    contract_raw = contract_path.read_bytes()
    if len(contract_raw) <= 0 or len(contract_raw) > REPORT_LIMIT:
        raise ValueError("source_contract_size_out_of_bound")
    contract = json.loads(contract_raw.decode("utf-8"))
    if contract.get("schema") != "information_military_technology_static.v1" or contract.get("exe", {}).get("sha256", "").lower() != EXE_SHA256:
        raise ValueError("source_contract_invalid")
    getter_start, getter_end, getter_bytes = range_bytes(getter, 0)
    singleton_start, singleton_end, singleton_bytes = range_bytes(singleton, 0)
    source_evidence = [
        {
            "path": str(contract_path.relative_to(ROOT)).replace("\\", "/"),
            "sha256": hashlib.sha256(contract_raw).hexdigest(),
            "bytes": len(contract_raw),
            "role": "final bounded military-technology source contract",
        },
        {
            "path": str(getter_path.relative_to(ROOT)).replace("\\", "/"),
            "sha256": hashlib.sha256(getter_raw).hexdigest(),
            "bytes": len(getter_raw),
            "role": "bounded ordinary-PE getter and exact mil_tech lookup evidence",
        },
        {
            "path": str(singleton_path.relative_to(ROOT)).replace("\\", "/"),
            "sha256": hashlib.sha256(singleton_raw).hexdigest(),
            "bytes": len(singleton_raw),
            "role": "bounded ordinary-PE singleton layout evidence",
        },
    ]
    guards = [
        {
            "name": "military_quality_getter_6df5a0",
            "rva": hex(getter_start),
            "rva_end_exclusive": hex(getter_end),
            "hex": getter_bytes.hex(),
            "sha256": hashlib.sha256(getter_bytes).hexdigest(),
        },
        {
            "name": "military_quality_singleton_9b240",
            "rva": hex(singleton_start),
            "rva_end_exclusive": hex(singleton_end),
            "hex": singleton_bytes.hex(),
            "sha256": hashlib.sha256(singleton_bytes).hexdigest(),
        },
    ]
    profile = {
        "profile_id": PROFILE_ID,
        "profile_version": 1,
        "game_version": GAME_VERSION,
        "executable": {"sha256": EXE_SHA256, "image_base": "0x140000000"},
        "source_evidence": source_evidence,
        "layout": {
            "singleton_global_rva": "0x242be30",
            "manager_bucket_count_offset": "0x34",
            "manager_buckets_offset": "0x38",
            "bucket_entry_stride": 8,
            "chain_definition_offset": "0x0",
            "chain_next_offset": "0x8",
            "definition_key_string_offset": "0x10",
            "definition_key_length_offset": "0x20",
            "definition_key_capacity_offset": "0x28",
            "definition_index_offset": "0x50",
            "country_technology_pointer_offset": "0x2440",
            "technology_vector_begin_offset": "0x128",
            "technology_vector_end_offset": "0x130",
            "technology_vector_capacity_offset": "0x138",
            "technology_component_width": 4,
            "technology_key": "mil_tech",
            "technology_key_length": 8,
            "max_bucket_count": 65536,
            "max_chain_steps": 64,
            "max_technology_vector_count": 256,
            "read_budget_bytes": 65536,
        },
        "semantics": {
            "field": "military_technology",
            "basis": "native_country_technology_level_cache",
            "value_origin": "copied_native_country_technology_cache",
            "unit": "technology_level",
            "scale": 1,
            "period": "current",
            "complete": True,
            "raw_encoding": "signed little-endian int32 copied from vector element; raw_hex preserves four bytes",
        },
        "code_guards": guards,
        "read_constraints": {
            "pointer_min": "0x10000",
            "pointer_max": "0x7fffffffffff",
            "definition_key_storage": "std::string at definition+0x10; length +0x20; capacity +0x28; heap data only when capacity >= 0x10",
            "hash": "unsigned 32-bit accumulator; for each signed ASCII byte: (accumulator + byte) * 61 modulo 2^32; unsigned remainder by manager+0x34",
            "vector": "begin/end define the bounded stride-4 range and index must be within count; +0x138 capacity is retained as unproven layout evidence and is not required for a known result",
            "failure": "missing key, malformed definition, cycle, bound violation, guard mismatch, short read, or context pointer failure remains unknown",
        },
        "unknown_conditions": [
            "Only military_technology is closed in this profile; morale, discipline, army_tradition, professionalism and military_modifiers remain outside this child contract.",
            "The profile proves a bounded native lookup/cache path, not GUI freshness or a live multi-country observer contract.",
        ],
    }
    write_exclusive(PROFILE_PATH, profile)
    print(json.dumps({
        "profile": str(PROFILE_PATH.relative_to(ROOT)).replace("\\", "/"),
        "profile_sha256": digest(PROFILE_PATH),
        "profile_bytes": PROFILE_PATH.stat().st_size,
        "guards": len(guards),
        "guard_bytes": sum(len(bytes.fromhex(item["hex"])) for item in guards),
        "source_evidence": source_evidence,
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
