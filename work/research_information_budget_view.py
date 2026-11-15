"""Locate static budget-view dispatch candidates without opening a live process."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE, check_memory_budget, rip_references
from work.local_config import game_exe

EXPECTED = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
STAGE = ROOT / "work/runtime/information-budget-forecast-20261027-001"


def main():
    pe = PE(game_exe())
    assert hashlib.sha256(pe.data).hexdigest() == EXPECTED
    pointers = {}
    for rva in (0xEB7B20, 0xEB40F0, 0xEB4910):
        needle = struct.pack("<Q", pe.base + rva)
        matches = []
        offset = pe.data.find(needle)
        while offset >= 0:
            location = pe.to_rva(offset)
            if location is not None:
                matches.append(location)
            offset = pe.data.find(needle, offset + 1)
        pointers[hex(rva)] = [hex(x) for x in matches]
    # The immediately preceding .rdata table window is inspected as raw static
    # candidates. It is not a proven class/vtable start or live object identity.
    locations = sorted({int(x, 0) for xs in pointers.values() for x in xs})
    table_candidates = []
    for location in locations:
        begin = max(0, location - 0x100)
        raw = pe.bytes_at(begin, 0x180)
        entries = []
        for index in range(0, len(raw) - 7, 8):
            value = struct.unpack_from("<Q", raw, index)[0]
            if pe.base <= value < pe.base + 0x4000000:
                entries.append({"slot_rva": hex(begin + index), "target_rva": hex(value - pe.base),
                                "executable": pe.executable(value - pe.base)})
        table_candidates.append({"matching_slot_rva": hex(location), "window_begin_rva": hex(begin),
                                 "window_end_exclusive_rva": hex(begin + len(raw)),
                                 "raw_hex": raw.hex(), "sha256": hashlib.sha256(raw).hexdigest(), "entries": entries})
    # References to a fixed 256-byte prefix around each matching slot locate
    # constructor/address-taken seeds; every hit remains an undecoded candidate.
    targets = {location - delta for location in locations for delta in range(0, 0x108, 8)}
    refs = rip_references(pe, targets)
    report = {"schema": "information_budget_view_static_inventory.v1",
              "evidence_type": "ordinary_fixed_PE_raw_pointer_and_RIP_pattern_candidates_not_REA",
              "target": {"version": "1.37.4", "sha256": EXPECTED, "image_base_va": hex(pe.base)},
              "pointer_occurrences": pointers, "table_candidates": table_candidates,
              "rip_candidates": {hex(k): v for k, v in refs.items()},
              "limitations": ["No live UI object, freshness, country binding or visibility was observed.",
                              "Raw qword table windows and RIP-pattern hits require instruction validation before class binding."]}
    path = STAGE / "budget-view-static-inventory-001.json"
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    check_memory_budget()
    print(json.dumps({"pointer_occurrences": pointers, "rip_candidates": report["rip_candidates"]}))


if __name__ == "__main__":
    main()
