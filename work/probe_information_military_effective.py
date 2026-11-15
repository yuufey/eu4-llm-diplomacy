"""Independent bounded raw inputs for the discipline scalar and callback."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE
from work.local_config import game_exe
from work.probe_information_current_overextension import probe
from work.probe_information_military_quality import (
    EXPECTED_DATE, EXPECTED_EXE_SHA256, EXPECTED_INSTALLATION,
    _installation_preflight, _valid_pointer,
)

STAGE = ROOT / "work/runtime/information-military-effective-20261027-001"
MAX_CHILD_BYTES = 96 * 1024


def capture(installation, *, processor_inputs=False, cache_fields=False):
    preflight = _installation_preflight(installation)
    pe = PE(game_exe())
    assert hashlib.sha256(pe.data).hexdigest() == EXPECTED_EXE_SHA256
    guard_rva, guard_width = 0x341850, 0xB4
    guard_bytes = pe.bytes_at(guard_rva, guard_width)

    def inputs(reader, module_base, country):
        used = 0
        calls = []

        def read(address, size, label):
            nonlocal used
            assert _valid_pointer(address) and 0 < size <= 65536
            assert address + size <= 0x7FFFFFFFFFFF
            assert used + size <= MAX_CHILD_BYTES
            used += size
            raw = reader.read(address, size, "reference.military_effective." + label)
            assert len(raw) == size
            calls.append({"label": label, "va": hex(address), "bytes": size, "raw_hex": raw.hex()})
            return raw

        def u64(address, label):
            return int.from_bytes(read(address, 8, label), "little")

        actual_guard = read(module_base + guard_rva, guard_width, "discipline_code_guard")
        assert actual_guard == guard_bytes
        state_raw = read(country + 0x28C8, 4, "country_cache_state")
        state = int.from_bytes(state_raw, "little", signed=True)
        result = {"module_base": hex(module_base), "country_pointer": hex(country),
                  "discipline_code_guard": {"rva": hex(guard_rva), "bytes": guard_width,
                                             "sha256": hashlib.sha256(actual_guard).hexdigest()},
                  "cache_state": state, "inputs_only_not_public_field": True}
        database = u64(module_base + 0x2358060, "modifier_database")
        assert _valid_pointer(database)
        processor = u64(database + 0x77 * 0x60 + 0x40, "discipline_processor")
        result.update(modifier_database=hex(database), modifier_id=0x77, processor=hex(processor))
        if processor:
            assert _valid_pointer(processor)
            vtable = u64(processor, "processor_vtable")
            assert _valid_pointer(vtable)
            body = u64(vtable + 8, "processor_value_method")
            assert module_base <= body < module_base + 0x4000000
            result.update(processor_vtable=hex(vtable), processor_vtable_rva=hex(vtable - module_base),
                          processor_method_va=hex(body), processor_method_rva=hex(body - module_base))
            read(body, 32, "processor_method_prefix")
        if state != 1:
            modifier = country + 0x28D0
            header = read(modifier, 0x68, "modifier_header")
            dense = header[0x10] != 0
            pointer = int.from_bytes(header[0x58:0x60], "little")
            count = int.from_bytes(header[0x64:0x68], "little", signed=True)
            result.update(modifier_object=hex(modifier), dense=dense, sparse_count=count,
                          values_pointer=hex(pointer))
            identifiers = (0x77, 0x102, 0x1BB, 0x1D2, 0x1C2) if processor_inputs else (0x77,)
            values = {identifier: 0 for identifier in identifiers}
            if dense:
                for identifier in identifiers:
                    values[identifier] = int.from_bytes(read(pointer + identifier * 8 + 4, 4,
                                                            f"modifier_{identifier:x}_dense_value"),
                                                        "little", signed=True)
            else:
                assert count <= 8192
                found = set()
                for index in range(max(0, count)):
                    row = read(pointer + index * 8, 8, f"discipline_sparse[{index}]")
                    identifier = int.from_bytes(row[:4], "little")
                    if identifier in values and identifier not in found:
                        values[identifier] = int.from_bytes(row[4:], "little", signed=True)
                        found.add(identifier)
                        if len(found) == len(identifiers):
                            break
            result["base_modifier_raw"] = values[0x77]
            if processor_inputs:
                result["processor_modifier_inputs"] = {hex(key): value for key, value in values.items()}
        if processor_inputs:
            result["processor_global_flags"] = {
                hex(rva): read(module_base + rva, 1, f"global_flag_{rva:x}").hex()
                for rva in (0x233FF0C, 0x233FF2C, 0x233FF54, 0x233FEB6)
            }
        if cache_fields:
            result["morale_caches"] = {
                key: {"raw": int.from_bytes(value := read(country + offset, 4, f"morale_{key}"),
                                           "little", signed=True), "raw_hex": value.hex()}
                for key, offset in (("army", 0x9874), ("navy", 0x987C))
            }
            professionalism = read(country + 0x50, 8, "professionalism_raw_unit_unresolved")
            result["professionalism_unit_unresolved"] = {
                "raw": int.from_bytes(professionalism, "little", signed=True), "raw_hex": professionalism.hex(),
                "source_only_not_public_value": True,
            }
        result.update(child_budget={"bytes_requested": used, "limit": MAX_CHILD_BYTES}, reads=calls)
        return {"military_effective": result}

    report = probe(installation, field="military_effective", input_reader=inputs)
    report.update(schema="information_military_effective_independent_raw_inputs.v1", preflight=preflight,
                  binary_sha256=EXPECTED_EXE_SHA256, static_image_base=hex(pe.base),
                  game_functions_called=False, business_actions_submitted=0)
    dates = [row["date"].get("value") for row in report.get("military_effective_inputs", [])]
    if dates != [EXPECTED_DATE, EXPECTED_DATE]:
        report.update(status="error", completed=False)
        report["errors"].append({"stage": "expected_date", "observed": dates,
                                 "expected": [EXPECTED_DATE, EXPECTED_DATE]})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--processor-inputs", action="store_true")
    parser.add_argument("--cache-fields", action="store_true")
    args = parser.parse_args()
    assert not args.output.exists()
    report = capture(EXPECTED_INSTALLATION, processor_inputs=args.processor_inputs, cache_fields=args.cache_fields)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    rows = report.get("military_effective_inputs", [])
    print(json.dumps({"status": report["status"], "completed": report["completed"],
                      "errors": report["errors"], "closed": report["access"].get("closed"),
                      "inputs": [{k: row["military_effective"].get(k) for k in
                                  ("cache_state", "dense", "base_modifier_raw", "processor", "processor_method_rva")}
                                 for row in rows]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
