"""Observe the remaining effective-unity branches through bounded RPM only."""
from __future__ import annotations

import argparse
import ctypes as C
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.information import domestic_pressure_memory as memory


def probe(installation: Path) -> dict:
    report = memory._base_report(installation, "FRA", ["stability"])
    report["schema"] = "information_effective_unity_inputs.v1"
    report["purpose"] = "private runtime inputs, not a published N04 field"
    report["unity_inputs"] = []
    kernel = handle = reader = None
    try:
        profile = memory._load_profile()
        document = memory._load_installation(installation)
        kernel = memory._configure_kernel()
        handle = kernel.OpenProcess(memory.PROCESS_ACCESS, False, int(document["pid"]))
        if not handle:
            raise C.WinError(C.get_last_error())
        base = memory._capture_identity(report, document, kernel, handle)
        if report["identity"].get("binding_verified") is not True:
            raise memory.ProbeError("identity_not_bound")
        file_guard = memory._file_code_guard(Path(report["identity"]["process_path"]), profile)
        if file_guard["status"] != "observed":
            raise memory.ProbeError("file_code_guard_failed")
        report["file_code_guard"] = file_guard
        reader = memory.AddressBoundedRPM(kernel, handle, base)
        for _ in range(2):
            capture = memory._pass(reader, base, "FRA", profile, ["stability"], len(reader.read_log))
            if capture["status"] != "observed":
                raise memory.ProbeError("country_snapshot_failed")
            country = memory._va(capture["country_scan"]["country_pointer"])
            modifier = country + 0x28D0
            state = int.from_bytes(reader.read(country + 0x28C8, 4, "unity.cache_state"), "little", signed=True)
            province = int.from_bytes(reader.read(country + 0xEE0, 4, "unity.province_component"), "little", signed=True)
            header = reader.read(modifier, 0x68, "unity.modifier_header")
            dense, count = header[0x10], int.from_bytes(header[0x64:0x68], "little", signed=True)
            values = int.from_bytes(header[0x58:0x60], "little")
            database, _ = reader.qword(base + 0x2358060, "unity.modifier_database")
            if not memory._valid_pointer(database):
                raise memory.ProbeError("modifier_database_invalid")
            records, amounts = {}, {}
            for identifier in (0xA8, 0xE7):
                raw = reader.read(database + identifier * 0x60, 0x60, f"unity.record.{identifier}")
                processor = int.from_bytes(raw[0x40:0x48], "little")
                record = {"raw_hex": raw.hex(), "processor": hex(processor),
                          "resolved_type": int.from_bytes(raw[0x54:0x58], "little")}
                if processor:
                    vtable, _ = reader.qword(processor, f"unity.processor.{identifier}.vtable")
                    methods = reader.read(vtable, 0x18, f"unity.processor.{identifier}.methods")
                    record["method_rvas"] = [hex(int.from_bytes(methods[i:i+8], "little") - base)
                                             for i in (0, 8, 16)]
                records[str(identifier)] = record
                if dense:
                    amount = int.from_bytes(reader.read(values + identifier * 8 + 4, 4,
                                                        f"unity.value.{identifier}"), "little", signed=True)
                else:
                    if count > 8192:
                        raise memory.ProbeError("sparse_table_over_bound")
                    amount = 0
                    for i in range(max(0, count)):
                        pair = reader.read(values + i * 8, 8, f"unity.sparse.{identifier}.{i}")
                        if int.from_bytes(pair[:4], "little") == identifier:
                            amount = int.from_bytes(pair[4:], "little", signed=True)
                            break
                amounts[str(identifier)] = amount
            special_type = records[str(0xE7)]["resolved_type"]
            if special_type > 0x286:
                raise memory.ProbeError("special_type_over_observation_bound")
            flags = reader.read(database + special_type * 0x60 + 0x5C, 1, "unity.special_type_flags")[0]
            report["unity_inputs"].append({
                "date": capture["game_date"], "country": capture["country_scan"],
                "cache_state": state, "province_component": province,
                "modifier_header_hex": header.hex(), "dense": bool(dense),
                "sparse_count": count, "modifier_database": hex(database),
                "records": records, "base_amounts": amounts, "special_type_flags": flags,
                "runtime_code_guard": capture["runtime_code_guard"],
            })
        report["doublepass"] = {"performed": True, "consistent": report["unity_inputs"][0] == report["unity_inputs"][1], "atomic": False}
        report["status"] = "observed" if report["doublepass"]["consistent"] else "doublepass_mismatch"
    except Exception as exc:
        report["status"] = "error"
        report["errors"].append({"stage": "unity_inputs", "error": f"{type(exc).__name__}:{exc}"})
    finally:
        if reader is not None:
            report["access"].update(rpm_bytes_requested=reader.bytes_requested, rpm_calls=reader.calls)
        memory._apply_cleanup(report, kernel, handle)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("refusing_to_overwrite_output")
    report = probe(args.installation)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"status": report["status"], "completed": report["completed"],
                      "errors": report["errors"], "output": str(args.output)}))
    raise SystemExit(0 if report["completed"] else 1)
