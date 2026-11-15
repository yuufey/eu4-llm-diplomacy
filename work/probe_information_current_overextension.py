"""Copy a specifically identified country cache using the existing RPM seams."""
from __future__ import annotations

import argparse
import ctypes as C
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.information import domestic_pressure_memory as memory


def probe(installation: Path, *, field="overextension", input_reader=None) -> dict:
    offset, size = ((0, 0) if input_reader is not None else
                    {"overextension": (0xE48, 4), "unrest": (0x2030, 4),
                     "monthly_ledger": (0x770, 228), "estimated_income": (0xE38, 4)}[field])
    report = memory._base_report(installation, "FRA", ["stability"])
    inputs = report[f"{field}_inputs"] = []
    report.update(schema="information_current_domestic_inputs.v2", field=field)
    if field == "monthly_ledger":
        report["schema"] = "information_current_country_ledger_inputs.v1"
    elif field == "estimated_income":
        report.update(schema="information_country_estimated_income_inputs.v1",
                      interpretation="serialized estimated_monthly_income cache; GUI forecast equivalence and update timing not established")
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
        guard = memory._file_code_guard(Path(report["identity"]["process_path"]), profile)
        if guard["status"] != "observed":
            raise memory.ProbeError("file_code_guard_failed")
        report["file_code_guard"] = guard
        reader = memory.AddressBoundedRPM(kernel, handle, base)
        for _ in range(2):
            snapshot = memory._pass(reader, base, "FRA", profile, ["stability"], len(reader.read_log))
            if snapshot["status"] != "observed":
                raise memory.ProbeError("country_snapshot_failed")
            country = memory._va(snapshot["country_scan"]["country_pointer"])
            raw = (b"" if input_reader is not None else
                   reader.read(country + offset, size, f"reference.country_{field}_cache"))
            record = {
                "date": snapshot["game_date"], "country": snapshot["country_scan"],
                "offset": hex(offset), "raw_hex": raw.hex(),
                "runtime_code_guard": snapshot["runtime_code_guard"],
            }
            if input_reader is not None:
                record.update(input_reader(reader, base, country))
            elif field == "monthly_ledger":
                record.update(income_slots=list(struct.unpack("<19i", raw[:76])),
                              expense_slots=list(struct.unpack("<38i", raw[76:])))
            else:
                record["raw"] = int.from_bytes(raw, "little", signed=True)
            inputs.append(record)
        report["doublepass"] = {"performed": True, "consistent": inputs[0] == inputs[1], "atomic": False}
        report["status"] = "observed" if report["doublepass"]["consistent"] else "doublepass_mismatch"
    except Exception as exc:
        report["status"] = "error"
        report["errors"].append({"stage": f"{field}_inputs", "error": f"{type(exc).__name__}:{exc}"})
    finally:
        if reader is not None:
            report["access"].update(rpm_bytes_requested=reader.bytes_requested, rpm_calls=reader.calls)
        memory._apply_cleanup(report, kernel, handle)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--field", choices=("overextension", "unrest", "monthly_ledger", "estimated_income"), default="overextension")
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("refusing_to_overwrite_output")
    report = probe(args.installation, field=args.field)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"status": report["status"], "completed": report["completed"], "errors": report["errors"]}))
    raise SystemExit(0 if report["completed"] else 1)
