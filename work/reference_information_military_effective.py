"""Recompute the observed discipline from independent raw reads, offline."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-military-effective-20261027-001"
SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


def pin(path):
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="native-effective-inputs-002.json")
    parser.add_argument("--output", default="expected-military-effective-001.json")
    parser.add_argument("--include-morale", action="store_true")
    args = parser.parse_args()
    path = STAGE / args.input
    report = json.loads(path.read_bytes())
    identity = report["identity"]
    assert report["status"] == "observed" and report["completed"] is True
    assert report["cleanup"]["handle_close"]["closed"] is True
    assert report["doublepass"]["consistent"] is True
    assert identity["binding_verified"] is True and identity["process_path_sha256"] == SHA
    assert identity["installation_session_id"] == "31460-1dd653f69242d7b"
    assert identity["installation_creation_filetime"] == identity["process_creation_filetime"] == 134374886912306555
    rows = report["military_effective_inputs"]
    assert len(rows) == 2 and rows[0] == rows[1]
    row = rows[0]
    assert row["date"]["value"] == 56557728
    country = row["country"]
    assert country["status"] == "observed" and country["requested_country"] == "FRA"
    assert len(country["matches"]) == 1
    match = country["matches"][0]
    assert match["tag"] == "FRA" and match["slot"] == match["index"] == 122
    assert match["handle_raw_hex"] == "465241007a000001"
    data = row["military_effective"]
    assert country["country_pointer"]["va"] == data["country_pointer"]
    reads = {item["label"]: item for item in data["reads"]}
    assert len(reads) == len(data["reads"])

    def raw(label, width):
        record = reads[label]
        value = bytes.fromhex(record["raw_hex"])
        assert len(value) == width == record["bytes"]
        return value

    assert int.from_bytes(raw("country_cache_state", 4), "little", signed=True) == data["cache_state"] != 1
    header = raw("modifier_header", 0x68)
    assert header[0x10] != 0 and data["dense"] is True
    pointer = int.from_bytes(header[0x58:0x60], "little")
    values = {}
    for identifier in (0x77, 0x102, 0x1BB, 0x1D2, 0x1C2):
        label = f"modifier_{identifier:x}_dense_value"
        assert int(reads[label]["va"], 16) == pointer + identifier * 8 + 4
        values[hex(identifier)] = int.from_bytes(raw(label, 4), "little", signed=True)
    assert values == data["processor_modifier_inputs"]
    assert int.from_bytes(raw("processor_value_method", 8), "little") - int(data["module_base"], 16) == 0x8F71D0
    flags = {rva: int.from_bytes(raw(f"global_flag_{rva:x}", 1), "little")
             for rva in (0x233FF0C, 0x233FF2C, 0x233FF54, 0x233FEB6)}
    gates = [flags[rva] == 0 or flags[0x233FEB6] != 0 for rva in (0x233FF0C, 0x233FF2C, 0x233FF54, 0x233FF54)]
    # This sample's gates all skip the processor branches.  No thread-local
    # value is assumed or synthesized, including when calculating a reference.
    assert not any(gates)
    native_sum = (1000 + values["0x77"]) & 0xFFFFFFFF
    native_sum = native_sum - 0x100000000 if native_sum & 0x80000000 else native_sum
    value = max(10, native_sum)
    expected = {"schema": "information_military_effective_independent_reference.v1", "status": "observed",
                "reference_id": Path(args.output).stem, "complete": True,
                "header": {"session_id": identity["installation_session_id"], "game_date": 56557728,
                           "creation_filetime": 134374886912306555, "game_sha256": SHA, "country": "FRA"},
                "fields": {"discipline": {"status": "known", "value": value, "raw": value,
                           "raw_hex": value.to_bytes(4, "little", signed=True).hex(), "unit": "ratio",
                           "scale": 1000, "period": "current", "basis": "native_country_discipline_calculation",
                           "value_origin": "derived_from_copied_native_inputs", "complete": False}},
                "raw_input": pin(path), "inputs": {"modifiers": values, "flags": {hex(k): v for k,v in flags.items()},
                                                    "enabled_gates": gates, "thread_flag_assumed": False},
                "basis": "Independent raw reads plus the observed native processor gates; no production military reader or MCP output imported.",
                "game_or_RPM": False, "new_sampling": False,
                "limitations": ["A complete reference for this observed sample does not mean complete field coverage.",
                                "Enabled nonzero thread-dependent contributions remain unsupported by the current adapter."]}
    if args.include_morale:
        caches = {}
        for key, offset in (("army", 0x9874), ("navy", 0x987C)):
            label = f"morale_{key}"
            assert int(reads[label]["va"], 16) == int(data["country_pointer"], 16) + offset
            value = int.from_bytes(raw(label, 4), "little", signed=True)
            assert data["morale_caches"][key] == {"raw": value, "raw_hex": raw(label, 4).hex()}
            caches[key] = value
        expected["fields"]["morale"] = {
            "status": "known", "value": caches, "raw": caches,
            "raw_hex": {key: raw(f"morale_{key}", 4).hex() for key in caches},
            "unit": "morale", "scale": 1000, "period": "current",
            "basis": "native_country_morale_caches", "value_origin": "copied_native_country_morale_cache",
            "complete": True,
        }
    output = STAGE / args.output
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(expected, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"reference": pin(output), "fields": expected["fields"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
