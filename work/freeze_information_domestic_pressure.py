"""Join bounded REA evidence into the fixed-build N04 contract and profile.

No process is opened. Only the fixed PE header, selected function spans and
four compiled token records are read. Existing evidence is never overwritten.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.freeze_information_country_powers import (
    DEFAULT_EXE, EXPECTED_EXE_SHA256, IMAGE_BASE, _procedure_record,
    _read_pe_rva_bytes, _write_json_new, dependency_record, read_json_bounded,
    relpath, sha256_bytes, sha256_file,
)

STAGE = ROOT / "work/runtime/information-domestic-pressure-20261025-001"
PROFILE = ROOT / "bridge/information/profiles/domestic-pressure-memory-1374.json"
CONTRACT = STAGE / "native-domestic-pressure-contract-001.json"

# All ranges below come from REA function-manager bodies, not byte-pattern
# guesses. The country writer uses R15 as its country object in these blocks.
SPECS = (
    ("rea-country-save-writer-001", "country_save_writer", 0x2DC6E0,
     ("FUN_141707a10(param_2,0x2886,uVar8);",
      "FUN_141707a10(param_2,0x2719,uVar8);",
      "FUN_141707a10(param_2,0x33f1,uVar8);",
      "FUN_141707a10(param_2,0x2be7,uVar8);")),
    ("rea-fixed-point-copy-001", "fixed_point_copy", 0x956F0,
     ("*param_1 = *param_2;", "return param_1;")),
    ("rea-save-fixed-point-writer-001", "fixed_point_writer", 0x1707A10,
     ("local_res18[0] = *param_3;", "FUN_140246bf0(param_1,local_res18);")),
    ("rea-save-fixed-point-format-001", "signed_fixed_point_formatter", 0x246BF0,
     ("iVar1 = *param_2 / 1000;", "iVar3 = *param_2 % 1000;", '"-%d.%03d"')),
    ("rea-save-key-resolver-001", "save_key_resolver", 0x17091B0,
     ("puVar2 = DAT_14242b868 + (ulonglong)param_2 * 4;",
      "FUN_141708e10(param_1,puVar2);", "FUN_14170d180();")),
    ("rea-save-key-initialization-001", "compiled_save_token_initializer", 0x170D180,
     ("piVar2 = &DAT_141fd8660;", "*piVar1 = *piVar2;",
      "piVar2 = piVar2 + 0x82;", "FUN_14170d980();")),
    ("rea-save-key-vector-001", "save_key_vector", 0x170D980,
     ("puVar2 = &DAT_141fd8660;",
      "FUN_140095110((ulonglong)*puVar2 * 0x20 + DAT_14242b868);",
      "puVar2 = puVar2 + 0x82;", "DAT_14242b880")),
)

FIELDS = {
    "stability": {"offset": 0xBD8, "key": 0x2886, "record_rva": 0x207D0E8,
                  "unit": "stability", "writer_window": (0x2DF169, 0x2DF18C)},
    "war_exhaustion": {"offset": 0xD10, "key": 0x2719, "record_rva": 0x2096110,
                       "unit": "war_exhaustion", "writer_window": (0x2DF444, 0x2DF46C)},
    "corruption": {"offset": 0xED0, "key": 0x33F1, "record_rva": 0x20EA5D0,
                   "unit": "corruption", "writer_window": (0x2DF960, 0x2DF983)},
    "religious_unity": {"offset": 0xEE0, "key": 0x2BE7, "record_rva": 0x211B3D8,
                        "unit": "fraction", "writer_window": (0x2DF676, 0x2DF69E)},
}


def collect():
    records = []
    values = {}
    for directory, name, rva, anchors in SPECS:
        path = STAGE / directory / "evidence.json"
        evidence, size, digest = read_json_bounded(path)
        record = _procedure_record(
            {"name": name, "rva": rva, "anchors": anchors}, path, evidence, size, digest)
        if record["rea_body_range"]["span_bytes"] > 20 * 1024:
            raise ValueError(f"function_span_over_bound:{name}")
        records.append(record)
        values[name] = evidence["raw_result"]["value"]
    return records, values


def build(exe: Path):
    size, digest = sha256_file(exe)
    if digest != EXPECTED_EXE_SHA256 or size != 38_463_016:
        raise ValueError("fixed_executable_identity_mismatch")
    records, values = collect()
    writer_asm = values["country_save_writer"]["assembly"]
    token_records = {}
    guard_records = []
    for field, spec in FIELDS.items():
        rva = spec["record_rva"]
        if not (0x1FD8660 <= rva < 0x2324620) or (rva - 0x1FD8660) % 0x208:
            raise ValueError(f"token_not_on_native_record_boundary:{field}")
        expected = spec["key"].to_bytes(4, "little") + field.encode("ascii") + b"\0"
        raw = _read_pe_rva_bytes(exe, rva, len(expected))
        if raw != expected:
            raise ValueError(f"compiled_token_record_mismatch:{field}")
        start, end = spec["writer_window"]
        lines = [s for s in writer_asm if start <= int(s.split(":", 1)[0], 16) - IMAGE_BASE < end]
        joined = "\n".join(lines)
        for anchor in (f"[R15 + {hex(spec['offset'])}]", f"MOV EDX, {hex(spec['key'])}",
                       "CALL 0x1400956f0", "CALL 0x141707a10"):
            if anchor not in joined:
                raise ValueError(f"native_writer_operand_missing:{field}:{anchor}")
        token_records[field] = {
            "rva": hex(rva), "static_va": hex(IMAGE_BASE + rva),
            "record_array_rva": ["0x1fd8660", "0x2324620"], "stride": 0x208,
            "index": (rva - 0x1FD8660) // 0x208,
            "key_id": spec["key"], "name": field, "hex": raw.hex(),
            "sha256": sha256_bytes(raw),
            "evidence_kind": "ordinary_bounded_PE_bytes_interpreted_using_REA_initializer_layout",
            "writer_assembly": lines,
            "writer_rva_range": [hex(start), hex(end)],
        }
        # The immutable ID and name prefix are checked in the loaded image as
        # well as in the fixed PE. No initialized STL metadata is guarded here.
        guard_records.append({"name": f"compiled_token_{field}", "rva": hex(rva),
                              "end_rva_exclusive": hex(rva + len(raw)),
                              "size": len(raw), "hex": raw.hex(), "sha256": sha256_bytes(raw)})
    for record in records:
        body = record["rea_body_range"]
        start = int(body["rva_start"], 0)
        raw = _read_pe_rva_bytes(exe, start, body["span_bytes"])
        guard_records.append({"name": record["name"], "rva": hex(start),
                              "end_rva_exclusive": hex(start + len(raw)),
                              "size": len(raw), "hex": raw.hex(),
                              "sha256": sha256_bytes(raw),
                              "source_evidence_id": record["evidence_id"]})
    contract = {
        "schema": "information_native_domestic_pressure_contract_v1",
        "contract_id": "native-domestic-pressure-contract-001",
        "evidence_kind": "REA_semantics_plus_ordinary_bounded_PE_record_bytes_not_runtime",
        "game": {"version": "1.37.4", "exe_sha256": digest, "exe_bytes": size,
                 "image_base": hex(IMAGE_BASE)},
        "fields": {field: {"country_offset": hex(spec["offset"]), "width": 4,
                            "signed": True, "scale": 1000, "unit": spec["unit"],
                            "save_key_id": spec["key"]} for field, spec in FIELDS.items()},
        "rea_records": records,
        "compiled_token_records": token_records,
        "semantic_join": [
            "The country writer passes country+offset through the exact dword-copy function and supplies the selected key ID to the fixed-point writer.",
            "The fixed-point writer selects a key using the native resolver and formats the copied signed int32 as quotient/remainder of 1000.",
            "The initializer reads {int32 ID,char name[]} records at stride0x208; the four selected records lie on those boundaries and match the writer IDs.",
            "The key-vector builder and resolver connect the initialized names to numeric key IDs; the compiled bytes alone were only candidates before this join.",
            "The vector builder also loads runtime registrations. Each capture must independently verify all four actual names at vector+key_id*32; compiled token names alone do not close that condition.",
            "religious_unity is exported as the stored ratio with scale1000; 1000 is1.000. A percentage display would multiply the ratio by100, not change the raw value.",
        ],
        "unknown_conditions": [
            "Static paths establish layout and serialization semantics, not current values or current UI rendering.",
            "The paused runtime reader still requires creation/session/path/hash/code/date/country and full read-log double-pass guards.",
            "Double-pass consistency is not a main-thread atomic snapshot or world-generation proof.",
            "Overextension and average unrest are excluded; nearby expense/cache fields are not substitutes.",
        ],
    }
    return contract, guard_records, records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, default=DEFAULT_EXE)
    args = parser.parse_args()
    for output in (CONTRACT, PROFILE, STAGE / "research-index-001.json", STAGE / "freeze-report-001.json"):
        if output.exists():
            raise FileExistsError(f"refusing_to_overwrite:{output}")
    contract, guards, records = build(args.exe)
    _, contract_sha = _write_json_new(CONTRACT, contract, overwrite=False)
    helper_paths = (
        "bridge/information/country_resources_memory.py",
        "bridge/information/localization_memory.py", "bridge/information/mission_memory.py",
        "bridge/information/profiles/localization-memory-1374.json",
        "bridge/information/profiles/mission-memory-1374.json",
        "bridge/information/profiles/country-resources-memory-1374.json",
        "work/freeze_information_country_powers.py", "work/freeze_information_domestic_pressure.py",
    )
    dependencies = [dependency_record(ROOT / path, role="audited helper/layout or contract builder") for path in helper_paths]
    dependencies.extend({"path": r["evidence_path"], "sha256": r["evidence_sha256"],
                         "bytes": r["evidence_bytes"], "role": "REA semantic evidence"} for r in records)
    dependencies.append(dependency_record(CONTRACT, role="frozen domestic pressure contract"))
    profile = {
        "profile_id": "domestic-pressure-memory-1374", "profile_version": 1,
        "game_version": "1.37.4", "executable": {"sha256": EXPECTED_EXE_SHA256, "image_base": hex(IMAGE_BASE)},
        "contract_sha256": contract_sha,
        "globals": {"database_rva": "0x233d8b0", "game_rva": "0x233fe58", "game_date_offset": "0x1dd0"},
        "country": {"supported_country": "FRA", "table_offset": "0x118", "handle_offset": "0x20", "country_scan_entries": 256},
        "scalars": {field: {"offset": hex(s["offset"]), "width": 4, "signed": True, "scale": 1000, "unit": s["unit"]} for field, s in FIELDS.items()},
        "save_tokens": {"vector_rva": "0x242b868", "tokens": {
            field: {"key_id": s["key"], "name": field} for field, s in FIELDS.items()}},
        "limits": {"max_total_rpm": 512 * 1024, "max_single_rpm": 65_536, "double_pass": True},
        "code_guards": guards,
        "source_evidence": {r["name"]: {"path": r["evidence_path"], "sha256": r["evidence_sha256"],
                                           "evidence_id": r["evidence_id"], "body_rva": r["rea_body_range"]} for r in records},
        "provenance": {"contract_path": relpath(CONTRACT), "contract_sha256": contract_sha,
                       "dependencies": dependencies, "reader_self_reference": False},
        "unknown_conditions": contract["unknown_conditions"],
    }
    raw = (json.dumps(profile, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(raw) > 64 * 1024:
        raise ValueError(f"profile_exceeds_reader_bound:{len(raw)}")
    profile_size, profile_sha = _write_json_new(PROFILE, profile, overwrite=False)
    all_rea = []
    for path in sorted(STAGE.glob("rea-*/evidence.json")):
        data, size, digest = read_json_bounded(path)
        value = data["raw_result"]["value"]
        all_rea.append({"path": relpath(path), "bytes": size, "sha256": digest,
                        "evidence_id": data["evidence_id"], "procedure": value["procedure"],
                        "selected_for_profile": any(r["evidence_path"] == relpath(path) for r in records)})
    _write_json_new(STAGE / "research-index-001.json", {
        "schema": "information_domestic_pressure_research_index_v1", "rea": all_rea,
        "excluded": {
            "rea-corruption-label-001": "generic label formatter; no country balance",
            "rea-stability-label-001": "reform enactment cost; no current stability",
            "rea-country-scalar-serialization-001": "global modifier registration; not a country serializer",
            "country_e3c": "debase-currency calculation input; not corruption",
            "country_e48": "peace-context overextension cache; no general current-state contract",
        }}, overwrite=False)
    report = {"status": "passed", "runtime_observation": False,
              "profile": {"path": relpath(PROFILE), "bytes": profile_size, "sha256": profile_sha},
              "contract": dependency_record(CONTRACT, role="native semantic contract"),
              "code_guard_bytes": sum(x["size"] for x in guards),
              "code_guard_count": len(guards), "fields": contract["fields"]}
    _write_json_new(STAGE / "freeze-report-001.json", report, overwrite=False)
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
