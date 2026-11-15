"""Freeze the bounded effective-unity investigation without enabling a reader."""
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.freeze_information_country_powers import (
    read_json_bounded, _procedure_record, _write_json_new, dependency_record,
)

STAGE = ROOT / "work/runtime/information-religious-unity-20261025-001"
SPECS = (
    ("rea-country-unity-wrapper-001", "country_unity_wrapper", 0x3B47B0,
     ("FUN_14093d5c0(param_1 + 0x28c0)",
      "FUN_1403b4530(param_1,param_2,lVar1 + 8,param_3,param_4)")),
    ("rea-country-modifier-cache-001", "country_modifier_cache", 0x93D5C0,
     ("piVar8 = (int *)(param_1 + 8);", "(*piVar8 == 1)",
      '"CCountryModifiers::EState::CALCULATING when called from "',
      "piVar8 = (int *)&DAT_14245bb10;")),
    ("rea-modifier-boolean-cache-001", "modifier_boolean", 0x8E79A0,
     ("param_2 * 0x60 + 0x40 + DAT_142358060", "*plVar1 + 0x10",
      "param_2 * 0x60 + 0x54 + DAT_142358060", "& 0x40",
      "FUN_1408e6a10(param_1,local_res10,param_2)")),
    ("rea-modifier-value-access-001", "modifier_value", 0x8E6A10,
     ("param_1 + 0x10", "param_1 + 0x58", "param_1 + 100",
      "param_3 * 0x60 + 0x40 + DAT_142358060", "*plVar1 + 8")),
    ("rea-unity-ui-tooltip-001", "unity_ui", 0xFEBFB0,
     ("FUN_1403b4530(lVar10,local_res10,lVar13 + 8,0,0);",
      '"religiousunity_value"', "FUN_1400cfb50(&local_res8,0x42c80000);",
      "(lVar13 * lVar10) / 1000")),
    ("rea-ui-fixed-point-from-float-001", "ui_float_to_fixed", 0xCFB50,
     ("_X = param_2 * 1000.0 + 0.5;", "*param_1 = (int)_X;")),
)


def main():
    records = []
    for directory, name, rva, anchors in SPECS:
        path = STAGE / directory / "evidence.json"
        evidence, size, digest = read_json_bounded(path)
        records.append(_procedure_record(
            {"name": name, "rva": rva, "anchors": anchors}, path, evidence, size, digest))
    getter = ROOT / "work/runtime/information-domestic-pressure-20261025-001/rea-religious-unity-ratio-001/evidence.json"
    old, size, digest = read_json_bounded(getter)
    records.append(_procedure_record({
        "name": "effective_unity_getter", "rva": 0x3B4530,
        "anchors": ("param_1 + 0xee0", '"RELIG_UNITY_FROM_PROVINCES"',
                    "*piVar5 == 0xa8", "iVar7 = iVar7 + local_114;",
                    "param_4 == '\\0'", "*param_2 = 1000;")}, getter, old, size, digest))
    report = {
        "schema": "information_effective_religious_unity_research_v1",
        "status": "static_paths_verified_runtime_and_callback_semantics_pending",
        "game_version": "1.37.4",
        "exe_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        "image_base": "0x140000000", "address_kind": "RVA unless explicitly VA",
        "source_records": records,
        "observations": {
            "stored_province_component": "signed int32 at country+0xEE0; not final current unity",
            "normal_cache_path": {
                "cache_owner_argument": "country+0x28C0", "state_address": "country+0x28C8",
                "modifier_object": "country+0x28D0",
                "condition": "The cache helper returns argument+8 except its CALCULATING/owner mismatch diagnostic fallback. Pure RPM must not assume that path while state==1.",
            },
            "numeric_modifier": {
                "id": "0xA8", "dense_flag_offset": "modifier_object+0x10",
                "values_pointer_offset": "modifier_object+0x58",
                "sparse_count_offset": "modifier_object+0x64",
                "dense_value": "signed int32 at values_pointer+0x544",
                "sparse_value": "first matching {id,value} pair with8-byte stride; absence starts at0",
                "callback": "optional object at modifier_db+0x3F40, method vtable+8",
            },
            "special_rule": {
                "id": "0xE7", "modifier_db_global_rva": "0x2358060",
                "record_stride": "0x60", "processor_offset": "0x40",
                "resolved_type_offset": "0x54", "boolean_flag_offset": "0x5C bit0x40",
                "callbacks": "optional processor method+0x10 remaps the type; boolean value query can also invoke method+8",
            },
            "ui_policy": {
                "callsite": "0xFEC7FF", "upper_clamp_argument": 0,
                "tooltip_argument": 0, "display_object": "religiousunity_value",
                "scale": 1000, "unit": "fraction",
                "percent_display": "UI converts float100.0 to fixed100000, multiplies the getter result and formats an integer percentage. It requests the getter without the optional upper clamp.",
            },
        },
        "unresolved": [
            "No running game exists for native values, cache states, callback presence, lifecycle or identity acceptance.",
            "Callback implementations and their complete read-only behavior are not established by an indirect call alone.",
            "A future query must follow the UI's unclamped getter convention, not silently force an upper bound of100%.",
            "A cached modifier sum is not universally equivalent to the native getter: the special rule, callback and cache fallback must be included or explicitly unavailable.",
            "Any future native invocation still needs the project's complete query ABI/thread/ownership/runtime audit; this static report authorizes no dispatch.",
        ],
        "production_changed": False, "religious_unity_coverage": "planned",
        "native_function_invoked": False, "runtime_observation": False,
        "builder": dependency_record(Path(__file__), role="bounded REA evidence join"),
    }
    _write_json_new(STAGE / "effective-unity-paths-001.json", report, overwrite=False)
    print(json.dumps({"status": report["status"], "source_records": len(records),
                      "production_changed": False}, ensure_ascii=False))


if __name__ == "__main__":
    main()
