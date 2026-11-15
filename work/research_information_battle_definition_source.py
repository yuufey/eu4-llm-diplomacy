"""Bind fixed battle-definition fields to existing REA and bounded PE bytes."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.information.mission_memory import _read_pe_rva_bytes  # noqa: E402
from work.local_config import game_exe  # noqa: E402

STAGE = ROOT / "work/runtime/information-battle-body-source-20261028-001"
PROFILE = ROOT / "bridge/information/profiles/battle-definition-memory-1374.json"
GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


def pin(path: Path) -> dict:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": str(path.resolve()), "bytes": path.stat().st_size,
            "sha256": digest.hexdigest()}


def write_new(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main() -> None:
    exe = game_exe()
    exe_pin = pin(exe)
    if exe_pin["sha256"] != GAME_SHA:
        raise ValueError("fixed_executable_changed")
    evidence_path = STAGE / "rea-definition-lookup-001/evidence.json"
    run = json.loads(evidence_path.with_name("run.json").read_text(encoding="utf-8"))
    if (run["exit_code"] != 0 or run["provider_exit_code"] != 0
            or run["database_unchanged"] is not True
            or run["cleanup"]["status"] != "complete"):
        raise ValueError("definition_lookup_REA_not_complete")
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    if (evidence["subject"]["digest"]["sha256"] != GAME_SHA
            or evidence["normalized_result"]["procedure"]["address"] != "0x1408c02a0"):
        raise ValueError("definition_lookup_REA_identity_mismatch")
    guards = []
    for label, rva, size, runtime in (
        ("manager_getter", 0x8BEFA0, 0xAF, False),
        ("manager_getter_unpatched_return", 0x8BF044, 11, True),
        ("definition_lookup", 0x8C02A0, 0x342, True),
        ("land_layout_consumer", 0x8C9470, 10, True),
        ("land_button_consumer", 0x8C9FA2, 13, True),
    ):
        raw = _read_pe_rva_bytes(exe, rva, size)
        guards.append({"label": label, "rva": hex(rva), "expected_hex": raw.hex(),
                       "runtime": runtime, "bytes": len(raw),
                       "sha256": hashlib.sha256(raw).hexdigest()})
    if pin(exe) != exe_pin:
        raise ValueError("executable_changed_during_bounded_reads")
    profile = {
        "profile_id": "battle-definition-memory-1374", "game_version": "1.37.4",
        "executable": {"sha256": GAME_SHA}, "country": {"supported_country": "FRA"},
        "globals": {"manager_cell_rva": "0x242bcd8"},
        "keys": [{"key": "LANDBATTLEOVER", "kind": 1},
                 {"key": "NAVALBATTLEOVER", "kind": 2}],
        "manager": {"bucket_count_offset": 4, "bucket_array_offset": 8},
        "node": {"definition_offset": 0, "next_offset": 8},
        "definition": {"key_offset": 56, "key_length_offset": 72,
                       "key_capacity_offset": 80, "kind_offset": 88,
                       "layout_raw_offset": 92, "button_flag_raw_offset": 96},
        "hash": {"seed": 0, "multiplier": 61, "arithmetic_bits": 32,
                 "algorithm": "h=((h+ASCII_byte)*61)&0xffffffff"},
        "limits": {"max_total_rpm": 131072, "max_single_rpm": 8192,
                   "max_rpm_calls": 2048, "max_nodes_per_bucket": 64,
                   "max_bucket_count": 65536, "max_key_bytes": 64,
                   "max_string_capacity": 8192},
        "code_guards": guards,
        "boundary": "Read current registered definitions only. No native lookup/fallback, "
                    "allocator, window creation, event attachment, or observer visibility claim.",
    }
    write_new(PROFILE, profile)
    source_paths = [evidence_path, evidence_path.with_name("run.json"),
                    STAGE / "definition-source-001/ordinary-PE-windows-001.json",
                    ROOT / "work/runtime/information-battle-layout-20261025-001/"
                           "rea-land-result-message-001/selected-evidence-001.json",
                    ROOT / "work/runtime/information-battle-message-20261025-001/"
                           "rea-message-presenter-001/evidence.json",
                    ROOT / "work/runtime/information-battle-popup-20261025-001/"
                           "rea-land-popup-fields-001/selected-evidence-001.json",
                    ROOT / "work/runtime/information-battle-popup-20261025-001/"
                           "rea-naval-popup-fields-001/selected-evidence-001.json"]
    contract = {
        "schema": "information.battle.definition_source_contract.v1",
        "status": "static_lookup_and_fields_closed_runtime_pending",
        "target": exe_pin, "address_convention": "RVA; preferred VA=0x140000000+RVA",
        "profile": pin(PROFILE), "sources": [pin(p) for p in source_paths],
        "REA": {"evidence_id": evidence["evidence_id"],
                "procedure": evidence["normalized_result"]["procedure"]["body"],
                "limitations": evidence["normalized_result"]["limitations"]},
        "manager_source": "Non-null [module+0x242bcd8] is returned unchanged by "
                          "8befa0; empty global is unknown, never invoke its allocating branch.",
        "lookup": "Hash selects bucket; compare String32 at definition+0x38 by exact "
                  "length+bytes along node+8 chain, node+0 is definition. Never use fallback.",
        "field_semantics": {
            "definition+0x58": "signed i32 popup kind: 1 land, 2 naval in 8c1270",
            "definition+0x5c": "signed i32: zero compact land; nonzero detailed land",
            "definition+0x60": "byte: zero takes Agree/Decline branch; nonzero CenterOK branch "
                               "in 8c75d0/8ca460; retain raw, not runtime widget visibility",
            "message+0x60": "Distinct object: String32 auxiliary text; not this definition byte",
        },
        "runtime": {"new_game_calls": 0, "new_game_writes": 0, "new_RPM": 0},
        "unresolved": ["current registered objects and their values", "same-event binding", 
                       "actual popup/widget visibility", "complete B04 original text"],
    }
    write_new(STAGE / "definition-source-contract-001.json", contract)
    print(json.dumps({"profile": pin(PROFILE), "contract": pin(STAGE / "definition-source-contract-001.json")}))


if __name__ == "__main__":
    main()
